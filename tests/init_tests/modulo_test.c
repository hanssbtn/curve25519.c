#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xDDCEBFE3AB6B008AULL,
		0x3C4D628101FED6FDULL,
		0x9C29C4B9221BD1D9ULL,
		0xA5C358A3D874346DULL,
		0x4801B94F1E4C3227ULL,
		0x126A57E82ECC85A3ULL,
		0x357B1F8EFF480F7EULL,
		0x65E4B39222793C40ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x8E1041A22ABA74A1ULL,
		0xF8166EF7F45AAD3AULL,
		0x8C7073F306CE1E8FULL,
		0x45B60054F67325F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B294F3A7CE9D13AULL,
		0xA1CBC87B07B0B417ULL,
		0x53EDB43289F8CFA1ULL,
		0x5473CC492F36860DULL,
		0x617A828F07B8054FULL,
		0x6AF9325036EC5C64ULL,
		0xDEB0516D6DED6146ULL,
		0x1C49D985C1F1C268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1358B075A23A9B9FULL,
		0x82C940632EC66AFEULL,
		0x6219CA70DB354015ULL,
		0x076A1623F919619EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF901B500BD05EE86ULL,
		0xD0205D773571E2E8ULL,
		0xC5FD4549CB82891DULL,
		0xA1D054CF9DB51FC7ULL,
		0x7BDFAD2A6217A66BULL,
		0x1CBD7D63668C68BAULL,
		0x023325D5137891C5ULL,
		0x1007309E09FEE561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C35694B4C88A2DAULL,
		0x1440FA386E496E97ULL,
		0x1994E2EAAF682C60ULL,
		0x02E18C45198B2C2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC68FC9359364615ULL,
		0xE0C037F03DF153ECULL,
		0x29F7004EA3E0E96CULL,
		0x749C213678F2AAECULL,
		0x453B316D55217730ULL,
		0x26A84565EEDB9FE8ULL,
		0x482142945326E4B4ULL,
		0x7DD5207409C03FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x433252CDFC2DFA07ULL,
		0x9DBA8511B28B1067ULL,
		0xDEE6E252FBA6DC2AULL,
		0x223EF26FEB7C1E0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D8B7801DF35565EULL,
		0x92908BE9F9767E67ULL,
		0xC2A482E2EDCB18FBULL,
		0x880CB098F5BF8BBBULL,
		0x593910DE8EFE81FAULL,
		0x51B0F2332E0E0DF1ULL,
		0x539689775E8792A0ULL,
		0x3FB95A2BE58BAAABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC03F90B18FCA2E3ULL,
		0xB2D47F82CF8C903AULL,
		0x2AFCEA9AF5EADCC7ULL,
		0x7D90131D087AE12AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6A89AF410420018ULL,
		0x67803F0C732AC589ULL,
		0x6698A1CD9B541589ULL,
		0x411F7A75B63A11DFULL,
		0xE33EBBE7B6F5331FULL,
		0x6CFC5F33A420074FULL,
		0x4D2FA828C96F871CULL,
		0x2AA553FE6A03321EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F87F5938A797A9ULL,
		0x94F660B6CFEBDB65ULL,
		0xDBAB97DB81E223C1ULL,
		0x15A9F23972B3825EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x231E054DCC418F38ULL,
		0xC4572AD3CE048AFCULL,
		0xBBD73C95C0DF15F3ULL,
		0xE12B2BC7251B3D3FULL,
		0x7FED6F4A39F664F2ULL,
		0x7037751AC78A0E2AULL,
		0x3788CFA59901B3ABULL,
		0xC141FB42648A2119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205C8A5266D48F85ULL,
		0x6C928CCD6C82A54BULL,
		0xFA260F2A771FC166ULL,
		0x10F677A2119C26FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71AE50245372EF97ULL,
		0xDFB36F594B3E11C4ULL,
		0xAFA6A4FC0C1FEB7BULL,
		0xDDC238D87E63F1E1ULL,
		0x848F80F3183FD06DULL,
		0x50006E71CFE7E1C6ULL,
		0x5675D938E3E8B988ULL,
		0x969A2576319B5165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EFB7439ECEBE32FULL,
		0xBFC3D43E27A9953CULL,
		0x8524E36DE0AB75B7ULL,
		0x38A3C863DB7206ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5659DAC225A6B9BAULL,
		0xD031F45DEFDA5E34ULL,
		0x1AABFB8C6361BF6BULL,
		0x4A05AEAC403F0159ULL,
		0x1AA448CACC5E2EF6ULL,
		0x86868614A7779DB2ULL,
		0x4313680ED6DEBC56ULL,
		0xBCF4E716DBA33072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABCA8DC7BA1B666ULL,
		0xC829DB6ECB9BC6A4ULL,
		0x0F8D6DC04871B443ULL,
		0x565FFC10DA78324FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x119F1C32950DA8A4ULL,
		0xC6404840812E86E3ULL,
		0xBF899CC0F0D71BDBULL,
		0x8332934843AA67ADULL,
		0x0A14F5D7A2CEB2ADULL,
		0x3B99BACFF7CEE4A7ULL,
		0x40D9D87A014157B0ULL,
		0xD10634FB28CE353BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90BB9A34BFBC32FFULL,
		0x9F12031F49E477AEULL,
		0x5FDFBEDD208A2004ULL,
		0x0A1E709052464E79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x389D9B49A8095F56ULL,
		0x21E4B543E56E7709ULL,
		0x7068976E6B7A71C5ULL,
		0xC3CA4336A4F898ADULL,
		0x0B51D0598B218306ULL,
		0xB4AC74AB0026D942ULL,
		0x4B1EC1B0BF5E787AULL,
		0xCA36049FE627BD5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C288944F02D6C1ULL,
		0xF37E06A5EB32B6D6ULL,
		0x96F957AAD38053FBULL,
		0x47CEF2F2CEDEB486ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77CB6627E8FF8ACCULL,
		0xAD887C832D5EDCB9ULL,
		0x5810F49FA64BF05AULL,
		0x9AC3FB9536E932A1ULL,
		0x55481E750E75E20EULL,
		0xC2AF7AD91DEF9BFEULL,
		0x00C5018A1DE78AAEULL,
		0x144ED811DE4C0FD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x207FEB880E7F1965ULL,
		0x9394B8BD9EF0047AULL,
		0x754F2F2016AA864BULL,
		0x1E780E3C36338C8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB8F9337DB4BAA4ULL,
		0x009F4190EBF9B274ULL,
		0x9AD98645093CE860ULL,
		0xF5131B878D21BAECULL,
		0xE8441A16FB92E3E0ULL,
		0x5BAACCAA18DF7423ULL,
		0xC6E8218D3F3BDC30ULL,
		0x3037CA91890EE3D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D4D89CD5828F14ULL,
		0x9BF9A2D09D24EFC8ULL,
		0x214E813C6C1F978DULL,
		0x1D5B2D21E5578CCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD08976C10945BEA0ULL,
		0x77BE94DFF86318A9ULL,
		0xCF9EF2C7C3F1FB95ULL,
		0x25F1523BD08EA51BULL,
		0x78C934F1C9EAE24DULL,
		0x3D52C82C75DDC01CULL,
		0x3C207F8BFC529550ULL,
		0x847281E56C69D843ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6752A5022358F3ULL,
		0x92084B79774D9CE3ULL,
		0xBC71E18F3834257EULL,
		0x4EF09A49E844BF16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CA9311C31FFBCE2ULL,
		0xCC64007E4E6DFEAFULL,
		0x5F9C0758B54AB444ULL,
		0xBB2246E012B0CDECULL,
		0x7974849C2CF33A8DULL,
		0x62DDD9C043EFBB71ULL,
		0xFC3FD0E6FC56BA65ULL,
		0x369ACF6896A53FC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53F4E04ADE1A6F13ULL,
		0x795253086403D187ULL,
		0xD11509A22A2A5F51ULL,
		0x561D10666F384491ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D5FAD99B95173AULL,
		0x511EAC1F05D4732EULL,
		0x74F1EB53C2FC67B2ULL,
		0xA922F577F22744F6ULL,
		0x4F5E8D506CB441A3ULL,
		0x9507AC0732CE8380ULL,
		0x9529DD4A9DDDC57EULL,
		0x75432B6A25D3026DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDEF4C9BE56D818ULL,
		0x70423530907BF839ULL,
		0x9928C46731E7B87CULL,
		0x111B67398F79A13AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71949695E398EC12ULL,
		0xC7443482EEF61649ULL,
		0x4D3BC701FB3B8CD1ULL,
		0x5CEE8679428F21B6ULL,
		0x3B4265980BD4332FULL,
		0xFBB8B0DE0F419FA5ULL,
		0x2B1BFE80B423EFCCULL,
		0x0A205B3504081F75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6FAB27A5188545ULL,
		0x24AE757932B3C8D0ULL,
		0xB3638E1CB891253FULL,
		0x5DBC1057DBC3CD1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3D7C43A6114423EULL,
		0x9E21A21E27BBFD65ULL,
		0xDC7A33F5C60217D8ULL,
		0x121E9318BEA95BFEULL,
		0x5C44820EA2BA24C1ULL,
		0x404428074B73FE9EULL,
		0xA3DCF4FA6B9FB889ULL,
		0x4C4A1F4E6D794651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8603126688B5B886ULL,
		0x283F93335AF3C8E7ULL,
		0x2F469121BFB77C38ULL,
		0x651F38BCFEA9CC1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x720330DC3BC21B8EULL,
		0xEFBD182C1815B9DAULL,
		0x8EF53B7F3DB39437ULL,
		0x17EA6AB4B973A1CEULL,
		0x3F391159C395BA63ULL,
		0x44660CD76D7D8DE4ULL,
		0x471D94FA9DAD3A57ULL,
		0x634A5467F86A1714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47BC42F43FBC867ULL,
		0x16E3002658B8C9BBULL,
		0x1D5958B2A56A3D2CULL,
		0x54F2F22399330ED1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208DDC64AB762556ULL,
		0x808DDC35E30903A9ULL,
		0xD7B7D2738A0C03C0ULL,
		0xDD529CDDA008A982ULL,
		0x03AC8AA35155144DULL,
		0xE4B4B021ED32B733ULL,
		0x8A2CEA1C9F9C711CULL,
		0x7C75BECDFBD42101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2A70A2BE172B96ULL,
		0x7360013F1890353BULL,
		0x5A6292B33B44CE0AULL,
		0x56CCEF7101858FBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x737DA112423DF334ULL,
		0x6E47BBC52C77A09BULL,
		0xD3CE933E37F8A332ULL,
		0x862B08C86F99C6B7ULL,
		0x295323EB226B4564ULL,
		0x5EE5E203698414ABULL,
		0xF6DCA8C127F7E079ULL,
		0x1B3A4FC3D94D6E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D4F5F95E2A40B7ULL,
		0x84674846D612B203ULL,
		0x788F9FEA26C3F536ULL,
		0x10D2DFDAB1182EE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x121643848855463BULL,
		0x44686324C731BA48ULL,
		0xBA2FCEF984177880ULL,
		0xB185EF29D02FBA1CULL,
		0x2569EE7DAE123C70ULL,
		0xEBB4026215FBEF30ULL,
		0x522024C82F9800B5ULL,
		0x8F04E6C95499A403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FCFAA2C5F0A420CULL,
		0x4120BDB40A973B6DULL,
		0xEAF544B094A79381ULL,
		0x6C40310C5EFE129AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF3907AA313CAFEBULL,
		0x4014C09141E49BFDULL,
		0x55FAD697F2C7C03CULL,
		0xAB9233BACEB1951EULL,
		0xD8852BEDE6AF91A4ULL,
		0x48B3954ADB03F8C6ULL,
		0xFCF9C8C8AF31599EULL,
		0x1148DFDFEDCFBDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02FD8CFA6F4C4EB5ULL,
		0x0ABCE9ADC47B8982ULL,
		0xE30EA461F41B0DBBULL,
		0x3C636EF81B87C625ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x131CD9F2ADB82F2BULL,
		0x04897F2F76535CACULL,
		0xCF6B24FE11EB3DAFULL,
		0x50960EF7CDA2892AULL,
		0x7DEC47E5E7F6E03FULL,
		0x34645993E8E0CCB2ULL,
		0x98B2559B77AF69A2ULL,
		0x3168632F8FCCFB25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42F86131C5D79A2ULL,
		0xCB6ECB2407B1BF2AULL,
		0x79E3DA11D5F4EBC2ULL,
		0x2614C807260FD0BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C2A2125C62A6AFEULL,
		0x9EA6FADF8F8645E9ULL,
		0x3560F72925B66BF9ULL,
		0xC26833A6A24DE669ULL,
		0x39D493C5CD68F738ULL,
		0xF0497D70C383CBC3ULL,
		0x6A6153985E3D0D9FULL,
		0x4CE1E19713A4855BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B8108243BF1F16ULL,
		0x498F999C951684E4ULL,
		0xFFD35FC722C671B7ULL,
		0x2BEFB0138CB9B1FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20C799662CC7AF75ULL,
		0x40234D67DB710D72ULL,
		0xC594F81238E7EF4CULL,
		0x14987C6CCBBF7F54ULL,
		0x78214BC5771CF1C0ULL,
		0xF01EAEBF2FC6C7B7ULL,
		0x5A371C681443C70FULL,
		0x895AA29E48349A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B8D8B5DB1394EDULL,
		0xE4B13DC8F2F2B2ADULL,
		0x29C32F853AF77BA9ULL,
		0x780C9FEB838E709CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50BE08990AD8835AULL,
		0x773612DA8E858D03ULL,
		0x9531AD591E59C362ULL,
		0x2B5AFB5DA11FA2FCULL,
		0xF7D06A0FAB0D24BAULL,
		0x3E960BA34B9838CDULL,
		0x20C8A4B8F92426AEULL,
		0x8E24E3EFB4419E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19ADC6EC6ECBFA14ULL,
		0xC17BCD17C71DFB96ULL,
		0x72FA20CE19B7813FULL,
		0x44D4D0F262DD2BC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ACB9821D51D9BF2ULL,
		0x937FCF7E5F36EFCFULL,
		0x895617EA91D7D548ULL,
		0x420986D872ADD833ULL,
		0x6449460AF832BB11ULL,
		0x8B3C3D47F7A9794EULL,
		0x49FF0AA915AC5B0FULL,
		0x558F94F7CF135FE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DABFDC2ACA56253ULL,
		0x3E70E82D225EF172ULL,
		0x8531AD03C96D5997ULL,
		0x7559A3A12F8E14AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3414337BC80EFA37ULL,
		0x4C083034ACE53803ULL,
		0xCC9F0ED06DA69568ULL,
		0xA86E6F041B7CBD46ULL,
		0x0F165CA92FD74502ULL,
		0xBEE35E23B1681427ULL,
		0xC27F7E6FFE52453FULL,
		0xD39F090A6BB136FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7165F498E2033D43ULL,
		0xA1C82981025835CFULL,
		0xAB8BD3702DDCDCDEULL,
		0x1209C69017CAE73DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93EC069A96C07AC6ULL,
		0x4EC42D221BA2F896ULL,
		0x6CAEA1C1AF19C1ACULL,
		0x59561D4B553D109BULL,
		0x286E079FCDBF80F4ULL,
		0x70A641F7E76EFC6DULL,
		0xF2CA8FB89D0C866BULL,
		0xFC4F2794E8BAB3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94412853212DA48FULL,
		0x0771F7EE761C70CAULL,
		0x76BFF728FEF5B59FULL,
		0x4D15FD65E0F3C873ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3B7F62587208761ULL,
		0x2F2E8178CC96E3ACULL,
		0xDACBFC4E041ABD4EULL,
		0xD2D10905A1DA0902ULL,
		0xCF6DEDDD054E31EDULL,
		0xCE056065F5E02222ULL,
		0x22CD8534D6133E72ULL,
		0x5AF961ABC69FA7F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE0944F450BBF2A3ULL,
		0xC3FAD09B4BDBF4D7ULL,
		0x054DC225CAF60258ULL,
		0x53D588851D8CF740ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E53C866CEE01AF7ULL,
		0xD48E0915DB132397ULL,
		0x28333D5465D4CF95ULL,
		0xE94A9533FFDF0DAEULL,
		0x9BF14FD9F26CCDE8ULL,
		0x1A30F3566A8E3A49ULL,
		0x429D752D1BB4B43FULL,
		0x2B29DB822DAE2AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB425A2C0CB06AC71ULL,
		0xB7D227E9AC2FCA84ULL,
		0x0B92A20682A790F3ULL,
		0x51812A86C7B963D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6191B006551F446AULL,
		0x45F22B4781EF299BULL,
		0x12BD76A04B20F7C1ULL,
		0xEE9033BBF1F543E8ULL,
		0xA8152242464398FDULL,
		0x009E79F37F1A689EULL,
		0x87D1D3B83BE6443FULL,
		0xAEC2B171BEA8B4D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B4C5DCC327FDE7ULL,
		0x5D78456C5FDAB128ULL,
		0x3BE2E3F92F4F191BULL,
		0x5F768A9E3F001C0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62BD3B198A6FD3E9ULL,
		0x36E1F1256F595480ULL,
		0x0FF6B48D190A08A5ULL,
		0xE2D2A48900BBDB0AULL,
		0xFAF24C4C5995C5A8ULL,
		0xBF857B2B953F6381ULL,
		0xF0CE0E1FB82250F1ULL,
		0x369C50474B669DB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2B48E6ED6AB2C1CULL,
		0xA4B2399D96C219CBULL,
		0xCE8CCD426E220C87ULL,
		0x7E068F1E31F7440BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE93E03CD9C78037EULL,
		0x5CAEC83456C7720AULL,
		0x0762161B41EC784DULL,
		0x0B8242B89DA22B5FULL,
		0x531290AE2EA7B276ULL,
		0x18294E1C3A51D986ULL,
		0x1EF5DCD6721DA8B8ULL,
		0x95514B285B620076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFF7DA8895C8446ULL,
		0xF2D06064FEEDBBFBULL,
		0x9FE0DDF0325383A0ULL,
		0x35936AB62E2E3CE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x750AC67207C33C1BULL,
		0xE04B546118983836ULL,
		0xB03A0761A33A68CEULL,
		0xBB49D9D152983A9FULL,
		0xFCBD0AA04A134CE7ULL,
		0xC069BCF57F0AECC1ULL,
		0xD1615EDF1125B58AULL,
		0x0400196BAF65629DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF91A5A3D06A0A68BULL,
		0x6FFD60D1F4375D01ULL,
		0xC4AE1C7E2ED35B67ULL,
		0x534D9FCD5BA4DE0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8F69B9AFC18BA36ULL,
		0x7CA100F228D925B4ULL,
		0xC34068E2E57B76F5ULL,
		0x5ADC4BA98609C8C4ULL,
		0x94EF9B26EC5AE728ULL,
		0xC16D190ECC7127EEULL,
		0xFCDB7FBCBE359E7FULL,
		0x01BC134C2B781EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF487A36211970A39ULL,
		0x32D2B92481A5131EULL,
		0x4BD55EE72170FDECULL,
		0x1CC728F7F9DE5D92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC88D2CD50F65A3ULL,
		0x9D054C18104A3572ULL,
		0x4B927FAAEA45761FULL,
		0x452C7AA2C2D1622DULL,
		0x2FBB2407F20C3F93ULL,
		0x377264AB5C834EC3ULL,
		0x815E16414422D3A5ULL,
		0xA61568E52AFF4520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE28FE65AC2E0D918ULL,
		0xD8003D87CBC7E66BULL,
		0x7F89CD5B0770E0A5ULL,
		0x6C5A0CA724B5A500ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8DE43253A2BDCB1ULL,
		0x5B25CEE1442EB2E9ULL,
		0x774F012B47A7EE0DULL,
		0xC8C225C1D0A54BA8ULL,
		0x393CF69939813FB1ULL,
		0x5A5900CA352A9006ULL,
		0x0DED72286DE0CEEFULL,
		0x1E0E9CBB7EC9F5BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47EADDE3C35B51B5ULL,
		0xC45BECE5288013D6ULL,
		0x888DF32B9706A594ULL,
		0x3EED6996A29FC56CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x429BDAD57A87E2A0ULL,
		0x872D1CE0143EF0A0ULL,
		0x50D0E7EB008F2C6DULL,
		0x9EF4B1125CA97325ULL,
		0x8CFF2D8C41EF7D6BULL,
		0x4389CDB38BE6FBC3ULL,
		0xFD875CC8EC20D3ADULL,
		0xE9051F5EC5A6EE64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x307C9DA7441485B4ULL,
		0x8DA1A586D8884FA7ULL,
		0xF2E8ADBE0D6E9825ULL,
		0x35B75923B370D622ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CA08197B485EF3CULL,
		0x3A73AC5F161F550BULL,
		0x218C902101DF09ACULL,
		0x49A5DC8DCE377039ULL,
		0x3E8B2D7F6E0ACABFULL,
		0xAE6360F6E0C2B105ULL,
		0x59C21518D8B042F7ULL,
		0x4AFFBB7B23E5E674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x854942820A200938ULL,
		0x1D34110473059BD2ULL,
		0x745BB1D12C08FA70ULL,
		0x6B9BB0D52257A57EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D61F7578BFDCE9CULL,
		0xBCCC5471127B8D87ULL,
		0x089E4EF0BFF7CFBCULL,
		0xF5072A8B59E1CF44ULL,
		0x41785D43ACAB4772ULL,
		0x82FA8BEE67D3F6C1ULL,
		0xA53C8EAD3C5363A9ULL,
		0xE5AB5B225FDA97F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53FCF632D6A6EBAULL,
		0x2DFD19D47BF22E36ULL,
		0x8F9B7CA7B4589AE6ULL,
		0x0C76B1A594545D22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5A0CBBBA4CC288ULL,
		0xEFF3F602324A2FAFULL,
		0x940858504EA65147ULL,
		0x162226B5B850376AULL,
		0xC76398A79C4D777CULL,
		0x2E7ED55FCBD69504ULL,
		0x11AE76BA50BC1344ULL,
		0x7AB4900FC4846A33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9722B59CEDCC819CULL,
		0xD6C7A23A74244E65ULL,
		0x33EDF7F84A912D66ULL,
		0x4CEF890CE3F7FAFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D49CE95F378A55FULL,
		0xF51A66FD3AEC15B0ULL,
		0x0C77C6408A59BC5BULL,
		0x3BDF84FF5886653FULL,
		0x89F638106A99D24DULL,
		0xB9D3EA66987CBEA7ULL,
		0x2823561AB1730B91ULL,
		0x3A3A78EBC74B97AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D62105C64DDE10ULL,
		0x8A8F3237DD70628EULL,
		0x01B68E36E16D73FDULL,
		0x608D77FEEDBEE919ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACC5BE8082F39F99ULL,
		0x00183F48A229CF32ULL,
		0x5415EFE45681BF9DULL,
		0xA18DE6B32FE8ED99ULL,
		0xB6992A318BFCE197ULL,
		0x9000BFDD5829DDF4ULL,
		0x1E16A9104B0869B5ULL,
		0x2C19D6E4E718B349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78201DB4A7D1D0DULL,
		0x6034BA23B860C185ULL,
		0xCB73084F79C17090ULL,
		0x2D63CCAD7D938A73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6A2860580B0CBEEULL,
		0x493ED8E2E8BE6410ULL,
		0x32956AC334A7A2A2ULL,
		0x60D4FA52D1B2C0DCULL,
		0x6CA04695346E5B12ULL,
		0x43AC73ADAF9655CFULL,
		0x9415353224C3E5BFULL,
		0xEA7850601DEE53A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE66D002B491255CCULL,
		0x54D804AAF90F20DAULL,
		0x2DBB5034A9BBBD06ULL,
		0x2EB0E89743132BE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9476B0CAA1895A0FULL,
		0xBA3843D47DD0BA6FULL,
		0xC4E726EC14F58F95ULL,
		0x1CC71189F73EBD69ULL,
		0x54EBAE705FF11452ULL,
		0x734C5CCED5963C02ULL,
		0x121DBD9E553CF21AULL,
		0xB8F92851A9F8B28BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F729578DF526250ULL,
		0xD78E0A88321DA2C8ULL,
		0x75514C6CBC017F82ULL,
		0x11C30DA932293E0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BADC7F841C25096ULL,
		0x2D0CB06166618278ULL,
		0x64838B5DAE846A4DULL,
		0x11875C369AD02D7FULL,
		0x07F9392D18EEAEBAULL,
		0x5E78D8E39814A4A2ULL,
		0xD58D01299D99D973ULL,
		0x7478299D180ACB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAAC44A9F53042B8ULL,
		0x32FCE229F971F285ULL,
		0x1771B78B135AB16DULL,
		0x5B5D89882C6A5C17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9FE0B0EB296A7E3ULL,
		0x02EACEAD5E0DD7C2ULL,
		0xB94CD6C25C9ABFB5ULL,
		0x876401601D3135D8ULL,
		0x48FA27A3371C352DULL,
		0xD62F5FA4A7E14EBDULL,
		0x17BC8D79FD454E1DULL,
		0x54044E945EC1A632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1FED48E0C68E7FULL,
		0xCDF3011E497F87DBULL,
		0x3F49D6DDF4E45822ULL,
		0x0007AB662DEFE148ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61033D4728D24268ULL,
		0xA42790E63EC573D0ULL,
		0xDA37C1DDB611EE0EULL,
		0x6D6C2F75310728D0ULL,
		0xED61090418141025ULL,
		0xDD9ADEDAC13D8B8CULL,
		0xE91BEB66DE48C32FULL,
		0x5E01B7B368B6894BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6A93E2BBCCA9FAULL,
		0x8924A55EEDE82ABBULL,
		0x745CB322B4DEE729ULL,
		0x61AD7416BC1F8A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43034BF3593B9463ULL,
		0x2928C6D7B8FC45E4ULL,
		0xF36C3D5DBFA2F7C2ULL,
		0xE382160BEAF477FCULL,
		0x0C752559E220D9A0ULL,
		0x086E4D0EDBCA071CULL,
		0xB75434050A76A5D4ULL,
		0x70E7AF6FEFB03CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C66D74AEA1BE4BCULL,
		0x6988370C58F9540EULL,
		0x29EBF61D4D3F953BULL,
		0x25E620A97F1D7B68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62413D1E201A26A2ULL,
		0x0CFA0F092606F7B9ULL,
		0xE3C9AC40BD7788B3ULL,
		0x5EA0A1EDF36CD423ULL,
		0x7BB42537E6E96537ULL,
		0xBEC36D968BD4E175ULL,
		0x7991620D5C921D16ULL,
		0x868E2136137B7EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEFEC36A66BF2FC4ULL,
		0x5DFC5361E7A06F29ULL,
		0xEF5E3A3C7B27DA13ULL,
		0x57B98FF4D7C1A209ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0FD3DF1E162B7FFULL,
		0x0B66985F45FB8DCFULL,
		0x8CC5844FDEA96E28ULL,
		0x67B7A3D25C09C600ULL,
		0xFBBE025208419B49ULL,
		0x520B61710140FD54ULL,
		0x6A3A122E2D54CB02ULL,
		0xC105ED91237B87F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F31961F1B1FC923ULL,
		0x39170F2575A1286DULL,
		0x5164372A993F9080ULL,
		0x0E98E75DA05FF4BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3C86D61E1FCD5B7ULL,
		0x17CDF0F9896DD910ULL,
		0x5AC302F67930D1A0ULL,
		0x42C53D2E7EB9CBD8ULL,
		0xE8133E076668B765ULL,
		0xBCF789DCC0FF3BEBULL,
		0x49AE7E2529ED7E35ULL,
		0xD58F10E96D92439BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A3A27B15881362ULL,
		0x248C67BE2F50BE15ULL,
		0x4AA9BC7AB2718D9AULL,
		0x7601BFD4C26FD4E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8308F22278792E08ULL,
		0x31F284A7BCB39756ULL,
		0xBCCBFE4103B14CA4ULL,
		0xF0EE39279C0D879FULL,
		0x9F319A6806E0D779ULL,
		0x6EC41BC8D15ABAD8ULL,
		0xBA22933897BA2E7AULL,
		0x9FE6D111359904DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2465DD937DD92DA1ULL,
		0xA30EA476D02B537EULL,
		0x5DEDD8A7895432D0ULL,
		0x2D3141B590C44063ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCABE629139167455ULL,
		0x830AE5271601DA2DULL,
		0x223EA9152C8AF983ULL,
		0x5A619AB495CC9359ULL,
		0x3FE1F0F775A5341AULL,
		0x40AC7958716A95C1ULL,
		0x6880C7EE4004B6BFULL,
		0x579768A55B420957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4648274CAF9C321FULL,
		0x1CA4E847EBD414DDULL,
		0xA55C5672AD3E19E7ULL,
		0x5ADB23402199F652ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5DF4BF5A491B228ULL,
		0x5AC1FD87A67939D4ULL,
		0xFB0BB2D56718E517ULL,
		0x132879D39439E6FFULL,
		0x1C13F8DBCA5F608AULL,
		0x2D6B9382EE4F0125ULL,
		0x23BEB510E939093EULL,
		0x8807A71CD4D4F8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D63C95AEBA099CULL,
		0x18B9E2F706336556ULL,
		0x495A935805904452ULL,
		0x444B481B2BD6D787ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x075605A1D4B7119BULL,
		0x055721B9FA0A7101ULL,
		0xBF1C42CC5ED6ABDAULL,
		0xFFC845FC983C1B93ULL,
		0x50E375F27A13841BULL,
		0xFFDFE1CB08802206ULL,
		0xDE82FA1FB6D24D4EULL,
		0x41227080DFC1D8F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0919879FF39CAF2CULL,
		0x0092A5DD3D0F7DF1ULL,
		0xC68D6381820E2594ULL,
		0x2AE4F91DCF025084ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1095472C9F93755CULL,
		0x9A3A2C839A9C7E00ULL,
		0x7AA20C99574CC364ULL,
		0xD2B8CFD6C2331A46ULL,
		0x9586B8FD20767291ULL,
		0x8C4ED7C6CC632D07ULL,
		0x356361150947B104ULL,
		0xC042F67AC92E0D7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4294BCBF71287B30ULL,
		0x6DEE3405F1552D20ULL,
		0x676275B8B7F10A11ULL,
		0x5CA966109F091B02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2367E35CC2AB1199ULL,
		0xA7C0711D3208C103ULL,
		0xE05CFCC0735B7C94ULL,
		0xE5E298C5D37EEF1AULL,
		0x7C02DC550EDBBCCFULL,
		0x65810FE235E27942ULL,
		0xA7801BE9143C9AC0ULL,
		0xD027B658F8BA18AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD497FCF7491D00ULL,
		0xB8E8CCB131A6C0E1ULL,
		0xBD612159745A7523ULL,
		0x4BC7A9FABF1E9907ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B6DE2CA9601A33EULL,
		0x3FA6454FFF8EB4CBULL,
		0xD530729CDA954FCBULL,
		0xC3DE19EC9EC2FB4EULL,
		0xBB304ACDBA3AA308ULL,
		0xA5635B9F8CE1FD4EULL,
		0xEF745621FFF38C96ULL,
		0x0A24084744FE73A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1498FD543AB5D6BAULL,
		0xCC65DEFEE91A4E7BULL,
		0x60753BA8D8BC2E27ULL,
		0x45375480DC882616ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3865D9F3F8037CBULL,
		0x6732A62CA761B7B4ULL,
		0xA3F2998C165F3079ULL,
		0x5628A1A12A9D3DE3ULL,
		0x5C3D2F0E37FA6065ULL,
		0xDF2A32E2DB3FF4ABULL,
		0xEA6F5F704DC8ADDAULL,
		0x3FC317CEA6CFCA48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849B59BB8EAA8832ULL,
		0x877633D932E00924ULL,
		0x707AC437A228FEF6ULL,
		0x4D1E2A4DED7544B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB820DA8B2C2C3C9BULL,
		0x9DC4659D2A3FA04AULL,
		0x05A159C1065D373DULL,
		0xAF3C4A74B257DB6BULL,
		0xB20945D3AE420F87ULL,
		0x26DC6E700F3629B1ULL,
		0x40DFFBD02E564A13ULL,
		0xD958E2E95703E05CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258137F709FA8F78ULL,
		0x627CCA3F6C49D0ABULL,
		0xA6E0BAA7E72C3615ULL,
		0x726DF9179CEB291CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC19AB2E0EAEF4FB3ULL,
		0x8B3BAB919F3F9A28ULL,
		0x8A3A505B820A91B4ULL,
		0xA64A45E00C812318ULL,
		0x2D2CBA8B9A542654ULL,
		0x0B9B4887838739B7ULL,
		0xC32C72183D4BD98EULL,
		0xA715CB139824EA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763E6399D36D03E1ULL,
		0x44486FAF25522B59ULL,
		0x82D33FF49B4CDCCAULL,
		0x73866AC8A1FBEF17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97E29780C08D5C68ULL,
		0x60E517EEC2D347F0ULL,
		0xC04A649D9DAE6523ULL,
		0x1E478878EDA94E9BULL,
		0xF1EC0699A44DD333ULL,
		0xEFEC1E1CF18EA29DULL,
		0xEF826ECF015A6F69ULL,
		0x620B863D835B1FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80EB924F241AB821ULL,
		0xFDF1903A9DFF6B62ULL,
		0x4DA6D757D11AEEDCULL,
		0x2BFD759A6D300189ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2A0D42D4FF429F6ULL,
		0xF133CD922DA3DA75ULL,
		0x1BD0E418ABEEEE3FULL,
		0xE7E7256B9A10C7FFULL,
		0x1EF2D2911DCA31B4ULL,
		0xBC87B356402AA5CCULL,
		0x78E961745B158E93ULL,
		0xD28C31C2A6A0123DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AAC15B7BBF78F6EULL,
		0xED586C5FB3F876C2ULL,
		0x0E755B5E3122182DULL,
		0x28B6885055D37D1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C85F499B2A74000ULL,
		0xC7242BB0F7A380EDULL,
		0xC636BE39F024BB91ULL,
		0xBB9A85E3250E4C68ULL,
		0x5D6B984318FF4ACDULL,
		0xA21352A65713C03FULL,
		0x82CDB7E82F295BD5ULL,
		0xE57B455AB3C62981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A7E8E8F688C5F8DULL,
		0xD6027061E4920A55ULL,
		0x30C00AB0F0485D47ULL,
		0x4BE6D159D47875A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D2B109CDE0EC2EULL,
		0xD395BE6D0D44829AULL,
		0x2FDDE9309BF7611CULL,
		0x722C69DCA7379B88ULL,
		0x088D2262DA448128ULL,
		0x05BB9A049ADF226CULL,
		0xBE799683AD156177ULL,
		0xCDDA3503180CB21DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC5CBB6340C1CB8ULL,
		0xAD6E9B1C0A639EA3ULL,
		0x75EA40BC4D23D8C7ULL,
		0x00904852391A0BF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC23DC019540606EULL,
		0x011008AEFE8B01A1ULL,
		0x15879FB82285BFB4ULL,
		0xDBAAE7AF6A96D271ULL,
		0x987F89D8B0D04FCCULL,
		0x244EC746615A4625ULL,
		0x1899B840652368A0ULL,
		0x8F2A734A100089FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F12522BD42C3BFAULL,
		0x64C19D2171F16B36ULL,
		0xBC58F94725C74779ULL,
		0x1BF804ADCAAB4D90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD54A54EC027B6A4AULL,
		0x8526C03464287332ULL,
		0x8AFE65E187CB7CFBULL,
		0x26D8CEC8C54C262EULL,
		0x577AF8D985FB6E67ULL,
		0xA753F8DCAADDA320ULL,
		0x6746BAEA88CC5A3FULL,
		0xEDB02DFC83D5974CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18B4535E5CDD2C6ULL,
		0x5B9DB0F5C10EA9FFULL,
		0xDF7E24B1D620E26EULL,
		0x6EFFA24457009B85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60882C85E4F0B8C2ULL,
		0x4F73DBA00B80B972ULL,
		0x8B0A9FE4B442983EULL,
		0xFF4AC77AE14129DEULL,
		0x4F192D8B23678C55ULL,
		0xA84EC0AE85E38745ULL,
		0x0C7C7D84ADAAD3B9ULL,
		0x4BA03507C1CF100FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E44EF2D264F8F28ULL,
		0x4B247587EB46CDBCULL,
		0x658541967B9E05CDULL,
		0x3912A6A1A5FD8C1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC606D5D6AA8B8EA5ULL,
		0x7698FE9DCEBF5226ULL,
		0xFACF8BBAE8D673CFULL,
		0x79DBCAA674401C33ULL,
		0x542D473B2345D039ULL,
		0x01945B50992015ACULL,
		0x002DE45DEAAD660EULL,
		0x688E0BA9E734BAD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BF689DE6E87968ULL,
		0xB29E8C94898289BBULL,
		0x019F71ABBE9399E3ULL,
		0x7EF185DEC613D73AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45320C6F2E36EF20ULL,
		0xF062A55A824DBB55ULL,
		0x57ED3C875A5D876FULL,
		0xD59F5B76477BADC4ULL,
		0xB8D24350557F0216ULL,
		0x844EADEA7D85ABB5ULL,
		0xD673353509F75ABEULL,
		0x69EC7657B9228C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4680A5BDF1140D7ULL,
		0x941076292425384EULL,
		0x2D072266D514FFB7ULL,
		0x0EB8EC7BC29C8612ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0263D68F9062E4DULL,
		0x280A12AA1DF2CB59ULL,
		0xFD06D91B70A979C7ULL,
		0x6F5827F2B99542A4ULL,
		0x50B5B5A8023D9EEDULL,
		0x053F9CA0C636E4F2ULL,
		0x1DA25185608D9B4AULL,
		0xB33775372F3EB773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1F34594E2BC97DULL,
		0xEF7B52878A18C751ULL,
		0x631EF2E7C5AE86C3ULL,
		0x09938E23BCE47DBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC16FD89A9624E351ULL,
		0xD50C93FD195BDBB7ULL,
		0xDCD4874133A3908EULL,
		0x2656E70A0E62D27FULL,
		0x27381938D307A816ULL,
		0x85E824DDEFA9CD46ULL,
		0xB74806064EF3C33EULL,
		0x63D3A506AB316CFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C39709E947D8BCULL,
		0xB5820CEEAC905421ULL,
		0x11856C30EBD28BD6ULL,
		0x77C1660777B9004FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x017740CC2DC4799EULL,
		0x7DC7C84FCC02C2A3ULL,
		0x2D81E566317845B9ULL,
		0xE4856F50A90BFEADULL,
		0x86D9A00BCCADAD5CULL,
		0x212B14E178169E8DULL,
		0x605405B9B5B895AAULL,
		0x5678EE0F423BA1BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C5028C8F8C3747ULL,
		0x6A2CE1C79F5E4BA5ULL,
		0x79FABEF72ADE7CFAULL,
		0x3A78C5947DE600EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6F55FBFD26C0BFFULL,
		0x32F269A20647D843ULL,
		0x64F4CBBD13A54204ULL,
		0x9E5F54B520F7F22CULL,
		0x8F73F55A18414444ULL,
		0xCBC27EF1EBD5C77CULL,
		0x2FB6C39E97FC876CULL,
		0x9C38761CCAC6ADC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF22BCB1F6C1C3194ULL,
		0x71D1418B080374C0ULL,
		0x7A15D547A3215C2AULL,
		0x4EC0DCFB3A75BD97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E5B063275F35FDBULL,
		0xA9BFD995DF6FD239ULL,
		0xE3C0AFDE891CC7F4ULL,
		0xAAEE57253F690474ULL,
		0x4428FBDD14EB3E04ULL,
		0x266EF318EEF41CA8ULL,
		0x885E3B4C48966F8CULL,
		0xDAA23E34DFADA95FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C70690390DE9959ULL,
		0x5E37EF4957AC1333ULL,
		0x21BD7D314F7156C2ULL,
		0x1F0392FE733028A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78EAE14FB98FB549ULL,
		0xBD9611C0CFD12777ULL,
		0x4959239CB448660CULL,
		0x95C795B111419C59ULL,
		0xCBA46705C4DBEE20ULL,
		0xE3D16A8F00AD152AULL,
		0x20FE9807259FCA11ULL,
		0x37AA73D20BAC050AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3522C2AF2350F4CULL,
		0x8EABE2FAE9824BD1ULL,
		0x2F23B4AC4A0064B4ULL,
		0x5914C6DECCCA5BDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB26A4FE41B02CC39ULL,
		0xE6FDD399816DAA0CULL,
		0x518ADCEC14937449ULL,
		0xD7D921A5DFEA1856ULL,
		0x655904BED538538CULL,
		0xF0EE24505E05F724ULL,
		0xCCCB70F233045511ULL,
		0xA416AAEB81FCCCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA10437C15F36B7ULL,
		0xAA57378776505973ULL,
		0xB7BDA0DFA73814F3ULL,
		0x3336809B2B7078A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65B4577D9AA55369ULL,
		0xECF497F4ECB0536CULL,
		0x396C12C0EEAA0EF0ULL,
		0x0878F2E339C03A25ULL,
		0x81D72ACD7C120637ULL,
		0x9A69D176CB49987FULL,
		0xAA0F9EBB443A602FULL,
		0x85F6F6E6035EDBD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA4B1FE05524278ULL,
		0xD8A9AF97199CF659ULL,
		0x77BDA28D0F545601ULL,
		0x6B219907B9D4DB44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11767DF34671F611ULL,
		0xDAC5245910D23606ULL,
		0xEB23EA3CBE1F0F9AULL,
		0x1B90D0F28F8600FEULL,
		0x9DCF4FC746048F70ULL,
		0xA4D530B00306FFBFULL,
		0x3254B40EC3E63D90ULL,
		0x71A35ADA2ABBFE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E3C5587AB1F4324ULL,
		0x526A5E7983DC2C77ULL,
		0x63B6A46DD24C3313ULL,
		0x79D04D54E76DB824ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ABF0EBD0A13D5F3ULL,
		0x586F8D03E93E886EULL,
		0xAA15688924B571CAULL,
		0x210496A80B55CF3BULL,
		0xDD294A8BB2785778ULL,
		0xB75759C23F28ED4FULL,
		0xEBC57FF5232FD8CCULL,
		0xA7763BAED5452C3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE01F7987F0D566ULL,
		0x8F66DFD94951C248ULL,
		0xA96666EC5DCFA02DULL,
		0x7C91729BB39A60B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9487E24E5360F96FULL,
		0x610C8AC915F2CE92ULL,
		0x77B43C2401C551B6ULL,
		0xD49A84D25DE6256CULL,
		0x03178FC725DF8822ULL,
		0xD5303A2E2848008BULL,
		0x318D143AFC69555EULL,
		0xEDD646185A1551FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A0739DDF28F33D3ULL,
		0x06352DA310A2E335ULL,
		0xD2A53CE57967FDCAULL,
		0x2268EC6FBD1050DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x224DBDF5799EAFCAULL,
		0x7DF6DCCF322BA345ULL,
		0x93421C53EE9BA5B2ULL,
		0xAEF595D7BC78AF91ULL,
		0xD1CFC72161F2138DULL,
		0xA9DD597CE9CDA2F8ULL,
		0x2A7F47423CD141EBULL,
		0xD4F098D071822B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47254CEA038D9B78ULL,
		0xB4D22559E6B1D434ULL,
		0xE226B028F5AB6EADULL,
		0x4AAC44C895CB2179ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x045B17271115B0BCULL,
		0x5D7C8B45D875A696ULL,
		0xDA6EEB88F74FD267ULL,
		0xE45798B83A474AF6ULL,
		0x345071442458313AULL,
		0xC2693BD14078C180ULL,
		0x40DB72E8F61DD77BULL,
		0xD0A5717F04B1E0EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC84BE744762D0405ULL,
		0x391B6C556A625F9DULL,
		0x7B01FA1D7FBDCEC6ULL,
		0x5CE67192ECAEAE54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC781D2458B954EFAULL,
		0xE9C25262AEF5FA6FULL,
		0x2747C732C6510D80ULL,
		0xD8A8F3D2A06628B0ULL,
		0xD838C287D3779508ULL,
		0x0494CC26EE1B9A20ULL,
		0x72E84E0C125CE356ULL,
		0x46C8881BC88D7112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEEB26EEF556FCCULL,
		0x97D8A02A070EDB4FULL,
		0x35C35CFD801ACC45ULL,
		0x5A6D27F26564F16DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3939BE871187017ULL,
		0xF012A9C8D7E9CE54ULL,
		0x35C0A856E29655CCULL,
		0xF8557F0D5903C7BDULL,
		0x4E64BDBAC8495E8FULL,
		0x6419BB8BD9849692ULL,
		0x07066CFF4B3CD281ULL,
		0x7E73ADDB35952D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9687C5A22BFC7C36ULL,
		0xCBE4808B2198280CULL,
		0x40B4D63C0D9D9501ULL,
		0x3D814D974D288094ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EC9CC373B6D7E3CULL,
		0x96F3B7686E701218ULL,
		0x5E7C5C7659C05119ULL,
		0xBEA1B0DE476C71BBULL,
		0xE429B08585FEC86CULL,
		0x9FA9196A2614FEC4ULL,
		0xF21BDA19E5058927ULL,
		0x9948CBCFD8031A37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFA00091F3F41AEULL,
		0x4A0D7D2A158DE352ULL,
		0x4E9EBC4E5892ACFBULL,
		0x7F6FF1B857E25609ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86310693A507C3CCULL,
		0xDC78F42D89C729C4ULL,
		0x6FED69F15BB0373EULL,
		0xBB585FA5607315DEULL,
		0x671FAC5FC4258864ULL,
		0x3D26B2DABAAAEF58ULL,
		0xE5CBEF50CBD21EE8ULL,
		0x3C06899796226041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4E49CCAC29A040DULL,
		0xF03780A53F26B0E3ULL,
		0x8C32EFEF9CE0CDB7ULL,
		0x2450CC25A98D5FA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30111B61FC05D1EAULL,
		0x2A0E9F9039450B52ULL,
		0x1260407FD74DA508ULL,
		0xF4EAD4D1610CC276ULL,
		0x9015DFD4AC5890FBULL,
		0x09519CD0F97830A6ULL,
		0xA7F6754C67B1491EULL,
		0x408EBCA35D285E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935054F3912B58BBULL,
		0x8C2BE695411C440BULL,
		0x00F5A9D73B9E7F7DULL,
		0x0A1AD511350AC035ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDBD660035B9367AULL,
		0xBBC5A017A1C7C0E9ULL,
		0x85136CA7B2C37E62ULL,
		0x4B9D9AF1159B0643ULL,
		0x14F23110792F4F32ULL,
		0x89244C9C67178262ULL,
		0xB16471D1608FDEA4ULL,
		0x71FDB27BEAE25AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B0AE7232BEFA6CULL,
		0x1728FF4EEF451B79ULL,
		0xD9FC51BC081E8ACFULL,
		0x37461955F33481AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44E6D7A1FD599F4DULL,
		0xAF1CAE1B47AB763AULL,
		0x68F0F904B1DD9DE8ULL,
		0x013301ED779BF04CULL,
		0xE71E846DC71F7785ULL,
		0x6AEBBB4276ABB313ULL,
		0x8604D076C23F978DULL,
		0x3D7984EA0971772BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936E7FED8C055E61ULL,
		0x8E1A79F8E5280B2EULL,
		0x4DA7EAA5874E1CE6ULL,
		0x213CBCAADE73A0C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D8C097655E50178ULL,
		0xBC5F8683E19D16F2ULL,
		0xE9E1902844E3E63FULL,
		0xB364F3DDD0984CC7ULL,
		0x8F0BBFE0E701469CULL,
		0x6B5A1CDE38A72606ULL,
		0x32BF045783DE0FC7ULL,
		0x4D8EA6F26B9541FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA94A84D8A0157E68ULL,
		0xABBFCF804A6CBBEBULL,
		0x723C3525D7DA3DD9ULL,
		0x3691BBD9C8C017EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD078AB1D3D41690FULL,
		0x0278044ECD0A8B1EULL,
		0xC6A9DF36B6E882AEULL,
		0xB026F12A53EF7724ULL,
		0xA1B31C3432605B0DULL,
		0xBEDA9D131E60BF1CULL,
		0x8103C4EE9BDC3328ULL,
		0x0ECE2B5DB9A7E26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD10EDADCB78EED5CULL,
		0x56EB55254F66E95EULL,
		0xED391AA1D9981ABAULL,
		0x62C16113E2DB133FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73BD8A05AA95D615ULL,
		0xC8746AF13F669550ULL,
		0x34DA82BC2D049124ULL,
		0x19B5AA3EA95F6273ULL,
		0x8EC1653DBF6A8048ULL,
		0x529C4FEE7924E57AULL,
		0xACB01E6C4340AE12ULL,
		0xCAD7554EBCF4443FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA47291301464E539ULL,
		0x0BA848573AE0A581ULL,
		0xD6FF06CE289E67DDULL,
		0x35AC53EEB5A183E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ADB4445D6E54751ULL,
		0xCE14564C71B9F3AAULL,
		0xDE1FFE682E7B51C9ULL,
		0x37EC68DA6FD0BC6BULL,
		0x8554F528738C9E8AULL,
		0xBCFD58241F547B22ULL,
		0x3CFA5A3F2C20889FULL,
		0x91DDA465E8F99B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD577A846FDC4D2FEULL,
		0xDBAF6BA918443AC9ULL,
		0xEB4963C8BB4F997FULL,
		0x5ED2CFFB04DDBF0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20EFE18F29105BCDULL,
		0x170C5BA628F83C0BULL,
		0x6411770F15DD3209ULL,
		0xF0CAA4FA02F966C1ULL,
		0x519F59F488E8283DULL,
		0x10C1298FFFB7347AULL,
		0xA448515163B2C5C1ULL,
		0x0D7740094476B083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E973BDB7B86553AULL,
		0x93B887061E2A0633ULL,
		0xC6CD8923E2668CB1ULL,
		0x707E265A2C979A4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA9C821798A58AF2ULL,
		0xBC7CEB5AE60D71D8ULL,
		0xA70FBAAEB1A93BEEULL,
		0xE7D7D154D8153D60ULL,
		0x13CA67A92971F37CULL,
		0xE830FA93B4DAEDD4ULL,
		0x71BF62EDB38833BDULL,
		0x1C13724DF0E56F13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA7E533BF8FB018ULL,
		0x33C21D47BE8CBF53ULL,
		0x897869F757E0EA1FULL,
		0x12BAC8E69A23BA43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9570CA8AC4E5A0ACULL,
		0xB39BA8614DC0B24FULL,
		0x77440BEC3A709A0CULL,
		0x9981EE97FBDA07E8ULL,
		0x7340AA0C65610342ULL,
		0x94D649655A88CAE5ULL,
		0x402421D20852E0F3ULL,
		0x618FC64ADE08082EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB10A0861D14C1EB2ULL,
		0xCB6A8D6CBE0ED05EULL,
		0xFCA1111976BDFE34ULL,
		0x14D95DB4F10B3EC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF2A043E6658C73EULL,
		0xA643A6F816A6670FULL,
		0x1AB21DDC5E4325C4ULL,
		0x6552574D7731D242ULL,
		0x1440FD8B454B63F1ULL,
		0xC116338D56B59AC1ULL,
		0x313FD59DE368F32FULL,
		0x45E95C3ACDB27FF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0CFA6EAAF899E93ULL,
		0x4F8F4DF2F59B5FB8ULL,
		0x6A2BD34C1FD73EDBULL,
		0x45F60807FFB0CFE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5867F3BA4A0011FULL,
		0x3C4ED097D60BB45DULL,
		0xBC0752D04BE6C4A8ULL,
		0xEB62607A0DF8EAAFULL,
		0x258005EA99C243BEULL,
		0x6E83367EA6D5DFC7ULL,
		0x651FF3331AD004A4ULL,
		0x2844E592A77F3984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4687600E7776104AULL,
		0xA3C8E76499CAEBEDULL,
		0xBEC56C6646C77510ULL,
		0x659C743EEADB7456ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2564EC38B8DFA57ULL,
		0xD685505DD31937EEULL,
		0x21349DD54D61D0F7ULL,
		0x27558BD54600A9EDULL,
		0x10FF683DC7658799ULL,
		0x44D62648A2E62ABFULL,
		0x0AE35E010CCBBF14ULL,
		0x5201220371F9335CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783FC7EF24A01CD5ULL,
		0x0E4EFF260143904BULL,
		0xBEF491FD33A02DFAULL,
		0x5380985830FE4996ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x616C0B8710D172DEULL,
		0x7548C6FB835D1F61ULL,
		0x1B2FEBC6CD7AEA8FULL,
		0x47ACC5297CD943B1ULL,
		0x85635E65EFF6B94FULL,
		0xD0D8024D9750CADDULL,
		0xB406DA429B880564ULL,
		0x89E5E6E9E27B92DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E2C0EA8AF70F7A3ULL,
		0x75591E7FF95B3C43ULL,
		0xD43451A9E3ABB786ULL,
		0x3FCD0BE11B31104DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FC11EBE09177C2CULL,
		0xB67B90179FCDF943ULL,
		0x3FB6D3DA2EF854ADULL,
		0x5951AC6C6394F276ULL,
		0x0F5727CA38B8491FULL,
		0x332ABBC5245E1307ULL,
		0x6D90985F8C3A36F8ULL,
		0x0FCF385CB3901DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B106C274725725ULL,
		0x4ED36F5B05C4CC4FULL,
		0x832D7208FF9C7D85ULL,
		0x32140A2F0AF960BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D42E5997127106DULL,
		0x0520C8D9AC0AB6FEULL,
		0x791769C1FA314939ULL,
		0x5AC50BD309BBB84AULL,
		0xD5CE806B25873207ULL,
		0xC7613827BDD1C7BAULL,
		0x7DE70F2F2FE080B9ULL,
		0x2B00F66C3202DD57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E9F58103387E6EULL,
		0x9D8F1EBFD92E5CBAULL,
		0x2963AAC3158464CCULL,
		0x3CE99FE276289347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A97BBA2E9A58056ULL,
		0xF58DB381CD2D780BULL,
		0x691E40BCBACEDDC1ULL,
		0x086C7151DFD82808ULL,
		0x0C87AD6FD531A35DULL,
		0x7B54244757935439ULL,
		0x30C0FD067882CF0DULL,
		0x535D09839293BB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56BB7A3C8F03C1ECULL,
		0x440B1618CD0BF883ULL,
		0xA5C3CFB29E3999C2ULL,
		0x683BDAD9A1C5EFB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFEEF54D9CB7411EULL,
		0x130D7B41278BBEA3ULL,
		0x5E51686B04561F65ULL,
		0x69A7A092D7BC50D0ULL,
		0x5364AA88031D2CB4ULL,
		0x8EAF494A97737DFBULL,
		0xC8F9206C7ABB9176ULL,
		0xE9D3406796F0FEBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60E0457E130BE908ULL,
		0x41125C53A2B071F2ULL,
		0x334C38853C2DB6FEULL,
		0x1F032FF33F8220FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD00980A27F75C5AULL,
		0x20B175FEC12F5D6DULL,
		0xD3B9FA4C03453CB4ULL,
		0x2E0CB21240F6FF9BULL,
		0x66C6FB657868328CULL,
		0xBF1D45547AA0BE46ULL,
		0xCB19C897AAE423BCULL,
		0x40F9389EE2A9700EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE89E91A076EDE8BULL,
		0x7F09C088F50B9BE0ULL,
		0xF98DC0CF61228AB8ULL,
		0x530B19A7E61DA1CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4131E500AB26DDF4ULL,
		0xF7C2071EE5C0E8A0ULL,
		0xECB748E3E34C6C63ULL,
		0x382E772813C4DD00ULL,
		0x7613ABFED34D153FULL,
		0xD0FE264D120DD0CEULL,
		0xB1D98F32538169E0ULL,
		0xA663B1D080253177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81D6CD4089808F1ULL,
		0xFD7BB68F93CDE745ULL,
		0x53028A5C488223C2ULL,
		0x6AFADC1B194A34C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB113B7C266C1BE52ULL,
		0xE5F7C6A1F06093F7ULL,
		0x39C189E5CB0CCEF4ULL,
		0x58444D7BAC7590BCULL,
		0x29EE185FA11D44B0ULL,
		0x3E7EFFAD852904B1ULL,
		0x0EEB7BC3903717DBULL,
		0x71AAE4EBC2D5FAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA6B55F45119F2F8ULL,
		0x2CD1BA63B4774643ULL,
		0x70B5E8ED333A5980ULL,
		0x37A2487A9838C4CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F1BD7D63BB13DBCULL,
		0xEC22DE7D120E98B0ULL,
		0x91ABC8D23C162F0FULL,
		0x03FACC64254DC47EULL,
		0xD3B168B0DBEB3743ULL,
		0x52E9A21CB963ECACULL,
		0x5308B24E8391302AULL,
		0x5DB0C3476D2409E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB716216E09B73AFULL,
		0x3AD0EEC096E3BA57ULL,
		0xE4F64079C3A35558ULL,
		0x6C37C8FE58A73BCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37B33669675CC62DULL,
		0x81C0671DCFC054F0ULL,
		0xC0620B2AF6E3EEA5ULL,
		0x0042156C50D3C763ULL,
		0x3F74C68E765C1F78ULL,
		0x8B90B779A01482DAULL,
		0xBAD29D0890AA7547ULL,
		0x4C098E78DA452673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA308AF8EF909739FULL,
		0x393BA32B92CBC155ULL,
		0x7BA55A7070315744ULL,
		0x49AD3B5CB7177C91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87D2C46E8392BA46ULL,
		0x6E4088FF9257FA4AULL,
		0x08B74768D2A04B0DULL,
		0xF5A3A71ABF67D9D1ULL,
		0xF9980067C232C603ULL,
		0x54D0C7EF018356CDULL,
		0x1B44750FB74C2EACULL,
		0x345E1A0EB87E357FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9462D3D5571C1FFBULL,
		0x053E3679CBD6DCDDULL,
		0x14E0A7BE07EF38A2ULL,
		0x3B9B854A2223CAAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10D90B8B2DBC4BF5ULL,
		0x879F827C4306BDBEULL,
		0xC9FAA36F7E060BBFULL,
		0x706ADCB5F592F03DULL,
		0x653D63CC844462B6ULL,
		0x8E8C3C629DB23AA9ULL,
		0x5F0C0C37BFCE65F7ULL,
		0x3C558252553C2F0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F5DBE6CFE2F44FULL,
		0xB070791FAB7B72E3ULL,
		0xE5C473B5F6A92E7EULL,
		0x651C34EE9C81EC85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CC8028ED78A82F8ULL,
		0x63438AD189DACD70ULL,
		0xB049A1CC90F43F27ULL,
		0x774CAAE1E626C255ULL,
		0x47004695AD779C4FULL,
		0xA5E7CC77F196B5CEULL,
		0x43D601B56AB54EDEULL,
		0xC84F4DD956C35467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D27CC6974BBB26ULL,
		0x03ABE49F6639CA0EULL,
		0xC20DE2BA67DDF434ULL,
		0x33123924C72549A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x390894682116DAAAULL,
		0x6457FFB822C8B705ULL,
		0x56492FA488408718ULL,
		0x7FD30C440282EB5AULL,
		0xCE6FFD3C7CE83F40ULL,
		0x340B189F68B0E5ADULL,
		0x5D2FF7171599C440ULL,
		0x4979FE24BB3038FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDA82B62AB903FCCULL,
		0x1DFDA761AD0ACED1ULL,
		0x2B67DD11BD13A8A0ULL,
		0x67EEC5B7CBAB6142ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAE65A532DAE8061ULL,
		0xEAA22C4D6EF6EE65ULL,
		0x27580F6D60B0E395ULL,
		0x08E871E0BC331CC5ULL,
		0x23086BCC2C4B60A0ULL,
		0x86C41F38FD087E7DULL,
		0xEBAE8E52BF2FC1A3ULL,
		0x240886F1AD0CFB6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE265AA1C0DED8DFULL,
		0xEBBECEC2FE39B4F8ULL,
		0x23412FB5C1C7A1DBULL,
		0x622C79C06C206F16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC025BFEEB0716229ULL,
		0x8C4849C4B2E814B9ULL,
		0x22147DAA65C741F8ULL,
		0x389B879D87C32290ULL,
		0x038F136259B7E9E7ULL,
		0x8D143C9C00635B9CULL,
		0xCF30BFFB979AD019ULL,
		0x1CD70D6AA56F736AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4762A08801BE1B1EULL,
		0x7D4948ECC1A7ADE2ULL,
		0xE350FD02E6C225C3ULL,
		0x00878572164E446AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E4DDBC733CB7988ULL,
		0xA1B66A64F8BF43A4ULL,
		0xE4FF8BA9D69AC9E2ULL,
		0x23EE1F176E9E6241ULL,
		0x20146E3702DD0B26ULL,
		0x438DAE1CE4F0A6A8ULL,
		0x5885D2EC4C65701DULL,
		0x0F5EEF590BD9F14DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x315637F1A09B2178ULL,
		0xA8BE42AEF4780099ULL,
		0x08DCDABD2DA96E3AULL,
		0x6C05A64F30F833BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E381689F620ADC0ULL,
		0x84A8FB12CE5A7E4EULL,
		0xDEA4DDEF7B1CBBF3ULL,
		0x395D7B542830EA65ULL,
		0x533BFC4687C13718ULL,
		0xF5C700DDFC2D81C3ULL,
		0x8F129484D8EBC0F9ULL,
		0xFDF9AD61F9F65E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x791F89021CCEE0E1ULL,
		0x00331C063D1BC14CULL,
		0x1B66E9A7AE1B610EULL,
		0x6C6D37DF42C2F155ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7230E530BCEA405ULL,
		0xF0092ACB88C4B6E9ULL,
		0x27FDF480BAF5440DULL,
		0xD09EBB6D2412F4FBULL,
		0x823135B12F684FCCULL,
		0x79F42E847BC13BC0ULL,
		0x40929D34790096DAULL,
		0xEE548F5682C07FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7106A0154A81A5ULL,
		0x0A481275E773957DULL,
		0xBDC14A4AB10BA87CULL,
		0x312C02448CA5E7F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1855142AC6C46CDDULL,
		0x26FB70733792CB7BULL,
		0xB2497DFE76F2EA52ULL,
		0x2C17828AC4FEBC5EULL,
		0x50FCFA95CC47AFFBULL,
		0xC14FB8E7154136B9ULL,
		0xD5399F15351657FDULL,
		0xACAA33B9D2EACC96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DE2466719688FE8ULL,
		0xD8D0E2C05F40EAFDULL,
		0x58D71B245843F9FCULL,
		0x4D5B302013D91AC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77E0063297C989D9ULL,
		0x615BF028CFCE160AULL,
		0xC2227596037AE913ULL,
		0x3E13028CB1DAD12DULL,
		0x26601CEC993B2DE0ULL,
		0x935AB7950080A046ULL,
		0xBF8355A15A9B5372ULL,
		0x8D07987D6602F14DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A24515156925C37ULL,
		0x40D33046E2E5E074ULL,
		0x2FA12B8976894C15ULL,
		0x2D33A529D64AA2B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54C01982E3683CC6ULL,
		0x9976CE2C1FB3D529ULL,
		0xA68A1DBEC0557493ULL,
		0x4323F9E903CAB3F1ULL,
		0x3B04B82FE6FF9402ULL,
		0x991482CC3DB5742BULL,
		0x1DA677BA586E80D0ULL,
		0x0ABAA2B72D790C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1773709F2D58354BULL,
		0x5282387D48A31394ULL,
		0x0D3FE367E0BC938AULL,
		0x5AD82119C3C28680ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68E34C46473AD125ULL,
		0x8196883FCA9DFAAFULL,
		0x7A0A5FECF6620A39ULL,
		0x48B762C495ED0BBBULL,
		0x5406B43674AF8B97ULL,
		0x1B42F180B1D2E6AFULL,
		0x10BEDE4ABAA8762DULL,
		0x2E1B1920938796D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1E20C5B99498A99ULL,
		0x8D86615A2FEC38B5ULL,
		0xF65F5F04AB6394EBULL,
		0x20BD1D9A7C0D6F0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2046336476025D2ULL,
		0xA595B86B60BF22ABULL,
		0x8CD4F18BEDADCEB4ULL,
		0x8EF043AF21697EF2ULL,
		0x2D5594BB47BD8045ULL,
		0x0DBB7026ED4FFE29ULL,
		0x34D73EFCFBB759E8ULL,
		0x20FA2DA9225875E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB87702ED8130CEULL,
		0xAF685E329A9EDCC8ULL,
		0x64C84B194AE52726ULL,
		0x74130ACA3A8AFF6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36D1ADDD02A50597ULL,
		0x447AD048CFE552E9ULL,
		0x8A6E013D11D69C5BULL,
		0x822E9A2E24E8DD27ULL,
		0x21D220D576770896ULL,
		0x35D93A4AE7451CE3ULL,
		0xA455C4638D40EBDEULL,
		0x56CB37826463F84DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C028D8C98504DC9ULL,
		0x42B9776724279CA0ULL,
		0xEF29280409799F57ULL,
		0x6458D7890BBFB8ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD83AE5F40D9653BDULL,
		0x4887E39B3C061541ULL,
		0xA052A64351E07709ULL,
		0xBD279E813E7FE87DULL,
		0x7C9C1B4EBE7ED50BULL,
		0xBB227E61A8A025C7ULL,
		0x7B1B71A7EBB776B6ULL,
		0xF8014EF8F9C59232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5766F3A45469F8F0ULL,
		0x0FA6A61A43CBB0DEULL,
		0xE66585304F1C1629ULL,
		0x0D59577651D39BFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCC6E7309582192FULL,
		0x88FF9CC170396A49ULL,
		0x6D7BB402251EE601ULL,
		0x24DB169AA9E4944DULL,
		0xEA3B2F6766CAE88DULL,
		0xAE5CDD358A68AEA3ULL,
		0xAD40E6BEC64544DCULL,
		0x21F951CEDF3AA480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC18FF089D7A09EDBULL,
		0x6AC872B3FBC3569EULL,
		0x251DF45393671EC3ULL,
		0x2FDD3B4FCC98FF67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63395C1C0A4BC4A5ULL,
		0x249B4620E1616C28ULL,
		0xB60BAFAEAAE49BEBULL,
		0xF6C4990CBF69DDB5ULL,
		0x3F55B5757B26E2A0ULL,
		0x8F7EE126C3E1D42BULL,
		0x5A09E1F69B6873F0ULL,
		0x7641287B56DED628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F24B8C52116B24ULL,
		0x7170B1E1F4E6EA93ULL,
		0x13833A49BC65D1A0ULL,
		0x04709B5BA47DA7B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86DE252529D0AD64ULL,
		0x6592DA281C7D09C2ULL,
		0xF9F155F1493D8A70ULL,
		0xD8EF7E235C9BC953ULL,
		0xE77F0443EB0D0A2DULL,
		0xE6BCC11C1E09D8A4ULL,
		0x9BF5A0B9075747E0ULL,
		0x46CD559BC5F07266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B8C73A0DC031B4ULL,
		0xA597845491F3323CULL,
		0x20673168603235D2ULL,
		0x5B6A3342BE4CC48FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B7A89B3A4E26482ULL,
		0x78E9CA4CE827D179ULL,
		0x6701D0BAA7FB6731ULL,
		0x5CC7705F73C158A4ULL,
		0xD0438AA758EC70CCULL,
		0xA2DE8CA5202157FEULL,
		0x44EE82F04566BAA4ULL,
		0xCA77418D905F2546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65811E8AD7FB273EULL,
		0xA5F2AACFAD1AE14CULL,
		0xA2694064F53B1BA1ULL,
		0x6A7B2B62E1E0E112ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FD2D9A2A8E95C05ULL,
		0x9598429615DF3940ULL,
		0xDB2A7A27C11E225DULL,
		0x810867C5C94F760BULL,
		0x902AF5E7B5AA11D0ULL,
		0x5FC9960508959092ULL,
		0x688042F651CB7CDEULL,
		0x1721B4947B8E58A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6335A07A028016AULL,
		0xCD8487555C12AF01ULL,
		0x5E346AB7E552AB5FULL,
		0x700935D020709E27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57E8AB45C594D314ULL,
		0x6899FE1C0CD82F87ULL,
		0x9A6EC6519C18C40DULL,
		0x33E04FCC0E043B50ULL,
		0x2ACCFB83F662A091ULL,
		0x1FA4ABA9AD1903A1ULL,
		0x8E05E848E3639AF0ULL,
		0x23B97F59DAC73169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB25600DC5838A96BULL,
		0x1B0B794BBE8EB973ULL,
		0xAF4F41235CE1C3B2ULL,
		0x01693722879590FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE629DF6AEA1CE737ULL,
		0x6DABF03EFEC3CF0BULL,
		0xEEFE6C21EB68693FULL,
		0xB59CEBEA86F76DA4ULL,
		0xF9CFE0372F7AA1DFULL,
		0xCF3573D020A4582EULL,
		0x8A4E4EF7B8C471CCULL,
		0x0EB8E3B0DAE11781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB05279BF650EEB0ULL,
		0x2F9B2123D728E604ULL,
		0x769E24E758914DA6ULL,
		0x650EB82B0460EADFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEA95AE890FDE5BCULL,
		0x02F84EA47FD9BD47ULL,
		0xF5AB750AF217B97FULL,
		0x1B4A00B62C93DBC4ULL,
		0xB35DB4F444E77715ULL,
		0xCD35A87148184096ULL,
		0x59AF10CDFD050843ULL,
		0x5095597956FEBCE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E92372ACB5994A2ULL,
		0x78EF4F75337353A6ULL,
		0x45A7F39E80D6F38FULL,
		0x117548B91663E642ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CA277E91FF40EB7ULL,
		0x05B392CCB9B5659CULL,
		0x0DD7DA7E30497267ULL,
		0x7AF843E30C2A1764ULL,
		0x737FB975EE033BF3ULL,
		0x2AA87B6B895E4AD0ULL,
		0xA63DBDB556559F20ULL,
		0x637305CB544499FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA197FF6A746EF703ULL,
		0x5AB5E4C31DB4808DULL,
		0xBB02036900FF112DULL,
		0x3E0B20118E58F356ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD9FEAF53CEBA259ULL,
		0xBA4C44C7C203483FULL,
		0xDC99BCECFD7F15B3ULL,
		0xA6ABE4A1A676ED1EULL,
		0xF7EDD11B5E374DFFULL,
		0x0E9013E30FDEC8FEULL,
		0xA88227B06F72E11FULL,
		0x87DF2521BA794D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAECF5053921393EULL,
		0xE3AF387C1D151E18ULL,
		0xDFEBA11D888C804FULL,
		0x51CB67A354786529ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1754CF56B019EF66ULL,
		0x46018808A3311761ULL,
		0x11464A1EB4ABFFA5ULL,
		0xB0A07F514B266C96ULL,
		0xAB0B4FFD687423FEULL,
		0x7A0CB0856A13CEC0ULL,
		0x51A4DDFCA25711CBULL,
		0x25A76835D2A43559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B02AEF4315747FEULL,
		0x63E3BBD66221C7FAULL,
		0x2FBF3D9ECD98A3D9ULL,
		0x4779F74E8F8657D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4147374C92A9C362ULL,
		0xAB3741AF7A20D7A5ULL,
		0x175D1FFB022E6CDDULL,
		0x50A5A2913F594E40ULL,
		0xCBE876A20A6EF6E0ULL,
		0x6646587A8B4EA1AFULL,
		0xE02C419CF7F29F61ULL,
		0xFE7E99C0A5CB6D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C8D35A1F226E46ULL,
		0xD9A863E027CCD7BDULL,
		0x5DEEDD47D0321552ULL,
		0x17707529DB8B8523ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEED48F5F72B6D686ULL,
		0x69DB6216150A3A62ULL,
		0xA8DE2E516CC040DCULL,
		0xDBD3B0B33867DB06ULL,
		0x5ACD1764C8CBA715ULL,
		0xEFF9F96612D0D8EFULL,
		0x26FBF39DB61DA73AULL,
		0x50405F6B02B9AC13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6946085540F1A57FULL,
		0x08F6673CE00A6DEAULL,
		0x724457BA7527139CULL,
		0x4561DA959FF765DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3725CB8E3ADE9F2FULL,
		0x94B54D5D1E750039ULL,
		0x5319A105EA0E7EBFULL,
		0x27C70759988E5831ULL,
		0xE7621CB7B2FBA57EULL,
		0x7754424B441F8732ULL,
		0xF4B103E8AFE8F1BBULL,
		0xFEBEF4802CD49DD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB60ED2CC393574ULL,
		0x4B3724893B2311C7ULL,
		0xA560359006A26093ULL,
		0x781F5260401DC5CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18BABC7C82B090EAULL,
		0x1F2FA5840FBEED93ULL,
		0x7132CECBB5FAB6A4ULL,
		0x31D179A3FE71507EULL,
		0x294DBD6F74050592ULL,
		0x26BD5AA2EA20CA2AULL,
		0x46223D264318FD3BULL,
		0x82CA0FA406502321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A44DB07BB6F677BULL,
		0xDF4B19B2D09CEFD5ULL,
		0xDA47E279ABB04D6BULL,
		0x1BCFCBFCEE56876EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35A8ADDA62E66B3AULL,
		0x9D6617F4BEE883CBULL,
		0x1480500B4E8458F8ULL,
		0x627BB8B635BB9459ULL,
		0xCB55D01418D74FDCULL,
		0x2B73161CB91353C6ULL,
		0x7235C575A6F4DBFFULL,
		0x64CDBCC616F59012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x646590D612DC481CULL,
		0x107B603837C6F34DULL,
		0x087B9F8216DD00D9ULL,
		0x5905BE1D9E2EF716ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0C5CF47B02CBD75ULL,
		0xEBD46D9590D5EE2FULL,
		0x2579A0B58130C02AULL,
		0x190EA47DBB6351F8ULL,
		0x9CE70CE2C0CE4850ULL,
		0x1C7AE36F93AC8073ULL,
		0xA09A5841ABFDF731ULL,
		0xEE5F3732311D2F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB11B8F04ECB7E87ULL,
		0x261230257C70FF58ULL,
		0xFC62BA7508E37175ULL,
		0x7B30D5F105B85A03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C121EB7C85A29C0ULL,
		0xFC476193232993A3ULL,
		0xC32351AEA6255CDBULL,
		0xE02BDC3C216BC8D8ULL,
		0x47240507A01A5F5DULL,
		0x992FF350A5B5367AULL,
		0x32E48BC610ECF26CULL,
		0x99F3BBDBA566C1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6ADDD98C44550BULL,
		0xB9657F8BBC0FA9CAULL,
		0x51101115295158FAULL,
		0x3A59BED6AEAC8D02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF28417AAFD0EA7ADULL,
		0xC3C734F57B41A7A9ULL,
		0x71F0EB5157441C56ULL,
		0x0ECAF72A820F8AB2ULL,
		0x5DD1EF923BC40676ULL,
		0x6E5C97A6EC67185EULL,
		0x78EA01DF66880127ULL,
		0xC4629A238C18CBE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFADA75FDC27A17FULL,
		0x2585B7BC928F45ABULL,
		0x64AD327A8F744831ULL,
		0x356DD8714DBDCF34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x356257F17B21EDB8ULL,
		0xA51ECD6E52A4544BULL,
		0xFB2C22C2F9C59DE0ULL,
		0x958F2F9E8A4492FAULL,
		0x65BC2F9162833FD7ULL,
		0x1E27B1497CC49CF5ULL,
		0x034EFD0B3A96AA7EULL,
		0xF25335CD163775E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F5167861A9D6D0DULL,
		0x1F031E56D7D3A0B8ULL,
		0x78E5B26DAC22EC99ULL,
		0x0DE92C0FD6801391ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B439C2E55F5EDDULL,
		0x57FD9B945A523E84ULL,
		0x80FB45152253BDB7ULL,
		0x07062CD62CDB9557ULL,
		0x77079FE5131F8602ULL,
		0xE80BA92119C8612FULL,
		0xBD3E6ACA00AB8B5BULL,
		0x4118821380EDC96FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BD5F5C3BC0D4492ULL,
		0xC9B8B67E2E10AB90ULL,
		0x983F1F113BCA6D5BULL,
		0x30A97BBB50277BEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x171046245AE24F9DULL,
		0x463EC08932933609ULL,
		0xF2C3C49ECCFA8020ULL,
		0x46D18D9B295CD3C9ULL,
		0x6CA717B3FAF318BBULL,
		0xA4C123B2F86FCAACULL,
		0x2EA2582CFB5F01FBULL,
		0x4972E36A8C122FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37DDCADB9AF7FD01ULL,
		0xBAEA0D1A132B4BA1ULL,
		0xDEDCDB4C1D14CB7AULL,
		0x2DDF4F6BF40FE628ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE791367A43421FBDULL,
		0xC128B5CE3B7C1975ULL,
		0xBD31F8D6A35D110FULL,
		0xF9918DEF44800077ULL,
		0x31F88DF642940C8EULL,
		0x67409D1C8E35715EULL,
		0x690CC2358583B014ULL,
		0x0646EEF51A553020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52764908253BFD0AULL,
		0x14C0080B576AED71ULL,
		0x5516CCC874E93417ULL,
		0x681906512D252547ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44B8676F1A1084F3ULL,
		0x421F1E3F2D2A262AULL,
		0xA99F7C95BED2FC8DULL,
		0x93B77486F1EC52DFULL,
		0x23066E546D47AFDBULL,
		0x3FCC29FE2B006F2FULL,
		0xED63A5E1CE2A9305ULL,
		0x83570B9262236703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77ACC7F752B4A26DULL,
		0xBA6D59F98F3AA729ULL,
		0xE66A1C1A5924CF54ULL,
		0x12A32C41832D9D74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE05772386C9E6BCULL,
		0xCDD7F78ABCDCBEECULL,
		0xE35E15968515C70EULL,
		0xFB67510CD17A1108ULL,
		0x44C3E584D53513CAULL,
		0xF10821A37153C5C4ULL,
		0xFA1832ABF8BA2BEBULL,
		0x227E2ECCE2C2F49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x331988DB2CAAD79CULL,
		0x950CF5CD8F4C1A0FULL,
		0x02F59B1D70B84C14ULL,
		0x1A2243767A6A6056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DB2389FF4FD9974ULL,
		0xAB95842002BE88B3ULL,
		0xACB4EAEECBAB73D1ULL,
		0x97E603EF536ABDE8ULL,
		0x0EC79B7B324F9D1CULL,
		0xDEE780721438D5F8ULL,
		0xA0458B0F6B1CD376ULL,
		0xEBA8E8C089147982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F534CE96CCEF0E1ULL,
		0xC1F2950F032E4B85ULL,
		0x77078F38B1F2D776ULL,
		0x12F89083AC74C74CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19E0502A045DE85CULL,
		0x352100AEEC5BB216ULL,
		0x748D2B7ED8BF125EULL,
		0xBB6FACC330869199ULL,
		0x19B239BADF32DD39ULL,
		0x767621A972735555ULL,
		0xF383122B60EFFCC2ULL,
		0xF9B7649C49333A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA54E1E725EAC463ULL,
		0xCAA9FFD5E97A5CB7ULL,
		0x9A01DDEF3C5E973BULL,
		0x4CA89BF60E213D53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x814682006368E20CULL,
		0xDE0742CC3DB85627ULL,
		0xF3C4F2F199723ACFULL,
		0xBD526778A7A50CF4ULL,
		0xAFD8CDF239C4CBB5ULL,
		0x8249932F6B870B4DULL,
		0x84E8D6980E3970FDULL,
		0x48489740648188CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7513F4F69F208CULL,
		0x34F31BD633C403AFULL,
		0xAE54CD83B5F90071ULL,
		0x7818DB0792DF5B9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56656AF0547760A3ULL,
		0x23E114BAD7622B55ULL,
		0xCC48D1970B6E3E97ULL,
		0xF2EB38254F3BECD5ULL,
		0x73746AB401551B52ULL,
		0x1E1D382B74E2E60AULL,
		0x828684128FAAFF0DULL,
		0x45BECFE6C99E04CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79AD41A887197071ULL,
		0x9C376B2E311050E2ULL,
		0x2C406C585ED01A89ULL,
		0x4D3E14673CB0A331ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA96A23A382AE2C66ULL,
		0xA28FE14BB80ED518ULL,
		0x6B44F3D30C0A5F79ULL,
		0xAFCCA122A2206AD3ULL,
		0x984340A49DDE4DC5ULL,
		0x2D63677A2C6DBCC5ULL,
		0xBB3C3319EB0E2B24ULL,
		0x56C4BFD78980BC2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4365BC12F1ADB9A5ULL,
		0x5F513D6E5058DA6DULL,
		0x363489ABF024C6D8ULL,
		0x11011B210B3C59C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33E11EF2E3EF5D09ULL,
		0x228F86478C3832AEULL,
		0x297A5D7975734FC0ULL,
		0xCFE060EA1E328AADULL,
		0x146F955F42666D36ULL,
		0x06FC473470C19C91ULL,
		0xDC10765439C62E0AULL,
		0xEDCF8846B1F324C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C714B16BF239865ULL,
		0x2C02181048F57037ULL,
		0xD3EBEDFA08DE253DULL,
		0x1CAE9B688849FF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD6B622F097A7E7DULL,
		0xB7997A214F7B845FULL,
		0x2D606647C4145A80ULL,
		0x8B5BA54605759DB3ULL,
		0xDA18FDD5DFB1641DULL,
		0xCECC242520623D5BULL,
		0xC0CB44A9FA5CFD98ULL,
		0xDA95B74457D25F07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D210FEE3DCF5F9EULL,
		0x69E6D7A41E10A002ULL,
		0xCB8C9782EDE1FF2FULL,
		0x7D94D96B0EAFB8D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF972B041EC931884ULL,
		0xB3BEB6767E3D6F8EULL,
		0xDF1365043A26017DULL,
		0x82220AB35E9043EEULL,
		0x5310AA087A536325ULL,
		0xE6E93061D66DFD10ULL,
		0x4FA145B9733B05C5ULL,
		0xCB8901FB517045ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEBED8414F3D489ULL,
		0xFA5BE4FC5290FFFBULL,
		0xB103BE8B54E8DCDDULL,
		0x38785601753A9BA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7CC4EE853F7A334ULL,
		0xCC0FE5D5F6387F0AULL,
		0xD630AA4A67A6244FULL,
		0x81AB6FACE00ACFE6ULL,
		0x4C6DEAC3AC86B5DBULL,
		0xDDF412A9E0DA0BAAULL,
		0x75C12EDB69F7A1E3ULL,
		0x60B86EB2899CD170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501D27F3EFF6A3DDULL,
		0xBE4AAB0D56963A52ULL,
		0x50DD9EDC22682C22ULL,
		0x5D0BDE2D4D51E698ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD777BD9B16C707F9ULL,
		0xD414D14CC4D1A55CULL,
		0x234F1982987C30FEULL,
		0x3AAB201749C600CAULL,
		0x7AC5B9BAF3BFEE7AULL,
		0xC97F3E7693845BF2ULL,
		0xFA68BE0BF8289087ULL,
		0x6AEEE97F5A7D24B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10D14F5B45447075ULL,
		0xBCF816E6AA774B5BULL,
		0x4EDB4F496E81A526ULL,
		0x1A21C8FEB8597465ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8806FA18B80D0870ULL,
		0x73ECC30738A20999ULL,
		0x04C849B6D3CC0E24ULL,
		0xDCAFB722A6DD5885ULL,
		0xAB6382EB0BAA12D6ULL,
		0x5C4BC9DF1153629AULL,
		0xFE401EBE7E53477CULL,
		0x3938FEAEDFA248F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8CC68FC734BD58AULL,
		0x272CBA23CB02AC8EULL,
		0xC24CD9FD9428AA9AULL,
		0x5B258517D8F42C4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0FE98DD68D52DAAULL,
		0x17C9A5B0B9D95647ULL,
		0xB4E0A9C673B657ACULL,
		0xCC4C7FD70C1C924AULL,
		0xE24442B2385FBAB3ULL,
		0xF85125B40ED4599AULL,
		0x7B462F3D33A4918CULL,
		0x6094464E654F1FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37207F51C70AE676ULL,
		0xF3D53E6AED5EA345ULL,
		0x014BACDC1E23F298ULL,
		0x224EEF7A15DB4D2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x682C0D7FA1541857ULL,
		0x0310C724B6112282ULL,
		0x38736C32A87E240DULL,
		0x773924B2671C9624ULL,
		0x459D749336DC4755ULL,
		0x013B244A4EC9400EULL,
		0x3B9CEEE21553C8FAULL,
		0xFADA571CF4B25370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8B5B59C606B486ULL,
		0x31D82A2C67F0A4A0ULL,
		0x11BEE1C1D2EDF929ULL,
		0x33A212FEB994F8CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C3DA4ED96257B04ULL,
		0x8A35A87BB74F4780ULL,
		0x52230E228B4CCDD3ULL,
		0xFE3254C49B439F82ULL,
		0x01D6AE5DAF97E999ULL,
		0x7F20ABA2A3466710ULL,
		0x6754F3ED8CC41875ULL,
		0x70A0260A30BB40FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921B86D5A6B22A53ULL,
		0x690F229FF3C293E0ULL,
		0xA8BF436570686F44ULL,
		0x35F7FA47D70F44ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70088F84B84EBB37ULL,
		0xEE166CA45D4906B7ULL,
		0x4C6BC91CFFA88AB7ULL,
		0x5523412CA1DCB52DULL,
		0xFEFF299862010BF7ULL,
		0xF76C67B2DB884325ULL,
		0xD244FC4098B374D8ULL,
		0x28DC0D5D01A2A232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E8BC23447682C5ULL,
		0xA82DD130F382FE5BULL,
		0x82A93AB3AA4BE2ECULL,
		0x65CD3CFAE000C8B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D2F1BFD272AE974ULL,
		0x5ADC269CB0A9CD4AULL,
		0xF48674D68744BF95ULL,
		0x70867E2438D18985ULL,
		0xFDBD91375DA2012CULL,
		0x0B415F7918DB2C5BULL,
		0x575EAD58C483A84CULL,
		0x74B43B1596A90EE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3752AA350D371895ULL,
		0x06905296613262F2ULL,
		0xEC943003B2CFBADFULL,
		0x4347435895E9BF1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A22B88371181444ULL,
		0x86893AABB6C747E6ULL,
		0x8A5AA9A5058557B6ULL,
		0x4012782937EED8BAULL,
		0xE1456E16515BF4D1ULL,
		0x3FEA4464BCC5C2CDULL,
		0xD4BC94C7C594D00AULL,
		0x9231C8EB5BA8DA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A710FD384BE6E7BULL,
		0x034F619FBC223275ULL,
		0x1E58BF4C599C393CULL,
		0x73764B18D2FF3656ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ABBFBB186E4E4EDULL,
		0x1D79C447C6DE9617ULL,
		0xDE084B6C67040BDCULL,
		0xCEF2F40251C4374DULL,
		0x704C31732FAE3BF5ULL,
		0x06691223C0F7B762ULL,
		0x81512F8E0754BBD0ULL,
		0xD6937F9CE8252D64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060B52CA9AC1D01EULL,
		0x111275966BA3CEB4ULL,
		0x10155A817D97ECBDULL,
		0x28D7E54CC748F439ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1396877490D1512ULL,
		0x64ED187B13C140C8ULL,
		0x2AAA92D476DBFE30ULL,
		0x0E296D2C807A8BF5ULL,
		0x312F8A8B0CC0DB84ULL,
		0x530F366E50FAD69DULL,
		0x34BD7CD8216C7704ULL,
		0x627F914907DEE07BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E47F91B2DADACD1ULL,
		0xB92F2CDB18FD1C1EULL,
		0xFECB1AE96CF5A8D4ULL,
		0x2D18FE03AB8FDE3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44CA95645C875868ULL,
		0x6C14BAFBB9FC7A84ULL,
		0xE583F5A12C1E59E8ULL,
		0x466FB88AE5F50E4AULL,
		0x2342DD0B6FB7AD1BULL,
		0x92E855483A87CEDAULL,
		0xF31E4B8A44E8E193ULL,
		0x2CC62992FB5D8E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B76516F1CB0B61ULL,
		0x3A9163B46A252EE5ULL,
		0xFC032C2766AFD5D0ULL,
		0x6BD9E45C35D82CF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FD9329C159B5A0FULL,
		0xB860F7C01432C3DAULL,
		0x7519DDC2F8F12D06ULL,
		0x328CC72FEB4E0F12ULL,
		0x7CF95F5A9D3CB472ULL,
		0xF8EC1F74445BC681ULL,
		0xB406E49E9BA4C288ULL,
		0x3BEDB8BCD4E55720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDD5A0F6C9E2451ULL,
		0xAB6DA30239D23B12ULL,
		0x2E1FCD4E13660D5BULL,
		0x17D633378558FDEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CAD5589EA527F67ULL,
		0x97DB6D629BBF8483ULL,
		0x5A6363A0A4AACE4EULL,
		0x285B6ABD5C0D42E1ULL,
		0xC62FBDC0EA5059CCULL,
		0xEB919C54FD0840AEULL,
		0xF772017550A9D57CULL,
		0xC18B7D4C4B233DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C3802CB23FD7EAULL,
		0x8F78A2002AF91E74ULL,
		0x154F9B0A9DE07ED9ULL,
		0x631004108348753EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B035BC04EDDB48FULL,
		0xF443DDEAC3577755ULL,
		0x3BE45FCAAC520103ULL,
		0xA2E47CAFA1EB700BULL,
		0xBA56ECF243573546ULL,
		0xC7A3670834C72A57ULL,
		0x3F3496EF5F1F2882ULL,
		0xFCEFFF9D27051217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43EA87B64DCFA297ULL,
		0x9685292298E7C05BULL,
		0x9DB2C752CAF2046DULL,
		0x2E846E036CAC1F7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98F5B1FCD65D5D3CULL,
		0xD75C4EA0798948D4ULL,
		0xFCA51C8987611CFBULL,
		0x572667D831AB6E66ULL,
		0xD31CF6F1F22436E1ULL,
		0x97DC9AC38925E05EULL,
		0x01124EB0193AC38DULL,
		0xDC142038876D9A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4259E6C7BD8788ULL,
		0x621B47A6D52896E7ULL,
		0x255CCAAD461A2400ULL,
		0x0223303C4BF04E1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D5122AD2598EC76ULL,
		0xA389E616FBFC61FFULL,
		0x0CFE0E61B3F93749ULL,
		0xC39C4E01AA2F75C2ULL,
		0x8965A849941F6795ULL,
		0xEB4EE3C0D15D3794ULL,
		0x7FAAD095DF316B3CULL,
		0xEE9035E1780D2560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2681D99224251ECULL,
		0x913FB4B60FD2A20BULL,
		0x005904A0D54F2254ULL,
		0x2D044D797C230215ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x949157EA647ECEFFULL,
		0xC382F19DE4EEF1A3ULL,
		0xD21889FCFC530BE0ULL,
		0xF66530255B189491ULL,
		0x4D814BDA229F6F3CULL,
		0x36BC384C7F08FE7AULL,
		0x57B1DDA7C2B2E6CDULL,
		0x1D1DD7F7D79348ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C29A4B882952A5ULL,
		0xE3734CF8C044B7CBULL,
		0xD67F70E3E2E14E56ULL,
		0x48D33EEF5AF55E00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED7BBE24C7C4006ULL,
		0x918895DFD3E3CEA3ULL,
		0x0AC782F81B1DDF49ULL,
		0x7AEAB3FB32003983ULL,
		0x9885266682E742F5ULL,
		0x844276A591C1D840ULL,
		0x2B05572AE3955D89ULL,
		0x6AA8FBC8FFC297C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29B6F19BAD032C4ULL,
		0x3366327376A9E83AULL,
		0x6D927355E349C1B3ULL,
		0x500013D128E2C009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18B182A243F0F753ULL,
		0xB1BF5DFC1E01135BULL,
		0x5B49924151F129BFULL,
		0x033C8E66E4FBC9D5ULL,
		0x826EAADA1243754DULL,
		0x8FD669A08E60D7D6ULL,
		0xC2B3F9142CBD0B65ULL,
		0x8FF5511AB1949458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x751EDF00F9F463DFULL,
		0x0B930BD140611D32ULL,
		0x42008B3FF600DAD3ULL,
		0x61A6985D4109CF02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE4CC43016707344ULL,
		0xB2FA55BE47511E58ULL,
		0xEF84303C4A40E995ULL,
		0x2B5BE24B38146346ULL,
		0xE21B20449E7FBE4EULL,
		0x5F0DFA4388EB6BD1ULL,
		0x2A1AB612C3151935ULL,
		0x6CAFE597CFC63B93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E538E5F9D66B538ULL,
		0xCF0D7BC49A431F80ULL,
		0x2F7B37053F62A781ULL,
		0x4D77F6D40F813B1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB77F30B42C136AC4ULL,
		0xBF669E8B9059E723ULL,
		0xCF8373DB88B08D86ULL,
		0x749D7FD7C8DE0F41ULL,
		0x4FB24A1CFEA34236ULL,
		0x773FB76354121C28ULL,
		0x4D7F6F6C2FA9354EULL,
		0x70F0906FA0BD2F75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF63101F84F414EULL,
		0x72DBD74A0B0A151FULL,
		0x506DFDEA9BCE772CULL,
		0x3852F069A4F31AABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9BDFCAA54D6D4C8ULL,
		0xA7F9484FD2D9B477ULL,
		0x42E48D7E38DC3809ULL,
		0x5DBF9000C0EB77ACULL,
		0xD8B3406867C753EFULL,
		0x0779AB774C8B3577ULL,
		0x72C0D1C91D5E85AAULL,
		0x34D9417B086EC697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04598C29BC6D4B72ULL,
		0xC408BC052F83A442ULL,
		0x4B83B15894E40F46ULL,
		0x35FF4844015CF227ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA006511513CC224BULL,
		0xE4AA1257446FA7F4ULL,
		0x44AB764B89FB2652ULL,
		0xBE5AA7AFB7991164ULL,
		0x2741C0A7DD74A51DULL,
		0x24B577D80A1E9E3DULL,
		0xB2152E5AD54B264DULL,
		0x6208D770AF53BF7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C8E9FFF31CA6D3ULL,
		0x5799DC68C4FB2508ULL,
		0xB3D057C73322D5C6ULL,
		0x4BAAA269BE077E32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD2C559311497ECDULL,
		0x06C443E35C6E0B68ULL,
		0x1870BB7CF0E07ED7ULL,
		0x2F52EDD1FC0C600FULL,
		0x87906A6C2B968221ULL,
		0xD43835F195AEF4DCULL,
		0x96B5AAF9E2F9E8CCULL,
		0xAAC0F057375FC36EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9C21A189A0D37CULL,
		0x871C45BF94666424ULL,
		0x77681C94A1F90D3EULL,
		0x07F69AC434436279ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B732AE8FABE6A4CULL,
		0xB1F623F596C7237AULL,
		0x2CAE3F25784EB401ULL,
		0x8715481883EBCC73ULL,
		0x368E0A7639BF3118ULL,
		0xA030D857607B8F26ULL,
		0xE00D594A2BF40083ULL,
		0x4CAF30C76FC04FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3488B8758D1FB591ULL,
		0x793640EDE91E6326ULL,
		0x6EA98027FE86C78BULL,
		0x691685B31A779F5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9F292E4D6B8CA9DULL,
		0xBC42C228E4DD3128ULL,
		0xE37ADC310664F2A6ULL,
		0x6AFFD9A7D13C9EDCULL,
		0x86A75286C93B3AD8ULL,
		0x76D737705AE6A92DULL,
		0xA01A5E3B85DF0291ULL,
		0xA9C95E88ECC2B35CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C8D2E6B5838A76ULL,
		0x6034FCD6631A4DEAULL,
		0xA764D906E57F543EULL,
		0x1EE3E1FAF6233E9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF9018A2EF397EE8ULL,
		0x09558EE0A903B504ULL,
		0xC2C14EDAA9379D78ULL,
		0xC50264E79E575D9FULL,
		0x437067EC7BCEC906ULL,
		0xEC7C8ED181D63056ULL,
		0xA8BB7B9289403390ULL,
		0xF50457A81B4A4030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF23F85BD4FEB5B4AULL,
		0x23D2C1F9EECEE1D2ULL,
		0xCE95A69B08BF44FBULL,
		0x23A767DBAB5CE4D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34E5415032C5D257ULL,
		0x02DA9A2B2991B1C1ULL,
		0xB3DDC355DE401094ULL,
		0x884A2ED0F7CB440DULL,
		0x2F85EE39040070F7ULL,
		0x2B3BBAE75C5D3067ULL,
		0x0C5F6722A8384C9BULL,
		0xE4FDAFC8A23B50DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C69DC6CAD69C20ULL,
		0x6DB85882DF66E112ULL,
		0x8A07127AD69B6F9CULL,
		0x05F246990C9944B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE85AB8E77FF5AF4ULL,
		0xAE9046D30E5E686DULL,
		0xE7CBA45F7F49CAA3ULL,
		0xFF12F8227CD021FFULL,
		0x835229EFA2933D0EULL,
		0x0EF85851D6D175E3ULL,
		0xEC59D34DE32B39E0ULL,
		0x07B8B363DC33B912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB7E52099DA6B54ULL,
		0xE76D62F8F175E833ULL,
		0xFD2101EF37B461E5ULL,
		0x247D98F52C7D9ACEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49D860D0F872FC39ULL,
		0x4DE5E0C598BD1BE4ULL,
		0xD913FB2634FB8F6EULL,
		0xC402B834EC85177FULL,
		0xDD9735ADB012F600ULL,
		0x14EB1C0AFEA5C2B6ULL,
		0xE28754747472B85AULL,
		0x3737B3D82FA5F513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4A58991B43817CULL,
		0x68CC0A6765580309ULL,
		0x792A846F7E02ECCDULL,
		0x76476A4BFF277873ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x426ABFBE53979CA3ULL,
		0x8CF0EDC8D1CE295DULL,
		0xB6BDFD2EAF93690BULL,
		0xBB224672292308F7ULL,
		0x27DE0B1224369DDBULL,
		0x4B9888AC81417380ULL,
		0x2F66430B1D511EA8ULL,
		0x1D61801590107072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D60646FB3B30BE3ULL,
		0xC595376401854E63ULL,
		0xBFEBF0D5099DF606ULL,
		0x179B49A58B93B9EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1614FC4A698A38C9ULL,
		0x99280E6238FE21FCULL,
		0xBC36F78A381BF176ULL,
		0x0F8C671E620CB97BULL,
		0x738BDD45F3E9D6D8ULL,
		0x1A9B5F9F5F5EA98CULL,
		0xBECB6ED08B317067ULL,
		0x7FF9E7308CB010E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD7D4AC9E401FABULL,
		0x8C38400A610B4CD5ULL,
		0x0E696A7EE172A0C4ULL,
		0x0EA4B853442F3C08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD14C391FC120787ULL,
		0x4AA7FF8F8DBDDCA2ULL,
		0x5D5121086161FBD6ULL,
		0x74123325A98576E4ULL,
		0xDB1EF2B3380B2DDAULL,
		0x1F84660C9182EB1EULL,
		0xBFE6BF893E529684ULL,
		0xFC63E80DED01B275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63ACCA2C4DBADB74ULL,
		0xF84F256D272CC337ULL,
		0xD9918F67A1A45372ULL,
		0x6AE6A536D7C5F45EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C8E91183614D680ULL,
		0x0644786F814FCC15ULL,
		0xDE2AA34BDCE661D1ULL,
		0x462ED38434FD26F9ULL,
		0xAD9B773CD2363C24ULL,
		0x2CE63012DF662992ULL,
		0xB2CC76CD7E9459FEULL,
		0x6776F24286DF767AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61A2441F6A21C625ULL,
		0xB06F9B3CAA79F7DBULL,
		0x688445CCA6EBBD8BULL,
		0x21D6C9643A28BD30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x282F1B24D009D02AULL,
		0x76D06E89506A7652ULL,
		0xA0922BB56AA733C3ULL,
		0xA22E4BB1248EE959ULL,
		0xFCB5AC341B07D8A0ULL,
		0x30CD209E6DF6C71CULL,
		0xE02EBAC9EC53198FULL,
		0xE9B2CAB14A36F492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB26AAE0D333FD1CULL,
		0xB543460DA30C049FULL,
		0xE781E5AE7EFCFF04ULL,
		0x52B8620228B73726ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E06B9427D503FABULL,
		0x3BC24343792C6C6AULL,
		0x7E7AB18F2FC98364ULL,
		0x601C592E9ECAFE43ULL,
		0x001C5AC8EBEDAB57ULL,
		0xABF04C1FF2264D2AULL,
		0xAE127147C8A730C5ULL,
		0xE8BE7B4A082B1C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323C33158297B3B4ULL,
		0xC16D90016ADBE0A6ULL,
		0x55378236F89AC0BBULL,
		0x6C62A62BD5313853ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75CC87365B6DDD11ULL,
		0x276A8EA9C36C86B5ULL,
		0xF119A8172666F68BULL,
		0x0C1FF29341939CD1ULL,
		0x917872BDD0C14238ULL,
		0x823BB2897A49F8E0ULL,
		0x7C01BA03E24F9A20ULL,
		0xE32D074DB2F7CAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DAD8F63581DB65AULL,
		0x7C470F11EA67780BULL,
		0x595B44AABE37D75EULL,
		0x44CF081BD25BBDB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7D2E457E6848C79ULL,
		0x34E50D5CD2CE6704ULL,
		0x2C7E2DC906922F55ULL,
		0x767FADE80F03784FULL,
		0x4060AB91A7EBFAFCULL,
		0x76D17935F4400B38ULL,
		0x3DB57F2B46D3101DULL,
		0xD71DBB58A07F0065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862C5BF6D38BD2A1ULL,
		0xD7FD0B5F1450115EULL,
		0x556F0E3589E693B4ULL,
		0x64E97D0FE1DD8756ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0F5378F0317D2DCULL,
		0xB5960ED5F995EF20ULL,
		0xBAD4FFC5CB382099ULL,
		0x75D3C49B5AC0CF5BULL,
		0xDC33A74BC701586BULL,
		0xDA0C64F28EDA2D81ULL,
		0x6547476BDF91346DULL,
		0x82886EB165D62229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A00CCE8D4AF5A3ULL,
		0x136D0AD72DF8B067ULL,
		0xC36999C8FAC5E8E8ULL,
		0x561432F07889E180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A1759AF5355A03FULL,
		0xEF3902840C12B7C5ULL,
		0xF84DE6D8A7C97582ULL,
		0xFC2E203E4527B326ULL,
		0xE4B8C8F4A6607E32ULL,
		0x15BB8EB7A14D9056ULL,
		0x9606DFCF8500C32EULL,
		0xE0126152B2290EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D852E0005A860B7ULL,
		0x291031C5FD9624ABULL,
		0x3D531FA665E66E5AULL,
		0x3EE89284B73FE0EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC437F6F971B7221CULL,
		0x80B86DA3D7A786A4ULL,
		0xEDAE857F8448D25FULL,
		0x6967A8721F2DBE73ULL,
		0x431FE82A30115FFEULL,
		0xE6D2AF7C77BCB66EULL,
		0xE80E84E5BD8ED40DULL,
		0x6BD000720C7723EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAF46D3C944B6430ULL,
		0xC3FE7A1D9DAA9B02ULL,
		0x5FD63F99A77C4C6FULL,
		0x6A47B95FF8DD1352ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0372FFE7B142F88ULL,
		0x379486E396175A84ULL,
		0x7D31484667C82A64ULL,
		0x09FED629844079A6ULL,
		0x0B75AABCB42A0230ULL,
		0xF5E97B7F2BCF36A8ULL,
		0xEC0BBEB5B297A88BULL,
		0x1945AD0CC6339650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63AE88013950832DULL,
		0xB83CDBC416D97776ULL,
		0x86EF973EEA4B2F2AULL,
		0x4A56860EEFE8C9A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6E742A1154C37DCULL,
		0x770E594135E25536ULL,
		0xFF059E4347FAFC0FULL,
		0x46D20C7D0B9C7B67ULL,
		0x6E91E1B11CBF8031ULL,
		0xA06E67AF710E48A7ULL,
		0x808097107B2293F8ULL,
		0xD59D4F02F1E8EE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108EC2EB59B943CFULL,
		0x4771BD4BFE011E11ULL,
		0x121C0AB58F1CF2F7ULL,
		0x7C2BC6ECF42FE3D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DC5C5CFC388AE81ULL,
		0xD3E6C15C1AFD4CC9ULL,
		0xA0FA9DDC743BCA7DULL,
		0xBB8D508DB8F96D6FULL,
		0x019C5B99C25AA2E0ULL,
		0x447B87B8FAF2F53DULL,
		0x2B5764A0270B7216ULL,
		0x61636BC59F66FE31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFB5EA29CFCDDFBULL,
		0xFE3CE6D15B0DB3D7ULL,
		0x0FF38DA23FEEB9CBULL,
		0x304F4FE3624328BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15BFFF6ED04DA5CCULL,
		0x71E96E9B0B2B2A46ULL,
		0x7A46199261A45BCEULL,
		0x0A59614B7AF0637AULL,
		0xE49E50BB9E1355D6ULL,
		0xD85DE3F2B10184C7ULL,
		0x427C06E2D4EA47F7ULL,
		0x3F9E9E8D5D21037EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x053FFB48472C64E6ULL,
		0x8FD944A15164DFF2ULL,
		0x58AF1F3DFC6B0A98ULL,
		0x7BE4EA474DD6E838ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB874D2DB350EF44AULL,
		0xF00B408BAE579C0DULL,
		0x7A0D6B91FA3F6B32ULL,
		0xD843D342427DFDBCULL,
		0xC46DE9DCBD51E1B6ULL,
		0x439CBA3A7E1E9DEEULL,
		0x0897AC93D5E7A959ULL,
		0x0E6880F9ECCD7D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C5899F4F3675ADULL,
		0xF94EE53A66E30D7EULL,
		0xC0910983BAA28E72ULL,
		0x7BC6F85B68FE8F01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF834D86F52801EDULL,
		0xF3ADBAC3DCAF2221ULL,
		0x7BE2FBD515500D90ULL,
		0xED82FC247425ED79ULL,
		0x7C7F1D2D22BAA411ULL,
		0x5637EA6B619FA340ULL,
		0xF154AD5B7BCF273AULL,
		0x2C8A70D181F78E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A61A23A1CDC5D90ULL,
		0xBFFA86B45A615DB4ULL,
		0x4E74B769760FE039ULL,
		0x0A0FBB3DBEE5104FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23F6BA18EE5C38A8ULL,
		0xBB140CC7D3FB6627ULL,
		0xEF3F5E5E71E9ADB6ULL,
		0x45F45A1A50F0639DULL,
		0xEA7BA737160EDFF2ULL,
		0x3138ADEC1AA1D472ULL,
		0x79F22788FDDA4508ULL,
		0x4999769CADAE6C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2518C4634917836ULL,
		0x097DDDD3C800EF35ULL,
		0x09313CB4204FECEEULL,
		0x32BBF55C18D46ECEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70B430B569C3111BULL,
		0x55A56102D49FDB51ULL,
		0xF09553584F0A861BULL,
		0x4557AC2CFCAFD2C5ULL,
		0x66B4450F590A33FAULL,
		0x966964DD5308EFEEULL,
		0xD098F981479E67C5ULL,
		0xFB92CB9B57B25D63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7670FCA146CDC8ULL,
		0xA94A59DD27F378B4ULL,
		0xE74A5C88F08DED6FULL,
		0x1D21E53C0129AF96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x342B08E1E031382CULL,
		0x25AE1923917A2CB5ULL,
		0x3083885AEFCAAA58ULL,
		0xB5509670DAD41E87ULL,
		0x21FAD83B6C905E51ULL,
		0x6C1E2FF6D90C3313ULL,
		0x44949CCEF385F981ULL,
		0xBCE8FA2288E48802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6721B3FD9F3C6DULL,
		0x322937C7C949C18CULL,
		0x5E92CF1315ADB38EULL,
		0x3FE5B7912CC04EDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7268814B6DB48D9BULL,
		0xAEC6F02F721F9047ULL,
		0xE9F413FA33D682BBULL,
		0x725A1213592795FCULL,
		0x6FFCEC08FDE3C752ULL,
		0x34ACE41A8230B07FULL,
		0x5A3765B35233B629ULL,
		0x95052C820ABC7A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F38AA11D84271EULL,
		0x8070CC1EC559C332ULL,
		0x4E2D2C9867838CD9ULL,
		0x111EAD60F121BD2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B813093E9A0C3F3ULL,
		0x04609E72C3F85B7BULL,
		0xE9376EC2CBE8C88CULL,
		0x6E31859847AF7C52ULL,
		0x53A42990C093E017ULL,
		0x77CA7BDFE13CA229ULL,
		0x03C9390DF37B9143ULL,
		0xA50E623F1C5059CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DF5C107F940B00ULL,
		0xCC6F01AE32F86D9DULL,
		0x7915E6D4F040588FULL,
		0x6E541AF67B9CD075ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x747CF6A5353956C1ULL,
		0xB47E1A8478F05C5EULL,
		0x9E79B3EA0E4B5C79ULL,
		0xFBE02FEFDB26EFBBULL,
		0x49FDD4EE6C169286ULL,
		0xC815B54C603D87D9ULL,
		0xA127DE15D95C7748ULL,
		0x29C5B56DB1BAB7CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702A9209409317AFULL,
		0x67B703DAC212869FULL,
		0x8A64AB2852051147ULL,
		0x2F391E383CDE381BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7E8413478A20EFBULL,
		0xD720A23A73FEC7DEULL,
		0x0F5E0710D5EA4AC9ULL,
		0xAB46BEDC63B1E9A7ULL,
		0x684FA9FEC6B685FDULL,
		0x802D45800FE70E56ULL,
		0xBC36EF206996F1C5ULL,
		0x6FF0CF1AE73B0180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BB7D05F7B9F50FULL,
		0xDDD8F33CD04AE8B2ULL,
		0xFF8585E082522E1AULL,
		0x49057CDAB67422C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABCD67546D1DF0FCULL,
		0x4D2CED217ED19C98ULL,
		0x3B3262653F879B3AULL,
		0xB1348F80271D42B9ULL,
		0xA274954DBB3A51D2ULL,
		0x10AFC5A984B94E05ULL,
		0x2DE045880625E31BULL,
		0xF439D5905C81B78AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91B90DE37C61B93ULL,
		0xC744444B3253316EULL,
		0x0A7CB4962927513EULL,
		0x71CA42EDE25E813CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5111A1B6DFB8D4A6ULL,
		0x8380B6D70923D079ULL,
		0x0D79DDFD47CAC575ULL,
		0xDE7BF3055706A050ULL,
		0xEE57AAB6599FC1B0ULL,
		0xF34C95D061C08E17ULL,
		0x76C5EE8DBCC753B5ULL,
		0xB2A5E54B04FC562BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB214F8C82D6F98C8ULL,
		0xA0DEF3C58BB8E806ULL,
		0xAEDB47074D613277ULL,
		0x631BFC28147B6AC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55B3AE14CC9D417BULL,
		0x3981B1A8EC8C85E0ULL,
		0xF82DC94DBF3CB4B3ULL,
		0x388796BF035EB7FCULL,
		0x8C42A8888481E408ULL,
		0xDB6C5A7348D9BC2CULL,
		0x5749192EE8F6E354ULL,
		0x1F1C65A9654A7ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2798B25877E51B56ULL,
		0xCB971EC5BCDE747DULL,
		0xED07864453E2734BULL,
		0x56BEADE40C6D8BF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38464BF6716987BULL,
		0x081A524462B69EC1ULL,
		0x05C77EFBEEB2F2D2ULL,
		0x7638F21A7DE57081ULL,
		0x862FDC3405E814B1ULL,
		0xDE443542CC7E8852ULL,
		0x2D07B19E0443D232ULL,
		0x7D1F6BFFA86FC947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9F14784789AD93ULL,
		0x063A3A2EBD7EDB01ULL,
		0xB4EBDC7090C4265FULL,
		0x08E2FA0D7E7D5111ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA26AC2FD01B68A40ULL,
		0x20D1506051841B7CULL,
		0xA76B4737E7CD4615ULL,
		0x0015DB0ABCDBACD9ULL,
		0xC277B16E52B9AF4CULL,
		0x4FAF89410BDDF7EAULL,
		0x8C28973CAE043957ULL,
		0xDCDC5053678D1E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802F195D4946945BULL,
		0xF4DFB0081476E855ULL,
		0x7571BA39BC6DC90AULL,
		0x48C9C76C1BCE2DFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB328B42658862360ULL,
		0xCB04F49DEB5E72DDULL,
		0x3AFFFA1C34E6A86BULL,
		0xAD81A59237F62945ULL,
		0xB06059E472723976ULL,
		0x31B674DD3A4F1797ULL,
		0xC60464C554838A77ULL,
		0x3D8E7BB45A0D1BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1760C0F557AAC4DULL,
		0x2C1A4D74931BF361ULL,
		0x9FA6EF66C06D361DULL,
		0x50A8025795E85116ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB53E6E0314C58AECULL,
		0x4F94EC941937ACFFULL,
		0x4C3FC04E20BA716BULL,
		0xA56481128F14CAD3ULL,
		0x2862894BC5227E47ULL,
		0x980F03CB263C13DFULL,
		0xF729C5AB97AEE86CULL,
		0x7C151990F8CF83FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3DECF4257E44C48ULL,
		0xE1CF7CBBC622A01FULL,
		0xFC7317C6A4B0F189ULL,
		0x10864C977DE26213ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF968E0523573518ULL,
		0xC5BF6C0F38401D1DULL,
		0xD14DD84BCBBC9EB3ULL,
		0xBEEC121E08109D13ULL,
		0x802935762F6F2278ULL,
		0x0B7634E3AF0617D5ULL,
		0xC8D80239A9142343ULL,
		0x6B09D8332B72B007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B47D902DD6555BULL,
		0x794B45DB3327A6CEULL,
		0xA15E2CDAE4B9DAA7ULL,
		0x226229B67B16BE3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21D8A8B8ADD7C2A4ULL,
		0x7055FA807F389BD4ULL,
		0x21155DFC8DAE0943ULL,
		0xC65AD12D0EAD2582ULL,
		0x97A5ED1C137F2E66ULL,
		0x5A9512EDF02E9CCDULL,
		0x9F3137FC795E0516ULL,
		0xB13968DD9A521360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA479DAE392B8A9CAULL,
		0xE276C9D22623E258ULL,
		0xC263AD7691A2CA94ULL,
		0x14E06211F6DC05D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AA614CA80AE7696ULL,
		0x44F840973C4C48E1ULL,
		0x4A15EC6AAAB534C1ULL,
		0x13C27721BB8C0A4CULL,
		0x21DA72915261C648ULL,
		0x242D54C10AB3202CULL,
		0x66A90311D96BF3B2ULL,
		0xE5B7EF54C0673957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7113165CBB31EA52ULL,
		0xA3B2D53ED2E30F6EULL,
		0x872C6110F0BB6132ULL,
		0x2D0FFDB64ADE8D45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD54AEBEFEFF9C259ULL,
		0x40EB9293CA7FDD1BULL,
		0xB8502614A89B0909ULL,
		0x06BC2E2A459ABA3DULL,
		0xE25C54A1A8F906A7ULL,
		0x9AF536E4CD92B9C3ULL,
		0xAEFAE67B1CEB33DAULL,
		0xD5F67CCBB5244285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFF7BEF04F0C3D0ULL,
		0x4151B88A4E47702FULL,
		0xB18E5C5AF384BB7CULL,
		0x4952B46728FC9A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B0931CD4DB62070ULL,
		0xA819B00ED1A0F6B1ULL,
		0xC301E6C01AB38F6AULL,
		0x350D14C68210DCFDULL,
		0xD69C78CF1804F05FULL,
		0xEE0393533C5EBA64ULL,
		0x74719C8BDCCB1ADCULL,
		0x88CD8C14F4E5A369ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE643208ADE71D195ULL,
		0xFCA18E69C7B0A1A8ULL,
		0x0BDF2382E0D98C35ULL,
		0x038FDFE2DC271EA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F0C0CC7682E68C9ULL,
		0x1C87DB6522EC0BC9ULL,
		0xB3E28FA5AB478B73ULL,
		0xAE3E115F0136D47EULL,
		0xFC93FCA75128D39BULL,
		0x3037B3845B5A22DCULL,
		0x9C69C52CC05F69DCULL,
		0x006382420DB187D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD038D9D743DD1DEULL,
		0x44CC810AB24D3896ULL,
		0xEB95D44A39714222ULL,
		0x3D03672D0990FE7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BE4096F0A8BC860ULL,
		0x2B228CE38BC2D697ULL,
		0x8FFCF77BF686D2F9ULL,
		0x8FC46B5E78FF46F7ULL,
		0x429C740784B698FEULL,
		0x92E358FDD641D5AAULL,
		0x19861C08E09A9E6FULL,
		0x1706A633DAF80B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1D428CBDA67E99ULL,
		0xF8E1C29159888DDDULL,
		0x59E520CD4D7A5788ULL,
		0x7AC11710F9D0F08DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0900B0602BBD050ULL,
		0x555BFE8CB70F6DFBULL,
		0xF143E99A42293655ULL,
		0x8EA20E38F41D1FBEULL,
		0xA120F87937D60571ULL,
		0xCF7D9AA90ACF61E6ULL,
		0xD02D98DD2F1FC074ULL,
		0x5D92F51C038B3B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B74ED044C80A12AULL,
		0x2200F3A451D7F637ULL,
		0xD8089A6F40DFC7ACULL,
		0x727270617AC7E819ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87ADC65635765D3FULL,
		0x43884B1D15D962DBULL,
		0x4C5F4DB98B5F7F25ULL,
		0x769B6383D2FFBA55ULL,
		0x2F8263996DA008B0ULL,
		0x439FE3878D426F27ULL,
		0x779DBC3B599D42E4ULL,
		0x11E2616984CD3AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95088F1C7B37A7D1ULL,
		0x4D44113C0DB5E2ACULL,
		0x0DC93E88D8B76D07ULL,
		0x1E35D92D8976762BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E610FADE0033352ULL,
		0x5FB113414CAC1394ULL,
		0xD1097334F7EC3E49ULL,
		0x4BB27401B87ABEE8ULL,
		0x459018EB2539571BULL,
		0x446975A705445913ULL,
		0x422F033A0568A7BAULL,
		0xF78A2D430A4C7695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C4C295668626D2ULL,
		0x87588A0C14D14C70ULL,
		0xA403EDD1C57523EFULL,
		0x0A352BF53FD45910ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC18336C8251B64BULL,
		0xEAE72B40FA2336BCULL,
		0xCAD0CE9322B61F94ULL,
		0xF994C7BE3D896070ULL,
		0x334C8C5D73F51C4DULL,
		0x2F6F16981BCB80D0ULL,
		0x5BC1046738EF72F5ULL,
		0x6962C5B804D88D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5975094BB8B3EC2CULL,
		0xF56485D51A5855A4ULL,
		0x697775E596412FF9ULL,
		0x1E3E210EF5AE5578ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A330E73D5232D03ULL,
		0x73658580F7C5DD7FULL,
		0x531E2AF051F7A43AULL,
		0x63EBBE412FB0C636ULL,
		0xF62D54C815E70470ULL,
		0x8D285A0C552B6E59ULL,
		0xCE94E957964694DDULL,
		0x5B38FE0C83C38A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4EDA427156DD7A4ULL,
		0x6762E3559C383ED9ULL,
		0xFD38CDF0A071BD1DULL,
		0x6E61741CBEB74EF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76BFEE7904718134ULL,
		0xF488111FC8B90194ULL,
		0x2FE52F4E15CDD817ULL,
		0xA1CF5A51A4CF9272ULL,
		0xB7308A4D9E0EABA5ULL,
		0x71207966F8CC2FD7ULL,
		0xBB2EB449E138E91AULL,
		0x11D143D540FA05A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F475FE7A9EFC24ULL,
		0xBF5A1668B7081B99ULL,
		0xF8D3F24584407204ULL,
		0x46DF6BF949EC684DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8704E8A5C2CF2C56ULL,
		0xB8E9956595993BA8ULL,
		0x2BC490FBA922CF05ULL,
		0x735DC444B50D4FAFULL,
		0x9BFFBFF83BD5345AULL,
		0x015722655C7B41ADULL,
		0x2FFFA2568A0E4938ULL,
		0xFFCDB2582F46A2A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEFB677EA474F756ULL,
		0xEBD8B0714FE4FB6DULL,
		0x4BB6A9D42741AD55ULL,
		0x6BE63D5BB98973C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF58F1754EB6B6B90ULL,
		0xDC9231E0D55C0CBBULL,
		0x779110BAD7B1A72DULL,
		0x9653E78552A2014BULL,
		0xC9D79792F91634A5ULL,
		0xEB1B1BB5859F2148ULL,
		0xB7D4D383ACCE5947ULL,
		0x14DDF794829BE8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB8F9725E4B73C93ULL,
		0xC2984ED2AAFAFD89ULL,
		0xC12876467E52E7DAULL,
		0x2F46A790B5C691E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D7F08D686E335A6ULL,
		0xC5A706C9AE6A5019ULL,
		0x2CD5A661B212AAA1ULL,
		0xC435666FDE9734CBULL,
		0x131AE4B22F2743F4ULL,
		0xED290C2E5F959017ULL,
		0x77DF358C5E2E76DDULL,
		0x92EE27FF1ECB143CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37CFB4986B74F35ULL,
		0xF9BED5ABDE9DB385ULL,
		0xF7F79937ACF84F92ULL,
		0x138F564E70BC35C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72640961BA222C8ULL,
		0x51F0AB63E8D9D634ULL,
		0xE976499A2267E70BULL,
		0x9DD0104402C2E42EULL,
		0x55A1CE559462F75DULL,
		0x8C8930765D57A4B5ULL,
		0x09D7685B54AFCC51ULL,
		0xB4990A3B342F5308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2AE14A2252DE98ULL,
		0x2E4DDCF5C3DC491FULL,
		0x5F6FC728B4803B26ULL,
		0x6C87950DC1C93760ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94E66657037AFB70ULL,
		0xF10B77DD8CF6EC68ULL,
		0x548AC718F4361F15ULL,
		0x8ECB43C89E63C7EBULL,
		0x37988EB653DFC5D3ULL,
		0x3D004B6E0A7069FCULL,
		0x6648FEAF8433F4D4ULL,
		0x26A69E3169B4A656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD58B956776B259A6ULL,
		0xFF16AA3319A6A7D8ULL,
		0x8360952693EC7696ULL,
		0x4B86BF1E4F3478BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6D123D79BFBA088ULL,
		0xEAB30157090EF93AULL,
		0x67206BCD09E6BE35ULL,
		0x9348AD2040527BC9ULL,
		0xFD5303E4DB82D09FULL,
		0x8FAF24CB89FC409EULL,
		0x8517CCC430482789ULL,
		0x79C78F30660F48DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6123B7D031669AE1ULL,
		0x3EB2778D848090D4ULL,
		0x28A8D0EC349C9CA1ULL,
		0x26E7EE4F66974C39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056440C9918E78CDULL,
		0x31B702E449FB6D13ULL,
		0x0D34D4ADC2C4C4B0ULL,
		0x210B27B469126CE2ULL,
		0x3D90A4F3DAFDACDBULL,
		0x4A8A1EE496CB9D20ULL,
		0xF1417BFD3C53438CULL,
		0xB80FBA067535D763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DCBCFC13362551ULL,
		0x423798D2AC34BFDCULL,
		0xDCED3C44B720CB83ULL,
		0x7360C4A9CF1065B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x199BBF7AA08C3B99ULL,
		0x9EE8C7C0029B5574ULL,
		0x6626B12E07A16376ULL,
		0x5C347E5AE2E9E035ULL,
		0x714E82A0E59335AAULL,
		0xE2165E8793CBF3CEULL,
		0x087E42D5ECF04804ULL,
		0x8E2CF2332E26F3BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB43235CB46635F3ULL,
		0x2E3ACFDFF2E18618ULL,
		0xA8E49CEF334C1430ULL,
		0x76E071F3BCB20E6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DD9A2404ABC1D50ULL,
		0xBEDDBD79B9F36B55ULL,
		0xC77FA40FD23D35DCULL,
		0x457EB67221519070ULL,
		0xB8F6290458E2938DULL,
		0xC3F4F0932E46C4D2ULL,
		0x866983724E939CA6ULL,
		0x53EB972F38E68E88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1263B8E57C5E0619ULL,
		0xD53973529874A29DULL,
		0xBB2927077C26769DULL,
		0x3A772774938AB8B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCA5B9A746506002ULL,
		0xE2D500C4C9C1A471ULL,
		0x6155E5D24F569729ULL,
		0x9082D47B890E485BULL,
		0xA9ABA44A53B71B8DULL,
		0xECF3D58BDF3B2F10ULL,
		0xE19FF38B92A97AADULL,
		0xFAB076EB36B8EEFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C201CAFB37E7C81ULL,
		0x0F06B387EC8AA0EBULL,
		0xDF140C8A147ECCFBULL,
		0x46B47B65A881C1BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B7ABAF7877B1AA8ULL,
		0xFDA1D3A49BC228ACULL,
		0xBF6F647C3C33E130ULL,
		0x8C992A2CAFFB5C33ULL,
		0x315A309D2F64B10CULL,
		0x1F609F9D81ECD3F1ULL,
		0x7623CF989D04D415ULL,
		0x9E0043BAFB256305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEDDF24C906D6600ULL,
		0xA5F98505E4E99E79ULL,
		0x48C035238AEB5C53ULL,
		0x00A337EDF7880F03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40D3AE37473FA8CDULL,
		0xFF5D4923CE74E828ULL,
		0xD70DD9CFAA482D2EULL,
		0x97BBBC0124972A7EULL,
		0x23BDD3AED9B4929AULL,
		0x2BB0C6F8F24C433BULL,
		0x84D7759807105D04ULL,
		0x3D9C1FF66243B1A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F011A2B980D6D12ULL,
		0x7B9AD217C5C6E2EFULL,
		0x8F094E60B6B5FBCDULL,
		0x3CE87A93BAA388C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0EC77F752C9AA7ULL,
		0x4CCEA29EBDA0E109ULL,
		0x991A6011B018DE71ULL,
		0x025EE1A8414B0031ULL,
		0x513BD13084A99989ULL,
		0x6FD53A43BDB064CFULL,
		0xBD292A6653FCC90FULL,
		0xA2E2B1C8D41717F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AEFD4B32659688DULL,
		0xE67548ACE5CFD7CFULL,
		0xAD36AB42279EB6BBULL,
		0x30054577BCB88EF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85ECB42C6DF0F3C2ULL,
		0x9870B8981F3DB8B1ULL,
		0x1325B8043BFA37D6ULL,
		0xBC6B59EB5B024D48ULL,
		0x49EF48E518DD2451ULL,
		0x6219A73180BA836FULL,
		0xA979CB7400B05DF7ULL,
		0x97207C8CC19B877EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F71862E1EC45B32ULL,
		0x283F89F13AED3B36ULL,
		0x3B39EB3C56282A8FULL,
		0x2B3DD6D018186A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0AD3900DCDB7781ULL,
		0xD6F2090CCF8E6C66ULL,
		0x20B50E7A96A93273ULL,
		0x59F079825B62B915ULL,
		0x748729657398DF8EULL,
		0x3D278F5654F6CB96ULL,
		0xBBE0D4DFBC687D61ULL,
		0x1D16CF4C4688C857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CBD5E10058CA740ULL,
		0xEAD14FDD6C30A4BCULL,
		0x0414A7B08E2BCEE2ULL,
		0x2B533ED4D3B0761BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCDB6C2579C5AD70ULL,
		0xEB633D35A7FE7952ULL,
		0xCC4A86646D166471ULL,
		0x61B27E38A61C2941ULL,
		0x8DFE62250FADFDC7ULL,
		0x0E86D153F623E741ULL,
		0x82E225E51A11577CULL,
		0x0ADF9D87276C29C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE09DFDA5CD995933ULL,
		0x13664FAC3152CD0DULL,
		0x39DC26664BA960DCULL,
		0x7EE3E048802A5BD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC548BEACB42675FULL,
		0xE2604C3DAE87CE37ULL,
		0xDC946373FF1D9FC9ULL,
		0xFA28A93F8D0F0BA0ULL,
		0xDAF5B4296219D72EULL,
		0x7A1DC534F25971A2ULL,
		0x0DC2BE2D36912CEFULL,
		0x1E5E5F8F3AA6943AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CCD4A0F5B1858F1ULL,
		0x02CB9219A7CEAC64ULL,
		0xE77C9E2A18AA4B56ULL,
		0x7C2AD88241C90C3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9274DBEB8830C663ULL,
		0xA275FB881CAA8E2AULL,
		0x452B18388AA85986ULL,
		0x1A3938541C55D541ULL,
		0x088B5CD7A20B6904ULL,
		0x58898128EF7D6A42ULL,
		0xF258AA27D1870172ULL,
		0xF412F8D7E144B18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD724A3ED95E26253ULL,
		0xC6DF279BA94853F7ULL,
		0x3E545A21A4B2907FULL,
		0x550A285F8C883007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95E5ABE3B6DF9737ULL,
		0x50799CA91FCAC2DFULL,
		0xF4D9AF4F62379D09ULL,
		0x56C17980F6191D5FULL,
		0xFE7310F8F8B3B9E9ULL,
		0xCD96FF9164A58B56ULL,
		0x47B1226281B53F22ULL,
		0x277CB053D2B12371ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AFA30D8A18D30B1ULL,
		0xD4E38C3E105D71C9ULL,
		0x9924C9EEA31EFC33ULL,
		0x3343A5F23C646030ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB62D73CC3D538DBULL,
		0x58F44EE62DD52E11ULL,
		0x9B40F0DFEF6DC2E5ULL,
		0xD47B269542202BD5ULL,
		0xFE448B19E893B780ULL,
		0xED4BDDADC240EC6AULL,
		0x027B4FE38812D085ULL,
		0xECAC31143DFCD990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998F7D1549C27B20ULL,
		0x923736B1037845F3ULL,
		0xF98ECCA62238B6C6ULL,
		0x760A6F9675A87735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AAD53E3E15CA6E6ULL,
		0x5825F46D00E522EAULL,
		0x9FFC461A948A8323ULL,
		0x45DE5B5D35C1303DULL,
		0x058305350FEF744AULL,
		0xE0A2E8471848C8ECULL,
		0x0D3F001E9250EED4ULL,
		0xC800D2B6BD9ABF51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2019C43EE7EE43ULL,
		0xB0546EFA9BB2F5F3ULL,
		0x97564AA44C8DF6BCULL,
		0x75FDA27D5AB99645ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DAE5BADC3A123B0ULL,
		0x28AADC6752DD2F56ULL,
		0xB9C448F654F40602ULL,
		0xB6D9E5BC937C2D6AULL,
		0x5AE31DBA380E5221ULL,
		0x82DDEDC4923F86C5ULL,
		0xA14858A56E42EB54ULL,
		0xD539BE60FDC971C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB64C55215C15956ULL,
		0x959C2795084B30A1ULL,
		0xAA817184B2E2F48DULL,
		0x5D6C28223F63110CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51DCB6763C7CA933ULL,
		0x7F85FC6852F1FDA5ULL,
		0x88B079B05E4F98A9ULL,
		0x8336AEF268C69A35ULL,
		0xC842539B1328F74CULL,
		0x44ACE0C61FAF6026ULL,
		0xE45B87B2412D0A94ULL,
		0x0DF3E0280F4080ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB51F7B14915EDAULL,
		0xB12F59D106FA4367ULL,
		0x6E469E260AFF2AABULL,
		0x1569F4E4AC59B3B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x373BEFB1EC20005AULL,
		0x79427CFCCE9C0958ULL,
		0x40F2CB43DFA31750ULL,
		0xD55814DB51BCA059ULL,
		0x26CDFC65D735813AULL,
		0xA75FCF15A48F3CADULL,
		0x9E91F067E7DAE04DULL,
		0x23E5E95759134708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CF66CFDE112FDAULL,
		0x517B3A333BDF0B0BULL,
		0xCA9C7AB04A2062D7ULL,
		0x2978B7D28A992BA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40C5D7E1A618971CULL,
		0x547BFD08010F3E2AULL,
		0x0C85332103428321ULL,
		0xA6FAADF736371AB8ULL,
		0x4657ABDAD47A3947ULL,
		0xECD23B8A5EE40EEBULL,
		0x43FD188BA9496D3BULL,
		0xBC614EE28652967AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C95A5D303D1BE1ULL,
		0x7BB0D39216E97516ULL,
		0x2416D7DC2428BA06ULL,
		0x1D6C6397267970DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F68BFCF162DA73DULL,
		0x66E9ED5A8FE4443BULL,
		0x4D162CB265F3EBD6ULL,
		0x3C124EFF460AD6DAULL,
		0x4710FEFE3DC0D615ULL,
		0x4A2F44365793BBA6ULL,
		0xEFA1CAE4CB0B2DF3ULL,
		0x31189F20069F4BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEE998C40CD6F78ULL,
		0x69EE0D6B8FD21EE9ULL,
		0xDF1A4AA8899CBDF3ULL,
		0x05B9EDC041B01473ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x897AE3AB9B8E56BEULL,
		0x2B421B5B9F4614B9ULL,
		0xDCD7D31F2D961D15ULL,
		0xCF4D1DB5FD93D95BULL,
		0xE4D8E716B40BBCEBULL,
		0xCAFF1A56E7BF1B06ULL,
		0xACCF293DA806D6B8ULL,
		0xF38141B8D445E99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81AD310A554C670BULL,
		0x4D20044205A417BFULL,
		0x8397F2461E99FC83ULL,
		0x747CDF257FF4870FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEE75FC62E9C6F6CULL,
		0x5C3237EF7F42A5E3ULL,
		0xAAE4FBDA73526F1FULL,
		0x7DEBBF4E5A1621D5ULL,
		0x8A53CDB6AA77BA23ULL,
		0x227782529921C29DULL,
		0xEB2EFE70C073EE9AULL,
		0xC05A4BD3FAF12782ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7757E8E37C6214ECULL,
		0x79EF90323A458946ULL,
		0x93DEC0970487DA00ULL,
		0x0B5300C599E1FF44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64D1F15512F8DA65ULL,
		0xFA153D4D38F3E2A5ULL,
		0x0E21479ADA630C4DULL,
		0x2395C2545138901FULL,
		0xFC1CF4C327A32B0CULL,
		0x66A54035E284893AULL,
		0x0D0608CD6D227BD8ULL,
		0xB0C7CB59A3C7BAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11E464CF5314209ULL,
		0x369CC54CD8A04166ULL,
		0xFD0696190D816E6DULL,
		0x613DF1A2A0DE5162ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7ABB39401DA984FULL,
		0xBEC6B1AE4674C5C9ULL,
		0x65CD68B381F17B6FULL,
		0xB144C169E889BE04ULL,
		0x6D89827E733B9223ULL,
		0x47604D84F0D4E60DULL,
		0x8992BE4BA5185FBEULL,
		0xEAC0C2CFEE0D7563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA1512591CB24EC6ULL,
		0x5712336A060EEBC7ULL,
		0xD195A7EE038FB1AEULL,
		0x09E1AC473E892ACAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A0551F10A82C79ULL,
		0x7FC8FF1EE066BF64ULL,
		0xBDA98880EBEC6D04ULL,
		0xA76AE77BB65241FAULL,
		0xE6DC372D3057F3BEULL,
		0x1218F11020708A49ULL,
		0x1405931DFC1FEDD1ULL,
		0x7DF9E29D989FD60EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x455085D43DB65D7FULL,
		0x2F7CC783B11B465CULL,
		0xB67D5EF458A9BA0DULL,
		0x5A828AE05E0C0811ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A03186370D83AA0ULL,
		0xB64371AE74396F7DULL,
		0xB14A36C23C30D494ULL,
		0x4E205F0CA3DCD28AULL,
		0x56A708319BB28E9FULL,
		0x3BD6B356833754DAULL,
		0x3CE19038725D6BB0ULL,
		0xDF00D73279C3899EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06CE4FC08D596B20ULL,
		0x98221085EE7007E6ULL,
		0xBAC59F23360ED0BDULL,
		0x6840508AB6E34007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA444E3380CDFF3CDULL,
		0x80B56C489CEC5C74ULL,
		0x40889C22431AD51EULL,
		0x6A3D426B44E0B418ULL,
		0xEED232B9262854EAULL,
		0x31D93D9EE2AC0EB0ULL,
		0xA5FAE4873F2215D8ULL,
		0xF3BA231709563691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17786AB3B6DC93F4ULL,
		0xE6F491DE42768AB8ULL,
		0xE3C68835A22A1335ULL,
		0x17DE77D6A7ACCDB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FA29C293DB965F1ULL,
		0x37A483680388ED4AULL,
		0x4DFFAB07DC0B4C83ULL,
		0x8EAA2A9FA0130217ULL,
		0xA6CAD605276B4EC4ULL,
		0x675DE82385AABBDAULL,
		0xF7370CD3820577E2ULL,
		0xA5E63E0052369F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61BE60ED17A71ABFULL,
		0x8F94F8ADDAE0CFBFULL,
		0x002B926D28DB181EULL,
		0x2ED75EABD42EA7D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0B6C51DEBB8CB0DULL,
		0xA28AB1231B80A9A9ULL,
		0x1ADF0ED845F603ABULL,
		0x65F917DA3CE37B0EULL,
		0x4030E3F39CB34EB5ULL,
		0xE251E5A413A9EF70ULL,
		0xB005364DB4CF59C1ULL,
		0xB700E3E0C2DFB610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F89B472E567E00ULL,
		0x3AB2C77E06BA3453ULL,
		0x3BA51E611CBD5673ULL,
		0x101AEB372A188188ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09A19FC0641ABF0DULL,
		0x1F2379C970F9779EULL,
		0x02354E973B7FA022ULL,
		0x1D6F8E0E4EC2EFCBULL,
		0x9F8412F5D5F8C3B7ULL,
		0xBEA218FA714FBE0EULL,
		0xA0D764B50A58CC0CULL,
		0x1CB0FC0EEFB8F68DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB73C703E2707CCCFULL,
		0x6B332EF642CFADC9ULL,
		0xE22E4176C4ADEA06ULL,
		0x5FB4F845E43788D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFC03D16CB9981EDULL,
		0x312C18F2747197C7ULL,
		0x4FF4DCA407482149ULL,
		0xA2810BC2D88E28CEULL,
		0x4F548D0993471E8AULL,
		0x6023B12096CC80A4ULL,
		0x7362CC101F583F9FULL,
		0xE5669F63B7001E94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864D2C82A8280F88ULL,
		0x767863C8D6CCB02BULL,
		0x709F2708AE6192F1ULL,
		0x2FBCB4900292B2D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28E35884A8AF0B30ULL,
		0x9722F77933E08209ULL,
		0xF70A1550126BD43EULL,
		0x21C8C80E3DE46701ULL,
		0x80E74D46CDA62C77ULL,
		0xD0285C129808BFE5ULL,
		0x6AE5D325CBC996DDULL,
		0x0C55C7F30D81A143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B38D1072F59A513ULL,
		0x7D20A23BC52CFE1AULL,
		0xD5276CEC5258392BULL,
		0x768476223F225703ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAAC4FF3FC9CB1C6ULL,
		0xC6C5389953B6CE1DULL,
		0x594D509324CD8431ULL,
		0xB63134A771DB90B8ULL,
		0xE1685E9D6F153845ULL,
		0x5ADB2745A133D712ULL,
		0xDD6C41460F1AD448ULL,
		0x8285F0FAE8950442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702A5B5279C30EFCULL,
		0x434D0CEF4168BAEBULL,
		0x375F00F962C906EFULL,
		0x1612F9E5F7FA32A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94ED2C3284D3C1BBULL,
		0x4D826779E8F526E1ULL,
		0xABD41008E9E8D3EAULL,
		0x35726B61C9192E2FULL,
		0x8254951D4A85555CULL,
		0xEDA64E585BAA1F40ULL,
		0xCE5160E67D656CF7ULL,
		0x2DF139211483DD88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED7B4E8B949E6E6DULL,
		0x943208978435CA74ULL,
		0x4BE8723F86F700B7ULL,
		0x0740E64AD4AC107EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7195E6C49BB96F39ULL,
		0x6A56B3E83D7F7B12ULL,
		0x4AF773E4A26AEF09ULL,
		0x8FAF08EB26C7DD72ULL,
		0x051A9BE7E56A830AULL,
		0x596676C326831EF6ULL,
		0x3855F582794DA2C8ULL,
		0x0425A776615E1466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33890B30A988E2DBULL,
		0xAF8C54DFF4F61397ULL,
		0xA7B9E542A3F118C6ULL,
		0x2D45E47D9ABEE49EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE829E2F49D2D5FEULL,
		0x8BBBF93E127D5F5EULL,
		0xBAC04CB48AA2C57DULL,
		0xF54EC7C6C378E30CULL,
		0xB61F70E731DCB02EULL,
		0x70B5E9B86D7679DBULL,
		0x33BD007D1CFD95A9ULL,
		0x432AD45C6E1614A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072D6080B094FE61ULL,
		0x46BCAA9E521375FCULL,
		0x68CE5F46D846FCA4ULL,
		0x6DAA4D7F1ABFF2FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05E7EEC669729788ULL,
		0x4792893F2A429E53ULL,
		0x6657A2C3DD04624AULL,
		0x9EFB4509B06EAD02ULL,
		0x9A0B0323D2D6F079ULL,
		0x0E954435CFD425EEULL,
		0xE851044EB3245B9AULL,
		0x2CC3AABEAF6B51C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE38A6617B55A4A88ULL,
		0x71BAA93C03C03FBDULL,
		0xE25E46727469FB28ULL,
		0x44069D57BA5CCFCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF18C69CAD733933EULL,
		0xB545A0641622D7A6ULL,
		0x09A11AC55C12E8E7ULL,
		0xF530128440E8F7D1ULL,
		0x4EA3FA3ED62551E1ULL,
		0xE239FDC6FC9DF988ULL,
		0x4F78BB3BB588AAA0ULL,
		0x08977F2F5E38B157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DE38F1EA0BDBAF0ULL,
		0x49E14BED9595E1E2ULL,
		0xD58CE5A24E5C3CC9ULL,
		0x3BACF38C3D534AC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F2448D572A23176ULL,
		0x83F8478B13E8E8F1ULL,
		0xB2F0CB6F97AEBDD7ULL,
		0x295FC61E63A51535ULL,
		0x5D0B87557621DD73ULL,
		0x401DBEA1053D047EULL,
		0x9764AE29365260C7ULL,
		0x3733D8CDD1437926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEDA5F84FBA911B8ULL,
		0x08629371DAF793B2ULL,
		0x2BE2A58DA7E91B6BULL,
		0x5B11F4AB73A910F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE47EDA89219BDAB2ULL,
		0x5E9A6B708E1F8C29ULL,
		0x32CEB95A3B06DA9BULL,
		0x0B650D735531A309ULL,
		0x5DF0C081EE52E446ULL,
		0x29AAF51CDA39B8E0ULL,
		0xD44178D9E3A91AADULL,
		0xA8F8ED0D18F78595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63B6DD281E9C0CCULL,
		0x8DFACDB8F2B0FD77ULL,
		0xB486A9B20620D04FULL,
		0x20583D6509EF7746ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CFD87F1A414FAC2ULL,
		0xFEFD8EC3AD977263ULL,
		0xF9C3A8B8F70B7F31ULL,
		0xE92048775CE01A36ULL,
		0x922FF27C34E9D283ULL,
		0x85D3DCC1C6E65ADCULL,
		0x2F586C16740504E9ULL,
		0x1F8492876854FA68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x201B86617ECA3B05ULL,
		0xDC70538733C8EF21ULL,
		0x00E3B40E2FCA39DBULL,
		0x16CE0890D97D45AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x722FE29B23E49F52ULL,
		0x03644B66A485CE3FULL,
		0xC20B1838578910CBULL,
		0xAA688BC8EDAA8F3DULL,
		0xA54DC1686118CFE2ULL,
		0x5F5702835BBEB324ULL,
		0xA2CA2B5320E61EFAULL,
		0xD9403C7818BAB639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBBA98198D937FB1ULL,
		0x2A4EAAE642D465AFULL,
		0xEC0D868F39B1A9F5ULL,
		0x69F1859C99619BCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4E649BACC3EE4D6ULL,
		0xC48EBFBEBC054D49ULL,
		0x3C06440DFA4778A2ULL,
		0x7C380721C5B03149ULL,
		0x8989EFBBB1373E7BULL,
		0x00ACE771CE5FC7A8ULL,
		0xC64F0BAA1D7C6856ULL,
		0x42BDA466C64AF941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5FDF971A722C94ULL,
		0xDE391AA35E3CF04EULL,
		0xABC1FF4E5ABEF566ULL,
		0x645E6E6334D1310CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1B1A0E510006418ULL,
		0x582B9F568DD32A32ULL,
		0xE82A6E45E2E54902ULL,
		0x28CAECE585BA4E23ULL,
		0x7274F9A35E7A5721ULL,
		0x6A47C0F2B3730DA2ULL,
		0xE3F64546F029E416ULL,
		0xFFBAB83CA8F623F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF0EAF25162958A2ULL,
		0x1ED2435D30E7304FULL,
		0xBEB8B6CD891D2456ULL,
		0x1E8245E69A43A431ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE95C25C65D37F7CULL,
		0x3988D3B7B63350D4ULL,
		0x7E79A561F5E20DD1ULL,
		0x7EDF70977AA54A6EULL,
		0x641D8577E6086B3BULL,
		0x9FE503C2DAF9A39FULL,
		0x2484C1262311E047ULL,
		0xA748FE2469C1BF50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF792288B136DF4ULL,
		0xF58762A437419A7DULL,
		0xEA2E510B2A895872ULL,
		0x53B529FF2D67B053ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76F27198A3D89700ULL,
		0xDE51873D57177720ULL,
		0x8D951D65023C9191ULL,
		0xB1E2FD047CE8D0D4ULL,
		0xFED1EF9420629FB5ULL,
		0x66C9C11D3B5F33F0ULL,
		0x9968C70DBF7A8937ULL,
		0x9FE90F43FEFF471FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1C0195727C4F6EULL,
		0x2044319427392CE6ULL,
		0x5322A96F6E6CEFCBULL,
		0x6E7B411C56CD5F85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DEFE22E576EE32CULL,
		0x9BE3FC8DF9E14195ULL,
		0x1C959011DAAA5D9DULL,
		0x0775D12536D376EDULL,
		0x6DA9630D90CA3F74ULL,
		0x7DA4938DC4E56F40ULL,
		0xAA524A4662331317ULL,
		0xCD1D9C1BD4CFAC2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5149631D57452D8ULL,
		0x4251E39933EFC525ULL,
		0x64CC96846E3F331AULL,
		0x79DAFD46CDA70568ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x157E80F39868BC52ULL,
		0xF0AB03099CDD107DULL,
		0xA1C7320B717576F6ULL,
		0x291CDA63AF8AC0CDULL,
		0xB2B857525616A45AULL,
		0x59F5447D9783735BULL,
		0xAF66C6806C582F04ULL,
		0x3EB7C5C336873CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CDB772C5FC52304ULL,
		0x4B132DAE1A603019ULL,
		0xAB08A91B868C719CULL,
		0x7864355DC79DC85FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F5A37213165412BULL,
		0xED3AD54A89761FFFULL,
		0x8F9FB30019C22EA3ULL,
		0x8410C5C8C812BD53ULL,
		0xEDDBC7D81E43C7ADULL,
		0xFDD9849379BFB5DFULL,
		0xED6918C17FFEF2B0ULL,
		0xD58237B5E8AFD929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF9E135AF74E999ULL,
		0x9B84832E9BEB1F3CULL,
		0xCD395FB9199A34E9ULL,
		0x35650AC9522CF98CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34776E21130BC64ULL,
		0x3C35190057BB55CAULL,
		0x3E870D98C99DAC43ULL,
		0x9BA44EE806A2DCE2ULL,
		0x194B3E1AD4AFB365ULL,
		0x315385219689AB67ULL,
		0xDA7CC8D9BED68C72ULL,
		0xB513216C7804C398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA472AEDDA3456164ULL,
		0x8E9ADBFCB02AC718ULL,
		0xAD0CDDEB1D768536ULL,
		0x7C7B4501D757E592ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D76C1B098F00895ULL,
		0xA8A20623773D5593ULL,
		0x53CAA9527623FF47ULL,
		0xD077751C5CF82408ULL,
		0x0B72BB025132C869ULL,
		0x6D5EF49B53DFFD45ULL,
		0x2AB7F99259B4A19DULL,
		0x1E4658CB1E48762BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x307E8408A679C8E9ULL,
		0xE4BA5531EA7CEDD3ULL,
		0xAB19B50BC6F3FCA5ULL,
		0x4EE8A342DBB9AE70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81275184DF623F06ULL,
		0x6D26CB3087B049F9ULL,
		0xB80A7800D6D49560ULL,
		0xD8CA5B73D73302E1ULL,
		0x0258C6CB0113D65BULL,
		0xB9A4B4661B74726FULL,
		0x2CE01339AC9DEFBFULL,
		0xC3213A9D260B2445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA54D3A7085414E9ULL,
		0xFB9992589AF94673ULL,
		0x614D529076462BD5ULL,
		0x4FB90EC77CDA6526ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5448973D4409407ULL,
		0x286B96DB79935BC3ULL,
		0x12E7805C91E521A2ULL,
		0x547422F3B6B25695ULL,
		0xE254B2FD83C2BD67ULL,
		0xFCB886D572B8EB11ULL,
		0xFF0D9D0C882EBDABULL,
		0xC2FA1EF5B11CAA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD71B156328B59FULL,
		0xABCF9A8A8106406BULL,
		0xEEECD038C8D54929ULL,
		0x4594BB6C00F39BEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28C217A60822795CULL,
		0x9FF15321C8100F37ULL,
		0x5873831D602E4766ULL,
		0x7BD2E87FB9A77F2AULL,
		0xB9C51782040DD6C9ULL,
		0x2A40A062DC4ABC06ULL,
		0x3E9631594C6CE447ULL,
		0x2B7DF5347F706838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC0394F2A2305C29ULL,
		0xE58921CE7B27F836ULL,
		0xA2BED65EB85829F6ULL,
		0x70854E4AA456F783ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93BB62F631E88D19ULL,
		0x7C33A894DF937FF8ULL,
		0x8606311D97F15EF8ULL,
		0x0741B0FB63EB4D03ULL,
		0x531FD86CE5706A95ULL,
		0x9141B28B78BF2320ULL,
		0xEF35FAB2EC691D1FULL,
		0xCC8DA594F5BB9985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA758320409863ABULL,
		0x0BF42948CBF2B6C4ULL,
		0x080967ACAF8BB1A8ULL,
		0x64484517DDC416E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x519DB19F1C8E11A3ULL,
		0xBB25327F885E06F5ULL,
		0x3BD87DA39650934AULL,
		0xC8C3FA13030021A0ULL,
		0x84CC77C2E54DB4A5ULL,
		0x2076925F6E279B6DULL,
		0xA562B1EEA264E3B9ULL,
		0x8D27A9EAC18C54D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F7788D2616E552ULL,
		0x8CBEECA9E23F1937ULL,
		0xC87EE70FB14A60C5ULL,
		0x3CA732EBBDD4B97CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x940C40E294253F5EULL,
		0x40C4AEFDBE403DEEULL,
		0xDDBE02BC50E7B18CULL,
		0x4298912EBF9425B7ULL,
		0xD991084FDC2DF36CULL,
		0xF60C0FA8B857F5DBULL,
		0xDD4F3ACAAC915DDCULL,
		0x502600CD6B1F64CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF937CBD42F7632EULL,
		0xC68F02091B4EBC90ULL,
		0xB780BCD1EE7BA058ULL,
		0x283CAFACA63D1BD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81574FF21D29AA9BULL,
		0x83B2880525774C1FULL,
		0x4BC22825DCFB3BB7ULL,
		0x2ED99D28D0E6CF01ULL,
		0x128E33C7E66D547AULL,
		0xE3D6A3BE1F5ECCDFULL,
		0xD18B376B09857E65ULL,
		0x5EFDE631011B1658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4272FF9E516436CBULL,
		0x558ED63DCD89B53CULL,
		0x666C620946CBFED7ULL,
		0x4889C86EFAEC2030ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A646C37087708ECULL,
		0xCEEA8467DAC67313ULL,
		0x2C8241D4D0664E92ULL,
		0xFCBECF3D8E7D8277ULL,
		0x6E115DAB9F18736DULL,
		0x2213B9E51F7DCEE1ULL,
		0xF6F6DD5A6CFC3EC9ULL,
		0x06C431152D003F48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F853B0A6182B53ULL,
		0xDDD81C6A87732889ULL,
		0xD5271D40FDD7A06DULL,
		0x7DDE18623C86E74BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC7D1AC2E03B18FAULL,
		0xBE9F87696F9E515DULL,
		0x0EAC6AD8A8F669C5ULL,
		0xA7B9284429B43477ULL,
		0x1F97413F7CC34620ULL,
		0x816010A091377905ULL,
		0xFCA9188340E895D4ULL,
		0xEE44BFDD9180C32AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF0CA2F65378712ULL,
		0xF2E1FF3EFDDA4820ULL,
		0x8FC60E544B7CA750ULL,
		0x05EDA327C2D12CD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x243FD53FEAD6541DULL,
		0xE3A87271671839CEULL,
		0x316E3C1EA5FDCC5BULL,
		0x09448CB9052CD36DULL,
		0x785E8264F64615B4ULL,
		0x99AF26A7DF8D33BCULL,
		0xCFDAAC909EEA3140ULL,
		0x75116D72283AEA48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0247303C793D8F5BULL,
		0xB3A82F5C960DE7C8ULL,
		0x0BE3D9963CC11BF2ULL,
		0x69DACBAAFDEB9A3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6205E9C6187618AULL,
		0x34F61F5FF2B8B75FULL,
		0x82E2B4D3003A232BULL,
		0x0A8A15329BE0258AULL,
		0x6684EE8375CA13EAULL,
		0x14BC75F13F611632ULL,
		0x2E1F41F085883E58ULL,
		0x069480A29DB10B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDBC61FDD86566CULL,
		0x48EFA12F5B2202DBULL,
		0x5B867E86D273643EULL,
		0x04952D560427DD17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x661782938EC3CB1FULL,
		0xAE4C7AE18ABC5747ULL,
		0xFD5BC9672C94EF32ULL,
		0x8643023C1CAED3B3ULL,
		0xB346C29AE5EBF55AULL,
		0x737C0ED72FB7D40FULL,
		0x0693356429E99103ULL,
		0x76F4D01B74493241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02986591AFCA3927ULL,
		0xD2B6AED2A005D19CULL,
		0xF735B645654075B5ULL,
		0x2E99E64F5F8C495AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2021D5F421E3B9F1ULL,
		0x662402D7FF6F7478ULL,
		0x4E417C03F65C0D98ULL,
		0xA8640328FE1A469BULL,
		0x8CAF8A0BB600D93DULL,
		0x1FF28810C27A929DULL,
		0xFAF9B566136CF29DULL,
		0x8EC7B6BDBCFD007BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023053B12603FC30ULL,
		0x24243554DDA137DBULL,
		0x8F52692AD88810EBULL,
		0x5A0923530BA85902ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACCBA61B97954A12ULL,
		0xA2E60FDCE8E5958EULL,
		0x9D6BFA315CFA35D2ULL,
		0x3E0485B70A9929EFULL,
		0xFE314638CD276425ULL,
		0x835D2EA1255E5E47ULL,
		0x86E77A7CA2281ED4ULL,
		0x8B1751C87C0D697FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681C128A0B6E2A9BULL,
		0x22BAFBC874E7943EULL,
		0xA3C828B16EEEC95EULL,
		0x637AA9797496D2DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BEAFA6DC1205B6AULL,
		0xEDF4F006001FC02FULL,
		0xE57F9E93DCD6D5B1ULL,
		0x0445023D161B408DULL,
		0x56A6C800C56FD7D6ULL,
		0xE59B3338A71EA472ULL,
		0xDC6668C96E33E76DULL,
		0x84A9807486403D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28ACAA8B0FBA6813ULL,
		0x02FE8A6ECEAC2928ULL,
		0x9CB32C7A388B3002ULL,
		0x356E138903A45E6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FCD30E0EE2CFB63ULL,
		0xED68B284726E8487ULL,
		0xE64CCDFD321D7499ULL,
		0x5D1221D98CA1D633ULL,
		0x21F1121D7855A8EBULL,
		0x41178BEA16DFB7A3ULL,
		0xD9FE01A871024B27ULL,
		0x1BAAB97BD0DFFA30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1995E140CAE40EDDULL,
		0x96E77743D7A3C6BEULL,
		0x42010CFDF8749C6DULL,
		0x7869AA3A8DE0F974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CE686A4877F66C1ULL,
		0x232C4F741CAAF0A8ULL,
		0xA62B766B02E17590ULL,
		0x7E56653D52A11B6EULL,
		0x5C35D7039B3E97F1ULL,
		0x4F8E42D069C44E62ULL,
		0x427B8450D05B448AULL,
		0xCF066211986536B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE4712D92C9F921ULL,
		0xF24A3A63CFCE9342ULL,
		0x84811A69F06DA217ULL,
		0x3948F3D9F1A739E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B14E51CE54ABBDULL,
		0x6FD050A9FF665F72ULL,
		0x8483FE887B682E06ULL,
		0xD68AF0CBB0ACFF10ULL,
		0x4BF1A36B60C95724ULL,
		0x4E8DD6EEF8DCC035ULL,
		0x36092EFCAD41B4F2ULL,
		0x9A426C9958FC60BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8F90422C379E92ULL,
		0x18DE3822F02AE75CULL,
		0x89E0F80A332909FEULL,
		0x3C670F8EE6235B00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85C55437FCA4CEA5ULL,
		0x28D1DD70443781A6ULL,
		0xC52DD6D6E7DE5AAAULL,
		0x70BAD6544825C78EULL,
		0xF5132B6F2BF2D68EULL,
		0x806454C2E8EFBBC5ULL,
		0x55AAD924E2F53628ULL,
		0xA470C338F0BE2CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE69DC6B882B0AB5CULL,
		0x37B6725ED7CD6108ULL,
		0x7C8A1250984464ADULL,
		0x5977D0C804606B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD57A0AD3A2BE3447ULL,
		0x4F99C8E38022CFB3ULL,
		0xE5AC0329F67768B5ULL,
		0x2D6C31A8658A0FD9ULL,
		0xF244F6B9829D0B42ULL,
		0x60B8279E880D46CEULL,
		0x0A70F5CA617372F0ULL,
		0xF04AC093EB6FD303ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB6AA5D060DE558ULL,
		0xAAEFAA6BB21B526BULL,
		0x72707F346D9A7863ULL,
		0x5884C79D5823624DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C422C65560D74B6ULL,
		0xF9251599C04EE843ULL,
		0x6DD67C9936D1F173ULL,
		0xE8D612357CF85382ULL,
		0xCE17B7DBD390F9DBULL,
		0x3EB6BD4299CFA19DULL,
		0x6F4F7628363524A7ULL,
		0xACA273E2C467A3F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C77706BD928F27ULL,
		0x48452D7C9520E5AFULL,
		0xF3A2069142B56247ULL,
		0x08F345DEA45AAA16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86C9598B5678271AULL,
		0xFB1AF1B6DB2F0C40ULL,
		0x3450FEC288A168B8ULL,
		0x1D1983731DD6AEF6ULL,
		0xD352F96947B061DCULL,
		0x19CB828E0F7E705CULL,
		0x95B628075DF27123ULL,
		0xF6C03C24E5F62472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51A5F2BFAA6B32DULL,
		0xCF5052CD27F3BA07ULL,
		0x6D5AEFDA7A9E33EEULL,
		0x3DA270ED406017F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB73E92A178B9DE90ULL,
		0xBB45FC6578C7D222ULL,
		0x59BA733CAF82DED1ULL,
		0x4DE519A9295DA250ULL,
		0x1638E5BF613CE165ULL,
		0x8B2BA15711E6111EULL,
		0x0D91A13DFFEAC12BULL,
		0x15C183DB3D90042AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B0AD09E7C35413ULL,
		0x63BFEF5220EE5C9AULL,
		0x5D586270AC5B8B48ULL,
		0x089EAC344CBE408EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x248413CB3A213826ULL,
		0x89126A4684173CA1ULL,
		0xBCE01259CBD90B8DULL,
		0x90BA7E2F83901275ULL,
		0x6E76D9786A640925ULL,
		0x3F65CB3758032762ULL,
		0x349A92A275FE23C5ULL,
		0xBF53DF8D066893D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A285BAB04FA97DFULL,
		0xF22E947D948F153DULL,
		0x8BD1D6774F925AD4ULL,
		0x772DAD1E771603F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x094C6DFD70F63944ULL,
		0x03D2E613F481C0F2ULL,
		0x5A3BB9B315E4E646ULL,
		0x71D06C371FE97C4AULL,
		0xEC5E17A8334F4228ULL,
		0xA78BBD5AD47B300FULL,
		0xDC8D624DC2E24C37ULL,
		0xC45A149C2B04CB58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F43F0F50EBA0F95ULL,
		0xE291018F7ECAE34FULL,
		0x1738513E037C3688ULL,
		0x172F7B65829FAB7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07594DBCF4E115DBULL,
		0x7B870436D29ECB33ULL,
		0xA107A3D54C7BD857ULL,
		0x15964B4664EE2FADULL,
		0x22B936A135CD6A09ULL,
		0xBFE005F0CC6FA213ULL,
		0x15AF9DA5D5F99607ULL,
		0x2247F087B67214D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED769AAF15ED3EFULL,
		0xF6C7E5F52B30DA0AULL,
		0xD9190A730F881D7DULL,
		0x2C43FF6B79DD47C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9409E8F40899325ULL,
		0x5104319F950DA61FULL,
		0x3182B42DF59212F8ULL,
		0x4018DCB487BE399CULL,
		0xE5077BCD98AE713AULL,
		0xB0704F81D039E3ECULL,
		0x470C48FB959C60F6ULL,
		0xF7B3C289485CC272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC85CFF13EA6E673FULL,
		0x81AFFEE47DA57B49ULL,
		0xBD5589862AC87796ULL,
		0x04C7BD1545831692ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC221A19BB503B2D3ULL,
		0x12E215E2E66DA77CULL,
		0x3ADB9E2AE9BB60BAULL,
		0x6C82F7EC3AB913D7ULL,
		0x517934E932113218ULL,
		0x443533CB61B9652AULL,
		0xCBBDCC2B682B951AULL,
		0x1F7B09A3754D1C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1F7C3923912321ULL,
		0x32C7C61367F2ABC4ULL,
		0x7907EC9C603382A0ULL,
		0x18C6662FA42B4E5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE28A7694435561BEULL,
		0xF451EB8F7ED33C4EULL,
		0x5E2C90A47C9B0CD5ULL,
		0x32B44DB5FCB635C0ULL,
		0x297CD6EFA5B5781AULL,
		0xC25F22EEFD3B8FF8ULL,
		0x1311C40F372A9383ULL,
		0xA51603F8033019A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B125E26DC45393DULL,
		0xCE711B0915AA9B25ULL,
		0x32CFAAE6ACECF264ULL,
		0x33F8E48675DA03A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA778068C55040C5ULL,
		0x1A67F9ECB464E458ULL,
		0x7CD93D88743E96C1ULL,
		0x9A078904B2AF7415ULL,
		0x57BEE2D10513F8BEULL,
		0x9D515F42F5EB0185ULL,
		0xAAE0302EE6ABAF32ULL,
		0x3D8967A97FBD8954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0CD2B6F86472E62ULL,
		0x747C1DDD35471E23ULL,
		0xDA20647EB1BA9844ULL,
		0x3C6CEC2DA8D1D6A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ACD4990E8EAE825ULL,
		0x7F98D72112F52C6BULL,
		0x06F40A2449E90228ULL,
		0x19B7F7DEDB6354B0ULL,
		0x7D6BC743B066141DULL,
		0x841512B6CA746F18ULL,
		0x53373077DC1B931DULL,
		0x874F65433AD095A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38CCDD9D1811E76BULL,
		0x1AB99E43203DAA0EULL,
		0x61253BEEF600D88AULL,
		0x2F80FFD996598AEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA74FEC5BBDAB71A0ULL,
		0xBBC5978D3523187FULL,
		0x0F30258193FA952DULL,
		0x793FD64555FFEDC0ULL,
		0xE24FF3DEEB5B0F28ULL,
		0x347D7E4E11DCC1A6ULL,
		0x85448A7485F4E2F7ULL,
		0x28A7F3C6731B3BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2E1F72AD2FB287ULL,
		0x86665723DBE7D745ULL,
		0xD75CB2CD765445DFULL,
		0x022E05BA6C0AC935ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E45B1FB2CA7039ULL,
		0xB1621889170EA129ULL,
		0xF61C168FBEB69A54ULL,
		0x15E64338FF2C171FULL,
		0x5761628FC19AD08AULL,
		0x49BFEFD5271C7D60ULL,
		0x98B8E809733A4F26ULL,
		0xA8D1D3932F856941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4258FC766FC5686BULL,
		0xA3DFB22CE5493D76ULL,
		0xA18E87F6D95E5A03ULL,
		0x250BAB120CF9B6DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1884BE856148EB0EULL,
		0x85CD3094FCCFD04AULL,
		0x7C823BA5A3255D0DULL,
		0xB958ACA1864A1A60ULL,
		0xF8690ABBA46B2601ULL,
		0xE63F8C17485BCD72ULL,
		0x574F30075A95D9E6ULL,
		0xE586E03FE1629FF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF81C565FC9309453ULL,
		0xB33BFC09BA704F5AULL,
		0x72435CBD1563B553ULL,
		0x4B5DF61CFAEDD8A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7AC2685C72A4976ULL,
		0xC497084B8883DB92ULL,
		0x053EC5BA6125B1A6ULL,
		0x0777A1396093E788ULL,
		0x2F1B014F8841C00FULL,
		0x6AF0C3C78C1F7475ULL,
		0x44061E638DDAA3C1ULL,
		0x662B6D84C780D4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5AE585400ECCDEAULL,
		0xA45417EA552F24F7ULL,
		0x1E2748816F9A005CULL,
		0x31E9E2EEFDB38202ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84D6ADB6C5697777ULL,
		0x35B0827DBF258052ULL,
		0x30012ADC09ECEBFFULL,
		0x136743663CADA149ULL,
		0x91E32A660D2BB062ULL,
		0x514FAFA3CC64CB65ULL,
		0x4D37507D9DD03D6CULL,
		0xA916B62363FCB5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8EF8DCB9E5A9B9ULL,
		0x478494CE161BB166ULL,
		0xA6371D8176D60A13ULL,
		0x2CC64CA71430A4E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7320A2DFA1FC2EAEULL,
		0xB3BEECF8E5719B83ULL,
		0xB331D2B46B387413ULL,
		0x610E202C46D3552FULL,
		0xAF143A1A0F0B640EULL,
		0xC3BF1BEB900AAA60ULL,
		0xDE4993F4F37FDCAAULL,
		0x45CF6EFFBF47B866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702142BDDDAD0A51ULL,
		0xC21D11F04706E5DDULL,
		0xB21DC9109033356CULL,
		0x3DD89A22AB78B474ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86D483E94663ED51ULL,
		0xE65B1C63B355D571ULL,
		0x8323D600C1C4528EULL,
		0x2F67E00558C24A72ULL,
		0xE9480BA820CFB976ULL,
		0x2A51CC420B33347EULL,
		0x7F88D145C73B9D88ULL,
		0xF7AC1C459DF9B8CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27863EDE25397A40ULL,
		0x2E7F6E315CEFA048ULL,
		0x7172E65C549DB4C5ULL,
		0x72F4125ACBD3B8F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E7ED1B697B2CC5EULL,
		0x8A3EE751E7D0FF68ULL,
		0x98275A8971A4905EULL,
		0xE8DE9E5ACE6115BFULL,
		0xF65F0B3741CA4369ULL,
		0x561EA9CD4E6BB076ULL,
		0x98F482F9F97F53F6ULL,
		0x9933BE65017EEFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309A7BEA5BB8D171ULL,
		0x52CC1BCB8BCD3111ULL,
		0x4C72CBA47A8B06EFULL,
		0x268CE1590738ADD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73D3CC27BAAF9263ULL,
		0x2211B004D6F29103ULL,
		0x2E01D38B0F84640AULL,
		0x6788C92D8AFFABC1ULL,
		0x72303CC36D06C6BBULL,
		0x1D10733BCE3F116BULL,
		0x561E96E5D94CF155ULL,
		0x01AC96599567BF3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66FCD129E9B11238ULL,
		0x7282CAE5744F26F6ULL,
		0xF68C39A950F036ACULL,
		0x27271A79B8660E8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C4AC9452B67C686ULL,
		0x588096437FF039CAULL,
		0xF0DAEEB63125AEEDULL,
		0xD5B411FA1B4F417AULL,
		0x13BF2A839F8AC29BULL,
		0xEA2B4A4BB09535E3ULL,
		0xF81443D2C8C8B019ULL,
		0x1E85FFD3BD40BE61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AAB18CEDA00AA46ULL,
		0x1AED9D7FB616397FULL,
		0xC3DCFFFFFEEFD2C6ULL,
		0x5D980B6832EB8405ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC70293FC4805F53BULL,
		0x3E9FC6C293E9A1F8ULL,
		0xFFE9AC35D8A00DFBULL,
		0xB9623AA04E4CAC05ULL,
		0x613305BF445F41B2ULL,
		0x8C85E65A066351E4ULL,
		0xAA28153C5D8515A8ULL,
		0x0CAFB44A66D19C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34956E606E29B606ULL,
		0x1A7FF81F86A7C9DFULL,
		0x41DCD32BBA614500ULL,
		0x1B76FDAB9169DEA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x368478C953F44D35ULL,
		0x63B69504E6695D62ULL,
		0x0C05030ECFAB85DBULL,
		0x8F8C9CFD4E81756EULL,
		0x6932EFE60CE6BFCAULL,
		0xC998D15349CF598FULL,
		0x922E5E889C14B383ULL,
		0xD64A55D2B15CF8B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41414EF3E34C9F1ULL,
		0x5065A761DB30A8ABULL,
		0xBEE70B55FABE2B6BULL,
		0x5E955A43A24E6061ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E733253354B7ABULL,
		0x4B2D0DB56EF392DAULL,
		0x53EC950AD596D37AULL,
		0x9250C1684773F731ULL,
		0xA0B25CA91D1CC788ULL,
		0xB213F8EE54D6E711ULL,
		0xDE183463BC4F6CBFULL,
		0x60E6364AF3975C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD60F43F859A5802ULL,
		0xBA24011606D9DF77ULL,
		0x4B845BD8C960F7EEULL,
		0x747CD0886FEBA5B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC14F671E01D67053ULL,
		0xD78BAD2EA46FFAFFULL,
		0x39EEE24DC7FE10F5ULL,
		0xC0012EE8575B289CULL,
		0x46143AC3A26E94D7ULL,
		0x9B9D4CD6167610B2ULL,
		0xA278EB5D7662070DULL,
		0xDD16C4BF8D28FED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x285020281E408D36ULL,
		0xF0E514F5F9F67576ULL,
		0x57E1D22D5A8B1CFAULL,
		0x116263574B70FBE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB2492B6AD67F1F0ULL,
		0x9174FC932E8BD64FULL,
		0xB6E609124709DC60ULL,
		0x90FE7B5C2FFC5C4CULL,
		0x39E2D34325F66D82ULL,
		0x4F1D4C72C9B91248ULL,
		0x92946FFB978DDA23ULL,
		0x496148EA2742E3C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52CFEEAE4FFC34DEULL,
		0x4FCE559D20048D08ULL,
		0x78EEA86AC6183D9EULL,
		0x756F4E1E03EA2BC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD90465821827ADBULL,
		0x050B604CD2C816BAULL,
		0xB02020161202559CULL,
		0xB64ABAFE14C14D68ULL,
		0xD7E5B432ECCA4FA4ULL,
		0xD491BAB3DAC8054AULL,
		0xFA9450064554DAF8ULL,
		0xAF05001A07E4CD11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A905E7478A5122ULL,
		0x92AD16FF4C78DFD6ULL,
		0xE22401045C9AD68BULL,
		0x3108BEDB40B7BE13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FAC7C969634F34DULL,
		0xCD9F9DC7204D1453ULL,
		0x9FCC064EED94CBB8ULL,
		0x38DA937A99FE0A84ULL,
		0x0BD412EA473A77EFULL,
		0xAD461F3DBED4893EULL,
		0xB1E3D0397B15F1F0ULL,
		0x0ACB07ECF3A30F1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21274B5D28E2C100ULL,
		0x860840F173D97389ULL,
		0x079CEED732D6B572ULL,
		0x52FDC0A6C4324939ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DEEA0D3AB79385BULL,
		0x027216FBEAB31736ULL,
		0x5D648E78AA8A0CAEULL,
		0x3E024E74F5B8AE3DULL,
		0x3D9F926D9B704599ULL,
		0x4AC0C752AB8EEE28ULL,
		0xCEF3056D7715017FULL,
		0xE67488568A2D4E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x839E5D18BE23921DULL,
		0x1B0FAD4161EA712FULL,
		0x15775CB857A84593ULL,
		0x734E8B4D7872523EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB451728EA9E9006ULL,
		0x1372EF6A1F07B737ULL,
		0xF40E1AE85C5FE961ULL,
		0xC9202DC938DE3BA7ULL,
		0x75F092227E3B0A43ULL,
		0x153E203361CB876BULL,
		0x6804BC0A1C2391EDULL,
		0x0062E79789EB6D80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFAC847A762160BULL,
		0x3AABB70AA33DD12BULL,
		0x64C2046889A79292ULL,
		0x57CE8E47B1D07CB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA15143A604C0661ULL,
		0x124C80C0ADF3166AULL,
		0x57352C1741217907ULL,
		0x587796D01F263F08ULL,
		0xBDCAFC98D5EF59AFULL,
		0x9D56242C3627E9ABULL,
		0xA5E7913BC47A5FE8ULL,
		0xB691801CB419DC18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63692EA21D35A5DULL,
		0x6D15DF50B7DFC5E8ULL,
		0xF794BAF66B4BB58EULL,
		0x72109B12DAFCEAB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF00A46A4E4560E8DULL,
		0x6514DC4BE505CBABULL,
		0x32DFACDDDA8A67F7ULL,
		0x11D1119570E0945CULL,
		0x2307254293419BC1ULL,
		0x529F1A08B4922D47ULL,
		0x234EF8C382B575F2ULL,
		0xD211A7B0A104B058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2319CE86C01331CDULL,
		0xA8B2B996B2B8843BULL,
		0x709899E34179E9EFULL,
		0x406FF5CD5792C171ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81CC25DBA3C89DC8ULL,
		0xB87EEFDBD1467F0DULL,
		0x0086235944B6A438ULL,
		0xABA654686FCC43FFULL,
		0x41CD8C95CC189E5CULL,
		0x939379507737231BULL,
		0x64701CCE4F9FD9E5ULL,
		0x1C2AC2FB1383B525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464F0417EF70201BULL,
		0xA062F1CD8375B519ULL,
		0xE92A69F91670FC4CULL,
		0x59FF45AD5559278BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91C923F364DECC78ULL,
		0xC945DEDB78304A11ULL,
		0xD0A88799A3F55AC8ULL,
		0x4D3553E92CADAE74ULL,
		0x156852F75A5F3D41ULL,
		0x6112F6C7E315ADECULL,
		0x7DFEDA2F9E3A8960ULL,
		0xDCCD7D08BE29DEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4574AACF01E904ULL,
		0x321680872D681B1CULL,
		0x847CEAAB20A5BF17ULL,
		0x13B5E33566E4C2E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BFFCD93EAA44482ULL,
		0xD3A9947365D06B60ULL,
		0x7E5B72A427826D49ULL,
		0x4F5A578DEFA4A584ULL,
		0x711252AE03A7B250ULL,
		0xA1554A167A636B51ULL,
		0xE48E336F6632AC82ULL,
		0x113DB522E2E786B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44B813687588BCC1ULL,
		0xC65293C990925977ULL,
		0x6B77152D530808ADULL,
		0x5E833ABB9E02A51CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x214257692675B48DULL,
		0x9AFAE659AD6EBD36ULL,
		0x47C26291813AA08BULL,
		0x79D230B8A68120D8ULL,
		0xFFE28EA701827228ULL,
		0x37DFC01C11FE8197ULL,
		0xF4AE388B0DD7E561ULL,
		0xAF8D6D3E783D52D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CE384335FD2AA6CULL,
		0xE6316A845935F9C6ULL,
		0x999EC7358F46ACF9ULL,
		0x08D067FE7F9B6C9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD05476EBA77D3D5ULL,
		0x29757EFBAFD71933ULL,
		0x34CCB9DF5047E6ADULL,
		0x9A90729E0BC440A5ULL,
		0xBE9D36E8FF277784ULL,
		0x0183CE8BAC7CD2AEULL,
		0x425EB5A311733DC9ULL,
		0xB2D074BD7AAC2D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085B6E049A53956FULL,
		0x630627B74A5E5F24ULL,
		0x0EDBB013E7631283ULL,
		0x2581C6BE41530481ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x478705960D024729ULL,
		0xE036C79D528C1B08ULL,
		0x6DB8390B086C8709ULL,
		0x4F9987401311B74EULL,
		0x59D94DE4D62AC2E7ULL,
		0xAA496857F8812038ULL,
		0xC1EB3ADCEA0BECE9ULL,
		0x76AA68726F10B3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC8958DD75B380CULL,
		0x271C44AC35B6E365ULL,
		0x36A2F5D5C631B1B9ULL,
		0x6CE5083C8F8C6553ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61CF96E958064B62ULL,
		0x24E24EC37201BE31ULL,
		0xC34EE4AA4D449CF4ULL,
		0x4C0C2BF2815BB923ULL,
		0x156C9B3787FEA0DDULL,
		0x72EBE9E90D636E68ULL,
		0xACD86BBC59CEC657ULL,
		0xDCFE2539BA223AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FEEA12787D23116ULL,
		0x33E7075B6EC421A4ULL,
		0x6B6EE29FA1F60DEFULL,
		0x19C5B284227070B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63B1BD5CEB5946A6ULL,
		0x65542C5F93BA36FCULL,
		0xFC4F3CE93B66F850ULL,
		0xDEAEF156799DD2A9ULL,
		0xCFCADE369F00D4C4ULL,
		0x6F31766F1F64180DULL,
		0x19DC23AFB9BB1968ULL,
		0xB488EAA097A666B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BCEB9788578DFD3ULL,
		0xE6ABC0DE3C95C909ULL,
		0xD2FC88FECD2CBDD0ULL,
		0x2B01C52CFC511223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9A088B2A3692691ULL,
		0x62FCEB4C71C5A832ULL,
		0x74E92B3343FD71A8ULL,
		0xEFC65EF5B72D76D6ULL,
		0xD019D016E9161DC5ULL,
		0x41FE62063132645EULL,
		0xE17FB1A9086308AFULL,
		0x40DAC30DCDC4D92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D756C193CB1935EULL,
		0x2EBF7837BF408E45ULL,
		0xEDDD8A4A82B0BBACULL,
		0x103F53024265B37FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3FEEB973C7FB2C2ULL,
		0x81CE3522E1AAD7EBULL,
		0x140739CB07A50CBDULL,
		0x5CE706B81FCCCD72ULL,
		0x28D455BDB06384B4ULL,
		0xEB5137DD88C23BF2ULL,
		0xB6C80A57B4BF0D15ULL,
		0x05EB89D1DE711D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD383A5BF6B4565A0ULL,
		0x6FDC80052E7FBDDDULL,
		0x35B8C2CFDC00FDFEULL,
		0x3DDD7BDF24972215ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4113C461FED3F600ULL,
		0xC45C16A6650FEDD5ULL,
		0x33573C4748131615ULL,
		0xFD857DB3DBAD2DCCULL,
		0x79794D3C0F51378EULL,
		0x12E68168FBF9A4FDULL,
		0x0B444BF4D6418658ULL,
		0x7FFA6DB814C51CBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49153B4C44E237F9ULL,
		0x92934C3BCC1E6B75ULL,
		0xDF7A829F15CD0728ULL,
		0x7CB1C706F0EF7227ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x152BE3C349A9AFA5ULL,
		0x4809A4FC0FD30DC5ULL,
		0x1742B1B7FCEFAC1CULL,
		0xDE06724A69D2F923ULL,
		0x2277DBC549C62E05ULL,
		0x41B93A24B5EE01EFULL,
		0x965D9E0265E76510ULL,
		0x6139021A58E34101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32F6830C3D14869DULL,
		0x0988466F11275744ULL,
		0x692826131D48AC86ULL,
		0x4C7CC2339B8E9F5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A2B77BA27FA1140ULL,
		0x12445A4E1FD9AD9BULL,
		0x107107C19C09BD77ULL,
		0x030C53F84E459813ULL,
		0x772678C5CE32B491ULL,
		0xCC27F2219F8DB22AULL,
		0x9A9D8F27EECE15BEULL,
		0xB8D835CA048AFBD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E16516C380E2C8ULL,
		0x60324B4BCEE21FE9ULL,
		0x03D447AF0EA0F7C9ULL,
		0x73244FF4FAE6F90AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16BA601EC308CB2FULL,
		0x60285D5C16F11A22ULL,
		0xAA0CE890AA703D5CULL,
		0x1FC6CC258656AE42ULL,
		0x4C23DD54FA62CBFDULL,
		0x7CB3C6B50C43B736ULL,
		0x5F9D46F64F088B94ULL,
		0x136D0FC458E59E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x640D3ABBEDB3132FULL,
		0xE2D7DC3BE8FE4C31ULL,
		0xDB65712065B4F566ULL,
		0x01F7234AB86C3128ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C7159B658B59F3DULL,
		0x98BA0B7E183B1C5EULL,
		0xE00C81A35B3CFE29ULL,
		0x81892F394ABC940DULL,
		0x909C46C058C07D9AULL,
		0x273CF254E65232BFULL,
		0xF9C0E9F1E4186B82ULL,
		0xCE7539EA7C2E2D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A3DA43854848B3ULL,
		0x6BC60418486EA4CDULL,
		0xF2AF3B8B36DCF37BULL,
		0x26EFC807B9975662ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D1E4FFFBC75D51DULL,
		0xE67739EB49C1ED45ULL,
		0xA75FB4B5A031D093ULL,
		0xB0FD5E38620B9084ULL,
		0xF07AB9D3AA8F0E01ULL,
		0xCD7067EE7486E8F9ULL,
		0xCE9ED37891B88366ULL,
		0x3E3108A394A906FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF55E56B0DB1EAACULL,
		0x6526A75095C8825EULL,
		0x52F3189B419551D6ULL,
		0x6C44A68073229A57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32AE3C52A842277AULL,
		0xEF6071940DCE1EFBULL,
		0xFD68CC91CAEE5D08ULL,
		0x83C5C4255CBEF47DULL,
		0x15B618BF2D715071ULL,
		0x1DF18FC0CCA5CEF9ULL,
		0x51F9A62A9F8A948AULL,
		0x51A2EDA947740272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB5E8B367141A1BULL,
		0x613BC8326E6AD7F4ULL,
		0x287776E579806989ULL,
		0x21F50B45F7F75176ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x137DCE7D7F3D1F9BULL,
		0xA652DD64DB35274AULL,
		0x79D0F46485163FF0ULL,
		0xC382AD2739FD7A81ULL,
		0x75807B9A05466F35ULL,
		0xD8E467F500BCFBFAULL,
		0x877E5935B412F7CFULL,
		0x5FE86E0BE5DC72D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8490275A47B1A3B3ULL,
		0xD83A4BC2F7428E77ULL,
		0x9692325D3FE708CAULL,
		0x000302EB58B6860DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AEE607351819304ULL,
		0x6BD93EDEC540F633ULL,
		0x9CFFE4668513BE44ULL,
		0x401705C63C874A4BULL,
		0x04A9A09F50DFE174ULL,
		0xC9957B6DA7AAB038ULL,
		0x0AF7C4B3B89BDEF2ULL,
		0xDCEC202BCE9C8D32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C1C381952BD0F22ULL,
		0x58099125A8971E84ULL,
		0x3DC71713EC36D64EULL,
		0x0B23CC46E7C43FB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B648A5DC8FFEA38ULL,
		0xE0DD7AE25052977CULL,
		0x792D308A29149EFFULL,
		0x97B73CC0A345C421ULL,
		0x8FE6A3E0A645C59FULL,
		0x7E806C700280065BULL,
		0x9EFC75BE00E61578ULL,
		0xC7051E4D037AF708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A0DDB6775B4446ULL,
		0xA7ED9382AF538913ULL,
		0x12A6AABE4B3BCEE2ULL,
		0x2279BC2F27866F69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C46D5DC11B27B98ULL,
		0x542A56C265BA68CCULL,
		0xAE453D10C727AC51ULL,
		0xD1308DED0C94CD2CULL,
		0x4AC53D76CFC5A0D1ULL,
		0x96DE33F47F104CB0ULL,
		0x964372765F766E5BULL,
		0xF6F4FCC7C34029E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58DF57EE908601CULL,
		0xB9260D0D4225CAF7ULL,
		0xFC483AA2F2BC0DE9ULL,
		0x798E1394081B0540ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55A59101ECDAF0C2ULL,
		0xD61F118921E10A00ULL,
		0x0B708618AEBBF124ULL,
		0xF42B1F4CA176F425ULL,
		0x02463B6647F7424AULL,
		0x61BF73B9BB272D00ULL,
		0x059C2C373D9C68DBULL,
		0x9E0E9AD301F5D659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1262309B8ECB4EULL,
		0x588A3F1AE9B1B800ULL,
		0xE09F164BD3F381B5ULL,
		0x6A561A9EEBF4C55BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DED066F5F7D7486ULL,
		0xE303F6000D66E713ULL,
		0x1166AAE21802D7FDULL,
		0xEEC8CB71E525F1ECULL,
		0x16203FABAEDF9F31ULL,
		0xF3F01270DD6826EFULL,
		0x3EAE71B8471E184FULL,
		0x6B26D21F6309E841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B679EB54AF183FULL,
		0x18A6B2C0EADCAE90ULL,
		0x5F4B8C3CA67A73DCULL,
		0x568BFC1A989E6B9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82A6DB121190F759ULL,
		0x7343566A727F5F26ULL,
		0xEFA0A7AD36C7E0ACULL,
		0xDD1E2DBCB29A1C00ULL,
		0xA4BC69567BE87F1FULL,
		0x4A7977482D2C1B01ULL,
		0x4A3B581E6D0E5A31ULL,
		0x011CCE59CA823426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF69E7DE87613D619ULL,
		0x814B0B21270B6164ULL,
		0xF46FBC3166E943FDULL,
		0x0764CF10C1EDD9AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x014F6A785D10A1C6ULL,
		0xB4DB1D74AEFCB9E7ULL,
		0x02BCCA987995D46DULL,
		0x69CDB7809EF755ABULL,
		0xFE5F462066874D4EULL,
		0xD1B012DC36E09981ULL,
		0x544B0C087D79F7E6ULL,
		0xB0568784EFD6123AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC373D34795261F49ULL,
		0xD4FDEA24D4538332ULL,
		0x85E093DB19B0A0B0ULL,
		0x16A5D53C38BE0A53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF02063C8CAD328C5ULL,
		0x3104DA55A8BF9A4FULL,
		0xB2B2984E579A6D2FULL,
		0x3FCED199ECD7E6BDULL,
		0xAB7E617EA7DD2EC0ULL,
		0x4CCBD1D28E7CFDB8ULL,
		0x0DCE1D6D2F14BBFFULL,
		0xAD22B9458992EC7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64E2DC95B5A81D0EULL,
		0x9745FF96CF4D43B9ULL,
		0xBF4AF68354AE5514ULL,
		0x72F651EC58A700DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0C0EDDF49F78008ULL,
		0x42486319EB2BDCDEULL,
		0xA1491B004B418B25ULL,
		0x854CA95B28D12D4CULL,
		0x0274F624D2AFC3D8ULL,
		0x3F727F8BA056A998ULL,
		0x4DD4530D71C9604FULL,
		0x4E0D3B280D9D85D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1D7756900E93E0ULL,
		0xAD4751D3B809096FULL,
		0x2ECD6EFF2F25D6E8ULL,
		0x1B43714D2E330B1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19A8374AA255DDFEULL,
		0xFA14E8732077BE59ULL,
		0x5579341DBA5F0267ULL,
		0xAC8EE756559747B8ULL,
		0x246F7BAF58CF8F5FULL,
		0x8F7EBF6F2A6B696EULL,
		0x24D799CBAEC15B8EULL,
		0xD37E13945F10FBADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82349351D1252AD8ULL,
		0x46E552F36C6964B2ULL,
		0xCD7A0859AB129991ULL,
		0x1145CF5C721CA36BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DE6F86CF5B93061ULL,
		0xFF142AB5B081BACDULL,
		0x2FDDFEA5F05B3FD2ULL,
		0x9035B8B08FB738C1ULL,
		0x388FE8F611E4BAA9ULL,
		0x2A2AF004C1307423ULL,
		0x07E941A178F70E81ULL,
		0xC857E93CF844B333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03438CF39DACE9EBULL,
		0x4173CB6A5DB2F808ULL,
		0x5C7DBC9DE50766FFULL,
		0x4D4257BD69E9D254ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1836BAF292929191ULL,
		0xAD83F371BEBBEE24ULL,
		0x5577BDC631D22442ULL,
		0xA4849307F041F320ULL,
		0xC3D4B54404915B5AULL,
		0x4943887890839FB4ULL,
		0xB7608AF1E5AFA167ULL,
		0xBB7589EA1A5AA74DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C9A30B40262515ULL,
		0x8D8A35573245A2F9ULL,
		0x8DCC5DAE49E41997ULL,
		0x77F70BC7D9B6C8A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x583BA8E9635804C7ULL,
		0xE2FBB6524C7F1346ULL,
		0xC77913290ACBFBBAULL,
		0x4E310D98174D4061ULL,
		0xC5FB77776380D029ULL,
		0x07F79206073C17AEULL,
		0x8B108BBA469B54C6ULL,
		0x68274DBB83C356FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB8F64A22876ED2AULL,
		0x11BB63375F6A9737ULL,
		0x6BEDD0CF85DA9120ULL,
		0x4406976DA64C29DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ECA88EFDDD75FC7ULL,
		0xD89DB33FE2F43C1AULL,
		0x4052CFB6C1758164ULL,
		0xC58A60F11A60451CULL,
		0x0617162CC00E4B79ULL,
		0xBBD848981042008FULL,
		0xA42ED81264739B8EULL,
		0x733B2311AE34AA75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1637D3945FF69656ULL,
		0xBAB879D24CC05155ULL,
		0x9F46E271AA9E9894ULL,
		0x60519590F6319292ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x229D21FB5D930C71ULL,
		0x534F1DE67286EDFEULL,
		0x195D736411E2B56CULL,
		0xBD824A96B7FB8BEEULL,
		0xD412E9FD1C771350ULL,
		0x3B1374677D393D5EULL,
		0x7BFCF7A6CC2B37D9ULL,
		0x67A6DCA040DC0DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6BDD8D973FECB1ULL,
		0x1832654309060A11ULL,
		0x80EA3626604CFFABULL,
		0x20470A6058A593FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC66F4B439EB74F74ULL,
		0x706BA993A5B0CF7BULL,
		0x142C364FFFA465ABULL,
		0x8194AB147EC69A9BULL,
		0x6F1592C904086AAFULL,
		0x37F4CD65302F4264ULL,
		0xE4EFB4FD06496B53ULL,
		0xFE6BA4F220F36F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A3151A37F72B12ULL,
		0xBEC22698CCB4AA64ULL,
		0x0FC113DEEE8A5405ULL,
		0x458F270562E928EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B5E4B21822D3A74ULL,
		0xE7652B03FD50EF88ULL,
		0x2EAB70B5131A7ADCULL,
		0x82AD732AB4EC7155ULL,
		0xE521718DFFF204B2ULL,
		0x0E600A62AD8D44BDULL,
		0xB02CBB44EF090F2CULL,
		0xB47C09D210E1101DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5526358019F0E2ULL,
		0x09A6B5A9C04923B8ULL,
		0x554F3CF08E72BB67ULL,
		0x4D16E8593654D5BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE7F841D62C51B9ULL,
		0xB61EF475AB1CD94EULL,
		0x8FDEC9AFB5BA589FULL,
		0x830ABAAADF249B74ULL,
		0x7E61B1458EC2FC38ULL,
		0x2B0BFBA8A9031A77ULL,
		0xFA1BB33F1B046757ULL,
		0xAACEC5560A52B42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F684895071DC5D2ULL,
		0x19E64F7EC192C70BULL,
		0xAFFB650DB861AF90ULL,
		0x5DBC0570676B5A6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6334FE5B9D10C2A8ULL,
		0xB5ADAC89D4EF4579ULL,
		0x7AB5842F070A4FE3ULL,
		0x1EBE0DF4CA266680ULL,
		0x1DE9B15A51F9A8EAULL,
		0x384768A546D2AEC9ULL,
		0x19EC19FA50C5889EULL,
		0xAB7E30EEF48FF4E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E551C3C81FD92DULL,
		0x1047351258353753ULL,
		0x53C15F57045C9760ULL,
		0x1379516D1784BFEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88370985C6540A50ULL,
		0xC543070A3F7CB1E0ULL,
		0x91D1BEA41C4A14C4ULL,
		0x7208A7BCED66758CULL,
		0x7671D7AB0A8D8F93ULL,
		0x30ADB27C6F217CCFULL,
		0xC8559F5064A595F1ULL,
		0x7391225A6927C543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D1D0CE957575CBBULL,
		0xFF0B8582BE7538ACULL,
		0x4E8764930CDE5691ULL,
		0x1993C128894DBD9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42DF028D39DD5034ULL,
		0x304F323203E7EDE0ULL,
		0x0DA7CC03F6574A42ULL,
		0xF79C996EEA8C0D18ULL,
		0xB0F1B392114ACD2DULL,
		0x65074788EBF6CCD0ULL,
		0x2754F5A05EDBC740ULL,
		0xAF6600359E9D858DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86BFAA3BCAF7C8E4ULL,
		0x2F63D0850A8A54DAULL,
		0xE44441D20AF6DDD1ULL,
		0x00C0A16475EDE00BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8EA635BF09D4FE9ULL,
		0xFBAACE18D7E88F89ULL,
		0x9E4ABAF454EF0747ULL,
		0x2B67A57450FA2863ULL,
		0xC7B3468F62908EFCULL,
		0x687F2DE011A019D8ULL,
		0x75344AC833323104ULL,
		0xF19297396842E648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D86DCA492128EA9ULL,
		0x7E8B9D5B75AC65B7ULL,
		0x040DD4ABEE624DEFULL,
		0x072A17F9CAE85725ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E10039D199D0EB0ULL,
		0x570013EFEE5DAA16ULL,
		0x63978CD790D0ECC2ULL,
		0x3C0EA3D4596C39CBULL,
		0xC3FC601A66539D19ULL,
		0x8D61BADC02882A62ULL,
		0x4D7E3E7AEBA82FB2ULL,
		0x1DD96C9EACCD07F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758647884A066111ULL,
		0x5381D0984E93F4BFULL,
		0xE454D3168BC80143ULL,
		0x2A54C361FFDB6776ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09FF6D8D64053C86ULL,
		0x7A24D1F6FED5C312ULL,
		0x9A96E697C95BF96FULL,
		0xE500C0AC547DD504ULL,
		0x21816550671A2770ULL,
		0x403F9264FD6C72CFULL,
		0xC1B28C98E33C8B14ULL,
		0x85D5CBC39B46CEDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0334777CB1E71A31ULL,
		0x03948CF49CEECDD1ULL,
		0x5B17C54984589E71ULL,
		0x42BCFFB561008A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9716BBDAAC672D72ULL,
		0xABAD76C6FC45B4A0ULL,
		0xF558A64E9E87B944ULL,
		0x670A3322BDD1C92BULL,
		0xABD80B2EE5D9E14BULL,
		0x6225851A72003E08ULL,
		0x3040DA928DF77A31ULL,
		0xC6768F85B5D961D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192864D0CABEA2F5ULL,
		0x3D3F38B3E84EE9EAULL,
		0x1EF9180FB143DC99ULL,
		0x5CA380FBBC164EF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C562ED48228FD06ULL,
		0xA0344966858C6999ULL,
		0x0EDB235F0041DF99ULL,
		0x97C298A0F79FC36BULL,
		0x9A61D930636A4D26ULL,
		0x65879A95500884D8ULL,
		0x05D1EF7C23C14792ULL,
		0x463146BD6CBE580AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DC6C0343F0724CULL,
		0xB2553B9066D021C0ULL,
		0xEC04AFCC4EF27F54ULL,
		0x031318BF1BE0D4E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCE104BF25E1CCE3ULL,
		0x6C95D474E3E08407ULL,
		0x00386C5B106147C4ULL,
		0xACE8058DADF1930AULL,
		0x559C0E90626C266CULL,
		0x77F2D389BBBB5591ULL,
		0x4E0598955E6A2809ULL,
		0x165A168721990038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB20B2E2DC1EF8170ULL,
		0x3AA13AE6C1AF379AULL,
		0x950D12871423392CULL,
		0x7E475D9CAAA79B65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66CFB2A740BE8FD5ULL,
		0xD97E507FB935D38BULL,
		0x2179684AC3C9E5D3ULL,
		0x0DF56F1C502A4463ULL,
		0x314FB54F15C78CE5ULL,
		0x11C7CB505A1BC97CULL,
		0x3158FBD8431B07AAULL,
		0x10C924987AF1A518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A49C647C5D7A32ULL,
		0x7D267E6D1955BBFAULL,
		0x74AECA64B9CD0912ULL,
		0x0BD0DDBE9008C5FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA52DA53A53758E55ULL,
		0x642FAC530146B0C2ULL,
		0x010326F8B646F9B0ULL,
		0x245B808036857AAAULL,
		0xEAE1330BF3A49B71ULL,
		0xE863F4565FFF5951ULL,
		0x097655E57CC8A527ULL,
		0x795A78297D80B3CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x829B39007DE4A3C7ULL,
		0xE305F125412DF2EBULL,
		0x6893E7093C0F7D9CULL,
		0x27C956A8D7A02ACDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF4ECCAA86EF7846ULL,
		0x9E048A33191B337FULL,
		0xC9291C93610BD9DEULL,
		0x0C00FFCBD48E2661ULL,
		0x0316602FE41CFC4BULL,
		0x01D6E34321EF8676ULL,
		0x2F7DD097CBE2D7C6ULL,
		0xFFF1DE93B27DE95AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64A113C6633CF10CULL,
		0xE3EA462A22A92904ULL,
		0xD5D6131BA4B7E142ULL,
		0x09E809B8533EC9C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC52BB437AEAA93D8ULL,
		0xD56F2947C110D5C4ULL,
		0x60A4ADF596AFE2B8ULL,
		0xBB2778CCD4213A1BULL,
		0xA1E0DD3E737CFD4DULL,
		0x6B61BD0B3D886F6EULL,
		0xF11C3F88E4FBEE00ULL,
		0x9F784FA38857E77AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC8C8B7CD33830D6ULL,
		0xC5F138F2E3516030ULL,
		0x2AD61C47941536C8ULL,
		0x67034B13112D965BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x173C1B68BA93AFF0ULL,
		0x4E2604BAC7E99FE6ULL,
		0xA0993FFC18B8519FULL,
		0x1DC929677927871BULL,
		0x8935B67827ADC7CBULL,
		0x06FA77D2DB626F51ULL,
		0xBE852798E75F0F91ULL,
		0xB50416B96AB8162EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7535313E9E5F5C01ULL,
		0x5753CE0758862600ULL,
		0xE85D20AE70D4A126ULL,
		0x7C6488ED507AD20BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26BAC105FF1E417AULL,
		0x9496609A2108D411ULL,
		0x86E355913C6C8A7EULL,
		0xB16E6140325EFF50ULL,
		0xE2F18AB6BDADDD0CULL,
		0x9817C9AC86B77B1AULL,
		0x092F7AEA38C0209AULL,
		0x3D50676D79433587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD695582626ED12ABULL,
		0x281E503620451A0EULL,
		0xE3EF9455A8F16171ULL,
		0x4B5DBB803258F15BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15C7F58CA86DD302ULL,
		0x0567CAE63B2B2E54ULL,
		0x4293DE9391B50E02ULL,
		0xE671D9CD8E1685CBULL,
		0xDAA0E2D996D3CCE2ULL,
		0x9CEE4904E2AB2B00ULL,
		0xE8AA1CD481255EBEULL,
		0xD9A54B4E7A69057AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A9A1D90BDE4174ULL,
		0x50C6A19FE0939074ULL,
		0xCBD4261EBD411E4DULL,
		0x34FB0773B9AD5609ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CBFEF23973B031AULL,
		0x42DD35143BD04761ULL,
		0x2A0BF5B0382A8CB0ULL,
		0xEBC74ED47BBCE56DULL,
		0xCADB03D74B9EFAEAULL,
		0xC33E755293CCFDBFULL,
		0xE224EA8392ACA284ULL,
		0xEA38BFB9E3715313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59428118D0D4471BULL,
		0x3E229F562C3DF1D9ULL,
		0xBB86C537FDCAAC65ULL,
		0x3033C46C3E8F3A60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA399C6AD6591BF8DULL,
		0xD948086F382AB207ULL,
		0x597112B7E2FE550EULL,
		0xBC7AB57E57301653ULL,
		0xEB96BEA4537DA10AULL,
		0x2A2241DB293849A7ULL,
		0xF25738A4F7D4B45FULL,
		0x633AD806ED85612CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFA1311CA37A943ULL,
		0x1A5DCEF75685A0F4ULL,
		0x52637B34AC911B2FULL,
		0x7736C68598FC82FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD1A8C8D1215515CULL,
		0x3B452AC0E1FBDBD1ULL,
		0xE624B8C2F755BFFDULL,
		0xA2F08FD2C23FAE63ULL,
		0xFD34CB784EBC4172ULL,
		0xC1AFA762C8DA9838ULL,
		0x427E0BFC246E3C51ULL,
		0x85436A3D8FB78577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72F0C068C2070B40ULL,
		0xFB58036AB26E7447ULL,
		0xC4DA80305FB2B41FULL,
		0x6AF254F6177D7E17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31079B0F448D383AULL,
		0xFB84607F227A5750ULL,
		0x257ED0D1B884BDBFULL,
		0xC577EBFBA8CB2227ULL,
		0x92216E7BA8BB9075ULL,
		0x0B7F3DDDD570F0A7ULL,
		0x0028D8C025C77D22ULL,
		0x91AF029A71EB67F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FE016A5064ACDCULL,
		0xB0678F6CD13E102FULL,
		0x2B8EFD57542150CDULL,
		0x65724EE891BC90F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81B50161A2D98CDAULL,
		0xC2D4E18D0070ACD2ULL,
		0xB0DE2079E4C8D625ULL,
		0x1ABFB6780B30948BULL,
		0xE10723FDB4636CB4ULL,
		0x8F9D5336F1594F50ULL,
		0x349C42BE011AF022ULL,
		0x8F1EE039B8EFD310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8C4590A699BB2B0ULL,
		0x142F3BB4D3B272D3ULL,
		0x801008AE0EC87B47ULL,
		0x5954FF097EC9E8F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D115895620A142DULL,
		0x199C8122140DF446ULL,
		0xE51F8B888E85938CULL,
		0x49C64799FBDF85BDULL,
		0xDB94F000F28281D3ULL,
		0x87356C127C8D93BEULL,
		0x17D61A6C217CC039ULL,
		0xB9CA799A426A09AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52CF8B961695D94ULL,
		0x2B8A8BE09111E29AULL,
		0x6EE77795870A1C16ULL,
		0x5DD4547FD79CF5BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05A08EB076E741BAULL,
		0x5DA0616751FD222DULL,
		0x18DBA5F8ACCA42DCULL,
		0x8A3896D5C2DD1A30ULL,
		0xF1D59BBE557F1D46ULL,
		0x198F42748D139552ULL,
		0x88CB57269FEA354DULL,
		0xB514502CA94312E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB55ACF127C59E20ULL,
		0x28E43EB442E54C7CULL,
		0x670A95B4698E2C4EULL,
		0x6B3C7D76E2D1E7F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x433B9D8824283D71ULL,
		0x92BB119869788DE2ULL,
		0x6E5DA115C852C749ULL,
		0xEF9CBA1F7673BA65ULL,
		0x11B720BEE0789E29ULL,
		0x3E000E1EDF4A6052ULL,
		0xF23B57E7068F6ACCULL,
		0xF06EE6C4385E2842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE46A79DD760FBCF2ULL,
		0xC6BD2A2D8E82DA10ULL,
		0x632CAD60C19CA19AULL,
		0x2012FB3FD46DB455ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD9AC0B7D5AA18D0ULL,
		0x04EA56773507BE6CULL,
		0x1A43C43F2884F532ULL,
		0xDCDFD2445CF322C7ULL,
		0x13B6A242E6CF5F30ULL,
		0x7DD0337B346B44E7ULL,
		0xA0AB51DFF6B6A3FFULL,
		0xB7725225BB5D3F78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAB6D6A618723E18ULL,
		0xB1D1FAC0FCF3F8B9ULL,
		0xF3B1EB7DC7A14D1EULL,
		0x17D803DE2CCA8EAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1542B12C012757FULL,
		0xE173541F8551904BULL,
		0x570518A3EE3B976AULL,
		0x7BB524B2C3A720B3ULL,
		0xE088BBB34B6B09D2ULL,
		0xF4219C80075C1E13ULL,
		0xD8334080868F5A80ULL,
		0xC290140DBA8A9C7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A007AFF1F5EEF9ULL,
		0x1E708F209CFE073FULL,
		0x6EA0ABB7E783068FULL,
		0x5D181EBC743A5BADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4361EDC8BF6710C5ULL,
		0x24F9F7CB2829B7F1ULL,
		0xF8333F1639C8F46DULL,
		0x61F56395DC99EFCEULL,
		0x8AF7350B96615971ULL,
		0xFA2FA3202A7E9BF1ULL,
		0xB2A7BB2FC153445AULL,
		0xEAB4431B80073014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE413CD8111DA5CBDULL,
		0x480C2E9176F4DDCBULL,
		0x7D19082CEC2519EEULL,
		0x38B759AADDAB12E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB9A73ECC2E67BEAULL,
		0x69FCAB66AF421E45ULL,
		0xFBD0F92A440D477FULL,
		0x6302FCC6D886AB2BULL,
		0x7563E2562741EF11ULL,
		0xFD80FC5553B2D0E8ULL,
		0x4D620FF651D6484DULL,
		0x273F5BB8B0574BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x686E0CB696AFF954ULL,
		0x0B2220111BCD20C7ULL,
		0x785F57BA69DC0313ULL,
		0x366A9A31057BF0FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD47E3E12DB75CB4ULL,
		0x6EF69C6DFCB36ADEULL,
		0x9E7EA04155AC6A78ULL,
		0x98D74D0B4483232AULL,
		0x499C723AE3E62140ULL,
		0x644BBFE80B8B9689ULL,
		0xEA16D7F433D9B473ULL,
		0x038EDA3333A05E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA80D89F01E04C5AULL,
		0x523518DFB36BC33FULL,
		0x5DE2AE8107FD3399ULL,
		0x200BB0A4EE5122E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x146BD8C751145BD3ULL,
		0xA2CA40115F93D391ULL,
		0x24D8335DCDB0DBF1ULL,
		0xB39954B914E38A83ULL,
		0x002B728BA72A45A8ULL,
		0x5CAFB86A3905E3FBULL,
		0x7361C06A4EC92EB6ULL,
		0xB06FD099D81511E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADED982215AB6B2ULL,
		0x64DF9FD5D673AAD3ULL,
		0x455AC3257F8DCB03ULL,
		0x64324B8F280432B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03640452CE7E45F1ULL,
		0xF23D656A9175DAC8ULL,
		0x5DA6E2D220530879ULL,
		0x2BEE1DF78A3D5C56ULL,
		0x982411712199630EULL,
		0xAD34A3969271E7A8ULL,
		0xEA6EADA3D665F107ULL,
		0xCA2353E01C5121ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BE9B1DCB42FE79ULL,
		0xA80DADC44E5E3DCEULL,
		0x2A14A923F374CF9DULL,
		0x2D2C913BBE486581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2388177B6EF2032ULL,
		0x33055ACAFAB6ED22ULL,
		0x24E5A4EB6D948E4EULL,
		0xD08DE7B37CCA3758ULL,
		0x9276E9BC84ABC3EBULL,
		0x69B30AE761A4DECEULL,
		0xA7706424652E09E7ULL,
		0x2ABF619651340F83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FDF3373686E361EULL,
		0xE398F923792FFFCCULL,
		0xFF948252726A06A7ULL,
		0x28F664038A8484E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B8715A0D31CA600ULL,
		0x133B488CE0553095ULL,
		0x7CED570C7C6F745DULL,
		0x95DDC2A91BFBA335ULL,
		0xB7E90BDC58554C8FULL,
		0xC7577B4716FB67C4ULL,
		0x5AAC6DC199BCE98EULL,
		0xB843E45B61683108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB81ED855EFC6074FULL,
		0xAA37951A49A697C8ULL,
		0xF285A1C94E7A1F8EULL,
		0x6FF1A8399172EA72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x711C0EB103370854ULL,
		0x6D5A8ECB023260DEULL,
		0x1AB0973BAE49E52EULL,
		0xBFC11D03E704381CULL,
		0x1EDAE99A04035BCAULL,
		0x77665D3256DF8F65ULL,
		0x2597A3D1495984D3ULL,
		0x6D5D2294A2170597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x059ABB8D9BB6AAC3ULL,
		0x268C6443E761A9E1ULL,
		0xAF32E84C91939C92ULL,
		0x7B943F13F66F0C8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D6FBA03AAF0C698ULL,
		0xF8572EA55DC5B70CULL,
		0x3D61E3542EC1F8A4ULL,
		0xCF86688246EDAC8AULL,
		0x3A6B4A1B0775CE07ULL,
		0x4086B4447C9D500EULL,
		0xA0C8B281F323EEF1ULL,
		0x0E441B3F7A787129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295CBA06C66D5C01ULL,
		0x8C55F0CFDD1F9929ULL,
		0x1B2C629E46177074ULL,
		0x6DA273EE74CE78B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFD616F8FE4264EEULL,
		0xA8C9EE5EAEB9D4C3ULL,
		0x2DC3F87498FBA7B6ULL,
		0x5E271CC2192F1B3CULL,
		0x89470C137B1F0B7DULL,
		0x887B09C4A32A1DFAULL,
		0x454A224AF9D32D34ULL,
		0x970698C2F2D1B6C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3061E1DD44DE1CD3ULL,
		0xEB0D618EE6FA47F4ULL,
		0x76C50F95AE545D82ULL,
		0x4921C9B224503CAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB448B7A5DDD074C8ULL,
		0x29F8BE9516E01D9DULL,
		0x22E1E1B6EAB7FDD7ULL,
		0xB86AEE2B315C43A0ULL,
		0x4301A4B0B4EDDE3AULL,
		0xC1699D6307CEF1E4ULL,
		0x61C770BDD7E6F018ULL,
		0x3D0C58025818C7A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA68729E0B91F72CDULL,
		0xDFA61B483F98057FULL,
		0xA67C9DE4F6FFA183ULL,
		0x483FFE844509E62CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE66764C51CD861ULL,
		0x4DE4C9C60ADAC232ULL,
		0x7C5DBF1CEAA96FA3ULL,
		0x0560B82276D5C103ULL,
		0x05D264E22F61D131ULL,
		0xFE12EF0DFE45135DULL,
		0xC723C51ADB4FFD2EULL,
		0x36CD5845D880E1D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE82160F7CDA1E6D7ULL,
		0x04B445D9C91BA200ULL,
		0x0BAD01197889049DULL,
		0x27DBD28099F74627ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C82EA371F6DEA8ULL,
		0xEFC370F283AFEA4DULL,
		0x7D05223B8FC3B10DULL,
		0x67F83C60B152FB64ULL,
		0xB8387B67A77C295EULL,
		0x7ABFF82EFEA27AEEULL,
		0xFA96008522A2F1D2ULL,
		0x25A849875C2C15B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2A80064E65036DULL,
		0x284247EC4FCE29BDULL,
		0xAF4935FEB3F3964CULL,
		0x7EF326785FDE348DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE6557DEA4EBD34DULL,
		0x16154FAE6E630959ULL,
		0xCC555D076A54EC13ULL,
		0x77479F36E7FA6450ULL,
		0x68E6FDD4394E0568ULL,
		0x264AD50DFE339B89ULL,
		0xD3D1BF514C5CDF06ULL,
		0x838617604F97467CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80AF055F2680A3A2ULL,
		0xC530EFC22A0C1FBFULL,
		0x3D77C318C01E06FCULL,
		0x7D2F1782B86EDAD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2D425FE619A9B2EULL,
		0xDBB7759A0F6A7D97ULL,
		0x8025AFD8B800FF31ULL,
		0xA0378DC38B0D1960ULL,
		0xA9DFF59538FB12B6ULL,
		0x3F25814C3FD49EF6ULL,
		0xD780DEC260717D01ULL,
		0xEF60057E1D982812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA129A24D6DF678AULL,
		0x3B48A6EB88FA1634ULL,
		0x7D46C0B308D98D61ULL,
		0x28785E7BEFA30C2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4CD62A3799BD934ULL,
		0x36A77D98129E1F08ULL,
		0xA6684B123824297FULL,
		0x98D0BC7E483AF113ULL,
		0xE5DCF62B3D64BB99ULL,
		0xD0E10702A0ACA640ULL,
		0x949C38B65A797FA3ULL,
		0x336E4DCDF31F464DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF399ED0E968FB31AULL,
		0x380E87FBEC3ECCAAULL,
		0xB598B623A62D1BD0ULL,
		0x3B3049105EDF6097ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF442EE4428029717ULL,
		0xE1DA2ED8A0B1EBEBULL,
		0xFCCE94E68989F9E1ULL,
		0x2DC02B4F10C61D77ULL,
		0xBB657E0BF7F8AC18ULL,
		0x48C5656CF29A44EEULL,
		0x7F14E182543F1FD0ULL,
		0x59E7EA1E3E3D899BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC553A40AF6EC24A8ULL,
		0xAF273D04A398275BULL,
		0xD9E80E3F0AE8B2CCULL,
		0x062CEBCC4DE88A8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B1909A97E9509D1ULL,
		0x7EA4DC8D55C0303EULL,
		0x61847A95E64C22D7ULL,
		0x4587EFB3D295CAE4ULL,
		0xC69D9B7CA480F730ULL,
		0xB9FA1CB0ECA53BFDULL,
		0xA901415B6090C03EULL,
		0x41AAFE6DDCF680C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x967E1E29E9B9BC6DULL,
		0x19C51ED0764717E9ULL,
		0x77B42E263BC8AC27ULL,
		0x04E9B4029F2CE7A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F2CDFBBFFE7FD7BULL,
		0xF6EA17417412FBF9ULL,
		0xFF2705915FD37FE6ULL,
		0x4A29203C24B6553EULL,
		0x7E33F7D64EEFC9D1ULL,
		0xE24B5ED7799625D5ULL,
		0xE8AE79916B6A4ED8ULL,
		0xDA8E49C8890EA70AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE3A98BB77FF754ULL,
		0x8E1A2B3D805C99A9ULL,
		0x890D1127519B3418ULL,
		0x3B4814007CE320DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0675AEFDE41AC4F1ULL,
		0x1FB0091E4CFEF501ULL,
		0xE7332CACAAB29AD9ULL,
		0x21C0894C553A6E35ULL,
		0x266DC5FC9035ED33ULL,
		0xA9C335172F4E8703ULL,
		0x10FD9981581690E5ULL,
		0x80313F6693266F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC1127B4C1BFD55ULL,
		0x52A9EA8F52A6FF78ULL,
		0x6CD7F5DFBE0C1CF0ULL,
		0x290FF2862CEEF3CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x189C05146A6CC08AULL,
		0x6526240AF672CB99ULL,
		0x9211F242D7D567C9ULL,
		0x307F30A7AD7C6DB5ULL,
		0x923428E2B340267AULL,
		0x66E7BC1220148668ULL,
		0xABB2D50D3D3BDE6CULL,
		0x868F9D0628D45236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5A16BB05F2799EULL,
		0xAB8C0EBBB97EBF1EULL,
		0x0E9D9239EEB86BE0ULL,
		0x29D07F91BD00A1D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2DF5E5A8FB78484ULL,
		0xF42AE17D302755AAULL,
		0x87AD8002200F199FULL,
		0x5F18DBC170499314ULL,
		0x4A1ED32576860944ULL,
		0x80D821F57708A002ULL,
		0x30C3D204A16093B7ULL,
		0x54D0B0CC0AD72F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD372B5EA279CE677ULL,
		0x143FEBECDB6F1601ULL,
		0xC4BEACB2146506DDULL,
		0x76131A0B0C3AA35FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCC69540EE5F01A9ULL,
		0xE93C54BBB2EDFB21ULL,
		0x54C770711B59C3CDULL,
		0xB822A99F82386B07ULL,
		0x832E0E875E696218ULL,
		0x4D710E301B58072CULL,
		0x92690A285B8E4825ULL,
		0xA71CC3F3459A0DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x559CBD58F2039502ULL,
		0x68046FDFC1FF0BBDULL,
		0x105EF26EB2787957ULL,
		0x0667BFBBD71678E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4988F4153C686FD1ULL,
		0x60C1011E5EFF81BDULL,
		0x3124FD286C7C5407ULL,
		0x25A26A6521ACB805ULL,
		0x99AC6082B9DD156AULL,
		0x64DBA18FE2E5C555ULL,
		0xBD3791A1BF50464AULL,
		0x0713E33A771338E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x191F477CD3399DB3ULL,
		0x595AFC7A0D1ACC72ULL,
		0x47649B2AD266C312ULL,
		0x32962512CE872987ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x695FB3B0D6410174ULL,
		0x364F1EA8E45ABE4CULL,
		0x916F655FBE65E34BULL,
		0xE288CC7E173D0AC8ULL,
		0x08877ED9DB150277ULL,
		0x427609CA2FE3229BULL,
		0x5B768021B98527B5ULL,
		0x3BCA5EE3DDF01332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7C88075B5F6087ULL,
		0x13D492AC0011E14FULL,
		0x25066A614829C833ULL,
		0x4292E25108DFE442ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A070CAB567817E5ULL,
		0x85309A6AC034EC42ULL,
		0x839C032AF036A377ULL,
		0x6E535AD4B969ABEEULL,
		0xB700C070F0436271ULL,
		0x467EB820A803C11AULL,
		0x148FB298C335057CULL,
		0x68AB447D0D3E0FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94239D6F0078B6F8ULL,
		0xFBFFEF43B0C39639ULL,
		0x90F085D7EA1573E9ULL,
		0x77BF8564B0A009B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x635B1D29A0410F18ULL,
		0xDD9692280C95E4C3ULL,
		0xE94DBD95906711ECULL,
		0x32B8A40A02A72CA8ULL,
		0xAA59912284352E64ULL,
		0x7F85408ADD8BE583ULL,
		0xD8CC5535626CE5AEULL,
		0xAE0535AC530B93BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA6A8494025F5CCULL,
		0xCB5E26C4EF59F64EULL,
		0x17A263822C9129D3ULL,
		0x077E9B9E565F1B23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97CE7DA7538E931FULL,
		0xC7ECF07ECB161D37ULL,
		0x7802F1AB609CE634ULL,
		0x1D7CE46391F3F953ULL,
		0x9CC10F4C98D244EAULL,
		0x51CBF5D5AE49C3A8ULL,
		0xE17D5C711C5C81A3ULL,
		0x89DBA3E28A7B3314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC76C30602C4D0E6ULL,
		0xEC336E36AA09283EULL,
		0xF09EAA7596582472ULL,
		0x14173804203D8E6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x756828457138A79CULL,
		0xEE1B1439F0EAA3A4ULL,
		0x08883EC8F272E30CULL,
		0x5096643F2AA38DB7ULL,
		0x7737127249CE1E93ULL,
		0x84894A58DF185D9EULL,
		0x1345B56BB0E8086EULL,
		0xC5C6274F6FBC4239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2794E53C65D135CFULL,
		0x9A7C1D6B0E88892AULL,
		0xE4E12CC534E42374ULL,
		0x2C003A09C095622FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x774F532D976E3FFFULL,
		0x48C56DF759F92780ULL,
		0xC302362EC6A9006AULL,
		0xC64043A04AC5F1D2ULL,
		0x28EFD480B59DAF1FULL,
		0x4ADC19E9DDF2CAB8ULL,
		0xE567531502B6A674ULL,
		0xBBB18CE5F917F76DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE8DE488CD642D4ULL,
		0x657146AE4C033ED6ULL,
		0xD0588B4D2DC5B5ADULL,
		0x229B2DC34454AC22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67B11C209332FEB8ULL,
		0xA7C3CE7FFD429951ULL,
		0xBC44A8D9E90DA6EBULL,
		0xFDADBE0B20454B8FULL,
		0x6D627BAAFE223374ULL,
		0x95D74D8F03177193ULL,
		0x5F5BF3F853D2EA7EULL,
		0x3109F831C847C061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44F77824C46A320ULL,
		0xE5B951BA72BD7533ULL,
		0xE3EADFB65A5C75B5ULL,
		0x4528956EDAEBDA03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D8EC8295BCC30D8ULL,
		0x6D88114B1F594DF9ULL,
		0x6B4CC9EB7AE4F4FAULL,
		0x8F2F04A1662205D2ULL,
		0xA81B80C0BAACCE4CULL,
		0x38E84F46FF7FBF80ULL,
		0xCB3D109F63EF1218ULL,
		0x2FC023266F4720A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81A3E4C51172D13DULL,
		0xE003D5D50C4FBB12ULL,
		0x965D41945061A492ULL,
		0x25B43C55EAB0DDB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BBF2E3D1B63F7E4ULL,
		0xA96F11DFB907CA89ULL,
		0x8B7FB021A2C720CFULL,
		0x8970A3A37E0524E0ULL,
		0x09C5B516C1DE66DFULL,
		0x19C852F1B75CC060ULL,
		0x461E223F326DB824ULL,
		0x11B84E13B938C733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF180F9DE2673D70ULL,
		0x7D2B61C0F0CC58CAULL,
		0xF3F8C5831F10762BULL,
		0x2ACC3A90FC72B67CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73F22B1B44758321ULL,
		0x41862A94E347B66FULL,
		0x7D8056F4C5D989B1ULL,
		0x832A59698122E311ULL,
		0x7F5049E5A007DDBFULL,
		0xC601998CA5320458ULL,
		0xE244F75D23827242ULL,
		0xC76F6DE5BE1EF9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59DD233105A071EFULL,
		0xA5C2F57568B45B92ULL,
		0x13BD0EC80B367F9AULL,
		0x1DB4A983B9BBF8F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2962389E2495A84ULL,
		0x9F80D9EE5D51EF95ULL,
		0xBE7F54BF3ED2C420ULL,
		0x496A621F396D61ECULL,
		0x3CAA5F8730CAA0C6ULL,
		0x2F8D7CFA2605135FULL,
		0x0E2939743C7148FFULL,
		0x3A1D842D45A2E737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E0519B205D392BULL,
		0xAE8167100212CFB8ULL,
		0xD89DDC0037A39A01ULL,
		0x69CC00D78F9BB418ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29F9089D1374C8D0ULL,
		0x13AE3BBC0D81704BULL,
		0x5B22DBE8F963F4D2ULL,
		0x65B17DF508D565E6ULL,
		0xBE2D7E06E590CEE1ULL,
		0x0709C4F57C8D81A6ULL,
		0xAC4706481E79ECFFULL,
		0xC8BF7A742F584CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B9BDA326F382AAULL,
		0x1F21782C8A82AF0BULL,
		0xEDADCA9D7F7D22ADULL,
		0x321DAB340FF0CF65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F760C20842ABD54ULL,
		0x6FD32E2475486FB1ULL,
		0x96C7A8DE992DACB2ULL,
		0x3110B784DA79B1DFULL,
		0x593516044FF0F015ULL,
		0xECED82CE6EC82C23ULL,
		0x92E20328CEB9D016ULL,
		0x4BAD36702A996F65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5750C461EE6214ULL,
		0x9B1498C8E6FEFCF0ULL,
		0x645420ED48C29019ULL,
		0x6CC6CC2B2D403AF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC93F4B6052301796ULL,
		0xD0444F934CE8A3E8ULL,
		0xE9FDBF0929E7D1D0ULL,
		0x3E7C264F2D4A9C05ULL,
		0x412659992636A27BULL,
		0xF0FF89C2B98EAFE0ULL,
		0x67BDF05D56D967ACULL,
		0x5C0AF5A8C9DCE972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74F0981BFE4C37D9ULL,
		0x9632C27AD816BF32ULL,
		0x502F6CE40E2D357CULL,
		0x681C9D5D24154301ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CC6BB5BD9592190ULL,
		0xB4C7F6A788F7936BULL,
		0x8D4D38A4D208961DULL,
		0xEB523B824ACAA966ULL,
		0x463FB523912F60C7ULL,
		0xA698C8451B1F9796ULL,
		0xE5235C0515A8369DULL,
		0x9BB1F5B6781E1D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3B9EA3666182AAULL,
		0x6F75B0E98FA813B9ULL,
		0x908CE1660900B184ULL,
		0x07BCB4981F4301A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC73542F713F8288AULL,
		0x7E6490643CA9BD01ULL,
		0xE4723127F5DAEF51ULL,
		0xEB3403833A7FA504ULL,
		0xA8286BC0E51AFCD0ULL,
		0xA5A419C65E19059AULL,
		0x530A87DB63158A7FULL,
		0x321FBD165D4BEFB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD35419915F9B09AULL,
		0x14C063D6346091F6ULL,
		0x38025BB8AB0D7E44ULL,
		0x5BEA14D513C53A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88ADA45625070DB6ULL,
		0x9E52B6A262617A03ULL,
		0xFDA303C2A1FE3BEFULL,
		0x6D4818CEF0E6EAF7ULL,
		0x7BCF51F079072780ULL,
		0xAB4807A702C27187ULL,
		0x72090491F284758BULL,
		0x580B149B0F481D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE973CE081C16ECA4ULL,
		0x0B03D96CCB3E541FULL,
		0xEAF9B16CA1A7AEABULL,
		0x7EED27D3359B3AAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF929BA076C7E6708ULL,
		0xC316EC7076E2347DULL,
		0x2697BFD2B0244232ULL,
		0x36C9B33DE658000CULL,
		0xA159D2C5765E221BULL,
		0x88359DD1288506E0ULL,
		0x49672FF9596C34DFULL,
		0x56B1D1531A8ABE6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7F0356FE7778F8ULL,
		0xFB0C597C7AA139D5ULL,
		0x0BE8DED5F6341B60ULL,
		0x152EC593D6F04445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43880B5B51DFCBF7ULL,
		0x2760164D85449C54ULL,
		0xDE5D2314CFC9F651ULL,
		0x8EA207C0E1909E34ULL,
		0x9F673A9B8025A5E3ULL,
		0xD3A9E7881873D1E6ULL,
		0x0072A175E75621FAULL,
		0x2B91D94E7AE37E4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECDABE7057766CB3ULL,
		0x929874812675C48FULL,
		0xEF611A952693018CULL,
		0x064849671F555D30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F19BC1AE8085C74ULL,
		0x98D685672C7C3DDAULL,
		0xE54676CA33487431ULL,
		0x58E01F05D72CD5C2ULL,
		0xD95FACE72D144A17ULL,
		0x48E2578F350BFA96ULL,
		0x52EE460317EB0994ULL,
		0xBA634EC51C5DE4FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC34D666B990B6006ULL,
		0x6A6F84A90C43703EULL,
		0x34A4DB3FC02BE034ULL,
		0x039DD0480D1CD35DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2295E98ADEE28801ULL,
		0xBF1F02AF0AECFE3EULL,
		0x17EDAF4F290A78AEULL,
		0x6DC866FA5216AB8BULL,
		0x13CE2DFEED4A6703ULL,
		0x6493E1C75A941F40ULL,
		0x94F6280CF863D15FULL,
		0x2715AFECBF069EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1330BD6217EDD357ULL,
		0xAD1286467CE9A1C1ULL,
		0x3477A13C07DB8CD7ULL,
		0x3B00841EAD1241EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C892CB820A334CULL,
		0x4328D2C219D991EDULL,
		0x0BF31FBF8B289512ULL,
		0xBD37998A572B998CULL,
		0x941441AB566E8979ULL,
		0xA4F7232340F563D7ULL,
		0xBE85EFD78C80399AULL,
		0xCB4D6D7556B4547DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CA523A56729FC9ULL,
		0xBFD809FDBE4663EDULL,
		0x53D4B9BE66312206ULL,
		0x6AB5D8F535F02436ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C8210F8D051F7F6ULL,
		0x60DFF61C047FF30EULL,
		0xF0A08D4E72AA2D73ULL,
		0x6E2C8E10CA7C59EBULL,
		0xA12B3F8BC8A9DEC2ULL,
		0x5BE45F1A16AC69A8ULL,
		0xF20ED67443995FDBULL,
		0xA82EE1A60B049A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28ED7FB899890C78ULL,
		0x04C613FB6217A216ULL,
		0xDED462907B6E6803ULL,
		0x65220CB66D2B44C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03E704FAF29A5CFBULL,
		0x85BFDA90AA27C4ACULL,
		0x0298E9896579D9BFULL,
		0x47BAEF0D1E8F6827ULL,
		0x4A6E1E16089A3CFBULL,
		0x34ADE880DA47F109ULL,
		0x27715ED32E7A1C36ULL,
		0xF67C37023ECF5721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103F7C40397F6FA8ULL,
		0x57905DB110D58C0DULL,
		0xDD6CFCE24B9A09CBULL,
		0x5E2B196271565712ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F69477DFD368347ULL,
		0x4DA4D1BB64A56B68ULL,
		0xF91935FC10597EF1ULL,
		0x493EEACFDD493C39ULL,
		0xC4740832AA16D604ULL,
		0x0C3CA312173641ACULL,
		0x820BE3E51B14DEADULL,
		0xE3B433D0CEF47AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A27F033C9A4CEBULL,
		0x1EA5066AD6B32B0DULL,
		0x46DD09FE15728CA1ULL,
		0x15FE9BCE95937A4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5563F1195425F35ULL,
		0x9ED35484173E1899ULL,
		0x2F5002C450F2A3D8ULL,
		0x8E3570C7CD374042ULL,
		0x84D71B2D78861539ULL,
		0xCF642BA505AC0A67ULL,
		0x76D1A32065FA18DCULL,
		0x7A131DBF5E185C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4447D17929886AULL,
		0x67B1CF02EEC7A3F7ULL,
		0xD26E39937412549FULL,
		0x2D0BDB2FC4D4EBE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8B42858211697FBULL,
		0x7AE19D6B7D123780ULL,
		0x22FA6CCF7F28E4F2ULL,
		0x128F7B6E5F05222CULL,
		0x9AF7D3D36EC3C194ULL,
		0x9DC07C274981C1A4ULL,
		0xEC9C3B0E44FF0AD6ULL,
		0x1340460B0AEE6C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97D99BA92255452ULL,
		0xE5740B406654F5EFULL,
		0x422B30EDBD0480CDULL,
		0x6E19E111FE69322DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB8583F11F287BF2ULL,
		0x20CB0A5F1996C7FFULL,
		0x8C62611BEE6455C2ULL,
		0x47EE1F1B4AC51E7CULL,
		0x6ACAFEC6B07E2ED4ULL,
		0xBF0E714188BBF8FEULL,
		0x45B59CF04E709815ULL,
		0xFBDC595F6F1A970DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85A7556F51E374FBULL,
		0x7CEFDA19657DBDC3ULL,
		0xE557ACC7931AE8FCULL,
		0x2AA36345C8B78A74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ADA95DA2E53B08CULL,
		0x773A50CBC44A5E6DULL,
		0x37762E9564BA32CDULL,
		0xC7EE2F70BA3AF8E2ULL,
		0x87F5BC22B130C844ULL,
		0xC9B0E1E1EAA05071ULL,
		0x9C6058C50CDC2B09ULL,
		0x8ACD00E058FBAC5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395483007B916DC2ULL,
		0x677BD85498164F47ULL,
		0x6DC35BD54D689641ULL,
		0x625C50BDEF968EC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5BFE903BE1930AEULL,
		0xC343CD35B538F726ULL,
		0x7DDAAD0583B61536ULL,
		0x5782BCCA6031E1DFULL,
		0xD6E5B66374C05733ULL,
		0xBE2F3DD39E3A0D8BULL,
		0xC94DBFBCC60D9811ULL,
		0x272C2C58A5F0FA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD8FBC712A62324ULL,
		0xFE46FA9F31D6F9E8ULL,
		0x5F65230AE9BAA7D8ULL,
		0x281151F301F708D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D707EE68E407F41ULL,
		0x1C584DDACC5FC397ULL,
		0x854E824F00B19715ULL,
		0x385C77E7CC50FF87ULL,
		0x6DC2B24BA2722698ULL,
		0x80AB157CC0EB33F2ULL,
		0x32A7E05B3938DE8CULL,
		0x037A62BFADBDB658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA856F620AB3239E4ULL,
		0x35BD7E5F6F497993ULL,
		0x0A39CFD97F229FF0ULL,
		0x3C87205B967A109FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF741932A9E0AD672ULL,
		0xB3772882EB1F1A89ULL,
		0x444265F6E7C1BD17ULL,
		0xA181772848ABF340ULL,
		0x7510DDB3A241020EULL,
		0xBF3955A476AE6DCAULL,
		0xB6BEE76408B0B65CULL,
		0xAD2B9FF4DAB29BCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57C27BD4B3B12862ULL,
		0x15F9DEEC89036697ULL,
		0x6498BED031FCCEDCULL,
		0x55FB3580BF2F1357ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB4114CECB0F8FBULL,
		0x5EF2949E5ED2FBD9ULL,
		0xBE245DEC48F0D0B6ULL,
		0xB22857680165D425ULL,
		0xB260EAEBD6C235D7ULL,
		0x1A843E8FD3A63866ULL,
		0x9095D521F1A9F065ULL,
		0x8D6DFAB568979F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A16F04ECD84FA16ULL,
		0x4E93DDF7C97F5B18ULL,
		0x346200F6282A7FB8ULL,
		0x307B8E5587E781D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85772F91C2D0E5E5ULL,
		0xCC3FE5F0560ACF95ULL,
		0x6EE127B4BF93D05DULL,
		0x1BCD8BA55F28D50AULL,
		0x51518585323E76F0ULL,
		0x22EEB6216B4C918CULL,
		0xA5AB3913B1732EF8ULL,
		0x3EAEF5B7926F2659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9791015738168EDBULL,
		0xFBAEEEE643686A69ULL,
		0x064BA0A116ACC932ULL,
		0x69C604E51BA88659ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E405BAC63F6C5F5ULL,
		0xB799226CECC56095ULL,
		0x90B799D5B9841DFEULL,
		0x2EF80504A045DDAEULL,
		0x33B014C37227BC87ULL,
		0x2046FA797A6D4029ULL,
		0x096BBAF580707F07ULL,
		0xF1E44F3F365EF708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6370AF55DCC757ULL,
		0x8222507518FCE6B2ULL,
		0xF6B55A46CA36F90DULL,
		0x16DBC866B25E88DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9ED9C3017BB57FULL,
		0x156A67C3375CC59FULL,
		0x970FA9AD3F1E8314ULL,
		0xEE6574DDAC368E10ULL,
		0x4812E034C9B210D8ULL,
		0xBA0B12719E1BDE1DULL,
		0xA84A80709EC8B1E5ULL,
		0x977C41D807AC09AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6C2198F1EA38F9ULL,
		0xB30F24A0AF7FBDF8ULL,
		0x921EBA64D0E8EB2DULL,
		0x6AD73AEECFBFFDFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10CA74BA02516CD4ULL,
		0x0C74F87868B71670ULL,
		0x0F3877DC8B5CB5BBULL,
		0x544837F998388FE6ULL,
		0x80E265AC0AF06EC2ULL,
		0x385AE6C9FAB72E5EULL,
		0x138A43F97EFDEA64ULL,
		0xAD71F4FED490523BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32658C43A201E17CULL,
		0x69F33A739FE7F877ULL,
		0xF5BE8EE5650D809BULL,
		0x133295CD25A4C4AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20361FE209D185FBULL,
		0x9E52C184DE97F672ULL,
		0xF79E630FB68B1E48ULL,
		0x362D172B2B6BF72EULL,
		0xFC572CECBE1315C4ULL,
		0x69B63A535D013E15ULL,
		0xA934CF8DF6BB5FB3ULL,
		0xDDA1D52CC78B791AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9526CB0640A6C5F9ULL,
		0x4F5F69E4ACC72DB5ULL,
		0x15753222565B52EAULL,
		0x1C32BBD0CA1FF124ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC759EBEF47F76CULL,
		0x6E16C4037657D21FULL,
		0xB6121E72CC44B60FULL,
		0x0D37542D986B6147ULL,
		0xA7A7703D39FF3EF1ULL,
		0x754E65D4F3D51469ULL,
		0xBCB145D64B7CCD86ULL,
		0xB40D561930E7B592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61A203028B2B5321ULL,
		0xD7B9E19FA7F8D9CEULL,
		0xB8627C4200CB3804ULL,
		0x47321BEADAD0550FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FA284D496676BCDULL,
		0x6AA9676FCC47DD71ULL,
		0xBAFBD5AB74EF2FB4ULL,
		0xD89BE252D20DDD94ULL,
		0x57835FD728B58141ULL,
		0x9E73DD6EAD46D439ULL,
		0xC082EDC2A7F96598ULL,
		0xD59A0939940D3137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D22BEC4A158A046ULL,
		0xEFDC45DD84CB5DF4ULL,
		0x4E6B209063F4445BULL,
		0x0D7940DECC032BDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21691C23C7120CC5ULL,
		0xCC746AD72B77C8BCULL,
		0x07B386F2CF5B7505ULL,
		0xF41C8406DBCF90C9ULL,
		0x4F6D427214747BB4ULL,
		0x347D01A39E7F414DULL,
		0x98E9DE21AC7C496CULL,
		0x574808F6365ACC2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA0F912D05C6B7EULL,
		0x9702A920B25B7A35ULL,
		0xBA6A7FF269CE5B15ULL,
		0x68CDD892ED49DF1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x917215E8084B084DULL,
		0x0E216D4327ADBD9FULL,
		0x945752CFF07A276DULL,
		0x436C81742084771EULL,
		0xAE98D65B4ECE3423ULL,
		0x93F0E0A4456EC8CEULL,
		0x701CAD60536255E6ULL,
		0xA7B549D32917F291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C21E775BAE6C935ULL,
		0x03E2C5A5761F8C4DULL,
		0x38990F1C5112E7A7ULL,
		0x285576CC3A1278B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE6FD829C4C58586ULL,
		0xC473D1CD11A4970AULL,
		0xD2CF09D2A29E5597ULL,
		0x3F3620C1692EBE99ULL,
		0x2768272BE9119032ULL,
		0xB80BA4506D456980ULL,
		0x8A65A0050585F260ULL,
		0x43161192EDC84D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E5A8AE5D60EE6EULL,
		0x162E35BD49F24010ULL,
		0x5DE4CA9174804FF3ULL,
		0x347CBC90B4EA348CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CCE4A569D8927F0ULL,
		0x8831E3A539B02369ULL,
		0x3D0BA62C1389FA7BULL,
		0x117CDABD77DCDC9FULL,
		0x613415FBC9399F6BULL,
		0xC626A9E99D0FB21DULL,
		0x8383538E311B3BC1ULL,
		0x1B39AB4EF096FDABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA898DB67C16D26AULL,
		0xF1EF1C528A0493C5ULL,
		0xC28A0D475D94D93EULL,
		0x1C0C48752E468414ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C713D56139AC6BFULL,
		0xE7B35894CFB20D55ULL,
		0x4A5D6B66999FA063ULL,
		0x545B5F134FF3B961ULL,
		0xEBBD2CD7C0E770B8ULL,
		0x31A54541247520C2ULL,
		0xF54547441EEA0AA7ULL,
		0x558960D3AADC3BECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A85E55CB5F583FDULL,
		0x463BA0403914EA44ULL,
		0xB2A5FF83305D3535ULL,
		0x06BFBE7EACA49E8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFACDD9C46D9DBEBULL,
		0x799609C197D520DAULL,
		0x0D50E755057B9C40ULL,
		0x84679E80A081B4CFULL,
		0xB8FD227EA217509AULL,
		0xEBFD9AED801322F8ULL,
		0x6BA65AF9ADDBC55FULL,
		0x390E81E68D464A8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x453FFC68564FD40AULL,
		0x813B09029AAC51C6ULL,
		0x08026864D41AE87DULL,
		0x7C8EE6B998F0C581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FCAEF0AFD1405E2ULL,
		0xAB3779B29FFDBE15ULL,
		0x1F9A246FD4B9EB5AULL,
		0x14F7AE04FDAD777CULL,
		0xA62F0818FDFAA9F8ULL,
		0xEFDFA621BFDEFCE2ULL,
		0x6C0C233D56F256E7ULL,
		0xED329794F08CF0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC622C0B04945E4ULL,
		0x466A22B51B1747BAULL,
		0x29675F8ABCB2D1C8ULL,
		0x4A7A2E20B2993186ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E03B10C63BC4302ULL,
		0x0E744F730FF6F398ULL,
		0x8D121CA34C1DE934ULL,
		0xCDD4CF989F5D395EULL,
		0xFED1C66F1F7A99A1ULL,
		0x5DDA6FDF39CE7CEDULL,
		0xC5F7B3DCB0751D59ULL,
		0xFBFB2D0DF4359BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6127258B0FEF168CULL,
		0xFCE0EA95A49D7EECULL,
		0xEFD6CF657D804477ULL,
		0x351D7FAADF525E11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x188C3B770224878AULL,
		0x805130BFF65512FAULL,
		0xA967B158D3A73D1FULL,
		0xFDD54EFC6369B608ULL,
		0xE7C44A8DA91B90E6ULL,
		0x2E0CBE5CBF4C2126ULL,
		0x4051C4870506DAC1ULL,
		0x43962E3C0626507EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAF4C7E1C3C0B50ULL,
		0x563572845BA1FEC0ULL,
		0x358ADD6392ABB5CCULL,
		0x06202BE54D19A8C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BEC044404A1FB11ULL,
		0x570A75609AC8FE3AULL,
		0x55952736FF332138ULL,
		0x1A7B347E355E66ACULL,
		0xE24B25608EEB8EC2ULL,
		0x936528153D384A8FULL,
		0x97B847D31F715513ULL,
		0xE8C63E697257CDB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31390993B9930FCULL,
		0x380E6887B1240F95ULL,
		0xDAEFD08DAA05C220ULL,
		0x27E878252E66EF54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2B33CF50A49E408ULL,
		0x14BD79E3F87C3073ULL,
		0x613626703076874CULL,
		0x938D890DF590700DULL,
		0x48EAA09974178091ULL,
		0x5A7922591F3E7F36ULL,
		0x0B5E5C7F1FC075C1ULL,
		0x4898691B85C35942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958713BC45C6FB30ULL,
		0x82B8931E9BC31282ULL,
		0x1137E14EE70801FFULL,
		0x5A2D2323D08FAFDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06DB9251F59E22C2ULL,
		0xE0DEB3CD7E2C2EC1ULL,
		0x8D935153AA31575DULL,
		0xD8FCF928F1C8F782ULL,
		0xCCBC441A6D8320A5ULL,
		0xC8D440E0A454B20FULL,
		0x6A35D1F91F9A63D7ULL,
		0x78EF392B5004A2B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACDAE3E3714FDFFULL,
		0xB0605525E2BE9D19ULL,
		0x51907C4E5B1C2965ULL,
		0x4C7F7596D2791DFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7AB0DFBB2601C0FULL,
		0x0E266AA0317E6613ULL,
		0xDA07C760CBCB3EDAULL,
		0x6F88B6872F8161C7ULL,
		0x33644B85782F7D15ULL,
		0x2758519C6B5A1F41ULL,
		0x898FD3747A37DF00ULL,
		0x0BA927D02814FE1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x488E43CB896CAD79ULL,
		0xE54287D820DF09C1ULL,
		0x45612AAAF01658DFULL,
		0x2AA49F6D229F1A50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBE6CF3063382681ULL,
		0xE62E235024362F15ULL,
		0xF42A2EC995637E5FULL,
		0x444675915F5AEA71ULL,
		0x0AA1821E7BEACBF0ULL,
		0xD60CFAD42F8FF7A6ULL,
		0x80067B412A0C561BULL,
		0x390A491E6ADF5D68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE01FB6C8126D64ULL,
		0xAC1B5ECF3394F1BBULL,
		0xF5207A75D3384681ULL,
		0x3BCD50153C82C7F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BB63E451D442FAEULL,
		0xFF16421747AF370AULL,
		0x5B8E458F3D19E6ABULL,
		0xE78CAD326432D8A8ULL,
		0xF7C617C5C25832A4ULL,
		0x4D3D5D723AA7A63FULL,
		0x5DCE619AFBCB97DEULL,
		0x631AE50E56FE858BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x031DC59FF65BB653ULL,
		0x7632210BFC91E489ULL,
		0x4830C2909D5271ABULL,
		0x1D8AAD534DFAAB58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2281A9D82C1DD82BULL,
		0xFF085855141BC870ULL,
		0x851FCFD4F359BBB7ULL,
		0x80C422AB9DB82D6BULL,
		0x8F2809AEF1ED59A9ULL,
		0x7E49815E1B4829CEULL,
		0x0CE4C18014CA5006ULL,
		0x550D9AFF6A595BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x627319D01559292FULL,
		0xBDF18C4D20D1FD19ULL,
		0x6F1488D809619CAEULL,
		0x20C9249566FBCC39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3CD9185F92EA903ULL,
		0x4199BF0C7E3EC9E2ULL,
		0x726922FD544EC113ULL,
		0x0E9DD518575C2B81ULL,
		0x5FD1F04FDD35F3A5ULL,
		0x4A9688910E3B866CULL,
		0x4A54F8AAD1F63915ULL,
		0xA37F81575E06626CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF73D60CF30D711ULL,
		0x53F204949B14BDF8ULL,
		0x7B060C587EDB3A3CULL,
		0x538B08104C4EC794ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FCE973FE1102E0DULL,
		0x70AA63E0B18167BDULL,
		0x8F5C49FAE81F20AAULL,
		0x135C95724CE0D8A5ULL,
		0x0029561FC87A4551ULL,
		0x91D679CE82D04F67ULL,
		0xB09A3581D2BD11EDULL,
		0x53420DECCC31FF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35F15FF7A33679DBULL,
		0x168078881C6D3107ULL,
		0xC6403B40302FC9EEULL,
		0x6F2AA6989C4CC35FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x191618A0778D1F2AULL,
		0xDD44D1B95E216A68ULL,
		0x809B9B92692C4F0CULL,
		0xF441CF3D854BFCBDULL,
		0x096CF3651CF34ADCULL,
		0x97D1FAC27E40EFC7ULL,
		0x5E13B72ED66E26FFULL,
		0x9B1D3846EF19F780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F4239A2C3AA3F4FULL,
		0x66700A981BC501F3ULL,
		0x7788CC863D8618FDULL,
		0x7A9829C50326B9CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33B962B720F93E35ULL,
		0xAB6235BA15136B08ULL,
		0x6FAAD58B74D2DE50ULL,
		0x86CF738C49CF8E5AULL,
		0x0D7F174B01BB44E0ULL,
		0x85520A61C96BBC3BULL,
		0x32791F713C8FBCF3ULL,
		0xAFB068EB4CD09D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3496D7D962C57B64ULL,
		0x758FC03DFB115BCCULL,
		0xEDA5805A7228EA76ULL,
		0x1AFF0679B0C6E523ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC790480F3FE4113ULL,
		0x3103CC42CFA2DD49ULL,
		0x45148A452F76D40DULL,
		0x8BC35F3C66658045ULL,
		0xA9BFA30DA166C54EULL,
		0xA9C49D2A51433FE6ULL,
		0x853F73FBE010E42CULL,
		0x409ACA0CC685BF6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEB3886E93F8C23ULL,
		0x6433208ADF9E5987ULL,
		0x0C7FC1A871F8B2AEULL,
		0x22BD5D21DE3FEA87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D171E810EF3406EULL,
		0x29451D102E20ADCCULL,
		0x08DF9AE856328633ULL,
		0xAC431F574F2E5128ULL,
		0xCA493ADAE12FDC0CULL,
		0x8CB9778F5A5C964BULL,
		0xAC163D4ABF9E6BCEULL,
		0xE22AD9E9D6C1B4C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43F5DAFE7C0DEF42ULL,
		0x0CCCDC5797DEFD0CULL,
		0x942CB400C7B686DCULL,
		0x3E9F780D2FEF26A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF8D475555D43515ULL,
		0x921F8EFD26646F1CULL,
		0xD7B1CC4121A3286BULL,
		0xFBD2E865DEC995E1ULL,
		0xBCCE062DCBFBAEF9ULL,
		0x5D9ECE130FD3C868ULL,
		0x0C5A5063173DBCF4ULL,
		0x8EE073F4101DB1D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062232219D30314FULL,
		0x77B225D17FD42EA9ULL,
		0xAD19BAF694CD34B1ULL,
		0x31241EA04331FBA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDE33AA687038189ULL,
		0xDFFE697590979A5CULL,
		0x36A9FD1E451EEEA5ULL,
		0x9E359230FB1F0225ULL,
		0x5FD2B33634639F55ULL,
		0xA0C424346EC78956ULL,
		0xF1540938A1387886ULL,
		0xEAC4B945C3A054FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1729D4B24DCD2D59ULL,
		0xBD1BC93E0235FD2FULL,
		0x09235B863380D2A1ULL,
		0x7769128C04EB9F65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED986422820585D7ULL,
		0x82A1E4C033AC2862ULL,
		0x1EB104CE261D4556ULL,
		0x152C1ADFEDFFBE96ULL,
		0xAEDAF710BAD38985ULL,
		0xA612DC41EB38861EULL,
		0x545D2DA140028DA0ULL,
		0xFC946F4BF83B32DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE219109E3D6BF526ULL,
		0x296E96891E1010F0ULL,
		0xA485CABDA67E4B2FULL,
		0x1334A026C6C94B70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAF167ECE08E8DB8ULL,
		0x88A3D95825333211ULL,
		0xE587CB9D9522B8D7ULL,
		0x58E38FFB32BDBCBAULL,
		0xC19EB63C1A8602E8ULL,
		0xA456C76481CC6246ULL,
		0x045F598340759A35ULL,
		0xF68FBEC7E09FAA16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88074D8D0730193ULL,
		0xED8572436989C892ULL,
		0x8BAF151926979CCDULL,
		0x7239E1A68A70FBFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x449476922B4E8466ULL,
		0x788BF811351B9220ULL,
		0x9937DB2725522C84ULL,
		0xE783F1245BFC95EFULL,
		0xE05A8B5953405F42ULL,
		0xFB1D585DF0ED9E9FULL,
		0x7C8A9959DC2E2690ULL,
		0x55B04D6D22960B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920525D486DCAA33ULL,
		0xBEE71602F8611DDBULL,
		0x15CA9E7DD42BE609ULL,
		0x1FAF6F577E4240C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16616EB50DD4359DULL,
		0x5E10B1B307BF6317ULL,
		0x62924C8A6A4A6FB6ULL,
		0x14C32C33443B0450ULL,
		0x16A30C6A1E978F49ULL,
		0xE6C3F525C38F7CE5ULL,
		0x6A9FD65A74AEF733ULL,
		0xED95752042367A33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7295467598537FA5ULL,
		0x9F27154E0F0BED18ULL,
		0x364C1DF7BC43216AULL,
		0x58F28EFD185127F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}