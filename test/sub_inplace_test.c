#include "tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Sub Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA503AF4E6424AAAAULL,
		0xBF62510092E97393ULL,
		0x8EBA5C3C1D50A4A4ULL,
		0x64A5D3A40507C6F2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x8C0665A5565EAF44ULL,
		0xF24810132547A4DAULL,
		0x93F0CE2DFCCDCBFDULL,
		0x6EE7A993989FD8C0ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x18FD49A90DC5FB53ULL,
		0xCD1A40ED6DA1CEB9ULL,
		0xFAC98E0E2082D8A6ULL,
		0x75BE2A106C67EE31ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
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
		0xEC460BB37D9BE5F1ULL,
		0x470334D8C40D0FF0ULL,
		0x47FA71F1B0366A26ULL,
		0x07CE106A1B9F4847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D8FDD4F13C1B6DULL,
		0x177D2FFE1FC90F60ULL,
		0x4E1CC86EB5DDF45AULL,
		0x02EE72083DA2C5F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6D0DDE8C5FCA84ULL,
		0x2F8604DAA4440090ULL,
		0xF9DDA982FA5875CCULL,
		0x04DF9E61DDFC8252ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x87D1BD90737DF0DFULL,
		0xEF9F79392854776EULL,
		0x63A015C4BEAFDA9CULL,
		0x236F613E08903F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DE93BF394DBDEDEULL,
		0x9421560297A1CF88ULL,
		0xDE96445DB5E96A03ULL,
		0x4902818544096B3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29E8819CDEA211EEULL,
		0x5B7E233690B2A7E6ULL,
		0x8509D16708C67099ULL,
		0x5A6CDFB8C486D3E1ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD185F3BC11568AFCULL,
		0xD9756398A1F4D976ULL,
		0xEF48939D748B8353ULL,
		0x1F27E13E55286CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x418FA65C25A9F4D9ULL,
		0x26CCF602E7C87860ULL,
		0x2A7D0887F87ADAE6ULL,
		0x52AE6EA60F2E93B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FF64D5FEBAC9610ULL,
		0xB2A86D95BA2C6116ULL,
		0xC4CB8B157C10A86DULL,
		0x4C79729845F9D91AULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3E4B03ABEF4482A6ULL,
		0x57A05E5CCD9933F8ULL,
		0x4B3EB9ED4D0F8749ULL,
		0x0FE9A0A0966E36CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA78546AA8A414A36ULL,
		0x30D8E9C173D6D988ULL,
		0xD405430226EDABA3ULL,
		0x0C641A5B1A15F5B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96C5BD0165033870ULL,
		0x26C7749B59C25A6FULL,
		0x773976EB2621DBA6ULL,
		0x038586457C584115ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC2A9E1AA273FFEC8ULL,
		0xA72A6112CA4F10FEULL,
		0xCE0A25D1F57D66D3ULL,
		0x5D6E6183304417E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92CE7CE11E48BA86ULL,
		0x979D8B9AD8BED3B9ULL,
		0xA24F355DAEA1F2B7ULL,
		0x6C83F21840542E27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FDB64C908F7442FULL,
		0x0F8CD577F1903D45ULL,
		0x2BBAF07446DB741CULL,
		0x70EA6F6AEFEFE9C1ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x878544D3C99ABE5FULL,
		0x8D3D80505F7CA9DEULL,
		0xFB069463F8272530ULL,
		0x12352F1410555014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E33804D5960949ULL,
		0xFDF689D750474393ULL,
		0xE2CAA4A5C2C5D7FDULL,
		0x38A73F89CF303F92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32A20CCEF404B503ULL,
		0x8F46F6790F35664BULL,
		0x183BEFBE35614D32ULL,
		0x598DEF8A41251082ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x095F138E8FE50F3DULL,
		0x74122D35489F51EEULL,
		0x8088FE8067A32F56ULL,
		0x17AEDAA7CDD8D75DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB51B42E955B87DULL,
		0xDF77144B63EE395CULL,
		0x74E34B18A8F91A2AULL,
		0x0DC345B02B4F39B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BA9F84BA68F56C0ULL,
		0x949B18E9E4B11891ULL,
		0x0BA5B367BEAA152BULL,
		0x09EB94F7A2899DADULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x84D026BD485D41B7ULL,
		0x630C56E06B877C02ULL,
		0xFE77D87CA8EA00C7ULL,
		0x5C234DFD3CB24548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x413A1379A09588BCULL,
		0xEE0965ED7DE69100ULL,
		0x08E3796D15118166ULL,
		0x1DC1E6DC3842CDA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43961343A7C7B8FBULL,
		0x7502F0F2EDA0EB02ULL,
		0xF5945F0F93D87F60ULL,
		0x3E616721046F779FULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDEDD940E2A78DD3DULL,
		0xB07C2391A1A45293ULL,
		0xF7F417A44233DB02ULL,
		0x323A6701A743F333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66839093CDBB80CULL,
		0x6A65B039E4AA7ADCULL,
		0xB7FEE922F8198BEAULL,
		0x2F9BE4624D2C3577ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18755B04ED9D2531ULL,
		0x46167357BCF9D7B7ULL,
		0x3FF52E814A1A4F18ULL,
		0x029E829F5A17BDBCULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBCD4F360E87650E9ULL,
		0xD0CEFDAAB82B90C2ULL,
		0x00F9E680C3EB8666ULL,
		0x195153106D4990B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B198FD71558B0EULL,
		0x7A0774F70B011616ULL,
		0xFBBD6D0F1EB6751EULL,
		0x7F1106F7D1EDC975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7235A637720C5C8ULL,
		0x56C788B3AD2A7AABULL,
		0x053C7971A5351148ULL,
		0x1A404C189B5BC740ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3DBE86EA20A1CEE7ULL,
		0x0B699F9E958B5B6BULL,
		0x33A96469454402B0ULL,
		0x4B8D5ABD0802CE30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BCD960471875F1ULL,
		0xA5C2F5CE320F2E12ULL,
		0x7F89B1316DA1513DULL,
		0x1DC1C3B4F8CD517FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2801AD89D98958F6ULL,
		0x65A6A9D0637C2D59ULL,
		0xB41FB337D7A2B172ULL,
		0x2DCB97080F357CB0ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D898F801029EE55ULL,
		0x887E0BF34153F203ULL,
		0xE3EBB0368C5714EAULL,
		0x0BF9BC8ECE3DB899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B754D9EF9D1412EULL,
		0x26C0292C682C34E5ULL,
		0x24B72E9FA9973E8AULL,
		0x4F49ABF94EB560F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x721441E11658AD14ULL,
		0x61BDE2C6D927BD1EULL,
		0xBF348196E2BFD660ULL,
		0x3CB010957F8857A7ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1E35497172B23D74ULL,
		0xCBA9BFBEA19A67ACULL,
		0xDEC0F27124D1D157ULL,
		0x277654C00F358047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110D474129465E2DULL,
		0xD7F4546C947083CEULL,
		0x129F17868E840D09ULL,
		0x12636A7A1DE57108ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D280230496BDF47ULL,
		0xF3B56B520D29E3DEULL,
		0xCC21DAEA964DC44DULL,
		0x1512EA45F1500F3FULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD7469DC1E4268081ULL,
		0x32B537F7D98816C2ULL,
		0xA99CE5B516E73264ULL,
		0x43D9510CE4F811F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819F28A505D865DAULL,
		0xF7FF0E591958C908ULL,
		0xCBEA78C3C8D8BC6EULL,
		0x711003B714222900ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55A7751CDE4E1A94ULL,
		0x3AB6299EC02F4DBAULL,
		0xDDB26CF14E0E75F5ULL,
		0x52C94D55D0D5E8F1ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x537D4B6D623F8FF8ULL,
		0xEC35E66B0FE809B7ULL,
		0xEB8A8C5B256B60DBULL,
		0x29F8868C80C71ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0F789AE44902B8ULL,
		0x202D4D7209155650ULL,
		0xAFC2B92D98499080ULL,
		0x74725CBBBBF198D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC76DD2D27DF68D2DULL,
		0xCC0898F906D2B366ULL,
		0x3BC7D32D8D21D05BULL,
		0x358629D0C4D58602ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA53DCEC65DD3BC2BULL,
		0x8AE2EB51692A2B15ULL,
		0x9FEE3FC81E921AC7ULL,
		0x3DCF82B732435697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10F53F7EBDF5731ULL,
		0x9667085C06DBA4FBULL,
		0x8C51B66D9C8E65B3ULL,
		0x6BB17A59D51CCDA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042E7ACE71F464E7ULL,
		0xF47BE2F5624E861AULL,
		0x139C895A8203B513ULL,
		0x521E085D5D2688F1ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3786980A353A0716ULL,
		0x81CBC2D92F18DEE0ULL,
		0x4F05CDC70AECF0BBULL,
		0x34618B951B7D72CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FECC1F44CB66F17ULL,
		0x9C69C239CD34EAD1ULL,
		0x733F059D2E1B40D4ULL,
		0x2659DDEE48AB8B9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD799D615E88397FFULL,
		0xE562009F61E3F40EULL,
		0xDBC6C829DCD1AFE6ULL,
		0x0E07ADA6D2D1E733ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x31CAD798265734F1ULL,
		0x92902F8DD6D0DD23ULL,
		0x433A6542D10ACD2FULL,
		0x7E63BCE0346BC1C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2A7C80690E70CBULL,
		0xEEC097130822EDE6ULL,
		0xC0FFD254C9EBD7F3ULL,
		0x6054EC9C787452D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12A05B17BD48C426ULL,
		0xA3CF987ACEADEF3DULL,
		0x823A92EE071EF53BULL,
		0x1E0ED043BBF76EF6ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF1C7C2FAC99BD101ULL,
		0x5BA082AD3B2813F4ULL,
		0x6B03323CD1C910C5ULL,
		0x4B41817C98B1D0BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A47FC7C42DCE05ULL,
		0x7B2EE8526B56D289ULL,
		0x2E32E5C4822547FFULL,
		0x20DE28BC4C08971EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB234333056E02FCULL,
		0xE0719A5ACFD1416BULL,
		0x3CD04C784FA3C8C5ULL,
		0x2A6358C04CA9399EULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF73CAF6243A7C301ULL,
		0x2DE61B4F884D517CULL,
		0x8D81A093892AAE99ULL,
		0x600DDD7ECB5F2AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4944B734292DCFB2ULL,
		0xF780511A0BACEEE9ULL,
		0x78AE174CB9EBDEAAULL,
		0x0D2D4D5811F6F841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADF7F82E1A79F34FULL,
		0x3665CA357CA06293ULL,
		0x14D38946CF3ECFEEULL,
		0x52E09026B9683262ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7A7A3E7C06890AC8ULL,
		0x0889BA4D2C58FA8CULL,
		0x36EAA0AD19DBF36EULL,
		0x290D45659C4A55C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D31D5B89D5CCFB9ULL,
		0x2F264A79BE53C8D6ULL,
		0xB28B73591E9A207EULL,
		0x1062725D1BA55573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D4868C3692C3B0FULL,
		0xD9636FD36E0531B6ULL,
		0x845F2D53FB41D2EFULL,
		0x18AAD30880A50053ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE443E3985846B618ULL,
		0x0AC95D61607CFFCCULL,
		0xA729976EA7316CB9ULL,
		0x0D192B7D7133CFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CE66B66BAB872EULL,
		0x61ADE3C973C04EAAULL,
		0x418A191422BFBFB3ULL,
		0x6A0E81AFFF830F25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B757CE1EC9B2ED7ULL,
		0xA91B7997ECBCB122ULL,
		0x659F7E5A8471AD05ULL,
		0x230AA9CD71B0C0B0ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFA673D51120E5FADULL,
		0x291365F6D94AEF4AULL,
		0xC92CD5FAD59A4A90ULL,
		0x52689B38440A010CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B02076D03F0D78ULL,
		0xF3B70E4F5091436DULL,
		0xC01ABAF6BCD41CC1ULL,
		0x2828092A28DEB6E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83B71CDA41CF5235ULL,
		0x355C57A788B9ABDDULL,
		0x09121B0418C62DCEULL,
		0x2A40920E1B2B4A27ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFA1B899BD14458B4ULL,
		0xB1FFA19551422A1CULL,
		0x36FE14B9C8D6C11BULL,
		0x01741419892D6433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x241BAFA5E3053173ULL,
		0x7F5E19E8F2DE867DULL,
		0xCDA87E0750F516B8ULL,
		0x51CC600F5501F7BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5FFD9F5EE3F272EULL,
		0x32A187AC5E63A39FULL,
		0x695596B277E1AA63ULL,
		0x2FA7B40A342B6C76ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x66C1F2E80885A85DULL,
		0xE53767C6932E9C12ULL,
		0x6FC6A557ED89B75AULL,
		0x4A4154C11A892E7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x937988E9F5A5D24DULL,
		0x30A174FADC57D647ULL,
		0x0CD8D1496AC01424ULL,
		0x464498BC7A8A23C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD34869FE12DFD610ULL,
		0xB495F2CBB6D6C5CAULL,
		0x62EDD40E82C9A336ULL,
		0x03FCBC049FFF0AB3ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3233D25DC8AACE41ULL,
		0x0A57C08E07581C5BULL,
		0xD230A7B6B9251686ULL,
		0x54C2A06264873BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA84808DF7EC3F90ULL,
		0x0E4E5ED5B64D8D51ULL,
		0x100CFAAF3BEDA862ULL,
		0x601708D91917EB03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67AF51CFD0BE8E9EULL,
		0xFC0961B8510A8F09ULL,
		0xC223AD077D376E23ULL,
		0x74AB97894B6F50BDULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFCBFEA1AF05ABAF1ULL,
		0x279458913C72D6ADULL,
		0x16EC7DB2C5FCB203ULL,
		0x5697B1F27C0C6744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC637EBF34792D7BFULL,
		0x9A5C970E23CA6490ULL,
		0x48687823B6E19DE3ULL,
		0x340608B194446FAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3687FE27A8C7E332ULL,
		0x8D37C18318A8721DULL,
		0xCE84058F0F1B141FULL,
		0x2291A940E7C7F794ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAC382FED4AC7ED47ULL,
		0x627BA97042014784ULL,
		0xB63070FEAC7EAAD0ULL,
		0x3011A876ACE757F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120F91B88B79212CULL,
		0x18F9862239A116BEULL,
		0x7D3D418F838ED2F5ULL,
		0x239DF6DE4B669C51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A289E34BF4ECC1BULL,
		0x4982234E086030C6ULL,
		0x38F32F6F28EFD7DBULL,
		0x0C73B1986180BBA3ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC6DFFFF8A13A1D3BULL,
		0xD6587D0753407BCBULL,
		0xECC2A3C2EA6FB6D1ULL,
		0x36DF5D6DCC2F75E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC9C1B614403112EULL,
		0x8E2168C59BACE42AULL,
		0x3646957141791A4DULL,
		0x629718B257041D55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA43E4975D370BFAULL,
		0x48371441B79397A0ULL,
		0xB67C0E51A8F69C84ULL,
		0x544844BB752B588EULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6D6E722A1CB19927ULL,
		0xAB0884EBFF239DA8ULL,
		0x40909EED11EACD4EULL,
		0x75E4B9AC337CDA07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB752871013BADD56ULL,
		0x5F35E494FEF1063FULL,
		0x12FE3A393713BFAEULL,
		0x06584117722AC0F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB61BEB1A08F6BBD1ULL,
		0x4BD2A05700329768ULL,
		0x2D9264B3DAD70DA0ULL,
		0x6F8C7894C1521914ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2F6D6DF0112A356FULL,
		0x460FFC881806D92AULL,
		0x2CB0AB25976E5D51ULL,
		0x62B7A5C4795CBEEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B530512111037CULL,
		0xA7E88BE7D63FA323ULL,
		0x32379457B87748E6ULL,
		0x4D821E036B478915ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37B83D9EF01931F3ULL,
		0x9E2770A041C73606ULL,
		0xFA7916CDDEF7146AULL,
		0x153587C10E1535D8ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB25057D43CB5640DULL,
		0xF6F6BE0FC687B935ULL,
		0x24FB93EC0CB99AF8ULL,
		0x5D32441E80AA7335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4AB9C47013907FULL,
		0x487DB8262C067805ULL,
		0xB6AA326205DCA109ULL,
		0x3E9FCF718FD515FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96059E0FCCA1D38EULL,
		0xAE7905E99A814130ULL,
		0x6E51618A06DCF9EFULL,
		0x1E9274ACF0D55D36ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDAACE48092CBB8F8ULL,
		0xE32CEA6455764C0BULL,
		0x5CDD8FC54ADF94CEULL,
		0x07E68FBD8D57CC8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4559EC5BA0692AULL,
		0x44C51E89B403D3BBULL,
		0x39BBFBA872116FA8ULL,
		0x069F799841B0633EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE678A94372B4FCEULL,
		0x9E67CBDAA1727850ULL,
		0x2321941CD8CE2526ULL,
		0x014716254BA7694FULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0DB9D4425D6DA916ULL,
		0xC07AC771354F57A1ULL,
		0x20A319D29C043215ULL,
		0x09BD9C3CBEC0A8D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77108047A5C876F9ULL,
		0x7D92B5F35852E00CULL,
		0x5BB2472D5BD06F5EULL,
		0x02F2BBB1C2848025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96A953FAB7A5321DULL,
		0x42E8117DDCFC7794ULL,
		0xC4F0D2A54033C2B7ULL,
		0x06CAE08AFC3C28B1ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x41FDC43073CD5395ULL,
		0x73F8B62C75EE402EULL,
		0xEE1170F94098726AULL,
		0x416C27159BBC09E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0B038C508D77D98ULL,
		0x223AD7E387520DF9ULL,
		0xCAA50781D98DB1B6ULL,
		0x13E4DE1F9466ED3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x914D8B6B6AF5D5FDULL,
		0x51BDDE48EE9C3234ULL,
		0x236C6977670AC0B4ULL,
		0x2D8748F607551CA8ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x79094F94263BD886ULL,
		0x57FF0353D76CF0A6ULL,
		0x212033A76A0FE999ULL,
		0x7B0CA7ADD97C45E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CE8BBAB514F5109ULL,
		0x12B7374EE87F6517ULL,
		0x2AB0CA74B4FA2310ULL,
		0x4199B0077C93FD21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C2093E8D4EC877DULL,
		0x4547CC04EEED8B8FULL,
		0xF66F6932B515C689ULL,
		0x3972F7A65CE848BFULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCA335C1DED3B0D9EULL,
		0x982F127AB9814719ULL,
		0x995F0CCF3B9DB204ULL,
		0x5BEFFD3E919DE08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C18ECD1CBC38EDULL,
		0x484CFD51559A95A5ULL,
		0x248C799DFFDEBAF1ULL,
		0x7D03D424E47D6755ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE571CD50D07ED49EULL,
		0x4FE2152963E6B173ULL,
		0x74D293313BBEF713ULL,
		0x5EEC2919AD207936ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4D9F161975DCFED3ULL,
		0x1AB76CA469800277ULL,
		0xD84101D14DA7B183ULL,
		0x7D26B85CBB0F97A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D460E161945DBC0ULL,
		0x879B1ECFC6C38AC5ULL,
		0x9A5153659C13761BULL,
		0x242DE288C86FD8CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE05908035C972313ULL,
		0x931C4DD4A2BC77B1ULL,
		0x3DEFAE6BB1943B67ULL,
		0x58F8D5D3F29FBED5ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3F7D2EF71EC8886BULL,
		0x22318F08E44CB34AULL,
		0xB0713BDCCE7A838FULL,
		0x4468F48BE0E947FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E8A7A710F36594ULL,
		0xDB8A1256384F5E42ULL,
		0xA854F8BD499FDF78ULL,
		0x5C8BE8EAE5AD4565ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD99487500DD522C4ULL,
		0x46A77CB2ABFD5507ULL,
		0x081C431F84DAA416ULL,
		0x67DD0BA0FB3C0299ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x767D760AB703CF6EULL,
		0x78E63CA14E496C33ULL,
		0x8A3DB052DA07F997ULL,
		0x12399FC2D9837DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548242419B8166F5ULL,
		0xB0BE7EDBF9F9C335ULL,
		0xEE13DB08B8077CD0ULL,
		0x70A29D31E0529582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21FB33C91B826866ULL,
		0xC827BDC5544FA8FEULL,
		0x9C29D54A22007CC6ULL,
		0x21970290F930E83BULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x54E46F4BCEC71A42ULL,
		0x6C77DFC761AA4910ULL,
		0xE9AE691195FB6A94ULL,
		0x0384F3208A908E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E7157A2F232D294ULL,
		0xF66A243DA3D755A7ULL,
		0x634611E4354F4798ULL,
		0x454A3E1EC054992EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF67317A8DC94479BULL,
		0x760DBB89BDD2F368ULL,
		0x8668572D60AC22FBULL,
		0x3E3AB501CA3BF534ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEADE684C0EB7DF4DULL,
		0x393C02C19D1A0C1DULL,
		0x85B62BAB3770B991ULL,
		0x2D63CDC7203D475AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6F225FA09556C1ULL,
		0xE4C074BE1B619132ULL,
		0x485CAA7729A2CF16ULL,
		0x424EEEA4E825A653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F6F45EC6E228879ULL,
		0x547B8E0381B87AEBULL,
		0x3D5981340DCDEA7AULL,
		0x6B14DF223817A107ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4248EE9C4A193353ULL,
		0x875DDE272962BCBBULL,
		0x592DF032713D1A58ULL,
		0x4ABBD67ED65F3D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD696E4CCA426D1AULL,
		0x35C60D2FA6798336ULL,
		0x2DD27CACD749571CULL,
		0x5190717DB2513BF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64DF804F7FD6C626ULL,
		0x5197D0F782E93984ULL,
		0x2B5B738599F3C33CULL,
		0x792B6501240E016AULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA2B2884EA32A18AAULL,
		0x69BB9DD9B9A41E12ULL,
		0x8827D1D57E289C5BULL,
		0x7DCCD0F7D7139481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C7107C64321A6BBULL,
		0x348D5DC1791570EEULL,
		0x449D3B3D75199DACULL,
		0x29AB03DC23558659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56418088600871EFULL,
		0x352E4018408EAD24ULL,
		0x438A9698090EFEAFULL,
		0x5421CD1BB3BE0E28ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFF3149BC2C60CB9AULL,
		0x8EA7F3639224250EULL,
		0xD72460A20C3418F7ULL,
		0x7D7B6D3D02A4F967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x629F735FBA4E5517ULL,
		0x1EDD7B75949CCB9BULL,
		0xC57761172FB8B8D0ULL,
		0x45212598F09CABA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C91D65C72127683ULL,
		0x6FCA77EDFD875973ULL,
		0x11ACFF8ADC7B6027ULL,
		0x385A47A412084DC4ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE5B85B0E26A398AAULL,
		0xEE0E3335C780FD92ULL,
		0x6D03C901715E20C6ULL,
		0x10A4A1A23A0566DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA223F7CDA6EFCDF7ULL,
		0x44FDD514DD7C9046ULL,
		0x0A7190E9DC3CFF80ULL,
		0x56D2741A163C3CD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x439463407FB3CAA0ULL,
		0xA9105E20EA046D4CULL,
		0x6292381795212146ULL,
		0x39D22D8823C92A06ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7DEE82C1EB75B3D8ULL,
		0x8011B4709B5BC9D1ULL,
		0xAE239BA5EC9897F4ULL,
		0x7813BC723815B9D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548D54CEE00A19F5ULL,
		0x97489081AAA93219ULL,
		0xE3213EA6872C6295ULL,
		0x5328413CBD24A927ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29612DF30B6B99E3ULL,
		0xE8C923EEF0B297B8ULL,
		0xCB025CFF656C355EULL,
		0x24EB7B357AF110B1ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x160C772C0246BD82ULL,
		0xD8BF0C308345EBE0ULL,
		0x3B3CA18C5FC234F9ULL,
		0x051A5606C10B7663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18EF086EC2F121E2ULL,
		0x14422C3B8C02B54AULL,
		0x74C1F536CEE50C5DULL,
		0x41DB94EF41D42C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD1D6EBD3F559B8DULL,
		0xC47CDFF4F7433695ULL,
		0xC67AAC5590DD289CULL,
		0x433EC1177F374A42ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8E0B7C62B368F34BULL,
		0x19A5B7411B03BD41ULL,
		0x14C631DF1AC40C21ULL,
		0x4046ED30EFDEBFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8DE7B996EC5C644ULL,
		0x08704828122F4E37ULL,
		0xC6DFA29D9CD93766ULL,
		0x7E479373FAE4018DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x952D00C944A32CF4ULL,
		0x11356F1908D46F09ULL,
		0x4DE68F417DEAD4BBULL,
		0x41FF59BCF4FABE40ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x862976EC586EF3F8ULL,
		0x93267138AF736E98ULL,
		0x3C44753D55302552ULL,
		0x5497D03399F94434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DDFC1C17E956B8DULL,
		0xBC98FBE945B53E95ULL,
		0xF30A856C88FD884EULL,
		0x10433A534C5EE396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE849B52AD9D9886BULL,
		0xD68D754F69BE3002ULL,
		0x4939EFD0CC329D03ULL,
		0x445495E04D9A609DULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5ED7315BFD261173ULL,
		0xB36A09695E8A2F7CULL,
		0x44672D228FC26D4EULL,
		0x19A189B5C0F5D774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F8D725C2301A3CULL,
		0x94968967C7BACF65ULL,
		0xBC1AB6E335F19091ULL,
		0x4BAC2648070DDF1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69DE5A363AF5F724ULL,
		0x1ED3800196CF6016ULL,
		0x884C763F59D0DCBDULL,
		0x4DF5636DB9E7F856ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9A5A2FB9A6B1C36CULL,
		0xD049D60ECF679E5EULL,
		0x20DD642CE478DB89ULL,
		0x17CCBDFC961CD109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7763C352A79FFF3AULL,
		0x013DE28A13770209ULL,
		0x4F3D2FC2F9061F9FULL,
		0x0EF357D0EBD74F64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22F66C66FF11C432ULL,
		0xCF0BF384BBF09C55ULL,
		0xD1A03469EB72BBEAULL,
		0x08D9662BAA4581A4ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x420C174AEB5C1F41ULL,
		0x8B81B6ED22AEFF4CULL,
		0xEE9441D387FD13BEULL,
		0x15B78E2AF0B977D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03A7DE56A4CB9C5ULL,
		0xACB919BF546620DBULL,
		0xC04BA30EB80C4CCBULL,
		0x6BE294D5E6FB9B7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81D19965810F6569ULL,
		0xDEC89D2DCE48DE70ULL,
		0x2E489EC4CFF0C6F2ULL,
		0x29D4F95509BDDC5DULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x46DD8C960F13C77CULL,
		0x1E0C11AD2875B7AFULL,
		0x0B80FA759A3C1A06ULL,
		0x41440F5C19D38B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76930C79911B8A71ULL,
		0x1DF9B8B542BC8056ULL,
		0x03F6FB6A7471C31AULL,
		0x2045F6764EE1ED16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD04A801C7DF83D0BULL,
		0x001258F7E5B93758ULL,
		0x0789FF0B25CA56ECULL,
		0x20FE18E5CAF19E46ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0D8516D1529D47AFULL,
		0x685445FA8F49BE7FULL,
		0x01D70885F152B3B6ULL,
		0x11A6A5376A94ACD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4C30B39586A6C1ULL,
		0x874E1FDFAC143F66ULL,
		0x71D4D05EE365CE1BULL,
		0x5DCB99DC8787955CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F38E61DBD16A0DBULL,
		0xE106261AE3357F18ULL,
		0x900238270DECE59AULL,
		0x33DB0B5AE30D1777ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x61A99242804D3B13ULL,
		0x3C6E7FC5E2E81B2AULL,
		0xDBA883F9A5B0405DULL,
		0x4CA1B13198923DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A07F736A215A89ULL,
		0x34D157B00B377E03ULL,
		0x8EAA149886A1144CULL,
		0x4A0A104E4C476DEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A0912CF162BE08AULL,
		0x079D2815D7B09D26ULL,
		0x4CFE6F611F0F2C11ULL,
		0x0297A0E34C4ACFFBULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9C1ACAD750EC6C67ULL,
		0x5437312EED14A8A6ULL,
		0xD00E8540B0E35CB9ULL,
		0x7CD3E5D7375FAAD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34850BA3D8F5683BULL,
		0x2FB033B6329196E5ULL,
		0x79FF76F839FE9E9CULL,
		0x069B4765296BB549ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6795BF3377F7042CULL,
		0x2486FD78BA8311C1ULL,
		0x560F0E4876E4BE1DULL,
		0x76389E720DF3F589ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB11DAD7D0EEB8BE7ULL,
		0x3B34747F88E6C90BULL,
		0x876F1BA1438C197FULL,
		0x23BFBC4B61022F21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D07CB2AE0B9380CULL,
		0xF36664828AC79239ULL,
		0x5A3C3F2A3545ABE6ULL,
		0x7DB4820D1C9D8209ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4415E2522E3253C8ULL,
		0x47CE0FFCFE1F36D2ULL,
		0x2D32DC770E466D98ULL,
		0x260B3A3E4464AD18ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC13A7EB52D0A6161ULL,
		0x8FA464965202EDE4ULL,
		0x6F048B7CC1BDDB26ULL,
		0x32BE89E9761B97FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79763E3C4BF4FB6ULL,
		0x7437AAF286DD7929ULL,
		0x17D09856721B0A0DULL,
		0x0DAB501F880DDD08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9A31AD1684B11ABULL,
		0x1B6CB9A3CB2574BAULL,
		0x5733F3264FA2D119ULL,
		0x251339C9EE0DBAF3ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x99F4ADB4BCB25797ULL,
		0xBB6DD421071EF0E0ULL,
		0x258F3C727DAD9B09ULL,
		0x2DE65FD07C4C3CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4310E5F909E730ULL,
		0xE6896F4B5C040B1BULL,
		0xCA558D88A907D370ULL,
		0x15254D858245FED8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EB19CCEC3A87067ULL,
		0xD4E464D5AB1AE5C5ULL,
		0x5B39AEE9D4A5C798ULL,
		0x18C1124AFA063E26ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6DC1D04914458F7CULL,
		0xFA7FBD296CC881B5ULL,
		0x065E431CB56946B2ULL,
		0x64D62A05C4C30D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763642B58AFFAFA3ULL,
		0xDFF0889222873F86ULL,
		0x07C19061A110E5DBULL,
		0x076FD3DBBB7B4A52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF78B8D938945DFD9ULL,
		0x1A8F34974A41422EULL,
		0xFE9CB2BB145860D7ULL,
		0x5D66562A0947C346ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x373FA32DF2AACB20ULL,
		0x896CDD33EE47953EULL,
		0xE489FB94DD867A56ULL,
		0x570AD7B02E46CB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD473B9301AC93BULL,
		0x3BA67B609BA61531ULL,
		0x242420E3E7744EF0ULL,
		0x48F6D2E8645679AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A6B2F74C29001E5ULL,
		0x4DC661D352A1800CULL,
		0xC065DAB0F6122B66ULL,
		0x0E1404C7C9F051E8ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBFF61D8ED8EEB5BAULL,
		0x456D2BE74A61DD3DULL,
		0xC18134DD25B71B8EULL,
		0x63F30BB5F0895361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FC26EA1A03EA12ULL,
		0x7D0197FEAD34D8B3ULL,
		0x473D4244A20932DAULL,
		0x632335EFD61C9DC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55F9F6A4BEEACBA8ULL,
		0xC86B93E89D2D048AULL,
		0x7A43F29883ADE8B3ULL,
		0x00CFD5C61A6CB59DULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1A62A4C953892677ULL,
		0x161BFF30B1B9DA40ULL,
		0x7601F8A8078EF51FULL,
		0x1D8C9414B80AEC9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB13886141051CDULL,
		0x725D9FBC4DA95E95ULL,
		0x5F6B5FD016D6B7FCULL,
		0x4F8C33D95E162BD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BB16C433F78D497ULL,
		0xA3BE5F7464107BAAULL,
		0x169698D7F0B83D22ULL,
		0x4E00603B59F4C0C6ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xABD995F19D12B08BULL,
		0x884054D75384EF6FULL,
		0xBF699E34D0AB17D9ULL,
		0x2C6C7C501B70E80FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C8310882D0C676EULL,
		0x6D5533A0B655FD6BULL,
		0xC55DBDB6B7FD91B2ULL,
		0x464CFF1A06B7C5C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F5685697006490AULL,
		0x1AEB21369D2EF204ULL,
		0xFA0BE07E18AD8627ULL,
		0x661F7D3614B92246ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xAAAAD4ECCD7FF83CULL,
		0xC4FD1208237B49C7ULL,
		0x6522B92CE6B1F98EULL,
		0x26CA49810A68C224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462BCBB562A65144ULL,
		0x299B304B4A716356ULL,
		0x32A5D7EBA7C63B6EULL,
		0x103572E1901D7D53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x647F09376AD9A6F8ULL,
		0x9B61E1BCD909E671ULL,
		0x327CE1413EEBBE20ULL,
		0x1694D69F7A4B44D1ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x78C68122C14916EEULL,
		0x6935FBDA1817D31EULL,
		0xA36E701AD8D5968CULL,
		0x283DC53753ED4E4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3116FE57FDF03631ULL,
		0xF47EE2B5F271879CULL,
		0x4ED0947B7686CF2AULL,
		0x3693FDDFA059C9DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47AF82CAC358E0AAULL,
		0x74B7192425A64B82ULL,
		0x549DDB9F624EC761ULL,
		0x71A9C757B3938474ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5F8A332252588437ULL,
		0xA1C63A6C55F09B59ULL,
		0xBC55DC9A45F529ECULL,
		0x057E6C525F879D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1DDACFD9121C3BULL,
		0x1A6EDC037A5FD57CULL,
		0x3F01BE73DFB58709ULL,
		0x4298D8F519F8D937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC46C5852794667E9ULL,
		0x87575E68DB90C5DCULL,
		0x7D541E26663FA2E3ULL,
		0x42E5935D458EC3EBULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x33D03B6A6D587D83ULL,
		0x3DDF75E5F9FB9F4DULL,
		0xC8FBF0FF0B58950BULL,
		0x608B471FA33CF543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8E54D32572B09AULL,
		0x8FEF61EE348FF4D8ULL,
		0x49A754760557E5FFULL,
		0x013D8B86A0CDF376ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3941E69747E5CCE9ULL,
		0xADF013F7C56BAA74ULL,
		0x7F549C890600AF0BULL,
		0x5F4DBB99026F01CDULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFA6E8D736A2A4D74ULL,
		0x688FC8AF852639A2ULL,
		0x2AD5A070C4561E30ULL,
		0x1723802FA087EE0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F832B3E15455B9CULL,
		0xDC710DE90260D6CFULL,
		0xD10DF06FA76D97ADULL,
		0x5C7E0A2275CA2987ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAEB623554E4F1C5ULL,
		0x8C1EBAC682C562D3ULL,
		0x59C7B0011CE88682ULL,
		0x3AA5760D2ABDC483ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBD93B0D5349857B4ULL,
		0xE9EFFB4C50AD3BBEULL,
		0x641B13E3BF2EEEBAULL,
		0x7CD764C9C6726896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC5C936A76B274EULL,
		0xB2E1EA5BBD4CF9A5ULL,
		0x2B2B2B4E936A5DBCULL,
		0x6C71755A0FA52B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62CDE79E8D2D3066ULL,
		0x370E10F093604219ULL,
		0x38EFE8952BC490FEULL,
		0x1065EF6FB6CD3D85ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2F0FCDFB7856E20EULL,
		0xF1384B6FF5543B01ULL,
		0x4354AD426DB2BFE6ULL,
		0x4D3655B0646C358BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F423265D272BCEBULL,
		0xA0A0D89C1A7C8CAEULL,
		0x9A43FB312B8C84A2ULL,
		0x08DD4FAC29EEC3FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FCD9B95A5E42523ULL,
		0x509772D3DAD7AE52ULL,
		0xA910B21142263B44ULL,
		0x445906043A7D718BULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x244BC88C6FD990C5ULL,
		0x020D2505FA60A18FULL,
		0xF71BFED1D0085BCDULL,
		0x1EE973700D0CAFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9111A7C9D516CB4ULL,
		0xAFA2D46D692F3ACFULL,
		0x4211E411A4F60B9BULL,
		0x27AEC153396A402AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B3AAE0FD28823FEULL,
		0x526A5098913166BFULL,
		0xB50A1AC02B125031ULL,
		0x773AB21CD3A26FABULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA6EA58127B4758A7ULL,
		0x0FE75B640F96E430ULL,
		0x5F5C653FD2FB6789ULL,
		0x407542E9510D71D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBE1FF0BA4FF0E2DULL,
		0xECCA74EA065043CBULL,
		0xD0C544BA3611C125ULL,
		0x0FA2725D09A7D53AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB085906D6484A7AULL,
		0x231CE67A0946A064ULL,
		0x8E9720859CE9A663ULL,
		0x30D2D08C47659C9CULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x47D6D042E62B8EC8ULL,
		0x1BBE319A386BE480ULL,
		0xB813E0DC77AD47ACULL,
		0x36E838091E055449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916EF7768324384AULL,
		0x404993AA9C6DF51AULL,
		0xBAF01C9016FDDBA2ULL,
		0x032C477649938033ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB667D8CC6307567EULL,
		0xDB749DEF9BFDEF65ULL,
		0xFD23C44C60AF6C09ULL,
		0x33BBF092D471D415ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD7BD999F17F1F22CULL,
		0x03B1E49E70739D2DULL,
		0x1017A49508B1C8CBULL,
		0x1960DC9C5E085C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4BB7344F73829DULL,
		0x868B32C6D55ED004ULL,
		0x20CA844F8860AA02ULL,
		0x649B76D9C8033E72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3971E26AC87E6F7CULL,
		0x7D26B1D79B14CD29ULL,
		0xEF4D204580511EC8ULL,
		0x34C565C296051DD5ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD1C17D00A826DCEFULL,
		0x927A9BA3982F539AULL,
		0x751476918B610E42ULL,
		0x59038E2B2ED4D28AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC03C4048FB6DE0ULL,
		0xDF50C0ADCEA4D734ULL,
		0xA71ACE19EC7F347BULL,
		0x7BA0EE8CFBDAD600ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x370140C05F2B6EFCULL,
		0xB329DAF5C98A7C66ULL,
		0xCDF9A8779EE1D9C6ULL,
		0x5D629F9E32F9FC89ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x039B0C801E1459E6ULL,
		0x2A00444EF8B54481ULL,
		0x4A79FF1BEC6262A9ULL,
		0x4CDDEF1C7EA416DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BA1541906FAAEB8ULL,
		0xC138E7BF50634D7CULL,
		0xD8B3111DAE9B79D8ULL,
		0x3C09B0D5349A11E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7F9B8671719AB2EULL,
		0x68C75C8FA851F704ULL,
		0x71C6EDFE3DC6E8D0ULL,
		0x10D43E474A0A04F4ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4200DB401862BE98ULL,
		0x3879EE9379432B26ULL,
		0x15A22E89B0CA4F1BULL,
		0x4D3B903C13E03BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D79BAA1133733ADULL,
		0xF8BBEF2B830996BAULL,
		0xD73C03335C941482ULL,
		0x05F6B9364427D879ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0487209F052B8AEBULL,
		0x3FBDFF67F639946CULL,
		0x3E662B5654363A98ULL,
		0x4744D705CFB86356ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCFBE83B7ED799619ULL,
		0x41FFD1352AB332C8ULL,
		0xB7680B2066A192D3ULL,
		0x030BB6A66A27001EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5D1440F1D8E4C4ULL,
		0xE7FBC5B63E142AA5ULL,
		0xE9B2A6B2398068CCULL,
		0x5EDD3BEAF1BD50E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4616F76FBA0B142ULL,
		0x5A040B7EEC9F0822ULL,
		0xCDB5646E2D212A06ULL,
		0x242E7ABB7869AF39ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7A4626A8A5A912EFULL,
		0x49C85FA81FD856DDULL,
		0x300E0BF266E6B249ULL,
		0x0CB405E61EC6C5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3705E400A0F518F7ULL,
		0x50DC226A90A1791EULL,
		0xF1928880471AA7E4ULL,
		0x67AF0ECA232950F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434042A804B3F9E5ULL,
		0xF8EC3D3D8F36DDBFULL,
		0x3E7B83721FCC0A64ULL,
		0x2504F71BFB9D74EDULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4ABF659AE78FC0ABULL,
		0xD504D6717BAC9821ULL,
		0xF4702A035FAF291EULL,
		0x512346D2B2883D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3EBC5171B606FCULL,
		0xE1DF92EF3BCF8318ULL,
		0x24E9C52EFC588CF2ULL,
		0x4CA083FC7F3556D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD080A94975D9B9AFULL,
		0xF32543823FDD1508ULL,
		0xCF8664D463569C2BULL,
		0x0482C2D63352E6CEULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFDE11185821F2C8CULL,
		0xAA48591C8488676AULL,
		0x8C5CF68FE9D9544FULL,
		0x2EE05F558FAD8AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5B8CC667B765C1ULL,
		0xF831AA6B0B3A384BULL,
		0x1AA1CC5C6F193572ULL,
		0x3EA55BC5E0CD837DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F8584BF1A67C6B8ULL,
		0xB216AEB1794E2F1FULL,
		0x71BB2A337AC01EDCULL,
		0x703B038FAEE00775ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x98BEBC69642BF82DULL,
		0x134622523631ABE9ULL,
		0xA3373D415723211CULL,
		0x27865ECFD8F27541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C6A505783C7D49ULL,
		0x6FF4512FF6B0E3E3ULL,
		0xF1A015B44D77526FULL,
		0x6D5EF537984277C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2F81763EBEF7AD1ULL,
		0xA351D1223F80C805ULL,
		0xB197278D09ABCEACULL,
		0x3A27699840AFFD7CULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF1E3A77DB7C9C0EEULL,
		0x4291503EF9860A87ULL,
		0x1EA0A953AF25B851ULL,
		0x547FE20155F5D64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F06AFA0AA196AFULL,
		0xB0B99201DAC9879BULL,
		0x5144AA4B05C02A8DULL,
		0x287403F02661962CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0F33C83AD282A3FULL,
		0x91D7BE3D1EBC82ECULL,
		0xCD5BFF08A9658DC3ULL,
		0x2C0BDE112F944022ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x97744E2FCE9DE537ULL,
		0x9F44B923A654B0E9ULL,
		0x63DC65044F38F1E9ULL,
		0x17981CD5CDD488EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC96FF285236569ULL,
		0xE9B1C60774EE75AFULL,
		0x4E87C327759B9664ULL,
		0x2CC66A70D7C65777ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CAADE3D497A7FBBULL,
		0xB592F31C31663B3AULL,
		0x1554A1DCD99D5B84ULL,
		0x6AD1B264F60E3178ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x32FD99AADB34DBFBULL,
		0x39A0F49FEB55EF81ULL,
		0x74FADC305FA7F116ULL,
		0x4B2C897D78104022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E5F60ADD6C936FULL,
		0xE487416F1485D8F7ULL,
		0xA74DF7741A0AD339ULL,
		0x789FFEB93854F2D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E17A39FFDC84879ULL,
		0x5519B330D6D0168AULL,
		0xCDACE4BC459D1DDCULL,
		0x528C8AC43FBB4D4CULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB1F62AC4EEBE18CAULL,
		0x0E8CB1E7C75449F9ULL,
		0xAAC5A3386C784941ULL,
		0x1B8EE66EB1F9A77AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBB5DB27D3DA0D5CULL,
		0x0E006DC4415A4AB8ULL,
		0x8125308C70F98191ULL,
		0x55610681A7A44D89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6404F9D1AE40B5BULL,
		0x008C442385F9FF40ULL,
		0x29A072ABFB7EC7B0ULL,
		0x462DDFED0A5559F1ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8C10D2BC698898DAULL,
		0x01F6AACD69853D6CULL,
		0x8958BC20D4EFC09AULL,
		0x54FFFD6CC608A1FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE98B4E2D391B4DULL,
		0x2BFB2E4CE5FD576BULL,
		0xD94549195238F2F4ULL,
		0x63FCF9B6A525D059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE27476E3C4F7D7AULL,
		0xD5FB7C808387E600ULL,
		0xB013730782B6CDA5ULL,
		0x710303B620E2D1A2ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF42986B2D362AC16ULL,
		0xBA6006DE4EEADF57ULL,
		0xB4292FDF10CFCFD7ULL,
		0x709FCF98C3F9836BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B98E3E0DC921330ULL,
		0x3D800997ED567279ULL,
		0x599729D901525009ULL,
		0x1A324BF6B83D2FFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE890A2D1F6D098E6ULL,
		0x7CDFFD4661946CDEULL,
		0x5A9206060F7D7FCEULL,
		0x566D83A20BBC5371ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC77BAAAF27A33D9EULL,
		0xF8D869213F1D417FULL,
		0xA1F7D362B6762369ULL,
		0x2BB1085F7E70082FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D2756126F878E6ULL,
		0xB812E1FC5E8C4FEAULL,
		0xB86CE147704DB9A5ULL,
		0x016A94CB632799CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EA9354E00AAC4B8ULL,
		0x40C58724E090F195ULL,
		0xE98AF21B462869C4ULL,
		0x2A4673941B486E5FULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D54E990B8349A76ULL,
		0xCCF2C40A07CECF98ULL,
		0x1048524BD811CF90ULL,
		0x6074787C0428EBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73677FCFFC097A0EULL,
		0xA24B53B9C0AD7108ULL,
		0xE187816782BE2799ULL,
		0x52017DEB54E569D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19ED69C0BC2B2068ULL,
		0x2AA7705047215E90ULL,
		0x2EC0D0E45553A7F7ULL,
		0x0E72FA90AF4381CFULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x706967C533785876ULL,
		0xF6C94E7FF1468111ULL,
		0x0700BA22F4405A93ULL,
		0x4E7E76F3955F7E55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB251B8974ED3AFULL,
		0x2A7CD34BA78525B6ULL,
		0x82AD954DC055BDE1ULL,
		0x05CACB511E65D526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85B7160C9C2984C7ULL,
		0xCC4C7B3449C15B5AULL,
		0x845324D533EA9CB2ULL,
		0x48B3ABA276F9A92EULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA5806786D85D337AULL,
		0x049546458CAFCD57ULL,
		0xA652A3C1F97CE336ULL,
		0x616D6FB92BC1CE95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE2FFD7BC4C4679ULL,
		0xD72A2699D927BE2BULL,
		0x235AFAE8BE4A9E99ULL,
		0x09A4A945B35AEB00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x999D67AF1C10ED01ULL,
		0x2D6B1FABB3880F2CULL,
		0x82F7A8D93B32449CULL,
		0x57C8C6737866E395ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2CFD127C23D38C77ULL,
		0x8A7F41F152073533ULL,
		0x52ACCD698379F3E7ULL,
		0x7969E0A39E3B4A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBE4A9940AA3069ULL,
		0xE90B3C33BF605018ULL,
		0xA17CD6D4DC9C89FFULL,
		0x2C73B41050FFC74DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103EC7E2E3295C0EULL,
		0xA17405BD92A6E51BULL,
		0xB12FF694A6DD69E7ULL,
		0x4CF62C934D3B8303ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2CEB4233649E5A35ULL,
		0xDFD9A3F7B8F35685ULL,
		0x1FB233E479DF946AULL,
		0x094D43A57EB7192CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60F2F460C1D551F5ULL,
		0x581689793C2A8074ULL,
		0xAA13C96F1C3A1053ULL,
		0x5905A182206A0123ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF84DD2A2C9082DULL,
		0x87C31A7E7CC8D610ULL,
		0x759E6A755DA58417ULL,
		0x3047A2235E4D1808ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x97B855EA1A03469CULL,
		0x92EE497E1B5CA7DAULL,
		0x2E06FB70AF9084A4ULL,
		0x1DC5C1D95E914231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805671489CA0F71FULL,
		0x8AC7554FA002B149ULL,
		0x251DB8D505F13EF7ULL,
		0x5998F99D9056738BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1761E4A17D624F6AULL,
		0x0826F42E7B59F691ULL,
		0x08E9429BA99F45ADULL,
		0x442CC83BCE3ACEA6ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x82E06B0DCA5D16AAULL,
		0x37DF69347BA5C1B3ULL,
		0xC38B6EF9B939F116ULL,
		0x045D7B862DF82EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72640362BCB84368ULL,
		0x94D9CD8AAF58FAC7ULL,
		0x4BDC53FD75EB7216ULL,
		0x674FBD35AB3361ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x107C67AB0DA4D32FULL,
		0xA3059BA9CC4CC6ECULL,
		0x77AF1AFC434E7EFFULL,
		0x1D0DBE5082C4CD31ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9AB3B362D050086CULL,
		0x447F26B29F39FD1AULL,
		0x279155F47227AC0DULL,
		0x1448F3FABE459856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x402E0CFDEA01E368ULL,
		0xA4842DFE2C034F2AULL,
		0x6A56A19132720DDDULL,
		0x16CCF7723308278BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A85A664E64E24F1ULL,
		0x9FFAF8B47336ADF0ULL,
		0xBD3AB4633FB59E2FULL,
		0x7D7BFC888B3D70CAULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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