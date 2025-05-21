#include "tests.h"

int32_t curve25519_key_add_self_test(void) {
	printf("Add Self Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x18A1B5A55618FF6CULL,
		0x0D512794BCC0CBCEULL,
		0xC4148D13CE203A7FULL,
		0x46BB3BA07C69FDC2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x18A1B5A55618FF6CULL,
		0x0D512794BCC0CBCEULL,
		0xC4148D13CE203A7FULL,
		0x46BB3BA07C69FDC2ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x31436B4AAC31FEEBULL,
		0x1AA24F297981979CULL,
		0x88291A279C4074FEULL,
		0x0D767740F8D3FB85ULL
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
		0x904377E0F727D8ABULL,
		0xD9938C60044345B5ULL,
		0x7FD91129DC36EB5FULL,
		0x6463168C15AC8333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x904377E0F727D8ABULL,
		0xD9938C60044345B5ULL,
		0x7FD91129DC36EB5FULL,
		0x6463168C15AC8333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2086EFC1EE4FB169ULL,
		0xB32718C008868B6BULL,
		0xFFB22253B86DD6BFULL,
		0x48C62D182B590666ULL
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
		0x84407C9D480C5511ULL,
		0xA7DFF3144A3492CDULL,
		0x38D8DD14D1449B0FULL,
		0x1944C6638427AAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84407C9D480C5511ULL,
		0xA7DFF3144A3492CDULL,
		0x38D8DD14D1449B0FULL,
		0x1944C6638427AAF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0880F93A9018AA22ULL,
		0x4FBFE6289469259BULL,
		0x71B1BA29A289361FULL,
		0x32898CC7084F55F0ULL
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
		0xF3EFC175281C0D33ULL,
		0x8CDBF30076ABCD34ULL,
		0x792839EBFE34FA7DULL,
		0x7AB4C5FD85460E06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3EFC175281C0D33ULL,
		0x8CDBF30076ABCD34ULL,
		0x792839EBFE34FA7DULL,
		0x7AB4C5FD85460E06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7DF82EA50381A79ULL,
		0x19B7E600ED579A69ULL,
		0xF25073D7FC69F4FBULL,
		0x75698BFB0A8C1C0CULL
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
		0x00322A2DD4CC02F4ULL,
		0x66D71C856B98691EULL,
		0x3A1F559D7FC87311ULL,
		0x754AAC4DCC1FDC7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00322A2DD4CC02F4ULL,
		0x66D71C856B98691EULL,
		0x3A1F559D7FC87311ULL,
		0x754AAC4DCC1FDC7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0064545BA99805FBULL,
		0xCDAE390AD730D23CULL,
		0x743EAB3AFF90E622ULL,
		0x6A95589B983FB8F4ULL
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
		0x82C43462741729B0ULL,
		0x0E6FA1A0DEA0DCA0ULL,
		0x0946F8A163F3E3C2ULL,
		0x11321FDDFAA36FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C43462741729B0ULL,
		0x0E6FA1A0DEA0DCA0ULL,
		0x0946F8A163F3E3C2ULL,
		0x11321FDDFAA36FC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x058868C4E82E5360ULL,
		0x1CDF4341BD41B941ULL,
		0x128DF142C7E7C784ULL,
		0x22643FBBF546DF82ULL
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
		0x1C7F4A7203809BE2ULL,
		0x6EF8A48950008761ULL,
		0x6AD08722570A728BULL,
		0x4C152432B7B7DEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C7F4A7203809BE2ULL,
		0x6EF8A48950008761ULL,
		0x6AD08722570A728BULL,
		0x4C152432B7B7DEA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38FE94E4070137D7ULL,
		0xDDF14912A0010EC2ULL,
		0xD5A10E44AE14E516ULL,
		0x182A48656F6FBD40ULL
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
		0x7921C52386391CD0ULL,
		0x46B983FE1F17D501ULL,
		0x9F3128A900B85E5FULL,
		0x00FF5870C1169247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7921C52386391CD0ULL,
		0x46B983FE1F17D501ULL,
		0x9F3128A900B85E5FULL,
		0x00FF5870C1169247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2438A470C7239A0ULL,
		0x8D7307FC3E2FAA02ULL,
		0x3E6251520170BCBEULL,
		0x01FEB0E1822D248FULL
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
		0x2FB7AC275EABBD64ULL,
		0x8D9FA5468F3FB8AAULL,
		0x7AE9788EA9C3E601ULL,
		0x7B02864CDB689F68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FB7AC275EABBD64ULL,
		0x8D9FA5468F3FB8AAULL,
		0x7AE9788EA9C3E601ULL,
		0x7B02864CDB689F68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F6F584EBD577ADBULL,
		0x1B3F4A8D1E7F7154ULL,
		0xF5D2F11D5387CC03ULL,
		0x76050C99B6D13ED0ULL
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
		0x21AAA6E5BBF2B372ULL,
		0xB32F74CF630F021AULL,
		0xB4893168DDFC2F33ULL,
		0x69F20A3EB7B2F3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21AAA6E5BBF2B372ULL,
		0xB32F74CF630F021AULL,
		0xB4893168DDFC2F33ULL,
		0x69F20A3EB7B2F3FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43554DCB77E566F7ULL,
		0x665EE99EC61E0434ULL,
		0x691262D1BBF85E67ULL,
		0x53E4147D6F65E7FDULL
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
		0xA9D9ABF9E942706EULL,
		0x12730284448177B0ULL,
		0x42D3E7A327F1E8A2ULL,
		0x2424750EBCA630A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9D9ABF9E942706EULL,
		0x12730284448177B0ULL,
		0x42D3E7A327F1E8A2ULL,
		0x2424750EBCA630A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B357F3D284E0DCULL,
		0x24E605088902EF61ULL,
		0x85A7CF464FE3D144ULL,
		0x4848EA1D794C6150ULL
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
		0x3846E4BF73726FDBULL,
		0x10C43917ACEDA41AULL,
		0x164AFC546C9643A1ULL,
		0x5B95D35446D24D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3846E4BF73726FDBULL,
		0x10C43917ACEDA41AULL,
		0x164AFC546C9643A1ULL,
		0x5B95D35446D24D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x708DC97EE6E4DFC9ULL,
		0x2188722F59DB4834ULL,
		0x2C95F8A8D92C8742ULL,
		0x372BA6A88DA49AA2ULL
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
		0x12258B2A603FA1B4ULL,
		0x47863442D316E545ULL,
		0x6024FF167733E77FULL,
		0x7B4B20E495B46FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12258B2A603FA1B4ULL,
		0x47863442D316E545ULL,
		0x6024FF167733E77FULL,
		0x7B4B20E495B46FB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x244B1654C07F437BULL,
		0x8F0C6885A62DCA8AULL,
		0xC049FE2CEE67CEFEULL,
		0x769641C92B68DF6CULL
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
		0x1D8CE864D73AC480ULL,
		0xA18142473F8BBE2EULL,
		0x2DEE0E586B2BB8AEULL,
		0x16C487014AA4602AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8CE864D73AC480ULL,
		0xA18142473F8BBE2EULL,
		0x2DEE0E586B2BB8AEULL,
		0x16C487014AA4602AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3B19D0C9AE758900ULL,
		0x4302848E7F177C5CULL,
		0x5BDC1CB0D657715DULL,
		0x2D890E029548C054ULL
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
		0x3255586ED1A048BCULL,
		0xDE1EAAACD4D1A753ULL,
		0xFDDA02E11ABB75C8ULL,
		0x51503A66AC077FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3255586ED1A048BCULL,
		0xDE1EAAACD4D1A753ULL,
		0xFDDA02E11ABB75C8ULL,
		0x51503A66AC077FF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64AAB0DDA340918BULL,
		0xBC3D5559A9A34EA6ULL,
		0xFBB405C23576EB91ULL,
		0x22A074CD580EFFE7ULL
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
		0xF636C675EF5F2FB0ULL,
		0xBBD8FA0F413B211CULL,
		0x07B3BA86D8FBF352ULL,
		0x113FD681C6536A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF636C675EF5F2FB0ULL,
		0xBBD8FA0F413B211CULL,
		0x07B3BA86D8FBF352ULL,
		0x113FD681C6536A68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC6D8CEBDEBE5F60ULL,
		0x77B1F41E82764239ULL,
		0x0F67750DB1F7E6A5ULL,
		0x227FAD038CA6D4D0ULL
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
		0x86756D730A5D9531ULL,
		0x9B489F8DD2118B4AULL,
		0xCEEE93782FD12DF5ULL,
		0x73232534D54E9618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86756D730A5D9531ULL,
		0x9B489F8DD2118B4AULL,
		0xCEEE93782FD12DF5ULL,
		0x73232534D54E9618ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CEADAE614BB2A75ULL,
		0x36913F1BA4231695ULL,
		0x9DDD26F05FA25BEBULL,
		0x66464A69AA9D2C31ULL
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
		0x307DD7E6FC04F70BULL,
		0x079CFB0D5E17F33AULL,
		0x8B871E1CA9FE66FCULL,
		0x73DE0A55CDA941C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x307DD7E6FC04F70BULL,
		0x079CFB0D5E17F33AULL,
		0x8B871E1CA9FE66FCULL,
		0x73DE0A55CDA941C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60FBAFCDF809EE29ULL,
		0x0F39F61ABC2FE674ULL,
		0x170E3C3953FCCDF8ULL,
		0x67BC14AB9B528389ULL
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
		0x5DBD069AC7BE32B4ULL,
		0x42184AE81294EBFBULL,
		0xC8E97A49A74A1667ULL,
		0x500CD1BDF09940FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DBD069AC7BE32B4ULL,
		0x42184AE81294EBFBULL,
		0xC8E97A49A74A1667ULL,
		0x500CD1BDF09940FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB7A0D358F7C657BULL,
		0x843095D02529D7F6ULL,
		0x91D2F4934E942CCEULL,
		0x2019A37BE13281FDULL
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
		0x981E460D41A399CAULL,
		0x8E4388E296C2DB44ULL,
		0x6C1BA24452C8A240ULL,
		0x5823B216048CA9C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x981E460D41A399CAULL,
		0x8E4388E296C2DB44ULL,
		0x6C1BA24452C8A240ULL,
		0x5823B216048CA9C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x303C8C1A834733A7ULL,
		0x1C8711C52D85B689ULL,
		0xD8374488A5914481ULL,
		0x3047642C09195384ULL
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
		0xC772CFCC409A807AULL,
		0x5D85D7980877B579ULL,
		0xBEDDBEBB08B3D680ULL,
		0x62DFB4D5FBF3DCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC772CFCC409A807AULL,
		0x5D85D7980877B579ULL,
		0xBEDDBEBB08B3D680ULL,
		0x62DFB4D5FBF3DCA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EE59F9881350107ULL,
		0xBB0BAF3010EF6AF3ULL,
		0x7DBB7D761167AD00ULL,
		0x45BF69ABF7E7B94BULL
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
		0xD9749D569406AFF5ULL,
		0x8AEB527E51E1A812ULL,
		0x2393183044D939B6ULL,
		0x6D330C2016F39BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9749D569406AFF5ULL,
		0x8AEB527E51E1A812ULL,
		0x2393183044D939B6ULL,
		0x6D330C2016F39BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2E93AAD280D5FFDULL,
		0x15D6A4FCA3C35025ULL,
		0x4726306089B2736DULL,
		0x5A6618402DE73780ULL
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
		0x792D4AFD51783280ULL,
		0x19359825A04E76E6ULL,
		0x76390E9F3F6BB4BBULL,
		0x035F81EA0A6F336DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792D4AFD51783280ULL,
		0x19359825A04E76E6ULL,
		0x76390E9F3F6BB4BBULL,
		0x035F81EA0A6F336DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF25A95FAA2F06500ULL,
		0x326B304B409CEDCCULL,
		0xEC721D3E7ED76976ULL,
		0x06BF03D414DE66DAULL
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
		0x03EA67CAAA1B61B4ULL,
		0xFE3AA7FC0EE5BEC5ULL,
		0x4F465B11DCFDC0F3ULL,
		0x460B7FCF9768F82BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03EA67CAAA1B61B4ULL,
		0xFE3AA7FC0EE5BEC5ULL,
		0x4F465B11DCFDC0F3ULL,
		0x460B7FCF9768F82BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07D4CF955436C37BULL,
		0xFC754FF81DCB7D8AULL,
		0x9E8CB623B9FB81E7ULL,
		0x0C16FF9F2ED1F056ULL
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
		0x8F74E801FE1040F6ULL,
		0x63074EE3841047B2ULL,
		0x50A456E759AAF82EULL,
		0x66C8BA243C9667C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F74E801FE1040F6ULL,
		0x63074EE3841047B2ULL,
		0x50A456E759AAF82EULL,
		0x66C8BA243C9667C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EE9D003FC2081FFULL,
		0xC60E9DC708208F65ULL,
		0xA148ADCEB355F05CULL,
		0x4D917448792CCF82ULL
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
		0x2B86BB2B8096AE60ULL,
		0xB6A7B04E50B2D284ULL,
		0xDC6327A8A2AD6CAEULL,
		0x1FFE1BB5B59B1E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B86BB2B8096AE60ULL,
		0xB6A7B04E50B2D284ULL,
		0xDC6327A8A2AD6CAEULL,
		0x1FFE1BB5B59B1E4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x570D7657012D5CC0ULL,
		0x6D4F609CA165A508ULL,
		0xB8C64F51455AD95DULL,
		0x3FFC376B6B363C97ULL
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
		0x9A3618BC49B04171ULL,
		0xB71257960E417FEAULL,
		0x4B906DA155B7BF00ULL,
		0x71AD99C746AF2130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A3618BC49B04171ULL,
		0xB71257960E417FEAULL,
		0x4B906DA155B7BF00ULL,
		0x71AD99C746AF2130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x346C3178936082F5ULL,
		0x6E24AF2C1C82FFD5ULL,
		0x9720DB42AB6F7E01ULL,
		0x635B338E8D5E4260ULL
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
		0x0823D5D4CFE52629ULL,
		0x9A967754B00E32CAULL,
		0xCBD53A2815912CB8ULL,
		0x4DC40CA8B469B116ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0823D5D4CFE52629ULL,
		0x9A967754B00E32CAULL,
		0xCBD53A2815912CB8ULL,
		0x4DC40CA8B469B116ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1047ABA99FCA4C65ULL,
		0x352CEEA9601C6594ULL,
		0x97AA74502B225971ULL,
		0x1B88195168D3622DULL
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
		0xC18258BC072C556AULL,
		0xAADF13222AFA0045ULL,
		0xFECFF8E7F99D612DULL,
		0x5E7883A594342AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC18258BC072C556AULL,
		0xAADF13222AFA0045ULL,
		0xFECFF8E7F99D612DULL,
		0x5E7883A594342AD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8304B1780E58AAE7ULL,
		0x55BE264455F4008BULL,
		0xFD9FF1CFF33AC25BULL,
		0x3CF1074B286855A7ULL
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
		0x936C1079BFFA0DB2ULL,
		0x8606E369A63A2B19ULL,
		0xB80BD0CD883C0326ULL,
		0x49B411B8DDFA0821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936C1079BFFA0DB2ULL,
		0x8606E369A63A2B19ULL,
		0xB80BD0CD883C0326ULL,
		0x49B411B8DDFA0821ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26D820F37FF41B77ULL,
		0x0C0DC6D34C745633ULL,
		0x7017A19B1078064DULL,
		0x13682371BBF41043ULL
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
		0x60141E6589C0E3D7ULL,
		0x42A0D988E9236C8EULL,
		0x4C2D4485C124CCCEULL,
		0x109114D9AC4C22FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60141E6589C0E3D7ULL,
		0x42A0D988E9236C8EULL,
		0x4C2D4485C124CCCEULL,
		0x109114D9AC4C22FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0283CCB1381C7AEULL,
		0x8541B311D246D91CULL,
		0x985A890B8249999CULL,
		0x212229B3589845F8ULL
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
		0x0B505A093B3314DBULL,
		0x4C2ECDB7B377C356ULL,
		0x13173F530D75BFFAULL,
		0x16F95C8BB9DD2069ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B505A093B3314DBULL,
		0x4C2ECDB7B377C356ULL,
		0x13173F530D75BFFAULL,
		0x16F95C8BB9DD2069ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A0B412766629B6ULL,
		0x985D9B6F66EF86ACULL,
		0x262E7EA61AEB7FF4ULL,
		0x2DF2B91773BA40D2ULL
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
		0x0B4681ABA49B76E3ULL,
		0x48A7E1D3C64EA780ULL,
		0xA0B6C84F2E027374ULL,
		0x095C6A1E734CF505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4681ABA49B76E3ULL,
		0x48A7E1D3C64EA780ULL,
		0xA0B6C84F2E027374ULL,
		0x095C6A1E734CF505ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x168D03574936EDC6ULL,
		0x914FC3A78C9D4F00ULL,
		0x416D909E5C04E6E8ULL,
		0x12B8D43CE699EA0BULL
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
		0x7CFD2A7FB847B752ULL,
		0xC57AF57E00399A0AULL,
		0x18B14BE92EA17651ULL,
		0x477A8C6DDE83CB3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFD2A7FB847B752ULL,
		0xC57AF57E00399A0AULL,
		0x18B14BE92EA17651ULL,
		0x477A8C6DDE83CB3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9FA54FF708F6EB7ULL,
		0x8AF5EAFC00733414ULL,
		0x316297D25D42ECA3ULL,
		0x0EF518DBBD079678ULL
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
		0xA60E7D5AEE186659ULL,
		0x0CD400D43D73B9DDULL,
		0x75FC2E8ED9C37025ULL,
		0x19E2E3CD2CD18B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA60E7D5AEE186659ULL,
		0x0CD400D43D73B9DDULL,
		0x75FC2E8ED9C37025ULL,
		0x19E2E3CD2CD18B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C1CFAB5DC30CCB2ULL,
		0x19A801A87AE773BBULL,
		0xEBF85D1DB386E04AULL,
		0x33C5C79A59A316D6ULL
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
		0x71883A61FF9A824DULL,
		0xF5920104BD17071EULL,
		0x2723733192FCD9DCULL,
		0x771D2005D88AAF16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71883A61FF9A824DULL,
		0xF5920104BD17071EULL,
		0x2723733192FCD9DCULL,
		0x771D2005D88AAF16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE31074C3FF3504ADULL,
		0xEB2402097A2E0E3CULL,
		0x4E46E66325F9B3B9ULL,
		0x6E3A400BB1155E2CULL
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
		0xC68CB36892C54575ULL,
		0x3325EB6F6BA7792EULL,
		0x490A93D3EB82DE61ULL,
		0x462D4F6531515EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68CB36892C54575ULL,
		0x3325EB6F6BA7792EULL,
		0x490A93D3EB82DE61ULL,
		0x462D4F6531515EA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D1966D1258A8AFDULL,
		0x664BD6DED74EF25DULL,
		0x921527A7D705BCC2ULL,
		0x0C5A9ECA62A2BD42ULL
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
		0x09B1A0CE978341D1ULL,
		0x0AE161FA707FECE0ULL,
		0xD159B95C0E96BDAFULL,
		0x58C03B63A58513CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B1A0CE978341D1ULL,
		0x0AE161FA707FECE0ULL,
		0xD159B95C0E96BDAFULL,
		0x58C03B63A58513CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1363419D2F0683B5ULL,
		0x15C2C3F4E0FFD9C0ULL,
		0xA2B372B81D2D7B5EULL,
		0x318076C74B0A2799ULL
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
		0xF7A3A5A9162671A0ULL,
		0x551912C18ADE541DULL,
		0x3511C685FA86E81FULL,
		0x442C4956C7434344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A3A5A9162671A0ULL,
		0x551912C18ADE541DULL,
		0x3511C685FA86E81FULL,
		0x442C4956C7434344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF474B522C4CE353ULL,
		0xAA32258315BCA83BULL,
		0x6A238D0BF50DD03EULL,
		0x085892AD8E868688ULL
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
		0x6F5CE8ECC5C83FB7ULL,
		0x0B86FE9E373BF011ULL,
		0xF6CAC4FA11C9FDBFULL,
		0x01F2986610D330A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5CE8ECC5C83FB7ULL,
		0x0B86FE9E373BF011ULL,
		0xF6CAC4FA11C9FDBFULL,
		0x01F2986610D330A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEB9D1D98B907F6EULL,
		0x170DFD3C6E77E022ULL,
		0xED9589F42393FB7EULL,
		0x03E530CC21A6614FULL
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
		0x3264A1B1D11D1CD4ULL,
		0xCE5A1B2EC04726D7ULL,
		0xA9BB4107F77888C8ULL,
		0x030132F1486AE049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3264A1B1D11D1CD4ULL,
		0xCE5A1B2EC04726D7ULL,
		0xA9BB4107F77888C8ULL,
		0x030132F1486AE049ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64C94363A23A39A8ULL,
		0x9CB4365D808E4DAEULL,
		0x5376820FEEF11191ULL,
		0x060265E290D5C093ULL
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
		0xC5E913744FAD3063ULL,
		0x2829981AA7E6DB2DULL,
		0xC785B0131D7629FBULL,
		0x07AD8DE875882713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E913744FAD3063ULL,
		0x2829981AA7E6DB2DULL,
		0xC785B0131D7629FBULL,
		0x07AD8DE875882713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BD226E89F5A60C6ULL,
		0x505330354FCDB65BULL,
		0x8F0B60263AEC53F6ULL,
		0x0F5B1BD0EB104E27ULL
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
		0xF507553DCB398173ULL,
		0xD9962B258F8EDD67ULL,
		0x13DF19C9843F06B8ULL,
		0x143B032CC557C346ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF507553DCB398173ULL,
		0xD9962B258F8EDD67ULL,
		0x13DF19C9843F06B8ULL,
		0x143B032CC557C346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA0EAA7B967302E6ULL,
		0xB32C564B1F1DBACFULL,
		0x27BE3393087E0D71ULL,
		0x287606598AAF868CULL
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
		0xFFE38A27CA19908FULL,
		0x2C33B4FA8C167EDEULL,
		0x71BDCD870E33DC73ULL,
		0x54A321A69B698C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFE38A27CA19908FULL,
		0x2C33B4FA8C167EDEULL,
		0x71BDCD870E33DC73ULL,
		0x54A321A69B698C81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFC7144F94332131ULL,
		0x586769F5182CFDBDULL,
		0xE37B9B0E1C67B8E6ULL,
		0x2946434D36D31902ULL
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
		0x538856A2363743EAULL,
		0xB0F2CCFD796C37B4ULL,
		0x41466E062F259E7CULL,
		0x5D91494E1AD5667FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538856A2363743EAULL,
		0xB0F2CCFD796C37B4ULL,
		0x41466E062F259E7CULL,
		0x5D91494E1AD5667FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA710AD446C6E87E7ULL,
		0x61E599FAF2D86F68ULL,
		0x828CDC0C5E4B3CF9ULL,
		0x3B22929C35AACCFEULL
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
		0x66540E66E651852FULL,
		0x3AA5FF33C8BA50B8ULL,
		0xF61847455CD1ED40ULL,
		0x107CEEEE7BC35B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66540E66E651852FULL,
		0x3AA5FF33C8BA50B8ULL,
		0xF61847455CD1ED40ULL,
		0x107CEEEE7BC35B91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCA81CCDCCA30A5EULL,
		0x754BFE679174A170ULL,
		0xEC308E8AB9A3DA80ULL,
		0x20F9DDDCF786B723ULL
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
		0xCF7C7F5735A351A9ULL,
		0xE2A4FACFB7C9CF7DULL,
		0x3B949B37DEC66CFAULL,
		0x6E265F6897A5475CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7C7F5735A351A9ULL,
		0xE2A4FACFB7C9CF7DULL,
		0x3B949B37DEC66CFAULL,
		0x6E265F6897A5475CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EF8FEAE6B46A365ULL,
		0xC549F59F6F939EFBULL,
		0x7729366FBD8CD9F5ULL,
		0x5C4CBED12F4A8EB8ULL
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
		0x3841F1061CEA5D70ULL,
		0x113DE21DCE0CF0A3ULL,
		0x6B81DA2CD5EE9C8CULL,
		0x63E1C39B3180DE8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3841F1061CEA5D70ULL,
		0x113DE21DCE0CF0A3ULL,
		0x6B81DA2CD5EE9C8CULL,
		0x63E1C39B3180DE8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7083E20C39D4BAF3ULL,
		0x227BC43B9C19E146ULL,
		0xD703B459ABDD3918ULL,
		0x47C387366301BD18ULL
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
		0xF484B297D34E0322ULL,
		0xEAE11E007803813DULL,
		0xD9D1ACC3F51CD4BAULL,
		0x5D713CE7AC9993E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF484B297D34E0322ULL,
		0xEAE11E007803813DULL,
		0xD9D1ACC3F51CD4BAULL,
		0x5D713CE7AC9993E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE909652FA69C0657ULL,
		0xD5C23C00F007027BULL,
		0xB3A35987EA39A975ULL,
		0x3AE279CF593327CDULL
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
		0x8B4BB30FE42B1C84ULL,
		0x64F78EC03F0D36D7ULL,
		0x4A41C958770B4635ULL,
		0x7D4F8E76C45B6460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4BB30FE42B1C84ULL,
		0x64F78EC03F0D36D7ULL,
		0x4A41C958770B4635ULL,
		0x7D4F8E76C45B6460ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1697661FC856391BULL,
		0xC9EF1D807E1A6DAFULL,
		0x948392B0EE168C6AULL,
		0x7A9F1CED88B6C8C0ULL
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
		0x98A4D6A846A036CAULL,
		0x21BEE521844DF832ULL,
		0x76363C1082AC8AC8ULL,
		0x5C322BB23B50DB51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A4D6A846A036CAULL,
		0x21BEE521844DF832ULL,
		0x76363C1082AC8AC8ULL,
		0x5C322BB23B50DB51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3149AD508D406DA7ULL,
		0x437DCA43089BF065ULL,
		0xEC6C782105591590ULL,
		0x3864576476A1B6A2ULL
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
		0x673423BE17E5A6CDULL,
		0x2A5512144C9507B4ULL,
		0xCA55659DFB39FE4EULL,
		0x486C7B2AF910C16EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x673423BE17E5A6CDULL,
		0x2A5512144C9507B4ULL,
		0xCA55659DFB39FE4EULL,
		0x486C7B2AF910C16EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE68477C2FCB4DADULL,
		0x54AA2428992A0F68ULL,
		0x94AACB3BF673FC9CULL,
		0x10D8F655F22182DDULL
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
		0x62CBF0CA1CD55861ULL,
		0x8267851CA0E0132EULL,
		0x209F34B1267D69E1ULL,
		0x651D78C1C1AA8B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62CBF0CA1CD55861ULL,
		0x8267851CA0E0132EULL,
		0x209F34B1267D69E1ULL,
		0x651D78C1C1AA8B15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC597E19439AAB0D5ULL,
		0x04CF0A3941C0265CULL,
		0x413E69624CFAD3C3ULL,
		0x4A3AF1838355162AULL
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
		0x4652ED0D1D3E9397ULL,
		0x410BAE0BE4440E93ULL,
		0x7526E75C4E62377BULL,
		0x7718C3F5149C5DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4652ED0D1D3E9397ULL,
		0x410BAE0BE4440E93ULL,
		0x7526E75C4E62377BULL,
		0x7718C3F5149C5DA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CA5DA1A3A7D2741ULL,
		0x82175C17C8881D26ULL,
		0xEA4DCEB89CC46EF6ULL,
		0x6E3187EA2938BB4AULL
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
		0x59A4B4D61E37635BULL,
		0xA03581B1E0218D4DULL,
		0x028808EF915A2698ULL,
		0x00E6F9571F7F0A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A4B4D61E37635BULL,
		0xA03581B1E0218D4DULL,
		0x028808EF915A2698ULL,
		0x00E6F9571F7F0A4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB34969AC3C6EC6B6ULL,
		0x406B0363C0431A9AULL,
		0x051011DF22B44D31ULL,
		0x01CDF2AE3EFE149CULL
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
		0xB21446FD4E79A81BULL,
		0x22AD472FB474B5CFULL,
		0x133FC960AE09E498ULL,
		0x685E079B07EE546AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB21446FD4E79A81BULL,
		0x22AD472FB474B5CFULL,
		0x133FC960AE09E498ULL,
		0x685E079B07EE546AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64288DFA9CF35049ULL,
		0x455A8E5F68E96B9FULL,
		0x267F92C15C13C930ULL,
		0x50BC0F360FDCA8D4ULL
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
		0x4F494D49DDEF0E8AULL,
		0x49C6E88921D85F19ULL,
		0xB5B325A8E65528E0ULL,
		0x3FD3DA54D1D21DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F494D49DDEF0E8AULL,
		0x49C6E88921D85F19ULL,
		0xB5B325A8E65528E0ULL,
		0x3FD3DA54D1D21DBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E929A93BBDE1D14ULL,
		0x938DD11243B0BE32ULL,
		0x6B664B51CCAA51C0ULL,
		0x7FA7B4A9A3A43B77ULL
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
		0x2AC3511B6576B24BULL,
		0xA75D01200B1A607BULL,
		0xDED6244EEF4248C6ULL,
		0x315AE6EF1EBBE047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AC3511B6576B24BULL,
		0xA75D01200B1A607BULL,
		0xDED6244EEF4248C6ULL,
		0x315AE6EF1EBBE047ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5586A236CAED6496ULL,
		0x4EBA02401634C0F6ULL,
		0xBDAC489DDE84918DULL,
		0x62B5CDDE3D77C08FULL
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
		0xEF13EC3F622B88DBULL,
		0x206040DD8025B93BULL,
		0x207BC0C1937D1CBDULL,
		0x474AB4188AE8FDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF13EC3F622B88DBULL,
		0x206040DD8025B93BULL,
		0x207BC0C1937D1CBDULL,
		0x474AB4188AE8FDF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE27D87EC45711C9ULL,
		0x40C081BB004B7277ULL,
		0x40F7818326FA397AULL,
		0x0E95683115D1FBEAULL
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
		0x5A3C91C0AEE5C90FULL,
		0xA2D1C55A1FC70729ULL,
		0x759E4E5B7F6D5EF5ULL,
		0x1EB48B038AE4F937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3C91C0AEE5C90FULL,
		0xA2D1C55A1FC70729ULL,
		0x759E4E5B7F6D5EF5ULL,
		0x1EB48B038AE4F937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB47923815DCB921EULL,
		0x45A38AB43F8E0E52ULL,
		0xEB3C9CB6FEDABDEBULL,
		0x3D69160715C9F26EULL
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
		0x5B3061C29409710EULL,
		0xED7F9491356ED869ULL,
		0xB9748F507C7026D3ULL,
		0x2F5F50B5AF0EF3E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B3061C29409710EULL,
		0xED7F9491356ED869ULL,
		0xB9748F507C7026D3ULL,
		0x2F5F50B5AF0EF3E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB660C3852812E21CULL,
		0xDAFF29226ADDB0D2ULL,
		0x72E91EA0F8E04DA7ULL,
		0x5EBEA16B5E1DE7D1ULL
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
		0x50194196EE036A3DULL,
		0x70FEAE7AC3E5369AULL,
		0xD8EF78C6070B6E33ULL,
		0x411DB8E9798D420DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50194196EE036A3DULL,
		0x70FEAE7AC3E5369AULL,
		0xD8EF78C6070B6E33ULL,
		0x411DB8E9798D420DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA032832DDC06D48DULL,
		0xE1FD5CF587CA6D34ULL,
		0xB1DEF18C0E16DC66ULL,
		0x023B71D2F31A841BULL
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
		0x8FA3FCDE7330FAC2ULL,
		0xB15616518D6BE5C3ULL,
		0xA2E4F242A24EF028ULL,
		0x44A01C6043E5BA9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FA3FCDE7330FAC2ULL,
		0xB15616518D6BE5C3ULL,
		0xA2E4F242A24EF028ULL,
		0x44A01C6043E5BA9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F47F9BCE661F597ULL,
		0x62AC2CA31AD7CB87ULL,
		0x45C9E485449DE051ULL,
		0x094038C087CB753DULL
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
		0x9F05120E843DFADDULL,
		0x5FE13A7D0173B373ULL,
		0x775D67F096F5A30AULL,
		0x7E8AF48581D41991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F05120E843DFADDULL,
		0x5FE13A7D0173B373ULL,
		0x775D67F096F5A30AULL,
		0x7E8AF48581D41991ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E0A241D087BF5CDULL,
		0xBFC274FA02E766E7ULL,
		0xEEBACFE12DEB4614ULL,
		0x7D15E90B03A83322ULL
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
		0xEFA366BE06EC6012ULL,
		0x2999FC225785F827ULL,
		0x1230D1B106303A1DULL,
		0x7946AD2A8E5EBA06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA366BE06EC6012ULL,
		0x2999FC225785F827ULL,
		0x1230D1B106303A1DULL,
		0x7946AD2A8E5EBA06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF46CD7C0DD8C037ULL,
		0x5333F844AF0BF04FULL,
		0x2461A3620C60743AULL,
		0x728D5A551CBD740CULL
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
		0xE7D516FE32EF8390ULL,
		0x84CD8BF6E547FD7CULL,
		0xBC89F4C962C31E65ULL,
		0x2C0BBC378BE734C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D516FE32EF8390ULL,
		0x84CD8BF6E547FD7CULL,
		0xBC89F4C962C31E65ULL,
		0x2C0BBC378BE734C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFAA2DFC65DF0720ULL,
		0x099B17EDCA8FFAF9ULL,
		0x7913E992C5863CCBULL,
		0x5817786F17CE6993ULL
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
		0x4C6518BD31782FDAULL,
		0x1FB18E2012D6C3F6ULL,
		0xC2B4E9060F4B7C55ULL,
		0x31589B01CFFF4DA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C6518BD31782FDAULL,
		0x1FB18E2012D6C3F6ULL,
		0xC2B4E9060F4B7C55ULL,
		0x31589B01CFFF4DA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98CA317A62F05FB4ULL,
		0x3F631C4025AD87ECULL,
		0x8569D20C1E96F8AAULL,
		0x62B136039FFE9B4FULL
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
		0xCE29C6BEFD3834A0ULL,
		0x2C4C86D93231801CULL,
		0x4B3ED95CFEB7A818ULL,
		0x47128238D7129680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE29C6BEFD3834A0ULL,
		0x2C4C86D93231801CULL,
		0x4B3ED95CFEB7A818ULL,
		0x47128238D7129680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C538D7DFA706953ULL,
		0x58990DB264630039ULL,
		0x967DB2B9FD6F5030ULL,
		0x0E250471AE252D00ULL
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
		0x6DE4E18D5C46BF0BULL,
		0xD468945A73CC7EB4ULL,
		0x51B73B97123EEA5CULL,
		0x59C91BAB785D30CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE4E18D5C46BF0BULL,
		0xD468945A73CC7EB4ULL,
		0x51B73B97123EEA5CULL,
		0x59C91BAB785D30CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBC9C31AB88D7E29ULL,
		0xA8D128B4E798FD68ULL,
		0xA36E772E247DD4B9ULL,
		0x33923756F0BA619CULL
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
		0x621965461EF17C33ULL,
		0x0B4DE977F08B808EULL,
		0x321922FE04CF1A63ULL,
		0x585BC56C0F7A2504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x621965461EF17C33ULL,
		0x0B4DE977F08B808EULL,
		0x321922FE04CF1A63ULL,
		0x585BC56C0F7A2504ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC432CA8C3DE2F879ULL,
		0x169BD2EFE117011CULL,
		0x643245FC099E34C6ULL,
		0x30B78AD81EF44A08ULL
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
		0xA922F2F2903098E0ULL,
		0xA286C1D722332187ULL,
		0xA54F3FEFE9B00FF7ULL,
		0x5A593621E0E22607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA922F2F2903098E0ULL,
		0xA286C1D722332187ULL,
		0xA54F3FEFE9B00FF7ULL,
		0x5A593621E0E22607ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5245E5E5206131D3ULL,
		0x450D83AE4466430FULL,
		0x4A9E7FDFD3601FEFULL,
		0x34B26C43C1C44C0FULL
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
		0xD6B051E0B05867F5ULL,
		0xD558900C2D2F8186ULL,
		0x9509287335590CE4ULL,
		0x0E63AB291A02AC74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B051E0B05867F5ULL,
		0xD558900C2D2F8186ULL,
		0x9509287335590CE4ULL,
		0x0E63AB291A02AC74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD60A3C160B0CFEAULL,
		0xAAB120185A5F030DULL,
		0x2A1250E66AB219C9ULL,
		0x1CC75652340558E9ULL
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
		0xC6030F738264D7E9ULL,
		0x8E925490D7798652ULL,
		0xC5BC54163DF68BF1ULL,
		0x2EA51D37E826CBA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6030F738264D7E9ULL,
		0x8E925490D7798652ULL,
		0xC5BC54163DF68BF1ULL,
		0x2EA51D37E826CBA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C061EE704C9AFD2ULL,
		0x1D24A921AEF30CA5ULL,
		0x8B78A82C7BED17E3ULL,
		0x5D4A3A6FD04D9743ULL
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
		0x00E29CE15CF1ECE7ULL,
		0xAF6EA7C72495FC09ULL,
		0x9A3BEBEBFFFB0398ULL,
		0x25A60E1B232D0D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E29CE15CF1ECE7ULL,
		0xAF6EA7C72495FC09ULL,
		0x9A3BEBEBFFFB0398ULL,
		0x25A60E1B232D0D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01C539C2B9E3D9CEULL,
		0x5EDD4F8E492BF812ULL,
		0x3477D7D7FFF60731ULL,
		0x4B4C1C36465A1A7BULL
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
		0x62B422EB01CAA1C2ULL,
		0xB555C7061BAB476AULL,
		0x443732585A064C4CULL,
		0x5769342CAAF15DFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B422EB01CAA1C2ULL,
		0xB555C7061BAB476AULL,
		0x443732585A064C4CULL,
		0x5769342CAAF15DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC56845D603954397ULL,
		0x6AAB8E0C37568ED4ULL,
		0x886E64B0B40C9899ULL,
		0x2ED2685955E2BBF4ULL
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
		0x656B8C6728794514ULL,
		0xC644F24F7A39EE3EULL,
		0x87CF68021BAECAF5ULL,
		0x3F921E1E9938C6DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x656B8C6728794514ULL,
		0xC644F24F7A39EE3EULL,
		0x87CF68021BAECAF5ULL,
		0x3F921E1E9938C6DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAD718CE50F28A28ULL,
		0x8C89E49EF473DC7CULL,
		0x0F9ED004375D95EBULL,
		0x7F243C3D32718DBBULL
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
		0x989425B7E759562AULL,
		0x0FB30465BB69A65CULL,
		0x9EE8CFD90587A426ULL,
		0x0D0A920BE12913BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x989425B7E759562AULL,
		0x0FB30465BB69A65CULL,
		0x9EE8CFD90587A426ULL,
		0x0D0A920BE12913BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31284B6FCEB2AC54ULL,
		0x1F6608CB76D34CB9ULL,
		0x3DD19FB20B0F484CULL,
		0x1A152417C2522775ULL
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
		0xA0F0FBFF7FD981B3ULL,
		0x7024DA078A3E8ECBULL,
		0xBDD6A81301807AA4ULL,
		0x184D3011036AF1E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F0FBFF7FD981B3ULL,
		0x7024DA078A3E8ECBULL,
		0xBDD6A81301807AA4ULL,
		0x184D3011036AF1E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41E1F7FEFFB30366ULL,
		0xE049B40F147D1D97ULL,
		0x7BAD50260300F548ULL,
		0x309A602206D5E3CFULL
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
		0x8B7E3856FD187C1BULL,
		0xA2408380BBDF1DB2ULL,
		0xEB7526904C566D56ULL,
		0x3404D4C336BFA12FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7E3856FD187C1BULL,
		0xA2408380BBDF1DB2ULL,
		0xEB7526904C566D56ULL,
		0x3404D4C336BFA12FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16FC70ADFA30F836ULL,
		0x4481070177BE3B65ULL,
		0xD6EA4D2098ACDAADULL,
		0x6809A9866D7F425FULL
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
		0x155FAE8980B3D45CULL,
		0xDF9F3B3381CF1586ULL,
		0xCE67702490BF8CF3ULL,
		0x1502DBFE09443D53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155FAE8980B3D45CULL,
		0xDF9F3B3381CF1586ULL,
		0xCE67702490BF8CF3ULL,
		0x1502DBFE09443D53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ABF5D130167A8B8ULL,
		0xBF3E7667039E2B0CULL,
		0x9CCEE049217F19E7ULL,
		0x2A05B7FC12887AA7ULL
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
		0x552ABA40FA460632ULL,
		0x43104DBF01599CD6ULL,
		0xE4EA4EDDA24834B2ULL,
		0x69B5E5097D2E131EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x552ABA40FA460632ULL,
		0x43104DBF01599CD6ULL,
		0xE4EA4EDDA24834B2ULL,
		0x69B5E5097D2E131EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA557481F48C0C77ULL,
		0x86209B7E02B339ACULL,
		0xC9D49DBB44906964ULL,
		0x536BCA12FA5C263DULL
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
		0x87AD82129A3C502AULL,
		0xF5BF62159D1A7612ULL,
		0xAEA7AB0982E687B0ULL,
		0x3FF2947576F05F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87AD82129A3C502AULL,
		0xF5BF62159D1A7612ULL,
		0xAEA7AB0982E687B0ULL,
		0x3FF2947576F05F14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F5B04253478A054ULL,
		0xEB7EC42B3A34EC25ULL,
		0x5D4F561305CD0F61ULL,
		0x7FE528EAEDE0BE29ULL
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
		0x7AEBD68DBEADE8EEULL,
		0x30A1465CCF60D63AULL,
		0x718123DB89EABC81ULL,
		0x49727B97E16DACA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AEBD68DBEADE8EEULL,
		0x30A1465CCF60D63AULL,
		0x718123DB89EABC81ULL,
		0x49727B97E16DACA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5D7AD1B7D5BD1EFULL,
		0x61428CB99EC1AC74ULL,
		0xE30247B713D57902ULL,
		0x12E4F72FC2DB5950ULL
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
		0x328AE1FEF011FFBCULL,
		0xD17F3FD6DD2513FAULL,
		0x4A328FE39EAED9E2ULL,
		0x723C2BDD2905C904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x328AE1FEF011FFBCULL,
		0xD17F3FD6DD2513FAULL,
		0x4A328FE39EAED9E2ULL,
		0x723C2BDD2905C904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6515C3FDE023FF8BULL,
		0xA2FE7FADBA4A27F4ULL,
		0x94651FC73D5DB3C5ULL,
		0x647857BA520B9208ULL
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
		0xBD499E7A0A1CC5AAULL,
		0xBF7D807ED8C2ECAEULL,
		0x7235164D65E1B9E1ULL,
		0x4C1FD02BFA0EE769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD499E7A0A1CC5AAULL,
		0xBF7D807ED8C2ECAEULL,
		0x7235164D65E1B9E1ULL,
		0x4C1FD02BFA0EE769ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A933CF414398B67ULL,
		0x7EFB00FDB185D95DULL,
		0xE46A2C9ACBC373C3ULL,
		0x183FA057F41DCED2ULL
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
		0xAB4F0E37F149A1E3ULL,
		0xFC24876712A32C20ULL,
		0xE6710AA08A4887CBULL,
		0x12CC9342187E7646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB4F0E37F149A1E3ULL,
		0xFC24876712A32C20ULL,
		0xE6710AA08A4887CBULL,
		0x12CC9342187E7646ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x569E1C6FE29343C6ULL,
		0xF8490ECE25465841ULL,
		0xCCE2154114910F97ULL,
		0x2599268430FCEC8DULL
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
		0xF7976EFEC7425407ULL,
		0x81F3BF1C88BAF68EULL,
		0xB8505A36E6E58511ULL,
		0x16C8C7DE8B7A075DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7976EFEC7425407ULL,
		0x81F3BF1C88BAF68EULL,
		0xB8505A36E6E58511ULL,
		0x16C8C7DE8B7A075DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF2EDDFD8E84A80EULL,
		0x03E77E391175ED1DULL,
		0x70A0B46DCDCB0A23ULL,
		0x2D918FBD16F40EBBULL
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
		0x1E5E94BD54F25E2DULL,
		0x5918E82574D1C0B5ULL,
		0x6B7FA4C732A5C00AULL,
		0x35999CC4F27F1C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5E94BD54F25E2DULL,
		0x5918E82574D1C0B5ULL,
		0x6B7FA4C732A5C00AULL,
		0x35999CC4F27F1C99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CBD297AA9E4BC5AULL,
		0xB231D04AE9A3816AULL,
		0xD6FF498E654B8014ULL,
		0x6B333989E4FE3932ULL
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
		0x9C1FBE887CA4185BULL,
		0x5A1B32ECBE96D14EULL,
		0xE300773B56BCFCEAULL,
		0x13C394FCA9268A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C1FBE887CA4185BULL,
		0x5A1B32ECBE96D14EULL,
		0xE300773B56BCFCEAULL,
		0x13C394FCA9268A44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x383F7D10F94830B6ULL,
		0xB43665D97D2DA29DULL,
		0xC600EE76AD79F9D4ULL,
		0x278729F9524D1489ULL
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
		0xF3DD9E4540033893ULL,
		0x9EE37B475B761AACULL,
		0xFD3F0E1E146088A2ULL,
		0x704536B4342001D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3DD9E4540033893ULL,
		0x9EE37B475B761AACULL,
		0xFD3F0E1E146088A2ULL,
		0x704536B4342001D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7BB3C8A80067139ULL,
		0x3DC6F68EB6EC3559ULL,
		0xFA7E1C3C28C11145ULL,
		0x608A6D68684003ABULL
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
		0x8919A3A159280302ULL,
		0xF9E0FCA6993ED4F0ULL,
		0x76583FEB7B4B02E2ULL,
		0x670BD168913C8CD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8919A3A159280302ULL,
		0xF9E0FCA6993ED4F0ULL,
		0x76583FEB7B4B02E2ULL,
		0x670BD168913C8CD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12334742B2500617ULL,
		0xF3C1F94D327DA9E1ULL,
		0xECB07FD6F69605C5ULL,
		0x4E17A2D1227919A0ULL
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
		0x1726D301D649F93DULL,
		0x35011EB78F23B253ULL,
		0xAB51A07AF82A6194ULL,
		0x3B02A31D9D9777B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1726D301D649F93DULL,
		0x35011EB78F23B253ULL,
		0xAB51A07AF82A6194ULL,
		0x3B02A31D9D9777B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E4DA603AC93F27AULL,
		0x6A023D6F1E4764A6ULL,
		0x56A340F5F054C328ULL,
		0x7605463B3B2EEF71ULL
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
		0x33C5C5E68E943A76ULL,
		0xFD68812D7677F0EFULL,
		0xF4FD93497AA118F5ULL,
		0x17C8718FD877DBC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C5C5E68E943A76ULL,
		0xFD68812D7677F0EFULL,
		0xF4FD93497AA118F5ULL,
		0x17C8718FD877DBC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x678B8BCD1D2874ECULL,
		0xFAD1025AECEFE1DEULL,
		0xE9FB2692F54231EBULL,
		0x2F90E31FB0EFB781ULL
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
		0x0C0F56BB0AADD67DULL,
		0x0DB4E254432120C6ULL,
		0xC256F10F7E7160EBULL,
		0x797A66467604AAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0F56BB0AADD67DULL,
		0x0DB4E254432120C6ULL,
		0xC256F10F7E7160EBULL,
		0x797A66467604AAEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x181EAD76155BAD0DULL,
		0x1B69C4A88642418CULL,
		0x84ADE21EFCE2C1D6ULL,
		0x72F4CC8CEC0955D5ULL
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
		0x14BCBD789A4FB7D9ULL,
		0x3E889F66694F7140ULL,
		0x8A89C484D245AADDULL,
		0x1EACE9E0DC9F4F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BCBD789A4FB7D9ULL,
		0x3E889F66694F7140ULL,
		0x8A89C484D245AADDULL,
		0x1EACE9E0DC9F4F15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29797AF1349F6FB2ULL,
		0x7D113ECCD29EE280ULL,
		0x15138909A48B55BAULL,
		0x3D59D3C1B93E9E2BULL
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
		0xA821ABCFE39450F2ULL,
		0xFF3D12A0F1D4EED7ULL,
		0x651BD04822D2ABF7ULL,
		0x37A9CA78D2539A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA821ABCFE39450F2ULL,
		0xFF3D12A0F1D4EED7ULL,
		0x651BD04822D2ABF7ULL,
		0x37A9CA78D2539A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5043579FC728A1E4ULL,
		0xFE7A2541E3A9DDAFULL,
		0xCA37A09045A557EFULL,
		0x6F5394F1A4A7351EULL
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
		0xD7B861CCD8C5282BULL,
		0x6644E2E286DA53B4ULL,
		0x89AECA40BC499856ULL,
		0x413572CF2CB4607BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B861CCD8C5282BULL,
		0x6644E2E286DA53B4ULL,
		0x89AECA40BC499856ULL,
		0x413572CF2CB4607BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF70C399B18A5069ULL,
		0xCC89C5C50DB4A769ULL,
		0x135D9481789330ACULL,
		0x026AE59E5968C0F7ULL
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
		0x9A249F6383683FA5ULL,
		0x37C11195AB068E21ULL,
		0x185023C10F612770ULL,
		0x6B2F5CB5E8B90605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A249F6383683FA5ULL,
		0x37C11195AB068E21ULL,
		0x185023C10F612770ULL,
		0x6B2F5CB5E8B90605ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34493EC706D07F5DULL,
		0x6F82232B560D1C43ULL,
		0x30A047821EC24EE0ULL,
		0x565EB96BD1720C0AULL
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
		0x007F713E981E738AULL,
		0xAB77802EBA8D21E5ULL,
		0x1C66EB7E78FA9A4BULL,
		0x7F247228030B2705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007F713E981E738AULL,
		0xAB77802EBA8D21E5ULL,
		0x1C66EB7E78FA9A4BULL,
		0x7F247228030B2705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00FEE27D303CE727ULL,
		0x56EF005D751A43CAULL,
		0x38CDD6FCF1F53497ULL,
		0x7E48E45006164E0AULL
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
		0x5870CE964A10E434ULL,
		0x239122198F858A34ULL,
		0x78F146CFA553253BULL,
		0x5C98307B0A48757EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5870CE964A10E434ULL,
		0x239122198F858A34ULL,
		0x78F146CFA553253BULL,
		0x5C98307B0A48757EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E19D2C9421C87BULL,
		0x472244331F0B1468ULL,
		0xF1E28D9F4AA64A76ULL,
		0x393060F61490EAFCULL
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