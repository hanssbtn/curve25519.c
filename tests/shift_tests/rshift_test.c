#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F383D44F5FF3F20ULL,
		0xBB16A5FE483A7A1FULL,
		0xF6428977139AD3C9ULL,
		0x04C250552373CDD2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCFC800000000000ULL,
		0xE9E87C7CE0F513D7ULL,
		0x6B4F26EC5A97F920ULL,
		0xCF374BD90A25DC4EULL,
		0x000000130941548DULL
	}};
	int shift = 22;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FE48D93BE062081ULL,
		0xA062D4F543B13255ULL,
		0x533EAA8C258B7BBEULL,
		0xAB4085B4CB1E9DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2081000000000000ULL,
		0x32552FE48D93BE06ULL,
		0x7BBEA062D4F543B1ULL,
		0x9DE5533EAA8C258BULL,
		0x0000AB4085B4CB1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5FB4B88713E6405ULL,
		0xB5F7A6A1401BE7B8ULL,
		0xBC4AA06E7BE47109ULL,
		0x9F79710271A17CE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB4B88713E6405000ULL,
		0x7A6A1401BE7B8B5FULL,
		0xAA06E7BE47109B5FULL,
		0x9710271A17CE3BC4ULL,
		0x00000000000009F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D05BDFE0A56B241ULL,
		0x9E6FD43A298F2910ULL,
		0x4CD4964462AEA605ULL,
		0x59B0C8460E87CF7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x03A0B7BFC14AD648ULL,
		0xB3CDFA874531E522ULL,
		0x899A92C88C55D4C0ULL,
		0x0B361908C1D0F9EFULL
	}};
	shift = 3;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF28AE5F7F52332E5ULL,
		0xCE4048D25F59A000ULL,
		0x2FAB32284FBBD8FDULL,
		0x6F38D15387FDBD70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F52332E50000000ULL,
		0x25F59A000F28AE5FULL,
		0x84FBBD8FDCE4048DULL,
		0x387FDBD702FAB322ULL,
		0x0000000006F38D15ULL
	}};
	shift = 36;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BF682AD3CFC145EULL,
		0x0A7BC0CE815C6272ULL,
		0xCD913CD222316B12ULL,
		0x3FDCA4799E30CC9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x828BC00000000000ULL,
		0x8C4E4D7ED055A79FULL,
		0x2D62414F7819D02BULL,
		0x1993D9B2279A4446ULL,
		0x000007FB948F33C6ULL
	}};
	shift = 19;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x310D3DABB03E1D20ULL,
		0x43A2800A26E3A2A6ULL,
		0x485C692485E4ABD1ULL,
		0x03861548A9CD2B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DABB03E1D200000ULL,
		0x800A26E3A2A6310DULL,
		0x692485E4ABD143A2ULL,
		0x1548A9CD2B15485CULL,
		0x0000000000000386ULL
	}};
	shift = 48;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CE18B69ACA37CF2ULL,
		0x9455583F11E2E728ULL,
		0x544261A8DC822B4EULL,
		0x8A1DAEB2715B33DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD35946F9E4000000ULL,
		0x7E23C5CE5099C316ULL,
		0x51B904569D28AAB0ULL,
		0x64E2B667B8A884C3ULL,
		0x0000000001143B5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32BED8A3F7AC9EAFULL,
		0x616E7BF1A6CEF758ULL,
		0x3776B828829C914DULL,
		0x69777F2503F020CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFB628FDEB27ABC00ULL,
		0xB9EFC69B3BDD60CAULL,
		0xDAE0A20A72453585ULL,
		0xDDFC940FC08328DDULL,
		0x00000000000001A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2AEFE3F304042F2ULL,
		0x73290E3C3A9C952DULL,
		0x8F3DD41D725EDB16ULL,
		0x0F8071CF4F170E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF982021790000000ULL,
		0xE1D4E4A96E9577F1ULL,
		0xEB92F6D8B3994871ULL,
		0x7A78B8734C79EEA0ULL,
		0x00000000007C038EULL
	}};
	shift = 37;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x10FD7EBF8B537C74ULL,
		0xFAB036B63D2262EFULL,
		0x31ECF5096DDF037CULL,
		0xCF71A4FF2146A20DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE3A000000000000ULL,
		0x3177887EBF5FC5A9ULL,
		0x81BE7D581B5B1E91ULL,
		0x510698F67A84B6EFULL,
		0x000067B8D27F90A3ULL
	}};
	shift = 17;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF751CE504609D14ULL,
		0x60D0BDBED464524AULL,
		0x3ACF015EEEB5AFCAULL,
		0x8C345C04316D6ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E7282304E8A000ULL,
		0x85EDF6A32292557BULL,
		0x780AF775AD7E5306ULL,
		0xA2E0218B6B7651D6ULL,
		0x0000000000000461ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31711957AB858390ULL,
		0x3276D5D3C40DEEE6ULL,
		0x5C866AA39127E991ULL,
		0x3039FD4B7320604DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xCC62E232AF570B07ULL,
		0x2264EDABA7881BDDULL,
		0x9AB90CD547224FD3ULL,
		0x006073FA96E640C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF12902CD72E07A0AULL,
		0x5292F24240D2C6C1ULL,
		0xE090F5B24DFC0B7FULL,
		0x58E88DBD8BB65D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9AE5C0F414000000ULL,
		0x8481A58D83E25205ULL,
		0x649BF816FEA525E4ULL,
		0x7B176CBA49C121EBULL,
		0x0000000000B1D11BULL
	}};
	shift = 39;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3CF3F3E4674189CULL,
		0x2982B294C45F1612ULL,
		0xDC533A3BB71189A2ULL,
		0xD3C295309F7A8223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189C000000000000ULL,
		0x1612C3CF3F3E4674ULL,
		0x89A22982B294C45FULL,
		0x8223DC533A3BB711ULL,
		0x0000D3C295309F7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9EBC2E6270B155DULL,
		0xE5713B3D03605440ULL,
		0xC93AA706B25B3945ULL,
		0x5B4021B6433A1AA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE17313858AAE8000ULL,
		0x9D9E81B02A205CF5ULL,
		0x5383592D9CA2F2B8ULL,
		0x10DB219D0D50649DULL,
		0x0000000000002DA0ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6A5D38EBAF8E72FULL,
		0x01D6B9ECF8042242ULL,
		0x24E2DB595C61CCCEULL,
		0xBE7DA5EBD90B46B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39CBC00000000000ULL,
		0x0890B1A974E3AEBEULL,
		0x73338075AE7B3E01ULL,
		0xD1ACC938B6D65718ULL,
		0x00002F9F697AF642ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66242630F3BB149FULL,
		0x5844320FE1312396ULL,
		0xC27F86CAB46A537AULL,
		0x0BC22EFC2DFC1DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xCCC484C61E776293ULL,
		0x4B088641FC262472ULL,
		0x984FF0D9568D4A6FULL,
		0x017845DF85BF83B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC57117EB071A9DF2ULL,
		0xB59A6AFFD7891756ULL,
		0x37B50B690DC76CE1ULL,
		0x57724E57643B44D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xD8AE22FD60E353BEULL,
		0x36B34D5FFAF122EAULL,
		0x06F6A16D21B8ED9CULL,
		0x0AEE49CAEC87689AULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E56D80CEC134540ULL,
		0x9404EAD571D075A9ULL,
		0xB20824874EB850CFULL,
		0x16C738CD4F9E70B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80CEC1345400000ULL,
		0xEAD571D075A99E56ULL,
		0x24874EB850CF9404ULL,
		0x38CD4F9E70B7B208ULL,
		0x00000000000016C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x038EA6E7096ABE3DULL,
		0x63691D5625A8C12BULL,
		0x71670D7468FACB17ULL,
		0x385801B2F6F4B048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6ABE3D0000000000ULL,
		0xA8C12B038EA6E709ULL,
		0xFACB1763691D5625ULL,
		0xF4B04871670D7468ULL,
		0x000000385801B2F6ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x608A76A28501FF20ULL,
		0xC90B636B8CD384B6ULL,
		0x533CDECA1F83ECD7ULL,
		0xD20E25D41177C256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB514280FF9000000ULL,
		0x1B5C669C25B30453ULL,
		0xF650FC1F66BE485BULL,
		0x2EA08BBE12B299E6ULL,
		0x0000000000069071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68DDCC22BB0C427AULL,
		0x2A290A316B986EE4ULL,
		0x4BC227F5205812E1ULL,
		0xCCCFCA529D06162AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9845761884F4000ULL,
		0x21462D730DDC8D1BULL,
		0x44FEA40B025C2545ULL,
		0xF94A53A0C2C54978ULL,
		0x0000000000001999ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD3CAAB5D3A47E68ULL,
		0x9BE172570FF83C89ULL,
		0xF23DB83D3632A380ULL,
		0x16178A86A4E1C6FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E91F9A00000000ULL,
		0xC3FE0F22734F2AADULL,
		0x4D8CA8E026F85C95ULL,
		0xA93871BEFC8F6E0FULL,
		0x000000000585E2A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD06A824A3A6D56B7ULL,
		0xDEF09D662B791192ULL,
		0xCC5FA63513B964FBULL,
		0x89F72DC3F865904CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DAAD6E000000000ULL,
		0x6F22325A0D504947ULL,
		0x772C9F7BDE13ACC5ULL,
		0x0CB209998BF4C6A2ULL,
		0x000000113EE5B87FULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x856F08D2B69CE3F4ULL,
		0x02D08F135CDB3929ULL,
		0x289E6DBC616B3832ULL,
		0xF50A3E0B5A393E4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x30ADE11A56D39C7EULL,
		0x405A11E26B9B6725ULL,
		0xA513CDB78C2D6706ULL,
		0x1EA147C16B4727C9ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9F0449814C18AC6ULL,
		0x323425B913601D29ULL,
		0x1B36C8F73E48F456ULL,
		0x456DACBFE0E8ADC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x58C0000000000000ULL,
		0xA5373E0893029831ULL,
		0x8AC64684B7226C03ULL,
		0xB80366D91EE7C91EULL,
		0x0008ADB597FC1D15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1AAC0ACC290FCCAAULL,
		0x803688D847715E30ULL,
		0x1C13695A0E8B65BBULL,
		0x0BB04A57FC65FC2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x80D5605661487E65ULL,
		0xDC01B446C23B8AF1ULL,
		0x50E09B4AD0745B2DULL,
		0x005D8252BFE32FE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CDDB15217CEAC18ULL,
		0x37592511EA0A67E6ULL,
		0x618761883F4E406DULL,
		0xD49672E50D882A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDB15217CEAC1800ULL,
		0x592511EA0A67E67CULL,
		0x8761883F4E406D37ULL,
		0x9672E50D882A2961ULL,
		0x00000000000000D4ULL
	}};
	shift = 56;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66996FE610158DCCULL,
		0x0120C5D7DF48F008ULL,
		0xBCAFAB83E79B58B2ULL,
		0x2C9BEC5F67076FF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4056373000000000ULL,
		0x7D23C0219A65BF98ULL,
		0x9E6D62C80483175FULL,
		0x9C1DBFE6F2BEAE0FULL,
		0x00000000B26FB17DULL
	}};
	shift = 30;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x166FA7C9FC18D75EULL,
		0xB6F4F45DDFFA5229ULL,
		0xACC83AB0197F7340ULL,
		0x648C5B19D0976B2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC00000000000000ULL,
		0x522CDF4F93F831AEULL,
		0x816DE9E8BBBFF4A4ULL,
		0x5B5990756032FEE6ULL,
		0x00C918B633A12ED6ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4729C3769CC15B7ULL,
		0x35433A44A7B8FC0DULL,
		0x79277CBD6041FC09ULL,
		0x684BCE8D9E6D75B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x29C3769CC15B7000ULL,
		0x33A44A7B8FC0DD47ULL,
		0x77CBD6041FC09354ULL,
		0xBCE8D9E6D75B8792ULL,
		0x0000000000000684ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9827634F7F3672CEULL,
		0x48AB0292B58DE197ULL,
		0x3E277512A184F7CEULL,
		0x7757D525557574B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B39670000000000ULL,
		0xC6F0CBCC13B1A7BFULL,
		0xC27BE7245581495AULL,
		0xBABA5C1F13BA8950ULL,
		0x0000003BABEA92AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0F4DD38A34DD13DULL,
		0x783ECBE5C2BDD47DULL,
		0xF048A03B4CB0A754ULL,
		0xEB6ED444EC739E25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA71469BA27A000ULL,
		0xD97CB857BA8FB41EULL,
		0x1407699614EA8F07ULL,
		0xDA889D8E73C4BE09ULL,
		0x0000000000001D6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14323A7F0C575356ULL,
		0xDEC2EE12176E79CEULL,
		0x613A8C0C6B466E75ULL,
		0x4566B36AC718F7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6AC0000000000000ULL,
		0x39C286474FE18AEAULL,
		0xCEBBD85DC242EDCFULL,
		0xFC8C2751818D68CDULL,
		0x0008ACD66D58E31EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16DB9D76A43FEE62ULL,
		0xF1A18BD6C9F9C2CDULL,
		0x63CC1965F6463690ULL,
		0xC92D86ACA6C5163EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB98800000000000ULL,
		0x70B345B6E75DA90FULL,
		0x8DA43C6862F5B27EULL,
		0x458F98F306597D91ULL,
		0x0000324B61AB29B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80E3611A5B80E633ULL,
		0x0B41F67DA9D8973DULL,
		0x59A81B3B90BF0EDDULL,
		0xA0A0194845678DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A5B80E633000000ULL,
		0x7DA9D8973D80E361ULL,
		0x3B90BF0EDD0B41F6ULL,
		0x4845678DCD59A81BULL,
		0x0000000000A0A019ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x653EDEFB26E73FA0ULL,
		0xDEAC532F11FD3730ULL,
		0xAB9F2E62C743F25EULL,
		0xA8B158C73B23536FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA7DBDF64DCE7F40ULL,
		0xBD58A65E23FA6E60ULL,
		0x573E5CC58E87E4BDULL,
		0x5162B18E7646A6DFULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9490F3E1C313DB13ULL,
		0xF441A9E011C0D1DDULL,
		0xE03B752ADCBA4548ULL,
		0x6A260965650F4CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6C4C00000000000ULL,
		0x347765243CF870C4ULL,
		0x91523D106A780470ULL,
		0xD337B80EDD4AB72EULL,
		0x00001A8982595943ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5F99A5643BB7779ULL,
		0x61044B6C8C84071FULL,
		0x973C1BC0D32CE97CULL,
		0x579A43EE9135967AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EEF200000000000ULL,
		0x80E3FCBF334AC877ULL,
		0x9D2F8C20896D9190ULL,
		0xB2CF52E783781A65ULL,
		0x00000AF3487DD226ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE604A160C503DA1ULL,
		0x1F59E8D20E4541DDULL,
		0x97D5AD0215E6CEA2ULL,
		0xAB3720001BFEA9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x160C503DA1000000ULL,
		0xD20E4541DDDE604AULL,
		0x0215E6CEA21F59E8ULL,
		0x001BFEA9AF97D5ADULL,
		0x0000000000AB3720ULL
	}};
	shift = 40;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44D69C882D1B7DB9ULL,
		0xF53328F3CF0AE07DULL,
		0xB072029CF0EDD109ULL,
		0x2550FA7DF7CAD1A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xA26B4E44168DBEDCULL,
		0xFA999479E785703EULL,
		0xD839014E7876E884ULL,
		0x12A87D3EFBE568D1ULL
	}};
	shift = 1;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE254F59281188680ULL,
		0xC2A165089D0DA940ULL,
		0x61E717D4A678B2DBULL,
		0xED3276E11682AE18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0x940E254F59281188ULL,
		0x2DBC2A165089D0DAULL,
		0xE1861E717D4A678BULL,
		0x000ED3276E11682AULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6262420D50ACF7CULL,
		0x5733CE75E2A5C589ULL,
		0x7E6E7B9A00BA47EDULL,
		0x50B57D4DEA5A033FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2420D50ACF7C0000ULL,
		0xCE75E2A5C589D626ULL,
		0x7B9A00BA47ED5733ULL,
		0x7D4DEA5A033F7E6EULL,
		0x00000000000050B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD231B99393E84CDULL,
		0x5490C6E660C11527ULL,
		0x5E03B058B6E87608ULL,
		0x9895C5AE0C23661BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99393E84CD000000ULL,
		0xE660C11527DD231BULL,
		0x58B6E876085490C6ULL,
		0xAE0C23661B5E03B0ULL,
		0x00000000009895C5ULL
	}};
	shift = 40;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6201BC16B45A0D53ULL,
		0x5AC55B52B8A0D3BEULL,
		0x969CA9297A69C939ULL,
		0xB259A477AE0ED9BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x82D68B41AA600000ULL,
		0x6A57141A77CC4037ULL,
		0x252F4D39272B58ABULL,
		0x8EF5C1DB37F2D395ULL,
		0x0000000000164B34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07C8794145DACB33ULL,
		0xA22013D82401FCB8ULL,
		0xF3603749FEC3FD94ULL,
		0x8BE22EDC08AE0C05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF21E505176B2CCC0ULL,
		0x8804F609007F2E01ULL,
		0xD80DD27FB0FF6528ULL,
		0xF88BB7022B83017CULL,
		0x0000000000000022ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE94D5FD9E6EA8B6BULL,
		0x3A1AFE829A8876D8ULL,
		0xD005DFDEC658A0D3ULL,
		0xABBA111D5E68E7B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x94D5FD9E6EA8B6B0ULL,
		0xA1AFE829A8876D8EULL,
		0x005DFDEC658A0D33ULL,
		0xBBA111D5E68E7B2DULL,
		0x000000000000000AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC394D1EF647F6D6ULL,
		0x47B949B99B786849ULL,
		0x11A0E136CA902185ULL,
		0xCBCC9998C55E7127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6D60000000000000ULL,
		0x849CC394D1EF647FULL,
		0x18547B949B99B786ULL,
		0x12711A0E136CA902ULL,
		0x000CBCC9998C55E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F19E897F5667FC5ULL,
		0x1669C52E4EFD0610ULL,
		0xF169C6A14A939103ULL,
		0xDEA8A4C71FDF8369ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF19E897F5667FC50ULL,
		0x669C52E4EFD06103ULL,
		0x169C6A14A9391031ULL,
		0xEA8A4C71FDF8369FULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF4BC351F21D3A0F1ULL,
		0x7352969173175EA3ULL,
		0x2F39984EE2703606ULL,
		0x5B0ADBDAB1D71A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF90E9D0788000000ULL,
		0x8B98BAF51FA5E1A8ULL,
		0x771381B0339A94B4ULL,
		0xD58EB8D40179CCC2ULL,
		0x0000000002D856DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 229;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB0A4BED653149F24ULL,
		0xB4DCD01F4CFA65A9ULL,
		0x70238107EB2270F7ULL,
		0x5E2986B2AFC09C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B298A4F9200000ULL,
		0x80FA67D32D4D8525ULL,
		0x083F591387BDA6E6ULL,
		0x35957E04E17B811CULL,
		0x000000000002F14CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08F53EC1EEBC72F5ULL,
		0xC882B6C26A516D9BULL,
		0x869864E41D05038DULL,
		0xE6E6609C65D047DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83DD78E5EA000000ULL,
		0x84D4A2DB3611EA7DULL,
		0xC83A0A071B91056DULL,
		0x38CBA08FB50D30C9ULL,
		0x0000000001CDCCC1ULL
	}};
	shift = 39;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9B1D853019132B0ULL,
		0x0934DF151A8D7CCCULL,
		0xD58B04A31DD4F823ULL,
		0xB93CBA1ED3F68E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC00000000000000ULL,
		0x333E6C7614C0644CULL,
		0x08C24D37C546A35FULL,
		0x907562C128C7753EULL,
		0x002E4F2E87B4FDA3ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE21833BE13042A0CULL,
		0x864691A29606A2B9ULL,
		0x0EC68646A10D8A50ULL,
		0x93009A9CD30A0B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0677C26085418000ULL,
		0xD23452C0D4573C43ULL,
		0xD0C8D421B14A10C8ULL,
		0x13539A614162C1D8ULL,
		0x0000000000001260ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41C4558F682B0293ULL,
		0x63FE4001DD6E4362ULL,
		0x17ECEB9E5AA6428DULL,
		0x26475E3A0F332159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8388AB1ED0560526ULL,
		0xC7FC8003BADC86C4ULL,
		0x2FD9D73CB54C851AULL,
		0x4C8EBC741E6642B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D138D38E093249BULL,
		0x58A333A3A74ECB95ULL,
		0xADD26A175039A765ULL,
		0xAEC8FBE9BD023E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x24D8000000000000ULL,
		0x5CAA689C69C70499ULL,
		0x3B2AC5199D1D3A76ULL,
		0xF1756E9350BA81CDULL,
		0x00057647DF4DE811ULL
	}};
	shift = 13;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BCDC7B85C90CC8BULL,
		0x06A8E2BC80371E19ULL,
		0xC0E7BE5D1DB69C05ULL,
		0xCF3B9B2262ED57E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0x92BCDC7B85C90CC8ULL,
		0x506A8E2BC80371E1ULL,
		0x5C0E7BE5D1DB69C0ULL,
		0x0CF3B9B2262ED57EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9EC8E0D4C8B8F111ULL,
		0x5C6CE7662F8B9CA6ULL,
		0xAFCADBA7B24403E5ULL,
		0xC110312509749E17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E0D4C8B8F111000ULL,
		0xCE7662F8B9CA69ECULL,
		0xADBA7B24403E55C6ULL,
		0x0312509749E17AFCULL,
		0x0000000000000C11ULL
	}};
	shift = 52;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDED80A96D2545439ULL,
		0x5551CCDB1940580CULL,
		0xD227951A5933AC71ULL,
		0xD6CB2E3090D9E621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x9BDB0152DA4A8A87ULL,
		0x2AAA399B63280B01ULL,
		0x3A44F2A34B26758EULL,
		0x1AD965C6121B3CC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEEED99AB1AB4CA1DULL,
		0x3E000278AE3BE0BEULL,
		0xCFC408C94B080BC3ULL,
		0x97318D6D065D323CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2874000000000000ULL,
		0x82FBBBB666AC6AD3ULL,
		0x2F0CF80009E2B8EFULL,
		0xC8F33F1023252C20ULL,
		0x00025CC635B41974ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE281E7AE2DDA63D3ULL,
		0x1AD0D84A4D1935ACULL,
		0x471F490636F9105CULL,
		0xE0BB7F9F6018DEC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2DDA63D30000000ULL,
		0xA4D1935ACE281E7AULL,
		0x636F9105C1AD0D84ULL,
		0xF6018DEC9471F490ULL,
		0x000000000E0BB7F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x35B0EF8B3A15E38BULL,
		0xD0489177319B4B8BULL,
		0x1EDBAD2670250BE1ULL,
		0xD58EAC29CB32E67AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3BE2CE8578E2C00ULL,
		0x2245DCC66D2E2CD6ULL,
		0x6EB499C0942F8741ULL,
		0x3AB0A72CCB99E87BULL,
		0x0000000000000356ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5EE02A21C2E1576DULL,
		0xECFC9E3A183A823FULL,
		0xAB29FE50E9B12BA5ULL,
		0xC6C9EE55266FB5C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1C2E1576D0000000ULL,
		0xA183A823F5EE02A2ULL,
		0x0E9B12BA5ECFC9E3ULL,
		0x5266FB5C5AB29FE5ULL,
		0x000000000C6C9EE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE4102CB9480DC02CULL,
		0x33C12948E9404782ULL,
		0x151F56F10EE3C0D9ULL,
		0xB309C9E73D8F9BDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65CA406E01600000ULL,
		0x4A474A023C172081ULL,
		0xB788771E06C99E09ULL,
		0x4F39EC7CDEF0A8FAULL,
		0x000000000005984EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0690D6B01DD00B5CULL,
		0xB23546FBD734862DULL,
		0x09743D7C37D2A98FULL,
		0x581E6377D886F42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D6B01DD00B5C00ULL,
		0x3546FBD734862D06ULL,
		0x743D7C37D2A98FB2ULL,
		0x1E6377D886F42F09ULL,
		0x0000000000000058ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62106A3BECBC6647ULL,
		0xB0C708D8FEB380CBULL,
		0x36FA81E0595957A6ULL,
		0x305D982236B7320EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0xB62106A3BECBC664ULL,
		0x6B0C708D8FEB380CULL,
		0xE36FA81E0595957AULL,
		0x0305D982236B7320ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31F5246A7D47E43FULL,
		0x7C42E380D517B1B2ULL,
		0x74902EC7497AB5E6ULL,
		0x1F3A7B0858B67BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5246A7D47E43F0ULL,
		0xC42E380D517B1B23ULL,
		0x4902EC7497AB5E67ULL,
		0xF3A7B0858B67BAD7ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BC35E0F1684E54DULL,
		0xAAA8327E0599B05AULL,
		0x54F061F5F32D629EULL,
		0x10B12FBD91629374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0F1684E54D00000ULL,
		0x27E0599B05A1BC35ULL,
		0x1F5F32D629EAAA83ULL,
		0xFBD9162937454F06ULL,
		0x0000000000010B12ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9F38DB0B8D770052ULL,
		0x0508EB4A309C12DDULL,
		0x018547E793678054ULL,
		0x2F5D1CE35DB9AC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB6171AEE00A40000ULL,
		0xD694613825BB3E71ULL,
		0x8FCF26CF00A80A11ULL,
		0x39C6BB73589C030AULL,
		0x0000000000005EBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0066275C7EFAA34CULL,
		0xC518BBE292F99F15ULL,
		0xBB18F06D6DBAC09DULL,
		0xB6114C5761CAE5C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1989D71FBEA8D300ULL,
		0x462EF8A4BE67C540ULL,
		0xC63C1B5B6EB02771ULL,
		0x845315D872B970EEULL,
		0x000000000000002DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AD5EDD3E067BEFAULL,
		0x18AB625B8C2CB99FULL,
		0xAEBE7C06117F3B3AULL,
		0x94BA72FEB034ED79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BEFA00000000000ULL,
		0xCB99F3AD5EDD3E06ULL,
		0xF3B3A18AB625B8C2ULL,
		0x4ED79AEBE7C06117ULL,
		0x0000094BA72FEB03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ABD3145F535E0B9ULL,
		0xA57467E90FDAA98AULL,
		0x13C833CD7CF12FEDULL,
		0xA1CA38954F1191DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC17200000000000ULL,
		0x55314557A628BEA6ULL,
		0x25FDB4AE8CFD21FBULL,
		0x323B42790679AF9EULL,
		0x000014394712A9E2ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8010039A4C4E433EULL,
		0x893BE08550373E73ULL,
		0x888D1C53062ED951ULL,
		0x980206D55463F3F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x00200734989C867CULL,
		0x1277C10AA06E7CE7ULL,
		0x111A38A60C5DB2A3ULL,
		0x30040DAAA8C7E7E5ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x451DA98F655D1DAFULL,
		0xE94B3372755D4A49ULL,
		0x96B1AC81F6E878B6ULL,
		0x9DB0FD92F7DCB7DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DAF00000000000ULL,
		0xD4A49451DA98F655ULL,
		0x878B6E94B3372755ULL,
		0xCB7DB96B1AC81F6EULL,
		0x000009DB0FD92F7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BF9123259950D3DULL,
		0x3D26EB0AD19F726EULL,
		0xF2E3B5E06BD14FD2ULL,
		0xD00663B77FE346F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2CCA869E80000000ULL,
		0x68CFB93735FC8919ULL,
		0x35E8A7E91E937585ULL,
		0xBFF1A37B7971DAF0ULL,
		0x00000000680331DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E8A898ED48A1AB8ULL,
		0xF59BBDC44C62E96AULL,
		0x284BEF226F9B5540ULL,
		0x5DED428552411432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3570000000000000ULL,
		0xD2D4BD15131DA914ULL,
		0xAA81EB377B8898C5ULL,
		0x28645097DE44DF36ULL,
		0x0000BBDA850AA482ULL
	}};
	shift = 15;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84C156929E3702FDULL,
		0x74D1C48B1ACE8B57ULL,
		0x1BCA7F51ADAE4E1DULL,
		0xB7CB615AD1A65276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x156929E3702FD000ULL,
		0x1C48B1ACE8B5784CULL,
		0xA7F51ADAE4E1D74DULL,
		0xB615AD1A652761BCULL,
		0x0000000000000B7CULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE7EC00CD5EA469FULL,
		0x3BD7E0803EF021B5ULL,
		0x51ED70E833503AD0ULL,
		0x9CC9569F5445C9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57A91A7C00000000ULL,
		0xFBC086D739FB0033ULL,
		0xCD40EB40EF5F8200ULL,
		0x511727DD47B5C3A0ULL,
		0x0000000273255A7DULL
	}};
	shift = 30;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x900A5C6B01216100ULL,
		0xD6EA9D7E388AA665ULL,
		0xBF96C60DD6D8C7CDULL,
		0xFB47E136E03771D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x052E358090B08000ULL,
		0x754EBF1C455332C8ULL,
		0xCB6306EB6C63E6EBULL,
		0xA3F09B701BB8E95FULL,
		0x000000000000007DULL
	}};
	shift = 57;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECE127E03B663CEEULL,
		0x748EF10C68C65F30ULL,
		0x7C9B51FCAAD9E147ULL,
		0x2CBF1BDC8BC7C04EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF01DB31E77000000ULL,
		0x8634632F98767093ULL,
		0xFE556CF0A3BA4778ULL,
		0xEE45E3E0273E4DA8ULL,
		0x0000000000165F8DULL
	}};
	shift = 41;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AEE9852C7D40BBCULL,
		0x07A4D844DA0D76C6ULL,
		0x0E028B871143A449ULL,
		0xCFC8B39BB4429AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x63EA05DE00000000ULL,
		0x6D06BB6345774C29ULL,
		0x88A1D22483D26C22ULL,
		0xDA214D73870145C3ULL,
		0x0000000067E459CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39E2AD1B669A153AULL,
		0x9B624DBC7DE06891ULL,
		0x855F81D3BA14FC03ULL,
		0x77802045FD560FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1B669A153A000000ULL,
		0xBC7DE0689139E2ADULL,
		0xD3BA14FC039B624DULL,
		0x45FD560FFA855F81ULL,
		0x0000000000778020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60F14BAF404E4237ULL,
		0x01A0A554945A1347ULL,
		0x394507292235A053ULL,
		0xB3C49B09C52B4309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09C846E000000000ULL,
		0x8B4268EC1E2975E8ULL,
		0x46B40A603414AA92ULL,
		0xA568612728A0E524ULL,
		0x0000001678936138ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57AE81D2722946B6ULL,
		0x049D9FD2D8B6F28FULL,
		0xB522209997079508ULL,
		0x266B881BF6C36176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E4528D6C0000000ULL,
		0x5B16DE51EAF5D03AULL,
		0x32E0F2A10093B3FAULL,
		0x7ED86C2ED6A44413ULL,
		0x0000000004CD7103ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42FF4175BF4D3E72ULL,
		0xF2FDB7C2447192DEULL,
		0x6F6F8049D952D6A5ULL,
		0x6F55574C339BEC1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF390000000000000ULL,
		0x96F217FA0BADFA69ULL,
		0xB52F97EDBE12238CULL,
		0x60E37B7C024ECA96ULL,
		0x00037AAABA619CDFULL
	}};
	shift = 13;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x222DC14BB3347168ULL,
		0x72004843CBB2A0C4ULL,
		0x0A309FC5365AA513ULL,
		0x6B951FA15225C6A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B40000000000000ULL,
		0x0621116E0A5D99A3ULL,
		0x289B9002421E5D95ULL,
		0x35205184FE29B2D5ULL,
		0x00035CA8FD0A912EULL
	}};
	shift = 13;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53045A1CABEA4563ULL,
		0xAAD31F97CCAE9FF0ULL,
		0x4CCB002D5545C66DULL,
		0xB4AB8B76184AFE26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2D0E55F522B18000ULL,
		0x8FCBE6574FF82982ULL,
		0x8016AAA2E336D569ULL,
		0xC5BB0C257F132665ULL,
		0x0000000000005A55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50B3EF9439070DB4ULL,
		0x0F646A3869E9A880ULL,
		0xDBD212A9A8C7A6F4ULL,
		0xC9466BC4D2AC4CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC36D000000000000ULL,
		0x6A20142CFBE50E41ULL,
		0xE9BD03D91A8E1A7AULL,
		0x1328B6F484AA6A31ULL,
		0x000032519AF134ABULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53A4D98447C80A13ULL,
		0xC9EC87312DE4C8A4ULL,
		0x94AD180078A1E1D3ULL,
		0x046CF69A595C9188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D98447C80A1300ULL,
		0xEC87312DE4C8A453ULL,
		0xAD180078A1E1D3C9ULL,
		0x6CF69A595C918894ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5EF83077C2C16426ULL,
		0xCF8E1D9F5A3AFFC7ULL,
		0x09587F54A4815945ULL,
		0x3C880C4F822DE27EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x82C84C0000000000ULL,
		0x75FF8EBDF060EF85ULL,
		0x02B28B9F1C3B3EB4ULL,
		0x5BC4FC12B0FEA949ULL,
		0x0000007910189F04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4D03B2E4B955B45ULL,
		0xCE805694A097704FULL,
		0x6FA5C888A3FFB036ULL,
		0x8143A1DCCE1B1E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xECB92E556D140000ULL,
		0x5A52825DC13F5340ULL,
		0x22228FFEC0DB3A01ULL,
		0x8773386C79FDBE97ULL,
		0x000000000002050EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43769E1E79A624C3ULL,
		0x29F5679A18D52AB3ULL,
		0xE5CC635102B1D33BULL,
		0x1954F1F2E27FDCF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3CF34C498600000ULL,
		0xF3431AA556686ED3ULL,
		0x6A20563A67653EACULL,
		0x3E5C4FFB9E5CB98CULL,
		0x0000000000032A9EULL
	}};
	shift = 43;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x835ACB576E142399ULL,
		0xBD0D7CE2D3ADA3C4ULL,
		0x698ED626CDAA5838ULL,
		0xD5902C7062106064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8508E64000000000ULL,
		0xEB68F120D6B2D5DBULL,
		0x6A960E2F435F38B4ULL,
		0x8418191A63B589B3ULL,
		0x00000035640B1C18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 218;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x915F9D8B11EE2453ULL,
		0x998D508E4D349AC5ULL,
		0x44942DE7474195F2ULL,
		0x1E9BF344CDA25100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE24530000000000ULL,
		0x349AC5915F9D8B11ULL,
		0x4195F2998D508E4DULL,
		0xA2510044942DE747ULL,
		0x0000001E9BF344CDULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADD76B9281A5E8A5ULL,
		0x29071992AB90CE99ULL,
		0xF4F859EF2A2CC103ULL,
		0x674D44DF6797949EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E8A500000000000ULL,
		0x0CE99ADD76B9281AULL,
		0xCC10329071992AB9ULL,
		0x7949EF4F859EF2A2ULL,
		0x00000674D44DF679ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x257411FCF9321639ULL,
		0x74D779E9112B2443ULL,
		0x42FA2A1B6FABF1D1ULL,
		0x73A9946EC92B8DFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x411FCF9321639000ULL,
		0x779E9112B2443257ULL,
		0xA2A1B6FABF1D174DULL,
		0x9946EC92B8DFF42FULL,
		0x000000000000073AULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9A88D29C0B04CE9ULL,
		0x864D181C6AD1DCBCULL,
		0x61EABA58AAD59EB5ULL,
		0xCA6037A8F2204D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4A702C133A400000ULL,
		0x071AB4772F2A6A23ULL,
		0x962AB567AD619346ULL,
		0xEA3C881358587AAEULL,
		0x000000000032980DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C32A5CE0631A1A3ULL,
		0xE474C8F707E7FFEFULL,
		0xAAE6C27C07CE3F50ULL,
		0x7A831FD807059234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC6868C0000000000ULL,
		0x9FFFBDF0CA973818ULL,
		0x38FD4391D323DC1FULL,
		0x1648D2AB9B09F01FULL,
		0x000001EA0C7F601CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1780E30F52B83B8CULL,
		0x1E9FF061FC083DC2ULL,
		0x599A8568F3BF138FULL,
		0xEABF666B234E51C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7718000000000000ULL,
		0x7B842F01C61EA570ULL,
		0x271E3D3FE0C3F810ULL,
		0xA386B3350AD1E77EULL,
		0x0001D57ECCD6469CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A2E3E4A493914B6ULL,
		0x73D8C4F496E4E613ULL,
		0x395F27CCCE9C910FULL,
		0x671333702FF1FAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE3E4A493914B6000ULL,
		0x8C4F496E4E6132A2ULL,
		0xF27CCCE9C910F73DULL,
		0x333702FF1FAF0395ULL,
		0x0000000000000671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75DDC977CD057480ULL,
		0x79F82A5415E9AAD5ULL,
		0x6AEDF1FD061EFE65ULL,
		0x981538C025A6146FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAAEBBB92EF9A0AE9ULL,
		0xCAF3F054A82BD355ULL,
		0xDED5DBE3FA0C3DFCULL,
		0x01302A71804B4C28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06CFEBF3D57D1E9FULL,
		0xF959D9FD96902D14ULL,
		0xF8820789CBE51D6FULL,
		0xE5BABB706AB92269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x80D9FD7E7AAFA3D3ULL,
		0xFF2B3B3FB2D205A2ULL,
		0x3F1040F1397CA3ADULL,
		0x1CB7576E0D57244DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF04FCF787847C7EAULL,
		0x37459E585882C94DULL,
		0x209CDF91D4612399ULL,
		0x69DA4C2A2348411CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3F5000000000000ULL,
		0x64A6F827E7BC3C23ULL,
		0x91CC9BA2CF2C2C41ULL,
		0x208E104E6FC8EA30ULL,
		0x000034ED261511A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A03AE63E3696E24ULL,
		0xCFED5C93FCDB3A6FULL,
		0x8F495FA9A76ABC6DULL,
		0xBDFDC4A14AF8F233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC48000000000000ULL,
		0x74DEF4075CC7C6D2ULL,
		0x78DB9FDAB927F9B6ULL,
		0xE4671E92BF534ED5ULL,
		0x00017BFB894295F1ULL
	}};
	shift = 15;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2563C768E565CA11ULL,
		0xC24505F40F3EE9E2ULL,
		0xB3AD3EC3F0509838ULL,
		0x07B4E5695CC22B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AC78ED1CACB9422ULL,
		0x848A0BE81E7DD3C4ULL,
		0x675A7D87E0A13071ULL,
		0x0F69CAD2B984566BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51825B60E9DB9EC9ULL,
		0x2054EB34924D65D9ULL,
		0xDCEE20080A115134ULL,
		0x172AB65F506293A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB9EC9000000000ULL,
		0x24D65D951825B60EULL,
		0xA1151342054EB349ULL,
		0x06293A6DCEE20080ULL,
		0x0000000172AB65F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BD9DAC934D0092FULL,
		0xA607AF8DA61BCF26ULL,
		0xC109F9D1F14FE3CBULL,
		0x87FB845A88BCC2D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9780000000000000ULL,
		0x9315ECED649A6804ULL,
		0xE5D303D7C6D30DE7ULL,
		0x68E084FCE8F8A7F1ULL,
		0x0043FDC22D445E61ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65F0DB686C51774BULL,
		0xDF83C878A351FD19ULL,
		0x0E8E80EA4470F76CULL,
		0x585E2A6AE93724FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1B6D0D8A2EE960ULL,
		0xF0790F146A3FA32CULL,
		0xD1D01D488E1EED9BULL,
		0x0BC54D5D26E49FC1ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF7F80F0579C2753ULL,
		0x74486869F227A571ULL,
		0x844775709BAA7DB7ULL,
		0x02202D75D862068FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x709D4C0000000000ULL,
		0x9E95C6FDFE03C15EULL,
		0xA9F6DDD121A1A7C8ULL,
		0x881A3E111DD5C26EULL,
		0x0000000880B5D761ULL
	}};
	shift = 22;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAC35CF88827DE60ULL,
		0x31F725AD4AC923DCULL,
		0x3C31E3396988EF60ULL,
		0x68AA310F28958F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D73E2209F798000ULL,
		0xDC96B52B248F72ABULL,
		0xC78CE5A623BD80C7ULL,
		0xA8C43CA2563D64F0ULL,
		0x00000000000001A2ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD15317291D99F91CULL,
		0x9F43BCDC08741C7BULL,
		0xFB917F7774A004A1ULL,
		0x8AA14DDC1DE7AF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x7A2A62E523B33F23ULL,
		0x33E8779B810E838FULL,
		0x5F722FEEEE940094ULL,
		0x115429BB83BCF5F1ULL
	}};
	shift = 3;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6E97EB1FFC0E154ULL,
		0xC2BDAFCA736C0F0AULL,
		0xBE0B58ACB5D4DD39ULL,
		0x5C6C1E5EB108A38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5400000000000000ULL,
		0x0AF6E97EB1FFC0E1ULL,
		0x39C2BDAFCA736C0FULL,
		0x8EBE0B58ACB5D4DDULL,
		0x005C6C1E5EB108A3ULL
	}};
	shift = 8;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51B332C3C5D77E2BULL,
		0x28BAB7BBD8B0C365ULL,
		0x989FC06AE243682CULL,
		0x3A281EFC9764269AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x65878BAEFC560000ULL,
		0x6F77B16186CAA366ULL,
		0x80D5C486D0585175ULL,
		0x3DF92EC84D35313FULL,
		0x0000000000007450ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E260B171CDA40DFULL,
		0x7542AA70111B6C56ULL,
		0xB4F87993F6AAA460ULL,
		0x6779A579FA36144BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800000000000000ULL,
		0xB0713058B8E6D206ULL,
		0x03AA15538088DB62ULL,
		0x5DA7C3CC9FB55523ULL,
		0x033BCD2BCFD1B0A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D0A736F3F02E304ULL,
		0x4E8ED92F7AFE9C92ULL,
		0x16B9A4EE0FD3FD12ULL,
		0xA8243B1E5607EBE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1820000000000000ULL,
		0xE49168539B79F817ULL,
		0xE8927476C97BD7F4ULL,
		0x5F30B5CD27707E9FULL,
		0x00054121D8F2B03FULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC25A065D5006EFEULL,
		0x404D713563ABA6B7ULL,
		0xB79088A376401B3DULL,
		0xC8F9C33D5E4A6112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77F0000000000000ULL,
		0x35BE612D032EA803ULL,
		0xD9EA026B89AB1D5DULL,
		0x0895BC84451BB200ULL,
		0x000647CE19EAF253ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC273DEED7B623A10ULL,
		0xC6FC7CFE48B9AEDEULL,
		0xBA25DCE7B2C879F2ULL,
		0xE09D306F9D68A631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBDDAF6C474200000ULL,
		0xF9FC91735DBD84E7ULL,
		0xB9CF6590F3E58DF8ULL,
		0x60DF3AD14C63744BULL,
		0x000000000001C13AULL
	}};
	shift = 47;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75098E7891861276ULL,
		0xC71FEC6544237FB4ULL,
		0x64ACA2381185AAB9ULL,
		0x1470BAC80C6B2ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2639E2461849D800ULL,
		0x7FB195108DFED1D4ULL,
		0xB288E04616AAE71CULL,
		0xC2EB2031ACBB3192ULL,
		0x0000000000000051ULL
	}};
	shift = 54;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE36BEF5856252E3CULL,
		0x9DF5C6B20F2A252DULL,
		0xDA9F27773D849FDCULL,
		0xD03253223398B476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78DAFBD615894B8FULL,
		0x277D71AC83CA894BULL,
		0xB6A7C9DDCF6127F7ULL,
		0x340C94C88CE62D1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE784F7B6C47CA490ULL,
		0xD5BE76465546071EULL,
		0x47E2E7BF73BFD9BAULL,
		0xA22DE5F4BD55C5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF292400000000000ULL,
		0x181C7B9E13DEDB11ULL,
		0xFF66EB56F9D91955ULL,
		0x57176D1F8B9EFDCEULL,
		0x00000288B797D2F5ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CCD0115D4A965E5ULL,
		0x39C4940C4E59E26DULL,
		0x5B6034B8EB6E7FC6ULL,
		0x415BEE0F1DAF0D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xA999A022BA952CBCULL,
		0xC738928189CB3C4DULL,
		0x2B6C06971D6DCFF8ULL,
		0x082B7DC1E3B5E1B2ULL
	}};
	shift = 3;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE0E6423C52359F7ULL,
		0x9ECA2A9A11F76321ULL,
		0x15386F515E145D19ULL,
		0xB3CE2A5868752F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB3EE000000000000ULL,
		0xC643BC1CC8478A46ULL,
		0xBA333D94553423EEULL,
		0x5E782A70DEA2BC28ULL,
		0x0001679C54B0D0EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E461AA84A51CB39ULL,
		0x686649DC4E80520CULL,
		0xCF6C84A8D226776BULL,
		0x3092F2BBABD12C68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6AA129472CE40000ULL,
		0x27713A014831B918ULL,
		0x12A34899DDADA199ULL,
		0xCAEEAF44B1A33DB2ULL,
		0x000000000000C24BULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x796BDDEB2A426A86ULL,
		0x267DECB9707740E8ULL,
		0x53825B6F026F3B71ULL,
		0x5A68492E9F8F9AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x796BDDEB2A426A86ULL,
		0x267DECB9707740E8ULL,
		0x53825B6F026F3B71ULL,
		0x5A68492E9F8F9AF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50A49782ECF57BCFULL,
		0x5DEB4CF831FAC952ULL,
		0xED5487E6D7E31077ULL,
		0x21ED17A3A0957D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x524BC1767ABDE780ULL,
		0xF5A67C18FD64A928ULL,
		0xAA43F36BF1883BAEULL,
		0xF68BD1D04ABE9E76ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC65A08DD681FAE7ULL,
		0x3BF6F240E1AFEFC2ULL,
		0x0191B0A8BCAF3708ULL,
		0xB016F86C66A6AA08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC65A08DD681FAE7ULL,
		0x3BF6F240E1AFEFC2ULL,
		0x0191B0A8BCAF3708ULL,
		0xB016F86C66A6AA08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A61E9F010C5261CULL,
		0xF6357A7B7D852B4CULL,
		0x3962903D493D2E29ULL,
		0x2C5E2AA68B164E8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F4F80862930E000ULL,
		0xABD3DBEC295A6353ULL,
		0x1481EA49E9714FB1ULL,
		0xF1553458B27471CBULL,
		0x0000000000000162ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAED63B1D059C06F4ULL,
		0x23F6B4F438720949ULL,
		0x141C7D73B0373E99ULL,
		0x0B017A6B1E1E43DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x35DAC763A0B380DEULL,
		0x247ED69E870E4129ULL,
		0xA2838FAE7606E7D3ULL,
		0x01602F4D63C3C87BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3FB3002E15D0F79ULL,
		0xDE359121576393EDULL,
		0x843C0B95E2C07972ULL,
		0x7CED56EB7A44FBC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x05C2BA1EF2000000ULL,
		0x42AEC727DB67F660ULL,
		0x2BC580F2E5BC6B22ULL,
		0xD6F489F78D087817ULL,
		0x0000000000F9DAADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x042EB6204A42F26DULL,
		0xE0C87BD762E6764DULL,
		0x7D38D23088ECE1B4ULL,
		0x5541E2D7DA246DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B40000000000000ULL,
		0x93410BAD881290BCULL,
		0x6D38321EF5D8B99DULL,
		0x7E1F4E348C223B38ULL,
		0x00155078B5F6891BULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F289D357AF05B96ULL,
		0xB3FF7405E86DD358ULL,
		0x56176DA942935303ULL,
		0xCD90AFAA63556DB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E0B72C00000000ULL,
		0xD0DBA6B0DE513A6AULL,
		0x8526A60767FEE80BULL,
		0xC6AADB6AAC2EDB52ULL,
		0x000000019B215F54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6AB8CBA22A770F56ULL,
		0x07677F7A40FBDDC7ULL,
		0x9D2F839370EC6F35ULL,
		0x5CA59D5D9D6628D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5600000000000000ULL,
		0xC76AB8CBA22A770FULL,
		0x3507677F7A40FBDDULL,
		0xD99D2F839370EC6FULL,
		0x005CA59D5D9D6628ULL
	}};
	shift = 8;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x474543ABAA13A0AFULL,
		0xC521744B6D457F87ULL,
		0x9D180EE0CF493FE4ULL,
		0x798D80E84B4E2D89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x427415E000000000ULL,
		0xA8AFF0E8E8A87575ULL,
		0xE927FC98A42E896DULL,
		0x69C5B133A301DC19ULL,
		0x0000000F31B01D09ULL
	}};
	shift = 27;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5063D9B8B95E736BULL,
		0x7542C3FDCCC174EEULL,
		0x2CC98147D1E1552DULL,
		0xD8F5C6BF671530FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x172BCE6D60000000ULL,
		0xB9982E9DCA0C7B37ULL,
		0xFA3C2AA5AEA8587FULL,
		0xECE2A61F45993028ULL,
		0x000000001B1EB8D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F05DFFCDC754131ULL,
		0x0A7E2098701B3634ULL,
		0x50C7F1E4FCC0AA79ULL,
		0xEF55768BEE584AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE6E3AA098800000ULL,
		0x4C380D9B1A3F82EFULL,
		0xF27E60553C853F10ULL,
		0x45F72C2558A863F8ULL,
		0x000000000077AABBULL
	}};
	shift = 41;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AB74EDBE22E6364ULL,
		0x4AB213DD311FA56AULL,
		0xBCFFE28091ED6F38ULL,
		0x37DEEB3D4505E701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6F88B98D9000000ULL,
		0xF74C47E95A8EADD3ULL,
		0xA0247B5BCE12AC84ULL,
		0xCF514179C06F3FF8ULL,
		0x00000000000DF7BAULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFF1DF9F995A7219ULL,
		0xD04E8AB32906AB58ULL,
		0x07D1DA77E9BB6F5CULL,
		0x23B6E14E0971C88AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC800000000000000ULL,
		0xC7FF8EFCFCCAD390ULL,
		0xE68274559948355AULL,
		0x503E8ED3BF4DDB7AULL,
		0x011DB70A704B8E44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x378D58B9D32EB8ADULL,
		0x9355A3C5D20AD6E0ULL,
		0xE233479B0DBCF3DEULL,
		0xBB99A0D03CAAC86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B9D32EB8AD00000ULL,
		0x3C5D20AD6E0378D5ULL,
		0x79B0DBCF3DE9355AULL,
		0x0D03CAAC86FE2334ULL,
		0x00000000000BB99AULL
	}};
	shift = 44;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE8BAD6BF1DDFA1EULL,
		0xE3E35137D261C3D5ULL,
		0x252136178302078DULL,
		0xBD542F2B4C2AA5B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F8EEFD0F0000000ULL,
		0xBE930E1EAE745D6BULL,
		0xBC18103C6F1F1A89ULL,
		0x5A61552D992909B0ULL,
		0x0000000005EAA179ULL
	}};
	shift = 37;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5257D06BE131ADBEULL,
		0xBEDF50674EC058A8ULL,
		0x903AA817E6F775A0ULL,
		0x6D350AE2D0E00D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7C0000000000000ULL,
		0x150A4AFA0D7C2635ULL,
		0xB417DBEA0CE9D80BULL,
		0xA6D2075502FCDEEEULL,
		0x000DA6A15C5A1C01ULL
	}};
	shift = 11;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD03551A1D84C9622ULL,
		0x5E95CCBC37FF422CULL,
		0x5DB980668CC5B2E4ULL,
		0x763C0722D403C901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2200000000000000ULL,
		0x2CD03551A1D84C96ULL,
		0xE45E95CCBC37FF42ULL,
		0x015DB980668CC5B2ULL,
		0x00763C0722D403C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAB8A283A64067A9ULL,
		0x13E047C1B6047A15ULL,
		0x6B13EE3AFCA3F2EFULL,
		0x87DC05AAA87E9E5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A64067A90000000ULL,
		0x1B6047A15EAB8A28ULL,
		0xAFCA3F2EF13E047CULL,
		0xAA87E9E5D6B13EE3ULL,
		0x00000000087DC05AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64CE2FC72DE887E3ULL,
		0x790BD461B5F45856ULL,
		0x87CFD2F14AF86512ULL,
		0x7BABE45999B7A6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCE2FC72DE887E300ULL,
		0x0BD461B5F4585664ULL,
		0xCFD2F14AF8651279ULL,
		0xABE45999B7A6C587ULL,
		0x000000000000007BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCCD296D6E35D439BULL,
		0x2B8D86755612FD34ULL,
		0xAF69662BC542235FULL,
		0x0F6F0A4BA02B6049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x3334A5B5B8D750E6ULL,
		0xCAE3619D5584BF4DULL,
		0x6BDA598AF15088D7ULL,
		0x03DBC292E80AD812ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E7E3E4F9E543B49ULL,
		0xF8A7C34758D020ECULL,
		0x541CECFFE990BE50ULL,
		0x90ADD12EA2B892A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F1F27CF2A1DA480ULL,
		0x53E1A3AC68107617ULL,
		0x0E767FF4C85F287CULL,
		0x56E897515C4952AAULL,
		0x0000000000000048ULL
	}};
	shift = 57;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF42BF8F4DDA8195EULL,
		0x850A128764DBEBD1ULL,
		0xD4924C69082A08D5ULL,
		0x60A74DB9CA5C0103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x7D0AFE3D376A0657ULL,
		0x614284A1D936FAF4ULL,
		0xF524931A420A8235ULL,
		0x1829D36E72970040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9EB0B5819A8696C0ULL,
		0x2374998997FBD60FULL,
		0x080BDC2CF1B63B02ULL,
		0x9B4EE862D2A2602BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03350D2D80000000ULL,
		0x132FF7AC1F3D616BULL,
		0x59E36C760446E933ULL,
		0xC5A544C0561017B8ULL,
		0x0000000001369DD0ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D51BB1A024860EDULL,
		0x4E04F1515866C91AULL,
		0x407F40C726F163A8ULL,
		0x7599D7E7F8A8318CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x51AA376340490C1DULL,
		0x09C09E2A2B0CD923ULL,
		0x880FE818E4DE2C75ULL,
		0x0EB33AFCFF150631ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6678DCA00D294BECULL,
		0x8D05B26A6E8D99C3ULL,
		0xAE76B4AD3306B00AULL,
		0xF607FC310280CFC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC6E500694A5F6000ULL,
		0x2D9353746CCE1B33ULL,
		0xB5A5699835805468ULL,
		0x3FE18814067E1D73ULL,
		0x00000000000007B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F2F8297D2BFAA70ULL,
		0xEDA31EBA19CB3D84ULL,
		0x7EEF9D6419F63A14ULL,
		0xA0A1BCABD39AF580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x21F97C14BE95FD53ULL,
		0xA76D18F5D0CE59ECULL,
		0x03F77CEB20CFB1D0ULL,
		0x05050DE55E9CD7ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C03514115C28138ULL,
		0x20914FB210868289ULL,
		0x99B277293B36485DULL,
		0x4CBAA95297CA8EFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8138000000000000ULL,
		0x82895C03514115C2ULL,
		0x485D20914FB21086ULL,
		0x8EFB99B277293B36ULL,
		0x00004CBAA95297CAULL
	}};
	shift = 16;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA652748EBD1C16FULL,
		0x94C81527338C581EULL,
		0x7BDE8ABAD18CF2B6ULL,
		0xCA3A119BA31DA739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD1C16F0000000000ULL,
		0x8C581EDA652748EBULL,
		0x8CF2B694C8152733ULL,
		0x1DA7397BDE8ABAD1ULL,
		0x000000CA3A119BA3ULL
	}};
	shift = 24;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F6C379C77CF2863ULL,
		0x534E9FDA82F90649ULL,
		0x100410AC11402B05ULL,
		0x6E705CA9434CFAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18C0000000000000ULL,
		0x924BDB0DE71DF3CAULL,
		0xC154D3A7F6A0BE41ULL,
		0xB0C401042B04500AULL,
		0x001B9C172A50D33EULL
	}};
	shift = 10;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FE2064D0DD24B1FULL,
		0x730435B318E3255AULL,
		0x4BB1E26754F18F7AULL,
		0x4D8B88FE0D611C4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C7C000000000000ULL,
		0x9568BF8819343749ULL,
		0x3DE9CC10D6CC638CULL,
		0x71392EC7899D53C6ULL,
		0x0001362E23F83584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9658DF3D08B639F9ULL,
		0x9CDD3D437F5315F7ULL,
		0x52A9455AF1517011ULL,
		0x4AF0237F874E8EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB1CFC80000000000ULL,
		0x98AFBCB2C6F9E845ULL,
		0x8B808CE6E9EA1BFAULL,
		0x7476F2954A2AD78AULL,
		0x00000257811BFC3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1ACF6EBB65DD4AFDULL,
		0x6BA3F1602548055FULL,
		0xD4DDCCAD19636C91ULL,
		0xC527A497347BA651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD0000000000000ULL,
		0x55F1ACF6EBB65DD4ULL,
		0xC916BA3F16025480ULL,
		0x651D4DDCCAD19636ULL,
		0x000C527A497347BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDAEBF2FD3249C2AULL,
		0x7C31037FF918C28DULL,
		0x8703DDC1A2374076ULL,
		0x9853D7236B7C16B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1500000000000000ULL,
		0x46F6D75F97E9924EULL,
		0x3B3E1881BFFC8C61ULL,
		0x58C381EEE0D11BA0ULL,
		0x004C29EB91B5BE0BULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE2E167CFD5FB3FFULL,
		0xF9EBB4B93BBB7FE9ULL,
		0x8B90CDCF52BEC55CULL,
		0xA24A6B3E9545B711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFB3FF00000000000ULL,
		0xB7FE9BE2E167CFD5ULL,
		0xEC55CF9EBB4B93BBULL,
		0x5B7118B90CDCF52BULL,
		0x00000A24A6B3E954ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63E28E9F4DA5D8CBULL,
		0xA0EDC99E56ACD780ULL,
		0x0CB72D5F9F08CA26ULL,
		0x73813BA83A2D65A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697632C000000000ULL,
		0xAB35E018F8A3A7D3ULL,
		0xC23289A83B726795ULL,
		0x8B596A032DCB57E7ULL,
		0x0000001CE04EEA0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 218;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x85ED3FD23BE005E3ULL,
		0x0DB6E7E621DD6DD5ULL,
		0x1A11F6777217FD7DULL,
		0x2ADF3202B8C4DCAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85ED3FD23BE005E3ULL,
		0x0DB6E7E621DD6DD5ULL,
		0x1A11F6777217FD7DULL,
		0x2ADF3202B8C4DCAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD6C99086252A3F0ULL,
		0x9BC403A199EC4785ULL,
		0xC2A06C9E8D2939F8ULL,
		0xC1BEB8191F81AAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2A3F000000000000ULL,
		0xC4785FD6C9908625ULL,
		0x939F89BC403A199EULL,
		0x1AAEEC2A06C9E8D2ULL,
		0x00000C1BEB8191F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE6671547ACC7BBFULL,
		0x81B618A9A762CD7BULL,
		0x9DA627145265369EULL,
		0x2615F6175AECCF42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51EB31EEFC000000ULL,
		0xA69D8B35EEF999C5ULL,
		0x514994DA7A06D862ULL,
		0x5D6BB33D0A76989CULL,
		0x00000000009857D8ULL
	}};
	shift = 38;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D2454CB9E5226F1ULL,
		0xD1FC0469ED47C11BULL,
		0x617C78951AA83CCBULL,
		0xD7005592226EEB33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9973CA44DE20000ULL,
		0x08D3DA8F82365A48ULL,
		0xF12A35507997A3F8ULL,
		0xAB2444DDD666C2F8ULL,
		0x000000000001AE00ULL
	}};
	shift = 47;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x01C4B1E2FF9496FAULL,
		0x2BFA5172F8AD418EULL,
		0xE86F97AF55D2FC4FULL,
		0x28B893273DF0C26FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4B7D00000000000ULL,
		0x6A0C700E258F17FCULL,
		0x97E2795FD28B97C5ULL,
		0x86137F437CBD7AAEULL,
		0x00000145C49939EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC03E0F3FFB661BBDULL,
		0x7A73936D1CD4C9CAULL,
		0x450D63669D27D34FULL,
		0xD55F8DC8F262BDDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB661BBD000000000ULL,
		0xCD4C9CAC03E0F3FFULL,
		0xD27D34F7A73936D1ULL,
		0x262BDDE450D63669ULL,
		0x0000000D55F8DC8FULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF7604654F3E4D0EULL,
		0x9A5A0265FD6A5E80ULL,
		0x29EA967D6A28C207ULL,
		0x0F4CE7273AF061D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32A79F2687000000ULL,
		0x32FEB52F4057BB02ULL,
		0x3EB5146103CD2D01ULL,
		0x939D7830E814F54BULL,
		0x000000000007A673ULL
	}};
	shift = 41;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x850310C574C35675ULL,
		0x778C4D8AE6F1E8B4ULL,
		0xDFA6505FA64E1554ULL,
		0x3E7E100C6BACAAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC356750000000000ULL,
		0xF1E8B4850310C574ULL,
		0x4E1554778C4D8AE6ULL,
		0xACAAEADFA6505FA6ULL,
		0x0000003E7E100C6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2726A1CB12DF837ULL,
		0x1B60732ECDF35816ULL,
		0x5600F83ECC9A8A8BULL,
		0x6652203B0431A123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26A1CB12DF837000ULL,
		0x0732ECDF35816F27ULL,
		0x0F83ECC9A8A8B1B6ULL,
		0x2203B0431A123560ULL,
		0x0000000000000665ULL
	}};
	shift = 52;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D5E811D144FF975ULL,
		0xD42C53E8E4296FA2ULL,
		0x3E870A0191A0D2EFULL,
		0xFA9337629D5BFFDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x49ABD023A289FF2EULL,
		0xFA858A7D1C852DF4ULL,
		0x47D0E14032341A5DULL,
		0x1F5266EC53AB7FFBULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x45502021FCF32F61ULL,
		0xE3BF4D15D5DD4D51ULL,
		0xF00931BB7E2C44C0ULL,
		0x8B4B533DAFCF4714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81010FE7997B0800ULL,
		0xFA68AEAEEA6A8A2AULL,
		0x498DDBF16226071DULL,
		0x5A99ED7E7A38A780ULL,
		0x000000000000045AULL
	}};
	shift = 53;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x17D5972B43EB74F7ULL,
		0x8ADC9D760D1E5264ULL,
		0x4AC4B818BDB7AF70ULL,
		0xEC88A8BA168CB3F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7B80000000000000ULL,
		0x320BEACB95A1F5BAULL,
		0xB8456E4EBB068F29ULL,
		0xFC25625C0C5EDBD7ULL,
		0x007644545D0B4659ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0411B17DD23C88CULL,
		0x95E80EB4B6E508F8ULL,
		0x9EADFECB6EE58CD9ULL,
		0x89FB702FE8F1902CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08D8BEE91E446000ULL,
		0x4075A5B72847C782ULL,
		0x6FF65B772C66CCAFULL,
		0xDB817F478C8164F5ULL,
		0x000000000000044FULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA43604F9490239FFULL,
		0x7CE0E7FD09B28259ULL,
		0x3BEC7DCA8C2B70E2ULL,
		0x90F5546E550E7E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CA4811CFF800000ULL,
		0xFE84D9412CD21B02ULL,
		0xE54615B8713E7073ULL,
		0x372A873F039DF63EULL,
		0x0000000000487AAAULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B391D9515D83D06ULL,
		0x2AB0B2AFBE4008B5ULL,
		0x2C8E41708CB1058AULL,
		0x78A975DD8D3B2ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B391D9515D83D06ULL,
		0x2AB0B2AFBE4008B5ULL,
		0x2C8E41708CB1058AULL,
		0x78A975DD8D3B2ECEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3279AD446FA1737ULL,
		0x5EC5F0037B18B19AULL,
		0xDE2DAE2C7B431D38ULL,
		0x639000E37248B450ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B9B800000000000ULL,
		0x58CD5193CD6A237DULL,
		0x8E9C2F62F801BD8CULL,
		0x5A286F16D7163DA1ULL,
		0x000031C80071B924ULL
	}};
	shift = 17;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5566F916BE7245FULL,
		0xEBDB8303E6DEC62DULL,
		0x41BC44EA52E3E267ULL,
		0x2918027FAD355E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF916BE7245F00000ULL,
		0x303E6DEC62DC5566ULL,
		0x4EA52E3E267EBDB8ULL,
		0x27FAD355E9841BC4ULL,
		0x0000000000029180ULL
	}};
	shift = 44;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B12429266C06DD3ULL,
		0xB75152E1EBB71101ULL,
		0x152668DC49CF98EFULL,
		0xE7102CE474944477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x2B6248524CD80DBAULL,
		0xF6EA2A5C3D76E220ULL,
		0xE2A4CD1B8939F31DULL,
		0x1CE2059C8E92888EULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D46020A44C53E5BULL,
		0xFDA711E6826DA345ULL,
		0x9D0F0CAC3868E43AULL,
		0x2DA540D7FEC76C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D80000000000000ULL,
		0xA2B6A3010522629FULL,
		0x1D7ED388F34136D1ULL,
		0x4E4E8786561C3472ULL,
		0x0016D2A06BFF63B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x332B60B76149DC49ULL,
		0xD5D771D40B53F4C9ULL,
		0x2A52F0D0C595123BULL,
		0x68C36A406BD6F082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2771240000000000ULL,
		0x4FD324CCAD82DD85ULL,
		0x5448EF575DC7502DULL,
		0x5BC208A94BC34316ULL,
		0x000001A30DA901AFULL
	}};
	shift = 22;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21BB6758462F0A18ULL,
		0xE5556B0F0CA16B93ULL,
		0x982654FE047341DEULL,
		0xCFE6C5B7918E5FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18BC286000000000ULL,
		0x3285AE4C86ED9D61ULL,
		0x11CD077B9555AC3CULL,
		0x46397EEA609953F8ULL,
		0x000000033F9B16DEULL
	}};
	shift = 30;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x494C556518637BFDULL,
		0x5A457D240A5B796DULL,
		0x62054AEBD363F9C6ULL,
		0xFC87A4302ADC1BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF7FA000000000000ULL,
		0xF2DA9298AACA30C6ULL,
		0xF38CB48AFA4814B6ULL,
		0x37BAC40A95D7A6C7ULL,
		0x0001F90F486055B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA7752ECD6507F47ULL,
		0x2563E2138CC34CFAULL,
		0x3003BB811A258214ULL,
		0x035102C886BB30BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD9ACA0FE8E000000ULL,
		0x27198699F594EEA5ULL,
		0x02344B04284AC7C4ULL,
		0x910D766174600777ULL,
		0x000000000006A205ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x458C697EDDD2D214ULL,
		0xABB6375A30493F07ULL,
		0x7C4D0186EDE1BD57ULL,
		0xFCC0B6C83E99E84BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FB774B485000000ULL,
		0xD68C124FC1D1631AULL,
		0x61BB786F55EAED8DULL,
		0xB20FA67A12DF1340ULL,
		0x00000000003F302DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB70F2130C1A1ED19ULL,
		0x1DD570A8669B98C5ULL,
		0x67AE6525F1414D59ULL,
		0x5650AD4F772FA597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0687B46400000000ULL,
		0x9A6E6316DC3C84C3ULL,
		0xC50535647755C2A1ULL,
		0xDCBE965D9EB99497ULL,
		0x000000015942B53DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD503BA96B1B06DCBULL,
		0xC2FE557D753182CAULL,
		0x945E5226F58D317FULL,
		0xE820CDF083F17349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6360DB960000000ULL,
		0xAEA630595AA07752ULL,
		0xDEB1A62FF85FCAAFULL,
		0x107E2E69328BCA44ULL,
		0x000000001D0419BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EE415480C628648ULL,
		0x3A4FAF5CFD5C3775ULL,
		0x0A70A2D3964E2005ULL,
		0xA9AC2876D2D05778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAA40631432400000ULL,
		0x7AE7EAE1BBA87720ULL,
		0x169CB2710029D27DULL,
		0x43B69682BBC05385ULL,
		0x0000000000054D61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0263A0532D56D8CULL,
		0x71BB169AFC4C2BD7ULL,
		0x9187F2A410E63645ULL,
		0x9DAA06293B251AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD02996AB6C600000ULL,
		0xB4D7E2615EBF8131ULL,
		0x95208731B22B8DD8ULL,
		0x3149D928D7CC8C3FULL,
		0x000000000004ED50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7032CD94B54C9559ULL,
		0x5F7860BA2A316854ULL,
		0x255E9E9CB7CBCF48ULL,
		0x759C78870A7EBE00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA64AAC80000000ULL,
		0x1518B42A381966CAULL,
		0x5BE5E7A42FBC305DULL,
		0x853F5F0012AF4F4EULL,
		0x000000003ACE3C43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF401A253F53E1AA5ULL,
		0xF329281A9DC233D8ULL,
		0xC88BC50253383772ULL,
		0x02BE3556620A8AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A253F53E1AA5000ULL,
		0x9281A9DC233D8F40ULL,
		0xBC50253383772F32ULL,
		0xE3556620A8AAFC88ULL,
		0x000000000000002BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x832A07C6A113481CULL,
		0xC649DAC9F7072757ULL,
		0x840A21D103252937ULL,
		0xB231EA1A3F710A40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x844D207000000000ULL,
		0xDC1C9D5E0CA81F1AULL,
		0x0C94A4DF19276B27ULL,
		0xFDC4290210288744ULL,
		0x00000002C8C7A868ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5462932689969F61ULL,
		0x58A25A3FD84BAD66ULL,
		0x644369CFA0394A3BULL,
		0xA683DDDDA037D335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31499344CB4FB080ULL,
		0x512D1FEC25D6B32AULL,
		0x21B4E7D01CA51DACULL,
		0x41EEEED01BE99AB2ULL,
		0x0000000000000053ULL
	}};
	shift = 57;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x071CDE2061EF2C16ULL,
		0xBC10056E02540CF2ULL,
		0x7D30289A36532926ULL,
		0x31C79F97DFFEF7AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x187BCB0580000000ULL,
		0x8095033C81C73788ULL,
		0x8D94CA49AF04015BULL,
		0xF7FFBDEB9F4C0A26ULL,
		0x000000000C71E7E5ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5ECC1FA733508A4DULL,
		0xD9E4554E4F584620ULL,
		0x1CF6759DA9EE6DC4ULL,
		0xB65C542735E54BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4E66A1149A000000ULL,
		0x9C9EB08C40BD983FULL,
		0x3B53DCDB89B3C8AAULL,
		0x4E6BCA97D639ECEBULL,
		0x00000000016CB8A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E104BDE7257C9DBULL,
		0x639B2CA9FAA3A829ULL,
		0xEAA2A713DD46E113ULL,
		0xFB50B85469AC88BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x257C9DB000000000ULL,
		0xAA3A8290E104BDE7ULL,
		0xD46E113639B2CA9FULL,
		0x9AC88BBEAA2A713DULL,
		0x0000000FB50B8546ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9ABD71BF01B9B65ULL,
		0x63DC426472F1DAE5ULL,
		0xD5FF2F9FB8DD56CCULL,
		0xB07E6801E87A67C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF01B9B650000000ULL,
		0x472F1DAE5B9ABD71ULL,
		0xFB8DD56CC63DC426ULL,
		0x1E87A67C4D5FF2F9ULL,
		0x000000000B07E680ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC3F4B245AA18C51ULL,
		0x9AC80E1A35133D32ULL,
		0x3EC719F4080BBF29ULL,
		0x26141CC6FE28DFA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x648B54318A200000ULL,
		0xC346A267A65B87E9ULL,
		0x3E810177E5335901ULL,
		0x98DFC51BF447D8E3ULL,
		0x000000000004C283ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3803ED898D7ADCBAULL,
		0xBDB67D29540D54FAULL,
		0xA64F72A7C46F704BULL,
		0x23937C8E8557F01DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE00FB62635EB72E8ULL,
		0xF6D9F4A5503553E8ULL,
		0x993DCA9F11BDC12EULL,
		0x8E4DF23A155FC076ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x437405C91AAB22B6ULL,
		0xD0C445CA90C29586ULL,
		0x30E4B9DD824FB52AULL,
		0x477967972FF9B781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C00000000000000ULL,
		0x0C86E80B92355645ULL,
		0x55A1888B9521852BULL,
		0x0261C973BB049F6AULL,
		0x008EF2CF2E5FF36FULL
	}};
	shift = 7;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1B229B9C9A849BAFULL,
		0xD62435EFCDBB9361ULL,
		0x4D6123BB74B48E95ULL,
		0xBD905FF327014E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26EBC00000000000ULL,
		0xE4D846C8A6E726A1ULL,
		0x23A575890D7BF36EULL,
		0x5388535848EEDD2DULL,
		0x00002F6417FCC9C0ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x097A04D75EA6FF68ULL,
		0x4D61E6A362AE853CULL,
		0x5716B4CC3938EE03ULL,
		0xB32AD0DB3BC5B8FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x75EA6FF680000000ULL,
		0x362AE853C097A04DULL,
		0xC3938EE034D61E6AULL,
		0xB3BC5B8FB5716B4CULL,
		0x000000000B32AD0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B5BB65D5AD085B3ULL,
		0x84745449F62C9EA3ULL,
		0x1FBC2254F1C67C1FULL,
		0x3F9D6136AEA0A053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD6842D9800000000ULL,
		0xB164F51A5ADDB2EAULL,
		0x8E33E0FC23A2A24FULL,
		0x75050298FDE112A7ULL,
		0x00000001FCEB09B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA529B38B3801ED1ULL,
		0x3361304277FCAF1EULL,
		0x368F855360826448ULL,
		0x1AC6348E118A7BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9C59C00F688000ULL,
		0x98213BFE578F6529ULL,
		0xC2A9B041322419B0ULL,
		0x1A4708C53DF01B47ULL,
		0x0000000000000D63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA196908B9CF98D9AULL,
		0x8BB4AE922ACBB947ULL,
		0xBC3F2F9D19B37250ULL,
		0xFF451768AF33F091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6CD0000000000000ULL,
		0xCA3D0CB4845CE7CCULL,
		0x92845DA57491565DULL,
		0x848DE1F97CE8CD9BULL,
		0x0007FA28BB45799FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB298E0837783EDC2ULL,
		0x3162303AA28A0AB7ULL,
		0x164E7A499CBF3ABFULL,
		0x2A08C9988553657FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6EF07DB840000000ULL,
		0x54514156F6531C10ULL,
		0x3397E757E62C4607ULL,
		0x10AA6CAFE2C9CF49ULL,
		0x0000000005411933ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C9924AE7D61F53FULL,
		0xDD51E1D8B005EF3CULL,
		0x31FEDF50B0DB6BB8ULL,
		0x329EE39FE32EBDE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x495CFAC3EA7E0000ULL,
		0xC3B1600BDE783932ULL,
		0xBEA161B6D771BAA3ULL,
		0xC73FC65D7BC463FDULL,
		0x000000000000653DULL
	}};
	shift = 47;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A96FB4D35578030ULL,
		0x60B206D5BE3866C1ULL,
		0xC287B741A72E8B75ULL,
		0x6588F85C8D328CCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7DA69AABC018000ULL,
		0x9036ADF1C3360BD4ULL,
		0x3DBA0D39745BAB05ULL,
		0x47C2E46994666614ULL,
		0x000000000000032CULL
	}};
	shift = 53;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8360B31463C0A183ULL,
		0x5AC8D1F148537C1BULL,
		0x38C050639641953AULL,
		0x628DF48A5F39DA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x463C0A1830000000ULL,
		0x148537C1B8360B31ULL,
		0x39641953A5AC8D1FULL,
		0xA5F39DA0A38C0506ULL,
		0x000000000628DF48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE48715660978CFC2ULL,
		0x31D07A89C223E4AEULL,
		0x1D2EA2816E4CC7B4ULL,
		0x3A26F2CD788F1F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC90E2ACC12F19F84ULL,
		0x63A0F5138447C95DULL,
		0x3A5D4502DC998F68ULL,
		0x744DE59AF11E3F02ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54860885046C11A5ULL,
		0x80742B8D2D8F6ECEULL,
		0x471FD6A974A0EFD1ULL,
		0x2871F38409587C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18221411B0469400ULL,
		0xD0AE34B63DBB3952ULL,
		0x7F5AA5D283BF4601ULL,
		0xC7CE102561F2011CULL,
		0x00000000000000A1ULL
	}};
	shift = 54;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF32DF67366AE1075ULL,
		0x4A6F54F8DFE0EA44ULL,
		0xC3FFBFC305AF60DFULL,
		0xB6A9C5FBF6AD1D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECE6CD5C20EA0000ULL,
		0xA9F1BFC1D489E65BULL,
		0x7F860B5EC1BE94DEULL,
		0x8BF7ED5A3B1F87FFULL,
		0x0000000000016D53ULL
	}};
	shift = 47;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x329659CFB6995BDEULL,
		0x10F1ED977D980B4AULL,
		0x9619354BCF6CD966ULL,
		0xBB8421D9461ADBD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CB39F6D32B7BC00ULL,
		0xE3DB2EFB30169465ULL,
		0x326A979ED9B2CC21ULL,
		0x0843B28C35B7A92CULL,
		0x0000000000000177ULL
	}};
	shift = 55;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DDA086FA33AAEFBULL,
		0xF8E3774DDCD0A208ULL,
		0x6FF19944D465F5A5ULL,
		0x1F4F2373BC2ECAA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CEABBEC00000000ULL,
		0x73428820B76821BEULL,
		0x5197D697E38DDD37ULL,
		0xF0BB2A8DBFC66513ULL,
		0x000000007D3C8DCEULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A437C52E1AC8978ULL,
		0x403C52488CD1B898ULL,
		0xAC8D9D3B264AAD13ULL,
		0x6E17AA438B0FA92AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8978000000000000ULL,
		0xB8980A437C52E1ACULL,
		0xAD13403C52488CD1ULL,
		0xA92AAC8D9D3B264AULL,
		0x00006E17AA438B0FULL
	}};
	shift = 16;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47E3061941E5648CULL,
		0xDCAFD9BAFB5CA468ULL,
		0xF3C60FEAA06DE058ULL,
		0xEFBA134339E49233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FC60C3283CAC918ULL,
		0xB95FB375F6B948D0ULL,
		0xE78C1FD540DBC0B1ULL,
		0xDF74268673C92467ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CD4860084FEBB0EULL,
		0xFD0140E4D8DFC919ULL,
		0xF2378BF9734F7F9DULL,
		0xE4BB94F882E4E2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0109FD761C00000ULL,
		0x1C9B1BF923239A90ULL,
		0x7F2E69EFF3BFA028ULL,
		0x9F105C9C591E46F1ULL,
		0x00000000001C9772ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5BCD233E5C7422E3ULL,
		0x38C3306ED72D3518ULL,
		0xCC8C2362F9DE71B2ULL,
		0xAD4019F7B01BB5E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C60000000000000ULL,
		0xA30B79A467CB8E84ULL,
		0x364718660DDAE5A6ULL,
		0xBC1991846C5F3BCEULL,
		0x0015A8033EF60376ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF58D16DEDD46BC0CULL,
		0xD8C8B80C980434DCULL,
		0x0D08147EED3DFF6DULL,
		0x0BBBE6FBCC405F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F6EA35E06000000ULL,
		0x064C021A6E7AC68BULL,
		0x3F769EFFB6EC645CULL,
		0x7DE6202F9306840AULL,
		0x000000000005DDF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA9A0B1F57D7B0D8ULL,
		0x6FA099DF8DA1A55EULL,
		0xD52BF5A8A1A3C44AULL,
		0xF6D8DD071167C664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC36000000000000ULL,
		0x6957AEA682C7D5F5ULL,
		0xF1129BE82677E368ULL,
		0xF199354AFD6A2868ULL,
		0x00003DB63741C459ULL
	}};
	shift = 18;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF471A1680F7EC3CULL,
		0x706B04ABC0FE7DEBULL,
		0x5BE7147A14C5E98DULL,
		0x03F861CC5D053654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA1680F7EC3C00000ULL,
		0x4ABC0FE7DEBCF471ULL,
		0x47A14C5E98D706B0ULL,
		0x1CC5D0536545BE71ULL,
		0x0000000000003F86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D42A4FA551623E7ULL,
		0x93F4C8AC8C4CC42FULL,
		0x7DD1C0FBE0A560EFULL,
		0x77E5FCEE0A477EB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF380000000000000ULL,
		0x179EA1527D2A8B11ULL,
		0x77C9FA6456462662ULL,
		0x59BEE8E07DF052B0ULL,
		0x003BF2FE770523BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54A27E2575B0B3FEULL,
		0x87D1C3D418525EBFULL,
		0x53B27F6AC9662E8EULL,
		0x42839C34D08FD662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859FF00000000000ULL,
		0x92F5FAA513F12BADULL,
		0x3174743E8E1EA0C2ULL,
		0x7EB3129D93FB564BULL,
		0x000002141CE1A684ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6789602564898F0EULL,
		0x7F0FD494CA66EDD6ULL,
		0xB1A3C2D62AC552B3ULL,
		0x3625633BF2CE9198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x66789602564898F0ULL,
		0x37F0FD494CA66EDDULL,
		0x8B1A3C2D62AC552BULL,
		0x03625633BF2CE919ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x909E92505F7296ABULL,
		0x9F9B9D1A298DAE0DULL,
		0x0D8AC6BA3DA85E97ULL,
		0x39994CDD0F011734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2505F7296AB00000ULL,
		0xD1A298DAE0D909E9ULL,
		0x6BA3DA85E979F9B9ULL,
		0xCDD0F0117340D8ACULL,
		0x0000000000039994ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D535DF897BF794DULL,
		0x36770B9C079A9FC3ULL,
		0xC2222683F1D74AE7ULL,
		0x4DF35BFCE784C0B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE534000000000000ULL,
		0x7F0E354D77E25EFDULL,
		0x2B9CD9DC2E701E6AULL,
		0x02CB08889A0FC75DULL,
		0x000137CD6FF39E13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDBE9D945A9854894ULL,
		0x0BAB6890DAD94A32ULL,
		0x769E54947E11D5B4ULL,
		0xAFA95E22E98DD098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45A9854894000000ULL,
		0x90DAD94A32DBE9D9ULL,
		0x947E11D5B40BAB68ULL,
		0x22E98DD098769E54ULL,
		0x0000000000AFA95EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB81B666B77FAB4C9ULL,
		0x5DE15BDB890954EDULL,
		0x8E9A081FA1C95B6AULL,
		0x6C2E5E8B36F1E56BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x66B77FAB4C900000ULL,
		0xBDB890954EDB81B6ULL,
		0x81FA1C95B6A5DE15ULL,
		0xE8B36F1E56B8E9A0ULL,
		0x000000000006C2E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86771A64DDE160FDULL,
		0xC1C85107622F5849ULL,
		0x49D49A411EE08939ULL,
		0x9D442E57C271B948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83F4000000000000ULL,
		0x612619DC69937785ULL,
		0x24E70721441D88BDULL,
		0xE521275269047B82ULL,
		0x00027510B95F09C6ULL
	}};
	shift = 14;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x763D058948090F94ULL,
		0xB5744D0DB87A8CFAULL,
		0x5C619E88854383C3ULL,
		0xD0D0BA14A7FD2C59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8F4162520243E500ULL,
		0x5D13436E1EA33E9DULL,
		0x1867A22150E0F0EDULL,
		0x342E8529FF4B1657ULL,
		0x0000000000000034ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23BDAA300171DE9FULL,
		0x387532E5766F1EC3ULL,
		0x77EC693C26F10D2DULL,
		0x1CD132BA3F926500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDAA300171DE9F000ULL,
		0x532E5766F1EC323BULL,
		0xC693C26F10D2D387ULL,
		0x132BA3F92650077EULL,
		0x00000000000001CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3A6410BDDE2D1CFULL,
		0x74E9CE8A5DB0A02BULL,
		0x61AA56C77CEC7E68ULL,
		0x2A9C7A55E09203D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE2D1CF00000000ULL,
		0x5DB0A02BD3A6410BULL,
		0x7CEC7E6874E9CE8AULL,
		0xE09203D861AA56C7ULL,
		0x000000002A9C7A55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A74635426966810ULL,
		0x6993A07BEC10BA46ULL,
		0x76EDD5813F9BA1F7ULL,
		0x65DFB43C591E7A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4080000000000000ULL,
		0xD230D3A31AA134B3ULL,
		0x0FBB4C9D03DF6085ULL,
		0xD4FBB76EAC09FCDDULL,
		0x00032EFDA1E2C8F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x205C8CEFFE1D0119ULL,
		0x6B24CF3E6685CA1FULL,
		0x4AE79080696B4E72ULL,
		0xE853B96267A9756AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8C80000000000000ULL,
		0x0F902E4677FF0E80ULL,
		0x393592679F3342E5ULL,
		0xB52573C84034B5A7ULL,
		0x007429DCB133D4BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3D09FC6602F3D32ULL,
		0x83865D9E8CBDCC79ULL,
		0xE0B161539CC7E5F5ULL,
		0xE0530E7F36DF80F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x980BCF4C80000000ULL,
		0xA32F731E68F427F1ULL,
		0xE731F97D60E19767ULL,
		0xCDB7E03CB82C5854ULL,
		0x000000003814C39FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CEE0400A5A1B93FULL,
		0xBF90040157B21104ULL,
		0x28720B674A50EE52ULL,
		0xB943045119758433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DC08014B43727E0ULL,
		0xF200802AF6422089ULL,
		0x0E416CE94A1DCA57ULL,
		0x28608A232EB08665ULL,
		0x0000000000000017ULL
	}};
	shift = 59;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FFAB27FC0B15E17ULL,
		0x32EE7DEC48190EABULL,
		0x4334170426C707E0ULL,
		0x22F7B6A040AD34B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xC7FD593FE058AF0BULL,
		0x19773EF6240C8755ULL,
		0xA19A0B82136383F0ULL,
		0x117BDB5020569A59ULL
	}};
	shift = 1;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A67FEAFD0693619ULL,
		0x53655698CEBD6001ULL,
		0x808F371C8D39A824ULL,
		0xCAD2D2AD305D6B9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA67FEAFD06936190ULL,
		0x3655698CEBD60012ULL,
		0x08F371C8D39A8245ULL,
		0xAD2D2AD305D6B9C8ULL,
		0x000000000000000CULL
	}};
	shift = 60;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE4297EB113F489FCULL,
		0xEE34F8DFFBBD15F8ULL,
		0x70514C95A971DB7FULL,
		0xD98CD0CA3F7B58BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x852FD6227E913F80ULL,
		0xC69F1BFF77A2BF1CULL,
		0x0A2992B52E3B6FFDULL,
		0x319A1947EF6B17EEULL,
		0x000000000000001BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5119877FD9EEB51ULL,
		0xCE4DE4E16B737443ULL,
		0xFBFD949BF4AAAAB0ULL,
		0xB3B0D136811795C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0x1D288CC3BFECF75AULL,
		0x86726F270B5B9BA2ULL,
		0x07DFECA4DFA55555ULL,
		0x059D8689B408BCAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE78CA33D241EB63ULL,
		0xE34EA07E42CF838EULL,
		0xD890DEB4C0A5726AULL,
		0x5DACC81F11DE1D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CA33D241EB6300ULL,
		0x4EA07E42CF838EAEULL,
		0x90DEB4C0A5726AE3ULL,
		0xACC81F11DE1D44D8ULL,
		0x000000000000005DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x347E3FDCC840C45DULL,
		0x6F755DBC47EEC3F0ULL,
		0xFCC8EEC352BEA0A9ULL,
		0x43B72AB6835AC79EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x68FC7FB9908188BAULL,
		0xDEEABB788FDD87E0ULL,
		0xF991DD86A57D4152ULL,
		0x876E556D06B58F3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA250272A020D8015ULL,
		0xB6F079745C4C2F8CULL,
		0xC4CEAF4467666C01ULL,
		0x2192A552F036FF7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D80150000000000ULL,
		0x4C2F8CA250272A02ULL,
		0x666C01B6F079745CULL,
		0x36FF7DC4CEAF4467ULL,
		0x0000002192A552F0ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5679C93D8F0FD67ULL,
		0x40CFD45CD6D2BE06ULL,
		0x7D9AE9E032C5C2C4ULL,
		0x05D8155041B8E9E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEC787EB380000000ULL,
		0x6B695F0352B3CE49ULL,
		0x1962E1622067EA2EULL,
		0x20DC74F13ECD74F0ULL,
		0x0000000002EC0AA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5641F1DEF45FADB7ULL,
		0x4ABDADF603BAC6AAULL,
		0x59FD31ADE5483E59ULL,
		0x9F389BB34058E506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC83E3BDE8BF5B6EULL,
		0x957B5BEC07758D54ULL,
		0xB3FA635BCA907CB2ULL,
		0x3E71376680B1CA0CULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF979A4D1B5042DBULL,
		0x75A944B8DBDF86A7ULL,
		0xA963581B877E70B4ULL,
		0x1E7273EEFE639BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36A085B600000000ULL,
		0xB7BF0D4F5F2F349AULL,
		0x0EFCE168EB528971ULL,
		0xFCC737F352C6B037ULL,
		0x000000003CE4E7DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE625AB96ADA5241ULL,
		0x7BDD21F4A764DF57ULL,
		0xB598BDD9BC77C422ULL,
		0xAA854944DE2591E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB56D2920800000ULL,
		0xFA53B26FABF7312DULL,
		0xECDE3BE2113DEE90ULL,
		0xA26F12C8F35ACC5EULL,
		0x00000000005542A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3316F93B420122B1ULL,
		0xD725961635949D3DULL,
		0x0209F49416B92A9AULL,
		0xBC30C228ACDBD91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB100000000000000ULL,
		0x3D3316F93B420122ULL,
		0x9AD725961635949DULL,
		0x1F0209F49416B92AULL,
		0x00BC30C228ACDBD9ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x92BBE3BBC3EB84E6ULL,
		0x18BE64084517E7B5ULL,
		0xF95B6E6580D5568FULL,
		0x6D48E23C882208CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x592BBE3BBC3EB84EULL,
		0xF18BE64084517E7BULL,
		0xAF95B6E6580D5568ULL,
		0x06D48E23C882208CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC7EDC13A9961C11ULL,
		0xF895AA79361A65EAULL,
		0x9E927E33BBBA4031ULL,
		0x7AB0B35FB88B79E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0880000000000000ULL,
		0xF5763F6E09D4CB0EULL,
		0x18FC4AD53C9B0D32ULL,
		0xF3CF493F19DDDD20ULL,
		0x003D5859AFDC45BCULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5A15712200CF418ULL,
		0x43BBC0D7CD31E718ULL,
		0xDB19A72E7436E8BFULL,
		0x2EDBF0EEE5A21FE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF41800000000000ULL,
		0x1E718D5A15712200ULL,
		0x6E8BF43BBC0D7CD3ULL,
		0x21FE2DB19A72E743ULL,
		0x000002EDBF0EEE5AULL
	}};
	shift = 20;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0957D86C7C09AC5AULL,
		0x8C442FE150AAE247ULL,
		0xB551D6FF76879864ULL,
		0xC3D7D5558A996187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFB0D8F81358B400ULL,
		0x885FC2A155C48E12ULL,
		0xA3ADFEED0F30C918ULL,
		0xAFAAAB1532C30F6AULL,
		0x0000000000000187ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5984A90A4560595EULL,
		0xAB57DAC07661D9E4ULL,
		0x9E287608F31D1D9CULL,
		0x83ACE6B5E43D5E50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x45984A90A4560595ULL,
		0xCAB57DAC07661D9EULL,
		0x09E287608F31D1D9ULL,
		0x083ACE6B5E43D5E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6882EC1373C87AA4ULL,
		0x666EFDE663BA87A9ULL,
		0x2C577788C40C582CULL,
		0xD5BDD8060B101CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6882EC1373C87AA4ULL,
		0x666EFDE663BA87A9ULL,
		0x2C577788C40C582CULL,
		0xD5BDD8060B101CE0ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD2237B5B059000AULL,
		0x2BAE88C292875467ULL,
		0x424FF3934044B406ULL,
		0x8448D38DFD49F179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE911BDAD82C8005ULL,
		0x15D744614943AA33ULL,
		0xA127F9C9A0225A03ULL,
		0x422469C6FEA4F8BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x189C8C102F46DE6BULL,
		0x0FAE296EE08197D7ULL,
		0xBD25D1D4E363AE27ULL,
		0x4B8E47BE5EB6BBECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817A36F358000000ULL,
		0x77040CBEB8C4E460ULL,
		0xA71B1D71387D714BULL,
		0xF2F5B5DF65E92E8EULL,
		0x00000000025C723DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 229;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D2DC70E6E71E92FULL,
		0x6162C428D6CB9CE3ULL,
		0x258333C41846F591ULL,
		0x8FFECDC663418D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C7A4BC000000000ULL,
		0xB2E738E34B71C39BULL,
		0x11BD645858B10A35ULL,
		0xD0634A0960CCF106ULL,
		0x00000023FFB37198ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE86958A57795460ULL,
		0xD9010C7F4D927981ULL,
		0x1D6309CE83DA4ED1ULL,
		0x70B7AEDA725EFA3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x07FA1A56295DE551ULL,
		0x47640431FD3649E6ULL,
		0xE8758C273A0F693BULL,
		0x01C2DEBB69C97BE8ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05FEB6F90639B850ULL,
		0x0BD4A63449607689ULL,
		0xF8A1757728250409ULL,
		0xAA4F72F7BC223F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF90639B850000000ULL,
		0x344960768905FEB6ULL,
		0x77282504090BD4A6ULL,
		0xF7BC223F10F8A175ULL,
		0x0000000000AA4F72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97B631D7B56CD5B5ULL,
		0x1C19C00433D8F946ULL,
		0xE51046996235ACBEULL,
		0xFBA72FBFC268BB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5B356D400000000ULL,
		0xCF63E51A5ED8C75EULL,
		0x88D6B2F870670010ULL,
		0x09A2ECAB94411A65ULL,
		0x00000003EE9CBEFFULL
	}};
	shift = 30;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E55031F65F0AAFBULL,
		0x26516A348BF74971ULL,
		0xD20B4E503A896552ULL,
		0xEC912E53F044F92FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD800000000000000ULL,
		0x8972A818FB2F8557ULL,
		0x91328B51A45FBA4BULL,
		0x7E905A7281D44B2AULL,
		0x076489729F8227C9ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9AA20A2B2174B032ULL,
		0xD19D85B3E0F1E889ULL,
		0x09F84229CC80C529ULL,
		0x421064172B65098DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6A8828AC85D2C0C8ULL,
		0x467616CF83C7A226ULL,
		0x27E108A7320314A7ULL,
		0x0841905CAD942634ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4BB325ACB37C973CULL,
		0xC3E56FD2B2959C12ULL,
		0x60AC4DA59EB25A0DULL,
		0xAF061C5562FFC59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x497664B5966F92E7ULL,
		0xB87CADFA5652B382ULL,
		0x4C1589B4B3D64B41ULL,
		0x15E0C38AAC5FF8B3ULL
	}};
	shift = 3;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB41E4EAFCE23CB96ULL,
		0xB91D97B43B09C397ULL,
		0x88C0E5590E25D692ULL,
		0x7873FC93CCF25D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0793ABF388F2E580ULL,
		0x4765ED0EC270E5EDULL,
		0x303956438975A4AEULL,
		0x1CFF24F33C974862ULL,
		0x000000000000001EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9624C3A53747832ULL,
		0xFAFBE279C9DAE538ULL,
		0x8B2AFF56AD4E377AULL,
		0x97A0C56CE3D1C146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6E8F064000000000ULL,
		0x3B5CA7172C49874AULL,
		0xA9C6EF5F5F7C4F39ULL,
		0x7A3828D1655FEAD5ULL,
		0x00000012F418AD9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A552E60139F264EULL,
		0xD97D153E7C643D08ULL,
		0xD76F0B7B14B74084ULL,
		0x06B4398B83583F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x139F264E00000000ULL,
		0x7C643D088A552E60ULL,
		0x14B74084D97D153EULL,
		0x83583F02D76F0B7BULL,
		0x0000000006B4398BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3840DE877F0E787EULL,
		0x5FDEE78800C871E3ULL,
		0xC10D631378FAF561ULL,
		0xE18B1FD536CEBA77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EFE1CF0FC000000ULL,
		0x100190E3C67081BDULL,
		0x26F1F5EAC2BFBDCFULL,
		0xAA6D9D74EF821AC6ULL,
		0x0000000001C3163FULL
	}};
	shift = 39;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23690D5B3DDE0006ULL,
		0x58FD68F4575FE6F8ULL,
		0xD7766EBD162B4734ULL,
		0x30C0DF37D9891816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0018000000000000ULL,
		0x9BE08DA4356CF778ULL,
		0x1CD163F5A3D15D7FULL,
		0x605B5DD9BAF458ADULL,
		0x0000C3037CDF6624ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5677FF9E09EDA055ULL,
		0xABA3C552D39E4A2CULL,
		0x786A0F7AE450FC15ULL,
		0x0CE837F397C38E97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x8ACEFFF3C13DB40AULL,
		0xB57478AA5A73C945ULL,
		0xEF0D41EF5C8A1F82ULL,
		0x019D06FE72F871D2ULL
	}};
	shift = 3;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9F65417D3CF2051ULL,
		0xB00A255CC6DCFF43ULL,
		0xE1A5CFC2875FC810ULL,
		0x35D496D2A4EA9D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x505F4F3C81440000ULL,
		0x95731B73FD0EA7D9ULL,
		0x3F0A1D7F2042C028ULL,
		0x5B4A93AA766B8697ULL,
		0x000000000000D752ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A9C88670A97A53DULL,
		0x7BD00C3C5ED3D875ULL,
		0x5BBD442494A1624BULL,
		0x1C00E55D6D17F053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x53D0000000000000ULL,
		0x8755A9C88670A97AULL,
		0x24B7BD00C3C5ED3DULL,
		0x0535BBD442494A16ULL,
		0x0001C00E55D6D17FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF6C83C19ACEB441ULL,
		0xA44EDD857DC4D8A0ULL,
		0xA6E9623BE279285EULL,
		0x625A291DDF7F9866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD675A20800000000ULL,
		0xEE26C5077B641E0CULL,
		0x13C942F52276EC2BULL,
		0xFBFCC335374B11DFULL,
		0x0000000312D148EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E5BAF7F9140EF5DULL,
		0x7DCE35404D90838FULL,
		0xFC9E7F8E7700F335ULL,
		0x4F7AE25524501139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEBA000000000000ULL,
		0x071E7CB75EFF2281ULL,
		0xE66AFB9C6A809B21ULL,
		0x2273F93CFF1CEE01ULL,
		0x00009EF5C4AA48A0ULL
	}};
	shift = 15;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31A54D06DCE6748FULL,
		0xD8C39E600CB4724AULL,
		0x227B10F0C04570A2ULL,
		0x72D4D919DA0AB180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0DB9CCE91E00000ULL,
		0xCC01968E494634A9ULL,
		0x1E1808AE145B1873ULL,
		0x233B415630044F62ULL,
		0x00000000000E5A9BULL
	}};
	shift = 43;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D7C5CED1DA66733ULL,
		0x93B59C5C958F4A5DULL,
		0x76E5A97E52F6EE91ULL,
		0xF0F611311FDE7114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA3B4CCE66000000ULL,
		0xB92B1E94BABAF8B9ULL,
		0xFCA5EDDD23276B38ULL,
		0x623FBCE228EDCB52ULL,
		0x0000000001E1EC22ULL
	}};
	shift = 39;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD692C6A793FA92B7ULL,
		0xE289113E8137BD03ULL,
		0x03C8624CB218D2FFULL,
		0x8FEBBBD33BAFA933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x692C6A793FA92B70ULL,
		0x289113E8137BD03DULL,
		0x3C8624CB218D2FFEULL,
		0xFEBBBD33BAFA9330ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8310F17D9EBBB66FULL,
		0x337C7AB613AA53D3ULL,
		0x9C0D51B7C51FDE09ULL,
		0xD74F80BFA5C65013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDB37800000000000ULL,
		0x29E9C18878BECF5DULL,
		0xEF0499BE3D5B09D5ULL,
		0x2809CE06A8DBE28FULL,
		0x00006BA7C05FD2E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84DD8ACADC2E4C10ULL,
		0x920A7712870C93C2ULL,
		0xE8510EA45E7AF6B7ULL,
		0x954F8C5D95CCDD37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B2B70B930400000ULL,
		0xDC4A1C324F0A1376ULL,
		0x3A9179EBDADE4829ULL,
		0x3176573374DFA144ULL,
		0x000000000002553EULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E6F94C7B3DAE71ULL,
		0xC81639FD5F89C6EEULL,
		0x2B13F32FD696EE2CULL,
		0x8345C0B78C573555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CDF298F67B5CE2ULL,
		0x902C73FABF138DDCULL,
		0x5627E65FAD2DDC59ULL,
		0x068B816F18AE6AAAULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE601A04FD0189AFEULL,
		0x096EFBFE024F615BULL,
		0x242156596514B7A6ULL,
		0xC534D1074C742D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x06813F40626BF800ULL,
		0xBBEFF8093D856F98ULL,
		0x8559659452DE9825ULL,
		0xD3441D31D0B67C90ULL,
		0x0000000000000314ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3EB5B448121B8788ULL,
		0x5B60BF45160026F7ULL,
		0x7D47AB58CCB72530ULL,
		0x33632296D1D99FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x370F100000000000ULL,
		0x004DEE7D6B689024ULL,
		0x6E4A60B6C17E8A2CULL,
		0xB33FBCFA8F56B199ULL,
		0x00000066C6452DA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1FC515EA97D65531ULL,
		0xF2FD28F0414AACE0ULL,
		0x86EC8E57B0A8800AULL,
		0x5AA41F3091398F62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4BEB2A9880000000ULL,
		0x20A556700FE28AF5ULL,
		0xD8544005797E9478ULL,
		0x489CC7B14376472BULL,
		0x000000002D520F98ULL
	}};
	shift = 33;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3B9F1E6DAAAB0A2ULL,
		0xACFD974814D3B41FULL,
		0xE54608BAF64AD84FULL,
		0xBDC181A39C1757ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5614400000000000ULL,
		0x7683F6773E3CDB55ULL,
		0x5B09F59FB2E9029AULL,
		0xEAF59CA8C1175EC9ULL,
		0x000017B830347382ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB01FD263456B0A3AULL,
		0x8B95A7361E749F71ULL,
		0xF908CE578F62F0E2ULL,
		0x0714A98E456401C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE931A2B5851D000ULL,
		0xAD39B0F3A4FB8D80ULL,
		0x4672BC7B1787145CULL,
		0xA54C722B200E47C8ULL,
		0x0000000000000038ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A8513D357A5EAF7ULL,
		0x824213031F24A5C2ULL,
		0x88600B7F266B2578ULL,
		0x15B0F410B8775F06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC00000000000000ULL,
		0x09EA144F4D5E97ABULL,
		0xE209084C0C7C9297ULL,
		0x1A21802DFC99AC95ULL,
		0x0056C3D042E1DD7CULL
	}};
	shift = 6;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x048AEE763C48D492ULL,
		0x2C16D9A0B8FD356BULL,
		0x553594D44A641DDAULL,
		0x4BA845E8BA6A30AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x15DCEC7891A92400ULL,
		0x2DB34171FA6AD609ULL,
		0x6B29A894C83BB458ULL,
		0x508BD174D4615EAAULL,
		0x0000000000000097ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 183;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0726B25FE8650249ULL,
		0x2AE925DF0408F634ULL,
		0x2A075A2329CC78C9ULL,
		0x5866F6FE28C6F3C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0CA049200000000ULL,
		0x0811EC680E4D64BFULL,
		0x5398F19255D24BBEULL,
		0x518DE784540EB446ULL,
		0x00000000B0CDEDFCULL
	}};
	shift = 31;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1B7EA91231B8A747ULL,
		0x567D4CE9B4C01EA0ULL,
		0x6AC1E26F9FF2E350ULL,
		0x1440A0A0752675FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31B8A74700000000ULL,
		0xB4C01EA01B7EA912ULL,
		0x9FF2E350567D4CE9ULL,
		0x752675FD6AC1E26FULL,
		0x000000001440A0A0ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DFBAFEAD3116C36ULL,
		0xB8E89D0427B3AE03ULL,
		0x9EB586143451D18EULL,
		0xEEF1F03BCF0C1CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x16C3600000000000ULL,
		0x3AE034DFBAFEAD31ULL,
		0x1D18EB8E89D0427BULL,
		0xC1CEA9EB58614345ULL,
		0x00000EEF1F03BCF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C53CC1AB64AA119ULL,
		0xFFC9B4C2C88C292AULL,
		0x6BE986876DE82360ULL,
		0x27EF910C074BE2B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE60D5B25508C8000ULL,
		0xDA61644614953629ULL,
		0xC343B6F411B07FE4ULL,
		0xC88603A5F158B5F4ULL,
		0x00000000000013F7ULL
	}};
	shift = 49;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93444EAAE577E907ULL,
		0xD5A6FAB6140AD2B7ULL,
		0xDE246AA3DFE87374ULL,
		0x76EA3605EBBBA70BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9D55CAEFD20E0000ULL,
		0xF56C2815A56F2688ULL,
		0xD547BFD0E6E9AB4DULL,
		0x6C0BD7774E17BC48ULL,
		0x000000000000EDD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA22A8892942A810ULL,
		0x2773C6188CAF7B51ULL,
		0xC5BF6ED4F2094D48ULL,
		0x2C3C2DAF84BCDEC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA224A50AA0400000ULL,
		0x186232BDED46A88AULL,
		0xBB53C82535209DCFULL,
		0xB6BE12F37B1B16FDULL,
		0x000000000000B0F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x121486AFB5ADC46CULL,
		0x8A9EF610166D5A68ULL,
		0xD5756D64583AACBBULL,
		0xE7FFF6DB5F074DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21486AFB5ADC46C0ULL,
		0xA9EF610166D5A681ULL,
		0x5756D64583AACBB8ULL,
		0x7FFF6DB5F074DAEDULL,
		0x000000000000000EULL
	}};
	shift = 60;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4BADBECA7B6A0AF8ULL,
		0x7911075EF575DA39ULL,
		0xF51A10037483123BULL,
		0xD27D0DBFB3F77032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5057C0000000000ULL,
		0xBAED1CA5D6DF653DULL,
		0x41891DBC8883AF7AULL,
		0xFBB8197A8D0801BAULL,
		0x000000693E86DFD9ULL
	}};
	shift = 25;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x338306B526BB7AF6ULL,
		0x8B20F9E48D65091CULL,
		0xDFEB5459026D58BDULL,
		0x1E29EB1385C6E3DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBD8000000000000ULL,
		0x2470CE0C1AD49AEDULL,
		0x62F62C83E7923594ULL,
		0x8F7F7FAD516409B5ULL,
		0x000078A7AC4E171BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9821B105C52174BFULL,
		0x107274447D321268ULL,
		0x02297407A81A5E79ULL,
		0x3D739367B81F1835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C52174BF0000000ULL,
		0x47D3212689821B10ULL,
		0x7A81A5E791072744ULL,
		0x7B81F18350229740ULL,
		0x0000000003D73936ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8281BD47447E72E5ULL,
		0xF1FB44B9CD81CBC2ULL,
		0x91C218A0C8BD9025ULL,
		0xC05F58C4A38304A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x281BD47447E72E50ULL,
		0x1FB44B9CD81CBC28ULL,
		0x1C218A0C8BD9025FULL,
		0x05F58C4A38304A19ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C7ED1AD947C9450ULL,
		0xB7C8B319391131F8ULL,
		0xCBC94081C431A552ULL,
		0xFEE45B6A34FDBD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5B28F928A0000000ULL,
		0x32722263F078FDA3ULL,
		0x0388634AA56F9166ULL,
		0xD469FB7AB1979281ULL,
		0x0000000001FDC8B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDD478A3B04FD433ULL,
		0x5982863977E515DBULL,
		0x8489C83801BFBAFEULL,
		0xDEA2B5B5ADD1DC94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC13F50CC0000000ULL,
		0x5DF94576F3751E28ULL,
		0x006FEEBF9660A18EULL,
		0x6B7477252122720EULL,
		0x0000000037A8AD6DULL
	}};
	shift = 34;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53D09B53C1276927ULL,
		0x419F4BD7E261EFEDULL,
		0xAC26BF092CEFAB49ULL,
		0x9AD0BE5F0C4F3074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDA9E093B49380000ULL,
		0x5EBF130F7F6A9E84ULL,
		0xF849677D5A4A0CFAULL,
		0xF2F8627983A56135ULL,
		0x000000000004D685ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x22C692E0002F4618ULL,
		0x653E762BB35BA941ULL,
		0x7D23C7408B068E84ULL,
		0x4F6DBA4E7240BC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1860000000000000ULL,
		0xA5048B1A4B8000BDULL,
		0x3A1194F9D8AECD6EULL,
		0xF035F48F1D022C1AULL,
		0x00013DB6E939C902ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6AAE699052E803DULL,
		0x2990C2F71920209CULL,
		0xC4D6F07D9AF776B0ULL,
		0x4F6FB7CDAD868FF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x052E803D00000000ULL,
		0x1920209CA6AAE699ULL,
		0x9AF776B02990C2F7ULL,
		0xAD868FF4C4D6F07DULL,
		0x000000004F6FB7CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB0C6260C99D4330FULL,
		0xCFF949D492053EC6ULL,
		0x5DF3EEF1A272989EULL,
		0x9E313688FA655A64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC6260C99D4330F00ULL,
		0xF949D492053EC6B0ULL,
		0xF3EEF1A272989ECFULL,
		0x313688FA655A645DULL,
		0x000000000000009EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0BD9B7C8F6C6DFDCULL,
		0xB34B85BDCC8426F2ULL,
		0x7FC0A4068F5CA5FEULL,
		0x183122C1523CD24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB800000000000000ULL,
		0xE417B36F91ED8DBFULL,
		0xFD66970B7B99084DULL,
		0x9CFF81480D1EB94BULL,
		0x0030624582A479A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DB36019D1618510ULL,
		0x91034DFDAF0081D3ULL,
		0xB22B65E7D91B7E1CULL,
		0x107C7C4C56C708B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7458614400000000ULL,
		0x6BC02074E76CD806ULL,
		0xF646DF872440D37FULL,
		0x15B1C22CAC8AD979ULL,
		0x00000000041F1F13ULL
	}};
	shift = 34;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD61394643091A77AULL,
		0xC10868A2F8DF4DCCULL,
		0x9FC1BD1BAF51E66EULL,
		0xDB5385E9E7C3414CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09CA321848D3BD00ULL,
		0x8434517C6FA6E66BULL,
		0xE0DE8DD7A8F33760ULL,
		0xA9C2F4F3E1A0A64FULL,
		0x000000000000006DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9F44DB08BFEA5DE2ULL,
		0x9FF09C96EF41533FULL,
		0x0F1C7F50D3F0DF06ULL,
		0x11FE9F141E19A700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0xFCFA26D845FF52EFULL,
		0x34FF84E4B77A0A99ULL,
		0x0078E3FA869F86F8ULL,
		0x008FF4F8A0F0CD38ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C8F982CE6023BF6ULL,
		0xA1446BD5AE10FD6BULL,
		0xF54F1818A5EDA119ULL,
		0x75E346D29876EA92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x982CE6023BF60000ULL,
		0x6BD5AE10FD6B1C8FULL,
		0x1818A5EDA119A144ULL,
		0x46D29876EA92F54FULL,
		0x00000000000075E3ULL
	}};
	shift = 48;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CA8B8C729B92040ULL,
		0x3AFCD5A306C6D241ULL,
		0xEC159B897F6A50AEULL,
		0x3119719A78E912B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08E545C6394DC902ULL,
		0x71D7E6AD18363692ULL,
		0xA760ACDC4BFB5285ULL,
		0x0188CB8CD3C74895ULL
	}};
	shift = 5;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1AC2FCD74B8DA768ULL,
		0xFE877856D06F1D71ULL,
		0x700F25D4D8FCBE4DULL,
		0x406AC68791122EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4ED0000000000000ULL,
		0x3AE23585F9AE971BULL,
		0x7C9BFD0EF0ADA0DEULL,
		0x5D62E01E4BA9B1F9ULL,
		0x000080D58D0F2224ULL
	}};
	shift = 15;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF4F59CE8A1960BCBULL,
		0x455035B19EF1734DULL,
		0x6CB9C3E1EED24523ULL,
		0x1F1F97EDFED84873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39D1432C17960000ULL,
		0x6B633DE2E69BE9EBULL,
		0x87C3DDA48A468AA0ULL,
		0x2FDBFDB090E6D973ULL,
		0x0000000000003E3FULL
	}};
	shift = 47;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43E4513DD7159996ULL,
		0x1345C3E18045069CULL,
		0xAC0B0B71E50FB42BULL,
		0x891C85734BE4EFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD7159996000000ULL,
		0xE18045069C43E451ULL,
		0x71E50FB42B1345C3ULL,
		0x734BE4EFB3AC0B0BULL,
		0x0000000000891C85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2291B67D75049337ULL,
		0xE829EF28304914C3ULL,
		0x3B9F502835AD1BC4ULL,
		0x71BF300EAA9F9BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6CFAEA09266E0000ULL,
		0xDE50609229864523ULL,
		0xA0506B5A3789D053ULL,
		0x601D553F375A773EULL,
		0x000000000000E37EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6DA32F255FA9C5A2ULL,
		0x078EC3187551AE5AULL,
		0xC199FC7C7252DB05ULL,
		0xCC85C4A0A80BDAB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0x69B68CBC957EA716ULL,
		0x141E3B0C61D546B9ULL,
		0xD30667F1F1C94B6CULL,
		0x0332171282A02F6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A38A0BD7E37FCD2ULL,
		0x4A9FCEE7B28D8EB7ULL,
		0xCFF372B66AEEB90AULL,
		0xDDE38B540BAD296CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x82F5F8DFF3480000ULL,
		0x3B9ECA363ADDA8E2ULL,
		0xCAD9ABBAE4292A7FULL,
		0x2D502EB4A5B33FCDULL,
		0x000000000003778EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16BBED1A9A0B0B66ULL,
		0x2D81A0EE9747E2C4ULL,
		0x455DCBC94CB6E98AULL,
		0x2C022718CB572267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x05AEFB46A682C2D9ULL,
		0x8B60683BA5D1F8B1ULL,
		0xD15772F2532DBA62ULL,
		0x0B0089C632D5C899ULL
	}};
	shift = 2;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC008DE8B9F52929ULL,
		0xB33BEF100525C011ULL,
		0x64F4D66DA8F57FD8ULL,
		0xADFDC1F614636E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2520000000000000ULL,
		0x02378011BD173EA5ULL,
		0xFB16677DE200A4B8ULL,
		0xCFCC9E9ACDB51EAFULL,
		0x0015BFB83EC28C6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA7A1ECD61BCD303EULL,
		0x965BAF86EBE42C1BULL,
		0x091979BF44715AADULL,
		0xC9F31BC9F3D546CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61BCD303E0000000ULL,
		0x6EBE42C1BA7A1ECDULL,
		0xF44715AAD965BAF8ULL,
		0x9F3D546CF091979BULL,
		0x000000000C9F31BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD33A655AC913C3CBULL,
		0x3A3E95035BB28744ULL,
		0x4DF6B1E91B1F1B31ULL,
		0x17E01FF10F5D1DC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA655AC913C3CB000ULL,
		0xE95035BB28744D33ULL,
		0x6B1E91B1F1B313A3ULL,
		0x01FF10F5D1DC74DFULL,
		0x000000000000017EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F17B5D8C68B0626ULL,
		0x8E8804AC87DAA0E4ULL,
		0x2C32C5A0906B1280ULL,
		0x6BFB57ECCC7E9535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1300000000000000ULL,
		0x72378BDAEC634583ULL,
		0x404744025643ED50ULL,
		0x9A961962D0483589ULL,
		0x0035FDABF6663F4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x645FB55E949DB3E3ULL,
		0x2928DE3A3CFD4524ULL,
		0x69EAD2D7768A2058ULL,
		0x659B53351139800BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6CF8C00000000000ULL,
		0x51491917ED57A527ULL,
		0x88160A4A378E8F3FULL,
		0x6002DA7AB4B5DDA2ULL,
		0x00001966D4CD444EULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41265D996A20BB75ULL,
		0xF03B2D0CF625C716ULL,
		0x1E4D227D3D05615AULL,
		0xB2BD724715DCFECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x932ECCB5105DBA80ULL,
		0x1D96867B12E38B20ULL,
		0x26913E9E82B0AD78ULL,
		0x5EB9238AEE7F678FULL,
		0x0000000000000059ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x438AF2101CDD7177ULL,
		0xE98740EEF0A437B3ULL,
		0x5457F3941B26AB6FULL,
		0xAEF51BAD0DFE3B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42039BAE2EE00000ULL,
		0x1DDE1486F668715EULL,
		0x728364D56DFD30E8ULL,
		0x75A1BFC76C8A8AFEULL,
		0x000000000015DEA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D9D98B4705FD214ULL,
		0x3A90BD933D2F005DULL,
		0x98AD1F97CCF83478ULL,
		0x36A68404FCFEB99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3168E0BFA428000ULL,
		0x17B267A5E00BA5B3ULL,
		0xA3F2F99F068F0752ULL,
		0xD0809F9FD733F315ULL,
		0x00000000000006D4ULL
	}};
	shift = 51;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2BBCED76B93F1E2ULL,
		0x0546359BA80489FBULL,
		0x16D79DDBECE232A7ULL,
		0x2B8C8D6CCF409353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76B93F1E20000000ULL,
		0xBA80489FBB2BBCEDULL,
		0xBECE232A70546359ULL,
		0xCCF40935316D79DDULL,
		0x0000000002B8C8D6ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80470C5BC2E14B69ULL,
		0x7CFAB950D3E0EB48ULL,
		0x8406095D2B808B7FULL,
		0xCA2EADD050B6C862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5B48000000000000ULL,
		0x5A44023862DE170AULL,
		0x5BFBE7D5CA869F07ULL,
		0x431420304AE95C04ULL,
		0x000651756E8285B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6903845E5F281F5ULL,
		0xA72556CF8D57CD5EULL,
		0xE9E5371C9FA5AE66ULL,
		0x27967DBEB7E2CDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2F940FA80000000ULL,
		0xC6ABE6AF7B481C22ULL,
		0x4FD2D7335392AB67ULL,
		0x5BF166ED74F29B8EULL,
		0x0000000013CB3EDFULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4C97FA745C6BCEBULL,
		0x354888B0AAF8A144ULL,
		0x1478E48D8196ACB3ULL,
		0xBDBE3FF4446D0590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE758000000000000ULL,
		0x0A26264BFD3A2E35ULL,
		0x6599AA44458557C5ULL,
		0x2C80A3C7246C0CB5ULL,
		0x0005EDF1FFA22368ULL
	}};
	shift = 13;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8682745AD238E07ULL,
		0x2DF9E8C70EA4E7B0ULL,
		0x7C19B25E0D4E5C77ULL,
		0x3068F47A88B0B9CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA09D16B48E381C00ULL,
		0xE7A31C3A939EC3A1ULL,
		0x66C978353971DCB7ULL,
		0xA3D1EA22C2E73DF0ULL,
		0x00000000000000C1ULL
	}};
	shift = 54;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9232779ACE87AE6EULL,
		0xDC266006E7C1034EULL,
		0x326962C4022DEF6AULL,
		0x5FAAF06564C2652FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE6E0000000000000ULL,
		0x34E9232779ACE87AULL,
		0xF6ADC266006E7C10ULL,
		0x52F326962C4022DEULL,
		0x0005FAAF06564C26ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4D47893C5CB7A15ULL,
		0x444513AD7DA17163ULL,
		0xB95DA2B894597D82ULL,
		0x75C18DBF144DF14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB7A150000000000ULL,
		0xA17163C4D47893C5ULL,
		0x597D82444513AD7DULL,
		0x4DF14CB95DA2B894ULL,
		0x00000075C18DBF14ULL
	}};
	shift = 24;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x90E7B25AFF4E2686ULL,
		0x8BFB42EB2B2E93FAULL,
		0x03F0A718857361E0ULL,
		0x2C237794D340F758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD0C0000000000000ULL,
		0x7F521CF64B5FE9C4ULL,
		0x3C117F685D6565D2ULL,
		0xEB007E14E310AE6CULL,
		0x0005846EF29A681EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38A3D79574C42778ULL,
		0x608E59DA7D5DC8FCULL,
		0xA8CC8C79D54C1E01ULL,
		0xC71185DBBB2DA39CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09DE000000000000ULL,
		0x723F0E28F5E55D31ULL,
		0x0780582396769F57ULL,
		0x68E72A33231E7553ULL,
		0x000031C46176EECBULL
	}};
	shift = 18;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD134694D71D26E7ULL,
		0xB7BF0793FCE1E9AAULL,
		0x7E2C31EA76F9C6AAULL,
		0x928ACFCD552257BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3800000000000000ULL,
		0x55E89A34A6B8E937ULL,
		0x55BDF83C9FE70F4DULL,
		0xFBF1618F53B7CE35ULL,
		0x0494567E6AA912BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2984CF4D47472A72ULL,
		0x10537D1654A2DC3CULL,
		0xE90B90992F949B98ULL,
		0x3BC63976C4DE13FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33D351D1CA9C8000ULL,
		0xDF459528B70F0A61ULL,
		0xE4264BE526E60414ULL,
		0x8E5DB13784FFBA42ULL,
		0x0000000000000EF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB04F57F4C81775F7ULL,
		0xBAEE43EADF92FABDULL,
		0x869DD9E2C7EC88D7ULL,
		0x0EF5308820BEF14FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D5FD3205DD7DC00ULL,
		0xB90FAB7E4BEAF6C1ULL,
		0x77678B1FB2235EEBULL,
		0xD4C22082FBC53E1AULL,
		0x000000000000003BULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFDFBDE4DB18E603ULL,
		0x59DE601A6355DE49ULL,
		0x08C9BFF29ADE80ACULL,
		0x0B0283C2597B30E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18E6030000000000ULL,
		0x55DE49FFDFBDE4DBULL,
		0xDE80AC59DE601A63ULL,
		0x7B30E608C9BFF29AULL,
		0x0000000B0283C259ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x244E51FA944D672DULL,
		0xE56AA9E7605FE728ULL,
		0xDBFD84FB7992657FULL,
		0x8CE8000A06969FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2728FD4A26B39680ULL,
		0xB554F3B02FF39412ULL,
		0xFEC27DBCC932BFF2ULL,
		0x740005034B4FFEEDULL,
		0x0000000000000046ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89C22A16D06B7605ULL,
		0x8FCCFD26921EBEC7ULL,
		0xA875397888B9B07DULL,
		0xABF82EB39E79C650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0x789C22A16D06B760ULL,
		0xD8FCCFD26921EBECULL,
		0x0A875397888B9B07ULL,
		0x0ABF82EB39E79C65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA38122D7828A690EULL,
		0xCE3FAE3F64E75A90ULL,
		0x5B173EAB00F596A6ULL,
		0x4DC702375306A794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x122D7828A690E000ULL,
		0xFAE3F64E75A90A38ULL,
		0x73EAB00F596A6CE3ULL,
		0x702375306A7945B1ULL,
		0x00000000000004DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB919ED06E0BAB694ULL,
		0x220522E64C5B7F63ULL,
		0x2D58FA5B85E59A65ULL,
		0xB5FBB08FC0AB08A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0BAB69400000000ULL,
		0x4C5B7F63B919ED06ULL,
		0x85E59A65220522E6ULL,
		0xC0AB08A82D58FA5BULL,
		0x00000000B5FBB08FULL
	}};
	shift = 32;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE290F56466059D2EULL,
		0xCAA8351F917EE2DFULL,
		0xF2D60BE03D94CE0AULL,
		0x17C00E17B470EAD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5C0000000000000ULL,
		0x5BFC521EAC8CC0B3ULL,
		0xC1595506A3F22FDCULL,
		0x5A5E5AC17C07B299ULL,
		0x0002F801C2F68E1DULL
	}};
	shift = 11;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C674E626F66081CULL,
		0x1816D9DB3E7FEA09ULL,
		0x9746C620169ECA0EULL,
		0xC640CE18871FAA6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A73137B3040E00ULL,
		0x0B6CED9F3FF504C6ULL,
		0xA363100B4F65070CULL,
		0x20670C438FD5374BULL,
		0x0000000000000063ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42FC243E9D7FFF84ULL,
		0x6F8322D6C395CD21ULL,
		0x46A441E8B6A8AB99ULL,
		0x21F7C0BEC37AC080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD7FFF84000000000ULL,
		0x395CD2142FC243E9ULL,
		0x6A8AB996F8322D6CULL,
		0x37AC08046A441E8BULL,
		0x000000021F7C0BECULL
	}};
	shift = 28;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8607A79502395EA2ULL,
		0x6DA5C9B21FBC6D1EULL,
		0x1E885E852B7714B7ULL,
		0x8881C1C553366F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E5408E57A880000ULL,
		0x26C87EF1B47A181EULL,
		0x7A14ADDC52DDB697ULL,
		0x07154CD9BC547A21ULL,
		0x0000000000022207ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37F79F15BB02C09AULL,
		0x3818DD768B5F6DA7ULL,
		0xD470837180A03266ULL,
		0xAB214176DAC6D731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCF8ADD81604D000ULL,
		0xC6EBB45AFB6D39BFULL,
		0x841B8C05019331C0ULL,
		0x0A0BB6D636B98EA3ULL,
		0x0000000000000559ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95510ED1EB6CDC69ULL,
		0x9DA63B7C0538AA98ULL,
		0x1660E22CA73FA0B7ULL,
		0xA83BCA93617AA4BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E34800000000000ULL,
		0x554C4AA88768F5B6ULL,
		0xD05BCED31DBE029CULL,
		0x525E0B307116539FULL,
		0x0000541DE549B0BDULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x670E8B91D5B0AE54ULL,
		0x56C673AB78145653ULL,
		0xAF1EE2B82EEBA95DULL,
		0x090701417B47E5AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAD8572A000000000ULL,
		0xC0A2B29B38745C8EULL,
		0x775D4AEAB6339D5BULL,
		0xDA3F2D5578F715C1ULL,
		0x0000000048380A0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C7E44156CE96B9EULL,
		0xF81AB80735893882ULL,
		0xC38B69BE6E99A533ULL,
		0x113E98EC0B57B958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6CE96B9E00000000ULL,
		0x358938829C7E4415ULL,
		0x6E99A533F81AB807ULL,
		0x0B57B958C38B69BEULL,
		0x00000000113E98ECULL
	}};
	shift = 32;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBC693979131D217ULL,
		0xF0E4210F0222A0A7ULL,
		0x6E89C976ED24A2D8ULL,
		0x623A1AECC19D1336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78D272F2263A42E0ULL,
		0x1C8421E0445414FDULL,
		0xD1392EDDA4945B1EULL,
		0x47435D9833A266CDULL,
		0x000000000000000CULL
	}};
	shift = 59;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x373D652DD6C29F51ULL,
		0xECD0B23A9B5DE3E7ULL,
		0xDB504F2F4636E5D4ULL,
		0x31370F3206F83A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCF594B75B0A7D440ULL,
		0x342C8EA6D778F9CDULL,
		0xD413CBD18DB9753BULL,
		0x4DC3CC81BE0E9EF6ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x218B052093DA6CAEULL,
		0xF7240B2B65B130AAULL,
		0xBED56596336C75CEULL,
		0x2DB297CFBF9BF653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4824F69B2B800000ULL,
		0xCAD96C4C2A8862C1ULL,
		0x658CDB1D73BDC902ULL,
		0xF3EFE6FD94EFB559ULL,
		0x00000000000B6CA5ULL
	}};
	shift = 42;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14967AB2BACFBBFFULL,
		0x15262C394D619CD5ULL,
		0xC1591CAA15595F23ULL,
		0xAE8A10BC4BD1DE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9EACAEB3EEFFC000ULL,
		0x8B0E535867354525ULL,
		0x472A855657C8C549ULL,
		0x842F12F477807056ULL,
		0x0000000000002BA2ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C2D699405A722EEULL,
		0x191F0256AB787790ULL,
		0xF630C35FCC784630ULL,
		0x164F91BFCDFBECCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8BB80000000000ULL,
		0xE1DE4070B5A65016ULL,
		0xE118C0647C095AADULL,
		0xEFB333D8C30D7F31ULL,
		0x000000593E46FF37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x276BA5F01E1E790FULL,
		0x19943C62B430286CULL,
		0xBD727525F2D8CD25ULL,
		0xFC4817D623F05F69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F3C87800000000ULL,
		0xA18143613B5D2F80ULL,
		0x96C66928CCA1E315ULL,
		0x1F82FB4DEB93A92FULL,
		0x00000007E240BEB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E803FC55D0D36EAULL,
		0xF60C142AE5B0083EULL,
		0x157C449026095C71ULL,
		0x6A758ADC491EC543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7401FE2AE869B750ULL,
		0xB060A1572D8041F1ULL,
		0xABE22481304AE38FULL,
		0x53AC56E248F62A18ULL,
		0x0000000000000003ULL
	}};
	shift = 61;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BE3910FD963D409ULL,
		0xF8798454267DA2A0ULL,
		0x523E9FE1F95FB606ULL,
		0x06923C7A3BD9A325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F658F5024000000ULL,
		0x5099F68A81EF8E44ULL,
		0x87E57ED81BE1E611ULL,
		0xE8EF668C9548FA7FULL,
		0x00000000001A48F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31BB7CB4AF95BA02ULL,
		0xB35D1EC430D05AADULL,
		0x4E004100E6F1D145ULL,
		0xD859A9992BFC5136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADD0100000000000ULL,
		0x82D5698DDBE5A57CULL,
		0x8E8A2D9AE8F62186ULL,
		0xE289B27002080737ULL,
		0x000006C2CD4CC95FULL
	}};
	shift = 21;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5C80FFE4BC14C70ULL,
		0x776E37517FCCECBCULL,
		0x7DBD3596532B002FULL,
		0x23B8B1AA8FAFC7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6380000000000000ULL,
		0x65E7AE407FF25E0AULL,
		0x017BBB71BA8BFE67ULL,
		0x3D6BEDE9ACB29958ULL,
		0x00011DC58D547D7EULL
	}};
	shift = 13;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAE56C4333926EA4ULL,
		0x21035925FB425715ULL,
		0xCE4ECB97469E734CULL,
		0x09CA75F7776863F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xAF572B62199C9375ULL,
		0x61081AC92FDA12B8ULL,
		0x8E72765CBA34F39AULL,
		0x004E53AFBBBB431FULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7714652E82AD87F3ULL,
		0x23F5C82EA0B5F717ULL,
		0x1D8EB4EF1B3FB98BULL,
		0xF730A6CD97639A6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x156C3F9800000000ULL,
		0x05AFB8BBB8A32974ULL,
		0xD9FDCC591FAE4175ULL,
		0xBB1CD370EC75A778ULL,
		0x00000007B985366CULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9DF46BF6D80111FULL,
		0x805468E58AFB35B2ULL,
		0xA9FC09246E057512ULL,
		0x274A5F6AD0E59511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xB677D1AFDB600447ULL,
		0xA0151A3962BECD6CULL,
		0x6A7F02491B815D44ULL,
		0x09D297DAB4396544ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD81E4AC26C431599ULL,
		0xA66BCE1C94C9A036ULL,
		0x59D4E77AF12106A5ULL,
		0xAE1CBDD554DC111CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x218ACC8000000000ULL,
		0x64D01B6C0F256136ULL,
		0x908352D335E70E4AULL,
		0x6E088E2CEA73BD78ULL,
		0x000000570E5EEAAAULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2B2A7EAC8B677CEULL,
		0xE7EE9561A11F672CULL,
		0x9E11BE26B1E8D2AFULL,
		0x9A00A4171C985DD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xCE2B2A7EAC8B677CULL,
		0xFE7EE9561A11F672ULL,
		0x89E11BE26B1E8D2AULL,
		0x09A00A4171C985DDULL
	}};
	shift = 4;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50D5C058DB708EA7ULL,
		0x4DEFDC5D8E689DFAULL,
		0x23D62A8BC9DBDC3BULL,
		0x883ED322F124FD47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1B6E11D4E000000ULL,
		0xBB1CD13BF4A1AB80ULL,
		0x1793B7B8769BDFB8ULL,
		0x45E249FA8E47AC55ULL,
		0x0000000001107DA6ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C8567AEC32D9869ULL,
		0x69025E71C4A4876EULL,
		0xA65D34E15A0BB9C8ULL,
		0x9425CFFB19D2BCB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3480000000000000ULL,
		0xB74642B3D76196CCULL,
		0xE434812F38E25243ULL,
		0x5A532E9A70AD05DCULL,
		0x004A12E7FD8CE95EULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51535F2CB8363540ULL,
		0x1B64DB962679ADACULL,
		0x2677023DE05732ABULL,
		0x56D1C3999C731266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xD628A9AF965C1B1AULL,
		0x558DB26DCB133CD6ULL,
		0x33133B811EF02B99ULL,
		0x002B68E1CCCE3989ULL
	}};
	shift = 9;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC318EBE14D64BE9ULL,
		0xCD32C13E93DAD30CULL,
		0x210AF57904A09703ULL,
		0x5FC495E34495D4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE14D64BE9000000ULL,
		0x3E93DAD30CBC318EULL,
		0x7904A09703CD32C1ULL,
		0xE34495D4DC210AF5ULL,
		0x00000000005FC495ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94DCD052A7B246F1ULL,
		0xC592D0E616E78342ULL,
		0xBC8C15FB7382AABDULL,
		0xAC926610286DA7EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91BC400000000000ULL,
		0xE0D0A5373414A9ECULL,
		0xAAAF7164B43985B9ULL,
		0x69FBEF23057EDCE0ULL,
		0x00002B2499840A1BULL
	}};
	shift = 18;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA617C62094FAEA0BULL,
		0xBAD9E9728FCCA25CULL,
		0x9149FC1FC7508C03ULL,
		0xB9A0AF9D45744F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82C0000000000000ULL,
		0x972985F188253EBAULL,
		0x00EEB67A5CA3F328ULL,
		0xD7E4527F07F1D423ULL,
		0x002E682BE7515D13ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x819B11DB7A0FCAACULL,
		0x02CDA775E20A5ADFULL,
		0x3EEDD6AA23B8271AULL,
		0x9E0C310E91A9FADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F2AB00000000000ULL,
		0x296B7E066C476DE8ULL,
		0xE09C680B369DD788ULL,
		0xA7EB7CFBB75AA88EULL,
		0x0000027830C43A46ULL
	}};
	shift = 22;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE32ACF65B97B3CF4ULL,
		0x9D4655E2477D21E2ULL,
		0x8BF3C542D4A67004ULL,
		0x1D7B160C3378EDC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97B3CF4000000000ULL,
		0x77D21E2E32ACF65BULL,
		0x4A670049D4655E24ULL,
		0x378EDC28BF3C542DULL,
		0x00000001D7B160C3ULL
	}};
	shift = 28;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B3E0B75502BDFC5ULL,
		0x5BF6207D980ADF79ULL,
		0x1BA8C140E90980F0ULL,
		0x32BBBD40DA5225B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x540AF7F140000000ULL,
		0x6602B7DE52CF82DDULL,
		0x3A42603C16FD881FULL,
		0x3694896CC6EA3050ULL,
		0x000000000CAEEF50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x107625D07FDBE474ULL,
		0x11F736AE823C613FULL,
		0x83FC7CC307407A87ULL,
		0x02B6F10FA272AE2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE47400000000000ULL,
		0xC613F107625D07FDULL,
		0x07A8711F736AE823ULL,
		0x2AE2F83FC7CC3074ULL,
		0x0000002B6F10FA27ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF07BE2231C4220D8ULL,
		0x4CDD28BB41F4EB4CULL,
		0x4A999E0A3F57221EULL,
		0x5A88C50C9D471BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7108836000000000ULL,
		0x07D3AD33C1EF888CULL,
		0xFD5C88793374A2EDULL,
		0x751C6EFD2A667828ULL,
		0x000000016A231432ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D7CD34417122953ULL,
		0x125C3295CF126D83ULL,
		0x9765B0BF7D45E58FULL,
		0x847B396D600037E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4171229530000000ULL,
		0x5CF126D830D7CD34ULL,
		0xF7D45E58F125C329ULL,
		0xD600037E39765B0BULL,
		0x000000000847B396ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x642FBDB1C9F02A11ULL,
		0x9087716B52E23339ULL,
		0x9339F7605B628BE4ULL,
		0xDD04133B6128336DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4220000000000000ULL,
		0x672C85F7B6393E05ULL,
		0x7C9210EE2D6A5C46ULL,
		0x6DB2673EEC0B6C51ULL,
		0x001BA082676C2506ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76640A30204F7D50ULL,
		0x0FEBBA3A2E401191ULL,
		0xC060B5BE5898A2EDULL,
		0xF80AC174592DD965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5400000000000000ULL,
		0x645D99028C0813DFULL,
		0xBB43FAEE8E8B9004ULL,
		0x5970182D6F962628ULL,
		0x003E02B05D164B76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6254962A71735EFBULL,
		0x1F60552C4BE32B34ULL,
		0xFCDF18497787D7D4ULL,
		0x384E6AFC64261851ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4A92C54E2E6BDF6ULL,
		0x3EC0AA5897C65668ULL,
		0xF9BE3092EF0FAFA8ULL,
		0x709CD5F8C84C30A3ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x22E655AB0881A1E4ULL,
		0x91D4F1D13329CDD8ULL,
		0x2FFF8B3E0880AFF9ULL,
		0x9E6DF3E0EA28F24AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x045CCAB56110343CULL,
		0x323A9E3A266539BBULL,
		0x45FFF167C11015FFULL,
		0x13CDBE7C1D451E49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02B6C369E9DD00AEULL,
		0xE2BF217BBAEB1574ULL,
		0xAF10E4B82E00BB42ULL,
		0x66F307D935C326D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x15C0000000000000ULL,
		0xAE8056D86D3D3BA0ULL,
		0x685C57E42F775D62ULL,
		0xDAD5E21C9705C017ULL,
		0x000CDE60FB26B864ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9A4731274290159ULL,
		0x80738AF006836EF5ULL,
		0xD51F8AC3FBB26D01ULL,
		0x8DE67CFF08803C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5202B20000000000ULL,
		0x06DDEBD348E624E8ULL,
		0x64DA0300E715E00DULL,
		0x00784BAA3F1587F7ULL,
		0x0000011BCCF9FE11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE4D31EB2560E6C7ULL,
		0xC6A9165E561CAB3DULL,
		0x16CCD3CB52A2C669ULL,
		0x66D1B01CC070944EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39B1C00000000000ULL,
		0x2ACF6B934C7AC958ULL,
		0xB19A71AA45979587ULL,
		0x251385B334F2D4A8ULL,
		0x000019B46C07301CULL
	}};
	shift = 18;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC681C6E5D615466ULL,
		0xA734C469A9B878C0ULL,
		0xB2546AEB37A51C57ULL,
		0x0AC0C92150B7A78DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC681C6E5D615466ULL,
		0xA734C469A9B878C0ULL,
		0xB2546AEB37A51C57ULL,
		0x0AC0C92150B7A78DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6014E4ED73489ED9ULL,
		0xC4D7CB074449A0F8ULL,
		0xBBC5B61C771B539DULL,
		0x60A78518AABB3721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7276B9A44F6C8000ULL,
		0xE583A224D07C300AULL,
		0xDB0E3B8DA9CEE26BULL,
		0xC28C555D9B90DDE2ULL,
		0x0000000000003053ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x494AA252F17A2C56ULL,
		0xBB6B3D40C254E109ULL,
		0x17682102113DB2F1ULL,
		0xF2E289B0B64FE3A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5512978BD162B00ULL,
		0xB59EA0612A7084A4ULL,
		0xB41081089ED978DDULL,
		0x7144D85B27F1D08BULL,
		0x0000000000000079ULL
	}};
	shift = 57;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65AE0E16F8279B02ULL,
		0xBCF9A3518FF83CF9ULL,
		0x60DF46FB8F033EA9ULL,
		0xA765A25320636404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8100000000000000ULL,
		0x7CB2D7070B7C13CDULL,
		0x54DE7CD1A8C7FC1EULL,
		0x02306FA37DC7819FULL,
		0x0053B2D1299031B2ULL
	}};
	shift = 9;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16728B363F1FE4CEULL,
		0xDEDD07E9289A35ABULL,
		0xBB29677D704DB13AULL,
		0x9473A6F4C2473CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF267000000000000ULL,
		0x1AD58B39459B1F8FULL,
		0xD89D6F6E83F4944DULL,
		0x9E50DD94B3BEB826ULL,
		0x00004A39D37A6123ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8694C84C70D280C8ULL,
		0x5D8FA09F63936C0AULL,
		0xE7767125EE78665AULL,
		0x0ACA238E611166E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9000000000000000ULL,
		0x150D299098E1A501ULL,
		0xB4BB1F413EC726D8ULL,
		0xD1CEECE24BDCF0CCULL,
		0x001594471CC222CDULL
	}};
	shift = 7;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x569B3D982C6C0D28ULL,
		0xE22D408091846735ULL,
		0x87A907E3E77151B6ULL,
		0xB7678DC6580DD123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6360694000000000ULL,
		0x8C2339AAB4D9ECC1ULL,
		0x3B8A8DB7116A0404ULL,
		0xC06E891C3D483F1FULL,
		0x00000005BB3C6E32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9F26B121BAEF4F0ULL,
		0xE608D79BE682B637ULL,
		0x87BD84E25857D257ULL,
		0x41BB7E9002BDB3B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD77A7800000000ULL,
		0xF3415B1BE4F93589ULL,
		0x2C2BE92BF3046BCDULL,
		0x015ED9DB43DEC271ULL,
		0x0000000020DDBF48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7250158A82B0A61FULL,
		0x7423F5B09B53F0C0ULL,
		0x5E1EBA9A191C2800ULL,
		0xCB0E23F48E7A2234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x1C940562A0AC2987ULL,
		0x1D08FD6C26D4FC30ULL,
		0x1787AEA686470A00ULL,
		0x32C388FD239E888DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x979703139FC4E42AULL,
		0xEF5A0FE3F46B1016ULL,
		0x58315B0BF671A093ULL,
		0x5E41BC975268C7C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F2E06273F89C854ULL,
		0xDEB41FC7E8D6202DULL,
		0xB062B617ECE34127ULL,
		0xBC83792EA4D18F8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF68112EBB800899ULL,
		0x75E5870918918847ULL,
		0x55D14CDCC69CE2B6ULL,
		0xCB41AD4CE01E9DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC0044C800000000ULL,
		0xC48C423F7B408975ULL,
		0x34E715B3AF2C3848ULL,
		0x00F4ED52AE8A66E6ULL,
		0x000000065A0D6A67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6061AA438BF3D351ULL,
		0xED3C81863E9A8542ULL,
		0x667727BF6F3B5258ULL,
		0x3ED59456BFB9F840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3548717E7A6A200ULL,
		0x79030C7D350A84C0ULL,
		0xEE4F7EDE76A4B1DAULL,
		0xAB28AD7F73F080CCULL,
		0x000000000000007DULL
	}};
	shift = 55;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F621906E7303F54ULL,
		0x7F7B126669CD285FULL,
		0x0E61191DB805E480ULL,
		0xC402F64A057CD211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41B9CC0FD5000000ULL,
		0x999A734A17C7D886ULL,
		0x476E0179201FDEC4ULL,
		0x92815F3484439846ULL,
		0x00000000003100BDULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD22F5D307B23C828ULL,
		0xBAA7BD8C849AEABBULL,
		0x3202994711D338B4ULL,
		0xDA5966D42425DA1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD22F5D307B23C828ULL,
		0xBAA7BD8C849AEABBULL,
		0x3202994711D338B4ULL,
		0xDA5966D42425DA1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98F0CDB962C6C6F4ULL,
		0x0CDC4814E0FFB6E5ULL,
		0x084582F40161A85FULL,
		0x5E7822963273200AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D8DE80000000000ULL,
		0xFF6DCB31E19B72C5ULL,
		0xC350BE19B89029C1ULL,
		0xE64014108B05E802ULL,
		0x000000BCF0452C64ULL
	}};
	shift = 23;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x075F69221EF8A6ECULL,
		0x3150AF504DDC9B53ULL,
		0x026276BF61D67E9CULL,
		0x4012E3200F1F937BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D7DA4887BE29BB0ULL,
		0xC542BD4137726D4CULL,
		0x0989DAFD8759FA70ULL,
		0x004B8C803C7E4DECULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0503D41CFAD7B12ULL,
		0xD59F36E04AC0BB34ULL,
		0x5DD603177027C881ULL,
		0x180A575AEEA27D8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40A07A839F5AF624ULL,
		0xAB3E6DC095817669ULL,
		0xBBAC062EE04F9103ULL,
		0x3014AEB5DD44FB1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA14DBBDA8BD12FAULL,
		0x4DBA749B2586C111ULL,
		0x76606EE0825EE33CULL,
		0x65A403301FC153CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDED45E897D000000ULL,
		0x4D92C36088D50A6DULL,
		0x70412F719E26DD3AULL,
		0x980FE0A9E5BB3037ULL,
		0x000000000032D201ULL
	}};
	shift = 41;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x428BA67BE8560FB3ULL,
		0xDE6BA1445504B4A9ULL,
		0x2F17C3D97F1B40ADULL,
		0x2CE897BB25EF9891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF660000000000000ULL,
		0x95285174CF7D0AC1ULL,
		0x15BBCD74288AA096ULL,
		0x1225E2F87B2FE368ULL,
		0x00059D12F764BDF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA87D6392B55E7E87ULL,
		0x624D7F54BB0F6C5AULL,
		0x2F6BDC28C7A5A76CULL,
		0x9FF9C4BDCEE3A55CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7256ABCFD0E00000ULL,
		0xEA9761ED8B550FACULL,
		0x8518F4B4ED8C49AFULL,
		0x97B9DC74AB85ED7BULL,
		0x000000000013FF38ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB91CE85BE2DE9E9DULL,
		0xD12E310FAB02A6AFULL,
		0x60335623830B82F7ULL,
		0xC44DBF8C23892C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9E9D0000000000ULL,
		0x02A6AFB91CE85BE2ULL,
		0x0B82F7D12E310FABULL,
		0x892C186033562383ULL,
		0x000000C44DBF8C23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x006E8B4E0B8B6C3BULL,
		0xD042940C3CCDBEE5ULL,
		0xDD2B60F543B235E2ULL,
		0x4E45E0BD36A808BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5A705C5B61D80000ULL,
		0xA061E66DF7280374ULL,
		0x07AA1D91AF168214ULL,
		0x05E9B54045F6E95BULL,
		0x000000000002722FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x282C2567F5D6E6F0ULL,
		0xFC7FDE1E9ABD6762ULL,
		0xAF787D042EE4EBFDULL,
		0x9D03597932D9B5A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACFEBADCDE000000ULL,
		0xC3D357ACEC450584ULL,
		0xA085DC9D7FBF8FFBULL,
		0x2F265B36B475EF0FULL,
		0x000000000013A06BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EBF59FBD0AD75E5ULL,
		0x8AC57319C9CF3F89ULL,
		0xD498AFFFAE2D8E60ULL,
		0x60F72EF84806AA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xACFDE856BAF28000ULL,
		0xB98CE4E79FC4875FULL,
		0x57FFD716C7304562ULL,
		0x977C24035543EA4CULL,
		0x000000000000307BULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54B4AECB14CA403CULL,
		0x695EF1400902C50FULL,
		0xAD6F07AD0FA2C3D2ULL,
		0xB4BEE58DDFC99F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5A57658A65201E00ULL,
		0xAF78A004816287AAULL,
		0xB783D687D161E934ULL,
		0x5F72C6EFE4CF8056ULL,
		0x000000000000005AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E42009180ADF6D6ULL,
		0x4C930A1E6264BDFDULL,
		0x7E1BD7D6CC8AFCBCULL,
		0xC0A3032CF1068072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15BEDAC000000000ULL,
		0x4C97BFB3C8401230ULL,
		0x915F9789926143CCULL,
		0x20D00E4FC37AFAD9ULL,
		0x000000181460659EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86BA82A573B7BEA0ULL,
		0x7B4D87257A1FBD01ULL,
		0xD64900A54C7B3532ULL,
		0x2BE0049D618A0EC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F7D40000000000ULL,
		0x43F7A030D75054AEULL,
		0x8F66A64F69B0E4AFULL,
		0x3141D8FAC92014A9ULL,
		0x000000057C0093ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x69A64E8EA58C435EULL,
		0x5CCC702E1C3B7F57ULL,
		0xE3AC4D48405BD314ULL,
		0x93A8DDB87172D5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD34C9D1D4B1886BCULL,
		0xB998E05C3876FEAEULL,
		0xC7589A9080B7A628ULL,
		0x2751BB70E2E5ABBFULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC07A04B74E5A30FFULL,
		0x97F5BB0269A05B34ULL,
		0x485D8D192468F14FULL,
		0x1EDDC580B130D7F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A30FF0000000000ULL,
		0xA05B34C07A04B74EULL,
		0x68F14F97F5BB0269ULL,
		0x30D7F1485D8D1924ULL,
		0x0000001EDDC580B1ULL
	}};
	shift = 24;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7675053C652173BCULL,
		0xA40AD497D1717C9DULL,
		0xF83FC3294670D656ULL,
		0x15F43CFA49D8CD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9DE000000000000ULL,
		0xBE4EBB3A829E3290ULL,
		0x6B2B52056A4BE8B8ULL,
		0x6699FC1FE194A338ULL,
		0x00000AFA1E7D24ECULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x22DA9C59800B2037ULL,
		0xEC27AD86A26FBBBCULL,
		0x590B3619E5EBEC07ULL,
		0x51F9FFCA05972E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB538B30016406E00ULL,
		0x4F5B0D44DF777845ULL,
		0x166C33CBD7D80FD8ULL,
		0xF3FF940B2E5CC6B2ULL,
		0x00000000000000A3ULL
	}};
	shift = 55;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x663ABD937A236BA5ULL,
		0x07E75FF46A78434FULL,
		0x32A02F475CA08543ULL,
		0xB179E95DF1952772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5EC9BD11B5D2800ULL,
		0x3AFFA353C21A7B31ULL,
		0x017A3AE5042A183FULL,
		0xCF4AEF8CA93B9195ULL,
		0x000000000000058BULL
	}};
	shift = 53;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBEB26B499E34B6AAULL,
		0x934041BB32848500ULL,
		0xE1E163D1DDB97B83ULL,
		0xF92C1DB1F9CF05D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6933C696D5400000ULL,
		0x37665090A017D64DULL,
		0x7A3BB72F70726808ULL,
		0xB63F39E0BA3C3C2CULL,
		0x00000000001F2583ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2353F1B78530D59ULL,
		0x422913B336FDF3CDULL,
		0x656BF4A2D24C7863ULL,
		0x55BB3AA0F3492872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC46A7E36F0A61AB2ULL,
		0x845227666DFBE79BULL,
		0xCAD7E945A498F0C6ULL,
		0xAB767541E69250E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x35E666F70BC0A7ADULL,
		0x374B1ADF3334DFB6ULL,
		0x80AF68830118C480ULL,
		0xAF22C5E03DD77E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF70BC0A7AD000000ULL,
		0xDF3334DFB635E666ULL,
		0x830118C480374B1AULL,
		0xE03DD77E9F80AF68ULL,
		0x0000000000AF22C5ULL
	}};
	shift = 40;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8BBA780D4A59ABEULL,
		0x0007C01E84054893ULL,
		0x249C03CED2229734ULL,
		0xC8F577A73AEB1AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x52966AF800000000ULL,
		0x1015224FE2EE9E03ULL,
		0x488A5CD0001F007AULL,
		0xEBAC6A9492700F3BULL,
		0x0000000323D5DE9CULL
	}};
	shift = 30;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x85A45BEBE05B6FA3ULL,
		0xC5A4BBEDDF1DBC36ULL,
		0xEE9BBFEA0832B100ULL,
		0xFB78B8636F25C80AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE05B6FA30000000ULL,
		0xDDF1DBC3685A45BEULL,
		0xA0832B100C5A4BBEULL,
		0x36F25C80AEE9BBFEULL,
		0x000000000FB78B86ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x265DC6A29B2AFA5AULL,
		0x18DAE132D410D8E7ULL,
		0x06F0A394E2D44F15ULL,
		0xCF4D3E8435EE3BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3514D957D2D00000ULL,
		0x0996A086C73932EEULL,
		0x1CA716A278A8C6D7ULL,
		0xF421AF71DEA03785ULL,
		0x0000000000067A69ULL
	}};
	shift = 45;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D0397FBCA42297BULL,
		0x1B3906474DD42C02ULL,
		0xEED7F4E07C467A67ULL,
		0x137BDB0EA037CCA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBCA42297B000000ULL,
		0x474DD42C028D0397ULL,
		0xE07C467A671B3906ULL,
		0x0EA037CCA4EED7F4ULL,
		0x0000000000137BDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x000D77E484A85DB2ULL,
		0x148BCCE5BDD0321EULL,
		0xC3D948CC9DC96766ULL,
		0xB18339D820C506ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0035DF9212A176C8ULL,
		0x522F3396F740C878ULL,
		0x0F65233277259D98ULL,
		0xC60CE76083141AAFULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96F455FD896175DCULL,
		0x507EF70AD70BB242ULL,
		0x30EEB7FF3CB5F384ULL,
		0x18A4A4778AEF6DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF62585D770000000ULL,
		0x2B5C2EC90A5BD157ULL,
		0xFCF2D7CE1141FBDCULL,
		0xDE2BBDB784C3BADFULL,
		0x0000000000629291ULL
	}};
	shift = 38;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA321B89D3ECB6958ULL,
		0xFA5126669CA2E6BBULL,
		0xDC737A0E798445BFULL,
		0xA9BEAB81DBCFFFDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DA5600000000000ULL,
		0x8B9AEE8C86E274FBULL,
		0x1116FFE944999A72ULL,
		0x3FFF7F71CDE839E6ULL,
		0x000002A6FAAE076FULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7B7E147B0120B282ULL,
		0x811C1B6C5D5A4E8DULL,
		0xAB4C5842AF87523AULL,
		0xB6B878393367719DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28F6024165040000ULL,
		0x36D8BAB49D1AF6FCULL,
		0xB0855F0EA4750238ULL,
		0xF07266CEE33B5698ULL,
		0x0000000000016D70ULL
	}};
	shift = 47;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x844F6ED987606E06ULL,
		0x1DBD0D2D35B454F8ULL,
		0xDB18C2FEBA76F742ULL,
		0xD4DF1D0AA91490FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3703000000000000ULL,
		0x2A7C4227B76CC3B0ULL,
		0x7BA10EDE86969ADAULL,
		0x487DED8C617F5D3BULL,
		0x00006A6F8E85548AULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D8183BEE8C55265ULL,
		0x865686F6E86FFAAEULL,
		0x2D724141EC13EDD4ULL,
		0xA1A7B5BBE0311323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6500000000000000ULL,
		0xAE8D8183BEE8C552ULL,
		0xD4865686F6E86FFAULL,
		0x232D724141EC13EDULL,
		0x00A1A7B5BBE03113ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x334AB0BDF5BB970FULL,
		0x9B0CFD346E77F3A0ULL,
		0x6E4D6F28004F8305ULL,
		0x087E1D642BC3C44EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7800000000000000ULL,
		0x019A5585EFADDCB8ULL,
		0x2CD867E9A373BF9DULL,
		0x73726B7940027C18ULL,
		0x0043F0EB215E1E22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36898B8B1B184BA5ULL,
		0x16F0153D71DB23D1ULL,
		0x21C146AD848FFFD9ULL,
		0x7D85599D51DCE509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0974A00000000000ULL,
		0x647A26D131716363ULL,
		0xFFFB22DE02A7AE3BULL,
		0x9CA1243828D5B091ULL,
		0x00000FB0AB33AA3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBBD6ADF3D940D22ULL,
		0x21D15A3102DAE9E0ULL,
		0x56AEA83486883783ULL,
		0x97E82C94CDE6E766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5AB7CF6503488000ULL,
		0x568C40B6BA783AEFULL,
		0xAA0D21A20DE0C874ULL,
		0x0B253379B9D995ABULL,
		0x00000000000025FAULL
	}};
	shift = 50;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEFF6B025FF5446EFULL,
		0x0403C17F4A65D62CULL,
		0x647E37A151EE87C9ULL,
		0xC9DFA3611EE4EA67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4BFEA88DDE000000ULL,
		0xFE94CBAC59DFED60ULL,
		0x42A3DD0F92080782ULL,
		0xC23DC9D4CEC8FC6FULL,
		0x000000000193BF46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x615A5087477F67C7ULL,
		0x30AA53E7AA4CAEDCULL,
		0xD8B40F1B224D43B7ULL,
		0x6929C3E02CFD90F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x087477F67C700000ULL,
		0x3E7AA4CAEDC615A5ULL,
		0xF1B224D43B730AA5ULL,
		0x3E02CFD90F6D8B40ULL,
		0x000000000006929CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A81F72237FB9577ULL,
		0x2DBA9E0A7C674244ULL,
		0xE9FA86AF7F94DF06ULL,
		0x4054311FC94F9FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0x43A81F72237FB957ULL,
		0x62DBA9E0A7C67424ULL,
		0xDE9FA86AF7F94DF0ULL,
		0x04054311FC94F9FAULL
	}};
	shift = 4;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x879CDF45D5F1154EULL,
		0xEA169ECB9C83DF08ULL,
		0xC8DE2E1C9CE22D5CULL,
		0x713A0284959A1F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CDF45D5F1154E00ULL,
		0x169ECB9C83DF0887ULL,
		0xDE2E1C9CE22D5CEAULL,
		0x3A0284959A1F33C8ULL,
		0x0000000000000071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x720F75F92DC90BBBULL,
		0x8BB7872B1AD558EEULL,
		0xD11D2EDE91A8660DULL,
		0x120FC1AE03FDDC23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB00000000000000ULL,
		0xEE720F75F92DC90BULL,
		0x0D8BB7872B1AD558ULL,
		0x23D11D2EDE91A866ULL,
		0x00120FC1AE03FDDCULL
	}};
	shift = 8;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA22BB10C9FEC2BCULL,
		0x6CC112E451A00584ULL,
		0xE4AE3DC9BBD6C7D6ULL,
		0xCAB9929D2A2E7EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x115D8864FF615E00ULL,
		0x60897228D002C275ULL,
		0x571EE4DDEB63EB36ULL,
		0x5CC94E95173F5EF2ULL,
		0x0000000000000065ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x433D020F8081BF33ULL,
		0x9C51CA3320EA84B2ULL,
		0xB93DAD36A4E72F88ULL,
		0xA25C4311FF026F85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE660000000000000ULL,
		0x964867A041F01037ULL,
		0xF1138A3946641D50ULL,
		0xF0B727B5A6D49CE5ULL,
		0x00144B88623FE04DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCC69BEBEAD1127BULL,
		0xEC0ED8A1E4D09B01ULL,
		0xBAF7768AAB229C00ULL,
		0x24E35691298564DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F568893D800000ULL,
		0x50F2684D80FE634DULL,
		0x4555914E0076076CULL,
		0x4894C2B26EDD7BBBULL,
		0x00000000001271ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3705C7393DAE901ULL,
		0x0AB437F4788CE513ULL,
		0xF52802B99C678044ULL,
		0xA2F00110F2C96822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DC171CE4F6BA404ULL,
		0x2AD0DFD1E233944FULL,
		0xD4A00AE6719E0110ULL,
		0x8BC00443CB25A08BULL,
		0x0000000000000002ULL
	}};
	shift = 62;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5392F1A650786A3ULL,
		0x0E962C07C351A930ULL,
		0x2FCB8B001485D59DULL,
		0x77B5A7694BE27864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A30000000000000ULL,
		0x930E5392F1A65078ULL,
		0x59D0E962C07C351AULL,
		0x8642FCB8B001485DULL,
		0x00077B5A7694BE27ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E7031518EA004C4ULL,
		0xBB295661F3FF88CBULL,
		0x8D46257CDFB88382ULL,
		0x395021C770257DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062A31D400988000ULL,
		0x2ACC3E7FF1196DCEULL,
		0xC4AF9BF710705765ULL,
		0x0438EE04AFB7B1A8ULL,
		0x000000000000072AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F68662B3BB2D008ULL,
		0xF3D2D37C906E5D79ULL,
		0xD0435A148CB82CBFULL,
		0x14CA204871441E4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xED0CC567765A0100ULL,
		0x7A5A6F920DCBAF21ULL,
		0x086B4291970597FEULL,
		0x9944090E2883C95AULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x975FEBC98138225AULL,
		0xC2F35D2836A11933ULL,
		0x7E0FA83D30F13DDAULL,
		0x662951D192D7F057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC98138225A00000ULL,
		0xD2836A11933975FEULL,
		0x83D30F13DDAC2F35ULL,
		0x1D192D7F0577E0FAULL,
		0x0000000000066295ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 236;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDBC8B7475D6BD357ULL,
		0x32C9F2CE14623BD3ULL,
		0x8CD0F592C21C4A3DULL,
		0xD3FE6545995B68BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE00000000000000ULL,
		0xA7B7916E8EBAD7A6ULL,
		0x7A6593E59C28C477ULL,
		0x7519A1EB25843894ULL,
		0x01A7FCCA8B32B6D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65F1E9EDD1E91B6DULL,
		0xEAFB971A676FC23CULL,
		0x62B33D02995C371FULL,
		0xE2350B901483DF80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x32F8F4F6E8F48DB6ULL,
		0xF57DCB8D33B7E11EULL,
		0x31599E814CAE1B8FULL,
		0x711A85C80A41EFC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBEA2AD78496A2994ULL,
		0x719A07D789B598B0ULL,
		0xFBEF0F482272B65FULL,
		0xA5E255DC438DD33BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8AB5E125A8A650ULL,
		0xC6681F5E26D662C2ULL,
		0xEFBC3D2089CAD97DULL,
		0x978957710E374CEFULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1860C00CD5C738BULL,
		0xCA6EF8E847E2B380ULL,
		0xADA863320D8B7189ULL,
		0x13D6026143F28144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C00000000000000ULL,
		0x02861830033571CEULL,
		0x2729BBE3A11F8ACEULL,
		0x12B6A18CC8362DC6ULL,
		0x004F5809850FCA05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD465C949B9B0B618ULL,
		0x5FBA9FCB4A010074ULL,
		0x36AA09B4E7F83029ULL,
		0xC5C4DE7A5742FD50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A8CB929373616C3ULL,
		0x2BF753F96940200EULL,
		0x06D541369CFF0605ULL,
		0x18B89BCF4AE85FAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFC41BA644D4060DULL,
		0xEC10BB5EF5C858B5ULL,
		0xA7FD47E71BD766DEULL,
		0x8A10F344E17D24D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA030680000000000ULL,
		0x42C5AFFE20DD3226ULL,
		0xBB36F76085DAF7AEULL,
		0xE926B53FEA3F38DEULL,
		0x00000450879A270BULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC45D5EE085735F5ULL,
		0xD0C462D259037BABULL,
		0xA35E668EC2291F3EULL,
		0x36AFE705A7E11DDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xEE22EAF7042B9AFAULL,
		0x686231692C81BDD5ULL,
		0x51AF334761148F9FULL,
		0x1B57F382D3F08EEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0264DE523F732D49ULL,
		0x9F9D636FDB16166FULL,
		0xD9791ED8695FA7ADULL,
		0x065056AFAB0BABB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26F291FB996A4800ULL,
		0xEB1B7ED8B0B37813ULL,
		0xC8F6C34AFD3D6CFCULL,
		0x82B57D585D5DB6CBULL,
		0x0000000000000032ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9B7E5C7E4FCF749ULL,
		0x237CE6730C6828F6ULL,
		0x25A4F96F93E191A0ULL,
		0x1473BBAFD3C909BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x6CDBF2E3F27E7BA4ULL,
		0x11BE73398634147BULL,
		0x12D27CB7C9F0C8D0ULL,
		0x0A39DDD7E9E484DEULL
	}};
	shift = 1;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E1FADD672E21B4BULL,
		0xE1604E8BCB0BE8D9ULL,
		0x031C3AD74062CA80ULL,
		0x8C1349BDF84D9820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C3F5BACE5C43696ULL,
		0xC2C09D179617D1B3ULL,
		0x063875AE80C59501ULL,
		0x1826937BF09B3040ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79B1A0D7C4C68DB3ULL,
		0xAD78510B1D500068ULL,
		0x073D412EC8BA7D9AULL,
		0xD9DF7ED12B9C61C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x0F36341AF898D1B6ULL,
		0x55AF0A2163AA000DULL,
		0x80E7A825D9174FB3ULL,
		0x1B3BEFDA25738C38ULL
	}};
	shift = 3;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x90F76A6D80B97CE0ULL,
		0xA3946E54AAC37A02ULL,
		0xFD6BDB584A1CA477ULL,
		0x37ACE46D94F3F343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x36C05CBE70000000ULL,
		0x2A5561BD01487BB5ULL,
		0xAC250E523BD1CA37ULL,
		0x36CA79F9A1FEB5EDULL,
		0x00000000001BD672ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC57AAE512BF71CBULL,
		0xBFC87BDDE564FC69ULL,
		0xAFF0C033946D7269ULL,
		0xD0CB01BF7E6F2754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71CB000000000000ULL,
		0xFC69BC57AAE512BFULL,
		0x7269BFC87BDDE564ULL,
		0x2754AFF0C033946DULL,
		0x0000D0CB01BF7E6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF17E87893E49F04ULL,
		0x98F1A05A08919623ULL,
		0xCE6B3AEADC86C664ULL,
		0x04F07AE8349E25BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEFC5FA1E24F927C1ULL,
		0x263C681682246588ULL,
		0xF39ACEBAB721B199ULL,
		0x013C1EBA0D27896FULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8ACAEC603D89783AULL,
		0x2DDE6444843182F3ULL,
		0x0180A9274958FD08ULL,
		0x63E07DE2E7CB87F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC07B12F074000000ULL,
		0x89086305E71595D8ULL,
		0x4E92B1FA105BBCC8ULL,
		0xC5CF970FEC030152ULL,
		0x0000000000C7C0FBULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4EB5CE0CAD9EA998ULL,
		0xF29DD08927982BA0ULL,
		0x2D0EF0B9ADE5ABC0ULL,
		0xEF96A6E828D8F3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B3D53300000000ULL,
		0x24F3057409D6B9C1ULL,
		0x35BCB5781E53BA11ULL,
		0x051B1E74E5A1DE17ULL,
		0x000000001DF2D4DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x021387B1335B3639ULL,
		0x2A12F3FBBCB27D35ULL,
		0xFB0FD608109122B0ULL,
		0xA72913D6FD37D3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1335B3639000000ULL,
		0xFBBCB27D35021387ULL,
		0x08109122B02A12F3ULL,
		0xD6FD37D3E9FB0FD6ULL,
		0x0000000000A72913ULL
	}};
	shift = 40;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6C2126DB95DF5EAULL,
		0x39C591DBDF61B9EFULL,
		0xB91C84793F61DBA7ULL,
		0x60E90C394C9D01CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB95DF5EA0000000ULL,
		0xBDF61B9EFD6C2126ULL,
		0x93F61DBA739C591DULL,
		0x94C9D01CBB91C847ULL,
		0x00000000060E90C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1C2A2F277518E15ULL,
		0x6D90CE9472A92680ULL,
		0x69AB03553DBAD0ACULL,
		0x59ADA448DEFD1887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD46385400000000ULL,
		0xCAA49A03070A8BC9ULL,
		0xF6EB42B1B6433A51ULL,
		0x7BF4621DA6AC0D54ULL,
		0x0000000166B69123ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CE91C3DF2F2514DULL,
		0xBD0E4B8E768F8ABAULL,
		0x5E2A32C916CB7749ULL,
		0x9075873C3CBD5EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7928A68000000000ULL,
		0x47C55D0E748E1EF9ULL,
		0x65BBA4DE8725C73BULL,
		0x5EAF62AF1519648BULL,
		0x000000483AC39E1EULL
	}};
	shift = 25;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D81D0398983C7F1ULL,
		0x20E9243CB6508B81ULL,
		0x6CAA4B12BDEF1A5CULL,
		0x8B1C245247DB1209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C1E3F880000000ULL,
		0x5B2845C086C0E81CULL,
		0x5EF78D2E1074921EULL,
		0x23ED8904B6552589ULL,
		0x00000000458E1229ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3699ED75BD1709C7ULL,
		0x77ABFA1FC96B4BF5ULL,
		0xCAA6B764757F33D4ULL,
		0x52BD8F68830772B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF45C271C00000000ULL,
		0x25AD2FD4DA67B5D6ULL,
		0xD5FCCF51DEAFE87FULL,
		0x0C1DCAD32A9ADD91ULL,
		0x000000014AF63DA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BE47370BC107D19ULL,
		0x3E6F7E48AF3AE3D2ULL,
		0x6491DF1BD2031692ULL,
		0xA8617FD4E1EE636FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x15F239B85E083E8CULL,
		0x1F37BF24579D71E9ULL,
		0xB248EF8DE9018B49ULL,
		0x5430BFEA70F731B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A69446C81F2F6EDULL,
		0xC002A852F1057DA3ULL,
		0xEAF1485879540567ULL,
		0xCB3498DC1DFC78C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB207CBDBB4000000ULL,
		0x4BC415F68C29A511ULL,
		0x61E550159F000AA1ULL,
		0x7077F1E31FABC521ULL,
		0x00000000032CD263ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55526B3DD9382C06ULL,
		0x4CDC81F468159E61ULL,
		0xFD29E3B1071D0699ULL,
		0xD9F5D9CE35CA3292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x526B3DD9382C0600ULL,
		0xDC81F468159E6155ULL,
		0x29E3B1071D06994CULL,
		0xF5D9CE35CA3292FDULL,
		0x00000000000000D9ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x412C24BD80D8FB53ULL,
		0x7D55A14E3532B09AULL,
		0x765E2331A8A709E6ULL,
		0xF5BD104198425C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB53000000000000ULL,
		0xB09A412C24BD80D8ULL,
		0x09E67D55A14E3532ULL,
		0x5C6E765E2331A8A7ULL,
		0x0000F5BD10419842ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE271DBD3535D7078ULL,
		0xD84B90FCA5354E37ULL,
		0xFB854B09275C058EULL,
		0xD1C5A7BA9967FB30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71DBD3535D707800ULL,
		0x4B90FCA5354E37E2ULL,
		0x854B09275C058ED8ULL,
		0xC5A7BA9967FB30FBULL,
		0x00000000000000D1ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8231FAA89CC8F85EULL,
		0x389D7C15D7E70D2AULL,
		0xB4E307A054AA554FULL,
		0xF9BB5C573F6178D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xA08C7EAA27323E17ULL,
		0xCE275F0575F9C34AULL,
		0x6D38C1E8152A9553ULL,
		0x3E6ED715CFD85E36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6AF3586C198D5E1ULL,
		0xF9F80236FA6B6566ULL,
		0x72920B6A2E8A1B87ULL,
		0xE3C972635AE8BD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60CC6AF080000000ULL,
		0x7D35B2B36B579AC3ULL,
		0x17450DC3FCFC011BULL,
		0xAD745EB1394905B5ULL,
		0x0000000071E4B931ULL
	}};
	shift = 33;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x105835300A14E572ULL,
		0xF6F58918A9EA453FULL,
		0x0A48B07EBE4620E2ULL,
		0xB10E2664EDD16050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x20B06A601429CAE4ULL,
		0xEDEB123153D48A7EULL,
		0x149160FD7C8C41C5ULL,
		0x621C4CC9DBA2C0A0ULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B65C7F6E83D5D85ULL,
		0xEB9AEDE47904E388ULL,
		0x37506D99D2F40F10ULL,
		0xB8CFE8C7D0A9289FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2E3FB741EAEC280ULL,
		0xCD76F23C8271C405ULL,
		0xA836CCE97A078875ULL,
		0x67F463E854944F9BULL,
		0x000000000000005CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E30FEA16FD90B6AULL,
		0x578B2CB813ACAFD7ULL,
		0xC6DFF84A9521CEE8ULL,
		0x1CF64C307A045716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42DFB216D4000000ULL,
		0x7027595FAEFC61FDULL,
		0x952A439DD0AF1659ULL,
		0x60F408AE2D8DBFF0ULL,
		0x000000000039EC98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59710E628505D4F2ULL,
		0xC1C5DF061380F26CULL,
		0xB2F17E1F17A4FDFDULL,
		0x9BD36B481975996EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4282EA7900000000ULL,
		0x09C079362CB88731ULL,
		0x8BD27EFEE0E2EF83ULL,
		0x0CBACCB75978BF0FULL,
		0x000000004DE9B5A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9566A04E1466A7C2ULL,
		0x36BB3763BE1F2BA2ULL,
		0x629E8E4FE7569AF0ULL,
		0x13FB61A649164E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1466A7C200000000ULL,
		0xBE1F2BA29566A04EULL,
		0xE7569AF036BB3763ULL,
		0x49164E73629E8E4FULL,
		0x0000000013FB61A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DBF85B26802AC64ULL,
		0x28FB003F84C09C55ULL,
		0xABF9DFDC45641AC3ULL,
		0x5FE6F5D937D6005DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA00AB19000000000ULL,
		0x1302715536FE16C9ULL,
		0x15906B0CA3EC00FEULL,
		0xDF580176AFE77F71ULL,
		0x000000017F9BD764ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x059F813206313E7AULL,
		0xFDD86E4D314103F0ULL,
		0xC96C2A080F4542C6ULL,
		0xEF3260D432F24AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE04C818C4F9E8000ULL,
		0x1B934C5040FC0167ULL,
		0x0A8203D150B1BF76ULL,
		0x98350CBC92ABF25BULL,
		0x0000000000003BCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E7ECD1CDE1C585DULL,
		0x95F042A249100BA6ULL,
		0x71C277F2A4D90E73ULL,
		0xDB4E1FC0237EC823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA00000000000000ULL,
		0x4C9CFD9A39BC38B0ULL,
		0xE72BE08544922017ULL,
		0x46E384EFE549B21CULL,
		0x01B69C3F8046FD90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B58720D9DC4AAA6ULL,
		0x430898F0C18F2158ULL,
		0x957A7487185CEAB4ULL,
		0x27BEB0FE967F411FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9DC4AAA60000000ULL,
		0x0C18F21582B58720ULL,
		0x7185CEAB4430898FULL,
		0xE967F411F957A748ULL,
		0x00000000027BEB0FULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6346BED3E31D8975ULL,
		0x69CA87ACDC535161ULL,
		0x64DC125F7B1177FBULL,
		0x0B74DD809233B14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7DA7C63B12EA00ULL,
		0x950F59B8A6A2C2C6ULL,
		0xB824BEF622EFF6D3ULL,
		0xE9BB0124676296C9ULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4F494ACF4FA1CEDULL,
		0x7F693C25BA6CC21AULL,
		0x710B45B566DC0B14ULL,
		0xC841EFD91E0E9B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x5A7A4A567A7D0E76ULL,
		0x3FB49E12DD36610DULL,
		0xB885A2DAB36E058AULL,
		0x6420F7EC8F074DCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x486DFDAC4A9BC867ULL,
		0xBEF5221CA893246BULL,
		0xEC58C8BD94F01A33ULL,
		0x9B13AC73B5ACCFAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6700000000000000ULL,
		0x6B486DFDAC4A9BC8ULL,
		0x33BEF5221CA89324ULL,
		0xAAEC58C8BD94F01AULL,
		0x009B13AC73B5ACCFULL
	}};
	shift = 8;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A441FCCAC58C741ULL,
		0x6F58549CAC64CEE3ULL,
		0xE7DE32ADB0C60649ULL,
		0xE9795786E0116616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x41FCCAC58C741000ULL,
		0x8549CAC64CEE37A4ULL,
		0xE32ADB0C606496F5ULL,
		0x95786E0116616E7DULL,
		0x0000000000000E97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF54098BE92D67B1DULL,
		0xF5F167A43783E2D8ULL,
		0x30743847F2AF3DE1ULL,
		0x0102B49701D8FB38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x1EA81317D25ACF63ULL,
		0x3EBE2CF486F07C5BULL,
		0x060E8708FE55E7BCULL,
		0x00205692E03B1F67ULL
	}};
	shift = 3;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE75719469F1018A3ULL,
		0xCC06D5E5D12E0874ULL,
		0x4C319176DBA8AFBDULL,
		0x5E439E70BD4DEBA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9F1018A300000000ULL,
		0xD12E0874E7571946ULL,
		0xDBA8AFBDCC06D5E5ULL,
		0xBD4DEBA44C319176ULL,
		0x000000005E439E70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D3016CE71020588ULL,
		0xB9DD3D985C7785BDULL,
		0xBC2792DEBEA34224ULL,
		0xD06CC8F4EB94CE29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0588000000000000ULL,
		0x85BD5D3016CE7102ULL,
		0x4224B9DD3D985C77ULL,
		0xCE29BC2792DEBEA3ULL,
		0x0000D06CC8F4EB94ULL
	}};
	shift = 16;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F9EDEAD3B425EE1ULL,
		0xDA837E5C11398CBAULL,
		0xEF448D31A6BB7DA0ULL,
		0x1BF71DFE6A892DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x569DA12F70800000ULL,
		0x2E089CC65D37CF6FULL,
		0x98D35DBED06D41BFULL,
		0xFF354496D0F7A246ULL,
		0x00000000000DFB8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x656B6F0A73876B5AULL,
		0x70D9AF156C3062BDULL,
		0x0058A7F5BD463E42ULL,
		0xA33138B4C3BFB300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9CE1DAD680000000ULL,
		0x5B0C18AF595ADBC2ULL,
		0x6F518F909C366BC5ULL,
		0x30EFECC0001629FDULL,
		0x0000000028CC4E2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82A1DAAD465260F6ULL,
		0xCE1CA89C9D3B3111ULL,
		0xDD19C651E740ECF6ULL,
		0x7E5F6558F8AC26E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC150ED56A329307BULL,
		0x670E544E4E9D9888ULL,
		0xEE8CE328F3A0767BULL,
		0x3F2FB2AC7C561371ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA836BDF96A813F67ULL,
		0x75EA77FDDBC2D27DULL,
		0xAE5B439ED1D9B7BDULL,
		0x39DFE32C9B60D85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9FB3800000000000ULL,
		0x693ED41B5EFCB540ULL,
		0xDBDEBAF53BFEEDE1ULL,
		0x6C2F572DA1CF68ECULL,
		0x00001CEFF1964DB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05FFC21DCB7D343AULL,
		0xFDB5AB563CD188F1ULL,
		0x77680EF5004683E0ULL,
		0xBFC0C10B77D3C1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB96FA68740000000ULL,
		0xC79A311E20BFF843ULL,
		0xA008D07C1FB6B56AULL,
		0x6EFA783E0EED01DEULL,
		0x0000000017F81821ULL
	}};
	shift = 35;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC2331A644C8F1E82ULL,
		0x18AE587C62EDBD49ULL,
		0x9E622ED23F253CC3ULL,
		0x2E1079946BAC988DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x323C7A0800000000ULL,
		0x8BB6F52708CC6991ULL,
		0xFC94F30C62B961F1ULL,
		0xAEB262367988BB48ULL,
		0x00000000B841E651ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BB45792FDB14F21ULL,
		0xCC8EBD887518C1A8ULL,
		0xB4B2606FEF0B3AB3ULL,
		0x98C695608D76A9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB45792FDB14F2100ULL,
		0x8EBD887518C1A83BULL,
		0xB2606FEF0B3AB3CCULL,
		0xC695608D76A9B3B4ULL,
		0x0000000000000098ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAE71F3AA279454EULL,
		0x9348718960A58445ULL,
		0xDE105F1001842F9BULL,
		0x2707DC2F05E15C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x76B9C7CEA89E5153ULL,
		0xE4D21C6258296111ULL,
		0xB78417C400610BE6ULL,
		0x09C1F70BC1785727ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBEF0646469E27FDBULL,
		0xE46E018F9C735FEAULL,
		0xCBA47E3D9A99B35EULL,
		0x20FBA0865FB2B932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x89FF6C0000000000ULL,
		0xCD7FAAFBC19191A7ULL,
		0x66CD7B91B8063E71ULL,
		0xCAE4CB2E91F8F66AULL,
		0x00000083EE82197EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3BF8382BB2BD691ULL,
		0xFCFEC9286507B869ULL,
		0xF0CF2EA1B26F1093ULL,
		0x4CC381617BFE8694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0AECAF5A440000ULL,
		0x24A1941EE1A70EFEULL,
		0xBA86C9BC424FF3FBULL,
		0x0585EFFA1A53C33CULL,
		0x000000000001330EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 238;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x154640C3D3C3D5E9ULL,
		0x9E15D7C7306C8384ULL,
		0xCE15CDE30019041EULL,
		0x183776806FB37BEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE1EAF48000000000ULL,
		0x3641C20AA32061E9ULL,
		0x0C820F4F0AEBE398ULL,
		0xD9BDF5E70AE6F180ULL,
		0x0000000C1BBB4037ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE966A4D19B99B647ULL,
		0xDCC67944C8AF2C12ULL,
		0x21B2F038D945A41FULL,
		0x3F3BF6836CD1DF02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B64700000000000ULL,
		0xF2C12E966A4D19B9ULL,
		0x5A41FDCC67944C8AULL,
		0x1DF0221B2F038D94ULL,
		0x000003F3BF6836CDULL
	}};
	shift = 20;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0040000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000400000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000040000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000040000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0004000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000040000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000008000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000002000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000400000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}