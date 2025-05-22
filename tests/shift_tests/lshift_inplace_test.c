#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x42AA366FC82B89D8ULL,
		0xD3895E3AF79B853AULL,
		0x5EEDF0CE2B6FC9DCULL,
		0x6DD623EFB8D766C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x7600000000000000ULL,
		0x4E90AA8D9BF20AE2ULL,
		0x7734E2578EBDE6E1ULL,
		0xB257BB7C338ADBF2ULL,
		0x001B7588FBEE35D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int shift = 54;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5AADED36BB919CA2ULL,
		0x627CCA04002A7574ULL,
		0xB1646ED40D49E3B2ULL,
		0x71790AD0C0C9DCABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xADED36BB919CA200ULL,
		0x7CCA04002A75745AULL,
		0x646ED40D49E3B262ULL,
		0x790AD0C0C9DCABB1ULL,
		0x0000000000000071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x96715F150E85C920ULL,
		0x7479D68EAE302B82ULL,
		0x007F00EFEF5DE047ULL,
		0x43E6C503AFF0AC17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2A1D0B9240000000ULL,
		0x1D5C6057052CE2BEULL,
		0xDFDEBBC08EE8F3ADULL,
		0x075FE1582E00FE01ULL,
		0x000000000087CD8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A7B713E65A6333DULL,
		0x74DDA164801E752CULL,
		0x327D769E24001306ULL,
		0x3E4A7A3A0EB0D8A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC4F99698CCF4000ULL,
		0x685920079D4B129EULL,
		0x5DA7890004C19D37ULL,
		0x9E8E83AC362A4C9FULL,
		0x0000000000000F92ULL
	}};
	shift = 206;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x204D4F508131DEDCULL,
		0x86F2AF74E4C118FEULL,
		0x46B848FD2A849214ULL,
		0x1ACBEB6869BFDC1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08131DEDC0000000ULL,
		0x4E4C118FE204D4F5ULL,
		0xD2A84921486F2AF7ULL,
		0x869BFDC1F46B848FULL,
		0x0000000001ACBEB6ULL
	}};
	shift = 220;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE13111202227F1ACULL,
		0x578472318ECD1639ULL,
		0xEDF57E779559D732ULL,
		0x7C4F2E508F752BE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x9E13111202227F1AULL,
		0x2578472318ECD163ULL,
		0x4EDF57E779559D73ULL,
		0x07C4F2E508F752BEULL
	}};
	shift = 252;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB7227F1C52777C89ULL,
		0x5B11902ED5B1AAD4ULL,
		0xBBD4CACCA8A12DF2ULL,
		0x29848BF781F27551ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C52777C89000000ULL,
		0x2ED5B1AAD4B7227FULL,
		0xCCA8A12DF25B1190ULL,
		0xF781F27551BBD4CAULL,
		0x000000000029848BULL
	}};
	shift = 216;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x174F63B8C87EF820ULL,
		0x780B5D5333BA4266ULL,
		0xBD83BABAE965A024ULL,
		0x0ABFD6685F114FABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL,
		0x4CC2E9EC77190FDFULL,
		0x048F016BAA667748ULL,
		0xF577B077575D2CB4ULL,
		0x000157FACD0BE229ULL
	}};
	shift = 245;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9102C2E2D9F22EA8ULL,
		0xC05F66D2717345DFULL,
		0x5FE9D2087F9D3C72ULL,
		0x0DC59FA7E65DEB75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61716CF917540000ULL,
		0xB36938B9A2EFC881ULL,
		0xE9043FCE9E39602FULL,
		0xCFD3F32EF5BAAFF4ULL,
		0x00000000000006E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x19A2D66FA7991E86ULL,
		0xF8E085499C92BC39ULL,
		0xD13FBA7833749663ULL,
		0x275CD5B6126F6BB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9A2D66FA7991E860ULL,
		0x8E085499C92BC391ULL,
		0x13FBA7833749663FULL,
		0x75CD5B6126F6BB7DULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x308E94479D927920ULL,
		0x6D4870DB20D9CC50ULL,
		0xFE5A02F94028E988ULL,
		0x6F60BB589B708AF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC900000000000000ULL,
		0x62818474A23CEC93ULL,
		0x4C436A4386D906CEULL,
		0x579FF2D017CA0147ULL,
		0x00037B05DAC4DB84ULL
	}};
	shift = 243;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07F3A474CC4AC109ULL,
		0x7053FDA760F98F7CULL,
		0x86F03E15CC0F3FD2ULL,
		0x5F27485E4DF65C20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3A474CC4AC10900ULL,
		0x53FDA760F98F7C07ULL,
		0xF03E15CC0F3FD270ULL,
		0x27485E4DF65C2086ULL,
		0x000000000000005FULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75D9F4875C465306ULL,
		0xFF64A808C85AAED9ULL,
		0xDE902C0A983BE4C4ULL,
		0x0D73D5CA9053D16BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1194C18000000000ULL,
		0x16ABB65D767D21D7ULL,
		0x0EF9313FD92A0232ULL,
		0x14F45AF7A40B02A6ULL,
		0x000000035CF572A4ULL
	}};
	shift = 230;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB6DE08FB91AF0E5ULL,
		0x86D11C96FD26139EULL,
		0x75789924CFB604A5ULL,
		0x341C6C4D67953AA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xAADB7823EE46BC39ULL,
		0x61B44725BF4984E7ULL,
		0x9D5E264933ED8129ULL,
		0x0D071B1359E54EA8ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBF3DAF476977C3DBULL,
		0x0379A0F9BCD6EA4DULL,
		0x65B7A7B06CF0116BULL,
		0x6A17D80E555251D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0xDBF3DAF476977C3DULL,
		0xB0379A0F9BCD6EA4ULL,
		0x765B7A7B06CF0116ULL,
		0x06A17D80E555251DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x916F5248A389389BULL,
		0xCB5EAB92CF79A853ULL,
		0x25F27256FB95390DULL,
		0x77A5AC849E078F52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6C00000000000000ULL,
		0x4E45BD49228E24E2ULL,
		0x372D7AAE4B3DE6A1ULL,
		0x4897C9C95BEE54E4ULL,
		0x01DE96B212781E3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x53B3579DD9E7E4F9ULL,
		0x6518F37B4ECDD09FULL,
		0x36C94613F4F35232ULL,
		0x6418039FFD87A9D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93E4000000000000ULL,
		0x427D4ECD5E77679FULL,
		0x48C99463CDED3B37ULL,
		0xA74CDB25184FD3CDULL,
		0x000190600E7FF61EULL
	}};
	shift = 242;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x03909B230FDADE51ULL,
		0x0E127AB0166DF5B4ULL,
		0x4F27929E96B2C430ULL,
		0x76918612E5226CA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7ED6F28800000000ULL,
		0xB36FADA01C84D918ULL,
		0xB59621807093D580ULL,
		0x2913652A793C94F4ULL,
		0x00000003B48C3097ULL
	}};
	shift = 227;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4EFA8292AFB41935ULL,
		0xF644F35D1A9D632DULL,
		0x0859EA6F42A38815ULL,
		0x6C21150A682A2F6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB4193500000000ULL,
		0x1A9D632D4EFA8292ULL,
		0x42A38815F644F35DULL,
		0x682A2F6C0859EA6FULL,
		0x000000006C21150AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFD048EE60B13006FULL,
		0xA53596F2D5374DBDULL,
		0x4443611360CC4A52ULL,
		0x2040529B9E450A71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5898037800000000ULL,
		0xA9BA6DEFE8247730ULL,
		0x0662529529ACB796ULL,
		0xF228538A221B089BULL,
		0x00000001020294DCULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB4DD091036FED628ULL,
		0x23A9A28EC7ED662DULL,
		0x22BBB061FD6EE0D4ULL,
		0x2223D1A8EEBA60F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3742440DBFB58A0ULL,
		0x8EA68A3B1FB598B6ULL,
		0x8AEEC187F5BB8350ULL,
		0x888F46A3BAE983DCULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAA95EDFF6A3CE2B7ULL,
		0x1215F0C3CA7A7499ULL,
		0x4DE42CD369E06E50ULL,
		0x7C8BE647DC1BD178ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E715B8000000000ULL,
		0x3D3A4CD54AF6FFB5ULL,
		0xF03728090AF861E5ULL,
		0x0DE8BC26F21669B4ULL,
		0x0000003E45F323EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x72F36BB7D0CF0137ULL,
		0xBA7BC281AB931A50ULL,
		0x38DBDB60EBB9D4ABULL,
		0x471FB0B95BE2DF6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BB7D0CF01370000ULL,
		0xC281AB931A5072F3ULL,
		0xDB60EBB9D4ABBA7BULL,
		0xB0B95BE2DF6D38DBULL,
		0x000000000000471FULL
	}};
	shift = 208;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC1A470950611184CULL,
		0x73BE7C152BC068EBULL,
		0x7ACEA79D983E07BCULL,
		0x510AB5FB77663650ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A83088C2600000ULL,
		0xE0A95E03475E0D23ULL,
		0x3CECC1F03DE39DF3ULL,
		0xAFDBBB31B283D675ULL,
		0x0000000000028855ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x41D1D3A7BFE02149ULL,
		0x7667EE6B26A4A399ULL,
		0xDD20AAD6FD4DFF82ULL,
		0x443694DE821DD10CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D3DFF010A480000ULL,
		0x735935251CCA0E8EULL,
		0x56B7EA6FFC13B33FULL,
		0xA6F410EE8866E905ULL,
		0x00000000000221B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x79CC28B8D8A4A8C7ULL,
		0xF272D4EFAC10D736ULL,
		0x099A0D9CF63800D9ULL,
		0x43A6066AE6FA436DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36292A31C0000000ULL,
		0xEB0435CD9E730A2EULL,
		0x3D8E00367C9CB53BULL,
		0xB9BE90DB42668367ULL,
		0x0000000010E9819AULL
	}};
	shift = 222;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC37945356A75DA8AULL,
		0xCA6F781F656DFF46ULL,
		0xBCB410A852264126ULL,
		0x04C69F8C4586267BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F28A6AD4EBB5140ULL,
		0x4DEF03ECADBFE8D8ULL,
		0x9682150A44C824D9ULL,
		0x98D3F188B0C4CF77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x24C8F073BE874DB3ULL,
		0x7E88BD7997FAF9CDULL,
		0x80D4248B8651B340ULL,
		0x73D1ACDE97FB2074ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x874DB30000000000ULL,
		0xFAF9CD24C8F073BEULL,
		0x51B3407E88BD7997ULL,
		0xFB207480D4248B86ULL,
		0x00000073D1ACDE97ULL
	}};
	shift = 232;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE27717CFD69AD662ULL,
		0x369A9FA11716188EULL,
		0x4DDCE054D1DF1899ULL,
		0x337D75ADE7493CC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xEE27717CFD69AD66ULL,
		0x9369A9FA11716188ULL,
		0x34DDCE054D1DF189ULL,
		0x0337D75ADE7493CCULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC50C8CF5EF5B2C4ULL,
		0x7FDF37699420D242ULL,
		0xCCBF84D543265294ULL,
		0x317252757CFC6CC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF143233D7BD6CB10ULL,
		0xFF7CDDA65083490AULL,
		0x32FE13550C994A51ULL,
		0xC5C949D5F3F1B307ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9A4FD52EE786C55ULL,
		0xFFB4AD16B2610165ULL,
		0x21F3C77494EBA203ULL,
		0x105DAF53C7493741ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA800000000000000ULL,
		0x2F4D27EA9773C362ULL,
		0x1FFDA568B593080BULL,
		0x090F9E3BA4A75D10ULL,
		0x0082ED7A9E3A49BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD344ECD7FA0C0B5DULL,
		0x54F9F9C6050B3E0FULL,
		0xFCB2BFAD8F80E23EULL,
		0x15CA0E8000E6FABEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A2766BFD0605AE8ULL,
		0xA7CFCE302859F07EULL,
		0xE595FD6C7C0711F2ULL,
		0xAE5074000737D5F7ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2239BE454B3B808DULL,
		0xC62DC9E02C0C475BULL,
		0x3346F09A749BE641ULL,
		0x14676BC2CBB8CA02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x677011A000000000ULL,
		0x8188EB644737C8A9ULL,
		0x937CC838C5B93C05ULL,
		0x7719404668DE134EULL,
		0x000000028CED7859ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E14EEC7F4B2804EULL,
		0xECBFBC93B271464EULL,
		0xBE4324940E89A8DDULL,
		0x64E066BA6C4A776FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA013800000000000ULL,
		0x5193A7853BB1FD2CULL,
		0x6A377B2FEF24EC9CULL,
		0x9DDBEF90C92503A2ULL,
		0x0000193819AE9B12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x93CB0EF2A0E684F4ULL,
		0x9141362BEDFA567BULL,
		0x8CB33EDBBAE50FF9ULL,
		0x3DB7DB577347D87BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E587795073427A0ULL,
		0x8A09B15F6FD2B3DCULL,
		0x6599F6DDD7287FCCULL,
		0xEDBEDABB9A3EC3DCULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x320C05F768FE9A58ULL,
		0x3F111B09AA4E602BULL,
		0x0CD25C9B99170479ULL,
		0x041ACFC7E9B70466ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FE9A58000000000ULL,
		0xA4E602B320C05F76ULL,
		0x91704793F111B09AULL,
		0x9B704660CD25C9B9ULL,
		0x0000000041ACFC7EULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5CD717BA9FD91169ULL,
		0x1562280DDAAD4F46ULL,
		0xFE05553CB5F9B1E0ULL,
		0x49CD24E405023230ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x753FB222D2000000ULL,
		0x1BB55A9E8CB9AE2FULL,
		0x796BF363C02AC450ULL,
		0xC80A046461FC0AAAULL,
		0x0000000000939A49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2D24D797B030CC32ULL,
		0xF907B3B2D5756A33ULL,
		0xC7007D92EADCB401ULL,
		0x0BC42DD55095CD71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0C330C800000000ULL,
		0x55D5A8CCB4935E5EULL,
		0xAB72D007E41ECECBULL,
		0x425735C71C01F64BULL,
		0x000000002F10B755ULL
	}};
	shift = 226;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA12F0D1749BD0C29ULL,
		0x3851CEC88E706A08ULL,
		0x965A319262839AECULL,
		0x157CD162C3315D37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x37A1852000000000ULL,
		0xCE0D411425E1A2E9ULL,
		0x50735D870A39D911ULL,
		0x662BA6F2CB46324CULL,
		0x00000002AF9A2C58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6D5B79CBDA59D675ULL,
		0x844DC153B6764A2CULL,
		0x679E83679B0651C1ULL,
		0x39796323FDC973E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x397B4B3ACEA00000ULL,
		0x2A76CEC9458DAB6FULL,
		0x6CF360CA383089B8ULL,
		0x647FB92E7CCCF3D0ULL,
		0x0000000000072F2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D9E3843DA702BC0ULL,
		0xA18CF3B0540BE9B8ULL,
		0xC479746A996D22CAULL,
		0x73399FD72E95CD27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F69C0AF00000000ULL,
		0xC1502FA6E13678E1ULL,
		0xAA65B48B2A8633CEULL,
		0x5CBA57349F11E5D1ULL,
		0x0000000001CCE67FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7195AC81CECF6968ULL,
		0x90D3F1FFCF97EBA1ULL,
		0x645212ADE3969E27ULL,
		0x1A76DA7FEB151160ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B4B400000000000ULL,
		0xBF5D0B8CAD640E76ULL,
		0xB4F13C869F8FFE7CULL,
		0xA88B032290956F1CULL,
		0x000000D3B6D3FF58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC6AC456C17638D8CULL,
		0xA84A9FAD50638FEEULL,
		0xED37F1A4D9ACC694ULL,
		0x254355A202A08CD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C00000000000000ULL,
		0xEEC6AC456C17638DULL,
		0x94A84A9FAD50638FULL,
		0xD3ED37F1A4D9ACC6ULL,
		0x00254355A202A08CULL
	}};
	shift = 248;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA202DFECA9AAD20CULL,
		0x5F8C92827BBE77FFULL,
		0x8A79F7A5B78374F0ULL,
		0x3F13DF12AA1FB1FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD95355A418000000ULL,
		0x04F77CEFFF4405BFULL,
		0x4B6F06E9E0BF1925ULL,
		0x25543F63F514F3EFULL,
		0x00000000007E27BEULL
	}};
	shift = 217;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7DFAB5B673651F58ULL,
		0xF2BD45BBA56F89EFULL,
		0x37FAB1B1D10AF2DDULL,
		0x0E172D6A212405A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAB5B673651F5800ULL,
		0xBD45BBA56F89EF7DULL,
		0xFAB1B1D10AF2DDF2ULL,
		0x172D6A212405A337ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD96B347780A974F3ULL,
		0x84A376432E7D730CULL,
		0x6C6E42321834EBD3ULL,
		0x78EE9BF797B819A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD1DE02A5D3CC000ULL,
		0xDD90CB9F5CC3365AULL,
		0x908C860D3AF4E128ULL,
		0xA6FDE5EE06685B1BULL,
		0x0000000000001E3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAEE6002368BE2C7EULL,
		0xA7DD951030083C84ULL,
		0xE0A423DC5DFEEE67ULL,
		0x6C4F5FA937301B8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x2BB98008DA2F8B1FULL,
		0xE9F765440C020F21ULL,
		0xF82908F7177FBB99ULL,
		0x1B13D7EA4DCC06E3ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA1ACF77EAA510174ULL,
		0x0481CEF485569220ULL,
		0x43468F1F16B136EAULL,
		0x3CF657456C0F0695ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF552880BA000000ULL,
		0x7A42AB491050D67BULL,
		0x8F8B589B750240E7ULL,
		0xA2B607834AA1A347ULL,
		0x00000000001E7B2BULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC51F9CF00A7620A3ULL,
		0x4196F045F9AD1347ULL,
		0x1D602158B79FAD0AULL,
		0x598B9BAC6AD73FB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C00000000000000ULL,
		0x1F147E73C029D882ULL,
		0x29065BC117E6B44DULL,
		0xE475808562DE7EB4ULL,
		0x01662E6EB1AB5CFEULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x427666F4E43AB347ULL,
		0x3C148E4FC9907BDFULL,
		0x4540F49C43A5EFE3ULL,
		0x5DFD33727C7E69FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD390EACD1C000000ULL,
		0x3F2641EF7D09D99BULL,
		0x710E97BF8CF05239ULL,
		0xC9F1F9A7F51503D2ULL,
		0x000000000177F4CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x89C6CAA956B876FBULL,
		0x8510766A02D84B4CULL,
		0xF1DBD193980DF644ULL,
		0x3BA26209396BDA86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x9138D9552AD70EDFULL,
		0x90A20ECD405B0969ULL,
		0xDE3B7A327301BEC8ULL,
		0x07744C41272D7B50ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x59D77DF9CA19EE93ULL,
		0x709218A215C876AFULL,
		0x6A3B22F676917ACDULL,
		0x372FE03DC68353F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFBF39433DD26000ULL,
		0x431442B90ED5EB3AULL,
		0x645ECED22F59AE12ULL,
		0xFC07B8D06A7E4D47ULL,
		0x00000000000006E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDB002D88C081ECB9ULL,
		0x5B0D13695A921AA1ULL,
		0x0A6D0E0E27ADF07FULL,
		0x2A40B0CA7B343BFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x040F65C800000000ULL,
		0xD490D50ED8016C46ULL,
		0x3D6F83FAD8689B4AULL,
		0xD9A1DFD853687071ULL,
		0x0000000152058653ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD8A39EAE48FD1AB6ULL,
		0xCA717880877199EFULL,
		0x7656E20AF3C72C6CULL,
		0x71EF51CEE9B0CBDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56C0000000000000ULL,
		0x3DFB1473D5C91FA3ULL,
		0x8D994E2F1010EE33ULL,
		0x7B8ECADC415E78E5ULL,
		0x000E3DEA39DD3619ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5AE8829B78355630ULL,
		0xA2AB30429DF009BCULL,
		0x400644270B8A7835ULL,
		0x4B3B91F0F27C99C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB180000000000000ULL,
		0x4DE2D74414DBC1AAULL,
		0xC1AD15598214EF80ULL,
		0xCE2A003221385C53ULL,
		0x000259DC8F8793E4ULL
	}};
	shift = 243;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5F187193F1E3F7E5ULL,
		0x846A7C3F4D8AE289ULL,
		0xEE1E57998E332CB0ULL,
		0x6DCCFB67A9B18493ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF940000000000000ULL,
		0xA257C61C64FC78FDULL,
		0x2C211A9F0FD362B8ULL,
		0x24FB8795E6638CCBULL,
		0x001B733ED9EA6C61ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x93D08BB88FB2CD27ULL,
		0xFB3BE0C8873D0CB0ULL,
		0xE22FBE7630D46922ULL,
		0x11B49DCDD3AE9E64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB88FB2CD27000000ULL,
		0xC8873D0CB093D08BULL,
		0x7630D46922FB3BE0ULL,
		0xCDD3AE9E64E22FBEULL,
		0x000000000011B49DULL
	}};
	shift = 216;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1074195FFD598CF6ULL,
		0x1CE6C0CB79046450ULL,
		0xB8E795CE79C0F8B6ULL,
		0x6489F3F43352D0FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFEACC67B0000000ULL,
		0x5BC823228083A0CAULL,
		0x73CE07C5B0E73606ULL,
		0xA19A9687DDC73CAEULL,
		0x0000000003244F9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC291E80B89E5AFBULL,
		0x957048E008F00696ULL,
		0x2E9C7C874DD644CBULL,
		0x1248FFDBF0794C15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F405C4F2D7D8000ULL,
		0x24700478034B7614ULL,
		0x3E43A6EB2265CAB8ULL,
		0x7FEDF83CA60A974EULL,
		0x0000000000000924ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x00F15FD84E3D1C50ULL,
		0x148B191DB2E5DA2BULL,
		0xFF93B82EC547A965ULL,
		0x6A358A050BD5EBB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E8E280000000000ULL,
		0x72ED158078AFEC27ULL,
		0xA3D4B28A458C8ED9ULL,
		0xEAF5DC7FC9DC1762ULL,
		0x000000351AC50285ULL
	}};
	shift = 231;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB98224039B0BFE19ULL,
		0x62CA47B5483EB090ULL,
		0x6E83E2D8D0A263C7ULL,
		0x6522F87793D1FA81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9000000000000000ULL,
		0x0B98224039B0BFE1ULL,
		0x762CA47B5483EB09ULL,
		0x16E83E2D8D0A263CULL,
		0x06522F87793D1FA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC48C7AB3E5B55401ULL,
		0xB79951651510D0B6ULL,
		0x0987945F2DD916EDULL,
		0x141879375534359FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0200000000000000ULL,
		0x6D8918F567CB6AA8ULL,
		0xDB6F32A2CA2A21A1ULL,
		0x3E130F28BE5BB22DULL,
		0x002830F26EAA686BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x62D4F273DA1281DFULL,
		0x531ED2DA804D8134ULL,
		0x13FC16F0C7B7391EULL,
		0x0440647486D07377ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDA1281DF00000000ULL,
		0x804D813462D4F273ULL,
		0xC7B7391E531ED2DAULL,
		0x86D0737713FC16F0ULL,
		0x0000000004406474ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDCCB71F3699BDE7EULL,
		0xF60DD8E06E289342ULL,
		0xE3E636E4DA0C19C2ULL,
		0x3406D107D03624EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BDE7E000000000ULL,
		0xE289342DCCB71F36ULL,
		0xA0C19C2F60DD8E06ULL,
		0x03624EAE3E636E4DULL,
		0x00000003406D107DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFDB1DCB93DA7BC14ULL,
		0xEDEA424742F95C34ULL,
		0x4A82E489E61A1755ULL,
		0x418D5040881352EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBC14000000000000ULL,
		0x5C34FDB1DCB93DA7ULL,
		0x1755EDEA424742F9ULL,
		0x52EF4A82E489E61AULL,
		0x0000418D50408813ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFF2BD2AF50F199C0ULL,
		0xB399207EA2FDCCF1ULL,
		0x796C94846B8D2CF9ULL,
		0x2A9D4D73546DAF53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57A878CCE0000000ULL,
		0x3F517EE678FF95E9ULL,
		0x4235C6967CD9CC90ULL,
		0xB9AA36D7A9BCB64AULL,
		0x0000000000154EA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9841CA0D7B211F82ULL,
		0xA277AD2D9C306A0AULL,
		0xF1AA01BE2EF8D1EFULL,
		0x6CB0CB43B7E0B2ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E506BD908FC100ULL,
		0x3BD696CE1835054CULL,
		0xD500DF177C68F7D1ULL,
		0x5865A1DBF0597678ULL,
		0x0000000000000036ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBFE18978D7CFCCF8ULL,
		0x1A4C4B1F78D0718BULL,
		0x2DF3464AB96B0D41ULL,
		0x6A8DCF5A54F5CC58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7E67C0000000000ULL,
		0x6838C5DFF0C4BC6BULL,
		0xB586A08D26258FBCULL,
		0x7AE62C16F9A3255CULL,
		0x0000003546E7AD2AULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD1BCF9152D4844A1ULL,
		0x9AB6D20D4BAA76CCULL,
		0x3E47A41C231450BFULL,
		0x025917C1EE8564D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4225080000000000ULL,
		0x53B6668DE7C8A96AULL,
		0xA285FCD5B6906A5DULL,
		0x2B2699F23D20E118ULL,
		0x00000012C8BE0F74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBA09FD4B8C9F45C7ULL,
		0x7F43D324756DFE1EULL,
		0x3297849972E2FD8BULL,
		0x6A72D23429EBFBD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x327D171C00000000ULL,
		0xD5B7F87AE827F52EULL,
		0xCB8BF62DFD0F4C91ULL,
		0xA7AFEF4CCA5E1265ULL,
		0x00000001A9CB48D0ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0FC354A8B3C95C62ULL,
		0xA4A3044ECD5A0BE2ULL,
		0x49A7EF72529B73FCULL,
		0x0F778238B9765266ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFC354A8B3C95C620ULL,
		0x4A3044ECD5A0BE20ULL,
		0x9A7EF72529B73FCAULL,
		0xF778238B97652664ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x284E66DDA9262FC6ULL,
		0xA594E068E5BE91F7ULL,
		0x5FAE2B72F41E49F1ULL,
		0x5508468EB58A3952ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xE509CCDBB524C5F8ULL,
		0x34B29C0D1CB7D23EULL,
		0x4BF5C56E5E83C93EULL,
		0x0AA108D1D6B1472AULL
	}};
	shift = 253;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x72692020ECD61292ULL,
		0x16885B8EA1EF513DULL,
		0xE936B6BE4E23AF23ULL,
		0x76B5168AFCD8B6B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECD612920000000ULL,
		0xEA1EF513D7269202ULL,
		0xE4E23AF2316885B8ULL,
		0xAFCD8B6B8E936B6BULL,
		0x00000000076B5168ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF7C806DEB01DB71EULL,
		0x9BE1DCDE5DA07AF6ULL,
		0x90B9E6AF7BDAB2B1ULL,
		0x73A6A7ACADE499A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDEB01DB71E000000ULL,
		0xDE5DA07AF6F7C806ULL,
		0xAF7BDAB2B19BE1DCULL,
		0xACADE499A290B9E6ULL,
		0x000000000073A6A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8A32496EBEB72020ULL,
		0xC05ABAAA9B581C72ULL,
		0x543DA7B2B400013AULL,
		0x6C3AC77C44CAC568ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2496EBEB72020000ULL,
		0xABAAA9B581C728A3ULL,
		0xDA7B2B400013AC05ULL,
		0xAC77C44CAC568543ULL,
		0x00000000000006C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFFD625AFED2ACFC5ULL,
		0x16FFA8ADB37C2711ULL,
		0xA24CEEE78F4B85E1ULL,
		0x25D9010706762007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x3FFAC4B5FDA559F8ULL,
		0x22DFF515B66F84E2ULL,
		0xF4499DDCF1E970BCULL,
		0x04BB2020E0CEC400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDE7EA4DFB9947AD9ULL,
		0x5AA68518A7001DA0ULL,
		0xAA4ECA246BB1E228ULL,
		0x4BC9012260B53150ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD49BF7328F5B2000ULL,
		0xD0A314E003B41BCFULL,
		0xD9448D763C450B54ULL,
		0x20244C16A62A1549ULL,
		0x0000000000000979ULL
	}};
	shift = 205;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB2ECA518DCA54984ULL,
		0x1C31076A32BBD590ULL,
		0x95BA088B251F7F8DULL,
		0x0CE5D5C383CAB1D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xECA518DCA5498400ULL,
		0x31076A32BBD590B2ULL,
		0xBA088B251F7F8D1CULL,
		0xE5D5C383CAB1D095ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA87C44168DE67CF3ULL,
		0xAE0E09FAED65C88EULL,
		0xE63A8757FC1A1784ULL,
		0x38455347359996B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x543E220B46F33E79ULL,
		0x570704FD76B2E447ULL,
		0x731D43ABFE0D0BC2ULL,
		0x1C22A9A39ACCCB5CULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCBAF9EBCBD138158ULL,
		0x6A66CDC90DED8D37ULL,
		0xFEC157BDCFCA58EDULL,
		0x41FE079657074BF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5E89C0AC0000000ULL,
		0x486F6C69BE5D7CF5ULL,
		0xEE7E52C76B53366EULL,
		0xB2B83A5F8FF60ABDULL,
		0x00000000020FF03CULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4DF6D2A82E251729ULL,
		0x320501793CFB7DA3ULL,
		0x86193FFE8F1252BBULL,
		0x13DF07427B487D18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xD37DB4AA0B8945CAULL,
		0xCC81405E4F3EDF68ULL,
		0x21864FFFA3C494AEULL,
		0x04F7C1D09ED21F46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAC01BE99BBD3338FULL,
		0xB3255CE567959A84ULL,
		0x6DD0F9B1ECCFC817ULL,
		0x4C74B56BFB649708ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF4CDDE999C7800ULL,
		0x2AE72B3CACD42560ULL,
		0x87CD8F667E40BD99ULL,
		0xA5AB5FDB24B8436EULL,
		0x0000000000000263ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA839263F22FF84A2ULL,
		0xD40F7EAB664DE174ULL,
		0xAEE24D427EA21AF2ULL,
		0x6DCE5A0E03BF9AD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F22FF84A2000000ULL,
		0xAB664DE174A83926ULL,
		0x427EA21AF2D40F7EULL,
		0x0E03BF9AD1AEE24DULL,
		0x00000000006DCE5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE4DF0369C6E42AAAULL,
		0xDC877FC5F54559EFULL,
		0x85C9E689742429AAULL,
		0x0CB70B5767E5F38CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA800000000000000ULL,
		0xBF937C0DA71B90AAULL,
		0xAB721DFF17D51567ULL,
		0x3217279A25D090A6ULL,
		0x0032DC2D5D9F97CEULL
	}};
	shift = 250;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E7CDC6A2AEC5850ULL,
		0x60025C77C898564BULL,
		0xCB59A984469B9BF1ULL,
		0x350DC110667C1172ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79F371A8ABB16140ULL,
		0x800971DF2261592EULL,
		0x2D66A6111A6E6FC5ULL,
		0xD437044199F045CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1069255A5A3E5C0BULL,
		0xEE04C731F6A09747ULL,
		0x6CBDC87FC6047FEEULL,
		0x6CDE9A44346212C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4B47CB8160000000ULL,
		0x3ED412E8E20D24ABULL,
		0xF8C08FFDDDC098E6ULL,
		0x868C4258AD97B90FULL,
		0x000000000D9BD348ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6C8D4876A844BBACULL,
		0x78309991748702B2ULL,
		0xABE6250FB7FDC86DULL,
		0x059F8DA4201CD5E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEEB0000000000000ULL,
		0x0AC9B23521DAA112ULL,
		0x21B5E0C26645D21CULL,
		0x578AAF98943EDFF7ULL,
		0x0000167E36908073ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDBFED2EA1192CD37ULL,
		0x2BB6EC1490DAF0DCULL,
		0x501D98E551EF0A97ULL,
		0x0118A71FF3344EE8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA8464B34DC00000ULL,
		0x052436BC3736FFB4ULL,
		0x39547BC2A5CAEDBBULL,
		0xC7FCCD13BA140766ULL,
		0x0000000000004629ULL
	}};
	shift = 214;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5A3FB7A984ECD4A9ULL,
		0x9563EAB0BEACC452ULL,
		0xF2F58B27B0A46DC6ULL,
		0x43482DE5AAF59B9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C2766A548000000ULL,
		0x85F5662292D1FDBDULL,
		0x3D85236E34AB1F55ULL,
		0x2D57ACDCEF97AC59ULL,
		0x00000000021A416FULL
	}};
	shift = 219;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD22513710A852FAEULL,
		0x35924057CD79D79DULL,
		0x61ACA3751BA22E0BULL,
		0x6A143AB8672D2EC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD22513710A852FAEULL,
		0x35924057CD79D79DULL,
		0x61ACA3751BA22E0BULL,
		0x6A143AB8672D2EC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8CD8CD49498EFDE3ULL,
		0x3C4FD52566EF4343ULL,
		0xCDEF87F0D795A1C0ULL,
		0x2DE019FFC3FB3865ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDFBC600000000000ULL,
		0xE868719B19A92931ULL,
		0xB4380789FAA4ACDDULL,
		0x670CB9BDF0FE1AF2ULL,
		0x000005BC033FF87FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3937F4EE5EB15D49ULL,
		0xE0E1A36BA9ED0B70ULL,
		0x8FA6C1119E1EF26FULL,
		0x463B71C9573141DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA772F58AEA48000ULL,
		0xD1B5D4F685B81C9BULL,
		0x6088CF0F7937F070ULL,
		0xB8E4AB98A0EE47D3ULL,
		0x000000000000231DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xADE20AD5D3D1FCE8ULL,
		0x77C4B583CC05FB61ULL,
		0x9E83DDA837632DCCULL,
		0x7AFCF343A3F89D28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A3F9D000000000ULL,
		0x980BF6C35BC415ABULL,
		0x6EC65B98EF896B07ULL,
		0x47F13A513D07BB50ULL,
		0x00000000F5F9E687ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75EA90364312CE38ULL,
		0x453D69947045EF1BULL,
		0x39EC54E46B52D252ULL,
		0x5AC6B852242127F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2189671C000000ULL,
		0xCA3822F78DBAF548ULL,
		0x7235A96929229EB4ULL,
		0x29121093F99CF62AULL,
		0x00000000002D635CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9CC29899568DC377ULL,
		0x47A05796079700A8ULL,
		0x660CAD53E771EFE4ULL,
		0x5595213CB57F51C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDDC0000000000000ULL,
		0x2A2730A62655A370ULL,
		0xF911E815E581E5C0ULL,
		0x7199832B54F9DC7BULL,
		0x001565484F2D5FD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD068AA39323DFB90ULL,
		0x03853839E2F4A264ULL,
		0xDB07FA398DE83425ULL,
		0x6FE6DC1DF755FD89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7EE400000000000ULL,
		0xD2899341A2A8E4C8ULL,
		0xA0D0940E14E0E78BULL,
		0x57F6276C1FE8E637ULL,
		0x000001BF9B7077DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x29613366BA2FF4CFULL,
		0x5AE11280E5BCB8DEULL,
		0xA7D145183E1B0985ULL,
		0x327642F9E896722CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD9AE8BFD33C00000ULL,
		0xA0396F2E378A584CULL,
		0x460F86C26156B844ULL,
		0xBE7A259C8B29F451ULL,
		0x00000000000C9D90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBCB19703985DD8F5ULL,
		0xA6ED106897AE1AAAULL,
		0xAFA135675314A00AULL,
		0x59E6694F77656C06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81CC2EEC7A800000ULL,
		0x344BD70D555E58CBULL,
		0xB3A98A5005537688ULL,
		0xA7BBB2B60357D09AULL,
		0x00000000002CF334ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x43C0D6BF20B47051ULL,
		0x12F135B037D59D1DULL,
		0x9D4D5EE239D9CE52ULL,
		0x27EFF172B03EA3D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C0D6BF20B470510ULL,
		0x2F135B037D59D1D4ULL,
		0xD4D5EE239D9CE521ULL,
		0x7EFF172B03EA3D49ULL,
		0x0000000000000002ULL
	}};
	shift = 196;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8ABBE5D1991E59E1ULL,
		0xADF77D699F4BEFE9ULL,
		0x1B384C388281375BULL,
		0x2996601CC688A4D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3323CB3C2000000ULL,
		0xD33E97DFD31577CBULL,
		0x7105026EB75BEEFAULL,
		0x398D1149AA367098ULL,
		0x0000000000532CC0ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x03E45B70B7DE8956ULL,
		0x6F60794D66FE9942ULL,
		0x9B826CF5CA6C1C2BULL,
		0x4E3D10B0CB261ED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E16FBD12AC00000ULL,
		0x29ACDFD328407C8BULL,
		0x9EB94D83856DEC0FULL,
		0x161964C3DA53704DULL,
		0x000000000009C7A2ULL
	}};
	shift = 213;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD01CDF4D54301AF5ULL,
		0x6F51A0B30366CBD0ULL,
		0x4F3DEFFD15852690ULL,
		0x32943797076B162CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE9AA86035EA0000ULL,
		0x416606CD97A1A039ULL,
		0xDFFA2B0A4D20DEA3ULL,
		0x6F2E0ED62C589E7BULL,
		0x0000000000006528ULL
	}};
	shift = 209;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCA7C0E4333618B8CULL,
		0x302E9535A5032D8DULL,
		0x4D33A95CBBF6DB31ULL,
		0x13F4F2A11A963BB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7180000000000000ULL,
		0xB1B94F81C8666C31ULL,
		0x662605D2A6B4A065ULL,
		0x7729A6752B977EDBULL,
		0x00027E9E542352C7ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB9047E9B52CB60CEULL,
		0x8DF90ECB48EEDC46ULL,
		0xC0BB17254FFE3223ULL,
		0x4FB9B1BA63877F16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA6D4B2D83380000ULL,
		0x3B2D23BB711AE411ULL,
		0x5C953FF8C88E37E4ULL,
		0xC6E98E1DFC5B02ECULL,
		0x0000000000013EE6ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x287DD9181F27B90EULL,
		0x612FE2BEF83C0B1FULL,
		0x25AA30DA7D192A8FULL,
		0x69D2ADC75DF1ED83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2303E4F721C0000ULL,
		0xC57DF078163E50FBULL,
		0x61B4FA32551EC25FULL,
		0x5B8EBBE3DB064B54ULL,
		0x000000000000D3A5ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1B940C4E19747D18ULL,
		0xCA74DB3F46D6713DULL,
		0x2F6389C2EFA71FA5ULL,
		0x38442A6F45D77F2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3728189C32E8FA3ULL,
		0xB94E9B67E8DACE27ULL,
		0xE5EC71385DF4E3F4ULL,
		0x0708854DE8BAEFE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x951DC7A434170A9AULL,
		0x0B395AF22037F017ULL,
		0x45E8EFC6FCEBC468ULL,
		0x30062B2F1B9EA63FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC2A6800000000000ULL,
		0xFC05E54771E90D05ULL,
		0xF11A02CE56BC880DULL,
		0xA98FD17A3BF1BF3AULL,
		0x00000C018ACBC6E7ULL
	}};
	shift = 238;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8FE219FA7D09C181ULL,
		0xA1DC3FE859E43248ULL,
		0x95A64176B2A56BE7ULL,
		0x3C022F293E4CB1C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E84E0C08000000ULL,
		0x42CF2192447F10CFULL,
		0xB5952B5F3D0EE1FFULL,
		0x49F2658E4CAD320BULL,
		0x0000000001E01179ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4923D3018FFAC42BULL,
		0xEF2D66453414CE4EULL,
		0xAA9FDDF6251862DAULL,
		0x74CEBD244A6DE182ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFF58856000000000ULL,
		0x8299C9C9247A6031ULL,
		0xA30C5B5DE5ACC8A6ULL,
		0x4DBC305553FBBEC4ULL,
		0x0000000E99D7A489ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B4B119FDF0CBDC6ULL,
		0x8B6BD39A0DCF230EULL,
		0x191FF7ADCDECB8A3ULL,
		0x50E26C30BD07C19EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x696233FBE197B8C0ULL,
		0x6D7A7341B9E461D1ULL,
		0x23FEF5B9BD971471ULL,
		0x1C4D8617A0F833C3ULL,
		0x000000000000000AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE0F25FF078FEC8F0ULL,
		0x7BDB343D33CC959DULL,
		0x117C6C6B3AC80B5DULL,
		0x2EB7A96ED97E58FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4780000000000000ULL,
		0xACEF0792FF83C7F6ULL,
		0x5AEBDED9A1E99E64ULL,
		0xC7E88BE36359D640ULL,
		0x000175BD4B76CBF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x45D6B22C1586CC51ULL,
		0xBDF804BE41BB3ED1ULL,
		0x5722F48B80961A1AULL,
		0x7D0C8A8889351A1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x561B314400000000ULL,
		0x06ECFB45175AC8B0ULL,
		0x0258686AF7E012F9ULL,
		0x24D468695C8BD22EULL,
		0x00000001F4322A22ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD502DB8B741F3730ULL,
		0xA3C8C660E6EED1D0ULL,
		0xC581A59E98AD5559ULL,
		0x46A2A08D247C73BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CDCC00000000000ULL,
		0xBB4743540B6E2DD0ULL,
		0xB555668F2319839BULL,
		0xF1CEEB1606967A62ULL,
		0x0000011A8A823491ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5AE32D2F13B7D271ULL,
		0x4603253A4ED77850ULL,
		0xE76B24C5B32603EFULL,
		0x6EAE1484499C8D64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9388000000000000ULL,
		0xC282D71969789DBEULL,
		0x1F7A301929D276BBULL,
		0x6B273B59262D9930ULL,
		0x00037570A4224CE4ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1B3A39782B1006EDULL,
		0xEF834BA16FE5D5DFULL,
		0x413F6102471A4788ULL,
		0x6C5503C863435BA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BB4000000000000ULL,
		0x577C6CE8E5E0AC40ULL,
		0x1E23BE0D2E85BF97ULL,
		0x6E9904FD84091C69ULL,
		0x0001B1540F218D0DULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAECC6B425D257F52ULL,
		0x6B64EDA5C53037A3ULL,
		0xB67A8E800A15333DULL,
		0x1C817CC20E54A686ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAECC6B425D257F52ULL,
		0x6B64EDA5C53037A3ULL,
		0xB67A8E800A15333DULL,
		0x1C817CC20E54A686ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x561CC31D44686995ULL,
		0x688B8AE3661AC153ULL,
		0x846ACE707B187E56ULL,
		0x29D9D4BD4507ACBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x863A88D0D32A0000ULL,
		0x15C6CC3582A6AC39ULL,
		0x9CE0F630FCACD117ULL,
		0xA97A8A0F597708D5ULL,
		0x00000000000053B3ULL
	}};
	shift = 209;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA786F418BF90706EULL,
		0x4847E01B72CAEFD6ULL,
		0xD3DEA3B4DBD41D2FULL,
		0x5E427CF646B2BE51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x6A786F418BF90706ULL,
		0xF4847E01B72CAEFDULL,
		0x1D3DEA3B4DBD41D2ULL,
		0x05E427CF646B2BE5ULL
	}};
	shift = 252;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8F412F68F728EAE0ULL,
		0x93C2FAEE3FFD8AF1ULL,
		0x9D7CF6BA73E81453ULL,
		0x532C8A59BDC0EB57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31E825ED1EE51D5CULL,
		0x72785F5DC7FFB15EULL,
		0xF3AF9ED74E7D028AULL,
		0x0A65914B37B81D6AULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD293E25EBB982C12ULL,
		0x32908B697573C75AULL,
		0xCC45B49D067D8493ULL,
		0x4C9F98627050310CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7730582400000000ULL,
		0xEAE78EB5A527C4BDULL,
		0x0CFB0926652116D2ULL,
		0xE0A06219988B693AULL,
		0x00000000993F30C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x57474AA16BF41F49ULL,
		0xFBDD2088C0C8DCA8ULL,
		0x1587B6D5C6F746EEULL,
		0x4A56D038A831CB78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFD07D24000000000ULL,
		0x32372A15D1D2A85AULL,
		0xBDD1BBBEF7482230ULL,
		0x0C72DE0561EDB571ULL,
		0x0000001295B40E2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x178CD99A62467C08ULL,
		0xE7C597E6BEBF29CAULL,
		0xEEAF2D9177A11B53ULL,
		0x26130404F3FB5C1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8100000000000000ULL,
		0x3942F19B334C48CFULL,
		0x6A7CF8B2FCD7D7E5ULL,
		0x83FDD5E5B22EF423ULL,
		0x0004C260809E7F6BULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A129BC11BBA2E6FULL,
		0x5E24C3FB90F74245ULL,
		0x0BC45E76C151C9CBULL,
		0x7BBB0B7A24EA36DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DDD173780000000ULL,
		0xC87BA122A5094DE0ULL,
		0x60A8E4E5AF1261FDULL,
		0x12751B6D05E22F3BULL,
		0x000000003DDD85BDULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x95DE2179D095DBFCULL,
		0x8E4F0BE956505BA5ULL,
		0xDFD3469EEF479B10ULL,
		0x64261FC0D3ABD184ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5DE2179D095DBFC0ULL,
		0xE4F0BE956505BA59ULL,
		0xFD3469EEF479B108ULL,
		0x4261FC0D3ABD184DULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1EF847933187ED75ULL,
		0x332B8945A8DF3CC9ULL,
		0xB184F8AF26B69E67ULL,
		0x375A26AAA651F49FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FDAEA000000000ULL,
		0x1BE79923DF08F266ULL,
		0xD6D3CCE6657128B5ULL,
		0xCA3E93F6309F15E4ULL,
		0x00000006EB44D554ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x082CBF81481DEC4DULL,
		0x018114A4B328ECF2ULL,
		0x3FDB12FBCBE557E4ULL,
		0x72E17C3B0EA95C00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x81DEC4D000000000ULL,
		0x328ECF2082CBF814ULL,
		0xBE557E4018114A4BULL,
		0xEA95C003FDB12FBCULL,
		0x000000072E17C3B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x103BDD29F9B90336ULL,
		0x8DC607D2F0861821ULL,
		0x3630D0B2269DFB1DULL,
		0x609A370CA75B61D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x1103BDD29F9B9033ULL,
		0xD8DC607D2F086182ULL,
		0x13630D0B2269DFB1ULL,
		0x0609A370CA75B61DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x10834F06747F1981ULL,
		0xDE6D9D851B02FB98ULL,
		0xAC840F587735D9EFULL,
		0x68C9EC649188E298ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x833A3F8CC0800000ULL,
		0xC28D817DCC0841A7ULL,
		0xAC3B9AECF7EF36CEULL,
		0x3248C4714C564207ULL,
		0x00000000003464F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF7164C4A1D187955ULL,
		0x0AD5F25685849428ULL,
		0x248AD25CC883C548ULL,
		0x20E6915AB686A099ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1D187955000000ULL,
		0x5685849428F7164CULL,
		0x5CC883C5480AD5F2ULL,
		0x5AB686A099248AD2ULL,
		0x000000000020E691ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD4FCFE0D67256B54ULL,
		0x38D795F2CADB7661ULL,
		0x23C80F37992F59FAULL,
		0x07066A7977706ED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCE4AD6A800000000ULL,
		0x95B6ECC3A9F9FC1AULL,
		0x325EB3F471AF2BE5ULL,
		0xEEE0DDA447901E6FULL,
		0x000000000E0CD4F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x40CA10DA896A771BULL,
		0xB31F51BD4A2D49FFULL,
		0xA819A85F742FCFB2ULL,
		0x5ADB26D03087563AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6C00000000000000ULL,
		0xFD0328436A25A9DCULL,
		0xCACC7D46F528B527ULL,
		0xEAA066A17DD0BF3EULL,
		0x016B6C9B40C21D58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5CA66CD786B47660ULL,
		0x8FA13CDFF9BA6B25ULL,
		0x787E2AB673241703ULL,
		0x133A6ED0A3EA07CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9800000000000000ULL,
		0xC957299B35E1AD1DULL,
		0xC0E3E84F37FE6E9AULL,
		0xF39E1F8AAD9CC905ULL,
		0x0004CE9BB428FA81ULL
	}};
	shift = 246;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x17DAFA8590588489ULL,
		0x7B64F364DC79A09FULL,
		0xB68A615AE8FDB13DULL,
		0x7D9B3A25CECEEF64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x20B1091200000000ULL,
		0xB8F3413E2FB5F50BULL,
		0xD1FB627AF6C9E6C9ULL,
		0x9D9DDEC96D14C2B5ULL,
		0x00000000FB36744BULL
	}};
	shift = 225;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0C41F169E651DB56ULL,
		0x866F6070749CB411ULL,
		0x5F1F145A38AA6819ULL,
		0x7AFE5BA4EE4EE8C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAC00000000000000ULL,
		0x221883E2D3CCA3B6ULL,
		0x330CDEC0E0E93968ULL,
		0x8EBE3E28B47154D0ULL,
		0x00F5FCB749DC9DD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5E113982EEF2654FULL,
		0x59C4387781E3C8F5ULL,
		0x6E92D2B6937C1A90ULL,
		0x26E7B4A54BDAA683ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x982EEF2654F00000ULL,
		0x87781E3C8F55E113ULL,
		0x2B6937C1A9059C43ULL,
		0x4A54BDAA6836E92DULL,
		0x0000000000026E7BULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7197A92EE3215C38ULL,
		0x6A0E8BA0F0A626A2ULL,
		0x5E5C7F4F5250969EULL,
		0x6B4159D80A549DE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8C8570E00000000ULL,
		0x3C2989A89C65EA4BULL,
		0xD49425A79A83A2E8ULL,
		0x02952778D7971FD3ULL,
		0x000000001AD05676ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD24334AD98DDD7F8ULL,
		0x49E35320CD98D3ABULL,
		0xB7C85EC3A332F661ULL,
		0x7884DF0983529F41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x334AD98DDD7F8000ULL,
		0x35320CD98D3ABD24ULL,
		0x85EC3A332F66149EULL,
		0x4DF0983529F41B7CULL,
		0x0000000000000788ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA6613A04CD9F214BULL,
		0x096AA59B88E17B64ULL,
		0xD744FBB098F54348ULL,
		0x33C9E45D96FE2DD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x613A04CD9F214B00ULL,
		0x6AA59B88E17B64A6ULL,
		0x44FBB098F5434809ULL,
		0xC9E45D96FE2DD2D7ULL,
		0x0000000000000033ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4B2F9EF55E6AF21DULL,
		0x17E87F45884EB402ULL,
		0x14C110874CCBC030ULL,
		0x752AD9FD5CE62F2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x79ABC87400000000ULL,
		0x213AD0092CBE7BD5ULL,
		0x332F00C05FA1FD16ULL,
		0x7398BCA85304421DULL,
		0x00000001D4AB67F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCE4DED5B3E104BD9ULL,
		0xECAD10F7D1991F6AULL,
		0xDE3A9A4623D74CBFULL,
		0x0B277D8809A66A98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB200000000000000ULL,
		0xD59C9BDAB67C2097ULL,
		0x7FD95A21EFA3323EULL,
		0x31BC75348C47AE99ULL,
		0x00164EFB10134CD5ULL
	}};
	shift = 249;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE68B722B6A70A91DULL,
		0x112075EACE973862ULL,
		0x7194E43D777C1873ULL,
		0x2F2F284A44C78785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A00000000000000ULL,
		0xC5CD16E456D4E152ULL,
		0xE62240EBD59D2E70ULL,
		0x0AE329C87AEEF830ULL,
		0x005E5E5094898F0FULL
	}};
	shift = 249;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x02CA85F8E6CC63F1ULL,
		0xC1E1EB4E8E241918ULL,
		0xB3B319FDD52130FBULL,
		0x28403C866CAE170BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6631F88000000000ULL,
		0x120C8C016542FC73ULL,
		0x90987DE0F0F5A747ULL,
		0x570B85D9D98CFEEAULL,
		0x00000014201E4336ULL
	}};
	shift = 231;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x37DA56BF05B9C6EDULL,
		0xC60F8FA04220B022ULL,
		0x1CF69A7C8C26220FULL,
		0x487AFC48630EC86CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9C6ED00000000000ULL,
		0x0B02237DA56BF05BULL,
		0x6220FC60F8FA0422ULL,
		0xEC86C1CF69A7C8C2ULL,
		0x00000487AFC48630ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD0E36AB9FA7FAD2AULL,
		0xDD60FCF6F1EADD94ULL,
		0xE09223CE1CD997C5ULL,
		0x05B84339140407A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD695000000000000ULL,
		0x6ECA6871B55CFD3FULL,
		0xCBE2EEB07E7B78F5ULL,
		0x03D1F04911E70E6CULL,
		0x000002DC219C8A02ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB06670C235647016ULL,
		0x7C9EF2F8480A8517ULL,
		0x70C7187E04E83158ULL,
		0x108569D612DCE7BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x199C308D591C0580ULL,
		0x27BCBE1202A145ECULL,
		0x31C61F813A0C561FULL,
		0x215A7584B739EFDCULL,
		0x0000000000000004ULL
	}};
	shift = 198;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x201930BC8EBB3753ULL,
		0x6E311C4F16B78598ULL,
		0x3B8C523EB94CF42BULL,
		0x35926D9EE3965EA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2F23AECDD4C00000ULL,
		0x13C5ADE16608064CULL,
		0x8FAE533D0ADB8C47ULL,
		0x67B8E597A94EE314ULL,
		0x00000000000D649BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x27C9A33F3A2BE78EULL,
		0x649D67D9F56E359BULL,
		0x39111BC18D8098B8ULL,
		0x3C0228181686911AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF9E380000000000ULL,
		0xB8D66C9F268CFCE8ULL,
		0x0262E192759F67D5ULL,
		0x1A4468E4446F0636ULL,
		0x000000F008A0605AULL
	}};
	shift = 234;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE21DBAA4989FA7EAULL,
		0xDF5DB884220845B2ULL,
		0x1BBED33F92F56CB2ULL,
		0x238A60FAFE839B44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B7549313F4FD400ULL,
		0xBB710844108B65C4ULL,
		0x7DA67F25EAD965BEULL,
		0x14C1F5FD07368837ULL,
		0x0000000000000047ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC3953B04D31D75FULL,
		0x45BC484BCBE931B7ULL,
		0x2A5EA43B83787790ULL,
		0x5B2D0442B2FFFE88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBE0000000000000ULL,
		0x36FF872A7609A63AULL,
		0xF208B78909797D26ULL,
		0xD1054BD487706F0EULL,
		0x000B65A088565FFFULL
	}};
	shift = 245;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x219D87AC02CFA543ULL,
		0x98E71B5332142BBEULL,
		0xEA73FB19AA70E886ULL,
		0x775033E6AA7A1F68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61EB00B3E950C000ULL,
		0xC6D4CC850AEF8867ULL,
		0xFEC66A9C3A21A639ULL,
		0x0CF9AA9E87DA3A9CULL,
		0x0000000000001DD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAE53F318F7C360C1ULL,
		0x23B89D741F248B8EULL,
		0x4FD5283F5ECF4956ULL,
		0x3886F078E41D4C7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DF0D83040000000ULL,
		0x07C922E3AB94FCC6ULL,
		0xD7B3D25588EE275DULL,
		0x3907531FD3F54A0FULL,
		0x000000000E21BC1EULL
	}};
	shift = 222;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDD81F0016EF9F728ULL,
		0xFD810C3BA561C266ULL,
		0xC383ACDE113A343FULL,
		0x0D972E5A5CD7FA7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B77CFB940000000ULL,
		0xDD2B0E1336EC0F80ULL,
		0xF089D1A1FFEC0861ULL,
		0xD2E6BFD3F61C1D66ULL,
		0x00000000006CB972ULL
	}};
	shift = 219;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x779195BB9F0A0DA1ULL,
		0xC9E4DEC16D850B64ULL,
		0xBF13A2DFDE4AA4D6ULL,
		0x5033DB43E653DA4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41B4200000000000ULL,
		0xA16C8EF232B773E1ULL,
		0x549AD93C9BD82DB0ULL,
		0x7B49D7E2745BFBC9ULL,
		0x00000A067B687CCAULL
	}};
	shift = 237;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDF10A74D5A596C55ULL,
		0x9DA4B719CAF17A21ULL,
		0x8236DBCEA16ECB90ULL,
		0x4A17201F9D5379A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB62A800000000000ULL,
		0xBD10EF8853A6AD2CULL,
		0x65C84ED25B8CE578ULL,
		0xBCD2411B6DE750B7ULL,
		0x0000250B900FCEA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x09A3375AF0D6B867ULL,
		0x16FF8C59BC982910ULL,
		0xA7DAFE34BC5E98DDULL,
		0x2FAA59DED008F1F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB5E1AD70CE00000ULL,
		0x8B37930522013466ULL,
		0xC6978BD31BA2DFF1ULL,
		0x3BDA011E3E54FB5FULL,
		0x000000000005F54BULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD4382DF789196C89ULL,
		0x0E8C12923046569EULL,
		0xB8A45C61EFA176BDULL,
		0x043EFAEEC3C0EA06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCB64480000000000ULL,
		0x32B4F6A1C16FBC48ULL,
		0x0BB5E87460949182ULL,
		0x075035C522E30F7DULL,
		0x00000021F7D7761EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB09AF451C9E53C61ULL,
		0x6D484E0A9717B866ULL,
		0x90023853547F7553ULL,
		0x0C62C91D5F6E4477ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF29E308000000000ULL,
		0x8BDC33584D7A28E4ULL,
		0x3FBAA9B6A427054BULL,
		0xB7223BC8011C29AAULL,
		0x0000000631648EAFULL
	}};
	shift = 231;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4DBA712E25FCE8BCULL,
		0xA62E2F2E0E9BCF90ULL,
		0x795A5C4EE0F7894DULL,
		0x3BE74F8F767858BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E9C4B897F3A2F00ULL,
		0x8B8BCB83A6F3E413ULL,
		0x569713B83DE25369ULL,
		0xF9D3E3DD9E162F1EULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB442A03FFE9FAA8BULL,
		0x6D6BB03B3F9402B6ULL,
		0x4B86810FF4A384EFULL,
		0x6D1047135469C85FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE9FAA8B00000000ULL,
		0x3F9402B6B442A03FULL,
		0xF4A384EF6D6BB03BULL,
		0x5469C85F4B86810FULL,
		0x000000006D104713ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x97B08EFC3D14FACEULL,
		0x2D1058A48BC16EA8ULL,
		0x588D0AF23111273EULL,
		0x25656DA2724A6B2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x897B08EFC3D14FACULL,
		0xE2D1058A48BC16EAULL,
		0xE588D0AF23111273ULL,
		0x025656DA2724A6B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7396708902308806ULL,
		0x606013A39FB3C007ULL,
		0x14136CBE9A987113ULL,
		0x523368F6F506CF7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7089023088060000ULL,
		0x13A39FB3C0077396ULL,
		0x6CBE9A9871136060ULL,
		0x68F6F506CF7B1413ULL,
		0x0000000000005233ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6582F6D743993DA3ULL,
		0xF58C118F4A5C8D2EULL,
		0xE71D31E488E4BA0DULL,
		0x483CBD26751F5E17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC9ED18000000000ULL,
		0x2E469732C17B6BA1ULL,
		0x725D06FAC608C7A5ULL,
		0x8FAF0BF38E98F244ULL,
		0x000000241E5E933AULL
	}};
	shift = 231;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEE8793D00BBEA480ULL,
		0xC45D959266DDBCFFULL,
		0x9D5702EAD51F1C89ULL,
		0x43EC98B2DEB4BE1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF743C9E805DF5240ULL,
		0xE22ECAC9336EDE7FULL,
		0xCEAB81756A8F8E44ULL,
		0x21F64C596F5A5F0FULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E4961ABD07F3C2BULL,
		0xD5545F91A6121FBDULL,
		0x17CB16AD1D9BD02AULL,
		0x7C18E301824158E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2B0000000000000ULL,
		0xFBD9E4961ABD07F3ULL,
		0x02AD5545F91A6121ULL,
		0x8E017CB16AD1D9BDULL,
		0x0007C18E30182415ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x43DC173134DCEC70ULL,
		0xA99BA4AB41207125ULL,
		0xD095DCAF48532F8BULL,
		0x343B36CD904FF6CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD373B1C000000000ULL,
		0x0481C4950F705CC4ULL,
		0x214CBE2EA66E92ADULL,
		0x413FDB3B425772BDULL,
		0x00000000D0ECDB36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x61EFE2DAE0448D50ULL,
		0xAA17E5C48AD314A9ULL,
		0x772458A226506658ULL,
		0x05394BDD44B57880ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6B8112354000000ULL,
		0x7122B4C52A587BF8ULL,
		0x28899419962A85F9ULL,
		0xF7512D5E201DC916ULL,
		0x0000000000014E52ULL
	}};
	shift = 214;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF3D758E5BB6F5CA1ULL,
		0x44E0B6FC575AEB95ULL,
		0xA040ED60035717B0ULL,
		0x21AAF6A7683D55C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCF5D6396EDBD7284ULL,
		0x1382DBF15D6BAE57ULL,
		0x8103B5800D5C5EC1ULL,
		0x86ABDA9DA0F5571AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC16C8C9479D968EULL,
		0x2F8AD159403F684CULL,
		0xAFA53731B202D415ULL,
		0x16772ACB2D04CA52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B2D1C000000000ULL,
		0x07ED099D82D91928ULL,
		0x405A82A5F15A2B28ULL,
		0xA0994A55F4A6E636ULL,
		0x00000002CEE55965ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAC40A4E1976ABF08ULL,
		0x288453075C56FB24ULL,
		0x029CB50B6DD2F301ULL,
		0x09957FD08CD4BDBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE1976ABF08000000ULL,
		0x075C56FB24AC40A4ULL,
		0x0B6DD2F301288453ULL,
		0xD08CD4BDBA029CB5ULL,
		0x000000000009957FULL
	}};
	shift = 216;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2DDC5F611901C9F4ULL,
		0x8CF708E0D5B39335ULL,
		0x99079A579E922859ULL,
		0x61B79370FDD0F935ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x96EE2FB08C80E4FAULL,
		0xC67B84706AD9C99AULL,
		0xCC83CD2BCF49142CULL,
		0x30DBC9B87EE87C9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9C730BA586BCB87BULL,
		0x87036C42044DD196ULL,
		0x9D25C600924902A1ULL,
		0x6B208924DBE922E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6174B0D7970F600ULL,
		0x06D884089BA32D38ULL,
		0x4B8C01249205430EULL,
		0x411249B7D245CD3AULL,
		0x00000000000000D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD3CE9DFBA523D9FBULL,
		0x46C32B6143E3DA16ULL,
		0x72754321E620B1E4ULL,
		0x1718B53D0E796F9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A77EE948F67EC00ULL,
		0x0CAD850F8F685B4FULL,
		0xD50C879882C7911BULL,
		0x62D4F439E5BE69C9ULL,
		0x000000000000005CULL
	}};
	shift = 202;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7F28A638C6D4173FULL,
		0x6FA89B1682DEB233ULL,
		0xD57D850CCCF6E78FULL,
		0x72FF5A19A43AFB14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5CFC000000000000ULL,
		0xC8CDFCA298E31B50ULL,
		0x9E3DBEA26C5A0B7AULL,
		0xEC5355F6143333DBULL,
		0x0001CBFD686690EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x23E48A218D82CDA6ULL,
		0xF4A7CC2E6A2E458FULL,
		0x70424C840F37C5D6ULL,
		0x32CED73531A8BF0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC914431B059B4C00ULL,
		0x4F985CD45C8B1E47ULL,
		0x8499081E6F8BADE9ULL,
		0x9DAE6A63517E1CE0ULL,
		0x0000000000000065ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x194468DB8B171B7BULL,
		0xBA038E7E1F95E999ULL,
		0xB75309314741DAF4ULL,
		0x69927B85881B7DA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDBD8000000000000ULL,
		0x4CC8CA2346DC58B8ULL,
		0xD7A5D01C73F0FCAFULL,
		0xED0DBA98498A3A0EULL,
		0x00034C93DC2C40DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x66C5226048DA842AULL,
		0xEA1B8CDE71B76E41ULL,
		0x61F4C31019B4FE98ULL,
		0x2DDD680C0C6B1E0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81236A10A8000000ULL,
		0x79C6DDB9059B1489ULL,
		0x4066D3FA63A86E33ULL,
		0x3031AC783187D30CULL,
		0x0000000000B775A0ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB7AC80C4DCB47E5ULL,
		0x067ACCC73B70A8D2ULL,
		0x2CB7ECC19B32FFA0ULL,
		0x5F8C75F3BAB8592CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x968FCA0000000000ULL,
		0xE151A556F590189BULL,
		0x65FF400CF5998E76ULL,
		0x70B258596FD98336ULL,
		0x000000BF18EBE775ULL
	}};
	shift = 233;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7B6EC298850A35DDULL,
		0x7FEF65EAC5692DDBULL,
		0xBF953961F9FFA820ULL,
		0x70A65B4CEC5EC8AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A35DD0000000000ULL,
		0x692DDB7B6EC29885ULL,
		0xFFA8207FEF65EAC5ULL,
		0x5EC8AEBF953961F9ULL,
		0x00000070A65B4CECULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6EB2C35B8CFF38C8ULL,
		0xDF2C3AC7E1970490ULL,
		0xCD30A47E6D3536D2ULL,
		0x2601D9D195D55F23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C35B8CFF38C800ULL,
		0x2C3AC7E19704906EULL,
		0x30A47E6D3536D2DFULL,
		0x01D9D195D55F23CDULL,
		0x0000000000000026ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B794A13A0018077ULL,
		0x27DBA04FF58C769EULL,
		0xA238ED3C98EB6820ULL,
		0x75650F81223FA6AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB800000000000000ULL,
		0xF45BCA509D000C03ULL,
		0x013EDD027FAC63B4ULL,
		0x7D11C769E4C75B41ULL,
		0x03AB287C0911FD35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F6E20762A521EC2ULL,
		0x0C1C59708A18AC7FULL,
		0xE6E2960CA61EF778ULL,
		0x3D6460C7F41606F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB15290F610000000ULL,
		0x8450C563F9FB7103ULL,
		0x6530F7BBC060E2CBULL,
		0x3FA0B037AF3714B0ULL,
		0x0000000001EB2306ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x292B3B8C539C85BDULL,
		0x3F9686EE3E61A590ULL,
		0x1596FCF97B274984ULL,
		0x461875DC2D313998ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7216F40000000000ULL,
		0x869640A4ACEE314EULL,
		0x9D2610FE5A1BB8F9ULL,
		0xC4E660565BF3E5ECULL,
		0x0000011861D770B4ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE6EF3FBAEDE8F1FAULL,
		0xEB034EE6A6BA4731ULL,
		0x6E7E9B34556B72C8ULL,
		0x2D430179A7512A62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDDE7F75DBD1E3F40ULL,
		0x6069DCD4D748E63CULL,
		0xCFD3668AAD6E591DULL,
		0xA8602F34EA254C4DULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x92AC8278C4B6012EULL,
		0x0443545F7AC78D18ULL,
		0x3924914DA0605C06ULL,
		0x391D0472294360ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B80000000000000ULL,
		0x4624AB209E312D80ULL,
		0x018110D517DEB1E3ULL,
		0x2B4E492453681817ULL,
		0x000E47411C8A50D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x64BDEE20A36C564BULL,
		0x5BABDA27B01703A4ULL,
		0xE022E97027E2D036ULL,
		0x0D601A1F71B822C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC4146D8AC960000ULL,
		0xB44F602E0748C97BULL,
		0xD2E04FC5A06CB757ULL,
		0x343EE3704591C045ULL,
		0x0000000000001AC0ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAD31784A676F4A60ULL,
		0x10483B020643312DULL,
		0x800CFCDB2DAAA560ULL,
		0x4EEC89985687E21AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDE94C0000000000ULL,
		0xC86625B5A62F094CULL,
		0xB554AC0209076040ULL,
		0xD0FC4350019F9B65ULL,
		0x00000009DD91330AULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8D70E2AF12B407E8ULL,
		0xFA1530D0275C699BULL,
		0xF644CCC9A537E4B7ULL,
		0x5B95C5EE0BBCCD62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC4AD01FA0000000ULL,
		0x409D71A66E35C38AULL,
		0x2694DF92DFE854C3ULL,
		0xB82EF3358BD91333ULL,
		0x00000000016E5717ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x88097EC8DCC058D9ULL,
		0x63E3BE0982C183E8ULL,
		0x6DD9CDB943B0179FULL,
		0x640C15D51EEFB97AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B1B200000000000ULL,
		0x307D11012FD91B98ULL,
		0x02F3EC7C77C13058ULL,
		0xF72F4DBB39B72876ULL,
		0x00000C8182BAA3DDULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x81725248A0C45465ULL,
		0x7C40CC4273EFE719ULL,
		0x021D70AEF1145A62ULL,
		0x18BB3BF848DAD20EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCA00000000000000ULL,
		0x3302E4A4914188A8ULL,
		0xC4F8819884E7DFCEULL,
		0x1C043AE15DE228B4ULL,
		0x00317677F091B5A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8F425DAAD5961795ULL,
		0xBA222E83B1B101D3ULL,
		0xE3E8026FC65A1FA9ULL,
		0x17DF8E721E6498DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED56ACB0BCA80000ULL,
		0x741D8D880E9C7A12ULL,
		0x137E32D0FD4DD111ULL,
		0x7390F324C6FF1F40ULL,
		0x000000000000BEFCULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB4D3F4A77E8A127FULL,
		0xBA48EFE0FECFDF24ULL,
		0xF1C8DF072370894EULL,
		0x1C8FF9AF07A9F501ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BF45093F8000000ULL,
		0x07F67EF925A69FA5ULL,
		0x391B844A75D2477FULL,
		0x783D4FA80F8E46F8ULL,
		0x0000000000E47FCDULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2D85BAFC8FA21597ULL,
		0x793317EEDB9494D5ULL,
		0x9025BD8180DC97A1ULL,
		0x41DBE4C41AF1D20FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x75F91F442B2E0000ULL,
		0x2FDDB72929AA5B0BULL,
		0x7B0301B92F42F266ULL,
		0xC98835E3A41F204BULL,
		0x00000000000083B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0842EB7C7BC515E6ULL,
		0x4F8015564F421FA4ULL,
		0xEB52760FA4CCA612ULL,
		0x7C09E13E0560BB30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D6F8F78A2BCC000ULL,
		0x02AAC9E843F48108ULL,
		0x4EC1F49994C249F0ULL,
		0x3C27C0AC17661D6AULL,
		0x0000000000000F81ULL
	}};
	shift = 205;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E86C7EEE7E2C958ULL,
		0x702F371532A4FEB5ULL,
		0x9FFD4059768A7318ULL,
		0x00616A3A481009F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB9F8B2560000000ULL,
		0x54CA93FAD43A1B1FULL,
		0x65DA29CC61C0BCDCULL,
		0xE9204027D67FF501ULL,
		0x00000000000185A8ULL
	}};
	shift = 218;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x687B62A7BDB4DCFFULL,
		0x99D62EDF70E2FBDDULL,
		0x7ED22D7926E98036ULL,
		0x138C0F68EA9460CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373FC00000000000ULL,
		0xBEF75A1ED8A9EF6DULL,
		0x600DA6758BB7DC38ULL,
		0x18335FB48B5E49BAULL,
		0x000004E303DA3AA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x812143064690D3FDULL,
		0xA54AEB5781A6EE41ULL,
		0x075A122DDC2D4609ULL,
		0x2BDFA70AE0FA700FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C8D21A7FA000000ULL,
		0xAF034DDC83024286ULL,
		0x5BB85A8C134A95D6ULL,
		0x15C1F4E01E0EB424ULL,
		0x000000000057BF4EULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB10CB7C99BE26EB0ULL,
		0x5D296CC3D2AA2C4EULL,
		0x9D2FA7968B799771ULL,
		0x1E62039A3D49FB95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAC00000000000000ULL,
		0x13AC432DF266F89BULL,
		0xDC574A5B30F4AA8BULL,
		0xE5674BE9E5A2DE65ULL,
		0x00079880E68F527EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCB53F550E1B52351ULL,
		0x1B484C26E8304034ULL,
		0x2FAF5DFBBCA3DC32ULL,
		0x52B576C48745066EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x65A9FAA870DA91A8ULL,
		0x0DA426137418201AULL,
		0x17D7AEFDDE51EE19ULL,
		0x295ABB6243A28337ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9A28931B05245A72ULL,
		0x4E05115195C193D2ULL,
		0xCAFA52A9625AF662ULL,
		0x6079532D47F6E0ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x149169C800000000ULL,
		0x57064F4A68A24C6CULL,
		0x896BD98938144546ULL,
		0x1FDB82B72BE94AA5ULL,
		0x0000000181E54CB5ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE30653680AC363C8ULL,
		0x3C397A7CECA8DD66ULL,
		0xCC98C0F000E751B4ULL,
		0x57CD13D16E5CCC44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF200000000000000ULL,
		0x59B8C194DA02B0D8ULL,
		0x6D0F0E5E9F3B2A37ULL,
		0x113326303C0039D4ULL,
		0x0015F344F45B9733ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0004000000000000ULL,
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
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000200000000ULL,
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
		0x0000000002000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000200000000000ULL,
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
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000010ULL,
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
		0x0001000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000400000000ULL,
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
		0x0000000000040000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000004000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8000000000000000ULL,
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
		0x0000000080000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000010000000ULL,
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
		0x0000000000010000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0001000000000000ULL,
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
		0x0000000100000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0000000008000000ULL,
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
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}