#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x79CC0314648A8162ULL,
		0x4C1B91FBE909D46BULL,
		0x105036079439FBE4ULL,
		0x7898EC60513EB7F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x1922A05880000000ULL,
		0xFA42751ADE7300C5ULL,
		0xE50E7EF91306E47EULL,
		0x144FADFC04140D81ULL,
		0x000000001E263B18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int shift = 30;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3B0F7EB9CC5173D2ULL,
		0xB3293650806F6407ULL,
		0x2BEC2EFC64AE39C5ULL,
		0x5AB1A3C89791759DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9E9000000000000ULL,
		0xB2039D87BF5CE628ULL,
		0x1CE2D9949B284037ULL,
		0xBACE95F6177E3257ULL,
		0x00002D58D1E44BC8ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4E5A7AC9E4964210ULL,
		0x15926E0C84364C1DULL,
		0x579D25F827480CA7ULL,
		0x718C0047C2B35C1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C92C84200000000ULL,
		0x9086C983A9CB4F59ULL,
		0x04E90194E2B24DC1ULL,
		0xF8566B834AF3A4BFULL,
		0x000000000E318008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9B734BA6ACE4B92EULL,
		0x443B987CCF25A21BULL,
		0x3331DFE38F797FCCULL,
		0x7FE18D1EF44A377AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B8000000000000ULL,
		0x886E6DCD2E9AB392ULL,
		0xFF3110EE61F33C96ULL,
		0xDDE8CCC77F8E3DE5ULL,
		0x0001FF86347BD128ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3EBF9BE2960F9821ULL,
		0x8CE96F081CE44BB1ULL,
		0x216A328BEEC04C39ULL,
		0x5059C14F3717E7B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CC1080000000000ULL,
		0x225D89F5FCDF14B0ULL,
		0x0261CC674B7840E7ULL,
		0xBF3D910B51945F76ULL,
		0x00000282CE0A79B8ULL
	}};
	shift = 235;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC8F7197674DB9C79ULL,
		0x7BD0CB2910ADF35CULL,
		0x70F5A4A26FF992BBULL,
		0x0886D6C876B777A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ECE9B738F200000ULL,
		0x652215BE6B991EE3ULL,
		0x944DFF32576F7A19ULL,
		0xD90ED6EEF46E1EB4ULL,
		0x00000000000110DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1CFA1811DC74F32FULL,
		0x8DDF99AACC174216ULL,
		0xA7C87BCDDAC416CCULL,
		0x653158B0F09AF48EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCBC0000000000000ULL,
		0x85873E8604771D3CULL,
		0xB32377E66AB305D0ULL,
		0x23A9F21EF376B105ULL,
		0x00194C562C3C26BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x625A3A9D28D42958ULL,
		0x08068CF31E0288AFULL,
		0x57F59858D6CBD268ULL,
		0x4AC6F317F16D7D8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB12D1D4E946A14ACULL,
		0x040346798F014457ULL,
		0xABFACC2C6B65E934ULL,
		0x2563798BF8B6BEC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x13FDF7A24B9456A1ULL,
		0x726B05B8532168B8ULL,
		0x3483C05F016BE5DEULL,
		0x4077A647C9FB9DC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA2B5080000000000ULL,
		0x0B45C09FEFBD125CULL,
		0x5F2EF393582DC299ULL,
		0xDCEE39A41E02F80BULL,
		0x00000203BD323E4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7A8409059603A455ULL,
		0x32E81B1821D08710ULL,
		0xA9685D7DC9897B0CULL,
		0x3565B2AEBE0E32CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8409059603A45500ULL,
		0xE81B1821D087107AULL,
		0x685D7DC9897B0C32ULL,
		0x65B2AEBE0E32CEA9ULL,
		0x0000000000000035ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0F8269EB0FBEA111ULL,
		0x91DBC888820D8DE5ULL,
		0x81B3B9FA05F5CEB3ULL,
		0x237E3B9DF3671E8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8269EB0FBEA11100ULL,
		0xDBC888820D8DE50FULL,
		0xB3B9FA05F5CEB391ULL,
		0x7E3B9DF3671E8B81ULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB66598DB4D73EE60ULL,
		0xE4A9D7F4C6604FBEULL,
		0x541C875274A32018ULL,
		0x6A4F4B09EBB8DAD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0xBEB66598DB4D73EEULL,
		0x18E4A9D7F4C6604FULL,
		0xD4541C875274A320ULL,
		0x006A4F4B09EBB8DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4033ED99E8223CA4ULL,
		0xA6F5B7440FB1A0C6ULL,
		0xD33D4ECF2B48AAB9ULL,
		0x77606D14697A0DBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D04479480000000ULL,
		0x81F63418C8067DB3ULL,
		0xE569155734DEB6E8ULL,
		0x8D2F41B79A67A9D9ULL,
		0x000000000EEC0DA2ULL
	}};
	shift = 221;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB0194E947F4DD002ULL,
		0x279EDA1E3F0C596DULL,
		0xC301A7236297534DULL,
		0x3080F26F068CC5A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x94E947F4DD002000ULL,
		0xEDA1E3F0C596DB01ULL,
		0x1A7236297534D279ULL,
		0x0F26F068CC5A1C30ULL,
		0x0000000000000308ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF268E72794755133ULL,
		0x622BB4E593C1BCD0ULL,
		0xCF9A176737DDBE7EULL,
		0x59E85A59CCC9DBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51D544CC0000000ULL,
		0x64F06F343C9A39C9ULL,
		0xCDF76F9F988AED39ULL,
		0x733276F6F3E685D9ULL,
		0x00000000167A1696ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD3C908815460DB22ULL,
		0xA8BD867A0B720BD7ULL,
		0x89E4EC7D996100D4ULL,
		0x3EE6BEA63446691DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD910000000000000ULL,
		0x5EBE9E48440AA306ULL,
		0x06A545EC33D05B90ULL,
		0x48EC4F2763ECCB08ULL,
		0x0001F735F531A233ULL
	}};
	shift = 243;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x116E42768AE5AC79ULL,
		0xB8D312105649F621ULL,
		0x95EACC29D232DAF3ULL,
		0x65CFD00143002A25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09DA2B96B1E40000ULL,
		0x48415927D88445B9ULL,
		0x30A748CB6BCEE34CULL,
		0x40050C00A89657ABULL,
		0x000000000001973FULL
	}};
	shift = 210;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x57EAD03B4B863C67ULL,
		0x9A524403F0363E2AULL,
		0x7EE7B711591ECF7FULL,
		0x5DFCDFA2A00204DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB4B863C670000000ULL,
		0x3F0363E2A57EAD03ULL,
		0x1591ECF7F9A52440ULL,
		0x2A00204DA7EE7B71ULL,
		0x0000000005DFCDFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x39804298405DCAB0ULL,
		0x83A50BE29073BD3BULL,
		0xD16E9D362B8F55C7ULL,
		0x36BB49BBC9306B16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x298405DCAB000000ULL,
		0xBE29073BD3B39804ULL,
		0xD362B8F55C783A50ULL,
		0x9BBC9306B16D16E9ULL,
		0x0000000000036BB4ULL
	}};
	shift = 212;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x621038057576F5ECULL,
		0x1C4E218B07251941ULL,
		0xAA851C80D04EAC09ULL,
		0x7EBCEC4886838770ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81C02BABB7AF6000ULL,
		0x710C583928CA0B10ULL,
		0x28E40682756048E2ULL,
		0xE76244341C3B8554ULL,
		0x00000000000003F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x059A4B7F4CBA8DA1ULL,
		0xB445EEED11216C58ULL,
		0x6BD5429DC3BF664AULL,
		0x78BCA9DC032B976DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x92DFD32EA3684000ULL,
		0x7BBB44485B160166ULL,
		0x50A770EFD992AD11ULL,
		0x2A7700CAE5DB5AF5ULL,
		0x0000000000001E2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA087854F8CAD9424ULL,
		0xD919616202600E35ULL,
		0xF370B545AD1F5719ULL,
		0x1004E7A0A4170027ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6509000000000000ULL,
		0x038D6821E153E32BULL,
		0xD5C6764658588098ULL,
		0xC009FCDC2D516B47ULL,
		0x0000040139E82905ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4AA2B434C54CDEF6ULL,
		0x8BFF162DE987444AULL,
		0x84CF1AF88C6B842EULL,
		0x09897978FCDC3DC0ULL,
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
		0x4AA2B434C54CDEF6ULL,
		0x8BFF162DE987444AULL,
		0x84CF1AF88C6B842EULL,
		0x09897978FCDC3DC0ULL
	}};
	shift = 256;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x48F0A9AFFE06255AULL,
		0x05BD4420C13A0F2CULL,
		0xE2445444DC25E382ULL,
		0x49C3CAEEC17C13A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x247854D7FF0312ADULL,
		0x02DEA210609D0796ULL,
		0xF1222A226E12F1C1ULL,
		0x24E1E57760BE09D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE150F24DC307968CULL,
		0x60E8AA5812714720ULL,
		0x9D0B30E7FAEB93E0ULL,
		0x260FFCD63BB687E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E49B860F2D18000ULL,
		0x154B024E28E41C2AULL,
		0x661CFF5D727C0C1DULL,
		0xFF9AC776D0FC13A1ULL,
		0x00000000000004C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE157CE72EBC7DF8AULL,
		0xCBE77D521A5C058EULL,
		0x518DC430190B3F07ULL,
		0x785CE577DDE1227CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5D78FBF14000000ULL,
		0xA434B80B1DC2AF9CULL,
		0x6032167E0F97CEFAULL,
		0xEFBBC244F8A31B88ULL,
		0x0000000000F0B9CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF81841422BCFE533ULL,
		0xEBEF64FE7D89E46CULL,
		0x93103F1417DB3BEEULL,
		0x509AB9428839B1ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84579FCA66000000ULL,
		0xFCFB13C8D9F03082ULL,
		0x282FB677DDD7DEC9ULL,
		0x851073635926207EULL,
		0x0000000000A13572ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFE0BAECB096A4E4DULL,
		0x8B41BDED2E8462EDULL,
		0x534FF0A3B7139B06ULL,
		0x13AEECA3EE358927ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECB096A4E4D00000ULL,
		0xDED2E8462EDFE0BAULL,
		0x0A3B7139B068B41BULL,
		0xCA3EE358927534FFULL,
		0x0000000000013AEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBBD18619CC6C57B4ULL,
		0xA9FB2E901E8C5AD3ULL,
		0xAE80E8835934E9A8ULL,
		0x0AFEBCAEA56B913AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE6362BDA00000000ULL,
		0x0F462D69DDE8C30CULL,
		0xAC9A74D454FD9748ULL,
		0x52B5C89D57407441ULL,
		0x00000000057F5E57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB02E31A6961EC75EULL,
		0x049AACBC90D3A82FULL,
		0x64EBBF719056A89BULL,
		0x31988F6CDCC3354AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xEC0B8C69A587B1D7ULL,
		0xC126AB2F2434EA0BULL,
		0x993AEFDC6415AA26ULL,
		0x0C6623DB3730CD52ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB4CCF79F330697C4ULL,
		0x4854EF4FEB8C2F0AULL,
		0xD2591368CE6D4F35ULL,
		0x2F958940771E0376ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE20000000000000ULL,
		0x7855A667BCF99834ULL,
		0x79AA42A77A7F5C61ULL,
		0x1BB692C89B46736AULL,
		0x00017CAC4A03B8F0ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0FC011A05297AF15ULL,
		0xE203628B8CC5D6D4ULL,
		0x15839A009FB6EA50ULL,
		0x4C21C96D37D5E798ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5EBC540000000000ULL,
		0x175B503F0046814AULL,
		0xDBA943880D8A2E33ULL,
		0x579E60560E68027EULL,
		0x000001308725B4DFULL
	}};
	shift = 234;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD6652A23C7D700EDULL,
		0xA22ED9401C28F239ULL,
		0x5D337EA05D1CB539ULL,
		0x648970B42BC13D10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x3ACCA54478FAE01DULL,
		0x3445DB2803851E47ULL,
		0x0BA66FD40BA396A7ULL,
		0x0C912E16857827A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x971F140C140BCE83ULL,
		0xB02DB8E1CFDB070AULL,
		0xF182DAF9E13B69E4ULL,
		0x45864DD49AE35865ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1F140C140BCE8300ULL,
		0x2DB8E1CFDB070A97ULL,
		0x82DAF9E13B69E4B0ULL,
		0x864DD49AE35865F1ULL,
		0x0000000000000045ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x71F461A7F26E8C5BULL,
		0xF0D8D1823A327764ULL,
		0x951F56F9EE89775CULL,
		0x1110E803694BACE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE8C5B00000000000ULL,
		0x2776471F461A7F26ULL,
		0x9775CF0D8D1823A3ULL,
		0xBACE5951F56F9EE8ULL,
		0x000001110E803694ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2694F928374A7BFEULL,
		0x7747A3B2BF6E924CULL,
		0xEBE31CDD85943470ULL,
		0x496CAFC04494EA09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x506E94F7FC000000ULL,
		0x657EDD24984D29F2ULL,
		0xBB0B2868E0EE8F47ULL,
		0x808929D413D7C639ULL,
		0x000000000092D95FULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFC1EC629ACA749FDULL,
		0x7BECD6ECAE258DCEULL,
		0xC916B63136CFE078ULL,
		0x58AD505863E1E73AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE80000000000000ULL,
		0xE77E0F6314D653A4ULL,
		0x3C3DF66B765712C6ULL,
		0x9D648B5B189B67F0ULL,
		0x002C56A82C31F0F3ULL
	}};
	shift = 247;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E0AF94C98D6F876ULL,
		0x80534F8158718603ULL,
		0xA9871B05D13B54C6ULL,
		0x7D068EC4381754E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF876000000000000ULL,
		0x86035E0AF94C98D6ULL,
		0x54C680534F815871ULL,
		0x54E1A9871B05D13BULL,
		0x00007D068EC43817ULL
	}};
	shift = 240;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x81BD49DB65E3AC1BULL,
		0x2E3F077D61ED5BF2ULL,
		0xD22E5DAA5A9ADB99ULL,
		0x643A00C9E2E18A40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x49DB65E3AC1B0000ULL,
		0x077D61ED5BF281BDULL,
		0x5DAA5A9ADB992E3FULL,
		0x00C9E2E18A40D22EULL,
		0x000000000000643AULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCFB6DB04C1B1BBB3ULL,
		0x1CBBACCB1AB69C07ULL,
		0x8F6E47CDE604F2DBULL,
		0x0FA79198521775B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCFB6DB04C1B1BBB3ULL,
		0x1CBBACCB1AB69C07ULL,
		0x8F6E47CDE604F2DBULL,
		0x0FA79198521775B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAA858896A290066CULL,
		0xDD9F8878C2DFFE28ULL,
		0x99946344DC31970BULL,
		0x1D5FC909F9FB7259ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x550B112D45200CD8ULL,
		0xBB3F10F185BFFC51ULL,
		0x3328C689B8632E17ULL,
		0x3ABF9213F3F6E4B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x75208766429B6C94ULL,
		0x4FFCB0D184DF8178ULL,
		0xC033E800D19BCD2AULL,
		0x6CE4265B0634E248ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A00000000000000ULL,
		0xBC3A9043B3214DB6ULL,
		0x9527FE5868C26FC0ULL,
		0x246019F40068CDE6ULL,
		0x003672132D831A71ULL
	}};
	shift = 247;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFABFA41E84FA2A5AULL,
		0x20CB0EC5B05E8610ULL,
		0xC0DE79D0781CE851ULL,
		0x67794002C03F86E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF483D09F454B4000ULL,
		0x61D8B60BD0C21F57ULL,
		0xCF3A0F039D0A2419ULL,
		0x28005807F0DCB81BULL,
		0x0000000000000CEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDB4CA7F842D8D6A3ULL,
		0xF5F4E58996547305ULL,
		0xC068A1F114A90DA6ULL,
		0x15C458A97DF574F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D6A30000000000ULL,
		0x547305DB4CA7F842ULL,
		0xA90DA6F5F4E58996ULL,
		0xF574F8C068A1F114ULL,
		0x00000015C458A97DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4BE9FC7978EBB929ULL,
		0x6F0BEAE542E5EDE0ULL,
		0xB994B2F6D86E353FULL,
		0x706472D5407B852BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CBC75DC94800000ULL,
		0x72A172F6F025F4FEULL,
		0x7B6C371A9FB785F5ULL,
		0x6AA03DC295DCCA59ULL,
		0x0000000000383239ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x98D2B485C726A423ULL,
		0x39FF1EE1B9DCC841ULL,
		0x7AD91D66C8837004ULL,
		0x383ADE85F525B2ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x908C000000000000ULL,
		0x2106634AD2171C9AULL,
		0xC010E7FC7B86E773ULL,
		0xCBB1EB64759B220DULL,
		0x0000E0EB7A17D496ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA21296FBECF14C2CULL,
		0x1449AC7B1EF290E8ULL,
		0x87CFCE91D3092794ULL,
		0x1E1B693DBDD24588ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C00000000000000ULL,
		0xE8A21296FBECF14CULL,
		0x941449AC7B1EF290ULL,
		0x8887CFCE91D30927ULL,
		0x001E1B693DBDD245ULL
	}};
	shift = 248;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFA9AE65FEDC0168AULL,
		0xAEB1B0F4CD8831DFULL,
		0x3964F9041E7A15D2ULL,
		0x5994D858294EBA7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A0000000000000ULL,
		0x1DFFA9AE65FEDC01ULL,
		0x5D2AEB1B0F4CD883ULL,
		0xA7B3964F9041E7A1ULL,
		0x0005994D858294EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE037E6ED3AA18FC0ULL,
		0xD47E050584A573F5ULL,
		0x64DB533C402F2F21ULL,
		0x494E8BF3CB1969D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF01BF3769D50C7E0ULL,
		0xEA3F0282C252B9FAULL,
		0xB26DA99E20179790ULL,
		0x24A745F9E58CB4EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEA493EF1B22C1597ULL,
		0x6F6DF1B00E9771C0ULL,
		0xE6336728F9790099ULL,
		0x6D71767CC5211F23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x924FBC6C8B0565C0ULL,
		0xDB7C6C03A5DC703AULL,
		0x8CD9CA3E5E40265BULL,
		0x5C5D9F314847C8F9ULL,
		0x000000000000001BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEBE4C14FE153FEC1ULL,
		0x9D259ED610A350F5ULL,
		0x9088B4F0544DF74FULL,
		0x7A36720499623F0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A7FD82000000000ULL,
		0x146A1EBD7C9829FCULL,
		0x89BEE9F3A4B3DAC2ULL,
		0x2C47E1D211169E0AULL,
		0x0000000F46CE4093ULL
	}};
	shift = 229;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1FD34B30E9F7595FULL,
		0x329F6EEC5F979034ULL,
		0xB1CC7637AC4339F6ULL,
		0x11B470F04A529F71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB30E9F7595F00000ULL,
		0xEEC5F9790341FD34ULL,
		0x637AC4339F6329F6ULL,
		0x0F04A529F71B1CC7ULL,
		0x0000000000011B47ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF2EFDD7F8D788BEBULL,
		0xF47639FF1A060871ULL,
		0xA644DCED227BDBD2ULL,
		0x5B021D60954E9427ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFDD7F8D788BEB000ULL,
		0x639FF1A060871F2EULL,
		0x4DCED227BDBD2F47ULL,
		0x21D60954E9427A64ULL,
		0x00000000000005B0ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x250F9DF9B5072B02ULL,
		0x4CAF99773D129310ULL,
		0xA7FD0622358AD840ULL,
		0x123EB5268D629856ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF9B5072B0200000ULL,
		0x9773D129310250F9ULL,
		0x622358AD8404CAF9ULL,
		0x5268D629856A7FD0ULL,
		0x00000000000123EBULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3838C05F7E316146ULL,
		0xC641BA4518B97ED7ULL,
		0x2F2040213D0FA753ULL,
		0x4E2CC473C7CF6555ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE316146000000000ULL,
		0x8B97ED73838C05F7ULL,
		0xD0FA753C641BA451ULL,
		0x7CF65552F2040213ULL,
		0x00000004E2CC473CULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x38DA51BEC57578B6ULL,
		0x60AA498C5AA393C0ULL,
		0xDD2A9B058596DE3FULL,
		0x1870B93BE6F5CC3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DF62BABC5B0000ULL,
		0x24C62D51C9E01C6DULL,
		0x4D82C2CB6F1FB055ULL,
		0x5C9DF37AE61EEE95ULL,
		0x0000000000000C38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCE6E4C150296A207ULL,
		0x6EECEAE6B8F6EDE7ULL,
		0x17F5F6569344BA05ULL,
		0x0FE846217128A6E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50296A2070000000ULL,
		0x6B8F6EDE7CE6E4C1ULL,
		0x69344BA056EECEAEULL,
		0x17128A6E717F5F65ULL,
		0x0000000000FE8462ULL
	}};
	shift = 220;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9CABEE9523E1CC2DULL,
		0xBE699F2CE394F61EULL,
		0xD6D5DDBE9979203AULL,
		0x5772F9E99BF42C68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB400000000000000ULL,
		0x7A72AFBA548F8730ULL,
		0xEAF9A67CB38E53D8ULL,
		0xA35B5776FA65E480ULL,
		0x015DCBE7A66FD0B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8E9E594DFA9D4DFEULL,
		0x6C78733D9C8C81F0ULL,
		0xA2FE9BD21C6C40F2ULL,
		0x0951B3D310113E2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94DFA9D4DFE00000ULL,
		0x33D9C8C81F08E9E5ULL,
		0xBD21C6C40F26C787ULL,
		0x3D310113E2CA2FE9ULL,
		0x000000000000951BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA275FD314FBC683EULL,
		0x783CBEF901EFBE4CULL,
		0x1A7AA081EF33E3D1ULL,
		0x1636A1BB77D08FCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78D07C0000000000ULL,
		0xDF7C9944EBFA629FULL,
		0x67C7A2F0797DF203ULL,
		0xA11F9C34F54103DEULL,
		0x0000002C6D4376EFULL
	}};
	shift = 233;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x88B32E40131A6B43ULL,
		0x06E1257D03427B33ULL,
		0xA53442D5784562A9ULL,
		0x4759AF3206D7F894ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x131A6B4300000000ULL,
		0x03427B3388B32E40ULL,
		0x784562A906E1257DULL,
		0x06D7F894A53442D5ULL,
		0x000000004759AF32ULL
	}};
	shift = 224;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x08EFD5681B1A08A7ULL,
		0x91AC590EFA35DC2AULL,
		0x4110BEB5CE4C97B3ULL,
		0x2015FBC1274AF922ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C68229C0000000ULL,
		0xBE8D770A823BF55AULL,
		0x739325ECE46B1643ULL,
		0x49D2BE4890442FADULL,
		0x0000000008057EF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2F501527478A6B65ULL,
		0xB24DAD054AAC52FEULL,
		0xA0E5354C00B11B9FULL,
		0x135DACCA995F6224ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B6500000000000ULL,
		0xC52FE2F501527478ULL,
		0x11B9FB24DAD054AAULL,
		0xF6224A0E5354C00BULL,
		0x00000135DACCA995ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD7ABC410C9C584A4ULL,
		0x6CE5773BACA872B7ULL,
		0xE6AF769DAC5D5F08ULL,
		0x292787CCF855CD00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5200000000000000ULL,
		0x5BEBD5E20864E2C2ULL,
		0x843672BB9DD65439ULL,
		0x807357BB4ED62EAFULL,
		0x001493C3E67C2AE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCEECC335DD02A09FULL,
		0xBE1E6E78814B7137ULL,
		0xC0AA2FD43166A9C9ULL,
		0x6A4701C7BBA63A09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB30CD7740A827C00ULL,
		0x79B9E2052DC4DF3BULL,
		0xA8BF50C59AA726F8ULL,
		0x1C071EEE98E82702ULL,
		0x00000000000001A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x88040D9A7F3C211DULL,
		0x5147205E6C8B9C02ULL,
		0xBD38A760EBA627B8ULL,
		0x033D1BDA6DDC87DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4740000000000000ULL,
		0x00A20103669FCF08ULL,
		0xEE1451C8179B22E7ULL,
		0xF76F4E29D83AE989ULL,
		0x0000CF46F69B7721ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x51717D52C231F4C6ULL,
		0xBD71BC5492E7E09CULL,
		0x2D1A643DE6D01824ULL,
		0x77C51643C8E6B071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54B08C7D31800000ULL,
		0x1524B9F827145C5FULL,
		0x0F79B406092F5C6FULL,
		0x90F239AC1C4B4699ULL,
		0x00000000001DF145ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF9760847AF0A6596ULL,
		0x4267D034961DE5ACULL,
		0xD3F4316F15924F98ULL,
		0x2852EE182D0F2FA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9600000000000000ULL,
		0xACF9760847AF0A65ULL,
		0x984267D034961DE5ULL,
		0xA3D3F4316F15924FULL,
		0x002852EE182D0F2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x88168F1809A1EAD5ULL,
		0xFF11562862369E00ULL,
		0xEEF4725BB60B9814ULL,
		0x66965E8CA965EC2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF1809A1EAD500000ULL,
		0x62862369E0088168ULL,
		0x25BB60B9814FF115ULL,
		0xE8CA965EC2EEEF47ULL,
		0x0000000000066965ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x32F23A5165596AABULL,
		0x44EE6C24A1C52343ULL,
		0x91A0626BF31A0D21ULL,
		0x7AC9D7E1CA2F6B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAB000000000000ULL,
		0x234332F23A516559ULL,
		0x0D2144EE6C24A1C5ULL,
		0x6B1191A0626BF31AULL,
		0x00007AC9D7E1CA2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2826720F5834E850ULL,
		0x0CB2DEB18A569391ULL,
		0x121D1292866EECA7ULL,
		0x31E08F485F045640ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5834E8500000000ULL,
		0x18A5693912826720ULL,
		0x2866EECA70CB2DEBULL,
		0x85F045640121D129ULL,
		0x00000000031E08F4ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCE407B29E6E34CFEULL,
		0xD6633411074A4CACULL,
		0x1EB6B36837F7E18AULL,
		0x4BDF7E539E89A554ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07B29E6E34CFE000ULL,
		0x33411074A4CACCE4ULL,
		0x6B36837F7E18AD66ULL,
		0xF7E539E89A5541EBULL,
		0x00000000000004BDULL
	}};
	shift = 204;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x20DE41B58BD6C88FULL,
		0x091D7ACB54B58A0AULL,
		0xD51ECE758514A9C3ULL,
		0x75E09A7AA52FE83CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x106F20DAC5EB6447ULL,
		0x848EBD65AA5AC505ULL,
		0x6A8F673AC28A54E1ULL,
		0x3AF04D3D5297F41EULL
	}};
	shift = 255;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFB6A0FF2EF8CC860ULL,
		0x4078FA6ACE91B8E5ULL,
		0xD007870AEE61BE8DULL,
		0x14CE3EF4740A2365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC86000000000000ULL,
		0x1B8E5FB6A0FF2EF8ULL,
		0x1BE8D4078FA6ACE9ULL,
		0xA2365D007870AEE6ULL,
		0x0000014CE3EF4740ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7127A6BE9EE0FBB4ULL,
		0xD20089EE039045DEULL,
		0x8818C7D962BB4324ULL,
		0x1F035C9290571386ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA7B83EED00000000ULL,
		0x80E411779C49E9AFULL,
		0x58AED0C93480227BULL,
		0xA415C4E1A20631F6ULL,
		0x0000000007C0D724ULL
	}};
	shift = 222;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDA8DF4AFBD2F6E3FULL,
		0x0E0BF1153C3064A9ULL,
		0x29F60C63E41F2A4EULL,
		0x633CF16C67215EE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE3F0000000000000ULL,
		0x4A9DA8DF4AFBD2F6ULL,
		0xA4E0E0BF1153C306ULL,
		0xEE029F60C63E41F2ULL,
		0x000633CF16C67215ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD9263E54A7359AABULL,
		0xBEACB3B4B05F7F64ULL,
		0x85F91903342CC54FULL,
		0x04284F31D3F8DC6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7359AAB000000000ULL,
		0x05F7F64D9263E54AULL,
		0x42CC54FBEACB3B4BULL,
		0x3F8DC6E85F919033ULL,
		0x000000004284F31DULL
	}};
	shift = 228;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1B4E4F369DDD6E92ULL,
		0x31ADF0CCA05C71AAULL,
		0x1F01A71EC779EC78ULL,
		0x0756580B381055EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9200000000000000ULL,
		0xAA1B4E4F369DDD6EULL,
		0x7831ADF0CCA05C71ULL,
		0xEF1F01A71EC779ECULL,
		0x000756580B381055ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3E3C59337C46EE16ULL,
		0x755CCABDC5069F36ULL,
		0xC5D983BEDEA7227AULL,
		0x4F03DDB28D6230F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x37C46EE160000000ULL,
		0xDC5069F363E3C593ULL,
		0xEDEA7227A755CCABULL,
		0x28D6230F6C5D983BULL,
		0x0000000004F03DDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x19D99C0BFF694741ULL,
		0x7F978F8BD611FEA0ULL,
		0xEBDFF474D9B09DF3ULL,
		0x113B28BAB7448C3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8200000000000000ULL,
		0x4033B33817FED28EULL,
		0xE6FF2F1F17AC23FDULL,
		0x7DD7BFE8E9B3613BULL,
		0x00227651756E8918ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC62D39F425B2D3CBULL,
		0x956FB1EB44539A0DULL,
		0xF5CF7A624FC39480ULL,
		0x490925380BD69F03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D39F425B2D3CB00ULL,
		0x6FB1EB44539A0DC6ULL,
		0xCF7A624FC3948095ULL,
		0x0925380BD69F03F5ULL,
		0x0000000000000049ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5000253FCDC7EF6BULL,
		0xBF69FF36D1099009ULL,
		0x83B1B52807BB2CB6ULL,
		0x671A6B42D0435E95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4FF371FBDAC00000ULL,
		0xCDB4426402540009ULL,
		0x4A01EECB2DAFDA7FULL,
		0xD0B410D7A560EC6DULL,
		0x000000000019C69AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2E967FD1C252BE60ULL,
		0xD641BD11AA62417BULL,
		0x1EF524A87EDE5443ULL,
		0x72F8BB4AA412B63CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF300000000000000ULL,
		0x0BD974B3FE8E1295ULL,
		0xA21EB20DE88D5312ULL,
		0xB1E0F7A92543F6F2ULL,
		0x000397C5DA552095ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x44EE5DA6C90652FBULL,
		0x78BD060B287EE9F4ULL,
		0x277E053C286B32C4ULL,
		0x19BBB4A3DFB27328ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x772ED36483297D80ULL,
		0x5E8305943F74FA22ULL,
		0xBF029E143599623CULL,
		0xDDDA51EFD9399413ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E24EEA8355E82D7ULL,
		0x46E95545DB22555BULL,
		0x3AF2F50220E5515BULL,
		0x523A334D53AA1C37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF416B80000000000ULL,
		0x12AADAF1277541AAULL,
		0x2A8ADA374AAA2ED9ULL,
		0x50E1B9D797A81107ULL,
		0x00000291D19A6A9DULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCB6093FFAEAF39E5ULL,
		0xB5931448E7C9841FULL,
		0x3797D3F94BDAD7B4ULL,
		0x7880A0E47DA85896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xF2D824FFEBABCE79ULL,
		0x2D64C51239F26107ULL,
		0x8DE5F4FE52F6B5EDULL,
		0x1E2028391F6A1625ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x22567ADA66A603A2ULL,
		0x9608158CBC940326ULL,
		0x240B2ACDC382BC95ULL,
		0x4A7C37A71C9FA58FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E88000000000000ULL,
		0x0C988959EB699A98ULL,
		0xF25658205632F250ULL,
		0x963C902CAB370E0AULL,
		0x000129F0DE9C727EULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7A79BBB92E99CC02ULL,
		0x11C71D0971E5D4E5ULL,
		0xEA3B8A2170DE00D5ULL,
		0x6ADCEBC17546E019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2E99CC0200000000ULL,
		0x71E5D4E57A79BBB9ULL,
		0x70DE00D511C71D09ULL,
		0x7546E019EA3B8A21ULL,
		0x000000006ADCEBC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x04B1292FCFBAB18FULL,
		0x8CF93793C194C7F7ULL,
		0x656F66950C833887ULL,
		0x3699B0EBC151CA12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F00000000000000ULL,
		0xF704B1292FCFBAB1ULL,
		0x878CF93793C194C7ULL,
		0x12656F66950C8338ULL,
		0x003699B0EBC151CAULL
	}};
	shift = 248;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x54E2105B23516BA8ULL,
		0xC293D03CAF482802ULL,
		0xDAA946E87E3FB209ULL,
		0x5219091B58922B4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x12A71082D91A8B5DULL,
		0x4E149E81E57A4140ULL,
		0x7ED54A3743F1FD90ULL,
		0x0290C848DAC4915AULL
	}};
	shift = 251;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x989229FF0570EDD9ULL,
		0x4CCE50F045FA2828ULL,
		0x32D6C2A839D545CEULL,
		0x2C7156126B0F14A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FF0570EDD90000ULL,
		0x50F045FA28289892ULL,
		0xC2A839D545CE4CCEULL,
		0x56126B0F14A232D6ULL,
		0x0000000000002C71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x77CB84745DF2658BULL,
		0x23D1ACC66AC20C61ULL,
		0x3E7D40CD45CD2DC5ULL,
		0x5816C4F6C475B274ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB84745DF2658B000ULL,
		0x1ACC66AC20C6177CULL,
		0xD40CD45CD2DC523DULL,
		0x6C4F6C475B2743E7ULL,
		0x0000000000000581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA373A54CD13BF577ULL,
		0x67C833402FCE64B1ULL,
		0x0E709C9F0F0298E9ULL,
		0x23D5E8D70C37204EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAEE0000000000000ULL,
		0x96346E74A99A277EULL,
		0x1D2CF9066805F9CCULL,
		0x09C1CE1393E1E053ULL,
		0x00047ABD1AE186E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6B55A97BF589DB66ULL,
		0xE98BFF1E6F07187CULL,
		0x4F975095D391874DULL,
		0x2AA3A5B895A1D020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x589DB66000000000ULL,
		0xF07187C6B55A97BFULL,
		0x391874DE98BFF1E6ULL,
		0x5A1D0204F975095DULL,
		0x00000002AA3A5B89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6ECDF17624718D21ULL,
		0x8C352630BA19ECD9ULL,
		0x7CCD844F588F44F2ULL,
		0x2EB404942AAB57B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6908000000000000ULL,
		0x66CB766F8BB1238CULL,
		0x279461A93185D0CFULL,
		0xBD9BE66C227AC47AULL,
		0x000175A024A1555AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD28010949355F0EAULL,
		0x19BE4635FDCCC33EULL,
		0x428BEC470895A345ULL,
		0x5B2604B7563849A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40084A49AAF87500ULL,
		0xDF231AFEE6619F69ULL,
		0x45F623844AD1A28CULL,
		0x93025BAB1C24D3A1ULL,
		0x000000000000002DULL
	}};
	shift = 199;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x016746B1ADDA9097ULL,
		0x3856BD723BDC8B57ULL,
		0x8D0C6DD662B31A2CULL,
		0x7C3359614F76BE73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9097000000000000ULL,
		0x8B57016746B1ADDAULL,
		0x1A2C3856BD723BDCULL,
		0xBE738D0C6DD662B3ULL,
		0x00007C3359614F76ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBD6B6C32C33B6C48ULL,
		0xD8429166C29F679AULL,
		0xF93EBAEFAA8DCE4EULL,
		0x380425924F8806A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C32C33B6C480000ULL,
		0x9166C29F679ABD6BULL,
		0xBAEFAA8DCE4ED842ULL,
		0x25924F8806A1F93EULL,
		0x0000000000003804ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF7FF5605914D12F6ULL,
		0x032E55DBD51CC610ULL,
		0xD55A12ABB04E3ACCULL,
		0x0FC259CB3BF59136ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD581645344BD8000ULL,
		0x9576F54731843DFFULL,
		0x84AAEC138EB300CBULL,
		0x9672CEFD644DB556ULL,
		0x00000000000003F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x368F604A897DFFC8ULL,
		0x73AC423D34C7C070ULL,
		0xA758BDC56D801F1CULL,
		0x0A835ED1B5F1CC6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02544BEFFE400000ULL,
		0x11E9A63E0381B47BULL,
		0xEE2B6C00F8E39D62ULL,
		0xF68DAF8E63753AC5ULL,
		0x000000000000541AULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0EF8D84C8E2237F3ULL,
		0x115496D94AB10C86ULL,
		0x9958F14B4071BCB2ULL,
		0x7472215C0823485DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x647111BF98000000ULL,
		0xCA5588643077C6C2ULL,
		0x5A038DE5908AA4B6ULL,
		0xE0411A42ECCAC78AULL,
		0x0000000003A3910AULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8BB1058FFFBB552FULL,
		0x859C28AFDE76D4DFULL,
		0x7F189DCB7EE5A8B3ULL,
		0x1B3E0B1F9F6F0BD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xF17620B1FFF76AA5ULL,
		0x70B38515FBCEDA9BULL,
		0xEFE313B96FDCB516ULL,
		0x0367C163F3EDE17AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCB5CBB0982CA4562ULL,
		0x32BC1344AAA6058EULL,
		0x003F1AC880214FA7ULL,
		0x5765B0CE81F1552BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB291588000000000ULL,
		0xA98163B2D72EC260ULL,
		0x0853E9CCAF04D12AULL,
		0x7C554AC00FC6B220ULL,
		0x00000015D96C33A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB0116252C3E39541ULL,
		0xA6377351E359707DULL,
		0x3FA0ADEDE7FB268DULL,
		0x5621DDD25A89DEE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x6C045894B0F8E550ULL,
		0x698DDCD478D65C1FULL,
		0x4FE82B7B79FEC9A3ULL,
		0x1588777496A277BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2229A2DA4FE9B082ULL,
		0x587AF328C3872DDFULL,
		0xB5407971631BD078ULL,
		0x4411975DB06C48B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x345B49FD36104000ULL,
		0x5E651870E5BBE445ULL,
		0x0F2E2C637A0F0B0FULL,
		0x32EBB60D891616A8ULL,
		0x0000000000000882ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFE9C176C4D2B6D7BULL,
		0x8842A7B6D6DA523AULL,
		0x383CA162B52B0A93ULL,
		0x6CDAB29516C5CAEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xBFA705DB134ADB5EULL,
		0xE210A9EDB5B6948EULL,
		0x8E0F2858AD4AC2A4ULL,
		0x1B36ACA545B172BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3A9004827D9A4417ULL,
		0x6A5E73E750827C9CULL,
		0x18E3EF08722ED4CAULL,
		0x55D1125F563DE4FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA401209F669105C0ULL,
		0x979CF9D4209F270EULL,
		0x38FBC21C8BB5329AULL,
		0x744497D58F793FC6ULL,
		0x0000000000000015ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA51972016B88EE1CULL,
		0xFD514FE535537886ULL,
		0x2740CD8006236B4CULL,
		0x7663A8A1B652C893ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB900B5C4770E0000ULL,
		0xA7F29AA9BC43528CULL,
		0x66C00311B5A67EA8ULL,
		0xD450DB29644993A0ULL,
		0x0000000000003B31ULL
	}};
	shift = 207;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEA7B8CE37662107AULL,
		0xD74723C4904E1097ULL,
		0x94BFC44327B73747ULL,
		0x79891AF6EA970445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F719C6ECC420F40ULL,
		0xE8E4789209C212FDULL,
		0x97F88864F6E6E8FAULL,
		0x31235EDD52E088B2ULL,
		0x000000000000000FULL
	}};
	shift = 197;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1A79881D61C502F8ULL,
		0xC4A7FBE9341D61E4ULL,
		0xE25CEDBDA17894A3ULL,
		0x1363703C06757892ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05F0000000000000ULL,
		0xC3C834F3103AC38AULL,
		0x2947894FF7D2683AULL,
		0xF125C4B9DB7B42F1ULL,
		0x000026C6E0780CEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xABC460B34BC0452DULL,
		0xC7F9AB231C58D3A3ULL,
		0xF72E4C0B3966A8F9ULL,
		0x1724268A2C3BB056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2296800000000000ULL,
		0x69D1D5E23059A5E0ULL,
		0x547CE3FCD5918E2CULL,
		0xD82B7B9726059CB3ULL,
		0x00000B921345161DULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x09533331359044BCULL,
		0x6E1334BEB9BC6AE1ULL,
		0x03CFAA834466251DULL,
		0x313BCE89B3ED9548ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12F0000000000000ULL,
		0xAB84254CCCC4D641ULL,
		0x9475B84CD2FAE6F1ULL,
		0x55200F3EAA0D1198ULL,
		0x0000C4EF3A26CFB6ULL
	}};
	shift = 242;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA9CCA24A48E76B28ULL,
		0x82429FB8B4689533ULL,
		0x46644DE891072135ULL,
		0x65E0C1CD82175323ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7328929239DACA00ULL,
		0x90A7EE2D1A254CEAULL,
		0x99137A2441C84D60ULL,
		0x7830736085D4C8D1ULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5BE909E23DF87FECULL,
		0xAB5FECF53C436461ULL,
		0x74D9404713D3FB66ULL,
		0x36DCFF57989324C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x13C47BF0FFD80000ULL,
		0xD9EA7886C8C2B7D2ULL,
		0x808E27A7F6CD56BFULL,
		0xFEAF3126498AE9B2ULL,
		0x0000000000006DB9ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD3612513AAACB5A6ULL,
		0x55AA5A54FD0EDC6BULL,
		0x50B2FBF7539467A0ULL,
		0x636688706C8A74D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB2D6980000000000ULL,
		0x3B71AF4D84944EAAULL,
		0x519E8156A96953F4ULL,
		0x29D34D42CBEFDD4EULL,
		0x0000018D9A21C1B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2DA4EDB8C699A28AULL,
		0xD93FD50A36F4BA2DULL,
		0x1F0987AC68680149ULL,
		0x0878D639BE2E9446ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31A668A28000000ULL,
		0x28DBD2E8B4B693B6ULL,
		0xB1A1A0052764FF54ULL,
		0xE6F8BA51187C261EULL,
		0x000000000021E358ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5C9681CFD9FC481CULL,
		0x14ACD4BF1C16BA87ULL,
		0xAC85B9C57A210B2EULL,
		0x6AFAE63A66D85C69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81C0000000000000ULL,
		0xA875C9681CFD9FC4ULL,
		0xB2E14ACD4BF1C16BULL,
		0xC69AC85B9C57A210ULL,
		0x0006AFAE63A66D85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x47F5E4CA9CDC7BD6ULL,
		0x768C950F020C3F49ULL,
		0xBB097BF51D877022ULL,
		0x3CD0A6D75DCEBBFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF580000000000000ULL,
		0xD251FD7932A7371EULL,
		0x089DA32543C0830FULL,
		0xFF6EC25EFD4761DCULL,
		0x000F3429B5D773AEULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE1B1108BAE448E32ULL,
		0x87B589B1CD159481ULL,
		0xA5C8C075398FFCD7ULL,
		0x77A69920BEB36196ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C4422EB91238C80ULL,
		0xED626C7345652078ULL,
		0x72301D4E63FF35E1ULL,
		0xE9A6482FACD865A9ULL,
		0x000000000000001DULL
	}};
	shift = 198;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x463412B1378BBE8FULL,
		0x3EA3BAA309FC33CEULL,
		0x6D281AF2B8C3A71EULL,
		0x79F958E957AE2755ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF478000000000000ULL,
		0x9E7231A09589BC5DULL,
		0x38F1F51DD5184FE1ULL,
		0x3AAB6940D795C61DULL,
		0x0003CFCAC74ABD71ULL
	}};
	shift = 243;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1890A7DEB3646ABFULL,
		0x4BBE75D4A335335AULL,
		0x5A5CBB669BA185DAULL,
		0x2E5D345DD736ABA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBD66C8D57E000000ULL,
		0xA9466A66B431214FULL,
		0xCD37430BB4977CEBULL,
		0xBBAE6D5748B4B976ULL,
		0x00000000005CBA68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDF8FC138B89E501EULL,
		0xE5097B8E84037DA0ULL,
		0x0617F2E74233D92CULL,
		0x6914939888EFE240ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8271713CA03C0000ULL,
		0xF71D0806FB41BF1FULL,
		0xE5CE8467B259CA12ULL,
		0x273111DFC4800C2FULL,
		0x000000000000D229ULL
	}};
	shift = 209;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF4D8CF07832AF017ULL,
		0x5BCBEA1D5C3FD6B0ULL,
		0x316862119D8DF482ULL,
		0x274A69E31A1F2015ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0655E02E0000000ULL,
		0xAB87FAD61E9B19E0ULL,
		0x33B1BE904B797D43ULL,
		0x6343E402A62D0C42ULL,
		0x0000000004E94D3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x099A83535A10E164ULL,
		0xA12B5A1C86BD4D22ULL,
		0x7C1E4134C5826F65ULL,
		0x5C9970084AE11F1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C80000000000000ULL,
		0xA44133506A6B421CULL,
		0xECB4256B4390D7A9ULL,
		0xE3EF83C82698B04DULL,
		0x000B932E01095C23ULL
	}};
	shift = 245;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x92F1F0BEDB2F0059ULL,
		0xE068A1747F8B3EA8ULL,
		0x7C88B8456BE967C2ULL,
		0x4F54EEDAC4A8FAC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDB2F005900000000ULL,
		0x7F8B3EA892F1F0BEULL,
		0x6BE967C2E068A174ULL,
		0xC4A8FAC87C88B845ULL,
		0x000000004F54EEDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x90D603D23BA9BD07ULL,
		0xAD13768A666677BAULL,
		0x798F4A62F99A6AE9ULL,
		0x54E7AF1C68197C3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86B01E91DD4DE838ULL,
		0x689BB4533333BDD4ULL,
		0xCC7A5317CCD3574DULL,
		0xA73D78E340CBE1FBULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3A952606947E5B7CULL,
		0xCF4683C29D07DF0BULL,
		0x92B9AD9208AA20B6ULL,
		0x7A49545845279C74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x47E5B7C000000000ULL,
		0xD07DF0B3A9526069ULL,
		0x8AA20B6CF4683C29ULL,
		0x5279C7492B9AD920ULL,
		0x00000007A4954584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x11316B6F1579CD30ULL,
		0x19816512AA6F1C4CULL,
		0x0332EF2A35F64E53ULL,
		0x5625DFBF2921140BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55E734C000000000ULL,
		0xA9BC713044C5ADBCULL,
		0xD7D9394C6605944AULL,
		0xA484502C0CCBBCA8ULL,
		0x0000000158977EFCULL
	}};
	shift = 226;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDC009BDE3A77D351ULL,
		0x2877590C1B4DDFB8ULL,
		0x14814E12587FF20FULL,
		0x524648BB80F121C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0137BC74EFA6A200ULL,
		0xEEB218369BBF71B8ULL,
		0x029C24B0FFE41E50ULL,
		0x8C917701E2439029ULL,
		0x00000000000000A4ULL
	}};
	shift = 201;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1EDF72C810ACF27EULL,
		0x78F60C6570A77B07ULL,
		0xD3FE22B65A0C1876ULL,
		0x3A57E889495A1A5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1EDF72C810ACF27EULL,
		0x78F60C6570A77B07ULL,
		0xD3FE22B65A0C1876ULL,
		0x3A57E889495A1A5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x843E300F44162C9DULL,
		0xF4C7A3CD3E90389EULL,
		0x688CB10A5297C7D8ULL,
		0x1FF365E313B107B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD1058B2740000000ULL,
		0x4FA40E27A10F8C03ULL,
		0x94A5F1F63D31E8F3ULL,
		0xC4EC41ED1A232C42ULL,
		0x0000000007FCD978ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0A88BFAE8F54F725ULL,
		0x10F42BB5A3EAE2C8ULL,
		0x887442E8F9067290ULL,
		0x01E011BF96BFD966ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22FEBA3D53DC940ULL,
		0x3D0AED68FAB8B202ULL,
		0x1D10BA3E419CA404ULL,
		0x78046FE5AFF659A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCCAA062DCF7BDB2EULL,
		0x154964D84208E9D8ULL,
		0x1BEDD168D4CBDB31ULL,
		0x4C8191E90FAC97C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B73DEF6CB80000ULL,
		0x93610823A76332A8ULL,
		0x45A3532F6CC45525ULL,
		0x47A43EB25F146FB7ULL,
		0x0000000000013206ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4BB4801AB16B7D49ULL,
		0xAE4B62FDEC80AFCCULL,
		0xB3DED1F0B7162CA5ULL,
		0x408E117DF18CBA5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1AB16B7D49000000ULL,
		0xFDEC80AFCC4BB480ULL,
		0xF0B7162CA5AE4B62ULL,
		0x7DF18CBA5AB3DED1ULL,
		0x0000000000408E11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF9CF71C2765ACA19ULL,
		0xE74915C9DA68B15BULL,
		0x2E51072825BDDC5AULL,
		0x1E353E74CAF09B84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D96B28640000000ULL,
		0x769A2C56FE73DC70ULL,
		0x096F7716B9D24572ULL,
		0x32BC26E10B9441CAULL,
		0x00000000078D4F9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x658C2F52EC0D0B6CULL,
		0x3083193DB82398F1ULL,
		0x36583AB1101AAACCULL,
		0x31EBC1BCBDB1110AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D80000000000000ULL,
		0x1E2CB185EA5D81A1ULL,
		0x5986106327B70473ULL,
		0x2146CB0756220355ULL,
		0x00063D783797B622ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x028ADECFE6A45677ULL,
		0xA2887D40367F4F16ULL,
		0x684FA7C4149BF64FULL,
		0x5189A4FA3AB0369BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28ADECFE6A456770ULL,
		0x2887D40367F4F160ULL,
		0x84FA7C4149BF64FAULL,
		0x189A4FA3AB0369B6ULL,
		0x0000000000000005ULL
	}};
	shift = 196;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x56C61076FD99C03DULL,
		0x67747A5B075D3E7EULL,
		0x85A71187F76900BCULL,
		0x2E60FE0B1522A1E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD000000000000000ULL,
		0xE56C61076FD99C03ULL,
		0xC67747A5B075D3E7ULL,
		0x285A71187F76900BULL,
		0x02E60FE0B1522A1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC0A649F6ADC12B6CULL,
		0x571E537D5AB8EE4DULL,
		0x975A43925A88D505ULL,
		0x3C8FF51289A89F8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB00000000000000ULL,
		0x937029927DAB704AULL,
		0x4155C794DF56AE3BULL,
		0xE2E5D690E496A235ULL,
		0x000F23FD44A26A27ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x64E9B11E4F0B3A09ULL,
		0xF5660E58D742E590ULL,
		0x5C3A589AB83D92ADULL,
		0x12F86FE9954A0E4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7859D04800000000ULL,
		0xBA172C83274D88F2ULL,
		0xC1EC956FAB3072C6ULL,
		0xAA507262E1D2C4D5ULL,
		0x0000000097C37F4CULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDB13BE3D0A1F82B6ULL,
		0xDC6BDC511C3EC0A7ULL,
		0x0CE8DF4231411112ULL,
		0x528AA5E3129BFDF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x277C7A143F056C00ULL,
		0xD7B8A2387D814FB6ULL,
		0xD1BE8462822225B8ULL,
		0x154BC62537FBEC19ULL,
		0x00000000000000A5ULL
	}};
	shift = 201;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC941AFE3BAF30076ULL,
		0x989D425FAED6A8EBULL,
		0x9A1E24303C314B98ULL,
		0x33FA2E642E7DB15CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9803B00000000000ULL,
		0xB5475E4A0D7F1DD7ULL,
		0x8A5CC4C4EA12FD76ULL,
		0xED8AE4D0F12181E1ULL,
		0x0000019FD1732173ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3243CAE09D11E49BULL,
		0xBB5CA983C205E40DULL,
		0x00C1EE91274ACF13ULL,
		0x7232753CC24AE221ULL,
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
		0x3243CAE09D11E49BULL,
		0xBB5CA983C205E40DULL,
		0x00C1EE91274ACF13ULL,
		0x7232753CC24AE221ULL
	}};
	shift = 256;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCECAA72C367CCAB2ULL,
		0xCEFABA325EE16B3FULL,
		0xF2CC2EC01DEC1644ULL,
		0x77FD921773F8F8B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3961B3E655900000ULL,
		0xD192F70B59FE7655ULL,
		0x7600EF60B22677D5ULL,
		0x90BB9FC7C5B79661ULL,
		0x000000000003BFECULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC3CA1F0F84D55AAFULL,
		0x7D406181EC1936A6ULL,
		0x5811D36ABC881B93ULL,
		0x45845BECE044D4D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F87C26AAD57800ULL,
		0x030C0F60C9B5361EULL,
		0x8E9B55E440DC9BEAULL,
		0x22DF670226A6B2C0ULL,
		0x000000000000022CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9D3D35A29947A5EBULL,
		0x977B2396C14A0871ULL,
		0x8516BBAA26F8780CULL,
		0x6CE603D8D865CA25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E9AD14CA3D2F580ULL,
		0xBD91CB60A50438CEULL,
		0x8B5DD5137C3C064BULL,
		0x7301EC6C32E512C2ULL,
		0x0000000000000036ULL
	}};
	shift = 199;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7B7335E612B24E79ULL,
		0xC11A0A2B4877754CULL,
		0xD4CAC7C767BF0F5CULL,
		0x101E87A3F0B88E2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9273C80000000000ULL,
		0xBBAA63DB99AF3095ULL,
		0xF87AE608D0515A43ULL,
		0xC4717EA6563E3B3DULL,
		0x00000080F43D1F85ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA7161605B4771B6CULL,
		0x0F4E7E7A9F61D569ULL,
		0x0E2B570FBC969976ULL,
		0x64806BEA203510ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36D8000000000000ULL,
		0xAAD34E2C2C0B68EEULL,
		0x32EC1E9CFCF53EC3ULL,
		0x215A1C56AE1F792DULL,
		0x0000C900D7D4406AULL
	}};
	shift = 241;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x58985DDA688A5A9BULL,
		0x97FB20563E257325ULL,
		0x16E35661D23B536AULL,
		0x738752E6FCEB0757ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEED34452D4D80000ULL,
		0x02B1F12B992AC4C2ULL,
		0xB30E91DA9B54BFD9ULL,
		0x9737E7583AB8B71AULL,
		0x0000000000039C3AULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x08FDD099070DB243ULL,
		0x23663BD171DF32B0ULL,
		0x993BAAD5A21C3055ULL,
		0x004C26F804B3E66CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x11FBA1320E1B6486ULL,
		0x46CC77A2E3BE6560ULL,
		0x327755AB443860AAULL,
		0x00984DF00967CCD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x822D4A51476FD730ULL,
		0x3860FF0FFC83DF42ULL,
		0xF56A295C827EB4EBULL,
		0x7DA171238E81F96BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA28EDFAE60000000ULL,
		0x1FF907BE85045A94ULL,
		0xB904FD69D670C1FEULL,
		0x471D03F2D7EAD452ULL,
		0x0000000000FB42E2ULL
	}};
	shift = 217;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA934A1E626262A62ULL,
		0xB425EF2C4EDB2BB5ULL,
		0xC4FEC66F9B434C1AULL,
		0x64D1FEF31B1BC4FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x262A620000000000ULL,
		0xDB2BB5A934A1E626ULL,
		0x434C1AB425EF2C4EULL,
		0x1BC4FAC4FEC66F9BULL,
		0x00000064D1FEF31BULL
	}};
	shift = 232;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x26060109584C9CB2ULL,
		0xB89F647A52F96BB1ULL,
		0x631E813771578859ULL,
		0x4D65C347E9AAC277ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x084AC264E5900000ULL,
		0x23D297CB5D893030ULL,
		0x09BB8ABC42CDC4FBULL,
		0x1A3F4D5613BB18F4ULL,
		0x0000000000026B2EULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x55AD5FFC9CC6594BULL,
		0xBD7D1A93CC62ADB1ULL,
		0xCC062D900B82ABB4ULL,
		0x1BF650ADB99B98BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD6AFFE4E632CA580ULL,
		0xBE8D49E63156D8AAULL,
		0x0316C805C155DA5EULL,
		0xFB2856DCCDCC5D66ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5BAC0824A104DD64ULL,
		0xE8E1EFA8BF7C0221ULL,
		0x985DE19A9095735EULL,
		0x02A4061066970A0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0824A104DD64000ULL,
		0x1EFA8BF7C02215BAULL,
		0xDE19A9095735EE8EULL,
		0x4061066970A0A985ULL,
		0x000000000000002AULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA825BAA11B5CCBA5ULL,
		0x47DBCC31997A688FULL,
		0x84F894FA2F516DF8ULL,
		0x1D0DF015CE45144FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE65D28000000000ULL,
		0xBD3447D412DD508DULL,
		0xA8B6FC23EDE618CCULL,
		0x228A27C27C4A7D17ULL,
		0x0000000E86F80AE7ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5C0D1CAB9D2F813BULL,
		0xC611DC673C22C077ULL,
		0xD2D8E7F5AE7E2A9EULL,
		0x2F1E728BEECAD6AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x04EC000000000000ULL,
		0x01DD703472AE74BEULL,
		0xAA7B1847719CF08BULL,
		0x5AAB4B639FD6B9F8ULL,
		0x0000BC79CA2FBB2BULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x964FE31F4492F7F3ULL,
		0x0F9834C7350861E8ULL,
		0x5696410B3EB0E0DEULL,
		0x14AFD00BAA0A09F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C7D124BDFCC0000ULL,
		0xD31CD42187A2593FULL,
		0x042CFAC383783E60ULL,
		0x402EA82827D95A59ULL,
		0x00000000000052BFULL
	}};
	shift = 210;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD014F254AB433289ULL,
		0x0C87156335BE5BC0ULL,
		0x330CF8DE08B71202ULL,
		0x7E4DF8D8871866FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF254AB4332890000ULL,
		0x156335BE5BC0D014ULL,
		0xF8DE08B712020C87ULL,
		0xF8D8871866FF330CULL,
		0x0000000000007E4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE5CE754D019D9DC3ULL,
		0x5F2269E61F3D91BDULL,
		0x1333043C9380EE2EULL,
		0x4A8418725A455DD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE18000000000000ULL,
		0x8DEF2E73AA680CECULL,
		0x7172F9134F30F9ECULL,
		0xEEC8999821E49C07ULL,
		0x00025420C392D22AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBADB3F2D0302EC85ULL,
		0x377172046EFA38C7ULL,
		0x5C76474E89962275ULL,
		0x0C8DC8A0AF726B36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6428000000000000ULL,
		0xC63DD6D9F9681817ULL,
		0x13A9BB8B902377D1ULL,
		0x59B2E3B23A744CB1ULL,
		0x0000646E45057B93ULL
	}};
	shift = 243;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE5FD4F782559019AULL,
		0xD3D7281F0E806C34ULL,
		0x68C33812D961129BULL,
		0x6C517B3D139176DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CD0000000000000ULL,
		0x61A72FEA7BC12AC8ULL,
		0x94DE9EB940F87403ULL,
		0xB6F34619C096CB08ULL,
		0x0003628BD9E89C8BULL
	}};
	shift = 243;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBD28F08A618A35F5ULL,
		0xD1030C74C1422BE0ULL,
		0x7ED484156BDDA2C4ULL,
		0x5AE1ED20A1101BB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94784530C51AFA80ULL,
		0x81863A60A115F05EULL,
		0x6A420AB5EED16268ULL,
		0x70F69050880DD83FULL,
		0x000000000000002DULL
	}};
	shift = 199;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x41B611EDD2891370ULL,
		0x0E527B050A79DAFEULL,
		0x903FB0D9DED87E8EULL,
		0x02BA6A179AC69170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A244DC000000000ULL,
		0x29E76BF906D847B7ULL,
		0x7B61FA383949EC14ULL,
		0x6B1A45C240FEC367ULL,
		0x000000000AE9A85EULL
	}};
	shift = 226;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6337CF40A9169D59ULL,
		0xB968B00970BCC4F4ULL,
		0x1F1FC271A547F293ULL,
		0x21D895156EFB9BE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9E81522D3AB2000ULL,
		0x16012E17989E8C66ULL,
		0xF84E34A8FE52772DULL,
		0x12A2ADDF737C03E3ULL,
		0x000000000000043BULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC19F3CB9FA89AF3FULL,
		0x4AAF7DE3553D8977ULL,
		0xF0EFA3624A23B687ULL,
		0x634E2DF90694E113ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7EA26BCFC000000ULL,
		0x8D54F625DF067CF2ULL,
		0x89288EDA1D2ABDF7ULL,
		0xE41A53844FC3BE8DULL,
		0x00000000018D38B7ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDC47E06F370E283CULL,
		0xD71727A1274C7398ULL,
		0x73A355226532D57CULL,
		0x67B1E0E398692008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C0000000000000ULL,
		0x398DC47E06F370E2ULL,
		0x57CD71727A1274C7ULL,
		0x00873A355226532DULL,
		0x00067B1E0E398692ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFDFE9806BD1BEF67ULL,
		0xA73083404156B55DULL,
		0xDF57484ACF0DFAB9ULL,
		0x5B76226CDDB3739AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF46FBD9C000000ULL,
		0x01055AD577F7FA60ULL,
		0x2B3C37EAE69CC20DULL,
		0xB376CDCE6B7D5D21ULL,
		0x00000000016DD889ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE46A94562E82CC9FULL,
		0x56C1D5B087A77422ULL,
		0x34E6E5A20A2EB12CULL,
		0x3DC98D908E12A363ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x5C8D528AC5D05993ULL,
		0x8AD83AB610F4EE84ULL,
		0x669CDCB44145D625ULL,
		0x07B931B211C2546CULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x47678858073A114CULL,
		0x18C6796B050B232FULL,
		0x1B309819EDB0E4A5ULL,
		0x08A0CF53C73EE09EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3C42C039D08A6000ULL,
		0x33CB582859197A3BULL,
		0x84C0CF6D872528C6ULL,
		0x067A9E39F704F0D9ULL,
		0x0000000000000045ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBA56EE512A2B9F75ULL,
		0x791540D49E32DF94ULL,
		0xEC45E5D919D370A7ULL,
		0x230C8CD9CF5696C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7DD400000000000ULL,
		0xB7E52E95BB944A8AULL,
		0xDC29DE455035278CULL,
		0xA5B17B1179764674ULL,
		0x000008C3233673D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAF62F6E31134509EULL,
		0xA91451BE582E0557ULL,
		0xF004F77866A6FC1FULL,
		0x19E56633E91D9659ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x17B71889A284F000ULL,
		0xA28DF2C1702ABD7BULL,
		0x27BBC33537E0FD48ULL,
		0x2B319F48ECB2CF80ULL,
		0x00000000000000CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8C1EB5888E6EFF3CULL,
		0x028B158570C522B5ULL,
		0x8DBFC50755344072ULL,
		0x18793BFDB2A77745ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x77F9E00000000000ULL,
		0x2915AC60F5AC4473ULL,
		0xA203901458AC2B86ULL,
		0x3BBA2C6DFE283AA9ULL,
		0x000000C3C9DFED95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5F9D489C652D7447ULL,
		0x119B2D5F582D443AULL,
		0x51C29DDFD155DB71ULL,
		0x62440D3FC4A5B707ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D7447000000000ULL,
		0x82D443A5F9D489C6ULL,
		0x155DB71119B2D5F5ULL,
		0x4A5B70751C29DDFDULL,
		0x000000062440D3FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5869792397139C8FULL,
		0x4D144E60121EC69EULL,
		0xB70021AE2B8B3CB5ULL,
		0x1AA7350DCC0A90F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C00000000000000ULL,
		0x7961A5E48E5C4E72ULL,
		0xD534513980487B1AULL,
		0xC2DC0086B8AE2CF2ULL,
		0x006A9CD437302A43ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6A269DA913B9C1D3ULL,
		0xAC68F508DB41834DULL,
		0xD4517EA245144C8CULL,
		0x7FEBE179F4B563ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA913B9C1D300000ULL,
		0x508DB41834D6A269ULL,
		0xEA245144C8CAC68FULL,
		0x179F4B563ECD4517ULL,
		0x000000000007FEBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7A3CF583DE5F942FULL,
		0xCCFAB15EF9CF81AFULL,
		0x4EBAA64BA28FD6E3ULL,
		0x7991E20AA2CE08FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F0000000000000ULL,
		0x1AF7A3CF583DE5F9ULL,
		0x6E3CCFAB15EF9CF8ULL,
		0x8FA4EBAA64BA28FDULL,
		0x0007991E20AA2CE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x75C04AF5B57568CCULL,
		0x0F1100FC5D2B0B75ULL,
		0x56A27B4794A6FDD5ULL,
		0x4365D7DBFAC84669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12BD6D5D5A330000ULL,
		0x403F174AC2DD5D70ULL,
		0x9ED1E529BF7543C4ULL,
		0x75F6FEB2119A55A8ULL,
		0x00000000000010D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB73ECA276ACAC4DDULL,
		0x0CB42AD4A8403A2EULL,
		0xCAF8013971B5FE62ULL,
		0x665066A0710505A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x76ACAC4DD0000000ULL,
		0x4A8403A2EB73ECA2ULL,
		0x971B5FE620CB42ADULL,
		0x0710505A5CAF8013ULL,
		0x000000000665066AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAF521196FDE80CB7ULL,
		0x152B058603803193ULL,
		0x2BE61D056CD42EDCULL,
		0x4DDD016AB5EFF682ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4232DFBD0196E000ULL,
		0x60B0C070063275EAULL,
		0xC3A0AD9A85DB82A5ULL,
		0xA02D56BDFED0457CULL,
		0x00000000000009BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x28406C5E96B4C73BULL,
		0x9BCC27E23700BE06ULL,
		0x26EA3271B22754A0ULL,
		0x7765C7EDC45F7F35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D8BD2D698E76000ULL,
		0x84FC46E017C0C508ULL,
		0x464E3644EA941379ULL,
		0xB8FDB88BEFE6A4DDULL,
		0x0000000000000EECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8D38BDE52DBEDC6EULL,
		0xF6ED3F9E98B20728ULL,
		0x34143912A36239E4ULL,
		0x17A982A5F608046FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F794B6FB71B8000ULL,
		0x4FE7A62C81CA234EULL,
		0x0E44A8D88E793DBBULL,
		0x60A97D82011BCD05ULL,
		0x00000000000005EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCC7024BFA6D92916ULL,
		0xF902799911141567ULL,
		0x57F0BF22E80C8366ULL,
		0x7AA797809A123C34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x092FE9B64A458000ULL,
		0x9E6644450559F31CULL,
		0x2FC8BA0320D9BE40ULL,
		0xE5E026848F0D15FCULL,
		0x0000000000001EA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2E7C0B7773BBCC2EULL,
		0x8842C571383507D4ULL,
		0x49B238D7E25EC8C0ULL,
		0x55CD578AD144A46BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9F02DDDCEEF30B80ULL,
		0x10B15C4E0D41F50BULL,
		0x6C8E35F897B23022ULL,
		0x7355E2B451291AD2ULL,
		0x0000000000000015ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2D488BDA4FABB511ULL,
		0xA0948225821E18F0ULL,
		0x45B1CBDFB56AC7C2ULL,
		0x3A8750447C610900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x05A9117B49F576A2ULL,
		0x54129044B043C31EULL,
		0x08B6397BF6AD58F8ULL,
		0x0750EA088F8C2120ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4E66CCD8D42F0DCCULL,
		0x0C3977C537446E1EULL,
		0xB01966E7BB185815ULL,
		0x733B949D522C4F4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x336350BC37300000ULL,
		0xDF14DD11B879399BULL,
		0x9B9EEC61605430E5ULL,
		0x527548B13D3AC065ULL,
		0x000000000001CCEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAA51EC275DC27619ULL,
		0xBF4755C94A240FF0ULL,
		0x17A81A5B296CB02AULL,
		0x1CFEEEE3B9E7757CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C80000000000000ULL,
		0xF85528F613AEE13BULL,
		0x155FA3AAE4A51207ULL,
		0xBE0BD40D2D94B658ULL,
		0x000E7F7771DCF3BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD1F9353CA4C03C8CULL,
		0xE7CA06E530F6B4D1ULL,
		0x774D1770D510F82BULL,
		0x06D5C4619471E1E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7949807918000000ULL,
		0xCA61ED69A3A3F26AULL,
		0xE1AA21F057CF940DULL,
		0xC328E3C3C8EE9A2EULL,
		0x00000000000DAB88ULL
	}};
	shift = 217;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2FBBD2ADB1649824ULL,
		0xEF382375272EA037ULL,
		0x3C2778B03851237DULL,
		0x4772C15F66D16674ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97DDE956D8B24C12ULL,
		0xF79C11BA9397501BULL,
		0x1E13BC581C2891BEULL,
		0x23B960AFB368B33AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEFC31C09F6385F51ULL,
		0x41941E3C9CFA6EA2ULL,
		0x115C8C89CEBB3922ULL,
		0x1DBB4068DF353D3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C09F6385F51000ULL,
		0x41E3C9CFA6EA2EFCULL,
		0xC8C89CEBB3922419ULL,
		0xB4068DF353D3A115ULL,
		0x00000000000001DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x20D827F2BE84125BULL,
		0x2FF610397745325BULL,
		0xDC0DAD2E1439C7B5ULL,
		0x0568AA235D52CFB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42092D800000000ULL,
		0xBA2992D906C13F95ULL,
		0xA1CE3DA97FB081CBULL,
		0xEA967D9EE06D6970ULL,
		0x000000002B45511AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD727B4BA6148AA9AULL,
		0xDBC9BDCF8346E51DULL,
		0x4629726DBC42E315ULL,
		0x08F4E340D7F8C696ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9ED2E98522AA6800ULL,
		0x26F73E0D1B94775CULL,
		0xA5C9B6F10B8C576FULL,
		0xD38D035FE31A5918ULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x27C033AA4AEBE4E4ULL,
		0x994E66C573B6F7C2ULL,
		0x70626996F0B85CD6ULL,
		0x54B69220C3D990A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19D52575F2720000ULL,
		0x3362B9DB7BE113E0ULL,
		0x34CB785C2E6B4CA7ULL,
		0x491061ECC853B831ULL,
		0x0000000000002A5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFA7D4C32AB203149ULL,
		0x0109EE83A5FB4295ULL,
		0xD1091B3D9D9330CBULL,
		0x6661576A4800B7FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x32AB203149000000ULL,
		0x83A5FB4295FA7D4CULL,
		0x3D9D9330CB0109EEULL,
		0x6A4800B7FFD1091BULL,
		0x0000000000666157ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA4162CB2E679F15EULL,
		0x6F9E1C2C605C7D25ULL,
		0x55F68651D3B6ACD6ULL,
		0x3A1C6DDC03F6E3C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCCF3E2BC00000000ULL,
		0xC0B8FA4B482C5965ULL,
		0xA76D59ACDF3C3858ULL,
		0x07EDC78EABED0CA3ULL,
		0x000000007438DBB8ULL
	}};
	shift = 225;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2AB8750C1834835DULL,
		0xCB72A256C90C3AFEULL,
		0xB6D5037E24942A17ULL,
		0x4E4B1897A75695CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D43060D20D74000ULL,
		0xA895B2430EBF8AAEULL,
		0x40DF89250A85F2DCULL,
		0xC625E9D5A572EDB5ULL,
		0x0000000000001392ULL
	}};
	shift = 206;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x586FB440FEB6DF61ULL,
		0x696DA7FC58241408ULL,
		0x091DAE06859EF31FULL,
		0x231CEB5FE4183735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x207F5B6FB0800000ULL,
		0xFE2C120A042C37DAULL,
		0x0342CF798FB4B6D3ULL,
		0xAFF20C1B9A848ED7ULL,
		0x0000000000118E75ULL
	}};
	shift = 215;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2947DDA455B54353ULL,
		0xBABDC5CEFB8F52D7ULL,
		0xF088F3B95A121FCFULL,
		0x4DCD8AFF99209A3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEED22ADAA1A98000ULL,
		0xE2E77DC7A96B94A3ULL,
		0x79DCAD090FE7DD5EULL,
		0xC57FCC904D1E7844ULL,
		0x00000000000026E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x79D7D089E61367ADULL,
		0x35A7C6C289D5F39AULL,
		0x1C5118DB45C2420BULL,
		0x2A8F6100FA1724D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBE844F309B3D680ULL,
		0xD3E36144EAF9CD3CULL,
		0x288C6DA2E121059AULL,
		0x47B0807D0B926A0EULL,
		0x0000000000000015ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x87C9000F7755C1E6ULL,
		0x4C0D488D51B89A46ULL,
		0x5B40E5BDB8D98FF0ULL,
		0x1CA9E55C3CA8C536ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1E6000000000000ULL,
		0x9A4687C9000F7755ULL,
		0x8FF04C0D488D51B8ULL,
		0xC5365B40E5BDB8D9ULL,
		0x00001CA9E55C3CA8ULL
	}};
	shift = 240;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCCF141105D58FE87ULL,
		0x1F5418AF967CE12AULL,
		0x6290F9C47B429452ULL,
		0x0CA86496EAED634AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417563FA1C000000ULL,
		0xBE59F384AB33C504ULL,
		0x11ED0A51487D5062ULL,
		0x5BABB58D298A43E7ULL,
		0x000000000032A192ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5B1C041C0106F52EULL,
		0x4D3A5CB1ADCF44B3ULL,
		0xF5447846ED6324D6ULL,
		0x60268C1A107E47C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C701070041BD4B8ULL,
		0x34E972C6B73D12CDULL,
		0xD511E11BB58C9359ULL,
		0x809A306841F91F13ULL,
		0x0000000000000001ULL
	}};
	shift = 194;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x16EF88C2B9E308E7ULL,
		0x54E257622D4116ABULL,
		0xE57BEE9BB6AC57CBULL,
		0x04AE708EA7FC8CC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3800000000000000ULL,
		0x58B77C4615CF1847ULL,
		0x5AA712BB116A08B5ULL,
		0x172BDF74DDB562BEULL,
		0x00257384753FE466ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8076438D100DA1C1ULL,
		0xE119C0CDF3FA8AF0ULL,
		0x56588073F5019DE3ULL,
		0x38D6E8B59D94C3E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4382000000000000ULL,
		0x15E100EC871A201BULL,
		0x3BC7C233819BE7F5ULL,
		0x87CAACB100E7EA03ULL,
		0x000071ADD16B3B29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0A64B648830EB3D7ULL,
		0x86E595828406F852ULL,
		0x1DC149C141D6CCC4ULL,
		0x49B9BD25F263F725ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xACF5C00000000000ULL,
		0xBE1482992D9220C3ULL,
		0xB33121B96560A101ULL,
		0xFDC9477052705075ULL,
		0x0000126E6F497C98ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1451F0C5D97A94DBULL,
		0xF983DD0EC04320EDULL,
		0xEE278C0CD789D0DBULL,
		0x239FD12D5AE931C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28F862ECBD4A6D80ULL,
		0xC1EE87602190768AULL,
		0x13C6066BC4E86DFCULL,
		0xCFE896AD7498E177ULL,
		0x0000000000000011ULL
	}};
	shift = 199;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x56726B760EF863BBULL,
		0x6430F1CB0404AFDBULL,
		0xD9D331B498902A34ULL,
		0x5C8784B10580898EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF863BB00000000ULL,
		0x0404AFDB56726B76ULL,
		0x98902A346430F1CBULL,
		0x0580898ED9D331B4ULL,
		0x000000005C8784B1ULL,
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
	curve25519_key_lshift(&k1, shift, &r);
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
		0x25D573DB08E30565ULL,
		0x12CB54C744592A3DULL,
		0xBB01A64C9E16CE17ULL,
		0x03F85B6EF722F611ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAAE7B611C60ACA00ULL,
		0x96A98E88B2547A4BULL,
		0x034C993C2D9C2E25ULL,
		0xF0B6DDEE45EC2376ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB566BEA58761B268ULL,
		0x806114C811939849ULL,
		0x4D8E21BA7D996D1EULL,
		0x7AC5367B4E7828C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA58761B268000000ULL,
		0xC811939849B566BEULL,
		0xBA7D996D1E806114ULL,
		0x7B4E7828C34D8E21ULL,
		0x00000000007AC536ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFCF331B520F98501ULL,
		0xF2395763856AC7B8ULL,
		0x2EC81AC15A6FD623ULL,
		0x04FECDFC1380BF01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA41F30A020000000ULL,
		0x70AD58F71F9E6636ULL,
		0x2B4DFAC47E472AECULL,
		0x827017E025D90358ULL,
		0x00000000009FD9BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x76F99F54DDDF8193ULL,
		0x87DD86A03FB4E47BULL,
		0x0761BC882B981D14ULL,
		0x769CA716BBBEBE82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAA6EEFC0C980000ULL,
		0x3501FDA723DBB7CCULL,
		0xE4415CC0E8A43EECULL,
		0x38B5DDF5F4103B0DULL,
		0x000000000003B4E5ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1D506910375F1C91ULL,
		0x7A1C9213F95ED9A4ULL,
		0x51C71E2DC97FFCD8ULL,
		0x7D048C5186136A54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE488000000000000ULL,
		0xCD20EA834881BAF8ULL,
		0xE6C3D0E4909FCAF6ULL,
		0x52A28E38F16E4BFFULL,
		0x0003E824628C309BULL
	}};
	shift = 243;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x265C4020A2A1D685ULL,
		0x5435F5A1CB8238FDULL,
		0xAB774BADFF28C6F9ULL,
		0x4F674563D76DA500ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0xA4CB880414543AD0ULL,
		0x2A86BEB43970471FULL,
		0x156EE975BFE518DFULL,
		0x09ECE8AC7AEDB4A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7AAC4AD9DF61861FULL,
		0xD0914B02137C3600ULL,
		0x8E010D2590A2C50DULL,
		0x14B6A0F5A290C1C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x895B3BEC30C3E000ULL,
		0x2960426F86C00F55ULL,
		0x21A4B21458A1BA12ULL,
		0xD41EB4521838F1C0ULL,
		0x0000000000000296ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xABC7AEAAF6D500F8ULL,
		0xC163E2D8C181B59BULL,
		0xD8ACBD13D59AAE03ULL,
		0x350A6CC5C372E4F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F00000000000000ULL,
		0xB37578F5D55EDAA0ULL,
		0xC0782C7C5B183036ULL,
		0x9F1B1597A27AB355ULL,
		0x0006A14D98B86E5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6426E0D45FCA3ADBULL,
		0xE1A47D6EA83E997AULL,
		0x79943EA4B4FCD1FEULL,
		0x386279009F18D966ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB600000000000000ULL,
		0xF4C84DC1A8BF9475ULL,
		0xFDC348FADD507D32ULL,
		0xCCF3287D4969F9A3ULL,
		0x0070C4F2013E31B2ULL
	}};
	shift = 249;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6EC7D5BC0779D640ULL,
		0xFC3B0B1DBE7337D0ULL,
		0x822B71584632302FULL,
		0x444C0350FB94E539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0779D6400000000ULL,
		0xDBE7337D06EC7D5BULL,
		0x84632302FFC3B0B1ULL,
		0x0FB94E539822B715ULL,
		0x000000000444C035ULL
	}};
	shift = 220;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x12A23CA0EEA78DAEULL,
		0x729FAD16832D2893ULL,
		0x2A51CE831BEEE2E6ULL,
		0x6645236622ADC058ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD4F1B5C00000000ULL,
		0x065A512625447941ULL,
		0x37DDC5CCE53F5A2DULL,
		0x455B80B054A39D06ULL,
		0x00000000CC8A46CCULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEF38DD505827F974ULL,
		0xD1E668EDB93ED613ULL,
		0xD2D466796D907572ULL,
		0x12CF409AF27A0179ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCBA000000000000ULL,
		0x6B09F79C6EA82C13ULL,
		0x3AB968F33476DC9FULL,
		0x00BCE96A333CB6C8ULL,
		0x00000967A04D793DULL
	}};
	shift = 239;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD4AE996F09A3C2FCULL,
		0xEC8AE87E38B32BC0ULL,
		0x17562708D90D4E6FULL,
		0x5D5EF7E52847A9A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE134785F8000000ULL,
		0xFC71665781A95D32ULL,
		0x11B21A9CDFD915D0ULL,
		0xCA508F534C2EAC4EULL,
		0x0000000000BABDEFULL
	}};
	shift = 217;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4405BFFEE75074B4ULL,
		0x6CCFB5AA9B9D6D1AULL,
		0xDFD25C3901B0E468ULL,
		0x1339C20F124ED455ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFF73A83A5A00000ULL,
		0xAD54DCEB68D2202DULL,
		0xE1C80D872343667DULL,
		0x10789276A2AEFE92ULL,
		0x00000000000099CEULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB138BEB2F9EF0523ULL,
		0x15E8116386B1587CULL,
		0xBEFE5812DC4F3198ULL,
		0x424B8B9DC417F8E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x2C4E2FACBE7BC148ULL,
		0x057A0458E1AC561FULL,
		0xEFBF9604B713CC66ULL,
		0x1092E2E77105FE39ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB53F965443F34022ULL,
		0x803BB353D67F240FULL,
		0xEDD6046A4B6A4178ULL,
		0x262333236EBA7B6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFCB2A21F9A011000ULL,
		0xDD9A9EB3F9207DA9ULL,
		0xB023525B520BC401ULL,
		0x19991B75D3DB776EULL,
		0x0000000000000131ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x511BF263CACEA9B6ULL,
		0x9C97961930885A23ULL,
		0xCC28AC530813354FULL,
		0x4E93578F5110EA08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BF263CACEA9B600ULL,
		0x97961930885A2351ULL,
		0x28AC530813354F9CULL,
		0x93578F5110EA08CCULL,
		0x000000000000004EULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5B727AC500969C96ULL,
		0x4265C4EA0418BF9FULL,
		0x2ECDC4B9B172D198ULL,
		0x7E95F93D999A2E40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4B4E4B0000000000ULL,
		0x0C5FCFADB93D6280ULL,
		0xB968CC2132E27502ULL,
		0xCD17201766E25CD8ULL,
		0x0000003F4AFC9ECCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9E74EB92E1069804ULL,
		0x7FEC5F7460822C05ULL,
		0x9A24A8DE1D3019D3ULL,
		0x28B8D0E33485CC3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC20D300800000000ULL,
		0xC104580B3CE9D725ULL,
		0x3A6033A6FFD8BEE8ULL,
		0x690B9875344951BCULL,
		0x000000005171A1C6ULL
	}};
	shift = 225;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x260EAADC0B234390ULL,
		0xC73ED9C761F5F904ULL,
		0x2944E9F5FE192E2EULL,
		0x792DACBAF109466BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C80000000000000ULL,
		0xC821307556E0591AULL,
		0x717639F6CE3B0FAFULL,
		0x33594A274FAFF0C9ULL,
		0x0003C96D65D7884AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB56E9AA2ACB81C25ULL,
		0xA4E4C149BAF4B0FEULL,
		0x670AFCBD4F38C580ULL,
		0x2F18A34D7E4A628EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x565C0E1280000000ULL,
		0xDD7A587F5AB74D51ULL,
		0xA79C62C0527260A4ULL,
		0xBF25314733857E5EULL,
		0x00000000178C51A6ULL
	}};
	shift = 223;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCB8FCF2CBAFF4FDBULL,
		0xB8A490311D23C514ULL,
		0x8C1444ED71FD28D7ULL,
		0x447F515AC87D32E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA7ED80000000000ULL,
		0x1E28A65C7E7965D7ULL,
		0xE946BDC5248188E9ULL,
		0xE9972460A2276B8FULL,
		0x00000223FA8AD643ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5FBB8EF1E8157A63ULL,
		0x08C5EF4362C9C98DULL,
		0x0A407932766B1627ULL,
		0x3F75789A61813584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD31800000000000ULL,
		0xE4C6AFDDC778F40AULL,
		0x8B138462F7A1B164ULL,
		0x9AC205203C993B35ULL,
		0x00001FBABC4D30C0ULL
	}};
	shift = 239;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDB358D14AA699129ULL,
		0xC8600FB630E61B52ULL,
		0xE8F6FB3F9952E0FFULL,
		0x7D68273E8DC1030AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9AC68A5534C89480ULL,
		0x3007DB18730DA96DULL,
		0x7B7D9FCCA9707FE4ULL,
		0xB4139F46E0818574ULL,
		0x000000000000003EULL
	}};
	shift = 199;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x78FF1D46E58658A1ULL,
		0x55011E520EDBBB9FULL,
		0xB5F5E758C813952BULL,
		0x51F2C068ED3CE24FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC508000000000000ULL,
		0xDCFBC7F8EA372C32ULL,
		0xA95AA808F29076DDULL,
		0x127DAFAF3AC6409CULL,
		0x00028F96034769E7ULL
	}};
	shift = 243;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBCC2C26073DD87E1ULL,
		0x9698D6560AB5E0B0ULL,
		0xAE52DC6A7E0058C1ULL,
		0x60B25E393FFF301BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0981CF761F840000ULL,
		0x59582AD782C2F30BULL,
		0x71A9F80163065A63ULL,
		0x78E4FFFCC06EB94BULL,
		0x00000000000182C9ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCACD4939CBFD251AULL,
		0xE5D120D2B029015AULL,
		0x52A44A9729D9F8B7ULL,
		0x45A6449AB10AD866ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A00000000000000ULL,
		0x5ACACD4939CBFD25ULL,
		0xB7E5D120D2B02901ULL,
		0x6652A44A9729D9F8ULL,
		0x0045A6449AB10AD8ULL
	}};
	shift = 248;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD9E72DF8EE47A087ULL,
		0xCDE8C56FF9B16951ULL,
		0x3828F62BD72B1A1AULL,
		0x7446CC71FEDFB8A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91E821C00000000ULL,
		0xE6C5A547679CB7E3ULL,
		0x5CAC686B37A315BFULL,
		0xFB7EE284E0A3D8AFULL,
		0x00000001D11B31C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2D0B1A6417D5DC33ULL,
		0xCCEF44B1F0462C63ULL,
		0xB2A602BF3E85E073ULL,
		0x6FB6E36BA4B3E6BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF5770CC000000000ULL,
		0x118B18CB42C69905ULL,
		0xA1781CF33BD12C7CULL,
		0x2CF9AFACA980AFCFULL,
		0x0000001BEDB8DAE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2BA7743B25449818ULL,
		0xF297F30C66285A8BULL,
		0xFDAF22E1BD306F1CULL,
		0x2E1A8D200B0CB675ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x743B254498180000ULL,
		0xF30C66285A8B2BA7ULL,
		0x22E1BD306F1CF297ULL,
		0x8D200B0CB675FDAFULL,
		0x0000000000002E1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x02BA43A4F2B54A6BULL,
		0x799C2D5BD7DEB6E9ULL,
		0xEFCEB7B73510B20AULL,
		0x3F008BC7E863C52BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D2795AA53580000ULL,
		0x6ADEBEF5B74815D2ULL,
		0xBDB9A8859053CCE1ULL,
		0x5E3F431E295F7E75ULL,
		0x000000000001F804ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC32392D5D8986E9FULL,
		0x86662A9387A3AE87ULL,
		0x9513B096457BA82CULL,
		0x350B2CB899AC6181ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x374F800000000000ULL,
		0xD743E191C96AEC4CULL,
		0xD41643331549C3D1ULL,
		0x30C0CA89D84B22BDULL,
		0x00001A85965C4CD6ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x775268F31F8DEE5FULL,
		0xA05FCA05C9169E99ULL,
		0x1E522E6AC84ECDBEULL,
		0x5340CB8792869C4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C00000000000000ULL,
		0x65DD49A3CC7E37B9ULL,
		0xFA817F2817245A7AULL,
		0x2C7948B9AB213B36ULL,
		0x014D032E1E4A1A71ULL
	}};
	shift = 250;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDD64DBC3213CC882ULL,
		0x7E34923C377EDBE5ULL,
		0x22E13A29B2532F41ULL,
		0x085D91D0FC9745BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13CC882000000000ULL,
		0x77EDBE5DD64DBC32ULL,
		0x2532F417E34923C3ULL,
		0xC9745BE22E13A29BULL,
		0x0000000085D91D0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x87E83F34675D063AULL,
		0xEE203650BEC79B94ULL,
		0x854917E9CD5C6876ULL,
		0x0AA1949050E0C9A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E80000000000000ULL,
		0xE521FA0FCD19D741ULL,
		0x1DBB880D942FB1E6ULL,
		0x69E15245FA73571AULL,
		0x0002A86524143832ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD6EC79EF98090D1FULL,
		0x3B8C9E34A31DD552ULL,
		0xDB9C240D754EE77CULL,
		0x75C3C4A22AD7844BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x763CF7CC04868F80ULL,
		0xC64F1A518EEAA96BULL,
		0xCE1206BAA773BE1DULL,
		0xE1E251156BC225EDULL,
		0x000000000000003AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA36DA1BD98FE58BDULL,
		0x80B1D6D36DAABC3EULL,
		0xB6B1453E166F0D3AULL,
		0x0C6ECC822A859983ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1FCB17A000000000ULL,
		0xB55787D46DB437B3ULL,
		0xCDE1A750163ADA6DULL,
		0x50B33076D628A7C2ULL,
		0x000000018DD99045ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3DD2A0471BDAC50DULL,
		0xB39F5B28B1313179ULL,
		0xD1BD4C02522694CDULL,
		0x2B2FCC6DAA1D138AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC50D000000000000ULL,
		0x31793DD2A0471BDAULL,
		0x94CDB39F5B28B131ULL,
		0x138AD1BD4C025226ULL,
		0x00002B2FCC6DAA1DULL
	}};
	shift = 240;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD5F351E0E929C1E5ULL,
		0x94CBE2ECDB72CD9DULL,
		0xE03B0D379277F2D5ULL,
		0x4CC1F1BE9702265BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE0E929C1E5000000ULL,
		0xECDB72CD9DD5F351ULL,
		0x379277F2D594CBE2ULL,
		0xBE9702265BE03B0DULL,
		0x00000000004CC1F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3AFD267E84D79A67ULL,
		0xB8841F1F28312D85ULL,
		0xFFAEA159343C8093ULL,
		0x6B1BBD92F65C00F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD7E933F426BCD338ULL,
		0xC420F8F941896C29ULL,
		0xFD750AC9A1E4049DULL,
		0x58DDEC97B2E007BFULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x48E0ED69AC8D61FAULL,
		0x2775F0516D3D9998ULL,
		0x1EEFC34D744298D4ULL,
		0x59999AC27DC0CF15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE0ED69AC8D61FA00ULL,
		0x75F0516D3D999848ULL,
		0xEFC34D744298D427ULL,
		0x999AC27DC0CF151EULL,
		0x0000000000000059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFF0B66C6A0E78ACDULL,
		0xB56535118F454D9BULL,
		0xBB463D8FC9A65B12ULL,
		0x6C5EB143C66F8C31ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9E2B340000000000ULL,
		0x15366FFC2D9B1A83ULL,
		0x996C4AD594D4463DULL,
		0xBE30C6ED18F63F26ULL,
		0x000001B17AC50F19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6D2DD49F78FA7BA7ULL,
		0xADBBA9842584B218ULL,
		0x435DC764F3A234B8ULL,
		0x4DA886A6E23768F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x0DA5BA93EF1F4F74ULL,
		0x15B7753084B09643ULL,
		0x086BB8EC9E744697ULL,
		0x09B510D4DC46ED1FULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5F95FA16BD8112C4ULL,
		0x8497469057A5070AULL,
		0x382D6C7EDAB523F1ULL,
		0x6B12A70C15D2BD5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B5EC08962000000ULL,
		0x482BD283852FCAFDULL,
		0x3F6D5A91F8C24BA3ULL,
		0x860AE95EAD1C16B6ULL,
		0x0000000000358953ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4942080EF2F7CD8DULL,
		0x05762B474A9B82A8ULL,
		0x5A8C336C7EEAAC4EULL,
		0x30EEF5DD3DAA6375ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08203BCBDF363400ULL,
		0xD8AD1D2A6E0AA125ULL,
		0x30CDB1FBAAB13815ULL,
		0xBBD774F6A98DD56AULL,
		0x00000000000000C3ULL
	}};
	shift = 202;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9F5EC83C458D118CULL,
		0x7E85A5BC3D32015DULL,
		0xB2C0B3C2AD557C57ULL,
		0x3FA4E9E389504E57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4463000000000000ULL,
		0x805767D7B20F1163ULL,
		0x5F15DFA1696F0F4CULL,
		0x1395ECB02CF0AB55ULL,
		0x00000FE93A78E254ULL
	}};
	shift = 238;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x98EC86E13EE7B920ULL,
		0x5006BC33A8EE85F4ULL,
		0x5B9C1BB8B4E31EA4ULL,
		0x7175D8A442F51EB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC27DCF724000000ULL,
		0x86751DD0BE931D90ULL,
		0x77169C63D48A00D7ULL,
		0x14885EA3D68B7383ULL,
		0x00000000000E2EBBULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE8A4A40D196B638EULL,
		0x365BCE1E140499C8ULL,
		0xBEA7824B6B0CDF94ULL,
		0x5A06F6A9BC318ACFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x903465AD8E380000ULL,
		0x387850126723A292ULL,
		0x092DAC337E50D96FULL,
		0xDAA6F0C62B3EFA9EULL,
		0x000000000001681BULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x35C6B7B28B4D4343ULL,
		0x77CA8F53222DD703ULL,
		0xBC6D9159DDF0E5ADULL,
		0x78E1952E517CF114ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADECA2D350D0C00ULL,
		0x2A3D4C88B75C0CD7ULL,
		0xB6456777C396B5DFULL,
		0x8654B945F3C452F1ULL,
		0x00000000000001E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDA4A3FE3F9F79F63ULL,
		0x681B42F85FACFAA6ULL,
		0x390E7036EF20EB12ULL,
		0x468E022C8BFC5B84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6300000000000000ULL,
		0xA6DA4A3FE3F9F79FULL,
		0x12681B42F85FACFAULL,
		0x84390E7036EF20EBULL,
		0x00468E022C8BFC5BULL
	}};
	shift = 248;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDB77DF2C29AB3496ULL,
		0xD4D1F2E2D079F859ULL,
		0xB2EE87B79FD8180EULL,
		0x3B325F1BCD2B9B3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29AB349600000000ULL,
		0xD079F859DB77DF2CULL,
		0x9FD8180ED4D1F2E2ULL,
		0xCD2B9B3FB2EE87B7ULL,
		0x000000003B325F1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBE9ECA88AB1E16ECULL,
		0x169C0711EABBBDCFULL,
		0x07FC0430F83137BEULL,
		0x5F251E01F19B5C6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x7DF4F6544558F0B7ULL,
		0xF0B4E0388F55DDEEULL,
		0x603FE02187C189BDULL,
		0x02F928F00F8CDAE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBBE703AB3A0E13A2ULL,
		0xF8EB0A0F5BE354A1ULL,
		0xFA2C1C4EDF22DC06ULL,
		0x71F99EFE7A74CE5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77CE0756741C2744ULL,
		0xF1D6141EB7C6A943ULL,
		0xF458389DBE45B80DULL,
		0xE3F33DFCF4E99CB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF0B15A6DD448CE50ULL,
		0xDE5B02BA115B653FULL,
		0x41B824AA859A117FULL,
		0x2163287F8EFF1468ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62B4DBA8919CA000ULL,
		0xB6057422B6CA7FE1ULL,
		0x7049550B3422FFBCULL,
		0xC650FF1DFE28D083ULL,
		0x0000000000000042ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0DF2BAF83853A47DULL,
		0x5A848A3DA1EF08EEULL,
		0xFF6A600E2B84DC13ULL,
		0x1AB0CDAAE19F1E41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0E14E91F40000000ULL,
		0x687BC23B837CAEBEULL,
		0x8AE13704D6A1228FULL,
		0xB867C7907FDA9803ULL,
		0x0000000006AC336AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0A6E86F7B1BEE9C0ULL,
		0x9657148D691F08EDULL,
		0x5F4CD7D201A303BCULL,
		0x47B945FD10923A8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDEC6FBA700000000ULL,
		0x35A47C23B429BA1BULL,
		0x48068C0EF2595C52ULL,
		0xF44248EA297D335FULL,
		0x00000000011EE517ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE1E5789B60B3EEB1ULL,
		0x3CD388B257E78BD5ULL,
		0xCF1B786FD7307932ULL,
		0x4DEC3372620A6CBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF136C167DD620000ULL,
		0x1164AFCF17ABC3CAULL,
		0xF0DFAE60F26479A7ULL,
		0x66E4C414D97B9E36ULL,
		0x0000000000009BD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4F89D4890451A9B2ULL,
		0x268B380CB7F4FB7FULL,
		0x1BA1EC4ACE961396ULL,
		0x77F0A084588D71C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3536400000000000ULL,
		0x9F6FE9F13A91208AULL,
		0xC272C4D1670196FEULL,
		0xAE3803743D8959D2ULL,
		0x00000EFE14108B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x96A1D1FB1BCABF87ULL,
		0x60978F50318BF883ULL,
		0x1C18CD92A5548541ULL,
		0x62B87C61ECA8194EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x637957F0E0000000ULL,
		0x06317F1072D43A3FULL,
		0x54AA90A82C12F1EAULL,
		0x3D950329C38319B2ULL,
		0x000000000C570F8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x947630827DB6010DULL,
		0x844BE6FF5162BF95ULL,
		0xFC6C55F8F5E712E8ULL,
		0x5F9586131558D34AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B18413EDB008680ULL,
		0x25F37FA8B15FCACAULL,
		0x362AFC7AF3897442ULL,
		0xCAC3098AAC69A57EULL,
		0x000000000000002FULL
	}};
	shift = 199;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x52CC67F35C1A64B2ULL,
		0x61BD237A63AA300FULL,
		0x5E7B4AC2B6AAF90CULL,
		0x70E405E5FB3DE7C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B20000000000000ULL,
		0x00F52CC67F35C1A6ULL,
		0x90C61BD237A63AA3ULL,
		0x7C15E7B4AC2B6AAFULL,
		0x00070E405E5FB3DEULL
	}};
	shift = 244;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x576A4722BAE24835ULL,
		0xA7C9A01544E90ABAULL,
		0x7C695182678643ECULL,
		0x507A4B9831B28A34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAEB8920D40000000ULL,
		0x513A42AE95DA91C8ULL,
		0x99E190FB29F26805ULL,
		0x0C6CA28D1F1A5460ULL,
		0x00000000141E92E6ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD12D40EC299B2AC0ULL,
		0x586B467C35E32EFFULL,
		0xC71004EDC5070428ULL,
		0x22C83677C383760EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB00000000000000ULL,
		0xBBFF44B503B0A66CULL,
		0x10A161AD19F0D78CULL,
		0xD83B1C4013B7141CULL,
		0x00008B20D9DF0E0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x77DC64130412B866ULL,
		0xB9EFC5EE36509E9CULL,
		0x0331F7B2D5DB2F96ULL,
		0x4D521083AE174C57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x826082570CC00000ULL,
		0xBDC6CA13D38EFB8CULL,
		0xF65ABB65F2D73DF8ULL,
		0x1075C2E98AE0663EULL,
		0x000000000009AA42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDE70DE0608928D23ULL,
		0x8F532F93C880E735ULL,
		0xE1391940E2BA4AA3ULL,
		0x357A7E75B041A082ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8928D23000000000ULL,
		0x880E735DE70DE060ULL,
		0x2BA4AA38F532F93CULL,
		0x041A082E1391940EULL,
		0x0000000357A7E75BULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE9207EAA3043484FULL,
		0x478CBF8E1ECF50BFULL,
		0x1503C4E647806546ULL,
		0x3FF6CF895766CD35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA8C10D213C00000ULL,
		0xE387B3D42FFA481FULL,
		0x3991E0195191E32FULL,
		0xE255D9B34D4540F1ULL,
		0x00000000000FFDB3ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x29902DF72935C756ULL,
		0xD416B6EF9126C805ULL,
		0x49ECA398B956341DULL,
		0x6FBDBAF2FBE442BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7DCA4D71D5800000ULL,
		0xBBE449B2014A640BULL,
		0xE62E558D077505ADULL,
		0xBCBEF910AF927B28ULL,
		0x00000000001BEF6EULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC57261E554DF7EFFULL,
		0x308A1DC6E99AC2B2ULL,
		0x3FC9BF2BD0CA160CULL,
		0x74F121EE07981D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800000000000000ULL,
		0x962B930F2AA6FBF7ULL,
		0x618450EE374CD615ULL,
		0x71FE4DF95E8650B0ULL,
		0x03A7890F703CC0ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x18709E5590910E0FULL,
		0x2739427AA9799E51ULL,
		0x1FB2E0653D74ECC7ULL,
		0x4FDDA52139169460ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7078000000000000ULL,
		0xF288C384F2AC8488ULL,
		0x663939CA13D54BCCULL,
		0xA300FD970329EBA7ULL,
		0x00027EED2909C8B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCD78360A50DCE609ULL,
		0x8F08498E321AC66AULL,
		0xAD95A4AD4373065DULL,
		0x3F54D07C3205111DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0D82943739824000ULL,
		0x12638C86B19AB35EULL,
		0x692B50DCC19763C2ULL,
		0x341F0C8144476B65ULL,
		0x0000000000000FD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x27916673F470A42FULL,
		0xFC3F92A7EF083101ULL,
		0xFE21C53A06EEC4CCULL,
		0x5ACC1D35486DCCC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4599CFD1C290BC0ULL,
		0x0FE4A9FBC20C4049ULL,
		0x88714E81BBB1333FULL,
		0xB3074D521B73303FULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAC739F14F07C1BFAULL,
		0x0896D9D42A3BC03EULL,
		0x4F59E51EECA89D86ULL,
		0x45F2B62838F5C53EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE73E29E0F837F400ULL,
		0x2DB3A85477807D58ULL,
		0xB3CA3DD9513B0C11ULL,
		0xE56C5071EB8A7C9EULL,
		0x000000000000008BULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5F676E0CAC4D6707ULL,
		0x7C650808694915E2ULL,
		0x4A4008DC1C9154A1ULL,
		0x466A4E5B59E6010EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7065626B38380000ULL,
		0x40434A48AF12FB3BULL,
		0x46E0E48AA50BE328ULL,
		0x72DACF3008725200ULL,
		0x0000000000023352ULL
	}};
	shift = 211;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x96BA37EA2AC05F26ULL,
		0xEC931CBA03D920E2ULL,
		0xED9D16F2EC38D731ULL,
		0x054BCF1A7BDDD0A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8DFA8AB017C9800ULL,
		0x4C72E80F64838A5AULL,
		0x745BCBB0E35CC7B2ULL,
		0x2F3C69EF77429FB6ULL,
		0x0000000000000015ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB394A995E2E6383CULL,
		0x91E56F9D9D2A714CULL,
		0x6EDD09B89C569715ULL,
		0x795ECEBDF741E6C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7800000000000000ULL,
		0x996729532BC5CC70ULL,
		0x2B23CADF3B3A54E2ULL,
		0x92DDBA137138AD2EULL,
		0x00F2BD9D7BEE83CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x62BC7B3EF9ADCBE1ULL,
		0x878D4E4D36353F29ULL,
		0x83CBB83EC702D6F9ULL,
		0x574D514261765E3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B72F8400000000ULL,
		0xD8D4FCA58AF1ECFBULL,
		0x1C0B5BE61E353934ULL,
		0x85D978FA0F2EE0FBULL,
		0x000000015D354509ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x663FA9D2265B53F3ULL,
		0x363E3E257F8899A1ULL,
		0xC70306656D59535BULL,
		0x26ADDF9F010A92B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDA9F980000000000ULL,
		0x44CD0B31FD4E9132ULL,
		0xCA9AD9B1F1F12BFCULL,
		0x54958E3818332B6AULL,
		0x000001356EFCF808ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3193C5E7B5F19B0FULL,
		0xE5C5020039F01CE9ULL,
		0xC85CC98F33386B2AULL,
		0x26BF4C15D939251DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E7B5F19B0F00000ULL,
		0x20039F01CE93193CULL,
		0x98F33386B2AE5C50ULL,
		0xC15D939251DC85CCULL,
		0x0000000000026BF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE05EC7BDE914F0ABULL,
		0x801D4AAE7C34E4DDULL,
		0xAAF9777F810C7106ULL,
		0x177478F2C387E960ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48A7855800000000ULL,
		0xE1A726EF02F63DEFULL,
		0x0863883400EA5573ULL,
		0x1C3F4B0557CBBBFCULL,
		0x00000000BBA3C796ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAB9C175E2641E937ULL,
		0xA899E757B01E6E88ULL,
		0xE90C208D21C9F3FFULL,
		0x709DA2E21FF1E54AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x175E2641E9370000ULL,
		0xE757B01E6E88AB9CULL,
		0x208D21C9F3FFA899ULL,
		0xA2E21FF1E54AE90CULL,
		0x000000000000709DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7CD80D35E064CE8FULL,
		0xAA5C3B10E793695FULL,
		0xE0C0CEFA4416AEEEULL,
		0x164CE5E00A0C328AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE8F000000000000ULL,
		0x695F7CD80D35E064ULL,
		0xAEEEAA5C3B10E793ULL,
		0x328AE0C0CEFA4416ULL,
		0x0000164CE5E00A0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE9A020C7817F5167ULL,
		0xFE267F43F9DC4A61ULL,
		0xE71B73C9105901EDULL,
		0x04647FC8CF080D98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A020C7817F51670ULL,
		0xE267F43F9DC4A61EULL,
		0x71B73C9105901EDFULL,
		0x4647FC8CF080D98EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF85A9E3BD8591946ULL,
		0x809DF34ACAC3825CULL,
		0xF88AE095BA4E1DD2ULL,
		0x6BF12154ECB2DD33ULL,
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
		0x9F0B53C77B0B2328ULL,
		0x5013BE695958704BULL,
		0x7F115C12B749C3BAULL,
		0x0D7E242A9D965BA6ULL
	}};
	shift = 253;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3D5B4C2C65865559ULL,
		0x76061BD264268C10ULL,
		0xE9798B68A7E4DE0DULL,
		0x606EF44A1F254ED7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C2C658655590000ULL,
		0x1BD264268C103D5BULL,
		0x8B68A7E4DE0D7606ULL,
		0xF44A1F254ED7E979ULL,
		0x000000000000606EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB90DBCED4EEE5970ULL,
		0xC2EA044C25FF6F89ULL,
		0x8F17128C24967B53ULL,
		0x08DD5F792AF9D6CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED4EEE5970000000ULL,
		0x4C25FF6F89B90DBCULL,
		0x8C24967B53C2EA04ULL,
		0x792AF9D6CE8F1712ULL,
		0x000000000008DD5FULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2797E532931194B2ULL,
		0xCE15D0C9DC0A8217ULL,
		0x7C86FD409DB7E6A4ULL,
		0x4FCBAAB0BBE57FB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x994988CA59000000ULL,
		0x64EE05410B93CBF2ULL,
		0xA04EDBF352670AE8ULL,
		0x585DF2BFD9BE437EULL,
		0x000000000027E5D5ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x16DADBD8F1B8CE88ULL,
		0x6A00DB06E4D93392ULL,
		0x4A6B3A73F38C40D0ULL,
		0x28F1B91A6C1B365CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5B7B1E3719D1000ULL,
		0x01B60DC9B267242DULL,
		0xD674E7E71881A0D4ULL,
		0xE37234D8366CB894ULL,
		0x0000000000000051ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD4FF53753FC2C3A4ULL,
		0x52536A48BB2778C2ULL,
		0x71EFDBA2BA1FDC88ULL,
		0x395913ECD4BDDE78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53FC2C3A40000000ULL,
		0x8BB2778C2D4FF537ULL,
		0x2BA1FDC8852536A4ULL,
		0xCD4BDDE7871EFDBAULL,
		0x000000000395913EULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE60A3E0CC2DD5F9EULL,
		0x05AB4C04315A391FULL,
		0xA05EAC065D08C175ULL,
		0x0534D24CDBCD24B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9828F8330B757E78ULL,
		0x16AD3010C568E47FULL,
		0x817AB019742305D4ULL,
		0x14D349336F3492DEULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD2E32C624FC45016ULL,
		0x1943311AE49F65ADULL,
		0x1306AEF412174BC4ULL,
		0x796919A5B198513FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3127E2280B000000ULL,
		0x8D724FB2D6E97196ULL,
		0x7A090BA5E20CA198ULL,
		0xD2D8CC289F898357ULL,
		0x00000000003CB48CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC12486A1606643CCULL,
		0xBDD71A8944D3FBC2ULL,
		0x8B0284E3BCE7A924ULL,
		0x15F0924EE469FF4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9800000000000000ULL,
		0x8582490D42C0CC87ULL,
		0x497BAE351289A7F7ULL,
		0x9F160509C779CF52ULL,
		0x002BE1249DC8D3FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1AEFC334498E9B76ULL,
		0xD549CB66D99C940DULL,
		0x604DB3EC8B7DC675ULL,
		0x5BDB2732E684B40BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0CD1263A6DD8000ULL,
		0x72D9B667250346BBULL,
		0x6CFB22DF719D7552ULL,
		0xC9CCB9A12D02D813ULL,
		0x00000000000016F6ULL
	}};
	shift = 206;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCE1936332EE2A594ULL,
		0x58A3D74FDCD4771BULL,
		0xA964F9167C49C84AULL,
		0x3D447A8A7E965EF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9B19977152CA000ULL,
		0x1EBA7EE6A3B8DE70ULL,
		0x27C8B3E24E4252C5ULL,
		0x23D453F4B2F7C54BULL,
		0x00000000000001EAULL
	}};
	shift = 203;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD80A40F3DA51D53DULL,
		0xD1CCF4E7F0379C2EULL,
		0x10CC0EDE5B850A01ULL,
		0x72E361859979B7B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x079ED28EA9E80000ULL,
		0xA73F81BCE176C052ULL,
		0x76F2DC28500E8E67ULL,
		0x0C2CCBCDBDB08660ULL,
		0x000000000003971BULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEF8D0B082B054E83ULL,
		0xC25A11776D0421CDULL,
		0xC6F3F444D99535D1ULL,
		0x0A54118E9444F9D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9D0600000000000ULL,
		0x8439BDF1A1610560ULL,
		0xA6BA384B422EEDA0ULL,
		0x9F3B18DE7E889B32ULL,
		0x0000014A8231D288ULL
	}};
	shift = 237;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1E097B06A6F683ACULL,
		0xBA348772BB146D84ULL,
		0xEBC456B026B04628ULL,
		0x74E8F1E74020477FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04BD83537B41D600ULL,
		0x1A43B95D8A36C20FULL,
		0xE22B58135823145DULL,
		0x7478F3A01023BFF5ULL,
		0x000000000000003AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1BCDFF5240DB7680ULL,
		0xFB93EDDDB59B052DULL,
		0x8CFA946082FC3B92ULL,
		0x148D596D7E93573AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6ED000000000000ULL,
		0x360A5A379BFEA481ULL,
		0xF87725F727DBBB6BULL,
		0x26AE7519F528C105ULL,
		0x000000291AB2DAFDULL
	}};
	shift = 233;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x20AAA3CC67110E33ULL,
		0xA819FE8F647031BCULL,
		0x6F7AA507DAD3342AULL,
		0x24A2F8C4841CBEECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE221C6600000000ULL,
		0xC8E0637841554798ULL,
		0xB5A668555033FD1EULL,
		0x08397DD8DEF54A0FULL,
		0x000000004945F189ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEF0063BBBF062459ULL,
		0xA3C171186486287AULL,
		0x7E065A12F2F46C71ULL,
		0x0AF3DF8CE9C6B82DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3122C80000000000ULL,
		0x3143D778031DDDF8ULL,
		0xA3638D1E0B88C324ULL,
		0x35C16BF032D09797ULL,
		0x000000579EFC674EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5597EE421E616A6FULL,
		0xAC1783C2D0FE515BULL,
		0x49A689A573351073ULL,
		0x0214838E1F8B7D3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC2D4DE000000000ULL,
		0x1FCA2B6AB2FDC843ULL,
		0x66A20E7582F0785AULL,
		0xF16FA7C934D134AEULL,
		0x00000000429071C3ULL
	}};
	shift = 229;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA65F70E29A64046FULL,
		0x0C821D0C5F55D91FULL,
		0x53E57E06CC73349EULL,
		0x679D96DFB5BB593AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8DE0000000000000ULL,
		0x23F4CBEE1C534C80ULL,
		0x93C19043A18BEABBULL,
		0x274A7CAFC0D98E66ULL,
		0x000CF3B2DBF6B76BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6D47868657B6E14EULL,
		0x9A0A39052BBB22C3ULL,
		0x93D1552ECF65E681ULL,
		0x7E352A60EEBF2DA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51E1A195EDB8538ULL,
		0x6828E414AEEC8B0DULL,
		0x4F4554BB3D979A06ULL,
		0xF8D4A983BAFCB692ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x874A359F31C5E2D9ULL,
		0x57C7572B8A56C830ULL,
		0x0F1526A1BD1AEA12ULL,
		0x245FD3258D2D9F65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F31C5E2D900000ULL,
		0x72B8A56C830874A3ULL,
		0x6A1BD1AEA1257C75ULL,
		0x3258D2D9F650F152ULL,
		0x00000000000245FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0944657C47AD36BBULL,
		0xB8B9FDDEE3AB11A1ULL,
		0x0B0930F02EFB7AC7ULL,
		0x48A8B4C21A486B4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCAF88F5A6D760000ULL,
		0xFBBDC75623421288ULL,
		0x61E05DF6F58F7173ULL,
		0x69843490D6961612ULL,
		0x0000000000009151ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF9B481B7D711B15EULL,
		0xE946B3084F0ED99FULL,
		0x3027D923D73604E7ULL,
		0x6D0001516F073917ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x711B15E000000000ULL,
		0xF0ED99FF9B481B7DULL,
		0x73604E7E946B3084ULL,
		0xF0739173027D923DULL,
		0x00000006D0001516ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8D78430344A6F2B0ULL,
		0xEF0FFCFA3B621D20ULL,
		0x839970B458445C26ULL,
		0x7BBC8A1C88CE3194ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08606894DE560000ULL,
		0xFF9F476C43A411AFULL,
		0x2E168B088B84DDE1ULL,
		0x91439119C6329073ULL,
		0x0000000000000F77ULL
	}};
	shift = 205;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2D6FF1EB762ABFC6ULL,
		0x373A7DE88958B66CULL,
		0x9930532CEB3193F0ULL,
		0x6B897AE0227792BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x155FE30000000000ULL,
		0xAC5B3616B7F8F5BBULL,
		0x98C9F81B9D3EF444ULL,
		0x3BC95ECC98299675ULL,
		0x00000035C4BD7011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xECE28A349DE3650BULL,
		0x2D29C6B574B1FC37ULL,
		0xB9C71FFC981045D4ULL,
		0x57E52A62B84DF13AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8A28D2778D942C00ULL,
		0xA71AD5D2C7F0DFB3ULL,
		0x1C7FF260411750B4ULL,
		0x94A98AE137C4EAE7ULL,
		0x000000000000015FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE4FF8AB4244870D9ULL,
		0x7CABF848A937CE47ULL,
		0x9B0DD3D59003CEB0ULL,
		0x5F551DF3BFC1EA8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84890E1B20000000ULL,
		0x1526F9C8FC9FF156ULL,
		0xB20079D60F957F09ULL,
		0x77F83D51B361BA7AULL,
		0x000000000BEAA3BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8277EDE8EEFF9E00ULL,
		0x43A5922AA863D187ULL,
		0x8E035E4B8A7A11E3ULL,
		0x2E632A03B6157E05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x277EDE8EEFF9E000ULL,
		0x3A5922AA863D1878ULL,
		0xE035E4B8A7A11E34ULL,
		0xE632A03B6157E058ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x53D70620E7080A06ULL,
		0xC9DB4779C823666EULL,
		0xC1F5E1ACAD87CBBEULL,
		0x6FC35600DCBC22C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7384050300000000ULL,
		0xE411B33729EB8310ULL,
		0x56C3E5DF64EDA3BCULL,
		0x6E5E1160E0FAF0D6ULL,
		0x0000000037E1AB00ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF689E5E7CF3A339CULL,
		0xDD21A27C980ADD75ULL,
		0x8AC68A2E0F3AE437ULL,
		0x11CFD8D6A5BDC25DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2F3E79D19CE0000ULL,
		0xD13E4C056EBAFB44ULL,
		0x4517079D721BEE90ULL,
		0xEC6B52DEE12EC563ULL,
		0x00000000000008E7ULL
	}};
	shift = 207;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x86C4679DA6A9799EULL,
		0x9255A4089305AD43ULL,
		0x6C17866033EAA499ULL,
		0x018A1AD4B6CFC537ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6233CED354BCCF00ULL,
		0x2AD2044982D6A1C3ULL,
		0x0BC33019F5524CC9ULL,
		0xC50D6A5B67E29BB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEADF89250DBD01C0ULL,
		0xB29BE74D5FF22164ULL,
		0x85FDE1710D1887D0ULL,
		0x715DB9C9C735533CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xC9D5BF124A1B7A03ULL,
		0xA16537CE9ABFE442ULL,
		0x790BFBC2E21A310FULL,
		0x00E2BB73938E6AA6ULL
	}};
	shift = 249;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E1BEDD539741B6DULL,
		0x7CF819A8E542DDD8ULL,
		0x7CF1E60127ED6691ULL,
		0x04B840256DB92EBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDD539741B6D0000ULL,
		0x19A8E542DDD85E1BULL,
		0xE60127ED66917CF8ULL,
		0x40256DB92EBF7CF1ULL,
		0x00000000000004B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x633CD58E3C2DF70EULL,
		0x2B6D22B936EF4B4AULL,
		0x3769C5F7F63314FFULL,
		0x73D7EF3E6DBBBEDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB870000000000000ULL,
		0x5A5319E6AC71E16FULL,
		0xA7F95B6915C9B77AULL,
		0xF6E9BB4E2FBFB198ULL,
		0x00039EBF79F36DDDULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4BFF8C85EA5DE103ULL,
		0x2D99A0BC17FAE59EULL,
		0xEE41BEDEFB9CA0B7ULL,
		0x56239D9620770366ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190BD4BBC2060000ULL,
		0x41782FF5CB3C97FFULL,
		0x7DBDF739416E5B33ULL,
		0x3B2C40EE06CDDC83ULL,
		0x000000000000AC47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4B623AFC71EC526BULL,
		0x2A758F251D66254EULL,
		0x3675833140F6FA23ULL,
		0x33766FD1739A0EE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EBF1C7B149AC00ULL,
		0xD63C94759895392DULL,
		0xD60CC503DBE88CA9ULL,
		0xD9BF45CE683B98D9ULL,
		0x00000000000000CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2D438A87E3A17CB1ULL,
		0x3CE77266379CA0D1ULL,
		0xE01B214D9C2863D1ULL,
		0x28EAB2F6A16BBA20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF962000000000000ULL,
		0x41A25A87150FC742ULL,
		0xC7A279CEE4CC6F39ULL,
		0x7441C036429B3850ULL,
		0x000051D565ED42D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x51339055E5DABE7EULL,
		0x9F3074F28A376160ULL,
		0x118C1470734F467FULL,
		0x75D4E8A36B9C5E1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CFC000000000000ULL,
		0xC2C0A26720ABCBB5ULL,
		0x8CFF3E60E9E5146EULL,
		0xBC34231828E0E69EULL,
		0x0000EBA9D146D738ULL
	}};
	shift = 241;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA7BC554F1AB02E18ULL,
		0x0577E623905521B8ULL,
		0x40EC38739A247B0DULL,
		0x0E03721ED1421279ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE35605C300000000ULL,
		0x720AA43714F78AA9ULL,
		0x73448F61A0AEFCC4ULL,
		0xDA28424F281D870EULL,
		0x0000000001C06E43ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF32F66EC48EFEB41ULL,
		0xD2BCB3C18B2E6061ULL,
		0xA3E5AB901BCB90ABULL,
		0x21D1DE1237A9E85BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA080000000000000ULL,
		0x30F997B3762477F5ULL,
		0x55E95E59E0C59730ULL,
		0x2DD1F2D5C80DE5C8ULL,
		0x0010E8EF091BD4F4ULL
	}};
	shift = 247;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7A8E8586E6527BC1ULL,
		0xB120FCFD30D1FD7DULL,
		0x198256299DDC4CC4ULL,
		0x796B856CD6777C30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61B9949EF0400000ULL,
		0x3F4C347F5F5EA3A1ULL,
		0x8A677713312C483FULL,
		0x5B359DDF0C066095ULL,
		0x00000000001E5AE1ULL
	}};
	shift = 214;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8F962DE044F413F5ULL,
		0x3F3CB622493F51A6ULL,
		0x259B5689AA28A30EULL,
		0x41AE733777AD31DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x413F500000000000ULL,
		0xF51A68F962DE044FULL,
		0x8A30E3F3CB622493ULL,
		0xD31DF259B5689AA2ULL,
		0x0000041AE733777AULL
	}};
	shift = 236;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x248BE843921920A6ULL,
		0xDC0AEC52BC28E5CCULL,
		0xB3CA18628AA052D5ULL,
		0x637B4D773BB5F265ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x920A600000000000ULL,
		0x8E5CC248BE843921ULL,
		0x052D5DC0AEC52BC2ULL,
		0x5F265B3CA18628AAULL,
		0x00000637B4D773BBULL
	}};
	shift = 236;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x24F4E95D1CA8E43DULL,
		0xEC5AEDD823D76E58ULL,
		0x645CCE81E0BE5355ULL,
		0x079ECBBE2FD96671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x57472A390F400000ULL,
		0x7608F5DB96093D3AULL,
		0xA0782F94D57B16BBULL,
		0xEF8BF6599C591733ULL,
		0x000000000001E7B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9A682B672E94B564ULL,
		0x8467AA52B8BD2D80ULL,
		0x9BBE224ABA6BA614ULL,
		0x44572D3FB0DD9E90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x415B3974A5AB2000ULL,
		0x3D5295C5E96C04D3ULL,
		0xF11255D35D30A423ULL,
		0xB969FD86ECF484DDULL,
		0x0000000000000222ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x88FB82A545FE6543ULL,
		0xED3DCFC474A47E03ULL,
		0xF1466867C462EB4AULL,
		0x462B4CF1BD871980ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F9950C000000000ULL,
		0x291F80E23EE0A951ULL,
		0x18BAD2BB4F73F11DULL,
		0x61C6603C519A19F1ULL,
		0x000000118AD33C6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7B1E445D1314B5A4ULL,
		0xFB84642C88038307ULL,
		0x0362DCF92F1A869BULL,
		0x48F7D557EAB088D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6900000000000000ULL,
		0xC1DEC7911744C52DULL,
		0xA6FEE1190B2200E0ULL,
		0x3600D8B73E4BC6A1ULL,
		0x00123DF555FAAC22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8F4A0A3DA0D0D657ULL,
		0xA6F47B469BAFFFE0ULL,
		0x06818ECDED8B86D8ULL,
		0x7BFD3015755BEED6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3595C00000000000ULL,
		0xFFF823D2828F6834ULL,
		0xE1B629BD1ED1A6EBULL,
		0xFBB581A063B37B62ULL,
		0x00001EFF4C055D56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x57957D28A44946D6ULL,
		0x87BB5D2E47FF8507ULL,
		0x34DD8AC484A80340ULL,
		0x4A480EA10EB348BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCABE945224A36B00ULL,
		0xDDAE9723FFC283ABULL,
		0x6EC562425401A043ULL,
		0x2407508759A45D1AULL,
		0x0000000000000025ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE9B83FFBD925E41DULL,
		0x8821E0CEBD2F85D2ULL,
		0x55974B77FAF23A1CULL,
		0x3431AFFEB9BAA99DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEC92F20E8000000ULL,
		0x75E97C2E974DC1FFULL,
		0xBFD791D0E4410F06ULL,
		0xF5CDD54CEAACBA5BULL,
		0x0000000001A18D7FULL
	}};
	shift = 219;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA48EB3FB7D056DC7ULL,
		0x2D3C50844C84B4E6ULL,
		0x218F6BAF7484C947ULL,
		0x4C316B69FF90772CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDC70000000000000ULL,
		0x4E6A48EB3FB7D056ULL,
		0x9472D3C50844C84BULL,
		0x72C218F6BAF7484CULL,
		0x0004C316B69FF907ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5AF12EC7FFBE7C3AULL,
		0x54A86102F5B11613ULL,
		0xF7E4F8B66A10567EULL,
		0x4ECEE69EDCF5691BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF12EC7FFBE7C3A00ULL,
		0xA86102F5B116135AULL,
		0xE4F8B66A10567E54ULL,
		0xCEE69EDCF5691BF7ULL,
		0x000000000000004EULL
	}};
	shift = 200;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1CB91027131E20B2ULL,
		0x4D12A3F9AE37833FULL,
		0x50BC8E6306C3AAC1ULL,
		0x0B6FA9A00B9C6A51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x972204E263C41640ULL,
		0xA2547F35C6F067E3ULL,
		0x1791CC60D8755829ULL,
		0x6DF53401738D4A2AULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4765BE51BAF6AA67ULL,
		0xC629C7B6625251BAULL,
		0x6BCE5C32995839B9ULL,
		0x44F41C9722A1874EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x48ECB7CA375ED54CULL,
		0x38C538F6CC4A4A37ULL,
		0xCD79CB86532B0737ULL,
		0x089E8392E45430E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCD73CA59FEC071F1ULL,
		0x1F5710ACABFCA5FDULL,
		0xD237BA391A0F28A4ULL,
		0x36F964801DC6D8D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67FB01C7C4000000ULL,
		0xB2AFF297F735CF29ULL,
		0xE4683CA2907D5C42ULL,
		0x00771B635348DEE8ULL,
		0x0000000000DBE592ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x668414575EC8AFB4ULL,
		0xF35DA1DB865B0529ULL,
		0x781C01D4321DA48DULL,
		0x0CB57006AEA638E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75EC8AFB40000000ULL,
		0xB865B05296684145ULL,
		0x4321DA48DF35DA1DULL,
		0x6AEA638E1781C01DULL,
		0x0000000000CB5700ULL
	}};
	shift = 220;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA7BFC405C5E50FADULL,
		0xEE40696FAD776F72ULL,
		0x3581BE00AFA5E3A9ULL,
		0x126A3DBBC253EE0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3EB4000000000000ULL,
		0xBDCA9EFF10171794ULL,
		0x8EA7B901A5BEB5DDULL,
		0xB828D606F802BE97ULL,
		0x000049A8F6EF094FULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x20A00F20CF26714FULL,
		0x59AAA6DA0F9C31D8ULL,
		0xF6EA820BF6A46C44ULL,
		0x798C7D0161783EEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C833C99C53C0000ULL,
		0x9B683E70C7608280ULL,
		0x082FDA91B11166AAULL,
		0xF40585E0FBAFDBAAULL,
		0x000000000001E631ULL
	}};
	shift = 210;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x463307258D867F80ULL,
		0x9FB2C46D6F47DCAFULL,
		0xFBDC7EDC5D7678F6ULL,
		0x305C1A2ABE0FCE89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C33FC0000000000ULL,
		0x7A3EE57A3198392CULL,
		0xEBB3C7B4FD96236BULL,
		0xF07E744FDEE3F6E2ULL,
		0x0000000182E0D155ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD02E89DDF214519FULL,
		0xB8838DC46BB314DCULL,
		0xAED6E2C873FBD83DULL,
		0x070884281C37C8CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44EEF90A28CF8000ULL,
		0xC6E235D98A6E6817ULL,
		0x716439FDEC1EDC41ULL,
		0x42140E1BE466D76BULL,
		0x0000000000000384ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x521CAD7BD413A737ULL,
		0x0C5B1871FE23A088ULL,
		0x34FC3877CEDAF38CULL,
		0x72A64C93D394D76FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x274E6E0000000000ULL,
		0x474110A4395AF7A8ULL,
		0xB5E71818B630E3FCULL,
		0x29AEDE69F870EF9DULL,
		0x000000E54C9927A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB29318C0058FA3A2ULL,
		0x8261853743E18F62ULL,
		0x647AF7CB977B890AULL,
		0x65093EF1A9EECB7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA4C6300163E8E880ULL,
		0x98614DD0F863D8ACULL,
		0x1EBDF2E5DEE242A0ULL,
		0x424FBC6A7BB2DE99ULL,
		0x0000000000000019ULL
	}};
	shift = 198;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBF34BF6ED8F453F3ULL,
		0xB1F3FD8B95A3E653ULL,
		0x350F5DBA71975439ULL,
		0x4F6FA823F3FDE43FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDDB1E8A7E600000ULL,
		0xB172B47CCA77E697ULL,
		0xB74E32EA87363E7FULL,
		0x047E7FBC87E6A1EBULL,
		0x000000000009EDF5ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD4A8C264B5C352C2ULL,
		0xC60E5C67D84A791AULL,
		0xA49D67058A359918ULL,
		0x5B886EA31583C719ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5AE1A96100000000ULL,
		0xEC253C8D6A546132ULL,
		0xC51ACC8C63072E33ULL,
		0x8AC1E38CD24EB382ULL,
		0x000000002DC43751ULL
	}};
	shift = 223;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x70D9606091D17547ULL,
		0x5BBCA38305ABBE0CULL,
		0x65176F58649695B7ULL,
		0x4F92074221242D4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5470000000000000ULL,
		0xE0C70D9606091D17ULL,
		0x5B75BBCA38305ABBULL,
		0xD4D65176F5864969ULL,
		0x0004F92074221242ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7A43173141362A8AULL,
		0xD8BB25474B23133FULL,
		0xC2FC0E563E3A5E01ULL,
		0x1DF62889B1681705ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C5CC504D8AA2800ULL,
		0xEC951D2C8C4CFDE9ULL,
		0xF03958F8E9780762ULL,
		0xD8A226C5A05C170BULL,
		0x0000000000000077ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x440ED0A94248FA0BULL,
		0x2EE5FF270DCEEA6FULL,
		0x05B95FD3B65ECA94ULL,
		0x48D98FDBD6677633ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x82C0000000000000ULL,
		0x9BD103B42A50923EULL,
		0xA50BB97FC9C373BAULL,
		0x8CC16E57F4ED97B2ULL,
		0x00123663F6F599DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAFA47898FCACF706ULL,
		0xBB1EA8027BA44261ULL,
		0x418F94AD4097FA4EULL,
		0x4748FCE52A13D8D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C7E567B83000000ULL,
		0x013DD22130D7D23CULL,
		0x56A04BFD275D8F54ULL,
		0x729509EC6CA0C7CAULL,
		0x000000000023A47EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFF95FCD793600C07ULL,
		0x74355459A1CEE20CULL,
		0x81F19C662D436C49ULL,
		0x2C22131C7F3E0692ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD793600C07000000ULL,
		0x59A1CEE20CFF95FCULL,
		0x662D436C49743554ULL,
		0x1C7F3E069281F19CULL,
		0x00000000002C2213ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA40E1E3DF118205DULL,
		0x3E724B3DBBAE0129ULL,
		0xC25694EEDA9B6C1BULL,
		0x4230FAF94072E884ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4608174000000000ULL,
		0xEB804A6903878F7CULL,
		0xA6DB06CF9C92CF6EULL,
		0x1CBA213095A53BB6ULL,
		0x000000108C3EBE50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x67B94D0B52689D9DULL,
		0xAEAD485731C44A80ULL,
		0xBF7E0AA0A858EE5BULL,
		0x38E1595FA00768CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0B52689D9D00000ULL,
		0x85731C44A8067B94ULL,
		0xAA0A858EE5BAEAD4ULL,
		0x95FA00768CABF7E0ULL,
		0x0000000000038E15ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC9410D411C5182A2ULL,
		0x983532F24D015795ULL,
		0x4787A4D331429B84ULL,
		0x7607286E468A1B2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1460A88000000000ULL,
		0x4055E57250435047ULL,
		0x50A6E1260D4CBC93ULL,
		0xA286CB11E1E934CCULL,
		0x0000001D81CA1B91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x03F9B0A617459412ULL,
		0xAE4E884367CA2807ULL,
		0x667A09581CF98516ULL,
		0x59943B3E2F086F5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0A617459412000ULL,
		0xE884367CA280703FULL,
		0xA09581CF98516AE4ULL,
		0x43B3E2F086F5C667ULL,
		0x0000000000000599ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA9A00BA54802658AULL,
		0x1C3DF45105933672ULL,
		0x06730C1E68FB546AULL,
		0x5F86E309AD9A6DDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A00000000000000ULL,
		0x72A9A00BA5480265ULL,
		0x6A1C3DF451059336ULL,
		0xDD06730C1E68FB54ULL,
		0x005F86E309AD9A6DULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1A5DFF9E8FB6EFA2ULL,
		0xBEFDFC7663EFDB24ULL,
		0xC22E6ADAFAF049C3ULL,
		0x705229ED5CA81EB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFCF47DB77D100000ULL,
		0xE3B31F7ED920D2EFULL,
		0x56D7D7824E1DF7EFULL,
		0x4F6AE540F5C61173ULL,
		0x0000000000038291ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8426E44264959EBBULL,
		0xE585CB979579E724ULL,
		0x5CC5F0527533370AULL,
		0x7A8F6A06283C52A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDC884C92B3D76000ULL,
		0xB972F2AF3CE49084ULL,
		0xBE0A4EA666E15CB0ULL,
		0xED40C5078A546B98ULL,
		0x0000000000000F51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1BD00B76DFEE8809ULL,
		0x7A14B14098293737ULL,
		0x4E320D58E6FCF747ULL,
		0x5279BEAC458959F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE88090000000000ULL,
		0x2937371BD00B76DFULL,
		0xFCF7477A14B14098ULL,
		0x8959F84E320D58E6ULL,
		0x0000005279BEAC45ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD02B3D94D3616BBCULL,
		0x1DA411094C74ED12ULL,
		0xE7DDF3D221D43DBFULL,
		0x30ABEBEFABFBD9D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67B29A6C2D778000ULL,
		0x8221298E9DA25A05ULL,
		0xBE7A443A87B7E3B4ULL,
		0x7D7DF57F7B3A9CFBULL,
		0x0000000000000615ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x54296B153D472ABBULL,
		0x716A43280760026DULL,
		0xD8B6009FF87F3CB9ULL,
		0x2A9A557FF6C08F42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD800000000000000ULL,
		0x6AA14B58A9EA3955ULL,
		0xCB8B5219403B0013ULL,
		0x16C5B004FFC3F9E5ULL,
		0x0154D2ABFFB6047AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x140FBCC7368E693FULL,
		0x06F00C27FD8D6370ULL,
		0xCC31EA913E0CC1F7ULL,
		0x482FBF2C84FE4A55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CD27E000000000ULL,
		0xB1AC6E0281F798E6ULL,
		0xC1983EE0DE0184FFULL,
		0x9FC94AB9863D5227ULL,
		0x0000000905F7E590ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7C0EE17570C5141FULL,
		0xFAADADE1D336D387ULL,
		0x7F6FDBB3244F2B15ULL,
		0x35D2E597DC57ED33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F80000000000000ULL,
		0xC3BE0770BAB8628AULL,
		0x8AFD56D6F0E99B69ULL,
		0x99BFB7EDD9922795ULL,
		0x001AE972CBEE2BF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBF7D32E51409091EULL,
		0x6749458E25B8D26EULL,
		0xA4896153A2C99F82ULL,
		0x4E9F720A4A90B3D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5FBE99728A04848FULL,
		0x33A4A2C712DC6937ULL,
		0xD244B0A9D164CFC1ULL,
		0x274FB905254859E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x67A91DBE96A54A26ULL,
		0x420BE424D7A9F68AULL,
		0x76882D8395A152AEULL,
		0x5B4BAFF5722BB913ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5A952898000000ULL,
		0x935EA7DA299EA476ULL,
		0x0E56854AB9082F90ULL,
		0xD5C8AEE44DDA20B6ULL,
		0x00000000016D2EBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x669537E5EBA5E2BCULL,
		0xC7CBDEBB7B1CAC87ULL,
		0xED398A84A39E4F3AULL,
		0x5F3145F9D12FD5D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE978AF0000000000ULL,
		0xC72B21D9A54DF97AULL,
		0xE793CEB1F2F7AEDEULL,
		0x4BF5763B4E62A128ULL,
		0x00000017CC517E74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3AF3F38A7F53BE29ULL,
		0x3EB7397A75F74A7AULL,
		0x646AD376A231F5DDULL,
		0x5057E5D0CEBDD9AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC53FA9DF14800000ULL,
		0xBD3AFBA53D1D79F9ULL,
		0xBB5118FAEE9F5B9CULL,
		0xE8675EECD7323569ULL,
		0x0000000000282BF2ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x20FB7F05C61525E9ULL,
		0xA029FB4A24DC0537ULL,
		0xBDC04A050A72AAC9ULL,
		0x766D1C9D7044C1BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5497A40000000000ULL,
		0x7014DC83EDFC1718ULL,
		0xCAAB2680A7ED2893ULL,
		0x1306FEF701281429ULL,
		0x000001D9B47275C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0B384929A7398BEEULL,
		0x665E4C494153CA06ULL,
		0xC2DB1A15B8E197DFULL,
		0x27D651A78776AD70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167092534E7317DCULL,
		0xCCBC989282A7940CULL,
		0x85B6342B71C32FBEULL,
		0x4FACA34F0EED5AE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x93F1147D109D6487ULL,
		0x1A2D76F7BD2BF29CULL,
		0xD9191D589BA6CB79ULL,
		0x0E88D9F806E837A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9D64870000000000ULL,
		0x2BF29C93F1147D10ULL,
		0xA6CB791A2D76F7BDULL,
		0xE837A3D9191D589BULL,
		0x0000000E88D9F806ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB8C662C37BA91DF8ULL,
		0x5DBA24A382CCF7F5ULL,
		0x09170279D7564E84ULL,
		0x62C494C80CED4293ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF80000000000000ULL,
		0x7F5B8C662C37BA91ULL,
		0xE845DBA24A382CCFULL,
		0x29309170279D7564ULL,
		0x00062C494C80CED4ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1186847E6BEC3291ULL,
		0xA808538436967C28ULL,
		0x1736871D944A5530ULL,
		0x523D4A5B8F0C1BB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6847E6BEC3291000ULL,
		0x8538436967C28118ULL,
		0x6871D944A5530A80ULL,
		0xD4A5B8F0C1BB5173ULL,
		0x0000000000000523ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC7E9ACCDF4AE00B7ULL,
		0x92DD62FC32544CB2ULL,
		0x435D605689B143D0ULL,
		0x3015DA7868E20B00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x337D2B802DC00000ULL,
		0xBF0C95132CB1FA6BULL,
		0x15A26C50F424B758ULL,
		0x9E1A3882C010D758ULL,
		0x00000000000C0576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF2CF17EF6C6F37B6ULL,
		0x03B3140EC0E80D57ULL,
		0x8669CBC6DA493E20ULL,
		0x3B63EF45C64C1E2AULL,
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
		0xFE59E2FDED8DE6F6ULL,
		0x00766281D81D01AAULL,
		0x50CD3978DB4927C4ULL,
		0x076C7DE8B8C983C5ULL
	}};
	shift = 253;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x964DB15B0CFAF6CAULL,
		0xCF7BCFC30EDB8E30ULL,
		0x08B35761D828351DULL,
		0x4900B011EBB817A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CFAF6CA00000000ULL,
		0x0EDB8E30964DB15BULL,
		0xD828351DCF7BCFC3ULL,
		0xEBB817A808B35761ULL,
		0x000000004900B011ULL
	}};
	shift = 224;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1AFD6076D32BF08CULL,
		0xA37D0E867102F2FFULL,
		0xBE1C957D148B4F4FULL,
		0x52A7EF82064156FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1180000000000000ULL,
		0x5FE35FAC0EDA657EULL,
		0xE9F46FA1D0CE205EULL,
		0xDFB7C392AFA29169ULL,
		0x000A54FDF040C82AULL
	}};
	shift = 245;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF927C647B63717B2ULL,
		0x7C6CDC9C2FA5B7E9ULL,
		0x156EDB9B79F888EDULL,
		0x6C04BD41C486D666ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8DC5EC800000000ULL,
		0xBE96DFA7E49F191EULL,
		0xE7E223B5F1B37270ULL,
		0x121B599855BB6E6DULL,
		0x00000001B012F507ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD14A250ECB0AB5AAULL,
		0xFC9503F545B89401ULL,
		0x0E4D6FAB3221A076ULL,
		0x2A5BFCE25600D401ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x944A1D96156B5400ULL,
		0x2A07EA8B712803A2ULL,
		0x9ADF56644340EDF9ULL,
		0xB7F9C4AC01A8021CULL,
		0x0000000000000054ULL
	}};
	shift = 201;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCFDB9C4824E5C1E3ULL,
		0x51DD1DE6CB60EDCDULL,
		0x427414FE14CDD585ULL,
		0x515EF95791EF927EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0xDCFDB9C4824E5C1EULL,
		0x551DD1DE6CB60EDCULL,
		0xE427414FE14CDD58ULL,
		0x0515EF95791EF927ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5A8FD89999E94489ULL,
		0x33762553D01F1A07ULL,
		0xE8C3BCF8682BC614ULL,
		0x4D1F40C7A170413FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3F626667A512240ULL,
		0xDD8954F407C681D6ULL,
		0x30EF3E1A0AF1850CULL,
		0x47D031E85C104FFAULL,
		0x0000000000000013ULL
	}};
	shift = 198;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6E4DB739F03DCB63ULL,
		0xAC28940CBE34A6E6ULL,
		0x43AB8FC40F1ED289ULL,
		0x426F2979B9A8DADEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0F72D8C0000000ULL,
		0x2F8D29B99B936DCEULL,
		0x03C7B4A26B0A2503ULL,
		0x6E6A36B790EAE3F1ULL,
		0x00000000109BCA5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x408616579A34D424ULL,
		0x2FD83D566664BF7DULL,
		0x555562B511A366B1ULL,
		0x79D967C9A6660710ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A34D4240000000ULL,
		0x66664BF7D4086165ULL,
		0x511A366B12FD83D5ULL,
		0x9A6660710555562BULL,
		0x00000000079D967CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x31D6335E63105D8FULL,
		0x92E0441E4E3FBC02ULL,
		0x73410E1F5632BE51ULL,
		0x61076262BA6015F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3105D8F000000000ULL,
		0xE3FBC0231D6335E6ULL,
		0x632BE5192E0441E4ULL,
		0xA6015F873410E1F5ULL,
		0x000000061076262BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB1C1F06B7338AFCDULL,
		0x6FB79BDF5F1EE7E2ULL,
		0x528BF47D29F34458ULL,
		0x5720235229C31ADBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E6715F9A000000ULL,
		0xBEBE3DCFC56383E0ULL,
		0xFA53E688B0DF6F37ULL,
		0xA4538635B6A517E8ULL,
		0x0000000000AE4046ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x26257755FEE815DDULL,
		0x42A344A1B33259B5ULL,
		0x01EFE0D902A64190ULL,
		0x032E20D0B653FF88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEE815DD000000000ULL,
		0x33259B526257755FULL,
		0x2A6419042A344A1BULL,
		0x653FF8801EFE0D90ULL,
		0x0000000032E20D0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6EF68EEEB9DC1033ULL,
		0x1B4D5574CE64D590ULL,
		0x52EAE874AD8DE902ULL,
		0x1A69BDE00C6194A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0x06EF68EEEB9DC103ULL,
		0x21B4D5574CE64D59ULL,
		0x152EAE874AD8DE90ULL,
		0x01A69BDE00C6194AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC5712C78F0F80622ULL,
		0x0AE3FEC3A9112AC2ULL,
		0x7E8D7B385EFA2826ULL,
		0x5C466E515D42D867ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5712C78F0F80622ULL,
		0x0AE3FEC3A9112AC2ULL,
		0x7E8D7B385EFA2826ULL,
		0x5C466E515D42D867ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3E7FB3941B8B94D6ULL,
		0x4BCB46BF2F54139FULL,
		0xEAD2174023D52005ULL,
		0x4450EF3E6F813845ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x371729AC00000000ULL,
		0x5EA8273E7CFF6728ULL,
		0x47AA400A97968D7EULL,
		0xDF02708BD5A42E80ULL,
		0x0000000088A1DE7CULL
	}};
	shift = 225;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBA4FF8D01FC601A8ULL,
		0xDC6DD4704DDADCC0ULL,
		0x6B97B902B77A6DC0ULL,
		0x5A999C721F00FEADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FF1A03F8C035000ULL,
		0xDBA8E09BB5B98174ULL,
		0x2F72056EF4DB81B8ULL,
		0x3338E43E01FD5AD7ULL,
		0x00000000000000B5ULL
	}};
	shift = 201;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4BEEB8129A1AD003ULL,
		0xF2A3DAED0F9B5961ULL,
		0xA6ECCDE534A8903FULL,
		0x6CA84EDC27570842ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C00000000000000ULL,
		0x852FBAE04A686B40ULL,
		0xFFCA8F6BB43E6D65ULL,
		0x0A9BB33794D2A240ULL,
		0x01B2A13B709D5C21ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF5A653F0866D0B65ULL,
		0xED55959F030E5E44ULL,
		0xA39F0CE2F185F436ULL,
		0x703474376CA8F7CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2800000000000000ULL,
		0x27AD329F8433685BULL,
		0xB76AACACF81872F2ULL,
		0x7D1CF867178C2FA1ULL,
		0x0381A3A1BB6547BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE9BF9FC4D95366E0ULL,
		0xBEF673F58C5EC655ULL,
		0x76CCF2E0ACE5484FULL,
		0x47FF17F99355F11CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB370000000000000ULL,
		0x632AF4DFCFE26CA9ULL,
		0xA427DF7B39FAC62FULL,
		0xF88E3B6679705672ULL,
		0x000023FF8BFCC9AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5AA62CD104B3580AULL,
		0x030E35BDDCEB061BULL,
		0x8949883983FE44A4ULL,
		0x4C6C856E4E92B999ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5316688259AC0500ULL,
		0x871ADEEE75830DADULL,
		0xA4C41CC1FF225201ULL,
		0x3642B727495CCCC4ULL,
		0x0000000000000026ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAA4F80DC1D222A88ULL,
		0x8A11443BB21C23CAULL,
		0x20F744CB5AD2BD64ULL,
		0x758765708EB9B952ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01B83A445510000ULL,
		0x2887764384795549ULL,
		0xE8996B5A57AC9142ULL,
		0xECAE11D7372A441EULL,
		0x0000000000000EB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E24446D116F37CFULL,
		0x2223C5E57A536B4CULL,
		0xB641F5C1C78723AAULL,
		0x5AE36F958F8B58AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDF3C00000000000ULL,
		0xDAD31789111B445BULL,
		0xC8EA8888F1795E94ULL,
		0xD62BAD907D7071E1ULL,
		0x000016B8DBE563E2ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7B6E228D2D92B915ULL,
		0x76C9C83824AA823EULL,
		0x315F818F2314F573ULL,
		0x2F02FFFC75FEBD95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE4540000000000ULL,
		0xAA08F9EDB88A34B6ULL,
		0x53D5CDDB2720E092ULL,
		0xFAF654C57E063C8CULL,
		0x000000BC0BFFF1D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x70257CECC4DAD4F0ULL,
		0x1BB86ACD9C1869C9ULL,
		0x3763901C41A62226ULL,
		0x16811C8CA3EF91E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD4F0000000000000ULL,
		0x69C970257CECC4DAULL,
		0x22261BB86ACD9C18ULL,
		0x91E23763901C41A6ULL,
		0x000016811C8CA3EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0D7E9B7525CA01A4ULL,
		0x9771DA2111F7E3B3ULL,
		0x12C2BA6CCEB4A6E9ULL,
		0x3169EAD2C1B1175CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6900000000000000ULL,
		0xECC35FA6DD497280ULL,
		0xBA65DC7688447DF8ULL,
		0xD704B0AE9B33AD29ULL,
		0x000C5A7AB4B06C45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x075FDF4BCFB3E389ULL,
		0x0156402EE87E2768ULL,
		0x79379A31C5486CEFULL,
		0x0B9E191AB2899666ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFBE979F67C7120ULL,
		0x2AC805DD0FC4ED00ULL,
		0x26F34638A90D9DE0ULL,
		0x73C323565132CCCFULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x19E68041270AEF1BULL,
		0xAC9963DEF3F535F5ULL,
		0x36438144736F2A56ULL,
		0x58C75B7335739601ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x41270AEF1B000000ULL,
		0xDEF3F535F519E680ULL,
		0x44736F2A56AC9963ULL,
		0x7335739601364381ULL,
		0x000000000058C75BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE85EE85372E6DDACULL,
		0xEB9CEDBB5A013BDFULL,
		0x788D5EB9607E4B49ULL,
		0x0614031B6A73F21DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBDD0A6E5CDBB5800ULL,
		0x39DB76B40277BFD0ULL,
		0x1ABD72C0FC9693D7ULL,
		0x280636D4E7E43AF1ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCABE9DD4A86B510AULL,
		0x0FD011047D68EBC0ULL,
		0xA28162D1A0B885DBULL,
		0x77348B6CDCAD9812ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3BA950D6A214000ULL,
		0x02208FAD1D781957ULL,
		0x2C5A341710BB61FAULL,
		0x916D9B95B3025450ULL,
		0x0000000000000EE6ULL
	}};
	shift = 205;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0B62EF46D6B77755ULL,
		0x5CD67683FD8AC6BFULL,
		0x6F8752EBFBC929F6ULL,
		0x69471FA6B85778FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5DE8DAD6EEEAA00ULL,
		0xACED07FB158D7E16ULL,
		0x0EA5D7F79253ECB9ULL,
		0x8E3F4D70AEF1F4DFULL,
		0x00000000000000D2ULL
	}};
	shift = 201;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9F598B23E6E8D8EDULL,
		0xBDF3177F1E11BF42ULL,
		0x8DD71B86A247CCB4ULL,
		0x0E99CD871FFA0ACEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x31647CDD1B1DA000ULL,
		0x62EFE3C237E853EBULL,
		0xE370D448F99697BEULL,
		0x39B0E3FF4159D1BAULL,
		0x00000000000001D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF1D6B301E10DBF9DULL,
		0x2E48B87E4542EC64ULL,
		0xF4532BAC43FD530CULL,
		0x14E29EC4D5F97A36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE74000000000000ULL,
		0xB193C75ACC078436ULL,
		0x4C30B922E1F9150BULL,
		0xE8DBD14CAEB10FF5ULL,
		0x0000538A7B1357E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB502728AB0680D52ULL,
		0xC563385033FE07EAULL,
		0x6DBF6B09AD9DE6C0ULL,
		0x728EAA0BF6773D3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0xAB502728AB0680D5ULL,
		0x0C563385033FE07EULL,
		0xA6DBF6B09AD9DE6CULL,
		0x0728EAA0BF6773D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0C8C051AEFA20624ULL,
		0xAB83F99117E5B80AULL,
		0x8D2567506802A27CULL,
		0x4B9C560930DC852CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8C051AEFA206240ULL,
		0xB83F99117E5B80A0ULL,
		0xD2567506802A27CAULL,
		0xB9C560930DC852C8ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE1AF0B74B9444BC4ULL,
		0x2F5957EA8FB12C4DULL,
		0x1B57F48893761D65ULL,
		0x367C4FA8075F9738ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA5CA225E20000000ULL,
		0x547D89626F0D785BULL,
		0x449BB0EB297ACABFULL,
		0x403AFCB9C0DABFA4ULL,
		0x0000000001B3E27DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4A63E5027623207AULL,
		0x66DE19929AF58BB3ULL,
		0xA83B9875798B4CECULL,
		0x372850F8848E6F70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D00000000000000ULL,
		0xD9A531F2813B1190ULL,
		0x76336F0CC94D7AC5ULL,
		0xB8541DCC3ABCC5A6ULL,
		0x001B94287C424737ULL
	}};
	shift = 247;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E9F56FA8F452463ULL,
		0x7BA304BD82B99D8BULL,
		0x05BE82E2DB7B59BCULL,
		0x3A69DF47381151AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0xB5E9F56FA8F45246ULL,
		0xC7BA304BD82B99D8ULL,
		0xA05BE82E2DB7B59BULL,
		0x03A69DF47381151AULL
	}};
	shift = 252;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA20A28B4E87A0B8EULL,
		0xCA01487267DCA8F5ULL,
		0x36AF68A2AC3C106AULL,
		0x7D63672EA867E1B5ULL,
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
		0xD105145A743D05C7ULL,
		0x6500A43933EE547AULL,
		0x9B57B451561E0835ULL,
		0x3EB1B3975433F0DAULL
	}};
	shift = 255;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2A981A018746164DULL,
		0x91B670196440BB58ULL,
		0x1E632D5550AC8C35ULL,
		0x4BB82ADCE7371884ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x34030E8C2C9A0000ULL,
		0xE032C88176B05530ULL,
		0x5AAAA159186B236CULL,
		0x55B9CE6E31083CC6ULL,
		0x0000000000009770ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x679AE4149D8D0C39ULL,
		0xFA23F2EC72725410ULL,
		0x77B259EF0A0111E7ULL,
		0x4C3B5537B78ECE7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B9052763430E400ULL,
		0x8FCBB1C9C950419EULL,
		0xC967BC2804479FE8ULL,
		0xED54DEDE3B39FDDEULL,
		0x0000000000000130ULL
	}};
	shift = 202;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8C703FF3A4D2DCB8ULL,
		0xC879B7E45D857426ULL,
		0x028627977CBAC813ULL,
		0x1AA20C2FF03103C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x81FF9D2696E5C000ULL,
		0xCDBF22EC2BA13463ULL,
		0x313CBBE5D6409E43ULL,
		0x10617F81881E3814ULL,
		0x00000000000000D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x55E5D4ABC698FD8BULL,
		0x9D81BCD2FBE85C19ULL,
		0xDF8A1B751FFB4A69ULL,
		0x7BE0D977F50540A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C00000000000000ULL,
		0x65579752AF1A63F6ULL,
		0xA67606F34BEFA170ULL,
		0x837E286DD47FED29ULL,
		0x01EF8365DFD41502ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE49E03BFAFB956D0ULL,
		0x791A2EF1382981DFULL,
		0x7D5CF0119847129BULL,
		0x6F2262A8B6BC873BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9E03BFAFB956D000ULL,
		0x1A2EF1382981DFE4ULL,
		0x5CF0119847129B79ULL,
		0x2262A8B6BC873B7DULL,
		0x000000000000006FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5ADDED1C691C15B1ULL,
		0x2708A8B1F7296506ULL,
		0x065C7F8E3E850E23ULL,
		0x56865A7CAC96C075ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDED1C691C15B1000ULL,
		0x8A8B1F72965065ADULL,
		0xC7F8E3E850E23270ULL,
		0x65A7CAC96C075065ULL,
		0x0000000000000568ULL
	}};
	shift = 204;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3C079DA2331AEE36ULL,
		0x1E8DF4C5BA733254ULL,
		0x181DAEF3F9E080C7ULL,
		0x24F43AFED5995320ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE360000000000000ULL,
		0x2543C079DA2331AEULL,
		0x0C71E8DF4C5BA733ULL,
		0x320181DAEF3F9E08ULL,
		0x00024F43AFED5995ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFE9FF2CC2297581EULL,
		0x783E83F00D58CFB4ULL,
		0x9B7F1F0EDBE40751ULL,
		0x4AAAF348A08DB35CULL,
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
		0x7F4FF966114BAC0FULL,
		0xBC1F41F806AC67DAULL,
		0x4DBF8F876DF203A8ULL,
		0x255579A45046D9AEULL
	}};
	shift = 255;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x59DD09527F356E9AULL,
		0xD69302BD96BAC2FCULL,
		0x370A581800816C88ULL,
		0x04C26257E9392658ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD340000000000000ULL,
		0x5F8B3BA12A4FE6ADULL,
		0x911AD26057B2D758ULL,
		0xCB06E14B0300102DULL,
		0x0000984C4AFD2724ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x459E60AF26693DBFULL,
		0x3468330BF412922AULL,
		0x97FE0E34E1CE7938ULL,
		0x078C1288119734EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF80000000000000ULL,
		0x1522CF305793349EULL,
		0x9C1A341985FA0949ULL,
		0x774BFF071A70E73CULL,
		0x0003C6094408CB9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x828473EA3BB89817ULL,
		0xB06DB17C73D22B2CULL,
		0xECCA5EC5761BC31EULL,
		0x2622378A59E28CCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x14239F51DDC4C0B8ULL,
		0x836D8BE39E915964ULL,
		0x6652F62BB0DE18F5ULL,
		0x3111BC52CF146657ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x359BDC4DC3AEA32CULL,
		0x0F8D27E4260C4C37ULL,
		0x48BAED52B84357DDULL,
		0x439A5B7AA41151F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC3AEA32C000000ULL,
		0xE4260C4C37359BDCULL,
		0x52B84357DD0F8D27ULL,
		0x7AA41151F648BAEDULL,
		0x0000000000439A5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3F17609744DE49BAULL,
		0x5CEE38AA943A5D21ULL,
		0x6B8F4EC59F280A65ULL,
		0x184B5B12AA32ECF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24DD000000000000ULL,
		0x2E909F8BB04BA26FULL,
		0x0532AE771C554A1DULL,
		0x767B35C7A762CF94ULL,
		0x00000C25AD895519ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFCA16812AC5646AAULL,
		0x88598CF4A920A8C0ULL,
		0x4511D3A83CA9EC39ULL,
		0x3E55FE4A4A512381ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16812AC5646AA000ULL,
		0x98CF4A920A8C0FCAULL,
		0x1D3A83CA9EC39885ULL,
		0x5FE4A4A512381451ULL,
		0x00000000000003E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB11DE2D0BC5824CDULL,
		0x969FB28A2924F995ULL,
		0xC7EFBE403DBC2632ULL,
		0x170FC51AE1C8179EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0933400000000000ULL,
		0x3E656C4778B42F16ULL,
		0x098CA5A7ECA28A49ULL,
		0x05E7B1FBEF900F6FULL,
		0x000005C3F146B872ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1039EC275BF93127ULL,
		0x4FB7681DDDAA3DA4ULL,
		0xC8F06C88F6CA0F2BULL,
		0x7CF245367C01C21DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC989380000000000ULL,
		0x51ED2081CF613ADFULL,
		0x50795A7DBB40EEEDULL,
		0x0E10EE47836447B6ULL,
		0x000003E79229B3E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0D0068D4328F29FEULL,
		0x5F8BBFE650BAEF6FULL,
		0x94DB5C890C5D064CULL,
		0x556275F3C38CDC32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA7F800000000000ULL,
		0xBBDBC3401A350CA3ULL,
		0x419317E2EFF9942EULL,
		0x370CA536D7224317ULL,
		0x000015589D7CF0E3ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA51D001A4B03C727ULL,
		0x8EC623BD1D44B17BULL,
		0x313DDD2B40A9BED0ULL,
		0x63D7AD9DD3818F13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D001A4B03C72700ULL,
		0xC623BD1D44B17BA5ULL,
		0x3DDD2B40A9BED08EULL,
		0xD7AD9DD3818F1331ULL,
		0x0000000000000063ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x832A7BCFB3C02713ULL,
		0x97F93862084B5E81ULL,
		0x271DE7AE2DEFC4D0ULL,
		0x58470B6CEF7E229DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2600000000000000ULL,
		0x030654F79F67804EULL,
		0xA12FF270C41096BDULL,
		0x3A4E3BCF5C5BDF89ULL,
		0x00B08E16D9DEFC45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2B6119F2A73EBBFFULL,
		0xC0B7238EABA94240ULL,
		0x9709ECB52A69646CULL,
		0x4C7EE3F8AFB59CFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CA9CFAEFFC00000ULL,
		0xE3AAEA50900AD846ULL,
		0x2D4A9A591B302DC8ULL,
		0xFE2BED673FE5C27BULL,
		0x0000000000131FB8ULL
	}};
	shift = 214;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE0A19060E936DF1FULL,
		0x690E9FD73EB630C4ULL,
		0x832156F314960E4CULL,
		0x515D2B83D3A668A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDB7C7C0000000000ULL,
		0xD8C31382864183A4ULL,
		0x583931A43A7F5CFAULL,
		0x99A29E0C855BCC52ULL,
		0x0000014574AE0F4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD9C5C3F20C17AD32ULL,
		0x9B75C4A18E11A570ULL,
		0x07A3EEBF73E057A1ULL,
		0x0B6EEF45269BF19EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8305EB4C80000000ULL,
		0x6384695C367170FCULL,
		0xDCF815E866DD7128ULL,
		0x49A6FC6781E8FBAFULL,
		0x0000000002DBBBD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCAA7638A130B2B6DULL,
		0x1F655AAC1D804F76ULL,
		0x2091D2F71DB653B7ULL,
		0x2708300C1162EBCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xB2A9D8E284C2CADBULL,
		0xC7D956AB076013DDULL,
		0xC82474BDC76D94EDULL,
		0x09C20C030458BAF3ULL
	}};
	shift = 254;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9D25190613FDB47CULL,
		0x372AA71529B6892FULL,
		0x29C603BA97B71CD0ULL,
		0x2C4A0608C22705B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x25190613FDB47C00ULL,
		0x2AA71529B6892F9DULL,
		0xC603BA97B71CD037ULL,
		0x4A0608C22705B029ULL,
		0x000000000000002CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x342728CB0E791521ULL,
		0xCD40659A0F517459ULL,
		0x7E7A0C8E249114F8ULL,
		0x18ABC85DA1AC6952ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728CB0E791521000ULL,
		0x0659A0F517459342ULL,
		0xA0C8E249114F8CD4ULL,
		0xBC85DA1AC69527E7ULL,
		0x000000000000018AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x57DA9EE55C613428ULL,
		0xA470A799E59DC244ULL,
		0x12665BCEA87A16C1ULL,
		0x3AF564F750CD2889ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A1400000000000ULL,
		0xEE1222BED4F72AE3ULL,
		0xD0B60D23853CCF2CULL,
		0x6944489332DE7543ULL,
		0x000001D7AB27BA86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCF59C2567F8DA53BULL,
		0x4CC8BEE27315EE69ULL,
		0x6EAAB7A2BFCC3CD7ULL,
		0x67D2C7A0BF1CDD64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59FE3694EC000000ULL,
		0x89CC57B9A73D6709ULL,
		0x8AFF30F35D3322FBULL,
		0x82FC737591BAAADEULL,
		0x00000000019F4B1EULL
	}};
	shift = 218;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2E3EAC5F25C9C44CULL,
		0x6E8B96FE78009395ULL,
		0x0C34B3BCEF96DC1BULL,
		0x4B1E49BC111C5CB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F92E4E226000000ULL,
		0x7F3C0049CA971F56ULL,
		0xDE77CB6E0DB745CBULL,
		0xDE088E2E5C061A59ULL,
		0x0000000000258F24ULL
	}};
	shift = 215;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC9AA88E45661FCECULL,
		0xB4A97CE99826C7C1ULL,
		0x6B3801A13A66BDAAULL,
		0x4A853013F19D1D65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61FCEC0000000000ULL,
		0x26C7C1C9AA88E456ULL,
		0x66BDAAB4A97CE998ULL,
		0x9D1D656B3801A13AULL,
		0x0000004A853013F1ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCFAACE5F80B1C778ULL,
		0x5645267FC073F357ULL,
		0x26779B9826C372D4ULL,
		0x464E44F004D79D31ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC058E3BC0000000ULL,
		0xFE039F9ABE7D5672ULL,
		0xC1361B96A2B22933ULL,
		0x8026BCE98933BCDCULL,
		0x0000000002327227ULL
	}};
	shift = 219;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8DA6CA13AFA2C852ULL,
		0xBD9CAA9E4972FE51ULL,
		0x9B5121D13BF347A4ULL,
		0x6FC52A147897C713ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6509D7D164290000ULL,
		0x554F24B97F28C6D3ULL,
		0x90E89DF9A3D25ECEULL,
		0x950A3C4BE389CDA8ULL,
		0x00000000000037E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x90B8A23346CC9380ULL,
		0x405C84B8CA82337BULL,
		0xB7E953BC4EA6DDB7ULL,
		0x443617CF19512637ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x668D992700000000ULL,
		0x71950466F7217144ULL,
		0x789D4DBB6E80B909ULL,
		0x9E32A24C6F6FD2A7ULL,
		0x0000000000886C2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8827943FA349D331ULL,
		0x12573EBECCD7FF16ULL,
		0x1DA371838E1530D2ULL,
		0x5C0C801B16FC5F60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827943FA349D3310ULL,
		0x2573EBECCD7FF168ULL,
		0xDA371838E1530D21ULL,
		0xC0C801B16FC5F601ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x590E86F8F0D50FE0ULL,
		0x80CE6C62A94B0A8EULL,
		0xFE8EC7BEFBE44E5CULL,
		0x1EFE1F6389D7FC95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C786A87F0000000ULL,
		0x3154A585472C8743ULL,
		0xDF7DF2272E406736ULL,
		0xB1C4EBFE4AFF4763ULL,
		0x00000000000F7F0FULL
	}};
	shift = 215;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAE3D58B875F10997ULL,
		0x18943BF1C007367AULL,
		0x80E492ABDB4A9AF8ULL,
		0x59E168350C2B3E48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x875F109970000000ULL,
		0x1C007367AAE3D58BULL,
		0xBDB4A9AF818943BFULL,
		0x50C2B3E4880E492AULL,
		0x00000000059E1683ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x86B7075A9DF140DFULL,
		0xB6234A23146C8641ULL,
		0xAD17CA73525FBF1DULL,
		0x015511BFF8E5C40DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x61ADC1D6A77C5037ULL,
		0x6D88D288C51B2190ULL,
		0x6B45F29CD497EFC7ULL,
		0x0055446FFE397103ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA82D09D771F5BDE3ULL,
		0x3E6BE84B836D553FULL,
		0xE16EE5DEEC23FF87ULL,
		0x50CB09D3471126B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA0B4275DC7D6F78CULL,
		0xF9AFA12E0DB554FEULL,
		0x85BB977BB08FFE1CULL,
		0x432C274D1C449ACFULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x766B2ADD0E3A3F40ULL,
		0x9F9F12055306CE77ULL,
		0x6D60E4364F20B4DEULL,
		0x023661DA38183087ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x871D1FA000000000ULL,
		0xA983673BBB35956EULL,
		0x27905A6F4FCF8902ULL,
		0x1C0C1843B6B0721BULL,
		0x00000000011B30EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x03BB370CCDDDDA59ULL,
		0x0D7A956B3DAC494AULL,
		0x6B6D5C7766F129D1ULL,
		0x3F375DBCAE9897E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B20000000000000ULL,
		0x29407766E199BBBBULL,
		0x3A21AF52AD67B589ULL,
		0xFCAD6DAB8EECDE25ULL,
		0x0007E6EBB795D312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBAF36B4E26431F35ULL,
		0xA3AD13D3526A640CULL,
		0xD1FAAA7F230AE9D5ULL,
		0x2F5153B3C553D61EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C7CD40000000000ULL,
		0xA99032EBCDAD3899ULL,
		0x2BA7568EB44F4D49ULL,
		0x4F587B47EAA9FC8CULL,
		0x000000BD454ECF15ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x05555DC7388CDD61ULL,
		0xDB4E08CA85EAF8E1ULL,
		0xD117AD22F16539A3ULL,
		0x490EF2BB510E4BB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC200000000000000ULL,
		0xC20AAABB8E7119BAULL,
		0x47B69C11950BD5F1ULL,
		0x61A22F5A45E2CA73ULL,
		0x00921DE576A21C97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFA494E5D64AF05E3ULL,
		0x99202B9621DFE602ULL,
		0xEC191BD9A74CEACEULL,
		0x55DDFD22FF66070CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9CBAC95E0BC60000ULL,
		0x572C43BFCC05F492ULL,
		0x37B34E99D59D3240ULL,
		0xFA45FECC0E19D832ULL,
		0x000000000000ABBBULL
	}};
	shift = 209;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA2CE72B5D482DDC0ULL,
		0x8AA02A552212CACCULL,
		0x57ACF7831AD175B8ULL,
		0x3CEB0A1A71805FE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x905BB80000000000ULL,
		0x4259599459CE56BAULL,
		0x5A2EB71154054AA4ULL,
		0x300BFC6AF59EF063ULL,
		0x000000079D61434EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x807F1552B24E5E6FULL,
		0x323186E28E996CEFULL,
		0x51024BF46F970BA0ULL,
		0x33E916983563788CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA959272F3780000ULL,
		0x371474CB677C03F8ULL,
		0x5FA37CB85D01918CULL,
		0xB4C1AB1BC4628812ULL,
		0x0000000000019F48ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFE3F9ACC5AF46099ULL,
		0xEDE2EC93B2D36100ULL,
		0x6454B9948965A23FULL,
		0x341429A2D652D8B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C13200000000000ULL,
		0x6C201FC7F3598B5EULL,
		0xB447FDBC5D92765AULL,
		0x5B168C8A9732912CULL,
		0x0000068285345ACAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9EE0D1BD0E211C61ULL,
		0x6B0096B50C982D3CULL,
		0xBE2FED0E0FFF0858ULL,
		0x7DD7AD6C911A22BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3884718400000000ULL,
		0x3260B4F27B8346F4ULL,
		0x3FFC2161AC025AD4ULL,
		0x44688AFEF8BFB438ULL,
		0x00000001F75EB5B2ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x84ABCB0009D4BBEEULL,
		0x835C92909781E3CFULL,
		0xA23875EF65BBDED2ULL,
		0x3A2F4221A9F4E262ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBEE0000000000000ULL,
		0x3CF84ABCB0009D4BULL,
		0xED2835C92909781EULL,
		0x262A23875EF65BBDULL,
		0x0003A2F4221A9F4EULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7B6535D5BAF1D5F7ULL,
		0x95E341340A9CD323ULL,
		0xECF9191FC8CD1260ULL,
		0x7A7356B61B7D1E12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x75E3ABEE00000000ULL,
		0x1539A646F6CA6BABULL,
		0x919A24C12BC68268ULL,
		0x36FA3C25D9F2323FULL,
		0x00000000F4E6AD6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC413603B9CD312C8ULL,
		0xA4939034E6EFE002ULL,
		0x1A0CB3969E0079FAULL,
		0x78B7999A8F2F5300ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8964000000000000ULL,
		0xF0016209B01DCE69ULL,
		0x3CFD5249C81A7377ULL,
		0xA9800D0659CB4F00ULL,
		0x00003C5BCCCD4797ULL
	}};
	shift = 239;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x37C020CB9DCB345DULL,
		0x7D2A78741D7A197EULL,
		0xC08188F7242EC00EULL,
		0x53765C0D4E7F3838ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD174000000000000ULL,
		0x65F8DF00832E772CULL,
		0x0039F4A9E1D075E8ULL,
		0xE0E3020623DC90BBULL,
		0x00014DD9703539FCULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8110516CA9CEDBB9ULL,
		0xCD78682C6F4152D5ULL,
		0xD5C81780DE991A56ULL,
		0x2D4430A113A7AA6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB77200000000000ULL,
		0x2A5AB0220A2D9539ULL,
		0x234AD9AF0D058DE8ULL,
		0xF54DDAB902F01BD3ULL,
		0x000005A886142274ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9B674CD169E51343ULL,
		0x2EDF5F600F4ADA28ULL,
		0x7EEED85502C6927EULL,
		0x6A4E6E8803DA340CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x44D0C00000000000ULL,
		0xB68A26D9D3345A79ULL,
		0xA49F8BB7D7D803D2ULL,
		0x8D031FBBB61540B1ULL,
		0x00001A939BA200F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4A5AAFE1EB733C90ULL,
		0x90B616D34072CC1EULL,
		0xBA9BDC2275D201F5ULL,
		0x4FFE1C0565A02D45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55FC3D6E67920000ULL,
		0xC2DA680E5983C94BULL,
		0x7B844EBA403EB216ULL,
		0xC380ACB405A8B753ULL,
		0x00000000000009FFULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE00946D6E2110D76ULL,
		0xFDF8216E833EFB89ULL,
		0x30EBA5DAB8DA8BD5ULL,
		0x654C4B4667551BE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x10D7600000000000ULL,
		0xEFB89E00946D6E21ULL,
		0xA8BD5FDF8216E833ULL,
		0x51BE430EBA5DAB8DULL,
		0x00000654C4B46675ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD6102679A2475592ULL,
		0x4D773CDE512CCCADULL,
		0x3DCB0F3DC62D27B2ULL,
		0x46AF15FD2D3BBB03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6480000000000000ULL,
		0x2B7584099E6891D5ULL,
		0xEC935DCF37944B33ULL,
		0xC0CF72C3CF718B49ULL,
		0x0011ABC57F4B4EEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4A66F5F208581DF7ULL,
		0x1FA500EFA8578E40ULL,
		0x7C0EA8B0220EA9EBULL,
		0x3CC941014C0D6F22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F5F208581DF7000ULL,
		0x500EFA8578E404A6ULL,
		0xEA8B0220EA9EB1FAULL,
		0x941014C0D6F227C0ULL,
		0x00000000000003CCULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9951DE073C9ABC29ULL,
		0xE73CA4796F7135A3ULL,
		0x8596E28EAF038F0EULL,
		0x3E2B73CD3E12FC58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x732A3BC0E7935785ULL,
		0xDCE7948F2DEE26B4ULL,
		0x10B2DC51D5E071E1ULL,
		0x07C56E79A7C25F8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA3C4D34CCF66F803ULL,
		0xAA074C563952B35CULL,
		0x1A65D1BE4869D973ULL,
		0x31276362DEFEF968ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDF00600000000000ULL,
		0x566B94789A6999ECULL,
		0x3B2E7540E98AC72AULL,
		0xDF2D034CBA37C90DULL,
		0x00000624EC6C5BDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2C90FC88DF83A502ULL,
		0x9BB094DCD2E3C8EDULL,
		0x4B7A5C3AE16B93B9ULL,
		0x4BEA8ED71778D245ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FC1D28100000000ULL,
		0x6971E47696487E44ULL,
		0x70B5C9DCCDD84A6EULL,
		0x8BBC6922A5BD2E1DULL,
		0x0000000025F5476BULL
	}};
	shift = 223;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC50AC03C4BA42223ULL,
		0xF60976511ADE029EULL,
		0xF0E7490397C26EEFULL,
		0x349DE29A26DCADEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x01E25D2111180000ULL,
		0xB288D6F014F62856ULL,
		0x481CBE13777FB04BULL,
		0x14D136E56F6F873AULL,
		0x000000000001A4EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x24723026F2D11383ULL,
		0x97BCD39FC1A24D65ULL,
		0x21FFF28C816440B7ULL,
		0x63C6EC599E13C743ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4723026F2D113830ULL,
		0x7BCD39FC1A24D652ULL,
		0x1FFF28C816440B79ULL,
		0x3C6EC599E13C7432ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6E4B39CEEBFFDBFCULL,
		0x46D1BBC0C6C7E9B9ULL,
		0x80B9258F22233A48ULL,
		0x1FC4FDDFDA9CED72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB7F800000000000ULL,
		0xFD372DC96739DD7FULL,
		0x674908DA377818D8ULL,
		0x9DAE501724B1E444ULL,
		0x000003F89FBBFB53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8954249CC8747B35ULL,
		0x223943A14897D414ULL,
		0x314FCD374C370AB7ULL,
		0x31A9853DBB14DE15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7B35000000000000ULL,
		0xD4148954249CC874ULL,
		0x0AB7223943A14897ULL,
		0xDE15314FCD374C37ULL,
		0x000031A9853DBB14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2111BDB6B7C431E3ULL,
		0xE3FCCCEB8057924CULL,
		0x27481AE95E82ECA0ULL,
		0x3B5875775482719BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6D6F8863C60000ULL,
		0x99D700AF24984223ULL,
		0x35D2BD05D941C7F9ULL,
		0xEAEEA904E3364E90ULL,
		0x00000000000076B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAE481CECDDE9221BULL,
		0xEE9ADB2CA0D51307ULL,
		0x39F60E627AE77D50ULL,
		0x1E4271CE638706E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9BBD24436000000ULL,
		0x5941AA260F5C9039ULL,
		0xC4F5CEFAA1DD35B6ULL,
		0x9CC70E0DCC73EC1CULL,
		0x00000000003C84E3ULL
	}};
	shift = 217;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAF6FD9DC4B698405ULL,
		0xC00093F9A52584DDULL,
		0xBB5D321F5BDA96BCULL,
		0x200DFF50A7C74213ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D3080A000000000ULL,
		0xA4B09BB5EDFB3B89ULL,
		0x7B52D79800127F34ULL,
		0xF8E842776BA643EBULL,
		0x0000000401BFEA14ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD08963C70434B417ULL,
		0xB5A53DAE34FD6253ULL,
		0x399999B117BF727FULL,
		0x405700AFE327E2C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB800000000000000ULL,
		0x9E844B1E3821A5A0ULL,
		0xFDAD29ED71A7EB12ULL,
		0x49CCCCCD88BDFB93ULL,
		0x0202B8057F193F16ULL
	}};
	shift = 251;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5C3D0C1DD1873B54ULL,
		0x159DFA21DDB7751DULL,
		0x56381210A3783C0FULL,
		0x2ECD94CEFB9318F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39DAA00000000000ULL,
		0xBBA8EAE1E860EE8CULL,
		0xC1E078ACEFD10EEDULL,
		0x98C7B2B1C090851BULL,
		0x000001766CA677DCULL
	}};
	shift = 235;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x696299B1C3A263DDULL,
		0x5EBA14FE7F63F4DCULL,
		0x23461DDCEB1C5E4BULL,
		0x7AC3E24E03D29E4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70E898F740000000ULL,
		0x9FD8FD371A58A66CULL,
		0x3AC71792D7AE853FULL,
		0x80F4A79288D18777ULL,
		0x000000001EB0F893ULL
	}};
	shift = 222;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x61268C5D512706A4ULL,
		0x1474E6B93B3B8551ULL,
		0x9CC72696F7AD5C10ULL,
		0x2C58961739E6517AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x175449C1A9000000ULL,
		0xAE4ECEE1545849A3ULL,
		0xA5BDEB5704051D39ULL,
		0x85CE79945EA731C9ULL,
		0x00000000000B1625ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x56B1BE0448A5F9DDULL,
		0x6FA39C93CEEDE9A0ULL,
		0xFEA71CF5528F2A1DULL,
		0x0305610D3D7FE354ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0x02B58DF022452FCEULL,
		0xEB7D1CE49E776F4DULL,
		0xA7F538E7AA947950ULL,
		0x00182B0869EBFF1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEDE74627E67EC4B1ULL,
		0xAB01D57B7167475CULL,
		0x03A2A65FF3CFF35DULL,
		0x71BC92A90AAF7E30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB79D189F99FB12C4ULL,
		0xAC0755EDC59D1D73ULL,
		0x0E8A997FCF3FCD76ULL,
		0xC6F24AA42ABDF8C0ULL,
		0x0000000000000001ULL
	}};
	shift = 194;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE0C847E360D01581ULL,
		0x94A0E09097C16E48ULL,
		0xCEADEFBFFDFFBC71ULL,
		0x43392B39068F3470ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5604000000000000ULL,
		0xB92383211F8D8340ULL,
		0xF1C6528382425F05ULL,
		0xD1C33AB7BEFFF7FEULL,
		0x00010CE4ACE41A3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCC6D002928801B4AULL,
		0xF4973E46B7965836ULL,
		0x11F34AACB4DBAEC9ULL,
		0x2D1C9959C1668922ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6636801494400DA5ULL,
		0xFA4B9F235BCB2C1BULL,
		0x08F9A5565A6DD764ULL,
		0x168E4CACE0B34491ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4BA60A786C0E1C5CULL,
		0x8F3F688858F07241ULL,
		0x1E93CDE2FCE25F47ULL,
		0x3DFF658EC77B3C60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3C36070E2E000000ULL,
		0x442C783920A5D305ULL,
		0xF17E712FA3C79FB4ULL,
		0xC763BD9E300F49E6ULL,
		0x00000000001EFFB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x663CAB0B0A3324B5ULL,
		0xC2C9D28D76BE24BDULL,
		0xDC640B47176A923BULL,
		0x65092C5E3699CBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x663CAB0B0A3324B5ULL,
		0xC2C9D28D76BE24BDULL,
		0xDC640B47176A923BULL,
		0x65092C5E3699CBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x92ADBA89CA98C668ULL,
		0x19F1D5C96D5DC0C1ULL,
		0x042BC3D424B4602CULL,
		0x69AC33B8515AB9E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x92ADBA89CA98C668ULL,
		0x19F1D5C96D5DC0C1ULL,
		0x042BC3D424B4602CULL,
		0x69AC33B8515AB9E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD6617C7C22588D0DULL,
		0x9B7A367DD36DE6DEULL,
		0xCC02AEF7C0BFC8BFULL,
		0x55A4279BE28BB2AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7C22588D0D00000ULL,
		0x67DD36DE6DED6617ULL,
		0xEF7C0BFC8BF9B7A3ULL,
		0x79BE28BB2AECC02AULL,
		0x0000000000055A42ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE6F5B35C54F4AEFAULL,
		0xB0143D0312A11B02ULL,
		0xC0EA805D9ACD73F9ULL,
		0x601BECF3E28E79A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE2A7A577D000000ULL,
		0x8189508D81737AD9ULL,
		0x2ECD66B9FCD80A1EULL,
		0x79F1473CD4E07540ULL,
		0x0000000000300DF6ULL
	}};
	shift = 215;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x905767D6E79BE2E0ULL,
		0x50C721E2B5FDBCEBULL,
		0xDD73F2DEF42C1117ULL,
		0x6589613D049B2D22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xEB905767D6E79BE2ULL,
		0x1750C721E2B5FDBCULL,
		0x22DD73F2DEF42C11ULL,
		0x006589613D049B2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8AD4870B94C86501ULL,
		0xDCBD567CCE866B51ULL,
		0x5A770480B498E81CULL,
		0x038A4B46E8AB9389ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC865010000000000ULL,
		0x866B518AD4870B94ULL,
		0x98E81CDCBD567CCEULL,
		0xAB93895A770480B4ULL,
		0x000000038A4B46E8ULL
	}};
	shift = 232;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x463D1FB82CB261EBULL,
		0xEA27996EBD2319F5ULL,
		0x9FDD131DAB5B019DULL,
		0x3E79DAE04FC2297AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5930F58000000000ULL,
		0x918CFAA31E8FDC16ULL,
		0xAD80CEF513CCB75EULL,
		0xE114BD4FEE898ED5ULL,
		0x0000001F3CED7027ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000001ULL,
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
		0x0000000000000100ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000800000000000ULL,
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
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000040000ULL,
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
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL,
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
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0100000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000040ULL,
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
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000002000ULL,
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
		0x0000000000000200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000008000ULL,
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
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000400000000000ULL,
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
		0x0000000040000000ULL
	}};
	shift = 240;
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
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
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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