#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x892F3A5CD3EB2579ULL,
		0x5CAD72A520AAD624ULL,
		0xBE945E2D884AE6F3ULL,
		0x9BFF76AA24829EC3ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BC8000000000000ULL,
		0xB1244979D2E69F59ULL,
		0x379AE56B95290556ULL,
		0xF61DF4A2F16C4257ULL,
		0x0004DFFBB5512414ULL
	}};
	int shift = 13;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11706BB91FF0141AULL,
		0x66788CA923694AA7ULL,
		0x5962D7D45ABBEB60ULL,
		0xF1E99073170978BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11706BB91FF0141AULL,
		0x66788CA923694AA7ULL,
		0x5962D7D45ABBEB60ULL,
		0xF1E99073170978BBULL
	}};
	shift = 0;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB0302686E05022FEULL,
		0x1B4FB32D2669E26AULL,
		0xB2BA6F4ABABAD630ULL,
		0x2FDC14CA35141AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1408BF8000000000ULL,
		0x9A789AAC0C09A1B8ULL,
		0xAEB58C06D3ECCB49ULL,
		0x4506B5ECAE9BD2AEULL,
		0x0000000BF705328DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B178E4158338A15ULL,
		0xC8B13F872599D47AULL,
		0x75A4B45129A7F093ULL,
		0xAAF6264B40C93223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A8000000000000ULL,
		0xA3D058BC720AC19CULL,
		0x849E4589FC392CCEULL,
		0x911BAD25A2894D3FULL,
		0x000557B1325A0649ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03DB4EE06A16D68AULL,
		0x1691EC6B66FCEB44ULL,
		0x92DED4D01E558C9DULL,
		0xFD7DF051273D1DECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA770350B6B450000ULL,
		0xF635B37E75A201EDULL,
		0x6A680F2AC64E8B48ULL,
		0xF828939E8EF6496FULL,
		0x0000000000007EBEULL
	}};
	shift = 49;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C62EB7490657AB2ULL,
		0x2F540A8EE9BC6700ULL,
		0x575D5CA83E3F1C20ULL,
		0xBAC6EBED3524528DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6E920CAF5640000ULL,
		0x151DD378CE0058C5ULL,
		0xB9507C7E38405EA8ULL,
		0xD7DA6A48A51AAEBAULL,
		0x000000000001758DULL
	}};
	shift = 47;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B2E1C2B3F29A670ULL,
		0x12544BBEC03F33A3ULL,
		0x964D0FD9FC588C01ULL,
		0xA967E3F63BD2E1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCECB870ACFCA699CULL,
		0x449512EFB00FCCE8ULL,
		0x659343F67F162300ULL,
		0x2A59F8FD8EF4B871ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B4F96DEBCCE872FULL,
		0x3C93D3EFA63EC619ULL,
		0x7B16CD1EDF702A57ULL,
		0x405553B906951684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0E5E00000000000ULL,
		0xD8C32B69F2DBD799ULL,
		0x054AE7927A7DF4C7ULL,
		0xA2D08F62D9A3DBEEULL,
		0x0000080AAA7720D2ULL
	}};
	shift = 19;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD61F65E1CEE174F2ULL,
		0xF71DB502247BD41AULL,
		0x456D16E79FB633CCULL,
		0x432A677DFAA8263BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE9E4000000000000ULL,
		0xA835AC3ECBC39DC2ULL,
		0x6799EE3B6A0448F7ULL,
		0x4C768ADA2DCF3F6CULL,
		0x00008654CEFBF550ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C506BC7070AF79EULL,
		0x35A2D58C94B58A03ULL,
		0xF8277E0CEAE77077ULL,
		0x230578F2CD9FBF27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF3C000000000000ULL,
		0x1406D8A0D78E0E15ULL,
		0xE0EE6B45AB19296BULL,
		0x7E4FF04EFC19D5CEULL,
		0x0000460AF1E59B3FULL
	}};
	shift = 15;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x24278580B396B99FULL,
		0x1568EB0E6ED7A94CULL,
		0x98B9705ADA3083D4ULL,
		0x803A1BE7BD09035BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96B99F0000000000ULL,
		0xD7A94C24278580B3ULL,
		0x3083D41568EB0E6EULL,
		0x09035B98B9705ADAULL,
		0x000000803A1BE7BDULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60FA07AE936D76E0ULL,
		0xC4A38E422F88022CULL,
		0xF4DB7D2B5A2862ECULL,
		0xE27FFC95E106A3CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE81EBA4DB5DB8000ULL,
		0x8E3908BE2008B183ULL,
		0x6DF4AD68A18BB312ULL,
		0xFFF257841A8F3FD3ULL,
		0x0000000000000389ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C3E13E70B8FE6C9ULL,
		0xCFE3BA5BDFACFDE8ULL,
		0x3F64791DC598E9BFULL,
		0xCC8EA5547AE329B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x0B87C27CE171FCD9ULL,
		0xF9FC774B7BF59FBDULL,
		0xA7EC8F23B8B31D37ULL,
		0x1991D4AA8F5C6536ULL
	}};
	shift = 3;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6221EBC7F04C04E2ULL,
		0xB48F144A3587946FULL,
		0xFF192A241A89C744ULL,
		0x5B767092CF2EBB2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC400000000000000ULL,
		0xDEC443D78FE09809ULL,
		0x89691E28946B0F28ULL,
		0x5FFE32544835138EULL,
		0x00B6ECE1259E5D76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6A5A4CE262F0CF8ULL,
		0xA7AE76427EE202E9ULL,
		0x71E5C1CA73438050ULL,
		0x878079B3A81D460DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x52D2671317867C00ULL,
		0xD73B213F710174DBULL,
		0xF2E0E539A1C02853ULL,
		0xC03CD9D40EA306B8ULL,
		0x0000000000000043ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BEB16A842887201ULL,
		0x566D81BD0F742BE2ULL,
		0x12A3C8F20C50DDC8ULL,
		0xF98D7D6F07CC7ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0200000000000000ULL,
		0xC4D7D62D508510E4ULL,
		0x90ACDB037A1EE857ULL,
		0x98254791E418A1BBULL,
		0x01F31AFADE0F98FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA83405DCFFF76699ULL,
		0xEC9C73FDB39EBAF8ULL,
		0x4EC396709D04AD3FULL,
		0xD029E8D8B703A38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA640000000000000ULL,
		0xBE2A0D01773FFDD9ULL,
		0x4FFB271CFF6CE7AEULL,
		0xE313B0E59C27412BULL,
		0x00340A7A362DC0E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDFC9F6236C4C8781ULL,
		0x8E08B0F4430DD11EULL,
		0xB742D2D372558B1EULL,
		0x4840106D60AD56CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9F6236C4C878100ULL,
		0x08B0F4430DD11EDFULL,
		0x42D2D372558B1E8EULL,
		0x40106D60AD56CFB7ULL,
		0x0000000000000048ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB4732CD551ABAE0ULL,
		0xDD626133158CE3FCULL,
		0xE2E33AF1ED89EC5DULL,
		0x21E19A813CB82BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3575C0000000000ULL,
		0xB19C7F9F68E659AAULL,
		0xB13D8BBBAC4C2662ULL,
		0x97057A9C5C675E3DULL,
		0x000000043C335027ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE5BC6993D355282ULL,
		0x6B7EB6B35903CE07ULL,
		0x87F6A430BECA27C5ULL,
		0xDBA467875DA3CE87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5528200000000000ULL,
		0x3CE07DE5BC6993D3ULL,
		0xA27C56B7EB6B3590ULL,
		0x3CE8787F6A430BECULL,
		0x00000DBA467875DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8090114DF6B350BULL,
		0xCA64474F61EABCFBULL,
		0x5F6E51DA7EE2C12CULL,
		0xB59EAEB8DDCCF93BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED66A16000000000ULL,
		0x3D579F7D0120229BULL,
		0xDC5825994C88E9ECULL,
		0xB99F276BEDCA3B4FULL,
		0x00000016B3D5D71BULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00E2A128BFE3E179ULL,
		0x777E63DD057A18E5ULL,
		0x45956AD5C81E7F01ULL,
		0x8FF927C418826CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1F0BC80000000000ULL,
		0xD0C72807150945FFULL,
		0xF3F80BBBF31EE82BULL,
		0x1366E22CAB56AE40ULL,
		0x0000047FC93E20C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2465EE28C7D702AULL,
		0x187E7AC2DE5A445AULL,
		0xC2ABB3F04BC0DAF7ULL,
		0x3ECE67FCF02A1ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32F71463EB815000ULL,
		0xF3D616F2D222D792ULL,
		0x5D9F825E06D7B8C3ULL,
		0x733FE78150D66E15ULL,
		0x00000000000001F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDABC239367755A90ULL,
		0xB9832C4277F1E5ACULL,
		0xB139CDAE0AE7729AULL,
		0xEDEE742D62D0C2B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D9DD56A4000000ULL,
		0x109DFC796B36AF08ULL,
		0x6B82B9DCA6AE60CBULL,
		0x0B58B430AC6C4E73ULL,
		0x00000000003B7B9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6582381DA645D96EULL,
		0xB6921DCB0923938CULL,
		0x1EE141DB250774F2ULL,
		0x8F507A71CDCE48C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32C11C0ED322ECB7ULL,
		0x5B490EE58491C9C6ULL,
		0x8F70A0ED9283BA79ULL,
		0x47A83D38E6E72461ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF93136BFB8BD8DEULL,
		0x74F8669B068E7F23ULL,
		0xFD615DC0D7BEA741ULL,
		0x88ABCEAF8C0524C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36BFB8BD8DE00000ULL,
		0x69B068E7F23BF931ULL,
		0xDC0D7BEA74174F86ULL,
		0xEAF8C0524C9FD615ULL,
		0x0000000000088ABCULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AC0227D2A9CC84EULL,
		0x9E959E07A3702A99ULL,
		0xF057B7C31DF36A95ULL,
		0x73E9211D1AC8DB9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4FA5539909C00000ULL,
		0xC0F46E0553315804ULL,
		0xF863BE6D52B3D2B3ULL,
		0x23A3591B735E0AF6ULL,
		0x00000000000E7D24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF960C0D1EC72E2D2ULL,
		0x05A7EBD24890F3BBULL,
		0xEA3E0DC94DEA2C57ULL,
		0x20BC892519B7D01DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC72E2D200000000ULL,
		0x4890F3BBF960C0D1ULL,
		0x4DEA2C5705A7EBD2ULL,
		0x19B7D01DEA3E0DC9ULL,
		0x0000000020BC8925ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA2E788C8B1F7FF7ULL,
		0xB6F3CD0C69190721ULL,
		0xF00F150462819CD2ULL,
		0x6BD24C4D886A7FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x119163EFFEE00000ULL,
		0xA18D2320E43F45CFULL,
		0xA08C50339A56DE79ULL,
		0x89B10D4FF49E01E2ULL,
		0x00000000000D7A49ULL
	}};
	shift = 43;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD148EBDD40088167ULL,
		0x5259D99146EDE3A1ULL,
		0x808769FC5DE5DCD4ULL,
		0x9317010119802F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x059C000000000000ULL,
		0x8E874523AF750022ULL,
		0x7351496766451BB7ULL,
		0xBD9A021DA7F17797ULL,
		0x00024C5C04046600ULL
	}};
	shift = 14;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8ADF667D63573A5ULL,
		0xBC0AD672FACACA37ULL,
		0xC98B4F2426BA501BULL,
		0xAE0EBE1C1826B74CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF667D63573A50000ULL,
		0xD672FACACA37B8ADULL,
		0x4F2426BA501BBC0AULL,
		0xBE1C1826B74CC98BULL,
		0x000000000000AE0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05DA9A3D21B092DCULL,
		0x75B37BAABCA06748ULL,
		0xE5CA34F31D08EC80ULL,
		0x75F07087A228E4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5347A436125B8000ULL,
		0x6F7557940CE900BBULL,
		0x469E63A11D900EB6ULL,
		0x0E10F4451C9E9CB9ULL,
		0x0000000000000EBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E4B4507649E1C88ULL,
		0x581B3BE6751475E6ULL,
		0x44289985655BE5A7ULL,
		0x528460128A9858C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8800000000000000ULL,
		0xE60E4B4507649E1CULL,
		0xA7581B3BE6751475ULL,
		0xC344289985655BE5ULL,
		0x00528460128A9858ULL
	}};
	shift = 8;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x095FCB6E15E19767ULL,
		0x2353ABCE23B7CAF3ULL,
		0xC13B207ADDEBA85EULL,
		0xECFC240B08C57A6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9767000000000000ULL,
		0xCAF3095FCB6E15E1ULL,
		0xA85E2353ABCE23B7ULL,
		0x7A6FC13B207ADDEBULL,
		0x0000ECFC240B08C5ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB66E90752A98834CULL,
		0x45951CCE8BF9136DULL,
		0xADD67E2719DB230BULL,
		0x973AC0B955594802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x90752A98834C0000ULL,
		0x1CCE8BF9136DB66EULL,
		0x7E2719DB230B4595ULL,
		0xC0B955594802ADD6ULL,
		0x000000000000973AULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x25BFA255A60B90EDULL,
		0xFED5525E47F5C501ULL,
		0x7671F2C2374AAB39ULL,
		0x6D3BE31FC7EBB38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5BFA255A60B90ED0ULL,
		0xED5525E47F5C5012ULL,
		0x671F2C2374AAB39FULL,
		0xD3BE31FC7EBB38C7ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D00D46450579919ULL,
		0x49E8E10905539592ULL,
		0x9447C63F5FEC02C4ULL,
		0xEAFA17906EA7E263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4640000000000000ULL,
		0x648F4035191415E6ULL,
		0xB1127A38424154E5ULL,
		0x98E511F18FD7FB00ULL,
		0x003ABE85E41BA9F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x470038D3B966C701ULL,
		0x4E7137FE890BBCA2ULL,
		0xA676647878880398ULL,
		0x4D4573DB84181F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9DCB363808000000ULL,
		0xF4485DE5123801C6ULL,
		0xC3C4401CC27389BFULL,
		0xDC20C0FB8533B323ULL,
		0x00000000026A2B9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE32F30C6E2F17746ULL,
		0xA3788D739E048A5BULL,
		0x105E1A0AF95AC1A5ULL,
		0xC5B3B9763B7666B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF19798637178BBA3ULL,
		0xD1BC46B9CF02452DULL,
		0x882F0D057CAD60D2ULL,
		0x62D9DCBB1DBB335CULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73B2FA99B335C378ULL,
		0x03F78D2F5B0A6059ULL,
		0x1426EAEDFC7BB822ULL,
		0x8FF15778E810FD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xCB9D97D4CD99AE1BULL,
		0x101FBC697AD85302ULL,
		0xE8A137576FE3DDC1ULL,
		0x047F8ABBC74087E9ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5A7CD2976BC1378ULL,
		0x1F1C4D978856F782ULL,
		0xB1C16D6B8B0781E8ULL,
		0xD5FE5D4D51888295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ED7826F00000000ULL,
		0xF10ADEF05CB4F9A5ULL,
		0x7160F03D03E389B2ULL,
		0xAA311052B6382DADULL,
		0x000000001ABFCBA9ULL
	}};
	shift = 35;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x24DFB9C0908A8C8CULL,
		0xFD40FF281EF366DBULL,
		0x2BCF8FDDD4A34895ULL,
		0x11BC03BF6054C3B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4845464600000000ULL,
		0x0F79B36D926FDCE0ULL,
		0xEA51A44AFEA07F94ULL,
		0xB02A61D915E7C7EEULL,
		0x0000000008DE01DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAB3ECC4E38AC5B3EULL,
		0x58396695133A048FULL,
		0x6422EB7FD9981CFEULL,
		0x1DC6200D238067EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x989C7158B67C0000ULL,
		0xCD2A2674091F567DULL,
		0xD6FFB33039FCB072ULL,
		0x401A4700CFDAC845ULL,
		0x0000000000003B8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE8F6CB3D34AA3B6ULL,
		0xCC3F47D739C7CE47ULL,
		0x99A289A7DC20DDA7ULL,
		0x438C6051F84B8C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5476C00000000000ULL,
		0xF9C8FBD1ED967A69ULL,
		0x1BB4F987E8FAE738ULL,
		0x718B53345134FB84ULL,
		0x000008718C0A3F09ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9007A02CD4FDA06CULL,
		0xDA5EB545B4D6D80AULL,
		0xA6F899FEF6A06469ULL,
		0xDF1ADA5E63CA41E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0B353F681B000000ULL,
		0x516D35B602A401E8ULL,
		0x7FBDA8191A7697ADULL,
		0x9798F2907829BE26ULL,
		0x000000000037C6B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC2833BF53100868ULL,
		0x8C5D0191A0B7599BULL,
		0x2A18535AC3D01A62ULL,
		0xC57F0BCA1DA851B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4021A00000000000ULL,
		0xDD666EF0A0CEFD4CULL,
		0x40698A3174064682ULL,
		0xA146E0A8614D6B0FULL,
		0x00000315FC2F2876ULL
	}};
	shift = 22;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9CAD3AEBE12DC62ULL,
		0x7BB04F6CD3011CF0ULL,
		0x194A4A9FA6CB694DULL,
		0x77C2FB7FAD03AEEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9395A75D7C25B8C4ULL,
		0xF7609ED9A60239E1ULL,
		0x3294953F4D96D29AULL,
		0xEF85F6FF5A075DDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F63C329AC9C92EBULL,
		0x70074BFC4A5E52F5ULL,
		0xD3C811F9D4026DB4ULL,
		0x00548FE9D291406AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2724BAC00000000ULL,
		0x29794BD53D8F0CA6ULL,
		0x5009B6D1C01D2FF1ULL,
		0x4A4501AB4F2047E7ULL,
		0x0000000001523FA7ULL
	}};
	shift = 30;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE96FCAE4FBA3CD87ULL,
		0x246AADD068A02E74ULL,
		0x7C3CB4A70699C995ULL,
		0xE00A6C7686614DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC380000000000000ULL,
		0x3A74B7E5727DD1E6ULL,
		0xCA923556E8345017ULL,
		0xE13E1E5A53834CE4ULL,
		0x007005363B4330A6ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38E1E80919AA0089ULL,
		0x416E4DF552570A26ULL,
		0xC27A2A3395B74A44ULL,
		0xDA193DEAAB485004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA008900000000000ULL,
		0x70A2638E1E80919AULL,
		0x74A44416E4DF5525ULL,
		0x85004C27A2A3395BULL,
		0x00000DA193DEAAB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF76940CD2CD9A2EULL,
		0x602629FFAE0B907FULL,
		0x4E08348954B01AF7ULL,
		0x035529B91582419CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x45C0000000000000ULL,
		0x0FF9EED2819A59B3ULL,
		0x5EEC04C53FF5C172ULL,
		0x3389C106912A9603ULL,
		0x00006AA53722B048ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F870CD8246931CEULL,
		0xC5B2F4175DB9D026ULL,
		0x4F99402129F080F9ULL,
		0x037B40D582DE13CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19B048D2639C000ULL,
		0x5E82EBB73A04C7F0ULL,
		0x2804253E101F38B6ULL,
		0x681AB05BC27969F3ULL,
		0x000000000000006FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F14396E83C38DFCULL,
		0x88A227E8CC78B7D2ULL,
		0x32897908DA0E1689ULL,
		0xA9F38B66BD80C8B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x41E1C6FE00000000ULL,
		0x663C5BE92F8A1CB7ULL,
		0x6D070B44C45113F4ULL,
		0x5EC0645C9944BC84ULL,
		0x0000000054F9C5B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF420006CB95AE5A0ULL,
		0x2FC0C9D7A23B7420ULL,
		0xFE9B44E0A3DFA2CCULL,
		0xA535B2D5BC158B4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB95AE5A000000000ULL,
		0xA23B7420F420006CULL,
		0xA3DFA2CC2FC0C9D7ULL,
		0xBC158B4CFE9B44E0ULL,
		0x00000000A535B2D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E1C6495D624A75ULL,
		0xC6AEF090AF72362DULL,
		0x18BCB58AB71B7D99ULL,
		0x0F22033412A3A69AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x253A800000000000ULL,
		0x1B168CF0E324AEB1ULL,
		0xBECCE357784857B9ULL,
		0xD34D0C5E5AC55B8DULL,
		0x00000791019A0951ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9029825F0078DCE1ULL,
		0xD6F12CC2CD6AA8ADULL,
		0xB240311CFE7207DDULL,
		0xC83E67E60499E0F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C6E708000000000ULL,
		0xB55456C814C12F80ULL,
		0x3903EEEB78966166ULL,
		0x4CF0785920188E7FULL,
		0x000000641F33F302ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28C57B99DBAD30E7ULL,
		0xF477133E9490EC71ULL,
		0x59A22E8ED60E989AULL,
		0x13CDC9CA5AF74C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4C39C0000000000ULL,
		0x43B1C4A315EE676EULL,
		0x3A626BD1DC4CFA52ULL,
		0xDD30516688BA3B58ULL,
		0x0000004F3727296BULL
	}};
	shift = 22;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26C374D013C8FE68ULL,
		0xE99CE1F9CA870DEAULL,
		0x6C2FD49779F28CF2ULL,
		0x8D27225A9A904088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0xD44D86E9A02791FCULL,
		0xE5D339C3F3950E1BULL,
		0x10D85FA92EF3E519ULL,
		0x011A4E44B5352081ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E69829EBE2569B9ULL,
		0x1BB5A468032CC45BULL,
		0x43CFCCBEDA9D8F14ULL,
		0x8550111443C4E8CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7AF895A6E4000000ULL,
		0xA00CB3116DB9A60AULL,
		0xFB6A763C506ED691ULL,
		0x510F13A3290F3F32ULL,
		0x0000000002154044ULL
	}};
	shift = 38;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x077C77E316D95C54ULL,
		0xB051F8635CFB8705ULL,
		0x2E84AB622B151667ULL,
		0xCC2DD7A5A31DF675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6CAE2A000000000ULL,
		0xE7DC38283BE3BF18ULL,
		0x58A8B33D828FC31AULL,
		0x18EFB3A974255B11ULL,
		0x00000006616EBD2DULL
	}};
	shift = 29;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14E810CCC8EB9241ULL,
		0xE274F4DA484B3AEDULL,
		0x810A4A136264EAB7ULL,
		0xBA04827D5EDEED1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAE49040000000000ULL,
		0x2CEBB453A0433323ULL,
		0x93AADF89D3D36921ULL,
		0x7BB46E0429284D89ULL,
		0x000002E81209F57BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD16B0DB1999BA8DULL,
		0x21D858596A8425C7ULL,
		0x6EE9228ABB7B0F7BULL,
		0xCDFBA5C0F339EBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D8CCCDD46800000ULL,
		0x2CB54212E3EE8B58ULL,
		0x455DBD87BD90EC2CULL,
		0xE0799CF5D2B77491ULL,
		0x000000000066FDD2ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76F6CE24DB96796BULL,
		0xC4FA1F9AF93EDB66ULL,
		0x93FA2F63DB4864F8ULL,
		0x07A8CFA48BF84F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDB38936E59E5AC00ULL,
		0xE87E6BE4FB6D99DBULL,
		0xE8BD8F6D2193E313ULL,
		0xA33E922FE13C6A4FULL,
		0x000000000000001EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E01F8A3044AFC0BULL,
		0x76FF9957D935C497ULL,
		0x09ED26A65BD60FAEULL,
		0xBE699A33E7910353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F81600000000000ULL,
		0xB892EFC03F146089ULL,
		0xC1F5CEDFF32AFB26ULL,
		0x206A613DA4D4CB7AULL,
		0x000017CD33467CF2ULL
	}};
	shift = 19;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A0261D73143DBB4ULL,
		0x76E9C8B76B41651CULL,
		0x1546EBDC45A08183ULL,
		0x8B979EB7FBED43D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC50F6ED000000000ULL,
		0xAD0594712809875CULL,
		0x1682060DDBA722DDULL,
		0xEFB50F4C551BAF71ULL,
		0x000000022E5E7ADFULL
	}};
	shift = 30;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC43B360E74C17F2AULL,
		0x0A53D075A09FB627ULL,
		0xF015EE91CAF0E8FFULL,
		0xAD636E93D43513ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82FE540000000000ULL,
		0x3F6C4F88766C1CE9ULL,
		0xE1D1FE14A7A0EB41ULL,
		0x6A2757E02BDD2395ULL,
		0x0000015AC6DD27A8ULL
	}};
	shift = 23;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C76FAAE08A8DE6FULL,
		0x86DF6A288D9B0DECULL,
		0x72E2CAB15146AA6CULL,
		0x5C855CFAFE24942BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC1151BCDE0000000ULL,
		0x11B361BD858EDF55ULL,
		0x2A28D54D90DBED45ULL,
		0x5FC492856E5C5956ULL,
		0x000000000B90AB9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x322B223A0D41B2F1ULL,
		0xA35993EDB36158ACULL,
		0x8841BBB73A10C928ULL,
		0x2224E6215611EF71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x644741A8365E2000ULL,
		0x327DB66C2B158645ULL,
		0x3776E7421925146BULL,
		0x9CC42AC23DEE3108ULL,
		0x0000000000000444ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A43D13D9BB148FEULL,
		0xDDD1D1D551A67010ULL,
		0xD06D5E5D58D0EAA3ULL,
		0x6930A50369328829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC523F8000000000ULL,
		0x699C041E90F44F66ULL,
		0x343AA8F774747554ULL,
		0x4CA20A741B579756ULL,
		0x0000001A4C2940DAULL
	}};
	shift = 26;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD92B3CEBA38E80EULL,
		0x576B2EE8D07F9E82ULL,
		0x069093840439472EULL,
		0x5B096B8D42B98E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80E0000000000000ULL,
		0xE82BD92B3CEBA38EULL,
		0x72E576B2EE8D07F9ULL,
		0xE5A0690938404394ULL,
		0x0005B096B8D42B98ULL
	}};
	shift = 12;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BC73A1462F09694ULL,
		0x4A593D99895B8FF0ULL,
		0xBFDBCF1845EE1365ULL,
		0x327DFC4B0C255FE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A1462F096940000ULL,
		0x3D99895B8FF06BC7ULL,
		0xCF1845EE13654A59ULL,
		0xFC4B0C255FE4BFDBULL,
		0x000000000000327DULL
	}};
	shift = 48;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x527401EF24E1432CULL,
		0xDBB4DFA1355CD0E4ULL,
		0xE9085ABE73C2C9A1ULL,
		0x2ADD47E96B70E477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA196000000000000ULL,
		0x6872293A00F79270ULL,
		0x64D0EDDA6FD09AAEULL,
		0x723BF4842D5F39E1ULL,
		0x0000156EA3F4B5B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29F34D0FB6650483ULL,
		0xA57821D039C1C3FAULL,
		0x1ECF78EFB86060FBULL,
		0xE77C4DA589F15AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA687DB3282418000ULL,
		0x10E81CE0E1FD14F9ULL,
		0xBC77DC30307DD2BCULL,
		0x26D2C4F8AD7D8F67ULL,
		0x00000000000073BEULL
	}};
	shift = 49;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D7AAC2963F926DEULL,
		0xF62448FE790764FDULL,
		0x3CB5A30FAAC74DFEULL,
		0x6931155442D812F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDE00000000000000ULL,
		0xFD8D7AAC2963F926ULL,
		0xFEF62448FE790764ULL,
		0xF63CB5A30FAAC74DULL,
		0x006931155442D812ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB640867E8A5A7223ULL,
		0x7AE2A4F7BC7618BAULL,
		0xF5CC414C9A449C0FULL,
		0x5B2FB4717E77F750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0867E8A5A7223000ULL,
		0x2A4F7BC7618BAB64ULL,
		0xC414C9A449C0F7AEULL,
		0xFB4717E77F750F5CULL,
		0x00000000000005B2ULL
	}};
	shift = 52;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8EEECF700310FAEULL,
		0xC902518467ACCFF3ULL,
		0xAC38E0CE91F3855EULL,
		0x0DF5DAED7AE58D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9EE00621F5C000ULL,
		0x4A308CF599FE7B1DULL,
		0x1C19D23E70ABD920ULL,
		0xBB5DAF5CB1A03587ULL,
		0x00000000000001BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CD3E07D94A3C037ULL,
		0xAC64AF79D3E94D5BULL,
		0xE7AD2866E3698872ULL,
		0x5398FB1668329258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF81F6528F00DC000ULL,
		0x2BDE74FA5356D734ULL,
		0x4A19B8DA621CAB19ULL,
		0x3EC59A0CA49639EBULL,
		0x00000000000014E6ULL
	}};
	shift = 50;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF76D9F2C25DEB69FULL,
		0x598618152D9D43D1ULL,
		0xA311BA91BB97B546ULL,
		0x02B8CA8BC8BD7181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12EF5B4F80000000ULL,
		0x96CEA1E8FBB6CF96ULL,
		0xDDCBDAA32CC30C0AULL,
		0xE45EB8C0D188DD48ULL,
		0x00000000015C6545ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82C7BED9E05A8405ULL,
		0x9CF9E24C70A5C4EEULL,
		0x6D5C4F5D1BEF5B1DULL,
		0xFE3781206170BBC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C0B5080A0000000ULL,
		0x8E14B89DD058F7DBULL,
		0xA37DEB63B39F3C49ULL,
		0x0C2E1778EDAB89EBULL,
		0x000000001FC6F024ULL
	}};
	shift = 35;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59C23B3C5B616D6DULL,
		0xC80F021B355C7AA7ULL,
		0xE788F0D7BD05B1DFULL,
		0x264016E38569E1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23B3C5B616D6D000ULL,
		0xF021B355C7AA759CULL,
		0x8F0D7BD05B1DFC80ULL,
		0x016E38569E1E2E78ULL,
		0x0000000000000264ULL
	}};
	shift = 52;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B726BDB4DA27A33ULL,
		0x018F0C9FA7403846ULL,
		0x005E0CBC9112D7A6ULL,
		0x29D9E7B25E7928DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E8CC00000000000ULL,
		0x0E118ADC9AF6D368ULL,
		0xB5E98063C327E9D0ULL,
		0x4A378017832F2444ULL,
		0x00000A7679EC979EULL
	}};
	shift = 18;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x375C1E36BA12B902ULL,
		0xE6A4E591AD2A694DULL,
		0x6865ADFE0D63983BULL,
		0xDDA744E5E23AA511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2572040000000000ULL,
		0x54D29A6EB83C6D74ULL,
		0xC73077CD49CB235AULL,
		0x754A22D0CB5BFC1AULL,
		0x000001BB4E89CBC4ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1530F55C944DBE52ULL,
		0x1F88B92EBF6149F4ULL,
		0x57B378E3D9A6A3F0ULL,
		0xA497762554AA6FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x987AAE4A26DF2900ULL,
		0xC45C975FB0A4FA0AULL,
		0xD9BC71ECD351F80FULL,
		0x4BBB12AA5537EDABULL,
		0x0000000000000052ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA47C02A0C081BAD5ULL,
		0x006EE61A07A0BA8BULL,
		0x62967FD315D49500ULL,
		0xCC021B92706F57E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD50000000000000ULL,
		0xA8BA47C02A0C081BULL,
		0x500006EE61A07A0BULL,
		0x7E762967FD315D49ULL,
		0x000CC021B92706F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55546F246936421CULL,
		0x540A06B377D1F368ULL,
		0x41A062A3F51CA600ULL,
		0x4F31738266F5FA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x546F246936421C00ULL,
		0x0A06B377D1F36855ULL,
		0xA062A3F51CA60054ULL,
		0x31738266F5FA1E41ULL,
		0x000000000000004FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14CD0604716A5177ULL,
		0x9F41D992A459006CULL,
		0x693CF9FA52130130ULL,
		0x0B1B5C5955F1F109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28BB800000000000ULL,
		0x80360A66830238B5ULL,
		0x80984FA0ECC9522CULL,
		0xF884B49E7CFD2909ULL,
		0x0000058DAE2CAAF8ULL
	}};
	shift = 17;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1749C337BD75F23ULL,
		0x85E9F6AF987953B3ULL,
		0xB260C4DB70FE5652ULL,
		0xCB07314C3FD9E213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1749C337BD75F23ULL,
		0x85E9F6AF987953B3ULL,
		0xB260C4DB70FE5652ULL,
		0xCB07314C3FD9E213ULL
	}};
	shift = 0;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x785DABC3A991341EULL,
		0xC954AD960939839CULL,
		0x9001BE1F8A45AD3AULL,
		0xAA03039EBC7CE7A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ED5E1D4C89A0F00ULL,
		0xAA56CB049CC1CE3CULL,
		0x00DF0FC522D69D64ULL,
		0x0181CF5E3E73D4C8ULL,
		0x0000000000000055ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72E5DFD6AD9F3049ULL,
		0xF94358E0A936842FULL,
		0x1C7EB0A9B6BB1959ULL,
		0x77F49F05BB6B2EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF982480000000000ULL,
		0xB4217B972EFEB56CULL,
		0xD8CACFCA1AC70549ULL,
		0x597740E3F5854DB5ULL,
		0x000003BFA4F82DDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0846BF0FEEDF4FE7ULL,
		0x70BA9F9FDF9DE462ULL,
		0xBDF7CC7BB7ECECC2ULL,
		0x3A7CE6DB8BB6A59BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF9C0000000000000ULL,
		0x188211AFC3FBB7D3ULL,
		0x309C2EA7E7F7E779ULL,
		0x66EF7DF31EEDFB3BULL,
		0x000E9F39B6E2EDA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00152EB05E2E5112ULL,
		0xE8DFB6DDE7FBF82CULL,
		0xD7965B31EA512AB2ULL,
		0x1F0037D151E432D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78B9444800000000ULL,
		0x9FEFE0B00054BAC1ULL,
		0xA944AACBA37EDB77ULL,
		0x4790CB535E596CC7ULL,
		0x000000007C00DF45ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6689245AD1FCCC7BULL,
		0xED73394686DD7503ULL,
		0xC7F0737E042FD39BULL,
		0xB0D13FED5DEAD715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A24916B47F331ECULL,
		0xB5CCE51A1B75D40DULL,
		0x1FC1CDF810BF4E6FULL,
		0xC344FFB577AB5C57ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x67754956A92AC7DAULL,
		0x3B9A37D24582FA7EULL,
		0xC062E31C394BB8C9ULL,
		0x4E7C372EBDE6BBECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4AB1F68000000000ULL,
		0x60BE9F99DD5255AAULL,
		0x52EE324EE68DF491ULL,
		0x79AEFB3018B8C70EULL,
		0x000000139F0DCBAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA891888DFEF2E3F2ULL,
		0x422073CE88B57FDCULL,
		0xB3F09968FF5B3714ULL,
		0x71B2DA4876DABAC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBFDE5C7E40000000ULL,
		0xD116AFFB95123111ULL,
		0x1FEB66E288440E79ULL,
		0x0EDB5759167E132DULL,
		0x000000000E365B49ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBFD2987A6788A266ULL,
		0xF56CA31DCB01407AULL,
		0xA51F3E34400F03BCULL,
		0xB1E607F33762AE76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94C3D33C45133000ULL,
		0x6518EE580A03D5FEULL,
		0xF9F1A200781DE7ABULL,
		0x303F99BB1573B528ULL,
		0x000000000000058FULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x623FD9FBD4532A97ULL,
		0x3AF5EAFCF80B7DAEULL,
		0x9DE1BCABA1F63B0BULL,
		0x3E2AFD62592B2E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB3F7A8A6552E000ULL,
		0xBD5F9F016FB5CC47ULL,
		0x3795743EC761675EULL,
		0x5FAC4B2565D133BCULL,
		0x00000000000007C5ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5238C503DC9C4BDDULL,
		0x4B096F8B8EEF21EEULL,
		0x9913486F280079FCULL,
		0xF915390751B79CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7400000000000000ULL,
		0xB948E3140F72712FULL,
		0xF12C25BE2E3BBC87ULL,
		0x72644D21BCA001E7ULL,
		0x03E454E41D46DE73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x183EC5C5EEDEEE9DULL,
		0x89FC3E9EF5C0565FULL,
		0xB06EF5894FB76F7DULL,
		0x030318711E102337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF774E80000000000ULL,
		0x02B2F8C1F62E2F76ULL,
		0xBB7BEC4FE1F4F7AEULL,
		0x8119BD8377AC4A7DULL,
		0x0000001818C388F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x934B9BC51832AD75ULL,
		0x72883B6141664D13ULL,
		0x916B80014572897BULL,
		0xE4A0C7CE379BA179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2E6F1460CAB5D40ULL,
		0xA20ED850599344E4ULL,
		0x5AE000515CA25EDCULL,
		0x2831F38DE6E85E64ULL,
		0x0000000000000039ULL
	}};
	shift = 58;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC393AFAB741F5284ULL,
		0x2CE452347FF724BAULL,
		0xF87E79C764BAED07ULL,
		0xA408C30B284A4467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFAB741F5284000ULL,
		0x452347FF724BAC39ULL,
		0xE79C764BAED072CEULL,
		0x8C30B284A4467F87ULL,
		0x0000000000000A40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F1C28EAA09904ECULL,
		0x69D02F1499194BBCULL,
		0x09933C81AA0F2AC3ULL,
		0xCA9FBFD6DF4D87EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x413209D800000000ULL,
		0x323297783E3851D5ULL,
		0x541E5586D3A05E29ULL,
		0xBE9B0FD613267903ULL,
		0x00000001953F7FADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B7A9FFF11B6D218ULL,
		0x20A453E0D867BDB5ULL,
		0x8C04E5D4D7EB9F5BULL,
		0x34CAC989CF2D584CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA76F53FFE236DA43ULL,
		0x64148A7C1B0CF7B6ULL,
		0x91809CBA9AFD73EBULL,
		0x0699593139E5AB09ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC6E54079F36EBB9ULL,
		0x4064FAB727B1E59FULL,
		0x876EEB81543788DDULL,
		0x762CB82390025EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3CF9B75DC8000000ULL,
		0xB93D8F2CFE6372A0ULL,
		0x0AA1BC46EA0327D5ULL,
		0x1C8012F7FC3B775CULL,
		0x0000000003B165C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x467CA753FE7A4833ULL,
		0xF3DE50B619B01FF7ULL,
		0x38A234B9E8BA2620ULL,
		0x640000978955878BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A9FF3D24198000ULL,
		0x285B0CD80FFBA33EULL,
		0x1A5CF45D131079EFULL,
		0x004BC4AAC3C59C51ULL,
		0x0000000000003200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB653B8C8466D39CBULL,
		0x77252CCEE290B1C6ULL,
		0x6E0B3C6C1B3E3FDEULL,
		0x785112391C97818EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8466D39CB000000ULL,
		0xCEE290B1C6B653B8ULL,
		0x6C1B3E3FDE77252CULL,
		0x391C97818E6E0B3CULL,
		0x0000000000785112ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F04C31E854155DCULL,
		0xF27EF04E3DDE53CDULL,
		0x81A4C58018E058C6ULL,
		0x553EAB2EC77A0D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB800000000000000ULL,
		0x9ADE09863D0A82ABULL,
		0x8DE4FDE09C7BBCA7ULL,
		0x3303498B0031C0B1ULL,
		0x00AA7D565D8EF41BULL
	}};
	shift = 7;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5D9EC93F2A2A238ULL,
		0x118B30FE2AA285CFULL,
		0xB72E81F7945930B6ULL,
		0x3B2137544495C24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1767B24FCA8A88E0ULL,
		0x462CC3F8AA8A173FULL,
		0xDCBA07DE5164C2D8ULL,
		0xEC84DD5112570936ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F09299C26542A60ULL,
		0xEE1B306B98625C2BULL,
		0x9FD3EE1C2269E3E0ULL,
		0xD4754F7E9C92A926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F09299C26542A60ULL,
		0xEE1B306B98625C2BULL,
		0x9FD3EE1C2269E3E0ULL,
		0xD4754F7E9C92A926ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F8FA788CE3FF126ULL,
		0x2570E0460EE57810ULL,
		0xAF77E1787BB2F89CULL,
		0xA506D501E30C953AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3FF1260000000000ULL,
		0xE578107F8FA788CEULL,
		0xB2F89C2570E0460EULL,
		0x0C953AAF77E1787BULL,
		0x000000A506D501E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23FE847C48536C28ULL,
		0xA9FC2AE399054FF8ULL,
		0x9C352AFAE370DEC4ULL,
		0x587BAD8B74D418E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB614000000000000ULL,
		0xA7FC11FF423E2429ULL,
		0x6F6254FE1571CC82ULL,
		0x0C724E1A957D71B8ULL,
		0x00002C3DD6C5BA6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4809D58474C1518EULL,
		0x56E4D915BC698896ULL,
		0xEFFF619CB92F6E9FULL,
		0xFF2BFBF99D92CBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5463800000000000ULL,
		0x6225920275611D30ULL,
		0xDBA7D5B936456F1AULL,
		0xB2F7BBFFD8672E4BULL,
		0x00003FCAFEFE6764ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E89E3C2E2A6F788ULL,
		0xF6E3C701DF5E11E7ULL,
		0x7FBA384945E1946EULL,
		0xDA7DC2CAA8F993BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1537BC4000000000ULL,
		0xFAF08F39744F1E17ULL,
		0x2F0CA377B71E380EULL,
		0x47CC9DEBFDD1C24AULL,
		0x00000006D3EE1655ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4211723AB7DD6D6BULL,
		0x2DB17AA72227415FULL,
		0xDE7D395452550A06ULL,
		0x9C124542BEEA405BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AB7DD6D6B000000ULL,
		0xA72227415F421172ULL,
		0x5452550A062DB17AULL,
		0x42BEEA405BDE7D39ULL,
		0x00000000009C1245ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82BD3E42597907F1ULL,
		0x73EA462E5E61F088ULL,
		0x46F07D4485E4C0C2ULL,
		0x7AB5E2F9FA4FAA04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC84B2F20FE200000ULL,
		0xC5CBCC3E111057A7ULL,
		0xA890BC98184E7D48ULL,
		0x5F3F49F54088DE0FULL,
		0x00000000000F56BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x655DD18F80F0B67EULL,
		0x29A1F7CF6817F69FULL,
		0xBA68AABD44F20BA1ULL,
		0x5739F2DEE3493DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x785B3F0000000000ULL,
		0x0BFB4FB2AEE8C7C0ULL,
		0x7905D094D0FBE7B4ULL,
		0xA49EDFDD34555EA2ULL,
		0x0000002B9CF96F71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC4589B0D1D4A2E7ULL,
		0xF6A4AEB5169F543FULL,
		0x9C66F6552D2D39B1ULL,
		0x8407BFF7B5404D8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0xFCC4589B0D1D4A2EULL,
		0x1F6A4AEB5169F543ULL,
		0xD9C66F6552D2D39BULL,
		0x08407BFF7B5404D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC497A012B72913E2ULL,
		0x1D54E13795E8B73AULL,
		0xE8F51C84D381DD63ULL,
		0xBD18C53CA90C71DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB72913E200000000ULL,
		0x95E8B73AC497A012ULL,
		0xD381DD631D54E137ULL,
		0xA90C71DAE8F51C84ULL,
		0x00000000BD18C53CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BF61912322156A4ULL,
		0xE8C7F6B0D07C2847ULL,
		0x050B9F4907A15C3FULL,
		0x03C5E5C76B546D09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA400000000000000ULL,
		0x479BF61912322156ULL,
		0x3FE8C7F6B0D07C28ULL,
		0x09050B9F4907A15CULL,
		0x0003C5E5C76B546DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7502EF9CFBBE50EULL,
		0x13D14F6DE4AAF3C0ULL,
		0x9FA41FC4B82B9E1CULL,
		0xDB293972C8358281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBE73EEF94380000ULL,
		0x3DB792ABCF02DD40ULL,
		0x7F12E0AE78704F45ULL,
		0xE5CB20D60A067E90ULL,
		0x0000000000036CA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 238;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F7141126E37A108ULL,
		0x974ECCB4BD606C0CULL,
		0xF2F81E39A9B4C4B3ULL,
		0xD20EB260B62D27F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89371BD084000000ULL,
		0x5A5EB036063FB8A0ULL,
		0x1CD4DA6259CBA766ULL,
		0x305B1693FAF97C0FULL,
		0x0000000000690759ULL
	}};
	shift = 41;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15225347C9B07DE9ULL,
		0x85E8F65EA1DAE349ULL,
		0x8C1A4125BDDF8EE0ULL,
		0xEEC51ECB83E37956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F26C1F7A4000000ULL,
		0x7A876B8D2454894DULL,
		0x96F77E3B8217A3D9ULL,
		0x2E0F8DE55A306904ULL,
		0x0000000003BB147BULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x709F08701E751333ULL,
		0x88493CB767FE42A3ULL,
		0x384C29725CDB3E87ULL,
		0x68A9DFB7954AAAEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A8999800000000ULL,
		0x3FF2151B84F84380ULL,
		0xE6D9F43C4249E5BBULL,
		0xAA555779C2614B92ULL,
		0x00000003454EFDBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x116119EBE45B14FAULL,
		0x88A2E55F3B5477E7ULL,
		0x2C50BDB6AE39D450ULL,
		0x91D66CC1CB9E99B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119EBE45B14FA000ULL,
		0x2E55F3B5477E7116ULL,
		0x0BDB6AE39D45088AULL,
		0x66CC1CB9E99B92C5ULL,
		0x000000000000091DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31723BACAAEE3317ULL,
		0x654D69A968BE5369ULL,
		0x2EFEF715BCA8FC6BULL,
		0xE89DF9F7577412AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB8CC5C0000000000ULL,
		0xF94DA4C5C8EEB2ABULL,
		0xA3F1AD9535A6A5A2ULL,
		0xD04ABCBBFBDC56F2ULL,
		0x000003A277E7DD5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA4FA9A8A9C9A898ULL,
		0x80E42C574E46A2C1ULL,
		0xEE6338CD83D6A297ULL,
		0xB87EB64F9F5B54B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8980000000000000ULL,
		0x2C1CA4FA9A8A9C9AULL,
		0x29780E42C574E46AULL,
		0x4B3EE6338CD83D6AULL,
		0x000B87EB64F9F5B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BA9C1E8FC7D06C4ULL,
		0xBEB03B8FC4A65675ULL,
		0xC2BD35E1755BBE10ULL,
		0x21C78A6B9DBBDF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E3E836200000000ULL,
		0xE2532B3A8DD4E0F4ULL,
		0xBAADDF085F581DC7ULL,
		0xCEDDEFA6615E9AF0ULL,
		0x0000000010E3C535ULL
	}};
	shift = 33;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C17CC929EA40EC0ULL,
		0x6AAAAFC8361E3F18ULL,
		0xEEA6CB806375566EULL,
		0xF03AD118BB9B27A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1705F324A7A903B0ULL,
		0x9AAAABF20D878FC6ULL,
		0x3BA9B2E018DD559BULL,
		0x3C0EB4462EE6C9E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8577E338D17DD47ULL,
		0xAEBEDEBBF3A0ABCDULL,
		0xF6413CA372A2F76EULL,
		0x926D9D1341A75987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4700000000000000ULL,
		0xCDF8577E338D17DDULL,
		0x6EAEBEDEBBF3A0ABULL,
		0x87F6413CA372A2F7ULL,
		0x00926D9D1341A759ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB129F8A62833C4B3ULL,
		0xCA2B8796555BBE3FULL,
		0x054516D337CC127AULL,
		0xBED90B8FEE399502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF12CC0000000000ULL,
		0x6EF8FEC4A7E298A0ULL,
		0x3049EB28AE1E5955ULL,
		0xE6540815145B4CDFULL,
		0x000002FB642E3FB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x242041878DC4F040ULL,
		0xDA351EAA7C4AAC39ULL,
		0x4325B5D59E9DF902ULL,
		0x66FFE0235CD893EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42041878DC4F0400ULL,
		0xA351EAA7C4AAC392ULL,
		0x325B5D59E9DF902DULL,
		0x6FFE0235CD893EF4ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1FAD7DD11613281BULL,
		0xFEF1F80A26F882EEULL,
		0x48250946225E6E69ULL,
		0xFD91E5353A639AA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE88B09940D800000ULL,
		0x05137C41770FD6BEULL,
		0xA3112F3734FF78FCULL,
		0x9A9D31CD54241284ULL,
		0x00000000007EC8F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2470E490A321FEE3ULL,
		0x404A2FA8D9406D77ULL,
		0xE538BD0E7825FB0EULL,
		0x3B116930DD7A91E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC60000000000000ULL,
		0xAEE48E1C9214643FULL,
		0x61C80945F51B280DULL,
		0x3C7CA717A1CF04BFULL,
		0x0007622D261BAF52ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F15C8FC008E4348ULL,
		0x48E132A1EEB4697BULL,
		0x796C1BEC42656625ULL,
		0x5FBADB6C8D9B0B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE004721A40000000ULL,
		0x0F75A34BD878AE47ULL,
		0x62132B312A470995ULL,
		0x646CD85A33CB60DFULL,
		0x0000000002FDD6DBULL
	}};
	shift = 37;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7AC77DB539B69593ULL,
		0xDE885CEC79CB75E9ULL,
		0x1BEC87E834D8DC90ULL,
		0xE90EB99AF4F6EDBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4E6DA564C000000ULL,
		0xB1E72DD7A5EB1DF6ULL,
		0xA0D36372437A2173ULL,
		0x6BD3DBB6EC6FB21FULL,
		0x0000000003A43AE6ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1FA20D131BE8FD7ULL,
		0xFC72F0A8FC160F7CULL,
		0x877D6F2477860814ULL,
		0x64BA3C241318A998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA20D131BE8FD7000ULL,
		0x2F0A8FC160F7CF1FULL,
		0xD6F2477860814FC7ULL,
		0xA3C241318A998877ULL,
		0x000000000000064BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9003C26238C5250ULL,
		0x0A8F4BCFD54A30ECULL,
		0x07EE44470F30E971ULL,
		0xBE28BE1BDA370184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xD9D200784C4718A4ULL,
		0xE2151E979FAA9461ULL,
		0x080FDC888E1E61D2ULL,
		0x017C517C37B46E03ULL
	}};
	shift = 7;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2A5F1DD8E163FA9ULL,
		0xC6D7812D3E01D146ULL,
		0x5E08B7108E2712C3ULL,
		0xEE45CFD29E330992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1C2C7F520000000ULL,
		0xA7C03A28D654BE3BULL,
		0x11C4E25878DAF025ULL,
		0x53C661324BC116E2ULL,
		0x000000001DC8B9FAULL
	}};
	shift = 35;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC13323EBEFE05125ULL,
		0xD01837330E36E9D4ULL,
		0xB3DC2AEB5273C776ULL,
		0x19B52890539D4E0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4494000000000000ULL,
		0xA75304CC8FAFBF81ULL,
		0x1DDB4060DCCC38DBULL,
		0x3836CF70ABAD49CFULL,
		0x000066D4A2414E75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD261A67A4109CEB6ULL,
		0x900365756ED5FB40ULL,
		0x52387B2227DE308AULL,
		0x438AF8D4C5080CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x09CEB60000000000ULL,
		0xD5FB40D261A67A41ULL,
		0xDE308A900365756EULL,
		0x080CB952387B2227ULL,
		0x000000438AF8D4C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32C638DBA413DD68ULL,
		0x8CA8B4017C94576CULL,
		0xA92E58FF16611DEBULL,
		0x3A200A1496CB7496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32C638DBA413DD68ULL,
		0x8CA8B4017C94576CULL,
		0xA92E58FF16611DEBULL,
		0x3A200A1496CB7496ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x609E631F08E74E66ULL,
		0xF63B95F2BF760C47ULL,
		0xA4EF878739F2E4FDULL,
		0x6ED0F7B8AC739B8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE9CCC0000000000ULL,
		0xEC188EC13CC63E11ULL,
		0xE5C9FBEC772BE57EULL,
		0xE7371549DF0F0E73ULL,
		0x000000DDA1EF7158ULL
	}};
	shift = 23;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x882735820EC4C5F1ULL,
		0x5F1248FFA6419BCCULL,
		0x773C877DAD8BE73CULL,
		0xC28B9DAAF4FB5F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D898BE200000000ULL,
		0x4C833799104E6B04ULL,
		0x5B17CE78BE2491FFULL,
		0xE9F6BF08EE790EFBULL,
		0x0000000185173B55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xABC1ED8F4A65B2A1ULL,
		0x61EE2DC562A18AC7ULL,
		0xDB2F206030E34D56ULL,
		0x6AF73B6508DF2CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5080000000000000ULL,
		0x63D5E0F6C7A532D9ULL,
		0xAB30F716E2B150C5ULL,
		0x56ED9790301871A6ULL,
		0x00357B9DB2846F96ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9569B7925D6C0288ULL,
		0x8CFB0C55F5D00D89ULL,
		0xFFA1F5EB223A00F3ULL,
		0xC10BEEBCAE0F0A73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAB4DBC92EB601440ULL,
		0x67D862AFAE806C4CULL,
		0xFD0FAF5911D0079CULL,
		0x085F75E57078539FULL,
		0x0000000000000006ULL
	}};
	shift = 61;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7ADA7BA1AD519860ULL,
		0x6DA0628D8A21F781ULL,
		0x3528822EEBE795D0ULL,
		0x46E5F7A8898C3253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86B5466180000000ULL,
		0x362887DE05EB69EEULL,
		0xBBAF9E5741B6818AULL,
		0xA22630C94CD4A208ULL,
		0x00000000011B97DEULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x903AE99EC989D98EULL,
		0x50BD69A47EA88513ULL,
		0x35EF144A90B00A64ULL,
		0x9EEE9A6450DCE666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA67B26276638000ULL,
		0x5A691FAA2144E40EULL,
		0xC512A42C0299142FULL,
		0xA699143739998D7BULL,
		0x00000000000027BBULL
	}};
	shift = 50;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4D047C728A3EBB6ULL,
		0x34E94AF0EEAD623DULL,
		0xEDD41C457257BB28ULL,
		0xF95C2179B0B0EA4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8FAED80000000000ULL,
		0xB588F713411F1CA2ULL,
		0x5EECA0D3A52BC3BAULL,
		0xC3A93FB7507115C9ULL,
		0x000003E57085E6C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB99F2CCC1D0F80FULL,
		0x7ED99063807A424BULL,
		0x8DDE3718539C277BULL,
		0x1FF640D8ABFB7ED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96660E87C0780000ULL,
		0x831C03D2125EDCCFULL,
		0xB8C29CE13BDBF6CCULL,
		0x06C55FDBF6946EF1ULL,
		0x000000000000FFB2ULL
	}};
	shift = 45;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBFADC20A1C03B54ULL,
		0xBE13FE0350402D3DULL,
		0x627449621372EA9EULL,
		0x3ABE4FA7BB92B2D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x01DAA00000000000ULL,
		0x0169EF5FD6E1050EULL,
		0x9754F5F09FF01A82ULL,
		0x9596AB13A24B109BULL,
		0x000001D5F27D3DDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B85D05B2FAFAAF9ULL,
		0xDEEF15D760182DDAULL,
		0x049C2F6998A14CCCULL,
		0xC079E88C7A518BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE400000000000000ULL,
		0x692E17416CBEBEABULL,
		0x337BBC575D8060B7ULL,
		0x641270BDA6628533ULL,
		0x0301E7A231E9462FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D2AD746B4D4AD10ULL,
		0x389A181C676AC19CULL,
		0x33565D786903A0F1ULL,
		0x3C1F3D002BE410DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5688000000000000ULL,
		0x60CE3E956BA35A6AULL,
		0xD0789C4D0C0E33B5ULL,
		0x086D19AB2EBC3481ULL,
		0x00001E0F9E8015F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64D9A89B871A5764ULL,
		0x344B4B049CB98C02ULL,
		0x8C9DF4501DD431C9ULL,
		0xAA546E994297D44DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D2BB20000000000ULL,
		0x5CC601326CD44DC3ULL,
		0xEA18E49A25A5824EULL,
		0x4BEA26C64EFA280EULL,
		0x000000552A374CA1ULL
	}};
	shift = 25;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x103E39641106CBBAULL,
		0x02FA667AF436232CULL,
		0xB1F937BA359F8D13ULL,
		0x9116D269EE43187AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03E39641106CBBA0ULL,
		0x2FA667AF436232C1ULL,
		0x1F937BA359F8D130ULL,
		0x116D269EE43187ABULL,
		0x0000000000000009ULL
	}};
	shift = 60;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1E12C38683A0791ULL,
		0x3740DA1970B4209FULL,
		0xDD5F12B42833DBF4ULL,
		0x7B7596738F17EBD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E12C38683A07910ULL,
		0x740DA1970B4209FBULL,
		0xD5F12B42833DBF43ULL,
		0xB7596738F17EBD5DULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82EADC6AE4EF0A15ULL,
		0x1CA1570D6FBC08D9ULL,
		0xEFD08DCF8775E119ULL,
		0xDEAA9069E9CE8A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B8D5C9DE142A000ULL,
		0x2AE1ADF7811B305DULL,
		0x11B9F0EEBC232394ULL,
		0x520D3D39D14B3DFAULL,
		0x0000000000001BD5ULL
	}};
	shift = 51;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E03366106681C2CULL,
		0x74CC3B2D3CAE9A5EULL,
		0x7BDB43A4D5B78D8FULL,
		0x40D869656BEA8CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x419A070B00000000ULL,
		0x4F2BA6979F80CD98ULL,
		0x356DE363DD330ECBULL,
		0x5AFAA32F9EF6D0E9ULL,
		0x0000000010361A59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15197B541900DC02ULL,
		0xE58C850FA787C8DFULL,
		0xC07853163BF992AEULL,
		0xAC81C365F756D4B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE010000000000000ULL,
		0x46F8A8CBDAA0C806ULL,
		0x95772C64287D3C3EULL,
		0xA5C603C298B1DFCCULL,
		0x0005640E1B2FBAB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6F5BB290DB52C3EULL,
		0x902578C9D6ADCBD7ULL,
		0xA3DF1253AFE45200ULL,
		0x5AFC1F47A17A17A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6A587C000000000ULL,
		0xD5B97AF4DEB76521ULL,
		0xFC8A401204AF193AULL,
		0x2F42F4F47BE24A75ULL,
		0x0000000B5F83E8F4ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FF302C5530C9560ULL,
		0x4C06A7CB4E48BA54ULL,
		0x1C2D52682588014EULL,
		0x0C750E3F77CA0C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2558000000000000ULL,
		0x2E9517FCC0B154C3ULL,
		0x00539301A9F2D392ULL,
		0x830D470B549A0962ULL,
		0x0000031D438FDDF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F9AAC8A425A7264ULL,
		0x860222FBCDFB5E14ULL,
		0x1688E214189D3B3AULL,
		0x2A131BDE47B6354BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2640000000000000ULL,
		0xE140F9AAC8A425A7ULL,
		0xB3A860222FBCDFB5ULL,
		0x54B1688E214189D3ULL,
		0x0002A131BDE47B63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43F50DF34EFAA4E1ULL,
		0x05D6C44AFE66A832ULL,
		0xD6C410EF5B7F2573ULL,
		0xF9615BE6EEEDB473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F9A77D527080000ULL,
		0x2257F33541921FA8ULL,
		0x877ADBF92B982EB6ULL,
		0xDF37776DA39EB620ULL,
		0x000000000007CB0AULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD02040DFA3FF6E4ULL,
		0xD566D5A2B945DBB5ULL,
		0xE0F653F650EEE294ULL,
		0xCAD6CA847414D786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE400000000000000ULL,
		0xB5AD02040DFA3FF6ULL,
		0x94D566D5A2B945DBULL,
		0x86E0F653F650EEE2ULL,
		0x00CAD6CA847414D7ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA24F24029AAC51DAULL,
		0xB3FD98F999EF347EULL,
		0x9DDFD233C42708FCULL,
		0xEB86E32A3BF40451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93C900A6AB147680ULL,
		0xFF663E667BCD1FA8ULL,
		0x77F48CF109C23F2CULL,
		0xE1B8CA8EFD011467ULL,
		0x000000000000003AULL
	}};
	shift = 58;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E4DD038F9092859ULL,
		0x3F11384FAF091DF1ULL,
		0xCA0DF8B72A4BB172ULL,
		0xBEA5E2FB8AAEAE5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC84942C800000000ULL,
		0x7848EF88726E81C7ULL,
		0x525D8B91F889C27DULL,
		0x557572DE506FC5B9ULL,
		0x00000005F52F17DCULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6165D09B0CA37B09ULL,
		0x18C9CFFBB30C70BDULL,
		0x497205ACB9E64D96ULL,
		0x06452F5E028DC552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x58597426C328DEC2ULL,
		0x863273FEECC31C2FULL,
		0x925C816B2E799365ULL,
		0x01914BD780A37154ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE75603571AFEB85FULL,
		0x7DF428394791F94AULL,
		0xBBF9BBB028553DF4ULL,
		0x5B1F27409D1F28A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7F5C2F80000000ULL,
		0xA3C8FCA573AB01ABULL,
		0x142A9EFA3EFA141CULL,
		0x4E8F94515DFCDDD8ULL,
		0x000000002D8F93A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E66C39FF5E086D6ULL,
		0x82B3071438923F47ULL,
		0x174A1139712ED9F5ULL,
		0x4C005B4DD9FD390EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D6000000000000ULL,
		0x3F475E66C39FF5E0ULL,
		0xD9F582B307143892ULL,
		0x390E174A1139712EULL,
		0x00004C005B4DD9FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A4841B7E1EE4D9CULL,
		0x3F1D7594EF7B8C81ULL,
		0x0B223BBC51445CD6ULL,
		0xEB63B74D7880D7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4841B7E1EE4D9C0ULL,
		0xF1D7594EF7B8C810ULL,
		0xB223BBC51445CD63ULL,
		0xB63B74D7880D7E40ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECD679801DA1E519ULL,
		0xE54B5A7CCC33D6D1ULL,
		0xC7671740063564B0ULL,
		0xECC3CCB9323ED9DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE519000000000000ULL,
		0xD6D1ECD679801DA1ULL,
		0x64B0E54B5A7CCC33ULL,
		0xD9DBC76717400635ULL,
		0x0000ECC3CCB9323EULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF81883664867613BULL,
		0xDBB2D2DB5A7AD653ULL,
		0xE0AB90B65877BB36ULL,
		0xD12749BCFCC42453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81883664867613B0ULL,
		0xBB2D2DB5A7AD653FULL,
		0x0AB90B65877BB36DULL,
		0x12749BCFCC42453EULL,
		0x000000000000000DULL
	}};
	shift = 60;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FAA5E25A1C401BDULL,
		0x5C2078DBBA3E136BULL,
		0xC8C05C4AB6493BB4ULL,
		0xDEC26A63F4BEEDD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0xB9FAA5E25A1C401BULL,
		0x45C2078DBBA3E136ULL,
		0x0C8C05C4AB6493BBULL,
		0x0DEC26A63F4BEEDDULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC672D24942805D02ULL,
		0x0D8C672DE14C3198ULL,
		0xC22605FB77C7CDC8ULL,
		0x5EBA765CAD32309AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4A1402E810000000ULL,
		0x6F0A618CC6339692ULL,
		0xDBBE3E6E406C6339ULL,
		0xE5699184D611302FULL,
		0x0000000002F5D3B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73321DFDBF9E82FDULL,
		0x00B835EAB066EA2FULL,
		0x8AAEA5699EA00569ULL,
		0x038247D14DD27799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF417E8000000000ULL,
		0x337517B9990EFEDFULL,
		0x5002B4805C1AF558ULL,
		0xE93BCCC55752B4CFULL,
		0x00000001C123E8A6ULL
	}};
	shift = 25;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF366247648FD4215ULL,
		0xF6F8206AF237C923ULL,
		0x25F7CAFB992BA5F8ULL,
		0x973E68E6E7CE36C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F50854000000000ULL,
		0x8DF248FCD9891D92ULL,
		0x4AE97E3DBE081ABCULL,
		0xF38DB2097DF2BEE6ULL,
		0x00000025CF9A39B9ULL
	}};
	shift = 26;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x419FA3AC939F52A5ULL,
		0xC51D1D38AF55DB0EULL,
		0x37A7F10A3737A7F0ULL,
		0x613D178AB7B2642AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A94000000000000ULL,
		0x6C39067E8EB24E7DULL,
		0x9FC3147474E2BD57ULL,
		0x90A8DE9FC428DCDEULL,
		0x000184F45E2ADEC9ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B88512F005E1659ULL,
		0xFA25CC886C3048F6ULL,
		0x4931F1C6B7103DE0ULL,
		0x0A0DC82CA365E13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB88512F005E16590ULL,
		0xA25CC886C3048F64ULL,
		0x931F1C6B7103DE0FULL,
		0xA0DC82CA365E13B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB391A2D82F55292ULL,
		0x420AD3151312C031ULL,
		0x66C45E934CD181B3ULL,
		0xBB4C4F29D3D231C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4800000000000000ULL,
		0xC7ACE468B60BD54AULL,
		0xCD082B4C544C4B00ULL,
		0x1D9B117A4D334606ULL,
		0x02ED313CA74F48C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD6DA76C6F9C1993ULL,
		0x2339AFA3C6C742CAULL,
		0x17D5FC0080609DDEULL,
		0x9FB515921079C5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9800000000000000ULL,
		0x566B6D3B637CE0CCULL,
		0xF119CD7D1E363A16ULL,
		0x28BEAFE0040304EEULL,
		0x04FDA8AC9083CE2FULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8902320B257B4282ULL,
		0xABDE58889F98AC89ULL,
		0xEFDAB706542BE9FBULL,
		0x29CAC2246BB3307CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x81190592BDA14100ULL,
		0xEF2C444FCC5644C4ULL,
		0xED5B832A15F4FDD5ULL,
		0xE5611235D9983E77ULL,
		0x0000000000000014ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xABA48F7ADC0CBCABULL,
		0xFA3879135C019AEDULL,
		0xFD52CD2FA22982DAULL,
		0xDF89EAC694CA7AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE923DEB7032F2AC0ULL,
		0x8E1E44D70066BB6AULL,
		0x54B34BE88A60B6BEULL,
		0xE27AB1A5329EBD3FULL,
		0x0000000000000037ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x413345D5495FCD9AULL,
		0x955B21DF5E82E35EULL,
		0x55CD9DCB65A5700DULL,
		0xC41543A7F25C24EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xE413345D5495FCD9ULL,
		0xD955B21DF5E82E35ULL,
		0xB55CD9DCB65A5700ULL,
		0x0C41543A7F25C24EULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5B180C3F3726977ULL,
		0x3BBDE79A7A2FACACULL,
		0xF596752FE56C7197ULL,
		0x234935A85EF67EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8C061F9B934BB80ULL,
		0xDEF3CD3D17D6566AULL,
		0xCB3A97F2B638CB9DULL,
		0xA49AD42F7B3F7E7AULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x463AF1006860E003ULL,
		0x59163F193E1B2A18ULL,
		0x9C20925845A81FE5ULL,
		0xD117CC92919765F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3AF1006860E00300ULL,
		0x163F193E1B2A1846ULL,
		0x20925845A81FE559ULL,
		0x17CC92919765F19CULL,
		0x00000000000000D1ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99A16E4DB88980E7ULL,
		0xC525F53EC9432A79ULL,
		0xCABF71FF5B7973C2ULL,
		0xCF2C0C66B2E45919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0E70000000000000ULL,
		0xA7999A16E4DB8898ULL,
		0x3C2C525F53EC9432ULL,
		0x919CABF71FF5B797ULL,
		0x000CF2C0C66B2E45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB040B35666499508ULL,
		0x13E9744709069A14ULL,
		0xD922973B2135BB1EULL,
		0x8F49CDDA26F4FB12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0800000000000000ULL,
		0x14B040B356664995ULL,
		0x1E13E9744709069AULL,
		0x12D922973B2135BBULL,
		0x008F49CDDA26F4FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5E615C341799442ULL,
		0x73DB551A5C2B6115ULL,
		0xCEA7B36A9FF4198BULL,
		0x27A3CD5C75FEB765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBCC2B8682F32884ULL,
		0xE7B6AA34B856C22BULL,
		0x9D4F66D53FE83316ULL,
		0x4F479AB8EBFD6ECBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA35AAE7A47916904ULL,
		0x9E583C1C41144036ULL,
		0x524D54CAACC765F8ULL,
		0x6093F2F1CC8F7DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD573D23C8B48200ULL,
		0x2C1E0E208A201B51ULL,
		0x26AA655663B2FC4FULL,
		0x49F978E647BEF6A9ULL,
		0x0000000000000030ULL
	}};
	shift = 57;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAEB08E27E8B06C08ULL,
		0x55F6AF73B68F907EULL,
		0xE211718D124B0CD5ULL,
		0xCC44730BCFE9E9DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84713F4583604000ULL,
		0xB57B9DB47C83F575ULL,
		0x8B8C68925866AAAFULL,
		0x23985E7F4F4EFF10ULL,
		0x0000000000000662ULL
	}};
	shift = 53;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC936E6B065895D3ULL,
		0x6BCC407C5A6E744DULL,
		0x9F67BDA1D000D6A0ULL,
		0xED0C2D6BD9C417BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74C0000000000000ULL,
		0x137F24DB9AC19625ULL,
		0xA81AF3101F169B9DULL,
		0xEEA7D9EF68740035ULL,
		0x003B430B5AF67105ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x700ABB2384F4EEEAULL,
		0x1D5E9DAD8DDBF541ULL,
		0x7DBFDABB13D7A650ULL,
		0xE08CA00A283FF8A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x0B8055D91C27A777ULL,
		0x80EAF4ED6C6EDFAAULL,
		0x33EDFED5D89EBD32ULL,
		0x070465005141FFC5ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB461BB1237E1BEC4ULL,
		0x1599559F1E74926DULL,
		0x8E9B67F499DB7F69ULL,
		0xD764D27CC76D2C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x186EC48DF86FB100ULL,
		0x665567C79D249B6DULL,
		0xA6D9FD2676DFDA45ULL,
		0xD9349F31DB4B2663ULL,
		0x0000000000000035ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6F797E4A26EF5A0ULL,
		0xAF3AB8B50091884BULL,
		0x43BD53DE8717B900ULL,
		0xACC4BD5FAB22549FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0x25FB7BCBF251377AULL,
		0x80579D5C5A8048C4ULL,
		0x4FA1DEA9EF438BDCULL,
		0x0056625EAFD5912AULL
	}};
	shift = 9;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9F5127678DB2611BULL,
		0x140576B829B8F9F8ULL,
		0xD2C4D0AA45803F2EULL,
		0x5A5E6D24DF3EFE8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78DB2611B0000000ULL,
		0x829B8F9F89F51276ULL,
		0xA45803F2E140576BULL,
		0x4DF3EFE8AD2C4D0AULL,
		0x0000000005A5E6D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x109FF3B34B9E2A83ULL,
		0xD361A76CB9F41D66ULL,
		0xAF2E9CD9C74334A7ULL,
		0x9B88866C9B7D51B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9A5CF15418000000ULL,
		0x65CFA0EB3084FF9DULL,
		0xCE3A19A53E9B0D3BULL,
		0x64DBEA8D957974E6ULL,
		0x0000000004DC4433ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71FCC0C7F2C501CEULL,
		0x5AA05969343E48CEULL,
		0x2C685074B5301B22ULL,
		0x153B4D45811C0E86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF96280E700000000ULL,
		0x9A1F246738FE6063ULL,
		0x5A980D912D502CB4ULL,
		0xC08E07431634283AULL,
		0x000000000A9DA6A2ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21BFBCF0D17340DDULL,
		0x780233B42BE21768ULL,
		0xE2AD6D5FAF9D2A17ULL,
		0x2F9FED785F54BD80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0x410DFDE7868B9A06ULL,
		0xBBC0119DA15F10BBULL,
		0x07156B6AFD7CE950ULL,
		0x017CFF6BC2FAA5ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15B741AD377DE47DULL,
		0x65A9BE911AD51A32ULL,
		0x2FC511664C4D9956ULL,
		0x1724869FED15E3DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06B4DDF791F40000ULL,
		0xFA446B5468C856DDULL,
		0x45993136655996A6ULL,
		0x1A7FB4578F6CBF14ULL,
		0x0000000000005C92ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0C6A7912F674C87ULL,
		0xBE779D527CA042E8ULL,
		0x3A9F025A4C5FD233ULL,
		0x6E7B609BC6D81D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBD9D321C00000000ULL,
		0xF2810BA3831A9E44ULL,
		0x317F48CEF9DE7549ULL,
		0x1B607490EA7C0969ULL,
		0x00000001B9ED826FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x342DC00CC2426F6AULL,
		0x292F2E4E0A7DC7F5ULL,
		0xA1A8333C27FC106FULL,
		0xA902A423EA637E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA16E006612137B50ULL,
		0x4979727053EE3FA9ULL,
		0x0D4199E13FE08379ULL,
		0x4815211F531BF1C5ULL,
		0x0000000000000005ULL
	}};
	shift = 61;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C934742FD43BB01ULL,
		0x58A85AC0F7C3535BULL,
		0x46AAB82B3D19BFF4ULL,
		0xD9D8E32D3BE4CC9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E85FA8776020000ULL,
		0xB581EF86A6B6F926ULL,
		0x70567A337FE8B150ULL,
		0xC65A77C9993C8D55ULL,
		0x000000000001B3B1ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF571515CB3144244ULL,
		0x544CB4DAF313A248ULL,
		0xC3F51CE4882838BAULL,
		0x0311183CFD934CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA212200000000000ULL,
		0x9D1247AB8A8AE598ULL,
		0x41C5D2A265A6D798ULL,
		0x9A665E1FA8E72441ULL,
		0x0000001888C1E7ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAB7F0AFD3C566490ULL,
		0xEE7A10FEFCF5FB29ULL,
		0x3FA07DAF96FA43FFULL,
		0x855DE17483BF5D5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F0AFD3C56649000ULL,
		0x7A10FEFCF5FB29ABULL,
		0xA07DAF96FA43FFEEULL,
		0x5DE17483BF5D5B3FULL,
		0x0000000000000085ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A76604DEAA2A12AULL,
		0x4216596B7C18B586ULL,
		0xF6241617DFE9B604ULL,
		0xEE96C41B7F498B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53B3026F55150950ULL,
		0x10B2CB5BE0C5AC32ULL,
		0xB120B0BEFF4DB022ULL,
		0x74B620DBFA4C5BEFULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0xC189AECCD69DE784ULL,
		0xE768C8A0692BB682ULL,
		0x0EAC2ABE4B18DD55ULL,
		0x6F86316D1007D196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0B0626BB335A779EULL,
		0x579DA32281A4AEDAULL,
		0x583AB0AAF92C6375ULL,
		0x01BE18C5B4401F46ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BE1E9B69878748CULL,
		0xFCAD3F0BFEBF415EULL,
		0x8C9F01D6851C7F44ULL,
		0x62913FB427573F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD230000000000000ULL,
		0x0579AF87A6DA61E1ULL,
		0xFD13F2B4FC2FFAFDULL,
		0xFC42327C075A1471ULL,
		0x00018A44FED09D5CULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5367354177139020ULL,
		0x38BC8D166D6F0DD3ULL,
		0xA0FE1C4C412E95D2ULL,
		0xCEC3A3BA9E844F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E40800000000000ULL,
		0xBC374D4D9CD505DCULL,
		0xBA5748E2F23459B5ULL,
		0x113D1E83F8713104ULL,
		0x0000033B0E8EEA7AULL
	}};
	shift = 22;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x802673A78096D5FEULL,
		0x496B76415623612DULL,
		0x8E6294A697471B8EULL,
		0x25520886C6B68253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B6AFF0000000000ULL,
		0x11B096C01339D3C0ULL,
		0xA38DC724B5BB20ABULL,
		0x5B4129C7314A534BULL,
		0x00000012A9044363ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x239855B5A42B95E5ULL,
		0x8B0A292541168BC4ULL,
		0x1946A764A5E5E4D2ULL,
		0xCB694D9C1C6446BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA42B95E500000000ULL,
		0x41168BC4239855B5ULL,
		0xA5E5E4D28B0A2925ULL,
		0x1C6446BD1946A764ULL,
		0x00000000CB694D9CULL
	}};
	shift = 32;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07F604E33B44C63EULL,
		0xF028FC7C2334C245ULL,
		0x11C45B456B7EB61DULL,
		0x05119500AE8EFCB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F00000000000000ULL,
		0x2283FB02719DA263ULL,
		0x0EF8147E3E119A61ULL,
		0x5908E22DA2B5BF5BULL,
		0x000288CA8057477EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56F3199129425ACBULL,
		0x628D6B013072D7BFULL,
		0x34949DB2107277F1ULL,
		0xB4AD3287E95D8FA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5096B2C000000000ULL,
		0x1CB5EFD5BCC6644AULL,
		0x1C9DFC58A35AC04CULL,
		0x5763E80D25276C84ULL,
		0x0000002D2B4CA1FAULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4BF40E9D4410E609ULL,
		0x26B73AD6FAAC7C94ULL,
		0x5CD4A16B558F5309ULL,
		0xEB3B959DFF229791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2400000000000000ULL,
		0x512FD03A75104398ULL,
		0x249ADCEB5BEAB1F2ULL,
		0x45735285AD563D4CULL,
		0x03ACEE5677FC8A5EULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0194F754CC6A900ULL,
		0x6FFF0FA46D56B483ULL,
		0x6F2E763B5174A536ULL,
		0xBB646B530F759C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E00CA7BAA663548ULL,
		0xB37FF87D236AB5A4ULL,
		0x0B7973B1DA8BA529ULL,
		0x05DB235A987BACE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48184562E432D15FULL,
		0xD91EC6CA8C437E5EULL,
		0x7E2595A6FC52D2CEULL,
		0x6A64131FAB21A623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB90CB457C0000000ULL,
		0xA310DF9792061158ULL,
		0xBF14B4B3B647B1B2ULL,
		0xEAC86988DF896569ULL,
		0x000000001A9904C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CC8F4967363522FULL,
		0x67DA29059BF7F7E7ULL,
		0x6D70CE00AFFD63F6ULL,
		0xE61E8DBF15F84BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F00000000000000ULL,
		0xE78CC8F496736352ULL,
		0xF667DA29059BF7F7ULL,
		0xC86D70CE00AFFD63ULL,
		0x00E61E8DBF15F84BULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BC00B3CB27A317CULL,
		0x8110C63D3B0907DCULL,
		0x510E465BCE5C27E8ULL,
		0xDBA47C9B66919215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9E8C5F000000000ULL,
		0xEC241F71EF002CF2ULL,
		0x39709FA2044318F4ULL,
		0x9A4648554439196FULL,
		0x000000036E91F26DULL
	}};
	shift = 30;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x690ECC9E85918C39ULL,
		0x710945BD256F3EF5ULL,
		0x2E58B4609E771145ULL,
		0x72B3194DF971F399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0B23187200000000ULL,
		0x4ADE7DEAD21D993DULL,
		0x3CEE228AE2128B7AULL,
		0xF2E3E7325CB168C1ULL,
		0x00000000E566329BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCEE19B5FFDBB7C1DULL,
		0x3D5FD87D373D2650ULL,
		0xF5D85ABF8164868DULL,
		0xA90AD572E33DC88BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D00000000000000ULL,
		0x50CEE19B5FFDBB7CULL,
		0x8D3D5FD87D373D26ULL,
		0x8BF5D85ABF816486ULL,
		0x00A90AD572E33DC8ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FFC305C0CEE749BULL,
		0x8A3616C0773EB64DULL,
		0x3E1199B6E2E8DBF9ULL,
		0xFDAC23DDA15566F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B819DCE9360000ULL,
		0x2D80EE7D6C9A5FF8ULL,
		0x336DC5D1B7F3146CULL,
		0x47BB42AACDE27C23ULL,
		0x000000000001FB58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5280BE74B9692B7ULL,
		0x422B750B04887575ULL,
		0xC59965999C5E363EULL,
		0x8BC2FBA14E3A031FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2E5A4ADC000000ULL,
		0x2C1221D5D694A02FULL,
		0x667178D8F908ADD4ULL,
		0x8538E80C7F166596ULL,
		0x00000000022F0BEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8BE386CF37D33F18ULL,
		0x7C5E75A0F6A14E42ULL,
		0xEC939ABC7C4733BEULL,
		0xF2CB539C1B5C6B31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79BE99F8C0000000ULL,
		0x07B50A72145F1C36ULL,
		0xE3E2399DF3E2F3ADULL,
		0xE0DAE3598F649CD5ULL,
		0x0000000007965A9CULL
	}};
	shift = 37;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E84504AFB356B5DULL,
		0xB0951965AC4000CBULL,
		0x0BA4C326A363B371ULL,
		0xC7F0F936AA6136F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1412BECD5AD74000ULL,
		0x46596B100032C7A1ULL,
		0x30C9A8D8ECDC6C25ULL,
		0x3E4DAA984DBD82E9ULL,
		0x00000000000031FCULL
	}};
	shift = 50;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x291462C952D82A13ULL,
		0x3EB4B9FE20B25782ULL,
		0x7BF1A9D82389CE7DULL,
		0x8017671E66876201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C00000000000000ULL,
		0x08A4518B254B60A8ULL,
		0xF4FAD2E7F882C95EULL,
		0x05EFC6A7608E2739ULL,
		0x02005D9C799A1D88ULL
	}};
	shift = 6;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA2C9CC35131065B0ULL,
		0x96709D41A579D041ULL,
		0x7015725F137F6780ULL,
		0x2ED373A977FC2E50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x834593986A2620CBULL,
		0x012CE13A834AF3A0ULL,
		0xA0E02AE4BE26FECFULL,
		0x005DA6E752EFF85CULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4742BE8B356D5465ULL,
		0xA346AF2D78A6CC58ULL,
		0x6AB581053D74AE6CULL,
		0x11C3337407A0E2B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCA00000000000000ULL,
		0xB08E857D166ADAA8ULL,
		0xD9468D5E5AF14D98ULL,
		0x70D56B020A7AE95CULL,
		0x00238666E80F41C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB43DF60B2E25C57FULL,
		0x1E74CA99E8936CB9ULL,
		0x4EFC712229EE3217ULL,
		0xF5713EFCEAF0A100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15FC000000000000ULL,
		0xB2E6D0F7D82CB897ULL,
		0xC85C79D32A67A24DULL,
		0x84013BF1C488A7B8ULL,
		0x0003D5C4FBF3ABC2ULL
	}};
	shift = 14;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x536B5DD4D008C1A0ULL,
		0x22BE87A81FA14842ULL,
		0x1D9F0E6710A8970FULL,
		0x14C23B48A51F9B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2536B5DD4D008C1AULL,
		0xF22BE87A81FA1484ULL,
		0xB1D9F0E6710A8970ULL,
		0x014C23B48A51F9B6ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x710FEC91B2F01424ULL,
		0x38DA938735562430ULL,
		0x258B5416849A49CFULL,
		0x1A31D2B90D3B0773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC91B2F0142400000ULL,
		0x38735562430710FEULL,
		0x416849A49CF38DA9ULL,
		0x2B90D3B0773258B5ULL,
		0x000000000001A31DULL
	}};
	shift = 44;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B6BE672CFC5FF39ULL,
		0x3FFBB2E4EC97B8F1ULL,
		0x789B77586CCA3B0EULL,
		0x6F318B48CE632458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9C80000000000000ULL,
		0x789DB5F33967E2FFULL,
		0x871FFDD972764BDCULL,
		0x2C3C4DBBAC36651DULL,
		0x003798C5A4673192ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7AD02DD4C27A550ULL,
		0x1F2F6B3102DD4B06ULL,
		0x2F61A8688132BF1EULL,
		0x25E356F77EC6B61DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA613D2A8000000ULL,
		0x98816EA58363D681ULL,
		0x3440995F8F0F97B5ULL,
		0x7BBF635B0E97B0D4ULL,
		0x000000000012F1ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 233;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD076CE08110AD0AULL,
		0x1263DE52A103333CULL,
		0x6B9E013B80A3CDDAULL,
		0x13F5A2E1D6E31675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x820442B428000000ULL,
		0x4A840CCCF2F41DB3ULL,
		0xEE028F3768498F79ULL,
		0x875B8C59D5AE7804ULL,
		0x00000000004FD68BULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D1D99DE95986D28ULL,
		0xBAD98AB64040B4CEULL,
		0x2AE12C0184921D0BULL,
		0x0AC6E1C1A465EE25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCEF4ACC3694000ULL,
		0xCC55B20205A67168ULL,
		0x09600C2490E85DD6ULL,
		0x370E0D232F712957ULL,
		0x0000000000000056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C55DAE178070F8AULL,
		0x6751A4B44BC04F4EULL,
		0x0BC5A3801EF51CABULL,
		0x5D7EBC35EC977B3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1400000000000000ULL,
		0x9C98ABB5C2F00E1FULL,
		0x56CEA3496897809EULL,
		0x7E178B47003DEA39ULL,
		0x00BAFD786BD92EF6ULL
	}};
	shift = 7;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A3DC76D13E40EFCULL,
		0xD71862A6652DDF4EULL,
		0x06EE36D27127944EULL,
		0x47889D9B650AA30FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x74D1EE3B689F2077ULL,
		0x76B8C31533296EFAULL,
		0x783771B693893CA2ULL,
		0x023C44ECDB285518ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9AAE3519E60BD33CULL,
		0x98451E792E00429DULL,
		0x5FD4B4DD4244C582ULL,
		0x83E3A69B5F6B281DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD571A8CF305E99E0ULL,
		0xC228F3C9700214ECULL,
		0xFEA5A6EA12262C14ULL,
		0x1F1D34DAFB5940EAULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCF10EA1EBF21592ULL,
		0x5A0DD651E38D50F4ULL,
		0xE99F8A3FD532C68FULL,
		0x8401B85B97B69EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9000000000000000ULL,
		0xA7E788750F5F90ACULL,
		0x7AD06EB28F1C6A87ULL,
		0xE74CFC51FEA99634ULL,
		0x04200DC2DCBDB4F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDD5479E642D97C1ULL,
		0xFB2BA70F1118E77BULL,
		0x42E2CF4167DD29A1ULL,
		0x8AEE644BC99D523CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCBE0800000000000ULL,
		0x73BDE6EAA3CF3216ULL,
		0x94D0FD95D387888CULL,
		0xA91E217167A0B3EEULL,
		0x000045773225E4CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7B07775AF79F6D3ULL,
		0xA630F3834647B29FULL,
		0xFE6BBF39773E3A85ULL,
		0x52BAF1A66C116848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3D83BBAD7BCFB698ULL,
		0x31879C1A323D94FFULL,
		0xF35DF9CBB9F1D42DULL,
		0x95D78D33608B4247ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91E841EAFA69DC78ULL,
		0x71BCDB691BD74D17ULL,
		0x846F5ACDE67110D0ULL,
		0x159198B26A8113DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x5E47A107ABE9A771ULL,
		0x41C6F36DA46F5D34ULL,
		0x6A11BD6B3799C443ULL,
		0x00564662C9AA044FULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7257BEE06480112CULL,
		0xAFCC40359F3B7A89ULL,
		0x5C3A2AEEF7BF0279ULL,
		0x8CAA1EA0FB231E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7257BEE06480112CULL,
		0xAFCC40359F3B7A89ULL,
		0x5C3A2AEEF7BF0279ULL,
		0x8CAA1EA0FB231E87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4C91A20B0D951C2ULL,
		0x244CAA8F84FD2091ULL,
		0x8CACA8009D716EC0ULL,
		0x7814A37CC0E11D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE100000000000000ULL,
		0x48E2648D10586CA8ULL,
		0x6012265547C27E90ULL,
		0xA8C65654004EB8B7ULL,
		0x003C0A51BE60708EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02C816CD489BDD86ULL,
		0xD34E5D175F223369ULL,
		0x3D289546F0DBB3D9ULL,
		0xE21497F8484B15C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0B205B35226F7618ULL,
		0x4D39745D7C88CDA4ULL,
		0xF4A2551BC36ECF67ULL,
		0x88525FE1212C5718ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x147E2265A00C6471ULL,
		0x5B59CAB7B84F111CULL,
		0x95D47C23516BF501ULL,
		0xD941C258F8B7C725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x803191C400000000ULL,
		0xE13C447051F88996ULL,
		0x45AFD4056D672ADEULL,
		0xE2DF1C965751F08DULL,
		0x0000000365070963ULL
	}};
	shift = 30;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11BBCF9ABA3E4D7DULL,
		0x8AEF1566D3069AF6ULL,
		0x804945B3E1449C69ULL,
		0x21CE468CB5B5B1A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCF9ABA3E4D7D0000ULL,
		0x1566D3069AF611BBULL,
		0x45B3E1449C698AEFULL,
		0x468CB5B5B1A18049ULL,
		0x00000000000021CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79F379FAE9BA5259ULL,
		0x841DF975F7BBAFE4ULL,
		0xF74C4DD9013D45E8ULL,
		0xBB42C524717DC24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE9BA52590000000ULL,
		0x5F7BBAFE479F379FULL,
		0x9013D45E8841DF97ULL,
		0x4717DC24EF74C4DDULL,
		0x000000000BB42C52ULL
	}};
	shift = 36;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CB10FBD2A460963ULL,
		0x0B31C63001314402ULL,
		0x9887DA4ACEB72F0EULL,
		0xD0888CD9AE92A7C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE952304B1800000ULL,
		0x180098A201465887ULL,
		0x25675B97870598E3ULL,
		0x6CD74953E24C43EDULL,
		0x0000000000684446ULL
	}};
	shift = 41;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1DDB15344DA326E7ULL,
		0x49C20318F17558B5ULL,
		0xE672980A36108031ULL,
		0xB08DCE2D90DB526AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE700000000000000ULL,
		0xB51DDB15344DA326ULL,
		0x3149C20318F17558ULL,
		0x6AE672980A361080ULL,
		0x00B08DCE2D90DB52ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4918F5ED3492A63FULL,
		0x5C4F758BF205E590ULL,
		0x5C5DD717B21C6A09ULL,
		0xA6D2707243A2EFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7E0000000000000ULL,
		0xB209231EBDA69254ULL,
		0x412B89EEB17E40BCULL,
		0xFDEB8BBAE2F6438DULL,
		0x0014DA4E0E48745DULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3467BF25B05B16C1ULL,
		0x18BA1F9D09E1C849ULL,
		0x72E26D6A2E0E5DEDULL,
		0x9EF8A9A4435F338FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC96C16C5B040000ULL,
		0x7E7427872124D19EULL,
		0xB5A8B83977B462E8ULL,
		0xA6910D7CCE3DCB89ULL,
		0x0000000000027BE2ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8B5A3415F7933DFULL,
		0xDD8B3C7908BB26E5ULL,
		0x79156EE9BBC4CD06ULL,
		0x5B462DB11146D691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF267BE000000000ULL,
		0x1764DCBF16B4682BULL,
		0x7899A0DBB1678F21ULL,
		0x28DAD22F22ADDD37ULL,
		0x0000000B68C5B622ULL
	}};
	shift = 27;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8079E5308839E2F7ULL,
		0xD5763AF18CA459D7ULL,
		0xD300F2DCC7574FAFULL,
		0x93DD08E5E4E6FF41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C5EE00000000000ULL,
		0x8B3AF00F3CA61107ULL,
		0xE9F5FAAEC75E3194ULL,
		0xDFE83A601E5B98EAULL,
		0x0000127BA11CBC9CULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB10DAE207AF06726ULL,
		0x568712A5433A4947ULL,
		0x48260F250633A57BULL,
		0xC58F136040AB12B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD886D7103D783393ULL,
		0xAB438952A19D24A3ULL,
		0xA41307928319D2BDULL,
		0x62C789B020558958ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7663246447E72DAULL,
		0x8829B9170636F82FULL,
		0x0FB82ECAB36CDFE5ULL,
		0x87409BCA911BB3B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0xBEDD98C91911F9CBULL,
		0x9620A6E45C18DBE0ULL,
		0xDC3EE0BB2ACDB37FULL,
		0x021D026F2A446ECEULL
	}};
	shift = 6;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF09F4F3384C37988ULL,
		0xE4DAE27812C00CBAULL,
		0x2951E14F609B3F2EULL,
		0x3C591476128B623DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x986F310000000000ULL,
		0x5801975E13E9E670ULL,
		0x1367E5DC9B5C4F02ULL,
		0x516C47A52A3C29ECULL,
		0x000000078B228EC2ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BAE582D87D25526ULL,
		0xCCA186AE0BC36A83ULL,
		0x60BA136F856A59DEULL,
		0x8BECB200C2D02F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD255260000000000ULL,
		0xC36A836BAE582D87ULL,
		0x6A59DECCA186AE0BULL,
		0xD02F5360BA136F85ULL,
		0x0000008BECB200C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x287AC99A8EC3A4ABULL,
		0x6AAF043C264043B4ULL,
		0x3AC049A658FC653DULL,
		0x4E015DB0CD4FF7F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x43D64CD4761D2558ULL,
		0x557821E132021DA1ULL,
		0xD6024D32C7E329EBULL,
		0x700AED866A7FBFB9ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33EBAB498B2A8DB7ULL,
		0x04B23C5CE5213889ULL,
		0x8C5B843D3B84FCB5ULL,
		0x8A4F3813E6B68369ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x4CFAEAD262CAA36DULL,
		0x412C8F1739484E22ULL,
		0x6316E10F4EE13F2DULL,
		0x2293CE04F9ADA0DAULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCED1156E5DA473F7ULL,
		0x7648BAE9E32F12B8ULL,
		0x921A7298AF315D94ULL,
		0x36A55F4FE4395644ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA22ADCBB48E7EE00ULL,
		0x9175D3C65E25719DULL,
		0x34E5315E62BB28ECULL,
		0x4ABE9FC872AC8924ULL,
		0x000000000000006DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 183;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x01EFC90870793B6CULL,
		0xEDFBC7588956821CULL,
		0xB18A46A3F43DFB1DULL,
		0x5954E3B482CFEE97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00F7E484383C9DB6ULL,
		0xF6FDE3AC44AB410EULL,
		0xD8C52351FA1EFD8EULL,
		0x2CAA71DA4167F74BULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x143635BAB6CAA789ULL,
		0x3998CFE2FC13AFFDULL,
		0xCAAD27A93B8E99EAULL,
		0x1B78534956D1CF5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BAB6CAA7890000ULL,
		0xCFE2FC13AFFD1436ULL,
		0x27A93B8E99EA3998ULL,
		0x534956D1CF5CCAADULL,
		0x0000000000001B78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71B88833FE04D17BULL,
		0x01D88E4E0237362AULL,
		0x0CEA31015E2A32BCULL,
		0xBCE8AD2DCA5D3F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6E220CFF81345EC0ULL,
		0x762393808DCD8A9CULL,
		0x3A8C40578A8CAF00ULL,
		0x3A2B4B72974FD683ULL,
		0x000000000000002FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3D1768F1CBAAD31ULL,
		0xCE1CB4E9C0D7FEF3ULL,
		0x5DCC5C9BD4CCBEAFULL,
		0xC0728D7521E6B642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xF4F45DA3C72EAB4CULL,
		0xF3872D3A7035FFBCULL,
		0x97731726F5332FABULL,
		0x301CA35D4879AD90ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x927251066EEC5159ULL,
		0x85A9AF59BB948DF1ULL,
		0x01EE33877CA00235ULL,
		0x67893804F700FD50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEEC5159000000000ULL,
		0xB948DF1927251066ULL,
		0xCA0023585A9AF59BULL,
		0x700FD5001EE33877ULL,
		0x000000067893804FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7E3460053351A0CULL,
		0x72D125C5E29612D5ULL,
		0x39B279D2D94E073AULL,
		0x93AE31D252E41513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A34180000000000ULL,
		0x2C25ABCFC68C00A6ULL,
		0x9C0E74E5A24B8BC5ULL,
		0xC82A267364F3A5B2ULL,
		0x000001275C63A4A5ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x390BA1651D58DCE0ULL,
		0xD0D8781E9F3DA75EULL,
		0x6124DED5B8B5609EULL,
		0x400F7AA9F218E7F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E8594756373800ULL,
		0x361E07A7CF69D78EULL,
		0x4937B56E2D5827B4ULL,
		0x03DEAA7C8639FC58ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x709EC4E50A84E6DAULL,
		0xB502ABD29E947B85ULL,
		0x2732AA0FB28A1207ULL,
		0x8B300A9DDB1BB7B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D00000000000000ULL,
		0xC2B84F6272854273ULL,
		0x03DA8155E94F4A3DULL,
		0xDC13995507D94509ULL,
		0x004598054EED8DDBULL
	}};
	shift = 9;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72F9C34EF875005BULL,
		0xA92F136B92E905E2ULL,
		0xB5E1B9CB0E47B11CULL,
		0x3B790F860E43F03AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C34EF875005B000ULL,
		0xF136B92E905E272FULL,
		0x1B9CB0E47B11CA92ULL,
		0x90F860E43F03AB5EULL,
		0x00000000000003B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x629764F7E93C3BDBULL,
		0x479BCB4D2756D256ULL,
		0xB8501A9B8C53CDA5ULL,
		0xB4EC4052B44D0CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x877B600000000000ULL,
		0xDA4ACC52EC9EFD27ULL,
		0x79B4A8F37969A4EAULL,
		0xA198770A0353718AULL,
		0x0000169D880A5689ULL
	}};
	shift = 19;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC37AFF725ADCF039ULL,
		0x620B93BB8937CBB0ULL,
		0x99F25DD3E3D1BF9BULL,
		0xB908E6883E93F066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C80000000000000ULL,
		0xD861BD7FB92D6E78ULL,
		0xCDB105C9DDC49BE5ULL,
		0x334CF92EE9F1E8DFULL,
		0x005C8473441F49F8ULL
	}};
	shift = 9;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AB85E17EEF705B8ULL,
		0xBCAC3215DF7C7803ULL,
		0x374C3CE5745798CDULL,
		0x17BB79CEFBFFB591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5570BC2FDDEE0B70ULL,
		0x7958642BBEF8F006ULL,
		0x6E9879CAE8AF319BULL,
		0x2F76F39DF7FF6B22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89566527C3E61497ULL,
		0xB6AA9E0709331F3EULL,
		0x78FFE9D491C73858ULL,
		0xAAE192F5E1A9680BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8525C00000000000ULL,
		0xC7CFA2559949F0F9ULL,
		0xCE162DAAA781C24CULL,
		0x5A02DE3FFA752471ULL,
		0x00002AB864BD786AULL
	}};
	shift = 18;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94D89371718656DDULL,
		0xAEDA72C62C25D321ULL,
		0x9139A52394799DADULL,
		0x19EF0F996361B2F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3624DC5C6195B740ULL,
		0xB69CB18B0974C865ULL,
		0x4E6948E51E676B6BULL,
		0x7BC3E658D86CBD64ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A40EF3AA6C11FDBULL,
		0x61DAFD9E8A976564ULL,
		0x4BBBDDEFA0C0E906ULL,
		0x2C2B27021E7945B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6C0000000000000ULL,
		0x5922903BCEA9B047ULL,
		0x419876BF67A2A5D9ULL,
		0x6E52EEF77BE8303AULL,
		0x000B0AC9C0879E51ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63F7BAE7C4D2B35EULL,
		0x6622DC83970608B6ULL,
		0xC0CED0043D5B7AB0ULL,
		0x10914777383920A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEEB9F134ACD7800ULL,
		0x8B720E5C1822D98FULL,
		0x3B4010F56DEAC198ULL,
		0x451DDCE0E4829703ULL,
		0x0000000000000042ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B538E69E11234CCULL,
		0x996CF80E047101FAULL,
		0x2CAC97C56E40EE29ULL,
		0x914F0D6E1C5F4745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2469980000000000ULL,
		0xE203F496A71CD3C2ULL,
		0x81DC5332D9F01C08ULL,
		0xBE8E8A59592F8ADCULL,
		0x000001229E1ADC38ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1019D55AF51007A7ULL,
		0x8B06C782AE4F465EULL,
		0x88EB6FCD6BB25FD1ULL,
		0x7F408E457C1C5E4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA200F4E0000000ULL,
		0x55C9E8CBC2033AABULL,
		0xAD764BFA3160D8F0ULL,
		0xAF838BC9911D6DF9ULL,
		0x000000000FE811C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94C1F5275B49D5CCULL,
		0x10FE21E5849440D0ULL,
		0xDB1D81A8FEC1ADEFULL,
		0x5DD3B399123A4EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1F5275B49D5CC00ULL,
		0xFE21E5849440D094ULL,
		0x1D81A8FEC1ADEF10ULL,
		0xD3B399123A4EE3DBULL,
		0x000000000000005DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0793CAAF3224D2E8ULL,
		0x02366C4F5A70D8FCULL,
		0x3DA327704B898396ULL,
		0x30F5968B35F7B08AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA00000000000000ULL,
		0x3F01E4F2ABCC8934ULL,
		0xE5808D9B13D69C36ULL,
		0x228F68C9DC12E260ULL,
		0x000C3D65A2CD7DECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4BD559602BFE965ULL,
		0x50A47749A0BAA97BULL,
		0x02E5B9BB46C07A78ULL,
		0x995383CF91748846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C057FD2CA000000ULL,
		0x93417552F7A97AABULL,
		0x768D80F4F0A148EEULL,
		0x9F22E9108C05CB73ULL,
		0x000000000132A707ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E343ACD6ABB4BF7ULL,
		0x5435B7601BBF3908ULL,
		0x89E05E92607ED487ULL,
		0xF428E52CCA5A0DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB4BF7000000000ULL,
		0xBBF39083E343ACD6ULL,
		0x07ED4875435B7601ULL,
		0xA5A0DC689E05E926ULL,
		0x0000000F428E52CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18DE8AF61CF41659ULL,
		0xCB9C217CE4300883ULL,
		0xA15C8E4D5A3AC2D2ULL,
		0x2E0C0686F65D8C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4165900000000000ULL,
		0x0088318DE8AF61CFULL,
		0xAC2D2CB9C217CE43ULL,
		0xD8C56A15C8E4D5A3ULL,
		0x000002E0C0686F65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6047A8A3268D8583ULL,
		0xA779DD3EB84225D8ULL,
		0x1EAB1B1A6246FCA1ULL,
		0x3A70A06C3E2F97CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4519346C2C180000ULL,
		0xE9F5C2112EC3023DULL,
		0xD8D31237E50D3BCEULL,
		0x0361F17CBE50F558ULL,
		0x000000000001D385ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x241A4E9C113347C9ULL,
		0x6243281F276483A9ULL,
		0x5B2195FD2094367AULL,
		0xE7197CB9AA7D0706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C9000000000000ULL,
		0x83A9241A4E9C1133ULL,
		0x367A6243281F2764ULL,
		0x07065B2195FD2094ULL,
		0x0000E7197CB9AA7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFB23B017B4AB149ULL,
		0xE01E1521C1793612ULL,
		0x2E6C6F8062EAE5B7ULL,
		0xBB66A680F7A8C571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF647602F69562920ULL,
		0x03C2A4382F26C255ULL,
		0xCD8DF00C5D5CB6FCULL,
		0x6CD4D01EF518AE25ULL,
		0x0000000000000017ULL
	}};
	shift = 59;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6690C170AF2F8040ULL,
		0x647ED4D453BD86C7ULL,
		0xB57F75EBFD7DCE17ULL,
		0x7AD7A369FF34C57FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D9A4305C2BCBE01ULL,
		0x5D91FB53514EF61BULL,
		0xFED5FDD7AFF5F738ULL,
		0x01EB5E8DA7FCD315ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB40B85FBC209FE2CULL,
		0x0AD978643EEC5EA0ULL,
		0x36425A921A7A0261ULL,
		0x2F7142221B794012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x0B40B85FBC209FE2ULL,
		0x10AD978643EEC5EAULL,
		0x236425A921A7A026ULL,
		0x02F7142221B79401ULL
	}};
	shift = 4;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x714175663C581FA6ULL,
		0xF686FAEC8938FA20ULL,
		0x6BDA25A220DAFFB9ULL,
		0x7EB8C8C5F02815EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9800000000000000ULL,
		0x81C505D598F1607EULL,
		0xE7DA1BEBB224E3E8ULL,
		0xADAF689688836BFEULL,
		0x01FAE32317C0A057ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E965CCBEA92099EULL,
		0xF4AD0827A042C149ULL,
		0xC8FF33164DEAB107ULL,
		0x93A46DF77034BB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA59732FAA4826780ULL,
		0x2B4209E810B05267ULL,
		0x3FCCC5937AAC41FDULL,
		0xE91B7DDC0D2EC7B2ULL,
		0x0000000000000024ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA98080188D4113EULL,
		0x993EF8104E746D4BULL,
		0x9E7D62D80B42F239ULL,
		0x1E7E167F0EEE7958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13E0000000000000ULL,
		0xD4BEA98080188D41ULL,
		0x239993EF8104E746ULL,
		0x9589E7D62D80B42FULL,
		0x0001E7E167F0EEE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9EDAFD586BAAD98ULL,
		0x08E34CFE4C199203ULL,
		0x1997968F9EC7BF6FULL,
		0x38A58CF3E9E8A2DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAEAB660000000000ULL,
		0x066480EA7B6BF561ULL,
		0xB1EFDBC238D33F93ULL,
		0x7A28B70665E5A3E7ULL,
		0x0000000E29633CFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x576BA5E7B7431E9BULL,
		0x4A498F3C8A38932EULL,
		0x9E6ABCCFFD0AAD4BULL,
		0x59312BAEE962159FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA5E7B7431E9B000ULL,
		0x98F3C8A38932E576ULL,
		0xABCCFFD0AAD4B4A4ULL,
		0x12BAEE962159F9E6ULL,
		0x0000000000000593ULL
	}};
	shift = 52;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x246007B20BED67F4ULL,
		0x07BC851EBAD6DB7EULL,
		0xC93C1AA1C5C831F2ULL,
		0xA35029B63CDE7D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FB59FD000000000ULL,
		0xEB5B6DF891801EC8ULL,
		0x1720C7C81EF2147AULL,
		0xF379F50F24F06A87ULL,
		0x000000028D40A6D8ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A6E3169BDA559ACULL,
		0xFAE3FB1D83D47CE0ULL,
		0x4410813376DC7867ULL,
		0x86FE2AB45E0425F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC62D37B4AB3580ULL,
		0x5C7F63B07A8F9C05ULL,
		0x8210266EDB8F0CFFULL,
		0xDFC5568BC084BE08ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA09B6BA73B416907ULL,
		0x83A90A4F748D5D18ULL,
		0x195761AB5469ECE2ULL,
		0xD3195A20A6B726B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA09B6BA73B416907ULL,
		0x83A90A4F748D5D18ULL,
		0x195761AB5469ECE2ULL,
		0xD3195A20A6B726B7ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC325FFE082EE3829ULL,
		0x0AB3801B4FD54E8AULL,
		0xCCB24F89200E12BCULL,
		0x7288EBD7758F4926ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x082EE38290000000ULL,
		0xB4FD54E8AC325FFEULL,
		0x9200E12BC0AB3801ULL,
		0x7758F4926CCB24F8ULL,
		0x0000000007288EBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86CF3F5A31A8FB7FULL,
		0x9AA9F5026CBFA491ULL,
		0xB8A9058D3FAFA1B5ULL,
		0x15564DAC48208D9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F5A31A8FB7F0000ULL,
		0xF5026CBFA49186CFULL,
		0x058D3FAFA1B59AA9ULL,
		0x4DAC48208D9CB8A9ULL,
		0x0000000000001556ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CA26DEFC494BD06ULL,
		0xF92300B2DD50D400ULL,
		0x1C3F8D3113A4CE67ULL,
		0x795355C03F036F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0C0000000000000ULL,
		0x8001944DBDF89297ULL,
		0xCCFF2460165BAA1AULL,
		0xEB8387F1A6227499ULL,
		0x000F2A6AB807E06DULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD307FDD2D5B2EFFULL,
		0xF31A5AFE271430EBULL,
		0x81E04B73BE303AA1ULL,
		0x9879C6B4145232BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6AD977F800000000ULL,
		0x38A1875DE983FEE9ULL,
		0xF181D50F98D2D7F1ULL,
		0xA29195D40F025B9DULL,
		0x00000004C3CE35A0ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x749C6F929E04A779ULL,
		0x26B2161E5BEAB903ULL,
		0x1D490357439AAB54ULL,
		0xA8D13A557A33C3DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53C094EF20000000ULL,
		0xCB7D57206E938DF2ULL,
		0xE873556A84D642C3ULL,
		0xAF46787BC3A9206AULL,
		0x00000000151A274AULL
	}};
	shift = 35;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA465B2F7567146EDULL,
		0x2FCDEA5457BD4E41ULL,
		0x527492739FA465BCULL,
		0xB2361361C9DD15F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5EEACE28DDA00000ULL,
		0x4A8AF7A9C8348CB6ULL,
		0x4E73F48CB785F9BDULL,
		0x6C393BA2BF0A4E92ULL,
		0x00000000001646C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63E50B3B340C7D23ULL,
		0xE31745CB0EE2BF35ULL,
		0xAAE506644FF5E486ULL,
		0xD8773B0671D57C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA46000000000000ULL,
		0x7E6AC7CA16766818ULL,
		0xC90DC62E8B961DC5ULL,
		0xF91155CA0CC89FEBULL,
		0x0001B0EE760CE3AAULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E57411A78188989ULL,
		0x8370550F39BBDB38ULL,
		0xA4EA796F5DEAADBBULL,
		0x9B5B97CA6F478304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5D0469E062262400ULL,
		0xC1543CE6EF6CE179ULL,
		0xA9E5BD77AAB6EE0DULL,
		0x6E5F29BD1E0C1293ULL,
		0x000000000000026DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26577E52F18F4FC6ULL,
		0xEDDFE9C9EAFD6FBDULL,
		0xCC27C033F01C3A9EULL,
		0x4511D37212630D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E9F8C0000000000ULL,
		0xFADF7A4CAEFCA5E3ULL,
		0x38753DDBBFD393D5ULL,
		0xC61A6F984F8067E0ULL,
		0x0000008A23A6E424ULL
	}};
	shift = 23;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38FE1BB1CC52BC47ULL,
		0x5BA12F8D6CA8DC4FULL,
		0xD5937C8E9426BDCBULL,
		0x316F2A50703137B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDD8E6295E2380000ULL,
		0x7C6B6546E279C7F0ULL,
		0xE474A135EE5ADD09ULL,
		0x52838189BDCEAC9BULL,
		0x0000000000018B79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC430C407A704F7C6ULL,
		0xE14D1CD61931DF33ULL,
		0x6F2280D776B0FA6BULL,
		0x0BFF30620E31EF69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF4E09EF8C0000000ULL,
		0xC3263BE678861880ULL,
		0xEED61F4D7C29A39AULL,
		0x41C63DED2DE4501AULL,
		0x00000000017FE60CULL
	}};
	shift = 35;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD576328744F244DULL,
		0x60C8076431750D78ULL,
		0xD4318C86615DD96EULL,
		0x88037EA479F4CE60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x3F55D8CA1D13C913ULL,
		0x983201D90C5D435EULL,
		0x350C63219857765BULL,
		0x2200DFA91E7D3398ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA09EC5784B5527C8ULL,
		0x62EDFBB7E97FFAB5ULL,
		0x9833C88838D5B79DULL,
		0xEDB4F524C8F9EA2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA09EC5784B5527C8ULL,
		0x62EDFBB7E97FFAB5ULL,
		0x9833C88838D5B79DULL,
		0xEDB4F524C8F9EA2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BBE81E3D92597F5ULL,
		0x460A57304A144658ULL,
		0xB1E5CF8A3BE86A46ULL,
		0xA76AAB46907EEACEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B2FEA000000000ULL,
		0x4288CB0577D03C7BULL,
		0x7D0D48C8C14AE609ULL,
		0x0FDD59D63CB9F147ULL,
		0x00000014ED5568D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x836544461EC9BA5FULL,
		0x5F147BADE9C9478DULL,
		0x32C044A793E9852FULL,
		0x3887CD10DCD8EA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA888C3D9374BE00ULL,
		0x28F75BD3928F1B06ULL,
		0x80894F27D30A5EBEULL,
		0x0F9A21B9B1D48065ULL,
		0x0000000000000071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x493F7998DBB82547ULL,
		0x1B16C576F776A46CULL,
		0xD465F3DB87A26219ULL,
		0x390CAF6AE20E3CC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A38000000000000ULL,
		0x236249FBCCC6DDC1ULL,
		0x10C8D8B62BB7BBB5ULL,
		0xE616A32F9EDC3D13ULL,
		0x0001C8657B571071ULL
	}};
	shift = 13;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0A45504391B0835ULL,
		0x1B350490F2575DE6ULL,
		0x50DCAA1AF01AF47AULL,
		0xCC6EF2AE84B62823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x087236106A000000ULL,
		0x21E4AEBBCD8148AAULL,
		0x35E035E8F4366A09ULL,
		0x5D096C5046A1B954ULL,
		0x000000000198DDE5ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07A24D89EDB49C9AULL,
		0xE0FED833D0A3A61EULL,
		0xED89BAC481672693ULL,
		0xCDAAB89E6BDAB956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3400000000000000ULL,
		0x3C0F449B13DB6939ULL,
		0x27C1FDB067A1474CULL,
		0xADDB13758902CE4DULL,
		0x019B55713CD7B572ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02DF0A6EDE394FF9ULL,
		0x40BEC5754DE4D2C7ULL,
		0xA5A9A807E1D314F9ULL,
		0x42664942B5218BDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA7FC800000000000ULL,
		0x6963816F85376F1CULL,
		0x8A7CA05F62BAA6F2ULL,
		0xC5EDD2D4D403F0E9ULL,
		0x0000213324A15A90ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9A7245696569557ULL,
		0x03B7F4EAEE3C059CULL,
		0xF8C2837E5A3227ACULL,
		0xF6210310402ADE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B4AAB800000000ULL,
		0x71E02CE5CD3922B4ULL,
		0xD1913D601DBFA757ULL,
		0x0156F317C6141BF2ULL,
		0x00000007B1081882ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F7062DBDDA8485FULL,
		0x384F52CEC79A41E3ULL,
		0x6EA937927C3D16FAULL,
		0x761CAD7136849C82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F76A1217C000000ULL,
		0x3B1E69078DFDC18BULL,
		0x49F0F45BE8E13D4BULL,
		0xC4DA127209BAA4DEULL,
		0x0000000001D872B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0D94D91DFC2BE3CULL,
		0xC7F10D36C46D8E54ULL,
		0x21FFFCA445BF3ECCULL,
		0x229CE7AC31BF289CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91DFC2BE3C000000ULL,
		0x36C46D8E54C0D94DULL,
		0xA445BF3ECCC7F10DULL,
		0xAC31BF289C21FFFCULL,
		0x0000000000229CE7ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF3363B685CA4A8EULL,
		0xF11060FBE0F4D604ULL,
		0x775FA1668EC33524ULL,
		0x4EF7D6625E833980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5470000000000000ULL,
		0xB027799B1DB42E52ULL,
		0xA927888307DF07A6ULL,
		0xCC03BAFD0B347619ULL,
		0x000277BEB312F419ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD7A9ED8366E652A7ULL,
		0x7AD4A1A24124B5B1ULL,
		0xD8D865A0BD36B279ULL,
		0x9ABE61A00E1A449BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E652A7000000000ULL,
		0x124B5B1D7A9ED836ULL,
		0xD36B2797AD4A1A24ULL,
		0xE1A449BD8D865A0BULL,
		0x00000009ABE61A00ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE947B8C4D40EA94DULL,
		0x02857640FA4418C4ULL,
		0x982A3EF9412B8119ULL,
		0x6F9499A9B81DFD6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x9D28F7189A81D529ULL,
		0x2050AEC81F488318ULL,
		0xB30547DF28257023ULL,
		0x0DF293353703BFADULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x10FCFF84B7991E3AULL,
		0x6B3AFE674D36D5FEULL,
		0x4AFD24EE65D644F1ULL,
		0x8932E43F1F5BF838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xE10FCFF84B7991E3ULL,
		0x16B3AFE674D36D5FULL,
		0x84AFD24EE65D644FULL,
		0x08932E43F1F5BF83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5DC7FA746106521ULL,
		0xBDFFC9232C797AC5ULL,
		0x6F4B0C9184013995ULL,
		0x2F87695580D8B28CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE3FD3A308329080ULL,
		0xFFE491963CBD62DAULL,
		0xA58648C2009CCADEULL,
		0xC3B4AAC06C594637ULL,
		0x0000000000000017ULL
	}};
	shift = 57;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9306E514B934D5E5ULL,
		0xCDB8771889799E8AULL,
		0x82A1EE8D16DE9D35ULL,
		0x1D74A1E2E1043AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C1B9452E4D35794ULL,
		0x36E1DC6225E67A2AULL,
		0x0A87BA345B7A74D7ULL,
		0x75D2878B8410EBBAULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60122781EAEBA032ULL,
		0x9FB4CFCC8FF9EC63ULL,
		0x3CA9FB46E8F06607ULL,
		0x8FF4C4653BEF3DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4064000000000000ULL,
		0xD8C6C0244F03D5D7ULL,
		0xCC0F3F699F991FF3ULL,
		0x7B767953F68DD1E0ULL,
		0x00011FE988CA77DEULL
	}};
	shift = 15;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53EF9BDE41E05FAAULL,
		0x9FBAAFBA68250523ULL,
		0x8883BFED5B899031ULL,
		0x6FF98316321661F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FBE6F7907817EA8ULL,
		0x7EEABEE9A094148DULL,
		0x220EFFB56E2640C6ULL,
		0xBFE60C58C85987E6ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2CF1AA69828D19BULL,
		0x60E0E343D45CF7B1ULL,
		0xD7AB9579BFD42BC3ULL,
		0xD8BC3C5D255BDCADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCF1AA69828D19B00ULL,
		0xE0E343D45CF7B1E2ULL,
		0xAB9579BFD42BC360ULL,
		0xBC3C5D255BDCADD7ULL,
		0x00000000000000D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB696ADF1F2D4F3D4ULL,
		0x5178E29FF4B10F50ULL,
		0x68C44B62C15B5B3EULL,
		0xAF955086B8353FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB53CF500000000ULL,
		0xFD2C43D42DA5AB7CULL,
		0xB056D6CF945E38A7ULL,
		0xAE0D4FF29A3112D8ULL,
		0x000000002BE55421ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1B3D9A451A1F8A61ULL,
		0xB79AB40080C25C8EULL,
		0x1C49F5C6B3ACE514ULL,
		0x9D8D3CB7819E79F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xECD228D0FC530800ULL,
		0xD5A0040612E470D9ULL,
		0x4FAE359D6728A5BCULL,
		0x69E5BC0CF3CFB0E2ULL,
		0x00000000000004ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFF9EC2327ED91DBULL,
		0xD01868392BF54A95ULL,
		0x7B36DE574D798213ULL,
		0x73CC2E2601EA0EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27ED91DB00000000ULL,
		0x2BF54A95AFF9EC23ULL,
		0x4D798213D0186839ULL,
		0x01EA0EC47B36DE57ULL,
		0x0000000073CC2E26ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x614B315D50BAD586ULL,
		0x0E500324A23891E6ULL,
		0x964D6E3A45AD7BF8ULL,
		0x0DED16733C860F64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB56180000000000ULL,
		0xE24799852CC57542ULL,
		0xB5EFE039400C9288ULL,
		0x183D925935B8E916ULL,
		0x00000037B459CCF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CAC8F55A063EB7CULL,
		0xE2806E13242E139CULL,
		0xB5435CC157599D2EULL,
		0xEA18967544D488F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C7D6F8000000000ULL,
		0x85C273919591EAB4ULL,
		0xEB33A5DC500DC264ULL,
		0x9A911F16A86B982AULL,
		0x0000001D4312CEA8ULL
	}};
	shift = 27;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x182D415C70FDD9B7ULL,
		0xCED160C4937902E3ULL,
		0x821B8F1BCB7483ECULL,
		0x457E57AAB21411BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEECDB80000000000ULL,
		0xC81718C16A0AE387ULL,
		0xA41F66768B06249BULL,
		0xA08DD410DC78DE5BULL,
		0x0000022BF2BD5590ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1AF7F16892D3BDA3ULL,
		0x85E73BA91D0A5EE9ULL,
		0xE714860333790A37ULL,
		0x5521BC966C5225E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC5A24B4EF68C000ULL,
		0xCEEA474297BA46BDULL,
		0x2180CCDE428DE179ULL,
		0x6F259B14897979C5ULL,
		0x0000000000001548ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x49D885204BF5042DULL,
		0x0712AC0D2956734EULL,
		0x510232CEB66E0FC6ULL,
		0x56078E4A49BDC61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x24EC429025FA8216ULL,
		0x0389560694AB39A7ULL,
		0x288119675B3707E3ULL,
		0x2B03C72524DEE30FULL
	}};
	shift = 1;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0016C3F5DC8F3509ULL,
		0x8734359039B718EFULL,
		0x2CBADA0D15760B23ULL,
		0x83A5798F608EC59DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02D87EBB91E6A120ULL,
		0xE686B20736E31DE0ULL,
		0x975B41A2AEC16470ULL,
		0x74AF31EC11D8B3A5ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8689B1C4FE7E4BD1ULL,
		0xBE1F956AC0A3117BULL,
		0x75C7D43294E5ACC1ULL,
		0xEBF444D6301DB6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE880000000000000ULL,
		0xBDC344D8E27F3F25ULL,
		0x60DF0FCAB5605188ULL,
		0x573AE3EA194A72D6ULL,
		0x0075FA226B180EDBULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93C30736C5032588ULL,
		0x1647E205577EFD59ULL,
		0x285C5066A3E3A780ULL,
		0x470342EF1DD25247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x993C30736C503258ULL,
		0x01647E205577EFD5ULL,
		0x7285C5066A3E3A78ULL,
		0x0470342EF1DD2524ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6D2BF5840292708ULL,
		0xDCFD63DD083C7F51ULL,
		0xFBDC0F45541010FFULL,
		0xD97D63BC91A2EAC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAC2014938400000ULL,
		0x1EE841E3FA8FB695ULL,
		0x7A2AA08087FEE7EBULL,
		0x1DE48D175627DEE0ULL,
		0x000000000006CBEBULL
	}};
	shift = 45;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54F235E071E4A03FULL,
		0xB4D471C8BD731585ULL,
		0x9CECF9CBFA351388ULL,
		0x513A67A612B7B3CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x791AF038F2501F80ULL,
		0x6A38E45EB98AC2AAULL,
		0x767CE5FD1A89C45AULL,
		0x9D33D3095BD9E54EULL,
		0x0000000000000028ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8588F85245086980ULL,
		0xBDBD3328D2CFCA88ULL,
		0x9C4D2FCD49CA81AAULL,
		0xB08A0801700E3793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9800000000000000ULL,
		0xA888588F85245086ULL,
		0x1AABDBD3328D2CFCULL,
		0x7939C4D2FCD49CA8ULL,
		0x000B08A0801700E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B01FFAB7AE5CE1EULL,
		0x1A2D6D9E50B9B76FULL,
		0x8D914D5210228074ULL,
		0x908EC7C8C519FCB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE1E00000000000ULL,
		0x9B76F3B01FFAB7AEULL,
		0x280741A2D6D9E50BULL,
		0x9FCB18D914D52102ULL,
		0x00000908EC7C8C51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE6C196E744FBA6CFULL,
		0x292BAB2294BA9CA0ULL,
		0x659DEA1690E1E058ULL,
		0xA59DFB0D4B2A02A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6CF000000000000ULL,
		0x9CA0E6C196E744FBULL,
		0xE058292BAB2294BAULL,
		0x02A7659DEA1690E1ULL,
		0x0000A59DFB0D4B2AULL
	}};
	shift = 16;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0A62F0615FF9FD0ULL,
		0xBAB9DB74908C4733ULL,
		0xCEBC46696599BDA7ULL,
		0x0D01056992D12EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFA00000000000000ULL,
		0xE67C14C5E0C2BFF3ULL,
		0xB4F7573B6E921188ULL,
		0xDB59D788CD2CB337ULL,
		0x0001A020AD325A25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FB681E675EECE04ULL,
		0xD0224CA060EB4E24ULL,
		0xD30F41D64C8DE923ULL,
		0x1A119E3785EAAC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681E675EECE04000ULL,
		0x24CA060EB4E244FBULL,
		0xF41D64C8DE923D02ULL,
		0x19E3785EAAC01D30ULL,
		0x00000000000001A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7ECD535734774CB7ULL,
		0xAE04E0A822D179EDULL,
		0x972007A8FDE06393ULL,
		0x9A86E09A0B1F2A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD535734774CB7000ULL,
		0x4E0A822D179ED7ECULL,
		0x007A8FDE06393AE0ULL,
		0x6E09A0B1F2A4D972ULL,
		0x00000000000009A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00A48CF1744DBFBCULL,
		0xBFE5E94BFBD9FD0CULL,
		0x33BCA5087667D8F2ULL,
		0xA1043B4B59E9E394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5D136FEF00000000ULL,
		0xFEF67F430029233CULL,
		0x1D99F63CAFF97A52ULL,
		0xD67A78E50CEF2942ULL,
		0x0000000028410ED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A4D2F7E2E1E94AFULL,
		0x761BE3E59DBC641FULL,
		0xD956BB246B0C12CFULL,
		0xB866A39262409EEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D295E0000000000ULL,
		0x78C83F149A5EFC5CULL,
		0x18259EEC37C7CB3BULL,
		0x813DDDB2AD7648D6ULL,
		0x00000170CD4724C4ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41B71371881B3DD4ULL,
		0xDF17517C06F2A476ULL,
		0x69D79690E3AA6232ULL,
		0xE77D47AEB25AAFD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1371881B3DD40000ULL,
		0x517C06F2A47641B7ULL,
		0x9690E3AA6232DF17ULL,
		0x47AEB25AAFD269D7ULL,
		0x000000000000E77DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B6933C41D440C5AULL,
		0x9B4149B2FDB50BB5ULL,
		0xD55E71B09C7A7940ULL,
		0x2BEDD350E498676FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD440C5A000000000ULL,
		0xDB50BB53B6933C41ULL,
		0xC7A79409B4149B2FULL,
		0x498676FD55E71B09ULL,
		0x00000002BEDD350EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D2A193F262F05C4ULL,
		0x14A04AB9FF7B89AFULL,
		0x308F3692A1F78AAFULL,
		0xE1003C748AA70D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D2A193F262F05C4ULL,
		0x14A04AB9FF7B89AFULL,
		0x308F3692A1F78AAFULL,
		0xE1003C748AA70D5DULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5E1B4136627B071ULL,
		0xA508C3A2098870E3ULL,
		0x36637CD04B404FBEULL,
		0x8A7DB223CC822DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x3D5E1B4136627B07ULL,
		0xEA508C3A2098870EULL,
		0x036637CD04B404FBULL,
		0x08A7DB223CC822DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38E3900638315C26ULL,
		0x18FB6D2BCEA6C733ULL,
		0x115205B5D04C35CAULL,
		0xCE953A87E2470DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0C57098000000000ULL,
		0xA9B1CCCE38E4018EULL,
		0x130D72863EDB4AF3ULL,
		0x91C37B4454816D74ULL,
		0x00000033A54EA1F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57BDC0D7372E18F4ULL,
		0x0ABBCF36068C5F08ULL,
		0x6393B02BBD5AE5BBULL,
		0xA38518071B9B3145ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5EF7035CDCB863D0ULL,
		0x2AEF3CD81A317C21ULL,
		0x8E4EC0AEF56B96ECULL,
		0x8E14601C6E6CC515ULL,
		0x0000000000000002ULL
	}};
	shift = 62;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF23B4F6E5D700956ULL,
		0xEE27E85A089E0E32ULL,
		0xB2CA17EB10284B28ULL,
		0xF3C8B728165DD4DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB975C02558000000ULL,
		0x68227838CBC8ED3DULL,
		0xAC40A12CA3B89FA1ULL,
		0xA05977537ACB285FULL,
		0x0000000003CF22DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x819C3C838AE7C461ULL,
		0xBBE0AC18D8B70C1EULL,
		0x9D3ABFBA68B44CAFULL,
		0xAB83638AF6D45126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x838AE7C461000000ULL,
		0x18D8B70C1E819C3CULL,
		0xBA68B44CAFBBE0ACULL,
		0x8AF6D451269D3ABFULL,
		0x0000000000AB8363ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5238BE7A315F75D2ULL,
		0x533BA1CF022B6094ULL,
		0x2733B595B7B866CFULL,
		0xAEC9BE00CD0B8FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5238BE7A315F75D2ULL,
		0x533BA1CF022B6094ULL,
		0x2733B595B7B866CFULL,
		0xAEC9BE00CD0B8FD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0225A96487FF4784ULL,
		0x300A3B2579D6679EULL,
		0xF2630E26961CD21DULL,
		0x4E5168B79607E46FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921FFD1E10000000ULL,
		0x95E7599E780896A5ULL,
		0x9A58734874C028ECULL,
		0xDE581F91BFC98C38ULL,
		0x00000000013945A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34BDDE16A2CE46FEULL,
		0xCD1CCF198C443AE8ULL,
		0x43FF8266A07D704AULL,
		0xF7EE4BEB08E52960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EEF0B5167237F0ULL,
		0x68E678CC6221D741ULL,
		0x1FFC133503EB8256ULL,
		0xBF725F5847294B02ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB4AC5D0115CF4C5ULL,
		0xF71E7AE211A949A3ULL,
		0xD8C825F3CC17B793ULL,
		0xD518597BC9A77D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96958BA022B9E98AULL,
		0xEE3CF5C423529347ULL,
		0xB1904BE7982F6F27ULL,
		0xAA30B2F7934EFA97ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96138B033F976203ULL,
		0x0171453F8C2D9FD0ULL,
		0x256851A88AB83E3BULL,
		0x577A7217B22D1C8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F2EC40600000000ULL,
		0x185B3FA12C271606ULL,
		0x15707C7602E28A7FULL,
		0x645A39164AD0A351ULL,
		0x00000000AEF4E42FULL
	}};
	shift = 31;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDC762BADFB3485EULL,
		0xC8F37FABB328F72FULL,
		0x52046D6446724DF5ULL,
		0x9A989A5DF50EB038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDDC762BADFB3485EULL,
		0xC8F37FABB328F72FULL,
		0x52046D6446724DF5ULL,
		0x9A989A5DF50EB038ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50876A1BE34AC8FBULL,
		0xA89F17611FE4589AULL,
		0x78AA5314EF779FDDULL,
		0xA79514EF3975F6DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x9421DA86F8D2B23EULL,
		0x6A27C5D847F91626ULL,
		0x1E2A94C53BDDE7F7ULL,
		0x29E5453BCE5D7DB7ULL
	}};
	shift = 2;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80FFE4D755B584BDULL,
		0x0B9E5D07D7258D73ULL,
		0xE3197F18FC93C850ULL,
		0x00EA7E0DC1165FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE4D755B584BD000ULL,
		0xE5D07D7258D7380FULL,
		0x97F18FC93C8500B9ULL,
		0xA7E0DC1165FEAE31ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A5477A35CB65C20ULL,
		0xA4BD292AA6C712E3ULL,
		0xB57B11E9AB0F1AABULL,
		0xDBA6A4DBF596E67EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2E10000000000000ULL,
		0x8971C52A3BD1AE5BULL,
		0x8D55D25E94955363ULL,
		0x733F5ABD88F4D587ULL,
		0x00006DD3526DFACBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E52F0880698C9F1ULL,
		0x87C732E5C5E9EF3CULL,
		0x2CBC76B2D748C621ULL,
		0x084671B76BE7A9D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x844034C64F880000ULL,
		0x972E2F4F79E37297ULL,
		0xB596BA46310C3E39ULL,
		0x8DBB5F3D4E8165E3ULL,
		0x0000000000004233ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E40F80F3AF27611ULL,
		0x0D3596CA24F9CA10ULL,
		0xA083CA5A6E42527EULL,
		0x5C0DD2AAD6A4A157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3AF2761100000000ULL,
		0x24F9CA108E40F80FULL,
		0x6E42527E0D3596CAULL,
		0xD6A4A157A083CA5AULL,
		0x000000005C0DD2AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CE47DCD911AC02BULL,
		0x2FC6493337D9D140ULL,
		0x44441D3FC3937059ULL,
		0x93C648A5C6A1861FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD911AC02B000000ULL,
		0x3337D9D1402CE47DULL,
		0x3FC39370592FC649ULL,
		0xA5C6A1861F44441DULL,
		0x000000000093C648ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE447387EE1227F18ULL,
		0x1CE78F029ECE5951ULL,
		0x76EB638E8AFB54EBULL,
		0x25D5C78E163A9472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E70FDC244FE300ULL,
		0x9CF1E053D9CB2A3CULL,
		0xDD6C71D15F6A9D63ULL,
		0xBAB8F1C2C7528E4EULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80AF4D3FA2FDCE81ULL,
		0x2F10B4DF4C677A33ULL,
		0x49CFDACB7BCE0434ULL,
		0x168F3F9935DB1754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xC057A69FD17EE740ULL,
		0x17885A6FA633BD19ULL,
		0x24E7ED65BDE7021AULL,
		0x0B479FCC9AED8BAAULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE3E3C7D6D12B3A70ULL,
		0x114C2B9DEF0EE2A0ULL,
		0x488FD63B0ADA6989ULL,
		0x6FFB68A65EC156FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3A7000000000000ULL,
		0xEE2A0E3E3C7D6D12ULL,
		0xA6989114C2B9DEF0ULL,
		0x156FB488FD63B0ADULL,
		0x000006FFB68A65ECULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64194910B18E68C7ULL,
		0x0E9C5A9027B0FFECULL,
		0x8F55F92950783D08ULL,
		0xA87521AA5F75004BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x18E68C7000000000ULL,
		0x7B0FFEC64194910BULL,
		0x0783D080E9C5A902ULL,
		0xF75004B8F55F9295ULL,
		0x0000000A87521AA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C3E791FB38C3154ULL,
		0xB133FFB299F0B87BULL,
		0x325259D19AB97E7FULL,
		0xBF3899981ED3BE94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1F3C8FD9C618AA0ULL,
		0x899FFD94CF85C3D9ULL,
		0x9292CE8CD5CBF3FDULL,
		0xF9C4CCC0F69DF4A1ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D6D87FAAA5359E7ULL,
		0x6EC4C63160663AB0ULL,
		0xE00554E0F41D0C5CULL,
		0x32CED61196797551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE700000000000000ULL,
		0xB05D6D87FAAA5359ULL,
		0x5C6EC4C63160663AULL,
		0x51E00554E0F41D0CULL,
		0x0032CED611967975ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD73FBA8358875D9BULL,
		0x437FDBE18D3DC8E8ULL,
		0xCB87BB1D957A470AULL,
		0xABF8A312766EA798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD621D766C0000000ULL,
		0x634F723A35CFEEA0ULL,
		0x655E91C290DFF6F8ULL,
		0x9D9BA9E632E1EEC7ULL,
		0x000000002AFE28C4ULL,
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
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06B433C7DFFA71EFULL,
		0x137D8C035A600043ULL,
		0x506E6B283F663FA5ULL,
		0x39DC290C538EF765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E3EFFD38F78000ULL,
		0xC601AD300021835AULL,
		0x35941FB31FD289BEULL,
		0x148629C77BB2A837ULL,
		0x0000000000001CEEULL
	}};
	shift = 49;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD19633D1A6DEADFULL,
		0x26536A060C40493FULL,
		0x6FC1C2B6ADBA85C2ULL,
		0xDAA9C476AAAD9EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF00000000000000ULL,
		0x3FFD19633D1A6DEAULL,
		0xC226536A060C4049ULL,
		0xB46FC1C2B6ADBA85ULL,
		0x00DAA9C476AAAD9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x776575EBCCA66335ULL,
		0x589621A86D922DC6ULL,
		0x9887915AC1233032ULL,
		0xE66459AF8CCF8B69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6335000000000000ULL,
		0x2DC6776575EBCCA6ULL,
		0x3032589621A86D92ULL,
		0x8B699887915AC123ULL,
		0x0000E66459AF8CCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F1FFA74AFB72964ULL,
		0xDB8EB6D2153AD854ULL,
		0xAC0B15FAF7DD3EC1ULL,
		0x9444FDE4858B5D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF4E95F6E52C8000ULL,
		0xD6DA42A75B0A89E3ULL,
		0x62BF5EFBA7D83B71ULL,
		0x9FBC90B16BA9D581ULL,
		0x0000000000001288ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7B3C4BA69DCD71FFULL,
		0xBE7D74A1747933B1ULL,
		0xF287DD14FE273BFBULL,
		0x95FA5271493DC344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x974D3B9AE3FE0000ULL,
		0xE942E8F26762F678ULL,
		0xBA29FC4E77F77CFAULL,
		0xA4E2927B8689E50FULL,
		0x0000000000012BF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5032A3CCCA15C11ULL,
		0x5C1EB330D09EC44AULL,
		0xC4AD2E939AD8C8FDULL,
		0x4467CC4C05B59DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951E6650AE088000ULL,
		0x5998684F62256A81ULL,
		0x9749CD6C647EAE0FULL,
		0xE62602DACED5E256ULL,
		0x0000000000002233ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34A7CF16FA13083AULL,
		0xF9ACAAB042D0579CULL,
		0x58F43C65AF18C998ULL,
		0x285F1E0AE34EE01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C20E80000000000ULL,
		0x415E70D29F3C5BE8ULL,
		0x632663E6B2AAC10BULL,
		0x3B807963D0F196BCULL,
		0x000000A17C782B8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68EE099AAFA0837DULL,
		0xAF4EFD3F75A0DAD2ULL,
		0x238CE1BD29DB8FAAULL,
		0x5D523BB67D33F4EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B8266ABE820DF40ULL,
		0xD3BF4FDD6836B49AULL,
		0xE3386F4A76E3EAABULL,
		0x548EED9F4CFD3AC8ULL,
		0x0000000000000017ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC9E6A6FD53C330BULL,
		0xA942272CA688B673ULL,
		0x3E695AE62F2EED3BULL,
		0x60EEA0721903296DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DFAA78661600000ULL,
		0xE594D116CE7993CDULL,
		0x5CC5E5DDA7752844ULL,
		0x0E4320652DA7CD2BULL,
		0x00000000000C1DD4ULL
	}};
	shift = 43;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0B84C7A001D82E3ULL,
		0x896EF4BF162CF51BULL,
		0x241F51620FB98875ULL,
		0x9AC3503AEB56803BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B8C00000000000ULL,
		0x3D46F42E131E8007ULL,
		0x621D625BBD2FC58BULL,
		0xA00EC907D45883EEULL,
		0x000026B0D40EBAD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF4D2D410FDF4882ULL,
		0xD55E5F87F6ABAD91ULL,
		0x7FAB95B8B7183077ULL,
		0x802E9C6D8462615AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1040000000000000ULL,
		0xB23DE9A5A821FBE9ULL,
		0x0EFAABCBF0FED575ULL,
		0x2B4FF572B716E306ULL,
		0x001005D38DB08C4CULL
	}};
	shift = 11;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD1206B091AD5FE25ULL,
		0xBD06FA92D37E19DBULL,
		0x004697038A61792DULL,
		0xE2A2F94D39605E0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8D6AFF1280000000ULL,
		0x69BF0CEDE8903584ULL,
		0xC530BC96DE837D49ULL,
		0x9CB02F0700234B81ULL,
		0x0000000071517CA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82388954A00EA5F8ULL,
		0xC90BD0E2BC736910ULL,
		0x78224F8405077335ULL,
		0xEF47EC493C6B4E96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0752FC0000000000ULL,
		0x39B488411C44AA50ULL,
		0x83B99AE485E8715EULL,
		0x35A74B3C1127C202ULL,
		0x00000077A3F6249EULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34C1D9C25EAFA72FULL,
		0xC446866D64771178ULL,
		0x0E5ECDF5427D690AULL,
		0x0BFD299E0003458CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA60ECE12F57D3978ULL,
		0x2234336B23B88BC1ULL,
		0x72F66FAA13EB4856ULL,
		0x5FE94CF0001A2C60ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D0C346251138CE5ULL,
		0xAF9D23DA0EE636B0ULL,
		0x421FEC491D2ED61AULL,
		0x60A491E8FFC833C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE339400000000000ULL,
		0x8DAC07430D189444ULL,
		0xB586ABE748F683B9ULL,
		0x0CF11087FB12474BULL,
		0x00001829247A3FF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C0CF25C654662A1ULL,
		0xBC9BA60DBE0DD5A2ULL,
		0x846D83DB6E75B723ULL,
		0x18D7907E03E1069CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x25C654662A100000ULL,
		0x60DBE0DD5A21C0CFULL,
		0x3DB6E75B723BC9BAULL,
		0x07E03E1069C846D8ULL,
		0x0000000000018D79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC898C643DCC3F7EEULL,
		0x140379413E11A969ULL,
		0xCEE1E81372C183B0ULL,
		0x86BE4014379EC379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x87EFDC0000000000ULL,
		0x2352D391318C87B9ULL,
		0x8307602806F2827CULL,
		0x3D86F39DC3D026E5ULL,
		0x0000010D7C80286FULL
	}};
	shift = 23;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FDF06F0D3E3E764ULL,
		0x342C5D8F04DACBD6ULL,
		0x99772A8DDB0175DBULL,
		0x07E66FF600CC0CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF7C1BC34F8F9D900ULL,
		0x0B1763C136B2F59BULL,
		0x5DCAA376C05D76CDULL,
		0xF99BFD80330333A6ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DD0321CAA934E13ULL,
		0x1C86A65F6EE311F0ULL,
		0x9BE161095089C0C9ULL,
		0x8C1B2FAE6FE3DC20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x13BA0643955269C2ULL,
		0x2390D4CBEDDC623EULL,
		0x137C2C212A113819ULL,
		0x118365F5CDFC7B84ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CAE593D77FA4AB9ULL,
		0x662377220AAEB577ULL,
		0xD118C2EB979B0313ULL,
		0xEAE6A6DE2D62F688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF49572000000000ULL,
		0x55D6AEE395CB27AEULL,
		0xF360626CC46EE441ULL,
		0xAC5ED11A23185D72ULL,
		0x0000001D5CD4DBC5ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x038F399578A6655DULL,
		0xD751E3DA5753985FULL,
		0x976C209543359807ULL,
		0xE161C25A1F62B9E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5740000000000000ULL,
		0x17C0E3CE655E2999ULL,
		0x01F5D478F695D4E6ULL,
		0x7925DB082550CD66ULL,
		0x003858709687D8AEULL
	}};
	shift = 10;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6802A9146191F2EULL,
		0xDBE44341B4D13187ULL,
		0x1EA632835690E8B9ULL,
		0xE4BC5DCD89F4E9CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C0000000000000ULL,
		0x30F6D0055228C323ULL,
		0x173B7C8868369A26ULL,
		0x39C3D4C6506AD21DULL,
		0x001C978BB9B13E9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD00CB904B6D97704ULL,
		0xF11918A8FCB38275ULL,
		0x2BC165337E63AC07ULL,
		0x4525EB1A00D8EEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC100000000000000ULL,
		0x9D74032E412DB65DULL,
		0x01FC46462A3F2CE0ULL,
		0xA9CAF0594CDF98EBULL,
		0x0011497AC680363BULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31902632CEA0337CULL,
		0x49F6E062D77B2B88ULL,
		0x9B22C305208E037CULL,
		0x1A236EFA9B7B2AD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98CB3A80CDF00000ULL,
		0x818B5DECAE20C640ULL,
		0x0C1482380DF127DBULL,
		0xBBEA6DECAB426C8BULL,
		0x000000000000688DULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7D15AC886A7961DULL,
		0xF070884D13A88BFEULL,
		0x7448E98454747B9FULL,
		0x55821EAA93598C84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xADF456B221A9E587ULL,
		0xFC1C221344EA22FFULL,
		0x1D123A61151D1EE7ULL,
		0x156087AAA4D66321ULL
	}};
	shift = 2;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x854671822D0748A9ULL,
		0x6B159691F9B542C3ULL,
		0xB7296DD6F661B938ULL,
		0xA6ED42D69684A0A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11683A4548000000ULL,
		0x8FCDAA161C2A338CULL,
		0xB7B30DC9C358ACB4ULL,
		0xB4B425052DB94B6EULL,
		0x0000000005376A16ULL
	}};
	shift = 37;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95A243A04052EE80ULL,
		0x90775554F0D5A54FULL,
		0x8729626BB5D973FBULL,
		0xD7152A43B284C54FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5DD000000000000ULL,
		0xAB4A9F2B44874080ULL,
		0xB2E7F720EEAAA9E1ULL,
		0x098A9F0E52C4D76BULL,
		0x000001AE2A548765ULL
	}};
	shift = 23;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4513CFDF707B7005ULL,
		0xA0E26607CE60CF3EULL,
		0x3B729C61D081247EULL,
		0x58A62D98171916F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7DC1EDC014000000ULL,
		0x1F39833CF9144F3FULL,
		0x87420491FA838998ULL,
		0x605C645BD8EDCA71ULL,
		0x00000000016298B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x467F885C7273C3EFULL,
		0x20ECEDC584E34E55ULL,
		0x5C330C6CC0CD946AULL,
		0xBDC7F8645F5946FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x519FE2171C9CF0FBULL,
		0x883B3B716138D395ULL,
		0x170CC31B3033651AULL,
		0x2F71FE1917D651BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED69018CB0418DF8ULL,
		0x0532EF27DFAA2200ULL,
		0xD2FC8430A98A78BEULL,
		0x377ADE4BA6929CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B480C65820C6FC0ULL,
		0x2997793EFD511007ULL,
		0x97E421854C53C5F0ULL,
		0xBBD6F25D3494E50EULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD666F9AAC0651896ULL,
		0x9FAA0FC8AC5F497EULL,
		0xA26F751803B6EFEFULL,
		0x6B4CA448F130E1C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6518960000000000ULL,
		0x5F497ED666F9AAC0ULL,
		0xB6EFEF9FAA0FC8ACULL,
		0x30E1C8A26F751803ULL,
		0x0000006B4CA448F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D962DFF14805C5AULL,
		0x01D5243C51CCE5D0ULL,
		0xE593759AFCD1B4B6ULL,
		0x1A6EC9F0E1654585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0x41B658B7FC520171ULL,
		0xD8075490F1473397ULL,
		0x17964DD66BF346D2ULL,
		0x0069BB27C3859516ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC677C34B1202618ULL,
		0x9DFD15A4AB518AF5ULL,
		0x7760E3FB070F7BEDULL,
		0xB4DEECA3A26256E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7C34B12026180000ULL,
		0x15A4AB518AF5AC67ULL,
		0xE3FB070F7BED9DFDULL,
		0xECA3A26256E17760ULL,
		0x000000000000B4DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F89D7508F583387ULL,
		0x8275D6FA8E0B2D93ULL,
		0xECEC3C5C8C1740A9ULL,
		0x5F9A170CD67861A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AEA11EB0670E000ULL,
		0xBADF51C165B261F1ULL,
		0x878B9182E815304EULL,
		0x42E19ACF0C347D9DULL,
		0x0000000000000BF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9DFF67451EAD64AULL,
		0x32D4A5E5F41F4DD3ULL,
		0xFF70B40291B3BC6FULL,
		0x5A583DDF3724CF48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B25000000000000ULL,
		0xA6E9ECEFFB3A28F5ULL,
		0xDE37996A52F2FA0FULL,
		0x67A47FB85A0148D9ULL,
		0x00002D2C1EEF9B92ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE7B16A0D91DCB7AULL,
		0xD5671CE0A5081A0CULL,
		0xDA4B368AC5FBDE00ULL,
		0x76DD93E2BA8AE253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8B506C8EE5BD000ULL,
		0x38E7052840D065F3ULL,
		0x59B4562FDEF006ABULL,
		0xEC9F15D457129ED2ULL,
		0x00000000000003B6ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7302C2161DCF5A56ULL,
		0xB24900322C6DF29AULL,
		0x8A7C473EDCF73C30ULL,
		0x7F94AC3FAE708DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2161DCF5A5600000ULL,
		0x0322C6DF29A7302CULL,
		0x73EDCF73C30B2490ULL,
		0xC3FAE708DBF8A7C4ULL,
		0x000000000007F94AULL
	}};
	shift = 44;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23049E5DEACD78CFULL,
		0x26FFC1F73ACD600BULL,
		0x4D3C391748B0E3ABULL,
		0x3D64EAFBBE1941CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E0000000000000ULL,
		0x01646093CBBD59AFULL,
		0x7564DFF83EE759ACULL,
		0x3969A78722E9161CULL,
		0x0007AC9D5F77C328ULL
	}};
	shift = 11;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x561168C53DBF4345ULL,
		0xE54C541781A8F9D6ULL,
		0x5DFE3651DD6B7209ULL,
		0x408753AEECEAC934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x2B08B4629EDFA1A2ULL,
		0xF2A62A0BC0D47CEBULL,
		0x2EFF1B28EEB5B904ULL,
		0x2043A9D77675649AULL
	}};
	shift = 1;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB299A5894A28FA14ULL,
		0x7823F649B4D1AAE8ULL,
		0xDB1BAA51D05C7795ULL,
		0x6530308DFB0AA5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5334B129451F4280ULL,
		0x047EC9369A355D16ULL,
		0x63754A3A0B8EF2AFULL,
		0xA60611BF6154BF7BULL,
		0x000000000000000CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB752A6954DE099B7ULL,
		0x74D709A87F2855F7ULL,
		0x555267C16D5AAEADULL,
		0xC8873C4A7CD876B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4AA6F04CDB800000ULL,
		0xD43F942AFBDBA953ULL,
		0xE0B6AD5756BA6B84ULL,
		0x253E6C3B592AA933ULL,
		0x000000000064439EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x361D4CC886F210ACULL,
		0x0C0FE89A3C3ACA6EULL,
		0x9D7F8C6551C23247ULL,
		0x9A1F30F311C6049AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6644379085600000ULL,
		0x44D1E1D65371B0EAULL,
		0x632A8E119238607FULL,
		0x87988E3024D4EBFCULL,
		0x000000000004D0F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCEC376003D3BFB72ULL,
		0xB1C9A77723314F82ULL,
		0x8C79A377A3FEF443ULL,
		0x8CB15C302FB30F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x800F4EFEDC800000ULL,
		0xDDC8CC53E0B3B0DDULL,
		0xDDE8FFBD10EC7269ULL,
		0x0C0BECC3E7631E68ULL,
		0x0000000000232C57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7673DF2BAFA1A9E6ULL,
		0xC9AB8A0DC7ED9A7BULL,
		0x740D5BA458BB124AULL,
		0x693CF0C3A6365EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D7D0D4F30000000ULL,
		0x6E3F6CD3DBB39EF9ULL,
		0x22C5D892564D5C50ULL,
		0x1D31B2F7ABA06ADDULL,
		0x000000000349E786ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9301D8018D51D112ULL,
		0x5BECFE444231C5B7ULL,
		0xE1DB13BE6C2EFB35ULL,
		0x2D3F9F6AF51082CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA224000000000000ULL,
		0x8B6F2603B0031AA3ULL,
		0xF66AB7D9FC888463ULL,
		0x0595C3B6277CD85DULL,
		0x00005A7F3ED5EA21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15C202C91E774980ULL,
		0x3A979B7FDC186C18ULL,
		0x48BDF43E147E358EULL,
		0xBD9089E9E2F6CBEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C91E77498000000ULL,
		0xB7FDC186C1815C20ULL,
		0x43E147E358E3A979ULL,
		0x9E9E2F6CBEF48BDFULL,
		0x00000000000BD908ULL
	}};
	shift = 44;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA99F450D85708BBCULL,
		0x00A6C623D761770FULL,
		0x686E6777E8E7E694ULL,
		0x27D52F31B2529B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x450D85708BBC0000ULL,
		0xC623D761770FA99FULL,
		0x6777E8E7E69400A6ULL,
		0x2F31B2529B38686EULL,
		0x00000000000027D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5944B27BC4990F31ULL,
		0x312C4BA2183F10BBULL,
		0x2FE53D1F23904FEBULL,
		0x630EEF694FAC7168ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA2593DE24C879880ULL,
		0x9625D10C1F885DACULL,
		0xF29E8F91C827F598ULL,
		0x8777B4A7D638B417ULL,
		0x0000000000000031ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43B8CF69EA109DC9ULL,
		0x5C3EF08BD9C581F7ULL,
		0x662FF5BF461A3D06ULL,
		0xA88A8399D3717CFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x67B4F5084EE48000ULL,
		0x7845ECE2C0FBA1DCULL,
		0xFADFA30D1E832E1FULL,
		0x41CCE9B8BE7EB317ULL,
		0x0000000000005445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B219234FFB05141ULL,
		0x47C93DACEFC5A613ULL,
		0x69326A2D43039746ULL,
		0x50EE0FC2E283BD6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFB05141000000000ULL,
		0xFC5A6135B219234FULL,
		0x303974647C93DACEULL,
		0x283BD6B69326A2D4ULL,
		0x000000050EE0FC2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1891F7814E6E72C8ULL,
		0x423DC082ECFC4A89ULL,
		0x066B1EF3EB08B188ULL,
		0xAB02BB82D5E67DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FBC0A7373964000ULL,
		0xEE041767E25448C4ULL,
		0x58F79F58458C4211ULL,
		0x15DC16AF33EFF033ULL,
		0x0000000000000558ULL
	}};
	shift = 53;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC51CA81F09C7C0FCULL,
		0xAD43FB0C554A5E12ULL,
		0xF6E16050353FF08FULL,
		0x7CBED7636F762A47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x628E540F84E3E07EULL,
		0xD6A1FD862AA52F09ULL,
		0xFB70B0281A9FF847ULL,
		0x3E5F6BB1B7BB1523ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x125E414F8A0B4879ULL,
		0x39FD1A42DC17B360ULL,
		0xE47E4DC8EE80D639ULL,
		0x5FF20F0ACA7D2B54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA7C505A43C800000ULL,
		0x216E0BD9B0092F20ULL,
		0xE477406B1C9CFE8DULL,
		0x85653E95AA723F26ULL,
		0x00000000002FF907ULL
	}};
	shift = 41;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E15DB4C7135D255ULL,
		0x4C540652417BEB5CULL,
		0xC9165BB15278E667ULL,
		0x1935EE2D4611D9BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A80000000000000ULL,
		0xAE1F0AEDA6389AE9ULL,
		0x33A62A032920BDF5ULL,
		0xDEE48B2DD8A93C73ULL,
		0x000C9AF716A308ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8D0C71E7F273A8CULL,
		0x003F4FA2DCA71AA6ULL,
		0x825F02C8E6BE9621ULL,
		0x9E8A0C80E5FD130CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68638F3F939D4600ULL,
		0x1FA7D16E538D5374ULL,
		0x2F8164735F4B1080ULL,
		0x45064072FE898641ULL,
		0x000000000000004FULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD567C7746C7CCFF2ULL,
		0x8E0735AA7FB0B203ULL,
		0xC0082FF23BBDCCCFULL,
		0xF9765266260952FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE8D8F99FE400000ULL,
		0xB54FF616407AACF8ULL,
		0xFE4777B999F1C0E6ULL,
		0x4CC4C12A5F780105ULL,
		0x00000000001F2ECAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6250C5FDD044056ULL,
		0x95AA7ADB4EF62E4FULL,
		0x6703266B4EA61A65ULL,
		0x96D4A2C9F12EB179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6250C5FDD0440560ULL,
		0x5AA7ADB4EF62E4FDULL,
		0x703266B4EA61A659ULL,
		0x6D4A2C9F12EB1796ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E6A91D0F2A17613ULL,
		0x68BA837D74DC51DCULL,
		0x12A9022A60A57C34ULL,
		0x453F16CC29159F62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1E542EC26000000ULL,
		0xFAE9B8A3B93CD523ULL,
		0x54C14AF868D17506ULL,
		0x98522B3EC4255204ULL,
		0x00000000008A7E2DULL
	}};
	shift = 39;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3D9A200857CD6E3ULL,
		0x94E8FD8E336A5C22ULL,
		0x872D26EECF14A9C7ULL,
		0xC5F58C67628D6AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66880215F35B8C00ULL,
		0xA3F638CDA9708B0FULL,
		0xB49BBB3C52A71E53ULL,
		0xD6319D8A35AB5E1CULL,
		0x0000000000000317ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C1F43766AA12464ULL,
		0xF8C61E9045CF3A38ULL,
		0x40F558BAE8D4505FULL,
		0x2F1FB88FDA94F596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383E86ECD54248C8ULL,
		0xF18C3D208B9E7471ULL,
		0x81EAB175D1A8A0BFULL,
		0x5E3F711FB529EB2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x58237D729C4F5C40ULL,
		0xF5FD2660B7A32601ULL,
		0x4527FA5A209A35FEULL,
		0x0450D7DAC023D6BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB94E27AE20000000ULL,
		0x305BD19300AC11BEULL,
		0x2D104D1AFF7AFE93ULL,
		0xED6011EB5E2293FDULL,
		0x000000000002286BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF429E3C6503550FULL,
		0x9D76F1993244DB8EULL,
		0xC17C7C09449FB0B8ULL,
		0x382F2A1723F09A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06AA1E0000000000ULL,
		0x89B71DBE853C78CAULL,
		0x3F61713AEDE33264ULL,
		0xE134F382F8F81289ULL,
		0x000000705E542E47ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3A5DCA97DDEBAC4ULL,
		0xE8FC94E5CDE27657ULL,
		0x3EF74DA104DE3E3DULL,
		0x648D64E4858B28B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2FBBD75880000000ULL,
		0xB9BC4ECAFE74BB95ULL,
		0x209BC7C7BD1F929CULL,
		0x90B1651607DEE9B4ULL,
		0x000000000C91AC9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF606116897FCB6A7ULL,
		0xBF20EB1D9964605EULL,
		0xAFFC29EF96CC04CEULL,
		0xAFA0AD13AAD651F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF606116897FCB6A7ULL,
		0xBF20EB1D9964605EULL,
		0xAFFC29EF96CC04CEULL,
		0xAFA0AD13AAD651F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD83550F28500351ULL,
		0xF43FA121DBF9503FULL,
		0x7B8FEBB04EFC81B8ULL,
		0xEDC5919EBF6D4E44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF285003510000000ULL,
		0x1DBF9503FFD83550ULL,
		0x04EFC81B8F43FA12ULL,
		0xEBF6D4E447B8FEBBULL,
		0x000000000EDC5919ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xACEF0CDDCC8476E1ULL,
		0x1224EDDF6D6C76CAULL,
		0x06FC1F0CA39EBA4CULL,
		0x146C6E36E25B8815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x211DB84000000000ULL,
		0x5B1DB2AB3BC33773ULL,
		0xE7AE9304893B77DBULL,
		0x96E20541BF07C328ULL,
		0x000000051B1B8DB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x377ECA7CC3266131ULL,
		0xEBC82F3A51F00E54ULL,
		0x5EA7426E5DC013BDULL,
		0x14180B74D63614EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDFB29F30C9984C40ULL,
		0xF20BCE947C03950DULL,
		0xA9D09B977004EF7AULL,
		0x0602DD358D853A97ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CF64840D9A32291ULL,
		0x5A796837E6E556BBULL,
		0x03CF21C4DFBAFC39ULL,
		0xCD935A2EBDE906C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0xB5CF64840D9A3229ULL,
		0x95A796837E6E556BULL,
		0x503CF21C4DFBAFC3ULL,
		0x0CD935A2EBDE906CULL
	}};
	shift = 4;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD00790AF440E832EULL,
		0x1367652753D05877ULL,
		0xED0C02996EF85EEFULL,
		0x12DC39586243C798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E881D065C00000ULL,
		0xA4EA7A0B0EFA00F2ULL,
		0x532DDF0BDDE26CECULL,
		0x2B0C4878F31DA180ULL,
		0x0000000000025B87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC4147C723485393ULL,
		0x6E9F02640A7D809FULL,
		0xCBE96918892E94CBULL,
		0xEC4AFB547F54DAC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E391A429C980000ULL,
		0x132053EC04FFE20AULL,
		0x48C44974A65B74F8ULL,
		0xDAA3FAA6D60E5F4BULL,
		0x0000000000076257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x793CD2EF700C2CF0ULL,
		0x9AE0D6593C021A9FULL,
		0xE47132C5F1CBFEF2ULL,
		0x498775B1F0C23022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x279A5DEE01859E00ULL,
		0x5C1ACB27804353EFULL,
		0x8E2658BE397FDE53ULL,
		0x30EEB63E1846045CULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB9EBEDE3CC5669DULL,
		0x1480C053B3410167ULL,
		0x79754B44A008FA54ULL,
		0x8F0AA742C2DEABF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAFB78F3159A74000ULL,
		0x3014ECD04059FAE7ULL,
		0x52D128023E950520ULL,
		0xA9D0B0B7AAFC1E5DULL,
		0x00000000000023C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC41FE789813DC7E3ULL,
		0x4B45ABFDA6C8E014ULL,
		0xFBB3D5484DE42541ULL,
		0x0711178EE7A0DE46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20FF3C4C09EE3F18ULL,
		0x5A2D5FED364700A6ULL,
		0xDD9EAA426F212A0AULL,
		0x3888BC773D06F237ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x180F2387CA506253ULL,
		0xCA99E64B3CC1E957ULL,
		0x7A0893119F7E497DULL,
		0x5CF1E3BCBA6A0265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC0791C3E52831298ULL,
		0x54CF3259E60F4AB8ULL,
		0xD044988CFBF24BEEULL,
		0xE78F1DE5D350132BULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6345B30BF6439AE1ULL,
		0x5F4D02F162131298ULL,
		0x685EC0B26D297F10ULL,
		0x5C39A9DC12340F86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x16CC2FD90E6B8400ULL,
		0x340BC5884C4A618DULL,
		0x7B02C9B4A5FC417DULL,
		0xE6A77048D03E19A1ULL,
		0x0000000000000170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD28DC60A7144C70ULL,
		0xFB9E77446F6703FDULL,
		0xA3E1F0F54151F80CULL,
		0x44A6CA0FD8D5A10FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6380000000000000ULL,
		0x1FEDE946E30538A2ULL,
		0xC067DCF3BA237B38ULL,
		0x087D1F0F87AA0A8FULL,
		0x00022536507EC6ADULL
	}};
	shift = 13;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x305E86C7C3A3B7A3ULL,
		0x5F240A26C68E36AEULL,
		0xCAA6B61A65143406ULL,
		0x1D0BCD02576B1612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D8F87476F460000ULL,
		0x144D8D1C6D5C60BDULL,
		0x6C34CA28680CBE48ULL,
		0x9A04AED62C25954DULL,
		0x0000000000003A17ULL
	}};
	shift = 47;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68DCEB129DD06B08ULL,
		0xE426B8D5272ECCABULL,
		0xC876B6CC513393A2ULL,
		0x827240F54B9B94EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8358400000000000ULL,
		0x76655B46E75894EEULL,
		0x9C9D172135C6A939ULL,
		0xDCA75643B5B66289ULL,
		0x000004139207AA5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B08AD115732FE56ULL,
		0xF8283D28A15CE752ULL,
		0xED503AE9BE0CA930ULL,
		0x3F4A8CAB6FD8458EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5845688AB997F2B0ULL,
		0xC141E9450AE73A93ULL,
		0x6A81D74DF0654987ULL,
		0xFA54655B7EC22C77ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57845A75929BC0B3ULL,
		0xB90B29058CD29AE0ULL,
		0xCBA6855F110DB962ULL,
		0x4280EA0404B4B35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC94DE05980000000ULL,
		0xC6694D702BC22D3AULL,
		0x8886DCB15C859482ULL,
		0x025A59AFE5D342AFULL,
		0x0000000021407502ULL
	}};
	shift = 33;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB26ADE14AA0511EULL,
		0x47B12C9A0AA80918ULL,
		0x9309B2721F5EDFC9ULL,
		0xCC4618DBFA3198C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C00000000000000ULL,
		0x31F64D5BC29540A2ULL,
		0x928F625934155012ULL,
		0x85261364E43EBDBFULL,
		0x01988C31B7F46331ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC564AA46D0029393ULL,
		0x0840826E34A92796ULL,
		0xAD02EFC29F08B089ULL,
		0x4E27CEC4F0BE3297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA005272600000000ULL,
		0x69524F2D8AC9548DULL,
		0x3E116112108104DCULL,
		0xE17C652F5A05DF85ULL,
		0x000000009C4F9D89ULL
	}};
	shift = 31;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA92D6FB65DDE7DBULL,
		0xE132C0AB9820E669ULL,
		0x780E3CCCEBD0B327ULL,
		0x1CAF60309E79D874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x97779F6C00000000ULL,
		0x608399A76A4B5BEDULL,
		0xAF42CC9F84CB02AEULL,
		0x79E761D1E038F333ULL,
		0x0000000072BD80C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD49B67825DCDE5F2ULL,
		0x1F625B2D5C8FC8BAULL,
		0x795192D215F7404BULL,
		0xD727C8F4C37174E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73797C8000000000ULL,
		0x23F22EB526D9E097ULL,
		0x7DD012C7D896CB57ULL,
		0xDC5D395E5464B485ULL,
		0x00000035C9F23D30ULL
	}};
	shift = 26;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB663F08CC69C572ULL,
		0x84E470BB13AC9667ULL,
		0x178E85F11D2D6366ULL,
		0x86983FFCC3CF2F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC7E1198D38AE400ULL,
		0xC8E17627592CCFB6ULL,
		0x1D0BE23A5AC6CD09ULL,
		0x307FF9879E5EB02FULL,
		0x000000000000010DULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADA9382E453DDEACULL,
		0x6D8DAEA5B1E134BEULL,
		0xFCC1D98562C09640ULL,
		0x933723AC55B5F998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x17229EEF56000000ULL,
		0x52D8F09A5F56D49CULL,
		0xC2B1604B2036C6D7ULL,
		0xD62ADAFCCC7E60ECULL,
		0x0000000000499B91ULL
	}};
	shift = 41;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A84634BDA0051B3ULL,
		0x60439E4259A56F0BULL,
		0x8A0AEA84A77FB43BULL,
		0xC89ABE93D5972C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0051B30000000000ULL,
		0xA56F0B4A84634BDAULL,
		0x7FB43B60439E4259ULL,
		0x972C388A0AEA84A7ULL,
		0x000000C89ABE93D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD708032FFFC8F01ULL,
		0xC07D38E37B34253AULL,
		0xE59E18A0549557CBULL,
		0x47A4F97ABCB283A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD708032FFFC8F01ULL,
		0xC07D38E37B34253AULL,
		0xE59E18A0549557CBULL,
		0x47A4F97ABCB283A2ULL
	}};
	shift = 0;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FB014E6B092E5C8ULL,
		0x167F7D1989993B82ULL,
		0x3933F7A2F9910DCBULL,
		0xD87C0B27DEA5BFD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B97200000000000ULL,
		0x64EE08BEC0539AC2ULL,
		0x44372C59FDF46626ULL,
		0x96FF58E4CFDE8BE6ULL,
		0x00000361F02C9F7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x068C25C78605C14FULL,
		0xC3C53382E5864D4FULL,
		0x01CD91C398B897B0ULL,
		0x5360EFC853BD7241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0B829E00000000ULL,
		0xCB0C9A9E0D184B8FULL,
		0x31712F61878A6705ULL,
		0xA77AE482039B2387ULL,
		0x00000000A6C1DF90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65828AA23639F605ULL,
		0x4AFE0D1C94CB3771ULL,
		0x374D513950F498D5ULL,
		0x7C55D13F3CAE867DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E7D814000000000ULL,
		0x32CDDC5960A2A88DULL,
		0x3D263552BF834725ULL,
		0x2BA19F4DD3544E54ULL,
		0x0000001F15744FCFULL
	}};
	shift = 26;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAB2AAF1721BE6FEULL,
		0xB21C99196B877DE6ULL,
		0xDF702CF9D3F64608ULL,
		0x3B4A8EE965E4C9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF1721BE6FE00000ULL,
		0x9196B877DE6DAB2AULL,
		0xCF9D3F64608B21C9ULL,
		0xEE965E4C9D7DF702ULL,
		0x000000000003B4A8ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD37F6CC2F4121B4ULL,
		0x61AC20986C5FD21DULL,
		0x36309D71C3BEAE09ULL,
		0xEE54BBA7B32BD802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7F6CC2F4121B4000ULL,
		0xC20986C5FD21DAD3ULL,
		0x09D71C3BEAE0961AULL,
		0x4BBA7B32BD802363ULL,
		0x0000000000000EE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x639B3D2245134485ULL,
		0x81BC2517A2AB912DULL,
		0x3B2510293BB4F93AULL,
		0x9E9177F0AA50E7D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6890A00000000000ULL,
		0x7225AC7367A448A2ULL,
		0x9F27503784A2F455ULL,
		0x1CFAC764A2052776ULL,
		0x000013D22EFE154AULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9351B3805419661ULL,
		0x7F64398495ECA98FULL,
		0xAAAE742716E45806ULL,
		0x273796E85B0ADA33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6610000000000000ULL,
		0x98FE9351B3805419ULL,
		0x8067F64398495ECAULL,
		0xA33AAAE742716E45ULL,
		0x000273796E85B0ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0AAD1D57EBE69EFCULL,
		0x800B887A321282EEULL,
		0x20C4E83CC7000A74ULL,
		0x878EFEEC9059CA78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF34F7E0000000000ULL,
		0x09417705568EABF5ULL,
		0x80053A4005C43D19ULL,
		0x2CE53C1062741E63ULL,
		0x00000043C77F7648ULL
	}};
	shift = 25;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAEFCC047DC5CD060ULL,
		0x754F74AF81BE8EF1ULL,
		0xD192B080B6A24D87ULL,
		0xF9C9E0B637D2039CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD06000000000000ULL,
		0xE8EF1AEFCC047DC5ULL,
		0x24D87754F74AF81BULL,
		0x2039CD192B080B6AULL,
		0x00000F9C9E0B637DULL
	}};
	shift = 20;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE470CAE55D4470E1ULL,
		0x9466DCFAC95738E1ULL,
		0xF2DC87128651A0E8ULL,
		0xE3233986779DA641ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72AEA23870800000ULL,
		0x7D64AB9C70F23865ULL,
		0x894328D0744A336EULL,
		0xC33BCED320F96E43ULL,
		0x000000000071919CULL
	}};
	shift = 41;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAB6598C27A35353BULL,
		0x691D5D6E7DA0078EULL,
		0xD43B08CBBA27D1A7ULL,
		0x36B61AFE165DCC2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7600000000000000ULL,
		0x1D56CB3184F46A6AULL,
		0x4ED23ABADCFB400FULL,
		0x55A8761197744FA3ULL,
		0x006D6C35FC2CBB98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x285C5C85D9B5845BULL,
		0xD92449FFBBA7527EULL,
		0xEF5EBCF2B70B5395ULL,
		0x13D44ED75C3C3204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x21766D6116C00000ULL,
		0x7FEEE9D49F8A1717ULL,
		0x3CADC2D4E5764912ULL,
		0xB5D70F0C813BD7AFULL,
		0x000000000004F513ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x278073D8869C21CDULL,
		0xA2A8B8EC9A1D27C1ULL,
		0x458FDFB8730A65F1ULL,
		0xBC757FC7A8954EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39A0000000000000ULL,
		0xF824F00E7B10D384ULL,
		0xBE3455171D9343A4ULL,
		0xD4A8B1FBF70E614CULL,
		0x00178EAFF8F512A9ULL
	}};
	shift = 11;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FF87C80EACBC904ULL,
		0x3388D0768299221AULL,
		0x62F1E1C6AFA462ABULL,
		0xA2456E97616965EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFC3E407565E4820ULL,
		0x9C4683B414C910D3ULL,
		0x178F0E357D231559ULL,
		0x122B74BB0B4B2F73ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2249796FE152021ULL,
		0x4EF14249D6BDAED9ULL,
		0xD3DD05AAEE4FD591ULL,
		0xD5A82CD1ECD12D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFC2A404200000000ULL,
		0xAD7B5DB3A4492F2DULL,
		0xDC9FAB229DE28493ULL,
		0xD9A25A1FA7BA0B55ULL,
		0x00000001AB5059A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65A75710E3C1995FULL,
		0x6A5114C2F87480B8ULL,
		0xB43CB58D919E2D19ULL,
		0x119C81D91AE3D5C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x438F06657C000000ULL,
		0x0BE1D202E1969D5CULL,
		0x364678B465A94453ULL,
		0x646B8F571AD0F2D6ULL,
		0x0000000000467207ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FED1D4219B2112DULL,
		0xFA98C6FE4DF319BCULL,
		0xC57536C3C6E98562ULL,
		0x77D1D35E3D7D0375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB4750866C844B4ULL,
		0xEA631BF937CC66F1ULL,
		0x15D4DB0F1BA6158BULL,
		0xDF474D78F5F40DD7ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AEF5A9BCCEF7CCEULL,
		0x5E68D3700331A932ULL,
		0x2C22BE5C474E9462ULL,
		0xB00134CEF40A19B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x577AD4DE677BE670ULL,
		0xF3469B80198D4994ULL,
		0x6115F2E23A74A312ULL,
		0x8009A677A050CD91ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF16D4637EC39FDC4ULL,
		0x8727915F70480E7CULL,
		0xB8D60D85AC377EB9ULL,
		0xD30E6F705BE3AD64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FD873FB88000000ULL,
		0xBEE0901CF9E2DA8CULL,
		0x0B586EFD730E4F22ULL,
		0xE0B7C75AC971AC1BULL,
		0x0000000001A61CDEULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99290E2185434F8BULL,
		0x4D79ABB5295681D4ULL,
		0xA3969317256A3105ULL,
		0x365C86F646ED8C0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30A869F160000000ULL,
		0xA52AD03A932521C4ULL,
		0xE4AD4620A9AF3576ULL,
		0xC8DDB181F472D262ULL,
		0x0000000006CB90DEULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A5B5CA41E487CF1ULL,
		0x9A7BF48DE4B6F6CFULL,
		0x37A739658560ED59ULL,
		0x30AEDD37B3CFC003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x483C90F9E2000000ULL,
		0x1BC96DED9F14B6B9ULL,
		0xCB0AC1DAB334F7E9ULL,
		0x6F679F80066F4E72ULL,
		0x0000000000615DBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x374D8E7660256831ULL,
		0x9E782132219F8544ULL,
		0x4867610683528BE9ULL,
		0x9B16427BD3A78E16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9D98095A0C400000ULL,
		0x4C8867E1510DD363ULL,
		0x41A0D4A2FA679E08ULL,
		0x9EF4E9E3859219D8ULL,
		0x000000000026C590ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59F653555CE328CAULL,
		0x6426637B3A8A9A69ULL,
		0xB81D358305FCD51FULL,
		0xDE87840401379E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD94D55738CA32800ULL,
		0x998DECEA2A69A567ULL,
		0x74D60C17F3547D90ULL,
		0x1E101004DE79AAE0ULL,
		0x000000000000037AULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51E0DCD14B878D2CULL,
		0x6E3A81C643A9BB10ULL,
		0xC3E3E531A89C5929ULL,
		0xDC52A3E471F55176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478373452E1E34B0ULL,
		0xB8EA07190EA6EC41ULL,
		0x0F8F94C6A27164A5ULL,
		0x714A8F91C7D545DBULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B276CD658429676ULL,
		0x35BE15EC1230425BULL,
		0xF746A6A098F71EF9ULL,
		0x17623FCC82CD9626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9ACB0852CEC00000ULL,
		0xBD8246084B7164EDULL,
		0xD4131EE3DF26B7C2ULL,
		0xF99059B2C4DEE8D4ULL,
		0x000000000002EC47ULL
	}};
	shift = 43;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5BF056789758FE2ULL,
		0x8F01C621B9548725ULL,
		0xB352FE05887D6FC1ULL,
		0x972276A9CEC231B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF82B3C4BAC7F10ULL,
		0x780E310DCAA4392DULL,
		0x9A97F02C43EB7E0CULL,
		0xB913B54E76118D9DULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x014D9B4D18C538B8ULL,
		0x5338E8085D46D62EULL,
		0xB4D3821B55A4F64FULL,
		0x12FE8026825BDD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18A7170000000000ULL,
		0xA8DAC5C029B369A3ULL,
		0xB49EC9EA671D010BULL,
		0x4B7BA9769A70436AULL,
		0x000000025FD004D0ULL
	}};
	shift = 27;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79C3CDD500E4DCA9ULL,
		0xF0F0801B905206A0ULL,
		0xB62CF50E6394CE80ULL,
		0xBF4A18B46E1E3322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA01C9B952000000ULL,
		0x3720A40D40F3879BULL,
		0x1CC7299D01E1E100ULL,
		0x68DC3C66456C59EAULL,
		0x00000000017E9431ULL
	}};
	shift = 39;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B669D3C832BCB5EULL,
		0x1A13EFAD416DCE90ULL,
		0xA0069D4975D3A8F9ULL,
		0x36B46534F2715788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3C832BCB5E00000ULL,
		0xFAD416DCE902B669ULL,
		0xD4975D3A8F91A13EULL,
		0x534F2715788A0069ULL,
		0x0000000000036B46ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA461381D3C0CABF9ULL,
		0x35D9D5C3B3F9C8F0ULL,
		0x8EDE3CA6D2BDA30BULL,
		0x884F32AD5196B314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF032AFE400000000ULL,
		0xCFE723C29184E074ULL,
		0x4AF68C2CD767570EULL,
		0x465ACC523B78F29BULL,
		0x00000002213CCAB5ULL
	}};
	shift = 30;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x335E3A5CD5F9B509ULL,
		0xF8F0D05565163D29ULL,
		0xE9C7B335D81FD4F9ULL,
		0xA22E9032EE800874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD424000000000000ULL,
		0xF4A4CD78E97357E6ULL,
		0x53E7E3C341559458ULL,
		0x21D3A71ECCD7607FULL,
		0x000288BA40CBBA00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 206;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEECBC9BCD1AAD354ULL,
		0xB0F0817B549CB960ULL,
		0x93DFA1C09D12F96AULL,
		0x11C88162A61B3616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79A355A6A8000000ULL,
		0xF6A93972C1DD9793ULL,
		0x813A25F2D561E102ULL,
		0xC54C366C2D27BF43ULL,
		0x0000000000239102ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33CB0E783A71DE39ULL,
		0x1B9595A401AEEEF8ULL,
		0x2EDA4C1611374A81ULL,
		0xD3963F3013A6551EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF074E3BC720000ULL,
		0x2B48035DDDF06796ULL,
		0x982C226E9502372BULL,
		0x7E60274CAA3C5DB4ULL,
		0x000000000001A72CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF197383569C195EBULL,
		0xF86D9294FA847B52ULL,
		0xAAC7C2AC84868AB6ULL,
		0x3E302B0B1CCCD5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70657AC00000000ULL,
		0xEA11ED4BC65CE0D5ULL,
		0x121A2ADBE1B64A53ULL,
		0x7333570AAB1F0AB2ULL,
		0x00000000F8C0AC2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9407D35E3DDD756ULL,
		0x4F609512CBCCCEAFULL,
		0xA4CC152D030F4C57ULL,
		0xED230708FC644DDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6BC7BBAEAC000000ULL,
		0x2597999D5F7280FAULL,
		0x5A061E98AE9EC12AULL,
		0x11F8C89BB949982AULL,
		0x0000000001DA460EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62ABA64BF5F4031AULL,
		0x9D662C50ABB330E8ULL,
		0x13AB5C34C6BF5C9EULL,
		0xC74D4B3A290A43D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ABA64BF5F4031A0ULL,
		0xD662C50ABB330E86ULL,
		0x3AB5C34C6BF5C9E9ULL,
		0x74D4B3A290A43D91ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38A166E47A7F68D5ULL,
		0xC5B071CD751E5EE6ULL,
		0x2D8E607CF15DEE0FULL,
		0xE675A06DE25B5309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF68D500000000000ULL,
		0xE5EE638A166E47A7ULL,
		0xDEE0FC5B071CD751ULL,
		0xB53092D8E607CF15ULL,
		0x00000E675A06DE25ULL
	}};
	shift = 20;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x849D266482E3423EULL,
		0xB0A7FCF8B1A17E3DULL,
		0x724CCA164229B1F4ULL,
		0x84114FE01CD424B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23E0000000000000ULL,
		0xE3D849D266482E34ULL,
		0x1F4B0A7FCF8B1A17ULL,
		0x4B2724CCA164229BULL,
		0x00084114FE01CD42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D82B3DD9F027103ULL,
		0x023025992BF99D4DULL,
		0x98E147101F274274ULL,
		0x7BFC7CFC4C860F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0567BB3E04E20600ULL,
		0x604B3257F33A9AFBULL,
		0xC28E203E4E84E804ULL,
		0xF8F9F8990C1E8D31ULL,
		0x00000000000000F7ULL
	}};
	shift = 55;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC88F82330D4C71CULL,
		0x0AB107A6EE3BD42BULL,
		0x44671BB17F61BA5EULL,
		0x1D6F822486CB7C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1C00000000000000ULL,
		0x2BBC88F82330D4C7ULL,
		0x5E0AB107A6EE3BD4ULL,
		0x2E44671BB17F61BAULL,
		0x001D6F822486CB7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0200000000000000ULL,
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
	shift = 176;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000000001000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000200000000ULL,
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
	shift = 216;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000000020000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0200000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0010000000000000ULL,
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
	shift = 112;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
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
	shift = 248;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000000000020ULL,
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
	shift = 100;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000002000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000200000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000200000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000004000000000ULL,
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
	shift = 132;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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