#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0x6C33D09C8E816335ULL,
		0x673B2118422697D7ULL,
		0x73C628004C5F150AULL,
		0x47384624EBF61627ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x01B9CC03104A4B8CULL,
		0x2FB807D09A462BA3ULL,
		0x9596EA9DD6F8DCD0ULL,
		0x6D1CA08190553E48ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x6A7A04997E371796ULL,
		0x37831947A7E06C34ULL,
		0xDE2F3D627566383AULL,
		0x5A1BA5A35BA0D7DEULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48EDD3E7596AA982ULL,
		0xFB6A67C1665DF1FDULL,
		0xD3E668C449847C2DULL,
		0x2B953C50383888B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3906E48F0B65A8C2ULL,
		0xA1040D902A12B985ULL,
		0x1EFC051C7237195DULL,
		0x7BD9C8EDF68E1EBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FE6EF584E0500ADULL,
		0x5A665A313C4B3878ULL,
		0xB4EA63A7D74D62D0ULL,
		0x2FBB736241AA69F3ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C821BE5E2ECCF9BULL,
		0x991C3234F55AB160ULL,
		0x6369D4985DB76A21ULL,
		0x6DD0C15067D23B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4538B04AEDE9CA1BULL,
		0x791FAB4E757FC5BBULL,
		0xB6FCA271CF1615B2ULL,
		0x50463196B0D52B14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17496B9AF5030580ULL,
		0x1FFC86E67FDAEBA5ULL,
		0xAC6D32268EA1546FULL,
		0x1D8A8FB9B6FD1035ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BEC6A87460F9506ULL,
		0x81C7920C14A5E401ULL,
		0xCDB16B8FAA977BF5ULL,
		0x1A7DB4F9DB6D5743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC398CEDE0B4D0A29ULL,
		0xBA422C2FC752640EULL,
		0x1AA9B097C8041BD4ULL,
		0x152FD70348DAE4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8539BA93AC28ADDULL,
		0xC78565DC4D537FF2ULL,
		0xB307BAF7E2936020ULL,
		0x054DDDF69292728BULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA57C3F74A2B78A94ULL,
		0x890A2CD1C2619A46ULL,
		0x703D42AE8E1E68B6ULL,
		0x033834538322ED3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11041A998512956FULL,
		0x2F82E96760E00885ULL,
		0x5E05211AF470802EULL,
		0x37BA94F94B338D6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x947824DB1DA4F512ULL,
		0x5987436A618191C1ULL,
		0x1238219399ADE888ULL,
		0x4B7D9F5A37EF5FD0ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7126984B64A343BULL,
		0xD8ED82E9B95B2B5BULL,
		0x8855BB2020A26B47ULL,
		0x43A391B5F1B76ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE777E17D739E4C96ULL,
		0xCF19DF283FAB3C94ULL,
		0x2C2CB4DCCB21F81CULL,
		0x6E0BB1C5770E362EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF9A880742ABE792ULL,
		0x09D3A3C179AFEEC6ULL,
		0x5C2906435580732BULL,
		0x5597DFF07AA938A3ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x110377E617ECE185ULL,
		0x820E4616302BB3EEULL,
		0x351F36705F1D62CCULL,
		0x2E5698CA3AC58F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258F6CC05D1007DBULL,
		0x39CC2FBCA73703E6ULL,
		0x97E8B92D83271D18ULL,
		0x24FE62C23741FFA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB740B25BADCD9AAULL,
		0x4842165988F4B007ULL,
		0x9D367D42DBF645B4ULL,
		0x0958360803838FB3ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2D24C636E2BF16DULL,
		0x4280B170C8FAA6A6ULL,
		0x7A6F921B09828195ULL,
		0x1CC01321DC1B4D08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x497A3297A6CD9DE5ULL,
		0x9F5611754BC96E7AULL,
		0xD3AFBEC97FB3997AULL,
		0x11FB82E6ED383115ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x995819CBC75E5388ULL,
		0xA32A9FFB7D31382CULL,
		0xA6BFD35189CEE81AULL,
		0x0AC4903AEEE31BF2ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA678206695C8FB75ULL,
		0xC6D28CC87137BF46ULL,
		0x62FA1743242E715EULL,
		0x2B2B3DA72D0071DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DBBB0434E521DEDULL,
		0x213FAF84E7B287A2ULL,
		0x474E8937494465C3ULL,
		0x34078E51A379D14FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28BC70234776DD75ULL,
		0xA592DD43898537A4ULL,
		0x1BAB8E0BDAEA0B9BULL,
		0x7723AF558986A08BULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ABF648B339ECC73ULL,
		0x68BDD53679210E55ULL,
		0x963061BDB9705823ULL,
		0x77AE74C3B8FD188EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E30BBBE70B00A6AULL,
		0x1703B104C1CBDC37ULL,
		0x1A68CE9792BD2553ULL,
		0x4226B6561A21D0EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8EA8CCC2EEC209ULL,
		0x51BA2431B755321EULL,
		0x7BC7932626B332D0ULL,
		0x3587BE6D9EDB47A1ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x871246D2E8A3028BULL,
		0x015F465D71E2D3EEULL,
		0xFD9E6BEDBF0C5D46ULL,
		0x15A7AB3E9B6A1A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x945884BD6D134A2CULL,
		0x705359CEDA7D647AULL,
		0x79F555172D9EB323ULL,
		0x2533F567B58CBD7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2B9C2157B8FB84CULL,
		0x910BEC8E97656F73ULL,
		0x83A916D6916DAA22ULL,
		0x7073B5D6E5DD5CB9ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x356BB046113AA161ULL,
		0xDB528E659C4BEC90ULL,
		0xCBB56CE082F273E2ULL,
		0x3E04850A3485808AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27C4A659BA322C3BULL,
		0xC62B75315DBBFF52ULL,
		0x607F2FC32F95C947ULL,
		0x3C9F266B7E76982DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DA709EC57087526ULL,
		0x152719343E8FED3EULL,
		0x6B363D1D535CAA9BULL,
		0x01655E9EB60EE85DULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE4246E5B464B379ULL,
		0x62DA01D54542A6DBULL,
		0xFAB35CBA2386F3E9ULL,
		0x6E1E1361336243C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA482995BCDE5324CULL,
		0x6BF777A75D4498DDULL,
		0xEF9F5FFAADDE0C7AULL,
		0x727C933AE08214BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59BFAD89E67F811AULL,
		0xF6E28A2DE7FE0DFEULL,
		0x0B13FCBF75A8E76EULL,
		0x7BA1802652E02F0CULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA28F651E94DDBD33ULL,
		0x77EFE64F1302510DULL,
		0x619AE262821546ECULL,
		0x11BF154DBB03C8E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7088F620552CC61EULL,
		0x0C4BC4D8F0169D3FULL,
		0xDD85AF01EAF0917AULL,
		0x354C961539F32541ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32066EFE3FB0F702ULL,
		0x6BA4217622EBB3CEULL,
		0x841533609724B572ULL,
		0x5C727F388110A3A7ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BACF7518194E588ULL,
		0xE2668E3FCE7EEE5AULL,
		0xC175A2172A72AD36ULL,
		0x002E7A5FC4421D9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66893AA6DAEF64ECULL,
		0xED23AA00EAFB22C8ULL,
		0xFB35A5B4259AE788ULL,
		0x5E150AC23F281D58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA523BCAAA6A58089ULL,
		0xF542E43EE383CB91ULL,
		0xC63FFC6304D7C5ADULL,
		0x22196F9D851A0044ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7DC449A3D6B80A7ULL,
		0x4FC9C115309EB486ULL,
		0x1C02D417B8B4784AULL,
		0x5A75AEF01837EE66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69288B07C8DFDDC1ULL,
		0xF83FBE7869E8DE7CULL,
		0xEA683CB90C4AB777ULL,
		0x3F6D15F099F28E5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EB3B992748BA2E6ULL,
		0x578A029CC6B5D60AULL,
		0x319A975EAC69C0D2ULL,
		0x1B0898FF7E456009ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1062CE413D3FF15ULL,
		0x53BCFBA3A754C678ULL,
		0x1924A2158184119CULL,
		0x77854396861C4F64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x617EFF4CEBD8E12AULL,
		0x93793C909AA4AB9EULL,
		0x9AA97B52CBC6DA94ULL,
		0x760625EA9B86F8AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F872D9727FB1DEBULL,
		0xC043BF130CB01ADAULL,
		0x7E7B26C2B5BD3707ULL,
		0x017F1DABEA9556B5ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F674134851161CAULL,
		0x3CD3F635DF99477AULL,
		0xE65828B4D065F443ULL,
		0x58B3D40B01CDFA66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957CB1DA3CF58B69ULL,
		0x448238D64CC6F58AULL,
		0x999B6BB9F3944ADDULL,
		0x057A75E158A32CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9EA8F5A481BD661ULL,
		0xF851BD5F92D251EFULL,
		0x4CBCBCFADCD1A965ULL,
		0x53395E29A92ACD6DULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0A0850C53563EBAULL,
		0xA007EDED627DBEBBULL,
		0x5B63FFA27507AC7DULL,
		0x0BA7101E45725F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3396698A9DDC581ULL,
		0xD5BBEFAB6A70C9DBULL,
		0x4246271501771383ULL,
		0x3D9B23C01273CEB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD671E73A9787926ULL,
		0xCA4BFE41F80CF4DFULL,
		0x191DD88D739098F9ULL,
		0x4E0BEC5E32FE90DAULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53466E9A1D07D781ULL,
		0x7582FEF07BA04EFAULL,
		0x897FA963CDCB1144ULL,
		0x51BF005C89D1924DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAC4100C6B2F8610ULL,
		0xB3AC1770C19AE05EULL,
		0x3E691FCB5F4ED600ULL,
		0x5788EE83D804325FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88825E8DB1D8515EULL,
		0xC1D6E77FBA056E9BULL,
		0x4B1689986E7C3B43ULL,
		0x7A3611D8B1CD5FEEULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x904CF7E89351D0E0ULL,
		0xCB54BA295F515B79ULL,
		0xA05A1929DC8E1C25ULL,
		0x1CB716F7B357874DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36A440DC67EB316ULL,
		0x34E897E9BF54A2A9ULL,
		0x9B8426D09D908F0BULL,
		0x21CEBE555CA30AD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACE2B3DACCD31DB7ULL,
		0x966C223F9FFCB8CFULL,
		0x04D5F2593EFD8D1AULL,
		0x7AE858A256B47C7CULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DD34670A97F4322ULL,
		0xDFAC28AF2AF4B4A8ULL,
		0x430BD5BC2BB40FD1ULL,
		0x0708D1D8A6C98459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x250A820045DEC00EULL,
		0x218F70A716E3372EULL,
		0xB1FF9907F362A88DULL,
		0x4166CB171FFF0337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28C8C47063A08301ULL,
		0xBE1CB80814117D7AULL,
		0x910C3CB438516744ULL,
		0x45A206C186CA8121ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8EBE7616208A8B4ULL,
		0x82B3CB3238FC74A2ULL,
		0x0AAAAE8D47A8E233ULL,
		0x48390B56E92A472CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EFEAB6C35932CA4ULL,
		0x98DC68E437A4AD31ULL,
		0x1C9FD5E0AC883769ULL,
		0x7BDC2138D0700ED3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69ED3BF52C757BFDULL,
		0xE9D7624E0157C771ULL,
		0xEE0AD8AC9B20AAC9ULL,
		0x4C5CEA1E18BA3858ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1336E78A785FBA8AULL,
		0xFC07663A84426A99ULL,
		0x46C4B3EA198B3F71ULL,
		0x21CADBF567F27447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEE3F65CB3910E2ULL,
		0x818AC4E4C924029CULL,
		0x1E230B55BB397AC5ULL,
		0x7738F4E9AD3781F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC548A824AD26A995ULL,
		0x7A7CA155BB1E67FCULL,
		0x28A1A8945E51C4ACULL,
		0x2A91E70BBABAF257ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9061A6B28776B5B8ULL,
		0xCFDF7A9F8D4765A1ULL,
		0x8CAF9C0F5AC25284ULL,
		0x45627D44E7E48DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820E59FCA9DB1350ULL,
		0x05BC6B2AB4187ACFULL,
		0x9D0383EF39C2AFDDULL,
		0x7219A6E78994E6D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E534CB5DD9BA255ULL,
		0xCA230F74D92EEAD2ULL,
		0xEFAC182020FFA2A7ULL,
		0x5348D65D5E4FA722ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26D8F1B91DDFE2CEULL,
		0xDEDD1A1BFF717C46ULL,
		0x58CB54832D0E2F98ULL,
		0x561BDB50B9E56399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DEA34DEB759177ULL,
		0xE6B83FB54806D8AFULL,
		0xB782826166923C6DULL,
		0x171A3DEBF4CC0715ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3FA4E6B326A5157ULL,
		0xF824DA66B76AA396ULL,
		0xA148D221C67BF32AULL,
		0x3F019D64C5195C83ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9F5FB6EE56CD32FULL,
		0x371047AD64CE2BF1ULL,
		0x7AAB2BAA29944B94ULL,
		0x46E6318D2796804EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E456F96885C25BULL,
		0x615AC84148C369C6ULL,
		0x8AEA36BEEDF5EC8FULL,
		0x38FDFEBA5819336EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB111A4757CE710D4ULL,
		0xD5B57F6C1C0AC22AULL,
		0xEFC0F4EB3B9E5F04ULL,
		0x0DE832D2CF7D4CDFULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D9E7B150BEA0200ULL,
		0x547759E943139C82ULL,
		0x633577A0A8156AEFULL,
		0x367520C01EEBFAD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31AA813B5C836D13ULL,
		0xB64BB9F956C0FCFFULL,
		0x77C1EA39E25F2F51ULL,
		0x1F805F9363094F38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBF3F9D9AF6694EDULL,
		0x9E2B9FEFEC529F82ULL,
		0xEB738D66C5B63B9DULL,
		0x16F4C12CBBE2AB9EULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D5F35BDA1573991ULL,
		0x6CA80220BB8ED82DULL,
		0x6AFB58994B078142ULL,
		0x7F3C256051945F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECEFD333AC979DFULL,
		0x56BDB90EE72045DAULL,
		0x82E257C8B5EA97D5ULL,
		0x5464FE198CACD814ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E90388A668DBFB2ULL,
		0x15EA4911D46E9253ULL,
		0xE81900D0951CE96DULL,
		0x2AD72746C4E78731ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01BFFD2BE80F6C25ULL,
		0xD9FB0430E28E617AULL,
		0x68EF9E0981FC3DB8ULL,
		0x49AA9183C0957EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFB1437F80728308ULL,
		0x2F1CCF1FD9E39076ULL,
		0x53F550EEB7AD24D5ULL,
		0x30F56E458F601397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020EB9AC679CE91DULL,
		0xAADE351108AAD103ULL,
		0x14FA4D1ACA4F18E3ULL,
		0x18B5233E31356B44ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F588D8DE21B8AB2ULL,
		0xB0A0F4AEA2E27C4CULL,
		0xE589CD73543EFCB1ULL,
		0x34ACDAC53CC939FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0892AE85989EE7D9ULL,
		0x14CD5A2E8847CA0EULL,
		0x7D8121038C091E96ULL,
		0x3134456459B1A3E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66C5DF08497CA2D9ULL,
		0x9BD39A801A9AB23EULL,
		0x6808AC6FC835DE1BULL,
		0x03789560E317961CULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7898CF0C43FEF84FULL,
		0x0AFF8CC3D0E88F2BULL,
		0x05D79EFB7B0A5754ULL,
		0x406DF3039F1A2CFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F190C5F151E712ULL,
		0xB92416C4BD7A632EULL,
		0x8DAC557E48EC1ED1ULL,
		0x0936B08EC6FFAF1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64A73E4652AD113DULL,
		0x51DB75FF136E2BFDULL,
		0x782B497D321E3882ULL,
		0x37374274D81A7DDAULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF0B503EE0F7A972ULL,
		0xACED393E17540DE9ULL,
		0x8853862E4337F862ULL,
		0x0273921591EBAE77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6225B0B17457544ULL,
		0x99EB7FB511E94E1EULL,
		0x290CC3822976E34BULL,
		0x1B2D03CCC343AB76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8E8F533C9B2341BULL,
		0x1301B989056ABFCAULL,
		0x5F46C2AC19C11517ULL,
		0x67468E48CEA80301ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A5685593ADA54E2ULL,
		0x5B47083E21DCB337ULL,
		0xC59CA775CE0A0B20ULL,
		0x73042706E9526AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6872789961C05703ULL,
		0x0E865AFD509F9B83ULL,
		0x61EAB51B52D71290ULL,
		0x2F4971E46563EEC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E40CBFD919FDDFULL,
		0x4CC0AD40D13D17B4ULL,
		0x63B1F25A7B32F890ULL,
		0x43BAB52283EE7C18ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8345CE385F7E168ULL,
		0xE8AD3F63EBDDE947ULL,
		0x0E1039EE12D14D2FULL,
		0x3D6D1943BAB346C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5730617EDDD5D861ULL,
		0xD3FCC538BC7D8E9FULL,
		0xD86B249F244F63DAULL,
		0x4D2DACEFEB01692EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8103FB64A82208F4ULL,
		0x14B07A2B2F605AA8ULL,
		0x35A5154EEE81E955ULL,
		0x703F6C53CFB1DD92ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE90E9056DC4C45BULL,
		0x94621FB408652323ULL,
		0xD1E430343E9ADF83ULL,
		0x68D25B7BF09E6F41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE403C6149B440CBEULL,
		0x59238C4F76E70666ULL,
		0x92E85658C4D94309ULL,
		0x60A5541E9622582BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA8D22F0D280B79DULL,
		0x3B3E9364917E1CBCULL,
		0x3EFBD9DB79C19C7AULL,
		0x082D075D5A7C1716ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD21C7FA8A26F602CULL,
		0xE65F13F38D821118ULL,
		0x94F383FC347CA766ULL,
		0x65EDD6205BAF1860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2EA6FB246BB8795ULL,
		0x9D7542279D594DC5ULL,
		0x2A1B0E0942D85290ULL,
		0x7D724B513DABCCA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF320FF65BB3D884ULL,
		0x48E9D1CBF028C352ULL,
		0x6AD875F2F1A454D6ULL,
		0x687B8ACF1E034BB7ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65DB6EC88E46251AULL,
		0x2F8D510531CDA9E8ULL,
		0xF3542B58563B3D30ULL,
		0x5D3A8F135FC59432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C875C60BC30DA7ULL,
		0x0821CF7EFA43E32BULL,
		0xFA1267C76E4260DDULL,
		0x0F3684B3BCA9C30CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F12F90282831773ULL,
		0x276B81863789C6BDULL,
		0xF941C390E7F8DC53ULL,
		0x4E040A5FA31BD125ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AC52ADCA7115063ULL,
		0x0BC05D3CB34AD80BULL,
		0xBD9FC394208319DBULL,
		0x5C75EAC36E83DB87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5EE7DF90C775E0ULL,
		0xF5B44D5646A9C792ULL,
		0xE19E423059C27772ULL,
		0x0075F4385F7F2164ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E6642FD1649DA83ULL,
		0x160C0FE66CA11078ULL,
		0xDC018163C6C0A268ULL,
		0x5BFFF68B0F04BA22ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC262E2034C943642ULL,
		0xEB65792E56732616ULL,
		0xB3EB98C4660032FEULL,
		0x2B5BB90B64BEA2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x440816FB44348CCAULL,
		0xE472BF9239171E45ULL,
		0x67ACBE627593B162ULL,
		0x4D07D11B64653361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E5ACB08085FA965ULL,
		0x06F2B99C1D5C07D1ULL,
		0x4C3EDA61F06C819CULL,
		0x5E53E7F000596F5EULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0690D7376BF12093ULL,
		0x6E2202A036FE8896ULL,
		0x9150AD813D1E0843ULL,
		0x3C41865AF1F7F00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B05C8E67E36832ULL,
		0x54BDEEF465485FCEULL,
		0x9F0108B888659601ULL,
		0x71EFFCD017DA0A2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FE07AA9040DB84EULL,
		0x196413ABD1B628C7ULL,
		0xF24FA4C8B4B87242ULL,
		0x4A51898ADA1DE5E1ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF55353A7C39FE688ULL,
		0x283D33F747B002D9ULL,
		0xFD078FD877589305ULL,
		0x0002319AEFA4030FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8440DC46AF88550DULL,
		0xC042B19118DD64E7ULL,
		0xF9BA3CF13F1061BBULL,
		0x6AF493C3811E2266ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7112776114179168ULL,
		0x67FA82662ED29DF2ULL,
		0x034D52E738483149ULL,
		0x150D9DD76E85E0A9ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x136BEBB430BD0991ULL,
		0xC980DFE30DD6BF78ULL,
		0x2E1429875862610AULL,
		0x008A068384683DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD937B8E99EDE15ULL,
		0x5273F712DD67F420ULL,
		0x1A8420746438D099ULL,
		0x2A18683FCC9276A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8792B3FB471E2B69ULL,
		0x770CE8D0306ECB57ULL,
		0x13900912F4299071ULL,
		0x56719E43B7D5C749ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x555CDBCE460C4539ULL,
		0xDD8E289DBF901224ULL,
		0x4AD15114450C9E5EULL,
		0x4AD9717D0B423F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D5FBDFEBD53901DULL,
		0x012CB14692BAD7C4ULL,
		0x8DA12335CCD7D02BULL,
		0x0A2A6F20DB36CB5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7FD1DCF88B8B51CULL,
		0xDC6177572CD53A5FULL,
		0xBD302DDE7834CE33ULL,
		0x40AF025C300B7431ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x205CDB9E1971A939ULL,
		0x3F1C20E09BD7AA64ULL,
		0x66031C6323D2EA3CULL,
		0x0EE20B3784539935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D9C2447C27FA14ULL,
		0xF2012D1413633CC1ULL,
		0xF8FC4FDF96545656ULL,
		0x7F15B8A7E03383F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D8319599D49AF12ULL,
		0x4D1AF3CC88746DA2ULL,
		0x6D06CC838D7E93E5ULL,
		0x0FCC528FA4201542ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2372FF0E37603B7ULL,
		0xEAAFDD64398E7140ULL,
		0xE6933B470AC023C1ULL,
		0x00EF6422A1299A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835B963F7EE07A27ULL,
		0xFEFBFAF4C47D6669ULL,
		0x20F68135974AEA40ULL,
		0x7E77D21FDCE4670AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EDB99B16495897DULL,
		0xEBB3E26F75110AD7ULL,
		0xC59CBA1173753980ULL,
		0x02779202C445334FULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA51ED9AB12AF885CULL,
		0xD8B3BBF4E4FD5A5DULL,
		0x9B1D4735CE39637BULL,
		0x43611A077A9132E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B2C5ACD1D14536ULL,
		0x80D66357006081C1ULL,
		0x6F2360413580773BULL,
		0x186E5487988A88A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x926C13FE40DE4326ULL,
		0x57DD589DE49CD89CULL,
		0x2BF9E6F498B8EC40ULL,
		0x2AF2C57FE206AA48ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9BFD5C56E997FE5ULL,
		0x7E4A4C818AE30401ULL,
		0x7B3ABC436184D913ULL,
		0x4F2AE55DD3D41DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F7D2DE13F22C38ULL,
		0xFC0E2ECAD55BADB4ULL,
		0xFA3D09A33FD9CD48ULL,
		0x740A8B24BF21E33CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C802E75AA7539AULL,
		0x823C1DB6B587564DULL,
		0x80FDB2A021AB0BCAULL,
		0x5B205A3914B23A68ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6279970038B1C216ULL,
		0x9E02E16A2E39D274ULL,
		0x8418B0E73DB7BE92ULL,
		0x5F42BCFF547FB98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA362529ED36C5A28ULL,
		0x5021D3ABDEEA1F89ULL,
		0xD3DB924DE6B0DD11ULL,
		0x376B26CBAC228C60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF174461654567EEULL,
		0x4DE10DBE4F4FB2EAULL,
		0xB03D1E995706E181ULL,
		0x27D79633A85D2D29ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAA8B246A13F4CD4ULL,
		0x7B7BF9E5F1C5F519ULL,
		0xB9F4FD787A2007A5ULL,
		0x4B09EA405846CE56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380E381E0C1FCA29ULL,
		0x77BFAFFEAB1F9DE5ULL,
		0xAE447DC1F7AB3FCBULL,
		0x1B22BAE95B504A06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA29A7A28951F82ABULL,
		0x03BC49E746A65734ULL,
		0x0BB07FB68274C7DAULL,
		0x2FE72F56FCF68450ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x955208FF36FAE4E5ULL,
		0xB05CCDF3C68A0D8DULL,
		0xDE155EA120CDCD5AULL,
		0x79889880D6888F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD55A178A569C5A0DULL,
		0x28A6808A05044087ULL,
		0x07F644B67460A4FEULL,
		0x00C035261A2E731EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFF7F174E05E8AD8ULL,
		0x87B64D69C185CD05ULL,
		0xD61F19EAAC6D285CULL,
		0x78C8635ABC5A1BECULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A552F1A482A8249ULL,
		0x1AA8E8F1CD5AC663ULL,
		0xB0241E94C25FF3A2ULL,
		0x05DCE41384714609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAEB5AF6987E8026ULL,
		0xE7B5447C4B1F48B7ULL,
		0x6A7300E3D71D03B4ULL,
		0x4CC454FE951CE6A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF69D423AFAC0210ULL,
		0x32F3A475823B7DABULL,
		0x45B11DB0EB42EFEDULL,
		0x39188F14EF545F66ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A91B124367D6A0BULL,
		0x4E84343B76D9DF5BULL,
		0x8BFCD83B992CA76DULL,
		0x33252492A8DFA5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6CF3A1643E5534ULL,
		0x3A73AE67259867DDULL,
		0x9858DDB91029D1BBULL,
		0x731146701B717AC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC24BD82D23F14C4ULL,
		0x141085D45141777DULL,
		0xF3A3FA828902D5B2ULL,
		0x4013DE228D6E2B25ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00D3092D7693A4FAULL,
		0xF67523AF789798D3ULL,
		0xF8F11AB0462FCFFCULL,
		0x3E386008477AAF4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC80C1828EEAE5F2AULL,
		0xD232E7BCF66A16E3ULL,
		0x4A60FA1896A493ACULL,
		0x45A107D02D2B62A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38C6F10487E545BDULL,
		0x24423BF2822D81EFULL,
		0xAE902097AF8B3C50ULL,
		0x789758381A4F4CA3ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C37BC2CC5DE0641ULL,
		0x9075D9C88E2DC42BULL,
		0xA907639D86E32E29ULL,
		0x15215D7EE8B4133AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E574C0B66A48F3ULL,
		0xF77F2F4AB13C8DB7ULL,
		0xF2132608C7D47F06ULL,
		0x48D4D31F22CE83F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2252476C0F73BD3BULL,
		0x98F6AA7DDCF13674ULL,
		0xB6F43D94BF0EAF22ULL,
		0x4C4C8A5FC5E58F45ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB6B1F96F62B13F3ULL,
		0x35709E8D91951721ULL,
		0xBE53C659BFE40624ULL,
		0x422C73FFC1B88B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0289131FE05C9FC7ULL,
		0xF257DA4151FDB842ULL,
		0x0AF53E8AE53216E6ULL,
		0x31ECDEBDBE9B8AD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8E20C7715CE742CULL,
		0x4318C44C3F975EDFULL,
		0xB35E87CEDAB1EF3DULL,
		0x103F9542031D009BULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B684CFC922F5B7EULL,
		0xAC6C0F4161A0D89FULL,
		0x7D80AE6E6C986110ULL,
		0x27A25C9941AFF072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0448B736DF348B84ULL,
		0xCA40E1FE17346A17ULL,
		0x9E0FB89BD1740775ULL,
		0x195DC67973A41DB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x171F95C5B2FACFFAULL,
		0xE22B2D434A6C6E88ULL,
		0xDF70F5D29B24599AULL,
		0x0E44961FCE0BD2C0ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA1A7C589F60CBE9ULL,
		0x1222C5B36E053787ULL,
		0x41921B82181B60A2ULL,
		0x5D32E7630FB098A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501331277918E14DULL,
		0xD115777457007F60ULL,
		0x63F6F30BC7C5D59AULL,
		0x6822ED8886122F5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A074B312647EA89ULL,
		0x410D4E3F1704B827ULL,
		0xDD9B287650558B07ULL,
		0x750FF9DA899E694EULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36B2DCB65D57CFA4ULL,
		0xDBC6D059A4F0A417ULL,
		0xC40B49CF53444FC6ULL,
		0x371CE0EBE0807497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712AC077F1DBF0D5ULL,
		0xD0CB305A92CD8078ULL,
		0x712C33FD03F14E66ULL,
		0x52D899396EEF0FDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5881C3E6B7BDEBCULL,
		0x0AFB9FFF1223239EULL,
		0x52DF15D24F530160ULL,
		0x644447B2719164B8ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DA0138076118C23ULL,
		0x5D65AD6A693F311AULL,
		0xF52C26EDDBCF50D1ULL,
		0x15E89046AA9FF44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07ACA84680D1097CULL,
		0xB65325FCD1DD29C7ULL,
		0x6A1D4A04B11263BCULL,
		0x1EE5D49C8F626148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15F36B39F5408294ULL,
		0xA712876D97620753ULL,
		0x8B0EDCE92ABCED14ULL,
		0x7702BBAA1B3D9304ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF36D4FD5E11A05AULL,
		0xA370EBB5073547A4ULL,
		0x93D3C9A3FB6E7108ULL,
		0x5DD2C48E4C4BF247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD15AFC3D8E597A3ULL,
		0xF0D53208130D837EULL,
		0xC12703F48076B2E8ULL,
		0x48E93DFAC39E5FA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2212539852C08B7ULL,
		0xB29BB9ACF427C425ULL,
		0xD2ACC5AF7AF7BE1FULL,
		0x14E9869388AD92A4ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BC3807D8F271764ULL,
		0xAA59634E77F0FF2FULL,
		0xF73AA90DA111A83DULL,
		0x4BE81E32CACF6C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48DA1563D16363BULL,
		0x89EC345A1F3AE2F0ULL,
		0x7B008A8565612A98ULL,
		0x28C9F7F52C8B44CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7735DF275210E129ULL,
		0x206D2EF458B61C3EULL,
		0x7C3A1E883BB07DA5ULL,
		0x231E263D9E442779ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09BAAB1EBCD8CD30ULL,
		0x9FAA1399FDCF6908ULL,
		0xE5369AAA9367CEAAULL,
		0x15222CA14CA13888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1C089CF7B209CB9ULL,
		0x652F28346FD13651ULL,
		0x2F612EBC48432E31ULL,
		0x0130478456D6CF45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67FA214F41B83077ULL,
		0x3A7AEB658DFE32B6ULL,
		0xB5D56BEE4B24A079ULL,
		0x13F1E51CF5CA6943ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB72515D9DCBB7840ULL,
		0x765C834A391ED9E2ULL,
		0x180EB42DC8CBF505ULL,
		0x608038219F55E3E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF72883F09349037ULL,
		0x81E025B65FD4CB15ULL,
		0x14472820A946C7DBULL,
		0x394F67A7C1817701ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07B28D9AD386E809ULL,
		0xF47C5D93D94A0ECDULL,
		0x03C78C0D1F852D29ULL,
		0x2730D079DDD46CDFULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD384AD7E0BD4DC3EULL,
		0x7499F2E7A3E89E44ULL,
		0x9ACD1125951C70BDULL,
		0x787962EB969E16A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF140CA2F53A65AB0ULL,
		0xD0753AE4711F4821ULL,
		0xA5217C1DCD8ED376ULL,
		0x3A2A26C6E1B09799ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE243E34EB82E818EULL,
		0xA424B80332C95622ULL,
		0xF5AB9507C78D9D46ULL,
		0x3E4F3C24B4ED7F0EULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDB9671A7660D49AULL,
		0x75DCF1F3054A0930ULL,
		0x17C429981B80D1EFULL,
		0x17FCE33E56C123B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D60697F22EBEB0EULL,
		0x15C83432B39CA448ULL,
		0xC21BA0424580BF67ULL,
		0x623D4AB7984D77C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8058FD9B5374E979ULL,
		0x6014BDC051AD64E8ULL,
		0x55A88955D6001288ULL,
		0x35BF9886BE73ABEEULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03E1C1F606F5EE32ULL,
		0xD6881F8A40C719CDULL,
		0xE598A9345C004E76ULL,
		0x28A31AD7103E0532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x594B49A1FE97F79CULL,
		0x7CE0A960B7F0F752ULL,
		0xC7EF5D744803B0D7ULL,
		0x305A19F2EAF58ABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA967854085DF683ULL,
		0x59A7762988D6227AULL,
		0x1DA94BC013FC9D9FULL,
		0x784900E425487A73ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8E8CD8CD40F7D6CULL,
		0x20D03876DF98F41EULL,
		0x661FD220F16FBD91ULL,
		0x384A3293201FC7EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9323759C7783B965ULL,
		0xBA901E8F33F34823ULL,
		0x0D533872D176AC87ULL,
		0x357219CA903AC2BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25C557F05C8BC407ULL,
		0x664019E7ABA5ABFBULL,
		0x58CC99AE1FF91109ULL,
		0x02D818C88FE5052DULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC94DF65B009B924DULL,
		0xE94B524746027AD6ULL,
		0xE300459F853B91BFULL,
		0x06E8CFE80D28E72BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7330715253E2F53ULL,
		0x70646535F034E71EULL,
		0xA1DDA068535BE8A6ULL,
		0x43F2760A11866E81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x221AEF45DB5D62E7ULL,
		0x78E6ED1155CD93B8ULL,
		0x4122A53731DFA919ULL,
		0x42F659DDFBA278AAULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29129679DECB52D3ULL,
		0xF3FB0BCB17CFA91AULL,
		0x704F7038A91C100AULL,
		0x23F9E915B7F86911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34EBB2BF1B076468ULL,
		0xDD676B4351D24887ULL,
		0x466C26A1B9139A08ULL,
		0x121F6F8C9DCF8D73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF426E3BAC3C3EE6BULL,
		0x1693A087C5FD6092ULL,
		0x29E34996F0087602ULL,
		0x11DA79891A28DB9EULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53465D2401C91C50ULL,
		0x0A453C3A6B341235ULL,
		0x763D40AF44C72019ULL,
		0x446A8EB952F94021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548CCF02234C5F94ULL,
		0xCCAF64DE9E8C9A9DULL,
		0x0C4E5ED0E70444E6ULL,
		0x66704FCC551B9F89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEB98E21DE7CBCA9ULL,
		0x3D95D75BCCA77797ULL,
		0x69EEE1DE5DC2DB32ULL,
		0x5DFA3EECFDDDA098ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D091304E4B8BF94ULL,
		0x8FB7E73DDE3A5FE2ULL,
		0x8EDC3EBE79405F5AULL,
		0x4691D770A604E4F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5F04E07E7325FBULL,
		0x075CCFD7AD3C0647ULL,
		0x29ED11C1D010F0CEULL,
		0x28B92A70C94D5768ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEAA0E2466459999ULL,
		0x885B176630FE599AULL,
		0x64EF2CFCA92F6E8CULL,
		0x1DD8ACFFDCB78D8FULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2DE3BC90FD101ADULL,
		0x21A0E4480C6A622DULL,
		0x39777F399310BA57ULL,
		0x0C118A1A26B0666EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7854FC7012149903ULL,
		0x8F21452E775F5C1CULL,
		0x2777C7D38AF20538ULL,
		0x02AF8B7B8630857FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A893F58FDBC68AAULL,
		0x927F9F19950B0611ULL,
		0x11FFB766081EB51EULL,
		0x0961FE9EA07FE0EFULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA0DAB3F9A5D05E9ULL,
		0x890753D80C8E7C08ULL,
		0xE6E59F9A2075CC09ULL,
		0x5F1AE36E6B48FAA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB148C76E4FC3B8ULL,
		0x014C8C3F77D054A2ULL,
		0x37AB1564D5AFC18DULL,
		0x5E41AEFDAAD6940FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E5C62782C0D4231ULL,
		0x87BAC79894BE2766ULL,
		0xAF3A8A354AC60A7CULL,
		0x00D93470C0726695ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D8348A473452742ULL,
		0x296A2982A2F01A86ULL,
		0x44A327729BDDEAA1ULL,
		0x23824E8EB2D8AEB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD70FCFE6FABB2AULL,
		0x73CC29B6B6B83297ULL,
		0x4B713639620989F5ULL,
		0x7D34DC3098C0B3D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32AC38D48C4A6C05ULL,
		0xB59DFFCBEC37E7EEULL,
		0xF931F13939D460ABULL,
		0x264D725E1A17FAE1ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06DB6BCF9D6A58C3ULL,
		0x3CB087B4AB458923ULL,
		0x7752ADCB552A60A7ULL,
		0x3D279DA487563E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD915D93AD9481C5CULL,
		0xA2B4EC1A5B912158ULL,
		0xAF377FD2A6693268ULL,
		0x25BF1C6430DC1150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DC59294C4223C67ULL,
		0x99FB9B9A4FB467CAULL,
		0xC81B2DF8AEC12E3EULL,
		0x17688140567A2CD8ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66BE1505B0086E18ULL,
		0x4D324895F16C756FULL,
		0xC1F2226F28AE3C94ULL,
		0x17CEC8A2F78060FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC756B868DCD866B5ULL,
		0x14151EC4D6DA722DULL,
		0xD66132E7E303C51EULL,
		0x48272E720A592DD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F675C9CD3300750ULL,
		0x391D29D11A920341ULL,
		0xEB90EF8745AA7776ULL,
		0x4FA79A30ED273326ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26706809838F7DCBULL,
		0x771686968064CC7EULL,
		0x2221C3B711A30388ULL,
		0x4383DE3693B6E416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE935196462A9F0E0ULL,
		0x739A2BD4BA81CF35ULL,
		0x06189FB2897A8956ULL,
		0x52CA4702CCF3E5A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D3B4EA520E58CD8ULL,
		0x037C5AC1C5E2FD48ULL,
		0x1C09240488287A32ULL,
		0x70B99733C6C2FE76ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1408E749A35B378ULL,
		0xA6046A29CF1F7341ULL,
		0x6F2194BE6D038009ULL,
		0x33D293647826A82FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0995B96A47ED79D1ULL,
		0x5E135B170F993DD4ULL,
		0x1623D8D2F89EDBDCULL,
		0x52BA85052C02F054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7AAD50A52483994ULL,
		0x47F10F12BF86356DULL,
		0x58FDBBEB7464A42DULL,
		0x61180E5F4C23B7DBULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E7F86BEA2351251ULL,
		0x8F66A859972E9C5AULL,
		0xCBC835204A1E5F59ULL,
		0x6617FAF017967D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35403D161ECC51DEULL,
		0x0062E8E9E463A3BDULL,
		0xEA18140DF87952CCULL,
		0x443998B743701C40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD93F49A88368C073ULL,
		0x8F03BF6FB2CAF89CULL,
		0xE1B0211251A50C8DULL,
		0x21DE6238D4266103ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2317E88CA944112CULL,
		0x7017A023431DA203ULL,
		0x676635D6E5EE2479ULL,
		0x7720B740D1E2B754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D7C970AC6C78ADBULL,
		0x7158DE855695D093ULL,
		0x887004AB34735660ULL,
		0x1CB7BFEC70F5B35AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD59B5181E27C8651ULL,
		0xFEBEC19DEC87D16FULL,
		0xDEF6312BB17ACE18ULL,
		0x5A68F75460ED03F9ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9322841AEA9E925ULL,
		0x2E75E987875FF77BULL,
		0xEE0D1F4A22A2FA9FULL,
		0x5654DAE6703D275DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6006B90202DCDC2ULL,
		0x1E5757522CB287EAULL,
		0xB1030B1D4944452FULL,
		0x3541B69860A0151FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE331BCB18E7C1B63ULL,
		0x101E92355AAD6F90ULL,
		0x3D0A142CD95EB570ULL,
		0x2113244E0F9D123EULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCC8A762F2E36492ULL,
		0x432AA06FA24A4E7BULL,
		0xF02919FC5E0D1A5BULL,
		0x2F753103CDC87F0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738DD9B7A62593D5ULL,
		0x9337639714D827EBULL,
		0x8FEE17A8D0697AE4ULL,
		0x2F855CAC959B121FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x493ACDAB4CBDD0AAULL,
		0xAFF33CD88D722690ULL,
		0x603B02538DA39F76ULL,
		0x7FEFD457382D6CECULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AE38E503F747B22ULL,
		0x9EAA03AFF42F25AEULL,
		0x32C38140A0FB6E32ULL,
		0x2BBFA2263C612DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58403FFA8167898BULL,
		0x19CAD88ED45BEC7EULL,
		0x5714E9493BB5F198ULL,
		0x41A11091C985F54AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42A34E55BE0CF184ULL,
		0x84DF2B211FD33930ULL,
		0xDBAE97F765457C9AULL,
		0x6A1E919472DB385FULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFC2C2A16B7D0C52ULL,
		0xF4BD4DF58591C848ULL,
		0xCF4B13AA3EEFDFFFULL,
		0x7E5D8CF94EBEAB48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70D5E2E0E8F48FEULL,
		0x23B089BE6A78E251ULL,
		0xF7BA8409F15DE2F2ULL,
		0x4A0B6157B9C92A8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58B564735CEDC354ULL,
		0xD10CC4371B18E5F7ULL,
		0xD7908FA04D91FD0DULL,
		0x34522BA194F580B8ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8A2889FA2D7E15CULL,
		0xCF910071F0BFF893ULL,
		0x6761D6D2397C1F29ULL,
		0x31E5A018E4606D67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37AF0178B33D1146ULL,
		0x30F53FB793B56E41ULL,
		0x402CBFCB2DE304C2ULL,
		0x314167A055CEC73DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0F38726EF9AD016ULL,
		0x9E9BC0BA5D0A8A52ULL,
		0x273517070B991A67ULL,
		0x00A438788E91A62AULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB0F01AD56F09966ULL,
		0x066F3FFB35586041ULL,
		0x978E047C00C25348ULL,
		0x25C547C900E88291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7950502EDA790FD5ULL,
		0x5ABD47F68AB6F317ULL,
		0xA5C8B3C3AB431A23ULL,
		0x7C4B274237CD2986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41BEB17E7C77897EULL,
		0xABB1F804AAA16D2AULL,
		0xF1C550B8557F3924ULL,
		0x297A2086C91B590AULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D6A3BD4488BAB2AULL,
		0xB6438BEE3CF90A52ULL,
		0xAE3E87AED209B58EULL,
		0x1BB5E940A2C2B037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17C35B9348F87B6ULL,
		0xD00A932A115A7BEFULL,
		0x06694378870F453CULL,
		0x75468F39D9F89E93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BEE061B13FC2361ULL,
		0xE638F8C42B9E8E62ULL,
		0xA7D544364AFA7051ULL,
		0x266F5A06C8CA11A4ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF90E3C4D3D71B9EDULL,
		0x6E4E45D648181436ULL,
		0x7AA7A439F6507E92ULL,
		0x297C46C1C9A4DD70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08BF133028A6D787ULL,
		0x6320E645E97E5430ULL,
		0x78E9CEA37E7ECC84ULL,
		0x19C79AB0BBEF7DEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF04F291D14CAE266ULL,
		0x0B2D5F905E99C006ULL,
		0x01BDD59677D1B20EULL,
		0x0FB4AC110DB55F82ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF55E9F666B3A6051ULL,
		0x6524FC57941BEF89ULL,
		0x5A13C022E95D78F5ULL,
		0x27634F5B6EB32D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962ABE5C1C429374ULL,
		0xBCBCF51BC1211A7DULL,
		0x7D3B57783626B093ULL,
		0x07D97F1A6C0645F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F33E10A4EF7CCDDULL,
		0xA868073BD2FAD50CULL,
		0xDCD868AAB336C861ULL,
		0x1F89D04102ACE797ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED435084F7680C5ULL,
		0x3682C3603C8D59C5ULL,
		0xDD51A8AAA6813904ULL,
		0x7A2D57689872933EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700E256FAF81459CULL,
		0x08952101B6B5CF3DULL,
		0x8FC2A9D0D22FD880ULL,
		0x05182A52F491818BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EC60F989FF53B29ULL,
		0x2DEDA25E85D78A88ULL,
		0x4D8EFED9D4516084ULL,
		0x75152D15A3E111B3ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2B3369317AE7C1DULL,
		0x6A784ED66B8EA49CULL,
		0x798460A8891ADAF8ULL,
		0x30720121E9D201CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59B03497861B7CDULL,
		0x8AA16C7A65E1EE5AULL,
		0xBB2F75521B4211EEULL,
		0x51C9331B0D35B425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D1833499F4CC43DULL,
		0xDFD6E25C05ACB642ULL,
		0xBE54EB566DD8C909ULL,
		0x5EA8CE06DC9C4DA4ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3FAC9D00A70A940ULL,
		0xA1CD6F7D3BBEDEC6ULL,
		0x5DA2F8EDB0092160ULL,
		0x6A6E6BC51E730277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1229570275B251ULL,
		0x7911D9656C7FA117ULL,
		0x832026050F3039CAULL,
		0x1D2341E15D6839DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44E8A07907FAF6EFULL,
		0x28BB9617CF3F3DAFULL,
		0xDA82D2E8A0D8E796ULL,
		0x4D4B29E3C10AC89AULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF88B8BEF9682452AULL,
		0x06EAF8EE6A9F20A6ULL,
		0x4D23DB927553499BULL,
		0x4C68E5B0A83ED55DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x838BA1F68C0C95E0ULL,
		0x25586497609AA210ULL,
		0xF16047D79EFABBBEULL,
		0x3D391960B4E72894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74FFE9F90A75AF4AULL,
		0xE19294570A047E96ULL,
		0x5BC393BAD6588DDCULL,
		0x0F2FCC4FF357ACC8ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8B3FE12FCBB0D4AULL,
		0x91915EB74C1A725EULL,
		0x4EB39C2988AD67C4ULL,
		0x30D436DF2E14CB19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B4AB16170FED65ULL,
		0x8EACE7875D867B83ULL,
		0x2F75415168CEF8F4ULL,
		0x1FC6BB7DF4E7A709ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFFF52FCE5AB1FE5ULL,
		0x02E4772FEE93F6DBULL,
		0x1F3E5AD81FDE6ED0ULL,
		0x110D7B61392D2410ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8878F0C2849F2B03ULL,
		0xBF2508A3E0527331ULL,
		0x85BBF6C75C9B142CULL,
		0x4A0A8ED135BF7CC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C96E0D0C97A0CAULL,
		0x8A086396249A032BULL,
		0xBB6CF6B1B03E20DAULL,
		0x0E8F035A681F761EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FAF82B578078A39ULL,
		0x351CA50DBBB87006ULL,
		0xCA4F0015AC5CF352ULL,
		0x3B7B8B76CDA006A5ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x617E57A250E1239DULL,
		0x88D83507F32B5E16ULL,
		0x8AA978A1A3F2DCDFULL,
		0x5AEB2427C2CD1488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69624B71486F18F5ULL,
		0xC7A741578C6C0154ULL,
		0x0D26137B4C260B6FULL,
		0x245CB7D17339951DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF81C0C3108720AA8ULL,
		0xC130F3B066BF5CC1ULL,
		0x7D83652657CCD16FULL,
		0x368E6C564F937F6BULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F06EFA4E5432121ULL,
		0xCC0EDAD358E63A20ULL,
		0x3F8FE99442C2C037ULL,
		0x350E755CC688FF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDD0062ADEF1F925ULL,
		0x6C6EE44D24C5CE85ULL,
		0x023A9F9D1EA9541BULL,
		0x0E3FA479DEE5FE42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC136E97A065127FCULL,
		0x5F9FF68634206B9AULL,
		0x3D5549F724196C1CULL,
		0x26CED0E2E7A30136ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD8510A03E6B142BULL,
		0x35D575208FFA0797ULL,
		0xA19BE3B6372F94C9ULL,
		0x0A85164139FBBC73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F991480F01EB7AULL,
		0x7EA80F0B7BF611A7ULL,
		0x3B65F35E577BCAB2ULL,
		0x68156F814DEB12FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x648B7F582F69289EULL,
		0xB72D66151403F5F0ULL,
		0x6635F057DFB3CA16ULL,
		0x226FA6BFEC10A979ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECC4D73A0087734ULL,
		0x639EA232B4934705ULL,
		0xF6377CDB683BFA9BULL,
		0x7F52BAEF12BC3247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE3DC19742DEE8BULL,
		0x4214AC7F220FFBF5ULL,
		0x84F92D706991C269ULL,
		0x72D180184D24126AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02E8715A2BDA88A9ULL,
		0x2189F5B392834B10ULL,
		0x713E4F6AFEAA3832ULL,
		0x0C813AD6C5981FDDULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46F5731390DB94B9ULL,
		0xF1D399AE22DC66E2ULL,
		0xF24F1636585263DBULL,
		0x7BD2287A973EF882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7088A19629FFDAADULL,
		0xCAF1E20076235060ULL,
		0x701013C9747EFD4EULL,
		0x01C1B5493382E29AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD66CD17D66DBBA0CULL,
		0x26E1B7ADACB91681ULL,
		0x823F026CE3D3668DULL,
		0x7A10733163BC15E8ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41E6A3F1BC24685CULL,
		0xBB418B68C9D5D995ULL,
		0x219BF0DA783822B3ULL,
		0x64F0E087F4EF02B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A014995AD044F49ULL,
		0xB3A3C571F760E243ULL,
		0x9E28DC02FA5A2D8BULL,
		0x6B1675448B25134CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07E55A5C0F201900ULL,
		0x079DC5F6D274F752ULL,
		0x837314D77DDDF528ULL,
		0x79DA6B4369C9EF6BULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26EE83C46B62158EULL,
		0xFBF90614456FF91DULL,
		0xC69FF8CDBBE07C61ULL,
		0x7CAE2990A881916CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D36C14B5414BB8ULL,
		0xBB58308740FD2FC6ULL,
		0xC929529CC49D0FA9ULL,
		0x184C5AAEF7BFDFD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261B17AFB620C9D6ULL,
		0x40A0D58D0472C957ULL,
		0xFD76A630F7436CB8ULL,
		0x6461CEE1B0C1B19AULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x634E3D19DEFB3B61ULL,
		0x3347F515BE06E1A9ULL,
		0xC91A55C7134558ABULL,
		0x1B08570C0027562DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EDA7E821D6983FULL,
		0x99B7321F4677EC22ULL,
		0x3A61FB5E022891FFULL,
		0x2C64B202DDB53D36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9609531BD24A30FULL,
		0x9990C2F6778EF586ULL,
		0x8EB85A69111CC6ABULL,
		0x6EA3A509227218F7ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3617E9CE867145CULL,
		0x0B484EC459ABCA8DULL,
		0xF67A25355CBBE6AEULL,
		0x49799E20D0F34C95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A68276663A097C5ULL,
		0xC43A29B1FE56EB9FULL,
		0xC0F70EC0330D1984ULL,
		0x2C06510DED9FBD5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8F9573684C67C97ULL,
		0x470E25125B54DEEEULL,
		0x3583167529AECD29ULL,
		0x1D734D12E3538F36ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07D291EC51D4EA2EULL,
		0x7C66C29D18C9E57BULL,
		0xBB93280CAE137512ULL,
		0x5B7DF63E25C4C886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18FEAC1F28D787C5ULL,
		0x4AA57FA065B18E34ULL,
		0x316CF6B1C99FABCFULL,
		0x5604675B303D212FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEED3E5CD28FD6269ULL,
		0x31C142FCB3185746ULL,
		0x8A26315AE473C943ULL,
		0x05798EE2F587A757ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x336A73075916519AULL,
		0xD8172DD16976C0DCULL,
		0xC6327F53FAB1BAD8ULL,
		0x5341EAB0BC4A661CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E05EB5A8AE3804ULL,
		0x1D8F186480E194FAULL,
		0xD4790507B470F39CULL,
		0x7E1A013CA35DC03DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8A1451B0681983ULL,
		0xBA88156CE8952BE1ULL,
		0xF1B97A4C4640C73CULL,
		0x5527E97418ECA5DEULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7321872CDB21075BULL,
		0x049BA5945E9E350DULL,
		0x46B4B4957D4CE1F1ULL,
		0x2B4968134CE899C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE44ACF09768B831DULL,
		0x201F5CF1DD49B46EULL,
		0xEAFB8DF8F88D8BB1ULL,
		0x511F42B75444762BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED6B8236495842BULL,
		0xE47C48A28154809EULL,
		0x5BB9269C84BF563FULL,
		0x5A2A255BF8A4239BULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A8AC53B235E1019ULL,
		0x692E0449BC51EFE0ULL,
		0x300883A463C99750ULL,
		0x341C29EBCFAA3445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190BF467F9452F69ULL,
		0xCC2710BE5FB1878BULL,
		0xC9CB8B90B9590139ULL,
		0x3F684B8CB0692D73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x217ED0D32A18E09DULL,
		0x9D06F38B5CA06855ULL,
		0x663CF813AA709616ULL,
		0x74B3DE5F1F4106D1ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C4BA55EBE691CBFULL,
		0xA4E326C193862FF8ULL,
		0xA0C419D23FEBEEFFULL,
		0x18FE8F55BAD20ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D09BCBFBDD7BD9FULL,
		0xC35EC41685E04B91ULL,
		0xEA433173261C0F99ULL,
		0x132B628803B3BB99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF41E89F00915F20ULL,
		0xE18462AB0DA5E466ULL,
		0xB680E85F19CFDF65ULL,
		0x05D32CCDB71E5335ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D0E8F25F83CA6A2ULL,
		0xB78EAF1DF84F1DCBULL,
		0xE6C1B51EE995CE15ULL,
		0x3787A878970A21D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C69687FE538BF7ULL,
		0x13B889ACDB774340ULL,
		0x0686FDB3A6754CA0ULL,
		0x14D2883E56BEE0BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA747F89DF9E91AABULL,
		0xA3D625711CD7DA8AULL,
		0xE03AB76B43208175ULL,
		0x22B5203A404B4112ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BC1C27838139753ULL,
		0x431A9658512901D5ULL,
		0x6EDC70CF4CBBEBB0ULL,
		0x7D93C0A092FE9929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D48F4E4C0849E37ULL,
		0xB73991A2CA60353DULL,
		0x739195E99B90F53DULL,
		0x209F9A7655AF5BD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE78CD93778EF91CULL,
		0x8BE104B586C8CC97ULL,
		0xFB4ADAE5B12AF672ULL,
		0x5CF4262A3D4F3D53ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA360B676FDBED0FEULL,
		0x93F30D0E620063FAULL,
		0x06BC9D34B587F171ULL,
		0x04FF59A66747F699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2944C977B6017998ULL,
		0x1880F83D17004E16ULL,
		0x1BDCAF39F7D71F44ULL,
		0x46B737C8932C54D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A1BECFF47BD5753ULL,
		0x7B7214D14B0015E4ULL,
		0xEADFEDFABDB0D22DULL,
		0x3E4821DDD41BA1C3ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7940DF0414072C77ULL,
		0x2199A4FB5914262DULL,
		0x0009FFED7959DB3BULL,
		0x5BD3B22B29868A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FE4F4BA89AAB60ULL,
		0xD7CBA640F7ADF332ULL,
		0x4636D18802ED8421ULL,
		0x6B5170E53A347BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F428FB86B6C8104ULL,
		0x49CDFEBA616632FBULL,
		0xB9D32E65766C5719ULL,
		0x70824145EF520E42ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9D2922E3B855EADULL,
		0x19FFD5467E9FE347ULL,
		0xB057E5F7A4A13649ULL,
		0x6EBD5AE7FFC15A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF54C10FAFA28B32ULL,
		0x2D22FF9DEFDD62E2ULL,
		0xEE89D4708941C562ULL,
		0x3926CB950669EE2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA7DD11E8BE2D37BULL,
		0xECDCD5A88EC28064ULL,
		0xC1CE11871B5F70E6ULL,
		0x35968F52F9576BF1ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED23BCA8D2B515C8ULL,
		0x749E4CF8B1791582ULL,
		0x461AB1A8B5C3B331ULL,
		0x6471486BA29F4ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E9A8FDA7B7D8CFULL,
		0xF842D1082E47DAC3ULL,
		0x8146386AA86C9371ULL,
		0x4453D864DC6E6C7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x583A13AB2AFD3CF9ULL,
		0x7C5B7BF083313ABFULL,
		0xC4D4793E0D571FBFULL,
		0x201D7006C630DE3EULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37E3A6C74DB2483AULL,
		0xA79C08FDFC6349F0ULL,
		0x006094E3479113C4ULL,
		0x22514BE1DDFFCD7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBD438332682EC57ULL,
		0x4F5E60BB29AF4BC9ULL,
		0xB309DD75786FE568ULL,
		0x328AA596E291632DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C0F6E94272F5BD0ULL,
		0x583DA842D2B3FE26ULL,
		0x4D56B76DCF212E5CULL,
		0x6FC6A64AFB6E6A50ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE94E8CE7B0AA1B01ULL,
		0x02C8B18917F1C5DCULL,
		0x0BF49E46472E7B73ULL,
		0x39E1CE9735AF0A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB03A3CFA26ABD26CULL,
		0x3B45B0B54D683554ULL,
		0x9B562689849DCBD0ULL,
		0x0605389AC72A25ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39144FED89FE4895ULL,
		0xC78300D3CA899088ULL,
		0x709E77BCC290AFA2ULL,
		0x33DC95FC6E84E480ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1633C216C8EE6D40ULL,
		0xE48F440931DA65E4ULL,
		0xE44504AFFAF90B93ULL,
		0x25563AA03379197BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3499469C40CF542ULL,
		0x346DD5969CD6C373ULL,
		0xA34E0ADEFB99D1D6ULL,
		0x6E27BB7966BF4CC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72EA2DAD04E177EBULL,
		0xB0216E729503A270ULL,
		0x40F6F9D0FF5F39BDULL,
		0x372E7F26CCB9CCB6ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2797B2F67B4B3502ULL,
		0x13E1B49722795048ULL,
		0xB90E10D5932D565DULL,
		0x04592B359BE48E39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBFB501284185097ULL,
		0x5C796A5005126145ULL,
		0x9527C92BEA345B7FULL,
		0x2758A86B20EB6C5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B9C62E3F732E458ULL,
		0xB7684A471D66EF02ULL,
		0x23E647A9A8F8FADDULL,
		0x5D0082CA7AF921DFULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x211BE7305766C375ULL,
		0x2C35CD5D75D54F6BULL,
		0xCDB1F58D124CF96AULL,
		0x04BF37FF29C4CF95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C0321D212E6BAFULL,
		0x1CCEB66AFD048DCBULL,
		0x91EEFBE2A7637D72ULL,
		0x09D35861DBA25142ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED5BB513363857B3ULL,
		0x0F6716F278D0C19FULL,
		0x3BC2F9AA6AE97BF8ULL,
		0x7AEBDF9D4E227E53ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x995730C2933B4512ULL,
		0xCD11F02881066FE9ULL,
		0x4CE3FEA783DF8121ULL,
		0x292C390CACC9F226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D3644D7C6472316ULL,
		0xBA47FF985C0EA2EFULL,
		0x0C8FB2AA7469C5E8ULL,
		0x365B96ED7B435589ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C20EBEACCF421E9ULL,
		0x12C9F09024F7CCFAULL,
		0x40544BFD0F75BB39ULL,
		0x72D0A21F31869C9DULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x826F13FA1F87899AULL,
		0x4E257C17AE4C9B68ULL,
		0xEE1D46AA74E2B910ULL,
		0x7F33E54ED9E42916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3DB0D4C4C507BEULL,
		0x12B097519EE1A463ULL,
		0x7384D29AB98A8301ULL,
		0x32515CB4B1D393FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x733163255AC281DCULL,
		0x3B74E4C60F6AF705ULL,
		0x7A98740FBB58360FULL,
		0x4CE2889A28109517ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6055437AD1B4D18ULL,
		0x92303BD139CD3381ULL,
		0xDC85ACC2D6FDCE86ULL,
		0x052310A31F334D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFB57A315173C709ULL,
		0x936A50316342A593ULL,
		0x28B62AB31B806167ULL,
		0x346747B004E61952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x164FDA065BA785FCULL,
		0xFEC5EB9FD68A8DEEULL,
		0xB3CF820FBB7D6D1EULL,
		0x50BBC8F31A4D33F9ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03FEA19D48DF4F4FULL,
		0xE3582024C8C6A8F9ULL,
		0x8132146B3AC43DD2ULL,
		0x37B6F2508BD18B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F3AE389367FFB7ULL,
		0x72C396D4818D5CBFULL,
		0x43FEC88C53C294E6ULL,
		0x434E2A5984A9B0D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A0AF364B5774F85ULL,
		0x7094895047394C39ULL,
		0x3D334BDEE701A8ECULL,
		0x7468C7F70727DA5AULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BCA55E1C455D679ULL,
		0x2D7932EF45673B63ULL,
		0xAE82A2E3E8EBBBBDULL,
		0x178034D03649C519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FF67F7F9A2A7662ULL,
		0x2956F5A0D056C274ULL,
		0x469BB9796EA2B106ULL,
		0x6DE0A16C129A20E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BD3D6622A2B6004ULL,
		0x04223D4E751078EFULL,
		0x67E6E96A7A490AB7ULL,
		0x299F936423AFA437ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C4D6352E0D58AFFULL,
		0xF79B53E414CCAC94ULL,
		0xF4AA0BD37CCDFFCDULL,
		0x795A2706CBAD70C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13549801A4E61FABULL,
		0xB37BD764C1525359ULL,
		0xBBFF281FB2187651ULL,
		0x5DFC179F0C146965ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78F8CB513BEF6B54ULL,
		0x441F7C7F537A593BULL,
		0x38AAE3B3CAB5897CULL,
		0x1B5E0F67BF990761ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7124634F659AB042ULL,
		0xB1E9B0554784DCAFULL,
		0x86E8021E5C8D2F3FULL,
		0x54ADEBA89EDF5DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266552459C1CE0EEULL,
		0xF149B074DECF1823ULL,
		0x4DD71166FC015371ULL,
		0x36D6885799A27BFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4ABF1109C97DCF54ULL,
		0xC09FFFE068B5C48CULL,
		0x3910F0B7608BDBCDULL,
		0x1DD76351053CE1B2ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8875669EA72D94A9ULL,
		0x5A4BCF38A7B654D3ULL,
		0x81464FA16E8DA063ULL,
		0x743454146C21AEF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1646D827449DE0AEULL,
		0xA3C8476CDA43E28BULL,
		0xADF6951B2C818928ULL,
		0x20C937C54E7AA474ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x722E8E77628FB3FBULL,
		0xB68387CBCD727248ULL,
		0xD34FBA86420C173AULL,
		0x536B1C4F1DA70A84ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9D9927C94C4C310ULL,
		0x6F5B4ED5EFEDA947ULL,
		0x3B37F049134BE404ULL,
		0x488BD3145F656F7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8856400DE3090813ULL,
		0x154A22B54F32BA29ULL,
		0xB2DBFF3AC0A2F0FFULL,
		0x4754E9C4ED56518EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6183526EB1BBBAFDULL,
		0x5A112C20A0BAEF1EULL,
		0x885BF10E52A8F305ULL,
		0x0136E94F720F1DEFULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA85E138CD35D558DULL,
		0x45F01BE886E807A7ULL,
		0x1CEAD4C4768C4CF1ULL,
		0x6E6450A1B1ADB3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9E8A223927E0EC6ULL,
		0xA6795F3FAC67DB85ULL,
		0x8B1DE0D15F6A25D9ULL,
		0x5451D7FFDEA2BF30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE75716940DF46C7ULL,
		0x9F76BCA8DA802C21ULL,
		0x91CCF3F317222717ULL,
		0x1A1278A1D30AF4B5ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1779CB4AF007FAA1ULL,
		0xFF730260BAA2B0D2ULL,
		0x09BFCD339093715BULL,
		0x31C3621067B500B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE32EDCDE10C7038ULL,
		0x94EF3737CDDE8D01ULL,
		0x9238E10A6C8319F2ULL,
		0x3CAB20513A6C0BEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3946DD7D0EFB8A56ULL,
		0x6A83CB28ECC423D0ULL,
		0x7786EC2924105769ULL,
		0x751841BF2D48F4C4ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEF7869A569A9E5CULL,
		0xD7210430E2C72800ULL,
		0xA9ACBD99FE6C28ECULL,
		0x52319E0F1DF32983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04CBC644525A990ULL,
		0x1EDB8DF744C06465ULL,
		0x9E93DD3D2182C8DCULL,
		0x434D5FD161B05276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EAACA361174F4CCULL,
		0xB84576399E06C39BULL,
		0x0B18E05CDCE96010ULL,
		0x0EE43E3DBC42D70DULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5260C8F06EACC28ULL,
		0x1764D53E9D0EFB53ULL,
		0xCDE9FBABCBD2DA2CULL,
		0x6EA34C7FB0666CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3CD8AC25C2213C3ULL,
		0x5939D226973E64FAULL,
		0xE9C79B6807FD3E1CULL,
		0x56672D30AE9EECE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x415881CCAAC8B865ULL,
		0xBE2B031805D09659ULL,
		0xE4226043C3D59C0FULL,
		0x183C1F4F01C77FE3ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DDEDE8C4A1EA28BULL,
		0x9EE33011DE827D28ULL,
		0xC1F2927704564DF7ULL,
		0x514C89AAC2C68C08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D12EEE69705A7B6ULL,
		0x5B09B37675A64E33ULL,
		0x908504E7E50C731BULL,
		0x2567AAAA492D2F2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50CBEFA5B318FAD5ULL,
		0x43D97C9B68DC2EF5ULL,
		0x316D8D8F1F49DADCULL,
		0x2BE4DF0079995CDAULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD0D01CE1EE6A29EULL,
		0x0A22306839AB13A7ULL,
		0xBA34DFF80C419842ULL,
		0x5084DC49D95EAC7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CAEF6D8DDD29A3FULL,
		0x5608C7EAFA856D70ULL,
		0x6243E81CFC61601BULL,
		0x1A0747DC56A57F0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA05E0AF54114085FULL,
		0xB419687D3F25A637ULL,
		0x57F0F7DB0FE03826ULL,
		0x367D946D82B92D72ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB63181D051A7FA92ULL,
		0x52A0261974DAA6A5ULL,
		0xC146D34730DA24E5ULL,
		0x734EA36547657788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE83AE150327E795ULL,
		0x6BADC9E9ABFBFA57ULL,
		0x4CC528D7ADD6B327ULL,
		0x03194C3D90E5DCF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7ADD3BB4E8012FDULL,
		0xE6F25C2FC8DEAC4DULL,
		0x7481AA6F830371BDULL,
		0x70355727B67F9A92ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27BE9C10E86637C2ULL,
		0x68F92535D623198BULL,
		0x3C89CA964F4EEB8DULL,
		0x20B1DBCF74D56551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD90E2FE9DF9E3652ULL,
		0x107561FE685F2BECULL,
		0xE7076442785CECC8ULL,
		0x0044F0C47AD674D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EB06C2708C80170ULL,
		0x5883C3376DC3ED9EULL,
		0x55826653D6F1FEC5ULL,
		0x206CEB0AF9FEF07BULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x852DA4700365E081ULL,
		0x3057A46769B0CDA6ULL,
		0x2D3F67BA87387587ULL,
		0x174D5A3925052FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F2B1636D151F556ULL,
		0x71840A4901E29D38ULL,
		0x3ED8CE7281CC3F90ULL,
		0x6CF1B7E43527B532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16028E393213EB18ULL,
		0xBED39A1E67CE306EULL,
		0xEE669948056C35F6ULL,
		0x2A5BA254EFDD7ABBULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF576D053AE54E1DULL,
		0xA5127046187B9AF9ULL,
		0x335339086A4EF592ULL,
		0x5D12B2B81B6905ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F23F83AFD19180ULL,
		0x61B90CC361F5EC13ULL,
		0xA7F66168F542D23DULL,
		0x0DA8FA649E827E89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07652D818B13BC9DULL,
		0x43596382B685AEE6ULL,
		0x8B5CD79F750C2355ULL,
		0x4F69B8537CE68722ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAE54244C8F8A338ULL,
		0x7E716B019954029DULL,
		0x465167329407B41EULL,
		0x41950A29F7BD73F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x804B4932A5380C34ULL,
		0x2A5E50F8B08A70B7ULL,
		0xBFE99575B44AAC02ULL,
		0x24431CD6D8D57F46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A99F91223C09704ULL,
		0x54131A08E8C991E6ULL,
		0x8667D1BCDFBD081CULL,
		0x1D51ED531EE7F4A9ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x285085D789E8893FULL,
		0x57C944FEDCE56665ULL,
		0x0B70967D910E3239ULL,
		0x550D862B9F52BC66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8FAF44C91BB005ULL,
		0xA32151E628883A80ULL,
		0x3BEDDDF43C0B047CULL,
		0x5F93C83AEC50942CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCC0D692C0CCD927ULL,
		0xB4A7F318B45D2BE4ULL,
		0xCF82B88955032DBCULL,
		0x7579BDF0B3022839ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB8CDD2CDE8857E7ULL,
		0xE1D937966761C491ULL,
		0x7234C3A186401693ULL,
		0x66D2FE188039758AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C51ADF9E6B1B2AULL,
		0x932335F2F323C368ULL,
		0xBFCF4A05BD377998ULL,
		0x76BEEC8C7E138D1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AC7C24D401D3CAAULL,
		0x4EB601A3743E0129ULL,
		0xB265799BC9089CFBULL,
		0x7014118C0225E86BULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17E390E862C0C3D0ULL,
		0xAC868164A43A3572ULL,
		0x1F262161D406999EULL,
		0x44A8FF2A55809BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5821D16336AB4DACULL,
		0xAD4935A904EE34DBULL,
		0x7F59792F2F82EBC6ULL,
		0x2D338D2CAE4DF53BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFC1BF852C157624ULL,
		0xFF3D4BBB9F4C0096ULL,
		0x9FCCA832A483ADD7ULL,
		0x177571FDA732A6A0ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x821ACBB91A094C5EULL,
		0x81BBCB0835732FC6ULL,
		0x93C0EA9FD4B0628AULL,
		0x34EE13D84FC1341DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E591BB78C3FADF4ULL,
		0x052B8FB2F23C8173ULL,
		0xA2ECD3FE08830EC5ULL,
		0x64968D0EB38082E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13C1B0018DC99E57ULL,
		0x7C903B554336AE53ULL,
		0xF0D416A1CC2D53C5ULL,
		0x505786C99C40B137ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C83FAB8E41F91BFULL,
		0x417A09C4C0ED2A3AULL,
		0x825CDBEA84080870ULL,
		0x7C82BFC1DFE9FD76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE195CBD997CEB869ULL,
		0xD2A9E6D8DBDFB6D4ULL,
		0xF3A59B23AF124DC9ULL,
		0x41B43F367B1C2F16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AEE2EDF4C50D956ULL,
		0x6ED022EBE50D7365ULL,
		0x8EB740C6D4F5BAA6ULL,
		0x3ACE808B64CDCE5FULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF74CD43F92B355DAULL,
		0x08E10B5A9EAD2340ULL,
		0x4AB45A22B1819BDBULL,
		0x6F791B7FE6226C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE56991946DED24ULL,
		0x38A0DD1C314CC462ULL,
		0xFC29E20B0F47CCCCULL,
		0x3A8BD636C16FF82BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C676AADFE4568B6ULL,
		0xD0402E3E6D605EDEULL,
		0x4E8A7817A239CF0EULL,
		0x34ED454924B273EDULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA795BE855DD71929ULL,
		0xECCB8CB8498FA7A9ULL,
		0x8B32B4CB9C79388BULL,
		0x04210093ABC41429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D587F3F655AD4AFULL,
		0x8A421D65755D969BULL,
		0xF21A8547CA6DE592ULL,
		0x5E1B09373C4F3999ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A3D3F45F87C4467ULL,
		0x62896F52D432110EULL,
		0x99182F83D20B52F9ULL,
		0x2605F75C6F74DA8FULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84CB87BF4ADCA6C1ULL,
		0xBF420E1E28B0E939ULL,
		0x923F42FA424B7811ULL,
		0x2EA6473E27761241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD204A50CE6731D3CULL,
		0x404694E95FEC356BULL,
		0x97C8D65267D12567ULL,
		0x09000458C84C2406ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C6E2B264698985ULL,
		0x7EFB7934C8C4B3CDULL,
		0xFA766CA7DA7A52AAULL,
		0x25A642E55F29EE3AULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1BEECE669E3690DULL,
		0xBD106C5B5AEA1CFFULL,
		0xF2EA27FE96A929B9ULL,
		0x1F5B8FF5A76D9DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32CFBC5F7D0AC04CULL,
		0x62E56A2CCCAD382BULL,
		0xD4E1AD6819845052ULL,
		0x71540BBD2083CC4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EEF3086ECD8A8AEULL,
		0x5A2B022E8E3CE4D4ULL,
		0x1E087A967D24D967ULL,
		0x2E07843886E9D16AULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x095CA7FB58AB2CE2ULL,
		0x393D397B90C0D6EBULL,
		0xE9ED6FEA6641DC70ULL,
		0x1CAB59BBCBEA8EA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE3E732FE3A118AULL,
		0xA3F3F21B1466A8D0ULL,
		0x06CB5BC4E7780DADULL,
		0x3D8A81F202C1EB93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E78C0C85A711B45ULL,
		0x954947607C5A2E1AULL,
		0xE32214257EC9CEC2ULL,
		0x5F20D7C9C928A316ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED2477F263B99096ULL,
		0x5C8425BB558144ABULL,
		0x043A8AA9C9313877ULL,
		0x38D8A863B530AA4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14322D0331CD349DULL,
		0x53465D5870D69598ULL,
		0x7F9C13934D24FACDULL,
		0x54C40A1CC2283A52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8F24AEF31EC5BE6ULL,
		0x093DC862E4AAAF13ULL,
		0x849E77167C0C3DAAULL,
		0x64149E46F3086FF8ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x565C7FC3CB0D8FB6ULL,
		0x12E87FFB7610CB16ULL,
		0xB69BA2DD5DE5E13CULL,
		0x041A9873ACE481ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED5A3B9C46CACFA7ULL,
		0xD07313C6DC74EDAEULL,
		0x546E16F4670E8034ULL,
		0x3CDD71603BB544D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x690244278442BFFCULL,
		0x42756C34999BDD67ULL,
		0x622D8BE8F6D76107ULL,
		0x473D2713712F3CD9ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88EA5C3114D7866FULL,
		0xC1AF873F04AA082EULL,
		0x94BA723FF7293222ULL,
		0x14DC7B926054A1B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41F22F2A32083B0ULL,
		0xFD92EFADCF16F913ULL,
		0xA750932BF5F0A86AULL,
		0x721C27662D30DD46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94CB393E71B702ACULL,
		0xC41C979135930F1AULL,
		0xED69DF14013889B7ULL,
		0x22C0542C3323C46CULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE9E522915682389ULL,
		0x7334A7FF9D128365ULL,
		0x2E006F4D10092168ULL,
		0x3E2C0E85AE0C9A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33F52B82236EE95EULL,
		0xC66410D6D3023D00ULL,
		0xF426152EA9A9B6DEULL,
		0x2C59D763E5C1DBA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAA926A6F1F93A2BULL,
		0xACD09728CA104665ULL,
		0x39DA5A1E665F6A89ULL,
		0x11D23721C84ABEBDULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF744F7D6E670EE18ULL,
		0x6828384C9FC1663BULL,
		0xC02F695E1DBB0B59ULL,
		0x269210E566E4844FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94FAA394507E6314ULL,
		0xEB5DF353EEA43D3EULL,
		0x016D08346A5E162BULL,
		0x4A70E6C9AF549E28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x624A544295F28AF1ULL,
		0x7CCA44F8B11D28FDULL,
		0xBEC26129B35CF52DULL,
		0x5C212A1BB78FE627ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B07B4A086DF84E2ULL,
		0xF6B94484638BD361ULL,
		0x28B0F0CEA9308F1EULL,
		0x7CD6B45590EF1725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0353929E8C031C1FULL,
		0xA4ED28796B531B4AULL,
		0x20F01126197CC0D6ULL,
		0x7F9F23397D77F62AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97B42201FADC68B0ULL,
		0x51CC1C0AF838B817ULL,
		0x07C0DFA88FB3CE48ULL,
		0x7D37911C137720FBULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x658F0EF9AD8D1CA4ULL,
		0xE0A510F2C1BCE210ULL,
		0xE53033EBF4298E0CULL,
		0x53B71F5B2F1F2071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6485217702CCF499ULL,
		0x8ACE0C514B8531E7ULL,
		0x8D69E48FD717C2E8ULL,
		0x0D0EF7C431512B9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0109ED82AAC0280BULL,
		0x55D704A17637B029ULL,
		0x57C64F5C1D11CB24ULL,
		0x46A82796FDCDF4D3ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A8194AA046CDEABULL,
		0xE6653AD2F5B27AFBULL,
		0x020493324462C0ECULL,
		0x044BDBBC205A8BE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B57E83140098552ULL,
		0xE6D62E6BFA89EF66ULL,
		0x5846D49488AF19F2ULL,
		0x73B9525DCB1D64E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF29AC78C4635946ULL,
		0xFF8F0C66FB288B94ULL,
		0xA9BDBE9DBBB3A6F9ULL,
		0x1092895E553D26FFULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3A0EB2BBF01AC0AULL,
		0xD827BC0D29B8496DULL,
		0xEB0E3B30944B3BBAULL,
		0x716A7103EA06593AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45A477691B9FFBACULL,
		0x15971A2A8059AC1BULL,
		0xA77127E3DAF4EE8DULL,
		0x06942EB961588727ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADFC73C2A361B05EULL,
		0xC290A1E2A95E9D52ULL,
		0x439D134CB9564D2DULL,
		0x6AD6424A88ADD213ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C3D690AC07CCC2AULL,
		0x3281D8BD9C05B0ECULL,
		0x2BFEA79E6BE2401BULL,
		0x53562EA70FB9A7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4239226D1C135C5ULL,
		0x4D88DEED14F28D59ULL,
		0x98FCEAABC022DFA4ULL,
		0x4D7207BCA9E48D79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9819D6E3EEBB9665ULL,
		0xE4F8F9D087132392ULL,
		0x9301BCF2ABBF6076ULL,
		0x05E426EA65D51A2CULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA89A73A28A861E50ULL,
		0xC699B0A7B6F62766ULL,
		0xE2B12E582F904B52ULL,
		0x726FBCC398984C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16742E5D847C812ULL,
		0x586DF5A0767408B8ULL,
		0x037614140DF43CE9ULL,
		0x74B79C8CE5ED63D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB73330BCB23E562BULL,
		0x6E2BBB0740821EADULL,
		0xDF3B1A44219C0E69ULL,
		0x7DB82036B2AAE896ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E481E28E57759C7ULL,
		0x321BFC657B1C5A98ULL,
		0x584D84CC685CFCE2ULL,
		0x065FF5FE0C33E2F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBAF65A12CAB129ULL,
		0x03CA56444A74A9F6ULL,
		0x3AD2CD98663D6884ULL,
		0x6A20D4A7CDC71A9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x228D27CED2ACA88BULL,
		0x2E51A62130A7B0A2ULL,
		0x1D7AB734021F945EULL,
		0x1C3F21563E6CC85AULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D2299705D48398AULL,
		0xC5D123708F45E079ULL,
		0x3E4980F4E76107CBULL,
		0x72E9A49E77C3B938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08C1721A3B8E69BULL,
		0x3C9140E8F9996A77ULL,
		0xB2BDB396A5491C0EULL,
		0x6708100EB027B610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC96824EB98F52EFULL,
		0x893FE28795AC7601ULL,
		0x8B8BCD5E4217EBBDULL,
		0x0BE1948FC79C0327ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFFE6A0FF3C8F9FEULL,
		0xF08852A00AC6C5C1ULL,
		0x5DBE013137EF9C36ULL,
		0x23E5D43BDCF15490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE261C7BBEC63AD14ULL,
		0x53B8463DFA97428EULL,
		0x5BAAB80137F6E091ULL,
		0x1142F9C6042493E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD9CA25407654CEAULL,
		0x9CD00C62102F8332ULL,
		0x0213492FFFF8BBA5ULL,
		0x12A2DA75D8CCC0ACULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0E4DE090FE5C9EFULL,
		0xCF9A7661630AF49AULL,
		0x9AC12A64C6D57A32ULL,
		0x2C75C77F97AF5FD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB818F9C73F182A55ULL,
		0x9D21F244E33CDA8EULL,
		0xDE514640847DB260ULL,
		0x5D53FA343C886EDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8CBE441D0CD9F87ULL,
		0x3278841C7FCE1A0BULL,
		0xBC6FE4244257C7D2ULL,
		0x4F21CD4B5B26F0FDULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE206D03787CA86DFULL,
		0xD0D3C513E4D41486ULL,
		0x882EB81D7D190DC0ULL,
		0x3BF3E30D02734115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A2B87D26118B6BULL,
		0xADC47F2FE9DD4C91ULL,
		0xF54BADA81865A31AULL,
		0x53AF06F224C81499ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x106417BA61B8FB61ULL,
		0x230F45E3FAF6C7F5ULL,
		0x92E30A7564B36AA6ULL,
		0x6844DC1ADDAB2C7BULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE926D6267FB36BDEULL,
		0xD38B1A6B19AD0920ULL,
		0xC0BEBF934270F026ULL,
		0x7D7F883380BBC7B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8899554D13C18606ULL,
		0xF440576C87C8F851ULL,
		0x0BFBEB5D720745C7ULL,
		0x0F9BB4168C9131D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x608D80D96BF1E5D8ULL,
		0xDF4AC2FE91E410CFULL,
		0xB4C2D435D069AA5EULL,
		0x6DE3D41CF42A95E0ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ED335E089D64C22ULL,
		0x8808C1C5E571C8FCULL,
		0xAEDB3A048D8698ADULL,
		0x77A994A86D841D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8089493F1E208300ULL,
		0x0DE29756AAFF94CBULL,
		0x325F24FA9B19897FULL,
		0x46A1A1C3977F8991ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E49ECA16BB5C922ULL,
		0x7A262A6F3A723430ULL,
		0x7C7C1509F26D0F2EULL,
		0x3107F2E4D60493B7ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BA0CA714BE762E6ULL,
		0x226AA32A330125B6ULL,
		0x48830824C0FCEE47ULL,
		0x090F3262B60C7659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x285A4AAE987AD081ULL,
		0x2713470E11095B5AULL,
		0x976B430180014221ULL,
		0x2F4239756CB2EE54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53467FC2B36C9252ULL,
		0xFB575C1C21F7CA5CULL,
		0xB117C52340FBAC25ULL,
		0x59CCF8ED49598804ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67C02962541164FULL,
		0xCBCC9590A5E1FBBAULL,
		0x79462C3C9CF0D2BAULL,
		0x06F09C13EDCAED68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62EF691E1803A182ULL,
		0xDE21683798B7D002ULL,
		0xB7F6A79212D14075ULL,
		0x48EFEDCFD86EDC24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x638C99780D3D74BAULL,
		0xEDAB2D590D2A2BB8ULL,
		0xC14F84AA8A1F9244ULL,
		0x3E00AE44155C1143ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF12F846D3FE77F0CULL,
		0x6FEE5A721DA40A02ULL,
		0x4BAA4A2A729AE90CULL,
		0x620B8FD7A260108BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297A6E02246B7659ULL,
		0xA91F466539FF05E0ULL,
		0x979CF22599CD3260ULL,
		0x1F3B07E3C132E9AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7B5166B1B7C08B3ULL,
		0xC6CF140CE3A50422ULL,
		0xB40D5804D8CDB6ABULL,
		0x42D087F3E12D26DBULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FFAD743E9C7458ULL,
		0xC99478F021727821ULL,
		0xCCEA954D25636B7AULL,
		0x779BDEB7B9C1D310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D703D800D66CDEULL,
		0x21955A04F5E71DE3ULL,
		0xACF93C53A1007E68ULL,
		0x25096B9DC447B2DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7528A99C3DC6077AULL,
		0xA7FF1EEB2B8B5A3EULL,
		0x1FF158F98462ED12ULL,
		0x52927319F57A2035ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4FE7A546F7FFB67ULL,
		0x595759DA23F75093ULL,
		0x875530CA0EA9A5ACULL,
		0x6C2B2C10598F8EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C090594E1D0F4B2ULL,
		0x8E983A889C6400D3ULL,
		0x82D44B4A22081A28ULL,
		0x6A7ED9FC58775122ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38F574BF8DAF06B5ULL,
		0xCABF1F5187934FC0ULL,
		0x0480E57FECA18B83ULL,
		0x01AC521401183DB9ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB19A72D5D6A15FULL,
		0xBF3A4AEFE9AAE14FULL,
		0xD9CF1102889D8C91ULL,
		0x0F6E8A14FB6643B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BCF7F132FE053E9ULL,
		0xB22437432762629EULL,
		0x4B45F26C6E8B61CAULL,
		0x17B0D4B44091DD0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3E21B5FA5F64D63ULL,
		0x0D1613ACC2487EB0ULL,
		0x8E891E961A122AC7ULL,
		0x77BDB560BAD466ADULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C4FA11ABB54F426ULL,
		0x530528997E063E79ULL,
		0x9648A8211D53BF92ULL,
		0x207C1E85697E7C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2462560E2B7599B3ULL,
		0x164AA338B2C125E9ULL,
		0xED5DC3D58DE96CFCULL,
		0x56297833A108B40DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57ED4B0C8FDF5A60ULL,
		0x3CBA8560CB451890ULL,
		0xA8EAE44B8F6A5296ULL,
		0x4A52A651C875C83EULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4726FDA428640A02ULL,
		0x4527187C020EAB2EULL,
		0x856DC036BC96740CULL,
		0x05B8663E4E135256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666FE9148338D657ULL,
		0x06260DF40382CBF1ULL,
		0x71858A3A745CC6EBULL,
		0x404D69CA646AE7CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0B7148FA52B3398ULL,
		0x3F010A87FE8BDF3CULL,
		0x13E835FC4839AD21ULL,
		0x456AFC73E9A86A87ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8C0DDF060A7A011ULL,
		0xB943CFA5A6E52F2FULL,
		0xC3AE69D4B395ECAEULL,
		0x2DACB033478A11DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C90A94C776B6955ULL,
		0x09349B1ACE2B88BAULL,
		0x64F4ADD1C5E11F98ULL,
		0x6F1A87C87A607671ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C3034A3E93C36A9ULL,
		0xB00F348AD8B9A675ULL,
		0x5EB9BC02EDB4CD16ULL,
		0x3E92286ACD299B69ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33D9415C7ABA1712ULL,
		0xD6DA3226F8C4AEB5ULL,
		0x87A0EFEAA7EA9BE4ULL,
		0x2C0163C19103B075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E550EB559A35C7ULL,
		0xCEFE7E1984185ED2ULL,
		0xC15408AA2725D7E0ULL,
		0x60FED91E1F80AD7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CF3F071251FE138ULL,
		0x07DBB40D74AC4FE3ULL,
		0xC64CE74080C4C404ULL,
		0x4B028AA3718302F7ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCBE83A6F1E731ACULL,
		0x9B8494F189D095A5ULL,
		0xC9935CF35BAD7208ULL,
		0x370D087992CC385BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CAA8C37376EC99ULL,
		0x2F06FF84080E0FDFULL,
		0x198FE912EBAF31ADULL,
		0x75EE8E2F61F93611ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19F3DAE37E704500ULL,
		0x6C7D956D81C285C6ULL,
		0xB00373E06FFE405BULL,
		0x411E7A4A30D3024AULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4478580067337F4CULL,
		0xC78181632931FBE3ULL,
		0x7634C42E192179A7ULL,
		0x280B9B5E9C7D578CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D899A7E1BDE223ULL,
		0xA844A5BB28AFE784ULL,
		0x63DB758CAC352F5FULL,
		0x217C80E7E2C2E681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D9FBE5885759D29ULL,
		0x1F3CDBA80082145EULL,
		0x12594EA16CEC4A48ULL,
		0x068F1A76B9BA710BULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83CD76F562D4AA68ULL,
		0x46CB1ED4F0E62499ULL,
		0x830F31039B983956ULL,
		0x7A649932936B0085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14A07560F6AD08F3ULL,
		0xC4EF0E12D72246B9ULL,
		0x5782F4C7E49B8136ULL,
		0x5BDBB63F4E60BCFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F2D01946C27A175ULL,
		0x81DC10C219C3DDE0ULL,
		0x2B8C3C3BB6FCB81FULL,
		0x1E88E2F3450A4389ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC9CFFA20A31B0EEULL,
		0xC285D81DDD6BC4C8ULL,
		0x9BA6BD17316FD012ULL,
		0x3E80EDFC83F17172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4377C9833C7F54ULL,
		0x9310D9DF696320A7ULL,
		0x544CB97A568E06CBULL,
		0x66B0F6781DD3586AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x605987D886F53187ULL,
		0x2F74FE3E7408A421ULL,
		0x475A039CDAE1C947ULL,
		0x57CFF784661E1908ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x463A080D8DBD135DULL,
		0xBF41C8E0CD10FA55ULL,
		0x0D5F35DE46BC4E88ULL,
		0x5B3036433AFFA2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0567A5EBBF88BBULL,
		0xB907924AD50CDE1EULL,
		0xC5FA1824A790B0F7ULL,
		0x6998801BE737D09BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC834A067A1FD8A8FULL,
		0x063A3695F8041C36ULL,
		0x47651DB99F2B9D91ULL,
		0x7197B62753C7D222ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE649B4E378393B63ULL,
		0xFA94BCB997968A44ULL,
		0x6681DA6D5CEAF184ULL,
		0x0A5628172305E792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DD0ABC191675D2ULL,
		0xA8944AA877D855E0ULL,
		0x121DBE0091FA23F7ULL,
		0x6D559AAF19AD3AB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x146CAA275F22C57EULL,
		0x520072111FBE3464ULL,
		0x54641C6CCAF0CD8DULL,
		0x1D008D680958ACD9ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF50435E43C44221ULL,
		0x9C63C10537D52E30ULL,
		0xCA0951612F99430EULL,
		0x4554F86962E50469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467FB49DA05F560AULL,
		0xBAF006670C6690D6ULL,
		0xD7FEC658A244C20DULL,
		0x2CA18D1573D5B99DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88D08EC0A364EC17ULL,
		0xE173BA9E2B6E9D5AULL,
		0xF20A8B088D548100ULL,
		0x18B36B53EF0F4ACBULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FB2BD23AD7E6F40ULL,
		0x5387A594848EBA4BULL,
		0x8B39AC962A082D83ULL,
		0x179384EAF8E0B0A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E3A8777B46B2E5ULL,
		0x41C8F75D551594AEULL,
		0xA730B293D0CFF6B7ULL,
		0x6B9CFE3D69A90E5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CCF14AC3237BC48ULL,
		0x11BEAE372F79259CULL,
		0xE408FA02593836CCULL,
		0x2BF686AD8F37A245ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0AD7662DB8226D5ULL,
		0x15A051519B51256CULL,
		0x2B64EF3000F30864ULL,
		0x0FAACFBFB26495D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4592219C563F8CULL,
		0xDF5E61B544945843ULL,
		0xEB573355DDED383DULL,
		0x3074DA4D41141E67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD167E4413F2BE736ULL,
		0x3641EF9C56BCCD28ULL,
		0x400DBBDA2305D026ULL,
		0x5F35F5727150776CULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5006B215950EF804ULL,
		0x9FD41105FD2C4D2EULL,
		0xD2A2F9F2BF47E6EDULL,
		0x3C747AE51FFA5B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A56DC00239C69CULL,
		0x0EF9893F59B6D6E1ULL,
		0x121D61FEE899BBEEULL,
		0x166CF29762B67093ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E61445592D53168ULL,
		0x90DA87C6A375764DULL,
		0xC08597F3D6AE2AFFULL,
		0x2607884DBD43EAB4ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA73A5C0227FAD2A8ULL,
		0xF27C7C9C66231E4AULL,
		0x769A83FE051A848EULL,
		0x135A5F5BA0716A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CF71042F64CF79ULL,
		0x0C95B6B2A85EC83EULL,
		0xA25C69D6EAD0D519ULL,
		0x488C70D01D11C2A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x606AEAFDF896031CULL,
		0xE5E6C5E9BDC4560CULL,
		0xD43E1A271A49AF75ULL,
		0x4ACDEE8B835FA75EULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0B85C44A02E2F70ULL,
		0x0CA2A9039A88A39FULL,
		0x82787C398A6717AEULL,
		0x19940DF249767D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51FB583AC3A7E456ULL,
		0x0DA1E0209DA904BEULL,
		0xBAA0D4D5293134B0ULL,
		0x4D6FBB5EE7C08612ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EBD0409DC864B07ULL,
		0xFF00C8E2FCDF9EE1ULL,
		0xC7D7A7646135E2FDULL,
		0x4C24529361B5F6EFULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5B94D3B1EBCB1F1ULL,
		0x49746007D6A4F4D9ULL,
		0xC01793901D7B5BE3ULL,
		0x57039318DEF1F7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BEE6F5A3EF36666ULL,
		0x02B4B047666945AFULL,
		0x46F723D1F4D10A22ULL,
		0x35329A58E782EF15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69CADDE0DFC94B8BULL,
		0x46BFAFC0703BAF2AULL,
		0x79206FBE28AA51C1ULL,
		0x21D0F8BFF76F089EULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE129C068D6DC4BEAULL,
		0x3D1CF8E22C6039BCULL,
		0xDA224616F19FEB4CULL,
		0x2CC345DB8A870323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C4FDBCDFF9FF629ULL,
		0xE190C287595826B3ULL,
		0x01F0142D470A042FULL,
		0x0E0F32F5BB45F38EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64D9E49AD73C55C1ULL,
		0x5B8C365AD3081309ULL,
		0xD83231E9AA95E71CULL,
		0x1EB412E5CF410F95ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1262DCD7A65A068ULL,
		0x18A3C1C84D951614ULL,
		0x1310472F1A87950EULL,
		0x0B1C82EFAEDBC8A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86F749B5603C98E7ULL,
		0x32B51FB3606E7CC6ULL,
		0x562429B7820A9920ULL,
		0x1714F446CE92C1D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A2EE4181A29076EULL,
		0xE5EEA214ED26994EULL,
		0xBCEC1D77987CFBEDULL,
		0x74078EA8E04906CEULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DF6107EDCD949CDULL,
		0xAE39E6A087BBB219ULL,
		0x4E8B043F1EE8974EULL,
		0x19D622DFB35AF0B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x784A680A7D91AD25ULL,
		0x2DB22F375539F499ULL,
		0x279F36BFD1A2F8C7ULL,
		0x1AEF85034D51D394ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5ABA8745F479C95ULL,
		0x8087B7693281BD7FULL,
		0x26EBCD7F4D459E87ULL,
		0x7EE69DDC66091D21ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A4AACEBD9777F1EULL,
		0xD42081FC1AEDAF5FULL,
		0x3CCB1ED496D73642ULL,
		0x714EF9AC8A022056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4537D05D63D905EDULL,
		0x9694A6A3EDC5B9B2ULL,
		0x73E133BB349E3562ULL,
		0x79B6B44DA8DFBEF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC512DC8E759E791EULL,
		0x3D8BDB582D27F5ACULL,
		0xC8E9EB19623900E0ULL,
		0x7798455EE1226164ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C4C2DC1E926E17DULL,
		0xD84C1C724670C4B1ULL,
		0x301307CDF7F030A3ULL,
		0x392CA55853A9040DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7AB253D334F3D1ULL,
		0x6E8103B145820984ULL,
		0xD0B3EDB6C87D3525ULL,
		0x1A21C371504E828BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CD17B6E15F1EDACULL,
		0x69CB18C100EEBB2CULL,
		0x5F5F1A172F72FB7EULL,
		0x1F0AE1E7035A8181ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81F71968DE645288ULL,
		0xD50110886DD225C5ULL,
		0xB2E8D9D4F4742187ULL,
		0x0894E3AA5138E2E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12DD4E18F7DDD37ULL,
		0xE2D1960504A65FC9ULL,
		0x98549AD6B928E325ULL,
		0x46FA923F793ADC95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0C944874EE6753EULL,
		0xF22F7A83692BC5FBULL,
		0x1A943EFE3B4B3E61ULL,
		0x419A516AD7FE064BULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B346393D27226FAULL,
		0x8E3174CFFFB7B4DBULL,
		0xCE69E126E822EB40ULL,
		0x60CF50E8543010B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B85FFBD9943D69DULL,
		0xF25A2F742B4EFE36ULL,
		0x40DDBE90A8A56B74ULL,
		0x3CF676B0FE46D8DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFAE63D6392E505DULL,
		0x9BD7455BD468B6A4ULL,
		0x8D8C22963F7D7FCBULL,
		0x23D8DA3755E937DAULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FA6A58D24082DC7ULL,
		0x6FCF7C92DBA78D14ULL,
		0x7321FD29D48ABE11ULL,
		0x6B01A249AB0EDD67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB08787C7F1CA1BULL,
		0x2EC56B7ABF5434A7ULL,
		0x5B2343CEA4911A25ULL,
		0x0B361F20D8F13C97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61F61E055C1663ACULL,
		0x410A11181C53586CULL,
		0x17FEB95B2FF9A3ECULL,
		0x5FCB8328D21DA0D0ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
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