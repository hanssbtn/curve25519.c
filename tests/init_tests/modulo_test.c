#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x08F1C20A7547E791ULL,
		0x3EBDB51499D7CAB1ULL,
		0xB7C17D40E01B1AB3ULL,
		0xAAF21714B511D8EEULL,
		0xECC8EB3850DDFA98ULL,
		0x38BB9814B949D98BULL,
		0x96734C53E0FE33A2ULL,
		0xFC3F0B21EC9E334CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x2EC4AC66763B1FC5ULL,
		0xAA9648281ACE1576ULL,
		0x0CDED1B445D6C4C7ULL,
		0x1C4DBE1DD48D764DULL,
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
		0x2A11B5CCB9FA2623ULL,
		0x09A500E68F2C44D9ULL,
		0xED582E79833E9549ULL,
		0x8308E46868925D8EULL,
		0xD28622E9185703B0ULL,
		0xF439C790E5510F14ULL,
		0xCF9218B522E9DC60ULL,
		0x38D3B5D49C294B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FAE46656E4B386ULL,
		0x4A38A068993481F0ULL,
		0xBD07D95CB1F54BADULL,
		0x7275E1F796B38D55ULL,
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
		0x15E1BBF6BCF682E5ULL,
		0x804A2D5E1518E05AULL,
		0x546C6B0D0A47633EULL,
		0x9627DF45418ECD1CULL,
		0xBE36CA66357C560CULL,
		0xB51A0B3416C6C0CCULL,
		0x17DC70153304A879ULL,
		0xAB3494FCED746969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5203C722AD6B4C76ULL,
		0x6227D71976997EBEULL,
		0xDF250E329CF8654FULL,
		0x7FF5FCD080D672B5ULL,
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
		0x6AF2553DF053A395ULL,
		0x0D0E26DC39AD3B3FULL,
		0xCDE2054F5A5A6D40ULL,
		0x7643264FC96B78B7ULL,
		0xB75DDFCA60244EFDULL,
		0x3EEE3AD443F75EBEULL,
		0xE7C3AC34867CB8BCULL,
		0x0E72C83571F67ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E18D4835B75D82ULL,
		0x646AE25E50654B8EULL,
		0x34ED951B50DDD931ULL,
		0x1B4CDE3EB4024CEAULL,
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
		0x1E54F218CEEC86A8ULL,
		0x00FC6CCD117FD23FULL,
		0x2B093B780B6D5FF3ULL,
		0x1B9A48C52A6DC6A1ULL,
		0xF29CD5801436AA5AULL,
		0xF5DA4556C6843561ULL,
		0xB89701E29AB78F84ULL,
		0xC76558A6829412B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x219CA31BCF09D465ULL,
		0x7F62B7AE891FBEC9ULL,
		0x9173831B02ACADAFULL,
		0x34A5717C8C688E0CULL,
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
		0x61A33BEF53B814E2ULL,
		0xCA94EF46AA77F0B7ULL,
		0x72CABB2FBCB84406ULL,
		0xEE3A8DE20119AFE1ULL,
		0x1967FCA0E3A5E9C2ULL,
		0x615DEF841B03F01BULL,
		0x8AB04EB0933DC9CCULL,
		0x32C532E928C4D6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2712BBD11E58C8DEULL,
		0x3E867CE2AD0D94BDULL,
		0x08F6696597E4385DULL,
		0x77801C7E0E519770ULL,
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
		0x7F15A31022FEE012ULL,
		0x595E15AA639E951AULL,
		0x26C539E57B79DEA3ULL,
		0xF874FB28E54CD531ULL,
		0x17D977BEBC71CF46ULL,
		0xA4469E8F82D2B360ULL,
		0xA6452CB2262ECB36ULL,
		0x47C2191C39DE3AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095D69601BE3A62BULL,
		0xBBD99EF7CEE5355EULL,
		0xD509DC57266C08BFULL,
		0x1F44B5597C498BDBULL,
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
		0xBD2DD1C071122743ULL,
		0xB1C1D3EAC4777999ULL,
		0x7F755CC9FD0D8B7CULL,
		0x321A66262C50BA25ULL,
		0x48BB12EA5A52C554ULL,
		0x8FDAE11FC425E31EULL,
		0x814A23D4708B5096ULL,
		0xD526A3263F9A091CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F2A089D95B7668ULL,
		0x0C3F3EA1E2173018ULL,
		0xB076AE52B1BB81D6ULL,
		0x55D69DD39D2E1460ULL,
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
		0x9648177F7C3DA4B0ULL,
		0x8E5979021078EFB4ULL,
		0xBF45383C1D2C3F71ULL,
		0x0D22D0BAE633A63CULL,
		0x28F609E4F2934FFCULL,
		0xEE53FA654ADAEE4DULL,
		0x6E080DD5BCB91438ULL,
		0x6F3B718C00FFD2B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAACD8F7B7E1B868BULL,
		0xEED0A40B2CF84F28ULL,
		0x147745F620A53FE4ULL,
		0x0FF5AB830C2CEDC3ULL,
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
		0x87E22B50C956C6FAULL,
		0x19D68D317B21C645ULL,
		0x9464C538010212A1ULL,
		0xA25D2B843F5F069CULL,
		0x309CFA626DC57274ULL,
		0x60184874A6240038ULL,
		0x5A61B9398CDEEA3CULL,
		0x76440EE528851F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2F55ED14A5C6DEULL,
		0x5D714E822479CE9CULL,
		0xFEE643C2EA18D797ULL,
		0x307761884321A945ULL,
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
		0xCF600F12ECAA39B1ULL,
		0x49270E1C3E20F69CULL,
		0x162E60E9D15619D2ULL,
		0x68A3CC3AFFB30884ULL,
		0x11477CF931697BA5ULL,
		0x33C4D59DF95B4023ULL,
		0xFA74D048ED27DBEAULL,
		0x85C5D09C1C6B1CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FFC9C1042529727ULL,
		0xF85EC38F41AC7BD1ULL,
		0x43854BBD0540BE95ULL,
		0x4400C36737994A0BULL,
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
		0x27E8AE1E4193A15AULL,
		0xC81EC43769AE2E89ULL,
		0xE3C217E0D2850337ULL,
		0xB47821CD0EF6ED78ULL,
		0x8854F7A0DF601340ULL,
		0x55CB0E031FA4C98CULL,
		0x0B782FBE5D579117ULL,
		0x07DB929A5D772F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64856FFF69D67D13ULL,
		0x8442D8AE1C241965ULL,
		0x97992E22AD848CAEULL,
		0x5F0FE4B6EEA7E7C6ULL,
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
		0xFF9349F0A3CE229FULL,
		0x2BD65E17CE0A99EAULL,
		0x125A974E6F16393DULL,
		0xE7FC949218884C7DULL,
		0xA5DA739FD061E561ULL,
		0xD390F57A69CCE62FULL,
		0xE47B6CC532E65DA6ULL,
		0x7C1926D04DCE120BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0073A9925631D7ULL,
		0x935ACE438274C4FDULL,
		0xFCACBC93FD482000ULL,
		0x53B8577DA51EFA40ULL,
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
		0x33B6D133350F8EBFULL,
		0xF8B02DBC424940D1ULL,
		0x7B0652D0C3017640ULL,
		0x58B71ED85D57F33CULL,
		0xE3E5C4A48F2F9A20ULL,
		0x92BE238ED2E7C5B4ULL,
		0xBB020CB5D00DD269ULL,
		0xE75F51BCEEA7171EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D201A07620749EULL,
		0xC0E974EF90B099ABULL,
		0x3D5435CDA50EB1ECULL,
		0x30DD40E3CA2561CCULL,
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
		0xB3965A57270FC7EBULL,
		0x094953800D84D748ULL,
		0xBA5C949E61AC33CAULL,
		0xB33A1599BF619681ULL,
		0x56E612110E7D42E0ULL,
		0x653110A5A2412ADBULL,
		0x8916F2D21FCF2811ULL,
		0xCDB4B1273C5347EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BD08DF4DA7B9C5ULL,
		0x0E91CC16233133D7ULL,
		0x13C49FCF1A6C265FULL,
		0x3C0C616CB3BE4410ULL,
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
		0xF57776AF224AA1B3ULL,
		0x68D9F8B6A1EB781BULL,
		0xD9EA5D58764FF0B5ULL,
		0x6A8F129CEC114477ULL,
		0x3CC50D32856DD572ULL,
		0xB3BFED6AAA1343CFULL,
		0xF75D71D017B9F760ULL,
		0x45DA7BAF1A647987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB76C2EF098522EULL,
		0x1757368BE0C788DEULL,
		0x91C9423BFBEAA910ULL,
		0x48FD6E9AD6FB4EA6ULL,
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
		0x7A43769EA47084B1ULL,
		0x4F6A849B88C5D29EULL,
		0x624486B18FDE3115ULL,
		0xF4927956AC0D52B7ULL,
		0x453A129CF695763BULL,
		0xFACACCDDA57137FAULL,
		0x8B1CC3395EC751D9ULL,
		0x8A1B1155D26179D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E239EB3EA01491ULL,
		0x8984ED82179421C4ULL,
		0x08898135A1745770ULL,
		0x74970C13E6856844ULL,
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
		0x35B23FF1F98C0040ULL,
		0x40C99B664F406016ULL,
		0xA8BB58CFAE1AF5EFULL,
		0xBC3DABF89D25F4F6ULL,
		0x875917A390B9F57CULL,
		0xB49251D2189991B6ULL,
		0x98EB617D745FC35EULL,
		0x059061D0650008C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEBC239752670E1ULL,
		0x0E81C095F60C012EULL,
		0x5BABD16EF451F5FEULL,
		0x0FAC30E79B274271ULL,
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
		0x8726F5D2B32F2CB0ULL,
		0x3A07909A881C768EULL,
		0xB5C67B61FC8B9739ULL,
		0x1C7487F51E56B02EULL,
		0x71DF8E11FB8ECCEAULL,
		0xA4843F22AD3131B7ULL,
		0x73786AB28345BE8BULL,
		0xFBBDF1A7B91D2E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E560C7E0A619CEAULL,
		0xA5A8EFC03D69D7C9ULL,
		0xD9A651E178E5DFF3ULL,
		0x7AA666DA98AB87CFULL,
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
		0xC476797713DF24EEULL,
		0x0D58DB271F7C4A9BULL,
		0x85191EB4ACC3D1CCULL,
		0x27C77FF057E0F317ULL,
		0x59665DC8ED13547FULL,
		0x8EA6E93321412124ULL,
		0xA26887D0D4742C54ULL,
		0x3CCD2A4B596AE30DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A8654A44BDB11EULL,
		0x3A1F78BE0F273601ULL,
		0xA09D47B436026659ULL,
		0x2E3BC71F9DBEA71DULL,
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
		0xC190DEE93EAFEDA2ULL,
		0x91193118E43E36CCULL,
		0xCDD3054F9775351FULL,
		0x25D628AD01A1B15CULL,
		0xC21E39A6B9FF132AULL,
		0x6B43A7311FB7FF35ULL,
		0x0EA6B6C740AB1925ULL,
		0xD2C5851B868EA4D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920D6DA8DA8CCA78ULL,
		0x7D240263998E18C7ULL,
		0xFA9226E330DAF0ADULL,
		0x6F27EAC2FACE28B0ULL,
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
		0xBFB5286EF39F3888ULL,
		0xB0DA5D9DAADE6B5CULL,
		0x7D91F19468499BD5ULL,
		0xF18414122302C500ULL,
		0xC13DA3F90B33F430ULL,
		0x30499C4500A69ADEULL,
		0x1EF6C9A17C5C9D48ULL,
		0x531D0345C693894DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EDB7F669D557996ULL,
		0xDBC78FDBC399686DULL,
		0x1633DF8CDE08F48CULL,
		0x47D2906D9CE92673ULL,
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
		0x7ED4671BFD847546ULL,
		0xA1AC5FCB6B13CF4AULL,
		0x69C98DE82DD83515ULL,
		0x2B6267C54BA404E1ULL,
		0x81E9EDB469D763C4ULL,
		0x710DE1CDD54104DFULL,
		0xCC3F2149204D2FB2ULL,
		0x41EC64E2B9C97B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78DAFE3B37D45C7ULL,
		0x69BBE45912BA8877ULL,
		0xBB287EC2F94D4992ULL,
		0x7479616CDF8C4725ULL,
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
		0x2653EB358D5060F1ULL,
		0x509B2001CD9F3D8CULL,
		0x4B30E21B4FD73D42ULL,
		0x2B5B0A9B5DC64DEAULL,
		0xB15A11A867F9BCF6ULL,
		0xDA134A2F369F4343ULL,
		0x7011B7FF74A00BA6ULL,
		0xB247D556918E1AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B28A34FC627164ULL,
		0xAF782303E9433998ULL,
		0xEDD232069F98F806ULL,
		0x2204B574F8DE441AULL,
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
		0x7A32A1C09FE96BA4ULL,
		0x6A67FDF676352AFFULL,
		0xD8235A37DD856449ULL,
		0xDFD724D0F6718C6CULL,
		0xCFD4E0E3A41F9DE6ULL,
		0xDB17BEFED499B703ULL,
		0xE3E141DE8011AF49ULL,
		0x6907DA7EAEFF3F64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53CC038AFC9ADE28ULL,
		0xEFEE57CA05065590ULL,
		0xAB93213EE025693FULL,
		0x7701939EF054F566ULL,
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
		0x3FB8063E4D6B8F86ULL,
		0x8382626601ED81A7ULL,
		0x84070F1470B5D533ULL,
		0x7B66118EA0813B5FULL,
		0x628F4AC375F0AF73ULL,
		0x0722B3006985A815ULL,
		0xA30E8C0DA190FD95ULL,
		0xA72BF8776FA28D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0FD1F41CF259E4EULL,
		0x92A8F475ABC474D3ULL,
		0xB82FD91A6C3B7952ULL,
		0x4BECF34932A2338FULL,
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
		0xFB6AF6E440CFEA40ULL,
		0xCC1860CC53166B11ULL,
		0x053FEC84C21244EFULL,
		0xF97CEDC056F0550AULL,
		0x4ECA8BBD06F696A7ULL,
		0x21AFC007DCFBB403ULL,
		0x69CF5C63F7FB14ABULL,
		0x779879CC1D767BB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7BB4F3496A49C9ULL,
		0xCC2EE1F72073238FULL,
		0xBA07A35B91575656ULL,
		0x3A1F020CB686B21DULL,
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
		0x28B7ACA757BD684AULL,
		0xECA03DC06D80C05EULL,
		0x6836626E03404829ULL,
		0x46DA6B75A8A0D5F2ULL,
		0x5FC7715E31B1ADDDULL,
		0x65F18B2EF10CFCC2ULL,
		0x4829FF4EC385CEA0ULL,
		0xC0C1F0DCBC490FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605280A2B81D3B53ULL,
		0x0E7AE6B8356E4538ULL,
		0x1E72481F091CF3F9ULL,
		0x63A42C399B7933C3ULL,
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
		0xFC695D86AFFE88D8ULL,
		0xA6BA00834FED44B6ULL,
		0x55C2A3CFE620887CULL,
		0x331612BD05DFD433ULL,
		0x199498C843F840EFULL,
		0x7EA7782859A6E048ULL,
		0x40F0F065F8ADE28BULL,
		0xFDCF317D2B11E312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8780B40C6D831E3ULL,
		0x7395D6809EB28F6AULL,
		0xF98652F2CFF02931ULL,
		0x5FD76B516A8788E8ULL,
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
		0xF0DF2741E830ADE4ULL,
		0x0749B6E44551C7FAULL,
		0x0DEAC26D5FAA6904ULL,
		0x36CD11D592667ECFULL,
		0xBA301343AD17F710ULL,
		0x044D2AC73BF45E95ULL,
		0x9866D38BF5CE4D7DULL,
		0xBBA7541E006FE6BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9402034D99BF5E6CULL,
		0xAABE10772B97D234ULL,
		0xAD2E2933DC49E992ULL,
		0x11A38E49A302BF19ULL,
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
		0x44EA7188F1CED4FBULL,
		0x2AE2D5662D059C5FULL,
		0x38830F98F2A12C9CULL,
		0x7735F89F3A52180CULL,
		0x2CB9426A2CE0C0ABULL,
		0xFB4E5AC6C646058EULL,
		0x3D3D11DB692FCAD7ULL,
		0x91A2F992131B239FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE86A4D4B9B2B71A1ULL,
		0x78844EE79B6A6F79ULL,
		0x4F93B62A8FB948ABULL,
		0x1567044E105961AFULL,
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
		0xC053F9125458EBE1ULL,
		0x1FC7C717D44DFD5EULL,
		0xD6AE34E0759316FCULL,
		0x3BD784DD66DFC530ULL,
		0x1FA9AC73EE999B74ULL,
		0x0224BEC60ACA2154ULL,
		0x37F24D25A9541901ULL,
		0x462BA916DE8C19DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73839247BF2600A8ULL,
		0x713C187D6E4EEFDBULL,
		0x24A5A877980ECD22ULL,
		0x26529E426FAB9C2DULL,
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
		0x1E610F36D01328FEULL,
		0xD45AC57B09332B16ULL,
		0x53CB26CE1E8E545EULL,
		0xFAC17B1D5E647BCAULL,
		0xA56A76B90647B395ULL,
		0xF7A08D52703224B7ULL,
		0x813D199103C2149DULL,
		0x1D49F1C9EE414AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC2EAEADBEB7D1DAULL,
		0x962FBFB7B0A49E58ULL,
		0x82DCF254AD5D63D1ULL,
		0x53BB5F16BC159ABFULL,
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
		0x4F8B72348F984ED7ULL,
		0xC36AC2CBB04E6EE8ULL,
		0xBDEB7D2831963CB8ULL,
		0x250014BFB98EC0A2ULL,
		0x745CEDE995EE3457ULL,
		0x52205FC447C570AEULL,
		0xDAB27AA648EBF271ULL,
		0x5290848F6B78766CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9556C2E0D0F41589ULL,
		0xF438F9EE579D28CDULL,
		0x3469B1D7049C398AULL,
		0x6673C209AD7054CBULL,
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
		0x9B8B3D8CCAE3A9BBULL,
		0x655AAA5D588BEB74ULL,
		0xD1DD4D55661C6600ULL,
		0xEB9B495B9348F52CULL,
		0x2C499C18E24379BEULL,
		0x18BA2D225406686AULL,
		0x3E5767474B5798FFULL,
		0x6E3DF1D69351023AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E78693E60E7BE75ULL,
		0x10FD5D75D17F6B37ULL,
		0x12D6A1EA951D1BDEULL,
		0x48CD2F35714F49D2ULL,
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
		0x4560F79D4152EB21ULL,
		0x84A73EF9FE0E53E2ULL,
		0x796715C50CF830F3ULL,
		0xCF677DB6A081E5FAULL,
		0x0B27784B19643604ULL,
		0xC08239D2EC9561C5ULL,
		0xAD8E41BC38162A1BULL,
		0xB0E2D39BF23D4D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3CD2C30632F3BBULL,
		0x17FBD4491C3AD721ULL,
		0x3C84D7B560427112ULL,
		0x1112E6DC959B5FA8ULL,
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
		0xACDC416D7ADDE0E0ULL,
		0xDB55126EA699D254ULL,
		0x1761178132E2B3A7ULL,
		0xFB093ECF5FE06176ULL,
		0xE0033D508116E5B7ULL,
		0x6C2C5E9426FC67D1ULL,
		0x680127DF3BBE0BB4ULL,
		0xD9390B280E6B5468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED575B60A443FEF0ULL,
		0xE9EB1C6C70113B7BULL,
		0x878D02A41118706FULL,
		0x3980E6C183CEE8F5ULL,
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
		0xFA4F94853B519CDFULL,
		0x4E0A4E8F72656541ULL,
		0xB14D05085D070D3EULL,
		0x1F2F46064A060322ULL,
		0x96A1A5FCEB1F4091ULL,
		0x5B95D1CF73FF9901ULL,
		0xDE61F1867E951E46ULL,
		0xCBC6ABF3571A0778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564E381021F536D9ULL,
		0xE647735AAA561B7EULL,
		0xB3D6DEFF27298BAFULL,
		0x5EACCC2537E31F13ULL,
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
		0x3B84CC2E62B3938EULL,
		0xFCECDD3699FCD8DEULL,
		0xE495F50BDA9FA56CULL,
		0x3AE614E28931E461ULL,
		0x161FCBD098A68FB0ULL,
		0x03C24FCAAE78F10EULL,
		0xDBA718E5DBB0DBC7ULL,
		0xD2A7A3CDD8A834FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x843D0D250B6CEC48ULL,
		0x8BC4B54C7FF0A0F5ULL,
		0x7F63A72A76E044F7ULL,
		0x7FC86570B229C1EAULL,
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
		0x880024F0DD7B76AAULL,
		0x27C309361188C089ULL,
		0x48BAD4EEB27CA117ULL,
		0x018837EB80DEC12CULL,
		0xF5A654F30D8490B8ULL,
		0x2020FA8926D7C17FULL,
		0xD218BA07994D9114ULL,
		0x5B6D270DF7F41CA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB0C104DF28F3FBULL,
		0xECA83991D58F7987ULL,
		0x7866720F74002A13ULL,
		0x13BC03FE4F1B0157ULL,
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
		0x5560F4FD2ABBF48DULL,
		0x861E35FE37905CDEULL,
		0xFA20DF40FE9F94CEULL,
		0xD3075E71364BC1C4ULL,
		0x0CCF1DECE6FCCF50ULL,
		0x48CE5BC4092F091BULL,
		0x792FEB940E95FA42ULL,
		0x7081C2D066CBA167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C1F66277442BD06ULL,
		0x54BFD517948BB6E2ULL,
		0xF73DD73B28E2BAA5ULL,
		0x064A49607885B720ULL,
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
		0x2EC740D4D7F35862ULL,
		0x12F05547C93601C1ULL,
		0xF4A8F56B4CD68F34ULL,
		0x8927E6906438D380ULL,
		0x8F66C3FDD1F5662BULL,
		0xCEB039085A9B63DCULL,
		0xFA3C0F5D23412C0EULL,
		0xDC2646C87A5DFF9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78085882026087AAULL,
		0xC118CC853C46D47EULL,
		0x19933D3E88831966ULL,
		0x36D668528E2CC4F4ULL,
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
		0xC79ADEAFCCE2B9FCULL,
		0x8FAB1DEF3EAB9849ULL,
		0x73E3F78304455556ULL,
		0x27807B277D74FE5FULL,
		0x5679827200496AE3ULL,
		0x0C2BA2031AB87BA1ULL,
		0xC47B2A6400E42576ULL,
		0xE0AFDAC24F0C59D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA43B9BD7C89CA7ULL,
		0x5E252A65360DF23CULL,
		0x9E2C425B2622E4DCULL,
		0x019AF3FF394A5440ULL,
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
		0xD681FA0F4B541C43ULL,
		0x8A9453D99548F4ECULL,
		0x131938F5E6B003CEULL,
		0xB74E7156DF468F36ULL,
		0x528BA9DD4CC7CF75ULL,
		0x8FF6437CC3BA1898ULL,
		0x8C349A62E80714A4ULL,
		0xDF1346CCF82F09E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173D30E8B0FCEC9AULL,
		0xE922585EA2E89B89ULL,
		0xE2E823A457BD143BULL,
		0x542AF3C3B64207E0ULL,
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
		0x14AE061BD4561084ULL,
		0x69175A1048208B87ULL,
		0xEA5DE6D3AE9D88D2ULL,
		0xCD8C764B1A569B7DULL,
		0xF60FC4B6A7A6C96DULL,
		0x1F145A174E588CA4ULL,
		0x31FCB6C60961AD5BULL,
		0xE5CB94F8F72AD2F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B053938B717FBD1ULL,
		0x061CB985E9456C03ULL,
		0x55E10839131D4459ULL,
		0x69C4933FCAB1EB97ULL,
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
		0xA3C4C15F28270AFEULL,
		0x22C92B3B29375E40ULL,
		0x6291BE5838A39F4DULL,
		0xD6400FEC06D8CE8AULL,
		0x8B2BC2A7E6C54497ULL,
		0x7F13D3088129942DULL,
		0x93942C613FD34E3CULL,
		0xFE0E709411E15208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C43A64B696F3F1FULL,
		0xFFBA7E7E55635D03ULL,
		0x4A9054C7B2013C47ULL,
		0x0C64C5E6AE4AFBD0ULL,
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
		0x52836AD61EA96DBFULL,
		0x5C7F29735812E09CULL,
		0x212715CBBC59167BULL,
		0x09274854C0FDDD02ULL,
		0x178C7032D7B863F9ULL,
		0xFDAD06351E2BEE5AULL,
		0x4E9CC1A8C73E0E6FULL,
		0x7E044EBAEF552CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15C126224084774ULL,
		0x042E1555D29841FBULL,
		0xCC6BD4D94F8F3B1BULL,
		0x3DCAF81447A28413ULL,
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
		0x64A0A04F33A7E048ULL,
		0x76DFB552F3DD976FULL,
		0x30C9ED11029F668EULL,
		0x3D4BD22391A01649ULL,
		0x0C358F71FDA3EDDFULL,
		0xDA622AF6D02A4004ULL,
		0x167BAC02379A16BAULL,
		0x0E0E4516C8F00998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3493EB3AD9FD2FAEULL,
		0xE17215F5DA231809ULL,
		0x87257565437EC64AULL,
		0x536A1385654182DCULL,
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
		0xEE646F642166BC4EULL,
		0x52CA9E8122D08C3DULL,
		0x8261FCE2DE91749AULL,
		0x06627E94C520670AULL,
		0xC6EB6D956225FE80ULL,
		0xB959BE7483CB67F6ULL,
		0x5A8F50CC6E731306ULL,
		0xE8EEB59CA602837FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7556B390B30A886DULL,
		0xD61CE3CCB301FADFULL,
		0xF3A7FB3B43A64799ULL,
		0x19D173D5697FEBF1ULL,
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
		0x4FE1D9D5A102BB3EULL,
		0xC1129C32C63160BFULL,
		0x645FB6C2FFA7B31DULL,
		0xDBAE3650A002D859ULL,
		0xE33CA22656F15F3DULL,
		0xE02FF0C7FBB64534ULL,
		0x47068AB9A00A30AAULL,
		0x7732ACCD8CE65E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE1EB8688D6E10BULL,
		0x083059E2233FA699ULL,
		0xEF584E50C12AEC7BULL,
		0x0D33DCD38A34D41BULL,
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
		0x6B8D9C9A1E6B47B7ULL,
		0x107DD14A8D59ABEDULL,
		0xB571B08C26B3307EULL,
		0x52669DCA080F3411ULL,
		0xCA191A7ADAC9D638ULL,
		0x08CAC12896E50105ULL,
		0xE3072A09D4BD7ECFULL,
		0xF7DA249B6AFF1ADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B478AD698611985ULL,
		0x5E967D50F357D2C9ULL,
		0x6881EE01BAD40339ULL,
		0x1CC80CDBE9ED314DULL,
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
		0xD75BFA594B5D9102ULL,
		0xE2F95280153A2AD9ULL,
		0xE66650AE9CFEB0C5ULL,
		0x5E1B99053250AB26ULL,
		0x7DDF65FA3D12132BULL,
		0x16A132B1EF3DAA04ULL,
		0x5103184B25F7A24DULL,
		0xE018505296E60BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86851D7E5C0C6E5DULL,
		0x3EE6D8E998616784ULL,
		0xECDBEBD63FC0C837ULL,
		0x21B7854798767202ULL,
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
		0xFE7EB5C0AE7DF6EEULL,
		0xFD84E24A7D353ECEULL,
		0xF5F709A89481E5A7ULL,
		0x105DC6A03287A2DFULL,
		0x4AEB4D51EADFE8BEULL,
		0x24D84B1A6CB6BFEFULL,
		0x7F5B8B9431943B01ULL,
		0xE312EFB28B30344AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6C2FE98BBA881BULL,
		0x75A00836A055BC54ULL,
		0xDD8DC1A7F082A7D3ULL,
		0x452D5B20DBAF65EEULL,
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
		0xB0D5B9FEB317C059ULL,
		0x2F10C2E9E86F7116ULL,
		0x0499B868F283925DULL,
		0xDB076636D9895FCFULL,
		0x4CA643D7C5799C4AULL,
		0x180EAFE2F7AD039FULL,
		0xE4084975F0F8382FULL,
		0x0B455C0F0A92A180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1183CC060324F3B4ULL,
		0xC13EDE9AAC1DFABCULL,
		0xDDD49FEAB75BE95AULL,
		0x075310726B4D58F0ULL,
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
		0x6D89AA4DAAD2A805ULL,
		0x796F5F6B3509EDD4ULL,
		0xF2DEAEF49047B8A5ULL,
		0x720165BD348EB085ULL,
		0x57801DD3F11A7C4FULL,
		0x1EF6FCDC6949D160ULL,
		0xAD425A0F0BB54EB8ULL,
		0x76AEFBDAFE95577EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8E17C374C11E6BULL,
		0x1218E822D5FF0221ULL,
		0xAAB80D304D3167FAULL,
		0x0FFAC83EFEB9AD53ULL,
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
		0x00679C1288DD626FULL,
		0x9BE47A96AF84CEF1ULL,
		0x731FFE910FCF0F86ULL,
		0x14FB59707065735BULL,
		0x8D649A4D945E4D76ULL,
		0xCA990E8D77A399C6ULL,
		0xDBB8B43212323C9EULL,
		0x95D5367AFD59F8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5683968EDCE537ULL,
		0xAE9CA39671CDA269ULL,
		0x108ABDFFC3440F18ULL,
		0x52A16FB20BC063FEULL,
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
		0x6B9CB38EBD40028CULL,
		0x054DDCE34565F032ULL,
		0xD264076551775A24ULL,
		0x3265E4F78EF0C202ULL,
		0x39B395EFA05A6517ULL,
		0xCD535388BE2E5EB7ULL,
		0x20D6C930F0CD79BCULL,
		0xA93066B77C59760CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC44F5208AAB07ACULL,
		0x7FAC432F8047FF64ULL,
		0xB245E4A90FF76C2AULL,
		0x4F952434043847CFULL,
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
		0x8B3242DDAD93AB9AULL,
		0xFDEFC1207C5A1632ULL,
		0xCA38216477692834ULL,
		0x3D48B93D8ABE2BA7ULL,
		0x2D27F75A8E881A6BULL,
		0x140302E9D8CB943FULL,
		0xADFE63AF16B14FACULL,
		0xBD7CB5B6378D0F8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F20FA4ED5C79BA4ULL,
		0xF6622FD6AA921793ULL,
		0x9DFAED61D5BAFBBFULL,
		0x5DCBB249C9AE7AFBULL,
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
		0x5D82572065D59CAFULL,
		0x2A2F3A2D2E06FFB8ULL,
		0x0E1625F4A754C99CULL,
		0xE0D2401CF574E648ULL,
		0xBFF97BAC3458B0DAULL,
		0x08194B2F891926A3ULL,
		0xC408A15B9159DA46ULL,
		0xF209978C49E9545DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8AB2B02AFFE276ULL,
		0x5DF0633B87C2BC06ULL,
		0x275E198C3AAB3001ULL,
		0x4E3EBEEFEE176C33ULL,
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
		0x05486C03A3B0311AULL,
		0xECE5832FC20A4227ULL,
		0x87CAE0659AF178CFULL,
		0x2C5CA4D1D69672C0ULL,
		0x4C8514712304C2EDULL,
		0xE443A171466BAD56ULL,
		0x2DCAA1ADEC99D87CULL,
		0xB0520362BA295213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x610974CED6652424ULL,
		0xCEEF7A003605FCF6ULL,
		0x53DEE036B9C79B59ULL,
		0x5889257978B8A199ULL,
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
		0xC6E9CAB6B926E5CCULL,
		0x3E5B21E9A70CC388ULL,
		0xA419C97EAD4D9E5DULL,
		0x04D22B6E60E30EADULL,
		0x60FE70F04A7B7E0EULL,
		0x71E33E808F7E9429ULL,
		0xD77FCD721F48100DULL,
		0x2BB7399E1BC401A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CAE8E61C77B9CD7ULL,
		0x261668FEF3D6C1ADULL,
		0xA112486F5200005CULL,
		0x0204B8E67FFB4D97ULL,
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
		0x038249EA96023711ULL,
		0x088E1C3A3B65D97BULL,
		0x9007849DB7183BECULL,
		0x88CAB483B37E02BDULL,
		0xAEFE15D0F0E19F35ULL,
		0xBA32F2E2688E5815ULL,
		0x608ABA5567E30D27ULL,
		0x3D9CA9E0DE3FC0A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3986EE577FDA58ULL,
		0xAC1E29D5C086ECB2ULL,
		0xE49F2D4B22CC2FD1ULL,
		0x2E0BEBE4B0F49B23ULL,
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
		0x0D4A720AA155AD90ULL,
		0x0A622C14560D358CULL,
		0x99CD8B778FA91ABCULL,
		0x68D21EC7D8FE0D6AULL,
		0x92CCEC83C0A45A65ULL,
		0xF19B25E11D0E1B93ULL,
		0x67758039743A1D55ULL,
		0xA9D0914152A129A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B58D9939BB1C57ULL,
		0xE769CB7EA6254D73ULL,
		0xF53E93FED049757DULL,
		0x1DC7AE7A1CEA3C8FULL,
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
		0xBE5C4251BFA2B268ULL,
		0xFBD04C1EBB342B1DULL,
		0x1B15F30EBF3F7E3DULL,
		0xBE28614E1B684A7EULL,
		0xB0E8E178D85F6080ULL,
		0x3ECAF3D5B3D3C492ULL,
		0xDCB20711BF97401FULL,
		0xB2BF1A203AD6DEEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00EDBA41DDCB096AULL,
		0x4DF07DD76CA358E4ULL,
		0xDD82FFB12FB302E1ULL,
		0x46864216D74D6218ULL,
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
		0x2405C1E2E5E4D2E9ULL,
		0x6FD92F9D488576AAULL,
		0xC8D39BB9A7191DF5ULL,
		0x833A61DBE98E4814ULL,
		0xBFE8DDD29BA60A09ULL,
		0x201DDE35B8F01B42ULL,
		0x4A32812F37D093A6ULL,
		0x8EA37CF8FAC25834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA096AF26008A5370ULL,
		0x34482B96BC298292ULL,
		0xCC52C8BBF00F089EULL,
		0x2F7EEED122675FD7ULL,
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
		0x63DB527C1C4D7C44ULL,
		0x010B542B062194C9ULL,
		0x6A2738C54C81AFC3ULL,
		0xD1F679C3D68DA6DBULL,
		0x6F901088AF67FA60ULL,
		0x0DEF2BB7A9E08C84ULL,
		0xF47C8A61B2332440ULL,
		0x5E859E4A343D0083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF33DC6C625BCA8ABULL,
		0x128BD16E3D767071ULL,
		0xB4A3C345C0191145ULL,
		0x59CBF8C7979BBA71ULL,
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
		0xA8C6F126A3170242ULL,
		0x37E3E8B5F3E7BA90ULL,
		0x8D2309A61EAF8905ULL,
		0xF055600ACF13C34EULL,
		0x4D19DD387E724497ULL,
		0xDD3F2A26805EEA40ULL,
		0xC86DCB21E35315D4ULL,
		0xDB9239D3DFB1ACB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A9DC789680D35A5ULL,
		0x0F442A6D01FE801CULL,
		0x4D6F30ADDD04C69EULL,
		0x0809F57E03736670ULL,
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
		0x44C7DD51DC4A371EULL,
		0x0C851F0E58DCBC97ULL,
		0xFDA61A8FEB6E2CC6ULL,
		0x117BA6EB43821FB8ULL,
		0x5665FA2DA3C702E0ULL,
		0x7B25758D4DECB00CULL,
		0x85629E476FF20F6EULL,
		0x8767C375B122032EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17EB00182BD4A756ULL,
		0x54149207E9FEDE6CULL,
		0xCA49992A895C772CULL,
		0x2AE2AA638E8E98A0ULL,
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
		0x39736FAFA4A88966ULL,
		0x83ECA4BD0A1B1F0AULL,
		0xF0E5E4044F91A780ULL,
		0x5A635146BC4AF991ULL,
		0x5FFB4F25E73231E1ULL,
		0x79BBB2A92E8F473DULL,
		0x4A70F6F5627F0EE5ULL,
		0x5247D9C93B4D8040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C12F4FF61BF2A7ULL,
		0x95C929D9F35FB226ULL,
		0xFDAA8C70EE6DDD90ULL,
		0x110DA52589CC031CULL,
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
		0xCC7AD5CA51DB79F0ULL,
		0xB788E8A0A1870136ULL,
		0x3319C69A530DB15DULL,
		0x2EE126C4D302CE86ULL,
		0x4F93436924CFCB8EULL,
		0x1CDB775064D95232ULL,
		0x6125AEC2C1CD232DULL,
		0x694940FBE8861477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C56D765C8B3B351ULL,
		0x001C9E8F99C934AEULL,
		0x9EB1B7831780EA10ULL,
		0x4FC0CC2956E9D83EULL,
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
		0xE6C3FE129A620147ULL,
		0x753FD15F01FFCA83ULL,
		0x22D1065C948C2966ULL,
		0x48F06DE50B0C1267ULL,
		0x6F6C9216DF2140F1ULL,
		0xFB6AEA38F404BB88ULL,
		0x127F5FDDC7694B3CULL,
		0xC632C6FE74D984A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E1AD77B951A96EULL,
		0xC71E95D33AB3A0C4ULL,
		0xE1B941482E2D5473ULL,
		0x3479F7AA6355C2C1ULL,
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
		0x6091645AD30A8D59ULL,
		0x4E61E7D8C4B43CA0ULL,
		0xEBB9E46AC1CD1135ULL,
		0x157C3DFACD21F3CCULL,
		0xD6D6F969E77F5D04ULL,
		0x96F02F03235B1F2DULL,
		0x08A764599ACE33CFULL,
		0x6A7B0A463B6423F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x447A6A132FF25E3EULL,
		0xB608E250043ADD6EULL,
		0x3492C9B7BC68C205ULL,
		0x63BFC4679DFF4A06ULL,
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
		0x4BC1F86894417DE2ULL,
		0x69BB929AD26DF33AULL,
		0x8AC464E13734256DULL,
		0x65B56DFBF85F88C7ULL,
		0xF4DB234CA47D4A91ULL,
		0xD3C549D84B4ECB14ULL,
		0x5954DD20FCE598A7ULL,
		0x394D884B1EBEFB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44935C8FEDA90ABULL,
		0xD90488B600201856ULL,
		0xCD5D37C6C148CE56ULL,
		0x6737A92288B8CEB0ULL,
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
		0x6CCC2376D999A741ULL,
		0x825A922A395C9C1CULL,
		0xB6EB4A6047F488BDULL,
		0xB2964E88709D50AFULL,
		0xCD5732459E19B85DULL,
		0x154502E8B41D030EULL,
		0x8CB23517FFD76D05ULL,
		0x150833AB467B4893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7BD99CC516B0594ULL,
		0xAA9900B4F5AB104EULL,
		0x995F2BF041EEB77EULL,
		0x51CDF9F4E6EA1696ULL,
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
		0x55AC6782E5FC24CBULL,
		0xE0E46E53CAB7E633ULL,
		0x19027E666372D657ULL,
		0x31E29418A8BC4FEEULL,
		0x1E838445EB604761ULL,
		0xDCBD4C30DD6D6578ULL,
		0x13505B828D59BE7FULL,
		0x5EDE1FCA504001F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3209E3D646BF45ULL,
		0xA4FDBD94A8F4F607ULL,
		0xF6F013C75EC51D52ULL,
		0x46DB4C20923C9AE6ULL,
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
		0xE9CEBC5C8447F811ULL,
		0x091BFFD1F4E6459EULL,
		0xCFFCFE9A9126D02FULL,
		0x60C8C528CC845937ULL,
		0x615318818A825494ULL,
		0xFF753FF49AA1D716ULL,
		0x9757B09A14062508ULL,
		0xAD33D6564B7ADCCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C245F9713A089E5ULL,
		0xF4837E20E8EC32F1ULL,
		0x470135798A104F84ULL,
		0x167A95F800C11F4AULL,
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
		0xA8B4C0A3C54243ACULL,
		0xC40904386E12F2C5ULL,
		0x06EE61A5DA2572F5ULL,
		0x966E612FAB4CF5F9ULL,
		0xCBDCB6DDDCB04F02ULL,
		0x408EA25E3760A23EULL,
		0x5DE1FA3EC416CAF3ULL,
		0x9C167F06E2922D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB77E592876E0175ULL,
		0x59351E34A66B0817ULL,
		0xF67986F6F5879311ULL,
		0x41C53C354CFFA912ULL,
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
		0x80456A0032E6E5FAULL,
		0xAE252F2C5D8FFC10ULL,
		0x561A0F4921FA5F66ULL,
		0xF675A9AA45EA8F34ULL,
		0x61C5C8D448FD351FULL,
		0x8FE56B3B1F17221CULL,
		0xFD6D369F2A278484ULL,
		0xAF8F99E33A38605BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A13983087CCC96ULL,
		0x0A3319F2FAFF0C47ULL,
		0xF4502AE963D80B14ULL,
		0x05C68164EA48DCDBULL,
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
		0xBB4A843DFE19E58AULL,
		0x255711482DA78C05ULL,
		0xE00648C7B04762DBULL,
		0x99DF0FE8D6355A62ULL,
		0x19B875B55DE6EEB9ULL,
		0xA679AF1D9D3A1F5BULL,
		0xB55F7D463F796FBFULL,
		0xBD6766DA2ED630ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CABFD29EE61593BULL,
		0xDB670FAD8448338BULL,
		0xCC32E1351C4DF94DULL,
		0x3738544BCA009D85ULL,
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
		0x5256160C64046679ULL,
		0x46B8C70DBBA7928CULL,
		0x14F363D6055C9E70ULL,
		0x57311ED12426C438ULL,
		0xC40BA69BE3AF8008ULL,
		0x32E1AD7BCB66065CULL,
		0x5D027896B1DA8835ULL,
		0x19BA08A4BEA1D41CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C10D13030116841ULL,
		0xD438876DECCC8451ULL,
		0xE3514A346BCCD655ULL,
		0x28CE6745702C406DULL,
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
		0xD0809423B7039305ULL,
		0x6D518ADA52163C1AULL,
		0x07B0C342C9B0BD1BULL,
		0x059FE62B79E40D18ULL,
		0x17821357BFB6A958ULL,
		0xECAFC7CFC4364140ULL,
		0xE99F957C7DEC6825ULL,
		0x322680A2149C70EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCF732A2C20B71FULL,
		0x8F6933B17223EB9EULL,
		0xB560F3BD7AC832BCULL,
		0x7756FE3A891CD08EULL,
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
		0x3A2C06E0590AE89CULL,
		0x9529BEA5D1D48500ULL,
		0xB5816288E74FA987ULL,
		0xF87C813A5D3C23C3ULL,
		0xB6957DBA3D839870ULL,
		0x97E46C8F4649D6AAULL,
		0x7E65BCA4CC960DACULL,
		0x32B0EFBCCBE2B088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545CB0857A938A6CULL,
		0x2111DBEA40CA6257ULL,
		0x789B62FF4595B126ULL,
		0x7EC01740A0E25806ULL,
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
		0x0ACB288BF2EEF8FAULL,
		0xEC2D4BBFF038BB1CULL,
		0xA17370637DA1CC42ULL,
		0xA749629488F8897AULL,
		0xA0C72240FD5F4415ULL,
		0xB30D6FB5BEBF8D38ULL,
		0x9BF75C5BB8925388ULL,
		0x9D6FB2E02DAA5F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE85A3E318F1317A8ULL,
		0x802BE0BA40A7B183ULL,
		0xC82B2600E35A328DULL,
		0x05DDEFDB5042A9A7ULL,
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
		0x5781433DE7A39019ULL,
		0xDF3F23FA87D6AC8EULL,
		0xBFA9E500356F14ADULL,
		0x37C02C656156B783ULL,
		0xC540C80FF4B166AAULL,
		0x6792B951490D6556ULL,
		0xE1E268A01E6B060BULL,
		0x8C33ADE9BA733DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1EF59C39F8D073ULL,
		0x3F06A60B5FD3B76FULL,
		0x47456CC4B951FA5FULL,
		0x076BFD170E71EA29ULL,
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
		0x94035559F11B42D3ULL,
		0x101D47636D924500ULL,
		0xE0ACD849BC01D395ULL,
		0x0BB5F9BB4C18DF28ULL,
		0xF77E1BC14C7A01C9ULL,
		0xBD6088853FFAA741ULL,
		0x8C77C7E53695A12AULL,
		0x953ACFE2B0A2BA81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BB740B4B3789EDULL,
		0x2C718B2AECC718CBULL,
		0xBA74844FD637BFEDULL,
		0x3270D56184408E63ULL,
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
		0xAFCB3865D67E192FULL,
		0xC1A2B94C3F867EA5ULL,
		0x35724E4642F08283ULL,
		0xC2CBCA7659756253ULL,
		0xE7B27980C74B81FEULL,
		0x7A5A0D9D3672295FULL,
		0x1D6F0F6B1F6E5689ULL,
		0xB71813E3A529B2E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144941836BB368F8ULL,
		0xEB00BEA25478A2E2ULL,
		0x93EE982CED515AEBULL,
		0x705EBE40DDA5EFBDULL,
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
		0x510B5DEADF8C74E0ULL,
		0xF7112B2B9197F98FULL,
		0x683239B47FCD6D3AULL,
		0x0B38CEF5A42FE64EULL,
		0x4D9B9E313F6E47FCULL,
		0xAFA8C58314476630ULL,
		0x7C9A677AEDE64184ULL,
		0x35ABD53F95777E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD624D93A49EB2578ULL,
		0x0A1E7CA0943124BAULL,
		0xE71D95F3CFFB26EDULL,
		0x02BA7665D3ECAD14ULL,
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
		0xF04157E84ACC3BB1ULL,
		0x83845DD9F94904DAULL,
		0x8594888F238AC21AULL,
		0x9451BA59EBF0F6C6ULL,
		0xED7E401C2DCA3E36ULL,
		0x5149FE0D02C57744ULL,
		0xCD4480AE42465E3FULL,
		0xC4BB77E185F128D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FEDC1716D17C16ULL,
		0x948013C86298B916ULL,
		0xFDBFA26CF9FCBF80ULL,
		0x482585D3CDBD06A8ULL,
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
		0x6DB0537157FE1ADBULL,
		0x82B0C6624EF9BBA5ULL,
		0xB58D60D8C304C082ULL,
		0xDD305CC7DFDF6D00ULL,
		0x0E46DAB54D01EB1BULL,
		0x6DD742984A765F9BULL,
		0xCE02EB2CE8397D1EULL,
		0x43E5048677038B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C34CA5AC647026CULL,
		0xD0A4A8FD5C8BECA9ULL,
		0x49FC49833B8D5306ULL,
		0x712F08BD8A661BE3ULL,
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
		0x50AAC95ED63540EEULL,
		0xE6E008D179CD89E4ULL,
		0xFB2DD9E5E0FFD1B1ULL,
		0x23022C63A44931A5ULL,
		0x4BCBC7BAB8C74A2AULL,
		0xC8F699F97FC632AFULL,
		0x48C1AEF7B4F741C5ULL,
		0xA63A4864849C81B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90EA6F1643CA46CDULL,
		0xBB7AE3DA71390FE9ULL,
		0xC7EDD2AABDB3950DULL,
		0x4FA8EB4F538471F6ULL,
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
		0x069F48F1CE2900C2ULL,
		0xE3E17D79D2107101ULL,
		0x1B66D0C189DF44EBULL,
		0x087F719486510666ULL,
		0x24924E2B21BAD476ULL,
		0x32E5ED0F4EBD7D9EULL,
		0x121E5948A7870B0EULL,
		0x4199AC215B0250DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7456E358CFE48BAFULL,
		0x7202ADBF8231167AULL,
		0xCBE8118A67EAE907ULL,
		0x454EFE8808A9075CULL,
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
		0xA560ECDF05BE498FULL,
		0xFCFF37FF17B65BBBULL,
		0xBBBCDA6AC5842113ULL,
		0x103D9A538BC11F87ULL,
		0xDCFE1ED98995CF9FULL,
		0x713679DFDB975F8DULL,
		0x3261D6CB381FD14AULL,
		0x3823534B84915FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7319812971FB1C59ULL,
		0xCB154F39B02E8ACAULL,
		0x3642BC951A3D3220ULL,
		0x657BF78939555A5DULL,
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
		0x97135A9EB5D86BDEULL,
		0x6948DF29CA2C8D5DULL,
		0x13CFAB40E3F2CA7DULL,
		0xAFDCF6B7C3299D6CULL,
		0xD3730C403627BDF9ULL,
		0xB58EF2EB9FC5D797ULL,
		0x32D22C33056EA232ULL,
		0xD40BCD32C023F92DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA272C26BFBEA394ULL,
		0x5C80EE23818A8DE6ULL,
		0x9F023AD3B25EDE04ULL,
		0x299D6C4048809A21ULL,
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
		0x42882B79D2750092ULL,
		0x102F4D60D8D34666ULL,
		0x5B339DFA76C166C8ULL,
		0x54CE5F1901B70710ULL,
		0x37F469D5FA6570AAULL,
		0x387A2597C67FEA3BULL,
		0xC9C57310B76FF72DULL,
		0x0337C5EB608D23D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90CFE13CFD83B9E1ULL,
		0x7250E1E84FD00B30ULL,
		0x4E82B275B160177EULL,
		0x4F15C00956AA5834ULL,
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
		0x925FE9ABF054684FULL,
		0x54ECC5CD6394D491ULL,
		0xCE76FC233CFA4B96ULL,
		0xFD8A692CABF704D4ULL,
		0x41DCC881BD25F46DULL,
		0x45FE5A0A6E894A3BULL,
		0x73141B4799D491E5ULL,
		0xFFE4FE00541401A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5925ACEE03F6B634ULL,
		0xB8AE2359CBF5D95DULL,
		0xE37308C41287F39EULL,
		0x79881D3926EF4389ULL,
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
		0x144EF8AF396B8DB5ULL,
		0xC2A080433A11D53EULL,
		0xAFE987D0312B60DFULL,
		0x2A770940CB604480ULL,
		0xFABE7FBDA40D3EA3ULL,
		0xC903931ECD780915ULL,
		0x14333239C3576108ULL,
		0x7D15097AB5958BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C95EED59362DCA6ULL,
		0x992856D5B9E32E81ULL,
		0xAF82FC633023C82DULL,
		0x3B967177BF9308CDULL,
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
		0x8444EEF3DFE755C5ULL,
		0x6E233CBEB536D0F9ULL,
		0x28721CC32A38848BULL,
		0x745857D1E1F82A3DULL,
		0xBF2474CBAF0EA935ULL,
		0x9D8A2C6992E8B448ULL,
		0xAD7011FDD401FA50ULL,
		0x2424C2C8A6B93FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3AE452FDC147474ULL,
		0xD0A5D46A83C193C5ULL,
		0xE714C870A283AC82ULL,
		0x51CD419AA177A75EULL,
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
		0x5E9AC0F02DA641EFULL,
		0x3029E59FE916CB64ULL,
		0xE3DC680F2B81A60CULL,
		0xF5C7DE2863CC38D2ULL,
		0x7DF32B985496B42FULL,
		0x732BBC4443C6FDB0ULL,
		0x6DB0E6AA16EF55C1ULL,
		0x34CC7DD9CA6AD361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10B3398CBC05022CULL,
		0x48A7D7C1F8A07397ULL,
		0x2C1EA54E930860C3ULL,
		0x4C228C7C6FA79949ULL,
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
		0x51C73709FCDFF84EULL,
		0x0DB23B4966264EE7ULL,
		0x87CFF02C9DACA770ULL,
		0x402F55C1DAFF86F1ULL,
		0xD529C34B69E22DB2ULL,
		0x4B4AA5285AB1CCC3ULL,
		0x9647E26BA55C4FE6ULL,
		0xF00A61461086E9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5FA343BB472C5FFULL,
		0x3AC6BF46DC8AB3F8ULL,
		0xD67B8C272960839FULL,
		0x61B9C6284F063A91ULL,
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
		0x3446DE5D833078B2ULL,
		0x4626737766578C8FULL,
		0x31C52676EAFBC515ULL,
		0x40F4C50351059CC8ULL,
		0x7F1F4DB216F66300ULL,
		0x99151D0F7B8E495BULL,
		0x3E42A8315396A19FULL,
		0x00C35C6AB2C20F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12EC66CCEBC32AB2ULL,
		0xFF48C3C3BD767024ULL,
		0x6FAA1DC95357C2C5ULL,
		0x5DF47CD9D9D3EB73ULL,
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
		0xC9D32A8E96E39CC4ULL,
		0xC7487144F4C12859ULL,
		0x1CE2D563B90A47EDULL,
		0xFA8CFCAC0D6F87E5ULL,
		0x83B5C3339601F586ULL,
		0xFFE53D38B44543D4ULL,
		0x7F2F3AF681BC148AULL,
		0x2ED237A2AE279763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CE2436DB2E0FC5ULL,
		0xC34F87AFB70939E5ULL,
		0xFDE595FAFAF5548FULL,
		0x6DC13ED1E75000A9ULL,
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
		0x0ABF3D022734C874ULL,
		0x94C81052C2BE0BF5ULL,
		0x193E8164868CDDD9ULL,
		0x2C5430824196A6ADULL,
		0xBBC9D8A04AC4D343ULL,
		0x2094DCC527E08EFFULL,
		0x008F89160C4018E8ULL,
		0xEA0D5AED40011FCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB564CD406C2985ULL,
		0x6AE0D596AE1345EAULL,
		0x2E8CDAAA5810904EULL,
		0x6A4FAFB9C1C15EF5ULL,
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
		0x5DC8BD79DA9E1772ULL,
		0x9F1A29D268335D36ULL,
		0x28F9783E0262E2A0ULL,
		0x8249AB13128FF40FULL,
		0x41CDA737468B6A38ULL,
		0xB32C1FED7F21E6F9ULL,
		0xE17EDCBD91151D76ULL,
		0x5E5294056C61D872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224F8FAE534FDDE9ULL,
		0x37A6E713473BA636ULL,
		0xA1CE3C618B85423FULL,
		0x028BA3E12916151CULL,
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
		0xDB3912DD2CC5FA65ULL,
		0x737A0A2D6759AF5CULL,
		0xA2586EB358405EE2ULL,
		0x7F9ED819ED679AB3ULL,
		0x35E387B9D576762EULL,
		0xBA491120E678FAA4ULL,
		0x5A0E299F5A12C2DDULL,
		0xA201595AC8A6B70CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFF3872DC5B88DCULL,
		0x1A52950F9D4EE3BCULL,
		0x00729C5AB7094BCCULL,
		0x0BD21B93B626C689ULL,
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
		0x1723CAF79151C81FULL,
		0x83B4005D47A8373DULL,
		0x117AD467B70DE4B3ULL,
		0x166F12D2C462EA8FULL,
		0xD3B47D61F83261EBULL,
		0xE010517AB3A42F4DULL,
		0x63989111D05EA06EULL,
		0xD478563B187AAED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83EE678268CC55AEULL,
		0xC6201893F2073CCAULL,
		0xDA205D0CA519B528ULL,
		0x204BDF986698DE15ULL,
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
		0xB8499378D80DB6CEULL,
		0x5F3AB1F97FC92053ULL,
		0x85607282F50A5432ULL,
		0x62E090C67F0D4985ULL,
		0x7D9EA7B23DD0D407ULL,
		0x41B62B1751307CE4ULL,
		0xE2BE1DA395B6BC96ULL,
		0xBB2C25C97D201081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DD677EE050D3400ULL,
		0x2045176F8CFBAA3EULL,
		0x2D98D8CB2E2A5280ULL,
		0x2B6E2CAF11CFBCCDULL,
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
		0x5E7AC17E1AB822CDULL,
		0x96F24D5A3F3AF55AULL,
		0xBBF417CEA4A6E849ULL,
		0x1618930691EFE853ULL,
		0x12A285757A65FEB9ULL,
		0x812ABEF358CAFA99ULL,
		0x9E084C9E93A2F372ULL,
		0x9413C74B2CBC0CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x229A90EE45DBF587ULL,
		0xC34AA5796D5C2813ULL,
		0x312F77588ED70B48ULL,
		0x1108282F35D9D431ULL,
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
		0xF59D1B84200811F5ULL,
		0x7194EB58F00B42D8ULL,
		0x68B1D4B6034A2F1EULL,
		0xC3CB66DC02F39FB8ULL,
		0x171781772A303917ULL,
		0xED01378701475891ULL,
		0x9F973FC851EC3A27ULL,
		0x9AFEFE43BEE7B69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631A533463308EDCULL,
		0x9FC3296320A26862ULL,
		0x19254C722C5AD10BULL,
		0x45A524EA5958BAF8ULL,
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
		0x1699DF3F7F7518D6ULL,
		0xDB100098668BEEA5ULL,
		0x23717D42697BF205ULL,
		0x869F5C58F39B27AEULL,
		0x7E80D50B2A0E6C3BULL,
		0xD911E4060BA9205EULL,
		0x629A9EDDEB0639B2ULL,
		0x0D9727932360E6B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB97EE7BD9929F7ULL,
		0x13B7D97E21A6BCABULL,
		0xC66512334C688292ULL,
		0x0B0F3C3033FD6732ULL,
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
		0xF1F325E8B6B5A17EULL,
		0x7D36ABC02B5AFC6EULL,
		0xD6311A2DB583BAE1ULL,
		0xDB2858CA52EECFFCULL,
		0x61622D04B35C955BULL,
		0x6E455D8B8D0A726EULL,
		0x2AD54DFEDB538AE7ULL,
		0x6E8B873B1CE6815EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6685D49B5673CF86ULL,
		0xDB828E771AE7F8D1ULL,
		0x31DAAE0243EA593BULL,
		0x43DE6B909D2603F7ULL,
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
		0x587B2253C8BB73EDULL,
		0xB6D75BE3E28211F6ULL,
		0xE938D3F174931C84ULL,
		0x37ECF01AEAB60889ULL,
		0xA72E39FCE201A878ULL,
		0x207B081F7F4F5D8BULL,
		0x8ADE18DAAEEBDF80ULL,
		0x7FD09514E3038FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2957BDDD54FA788FULL,
		0x891A9090C849F4B1ULL,
		0x863084676B964989ULL,
		0x30E311349D3D5B68ULL,
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
		0x44087999A80114A4ULL,
		0xAC0E5DD50B663062ULL,
		0x96A53BE0EA730FABULL,
		0x87DE5D5CB1018F57ULL,
		0xFAB023AE8577E218ULL,
		0x44B106690FB8E32AULL,
		0xFA9975B407E1F8AFULL,
		0x66CD3DD34536A386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2DC58177CCA681ULL,
		0xDE55516D60D7E8C3ULL,
		0xC96CB49A15FDF9AFULL,
		0x4A558AB8F71DD560ULL,
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
		0x8ABCBAB1315209B9ULL,
		0x610FC39AB87C2AABULL,
		0x9942F77AFF56DBC0ULL,
		0x1279CAE130EFF901ULL,
		0x0FE304F2E87FFA01ULL,
		0x49ADB0D9103E5B10ULL,
		0x2798CB066A331E19ULL,
		0x490AC26092EE9075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE66F76BFB451276EULL,
		0x50D803D321BDAF0DULL,
		0x79F11A6EC2ED5381ULL,
		0x6A12A53700596A65ULL,
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
		0x8B8FD583FEA1D966ULL,
		0x2653366FB2BF9717ULL,
		0x9131D3F69B8B1574ULL,
		0xE175B56A877D1711ULL,
		0x38F30764C00582B4ULL,
		0x1CF7121D95E52808ULL,
		0x4411C1419FE00FA6ULL,
		0xB70F3439D77AE2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA2EE787F734446ULL,
		0x72FFE6D3F2C3884FULL,
		0xABD483B456CD681CULL,
		0x0DB7760083BABB4DULL,
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
		0xD44A23BADE54FAE3ULL,
		0x0B89D82D550E275BULL,
		0xF64BCD39B891FC65ULL,
		0xA2D6770011526ECFULL,
		0x95EDE1D39879B426ULL,
		0xAA0D1F8853267E92ULL,
		0xD44739DEB2EF7402ULL,
		0xB0B81CB56F157640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1599A9238065BC76ULL,
		0x497C8669ACC4F11EULL,
		0x78DE6448481D34CAULL,
		0x5E2AB9EE8E81FC6FULL,
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
		0xE884822BA23E5975ULL,
		0xD23B4A09A592C36FULL,
		0xF46221573B8AD189ULL,
		0x8E103F20C85A082CULL,
		0x07E24C0AD6272D7EULL,
		0x0A08C30BB639A72EULL,
		0x9ACF1FBEF04A6D63ULL,
		0xCF46F901F855E634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x141BCBC76C0F1EC3ULL,
		0x4F883DC6B2219445ULL,
		0xEF20D7AEE6970E3DULL,
		0x5299356BA51A33FBULL,
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
		0xDC20B1BDFC3CE23BULL,
		0x57608EC82E36E0F1ULL,
		0x962D3C1650B177C9ULL,
		0x618BF483775DF418ULL,
		0xAFA81DEA37954BBEULL,
		0x56238854E34EF2FAULL,
		0x1D9509376BDF8D18ULL,
		0x44B51151E94BD074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF1522823C6621FEULL,
		0x20A6CB61EBEEF227ULL,
		0xFA4C9A5053E06966ULL,
		0x146C86AC189EE554ULL,
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
		0xD4136CD87C18B753ULL,
		0x9393971CA7F1D66AULL,
		0x11A7899D124CFC2AULL,
		0x7EA68EF21272C360ULL,
		0xE865A2B98DF80876ULL,
		0x4ACAD9B1D47DE429ULL,
		0x3E1A7019ECC83DBBULL,
		0x25916BC85408CEB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532994638EE9F9BBULL,
		0xADAFE78232A1B4A3ULL,
		0x49942D76380625F7ULL,
		0x123C8EAE8BC171AFULL,
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
		0x95C64726CB1EDD9EULL,
		0x1B1B1997C70D2388ULL,
		0x211D24480AB24666ULL,
		0x2E87D3298E33E3F2ULL,
		0x14EF10E740FB4F8BULL,
		0xB227118F15C84753ULL,
		0xC3FBA3801AD20D53ULL,
		0x22CB87A0F2376216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB142C97A706CACFEULL,
		0x8CE7B4D502C7B9DDULL,
		0x3877694C05E040D2ULL,
		0x58BDF50D826C7353ULL,
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
		0x1001680CB93F0230ULL,
		0x95AA9FDC0589CB00ULL,
		0x3A2340D9464F3167ULL,
		0xBF5408BFAB442E40ULL,
		0xB500A729DC4C6252ULL,
		0xDBE456ECD6347A81ULL,
		0xBF4E2DDF60AF13B3ULL,
		0x7FF4CCE9DB5F6378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1A38436C959D41ULL,
		0x398F8703D153FA40ULL,
		0x9FBE1001A04C1E1AULL,
		0x3DAA73763B6CF22CULL,
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
		0xE6FF138C72FA0547ULL,
		0x4C2D3F0BF16C7627ULL,
		0xF70A2959EE9032B0ULL,
		0x9ECB695A6E6890E7ULL,
		0x6F60AD250A64632CULL,
		0xF913142935B5E2D6ULL,
		0xDB00521A11AD3968ULL,
		0x657D9CA52646A2A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F58C70BFDE0C01CULL,
		0x45023D29EA6C21FCULL,
		0x791659388E46B845ULL,
		0x2F70A9DE1CE4B4C8ULL,
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
		0xF0CC3CE43F6C08D2ULL,
		0x2BA8B20895B78731ULL,
		0x075C7BAF1D747528ULL,
		0x9D3FE5A249631146ULL,
		0xC0697B951EDBA51DULL,
		0xDAD252F9E5189353ULL,
		0xF1C5AB197C98DA0EULL,
		0xE92449E479E541EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80749506D4069052ULL,
		0xA6E10320975D65A0ULL,
		0xEAB3E1779C24D35CULL,
		0x38A2DD8C616ADA25ULL,
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
		0xFA6548887D62B95BULL,
		0xB3AA0FD34E63B977ULL,
		0x0A6802BFC50F362FULL,
		0xB0400808144AB38DULL,
		0x168F15685B21BF70ULL,
		0xFF0048B92DD32B91ULL,
		0xD1CF12BBD3DDE230ULL,
		0xA2AB449AFA14E7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A276060465279EULL,
		0x8DB4DB501BBC3101ULL,
		0x2F24CAA137FEC975ULL,
		0x55AC370933651994ULL,
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
		0x32A501B34388CFBCULL,
		0x5F3DB55FFC80E364ULL,
		0xA7B2658A94DD5412ULL,
		0x63C44692B20CE56CULL,
		0x83DCA22F4BD4FE92ULL,
		0x8FCA98B05C0AAAE5ULL,
		0xC0DB220E37DDF6D7ULL,
		0xC44D623128531058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC56514B885269DC9ULL,
		0xB7505F8DA6164175ULL,
		0x483973A6DFCFF811ULL,
		0x0740D9DEAE615299ULL,
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
		0xB4B4C2E821425659ULL,
		0xFEB61AB1D366709BULL,
		0x3AF649251B8982EBULL,
		0x3608087DF8AE5156ULL,
		0x8BF8C7320178D0D7ULL,
		0x38F537A57F198B62ULL,
		0xA1063A457B1786EAULL,
		0xC8F2520EB4EC1B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BA2545459315AB7ULL,
		0x731C5D42B131213CULL,
		0x21E2EF75610789B0ULL,
		0x0A0036ACD3BA62DEULL,
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
		0xC202119206F9F707ULL,
		0xF9487C9B9D313F1BULL,
		0xE7DA9DAF7732DDC2ULL,
		0xCF90DE49FFF403F6ULL,
		0x50A26EEF1D97AA47ULL,
		0xE43BDA75C42002D7ULL,
		0x1B5EF60B6CFDFA5AULL,
		0x98CD8B6541CBDE5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1E89106B7D40FBULL,
		0xDA2AEA16B9F1AB11ULL,
		0xF7F32361A4E60740ULL,
		0x7E138F51C43705C8ULL,
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
		0x8B37F80B4C0844A5ULL,
		0x2A195617A686AA14ULL,
		0x89F24C55FB248AA2ULL,
		0xA3A55217EF838B96ULL,
		0x3C2FC9C2B5A86468ULL,
		0x24201288402DCBD2ULL,
		0x8E2B45893593DB18ULL,
		0x31474656E0012815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4FEAF243072D32ULL,
		0x86DC16512D52EB49ULL,
		0xA45E9EB3EF171037ULL,
		0x7439C2FD2FAF7EC9ULL,
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
		0x9773B4968347E37FULL,
		0xF6D446D3778C5A6FULL,
		0x05AF0A688CA0EB1CULL,
		0xA96DD120DA2EA93CULL,
		0x8295716832A1DE80ULL,
		0x0005553CAA2D520AULL,
		0x402626FADB717AD2ULL,
		0x7B2D21ADA3508A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A28A0E074EED3EULL,
		0xF79EEDD4BA4687FEULL,
		0x8B58D3A51F792648ULL,
		0x7220D0E7182326E7ULL,
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
		0x764E91AC2F643D6FULL,
		0x2F7F86A7356F7455ULL,
		0xC24D831011ADA8D4ULL,
		0xEA367E01C0E8F064ULL,
		0x5D7E3EEB8489BE64ULL,
		0x2D33C6411CA9A934ULL,
		0x36A2C771B6CE26B8ULL,
		0x70FB8D23626FB0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570BE8A1DBD682E0ULL,
		0xE52EF451769E921BULL,
		0xDE771DF13447682AULL,
		0x2F8D71425D7D29F4ULL,
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
		0xA224268E91480CFFULL,
		0x3A74E9290BE705ABULL,
		0x82C625C39F1C2588ULL,
		0x837E40F1906B76D1ULL,
		0xF5029C22AD75A01CULL,
		0x130D9483EA2FBB74ULL,
		0x886D8E34D989D1FEULL,
		0x3A3F438E6FB73587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x008753B450BDD27DULL,
		0x0E78F4BDCEFCD908ULL,
		0xC309419BE991513FULL,
		0x28E24816259D68EFULL,
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
		0x51C623B242B1DFEBULL,
		0x95B2ECE1C1149BBCULL,
		0x6616C4CB4CEFEE8CULL,
		0xF135D5D5EEC6AFC6ULL,
		0x9793F5D6223EA928ULL,
		0xD239EC338C6B4CFBULL,
		0xDDA78B3581691AFAULL,
		0xE01BA4BD75F85EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1BCA17B57FF00E7ULL,
		0xCA4BFC8899020914ULL,
		0x4CF56EBC8289EFC7ULL,
		0x355049F571A4C0D9ULL,
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
		0x3E02CFCD58552623ULL,
		0xEDE63F659F7539DCULL,
		0x7B3E5E0A333ACE0BULL,
		0x4EF32F3DAC4FA64BULL,
		0xE276CB9B0A3EE37CULL,
		0x3FFF0D0345E38FE7ULL,
		0x83CF7C17C37A6CB4ULL,
		0x5FABAAA447EEFFA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA508D0DDAAECB2ULL,
		0x6DC22DE1FF3C9647ULL,
		0x0C0AC9913766F0CDULL,
		0x026E83A059C99975ULL,
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
		0x062AA3D913A7E712ULL,
		0x16600B7D944C9BCAULL,
		0x95D41C89A72716CCULL,
		0x8959380CF0A60EEDULL,
		0xE518A8A38A68E1C8ULL,
		0x791C4440DC18BA0AULL,
		0x15F8A6265B05DBEDULL,
		0x5033F40FC44DA706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D3AC1F9F396C8AULL,
		0x10922D1E3FF83968ULL,
		0xD8BCC63B2A05BC0CULL,
		0x710F7264142CD9D4ULL,
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
		0xA15DD8BFE96B02BAULL,
		0xF2E21A9391F0FE95ULL,
		0x3577AD22B8629D02ULL,
		0x127955B172BE9CBEULL,
		0x7B3CF6D23C15C5E6ULL,
		0x7DB275E509B3A8B5ULL,
		0x695E57CA07653DB8ULL,
		0xEB447C37A695A045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6A7BF4D4A667FDULL,
		0x9B5F9A93029C0985ULL,
		0xD978B51FD169C665ULL,
		0x7EA3C5F42CF4670BULL,
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
		0x2011DCF6B279E805ULL,
		0x194F79E9CFE4A058ULL,
		0x6B57AACCA969DEFCULL,
		0xF13903C3092C2FACULL,
		0xA2115B55BF895F70ULL,
		0x6DED522999A7EDAEULL,
		0x08B0CB1F317B9930ULL,
		0x0C5457417F5B462DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA56BB120DE1304ULL,
		0x6A89AC169ED1E844ULL,
		0xB595D16E01C29C2CULL,
		0x45BDF77BF0B89A5BULL,
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
		0x92529C7F99F7889FULL,
		0xA9434B1B3EA15449ULL,
		0xFD1BA4FB978FEED2ULL,
		0x6FB9C029CEFFBFFEULL,
		0x8C4354F7140BC732ULL,
		0x3572C9167520BAE0ULL,
		0xFE040E359BFB7861ULL,
		0x2EA0CA435E459335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6451392C93B71B15ULL,
		0x984D2470A17D119EULL,
		0xB1B5C0F0BEE3CD40ULL,
		0x5B97C629CD539A02ULL,
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
		0x4E51899EE075915EULL,
		0xBAB167D9A2B03FC2ULL,
		0xE695AB1A13A76684ULL,
		0x07AC16822BE5AC2CULL,
		0x6B947FD3B4208E5FULL,
		0xE215F0C9AC9B2BB0ULL,
		0xC1ADE9FA031C1F6FULL,
		0x831669FEF30E4B4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x465C830B9D4AB64AULL,
		0x49F325C941B8BBF2ULL,
		0xA666663689D41120ULL,
		0x7CFFD25A4004DA03ULL,
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
		0xF1DE9779F33702F0ULL,
		0xF7B55337E9E96318ULL,
		0xBB89EE483108693EULL,
		0x87DC3BB7EB5D9F6BULL,
		0xC73F2CD7EF91798BULL,
		0x78D11802A3BD51F1ULL,
		0xF2828E34303311A9ULL,
		0x96853A77F4C32C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x853F3F8782CF10E9ULL,
		0xE6BEE39C38038CFCULL,
		0xBAEB0A07589D0866ULL,
		0x5FA2E98640563E45ULL,
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
		0x510355484EDEEC60ULL,
		0xAEEDC2A7992CACDFULL,
		0x547140138A9AACE9ULL,
		0xB2D843E80226D7C3ULL,
		0xDF5ACA3E666B1F31ULL,
		0x8E5FF523E3572546ULL,
		0x5FACFE12C4C61A24ULL,
		0x86C93823344A8E27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x787D5A8B82C590B1ULL,
		0xD12C25FB581C3564ULL,
		0x881EF6DCC0028E56ULL,
		0x34B69921C537F19BULL,
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
		0x739CD840B58E5AD3ULL,
		0x8C187DE1FF3B5A37ULL,
		0x5D53E0DC45976D9AULL,
		0x6E43321D2CF0DC7BULL,
		0xF1E5A6503ADAFBC9ULL,
		0x0E68AD8AC7D59831ULL,
		0x02E1D592BB377E9DULL,
		0xDF7BFA27AE95D355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB38829720FBFA2ULL,
		0xAFA2407BA8EFF1A1ULL,
		0xCAD994A40FD438EAULL,
		0x1AAA5401172E3B19ULL,
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
		0xB9C57C3ADB35C5CEULL,
		0xE4A7D97A9A361C22ULL,
		0x2A4237081DCF23A9ULL,
		0x6302B0D2D054308FULL,
		0x480A803728FD5EF6ULL,
		0x6721F47F8470DCDBULL,
		0x581E3B381ADF69A4ULL,
		0xE971A98A057FB368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B54846AF0D1E384ULL,
		0x33B2246842F6E4AFULL,
		0x3EBF015C1AF8D211ULL,
		0x09E1DB4FA148D20CULL,
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
		0xA5C4D679002AC685ULL,
		0x355566AE81DABD32ULL,
		0x4ADD51243580F063ULL,
		0x850B303B54F2EBDAULL,
		0x1A9009CBEEFF6F57ULL,
		0x507D366E9FB28C84ULL,
		0x49F20681E7E222C4ULL,
		0xD2B90043F33FB933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97264ABE7A15521CULL,
		0x27EB7B1A365B98CEULL,
		0x44CA486CA1121987ULL,
		0x4C813A5170686977ULL,
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
		0x99A47F73DF7962ADULL,
		0xA4BDD22970E3E1AEULL,
		0xA10CF938E76BBFB7ULL,
		0x96D2D472C0E27676ULL,
		0xAA371287113E62ECULL,
		0x8EB337CF60F37AA0ULL,
		0x21DC58F2E5619F2BULL,
		0x8493398367C0CDD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD13F806EBC14ADULL,
		0xD3581AF1D5081587ULL,
		0xA7C22D46F3E9602EULL,
		0x44AD5DF4278104B1ULL,
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
		0x91D68AE909D442F3ULL,
		0x8E6766C556826DACULL,
		0x180129596B355096ULL,
		0xB4698C2FCDDB2F26ULL,
		0x0417EE558E376339ULL,
		0x99EEDB46F9BEE237ULL,
		0x9E5717C6051E6C57ULL,
		0x6F8E2D59D538FDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D63EB9C260CFFEFULL,
		0x67DBF34E68D801D7ULL,
		0x98EEB0BE2DB96597ULL,
		0x438447857450DDE5ULL,
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
		0x3B71F726262B2390ULL,
		0x35357FFBA1C0CEE3ULL,
		0x63CB09A82A12602AULL,
		0xC7FE0878BCADBF19ULL,
		0x8874AA3EB0C96D1FULL,
		0x29B46EBEC8B74FC1ULL,
		0xB046C11DCC45B0A5ULL,
		0x32F2C9A497726D29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC33C746411575AULL,
		0x65FDF04D6CF6A59DULL,
		0x8E4BB4147C6A98AEULL,
		0x5807F6E737A9F349ULL,
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
		0xE1EA238D6C1AF42AULL,
		0xB1BE24E986166584ULL,
		0xD230C49963317D91ULL,
		0x7FA7F0750C65B90CULL,
		0x98F8D5F38DE27613ULL,
		0x5CBC2CD8E07F92CBULL,
		0xD15709EC2FF25D3DULL,
		0xD08EEC3B9E8030F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D9E5B47BB87F96ULL,
		0x75ACCD1AD9062FBDULL,
		0xE51C3DA8812B54ADULL,
		0x74DF014E936CFD17ULL,
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
		0x3D056AFE2861DD4DULL,
		0x8A2672DDA3D3562DULL,
		0xE69609FEF0345D93ULL,
		0x0F5B61DE8EC35A8BULL,
		0x94305EE1F51C3F2BULL,
		0xB799EC9A5C254FB9ULL,
		0x8D47DEC66F402F63ULL,
		0x54EF3B52137BDAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C3380888A933F8AULL,
		0xCAFF91C7515D2BB9ULL,
		0xDF411B7373BB6660ULL,
		0x2ADE300D7325D9F4ULL,
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
		0x7176C542663D8692ULL,
		0xE7A714ADFCB6D100ULL,
		0x7E28CD8E09882DC5ULL,
		0xDD5E4E582ECD1BEEULL,
		0x93C8CDF076FA051DULL,
		0xDAD554666481B1AEULL,
		0xE1BE088F3B124C6DULL,
		0xB8EE15BA5013043FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x614556F40F5A4D08ULL,
		0x63519BE0E7F730EAULL,
		0x005E12D0CE3F8614ULL,
		0x50B58800119FBD6AULL,
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
		0x6EB4C511CA8F43BDULL,
		0x9A3869950F561E35ULL,
		0xF0E766B2CAB4EC86ULL,
		0x274B15FB9156B9A6ULL,
		0x7C30537D54FC3FC1ULL,
		0xB3497BD07AD853FFULL,
		0x0C2DB23FDF3B977AULL,
		0xFBDE5BB832B15ABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDE129AC6800BFF4ULL,
		0x3720CA874B729621ULL,
		0xBFAFDC2DED8D68BDULL,
		0x0A4CB35317AA316AULL,
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
		0x5342D949B5144F10ULL,
		0xEF91A89FE87515ABULL,
		0xC27B7B6DF20E683EULL,
		0xC304DAC580A767D2ULL,
		0x475BFDF295CE4E5CULL,
		0x341DECE3AD1450C2ULL,
		0xDECFE721A428AFD2ULL,
		0xD2C0DC7D7B1F72B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAEA8B4BF1B3F578ULL,
		0xAC02D26B99791281ULL,
		0xD557CA6C50188172ULL,
		0x0BA59565C7526EABULL,
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
		0xAF856F912AE9DECAULL,
		0xAB9174FC01D51A3CULL,
		0xEEDA4DDA0A1927E8ULL,
		0x3CB5FDA266A46649ULL,
		0x94AF17D502100973ULL,
		0x6828E57FB57A159CULL,
		0x5CC85E0119195730ULL,
		0x0A8393F73AEC998EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC182F92F794B4615ULL,
		0x21A385F0F1F44F7AULL,
		0xB4984203C3DC1918ULL,
		0x4C3DF45525C3316BULL,
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
		0xE80562D77D0B5A15ULL,
		0xC73158BBA6900C7AULL,
		0x27FD33C9A21076D6ULL,
		0xFF5D6A6DCA7153F0ULL,
		0x548DFAD0B32FFA2DULL,
		0xC82DF76E42C12260ULL,
		0xAE1B397FE26CA9BAULL,
		0x30BD06248EAC450CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75189DD2162A7DF3ULL,
		0x7E0413198F3B26C7ULL,
		0x0007BCC53E31A890ULL,
		0x3B6C53DAF80393D2ULL,
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
		0xD40A957704F51019ULL,
		0x0379D60B674AC539ULL,
		0x5EE337CB4840110CULL,
		0x7595473050BF8321ULL,
		0x0E5DFB6CB28EA900ULL,
		0x7FDC18F373BC6468ULL,
		0xE147333C9DECD6B8ULL,
		0x479B01C8AC260DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5FDE799862227BBULL,
		0xFE258A2E9541ACABULL,
		0xCF74D2CAB967F06EULL,
		0x16978AF9DE658DC2ULL,
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
		0xD441AB297631D721ULL,
		0x097979C771C12C0FULL,
		0x2D6C5F2FA9F6CB06ULL,
		0xE610552EEFCC078EULL,
		0x56ADC301C3A50D35ULL,
		0x721349E7A9822CE1ULL,
		0xE2FBB3B1562D1805ULL,
		0x345BCC724D58A1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB20C9D6C80B1CE42ULL,
		0xF856722A9B13D582ULL,
		0xDEC90B8274A85BD4ULL,
		0x2BB0AE266AF40BD1ULL,
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
		0x60BEB51AC7566D33ULL,
		0x3812EA724502B773ULL,
		0x62D53387A7B09109ULL,
		0x16AC65833294CBA4ULL,
		0x1A52EF5E6AC2A818ULL,
		0xBC5C2F26811EA8D1ULL,
		0x02EFEC654261AA22ULL,
		0xEE61A258A49340B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x490E3D1EA03B65F5ULL,
		0x2DC1EA296F8FC67DULL,
		0xD2724A8F822FD231ULL,
		0x792A7EABA0706610ULL,
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
		0x194C499366037AA5ULL,
		0xCA431CAD37EF97A5ULL,
		0x892F1A286362FB17ULL,
		0xCA998D01FE9D6F25ULL,
		0xDA68506115015DD3ULL,
		0x0B461147D2859E36ULL,
		0xA2E47F42608B51ADULL,
		0x5CD96D60BE2290C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C837FC84376A1EULL,
		0x76A9AD5677C513C9ULL,
		0xB719FE02B8111AC7ULL,
		0x12DFC95E37BEECC7ULL,
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
		0xE317F23B4F54DEC6ULL,
		0x0F4926BD127B40C6ULL,
		0x4057F37D6DE0F998ULL,
		0x9B9DF50E0D8D1141ULL,
		0xF5360B516BB3FA8EULL,
		0x5AEDA6552ACA2B7CULL,
		0xD136A281655A8E1AULL,
		0x7140B9CFE9CD630FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491DA0514C0C1260ULL,
		0x8E8FD7616C7DB553ULL,
		0x4E7412B279521181ULL,
		0x6B3989EAC209C59AULL,
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
		0x3689B5272CFA5F50ULL,
		0x7FF298D66288FBEDULL,
		0xC866B7AA8A033BDBULL,
		0xBEFF877EDAA6BFB1ULL,
		0x873734CDFCCBEF85ULL,
		0x28B516AA3926A536ULL,
		0xFFC49D6D6290B682ULL,
		0x9E5EE1787D65616DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48BB8BBAB33FF09EULL,
		0x8AD3F61ADE458205ULL,
		0xBF9615E72B7E532DULL,
		0x4114FF6177B33605ULL,
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
		0x7011FC6E74D34F28ULL,
		0x82B1A7CC38844840ULL,
		0x0DD936A4BDE645EBULL,
		0xED340B03E648D558ULL,
		0x983305F1377961F0ULL,
		0x3128ACABA101048DULL,
		0x2D7E40EDBBC5739DULL,
		0x999EF56F89ECBF6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A4DE3CB0D7DC45ULL,
		0xCEBB49461EAAF545ULL,
		0xCE96D9EE9D356F40ULL,
		0x3ACC79925F6D3F40ULL,
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
		0x20D378FF67789842ULL,
		0xC2CA4B5D24718F4DULL,
		0x358AA4D44D83061AULL,
		0xA1A1E5E69CEE6580ULL,
		0x4576C51CDC1A5464ULL,
		0x6D6EB07141BD5385ULL,
		0x31754A1848833249ULL,
		0x025435908056A59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7074BB4813611F2DULL,
		0x01387C2CE68BF515ULL,
		0x8CF3A46F10FC7D01ULL,
		0x7A21D959A9CAFB21ULL,
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
		0xD6F6E6C19EC3DAEBULL,
		0xE1D6EB5A5608A96BULL,
		0x0E386C11FFBD7B6CULL,
		0x480E7F418C208B6AULL,
		0x3570042D70D9C86AULL,
		0x3A68266227B36882ULL,
		0x94A99693AE651689ULL,
		0x4D0154326B3AAB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC59785805F179C5CULL,
		0x8D4C9DEC3AAA2CBFULL,
		0x1F64C5FDE2BED3CBULL,
		0x3640FEBD76D5F2D8ULL,
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
		0xB6893F25B9794C81ULL,
		0xA83B6FA59C31A1F0ULL,
		0xC3C95519645BE95BULL,
		0x9C0EB078DA1CD886ULL,
		0x801A6C202D8F41C2ULL,
		0x38D2397D2F4DE069ULL,
		0xAEAD83F9B9976403ULL,
		0x1E36AA42AA892720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA754BEC7CBD100BULL,
		0x176FF83AA1C0F199ULL,
		0xB18AEC2AF0D4C1D6ULL,
		0x182BF65E2A78A760ULL,
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
		0xCFFF89AF253D2EEBULL,
		0x6FE8BB36B4F336BCULL,
		0xC594C4FBD821024EULL,
		0x97A26179590F9BE0ULL,
		0xB20763087D1530A2ULL,
		0xA520B62611441559ULL,
		0x3472DC73334610F5ULL,
		0x738F665A0CA06072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D183CF1B6626990ULL,
		0xF2C3C4DD450E620DULL,
		0x8EA17E15748786C4ULL,
		0x3EEB92D738DDECD4ULL,
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
		0x2C45BAEE88FB60E1ULL,
		0x417F4507AE081943ULL,
		0x63AD7DA3FC9DB572ULL,
		0x5D35FEBD4FF8DFBAULL,
		0xD7AD440B348E4536ULL,
		0x29BE849708D7C5B4ULL,
		0x60364C635051F032ULL,
		0x04DFA5BA622F10BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FFDD4985619A70BULL,
		0x73C6F372FE0F721BULL,
		0xABBCD461E8C75CE4ULL,
		0x16689867E2F55C22ULL,
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
		0xBCD0FAACD502B1DBULL,
		0xC08185D70FCB0F52ULL,
		0x9FEAD63F4DD43169ULL,
		0xD4AF5B1DD8DD82F0ULL,
		0xB5D91EB97BE7917FULL,
		0xD147B45443DBBA4DULL,
		0xEFEB18A60F857C71ULL,
		0x5D64243C54216956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0B8A3539624CDCULL,
		0xD1264A592268B6DBULL,
		0x3CD07EE59BA4AA4EULL,
		0x318CBC1255D325D8ULL,
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
		0x9C2ABCA59390B134ULL,
		0xFE7ECD74A626C79FULL,
		0x53B4F4881CE195F3ULL,
		0x3109E358D18CDDEBULL,
		0x3BEE03727772D4CEULL,
		0x36532D4CDA770EE7ULL,
		0x484B58C133CFA588ULL,
		0x51060D372EDA9F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817F3FA34E9C4990ULL,
		0x0ED786DD13D2FDF2ULL,
		0x0EE42135CDB4282CULL,
		0x37EFD989C600852CULL,
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
		0xEDD4CA5D20D557A0ULL,
		0x2D0DA6346F8C75DBULL,
		0x800D2BBA340F4837ULL,
		0x8420C3008C36A1ECULL,
		0x370CF3843190D5B1ULL,
		0x5F6535FDFD057783ULL,
		0x9FCECE9239A2F12AULL,
		0x012BC7525A9602DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C0EFFC7C550FF9ULL,
		0x5613A9E7FE5C3356ULL,
		0x38BFD56EC23F1481ULL,
		0x30A05939FE7B0E86ULL,
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
		0xDF4AEC1C7708A839ULL,
		0x9F3FE3B4AB8AA070ULL,
		0x625F880EA2B8FADFULL,
		0x784EB402C65C9C01ULL,
		0x17603E63D7F3CD1BULL,
		0x118F89B34422FA64ULL,
		0xBCD50526FDF54DB2ULL,
		0x92A2343079DBE6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57942EEE85391D7FULL,
		0x3A8E5450C8BBCB4CULL,
		0x69FE4BD85522834EULL,
		0x3C627334DD00E09FULL,
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
		0x09F0B28133BAA122ULL,
		0x3C1EB64F946CFAA5ULL,
		0x6A50D04B228E2EE6ULL,
		0x37AFD5A74BE31A50ULL,
		0xBD4E756DFAB41DAEULL,
		0xD594C44AD60A8D8AULL,
		0xCB90E08EFD88FC36ULL,
		0x9E520B4D53C1D201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x239620D46A770C73ULL,
		0xF033D96B59FDFD3DULL,
		0xA1D22584C4E39F09ULL,
		0x37DD8321BAA84694ULL,
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
		0x0F80B683B7735F6AULL,
		0xB8A3FE167EB476A2ULL,
		0x1B71EB79AB2B8F64ULL,
		0x8BBCD833D9D78884ULL,
		0x8D129C76D412E9FEULL,
		0xE010008E5D0D9CB3ULL,
		0xE1DB2B36CF8B4B7EULL,
		0x29730301D11A3004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0043F02732421C15ULL,
		0xFB0413384EB9B949ULL,
		0xA1FA559C79D8C439ULL,
		0x32CF4A78E3BAA93DULL,
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
		0x1D1DC201DAD3E560ULL,
		0xDC588A270638A99FULL,
		0x3DFAD98A5131EF90ULL,
		0x4B2BDC13A792928BULL,
		0xEBB3E241600A1620ULL,
		0x84DCF7E00AD76D22ULL,
		0xC9C3701714E5711EULL,
		0x08553864AF4CC153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19D157B61C532E59ULL,
		0x95255568A232DCCEULL,
		0x30FD7CF76B40BA18ULL,
		0x07D23B05ACF744FBULL,
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
		0x60E50A692C482D7EULL,
		0x55F2BFD0F55386F9ULL,
		0xF3FD229B61C31442ULL,
		0xD9D4CF4E211816C1ULL,
		0x6C1640D240E38439ULL,
		0x98ED8C53163AA18CULL,
		0x483557380678C47BULL,
		0x6F08C4DD26D310BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C32A99ECE0DD07AULL,
		0x09359426420781D1ULL,
		0xABE814EC57B03E9BULL,
		0x55220821E46C928EULL,
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
		0x298F0163BD6A4DB2ULL,
		0x6F9981BE78F7E307ULL,
		0xFAF0C9DC7A5F1302ULL,
		0x132946A0A8C46C06ULL,
		0xCE88CB0D29686EC6ULL,
		0xDA4E2984A1C8F871ULL,
		0x085192291923463BULL,
		0x0D3A6DE69BEB9CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1DD2557E2EABF62ULL,
		0xD733AB6E7CCCC3EBULL,
		0x370C7BF6359B7FE4ULL,
		0x09D596DBCDBDB678ULL,
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
		0xB58964AB09AD4A69ULL,
		0x2D85592E5248C18EULL,
		0xAE1337AF49CC9EF4ULL,
		0x26BC555578E26E18ULL,
		0x4271334D84BE6531ULL,
		0xC5D11468FF010267ULL,
		0x06EEB26C7448C10AULL,
		0xBC3535DCDCC67678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9257022CBDF053D7ULL,
		0x8A8E60C42C6F1CE2ULL,
		0xB581B3C88C99468DULL,
		0x16A2541E3E5803E9ULL,
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
		0x8CA3865B789E1CD7ULL,
		0xE7AA4D69F73DC8AFULL,
		0x515A8B9626638F33ULL,
		0x2704A05A05C6BB34ULL,
		0xB3376A3242774878ULL,
		0x2FD37527A5D0E3DAULL,
		0xCF80B9DCCBD89B14ULL,
		0x10B2481482683057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26DD49D15652DF06ULL,
		0x010DB14C943F9B26ULL,
		0x1E76225C688A9433ULL,
		0x217B5365613DE83DULL,
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
		0xD32BD71761E36644ULL,
		0xD8B409CD6D5E85DFULL,
		0xB459B889978EF3FBULL,
		0x26A908C57B6AFDCCULL,
		0x6233860F0F561925ULL,
		0x5F3B3ABB0EA8B4BEULL,
		0x80F4440838453FF6ULL,
		0x8B9BDADE4C9F6C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66D1BD53A8AB24CDULL,
		0xFB7EC1919A695A22ULL,
		0xD89BD1C1F1D6728DULL,
		0x5FCB85C4DB150D71ULL,
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
		0xB12FD5F8A9A1963DULL,
		0x0AA44AB3228A2680ULL,
		0x2B48AE8CEDE49CB5ULL,
		0x0E3F7A77F00C81EFULL,
		0xCD1992A3BF12C59FULL,
		0x2E3836B205101E07ULL,
		0x341A09D3A944CCDBULL,
		0x22FE3EB0121D6182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22FB9A47066AEC95ULL,
		0xE6FC691FE2EE9BA9ULL,
		0xE72623F80E1B053DULL,
		0x3FFCC89AA068FB42ULL,
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
		0xD429361AAD631AB3ULL,
		0xC34D04EB09CEC944ULL,
		0x15EB0C9E653C63F7ULL,
		0xB4DFF9BEFC440866ULL,
		0xDABD30E2441DA7F2ULL,
		0x96EDC82D0B972D4FULL,
		0x6447F24AA5FAA56BULL,
		0x99AD40DC8DF4650DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3E77B0C9CA0C1CULL,
		0x2A98BB9AC23F831FULL,
		0xF89903B30870F1F0ULL,
		0x04979A7C0E8B0862ULL,
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
		0xBA0EC80BDCA908D7ULL,
		0x8AA9D0C7F73F7AB8ULL,
		0x33D21A37E9F17420ULL,
		0x315C29341B0366B1ULL,
		0x65BBDD020CBDC2F7ULL,
		0x7BE02D56CEBD0E91ULL,
		0xD6975F662B464E42ULL,
		0x27E03A60006C3AA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F19659C0D3FA65ULL,
		0xEDF08BAAA74FA44DULL,
		0x0E4A4362566111FEULL,
		0x1CA4D3742B141ADDULL,
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
		0x3A46B311B94994EBULL,
		0x9D8B145F46443354ULL,
		0x4C78DBC59F2213E2ULL,
		0x2A30F72A7E8E6888ULL,
		0xA4E7EF92CD936212ULL,
		0x2C44C4031559841EULL,
		0x813DECEEFC3649DBULL,
		0xF00BF7FEAABEB61CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B442DC3D2A28DCULL,
		0x2FC02CD4718DCFE0ULL,
		0x7BAA073F0F310A6BULL,
		0x4BF7C6F7D6DD70C3ULL,
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
		0xD39CBFAAB1935933ULL,
		0xC17F718B3ADAFEFDULL,
		0x2AA1F72A8351E1BCULL,
		0xD9D8E136788392E2ULL,
		0x5BD24CE8671E6C09ULL,
		0xB0EEB570FB0271B0ULL,
		0x0498235322C73481ULL,
		0x3A5A27ADE1109956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D42A2A001763F2ULL,
		0x04EE60507D37DF2BULL,
		0xD9373581ACE3ACFDULL,
		0x033AC505E0FA55A6ULL,
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
		0x61B7421118D55210ULL,
		0x190C49CE5191BA36ULL,
		0xFCBD52530D3F19B5ULL,
		0xE7DFD0172297C5BDULL,
		0xE98003B88219F9D3ULL,
		0x75370A534958DFFFULL,
		0x76EAB4826828DDFAULL,
		0x687E6913FCBAE224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB7CF7468B069C2ULL,
		0x7F37D22B34C2FA33ULL,
		0xA3941DAE83500CE2ULL,
		0x6AA3690EA6555727ULL,
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
		0x729E0C45C53EBC5BULL,
		0xD96E0A7A0193321BULL,
		0xE9077FD7A3E67BE8ULL,
		0x5AAF68FDDC1F3395ULL,
		0xD21D934AE07A8420ULL,
		0x3E328B4E2C6815C1ULL,
		0xB9D8D6B7E7B1CF3BULL,
		0x18C481A1843032B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA301E963176E59B3ULL,
		0x14EEB81499066CE0ULL,
		0x7F375F24084B3EB4ULL,
		0x07DAA6F77B46BADBULL,
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
		0x23E26CC99AF9A1E0ULL,
		0x28996447F13A5105ULL,
		0x618EB5F5FB3682CAULL,
		0x524678E933B781D0ULL,
		0x5C2F6E0CB7AE79D6ULL,
		0x532D64EB1812DA71ULL,
		0x8F0B910838828694ULL,
		0xFBAAADA9A042E35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2ECC2ACDEDFBD35ULL,
		0x81565F2D8406BDD8ULL,
		0x9D463D2E5E967CCEULL,
		0x2D9C4016FDA541FFULL,
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
		0xF90EED08BCC96C49ULL,
		0xE2D9F9C5235F2449ULL,
		0x22AA8DB896B768E8ULL,
		0x3A00A729C8041DFEULL,
		0x69A594253E082499ULL,
		0x17DCE5BC6B85414AULL,
		0x2DD33BCAE8BE301EULL,
		0x6CF8F1F3C1BA5BFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A2EA8FF1FEDD5FULL,
		0x6DA413BD1926D555ULL,
		0xF0056DD722F28D60ULL,
		0x66F4915889ADC56CULL,
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
		0x2E1B4A2AFB3C83B7ULL,
		0x04A0A742D4D3326FULL,
		0x6663A721ADE5C08DULL,
		0xD74C21D7A358E637ULL,
		0x092C9C94A741864BULL,
		0x83B0773DF9257ACCULL,
		0x9E396094D26AD446ULL,
		0x96514ABF1D9FD732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ABA883BCEF67643ULL,
		0x90D25A75D0636CB8ULL,
		0xE2E7FD38E9C14304ULL,
		0x275D3A360912D7BAULL,
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
		0xC32B7793EFFEA2CCULL,
		0x3A52E726C6CFFC47ULL,
		0x35844D3542A273AAULL,
		0x42C819B6966A37CCULL,
		0x42DFA3471C66C478ULL,
		0x7351515C17A03762ULL,
		0xF48A9CB5D7783848ULL,
		0x82B19DD06A9B5831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB05DB422273FCF81ULL,
		0x5864FAD2489834DDULL,
		0x821790333E7ACE6BULL,
		0x292586A669794F36ULL,
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
		0xCE652A32B80CFC60ULL,
		0x399501B2306021FDULL,
		0x702DDB2E5E08F3CEULL,
		0x5E5266A5562534DBULL,
		0x911BD7CB0D0D0510ULL,
		0x8F214FC5A1DF4AC5ULL,
		0xCC835505ED428D1BULL,
		0x03580DED9EFF41C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58873256A7FBBCD3ULL,
		0x7886D90837853B51ULL,
		0xCBAC7A0F95E9E5E5ULL,
		0x5D6477EAF008F811ULL,
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
		0x7A1470DE9DD9B62DULL,
		0x412435A79A1E5C62ULL,
		0x9B9A2CBB966079D2ULL,
		0xFBD031412084DDE9ULL,
		0x47A002E77B447E03ULL,
		0x37E0F7382694FC85ULL,
		0x0E9143F3CB9CB8D1ULL,
		0x6807909252A00F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD4DF3AEA046CFFULL,
		0x8C88E7FD543BD82BULL,
		0xC52A42EBCFA3E8E0ULL,
		0x6CEFA6F9644725B9ULL,
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
		0x67076121C5560551ULL,
		0x81A69562EFF30981ULL,
		0x7E2EC6F31D4813F0ULL,
		0x15765F374CB7D44AULL,
		0x5EBA0D105464F130ULL,
		0xFB87D12A639A1B73ULL,
		0xA6EBB874D18E37F0ULL,
		0x449A22E348105753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A5518E4C51D3EDULL,
		0xD7CFA1ADB8D31CA1ULL,
		0x452C284A386461B5ULL,
		0x44578CF3FF24CAB5ULL,
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
		0x5635D8BF7899E3F8ULL,
		0x5F68456FDD4C0610ULL,
		0x9A343450FE9E568FULL,
		0x012DA03D016E8E1CULL,
		0x115014D019C7DC5FULL,
		0x7914D4CEAD971C26ULL,
		0x8B37071DC3B80437ULL,
		0xA0A8DA7B313C94B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE818EFA34C449D8FULL,
		0x587FDC1DA1BA33B6ULL,
		0x445F42BC0BEEF6CBULL,
		0x5A3E0E86506CA135ULL,
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
		0xFB622D68E23D8469ULL,
		0xC4D1911807C01C9CULL,
		0xC170716CAF848408ULL,
		0xC9BB42C72180A432ULL,
		0x777EC262C393D9BDULL,
		0xC12C7BD6C2AF73E9ULL,
		0x09242EC76B1A3534ULL,
		0x226EBDD136E961BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8330811EA2FD748ULL,
		0x716BF2F8EDCB5144ULL,
		0x1CCF6306956869DDULL,
		0x662B6FD5482525F6ULL,
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
		0x2249EB1D26C6D4FFULL,
		0x2CBE38AFA72FB6F0ULL,
		0xAF599A961B320237ULL,
		0x7D14BAF7F7CBD14AULL,
		0x1F6264A9A053284BULL,
		0xD4D813A90A0220DBULL,
		0xDD8B831B5CAAA248ULL,
		0xAE91AD8DB3EB73AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE4DC4AF31ED3FDULL,
		0xC4D123C723809776ULL,
		0x920F10A5DC861906ULL,
		0x66B47E00ACBEFD65ULL,
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
		0xD48EA50A48774304ULL,
		0x45053B83EB1C66E4ULL,
		0x94B1D160B36A4843ULL,
		0xA7DB6C884ECD189AULL,
		0x2ADE1C578B043B36ULL,
		0x986253FA2702D83EULL,
		0x28F75A3E0EC0D3BDULL,
		0xCF2948870EF1A507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3186DA08EB1811A2ULL,
		0xE39DB2A5B588801FULL,
		0xA9693696E409B667ULL,
		0x67FC309486AB97AAULL,
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
		0x6EA65FB5C92E7C43ULL,
		0x8B64A2E03722A923ULL,
		0x3A63A35B11D12BC8ULL,
		0x3630B124E5EF3BF5ULL,
		0xF519B446EE7E3CE9ULL,
		0xCF37764D7D8EA468ULL,
		0xC6E850ADCE4BCBFAULL,
		0x999CCD5759D52795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD077223D2FEB8A43ULL,
		0x4DA03260DA4F10B7ULL,
		0xC0DF9D27B1117303ULL,
		0x03772C1C3B931C30ULL,
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
		0xDF2EF5BCBCDCD5BDULL,
		0x7C25025CCCAFF167ULL,
		0x50173BC65DBB31EFULL,
		0x6A16E8CEBEDAD18FULL,
		0xD003987F0EAB70D8ULL,
		0xF7822B5A8CF02B2BULL,
		0xD4A1093FA115BEB2ULL,
		0x0F1322CA984DF34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFB79898EA4F962CULL,
		0x397771CDB85659E8ULL,
		0xDFFE9B3846F58080ULL,
		0x26EE12E15A6CEED0ULL,
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
		0x00000824CA3293FFULL,
		0xE8E94F431AF8ABEEULL,
		0xF1F1DBC6C9F6F9CFULL,
		0x73C97F318093D825ULL,
		0xE57315B1091C8D51ULL,
		0xA0CE1FD7E2011C1CULL,
		0x5CC5BBF0E7E2EA7BULL,
		0x62DA9726D35B1FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F15406C246F903FULL,
		0xC782094EA722D838ULL,
		0xB74BC18935A5C829ULL,
		0x203BEEF4E01A94EFULL,
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
		0xB9E5F3FBD2A024DCULL,
		0xA47B6AC037BC11CFULL,
		0x2ACBF455C772BB84ULL,
		0x6CD118A4DC4A50D4ULL,
		0xC983ED32583A7726ULL,
		0x0357A35E5AD232FCULL,
		0xEACAEC4F06E9E4ADULL,
		0x2A2BA7F0EF526270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA37B2974EB4DD577ULL,
		0x237DAAC1B2EFA355ULL,
		0x04EB0810CE2AAD33ULL,
		0x2F4C06686284ED97ULL,
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
		0x684E2634B20DE3A5ULL,
		0xF1C4A9376C34EC79ULL,
		0x054BD5189C14CD15ULL,
		0x086A266ED64273A4ULL,
		0x7E253C4A4FB9CC9CULL,
		0x674E4FF5F15D88EBULL,
		0x4B7E6B31381E1229ULL,
		0xB9A67B7CA9E7B1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D5193C87A246E2ULL,
		0x476487B940173F6EULL,
		0x3A0FBE66F08B7F3BULL,
		0x17207AF00EA6DD4FULL,
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
		0x0223F8671282D5E9ULL,
		0xC7922E1D7CFAF5A4ULL,
		0x2F36956E3BE7E813ULL,
		0x6423D89BACEA3E38ULL,
		0x03502702BB523DDCULL,
		0xC87D470CB2D1C585ULL,
		0x41FFA1C67A7C15DCULL,
		0xA13CB9755D6CBFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8009C2CEE0B80821ULL,
		0x8A2ABA00081E4762ULL,
		0xFB2898E46A5326D9ULL,
		0x532760078B0EB2D3ULL,
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
		0xB005D7639114EBDCULL,
		0xDC7A674BE3B4BDD3ULL,
		0xB5E3B7CC2920726DULL,
		0x2A4811C9E23E3309ULL,
		0xC0156E475AC5AC3FULL,
		0xA0E982A1293168ACULL,
		0x7196C8AE6B70BCCCULL,
		0x4648339FB316B323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x333435FB0A6C7EC5ULL,
		0xBF23CB38010A4778ULL,
		0x924581B01BDC78CDULL,
		0x18FFBB7E779CCA4CULL,
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
		0x29CF706D85D349CBULL,
		0xD25D6D57B65CF18DULL,
		0xD6B243117A75CD30ULL,
		0xAC76D42BF0F015E3ULL,
		0x96189919760BE86AULL,
		0x04250048DA3E84C0ULL,
		0x90DB23A9E2CBDA48ULL,
		0x4A55C53841C71829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71762A350B97CB3CULL,
		0x6FDB78281BA4A623ULL,
		0x57398E4924B833E1ULL,
		0x35321A85B47DAC0FULL,
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
		0x19D3692F867317CFULL,
		0x2FA86ADBB3EC0A25ULL,
		0x36D1007339DA8289ULL,
		0x9CA07A280BB0AFFAULL,
		0xEBE899FBADFB349AULL,
		0xA78A67EAB09958EFULL,
		0x2B9BA395EB6A1A62ULL,
		0xB2D9E00D4191ECEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5A448B59BCEAADULL,
		0x0E33D7B1EAAF3DC2ULL,
		0xAFEB48B42B9A6D2EULL,
		0x28F7BC1FC759DAE2ULL,
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
		0x2E606B74E1FD76E4ULL,
		0xC726C48A7E0A122AULL,
		0x784B328562F49CB6ULL,
		0xFEFF5817CBB9E837ULL,
		0x679C071D3B3CCAD9ULL,
		0x7B882103686CA133ULL,
		0xE74244A3225D03CEULL,
		0x5ACDFE8164249630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F8979CBAD03952EULL,
		0x1D5BAB0BFE29FFCBULL,
		0xCC2162BC7CC32D5DULL,
		0x79931F4CA9283379ULL,
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
		0xBF6BCD4F60AA58BAULL,
		0x8736D0FF97E2A2C1ULL,
		0xDE8012279651749DULL,
		0xA2D96197450D25B2ULL,
		0x7F93111E24615D41ULL,
		0x8D41844A1DB00376ULL,
		0x0FA4B254AC838A0DULL,
		0xE3E5E6AA85CF6F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF4057C8C71E356CULL,
		0x7EF0740000032658ULL,
		0x30F28AB931D7F2A0ULL,
		0x76F99EE721D7B431ULL,
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
		0xE7734F702B7ACAD3ULL,
		0x4FAF4097D4596C3CULL,
		0xDE5B73CA32D503D0ULL,
		0xE0CC7B399BF1F7D4ULL,
		0x17603D6B4E951C76ULL,
		0x162716B8039F3D15ULL,
		0xA5297DB7E2A43EADULL,
		0x61DA31B9B00DC012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBC6D5DD59D0691ULL,
		0x997C9FE85DFC7D5EULL,
		0x62841D15D7365181ULL,
		0x672FDCC9BDFC7A99ULL,
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
		0x76F2107420D5ED95ULL,
		0x552948350D82BD9EULL,
		0xD2C94D8BAF75D117ULL,
		0xE118D90E76B08A2DULL,
		0x19FE13384E8FF3FEULL,
		0xF24741204D45040BULL,
		0x2C7CDC52E5C13E81ULL,
		0x73E48E7D32AAD330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52A8EACFCA3427F5ULL,
		0x4BBCF30085C15744ULL,
		0x6D5201D9CA251861ULL,
		0x1505FFA3FC0BE354ULL,
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
		0x760595C2E4E11D36ULL,
		0xE43E9F3DAFA3742CULL,
		0x72C0398EBFF9CF78ULL,
		0xD9FFF6EE3DFE0DD2ULL,
		0xD7FDB79B8BC9F621ULL,
		0x49FD3F22CBE7B399ULL,
		0xEC61C097966E42CEULL,
		0xCB94763351ED63B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85AED6D9A4DBAAB6ULL,
		0xDFD5FE67F4081D02ULL,
		0x8942D00F1457BA17ULL,
		0x1209828C673ADAD3ULL,
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
		0x48E0E1C4F1D09B4FULL,
		0x5BFD36E9C085AEF3ULL,
		0x1D476082DC05CC8FULL,
		0x351E7006C9BDFA38ULL,
		0xB177972BED9350F7ULL,
		0x43148EFD5C42977DULL,
		0x1FC3AE5A83E3A511ULL,
		0x1FAF63691B8667C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A1524A35AEA0A4ULL,
		0x510A708572682B9BULL,
		0xD45341F26FD04D1FULL,
		0x692731A0DFB161A0ULL,
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
		0x97FF6457F317EEF1ULL,
		0x30437E74F01130A5ULL,
		0x7F95F9DE5D568358ULL,
		0x96EBD9E32BB931DEULL,
		0x85462D635BC2096CULL,
		0x0D98E3C789B27BC5ULL,
		0xFBC3B6EEBA231A04ULL,
		0x5CAF5EA31F296541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606A211791E5570DULL,
		0x34F54E13608F8FF7ULL,
		0xDEA3214DFE8C5FF2ULL,
		0x58F3E619CBDE39A9ULL,
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
		0xCE6F7255434064A6ULL,
		0xAB1D012DD5E6BD68ULL,
		0xA5805FFAA7FDB7E9ULL,
		0xBB370F3F51F2A411ULL,
		0x4166BAD915924FBCULL,
		0x08A663C46A95B452ULL,
		0xF92422DB0EF335C2ULL,
		0x28F7D0CA652D24E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83AF2E8E76F83B85ULL,
		0xF3CFD055A81F819EULL,
		0xA0DD8C7EE017B2B6ULL,
		0x50000D4A56A61D76ULL,
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
		0x80DEB9165417A90DULL,
		0xCF28E03465AF9A9EULL,
		0x22931A5F1A3A2DF5ULL,
		0x8EE3BEAE30BFF644ULL,
		0xCCCE1C34FD436169ULL,
		0x72F034248DB69FFFULL,
		0x08C1FFF15E962DA9ULL,
		0xEAF2AE634960AE87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE776E8F3EC1823D5ULL,
		0xDED09DA16ECB5A96ULL,
		0x6F5F18332484F51CULL,
		0x6EE9A16B1519DE4FULL,
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
		0xDBD4959660A3EF38ULL,
		0x94A8AD8F5C37F7D9ULL,
		0x624A0ABFBF9DB515ULL,
		0x0A96CF3AABF4AD46ULL,
		0xEA3E7EE17CC0DB9BULL,
		0xF7AB8894AF180D75ULL,
		0x33B6E8B52400F3A1ULL,
		0x217AFC41DBED2CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA11B6B0EE54488F8ULL,
		0x581EF3A159C9F75AULL,
		0x0F7095A317C1DF20ULL,
		0x02D8410151295136ULL,
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
		0xA5411069D34C360DULL,
		0x78E4D1AC428B7F36ULL,
		0xD63D663EBD8B3D24ULL,
		0x866F724395C1FFCDULL,
		0xD6D6B9293E502F88ULL,
		0xC573DB6CA23442B7ULL,
		0x4453344ADE208D09ULL,
		0xC41288592E2D81CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89208C891333489EULL,
		0xC81763CC564D6680ULL,
		0xFA97295BB6602C97ULL,
		0x212FAF8070834445ULL,
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
		0x90CE36D6CDFF2668ULL,
		0x0867A28C7D54E99FULL,
		0xCC63576433F3ADD8ULL,
		0xDAA2AABC5CE86B51ULL,
		0x0B4F17DFE9AFBA17ULL,
		0x5D19B9B2624AE833ULL,
		0x0B764FFECD627240ULL,
		0x3E9F42DD070D8E0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8BC2137E14C74EULL,
		0xDA39330714736133ULL,
		0x7FF33736B090A365ULL,
		0x2646978B68EB8141ULL,
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
		0xD10E617D7B48AF49ULL,
		0x93386E972EDBDC7FULL,
		0xB941D5BC5391FC1CULL,
		0x77128F84B0ECB507ULL,
		0x592A40F40437FE02ULL,
		0xBAE18895EDFA429FULL,
		0xD6AE816F50B8BF9BULL,
		0xAB0DDD45098B39E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D5405B61B98675EULL,
		0x50B2B4D88201C027ULL,
		0x97290C424EFE6D3AULL,
		0x5B2167C41B974CFFULL,
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
		0xD958E31CDEC3F5A7ULL,
		0xFDCB187DCD60A7A0ULL,
		0xBE9B6F03800267E0ULL,
		0x0ED94973DBC0688CULL,
		0xF1816E236B017028ULL,
		0x942E8CEC95063E43ULL,
		0x85E0BFC0C0BAC70BULL,
		0x0B8E35ACA421D99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB28F3C5EC0FA9BD0ULL,
		0xFCB4039BEC4DE5B6ULL,
		0x9DF7E5A01BBBF398ULL,
		0x45F5411438C6B5A2ULL,
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
		0xBF54D868468B3EDCULL,
		0x9B1ADA731E33DE08ULL,
		0x999072FD03FEAEFBULL,
		0xB239E9202AD09586ULL,
		0xFB37E242D32FE36AULL,
		0x07F4362BAE763C62ULL,
		0x617CB26BF2BA52BCULL,
		0x72F7C6F8854C637EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A06E539FA70331ULL,
		0xC95AE4EF03C0D4BAULL,
		0x1212EF030BA6F6E4ULL,
		0x43017203F4275A49ULL,
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
		0xFCB0657EAA64BC63ULL,
		0xE6FB6BBBC702F865ULL,
		0xE8FA3B1BC509A37AULL,
		0x8E4D87A13B6DE8BAULL,
		0xCA16439920BC1374ULL,
		0x210887B912856E89ULL,
		0x26B69A67418025C3ULL,
		0xFA10858BDFCB0816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBFE6E39864FA52CULL,
		0xCE3F913486D160D9ULL,
		0xA815266F7E0F3E71ULL,
		0x2CC15A6473911C04ULL,
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
		0x9D42214C4951970FULL,
		0x7B75B32DFAFF3506ULL,
		0xF5C292BBD969DEB7ULL,
		0x9F24B68231ECB1EEULL,
		0xE5714685372D6199ULL,
		0x8178BD95BFDE85D1ULL,
		0x197B2FA56DA6DAE9ULL,
		0xEFC7BEA7CF4B8DF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1299127A0E191DULL,
		0xB361D7687607122EULL,
		0xBE0BA54A202E5D60ULL,
		0x36CB036AF723C49CULL,
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
		0xE53CC3BE30FA3DB4ULL,
		0xBFB47BB0F0F8A63EULL,
		0x55E0DC43C52C0274ULL,
		0xD1565775ECDB3FF0ULL,
		0xE2068194923F355AULL,
		0x6A08306E7B463196ULL,
		0xF975D24B5C251AD2ULL,
		0xDD66E66B147ED561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7233FFCBE65C2E09ULL,
		0x7CEBAC173D6402A4ULL,
		0x5D5E137372ADFDB0ULL,
		0x2E9C8B5AF7AEEC7BULL,
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
		0xCB299CE6F05C0EE2ULL,
		0x909E4DE1FF5E4E4AULL,
		0x6ECF37F75BFC8CBEULL,
		0x1723B6D12129D19AULL,
		0xA5A43069EDCF9CEBULL,
		0x384C346BE0A15F11ULL,
		0xFE9BFBDB9E03C9C4ULL,
		0xD8E81209E2833235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6188CCA03D2D5E84ULL,
		0xEBEE15E557526AE9ULL,
		0x39F69A90D08C7FDEULL,
		0x49966448C0A3459EULL,
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
		0x5FB22647711CF990ULL,
		0xC6B0E9544EDAD810ULL,
		0xF8E10B34C4F0F18BULL,
		0x69C833EBF34836F8ULL,
		0x1E1B9CAB4F93A974ULL,
		0xE4453BD8C390FDB5ULL,
		0xDE1F76C41DB580B7ULL,
		0xF6CB6526A8A65839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7CB67B541082646ULL,
		0xA8F7CB81566080F2ULL,
		0xF18CAC512DE20CD7ULL,
		0x0BF937A8FBF94F8FULL,
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
		0xBD4128F1213B6DC8ULL,
		0x80CF25E5C0A7C8D2ULL,
		0x5FEB842D22464F30ULL,
		0xEE04DEC129D6B1CCULL,
		0x01960B09B8FBCB6AULL,
		0xA90B1C865F6DAB67ULL,
		0x008108C0985A9FFBULL,
		0x5C04F478A9FFAEF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF986CC62969BA1ABULL,
		0x987561D7EAEF3A1CULL,
		0x7312D0C3BFBA0E8BULL,
		0x16C128AA65CAAA9CULL,
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
		0x0A9C9741F3F0A87DULL,
		0x1F2A2E0FDD9F355AULL,
		0x9958D17773D08E26ULL,
		0x9A1B2B9DAF2DDE6AULL,
		0x6859097940CEE94FULL,
		0xED2A34FC96D37BEEULL,
		0x8560878C7F2E5246ULL,
		0xB36DEFB5975B4E27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D3FF4192A74E39ULL,
		0x536E0B8E41039ABDULL,
		0x65ACF05254B0C4ADULL,
		0x3C6CC09226BB7848ULL,
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
		0x8252538C9FA239DFULL,
		0x0996CF6CF28F2B44ULL,
		0x0AC848A50109AC49ULL,
		0xFFA10D63D947A02DULL,
		0x1A8810456268AF99ULL,
		0x8D17CB7E39FE80E4ULL,
		0x3C0617188E46199DULL,
		0xE76F876F6F1865A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7284BDD93B2C4FC7ULL,
		0xFB1F04298E564D20ULL,
		0xF3AFB64A1F7179ABULL,
		0x5A2F27EE56E6B74BULL,
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
		0x7273EFF1CA910B70ULL,
		0xD896A21336C09E0DULL,
		0xD46911E72874F6E5ULL,
		0xCED8CBE4D50DE93EULL,
		0x60FF025D4756BB7EULL,
		0x5999B92891057E98ULL,
		0x22A3A1E6E869316FULL,
		0x119842AA3ACE04D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD84E49CA6170E096ULL,
		0x25681E18BD9168ABULL,
		0xF8B31A2DA8124D6DULL,
		0x6B72B1298FA2A179ULL,
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
		0xEAC6D18D5DF2F0C9ULL,
		0xD62609F2C9067860ULL,
		0x4256B0AC601B1151ULL,
		0x174D137CE02BBD05ULL,
		0xFFBBD7C3682BF4B5ULL,
		0xE36E8515F002F7F1ULL,
		0x4AD4FD7C754CD16DULL,
		0xDD9D43ADD929C8BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A8D88ED479487AULL,
		0x988DCB346977464CULL,
		0x5DF45125C98227A1ULL,
		0x7CA51F4B1C5F88ACULL,
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
		0x8A410CA83772ACF2ULL,
		0x052B368C14A65378ULL,
		0x1E71BE6C2CF8FC2EULL,
		0xD3E1CF888B06B7E1ULL,
		0x99881E8373C15853ULL,
		0x3484C854FC24D171ULL,
		0x86985325F1EB9011ULL,
		0xD769FFAD0FFDE5A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5475942B6625CE17ULL,
		0xD0E0F329821D6A55ULL,
		0x190E160E15F05EBBULL,
		0x4D9DC338EAB6CF0BULL,
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
		0x5CFBF091AE8519D2ULL,
		0xC3022886FF8183C9ULL,
		0x0E0077E3C039791EULL,
		0x5A811ACF50CB93D0ULL,
		0x3F60A8CC77D0CF5AULL,
		0x36C7FC92F0551E99ULL,
		0x12FDF82B519A7179ULL,
		0xB3F560BB02063E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC554FEEB7783E530ULL,
		0xE4B1A656AC240E88ULL,
		0xDFB34E51DD26511CULL,
		0x10ED76919DB8DCC0ULL,
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
		0xB66841AA89A3F374ULL,
		0x409C08CDACD3D0EDULL,
		0xA4512A0C676B7541ULL,
		0xD365F3D552A683B2ULL,
		0x81478F0CB0B34E17ULL,
		0xED7A3ACF71EFE379ULL,
		0x3FE757F2A8604F9CULL,
		0xBC22E70A8B665452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7077D8CC4418F19ULL,
		0x80C0C398966F94F6ULL,
		0x20A8381165B7468CULL,
		0x40943F6603D707E8ULL,
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
		0x1240575E1502FEB6ULL,
		0xD6F6047E1EF69C7BULL,
		0x41C7C6E0A24F82C7ULL,
		0x0C0A18E9E2532F31ULL,
		0x96924A32B6A534C8ULL,
		0x9B92F3746BA71C81ULL,
		0x229310F82AD1E50EULL,
		0x720DBE5DAD13228FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF75AE53188D6D9ULL,
		0xEEC627C619C4D7B7ULL,
		0x639C4BB6FD7782F2ULL,
		0x7A145AD1932A5070ULL,
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
		0xA6806D5C331C13EEULL,
		0x94FA508104077EA5ULL,
		0xAFE9DAC2E5D18800ULL,
		0x407B0654605C6064ULL,
		0x7DB6393A362D3FDEULL,
		0x20F55A20F29CDAE4ULL,
		0xA626497559A5EFB4ULL,
		0xCC1AF4E8729F5FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F8CEC003DD39369ULL,
		0x7965B165074FFC90ULL,
		0x5998C22E34731CBDULL,
		0x0C7B60D564049619ULL,
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
		0x539261B50370B418ULL,
		0xD3119E086B96CDB6ULL,
		0x8AF989C061B99853ULL,
		0x2F04685E7C77C4B9ULL,
		0xE6D1B96456F3EBBEULL,
		0x52BA9CC8E380BE22ULL,
		0xF60C7755AA400002ULL,
		0xD01D7D0B4917635FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B3E699EBA5B6E6ULL,
		0x1AC4E3DA30B306E4ULL,
		0x10D34077A73998ACULL,
		0x1364F80B55F084F8ULL,
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
		0xF3AD72E85396B4ACULL,
		0x448FB3A9FDCA41CEULL,
		0xDDAC2B7E4742F949ULL,
		0xB2ADFAAD22C8C043ULL,
		0x8763D19CFD161D81ULL,
		0xD9F8F11083F4B149ULL,
		0x27CB4D50C109329CULL,
		0xA357DC3E8448DAF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C7E9035E4DF1975ULL,
		0x9F837C1D941C92B9ULL,
		0xC5D9A57AEEA07C91ULL,
		0x71B8ABF4C599413FULL,
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
		0x6C24C9DF84E91577ULL,
		0x9EF6C9580C1E14C9ULL,
		0x20B5A5F00E9D32D6ULL,
		0xC1827D63E59564CBULL,
		0x7583A6B7DADD95C5ULL,
		0x12795F4EE4F5E8D6ULL,
		0x738BA3454FC4CCD1ULL,
		0xB956D52B5620D971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDAF892A01CD54DDULL,
		0x5CFAEF0E089EA49EULL,
		0x476FE239E5D399DFULL,
		0x446621D2AE75ABA2ULL,
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
		0x41C8C9BEEAB4A5D8ULL,
		0x0C0BB7F9F330CC90ULL,
		0xD216BD401D0CD05BULL,
		0x517DAC7C92EC198BULL,
		0xF13EE1081B415DBCULL,
		0xA48A04F9BA344358ULL,
		0xBF0D7209C87C0A45ULL,
		0x0E57FF15E92967F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x111E30F2F668900CULL,
		0x7888750B96F2CBC4ULL,
		0x2E15AAB3DF7656B1ULL,
		0x728D89BD2F118852ULL,
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
		0xA9817ECA8A748144ULL,
		0x8F90E2230FD7950BULL,
		0x558C16CB0C8B2B6FULL,
		0x8273014DECE0E49DULL,
		0x5D655BBED5996790ULL,
		0xDDA000E224E51BA3ULL,
		0xE81C0B3F695D8105ULL,
		0x50246049BEC283F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x868D1D1E3F39E26CULL,
		0x755103B489D9AF4BULL,
		0xC9B5C234B06C524EULL,
		0x67D94C403DC07B69ULL,
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
		0xB5D32D777BDC26E9ULL,
		0x38CB51463FFC6A73ULL,
		0x41B58D18735A1BE8ULL,
		0xA36E26C4CFEFBE37ULL,
		0xE1F4804D3E859EEBULL,
		0x3D3D561B5569C608ULL,
		0x03E8E79D1ABD5415ULL,
		0x2E2DB0C39DD82CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x401E38EEC3B1BED5ULL,
		0x4FE61954EDAFCFC5ULL,
		0xD647EE6A6B74970FULL,
		0x7E3663CE3E066705ULL,
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
		0x42E47457578FC34FULL,
		0x52311FE9D7D5EBF1ULL,
		0x71636FFC21A34E63ULL,
		0xD9A7B3EC5C7B7633ULL,
		0x3560C71D4E07337EULL,
		0xF763089AE79BDAE0ULL,
		0x18AEBEC328936666ULL,
		0xD458B685F122E435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4202B0ECA16CC3ULL,
		0x0AE466E838F86939ULL,
		0x1B53C0F4278481ACULL,
		0x5ED2CBCE27A95615ULL,
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
		0x37401932233EA859ULL,
		0x792552428CFC9422ULL,
		0xACD7F9A7129FC1D4ULL,
		0x0A6EA9DE6052BE39ULL,
		0x867C404CBBBD84D4ULL,
		0x65F77E2B5F45CA2AULL,
		0x2A60C06D73E815DEULL,
		0x7F84BB7D3635D51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB1A49601606290ULL,
		0x9BE20CB2B1589672ULL,
		0xF73489E6471300D7ULL,
		0x78227E746C506067ULL,
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
		0xA3450454B21393EEULL,
		0x8FD89FFC42DFDFEAULL,
		0x9926AA2A5CC52B2EULL,
		0x23CA221E91FBA3CCULL,
		0x7D57307EC992A39DULL,
		0x562AC769688DFEC1ULL,
		0x2406E83ECD887336ULL,
		0x94C44A82E85C6D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E3637269DD7E080ULL,
		0x5A3239A1C7F3B0A3ULL,
		0xF22D237CDF06453FULL,
		0x38ED318D0FB3DBE9ULL,
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
		0x129E94834EC5F50EULL,
		0x5270D777F371973EULL,
		0x41F36A487B83A353ULL,
		0xA013B89FC6FCDDADULL,
		0x8412A1B030C9863FULL,
		0x656E795D6390716DULL,
		0x2B00CF64F778920FULL,
		0xFF8D4289979C180BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD6294AA8CAFE81FULL,
		0x60D6DB54BAE26D7FULL,
		0xA41233453769519CULL,
		0x0F0B990C48286F55ULL,
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
		0xB1B8E5E4FB2F6D0BULL,
		0x02A5FA1EEF06C5AFULL,
		0x082B381BCBD28658ULL,
		0x1F05D0BDC9FB33A1ULL,
		0xD95FB738A937E5D3ULL,
		0xF0BF821E1DD2495FULL,
		0xA90CB3F306BFB325ULL,
		0xC38E14BAF5CCC2F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5EE184E197B8EABULL,
		0xBF134A975C3DA9E9ULL,
		0x200DEE2ECC471DF9ULL,
		0x261CE47E4660235AULL,
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
		0x4E78C98738E560FBULL,
		0xD04DCEB46CBFA3D7ULL,
		0xBE84A1A56A4F14C4ULL,
		0xC4D05BCFE83596ABULL,
		0xE7974C8724871AA0ULL,
		0x40E070010175F7C0ULL,
		0xB1C7013B9AEE3ED8ULL,
		0x0702FE94FB747A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEEE2596A4F354F4ULL,
		0x719E6EDAA4426A79ULL,
		0x220ED07E69AC68DEULL,
		0x4F4225ED3B7FC2A8ULL,
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
		0x5F7003A812BBFF08ULL,
		0x6B6DF981EEF920C3ULL,
		0x13A694AF29BD5C34ULL,
		0xAF3A91BD914A3535ULL,
		0x82223D49B4E980C8ULL,
		0xD2FE272F8B97CB96ULL,
		0xD0343928A88D5F53ULL,
		0xFF7F96ABA579948CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0851C98ED65226FULL,
		0xBD27CA90A781591AULL,
		0xFB6710B82EB982A5ULL,
		0x1C2AEF382156421BULL,
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
		0x9569F27391E3C8C5ULL,
		0x32A1C2424BF6EFBAULL,
		0xA4C68BCAD832F8A6ULL,
		0x40FE8AAB9706613FULL,
		0x809015AE67A1E5ABULL,
		0x589F6298EF051B2CULL,
		0xAA0306A4B1DDB627ULL,
		0x9C31E18C74C58D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAACD2A56F3EBE391ULL,
		0x5A4A64F5C6B8F855ULL,
		0xE139883D3F1C027DULL,
		0x70660584EC59646CULL,
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
		0x8E839B5471537856ULL,
		0x8231080F063E86A3ULL,
		0x972F2373D05A7327ULL,
		0x4611B5F9F914DA69ULL,
		0x4DE7B1ABA0A5036CULL,
		0x4615A07AF73FC805ULL,
		0xEF1D311F7D75F691ULL,
		0x0076CE952812C5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE7FACE49D1FA5EULL,
		0xE966DA4FB9B6376DULL,
		0x15846E206FDD0CB7ULL,
		0x57B4601DEBDE3B49ULL,
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
		0x58AA3C698953A056ULL,
		0xEB84F1EE723220FBULL,
		0xBB8F548E2E9C4F30ULL,
		0xF08B6B3C33C3B15FULL,
		0x3C347621CFC1257CULL,
		0x01214C83F8799008ULL,
		0x071821F76C6D2AD0ULL,
		0x9863D634500517ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4873C56E5FFF343BULL,
		0x16764D85543D8234ULL,
		0xC9245F4846D0AA11ULL,
		0x0F5D3700148534C2ULL,
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
		0xC6927F4EFA1DAB42ULL,
		0x4178EE9807AB1874ULL,
		0x715E6AEF491F0A15ULL,
		0x8AFA02A34C0EC4D6ULL,
		0xBA076CDD360B0056ULL,
		0x74FEEDBBA7600D6DULL,
		0xD79EE750D967A747ULL,
		0xD0F2E05158D5BD5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63ACA824FFBFBCB3ULL,
		0x9F503872DFED16BEULL,
		0x72F4C0EF8E81DEB0ULL,
		0x0F074EB67BC8E0EAULL,
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
		0x1F7A579D3BC140CEULL,
		0xC177C6550918380EULL,
		0x7C852A880B6D4EAAULL,
		0x9FB4A6E03E953055ULL,
		0x88E165C1F43517C2ULL,
		0x451E836458A44B0FULL,
		0xDAC310CA46446276ULL,
		0xC091B7F662A9BF97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70EF72677BA2CBE8ULL,
		0x03FF473A317B5C5CULL,
		0xF579A88E7993EC39ULL,
		0x3555F572E3C7A0DFULL,
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
		0x3A284314659F6DDCULL,
		0x49EC405B2B9F6E3CULL,
		0x80FE6C950B3D7633ULL,
		0x5B2C815A13933365ULL,
		0xA500E97C784A260DULL,
		0x7414EFAA9C4B81FCULL,
		0xABDF51C7920A0E49ULL,
		0x0C86AC9C06F069F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB84AEB8E40A11416ULL,
		0x8507D3AE5ED4B9BCULL,
		0x04249034B8BB951AULL,
		0x372A20831B42EE75ULL,
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
		0xB22052057E3D0B22ULL,
		0x2DD8ABCB5E41415AULL,
		0xA30BAD507FF1FA67ULL,
		0x8DE0E401055083CCULL,
		0xF9345F55D7DE1E85ULL,
		0x300015034861E51FULL,
		0xB68BFF1ACA8F98F5ULL,
		0x8F979E147F8B6F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE678C389359611ULL,
		0x4DDBCA481CC94419ULL,
		0xBBD38B4A9142AECCULL,
		0x5E625B0BF4030AF7ULL,
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
		0x313A4C00BEB10DB0ULL,
		0x0A4098E79B0C9DC8ULL,
		0x817C2DE75FDF096EULL,
		0x1BD19DC18458B430ULL,
		0x8959E622BEDA42DDULL,
		0x31BD9D55E43C56F0ULL,
		0x1F4E52B22C865A7CULL,
		0x44E4B43FE96D206DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x949275291316FBFAULL,
		0x6C65F3A77C01857CULL,
		0x271C7459FBD077DDULL,
		0x55C45F3E2A8B8463ULL,
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
		0xE5408FC0C0F4EFCAULL,
		0x8AF04A5605C2938FULL,
		0x65A5AFEA25744C00ULL,
		0xAF6770ED4C04062AULL,
		0xE51DFBDAFB303FC8ULL,
		0xD27953768C2F7218ULL,
		0x627B3926462DCE73ULL,
		0xDE6CFA7427AF21B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B3F2420A1E6C73ULL,
		0xC8F2ADEED4CD8341ULL,
		0x03F02B989040F131ULL,
		0x33949E2B30030763ULL,
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
		0x9F918909152320D1ULL,
		0x662D2858BAB87875ULL,
		0xE128C5293CB18ABBULL,
		0xEF6F8AB0D78F3DCBULL,
		0xC72D2E314139D085ULL,
		0xEDF96D1CE789CB74ULL,
		0x76C905D9032E99F5ULL,
		0x769542878DA34EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30466458C3B8174EULL,
		0xB9335AA3192CABCBULL,
		0x82FFA35FB59C653CULL,
		0x09976ACFDDCCEA5BULL,
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
		0x00CEDAA27B261C21ULL,
		0x5591A5D92E49C272ULL,
		0xD5779DA69F6299F0ULL,
		0xF584234210BA99DBULL,
		0x45BD7E0B812C60B1ULL,
		0x2EDD677A069CFF57ULL,
		0xA13F49906A83C20EULL,
		0xEC1EE32B68217325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AEF9057A7BC7BBFULL,
		0x4A6F01F62997A966ULL,
		0xC4DC89166EF1680BULL,
		0x0219DBB385B1B171ULL,
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
		0xED19FE71F29915E2ULL,
		0xD887A0FD0879F736ULL,
		0xF79808F8B55C8D0FULL,
		0xF4D2F0F5E070C97BULL,
		0xA53C40CDD5BD72F0ULL,
		0x319791EA4F500ADCULL,
		0xAB1B57564A4B7FD1ULL,
		0x9D6B23BDE3C4BA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740B9CFFACB82912ULL,
		0x350749C4CE5B93F7ULL,
		0x5DA6FFC7BC91861DULL,
		0x52BA3F25AFA4799FULL,
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
		0xEB1D0CD8CEB7795AULL,
		0xC04AB3E664BD42C7ULL,
		0x5E46B4E35453C828ULL,
		0xDF104E738B383545ULL,
		0x6F39EBFB7C027AA8ULL,
		0x4D43D55828267ED7ULL,
		0xC3F4E47B09CCBF2CULL,
		0x6B6B7AFCF6791FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB6142D3715B0BDULL,
		0x385C5EFC5A7416C2ULL,
		0x74A09F26C8B828BCULL,
		0x510490002132ECA0ULL,
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
		0x96222C3E39D0974FULL,
		0x26EF530B7A422BE3ULL,
		0x566DBD05AB79E3BEULL,
		0xDB07BD3012C94B31ULL,
		0x26ADABE68E128A08ULL,
		0x9B028C568E05B584ULL,
		0x73CA5577B0EFC271ULL,
		0xAB198EC5A126CA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53E9B0775091185BULL,
		0x295027E48F1B1D81ULL,
		0x86766CC9EF10C09BULL,
		0x40D2EE85FE8B5B98ULL,
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
		0x9AF433A8871C27BDULL,
		0x9EB06338D1D3D863ULL,
		0x746C78B4F48D6D28ULL,
		0x824159F6AE1B8DE9ULL,
		0xA0C5665A2E893090ULL,
		0x878CEECB09D699DDULL,
		0xF77C48715AE72904ULL,
		0xEC06867AAAB760CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7841650B6F796262ULL,
		0xBD9BD55C47AEAF49ULL,
		0x30DF398872DD83D4ULL,
		0x0B39502C0553EC30ULL,
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
		0x1CF44E98B832523DULL,
		0x7DE1C3A8716F8AA7ULL,
		0xEBD8B04F3365BAE2ULL,
		0xEA0584F8DEFB4FB1ULL,
		0xE3FACE3A7E91BDCAULL,
		0xEABC73CEC68CD1B3ULL,
		0x3AF0C67EA7BF8E15ULL,
		0x7996F1A31448E8EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42EEB4781D480F8ULL,
		0x55DAF459EA56AB5AULL,
		0xAB96271C19D4D223ULL,
		0x766D632DE1CDE30EULL,
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
		0x3500F75AE90A2E43ULL,
		0xD157088EADEC1298ULL,
		0x89570FBE67057AE0ULL,
		0x68C32C44ADBEC2C0ULL,
		0x2BF591456A50E906ULL,
		0xE16F2B618E280BBFULL,
		0x91D09CA82346CD8DULL,
		0xED0A95C0A598BD18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7487A8B10CCA6CULL,
		0x47D77909C7DDD0F8ULL,
		0x2E4E50B3A387FDF0ULL,
		0x185566DD426AD466ULL,
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
		0x82C05A0D4798D7EDULL,
		0x0FA9EBC6DEC25777ULL,
		0x3F25A4C7601E453DULL,
		0x08CF3BDFECA327A3ULL,
		0xCBB95E96BE2BA945ULL,
		0x94B89A350F9049A2ULL,
		0xDF7BFAD3FEA21B9EULL,
		0x9161979DBFAEB211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC044646D8213FB5CULL,
		0x2310CFA72E2D45A1ULL,
		0x6B8CE03F2C2E5EC7ULL,
		0x1D4BBD4A6091964AULL,
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
		0x5E736EC441BC6A1DULL,
		0xF13F84B4A193FACDULL,
		0x0589385DE5CEBCB2ULL,
		0x062976BA25CF66FEULL,
		0x27A47594ABA80DF0ULL,
		0x689D2CEE00D959E6ULL,
		0xB9637589137C6B6AULL,
		0x163B9F8380A9951AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40DCE2D5BCAE7C2FULL,
		0x78943008C1D752F7ULL,
		0x8A4CAAB6CA46AE7EULL,
		0x5303243F3EFB88F5ULL,
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
		0xA05B5EFC425BB61AULL,
		0x5C34F4836F37DB84ULL,
		0x1836B1A8ADAE3C82ULL,
		0x675C30BEE9F600F4ULL,
		0xE8B861CA2E43D28BULL,
		0x4DFE06D3EB1CFE38ULL,
		0xD8E68D62AE25BBDBULL,
		0xBAF1EFA48D6616D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BB9E2FF206CFAE4ULL,
		0xEFE9F7F8558597F7ULL,
		0x4A6FAE4E87481F0FULL,
		0x2745C32BE71D654AULL,
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
		0xB4F1482933034F6EULL,
		0x23EFED3DA04BA552ULL,
		0x373A2D0ACFB7313CULL,
		0x7BACD4A61E88F0C1ULL,
		0x2E5065FD447549D9ULL,
		0xEA0F7A6E27133493ULL,
		0xE5F30D03E94C7CEFULL,
		0xD048521A24394FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E06BC15C6C4A3EULL,
		0xE23C19976D25732BULL,
		0x594E1B9F7111BCD8ULL,
		0x666904877F0AC2C9ULL,
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
		0xD6C38F2BAFA5624DULL,
		0xBC66E7C48764A302ULL,
		0x7B2FA750678B2C1DULL,
		0xCED852F780861BEEULL,
		0xD1E31F2B6405C5C0ULL,
		0x684A4CC5C629600CULL,
		0xDC286B17026DFD6EULL,
		0x420F316EAFF1B774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7A2F9C8880BE5CULL,
		0x376E4D1FF188E4E9ULL,
		0x292F8CBAC3DECA81ULL,
		0x1D19A9659E675747ULL,
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
		0x9E9FCBC5767527A2ULL,
		0x6F69F1EC543978E2ULL,
		0x457F38D1089F630FULL,
		0x0FD5067F2DEBDC67ULL,
		0xF81F9B6A7EAF6AEBULL,
		0x90AFA729D9ECFD1EULL,
		0x7C3885528CF3EFA2ULL,
		0x37417FA647D8C1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7350DD94447F07B4ULL,
		0xE97CC222AD670B7BULL,
		0xB5E30311F4D4F530ULL,
		0x438DF92DD8189E87ULL,
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
		0x8550A0A436511634ULL,
		0xFA60A98CE150C14EULL,
		0x89808EBF402AAE22ULL,
		0x43BBDDED55315350ULL,
		0x878296C9ECA3B1ECULL,
		0x2928994383E90050ULL,
		0xC25D2CCD61835E16ULL,
		0x2E6092DD9C8DC089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2B3029D569D8046ULL,
		0x1667699275E6CD42ULL,
		0x6355353BB9AAA56DULL,
		0x2611AAD2923BE7C3ULL,
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
		0xD294B0424488512EULL,
		0xBEA6ED6BC499F36CULL,
		0x815EFE6CCB26D219ULL,
		0x682250D057E9253BULL,
		0xEBE93C3BF5D1C7C4ULL,
		0x52951A4BA256ED37ULL,
		0x5268EB0666EC3AB8ULL,
		0x1017BB7FBD19722DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD733A128C1ABF8A5ULL,
		0x00C8D4A5DD8129B9ULL,
		0xBCF1E16012378976ULL,
		0x4BA825C669B017F5ULL,
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
		0x86899E5DC1CD9B9BULL,
		0x8CC35A87A101523AULL,
		0x86860139ED4E9FB1ULL,
		0x53C0CD8B5BE5CEC9ULL,
		0x34C16AFFF001FABCULL,
		0xA6E712C120A549A6ULL,
		0x3C05078E8C1592B0ULL,
		0xC9EA345B44CC4382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B3F805B6218D7F7ULL,
		0x53102332798A40E6ULL,
		0x6F452062B88265EAULL,
		0x4C8493179237D41EULL,
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
		0x95746D0BCCC9D503ULL,
		0x87C95312A4F8C9BFULL,
		0xD0923E57DC068921ULL,
		0xF4D01F89F9BDC994ULL,
		0x5837A72EE3326FD6ULL,
		0x1CCB861AC131C101ULL,
		0xB471A5CF5850F6CAULL,
		0x9A202EFA28C9FCF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB73E0186467244ULL,
		0xCDFF3B0B525B6FF2ULL,
		0x9970DB1EF80B2B21ULL,
		0x559718AC07B9560DULL,
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
		0xAEACCEE7A860795FULL,
		0x44E7F80E2D634FF2ULL,
		0xB0386145BEEB0D46ULL,
		0x7ED423FEEEC88B81ULL,
		0x7426775029F29E89ULL,
		0x8D7CEB7560157C8AULL,
		0xFE738CACA1A800F6ULL,
		0xE78A7CCEA0E6B553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6284CDE26406D4ULL,
		0x4572EB7A7093CC7FULL,
		0x755F42E5BDDB31DFULL,
		0x5D62AAAAD10775F9ULL,
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
		0xE54774BF7602DDA7ULL,
		0x9FD1103FF6F1F78DULL,
		0x867A0ADE433E533DULL,
		0x90182C7D8BBB203BULL,
		0x5AAED5B881F518B0ULL,
		0x2D5917F48ECC5674ULL,
		0x944F11CE1C540A24ULL,
		0x818A2D25B8D0C123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B3B2E22C0648AACULL,
		0x5B0A9E8D2946CCD3ULL,
		0x8A36AF7677B7D49CULL,
		0x4A9AE016FAB7CB83ULL,
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
		0x861A06CED5048840ULL,
		0x0480529DFBC74537ULL,
		0x0417C56177E394B6ULL,
		0x52D65638B1BAD126ULL,
		0x9F49E93E6BA48F33ULL,
		0x4DE9B9B936392493ULL,
		0x2CB0DDEBD51E1DE6ULL,
		0xFE1E4898C98A700AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B12A612CF71CF76ULL,
		0x9531E41C0842B321ULL,
		0xA658B6631A5C04E5ULL,
		0x0B551CE69C4772A8ULL,
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
		0x1D761C5E11CF9B2DULL,
		0xEDD48A12160FDB66ULL,
		0xAA8735D0916962DDULL,
		0x3F3B2D5D0C552E2FULL,
		0xBBB06A8EB996BC3DULL,
		0x6498739D07F49985ULL,
		0x3E25951673F7D3D9ULL,
		0x05E7DDAA1E6D3E81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A5ED8D9E2F8C61ULL,
		0xDC75B361445EA53FULL,
		0xE41B5725C832D522ULL,
		0x1FA6149D908C755EULL,
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
		0x004FC7AB5BE90EE7ULL,
		0xB76770841CF85B06ULL,
		0x2C310964C825FB4EULL,
		0xD53CF050B15E33FDULL,
		0x56FC615455F9EE68ULL,
		0xCD8EE53852D101BBULL,
		0x651E1E146A2C7C80ULL,
		0x697B2977D81BD1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C63A301F0274B7ULL,
		0x3A9D76E067FE9CD4ULL,
		0x2EA9806C8AC0766DULL,
		0x7D85181AC57F5DACULL,
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
		0x167776652860CCE2ULL,
		0xBA320272976A6AEDULL,
		0xA22723F61E63AE12ULL,
		0x56201DF66C6D2062ULL,
		0xA8F3F5B2288DB237ULL,
		0x10AC50D931C76429ULL,
		0x62E71017B8613611ULL,
		0x61A1D75F9C62C191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AADEED72D694333ULL,
		0x33C602AFFB03491CULL,
		0x5073877B7CD1B49BULL,
		0x54261627A315DBF7ULL,
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
		0xFCEAB4C4EEB3528CULL,
		0x4A67FF25BFE33330ULL,
		0xC4AF8B3467F4A2DEULL,
		0x3B06E0F5552F076EULL,
		0xFD0AB7F650EB12FFULL,
		0x66BC8D264CE50932ULL,
		0xCA8FCB1DE09F1BF9ULL,
		0xAD51E97A52BEA304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C820354F198282FULL,
		0x8A64F2D529E290C2ULL,
		0xD607B1A3BF92C9E3ULL,
		0x752F891D9D7B3A24ULL,
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
		0x3B397CE9016F2C02ULL,
		0xBAA90382A577B6C0ULL,
		0x8E620181B2983742ULL,
		0x50F202510C2E1FF2ULL,
		0x1519ED9DCCD439EDULL,
		0xFEAC52451A61BD64ULL,
		0xB8794C20BA2188F7ULL,
		0xE8EC57515C132CF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D12C25568EFCA4FULL,
		0x883D39C48FF9D39BULL,
		0xF0634E5D53928C12ULL,
		0x6406F864B706CBADULL,
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
		0x044C3F842F157EA8ULL,
		0xD33D3A3BBCBFA55BULL,
		0xEC64CB4BF9A534E8ULL,
		0x134B00223DAB0B3AULL,
		0xA7E3B3FAD3243541ULL,
		0x3EB7D0C4492197C3ULL,
		0x7ED429C5D8FDC3F7ULL,
		0xE8CDCB6F9E41423BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF018F6BF86756B6DULL,
		0x2286375E97BC2C65ULL,
		0xBFE2FEAA2F504B9CULL,
		0x21D732B3BB5AE00FULL,
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
		0x771632B3A2BE70F7ULL,
		0x1A0D4FEAB39528DAULL,
		0xA7B64467551C406DULL,
		0xFFC3DC97DAD66A3DULL,
		0x9B572B54112994B3ULL,
		0xDFB76E213F3CF91DULL,
		0x5F58E3B29C87A294ULL,
		0xFA74A0AB8F6353FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8606A12E2EEA892DULL,
		0x4F47A8DA16A2233FULL,
		0xCEE810EA913E6286ULL,
		0x2D13B60F2394E225ULL,
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
		0xE011083323BD0EB6ULL,
		0xA536554FC13CB6AAULL,
		0xCB11340DE0AE2A90ULL,
		0xA5C15ED8887E9CB6ULL,
		0xD301191B0B9B4C08ULL,
		0x01916B186EC7CAEEULL,
		0x2F3E24BEEEAB4AA6ULL,
		0x8715F3E0A1894488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323AC236DCCA5AF1ULL,
		0xE0CC3AF032E4D61EULL,
		0xCE4AA8654E1B3F34ULL,
		0x3303923082DEC8EDULL,
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
		0x2971C8418D77FD74ULL,
		0x348507890135E96CULL,
		0xB6E59E8010A6D96DULL,
		0xC89BADC6ACC5880AULL,
		0x26CCB10BC57A648CULL,
		0x5083082866E13EA8ULL,
		0xA92B90C8E5E0506BULL,
		0xF282E4BDDB85B1B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBD41000DDA2EFA7ULL,
		0x27F83D8846A53661ULL,
		0xD35D1C522FF2C95BULL,
		0x4809A1F5429DE901ULL,
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
		0x40969764FBF442B5ULL,
		0xEF1EDFFA030D604CULL,
		0x1CF8B7F2AEB10CA7ULL,
		0xC9FC587C54B4D199ULL,
		0x7E464E97C729BE5EULL,
		0xF6C12224B77A433AULL,
		0x221559DC90DC09A3ULL,
		0x42F3C6C1926009E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF0641EC8C268638ULL,
		0x8FC9F16D3F335AFAULL,
		0x2C240EB02F5A7AFEULL,
		0x3A2BD9380EF64A34ULL,
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
		0x677A41F9A8D3C3C1ULL,
		0xC6689873AB076D28ULL,
		0xC64BAA05F6C00FF3ULL,
		0x2C4F51D1DB637E0FULL,
		0xDC7D9FC835BDE2F5ULL,
		0xD61C3232A1978FE7ULL,
		0x7FF3F0C6F2873CEEULL,
		0x7686E9B7B7ED3EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x221FF9B1A30376B8ULL,
		0x8E980BF7A786C993ULL,
		0xC481678DF6D31B67ULL,
		0x44560317289AD316ULL,
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
		0x160FD0BF5FF6BACFULL,
		0x3A537A589E812B95ULL,
		0x5849C5AF20E86900ULL,
		0x1A3A8E348B7F25E7ULL,
		0xCF93515CADAEC6FFULL,
		0x8533A8D548A14D8FULL,
		0x84F879AD47219280ULL,
		0x61AFAB553263E0EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5EDE48127E846D0ULL,
		0xFFFE8A016672AEEDULL,
		0x152BD567AFE42813ULL,
		0x1A4DFCDA06528929ULL,
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
		0x15CC715613D8A833ULL,
		0x26DC84702CE2D5BEULL,
		0x3B63FA4381447AE3ULL,
		0x618CA87B43311249ULL,
		0xAAB1E22A01EC9F15ULL,
		0x273C6944F7E66CC0ULL,
		0x6F43162BB4B48AA5ULL,
		0x81EB87D48C896CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C3403925CF84836ULL,
		0xF9D424ACF916FA57ULL,
		0xBF5944C054110F66ULL,
		0x2A82D2081F973EDDULL,
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
		0x42C127CA933208F0ULL,
		0x242BFB3A1116274FULL,
		0xD6BBAD904078E5C2ULL,
		0x260DD123D1F4934FULL,
		0x172C4AD907CCEF62ULL,
		0xC7601178493EE45AULL,
		0x12CF46399973B244ULL,
		0xEB2DA4F72962C2BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3544401BB9D96AEULL,
		0xBC6E9314F06C0CAEULL,
		0xA1801A1D07A55BF7ULL,
		0x0ED44DD3F69D7B14ULL,
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
		0x5CB9F3EBD1C3A1F8ULL,
		0x2AE3C7D167679A9FULL,
		0xE56E3C3EB274EC02ULL,
		0x4904B840F346823EULL,
		0x87A9E627293A7821ULL,
		0x58E6548DCD60615CULL,
		0xBB10669782C1954AULL,
		0xDEC07B8261C3BD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF21DBBF0717BC4ULL,
		0x5D1454DDE3B60E5BULL,
		0xA9DD76BC1B31150BULL,
		0x59970D9B76549482ULL,
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
		0x2E25A97657916434ULL,
		0xE1DA432F62914C20ULL,
		0x1D443E251F89B35AULL,
		0x910CA43D18BB448FULL,
		0xFB0FBB2A2AB77C49ULL,
		0x4ACEFC47AA6683C7ULL,
		0xDA676202B2A24856ULL,
		0x3E79FD9B8654A03FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x727B71B8AECDD873ULL,
		0xFC93B5D2ADC8DBCFULL,
		0x889CCA8BA3A07029ULL,
		0x57284953094B0E09ULL,
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
		0x3CE7D58A625A2E62ULL,
		0xC4297CFCC9B3A4F7ULL,
		0x5DB08E014F68DFB7ULL,
		0x5B5324623E7A56F3ULL,
		0x8393A4EB16292486ULL,
		0xF8DC0E846E9297C7ULL,
		0xD53EDD8C08D48F4BULL,
		0xE64C13A1B520BFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D2506FAC759F65ULL,
		0xB4D3A4A533762C94ULL,
		0x050570CA9EF624FEULL,
		0x0A9E0E632156D4B3ULL,
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
		0x2BD96D89985B51F0ULL,
		0x92041A4F082C1480ULL,
		0x872E8A1F11785421ULL,
		0x7E65E538BB4323F6ULL,
		0x1E6B0CBF7634439CULL,
		0x5AF3838527122C04ULL,
		0x602A5666A38B5C8AULL,
		0x95AAD038F4D99688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFBD51F5241D5E6FULL,
		0x1229A012D4DE9D1CULL,
		0xCD775D5B582810ABULL,
		0x35C0CDAD138F7C34ULL,
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
		0x009E8821ADDBC9B7ULL,
		0x297AA10C6923144FULL,
		0x35A5CBA9BCC75B67ULL,
		0xD954DD14FBE6B3A4ULL,
		0x8F3836B5D082E544ULL,
		0x923BFA0012C17425ULL,
		0x429C99B44EB89AC9ULL,
		0x639D52A50B2B5D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42F6A71EA149D41CULL,
		0xDE61BD0F31DA51E2ULL,
		0x18E49C6D6C2E5552ULL,
		0x22AF2194A4569416ULL,
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
		0x4CAA61676E801096ULL,
		0xF8061C785D29AF3EULL,
		0xF7F2717BEB39CCE4ULL,
		0x4DC8D04769A5334CULL,
		0x3EE348904436DAA4ULL,
		0x26AECDF493168713ULL,
		0xC732699197815ACDULL,
		0x3C2DEA28E5945653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26726D18EA48644ULL,
		0xB5F8AEC63281BC19ULL,
		0x896E1D18686D4758ULL,
		0x3C9992597DAA03BCULL,
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
		0x8FDA218084A24D4AULL,
		0x12A3CD95A28CF2D8ULL,
		0x63CC1DBFE39F489EULL,
		0x1BBFB5CA19F679B4ULL,
		0x4B7402D1DB4A0F19ULL,
		0x29518985AE5492BCULL,
		0xED2C446B6574CE14ULL,
		0xC9BCDA28E77C2EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3128CA711A08F74ULL,
		0x34BE376D831ABACBULL,
		0x985E45B0F2F5DF9CULL,
		0x0DC817DC7665706DULL,
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
		0x961780561E1C9865ULL,
		0xEB2B9F0DF4C49FFDULL,
		0xF1C8F1924041F857ULL,
		0x4F908EC21B56DE85ULL,
		0xA61F4D881E370157ULL,
		0xC295806D3C474EF4ULL,
		0xC4A7459B65B27F74ULL,
		0x3EAA8BB24262173EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EBD028A9A46CCB8ULL,
		0xCD5CAF44E75A584EULL,
		0x229D46A358C0E3ACULL,
		0x1CE14B37F5E651D7ULL,
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
		0x6A74100ED1D8725CULL,
		0x35F96FE77E5399A0ULL,
		0x7B2310E8F187DAFAULL,
		0xEF34D34F9F1F619EULL,
		0xD269A8AA591D9051ULL,
		0xDAFF84C85ACDF998ULL,
		0x4D65A060A892F71EULL,
		0xA82A5CA4F5E806FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA62319580C3BE22BULL,
		0xB7E725A4F8E6A64FULL,
		0xF838DF41F758898EULL,
		0x657E93CC1F906AC5ULL,
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
		0xC21CB151514CC11BULL,
		0x6F653A1DC5603B46ULL,
		0xEF6E64EABC46060EULL,
		0xEE2418D2CB6533D7ULL,
		0x4B5A26FF3947F421ULL,
		0xC1FD6D75419F80B9ULL,
		0xC2653787FF993DB7ULL,
		0x934B1B1EA3341524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17E7B33D1FB0158ULL,
		0x3B037985830D56C7ULL,
		0xCA74A31AAD052F55ULL,
		0x4B4A1F5F0520574CULL,
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
		0x2642D29F9E541B5EULL,
		0xEB1524ED1F9ADEBAULL,
		0xF62E32EC9490341FULL,
		0xCEE1C94CB05C6682ULL,
		0x21193499A73FF83AULL,
		0x6E298E24E5133F76ULL,
		0x672360FDE2D811C9ULL,
		0x3C0DF0450E140253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000A16E71D2F563ULL,
		0x45403E6720764A43ULL,
		0x456E989C40A2D806ULL,
		0x38F3738CC754BEE4ULL,
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
		0x877176C8C792721AULL,
		0x69E3BBD31FC3794BULL,
		0x5B12F2AF31461758ULL,
		0xA984561226282E35ULL,
		0xC77C0FBD1432A224ULL,
		0x282F057824D691DBULL,
		0x17080DDAF9F3E0E3ULL,
		0x891A3782EC64C541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23DBCCD9C7168690ULL,
		0x60DE8BA8979D1FEBULL,
		0xC64501304B797910ULL,
		0x036893813D1D75DEULL,
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
		0x336C14449FAF4F66ULL,
		0xA89631B484D7BA54ULL,
		0xB2CEA9F9D9AA0301ULL,
		0x8590A971FB97839DULL,
		0xE33DDBA0F636B663ULL,
		0x36788D6B85A6AA3CULL,
		0x15E7663D59388C47ULL,
		0x3AAB5DD2731221A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9AAE292BCE636EULL,
		0xBE7B2FAA5B94FF5DULL,
		0xF327D715180ED593ULL,
		0x3B0096AF104881F8ULL,
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
		0x5DD8B9B620E4ED6EULL,
		0x70CAF7E7D62587D3ULL,
		0xB84AFB9EEC5AFD33ULL,
		0x78E8BCEB1F2B0262ULL,
		0x5021BE9B166E9EDBULL,
		0xB445B91A8663721CULL,
		0xE14E58DEB22B9A30ULL,
		0xF3C75AAF0CCECFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42DB04BB7550875BULL,
		0x332471D7C8E87807ULL,
		0x29EC2CAD5ED3E06EULL,
		0x288032E705DDDC22ULL,
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
		0xBCC6E2FF550AD43DULL,
		0xF9B4F851D7E16ECAULL,
		0x9C3EB94DE923CC1FULL,
		0x7F2C825056C86166ULL,
		0x089DC3777A194F11ULL,
		0xB3448217894AEB85ULL,
		0xA06B00DEE0BB03C7ULL,
		0x863E896B1C35347CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0431E6BB74CC93BBULL,
		0x95E047D03900648AULL,
		0x6C20DA6344E65BC4ULL,
		0x6C74E83686AE2BE6ULL,
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
		0x4A44215D8B65BD40ULL,
		0x2FE6EF01F8F6F16CULL,
		0xE52ABBF6199650B1ULL,
		0x5D0FEBD0872F0EF4ULL,
		0x2EE5A273F6F9DEF7ULL,
		0x08347AB768BA2366ULL,
		0xBD0B2C8B1A23249EULL,
		0xC35399F8536D1C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x405A3E94347CDA38ULL,
		0x67B1263B84983297ULL,
		0xF4D3589BFACDC026ULL,
		0x5B78C6ACE961459CULL,
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
		0xF53D3C01B9C8A364ULL,
		0x607AE9D57BDD9DDCULL,
		0x40841FD48021B7FFULL,
		0x09EFE57F45451C47ULL,
		0xC39875813808A34FULL,
		0xA708AB744B14CB91ULL,
		0xC1E78717BF80A0A1ULL,
		0xD226DC616D72E259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDEAD300B10E5B8ULL,
		0x2BC45D18A0F3D57FULL,
		0x08E22D5AED398FFEULL,
		0x3BB49BF58452B59AULL,
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
		0xBF1F7289B01CFF3CULL,
		0x608C97519E87F508ULL,
		0xF974A6189C0A6073ULL,
		0xDFB78D32B196F0EEULL,
		0xC501F5DDA10FFD28ULL,
		0x5C1D5F9095D25ED4ULL,
		0x89965F4054C79373ULL,
		0xA3066C30BD91CBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD69F16F987C96E2ULL,
		0x0CE8C6C7DBC2089DULL,
		0x65C6C9A531AA4393ULL,
		0x12AB9C6ED53B2CFDULL,
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
		0xEC0FA8B04E966131ULL,
		0x39FB6EE2E2201619ULL,
		0x54A6BD20EC8E25C3ULL,
		0x9305A4F5FF4D12C0ULL,
		0x336239502143280DULL,
		0x389E61F8566F0257ULL,
		0x0A503C1DB158A380ULL,
		0xBFED879A00AF360EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA42A953E8E576DULL,
		0xA17DF9BFB69A6F0BULL,
		0xDC8FA9893FB66ACBULL,
		0x1047C5D2194F18D5ULL,
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
		0x761FB394B09FFE87ULL,
		0xF608A795CB99FC0CULL,
		0x4862F705F37CD806ULL,
		0x7048EE2946B122B9ULL,
		0xCF4E10A776B11742ULL,
		0x8C1899EEBFF9523CULL,
		0x77D0685717478D7EULL,
		0x68E21DA8F7DCAFDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB62C704EE974B3ULL,
		0xC1AF81064A9C3113ULL,
		0x115273F3681BD8CFULL,
		0x01D9553E11733D73ULL,
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
		0x5DDD0CB5CEAE3C80ULL,
		0xB3D52A6645B30554ULL,
		0x494828312CBAE85DULL,
		0x2405626F6FBA17E7ULL,
		0xADDDB5B9F24A0EB0ULL,
		0x2645A5C07F426D49ULL,
		0x6399519E3E8A4F60ULL,
		0x89342A5C5D3CBFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC6064FC5AC6DABULL,
		0x622BC4F9298F3E44ULL,
		0x120A45AE7542B0A3ULL,
		0x01C3AC2546BE908AULL,
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
		0x518FA61C2DC145FBULL,
		0xC62A2C3158787F29ULL,
		0x684E1FE2738880C8ULL,
		0x8404A64BA6F1452CULL,
		0x36708963CEBC9B57ULL,
		0xA55A6A634AC2D24BULL,
		0x82E55EB6B369987CULL,
		0x9BC3188BFC54422DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66440AECDDC05862ULL,
		0x5195F6EE7163B653ULL,
		0xD65A2F0115352349ULL,
		0x22FA4B131B7317EDULL,
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
		0x073B8CBD25C05E64ULL,
		0x4910F810CEA1FBA2ULL,
		0x954BD7BF882A7EFCULL,
		0x916440B1A356B1E0ULL,
		0xE76CCC0596B62AE1ULL,
		0xD5FE8227ECF8BF29ULL,
		0x775CE4C92963D6B9ULL,
		0xFBE57F59DCABEECBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6161D59184CAC15BULL,
		0x0CD849FDFB8E5BDAULL,
		0x4D15CD9BACFC5E92ULL,
		0x7575280864DC2414ULL,
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
		0xB5210AD97ABAA7A9ULL,
		0xA5A874127E35774FULL,
		0x5C108930B2ABE8DCULL,
		0x3B9FAADE6D370274ULL,
		0x83ED9F9F0D4A8C63ULL,
		0x7DEC5A9AC16D6098ULL,
		0x8C0774DD7D47711FULL,
		0x7F2123592EE321D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A66BC7573CB812DULL,
		0x56BDE70B3471CDF3ULL,
		0x252BE2114B46B389ULL,
		0x1A8AEA1B62EE078FULL,
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
		0xD6A3116B66E85D00ULL,
		0x5D46BEBD363E56DDULL,
		0x896A00EBFFF01FC1ULL,
		0x2781F3FFEC58D071ULL,
		0x87579A8E9B1E229FULL,
		0xAF8D334FAF571480ULL,
		0x5C4628177918583AULL,
		0x15D0B624957C3BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA402966D61810CULL,
		0x6C3C5C913D2B61F1ULL,
		0x3BD3F467F98D3877ULL,
		0x647CFD6E1CC9B729ULL,
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
		0xF11F1EEA65DDD84AULL,
		0x23C03CC4BB96F0D0ULL,
		0xE0AF9C8D38ACAAC7ULL,
		0xA5296F6F6A9A2E84ULL,
		0xBEFC583C589AC8FCULL,
		0x0B7A0B642B219A6FULL,
		0x90AE64C837BE2E4BULL,
		0x3887ACB9320AF958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A9437DF8CD7AF08ULL,
		0xD7DDEDA32293DD67ULL,
		0x5A9292457EE789EAULL,
		0x094D12ECD83B31AAULL,
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
		0x2206D4C521AB8FAEULL,
		0x03DEFD1901B11B0FULL,
		0x451D383A2E7C8A34ULL,
		0x5C219A6848F2DBABULL,
		0x21AE5E54715F6EE1ULL,
		0x23F7459F47241378ULL,
		0xF1F1EC1B46F150F3ULL,
		0xD444F0E5B9555F74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E8D54DF5D609C1ULL,
		0x5A9352BD910BFEE4ULL,
		0x2F064446B64E8E4BULL,
		0x5E5D5C81CB9F0707ULL,
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
		0xE1F79A0F2870ACA4ULL,
		0xFD90BB3F734D6454ULL,
		0x2F928D0BA5147FFAULL,
		0x88ACE84DAD020C63ULL,
		0x84568491A46FA799ULL,
		0xA6DBCBFB474570B0ULL,
		0x2F5DFE1E5C3EC502ULL,
		0x00779F7EB5FA332EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86CF47AD91038D6DULL,
		0xC231028C079C1E88ULL,
		0x3786458D5665BE5FULL,
		0x1A6E951CB025A53EULL,
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
		0x271AAE0D4B739F67ULL,
		0x6015396251E43CB0ULL,
		0x04702F35D1660158ULL,
		0xF5608C64421779EAULL,
		0xDD7F3B07B52CDA53ULL,
		0xC03450BC5C72C083ULL,
		0x1EDDDD75841D7108ULL,
		0x0F054F0D9802B518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07FD7132301C082BULL,
		0xE7D935580AECD043ULL,
		0x995F0EA76DC4C8A4ULL,
		0x302A4868D27E5B7EULL,
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
		0xEF09823D59217B16ULL,
		0xA912C12F09F7A144ULL,
		0x5DD01F5016E9033AULL,
		0x8E559164DA0EE00DULL,
		0x169F5F2F516FA303ULL,
		0xD003ECFF833A932AULL,
		0x310CD5F10313C0D8ULL,
		0x473725649D1031CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB1A3436FB3AF2AULL,
		0x89A7EF1C84A97984ULL,
		0xA5B7E1168BD7A369ULL,
		0x20851E542A764436ULL,
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
		0xF90A3B88F14A2510ULL,
		0x6FA7C6B674FA0E68ULL,
		0x6D8C0E6038ECB695ULL,
		0xA31C0ABDE76B7669ULL,
		0xD49DBA34049FC353ULL,
		0xA0760FB4EF1E4B37ULL,
		0x81D3D67C1161934EULL,
		0x0FD661D18BCCD8A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8873DF41A10123C1ULL,
		0x412E1B91F37938B2ULL,
		0xB2FDE4CACD689441ULL,
		0x7CEE8FD8A7D39E88ULL,
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
		0x4E7A900D20342011ULL,
		0x6CC2AA1E262A3D96ULL,
		0x9AD12F10452E1A40ULL,
		0xC99AA12BB9842960ULL,
		0x53D352DF147D5BDAULL,
		0x1EC15D411FC760C8ULL,
		0x5AA2FCDB92035666ULL,
		0xB39AC881B74027DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD8DD2A2ACFC66FULL,
		0xFD7681C8DDC29B52ULL,
		0x0F02B7A7F1ACED68ULL,
		0x7294646CED0A1416ULL,
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
		0xC4068FF8C9542FE2ULL,
		0xAA255D8051D8BB4FULL,
		0xED9D42E2D4AF35BCULL,
		0xA1A8A87D923B97C6ULL,
		0x60CBA84EB1DF931AULL,
		0xEF8FE238DD4D8A90ULL,
		0xC2C1A989866B7FEAULL,
		0x4CD68EFED0A24EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22418BA730840786ULL,
		0x3980F1F12B5B4CBEULL,
		0xD65C6D4CC8A4329CULL,
		0x0981E2508A534EEBULL,
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
		0x7E1FB57299C5DCB6ULL,
		0xFCE80771F29D3992ULL,
		0xE1874BD697593E19ULL,
		0xEF2D817BE9DF1790ULL,
		0xF15A0D826C855B29ULL,
		0x9198AB88E41C9071ULL,
		0x391EE52F0609DF37ULL,
		0x6DAFBDE065FEEAD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517DB6CEB5916752ULL,
		0x99917DC3CEDAAA7CULL,
		0x5C1D50D17CD06059ULL,
		0x3743B0CB0DB5F3CFULL,
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
		0xB82B0DA680BCB325ULL,
		0x4A313BABFB5FB350ULL,
		0xD47BBB3592B8560AULL,
		0xBE396E3723F6CEE6ULL,
		0x9B33F1FE6F259DE0ULL,
		0x2C8C9F8244CD45DEULL,
		0xFDFBF256BE4CB8F8ULL,
		0x5F7CFEA70C91790BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1E0F96B0052248CULL,
		0xE710E90231D8125BULL,
		0x87E1B415D21BCAE0ULL,
		0x6AC73B03018EC6AEULL,
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
		0xE60F6AB62D7892BCULL,
		0xC0F157564E0A1727ULL,
		0xEE3EE31395651F2DULL,
		0xC0183F61B678788DULL,
		0x717516C5C63FF5D5ULL,
		0x85B1ED3A582FDFDBULL,
		0x222D28A2E57706BFULL,
		0x207CA6A0C3EC0C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD70CC119AF7112BULL,
		0x995A8DFF652551BAULL,
		0x00F2EB41A5101F9BULL,
		0x1298FB3ECB824AD1ULL,
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
		0x7603CBE2F95FE7C6ULL,
		0xA077D65D9543904DULL,
		0x830DF21C2495F581ULL,
		0x727A53A212DB863FULL,
		0x5CE2BD5705B1BB94ULL,
		0x580E88EBDBE407D4ULL,
		0x0EF19998B666F0CEULL,
		0xE78CA220C9C41136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FABE6CDD1C1C4DDULL,
		0xB2A02960391CB9D3ULL,
		0xBAEABEC737DDB422ULL,
		0x515A648005F61445ULL,
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
		0xA3866A8A72B3F6E0ULL,
		0xD2E9592D02C85631ULL,
		0x4B84FA21CFDB3FA3ULL,
		0xCD3EE10E9B4A27A6ULL,
		0x304051F5480B49F5ULL,
		0x15976CD9E279AC22ULL,
		0xEA06B8A85CA27271ULL,
		0x86C681A890C0DB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD1294F32460F449ULL,
		0x07638184A0D7E344ULL,
		0x0884631F8FF83C6DULL,
		0x4EB6201417EABDADULL,
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
		0x8AA859C624BC4C87ULL,
		0x35D94622F188F5EBULL,
		0x5937874F838610F4ULL,
		0xA0007B35C8425FACULL,
		0xADFD4B1B4C3D87FEULL,
		0x389411388A09E0CDULL,
		0x603C5BEBD8D80CA8ULL,
		0x7661F120A5A32693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E417FD375DE7EE7ULL,
		0x9BD3D4876F005473ULL,
		0xA22D2C51B397F1ECULL,
		0x328A460E5E7A198CULL,
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
		0xA5B172AE3003D024ULL,
		0x902555F2549CEDCAULL,
		0x83F6B87F7E3946D1ULL,
		0xC56F40094B7053A8ULL,
		0x74A4D4400C621518ULL,
		0x7AAE660C98F76C42ULL,
		0x12FECAE738326966ULL,
		0x46C52BB425442A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF628F4300692F356ULL,
		0xC6087BD10956FFA7ULL,
		0x55C8D6D1D5B4EC07ULL,
		0x46B3BCC6D38EA097ULL,
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
		0x7BFCB52ED7F9B9A2ULL,
		0x8DE487A854732B21ULL,
		0xCD5481269AABBB54ULL,
		0xC411E794C53D911EULL,
		0xEA26F231841A92CFULL,
		0xD3749CDDD15E2604ULL,
		0xA25E027362FE3544ULL,
		0x33616BED34E29818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC4A88873EB858CULL,
		0xF133D095686CCFDCULL,
		0xE748DE474C67A38BULL,
		0x6487ECCA9EE024C6ULL,
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
		0x8C489DBE79542FABULL,
		0x397822D9D93728C2ULL,
		0x3C64F721631C8F43ULL,
		0x8101A7791ACC3633ULL,
		0x55B94CBC9535952CULL,
		0xDD62A2E507390A78ULL,
		0xF456EC61928430CDULL,
		0xA2F238C24FBBE83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45CA01BC9F4857D6ULL,
		0x161C50D8EBAEB69FULL,
		0x814C0D9D22BBCDD2ULL,
		0x30F61450F0B0AEF3ULL,
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
		0x25841CB499F41DCBULL,
		0x8A82BAE4DA0E8707ULL,
		0x7B86F93B901AA327ULL,
		0xFE7201D5C735E5BAULL,
		0x1FB1D92A444906A0ULL,
		0x737149F02FAD1C0BULL,
		0x32DEB63E8B66C5FEULL,
		0xFEFF5BD9FC15719DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9EA58FABCCB1F42ULL,
		0xAD53B48BEDC0B0ADULL,
		0x08960684415C06ECULL,
		0x5859A4313264C310ULL,
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
		0x69482F89A6EE63B3ULL,
		0x3C0018BCEA567770ULL,
		0xB52C68D5C6448E47ULL,
		0x421927B45F0D2C01ULL,
		0x75C4A3BCCD879871ULL,
		0x1B408CFBC3834CD6ULL,
		0xE740486FD3AF4E2AULL,
		0xAB8B77AC85089955ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4787D90290F0842ULL,
		0x4795061BEFD3DF45ULL,
		0x08B7296F324A2887ULL,
		0x38CCEB501E53EEC2ULL,
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
		0xC83C30F3FC4F3B8EULL,
		0xDFA6DD3E413FDCD3ULL,
		0xAA3BC40AD3001689ULL,
		0x07FA418DAF66FA5CULL,
		0xE3AA867B6FF23022ULL,
		0xF75C29751231A450ULL,
		0x1F1CD8652B8B9C9FULL,
		0xBE754373B99746D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x938C27469A4264C2ULL,
		0x9755049EF49E40D5ULL,
		0x4883E30F49B95648ULL,
		0x4D6244BB3BDB7DD9ULL,
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
		0x43E4BB55E2640763ULL,
		0xFFE846D3F628D670ULL,
		0x1D635CE03B0A0BBEULL,
		0x086145363033D8B9ULL,
		0xE90BDCDE17F5D016ULL,
		0xC8EF771A09A1D1C4ULL,
		0x23A3FC8321C0EC82ULL,
		0xE35F7D40AC7C340DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA7844D70E0EFA0ULL,
		0xD373F4B1642DF9AAULL,
		0x67BAD8573DAD2728ULL,
		0x488DDCCFCAA392ACULL,
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
		0x4D3B7924E26554C3ULL,
		0x928029BDB4C64A75ULL,
		0x54C5C220BF775A9DULL,
		0xFBDF5CC4D61990D5ULL,
		0x09369DFE1EC438BAULL,
		0x9C92AF45E8658723ULL,
		0x9A8DF133B3E3DF14ULL,
		0x954085FC317E9388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB56ECDD7385C3C9ULL,
		0xD0462E1E33D859A8ULL,
		0x45D78FCD734A77ACULL,
		0x237340342EE3771CULL,
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
		0x01B161FB359D95D7ULL,
		0xABDA27BCF589C0ECULL,
		0xDF0970D23E93FF08ULL,
		0xFAB2E3E807306D46ULL,
		0x5744722A9D9596CAULL,
		0xF4A58A7513A75AA2ULL,
		0x494513AEADDCAF7FULL,
		0x7C002E58B0FB644EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5DA544E99D1FAA5ULL,
		0xFC6CB51DE0613504ULL,
		0xBF4A5CC00D560C06ULL,
		0x62B9C5124C8150E5ULL,
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
		0xD509C66B9BDA2DBCULL,
		0x1BD731F93F2C48A2ULL,
		0x503B8DC79185915CULL,
		0x48A581B521E89179ULL,
		0xA77BC7636E4EA7ECULL,
		0x2262EE907B9DB15BULL,
		0x9EEAE0AAB6D3E9C0ULL,
		0xB604B44FBB0581CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1695F2DFB871EC6ULL,
		0x36869B6B98949C3DULL,
		0xE718E71EB4FA43E1ULL,
		0x4D58458AE4B9D64AULL,
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
		0x077C9717F2AE288DULL,
		0xFAFB1648956B9E7FULL,
		0xC21B1429B5C30036ULL,
		0x6F6794170A1170DDULL,
		0x8035FA87124A82E8ULL,
		0x3F9B778ABAC257C9ULL,
		0x9ECF4E41BD6BF418ULL,
		0xD5CC83A7555BA26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7FC724A9BD9BBDULL,
		0x6C0ED4E04E44A668ULL,
		0x54E0B1EBD3C93BD0ULL,
		0x2BC31EEDB5AB8CB1ULL,
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
		0x56FB9A9D7F17042FULL,
		0xECF95A2201DAE395ULL,
		0x393AE54C76FD5461ULL,
		0x0124E77922FBF407ULL,
		0xB7FC0FC8B2F1F9D2ULL,
		0xAD977B120CB3B769ULL,
		0x28E050392DFF7455ULL,
		0x88959F3D1AA536EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA665F2680F021C53ULL,
		0xB1759ECFE4881D46ULL,
		0x4A86CDC94AE89919ULL,
		0x475A8A8B17821AC9ULL,
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
		0xC98A719C502887A1ULL,
		0xC7296CBAB9FE297DULL,
		0x263A08F8BA9EABA0ULL,
		0x0F1B33E4571E191AULL,
		0xF32E0D55F4EC88C5ULL,
		0x20AD3E9866904396ULL,
		0xC4E5367CA1B54063ULL,
		0x2FBD69DD715E8057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2606C5EAB44D5E9ULL,
		0xA0E0B759F36831E5ULL,
		0x60401F78BB863A57ULL,
		0x2538EAC32B252621ULL,
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
		0x7FB62DF6FD6F0F5BULL,
		0xD2383B74CF3CB37CULL,
		0xB53ADB5A2304786BULL,
		0xF41B10B3B736F6F8ULL,
		0x3DDAAA08D4FEA0FDULL,
		0x7663ABFD2C5AB2E6ULL,
		0xEE3A737B79749A76ULL,
		0x3727FF61BD3D43B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2B6B469B3AF63FULL,
		0x6503C30964B341A9ULL,
		0x11E7FFAE2A536601ULL,
		0x240AF935CE4F03D4ULL,
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
		0x2D0DE5A1790B9F88ULL,
		0x2AE8CD3C5E8E9505ULL,
		0xADD5DCF259D3C75EULL,
		0x6548AD062262A627ULL,
		0x320A7CDDFA84128BULL,
		0x34020BFDA201EA78ULL,
		0x0F667917D9BD8F2DULL,
		0x188EEAC5E9222F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9C6E94A8A660C2ULL,
		0xE33694E26AD762DCULL,
		0xF70BD67CABF70813ULL,
		0x0A7F8666BD75B777ULL,
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
		0xC906D7C315E5A3C7ULL,
		0xAC006C7F81B25415ULL,
		0x7C33DB6EA4633BDEULL,
		0x02FF1CA513228FD9ULL,
		0xEF7D026385EBE225ULL,
		0x43C637B38B6DE496ULL,
		0x7BC684BE0B0B1BDEULL,
		0x0F7D2D2F087E3789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55953288F6E93591ULL,
		0xBB6CB1263402427DULL,
		0xDBAB8FA448095EDCULL,
		0x4F93D1A055DECE41ULL,
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
		0xF97402283689F661ULL,
		0x4309B7070C13995DULL,
		0x8DDAFEF26EBA2AF1ULL,
		0x1D23B72A68A15164ULL,
		0xBDEEF3181F7E71DDULL,
		0xA7CFAE727A47203AULL,
		0xE0B4FB103B3C0063ULL,
		0x4079D466B7F3F435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AEC17BCE34EDE98ULL,
		0x2BDD9C0532A26216ULL,
		0xE8B8435B39A239BCULL,
		0x2F393E69B6D79163ULL,
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
		0x40600AD86895E13FULL,
		0x17E2B4FFC64DEF9DULL,
		0x7F8015A83D9AB298ULL,
		0x00EAC027CE09B620ULL,
		0x8EE177561A130650ULL,
		0xCD55220FEE9C712CULL,
		0xF435C848E3F9B1EAULL,
		0x9B1708E1AF4640C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D7C1A04768D489ULL,
		0x9285C35D3186BC3AULL,
		0xBF7BD07A14AB1B72ULL,
		0x065611A7D2775382ULL,
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
		0x28BC82F6B51512D5ULL,
		0x8A135FFCBBAFDFC3ULL,
		0x13396E2B8AA16337ULL,
		0x85783BE634AFD78DULL,
		0x1C8BC60607253E93ULL,
		0x46E35D8A05368119ULL,
		0xB6D236997ECEBE7AULL,
		0xB6FF43672A13B996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657BE7DBC49C60BCULL,
		0x0FD3427981C7097DULL,
		0x366D88F45D51A95EULL,
		0x2F5C3D36739D63ECULL,
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
		0xA88E4DC110B98658ULL,
		0x6F72AC2497F01079ULL,
		0xF0E5D92647A004DAULL,
		0xF62BA334AAEE95B1ULL,
		0x7F67D57484865656ULL,
		0xA392CEAD53E431FEULL,
		0xFFAFFEE21EA51E60ULL,
		0xAD06D269A5915A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F7FD0CBCAA5B0BULL,
		0xB73D59DF0BCF7C40ULL,
		0xE505AEB6D4228732ULL,
		0x252EDEE33E81F3EBULL,
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
		0x9CCAC99FE717CE4FULL,
		0xBC42C8DA5E6429B7ULL,
		0x4367DD678E8D78B7ULL,
		0xA270E938E02E785CULL,
		0xA8B916DEFC494F04ULL,
		0xBCC73F72F7EA4DF5ULL,
		0xC7AA630F9C4EEC7AULL,
		0xE35A7BA18A6B47F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8442EB959F98DF3ULL,
		0xC1D633EB2B2BBC2EULL,
		0xE6B291B8C24492EFULL,
		0x61DF43336C1B268BULL,
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
		0x9198B766F10EF99EULL,
		0x275CF651CE33E14FULL,
		0x460F31C6E82FDB90ULL,
		0x0B3F1FF338E21000ULL,
		0x503B18A97C2F42ECULL,
		0x8D21EF908FF70D14ULL,
		0x7D59D0F03D98DB5BULL,
		0x3F8147CFF93AC09BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A5E608F6012E9FCULL,
		0x1A6685C72CDFD253ULL,
		0xE16435700CE06B27ULL,
		0x786FC8D2379AA714ULL,
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
		0x7CC3B12B36E66050ULL,
		0xFC6FB450D86823D5ULL,
		0xAC02221DE6126D6CULL,
		0xE2DC4BF435400A6EULL,
		0x6531120D5AFA5EC1ULL,
		0xD0BE73B01C7600BCULL,
		0x28FF358D039D5E13ULL,
		0x7D72A6177E776011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x820C5F26B81073DBULL,
		0xF8B4E07511EC3FCCULL,
		0xC1E4150C6F6E645DULL,
		0x01E0F370FAF84CFAULL,
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
		0x4B83DE71A9F9FC09ULL,
		0xDC7AC3EF685D8CBAULL,
		0xEA299D3F02B164D6ULL,
		0x1E014C2C76330195ULL,
		0xE6B9CD45E7E62682ULL,
		0xD1362E9575F42118ULL,
		0x84E1F6B9F74AD8C8ULL,
		0x92C3EE19FE4396D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1856D21623B686ULL,
		0xEA85AE1EEA9A766CULL,
		0xA3B43CD9B7CD92A5ULL,
		0x6716A408343B65DFULL,
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
		0x20530B7A615B5DE7ULL,
		0x904B0D6A45A37019ULL,
		0xFCB35D3337FA5367ULL,
		0x34C0365AF55CCD6EULL,
		0xD7BA78140ED95B3DULL,
		0x35DBB5322F92217CULL,
		0x89D9A91254DD91BEULL,
		0x6DA84DF6BFC08F7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2600DE74959EEB55ULL,
		0x8EE7F2DD555468A1ULL,
		0x730275EBD0DDF5A3ULL,
		0x7BBBC8FB6BF21A11ULL,
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
		0x5A3FE3E9BEE1DE5CULL,
		0x8DC786A4E0BE4CA8ULL,
		0xBE57DEE701EAA1C3ULL,
		0x147E172C14FB3B39ULL,
		0x672224E2E1AB7D20ULL,
		0xEA00427598F07C18ULL,
		0x4CE57C58325B1610ULL,
		0x792C06CAD5DF4505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9515D973E5673C8ULL,
		0x49D164199470B847ULL,
		0x286853FE7B6FE846ULL,
		0x11071947D41F7A03ULL,
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
		0x7327D9FB99CFD619ULL,
		0x59C9588500266F2FULL,
		0xEA581C9F0813A804ULL,
		0x9FDC362BFC8429A8ULL,
		0xE1A839AF18B7D4CDULL,
		0xFADD5A2EF43AF31DULL,
		0x133A8E2C07B7E180ULL,
		0x3C991874738235A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF22069F945196DF0ULL,
		0x96A4BB7D40E6859EULL,
		0xC50937282D5F2129ULL,
		0x1E95D77521D820C1ULL,
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
		0x508335A39F65386CULL,
		0xE9902CFB209EC9B1ULL,
		0x09F22CD777BE7543ULL,
		0xC97E707DB0828A20ULL,
		0x37941E201A80C376ULL,
		0x54D71DF820D7E5E6ULL,
		0x2D21A990E0F3E2AFULL,
		0xF80B3034F035E850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x907FAE678E824181ULL,
		0x817E9FD000AAE9DDULL,
		0xBCF15858DBF21B4AULL,
		0x1B27985958830606ULL,
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
		0xD4E55DE60E7F484FULL,
		0x6E28E0805AEBD828ULL,
		0xC84E7DC20FB80711ULL,
		0xB979C0F811E20329ULL,
		0x4711443D9EE44212ULL,
		0x965C5533086E8A57ULL,
		0x0BACCD9F5FB96F19ULL,
		0x39E5815DBAA3BF33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61757F0BA4611851ULL,
		0xBFDD86139B54611DULL,
		0x83F5036A453E84DDULL,
		0x518AF4E1C63064BDULL,
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
		0x1165AC50F6321334ULL,
		0x5CA112D6BAEDCF28ULL,
		0x52E3FF4F70EDF4ABULL,
		0x44E7591A96B972A0ULL,
		0x1AB1780632D64593ULL,
		0x57D733A4DEB60F41ULL,
		0xD28CF869D7B50C08ULL,
		0xCA6C77A6B8FD9B69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BD7D3C82006B7AULL,
		0x6692BD4FC9F412D2ULL,
		0x93D0DF0575CDBDE8ULL,
		0x51011BDA0C5E8455ULL,
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
		0xB6519160C2240DEAULL,
		0x5F3B4C930541B4CFULL,
		0x88505354D075B760ULL,
		0x7748D0B794CB8F4AULL,
		0xE415A37843EA6E37ULL,
		0xDD341A0D9D2719F6ULL,
		0x4318B24C0C20F126ULL,
		0x5AB6DC4695224F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9187D53AD6F06C15ULL,
		0x34F72A98590F8F75ULL,
		0x7DFACA9E9D598325ULL,
		0x6E6D8331B7E35F00ULL,
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
		0xAF6BED1D5DD20409ULL,
		0xEDD8A529B5662D7FULL,
		0xC50859C594AC0770ULL,
		0x2F970839A40975AAULL,
		0x2D665127D5A1B4F5ULL,
		0x2D645E37D0BC450AULL,
		0xE53F77C2F2562182ULL,
		0xE53CF3403EE68059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9BF90713D2E573ULL,
		0xAABEA172B1586D02ULL,
		0xCC7420B58D7500C3ULL,
		0x36A323C2FA408302ULL,
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
		0x830BA5437F2F7CFBULL,
		0x8AAF98B00E92230DULL,
		0xD31A4C4A08DEA225ULL,
		0xDF6A05FAE02DF5F1ULL,
		0xBA437A178C6E5989ULL,
		0xC986BE0363F66F21ULL,
		0x2ECC8785354AB9E3ULL,
		0xE07775774F4241C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x290FC4C25790CC5DULL,
		0x74AFCD30E526A20FULL,
		0xC5766A0FF1F639F5ULL,
		0x312575B0A403B982ULL,
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
		0x0ED78A34E5CD3F2DULL,
		0x3376528C26469EE5ULL,
		0x43FCEA49B3B8BF17ULL,
		0x25FABC48C0F2769CULL,
		0xC018537EAEFDA34AULL,
		0xB80A6E26C2B49064ULL,
		0x1ADA33E268C52861ULL,
		0x3E9B1F6ACF8D062FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9273EF02DF737D7FULL,
		0x8502AC4D0D140DD9ULL,
		0x40609DE540FCBD98ULL,
		0x710166238FE1619AULL,
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
		0xBAFDDAD6649CF5B1ULL,
		0x1AFD342EA34D2CA8ULL,
		0xC9734BBF589AC217ULL,
		0x05B0646500620B4EULL,
		0x26E62F91F80A54A5ULL,
		0xDD1F742423368B79ULL,
		0x29E1EEA0F2F6AED9ULL,
		0x1B372C9C744725EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8128EA81362586C7ULL,
		0xEDA8718BDD65E0A4ULL,
		0x00FCB7A36938B66DULL,
		0x0FE1039E42F1ACA9ULL,
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
		0xFDC7510ABFBF6C99ULL,
		0x6DB35E8BDEE54AB2ULL,
		0xB74BB1586500C30EULL,
		0x53C403C76A039B75ULL,
		0xB87BA0CE83147485ULL,
		0xD0F15BE3AC0710DFULL,
		0x9DE9EF0533A26D52ULL,
		0xF3A1405DD658A3D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60212FB234C8BDAFULL,
		0x7187025767F1CBE8ULL,
		0x28052C1E0F1CFD59ULL,
		0x7DB391B53B2BEC93ULL,
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
		0x4A2653929EA01BBFULL,
		0x68A7A0922908AD4DULL,
		0x2C120A8633185E72ULL,
		0xF2D48921A3C5C924ULL,
		0x64AB6FC22A1FBA24ULL,
		0x93B1A2B195412167ULL,
		0xCDC554B3776AD289ULL,
		0x50E07BA3A1A5A79EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B98EA64DF55BEF2ULL,
		0x5505C6EE50B3A2A6ULL,
		0xB75C9D29ECF39EDEULL,
		0x7426E36BA25CAAB6ULL,
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
		0x95FCA43BD96BC554ULL,
		0x6914AA11ED79711EULL,
		0x61E20626AE4BA363ULL,
		0xB5D46C7D9DD25FACULL,
		0xC21ACBC1CB32E2CBULL,
		0x00A48CF73D6D9D29ULL,
		0xFC4CC4646B9D5211ULL,
		0xBFA3556F8CE14DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F6E30002F973C4ULL,
		0x818196C50BBEC551ULL,
		0xD5472D0EA7A5D1E9ULL,
		0x28131B0C8743E759ULL,
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
		0x5E0A4F064D317532ULL,
		0x1792A8566138224DULL,
		0x63BAF708EB20B1A7ULL,
		0x8CE0AB9988D99ADDULL,
		0x55AEE0FC95CB3B16ULL,
		0x5255A198099D53C3ULL,
		0xBB3A0A22F01AFC47ULL,
		0x27F8BF2CEC728C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15FFB484895C3B5AULL,
		0x5048A4E7CE92914CULL,
		0x2E5878388F22243DULL,
		0x7BCD0C44A1DA6E67ULL,
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
		0xE80A2AF0B46B7B1FULL,
		0xFBBA166547CEA352ULL,
		0x538CC897A389640CULL,
		0xEBCC4503B23BB03BULL,
		0xAFD85847BB27C34FULL,
		0xCA6A1CE51D4DF5BAULL,
		0xB50A0E37E7EB77FCULL,
		0x8588E8CA69E60B87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022745967C527BE4ULL,
		0x077A6067A1611D09ULL,
		0x330AE4E4107D3393ULL,
		0x3E1ED30F6A616660ULL,
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
		0xDFEE209ED1155A8CULL,
		0xE84D790602458B71ULL,
		0xDD13694346F9B175ULL,
		0xFB969D41055255A2ULL,
		0x4FFF389F9EC549E4ULL,
		0x8A2EBA562E4C4E4FULL,
		0x207411D7CEA3CB56ULL,
		0x9D60A24A4B68A899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD08850625E55F4ULL,
		0x6B3D21D0E1992B37ULL,
		0xAE4E0F4BF349E04EULL,
		0x57EEB44836DB5C5DULL,
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
		0x36657F1EE19A119BULL,
		0xE565D9672B4E0A02ULL,
		0xA4C0D0E6058750FEULL,
		0xC2836D35F2B350A6ULL,
		0xC4697F410C40F5D2ULL,
		0x9FC3F110BEDDBF42ULL,
		0xA4854C18D895C513ULL,
		0xF8E941BB64FCD104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0E62C6B33E9458ULL,
		0x9C7BA1E380386DEBULL,
		0x108A1C962BC291E8ULL,
		0x35232F06F03A5757ULL,
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
		0x9E341F5B06C6FCC3ULL,
		0x9C55925CC87EB442ULL,
		0x1C8BCB02F57D87A4ULL,
		0x8DE0C0DE39140F62ULL,
		0x839B010E0CD59207ULL,
		0xF4BE42D7DB47EEA8ULL,
		0xF14A375213FC0C02ULL,
		0x4B544F2656651BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27364770EE7AAB82ULL,
		0xF0937E67552C2146ULL,
		0xED900131ECE75014ULL,
		0x3C64808F0C162F0FULL,
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
		0xF13BD26722F35CACULL,
		0x8FD0F26EAA4F1620ULL,
		0x251105B695011F4FULL,
		0x461FBDD655E9C79DULL,
		0x563024502B0AAF13ULL,
		0xA124190665AAE9D5ULL,
		0x174D44F4A8FBF4C2ULL,
		0x93A84F4884562D2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC61364D86895CC2ULL,
		0x7B2CA961C1ADCBCBULL,
		0x9A894207AA677433ULL,
		0x311B8299FAB47BDCULL,
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
		0x1DED716392380173ULL,
		0xD42BFC449DFFD7A0ULL,
		0x1BFC4FABA8C74087ULL,
		0xBBE418A252025324ULL,
		0x30599649DC9CC826ULL,
		0xE10565BB4B96FD51ULL,
		0xB3C57F1F89D1BF58ULL,
		0xA0F36C26EFFA4C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B39C05A517DBABAULL,
		0x3AF91611D66971ADULL,
		0xCB4D2E5A1DE9A7B9ULL,
		0x20062669F1299B3EULL,
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
		0x4C7070BBB76E66CEULL,
		0x6BDA563535DF4601ULL,
		0x6FE2FCC4EDE3E92AULL,
		0x59995341302EAD0AULL,
		0xBB4F27E4C6975A25ULL,
		0x110DCB276A68D396ULL,
		0x30CC361F57C85830ULL,
		0xC4328EB697A142C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A305CB131E5CC9AULL,
		0xF3E67E0F016EAE61ULL,
		0xAE33056BF5A1004CULL,
		0x791A825BB21E9629ULL,
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
		0x7B8B26E9E9EF0C0AULL,
		0x7D9B43BF4E6BBA5BULL,
		0xBB757D54484D185AULL,
		0x82712A82FC8418E3ULL,
		0x6F7944395FD0B928ULL,
		0x6016E2615E9159F4ULL,
		0x958648962E9E05A1ULL,
		0x3F9A5B0F4837E739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x078B476E22EA8963ULL,
		0xC100DE3357FF14A4ULL,
		0xED64439F33C1EE4EULL,
		0x735AAEC7B4D06B6FULL,
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
		0x59C5DB21C0614925ULL,
		0x899A20274B50099BULL,
		0x29BC8BDE154F6B5AULL,
		0x053303A28B0B9678ULL,
		0x12E3DDFDA2B5686FULL,
		0xD4A42A917F852479ULL,
		0x555F0DA6F240579EULL,
		0x5FEA708FE30E344BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2798CEC7E74ECBB3ULL,
		0x19F871C039137394ULL,
		0xD5D892A60ADC6CEEULL,
		0x41FFB8FE3F2759A6ULL,
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
		0x128CBFD2B1E15DB1ULL,
		0xB8FCA03EB36633DAULL,
		0x7854E36694F598B9ULL,
		0xC0DD52B0702D571DULL,
		0xC2B381248451A2E9ULL,
		0x5141548463AEDBAFULL,
		0x6948DAA873B8C807ULL,
		0xC868A3EDB9465055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF931EB3E55FF90CEULL,
		0xC8AF2BE57F5ACFF0ULL,
		0x19255867C26349CFULL,
		0x0065A7F9F09D43CBULL,
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
		0xFFDE66936647862DULL,
		0x509D90721F22512BULL,
		0xF4761833C52BC4A6ULL,
		0x495E42EDC94C149AULL,
		0xEB732E9CF01B6D49ULL,
		0x705BF57764057E48ULL,
		0xC590496D7F658C39ULL,
		0x71DB88B9BD022EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2F751DF0A59C189ULL,
		0xFE44002AF7F30FFEULL,
		0x47E0FE74AE3E952CULL,
		0x2FF48E7FD79F0D16ULL,
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
		0xDCFA5D01B9F99C19ULL,
		0x662621B8925778E7ULL,
		0xA0E37D2B17DEA4A4ULL,
		0x3D8E3BA9D509B061ULL,
		0x9DBAF8906CB92677ULL,
		0x1732427A054DF475ULL,
		0xE5DC40E889468CB0ULL,
		0x6C36D54BC44AF88AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46BB4271DD755423ULL,
		0xD79BFFD55BE9C25DULL,
		0xBF951FAF785786C7ULL,
		0x4DB1E4E8F82A94FFULL,
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
		0x340514BE7872F0E8ULL,
		0x59421354F4FD7555ULL,
		0x25CE85546C2CC774ULL,
		0xF4689294605138D1ULL,
		0xC353BCDC1C1FB15FULL,
		0xFC248FC03CE6D9A8ULL,
		0x1560D92A99792FFBULL,
		0x363D0830CC2E024CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32731D6AA5274658ULL,
		0xC6AF69DDFF41C462ULL,
		0x522EC1A73429E6DBULL,
		0x0177C9D2AF25901CULL,
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
		0x78333C0131D41F86ULL,
		0x2A44A973A8C92BC8ULL,
		0x8C0419D89E2A0104ULL,
		0xE88F8B2D68AFB94AULL,
		0x85FD6C2530253999ULL,
		0x3B097A73A760430BULL,
		0x6EEA35EA53930D00ULL,
		0xCDD09619BFD19EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BD14986575AB0D6ULL,
		0xEDACD69E81131F7EULL,
		0x02C81AA105FDEF0CULL,
		0x7585D2FFE1CD4F33ULL,
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
		0xE87330D729F6E160ULL,
		0x87ED02A2C4C585A0ULL,
		0x1A30EEB23B2E7173ULL,
		0x6B1E9DF561ACAA83ULL,
		0x94A0B1A863DB1C24ULL,
		0x4904A6AF2C686AD4ULL,
		0x9179891D811F8A58ULL,
		0xA144988842E67135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84D8FD5FC7D1248ULL,
		0x5E9DC0A35C45612EULL,
		0xB23B491365DCFA8EULL,
		0x5B4D422F4FE17876ULL,
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
		0xC024F2C242DEF4CAULL,
		0xC9D5E45F105A4688ULL,
		0x2C6AA132FB0FD317ULL,
		0x2DE93FDE7EFCD627ULL,
		0xCECDB523790564D1ULL,
		0xC3584244D52A0086ULL,
		0x818E1AF417788710ULL,
		0x8E22A31E3131EAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72ADD60639ABEEEEULL,
		0xC8EFBA96B4965A8BULL,
		0x6782A16E76F3DF94ULL,
		0x470D7659CC65A9FAULL,
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
		0xC5D7725AF04ED3EAULL,
		0x8B8DB3380AE50509ULL,
		0x1D92265A7F9CB7EBULL,
		0x3D77B00A6F1C3B48ULL,
		0x427AEB010A4278FEULL,
		0xC4EDE9AF8C732840ULL,
		0x9BBE0ABEFE81A86CULL,
		0x2F3E94BD8A54DF00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4165482762CCAA8ULL,
		0xC6DE6346E3FCFE93ULL,
		0x3BC7BEB446DBB810ULL,
		0x40C1C42CF7B5555FULL,
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
		0xC2A1161475189056ULL,
		0xECD4E5384DE955B8ULL,
		0x65BDE02A9369DC61ULL,
		0xD85EECCF9D85D766ULL,
		0x37B7FC06869A7E71ULL,
		0x080612B92991E0A6ULL,
		0x267BA16D3037734EULL,
		0xF148CF670D2137EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F07F0C70075A87ULL,
		0x1DBBACB47990AE65ULL,
		0x1C17D65FBBA4F9F7ULL,
		0x292DB61B9074244EULL,
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
		0x350AB38802858EC4ULL,
		0x04D6B02A425C7A91ULL,
		0xF6DBC5D607039692ULL,
		0x494A363973C5397EULL,
		0x1CD780F81FE5A299ULL,
		0xCC7A4322E4B03FE4ULL,
		0x1C476AA743559096ULL,
		0x6ACA18F5D16A5330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D07D85CBE9BB3DAULL,
		0x5EFCA7583485F66DULL,
		0x29759AAA05B70CF4ULL,
		0x2349EAB6898D92A3ULL,
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
		0x9B10A4309875F902ULL,
		0xD7AC560F438D5CBDULL,
		0x7162F3820FF2E2ABULL,
		0xA7D6D071FBE9156BULL,
		0x86A1154FF7D498B7ULL,
		0xD273C270C5129132ULL,
		0x2C060580C7B1FE3EULL,
		0xEE05E8A1B0A3900FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F9CE0F6204A971ULL,
		0x14DB32CC844EEA3DULL,
		0xFA47C49FB45E9FFFULL,
		0x7CB75872343077ABULL,
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
		0x5D837609653334B4ULL,
		0x78A068FE8B1265BBULL,
		0xE692B270E6930415ULL,
		0xE305825108EB472BULL,
		0x82129842EA887FE6ULL,
		0xDB8595DC9822DBCEULL,
		0xCAD5314D562B2C8FULL,
		0x83D25A98CE65A086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC460FF8357633D0ULL,
		0x0E74A7BD203F0662ULL,
		0x023803EBB0FBA170ULL,
		0x743EF4FFAC011B2EULL,
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
		0xBE60B1151C2834A6ULL,
		0x75249F35954851E2ULL,
		0x0094AAF825824540ULL,
		0x623630BEE31472CBULL,
		0x7CD5B7C3F81C3754ULL,
		0xEEA607620EE7DBCBULL,
		0x1B0CF7F0DA01327DULL,
		0xC257502769956DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4619F82BF0586F6CULL,
		0xE1C9B7C3CBB2F217ULL,
		0x048178B881AFC3F1ULL,
		0x3B2C16988F42C093ULL,
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
		0xF7FD46A54F8E5890ULL,
		0x805F9E1704C835F7ULL,
		0xDA22B691695BB6C8ULL,
		0x4862B0A75DB45C4DULL,
		0x180F2C60763E69DEULL,
		0x6F5CC96F8D994787ULL,
		0x818A107590FDDB6AULL,
		0xAED19641A670CF08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A3DDCF6DCD21360ULL,
		0x082584A60988D405ULL,
		0x14A12804EF0A4895ULL,
		0x3B7EFE6612731791ULL,
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
		0x2FB6103A0D9F2CD7ULL,
		0xE1EDE70FDFD4E3F1ULL,
		0x48E9A7759D9D028CULL,
		0xA24F3323D5D777A2ULL,
		0xA05B913B0C501CD2ULL,
		0xEC975B9C71F04797ULL,
		0x92A296418C44EC50ULL,
		0xCF3EDCF74ABABF6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4D9EFDE183789DULL,
		0x00658048C97F8472ULL,
		0x0D0BF5306FD81690ULL,
		0x65A3FFD8ED8FE20CULL,
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
		0x958442D4BC3FE28BULL,
		0xAF0C9F7376C344FBULL,
		0x6DA819D524DD11D5ULL,
		0x52354DE47ABFDFCFULL,
		0x843B368B314D7300ULL,
		0xE2EA7EB846108C1CULL,
		0xCC7BD01852BC9C5DULL,
		0x541C0715FB3D0CA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x364E5B7E0DBEF666ULL,
		0x5DDB6ECDDD381137ULL,
		0xC808FD716CDC47C5ULL,
		0x4E5E5B27C5CFC103ULL,
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
		0x44A42B1FDF76ECE7ULL,
		0xAC1F50B52A22CCA4ULL,
		0xFB6E09235EB20CE3ULL,
		0x5CDB4440F9CD239BULL,
		0x586AB72BC12FE604ULL,
		0x4AF0566FB52EEDF2ULL,
		0x14E981ECA355ED92ULL,
		0xF9C6A56CC119AEB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647B5B9E8C9316FDULL,
		0xCBCC254A0F1A1E9DULL,
		0x161752439D73509AULL,
		0x7057D265A39D1315ULL,
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
		0xC41553C72DB3DCEAULL,
		0x4F4EFD6E5BAD6216ULL,
		0x589F55495E393D75ULL,
		0x1360DC9E789166CEULL,
		0x0BAA61E6EF3BE64BULL,
		0x37FAA7992BA5C622ULL,
		0x61B5AA18D314C53CULL,
		0x74E4D606082C6DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F5FDC0EB0980E92ULL,
		0x9E83DE2AD648CB24ULL,
		0xD99694F8B34E8465ULL,
		0x6D58A183AF29B7BEULL,
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
		0x0333E18981C12C03ULL,
		0x83A82E4F13900FD4ULL,
		0xF8206CF232203110ULL,
		0xC3B0D44031B45357ULL,
		0x4E1212CCECEF5940ULL,
		0x9582F9798F4F07FBULL,
		0x79C87E863AEE73C4ULL,
		0x929D39E27E5C34F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E2ABF4AD486EDAULL,
		0xB519365A594B3F21ULL,
		0x0BE334DEF185603EULL,
		0x07076BDEF3642FA2ULL,
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
		0xFDF598EDD7E7BA06ULL,
		0xF547C9F3FC29722BULL,
		0xB6A0EED1F0EA4559ULL,
		0xB4B3FDC8788D36E0ULL,
		0x7E38F84012841A23ULL,
		0xF3E74CD97F1989A6ULL,
		0x00FDEDFC91D65F06ULL,
		0x22B099EF67DD238BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA6A727097839C09ULL,
		0x299D323CD9F3E0E2ULL,
		0xDC52424F96BC6062ULL,
		0x5AEAD751E3607D82ULL,
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
		0x585B16DA7A6E92D5ULL,
		0xD839D7720CF699D2ULL,
		0xEA57920C58827CD0ULL,
		0x44B791EAD3F3BB4EULL,
		0xC014DCEB6D5826ABULL,
		0xD8635C739196B7A9ULL,
		0x04AE6E85E8C1EA45ULL,
		0x1638E13104633C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB73E1CCB58450BCULL,
		0xF6F99099A955DD04ULL,
		0x9C3BF9ECE54B432EULL,
		0x1128FF317AAEAFC7ULL,
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
		0xE44B95B8E32E346FULL,
		0x60494B151B385EB6ULL,
		0x9226EA051978F898ULL,
		0x4ED2959EE39D6387ULL,
		0x40F77764E0AFE96BULL,
		0x912B2EB34D703FE2ULL,
		0x040C0BB206395E9DULL,
		0xEFFDD8CD18F37654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89074EB23D4ADF96ULL,
		0xECB239B299E1DA4CULL,
		0x2BF0A67205FD03FBULL,
		0x6E80C41097C0F400ULL,
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
		0x79B13F23284D01A8ULL,
		0x81855DD5FD320F98ULL,
		0xDDC7F7E791C1E206ULL,
		0x0EB47E98FB35C167ULL,
		0xF445498D7CD9D6CCULL,
		0x75F9FCAB1C2A7BACULL,
		0x66E719C27C049DA5ULL,
		0x703C9ED4A9FB7E01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBFA2A23B0A2E663ULL,
		0x04A0DF3C2B806B44ULL,
		0x2415CAC5FA714896ULL,
		0x37B4122A368A759DULL,
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
		0x11C828C5D57E1F2CULL,
		0x659916C3FBE93402ULL,
		0x9D0CD738D0249785ULL,
		0x61454383CB7C4799ULL,
		0x729377C50394864FULL,
		0xB3530AE599F489EEULL,
		0x07DC0BF499DEEA21ULL,
		0x9761E67D979BABEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13ABF0045D8A123DULL,
		0x03ECB4D8D635AD67ULL,
		0xC7B69D87A73B5886ULL,
		0x59CD7A284C97CD14ULL,
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
		0x0773A5453FA6E6DFULL,
		0x7CADD5884560DD3EULL,
		0x35544A5B1836016BULL,
		0x168B3DCFC72B907CULL,
		0x4EB37819227A8AF8ULL,
		0x2825F72AEF42EB46ULL,
		0xEC7AA5C747D6BFF1ULL,
		0xBDB0B375EE10A147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB61779005DD78BD7ULL,
		0x725085E7C94FC9ADULL,
		0x4F88E5EFC2167F37ULL,
		0x3EC5E1511DA38129ULL,
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
		0xFB593C0C3358C023ULL,
		0xA745973892C8BFD3ULL,
		0xB4EC3A6FC8C8B76AULL,
		0x6DF2CF177DE7EE22ULL,
		0x5272A81E95FE60F6ULL,
		0xF4CDFD0CCAD5841DULL,
		0xE1E6440045EE6FD1ULL,
		0xB621E8B6D0883677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385E3096771B28A9ULL,
		0xFDD9271EAE7A5C2EULL,
		0x3D1A527A2A2D5094ULL,
		0x76FB5A3A722003EEULL,
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
		0x30C294234B674F95ULL,
		0x4E4489D35BFA97A1ULL,
		0x58C4FF3BDF8892E3ULL,
		0x7B1068C45514046BULL,
		0x80E08259ABA8A616ULL,
		0x32B68CEA7C39D512ULL,
		0xB9B28CFD42D1B4F4ULL,
		0x5C0E2835A2D6722DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5215ED72C66FF8EDULL,
		0xD55D74A1CC903860ULL,
		0xE945ECD3CAA96F22ULL,
		0x252A60BA80E8F734ULL,
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
		0xE8FFAA82F6445DA6ULL,
		0xECB0A14C975D41B1ULL,
		0xDCA8730CEF93F5B6ULL,
		0x239C74E8102885C0ULL,
		0x4749F5295540C374ULL,
		0x5AFAA4CF70109D9CULL,
		0x1B932D778B8DCBE1ULL,
		0x6F2E89D0BD528EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DFA0EA59DE16351ULL,
		0x6DE5181739D4A6E4ULL,
		0xF48132CBA6A0392AULL,
		0x2484E9E42A69BB2AULL,
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
		0x9FD67441CACAC64EULL,
		0x5134E3C51B76F602ULL,
		0xBB0C27E2C388319AULL,
		0xD4728C7D618872DBULL,
		0x6C9A5901D80F8F2FULL,
		0x37F98BC3F94A560DULL,
		0x9630396484854D3EULL,
		0xFF815E1EC62A38F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEBFAA87DD1A0CFFULL,
		0xA03FA2DC1C7FBC00ULL,
		0x0634ACCE6F51A8D6ULL,
		0x41A6850ECBCCE7E8ULL,
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
		0x737C8CDE3C04B0AAULL,
		0xA7DCD8047929CB2BULL,
		0x34E590C7819249A2ULL,
		0xB5B3A3BCAA76D23DULL,
		0x27C7DC0AE8AA079EULL,
		0x6D77E127C52ED3E4ULL,
		0x449DA3577288F518ULL,
		0x8C0021B0B742043BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B27367CC541D53CULL,
		0xE7A843EBBE1D3F09ULL,
		0x644BCFC281E6AB42ULL,
		0x7DB8A3F7DE437309ULL,
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
		0x2DCDBD4CDE153533ULL,
		0x46D9557BCDBCE0B1ULL,
		0x982FF6740FC29FB5ULL,
		0x6BEA96F65748F8D1ULL,
		0x1FE42E6CEE29ACA3ULL,
		0xB1095C8ED5AE99ABULL,
		0xEF288E0C9EED3F39ULL,
		0xB4729A36283E4208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9ACA1783844D967ULL,
		0x8E3D12AF85A7B017ULL,
		0x18350C53A6FA0245ULL,
		0x34ED7B005086C625ULL,
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
		0x94B6D36B0087F605ULL,
		0x3718CFAC2CE554EEULL,
		0xC3E953FC7D57F354ULL,
		0x29CB77AA738B1FC4ULL,
		0xD39A1BE20BEA8C24ULL,
		0x4AAD0ED1336758F8ULL,
		0x61FC6C1CCE75F9BDULL,
		0x2BE167F675B96449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD96F6F8C558C454ULL,
		0x4CC902B9CE3C89DDULL,
		0x4F61604322DB056DULL,
		0x2D40E63FED1002A9ULL,
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
		0xAEB0852DDB61E967ULL,
		0xE3F7D98174BCFEC6ULL,
		0x088C6ADF5E8B2AC5ULL,
		0xA2405EE979C12E16ULL,
		0xDD48681BACC53F6FULL,
		0x7BD0C89450D123E8ULL,
		0x44C0A88C5ECB1D6FULL,
		0xDF73689A54C436A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x876FF94980A958DAULL,
		0x44F59F8573C85357ULL,
		0x3D256FB570B18952ULL,
		0x4D61E5D20EE14B10ULL,
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
		0xC2D66DB822A541B6ULL,
		0xA81764476E8FAC02ULL,
		0xB965DF6258958AECULL,
		0x7B7B36ED4DFEFF8EULL,
		0xE41F14F1784AE0D6ULL,
		0x505513A9AF4AB8CAULL,
		0x8B642616F51F9F09ULL,
		0xFAA43E9BA83B2817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F73898FFDC2A70BULL,
		0x94B84F7773A71A20ULL,
		0x6A4386CABB47264EULL,
		0x2FDC820846C6F30DULL,
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
		0xFE14976060C22AA7ULL,
		0xBEBD1F26D014A90BULL,
		0x06C4BEA4D3AD8EDEULL,
		0xFD8B533A3B880DF6ULL,
		0xACFBD1130AED1285ULL,
		0x1B353C0748EB2ED3ULL,
		0xB8FD4365EEF31E01ULL,
		0x12F89B753CDD380DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB75A033FFF2EAEAULL,
		0xC8A4083BA2FD9C77ULL,
		0x7C5CBFC64BC40308ULL,
		0x4E7266A1445E5FFFULL,
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
		0xE6D63C1F3ADB0B5DULL,
		0x513D5579FC41BBC1ULL,
		0xEE07FC6285AAFC6AULL,
		0xCB14D3C32DE77793ULL,
		0xAED16A0EAAE2C992ULL,
		0xD46C63CD953E7118ULL,
		0x0F606919217CBF71ULL,
		0x039ECA777C116639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9EBFA4C9884F72FULL,
		0xD95425FE2386856BULL,
		0x3657961D7E2F674FULL,
		0x54A6E17F987CA40CULL,
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
		0x68C3926326D2AE5FULL,
		0x2CD7286E05EAD4E9ULL,
		0xB402F85DD962FCC0ULL,
		0x9E28343C679F7A49ULL,
		0xAC32F120CC28CF8EULL,
		0x96C06F62C09E26E9ULL,
		0xECEBBD0A37206D42ULL,
		0x5D6F3287293ED8C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8535D4174E17F87ULL,
		0x8D67B1169D649B98ULL,
		0xDF0107E2083334A2ULL,
		0x7CA9B44C86F3A7F6ULL,
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
		0xA94CFA8C53F8A840ULL,
		0x10D54E6BFED8D208ULL,
		0x8A449E4100D5104FULL,
		0x874C357836E68293ULL,
		0x41B5034A11CB023AULL,
		0xA88F7F43BF6AC573ULL,
		0x465A099F6630CC9FULL,
		0xAD7EE39E67260DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2B778AF81B00B8ULL,
		0x1622327A68B22124ULL,
		0xFBA20BEA2C137002ULL,
		0x4821FEFB868C8EE5ULL,
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
		0x72FF3B98850099EBULL,
		0x801C8B3CA3A30F64ULL,
		0x27A6E61B20A1A029ULL,
		0x7A935C6ADB5A91CBULL,
		0x41D7480F2D1904E3ULL,
		0x3709FBA3CFE76848ULL,
		0x0D77F58FE8BAC1A3ULL,
		0xD681A6496555AA8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F3EDD936B7585DULL,
		0xAB97E58D7FFC8A1EULL,
		0x27755977AC5A5E63ULL,
		0x51D20B4FE611E295ULL,
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
		0xFFEE1F300102BF61ULL,
		0xA9A68C17CD6B1D4AULL,
		0xA0168626DB82E30AULL,
		0xD972FAF3E6CDE290ULL,
		0xB389ED1B14B27FF5ULL,
		0xE3320F719B7F67DEULL,
		0x1CED8F913992EE1BULL,
		0xEFCD32CEC62331C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA66751351381C317ULL,
		0x6314D6F4E2548859ULL,
		0xEB59D5B567523B2EULL,
		0x71E885A5500745D2ULL,
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
		0x57E1241C709A15EDULL,
		0x74E416CA6DC5FC6CULL,
		0x43E347CA0AA714E4ULL,
		0x60D3B11BBA07B01EULL,
		0x69891DE1496AB439ULL,
		0x7D02224C580039B9ULL,
		0x561D9201FC2A812FULL,
		0x8C5C67A43D0D81EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023B938D5670D981ULL,
		0x03352E1F7DCE8DF2ULL,
		0x0C46F41578F641F1ULL,
		0x368B137CCA08F8E7ULL,
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
		0x6123F069239F67E0ULL,
		0x885F66492183070EULL,
		0xE73E22B19C4279E4ULL,
		0x3FD92B48581073C8ULL,
		0xC360D7483EB259F5ULL,
		0x57698CCEB67FCA82ULL,
		0x582C4216CAD0AF40ULL,
		0x9CAC511A0E8D1238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6183E5227218C5BBULL,
		0x820A4CF8387B1677ULL,
		0xFDCFF213B73C7D71ULL,
		0x016D352681012825ULL,
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
		0xCA7E2F9F4C692CDFULL,
		0xA1BB8F6D099106B4ULL,
		0x51E8B0CEA755C0FBULL,
		0xCF2BFD9EBBC43A77ULL,
		0x90F8F4C60E0FCCA6ULL,
		0x759869D8FC60CE5DULL,
		0x4013C471ED540BCBULL,
		0x4D9CFF089E8A6E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F72850562C18F4BULL,
		0x165B45A27FEFA898ULL,
		0xD4D7D9B7E1CF812FULL,
		0x5479D8E64450A180ULL,
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
		0xBD3ADA401D277EAEULL,
		0x92777CB849F35AF3ULL,
		0x5259BD4E9AC76AD5ULL,
		0x9A2364CFBF7A472AULL,
		0x6AB8C3A79F4D4800ULL,
		0x3CD0C772A00310C8ULL,
		0xD8759D73813CF69CULL,
		0xF74311ED3CA6DEA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A7E521C2A0342CULL,
		0x997517BC0A67D8B3ULL,
		0x73CF1C73C9D40606ULL,
		0x4E180E06C03F53C8ULL,
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
		0xA2BB0A04B84609C4ULL,
		0x6A244BE37FEAF8A6ULL,
		0x51ED7398823D3A66ULL,
		0xB6DB071AD0BA7FFAULL,
		0xB21580E1BEF840C8ULL,
		0xA7594E30E1AE02D9ULL,
		0x087CFF191EBD5D12ULL,
		0xB92F79B75F30FE65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11EC2B87111FAB9CULL,
		0x4165E724FFBF64F7ULL,
		0x947B515312590B2BULL,
		0x33E71852F20042F9ULL,
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
		0x35FE41B7C76AF5B9ULL,
		0x598763AFEE77BA6BULL,
		0x5C0A9D505A21BDDAULL,
		0x49FB67376BDD6BCFULL,
		0x5238A907E59BBD28ULL,
		0x4B07ECF896034591ULL,
		0xD6697E847725FF0FULL,
		0x81CCC1EF25F6A585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6758E3DC890C8EULL,
		0x7CB4909632F40DFDULL,
		0x2FB364FA09C59A1FULL,
		0x0E6030B70E79FDADULL,
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
		0x15FF938061DEA443ULL,
		0x551B4AB6D06BC539ULL,
		0x1D53F53A89BCD1F1ULL,
		0x9F713E0CF72CA395ULL,
		0x457FF197D36E6428ULL,
		0xD20B4F73ECA65153ULL,
		0xA9EC262D54016821ULL,
		0x7BF6C3E13A361E9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66FD7009C4418505ULL,
		0x82C915EBF11BD795ULL,
		0x56619FF501F246F6ULL,
		0x0612517B9B352EFCULL,
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
		0xAC589B6E0232D227ULL,
		0xB74F945154ADD162ULL,
		0x01BBBB454023C0E7ULL,
		0xCAB00107E521FB2FULL,
		0x587C3F0FC26E6195ULL,
		0x529B2503575BCCF0ULL,
		0x75B21CE5F4E4D876ULL,
		0x3E6653A5C4DC2251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC9F7C4DE954FC1ULL,
		0xFA5712D04C4E3D0FULL,
		0x7A2C05679A1BE277ULL,
		0x0DE06BA31DCF1346ULL,
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
		0xC746074BC13B5B64ULL,
		0x8BA78F57C0320D71ULL,
		0xBF08B48286CB6D67ULL,
		0x55E0F0B4CBC8288EULL,
		0x6E77FEA41EB9FF54ULL,
		0xB63FCD502CB48722ULL,
		0xFF19BD53A4A8DD15ULL,
		0x393174F7B089260BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D15D3A850D7431FULL,
		0x9920093E62FE1C8EULL,
		0x9CDACEECF7DC3EA0ULL,
		0x53384D790023CE56ULL,
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
		0x3ED35E6857F7D194ULL,
		0x9BC72671A6982BD6ULL,
		0x6C934E7D523EC701ULL,
		0x71BF160706CA880FULL,
		0x4F8B22B33D364B1DULL,
		0xA67459DEB3AC0F9BULL,
		0x4094B3A156E7864AULL,
		0x275B54041256F3D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7A85036E06F8C6ULL,
		0x510C7D8052227CE4ULL,
		0x02A5F870389CB616ULL,
		0x494D8EA1BFB2B96BULL,
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
		0xFACACCB968BE6D53ULL,
		0x10AAA410853C307DULL,
		0x611B0B1DA41591BCULL,
		0x5637ACB7C54BEB41ULL,
		0x88454EDC22D8B008ULL,
		0x4EA612EF61406271ULL,
		0xD3D18E75256C2E8BULL,
		0x3C92CA3117BA6B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3514816694E88FD9ULL,
		0xBD517398F4CACD58ULL,
		0xD236308132247A69ULL,
		0x5401B0014AF7CEDCULL,
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
		0xFBBEFA3F75D0D542ULL,
		0xEC347CEAEFD04216ULL,
		0x20961455C49E749FULL,
		0x548D7530291878C1ULL,
		0x7F63604BCAEEB2D9ULL,
		0xE5E6A00FDD62F81FULL,
		0x24DC14874FC8C1C5ULL,
		0x3F3183A69448ECABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE47F457F953F62E1ULL,
		0x0C703F45CC8116C3ULL,
		0x9941206B9C6B3800ULL,
		0x35E6FFEA2BEB9A28ULL,
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
		0x9FF4ED93DAF2C798ULL,
		0x87E5BFD4B1F33BBDULL,
		0x45FC8E2AA2CDBE91ULL,
		0x36A57E89537F3632ULL,
		0x59AE1B46AF7B69DDULL,
		0xB9DF7E719D3120DEULL,
		0x42DA1D4DB5589DAEULL,
		0xD4C33565876E5400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFCCFA11E7448313ULL,
		0x1F1284B2073E1CBEULL,
		0x325CE7B38DF52681ULL,
		0x4B9F6B9B6DDFAE3CULL,
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
		0x331101565CDC6C87ULL,
		0xBBA45BFDCA4013C3ULL,
		0x42E25F4AEEEBB016ULL,
		0x084E7CD322A09A47ULL,
		0xE24796873017C2B9ULL,
		0x002DB87B278D7950ULL,
		0x4DB8748FAB58AA1BULL,
		0xC50E56FEC18CE90BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9B159678063584BULL,
		0xC26DBE45A94015C4ULL,
		0xCC43AC9E5E14F018ULL,
		0x486F66A3DD8B31F4ULL,
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
		0x691713243B12F8F4ULL,
		0xD6195DF51BC0ACDCULL,
		0x692245E5B65010EFULL,
		0x4ED81BDBA4F4F63AULL,
		0xED118F17F15FA1E7ULL,
		0xBA6AF00029E9559DULL,
		0x62D7B7BFDFD2553DULL,
		0xB06FB32314483597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B250B20F45051AULL,
		0x81F8FDFB5463624DULL,
		0x15278C60EF88B819ULL,
		0x7F6CB310A7ACEAB3ULL,
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
		0x3BA5EA5604974371ULL,
		0xA21D3BE732B59947ULL,
		0x08C82EE1BC20A0D5ULL,
		0x9AA377F270787932ULL,
		0x841328D471BF3BC9ULL,
		0xC679F4A4BA4AE9CCULL,
		0x302BECE18141302BULL,
		0x805FE2E9E4AA5DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67DF9DEE6FA262CULL,
		0x18378C5AD9D44DA2ULL,
		0x2F4D585AEBCDC755ULL,
		0x28DF26AA61C262AFULL,
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
		0xA7669F7C85D921C3ULL,
		0x4B8C71D2E09C3408ULL,
		0x75BB9D4B9AE0C38FULL,
		0x0BC49114E770E37CULL,
		0x19D3311EABACFED9ULL,
		0x8199CBFFBFBA5800ULL,
		0x5854A8A09988C7A9ULL,
		0xCA7D6DB15012BDACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CBFEA0A0186FA6DULL,
		0x8860B9C95645440CULL,
		0x924CA522652E66B8ULL,
		0x1A62D966CA390B11ULL,
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
		0xCCD3E6C70BBC8231ULL,
		0x3C090C2927FC3ECBULL,
		0x18E8F8E170D9298CULL,
		0x2E74CA04C639E7B4ULL,
		0xDECA101B58D8EF4AULL,
		0x1D6AFEBF844C2918ULL,
		0xD1E8B48AC071E46FULL,
		0x83006C2C9D8D10C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED24AD63BF00A12ULL,
		0x99EADC96CB4A587CULL,
		0x4173C57A01C1120AULL,
		0x2084D8A4292A655DULL,
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
		0xF7B022B00D931FC2ULL,
		0xD96E80B69028DAE6ULL,
		0xEB598C62FA58D489ULL,
		0x9D051269866374C9ULL,
		0xA51EB1A37727AD04ULL,
		0xEE4AC0D4782F51FEULL,
		0xC3478A5D44391B4BULL,
		0x38690300E2E6B277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3E80F3BD76CF9DULL,
		0x38872040672F06B3ULL,
		0xE7F8163B1AD2E1CFULL,
		0x7C9B848B34A1F290ULL,
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
		0x1488B83C6BE8569AULL,
		0x2A8DC7B8220EF2C1ULL,
		0x9CCFD8D54F538F10ULL,
		0x0CAAEBC6621DBCEAULL,
		0xA318B4517B4BDB77ULL,
		0x1BD657C1199F2B92ULL,
		0x26B9A619BD84CCBFULL,
		0x1609C8168F46A277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A337C54B92AEAB6ULL,
		0x4C5ECE61EFAF6A85ULL,
		0x5C5E80A77109F36EULL,
		0x521E9F1FA699DA9AULL,
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
		0x0AEB4B3752097400ULL,
		0xC2BE173111A92DB5ULL,
		0xE120E9925967C6E0ULL,
		0x44535A2A1B05C7EDULL,
		0x677469151FA4326BULL,
		0xE73CA275B3DD7952ULL,
		0x9FD838F1ABC01669ULL,
		0x2741BDECF41E2EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6632E45A0468F0C6ULL,
		0x15BE34A9C4892FF0ULL,
		0x9B395D71D7EB1A99ULL,
		0x18158B565780B4A9ULL,
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
		0xAE8DC3908EF21BC4ULL,
		0xBC38D657151B0B80ULL,
		0x40754301917E51ECULL,
		0xBE9EB27C0A12E8DCULL,
		0x20D7DD8123B42C88ULL,
		0xD1E2D86DFACE7DFBULL,
		0x8A6B6C4337DB981BULL,
		0xF21A257932C168B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E98A4BBDBB0BD5FULL,
		0xE3E4F6AA4FC1BEC7ULL,
		0xCC6754FBDC16E60DULL,
		0x2E80427992C87440ULL,
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
		0xC9894D317239069CULL,
		0xABAFA44E871E6620ULL,
		0xBE4AAC856733BEE2ULL,
		0x2BCEF8BA7DF4BEE3ULL,
		0x2D7C022AF5C36BC0ULL,
		0xDEA9BCFBD0D56EA1ULL,
		0xE1C3533B015C15E6ULL,
		0xB913362975098046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F19F91ED3B0931ULL,
		0xB8E1B1AF86CCD20DULL,
		0x414907479ADEFF27ULL,
		0x24A902E1DD5DC969ULL,
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
		0xD94243CA89BBA3BEULL,
		0xF025A253BDA26D0BULL,
		0xC5475B33BABFC83DULL,
		0x617546291619A070ULL,
		0xA1AEEC1D1CEA7FB0ULL,
		0x427E02CD9DCFBB4AULL,
		0xA57982C6773877B3ULL,
		0xD05CDCDE389A1429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD939501CD48A9C78ULL,
		0xCEDA0CD92A783A1FULL,
		0x5550C4A96D218CD9ULL,
		0x4F3E0F257CF89E9FULL,
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
		0x5A97015AB44C3B7AULL,
		0x0F61B74171F3869AULL,
		0x1B239B97652E60A3ULL,
		0x66C516C56FBBE921ULL,
		0xEC3912497D6FA788ULL,
		0xA1525276EA344E68ULL,
		0x7F8684E301AFBB93ULL,
		0x2F44D3A7E0C39669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B0FB84352DF1AB4ULL,
		0x0199F4E835B72A2DULL,
		0x091B5549A544388DULL,
		0x6AFC81B0CCC43CCAULL,
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
		0xC3B26B67A0D92F37ULL,
		0xCAB31D13C1D2A8C0ULL,
		0x611B20B3FEA6CF7CULL,
		0x4B552C13CBA44E0EULL,
		0x3DAC48AB72D669B5ULL,
		0x413187477EB8DB17ULL,
		0x27301A8EBD3E05D4ULL,
		0x3DAFC087D9B9284AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB4534DAACACE16BULL,
		0x780D31B091432E33ULL,
		0x323F11E415DBACFEULL,
		0x736BC03E1D204910ULL,
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
		0xA4289E49AAB1274BULL,
		0xCC52E4D0FADC32A4ULL,
		0x7C20EDE5E1F9D983ULL,
		0x76C33CC90F608232ULL,
		0xA6F4FAD58B9B8647ULL,
		0xAA5809DD0F641581ULL,
		0x5182DB2195162C28ULL,
		0xC5B0C6EA7623F50AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C85D9FC63C71A36ULL,
		0x15645BA143B763E3ULL,
		0x958D74E20344678DULL,
		0x4F00C39698B6E1BAULL,
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
		0xA49FE41ABA946784ULL,
		0xD21C138BECCEF5EBULL,
		0x0A2DCF8D8A8543E3ULL,
		0x53D0DF87DAB0B201ULL,
		0xA4556F5C9AF1B4D4ULL,
		0x6D124637C487A1BFULL,
		0x6F46131BB56DB539ULL,
		0xF28F7E32A4178943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094E6BD9BA754454ULL,
		0x02D27FD318F0F85EULL,
		0x8E94A5AA78CE2A6AULL,
		0x551D9B0C362F1203ULL,
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
		0xB9A7B0B8A53626ECULL,
		0x1A30B5DF9D2BB187ULL,
		0xECE6100CE2A557FEULL,
		0x7FBA514F935EBFCCULL,
		0xCABA953E3A823279ULL,
		0x66559C78FB95D735ULL,
		0x10AA17F88A7353F7ULL,
		0x5B3A0D9512C1223BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD159D7F55489A6F6ULL,
		0x4AE5EFD4F569A383ULL,
		0x66259EF16FC3CEB7ULL,
		0x0A5855705C09D491ULL,
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
		0x6644E032284C53C6ULL,
		0xE25AD0E9B6A5D4FEULL,
		0xC8E464DBD1C8D07BULL,
		0x5293EDE4C54B6534ULL,
		0x4C3D1043691D671EULL,
		0x402C4E25F9913311ULL,
		0xF89EFCBAF941C9AAULL,
		0x18B3E4451B3705ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7554A33C2A9A2BFULL,
		0x68EE6A8CC233698FULL,
		0xB07DE89CD18CBFC1ULL,
		0x7D47D026CF763CBBULL,
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
		0x8EA7BD11A989A02AULL,
		0x094701ED42ABABE1ULL,
		0x7D98DB5A525C8778ULL,
		0x2D5D49C693505840ULL,
		0x7B4346208D6220B6ULL,
		0x0AA43B8BDD43E341ULL,
		0x3A2DAC36EE650E02ULL,
		0x026F434F3C321392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAA425E6A61A7B41ULL,
		0x9DA7D8B01ABF6799ULL,
		0x20606B81B55C9BC5ULL,
		0x09E1478982BF3FF5ULL,
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
		0x4A5C928BEC9907DAULL,
		0x03226765A1AC0FB2ULL,
		0x71C27FBE0FBADF63ULL,
		0xC4614E446E2D1FDCULL,
		0xCF6C0B0F20D97C40ULL,
		0xBF1A4694A5334EACULL,
		0x3A95866BA82AE934ULL,
		0xA2643DA51D080084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146636CACCE17CFDULL,
		0x6108E1762749BD59ULL,
		0x23F473B906197D37ULL,
		0x5F4274C6BD5D337DULL,
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
		0x1542A164299F1018ULL,
		0x004417DA75463355ULL,
		0xE441ADC4C56EBA5AULL,
		0xE9614B6C4192CB19ULL,
		0x5CF59AA96BA14727ULL,
		0x4B4962B8D512EEB2ULL,
		0x17393A3ED2526A9EULL,
		0xC222F30F5254E34AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B7968A238FA443ULL,
		0x2D28BF4A1615A1CEULL,
		0x56C05317FDAA8DD9ULL,
		0x3A915FB27A2C8819ULL,
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
		0x1718554650D936C1ULL,
		0x0A09BEB8FF1FAAD9ULL,
		0x1BC7B839154A57CFULL,
		0xE0F7F42FFE4985ECULL,
		0x44CA336B3E86F158ULL,
		0x9B00E9B2D6427099ULL,
		0x052A2EEB5E386934ULL,
		0xF796D1473EE041A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1BF73198E10F62ULL,
		0x0C2C6F44CCFC6199ULL,
		0xE00AAF2911A9F59EULL,
		0x215B04C353934502ULL,
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
		0x85F5A3BAB322E92AULL,
		0xDFF9ACB5CDCA13FDULL,
		0xA82F50689630D730ULL,
		0xDD790BBB9E4D310EULL,
		0x74C816BC47240C4EULL,
		0x8FE4D12571084997ULL,
		0x73DA988DB5F67895ULL,
		0xA5FECB9AE27DE26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA903AD427CC087ULL,
		0x3BF0B84495050078ULL,
		0xDAA1F57198C6BD64ULL,
		0x014B44B93CFCCD4DULL,
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
		0x3AA8E64B8ED81911ULL,
		0x8A5A8EEBC7FE60AEULL,
		0x74AA1EF2F7B61F79ULL,
		0xFA69146B39CE4638ULL,
		0x4C3B16F8BC48CD51ULL,
		0x4BD3F31DD00F6D78ULL,
		0x944EFA56FA99F143ULL,
		0x6CEF28405BE01D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B6E4F3781A6959DULL,
		0xCBD0A558AA48A089ULL,
		0x786347DC2A8FEF76ULL,
		0x25E90DF8DD1294C0ULL,
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
		0x097DA841FE07D9BEULL,
		0x92807F46352FA41BULL,
		0x6F8753137222DCFAULL,
		0xCAC1D3F350FE4D46ULL,
		0x7EDBC33C85569758ULL,
		0x4C209EB8441111FDULL,
		0x5E40B30FE45CC96FULL,
		0xA509BD2F1284FBD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1CA33DC8E25484ULL,
		0xDF580EA04FB84FBBULL,
		0x6D21E76F57E8C37FULL,
		0x4A33E8F010BBAE34ULL,
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
		0xE3F68276A565B841ULL,
		0xD4D940A6966304A8ULL,
		0xE9B24EC12E5F7574ULL,
		0x2787F4A8BE12F470ULL,
		0x075C45B92E72D143ULL,
		0xBAB3BFE9924E6CDEULL,
		0x35F6C9A1F6D93629ULL,
		0x1A035B2DD43EB6E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBA8DBF38A70C8CBULL,
		0x8B87BD524E072D9DULL,
		0xEC543CCBD29D7FA6ULL,
		0x04077D763F621B0EULL,
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
		0x07A188EF26F177C8ULL,
		0x8ADAF3E30062A66EULL,
		0x1A60CC6604666937ULL,
		0x115E81DAF103E74EULL,
		0x458C236CE9FB1B9DULL,
		0xCADC12D26CF942D4ULL,
		0xBA2B3E40198A16B9ULL,
		0x799F24F31F344178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A6ECB19E23793C2ULL,
		0xA785BF1F2D6291F0ULL,
		0xBCCC09E9CEE5C8CBULL,
		0x1EFDFDF192C59F39ULL,
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
		0xF8040696704F66E3ULL,
		0x55847D4F3D588E19ULL,
		0x77899A90FA00575BULL,
		0x8EEBB89E3AB6490CULL,
		0xE51DCB75E7BFC21BULL,
		0x8770228E61C8AC7BULL,
		0x0BABDC0E1F6C3711ULL,
		0x963AD9566EFC7764ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA703A16D6C63A3CULL,
		0x70299E71C122287DULL,
		0x330C44A9A41083F5ULL,
		0x5BA7FB72B43001E6ULL,
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
		0x992C3311880BED10ULL,
		0xC5A0FBBC4BCABFF8ULL,
		0x496A88E6C0EF020EULL,
		0xDDBB1CB65CC37F2BULL,
		0x3CF218186394FDC0ULL,
		0xBB7B6CCC6E50B367ULL,
		0xBA46F4C4627811F1ULL,
		0xD601F24F839DC1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA51BC6B050299C63ULL,
		0x99F32214ABC5614BULL,
		0xEFF2DE0D5EC1ABF0ULL,
		0x22051483E62E4154ULL,
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
		0x56489E318037A1CCULL,
		0x824DD4A5450A80CCULL,
		0x7655F88E827692FAULL,
		0xF921D1D816A105C7ULL,
		0x02A18DE71B5D9FADULL,
		0x202EA7AC9AE62F5CULL,
		0x448F38E5E46E7D61ULL,
		0x2192A07C5EB70529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA43AE7F901D564BULL,
		0x493AB84443358874ULL,
		0xA3986AAE6ADD2F65ULL,
		0x74E5A44E25CBC9E7ULL,
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
		0xD01D31C6C82201C5ULL,
		0xE6C68922C1A022E2ULL,
		0xAFA661178A0AC9F6ULL,
		0xD975BA23357FFBA6ULL,
		0x55ED220469983D97ULL,
		0xF1487F22A8A1112AULL,
		0x39D03B2B55E33EDFULL,
		0x8F62C150FBF4D507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91503E6E74BB2973ULL,
		0xB7896847C988AF2BULL,
		0x448F298649C61F34ULL,
		0x221E6C289BD79AB9ULL,
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
		0xF21EE9EBA29857E8ULL,
		0x0CEF1A93D2785FF0ULL,
		0xF3579568055DC68CULL,
		0x29EB8448CF13B2A4ULL,
		0x2D6A6EE5A95266CDULL,
		0x9DE32F76B15E1F64ULL,
		0xC684D50920783451ULL,
		0x521CB98C0A815F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFEB6002C4D39C1EULL,
		0x7CA82632267108CFULL,
		0x6B0F34C2D7358AA9ULL,
		0x5A2F0F125E47D538ULL,
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
		0xC1D98E6B435C1167ULL,
		0x9960F870280EF644ULL,
		0x65CE83EDD7D32FACULL,
		0xEB707A94483ADB56ULL,
		0x38423385D6113A75ULL,
		0x092E140F9378B513ULL,
		0x34B166083020B4F7ULL,
		0x02256608B647017DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BAD344909EABEEBULL,
		0xF637F2C00BF9D71FULL,
		0x3823A924FCAE0C57ULL,
		0x3CFD9FDF56C513ECULL,
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
		0xBAEFA2744280B1EBULL,
		0xBC9DDADD014C907FULL,
		0xABC282CFFB938B06ULL,
		0x856E1C261F334DC0ULL,
		0x7337E46EC1F593D7ULL,
		0xF3DB9E503245473CULL,
		0xF9AC558383DD0B88ULL,
		0xE8EB9891E3567A09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53B8AE50CF4A907ULL,
		0xEF375AC477952378ULL,
		0xBB5734558E63415AULL,
		0x1866C1CDDE096B3BULL,
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
		0x53E91411C30A2979ULL,
		0x4057FBDD6B8666D5ULL,
		0x63283B74BF6D3EBAULL,
		0xBE1718CADC7C71C1ULL,
		0x8DCC5D1DB479E942ULL,
		0x35B253C43A8DAE05ULL,
		0xB2A27224D78CF8F3ULL,
		0xF48A4B7417E5568DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603EE67A8D22CEC3ULL,
		0x38D06AFE1C8E3BA8ULL,
		0xE7452CECBE5A32D4ULL,
		0x0A9E4C0668874AC9ULL,
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
		0xD0DAA017F86E3E26ULL,
		0x4E03825DFA2E4653ULL,
		0x82F4A59D5B218EA1ULL,
		0xDA50A4F411F0BBA0ULL,
		0xED68E6E384580102ULL,
		0xCF284FA57F3D3672ULL,
		0xCA14DAD82F4BED81ULL,
		0xFB639A167771B67AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E6CE5DD9D7E6A16ULL,
		0x0DFF54EEDD445B63ULL,
		0x820D21B46066CFE6ULL,
		0x2B198449CCD1D1DAULL,
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
		0xE7A06AC1A3E6DAB6ULL,
		0xC06328F4BBC56213ULL,
		0x6828331B70A7954BULL,
		0x933FE05BD433E63AULL,
		0x6097430017E94638ULL,
		0xBD0472B60D0B3746ULL,
		0xA14582EE5704FBC4ULL,
		0x75342E1BD938CBB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E145CC53087499FULL,
		0xCF0C2FFAAB6F9686ULL,
		0x5879A27C5B64F47FULL,
		0x78FEB87E12A222BEULL,
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
		0x81AFBE800757DC6BULL,
		0x794321A2264FB7EBULL,
		0xDC227AD91F66C71CULL,
		0x101A82047430F425ULL,
		0xBEFBA7EC61B3BC92ULL,
		0x0FC2865B74FB66ECULL,
		0xDE796097AED9F340ULL,
		0x4506B73F19A83500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB0AAB968805DB93ULL,
		0xD023133583A0FF0FULL,
		0xE226D15D13C0E29EULL,
		0x4F19B5624328D246ULL,
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
		0x63FD823CDA8A6AC6ULL,
		0x40736DB6718C552BULL,
		0xE9DAABA5ED2F5624ULL,
		0xF02A71805F1D0DA1ULL,
		0x2D33911FA9C89989ULL,
		0xA2DFDA6182DDD0CFULL,
		0x7C2B376F721C779CULL,
		0x9F033363A745AF9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A50CF00E5138BFULL,
		0x6DADD82FDE7953ECULL,
		0x5844E630DD691764ULL,
		0x0AA4124B33751F02ULL,
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
		0x9A42D7081AC1DE98ULL,
		0x5DF490BDCD5F9425ULL,
		0xC5E24D3745A84442ULL,
		0x7F2AE0E8769B99A6ULL,
		0xF861D7EC20F61346ULL,
		0x75CAA3D18026A18AULL,
		0x9D92D44D8CDF3D64ULL,
		0x1E06888F8E4F07BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C8E414FF48BBA7ULL,
		0xDA08E1D6D31B8EC6ULL,
		0x29ADD0BA2ECB612BULL,
		0x742326379656BFA6ULL,
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
		0x474AF65D1B002055ULL,
		0x4B80150BFECC1D94ULL,
		0x0C73F5DD21A90F5DULL,
		0xD9EA940A60C0134CULL,
		0x6BB1757B75A4051CULL,
		0x49C1B7FCAFF9BB02ULL,
		0x8D9A9B7183607967ULL,
		0xDABF516C42EE4E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A266B09158E763ULL,
		0x3E41648E1DDDDFF0ULL,
		0x116708B6A1FB14B2ULL,
		0x5250AA1C501FB0E1ULL,
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
		0x4CFF099C2032E436ULL,
		0xA7A6E42DC1D58218ULL,
		0xF7DE67B2D2B9BFE6ULL,
		0x1CA61963D06CB40AULL,
		0x1539B4DC7BE2A22AULL,
		0x63711745FB873B41ULL,
		0x5D526F1629946F52ULL,
		0x46B2954CAEE9AB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738FE25683D6F801ULL,
		0x6A70589117E84DC1ULL,
		0xD21AE4FCFEC24621ULL,
		0x1B2842C5C71C2750ULL,
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
		0xB56126BFDE2C16F0ULL,
		0x128B0C5728342765ULL,
		0xA4702AC9582E01F8ULL,
		0xBB5E33F8F1250AB0ULL,
		0xD28CBFDEF0D55661ULL,
		0x38685FC267644955ULL,
		0x54F98B44A537D6DCULL,
		0x1C2E5637E199A68BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF645A1D79DD6EA01ULL,
		0x7209433281170A22ULL,
		0x417AD6F9DE77E6A8ULL,
		0x6A3F00446DF3C35FULL,
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
		0xF288F22F5EE34AB6ULL,
		0x212A96D0B25C63C9ULL,
		0x192F07DCD6B38214ULL,
		0xC6DCE549143934C3ULL,
		0xD40AA253F1E3CF1FULL,
		0x34C1B46F2B6C818EULL,
		0x087D372E2084D774ULL,
		0x0772E500A64B6022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C1D0AA546B40989ULL,
		0xF5EB5F5124779EFDULL,
		0x5BC538B5AA6B7D53ULL,
		0x61EAE361C36979D0ULL,
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
		0x4ED382E3E6AD731DULL,
		0x193AC3DEE059AC12ULL,
		0xF7C8C8E50E376DE1ULL,
		0x0651CB5EF9777F0BULL,
		0x9A9C21D293FCE0DCULL,
		0xC3CCC1FBA05B81DAULL,
		0x23C11469730D57C4ULL,
		0xC2D1BCC03EEB53BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42008825DE36D800ULL,
		0x299F8F38ADEEF285ULL,
		0x4671D08C22327516ULL,
		0x7173CFE85065ECF9ULL,
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
		0xF1E391F45498AF9EULL,
		0x294CF09B9BCB5305ULL,
		0x79CDABF54BAF31DDULL,
		0xA84F24EEAE65E0A5ULL,
		0xE324965AFF4BE31DULL,
		0x4455E9EEBF358DDCULL,
		0xF769AF477DCD53C3ULL,
		0x589E14587599D765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA951E37639DC67EDULL,
		0x4E0DAA0BFDBE61CFULL,
		0x337DB091F829A0D9ULL,
		0x4FC62A10233BD9C8ULL,
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
		0xB1E3C90958383CE0ULL,
		0x95F90EE5323423CBULL,
		0x67A6DB91C3EADDDDULL,
		0x60707C9F9BBEB5B1ULL,
		0x08C5D59A1D9A033AULL,
		0xD001EAD7BB91DE7FULL,
		0x7702A55E2ECE7974ULL,
		0x29D3F703E32DAD45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF417DE9BD14B873ULL,
		0x7641EAEB09DB2AA6ULL,
		0x120B678CB690E534ULL,
		0x15E7273354866E01ULL,
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
		0xF06B04908377AE7FULL,
		0x42388090A118EDC1ULL,
		0x7EF7260719A44382ULL,
		0x35A61783BE6B327FULL,
		0x4B736E0B4A50B2CFULL,
		0x98339FAA07AE1DCBULL,
		0xBBE224C5331F4F6EULL,
		0xD6221ECB81C18081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238D5A3D8B723DE6ULL,
		0xD9E233CDC4F159EFULL,
		0x62889B4CB04A0DECULL,
		0x7EB6A9B9012445C1ULL,
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
		0x3620F9B73084BF10ULL,
		0x48DEA8DC84D98B71ULL,
		0xC6AEF9FA2D513278ULL,
		0xD739DA941A49223EULL,
		0x751CFF7480CE8457ULL,
		0x3E828D03A7D698B9ULL,
		0x906AE3F1504FD951ULL,
		0x9749B4020ECFD96DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x986EE5024F2C6764ULL,
		0x903F97676EB436F8ULL,
		0x368CCFCC192B7487ULL,
		0x4C2A92E24D236882ULL,
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
		0x3D93262365288CAFULL,
		0xA016B22F0F416EDDULL,
		0x6E8956353B02BEAAULL,
		0x776402E85F44CF68ULL,
		0x172AE71590C20DA3ULL,
		0x9F459414183A2586ULL,
		0x9A0D55F583D4ED60ULL,
		0x699D9D95DF32FED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADF17356E1F69541ULL,
		0x446AAD2AA7E300C4ULL,
		0x4C8418A6CC9DFB02ULL,
		0x24C9672780D6A31DULL,
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
		0x4DFF7461DB5180C4ULL,
		0xCDEAC3B5F0889608ULL,
		0xFC0B09D207D1FF6CULL,
		0x1CA747C7BECE8565ULL,
		0x71F5F85EA3027E6AULL,
		0x3E724420575319A0ULL,
		0x159D1DA4A0AA178AULL,
		0x973AF8BFC630085FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3882526E0DB047D7ULL,
		0x12E0E082E6DE63D9ULL,
		0x315D7041E1117DF2ULL,
		0x0F68343F29EFC383ULL,
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
		0x568DC9E5F2EB403AULL,
		0x926ABDD081171856ULL,
		0xD44363CFE4C91CB6ULL,
		0xA31F20ABF626D8C1ULL,
		0x801BEA1D4965BAEBULL,
		0x94FA203C8D6990C9ULL,
		0xACBB66D95945464BULL,
		0x48AD291D1617F195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB28A3ED80500BEULL,
		0xAF8B86CD7EC2963FULL,
		0x7814A81325118BEEULL,
		0x6CD33AFD3DB4B4F9ULL,
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
		0xC041B76967CDF6B6ULL,
		0x2444385FE62F90A3ULL,
		0x2ABAB11CBC40E1A0ULL,
		0x8543E3F61D3D014FULL,
		0x67556DAFE6B32ED6ULL,
		0x94265236C95D01D1ULL,
		0x139DA7C494EBE648ULL,
		0x26B068CD118B6842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16EFFF85A666EB5EULL,
		0x21F46C81C9FDD5B9ULL,
		0x1421984AD7451066ULL,
		0x43737266B7EE7B1EULL,
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
		0x70E26DF474D8CB7BULL,
		0x23B7A83247A31FA9ULL,
		0x61B7876A214B99FCULL,
		0x9CEDA80357017EFCULL,
		0x97BA6B8B843FB9BDULL,
		0x05EE67F6D95EA810ULL,
		0xB6F578FFED0AC556ULL,
		0x239F5A6483CC515AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF68E64AA164E5E5AULL,
		0x051B16D68BB0121FULL,
		0x8A277D6750E4E4C1ULL,
		0x669512EEE7559273ULL,
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
		0x5B31B4C63C7277EBULL,
		0xAB12EC70DD01EAC8ULL,
		0x449578144EB8866BULL,
		0x0B6E01913199C7BDULL,
		0xA8C919C896594033ULL,
		0x3578C19AD0A5C420ULL,
		0xFC1B6E59EF7FB5E4ULL,
		0x59CED51531320CC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x690B888C8DB2016BULL,
		0x9AFFA96BD59D07A1ULL,
		0xB0A7D96DDBAD864BULL,
		0x6021A2B67F07AD92ULL,
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
		0xD1F2B0A13350BAA2ULL,
		0xA72707988D44BCB2ULL,
		0x051B4F2FB8849911ULL,
		0xE1C16C5DE7560E48ULL,
		0x4FA81313D4888DE6ULL,
		0x1F1B7B617B124E71ULL,
		0x4518522A1D071EF3ULL,
		0xC7852D7C60326EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E58592BF95CF3AULL,
		0x453B5810D1FC6184ULL,
		0x46B7817007933128ULL,
		0x7F862CD42ED28722ULL,
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
		0xC1DC39D2962269DBULL,
		0x39E87D454FE70BAFULL,
		0x3EDF44250C731B0AULL,
		0x9FAEFAF4F2E74DA5ULL,
		0xE4F2F43F6C67C86AULL,
		0x3B39E3E7728CF252ULL,
		0x8136A8F2EE56D4E6ULL,
		0x414EEFAF5D0E5AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDEC7B3CAD8A2B13ULL,
		0x048051A050D303FDULL,
		0x6CFC58346D56B537ULL,
		0x51668EFCC308C25CULL,
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
		0xA43E1A87843C5C29ULL,
		0xE313A0B43C38B2ECULL,
		0xD844B74CDB71974FULL,
		0xBFF3E033D827D8D2ULL,
		0x3E34F008C5BF75C9ULL,
		0x502AEC29915371F2ULL,
		0xE18A98F893196F89ULL,
		0x46FF6D94CC535EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE019BBD4DEA7D9A1ULL,
		0xC972AEDFCE9B9CE1ULL,
		0x52D76C32B13825B1ULL,
		0x49DE244A2C87E4DAULL,
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
		0x46B11FB083E1858EULL,
		0x1B7CF6266D52851EULL,
		0xE08DCE8503D3D1C4ULL,
		0xA49135BA5B1539FBULL,
		0x33D1531B28DE0303ULL,
		0xF414D53996955A0FULL,
		0x6E31156ADE85C533ULL,
		0x2E1DF07FDE645446ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C375B894D5F90AULL,
		0x56949CB2C77DE35FULL,
		0x3BD6FC620BAF177AULL,
		0x7D02E8B55DF9BC70ULL,
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
		0xD8CB7C360B5A941CULL,
		0x7E0255B1920C269BULL,
		0xC1AD55628FDE7111ULL,
		0x6E9312FC0D76D946ULL,
		0xAF23F08F8F3FE0CAULL,
		0x50B8E764F02C470AULL,
		0x9CDD7E40DD867A0AULL,
		0x69530F16C595E99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82131854ED5F478ULL,
		0x7974AEAD389EB231ULL,
		0x0A8E130371D48E99ULL,
		0x10E7505D61B786ACULL,
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
		0x68F35F30C2527F00ULL,
		0xFBB7ED44AF632E73ULL,
		0x597FF9A6810DFF1FULL,
		0xE1A86338E37CF1CDULL,
		0x111FD5DDD45FD203ULL,
		0x7EE8083BAA19A075ULL,
		0x197020C6896D7F29ULL,
		0x2708B43D25008946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3AD1E1E488BAC69ULL,
		0xD229261FEF30FFD3ULL,
		0x2024D71EE74EDF48ULL,
		0x2CF3244C61915235ULL,
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
		0x74BE4C6F022EBDFFULL,
		0x7DFD10CA00CA9569ULL,
		0x928CBA6376BEA0D4ULL,
		0x76C2C2112BAF1DC7ULL,
		0xACDA497918778EA9ULL,
		0x6803E8AF22595E12ULL,
		0x10491C82A9622872ULL,
		0x7B1849FC21C20CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D253468A3EDEDD4ULL,
		0xEE919AC91A0E8C2FULL,
		0xFD66F5C89B50A1CFULL,
		0x3C5DBD7E2E7CFF77ULL,
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
		0x8DB2DF7599339508ULL,
		0x2E7559AF7B278BBDULL,
		0xED6B50B10F5E574DULL,
		0x75156588B6CC1E60ULL,
		0x8F88D733E4D9DB55ULL,
		0xEA0EF51C3BDF9C50ULL,
		0x2640E1E1290F23DBULL,
		0x8D36E599F82159D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC02D129918A26C4ULL,
		0xECADBBE05E58BFB2ULL,
		0x9B0CD81D279DA9F1ULL,
		0x6B3B7A638BBF742AULL,
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
		0x0E698CA509B31508ULL,
		0x00CDE96FF36AF979ULL,
		0x342FE5B306B6B013ULL,
		0xA718E3EA2116120EULL,
		0x24604D9D3BB958F5ULL,
		0x5C4F8FF5A06A1DF3ULL,
		0x675639A50DD0636DULL,
		0x1BDD92A7786F8BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B511FBE7364A11ULL,
		0xB49D47E5C32B6B90ULL,
		0x8AFC743313A5724EULL,
		0x49FCA8C601A4D583ULL,
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
		0x5210D44CE43417FEULL,
		0x1E8C1602FDD5664FULL,
		0x4006AAD1B097782DULL,
		0xC83FB438298B7449ULL,
		0xC6F55B44C96BEA74ULL,
		0xF809A8A751D03831ULL,
		0xFA02DFCEF5838E2DULL,
		0x34CD90A9AD5F5234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA7C6082CA38E679ULL,
		0xEFFB1ED922BDBDB2ULL,
		0x5C73E38A221E92FFULL,
		0x1EC32D67E5B1A826ULL,
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
		0xEC7B993F373EB04FULL,
		0xBB0B6FD578F2DEA7ULL,
		0x35F24C21B96D7FABULL,
		0x8E431B6CC2DB7F33ULL,
		0x00AFE45F84439A41ULL,
		0xDE44838ED76014C6ULL,
		0x47C68C783E61A82FULL,
		0x0B5B06FDB28A91EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06977F6CD9479641ULL,
		0xB936F7097135F40CULL,
		0xDD6B25FAFBEC76C6ULL,
		0x3DC62515436D27F9ULL,
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
		0xB3CAE985B249ADA7ULL,
		0x022C5AAA03A3D300ULL,
		0x18CCC48BD5E12D38ULL,
		0x2F18458CD09A81FAULL,
		0xB0E9507E45485F79ULL,
		0x297D35C08228624CULL,
		0xAB553BFE6D03B948ULL,
		0x1F8FB2D11DB53A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66CDC43FB07DA48ULL,
		0x2AC2553D55A26A62ULL,
		0x8773AC50046EADEEULL,
		0x5E6CD09739812747ULL,
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
		0x8E845984B54FD05DULL,
		0x0D3A61598F6712D2ULL,
		0x5D9B5CA3EA5FFE4CULL,
		0x15375A78F9DC7F44ULL,
		0xA16F0BDE31D004A8ULL,
		0x37C73D7D3B1BF13EULL,
		0x2CE43153B8A1ED6EULL,
		0x10996A9283B7F447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85001C801A3081ACULL,
		0x54CD81F0558CE21EULL,
		0x077AAF1152693CA8ULL,
		0x0BFD2C38872AC1D5ULL,
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
		0x2E0F862478934677ULL,
		0xECB8232A51536405ULL,
		0x239FB9D10E7F37D8ULL,
		0xBE702A647C8C4A5FULL,
		0x9641B3F9ADB6F53BULL,
		0x10258A581925CE59ULL,
		0x96D0A8B6FC7DE986ULL,
		0xF8C7F8AC51885DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD03D3441BBB2CAULL,
		0x524AAC3E0CF00551ULL,
		0x8698C4FA892FE1BFULL,
		0x2C1F13F896CA3A27ULL,
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
		0xF80DC20B2F358832ULL,
		0x7F7D545AD9FE7CD9ULL,
		0x79F8B3E84FCE8FD1ULL,
		0x3A64F611D6FAC050ULL,
		0x62D327615BB0BEFAULL,
		0xD19250B349E6EEA5ULL,
		0x09398ECF26156613ULL,
		0x468FB37F452A3CA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3659A7ECB71E2DDULL,
		0x9B354EF7D245E966ULL,
		0xD883E6A7F6FBB6C2ULL,
		0x33B99AF61B3FC167ULL,
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
		0x2D55119602A67073ULL,
		0x96470BA69CDF0A37ULL,
		0x42C6905755F88545ULL,
		0x0E6439837AFBA618ULL,
		0x139C00A22900EB84ULL,
		0xD2971D78C59469FDULL,
		0xA96DFB6F772F5FD5ULL,
		0x6CC4989A7D45C43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167D29A818C9686BULL,
		0xD8B56B93F0E6C5C8ULL,
		0x6919E2E30700BF02ULL,
		0x3392E0721356C73FULL,
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