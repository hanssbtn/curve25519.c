#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x06AC206383EA0033ULL,
		0x46552E6453C3348DULL,
		0x8990EA7346B3A203ULL,
		0x5960C7E213071C60ULL,
		0x5644916337F92DC1ULL,
		0x474A554AAEBF131EULL,
		0x7642BD67BAA53FEDULL,
		0x64C3B41E3BFEBAC7ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBF731E568DB3ACC8ULL,
		0x53BDAB3B0F0CC01EULL,
		0xF7D53FB8B799FCACULL,
		0x3EDEA95558514EF0ULL,
		0xDEAAF44BC7427182ULL,
		0x112E894A910192B2ULL,
		0xE5127B86F128255AULL,
		0x4BB7A5D1E7A9F148ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68CB8B8BAAA0CFF4ULL,
		0x7D2CD9B5535233A6ULL,
		0xCB9E766A4255498CULL,
		0x5FDF5259E9A96CC7ULL,
		0x40E3C62B58F746D4ULL,
		0x0F74E9E18267EDFDULL,
		0x647AADA74CB476A8ULL,
		0xDA3AC9A1DAF625F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA41660B8C164E6ULL,
		0xD85835069191E5ACULL,
		0x56E83AAA8E8F4615ULL,
		0x657B69C009D7C2DDULL,
		0x62CAB74DBDBE4584ULL,
		0xCAE5C12CD880549FULL,
		0x48A2CC2C57A6DDB4ULL,
		0x2FD79D11B5A32302ULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAA36477A980DB22ULL,
		0x6D2FE1F98ECD8467ULL,
		0xC0F762CECDA193E7ULL,
		0xEA6A38826E60E94FULL,
		0xE02811372A18AE78ULL,
		0x0B0055191A903D58ULL,
		0xF5674013CFB9B3D2ULL,
		0x8AC1C5DC5E81A563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8814EB1DE7F963E5ULL,
		0x0BD8065EAE4C5389ULL,
		0xE63355DFCEFD7E55ULL,
		0x1E336CB75E177A85ULL,
		0x2253914788777F97ULL,
		0xB7BEA7E361520194ULL,
		0xB7A190E8499F5719ULL,
		0x12A1BA1F7BC6C710ULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A6F17E3DDA0A6C5ULL,
		0x7674915BC3F3C2B6ULL,
		0xDE497AE23DB6F706ULL,
		0x16A70957A03791A0ULL,
		0x5B3D78B6477E1A8EULL,
		0xC3D2808E198626B3ULL,
		0x8FDD8F7C79AF165AULL,
		0xFB4C051959F12555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x704F6B525C0EC555ULL,
		0x61234B17BB6865D1ULL,
		0x6B22E18ED3E01835ULL,
		0xFEF8FE7EC8A23685ULL,
		0x6483E92BA6A64B96ULL,
		0x4B6F69DD16BB21C9ULL,
		0x4B8EB492D78A5BFCULL,
		0x0B3B293B89465F86ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC59F7B3FDEB0603ULL,
		0xE2C6E285DF73E9F5ULL,
		0xD2AAE81CBBC7D5A7ULL,
		0xC48F76CB1B0F49CCULL,
		0x8CEF4433E052791DULL,
		0xDE9E017B4E743B11ULL,
		0x74A89F1FBB398FF1ULL,
		0x471790B52692FD3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC59F7B3FDEB0603ULL,
		0xE2C6E285DF73E9F5ULL,
		0xD2AAE81CBBC7D5A7ULL,
		0xC48F76CB1B0F49CCULL,
		0x8CEF4433E052791DULL,
		0xDE9E017B4E743B11ULL,
		0x74A89F1FBB398FF1ULL,
		0x471790B52692FD3CULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D487C72D787880DULL,
		0x56F077C3345B40A2ULL,
		0x13EA69FA0F85A710ULL,
		0xB70F656496AEF81AULL,
		0xF4000252B6D2B4FFULL,
		0x0F5780E74FCCB6E7ULL,
		0x0CED6E9648A68EF6ULL,
		0x8D81926260C1AFBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3648E599DFA326C0ULL,
		0x0BB066585DDE9005ULL,
		0x39D46057C769D4B1ULL,
		0x6EA0B9512926CD46ULL,
		0xD33749A08A78C7E8ULL,
		0x427E427EC02DEA66ULL,
		0x5094B8D6325AF001ULL,
		0x54EE61F9D95AD85AULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67A005D8448966CULL,
		0xC00A25BA53BB0D16ULL,
		0xD843D96E7DBC2FF8ULL,
		0xD5766FCEE91154E8ULL,
		0x2382201772CF4C72ULL,
		0x0625C74F23175033ULL,
		0xFD976B2881F917F6ULL,
		0x8F4D609AC2D5FCD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FA4C74C3A07049ULL,
		0xCCDAB1752AB7873CULL,
		0xF80D09B52D174027ULL,
		0xEEDDE3CE4CD0DB45ULL,
		0x4BC5D81EA6521F6AULL,
		0xC7E50F13DD260DD7ULL,
		0x5E30289849CC3081ULL,
		0x4832AA4CD8126009ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37048A216151441BULL,
		0x32B968B72979564DULL,
		0xF5656B51A90CB153ULL,
		0xF209E43238272587ULL,
		0x2EA5C0577BFED840ULL,
		0x22DA6E5340950411ULL,
		0x01868161B7306559ULL,
		0xFAF60C308781D10CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8939616B18B9C0ULL,
		0x232D3AA55C41DD9FULL,
		0xA887524652A3A1EBULL,
		0xD1E8C3004F29FB05ULL,
		0x5A4F9A06D5552F40ULL,
		0xFC6C372597928AC5ULL,
		0x9DA26891EE7C8FE2ULL,
		0x7B8E6ED3E194DC97ULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC278B6AAE485F9ULL,
		0x05CA3F3209B5E7D0ULL,
		0x73DC9A73C5EF145DULL,
		0x62027ABF66EF1FCEULL,
		0x74CA838625D7513CULL,
		0xD8FE82D23BC75014ULL,
		0x0F0FB593003BB87DULL,
		0x56B880F8EA689DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC278B6AAE485F9ULL,
		0x05CA3F3209B5E7D0ULL,
		0x73DC9A73C5EF145DULL,
		0x62027ABF66EF1FCEULL,
		0x74CA838625D7513CULL,
		0xD8FE82D23BC75014ULL,
		0x0F0FB593003BB87DULL,
		0x56B880F8EA689DF2ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7DB37D18E11EA6CULL,
		0xD602E54D45D80573ULL,
		0xEFCF014008EBC619ULL,
		0xDD0800C891276BBFULL,
		0xD4791B9C5DE103C7ULL,
		0x8B9724250B394185ULL,
		0x18DB1FB500E5965CULL,
		0x9BC2EB336690D38AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8678B8F9847CF62DULL,
		0xAF43AF7914668169ULL,
		0x16B4F954A6481004ULL,
		0xADCE98C50041D0D6ULL,
		0x492C069D142AC511ULL,
		0x8A899040D4F88946ULL,
		0x2D4007190F05D1EAULL,
		0xF541E52999A40D16ULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11390A4265D26304ULL,
		0xE6BC797F8D58B24DULL,
		0xD8BFEBE6A88DC3A2ULL,
		0x6655D73949CE8807ULL,
		0xC188E13D9C00BD5FULL,
		0xA7BEB3A739740B5BULL,
		0xDDCDB2FC88B5193EULL,
		0x27CF688A40F6EB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C855771D95424F0ULL,
		0x844432CCF23FD0E3ULL,
		0xA9426C1A0186D906ULL,
		0x6A260B795BC68036ULL,
		0x48949A5C8B0D66D0ULL,
		0x77E56E2FFB2C74CEULL,
		0x84F0FC8202DAC362ULL,
		0x6C3E6421DA526C59ULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83CC9508A4E5320FULL,
		0xE7A3837E537A28E7ULL,
		0x042F751063D009DEULL,
		0x7CD125760FEC84F9ULL,
		0x903CEBBA35BBC73FULL,
		0x4AB40AE5F323AE72ULL,
		0x182D28E7A9C8D17FULL,
		0xFD5B2888D0168A8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFAD82A8F4171694ULL,
		0x95EA6967933B5355ULL,
		0x5B5D508E8A8F8DF5ULL,
		0xF6CF9E43AC81FE02ULL,
		0xAA8B7E484145EE09ULL,
		0x3B7B6AFDA3A07339ULL,
		0x4B35BB64D5FE757BULL,
		0x5A172244D54D4345ULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC71F8B02E46D387CULL,
		0x21BB08050402A479ULL,
		0xFBD605F5F5F2567DULL,
		0xC7A3C206911ECD85ULL,
		0x722EE165B40C76D0ULL,
		0x774643718011C0B8ULL,
		0x93E6E43DE40B1AF3ULL,
		0x90C605FF1A8D72B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71F8B02E46D387CULL,
		0x21BB08050402A479ULL,
		0xFBD605F5F5F2567DULL,
		0xC7A3C206911ECD85ULL,
		0x722EE165B40C76D0ULL,
		0x774643718011C0B8ULL,
		0x93E6E43DE40B1AF3ULL,
		0x90C605FF1A8D72B1ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E15954D1B6B1ADULL,
		0x3BBEB3BAEFE65DCBULL,
		0xC0CFC49A233849FFULL,
		0x5184CE0825390723ULL,
		0x5A5134C5205C1D80ULL,
		0xD65BFFEC994F06CBULL,
		0x580E3ECDB4480287ULL,
		0x1E80CB950DC984F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5758E8521ACC1A1ULL,
		0x4A61BABEC4B6D814ULL,
		0x1CB4D1C987214702ULL,
		0x88C548DCB898523EULL,
		0x5D45BCFEEAE07B86ULL,
		0xF5B5472582CE1D93ULL,
		0x61F827DD1E8D54EFULL,
		0x11297342BC6E84A0ULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D28D7C561D34ED3ULL,
		0x037ED61154A00232ULL,
		0x4959791EA93BCA1DULL,
		0x32E84D45904642E4ULL,
		0xE63B87F513E07B70ULL,
		0x593F9E5F693AA89AULL,
		0x986BBE20F9102251ULL,
		0x55C39712CEF9F442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A60CCEC21E6AAAULL,
		0x3B275AE4F5F222EEULL,
		0x126635DF00779344ULL,
		0xF89439B9D5D8035BULL,
		0x2DF7CF64B3E92876ULL,
		0x6772D7F8CB1CA08BULL,
		0x0474C1846FAD4542ULL,
		0xC27B8DB6F9839EB1ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC431060084C91498ULL,
		0x24A05E1B39B77996ULL,
		0x0BD18EFC71667D8FULL,
		0xC1AA33C96BD6A9ACULL,
		0x6D2C7876095EFB94ULL,
		0xE63D805343AF41D7ULL,
		0x61B5120DC54C74CAULL,
		0x1086AA41BF10081BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0773BBC26584791FULL,
		0xF6993F7514561215ULL,
		0x8210D467941F78B0ULL,
		0x42632185FC6F9E8FULL,
		0x79E1518F700499FDULL,
		0xA5C8AADB9CA7FE43ULL,
		0xD336F33798A24708ULL,
		0x51BD16D1A528C169ULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6455AE275E2FE516ULL,
		0x924305C2CB9F5B15ULL,
		0x5B831921B773D45EULL,
		0x6D2E48BA6A1D3007ULL,
		0x5D5DCF8D982979D4ULL,
		0xEFF861AE1871D43EULL,
		0xAF1226CA1FB81E19ULL,
		0x844E72DBCCA1CD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6455AE275E2FE516ULL,
		0x924305C2CB9F5B15ULL,
		0x5B831921B773D45EULL,
		0x6D2E48BA6A1D3007ULL,
		0x5D5DCF8D982979D4ULL,
		0xEFF861AE1871D43EULL,
		0xAF1226CA1FB81E19ULL,
		0x844E72DBCCA1CD3DULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AC221FE65D43260ULL,
		0xF5C2CCD98D5AC92CULL,
		0xDD6219E384B6EBF3ULL,
		0xCFAC5E78C4361F71ULL,
		0xF8AA5E23C3547A4DULL,
		0xA1C497E06FA4BC18ULL,
		0x06923187B7848602ULL,
		0x3CF2D85D3554061AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9752ABA1E1C832AULL,
		0x0B86A24325BFD833ULL,
		0x18DC00CBC89F3343ULL,
		0x31CEB6CB14EB24E1ULL,
		0xA836F79CD5FB7A26ULL,
		0x4A2205039F50C255ULL,
		0x109811B94E141EA5ULL,
		0x2942CA25930D4B5CULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF020FC2540BDE8FULL,
		0x1C474671E3632D1AULL,
		0x17C4A215AF3A5096ULL,
		0xD17D52DE6018A6D0ULL,
		0x5841BCA828442061ULL,
		0xB8B2F20B652C8D95ULL,
		0xBF7EB5ED174BA5ACULL,
		0x9ECB3D75BFAAC20CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD2F5FF0614D635ULL,
		0xEDBD79ECE2D80AEFULL,
		0xA5665975E9C8D65DULL,
		0x33680EE8DE4B910FULL,
		0xE931FDD012A9B98FULL,
		0x6A3950387FB451DAULL,
		0x6FF6CFB7EB1D6758ULL,
		0xC4AD44B4A8D092A6ULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FA923196B3D45B8ULL,
		0x235C96DFD3A04EE1ULL,
		0xD7C19B5C551644F9ULL,
		0x0DD595AD424387FDULL,
		0x3D5E32C7C69F0908ULL,
		0xF9CE083F7A83C493ULL,
		0x5678484ACB0B3B8FULL,
		0x0D9CA6346EFFDEA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BEC4BDEE1D86208ULL,
		0x3AFD9FCF1C4831B1ULL,
		0xE7B4CDCD54B8EE20ULL,
		0xF153EA8A7A4F1AA5ULL,
		0x2070A48F99A86393ULL,
		0xC657B3E431AAF9C8ULL,
		0xFFD55C1C775D78CBULL,
		0x51499971BFC4EE46ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A33077F777864C5ULL,
		0x5F17C38A90C463B2ULL,
		0xB35B67F9B603B55EULL,
		0x897D21E855677628ULL,
		0x9310E76E78290727ULL,
		0xA5831BDC86483361ULL,
		0xAEAB9B61DC631FE2ULL,
		0x271D1F29E643558FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A33077F777864C5ULL,
		0x5F17C38A90C463B2ULL,
		0xB35B67F9B603B55EULL,
		0x897D21E855677628ULL,
		0x9310E76E78290727ULL,
		0xA5831BDC86483361ULL,
		0xAEAB9B61DC631FE2ULL,
		0x271D1F29E643558FULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6331F6DAFA020927ULL,
		0xF7EE614EB79ECA2EULL,
		0xC6CBEEFC1B5A81D1ULL,
		0xCC892B8D2E264088ULL,
		0x717B46345AFB77C9ULL,
		0xA79C0701D4181D3AULL,
		0x83BED8C7EF4E3EE3ULL,
		0x9BA012DC43456AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8A7A3478C73AA4ULL,
		0x3D8784CBAF9A785DULL,
		0x2C08AD72A6BE6C78ULL,
		0x3CB126C3E509BD2AULL,
		0xEEAF6D78C8657A81ULL,
		0xD310FD56D4204D38ULL,
		0x36145668749E371BULL,
		0x60801A0D7BBCAF34ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25FB9122C9D70729ULL,
		0x644A278482A7B7D5ULL,
		0x54B9411C20EEBDDEULL,
		0xB82854D0537F9AB1ULL,
		0x0E5A1966373619ECULL,
		0x974C232FA349BA3EULL,
		0x06D66439E7491126ULL,
		0x1E9D43A8CABD8CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278E12D0889921B3ULL,
		0xAABD0E241D780B94ULL,
		0x8751760B47415176ULL,
		0x31A1F57EA4359021ULL,
		0xD9CF6647B88051BFULL,
		0xCA451F358EF98357ULL,
		0x8D470BEF75458423ULL,
		0xED5026DF87831A65ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA449513DCA993EBCULL,
		0xEB6CD15FA67E2207ULL,
		0xDA4D55957BBE6862ULL,
		0x8DEF2B679A59739FULL,
		0x8CE019EFFACB5A31ULL,
		0xA5788681BE7587F4ULL,
		0x2717D77F42CB57A7ULL,
		0x1B347963A369A14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E8873313A36D0BULL,
		0x74DF5A003CD5EC0EULL,
		0x05DC14B0D038A31FULL,
		0x6831C4FB9BDE24CEULL,
		0x726EB66FC2D63135ULL,
		0xD66B75EDE065B54CULL,
		0x05DA6B9F7BB2E5FCULL,
		0x6F4C379180324B33ULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22411D4CC9247DFAULL,
		0x4CD259A156CFCE2DULL,
		0x74E93BB74B1A74A1ULL,
		0x539BFCAE2E6DD3E3ULL,
		0x74B7FE357D0587DDULL,
		0x96F8E400BD16CDADULL,
		0x44684FDED37B16D9ULL,
		0x404DDDA72282872AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22411D4CC9247DFAULL,
		0x4CD259A156CFCE2DULL,
		0x74E93BB74B1A74A1ULL,
		0x539BFCAE2E6DD3E3ULL,
		0x74B7FE357D0587DDULL,
		0x96F8E400BD16CDADULL,
		0x44684FDED37B16D9ULL,
		0x404DDDA72282872AULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7899BBC97F418BC3ULL,
		0x16DF444F1A280CECULL,
		0xB986ECAD69BA05FDULL,
		0xB6E4AC93BA1322D8ULL,
		0xDB255C694FDC73E5ULL,
		0x2AB65B56116586A1ULL,
		0xC732D3141AD233FCULL,
		0x9E9554ADC32DE60DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC926A8063406D7ULL,
		0xA3A7E2D231E5A52BULL,
		0xD87B9A1173046CF5ULL,
		0x77889CA413F86FF4ULL,
		0x452F262DDBD79A2BULL,
		0xBF65693803A40571ULL,
		0xD0ED853EF7E4B44AULL,
		0x4CFD66B0C397ABB7ULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB19AC3358AF66FDBULL,
		0x39FB79717C381B70ULL,
		0x0679F6A6D0452FF0ULL,
		0x41C26733278392DDULL,
		0x7127B3EBAD707947ULL,
		0xE5052C17D1C2D014ULL,
		0x3B9C0BDB45DEA324ULL,
		0x0F77403EA4E2861DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47928B7FC8758170ULL,
		0x69EF9CC4B753CB82ULL,
		0x79A0DC8CD9D1251CULL,
		0x81056099C6FF6097ULL,
		0x5908956E99A94A35ULL,
		0x3F90BE5E0E182A23ULL,
		0x89F4C3E0C51B9D55ULL,
		0x6CB06E338F126CFAULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45BF345F7CF1BDF4ULL,
		0xD299730F429E1D33ULL,
		0x905F9FDD719ED928ULL,
		0x36308DC5041DCE96ULL,
		0x4172F92889D2C777ULL,
		0x2009A26559A3BF26ULL,
		0x30B06B359D8AB54AULL,
		0x72BF4DAFE502850EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E8D6483EAA74018ULL,
		0x469368A47037ED8CULL,
		0x910B36B190D6F196ULL,
		0xDBDAE6CB6EF64365ULL,
		0x9D76DA592CF03509ULL,
		0xD4342A8C8B85FDEEULL,
		0x4CA1D1535FD5D46DULL,
		0xF93B111476C37204ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71B84D4EB117A5F7ULL,
		0x7C5AF1523F3842DCULL,
		0x0FE68A39138BF46DULL,
		0x71BC0B6E50E4319FULL,
		0xA542A91473D9D80EULL,
		0xD5268FA35E5D5851ULL,
		0x0F8CC20D47288B18ULL,
		0x694BC23E632BE779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B84D4EB117A5F7ULL,
		0x7C5AF1523F3842DCULL,
		0x0FE68A39138BF46DULL,
		0x71BC0B6E50E4319FULL,
		0xA542A91473D9D80EULL,
		0xD5268FA35E5D5851ULL,
		0x0F8CC20D47288B18ULL,
		0x694BC23E632BE779ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96B41F07F4CC86E4ULL,
		0x0F1B9A980A3E1FFFULL,
		0x58C658AED7281AE3ULL,
		0x058825035B781C13ULL,
		0xE925F61BD1C58AE1ULL,
		0x5A43162DD5A37B0AULL,
		0x4ECCE9203E7FF642ULL,
		0x123E0D431955059CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF65AD9AF6D60B76ULL,
		0x4C5A714A5E7892B0ULL,
		0x613044BC98DC56E9ULL,
		0x81361804B40B1296ULL,
		0x335123B2A267B760ULL,
		0xD08CB2F5D54B4429ULL,
		0xF3BF44AB2FF70D87ULL,
		0x665155BDBB26CF91ULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B81594138C493CULL,
		0xB6B934C7BDC8BB1EULL,
		0x7ECB9BC003A79E2AULL,
		0x91EB01771B544CE0ULL,
		0xB5CC7C38B73936B4ULL,
		0x472B61A3C770F5ABULL,
		0x09EF96340240EC51ULL,
		0xE2F6BFB3D6233909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8DD54B3FC2A32C4ULL,
		0x6D94E7DAF13ABB2BULL,
		0xF6D408C625ACF426ULL,
		0x134342A919FDCCE9ULL,
		0x4B0C206ED14ADE46ULL,
		0x808EE82C7CF608A7ULL,
		0x93F4D6EC2F4B0F50ULL,
		0x4580EEB1473BAFD6ULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22539CA6F47EF397ULL,
		0x30876A165FA1EDADULL,
		0xD1AAA5A9BC875445ULL,
		0x57CCBA4AC4331FCAULL,
		0x07CB5207D72C5E4AULL,
		0xDCEBCB07846A31D1ULL,
		0xD3A5C99F34AF8A85ULL,
		0x8D74F56CF58995CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C51FA57B45A3C3EULL,
		0x99712CE3B8DC2E67ULL,
		0xDEFF920220477365ULL,
		0xAB12EB05A7860061ULL,
		0x8C697C2E8C9D424AULL,
		0x95E45D336FB6EAA8ULL,
		0xAB2D4987DA62A3E0ULL,
		0x5C1CCC735032CBFFULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC39D0CF1C9D13F3AULL,
		0x1F3B9905A5FD719DULL,
		0x2B621DFC2EA131EFULL,
		0xBAD0C4C29647BADEULL,
		0xD7E3EABE634711B6ULL,
		0xECD4C56112537C6FULL,
		0x1D9F54B73EDB1D37ULL,
		0x8C70BECA650214FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC39D0CF1C9D13F3AULL,
		0x1F3B9905A5FD719DULL,
		0x2B621DFC2EA131EFULL,
		0xBAD0C4C29647BADEULL,
		0xD7E3EABE634711B6ULL,
		0xECD4C56112537C6FULL,
		0x1D9F54B73EDB1D37ULL,
		0x8C70BECA650214FBULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C62949621D6C5D5ULL,
		0x3699166C36A6A5B5ULL,
		0x00F5EB064C567B7DULL,
		0x3EF7AC0AAEAAF093ULL,
		0x986EEBB6C7905ACBULL,
		0xDE2F9D36D6953A8BULL,
		0x6433E475AAB9D21DULL,
		0x1F51C25D5489FBF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BFEEAD7785170AFULL,
		0xF2939E6952010D84ULL,
		0x90523931052C7E74ULL,
		0x50948DC0B5710395ULL,
		0x1E68EF918E430289ULL,
		0xE4367E1897A37071ULL,
		0x926993C1C1DB73C7ULL,
		0x7397B4A03506B003ULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A8AEB9C4B695D5DULL,
		0x80763F39DB3515CDULL,
		0x776B221845DAA82CULL,
		0xEF535DDD2679FDB0ULL,
		0x6DBA8CD9C0084D84ULL,
		0x03A997B4023AEED5ULL,
		0xB7EE409DEBC362C1ULL,
		0x349E6D5AFB960216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F257CBA79A1A3F7ULL,
		0xA1F917A42C34C81DULL,
		0x7168C0374F4FA6F7ULL,
		0x24A3F0AA96AE15BAULL,
		0xFFBC82A9E30FA3A7ULL,
		0x04FD8CCF9FD35E27ULL,
		0x636881FA1931B331ULL,
		0xF94AD075244A8CEAULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5F7CC0093FF3E0BULL,
		0x13D913651E1BBD75ULL,
		0x67D0B5F08BD493C5ULL,
		0x234E6E30470FD5F0ULL,
		0xA883DE7F9AFB8536ULL,
		0x316F1C96F5D72F82ULL,
		0xD716E7C454BE2228ULL,
		0x7AC15523DB2CCED3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F669B160FD70CDULL,
		0x1FA08E1F03EE638BULL,
		0xEE44EDF5509E4509ULL,
		0xBE688A103A865250ULL,
		0x29566432E2D9D3ADULL,
		0xCD50D98287A9B113ULL,
		0xB371D2DA6EBDC0F0ULL,
		0xE6AA5F76D42622AFULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99064C35C0F34DC1ULL,
		0xBB4248FC6FD8F7E7ULL,
		0x077B5B87DD3ABE90ULL,
		0xD0CF90E8BD65EA45ULL,
		0xB6D51D997C7286E1ULL,
		0xB1786BDF3DD22CB5ULL,
		0xC825E25C8257EA6BULL,
		0xB0F06150A65DBCB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99064C35C0F34DC1ULL,
		0xBB4248FC6FD8F7E7ULL,
		0x077B5B87DD3ABE90ULL,
		0xD0CF90E8BD65EA45ULL,
		0xB6D51D997C7286E1ULL,
		0xB1786BDF3DD22CB5ULL,
		0xC825E25C8257EA6BULL,
		0xB0F06150A65DBCB1ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD34C6825B0FB1080ULL,
		0x5A4282FD82DDC106ULL,
		0xA8C6AF3953E32B7CULL,
		0x01CC6D1CD95F8B2BULL,
		0xD2739960F0D94785ULL,
		0x48A6928A071A6FCEULL,
		0x991EC5768AED3CFFULL,
		0xF049A11C1F2F2AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x496AE4BA1AAE8265ULL,
		0x27BEB8C4FDD29583ULL,
		0x9661C816402E547DULL,
		0x2188FC17608582D7ULL,
		0xCFA953DA2C75127BULL,
		0xB79DDF059EF12616ULL,
		0x46E8095340556321ULL,
		0xB5D2FB674200442CULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54BAA2634606785ULL,
		0x366E498D302E525BULL,
		0xC396C9E786E651D4ULL,
		0x5AE8DA0C05E8BF9DULL,
		0x2FAE2FF67CA8DD6EULL,
		0xBB4A7B1565B73E0FULL,
		0x63C3A5BB4457ED0CULL,
		0xB97E7B8AD4C03602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425BA57CCF889B64ULL,
		0x42EB9105C9F0AB49ULL,
		0xA0449AB7D73DC793ULL,
		0x667C22355387E132ULL,
		0xC929DA1314790F22ULL,
		0x038B9469B9EB30D4ULL,
		0xFC254801A2E5F92EULL,
		0x22D1AD73C8C9B958ULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EE90291F04FD5C4ULL,
		0x254BA7B302D19A31ULL,
		0xB3AAD630D142327FULL,
		0xDC18B1D5F3C9F687ULL,
		0xA2D2FB6A2F13574AULL,
		0x8E76C4E1D9C278FBULL,
		0x775AB6B7FEC40707ULL,
		0xDCB945A5A834FCBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9F6EA0A5C6CD17ULL,
		0xFEB1C98E25B34976ULL,
		0x4DEF5C82883C2D5DULL,
		0x9B8A1E691F41087AULL,
		0x5D12AB56C9702E56ULL,
		0xAE84CDFA411B2B9BULL,
		0x72E6F33018BECA44ULL,
		0x11BE9BEA049C57AEULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDDEF6017043C6ABULL,
		0x470D5D3B3011EA97ULL,
		0x319850A264604717ULL,
		0x8E9C91E3F82BCC19ULL,
		0xEFE5D9672235A01DULL,
		0xF4FF87F7D72182DEULL,
		0x325BFCBEBE9A66F0ULL,
		0x888223D227EB59F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDDEF6017043C6ABULL,
		0x470D5D3B3011EA97ULL,
		0x319850A264604717ULL,
		0x8E9C91E3F82BCC19ULL,
		0xEFE5D9672235A01DULL,
		0xF4FF87F7D72182DEULL,
		0x325BFCBEBE9A66F0ULL,
		0x888223D227EB59F5ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x073FD990D8F9F46EULL,
		0x75CB25DE9A8623B1ULL,
		0x6491E010BAA290AEULL,
		0xCC59DF49D2DA33ECULL,
		0xE9E82B058BC8A299ULL,
		0x0F57B30421956E25ULL,
		0x89A0C01EE11C0E0FULL,
		0xC53A73980E6769D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90688E57BBBC9AA7ULL,
		0x74C0765433D3830BULL,
		0x18681BBD6525E4A3ULL,
		0x2FD349C9FB8B08D5ULL,
		0xCC13F36385641905ULL,
		0x6903FD17E538FEB2ULL,
		0x8D715141C47EDF9FULL,
		0xED584AA12765D2A7ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E1361D05071EC65ULL,
		0xE236ABAAF274403FULL,
		0x5FBDEDC3B1BDF674ULL,
		0x017C1E294CE168E9ULL,
		0x3FE4D6B7B035F05AULL,
		0x9A37153C12C848CAULL,
		0xB72236F419409E99ULL,
		0xCF23530BA5A577A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57325951F1E6AEE6ULL,
		0x559B4792CFE3B9E0ULL,
		0x6FC2B2444C1E62C1ULL,
		0x099434834CD81BCFULL,
		0x481977CA295BD499ULL,
		0xA339051F8C9B8483ULL,
		0x73130CB5FD1B92FCULL,
		0xBE01CDA72DA1B7E9ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE228B2712F1A6BADULL,
		0x48E26B073B00A647ULL,
		0xF342D880F51284E4ULL,
		0xF89366A7AFF0FED1ULL,
		0x64A2936DA03D3D0CULL,
		0x2D41A4AA54AB7D97ULL,
		0xC5B4747B3BF01DDDULL,
		0xA9AACCD578052242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516EF522C3E7879CULL,
		0xF375B3630D8B866AULL,
		0x2A2D09598F1672EFULL,
		0x8FEF66D78EBC5147ULL,
		0x9F100482D04935B2ULL,
		0xC6228078D438745BULL,
		0x17BFDFFA0902CC5FULL,
		0xBC245BA70B16B347ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1EFDC92D01B5C00ULL,
		0xE70A234C85826092ULL,
		0x10C3E8A0E3BF4B20ULL,
		0x500BB1B47033707BULL,
		0x202B6F8031D17CAAULL,
		0x2C038D8B5A2796C1ULL,
		0x8CB92D2E5523E55DULL,
		0x290B2E5B02CF0BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1EFDC92D01B5C00ULL,
		0xE70A234C85826092ULL,
		0x10C3E8A0E3BF4B20ULL,
		0x500BB1B47033707BULL,
		0x202B6F8031D17CAAULL,
		0x2C038D8B5A2796C1ULL,
		0x8CB92D2E5523E55DULL,
		0x290B2E5B02CF0BD5ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x289CDEA247C2C314ULL,
		0x56F74A3AF5EF22B5ULL,
		0x93880FB7ED1A8ABCULL,
		0x124D425827CB5CC7ULL,
		0x88992F4446C82A83ULL,
		0xE31CF29AA0F58AF2ULL,
		0x920D4F81FAE9A365ULL,
		0x6BF799D75FD26C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19124E90EE8BD98ULL,
		0xCB884FD40C4A8C80ULL,
		0x388E37C896C4F28EULL,
		0x80C1DFA100C2CAEEULL,
		0x03484B7AA2052576ULL,
		0xA1624F8D3DBBEBEFULL,
		0xEAB6CF9836EAAA7DULL,
		0x72E66DD8855799A6ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B02B24835B5E6A1ULL,
		0x1B38EBE42A7CB48EULL,
		0xF9A9913226A79DB9ULL,
		0xC9D1B7B4D17ADB9AULL,
		0x77795F703E07FDCDULL,
		0x0068AE5DC21B5741ULL,
		0x540BE4DFE6AA0AB3ULL,
		0xC5ACE8B93FF46287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC48A093E017A79ULL,
		0x997F041794CDBC2CULL,
		0x393C38944CF50256ULL,
		0xA035351E920E778CULL,
		0xE9E465BD08E96479ULL,
		0x041D5C194AFDC6C7ULL,
		0x4BEEB3C804D93FA1ULL,
		0x9DC48F4BE64B3749ULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD71FDBCEA2B836B7ULL,
		0xAED3884CB7FA9BB2ULL,
		0x97C77BACF2EE12F1ULL,
		0xA86B57990E407281ULL,
		0xDD74BB825D994D00ULL,
		0x8D4491BAF0FE2B48ULL,
		0x3545C0625ADE05CAULL,
		0xCA8C770B710C1CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x031A65EBB1B24C44ULL,
		0xA00BA193A8B4947AULL,
		0x3D209EC35412B86BULL,
		0x92307BED50BAE20AULL,
		0xA3DE7CC5765A8642ULL,
		0x386269E068DA5C7CULL,
		0xF25642253C3C06B1ULL,
		0x16CFE4BC075553B6ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D61FAE85B88C141ULL,
		0xB83AE59292CF2A03ULL,
		0x544C8ECA6FFC933DULL,
		0x3F46DC3A4C8B877FULL,
		0x301F50C80C133943ULL,
		0x29C49B8379C0041AULL,
		0x3F25CCD8312BB5A4ULL,
		0x866211F09FA7B558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D61FAE85B88C141ULL,
		0xB83AE59292CF2A03ULL,
		0x544C8ECA6FFC933DULL,
		0x3F46DC3A4C8B877FULL,
		0x301F50C80C133943ULL,
		0x29C49B8379C0041AULL,
		0x3F25CCD8312BB5A4ULL,
		0x866211F09FA7B558ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A714C92DBB8092ULL,
		0x8A7AD708747F9D8FULL,
		0x53CE929BA5A55D45ULL,
		0x0B004B672137B70EULL,
		0x83889F4EB15E1848ULL,
		0xC195A6C6CAF08F68ULL,
		0x7DE777AD2C3FAA2AULL,
		0x036E3E74518A7CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF7DE0A5A15A48DULL,
		0xD460AD6F7E658BAEULL,
		0x3CD1583F48245564ULL,
		0x015B75E4E6F7988FULL,
		0xE70D6EC15D64E688ULL,
		0x7D69A7B5C31E531CULL,
		0x8CB7D7C1941FBB2CULL,
		0x7DF5C5A0183CFC90ULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431243FEA7C97A88ULL,
		0x0CE76CB43D0B4BB3ULL,
		0x5D26AA4CEA16D607ULL,
		0xD000FDAA8CC7C572ULL,
		0xF577873D88EDD67DULL,
		0x3568BA98EF3F268BULL,
		0x07076739A474FE10ULL,
		0xE8D2BB1850084519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FEF11EB8E678FFULL,
		0x53A0927692B38981ULL,
		0xBE690C71817BD906ULL,
		0xF425CCEAB395B8C7ULL,
		0xBFF690F96BEA38DBULL,
		0xC0584EA893A267D3ULL,
		0x32A7B02BBE2A7ABEULL,
		0x1E305C4E43B4E645ULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4E34DDB8462B225ULL,
		0x468CDEA234FBF10FULL,
		0xAE5732333F0F8D34ULL,
		0x145E02114639C22AULL,
		0xE14F41F83FF6FCEAULL,
		0x4423E279B1D6D61AULL,
		0x80A5A6699844E7F6ULL,
		0x1C645E906F133547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C4DE8CB883A5FBULL,
		0x5313EC7C228C83AAULL,
		0x3CD7752455198225ULL,
		0xBD59A7CDAB776023ULL,
		0x0146297F63C093CCULL,
		0xCC1F7BF1E070F6B6ULL,
		0xDF9B5FA92D911BDFULL,
		0x09882550FD1CC8FCULL
	}};
	t = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75B1E2A299E56D3CULL,
		0xAB51B8C288C95C7DULL,
		0x2BB184A2361A5D1FULL,
		0x8B47A9B983A1148CULL,
		0x7654CC1585223735ULL,
		0xC09818018AC6D077ULL,
		0xD6B112C447FFD8ABULL,
		0xD6BC29F5214D184BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75B1E2A299E56D3CULL,
		0xAB51B8C288C95C7DULL,
		0x2BB184A2361A5D1FULL,
		0x8B47A9B983A1148CULL,
		0x7654CC1585223735ULL,
		0xC09818018AC6D077ULL,
		0xD6B112C447FFD8ABULL,
		0xD6BC29F5214D184BULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31C3AC480D665B31ULL,
		0x4A6CAB089E2E96CCULL,
		0xB4E6140C282F0018ULL,
		0x1A1A665A75EE30AAULL,
		0x3B1F0F8FC6681F4EULL,
		0x12C1CE2DB6D83BF5ULL,
		0x40EDAC944D31FE8FULL,
		0x306DD901F9187563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB668223DCB3F3EEULL,
		0xAE02565471148305ULL,
		0xB61F9246D91CB917ULL,
		0x01924E4C6356A9D9ULL,
		0x03FD101DBB241E09ULL,
		0x841912544A84919DULL,
		0x1B470559D6C80545ULL,
		0xBAD95E67B240A9B9ULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC76D1A88FE324FC6ULL,
		0x042159CAD5D9A368ULL,
		0x49A64D241F1F6BF1ULL,
		0xD35D5B6657482A6BULL,
		0x345F942FF2EDB88CULL,
		0x88AB0AFBBE9C3D95ULL,
		0x8D4F0AD81BE28EB7ULL,
		0x25097F0C829D19D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955831596D1B538BULL,
		0xB1EB8D831F93580CULL,
		0xA6488C55A9D91859ULL,
		0x76FF01149AC351D9ULL,
		0xDB23811E061B8AABULL,
		0x0F43370E3CB11C22ULL,
		0x20E5E336216AC061ULL,
		0xA0B37C22F674BB6CULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FA9CD781A8C7355ULL,
		0x2601F82F9EC70ACCULL,
		0x587696BCF73A7DFAULL,
		0xB15C51A5288103B2ULL,
		0x8C427109B17A89A7ULL,
		0xD837D33DD332C114ULL,
		0x12653A296FCBE101ULL,
		0xC08B413CFF65157CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F12754982B9836ULL,
		0xAC6D05102F785912ULL,
		0xD99477265EDD7756ULL,
		0x0BFB92289AF5934BULL,
		0x90331BFCAA000B13ULL,
		0x5A7006D5E85B9945ULL,
		0xDE37A042C9CEF9E1ULL,
		0xE7ED63ABCC02CC14ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1567042432B9A2C8ULL,
		0xE2C0A13333FE4126ULL,
		0xA36D3F5284AB2E50ULL,
		0x093EB43B4B52109DULL,
		0x857F6220CBE81B46ULL,
		0xC4195EF5F2C80191ULL,
		0x205F9985AAB9B53DULL,
		0x390636C4752E2AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1567042432B9A2C8ULL,
		0xE2C0A13333FE4126ULL,
		0xA36D3F5284AB2E50ULL,
		0x093EB43B4B52109DULL,
		0x857F6220CBE81B46ULL,
		0xC4195EF5F2C80191ULL,
		0x205F9985AAB9B53DULL,
		0x390636C4752E2AA3ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x631AAAE2BA82993CULL,
		0x180B6AC3FA4D0152ULL,
		0x931E90CD4AF60389ULL,
		0x006F39AAB291D11AULL,
		0x20C70627A0E62924ULL,
		0xBD45FAC4F211E196ULL,
		0xB181E73B1C29A95EULL,
		0x247BEE1D6B6DE2D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1E947DB7900AEFULL,
		0x3B1459750CA770C7ULL,
		0xD70CDE5DA158313FULL,
		0x6116913F57040DCDULL,
		0xA28E77B05BBCD703ULL,
		0xFEF8129A2FE65470ULL,
		0x3719D6AD8672E5B4ULL,
		0x86BD015899C5F22CULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AE40882B05A32E1ULL,
		0xBDC1506366171A11ULL,
		0xBCE47D2129980A56ULL,
		0xA3342224645F760AULL,
		0x26A0A9929AEDFF71ULL,
		0xE146B304C053FD97ULL,
		0xA9D04D2E65459B7EULL,
		0xD0BC54E30F9DA6FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D78F9DFBB1C999BULL,
		0x03FBA1F20F439569ULL,
		0xAED0AD8E48D780A5ULL,
		0x007318B8A1538745ULL,
		0x976448A2947B4360ULL,
		0xAC4A44BC60486B7EULL,
		0xC9B16E56F5CEECE4ULL,
		0x0214AEC4AF33DABFULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38195D30229FA58BULL,
		0x8F68E5782AA8DE09ULL,
		0xD7862108ED8D8A01ULL,
		0x41C15DABBC7998D5ULL,
		0xA65D034CA650D2B4ULL,
		0xC63FFA0C274402B5ULL,
		0xA6662E7CBCFDED33ULL,
		0xB23AAB1DA55195E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D069682811F49ACULL,
		0xE5BE9B622AD1B25CULL,
		0x5B1BCDC5D3C3D585ULL,
		0x0E05F402DABDDAAFULL,
		0x7AB0B6D1892171A2ULL,
		0xC54C30E31F545679ULL,
		0x6618B848F5137559ULL,
		0xAD000389E4BD3911ULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DF185ADC9D5267ULL,
		0x349E422FBAA49BACULL,
		0x1B221BECC886EA08ULL,
		0x0580F6C576D676C7ULL,
		0xE2842A8D3BB6C453ULL,
		0x4BA2290CF9226901ULL,
		0xF7A2EEFDD758498FULL,
		0x8F36591E10F6F6CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57DF185ADC9D5267ULL,
		0x349E422FBAA49BACULL,
		0x1B221BECC886EA08ULL,
		0x0580F6C576D676C7ULL,
		0xE2842A8D3BB6C453ULL,
		0x4BA2290CF9226901ULL,
		0xF7A2EEFDD758498FULL,
		0x8F36591E10F6F6CDULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x876E3ECD7BD7AC52ULL,
		0x29EAFC4563AA0489ULL,
		0x1E5EF21BE832564CULL,
		0xCCA25630D245E00DULL,
		0xB446D91F8BD17103ULL,
		0x74CF1B0DEFAE0778ULL,
		0x86518399BBEA2B8CULL,
		0xCB63AFA2F0E5A49AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D52EDBD94D3AA95ULL,
		0x26A388A80B7C818BULL,
		0x48DDA4771B2A339AULL,
		0xA9A4C3ADA91A9904ULL,
		0x9DB16A39D6C1AD50ULL,
		0x04B1D6250448C821ULL,
		0xA149A438D8A21429ULL,
		0xE3C3690D682A8E75ULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3237735B75C309FULL,
		0xA7F5C021784C0B2EULL,
		0xF28509E0FF4839D3ULL,
		0x7B44A042CD2D355EULL,
		0xD64DA693A5CCBF7DULL,
		0xB52132EC6F7971CDULL,
		0xA477D78C01C03358ULL,
		0x9319038967C9F158ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0539AB2143A0A2ACULL,
		0x1B308C2034A2F820ULL,
		0xDDA166724C7B9557ULL,
		0x150C5AAAED416C93ULL,
		0x4088C983E67E0CBEULL,
		0x47E051BB4792FF06ULL,
		0x5603183285B47996ULL,
		0xD98C5F0381784E88ULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD6F56CB502C8F38ULL,
		0xAEFD75C885970423ULL,
		0x552C1E41490F27D3ULL,
		0xF8179FD0E600BDCCULL,
		0x74C07BE1D9AE841FULL,
		0x78549EED1A0992A1ULL,
		0x9BD73493FC91DCC4ULL,
		0xBEC5166A3FC9F0C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB296DA551A793F7ULL,
		0x11C73EC2278BFED3ULL,
		0x908F7B7A07BF1C5DULL,
		0xF01D5F76863BE3E8ULL,
		0xE6235290EE14CCECULL,
		0x2C7B51400C49D997ULL,
		0xEF69B0A8AC38BD97ULL,
		0x27F8F6A73F9C9912ULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02F6D398A0D6886CULL,
		0xCE5EE5A87DF3167CULL,
		0x7BC7AAC5C0CDEFA3ULL,
		0xC5BD8C9796D514E9ULL,
		0x79A0138A849DC1C1ULL,
		0x888778E249BFCB7BULL,
		0x7AB53CA0EF45448AULL,
		0x9A64B520077C70A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F6D398A0D6886CULL,
		0xCE5EE5A87DF3167CULL,
		0x7BC7AAC5C0CDEFA3ULL,
		0xC5BD8C9796D514E9ULL,
		0x79A0138A849DC1C1ULL,
		0x888778E249BFCB7BULL,
		0x7AB53CA0EF45448AULL,
		0x9A64B520077C70A7ULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40A13275EF6DBAFFULL,
		0x5D5D0FFFE4B9BF8BULL,
		0xC226B6BB3FDE9CB0ULL,
		0x7A6A10D804BFC5B4ULL,
		0x34129019B3FDE67AULL,
		0x1DC609D1BFAF96E1ULL,
		0x403E1D3592C14619ULL,
		0xDA9C306EF9B5F5C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA02359AA6CB32ACULL,
		0x2DE3722C5FCD9C63ULL,
		0x6EEA5EA84F15A7A1ULL,
		0xC1654AEF8F03302CULL,
		0xE6AF7499C00D3EEEULL,
		0x762DD370A9A38166ULL,
		0x1AEC1FEA9EFCE76AULL,
		0x89FA1555E0D24FF3ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACBDA65AFBE0B137ULL,
		0x38B5537462B4E281ULL,
		0x6DF952D3F2E36023ULL,
		0x2BB1386F7F243322ULL,
		0x2FAC9F5527C096B2ULL,
		0xEB5B5B7D8A07511CULL,
		0xDC87AFE8F85E2895ULL,
		0xAFB7C2ADD5B3A672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119227B8524BC433ULL,
		0x2FAA65A484C70B5EULL,
		0x85FDC55F65FDE79BULL,
		0x98C3A6BF8C797F12ULL,
		0x1B1F9CBC7AEE9617ULL,
		0x58DB3122F6705EE3ULL,
		0xB9B7627E3EEBF8D7ULL,
		0x32527C9D3EB59180ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB09846F3E48B1673ULL,
		0xC25B03B2F214418DULL,
		0x4CF8E70ADAC1D924ULL,
		0x4A09407BB390F8F2ULL,
		0xCD212415ACEC612CULL,
		0x343889AB8AB6970AULL,
		0xD58AFC62EF014E0BULL,
		0xA5513C543BE31509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77DAECFAB54165FAULL,
		0x2C115A761BF70374ULL,
		0x6FC711EFCD5FB11BULL,
		0x75428E1627F8BF02ULL,
		0xDD007067EFAA38F6ULL,
		0x727F1D8871C7F795ULL,
		0x476C68E8CDB37001ULL,
		0x98C47979F366A0CCULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F466F3A0202681DULL,
		0x9E101B33F09BBE17ULL,
		0x3D152370128A7036ULL,
		0x99582CC9FAC707EBULL,
		0xD3EA791BF702BD56ULL,
		0x57F8E1855C2E3D5EULL,
		0x242EDD6E4B720BAAULL,
		0x3F80F4E54EE5D227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F466F3A0202681DULL,
		0x9E101B33F09BBE17ULL,
		0x3D152370128A7036ULL,
		0x99582CC9FAC707EBULL,
		0xD3EA791BF702BD56ULL,
		0x57F8E1855C2E3D5EULL,
		0x242EDD6E4B720BAAULL,
		0x3F80F4E54EE5D227ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC46542BD7EED724AULL,
		0x53D88601A813DF4BULL,
		0xCC446F7C3E0B833AULL,
		0x5E71E87C9BB41968ULL,
		0xCC5E502FF45BE356ULL,
		0xAC395AD587B35AC8ULL,
		0x16AFC27EEA08BFBDULL,
		0x01E7132552CCF339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F84B6CB622B604ULL,
		0xFE61DB1D28D9DBFFULL,
		0x37213B218519B4EBULL,
		0xB7E3955B117A82E7ULL,
		0x0CCA5E1A73B088C6ULL,
		0xD26D0B7CEBE84E72ULL,
		0xA2455F773D388CDAULL,
		0x462E5393BEB7B331ULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA292F9A4DFDC6A15ULL,
		0xF6270E169996FC83ULL,
		0x993DC198ADAC4A87ULL,
		0x646A15DAB5BFD329ULL,
		0x608A047A307C1997ULL,
		0xB22EF9653ECB69F1ULL,
		0xC94C206DF341A4C0ULL,
		0x8D1DE479D826EB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD285CC878FC1446EULL,
		0xD1E56F5CABA914F1ULL,
		0x980984A8B26E4FEEULL,
		0xF5A13C9116BEA856ULL,
		0x61A44BB15FD2BCB8ULL,
		0xE7F822ED9A37154DULL,
		0x58B58E602B59B2EEULL,
		0xB428FFF7117B3284ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDE8804B31334289ULL,
		0xC0CCF8E400FF2F3AULL,
		0xA8B373D849E6E0A0ULL,
		0x8BA59F52754E8265ULL,
		0x6CA187676CFBF213ULL,
		0x17D8336DAB9B2FC6ULL,
		0x9174E9746A24B2F4ULL,
		0x26A6105E86C577B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB01126A3223C80FULL,
		0x429A44D0D97D83F3ULL,
		0x7F119513C39134F8ULL,
		0xC5EDF9D056A1AA3EULL,
		0xEF60D1FD11567FECULL,
		0x3ED4E83B63E8CABEULL,
		0x8490D7CF125B0630ULL,
		0xF12B42BA8455C975ULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9CC0DFC7FEC1B94ULL,
		0x7602A75711EC1ABBULL,
		0x019CC95F6079B797ULL,
		0x178146A75FD4BE86ULL,
		0xC8371A0059E583CFULL,
		0xBD5052D19E1ABD3EULL,
		0x202CEFD78992B8C1ULL,
		0x46F2D6C176F0A803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9CC0DFC7FEC1B94ULL,
		0x7602A75711EC1ABBULL,
		0x019CC95F6079B797ULL,
		0x178146A75FD4BE86ULL,
		0xC8371A0059E583CFULL,
		0xBD5052D19E1ABD3EULL,
		0x202CEFD78992B8C1ULL,
		0x46F2D6C176F0A803ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8E58F171E16A960ULL,
		0xC1DF7959BB5C5216ULL,
		0x13293229FDA7E8F5ULL,
		0xC6D690079079831AULL,
		0x7E433FE5A377D181ULL,
		0xB25663254FF9EC54ULL,
		0xA01F714E42BF65D5ULL,
		0xD49F0B009E943F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A59D71F1F89097ULL,
		0xB9849012A6C55C10ULL,
		0x834D59208EC25E8AULL,
		0x8FF632C2783A8BD8ULL,
		0x16735C092E7C6F23ULL,
		0x517B3C5CB7A7F807ULL,
		0x1320874FB25A62E8ULL,
		0xBC42B8121B068B72ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99D66FACA6424E44ULL,
		0x2B36954B33BC2513ULL,
		0x1AFDB843BB6A9265ULL,
		0x3D7F4C1D3EC6BA00ULL,
		0x4A810EB1EF23B4DEULL,
		0xC428E689485DEF01ULL,
		0x06173E53CEA765FAULL,
		0xBDB5C894F7B012CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF880AA457180D0FULL,
		0x184963A2DB0892D5ULL,
		0x3CC1EAF026FE65EAULL,
		0x08F15B853A4EC8D1ULL,
		0x117A6907A8622D4AULL,
		0xC999D0C364E534E7ULL,
		0x045676E3649B3810ULL,
		0xF79679DF6DEFE763ULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9F3BA0F240377EEULL,
		0x9E4AC66FEB3F070BULL,
		0x5D83CA068EA52A60ULL,
		0x6D2A49F9B7C4C315ULL,
		0x70DFAB1D0B62D764ULL,
		0x5F8B5C805FC0EF37ULL,
		0xD63D8B2DE73D62C1ULL,
		0x76E16BCF587759B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD377B08C5EB488FEULL,
		0x0D8CAE3C631A7CC7ULL,
		0x41DF28B6B3949CE5ULL,
		0x4FE1FEFE32E2330FULL,
		0x3D26456DB9002A69ULL,
		0xAE5FB106F377379FULL,
		0x55E5FBAF31B555CBULL,
		0x6DDA19FAF239E7ECULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BC82AD8A98BBDA5ULL,
		0xDA4B3DCDF4C75D04ULL,
		0x9FDE6561F29730B2ULL,
		0xA3F7D89E56F021A1ULL,
		0xA793D01DB18D9801ULL,
		0xC614B2CC26C3CBD0ULL,
		0xE9A3476C2A64C6DCULL,
		0xB13F09D7AEB0870AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BC82AD8A98BBDA5ULL,
		0xDA4B3DCDF4C75D04ULL,
		0x9FDE6561F29730B2ULL,
		0xA3F7D89E56F021A1ULL,
		0xA793D01DB18D9801ULL,
		0xC614B2CC26C3CBD0ULL,
		0xE9A3476C2A64C6DCULL,
		0xB13F09D7AEB0870AULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669290062F33AA5EULL,
		0x0FF5FFA28217F00CULL,
		0x4F801149A05BE959ULL,
		0x52E4B9EA95DDDB9CULL,
		0x51FE85BD3EB4A333ULL,
		0x4A62B84DA2157BD7ULL,
		0x3E04B6AC816CA976ULL,
		0x2283820BE21560D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA207C49B4C622CFBULL,
		0x99014DC68424E837ULL,
		0x8E9E1A3B767C1DFCULL,
		0xFCC51568A5C2BA28ULL,
		0x434D1B2B0635FFBAULL,
		0xFF097C594122F412ULL,
		0x4F1A43022C8FEA9FULL,
		0x94FA93A8B318E3FAULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FC92F7D8A861EA5ULL,
		0xD0C497BCB0EBBA08ULL,
		0x91776DD9757B34BBULL,
		0x3A91878B3BD1B638ULL,
		0x1CE42DF03CD0C9F4ULL,
		0x9B5E37B8DFFC015AULL,
		0x7071480C64B0F2B7ULL,
		0xA857C8B712E05543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C900E4392D2779ULL,
		0x238D4C55315A5E70ULL,
		0x989ECDE74C623D86ULL,
		0x7D832EECDC04915AULL,
		0x3B00EDE4A959212CULL,
		0x338E42153EBFB74CULL,
		0xBA062E5C2D656E87ULL,
		0x4DB128B6D70DD544ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBB0E3B13DD3F1BEULL,
		0xEB621B4877DAC609ULL,
		0xACC58203A5A38EFFULL,
		0xB0E209B7DB8E20CAULL,
		0x5CD7D3FF1C0F6BEAULL,
		0x6202173C09DF1EDFULL,
		0x6366A6D72CD77363ULL,
		0x3444E151C4809B62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B269D1E520A4345ULL,
		0x7203C68B7C6FA4BCULL,
		0xDB719C848DAF19C7ULL,
		0x240CF9BE31717F66ULL,
		0xE95AA31DF1D68D69ULL,
		0x47E5E64CE67F474AULL,
		0x3545BA3624C5DAB7ULL,
		0x10CC7C36D8FE90A2ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x649B371DD16F2719ULL,
		0x2AEC553B4D877B99ULL,
		0x5BEAAC1561038B5EULL,
		0x0FC05FB8E041F0EFULL,
		0x6B9440F3AD00FC7DULL,
		0xF3DBD238D9CB7C9BULL,
		0xCB97239A4C62BACBULL,
		0xDFB1F6028A2C98B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x649B371DD16F2719ULL,
		0x2AEC553B4D877B99ULL,
		0x5BEAAC1561038B5EULL,
		0x0FC05FB8E041F0EFULL,
		0x6B9440F3AD00FC7DULL,
		0xF3DBD238D9CB7C9BULL,
		0xCB97239A4C62BACBULL,
		0xDFB1F6028A2C98B4ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x990A6A12AD1BCDF5ULL,
		0x095B2B2A8BBB356CULL,
		0x87D9012B92077331ULL,
		0xE787A4679BE7BC9DULL,
		0xE51351E56F2276DEULL,
		0xB17547423290116BULL,
		0x4B224D68C647F335ULL,
		0xA80322F7F0E3CB4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8B761E4A33D3E4ULL,
		0x7EA4242067DFAAA9ULL,
		0x4614C6915F4D0D3CULL,
		0xDAEEC52069AD2452ULL,
		0x7A2B9C481C58BE1FULL,
		0x2F15884A2752B6BFULL,
		0x75DC39355BDF80A6ULL,
		0x076268CCD9D3E3FFULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x480ED49F86B9BAAFULL,
		0x198E8BE9A41D114BULL,
		0x9D7034F0E67751E3ULL,
		0x02027B99C569725AULL,
		0x17CFA4E6A44205AFULL,
		0xBC511F5C869A63F4ULL,
		0xB0840344AE2876F9ULL,
		0xEF554182B9C0DCEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF7DA35400BBB10DULL,
		0xFB108A1617473414ULL,
		0xD93B0169603C0C12ULL,
		0x9EE6D383420A3877ULL,
		0xC70139EF5714DF65ULL,
		0x1BDF5E673BD79F8FULL,
		0xFF6B738A57931A3AULL,
		0x112C2EEB505346A8ULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7CFB000A9A7C181ULL,
		0xE521F28AABD7B9E0ULL,
		0x724E1324D9655E87ULL,
		0xF2D9876259746D69ULL,
		0x45DD29B8273AE920ULL,
		0x612ED755D7BDAD6FULL,
		0xA357BF7FAFC72E55ULL,
		0xCBAAE665A79B7743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9614020B4DF8BC2ULL,
		0xB60B8997FC74E7F1ULL,
		0xF9169C908DEDDDCCULL,
		0x3C538EC9773CCC3DULL,
		0x5303858E2ABD3A74ULL,
		0xA3C1877D64922848ULL,
		0xE73604E5DDC2F310ULL,
		0xECBB930778CF6BE9ULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC040A25727D6C1FFULL,
		0xEA7C3D1FB588D6D4ULL,
		0x82A70F1A02F8A33DULL,
		0x3999EA073FF673DAULL,
		0x2D68D14E70280E58ULL,
		0x6EFA89D40E0BD3C2ULL,
		0x257C94DEFA03AA2CULL,
		0xC9251BFA8C6F73A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC040A25727D6C1FFULL,
		0xEA7C3D1FB588D6D4ULL,
		0x82A70F1A02F8A33DULL,
		0x3999EA073FF673DAULL,
		0x2D68D14E70280E58ULL,
		0x6EFA89D40E0BD3C2ULL,
		0x257C94DEFA03AA2CULL,
		0xC9251BFA8C6F73A4ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC27F8B22EE4AFF12ULL,
		0x6C2DE43DA79C76DBULL,
		0xF0448F9C06FF9670ULL,
		0xB2C14E2AD486D33EULL,
		0xFD74C6DFAE695D4EULL,
		0xD42C53A8B0468BCAULL,
		0xA3FBA1315513922CULL,
		0xF103C1FCA07B4A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841ED1A30C10ECEEULL,
		0x90AAA79549032A0EULL,
		0xA735A0175306CDC1ULL,
		0x20E83985AC3DF638ULL,
		0x35B257B9E58A6034ULL,
		0x908E04988F493F02ULL,
		0x318B388E7056F65CULL,
		0xAC477B96AA781581ULL
	}};
	t = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x782A87337FE5AE83ULL,
		0xA7B1C41DF220F4BCULL,
		0x71F56884DEE9C1BEULL,
		0xE3D0277C1C5D3249ULL,
		0xC1F36A2AECBC63E0ULL,
		0x64D3F72BDE9D11EBULL,
		0xD7BECF1112CA42B1ULL,
		0x3B04957F30A31BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78071F8E008A4B4FULL,
		0x3EFA1FFA5577FCC6ULL,
		0xB5D2F9588BF80B7AULL,
		0xE101D76EDE3B58B9ULL,
		0x49E372512A638B67ULL,
		0xE52E62726A11A12BULL,
		0xD0209B65CEBA5B2CULL,
		0xD690BFBE5DD2FF08ULL
	}};
	t = -1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B32939C19865DC9ULL,
		0xA8F1071938908218ULL,
		0x47590218DE20EC33ULL,
		0x8830497715282291ULL,
		0x5FF935F942BF9A4DULL,
		0xC1A50B23A959505EULL,
		0xC5274A0A5890BA9DULL,
		0x737E0A6BD3326D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D75A843E14309FBULL,
		0x70B420B2E42121EFULL,
		0x60C79C6193635588ULL,
		0x6F60CABEB0D7CE6DULL,
		0xDC507A52643D2B34ULL,
		0x4C61C2EBAE1C79C6ULL,
		0xDDDFE4FFAC3ACD1DULL,
		0x394B43C6A41DF90DULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE994933FD031BB7EULL,
		0xC7A81ADE773594C8ULL,
		0x2EB9333B2E3D814CULL,
		0x2CD2EEFBDA015FB0ULL,
		0x2D7014BE343872CFULL,
		0x70BE5F30AF8E3455ULL,
		0x3074A03318E93252ULL,
		0xB6559702E9F4B015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE994933FD031BB7EULL,
		0xC7A81ADE773594C8ULL,
		0x2EB9333B2E3D814CULL,
		0x2CD2EEFBDA015FB0ULL,
		0x2D7014BE343872CFULL,
		0x70BE5F30AF8E3455ULL,
		0x3074A03318E93252ULL,
		0xB6559702E9F4B015ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E30ABEA5C443C9AULL,
		0xB73C35585EDC58E8ULL,
		0x15B3A77502BE4507ULL,
		0xDEC71D5A0BBD5BF4ULL,
		0xADBD722BFD874A59ULL,
		0xF054E129CD5F8E7DULL,
		0xC8569B09B78C4E85ULL,
		0x4133CE078FD236B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC08918937D233AULL,
		0x0CD32EA86CABBD72ULL,
		0x67FC13D092BE0E0FULL,
		0x9C3A59D7380859F9ULL,
		0xDFA79CFD1967FE1BULL,
		0xFF923D4C17A737EDULL,
		0xC8C55C8ECD7DEAA6ULL,
		0xEB1EE3566F2CED44ULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BD1FB8534C561BBULL,
		0x5315B3D7274232EBULL,
		0xA99166840C0CB66CULL,
		0x022F6CF3E2D52FCBULL,
		0xD94071CD942FA219ULL,
		0xAAB01A5E88EC25EFULL,
		0x9CFC1052A2B4ED04ULL,
		0xC07A56D1F22787A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E044D6F99F9C15ULL,
		0xFA2F201B739BB9C2ULL,
		0x7234C67AE6979E27ULL,
		0x69ACAC433608EEC3ULL,
		0x86713AFEC13D6D7DULL,
		0x1E985E03C2447B88ULL,
		0xA4B1928346045B52ULL,
		0x800A07E1F0E217C7ULL
	}};
	t = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E60D994E6CCB24EULL,
		0xABBCD037D123ABDAULL,
		0x00FAD932BB934320ULL,
		0x4956E83830681F9CULL,
		0x5B6FE51381EB610FULL,
		0x41FEC4743AE0C10AULL,
		0x26D2203FFE3ADE13ULL,
		0xD6485AA3EFFC0A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0AE33D69D22304DULL,
		0xC978264D5DA4DC0BULL,
		0xE89013550C020305ULL,
		0x59ACCE1153D96207ULL,
		0x01F3749A7C143FC3ULL,
		0xE322DCC7FC800F16ULL,
		0xFF058B6A65D757CFULL,
		0x1DACA830A9A44344ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9E77663BAE23060ULL,
		0x68D9AE5BB0373CA6ULL,
		0x81895FE7DFEA44EFULL,
		0xA70A596C9E1D9861ULL,
		0x4B1C8DEC0C892782ULL,
		0x7401A26B33F2A3D2ULL,
		0x5B7136E9D837B03CULL,
		0x88A88657341A9B6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E77663BAE23060ULL,
		0x68D9AE5BB0373CA6ULL,
		0x81895FE7DFEA44EFULL,
		0xA70A596C9E1D9861ULL,
		0x4B1C8DEC0C892782ULL,
		0x7401A26B33F2A3D2ULL,
		0x5B7136E9D837B03CULL,
		0x88A88657341A9B6EULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EBD0769C5C7F5F1ULL,
		0x9252E7F332F33FC2ULL,
		0xCE77118B89FA5B7EULL,
		0x53F2FDA6169F8D09ULL,
		0xD5D84616CB7BAFADULL,
		0xBF4E4DA350A79F20ULL,
		0xDD47CE4DFC2A655FULL,
		0x774E1D3AB28D1CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4A689464EB9368ULL,
		0x11F01C8E1C4CB2EEULL,
		0x5B0F3C894AF92406ULL,
		0x21197680710A286EULL,
		0xD462E124D58C4B07ULL,
		0x2A63C1C76345DCFEULL,
		0x841C10F03A1784C7ULL,
		0x878B800D5BE0E27DULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46BC5B512DADE725ULL,
		0xB0E9A1B164984DE4ULL,
		0x14D82FE261522BE4ULL,
		0x4E424A4BDEB7FA14ULL,
		0xBAB23F51D5F5B116ULL,
		0x5E3F407664ED8A52ULL,
		0x9410A500AA3F4EF3ULL,
		0xCA7218D22EBA1E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921E92B8A52AACF0ULL,
		0xA5AC192D7551F317ULL,
		0x975FA60B20D0C150ULL,
		0xE1574EDBC6DD28B1ULL,
		0xC864BDE298D7E439ULL,
		0xDC6F3C6EC3E0C9E6ULL,
		0x4B125A18E91480D2ULL,
		0xEB16E7BFF15C6B5FULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF18F2B606BD83F16ULL,
		0xEB2C55011EF26947ULL,
		0xC7DF64D06E0F158DULL,
		0xEE9833B1DEEFAC08ULL,
		0x84E9DDE871813A94ULL,
		0xEF27A0F7D4651B23ULL,
		0xB5E6967A374DA07FULL,
		0x9DC34CAEC4082D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F24323FD9DB2FEULL,
		0x28161ECA99D92BA1ULL,
		0x9D4A00384CFA25F8ULL,
		0xDBCAF8B87CDE8DD4ULL,
		0x5558ADE736AB2B78ULL,
		0x37C8E9CB158E75E5ULL,
		0x5D53302AC9F05A5BULL,
		0xB0E58272AAA227A2ULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C49DE528CCDA67EULL,
		0xACB9BDAC3931CEA1ULL,
		0xB11F6DAA0D20AC34ULL,
		0x12B35DC3E948E0EEULL,
		0xD45E9FC5A2DB1AF8ULL,
		0x127504407A842052ULL,
		0x3EAAA4C4AD9EB5A5ULL,
		0x8AAEBC6306861BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C49DE528CCDA67EULL,
		0xACB9BDAC3931CEA1ULL,
		0xB11F6DAA0D20AC34ULL,
		0x12B35DC3E948E0EEULL,
		0xD45E9FC5A2DB1AF8ULL,
		0x127504407A842052ULL,
		0x3EAAA4C4AD9EB5A5ULL,
		0x8AAEBC6306861BD5ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62D6126CF8A77752ULL,
		0xD6A361D30AFD0F6DULL,
		0x3698FE78F329AC75ULL,
		0x917943EAC4F6E20AULL,
		0x95B054BFD9965630ULL,
		0x167ACA1BDCDFBE42ULL,
		0x9DC8DF71C8FBB988ULL,
		0x57E31A1A2A1044BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0429A8FAFEE64E1AULL,
		0xE2815760BA8E8DA3ULL,
		0x92FFB9B4656774FCULL,
		0x64F7EDDFC51C8280ULL,
		0x2C402F0A3D6CD088ULL,
		0x23A4B19FDAD2F1EBULL,
		0xCEDFD9DAC0CA5011ULL,
		0xCA4B7511D57BB52AULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1009DA27C62835EEULL,
		0xF495515EAC36567CULL,
		0xC7C21CC690A5E7C5ULL,
		0xD17980A71053D243ULL,
		0xC36232A6274BE84CULL,
		0xE13CBE555E76F70BULL,
		0x1E3739BC9CC9C1D4ULL,
		0x0886F910135039B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CCE0ACE2F253BACULL,
		0x31368D43CD4D28AAULL,
		0x08643F66AAA2B14CULL,
		0xFD204430827FB2C2ULL,
		0xEA1B3F6A9E3BDC1AULL,
		0x6AA093C51C1AB5A2ULL,
		0x213DA8916FA33189ULL,
		0x602B2C93793A9C61ULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF958C368D2CE457AULL,
		0xDA00901972477E0FULL,
		0x140F91060DAA78D0ULL,
		0xB5C1A3DFAE6F0D81ULL,
		0x84B3711AF45F7637ULL,
		0x3CE781B12F20588FULL,
		0x8D37BD12E0C61D01ULL,
		0x94820BA07B463155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC097CBE90B6AD284ULL,
		0x54F1415EBD69CA51ULL,
		0x2C174B7036A3B74EULL,
		0x32E9ACDC57FA1EF2ULL,
		0xCA7BBFD838D8AD27ULL,
		0x2E122E5F88B77DFFULL,
		0xF3049E47D5C9C3B0ULL,
		0xB7D7A7AC263773FFULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF937301276C303CDULL,
		0x74DB85F54164D90EULL,
		0xCD1C5288E61C17E6ULL,
		0xF820AEF254E8A28BULL,
		0x28BEB46D1CA3443BULL,
		0x612EAE7D6C7B60DEULL,
		0x031EB71B145196F8ULL,
		0x60BE2AD9D91AB1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF937301276C303CDULL,
		0x74DB85F54164D90EULL,
		0xCD1C5288E61C17E6ULL,
		0xF820AEF254E8A28BULL,
		0x28BEB46D1CA3443BULL,
		0x612EAE7D6C7B60DEULL,
		0x031EB71B145196F8ULL,
		0x60BE2AD9D91AB1EBULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2475A4FE7376B454ULL,
		0x09607AA1BD64067BULL,
		0x9958C1C8D4835154ULL,
		0xEDDBE14B19D563BAULL,
		0xC7730E5989822C1CULL,
		0x23AE73E86D81C2BCULL,
		0x814BCC77E98BFC77ULL,
		0x0851CBA8F2191AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43285D728E053082ULL,
		0x53CE38F6B16F2050ULL,
		0xCB62E8523997D88CULL,
		0xBA16FC7E9C234E82ULL,
		0xD94C1AFC210D3E55ULL,
		0xB68DBDD616E82E59ULL,
		0x78CB4FE8B63DCC86ULL,
		0xBD2EF0C4151D5390ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3C9631113E68AA0ULL,
		0xA34CF734385568CFULL,
		0x56CFA73B8954124CULL,
		0xC38773BF9434E913ULL,
		0x477FCB18A20CD073ULL,
		0x60BFCCB40F4656C7ULL,
		0xABE9809E36C2434AULL,
		0xC01C105FFB8B988CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2056B8B48ECF0889ULL,
		0xFCD7E60AC611CF3BULL,
		0x5B7C6B92223A0FCAULL,
		0x2031A274C8FA5B52ULL,
		0xC7124F673ECFA57EULL,
		0x42F1DDBCE0350101ULL,
		0xFB6F3D06E02323ECULL,
		0xEE8D48F713CC8B4DULL
	}};
	t = -1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF70CB0F60C605613ULL,
		0xF3737EFC1DCA8B3AULL,
		0xB17572DCB5147E5DULL,
		0x530024C0A8EBE29DULL,
		0xB0E7B5E92AD1E382ULL,
		0x44BD69BA24FB18A1ULL,
		0xE5E139538C75D5A2ULL,
		0x3720606564E6127EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D7376F18627972ULL,
		0xFE6A236FF749F1B4ULL,
		0x0BC6B0C4404D10E4ULL,
		0x4F97B6F53DCB2A4AULL,
		0xD36A15320C220BF1ULL,
		0x8A5B7BFE1100A8F2ULL,
		0x1EFB844D839FF2A6ULL,
		0xBF87D5A631861BC7ULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3656F47B55707DC1ULL,
		0x2FC7353CE7155175ULL,
		0xB0BF0CA96C9D7F18ULL,
		0xE476DAD22485F32CULL,
		0x056C60F868984E25ULL,
		0x78455A768791EE97ULL,
		0xBFAC8060D37685E0ULL,
		0x20886774F1A216C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3656F47B55707DC1ULL,
		0x2FC7353CE7155175ULL,
		0xB0BF0CA96C9D7F18ULL,
		0xE476DAD22485F32CULL,
		0x056C60F868984E25ULL,
		0x78455A768791EE97ULL,
		0xBFAC8060D37685E0ULL,
		0x20886774F1A216C0ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09AEDAF17DCE7105ULL,
		0x238EF54EF5DB76EAULL,
		0x8E4FDDB9FCCD517BULL,
		0x23286744F71BD1EBULL,
		0xA65E90E12A3BCADBULL,
		0x605D69A403DAA892ULL,
		0x0B8A4D72F28948E3ULL,
		0xABC09D621E71FD4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E8A04F829C3E4AULL,
		0x72F7039384DFA5F7ULL,
		0x4FB912713C9F7DAFULL,
		0xAF1058CED8730D9FULL,
		0x6F380BB5614A9D86ULL,
		0x159EFD32FB314232ULL,
		0xC568A14B40035513ULL,
		0x1365724E0075A92FULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE85F08352DDF6AAEULL,
		0x0696D0E75D48EFA0ULL,
		0x269DB162DC9F7C46ULL,
		0x4BC9213E2A6CC75CULL,
		0x59BB712ABF76238CULL,
		0xD8E869DB76D8D2C5ULL,
		0x45762B248E905D64ULL,
		0x4DAF738F2F561199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDBE86BCE802A8F7ULL,
		0x38B32A2641761446ULL,
		0x0691A3828A4A2139ULL,
		0x4F2654DE64A70436ULL,
		0x0B4CB4DB1DBAF7D8ULL,
		0x760931C68FE69BF3ULL,
		0xB306DFF41E2A47ADULL,
		0xF617CE1B12180707ULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33DB367E0ED1313DULL,
		0xB4508F1D28754E82ULL,
		0x372B035B02271DFCULL,
		0x115E38B231F5A088ULL,
		0xAF391AA4DDF78A9FULL,
		0xA1137510B03BE7E9ULL,
		0x843D337E38A7B277ULL,
		0xB846162259199D9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD272010530916A2CULL,
		0xAFF88E86BEE06565ULL,
		0xEC596F3161F8E57FULL,
		0xB45C150001DA72E5ULL,
		0xAB8D0C2FAE4096D8ULL,
		0xFD702F8243026225ULL,
		0x840D346D09FF507DULL,
		0x6FB8C67231B1FE1DULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEAF92FE1DAF7BB4ULL,
		0x956DA9C5FB372BB3ULL,
		0x47F7D5BB38D26389ULL,
		0x79C83E073B47AF61ULL,
		0xC566CEC6DB38C4AFULL,
		0x0F925DC1A50BD827ULL,
		0x911F814FC2C00D91ULL,
		0xA83DC4FDCCF67CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEAF92FE1DAF7BB4ULL,
		0x956DA9C5FB372BB3ULL,
		0x47F7D5BB38D26389ULL,
		0x79C83E073B47AF61ULL,
		0xC566CEC6DB38C4AFULL,
		0x0F925DC1A50BD827ULL,
		0x911F814FC2C00D91ULL,
		0xA83DC4FDCCF67CADULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22E499424F94DC42ULL,
		0x4603A289EF6FC2D3ULL,
		0xC92523AE3BF3BC81ULL,
		0x071DDD7F117825DCULL,
		0x50664005292CFD00ULL,
		0xFDAC77275161AB1BULL,
		0xB48102B17A6A7EC2ULL,
		0x4B5D1FA1C9311B16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C6B0960D1B0C3B9ULL,
		0x1027D90DC2FA87EFULL,
		0xB3A1D121BBBC003EULL,
		0x49C9923FD4C99378ULL,
		0xE1B127EABA7EE015ULL,
		0x498592381D825CA8ULL,
		0x0F137A11BF753388ULL,
		0x1F08D19F0FA23906ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02A0148424C47DFBULL,
		0x38643D1A012CD857ULL,
		0x4E794B7F3ED62772ULL,
		0x9B4342980D851255ULL,
		0x905078360F0F8873ULL,
		0x3D32029A81E0A0A3ULL,
		0x386557B9E46BE194ULL,
		0xD014DA0474582EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A9AE64E17F8F3BULL,
		0x2400B188E1F01CBDULL,
		0x4F0CB7E6421103D8ULL,
		0x2A35D78021FD85B5ULL,
		0xEF62C0F012F13F6DULL,
		0x9EAA1ADD2B80E535ULL,
		0xC38EF430A8E95FD7ULL,
		0xD500588A70E6CBC0ULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFB1C8324401CE4DULL,
		0x78F439BB096FD6D5ULL,
		0x5FE79880E05B5AC1ULL,
		0x3410FD27263B2149ULL,
		0x14D55BEC734A5069ULL,
		0x7A81DBE0139E0F7FULL,
		0xACAA95B4B889D7A0ULL,
		0xF4408FADA4315C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D97B7D813CB859AULL,
		0x4FEC40524CEA6707ULL,
		0x17AC401CF9B81786ULL,
		0x3084AEF283522353ULL,
		0xBBA29E6946DA5718ULL,
		0xF2EC81A38CF5F2F5ULL,
		0x74710E482ABCCDC3ULL,
		0xF826611145197FE8ULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E52E8326CA7E95AULL,
		0x2BF368910C08ACE3ULL,
		0x1A436F87C789F115ULL,
		0x1A4313283DF8307DULL,
		0x51928A23B9D29B12ULL,
		0x44D88C880DB48816ULL,
		0x1FBD03B32C2CA2FEULL,
		0xAF98BF5C98061329ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E52E8326CA7E95AULL,
		0x2BF368910C08ACE3ULL,
		0x1A436F87C789F115ULL,
		0x1A4313283DF8307DULL,
		0x51928A23B9D29B12ULL,
		0x44D88C880DB48816ULL,
		0x1FBD03B32C2CA2FEULL,
		0xAF98BF5C98061329ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94C95EF7A19686F7ULL,
		0x0197D6E0AA7CB9B8ULL,
		0xEE4CD07778857CEFULL,
		0x1ED5BFAF13795B7FULL,
		0x9DAF217B718616F3ULL,
		0x100008B90E80754AULL,
		0x3FA66ED1AAD008CBULL,
		0x75AA51442AECDC6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BEDCF1F2D4729D7ULL,
		0x721FFBA8B799CB07ULL,
		0x71246787EC727FECULL,
		0x3EC0F6EE676445FEULL,
		0x6CE9B7D1E46DCE83ULL,
		0x1A3059048885928AULL,
		0xA25ECFB68165D753ULL,
		0xC1F48B4EC3FB181DULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x134515F80C6B53B9ULL,
		0xF18A33592588F35FULL,
		0x7F50964894E9AB5CULL,
		0xB46205221A1A3E48ULL,
		0x3C729AE6FA572B39ULL,
		0xCBAD02CBFF692E8CULL,
		0x961250AE041F2103ULL,
		0x6973CCF295F99F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869681C163BD3496ULL,
		0xFECA0A74AAB255FAULL,
		0xB159E7929254D25FULL,
		0xF392BAD699E3A2CBULL,
		0xF2AED5A5C3F47B7AULL,
		0xA262FF4FDEB75AECULL,
		0xEB5C7EC7B11BE282ULL,
		0x3CA80AED3BE10B00ULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x103225568CA4B061ULL,
		0x0CA94B71E152FE6FULL,
		0x99C21DAD0749BDC1ULL,
		0xA7A7BAE9E7AAE62EULL,
		0xEDFE7962F44F69F8ULL,
		0x8D29AE76C1F2B0BDULL,
		0x54DACD415B1E0A25ULL,
		0xA790C822DFFE5C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CE79AACD94F094ULL,
		0x15AAFBEA0201C7B0ULL,
		0xCEC806363860E64CULL,
		0x2A6EF5D0A642578BULL,
		0x4505C6528BC1D1CEULL,
		0xF0E66316B0374678ULL,
		0x886DA06263474F3BULL,
		0xFE97B162BEEFBC64ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EA619D3CA440C2CULL,
		0xF9690C10015F4E95ULL,
		0xC76482D3EAFDE1E3ULL,
		0x3E65F16B62BE1B71ULL,
		0x7A86D4589905B7A1ULL,
		0x4743A248756FBB94ULL,
		0x188456B55CA08126ULL,
		0x4369A9D73719A7A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA619D3CA440C2CULL,
		0xF9690C10015F4E95ULL,
		0xC76482D3EAFDE1E3ULL,
		0x3E65F16B62BE1B71ULL,
		0x7A86D4589905B7A1ULL,
		0x4743A248756FBB94ULL,
		0x188456B55CA08126ULL,
		0x4369A9D73719A7A7ULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x794D353D7E11CEA9ULL,
		0xACC4A0690F621265ULL,
		0xD6E3E58700B26F0CULL,
		0x9A3635635FD7E607ULL,
		0x0B0905993D829445ULL,
		0xA3A2BB895269A4A0ULL,
		0x4B6F9A73880B671FULL,
		0x4B7ED16350782F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C5756D634A8720ULL,
		0xF9BBC4B53F106B38ULL,
		0x213CF2652787F2F4ULL,
		0xEC71BD0F332FA736ULL,
		0xD103EC4109E76FAAULL,
		0x0CD4F2179EC7BD31ULL,
		0xD36B9C3C2AEF42CBULL,
		0x00FD01E9244725BEULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B66089C41D35C50ULL,
		0xA8CBC18DE9725691ULL,
		0x92E50C5916434C78ULL,
		0x44C9EB2FCEEDA0C8ULL,
		0xCC30BED0ADC48AB7ULL,
		0x4709F0096F73D609ULL,
		0x906D921D2E8965DDULL,
		0x5FC1539F11385F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F7E115B871A39DULL,
		0xBDF8FF4BC24CD522ULL,
		0x398E389A18B6949BULL,
		0x630DDCBB174798EFULL,
		0x541C9BAA4320F0A4ULL,
		0xF1AAF115D1F2A4A2ULL,
		0x677A6B9D74CE575DULL,
		0x1A6B6910E51FB31FULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0C5C0DA77B1825EULL,
		0x0603E875A09910C6ULL,
		0xDAA3FE0E8840C01EULL,
		0xFE9EF93E4F343D8BULL,
		0x2DC8E92852506E58ULL,
		0x761F0F197CC3584CULL,
		0x4208AC890E455421ULL,
		0x7207F81043C9CE93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B36B67A4D4B6208ULL,
		0x39E46E7251D7D2BAULL,
		0x10B2A5AC57915E2BULL,
		0x49A39D3C29DC3891ULL,
		0x57C53FC126531ECEULL,
		0xBF38B3CAAEFCF163ULL,
		0x7D5B928A95A5660CULL,
		0xB74DE311F1700204ULL
	}};
	t = -1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E1C9940CFDEDCFEULL,
		0x9793A858632C74D9ULL,
		0x3195DCEA5E0CD428ULL,
		0x9EABAC2DBACADC8AULL,
		0xBDABEAA37D3EBA03ULL,
		0xBA92CA3F57DDB1E8ULL,
		0x4942D84B5B78B02EULL,
		0x9FA8ECE85080173FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E1C9940CFDEDCFEULL,
		0x9793A858632C74D9ULL,
		0x3195DCEA5E0CD428ULL,
		0x9EABAC2DBACADC8AULL,
		0xBDABEAA37D3EBA03ULL,
		0xBA92CA3F57DDB1E8ULL,
		0x4942D84B5B78B02EULL,
		0x9FA8ECE85080173FULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x320157EFE5EC9486ULL,
		0x1838A59908175B3DULL,
		0xC77B1FA6DAA1BF0DULL,
		0x8B2A3227A2555213ULL,
		0xF40448FE5A9580AEULL,
		0xA1FE785E5C861F28ULL,
		0xBE928059FBF3776BULL,
		0x28CD8C128E76E8F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BBF2B223E8C87B8ULL,
		0x7F0B0FF7C686D13CULL,
		0x0940CBC0E1616178ULL,
		0x0354B66725DCC89EULL,
		0x01023EB10A3535EAULL,
		0xBAE4AB8AC51159FBULL,
		0xE2939F52B67908A2ULL,
		0x8DBA34B78668F261ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C2939248C60E251ULL,
		0xB330ED269BB3773DULL,
		0xE5BC92E22618B273ULL,
		0xDBA54EDCE2006CAEULL,
		0xC624E682C926EB4CULL,
		0xF9ED9E62A7ED1C7BULL,
		0x95DC5AA082736366ULL,
		0xFE6E693C8D7A42C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB11E65CD63C0F5ULL,
		0xA70A87BF22269516ULL,
		0x43A73A4ABD4EF50AULL,
		0x047F5050B22ACA0AULL,
		0x694D7C0EC4B26909ULL,
		0x2D31DBA478908D2CULL,
		0x0400CA5F24AD76EDULL,
		0x4BAC2234FFD2CA04ULL
	}};
	t = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C306F60A067D4C4ULL,
		0x67D55AAFC80DAFFEULL,
		0x4B50C97B8129E2B6ULL,
		0x32FAA9865FDB912EULL,
		0x624F0434B95E2ABCULL,
		0x3BBBA7806E7F00B8ULL,
		0xE93011895BEDA9F9ULL,
		0x9830D6A1EA197ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B94D600DFE3E11FULL,
		0xA201C1700D07913DULL,
		0x386135FB83B51933ULL,
		0x20E76B8FA8B69B6CULL,
		0xDE2840B9EF89ADEAULL,
		0xFCC1E5B946F554EAULL,
		0xE37E6A3A37822641ULL,
		0xA82F8D0B95B05AC6ULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4A51730CC7EF37AULL,
		0xDE360F5B8FBD028CULL,
		0x5C3EACA59C10A1CDULL,
		0x54A8EE1C0244AC0DULL,
		0xE769DF15C6FCCAAEULL,
		0xDA3404771FB4A0AEULL,
		0xFA6EB83A71688793ULL,
		0x0A15898A3560C333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4A51730CC7EF37AULL,
		0xDE360F5B8FBD028CULL,
		0x5C3EACA59C10A1CDULL,
		0x54A8EE1C0244AC0DULL,
		0xE769DF15C6FCCAAEULL,
		0xDA3404771FB4A0AEULL,
		0xFA6EB83A71688793ULL,
		0x0A15898A3560C333ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DB8D5A127AA8CD6ULL,
		0x6DAB1B43084DC5D2ULL,
		0x6AA9AB662DDFC83DULL,
		0xCE734D9E001392BEULL,
		0x71120CC896BAECFAULL,
		0x459EA3A158A1A55FULL,
		0x172F5007FCB0DEB8ULL,
		0x3245530B2D59815FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04DFAEFC115C29BULL,
		0x2EB45BDC277A7590ULL,
		0x6921C8DABE25D60AULL,
		0x67046C56BD2D1798ULL,
		0xBDDA7C78A7CAFDA9ULL,
		0x4742FEDCB4439ED8ULL,
		0x19D28A8C1BA67C71ULL,
		0x5E0A09576C438A54ULL
	}};
	t = -1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9378884BFE6141F2ULL,
		0xADEB28944FFAEEF1ULL,
		0x331DDF68FDE41B01ULL,
		0x70CF7EAFA8CA50C5ULL,
		0x5725670A7DB25987ULL,
		0x3713AB92BC0EBBF1ULL,
		0x87EF270771793F97ULL,
		0x789A05DB1B4E5D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB119263EDC8EF74ULL,
		0x26C78B1171178990ULL,
		0x092A0FBF5B9AFC10ULL,
		0xA72F113CF7E05AC1ULL,
		0xE285633DE46E58AEULL,
		0x457818E21E2AA63DULL,
		0x44E18F01A6586397ULL,
		0x54F5E55C875A5842ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF03F3279035906CFULL,
		0x8BB85FD42D021E77ULL,
		0x78B1BEF7DC2945D3ULL,
		0x3534190BAC6C467BULL,
		0x7D74485EEBFB1C27ULL,
		0x3FD6023189426D71ULL,
		0x17C4FB41463E85B0ULL,
		0x3583B8C24364A173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256C17CBEB973B27ULL,
		0x90018690BE85B5AAULL,
		0xCDC09DE9F211FDB3ULL,
		0x89FCFFCEE5060BBAULL,
		0x0C706D308FD615B0ULL,
		0xE7F3A83973028ECEULL,
		0xE4242CD2F79F025AULL,
		0x68C7C22747CCADA9ULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD07B43F4BB3B4047ULL,
		0xB4C841579AEBCC16ULL,
		0xE04AA8CEC644DD6FULL,
		0xBB08A9CE7D8BCD0BULL,
		0x0489BAE35F71240BULL,
		0x880BE400180650DCULL,
		0x3D50728F5EFB2F8EULL,
		0xFAB4353B210D564BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07B43F4BB3B4047ULL,
		0xB4C841579AEBCC16ULL,
		0xE04AA8CEC644DD6FULL,
		0xBB08A9CE7D8BCD0BULL,
		0x0489BAE35F71240BULL,
		0x880BE400180650DCULL,
		0x3D50728F5EFB2F8EULL,
		0xFAB4353B210D564BULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55A9E979D1FDDB7DULL,
		0x3F0718E9C98D5F71ULL,
		0xDC287037A974739EULL,
		0x16722CE50CE533B5ULL,
		0x06630852E6177C4BULL,
		0xF01C8B210FCC5AE3ULL,
		0x34C71C46DE85DC49ULL,
		0x4671588397D30ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA444F4C0158579A0ULL,
		0x16EBF3B4DD0C18A5ULL,
		0x83E178FD73B79554ULL,
		0xCC5F4096D1ACED7BULL,
		0x030167A4CAD53E87ULL,
		0x1CDB479DA5190B62ULL,
		0xA88DC9F9FBC24934ULL,
		0x1D2C2F769D11A0ECULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF59D1FFED7B52F35ULL,
		0xEC621B6B43B65C76ULL,
		0xCD36CD9C1C10C573ULL,
		0x697F110B81ECECE7ULL,
		0x139B75DD505BFA2DULL,
		0x64842B355870D05FULL,
		0xD207CD538A5C4899ULL,
		0x07C62015B151C35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A67911766A7B803ULL,
		0x45ACB66E8D33A1A2ULL,
		0x376ECF4D434EA283ULL,
		0x2CE6187A1EFE6BD7ULL,
		0x94C7F5BCEB3DBA00ULL,
		0xDE8F3DEA2597D873ULL,
		0xD23B77C352A21954ULL,
		0xFD505908F77B6600ULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E486766B2A5701BULL,
		0x4015FC5BC77E2202ULL,
		0x0CF6A15C68165707ULL,
		0xB2F0698FE783E7F2ULL,
		0x2CCBEDE0855AB4ADULL,
		0xFED578645C79BD3AULL,
		0xC3BA26245DD3741CULL,
		0x0C9ED47A5D9E0759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E6E06ACA0292F9ULL,
		0xC6B9FC23EC46B5A0ULL,
		0x2FCE0F80DDA2E30FULL,
		0xC4AA269CA722B0BFULL,
		0xE03BEC2F2D4E4564ULL,
		0x421BB5C8A30DEA9EULL,
		0x34EE2EBAECE8745DULL,
		0x6A4891EBC2797924ULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B1EA89DEC708272ULL,
		0x83A9879AB11F99DFULL,
		0x19F49DA36DF70C3AULL,
		0x5410CD4EB8B0A6D0ULL,
		0x0192EE0B66724C06ULL,
		0xA3F7D05941BDBAADULL,
		0x3A70E3BFDA9D1935ULL,
		0x04FCCB6413DB1124ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B1EA89DEC708272ULL,
		0x83A9879AB11F99DFULL,
		0x19F49DA36DF70C3AULL,
		0x5410CD4EB8B0A6D0ULL,
		0x0192EE0B66724C06ULL,
		0xA3F7D05941BDBAADULL,
		0x3A70E3BFDA9D1935ULL,
		0x04FCCB6413DB1124ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x779F679393253BC3ULL,
		0xD4FC552DE57B6895ULL,
		0x42943F300C89E3D0ULL,
		0x75DEA6C396FC0F7EULL,
		0xB4C8875081233D52ULL,
		0x2DE723DE5BFD3BA7ULL,
		0x9C113F47EFAA52F9ULL,
		0x1B2350D9D3087684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91AD2FAD7A5DF8BFULL,
		0xBADF240222817800ULL,
		0xECE1830A18395E2EULL,
		0x020009A0A038B233ULL,
		0x088E6D783CCF34BBULL,
		0xEDE8CBCD49F9BA99ULL,
		0x4BFC6658105C2D9EULL,
		0x9490C559A008E369ULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1943C0A6C40BE609ULL,
		0x5C335AF04F6188DAULL,
		0xDFA8390DE90F759EULL,
		0xCDA025B236953F06ULL,
		0x33BDA76F008240B5ULL,
		0x38F5FE86A64FD6B7ULL,
		0xF9868FBCB7598994ULL,
		0x2E44860A1FEB591DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3221F2FFB819949BULL,
		0x09D22C366F993EA9ULL,
		0xE4D3BDDD0D2A5574ULL,
		0x2851ACDFA072030CULL,
		0xF3E88B68BBBA8439ULL,
		0x3CAB0F9E53D09792ULL,
		0xE54ED7CBD56DDFC5ULL,
		0xBC412D156AE55F56ULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32F81F7C1B475DE6ULL,
		0xAE30F01E6F909CB2ULL,
		0x0FA630E9CC839CC2ULL,
		0x369E11744B781E91ULL,
		0xFA5D38001151BBB4ULL,
		0xD154F357BCA5A1ABULL,
		0x964D7A4A26E4DAF8ULL,
		0x7B15146A656F2F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC101DF25F6AE51F0ULL,
		0xCC4A8DB46627B76CULL,
		0x147E410CDA8207CCULL,
		0x1C144898697E4533ULL,
		0x631DC4483E48ED3EULL,
		0x2D38A6A83ACA656BULL,
		0x0D25534990917BB4ULL,
		0xB4F60713D5D8D36FULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD5888BFFD2AE20AULL,
		0xD4D1E32C2F3D537CULL,
		0x81238BD748D00A3AULL,
		0x48C5BF5A1D9E5457ULL,
		0x9B63FE1C15AE7F4AULL,
		0xC1C22EC54BA185D0ULL,
		0x9DC5A85399BB7817ULL,
		0x9D2EB6BF8FE16F8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5888BFFD2AE20AULL,
		0xD4D1E32C2F3D537CULL,
		0x81238BD748D00A3AULL,
		0x48C5BF5A1D9E5457ULL,
		0x9B63FE1C15AE7F4AULL,
		0xC1C22EC54BA185D0ULL,
		0x9DC5A85399BB7817ULL,
		0x9D2EB6BF8FE16F8DULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF92363D7FA6DE5A6ULL,
		0x7CD99D2419B012B5ULL,
		0x573104A040E6927CULL,
		0x2A1D2AD9482ED5B1ULL,
		0x328AF837721D2E16ULL,
		0x0BBA54EDBCFAC132ULL,
		0xC5B868BA056A48DBULL,
		0x6D26DE55C987F51EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1553CD79D625FE39ULL,
		0xA9BB8279697483A6ULL,
		0x533923594BB8E459ULL,
		0xB4F5BE0E1370AEDEULL,
		0x52D0CB766F69EAA2ULL,
		0x2E3E01BFEC3A8868ULL,
		0x6F8763187F07C086ULL,
		0xEB90B1987E2E8E35ULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57D6A5FAA140E3E9ULL,
		0x17BCE8CF27892AE4ULL,
		0xFF32AF0E76237240ULL,
		0x5EBF339B2FA7198BULL,
		0xC6AF9256CD6C0A65ULL,
		0xB6E684F534C2537CULL,
		0x19C7A8305FBEF8DCULL,
		0x515DD466B79D683AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AE8B2F46A8AEADDULL,
		0xF9CC3BC4109FAF89ULL,
		0xB1087119877C061FULL,
		0x5C3E1A473962A4D9ULL,
		0x8A419010C6C18527ULL,
		0x5D489EBDD3C75AC1ULL,
		0x3754CDB1C94598B5ULL,
		0xD30E42C0F48C6E65ULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CD44D61812D8518ULL,
		0x053F6F9A3EF29400ULL,
		0x4BF2317672A7EDB2ULL,
		0x65B3C9C57FD22090ULL,
		0x35D066A6A298DC77ULL,
		0x82D7E2215B6099A3ULL,
		0x9E69A4A2471ADCA6ULL,
		0xF662B8EA734F0BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0044818E9EEF2B14ULL,
		0x7A9992393DA3700DULL,
		0x1031E64C1225AEE1ULL,
		0x99CA9DFAA294D27BULL,
		0xB96684EC914B8941ULL,
		0x7923AD802777C0ECULL,
		0x7F4D2B5465D0016CULL,
		0xEC47D60E89CF5D2AULL
	}};
	t = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A0A5111B952E260ULL,
		0xDA918857AF7269C6ULL,
		0xD35F0DFD249E89DDULL,
		0x899444C920EB13B9ULL,
		0x0BE1BC81F09EE32AULL,
		0xB2C1F633D57F3C2FULL,
		0xE131AC9C99D796D9ULL,
		0x8E6C6ADF2CBE10C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0A5111B952E260ULL,
		0xDA918857AF7269C6ULL,
		0xD35F0DFD249E89DDULL,
		0x899444C920EB13B9ULL,
		0x0BE1BC81F09EE32AULL,
		0xB2C1F633D57F3C2FULL,
		0xE131AC9C99D796D9ULL,
		0x8E6C6ADF2CBE10C8ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DDEBD12E91F540FULL,
		0x95A116F3D51FA529ULL,
		0xDF08413D9072376BULL,
		0xF3D3441316CD3F96ULL,
		0x62FD46CA7610C512ULL,
		0x5A245CCBE1AE00E8ULL,
		0xA2B037FCC8BEE29DULL,
		0x9C4193B6058CAE74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8EADEC42DB39FCULL,
		0x608D774D660B5925ULL,
		0xCBC8342A45632EE0ULL,
		0x1B1A5D3A7A0FA19BULL,
		0xDEB4E67D0B365828ULL,
		0x836F57710C9B51A1ULL,
		0x6D80CD4DCB79EF67ULL,
		0x70D29375EAFACDD0ULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0AEA7826223FDDDULL,
		0x34D9DA24AD734327ULL,
		0x069200FBB35677CFULL,
		0xBB59846684CE23C6ULL,
		0x501811CD3F05BAAFULL,
		0x6764685AD7992C08ULL,
		0x31C8840806321774ULL,
		0xE74801BDA2E7E214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F950317CD1BA92ULL,
		0x87A844861C3C2DC4ULL,
		0xC456689C90FAEF4CULL,
		0x745AE38690045172ULL,
		0x120D6AF523BACB6EULL,
		0x6FDC665A1BB5110EULL,
		0xAA5106605C315A68ULL,
		0x1D267F23AC39F7FEULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99F6145A6A6BE8E1ULL,
		0x55FF4F3F04F0A3EAULL,
		0x20ABA2F9FC8DE6B2ULL,
		0x4008EB59E22AB37DULL,
		0x04DBD7C5137F4AFBULL,
		0xCC9E50B64A03C3FEULL,
		0xFEF5FC5D1E9DC5BEULL,
		0x92321D90F091A0EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF5BC26303A3D49DULL,
		0x5DA04193F3A4D7CAULL,
		0xC6A90ECBBE18FB1BULL,
		0x34C2524D984AD517ULL,
		0x409C7710ABE134E2ULL,
		0x7159B475B65E1E08ULL,
		0xC0F9408ED51A27FCULL,
		0xB62D2A807238DC68ULL
	}};
	t = -1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C2E829D65A0EB52ULL,
		0x90A58BF564FCA13EULL,
		0x4436B862AF899F60ULL,
		0x03CD12A7015017C2ULL,
		0x67CAC2C2C696FA3DULL,
		0x05AB30913D7C21C6ULL,
		0x523B97E5CF71E2B1ULL,
		0x655FDFB6FCE52B0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2E829D65A0EB52ULL,
		0x90A58BF564FCA13EULL,
		0x4436B862AF899F60ULL,
		0x03CD12A7015017C2ULL,
		0x67CAC2C2C696FA3DULL,
		0x05AB30913D7C21C6ULL,
		0x523B97E5CF71E2B1ULL,
		0x655FDFB6FCE52B0DULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6940A449A2395F40ULL,
		0xAA9F8856D9517C19ULL,
		0xD5E64B9FD99D9EE8ULL,
		0xEA2A0BAFC94BA079ULL,
		0x92169F037E99322AULL,
		0xCD19133455A507DBULL,
		0x82DD32107C4F13DBULL,
		0x64D451B33CD3691BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061C8E54D974CB16ULL,
		0x3EE324B26E5123D2ULL,
		0x11058F5465370D14ULL,
		0xB25D30E29906B7B8ULL,
		0x802E293A19E2F282ULL,
		0x23C2A88A0152CBB7ULL,
		0x1759F763830B2C3CULL,
		0x4147047FE33534D5ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3582C18C6F08D17CULL,
		0x6F27F66183F5BFAEULL,
		0x680EDE63CD79D3F9ULL,
		0xC1BA69A67CD02513ULL,
		0xCE0A11FD5F9FFCA3ULL,
		0xCC2117D01FAF6BD5ULL,
		0x1DF504853F015207ULL,
		0x57A27FC4E98D3887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8CBA7ED626F943ULL,
		0xF7CF9C70757F3F79ULL,
		0xCF8F22362F504EE6ULL,
		0x1CEBFF372F4A9CEEULL,
		0x7F207F8FC9C39B71ULL,
		0x0C3E1C8A540D0C20ULL,
		0xAE95D2C1521D3823ULL,
		0x937419EDA1ADFCBBULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51F786E1115ACED0ULL,
		0x0A50364F00CCCD2DULL,
		0xDBC552C92C62AA06ULL,
		0xFD7E86CEE89B2EA1ULL,
		0x2C9D72F8071ECE4FULL,
		0x8F26B92FF3589369ULL,
		0xD7CBB266EF19B8E5ULL,
		0x4919DDFC9E17BC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A9344E12BB2FA9ULL,
		0xB8B848D17CB1FB39ULL,
		0x58158A29FC85970BULL,
		0x1FDFE5BFE5E3EC45ULL,
		0xB1A5E43CCE20E5B5ULL,
		0x94F8A0073BD81613ULL,
		0xF3360C51EF063FB5ULL,
		0xB46FFFFAEA29FD66ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x238B80B5530AD15BULL,
		0x6C134E6F234A7FE0ULL,
		0xEE48C273DD000E98ULL,
		0xA4161093A5B5FBB6ULL,
		0xDBF7E16D5E9C3053ULL,
		0x837EF7CE4C7D5AF0ULL,
		0xBFB5A575FB021A6BULL,
		0xFD1699953C876C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238B80B5530AD15BULL,
		0x6C134E6F234A7FE0ULL,
		0xEE48C273DD000E98ULL,
		0xA4161093A5B5FBB6ULL,
		0xDBF7E16D5E9C3053ULL,
		0x837EF7CE4C7D5AF0ULL,
		0xBFB5A575FB021A6BULL,
		0xFD1699953C876C8DULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB40FB41EC3BCDC6AULL,
		0xD4E18DB8CCC993BDULL,
		0x490487FB08C2C192ULL,
		0xC27AE11D15D9FEADULL,
		0x5E438D77F10BD7AFULL,
		0x3445F29DDA5BE1FAULL,
		0x949E42549A85734EULL,
		0xF4DE92A3E6ED7166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE5D02FE532A09BCULL,
		0x102B281E45A505FFULL,
		0xF75281185A6BD874ULL,
		0x48AED7CD8B909722ULL,
		0x745C3B850EC05B2DULL,
		0x29C7FD768B1DC05DULL,
		0x51E841951BC0E0EFULL,
		0xAB250AB1CF8E27BCULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BE6F3B708265DF3ULL,
		0xE6F753A7EE56A474ULL,
		0x8A1DAE65578C630FULL,
		0x93522CE2BC540C34ULL,
		0x811406B986CEB72FULL,
		0x0699347C24DD4708ULL,
		0x31C6D0292CD8D86AULL,
		0x41A950AA0FBC9319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71C24E90C611CCBULL,
		0xFDE558445BD8190CULL,
		0xEB0CEF203A909E61ULL,
		0x2FE61C10209C1085ULL,
		0x2B5D25C0C000C888ULL,
		0xD80F14E4CE0B4E1EULL,
		0x985C101706268812ULL,
		0x4F38B84173247F4DULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x009D8BD9A47BDD2EULL,
		0x2C26B1DDC9F547B9ULL,
		0xDEACBECF5BC35944ULL,
		0x0611B6DC415A2B5DULL,
		0xA6594FF1F530988BULL,
		0xE8E3978035C5C092ULL,
		0x4621DC76D753808FULL,
		0x92C670291326C749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BED194348B7D854ULL,
		0xE15F364B036F2E0EULL,
		0x20FEDE0433A6CBDBULL,
		0x39AB34BF279235E9ULL,
		0x8A9CF43B59BDEE6AULL,
		0x9DAA47A376BE4CE8ULL,
		0x0BF0F84C9F03D4C1ULL,
		0x4D22C712CC532BC8ULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D01580397124210ULL,
		0x27EBED01BD69861CULL,
		0xE70504A727E601E9ULL,
		0xFBF735E0D604FB18ULL,
		0xC5F662281E0BC126ULL,
		0x13F1A04FEA45BB77ULL,
		0x3287F7E1817C958FULL,
		0x0C8A21810040FA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D01580397124210ULL,
		0x27EBED01BD69861CULL,
		0xE70504A727E601E9ULL,
		0xFBF735E0D604FB18ULL,
		0xC5F662281E0BC126ULL,
		0x13F1A04FEA45BB77ULL,
		0x3287F7E1817C958FULL,
		0x0C8A21810040FA6BULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80CA6933E1F43EABULL,
		0x8A919943DA8FAA97ULL,
		0x13D6FBF818941A50ULL,
		0xC03BF82473BA689FULL,
		0x996FD1CF198F816EULL,
		0x3893B1E4D584CC7BULL,
		0x33C97DB98A1AE623ULL,
		0x92732757ADD3979BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D5F90B2C999EF65ULL,
		0xB189C74FD51C8495ULL,
		0xB35D9F6031AC628CULL,
		0x69AC7A53B2F4679AULL,
		0x12D6251B2843AE05ULL,
		0x3E90B14DE05AE1CFULL,
		0x0003AF9037666030ULL,
		0x6A893B417C52029CULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBAFD01564E222A7ULL,
		0xC612DD9DC6570B04ULL,
		0xEB7BA648D681A841ULL,
		0x5AEF224765AF3B5CULL,
		0x4185C99C886D796AULL,
		0x4A70D8920B09C340ULL,
		0xC6CCB072BD2BD090ULL,
		0xFEE2A98941172AE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43BA9D2C26C7F744ULL,
		0x432094BEBB4FE820ULL,
		0x79C118CBB0FA67DAULL,
		0xAFA0F17BC38E99FCULL,
		0x2FEB39061EC1C85EULL,
		0x3672C24128921E24ULL,
		0xE77C734F81B51394ULL,
		0x459F17FE0086DCC6ULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x352ED1DCA095964BULL,
		0x762C0B98E30649BAULL,
		0xF4B8D8E74C240738ULL,
		0x304B974F724F5BAAULL,
		0x42D7400484A78FB4ULL,
		0xBFB7CA3302F725DBULL,
		0x46E6DD9387F98DF5ULL,
		0xE5773D52455B454FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A524942663384FULL,
		0x5E29FFFC135EF4FBULL,
		0x23041B3F337B3ADAULL,
		0x928338DC6961CD8EULL,
		0xD084F4A9CA0A8052ULL,
		0x8BC9BDA26C1F5575ULL,
		0xD8728D2E7B755E34ULL,
		0x06BACEECF398498CULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33115A35B26775ACULL,
		0x6EE076AC2049B746ULL,
		0xFDE9F1F8F8C4D2EEULL,
		0xB8497DF44568B8E1ULL,
		0x1F56C415E48AFAE4ULL,
		0xFBCF02EE272C12A5ULL,
		0xE9A493C5F9AF4113ULL,
		0x94D44AF2A9E9FAF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33115A35B26775ACULL,
		0x6EE076AC2049B746ULL,
		0xFDE9F1F8F8C4D2EEULL,
		0xB8497DF44568B8E1ULL,
		0x1F56C415E48AFAE4ULL,
		0xFBCF02EE272C12A5ULL,
		0xE9A493C5F9AF4113ULL,
		0x94D44AF2A9E9FAF3ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD07A307CA77D642FULL,
		0xE1A71108B607FC32ULL,
		0x7E84D5C19C1F0842ULL,
		0x3F9B08FF8FF1ECBFULL,
		0xE8A8193862A85E60ULL,
		0xC7A639167C5CCB70ULL,
		0x1580BB494FFE4076ULL,
		0x0C66F9D9E1E1C055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32394C7BC0D495AAULL,
		0x97DAFDC18CD2882DULL,
		0x45C38F3B5CC2AFB6ULL,
		0xE169F980993FDE68ULL,
		0xF06E1A9F7ED646E8ULL,
		0x1131E79DC53E2300ULL,
		0x3DF0854ECD9B2E58ULL,
		0x58190F2BB785C35EULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42B8CF7DFEDE9759ULL,
		0xC4FDA6EFAE241A54ULL,
		0x58C636F5E657E806ULL,
		0x0E7946E8972C1CF2ULL,
		0xE427B91A51946441ULL,
		0xED16A7B9C0FE9A50ULL,
		0xB2DA9976085DC80BULL,
		0xCC26F572E2335BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145F33000254EF41ULL,
		0xB397AF98EE711867ULL,
		0x4D057B2653E46A04ULL,
		0x60F6B127121EEA8FULL,
		0xC8C3E009B3E76EE2ULL,
		0x7D1D0CBBEF4DC54CULL,
		0x7FC8A4F28813AC4DULL,
		0xD59749F3A0E08381ULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6709C7EC53083E34ULL,
		0x9C6A28E81AB6C431ULL,
		0x16AA041C7C498183ULL,
		0xFDB60B5275FB785EULL,
		0xADF87DF209226961ULL,
		0x212A30572ADE90D8ULL,
		0x40333F97F79F04E7ULL,
		0xDE2BB4790CFA9BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F6E729CD86A233ULL,
		0x9ADC545A1DECAF30ULL,
		0xFE848F02BE412CD5ULL,
		0xD1A34BE97A015ED1ULL,
		0xDF94A6E934459F70ULL,
		0x3B70EE8BBA6E8437ULL,
		0x0079F44FE92AB2B0ULL,
		0x5C6AC9D06FF6D211ULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDB55E351902C430ULL,
		0xFF7596A5A5C7F7B7ULL,
		0x7AFECE76D7A69CB3ULL,
		0x4BE335D41D9B49F8ULL,
		0xA45EABF8F0B3C8A8ULL,
		0x33473954627B984EULL,
		0xCEEBD828D41F9A48ULL,
		0x20C9A1FE3CE94200ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB55E351902C430ULL,
		0xFF7596A5A5C7F7B7ULL,
		0x7AFECE76D7A69CB3ULL,
		0x4BE335D41D9B49F8ULL,
		0xA45EABF8F0B3C8A8ULL,
		0x33473954627B984EULL,
		0xCEEBD828D41F9A48ULL,
		0x20C9A1FE3CE94200ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBA686F2672203F6ULL,
		0x9272399691033EDDULL,
		0xAE695FCEE377ED4FULL,
		0xA13E54D52330B42BULL,
		0x671B937297BA70D9ULL,
		0x99C7DF9CA1B8CFC7ULL,
		0xA3121E38DCF379DEULL,
		0x0408AC7BB53C05E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FF6D6FF78E6CFFULL,
		0x1EBA9056F86DD26AULL,
		0x481A1D8615B12888ULL,
		0x4F19DB156F05B3A6ULL,
		0x963179E4AEA57F37ULL,
		0x38F323E7DDF540A6ULL,
		0xAE72D38A2D616119ULL,
		0x958CADC9AD1A1425ULL
	}};
	t = -1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA36524D245E63727ULL,
		0x471E9690B35241FBULL,
		0xA6D7CBFEE0BF883CULL,
		0x85E6E1C1ED10A356ULL,
		0x42F584B59576BF66ULL,
		0x2B3B8EA8FC96D3EEULL,
		0x9DE5D067685F3495ULL,
		0xF328553CDA6922B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817610AF17C4F908ULL,
		0x84A46D3F071AB8E9ULL,
		0x2713349A88A13EB5ULL,
		0x3E579783484BF309ULL,
		0xF3955E0CC32A01C4ULL,
		0xAFFF892A5D707EA8ULL,
		0x34CA482D14F65C45ULL,
		0x9E9E657DD0C027A7ULL
	}};
	t = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3420653316480F3AULL,
		0x630AF8E0E316C03AULL,
		0x8C51A74315B6F4E1ULL,
		0x75704A8A7BEE784EULL,
		0xF63B7774920E6A86ULL,
		0x604F751647DEEE9DULL,
		0xEAFE659C6B7DF2C0ULL,
		0x0C5B441E2681473DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D5898CE0C2E889ULL,
		0xED61B3C1871414B8ULL,
		0x11788DE3ACDAC461ULL,
		0x969D7AB9F85BC560ULL,
		0xACDED279D183D3E2ULL,
		0xD878F1BEA28B819EULL,
		0x6CE73D3C6536919CULL,
		0xD4033FE5E818D59DULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFD586F7478901CEULL,
		0xC9C697200AAD3553ULL,
		0x3F87452D76BE8EE0ULL,
		0xDDBD782FB2C1501CULL,
		0x1E068F36F6139F8CULL,
		0xB1DC1607C1A97D09ULL,
		0x149E8DBF48F66163ULL,
		0xF8D4F82749A72132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD586F7478901CEULL,
		0xC9C697200AAD3553ULL,
		0x3F87452D76BE8EE0ULL,
		0xDDBD782FB2C1501CULL,
		0x1E068F36F6139F8CULL,
		0xB1DC1607C1A97D09ULL,
		0x149E8DBF48F66163ULL,
		0xF8D4F82749A72132ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97EE46E7FC27735BULL,
		0x3A46CD5A3BAAC2C2ULL,
		0x182B236BEC054418ULL,
		0xB962B936BF53DE37ULL,
		0x2C5F0F1FFE47778DULL,
		0x0AEEC960B0EBF0B8ULL,
		0x48FDEF150909A302ULL,
		0x3D968DA6A3EBE2D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212005586698F310ULL,
		0x422ED38510375CA2ULL,
		0xF7DDFF9639E0425FULL,
		0x300703173FE0D061ULL,
		0xBC81AFFE57428401ULL,
		0xBD8B47136B4DC0ECULL,
		0xB82DBDAFEA0D1546ULL,
		0x2AC2D21C72C8E611ULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D09E92197A47C6EULL,
		0x9A6BB73C3F273617ULL,
		0x822931C1FB6B3D5EULL,
		0x1B8DF9FB202B0FF7ULL,
		0x3DA78E18C7E4E4E5ULL,
		0xB81FFA7CF59D9293ULL,
		0x4F9B82A834162B72ULL,
		0x1266AC1352967E20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DEBA0B62C55C8C0ULL,
		0x1ECD56A760F0402BULL,
		0xBD480C9A5297AAA4ULL,
		0x5E4C13120AE568DCULL,
		0xEDE26136B12AA08FULL,
		0x5D26F9304EEB18C8ULL,
		0x3670E7CD94E412FFULL,
		0x4FA46F50FDB25466ULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF514F6AAC22C54E8ULL,
		0x5AC19B254343E0A5ULL,
		0x5D4FA4DE390C16A3ULL,
		0xD80D380024309203ULL,
		0x28226BC2A9EDAA24ULL,
		0xC489E72028383661ULL,
		0x28836034BC3A6BC0ULL,
		0xBFAC448522CD5A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929A0FF248FCDF23ULL,
		0x20D1CB019527567EULL,
		0x66CF6FF293B3B75DULL,
		0x658122B168F2930EULL,
		0xBD78A0BAE0174A09ULL,
		0xD52E4FE3A7E65E5BULL,
		0x26ED3C2F5BF6D1BCULL,
		0x5C0E9EC0FCAA75B6ULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA28E04CA9EAAB898ULL,
		0x452F4906DFFDB38FULL,
		0xC0DF756B41B68469ULL,
		0xB73879D5B5C847C2ULL,
		0xD706FA59AAF8F18DULL,
		0x0F96A44C90A7A775ULL,
		0xF7B4FB181525C311ULL,
		0xD3ACD8D8109CCE7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28E04CA9EAAB898ULL,
		0x452F4906DFFDB38FULL,
		0xC0DF756B41B68469ULL,
		0xB73879D5B5C847C2ULL,
		0xD706FA59AAF8F18DULL,
		0x0F96A44C90A7A775ULL,
		0xF7B4FB181525C311ULL,
		0xD3ACD8D8109CCE7FULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24224CE95CD9DC9DULL,
		0x8E8F0E43EA81F449ULL,
		0xFE5CAC9264C0AF14ULL,
		0xF3E0A5E574175468ULL,
		0x9A4DBE055585C0E3ULL,
		0x53FBD80A7EE44542ULL,
		0x2F130DA9EFEF098DULL,
		0x07A27C17FEAD37F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01C003E2C0703B6CULL,
		0x40B43BEBCF85EB9AULL,
		0x2628C9759C22E90BULL,
		0x8953508718CA43BFULL,
		0xE7FD8772CD33F525ULL,
		0xC4ECE9D2F0F09F0EULL,
		0xB96CE71DE2C02075ULL,
		0xFBA0BCB93B9CE91BULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69C5A7D2B50D2B4BULL,
		0x510147CAC869AE1EULL,
		0xE52AE5646AFE40B5ULL,
		0x7FBCB22722C66E6EULL,
		0x3644B0EADB3F959AULL,
		0x1C4C9C520896DD40ULL,
		0xADFA519FD982B2D3ULL,
		0x8B6BE994C30F9C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355A882955E7F225ULL,
		0x0613CEAE0EDF2CD5ULL,
		0xE5FCA40E513F6F0DULL,
		0xA203C4F4CB4D35E6ULL,
		0x1CEB427D821523CBULL,
		0x4FDE5A1834ED3DB0ULL,
		0x700761B463897AD3ULL,
		0x98C3779D05B7C881ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE90057F198B03EBCULL,
		0x84DE4780712394A3ULL,
		0xF2C3CEDF69A12435ULL,
		0x2567FD0EE39307FFULL,
		0x39DAE25EAB0E0E3CULL,
		0xE3699FAB11BF0AC2ULL,
		0x5CA3B82B7C00475EULL,
		0xDC4E6773535CBD46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D3EC5E44B66481ULL,
		0xDF7963ADFE8529D9ULL,
		0xB494AF5AE0152117ULL,
		0xEA4C9594B022CAB8ULL,
		0xF8F542C7928CA50AULL,
		0x249B36E1DFED53D0ULL,
		0xD4A0CAE9BA9511F6ULL,
		0xDF45D72C4F72D6A7ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x349CD156158D69C0ULL,
		0x60CDC1FFB302FF79ULL,
		0x43F19B62B9FFE8E0ULL,
		0x690121E84C5EE9C5ULL,
		0xD2CB066F44EF4D90ULL,
		0x16DEFF745BDCB601ULL,
		0xBD6732D1002548B2ULL,
		0x3BABAF6E67CD75EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x349CD156158D69C0ULL,
		0x60CDC1FFB302FF79ULL,
		0x43F19B62B9FFE8E0ULL,
		0x690121E84C5EE9C5ULL,
		0xD2CB066F44EF4D90ULL,
		0x16DEFF745BDCB601ULL,
		0xBD6732D1002548B2ULL,
		0x3BABAF6E67CD75EEULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD18537E22A010796ULL,
		0x359EAF1ACA2576F3ULL,
		0xBE898F66F77D9AEEULL,
		0x75F7E9B3F0A19192ULL,
		0xAA9015F561B37070ULL,
		0x2FE5B051EA5057F1ULL,
		0x5791019D42302235ULL,
		0x6E8865DA39331206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3913FDC9161E8D7FULL,
		0x8480A10CABC1D036ULL,
		0xA36D195EE11EBD09ULL,
		0x84309BBC3707FBABULL,
		0x57BE2A82CC0A743DULL,
		0xC97935F67B077EC7ULL,
		0x72DBA396DB13A963ULL,
		0x9510F0B8B4E3A419ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC55E70ADAC7FF72FULL,
		0x1965EB81A6590A94ULL,
		0x8F73E2E6F60FACB8ULL,
		0x76B84E7036D83CE3ULL,
		0x72F98DB1CF072432ULL,
		0x9B136327B9A312C5ULL,
		0x1E3799187125A982ULL,
		0x178C52D3B6E27CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B15E5D34A5CC641ULL,
		0x53652AD439799FB0ULL,
		0x0A84BE4A0FD60A05ULL,
		0xB0F0B8CAF8DC90A5ULL,
		0xE4DFAE7FAA8F2DB3ULL,
		0x07065041A6004077ULL,
		0x86CFD85D59F9F70FULL,
		0x16BDDA8C7744C4BEULL
	}};
	t = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8123CE8B36208162ULL,
		0xAD727E6E9EFA928FULL,
		0xD96206C3EA6F74C7ULL,
		0x8296082FC0CD0496ULL,
		0x6AC0100119507469ULL,
		0x6B038C21FB51CB5DULL,
		0x49B903092BAA5A23ULL,
		0x4862223F77E3B032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2A9FCCE0A71168ULL,
		0x11BC14F92E9A570EULL,
		0xB5CFA5DD1531FB27ULL,
		0x5EF7DC789C3B7DF3ULL,
		0xC14A776E1F0ACD7DULL,
		0xF76811929EAE4BB8ULL,
		0x648F2D690AEC744CULL,
		0x1406D7CADC130C91ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86728DDFA171E1C9ULL,
		0x28ECE7A995E3B477ULL,
		0x1B809CB31E27AC62ULL,
		0x5C891F8D407A095DULL,
		0x2D8D1D1D7E388A78ULL,
		0x20E3729C8DF89D5BULL,
		0xF2BC9F82250FC09AULL,
		0x1670DF1FAEC26B70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86728DDFA171E1C9ULL,
		0x28ECE7A995E3B477ULL,
		0x1B809CB31E27AC62ULL,
		0x5C891F8D407A095DULL,
		0x2D8D1D1D7E388A78ULL,
		0x20E3729C8DF89D5BULL,
		0xF2BC9F82250FC09AULL,
		0x1670DF1FAEC26B70ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DD41C0CEE454FEDULL,
		0x6E20B50ACF35250EULL,
		0x9E156E52EF41ACDFULL,
		0x468DC70E58F1D1DBULL,
		0xF217B7F456A4FBC5ULL,
		0xA7A29CEB55381D2EULL,
		0x2494F99679D2EA96ULL,
		0x99A91A67925B5A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA038C9EB196792D8ULL,
		0xA98FB47F46096524ULL,
		0xA85775AB5C88B33FULL,
		0xE4EC736B11EDE123ULL,
		0x4456AF9EEE849750ULL,
		0x4304F3810B1F9DCDULL,
		0x7968D349E11657E2ULL,
		0x6A33AF1E8FB6E0B6ULL
	}};
	t = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D7CDAC7A1F5EB03ULL,
		0x22753233D7220DD2ULL,
		0x59093CE459C9F630ULL,
		0x7296A7350B43746AULL,
		0x0B62C74C550E2270ULL,
		0xE7B5EA765D43C2B0ULL,
		0x2DC11C41BF14DE6DULL,
		0x02FB701B05453DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261D311103CB9C2FULL,
		0xFD9C81C3431AEE96ULL,
		0x527F2D3E2BE44481ULL,
		0x5E065347D5E0839DULL,
		0xC0217706F741B5E9ULL,
		0x7B5696B5B046BA58ULL,
		0x10523C9E589D6C99ULL,
		0x31BA2F143142AEAEULL
	}};
	t = -1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8615ECFE3712DFEULL,
		0x2865A7027A850B23ULL,
		0x9FF19B3B4672F775ULL,
		0xBDAAAF7C44A677BAULL,
		0x208E5770E4CA4AD9ULL,
		0xB9162F3346C33459ULL,
		0x70A6482827308F34ULL,
		0xA93A24CBD18DD83BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6801B3EA311399A4ULL,
		0xC6E603D96E10831EULL,
		0xFE506A51EB867603ULL,
		0x6F9DA0ADD2823DBCULL,
		0x303E2CC81A219E7BULL,
		0xB54212E1E7B38DA9ULL,
		0x51661C571B114560ULL,
		0x94181085B49169CAULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB8A77EF0021BFF5ULL,
		0xD6613329D5730521ULL,
		0x958D4D5F16A58C47ULL,
		0x64990E7A9BF9BC1FULL,
		0xCAC3FF4E437FC900ULL,
		0x070E0C44BD483054ULL,
		0x4365B805AB15E69FULL,
		0x5241E6B9294B2706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB8A77EF0021BFF5ULL,
		0xD6613329D5730521ULL,
		0x958D4D5F16A58C47ULL,
		0x64990E7A9BF9BC1FULL,
		0xCAC3FF4E437FC900ULL,
		0x070E0C44BD483054ULL,
		0x4365B805AB15E69FULL,
		0x5241E6B9294B2706ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB06CBA0BF12FA1AAULL,
		0xD59406A7D94E011AULL,
		0xD3A8FA1B96E90380ULL,
		0xDBA7FD544D20DB70ULL,
		0x16C90E8362E6BAFEULL,
		0x62225F52082F93F8ULL,
		0xCCFC68E3AC3FC38BULL,
		0x3F8C69CE84870817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B1FD5D7A448C40BULL,
		0x4B60EF8EE3618CCAULL,
		0xF000302E8C9E21D4ULL,
		0x2804B765C11A4217ULL,
		0x7DD2020A83418376ULL,
		0x2EC56E29E98C7526ULL,
		0x67EB27D53CC7F33FULL,
		0x0505820C1DF51F86ULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A32CAB44188CD75ULL,
		0x98C8F49FBC2706E8ULL,
		0x533335B048FAE29BULL,
		0x263B1ED566B68514ULL,
		0xA5CD81652690900BULL,
		0xB8B52CACAA731375ULL,
		0x89CB4EB9956868A4ULL,
		0x1A2BAE5ED23F62CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2016F40BEF0B41ULL,
		0x3A6AEB54651F51F1ULL,
		0xB64F9A6860776F30ULL,
		0x4ABDEA8617694B27ULL,
		0x1C267AC1C034215EULL,
		0xDD4CF96A3ACCC7FDULL,
		0xF14E2707EC60EE3CULL,
		0x1786C2432C421195ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC713B8E6C4764582ULL,
		0xA91D8CA820B01AEBULL,
		0x52192B049D2C6E27ULL,
		0x8D953204756A8A18ULL,
		0x6DB7AA2995E7DEAAULL,
		0x9AF521391AEF7E65ULL,
		0x49CA032C19BF7C3EULL,
		0x0B00BF9E2D66A155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0C3F8032A437DFULL,
		0x822798D689DCE7C5ULL,
		0xE141CC97D31A6E30ULL,
		0x4155E70B6E2BE11CULL,
		0x529E2576C748A12FULL,
		0x3186F7801BA8A8DBULL,
		0x679D4048FB7E66BBULL,
		0x45C259BFBE81AFDEULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1A3EDA239695F2EULL,
		0xD2637BD542CDC8D2ULL,
		0xD3EF3525722AC2D6ULL,
		0xE4343C1EF24065F2ULL,
		0xA2C5D661126F0C68ULL,
		0x88280E5B9C455C6CULL,
		0x1F18755D8B5A2A48ULL,
		0x991D113B840F93E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A3EDA239695F2EULL,
		0xD2637BD542CDC8D2ULL,
		0xD3EF3525722AC2D6ULL,
		0xE4343C1EF24065F2ULL,
		0xA2C5D661126F0C68ULL,
		0x88280E5B9C455C6CULL,
		0x1F18755D8B5A2A48ULL,
		0x991D113B840F93E2ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CC9ACB7306156CAULL,
		0x00D919D2B9D5BBE0ULL,
		0xF8C42DA7DBB23E04ULL,
		0xA47B00BD26262465ULL,
		0xC11D536B668313A0ULL,
		0x6CB43FF5BBDD1D1FULL,
		0xFF759FAC1EF2B7B3ULL,
		0x6C2A52E8DCC874B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF21FE1D59BA1FE7ULL,
		0xDCCF4B2CE91FEBB1ULL,
		0xACAA0BC430CE1989ULL,
		0x16B4B11271FBCC1FULL,
		0xD9312A531F8F57F3ULL,
		0xD600460BA07A6F6CULL,
		0xEB294DC84A05CCA8ULL,
		0x0B351990C52818A6ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EEA71C6F8AB7F0FULL,
		0x0488EB40E756226CULL,
		0x876B6D63D5FD204CULL,
		0x3BF36A7EBEFC55EDULL,
		0x5C15A8AFA7DBA996ULL,
		0x8DC13AF8C697FACFULL,
		0x7A5F9B32060FCAF1ULL,
		0xADF9723E6B65FCFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x368124825FE0AA87ULL,
		0x37AFAC7B675D94D8ULL,
		0x9A73924190B8C00BULL,
		0x630DA1CE2CBA9E8FULL,
		0x80C50EDAB136ECA4ULL,
		0x314A520FDDA967A1ULL,
		0xCF12F359C57F74DBULL,
		0x1A5066BE61589E99ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F584A2A433B8D23ULL,
		0xE96995AF645DA04EULL,
		0x34A82C0BA79DC530ULL,
		0x606F0EF361D2DCE7ULL,
		0x7F6AE129CD3F1E41ULL,
		0xDEA309721A0FBAEDULL,
		0xC798CBAD354BAB4AULL,
		0x235117B0C2153F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D5C27282090F520ULL,
		0xB6A1D2C08CCC1CFCULL,
		0x262BEEDEE57CC7CAULL,
		0xC625A0A9AF2EB22AULL,
		0x6F3F6C07B49B91F2ULL,
		0xF9A1FB02B3092186ULL,
		0x9F5F397ED5560030ULL,
		0xBF3135C6375F2B0DULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4142131BF4551C79ULL,
		0x309E66658C71ABC1ULL,
		0xE6E9505E3108FF90ULL,
		0xFF83621BFC303EDDULL,
		0x211E4BAB45EE21D7ULL,
		0x9FECD5AFE4E18A6FULL,
		0xA50323E1DF554594ULL,
		0x65F1BCCAF174EFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4142131BF4551C79ULL,
		0x309E66658C71ABC1ULL,
		0xE6E9505E3108FF90ULL,
		0xFF83621BFC303EDDULL,
		0x211E4BAB45EE21D7ULL,
		0x9FECD5AFE4E18A6FULL,
		0xA50323E1DF554594ULL,
		0x65F1BCCAF174EFB3ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE159F050457F4A39ULL,
		0x5A738C4AD12CD365ULL,
		0xB96CB175C673A01BULL,
		0x8F54DD4DB60287CDULL,
		0xD83D62E6E9C6C50BULL,
		0x58DB92BB1F5764BAULL,
		0xAF27C997170098F5ULL,
		0x09E6CC83B1C68ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA320B18F5163EE82ULL,
		0x7B4A3AEDEF5C8F0FULL,
		0x9C1E9C5765D1B296ULL,
		0x16CA033C76AEDE81ULL,
		0xAB8972ED648459EEULL,
		0xB83171C6C23E200FULL,
		0xD8B11987D9696EA2ULL,
		0xDEB1916F320A769CULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE7F24D1416212EULL,
		0xA6AC655C5CEAAAC4ULL,
		0xF60BC19FB74C4340ULL,
		0xF467A452573C8D53ULL,
		0x99E3FCF6B2A5C048ULL,
		0xC4B882EC578979B4ULL,
		0x33BFE9C7059C96F0ULL,
		0x00D9522F1DB23437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31AAAF9A6AEBA435ULL,
		0x466B80822C0D5D8FULL,
		0x10CB3ACD968CC157ULL,
		0xD0706155157172E8ULL,
		0x49C8B3BBF116B696ULL,
		0x9B805AFB42D54813ULL,
		0xDA08883B553593DDULL,
		0x8B1BFC3D2AAE1433ULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FC734B3EC935477ULL,
		0x9DEF0517663AC7B8ULL,
		0xAF2D5DB10997D9A6ULL,
		0x16F29A37F2B646F5ULL,
		0x67C50F4FE5623A30ULL,
		0x825A1EFAC4D96C57ULL,
		0x8030E9E4B2BACFD1ULL,
		0x155E9CD669BD7512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A4ED76A3623AFB9ULL,
		0x566025DFB3F38D53ULL,
		0xD7AA07AD453450F1ULL,
		0x80FE026623387702ULL,
		0xEBA4551DC2593100ULL,
		0x315677DF9FEBAC93ULL,
		0x810777D009940067ULL,
		0xB3714F9A25AB262EULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA58ED45AA6D748C5ULL,
		0x1D38B11F8ECFD366ULL,
		0x691971ED18E3E7C6ULL,
		0xA41F58FA34FDBAC7ULL,
		0x1D4F4D8998FC6D39ULL,
		0xE1BB7D6216C3D192ULL,
		0x0CBE0FB107727EF6ULL,
		0x1E9CA1F24BCD970DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58ED45AA6D748C5ULL,
		0x1D38B11F8ECFD366ULL,
		0x691971ED18E3E7C6ULL,
		0xA41F58FA34FDBAC7ULL,
		0x1D4F4D8998FC6D39ULL,
		0xE1BB7D6216C3D192ULL,
		0x0CBE0FB107727EF6ULL,
		0x1E9CA1F24BCD970DULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D143F03DC39F88AULL,
		0x62C54AB3CA5C60DCULL,
		0x282DF207B8E25C8FULL,
		0xBAAAA08F198E9D59ULL,
		0x5AA6DD788B2F0884ULL,
		0x0106D37BFA7FB1C9ULL,
		0x95C397839EDA0F8CULL,
		0x14862C4B16DBDE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C96ED4EA614F05DULL,
		0xFA8CF2C8E8DA34D3ULL,
		0x4A24F26CEE536BE2ULL,
		0x4CD720299D090FF4ULL,
		0x165FD26996763807ULL,
		0x7BEC5437C47C7223ULL,
		0x9F96CB6021CE39DBULL,
		0x7F1C05A84B902B21ULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2B50315F1ED58EDULL,
		0x96F115E052661FBCULL,
		0x2EFA1467D1C7E271ULL,
		0x535E3F88FF44E7DFULL,
		0xA93A52AF80F04FF0ULL,
		0x87EF800DBEDBA4D7ULL,
		0xF25940C67551B399ULL,
		0x3009D4EFA39F916CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35DC34BC7C4CD7B0ULL,
		0x1C304826E9A3965CULL,
		0x5D146ED10696E81EULL,
		0x62D1F27FEA18F12BULL,
		0x5709E3EED66DDBD7ULL,
		0xA8FEAECF6B2C58DBULL,
		0xD6B54BC55F2D4439ULL,
		0x0197D1E08541D5E9ULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2B808200104BA42ULL,
		0x494A530F9E05C509ULL,
		0x91602E6042AD0E10ULL,
		0xB5CC2452C5BD532EULL,
		0xB442D79F5BB45662ULL,
		0x35313383F1DAC878ULL,
		0x8FDDFE1D5951C067ULL,
		0x553709E0369B2168ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4FDB3A04D786F78ULL,
		0xECC31CE1F7DC2D64ULL,
		0xE1CE8AA72AF6DF8CULL,
		0xE421C7A164B95E22ULL,
		0x134BBA0EA53A552AULL,
		0x8C04110D0C4BD292ULL,
		0xF1DBCF8A74A755D7ULL,
		0x78F2CDF7A6FF94C8ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD3C0A4EE9D1A5D6ULL,
		0xD5B265F123A4B1D2ULL,
		0x03E2DB5A78CAA317ULL,
		0x63270854DE1DF1AEULL,
		0xABAF20B8C9A330C0ULL,
		0x08AD00151174EDDBULL,
		0x94E48F32B69F0131ULL,
		0x6CC55C80B8F6CEB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD3C0A4EE9D1A5D6ULL,
		0xD5B265F123A4B1D2ULL,
		0x03E2DB5A78CAA317ULL,
		0x63270854DE1DF1AEULL,
		0xABAF20B8C9A330C0ULL,
		0x08AD00151174EDDBULL,
		0x94E48F32B69F0131ULL,
		0x6CC55C80B8F6CEB1ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F034F828BC0C36ULL,
		0xC9F0B450F7468455ULL,
		0x0EBFCDB4C2BCF20DULL,
		0x6E9FEA459CCC5AECULL,
		0x4DC6D1A19BE28560ULL,
		0xD64A722964DDA1DCULL,
		0xD0299878BAA62327ULL,
		0x038CFE02F7EAE538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807ADE815705FC25ULL,
		0xBEE8A4DDE20F0B04ULL,
		0xF640FCC1C0552F36ULL,
		0x6B485C3647BEB93FULL,
		0x0750E49067FF20CAULL,
		0xBC03604E47F6E9B9ULL,
		0x35963257AD346D5CULL,
		0x5A5F4B29BEDB37F6ULL
	}};
	t = -1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6202B879937923ACULL,
		0xF4776972EFC69358ULL,
		0xB65464D8C852F1C6ULL,
		0x1C9EE1F1459AF5A0ULL,
		0xF42D3C37BA64BAE4ULL,
		0x004B93A571F3DFC7ULL,
		0x9DAD16F55B81E9D2ULL,
		0x49D5E65239437D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x991876337AEAADB0ULL,
		0x381D124B4485EFA4ULL,
		0x9A5CB0B1C6FD2BE5ULL,
		0x3A36FB4D485067D8ULL,
		0x19666668B9234766ULL,
		0x3242A733B1B0530EULL,
		0xD8848A2D3AE8BE47ULL,
		0xD31A517D08FFAAFEULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6FD7636835DDB33ULL,
		0x625126867F15A8FAULL,
		0xDFB6DCF9859C18F1ULL,
		0xAD30E83F6AEF2BC3ULL,
		0xC794E3FEBC5D2781ULL,
		0x7DAD48019B38DB2BULL,
		0x54701FA075E558E9ULL,
		0x6A826E772B1C2712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E54BBFB770F361ULL,
		0xF86564D73F1E8C7AULL,
		0xB3B2B72104141226ULL,
		0x4FDDA81490D85F33ULL,
		0xFB7C002C46FB227CULL,
		0x0BA0000647416E99ULL,
		0x55224529134984FDULL,
		0x8BF20A21822AEFF1ULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE4B262E04610A3ULL,
		0x4CBB8022F7ABA8A8ULL,
		0x64EBAA8AA4C3652AULL,
		0x4AD12221885793A9ULL,
		0x64DAA5B90CC9DF46ULL,
		0xCAE2FA6028B5BB15ULL,
		0x106F4B757199463FULL,
		0x2553FF7902BC857CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE4B262E04610A3ULL,
		0x4CBB8022F7ABA8A8ULL,
		0x64EBAA8AA4C3652AULL,
		0x4AD12221885793A9ULL,
		0x64DAA5B90CC9DF46ULL,
		0xCAE2FA6028B5BB15ULL,
		0x106F4B757199463FULL,
		0x2553FF7902BC857CULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8D304314A3082C8ULL,
		0x6C4E623CBFDB1EB2ULL,
		0x1EF0D4B85669F8FCULL,
		0xFE3E51DC5C47F5B6ULL,
		0xB589A38EEED47753ULL,
		0x156895113A18F315ULL,
		0xBB4F350F7A8305DFULL,
		0x66F2BC3A93CBE0ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B98C1C9D69F45FULL,
		0xFC3753F515EB68C8ULL,
		0xB7E11699F9C8CA07ULL,
		0x9F0A1E275A6E7395ULL,
		0x9F8328F9D3959CFAULL,
		0x5C2977706FAB7021ULL,
		0xE12D3570451E41CEULL,
		0x83BB4E0834746887ULL
	}};
	t = -1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF129412855BDFFD0ULL,
		0xDDB65FB82F6BD938ULL,
		0x4B864A57A3C45A0BULL,
		0xF5748AC6B736B8C4ULL,
		0xB3A87B8CFCD97BEAULL,
		0xF32A8A9EA2DBBF82ULL,
		0xA458D11AB26A8EBFULL,
		0x5D002BB527A5E93EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA21B45712998F8ULL,
		0x406AC4C311F8D264ULL,
		0x0F16DD3EA08349FEULL,
		0x90DB582E398E0C0BULL,
		0x40BE0B85F0B4075BULL,
		0x7B6BEBD64C620F73ULL,
		0x475B9450F6F40B07ULL,
		0xB52DF0C7D77CD9B5ULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1555B67B331218B0ULL,
		0x6935B3BFB81E1423ULL,
		0x8F8C999E541A5145ULL,
		0xF5D90CEE79796622ULL,
		0x5C29AE5AE8BF3881ULL,
		0x50C32893F963BD14ULL,
		0x2E3C69B3FF7006D4ULL,
		0x59CF2CDA925A8BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C01B098F1F01FBULL,
		0x82E9441E8778D6B5ULL,
		0xC7F0A37B88658476ULL,
		0x22C0BE575E0A44DAULL,
		0x96A998409B3DC16FULL,
		0x4874DD22E73DC257ULL,
		0xD8810C87BE722CEDULL,
		0xF8A9324F9F012CFFULL
	}};
	t = -1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x309A8E27FCDBDE8FULL,
		0x6066CD891244DACBULL,
		0x82AF7CDA5D6D858FULL,
		0x0C014C6A4537463BULL,
		0xF860773C6AD72372ULL,
		0xF37F7C2D31B9B9AFULL,
		0x9BB39E6AE9DE334BULL,
		0x89D4F5A967F40AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309A8E27FCDBDE8FULL,
		0x6066CD891244DACBULL,
		0x82AF7CDA5D6D858FULL,
		0x0C014C6A4537463BULL,
		0xF860773C6AD72372ULL,
		0xF37F7C2D31B9B9AFULL,
		0x9BB39E6AE9DE334BULL,
		0x89D4F5A967F40AC2ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D0E5F31CA13B21CULL,
		0xABE24BD705681262ULL,
		0x599B6EBFDF396B89ULL,
		0xD4015ADA21600BA8ULL,
		0x81EC6ECD9E93C526ULL,
		0xCA4461B8D8EEA9E8ULL,
		0xE3549698B9E1D445ULL,
		0xEDC2D8D928CE616AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6946289C824F3333ULL,
		0xE5406C03A47465C2ULL,
		0xD9A5E1450813F86DULL,
		0x332F1BE8F904B0CCULL,
		0xEA7E272F490C3330ULL,
		0x7A451BCFA47BE553ULL,
		0x8B6A8669FF5F013DULL,
		0x19F840B50DAC5468ULL
	}};
	t = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76B5C762D61180D0ULL,
		0x2DB77E920FC607CBULL,
		0x5BC0A35F74DE40D9ULL,
		0x539755477AEC9D6FULL,
		0x4D4B9A8F58BE728EULL,
		0x694BD106858D2D37ULL,
		0x5A4A6C992780BEF5ULL,
		0xD46C32744542ABE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90937454F4F9687CULL,
		0xDE7EDFC07939E023ULL,
		0xE3B40890D03ED410ULL,
		0x77D70C9882EAC900ULL,
		0x64A370D359D9EE02ULL,
		0xFB650F5EF47A2D10ULL,
		0x441D8D074CD26022ULL,
		0xC2A55A4DA303FC9CULL
	}};
	t = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA12FA91789D95FE8ULL,
		0x44CCF3285A0F4CA3ULL,
		0x1C953AD851499278ULL,
		0xDF8880996E0AE9E1ULL,
		0x339482A221029196ULL,
		0x5426C0C1E12A49E7ULL,
		0xEE0A8000FA6C6CB6ULL,
		0x62CB595958094365ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7413DDF9D49D92ULL,
		0x1107EB48ACB16617ULL,
		0x41B1608DD5C0F94EULL,
		0x7A3AD94A92661349ULL,
		0x590DE7ABDD745A6FULL,
		0xBC997C5E5AB9744EULL,
		0x47A6CE90FB4BFD16ULL,
		0x4725576F93D60AA5ULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8724DF870C98FD79ULL,
		0xA206A7CE7C8B9706ULL,
		0x8E512A409A6C80FEULL,
		0xAEDDFCFF180CE4FEULL,
		0xB70480B855CF9C26ULL,
		0x3B2A850FCE711C36ULL,
		0xF8D02CAF5AEDFD0DULL,
		0x07FE4DD2BF83C12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8724DF870C98FD79ULL,
		0xA206A7CE7C8B9706ULL,
		0x8E512A409A6C80FEULL,
		0xAEDDFCFF180CE4FEULL,
		0xB70480B855CF9C26ULL,
		0x3B2A850FCE711C36ULL,
		0xF8D02CAF5AEDFD0DULL,
		0x07FE4DD2BF83C12EULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45CE1A85DFC607A9ULL,
		0xBE98BD21A5CB784BULL,
		0x64C4E2C6E31F9944ULL,
		0x59F75520D12A7E58ULL,
		0x790E76434A09C7F3ULL,
		0x32DC0D5E0706693FULL,
		0x9F965D17DF0D6AF9ULL,
		0x082E4FB2CC3A46FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x179013059C2E58DDULL,
		0x76F9AA853EB6DDAAULL,
		0x2971B5089900C963ULL,
		0x45544BF27B34A338ULL,
		0x398A7AE8AFB3EC99ULL,
		0xC537043038408E20ULL,
		0x5DF0B333E5D99848ULL,
		0x8B4ACAEF7C0B6742ULL
	}};
	t = -1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FCCBC96138D79D4ULL,
		0x41CE9E345F239381ULL,
		0xCC8BDFDCD9DF07E6ULL,
		0x4CC8D391EE05C897ULL,
		0xB6EF055D72FF732FULL,
		0xEBAE0A44E0571340ULL,
		0x7F82B7E0D7BC0AEAULL,
		0xFEFFC5DE63070296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A271A6328806674ULL,
		0x9F916DB0B92E499DULL,
		0x55221E46900AAC46ULL,
		0xFBC314626F5A7077ULL,
		0x6DF34B9D326738C1ULL,
		0xCB1A0C503566BD88ULL,
		0xE0E4095FBCBB8E30ULL,
		0x13402FB0E259FB29ULL
	}};
	t = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7A67288DFA5EEBBULL,
		0x6B4A6F6281C005F6ULL,
		0x6257126DFCBE2330ULL,
		0xA1AB04CA656A9548ULL,
		0x6FF1466DF6C1BAFFULL,
		0xF4CEEC88DCB3E53BULL,
		0xA054E874AA41AD70ULL,
		0x79793CFB63517AA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F487DFE7F7D85B3ULL,
		0xB6ECFACA6C162BA1ULL,
		0x3FC72BB3E8D451EEULL,
		0x1E0DF92616CE3A5DULL,
		0x239FA85989332EBFULL,
		0xD2B37C3256981426ULL,
		0xA2CE099B86448B82ULL,
		0x21BE38A24740E60DULL
	}};
	t = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85A053D47E97B84BULL,
		0x7E54EDE7E167A738ULL,
		0xF7CAA5795AFC0C3DULL,
		0xCE5F6D19B9AE156AULL,
		0xB8D4329320F73BF0ULL,
		0x1CA73EC7C5580368ULL,
		0xF16EA500DCCC3A73ULL,
		0x055327522D539776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85A053D47E97B84BULL,
		0x7E54EDE7E167A738ULL,
		0xF7CAA5795AFC0C3DULL,
		0xCE5F6D19B9AE156AULL,
		0xB8D4329320F73BF0ULL,
		0x1CA73EC7C5580368ULL,
		0xF16EA500DCCC3A73ULL,
		0x055327522D539776ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4626429B956165AULL,
		0x9572F0FA3DD4174BULL,
		0x9A359B6C50B6A7D0ULL,
		0x2084EACB8DC65F49ULL,
		0x04583B152C2A28DAULL,
		0xA2E93CCFCBD5B278ULL,
		0x6DF98FC1B48C06B5ULL,
		0x0213205A5D9EE8C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64751A30F7B36572ULL,
		0x213D6344308E532BULL,
		0x41E083926940118CULL,
		0x1AF2750CFC91625DULL,
		0x5AAA97A9CE04F285ULL,
		0x6772278E97F599EBULL,
		0x62E841F81E91C477ULL,
		0x66A6062ED3E52501ULL
	}};
	t = -1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4EAE3357B91CEC1ULL,
		0x19DB96BCC478E1A6ULL,
		0xB18F8F9C6382C076ULL,
		0xB9444E5DE1F63FC3ULL,
		0xCA88E5C9E828F5E1ULL,
		0x196F9FBDC463F81BULL,
		0x82017278F343C0EAULL,
		0xF09413C973746097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659C480D1AB859A2ULL,
		0x377BF8ED2FEB1FFFULL,
		0x67F800EC12CA1CEEULL,
		0xF86BD3A3C16466C9ULL,
		0xDDE5AE67414B1C34ULL,
		0x33B0A607CC5EAF3DULL,
		0x530FD1C49F369519ULL,
		0xD2ACC0FCF93E3F68ULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5CBC2E21E9F1251ULL,
		0x7FC92721ED7F6F18ULL,
		0x1414E146FDF907E9ULL,
		0x5B8ACE27CEF25985ULL,
		0xB54BFBC94A42485BULL,
		0xAFF5ECB9F62CF9BDULL,
		0x9575845F9722EFFAULL,
		0xABB395D47B483738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB83092BE3EFE00BULL,
		0x86358BACB437074CULL,
		0x8CC99F5B1851DED9ULL,
		0xAF314D2192E95F6FULL,
		0x45D5B9C099377EB2ULL,
		0x58461E7F1CB698EAULL,
		0xA88165451B1526B2ULL,
		0x31C895DC1A937F09ULL
	}};
	t = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA395B59B3ECA9F4BULL,
		0xC6A7D2E7C560E3BEULL,
		0x47A7A8C1C521E464ULL,
		0xBF6DF534D8E9D439ULL,
		0x4E106AC4901ECE3BULL,
		0xC31390F66712F937ULL,
		0xE0E831A26C6F7061ULL,
		0xAC5807DA78749919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA395B59B3ECA9F4BULL,
		0xC6A7D2E7C560E3BEULL,
		0x47A7A8C1C521E464ULL,
		0xBF6DF534D8E9D439ULL,
		0x4E106AC4901ECE3BULL,
		0xC31390F66712F937ULL,
		0xE0E831A26C6F7061ULL,
		0xAC5807DA78749919ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0ED8C78831AFE06ULL,
		0x7962517717DA04F1ULL,
		0x286AEE3BEEC89C3FULL,
		0xAC203E0AEC43AF25ULL,
		0x4B4D8CE7918D3E76ULL,
		0x49F6AFEC148DE6EEULL,
		0xE6B88EDB3C7DA1A9ULL,
		0x1ADB33C30DF125C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6E40985F07F3FDULL,
		0xB26555A44C0D7A95ULL,
		0xE3B5C9918291B8E1ULL,
		0x5705EAFBAE84F257ULL,
		0x18E815CF8D39E5DEULL,
		0x9A46749961B463ADULL,
		0xC94B4F6B23C77016ULL,
		0x02B96DFCA691C4E1ULL
	}};
	t = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3497E5D18AF2D3E9ULL,
		0x2395481AFCD25E3BULL,
		0xD6C15BD0F37EEC64ULL,
		0x20633C596B4EB0CAULL,
		0x327732F7A7603F78ULL,
		0x14271231D3480563ULL,
		0x1A4610A6F207EB5FULL,
		0x6373CE8776B7B20BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0839036C4F8DE54FULL,
		0xC3C4D3D6111FBD6BULL,
		0x9772048D74BB92C1ULL,
		0x881A3D5F668F06E2ULL,
		0x02DECDA232FEB079ULL,
		0x04EDCB009E8B2A32ULL,
		0x0DAE940873074168ULL,
		0x0BEBCAF7E70F5EF6ULL
	}};
	t = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE4AC0D120483B30ULL,
		0x291F14053878777DULL,
		0xE413DD72145CE7A4ULL,
		0xF8EAA77536038556ULL,
		0x226D96A7C6D286C9ULL,
		0x2890DF8ED12AE1B0ULL,
		0xA8BEBD0E1CE8F62BULL,
		0xECD76B4DB2AEB812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0BC583861DB16BULL,
		0x0CA37BC780927962ULL,
		0x69B6EA5A169A9D2EULL,
		0x5516585A4F93E05AULL,
		0x63C2414FC9DA2C21ULL,
		0xC7F6004B949F35BCULL,
		0xBB1E044EF4CA6FA3ULL,
		0xDA8ED673FCF163F3ULL
	}};
	t = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C6DE0535B093A3FULL,
		0x39FCF9D2A1608898ULL,
		0xBFE35D2AB7ABD30CULL,
		0x7AD6DFD38AE44A5BULL,
		0x705CAE2E033F6D53ULL,
		0x599A271D0D3E081AULL,
		0x57B47F97522DB82FULL,
		0xF40C76127CD21225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C6DE0535B093A3FULL,
		0x39FCF9D2A1608898ULL,
		0xBFE35D2AB7ABD30CULL,
		0x7AD6DFD38AE44A5BULL,
		0x705CAE2E033F6D53ULL,
		0x599A271D0D3E081AULL,
		0x57B47F97522DB82FULL,
		0xF40C76127CD21225ULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x186918F27C588AEDULL,
		0x035897895D1382BFULL,
		0x3D0179B6B09FC691ULL,
		0x013729145F6217E9ULL,
		0x0E46344358D05607ULL,
		0x0E1FE468C404FDB0ULL,
		0x203D974119403B66ULL,
		0xE855EBF95D590043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E09B239B7504C54ULL,
		0x993E7CBE2267D316ULL,
		0x2857E19D86B8711FULL,
		0x358382521B1A39B1ULL,
		0x5E3312CF84754A3CULL,
		0x80CF540783538347ULL,
		0x98D95FB747F2F5E4ULL,
		0x8F61AA9CB08050B8ULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC82989E932583FAEULL,
		0xD7AC303B13925BD6ULL,
		0x3D38423DA70978A6ULL,
		0xDD7B9ABB7D3A9D91ULL,
		0x0E8E8A26C7B1B0FAULL,
		0x7F4472C7B5199B4CULL,
		0xD8E89CB9F43748D5ULL,
		0x8426FC01D4607D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975BCD67D929D216ULL,
		0x29BD1537EB772D9CULL,
		0x489C9958AD7278E9ULL,
		0xC66894C997E57314ULL,
		0x6D6625637F64FE51ULL,
		0x1C85035ACABAC2D2ULL,
		0xAF3DAF944CD6879EULL,
		0xD21788ECFF03A2BAULL
	}};
	t = -1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E476549A1472C88ULL,
		0xE017BCA9AC9529D9ULL,
		0x7C0B038DDA0975DBULL,
		0x1563902FC9317775ULL,
		0xC336B6881D7CEE0EULL,
		0x5E60207E152B07C2ULL,
		0xF0331B9190F0EFFEULL,
		0x2C5809807CF6C6F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B2FC735BA7FAABDULL,
		0x906188D4F7ECCEB2ULL,
		0x1D75062DE88F598EULL,
		0x25646DA11DCCB8B9ULL,
		0xB5F89371618A8D7EULL,
		0x452AF19859A32288ULL,
		0x4A4353A1A64738FCULL,
		0x5701176F3DEA9316ULL
	}};
	t = -1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4D68759CE766118ULL,
		0xA9D851A9A0E3441AULL,
		0x3481194E0F8238C6ULL,
		0x7F8F832E7E03A5D0ULL,
		0xAC3DE9D00BB32C02ULL,
		0xA579EAD9922F9A65ULL,
		0x2ACAE5D702E6A063ULL,
		0x45508863EDA885BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D68759CE766118ULL,
		0xA9D851A9A0E3441AULL,
		0x3481194E0F8238C6ULL,
		0x7F8F832E7E03A5D0ULL,
		0xAC3DE9D00BB32C02ULL,
		0xA579EAD9922F9A65ULL,
		0x2ACAE5D702E6A063ULL,
		0x45508863EDA885BFULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFDCF51D01D6A023ULL,
		0x5E5923B7985D152CULL,
		0x6BCCE8B32C74417FULL,
		0x0A3B6B0523457E36ULL,
		0x4D47BB67FDD7E684ULL,
		0xA5AA4D7619933043ULL,
		0xDE4198290799B45CULL,
		0x3D2A573E7D3CEE9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0F63B1D4D80AEFULL,
		0x349679B7935515B1ULL,
		0x057C8C997607DABDULL,
		0x155CB0A87770E3E3ULL,
		0xD2D96D949D5897A9ULL,
		0x37945AA0D1009BB3ULL,
		0x4D62BB5A9DAE22F2ULL,
		0x1BB4742C1682B5ECULL
	}};
	t = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9B0932FDF7B1485ULL,
		0xAE2D982F5FA44B42ULL,
		0xBD5C9B20671A12B2ULL,
		0xF9873DE8EE65D42DULL,
		0xE7606DC08823FB0AULL,
		0x32F9128114AE902EULL,
		0xD91E1C937ED69AC0ULL,
		0x9CFCD8280BE15B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77ACF90BD48437AEULL,
		0xC54EBF6386DD2402ULL,
		0x5FE8DA04FCF1E38AULL,
		0x7FCCBE10FC84B5FAULL,
		0x14B78705B80FA8D7ULL,
		0xB2ED32BAAF1AA974ULL,
		0x7C4509B02D1D6FB9ULL,
		0x91FEAB9475F401B7ULL
	}};
	t = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EEF9129FBB3998CULL,
		0xA0584336ABA75DFDULL,
		0xEE28FAE2DE8E9190ULL,
		0xEC67BDE944E24C11ULL,
		0x1143C58CA773D181ULL,
		0xA3BF5A6B7CB5AA56ULL,
		0x7A817A476BC5E1A9ULL,
		0x88E1D9C9508CF105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FBB0B6BB3B0F54ULL,
		0x35FF995D1011CB82ULL,
		0x95C24B14433F3871ULL,
		0x69F5470668C2DACCULL,
		0x54F68F0E10FAB5C3ULL,
		0xC130BBCA4A2CD0AEULL,
		0x54DACDEBC635D90FULL,
		0x460EF7C8455E868AULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA38F94796B217D0ULL,
		0xB91FDFC6E350A1BBULL,
		0x65B33623FA34B30DULL,
		0x610F0B43DB48B8CDULL,
		0x997E10D734D507F4ULL,
		0x243A557B3A520C5BULL,
		0x05FBC557131E007DULL,
		0xAF0285B31DF9CC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA38F94796B217D0ULL,
		0xB91FDFC6E350A1BBULL,
		0x65B33623FA34B30DULL,
		0x610F0B43DB48B8CDULL,
		0x997E10D734D507F4ULL,
		0x243A557B3A520C5BULL,
		0x05FBC557131E007DULL,
		0xAF0285B31DF9CC9FULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6A5D0BB8F31497DULL,
		0x85BA0D078D691D43ULL,
		0x66909065E9B60B24ULL,
		0x76EA076D657D381CULL,
		0x8BA93964D682B75FULL,
		0xB0AFE56BE3E2A7AAULL,
		0xA411E667310FE621ULL,
		0x05B6A7EE0AD9E3B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CD64C9AB037A67CULL,
		0xE0FDD5A284AD5F89ULL,
		0xA508820877D13EBAULL,
		0x963C70BBE51E9BC7ULL,
		0x2FCE68BD2D8FF8A6ULL,
		0xFCA1A062295EBE93ULL,
		0x37E6456EA59A9615ULL,
		0xB1164E8DDFCF23B1ULL
	}};
	t = -1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8E62061B3D41C5BULL,
		0x1C7683AF385FD71DULL,
		0xA28A57CECE8AD834ULL,
		0xA9293276289FEA0BULL,
		0xE891E67C6CDD62C1ULL,
		0x2EC477EF2F19A47AULL,
		0xADC550AFB89A3C19ULL,
		0xBDCB89D0E0CA4264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5067BE92DEFF9E9BULL,
		0x03FFAF12E1596C18ULL,
		0x90B795EDF9259B82ULL,
		0x2A9EDB6DDD0E25DFULL,
		0x99EF80335BBBFD16ULL,
		0x1EB22940114891FEULL,
		0x96896831EAF2DCC3ULL,
		0xC6DAF4ED4B28BF43ULL
	}};
	t = -1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACC753466DF4665AULL,
		0xC79EED5B61530D03ULL,
		0x7FE48EC3489CB966ULL,
		0x8AD45F7E5D3B16BFULL,
		0x5C44C7CBBB11F16EULL,
		0x908A0911D6FEDEDEULL,
		0xA2595A8AD7EFA6B3ULL,
		0x73C43EABD2936E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5757D40D7A912BULL,
		0x838F16B86BD88F3FULL,
		0xF2D8C3D573511493ULL,
		0xBC28621BEDCA98C6ULL,
		0xEC86525FDAA5E59AULL,
		0xFB0C8F98DDAD71E4ULL,
		0x7603D3EBEDA640E0ULL,
		0xF1EBE39E4AF9F286ULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF491CD6F9F6115F0ULL,
		0xCE0608E683527BF3ULL,
		0x9E2024F09C8000ABULL,
		0x6A316D119C0BCF2CULL,
		0xA804C071E4955C6BULL,
		0x7F61DF6CDC353588ULL,
		0x6F82564B1FF74C09ULL,
		0x269085F25BF7311EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF491CD6F9F6115F0ULL,
		0xCE0608E683527BF3ULL,
		0x9E2024F09C8000ABULL,
		0x6A316D119C0BCF2CULL,
		0xA804C071E4955C6BULL,
		0x7F61DF6CDC353588ULL,
		0x6F82564B1FF74C09ULL,
		0x269085F25BF7311EULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85C82BF3C9497286ULL,
		0xFF7BB9227468BA9EULL,
		0x9FEAA9AD8018B030ULL,
		0x712936BC9DF8C102ULL,
		0x79F82A4148665366ULL,
		0x293766665FF81FDEULL,
		0xD76054217F4637E8ULL,
		0xA9A8BB048DDEA602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D113B05117A71FULL,
		0x2482426419C10182ULL,
		0x16DB6E5C5DAE7FB4ULL,
		0xDE280140EF6251A7ULL,
		0xC5C8EAA1BB5B2514ULL,
		0x4F50679DA737E814ULL,
		0xD5FA9969200CCA1EULL,
		0x2ACDD582FD9C4F90ULL
	}};
	t = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7698AA2E74D37BA0ULL,
		0x2C59B55862A7011BULL,
		0x5A316ED09A5DF80CULL,
		0x67E02078A2F3F900ULL,
		0x752F06F731BD4408ULL,
		0xC3EA71849D623954ULL,
		0x9B6C2FBAF1BAABB8ULL,
		0xE3E0E192E713D1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFF245396AE8E195ULL,
		0x4EA8ABBB30637F40ULL,
		0xC17933CDA20E3E63ULL,
		0x38E41B222F3E3786ULL,
		0x80A98F4D262C5D2BULL,
		0xB402202D6DA121F8ULL,
		0x6D656040DDBBE815ULL,
		0x11DBE9C584D0EC67ULL
	}};
	t = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBD7044816FB1446ULL,
		0xABF9064C8F2638D2ULL,
		0xF2BFA973D36212AFULL,
		0x371A537B34F65882ULL,
		0x8C9611FD3DE52FA6ULL,
		0xB1F508C52FB8984CULL,
		0x06D3C9D9C3F4C422ULL,
		0x4F262A7BF55EC068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E690D127DC3D61ULL,
		0xD55FC61584273CFBULL,
		0xE3B63B4F7D92A23FULL,
		0x41893D6DC2BF9F28ULL,
		0x506B582DDF3F598CULL,
		0xBE9EE020342C549FULL,
		0x4E41158A8929B157ULL,
		0xFB60BB17B8369D6EULL
	}};
	t = -1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7EDADB9EF1F1445ULL,
		0xD6C5780F255B34CBULL,
		0x203191F4D44B00EDULL,
		0xFD00B44450A5B3B5ULL,
		0x0949007410816D70ULL,
		0x8771FD8BDE41782CULL,
		0x5C1DE99606389173ULL,
		0x92AC64C6C55149E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EDADB9EF1F1445ULL,
		0xD6C5780F255B34CBULL,
		0x203191F4D44B00EDULL,
		0xFD00B44450A5B3B5ULL,
		0x0949007410816D70ULL,
		0x8771FD8BDE41782CULL,
		0x5C1DE99606389173ULL,
		0x92AC64C6C55149E4ULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55AED062B5997610ULL,
		0xB9AFE3A73DB46932ULL,
		0x015AC827BB098524ULL,
		0xB28DD534B215CE63ULL,
		0x3A6FA357FC4CC18CULL,
		0xEDCDE7365C05F370ULL,
		0xC9721A025E2DCC46ULL,
		0x5D4E0886E051732AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76A06CBB3019E64ULL,
		0x4D030BB0A0743300ULL,
		0x73D7ECBE7C1D1ABCULL,
		0xEAADBC30055E04DAULL,
		0xE219ABCB1C463164ULL,
		0xB4EA8DE4420106D6ULL,
		0x10C02FCFC319B055ULL,
		0xFDAADE0AE6EFC8BAULL
	}};
	t = -1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9693C8F2FADDAB15ULL,
		0x55FD2326C851EF1CULL,
		0xFA86D41691EA38E5ULL,
		0xEBA72B02A9058D11ULL,
		0xA7C0CAC9A0BB6F97ULL,
		0x9DBFCB18755B7C09ULL,
		0x206BE8E8CBF4041FULL,
		0x031C17D7A94B176EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x537ADF4B0A01A8B4ULL,
		0xE2970200D11E5CF5ULL,
		0xAF064FE3DEAB90D0ULL,
		0x238D265A399ED012ULL,
		0x560C750332C131CDULL,
		0xFEFDF044B7BFB7E2ULL,
		0x1476058E25F6969AULL,
		0x0E2E5C3DF96CEE75ULL
	}};
	t = -1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BFC6AAD762C0680ULL,
		0x027F42A90DD6AC6FULL,
		0x35026591CE976F5BULL,
		0xD5564898CB012951ULL,
		0x4AA1F18AAF0E0427ULL,
		0xDF0CCF582C3729DBULL,
		0x1598363DDE8940DEULL,
		0x4F800E24BFE73189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A90CA32B033FF7BULL,
		0xB2292DDF774F786FULL,
		0xC79EA83BA6292278ULL,
		0x9E38E8B624125689ULL,
		0x061B5EC6AEFF7595ULL,
		0xE7723388BDCDFDF9ULL,
		0x22ADC1FF927A2CBCULL,
		0x5ACB0331A301A967ULL
	}};
	t = -1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD89B256EEBF13938ULL,
		0x47977A645371BBDDULL,
		0x22E42313DAA3789EULL,
		0x318A6864C38F9B4BULL,
		0xB3E9F9D4B0042882ULL,
		0x88B47AF4F9F6A280ULL,
		0xBF8600F2462A8137ULL,
		0xC784A33C8373C563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD89B256EEBF13938ULL,
		0x47977A645371BBDDULL,
		0x22E42313DAA3789EULL,
		0x318A6864C38F9B4BULL,
		0xB3E9F9D4B0042882ULL,
		0x88B47AF4F9F6A280ULL,
		0xBF8600F2462A8137ULL,
		0xC784A33C8373C563ULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B74CA2D6E2FF8C8ULL,
		0xF7B37F6054732E5CULL,
		0x0EFD787625AEFE6EULL,
		0x0CF2D53EADE9CB64ULL,
		0x33099D3E276756ADULL,
		0x676FF2F910855FF2ULL,
		0x090406010079E722ULL,
		0xAF053CC2F971EA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79B679076A544B0ULL,
		0x077D0B424B9D682CULL,
		0x5333333B4A203634ULL,
		0xA7BBBA05819617C6ULL,
		0xFCDAD8FA8A2AF1D2ULL,
		0x86046E84AD194D56ULL,
		0xAC6CC003E39FC201ULL,
		0xA01210513F3CF92FULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EF3250F39568D54ULL,
		0x886082335094F773ULL,
		0xA27A54FA14E60FFBULL,
		0x14D83385F8B134F7ULL,
		0xC41601849BC2A0B1ULL,
		0xA1D99F754B9B27EFULL,
		0x4440C5C66DEB0A06ULL,
		0x236CBF61594CD49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85BEB56792C1B0F8ULL,
		0x09433663572B1267ULL,
		0xEB2C3CACD097DE03ULL,
		0xA99D429D65135D7DULL,
		0xA105F3CB750BB9CBULL,
		0x1092AA4FCAC07DCCULL,
		0x0F4293E997D7BF4CULL,
		0xBB69A21F6CCFF07FULL
	}};
	t = -1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27E0B37FF819A163ULL,
		0x59376C840DDCB497ULL,
		0x298BFE1A6A298869ULL,
		0xA12387091E0EC0D8ULL,
		0x07A9AE0D136D408DULL,
		0xE3A7F9375C5F1AA9ULL,
		0x9FD1B68C138D85C1ULL,
		0xC02051C23B8AEDB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9C64C551AFFED7BULL,
		0x2B4EC5C589B7FBF3ULL,
		0x77D733480892B4F8ULL,
		0x4AADAF4DE899BE06ULL,
		0x1F5638744842D4ABULL,
		0xD34064F2B895996DULL,
		0x992B10C0E993CA42ULL,
		0x4C257EBFFB8861ACULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0238A6B7F49B530ULL,
		0xEB69B5CF6C7AB69BULL,
		0x9A384A69B92BB932ULL,
		0xBC609A1BDC730EA0ULL,
		0x3FD16DE3099B2BB6ULL,
		0x9C41727125EDB8EEULL,
		0x650DD7B6A53F219EULL,
		0x0F53C8EB4D7757F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0238A6B7F49B530ULL,
		0xEB69B5CF6C7AB69BULL,
		0x9A384A69B92BB932ULL,
		0xBC609A1BDC730EA0ULL,
		0x3FD16DE3099B2BB6ULL,
		0x9C41727125EDB8EEULL,
		0x650DD7B6A53F219EULL,
		0x0F53C8EB4D7757F0ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20D3EDCEEE93B6E2ULL,
		0xF163076414922FC4ULL,
		0x87197B5840E91F46ULL,
		0xE094B44CC181D44FULL,
		0xCE544AB570B0128AULL,
		0xDEC83687F5FBA33EULL,
		0xFDB317155C93A09CULL,
		0x919DF7E8135DC180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7974D0BD9E54324FULL,
		0x689C3DE0D18C46E8ULL,
		0xA0BC0F0E5CA1BB46ULL,
		0x97DFFBC52AFCF19EULL,
		0x6CEF3BC5273D96A8ULL,
		0x74171F8214395C21ULL,
		0xF0F6AB956E345B67ULL,
		0xDFD5A895207308E5ULL
	}};
	t = -1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3B0E211943FBAA5ULL,
		0xE58C34FA7E270B27ULL,
		0xD6451E6FA0D0AE50ULL,
		0xB59252B9624E87DDULL,
		0x70C7BF30B9F98FBBULL,
		0x417A650C66AD1E6FULL,
		0x6720D0B20B3CB7B4ULL,
		0x01F0FCB0BE39C820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A1C512993BFADCULL,
		0xEA17436272B67CF9ULL,
		0xCF2BC5EBB0B4C00FULL,
		0x8FA0343D8D86DD4CULL,
		0x06AB2D13F0B2301EULL,
		0x7E2BE80CFCD1BD07ULL,
		0xACFAC2A7B92ADAB9ULL,
		0x4C843A07D41C9EEBULL
	}};
	t = -1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE4234748467ADA0ULL,
		0x0B7B8247A943280BULL,
		0x93041236C22D593AULL,
		0x1DBA50F1F474BC0EULL,
		0x19DEF1EA1BFDCC53ULL,
		0x54A03AE279E379C3ULL,
		0x70124C21C702DE78ULL,
		0x1383C1E1F2131405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451A5F9EBB854B65ULL,
		0xE64442F95B0C420AULL,
		0xF97B01064C97F886ULL,
		0x74B828D4861FFD05ULL,
		0x0796F2945D2880B6ULL,
		0x9E91912CC53CEED0ULL,
		0x5A213DC4883E32C3ULL,
		0x8EF6B73EAA13E1FDULL
	}};
	t = -1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB4C8C0AD12A8403ULL,
		0x5E71F328AD4A1225ULL,
		0x0A7B9834D74EAA4CULL,
		0xB8AC5628B3E73ECFULL,
		0x4D893FE8229CC317ULL,
		0xFCC8D492BFC1DDF2ULL,
		0x025DF64715B87DD3ULL,
		0x733A1F50DD172BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4C8C0AD12A8403ULL,
		0x5E71F328AD4A1225ULL,
		0x0A7B9834D74EAA4CULL,
		0xB8AC5628B3E73ECFULL,
		0x4D893FE8229CC317ULL,
		0xFCC8D492BFC1DDF2ULL,
		0x025DF64715B87DD3ULL,
		0x733A1F50DD172BC1ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7085CF315FC9070ULL,
		0xC968A435A973A187ULL,
		0x431C57988482C7FFULL,
		0x67B0BB8C366BCA2BULL,
		0x698F7BDAADDBE27CULL,
		0xE8F99F067E7D6340ULL,
		0x07237B29491A034CULL,
		0x7C703FB7C76D52F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE09956EF03B5C717ULL,
		0x584392132C8BD241ULL,
		0x1BD5F84E5CF730CAULL,
		0xEC01C514634F78B7ULL,
		0x8C80DDC7F9C51773ULL,
		0xD60C609C3BA84DBFULL,
		0xBD72488BBC17E9A9ULL,
		0x000B072946A74413ULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFADAE49EAB37F10ULL,
		0x74C30070DB1534B6ULL,
		0x8F796D3962B4DF83ULL,
		0x65720243DA2F816EULL,
		0x75B3F9E18D4BC147ULL,
		0x67F11355BCC9AE05ULL,
		0xB95EE024930CBC64ULL,
		0xF7AB3ED22D26DCFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F620C331EAC9B0ULL,
		0x1883C804E6681B0EULL,
		0x198E0345FEC790C1ULL,
		0x35503CDD5D5EB664ULL,
		0x1DD35BED41B1623CULL,
		0xE18AB234293ECDF0ULL,
		0xAFF0EDEBFFF86918ULL,
		0xF39BB8BAC271B05AULL
	}};
	t = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DFB97DD7FB29D46ULL,
		0xCA243BCD31A91B78ULL,
		0x6C470F893A6B1A83ULL,
		0x660E1F2D0E169B61ULL,
		0x49D37750048FC76BULL,
		0xF8E7AA2AC946CE64ULL,
		0xB8208B80093AD9AAULL,
		0xE33F9048C20AE94BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B1221109F6DB10ULL,
		0x0ECD59A65F6A1053ULL,
		0xD31B321DD4CE65A4ULL,
		0x3076AF88B8444B82ULL,
		0x7C21DDCAFB0A30B4ULL,
		0xC78FFE3AC30F3628ULL,
		0xA43E7CF16EF02C70ULL,
		0xCD187FCAE7ED0F00ULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4778E64BF87D1366ULL,
		0x1A3D56CEE1B5159CULL,
		0x62D2D14895E94C38ULL,
		0x5457E4048777AEE1ULL,
		0x940AD233811D30B9ULL,
		0xBF9F5D959C8E67C4ULL,
		0xAD634D8D0CF49A36ULL,
		0xE25BF551CBAA215AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4778E64BF87D1366ULL,
		0x1A3D56CEE1B5159CULL,
		0x62D2D14895E94C38ULL,
		0x5457E4048777AEE1ULL,
		0x940AD233811D30B9ULL,
		0xBF9F5D959C8E67C4ULL,
		0xAD634D8D0CF49A36ULL,
		0xE25BF551CBAA215AULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4EFCEBB713AB16DULL,
		0x05806A2C4A902C2FULL,
		0x73CED5EB62A0CA69ULL,
		0x2C10AD48617FEB6AULL,
		0x5F493C308FF7312AULL,
		0x83451013953A50F7ULL,
		0xD916143A3D520AD7ULL,
		0xEBF819CF8AA5016AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9428929FEB000DULL,
		0x874316CF43BF2284ULL,
		0x944AC09850398893ULL,
		0x34297CDB8842F27EULL,
		0x51B4E446C00B26FDULL,
		0x8825C519BB1F9164ULL,
		0xEA3C90660D908664ULL,
		0x5CA222C5A7A1EA5BULL
	}};
	t = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9326B7C08CB0E497ULL,
		0xF04F5693A4E67857ULL,
		0x3F4623EE34051AA5ULL,
		0x288CB48BA75DC703ULL,
		0x9F921FBFF62BA50EULL,
		0x09C65BA0E1280003ULL,
		0x6E7ABB05F8F5C525ULL,
		0xE5C3223463938D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45674D96DC30A02ULL,
		0xC6E97AC5B39E8676ULL,
		0x0915E4DABC4F0B6CULL,
		0x6A97A1E007E98DC5ULL,
		0x9D0C0FD9D11BF33BULL,
		0x5218399CA476A2BBULL,
		0xE8E323B174CBE67CULL,
		0x10AD2B2C87FCE72EULL
	}};
	t = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2FE0DBFDECA7C8AULL,
		0x59B52AB7FB36D626ULL,
		0xD7905CF38C8B9ABBULL,
		0x7423A07E6DB029A8ULL,
		0xDE85F567025AD2C2ULL,
		0x17C43CFBF0E5AD56ULL,
		0x841C10470D457465ULL,
		0xCDC59C366CED79B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD0488C6B1620E6ULL,
		0xD35D90708F67A5E7ULL,
		0x0EBD367E0767EDA5ULL,
		0x994429DA84C5DB43ULL,
		0xE0D9D8A74901D297ULL,
		0x55CF7C4F726874B1ULL,
		0x31051A34F0043087ULL,
		0xDCC5B8CD4A20E329ULL
	}};
	t = -1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3165BCD1A5CB841EULL,
		0x2B6A6153CB248584ULL,
		0x8C5FE7CED50DD6BBULL,
		0x398E531BD1C5DC30ULL,
		0x26F672E8DBEEBAEFULL,
		0x455F51BA285BFE29ULL,
		0xEFD790BFFEFEC0F7ULL,
		0x0311E373520C1B36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3165BCD1A5CB841EULL,
		0x2B6A6153CB248584ULL,
		0x8C5FE7CED50DD6BBULL,
		0x398E531BD1C5DC30ULL,
		0x26F672E8DBEEBAEFULL,
		0x455F51BA285BFE29ULL,
		0xEFD790BFFEFEC0F7ULL,
		0x0311E373520C1B36ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D15EF7825C6CA27ULL,
		0x62D99317B93C991CULL,
		0xC58CA5DF94AE686CULL,
		0xBB0ACF9651D1CEB9ULL,
		0x376224966DDB383EULL,
		0x3C8329BC3EDA7146ULL,
		0xE21E21709DB48BDFULL,
		0x8D3A19B8AD9C097EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3C43F83F7FB7CEULL,
		0xFFF0F1B90B41AE84ULL,
		0x11C6A14DBCFD9ED3ULL,
		0x892E62A751B00A7DULL,
		0x423674D1A34A3028ULL,
		0x213359EDE968C028ULL,
		0xC51C25669F22B7A8ULL,
		0x4D4848E78708E41CULL
	}};
	t = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6018801973D2FA69ULL,
		0xF3033157A0ECED3CULL,
		0xF5C9781A91A88E58ULL,
		0x6F8B394C7E535885ULL,
		0xD47A41BC32FEDD2EULL,
		0xFEBFEFD4222EB518ULL,
		0xCD167BAE3A93BA40ULL,
		0xD37E827E9B17F08DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB07F40571808941ULL,
		0x615A52C49F4AF687ULL,
		0x755B061E0F19CE9AULL,
		0xF3FA029B97DD1044ULL,
		0x033514FC4C3BACC4ULL,
		0x2153E09C6A3914DFULL,
		0x0672944FAB26502FULL,
		0xF2934A5A1F74B7E6ULL
	}};
	t = -1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6EFD09EA7A4E695ULL,
		0x5ED83D9646867D8EULL,
		0x82A6342ACFD2DFADULL,
		0x526A0B49DA0E1615ULL,
		0x23E0048FB8FB06E9ULL,
		0x654DF32DEECCC7C2ULL,
		0xE8E8F21AA94C2A9DULL,
		0x6425C31F0E691FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3936FC1EADBF9D1FULL,
		0x59AC75EF1944CE50ULL,
		0xEE76D7E6E4147C8EULL,
		0xDAE497F7BB92F610ULL,
		0xF8FA0C639F7380EBULL,
		0x4332F4972EC6D9BFULL,
		0xA16473C685D3149CULL,
		0x113D6DA684E8D7AEULL
	}};
	t = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1316EAA6543DB041ULL,
		0xCA02DAFCAB1F5CF9ULL,
		0x62A10A054BD0F8A7ULL,
		0x291564627D5D9680ULL,
		0x52E9E8B44E4C96AEULL,
		0x5595684D6B64D619ULL,
		0x9AAA46679C36C506ULL,
		0xC3CC7D3F0260D980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1316EAA6543DB041ULL,
		0xCA02DAFCAB1F5CF9ULL,
		0x62A10A054BD0F8A7ULL,
		0x291564627D5D9680ULL,
		0x52E9E8B44E4C96AEULL,
		0x5595684D6B64D619ULL,
		0x9AAA46679C36C506ULL,
		0xC3CC7D3F0260D980ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB98A953D3EB9C2B5ULL,
		0xCE021E2C5A33A36FULL,
		0xDDCD350C8E527EA6ULL,
		0x4AA438A1985ADDA3ULL,
		0x69CD43AFF6AA1373ULL,
		0x45274D3E9F85DF8BULL,
		0x0729AFBAA09A21F1ULL,
		0x15EEDFA31C5877ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAC9ED33978EC15ULL,
		0x55DDE4ADFA835D31ULL,
		0x6B37F4B8C6F85740ULL,
		0x6D164C5AFE7EB630ULL,
		0x3123AFFAB0B6D2B2ULL,
		0x64FCDEB5C60B3186ULL,
		0x52D1CF74A3615FA9ULL,
		0xD81CC2242BFA10B9ULL
	}};
	t = -1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99C82A35EE946828ULL,
		0x16ED67590AD09B6AULL,
		0x66A4AA57D0A6E293ULL,
		0xAD8640FC4A15A6A2ULL,
		0xE0CF7049E058DC44ULL,
		0x4A3F01C73E98DD25ULL,
		0xA5391C878A98843CULL,
		0x5E7AD658C173DE74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8913633A98AF4BE8ULL,
		0x8042CB82DC73E036ULL,
		0x821B649C79A1BFECULL,
		0x791390DAA67E2AD8ULL,
		0xB782E98442BD7E04ULL,
		0xE1AF70ADFCC5709CULL,
		0x659FA0EFEA8A9BC6ULL,
		0xB56F7076AE28D79AULL
	}};
	t = -1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F3C63219D75073AULL,
		0x13174CDAAD9D8690ULL,
		0xE3C4EF69575948C2ULL,
		0x526C7F82B3A60CE3ULL,
		0x5236D88DE2A28764ULL,
		0x455EFA41122C226DULL,
		0x6CF01C90F80188AAULL,
		0x73D0CB32FDB77802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x057F39B030BD7EB1ULL,
		0x1EEEF9410F3886E9ULL,
		0xB05965034C6F4645ULL,
		0x4EF65BAA85707954ULL,
		0x2C3930616A237819ULL,
		0xECA7648F7D9193A5ULL,
		0x6D4E4E87EE08B9DEULL,
		0xFE9FF8572DCE07C9ULL
	}};
	t = -1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x306F037287BBB664ULL,
		0x65047BEECB04D8A9ULL,
		0xCE779157EAD7CB4DULL,
		0xD7DEAAC84480A111ULL,
		0x72EFDD8A9EFEF613ULL,
		0x0800786FD4571823ULL,
		0x0DAB6E73FC79F33EULL,
		0xF87CD01289ACDBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x306F037287BBB664ULL,
		0x65047BEECB04D8A9ULL,
		0xCE779157EAD7CB4DULL,
		0xD7DEAAC84480A111ULL,
		0x72EFDD8A9EFEF613ULL,
		0x0800786FD4571823ULL,
		0x0DAB6E73FC79F33EULL,
		0xF87CD01289ACDBCDULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3BED4B4DD3BA956ULL,
		0xE57EC53C0E671A0FULL,
		0xE1273DD723C93E74ULL,
		0x284D16527C1AF108ULL,
		0xC604B3C7814BC8C5ULL,
		0x751301690461A335ULL,
		0x452CE5ADCC996450ULL,
		0x475E0266AD776C96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6AA24C2E4EEE0FULL,
		0x85563B0FEA011BE4ULL,
		0x9386EB930FC5F403ULL,
		0x4B738B6B65BBEC1BULL,
		0xE12D2A53B08886AAULL,
		0x9746692F4B0497C4ULL,
		0x22F349F33244F5D4ULL,
		0xE47D8930CD3741AAULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1BAA97F327180FBULL,
		0xDB1B5262DDF471F9ULL,
		0x9DEE1D02A145C76DULL,
		0x0CDA30BFA5255DC3ULL,
		0xB41AE049A1CA73A4ULL,
		0xA4BA6740BF297F13ULL,
		0x75D1CDF3C90B0EB9ULL,
		0xAEF9E16C53D376D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51498F5A5709B8EULL,
		0xD808ADA39E8BECF1ULL,
		0x1402E948A7D9DD1EULL,
		0x427E4C0BB08C21A8ULL,
		0x0408F3A2A6932E18ULL,
		0x5474A9F644C6D71AULL,
		0xB4FABE792AE5ECFFULL,
		0xCBA7018A04C4B2E3ULL
	}};
	t = -1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE15EF4E78F476B22ULL,
		0x1EA8D083C30D3C9EULL,
		0x907807D16F84A174ULL,
		0x2D6EBF70C69C5062ULL,
		0x7CCAB8BBDC3D64E1ULL,
		0x95ED7612050DFF0EULL,
		0xF644EF44218FB987ULL,
		0xFF7461ED0743C9D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0758CD54587ACB71ULL,
		0x3869B3DF577DE675ULL,
		0x67F1BE0D24521094ULL,
		0x238B16FE7E78EFB0ULL,
		0xC94650730E5DAA8BULL,
		0xBBDF3B57205F5909ULL,
		0x6AAC82C6C3BC0710ULL,
		0xCF846CC70D1597D2ULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE62FD81D7C3638ECULL,
		0xB8E4AADD6A23B2A7ULL,
		0xA9B5332DDFF80520ULL,
		0x32E7CE42A42591E3ULL,
		0x5637378DB5443FB8ULL,
		0x35FBBBE458D10AFEULL,
		0x737B3184899FF1ACULL,
		0x3460305DEF33319AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62FD81D7C3638ECULL,
		0xB8E4AADD6A23B2A7ULL,
		0xA9B5332DDFF80520ULL,
		0x32E7CE42A42591E3ULL,
		0x5637378DB5443FB8ULL,
		0x35FBBBE458D10AFEULL,
		0x737B3184899FF1ACULL,
		0x3460305DEF33319AULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8655AFA31E30AE21ULL,
		0xDB957E1AA4CD3FD1ULL,
		0x4471F4B9CF74CC07ULL,
		0x900626BA87456C70ULL,
		0xD15301D0DB2836CEULL,
		0xC24DCBDE8E5AD20DULL,
		0x41B0D1FBF21CC79FULL,
		0x60FBA433D5751809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B32A0543D204599ULL,
		0x1F8440351F991880ULL,
		0xC6ED642357D4EA38ULL,
		0x37A9782438B358B8ULL,
		0x4A67BC85715BAB4AULL,
		0xE3EFC68ACCC930B8ULL,
		0xC98A5AD61F544D01ULL,
		0x8DB7906CFDFEBA25ULL
	}};
	t = -1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9129EC104BA3A8FFULL,
		0x56B8BE71D4025376ULL,
		0x78C68F9FC2320371ULL,
		0x679DE9DBD808F3D0ULL,
		0x45E41F6CFD9B42F2ULL,
		0x0737ACF291D1CA8FULL,
		0x7F4DC8D6C7ABBB21ULL,
		0x6E9F119175362175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x472799AF1A5A14E2ULL,
		0xFE1CE355C45E663AULL,
		0x94A0D57D73E88A59ULL,
		0x5498B35CC3873185ULL,
		0xD1EBEA61C0B657E3ULL,
		0x0535772E2779AF00ULL,
		0xCE99568A73AEC009ULL,
		0x79C75C92FD6C6037ULL
	}};
	t = -1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B448CA6D301D04AULL,
		0x4131A43505699BA9ULL,
		0x24C43E457FD3906EULL,
		0xA338F5FB99D6B35CULL,
		0x3BF624A8CBE2A594ULL,
		0x04686B8B551BDE0CULL,
		0xD027555916D0158CULL,
		0x090ACCDA79D27F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2F3FAE5F533060ULL,
		0x54334F2548B62314ULL,
		0xAC6FCF2A814876EDULL,
		0x35DB96393E08FA89ULL,
		0x4FCFBAD232346058ULL,
		0x99A85EB1F9F64588ULL,
		0x18B1E8787A63C6FCULL,
		0x8DC6D0E414668FD6ULL
	}};
	t = -1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68CA9735E146863EULL,
		0xD50EA9FF4B12B09AULL,
		0xB31B9978563395D6ULL,
		0x3F4CB1C3D67F6DE3ULL,
		0x029A834FA3C7DFBBULL,
		0x345E30D7C9A9033CULL,
		0xFF3E7BEB33E4E757ULL,
		0xE1C3DA475CA6260FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CA9735E146863EULL,
		0xD50EA9FF4B12B09AULL,
		0xB31B9978563395D6ULL,
		0x3F4CB1C3D67F6DE3ULL,
		0x029A834FA3C7DFBBULL,
		0x345E30D7C9A9033CULL,
		0xFF3E7BEB33E4E757ULL,
		0xE1C3DA475CA6260FULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54A71372015C1F23ULL,
		0xB6FDBF9F9E0169E0ULL,
		0x2EBBE9D4C057B741ULL,
		0x1CA57EAAE333B0C0ULL,
		0xF8F708EF17CBBA17ULL,
		0x4722489EB3F4A8FCULL,
		0x48ADEFEBAE917E96ULL,
		0x6A0709673F420208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97EEE3A1A0650413ULL,
		0x30DC897EF6EBB761ULL,
		0xE3BDE49F79FF5959ULL,
		0x09571BFF1354E820ULL,
		0xC40A10ED1F1DC362ULL,
		0xF7DF83C7FE2B1BB6ULL,
		0xCDCB6B70846E527FULL,
		0x185FE121591E760EULL
	}};
	t = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF1A1855E670FB3DULL,
		0x47BDF6E378032055ULL,
		0xEC1109CFAF8911DDULL,
		0x463BE0AC8D50589FULL,
		0x0CE39BE7878032E2ULL,
		0x86A3DE61D2BB07C1ULL,
		0xA1707470AE114089ULL,
		0x687CC267B7E088D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79D401AA3B9A6BBULL,
		0x5E2E872146D8E56BULL,
		0x4D0B1DC357DF883EULL,
		0x115DB4B45B00FD77ULL,
		0xBE736EC5BB6D8C80ULL,
		0xDD7DBD90D32376D1ULL,
		0x8C40E2C9EE481110ULL,
		0xBAED2C9553D1727EULL
	}};
	t = -1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4DCB67681E0F7C9ULL,
		0x320ECE5CD5F46481ULL,
		0x34E57E16EBFF997DULL,
		0xEA2744E1DF11B7D5ULL,
		0x85FFD98EFC75FA6DULL,
		0x4D0A803B3C62A26CULL,
		0x3E55DD941A55B2DBULL,
		0xD36242B9333CA9F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E328839E54BCD7FULL,
		0x1E2819CD7B6356FDULL,
		0x6F20F9356AD2CF45ULL,
		0x8DE01DA46327ED7BULL,
		0x741C164567BBE53DULL,
		0x82E269AD78AD9FCAULL,
		0x4202D909336196F6ULL,
		0x2FD157895B78A678ULL
	}};
	t = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD400E274961D3D4EULL,
		0x89BC3FDDF09D0DBAULL,
		0xA96AC91A13763052ULL,
		0x6C26F029B2BC4ED1ULL,
		0x08EF829E699F0AD8ULL,
		0xE3DFF5320CC215F9ULL,
		0x6C8CF8AC3D10252AULL,
		0xE4C25EE5B08DF2A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD400E274961D3D4EULL,
		0x89BC3FDDF09D0DBAULL,
		0xA96AC91A13763052ULL,
		0x6C26F029B2BC4ED1ULL,
		0x08EF829E699F0AD8ULL,
		0xE3DFF5320CC215F9ULL,
		0x6C8CF8AC3D10252AULL,
		0xE4C25EE5B08DF2A9ULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B715CAC805B19F9ULL,
		0xB7CC361281F31056ULL,
		0x39C4434F9BF02471ULL,
		0x25FEDF36A0194FE6ULL,
		0xEDCA9F190F48B552ULL,
		0xBEAA020ED3B42441ULL,
		0xC18F1CBE5AE5EFB5ULL,
		0x5F403E5CD4A4F88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02293FF1C93E8C85ULL,
		0xA377B679DE662BEDULL,
		0x59F386992E44AC0AULL,
		0xE7945687AAB79BE1ULL,
		0x92C1EA94E47DDB9BULL,
		0x37F15C0989B485A3ULL,
		0xB04271EAC6050666ULL,
		0x15C12E0B199DF65DULL
	}};
	t = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x586C549D7F91AEAAULL,
		0x922DA6E622139EE7ULL,
		0x9974BFFEDD63708BULL,
		0x69143ABAD1C07332ULL,
		0xE5DC1F36D8D57250ULL,
		0x1A9A95399984EA79ULL,
		0x84DD9EA02E9CEA92ULL,
		0x02AAFF65C45B0831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x455A6FEEF16C1590ULL,
		0x4483A1B1BF64FC51ULL,
		0x06D3D00F89940081ULL,
		0xDCDAE02292E825BAULL,
		0xF7DF5FCDDE5F3D14ULL,
		0xA8EB7708840A52F2ULL,
		0x9E4A32403E89CA93ULL,
		0x691005188152654DULL
	}};
	t = -1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA671325A2B517C20ULL,
		0xBCEFCBE4B4AE5B35ULL,
		0x00BBF270FB854702ULL,
		0xE78BB7551719AB91ULL,
		0x49F4CF18579BAA80ULL,
		0x4A40376B094FC7C7ULL,
		0x3E2FE8399E699828ULL,
		0xCC72E1C1D9E71E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71DBD536DF5F24FEULL,
		0xB25BDC37EEFBA7A1ULL,
		0xDF387D7E7BD9279EULL,
		0xBFB2A19574C82CE7ULL,
		0x239B48076D758B6FULL,
		0x0797D23AC3D4A008ULL,
		0x774F23F3A3117D1AULL,
		0x3F9B676F503749D8ULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA29BA74F3697D80AULL,
		0x44925F3777B571DDULL,
		0x83519A9563556270ULL,
		0x6C938A67661B5C82ULL,
		0x777BC0D792EBF46DULL,
		0xCC2873CDB10BA613ULL,
		0x57E4D0113E273017ULL,
		0xDFB2056D9C311519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA29BA74F3697D80AULL,
		0x44925F3777B571DDULL,
		0x83519A9563556270ULL,
		0x6C938A67661B5C82ULL,
		0x777BC0D792EBF46DULL,
		0xCC2873CDB10BA613ULL,
		0x57E4D0113E273017ULL,
		0xDFB2056D9C311519ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AEB877B1D1EAEF0ULL,
		0x5669D9C440FD7B64ULL,
		0xA2FF1BFD9E2EDA62ULL,
		0xC09AA5DF7B6C62D1ULL,
		0x6CD4E1FCF6CB6769ULL,
		0xB434F9F7C20DC2E4ULL,
		0xA002F2C5201ED871ULL,
		0xFB6A3D51CF5A4B87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2448401E0850BC92ULL,
		0x77B1012DF26A6D13ULL,
		0x503CC648780D9EC8ULL,
		0x5918386F99CD131EULL,
		0x841CA331F2BA8A92ULL,
		0x1DE207A71CC26E77ULL,
		0xFD20824559CF9D8EULL,
		0x7A7A07740C89988EULL
	}};
	t = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2873877B51C11A1ULL,
		0xFBBE8DD5FB9DF8C9ULL,
		0x39122FDB740534CDULL,
		0x3D44C60FD8581606ULL,
		0x96404B1731950478ULL,
		0x2D99C7A4941BCE8DULL,
		0x8EDF21820EAA479FULL,
		0x87BE3C520EA9824CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2AD0010EA0D45EULL,
		0x29F815D9092EF5E5ULL,
		0x2A78523E6FD4978CULL,
		0x2D10F053208792E3ULL,
		0x45D71B7D2C165AB1ULL,
		0x7C7CC55087B02F3BULL,
		0x46209F57215D69C3ULL,
		0x5FC5C45905435226ULL
	}};
	t = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06024F3C435E5CE9ULL,
		0x53A4EB914BFFD836ULL,
		0x5BC57234D1B3D516ULL,
		0x59D40E2EB30E0959ULL,
		0x1D0EEB20C2D5D309ULL,
		0x733B30E6249C73A4ULL,
		0xFF09AE92D387F175ULL,
		0x0BA14D9D6FB97EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF033BC404DE65CEAULL,
		0x361D58A4270E814CULL,
		0xD95E72735010AEDBULL,
		0x4BA44ED4F011BEA1ULL,
		0x3A0BC96782510B53ULL,
		0x2330362D8A9C52D3ULL,
		0x1A169840ACB2F757ULL,
		0x718A48005D1119EDULL
	}};
	t = -1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DF7D2DA03BE66DFULL,
		0x54AB1123D5828F54ULL,
		0xC4078EBB3AD003C9ULL,
		0x373E5BDFD1D4C1F8ULL,
		0x37BE44F53390CCA2ULL,
		0xBE643B265D86DF55ULL,
		0x1D6086FA49894AFCULL,
		0xADA70B408F6DE2FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DF7D2DA03BE66DFULL,
		0x54AB1123D5828F54ULL,
		0xC4078EBB3AD003C9ULL,
		0x373E5BDFD1D4C1F8ULL,
		0x37BE44F53390CCA2ULL,
		0xBE643B265D86DF55ULL,
		0x1D6086FA49894AFCULL,
		0xADA70B408F6DE2FFULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E9C2A2F35AA357BULL,
		0x0B3734FACAA4007FULL,
		0x1AF4C26D57C6B907ULL,
		0xDF3D055850531762ULL,
		0xABE49B30EBE62E56ULL,
		0x19439A9E81C7CE38ULL,
		0xBEEE43105D64E07FULL,
		0x5248DF1DF2D55EFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF881487642B5D1CULL,
		0xCCF1A06999119790ULL,
		0x9D01BB4464AC93A6ULL,
		0x5809B9C451D9282AULL,
		0x0648BCBEE63DFF53ULL,
		0x50A3495FE8CB06D8ULL,
		0xDDED29D0E5F9678EULL,
		0x6C6DB3C3D8466F83ULL
	}};
	t = -1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7F1E98CC4D61C3FULL,
		0x6BBDAE6F8C81ECA5ULL,
		0xA11DCD15025DA83CULL,
		0x67E65B8D35E837A6ULL,
		0x7792F866B2205ACFULL,
		0x790F96CF48FBDA3CULL,
		0x2E79E3632F70EEDAULL,
		0x81342746B4DC3CF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x757E8657E2994005ULL,
		0x4E058DEB0E9907E6ULL,
		0xAA84D71C64194528ULL,
		0x45312D1ABA14ACF1ULL,
		0x2765F66A3442816DULL,
		0xF4BCD9A6DB44695CULL,
		0x3F408E24FB33D74EULL,
		0x9B50B1347E3BEF49ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C1FDF09D3E8AE7ULL,
		0x2F53B98806ACE680ULL,
		0x2430F392B89FF36FULL,
		0x0ED71476F090E8B7ULL,
		0x305138A15D0424D2ULL,
		0x1E0F5C41EB1B709CULL,
		0x66258C5C0A717CCFULL,
		0x412F9E4652A99C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5118669AF5A16CULL,
		0xF924FEC7C46195A4ULL,
		0x4AB0CA23D1E53081ULL,
		0x183C8A77CD60BAF7ULL,
		0x1E3662C834DE2188ULL,
		0xCE81052D06A80167ULL,
		0x115A51B670B122B1ULL,
		0x739C68C9A48909E4ULL
	}};
	t = -1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1644CE3133471C8FULL,
		0xE43B59AC2148672FULL,
		0x83F29FE5C2F6176AULL,
		0x1798842FAB563B89ULL,
		0x1FA3DBC1D22C1D0EULL,
		0x8E1D797EE7824E66ULL,
		0x4477BBF00691A699ULL,
		0xF6F652210FBB293EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1644CE3133471C8FULL,
		0xE43B59AC2148672FULL,
		0x83F29FE5C2F6176AULL,
		0x1798842FAB563B89ULL,
		0x1FA3DBC1D22C1D0EULL,
		0x8E1D797EE7824E66ULL,
		0x4477BBF00691A699ULL,
		0xF6F652210FBB293EULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12919C729DBA2866ULL,
		0x6DED093B24029349ULL,
		0xD9F6AB50B7DDF3EDULL,
		0x0992606FFB9C93F3ULL,
		0x9944E7040386F370ULL,
		0x9A8FEB9D768AC2CDULL,
		0x689F32C8F9224995ULL,
		0xA284945F7E6DBFD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF47D924260AA3FFBULL,
		0x9814B54D623AD055ULL,
		0x77F12972B598F77AULL,
		0xFAB6691E060BEB3BULL,
		0xB8395F71A40A86A1ULL,
		0xAF9E7ABF43745095ULL,
		0x4C32DA8EDF58B71CULL,
		0x4A6AB27D73639B45ULL
	}};
	t = 1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81ED31DB11CF8256ULL,
		0xC675EB7B6E8592E0ULL,
		0x81B5331662E8CE25ULL,
		0xEB9E4CB3BE849F64ULL,
		0x25E7CA0CCB494893ULL,
		0x31C8B93F749953C5ULL,
		0x71311079C3532721ULL,
		0x49D0D06C6EBF5B7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x604BACBA724B2870ULL,
		0x6E4E2204569A69E6ULL,
		0x1B5DAC8C2BCB194DULL,
		0xF6D74095D2A66250ULL,
		0xDEF9D577ECA58A2EULL,
		0xA4A2D3BA54A6781CULL,
		0xD1BC0D6CE58C1A2EULL,
		0xAFA6094867336461ULL
	}};
	t = -1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D49A46EB5121EF3ULL,
		0x18F03CD8CF11E2F2ULL,
		0x84CAB17CE13180E3ULL,
		0x6D284ABC1B3DD2F2ULL,
		0x190F8A0EB6D2D516ULL,
		0xD7950131D63BCB31ULL,
		0xF645BB88970DAE5BULL,
		0x4018440575AFAC38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFECCC8B4123D35CULL,
		0x0B68C59CE9054C54ULL,
		0xA511FEACBAF583D7ULL,
		0xE7A6639AC36D93CAULL,
		0x5BF216C47BCC87D7ULL,
		0x8CE1A7E528ABC57EULL,
		0x391B52752A573298ULL,
		0x164EEEB340C78C94ULL
	}};
	t = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C500F2560FE1630ULL,
		0x013207B92081D7F6ULL,
		0xD6BC9434BF29F912ULL,
		0x48C21E0F164EBF8EULL,
		0x59134858A48E1ACEULL,
		0xC329100F38D00D90ULL,
		0xE743A29FC61C024BULL,
		0x2C81C35566C661FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C500F2560FE1630ULL,
		0x013207B92081D7F6ULL,
		0xD6BC9434BF29F912ULL,
		0x48C21E0F164EBF8EULL,
		0x59134858A48E1ACEULL,
		0xC329100F38D00D90ULL,
		0xE743A29FC61C024BULL,
		0x2C81C35566C661FCULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF5A2C2A0799451ULL,
		0xE7672B89CE33A9B0ULL,
		0x553CB1F0248EFA22ULL,
		0x88C26189707B9982ULL,
		0x0178A59CF6F191D9ULL,
		0x2D11C8F884AFB047ULL,
		0x086B1F3590A56D2AULL,
		0x74CF446C644AFACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4942A9F98B189532ULL,
		0xBD0AE73E58D3A3B9ULL,
		0x7A4B77F7501E06AAULL,
		0xC191254B57E83B81ULL,
		0xCA0785CBA4320D1EULL,
		0x5B414E6B1E654122ULL,
		0x4543818137C6D554ULL,
		0x27D0121CCDB4A7D8ULL
	}};
	t = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34D547953CBB6B64ULL,
		0x1F5334D81C00257CULL,
		0xFCEC35420A799C57ULL,
		0x755525F0DA2A912EULL,
		0x3412899254853B53ULL,
		0x5BC5C5EAAB2AE9AEULL,
		0xDB9BEF79F7FAE8AEULL,
		0x460A9D00EDA73D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC27EED5254E66245ULL,
		0x84D217A490FDDE9DULL,
		0x974AB06F0B6AE5BFULL,
		0xFC7C5016A3329A3FULL,
		0x66FE9BAA9CD11F83ULL,
		0x51022611699276A9ULL,
		0xCB95D9BDC23C9C8AULL,
		0x89B5CFA627B03C11ULL
	}};
	t = -1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE42441D4F2C665CBULL,
		0x02CB66A9F5DB77BBULL,
		0xE81130E7115EA7ABULL,
		0xC43092C48DCF590CULL,
		0xE807461BED66349FULL,
		0x89B744B82A5AA781ULL,
		0xB25E3770D8EDD050ULL,
		0x0AA940083DACAAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7081C6512B571BECULL,
		0xAB9E4D99A7BC8DCAULL,
		0x6F97C39DD2E5AC3CULL,
		0x6337D7D08D372987ULL,
		0x05B696537D40A5BFULL,
		0x4B9ABE3A23CFA3A3ULL,
		0x0C1302A94B4BE9DFULL,
		0x6E22F5D8230A16CFULL
	}};
	t = -1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C3E3E7EBAC7875ULL,
		0xD6ECC7251348ED9CULL,
		0x6C81CD42CDC8F730ULL,
		0xFE2C9ED7C24BF8BEULL,
		0x85773FFB50E44A42ULL,
		0xA64B3BB798580E77ULL,
		0xF5AA87F9B3CE0BEBULL,
		0xEA1DD5A85692E473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C3E3E7EBAC7875ULL,
		0xD6ECC7251348ED9CULL,
		0x6C81CD42CDC8F730ULL,
		0xFE2C9ED7C24BF8BEULL,
		0x85773FFB50E44A42ULL,
		0xA64B3BB798580E77ULL,
		0xF5AA87F9B3CE0BEBULL,
		0xEA1DD5A85692E473ULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46DF8510297820A1ULL,
		0xD63E71EEA5DDBA8BULL,
		0x997726BA5B0A0319ULL,
		0xCFD73528397A6EC0ULL,
		0x74905ACF4FE6EE90ULL,
		0x592AAE3874CC4B94ULL,
		0x242BB374FDB77B2CULL,
		0xDFF2A92EB5E9A403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D9741E8A6E2E6DULL,
		0xDC9121A6B668C2BDULL,
		0x2CB5D1050CBBB397ULL,
		0x4CA89BE78AA11680ULL,
		0xF7CDDC4FFAABB791ULL,
		0x7A5167004C57623AULL,
		0xF7C770DEF2D04476ULL,
		0xBA5849FE7FB31E10ULL
	}};
	t = 1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A8156C91520FA5EULL,
		0xD876F8911163FAF1ULL,
		0x8EFA6741A763F7B0ULL,
		0x8CFC1E112EB7CA8AULL,
		0x0303444C0B66FA43ULL,
		0x6125BB7A5C8BA4CDULL,
		0xF11E8434F8D6CC11ULL,
		0x108009C2758DA650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF525B2957099B315ULL,
		0x6204EAED70257AECULL,
		0x23F69C03A84425CEULL,
		0x0C4CFD0391FDFCEBULL,
		0x364F294817571086ULL,
		0xE339C7FA197DC758ULL,
		0x1293464315BE4F47ULL,
		0x7760C40109D22FCEULL
	}};
	t = -1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FD285D7AA44C202ULL,
		0xAF879CFDAB64E4A0ULL,
		0x3469D68E85BBADBDULL,
		0x4F1A59888230B74CULL,
		0x9FC7CAB931713784ULL,
		0x2043DF52F55C53E2ULL,
		0x2504AE9C73E745B4ULL,
		0xD9667C2898289AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA440DCF2305903ULL,
		0xE42845633BEFCEC4ULL,
		0x1E6A17BC0ED1C1A9ULL,
		0xB9477E7E9E5981EFULL,
		0x246C8BA92CA9C663ULL,
		0x3DA11F36108BEDE9ULL,
		0x977A17C678E51723ULL,
		0xBD8EBFB8C08E53D0ULL
	}};
	t = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBEDC1017F014D06ULL,
		0xDD027349978C8F13ULL,
		0x68379105D7629219ULL,
		0x318DA763E4CBE7F2ULL,
		0x9B181D075B33128DULL,
		0xEDC06AD9AF50BD4FULL,
		0xC0D9ABAC2F0215E1ULL,
		0xC62242A7FF8BF315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBEDC1017F014D06ULL,
		0xDD027349978C8F13ULL,
		0x68379105D7629219ULL,
		0x318DA763E4CBE7F2ULL,
		0x9B181D075B33128DULL,
		0xEDC06AD9AF50BD4FULL,
		0xC0D9ABAC2F0215E1ULL,
		0xC62242A7FF8BF315ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FAE3693F17CC908ULL,
		0x5EF5A352B9BD7EEEULL,
		0x66FFD8353F35C8C7ULL,
		0x3E89C775BFC523A9ULL,
		0x4F1F24497D8F5981ULL,
		0x57E5A3358ADEDAF4ULL,
		0x1B7D616D60B9A37EULL,
		0xBB0FDC60F69D4F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0010EC8FA9B29B51ULL,
		0x9FDFB56D13319D53ULL,
		0x1A4A3D71E112B086ULL,
		0xD4BF7304750F1AFCULL,
		0xF97AECE14511B27AULL,
		0x7396FE4121F2B194ULL,
		0xA8082AF5B20C02CCULL,
		0x95BE4A5899ED82FDULL
	}};
	t = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7379EE3D6DEAFD47ULL,
		0x668DEFECBE228450ULL,
		0x3B42B9FCDCA59EEDULL,
		0x9A6F15F4ED2C451BULL,
		0xEBE787641B788939ULL,
		0x00EDDA378DFA0918ULL,
		0xBCB1A349EBCFC10FULL,
		0xBE95E2511255E394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C9511FF5F82CC7ULL,
		0xF6728098EAD28EE3ULL,
		0xB850293576C5B1ABULL,
		0xCB8A36B920B582F7ULL,
		0x6D9CF96575FA8BF7ULL,
		0x8991CA0828B78E6DULL,
		0xD6809D7190162F93ULL,
		0x5B468ED5B34D5AF5ULL
	}};
	t = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59D198B739A3DEE3ULL,
		0x56921415BCFBD676ULL,
		0xEC5FFEC0DA713F99ULL,
		0x7E40B78CD6A2F730ULL,
		0x4F88CC415E9D1BE3ULL,
		0x6A20C9032DD28288ULL,
		0x00DB8FC2A1D5C067ULL,
		0x96E529BB47CF092DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB157E7075222359ULL,
		0x736448CDB444A5B2ULL,
		0x293A08BB2BAC1E68ULL,
		0xCF11BBBC31A85ED0ULL,
		0xA043F1AA16B91171ULL,
		0x9159C8BEEE3647D0ULL,
		0x2519ABFBA686E838ULL,
		0x6D8D0363454F8092ULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B596E0DBA5FE82DULL,
		0x1BC5B4B52B23F788ULL,
		0x1C13E1511BAF36EBULL,
		0x873647AAAC6AA113ULL,
		0x31772A5865D81EB3ULL,
		0x03FF6E9E3045AE72ULL,
		0x4FBA16AC3148D37BULL,
		0x1418DA4F252E54D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B596E0DBA5FE82DULL,
		0x1BC5B4B52B23F788ULL,
		0x1C13E1511BAF36EBULL,
		0x873647AAAC6AA113ULL,
		0x31772A5865D81EB3ULL,
		0x03FF6E9E3045AE72ULL,
		0x4FBA16AC3148D37BULL,
		0x1418DA4F252E54D8ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DB166338B100B19ULL,
		0x4AE27CE16415C287ULL,
		0x6F886E6539B5604FULL,
		0xE6E7E4F6C7295925ULL,
		0xE2BF8A3437FD5E96ULL,
		0x5E23A9231B6AE88FULL,
		0x3ED92159EA97F9BCULL,
		0xA77F8DFEEC92AD32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA841E2E87E4D8491ULL,
		0xB8F55D9B82D1025FULL,
		0x56798E5C54D73CC0ULL,
		0xD982E61566FD02A0ULL,
		0x767221890A68516CULL,
		0x5601E69963580380ULL,
		0xD0EC7854776CD03EULL,
		0x51173FB5FD647661ULL
	}};
	t = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x049EBEBD9D866802ULL,
		0x308C966EA79FF2C2ULL,
		0xBF43BD93DB187232ULL,
		0xB9B20C8872C7F54FULL,
		0x58A9EF6C5D8D7FEEULL,
		0x212AA7D3FB54069FULL,
		0x0E9084B2AC72FBAEULL,
		0x00E267A141FBF4CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x198174806871AEC8ULL,
		0x295A0434A1F57B6BULL,
		0x87FB8F4821FB2F84ULL,
		0x5D378859B6345F8CULL,
		0x099DC0FAB6F87FCBULL,
		0xD240A7799EA2AAE6ULL,
		0xFAA13FBAEE7B2686ULL,
		0xA00C63F89E85D1B9ULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABABB647CD010308ULL,
		0x14D56AFBBFCA2BA7ULL,
		0xDDFDF1D46609B650ULL,
		0x1270AF15F44FBA3BULL,
		0x9D3C49114BA2FDFDULL,
		0xEE548BE0B1D86D93ULL,
		0x5A0D1033934D02D7ULL,
		0xAA91FAAE7382795DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x637A3A5BCE8989E5ULL,
		0xE1E2F9E32E19187BULL,
		0x78646E3C4B684B77ULL,
		0x7EA32C817DA0A2ABULL,
		0x6D1AA8D59DB64E36ULL,
		0x3953AF6708AEA554ULL,
		0xCB96A7160EE0F7B2ULL,
		0x54FB43F916308578ULL
	}};
	t = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E2E14C84B628C81ULL,
		0xB52277F82E66B553ULL,
		0x7C4F404F67CF07E7ULL,
		0x894D9719BC497904ULL,
		0x30A91DE2FDCD117AULL,
		0xDC35FA9D14903D59ULL,
		0x8CBC7A22264983D3ULL,
		0xB2F5455AB183AD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E2E14C84B628C81ULL,
		0xB52277F82E66B553ULL,
		0x7C4F404F67CF07E7ULL,
		0x894D9719BC497904ULL,
		0x30A91DE2FDCD117AULL,
		0xDC35FA9D14903D59ULL,
		0x8CBC7A22264983D3ULL,
		0xB2F5455AB183AD3BULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AB917CC1D9E7037ULL,
		0x1B865D9BF79C4B74ULL,
		0x4D2E94C687F068D8ULL,
		0x4DFD70E3BC22BE5EULL,
		0xFA11A5B96C84BC3BULL,
		0xFB8CC1E1F734720EULL,
		0x695963F76834A3D1ULL,
		0x32911D0A1B8E4015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2570A89B774A68ULL,
		0xA94E802C7B73D292ULL,
		0xE699C4D397D0552DULL,
		0x28F4FE0ED428A624ULL,
		0x6D14FB67C30EAB18ULL,
		0xC461A462E2571728ULL,
		0xECD3FE55141B4C5EULL,
		0x6FCBB29550DA4C1FULL
	}};
	t = -1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF305B18EA93D70CAULL,
		0x333CCD128286E1AEULL,
		0x5B1CD8B33B96B482ULL,
		0xB9CD4B7CC163C779ULL,
		0x0476985FAEACDA11ULL,
		0x74DDA4DCE1D7C9A0ULL,
		0x8C67883A4F0CB021ULL,
		0x81B99C67625BD20DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1632B8492C581E7CULL,
		0x67662716E131C575ULL,
		0xD368AE6E4A0ECAD8ULL,
		0xD398A1FD530AC0E4ULL,
		0xACF55E51EE0ECE10ULL,
		0xEC298E198F79D185ULL,
		0x898A271FCD5D0DA1ULL,
		0xF0AA59399B8A1582ULL
	}};
	t = -1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9657FF572344529DULL,
		0x1E07577D7CDFE05DULL,
		0xE1CD1599CC740124ULL,
		0x54CF375B5F8D8252ULL,
		0x0D400FDA8B5B86B0ULL,
		0x3DCED2DFA9514C4BULL,
		0x48FF0126F0DA6222ULL,
		0x736CA2B5CED87A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FFC1224B10BABDULL,
		0x180EDDBF654F6B4DULL,
		0x13B322F3CFDCAF91ULL,
		0x291358BF6128E7C3ULL,
		0xB881F87FE1465923ULL,
		0x8BE77C918FCC670CULL,
		0x076F26F2473FBCE7ULL,
		0x2C7327BB5F08CE6DULL
	}};
	t = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7B3BEADC4CB234BULL,
		0x6F3D4C4473DFF0B7ULL,
		0x5F7192F99C92B043ULL,
		0x0603124EB7B7E69EULL,
		0x4E039929B49D9484ULL,
		0x72788B29D498BCC4ULL,
		0x20B017157E0B1189ULL,
		0x7C62214EB936D172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B3BEADC4CB234BULL,
		0x6F3D4C4473DFF0B7ULL,
		0x5F7192F99C92B043ULL,
		0x0603124EB7B7E69EULL,
		0x4E039929B49D9484ULL,
		0x72788B29D498BCC4ULL,
		0x20B017157E0B1189ULL,
		0x7C62214EB936D172ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841326F35CCF4EC8ULL,
		0xA72066BDEBBABD69ULL,
		0x20AA2DBB62A7BF88ULL,
		0xC3CD628E8B828EB3ULL,
		0xD716A6EF78A8074CULL,
		0xD6F53822426492E0ULL,
		0x8A8B5DF20C1BF321ULL,
		0xE1F74A6A246F063FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF6DA31BC4FF01CULL,
		0x614773A10E5D69C1ULL,
		0x4EEEAF36C676AF48ULL,
		0x75686450DBD3AD84ULL,
		0x1B184C75F1B02058ULL,
		0x99269FDDD0B12675ULL,
		0x2EFC00FF7810A0DFULL,
		0xDC0299EF669FEC8FULL
	}};
	t = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7626EB09A20D1637ULL,
		0xA81510BFEAD94E05ULL,
		0xB89F6FCB7B1C50BDULL,
		0xA30616887F76F29EULL,
		0xFEAA4AED3F37AD2CULL,
		0xA48FB17404FA5296ULL,
		0x152D0310B55F37ECULL,
		0xC1F06645F14BFF4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13DCD56C17B7FF3AULL,
		0xA4B3BF9566305E4BULL,
		0xD7AE73A0F28F56DEULL,
		0x2FB7F16A0C75362BULL,
		0xEBED613AAB2E352AULL,
		0x71A0BEC6B9C5BB72ULL,
		0xA0788DC59EDEC017ULL,
		0x69D70AA342F8ED15ULL
	}};
	t = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7248327DE8F87EB5ULL,
		0xAC17A50437E93502ULL,
		0x19298D18A15D5E62ULL,
		0xC295B3EF4B49F629ULL,
		0x8B78073D0A32DCF5ULL,
		0xCA1D7CD6A7CD0D5CULL,
		0x1F38852A29D240B0ULL,
		0x21E25D62775586C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802E46E207BBA3A3ULL,
		0x58AC13ADFD83879EULL,
		0x5B1551031768392BULL,
		0xBD6DAC746C6AAD28ULL,
		0xD1359586BBAA3C4AULL,
		0xC70766A837E0410CULL,
		0x57C907A18F0DC797ULL,
		0xA965719E179FA982ULL
	}};
	t = -1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA575DB55B36043A3ULL,
		0x0D1631DD3E91D133ULL,
		0x3E23D60934E01223ULL,
		0xEB1E99A37E9FF6BFULL,
		0x43A0741C77A99BAAULL,
		0x5AC2CA427F187E05ULL,
		0x7C0A5D0AC579C48AULL,
		0xE5449EBBD8D10DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA575DB55B36043A3ULL,
		0x0D1631DD3E91D133ULL,
		0x3E23D60934E01223ULL,
		0xEB1E99A37E9FF6BFULL,
		0x43A0741C77A99BAAULL,
		0x5AC2CA427F187E05ULL,
		0x7C0A5D0AC579C48AULL,
		0xE5449EBBD8D10DEEULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58128537B3B097F0ULL,
		0x36E483202D64DCB6ULL,
		0xCADE61AC4EFAAEACULL,
		0x20351A3775F45CCFULL,
		0x8F8905945AFF4515ULL,
		0xFE31179E47557859ULL,
		0x9924FF2BE6C1BAECULL,
		0x867C6D3FB27E2B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3670301366B0E5B2ULL,
		0xF753DF8AC2961FA3ULL,
		0xBF1C8EE4B02D7B38ULL,
		0xA8E47FE61A5B6F4EULL,
		0x0A8656B06DDFD7CCULL,
		0x6543499874E9E031ULL,
		0x99C16572148C10B6ULL,
		0x1A6F83341F13CCA6ULL
	}};
	t = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4A1B07ACC078492ULL,
		0x18090E6191992143ULL,
		0x1CB9E447C9799F63ULL,
		0x7E0BD3D296170E71ULL,
		0xB45A39E480995E28ULL,
		0xAA81769B26FB4C05ULL,
		0x7FD1D6FF8EF09785ULL,
		0x3FA62174BA60CB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD3CC371DE66DB1ULL,
		0xEE9C943E480A32E2ULL,
		0xE4D8A5816653984AULL,
		0x4DC5B3B25BC72CA3ULL,
		0x45B9D4FDB9E2AEC3ULL,
		0x89A94BB7A95D16C4ULL,
		0xD3CF13729C06F7F0ULL,
		0xD75EEBF8D545A708ULL
	}};
	t = -1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841A357686B2545FULL,
		0xEA5606888C6509CAULL,
		0xB03442827B4A0DF0ULL,
		0x46DDEA013975AC72ULL,
		0x10CBE5911F781C82ULL,
		0x663DD342CEC6808AULL,
		0x16E934EE93D6EC8DULL,
		0xD128BEEF1A56B4FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84C511CCADACA42ULL,
		0x61C982C91433189CULL,
		0xD1693BA65D8F457DULL,
		0xA425583EFE2C0878ULL,
		0x1D3C71B13BF88CA1ULL,
		0xADA45598985D964CULL,
		0xF43021F9E7727682ULL,
		0xB1756FFCE3F999A1ULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D89B846284DE8B6ULL,
		0xD7AD49E1B05B48FFULL,
		0x4EB1EBD6CF415B19ULL,
		0x4BC6C29C8DCB6C60ULL,
		0x64C91BEAEB07A942ULL,
		0x5C5557C09C83B44CULL,
		0x0E2954496DC28E9AULL,
		0xF9EB6036CF717BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D89B846284DE8B6ULL,
		0xD7AD49E1B05B48FFULL,
		0x4EB1EBD6CF415B19ULL,
		0x4BC6C29C8DCB6C60ULL,
		0x64C91BEAEB07A942ULL,
		0x5C5557C09C83B44CULL,
		0x0E2954496DC28E9AULL,
		0xF9EB6036CF717BD9ULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5DF90195839BE82ULL,
		0x4B565880D139776CULL,
		0x22B3B20018E1B589ULL,
		0xB4F9FF5B6C157F23ULL,
		0x718A009C6B68EAE0ULL,
		0xA162AC5EEBD389A6ULL,
		0x4355B0BE30C364CCULL,
		0x480F56E61497C729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CC4C5C4005632B6ULL,
		0x89FE7D4A9C486E85ULL,
		0x3827B7AF894B3416ULL,
		0x127070D21F5D7119ULL,
		0x5F432E55CBD2EF31ULL,
		0xD1D97E20AEF23D3DULL,
		0x9DCF21B0BE8E8B10ULL,
		0x3B99789386E518EDULL
	}};
	t = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x276C9B9B0632C028ULL,
		0xC8F4A43B29450505ULL,
		0x7CE5D62C9C786221ULL,
		0x24B7E155FA995303ULL,
		0x16B233777097E6F6ULL,
		0x30CEB201EEF18089ULL,
		0xCFA5709CC9A982E8ULL,
		0xB6D38FF5351D0E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC99205D4BA927BE1ULL,
		0xE507AB877E0F0601ULL,
		0x2FC92309F54B39D9ULL,
		0x48BA6CB43DA35BE0ULL,
		0xAC8B71A7A5149CDBULL,
		0xA13ECA666B2DB0E1ULL,
		0x2167280B8450EF6CULL,
		0xB80AF11E9C37F6E5ULL
	}};
	t = -1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF7E309C17E8516ULL,
		0x84A910E4AB5D8B53ULL,
		0x64E1FC84D46C8D5DULL,
		0x24B864521AA4DB64ULL,
		0x62294D300E72CD0DULL,
		0x4426C192B86ABAB7ULL,
		0xF9F1B05B920A90F3ULL,
		0x0E9F3E37BB2B525CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA88B2EC2BCC905ULL,
		0xD186E12E888BC165ULL,
		0xC68122C338EB2E6BULL,
		0x02CB58F1D5D7A9D1ULL,
		0xE2EFCE2FB66FDE75ULL,
		0x3F60078CE6D90901ULL,
		0x2C0279B480C54CFBULL,
		0x0E9239AD5F290035ULL
	}};
	t = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA63EA3D817B315E1ULL,
		0x5EAF816DDF14AD40ULL,
		0x5BEE4103EDC57DFDULL,
		0x41DB96B15154BC25ULL,
		0xE8D6C4CE9087588FULL,
		0x90AFB815A1A07F6BULL,
		0x864D9213D589EFC4ULL,
		0xDBC8AE66AB448049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63EA3D817B315E1ULL,
		0x5EAF816DDF14AD40ULL,
		0x5BEE4103EDC57DFDULL,
		0x41DB96B15154BC25ULL,
		0xE8D6C4CE9087588FULL,
		0x90AFB815A1A07F6BULL,
		0x864D9213D589EFC4ULL,
		0xDBC8AE66AB448049ULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x238C9F7D2F7045EBULL,
		0x86CB5F9BBF747A21ULL,
		0x2B2F32E8DC50C66EULL,
		0xF028C54C90F2AC6CULL,
		0x98F455E2C0883D48ULL,
		0x073C407316B8817BULL,
		0x3D5F22706FF8C5B2ULL,
		0xBEF1C4F476B4A86EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0C76114640E3D6ULL,
		0x44D0B1CFAED3794FULL,
		0x3A31725A29823482ULL,
		0x3D39EEDF5A6B4438ULL,
		0xF5270BBE8368C407ULL,
		0x7D17DB279F4141D6ULL,
		0xD364D693E094FBBDULL,
		0xE823059308FBC926ULL
	}};
	t = -1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A7D8D8461B86BD6ULL,
		0xB5BBB7E09E31E612ULL,
		0xF2E0DA6236AF3649ULL,
		0x2C330C54DEF55463ULL,
		0xE458595730E786B8ULL,
		0xDECBE66278622153ULL,
		0x9DB06B5B8BD7075FULL,
		0xF2567CC9E3D25E4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x592E934AEB2819C1ULL,
		0xCC8868BF50B68DA6ULL,
		0xA4236A45FC756ECEULL,
		0x07F9412AC4F3BE03ULL,
		0xA06EB313303FF415ULL,
		0x13C8C1E6C03A2443ULL,
		0x8829EDCFDD913B8BULL,
		0x814D83EE2F949D91ULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DD85697B1B3F5D2ULL,
		0x2E85F6738CC791D4ULL,
		0xCEF9018D95D5A260ULL,
		0x562002DF81378BC2ULL,
		0x336EF851F683AD07ULL,
		0x940C37B7996C5A0AULL,
		0xD3187B55BDFE0FD1ULL,
		0x09C8AC1DA6A07874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF584A7CCAA6601ULL,
		0x7078154C3E7F6E89ULL,
		0x3AAC5DEEEE673C47ULL,
		0x1761CE37355682FFULL,
		0x320A3D4104FF3925ULL,
		0xF3DA3EA995F8CBA0ULL,
		0xD0171A4579DDD8FAULL,
		0x6E52205B6F428A8BULL
	}};
	t = -1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6425E48CC24948C8ULL,
		0x64BD461EC48DD1B2ULL,
		0xAEB47F114CDAF345ULL,
		0x116D051213258F32ULL,
		0xF62AE92C271010BCULL,
		0x0ED7F79EA95BB450ULL,
		0x5247C9A250DDD922ULL,
		0xEB82254943776E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6425E48CC24948C8ULL,
		0x64BD461EC48DD1B2ULL,
		0xAEB47F114CDAF345ULL,
		0x116D051213258F32ULL,
		0xF62AE92C271010BCULL,
		0x0ED7F79EA95BB450ULL,
		0x5247C9A250DDD922ULL,
		0xEB82254943776E95ULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3AFF218B265DBEAULL,
		0x2679315FC25EFB54ULL,
		0xE430364FE50728FBULL,
		0x78AE977017EAC525ULL,
		0xE61D8EBC511FA5C3ULL,
		0x7C9BC010437CBBD3ULL,
		0xFE89558A4A73BEB7ULL,
		0xE79BF02F484FD41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E20C8D55B5CE2C5ULL,
		0x23A2395EC350A73BULL,
		0x721696D780B4B8EEULL,
		0xB4CEE8ACD7A07469ULL,
		0xC2421CFBD710011EULL,
		0x8D556AF3559EEFC8ULL,
		0x0EDE4810AAD51828ULL,
		0x97A36CEC29D8161BULL
	}};
	t = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56895696E762C361ULL,
		0xFB97D341CC5AE2ADULL,
		0x9021E61F99CB7395ULL,
		0x48B79462348EC7E9ULL,
		0x9A7C36BFEC1DE844ULL,
		0x963C9CAC064707EDULL,
		0x9327F1D473E6E3F4ULL,
		0x8CB3AB7BBA287D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B6E20E1287822EULL,
		0xBE92E35271AE61CCULL,
		0x9641404F94ABBBD2ULL,
		0xD7380B65D5F6BC4FULL,
		0xCA3238E7FEC4DF5EULL,
		0x499DCB8315388F92ULL,
		0xA2EA7116300C175BULL,
		0x61731CEA95B56B8EULL
	}};
	t = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDCC494A67C56562ULL,
		0x95C0492F67122313ULL,
		0x2301588C38F62D88ULL,
		0x51C92D12289A9C87ULL,
		0xFF2D841EACC64775ULL,
		0x3B5EA45360C195FDULL,
		0xEC978378C58162F7ULL,
		0x2677B523C7342F69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x454D3A9CF228A0F3ULL,
		0x29A72D0431592358ULL,
		0x08279462CB8A82B7ULL,
		0xC273C370272AF80FULL,
		0x2BED60B4944F5FB5ULL,
		0xABA176DC402D8566ULL,
		0xA6A9CC4844106842ULL,
		0x6E70744684570C30ULL
	}};
	t = -1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31A8BBAAC7BBC2F2ULL,
		0x62348452546EA4A9ULL,
		0x68EC2A2937F53AA7ULL,
		0x0402BF9869332EC9ULL,
		0xE365170771526197ULL,
		0x651BF901B5240FD7ULL,
		0x79F5B6E9B963264EULL,
		0xE5CFA1E5042159A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A8BBAAC7BBC2F2ULL,
		0x62348452546EA4A9ULL,
		0x68EC2A2937F53AA7ULL,
		0x0402BF9869332EC9ULL,
		0xE365170771526197ULL,
		0x651BF901B5240FD7ULL,
		0x79F5B6E9B963264EULL,
		0xE5CFA1E5042159A1ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F8A6851D1035605ULL,
		0x4A043B1396B10686ULL,
		0xC876623BB481D93DULL,
		0xB7E7C048E755DF5EULL,
		0x45261AB2C2852AABULL,
		0x663E0DEA5C37299FULL,
		0xF19DB1B8092437A8ULL,
		0x46EE864B98966C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7455187CD3BCF6D1ULL,
		0x736FD124BD2ADECBULL,
		0x317046FFD757BC6BULL,
		0xB466B5FA5E91635DULL,
		0x3526C3A25120C92FULL,
		0xEB7E43585F49AEEDULL,
		0x593B87CFDC3BCEA2ULL,
		0xA8021B0DF434FF45ULL
	}};
	t = -1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0F5D86A8D0415C0ULL,
		0x5B73471CC4905585ULL,
		0x0B27B27E865092D9ULL,
		0x847F24F3091AD65EULL,
		0x6AAD1B65033DCF5CULL,
		0x04648A6E4F3EA906ULL,
		0xC2427AD43C8928CCULL,
		0xE06DEF79E912951BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FD05162A5F4BB3ULL,
		0x9501E6315F715EF3ULL,
		0xF6186764A190F61EULL,
		0x31D058D6BD5AB721ULL,
		0x144EC467E5EFF546ULL,
		0xB32AD5FB6E61431FULL,
		0x9A7D40CBDB18AA3EULL,
		0x4326E36B3C68B601ULL
	}};
	t = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x475C617394B8205AULL,
		0x997E04C5CFE2BE3DULL,
		0xB092F1E0DB7BC35DULL,
		0xC59D96BED39EBE36ULL,
		0x794FC5592F05B304ULL,
		0x2BFB7AD5621ECF86ULL,
		0x3791B23B55FAEDCFULL,
		0xE707849EB72001F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F9FCD0FC7ED79FAULL,
		0x9C59B2E534C11B71ULL,
		0xCCF449C662343CC3ULL,
		0x1A43392812992D16ULL,
		0xCC40288C11B2DD27ULL,
		0x4DF3DCBA772F8EE4ULL,
		0x90A27FC471C514EAULL,
		0xD3B467CC065855CCULL
	}};
	t = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9833077A8AE3B880ULL,
		0x87CFCFE8BFEFA53EULL,
		0x8CCEF885398B9472ULL,
		0xDF236E5E31F4B856ULL,
		0x33B64DE3F39F380EULL,
		0x61C26D4DFA07BEDEULL,
		0x83F349110C35CE1EULL,
		0xBF65B38260D68A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9833077A8AE3B880ULL,
		0x87CFCFE8BFEFA53EULL,
		0x8CCEF885398B9472ULL,
		0xDF236E5E31F4B856ULL,
		0x33B64DE3F39F380EULL,
		0x61C26D4DFA07BEDEULL,
		0x83F349110C35CE1EULL,
		0xBF65B38260D68A8AULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AC7B996FF8D2B43ULL,
		0xF0AFD48291605CBAULL,
		0x4F4ED7CD5EE0B994ULL,
		0xFCFA804429074D83ULL,
		0x580797C7BA71378AULL,
		0x957EB996E1B62646ULL,
		0x88AB4C2E4C53377CULL,
		0x68217A0C0555E628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2862671816869DDCULL,
		0xF29BD4BEC9ED06DDULL,
		0x8A12B7D963559FCBULL,
		0x322BF9BCE2BED338ULL,
		0xCFE8819C80987300ULL,
		0xE288AE11943E9979ULL,
		0xDAAF5BBEAF2770AEULL,
		0x55CADE07F77E237CULL
	}};
	t = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B9F953D9463FFF5ULL,
		0xBB31E730D5ACF718ULL,
		0x1A3FB5F1AEEF1619ULL,
		0x5B5CACB60CFD7A88ULL,
		0xF25230BCA581DF25ULL,
		0x2D5113280FBD0E68ULL,
		0x565F6536C7FD8CE3ULL,
		0x242C3CA5ED8D0279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8760BED5E21E96E2ULL,
		0x47DA19D7B4547FACULL,
		0xB792FA3DEABBF2AFULL,
		0xBE31C7778C194179ULL,
		0x3ABDCA374605EAB2ULL,
		0xD012369E04E9D3B9ULL,
		0x59FEE2E7E80B48AEULL,
		0x0E6DEEEEE8A1FF47ULL
	}};
	t = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBF0E9110F536538ULL,
		0x13A97F4C1EDAA9F1ULL,
		0x8254143DE805590EULL,
		0xBA8466022097A13AULL,
		0xDEFE88552C2D1438ULL,
		0xF95D6C062CB04D7FULL,
		0x974FAAA8584C6441ULL,
		0xA103B028A84ABC64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC98DC13E4EE3FAULL,
		0xE07D2C1E3BBBA396ULL,
		0xDDEFB95EF48D70FDULL,
		0x3C816F8F699066BFULL,
		0x046DFB074DEA68AAULL,
		0xA6E33F25860BD8C8ULL,
		0x6368AB0D6957E30EULL,
		0xCECB16FFCAC8FC53ULL
	}};
	t = -1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8052832BB2912C4CULL,
		0x4F57913A17555706ULL,
		0xD4797F0CB997DF5AULL,
		0x95000D2AA7323441ULL,
		0xA50305D9D5424C0CULL,
		0xE771B88C8EA92D83ULL,
		0x05B3585586FC07A1ULL,
		0xEB6707AD06C0C305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8052832BB2912C4CULL,
		0x4F57913A17555706ULL,
		0xD4797F0CB997DF5AULL,
		0x95000D2AA7323441ULL,
		0xA50305D9D5424C0CULL,
		0xE771B88C8EA92D83ULL,
		0x05B3585586FC07A1ULL,
		0xEB6707AD06C0C305ULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F6FA09838DB26C4ULL,
		0xEBBF4305F2E59A27ULL,
		0x5F5FF99194357409ULL,
		0xDC22BBE72B8DA5CDULL,
		0x665C13C6CF2D5EFEULL,
		0xC7BEA0E525C4BC36ULL,
		0x7C436C73D535726BULL,
		0x6786E294773AC58AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B75C18B643EBBDULL,
		0x472E1FB02DE943D2ULL,
		0x75997E92A53F5925ULL,
		0xA39ACA7CE87BC41AULL,
		0x0B8AFF0628A55F66ULL,
		0x63FCF94A35590A6DULL,
		0xA32C506CF00EF4C4ULL,
		0x064F13C0BCF3376DULL
	}};
	t = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x739D49BD3A97CA60ULL,
		0x136A5662D4E3EB30ULL,
		0x680CC8CB96D6DDACULL,
		0x0B331D49F3C505A6ULL,
		0x95F5A77059F3B2F3ULL,
		0xA11BEBBFF3351709ULL,
		0x3E129D3840AF9AC1ULL,
		0x41F5C2283FD68019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC997AF97A1EF5ADEULL,
		0x39B80BCCEEB5BADCULL,
		0x681FE6A9C0E2410EULL,
		0xB2936BE2068D2AA7ULL,
		0x37BAB201621B7169ULL,
		0x269463DFF8846D14ULL,
		0x615510B15D543753ULL,
		0xFBD92238F40A080CULL
	}};
	t = -1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE6332E881F88D39ULL,
		0x7CB34A3AFB09A3CDULL,
		0x9BCDE3445278712CULL,
		0xDC45005C54EC15E4ULL,
		0x73C16C5150C2647CULL,
		0xD4CDB3EF944CF6A3ULL,
		0xE267E04D6C257AE4ULL,
		0x600ABF8248751137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D746F57D68B2E53ULL,
		0x51DB4A46FCF25F17ULL,
		0x3B289117C0ED5A3CULL,
		0xB851B0E85B262CA7ULL,
		0xC24AD531F367838EULL,
		0x9907F80A21A97CA7ULL,
		0xD76686B446795FBFULL,
		0x7EE2AEA4CBC15599ULL
	}};
	t = -1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4CA89B195AFB069ULL,
		0xE54D505A1F5125CDULL,
		0x1E3A6300332FD51AULL,
		0x15CC09118563312AULL,
		0x31E7B0C488820E1BULL,
		0x3B5F23D7AD0F46E2ULL,
		0x9C2C915C9703BDBCULL,
		0x34E1EBB519C23567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CA89B195AFB069ULL,
		0xE54D505A1F5125CDULL,
		0x1E3A6300332FD51AULL,
		0x15CC09118563312AULL,
		0x31E7B0C488820E1BULL,
		0x3B5F23D7AD0F46E2ULL,
		0x9C2C915C9703BDBCULL,
		0x34E1EBB519C23567ULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x057C7F08AEDAD783ULL,
		0x9150D9488C79719FULL,
		0xAA71693E03E038C9ULL,
		0xC4D9BEF389B95F1AULL,
		0x319B121BB3491917ULL,
		0x0D5025947A275E59ULL,
		0xAB7686D6A1079085ULL,
		0x249A34AFDB3120F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4766CD58800285ULL,
		0x8BBB69FA2A2AD3E3ULL,
		0xE943AC86E954E2B5ULL,
		0x724A11933E4FD01EULL,
		0x386DD648C7B6E654ULL,
		0xE91E3B21EFD84FE5ULL,
		0x12233C5E252AC609ULL,
		0xC850E4B49933C4B1ULL
	}};
	t = -1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89A73E4AEC463800ULL,
		0xF282732C34895D90ULL,
		0x76C3CCE12AFFC8FDULL,
		0x917B6A950870ECD0ULL,
		0x378C4AD327C930DEULL,
		0xA2117D49A9CA9012ULL,
		0xB0573C7C4F6ECFDAULL,
		0x6652EA99A96131DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x113F87429D041FC3ULL,
		0x07914B47960F3782ULL,
		0xF874D22BF4E916D0ULL,
		0x1B0D8A8E9DAF9848ULL,
		0x19BFA5955C90C3C4ULL,
		0x1BE444FE592D87F7ULL,
		0x06E17055F60871DEULL,
		0xC25D5ED04CE3BE1BULL
	}};
	t = -1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6B5DF0E8F745987ULL,
		0x36DEC9DE8BB9578AULL,
		0xEE3232CA2DE3A107ULL,
		0x998AE0A857726F8AULL,
		0x036AEF989C67AF1BULL,
		0x234EDAD616F24C4FULL,
		0xF6328C3316AB21FEULL,
		0xCAC0FABB487E7647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC629F1431C0C988EULL,
		0x770AC4CA29F27A18ULL,
		0xEDD55A334190C262ULL,
		0x5503CFBF75844F19ULL,
		0x91E24DAA5553FCA3ULL,
		0x6A225201F990DAC7ULL,
		0xBA842C1B62D115DFULL,
		0x218E86D0EFB4EC17ULL
	}};
	t = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CC7E65435D550E6ULL,
		0xC8ABC513F5904A31ULL,
		0x4556F91B1CFD0DABULL,
		0x4EB60F4C928F1AB5ULL,
		0xB2EEC639D07435FDULL,
		0x2DF175AFD2BFA167ULL,
		0xED590A20124B912BULL,
		0x2C436817803CA057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC7E65435D550E6ULL,
		0xC8ABC513F5904A31ULL,
		0x4556F91B1CFD0DABULL,
		0x4EB60F4C928F1AB5ULL,
		0xB2EEC639D07435FDULL,
		0x2DF175AFD2BFA167ULL,
		0xED590A20124B912BULL,
		0x2C436817803CA057ULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE8DEC8C9F8694E1ULL,
		0x9E186AAB53FCA6BEULL,
		0x5F03A948FAEFEF01ULL,
		0x16BD06124347B02FULL,
		0x284692982160212CULL,
		0xFA23D340056D06C4ULL,
		0x4355D92E2261E686ULL,
		0x2988F194A1C6DB43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B07B14674B67F4ULL,
		0xED6C6F8416BD4828ULL,
		0x7F30CB58A97DA62FULL,
		0x7513205A2B8528EDULL,
		0xE3B4589E4CB63ADAULL,
		0xCADC90D713FF77E8ULL,
		0x02EC3E83B413C86CULL,
		0x04D6E3B46B3A815FULL
	}};
	t = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCB1A0788C43DBACULL,
		0x93337AF7A9576D60ULL,
		0x25149C53CCA1003EULL,
		0xC1DCE93BF7D2AA3EULL,
		0x86675128B40ED541ULL,
		0xDD55CBFC5688B71DULL,
		0xEA7B83D66A80FA9EULL,
		0x07B9DA8A20812127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x508CCAEBBB103005ULL,
		0x59CA8450923A55A8ULL,
		0xBA370DB647E5D4D5ULL,
		0x521D59A20E35990DULL,
		0x474DBC1BC826F037ULL,
		0x35DA5E2AD1F20B8BULL,
		0x9600771FF1B630A0ULL,
		0x335B308B3F7CF702ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9269B2752A363E2ULL,
		0x05FCA05A7637932EULL,
		0xC478AB4D11B42925ULL,
		0xA1CFA13209F6146DULL,
		0x14A48CD501C66105ULL,
		0x033F1F06E310776CULL,
		0x89F2A14BF883B8D2ULL,
		0xA8DB44ADAC3760ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAB56FEF09BB321CULL,
		0x913DEB2238B49558ULL,
		0x30D5B326FBFD697EULL,
		0x66FB4DD0205B64C7ULL,
		0x32030CF822F41E63ULL,
		0x0198D1D506ACD15EULL,
		0x0036F8AECB51E5ACULL,
		0x0B6B262828EE590AULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F21D0E579D21E2FULL,
		0xE17226FEFFEE723BULL,
		0xFB47C174A03AB5C8ULL,
		0xF1CBBC5E6CD6EAB9ULL,
		0x08AA666EC8A1288AULL,
		0x72048988F45BD62CULL,
		0x0AD78F78C37BAEEBULL,
		0x1A81A57C67FD2F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F21D0E579D21E2FULL,
		0xE17226FEFFEE723BULL,
		0xFB47C174A03AB5C8ULL,
		0xF1CBBC5E6CD6EAB9ULL,
		0x08AA666EC8A1288AULL,
		0x72048988F45BD62CULL,
		0x0AD78F78C37BAEEBULL,
		0x1A81A57C67FD2F61ULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F3EC1B2D211F6A6ULL,
		0xD8A5492ECA385F11ULL,
		0x58F5E0B3C265012BULL,
		0x3F0CDAF2207B1323ULL,
		0xE53CB395991D5DEAULL,
		0x675FB52D583725C5ULL,
		0xCFE8F8BEEF99F456ULL,
		0x92C4E3B06716E087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451130D28B40F552ULL,
		0xED152B21714B37BFULL,
		0x81365C408F69754CULL,
		0x6FBE4645E91F8B12ULL,
		0x512533070DCCCB6BULL,
		0xCD32D8921FD7668AULL,
		0xCB538107F505AA99ULL,
		0xB8215E8F7A353AF2ULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB8F9BDEFFA01178ULL,
		0xFB55E27B0E66256FULL,
		0x7674CC4B36D3F6E6ULL,
		0x6624ADE1BE5EE92FULL,
		0x3331DB19713FFDFAULL,
		0xE9F5C003B9B9F87CULL,
		0xCC2F97FC31DE9056ULL,
		0x76FA6650D58A237FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x460C6279CAB59240ULL,
		0x37FEFD3A4E83EE66ULL,
		0xA224DC8C71EBC351ULL,
		0xFE86F5CCA5C877D6ULL,
		0x0BBC8E1E7488D161ULL,
		0xA638B0610B3E48E5ULL,
		0x11992F9484F21788ULL,
		0x3DB2530E3C56ECF3ULL
	}};
	t = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BCC766938C1C3FEULL,
		0x167635C83D71C29FULL,
		0xDF4531A518961125ULL,
		0xD2BC599EC15A72C8ULL,
		0xBEE0D3A880267764ULL,
		0xE390C0B5B289BB79ULL,
		0xE14E8D8D8E3916D5ULL,
		0xD44998251FB6A8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC5C7F9C4FEEB19ULL,
		0x40E0DAB62AD146D9ULL,
		0xBF6FFC77642777A6ULL,
		0x757FF43A751E2FB3ULL,
		0x0FBDF70568174AFDULL,
		0x8A5A90E01739CAD1ULL,
		0x04E75E10C6AB8DF5ULL,
		0x059455C0924A46FEULL
	}};
	t = 1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0683232A84529BF5ULL,
		0x921804B626DADB1DULL,
		0xD1417FFFCB7DFEA1ULL,
		0x8502643BE3F76F1FULL,
		0x5A841378947595A3ULL,
		0x8788576872267FB3ULL,
		0x3170F1B5C6E53281ULL,
		0x30E7982F26D51AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0683232A84529BF5ULL,
		0x921804B626DADB1DULL,
		0xD1417FFFCB7DFEA1ULL,
		0x8502643BE3F76F1FULL,
		0x5A841378947595A3ULL,
		0x8788576872267FB3ULL,
		0x3170F1B5C6E53281ULL,
		0x30E7982F26D51AD7ULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44BD396D3B4F466BULL,
		0xF51396BE9FBAE02AULL,
		0x8A4880E50A927F57ULL,
		0x3ABC5DAAF2D3D594ULL,
		0x83BD21D7AE162B69ULL,
		0x5F5E3BE6A0D4B6E0ULL,
		0xEBD59FDBD3BF9794ULL,
		0x382A1A02268038BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA48B5E2BFFCB93ULL,
		0xB80213D9322E4E11ULL,
		0x683B9A33FD7665AAULL,
		0xFD93E5631CC92529ULL,
		0x0117888F5194394AULL,
		0x54FF4C8FDAB2EAB7ULL,
		0x76E52F0ACD4DFBC2ULL,
		0x800A42BDA722DC8AULL
	}};
	t = -1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDF53BF5D9149F55ULL,
		0x3054BF1FFBB3FBA8ULL,
		0x59E1C16D5F73991EULL,
		0xCCD88F27202D94DAULL,
		0xE14D128B63BD91B9ULL,
		0xC4FD1554E0AD41EEULL,
		0x52BE153966DFCE07ULL,
		0xAC8B27A658B95754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A3EEAC4918448A9ULL,
		0x3B673BA58A6C9853ULL,
		0x03002AFAC3AF5FFDULL,
		0x4DB5A7B5B49A1B93ULL,
		0x12D0AAC542EF5D94ULL,
		0xF711D3FA5559DC50ULL,
		0x34F35E3B78C5707DULL,
		0xAB436695232CD805ULL
	}};
	t = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D0A1786CC33FD3FULL,
		0x9D5EBCC6AE4DA521ULL,
		0x6C028C8FDAFA0AEBULL,
		0xFF1D14F1EECA6474ULL,
		0x46A7EE95EB400B5DULL,
		0xE9F113DCE4F0346BULL,
		0x2654EDCA1EA74239ULL,
		0x402032F5ACCB7C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F6E05B51251667ULL,
		0x800CBEBBF26BDF4CULL,
		0xC079ADE50B9F5052ULL,
		0x6955A5B6D484500DULL,
		0xC0ACA6871D8BBBD0ULL,
		0x8C4C755C184EAFC0ULL,
		0x909A7FB4D8863420ULL,
		0xBF9CDCEF8F4C5F49ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94392A83BBA744CCULL,
		0x76432390C0F13348ULL,
		0x33796C6D6845DD24ULL,
		0x12F889F2A758B34CULL,
		0x8C8CB915D091AC08ULL,
		0x1007260A68894F8DULL,
		0x036EC9CFCBCCD4CCULL,
		0xAD8D76ED0C56E831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94392A83BBA744CCULL,
		0x76432390C0F13348ULL,
		0x33796C6D6845DD24ULL,
		0x12F889F2A758B34CULL,
		0x8C8CB915D091AC08ULL,
		0x1007260A68894F8DULL,
		0x036EC9CFCBCCD4CCULL,
		0xAD8D76ED0C56E831ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x827C5DFD10A08108ULL,
		0x7FEF91DE10684F60ULL,
		0xF7E8E50E99F98AF0ULL,
		0xA657DCE959CB4A58ULL,
		0x13A62D0C5032C228ULL,
		0xB9746F02D258682DULL,
		0xC0C18B03924B139DULL,
		0x25046642F1067BD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD49D64BCBBD6835ULL,
		0x72EF31536EE3650AULL,
		0xBDA1EE8C8095DFF2ULL,
		0x2E44D274BB5BC5D8ULL,
		0xAC69915C7CE70B7AULL,
		0xC90D03F5419F67B6ULL,
		0x81D981E33DB7328BULL,
		0x352B5EA54FE7567CULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18AF8C7C4B848B6AULL,
		0x88FA4FA26F81F89AULL,
		0xEAABF6A2D0088F4FULL,
		0x73F7338337EECF8DULL,
		0xB082FF2D48CCC739ULL,
		0x8D5AB0F1EA3FAB4AULL,
		0x6145D48DBAE6BA92ULL,
		0x4721D6B9AC90B9DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864921FA046CBD34ULL,
		0x97A6A1961ECD458FULL,
		0x725D901C0AE1BCA2ULL,
		0xB148BE9258D3365CULL,
		0x4A3C25A3A4209FFDULL,
		0xB83C9741170C1AC8ULL,
		0xBBD4FDB6189EFEEEULL,
		0x6EDFA3197E504B6BULL
	}};
	t = -1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67F36345AD0F4AEFULL,
		0x9127998E68EFED86ULL,
		0x0E12B7F90844998CULL,
		0xB561584756D29DC2ULL,
		0x458B3E22B01C03CBULL,
		0x2EA08E3E4CE98751ULL,
		0x8B39BD59952C85E5ULL,
		0x08556F60ED5758AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40510289091839BCULL,
		0x94593A13737AF72AULL,
		0x84BAF4E474051366ULL,
		0x6B5398F21BD666F8ULL,
		0x3399339BA1837FAAULL,
		0x5AB5EED990665EC0ULL,
		0x59CC80E50BB606EAULL,
		0xE9DAB34F5753E223ULL
	}};
	t = -1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE1B7ED555B36FE0ULL,
		0x0B86269C58BD39A9ULL,
		0xF9724A3508FC6AD9ULL,
		0xFA6C7A87F16D9720ULL,
		0xD0E15702B8691C59ULL,
		0x1784C5AC7B03E7A7ULL,
		0xF426660E33C127B6ULL,
		0xB52CE6C88487F35CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE1B7ED555B36FE0ULL,
		0x0B86269C58BD39A9ULL,
		0xF9724A3508FC6AD9ULL,
		0xFA6C7A87F16D9720ULL,
		0xD0E15702B8691C59ULL,
		0x1784C5AC7B03E7A7ULL,
		0xF426660E33C127B6ULL,
		0xB52CE6C88487F35CULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x889DC391C6D1F289ULL,
		0x0F2B2BE3CEDF64CBULL,
		0x95074E833181FA03ULL,
		0x9E348ED3407C109CULL,
		0x59859479F52EE7FEULL,
		0x4EC28D87D596D047ULL,
		0xEDA1AE9379A39D5BULL,
		0xE7608BA074D57A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC062FEB56B7B2EAULL,
		0x35944545F161761AULL,
		0x60C831D55DF373DFULL,
		0xEE4081106D209991ULL,
		0x37D57E706BDA5F54ULL,
		0x5F65C1FFB384639FULL,
		0x1C0DF70FD2632A9DULL,
		0x283558802F91FD1CULL
	}};
	t = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD324980EA4420F98ULL,
		0x2CAAFD25956611C4ULL,
		0xCA680B791947710EULL,
		0xC22D8BE71BEB6A0DULL,
		0xCCD61C646896F59EULL,
		0xF2CCEB59B3AE071EULL,
		0x43EC76B4CE79F85DULL,
		0x9C4B4B2FF403470AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B06B2DBF5C3F3F7ULL,
		0xADBC14F7D3E74C70ULL,
		0x1C05CC7C29BB6822ULL,
		0xD146A265799E0673ULL,
		0xA20B35972236B257ULL,
		0x525B2F0EBD5BD8F7ULL,
		0x827A7A28047882ADULL,
		0x5D1CCE8997D9E235ULL
	}};
	t = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65B3918D789EB591ULL,
		0x81B2F97D0E340948ULL,
		0x69AA8174229062B0ULL,
		0x5F2AC505906983D8ULL,
		0xDC60EB72101D6677ULL,
		0x1FE09D0F0767A888ULL,
		0xAB067C25549C59DAULL,
		0x0F1679F3042F27B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD77864B5EBD8B2AULL,
		0xDE75B012CD7C939AULL,
		0xB4857E1B6FA45991ULL,
		0xC564FF0250C55C09ULL,
		0x0041EC5E25324520ULL,
		0x079CC72BFF699784ULL,
		0xA2DEFC7A8DBBD9E0ULL,
		0x65581560C85BC5F2ULL
	}};
	t = -1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49C03C8710E4395DULL,
		0x8606FF069E0B0757ULL,
		0x8B9DB1AA0C5A054BULL,
		0x6122AE250B9CE391ULL,
		0x6317E08D2E088662ULL,
		0xE7A8DF26F7D762F4ULL,
		0x00179784349D0F5CULL,
		0x01C98B077C8E2EEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C03C8710E4395DULL,
		0x8606FF069E0B0757ULL,
		0x8B9DB1AA0C5A054BULL,
		0x6122AE250B9CE391ULL,
		0x6317E08D2E088662ULL,
		0xE7A8DF26F7D762F4ULL,
		0x00179784349D0F5CULL,
		0x01C98B077C8E2EEEULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C5570DAC4AF83E2ULL,
		0xC11C73F4E37781D4ULL,
		0x324A7FEE1DAD173FULL,
		0x3C2B2835A42B4AD0ULL,
		0xD1D42A48B0AA3992ULL,
		0x217577E3792EAD4CULL,
		0x52B359A8ECFAFB2FULL,
		0x1CDF970BAC361CE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DBE4B4A27385BB8ULL,
		0x8E7943BA9C7663B1ULL,
		0x8EF45AE4B5A6220AULL,
		0x3A8309521A73BF45ULL,
		0x28D276C3D44DD8C9ULL,
		0xCC1DF86D46F07568ULL,
		0xAA1FC0CF4FABA862ULL,
		0xE4AB0B8A3A44D624ULL
	}};
	t = -1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x899407895A909A83ULL,
		0xD65B2AE56A4D36E5ULL,
		0xBDE73584ACAB7987ULL,
		0x38A2F92A4C2A611FULL,
		0xDDCCFD3EB039EBDEULL,
		0xEFF3D65F3E86D359ULL,
		0x0440FC554BF61132ULL,
		0x4BAD59609B05DD70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA1147A6FF4BA172ULL,
		0x5A57BE82F39A6841ULL,
		0x9C9A1693C3848EDCULL,
		0xABE49C6DC4934F88ULL,
		0x4C7C3CC673FFF0CBULL,
		0x3F81729A29F182B7ULL,
		0xD25066B4079D12C1ULL,
		0xCFAFB35516264E70ULL
	}};
	t = -1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE53EFE42BC5B92E8ULL,
		0x831B6E2E986F31D4ULL,
		0x964F1220E8EAF214ULL,
		0x27D1D9D770EA5F9DULL,
		0x6DF4DB0CE9DD207FULL,
		0xAD3738D1229D6B90ULL,
		0x2C6ACB4700276328ULL,
		0x7202EAAC12E6AEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA377AF5634B13D95ULL,
		0xC905038F8ABBC0AEULL,
		0x3A69237D0865EB4BULL,
		0xF9DB189B1F4B8CA7ULL,
		0x328B93AE575F460EULL,
		0x50D2A6C840969F9EULL,
		0x403A74C86E09213EULL,
		0x94FC3A943A883491ULL
	}};
	t = -1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0721C0B50391C561ULL,
		0x98F97520B1794065ULL,
		0x2F5474008E3DE9A2ULL,
		0x00D14548E5A9A2DBULL,
		0x0D14BD310B005ACAULL,
		0x7F18D1BCA4A6AC1DULL,
		0x4C62A50E3B1249E3ULL,
		0xE18B2D267727C82FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0721C0B50391C561ULL,
		0x98F97520B1794065ULL,
		0x2F5474008E3DE9A2ULL,
		0x00D14548E5A9A2DBULL,
		0x0D14BD310B005ACAULL,
		0x7F18D1BCA4A6AC1DULL,
		0x4C62A50E3B1249E3ULL,
		0xE18B2D267727C82FULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x339F36A97A6FCE95ULL,
		0x759BB52597B6E652ULL,
		0x38CB420C0C3CB08EULL,
		0x1A9F11F4F89F8E7DULL,
		0xF0CD9DBBC6BBCA6AULL,
		0x109F8139C2738B9FULL,
		0xF0766D5E732C6BFAULL,
		0xAA97D22E20AD6642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CD79428C0127D8ULL,
		0x8B5C4579CE3D4D2CULL,
		0x1A4C31465979BF2FULL,
		0x7EB9C078DE8E4A0FULL,
		0xB736DA50ED884EB5ULL,
		0x96F42C7E26CB7F39ULL,
		0xEE94370353D1C65AULL,
		0x372B474F615AB2F0ULL
	}};
	t = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93536C74BB87E463ULL,
		0x9C16DEAF69ED7FDEULL,
		0xF564E487111F02ADULL,
		0x83B61C1821528D33ULL,
		0x3EB350B288ED3654ULL,
		0x9CD9731CC8EA208BULL,
		0x6E85BA83A7DA1CE5ULL,
		0xCE283D59A6745092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7CDB9697D118E24ULL,
		0x7176CB5895B07230ULL,
		0xBC348B07F54FCF36ULL,
		0x69A9DFAD8925FF1EULL,
		0x72C5CBA4A6C30082ULL,
		0xBFE558B1218A8E51ULL,
		0xDF49A1DB923BE7AFULL,
		0xED3FA552A85882C8ULL
	}};
	t = -1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9AF97B01713F664ULL,
		0x0A46FAE02BFC9747ULL,
		0xDB46D8F9553AE51FULL,
		0xE51460B584F589A5ULL,
		0x817AEF4D52760799ULL,
		0x2B68B949B1A469E5ULL,
		0x17F2A656ABFD0BE5ULL,
		0x7C3DE9FE01F7A69EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA1184D08305CBA2ULL,
		0xD72E20F18630FDAAULL,
		0xF54A937DB7F64640ULL,
		0x6D9666768DA9B9AAULL,
		0x8330534B8026E768ULL,
		0x655816A0809BAE95ULL,
		0x4341E2AEBF8DACCFULL,
		0xB7366A867EDBD439ULL
	}};
	t = -1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37FDFDBA8C303FE0ULL,
		0x3B18EBC092881DE3ULL,
		0x8AA5DA950EE73367ULL,
		0xC683D2FC18B9FB81ULL,
		0x421EF374292EBF8EULL,
		0x61F18D92312DE4A8ULL,
		0xFCFC07E659CE24DAULL,
		0x0C7AD469D580F40EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37FDFDBA8C303FE0ULL,
		0x3B18EBC092881DE3ULL,
		0x8AA5DA950EE73367ULL,
		0xC683D2FC18B9FB81ULL,
		0x421EF374292EBF8EULL,
		0x61F18D92312DE4A8ULL,
		0xFCFC07E659CE24DAULL,
		0x0C7AD469D580F40EULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99282E7B8688D6F1ULL,
		0x7ED4A3293693A0E1ULL,
		0x797D87E444AB0CD1ULL,
		0xAB3A0734BB71FD6CULL,
		0xB59D15BF60B6F635ULL,
		0xC281177818ECE4A8ULL,
		0x9BE7D020934DAE4EULL,
		0xB3C5EAFFA403F83CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E6D6F889917AA0DULL,
		0xA3BF94E7D778B219ULL,
		0xC3156B03B6C4DA59ULL,
		0x24AAF37559921172ULL,
		0xEE617DDF579D5077ULL,
		0xB11C47AB19CA1A13ULL,
		0x7EF16B4A6E498449ULL,
		0x8E7536DFBE7FF5A7ULL
	}};
	t = 1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2895F9F1E2AD266EULL,
		0x1BC49C4D5A0684C8ULL,
		0x1E8F067696672E40ULL,
		0x56C1C7808B4A571FULL,
		0xF935D8E9348E84A1ULL,
		0xD4A489077EB1E059ULL,
		0xC5DDDEEE51441C63ULL,
		0x37D0A50C0B8A5355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD01ABB28554D66AULL,
		0xF0CCF2A99A23D92CULL,
		0x3EA2668266B79421ULL,
		0xA87B4F83625B240AULL,
		0xE8F3176BDC1A7D36ULL,
		0x0137401558861955ULL,
		0x655B5539A7C4F112ULL,
		0x80DA921DE5EF87B9ULL
	}};
	t = -1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7788386B5AFE477ULL,
		0xF9E74FB245E46D8EULL,
		0x2EA34925733FDF26ULL,
		0x9EB68250BFFF5490ULL,
		0x741929594AEDEB1EULL,
		0x5487A9C84EC45AE4ULL,
		0xDDC6AE267F04EF16ULL,
		0xECAF4795DC4DE331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34DCBD366C03A71BULL,
		0x69034A76C5AE17D3ULL,
		0x1DDEF1B8D8DB58E3ULL,
		0xA7C4BEB0BA4BD482ULL,
		0x66A9A93AA6616170ULL,
		0x666AE51358F7B7B4ULL,
		0xD301565432B47354ULL,
		0xBC42F465F37A2BA4ULL
	}};
	t = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46CF06E7D31A03B4ULL,
		0x70393A587F44DC41ULL,
		0xE40AE1346AA1CA6AULL,
		0xE1D9F3154455044CULL,
		0xA3D477C41BA3A9C6ULL,
		0xDD74B8CD8846A8A8ULL,
		0xFDBD2FEF56BF8622ULL,
		0xBD6964197834408FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CF06E7D31A03B4ULL,
		0x70393A587F44DC41ULL,
		0xE40AE1346AA1CA6AULL,
		0xE1D9F3154455044CULL,
		0xA3D477C41BA3A9C6ULL,
		0xDD74B8CD8846A8A8ULL,
		0xFDBD2FEF56BF8622ULL,
		0xBD6964197834408FULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3752E1E260815903ULL,
		0x2505BCA151796566ULL,
		0x9EBBF60C9D15235EULL,
		0x30B4B026B32FE0D3ULL,
		0x62217247323B19F3ULL,
		0x62CDEBAFA4DA35D1ULL,
		0x603F3C7528C515ECULL,
		0x8FCDCFACEDB59F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C0CC026E2D4A42ULL,
		0xB52E90CDCC6DBB4FULL,
		0xBB2DD065FEBD9C78ULL,
		0xCBC63FD8394A1368ULL,
		0x45BB559B694363D5ULL,
		0x6B485135B35A3C4BULL,
		0xE887E8ADE3FFE9CDULL,
		0x31E16DC75EC62A48ULL
	}};
	t = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BB4D764BBF2F588ULL,
		0x4A0D3AAE5086208AULL,
		0x6A82DA65D7CB4EACULL,
		0x1127B2221EFA86AFULL,
		0xAE21EC551459B9A8ULL,
		0x253CA326A6F6A823ULL,
		0xAF6E8CA177F0CB8EULL,
		0x6F4436546D4B885FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x378AC8D63EBD1D19ULL,
		0x6228FB677CFAB3A5ULL,
		0x30BE89B23432096FULL,
		0x98CB2B69A4D3E341ULL,
		0x70A5741C0E9ABF60ULL,
		0xA87E41E076049290ULL,
		0x02DC4379CB7C1E1AULL,
		0x8F7FC18EBFE23EBDULL
	}};
	t = -1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A7604A158D3BD0DULL,
		0x946068E6329E7067ULL,
		0x03AB86C153AE5ED6ULL,
		0x0338953A37B15940ULL,
		0xDD4BD6F9D6B7BD2BULL,
		0x9FB1F4B65830C7F4ULL,
		0x2FFB913FCE574399ULL,
		0xCD531B8DE587C999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE54187683551B5F5ULL,
		0x5E479852521C6F6FULL,
		0xBB3068A1C1E35B6EULL,
		0xAAE28FDBAE4B2483ULL,
		0x44706F31D412E54DULL,
		0x87C7B8B0BEB44A7CULL,
		0x92A9413FF52B8A76ULL,
		0x3DB4A18255131F57ULL
	}};
	t = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x516EE6908A7B9C55ULL,
		0xEB28A03AB8CA5468ULL,
		0x4EB941A134048073ULL,
		0x725B5E2D715D7439ULL,
		0x0CA13E2FEDF3A5B6ULL,
		0x352730C9AAAB6767ULL,
		0x8BE4E1C523FDD885ULL,
		0x9E74CF6CEF1FC05EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516EE6908A7B9C55ULL,
		0xEB28A03AB8CA5468ULL,
		0x4EB941A134048073ULL,
		0x725B5E2D715D7439ULL,
		0x0CA13E2FEDF3A5B6ULL,
		0x352730C9AAAB6767ULL,
		0x8BE4E1C523FDD885ULL,
		0x9E74CF6CEF1FC05EULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF9D5C7E229599EFULL,
		0x2C3B7A137832F217ULL,
		0x339ACB83FD9A8181ULL,
		0x176A4452596924EFULL,
		0xD148EEE980CB0C2CULL,
		0xB4B3DFA54295F54FULL,
		0xD4EAD8FA6B020562ULL,
		0x0ADD39C1428F048BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330B9732C2934DD7ULL,
		0x293A331E42F337CAULL,
		0x842175173F5FDF14ULL,
		0x81B543B548668D7CULL,
		0x73B4BD82D0C8EBB9ULL,
		0x047CFE0EEB554C3DULL,
		0x02C267080B4C2D63ULL,
		0x4CF62D5D3F0A018DULL
	}};
	t = -1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97A6272FE0342AEFULL,
		0xB2EB45802932C3ABULL,
		0xC53B91FA445D37B1ULL,
		0x37F2A7F8F876DC85ULL,
		0x255514E35C31BE4BULL,
		0xD00215F563B29194ULL,
		0xC1EF1F465A5CF75AULL,
		0x799CD6EBD34A955CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79EB0B338E0AB3ACULL,
		0xDCCB6E6A59D86200ULL,
		0x2BCA8F2BDC795A59ULL,
		0x87C9E21F8B4F0A42ULL,
		0x75D192C5BB94AE9FULL,
		0x3D8FA9FCE773FE26ULL,
		0x440C2F17C01C47ACULL,
		0x337E696D45A10833ULL
	}};
	t = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE85AB907915DDFC8ULL,
		0x610C80A6C9A6BE52ULL,
		0x285C284F3DD3367CULL,
		0x7C5DA6F67C2BC77AULL,
		0xE91F440DF880A6BCULL,
		0x0E6306B32D902F95ULL,
		0xB27FDDB21CC3FA12ULL,
		0xA618299348DBBCB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0A7F5F3D9CB175ULL,
		0xC538CE57028F2DD3ULL,
		0x4684F4D670C8A53AULL,
		0xC157D1A9EE223F28ULL,
		0x0D8AAC1105AA015FULL,
		0x2524FF6CDDDBE2ADULL,
		0xE9A9BD5D090E5CF9ULL,
		0x2AC6DE8EE0987478ULL
	}};
	t = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D2BCADAE6F322A8ULL,
		0xEBFEF61C8C3FA249ULL,
		0x850BB93262EF7D7EULL,
		0x2DCB1B30BA71B80CULL,
		0xD2B3C49C7A471728ULL,
		0xDF9A0A2B5A841C9EULL,
		0xAB278D6AE7EE4FC5ULL,
		0xAC36CE84CB1D6977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2BCADAE6F322A8ULL,
		0xEBFEF61C8C3FA249ULL,
		0x850BB93262EF7D7EULL,
		0x2DCB1B30BA71B80CULL,
		0xD2B3C49C7A471728ULL,
		0xDF9A0A2B5A841C9EULL,
		0xAB278D6AE7EE4FC5ULL,
		0xAC36CE84CB1D6977ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865C173810DBD1E8ULL,
		0xCBFB96FBC4533CF0ULL,
		0x7939A249475F5DFBULL,
		0xB63C01F551271654ULL,
		0xABA7AC92E914D93BULL,
		0x0F1E02BDF4CCE324ULL,
		0xA9CBCAF61603F230ULL,
		0xD9C38FD1734ED2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA2A2A3C230A1107ULL,
		0x6B51A87447281A7FULL,
		0xBAFD4B2722D65DBFULL,
		0x3EB5496F0089D8CEULL,
		0x301E940E2FE40F4BULL,
		0x7D1726ED14E0B672ULL,
		0x2F07E001AB319852ULL,
		0x8DDC3DAB94457EA2ULL
	}};
	t = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80DE12E178117C92ULL,
		0xB226F5EE8234E65EULL,
		0x9C7CCD897C9E5C81ULL,
		0x24EEB81C4C872095ULL,
		0x2F038BC980B3E5ABULL,
		0xB238641B9431878CULL,
		0x80025D0D8EE4364BULL,
		0x8E3A25B4942CCEC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC6D067555A5818ULL,
		0x45D7C443407CA7B2ULL,
		0xA407EFB3B915922DULL,
		0xA40FCF11CDC77C63ULL,
		0x7EDF19B484E63B2CULL,
		0xD116E89576538170ULL,
		0xA12D002B1FE82CB9ULL,
		0xF05F1F37A777C28AULL
	}};
	t = -1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EFEE8ACDD450488ULL,
		0x00734A8515D897B7ULL,
		0xB93E6EBC7FF2E7E2ULL,
		0x4F953145EBD14A62ULL,
		0xD67AA51144B59B93ULL,
		0xA9FD2BCE2733D9A8ULL,
		0xD25CAC9B2F788BB7ULL,
		0x4A93D897E109556CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D677DCDF816004BULL,
		0xFFB463B40BEB3A5FULL,
		0x1860AEB0771664D3ULL,
		0xF6D0F9FFF702B720ULL,
		0x00E9D7FD7B39F58EULL,
		0x973C5C5A6641C478ULL,
		0xE0AD662E690B06BAULL,
		0xC62C4273B5375855ULL
	}};
	t = -1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD811357B27998B0ULL,
		0xBD854B92B3EAF36DULL,
		0xFC50D4CFA9B91A01ULL,
		0xBD89734371360F3DULL,
		0xEC32CC619257C04EULL,
		0x6ECD46A96D17FF92ULL,
		0x2E09F21EE04FC11DULL,
		0x6CE757ACA072FEC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD811357B27998B0ULL,
		0xBD854B92B3EAF36DULL,
		0xFC50D4CFA9B91A01ULL,
		0xBD89734371360F3DULL,
		0xEC32CC619257C04EULL,
		0x6ECD46A96D17FF92ULL,
		0x2E09F21EE04FC11DULL,
		0x6CE757ACA072FEC1ULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACF147ABBA072A48ULL,
		0x45217E1BB1394879ULL,
		0x2DD69544C73AA8EBULL,
		0x10E44DB426F0FAEDULL,
		0x8C7CAF4BB63DB3B5ULL,
		0x649070B4D4EACB1FULL,
		0xA05308F6846C137EULL,
		0x475D35DBF2BB6C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x601A9753257B7F7AULL,
		0x24E2F7AA9E55FB4CULL,
		0xB78062E50081D94FULL,
		0x8256FE2571209363ULL,
		0xD101CC80FEDB8529ULL,
		0x16ADFB98F46A892BULL,
		0x659D5693EDFB2CDEULL,
		0x92B4C3B6FD6A5F25ULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32646B6C91B6F6B4ULL,
		0xEC5300F9A8644569ULL,
		0xF15B2B067A20CF1CULL,
		0x137CE5CE3B812526ULL,
		0xD48D57C3B01B8094ULL,
		0x7BAADAEFBB28A9C6ULL,
		0x4774818A978BB0ECULL,
		0x855598EEFB4BD1B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82AC79BE2BF1A4B5ULL,
		0x3F3228FF1B0293E4ULL,
		0xB57C252A8E1328CDULL,
		0x10ED20F8D9949984ULL,
		0x2C4E993CDD400427ULL,
		0x128705D0C43018B0ULL,
		0x2077C33E69AB8C4CULL,
		0xFEE6EC72DE262694ULL
	}};
	t = -1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8864DC9D0C8C4A3EULL,
		0x7A767C38A19DBA45ULL,
		0x59E01B91FB5D4EE1ULL,
		0x21164765F5341049ULL,
		0xC7A62DE6482B360AULL,
		0x3DF26F25504781C8ULL,
		0xF748B2F10893E543ULL,
		0x2000A4C0C57ACABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBD01AAD14C1A3F0ULL,
		0xFA2A1C7241FABFBCULL,
		0xBE8BCB67E98BDECEULL,
		0x5FD6C191265C2238ULL,
		0x49BC69AFDB92B037ULL,
		0xAB5E3F6A436A2A27ULL,
		0x4B30A204DB1CB5C1ULL,
		0xB9CD6F3BA38F1AACULL
	}};
	t = -1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DB46AFFA249E04EULL,
		0xC7262F78D12123EEULL,
		0xAC94A54893D2BC5FULL,
		0xB3ACDFA4CC3AEBD3ULL,
		0xAB3452E1F705F035ULL,
		0x2745CD6DD25E40F0ULL,
		0x355C1B8353E6B695ULL,
		0x5487A4D25E1B19E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DB46AFFA249E04EULL,
		0xC7262F78D12123EEULL,
		0xAC94A54893D2BC5FULL,
		0xB3ACDFA4CC3AEBD3ULL,
		0xAB3452E1F705F035ULL,
		0x2745CD6DD25E40F0ULL,
		0x355C1B8353E6B695ULL,
		0x5487A4D25E1B19E0ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB2FA6121EE0B9F8ULL,
		0x577B74BCAB3E3F5EULL,
		0x483092D4CF3FDD7AULL,
		0x8CEB731DB694BC2DULL,
		0xA167F8D4630D60B6ULL,
		0xDDD169DE994BDB83ULL,
		0xCEB87032C6163677ULL,
		0x990678D830D54BC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x090045A18FDA0758ULL,
		0x71C780937E50ACB9ULL,
		0xCEFF3AFD4D2C3977ULL,
		0x15889D4B5614F0E2ULL,
		0xAB1712246903D3E9ULL,
		0xBC0A3D8E39A96AA6ULL,
		0xD36BCD25E1278DC6ULL,
		0x772720D5F0775DF8ULL
	}};
	t = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87ED5C7EBB662509ULL,
		0x9B85B2FEE3E08D5CULL,
		0xD0DDC8F1D1E26637ULL,
		0x3CF60B72576C7D85ULL,
		0x918ADB07C40747D0ULL,
		0x8F0DDDCCD59AA3EAULL,
		0xAF81C12CD683EF91ULL,
		0xFA8FCA0D76686DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918C6AF6BBCEFDD3ULL,
		0xAD19ACBC7A0FE9DCULL,
		0x0D482AC9CB87E873ULL,
		0x6873D698C06A63FDULL,
		0x00F80E7D9FA6F5E7ULL,
		0x45E697923386DBD7ULL,
		0x7180F650E86A01FFULL,
		0x17F4E3C86C84F16BULL
	}};
	t = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77CB82FFE3FB1EBBULL,
		0xB21C0526A478FF7DULL,
		0x9D590FE9A3D32317ULL,
		0x1B8D4AED5C7271E0ULL,
		0xC1BD2E4896A8B461ULL,
		0x0D5BE5B53F7036F3ULL,
		0xB2E941B273A560C5ULL,
		0xEF75B9419A055036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FDFBFB73C06B2D2ULL,
		0xE074C07C3857E25AULL,
		0x108BDD0703B13ECFULL,
		0xAA135A54F5B07DF0ULL,
		0xA83900188A9F44D3ULL,
		0x534AE5C1FAF68198ULL,
		0x6200ED3BE5509CF8ULL,
		0x6D0EA574BA51051EULL
	}};
	t = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D84720AF60566F8ULL,
		0x133A016E5E504421ULL,
		0xECEBD0A6B710F789ULL,
		0x8E96D87DB7C2ADA7ULL,
		0xACAEB3B3787C20F4ULL,
		0xC39E50D6679AAE91ULL,
		0x761A8BB0E3DA4E8BULL,
		0x36D5E2B12EB3E339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D84720AF60566F8ULL,
		0x133A016E5E504421ULL,
		0xECEBD0A6B710F789ULL,
		0x8E96D87DB7C2ADA7ULL,
		0xACAEB3B3787C20F4ULL,
		0xC39E50D6679AAE91ULL,
		0x761A8BB0E3DA4E8BULL,
		0x36D5E2B12EB3E339ULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0773B0896916E661ULL,
		0xDFA5611B74F0C564ULL,
		0xC40F1C6EE4B1880EULL,
		0x7132305A84BDA15FULL,
		0x5F1EE4461D33AF26ULL,
		0x5E8FCA611FA39ACAULL,
		0x73E5D94958D069DBULL,
		0x65C5BCC520B0E47FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE0DE08A8BE92FCULL,
		0xE2CB7ED4A9402EBDULL,
		0x20C3B9DC3F7C27E8ULL,
		0x36F72062C9C623FEULL,
		0x6C3291A24979AC85ULL,
		0x165B941143415967ULL,
		0x872CA0B1738254BBULL,
		0xD91FD1F3C90664B2ULL
	}};
	t = -1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA89569B54D07F7F8ULL,
		0xE2DA9E13AEE3D0C5ULL,
		0x04CC9E2264B6E027ULL,
		0xA9C335A5B0526995ULL,
		0xE80834CEBDBDBBDCULL,
		0xEBB619CF46DE36A8ULL,
		0xF527D172B8A16240ULL,
		0x66D392467FE9BACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9FF2A27A6142ECULL,
		0xAA91843AACC809C4ULL,
		0x659CE0BAE1622A9DULL,
		0x120305EFFD3CFF04ULL,
		0xDBD7DCEF9361AD41ULL,
		0xC8B7D8B1A97A4117ULL,
		0x49B239A417C3A310ULL,
		0x8CBE74394F598647ULL
	}};
	t = -1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29A37DD3A7BE4A3BULL,
		0xFADEA07D3E2CD9E2ULL,
		0x57EFF5F05F4DEFBCULL,
		0x2D9894B370D44E75ULL,
		0x27616FDBCC6F9FBEULL,
		0xECDA3C96618F3644ULL,
		0x42CA2E76161DC9E8ULL,
		0xEB626DD706C2BD6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70A2D2A5221D437ULL,
		0x1D5E7BE94784A68CULL,
		0x55E7317283725DB6ULL,
		0xCCE77FEC653A0C3BULL,
		0x4F92CA9339E53BB5ULL,
		0xC9409460F8FC74ADULL,
		0xC0B34B8361E82DCDULL,
		0xD219594F5F0E35D7ULL
	}};
	t = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x122A11BA3AD76BECULL,
		0x984B91464A01449EULL,
		0x605EEA6996F3ADE6ULL,
		0x95869CD249D2CE52ULL,
		0xAF8191BBF605555EULL,
		0xED7895A68041413DULL,
		0xDE6ED1430877E955ULL,
		0x77A06A1EC923E0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x122A11BA3AD76BECULL,
		0x984B91464A01449EULL,
		0x605EEA6996F3ADE6ULL,
		0x95869CD249D2CE52ULL,
		0xAF8191BBF605555EULL,
		0xED7895A68041413DULL,
		0xDE6ED1430877E955ULL,
		0x77A06A1EC923E0FFULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B546C42F37074DBULL,
		0x078627D93EA3AF55ULL,
		0xC5F767626A2F3D88ULL,
		0x49D46F3F43EC9441ULL,
		0x36EEE69131E90C82ULL,
		0x5500CD006E79D150ULL,
		0xC0CC90582D47ABE8ULL,
		0x057E3FD6BDFCD640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B5A4F3C73C3EA9ULL,
		0x94994CD5CD243FFAULL,
		0x9CB8853D531B7240ULL,
		0x04E47EC86B43C928ULL,
		0x678A87F0830A3F4BULL,
		0x3E06296070D79D0BULL,
		0xB1FACA0F650F3897ULL,
		0x6C866153FA2BFD27ULL
	}};
	t = -1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEAA271274E50DEDULL,
		0x101B3069D70F2B5AULL,
		0xE9717C37713540A5ULL,
		0x76754AC3367649C3ULL,
		0xD20FCD0246BFB288ULL,
		0x5CD6F5EB9D87BDE0ULL,
		0x75F6DC3F1723D4ACULL,
		0x845CE534AB089278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2022A27670555CULL,
		0xDC6D564CFB6F3C3CULL,
		0x616BD164E56A417FULL,
		0xEBEE6D96BC5853C7ULL,
		0x375443718F418019ULL,
		0xE904EA241EFA9D3BULL,
		0x6F9E86CB5FAFAC2BULL,
		0x8F6708B5FACC3FA3ULL
	}};
	t = -1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA30F1CB8191F29DBULL,
		0xCC3ADDF5F1B49996ULL,
		0x0B8037C74064193EULL,
		0x8F430386ABAEAE74ULL,
		0x4D965F6A4A3CA32DULL,
		0xE5CC320EABBB7F8EULL,
		0xB05B75FC0B63C387ULL,
		0x95CAF5F23A6D5FF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2762121FE5ACBA6ULL,
		0x3194539048F522EFULL,
		0xF4E07A226330B22FULL,
		0x4FDEF954E2C66DEDULL,
		0x5432C9C9EC08EADFULL,
		0xB9DBC4B31BE846CFULL,
		0x3A82AA091C271038ULL,
		0x6124A6BE670F0ECEULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57B5D30540351263ULL,
		0x8A8A35671E895154ULL,
		0x7DD16A9EFE0F3DB0ULL,
		0xFB833AE8400C8991ULL,
		0x4F509DD9037B9B86ULL,
		0x566BE9D05BB4670FULL,
		0xB4501F9B625E437BULL,
		0x213BC8FE933821D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57B5D30540351263ULL,
		0x8A8A35671E895154ULL,
		0x7DD16A9EFE0F3DB0ULL,
		0xFB833AE8400C8991ULL,
		0x4F509DD9037B9B86ULL,
		0x566BE9D05BB4670FULL,
		0xB4501F9B625E437BULL,
		0x213BC8FE933821D9ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6322D3E877CEBD52ULL,
		0x402B4BFF60AF0ECFULL,
		0x60A4362289CFB72FULL,
		0x7238CB5D4A77F290ULL,
		0x37DD941ADD71C409ULL,
		0x4FEFAECE2AF2E1BDULL,
		0x3E82C9A6DB09BDEEULL,
		0xB45B20FC5CF0DB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A7CFF1B2BDEC7FULL,
		0xDF58F6B8C72BAF4BULL,
		0x4FA9108F34797D19ULL,
		0x01EAB1BC871FBE0AULL,
		0x11ABE028C932FE9CULL,
		0xBF6FD03BB0B7D901ULL,
		0x40677FB6215DBD8BULL,
		0xD7BDE428086EE71AULL
	}};
	t = -1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBF16CB2D009D0C8ULL,
		0x84815189B7370889ULL,
		0x7E112AE4C4FB5C15ULL,
		0xB33E29A3F52D5408ULL,
		0xB8F95E45BF586C1CULL,
		0xCA5E2E1A4D95D6D8ULL,
		0x2A44719489621D22ULL,
		0xA604FD0BD7EA3E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB90E1AB1CCDEB7ULL,
		0xA52790793DE5F97AULL,
		0x6E09312474612549ULL,
		0x347F98AA1F33176BULL,
		0xEE1ADFC1418CA8A6ULL,
		0xF369716245A2446CULL,
		0x4AB4726133979894ULL,
		0x64B7F774BDE74090ULL
	}};
	t = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD15883506C302DA0ULL,
		0x0E6705E3F4C54A94ULL,
		0x98169BFE381580D3ULL,
		0x179CB459241B2AD3ULL,
		0x768047ABD079E352ULL,
		0x4900DFA792B54C77ULL,
		0x8ACD72D813B839CBULL,
		0x7E1E33D87DB5D659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B56DC1561C9F220ULL,
		0x121CDACE8DE00268ULL,
		0x571C43E52FD8276AULL,
		0x067AA44FF6E041B9ULL,
		0x42F5B36C5CC21219ULL,
		0xBB9B478C5425B438ULL,
		0xB77365ED18B1999FULL,
		0x34BDE0B9704FAF14ULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41B2A3C1CDCB2092ULL,
		0x071A2B72D0A8C9CAULL,
		0x3E700EC709772C52ULL,
		0xB3F45CAF6DD81703ULL,
		0x300A5CE1C6A9C093ULL,
		0x122D3B701D822859ULL,
		0x36F0DC14F15B0AB5ULL,
		0x07BC47603D3E6FE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B2A3C1CDCB2092ULL,
		0x071A2B72D0A8C9CAULL,
		0x3E700EC709772C52ULL,
		0xB3F45CAF6DD81703ULL,
		0x300A5CE1C6A9C093ULL,
		0x122D3B701D822859ULL,
		0x36F0DC14F15B0AB5ULL,
		0x07BC47603D3E6FE1ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE81F03866840CE8BULL,
		0x88C6A79299AED299ULL,
		0x49ED23B754694B60ULL,
		0xC497B5427D29BD34ULL,
		0x54F7273BC2FBBAB5ULL,
		0x12FA4449214D8CD4ULL,
		0xA4FFBE41CAEE11C0ULL,
		0x976C899391770487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B24D5CB276E736AULL,
		0xD5F2A53FD2D63420ULL,
		0xD3DCD273079E176CULL,
		0xE4B9B3C278F76BA2ULL,
		0x46E56FEEB092B923ULL,
		0xA56501973E05CEE7ULL,
		0xB863EF264993212BULL,
		0xA4FAA0D380E86042ULL
	}};
	t = -1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7E4377B18C7D2D7ULL,
		0x328CD6DB82B5A1D1ULL,
		0xD5E34A7ADD39EF06ULL,
		0x9C914A78B9B3977FULL,
		0x7181E1210F5E5627ULL,
		0xBC005C3115030CA7ULL,
		0x9AAACB4D05D81561ULL,
		0xFC22BF995EF8F0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29CB9A8010F5D6DCULL,
		0x343699EFCDD70EAEULL,
		0xE4F38B2544AC5E23ULL,
		0x49A52A8AA91ACF6AULL,
		0x5CF60984D4E05DE5ULL,
		0xE03FB6E8D2ABDA65ULL,
		0x4ECE7734A07B0EC3ULL,
		0xD65FC1C67CC99397ULL
	}};
	t = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EB7C288FBE36D74ULL,
		0x1ED21D55F51A7B84ULL,
		0xA5B5E4CF1E919D30ULL,
		0xC5C2D2FD49827FD4ULL,
		0x0A0D19A7292070B8ULL,
		0xB90DF73537A1E681ULL,
		0xFB42F587A4BF3CADULL,
		0x1C83489054EF7B6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96290109C1B17677ULL,
		0xD54DD708B04F8982ULL,
		0x05EEDF18DDA1FF94ULL,
		0xAE84F9C42EC3DE32ULL,
		0x92F913EA264C38CBULL,
		0xCC608FE23C3D7056ULL,
		0x1ECF1D910C41E3C4ULL,
		0xD1E26BB3E28FB621ULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEC3BD3D6A0CD3E0ULL,
		0x6122F7CB45A921F8ULL,
		0x94EE4637B43C5EB2ULL,
		0x55F8E403DBE47644ULL,
		0xBC2C1A6EB31C13EDULL,
		0xAD524DB405F7E227ULL,
		0x6A7FC444A9455F94ULL,
		0x2B4984D908C50394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC3BD3D6A0CD3E0ULL,
		0x6122F7CB45A921F8ULL,
		0x94EE4637B43C5EB2ULL,
		0x55F8E403DBE47644ULL,
		0xBC2C1A6EB31C13EDULL,
		0xAD524DB405F7E227ULL,
		0x6A7FC444A9455F94ULL,
		0x2B4984D908C50394ULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A7FD748EAD72EAAULL,
		0xC707185C5913E43BULL,
		0x95C3DE0EE64CBFFCULL,
		0xA87F3EE9C87726E0ULL,
		0x504F2B7F85AF4572ULL,
		0x710AC48F0615F9E6ULL,
		0xB888D7642593D820ULL,
		0x40F08BE766D50BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E0B2B29D189B0E5ULL,
		0x96F4CF9ED12CDA47ULL,
		0x5304C36D3C0B251CULL,
		0x17DE928E238D8234ULL,
		0x1AF8A916D56F190FULL,
		0x796367C5AA9261D6ULL,
		0xC61890F9BDD90F57ULL,
		0xF7575D7D3A7845B8ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C9A37E9BCD2B8BBULL,
		0x0D3DFC2A73F89893ULL,
		0x509EC6F8BF92C8EFULL,
		0xE537DF1C11421021ULL,
		0x4E251647BDAF7038ULL,
		0x87EFB205C1300F0EULL,
		0x4F12CBF2ADE9DD20ULL,
		0x34D492728FD7B048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5E1B3BD3B042525ULL,
		0x5FC2209321A5ADEFULL,
		0x327C23F1EF9D64B8ULL,
		0xDDCC03CA721EB000ULL,
		0x6F9CC7F87191EC95ULL,
		0x429477D3AA98B18FULL,
		0x965A323C75934831ULL,
		0x88EB62E9CA3CBFABULL
	}};
	t = -1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1318A56F8A36AE9CULL,
		0x4F7BF30CBE3A5321ULL,
		0xEB743395D8EF4B55ULL,
		0x45F0E4FC715879CEULL,
		0x71175FB6CA788219ULL,
		0xE561832E0C060BAFULL,
		0x1621B2C3ECEE6E37ULL,
		0xCFBE05F4D24DFBB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50FBD2A2EA0557E2ULL,
		0x4D225DCA7E3E51E2ULL,
		0x187F45C3F3608391ULL,
		0x0B1B80998E2E098BULL,
		0x411482B6A47E116BULL,
		0x8695883B66BCCFA3ULL,
		0x0CCF219F3B558A8DULL,
		0x3157EB4A40541059ULL
	}};
	t = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA339703813F33E68ULL,
		0x795EF4F7094DECABULL,
		0x9FACFB46DCB80BDAULL,
		0x717A13299C3B718FULL,
		0x2C532DD395CBFA76ULL,
		0xA881D91067340D40ULL,
		0xBD33ACC30A13F20BULL,
		0x759DB3C8FE92A8B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA339703813F33E68ULL,
		0x795EF4F7094DECABULL,
		0x9FACFB46DCB80BDAULL,
		0x717A13299C3B718FULL,
		0x2C532DD395CBFA76ULL,
		0xA881D91067340D40ULL,
		0xBD33ACC30A13F20BULL,
		0x759DB3C8FE92A8B0ULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61F6967A760A0B0DULL,
		0xA3B9109A67D9FFE1ULL,
		0x3E2812B8A6148AF1ULL,
		0x7BCB0D174E100AD3ULL,
		0xAD647B51B5293E9FULL,
		0x68515F09C9EA036CULL,
		0x3E7431C3DC73D660ULL,
		0x6BCFF0F8819518C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B1B6CA5353E9B2ULL,
		0x63CB235F7B59111CULL,
		0x5FD19DE6270C67B0ULL,
		0x8B3EAB5EC9707C14ULL,
		0xF2A8AFC98AC4A6CEULL,
		0xE83539AD17BE641DULL,
		0x936374CF3B8BCA86ULL,
		0x16549072441FF3D0ULL
	}};
	t = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACD08B6AAD10F441ULL,
		0x3B6C903C5D4011CEULL,
		0x2F73C8B2B5F934BCULL,
		0xB5273751029D3678ULL,
		0x452AEC5383A01CC7ULL,
		0xA051B994AE1E1844ULL,
		0xC896828D9A665859ULL,
		0xEC52BF350C87B45CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF46C3BDC4670D53ULL,
		0x17EB535F16A9E0B6ULL,
		0x3DA24690B736D98BULL,
		0x73150B2B46113C3CULL,
		0x92DF4FE65A1E5B25ULL,
		0xB429C3A5FC5986A3ULL,
		0x7BDB2A8148B8DE51ULL,
		0x240C0448DE18C13BULL
	}};
	t = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBE34FC56A65EF86ULL,
		0x3D870B92FC35A650ULL,
		0x0E0EB7D143659011ULL,
		0x40984E96C6216696ULL,
		0x458C43382A9CA15FULL,
		0x34BC41291C5983E1ULL,
		0x179D096092ACE60BULL,
		0x682131DA6D154682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC32EA85439BF338ULL,
		0xDA20BFC9B6CA1D26ULL,
		0x744CCCDA6A4D4D8DULL,
		0x56C44848CED8CF30ULL,
		0x6A4A149CFA65FDE6ULL,
		0x115E2E1988516AA0ULL,
		0x0BF95E6D287467BBULL,
		0x12AAB7835314BD47ULL
	}};
	t = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC09E476CD5DF29AULL,
		0xB1D18EFB8FBFA728ULL,
		0xF286BC70E83D8C6BULL,
		0x2FC39D9251449057ULL,
		0xB46DA6626589F3DBULL,
		0xB1D7097498FB182EULL,
		0xA794A6816EE6DCE4ULL,
		0x889B897D32766A04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC09E476CD5DF29AULL,
		0xB1D18EFB8FBFA728ULL,
		0xF286BC70E83D8C6BULL,
		0x2FC39D9251449057ULL,
		0xB46DA6626589F3DBULL,
		0xB1D7097498FB182EULL,
		0xA794A6816EE6DCE4ULL,
		0x889B897D32766A04ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x761B89704032ADB5ULL,
		0x2529D94F64F244E4ULL,
		0x39DD1FE6B025B846ULL,
		0xB42A50CCBD79B383ULL,
		0xE35B74F11A224A97ULL,
		0x00026FF02994E704ULL,
		0x1DBC90BB50745EABULL,
		0x5EAE5C9B9DED4075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D69EEA264F1E156ULL,
		0x8AB49F3D4597F89CULL,
		0xCEDC74D75E1916B6ULL,
		0x9BA414AC76320189ULL,
		0x10C8B0FC897E64F8ULL,
		0xC2B971EDA16A580CULL,
		0x2342E324020039F7ULL,
		0x6D168F39C1D21DD3ULL
	}};
	t = -1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4FDF1E1591FC211ULL,
		0x0D974F6F4398955EULL,
		0x37205B4F455A19E0ULL,
		0x84D808B5140DB727ULL,
		0xBFA606739C62F54BULL,
		0xD13D292852C4650AULL,
		0x3EF396D39BE4B7D5ULL,
		0x1DD6A0B751516294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EDBD6AF79E5DA86ULL,
		0xC2F3E5C515E28D97ULL,
		0x7B2C172943FD7079ULL,
		0xD3B96EBF62D106D4ULL,
		0x216BD0EAAB7F6EC4ULL,
		0x4A2ABF91787D31F7ULL,
		0xD4CA334F5D44849EULL,
		0x325B2B9F5CF0F6E2ULL
	}};
	t = -1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6552B5F18F4964A0ULL,
		0xA6A0F5C4B93D6EA3ULL,
		0xA76F7A2AF90F5D7AULL,
		0x856360F012DEF1DBULL,
		0xA1FAA96B03AF2B99ULL,
		0x1B3C6DDEE04B85FFULL,
		0xEDCA498B56471EC9ULL,
		0xE4792F352ED11033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34C12B96804684C7ULL,
		0x8FA21F27C93547CAULL,
		0x859FD3DBB640FFA7ULL,
		0x9679DDD9AC2790F6ULL,
		0x2D414FA4CB2066BBULL,
		0x0FD899F3789E598EULL,
		0xDFD6D012AFB49FD7ULL,
		0xE04050282731AABCULL
	}};
	t = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4EC6AA2C2C8F635ULL,
		0x578EA262D8FAF9C6ULL,
		0xD6CBEB3EE8B9BF4DULL,
		0xA999C8FF308308A4ULL,
		0x4F3C9D0E6B3C056BULL,
		0x39FCD3DF2EE1E4BAULL,
		0x8672D265BD18DEA6ULL,
		0x514ED116207D2083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4EC6AA2C2C8F635ULL,
		0x578EA262D8FAF9C6ULL,
		0xD6CBEB3EE8B9BF4DULL,
		0xA999C8FF308308A4ULL,
		0x4F3C9D0E6B3C056BULL,
		0x39FCD3DF2EE1E4BAULL,
		0x8672D265BD18DEA6ULL,
		0x514ED116207D2083ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C97EBBB97A36DFAULL,
		0x3B6D481DAA1E531EULL,
		0xD9DB7B0719828B85ULL,
		0xDAE67D131F48B056ULL,
		0xA277ADD4355E2C98ULL,
		0xB113BF85A6856100ULL,
		0x85890061DEEA34B4ULL,
		0x8FBD4A83A6D60116ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3695797A44A0CC6EULL,
		0x704F2B45E7220DFDULL,
		0x1E7526E0B44607CDULL,
		0x17F2A0DF66FD14ACULL,
		0x00C68217209AC523ULL,
		0x2C69058517991D0EULL,
		0x17AD10EB5361F602ULL,
		0x855FA54A5FF466DEULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B823F9CE0256C6DULL,
		0xFBD4B6CB62AE5031ULL,
		0x6345001FF19CF989ULL,
		0x49370AEE38A25808ULL,
		0x16613904D17516A5ULL,
		0x42749854B19D6D42ULL,
		0x35106607DE68B1EEULL,
		0x0312257B15498A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4D94F2AF9CFFDBEULL,
		0x45C6004449497374ULL,
		0xD46AC1244D681DA7ULL,
		0xD5D70D8413246D9EULL,
		0x40E46C52D946EA5DULL,
		0x5CA2A385A3809F63ULL,
		0xB8231A6FA16CB6A0ULL,
		0x5DE69B766B861340ULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5771D1EE7D23607ULL,
		0xE6AA47EE068EEDEEULL,
		0xA1B3368D804EACA8ULL,
		0xD9CB3887E66E2EC8ULL,
		0x702C9957C0E0F535ULL,
		0x03FC443CF32EF73EULL,
		0xE7942B6583FEB0C5ULL,
		0xEA4089D1523F4679ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DCC51EB1BDACB50ULL,
		0xC422B198666C0A49ULL,
		0xA12031F2776D1C04ULL,
		0xF649A3264308F4B7ULL,
		0x24C3B7556FC01BA0ULL,
		0x15526F9FF60DFD97ULL,
		0xA74F7AE6F9E318DCULL,
		0xE6B30F01931FC881ULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A61FE262B8694FCULL,
		0x82936B73C792A58CULL,
		0xF8661B5F4DAE3775ULL,
		0xD301057C9999B54CULL,
		0xDF4A3D1D41F91AD4ULL,
		0x9EDD0C6DB6B3F71BULL,
		0x2F25DF7240C5E789ULL,
		0x09010A2FDA2531EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A61FE262B8694FCULL,
		0x82936B73C792A58CULL,
		0xF8661B5F4DAE3775ULL,
		0xD301057C9999B54CULL,
		0xDF4A3D1D41F91AD4ULL,
		0x9EDD0C6DB6B3F71BULL,
		0x2F25DF7240C5E789ULL,
		0x09010A2FDA2531EEULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9183D984D9A8F49FULL,
		0x8A30FD5F9D1FCBDAULL,
		0x7D81B09E32129E18ULL,
		0x057DF7E3A7D09988ULL,
		0x3076070A6A8A1387ULL,
		0x21EDE706A986734CULL,
		0xA73BB1007CFD4EF3ULL,
		0x0A46404EAFC32B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2EF475D4718DB2ULL,
		0xB1DCC1E527310A7BULL,
		0xA4CD19955FF029E4ULL,
		0xBDFE1901443BF290ULL,
		0xE9242C53B0C6AB33ULL,
		0xBBC645210D22D988ULL,
		0x3F2D37EBF37A1E14ULL,
		0xF6B98A18A2B7C1BEULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FFD3C0C08F3F0B8ULL,
		0xA09ADD99CF0FB372ULL,
		0x10097F78CA9F634EULL,
		0x41405247288F87B7ULL,
		0x83CFE6718EB27341ULL,
		0x6CA8633FD7287F98ULL,
		0x9B2C543427FB6E21ULL,
		0xDC1FF499F7B79894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02BE52563AF2489ULL,
		0xDA117A18E6B23AB7ULL,
		0x005B2E4B805988E1ULL,
		0xE1F6EB322A4DD393ULL,
		0x01DD367C1C05E466ULL,
		0x52107FFFCC17AF30ULL,
		0xACF03AB4059080B2ULL,
		0xE6B7DF13243F58D2ULL
	}};
	t = -1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC05CBB08EAA56CCULL,
		0x84A975E6CE829E75ULL,
		0xADD8553A75AE4B75ULL,
		0xB1C3F9E700B2EB08ULL,
		0xB2E85D26706FC9A6ULL,
		0xE309539587FEAC93ULL,
		0x7391066525980098ULL,
		0x3BA193CDD339D981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB7DDD1BA8295F2ULL,
		0x579789005E5F51E1ULL,
		0x68BB027B48E8C56BULL,
		0x42CC32B3C3CF7CE8ULL,
		0xE5786595DB51B16EULL,
		0xAB4DF23DA0062044ULL,
		0x59D2A4F063A15A94ULL,
		0x7074F18CA17FC3B0ULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x632521DC01FC4B1EULL,
		0xABF78D4CE90657EAULL,
		0xF32B4A881E83D340ULL,
		0x108A6DFBA985AACCULL,
		0xB595E487C1D9D7BDULL,
		0x0CEA779D99732B10ULL,
		0x0024540D536E6E97ULL,
		0x6DEC3A22205F1FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632521DC01FC4B1EULL,
		0xABF78D4CE90657EAULL,
		0xF32B4A881E83D340ULL,
		0x108A6DFBA985AACCULL,
		0xB595E487C1D9D7BDULL,
		0x0CEA779D99732B10ULL,
		0x0024540D536E6E97ULL,
		0x6DEC3A22205F1FA5ULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92CEF6DF90D570E9ULL,
		0x487803BCFED83333ULL,
		0x91B069143C9EF5C4ULL,
		0x4BA4542D4887ADE3ULL,
		0xAEAAD1FAFCB4CD7EULL,
		0x9789BF4A4931F361ULL,
		0x89F20F4AA88FEE89ULL,
		0x9D577E6F27771940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB184D87DA2B44849ULL,
		0xA1792D9F73A7BFA4ULL,
		0x1B745183F24B3A21ULL,
		0x6979CFCADE6E348FULL,
		0x6A69E9A5B196FE75ULL,
		0xF259DA7E7EFD9331ULL,
		0xF871D8480A05CA38ULL,
		0x8EDDD1BE822C7F0CULL
	}};
	t = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC9A408D21D0E031ULL,
		0x6B5BCF4A86DFCEC9ULL,
		0xDBDD58703D0A6936ULL,
		0xFE9A5725BAF793ACULL,
		0x551027C3051A5468ULL,
		0xFC3BF0A04DDC73B9ULL,
		0xC88C230DD8F9D037ULL,
		0x405BE26425E22C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4E8F7B57181FD2ULL,
		0x947E0F8EDD3140E4ULL,
		0xE3E47DE791742661ULL,
		0xE087B5341CD29D64ULL,
		0x52F8DD1C745FF994ULL,
		0x47B1AF73179E5BE8ULL,
		0x3B186040F634FDC4ULL,
		0xBAABC67F46C691FEULL
	}};
	t = -1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB58BDF525EB782D6ULL,
		0x4BD177AB81C0111CULL,
		0xA7A37AA089B296EBULL,
		0xD0CFD5921522FAD9ULL,
		0xE0777BFEC858D444ULL,
		0x563137C9ECD75FA0ULL,
		0x3079A3C395F87A29ULL,
		0x8578EAE72CBE8787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C6A8444899F36EULL,
		0x8C60828635ED2537ULL,
		0xDC6C54945D13127FULL,
		0x6F96733B02E96303ULL,
		0x366B658B8AB07E4CULL,
		0x1ECBB216C3F3FA3AULL,
		0x8C5CEA93134ABA36ULL,
		0x7A1C843C3A4E7890ULL
	}};
	t = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5442C30ABDAC042FULL,
		0xE65E8D83A0023EACULL,
		0x2D667185FCE34316ULL,
		0xFF41DD62DC0FDF6AULL,
		0xA49442F90AF0CF57ULL,
		0x05D5FE80EAD3CB04ULL,
		0x559A7B7767510561ULL,
		0xBF28AA337F547489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5442C30ABDAC042FULL,
		0xE65E8D83A0023EACULL,
		0x2D667185FCE34316ULL,
		0xFF41DD62DC0FDF6AULL,
		0xA49442F90AF0CF57ULL,
		0x05D5FE80EAD3CB04ULL,
		0x559A7B7767510561ULL,
		0xBF28AA337F547489ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF6C8C2153B18F4ULL,
		0x4933EB3169F7795DULL,
		0x23A5BF7CA77BC3A4ULL,
		0x17802BF62B142ABBULL,
		0xFA2B2A2E79BA812CULL,
		0x8BCE892CF8F540B3ULL,
		0xF0F292C54EB358E5ULL,
		0x4658788B305CB278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE6AB42CE0BEDA36ULL,
		0xAEB63EE70FEA96D7ULL,
		0x759190D0A6F499ECULL,
		0x4DD28C54BF933F3DULL,
		0x08A292095C68238BULL,
		0x7903270ED7C64E7EULL,
		0xD27EDB1D039193F2ULL,
		0x7061136B72891D89ULL
	}};
	t = -1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD656D3C678E06286ULL,
		0xC2C02E75416C81BEULL,
		0x95BC72661E72BFD1ULL,
		0xF84B265DFBCD4D01ULL,
		0xD7994F587EA67544ULL,
		0x4E5C9DD55D13E90DULL,
		0x21E7F30B9FD0F193ULL,
		0xF8C7A8801E551AA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x441445A44A700C8AULL,
		0x17284EFC38860DBDULL,
		0xC8129A7DCB54B340ULL,
		0xAAB8D403F6F5A200ULL,
		0x7D3159A5EAA6EA58ULL,
		0xED9820C5B05EFCDDULL,
		0x426832B5C64A3F93ULL,
		0x593E0515A82B138DULL
	}};
	t = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34AFDB8E67C652B8ULL,
		0xEBE9E70AB456F464ULL,
		0xF22A910D5AE3BA49ULL,
		0x87B1E0C275D45345ULL,
		0x9F2C38E04AA895E3ULL,
		0x8A8553718AB529B3ULL,
		0x4F3F6754135A69BFULL,
		0x8908F50E3020F7B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857192E5F5E4A35FULL,
		0xE3FEBC87D4BCD737ULL,
		0x364C5257FAAF6101ULL,
		0x224A84B2313CD2FAULL,
		0xBD62EA54BBF583A3ULL,
		0x5C39CCC562005CC7ULL,
		0x068FA19993108A13ULL,
		0x354E13F0F3ECB93BULL
	}};
	t = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933FBBF750BD1BABULL,
		0x4E405DDAE1757D6CULL,
		0x271C71A474D1F0E9ULL,
		0xA9952F191E8F4D01ULL,
		0x3C8E02C7958528A5ULL,
		0xF35C335508DE9C5BULL,
		0xA4C582F1A53D31D3ULL,
		0x780F320F51074E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933FBBF750BD1BABULL,
		0x4E405DDAE1757D6CULL,
		0x271C71A474D1F0E9ULL,
		0xA9952F191E8F4D01ULL,
		0x3C8E02C7958528A5ULL,
		0xF35C335508DE9C5BULL,
		0xA4C582F1A53D31D3ULL,
		0x780F320F51074E78ULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBEE1C89BE548674ULL,
		0xA8D80EEBF399F427ULL,
		0xBE55EFA90C7BC24CULL,
		0x56DB8C189B070E76ULL,
		0x1200417392E021D8ULL,
		0x274D3D86DB115B6FULL,
		0xC2DE0F6A4BA1FDDCULL,
		0x6B8B0340401D8897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DADFDDD36BFC96EULL,
		0xCCD5C5B3A9D5ABCBULL,
		0x581EB1BD24AF9380ULL,
		0x57A14A3DFD7841CEULL,
		0x3153375087C914A1ULL,
		0xB7131D98A64A53F4ULL,
		0xAD1EFE280FE5AA65ULL,
		0x2804E0BE288297DEULL
	}};
	t = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46FCCC4731D9E63CULL,
		0x64201DB034767334ULL,
		0xA9A28C34746F935AULL,
		0x5CC92578B90BD275ULL,
		0x76B9D882980F605AULL,
		0xF22C17B7592CC5A7ULL,
		0x75EA7C80118F79FEULL,
		0x46976482F484ECA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x469ED1308953D29BULL,
		0x700DF5DEF48C54E5ULL,
		0xA0A4F69AF552BC90ULL,
		0xC49D286C79717716ULL,
		0xD447D11EFC24794CULL,
		0xDE1DBACBDA060F97ULL,
		0xB3F02A392FAD938FULL,
		0xD0B4ED22BBA73898ULL
	}};
	t = -1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31A5816998455546ULL,
		0x2E9B0A3D91B16439ULL,
		0x8CF0F63C07CF19B6ULL,
		0x629294AF5203EDA5ULL,
		0xAF3A30BBD937EEAAULL,
		0x0868AC9335048854ULL,
		0xDCBDF9B3E4C67D31ULL,
		0x305878169864EEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1E6139C8C2EE236ULL,
		0x244118ED1D6E9B96ULL,
		0x1AD05120C866C3E5ULL,
		0x0A4A04E21F6F1AA3ULL,
		0xBCAC3CAB1A0783AAULL,
		0x3472FF941434B60AULL,
		0x6B2F447DE8EB556CULL,
		0x6AF3B1C3B21F4C20ULL
	}};
	t = -1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4723EB69B7E51E9ULL,
		0xA96302BA808FDBDDULL,
		0xAC5F84F8279E85E0ULL,
		0x20252C360AB08FFAULL,
		0xD07C5D9FDC1A0856ULL,
		0x7A43BF4FABD32C74ULL,
		0x8E4F448D9AA19381ULL,
		0xE02D4177F5513CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4723EB69B7E51E9ULL,
		0xA96302BA808FDBDDULL,
		0xAC5F84F8279E85E0ULL,
		0x20252C360AB08FFAULL,
		0xD07C5D9FDC1A0856ULL,
		0x7A43BF4FABD32C74ULL,
		0x8E4F448D9AA19381ULL,
		0xE02D4177F5513CE5ULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB112CF7C4D41537DULL,
		0x9FEBAE63451C0556ULL,
		0xF8DB98D3AD7120F1ULL,
		0xBD9C90E833C92866ULL,
		0x6A3BDD0878A1D4FBULL,
		0xC45A9E16AA10B044ULL,
		0xDBA998F2F9478E6FULL,
		0xB2D349E1DC465E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE406469E3E420AULL,
		0xE068E832904AFB3CULL,
		0x744F3D9F80521C1BULL,
		0xE3DA141F1DCE1D9DULL,
		0xE5ADBA4DF58AFB1CULL,
		0xA12873C80280AA29ULL,
		0x42905F5B12FB0736ULL,
		0x3AA3654691FC60C3ULL
	}};
	t = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A49334FA21BB2A7ULL,
		0x0F5552A20C487592ULL,
		0xCB83AAFA2DF07F0FULL,
		0xF5F3FE8B07AC5C23ULL,
		0x5A5443A4A985545AULL,
		0xD350E02070618E20ULL,
		0x77438F17FD7B56CFULL,
		0xC95D0407CF1AF098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20CCB4EC4BC917C1ULL,
		0xF205E83A55513973ULL,
		0x1C5F9A663295FD65ULL,
		0xFBFE629344B40F6FULL,
		0x18AB356C227740F7ULL,
		0x1079389486534A5CULL,
		0x3C650AECA30F11C6ULL,
		0x51A160A5DB21C4E3ULL
	}};
	t = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FA6E340DE4598E7ULL,
		0x1CCC34A23F54A077ULL,
		0x4BE4AC5D1AA7A2E5ULL,
		0xE7727EF9A74E882EULL,
		0x13D5F6A544C9B846ULL,
		0xFC67A4866088EB31ULL,
		0x8B3CA421AD5ECB47ULL,
		0x0073D787CB9A444DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CD76BFC12EEE1EULL,
		0xF9C1103045910589ULL,
		0x0B45DF1BF830A001ULL,
		0xCF49869F7DE14F5FULL,
		0x27104F764FB0AD06ULL,
		0x60717A28AD823AAFULL,
		0x564F508440C205A2ULL,
		0xF5414F82A56782E2ULL
	}};
	t = -1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x399AB0B12B9CB2C8ULL,
		0x44BC6CE9FD5AC894ULL,
		0x578F042A833A5407ULL,
		0xB479DA67D66E1543ULL,
		0x98301D4A886D30A3ULL,
		0x4196FCD0DEEF37D9ULL,
		0x41902B63FE15F966ULL,
		0x57119CC6D25AE52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x399AB0B12B9CB2C8ULL,
		0x44BC6CE9FD5AC894ULL,
		0x578F042A833A5407ULL,
		0xB479DA67D66E1543ULL,
		0x98301D4A886D30A3ULL,
		0x4196FCD0DEEF37D9ULL,
		0x41902B63FE15F966ULL,
		0x57119CC6D25AE52CULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B7753381A612E81ULL,
		0x062FF0CD76333033ULL,
		0xC5390E619FEB4BD1ULL,
		0xE37B60D7148DD26DULL,
		0x7418BC515D74BE8CULL,
		0xA24A4F2EC91B94ADULL,
		0x36914E0159B29219ULL,
		0x4F7FB6008FB26BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC08F2DBAB87286DFULL,
		0x82AC20D0FF0F7DFBULL,
		0x1454CF19805BD4F5ULL,
		0x3FBABF1C92E8C9ACULL,
		0x752490E3328311D2ULL,
		0x20B37D0F29C60A70ULL,
		0xFBF67C5E99A4E6D9ULL,
		0x6627D2156A48C6D8ULL
	}};
	t = -1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B5B218310E8DD1ULL,
		0x1F26BD257F9B45A7ULL,
		0x60ADF4FE5B88ECC5ULL,
		0x40335573748104DCULL,
		0xF6B727D214466BD4ULL,
		0xDB350E08FBDCFB81ULL,
		0x0DAE7BD09E7A542FULL,
		0x954A0261C9699745ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763503D0C3AB026EULL,
		0x6024F7BBC5BA0B41ULL,
		0xD8134312A7113807ULL,
		0xBA53ADBF72E27707ULL,
		0x21330A827C81157AULL,
		0xF2B4C0F94E89D5B9ULL,
		0x8BCB1692ACD960FFULL,
		0x6AD3A982C899677CULL
	}};
	t = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x687A114B85D40014ULL,
		0x028A1AD7E32C91CFULL,
		0x37D9C40BA8FA36BDULL,
		0x827B5FF33779BB15ULL,
		0x4C732A0FB55E06D9ULL,
		0xC863BBDAD0A4B83FULL,
		0x22875919736EF3E6ULL,
		0x04CDEEF079856612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x848B3E90F144961FULL,
		0xE61CC11086D0207BULL,
		0xC8C9A450AC0809CFULL,
		0x80EEF41065A9FA14ULL,
		0x792F07F054BBA131ULL,
		0x78F2271EC787534CULL,
		0xDA4F11F51C130D70ULL,
		0x48CA2FA247E7F606ULL
	}};
	t = -1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6009760CE6E032DFULL,
		0xF83CEB72B09F2923ULL,
		0xC2DB40F924BDBB25ULL,
		0x15FBA1D1F20C2B80ULL,
		0x78E8484B8A3BBE63ULL,
		0x5F92CE067A04D73CULL,
		0x2F09F90C1893DE19ULL,
		0xFA1FE1344855A98AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6009760CE6E032DFULL,
		0xF83CEB72B09F2923ULL,
		0xC2DB40F924BDBB25ULL,
		0x15FBA1D1F20C2B80ULL,
		0x78E8484B8A3BBE63ULL,
		0x5F92CE067A04D73CULL,
		0x2F09F90C1893DE19ULL,
		0xFA1FE1344855A98AULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6010C9346672168ULL,
		0xE745F9207EA873ADULL,
		0x2865ED5AC5398FF5ULL,
		0xE087215A4DE4CDC4ULL,
		0x411E7F0197D229B1ULL,
		0xD70676AF9DDF2FF4ULL,
		0x2B9B23949ECE41E1ULL,
		0xD627CC335C161AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB8A5383BF6B1741ULL,
		0xC3D11BFDCB7D8B41ULL,
		0x0E034026D3513E88ULL,
		0x83C1B2277C2D2A78ULL,
		0xB43B32ABECBEBEDDULL,
		0x8523BA662528DB71ULL,
		0xAA7A3B07DEA445F8ULL,
		0x3713E1820E370FF7ULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA20EDC3522FD8817ULL,
		0xF8654838D738500BULL,
		0xEC93CDAE069E4B48ULL,
		0x85C7A2F5CE38A3D5ULL,
		0xBD42806A294D6DEFULL,
		0x1D6C2B02E272707FULL,
		0x9F12A530C532D5DFULL,
		0x9266A7BDDE3A9872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0E4D26D494D61A5ULL,
		0x1B36831B86D63141ULL,
		0xD809CC2EAB849409ULL,
		0xE6FF155292A96733ULL,
		0x6EA029CC3A19FF34ULL,
		0xD49404ED5ED7D7D3ULL,
		0xEE4F44085B2BD2D6ULL,
		0x57B6A0DB14DB4E9EULL
	}};
	t = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C9A25BB39117689ULL,
		0xDF7A70D51C244094ULL,
		0x68F13B87D1BE992CULL,
		0x80F98256E0628799ULL,
		0x065F0477341901D3ULL,
		0xEFB25C4CF79E37FBULL,
		0x92B392E7B3A4E107ULL,
		0x4B22164F5A5110FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA24EB10D15CCB4ULL,
		0x6C064833B947D911ULL,
		0xAD13A9FF17FADDA7ULL,
		0xE16E359831516A1DULL,
		0xD3F3FCB6605488E1ULL,
		0x5DC7D108189CA18FULL,
		0x65D736CF0F6B8FC6ULL,
		0xBC5F781FD6D40465ULL
	}};
	t = -1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA464E662E129537ULL,
		0xE9397B301D492373ULL,
		0xEEC874356C589805ULL,
		0x2BF33477F8BCF996ULL,
		0x0B6EA443C56F8D4CULL,
		0x2D58C3C09F9A973BULL,
		0x9C0C94BC09D3C4E2ULL,
		0x8FC06345D10FC5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA464E662E129537ULL,
		0xE9397B301D492373ULL,
		0xEEC874356C589805ULL,
		0x2BF33477F8BCF996ULL,
		0x0B6EA443C56F8D4CULL,
		0x2D58C3C09F9A973BULL,
		0x9C0C94BC09D3C4E2ULL,
		0x8FC06345D10FC5E7ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E04E81D361E637FULL,
		0xB740C02A9FB4B654ULL,
		0x7DFED9125E6A1A35ULL,
		0x450F20250865BF65ULL,
		0xA4994CDD1AD35F78ULL,
		0x75EBFFB4A4E67428ULL,
		0x995FDE3D9FDDFF80ULL,
		0x46FAA499A4CC3FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC415EF4E5690608ULL,
		0xE4B6B3863B0137D1ULL,
		0x4938ED1836748D4DULL,
		0xE566D1E5FA45B98DULL,
		0x4AC9B669FFB0DA25ULL,
		0xBB0076698317F44FULL,
		0x33ED08F9D73E9638ULL,
		0x18A6476B33CCE2F6ULL
	}};
	t = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CF0E3E12CF11D4CULL,
		0x3DECFED9E8873445ULL,
		0x3F51244E8CC54018ULL,
		0xD6355D366352A1FEULL,
		0xF39ED2C9C2794257ULL,
		0xBB7EF758794AF167ULL,
		0x43CD94AF34160CC1ULL,
		0xD7985A764A30C663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339FB125BB499D78ULL,
		0x5DB3771AB6A085DAULL,
		0x7C2435DE7CCAC2CAULL,
		0x58F3D25C92B5752DULL,
		0xB92BD872A00DD934ULL,
		0x070B2E609A17EB0FULL,
		0x4F1E95BF90448327ULL,
		0x32824047014F03D7ULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75858F92496C75E8ULL,
		0x4D774ADC1D0EB1A6ULL,
		0x40DB94C80D2D220DULL,
		0xF6CAF604F0983522ULL,
		0x9E51DD4282400B58ULL,
		0xEC0B9674388B1B8FULL,
		0x8D6948EFCA581D39ULL,
		0x95958DDAC8C0D354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31AF054567C3A221ULL,
		0xF0CDE576F12461EEULL,
		0x0A3B8DEEF1B42E84ULL,
		0xB1075FEDF1942FC3ULL,
		0x025919DEAD1D79EDULL,
		0x4E2A0A3B024C0E6BULL,
		0x0CA5537F0DF88CBBULL,
		0x46F62F42EB93CA30ULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x545739CCBB3FDF4DULL,
		0xAF35723679F935A3ULL,
		0xA486DC6D4A0A43B4ULL,
		0x5AB69308B0F87729ULL,
		0xC5402F7F6F7F2640ULL,
		0x8ECEC992037A3D63ULL,
		0x53382EBDB6FB78B5ULL,
		0x4A6392E987145EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545739CCBB3FDF4DULL,
		0xAF35723679F935A3ULL,
		0xA486DC6D4A0A43B4ULL,
		0x5AB69308B0F87729ULL,
		0xC5402F7F6F7F2640ULL,
		0x8ECEC992037A3D63ULL,
		0x53382EBDB6FB78B5ULL,
		0x4A6392E987145EBAULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA808F85ECE3E87AULL,
		0x1DF797094A302409ULL,
		0x883589C90A421C32ULL,
		0x732EB84D801D79C5ULL,
		0x1ECEB35BCFB119E4ULL,
		0xFB373DF65BCB1858ULL,
		0x48E469A5AFB342E8ULL,
		0x9BAC27DD7AA69F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x371C60263BF54BBCULL,
		0xD357650ACBD54AC4ULL,
		0x07BCC2C01798A19CULL,
		0x0190FCA9DE85EE9BULL,
		0xEAA1BC8E16645423ULL,
		0x63FEC78A4E71B2A6ULL,
		0x438DF805E3B946F7ULL,
		0xB2CCD44134813AF2ULL
	}};
	t = -1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CF62DF608DD1827ULL,
		0x2B2943E57038DDDFULL,
		0x40C6B3894409894FULL,
		0x0C32696494669E77ULL,
		0x9F31140FCE33C1F0ULL,
		0xD37B3870FA43DE17ULL,
		0xDF465FFC2D19C9CDULL,
		0x5ECB1637308366C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x761B5BCD94D4C0B7ULL,
		0x28F6ADE72D8BCBE8ULL,
		0x2DED69E93475A6CDULL,
		0xC925CAEA9DBD1298ULL,
		0xB279B8545719E787ULL,
		0xE9385DF36B584011ULL,
		0x7F7E24E1BCAA252EULL,
		0xC54665DA336425E9ULL
	}};
	t = -1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11E06A8E998F4F6BULL,
		0x8264A4A4FBC5690EULL,
		0x7335CD3050387C61ULL,
		0xE798CA388DFD7680ULL,
		0xFE3FFE1A58674B5BULL,
		0xA1F6B59725700206ULL,
		0x437853FE2E18CACBULL,
		0x5A08365A92E27345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51404B65ED36F7BCULL,
		0x78E964916EEAB11AULL,
		0xD0357F1D3E49DC79ULL,
		0x76212C2C065BFBF5ULL,
		0xA19650DBD22D983AULL,
		0xF7D492C324C25B4FULL,
		0xB9523A9E06792A02ULL,
		0xD32E510FD978B485ULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFC9D2067862DBEEULL,
		0x11FAF7BA6D812ECBULL,
		0xAAD8A4EDBA325013ULL,
		0xBFE58BC979AC5F8EULL,
		0x745FE76BE0739040ULL,
		0x2369EDC5F8E9C106ULL,
		0x80A7812595AC87F5ULL,
		0xF790ED9184ECBE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC9D2067862DBEEULL,
		0x11FAF7BA6D812ECBULL,
		0xAAD8A4EDBA325013ULL,
		0xBFE58BC979AC5F8EULL,
		0x745FE76BE0739040ULL,
		0x2369EDC5F8E9C106ULL,
		0x80A7812595AC87F5ULL,
		0xF790ED9184ECBE78ULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD912FE56EBF86DC3ULL,
		0x0894FEDBD53DC150ULL,
		0x530CFB192C6E5E80ULL,
		0x69F507EB8CA3DCBEULL,
		0x448F2844A8E689B0ULL,
		0xE8B4A920A7C30C0AULL,
		0x6399F88DC43E7057ULL,
		0x62A9FC3E04CC14C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x943CEAA05F53996FULL,
		0x6BFDAFACFF778536ULL,
		0x985CD081EC279B0FULL,
		0xB74663F4A1002144ULL,
		0x03364118760A718DULL,
		0x2306097EEB56A9CFULL,
		0x446FE8BEB2D4D767ULL,
		0xC3F479924A36674EULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA2B5B94583FDBD8ULL,
		0x49B1287609DCA80DULL,
		0x4F896FEFBD83DA22ULL,
		0x53C489023B136073ULL,
		0x7D8C06CA2C4747CCULL,
		0x3B5CD8DDCC13933EULL,
		0x36E41C8857D9E5D3ULL,
		0x551DB0D383EA26AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A70A9549B7D885ULL,
		0x6A3962794A4032EEULL,
		0xFE91BAF426D1A381ULL,
		0x60F7836EE1FDABE8ULL,
		0x452BCAEC3872B91DULL,
		0x8C99D0CDAEF3D01FULL,
		0xA87917732109BEB4ULL,
		0xF7C8E85DC55852A3ULL
	}};
	t = -1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD47A56FC7BC56948ULL,
		0x4784DBBCEF14821AULL,
		0x6BD473301994380EULL,
		0x444F4304D88D0E9AULL,
		0xF6A27BC09C761C5BULL,
		0xCA04C479B1720C56ULL,
		0xFAB10CC2D8C279F0ULL,
		0x60E21C183CB727CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D528E0B306D75CBULL,
		0x96D20A3ADC2A1B5FULL,
		0xDED7DB84D26EC9A8ULL,
		0xE657862EB84C8FC6ULL,
		0x661BA19D72929E1AULL,
		0x42EAF05BB2FF180DULL,
		0x856B30B6DB0158AEULL,
		0xAC4E0BCF9384138EULL
	}};
	t = -1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7CFBE2A0A715DFBULL,
		0x42551E482942A245ULL,
		0xF9E2FC6E7FD38442ULL,
		0x1F24A31B18F70EEFULL,
		0xEFC0297F235A3BDBULL,
		0x4C97E8AC6B10B8D7ULL,
		0x65E4409DD7D85B42ULL,
		0x7E4A252ADA1BBB95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CFBE2A0A715DFBULL,
		0x42551E482942A245ULL,
		0xF9E2FC6E7FD38442ULL,
		0x1F24A31B18F70EEFULL,
		0xEFC0297F235A3BDBULL,
		0x4C97E8AC6B10B8D7ULL,
		0x65E4409DD7D85B42ULL,
		0x7E4A252ADA1BBB95ULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D929DAAEAF3CD9FULL,
		0xE0BF15C783593190ULL,
		0xD033C6D643E77A34ULL,
		0x4C198C3BDEBFCF30ULL,
		0x551D8E69C90EBFAEULL,
		0x397265319E344AFDULL,
		0xC715AFE74BADDDF0ULL,
		0x7ADD2D3C03EF8C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CCE2344C364013ULL,
		0xA27399CDC4C354C3ULL,
		0xE9FC0B0BBCCD5F1BULL,
		0xEEEDB6490FB5AE01ULL,
		0xB1B1F3E99961F435ULL,
		0x9E0775110C0BA3CAULL,
		0x3691E02C83CF51EDULL,
		0xBB5149DBDD412FB4ULL
	}};
	t = -1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F620A3F897BA30EULL,
		0x3067BD30191A4994ULL,
		0x7A433170813CB1B2ULL,
		0xDAA91A21ACB50645ULL,
		0x4142572BC0C28463ULL,
		0x3031A4EAB06A61A7ULL,
		0xFA68CBED97CDB31FULL,
		0x1BEAAF4794E5F981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C89AC4B44DCB90ULL,
		0xBCA1ED5896DA3514ULL,
		0x8A8996EE30B3EAA7ULL,
		0xB18A5E87A1C84166ULL,
		0xD2F9581FB54D4B43ULL,
		0x7EAA7C8C415D40DBULL,
		0x4E4EC11528E66312ULL,
		0xAFB044D707E809EDULL
	}};
	t = -1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DE605CCCEE1C42BULL,
		0xE2E0EA7414E8CC3CULL,
		0x67B58CDFB0145B26ULL,
		0xF6DF669A25BD4281ULL,
		0xF8E20142F8FA7CB1ULL,
		0x286C008C2CCDCC6CULL,
		0xCCCD29453F4D0E95ULL,
		0xAD19C2D871688D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DADF08D83B67D52ULL,
		0x85FF4485D5E682D2ULL,
		0x305E6FCB465EA669ULL,
		0x0F3F105346658CFDULL,
		0xCCECAB34794AF059ULL,
		0xD7E0CAE694B66F27ULL,
		0xD3BAD724810420B1ULL,
		0x27180262087471E3ULL
	}};
	t = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4DB2B054E52DAFFULL,
		0x1B1E8EA83288C147ULL,
		0xCA9AEA5361665497ULL,
		0x44C2531DF4687834ULL,
		0x6D0D96C6F49F78DBULL,
		0x46268F66261C3F95ULL,
		0xB1EBD5B8CFA26F4DULL,
		0xA3874BBE27DB9814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4DB2B054E52DAFFULL,
		0x1B1E8EA83288C147ULL,
		0xCA9AEA5361665497ULL,
		0x44C2531DF4687834ULL,
		0x6D0D96C6F49F78DBULL,
		0x46268F66261C3F95ULL,
		0xB1EBD5B8CFA26F4DULL,
		0xA3874BBE27DB9814ULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE4836574028A55FULL,
		0x2F98561FE49150C6ULL,
		0x2809934891545051ULL,
		0x0E971DD7BE831C58ULL,
		0x867CDFBC58A879FCULL,
		0x6C8E8FDFCB21FE65ULL,
		0xF859D1D8B582AD0CULL,
		0x86BF39DE8FB9C70EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A4F776194B9B68DULL,
		0x799C3D71E4270FCDULL,
		0x1CB78EF7C0B935DEULL,
		0x4C5A67FD4D43CB65ULL,
		0xCF369CEBDCDEA97AULL,
		0x5037D58505C06D06ULL,
		0xF379ED8368A068BDULL,
		0xF0C24EBDCC9C1D17ULL
	}};
	t = -1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x098654EEF1A9B064ULL,
		0x3B1D1E0A7F112849ULL,
		0x037C5C8C9CDA658BULL,
		0x124B7BE97558583DULL,
		0xC28824E11C856ED6ULL,
		0xA45EF55FE2AAD710ULL,
		0xB52215DF3A7BB3FBULL,
		0xB8E619968E32C26FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54985B4ACAC4C798ULL,
		0x3E405021EC9F7C42ULL,
		0x87911231FAD1BEBFULL,
		0x2BDAB1A67D112CB7ULL,
		0xF89B4AB430481AD3ULL,
		0xC00BADCBC5B9004CULL,
		0x3E40755F1625833EULL,
		0x8F0A235D7392FF86ULL
	}};
	t = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52085D049F29ED23ULL,
		0xDD611FEC69915FA1ULL,
		0xD5FE79094E34AA0EULL,
		0x56D8194D7693B2E3ULL,
		0xAC26D21C00B0E660ULL,
		0xCEE3C2182C0F6F81ULL,
		0xEFB35DD1EDBF0141ULL,
		0x89632F9B3BCBE186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x584BE0C8A0226DA4ULL,
		0x87CADD3DC8274506ULL,
		0xB14817C823DCA70BULL,
		0xF1CBC8642BFF7DE4ULL,
		0x85758D5F8633A7D1ULL,
		0xBB0AE100CD3F1238ULL,
		0x27EBD769C021A5ACULL,
		0xED88C306E8F8AFEAULL
	}};
	t = -1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA31A670411894AAULL,
		0x47E00DF1ABA4C656ULL,
		0xB7DECBBAE49294D5ULL,
		0xB19854E1E73D49ADULL,
		0xC3D7029858C4C978ULL,
		0x6077CEC283D96DE3ULL,
		0xE9D759CE7AE42589ULL,
		0x4235AABAC78B5021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA31A670411894AAULL,
		0x47E00DF1ABA4C656ULL,
		0xB7DECBBAE49294D5ULL,
		0xB19854E1E73D49ADULL,
		0xC3D7029858C4C978ULL,
		0x6077CEC283D96DE3ULL,
		0xE9D759CE7AE42589ULL,
		0x4235AABAC78B5021ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DD7FB59FA901ADEULL,
		0x5D5DE26FE457C6C6ULL,
		0x6C820735B21ECE02ULL,
		0x9FFC94A6E1CC054DULL,
		0xD56107BCE4F40539ULL,
		0x5898AE4EBD8CF2B5ULL,
		0xD938F8F8B16B3CE9ULL,
		0xE52EEDD6C5B2E9ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B2A3EF1D924074ULL,
		0x9C27185E7A54A779ULL,
		0xDF9133537C89AC10ULL,
		0x3A28946CA45286B0ULL,
		0x885D8490102A1B98ULL,
		0x6860D8A31CE658DFULL,
		0xA914097ED1A55AAFULL,
		0x9E12FFFA3C483FFCULL
	}};
	t = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27419C37A3535433ULL,
		0x369D3D8191BCE6EFULL,
		0x0005D48E1B04D596ULL,
		0xA7E01EC97EBEE21AULL,
		0x8974EFF6669C7B89ULL,
		0x372A84174CA8B756ULL,
		0x0FDB246B11C96434ULL,
		0x5A10BD928441C17DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC6EF8F9AD43E49FULL,
		0x266995067D181A58ULL,
		0xF4361A6D2215249CULL,
		0x19D30127F7CA851AULL,
		0xA989749090AE5A55ULL,
		0xF4058D1D644A54FCULL,
		0xAC709DED75677DCCULL,
		0xD36BBD82FEF2CC74ULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE0AFA265039EF9AULL,
		0x3095DFD349CA517DULL,
		0x3E18A85E6D020D78ULL,
		0x97CF309A3B7385FBULL,
		0x81B03C79CEDAA505ULL,
		0x8A8BCCA22543CB65ULL,
		0x202D19CFB12E92A1ULL,
		0x62651FD4929444CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D33179AE0924EB2ULL,
		0x12CC2FA9AED8D2B9ULL,
		0x759AAEE4858F7372ULL,
		0x4DBF4AF012630952ULL,
		0x5A6FAF8589576B6CULL,
		0xBA08BD49B403DD68ULL,
		0x12910F2F90ABB880ULL,
		0x016A11F79BA460BEULL
	}};
	t = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3088F2C035B70E38ULL,
		0xEAFD5B842976125FULL,
		0x8C4BC9B7BE4EEE83ULL,
		0x95F460C0A14DADCFULL,
		0x1ECBA51B9140CFFEULL,
		0x8C0B9D84EF8A771DULL,
		0x88524F65E8F4189CULL,
		0x5852B6617EAC9338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3088F2C035B70E38ULL,
		0xEAFD5B842976125FULL,
		0x8C4BC9B7BE4EEE83ULL,
		0x95F460C0A14DADCFULL,
		0x1ECBA51B9140CFFEULL,
		0x8C0B9D84EF8A771DULL,
		0x88524F65E8F4189CULL,
		0x5852B6617EAC9338ULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99EF4D5A36526730ULL,
		0xBD09EDF19F0B7D29ULL,
		0x1DBA45B780AEABBAULL,
		0x218C0E83C7599B74ULL,
		0x5593195BF04DAAD3ULL,
		0x7757EF6EB58C95ABULL,
		0xB209F918A30DF173ULL,
		0x281B3E6BD3E97D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA32E3C7BEB3009EULL,
		0x64FB1171DD39CDB6ULL,
		0xD3477783D86745A9ULL,
		0x0E7D67AA5054B3D9ULL,
		0x667E0EA63E69F56EULL,
		0x2594FE21BC0BEECCULL,
		0x649451FDE22C8406ULL,
		0xE507ADB7F750B4D6ULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1800F0EE601A2465ULL,
		0x199AB82EFDA5189BULL,
		0x562A9774199ADA29ULL,
		0x0B07A76B4F361AA1ULL,
		0x5E448475C19A86F5ULL,
		0xE3F10FFB09717039ULL,
		0x8DBB1F742E56A29FULL,
		0xA07D33FC40271E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CBDDB008B3BBA3ULL,
		0x187D4E44586C7486ULL,
		0x083357754FC45095ULL,
		0x653D489269DC3F9EULL,
		0x030126F66FC285E0ULL,
		0x148947D0367D1AB5ULL,
		0x056C83DBBA463E4AULL,
		0x00B33AF9F9A5008EULL
	}};
	t = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x688827EF96DB6CB6ULL,
		0x8146E73B8F866E10ULL,
		0x4FD3C4CBEC3C388DULL,
		0x500AE79E1515F3B4ULL,
		0x2600AF12423F3F8AULL,
		0x8C84833082BD7EFBULL,
		0xAE0AA0D951AE9B3FULL,
		0x4EFC4D7BAB8BF76FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC829DCF2FD12FA82ULL,
		0xB4070CB1A447852BULL,
		0xEC4DCD1A93C3D321ULL,
		0xF10D4B40D72DE4ACULL,
		0x2600DC2B06D830ACULL,
		0xAC900F3A559C4688ULL,
		0x86CFABFA7A89BEAFULL,
		0xFA101ACFD849A01DULL
	}};
	t = -1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FDED1B69CD85C40ULL,
		0x87C6DDA5E223AFEAULL,
		0x91C207D79C72B3B2ULL,
		0x7EE56846763D1CDAULL,
		0x16474448DB0DD707ULL,
		0xCEA9589456DC72DEULL,
		0xB3B405F3926E9FA0ULL,
		0x3ACAABE96FAEDB53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDED1B69CD85C40ULL,
		0x87C6DDA5E223AFEAULL,
		0x91C207D79C72B3B2ULL,
		0x7EE56846763D1CDAULL,
		0x16474448DB0DD707ULL,
		0xCEA9589456DC72DEULL,
		0xB3B405F3926E9FA0ULL,
		0x3ACAABE96FAEDB53ULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0639F4D57CC6C754ULL,
		0xDCA99A4E9C985131ULL,
		0x9EA875E1342AC626ULL,
		0x7EC2DB20952ACE77ULL,
		0xC16E15AAAE238AADULL,
		0x7527A347068E7B8DULL,
		0x8A4BECCFD1D04C4DULL,
		0x6B961CC187042022ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C18C20688E19F8ULL,
		0x857244B2CC19D4D4ULL,
		0x93F94E3257A9594EULL,
		0xAF81B4D761CD96D6ULL,
		0x5C2F737E4345A66CULL,
		0xF1639374BE92963BULL,
		0x03AC8F6441E72A53ULL,
		0xDA368B6C5D09C5DDULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7008373CB8BB9528ULL,
		0xE4F1EFBB1997FBCFULL,
		0x60EE0276FF6E68D7ULL,
		0x0F8B2E1A468FAE75ULL,
		0x15D83B407F463C5AULL,
		0x309CA926F2D388E8ULL,
		0x0B4D7915190828E8ULL,
		0x4C678F26FCA12776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AC6B6BFFEF8670BULL,
		0x2D0A5A211A805183ULL,
		0x2127B41308E2734CULL,
		0xB97F306D732EBB1AULL,
		0x2D85C367D553BDE2ULL,
		0x660BD212D42EFEA1ULL,
		0x7CA243B166762034ULL,
		0x442490026666550BULL
	}};
	t = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x742E78369858C9BBULL,
		0xA3209436986794BAULL,
		0xA640BF58E25266C9ULL,
		0x4CB998DB49155116ULL,
		0xA1C1C8C2DCC63B1CULL,
		0xA5213862467E03EDULL,
		0xACC90A67BA9DBF37ULL,
		0x46EC58E9F087BCDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13D24F79889EC633ULL,
		0xDBFEC92AA50CE074ULL,
		0xFAB1CD6AFFF1502AULL,
		0x7BC76F36371599C8ULL,
		0x1D9412D32E1167BCULL,
		0xEAB43D9621023C28ULL,
		0xC4EB683C3A2661D2ULL,
		0xFA101F1F0C989BE0ULL
	}};
	t = -1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x549350B6A61380F9ULL,
		0x0EFB88AA69F6C0E4ULL,
		0xC72EE7F58978EFB1ULL,
		0xFBFC87B022C8A223ULL,
		0x91CF3C4EE03D2A03ULL,
		0x6ED1620D8ED0DE3EULL,
		0x655606ABBB092B23ULL,
		0xF0EAECB84A0DE98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x549350B6A61380F9ULL,
		0x0EFB88AA69F6C0E4ULL,
		0xC72EE7F58978EFB1ULL,
		0xFBFC87B022C8A223ULL,
		0x91CF3C4EE03D2A03ULL,
		0x6ED1620D8ED0DE3EULL,
		0x655606ABBB092B23ULL,
		0xF0EAECB84A0DE98BULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B52A4A64C34B49FULL,
		0x8AFB7B80C482093EULL,
		0x4D649B5D636C7EC6ULL,
		0xDC033B39FA25EFF1ULL,
		0x2034344C9376DDE8ULL,
		0xD03FAADABB37D366ULL,
		0x507D06416D061E61ULL,
		0x68D0F2DF1318E186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254C54568BE149D1ULL,
		0xB020803900FEAB08ULL,
		0x13A37D8822C7FE0AULL,
		0x7F59325B91D42FE2ULL,
		0x875E6FA0015E0A53ULL,
		0xAE3D47E9EE7687B3ULL,
		0x159E0558DE5016D9ULL,
		0xC5AF0778B3FB7792ULL
	}};
	t = -1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB030323A147A54CCULL,
		0x875A9B5346DFD65AULL,
		0x767D21E4ECE5CDD2ULL,
		0x85194085DF3AD096ULL,
		0xE19247D33B9567CAULL,
		0x4711B7DD9386AF6EULL,
		0x2A81A076D0E6DA68ULL,
		0xB015C911A31AD38AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0684F92F97C375F8ULL,
		0xE2CF7B6D248D0F81ULL,
		0x5BFA66B39C974FC4ULL,
		0x06D003AB927414B2ULL,
		0xE92E7D43E2FA8D8AULL,
		0x98A0135821547FDDULL,
		0x43347FCA9829631AULL,
		0xA2323ED7165BB0C7ULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64ED496895C7EA02ULL,
		0xDC512C638E03C9B6ULL,
		0xE1581D3164A1EE10ULL,
		0x1682C1A41E54F5AEULL,
		0x840A2FA7782A20E5ULL,
		0xF033291653070D65ULL,
		0xD17A543745054ACDULL,
		0x0C6C7198EE57CAC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6493CDD7D7A7E97EULL,
		0xA9BE2CA3847CC967ULL,
		0x63087EB0A8F02DFFULL,
		0xCD1526737ED43113ULL,
		0xCB2D6EAD9255239BULL,
		0xB7D49B5C079852B2ULL,
		0x70887CA5EB08ADE8ULL,
		0x25327B4B1FBD99CCULL
	}};
	t = -1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD226F91BF844ADEEULL,
		0xD5AAD8FAAAF38B6DULL,
		0x1E7BD0F95530F5F0ULL,
		0x1E9A0969B6600E86ULL,
		0x7CD9ABCC603AF05AULL,
		0x5625FA02FBC403F1ULL,
		0x07D9A750ECDF0C6CULL,
		0x7DFBA445FEAA20FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD226F91BF844ADEEULL,
		0xD5AAD8FAAAF38B6DULL,
		0x1E7BD0F95530F5F0ULL,
		0x1E9A0969B6600E86ULL,
		0x7CD9ABCC603AF05AULL,
		0x5625FA02FBC403F1ULL,
		0x07D9A750ECDF0C6CULL,
		0x7DFBA445FEAA20FEULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x463CBC3B956F64ADULL,
		0xDC4CA7A40FB5EA07ULL,
		0x8606C8388585BA32ULL,
		0xF22DC0A82FBB2A95ULL,
		0x053895239301F5D7ULL,
		0xC32B2F4B39877614ULL,
		0xA404530C4741B208ULL,
		0x9D281B2EEDD3733AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3800CCD88D7F721EULL,
		0x5DBFB68D0DC00669ULL,
		0xCD6C3E0DDBA14546ULL,
		0x58405B167E7658CAULL,
		0xACB597A1F2AC6F59ULL,
		0x454AEB5FE6EA59ACULL,
		0xF5EFDEE0946421DDULL,
		0x6B3431B0280646CFULL
	}};
	t = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x573756E4F0628BFEULL,
		0x3048037A2C32E99FULL,
		0x908353BA03C3A967ULL,
		0xCCC1A304C563840EULL,
		0x458182226E76C6D5ULL,
		0x4291D212AAA9EAB2ULL,
		0x4D472812E892F631ULL,
		0x878C980E77490977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7E4840A2A64CBFULL,
		0xEB59178A1FFC22BEULL,
		0xFFBE50BBB7FA5DC8ULL,
		0xEE903654FEF4DAD5ULL,
		0xD065E79CD005DE0DULL,
		0xED9A16802436E81AULL,
		0x5F50890689577CF4ULL,
		0x7709EC06C3EFE1E1ULL
	}};
	t = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CD58CFDFB02A82BULL,
		0x4E5D12FDAD266575ULL,
		0x4964FF4F4368944EULL,
		0xEF47C215587C236BULL,
		0xA48D600279C9F7B8ULL,
		0x7932F7C09EDDC381ULL,
		0x08AB53ED0211E12FULL,
		0x016A18D5A571C0F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x404BA4BF846705B0ULL,
		0x375D9EC5933D9F9BULL,
		0x8A864D0728E0E447ULL,
		0x49362DA08DBD6ED5ULL,
		0xDD1D55C9D54EA0BCULL,
		0xB9B7C2F0BD2D2F5EULL,
		0x27A5F07CA9E42B38ULL,
		0x3C0BA4DC46A5E6AAULL
	}};
	t = -1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}