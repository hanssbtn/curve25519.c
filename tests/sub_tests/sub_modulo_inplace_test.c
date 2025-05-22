#include "../tests.h"

int32_t curve25519_key_sub_modulo_inplace_test(void) {
	printf("Inplace Modular Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x2F5438CFD2386BACULL,
		0xF55BAB249C770AF6ULL,
		0xA68396EE9EA3F296ULL,
		0x081A82F75C6BC002ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x922A5383C2A0F1F7ULL,
		0x6019A184A99D0CC1ULL,
		0xE0FE1B4555B661D8ULL,
		0x423A2F8FE04048F2ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x9D29E54C0F9779A2ULL,
		0x9542099FF2D9FE34ULL,
		0xC5857BA948ED90BEULL,
		0x45E053677C2B770FULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
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
		0x34C086208A5E0710ULL,
		0xC9511BE78C26C613ULL,
		0x515CD6FD3095C05CULL,
		0x165BB76F5FE2B109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF526FCA57AB3B64ULL,
		0xEDD81DFCB579022BULL,
		0x9407B0442B3B3292ULL,
		0x22060BA6B6466EBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x756E165632B2CB99ULL,
		0xDB78FDEAD6ADC3E7ULL,
		0xBD5526B9055A8DC9ULL,
		0x7455ABC8A99C424CULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x140D4AED045C1B21ULL,
		0x442097E32DED4D50ULL,
		0x9D037FCA50EF275AULL,
		0x468A9DDE4F01B9EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E58F0037CF6594ULL,
		0x153B1A4B76CBDAF8ULL,
		0x606DEA9392AD631DULL,
		0x13FD7F88E05E4CD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4227BBECCC8CB58DULL,
		0x2EE57D97B7217257ULL,
		0x3C959536BE41C43DULL,
		0x328D1E556EA36D11ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6F6704B602736580ULL,
		0x17AF43CF1BF9117AULL,
		0xAE17B0B165C09810ULL,
		0x62A2C802C585B754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D10E9DEF6DCF88ULL,
		0x5C827C7D0480F15BULL,
		0x356C9E0B011F3FE3ULL,
		0x50EA5EB460134E06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE95F618130595F8ULL,
		0xBB2CC7521778201EULL,
		0x78AB12A664A1582CULL,
		0x11B8694E6572694EULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x06ACEB9D1DDE1134ULL,
		0x514886851F2C33BCULL,
		0xF55E76D246ADB57FULL,
		0x19D038B4F0FDFC2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D5C554B7CBEEC0ULL,
		0xFFB7A94D31D68375ULL,
		0x2FBC6741309E0B8FULL,
		0x36B0C37DF183A476ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D7264866122261ULL,
		0x5190DD37ED55B046ULL,
		0xC5A20F91160FA9EFULL,
		0x631F7536FF7A57B5ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x12DEBA405BFC3E6BULL,
		0x27C53EA3C57CA494ULL,
		0x798DDFE2A24F1EA8ULL,
		0x3E2187775550E024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F8B78664B59C80ULL,
		0x685414E887C10410ULL,
		0x63E6E7EC1D59A545ULL,
		0x536F551B736485F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DE602B9F746A1D8ULL,
		0xBF7129BB3DBBA084ULL,
		0x15A6F7F684F57962ULL,
		0x6AB2325BE1EC5A33ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x912D94C3A7969889ULL,
		0x617C3C5AA0353CDCULL,
		0x29A95DE6E36C775AULL,
		0x4125508D6F138FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94946E7067C02373ULL,
		0xE10CA734C0669A27ULL,
		0x3729773B5915E8B3ULL,
		0x22EAB28BF898056AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC9926533FD67516ULL,
		0x806F9525DFCEA2B4ULL,
		0xF27FE6AB8A568EA6ULL,
		0x1E3A9E01767B8A63ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x682DAC7A30C0FDA4ULL,
		0x45041EB7175EFF45ULL,
		0xADD82CCC03C62490ULL,
		0x35B9C62FA880AB1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731CD9C854B539F2ULL,
		0x0F6A53FD240A31C8ULL,
		0xF13739B3FE039BACULL,
		0x2CD99C6910EFAE0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF510D2B1DC0BC3B2ULL,
		0x3599CAB9F354CD7CULL,
		0xBCA0F31805C288E4ULL,
		0x08E029C69790FD0FULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x945264285C921F75ULL,
		0x8DA951986A0538B4ULL,
		0xCC857A961CA335DEULL,
		0x35DB215ADFED3A1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1729CB8B1E51D35DULL,
		0x83295BE5E3791C02ULL,
		0x2B6A987FFF147C2EULL,
		0x4311A5638E0D5C76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D28989D3E404C05ULL,
		0x0A7FF5B2868C1CB2ULL,
		0xA11AE2161D8EB9B0ULL,
		0x72C97BF751DFDDA8ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6305355954833D89ULL,
		0xA1FAB263D75C10D3ULL,
		0x612C3E0844310281ULL,
		0x5F02A24654138722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574CE239681C6AE2ULL,
		0x909AC76BB7D503CEULL,
		0x89BA34E1C8036501ULL,
		0x4CEA9B7F85550425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BB8531FEC66D2A7ULL,
		0x115FEAF81F870D05ULL,
		0xD77209267C2D9D80ULL,
		0x121806C6CEBE82FCULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB940868646E894D4ULL,
		0x71F41CBE438A6AC7ULL,
		0x3866FD476B74125CULL,
		0x5AEA14BDDAA7E889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EED46D725439E78ULL,
		0xBF4285E258808EE6ULL,
		0xAB78A14E58C42411ULL,
		0x6428A769044A34FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A533FAF21A4F649ULL,
		0xB2B196DBEB09DBE1ULL,
		0x8CEE5BF912AFEE4AULL,
		0x76C16D54D65DB38EULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCCDBE91F1A98E5BCULL,
		0x8D0BE96336948638ULL,
		0x07E360CB7D54B767ULL,
		0x1633BD400BF5E587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFDC7CF57D826C8AULL,
		0xFFEB67F10E0A837AULL,
		0xD00813A50193B8F1ULL,
		0x3F9CF010456C3D2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECFF6C299D16791FULL,
		0x8D208172288A02BDULL,
		0x37DB4D267BC0FE75ULL,
		0x5696CD2FC689A85AULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x466FF65687FC4FF8ULL,
		0x9032960D05F96DFCULL,
		0xDFB4C6121C5DE93FULL,
		0x02C0DDDD14A9E3DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB797519C64E4B988ULL,
		0xDB44948D4C69AC80ULL,
		0x38124B54C298B1EAULL,
		0x73A72E389BFBC362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED8A4BA2317965DULL,
		0xB4EE017FB98FC17BULL,
		0xA7A27ABD59C53754ULL,
		0x0F19AFA478AE2078ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE9F9D99BEF38EAE4ULL,
		0x4C084575508D3DDCULL,
		0xBD48529AA40E75C0ULL,
		0x52AD3255CFF13675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87834CF967EBE0FCULL,
		0x4D07949FD8CA77A2ULL,
		0xDF4C75968779C959ULL,
		0x026AF0A64D843F7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62768CA2874D09E8ULL,
		0xFF00B0D577C2C63AULL,
		0xDDFBDD041C94AC66ULL,
		0x504241AF826CF6F7ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1EB9C54E3558A3A7ULL,
		0xB8076B69163E5AF1ULL,
		0x6B0C043E47DE1997ULL,
		0x7B9DC2B1B7EABA98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EBD41C2FA55493DULL,
		0x8D5D67186F9A1DC7ULL,
		0x585236B79CF542E6ULL,
		0x5A7D98DE811946B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFFC838B3B035A6AULL,
		0x2AAA0450A6A43D29ULL,
		0x12B9CD86AAE8D6B1ULL,
		0x212029D336D173E2ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x084D0A84AC6CA8B6ULL,
		0xEBDBC4BBAA53E27CULL,
		0xEAB10646BA9310E1ULL,
		0x46BC98801CC3E5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD5431821911125ULL,
		0xD1671FD51AA468E3ULL,
		0xADE7E5337A8B2570ULL,
		0x2245BFE5B4F900B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD77C76C8ADB9791ULL,
		0x1A74A4E68FAF7998ULL,
		0x3CC921134007EB71ULL,
		0x2476D89A67CAE4FDULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x49339779E9B5C3ACULL,
		0x13AE862B5D0970F0ULL,
		0x5C64AC0F872A40A6ULL,
		0x1259451C8AA69125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92A35020DD7426CULL,
		0x0ED49BF90FA62A65ULL,
		0x2B03779838AE5A57ULL,
		0x0B99D9FAF0AFBACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90096277DBDE8140ULL,
		0x04D9EA324D63468AULL,
		0x316134774E7BE64FULL,
		0x06BF6B2199F6D659ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x93F9F70FC82E2629ULL,
		0x76996E6C637AA588ULL,
		0x87270E4B54DDA2C1ULL,
		0x1CEC0A35E966EAB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC545D7C81C36CA5AULL,
		0x9BF5EDBA8101A464ULL,
		0xEDE1614BB48CAF44ULL,
		0x0D5DDA648B4FF22FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEB41F47ABF75BCFULL,
		0xDAA380B1E2790123ULL,
		0x9945ACFFA050F37CULL,
		0x0F8E2FD15E16F881ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB7C291BE0489E3C1ULL,
		0x6B2636C832CBC091ULL,
		0x239A82BAB6354225ULL,
		0x0D90E2EBC41BA9D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0B8183BA8734E0ULL,
		0xF6F15DB98E9061CDULL,
		0x176D632C68224C27ULL,
		0x7A0504CFFFC30A88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AB7103A4A02AECEULL,
		0x7434D90EA43B5EC4ULL,
		0x0C2D1F8E4E12F5FDULL,
		0x138BDE1BC4589F51ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA7F4D546BD3CDFD0ULL,
		0x86941359969DABCFULL,
		0x2B59D9AB43F55034ULL,
		0x7F60F9C046CC70F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0C1C315042527BULL,
		0x8BD17D2F10C816DEULL,
		0xC7BE62FB82A37A73ULL,
		0x30D8F7D97D2F4A12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE8B9156CFA8D55ULL,
		0xFAC2962A85D594F1ULL,
		0x639B76AFC151D5C0ULL,
		0x4E8801E6C99D26E2ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4AC27F08C647AE3DULL,
		0xF9898A6F3507BFBDULL,
		0x1D993CBC8DB2CDD8ULL,
		0x36DCECEA4DD6E980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D27ECA9BDAEB770ULL,
		0x758BA8A952D0213AULL,
		0x4B40B1EB456C9B82ULL,
		0x6FB141524380ADEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD9A925F0898F6BAULL,
		0x83FDE1C5E2379E82ULL,
		0xD2588AD148463256ULL,
		0x472BAB980A563B95ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCD1AA102D0175646ULL,
		0x64203C9F7A1408AFULL,
		0x1C0E5DA7A693B240ULL,
		0x78B4CE410EEC8540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763E2081DC28F59EULL,
		0x7AC55E88F397F243ULL,
		0xB98CC45FA65A892EULL,
		0x7BD7DDE2B8E6C103ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56DC8080F3EE6095ULL,
		0xE95ADE16867C166CULL,
		0x6281994800392911ULL,
		0x7CDCF05E5605C43CULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE62470B3E2D13F59ULL,
		0x077161B2D9609E11ULL,
		0xCA6B5625C1AFBF00ULL,
		0x232FFAFB2E40C0CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5769085714E28D3DULL,
		0x2567EF0B2EF5AE69ULL,
		0x044D1A98527E8792ULL,
		0x34B65A3D14592068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EBB685CCDEEB209ULL,
		0xE20972A7AA6AEFA8ULL,
		0xC61E3B8D6F31376DULL,
		0x6E79A0BE19E7A066ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCD9563191C411FB0ULL,
		0xC8547A849F5BEC06ULL,
		0x24CC5A5EAFD0FB23ULL,
		0x15EB5882001E8670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6701B4F51C9CA2EFULL,
		0xDF6B56FB9445B3FBULL,
		0x1F2C78CF078B0BD5ULL,
		0x30B76AC553082E8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6693AE23FFA47CAEULL,
		0xE8E923890B16380BULL,
		0x059FE18FA845EF4DULL,
		0x6533EDBCAD1657E4ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFF0482B8E58AB449ULL,
		0x75FD47C3B1091867ULL,
		0x75A9B64EA77FE571ULL,
		0x0535106445B6E417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5816B45E5444CD95ULL,
		0x693025DC22CED44BULL,
		0x6733C20265146978ULL,
		0x102FD77CB2FE53FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6EDCE5A9145E6A1ULL,
		0x0CCD21E78E3A441CULL,
		0x0E75F44C426B7BF9ULL,
		0x750538E792B89019ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x645A9F8E10C84307ULL,
		0xB91299F858D943B1ULL,
		0xCF2904641EC7E3FEULL,
		0x1584144963E11697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x276AD218989EEC24ULL,
		0x548B12876E095C42ULL,
		0x6363F779F8396063ULL,
		0x14B88B34103D9D12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CEFCD75782956E3ULL,
		0x64878770EACFE76FULL,
		0x6BC50CEA268E839BULL,
		0x00CB891553A37985ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB67400D95CCEEA5EULL,
		0x3B3221A414B4DCDDULL,
		0x9B8FA013C3252433ULL,
		0x4B4764D8D18A23F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x551C14292E21579AULL,
		0xA4CE522913A1785BULL,
		0xE88E7DFE94A7A1DEULL,
		0x490393D6D171B6C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6157ECB02EAD92C4ULL,
		0x9663CF7B01136482ULL,
		0xB30122152E7D8254ULL,
		0x0243D10200186D28ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD3AC9C87DB109570ULL,
		0xE2918230022707B9ULL,
		0x461888A63B4C0682ULL,
		0x69FFDDCD329D50C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63588CA8624E0FA6ULL,
		0x98FB7930B01CB054ULL,
		0x70D08CE30B5FE0EDULL,
		0x21E3194D505AEC5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70540FDF78C285CAULL,
		0x499608FF520A5765ULL,
		0xD547FBC32FEC2595ULL,
		0x481CC47FE2426466ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x43679F30E6825EDDULL,
		0xD162A6D150568380ULL,
		0x53E3387F1BA1A355ULL,
		0x6D8754AFFB1AB842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD401F41B63240F4ULL,
		0xCEC1A494B4C6F367ULL,
		0xFE73C2C4428BFE4AULL,
		0x445FCD74CB9990CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86277FEF30501DE9ULL,
		0x02A1023C9B8F9018ULL,
		0x556F75BAD915A50BULL,
		0x2927873B2F812772ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4E14AB654E1723CBULL,
		0xCC00EE4810EF34F0ULL,
		0x04CEFAEFC2B36481ULL,
		0x6E425549F73B9870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515018F7670FA2C9ULL,
		0x8849269789DBA3C0ULL,
		0x853049FD0392A10AULL,
		0x166F7B236452AC68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCC4926DE7078102ULL,
		0x43B7C7B08713912FULL,
		0x7F9EB0F2BF20C377ULL,
		0x57D2DA2692E8EC07ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x15C524B663FC0AA9ULL,
		0x764CC76946C00A1AULL,
		0x3010B3BC4A1ABEEDULL,
		0x4F01C9D6FC9B3E61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE78B0DC6156D1ECULL,
		0xBFCB8794B7D5360BULL,
		0xB4DDEA349EB3720FULL,
		0x29C46D23A60A75D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x174C73DA02A538BDULL,
		0xB6813FD48EEAD40EULL,
		0x7B32C987AB674CDDULL,
		0x253D5CB35690C890ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x40389D8BFA4F71F1ULL,
		0x5ACC4E02E8B91CC6ULL,
		0x143F46C7FA0407FDULL,
		0x4208C6AF6D43A346ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F764BF7CA395ACULL,
		0x074314C779446B14ULL,
		0xDA38315C87E16342ULL,
		0x734EC7FC09443518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C4138CC7DABDC32ULL,
		0x5389393B6F74B1B2ULL,
		0x3A07156B7222A4BBULL,
		0x4EB9FEB363FF6E2DULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF0D3144E057F4362ULL,
		0x562134545CC9E13EULL,
		0x0FB27C5ABB71570DULL,
		0x0ECBCBEBC7147393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F7628C7F9B877FULL,
		0x6B13766263349BD3ULL,
		0xFE31B86B8597FC28ULL,
		0x77826E251FA57B6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCADBB1C185E3BBD0ULL,
		0xEB0DBDF1F995456BULL,
		0x1180C3EF35D95AE4ULL,
		0x17495DC6A76EF825ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x93CF4FFDC3461B41ULL,
		0xFBE277B03704FC13ULL,
		0xB39FE5FD0AE26BE9ULL,
		0x6B05E09E2E460EBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECB352FE92880CABULL,
		0x000DC27E682BE3D1ULL,
		0xF913A7C6EDB55A74ULL,
		0x0FBB108F6B05EFCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA71BFCFF30BE0E96ULL,
		0xFBD4B531CED91841ULL,
		0xBA8C3E361D2D1175ULL,
		0x5B4AD00EC3401EF1ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF0B615DD4DA586B5ULL,
		0xB9651EAD860C185EULL,
		0x4A4985E9C2BD59E8ULL,
		0x4A307B35049C6191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3349E6CF2B9544BFULL,
		0x2F6F7CCA7617AD1AULL,
		0x9E71C30FE3EB36A4ULL,
		0x714ED5926E9A19A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD6C2F0E221041E3ULL,
		0x89F5A1E30FF46B44ULL,
		0xABD7C2D9DED22344ULL,
		0x58E1A5A2960247E9ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x49F73E136B498B45ULL,
		0x43F99AFF3398CB7AULL,
		0x1C9BED484D8CD8D4ULL,
		0x451D2A64A82403D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C31A7E9C184CEF7ULL,
		0x4D3922A70B98A4A7ULL,
		0xFB740BC22C117916ULL,
		0x534BF57C21E6ABB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDC59629A9C4BC3BULL,
		0xF6C07858280026D2ULL,
		0x2127E186217B5FBDULL,
		0x71D134E8863D5819ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4E6382749F90C00FULL,
		0x259732B736EE936BULL,
		0x9E8C91D80324AA5BULL,
		0x1F30E7D460151BA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED86D9A99188966EULL,
		0x5342C639BAC7275CULL,
		0x0E55F2627BE740F0ULL,
		0x30856D19CE405CFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60DCA8CB0E08298EULL,
		0xD2546C7D7C276C0EULL,
		0x90369F75873D696AULL,
		0x6EAB7ABA91D4BEA7ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB1929088C3C1E7FBULL,
		0xC2C8E3D845025F46ULL,
		0x9ACC2455BB97E613ULL,
		0x067978465FA9A6AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ED890D9A6EEA445ULL,
		0x71929E62926AA281ULL,
		0x5A0BDDAE97207308ULL,
		0x1C85A85EFF58FA9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52B9FFAF1CD343A3ULL,
		0x51364575B297BCC5ULL,
		0x40C046A72477730BULL,
		0x69F3CFE76050AC10ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x07EF81B631C096D7ULL,
		0xFF2048A7108A67FEULL,
		0x8C8480175E078B42ULL,
		0x4720250FB192ECB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56799DAD3C86B803ULL,
		0xC57681172164DBE4ULL,
		0xBE66918AFC50FCDFULL,
		0x3F4F15A5100AEB28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB175E408F539DED4ULL,
		0x39A9C78FEF258C19ULL,
		0xCE1DEE8C61B68E63ULL,
		0x07D10F6AA1880187ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDF2786BD724A4F18ULL,
		0x2C64EAC0C8F1E3BBULL,
		0xABCF05B1EF6FE62DULL,
		0x06A6D4406F9BE062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94C144C5852B987CULL,
		0x7DF8E2679CD2AA5DULL,
		0x0A4145A11F4E4465ULL,
		0x5341B54194044D64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A6641F7ED1EB689ULL,
		0xAE6C08592C1F395EULL,
		0xA18DC010D021A1C7ULL,
		0x33651EFEDB9792FEULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x68DAB5264E2DFDB5ULL,
		0xD9A2116C5976405EULL,
		0x455652D4CE925735ULL,
		0x4889680CC7041EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B6398DF964486FULL,
		0x43AC108336D36878ULL,
		0xAE031FE54A397D4BULL,
		0x02CE84DFE483EF20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22247B9854C9B546ULL,
		0x95F600E922A2D7E6ULL,
		0x975332EF8458D9EAULL,
		0x45BAE32CE2802FBBULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x43C719B08BE3BB52ULL,
		0x44FF53563453F737ULL,
		0x11520BB85BC73258ULL,
		0x1AF7565675EC2998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18973C2DE743D458ULL,
		0x36E201AA42F119CCULL,
		0x14D292800B664FE3ULL,
		0x1B64E6244FD559C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B2FDD82A49FE6E7ULL,
		0x0E1D51ABF162DD6BULL,
		0xFC7F79385060E275ULL,
		0x7F9270322616CFCEULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF99F2CEF842792E0ULL,
		0x54D5BFB1FBADA5CCULL,
		0x89368ECB0C5CD92DULL,
		0x2F7B608A5B6411CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A9021A55A1A4FBULL,
		0x080699AB75411270ULL,
		0xD2174152264DF163ULL,
		0x6D3E3E454AC0541AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4F62AD52E85EDD2ULL,
		0x4CCF2606866C935CULL,
		0xB71F4D78E60EE7CAULL,
		0x423D224510A3BDB1ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBFC57F6A1DCD57F9ULL,
		0x06C303DD1C215289ULL,
		0x573315444200CCE2ULL,
		0x74BBDD6CF54D0A32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F7285E2CD8C5A4FULL,
		0xF16F39CC3A9E7667ULL,
		0x0A629FECCBE5218DULL,
		0x2207B4FC2A90B840ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2052F9875040FDAAULL,
		0x1553CA10E182DC22ULL,
		0x4CD07557761BAB54ULL,
		0x52B42870CABC51F2ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x54336F1C8C98093FULL,
		0xEA0F9F088E5E474FULL,
		0x30CBE4694A1393C3ULL,
		0x51600A938384E6EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD943DDE7FF70F74BULL,
		0x338E30933204CCA9ULL,
		0x3F4D10B95DBB57AFULL,
		0x30BC6585A1DC40F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AEF91348D2711F4ULL,
		0xB6816E755C597AA5ULL,
		0xF17ED3AFEC583C14ULL,
		0x20A3A50DE1A8A5FBULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2B3CC8B55AC4FCD2ULL,
		0xFDC317BD02635488ULL,
		0x18D8EA5B8F52B1DEULL,
		0x3E4DFAEE01E80CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1497E5ACA07A3B3CULL,
		0x16664DD3DEF9F3E8ULL,
		0x5B94FA4F37C219C3ULL,
		0x678C4693BD178E43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A4E308BA4AC183ULL,
		0xE75CC9E9236960A0ULL,
		0xBD43F00C5790981BULL,
		0x56C1B45A44D07E9CULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2BA8367918D1180ULL,
		0xD70C5DA3ADBBAA3AULL,
		0x57631BC245435677ULL,
		0x0555D27D33D7B8C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E37ECB3EC2A608ULL,
		0x4B3B51414FBFFA65ULL,
		0x71E4477D1B064706ULL,
		0x2440E4350E02C149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D7049C52CA6B65ULL,
		0x8BD10C625DFBAFD5ULL,
		0xE57ED4452A3D0F71ULL,
		0x6114EE4825D4F77FULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD92D23DC6F1A2509ULL,
		0x657D43128FA5009CULL,
		0xB0D90256AB657D85ULL,
		0x24456F2D3D84D93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ACF84F2A32936C3ULL,
		0x437241E090D22A3CULL,
		0x7585D349C518CDCFULL,
		0x23C100B4D9C4671FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E5D9EE9CBF0EE46ULL,
		0x220B0131FED2D660ULL,
		0x3B532F0CE64CAFB6ULL,
		0x00846E7863C07220ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x013D7389B3AF47A5ULL,
		0xDC9C6A6AB36682BFULL,
		0xE8E4C377F9E7E121ULL,
		0x318A441756A2CB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCBF210D13AF90F8ULL,
		0x838370330F439FC6ULL,
		0x3F26A4A7A27DC805ULL,
		0x0761E1F8A836FD37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x447E527C9FFFB6ADULL,
		0x5918FA37A422E2F8ULL,
		0xA9BE1ED0576A191CULL,
		0x2A28621EAE6BCE1FULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x94DC3364BF19800AULL,
		0x9ED1B223BA4B22BBULL,
		0x70E6E9FCCBAEE7E3ULL,
		0x6998570BF85594D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3F52F480F63DF8ULL,
		0x0A713853035A626CULL,
		0x6E05DF34560C51E7ULL,
		0x64A38E34B4576B0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x799CE0703E234212ULL,
		0x946079D0B6F0C04FULL,
		0x02E10AC875A295FCULL,
		0x04F4C8D743FE29CAULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF73C4BC6E52C1C5CULL,
		0xFD54FFD484640DE7ULL,
		0xE9FFDEDB615E55E2ULL,
		0x7BBF1D7FB015EAB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6139B101738D6B4ULL,
		0x3659B3D95A988F32ULL,
		0x34B1FA73FDE387A3ULL,
		0x0CC59EB21E4C3208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3128B0B6CDF345A8ULL,
		0xC6FB4BFB29CB7EB5ULL,
		0xB54DE467637ACE3FULL,
		0x6EF97ECD91C9B8A9ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE94116B5A16CAE56ULL,
		0x44DD392848BBDF1FULL,
		0x33C558C6BC1DB6D4ULL,
		0x275B754F95143490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D54C4141281843AULL,
		0xAC83B70FC761D967ULL,
		0xA61A38537C4DEED4ULL,
		0x53C4622451E50B57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BEC52A18EEB2A09ULL,
		0x98598218815A05B8ULL,
		0x8DAB20733FCFC7FFULL,
		0x5397132B432F2938ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9AEEFF846071AEDEULL,
		0xD5A2443458535AD9ULL,
		0xACCD5F2257F60E1DULL,
		0x400111C0BE9C237EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D538F4875CB6C9BULL,
		0x20694548E1E94F9BULL,
		0xF23E297572DE84E6ULL,
		0x1B3157AFB7693DC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D9B703BEAA64243ULL,
		0xB538FEEB766A0B3EULL,
		0xBA8F35ACE5178937ULL,
		0x24CFBA110732E5B6ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDC5D7F4B83AD92D4ULL,
		0x092F4DF19DDCE7B5ULL,
		0xD77B22218D195545ULL,
		0x52AFCA0B3D42D06BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62511D09280F607EULL,
		0x87BAABA90E41459EULL,
		0xE0EDEF63CC9F9F0AULL,
		0x6B6474B3F863F128ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A0C62425B9E3243ULL,
		0x8174A2488F9BA217ULL,
		0xF68D32BDC079B63AULL,
		0x674B555744DEDF42ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x25306814CE00F54DULL,
		0x14F745761C989D98ULL,
		0x0CDA81FA4DF01A99ULL,
		0x3548B523D7872FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2193D595AF0F87E7ULL,
		0xB3D7B3AA331E7766ULL,
		0x06C4B37A59B7C9E8ULL,
		0x226E3EB71B345556ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x039C927F1EF16D66ULL,
		0x611F91CBE97A2632ULL,
		0x0615CE7FF43850B0ULL,
		0x12DA766CBC52DA5CULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDEF4EBADD4B07BEDULL,
		0x79E7EE65AE1E0BC2ULL,
		0x750E0AEFD59A242CULL,
		0x7FA8DF8FBABBAC82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF8C72C61FDA80F7ULL,
		0x2389D24946BE1C62ULL,
		0xE767EA1A07170428ULL,
		0x28B14587FB864F34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F6878E7B4D5FAF6ULL,
		0x565E1C1C675FEF60ULL,
		0x8DA620D5CE832004ULL,
		0x56F79A07BF355D4DULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x498F53741FADF0C1ULL,
		0xCF1C2655FBDFE226ULL,
		0x139ECFB442F6F574ULL,
		0x0522181E29E0E7FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DC5CB76CB17BC06ULL,
		0x7C010329B07D0661ULL,
		0xA86BF0449F806440ULL,
		0x5197E99ADC51E9AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BC987FD549634A8ULL,
		0x531B232C4B62DBC5ULL,
		0x6B32DF6FA3769134ULL,
		0x338A2E834D8EFE4CULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x68D047069F151DB5ULL,
		0x6DF59423D0372747ULL,
		0x9A7C7FF89C30F2F0ULL,
		0x2C579608A5520A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9392DFB88AAB284BULL,
		0xD2CB8A0003C251F0ULL,
		0x0C64682CF926E785ULL,
		0x5B2E783071B14015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD53D674E1469F557ULL,
		0x9B2A0A23CC74D556ULL,
		0x8E1817CBA30A0B6AULL,
		0x51291DD833A0CA29ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x96639D0142CEFF6DULL,
		0xCFCD7C9489E76F33ULL,
		0x74FECD8D2CBAE5C0ULL,
		0x11314F7E641C1EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04D1F74E649C771FULL,
		0x4840B610ACFEEED9ULL,
		0xC880F9AD4D01947DULL,
		0x259C1A39D5B13D2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9191A5B2DE32883BULL,
		0x878CC683DCE8805AULL,
		0xAC7DD3DFDFB95143ULL,
		0x6B9535448E6AE19DULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x53554D64181596FAULL,
		0xD59A85327FDE7852ULL,
		0x761F29AD178E2EF4ULL,
		0x5273EE5BC2881D81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F94723B8C95FAFULL,
		0xCFC271FEB5407208ULL,
		0x2FCC04E98C4BFEC6ULL,
		0x30964CBE23D1C061ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F5C06405F4C374BULL,
		0x05D81333CA9E0649ULL,
		0x465324C38B42302EULL,
		0x21DDA19D9EB65D20ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC45D938471B0A8E4ULL,
		0x3F578EC42FF10387ULL,
		0x1A1E0D27AA1E951CULL,
		0x2D4F2D743767148FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CDF69D8BB20AA9CULL,
		0x667BCC7AF83B617AULL,
		0x7A3ACC193C8DCCC7ULL,
		0x4212AE3AD935E189ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x777E29ABB68FFE35ULL,
		0xD8DBC24937B5A20DULL,
		0x9FE3410E6D90C854ULL,
		0x6B3C7F395E313305ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x881751E14937F41DULL,
		0x623F98CA9A3EB754ULL,
		0xB2F23FE6197A791FULL,
		0x72F20B692556B600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DEB52CE3B4EEF35ULL,
		0x3EAF39170B9D763BULL,
		0x132410B7BD834024ULL,
		0x4D1362CB64BD379BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA2BFF130DE904E8ULL,
		0x23905FB38EA14118ULL,
		0x9FCE2F2E5BF738FBULL,
		0x25DEA89DC0997E65ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x557000938D5A5853ULL,
		0x0285C30DD5DD3D3BULL,
		0xC6033454F9521D64ULL,
		0x3B26063C18584CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D0193F32534E13ULL,
		0xD3B5083836BF9D0AULL,
		0x981B63FEB5A58880ULL,
		0x0380069963E71617ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x849FE7545B070A40ULL,
		0x2ED0BAD59F1DA030ULL,
		0x2DE7D05643AC94E3ULL,
		0x37A5FFA2B47136D7ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x003CB12E279A8087ULL,
		0x03FA4A51962FB0BCULL,
		0xAE6C018FF9BC61E7ULL,
		0x4D187E450ACCB2B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2B0E7D648E5C42ULL,
		0xD2E6E97620361EA8ULL,
		0x0438F91DC66DF9C7ULL,
		0x44094785C51C4ABAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7211A2B0C30C2445ULL,
		0x311360DB75F99213ULL,
		0xAA330872334E681FULL,
		0x090F36BF45B067FFULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x16DD7DE55DBCB4A9ULL,
		0xEAA6DC4CBD287BC1ULL,
		0xD158731691467546ULL,
		0x7BFB368ADB9EA6F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AED5F67D1F33DEULL,
		0x75275845255BE054ULL,
		0xB1B11C360838170AULL,
		0x363AB7E946FC3934ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF2EA7EEE09D80CBULL,
		0x757F840797CC9B6CULL,
		0x1FA756E0890E5E3CULL,
		0x45C07EA194A26DBEULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3A102BE7DB88861FULL,
		0x601DFDAB4D49142CULL,
		0x1692879C858527B5ULL,
		0x3D461945A7F68AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2D7D4EB50A2055ULL,
		0x811F7F661AEA232EULL,
		0x29C40684F1A69586ULL,
		0x2AC9CEF94C48EF3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CE2AE99267E65CAULL,
		0xDEFE7E45325EF0FEULL,
		0xECCE811793DE922EULL,
		0x127C4A4C5BAD9B66ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF572EDEA347084B6ULL,
		0x1F5E54217F9B9179ULL,
		0x619936D0A45F21F1ULL,
		0x6DCE9E5A9A99C8A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28EC7C0BFE93C956ULL,
		0x8407782F6CAFD4ECULL,
		0x093E190B67E11506ULL,
		0x4E8D30450E05BB09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC8671DE35DCBB60ULL,
		0x9B56DBF212EBBC8DULL,
		0x585B1DC53C7E0CEAULL,
		0x1F416E158C940D9AULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC458FAC83C0F8560ULL,
		0x7778306A8A9FCF89ULL,
		0x485F65DEF84FE1CCULL,
		0x1801EFF6960FBC5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD68E65D1C71FC6ULL,
		0xC9C8977BFF7996A5ULL,
		0x5C2A7D19FDD69044ULL,
		0x2D552EDF15E08C87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14826C626A486587ULL,
		0xADAF98EE8B2638E4ULL,
		0xEC34E8C4FA795187ULL,
		0x6AACC117802F2FD6ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCE6BA14617F5B6E8ULL,
		0x004790B40DC986F5ULL,
		0xE64FC93BEE47876EULL,
		0x690A7BEBFD684C3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5BF8A67A718A5AEULL,
		0xA78879CB4DDADD4CULL,
		0x480DBB5594AA158AULL,
		0x4D9B25019FD1FEBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8AC16DE70DD113AULL,
		0x58BF16E8BFEEA9A8ULL,
		0x9E420DE6599D71E3ULL,
		0x1B6F56EA5D964D7FULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x22B1EB2B53D8B257ULL,
		0x35472D52BA99BC3EULL,
		0x401D146838E2E1F4ULL,
		0x50A72DFFF187F1BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B9AA3471501CECULL,
		0xB473480C75A630BFULL,
		0x74F2FF117682DFC4ULL,
		0x2B2C2C896AA07263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDF840F6E288956BULL,
		0x80D3E54644F38B7EULL,
		0xCB2A1556C260022FULL,
		0x257B017686E77F5BULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA47526F54AEF13B3ULL,
		0xFB375D7FD5E95AC9ULL,
		0xD099317C53AF5151ULL,
		0x17B6FC758BAEB066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7243BAF1E52A8804ULL,
		0x1D83047EF656EB88ULL,
		0x06C7402BF63A53A9ULL,
		0x66340A6C10D2D903ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32316C0365C48B9CULL,
		0xDDB45900DF926F41ULL,
		0xC9D1F1505D74FDA8ULL,
		0x3182F2097ADBD763ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x059BF09340C442D2ULL,
		0x779BCF3EB325E191ULL,
		0xE8E81DDB04EE0E52ULL,
		0x4FECDB42D0A1AE53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A50BCC3831BED3ULL,
		0x77CB88F5123D0641ULL,
		0xC233FECE16C364DFULL,
		0x79628FAB0FBBD5FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52F6E4C7089283ECULL,
		0xFFD04649A0E8DB4FULL,
		0x26B41F0CEE2AA972ULL,
		0x568A4B97C0E5D855ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x31E08921AA50B5B9ULL,
		0xDAA64CE10E4D19CCULL,
		0xA8150C1844C5DCECULL,
		0x6FE4E153A720BE40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x084878B8E149289CULL,
		0x96DD4A19B58D4F66ULL,
		0x99CAAD1B8F8279DBULL,
		0x1193397C9B92A65DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29981068C9078D1DULL,
		0x43C902C758BFCA66ULL,
		0x0E4A5EFCB5436311ULL,
		0x5E51A7D70B8E17E3ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1B0F92634465B27FULL,
		0x4F08465E7E1389A0ULL,
		0x0862AD2F4F0DFD0FULL,
		0x67857412EA233709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2546F9FD9D0B166FULL,
		0xD1FBD74CEA401F9FULL,
		0x7E0AB4D3680A4E1FULL,
		0x21358DDB4DF765D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5C89865A75A9C10ULL,
		0x7D0C6F1193D36A00ULL,
		0x8A57F85BE703AEEFULL,
		0x464FE6379C2BD135ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6187037398F4A6A3ULL,
		0x4FB65A377CCF6FA1ULL,
		0x0CD56BA224749270ULL,
		0x469BD4F6338378A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE049CFEE00FF291ULL,
		0xF57404807CFBF9ADULL,
		0x8C195C15CD3036ECULL,
		0x4DF44DDCB2176036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93826674B8E4B3FFULL,
		0x5A4255B6FFD375F3ULL,
		0x80BC0F8C57445B83ULL,
		0x78A78719816C1869ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF24B4577B4924E58ULL,
		0xD2FBA327A0277FDEULL,
		0xDD146F0E7DBADE3EULL,
		0x18970162FE93DBEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7965706FA2EBA0FULL,
		0x7FA0A403BC5C9CBFULL,
		0x7029F369030B0104ULL,
		0x3B0BCAC31AF1CC9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AB4EE70BA639436ULL,
		0x535AFF23E3CAE31FULL,
		0x6CEA7BA57AAFDD3AULL,
		0x5D8B369FE3A20F51ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2978D7209F7654D5ULL,
		0x585EB4FA3D909A97ULL,
		0x24A77DCE15672865ULL,
		0x0DAF26DF4D00CD49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84910C11541E2AB7ULL,
		0xC97CBEE2C70659B7ULL,
		0x22338ACDB3F9782AULL,
		0x50CD24C9B080AA8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4E7CB0F4B582A0BULL,
		0x8EE1F617768A40DFULL,
		0x0273F300616DB03AULL,
		0x3CE202159C8022BFULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB090B36D0555B5DEULL,
		0x2CCC8949B3C69DB6ULL,
		0x3EFC1AABAF1B86FCULL,
		0x49E6F090BE037E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FC4562ECB12CBBULL,
		0xD9699757C3DCE018ULL,
		0xAE56D76CF379BFA9ULL,
		0x4EA8B2B3198E5B17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D946E0A18A48910ULL,
		0x5362F1F1EFE9BD9EULL,
		0x90A5433EBBA1C752ULL,
		0x7B3E3DDDA4752374ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xADA22CDFC80E4FAAULL,
		0xEC53DEDFDAB891CCULL,
		0x236EC092B1F0930FULL,
		0x3821EB4E0565D508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51DA6FDED59A4AD5ULL,
		0x8155408295B6E29CULL,
		0xB952CA24368A0267ULL,
		0x360CC7D3441C05CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BC7BD00F27404D5ULL,
		0x6AFE9E5D4501AF30ULL,
		0x6A1BF66E7B6690A8ULL,
		0x0215237AC149CF3DULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6D8F3829BC720CCEULL,
		0x32758A687262D47DULL,
		0x81DC55C75394854FULL,
		0x48FDF7396C9D8F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3643F0C1DC7B16ULL,
		0xCDBA0D85D0903A04ULL,
		0x7A1BD012C42A3134ULL,
		0x6E12C377624EC9CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE058F438FA9591A5ULL,
		0x64BB7CE2A1D29A78ULL,
		0x07C085B48F6A541AULL,
		0x5AEB33C20A4EC588ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x251CF5F28A2A0FE9ULL,
		0x69ACDC9C04367C32ULL,
		0x389A5741E9F74174ULL,
		0x68698176F44A0B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E7370418CF60DBULL,
		0x1AFE9A45A579AEFEULL,
		0x4A5A754F801870ECULL,
		0x5572B8166F3FEA96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E35BEEE715AAF0EULL,
		0x4EAE42565EBCCD34ULL,
		0xEE3FE1F269DED088ULL,
		0x12F6C960850A2081ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x15A019B31FDE60D1ULL,
		0x7F57F406926B0677ULL,
		0x10308FE81C10BB19ULL,
		0x6EDB7860C15AFD48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA541A4860F91E5ULL,
		0xEC70059A6DD8F7D5ULL,
		0xC97190F2A3286271ULL,
		0x23500F209197D369ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5FAD80E99CECEECULL,
		0x92E7EE6C24920EA1ULL,
		0x46BEFEF578E858A7ULL,
		0x4B8B69402FC329DEULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB9C04D0F692309B2ULL,
		0xD5102594B5ADB097ULL,
		0x847F47684EDDF466ULL,
		0x0F0537E1E0EA583EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA08D5724CA8C4BDDULL,
		0x43789D708ECF7058ULL,
		0xB21C57868B21867AULL,
		0x2233F8E0F53C8E18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1932F5EA9E96BDC2ULL,
		0x9197882426DE403FULL,
		0xD262EFE1C3BC6DECULL,
		0x6CD13F00EBADCA25ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4C5ACC304115D565ULL,
		0x20B7CAA6065C85F5ULL,
		0x2B6AFA4440A5E60AULL,
		0x26CE4E449B950943ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EB5BA67556BA92EULL,
		0x913594E03379E279ULL,
		0x41B4FD31145D7538ULL,
		0x1693B347C94F1B16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA511C8EBAA2C37ULL,
		0x8F8235C5D2E2A37BULL,
		0xE9B5FD132C4870D1ULL,
		0x103A9AFCD245EE2CULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x559206EEFF18A056ULL,
		0xE439A4CAD16EB73FULL,
		0xEBFCA2C856AD807CULL,
		0x4BC5C3134834E641ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x963895E15642E0CEULL,
		0x2C1793675557D868ULL,
		0xC134775354CBED86ULL,
		0x0D9CAF71A8CC8FDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF59710DA8D5BF88ULL,
		0xB82211637C16DED6ULL,
		0x2AC82B7501E192F6ULL,
		0x3E2913A19F685665ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2EAA4337B987B729ULL,
		0x80ACB89BE337F255ULL,
		0x0AF4CDB2B8E45C41ULL,
		0x0986C09DEB9E9CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BC2811D1EFA803ULL,
		0xDC43F6ECC9801ADEULL,
		0x58A465C3684451F6ULL,
		0x3257EB2BB05F738BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95EE1B25E7980F13ULL,
		0xA468C1AF19B7D776ULL,
		0xB25067EF50A00A4AULL,
		0x572ED5723B3F2956ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x97EBCA59D9C8374EULL,
		0xAD689F8F3840D6CCULL,
		0x48FA76CEBC862548ULL,
		0x6780B2C9360E0C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC3BE7CF6CAFAE2ULL,
		0xF14087C6D75F5FAAULL,
		0x8BA9E4911F27473EULL,
		0x1B194D93923ECE03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC280BDCE2FD3C6CULL,
		0xBC2817C860E17721ULL,
		0xBD50923D9D5EDE09ULL,
		0x4C676535A3CF3E98ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x90C2EA3A86AAB7E9ULL,
		0x15281D93C2D6724BULL,
		0x5F8DD338C80E8B84ULL,
		0x423335C7084A4EF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC65E913AC68DEF5ULL,
		0x5479F0FEAEB0DAF6ULL,
		0xCCA7313B63A93138ULL,
		0x1D150249AAECF4D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD45D0126DA41D8F4ULL,
		0xC0AE2C9514259754ULL,
		0x92E6A1FD64655A4BULL,
		0x251E337D5D5D5A23ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7EDF1204AB38BE89ULL,
		0x4D93B94D708FC3F7ULL,
		0xFA207EB250F2F1C5ULL,
		0x372619010F7105F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC272ED2F1130C7ULL,
		0x1618F426C1C85985ULL,
		0xDAD3A262781B5E63ULL,
		0x10E653982A80ADF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x111C9F177C278DC2ULL,
		0x377AC526AEC76A72ULL,
		0x1F4CDC4FD8D79362ULL,
		0x263FC568E4F057FDULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0FC5B1F45510A46DULL,
		0x3682055B9CD9CCDEULL,
		0x47B75D295B3DB478ULL,
		0x0F5AD7BB6C07AC19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0C8E5B1218AA063ULL,
		0x40195FDCED5727BCULL,
		0x2389300E463C284AULL,
		0x3D0E9CC09F881208ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EFCCC43338603F7ULL,
		0xF668A57EAF82A521ULL,
		0x242E2D1B15018C2DULL,
		0x524C3AFACC7F9A11ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x490A52BA47AA71BBULL,
		0x05A93F02BEADAF2CULL,
		0xCE3FFBD6F3D76650ULL,
		0x35EC11C3DD4D3FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32EF2B2D02B0BEE2ULL,
		0x65F65AB4DF1DF5A4ULL,
		0xDEBF99CE29317AD3ULL,
		0x7D1B50708B3C5511ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x161B278D44F9B2C6ULL,
		0x9FB2E44DDF8FB988ULL,
		0xEF806208CAA5EB7CULL,
		0x38D0C1535210EAA0ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x041A308A34345B5AULL,
		0xF8832A078F895EB6ULL,
		0x4F3165EE29F20B7DULL,
		0x641A7041C66B8649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86584663416F1708ULL,
		0x71FFA6DA348C3DE3ULL,
		0x8B7D5F7E2D88E98BULL,
		0x78CF4CD1DA2682BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DC1EA26F2C5443FULL,
		0x8683832D5AFD20D2ULL,
		0xC3B4066FFC6921F2ULL,
		0x6B4B236FEC45038CULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x48281F9F4D675EA1ULL,
		0xE85D0936ADD96132ULL,
		0x1860776E156D019AULL,
		0x72780B934F86217AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398BADFD0FF4D986ULL,
		0x7A669E7CF00FADA6ULL,
		0x88394E6771070D0CULL,
		0x6A59AFC7B3BD638DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E9C71A23D72851BULL,
		0x6DF66AB9BDC9B38CULL,
		0x90272906A465F48EULL,
		0x081E5BCB9BC8BDECULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9A0F52919CDEA7EBULL,
		0x35A9730AF4B76798ULL,
		0x51776551647B4A32ULL,
		0x08E460588F78001AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53F0DE440140257ULL,
		0xF50B0DE8927EAEBFULL,
		0x39766D70B28BD0F3ULL,
		0x671D2302349BE492ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4D044AD5CCAA581ULL,
		0x409E65226238B8D8ULL,
		0x1800F7E0B1EF793EULL,
		0x21C73D565ADC1B88ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x484F37661557A1C9ULL,
		0x0D2F7632A0C3D884ULL,
		0xD8C2831913B54FC7ULL,
		0x14AA5DE3FCC665FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5629A16F94CAE0E1ULL,
		0x21EDB536C560BAE8ULL,
		0x7D0FF549B41B77D3ULL,
		0x00702F5D1643A336ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF22595F6808CC0E8ULL,
		0xEB41C0FBDB631D9BULL,
		0x5BB28DCF5F99D7F3ULL,
		0x143A2E86E682C2C7ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x88462960E1CF4FA8ULL,
		0x74A28D8C3F1F398DULL,
		0x7FC10B1C64891490ULL,
		0x1BC6B804E6964E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A235729E026A17AULL,
		0x9178089610C1E1B2ULL,
		0x2B21F0FF4167BEBBULL,
		0x143B3BC499FB6E8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E22D23701A8AE2EULL,
		0xE32A84F62E5D57DBULL,
		0x549F1A1D232155D4ULL,
		0x078B7C404C9ADF86ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x534C3AFA5A4FD637ULL,
		0xB6A9FCCAEECD8E68ULL,
		0xEE5B3A16642AFA4FULL,
		0x2CB58485C8135C53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7904C38CC796AA75ULL,
		0xDD9C53FF952917FAULL,
		0x6811DB93F427CF9DULL,
		0x5BD49DF3138E77B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA47776D92B92BAFULL,
		0xD90DA8CB59A4766DULL,
		0x86495E8270032AB1ULL,
		0x50E0E692B484E49AULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xDC157277F5AB9E7AULL,
		0x9383AF001309FF94ULL,
		0xB4BC0E63A3E1B307ULL,
		0x6BA9D31CABE6C422ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342339DD54E1D765ULL,
		0xE849FDF1A059C8A8ULL,
		0x94FA7E7A0079541BULL,
		0x4612941421B6F4EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7F2389AA0C9C715ULL,
		0xAB39B10E72B036ECULL,
		0x1FC18FE9A3685EEBULL,
		0x25973F088A2FCF33ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x358E8BFD9E282A4EULL,
		0x5C00F8DB3EF3F475ULL,
		0xD978CB6BA055A90AULL,
		0x4B6BAFCA5AD367D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA82A14087AA823AULL,
		0x117FBFA2536230F4ULL,
		0x13A028DFB098DF44ULL,
		0x499C45DEF6A88145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B0BEABD167DA814ULL,
		0x4A813938EB91C380ULL,
		0xC5D8A28BEFBCC9C6ULL,
		0x01CF69EB642AE68EULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD9FDFE2414C142EEULL,
		0xA9D17D47658B11BCULL,
		0x004313A3531F318AULL,
		0x6F513E864FDA3195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD08BB5D43F686462ULL,
		0x9C3FF6CC843A5000ULL,
		0x308C6B3667747B68ULL,
		0x5B6BBA15A3959BC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0972484FD558DE8CULL,
		0x0D91867AE150C1BCULL,
		0xCFB6A86CEBAAB622ULL,
		0x13E58470AC4495CEULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC38C7352C39956B7ULL,
		0x4A68897A3266CF0CULL,
		0x20CB2F4D09C165B7ULL,
		0x54E81620462B2EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F7A48E672A2AD82ULL,
		0xE707CD571EF5EF83ULL,
		0xBF36FFEA3C148836ULL,
		0x365D356BF8387C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74122A6C50F6A935ULL,
		0x6360BC231370DF89ULL,
		0x61942F62CDACDD80ULL,
		0x1E8AE0B44DF2B21CULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x63D3675E30EF442EULL,
		0xBC10319606C5377BULL,
		0x2A43845B37E1E151ULL,
		0x03823D2D268BCD08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8494ACD135206A9FULL,
		0x44BA6E7501597B7EULL,
		0x6E27816D615BD5E9ULL,
		0x05BA08F5EE322459ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF3EBA8CFBCED97CULL,
		0x7755C321056BBBFCULL,
		0xBC1C02EDD6860B68ULL,
		0x7DC834373859A8AEULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3A99A2DF1D16E0E1ULL,
		0x32CCD7CF881B0B9DULL,
		0x571E47DF31E611C0ULL,
		0x25AA432AD85DDA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC3278E30455259ULL,
		0x0510CB69E586328EULL,
		0xB8EEF23B30B83D7AULL,
		0x24C144E97065473AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABD67B50ECD18E88ULL,
		0x2DBC0C65A294D90EULL,
		0x9E2F55A4012DD446ULL,
		0x00E8FE4167F89344ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF16CB18D17EB3998ULL,
		0x7C76E348222C3518ULL,
		0x883C71E477E60915ULL,
		0x7A012B71D0F0A5FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD550364D065ADD55ULL,
		0x019FE3E4015017BFULL,
		0x014B083EB95C6F79ULL,
		0x7AFD6244D4F70E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C1C7B4011905C30ULL,
		0x7AD6FF6420DC1D59ULL,
		0x86F169A5BE89999CULL,
		0x7F03C92CFBF997E9ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x38FE30A3A246AF45ULL,
		0xE4C23A429F9EFAFBULL,
		0x9FAA820003EF0D1FULL,
		0x304FC57F7418F82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF885410A3B3F89B0ULL,
		0xB7374BFD47E9CA92ULL,
		0x0D8D431F2A2A3626ULL,
		0x6BCCB37077F29CD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4078EF9967072582ULL,
		0x2D8AEE4557B53068ULL,
		0x921D3EE0D9C4D6F9ULL,
		0x4483120EFC265B5DULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1EA967B2F2C3D70AULL,
		0x947F1BF28B59399BULL,
		0x59EEBD6D6BA991BDULL,
		0x566AF628FAD40046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA070FCA568CC8E53ULL,
		0x447778F8ED5D624EULL,
		0xEC9CF7A310DBEA28ULL,
		0x06FBC2B99157B3CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E386B0D89F748B7ULL,
		0x5007A2F99DFBD74CULL,
		0x6D51C5CA5ACDA795ULL,
		0x4F6F336F697C4C7BULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x180DD868EB898265ULL,
		0x8E9FD45F12DBF8C7ULL,
		0xE7C63F52A2281BF2ULL,
		0x1569D9800D12A91EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D3419BA01F6FB9ULL,
		0xF33608D229AC0FA2ULL,
		0x56B89D348E5091C2ULL,
		0x7C4A4A8284B4538DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF3A96CD4B6A1299ULL,
		0x9B69CB8CE92FE924ULL,
		0x910DA21E13D78A2FULL,
		0x191F8EFD885E5591ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x698F034B24999934ULL,
		0xA83A696D116C8551ULL,
		0x284210D6F3A898ACULL,
		0x3FC00FB2A0943ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF6373814300FA48ULL,
		0x2A6EFDC336BFBAD3ULL,
		0x73EC2AFEDFC15739ULL,
		0x69F86876A7887EF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A2B8FC9E1989ED9ULL,
		0x7DCB6BA9DAACCA7DULL,
		0xB455E5D813E74173ULL,
		0x55C7A73BF90BBFDEULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4454C0A4447FC231ULL,
		0x073A76FD6466B31DULL,
		0x77CF7E289E8F6C68ULL,
		0x10A39B4D15839972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E2259F2BF228D8ULL,
		0x713AA180DA984DAEULL,
		0xCAD548E923F9E44DULL,
		0x597359443B33A020ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3729B05188D9946ULL,
		0x95FFD57C89CE656EULL,
		0xACFA353F7A95881AULL,
		0x37304208DA4FF951ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x87C17C4F7A98DE24ULL,
		0x906B48D52A980DF7ULL,
		0xAE4155DC0D46DE0DULL,
		0x3445A67712FF8CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99101FBB9450DA9BULL,
		0x82F8A70372CA6648ULL,
		0x41D823E63BA48F05ULL,
		0x06EA6BA0174A68AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEB15C93E6480389ULL,
		0x0D72A1D1B7CDA7AEULL,
		0x6C6931F5D1A24F08ULL,
		0x2D5B3AD6FBB5242DULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x01C02F6509795DE6ULL,
		0x9B3D4CC55EED0154ULL,
		0x8CE3671E3D87BFB1ULL,
		0x6D7715B74649A8EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61E31381EE8705ADULL,
		0x2F36592AA3A92C01ULL,
		0x4040CDA83B70F1F9ULL,
		0x5669C417B17E89B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FDD1BE31AF25839ULL,
		0x6C06F39ABB43D552ULL,
		0x4CA299760216CDB8ULL,
		0x170D519F94CB1F37ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF16822A6CFDDC48CULL,
		0xE8D62A96DB8A4589ULL,
		0xC916379E7C953950ULL,
		0x66B6CBB68FA43895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BE9EFF1065E7DCULL,
		0x45E6D2CEA733CB24ULL,
		0xBC1C83A57AE3C2D0ULL,
		0x537ECC203A99D680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CA983A7BF77DCB0ULL,
		0xA2EF57C834567A65ULL,
		0x0CF9B3F901B17680ULL,
		0x1337FF96550A6215ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1E163915F07A5043ULL,
		0x7AA5D50BBC24101EULL,
		0x44D7F93576DF743BULL,
		0x7FDEBA77BD23EFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A22688975289CAULL,
		0x9AB55F7A77F5C8BDULL,
		0xAD789DA5A4398706ULL,
		0x007C4F22CC27FAF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B74128D5927C679ULL,
		0xDFF07591442E4760ULL,
		0x975F5B8FD2A5ED34ULL,
		0x7F626B54F0FBF4ECULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x132324EE3D323F4EULL,
		0x455FB73645A116BCULL,
		0xAADA884805E878AAULL,
		0x67D6DD713A20FF13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97EC255886361841ULL,
		0x155FD176B4C441CDULL,
		0xE750370A29C150CFULL,
		0x312AF2466AFFEC6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B36FF95B6FC270DULL,
		0x2FFFE5BF90DCD4EEULL,
		0xC38A513DDC2727DBULL,
		0x36ABEB2ACF2112A6ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5E7B5A96BA1AAC34ULL,
		0x45F043852B0DFCC9ULL,
		0x2618DD3EF64462C5ULL,
		0x21BCA49A196DAA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x761D13650CF80E03ULL,
		0x774188D021E5DB1FULL,
		0xD4BF30018204F4C8ULL,
		0x67A01216DEBDC430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE85E4731AD229E1EULL,
		0xCEAEBAB5092821A9ULL,
		0x5159AD3D743F6DFCULL,
		0x3A1C92833AAFE660ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5CBC438787FDC2FAULL,
		0x83DBB37DA06C8D98ULL,
		0xF66F4415B071F005ULL,
		0x5D935995BBED1AFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B48328A411C6556ULL,
		0xB2F1D40124337FDFULL,
		0x34D6C88127A2A035ULL,
		0x2FA4399920A8C38CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x317410FD46E15DA4ULL,
		0xD0E9DF7C7C390DB9ULL,
		0xC1987B9488CF4FCFULL,
		0x2DEF1FFC9B44576EULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x442827BC98558328ULL,
		0x5EEABF65F727BCA6ULL,
		0x2083C83D6C7D2DA5ULL,
		0x0B1800F476386A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59755ECB9CCAD5E0ULL,
		0x7384FED2362FD60DULL,
		0xAF4986CE4A7E749DULL,
		0x019AB2EF3DE734D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAB2C8F0FB8AAD48ULL,
		0xEB65C093C0F7E698ULL,
		0x713A416F21FEB907ULL,
		0x097D4E05385135BDULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3D595F441ED295C2ULL,
		0x06FACBF199AF1CDEULL,
		0xE9BAD99551E61882ULL,
		0x0E42912C101F5B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B78294E4E4EA4FULL,
		0xDC236820D74150C3ULL,
		0x7B7F121273D2A49CULL,
		0x459935213C3848ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89A1DCAF39EDAB60ULL,
		0x2AD763D0C26DCC1AULL,
		0x6E3BC782DE1373E5ULL,
		0x48A95C0AD3E71285ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x72555A8E914CED2DULL,
		0x814B529A545D629FULL,
		0x60BC138AC1345809ULL,
		0x759CB83A115A616EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25C53603D184ACA8ULL,
		0x1AE78C74FEEF242BULL,
		0x22AC3BA5C0078D60ULL,
		0x312786027577DE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C90248ABFC84085ULL,
		0x6663C625556E3E74ULL,
		0x3E0FD7E5012CCAA9ULL,
		0x447532379BE282D1ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCA26E0FAA983CC62ULL,
		0x9325C7FED447C229ULL,
		0x522BC10B792F2B20ULL,
		0x4BADC3481268BEC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C78963DAEAFC3FDULL,
		0xD93767822C5C4F11ULL,
		0x52F114008E7E45C3ULL,
		0x7DBC9295162C7A4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDAE4ABCFAD40852ULL,
		0xB9EE607CA7EB7318ULL,
		0xFF3AAD0AEAB0E55CULL,
		0x4DF130B2FC3C4475ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE35CF237C0BD334FULL,
		0xE9B6F9A48F8661CFULL,
		0x9281FBDEEB0ED85AULL,
		0x5C041D58451F32D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2ACFC60A88A63C1ULL,
		0x896A993096BD12FFULL,
		0x9FD698BA933293B4ULL,
		0x462C5FF646A34B4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40AFF5D71832CF8EULL,
		0x604C6073F8C94ED0ULL,
		0xF2AB632457DC44A6ULL,
		0x15D7BD61FE7BE786ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE375F983AB1DEE22ULL,
		0x8C7CC1F9B06190A9ULL,
		0x95174004A875BDCEULL,
		0x592E067BAAB8EBDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27943B6D404FD496ULL,
		0xE053F90CC4B8EB72ULL,
		0x51CB5A2C0A6F1702ULL,
		0x32B93E65EAC62CDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBE1BE166ACE198CULL,
		0xAC28C8ECEBA8A537ULL,
		0x434BE5D89E06A6CBULL,
		0x2674C815BFF2BEFEULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0359D83EB2323C9AULL,
		0x03DAD540BD7BBCD3ULL,
		0xD7D761A2CE24BFF7ULL,
		0x61959094993FEA0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956C47DAC2522463ULL,
		0xEF958816C4307F7FULL,
		0x763B562D9D90E824ULL,
		0x6F63DCA3EEBB45D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DED9063EFE01824ULL,
		0x14454D29F94B3D53ULL,
		0x619C0B753093D7D2ULL,
		0x7231B3F0AA84A43DULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x90B2473BED7BFD21ULL,
		0xEE83643C527CE465ULL,
		0x5CBB7B595CD7FE18ULL,
		0x790D19790CC1FF8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2364DE265CB3DDDEULL,
		0x1925FDC6903BAE90ULL,
		0xBC728B98CFD76C05ULL,
		0x4D9823F172CE1DCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4D691590C81F43ULL,
		0xD55D6675C24135D5ULL,
		0xA048EFC08D009213ULL,
		0x2B74F58799F3E1C1ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x615FB4636CA5DCFEULL,
		0xA988859AD2AA1EE8ULL,
		0x9A0497655B4EEAC8ULL,
		0x0CDE61DB25E4FA44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEF6AF1E7D6584A9ULL,
		0x64D65B3DFADB8DA2ULL,
		0xF6B626C19346BB14ULL,
		0x2C8484E00ED8CF0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2690544EF405842ULL,
		0x44B22A5CD7CE9145ULL,
		0xA34E70A3C8082FB4ULL,
		0x6059DCFB170C2B35ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8BCE0B3CB2674E30ULL,
		0x1E0CCD8C7C4774FFULL,
		0xDAC7F5DC83B9306AULL,
		0x2C5D339C792C233CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD91B700D136EE846ULL,
		0xD2036AEB09DE3D6EULL,
		0x25A7BFC77099BD42ULL,
		0x4FD161343D6D0C06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2B29B2F9EF865D7ULL,
		0x4C0962A172693790ULL,
		0xB5203615131F7327ULL,
		0x5C8BD2683BBF1736ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC31FF41EF48FF617ULL,
		0x5221B09F39533BCEULL,
		0xDB75C3703D8CC75EULL,
		0x2925B5BB44F3EDB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B07FA47600AC6CEULL,
		0x13F048F6E1EA170AULL,
		0x9376732177359A64ULL,
		0x1E2E1A96F036865CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6817F9D794852F49ULL,
		0x3E3167A8576924C4ULL,
		0x47FF504EC6572CFAULL,
		0x0AF79B2454BD6756ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1EE754AC74F161F1ULL,
		0xDA48FD10680F886AULL,
		0x2F87536AFB673262ULL,
		0x393AAADF36EB54F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBBA3CEE684EAE4ULL,
		0x1C2572FEF84D1F0EULL,
		0x79678085B658D2DEULL,
		0x2A246D3992034678ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x312BB0DD8E6C770DULL,
		0xBE238A116FC2695BULL,
		0xB61FD2E5450E5F84ULL,
		0x0F163DA5A4E80E7DULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xEA0694EFBB8BD87EULL,
		0x8CC17D0C881A11FEULL,
		0x71AA75EC3503D72AULL,
		0x6D3B305A01FC11F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266C33658126D2F0ULL,
		0xE552AF7169D645EDULL,
		0xA3C64CAB71E2B7ECULL,
		0x0BC20798DC0EAB02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC39A618A3A65058EULL,
		0xA76ECD9B1E43CC11ULL,
		0xCDE42940C3211F3DULL,
		0x617928C125ED66EDULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x96A217B48109EC6CULL,
		0x2EAD4CA19DE95EF9ULL,
		0x82E81909260D8D47ULL,
		0x09DD6580A28C4C3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB794155C86E5AE8FULL,
		0xDCF9FFA0AD47E14DULL,
		0x7D57F2A084A5F601ULL,
		0x1E6245E78134E7A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF0E0257FA243DCAULL,
		0x51B34D00F0A17DABULL,
		0x05902668A1679745ULL,
		0x6B7B1F992157649BULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2AE4FFFCF1F55546ULL,
		0x3C3CCACF29A34E82ULL,
		0x8C41F81F3BE08BDFULL,
		0x351ECC945F2CFA77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D9BBDE6F0D6040ULL,
		0xCB1EA90CF964C879ULL,
		0xAA16531026F9B7B8ULL,
		0x5232A1A5D00347C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x630B441E82E7F4F3ULL,
		0x711E21C2303E8608ULL,
		0xE22BA50F14E6D426ULL,
		0x62EC2AEE8F29B2B4ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xA018A78C40E52BF9ULL,
		0x65DBCC048AAC41F2ULL,
		0xE6801E986DABFB0AULL,
		0x7BC8AB87C6DF813EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B91D800CCB244D8ULL,
		0x4861EDC1C2670E5EULL,
		0x4C5A5C7D63A138E5ULL,
		0x7120D14E933BC50EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8486CF8B7432E721ULL,
		0x1D79DE42C8453394ULL,
		0x9A25C21B0A0AC225ULL,
		0x0AA7DA3933A3BC30ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xFE430D21EDA4892DULL,
		0x7E7FE30936C05B8EULL,
		0x71D80B1CCEE0596CULL,
		0x54B9914386395A36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08CF2A1B48C38B00ULL,
		0x1F675545AA7ECA5EULL,
		0x8F25A18353FF735BULL,
		0x44395B21CFDDF051ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF573E306A4E0FE2DULL,
		0x5F188DC38C419130ULL,
		0xE2B269997AE0E611ULL,
		0x10803621B65B69E4ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7F93097EF51EE1C6ULL,
		0xE99CE41439A3B796ULL,
		0x0F103DD39FF7C75AULL,
		0x0CCF09A6EB5D308DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF517D1EEB3E2C7CULL,
		0x4182954214F78E31ULL,
		0x69A4A4BC539AA109ULL,
		0x36FA51869E8AD4C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90418C6009E0B537ULL,
		0xA81A4ED224AC2964ULL,
		0xA56B99174C5D2651ULL,
		0x55D4B8204CD25BC8ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8D63D73D54D3B939ULL,
		0x0187E9582DEB129BULL,
		0x5371216A518D6DF5ULL,
		0x0C6121FFA6D2A847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB13F9D9D152830B7ULL,
		0x30747F296C1DE273ULL,
		0xBB7154BDE8533E04ULL,
		0x135FAB7DDB85326EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC2439A03FAB886FULL,
		0xD1136A2EC1CD3027ULL,
		0x97FFCCAC693A2FF0ULL,
		0x79017681CB4D75D8ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xED1E3AC611F55142ULL,
		0x513E05012348D61FULL,
		0x07A73FB3F6E81C24ULL,
		0x7F2081D3253C547DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0287A1C37C1190BDULL,
		0xC94EFFD5015BD363ULL,
		0xFBAB899BB5C1BAF3ULL,
		0x619C4871BDDAEA6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA96990295E3C085ULL,
		0x87EF052C21ED02BCULL,
		0x0BFBB61841266130ULL,
		0x1D84396167616A0FULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6EAA70A6829590C2ULL,
		0x8D85A34840E29F03ULL,
		0x7F5EEFF7FB0EA68DULL,
		0x55B3B5EE5141489DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x165E14091963DD25ULL,
		0xC667AE2C1776E354ULL,
		0xDE21273AB6823383ULL,
		0x29B7B2CF88977257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x584C5C9D6931B39DULL,
		0xC71DF51C296BBBAFULL,
		0xA13DC8BD448C7309ULL,
		0x2BFC031EC8A9D645ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8750F20F02BEF89DULL,
		0x4F2470D65DAA2675ULL,
		0xDBDC077E2FB6AE69ULL,
		0x55012CCC7098D932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x846E13FAFA606D32ULL,
		0x368FE660D43D928BULL,
		0xC3B3288CA7EBC4DEULL,
		0x3ADAA72999DFBA64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02E2DE14085E8B6BULL,
		0x18948A75896C93EAULL,
		0x1828DEF187CAE98BULL,
		0x1A2685A2D6B91ECEULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5CF4A7AD677DB8FFULL,
		0xD924C731BF34D803ULL,
		0xA19F2BD47D05A325ULL,
		0x0443719E56F3A924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A288CB03203D556ULL,
		0xED7549FEAB11F009ULL,
		0xF8FEE93325220A68ULL,
		0x1C11CAE00BA88745ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42CC1AFD3579E396ULL,
		0xEBAF7D331422E7FAULL,
		0xA8A042A157E398BCULL,
		0x6831A6BE4B4B21DEULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1AE93BC1744C6BFAULL,
		0x7C614ADB18356975ULL,
		0xCC0A5FBE6C76DCADULL,
		0x57003551FFA365A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F21DB2099EC849DULL,
		0x1687132CAC8C192AULL,
		0x35F6176CE9FEE8AEULL,
		0x52F6C1DA728536FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9BC760A0DA5FE75DULL,
		0x65DA37AE6BA9504AULL,
		0x961448518277F3FFULL,
		0x040973778D1E2EA6ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7C77B7A5523BA03CULL,
		0xB165196AC0AF6922ULL,
		0x55493F541AF415C1ULL,
		0x4561BF4E9BD4180DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4D0289A120E61FULL,
		0xA6705C4FFDBEEBF0ULL,
		0x11C3A4E3B08734D5ULL,
		0x556EA1F75F5CCE99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E2AB51BB11ABA0AULL,
		0x0AF4BD1AC2F07D32ULL,
		0x43859A706A6CE0ECULL,
		0x6FF31D573C774974ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB242938588049F81ULL,
		0x4BA42C976E77363EULL,
		0xC5134D1923F476E4ULL,
		0x2857B98AA590128FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC154E06783B422B0ULL,
		0x1CD599EF6D91D3A3ULL,
		0x5AAA27AFB576DBFDULL,
		0x53ED9D05F07BBB45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0EDB31E04507CBEULL,
		0x2ECE92A800E5629AULL,
		0x6A6925696E7D9AE7ULL,
		0x546A1C84B514574AULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x03E4ED4193195C4BULL,
		0x88C1E7DAEA27E31AULL,
		0x70FDE22E8460FE43ULL,
		0x2BF48E368BEDAA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16AB92592816064FULL,
		0xC3467E36862CBB9EULL,
		0x40A06F2D3E42A858ULL,
		0x0F5C9EA9895A16CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED395AE86B0355FCULL,
		0xC57B69A463FB277BULL,
		0x305D7301461E55EAULL,
		0x1C97EF8D029393B1ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5AE9747CCE99B90EULL,
		0x56D2F3147FF892E6ULL,
		0xA0129E9BD630F8ACULL,
		0x167E36725F31ED70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4ADAF847E8FF1CULL,
		0xC9438AC30FDAFB19ULL,
		0x9F8831216B4F9F54ULL,
		0x3F9D94DB0F55CF4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B9E998486B0B9DFULL,
		0x8D8F6851701D97CDULL,
		0x008A6D7A6AE15957ULL,
		0x56E0A1974FDC1E26ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x421CFEC7AF17724FULL,
		0xE95EE30713F6E0B4ULL,
		0x12A743FA3EFCEAF1ULL,
		0x12F2D76229C5D2E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB413DD3DF1F25439ULL,
		0xEB97B384219E2406ULL,
		0xEF9D9681F394F18FULL,
		0x70E98AF626820228ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E092189BD251E03ULL,
		0xFDC72F82F258BCADULL,
		0x2309AD784B67F961ULL,
		0x22094C6C0343D0BFULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE2575C667972B03CULL,
		0xF4FD435CCF66F445ULL,
		0xF454CAA8EA8C6BF1ULL,
		0x61DEE3010FB6D93BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C21F9254812DB2BULL,
		0x2168E64C701163F7ULL,
		0x3382F63EE493870DULL,
		0x0B031E4740E8A12BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76356341315FD511ULL,
		0xD3945D105F55904EULL,
		0xC0D1D46A05F8E4E4ULL,
		0x56DBC4B9CECE3810ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x177A3152658047D6ULL,
		0x1619F461676A58E4ULL,
		0x872894C75F06CCDAULL,
		0x676A264A4B483BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CBC374F2786EE4ULL,
		0x4C84FF7C1DA579E1ULL,
		0xCBAEBDA2E8202862ULL,
		0x69A62893981C98D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DAE6DDD7307D8DFULL,
		0xC994F4E549C4DF02ULL,
		0xBB79D72476E6A477ULL,
		0x7DC3FDB6B32BA2D5ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE14DAFF7648C6ACBULL,
		0x2B34F65545FFD940ULL,
		0x881B8438CA1F1479ULL,
		0x6A10177848767A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809C82B01A8A6DA6ULL,
		0xE194D44F008105D2ULL,
		0x5BFD73858B24CC2DULL,
		0x6C8BC3564BA57447ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60B12D474A01FD12ULL,
		0x49A02206457ED36EULL,
		0x2C1E10B33EFA484BULL,
		0x7D845421FCD10655ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x594D4794D83B6BD7ULL,
		0xFFCFA850A83CD190ULL,
		0x7936DB981C505D57ULL,
		0x1935905CE5C64C7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C659365701B413ULL,
		0x8C74FA4C5087ED11ULL,
		0xC126A381BBEFE2E1ULL,
		0x58D4DCA337DF5F4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2786EE5E8139B7B1ULL,
		0x735AAE0457B4E47FULL,
		0xB810381660607A76ULL,
		0x4060B3B9ADE6ED2CULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x840562707A11C366ULL,
		0x2435657EFF04D0A7ULL,
		0x7443426397215A93ULL,
		0x4A7D80DCDAE05D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D80DCE7DBF0D12DULL,
		0x361D41B2214286F8ULL,
		0x3974F79C2E3E7D78ULL,
		0x324B3C6C25F4A834ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x168485889E20F239ULL,
		0xEE1823CCDDC249AFULL,
		0x3ACE4AC768E2DD1AULL,
		0x18324470B4EBB516ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5940477731BF5C3CULL,
		0x035DCB83AE808E6EULL,
		0xD2A83E6630C53110ULL,
		0x00303DAA50AD0C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC76E01E197E9C0ULL,
		0xE8A01761F80A67D2ULL,
		0xE7D6EFA690024B4FULL,
		0x74AFF52F7A07E08BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D78D97550277269ULL,
		0x1ABDB421B676269BULL,
		0xEAD14EBFA0C2E5C0ULL,
		0x0B80487AD6A52BFAULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xBAD2048D0D9C289DULL,
		0x38E5F693B6AF1858ULL,
		0x84EBF8B029892DB9ULL,
		0x497A0C62DB53670BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ACD8C4E940D1D9AULL,
		0x9CC176FA42BB3540ULL,
		0x2566C2ABA9098A57ULL,
		0x01381DD8E3215C9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2004783E798F0B03ULL,
		0x9C247F9973F3E318ULL,
		0x5F853604807FA361ULL,
		0x4841EE89F8320A6FULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3FADB05B40E391DEULL,
		0xAC38178FCDCD519CULL,
		0x0B78C91D8A4CFEFCULL,
		0x49ADE3E9F3469EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7294B659596FB21ULL,
		0xB49C546E4D44A18FULL,
		0xB72DCDE65D607AC4ULL,
		0x2CEE6088D7C4EC1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988464F5AB4C96BDULL,
		0xF79BC3218088B00CULL,
		0x544AFB372CEC8437ULL,
		0x1CBF83611B81B2CDULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x425E6EBD35513CEFULL,
		0xE37134829B420B41ULL,
		0x294E5687B67E83F1ULL,
		0x5AE612A78827F9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB7001CAB76F9A3ULL,
		0x785133C86017475DULL,
		0xE98FB465F5B73292ULL,
		0x7CAB8D3E11287AB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45A76EA089DA4339ULL,
		0x6B2000BA3B2AC3E3ULL,
		0x3FBEA221C0C7515FULL,
		0x5E3A856976FF7F00ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3364E1CD631FD5CBULL,
		0x30BAA7990C4CAA38ULL,
		0x8049C35B403CB0B9ULL,
		0x3FE1970564855263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8931B31D92E306A5ULL,
		0xBEE9350A42064F89ULL,
		0x48A9CAE6C5AB37AAULL,
		0x3B1271F936AE7D40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA332EAFD03CCF26ULL,
		0x71D1728ECA465AAEULL,
		0x379FF8747A91790EULL,
		0x04CF250C2DD6D523ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x70A1A958D13D7761ULL,
		0x724616CCBEDCDAB4ULL,
		0xD3F497D70B39ADDCULL,
		0x02D3EF5B806403FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4CB13BC151189EULL,
		0xD3C4D064726E2794ULL,
		0x604FF0492EDF480BULL,
		0x2BEBB1978D98F4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5654F81D0FEC5EB0ULL,
		0x9E8146684C6EB320ULL,
		0x73A4A78DDC5A65D0ULL,
		0x56E83DC3F2CB0F46ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5E94D5ADF8C57707ULL,
		0xF2045EC220EC006BULL,
		0xE068C6FB90E5E4BCULL,
		0x63F806D7007DB1ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A017C4DEC982E5EULL,
		0x0555492B4BE884ECULL,
		0xCECF279E60B718F8ULL,
		0x27594FB31D443F1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD49359600C2D48A9ULL,
		0xECAF1596D5037B7EULL,
		0x11999F5D302ECBC4ULL,
		0x3C9EB723E339728FULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5B5CF98B3BCEF63BULL,
		0xC08F4B15DA59228CULL,
		0xA65E0F5A640BE21FULL,
		0x20E5B463BEB62BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86FE82604BE7489ULL,
		0x075949C0528ED368ULL,
		0xCCE15A37525D9DBAULL,
		0x1AF88CA71422587EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2ED1165371081B2ULL,
		0xB936015587CA4F23ULL,
		0xD97CB52311AE4465ULL,
		0x05ED27BCAA93D32BULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF155921F5FE0818BULL,
		0x4BCF7C36B1FDFE51ULL,
		0x72234465CF917724ULL,
		0x3B012FEE63D071B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6251FDAE6E35CCDULL,
		0x4CCF880E94982FDFULL,
		0x0EAA602BD85E6B70ULL,
		0x3AC23A6A261FAA9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B30724478FD24BEULL,
		0xFEFFF4281D65CE72ULL,
		0x6378E439F7330BB3ULL,
		0x003EF5843DB0C71AULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF7901EFBFCA61A89ULL,
		0x4469CA7628AA8D42ULL,
		0x14051794EBF73978ULL,
		0x1C6A338ED5E17A77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27E41C87AD52A64CULL,
		0xE627F71A9789DBA1ULL,
		0x246C1793AAAE33A8ULL,
		0x78045B1A9179C036ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFAC02744F53742AULL,
		0x5E41D35B9120B1A1ULL,
		0xEF990001414905CFULL,
		0x2465D8744467BA40ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x97D646FC96DABF0EULL,
		0x26691D4C9C7C736BULL,
		0x36CD85BDD6E6169CULL,
		0x562FF8DBFB02CB3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09BC8676B4457411ULL,
		0xAF7462570A604CCDULL,
		0x8E989AD01DF148D5ULL,
		0x75F4029C84B044D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E19C085E2954AEAULL,
		0x76F4BAF5921C269EULL,
		0xA834EAEDB8F4CDC6ULL,
		0x603BF63F7652866AULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x19B7E573AE9FA5D3ULL,
		0x7466E074D8862380ULL,
		0x57CA0BAD876B2995ULL,
		0x1F4CE3DFB96FDFB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3205FB027024BB7ULL,
		0x57EF9C162A96A260ULL,
		0x23138FC960E482F6ULL,
		0x0FB2CF697FC96CA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x669785C3879D5A1CULL,
		0x1C77445EADEF811FULL,
		0x34B67BE42686A69FULL,
		0x0F9A147639A6730DULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF6D71FE6D3F6D098ULL,
		0x276C1C8E3F651D63ULL,
		0x4A8CEFAAE0DFE20BULL,
		0x7BC7BD4B2D0543FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD0CAA8648467445ULL,
		0x74D3BA45C463EE47ULL,
		0x933DA080E7661FDCULL,
		0x62E0428930D5C8EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9CA75608BB05C53ULL,
		0xB29862487B012F1BULL,
		0xB74F4F29F979C22EULL,
		0x18E77AC1FC2F7B0FULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE7DFBBA66B2E5219ULL,
		0x66C74BD73A0ECFE9ULL,
		0x47D3EA4C4289A768ULL,
		0x791205AE76F379B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7BF1BDED667F745ULL,
		0xFCD8C67242197688ULL,
		0xCEBF221241C75609ULL,
		0x532A2E6062C2966CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00209FC794C65AD4ULL,
		0x69EE8564F7F55961ULL,
		0x7914C83A00C2515EULL,
		0x25E7D74E1430E34CULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x92AB9CDD9F789B38ULL,
		0x9EC50BFCAE2E7FB2ULL,
		0xF241FA259E8AEE73ULL,
		0x60ED5614581141D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14B827A1B724ACFULL,
		0x3DF2570631FB862DULL,
		0x5AA1BB968F5244BAULL,
		0x1EA6C4B51968A273ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1601A6384065069ULL,
		0x60D2B4F67C32F984ULL,
		0x97A03E8F0F38A9B9ULL,
		0x4246915F3EA89F62ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x0B5A02914AC532E1ULL,
		0x847D43BBAD5DC1D1ULL,
		0xB482125D95E6699FULL,
		0x15075CFC96296E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC282D6DA5AB2736ULL,
		0x9997956844D8298FULL,
		0xBA1E6201EDD3C777ULL,
		0x3C84DC8CF4490716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F31D523A51A0B98ULL,
		0xEAE5AE5368859841ULL,
		0xFA63B05BA812A227ULL,
		0x5882806FA1E06742ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xE30978AB8F9824DEULL,
		0xB8B6254325C1C4EEULL,
		0x7E2B80C39103E23CULL,
		0x4232F95BE0214281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33755B29EA371531ULL,
		0xAE80DA6FE4CA0F8BULL,
		0xBB76C436A89267ACULL,
		0x75BF5BF47A3DFD57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF941D81A5610F9AULL,
		0x0A354AD340F7B563ULL,
		0xC2B4BC8CE8717A90ULL,
		0x4C739D6765E34529ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9CEA4E637B526507ULL,
		0x0DB51219A891C389ULL,
		0x8142918F55683E33ULL,
		0x7C79C46C46FC1822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F558C8C1909906ULL,
		0x0287366F3CFE4973ULL,
		0x0AAA33B29517E990ULL,
		0x215DC5653CA7AD08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24F4F59AB9C1CC01ULL,
		0x0B2DDBAA6B937A16ULL,
		0x76985DDCC05054A3ULL,
		0x5B1BFF070A546B1AULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x62AE9A582F5B99F1ULL,
		0x559FFE40DDA56678ULL,
		0x2FF860539B769BD0ULL,
		0x6F450DC5B1BEACAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3191A728FA3A1892ULL,
		0x2481889E3B4582AAULL,
		0x6CCD7E0C070D3B28ULL,
		0x6A80117434151B4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x311CF32F3521815FULL,
		0x311E75A2A25FE3CEULL,
		0xC32AE247946960A8ULL,
		0x04C4FC517DA9915FULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD3080B95BEF2FC92ULL,
		0x7ABC76FDB493B5B0ULL,
		0x3E45E14C6A75F6E3ULL,
		0x5BD47D90C11D0E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB71B762243A6743ULL,
		0x0F4EF58F24010E83ULL,
		0x021827A1196F1D30ULL,
		0x6BCAB161A1FA3B76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x079654339AB8953CULL,
		0x6B6D816E9092A72DULL,
		0x3C2DB9AB5106D9B3ULL,
		0x7009CC2F1F22D2BDULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC65576EE8619EEACULL,
		0x5AA8B65F0F6DFBC6ULL,
		0xB194297804D09CA0ULL,
		0x2A8E799533D5594CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AD26FC20A320CEULL,
		0x6ECE6AD173DE8972ULL,
		0xDE6AF4253A71DA6DULL,
		0x554C7DA4F22186BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EA84FF26576CDCBULL,
		0xEBDA4B8D9B8F7254ULL,
		0xD3293552CA5EC232ULL,
		0x5541FBF041B3D28FULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7FE6D46241D5441CULL,
		0xB10601AA383666EAULL,
		0x3163C99E666F70BBULL,
		0x37CC56761D7D5256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4686A0CF7FB3A548ULL,
		0x10E8AB4EFBFB0EEAULL,
		0x04294E9233951B7DULL,
		0x205DF240B106E880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39603392C2219ED4ULL,
		0xA01D565B3C3B5800ULL,
		0x2D3A7B0C32DA553EULL,
		0x176E64356C7669D6ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7E2CE382DC4B2499ULL,
		0x3155B6FCB658F476ULL,
		0x191D45C43F829B61ULL,
		0x2BE249A1010FFE8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1808EBC51CEBCC45ULL,
		0xFCEF590E3D202477ULL,
		0x692C30815C6FA62BULL,
		0x141B5A6ED72C8CEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6623F7BDBF5F5854ULL,
		0x34665DEE7938CFFFULL,
		0xAFF11542E312F535ULL,
		0x17C6EF3229E371A1ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x9F48507E8CB283DFULL,
		0x7E0FE39707AF8DEDULL,
		0xAD98657E7055C851ULL,
		0x6C85AE9A7EAF993DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94701AD01D16BD4ULL,
		0x3160D201D5DA8031ULL,
		0x6A2A674E45C95435ULL,
		0x719F0E04F0C588BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6014ED18AE117F8ULL,
		0x4CAF119531D50DBBULL,
		0x436DFE302A8C741CULL,
		0x7AE6A0958DEA107FULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x58CE8C7DA54B776DULL,
		0xC0DBDFC1385A122AULL,
		0xC02BD32EAB5C173AULL,
		0x5EBDBADD51877B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0257E5146E0537ULL,
		0xB2722BD47AD421EFULL,
		0x756955422A4AFC3AULL,
		0x675542C644E76538ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDCC349890DD7223ULL,
		0x0E69B3ECBD85F03AULL,
		0x4AC27DEC81111B00ULL,
		0x776878170CA01642ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2AA89146BDC137C9ULL,
		0xA0642E83CF99111AULL,
		0xAE1D8100D737738AULL,
		0x5BEA5B0238F0D6D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D36390BA185DA9ULL,
		0xF9915BC21AF86028ULL,
		0xF501213CF0DB3EDEULL,
		0x3B18E15BDFEE4AC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59D52DB603A8DA20ULL,
		0xA6D2D2C1B4A0B0F1ULL,
		0xB91C5FC3E65C34ABULL,
		0x20D179A659028C11ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC456EA44637077B5ULL,
		0x4323123BACFA66BDULL,
		0x331439F5C98E9DFDULL,
		0x15016236BBD7D666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69D1E9271843524ULL,
		0x7608C43378C5EDE3ULL,
		0x64EDF9E42BC8DE4EULL,
		0x136F4F07CD719522ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDB9CBB1F1EC4291ULL,
		0xCD1A4E08343478D9ULL,
		0xCE2640119DC5BFAEULL,
		0x0192132EEE664143ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x73910710B45BD524ULL,
		0xEB18606FF84E609EULL,
		0x6376F6B240F45F75ULL,
		0x724F12323B07C560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97FF689572367BE1ULL,
		0x667E92A4A84F5521ULL,
		0xF28C51BAC1EEED85ULL,
		0x6ECC5BB19DD341C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB919E7B42255943ULL,
		0x8499CDCB4FFF0B7CULL,
		0x70EAA4F77F0571F0ULL,
		0x0382B6809D34839DULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2159B87F4D0A35CBULL,
		0xD8CF850DEDF50EBFULL,
		0x8B3DEB133E09ACABULL,
		0x6FEF4A5B6369309FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8D895EA384EC7AEULL,
		0x4A8EF6A2390FCA6AULL,
		0xF521E27CA1B96247ULL,
		0x400C74FD71604751ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6881229514BB6E1DULL,
		0x8E408E6BB4E54454ULL,
		0x961C08969C504A64ULL,
		0x2FE2D55DF208E94DULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xCCB55BC0579395E2ULL,
		0xC325914139481B17ULL,
		0x5D160BF6FAB5AA69ULL,
		0x1E113989B9AA9E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E2B3FD656EAEACAULL,
		0xA75796E64CDCD1EAULL,
		0x060D041DE49A2281ULL,
		0x13CBC63139B1CE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E8A1BEA00A8AB18ULL,
		0x1BCDFA5AEC6B492DULL,
		0x570907D9161B87E8ULL,
		0x0A4573587FF8D00EULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x2D98EF73201FAB02ULL,
		0x2DF3C241E4861D7AULL,
		0xBDF4729F1507CE46ULL,
		0x645B3E4D7ECF5D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE525632AA7620754ULL,
		0xED0447823F91C897ULL,
		0xA503A894482EE974ULL,
		0x2179E42912BE9956ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48738C4878BDA3AEULL,
		0x40EF7ABFA4F454E2ULL,
		0x18F0CA0ACCD8E4D1ULL,
		0x42E15A246C10C445ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x916FBAC37D153A4EULL,
		0x2F93BE134A97EE4BULL,
		0x11E3DDDE902D4353ULL,
		0x323EC40AE690BF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07DD602036D32B65ULL,
		0x3B21844E0329E50BULL,
		0x37E775F96CAE00DCULL,
		0x5A6C4AA0FC461AE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89925AA346420ED6ULL,
		0xF47239C5476E0940ULL,
		0xD9FC67E5237F4276ULL,
		0x57D27969EA4AA45BULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x737DBC7271BFADA7ULL,
		0xC9EE5BAAD0B4A24FULL,
		0xBC32AE43AF62F7A4ULL,
		0x575613620E966D7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2480EC52A532B7D0ULL,
		0x52CB64E44622FF15ULL,
		0xAFB8441A223DB862ULL,
		0x01A73F77E4F7ED54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EFCD01FCC8CF5D7ULL,
		0x7722F6C68A91A33AULL,
		0x0C7A6A298D253F42ULL,
		0x55AED3EA299E8029ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF94E6A78A566FE22ULL,
		0xBD620A18F0910F58ULL,
		0xB56F5DC39F081AB5ULL,
		0x545AF9C5C20854BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914034544577FE95ULL,
		0xDC15B24700ADD7BEULL,
		0x07F263BBE643E654ULL,
		0x367459C6762301B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x680E36245FEEFF8DULL,
		0xE14C57D1EFE3379AULL,
		0xAD7CFA07B8C43460ULL,
		0x1DE69FFF4BE5530DULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xF4CC28F558584AC1ULL,
		0x480BA134A969F371ULL,
		0xC47991E87CF5BB91ULL,
		0x163A954D4EB89360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x563C7646A232208EULL,
		0x1A58D951B74D0C6EULL,
		0x6996B328FEA34850ULL,
		0x0BDED4DDC63B1A26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E8FB2AEB6262A33ULL,
		0x2DB2C7E2F21CE703ULL,
		0x5AE2DEBF7E527341ULL,
		0x0A5BC06F887D793AULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD8D634579C6EDFE2ULL,
		0x5BB84BDFFC11D6C0ULL,
		0x6FD53A2D6BDC3FE3ULL,
		0x16127443D392B78EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9885EC6CA47D53DAULL,
		0x02EBABD6C2A10843ULL,
		0x9B6C88AEC8E3B4B2ULL,
		0x2FA7617C44585ED6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x405047EAF7F18BF5ULL,
		0x58CCA0093970CE7DULL,
		0xD468B17EA2F88B31ULL,
		0x666B12C78F3A58B7ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x6E81C3F7139EE9ADULL,
		0x112E6C76B8C1AE2BULL,
		0x4AD9FF56F5CC1FE5ULL,
		0x73C329BAF46AEC4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43ACC514C01E270FULL,
		0x9F72A2A63ECDE736ULL,
		0x280C6EA2AD3DFDFCULL,
		0x589079716D825926ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AD4FEE25380C29EULL,
		0x71BBC9D079F3C6F5ULL,
		0x22CD90B4488E21E8ULL,
		0x1B32B04986E89327ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xD6FA61D9026C063BULL,
		0x374F6588F2AB159AULL,
		0xA1030B0A48465217ULL,
		0x555AB4BB0136D658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12CDE7F41AB213D7ULL,
		0x99D8AF4EB806561BULL,
		0x6416DC178DD3F425ULL,
		0x5583C6567DDA44ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC42C79E4E7B9F251ULL,
		0x9D76B63A3AA4BF7FULL,
		0x3CEC2EF2BA725DF1ULL,
		0x7FD6EE64835C91ABULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC3A37F1DABBB5F9BULL,
		0x9A9DB3C233C3B46AULL,
		0x1ADB86BAF7B6A193ULL,
		0x30ED3BA53C951933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF923EB4ED2B2F58BULL,
		0x0284262557BC13C7ULL,
		0x181619BBF5A260EDULL,
		0x6B4455DA22AABA1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA7F93CED90869FDULL,
		0x98198D9CDC07A0A2ULL,
		0x02C56CFF021440A6ULL,
		0x45A8E5CB19EA5F16ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x1C698535FD88363CULL,
		0xA32613E98ECCE80AULL,
		0x8A73503F59CFB9F9ULL,
		0x73EB3710950F448AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF53ABD9EE5A0D7CULL,
		0x46DA24C1CBA819F6ULL,
		0x069E4DFD6ADC12FAULL,
		0x416B5BCF2BEA5F17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D15D95C0F2E28C0ULL,
		0x5C4BEF27C324CE13ULL,
		0x83D50241EEF3A6FFULL,
		0x327FDB416924E573ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x7155A7500E69F3F3ULL,
		0xC6D899F244B7DF2CULL,
		0xC63154698876A040ULL,
		0x6631FB57B7112D29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15ECC3D6797DE351ULL,
		0x53AA1D992409B611ULL,
		0xDF4063289277C798ULL,
		0x19EA9BB645E3A382ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B68E37994EC10A2ULL,
		0x732E7C5920AE291BULL,
		0xE6F0F140F5FED8A8ULL,
		0x4C475FA1712D89A6ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x8179FBDE032D53CCULL,
		0x84815B99A2CE8826ULL,
		0x2396DEBCCD7F1D8AULL,
		0x13D51C48541112A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF89030399358AFULL,
		0xDC36D6E6990B4407ULL,
		0x4431AE812ED74AC0ULL,
		0x7476182786FFC39DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3816BADC999FB0AULL,
		0xA84A84B309C3441EULL,
		0xDF65303B9EA7D2C9ULL,
		0x1F5F0420CD114F07ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3FD43BCB5C794DA5ULL,
		0x43DE78C9C13BE3E3ULL,
		0x4B68A6C055C66B7BULL,
		0x41138B8B15EE7483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06B32BA9FF01DF8ULL,
		0x01E5C6878B6745DEULL,
		0xB4F5EAEDB06B840CULL,
		0x591A2EA03A7E3694ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F690910BC892F9AULL,
		0x41F8B24235D49E04ULL,
		0x9672BBD2A55AE76FULL,
		0x67F95CEADB703DEEULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xB4AB9F3F46ACFD15ULL,
		0x56473D281D018EECULL,
		0xC9C7075CEFB9D2E7ULL,
		0x1693DDBC96DA5500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91A42E8BCB2547DBULL,
		0x9018BD5FBECC45AFULL,
		0x557BF736C674C8A7ULL,
		0x059B0E48CC59CEFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x230770B37B87B53AULL,
		0xC62E7FC85E35493DULL,
		0x744B102629450A3FULL,
		0x10F8CF73CA808605ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4FB7C9F7DC79B44BULL,
		0xF27AD9DB0FE8241EULL,
		0xFD4A8673049D296EULL,
		0x33C8665A12497398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B4FB0B9AC24899ULL,
		0x02A0E2EF68339F14ULL,
		0xEC8F377614FCBFF1ULL,
		0x28776440F8D52349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F02CEEC41B76BB2ULL,
		0xEFD9F6EBA7B4850AULL,
		0x10BB4EFCEFA0697DULL,
		0x0B5102191974504FULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x5EC69A605A79F64EULL,
		0x5EE9068FF7A42536ULL,
		0xA7B460D97249E53AULL,
		0x33EFCD1CFAEA6950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9E37BD2047BAEBULL,
		0x1D2DB4873DC35E4AULL,
		0x600705EF3223CE09ULL,
		0x5A5CB44DE88C3AD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB32862A33A323B50ULL,
		0x41BB5208B9E0C6EBULL,
		0x47AD5AEA40261731ULL,
		0x599318CF125E2E79ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x38B17019BF7E7584ULL,
		0x7D1D36727C6B4673ULL,
		0x34A16DC09C6C50D9ULL,
		0x384B747448F2B140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9096FBF62A857BBULL,
		0x43B0F68291A5A355ULL,
		0x497B5AB11024E175ULL,
		0x57B1D2F8351EC914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA8005A5CD61DB6ULL,
		0x396C3FEFEAC5A31DULL,
		0xEB26130F8C476F64ULL,
		0x6099A17C13D3E82BULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0xC0E7D18E4678B9E2ULL,
		0x74198D79B6FB9482ULL,
		0xDEE4956CB27B18CAULL,
		0x7A3624B28FABDFBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFDB3779423F68CULL,
		0x3D0462B3791DA703ULL,
		0xFB0F7DD8F8A55FADULL,
		0x00524DF64880A98FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53EA1E16B254C356ULL,
		0x37152AC63DDDED7FULL,
		0xE3D51793B9D5B91DULL,
		0x79E3D6BC472B362DULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x4FD6147BADF8E83FULL,
		0x369D44BBFE7BDF73ULL,
		0x5D4DDD762BE39334ULL,
		0x18FAA01E848BBD5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14164A2AD3511654ULL,
		0x97B741AE1968A059ULL,
		0xC45E2FD73FA7962DULL,
		0x0BC7C11C2E814763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BBFCA50DAA7D1EBULL,
		0x9EE6030DE5133F1AULL,
		0x98EFAD9EEC3BFD06ULL,
		0x0D32DF02560A75FAULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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
		0x3B87C73A0EFDFB36ULL,
		0x0884820AD29F5D66ULL,
		0xE64DF76890D3E3D1ULL,
		0x13ECCD6F7E863571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE73A7D8711A096B5ULL,
		0x58BF837E4E5DF35CULL,
		0x9F4A848C00391E31ULL,
		0x6B94931CD03BC8D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x544D49B2FD5D646EULL,
		0xAFC4FE8C84416A09ULL,
		0x470372DC909AC59FULL,
		0x28583A52AE4A6C9FULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
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