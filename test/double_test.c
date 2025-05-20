#include "tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Double Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD54EE664F91DDCDBULL,
		0x1A9CC88AF6969813ULL,
		0xCC973C4D783C8131ULL,
		0x052BB973A43C272CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xAA9DCCC9F23BB9B6ULL,
		0x35399115ED2D3027ULL,
		0x992E789AF0790262ULL,
		0x0A5772E748784E59ULL
	}};
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FD98F7611C6CF57ULL,
		0x4D63A13F8C0B3C06ULL,
		0x36F2F66E03B2206DULL,
		0x5B9153EA1D29D768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB31EEC238D9EC1ULL,
		0x9AC7427F1816780CULL,
		0x6DE5ECDC076440DAULL,
		0x3722A7D43A53AED0ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB2696D8C5CA0E18ULL,
		0x0538A723CF4A7527ULL,
		0x7D978BF2386B829DULL,
		0x3653E07C08D98578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564D2DB18B941C30ULL,
		0x0A714E479E94EA4FULL,
		0xFB2F17E470D7053AULL,
		0x6CA7C0F811B30AF0ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBE8C8792D241A48ULL,
		0x42DFE655FC47DE23ULL,
		0x40CD2431218D9325ULL,
		0x2B6A0BA86DF6D350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D190F25A483490ULL,
		0x85BFCCABF88FBC47ULL,
		0x819A4862431B264AULL,
		0x56D41750DBEDA6A0ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE7F69CDEB62C186ULL,
		0x2185BAB52D898EEBULL,
		0x0852BD59C413B8A3ULL,
		0x1596DD4500ED4B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCFED39BD6C5830CULL,
		0x430B756A5B131DD7ULL,
		0x10A57AB388277146ULL,
		0x2B2DBA8A01DA9736ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB965DC9414B799ULL,
		0xB64F5849F5513406ULL,
		0xA82E1404585B12D9ULL,
		0x3BDBDED318428707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF72CBB928296F32ULL,
		0x6C9EB093EAA2680DULL,
		0x505C2808B0B625B3ULL,
		0x77B7BDA630850E0FULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE409AFF59EA85207ULL,
		0x945D359857ABF6E8ULL,
		0xB4146F0488286926ULL,
		0x231D2FF010D25FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8135FEB3D50A40EULL,
		0x28BA6B30AF57EDD1ULL,
		0x6828DE091050D24DULL,
		0x463A5FE021A4BF6DULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303CB2073B4051C6ULL,
		0x34EA745DDDA9766CULL,
		0xF4EF8C4EA4863590ULL,
		0x6378C483CE711BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6079640E7680A39FULL,
		0x69D4E8BBBB52ECD8ULL,
		0xE9DF189D490C6B20ULL,
		0x46F189079CE23767ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7ACDCBC8B453693ULL,
		0x49D34796CB322C6FULL,
		0x500CBB478CC439FEULL,
		0x5F4AC36008166126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF59B979168A6D39ULL,
		0x93A68F2D966458DFULL,
		0xA019768F198873FCULL,
		0x3E9586C0102CC24CULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69657CF17473999ULL,
		0xACC83509421A6A03ULL,
		0x0F3B44D9E13C0779ULL,
		0x0D12EB2245BC609CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D2CAF9E2E8E7332ULL,
		0x59906A128434D407ULL,
		0x1E7689B3C2780EF3ULL,
		0x1A25D6448B78C138ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC0CF63AA3AEACD0ULL,
		0xC28BEC50831991E7ULL,
		0x6D6C183CF74BEF91ULL,
		0x5601938BA1796390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9819EC75475D59B3ULL,
		0x8517D8A1063323CFULL,
		0xDAD83079EE97DF23ULL,
		0x2C03271742F2C720ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC28F4DC56052E41ULL,
		0x0B69AA44B1E7BA9CULL,
		0x560A6128316D0B66ULL,
		0x5FD40C1D4AB68A6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5851E9B8AC0A5C95ULL,
		0x16D3548963CF7539ULL,
		0xAC14C25062DA16CCULL,
		0x3FA8183A956D14D4ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE15FE2550E6632D8ULL,
		0x62CDA59DDAA51733ULL,
		0xC080AB588059D6F3ULL,
		0x59AB93CFD14DBDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BFC4AA1CCC65C3ULL,
		0xC59B4B3BB54A2E67ULL,
		0x810156B100B3ADE6ULL,
		0x3357279FA29B7B61ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x863A56A395370E9DULL,
		0x81920F18D31E86BAULL,
		0xD907038D03D9A48EULL,
		0x6BCE791C58716C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C74AD472A6E1D4DULL,
		0x03241E31A63D0D75ULL,
		0xB20E071A07B3491DULL,
		0x579CF238B0E2D907ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93B1E319A26D66C7ULL,
		0x1DA4CBC9927741B8ULL,
		0x78D0A39C6A8D0C32ULL,
		0x581E797BA962CB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2763C63344DACDA1ULL,
		0x3B49979324EE8371ULL,
		0xF1A14738D51A1864ULL,
		0x303CF2F752C59634ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95A2C35FED23ABE7ULL,
		0x131AC6B2EA50C3FDULL,
		0xFDCCF9890B7EFDD2ULL,
		0x003F62219256ADA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4586BFDA4757CEULL,
		0x26358D65D4A187FBULL,
		0xFB99F31216FDFBA4ULL,
		0x007EC44324AD5B51ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x986C48FD7238D727ULL,
		0x8C6BED90BF5C8974ULL,
		0x383AEFB4E1F252F3ULL,
		0x0F03D684885FB7A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D891FAE471AE4EULL,
		0x18D7DB217EB912E9ULL,
		0x7075DF69C3E4A5E7ULL,
		0x1E07AD0910BF6F52ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EC7AAA077146BE1ULL,
		0xE4278AB6A71FDA6FULL,
		0x9BFDE7364363BE71ULL,
		0x5C2525345A295534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD8F5540EE28D7D5ULL,
		0xC84F156D4E3FB4DEULL,
		0x37FBCE6C86C77CE3ULL,
		0x384A4A68B452AA69ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92BC228578F5CE0AULL,
		0x41F43F65C7FD87DCULL,
		0x50BCDE087D94C204ULL,
		0x52E859A5FF2FC796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2578450AF1EB9C27ULL,
		0x83E87ECB8FFB0FB9ULL,
		0xA179BC10FB298408ULL,
		0x25D0B34BFE5F8F2CULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x176E36EF0F9279DCULL,
		0x837BC219907E5ADCULL,
		0xFBB7935E2401AFA0ULL,
		0x41BE877EC83C82E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EDC6DDE1F24F3CBULL,
		0x06F7843320FCB5B8ULL,
		0xF76F26BC48035F41ULL,
		0x037D0EFD907905D3ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE11FB3576A4B606ULL,
		0xFA3AB43ABF613D8FULL,
		0xB9183AFAF9DA3E04ULL,
		0x23C03DDD688A9B94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C23F66AED496C0CULL,
		0xF47568757EC27B1FULL,
		0x723075F5F3B47C09ULL,
		0x47807BBAD1153729ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x395C5E2D8083BA3EULL,
		0x2BB30E4834F24232ULL,
		0xEEC61CB37149D485ULL,
		0x5360AC01277D2000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72B8BC5B0107748FULL,
		0x57661C9069E48464ULL,
		0xDD8C3966E293A90AULL,
		0x26C158024EFA4001ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF52F58E2F28073DULL,
		0x8F9DC462A50E3819ULL,
		0x5FC351FC1E5D6C98ULL,
		0x1B02FCA238C05DCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA5EB1C5E500E7AULL,
		0x1F3B88C54A1C7033ULL,
		0xBF86A3F83CBAD931ULL,
		0x3605F9447180BB96ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F06E645359D6D45ULL,
		0x83548791B90748FAULL,
		0x38E147FA7CEDE8F6ULL,
		0x3FF44C6633DF8904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0DCC8A6B3ADA8AULL,
		0x06A90F23720E91F4ULL,
		0x71C28FF4F9DBD1EDULL,
		0x7FE898CC67BF1208ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA286803D06FD3562ULL,
		0x3ABD99C19978CFAFULL,
		0x657CB5CEF3172672ULL,
		0x0AA6254B6DCBF554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x450D007A0DFA6AC4ULL,
		0x757B338332F19F5FULL,
		0xCAF96B9DE62E4CE4ULL,
		0x154C4A96DB97EAA8ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8497FB9FA0FFC84ULL,
		0xE5326DD94288A1F8ULL,
		0xB873C4359B71C62DULL,
		0x41C9ED7CC88082C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF092FF73F41FF91BULL,
		0xCA64DBB2851143F1ULL,
		0x70E7886B36E38C5BULL,
		0x0393DAF991010581ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F654E122309192FULL,
		0x19E0FE5BB10B21AAULL,
		0x240DD154673D8D75ULL,
		0x19C96C24F7608E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECA9C244612325EULL,
		0x33C1FCB762164355ULL,
		0x481BA2A8CE7B1AEAULL,
		0x3392D849EEC11C1EULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2209FA0B737C9F7ULL,
		0x088CE092E0144848ULL,
		0xAFA325E288AB5310ULL,
		0x160547D605E0603DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4413F416E6F93EEULL,
		0x1119C125C0289091ULL,
		0x5F464BC51156A620ULL,
		0x2C0A8FAC0BC0C07BULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49643D9442FF53E9ULL,
		0x9A8858CE84116076ULL,
		0xED23925383C120ABULL,
		0x515352A2DF136AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C87B2885FEA7E5ULL,
		0x3510B19D0822C0ECULL,
		0xDA4724A707824157ULL,
		0x22A6A545BE26D573ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB2AEDA9E689361CULL,
		0x2300DCE186131461ULL,
		0x5EA0210EF13F6590ULL,
		0x3846A178AAC0F649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5655DB53CD126C38ULL,
		0x4601B9C30C2628C3ULL,
		0xBD40421DE27ECB20ULL,
		0x708D42F15581EC92ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95AC5991E595DDC6ULL,
		0xF45E2B9A0E35A83AULL,
		0x4E240019C22EAD9BULL,
		0x25623D3F2C1C2441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B58B323CB2BBB8CULL,
		0xE8BC57341C6B5075ULL,
		0x9C480033845D5B37ULL,
		0x4AC47A7E58384882ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x079280C3F06B4971ULL,
		0x7B724F501B971BBFULL,
		0x6F1FB5058FA56B5DULL,
		0x3403D86C2CF2C2A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F250187E0D692E2ULL,
		0xF6E49EA0372E377EULL,
		0xDE3F6A0B1F4AD6BAULL,
		0x6807B0D859E58550ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A5D24320133CD09ULL,
		0x5E338B56A477CFF8ULL,
		0xA313795B36DA1F0EULL,
		0x6C16AD848DF6755CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94BA486402679A25ULL,
		0xBC6716AD48EF9FF0ULL,
		0x4626F2B66DB43E1CULL,
		0x582D5B091BECEAB9ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADA217C674934658ULL,
		0x1EA84B9B191AD99AULL,
		0xE5ECAC9B8DE95F67ULL,
		0x3191E7499FA63301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B442F8CE9268CB0ULL,
		0x3D5097363235B335ULL,
		0xCBD959371BD2BECEULL,
		0x6323CE933F4C6603ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9332F0D1AB7726BULL,
		0x1F2F12FE26B8EF6CULL,
		0x40A68A503A2E2FFEULL,
		0x34B67002CFCE30E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2665E1A356EE4D6ULL,
		0x3E5E25FC4D71DED9ULL,
		0x814D14A0745C5FFCULL,
		0x696CE0059F9C61C0ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1570AB6C5065307CULL,
		0xB1D8C7AAEF952B6AULL,
		0xA190A38CCA66A600ULL,
		0x1DBA92D6A33E0ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE156D8A0CA60F8ULL,
		0x63B18F55DF2A56D4ULL,
		0x4321471994CD4C01ULL,
		0x3B7525AD467C1D95ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE8215FD3CEDABAEULL,
		0x3AA0433EDACAEEA0ULL,
		0xBAC06787E44044BEULL,
		0x1E1D266A81AAE8B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D042BFA79DB575CULL,
		0x7540867DB595DD41ULL,
		0x7580CF0FC880897CULL,
		0x3C3A4CD50355D163ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08B6A632956AD868ULL,
		0x8E6C57C0ED21B371ULL,
		0x62280FFE87A2B4B5ULL,
		0x67AEA471CF5E8440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x116D4C652AD5B0E3ULL,
		0x1CD8AF81DA4366E2ULL,
		0xC4501FFD0F45696BULL,
		0x4F5D48E39EBD0880ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BF92B766A4811A9ULL,
		0x3880330B798A9368ULL,
		0xDC72DBFFD4CCDFF7ULL,
		0x24764ECE8DAF2DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F256ECD4902352ULL,
		0x71006616F31526D0ULL,
		0xB8E5B7FFA999BFEEULL,
		0x48EC9D9D1B5E5B57ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD57324021CA594D8ULL,
		0xBF73DB032546417EULL,
		0xB8DCDB1E442EB532ULL,
		0x5ACEC1D54F87CD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAE64804394B29C3ULL,
		0x7EE7B6064A8C82FDULL,
		0x71B9B63C885D6A65ULL,
		0x359D83AA9F0F9AB1ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA21AF014CA20A34AULL,
		0xA314E5287DC183BCULL,
		0xDE62436AC6FCB405ULL,
		0x525B6A96F4FF83B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4435E029944146A7ULL,
		0x4629CA50FB830779ULL,
		0xBCC486D58DF9680BULL,
		0x24B6D52DE9FF0769ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54D5AA84C58FDC05ULL,
		0x3C5A7757A7D0A23FULL,
		0xE80BFD2A90F5E52BULL,
		0x3F33F259AB423335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AB55098B1FB80AULL,
		0x78B4EEAF4FA1447EULL,
		0xD017FA5521EBCA56ULL,
		0x7E67E4B35684666BULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8160FC6B7F42298FULL,
		0x678200BC78784069ULL,
		0xEA3E1A34D8DC9F8DULL,
		0x40E52AEA0A4696B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C1F8D6FE845331ULL,
		0xCF040178F0F080D3ULL,
		0xD47C3469B1B93F1AULL,
		0x01CA55D4148D2D6BULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x194779262F8D0800ULL,
		0x3516BD189FF84C87ULL,
		0xA2C5101682E92587ULL,
		0x4DAB6AA21FC87DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x328EF24C5F1A1013ULL,
		0x6A2D7A313FF0990EULL,
		0x458A202D05D24B0EULL,
		0x1B56D5443F90FB4BULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F0AA9DBC7137D00ULL,
		0x3245892D287A3077ULL,
		0x11B41202284E6A39ULL,
		0x352D059BB8BD06DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E1553B78E26FA00ULL,
		0x648B125A50F460EEULL,
		0x23682404509CD472ULL,
		0x6A5A0B37717A0DB4ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAFE664A032CBBA3ULL,
		0xDBAFFA9585F5D283ULL,
		0x221A77092A9863CDULL,
		0x7700DF7327640950ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5FCCC9406597759ULL,
		0xB75FF52B0BEBA507ULL,
		0x4434EE125530C79BULL,
		0x6E01BEE64EC812A0ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D9763E025DE4167ULL,
		0xB94687B862F9EC4BULL,
		0x8209CA5F0B093A67ULL,
		0x051974B266E654B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2EC7C04BBC82CEULL,
		0x728D0F70C5F3D896ULL,
		0x041394BE161274CFULL,
		0x0A32E964CDCCA96DULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A1CB03DB8F0B734ULL,
		0x36624EE5C5EB98C5ULL,
		0xE4FA1A17DD8165BAULL,
		0x57DA20D8FD6EA2ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB439607B71E16E7BULL,
		0x6CC49DCB8BD7318AULL,
		0xC9F4342FBB02CB74ULL,
		0x2FB441B1FADD4559ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F9161B84E62C7B3ULL,
		0x2BBDDA30D90DD0D6ULL,
		0x4E7879995F905DA1ULL,
		0x406C0EE38067C1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F22C3709CC58F79ULL,
		0x577BB461B21BA1ADULL,
		0x9CF0F332BF20BB42ULL,
		0x00D81DC700CF83D6ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAD61FD75E9CD0C4ULL,
		0x2244DA24F5E7DE83ULL,
		0x3A4A360FCC9838D1ULL,
		0x2B94F833D0AA6D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75AC3FAEBD39A188ULL,
		0x4489B449EBCFBD07ULL,
		0x74946C1F993071A2ULL,
		0x5729F067A154DA70ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F782BBFEF8580E6ULL,
		0xAA4AABFF280B346BULL,
		0x142DF855BAC286D3ULL,
		0x70D3082261079F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF0577FDF0B01DFULL,
		0x549557FE501668D6ULL,
		0x285BF0AB75850DA7ULL,
		0x61A61044C20F3F3AULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA087BFD997B58F41ULL,
		0x562D25E1FFB80379ULL,
		0x4B0D64BB211BFD48ULL,
		0x539F0D7874BFFA8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410F7FB32F6B1E95ULL,
		0xAC5A4BC3FF7006F3ULL,
		0x961AC9764237FA90ULL,
		0x273E1AF0E97FF516ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11D7EB6596A2C3A0ULL,
		0x2DF3D11E5EE4E1D0ULL,
		0x4EB4098601955CB7ULL,
		0x7C1B8FE22F74BCE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AFD6CB2D458753ULL,
		0x5BE7A23CBDC9C3A0ULL,
		0x9D68130C032AB96EULL,
		0x78371FC45EE979D0ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FCE76BECC6A08E5ULL,
		0x56D6F1AF95A97A66ULL,
		0x763737FE7DBCB857ULL,
		0x332871806B2F4ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9CED7D98D411CAULL,
		0xADADE35F2B52F4CCULL,
		0xEC6E6FFCFB7970AEULL,
		0x6650E300D65E9DB0ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE239BD785ABB26E5ULL,
		0x9E702AAD03AEB5C7ULL,
		0x5EDC9EDD7B05F78EULL,
		0x2637EC28DEBEBE8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4737AF0B5764DCAULL,
		0x3CE0555A075D6B8FULL,
		0xBDB93DBAF60BEF1DULL,
		0x4C6FD851BD7D7D14ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73B16E856C954517ULL,
		0xE908597CF145856CULL,
		0xE4DE634A2993306EULL,
		0x55ECDC54BD87D535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE762DD0AD92A8A41ULL,
		0xD210B2F9E28B0AD8ULL,
		0xC9BCC694532660DDULL,
		0x2BD9B8A97B0FAA6BULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3A47E237C38D091ULL,
		0xA9870EEEE0FFF679ULL,
		0xAA703E5114A7785FULL,
		0x2B9A77358E8E486FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC748FC46F871A122ULL,
		0x530E1DDDC1FFECF3ULL,
		0x54E07CA2294EF0BFULL,
		0x5734EE6B1D1C90DFULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1FAC70916F87DD2ULL,
		0x98E94639CA52CABBULL,
		0x16205DAC209A20E1ULL,
		0x10482560F0D6E8F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43F58E122DF0FBA4ULL,
		0x31D28C7394A59577ULL,
		0x2C40BB58413441C3ULL,
		0x20904AC1E1ADD1E0ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD52E968458AA9150ULL,
		0x6FE6B6E1343DA7C5ULL,
		0xBF5BCDA2579DFD37ULL,
		0x26EA83A0E0CC9AA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5D2D08B15522A0ULL,
		0xDFCD6DC2687B4F8BULL,
		0x7EB79B44AF3BFA6EULL,
		0x4DD50741C1993543ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D244D9935993008ULL,
		0xB947467B23CF222FULL,
		0xB8ACEECB94E656C0ULL,
		0x663B0682742AE3F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A489B326B326023ULL,
		0x728E8CF6479E445EULL,
		0x7159DD9729CCAD81ULL,
		0x4C760D04E855C7E5ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x345A4FDE8F83E993ULL,
		0xAC200881EA2A81ADULL,
		0x47B46558CDDE48D4ULL,
		0x782DB556D38F35A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B49FBD1F07D339ULL,
		0x58401103D455035AULL,
		0x8F68CAB19BBC91A9ULL,
		0x705B6AADA71E6B40ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FBA55ABCE6AF5B9ULL,
		0x67E0FDDFD891BB59ULL,
		0x8D607D879CAB292AULL,
		0x6D10F4EDE20EEFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF74AB579CD5EB85ULL,
		0xCFC1FBBFB12376B2ULL,
		0x1AC0FB0F39565254ULL,
		0x5A21E9DBC41DDFE7ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB3CA49B3F5DEE28ULL,
		0xDBB8DBD1038A089DULL,
		0x12284B172A1300A9ULL,
		0x4F16AD8C281D1742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67949367EBBDC63ULL,
		0xB771B7A20714113BULL,
		0x2450962E54260153ULL,
		0x1E2D5B18503A2E84ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2047161A2C5FB03FULL,
		0x76FF77D435CE5040ULL,
		0x2A1348B5B5C7CB0BULL,
		0x40F2A6F1669A2E0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408E2C3458BF6091ULL,
		0xEDFEEFA86B9CA080ULL,
		0x5426916B6B8F9616ULL,
		0x01E54DE2CD345C1EULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE93712E82BDB6944ULL,
		0x402212D56D789309ULL,
		0x34BF383C08581D3AULL,
		0x6B060D888399D38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26E25D057B6D29BULL,
		0x804425AADAF12613ULL,
		0x697E707810B03A74ULL,
		0x560C1B110733A71EULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x583F6D3F8E99CF65ULL,
		0x67C08A71CBBBDFA0ULL,
		0x0AD1BB5B402EC22EULL,
		0x53955A4EBBFCD23CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB07EDA7F1D339EDDULL,
		0xCF8114E39777BF40ULL,
		0x15A376B6805D845CULL,
		0x272AB49D77F9A478ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE429B1EA3B83077AULL,
		0x0743C956DEFC7195ULL,
		0xA6437FE85DF093D7ULL,
		0x2FB0AD1DBF5ED18DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC85363D477060EF4ULL,
		0x0E8792ADBDF8E32BULL,
		0x4C86FFD0BBE127AEULL,
		0x5F615A3B7EBDA31BULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD54132684BFF3C02ULL,
		0x3A78A537DBA0D91BULL,
		0x00265E4DB7B49D65ULL,
		0x2B90B915AA1D1787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8264D097FE7804ULL,
		0x74F14A6FB741B237ULL,
		0x004CBC9B6F693ACAULL,
		0x5721722B543A2F0EULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1E7DFD06867C62BULL,
		0x6AB00ECFC1B7FA75ULL,
		0xECB49187230ECC30ULL,
		0x252CA1CF4FB63D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43CFBFA0D0CF8C56ULL,
		0xD5601D9F836FF4EBULL,
		0xD969230E461D9860ULL,
		0x4A59439E9F6C7A79ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22FA2C9C76DA221FULL,
		0x3CD78EC816DD3186ULL,
		0xDCCCDC88D939F67AULL,
		0x2FAC5F7698C0D0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45F45938EDB4443EULL,
		0x79AF1D902DBA630CULL,
		0xB999B911B273ECF4ULL,
		0x5F58BEED3181A1EFULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D8DB29AA663FF50ULL,
		0xAC8D287B80EF17EEULL,
		0x928BF9D54139D679ULL,
		0x7DDCB68FD041E037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1B65354CC7FEB3ULL,
		0x591A50F701DE2FDCULL,
		0x2517F3AA8273ACF3ULL,
		0x7BB96D1FA083C06FULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x402B4B5858F855ABULL,
		0x3492AA8D7DDEE253ULL,
		0xC3C4E61D2F9EDDA5ULL,
		0x20FF580FA6DC02CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805696B0B1F0AB56ULL,
		0x6925551AFBBDC4A6ULL,
		0x8789CC3A5F3DBB4AULL,
		0x41FEB01F4DB80597ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C575084B5082CFAULL,
		0x4F668DF4F26F02F1ULL,
		0xA30FFD201F95D9C4ULL,
		0x322F2DB3E2AF6643ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8AEA1096A1059F4ULL,
		0x9ECD1BE9E4DE05E2ULL,
		0x461FFA403F2BB388ULL,
		0x645E5B67C55ECC87ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x460605903D1244D8ULL,
		0xABBE4EB142ABDE05ULL,
		0x3D3BB2FF39B33B99ULL,
		0x6E2115AAA3AA0AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0C0B207A2489C3ULL,
		0x577C9D628557BC0AULL,
		0x7A7765FE73667733ULL,
		0x5C422B55475415C0ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD5759B812551393ULL,
		0x79EB38BC8180B53BULL,
		0x983DA82A8A9CD5EFULL,
		0x3C91E56BA95E2AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAAEB37024AA2726ULL,
		0xF3D6717903016A77ULL,
		0x307B50551539ABDEULL,
		0x7923CAD752BC556DULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9766641E90559DF5ULL,
		0x269E7E0CABE5731AULL,
		0xEFF04FB363350B3BULL,
		0x67AF490D0414A98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ECCC83D20AB3BFDULL,
		0x4D3CFC1957CAE635ULL,
		0xDFE09F66C66A1676ULL,
		0x4F5E921A08295317ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDFD6AE228ED474FULL,
		0x5677EDAEA1D33A85ULL,
		0xDBF18F0367D020E9ULL,
		0x429AEE17B299BF0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BFAD5C451DA8EB1ULL,
		0xACEFDB5D43A6750BULL,
		0xB7E31E06CFA041D2ULL,
		0x0535DC2F65337E1BULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1B67B0AF298655AULL,
		0x7B3DA939C84B1B45ULL,
		0x0A718482755630B5ULL,
		0x7A4FE5E342A57E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x836CF615E530CAC7ULL,
		0xF67B52739096368BULL,
		0x14E30904EAAC616AULL,
		0x749FCBC6854AFCEAULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68ABA92A75082197ULL,
		0x086B6E7E77F1817CULL,
		0xBE473E29F8260C95ULL,
		0x14D2A1446C697A2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1575254EA10432EULL,
		0x10D6DCFCEFE302F8ULL,
		0x7C8E7C53F04C192AULL,
		0x29A54288D8D2F457ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1E83108C44E546ULL,
		0xCACC881FC29BE443ULL,
		0xA75CF5D174A756F1ULL,
		0x08B640118EBCF0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF83D06211889CA8CULL,
		0x9599103F8537C886ULL,
		0x4EB9EBA2E94EADE3ULL,
		0x116C80231D79E185ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3383019962029CBULL,
		0x095423DEEAAD9C0BULL,
		0xDB7687DABAD10E2FULL,
		0x0A80C3FB76CF8C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67060332C405396ULL,
		0x12A847BDD55B3817ULL,
		0xB6ED0FB575A21C5EULL,
		0x150187F6ED9F18D9ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x423CCEEAF78F8113ULL,
		0x8E505136CABC61BAULL,
		0x1A66C18A0C7F399AULL,
		0x6CFAB429C7385CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84799DD5EF1F0239ULL,
		0x1CA0A26D9578C374ULL,
		0x34CD831418FE7335ULL,
		0x59F568538E70B948ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EEBF52DB0436E83ULL,
		0xF1E6545F8C604771ULL,
		0xCD659EECAE3455D4ULL,
		0x624FB85DFE9E83CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD7EA5B6086DD19ULL,
		0xE3CCA8BF18C08EE3ULL,
		0x9ACB3DD95C68ABA9ULL,
		0x449F70BBFD3D079FULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B587FDA4AC1EF1DULL,
		0x35CE15AF0FFC0837ULL,
		0xCF91AF92AA756633ULL,
		0x4DF67AE13E44BDFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36B0FFB49583DE4DULL,
		0x6B9C2B5E1FF8106FULL,
		0x9F235F2554EACC66ULL,
		0x1BECF5C27C897BFBULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECAA707F8A9FAE74ULL,
		0x72A86AEA653C8CAEULL,
		0xA5E37F365231864FULL,
		0x5AD2C9FAA9C325EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD954E0FF153F5CFBULL,
		0xE550D5D4CA79195DULL,
		0x4BC6FE6CA4630C9EULL,
		0x35A593F553864BDBULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16038F4FC1DBAF09ULL,
		0xEC8A9472E8B3D7C5ULL,
		0x49AE82DAEE307101ULL,
		0x40EF571495EDDB5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C071E9F83B75E25ULL,
		0xD91528E5D167AF8AULL,
		0x935D05B5DC60E203ULL,
		0x01DEAE292BDBB6BEULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA3238912A0C8098ULL,
		0x95ABBEB7CC49E011ULL,
		0x71693A88659C6943ULL,
		0x0BBC441BD487DEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF464712254190130ULL,
		0x2B577D6F9893C023ULL,
		0xE2D27510CB38D287ULL,
		0x17788837A90FBDC0ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6ED76624AC8DB86ULL,
		0xD7DF90361E477B1FULL,
		0x646D57FEB0E37DEAULL,
		0x48DC166516A2D578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDDAECC49591B71FULL,
		0xAFBF206C3C8EF63FULL,
		0xC8DAAFFD61C6FBD5ULL,
		0x11B82CCA2D45AAF0ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25099223D2112FF1ULL,
		0xBCC63CA34AB8FF5BULL,
		0xBE629591FFBD0554ULL,
		0x50EE827870CF1936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A132447A4225FF5ULL,
		0x798C79469571FEB6ULL,
		0x7CC52B23FF7A0AA9ULL,
		0x21DD04F0E19E326DULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC6229207EEF7178ULL,
		0xE4C111D2CF59BC0DULL,
		0xDD9632F221C885ABULL,
		0x5582A3871BAF4271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C45240FDDEE303ULL,
		0xC98223A59EB3781BULL,
		0xBB2C65E443910B57ULL,
		0x2B05470E375E84E3ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FBFD59B7935AD26ULL,
		0x97FFF346231D5079ULL,
		0x436684971BCD5C52ULL,
		0x1236CF484BE46454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7FAB36F26B5A4CULL,
		0x2FFFE68C463AA0F3ULL,
		0x86CD092E379AB8A5ULL,
		0x246D9E9097C8C8A8ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FB0B39E9423ED1DULL,
		0xC000904ED5C734CFULL,
		0x8189C5DE04E2219CULL,
		0x1F259A2D4D7EC44AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF61673D2847DA3AULL,
		0x8001209DAB8E699EULL,
		0x03138BBC09C44339ULL,
		0x3E4B345A9AFD8895ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4420FD73CBD6CE7EULL,
		0x09B1EEA34C2ACB97ULL,
		0x23AE75D487D2EACCULL,
		0x6F00C57B6925B763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8841FAE797AD9D0FULL,
		0x1363DD469855972EULL,
		0x475CEBA90FA5D598ULL,
		0x5E018AF6D24B6EC6ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC0C09D71C14B984ULL,
		0x5C1A307D3836457EULL,
		0xC9B023B5FC951BE8ULL,
		0x27BF23177F0E34D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x581813AE38297308ULL,
		0xB83460FA706C8AFDULL,
		0x9360476BF92A37D0ULL,
		0x4F7E462EFE1C69ABULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x178D77F8AC1B4966ULL,
		0x178938E23DFD7358ULL,
		0x7A0EFFF6E96F7BAFULL,
		0x7F6B89637A736DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F1AEFF1583692DFULL,
		0x2F1271C47BFAE6B0ULL,
		0xF41DFFEDD2DEF75EULL,
		0x7ED712C6F4E6DB70ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38C6B4F6AC94C1A8ULL,
		0xE0CCC9DAA36E3A35ULL,
		0x2F46FD34D83054D9ULL,
		0x3586048C64E0D386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x718D69ED59298350ULL,
		0xC19993B546DC746AULL,
		0x5E8DFA69B060A9B3ULL,
		0x6B0C0918C9C1A70CULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD69BFB770D3856B2ULL,
		0xEE87F150B064CC64ULL,
		0x2987091759D2AD0EULL,
		0x384CFEB651148620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD37F6EE1A70AD64ULL,
		0xDD0FE2A160C998C9ULL,
		0x530E122EB3A55A1DULL,
		0x7099FD6CA2290C40ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x537B15AEA4190292ULL,
		0x445500A5CCD78E5BULL,
		0x5B0D96481D786C2CULL,
		0x1F927234C9235934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F62B5D48320524ULL,
		0x88AA014B99AF1CB6ULL,
		0xB61B2C903AF0D858ULL,
		0x3F24E4699246B268ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB2D7CE785D02CEAULL,
		0xFED520E0C12E0C8CULL,
		0x38E0C1FFDAA36D46ULL,
		0x47821A120C746393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB65AF9CF0BA059E7ULL,
		0xFDAA41C1825C1919ULL,
		0x71C183FFB546DA8DULL,
		0x0F04342418E8C726ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AEBB89A78EE22B8ULL,
		0xBD039D7E042BF6E9ULL,
		0x4F0F2FC87017C11FULL,
		0x59FA0ECED12CCBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D77134F1DC4583ULL,
		0x7A073AFC0857EDD2ULL,
		0x9E1E5F90E02F823FULL,
		0x33F41D9DA259979CULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}