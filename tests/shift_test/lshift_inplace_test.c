#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xFAAFC92C4008722EULL,
		0xB25322120EA47811ULL,
		0x7774090BDC561940ULL,
		0x7C639786A54314B4ULL,
		0x8C3B870CD173E7F6ULL,
		0x39B406860C6A6D96ULL,
		0x5DB8584D15B0123EULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4962004391700000ULL,
		0x10907523C08FD57EULL,
		0x485EE2B0CA059299ULL,
		0xBC352A18A5A3BBA0ULL,
		0x38668B9F3FB3E31CULL,
		0x343063536CB461DCULL,
		0xC268AD8091F1CDA0ULL,
		0x000000000002EDC2ULL
	}};
	int shift = 19;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC73897DDE1E58300ULL,
		0xD02BC9BD53099BC7ULL,
		0xE2C4BFD47846BE0AULL,
		0xCF5143A68C07E4EBULL,
		0xE7A5A4C3D8F2A504ULL,
		0xCCC018AD9F519597ULL,
		0x61E707A5AE1B4C07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C266F1F1CE25F7ULL,
		0x1E11AF82B40AF26FULL,
		0xA301F93AF8B12FF5ULL,
		0xF63CA94133D450E9ULL,
		0x67D46565F9E96930ULL,
		0x6B86D301F330062BULL,
		0x000000001879C1E9ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4AAFFCB62CB6A1ULL,
		0x9C34143A69C9A380ULL,
		0x5019414C782D2834ULL,
		0x96658E2CDB14653EULL,
		0x67C48DB0B64A7DC6ULL,
		0x73E711B42A6BD181ULL,
		0x1004FBF171F5C593ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A69C9A380AC4AAULL,
		0x14C782D28349C341ULL,
		0xE2CDB14653E50194ULL,
		0xDB0B64A7DC696658ULL,
		0x1B42A6BD18167C48ULL,
		0xBF171F5C59373E71ULL,
		0x000000000001004FULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E5A862789991D0EULL,
		0x254F63151BFFD866ULL,
		0xB30188A7ED4D6ECDULL,
		0x4E9A6C19FF327FFFULL,
		0x1BB292AEB7853212ULL,
		0xAB7AF2FBF52D2010ULL,
		0xDE42EA20AE68E639ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A37FFB0CD3CB50CULL,
		0x4FDA9ADD9A4A9EC6ULL,
		0x33FE64FFFF660311ULL,
		0x5D6F0A64249D34D8ULL,
		0xF7EA5A4020376525ULL,
		0x415CD1CC7356F5E5ULL,
		0x0000000001BC85D4ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75671DAE585B7DAFULL,
		0x6459A7A79DE7C673ULL,
		0xAA4B31BA6C2EC6E8ULL,
		0x7C4AEEA8F0DBEBFBULL,
		0x7514C4360705F950ULL,
		0x1D5D72B82B01F318ULL,
		0x83DD219B6273F4CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669E9E779F19CDD5ULL,
		0x2CC6E9B0BB1BA191ULL,
		0x2BBAA3C36FAFEEA9ULL,
		0x5310D81C17E541F1ULL,
		0x75CAE0AC07CC61D4ULL,
		0x74866D89CFD32875ULL,
		0x000000000000020FULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x142E51FDEA99F4BBULL,
		0xA6C7A7C5E5475D09ULL,
		0x02899D1D8F51F9B8ULL,
		0xB3E30D7BA4C63F4DULL,
		0xED2FD38F8A696F61ULL,
		0x9B0E4DC7586E6EA7ULL,
		0xB44114B5DF78C789ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA12285CA3FBD53ULL,
		0x3F3714D8F4F8BCA8ULL,
		0xC7E9A05133A3B1EAULL,
		0x2DEC367C61AF7498ULL,
		0xCDD4FDA5FA71F14DULL,
		0x18F13361C9B8EB0DULL,
		0x000016882296BBEFULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2AB4AAAF8EDC2E4ULL,
		0xE2372B1A99C885F4ULL,
		0x5F5E4B386866D332ULL,
		0xF062FF63F9C143FFULL,
		0x6FD0C139AA9668A6ULL,
		0x2D03BA4ED849AFAAULL,
		0x8A08D35DF9804A5DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC885F4F2AB4AAAF8ULL,
		0x66D332E2372B1A99ULL,
		0xC143FF5F5E4B3868ULL,
		0x9668A6F062FF63F9ULL,
		0x49AFAA6FD0C139AAULL,
		0x804A5D2D03BA4ED8ULL,
		0x0000008A08D35DF9ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CDE8913D2C9B629ULL,
		0xCDA5DBEF1980425EULL,
		0xEBC343D4DBF4CC39ULL,
		0x4006DBD85C262BC6ULL,
		0x0DBBA2667B0615F3ULL,
		0x5D608F42AA5A7D27ULL,
		0x6B0FA04725554530ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F0E6F4489E964DBULL,
		0x1CE6D2EDF78CC021ULL,
		0xE375E1A1EA6DFA66ULL,
		0xF9A0036DEC2E1315ULL,
		0x9386DDD1333D830AULL,
		0x982EB047A1552D3EULL,
		0x003587D02392AAA2ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC926D4ABBB477AE6ULL,
		0xA5425A934B8249FCULL,
		0x0EC4E8BEB4A50A2CULL,
		0x285089ADE8B4F29CULL,
		0x92E77F27F67BB6DCULL,
		0x31EF6E4968F12624ULL,
		0xD04F4B1668E277C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A84B526970493F9ULL,
		0x1D89D17D694A1459ULL,
		0x50A1135BD169E538ULL,
		0x25CEFE4FECF76DB8ULL,
		0x63DEDC92D1E24C49ULL,
		0xA09E962CD1C4EF8AULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DABFFEA5EC62B9CULL,
		0x93218817308212B4ULL,
		0x49064C7291C4AA1AULL,
		0xB07D99C49D28D4A2ULL,
		0x132B4899998F6435ULL,
		0x974D875D54833F4BULL,
		0xA21C3701EABB8492ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD276AFFFA97B18AULL,
		0x86A4C86205CC2084ULL,
		0x289241931CA4712AULL,
		0x0D6C1F6671274A35ULL,
		0xD2C4CAD2266663D9ULL,
		0x24A5D361D75520CFULL,
		0x0028870DC07AAEE1ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F1EE296DD19BACAULL,
		0x65168D2DEC554D5AULL,
		0xED2DAF01FD668BCDULL,
		0x4E4C3321BC52838AULL,
		0xB3E3D5A6BEBB28E1ULL,
		0x3C4020B62651F203ULL,
		0x9DE612F2B399C886ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47E3DC52DBA3375ULL,
		0x9ACA2D1A5BD8AA9AULL,
		0x15DA5B5E03FACD17ULL,
		0xC29C98664378A507ULL,
		0x0767C7AB4D7D7651ULL,
		0x0C7880416C4CA3E4ULL,
		0x013BCC25E5673391ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4E207632E481A4DULL,
		0x2EB175C0D5F093DBULL,
		0xEF8AC9717D402E8CULL,
		0x61ADEC8F0446844DULL,
		0x1B0A6A69F6DA98A2ULL,
		0x5DC1BDD16A653616ULL,
		0x837D226EDC0FE839ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF849EDFA7103B19ULL,
		0xEA017461758BAE06ULL,
		0x2234226F7C564B8BULL,
		0xB6D4C5130D6F6478ULL,
		0x5329B0B0D853534FULL,
		0xE07F41CAEE0DEE8BULL,
		0x000000041BE91376ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59861F8E3D81A53DULL,
		0xC69CD74E24883F2CULL,
		0x38FB1A63A85F9595ULL,
		0xF3E80BE205A0FB4BULL,
		0xB2EF7DC22E270CEFULL,
		0xCBDD1AC079C585EFULL,
		0x0B5FBB426227AA86ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9107E58B30C3F1C7ULL,
		0x0BF2B2B8D39AE9C4ULL,
		0xB41F69671F634C75ULL,
		0xC4E19DFE7D017C40ULL,
		0x38B0BDF65DEFB845ULL,
		0x44F550D97BA3580FULL,
		0x000000016BF7684CULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31ED105D93C5D7C6ULL,
		0x908CF5EA1B991FB5ULL,
		0x591DAC0C6B0013D8ULL,
		0x18B5D5A83A6F7007ULL,
		0x3AB596B7D40FAEE9ULL,
		0x2BC43F9E5D481BF7ULL,
		0x566A3999EBF96AD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A63DA20BB278BAULL,
		0x7B12119EBD437323ULL,
		0x00EB23B5818D6002ULL,
		0xDD2316BAB5074DEEULL,
		0x7EE756B2D6FA81F5ULL,
		0x5AE57887F3CBA903ULL,
		0x000ACD47333D7F2DULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF216D697C2BA253DULL,
		0x8E1ADDBCC36F1571ULL,
		0xA9553B9E0B95E2B3ULL,
		0x12E4AF01B164CF55ULL,
		0x8187AD03CD476036ULL,
		0x9929D91EF7E098CCULL,
		0x3845B12478C274C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x986DE2AE3E42DAD2ULL,
		0xC172BC5671C35BB7ULL,
		0x362C99EAB52AA773ULL,
		0x79A8EC06C25C95E0ULL,
		0xDEFC13199030F5A0ULL,
		0x8F184E98D3253B23ULL,
		0x000000000708B624ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F8EB4B528346953ULL,
		0xFE680CD3E7CB61BEULL,
		0xD890A623CBE5D52EULL,
		0xAA23608E02BD53ABULL,
		0x6E87FEE18DE7CF47ULL,
		0x97701FD521DE6864ULL,
		0xBDBA01E0D4C16405ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7CB61BE3F8EB4B5ULL,
		0xCBE5D52EFE680CD3ULL,
		0x02BD53ABD890A623ULL,
		0x8DE7CF47AA23608EULL,
		0x21DE68646E87FEE1ULL,
		0xD4C1640597701FD5ULL,
		0x00000000BDBA01E0ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC79FAD9A8676D2FDULL,
		0x2D90F2502837891AULL,
		0x7674C6C8CBD193E5ULL,
		0x7E7D3AFE0B6EAD42ULL,
		0x6566B87324954930ULL,
		0xA72BBCB65705620EULL,
		0xCC90B83D550361D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2502837891AC79FAULL,
		0x6C8CBD193E52D90FULL,
		0xAFE0B6EAD427674CULL,
		0x873249549307E7D3ULL,
		0xCB65705620E6566BULL,
		0x83D550361D5A72BBULL,
		0x00000000000CC90BULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2864F2E8DEF9978ULL,
		0xC6C5DF2F57ADB9B6ULL,
		0xA6F631BF04C1220AULL,
		0xA59FAAB1FA60F351ULL,
		0x3A86BE13F9921672ULL,
		0x85AF448429B2A9B3ULL,
		0x1728982C3D9B8A47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9B6D2864F2E8DEFULL,
		0x220AC6C5DF2F57ADULL,
		0xF351A6F631BF04C1ULL,
		0x1672A59FAAB1FA60ULL,
		0xA9B33A86BE13F992ULL,
		0x8A4785AF448429B2ULL,
		0x00001728982C3D9BULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x362093FF9733D8E0ULL,
		0xAFE0E71D6674A193ULL,
		0x6108B1263C55C6C2ULL,
		0x6F0CB30549043D65ULL,
		0x946BF41D5D6B0D44ULL,
		0xF83016F468E83411ULL,
		0x29BDD6220B3D3025ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7599D2864CD8824ULL,
		0x498F1571B0ABF839ULL,
		0xC152410F5958422CULL,
		0x07575AC3511BC32CULL,
		0xBD1A3A0D04651AFDULL,
		0x8882CF4C097E0C05ULL,
		0x00000000000A6F75ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF425ECDE837FEDA0ULL,
		0xB3789355F67AFBBEULL,
		0xC1867C3B690737D1ULL,
		0xFDA47537C7C75B44ULL,
		0x9E81A2B8D2B85123ULL,
		0x397D3EAFCCE2C82EULL,
		0xD5B0A3CE4F8A8015ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67AFBBEF425ECDE8ULL,
		0x90737D1B3789355FULL,
		0x7C75B44C1867C3B6ULL,
		0x2B85123FDA47537CULL,
		0xCE2C82E9E81A2B8DULL,
		0xF8A8015397D3EAFCULL,
		0x0000000D5B0A3CE4ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6D8C4CBE799C6A2ULL,
		0x8735E665DA321ADFULL,
		0xE2F9F153BD86F19EULL,
		0x78ED67B0DE4C613CULL,
		0x9641EF190DA48984ULL,
		0xE71AA9515F9896A6ULL,
		0xD5E392B36A11A27EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC86B7F1B63132F9EULL,
		0x1BC67A1CD7999768ULL,
		0x3184F38BE7C54EF6ULL,
		0x922611E3B59EC379ULL,
		0x625A9A5907BC6436ULL,
		0x4689FB9C6AA5457EULL,
		0x000003578E4ACDA8ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45F6CB0EE8CFDB97ULL,
		0x9A90FB7F7D4ABADBULL,
		0x51940E8C361CC47DULL,
		0xFC3841E508CB56E9ULL,
		0x53A1368C7961F482ULL,
		0xED13AC2B137A01E2ULL,
		0xCA651BAE87D39339ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEB6D17DB2C3BA33ULL,
		0x311F66A43EDFDF52ULL,
		0xD5BA546503A30D87ULL,
		0x7D20BF0E10794232ULL,
		0x807894E84DA31E58ULL,
		0xE4CE7B44EB0AC4DEULL,
		0x0000329946EBA1F4ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F53B3C2DC19C3F4ULL,
		0xE94857DFAD9ACDC5ULL,
		0x3A49FE21729C1F38ULL,
		0x8B6AAD5D86A8B126ULL,
		0xF502D8DE1694ADA7ULL,
		0xA719012C1980FADFULL,
		0x171CAB4A8DC1856FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9ACDC59F53B3C2ULL,
		0x729C1F38E94857DFULL,
		0x86A8B1263A49FE21ULL,
		0x1694ADA78B6AAD5DULL,
		0x1980FADFF502D8DEULL,
		0x8DC1856FA719012CULL,
		0x00000000171CAB4AULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87FCDC69B119C114ULL,
		0x10A68253148DD3A7ULL,
		0x098B0A9D2F9B9226ULL,
		0x95D13036B6F04FE9ULL,
		0x784EDB7AC226F0B3ULL,
		0x93CE1158DB3CBB3EULL,
		0xA86CB9C615A47FFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E1FF371A6C46704ULL,
		0x98429A094C52374EULL,
		0xA4262C2A74BE6E48ULL,
		0xCE5744C0DADBC13FULL,
		0xF9E13B6DEB089BC2ULL,
		0xEE4F3845636CF2ECULL,
		0x02A1B2E7185691FFULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97E597490A882CE3ULL,
		0x546F67500E5C44C9ULL,
		0x4D3555CC1123BDB3ULL,
		0xB01DD32B17E87B21ULL,
		0xB05718036C8D7B15ULL,
		0x55AEFA1AB63E2DC9ULL,
		0x0813871ED817605AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x397113265F965D24ULL,
		0x448EF6CD51BD9D40ULL,
		0x5FA1EC8534D55730ULL,
		0xB235EC56C0774CACULL,
		0xD8F8B726C15C600DULL,
		0x605D816956BBE86AULL,
		0x00000000204E1C7BULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A26004D7AA83DE4ULL,
		0xE1E2C7C92E428FABULL,
		0xE436B33EC4BEB968ULL,
		0x017BFAAA1B29E52EULL,
		0x6E1EFCE41EECF797ULL,
		0x1CE90538E4FAA762ULL,
		0xD1E8D424842F4AA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C58F925C851F56FULL,
		0x86D667D897D72D1CULL,
		0x2F7F5543653CA5DCULL,
		0xC3DF9C83DD9EF2E0ULL,
		0x9D20A71C9F54EC4DULL,
		0x3D1A849085E95463ULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69341130EFA7CFDBULL,
		0xA8A559F80D4B4F76ULL,
		0x129C09F4F01CFD78ULL,
		0x2C9D5ED8DDBFAFF9ULL,
		0x91D686D56022FB36ULL,
		0x7FDF8BABEA31B2FAULL,
		0x2553540510DAAA3AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F80D4B4F7669341ULL,
		0x9F4F01CFD78A8A55ULL,
		0xED8DDBFAFF9129C0ULL,
		0x6D56022FB362C9D5ULL,
		0xBABEA31B2FA91D68ULL,
		0x40510DAAA3A7FDF8ULL,
		0x0000000000025535ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6492156F750BECBBULL,
		0xC9DA27A285254B6DULL,
		0xE9039EA0EF99A514ULL,
		0xF73BAF20B6DB98CEULL,
		0x52D7FFEB8540E37BULL,
		0x9521E0D0015243B5ULL,
		0x2653733D0901A026ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED13D14292A5B6B2ULL,
		0x81CF5077CCD28A64ULL,
		0x9DD7905B6DCC6774ULL,
		0x6BFFF5C2A071BDFBULL,
		0x90F06800A921DAA9ULL,
		0x29B99E8480D0134AULL,
		0x0000000000000013ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8671E3F15CA3DFEULL,
		0x2B5EA4B558066738ULL,
		0x5CF9CE59654DFA9BULL,
		0x765D86CDA1E1E9FCULL,
		0xEBCCD3601CE444AAULL,
		0xA523E4E54D96672DULL,
		0x0BB97A7145C55437ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60199CE3A19C78FCULL,
		0x9537EA6CAD7A92D5ULL,
		0x8787A7F173E73965ULL,
		0x739112A9D9761B36ULL,
		0x36599CB7AF334D80ULL,
		0x171550DE948F9395ULL,
		0x000000002EE5E9C5ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85F2520A3640E101ULL,
		0x5CA8F70F33F123C3ULL,
		0xB431D71939EC053FULL,
		0xAE4F63E6482E26B0ULL,
		0xE8366EB3992ABBDFULL,
		0x27625ECE0E6F00D5ULL,
		0x05CE327D34429891ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F891E1C2F929051ULL,
		0xCF6029FAE547B879ULL,
		0x41713585A18EB8C9ULL,
		0xC955DEFD727B1F32ULL,
		0x737806AF41B3759CULL,
		0xA214C4893B12F670ULL,
		0x000000002E7193E9ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x851A7699B498DBADULL,
		0xBFE110FC11E91F3DULL,
		0x1E8C844BF93766C2ULL,
		0xB063DEF1A6B2BB65ULL,
		0x911C3B7957720B52ULL,
		0x403C7482B1936098ULL,
		0xB3C403AD08DDB5D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC28D3B4CDA4C6DDULL,
		0x15FF0887E08F48F9ULL,
		0x28F464225FC9BB36ULL,
		0x95831EF78D3595DBULL,
		0xC488E1DBCABB905AULL,
		0x8201E3A4158C9B04ULL,
		0x059E201D6846EDAEULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68CDF3CCA237E054ULL,
		0x43B1EDE0E3323B7DULL,
		0x9AA345FC956510DCULL,
		0x85527739B4E488A6ULL,
		0x46FF6124D3112C66ULL,
		0xE32197C1E9752C84ULL,
		0x35CAF54B282CA807ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x476FAD19BE799446ULL,
		0xA21B88763DBC1C66ULL,
		0x9114D35468BF92ACULL,
		0x258CD0AA4EE7369CULL,
		0xA59088DFEC249A62ULL,
		0x9500FC6432F83D2EULL,
		0x000006B95EA96505ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD10AD824E5563FDDULL,
		0xB6B740DA2D3F020EULL,
		0x9E1D59E187489D0EULL,
		0xD9D03FB3C68F99E6ULL,
		0xA7C10AF896A1B89FULL,
		0x4E296D28BE59A1B7ULL,
		0x18F39E739FA2D5F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D169F810768856CULL,
		0xF0C3A44E875B5BA0ULL,
		0xD9E347CCF34F0EACULL,
		0x7C4B50DC4FECE81FULL,
		0x945F2CD0DBD3E085ULL,
		0x39CFD16AFBA714B6ULL,
		0x00000000000C79CFULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAFDCA08961E2C90ULL,
		0xC1368C4D93C6E361ULL,
		0x7D2792F666263173ULL,
		0x6022C17F51FBE647ULL,
		0x26C80ECC22BAB079ULL,
		0x5DF242DBA7ECD312ULL,
		0x7DA2AAE7A7F5E7C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C6E361BAFDCA08ULL,
		0x66263173C1368C4DULL,
		0x51FBE6477D2792F6ULL,
		0x22BAB0796022C17FULL,
		0xA7ECD31226C80ECCULL,
		0xA7F5E7C15DF242DBULL,
		0x000000007DA2AAE7ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF04BBF76930B6E9BULL,
		0xFF02D796AA480A53ULL,
		0x3B813537993F785DULL,
		0x45D0734A92B4E5D8ULL,
		0xEB7CB1EF7DCE0D4EULL,
		0xA06B3E6E261EF05FULL,
		0x323A822A5A616768ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94FC12EFDDA4C2DBULL,
		0x177FC0B5E5AA9202ULL,
		0x760EE04D4DE64FDEULL,
		0x5391741CD2A4AD39ULL,
		0x17FADF2C7BDF7383ULL,
		0xDA281ACF9B8987BCULL,
		0x000C8EA08A969859ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE76104FC93B86898ULL,
		0xD8264C092B1E3272ULL,
		0x3C106227C42913B6ULL,
		0x8911847EDB4B44C4ULL,
		0xE74977478EE3E00BULL,
		0xB7DF5179C9139AE2ULL,
		0x069E7370A6040969ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812563C64E5CEC20ULL,
		0x44F8852276DB04C9ULL,
		0x8FDB69689887820CULL,
		0xE8F1DC7C01712230ULL,
		0x2F3922735C5CE92EULL,
		0x6E14C0812D36FBEAULL,
		0x000000000000D3CEULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AB5FB0542883A25ULL,
		0x07AA87FAE49A1B88ULL,
		0x73B971145BBF54A2ULL,
		0x56DEBC0F4E24AEFAULL,
		0x504FA2ED7646EB1EULL,
		0xCE27FBC594528B20ULL,
		0x0F5F9B27BD44B1A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x686E21EAD7EC150AULL,
		0xFD52881EAA1FEB92ULL,
		0x92BBE9CEE5C4516EULL,
		0x1BAC795B7AF03D38ULL,
		0x4A2C81413E8BB5D9ULL,
		0x12C6A3389FEF1651ULL,
		0x0000003D7E6C9EF5ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD66C549BD405AD1AULL,
		0xE61BFAE3AC7D9195ULL,
		0x76731DC9E060C6AFULL,
		0x0863012E24CBB1AFULL,
		0xA22CA91E28AEBDA0ULL,
		0xBEE945DEBD7A433EULL,
		0x758020295A59305EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFAE3AC7D9195D6ULL,
		0x731DC9E060C6AFE6ULL,
		0x63012E24CBB1AF76ULL,
		0x2CA91E28AEBDA008ULL,
		0xE945DEBD7A433EA2ULL,
		0x8020295A59305EBEULL,
		0x0000000000000075ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E7F49306CC735BULL,
		0x1CCD6B073B8B527CULL,
		0x435E7813ECF32E69ULL,
		0x16DE45BC01619130ULL,
		0x20F67F12E48B5134ULL,
		0x8469491CA2F90D16ULL,
		0x945B41361A7514B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527C49E7F49306CCULL,
		0x2E691CCD6B073B8BULL,
		0x9130435E7813ECF3ULL,
		0x513416DE45BC0161ULL,
		0x0D1620F67F12E48BULL,
		0x14B68469491CA2F9ULL,
		0x0000945B41361A75ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A8846935895293CULL,
		0x7C83CB4DDAA0E571ULL,
		0x23C7BE71C8E91315ULL,
		0x59C71F632393C3D3ULL,
		0x39202EA3E8C36282ULL,
		0xF878911BBC541C1DULL,
		0x0B4F2E6FF5809552ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B885442349AC4A9ULL,
		0x98ABE41E5A6ED507ULL,
		0x1E991E3DF38E4748ULL,
		0x1412CE38FB191C9EULL,
		0xE0E9C901751F461BULL,
		0xAA97C3C488DDE2A0ULL,
		0x00005A79737FAC04ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x009742FB797C0142ULL,
		0xA858BC8E2A3F0003ULL,
		0x21F4C6BDD45B6481ULL,
		0x1620385CBB686B9BULL,
		0x183B942D8DEF807FULL,
		0x55F8DD668B44C663ULL,
		0x43F9DC6795208337ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x006012E85F6F2F80ULL,
		0x90350B1791C547E0ULL,
		0x73643E98D7BA8B6CULL,
		0x0FE2C4070B976D0DULL,
		0xCC63077285B1BDF0ULL,
		0x66EABF1BACD16898ULL,
		0x00087F3B8CF2A410ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE023D7A3ECDA631CULL,
		0x7E8BE3E1FBFFE5C3ULL,
		0x6A4291953D5ED80BULL,
		0x7A7494E775A27237ULL,
		0x0C40753B1E241E13ULL,
		0x33253BB24C612538ULL,
		0x070FA6DBD0BFEAE3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x970F808F5E8FB369ULL,
		0x602DFA2F8F87EFFFULL,
		0xC8DDA90A4654F57BULL,
		0x784DE9D2539DD689ULL,
		0x94E03101D4EC7890ULL,
		0xAB8CCC94EEC93184ULL,
		0x00001C3E9B6F42FFULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7687CB04A171ECCULL,
		0x72872AC77227C283ULL,
		0x39A5F3DF34A40B1FULL,
		0xF465950BED23ED27ULL,
		0x89310146E27481F4ULL,
		0x5033A147896073C7ULL,
		0x33CC1DCC3EDC9BB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72AC77227C283D76ULL,
		0x5F3DF34A40B1F728ULL,
		0x5950BED23ED2739AULL,
		0x10146E27481F4F46ULL,
		0x3A147896073C7893ULL,
		0xC1DCC3EDC9BB5503ULL,
		0x000000000000033CULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF49B96A15D59375CULL,
		0xB1E0BCA96D652D92ULL,
		0xF5A9C5A606A81FA5ULL,
		0x33153383F4F1630BULL,
		0xBBA413D3ED2E5382ULL,
		0x8F5E1B9386F73803ULL,
		0x010083EADBF1C42BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BD26E5A857564DDULL,
		0x96C782F2A5B594B6ULL,
		0x2FD6A716981AA07EULL,
		0x08CC54CE0FD3C58CULL,
		0x0EEE904F4FB4B94EULL,
		0xAE3D786E4E1BDCE0ULL,
		0x0004020FAB6FC710ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9CA0E01770ADC3EULL,
		0x0E55C4AD7F8E5058ULL,
		0x4986E9B9E4B2E18CULL,
		0xFE5892743B16FD06ULL,
		0x34E6F62A61FDC65AULL,
		0x735DD2D4B4B4D469ULL,
		0x6C069A9C11B94335ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55C4AD7F8E5058AULL,
		0x986E9B9E4B2E18C0ULL,
		0xE5892743B16FD064ULL,
		0x4E6F62A61FDC65AFULL,
		0x35DD2D4B4B4D4693ULL,
		0xC069A9C11B943357ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172E797434D9A908ULL,
		0x259B679D84CA89B4ULL,
		0x92D4A183C398280DULL,
		0x182B1A5B9AAC23C2ULL,
		0x119F724305369494ULL,
		0x4C37E49F3ED96BBDULL,
		0xB160A58DF8F27047ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4172E797434D9A9ULL,
		0x0D259B679D84CA89ULL,
		0xC292D4A183C39828ULL,
		0x94182B1A5B9AAC23ULL,
		0xBD119F7243053694ULL,
		0x474C37E49F3ED96BULL,
		0x00B160A58DF8F270ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1048644D7CE5A4ACULL,
		0xBEBCAF3933B95425ULL,
		0xF4AC5C39C6B54662ULL,
		0x8B0F497570A82461ULL,
		0x068C9B7B5318AE6BULL,
		0x3231B71C7C7F63FDULL,
		0x6576EFBAC86117E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCAA1288243226BEULL,
		0x5AA3315F5E579C99ULL,
		0x541230FA562E1CE3ULL,
		0x8C5735C587A4BAB8ULL,
		0x3FB1FE83464DBDA9ULL,
		0x308BF11918DB8E3EULL,
		0x00000032BB77DD64ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3B6BEF16F783C37ULL,
		0xCC00ADCF0F650056ULL,
		0xC3F569D4E0970A6CULL,
		0xD22011964F3C20DEULL,
		0x92C9B884DDA38621ULL,
		0x3FB05270B8F6D78CULL,
		0xE6E87AFEAC82FFF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1ECA00AD876D7DEULL,
		0x9C12E14D998015B9ULL,
		0xC9E7841BD87EAD3AULL,
		0x9BB470C43A440232ULL,
		0x171EDAF192593710ULL,
		0xD5905FFE07F60A4EULL,
		0x000000001CDD0F5FULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8450179BC0390CEULL,
		0xAB3607F9EDED4FECULL,
		0x30FDF324C6ACDDA4ULL,
		0xEAA95B98D5B0F889ULL,
		0xC619CF74018FF9F5ULL,
		0x06D38C8024101889ULL,
		0x5E5A4ED3FEFD272EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED4FECE8450179BCULL,
		0xACDDA4AB3607F9EDULL,
		0xB0F88930FDF324C6ULL,
		0x8FF9F5EAA95B98D5ULL,
		0x101889C619CF7401ULL,
		0xFD272E06D38C8024ULL,
		0x0000005E5A4ED3FEULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B7FB16D236FD458ULL,
		0x7A8140BE03A06993ULL,
		0x2E02F0970F4A174EULL,
		0xA34DDE770C11DF94ULL,
		0xCD00A8E269468C82ULL,
		0x563548A3C74C35BFULL,
		0x1667D0B17D2794DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE03A069937B7FB1ULL,
		0x970F4A174E7A8140ULL,
		0x770C11DF942E02F0ULL,
		0xE269468C82A34DDEULL,
		0xA3C74C35BFCD00A8ULL,
		0xB17D2794DA563548ULL,
		0x00000000001667D0ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}