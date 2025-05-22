#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xAC7A8D68D88AB93AULL,
		0x68D565625F25F120ULL,
		0x4D0269ECDC516F5BULL,
		0xACCF1BE6CD4A56B6ULL,
		0xACB1508B6572FE00ULL,
		0x4B1D143AD128EA1BULL,
		0x0F14E6AEC6ADA14EULL,
		0x0FC635686FF1FB92ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9360B0FDEC8385B5ULL,
		0x912F31B79654C2E5ULL,
		0x4F253B17ABE38B87ULL,
		0x9AE7C67E333F5B04ULL,
		0x166A13E7404B906AULL,
		0xFDE5E937BF43F987ULL,
		0x78060CB47B27B783ULL,
		0x549B7AA1BAD58D9CULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEA1BF7CDBEB3E870ULL,
		0x055B2DA1CEDA0CE5ULL,
		0x448EDB5CC4546C22ULL,
		0xDBF80B1978DA94EAULL,
		0x0D4BAD0596DA9D92ULL,
		0xEF62DEF52ADABEABULL,
		0xA0CCF17DEC0BD47CULL,
		0x5E1D5366F30AB513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43FCAE79E6E31923ULL,
		0x5BE2C4C925EDDBE8ULL,
		0xA7F41960CBC7E3E6ULL,
		0xC4B2BB869A19A50FULL,
		0x028C5A432C87CEE9ULL,
		0xB8AE87DFF07A1E0FULL,
		0x8E818DA136D38C5DULL,
		0xBD5D52DC9B69FBDBULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x192E359AFF2156DCULL,
		0xE0141657363B7DFFULL,
		0x2BDAC2E7E77856E3ULL,
		0xF0043CE43957D686ULL,
		0x27E75E629A6FB316ULL,
		0x7C8323F4D56CA2FAULL,
		0x234DD103234B1010ULL,
		0x7B5F340B1A26EBBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x895A20613A304537ULL,
		0xF2CFD37DFB347312ULL,
		0x064E7B87FDC24EB3ULL,
		0xA7C84A66D44FB89EULL,
		0x7E4766016D28223AULL,
		0x75EA4458E1679FC0ULL,
		0xF1F1F8C40AEA9999ULL,
		0x4A03718E4B0E5973ULL
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
		0x50B12AB82AF8BC14ULL,
		0xB1FF5D36AC7C9A1DULL,
		0xFCA7B518672494EFULL,
		0x2687271D208BF891ULL,
		0xF71146D056CA6453ULL,
		0x06EEF9E3457F53B4ULL,
		0xBC41D58CC4E0C331ULL,
		0x72D392D814AAEF76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA789E455F8F69065ULL,
		0x802923FAC0EC09B3ULL,
		0x9C63502FDFE6E9E6ULL,
		0xC9FBD3741D870EAEULL,
		0x4D7DDC783513EEA5ULL,
		0xE58A67B8078BD2BBULL,
		0x8A7E1D2044827866ULL,
		0xD8F37FA37FDF8DA9ULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1C6BDD0BA03A83B3ULL,
		0x277528F70A9A9D17ULL,
		0x739B4126FEA678C3ULL,
		0xCA3E1D537AB64F2AULL,
		0x4242BB737E040EBFULL,
		0x8D3C0301117206DBULL,
		0xCAA5837D269AF6CBULL,
		0x0CD37BA99688D098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C6BDD0BA03A83B3ULL,
		0x277528F70A9A9D17ULL,
		0x739B4126FEA678C3ULL,
		0xCA3E1D537AB64F2AULL,
		0x4242BB737E040EBFULL,
		0x8D3C0301117206DBULL,
		0xCAA5837D269AF6CBULL,
		0x0CD37BA99688D098ULL
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
		0x80DEDE9A52A3D65EULL,
		0x1218A9DFC25FA501ULL,
		0xBC0B1C68E7CA7BF6ULL,
		0xC6279D169D8B3D67ULL,
		0x3E2B8F59CC0560EAULL,
		0x1467FC1312047DC0ULL,
		0xBFF33E5866FACA47ULL,
		0x0509468B57472248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F2897377DCF7E53ULL,
		0xC5AC482FEDEFB888ULL,
		0x597BB11AC98A7738ULL,
		0x24F07DFED87A79B7ULL,
		0xFA0C9EF84D8BE4D8ULL,
		0xAD6503F253BD0B2AULL,
		0x213EBD6B1C060156ULL,
		0x5C68B9E41BD82CE5ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8BE18F57CE0AC1B0ULL,
		0xD6C8023C5807D69CULL,
		0x46A8FEE9D6F8B6E3ULL,
		0x105A782065E4167FULL,
		0x72A96FE2778DF23AULL,
		0xFDFFFB2110396741ULL,
		0x8531204104395891ULL,
		0x124CA691BCE066D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59AEC1044BBFCCCDULL,
		0x00DE59594E910889ULL,
		0x5550632A465984BAULL,
		0x80867A8159942944ULL,
		0x382C72375B62144DULL,
		0xDE610DA0966794DBULL,
		0x89703388308EEC42ULL,
		0x9C6608C2EA2AFE89ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD695D922490F8EFEULL,
		0xC8EA1253D8ABE821ULL,
		0xA5EF3641AD3A696CULL,
		0x6A4A3109DA7A20DAULL,
		0x41847AEDA6F241BFULL,
		0x5FF17689B9ECE100ULL,
		0x9DE3D889132D186CULL,
		0x6A4DA5197B1B3314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C43B42831A695AULL,
		0x3CC6990461842258ULL,
		0x1A3C77ED2CF164F2ULL,
		0x0E9BAF599A45D424ULL,
		0x57B0158826213B10ULL,
		0x229F8AFC92A6098CULL,
		0x6B318121317E4F53ULL,
		0x167D66C5029EA731ULL
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
		0x1D6A616E5FA19963ULL,
		0x372ADF4A4B63AB8AULL,
		0xD1FB7AC6BB2E8192ULL,
		0xC44C099AE46CE2FAULL,
		0x74685E256FA94F8FULL,
		0x133DC6BC8DAAF4B1ULL,
		0x6F5F49FFC120D664ULL,
		0x686BC1DEFADD7FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D6A616E5FA19963ULL,
		0x372ADF4A4B63AB8AULL,
		0xD1FB7AC6BB2E8192ULL,
		0xC44C099AE46CE2FAULL,
		0x74685E256FA94F8FULL,
		0x133DC6BC8DAAF4B1ULL,
		0x6F5F49FFC120D664ULL,
		0x686BC1DEFADD7FF1ULL
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
		0x6C12F2199008FAE8ULL,
		0xB8F28B9A0724FFFEULL,
		0x4AD3B376C3EC6C3FULL,
		0x0B085C104BFCEF8CULL,
		0x9DC70024A0D42230ULL,
		0x7069AB690640EB3FULL,
		0x07EC40D7A5ED2DD6ULL,
		0xF54090C4DC941C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0623AE1EEBCAAD61ULL,
		0xC99E5A47A2634823ULL,
		0xDB7BC23934B32060ULL,
		0x4248BBA2A426C1CCULL,
		0x213AB3FDFD9772E8ULL,
		0x2A4282F1BF223B29ULL,
		0x8FD080ABF2AF9BCEULL,
		0x55B8A5FC0D112357ULL
	}};
	t = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x74033001323BCB6EULL,
		0xF5E9CE7F2575E8A0ULL,
		0x692AAAC045966F1BULL,
		0x1FE51682356CEA39ULL,
		0x5A42321EBB28C0C4ULL,
		0x63F3799DB8E45F56ULL,
		0x3AD4A3F54E0FD718ULL,
		0xD770E372F0C1858EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C53ADE5ABACE3BULL,
		0x4CD0EC41D663ACA4ULL,
		0x75D7F1DE19263F18ULL,
		0x379AF1B70B87FFE1ULL,
		0x3F771C15DB2E3C1CULL,
		0x0A9F43C227F10A43ULL,
		0x06B87073F43B8AC7ULL,
		0x068E98CA14FB6617ULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4ECF9F867A5DF1B0ULL,
		0xC1C16F7289BF00A0ULL,
		0xAF36EC6EC590787AULL,
		0x97B617AB6495A14EULL,
		0xE6C4B11E4FC2FAD4ULL,
		0xC2A802ABE2CAE1E8ULL,
		0xD5F3AF695AC6D7E0ULL,
		0xC199759889F83185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD2DDCFA8073606ULL,
		0x7ED9B2300B21DCC1ULL,
		0x951D7FACF2DA8B05ULL,
		0x7FF82288A4CAA4E9ULL,
		0xE88EA9DE387FD962ULL,
		0x81C12E3DECF7AC94ULL,
		0x2A7467D56CA480D8ULL,
		0x7FADDCADBD8AA3B4ULL
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
		0x43A874010AD73158ULL,
		0x8A78BF1D633AAD9CULL,
		0x5943E2130919F689ULL,
		0x1C40960FF0E6E393ULL,
		0x904E1A34CB72D567ULL,
		0x5BF91F7E48500D99ULL,
		0xF290EB1244284E95ULL,
		0x2D2E31F2EB8364BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A874010AD73158ULL,
		0x8A78BF1D633AAD9CULL,
		0x5943E2130919F689ULL,
		0x1C40960FF0E6E393ULL,
		0x904E1A34CB72D567ULL,
		0x5BF91F7E48500D99ULL,
		0xF290EB1244284E95ULL,
		0x2D2E31F2EB8364BDULL
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
		0x16CB2F1FB9984660ULL,
		0xC7D7EE5F8960D686ULL,
		0x54CA7407FAF441F9ULL,
		0x55A5BCBFC1A891EDULL,
		0x987A10BB5EEB1475ULL,
		0x4791B9229DEBA93BULL,
		0x18B1907D4E6DF25DULL,
		0x7982119C8BB71322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0687C00882A7FF3ULL,
		0x8033D6EBA3C8C2BEULL,
		0x2695A70F6275EFA5ULL,
		0x92F0A27D99099A6DULL,
		0x0F4C511056868968ULL,
		0x5F6E81136ED5B13AULL,
		0xEAE004D34DA7AAF8ULL,
		0xD188F86D316CF2E2ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFA34DD0D0966DB73ULL,
		0xDA1DE1801C95B323ULL,
		0x2F30E3366E4251F0ULL,
		0xADF4306E5C3CF501ULL,
		0x82241D60CB1118E5ULL,
		0xEE8898C9A2A4368EULL,
		0x78A67402E2E20B3FULL,
		0x1F01FF147DD8AB4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x255D4A420FE12C76ULL,
		0xD751F5D3E2DA0370ULL,
		0x340980B3642E55C8ULL,
		0xBFFBF84AD284DE33ULL,
		0x7E2B606DC8450971ULL,
		0x57B98DBF9F07833EULL,
		0xFBA733FFBF82D4C7ULL,
		0xADFF4DA86A361B82ULL
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
		0xA26ED564A3A4CEF8ULL,
		0x71EEFEE43D923EC8ULL,
		0x4063CB82040B6F06ULL,
		0x1F03DE52E3F0417AULL,
		0x10F916DDF0FF5AF1ULL,
		0x58F0F7EB54FBC244ULL,
		0xC5B2BE53D626DCE4ULL,
		0xF30E37F7F2EE1413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DF3A1708482C186ULL,
		0x72ECEF486B0F1E33ULL,
		0x7B7ACA8B3C43459FULL,
		0x12D0622CEBB0DC80ULL,
		0x28479DEF389F3FFBULL,
		0xB008823B14FE554DULL,
		0xD3393962911F34D8ULL,
		0xF21A7053B0E4E8ECULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x18082D57B27B0BAEULL,
		0x5CFBBEFE9BB066A1ULL,
		0x1950FE911F5036B4ULL,
		0xA93BDD9F27E21FF9ULL,
		0x0AB2840AF0884139ULL,
		0xEC7847DE30819409ULL,
		0x3959CFA31269AFAFULL,
		0x5860AC11FB9DC3C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18082D57B27B0BAEULL,
		0x5CFBBEFE9BB066A1ULL,
		0x1950FE911F5036B4ULL,
		0xA93BDD9F27E21FF9ULL,
		0x0AB2840AF0884139ULL,
		0xEC7847DE30819409ULL,
		0x3959CFA31269AFAFULL,
		0x5860AC11FB9DC3C0ULL
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
		0x9F894EBCA5B826D9ULL,
		0xFC2DE067EF60E560ULL,
		0x870FEE7912B0B23AULL,
		0x66C52A4637BD5180ULL,
		0x7598C2E9ED4246DBULL,
		0x65D8A1F11B0FC323ULL,
		0x569C33BD02D8B49EULL,
		0x28724A8F68120D96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CA184C5FCD33EAULL,
		0xE3B67761D7075988ULL,
		0x9E2E5C7ADE206F0DULL,
		0x293F74BB703C5B42ULL,
		0x037D4184D20FF4B8ULL,
		0x9503023280841C4AULL,
		0xDDF83B9E2A09F9ACULL,
		0x10F391773295F230ULL
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
		0x2C09557BF0AB499CULL,
		0x0F545C149C98DA4FULL,
		0x9C4539A59D36EA60ULL,
		0xECD8817723CA78BDULL,
		0x9A8CCECE46970440ULL,
		0x3FFCFA7EA179BB05ULL,
		0x5FFC05148324C0B6ULL,
		0x4A3DBFF6E9E50DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD933EB2C7A5342DEULL,
		0x0108F8394AB76D11ULL,
		0x40DA1FB969D08C34ULL,
		0x79F70AA9A3712FA2ULL,
		0xE1DF3F7BE11D484CULL,
		0xC5532AD9BAC38346ULL,
		0x300836F04BF7F7B2ULL,
		0xDC194E0A466CBCB1ULL
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
		0x828C9F5355AB0667ULL,
		0xDE3C0D6C30F450FBULL,
		0xB826D3E468AF0589ULL,
		0x26870FF947CC1C86ULL,
		0x9CBA94A3CAA6E97EULL,
		0x9E2EC961A7E17BA2ULL,
		0x8D871FF4756942F7ULL,
		0x59BB0B23046C2BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B44A4E578A0B0FEULL,
		0x502B6F49B0E6B09CULL,
		0xF136C2ED2D8A7BDFULL,
		0x668A1E8A2125CDA9ULL,
		0x475C95155CF7C224ULL,
		0xB32D1A42A3E327D9ULL,
		0x864602E21F3BE6D5ULL,
		0x157155806A21D94DULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA193A78B975E25E3ULL,
		0x72D0D75FF8C8BA75ULL,
		0x29A54502E9C02A95ULL,
		0xB6B38F864AA4A37DULL,
		0xD3D1F7954F588ADEULL,
		0x6CE3F8878AE8BFADULL,
		0x94494A7CF2515370ULL,
		0x8BADDABE7D5033ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA193A78B975E25E3ULL,
		0x72D0D75FF8C8BA75ULL,
		0x29A54502E9C02A95ULL,
		0xB6B38F864AA4A37DULL,
		0xD3D1F7954F588ADEULL,
		0x6CE3F8878AE8BFADULL,
		0x94494A7CF2515370ULL,
		0x8BADDABE7D5033ACULL
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
		0xCE59F5EFFDD2AA95ULL,
		0x8D607739BADDA7E0ULL,
		0xA2991D245F743C1AULL,
		0xAA1E274A2E96B177ULL,
		0xBC9DF861A45CD49DULL,
		0x05676685C73C0326ULL,
		0x70A55987C856F8BCULL,
		0x1CF21078495C4F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88D6C73EC3951766ULL,
		0x6CC5BB2853D23AC0ULL,
		0x22AFCBC4CF81E5F4ULL,
		0xF70F2FCF347AD42BULL,
		0xA5AD15202999BD93ULL,
		0x2E855969100578DFULL,
		0xAEBB948B2F143983ULL,
		0xB87B696D5136F93BULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x424CB7FAA9DF0BBAULL,
		0x912A7F3359C42388ULL,
		0xB03E9A256BD6DF00ULL,
		0xED0EC0B65A27A0DCULL,
		0x43502B97BD71F947ULL,
		0x3CEF99EDC62C8C08ULL,
		0x17DA9B54F90DE2FCULL,
		0xC80AA8BAC02021D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632FFD2BF4D50840ULL,
		0xEFE401054F71D00CULL,
		0xB796DD8C77167691ULL,
		0xDB01C9B63C1046A9ULL,
		0xAF60A148877AD848ULL,
		0x55CF7DEB16110B30ULL,
		0xF48BD83710FF9EC6ULL,
		0xBAC27D0393CA54FDULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x43377D959D3554B3ULL,
		0x924E6B7432AD68CFULL,
		0xFD84A32F757A8F68ULL,
		0xF2B341DC593AF40FULL,
		0x62B8DAF1A47C8BEBULL,
		0xE1E483DF272FBAD1ULL,
		0xDFACCD961EBC75A1ULL,
		0x591950B7384E8F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA369B3A665908C4ULL,
		0xC88AC0A54CE71E3CULL,
		0x2FA090E5EC815ABBULL,
		0xC3F64652926BD5EAULL,
		0x4C9D5D97B15928B7ULL,
		0x5FCE5D9B300C6D4AULL,
		0x7B04B9158B7663C4ULL,
		0x8664477B47237C83ULL
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
		0x2AE8B263C9686256ULL,
		0x1426D45B0140622FULL,
		0x9851E61F190FF608ULL,
		0x905A8DA665FD5035ULL,
		0xCB3439609DF78825ULL,
		0x22712852C8F6F0CCULL,
		0xF91408EBFC3D9F86ULL,
		0x47E1CF0F78BFCAF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AE8B263C9686256ULL,
		0x1426D45B0140622FULL,
		0x9851E61F190FF608ULL,
		0x905A8DA665FD5035ULL,
		0xCB3439609DF78825ULL,
		0x22712852C8F6F0CCULL,
		0xF91408EBFC3D9F86ULL,
		0x47E1CF0F78BFCAF9ULL
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
		0x1139B2ABCEF4B12AULL,
		0xADBA28F53CA9228AULL,
		0xC417A3F84C8A1AB0ULL,
		0x28A88513CB4C67F3ULL,
		0x48A8698EDDA09068ULL,
		0x7DD6E932B1080A96ULL,
		0x8F54540E65BAE291ULL,
		0xBCD5BAD3E9007077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x837BF202F04FB1EFULL,
		0x281A62A28820F536ULL,
		0x08063BBE890DF842ULL,
		0xC997D2C0C0F2FBDCULL,
		0xA2BB3AFECC9ED50CULL,
		0xBBE962B7316A3A68ULL,
		0x600E3C48FCC10CB3ULL,
		0x0245D706E98AA527ULL
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
		0x013F49B35CA9EAE6ULL,
		0x7F315A1EB7AD21D0ULL,
		0xF42C161D55E6597FULL,
		0x7D24D1A85ED52806ULL,
		0x8180707D43B00B56ULL,
		0xF9DE789997B9B2AAULL,
		0xBA8BEB707037D26AULL,
		0x3EF64647B7FB8039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD3EA5794093B5DULL,
		0xFAEDB9FCE8560F2CULL,
		0x3FC55C3F287D7F36ULL,
		0xC9AE835E4DE03936ULL,
		0x2C2200DC5CD7FDD3ULL,
		0x3D9588A66D7FD18DULL,
		0x2F90E6AC7E3338F6ULL,
		0xBE118F5155CE49F6ULL
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
		0x11F5F6E487702756ULL,
		0xF7959A2F98AF10ADULL,
		0x8F3B1A938144E4CCULL,
		0x5295F7E2B289F72DULL,
		0xC62AA51819DE10BEULL,
		0xC6D3D3301CCE51A6ULL,
		0x19B4635765E827E9ULL,
		0x348A80ABEDF859B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x445BC80FD95EF2EFULL,
		0x8785BE45AFCDBDAAULL,
		0x57FFFD0D924A1AFEULL,
		0x7F666C8893974AE7ULL,
		0xB49E7EA86D542D24ULL,
		0x600BB6376DAEC79CULL,
		0xD4BA4897643F4F77ULL,
		0x335471FD42F69C74ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD0A93B9F7C034B60ULL,
		0xC4D7DC9DEE521783ULL,
		0xA8DDD333896F6731ULL,
		0xB5670A46262FB27BULL,
		0x2901AFE29BD90373ULL,
		0x81D9C9DC3B47BBA4ULL,
		0xEA96C23B7CDD9FA3ULL,
		0x02AAE8ACC5A58522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0A93B9F7C034B60ULL,
		0xC4D7DC9DEE521783ULL,
		0xA8DDD333896F6731ULL,
		0xB5670A46262FB27BULL,
		0x2901AFE29BD90373ULL,
		0x81D9C9DC3B47BBA4ULL,
		0xEA96C23B7CDD9FA3ULL,
		0x02AAE8ACC5A58522ULL
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
		0xE764BD7BD67538F3ULL,
		0xED9A0844BEB98184ULL,
		0xF5DBB8E487BFB07CULL,
		0x0A39F5B44F205129ULL,
		0x99168220A3FA5A84ULL,
		0x5F08BE62590A448EULL,
		0x746FC11833CD13DFULL,
		0xB207BE87F6F002EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC185E2100496870ULL,
		0xFB5EFC545AD714CFULL,
		0x0E283E2230F54451ULL,
		0x0E6ECB011E42C911ULL,
		0x842B29D0934EE77DULL,
		0x24A1163388781598ULL,
		0x3AB1640E8220ACB8ULL,
		0x40A23692AF3E0180ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0A54F304782D82A0ULL,
		0x3138175845129544ULL,
		0x7343137D220E9B4EULL,
		0x3A9559715E251206ULL,
		0xD130CF5BCC87568BULL,
		0xABE103A8F0E24DF3ULL,
		0x80DA4AF846D1BE45ULL,
		0x716E254F8D11AC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A700BB810EBC054ULL,
		0x0C59A6029AAB8F5AULL,
		0x3FDFE6074E758D3BULL,
		0x24DB553F0098FA02ULL,
		0x89F8EB235F89C178ULL,
		0xB3963CEC942DBFADULL,
		0xE30BD9FF8D4C50E0ULL,
		0x5DA6F9B3AAF86AE0ULL
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
		0x5091B62B2AA615A9ULL,
		0x616B07FEE8CC3EDBULL,
		0x71A6B9110EAA48A0ULL,
		0xFF7C1E9FAA801D19ULL,
		0x44E1FA673D00AC45ULL,
		0x732F1AB1AD93BBC2ULL,
		0x610859F9B15AC357ULL,
		0x960B9FA1CC03F85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B3BDA752DEF559ULL,
		0x09ED0BB648703200ULL,
		0x6B047D00FCE7B275ULL,
		0xBCDDAA42153CF642ULL,
		0xB810F4E93A2DCE1EULL,
		0x6505E69450D648BAULL,
		0x3907A2302B5D07A1ULL,
		0xE3688DAC9485D0A5ULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF8F53BE50C92E8E9ULL,
		0x2F2EE895D46BF2E0ULL,
		0x16B5C390C39BBFE0ULL,
		0xF706E2AEB097E5EAULL,
		0x6F2AF2037405E3E5ULL,
		0xDCE95072FB043B87ULL,
		0xC250CF8198401E61ULL,
		0x2AF59ECB7F972956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F53BE50C92E8E9ULL,
		0x2F2EE895D46BF2E0ULL,
		0x16B5C390C39BBFE0ULL,
		0xF706E2AEB097E5EAULL,
		0x6F2AF2037405E3E5ULL,
		0xDCE95072FB043B87ULL,
		0xC250CF8198401E61ULL,
		0x2AF59ECB7F972956ULL
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
		0xBE5DD4F44C6417DFULL,
		0xB930B155C28D0587ULL,
		0xF552C6B84D2FA562ULL,
		0x1FB8C08580DEE38CULL,
		0x24FCE20BD065F3E7ULL,
		0x237A5EA59A039305ULL,
		0x1211E0DC1A35A42CULL,
		0x957ECF2DC77130F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D84AF2D00E3558ULL,
		0xACBA08411C0E11F3ULL,
		0x183943B0AB0D875DULL,
		0x86E7E9C026DE32F0ULL,
		0x98E12AA5F162FC6BULL,
		0x39D869DAE10D754AULL,
		0x3460441E8FBB35EFULL,
		0x2B270EBD331A426FULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3BCFEB5CDC3B1E8CULL,
		0x450AF420D5D85460ULL,
		0x7FAB78A54260BDD0ULL,
		0xD56434749CED062BULL,
		0xEDCF2F436D4A1175ULL,
		0xBFFC2D65F67726B2ULL,
		0x339BEE7D27A98B3AULL,
		0x958999F0FF46AEB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x701FDA5F7D5C5952ULL,
		0xFE579866AE3F07C0ULL,
		0x1BC918A16E339E91ULL,
		0x38DCB2BCA9C23D9DULL,
		0x2E8107D6AB7C86D5ULL,
		0xB1EC17FC5FD494C6ULL,
		0xE3FC0D1572B0657CULL,
		0xD620EF6A05943283ULL
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
		0x525AF36E397D66A9ULL,
		0xA42409B301E98D22ULL,
		0xC8C63C5B1E17FC3EULL,
		0x9AF8867513BFA5AEULL,
		0xDF509E414C0F199BULL,
		0x2582FD32DA042021ULL,
		0x7B8BB9FC9A304CA5ULL,
		0xBD735C3715D86489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536629F76541C1ECULL,
		0x0B4DD99AA7E2432BULL,
		0xA93CAAECBD71259EULL,
		0x9FB74328678168BAULL,
		0x69671CA46EFFD6F3ULL,
		0xD8266CBBFF2A0993ULL,
		0x42DFD49314605B06ULL,
		0x65FB933BCE8F773DULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2DD9A235F563D53DULL,
		0x6FDBD81649BDE396ULL,
		0xDE4AA21F3C51ED6EULL,
		0x7CAE294211C6D780ULL,
		0x40D2910CAA20EC6EULL,
		0x739D5814F1C1A969ULL,
		0x361A8000A321379FULL,
		0xB1D2160858F3F8E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD9A235F563D53DULL,
		0x6FDBD81649BDE396ULL,
		0xDE4AA21F3C51ED6EULL,
		0x7CAE294211C6D780ULL,
		0x40D2910CAA20EC6EULL,
		0x739D5814F1C1A969ULL,
		0x361A8000A321379FULL,
		0xB1D2160858F3F8E7ULL
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
		0x113FA864E786C335ULL,
		0xEE915F4454D27548ULL,
		0xFD923CCBDB6273B8ULL,
		0xE37AB287E500A02CULL,
		0xDF3514B7DEB1EC6CULL,
		0xE6FAEC0314D89DDBULL,
		0xDB286842C8612236ULL,
		0x6CFEB6DC9C60B42DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317F85F94AD8EB04ULL,
		0xA9D3E1CC08FE448BULL,
		0x0E8FA3B49CF2510BULL,
		0x1497483191903959ULL,
		0x6B505D9D63BABC68ULL,
		0xF4E17314F8A28DE8ULL,
		0x41A365A792F9291FULL,
		0x3EBFC2B9F5BE879AULL
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
		0xE00CAA834CB791E9ULL,
		0x3EF19ED54D44BD76ULL,
		0xBAA62137D617D18DULL,
		0x9CF321BAD02D94C5ULL,
		0x2CA942A10957B0E2ULL,
		0x78123E66BF76C21BULL,
		0xF7C7B3424D93D9C2ULL,
		0x4489C3AC5FA7395CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34850CD510586655ULL,
		0x147303A395E04FA3ULL,
		0x6F1E95682FAC4E9FULL,
		0xCBFC52D1D422ABE9ULL,
		0x310F97AA5CD06873ULL,
		0x32A22AAB3208C602ULL,
		0x6404AC149CE3B396ULL,
		0x04526E89A14B2861ULL
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
		0x4875A08B79173167ULL,
		0x82C809B77AB766BAULL,
		0x669286EBDFDFBA58ULL,
		0x71AFEEA35DE435DDULL,
		0x0A1B16CBA379A583ULL,
		0x209238476BC66233ULL,
		0x05F00F6EBBB85831ULL,
		0x503C8A82B0C9A91AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E573A504CD1396ULL,
		0x8FFC085A16CBD532ULL,
		0x012CE211618F13CFULL,
		0x4B6AC6B99C53D312ULL,
		0x9E67214A9ED4873EULL,
		0xFB1901F4A87C54E1ULL,
		0x134325508E5314D7ULL,
		0xBEF5CF9F83D9FB87ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1CFF62343A1935A2ULL,
		0xDBD7738D5BC6EEF3ULL,
		0x1B9B79FF21735110ULL,
		0xBEFE492D7889BFA2ULL,
		0x97601FAB3B0EF15EULL,
		0x02DBAD9136F90329ULL,
		0xEAF000827C4D0D90ULL,
		0x9311E1C477BFF5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFF62343A1935A2ULL,
		0xDBD7738D5BC6EEF3ULL,
		0x1B9B79FF21735110ULL,
		0xBEFE492D7889BFA2ULL,
		0x97601FAB3B0EF15EULL,
		0x02DBAD9136F90329ULL,
		0xEAF000827C4D0D90ULL,
		0x9311E1C477BFF5A8ULL
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
		0x077C556C18E35D7BULL,
		0x6BCEDD7B4371E0E4ULL,
		0x14D5B0B06CE6B3A8ULL,
		0x22A1235ABE0C42E7ULL,
		0x91888E9DA82FE3A1ULL,
		0x7D811DE4F69170A4ULL,
		0xD484D07CD52997A8ULL,
		0xAB70BCE3890DFFA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB1F30546685D0CEULL,
		0x8FBD8F196592F40AULL,
		0x780E096F26E89C77ULL,
		0xF5E777A916D057B4ULL,
		0x4801CEA577ACBB90ULL,
		0x2C3A91D2A976683DULL,
		0xF96714CB5821A8E6ULL,
		0x7FC781DB417F4A84ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x982880048974480EULL,
		0x4EFECEAA5C7238C9ULL,
		0x07453456A7A65B2CULL,
		0x1CFA3087C04C67DBULL,
		0x8D80287BA6FF93D4ULL,
		0xC9F6E9D9D726D007ULL,
		0x5A2819EDA727C2DFULL,
		0xCC50480BF4887920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D9FEDAA1719953DULL,
		0xB58E640D88A72F71ULL,
		0xA740D72A9C5890D6ULL,
		0x68527CAC7B1DF27FULL,
		0x1EFAEBE93B9A0FE3ULL,
		0x79F8EBB5FD89BABDULL,
		0xBA52CD85539E5264ULL,
		0x639F4F997A9EFB2DULL
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
		0xA6F85FAB2009DB3DULL,
		0x1AB16AD50D6FF19DULL,
		0xA6CCC1ED1A085A20ULL,
		0x56C4B34814DF7A7EULL,
		0x0F020AE79FB029DEULL,
		0x3FFB713A63C8EE18ULL,
		0x80E3CA4E635A4DC0ULL,
		0xC282BA853B341AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBD4161FBA3C645ULL,
		0xDC4DE929088FCDD5ULL,
		0xC1A97FD2E26B538DULL,
		0xF6686B2CEE2B94A7ULL,
		0x244FD7CA9D78BF41ULL,
		0xA03621348FF3556BULL,
		0xBAEEFB2614DC20B1ULL,
		0xB813CD1CCF35183AULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7B067324C1B5ACD7ULL,
		0xD963AFA38FCFCB1DULL,
		0xB0D7DD580DF15EE4ULL,
		0x5A0A73351FB9E78AULL,
		0x67BEF7F1C1F8C4BBULL,
		0x8B2F733BA9952D92ULL,
		0x1D6DBC40A619D4ABULL,
		0xFFD65CE383D2DDABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B067324C1B5ACD7ULL,
		0xD963AFA38FCFCB1DULL,
		0xB0D7DD580DF15EE4ULL,
		0x5A0A73351FB9E78AULL,
		0x67BEF7F1C1F8C4BBULL,
		0x8B2F733BA9952D92ULL,
		0x1D6DBC40A619D4ABULL,
		0xFFD65CE383D2DDABULL
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
		0xC2D3AC5E9B9B8F47ULL,
		0x181349806311C880ULL,
		0x28206C9625771F8BULL,
		0x52277E1D15A36D13ULL,
		0x2ECB69ACA577BBEBULL,
		0xA7C0970FF19B78CFULL,
		0x6200CBA4A0E1961FULL,
		0x47C454B136F2569CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072F85A398FF7172ULL,
		0xBE706A5CABEAFB54ULL,
		0x90EC9DF9184B82A4ULL,
		0xB8020A295A64BA5FULL,
		0x77DF19B4044457B9ULL,
		0xFE209E3C2BF27025ULL,
		0x0A3E4F2C3E11D74DULL,
		0x98B8086FAEA8809DULL
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
		0xABFC5C101C853845ULL,
		0x8729DC3CC255ED6BULL,
		0xC8044EB169FE708EULL,
		0x59E8826F313DC5D9ULL,
		0x090224444F3CFC6AULL,
		0x39AC4C0B922D4562ULL,
		0x919273A4937EC37FULL,
		0xF9706B462D97FE2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF0DC5EEB811CB7ULL,
		0xECE59BDBA131C0EDULL,
		0xD5439C9EC0E7B30BULL,
		0xDB57F3142D4075DFULL,
		0xFB1E31820A725B46ULL,
		0x6346A3D3F08A3803ULL,
		0xB666A68D2AE97274ULL,
		0xF47844012941E6AFULL
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
		0xCE0B179F69576650ULL,
		0x896B90074D2C55BBULL,
		0xC641FA1BDE2C6F6BULL,
		0xF0733F72140D8856ULL,
		0xE916DA3B52EBB13AULL,
		0x1C11D224651B59B1ULL,
		0x0672F98574368761ULL,
		0x0B49688F94418FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x370135FFDF05BB59ULL,
		0xEAEB01E16B8385FEULL,
		0xFE680FA3E4C49B89ULL,
		0x2CBC3BCD7A63101EULL,
		0x04215F766695F983ULL,
		0x767F8206751DDD1BULL,
		0xE796C8C0F7C60C03ULL,
		0x5AD4B606776B7E1AULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x20A4DF16A46EA697ULL,
		0x169E40C1777DDAF1ULL,
		0xCC32E75291268093ULL,
		0xCC5E562EF7DD261CULL,
		0xCD63AC770DABAA3DULL,
		0xDD4157BD63716EDCULL,
		0x27490199CC43F43DULL,
		0x5D5F0508B6D87FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20A4DF16A46EA697ULL,
		0x169E40C1777DDAF1ULL,
		0xCC32E75291268093ULL,
		0xCC5E562EF7DD261CULL,
		0xCD63AC770DABAA3DULL,
		0xDD4157BD63716EDCULL,
		0x27490199CC43F43DULL,
		0x5D5F0508B6D87FE9ULL
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
		0xCA4F20BC2E287C4BULL,
		0x5E1DC0E2EB27102BULL,
		0xC2C17865A106F89BULL,
		0x5AC06C22A2906035ULL,
		0xAC0906899DA6A203ULL,
		0x5856332FAAF4F649ULL,
		0x476AD0F31BBA9024ULL,
		0xB6ECD5714EC42281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A133AA5C81F186ULL,
		0xFE9FB7FA8D14C518ULL,
		0x13DCCAA8829D24FCULL,
		0x6A64A245BB7E6C12ULL,
		0x0E03525472BFFA1EULL,
		0x39F484C08AA484B9ULL,
		0xEEF0F803F2EB0143ULL,
		0x288D625E7FC8B3B3ULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x40555D6727FC7635ULL,
		0x39FFEEDAA7013C7DULL,
		0x288759BC710E37E7ULL,
		0x8C176523B6C91AC6ULL,
		0x8C92B8BEB48001D9ULL,
		0x1AFDA8DDB7007634ULL,
		0xC57E27537FBD5E5FULL,
		0x6E14D45A16EE3892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3621EB49B4DE92BULL,
		0x74BB55CFAB13937AULL,
		0x22E390D2F1C248C2ULL,
		0xAE4DA50FAE6C6048ULL,
		0x12A49F1EBF213556ULL,
		0x50E84EAC4533D847ULL,
		0x6D92089537B7BF29ULL,
		0x897A0EAFA0C1D4D8ULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCE97D815D1777AC5ULL,
		0x66B04BA017C6334FULL,
		0x0A1DC95DCDACB2EFULL,
		0x007489F9A425718BULL,
		0x4825B4FF67FA2CD8ULL,
		0xBA556FDE0E35BAA2ULL,
		0x28EF6F0EBE4DF4F6ULL,
		0xE9D7D45C81E9F9CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C4218595E1C788ULL,
		0x111EA7FF34D0A109ULL,
		0x189099E9114EFB68ULL,
		0xBC8633CADE12AE1CULL,
		0x2248CEE70C10C373ULL,
		0xCCB2BE3251E36C6CULL,
		0x4D7EDC68DEDC7E3DULL,
		0x3E5C0355C0E50113ULL
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
		0xB8BDA69D25D38A68ULL,
		0x4A4F63C3BB6A4056ULL,
		0xA3C6010BF3926933ULL,
		0x4C3C09C636538668ULL,
		0x2DEC3C3F2CAD8A73ULL,
		0x925EAB2F20733BC8ULL,
		0xBF5ABDDB29E3E817ULL,
		0x405569F83669C597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8BDA69D25D38A68ULL,
		0x4A4F63C3BB6A4056ULL,
		0xA3C6010BF3926933ULL,
		0x4C3C09C636538668ULL,
		0x2DEC3C3F2CAD8A73ULL,
		0x925EAB2F20733BC8ULL,
		0xBF5ABDDB29E3E817ULL,
		0x405569F83669C597ULL
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
		0x078448E749D4A0BDULL,
		0xF05CB03C55AB8615ULL,
		0x9B7E420B3E12637DULL,
		0x95AB0342776BED19ULL,
		0xB2B923FCC653CE2AULL,
		0x36E69C15382DC0C8ULL,
		0xB185B7D5F2617F9FULL,
		0x4291034525B2D436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B940654A332B12ULL,
		0xFA9B1E55AB0555EAULL,
		0x6CD4F2556D73E6D0ULL,
		0x590E6CEB744ED427ULL,
		0x193749DC48B7E8B2ULL,
		0x7F25663204DDE13BULL,
		0x8C5FE34CEF07C109ULL,
		0x57466F5DB6D46C7EULL
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
		0x398D457B96DD598FULL,
		0xC7643F5BD008176DULL,
		0x4AFBD3B1262E4336ULL,
		0xD0F83A5B5847FAC9ULL,
		0x8E9383A8E2D1BDCDULL,
		0xCA9DDFCF40EE4F56ULL,
		0x2837FFC0FE90BDAFULL,
		0x4478D7C0FE4BBF43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C932359DCDBC0D3ULL,
		0x0147E89DFFB8BC27ULL,
		0xBF73C56B4CA034A2ULL,
		0x53751729DA489825ULL,
		0xF8CEC6ACBACF0F00ULL,
		0xF587C0132E8155EBULL,
		0x721364AE5401DD71ULL,
		0xADF60E9889067CADULL
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
		0x336C4EB2B3EE8AC9ULL,
		0xA6416CD54CCFFB2DULL,
		0xB2FB4E0EA0086E56ULL,
		0xE3ED666C8071F701ULL,
		0xC93EF9AD22791229ULL,
		0x4EF5E3AFDB499951ULL,
		0x79A52E014A53E651ULL,
		0xF872C95F808D2DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4792B6BDC35B3601ULL,
		0xBE1CE182C9320612ULL,
		0xCE6A1A71F8B3266FULL,
		0xA246914FDF03E2C9ULL,
		0xF35715F753894BEFULL,
		0x6E70F100144F379EULL,
		0x1E9EB831C4ED091BULL,
		0x0FCEDCE5EECF53A8ULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDBAFFFAC420F2F7FULL,
		0x253F4010391BA9B5ULL,
		0xAD200DEA9F8969F7ULL,
		0x42CF89086D0B373AULL,
		0x3B19193D9C022462ULL,
		0x3D59BD39D21B7E8DULL,
		0x72A19E6263B5467DULL,
		0xD056CCFC6B419E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBAFFFAC420F2F7FULL,
		0x253F4010391BA9B5ULL,
		0xAD200DEA9F8969F7ULL,
		0x42CF89086D0B373AULL,
		0x3B19193D9C022462ULL,
		0x3D59BD39D21B7E8DULL,
		0x72A19E6263B5467DULL,
		0xD056CCFC6B419E5CULL
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
		0xE81A981D6C0BA0A7ULL,
		0xE34051C176752975ULL,
		0xC9DE4414747070ECULL,
		0xE49DB4097FB4C98BULL,
		0xC29FFB7A70271C70ULL,
		0xD8DED45EB47CC52FULL,
		0x63CFD6744FBA6353ULL,
		0xBAE84A21CBC2EAD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A8A3991AFFACBAULL,
		0x28FE37C3CC5C4C3CULL,
		0xABC3A7E0A9CE6650ULL,
		0x0433746CFA33D4AEULL,
		0x3B839719E8529332ULL,
		0x9E2BF1C71084820CULL,
		0x88D8A46EAD817B4EULL,
		0x7DD3AC510D7A4446ULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBC47F254307A375CULL,
		0x79B42F4FFC394829ULL,
		0xDACA8275124C74FDULL,
		0x7A10042AF18082B2ULL,
		0x3A2B1348138F8FC4ULL,
		0xAC5AFDE72B6265B4ULL,
		0x8C4C36E5A9856614ULL,
		0x5693C49906CB3277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247D4962C180A99EULL,
		0xDBC55B16693754EFULL,
		0xD51BA129417E098CULL,
		0x0652980853DEAB62ULL,
		0x438450D1AE93DA46ULL,
		0xD6B9DB76D288DDF1ULL,
		0x42303745B3F6E901ULL,
		0xE10424900B38149FULL
	}};
	t = -1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9B00DFAA163C9F9FULL,
		0xCE5792B415895532ULL,
		0x62FB714D82C1273FULL,
		0x9A8E24928C778B07ULL,
		0xE1B5B628D65EC75DULL,
		0x72416082F123EABCULL,
		0x7789052AE079F386ULL,
		0x674556B92E4B41CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89C6EF5443E1B560ULL,
		0x8CE7E2E72B26EA13ULL,
		0x16103C07B8CC0182ULL,
		0x574E740A818F506CULL,
		0x6BA56B4BEF4540B7ULL,
		0x53A3A2B889F0329EULL,
		0x1B809EFC03473ECDULL,
		0xE573DAE8F63481D0ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x71A9E06519D86E12ULL,
		0xB6CE4425C1FE205AULL,
		0xFE8FFA738E453851ULL,
		0x98AE57F21EB5CE27ULL,
		0xC083CADD48C066A6ULL,
		0xC8ECF41C49681DF9ULL,
		0x14968651FFCFA2C5ULL,
		0xA3264F76B9E0315CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71A9E06519D86E12ULL,
		0xB6CE4425C1FE205AULL,
		0xFE8FFA738E453851ULL,
		0x98AE57F21EB5CE27ULL,
		0xC083CADD48C066A6ULL,
		0xC8ECF41C49681DF9ULL,
		0x14968651FFCFA2C5ULL,
		0xA3264F76B9E0315CULL
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
		0x8C7198A9FC3C7ADDULL,
		0xD637875AC2CFA1C4ULL,
		0xE7E7E6DFEB0B236CULL,
		0xA11BD84F99A66CCAULL,
		0x3DFB0FDFD57FC60BULL,
		0xDA9A5528D87A4015ULL,
		0xFFAFD92BC649F51EULL,
		0x02FB5615209C22DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33DDCE8C6F4ABC98ULL,
		0x48B9CDE9FB3F2692ULL,
		0x23B6D0C03ACF3884ULL,
		0xF6B22A9ADC015D19ULL,
		0x6B8D627A9FEDAC01ULL,
		0xE93C7EBEB992FC0BULL,
		0x829D5C6D788998CEULL,
		0xC6C12D7CC5774129ULL
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
		0x1C4C5E1AC9D86B33ULL,
		0x1DDA8AA4307D8184ULL,
		0x7A472CD3CC1DE7DAULL,
		0xE5CBCBAD8FC479E8ULL,
		0xC7F071CE06F6F5AFULL,
		0xC8460B2794D684CEULL,
		0xF2595419BEBBF184ULL,
		0x11A5A1BA43EF16D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F3E0D4A0D40617ULL,
		0x8D35234BE1244576ULL,
		0x584838E1558BD394ULL,
		0x4CBAD5BD2FE55F89ULL,
		0xBDA7B9952E384F36ULL,
		0xFE66DAD6168FE756ULL,
		0x49D12EF5F6D9FC2FULL,
		0xCF382BB18C8AA5ECULL
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
		0x4047E2714F8CC5BBULL,
		0x9E2D5BEAE09604AEULL,
		0x4994271C74E02007ULL,
		0x1C28776C64BA50C0ULL,
		0x39D644EFEB760BE2ULL,
		0xCC84D16275452AEDULL,
		0x8510F81DBA313216ULL,
		0x472B1157C2D4FA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A8568DE7617E93ULL,
		0x61447D13766A39CFULL,
		0xCAFF2DB483AC97C0ULL,
		0x01EACA1EC0367E7DULL,
		0xAA6DFEBC87057AADULL,
		0x82ABF8BAA3274590ULL,
		0xFEE772F8AB8EC5FFULL,
		0x903198411D200CD1ULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE07B191C74EBF001ULL,
		0xC5B92580134AA68BULL,
		0x164BF244714A4967ULL,
		0xFCA097D08F4A8E64ULL,
		0x874E61E58BECCE2DULL,
		0x5BCE9C4F919C13B8ULL,
		0x2E6FE8263EB2B6C7ULL,
		0x097F88976E466A35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07B191C74EBF001ULL,
		0xC5B92580134AA68BULL,
		0x164BF244714A4967ULL,
		0xFCA097D08F4A8E64ULL,
		0x874E61E58BECCE2DULL,
		0x5BCE9C4F919C13B8ULL,
		0x2E6FE8263EB2B6C7ULL,
		0x097F88976E466A35ULL
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
		0xEB467C9E07EF5D97ULL,
		0xBA8AFA3B5EC3F675ULL,
		0xEFC7FE7C2AFC2ED2ULL,
		0x8046532BD0B2EA13ULL,
		0xB4C7BACF7AF5189BULL,
		0x3C0AAD48C382C2DDULL,
		0x534943E52551AFCEULL,
		0x395351DA6714E854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22397D7DB554CF5DULL,
		0x67C9A934F4406F56ULL,
		0xD1EEFB92CE5161B1ULL,
		0x3064FE11A10C2AEEULL,
		0xBEF0789D1D1B812BULL,
		0x1AA4EC9B0794A149ULL,
		0x4C74A5E39F7AE947ULL,
		0xBEF499E3F1CA69EEULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEA2D05834E15BCD4ULL,
		0x3D3CCD0FD426C129ULL,
		0x595278832BE583BDULL,
		0x45819BCBA0F3EEF4ULL,
		0x0A3D558C35E71268ULL,
		0x29DEA01395CF3A43ULL,
		0xB5D4103E48219CC7ULL,
		0xE0CEB9A058ADE63FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x796E9E35E786432EULL,
		0xE6DD885F304DAF15ULL,
		0x0D1F50771AB46E8DULL,
		0x3F2992BB3180C0C0ULL,
		0xFDF7F2C9366659A5ULL,
		0x666AE383A97EE916ULL,
		0x80DEF1FDDEA5CB0EULL,
		0x7BDBC2A6AC97C852ULL
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
		0x1D85E47A0E5F2A54ULL,
		0xA19B15721847D981ULL,
		0xB9E00FEAB750AD04ULL,
		0x9CF44C64CC4F89C5ULL,
		0x94744BD14FB082ECULL,
		0xA110DC592A2C0239ULL,
		0x1EB78A7FD98D80B0ULL,
		0x0E2557F25D3B3DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4EACC1809511F56ULL,
		0xDF6EC7672D1202FDULL,
		0xD24B6D943FFDAB10ULL,
		0x7600BB07B5E5D20BULL,
		0x730F08F79249A18DULL,
		0x277648D32BAD800BULL,
		0xA6D966B2A06317FAULL,
		0xB0FC4286BD7782D0ULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x03F587F14C595501ULL,
		0x499A3C886C430A00ULL,
		0xD7D6D8E9098A7133ULL,
		0x5AFC3ABD422003CFULL,
		0xA9EBC6507547C630ULL,
		0xB577080B1CCA9B50ULL,
		0xDF6B646429907A29ULL,
		0xA617A0F3999FFB3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F587F14C595501ULL,
		0x499A3C886C430A00ULL,
		0xD7D6D8E9098A7133ULL,
		0x5AFC3ABD422003CFULL,
		0xA9EBC6507547C630ULL,
		0xB577080B1CCA9B50ULL,
		0xDF6B646429907A29ULL,
		0xA617A0F3999FFB3AULL
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
		0x6B4FF980A98DD528ULL,
		0x7E5525743039E1ACULL,
		0x09E46A8D665AC739ULL,
		0x7ADE35729760142DULL,
		0xC5B23C7D2B74303CULL,
		0x9B2D1065783EA4CEULL,
		0x069F13757B4AA7B6ULL,
		0x62B85CA84F07A389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE342F9633A2D9C3DULL,
		0xA4E87BCAAE54A21DULL,
		0xF0DA52FAE3051167ULL,
		0x657200DF58E7BCACULL,
		0x5F4A1358AED72C0BULL,
		0x08555F3C15AE0C49ULL,
		0x1CF54655F50674F2ULL,
		0x7AEE9197D8A43400ULL
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
		0x27DC3E667AE32C0FULL,
		0x6D89DBE382485194ULL,
		0x4FD65E5749DC34A2ULL,
		0x3F0F9A33B68B66C4ULL,
		0xB2C9E119CC1ED32CULL,
		0xD9AB3A7E1DA4AA8DULL,
		0x0BB0266DF1BB234CULL,
		0x7FBB5571CB9FDA9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CACDA08ADD6236ULL,
		0x883991CE67623143ULL,
		0x261AA112EAE8EDF0ULL,
		0x300F3D7235F28085ULL,
		0xEE5FC0B0052725F0ULL,
		0x089718F2F4802721ULL,
		0xEC0B0249559F1E9AULL,
		0xB17A0E3A0375D2D0ULL
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
		0xE1E89DF4DFB80475ULL,
		0x4CD0ED1198B572F5ULL,
		0x49B652758B2E7516ULL,
		0xF42A965599744181ULL,
		0xC5DE9E77F291BF04ULL,
		0x7BFA5E57C02B35D7ULL,
		0x949CACE428D4DD7AULL,
		0x9B3DAF6472C368B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B2EC121E24880EULL,
		0x7EFF6C3A2CBE82B7ULL,
		0x63814A8078986FB1ULL,
		0xE2718F995B8F435FULL,
		0xAC35418E66F1A7C6ULL,
		0x2F4E748BF9A131DAULL,
		0xFA9CA377DEA85204ULL,
		0xA561C1F42180B53EULL
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
		0xDAABA60D9E4FC0EEULL,
		0x907439602A98EEB4ULL,
		0x65B276C27A236C11ULL,
		0x2D201E7B609433F7ULL,
		0xCDD713301F63CE51ULL,
		0x446A57348F86F03FULL,
		0x97246A01542DE2F0ULL,
		0x46942673C7CC0A71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAABA60D9E4FC0EEULL,
		0x907439602A98EEB4ULL,
		0x65B276C27A236C11ULL,
		0x2D201E7B609433F7ULL,
		0xCDD713301F63CE51ULL,
		0x446A57348F86F03FULL,
		0x97246A01542DE2F0ULL,
		0x46942673C7CC0A71ULL
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
		0x9902A4892D77A2AFULL,
		0x38B8EBF0D15D0EB0ULL,
		0xC8B6EF97FA7D2D27ULL,
		0xFCFE9BBD9A19F192ULL,
		0x9633C70BC9E86A6CULL,
		0x45E6C30C63FAA721ULL,
		0x8842984C84F6A2D3ULL,
		0x0E513F4723496BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6757F3229B0128ULL,
		0xCDB1B4F47D996C7DULL,
		0xF57F897CFFF23ED5ULL,
		0x12E0D264292D5098ULL,
		0x44EB5E25C3FFB2C9ULL,
		0x76C9FD02D5C2D3FCULL,
		0x6048DA3A0F7D65CDULL,
		0xFCCEB46F191BAAB0ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x684BE8C1B0085CB6ULL,
		0x6BE89535906CE864ULL,
		0xBE24AA829BEB3D7AULL,
		0x3F448651A11CE9A9ULL,
		0xC5451462DE586F8BULL,
		0x3C9E465F2E5E17BEULL,
		0xA70437054B381DDEULL,
		0xA1011443AADD4051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36ABD6838B01B666ULL,
		0x41403B78B504AAD8ULL,
		0x4C0F9474F73351B6ULL,
		0x2BA62E9D38E7540EULL,
		0xF30B54B11E1E43F0ULL,
		0x5B6EADAF629997E1ULL,
		0x2E1E820B4FDD87F7ULL,
		0x73B460ED3DAF4504ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5C2BB528DC338AADULL,
		0x7BBDF26C39D9268DULL,
		0xB70E6EC2DF6F1B94ULL,
		0xEE523148568F1FF3ULL,
		0x628DB9E7152A9D19ULL,
		0xB74E15FB5F812A22ULL,
		0x2223C17A290114E1ULL,
		0xAD67DB6C71EF4FF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAD3D54318E0536ULL,
		0xB3F6E1D36988AADDULL,
		0xCCFE33CA8EE7B035ULL,
		0xDDE7CCA8C6EC68E5ULL,
		0x31F955EC4451BA66ULL,
		0x2405B24D3DD529FEULL,
		0xBBD3E1140DCFD1FCULL,
		0x39209CFB2B19BD89ULL
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
		0x70050E3D41F1A22AULL,
		0x4BAC1FEC4289D125ULL,
		0x08F7F906C065F25BULL,
		0xAD1D6BD44D521BFAULL,
		0x0CE7D1B4C29D3B8CULL,
		0x44B7238D8DB5739AULL,
		0x75FD704D7C7EFD16ULL,
		0x985D4EAFB2CA925FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70050E3D41F1A22AULL,
		0x4BAC1FEC4289D125ULL,
		0x08F7F906C065F25BULL,
		0xAD1D6BD44D521BFAULL,
		0x0CE7D1B4C29D3B8CULL,
		0x44B7238D8DB5739AULL,
		0x75FD704D7C7EFD16ULL,
		0x985D4EAFB2CA925FULL
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
		0xAF57ABE0A2E52E48ULL,
		0x9059CD3935B934F5ULL,
		0x1E3C5E518593947DULL,
		0x46162A431B0824F3ULL,
		0x0267F4E092062CD6ULL,
		0x4B87535D9324BE16ULL,
		0xC0122F25D1167B8BULL,
		0x1C445512DBFB8A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x755DF23601A76E43ULL,
		0x3B35BAB26A210006ULL,
		0x8EFC60CD54F17784ULL,
		0x03D47BECE54AAE45ULL,
		0x06D8E2F986F57748ULL,
		0x09EABDB9C029A30AULL,
		0xE9DB3D9CC50CBD1FULL,
		0x8B0818402EE441F9ULL
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
		0x710C419F7438B93BULL,
		0x55E17ECA6AE3D7EFULL,
		0xDFDD79A5FE0BBCB2ULL,
		0x0230026911F906DCULL,
		0x415E77E2BD604358ULL,
		0x93E7B8A7DF785FEDULL,
		0x753CF2B3D1E6D8DDULL,
		0x5B735DD22DC984BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2213C0AB97F95D41ULL,
		0x44BA89E7C7A60092ULL,
		0xF563644D9031158BULL,
		0x037F38ADCABBB93AULL,
		0x1704534E5B68B2D8ULL,
		0x985CCCE89607280DULL,
		0xD8D47C210BCBD415ULL,
		0xD04CE77177F69D11ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC8481EE8A64B6ED9ULL,
		0x92277475D9D74BB6ULL,
		0x57CAEA55DD320CAFULL,
		0x723503C5B757BF77ULL,
		0x77A131ED71C7951BULL,
		0x2A8BCACAFDF34095ULL,
		0x6E45FD505346BA43ULL,
		0x47A68B3C27D95BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D9EAC667A3809CULL,
		0x6CFC05A77387AD28ULL,
		0xA5B2AD46FA52E8C8ULL,
		0x0F0DA068A953BB36ULL,
		0x6608CD80EE85A862ULL,
		0x509C56418A083B8AULL,
		0xE8336C0D1AC23E2CULL,
		0x99D2FCBDCC146C35ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFFDBE9E6257D2399ULL,
		0xA1EDC4A2F08FCC5BULL,
		0x092F8988786FF522ULL,
		0x48676AD3FA03B415ULL,
		0x4CD85220D5BDDC15ULL,
		0x37D24C842EDB5864ULL,
		0xE83C01F4062358BEULL,
		0x35A7BD175ADB80DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFDBE9E6257D2399ULL,
		0xA1EDC4A2F08FCC5BULL,
		0x092F8988786FF522ULL,
		0x48676AD3FA03B415ULL,
		0x4CD85220D5BDDC15ULL,
		0x37D24C842EDB5864ULL,
		0xE83C01F4062358BEULL,
		0x35A7BD175ADB80DAULL
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
		0xAF133E5CF7C22225ULL,
		0xB4BAEB410F56E3E3ULL,
		0xA462742BE83B8D8BULL,
		0x85DC56C3327CC54BULL,
		0x5AAB52FABE4BC7DCULL,
		0x45926646C0E68781ULL,
		0xB1E74023C1699B8CULL,
		0x784099AB6B5A3981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57ADFD0032BF8BE6ULL,
		0xE312534C3CA5D40AULL,
		0x8D7778C1E6D7BE74ULL,
		0x872BE6709AE73477ULL,
		0x68D79976513C6AE8ULL,
		0x6D2E6DE03542783FULL,
		0x57FF30EE9454F8E1ULL,
		0xC1FDBBEEE4F80463ULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x367A14AE3CC0F961ULL,
		0xC2AC86B8F067C19AULL,
		0xDBA07D62B7618443ULL,
		0x31C0FB2A5D349C47ULL,
		0x9A55C0FF89DF4241ULL,
		0x65CDF0E5F58034DBULL,
		0x3C82954C8D4F1C17ULL,
		0x50FB75B3988D2FF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D1A0713D27F2C2ULL,
		0xCF3E9C8CF47B4B5BULL,
		0x333EE107D1EC81F1ULL,
		0x4189F6B12FB3E771ULL,
		0xD67B9A1EB96CFA2AULL,
		0x093F03F0145A6A6FULL,
		0x09A440E40B5743ABULL,
		0x573F1425923D1ACDULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x00B19009F0512C6EULL,
		0x9D6E079A5245314AULL,
		0x0B5DB4BFD9E45E11ULL,
		0xD93E1A7B3A080FB1ULL,
		0xD8E94E2A6CF26A38ULL,
		0xBBE376F66AEFA064ULL,
		0x352252BFC1C187E9ULL,
		0xF83427E810AB5AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AFD1DB5A940DBBULL,
		0x50233BA11A457177ULL,
		0x9799EFE48E8F2BF2ULL,
		0xA6539F0D73753CD7ULL,
		0x3E9211CC8B69688FULL,
		0x9BE6FF3796D86732ULL,
		0xF04EA5B13CCF967CULL,
		0xD6729881738D6BF1ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBA94E688F9783398ULL,
		0x84C8646EC69D0DA8ULL,
		0x90977C748CB8BA80ULL,
		0x005D3D756F550FFEULL,
		0xE5B12F6C3A4AFB9FULL,
		0x5B09B7FADA310C30ULL,
		0x5EB7B8258F3106D8ULL,
		0x690932535937B280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA94E688F9783398ULL,
		0x84C8646EC69D0DA8ULL,
		0x90977C748CB8BA80ULL,
		0x005D3D756F550FFEULL,
		0xE5B12F6C3A4AFB9FULL,
		0x5B09B7FADA310C30ULL,
		0x5EB7B8258F3106D8ULL,
		0x690932535937B280ULL
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
		0x2002AFAADCBBD6FDULL,
		0x531930A1B8B5FD4CULL,
		0xEE44FED064697B72ULL,
		0x83A08CE7BD74E8A2ULL,
		0xF2BD9212A0AD25A9ULL,
		0x6643169C6983B455ULL,
		0x543832F361391904ULL,
		0xD0DA7B7AE66F3E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E6AEA42D3BFD1DEULL,
		0xFE20D2955EDD2D99ULL,
		0x8E5FC188D94DDCD7ULL,
		0x40CB1F34CAA7B2BCULL,
		0xB0D264387FAA58F7ULL,
		0xDDA490854733658CULL,
		0x616CE8DD042BECA9ULL,
		0x416C3F52F7680665ULL
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
		0x2A2ECF2D4615D76FULL,
		0xCB9C9CF5413263DAULL,
		0x421D23143B53C7B6ULL,
		0x3E03C634A48DCB27ULL,
		0x4D4090166729B8FEULL,
		0x6851B1A4B539BE03ULL,
		0x64CA3FE98B0616A1ULL,
		0x728B76119CD01D74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5EB35F0E0749ED8ULL,
		0xB217C1990273948AULL,
		0xEDE0B7133655932CULL,
		0x7BA2C034FB17B4F8ULL,
		0x6E3BA23500345708ULL,
		0x5507492BFC3716A1ULL,
		0xFD669A829385428AULL,
		0xA920DCD5B75D2C05ULL
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
		0x90ACE6CE822993D3ULL,
		0xD2BBBA5F2AE8852DULL,
		0xE30F282E3854F9C6ULL,
		0x0D0F6564DDB9E4B6ULL,
		0x1F9773E7474F286BULL,
		0xDFABED1FCF858BDCULL,
		0x2AD97361AFB85569ULL,
		0x4A16DC0901A0E079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266F8AB71109D1B2ULL,
		0x4CC7DF7A1C8FB41FULL,
		0xC2A79614E2B98956ULL,
		0x6FCF7F9FCA61C62AULL,
		0xBBFDAA986E8CEFDCULL,
		0xB5EA408F006971D8ULL,
		0x8E16B2EEC5C1295DULL,
		0x204AD7EF5443CAF6ULL
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
		0x9A049B87E5ACD058ULL,
		0x1349E50CC7483359ULL,
		0xEBA771397DEF2BA3ULL,
		0x334F8E223CD6201FULL,
		0x8CEDA99C88301B58ULL,
		0x9B325DD9AE5B8BB2ULL,
		0x1069B9518EFBC85DULL,
		0x6280F4C68E2376A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A049B87E5ACD058ULL,
		0x1349E50CC7483359ULL,
		0xEBA771397DEF2BA3ULL,
		0x334F8E223CD6201FULL,
		0x8CEDA99C88301B58ULL,
		0x9B325DD9AE5B8BB2ULL,
		0x1069B9518EFBC85DULL,
		0x6280F4C68E2376A0ULL
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
		0xEC57F7C5EC1DE746ULL,
		0x733917CC8BA5BC00ULL,
		0x969B082F622BD295ULL,
		0xC0F777F953F7EEEFULL,
		0x0DB6113F33FD65B0ULL,
		0xA93DF7292A77EE5AULL,
		0x655DECF144A8DABDULL,
		0xC44C4F856911FD44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F67B644FAD72E18ULL,
		0xE27B1676242F8886ULL,
		0xE8726523CB47318CULL,
		0xD1940C7393BAE81CULL,
		0x177AC6B15E08545FULL,
		0x58E4D0105644A501ULL,
		0x2273AF188B8B9F62ULL,
		0x67962DD20C8A775BULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEF6A1515ADB70349ULL,
		0x56CAEBA4D9A44B2AULL,
		0x643A26698A23C3E7ULL,
		0x83D3D6809E6236E8ULL,
		0x47523DA76C0EEC71ULL,
		0xC3054C327B057F17ULL,
		0x6D7C69C64E3687F8ULL,
		0x1571EFC84D489627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4A0E786E8F7713ULL,
		0x71BE79DF2DE09186ULL,
		0x24D2383CFAE8C946ULL,
		0xBB485A1A4AC91D74ULL,
		0xAAC5DD15CBD4EF77ULL,
		0xB5627D6A708957E6ULL,
		0xA570F01BF401E200ULL,
		0x39014445DDADB7F9ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x944472CF79D8868BULL,
		0xD7AE209AAA2BAA5CULL,
		0xAC9237B547037B71ULL,
		0xF7A1F00BF1CCC79AULL,
		0x33B166E647ABA6ABULL,
		0x1873290E1E8C4FB4ULL,
		0x98C17E8722FB5E48ULL,
		0x3DE64E659F8103DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF28EF8FA61AE657ULL,
		0x3263D56A22CA1029ULL,
		0x203687782E839934ULL,
		0xD3A3CCBC5F071ABDULL,
		0x632603F5B1257832ULL,
		0x453EA2D7E8B5F467ULL,
		0xFF8E0EE82F406049ULL,
		0xA6BB8244321737C2ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0CA2802385315795ULL,
		0x4AB51240535C89BDULL,
		0xA1E4BCDD19FFF9FAULL,
		0x7AE6DDB6CB87AD3DULL,
		0x9D9DAD5D0D9F11FBULL,
		0x53006BAA6D9D401BULL,
		0xB7D790C0A45C2935ULL,
		0xA7952101DBE21BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CA2802385315795ULL,
		0x4AB51240535C89BDULL,
		0xA1E4BCDD19FFF9FAULL,
		0x7AE6DDB6CB87AD3DULL,
		0x9D9DAD5D0D9F11FBULL,
		0x53006BAA6D9D401BULL,
		0xB7D790C0A45C2935ULL,
		0xA7952101DBE21BBDULL
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
		0x0C7F30A4F30D2250ULL,
		0x4A74BCA32E3F5603ULL,
		0xE54D26250B6135AFULL,
		0x33DEDC471FE1F784ULL,
		0x13EDB4B97E383B1BULL,
		0x975CE6239B6B3336ULL,
		0x2A63722EC6C30EABULL,
		0xE1B8CC1D6F91A0FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211EBCB178AC0010ULL,
		0x32A492E5E93446D9ULL,
		0x002B5822641EE281ULL,
		0xA1E16AC6B3303059ULL,
		0xC53D486F36167FB7ULL,
		0xBE31EE4864EC6A12ULL,
		0x43A560FFE78ABE3BULL,
		0xF8CB6EC38AD5C01EULL
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
		0x5FDB11A894990529ULL,
		0x93F9E853F38297E9ULL,
		0x8ECBF9B7A7C98025ULL,
		0x920119E1C6EDB070ULL,
		0x038E65588D44BB45ULL,
		0xCF161534D01F529AULL,
		0x889906ECBB0B7F06ULL,
		0x42BC2DF142FC2103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2A6F668824824FULL,
		0x97FA82A0C305DD85ULL,
		0x85D1D629B4F73A98ULL,
		0x63DAD1E74BC63B9DULL,
		0x96DB3F6590C8032DULL,
		0x11B9A2486FEA6B82ULL,
		0x36B940A183223CD6ULL,
		0xB59144A3E8FC8290ULL
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
		0xB9C2A4094002FAFDULL,
		0x4292D4561E42F77AULL,
		0xC9B8D5C8F5A47AB7ULL,
		0xF801912F61713680ULL,
		0xAF93BDC66F8D4BFFULL,
		0x14CC9B5B8F138D17ULL,
		0x9C573DED7B0FCB1FULL,
		0xA2D28BDC89C15388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F5F71825F63DEF5ULL,
		0x89C9482D497BBD64ULL,
		0x03BEB753B0135DA9ULL,
		0x62FCF68ABB4ABC0AULL,
		0xEC326876B450B0DCULL,
		0x061E3404E50FAB26ULL,
		0xE5EA41DA14CAB7DFULL,
		0x80F9D23FA7CCA379ULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB33CC68BE743212CULL,
		0x2B3D71E7DA94002DULL,
		0x1D286ED66F16E737ULL,
		0x0893309277835F6BULL,
		0x7DF85E6A6BE583BAULL,
		0xDB682360EE651B18ULL,
		0x84F5AB0752E1B007ULL,
		0x6E1DCCDB1586CA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33CC68BE743212CULL,
		0x2B3D71E7DA94002DULL,
		0x1D286ED66F16E737ULL,
		0x0893309277835F6BULL,
		0x7DF85E6A6BE583BAULL,
		0xDB682360EE651B18ULL,
		0x84F5AB0752E1B007ULL,
		0x6E1DCCDB1586CA89ULL
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
		0x2BE9D2440668FCA7ULL,
		0x9EEB92C202E60638ULL,
		0x5DFC4477B9D7A8CAULL,
		0xA8FBA82244B163BFULL,
		0xDA5EAE67443F2E0FULL,
		0xF9384F5BE6ECC0EEULL,
		0xA4657DEF5E4FC095ULL,
		0xC4800F461FFB46CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE941F9073AD527C2ULL,
		0x7326FDE1FC78D99AULL,
		0x65642A7609F2A43FULL,
		0x6D42DAAC2A8F7721ULL,
		0x14ACC77D45578B8EULL,
		0xC7336655EF5494B2ULL,
		0x32E825D3B35CD18DULL,
		0xE78A577D3808BA37ULL
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
		0x6635282B66920D34ULL,
		0xCBA973143D49CC3AULL,
		0x3EE12FA471E55724ULL,
		0xCE48DEEBC2DFA57FULL,
		0xCF742FF265612F4EULL,
		0xA208B83968D8BF6AULL,
		0xEBE60B98DDCC7D73ULL,
		0xDA1EB314A5BAE204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8598EB7AC0049702ULL,
		0xC3FE6F5604C7001AULL,
		0x78B9E764EB16DC93ULL,
		0xED8A35C3DAE4E5A6ULL,
		0x5544FF9992FD1C88ULL,
		0xE8C7C8CADF5E37B7ULL,
		0x3E11480BBF8302B5ULL,
		0x0DA12C0244F52FC6ULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7D54ACB6567B38A4ULL,
		0x6F28DEB6AD647EB6ULL,
		0xF265F7474536899CULL,
		0x743A7DD253D8D13CULL,
		0x02D30E0ED9F5EEF4ULL,
		0xA27FA0BBAA5DD4C8ULL,
		0xF458D81634EB5DEAULL,
		0xD4A2F0FFBC94F8BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F20CE459D6B180FULL,
		0xE9B5A149A9C76266ULL,
		0x45971436C1CD91E0ULL,
		0x021B1A25CA48DDCFULL,
		0xDACEBF4EE62B9525ULL,
		0xC6C92439812E3ACBULL,
		0x2B20CA48ACBE2CF3ULL,
		0xCE064209E4E322FCULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1F58141A76C15E83ULL,
		0xB030A8B5DC9B4CEBULL,
		0x3292B493AE76087BULL,
		0xB9C03051496FDACDULL,
		0xB9D7053CF5EAD37AULL,
		0x496A154AFFF00E53ULL,
		0xE19C2F25DA18ED0BULL,
		0xAAF2CBC8DDCA2CE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F58141A76C15E83ULL,
		0xB030A8B5DC9B4CEBULL,
		0x3292B493AE76087BULL,
		0xB9C03051496FDACDULL,
		0xB9D7053CF5EAD37AULL,
		0x496A154AFFF00E53ULL,
		0xE19C2F25DA18ED0BULL,
		0xAAF2CBC8DDCA2CE2ULL
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
		0xE0E55FC317B64C07ULL,
		0xB0E54ADFE1E83D4FULL,
		0x30081FECD6502E4DULL,
		0x3FBB45E3C93FA4F6ULL,
		0x3985CCDD03506BB0ULL,
		0x03F65E5AEA6E346FULL,
		0x6AE3C282D5E5A60AULL,
		0x214F16FF8FEE8482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40159FB8E6225DDAULL,
		0x7DD22F3FD209A35CULL,
		0x76622090D298194FULL,
		0x055A7E21D0F16906ULL,
		0xFFFF8BC77014D5A4ULL,
		0x22ECE10653EC99E8ULL,
		0x255C7D4D7EA68405ULL,
		0x48FC656DFCEABDD3ULL
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
		0x5248265F63757DF9ULL,
		0xC0ACE09374FC5399ULL,
		0xBD93F9C903D78C68ULL,
		0x203E19A9A6020ADBULL,
		0xB3459CB8F788B8CDULL,
		0x786466738A7B40AEULL,
		0x78D0EA0F2F78BDFAULL,
		0xA6FCBD97FD348C19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38106C98A6A90749ULL,
		0x3083E939915A5257ULL,
		0x48B40407F6464DB9ULL,
		0x5264C9FFD54E915FULL,
		0x4DF2490B64D41681ULL,
		0xC723E6C5B9D66DC7ULL,
		0xDB3ECF44A7C3DDF8ULL,
		0xE650163F78B0AB54ULL
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
		0x1F874F18F6A605B8ULL,
		0xE5B7B05068D5E2E9ULL,
		0xFA60F071EB1FFE24ULL,
		0x0F79CE395BF2E410ULL,
		0x7986B1A83C3CAB05ULL,
		0xE5ED4193EA98D5C2ULL,
		0x8319FC12BE32913DULL,
		0x9094B19A6C73C590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD60985376A02ABULL,
		0x1B4859C85B475F62ULL,
		0x12F853160E11170DULL,
		0x3CC8B70F820F86B6ULL,
		0xCA6872702BB505B7ULL,
		0x59087D1F2890734AULL,
		0x3E4FDB9A06844473ULL,
		0xFBB9387BFDC8BFFDULL
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
		0x841E248C3123B6A2ULL,
		0xF76668D397C2652CULL,
		0x640814F0F34BED65ULL,
		0xAFDE6BF5FE85A94EULL,
		0xD7F9B2267DA22310ULL,
		0x1E8B4D5C6AE81DC0ULL,
		0x3AD74E0E099D8E8FULL,
		0x9BB8902545CD304CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x841E248C3123B6A2ULL,
		0xF76668D397C2652CULL,
		0x640814F0F34BED65ULL,
		0xAFDE6BF5FE85A94EULL,
		0xD7F9B2267DA22310ULL,
		0x1E8B4D5C6AE81DC0ULL,
		0x3AD74E0E099D8E8FULL,
		0x9BB8902545CD304CULL
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
		0x082D22A955CCE3BFULL,
		0x6AA00F3326BD74FEULL,
		0x6130EB27E9F7DF14ULL,
		0x8122F892180F81FEULL,
		0x73DE231F22130D9EULL,
		0xF43960406C1C09C1ULL,
		0x7F03EA83668B5C4EULL,
		0x4E115738C73303FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x535956BE25A7E612ULL,
		0xF25F27A50D21001BULL,
		0xCDB8C2471BF211E9ULL,
		0xF6AF46673D70D92FULL,
		0x97DE9B4758EF2A1BULL,
		0x16FE3FB80E2361B8ULL,
		0xC23C3DCFDC520F38ULL,
		0x3027B63764E38713ULL
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
		0xEFB61FD4F4890921ULL,
		0x0A57ECB3D58A7CCFULL,
		0x5558A8E72B41128FULL,
		0x88BA25745A7E898DULL,
		0x12783C8247219F42ULL,
		0x3CE0890DF9F43D5DULL,
		0x18870C17E433E4D2ULL,
		0x2C5C2362FBFAC8D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CAFC6BB311F9175ULL,
		0xCA82F795DCEEFC9DULL,
		0x56801512A00674BAULL,
		0x31438856C864E6A7ULL,
		0xE6BD27ACD1848BB3ULL,
		0x861B66E31ECE3863ULL,
		0x614D83D2BCDD4FE1ULL,
		0xF2A178C5A2417B5DULL
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
		0x8609AED8322191D7ULL,
		0x8AC6D4705F1065E0ULL,
		0x19093A530ECF14D4ULL,
		0x1101E52513EA2883ULL,
		0x7366232ABEA19C94ULL,
		0xD587EA4A451C30FEULL,
		0x97491FA9E704F1E8ULL,
		0x76A10284D8DB144FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA137344B8247BC94ULL,
		0xE43C39FE60226303ULL,
		0xAD0AD4316E98BEADULL,
		0x7D1984F3EC5B0931ULL,
		0x3F8BD556A647F21DULL,
		0xE26E375C43C579E9ULL,
		0xCA86CAA65844EBBAULL,
		0x92A8E77E6CFB57FEULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6DA1BE6CFCD1E02FULL,
		0x43D8B46B010E0EA7ULL,
		0xF70453964B6D9EABULL,
		0x16BA3869A000CAA9ULL,
		0x2A846171B97D0EFEULL,
		0x0D803F83D5282847ULL,
		0xDF5C0944B6100AEFULL,
		0x3DF3C08FA4320F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA1BE6CFCD1E02FULL,
		0x43D8B46B010E0EA7ULL,
		0xF70453964B6D9EABULL,
		0x16BA3869A000CAA9ULL,
		0x2A846171B97D0EFEULL,
		0x0D803F83D5282847ULL,
		0xDF5C0944B6100AEFULL,
		0x3DF3C08FA4320F33ULL
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
		0x9874257296F51360ULL,
		0xBC43BEDA07E40C96ULL,
		0xF6EF29E43E21AA53ULL,
		0x41EEE848DEBE2BD5ULL,
		0x043C5E1C1BCFC829ULL,
		0x4FDF28188E64796BULL,
		0x632DA9CECAE53012ULL,
		0xC9BFCC10FAE5A441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A4F4DC0D8EF1FFULL,
		0xEECE496E826ECE38ULL,
		0x1A70F16CA9DE2E98ULL,
		0xF5BD6A7E8940F43AULL,
		0x713EA8610054E98FULL,
		0xF6E5903E8B0F8855ULL,
		0xA14754199FE795CBULL,
		0x5E2A79DAE803E80EULL
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
		0x5E80076E47E39A06ULL,
		0x7AD7205A4BBCB6D5ULL,
		0x1855DDE308F1C708ULL,
		0x02201F63AD33A815ULL,
		0x8C9D0529120B58B9ULL,
		0x4B99CC252D8B3755ULL,
		0x2B8DD4077ECA7851ULL,
		0x0ED9EC396C66E7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2CF8E5B556AFEEULL,
		0xE3CA5BD2EC480D1CULL,
		0x50B3782B84AEE89AULL,
		0x77E377D8F15D0835ULL,
		0xDD0E90BD29E53D1DULL,
		0x222591280B3F69FBULL,
		0x50D2074D1577E42CULL,
		0x0288A3919FF1FC66ULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAE4BA390A76D71F9ULL,
		0xF3D7C29A27D14A51ULL,
		0x07687A96433F5A1AULL,
		0x876D22B9B496C92CULL,
		0x7B304F69099F33E4ULL,
		0x44B2B8A8EFC74E0DULL,
		0xD58BC781DA165944ULL,
		0x64C4A5C8CE2D7674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47203E466B4CD882ULL,
		0x13BF4AF2B7A9B023ULL,
		0x419A66C1567AC911ULL,
		0x3A87108EC7423EACULL,
		0x31C7B27FF95CA089ULL,
		0x268EBD37756685C4ULL,
		0xE8EB3B9E003F7CC0ULL,
		0x8E3100482CB4E36EULL
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
		0xF18FC1936F4FEEC4ULL,
		0xD64A3C92B24C32B0ULL,
		0xFB7B0DFA19B0963FULL,
		0xB8CB2E2DBA3C71E5ULL,
		0x5B7C335AAFB9C72FULL,
		0x7DC70D55860C46B5ULL,
		0xEB1B15B0A79FD3C5ULL,
		0x615A03A74CD9BA81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18FC1936F4FEEC4ULL,
		0xD64A3C92B24C32B0ULL,
		0xFB7B0DFA19B0963FULL,
		0xB8CB2E2DBA3C71E5ULL,
		0x5B7C335AAFB9C72FULL,
		0x7DC70D55860C46B5ULL,
		0xEB1B15B0A79FD3C5ULL,
		0x615A03A74CD9BA81ULL
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
		0x18568374F9F9818CULL,
		0xEA4512D118C93763ULL,
		0xA7AABE0483AE758FULL,
		0x6B9E37218FC24109ULL,
		0x0600CF46F343A0B8ULL,
		0x8968BB7C413453BCULL,
		0x9C5108E86EFF9E28ULL,
		0x9BB19FBC62A6FFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE89E84CD0387DDEULL,
		0x43B40CF4F1B3FB0FULL,
		0xAF47A51B70F6D0A6ULL,
		0x328B1913A6980A63ULL,
		0x2CDE6987BDB351C3ULL,
		0xDE3F84F6C76CBAE5ULL,
		0x17854FEF8B164B6AULL,
		0x7DAE3E1EBA9DF7A4ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC967137FE67BBF49ULL,
		0x736C965F322E9B80ULL,
		0x8D781CCCA5CC28C7ULL,
		0x3BFE6FD720122B44ULL,
		0xDF14EAC91D8AA2DAULL,
		0x41607DA255B42E9BULL,
		0xFE294BA49A79DE2AULL,
		0x39057B1FD0A3DB69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63A5302AD81BD2EULL,
		0x286F153865BB8DF2ULL,
		0xEC3237205735C6D1ULL,
		0x0F430BD5B6479337ULL,
		0x868B05653E23336AULL,
		0x4BDA83DDA85DE696ULL,
		0x3401A0E40081BEA1ULL,
		0x2BC9AFC67A38CDB4ULL
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
		0x72A0CB75A0AC5646ULL,
		0x89DA0EE8AC9CBD55ULL,
		0x842A387D44443DDAULL,
		0xB53570F26A3B721BULL,
		0xDFF87C524D8C3C7EULL,
		0x41465A53333FD1F4ULL,
		0xA1868A2AEFE46002ULL,
		0x006F05283DAB107FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FEB6B75FC0F54FFULL,
		0x92F7DB8D9C3B1E09ULL,
		0x1BA59F086550B2ABULL,
		0x7CEFAAA8D40352B8ULL,
		0xF3681ADDCE1A3245ULL,
		0x441C7543D74EE198ULL,
		0xE51E85FA2644AF79ULL,
		0xF5917E3812E18128ULL
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
		0xC0A97C9B9C098291ULL,
		0x6F3FF285C9F99FF4ULL,
		0xE84A6938D7DD740FULL,
		0x5DDC1951518977F8ULL,
		0x668E136A81567294ULL,
		0xF41DABD789B3FDFEULL,
		0x5CB184EA38612DCDULL,
		0x4C4D9D136F7965A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0A97C9B9C098291ULL,
		0x6F3FF285C9F99FF4ULL,
		0xE84A6938D7DD740FULL,
		0x5DDC1951518977F8ULL,
		0x668E136A81567294ULL,
		0xF41DABD789B3FDFEULL,
		0x5CB184EA38612DCDULL,
		0x4C4D9D136F7965A3ULL
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
		0x8C36A3417B8AF6C1ULL,
		0x57EAFDE51D095186ULL,
		0xF21946FD906B4483ULL,
		0xA794357C75FB3E6FULL,
		0xD2754CFE8B768D80ULL,
		0x6CD36D22C405C166ULL,
		0xC72DAFEFDF64A86AULL,
		0x63A0840ACE340A88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE56DA90CDF71CD22ULL,
		0x9834A111FEF7D804ULL,
		0x21BF8485A1C69618ULL,
		0x54CC97405C57AB80ULL,
		0x4A8BF42718C598A8ULL,
		0x45110320B3A30255ULL,
		0x1F8F84AB9D65E057ULL,
		0x629A1FDFBEEEB013ULL
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
		0x6B42291F3CBEA911ULL,
		0x85131FCD94C5E196ULL,
		0x6AC6555B5CFAE650ULL,
		0xEC8115676A2F3EBDULL,
		0x7C263679865FCAF6ULL,
		0x71C9CE1BDF4D0445ULL,
		0x4EDBE5F7C54982F0ULL,
		0x4BEDA7275EB7A455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E71E41D30FE2AA4ULL,
		0x2FC644C1A86DA95CULL,
		0xA10DA7EFFBC25458ULL,
		0x2D9A3BED9290BA9EULL,
		0xAB9C3A3D3A920697ULL,
		0x398D0CD5FF1BECFBULL,
		0x8F70944C5B4C4F14ULL,
		0x478A528EA202AB3FULL
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
		0x800F9CC2B1FFDF14ULL,
		0x94DCD0C0E05F4A08ULL,
		0x9F57DF8FA0813C0AULL,
		0x888F6B0D4DD80BE0ULL,
		0x27173159B809F003ULL,
		0xC27A7C86BF89ACC0ULL,
		0x853A6243424E2790ULL,
		0xDC30F0CD68D64F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8763D1C90F433B41ULL,
		0x6E6103A62A24B926ULL,
		0xE386ECC29BF83BE0ULL,
		0x8EE62970FC30E684ULL,
		0x552806C0A1CFBDD4ULL,
		0x337DFF85F00570F4ULL,
		0x3A6D5A488488092EULL,
		0x78BB2955BABDC213ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2447818F5C47F790ULL,
		0x533604B190A2178BULL,
		0x85A02117F76B5B0AULL,
		0x1645A5B8CEEAABE5ULL,
		0x638FD415CD1FA49AULL,
		0xE835F1DB27833AC2ULL,
		0x7627B94B5F5995FBULL,
		0x6ED354B2F3B4FC8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2447818F5C47F790ULL,
		0x533604B190A2178BULL,
		0x85A02117F76B5B0AULL,
		0x1645A5B8CEEAABE5ULL,
		0x638FD415CD1FA49AULL,
		0xE835F1DB27833AC2ULL,
		0x7627B94B5F5995FBULL,
		0x6ED354B2F3B4FC8BULL
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
		0xD25386B1B8173BDCULL,
		0x01821D4AD09F3DB7ULL,
		0xB8085B1408DC7D95ULL,
		0x4543E93D2A991710ULL,
		0xC30DE48390BC18E8ULL,
		0xD74AB4BC55974DD3ULL,
		0x58D6A1BEF9710894ULL,
		0xFA4DE8FC78D5C9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x002934D16CBBB26FULL,
		0xABE57FB9E7C8DDB9ULL,
		0xAFF90F461D6287C2ULL,
		0x331F21C5B51E867EULL,
		0x4779C72961A8F432ULL,
		0x4D29A8F3362B213AULL,
		0x37EACDD171876E7BULL,
		0xF828DA73B41B2B70ULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7A1DD6FD19BB6A8DULL,
		0x69808150B6B3CB1DULL,
		0xA60D39BED6B2E1E4ULL,
		0xE886A97908931989ULL,
		0xC33415015383C825ULL,
		0x6B421A801B9204D4ULL,
		0xEC43E0972122AAA8ULL,
		0xDC2954B95C040216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62511BA6196CC965ULL,
		0x4058815B530BB82FULL,
		0x244B7063ACC91C89ULL,
		0xB52ED4316C105B07ULL,
		0xEAE3A6FBEC737010ULL,
		0xF01ABB94A7A4CD47ULL,
		0xCD63FC1C7DEBE217ULL,
		0x78F816677A137DDFULL
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
		0x0BB46F649441AED5ULL,
		0x3E460A6D9E6B0FCBULL,
		0xDDC5F34C138B8F04ULL,
		0xFEC46B745F74C7EEULL,
		0x06E4419F8581957FULL,
		0x042826B6D3BDB8F2ULL,
		0x0E14092501B4931AULL,
		0x8C538F2CAC9C6921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87E880AB7B62C75ULL,
		0x146D602A89A012E1ULL,
		0xF7AD8CCC95062EDAULL,
		0x2CEAF38F8FBFAD10ULL,
		0x5D8D0EF07B103DC8ULL,
		0xD30D69D183C37A13ULL,
		0x4AD80D83A1BCD616ULL,
		0xF42AFB2A96BFE328ULL
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
		0xEF64C83420D4FB89ULL,
		0x8D225342239CDA08ULL,
		0x0C757A1A1E0A43E9ULL,
		0x17037DA4146BDAEBULL,
		0x49B7435245752F0AULL,
		0xF8B6AE0BEC1C931AULL,
		0x1AFFBC993975B7F0ULL,
		0xFA5872E559AB5E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF64C83420D4FB89ULL,
		0x8D225342239CDA08ULL,
		0x0C757A1A1E0A43E9ULL,
		0x17037DA4146BDAEBULL,
		0x49B7435245752F0AULL,
		0xF8B6AE0BEC1C931AULL,
		0x1AFFBC993975B7F0ULL,
		0xFA5872E559AB5E19ULL
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
		0x6CBDA4A701ACEF5EULL,
		0x01D2C8806B7BDCBEULL,
		0x041992588C21D55AULL,
		0x6A0F7DFD5BE7E496ULL,
		0x35AA94441320ED33ULL,
		0xF4FDC348C1B2F7A1ULL,
		0x075900DCC9AD98F2ULL,
		0xC9C2EE5A9CAAF095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5E31B00F031E94ULL,
		0x87966BD8003D4B40ULL,
		0x73BC94A1D9D3C76DULL,
		0xC800BF6D06571988ULL,
		0x27FD0B1CF23EAA2DULL,
		0xE04CAB4F63D74624ULL,
		0xB38959031D8F4A6BULL,
		0x99B228FB4323EE4DULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x46214B2D703CF01EULL,
		0x1C95039AACF1B2C3ULL,
		0xD228014AC1AC753AULL,
		0x3C153046A20BCBBFULL,
		0x5A9EB090AC5B7C8DULL,
		0x370A56280D9C45F2ULL,
		0x6F07B50C37B3B8F0ULL,
		0xF721B1A4DEB4358AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B47638C14C70058ULL,
		0x33FDC61DF45C44BFULL,
		0x4BD85E6C40F95A67ULL,
		0xAF8DA2636A575E10ULL,
		0xA092AD3078D3892EULL,
		0x4167C9AA91C7A9EDULL,
		0x0BF4E37474457A2FULL,
		0x6D87096616B1E529ULL
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
		0x746EACE212AA0AB3ULL,
		0x6F25AB5551893F21ULL,
		0xC0BAD5109FD3B4D5ULL,
		0x94DF88027C279D5BULL,
		0x17DC2F22086CE792ULL,
		0x213C9919ED3D4F08ULL,
		0x1678F9B098649D7DULL,
		0xA50592229B0582C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC650948759885F1ULL,
		0x6FEBA4F2A47162BDULL,
		0x87F5A0D523752553ULL,
		0x775AE9F85E2DDDA3ULL,
		0x96512568A5E45CF7ULL,
		0xC63C4BD3851F5704ULL,
		0x2F8B7FAE4F4A3114ULL,
		0x7BC8C2DB0E0CDF55ULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7EEB621EEEB5F451ULL,
		0x40E73F550BB46CE7ULL,
		0xBBC60D4E25838254ULL,
		0x37D48BCBF96BEE8AULL,
		0x96D54A3C1BA9691BULL,
		0x3C2DBF8FF713D4F1ULL,
		0x7AD81633A141922CULL,
		0x835ADBCBF8114742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EEB621EEEB5F451ULL,
		0x40E73F550BB46CE7ULL,
		0xBBC60D4E25838254ULL,
		0x37D48BCBF96BEE8AULL,
		0x96D54A3C1BA9691BULL,
		0x3C2DBF8FF713D4F1ULL,
		0x7AD81633A141922CULL,
		0x835ADBCBF8114742ULL
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
		0x2DFE72989A17F574ULL,
		0x7F22BDD5E76D24C5ULL,
		0x81F460304521DECAULL,
		0x1341159C1AC58700ULL,
		0x91C3CF16147346B6ULL,
		0xBD0BF3573FB70BB6ULL,
		0x786AF4ADD405BEE9ULL,
		0x149BCAF06F56EDE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B6466766E52E90ULL,
		0x87B69400E0A1DD2CULL,
		0x10B1C8646AA35CA8ULL,
		0x3502B826C3BD23DEULL,
		0xB70ADE1A684CF1E5ULL,
		0xDD71C228232FDB59ULL,
		0x76C27A8231264678ULL,
		0x591B73FF4D2D22DEULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEBE9966FA51145DEULL,
		0xCE174591DF1A9346ULL,
		0xCF1A4C6FFE2EC5C1ULL,
		0x8CE7BF240E25BB65ULL,
		0x1AE3FB58BF0010CBULL,
		0x2A963242A5432C4CULL,
		0xD294E4BCD511009EULL,
		0x945012F2518FDBCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73DA632B0AD3CC95ULL,
		0xA4014DFB0EC4BC37ULL,
		0x31DCBBF3DBD1FC47ULL,
		0x6C29C890140C6C4AULL,
		0xCAF97BBFAA0CFA36ULL,
		0x0C3E92EA7320D1BFULL,
		0x0AA0A774F190C446ULL,
		0x1D3EAC5E226917B4ULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4BFE9F95D53B5C3CULL,
		0x13B8BAAAEC727F72ULL,
		0x349F66D551094DC2ULL,
		0x8C22769B14F53B9BULL,
		0xC27E6446390A54B6ULL,
		0x8B8A959BA0EE35D4ULL,
		0x240EC984919864D1ULL,
		0x605F1B72DB1C5245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x848DD62E1E7AD1A3ULL,
		0xF1979221919F115CULL,
		0x9B2B5E82BBD6A64EULL,
		0xC4411A2D78D3ECC0ULL,
		0x432886A1FD2A4281ULL,
		0x6835F427D9AFC7A7ULL,
		0xC356309F3DF2B735ULL,
		0x653F3FA9B243F820ULL
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
		0xA2D213E330CA37C8ULL,
		0x314562B768E24232ULL,
		0xA8FF99053CC5E328ULL,
		0x78D8391B84AA0C74ULL,
		0x0BF9675BF9FFE0D2ULL,
		0x1A13C2647FDF9789ULL,
		0x673565BEF7750089ULL,
		0x5CB50ACDB22DE236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D213E330CA37C8ULL,
		0x314562B768E24232ULL,
		0xA8FF99053CC5E328ULL,
		0x78D8391B84AA0C74ULL,
		0x0BF9675BF9FFE0D2ULL,
		0x1A13C2647FDF9789ULL,
		0x673565BEF7750089ULL,
		0x5CB50ACDB22DE236ULL
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
		0xFF858F5C7313241BULL,
		0x1B918878F97E1A84ULL,
		0xCD94EA3826C771B8ULL,
		0xED191DC9B57CEF78ULL,
		0xB6DAC6945BEB3E62ULL,
		0xF8BCC1EA89216DBEULL,
		0xE0B0F2F8FE98E85FULL,
		0xF2DC8A49D4DFD66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCCCB588AEA802DULL,
		0xE11450F6361B30E1ULL,
		0x00D5383D0812C959ULL,
		0x8F378201FC0D583CULL,
		0xB6F209422DFEBD2AULL,
		0x9677B69485C437C5ULL,
		0x8C34297100DF36B4ULL,
		0x69E4A7E029B03CB0ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x096ED8D919DF22F1ULL,
		0x0D0DA1D4F5FD1D60ULL,
		0xB8E626E03E6B643CULL,
		0x5538209E0388C075ULL,
		0xBA1B4AD4911642D8ULL,
		0x2DB1E4AC86C2ACD0ULL,
		0x615D490D7AC79B96ULL,
		0xDF398ADC7462C69DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x002FF3B6C235F20DULL,
		0xD6D0AB86D7806805ULL,
		0xE644167387AF72C1ULL,
		0x28A45569A899A378ULL,
		0xB65C65E226B5111AULL,
		0x6D601FEB972BF465ULL,
		0x7C55839CBCF59B6DULL,
		0x12EAEE82F5D7A970ULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2DC22AE5BA8DFF68ULL,
		0xFA3101F39C0D48B2ULL,
		0x819FE7B360C7A7DCULL,
		0x6673F97368AB9E8BULL,
		0x62ECC51E6C6A595DULL,
		0x1A5E591DD2C22569ULL,
		0x07128C997581E947ULL,
		0xC2FF11C397AE53BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEEA37FA86D97A0FULL,
		0x5CFDAC9A277C5762ULL,
		0xF82FE9643DC44969ULL,
		0x0F49AAE1353D8DD3ULL,
		0xE880690EA319CB20ULL,
		0x1FFBD7818DC89303ULL,
		0xEB59E103161E890DULL,
		0x570939B76C3391DFULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x936C9DC172D8A727ULL,
		0x09FB54124D1E5817ULL,
		0x66C8097E9AF4ECCAULL,
		0xA63898297BCD745BULL,
		0xCE493419475E8C27ULL,
		0x65B0F1837129C2EEULL,
		0x6A26B4D9EC28DB89ULL,
		0xF6466216F5FBBEFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936C9DC172D8A727ULL,
		0x09FB54124D1E5817ULL,
		0x66C8097E9AF4ECCAULL,
		0xA63898297BCD745BULL,
		0xCE493419475E8C27ULL,
		0x65B0F1837129C2EEULL,
		0x6A26B4D9EC28DB89ULL,
		0xF6466216F5FBBEFBULL
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
		0x705D4757DB09AC1BULL,
		0x1AD7D812732C7FFCULL,
		0x79BE61E5A2EC7ADBULL,
		0x77422C96BB05252CULL,
		0xB5CCDAC8A0C6A59AULL,
		0x2B5C4292626E14B4ULL,
		0xE739CE4F3B8C62A7ULL,
		0x41AB7B2F0ED091E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF623CCFEFE4372E7ULL,
		0xB9C8142D72E46112ULL,
		0x70163C1807CCF412ULL,
		0x42C382BA9712E7DCULL,
		0x10D7913751DE3E02ULL,
		0xA2F8495A5BED1415ULL,
		0x947098DE2934882CULL,
		0x5B9C2C018BD51CFEULL
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
		0xCD2E9C060317C1D0ULL,
		0x4CEFB254AA43EA19ULL,
		0x59C3C4CA2A632924ULL,
		0x4D9E623E9C9D81E6ULL,
		0x204A672301BA8238ULL,
		0x2CDF2CE0B9060240ULL,
		0x402201F8E9D25165ULL,
		0x6B87DB2315DECAB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FEC032CA14E96BULL,
		0xCB7A6676E5F3C86BULL,
		0xCA93FB1DCAD82D16ULL,
		0x72F85B457E9489BFULL,
		0x83775B381517C443ULL,
		0x65D51FFF65EA104BULL,
		0x030DAA6888AB21CEULL,
		0x77F53DBCEE3DE605ULL
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
		0x9B18E261CC43EF12ULL,
		0xFD054C900448A66BULL,
		0xBEE52B8EB2FC01CCULL,
		0x5CA7FB20B14E7FE2ULL,
		0xC2C833FA16DBDDA6ULL,
		0x0AC1D76A672DA494ULL,
		0x2DABE2115F69F04EULL,
		0x608B04FF0794FAF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79FB174E19E10482ULL,
		0x2CFE66188A91558DULL,
		0x7A581FF05E216AF6ULL,
		0x959FEA1FE4A70AB4ULL,
		0xC945214CDCDB2BD6ULL,
		0xADF1E6E25EDB1EC1ULL,
		0xF87353C811B34271ULL,
		0xBA513689D9293392ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4C26109855202FCEULL,
		0xCA7112136C403EB2ULL,
		0xD620EBB4BF9DACC7ULL,
		0xEEB02A1B798966EEULL,
		0xD429D3EE7C6BDD32ULL,
		0xD27E29AEE7E4544BULL,
		0x49EA8B834EC6F903ULL,
		0xD538A72D653058B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C26109855202FCEULL,
		0xCA7112136C403EB2ULL,
		0xD620EBB4BF9DACC7ULL,
		0xEEB02A1B798966EEULL,
		0xD429D3EE7C6BDD32ULL,
		0xD27E29AEE7E4544BULL,
		0x49EA8B834EC6F903ULL,
		0xD538A72D653058B2ULL
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
		0x5D3463745B449200ULL,
		0xD0B27467ED99A916ULL,
		0x04C418F255A671B7ULL,
		0x2016D4C604D7A0EAULL,
		0xC7234B07FD90144FULL,
		0x3501D650F53D4C4AULL,
		0x5602065BA40E0584ULL,
		0x8D77DD82381E7AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7AF1D763DB273C2ULL,
		0x72DCA41332486551ULL,
		0x1DF54B47ADA3A8C2ULL,
		0x5F626E994E3F9011ULL,
		0xE1D4BC338D78BA13ULL,
		0x5A23B206BD1EB166ULL,
		0x26EB6217B3AEC89DULL,
		0xD734AB826D08E2E8ULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x764E93E903A68430ULL,
		0xFF12EC5B8FFFF021ULL,
		0x44D2AB0D60F62C19ULL,
		0x766D46F0AFC7E1FAULL,
		0x4BA718D6D18BD81EULL,
		0x0EAB1352D03D26E0ULL,
		0x6698185BADEE407CULL,
		0x96A2452D84AB9B85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77921E90D16D1ACBULL,
		0x76C7FA7BB56173DAULL,
		0x8BAA388EE025F317ULL,
		0x88EE4EA542314542ULL,
		0x99DC45A506932A11ULL,
		0xF6293F5ECCF73199ULL,
		0x48D782C739B87010ULL,
		0x81E61D76057C0B3CULL
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
		0x73CB8E252AD3A72BULL,
		0x60D7FBA5B63BDF23ULL,
		0xDF27B24E661067D4ULL,
		0x1015993804377F1AULL,
		0x5D940E5AFE6D3FC1ULL,
		0x9276E7C181E23CD3ULL,
		0x004AD9FC5136A926ULL,
		0xCA3559A93A5C37CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D6DCC6F543BF75ULL,
		0x62C6263312BDF6A7ULL,
		0xFA5C2EEC980234AAULL,
		0xF5D3540889A003BBULL,
		0x233B39D56CCEF344ULL,
		0x2C128EA6427234A6ULL,
		0x43EC1C465B038E9EULL,
		0x0647F5CC99E8713FULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x094ABE796C755358ULL,
		0x682FB8D5A65ACEE0ULL,
		0xDBFE8BA35F4A7A8BULL,
		0x509D1CB2BE1AFBE6ULL,
		0x5E5AE728F2B7CCEEULL,
		0xD2911A94864DA42BULL,
		0xF06D18EA1EAC87E5ULL,
		0xFDADB3E986E326C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094ABE796C755358ULL,
		0x682FB8D5A65ACEE0ULL,
		0xDBFE8BA35F4A7A8BULL,
		0x509D1CB2BE1AFBE6ULL,
		0x5E5AE728F2B7CCEEULL,
		0xD2911A94864DA42BULL,
		0xF06D18EA1EAC87E5ULL,
		0xFDADB3E986E326C9ULL
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
		0x7480F74CEB1B3E1EULL,
		0x825A7D4F8DD011CCULL,
		0x82609C1601042FE2ULL,
		0x7E338AA802D49E2CULL,
		0x31C8119B39CA9030ULL,
		0xC27881053D02B7FEULL,
		0x6D9B1C2C1FB68A6CULL,
		0x0DEA3A230D76F348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADE17588DC9E578CULL,
		0xAD51731B75A05335ULL,
		0xB5CC95F3024D4777ULL,
		0x519631817322A701ULL,
		0x396FBE4B12BE6684ULL,
		0x236B5652079F1369ULL,
		0xF376C8761FE06F72ULL,
		0xFC58C6062AF9064BULL
	}};
	t = -1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x11A6587E6C23764DULL,
		0x1EA69F8E0CDE2BCEULL,
		0xDE45E6A3540D0620ULL,
		0x41E6674E58D1C125ULL,
		0xE4AD1C1D4C0910BFULL,
		0xFE33CCCAC2C26C80ULL,
		0x60645444C1BDD6EAULL,
		0x92A2E070854C8903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0A1D74498F2AEDULL,
		0x22B8AB84B19318BEULL,
		0x3F66AD59A65B1FB9ULL,
		0x1E989D1562B11B18ULL,
		0x39EF634C75911C28ULL,
		0x60CA00602E64D9CAULL,
		0xDE78EDEB0C02678AULL,
		0x46AFCB74DB095E2DULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFC23D740B955E6E9ULL,
		0xCE00597B31068BD8ULL,
		0xFB100E470DD9C107ULL,
		0xA60C2ACF16C11CD9ULL,
		0x635B30B6FC760A1EULL,
		0x53C036B5305317D4ULL,
		0xBA0DC38C8C299B1AULL,
		0x1DFE451CA4277ADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E7E9CB9DFE6AEFFULL,
		0x46A19780EFF95852ULL,
		0x6631AF8E1EDB482CULL,
		0x1E52A34BA76859A1ULL,
		0x6111304273B3E7E8ULL,
		0x741B688A16DA1CF5ULL,
		0x971635D56DF03941ULL,
		0xD093446860C22F5FULL
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
		0xBCE790C3720E6A6BULL,
		0xFA68C575C7CC6E2BULL,
		0x64B9293C2F543E2EULL,
		0x107A4EE1BEEA9BF1ULL,
		0x61AFF85136E7EDB0ULL,
		0x986802A3D240869BULL,
		0x4519D83F823EDC52ULL,
		0xFCC42893FDA1098DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE790C3720E6A6BULL,
		0xFA68C575C7CC6E2BULL,
		0x64B9293C2F543E2EULL,
		0x107A4EE1BEEA9BF1ULL,
		0x61AFF85136E7EDB0ULL,
		0x986802A3D240869BULL,
		0x4519D83F823EDC52ULL,
		0xFCC42893FDA1098DULL
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
		0x6561537018DA28DEULL,
		0xE26F1F42A46EB4E2ULL,
		0xF1AADF2518B3AB3BULL,
		0x5800FF164572C1F0ULL,
		0x23039ACB824C420FULL,
		0x5996F341C07F1987ULL,
		0x098ECD066685B9CEULL,
		0x3508F4880D9AED02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB212F6EDE6BE56DULL,
		0x41178639A834F482ULL,
		0xE768822E443AB0A7ULL,
		0xD1F780265F94CE28ULL,
		0x598A516BC9CE7BAEULL,
		0x27F8196FB3D19090ULL,
		0x41B39C1E9E25DD5EULL,
		0x45E4751E987846B9ULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x56D2F4DD078DFBBFULL,
		0xD26D709D569A8614ULL,
		0xCB3F84864634B998ULL,
		0x760306CACB108950ULL,
		0x80C0455CE7CEADFDULL,
		0x2548A8D0298B86EDULL,
		0x2695D3191146EFC9ULL,
		0x36EA8DA17457EF81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792BC9ED9857E1CEULL,
		0xF8ED70DEFC55CF5AULL,
		0xEA2BAB18C17F2B95ULL,
		0x89202098002B5081ULL,
		0x323C7A6BBF40D4CEULL,
		0xE67FFC73EF35A004ULL,
		0x9A03C53276E54D21ULL,
		0x5593CB6461AC653BULL
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
		0x036C748A831C63F5ULL,
		0x8B3F31FD00B0E71AULL,
		0x41EBB30209FC8820ULL,
		0xC243D8B6D7F34D0EULL,
		0xC893C05794FC530CULL,
		0xA7E3FF497F6118C6ULL,
		0xC55587D8C7C08EBFULL,
		0xD4FC3FF8488675A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC302840871BF0A5ULL,
		0xE208192E7F07CF55ULL,
		0x12326CEEC987B944ULL,
		0x3367AE0A1A7FAA1CULL,
		0x7F7EFBED9C9C1408ULL,
		0xF83ECD2B93362009ULL,
		0x57719643177D6F8AULL,
		0x18A8325039549338ULL
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
		0xCBBA111F0C54D141ULL,
		0x7AE0371E963DFE98ULL,
		0xAE772D1336044A9FULL,
		0xD9911485C4BCFBE7ULL,
		0x5AD57707C35BB547ULL,
		0x44EE44ACF344E2DEULL,
		0x8954B5378638C1F4ULL,
		0x28C7E3799A501EE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBA111F0C54D141ULL,
		0x7AE0371E963DFE98ULL,
		0xAE772D1336044A9FULL,
		0xD9911485C4BCFBE7ULL,
		0x5AD57707C35BB547ULL,
		0x44EE44ACF344E2DEULL,
		0x8954B5378638C1F4ULL,
		0x28C7E3799A501EE3ULL
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
		0x5227FF0FAC6D5C2CULL,
		0x5685680A7A330A4CULL,
		0xF60A1E6D0AC6C2A2ULL,
		0x95475818133BE846ULL,
		0x190EF708C4C9CFFFULL,
		0xFF1172B1386DD0E8ULL,
		0x79B0B97BD127DC08ULL,
		0x42A345EE23CFE139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23E715660E8ED776ULL,
		0x55C624E54D690309ULL,
		0xB0027D519BDF28ADULL,
		0x646D193A408708AAULL,
		0x9A7A3B9AB2B72884ULL,
		0x7F03B5DFED422603ULL,
		0x23CEF622D98A7231ULL,
		0x528F64209AAF71B9ULL
	}};
	t = -1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA765E3CDF6FA5355ULL,
		0xC85A1BBF3EA996ECULL,
		0x37B2CE1353E44689ULL,
		0xF27BAA3DDED7F7A7ULL,
		0xFE8D87DD10AEF89BULL,
		0x89BF0C0DAA4FF20FULL,
		0x9909D6C09A7BC0FAULL,
		0x793F1E7A10035F59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8843A07CDE72FBULL,
		0x0A0E1D3382B180B0ULL,
		0x8F2C8A7759A3DAEDULL,
		0x622F47F258DEACE1ULL,
		0x1D32FED2A154B9C5ULL,
		0xEF85C67F5C0829D1ULL,
		0xB017EE65082F19E3ULL,
		0x9EA2E40919766B26ULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE2432DE1907CF366ULL,
		0xD5C25C5750E6F0E7ULL,
		0x76DC7165FB46DADDULL,
		0xDDF7972894F8912CULL,
		0xF37283398EB10DA3ULL,
		0xAA41A21243C39F20ULL,
		0x0ECEF79B8C4AA3BDULL,
		0xD148503C938C648CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13766B325438948DULL,
		0x2B81835C88F3888CULL,
		0x5AD8BEA98400D4F7ULL,
		0x03377D26BE521D4EULL,
		0x950820B6AF79F7F9ULL,
		0x2BF7ED9B7306CF5AULL,
		0x90587ED7E17B28D2ULL,
		0x505CF142294EFC7FULL
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
		0xF1DE5B0159B224A9ULL,
		0xBE9A192828B81577ULL,
		0x7402CA70DA1C7464ULL,
		0x3793A25876E817ACULL,
		0xC1EF1328BB4D7773ULL,
		0xB884959730CD7843ULL,
		0xD6420114020EFC0AULL,
		0x765CE97234A6D95AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DE5B0159B224A9ULL,
		0xBE9A192828B81577ULL,
		0x7402CA70DA1C7464ULL,
		0x3793A25876E817ACULL,
		0xC1EF1328BB4D7773ULL,
		0xB884959730CD7843ULL,
		0xD6420114020EFC0AULL,
		0x765CE97234A6D95AULL
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
		0x9C7031AE8C5F0A5EULL,
		0xC9EC3FDE35C894B3ULL,
		0x4EA7E517DEDB36D8ULL,
		0xC2DB65905A734E56ULL,
		0xAA9729C64E23FA89ULL,
		0x02F3388B5356466DULL,
		0xCDA4D56AD33DAA8BULL,
		0x59F7AD661AF583CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E71E445A7B1D5B6ULL,
		0x24D3323124642075ULL,
		0x251B3A29820E32F9ULL,
		0xC9477D30D631E2CCULL,
		0x103A62C52B1715C6ULL,
		0xDEB04833C43D20BDULL,
		0x1A01AB6E5606C2D4ULL,
		0x3EAC4B4440E390FCULL
	}};
	t = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3FB0EFF711C87FEFULL,
		0x3BDDFF5CA78EF5B7ULL,
		0x7F9EB75CB82C278FULL,
		0x368E26FF33A0B5AEULL,
		0xAC07EE62B4EB6AF0ULL,
		0x528F4F2B34D146D7ULL,
		0x6D359216AAC8D01DULL,
		0xA61B78484D016591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9E671C0C88DE3CULL,
		0x52A47AFACF4AD4BDULL,
		0x688B7A675617A512ULL,
		0x815C437A95F1D294ULL,
		0xCE9E344B76C1F13FULL,
		0x0F2DA62E0F433F6EULL,
		0xE89326AB9B4D4A9CULL,
		0x16F9D216AC4B9651ULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFF83A410DC0A7C05ULL,
		0x89948DC01883B840ULL,
		0x03050B77CFBA9460ULL,
		0xF9C4F7700F266EE1ULL,
		0xA90A217F41625848ULL,
		0xA0F9E96C344892A1ULL,
		0x6C12A2BCD3DD6572ULL,
		0x2C84AD0B01D7299AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD532C3C8CFC592CEULL,
		0x7CD541A4671A0FF3ULL,
		0xAE47AEAB92A72B6FULL,
		0xC2A08A2C444C176FULL,
		0x5C0FBFB946970679ULL,
		0x15D2CE2091EB577CULL,
		0x3EB0ACC0B712B35DULL,
		0x33DBD04FE76E9DA6ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1D2F3BB977B179EEULL,
		0x5C2F11780DAD9381ULL,
		0xD75075E14FEF5245ULL,
		0xCB4D41DCF188A61EULL,
		0x7D870B61EBF71242ULL,
		0x84CCE7D0F54441B1ULL,
		0x74F02755CC97730CULL,
		0x4FB04068A8676AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2F3BB977B179EEULL,
		0x5C2F11780DAD9381ULL,
		0xD75075E14FEF5245ULL,
		0xCB4D41DCF188A61EULL,
		0x7D870B61EBF71242ULL,
		0x84CCE7D0F54441B1ULL,
		0x74F02755CC97730CULL,
		0x4FB04068A8676AA9ULL
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
		0x74F92E0D08B46BF2ULL,
		0xA96C38AC9F65F741ULL,
		0x17F4EDBD28C16AB9ULL,
		0x17F4BF223AF6BEBDULL,
		0x82E287FAA0AE6D3EULL,
		0x5A8C85A87C2CAF26ULL,
		0xB689E16B114340B8ULL,
		0x012CB0036D5E4BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED39FC783DC8A44DULL,
		0x6BB3B17BE36B14E0ULL,
		0x2E2FBB1BB8C8F725ULL,
		0x5D46E5A364E506B5ULL,
		0xEAA910CB2F280AA9ULL,
		0x67F70967C6590FDAULL,
		0xBE01108D515BB076ULL,
		0x523869672C6DC787ULL
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
		0x2E333C7F275B970CULL,
		0xE986985E51015484ULL,
		0x2000E2F0928AF0A8ULL,
		0xBF3FC610B2C58310ULL,
		0xB532310C4F563A6EULL,
		0x7CADC6D20449C064ULL,
		0xA3B84F865CC55C2DULL,
		0xF7E42E59EFFE1973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0708B1BB4379ED14ULL,
		0xC8B94DCC5AAFE70DULL,
		0x162F35F00D24EFA5ULL,
		0x9DE5936A44BC3B4DULL,
		0xBE491BDDD345FD91ULL,
		0xA218D2D41A269A85ULL,
		0x23A166D65579D094ULL,
		0x8D6BDB848E61ED25ULL
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
		0xBC202020E1F8D26FULL,
		0xD0A711C115520A89ULL,
		0xFB8B0A16785DB8EEULL,
		0x9523CAB4FD2E75AFULL,
		0x8950DF4A7AEBE25AULL,
		0x1088FDC7F753886AULL,
		0x36E106B2D83C2BEFULL,
		0x3DC8BA46FD8EE210ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1957A046418D93ULL,
		0x713BD7AE3EB47055ULL,
		0xAB998298F34CB222ULL,
		0x5F2087E55B2F4624ULL,
		0xFD3ACD3B80FD1797ULL,
		0xEFF2EE81D220EF23ULL,
		0xDB10DC0EC608ED3AULL,
		0x02A0BC0A865B04EFULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1729B5E79F4878AEULL,
		0xE7CE4FF1A664E82EULL,
		0x20006A60FB8D53B4ULL,
		0xC7097C193F6BB74DULL,
		0x966F8304D3DD512CULL,
		0x2ED1C77EFDA0B94DULL,
		0xCF237F304D37A6A3ULL,
		0xF4B1D2ECD044F62BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1729B5E79F4878AEULL,
		0xE7CE4FF1A664E82EULL,
		0x20006A60FB8D53B4ULL,
		0xC7097C193F6BB74DULL,
		0x966F8304D3DD512CULL,
		0x2ED1C77EFDA0B94DULL,
		0xCF237F304D37A6A3ULL,
		0xF4B1D2ECD044F62BULL
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
		0x643C8BA52D40E08FULL,
		0xE9C79B1E58D81A77ULL,
		0x560A113B97D36CE6ULL,
		0x1724C0D11A38499EULL,
		0x5E09D34A421AB17CULL,
		0xD9EEB03D4D066210ULL,
		0xAA82FA79B7F34F43ULL,
		0x2D523619439573E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC05DDDB521AFD8ULL,
		0xBF49C6D469B32E71ULL,
		0x030668668B5F1BFCULL,
		0x833E5CC6DD9A0F6EULL,
		0x770EC8337590A23AULL,
		0x5D0609CC48B4D923ULL,
		0x59C36AE64B3CD304ULL,
		0xE671E814736F3A1BULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5FE1D11F99CEFD0EULL,
		0xD0FECDEFAEC5E50CULL,
		0xE379BF2DA9A8C0DAULL,
		0x5C736134AD091037ULL,
		0x9578159F4BA2174CULL,
		0xF01CB39B1267D531ULL,
		0xE728DE873586836FULL,
		0xE4E774ABB6EEC10FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BD03497782696DCULL,
		0x83055C8635655787ULL,
		0x6AF72D3536DAE3B3ULL,
		0xD34C415405D20F43ULL,
		0x09402C85CE683A90ULL,
		0xB13236D1BB59B430ULL,
		0x2E0485AEBE6A1067ULL,
		0x6E0A881892E5F61CULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEDBB47C52964A726ULL,
		0x5DFFD39113A31345ULL,
		0x28F1A3473F70967BULL,
		0x2D623E42E0F8547FULL,
		0x9F98B67E8988EB2EULL,
		0xC96D32D166EFEB7AULL,
		0x33C1A45FA83F459FULL,
		0x3DD5AEFA3E2BD4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF935ECAA577CDE03ULL,
		0xA98CC91628A51841ULL,
		0xC5745C70D67EFF28ULL,
		0xC4CE366EA09E7FCAULL,
		0xE75C3E8677AC35D5ULL,
		0x827266852A61E95DULL,
		0xB0635E7369270677ULL,
		0xC9A7A47DE5FF5EC3ULL
	}};
	t = -1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x16E74780C6235055ULL,
		0xDE662FED2E20A925ULL,
		0x945348785892043CULL,
		0xE1C3F529425B5F43ULL,
		0x57FB2FF7C6C1BDACULL,
		0xE08C05FE8E34EAEDULL,
		0xABB8AFD952CD2020ULL,
		0x1C2C82D959310AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E74780C6235055ULL,
		0xDE662FED2E20A925ULL,
		0x945348785892043CULL,
		0xE1C3F529425B5F43ULL,
		0x57FB2FF7C6C1BDACULL,
		0xE08C05FE8E34EAEDULL,
		0xABB8AFD952CD2020ULL,
		0x1C2C82D959310AB3ULL
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
		0xC1BB473C2AEAD2E4ULL,
		0xF8CEB87DFC1694D2ULL,
		0xAB4F82F88207E2C1ULL,
		0x8FDA8652918168B2ULL,
		0x3A0E6610C5DA4D0BULL,
		0xBA843AF8D4780580ULL,
		0x2E93260822921B14ULL,
		0xF2AB4AD15916C44FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF8C022AB714540ULL,
		0x2A5C8617E71C5CADULL,
		0x0230C9E05CB8997AULL,
		0x94BD570D63E56F77ULL,
		0x7C2D27A7CFC1BD74ULL,
		0xDEFF3A7AA111AC16ULL,
		0x3D884F24AA04DE90ULL,
		0x991981E8AC91B5BBULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x32220BD2FDEDF356ULL,
		0xD22AF6B7A9266CA5ULL,
		0x90BF837745766775ULL,
		0x0B8A9C14349CC8EEULL,
		0xCF2131C19B2BC505ULL,
		0x95B555C1DA9D42ADULL,
		0x8F04299E5202A18EULL,
		0x6AEE6A42D36CF777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85A3C200745B1874ULL,
		0x655F20F2599B664BULL,
		0xBC340545D3DF1424ULL,
		0x747E84379FE1118BULL,
		0x694D59FAA7AB9124ULL,
		0xABF9E67860DABA4AULL,
		0x1F9AAE4E6F06E6FBULL,
		0x01FA99FE0FEFC225ULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC2C20DCA25946840ULL,
		0x70FA27F4F00A2C3FULL,
		0x6FFC083D1BBDD016ULL,
		0xD8A88E28590BB84EULL,
		0x21AFB7A6BEA96F8BULL,
		0x0D69F5184D513F00ULL,
		0x830CD90B892B851AULL,
		0x567A55A5820C9E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A1B14BAB373A3EULL,
		0xBDB7FC44F4454197ULL,
		0x13B9E2573B965927ULL,
		0x0B3AC6BAE5ED66E3ULL,
		0x19C256A92AACD791ULL,
		0xE5628242049E9E08ULL,
		0xB073240562ADA580ULL,
		0x78B702A02717547CULL
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
		0x5AAB1A836B5A5E4CULL,
		0xF3A6FAB091F53A6CULL,
		0xAEACC9F246242753ULL,
		0xF920E9456CFFE994ULL,
		0x1DFACCCF41FEA5F4ULL,
		0x8DA9585441B1B79FULL,
		0x940EBF219B34103FULL,
		0x03E6BE184686F40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AAB1A836B5A5E4CULL,
		0xF3A6FAB091F53A6CULL,
		0xAEACC9F246242753ULL,
		0xF920E9456CFFE994ULL,
		0x1DFACCCF41FEA5F4ULL,
		0x8DA9585441B1B79FULL,
		0x940EBF219B34103FULL,
		0x03E6BE184686F40FULL
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
		0x0F8F99CA29D7BDECULL,
		0x0DE74BA9E127940BULL,
		0xA3F3BF8D45FB5E38ULL,
		0xC8F4A790B3D07D74ULL,
		0x1CE9936F9FC7EF80ULL,
		0xC134F649E90DBCA4ULL,
		0xA8EC149A56014E69ULL,
		0x9E09863990A31335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A46BA4FF6AD3AECULL,
		0x205760B16C600A1EULL,
		0xA36543C7DDDC252BULL,
		0x360BB1DFC6675B06ULL,
		0x79ED0C4BAE4908ECULL,
		0x397B382F69C6350EULL,
		0x0BDE41FDF31B1F9BULL,
		0xCD399E1C70A77EA7ULL
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
		0x9890218FD0851146ULL,
		0x3AB191989BB3D6AEULL,
		0x83848AEED13A713BULL,
		0x4AC6A7DED16E2349ULL,
		0xE3058A600AAFB29FULL,
		0x76252131B7E783ACULL,
		0xB10D41B61C2B6FA2ULL,
		0x482D6A67E4A41033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC09DACB3F87C6048ULL,
		0x9CF14AAFC668180FULL,
		0x422A89222CA20E6FULL,
		0x5D756B2D94CA232DULL,
		0xD0760551DD4E5CCCULL,
		0x8ED79755EE2B0D5FULL,
		0x81710F27D0149409ULL,
		0x357311631118BCA1ULL
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
		0xD28F7F0E8E233FD4ULL,
		0x939F4F81AC7814D4ULL,
		0x5A0A4CDC85B44BFEULL,
		0x26A9B48ADD13FE93ULL,
		0xE2F93FFB9BCE363DULL,
		0xCCDB8EADF387F356ULL,
		0x0AFAD46B99B0D289ULL,
		0x550E4A0E11B2F8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7BC6C9B5DEFED66ULL,
		0xBBE02702F95050E5ULL,
		0x02DE5CB6786B1A98ULL,
		0x15428D092E8B9F05ULL,
		0x5DEEDD136358C345ULL,
		0xDE91210D054D350DULL,
		0x6A7B2AE430F73CDDULL,
		0x28B5369C61B9A67FULL
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
		0x6EF8D514E2D732C0ULL,
		0xC3425332B27E1576ULL,
		0x6E503752DDF1E676ULL,
		0x02031A1493779E07ULL,
		0x58E264EA863CC4DBULL,
		0x90EBA1D5F48C2B93ULL,
		0x915F1EFD7D00A164ULL,
		0x133DCF3AB1654D98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF8D514E2D732C0ULL,
		0xC3425332B27E1576ULL,
		0x6E503752DDF1E676ULL,
		0x02031A1493779E07ULL,
		0x58E264EA863CC4DBULL,
		0x90EBA1D5F48C2B93ULL,
		0x915F1EFD7D00A164ULL,
		0x133DCF3AB1654D98ULL
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
		0x49A8C143FF331D6FULL,
		0xF426E4994A749CB8ULL,
		0xB80ED34FF9E10C1CULL,
		0xF627A4E0269CC123ULL,
		0x9D61D3819B5AA22BULL,
		0x371A25AA76322C3CULL,
		0xB675A8F57072B162ULL,
		0xA0D9E5B646925ABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x608375EFB527A692ULL,
		0xDA7E563F77CF0856ULL,
		0x9DB78F2A5B357871ULL,
		0xF642CE262508A500ULL,
		0xBEF3E4FE2F486EA2ULL,
		0xEC94F77C38935AC8ULL,
		0x826E2DCF70A9EFEEULL,
		0xA1AA2B16EB8AFA4AULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4DA3D8C1DE9386F1ULL,
		0x9752997A7AE684D0ULL,
		0x4BF281351A996FF7ULL,
		0xF8861F5FDC5D540BULL,
		0xEEC2F32A8A959ED8ULL,
		0xCADB20392E3F383FULL,
		0xD01163783992EB67ULL,
		0x94EDC628351D78D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7570B13EC75379E4ULL,
		0x4DACE496D624BE69ULL,
		0xB2DBFBED445C556FULL,
		0x98B151E65FE01558ULL,
		0x1A8F5A2225A3870FULL,
		0x8CE4C2C8C9AD977FULL,
		0x27965BFD955D4552ULL,
		0x7D3A1F3A7940FEDFULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAA90840EEAFCBDADULL,
		0xA9FADD5D96EB923FULL,
		0x9A99AA0BF46D2C3EULL,
		0xD69F2E6DFE5CCE05ULL,
		0x0D9C0672C45590EDULL,
		0xF79C7B4289330835ULL,
		0x5D3B076A2217D4ADULL,
		0xEAE1E9FD1B01299BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC60A6B9BCB3825CULL,
		0xD1BC1F9430899B1CULL,
		0x031B2E8FE509C561ULL,
		0xC0572DA5333BA530ULL,
		0x755AEBD88E07415DULL,
		0x0482CCD9F8546576ULL,
		0x219B8A33FEC04E23ULL,
		0xBCBCAB5CA92FF9ACULL
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
		0x4B1DE996AAC4E149ULL,
		0x416A7250BD454F18ULL,
		0xD424A946B186EC9FULL,
		0xC299B0796AE23AB3ULL,
		0xC8DFFCB7AC6B966CULL,
		0xB948975805AA413BULL,
		0xB447FE25922415D4ULL,
		0xED17F50E79C56024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B1DE996AAC4E149ULL,
		0x416A7250BD454F18ULL,
		0xD424A946B186EC9FULL,
		0xC299B0796AE23AB3ULL,
		0xC8DFFCB7AC6B966CULL,
		0xB948975805AA413BULL,
		0xB447FE25922415D4ULL,
		0xED17F50E79C56024ULL
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
		0xDBD4CEE60B37EFDCULL,
		0xD519CC23F9B0D67CULL,
		0x306DC7D62A8C2409ULL,
		0xD469DD57C3DEEA3AULL,
		0x664180A433CA0B8DULL,
		0xC03D8F623DC116D2ULL,
		0x0E41BBC2521658E2ULL,
		0x3BC748FD8794AEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA92439554F0BFF0ULL,
		0x24C13DE2CE84E25BULL,
		0xF1008A45D19BE18AULL,
		0x62EF45E1DC262EFCULL,
		0xC2045EECA9AE78AAULL,
		0x503B9F1FF4AA24AFULL,
		0x136D0248B4B277D4ULL,
		0x3B7DF5FF5015C135ULL
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
		0x6D11E7B9FD56A11BULL,
		0xCBB261C6B645F6DFULL,
		0x70F3FB0E63D322EDULL,
		0x0424DF3A041194ABULL,
		0x693C49D7D477C4A4ULL,
		0x4A3290275A4C1753ULL,
		0x20A02D81D1E15CEBULL,
		0x1EF57759623EB9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BC825908774E15ULL,
		0x1D52E73CF17A5CAEULL,
		0x8B64501A545B3A51ULL,
		0x6C030CBB11F68779ULL,
		0x3AFF2D472A016D8EULL,
		0xB174813E048A7980ULL,
		0x036426FEF2D433D8ULL,
		0xBA3A25E646C7C5CBULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x19CDFB9E94BB758EULL,
		0xFDBD5A12B9A28F29ULL,
		0x4361CB334E476874ULL,
		0x2F40B8EE5EA24258ULL,
		0xAC4DE7DF42822ACFULL,
		0x196E0945CF48F7F5ULL,
		0xD9764D5E1FAE7DADULL,
		0xE1776400ABD28B15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98D3C33ED725A46EULL,
		0xBD57BBE76D4D0A71ULL,
		0x7C1C739D04D46627ULL,
		0x706664E354551C5DULL,
		0x96A9EF0B471A16C2ULL,
		0x5AFC0E2B5FDA78B1ULL,
		0x23E319FA9186055AULL,
		0xDEB3FB36A1842B7EULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4B73BAEE2CAC3ADFULL,
		0x99104D96E6CB5D45ULL,
		0xF5529E30D82A55D9ULL,
		0xF373AB54A3D86EDAULL,
		0x089837C54724BEA3ULL,
		0x53D31852BBCB5AAEULL,
		0xE4499C7EA2269FE7ULL,
		0x82B2E369F6314B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B73BAEE2CAC3ADFULL,
		0x99104D96E6CB5D45ULL,
		0xF5529E30D82A55D9ULL,
		0xF373AB54A3D86EDAULL,
		0x089837C54724BEA3ULL,
		0x53D31852BBCB5AAEULL,
		0xE4499C7EA2269FE7ULL,
		0x82B2E369F6314B7AULL
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
		0xAC5181BB943D0E6DULL,
		0x5A7186D5D5758322ULL,
		0x62364BA938442D62ULL,
		0xBEA9999D4F47B13BULL,
		0xB7E3BFAA676E49A3ULL,
		0x01538C0CBB31D4FDULL,
		0xD430A5DCA153AE4CULL,
		0xE24D18270AE398F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF768A2529B2F5E4DULL,
		0xD8812748F08B0290ULL,
		0x21B763779017C217ULL,
		0xE9ABC089909AB586ULL,
		0x22538AE002D00A86ULL,
		0x041C1CAE95A0706CULL,
		0x36CA26B564A59207ULL,
		0x0956E63372E6EA48ULL
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
		0x4402BC29FBB3964CULL,
		0x00A50430AEF3A42BULL,
		0xBB4A66C53553583AULL,
		0x211B5D66C3BA6987ULL,
		0x1234D4A5DD16B9C2ULL,
		0xBBC7CDB76036DE80ULL,
		0x2BC715D39DED4CB9ULL,
		0xFD4D1D4D0DDABDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6379F513DB8B451AULL,
		0x864889F15CD71F87ULL,
		0x3D684B4D56F9FD2BULL,
		0xA1613494445EB1A8ULL,
		0xAB4BBF45055CD69BULL,
		0xB6BE9CBBE69184D1ULL,
		0xDBA7FCF726F922A7ULL,
		0x52EEA08F4CB69A9AULL
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
		0xB5756F8E905056F2ULL,
		0x77874DA1E1C065B0ULL,
		0x624CBE7453B15E61ULL,
		0xEE24602C263F05A7ULL,
		0x9FBEC293E1E966A7ULL,
		0xD77B7E793F52DE41ULL,
		0x6507FCCA7A3E1DC3ULL,
		0x43E9B2B570E5475FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF56460ADCA17FDDULL,
		0x9C7982F2D5132F5EULL,
		0x1987B6450D4D4D35ULL,
		0xF95FB4CEC9621974ULL,
		0x623BE0C0647365B8ULL,
		0xF5AB270A472CE564ULL,
		0xD79D191BDBEC44B4ULL,
		0x5288C05161D9BE1FULL
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
		0x31CF565458484169ULL,
		0x0C4358FC63D6D917ULL,
		0x092A41590C5847BBULL,
		0x896E21804BBD1DEFULL,
		0x396F2A611E66545CULL,
		0x34CCEF638D269536ULL,
		0x0AD172B4AFFEBA44ULL,
		0xA1BA7511063DD82AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CF565458484169ULL,
		0x0C4358FC63D6D917ULL,
		0x092A41590C5847BBULL,
		0x896E21804BBD1DEFULL,
		0x396F2A611E66545CULL,
		0x34CCEF638D269536ULL,
		0x0AD172B4AFFEBA44ULL,
		0xA1BA7511063DD82AULL
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
		0x57C3AAF5611C529AULL,
		0x24BA1003D2D67C9CULL,
		0x39D60F7CA8A53E2BULL,
		0x3BB707FF9ABCC414ULL,
		0xDAF575BBD5D66711ULL,
		0x22C6720905F008EDULL,
		0xE2D426B3A9A14853ULL,
		0x10AB76A6C178DDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02936EA692755619ULL,
		0xDCCB9D671ADAEF45ULL,
		0x4124421D9D470ECBULL,
		0xBA17A1E5054093C3ULL,
		0x64E020B993732212ULL,
		0x28E97633546746BDULL,
		0x193D763B362A1E9DULL,
		0x0EA603BC6A20469EULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x8F1CB3A2F205B312ULL,
		0x022F01CBE63EE775ULL,
		0xE00E3EBBF84A1392ULL,
		0xCD49A55074287CE3ULL,
		0xC7F5FD7ABD60C86EULL,
		0x3468D0215360B56CULL,
		0x307A5D569F1AD7DEULL,
		0x4CFAE5E34696E732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CDD4AC14ED92A88ULL,
		0x92E74222C36FD4AAULL,
		0x71FC0E1242558CFEULL,
		0x751F274C26FE14C5ULL,
		0x61F2921E67DF2E82ULL,
		0x63239864083D441DULL,
		0x55A201E2722DDACEULL,
		0x9FF1927E720D08CAULL
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
		0x3B524741D649DA41ULL,
		0x27D199698A5FBA90ULL,
		0x2CDA308E2B5D6C58ULL,
		0xD107390C2D9A9594ULL,
		0xE4FFE19CB1C492BAULL,
		0x1F474F0ED0B32C21ULL,
		0x0938AF5ED0DA36ACULL,
		0x5A60FDD4A2E88036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A19100EE6B2B86ULL,
		0xE1CA28F0C81C0DBEULL,
		0x288FCF3BA3BEC50FULL,
		0x152A32E98740D3ABULL,
		0x91095C0AACACC780ULL,
		0x2AB2889E093657EFULL,
		0xC4BF39CBE930C0D7ULL,
		0x066FB038D9118CD9ULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x840DA8A094455095ULL,
		0x12018A25C48754B4ULL,
		0x1F4B71A058253E79ULL,
		0x2DC5E052266DCE2CULL,
		0xFD55744675F6890DULL,
		0x3B7524129C08BFE3ULL,
		0x8EF35D3FB80FBB67ULL,
		0x4A35BE89B05CADA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x840DA8A094455095ULL,
		0x12018A25C48754B4ULL,
		0x1F4B71A058253E79ULL,
		0x2DC5E052266DCE2CULL,
		0xFD55744675F6890DULL,
		0x3B7524129C08BFE3ULL,
		0x8EF35D3FB80FBB67ULL,
		0x4A35BE89B05CADA3ULL
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
		0x0C0869B909344EA5ULL,
		0xF5C75CB6F941922DULL,
		0x163F3A973AE7539FULL,
		0xEFA577F1191FE930ULL,
		0xF819D8592827124FULL,
		0xFB9181C4693AE816ULL,
		0xAA13A987CF945781ULL,
		0x6C614EE086AA958CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FB42BED4E7610EULL,
		0xF70CC488FDAD4AA6ULL,
		0xB933BCBE6BC083FAULL,
		0x9A0B1B0D97D2AEE0ULL,
		0xF385AB7D95EAB07DULL,
		0x83EB6B62C1459EC1ULL,
		0x051239752B65A1BDULL,
		0xEA1FDE3CFF2CFEA0ULL
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
		0x02A5D894E9FE1B2BULL,
		0xD047E0DDA7E86FC7ULL,
		0x3E787491A6FA4FB9ULL,
		0x40E12ABA9F23D5B0ULL,
		0x038782E3C6690B92ULL,
		0x05C20EAB6CD7A2E0ULL,
		0x5E0256EF95CFFE3BULL,
		0xCB3F7FE4E5820451ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3CFE45536CC88FULL,
		0x2E9AA793406A8B2FULL,
		0x2EDA75CEF613A9BDULL,
		0xCC5344955E90F191ULL,
		0x6AE14EC6D2EA767CULL,
		0x2CB214BAB1F43CE9ULL,
		0x0373AE3FC34463FCULL,
		0x442B6E4266AF5D2DULL
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
		0x804FBD62F6C3B7BFULL,
		0x817DDCF659916FA3ULL,
		0x592F0AA94EA6EEE3ULL,
		0xB59C13CBC87A7726ULL,
		0x9FB5C3CB06676617ULL,
		0x605E1BA7E5AB57DAULL,
		0x9275A97F1E0F6543ULL,
		0xCA66FFDDDFBC3C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30EB25100ED08BA9ULL,
		0x0CB099EBAA8F365CULL,
		0x7720E662C36D3F1BULL,
		0x7D302DC08BD544B5ULL,
		0x6D0C56351E76139FULL,
		0x5A1938EB6C2DEA01ULL,
		0xD254DB7B8F3DC2ABULL,
		0xFC95C3AD71961F32ULL
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
		0x8CE675974BBFD874ULL,
		0x801307FB8A3E58CBULL,
		0x4B97BE5411B89083ULL,
		0x25F0AA91CA6A2C3BULL,
		0xBE721C9E64177034ULL,
		0x5BAD1B1A9B8671FEULL,
		0x45E80393FF6D49A7ULL,
		0x2DE05C0B351022C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE675974BBFD874ULL,
		0x801307FB8A3E58CBULL,
		0x4B97BE5411B89083ULL,
		0x25F0AA91CA6A2C3BULL,
		0xBE721C9E64177034ULL,
		0x5BAD1B1A9B8671FEULL,
		0x45E80393FF6D49A7ULL,
		0x2DE05C0B351022C4ULL
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
		0x8CF969F377105FDEULL,
		0x12B011613E3117C9ULL,
		0xC9477F43C53444CBULL,
		0x336D9AAAC3CB25E9ULL,
		0x5F5F3001D28D873AULL,
		0xDBAA8C772025CC67ULL,
		0xDDB20BC5BE45B0BCULL,
		0xEA71B2274B38934BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C0709A0EAE2A3EULL,
		0xB693D472B51F7904ULL,
		0xBFC3EA46DC33AA17ULL,
		0xC0204F1D8E61083CULL,
		0xB6C2105BEEC4BC58ULL,
		0xF961CE252F046C04ULL,
		0x83416CC036EF7167ULL,
		0x501A7A5B403905EBULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA3050178FC786525ULL,
		0xC0EC349D9932B570ULL,
		0x239FB9B0C9DBE48EULL,
		0xB67FB5E3327E822EULL,
		0x606111605BB0561DULL,
		0x346B229318F6F281ULL,
		0xCFD58F36E3A8CD45ULL,
		0x6E5FCB4D2B575F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8BE9A5022AD24FULL,
		0x2744F81F247DF102ULL,
		0x0C7E20EF957992A9ULL,
		0xE588787EF77FD038ULL,
		0x434F4BD4F1C34BEBULL,
		0x9682FA56EFDD2646ULL,
		0x62E0AE77F915C71FULL,
		0x6858BF7C31EB16AAULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE430058EF818E13BULL,
		0xA060F5F1A7480405ULL,
		0x3010E49B5755BA46ULL,
		0xEA8D510EE1CEDE24ULL,
		0x01A0CF962021C06CULL,
		0xE6DEEA4B1AAC0561ULL,
		0xC5FB122C3D3C03BFULL,
		0xA348A2F5A8AA2352ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C444B588F9FF341ULL,
		0x543382B8573180BBULL,
		0x36C225AEB6A08898ULL,
		0x386B5492C8F596FDULL,
		0x7C4FE507F6BB5389ULL,
		0xA7E097BC8AAD5A3EULL,
		0x51D6E09361688E9FULL,
		0xAAF4736CCAE07B39ULL
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
	return 0;
}