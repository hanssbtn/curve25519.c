#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x7B5B4A9E54115024ULL,
		0x15FD9D6BD42F38ADULL,
		0xEF08C3AA8B075516ULL,
		0x530B41D442E1C0F0ULL,
		0x8EBA95372C5B4F94ULL,
		0xC06638D015C27874ULL,
		0xF69BC90CABECDE44ULL,
		0x15EB4BED9C848E13ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x760F2270A5C5815EULL,
		0xB2AD4EC011091FBBULL,
		0x82A818030846750BULL,
		0xD4DCBF4B64782FDAULL,
		0xF030F0D5BC03DE2FULL,
		0x28991E90339CEA4DULL,
		0xFD2BBED9535B89B8ULL,
		0xEDCF2624735AB212ULL
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
		0x44FB962E0262E273ULL,
		0x0DE7FD42174DD855ULL,
		0x51C56DF4C1CD8762ULL,
		0x76A8C419B4A29671ULL,
		0x69CB1525C457195FULL,
		0xD01631FB6FCF715DULL,
		0x3CA998BA1F03877FULL,
		0xD8170F5E921ECC08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80082798364CB29EULL,
		0xB355B7A508091BBCULL,
		0x20F94A0D783E9DA6ULL,
		0xE89FC9E0E117D539ULL,
		0x88E69FF36C612FCCULL,
		0xB7561E8EF1972621ULL,
		0x54352DEF917BD62EULL,
		0xD7BAB0BF5D48F9ADULL
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
		0x88764E82AD83A495ULL,
		0x519A5138C5B84F74ULL,
		0x439D8E8EA21157A4ULL,
		0x9DA69699925F3F06ULL,
		0x1DD808806D85359CULL,
		0x86E1A205C56829EEULL,
		0x28A3DA77BF7A3F6BULL,
		0x8EAC646F9FB0A0A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2E1CEF43B7988CCULL,
		0xE936D0E7E260F8C6ULL,
		0x7704AD8098472C23ULL,
		0x51C9F14A18389D6FULL,
		0x6AD7265E646D3D96ULL,
		0x0B7DAE73ACA87B28ULL,
		0x69CCB8BB47A9438DULL,
		0x849ECCC8D6E464CAULL
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
		0x223E76B6D9022F17ULL,
		0x53DEE09B071D6511ULL,
		0x81220D5A91B8036CULL,
		0x89C2C9515405E58BULL,
		0x4EEF836FBD6806B8ULL,
		0xDC7807C12ABCCA6FULL,
		0xA4BC5DC64AB18A72ULL,
		0x325F15E3225EE230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6111C513ED208281ULL,
		0xB7FF9608A9C6188EULL,
		0x5758E5B805FC2855ULL,
		0xCE1582E9A31B9A27ULL,
		0x365D128CB9603A02ULL,
		0x0D3B129F0D7DC8F5ULL,
		0xD6F148922957D088ULL,
		0xE4DD1D4B5DA4D8D9ULL
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
		0x2C18139D9FDB9AFDULL,
		0x10318E51C33B136BULL,
		0xB38AA31FEC33D3EBULL,
		0x5B59A5380F162009ULL,
		0xF03B2128DC441610ULL,
		0xE7500E6717E18708ULL,
		0x06E6649F2EFF6F3EULL,
		0xADDCBCDEEA992DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C18139D9FDB9AFDULL,
		0x10318E51C33B136BULL,
		0xB38AA31FEC33D3EBULL,
		0x5B59A5380F162009ULL,
		0xF03B2128DC441610ULL,
		0xE7500E6717E18708ULL,
		0x06E6649F2EFF6F3EULL,
		0xADDCBCDEEA992DB9ULL
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
		0x434AC7915C0CBB83ULL,
		0xADF2EDEE18AAD0A1ULL,
		0x24F927783BFEEA7BULL,
		0x6DE845C3F94EE480ULL,
		0x7A7FFCA11812F5ECULL,
		0xCFBB3CFCE666390DULL,
		0xDE92A83D867EAE3DULL,
		0x3A9ABE4ABA356E90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x865BE912FD5C32BEULL,
		0x8219C684BBF1DABAULL,
		0x01FE830EE18E96DFULL,
		0x61F651BF6BD6E0FDULL,
		0x27B92B0849305DDFULL,
		0x665FD29BBB24712BULL,
		0x5C01A958CA20C7E5ULL,
		0x2C13076973AB8004ULL
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
		0xB2BC97E4B2978A2FULL,
		0x7A927A7DAC4F8F8FULL,
		0x26FC3F6F6DA27DB0ULL,
		0xC238324DC0C5C3A6ULL,
		0x0723BCDB6C5C3B80ULL,
		0x279E01075735EF05ULL,
		0x474C03E99895CAB9ULL,
		0xBC99BFB98F584811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD2E81AF6FDB2F6EULL,
		0xE77220A83DE977BAULL,
		0x5EDD2713E55AB8ADULL,
		0x5DD48566A1C35003ULL,
		0xCAF8DA52A63A2698ULL,
		0xA357BDC63DA022DFULL,
		0x396EBFE9587DB795ULL,
		0x592015D8BC1C28C5ULL
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
		0xD846E4AF232C9A62ULL,
		0x8DC0087E0697BFE4ULL,
		0x85DB95DCEF954CFCULL,
		0xCF13AB14BCBEAF9CULL,
		0xA6F52C2318F4430EULL,
		0xDA36A4FAAB454C02ULL,
		0x37367B3F501ABE2CULL,
		0xBF13872F3D1C9C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80C785781B1546D3ULL,
		0x0476A1C6C9B9790AULL,
		0x816411C34F846454ULL,
		0x4F9FBA245B278138ULL,
		0xE110E6493312B914ULL,
		0xA4ECD0AEEDFE05AFULL,
		0x4F4AAC55901B98B2ULL,
		0x495121F86D293EF3ULL
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
		0xE52B99B5797A2FCDULL,
		0xBA2D35DDC41F6739ULL,
		0x5323E4732A49CB2FULL,
		0x39F612E7CAFCD916ULL,
		0x9839FBC59C88B593ULL,
		0xFD662B740224081DULL,
		0x51A5CA1A5B64E869ULL,
		0x9E188329A09D58DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52B99B5797A2FCDULL,
		0xBA2D35DDC41F6739ULL,
		0x5323E4732A49CB2FULL,
		0x39F612E7CAFCD916ULL,
		0x9839FBC59C88B593ULL,
		0xFD662B740224081DULL,
		0x51A5CA1A5B64E869ULL,
		0x9E188329A09D58DCULL
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
		0xE3FF4BDBD3B23D65ULL,
		0xD91776D225CF2350ULL,
		0xCA930075F3F2AFF5ULL,
		0xF0EE55023A963B50ULL,
		0x2CF51532F8115E17ULL,
		0xA2D4016074EB8679ULL,
		0xF5BDBD53D8CBA1C8ULL,
		0xEF1C44EAA0FF6159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0107AFEF66DFBF3ULL,
		0xC5B09062A11F1A44ULL,
		0x0E24CB20F0F7C65CULL,
		0x147A88A702E86836ULL,
		0x6241569E6C36BC4EULL,
		0xA30876D7355A92A5ULL,
		0x408CD78ADA06491EULL,
		0xEC0DA56B91371583ULL
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
		0xA76128F7E2DD9CF7ULL,
		0xE508D8B633A743E1ULL,
		0xD8C30542136EB235ULL,
		0x095017BC90420924ULL,
		0xAEA7C565DBC7F7A3ULL,
		0x42D328336BB3030DULL,
		0x47262B57B0FE3477ULL,
		0xE0EDEF8D616715C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x749261A6C15D5A33ULL,
		0xDC770064E6B97C17ULL,
		0x2B3F5AB529AB4C56ULL,
		0x002C064549F3DF0FULL,
		0x01B1731B48E57F01ULL,
		0x9EB5A6A0049371F8ULL,
		0x1172A500DEDE9ED1ULL,
		0xDDBD2029238A2223ULL
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
		0x8C026DB7627E8820ULL,
		0xC8C71E5C3B35CEF1ULL,
		0x2C3D7931B70636EAULL,
		0x5F8F2A79C7583035ULL,
		0xB253C2B615D2F57FULL,
		0x4ED3D87D12A33A1DULL,
		0xCDFB5F3A9B6BB3A9ULL,
		0x1FE3F8CE03785866ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD8A4145E8C8651BULL,
		0x72BC5037BC80E844ULL,
		0x72A8018E701C439AULL,
		0x49776590DEACEF09ULL,
		0x8D4F876D6C2EFF7AULL,
		0x44202530043C1A9BULL,
		0xA1D3EBE55AADA050ULL,
		0x4B78122F058A53EDULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2F763EA46D2AECCFULL,
		0x08F7668A0DF7B4E4ULL,
		0x3D23C9BC7D1EC1D7ULL,
		0x31AA15EF614B9026ULL,
		0xB232CBAD40D12AECULL,
		0xECD6307A3962B63AULL,
		0x7EA622BD18275CE3ULL,
		0xF67E3D05CDF6BAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F763EA46D2AECCFULL,
		0x08F7668A0DF7B4E4ULL,
		0x3D23C9BC7D1EC1D7ULL,
		0x31AA15EF614B9026ULL,
		0xB232CBAD40D12AECULL,
		0xECD6307A3962B63AULL,
		0x7EA622BD18275CE3ULL,
		0xF67E3D05CDF6BAEAULL
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
		0x3CCF8402B9EE731CULL,
		0xE924CAD9E80E09BFULL,
		0x1AF11767A71B797AULL,
		0x05CE51409BD6C0E7ULL,
		0xA3942C14A7AC12B9ULL,
		0x0A587C4589000E66ULL,
		0x610EB9C67F54FF51ULL,
		0x18C12E7CB583827FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C3C81AA5C1B952BULL,
		0x159A9C355D07E0FBULL,
		0x12984680372B7F05ULL,
		0xA57117B941BF1208ULL,
		0x604C502C6EEE1255ULL,
		0x661FDBCBBA880683ULL,
		0xB85DE0F01B8F3C7FULL,
		0x5CFA727F3FD59CB2ULL
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
		0x664E8D1685E2687EULL,
		0xA269928DA55F2177ULL,
		0x22F76AF37CBFCA85ULL,
		0x91C439FB4B2459A9ULL,
		0x88DA9DF5C7790113ULL,
		0xD6571DCA472877ADULL,
		0xE3D82E18D54E35CAULL,
		0x59B6414B9B5F66E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB51481169E1A92ULL,
		0xE7BECD27B60E4996ULL,
		0xB504DBCDE6607EE7ULL,
		0xA0A9780E02D114CDULL,
		0x2196CE90E6E4BD83ULL,
		0x019FE4D2C32256A2ULL,
		0x45B5F45CAA278AA4ULL,
		0x26CFABA39B499E1CULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAE011284A6C3C2F6ULL,
		0xE9E3F963F842048EULL,
		0x026C71EEA6766DFFULL,
		0x1BD72C33558505F7ULL,
		0x3CEE042AFDA0FA89ULL,
		0x77A0557EC909DD2DULL,
		0x865D4A133C891D2FULL,
		0x9D0566071E91FB88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC809F50E79C63E14ULL,
		0x3A9EB68CC62CFBD7ULL,
		0x6786E5AD27F04ED2ULL,
		0x03555A9AE589EFC0ULL,
		0xBB19A14907B1AB5BULL,
		0xAF4858B5DD7DC7F0ULL,
		0x0D5D9489728127E0ULL,
		0x707E08EA9E433000ULL
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
		0x073B4CEDF208CD7AULL,
		0x535D173857ADD943ULL,
		0x9AEFB94E327F306CULL,
		0x66B5A103E7BF4467ULL,
		0xB073468E20FC4227ULL,
		0x417B39564F207F11ULL,
		0xA54A50ADA9E57D12ULL,
		0xF1D0A6AF4D0A7101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x073B4CEDF208CD7AULL,
		0x535D173857ADD943ULL,
		0x9AEFB94E327F306CULL,
		0x66B5A103E7BF4467ULL,
		0xB073468E20FC4227ULL,
		0x417B39564F207F11ULL,
		0xA54A50ADA9E57D12ULL,
		0xF1D0A6AF4D0A7101ULL
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
		0x3B9663A87E3FAD5FULL,
		0x8E0F75740DE936ABULL,
		0x4E576E1782C92C08ULL,
		0xD3186632BCA17E16ULL,
		0xC1F9E28CDBE3F87DULL,
		0xD72480BBE98B03C0ULL,
		0x04D2BAC8E27ABD39ULL,
		0x2EAD8B2624E0404AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD4B2C3AF6D3EA6CULL,
		0x42DC354A18573E53ULL,
		0x597A9EC80C9A14B4ULL,
		0xFA400EF47A0E24C7ULL,
		0x98CDDA5D20C23402ULL,
		0x0F56E992BFBAA1CAULL,
		0x7108370BA4E0467EULL,
		0x367C7B5D8B717ACBULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6F5D9A510D3CCC15ULL,
		0xAA5DCAA774ECC8DAULL,
		0x353CCFA81ADC65BFULL,
		0xE83CAF8859D8496AULL,
		0x64704269CD051364ULL,
		0x3B9A50357AC5A249ULL,
		0x612593E57BF0534AULL,
		0x8CD7523774E03524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE69143A4E38366ULL,
		0x6110AA4EC50571C4ULL,
		0xA774F7C2B0D57E86ULL,
		0x7072DB891A1AD290ULL,
		0x7BE4A9D4B3BC1270ULL,
		0xA703F263F9419BFDULL,
		0x8E02D98B85F3AE74ULL,
		0xBE026CC03EA75270ULL
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
		0x82D55690BDC3F18EULL,
		0xAB0D009D311EDD50ULL,
		0x2580A884A598C9C6ULL,
		0x03962C69983F9B79ULL,
		0x2537AFDF386F2DF4ULL,
		0x15DC99BFB803A460ULL,
		0x95DD4B3640953BFEULL,
		0x7BDB01C81F29A3E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF366117DC08D3FDULL,
		0x4D5C0AF93CF14395ULL,
		0x1D289DBE705F9813ULL,
		0x39D3522517AF8E57ULL,
		0x8031D7FAA5FAB086ULL,
		0x33E594F7DC333AADULL,
		0xA5D95C44F820DEB5ULL,
		0x6F2169BC77D4B431ULL
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
		0xF0F1C929C948C116ULL,
		0x87C11C15EB431408ULL,
		0xA7E8F7ACDAED499CULL,
		0xC0C2C65A31076042ULL,
		0x15244EB0613D7D4BULL,
		0xF0A2F8598F18B715ULL,
		0xC2C3B85F729B2E18ULL,
		0x030DD1D0EBCA10D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F1C929C948C116ULL,
		0x87C11C15EB431408ULL,
		0xA7E8F7ACDAED499CULL,
		0xC0C2C65A31076042ULL,
		0x15244EB0613D7D4BULL,
		0xF0A2F8598F18B715ULL,
		0xC2C3B85F729B2E18ULL,
		0x030DD1D0EBCA10D3ULL
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
		0xCFA641F1F7BA410DULL,
		0x0D7D43CDBB76DA24ULL,
		0x9AF4506A30761541ULL,
		0x4EBA696EB7FF3FCBULL,
		0xC7FB33F5FBC9A790ULL,
		0xF1E73CC5BAB35E4BULL,
		0x3FD3032CB6BA369CULL,
		0x84976E4FEBA9F114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4A89A778143B64ULL,
		0xC41B0CEA88AE0222ULL,
		0x998F8BFEA049E84AULL,
		0x3F1217CCA46E2C62ULL,
		0x1BC5E69B6E00423EULL,
		0x836B74B37C4316E3ULL,
		0xA5DA5CB896BDEBFCULL,
		0x5968A4B7137F67C1ULL
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
		0x5F9B0FCEE2F633AAULL,
		0x7E267D569D9ED8A2ULL,
		0x9B6C29B5EC24BF24ULL,
		0x20FE0A1294A48DE7ULL,
		0x57892DF5F2EDCB7BULL,
		0x3AAA8EF16DE51BA0ULL,
		0x4937A95B0A1068F1ULL,
		0x7DD774136EA3A940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26EDA7350ACC7A6BULL,
		0x9B5255B00CC4F408ULL,
		0x18F1C1EC5DC1573CULL,
		0xE2A9C6BC2B4A7A60ULL,
		0xC14863D98F6C22FDULL,
		0x7ABE4DF75093968DULL,
		0x1089881E2B77A766ULL,
		0xCC84D18C0AE0A065ULL
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
		0x32DACAD040BA1C9BULL,
		0xC96A71C3CB46A61FULL,
		0x52DE77FDACEDCDF9ULL,
		0x67A1F21C73DF8E34ULL,
		0xFDB9B64EE7968AC5ULL,
		0x1FCCE8F55561BE04ULL,
		0x27DD9E8746EFB95BULL,
		0xE5962773047F6E82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44AB11AD730F572AULL,
		0x7C253B9F30BA688AULL,
		0xDE52028A7AF2A2A4ULL,
		0xAC904A52E829C529ULL,
		0x2B114545E3C21A3DULL,
		0x07EB3C29752E2E3FULL,
		0xA657B62D886BBB5EULL,
		0xE46D057CCDC10CCFULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6D6D39AC899F82FAULL,
		0xF4ADB9B12A90CDE0ULL,
		0xFA2E7F64AC7CAAD4ULL,
		0x5B8CD5CCE01E3EE6ULL,
		0xCE802CAE542FB44BULL,
		0x39B8C84482CC0697ULL,
		0x4E32CDAFB9950CCEULL,
		0x376C3C293F1D51BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6D39AC899F82FAULL,
		0xF4ADB9B12A90CDE0ULL,
		0xFA2E7F64AC7CAAD4ULL,
		0x5B8CD5CCE01E3EE6ULL,
		0xCE802CAE542FB44BULL,
		0x39B8C84482CC0697ULL,
		0x4E32CDAFB9950CCEULL,
		0x376C3C293F1D51BFULL
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
		0xAA674C645F312C8EULL,
		0xE2648D9D69009F03ULL,
		0x0ABDAA4A9016987BULL,
		0x63A5CDA198DB472EULL,
		0x6C2013658C0E9C5EULL,
		0xA3ABDE707CA82E2BULL,
		0x1DC34C7F74C95822ULL,
		0x00FC6B05E708D867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5AF5C4D9019089ULL,
		0x2F0973B9362A5AA4ULL,
		0xA6A5006E1BA4AA3BULL,
		0xF509AF33DA6C9530ULL,
		0xB28A35D00D1B6710ULL,
		0xF0F1D1ED3B07F524ULL,
		0xCD96F2EB76997A5FULL,
		0x39A23F2C6E020DACULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCBE63609019B4F56ULL,
		0xDA352107323C1E75ULL,
		0x18A6828EA68AEED5ULL,
		0x69D56D97949362B3ULL,
		0x45172261EA600343ULL,
		0x7A018D2AE3C9BA37ULL,
		0xE3EA14B2D054A6DEULL,
		0xC7035B0FF5EF1132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD07DFFAF3B0150ULL,
		0x6D59F52C81786B67ULL,
		0xB56A2D6AF203808FULL,
		0xD961FC053343ED16ULL,
		0xEBEEC3A7E82F47B0ULL,
		0xFF8A2EC665AAE489ULL,
		0x2B9C1FE4E6D91CF0ULL,
		0xA2F76D8BC039B1FCULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x108C841C9502F296ULL,
		0x832F7D355141F7C0ULL,
		0x57E0DE666B05EBEEULL,
		0x4AA4A3648014864EULL,
		0x92B37223BCA878B2ULL,
		0x87F26418D60518A9ULL,
		0x72D8E08B3AA17825ULL,
		0x7647B4A2397352EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2933DC48F205A5ULL,
		0x5A75E1E5C7FABEB8ULL,
		0x266BBB8A24C4F36AULL,
		0xA4B6481C8B5E1AADULL,
		0xB31B311571B3AEC6ULL,
		0x2383D6D56ECC5B3CULL,
		0x2F7C7F0605AF3B88ULL,
		0x5E55AC6BF774C5D2ULL
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
		0xDB0395A65B2A3FC9ULL,
		0x36550130EFE1D119ULL,
		0xA2484F21E8AF19F6ULL,
		0x389A8FFEAD759B24ULL,
		0xD97E5B0E2639DF9DULL,
		0x2FB1E52F485F4BB5ULL,
		0x00EFF4FBE73E14BBULL,
		0x1B24E6E70BEE0044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB0395A65B2A3FC9ULL,
		0x36550130EFE1D119ULL,
		0xA2484F21E8AF19F6ULL,
		0x389A8FFEAD759B24ULL,
		0xD97E5B0E2639DF9DULL,
		0x2FB1E52F485F4BB5ULL,
		0x00EFF4FBE73E14BBULL,
		0x1B24E6E70BEE0044ULL
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
		0x30B703BBAA2995F0ULL,
		0xA4B8320092D9875CULL,
		0x7C5E20DD210CA936ULL,
		0x41586253129D6CE4ULL,
		0xE3CF83046E17B26CULL,
		0x08865AA7E67531FAULL,
		0xA91016B3D7D72676ULL,
		0xD2C949AE7D199D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78759E382DD65934ULL,
		0x41AA0A4513C1B725ULL,
		0xBD6283FB02D7BE4BULL,
		0xA149097E72CA1D22ULL,
		0xDDA646224A21133EULL,
		0x4A990FA4482B719FULL,
		0xF8098B2A7B24758DULL,
		0xCBCA337B7B85CBE2ULL
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
		0x1A804AE1612A8AB7ULL,
		0x87F2835794232059ULL,
		0x3CCED4CD3B917C3FULL,
		0x6189043C873570F3ULL,
		0xCAA4F84D1ED475CDULL,
		0x3C12B117B65DB2ECULL,
		0xE9994153783A47C9ULL,
		0x498A2A5418533331ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D890F55ABC7E0DULL,
		0x4D5E3DEBACF14F15ULL,
		0x05E9E8A68AE096A0ULL,
		0xBFFBCB23AC14F5DEULL,
		0x4040A8600881C8AFULL,
		0x568B8116F763E90AULL,
		0x5E23F1E9CA7FDA3CULL,
		0xA09223FD27E58631ULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xADB02E6164C44313ULL,
		0xBA19357A981D182CULL,
		0xDEE319DCF4F61537ULL,
		0x796727D2DDF782B8ULL,
		0x30DB927C6699930EULL,
		0x520CBCE63CE7655FULL,
		0x3777F5FE67AFC56CULL,
		0xE845319FFCBC5F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4B27C86EC585C9ULL,
		0xA051BEA38547A074ULL,
		0x04C3CB17A3B9211AULL,
		0x4B8C79249890E24DULL,
		0xDE443E8CD2C6E538ULL,
		0x7A032C97DB5BCED7ULL,
		0x8136C3A4B60713C6ULL,
		0x639100CDBBE0E2C3ULL
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
		0x552D55790F8D347DULL,
		0xF5B6CBB3C3F5D2C6ULL,
		0x0AA2F746F0D1EA02ULL,
		0x50A3249AA82A56A8ULL,
		0x2B3863BFEE430C6FULL,
		0x6FB02EF8A35B910EULL,
		0x8F316A66BD8C2793ULL,
		0xE3B2620A2C9A63D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x552D55790F8D347DULL,
		0xF5B6CBB3C3F5D2C6ULL,
		0x0AA2F746F0D1EA02ULL,
		0x50A3249AA82A56A8ULL,
		0x2B3863BFEE430C6FULL,
		0x6FB02EF8A35B910EULL,
		0x8F316A66BD8C2793ULL,
		0xE3B2620A2C9A63D1ULL
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
		0xD0DA600E5E899E3EULL,
		0xDFFFD06898992F0BULL,
		0xA5AD562B92F308DFULL,
		0x86914EEDCDA6A2D1ULL,
		0x44CD6AF455584D67ULL,
		0x38108F91C463B6DCULL,
		0x87521B724162DDCFULL,
		0xB77EDA1772FCCDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C2ACA92FDBB9F5ULL,
		0x09337FCE73DF5BBAULL,
		0xE46FDADBF5E503DCULL,
		0x6E01FBE0385E5B61ULL,
		0x3A0930FE94C52A20ULL,
		0xB8B382D29B0A9839ULL,
		0x2F817A5B117BCFF5ULL,
		0xCD0974DE66806A97ULL
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
		0x382C4DFA84C7E6A4ULL,
		0x4B779B74AF37F1D6ULL,
		0x0B355721BA982196ULL,
		0xF284565A056AFDB6ULL,
		0x365D80698EB69609ULL,
		0x99955DE285F66FAAULL,
		0x656D0CDDB3D231EAULL,
		0x883BF0A037A6484CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7329CF9B044D8E7ULL,
		0x6E86E3C0A55A0528ULL,
		0x82DAD7727F1A7E2AULL,
		0xF00CFCE829F28CAEULL,
		0xDFB981E3761D1B16ULL,
		0x5479DABBD80956F8ULL,
		0x4328721A70810078ULL,
		0x2ADD1926D4501A02ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x37CA509A3C41D94FULL,
		0xA9ADD0650CE0CC13ULL,
		0x80D8EADFC3FF062EULL,
		0x0DE3882FDF627A42ULL,
		0xA49FB2EF724A86B1ULL,
		0xA4F02C6E1BDB1AC1ULL,
		0x4F05A59FCC29BE1BULL,
		0xD1085E3F7DEFC27BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403053D3614F6817ULL,
		0x155CED15D035CA08ULL,
		0x4AA6089FD69C1953ULL,
		0x2E48BE9236D447EAULL,
		0x49EF4456FAD12B3CULL,
		0xF4B5EF9D7EB4A949ULL,
		0xAD4C1CBA39EFA20AULL,
		0x81A9DCAB3BB51CA3ULL
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
		0x235E9110C5504A45ULL,
		0xD05B19C39C33ECABULL,
		0xFECC69795B239DE5ULL,
		0x7EB54751DE9CECBBULL,
		0xB9F5DBBCC1DA492CULL,
		0xA542F6BCADB70C78ULL,
		0x3305176D47C7950DULL,
		0xB9C9DADA0FCEDFF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x235E9110C5504A45ULL,
		0xD05B19C39C33ECABULL,
		0xFECC69795B239DE5ULL,
		0x7EB54751DE9CECBBULL,
		0xB9F5DBBCC1DA492CULL,
		0xA542F6BCADB70C78ULL,
		0x3305176D47C7950DULL,
		0xB9C9DADA0FCEDFF7ULL
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
		0x656541F969B3A1B9ULL,
		0xEF0C133EF21EA7F9ULL,
		0x9738F9F4CD75CB9EULL,
		0x30366C4F144473C1ULL,
		0x23DCC29237D331BDULL,
		0x29F71E265C569AE1ULL,
		0x0C35C0F494328A0CULL,
		0x7D4DA0F0324CB961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27AADB36B96EF42DULL,
		0x0755CDBA6D0F0A24ULL,
		0xE20A36259E17DDB5ULL,
		0x9DECFF780C0926BDULL,
		0x2CF7E2D3664175FFULL,
		0x3A815A3D97572FE8ULL,
		0x5314D11987C13556ULL,
		0xCAE11AB405AFB897ULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x805E0EDD1F04CCFDULL,
		0xD1451EA39B727480ULL,
		0x87E5705985F2BBF7ULL,
		0xCCD8D4FACA2ADAB5ULL,
		0x34C1F62A5B200A7AULL,
		0x54C2181CF5AB74B9ULL,
		0x709D59A46D30D8C3ULL,
		0x1D16DC747195C5A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D49B3EDFB1454B4ULL,
		0xCA9E21C6021B5EEEULL,
		0x9320F39F5105CDE0ULL,
		0x61F80CF4BC298EFBULL,
		0xB5A4E179B313C463ULL,
		0x3B7DCB3232EFCC51ULL,
		0x6720CE55E8376139ULL,
		0xDB56672D3721FDC0ULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x77A27FC7154BF556ULL,
		0xFE04911558D3BE03ULL,
		0xA835D9F37C7E7BD8ULL,
		0xC618B9FDC8C00D1BULL,
		0x92A912BC9EC028FBULL,
		0xA29633C7404E1DCFULL,
		0x33E4883451A71290ULL,
		0xD788FFFE287A848CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E487256C4979F1EULL,
		0x8416FFE42ED20A86ULL,
		0xDE0BFD27A2DB91EBULL,
		0x56BCB546CDF0E773ULL,
		0x852591B2B1B1990CULL,
		0xD0BDFFAC41FE9AF6ULL,
		0x9C03FFA96FDBDC41ULL,
		0x838ED5F82228DAEBULL
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
		0x034462EEFC1538AFULL,
		0x0E67E834A4AC5A2AULL,
		0x073A17D0555A4EEDULL,
		0x336BA64E2FC47B13ULL,
		0xA5F6DDB8D4427715ULL,
		0x14C99E73164F48ADULL,
		0x809906A251C14D29ULL,
		0x74FE692D7FB5996FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034462EEFC1538AFULL,
		0x0E67E834A4AC5A2AULL,
		0x073A17D0555A4EEDULL,
		0x336BA64E2FC47B13ULL,
		0xA5F6DDB8D4427715ULL,
		0x14C99E73164F48ADULL,
		0x809906A251C14D29ULL,
		0x74FE692D7FB5996FULL
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
		0x52D0828EA2A31329ULL,
		0x2340EE2019BFA605ULL,
		0xC79C950037FB08C8ULL,
		0xAFF76592A8EB7ADEULL,
		0xD6AD117E7A30769CULL,
		0xD986502C3CB1F7A3ULL,
		0x9E0B4813D151F2CDULL,
		0x8AE18AA48CBFCDD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2765B797F6BD7974ULL,
		0x3AF8445775D5EB74ULL,
		0x3E53460D07C7EEF3ULL,
		0x7764F7D56E60CBAFULL,
		0xEFBBFC59A241669FULL,
		0x2212066F1E3266C3ULL,
		0x045755D26952E11BULL,
		0x5C56D6684C493084ULL
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
		0x3C1E37CD619A5938ULL,
		0x6527AB793D7AA934ULL,
		0x05A9DA9885BEEBEFULL,
		0x0B97A86EBD11FA88ULL,
		0x60AB9CA42F9B7D43ULL,
		0x8E3723B34E20E573ULL,
		0xE331B59C50639187ULL,
		0xC14C631108A37F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1695A342A00631A5ULL,
		0xA0799BBBBA9EF41FULL,
		0x5E8DE54EF118CBF5ULL,
		0xC8FF0F5B43837058ULL,
		0xAA43E061EBC7791EULL,
		0x27A325598FDDA0F4ULL,
		0xC13C7425DDBA23B2ULL,
		0xD745B15DBC26227BULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x15DED922D9F08016ULL,
		0x176F65461A5198D7ULL,
		0x2B0270C1894164FDULL,
		0x1F984FA591E57481ULL,
		0x91AB8E29C6897E45ULL,
		0x3C88E9CAD07F7E4FULL,
		0x97E85164C786D852ULL,
		0x9825D75508570A33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF6C86EA8CA16386ULL,
		0xB9A9A8A6CD985551ULL,
		0xE6C6A95645860050ULL,
		0xE90EF282D870B974ULL,
		0xF0382640530185A9ULL,
		0x6B85A0A65AF3EBA6ULL,
		0xE3F332B7F0D1B4EEULL,
		0x5B854713A53B03D8ULL
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
		0x102B56D0F32C8445ULL,
		0xCC157F854DC9621AULL,
		0x72612C3ACC60F9BFULL,
		0x3BAFDE3508BF74E4ULL,
		0xA0DAA0005E012451ULL,
		0x02A65F07BD6AFDDDULL,
		0xC8CA019DFC42C7F0ULL,
		0x3E41D81255A138E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102B56D0F32C8445ULL,
		0xCC157F854DC9621AULL,
		0x72612C3ACC60F9BFULL,
		0x3BAFDE3508BF74E4ULL,
		0xA0DAA0005E012451ULL,
		0x02A65F07BD6AFDDDULL,
		0xC8CA019DFC42C7F0ULL,
		0x3E41D81255A138E8ULL
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
		0x696BC1B1E9C7C484ULL,
		0x0480A8F54D23BBB9ULL,
		0xA093B6245DF029DCULL,
		0x53A229C859621C9BULL,
		0xC9ADABAF4DF1C7ACULL,
		0x0750F2DA43B65589ULL,
		0xC3237B0DCC5C1C03ULL,
		0xA0F4D5632A9A4E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A682BEBDCD24CCFULL,
		0x6C2BBA49FCEBDA07ULL,
		0xEEAF83C8B6DBDE9AULL,
		0x845BB09A4B1CC2D7ULL,
		0x795BBACC9C2220CDULL,
		0x6FEE7FB01337645BULL,
		0xE11D8B8012D3CE80ULL,
		0x2755E22E2690BDA7ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEB04565C1C9D5096ULL,
		0x22B9076D6B84A0A4ULL,
		0xF5B31438010CBB3DULL,
		0x9B006553E20C9330ULL,
		0x2358C4857A75C4CDULL,
		0xA57A307F5F5CDE3EULL,
		0xA4994DCA18A08F36ULL,
		0x097CCF8428AF2B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD615EF03403C8BULL,
		0x33EBE6DFFBF8279DULL,
		0x143FB291B9688E98ULL,
		0xA5340A959745F296ULL,
		0x3367D30B90AB4408ULL,
		0x63D017926BE4E1E2ULL,
		0x4AB13ABC8EF11550ULL,
		0x949178562DFFADECULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7A36DACF7FD250D6ULL,
		0x32FF467B72179B6BULL,
		0x111099AD921C3214ULL,
		0x53CF1EFC766B1E8DULL,
		0x9B79837BC024A085ULL,
		0x563496C09F123A7FULL,
		0xD2B5585B2F733FA8ULL,
		0x043A51D6B99D62F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x263DD62B28540E17ULL,
		0xD4F225DDF1590D23ULL,
		0xAB30C3C688625DD1ULL,
		0x5EBD5B40BB702F1AULL,
		0x9EEB1E13DE09B0EAULL,
		0x352DDB37695B16F2ULL,
		0x17540DBEAFCE219BULL,
		0x578E38FB75A9DE94ULL
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
		0x64835EAD30AF81F1ULL,
		0xFB99828E80691958ULL,
		0xAAD95856C62735EBULL,
		0xFDD98989D25D663CULL,
		0xF99686E8EB7BF37CULL,
		0x10D5567235CCEABCULL,
		0xA0D781E952CB05F7ULL,
		0xB439CF21E561CC3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64835EAD30AF81F1ULL,
		0xFB99828E80691958ULL,
		0xAAD95856C62735EBULL,
		0xFDD98989D25D663CULL,
		0xF99686E8EB7BF37CULL,
		0x10D5567235CCEABCULL,
		0xA0D781E952CB05F7ULL,
		0xB439CF21E561CC3DULL
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
		0xDB334CB9AB549740ULL,
		0xD9B940867A50FB3EULL,
		0x64ABDB88296D6C00ULL,
		0x2A4CF8013215B26AULL,
		0xB5B10C2A632D5E15ULL,
		0x9C85E06FB5069C82ULL,
		0xFE159676F78F2BF9ULL,
		0x397BDFFF72ED8948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B97A4BF773A6ECULL,
		0x78BAAA2777E2C266ULL,
		0x8B591D718BA24139ULL,
		0xC6F936782065F55AULL,
		0x9B4C205F35DCA3E8ULL,
		0x00BEEBAA9B00606DULL,
		0x3F6D7F0A678803C9ULL,
		0x3886062CB03EC46CULL
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
		0x65568E731907D6E3ULL,
		0x3F3332E380C24BABULL,
		0x3F923F4359B29E9EULL,
		0xF3C54B92A3907A1EULL,
		0x729092B558042C38ULL,
		0xFF6C8CAD9AD75CE5ULL,
		0x14082DFFD68581DBULL,
		0xB1B6E04F28F06831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B039D331EB6C5BCULL,
		0x2F105FEFBD162EE7ULL,
		0xBE7D1743839E17E4ULL,
		0xE6D0C5D12EF05175ULL,
		0xC4D012EFA24167D2ULL,
		0x9A9A8D05C03B95BDULL,
		0xAE98EBA25DF60CABULL,
		0x98957DC340439B59ULL
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
		0x9029A74EE505304EULL,
		0x16AABE0EB7776FFDULL,
		0xC4AB793B19A2F154ULL,
		0x15EFD9211678CA4DULL,
		0xD2ACC8417D132B8DULL,
		0xB574C4CA4B890303ULL,
		0x1A9392E7D4B7A512ULL,
		0x0975930F80AB21A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB915BBF7C91D8B91ULL,
		0xDBAA1C4A6ABB9543ULL,
		0x98F3453AA9A06ACEULL,
		0xB63C4916E596A108ULL,
		0x572340B0A58D4355ULL,
		0xB961F75E6A71A25FULL,
		0x3D37812196D8B505ULL,
		0xFF6EEC3D81FC818DULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC6CD98EB104DBC83ULL,
		0xF8EE3E784C498D0EULL,
		0x96333124123B0716ULL,
		0x27E62FC45F69717DULL,
		0xC1BC529D7CB24B6CULL,
		0x4F44371F6A568E93ULL,
		0x38A683D3499E5767ULL,
		0x5DC62484C4D95E99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6CD98EB104DBC83ULL,
		0xF8EE3E784C498D0EULL,
		0x96333124123B0716ULL,
		0x27E62FC45F69717DULL,
		0xC1BC529D7CB24B6CULL,
		0x4F44371F6A568E93ULL,
		0x38A683D3499E5767ULL,
		0x5DC62484C4D95E99ULL
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
		0x71F67A98EB40ED7BULL,
		0x2A44CB32082637B3ULL,
		0x24E9110D6EB3F6D1ULL,
		0x47EF9C04C789D611ULL,
		0xC1D80D31922F5AA8ULL,
		0x861A56C35386BC8DULL,
		0xACC663CADBE40EB7ULL,
		0x57C1EF2D18440CB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED2E349D7BB2CBAULL,
		0x8395826F0B45439EULL,
		0xD151BF0829F21799ULL,
		0x7935581435481B83ULL,
		0x0B41E73C5AD9CF1EULL,
		0xFD8D144EFD1235D6ULL,
		0x1786956864A82DBBULL,
		0xC59640729E9B3D5EULL
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
		0xA99D874B0102C8C3ULL,
		0x5B61C545B37035DEULL,
		0x6832EA0B0FDACD56ULL,
		0xBC3EBE9446A923DBULL,
		0xA79C73440D6AB1BCULL,
		0x8EF5FC5408E8A6A7ULL,
		0x8A7D6D2F805E5593ULL,
		0x7C3EF5941AE19D34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE310AE4923CA12B0ULL,
		0x74904347770064D6ULL,
		0x969183D57E4BBD02ULL,
		0x1C2AC85B1763701BULL,
		0x1DDD702340ED44D5ULL,
		0x5D2332E80C1ECC88ULL,
		0x3316AEE17904E947ULL,
		0x20677E1ACFAEEDE9ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x07981C5A9C395B4AULL,
		0xB288A96F5B525F6DULL,
		0x03453E77C6548FF5ULL,
		0x994FF0FD33CA3C14ULL,
		0x28D2BA5ABB4FE893ULL,
		0xC5EC3D0C4BDD1D50ULL,
		0x1079E03ECEA0E4A9ULL,
		0xBFBB0D1AEEEEF631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6522EBA1E8A2DFULL,
		0xA9A320240022DEC4ULL,
		0x5DBC1058A515CC96ULL,
		0x8DE99F74BB93EEF0ULL,
		0xCEFD675D10F3A586ULL,
		0x82B3346ADBA8185BULL,
		0xD21F6E54D881A443ULL,
		0xA3F2B53803597A89ULL
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
		0x189256A1221AF06CULL,
		0xC3934775E34D3505ULL,
		0xE8E4EACF37CCE4C2ULL,
		0xFC4627EDB179B8F6ULL,
		0x184615E12803BC9CULL,
		0xA8F846688EDE9A9CULL,
		0xA77A490AB54A9662ULL,
		0x37C86762D45A4982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189256A1221AF06CULL,
		0xC3934775E34D3505ULL,
		0xE8E4EACF37CCE4C2ULL,
		0xFC4627EDB179B8F6ULL,
		0x184615E12803BC9CULL,
		0xA8F846688EDE9A9CULL,
		0xA77A490AB54A9662ULL,
		0x37C86762D45A4982ULL
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
		0x17FFC9A61DA2FE9EULL,
		0xF22DC8780ED00107ULL,
		0xF9AB8AEEBF276335ULL,
		0x524EC6DFCF30976BULL,
		0xC7331E21A4BD41B6ULL,
		0x9F95BE0F2FB0D381ULL,
		0xED9FE0C90F884F54ULL,
		0x52A75D04861F07F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124B8FF8A94AF003ULL,
		0x9E8DA83767F5A96FULL,
		0x46EC49C679D96155ULL,
		0xF9782B847A754850ULL,
		0x03447F78886BA3CBULL,
		0x318063257A32AD7FULL,
		0xAC75E6455FEED621ULL,
		0xB4723FB262B7B2D6ULL
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
		0x214BE16634731C87ULL,
		0x130A7C142CDDF468ULL,
		0xDF6FF943DF4B7FB4ULL,
		0x7167C3BFA32EB9AAULL,
		0x53CF03D5F6D0C2E4ULL,
		0x810821580EDFB112ULL,
		0xCF29DA2F0029D26EULL,
		0x2C34B779A27395F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA22FF2401C49DAULL,
		0xDE4478ADEC68D802ULL,
		0x0C162EF4B5D5E9F1ULL,
		0x240DEB8972D84EEBULL,
		0x92911A6E5BEAEB77ULL,
		0x95F2D076712AF8ABULL,
		0x810D2E003847DD06ULL,
		0xF96D55357C057340ULL
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
		0x1CC63F938632E402ULL,
		0xEC45D8804F606247ULL,
		0x1B510137A83EE309ULL,
		0x4F9C9C82D61BB095ULL,
		0xEFC7B6B042026A1DULL,
		0xBDAE82C103385D50ULL,
		0xFDD4D9E6E4CA7F09ULL,
		0xB04EDFFB48BD3583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FD55E883E4A286ULL,
		0xB9070558774577C8ULL,
		0x43715EB53C2D45ECULL,
		0x69E53D7B084635E2ULL,
		0x8E337E5E2035CA24ULL,
		0x44365F3CEEB2C882ULL,
		0xA073551012D951A3ULL,
		0x7B7B65C2A4E5FE49ULL
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
		0x9073E60F6855C03AULL,
		0x441412031665B03CULL,
		0x0599D15B9C5D8459ULL,
		0x7163E4FC253AE07AULL,
		0x5BD428EA2F2207BEULL,
		0x1BFAED133FE09E8EULL,
		0xBCC3EEDE136DC7F6ULL,
		0x538A96DEA6DAD395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9073E60F6855C03AULL,
		0x441412031665B03CULL,
		0x0599D15B9C5D8459ULL,
		0x7163E4FC253AE07AULL,
		0x5BD428EA2F2207BEULL,
		0x1BFAED133FE09E8EULL,
		0xBCC3EEDE136DC7F6ULL,
		0x538A96DEA6DAD395ULL
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
		0x6B51DB6CD75F6BF9ULL,
		0xAE13540604D84D15ULL,
		0x862D7D52C4027CA0ULL,
		0x6426842729E8ADE1ULL,
		0x06EEA7E4393A5052ULL,
		0xE5BF52A7CD426837ULL,
		0x86B1717A84D9157FULL,
		0x8D4E23F8C873F00BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF232EB845887237ULL,
		0xA39777E7C5090EC1ULL,
		0xB81619BC888A25D6ULL,
		0x2337184FD6066B2EULL,
		0x772F0FB5CB82A21FULL,
		0x71861AC99BFC6431ULL,
		0x4543E434F9F40EC8ULL,
		0x1DB495B9EA42B358ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9767BA87AF154352ULL,
		0x0CE1486564CD2AEBULL,
		0x89A822C62EC7F63BULL,
		0xF3D1AFEA24744B62ULL,
		0xC754A0724BF2D562ULL,
		0xB4B80149ADAFB294ULL,
		0x879FA130941CAFDCULL,
		0x8DAF62962E5FE4A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022BE7A82EA661AAULL,
		0x08E6F7C39226663AULL,
		0x16F44F0D306E2C29ULL,
		0xD1BDFAC67D2D01E6ULL,
		0x1F3276F0929BC670ULL,
		0xA17964B4EC3A193DULL,
		0xC94091721E644CB4ULL,
		0xA727E7343E9CB6CFULL
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
		0xC54F809EEB088580ULL,
		0x66731CF21EA8BD41ULL,
		0xEFA105D976011545ULL,
		0xC61235A920F4B817ULL,
		0x6C43468BD676E41EULL,
		0xB977B6B2D8EFD4AEULL,
		0x719B9D80E678C45EULL,
		0xD4EA914C7462A588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9769CF1FA9CA2A60ULL,
		0x42B63D4C855959B3ULL,
		0x600B37E55E2B96A8ULL,
		0x7E8B88299CA78100ULL,
		0x4EC80278F06F25A1ULL,
		0x94073847E5E3866AULL,
		0x3A18073C1374A2ADULL,
		0x918FE294D5F40FD6ULL
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
		0x8F9F18E627F86765ULL,
		0xB017144D5D7F8A11ULL,
		0xC6AE9498BF37BEEEULL,
		0x87258082A049245FULL,
		0x603735729A29C315ULL,
		0xD64AE6C96F3EE35BULL,
		0x920941FF71F9423CULL,
		0xC371903B0085444BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F9F18E627F86765ULL,
		0xB017144D5D7F8A11ULL,
		0xC6AE9498BF37BEEEULL,
		0x87258082A049245FULL,
		0x603735729A29C315ULL,
		0xD64AE6C96F3EE35BULL,
		0x920941FF71F9423CULL,
		0xC371903B0085444BULL
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
		0xB36F197E86C05959ULL,
		0x3A387ACA9E084004ULL,
		0xDA67A5CE10E609FCULL,
		0x69FB00BA34BEDC3FULL,
		0xDBC7E712AE1613D0ULL,
		0x3A0E19C9C458EC15ULL,
		0xAD7036719600BA85ULL,
		0xAF5B1E2A63F4B0DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD58AE46B8B0B2D60ULL,
		0x1F6A8B71FC958139ULL,
		0xD9BF1927EC6302E1ULL,
		0x04D13C9875B8375BULL,
		0xA06446F0EE4391C1ULL,
		0x4B4A3B193FB55CFEULL,
		0xCEF90BC77B637E2DULL,
		0x972E09782C12CC23ULL
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
		0x003CCD76E1A86F04ULL,
		0xDCD6925AD7AC579EULL,
		0xABABC11612935700ULL,
		0x3CB37EBB72744FA9ULL,
		0xB410641340BB59EDULL,
		0xC44BE9F9C53FE019ULL,
		0xE69466FBFB0EF6C3ULL,
		0x78F93714B627A753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F865EC193F927DULL,
		0x998EAB958D059182ULL,
		0xF8ADB079E8E88590ULL,
		0x34B1FBC4B9AC74FCULL,
		0x4BB6B24A5C5317A6ULL,
		0x9F96B7BFD051F6B9ULL,
		0x8CDDA758670ECFEAULL,
		0x2D2C899673189BD2ULL
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
		0x2C5C399D5166EF87ULL,
		0x47CAEF732335B6A8ULL,
		0x94AFDB2B426512F3ULL,
		0x738AEF3C29A1D620ULL,
		0x0F789D65AF7BCA01ULL,
		0x5179AF3646B80AAFULL,
		0xE128942AC116D515ULL,
		0x8D8DA3B45080E063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76F0CDE4C4D81E7ULL,
		0x708395F36C5C688EULL,
		0x1D60115EE8B65FB5ULL,
		0xE205D3EC166D64C6ULL,
		0x7D34C9FA307FD495ULL,
		0x71146A295C640C0CULL,
		0xCF378C9FE7C5B64BULL,
		0x36E47CF96AA1A073ULL
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
		0xCA13EAC638AFDE87ULL,
		0x957AC1E6982D709DULL,
		0xB7DF018AE7212020ULL,
		0xCBE676AB6DFD19B4ULL,
		0x7B45485F4287E63BULL,
		0x368912D0110CA6E6ULL,
		0x35510CEA06F44EB3ULL,
		0xF5EB8C57253C7A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA13EAC638AFDE87ULL,
		0x957AC1E6982D709DULL,
		0xB7DF018AE7212020ULL,
		0xCBE676AB6DFD19B4ULL,
		0x7B45485F4287E63BULL,
		0x368912D0110CA6E6ULL,
		0x35510CEA06F44EB3ULL,
		0xF5EB8C57253C7A3EULL
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
		0x1FE3513639B39873ULL,
		0xCC703E23D2CE096AULL,
		0x280262F079A85727ULL,
		0x396EA15E81E49947ULL,
		0xAEC543D842373267ULL,
		0xBA6CCCD0238A7A37ULL,
		0x215ADD58F549D594ULL,
		0xA7C0B6B3A968237BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90C8BA0EBA4A791FULL,
		0x9FA93510BAE59813ULL,
		0xB21DAE808503D7F1ULL,
		0x177A14B01044329AULL,
		0x74D0AAB16C8A32DAULL,
		0xFFB51B8625F116A7ULL,
		0x35433F257986B32AULL,
		0xB804F52D55CFE241ULL
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
		0x29700E2CC190C536ULL,
		0xF9802F2A1B781FBFULL,
		0xD3E2B33763D1D51EULL,
		0x0A7BFD7A6AAF8DFEULL,
		0x7A2D30B8543ABB5BULL,
		0x6AE566184802DE75ULL,
		0xFAE3BC80693E26D6ULL,
		0x35A915ED1D564BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2D6F07C93AE35AFULL,
		0x5EAE2127202498ADULL,
		0xF733760060B272A1ULL,
		0x730A17C443B7C7A1ULL,
		0x034B764B0E176A97ULL,
		0x265E20BBDA669019ULL,
		0xEC99B1B977E6239BULL,
		0xC5A53E72534640F7ULL
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
		0x26B578F92B59707CULL,
		0xB232D866A1E0D3DFULL,
		0xAA90B302F50E5160ULL,
		0xD0B92574BFE38C91ULL,
		0x29D23A809E727836ULL,
		0x8F9E4F28DBC01AA7ULL,
		0x5554AD37106C1609ULL,
		0xB754503431F7E5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8A2E9B4E7B2514ULL,
		0xD66D08AA23A2FC7EULL,
		0x0489C90EFADB52A7ULL,
		0x6BAC89FDFC31E42FULL,
		0x589A83BE978737A8ULL,
		0x0125DE176FAF64F4ULL,
		0xBF8D2C802FA59FDDULL,
		0x8D565016661F3931ULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA38423D2B8ADCC7DULL,
		0xCCF5B761B7B6E549ULL,
		0xB90D3F66A8368F96ULL,
		0x3BBEA0C7535A0342ULL,
		0x6547AB1B329799C7ULL,
		0xD4F292CA8DCA8175ULL,
		0x4B73B8556FF94DAAULL,
		0x41A67C7F30B5CDC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA38423D2B8ADCC7DULL,
		0xCCF5B761B7B6E549ULL,
		0xB90D3F66A8368F96ULL,
		0x3BBEA0C7535A0342ULL,
		0x6547AB1B329799C7ULL,
		0xD4F292CA8DCA8175ULL,
		0x4B73B8556FF94DAAULL,
		0x41A67C7F30B5CDC8ULL
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
		0x45F9073E09075306ULL,
		0x5CFA17E2F4233537ULL,
		0xFDB3977892B3797BULL,
		0x776A1FE3C0D7D77FULL,
		0x9B03543D1902664AULL,
		0xACCB7CF9EB66B798ULL,
		0x96C4459BAD532A47ULL,
		0x84CA58FA21DA589FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CDDC1EC61E60DF8ULL,
		0x71CF1258DACB665FULL,
		0x94DAE7C42197CC7DULL,
		0xE884E57835558CAEULL,
		0x0A42DA40978E5B69ULL,
		0xA5D572050ED942EAULL,
		0x01A5BB4B86399FB8ULL,
		0x6B21D14092C8102CULL
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
		0x8F5008826A5CD4FEULL,
		0x66DF17218E2EB6A7ULL,
		0x64EB9837DDBF3FD4ULL,
		0x3C729E813471E075ULL,
		0x76E232BE07CBC411ULL,
		0xE880E1FC9D34FB0AULL,
		0x0F0AA20BDD52F1FDULL,
		0x2086971A0E8A230BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499F8EB812DBCB08ULL,
		0x7B4DCB172FC89883ULL,
		0xF7486FB884216397ULL,
		0xC43E72FEEEED70BFULL,
		0xD7E09AB6A67FAB67ULL,
		0x9F9021E7243B0CD1ULL,
		0x624ED08A43AFE905ULL,
		0x7232DF2446E31EE7ULL
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
		0xA033CCB182435DFBULL,
		0x9AEDA3FAD0290425ULL,
		0x5D8F632860B8953EULL,
		0x0DB0FFF9611B035EULL,
		0xA3408AF53D0FA54DULL,
		0xC555C17BDFD54DE7ULL,
		0x5A794EF522AE34BEULL,
		0x369518E26C335659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC2588DD01BAB324ULL,
		0xF702ECEDB2937B06ULL,
		0xD38E743ECDD3DE40ULL,
		0x76ABFF6E9A1ED884ULL,
		0x2F9CF8FAB21A174DULL,
		0x329429BEFCC21AFBULL,
		0xD7638C39FDF216D2ULL,
		0x153B0EB58F184508ULL
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
		0x94F3F4CD5D94C54EULL,
		0xEC76F7EE9F825E1AULL,
		0x4334FDF4CA1382B3ULL,
		0x64FC8ACB80A89FBFULL,
		0x1BBF651219B89F96ULL,
		0xA821082BE1EA9D61ULL,
		0xE172A8BF25DC3AA5ULL,
		0x5C1A366CCBCA2E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F3F4CD5D94C54EULL,
		0xEC76F7EE9F825E1AULL,
		0x4334FDF4CA1382B3ULL,
		0x64FC8ACB80A89FBFULL,
		0x1BBF651219B89F96ULL,
		0xA821082BE1EA9D61ULL,
		0xE172A8BF25DC3AA5ULL,
		0x5C1A366CCBCA2E46ULL
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
		0xEB613123448CBE63ULL,
		0xE8A9CD6047556833ULL,
		0x42E466B7B996EE22ULL,
		0x75FF91742A4065B7ULL,
		0x617A8A32AB72DA87ULL,
		0x0701BBF827B8B0E8ULL,
		0x38AF2BA38721BD57ULL,
		0x6C743EC03125503FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C8370885F91ADCULL,
		0x31D8A081FFC32E9CULL,
		0xA0945D389270F650ULL,
		0x3EEC4E9E24497CA4ULL,
		0x31CEDE64538A4874ULL,
		0xD43AAC2E52CA5BB9ULL,
		0xC53AE4F2FB5B30B4ULL,
		0x4248821788FC9D60ULL
	}};
	t = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB2D99855F919339DULL,
		0x24BAB0C64B987763ULL,
		0xD781D229EE8FD506ULL,
		0xE4686ABF14EBF55CULL,
		0xC7E6F8A0B1A21A2BULL,
		0xA7BCFA0E0B27FCDFULL,
		0x31C0A647E306BFD4ULL,
		0x8C23E71416738564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A564FC695A43ACULL,
		0xD600F34000F51D1DULL,
		0x56CC922591D517B4ULL,
		0xEDF2BA2A1D9004A7ULL,
		0x5FCA879E7147B7D4ULL,
		0xE226251D4CA9BE69ULL,
		0x895F72D743BB27B6ULL,
		0x762AF541EF8AE448ULL
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
		0x28246EBA942378C9ULL,
		0x68BB96053A4B8C1DULL,
		0xB98E2C15A1A3EC31ULL,
		0x2FF4555833D342D0ULL,
		0xFBFE44F23DADDD5EULL,
		0xA82BAE2706BA3D13ULL,
		0xC9F969AC5249A4CEULL,
		0x72DF56FB2E6BA9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x590D7AC208B2192BULL,
		0x8F3B386470A456E2ULL,
		0x09C210847C11AB1BULL,
		0x4595F2D072170386ULL,
		0x63BC2850DA194D9CULL,
		0xA206548C5478E375ULL,
		0xE341009C1B1D42FFULL,
		0x642F5EC18F539DA1ULL
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
		0x58639D695668F96CULL,
		0x644542407829B883ULL,
		0x99E4B4D0AA6A8324ULL,
		0x510A2F1D18A8DA5FULL,
		0x80A020E9835884CBULL,
		0x00F2D4D279F104C1ULL,
		0x28058F96BBE0BE8AULL,
		0xAA67050C9905A0EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58639D695668F96CULL,
		0x644542407829B883ULL,
		0x99E4B4D0AA6A8324ULL,
		0x510A2F1D18A8DA5FULL,
		0x80A020E9835884CBULL,
		0x00F2D4D279F104C1ULL,
		0x28058F96BBE0BE8AULL,
		0xAA67050C9905A0EDULL
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
		0xB7B1133ABEB84A34ULL,
		0x6A337F5672A7ED69ULL,
		0x1A416062A9FF56B5ULL,
		0x23B355E8DE2B4494ULL,
		0x67E6E47797B1305EULL,
		0x0A8B0712E89E55A7ULL,
		0x7E10226E0A655B64ULL,
		0x3A38ACE585D0538BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ED0DAF17D5E24B1ULL,
		0x44ED9589366E9707ULL,
		0xF5BFB2E122E56879ULL,
		0xD6157155C95FBED5ULL,
		0x3B6A01A80B3C84FFULL,
		0x4BA014F49F314BCEULL,
		0x632D538509E2789DULL,
		0x083EEE20B7F2D641ULL
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
		0x0A0420479BAB55E2ULL,
		0xBB2F9A70008DC5F6ULL,
		0x030363B081F818D2ULL,
		0x53A7885B89B69D71ULL,
		0x674DEA5BAD8B2AB7ULL,
		0xAFA118797FF9A8D7ULL,
		0xDD2E9CA443177EB8ULL,
		0xCCDFD54A65C6C628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BBACF47A6C02D34ULL,
		0xD906C560C4FA2A07ULL,
		0x4016C27B84EB25B6ULL,
		0x6FA70B9529052573ULL,
		0x156BDA1A95598F86ULL,
		0x0EBBE3CC67D32E87ULL,
		0xB5F2A5B6D11FAB60ULL,
		0xC744C9BF309BB3CFULL
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
		0x1E87C45DCFCC6E30ULL,
		0x705CBCBA78558E17ULL,
		0x86EA410239034069ULL,
		0x938A12C3F861EE93ULL,
		0x0C647118C3769735ULL,
		0x69949D1C54F47D1DULL,
		0x0FD59ACEEC9C0B58ULL,
		0x7C4AAF606626D440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC75080BFC70151E2ULL,
		0xC7657DB6B60277CFULL,
		0x417D22CF2B274A33ULL,
		0x4D683822F4D6646CULL,
		0x0D2BD2123AD9C330ULL,
		0x21751D7551321368ULL,
		0xE66FC85CED3146A7ULL,
		0x2E5E0BC82D5F8A7BULL
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
		0x2ADFD1CBF0261F5AULL,
		0x61217448A17126A3ULL,
		0x1628386E4206BF50ULL,
		0x45E4EADFF201F95CULL,
		0x5D98B9D84A3802EBULL,
		0xFFB14DB8CF2329C8ULL,
		0xC7D4D664ADF24BF4ULL,
		0x4B2CF3F8A2225656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ADFD1CBF0261F5AULL,
		0x61217448A17126A3ULL,
		0x1628386E4206BF50ULL,
		0x45E4EADFF201F95CULL,
		0x5D98B9D84A3802EBULL,
		0xFFB14DB8CF2329C8ULL,
		0xC7D4D664ADF24BF4ULL,
		0x4B2CF3F8A2225656ULL
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
		0x4506A159E0C83003ULL,
		0x2D8EC604C93FEE5FULL,
		0xBE5B7249431BB6C8ULL,
		0x7487C7A5F076A76AULL,
		0x00EAE85C5089DCDFULL,
		0xA63967BEA72F3E4BULL,
		0x51503558CA138EE8ULL,
		0xA88BDF008C523F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD43F6CC48EF89375ULL,
		0x3E2D43EA10B9EB45ULL,
		0xE04D94E066FFD0D4ULL,
		0xE0E52A90A4AC12E0ULL,
		0x40F2AED4FF83F93DULL,
		0xE0E522F5510561A2ULL,
		0x48644EB76B4025DAULL,
		0x4AC0E371A618E807ULL
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
		0xBA40389B385A8B16ULL,
		0xF09A83FBC43AE2BEULL,
		0x1E7578D0268B6BF1ULL,
		0x4B7E7A5F497C8849ULL,
		0x76756EE607945A00ULL,
		0x261D4DAF2CD3093CULL,
		0xDF130DF3E1E1B982ULL,
		0xF1AA511066B8C9ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC26BD9D3A756FEULL,
		0x4D5F44ACCCA80666ULL,
		0x40D17192F5777B95ULL,
		0x60EEDC42EBA4F865ULL,
		0xF4514FD74E3042E5ULL,
		0x892E7FF95B0370C1ULL,
		0x10C76DF26C9DB0E1ULL,
		0xF4268D4B7D85B6C7ULL
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
		0x3DD619C5436FD955ULL,
		0x25C6E5B41D3705E7ULL,
		0xEDDED28CCE776B69ULL,
		0x5FE508224DFE9BA0ULL,
		0xA7E594BD5A5194E3ULL,
		0x1BBA3F685AE1A7ABULL,
		0x918D1608663760D5ULL,
		0xAAB20892326859AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556AB66F29EC1C23ULL,
		0xD4D59CEE38B4CE26ULL,
		0x2733D136561BCA01ULL,
		0xD752D3A1BC80522DULL,
		0x95072A9206A27372ULL,
		0x9409812AE3B02DCCULL,
		0xAC1D42585AD2FF7FULL,
		0x1BA98287BE22BC47ULL
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
		0x4B112A976A00BD8DULL,
		0xFB8950E2D6C029CDULL,
		0xC9F3B9FFCB77F7E0ULL,
		0xAF99379A587E7126ULL,
		0x5A27B6219F48F161ULL,
		0x1C44918B494B1767ULL,
		0x0408D49970A9ED16ULL,
		0x9FE9E2D099ADCA5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B112A976A00BD8DULL,
		0xFB8950E2D6C029CDULL,
		0xC9F3B9FFCB77F7E0ULL,
		0xAF99379A587E7126ULL,
		0x5A27B6219F48F161ULL,
		0x1C44918B494B1767ULL,
		0x0408D49970A9ED16ULL,
		0x9FE9E2D099ADCA5FULL
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
		0xA6D821DE7B661789ULL,
		0xD3BEB0FF6001949BULL,
		0x7858150FEAE42DF5ULL,
		0x41034010B1C41CB4ULL,
		0x772079F9A9FD86C4ULL,
		0xF4BA1A9E94B2C622ULL,
		0x827DF5E62F795C2CULL,
		0x97AB65BEFC0FFD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FF649FAF0D4B5DULL,
		0x17FD4A479F57998DULL,
		0x208778BBB1153682ULL,
		0x2B416C365527B5D3ULL,
		0x90A3506077567472ULL,
		0x00F765A802E7A6D5ULL,
		0x0040E1648329E7DFULL,
		0x3541CBD57B9BA64EULL
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
		0x4F071833FA9E1100ULL,
		0x49B9AEE24E3D04EEULL,
		0x2737236989B53577ULL,
		0xBA4145F9508525C6ULL,
		0x58C2B5FBA2642264ULL,
		0x6847BA48792675FEULL,
		0x8219BE7C50F073FBULL,
		0xDDC54792EC185F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB8DCB39299A7EF7ULL,
		0xE54447A21E0C204DULL,
		0xDA43C52BA343BCE8ULL,
		0x6A63C87EC075A05FULL,
		0xF4FE92C413291320ULL,
		0xDB34238BF3C3E566ULL,
		0xFB1799C873EB8913ULL,
		0x07FCC7D14AED6123ULL
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
		0x8AD4291B42136696ULL,
		0x84530B36C3E91734ULL,
		0x3276F1CB3476B6D1ULL,
		0x66999560D2CBE2E1ULL,
		0xB9CC765A56B3F5E0ULL,
		0x03DF5A9CFEA56707ULL,
		0x2353F1209F593D83ULL,
		0x2943F16AFBB73876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x617E2257B3D9A43EULL,
		0x0CAAAD25199B83FBULL,
		0x3C04207399F5EC2FULL,
		0xDC54E4F7C8939C96ULL,
		0x7C43AE9D842C1ACBULL,
		0x774DC8B0C2777311ULL,
		0x13DB04A373A9B397ULL,
		0x60D99C1592974354ULL
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
		0xB69C984951337B29ULL,
		0x10C19A998F43E39CULL,
		0xEAB5A3AA5BD64B7DULL,
		0xB7AED405160464BCULL,
		0xD332ECAE2A710251ULL,
		0x1BFE246B35EF31BEULL,
		0x64C789AF3F575CE1ULL,
		0x86848162ACBDA84EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB69C984951337B29ULL,
		0x10C19A998F43E39CULL,
		0xEAB5A3AA5BD64B7DULL,
		0xB7AED405160464BCULL,
		0xD332ECAE2A710251ULL,
		0x1BFE246B35EF31BEULL,
		0x64C789AF3F575CE1ULL,
		0x86848162ACBDA84EULL
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
		0xAA5B8F6860C96678ULL,
		0x7E2D7C87D962BD05ULL,
		0x084B98D66EE95048ULL,
		0xA4A654BF7DFEBB4EULL,
		0x9D9A9D97F84DCC7FULL,
		0x377051EB378294D8ULL,
		0xEAC20777E0520B37ULL,
		0x677A1219F787FC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4306C354AFFC51E3ULL,
		0xD4090AC138AD14D3ULL,
		0x8E2D4D7AFA0EDB6CULL,
		0xF0DD1587C87CBD23ULL,
		0xBF5DB2B8026B373FULL,
		0xCD96DC51BCA9F3BDULL,
		0x45E66F6CC05C4270ULL,
		0xEDA0CFB8FA93404BULL
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
		0xD655A9CB11586373ULL,
		0xC6025C8134892682ULL,
		0x0C5AE53E73BDEEA3ULL,
		0xD7D4907DAC65BA64ULL,
		0xA20E77737645F24DULL,
		0xD8453111EEEAD2E9ULL,
		0xB9D8B8436DFB333FULL,
		0x79437434FBB4DBF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FBA3A450801CF75ULL,
		0x4601D01998FCB6E1ULL,
		0x5020C8C6D1FAC8E7ULL,
		0xF9E8E03325850EF9ULL,
		0x5B34D2496CA2BB80ULL,
		0x1D6A4ECAC716F36EULL,
		0x6E2EDD418CE66D56ULL,
		0xFFEFDF15DE8DBDA1ULL
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
		0xBD1CAA90598D049FULL,
		0x27371E286B1E4A35ULL,
		0x2AB324A48993CA64ULL,
		0x962EFD06725998D3ULL,
		0xDF9526B323DA745DULL,
		0x5F1F53EC3366D993ULL,
		0x955CA98D0197AFD9ULL,
		0xFBD4977A3F74701CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA054D59E6A86C2ULL,
		0xE173F38BFB54C5A0ULL,
		0x9BCB8E0BBB3F381AULL,
		0x1328DA3AEF04F464ULL,
		0xF59C60C0AADA85A4ULL,
		0xDB77E366BC437655ULL,
		0x4B1F9457BABB65EDULL,
		0xB49448850BFC2DFBULL
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
		0x5151C6201FA30BACULL,
		0x10B8E01A1287EFD0ULL,
		0xDBAB03A83C439E3EULL,
		0xE5406F7A846F5D2FULL,
		0x91074C91B504D8A4ULL,
		0x1E1E70E61C7065AFULL,
		0xBEBDEF3108DB51F3ULL,
		0x5430F201AA77DDEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5151C6201FA30BACULL,
		0x10B8E01A1287EFD0ULL,
		0xDBAB03A83C439E3EULL,
		0xE5406F7A846F5D2FULL,
		0x91074C91B504D8A4ULL,
		0x1E1E70E61C7065AFULL,
		0xBEBDEF3108DB51F3ULL,
		0x5430F201AA77DDEFULL
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
		0x4364AC8EAC50AF3DULL,
		0xECAF4CEA6EEA9684ULL,
		0x2074C827DDDFB602ULL,
		0xE397243477C6E8AFULL,
		0x25B5AA86783D7860ULL,
		0x460384CCC96988EAULL,
		0xB4B8B9BF6545680DULL,
		0x6E857B02F3FD01EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63ED0F4D67A290EAULL,
		0xECD164FE7D0A4B55ULL,
		0xA81F3933C55D6B29ULL,
		0x03D56A65DFD6FCDDULL,
		0x238EB76328893C3CULL,
		0xBF88CB8B96ADC6FDULL,
		0xF16619B3CFF63194ULL,
		0x053711900E90F1ECULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBA9D9BAF12F0463BULL,
		0xD7465F2A9E63679FULL,
		0xF5414BBF00E72DDCULL,
		0x6056375B76D8F7F6ULL,
		0x57E565CB3CA57600ULL,
		0xD0EA1BDA273DEEC3ULL,
		0x6FA244136CC3CB59ULL,
		0x406D21A7C08FDBA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBC425A4FE35F8E0ULL,
		0x063B8A6359EC0394ULL,
		0x07E12A7776743B2EULL,
		0xE899E167CF63BBC5ULL,
		0x6DFE739A72EFFAC6ULL,
		0x00B2238BF367D124ULL,
		0x80B6864CDD4E8AFEULL,
		0x502BD734C1B9512BULL
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
		0x592891574FF870E2ULL,
		0xBBA28AA651B6751BULL,
		0x123D089A71261BBFULL,
		0x6DCBB3B501C8A2D4ULL,
		0xEE383F41AB9C8DA2ULL,
		0xBF15C0EAB9300535ULL,
		0x10AAC7E68BC94460ULL,
		0xC50FBEC8F19F99D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA154E6A4270529ECULL,
		0x163E09489CB53D3FULL,
		0xFB9ABA4079413581ULL,
		0xB8E561B1DF4D89A8ULL,
		0x14FEA7CC43C88320ULL,
		0x7FEA82720AE33A38ULL,
		0x118E3545FC2BB5C4ULL,
		0x79B3D3EA3E674A86ULL
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
		0x17C399B560658F35ULL,
		0x147E24AF4F180B25ULL,
		0xE86DDCEC1A4A5AFEULL,
		0x7D3DC9B00CDC063FULL,
		0x9699FD5A3882AADFULL,
		0x786ED800B9B33C4DULL,
		0xD7AB188BB42FD611ULL,
		0x6297DBF8AF6D7853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17C399B560658F35ULL,
		0x147E24AF4F180B25ULL,
		0xE86DDCEC1A4A5AFEULL,
		0x7D3DC9B00CDC063FULL,
		0x9699FD5A3882AADFULL,
		0x786ED800B9B33C4DULL,
		0xD7AB188BB42FD611ULL,
		0x6297DBF8AF6D7853ULL
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
		0xDCA4F4C13932B2F2ULL,
		0x9102C30548820829ULL,
		0xAC6333305B512CCDULL,
		0x7107A11558BB380EULL,
		0x4430E3B9AA219799ULL,
		0x2307C32F3101AFC6ULL,
		0x4F84CA2C165C7B09ULL,
		0x1DBED6AA05B959B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E77608173C6650ULL,
		0x7C59327CB81892FFULL,
		0xCF176CDC1EAFDBB8ULL,
		0xFF9A16D5F9041D01ULL,
		0x2541BD1CDB8E73E9ULL,
		0x1CAE2DFD521C1746ULL,
		0x62C414BFFEFF2245ULL,
		0x5BBF7BC2BDA8A884ULL
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
		0xB2F9122913F631EAULL,
		0x984997A8D45B1161ULL,
		0x2D4555F387EAD092ULL,
		0x3CB6D30C9A69A441ULL,
		0xB76C4EE749B483C5ULL,
		0xEDA6E191C58B015EULL,
		0xE336BF7AB7219D32ULL,
		0x5A0BC71F39C62FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAA148A1880DE76EULL,
		0x90610A14F1641989ULL,
		0x6AA3DC1173794FBFULL,
		0x3C1C322698B90BE0ULL,
		0x8F6CD06E92F99507ULL,
		0xE65E663375412915ULL,
		0xDC5D8DBFFB971656ULL,
		0x0763F20ACF297781ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x8A3E116C99C78094ULL,
		0xA992D7BAA6F206A2ULL,
		0xD87E0429DB0027C1ULL,
		0xAEDC6B097EBF7FD1ULL,
		0xC2CDCACB1CE4F8CDULL,
		0xFB47EA0AC40B016FULL,
		0x39456E4680BC5ACDULL,
		0xCC130C9C539DE0DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFBE45A9D7FC25EBULL,
		0xBDCA1ECA1988FA55ULL,
		0x699B7CEDC7853E31ULL,
		0x38E5ADEF8058FACFULL,
		0xB5194041651A0E72ULL,
		0xEEB09EE469DFC269ULL,
		0xF29FBDF57F3E3A06ULL,
		0x698BF987D8ED95CFULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7B431C835A9FDE3AULL,
		0x4DC648F4C0A94FFAULL,
		0x85519071423FFC16ULL,
		0xDD99416F9411B68CULL,
		0xC76EC47AAD9155E3ULL,
		0xF3B4188CF9482A93ULL,
		0x79850A264CB82861ULL,
		0xF755A250D13D6237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B431C835A9FDE3AULL,
		0x4DC648F4C0A94FFAULL,
		0x85519071423FFC16ULL,
		0xDD99416F9411B68CULL,
		0xC76EC47AAD9155E3ULL,
		0xF3B4188CF9482A93ULL,
		0x79850A264CB82861ULL,
		0xF755A250D13D6237ULL
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
		0xB6AE50968C1C2F81ULL,
		0xF6F23607422B9E27ULL,
		0x43C8C8994CF56C8CULL,
		0x30BBD7E5598B28C4ULL,
		0xBB2226B92F35CF1FULL,
		0x334F2AFF65805F01ULL,
		0xD621F2049C2B85A6ULL,
		0xB8D12994FD0DED4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC89143425DA7D48ULL,
		0x472386057030F257ULL,
		0xAF3576A989622AA2ULL,
		0xA312AF8C83B16A08ULL,
		0xF215E0D59E9FC955ULL,
		0x6F4B41D2EF874AB4ULL,
		0xAECC5BC6C9A0EA56ULL,
		0x95CFD95CF426A1DAULL
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
		0x82EC0A581CDFAB02ULL,
		0x29EBFA02F4E7DC73ULL,
		0x9AF2D2C5C3216E86ULL,
		0x51A196238179DA6CULL,
		0x4E5EF73880F250C1ULL,
		0x2F8908C449B2F8F2ULL,
		0x7DA1894252A9F444ULL,
		0xA72A1F5642E6B737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936BFDF40DFDE7EBULL,
		0x64067D1F437FF876ULL,
		0xF38D775E246DEFD7ULL,
		0x481CC52D10AAD3C0ULL,
		0x0E4901A05E4B1C96ULL,
		0xBBD280C34CC321FBULL,
		0xB3DA53ACA4F7FF72ULL,
		0x8C4E63B8A376A9CAULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCCCAE3A105860C9DULL,
		0xBF9EA8823097418EULL,
		0x4274E33956FE9527ULL,
		0xA41CC0000AB0DE8AULL,
		0x61AF519802EBDEFDULL,
		0x4980BCA1355CEBFFULL,
		0xD9C600376468FC5AULL,
		0x26010ACCBF34726EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF640489838121D0ULL,
		0x67E163AD1F99A6F6ULL,
		0xF7BDEA91A535A69EULL,
		0xD928317CD7436B8EULL,
		0x394BAEA91E2F60B3ULL,
		0xAE3F13588BCC8096ULL,
		0x352A099197F66ED9ULL,
		0x92893837CE45F877ULL
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
		0x59685949C4E2F4C1ULL,
		0x26D8E5C6F5C5AABCULL,
		0x9D4447C3204AEE26ULL,
		0x851F27C9C44CA051ULL,
		0x8EAC30EC561C818FULL,
		0xF056AE6601E483DBULL,
		0x32E2FFDE0C5321A4ULL,
		0x1B8B5B9E8FEEBC07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59685949C4E2F4C1ULL,
		0x26D8E5C6F5C5AABCULL,
		0x9D4447C3204AEE26ULL,
		0x851F27C9C44CA051ULL,
		0x8EAC30EC561C818FULL,
		0xF056AE6601E483DBULL,
		0x32E2FFDE0C5321A4ULL,
		0x1B8B5B9E8FEEBC07ULL
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
		0x67A5552BFE0661B6ULL,
		0x6F88671F99F055C4ULL,
		0xDE8B3251D0C94321ULL,
		0x06B28DD71F883CABULL,
		0x772C806F368CF925ULL,
		0x0692C38F3DEFF199ULL,
		0xE6DCFDDFADE6B0B6ULL,
		0x481229A41D88EAD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F5F24F2B84350DEULL,
		0x289B004622C4266AULL,
		0x6847FEF26389C6B9ULL,
		0x2F6C408491D412C4ULL,
		0x76429D0C5D9505B0ULL,
		0x746F1BC8DA83EFEDULL,
		0x19580D09D63E35C7ULL,
		0xA1EE3EC0675B338AULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC8C9C1571EDD3572ULL,
		0xE55D8CE7A7B7F986ULL,
		0x233F2A3926545A22ULL,
		0x577B22E340623D35ULL,
		0x080E3E7F85CF1878ULL,
		0x7406A5086807019CULL,
		0x1B51EB752D6096AFULL,
		0x3969CB3186574A90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD110221EA5CBF07BULL,
		0x14C3EC8B55F8B777ULL,
		0xFA091D5CA27271F1ULL,
		0x396DE0AD55D5D32EULL,
		0xFE616096C8E085AEULL,
		0xCB3E48D8CC57D07FULL,
		0x82E87F29E9A003DCULL,
		0x565F117350E7006CULL
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
		0x61AD3C111BAA9ABCULL,
		0x00E981B3E12DAD69ULL,
		0x3ABA7133B273DF21ULL,
		0xC96F841ED2207731ULL,
		0x5D1B615BAD4FA805ULL,
		0x8F0C33D8588BE11DULL,
		0x20A5576A7C3A0773ULL,
		0x0C75E01A57788924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F3ABA714E97DB3CULL,
		0x2B5C80CB44B3CA36ULL,
		0x39D8CBF2B01316F3ULL,
		0x192FF3C203D8B9E5ULL,
		0xCED947813670712AULL,
		0x283FB2B91AB7C4EBULL,
		0x99CB5A4A773AB3F6ULL,
		0xD3AAC1579F259F42ULL
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
		0x119433CBA4D141C7ULL,
		0x57576DDBBDDED851ULL,
		0x5173845F0FA811D7ULL,
		0xC9E20FFDF997F2E3ULL,
		0x40418F21CAE1FBADULL,
		0x16669A3AC17A6184ULL,
		0x84521CFEA49FBA54ULL,
		0xD541D560B31D22E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119433CBA4D141C7ULL,
		0x57576DDBBDDED851ULL,
		0x5173845F0FA811D7ULL,
		0xC9E20FFDF997F2E3ULL,
		0x40418F21CAE1FBADULL,
		0x16669A3AC17A6184ULL,
		0x84521CFEA49FBA54ULL,
		0xD541D560B31D22E4ULL
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
		0xB54600FE2EDA5749ULL,
		0x45019642B43ECB48ULL,
		0xA7FEC22B7D534BC6ULL,
		0x522A4D1FC524ECA0ULL,
		0x26E5CD4984B8B769ULL,
		0x679569EB754270C8ULL,
		0xCA9FABC75EBD3C03ULL,
		0x7204A6BD23CA90F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6190423ACFEC7E7EULL,
		0x641A15B43DA16F34ULL,
		0xAF70768B66696EE9ULL,
		0x16DFB4DC23FC5E25ULL,
		0xBCAE2DE10E2C1BCEULL,
		0x05BB7B436FA1DA0BULL,
		0xB5E2DCB7429874CEULL,
		0x99D86BC3C4E0333DULL
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
		0x255DF5AF9BEF09B4ULL,
		0x77E56A094852F633ULL,
		0x6EF66493AE99A4D2ULL,
		0x41A03DEDB5DF203FULL,
		0x2FEBBE49547070B3ULL,
		0x75CC088AE59845E0ULL,
		0x22E7FED922EFC7E4ULL,
		0x2E048FF6E2BE5F99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC09363FA051FECULL,
		0xE46D19624C33C2F2ULL,
		0xB88C7C51F8284F17ULL,
		0x6E2AA2CC17FAC7E4ULL,
		0x9A979797B1322619ULL,
		0xA37BF538D8F86E94ULL,
		0xA64CE456002C0754ULL,
		0x13F09E3DBE960275ULL
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
		0x6F5F0582B2F562B8ULL,
		0x754706F3D9E79AC7ULL,
		0x95D87FB9AFE6567AULL,
		0xF11469A578B67E35ULL,
		0x7B63B741AC13DC8BULL,
		0x03E8E0AE9FC6DC6CULL,
		0x4084943A8007D3FAULL,
		0xC922790C20B58F3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4B4820E18CD3D2ULL,
		0x9CE5C69AD219FED1ULL,
		0xB3FB5BC6B90541B7ULL,
		0x650EC5640AE04459ULL,
		0xED07512E2312CB12ULL,
		0x44F870DB54E087DFULL,
		0x04E47419FF0EC34AULL,
		0xB4964DFE61FC7908ULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1C1AE1AAED8E41A9ULL,
		0xED11F8701FFDD7FFULL,
		0xC345E46C218EB692ULL,
		0xF141BDB57B695BDBULL,
		0x42E102184CD57EE3ULL,
		0x31BD265D63C4C808ULL,
		0xD9333508BE1AE112ULL,
		0x7E92CEA4CC558D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1AE1AAED8E41A9ULL,
		0xED11F8701FFDD7FFULL,
		0xC345E46C218EB692ULL,
		0xF141BDB57B695BDBULL,
		0x42E102184CD57EE3ULL,
		0x31BD265D63C4C808ULL,
		0xD9333508BE1AE112ULL,
		0x7E92CEA4CC558D57ULL
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
		0x3184FCBFCDDBDE72ULL,
		0xB124AE33D373284BULL,
		0xEBE6C706F94309AFULL,
		0x395DC36FC406C0B0ULL,
		0x7E419696CA622FAEULL,
		0xBCA42F56A30080C0ULL,
		0xBC775DA4124D529AULL,
		0xCAFE5A826A303FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49A7F8AF6E376CA8ULL,
		0x471B077D0734ED1BULL,
		0xADAEEC42005E61B3ULL,
		0x812AADF3D5239AD4ULL,
		0xBC725BC1A4386B00ULL,
		0x77297A28CE3D67C0ULL,
		0x385C8C379DD9DE0CULL,
		0xD60C4388433D9F06ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xACE7B912961F06FEULL,
		0xD763635E575658CEULL,
		0xEEB49A884E3EE3F2ULL,
		0x89A11FAB0D871F08ULL,
		0xDE0CDF841CF65592ULL,
		0x686B8EDAB7DFC3A1ULL,
		0x30C1EFA4A067E03DULL,
		0x88449BABD0EC883FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7EF35E93938820ULL,
		0x35666EF25445B5B1ULL,
		0xCC0690C896332B79ULL,
		0xF873F3401A7A4921ULL,
		0x3F56DF3A95A5F34AULL,
		0x2FF0E083B9CE45ADULL,
		0xE73B90981792B47CULL,
		0x9436E72A83E5CA03ULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6FAEFFA05577125DULL,
		0x358B2EB378C92965ULL,
		0xFB7050F97631D101ULL,
		0x2A37E79AFB0DBB45ULL,
		0xBEBA486BB897B0EFULL,
		0xEDF2B608701E0D1DULL,
		0x890F0A8DA0D1C8A3ULL,
		0x3F03E8E0B4865F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2B5E7F03336E2FULL,
		0x55262DABB6EE7C9CULL,
		0xE7A4E6F780FFD242ULL,
		0x7A26F0C65ACF88AAULL,
		0xE58ADA944329EE57ULL,
		0x286EF43AB1E84D31ULL,
		0x86033A44BCE01F93ULL,
		0x1A13C228FF6551A9ULL
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
		0x85199405705249C9ULL,
		0x84CD00B330B361BBULL,
		0xE2E112BDE323E682ULL,
		0x1A47CB2A06A953FBULL,
		0x3DB23CBC03752990ULL,
		0x24F2DEFFEC971639ULL,
		0x5C95BA244EE8F99FULL,
		0x217B183962F55B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85199405705249C9ULL,
		0x84CD00B330B361BBULL,
		0xE2E112BDE323E682ULL,
		0x1A47CB2A06A953FBULL,
		0x3DB23CBC03752990ULL,
		0x24F2DEFFEC971639ULL,
		0x5C95BA244EE8F99FULL,
		0x217B183962F55B32ULL
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
		0xB67DB8EF51BA95F0ULL,
		0x0256E51313BE876FULL,
		0x15D8A0F1F7580AE2ULL,
		0x718EF11227F60654ULL,
		0x67F1451491E8453BULL,
		0x386E4C801F080AACULL,
		0x7C828C98CFCA81C6ULL,
		0x16C1B5A42598C349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4ECF5EB4FC41D4ULL,
		0x24D7DDA54F7C23F5ULL,
		0x36D4DCAF4197DEEEULL,
		0x5675911DAE944D8CULL,
		0x7CBA482A37B8F64BULL,
		0x87611A399377CCE7ULL,
		0xAEA606CDDEC9889BULL,
		0xC69C78472DEB7B12ULL
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
		0x6110537CD483BCE8ULL,
		0x614187A543CB1C35ULL,
		0xE7C07229DF9AC6AFULL,
		0xB5011116815B4D24ULL,
		0x1407CE7B51E4AF65ULL,
		0x33A1B6B74E07D5FAULL,
		0x5D85AB50E0C8B1B6ULL,
		0xB5FAC1FE349D601AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D0BC65B767BD8B4ULL,
		0x908B721A7D245F62ULL,
		0x3F93680C042EBA2BULL,
		0x7FEFA7BED9E6DA05ULL,
		0xD5E307A653AB82EEULL,
		0x2526CF6E7EEEE878ULL,
		0x1F9497153EE0F01CULL,
		0x3D6A2B905E478DB8ULL
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
		0x345F3FBBFAE2633BULL,
		0x37142C3803C714F6ULL,
		0x57D04EBE893E87CEULL,
		0x3CB0CF55D0769A1FULL,
		0x55FF76D1369F1A46ULL,
		0x9991E15BBD2A794FULL,
		0x8BC994CAA3F06F4CULL,
		0xA211C0FFE09349FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x258FDFE556432BEDULL,
		0x25BCD737D5FBDD81ULL,
		0xA8F135912938CF6EULL,
		0x4D76699E13F5F1A7ULL,
		0x241BDDF3908C169CULL,
		0x51F0C4F6E0B7AA1DULL,
		0x7960F58FF0C41637ULL,
		0xA85DD0C407DE5CA3ULL
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
		0xA53917369EA706CEULL,
		0xF27BB823D169157AULL,
		0xB40A77071CBE6C55ULL,
		0xE61F5B8309037C97ULL,
		0xC37C517AB9A1D139ULL,
		0x49237D593E9BCD40ULL,
		0x5E0C5FC1CCFC106DULL,
		0xBC7E34B38979AE6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53917369EA706CEULL,
		0xF27BB823D169157AULL,
		0xB40A77071CBE6C55ULL,
		0xE61F5B8309037C97ULL,
		0xC37C517AB9A1D139ULL,
		0x49237D593E9BCD40ULL,
		0x5E0C5FC1CCFC106DULL,
		0xBC7E34B38979AE6CULL
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
		0xED43F77477C89290ULL,
		0xA0CFE6FECE1CDF2AULL,
		0x1DA5D600FDF18FACULL,
		0x87BF1A6B2B424FF2ULL,
		0x3156089F711F9203ULL,
		0x54CEF34ABB9EBE24ULL,
		0x6B9D7B51886FCF66ULL,
		0xCE20D5BF57F883A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F8F556F1D5D250ULL,
		0xD6C7F29BE79AB129ULL,
		0x19875758C4A38695ULL,
		0x3F60F15AAE596C91ULL,
		0x346C126B4D6F1E4CULL,
		0x072FCB568BF627B2ULL,
		0xF0646580C0EE2341ULL,
		0x086164CA994F262BULL
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
		0xBFC0391E487D1E5EULL,
		0x1140C13678E0EB90ULL,
		0xE5C3C81B8FC8FA6EULL,
		0xEE9F33A8A3FD283BULL,
		0xE41BE06CD48703D4ULL,
		0x200D4C2E94B667A8ULL,
		0xD25000C541811C88ULL,
		0x1BAD9D8281B250C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A844748721B0C6ULL,
		0x68D81099F7E23563ULL,
		0xDC5AD4EBD41058A3ULL,
		0x36FEF468B94B03F3ULL,
		0x9861E355C31AC2A8ULL,
		0x2DB20218317B7078ULL,
		0x309FDE34A03F1413ULL,
		0x1924FA7A56673B1EULL
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
		0x5C8DEDDBA62AAAAFULL,
		0x78D44F94967BBC11ULL,
		0x17BC23A832CF7557ULL,
		0xDD39DE8F63B53D3FULL,
		0x631D01089B394EB0ULL,
		0x4DDD454FCFB87421ULL,
		0x8D077423E483867DULL,
		0xD70CBD07BB3A8A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B9EB44D8D70576ULL,
		0x5425FBE083E93939ULL,
		0x6BE7BE3E6A305865ULL,
		0x2E0522117CC7BFDCULL,
		0x529E7EB372FF7F8EULL,
		0x5954A80D0F84CBDDULL,
		0x52DA9A3ADF82979AULL,
		0xAF9A2A36530D599BULL
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
		0x12449B6207320495ULL,
		0x72DCAF151FA5418AULL,
		0xA4AA74E48FEF350FULL,
		0x6D0F5B42AF7085B1ULL,
		0x183E729EFF59C91EULL,
		0x0E80E422BC4B370EULL,
		0x8C7A2474FD73C725ULL,
		0xEA9CDE205ADA5887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12449B6207320495ULL,
		0x72DCAF151FA5418AULL,
		0xA4AA74E48FEF350FULL,
		0x6D0F5B42AF7085B1ULL,
		0x183E729EFF59C91EULL,
		0x0E80E422BC4B370EULL,
		0x8C7A2474FD73C725ULL,
		0xEA9CDE205ADA5887ULL
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
		0x3BEF7D3E9890E192ULL,
		0xFF216DEDA1C429E8ULL,
		0x3E92C132B8745ADDULL,
		0x6C7D767CE127229AULL,
		0x56B9E53A5F74394AULL,
		0x3473A6243C4D71A5ULL,
		0xED257D1C5A6378C4ULL,
		0x5410C1EB9D2D4FC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x853149CDDBC00A33ULL,
		0xE8BB4E566E4041C8ULL,
		0x5911FCF071F6B0D6ULL,
		0x458C834FC2A3904EULL,
		0x62D5E90E408CA1BCULL,
		0x2E548EAACA5EF696ULL,
		0x6FD1EDBCA751A59AULL,
		0x3230AAA590FA786CULL
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
		0x2B8BE18FBA50A1C9ULL,
		0xBDC7F24DCBD5AE22ULL,
		0xE741FA3AC2B93324ULL,
		0x811BBB8CC7720F93ULL,
		0xEE32E9F2CEBB86E3ULL,
		0xFD70596787E8F948ULL,
		0x48C4FB5E23F5005AULL,
		0x1B55CF87BF0F538EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x336DFF15395B36D3ULL,
		0x0E705C367FF2A24AULL,
		0x1DD78216ACFA527FULL,
		0xB8EDAA79D0B20016ULL,
		0x78C2A87CA76E7D71ULL,
		0xA2062B4036338ECBULL,
		0x3DC23AF4CE0B3816ULL,
		0x2E8614E2FEA37F61ULL
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
		0x6BE63BE992AD012AULL,
		0x0B3FE190ECD481E8ULL,
		0x6EC74B3361C26E18ULL,
		0xF5D5BAEBFFC24F35ULL,
		0x6CDD27E3FBD5C934ULL,
		0xC2FAA4CD12A7A947ULL,
		0xD74F0E1ECE6EBF5FULL,
		0xECF0C4A50C2545C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2BBDB12C309E67CULL,
		0xB095F8FD07A95B65ULL,
		0x613EDA400524B0ACULL,
		0xCEC9F588A65BDDA0ULL,
		0xA865E34E7A74FD5AULL,
		0x2FB13EABF56A90D7ULL,
		0xE8979F8C2DE91EFAULL,
		0xCFE2B813FE3FB65AULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x209909D2DED50914ULL,
		0xDF98570A08C86704ULL,
		0xD2855F93ED1F278CULL,
		0x34111513A2F25355ULL,
		0x14C9C5B017F18ABDULL,
		0x5F0AE60352FB53BBULL,
		0xB5779098C1166ECCULL,
		0x512360B08B9D6D2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209909D2DED50914ULL,
		0xDF98570A08C86704ULL,
		0xD2855F93ED1F278CULL,
		0x34111513A2F25355ULL,
		0x14C9C5B017F18ABDULL,
		0x5F0AE60352FB53BBULL,
		0xB5779098C1166ECCULL,
		0x512360B08B9D6D2DULL
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
		0x1482A076E66C8DE4ULL,
		0x5B0DDDFB6D9A576DULL,
		0x3772E799FBA0A624ULL,
		0x84C5C5CF6CD77E26ULL,
		0x3E75B768DFF3223BULL,
		0xA4DB35F7B6C1B1E9ULL,
		0x22DF6A7033A429EDULL,
		0x85321E8A5BD63942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7221A7EB6719BDULL,
		0xC5D5EF88537B484FULL,
		0xD287EA9E2B0035C9ULL,
		0x3BCECD0A8FB4AB89ULL,
		0xC2EC02D999F486D0ULL,
		0x0115B50D1EAB7D88ULL,
		0x7BF11CC1B635DEB9ULL,
		0x45B311CF4D5AB090ULL
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
		0xA12C46FA019E6DF4ULL,
		0xDFA43C4B39065E0EULL,
		0x66ED30F05D9FD826ULL,
		0x25C940FC54B59CE6ULL,
		0xE73CCD81351BBF18ULL,
		0x09E5C9210DD0A88FULL,
		0x624D3DB4CA281CE7ULL,
		0xC36DDC8DCF2738D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE481B3F61AA03EE9ULL,
		0x71D65137B3C2942CULL,
		0x21262586BE2EE246ULL,
		0x93E8DC147B107794ULL,
		0x8ABBBACD7CD82B7DULL,
		0x9420E3049553BCA7ULL,
		0x78B3501B0E3FDA1FULL,
		0x7FCD5358FAC12103ULL
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
		0x676E84689C06FD3DULL,
		0x5315E5BF20276481ULL,
		0xD4F6A11B827F0E2AULL,
		0xE6687901D1D95968ULL,
		0x30111BF6932FE6D4ULL,
		0xC9CA9192B0ACEDE0ULL,
		0x45EAC48951A9954BULL,
		0x73BFF93783CAD846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B00A756F4735DC7ULL,
		0x6A224460D72BED18ULL,
		0xE6F347C6A9A0FD4AULL,
		0xD77C25264F52572FULL,
		0x70DF8FBB5000310BULL,
		0x09F02FECE45839A8ULL,
		0x8077869A30339A54ULL,
		0x0E56F6091CB009EAULL
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
		0xF17BDF5ECF35ED3EULL,
		0xBA13013100E6896BULL,
		0xE3DF5637871D6A79ULL,
		0x6708F6721323DA2CULL,
		0xA49E0888535A7B61ULL,
		0x09AA38B1291C70DDULL,
		0xAB8040FB5CC586DFULL,
		0x575C9E023A3347A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17BDF5ECF35ED3EULL,
		0xBA13013100E6896BULL,
		0xE3DF5637871D6A79ULL,
		0x6708F6721323DA2CULL,
		0xA49E0888535A7B61ULL,
		0x09AA38B1291C70DDULL,
		0xAB8040FB5CC586DFULL,
		0x575C9E023A3347A4ULL
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
		0x55270AF00FC1315BULL,
		0x87D6F77AC45910A2ULL,
		0x1BDB28EFF76B082AULL,
		0x03F423F0714B1EBBULL,
		0x86BA514FD6520C19ULL,
		0xE4292C7A60709DEEULL,
		0x63E382A759AB584DULL,
		0xB0F11C2E74A1B59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9F5D9348A472A2BULL,
		0x747EB5AD62055B10ULL,
		0x30AB07E8D5992A33ULL,
		0x08E78EA6475D5515ULL,
		0x8BA2F4796CB2CB8CULL,
		0xF1EE85C3C4484F30ULL,
		0x4266CCDC9EA7052FULL,
		0xD659D96073E5FA2CULL
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
		0xDB998E7FB7F2E591ULL,
		0x7A847453345ABE09ULL,
		0x971EF505BD6D0FEFULL,
		0x40E770C999B9769FULL,
		0x6C5DFEF41722F1B4ULL,
		0x731F028378D5449DULL,
		0x7C84AE7B443079BAULL,
		0x6BC280FD2197018CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4614B9218CE78F58ULL,
		0xC695D55442912A95ULL,
		0x37E9217FEE9F0300ULL,
		0x06B54FADDB697149ULL,
		0x3898B61D5CDAB79BULL,
		0x4ADED1B2019FDDE7ULL,
		0x3CF18B10BF194376ULL,
		0x151D6A3F8A80AC77ULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4681D9261B0D6090ULL,
		0xD0FA1F1C3583A27AULL,
		0x1C489F3CBEC2BB9EULL,
		0x061E0A25E36E0049ULL,
		0x1429D4209C83D57CULL,
		0x99AB444EA5334F06ULL,
		0x53E283550CA1E685ULL,
		0x67FD75A9C024C062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A974BF27A205D7ULL,
		0xBB82FB66867D9AF9ULL,
		0x1007C1E02512D0F5ULL,
		0xC03B99102CF35A4FULL,
		0xAB84CA245A71801FULL,
		0x52B15BA4CD8FA3FCULL,
		0x2B32C81435115FA1ULL,
		0xFA15CAEB462AA5FBULL
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
		0x9B06FDFFFE5A1EA0ULL,
		0x92518423F9D812F3ULL,
		0xE32A2BCFF540D061ULL,
		0x01FC7F968FB4F7E8ULL,
		0xD2E436A343CA8DF0ULL,
		0xD82317F6499A215BULL,
		0x9C0C11F6F1A6FE9EULL,
		0x3D39D2CFE8C7873AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B06FDFFFE5A1EA0ULL,
		0x92518423F9D812F3ULL,
		0xE32A2BCFF540D061ULL,
		0x01FC7F968FB4F7E8ULL,
		0xD2E436A343CA8DF0ULL,
		0xD82317F6499A215BULL,
		0x9C0C11F6F1A6FE9EULL,
		0x3D39D2CFE8C7873AULL
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
		0x0E336596AB4D5DC8ULL,
		0x9E1078DB4254DE7EULL,
		0xCED3ADE6E4A5AEDCULL,
		0xD7CF1B69B186C583ULL,
		0x54F86468A82169C1ULL,
		0x9EDAF775C353BCEAULL,
		0x622AC60C687374A9ULL,
		0x58FB8CB7C689A60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA521B5F3DC4CAEE1ULL,
		0xFE5ADA7A9CCA59DEULL,
		0x90B976CB2D57F02FULL,
		0x2BFBDFBDD48E2683ULL,
		0x3E606C7C68445BAAULL,
		0x1138C08E8E4F3392ULL,
		0xF0127E296A4770AAULL,
		0x6A6DBC576FC85EF7ULL
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
		0x6C84D90ED70D2071ULL,
		0xCE2C296E6614F232ULL,
		0x896B25EC61989B68ULL,
		0xEF03DF7742CED9E2ULL,
		0xA1E1BB0EFBF20635ULL,
		0xCFC332749D8DF862ULL,
		0x74AAECFC5A50A057ULL,
		0xDF2AD8EA908FA526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1F86709117C61FAULL,
		0xCF6C41805C18BF60ULL,
		0xE3F2B7AFBEB2EB1FULL,
		0x494716C3D3C1E32DULL,
		0x7FD18404F0E59A14ULL,
		0x35DC67A410464FFEULL,
		0xB5ECC0EA9288B57BULL,
		0xB31ACDA9CC96D648ULL
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
		0x2092EF5DA9EE9376ULL,
		0x51C5B6943D2154B1ULL,
		0xBB381DB71AD8B358ULL,
		0xA2EC7DB6920758E7ULL,
		0x64E0C2FE60E82C59ULL,
		0x3BFB75BB2D562172ULL,
		0xED0261597BA18565ULL,
		0x9B90818D03868595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A276D8DFE181F3ULL,
		0x98AE195E8A6EFB6CULL,
		0x0EA9844A2DCA09B6ULL,
		0xF57172712B3C7369ULL,
		0x992814A7D5EFF0D7ULL,
		0xD6F5C0DC60363B55ULL,
		0xBA0E5B6E3147BA29ULL,
		0x4AD8BF627749BA25ULL
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
		0x642B1BE296F950F3ULL,
		0xB4A3C9FA7F0DD9F7ULL,
		0x2FE3F7310198AE92ULL,
		0xDD2A2B748F1A77B6ULL,
		0x475A0DB564F82019ULL,
		0x71BD92786024DBEAULL,
		0xCA46C7552B9ED464ULL,
		0x56F13C21F4040F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642B1BE296F950F3ULL,
		0xB4A3C9FA7F0DD9F7ULL,
		0x2FE3F7310198AE92ULL,
		0xDD2A2B748F1A77B6ULL,
		0x475A0DB564F82019ULL,
		0x71BD92786024DBEAULL,
		0xCA46C7552B9ED464ULL,
		0x56F13C21F4040F2BULL
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
		0x60747E261628E57BULL,
		0x6E26457AE55DABFDULL,
		0x853F50139F498EDEULL,
		0x959A33D080E9C040ULL,
		0xE09B1BB035268E33ULL,
		0x3506794978784BA9ULL,
		0x106917C725598439ULL,
		0x40831BBFA543B0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0EF3306AA1DA92AULL,
		0x439B6000B3845896ULL,
		0x185E8D44D5151D94ULL,
		0x1779BB4332094DB4ULL,
		0x948B42B345815C99ULL,
		0xA2283653BC253F16ULL,
		0x3279140305A4973AULL,
		0x9BE0C34FE83A4CFFULL
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
		0xB79FA3BD68E52A53ULL,
		0xE0E9F433E11A5BA9ULL,
		0x448C60A9A1A61918ULL,
		0x0CBEF7B6795A1C5FULL,
		0x700093013959059EULL,
		0xFD8C8378C7DFB6A6ULL,
		0x82E3D071251DC0EDULL,
		0x019A18500F5F332AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BDA779A38AA58FBULL,
		0x32F110389030FD83ULL,
		0x7E4497D754B98E91ULL,
		0xC44E94540C9BA749ULL,
		0xE4561A41A275E512ULL,
		0xC88F0E4ED85EED5CULL,
		0x12BAD61190D737C1ULL,
		0xAEAA902E232432A3ULL
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
		0xEEBC53FF6C1E79EAULL,
		0x133CFF16AD82E573ULL,
		0xFE00A7C708097D60ULL,
		0xD0852DA45AAC78F0ULL,
		0x0B92DF96451AF02FULL,
		0x09A51C30CC1AD049ULL,
		0xB8F4034E9EE5F762ULL,
		0xEA709C20DEDD0ACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x466034455E8CF5CDULL,
		0xBA03832AE751BDB9ULL,
		0x0B2BE74B8300B1C3ULL,
		0x57CBF5D5D6FCE790ULL,
		0xDC15DA0D07383DB7ULL,
		0x23FC70FDB1F34C90ULL,
		0x67D281FFC685D297ULL,
		0xE334599F3DED6F32ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4ED015D930F3EF51ULL,
		0x135E9745C9F5FDEFULL,
		0xCA280086F9AFE01BULL,
		0xC882DBD192B9DA7AULL,
		0x6C584F244B77483BULL,
		0x43E2F36D8D6C6F84ULL,
		0x75346C80A9680A9DULL,
		0x00C564AB7661AAEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED015D930F3EF51ULL,
		0x135E9745C9F5FDEFULL,
		0xCA280086F9AFE01BULL,
		0xC882DBD192B9DA7AULL,
		0x6C584F244B77483BULL,
		0x43E2F36D8D6C6F84ULL,
		0x75346C80A9680A9DULL,
		0x00C564AB7661AAEFULL
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
		0x90FE5816412F332FULL,
		0xA434622A4BAC121BULL,
		0x6F0BCCCF8D033935ULL,
		0xBB93B0E56EC34143ULL,
		0xA049A303F8CA58D0ULL,
		0x7431F2624854D9FDULL,
		0xDA2ED3232FAEA6F0ULL,
		0x43D84192237CA746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x392A54E4D5C44851ULL,
		0x7DC74ED822764423ULL,
		0x97E576315910DC46ULL,
		0x42C9AAAE7733D2F2ULL,
		0xBBE46CB44B1EE92BULL,
		0xE77C1261FEBB24E1ULL,
		0x1E4AC31B424F535DULL,
		0xC78E3D389608FF78ULL
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
		0x262F0AF4DC1352F2ULL,
		0xA48609853ED77CC6ULL,
		0x5EBC5ACB55814868ULL,
		0x9B8791DA6844BF1CULL,
		0xDB702F90AA67868FULL,
		0xF65AE93F8E47273CULL,
		0x1BB79CEE90B8842AULL,
		0x09DF4B7AC26234BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0EBE1601DEADCA2ULL,
		0x540F5575D075C252ULL,
		0xD9A113F45929F63BULL,
		0xD9A74A44C419A83CULL,
		0x51BCC2BE846FD8D8ULL,
		0x02D467320CF03AE8ULL,
		0x2A5D9B68172CFB80ULL,
		0x2F19AE281C9BC9CBULL
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
		0x8E71FDA5F8490A68ULL,
		0x341E30DB6401BFF1ULL,
		0x323CBFDF48F9C341ULL,
		0xE85DDC86D258809DULL,
		0xFB764FD6FF7225A8ULL,
		0x4F0F7BC151839452ULL,
		0x21ECBC5D56938063ULL,
		0x0DC9659C36C4B969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B562CA654CC37ECULL,
		0xE9D5440A4A6141F4ULL,
		0xD82D9C11C0F5ABABULL,
		0x750D4902FECCC8C1ULL,
		0x3196431F1B310762ULL,
		0x1C33CD19CE1B10CBULL,
		0xE170542B8DB56407ULL,
		0x4CD65AA6B09EA898ULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x814CBF3BB8C53AC7ULL,
		0xCDDECDBC60AC6F61ULL,
		0xEE2399B68062AA0EULL,
		0x2E9A2D1D11BCBB76ULL,
		0x8FC84DE105634B31ULL,
		0xB152322F48BE3292ULL,
		0xBD21654CA88A3859ULL,
		0x7D0194E81742756AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814CBF3BB8C53AC7ULL,
		0xCDDECDBC60AC6F61ULL,
		0xEE2399B68062AA0EULL,
		0x2E9A2D1D11BCBB76ULL,
		0x8FC84DE105634B31ULL,
		0xB152322F48BE3292ULL,
		0xBD21654CA88A3859ULL,
		0x7D0194E81742756AULL
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
		0x5231C875E9819EC9ULL,
		0x13774B73A61D3E0EULL,
		0x5674FE09CD337FC9ULL,
		0x9DC29A5E7D0D3BBFULL,
		0xD34A5603482DB779ULL,
		0x5D7EA80DAA1454B8ULL,
		0xC3AB97D818ED2564ULL,
		0xB7B343060DBD37E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB78AD1B1E6D4272DULL,
		0x28CFCB02D83A4369ULL,
		0x7DBF878C1169481AULL,
		0x4DD944666CE117B2ULL,
		0x6A35B7DF9DA3C489ULL,
		0x437AF327AF823F0BULL,
		0x66D4D63B6C21C30FULL,
		0x1E9D38336D4EC495ULL
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
		0x44CD977EFBAD1CBFULL,
		0xA205A883BE93E201ULL,
		0x9D835C92F153C66AULL,
		0xE3356D4AB21447E2ULL,
		0xFBCBC090B0A7409FULL,
		0x648B7083CFAC4868ULL,
		0x921404D3E20C6F2AULL,
		0x79C67BFD2739B902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87648AE02F85248BULL,
		0x15147D3135860FE0ULL,
		0xE3EA4F98476DA2DCULL,
		0xE0EDB8BEE2DC64D9ULL,
		0xE0F2DA3613C0C341ULL,
		0xB54B6CB293BEED38ULL,
		0xD30ED03C3CA30150ULL,
		0x91D7B6A700302BABULL
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
		0x5DBEAFCF2705A881ULL,
		0x1BC8002F5A876087ULL,
		0xAFC52CD5B76D7DD5ULL,
		0xCF42ADA1FC0A3F16ULL,
		0x34D12ABD21B6D57FULL,
		0xDCC548479B50DDC4ULL,
		0x517BCA2FCE4954B4ULL,
		0x8C8AF03BD50F7C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D60ABBB5F69AEEULL,
		0x78743939ECA022E5ULL,
		0xBB895B9FDACC2532ULL,
		0x1F324A960DC59912ULL,
		0xC0FF47BB444BC204ULL,
		0x4A62D5E55DCEDDACULL,
		0xB8AA9A6059B82A5EULL,
		0x3E3309BB45376BB7ULL
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
		0xEB65689A3D84FC1CULL,
		0x4EC58869EC75D5B7ULL,
		0x29E40ABA12CE3818ULL,
		0x9892B1A0402C3164ULL,
		0xEB5FCB90D608467AULL,
		0xB60058BF9CD94B92ULL,
		0xA33B3F53EC7554F6ULL,
		0xF805005B59DF7409ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB65689A3D84FC1CULL,
		0x4EC58869EC75D5B7ULL,
		0x29E40ABA12CE3818ULL,
		0x9892B1A0402C3164ULL,
		0xEB5FCB90D608467AULL,
		0xB60058BF9CD94B92ULL,
		0xA33B3F53EC7554F6ULL,
		0xF805005B59DF7409ULL
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
		0x443E2E7DE105AC65ULL,
		0xDDC8A86E89F08337ULL,
		0x0211E1168588D77CULL,
		0x59CFDE62673AFAE5ULL,
		0xC53AA3D29FF10590ULL,
		0xC25AF90AF4716FB2ULL,
		0x9A3F11414A7F81F8ULL,
		0xBF7D07E4F0A6F632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3B2108716EA92FCULL,
		0x88694498F0F37CC8ULL,
		0xD09D7650483B52FCULL,
		0x410D970CE5D8F578ULL,
		0x17CECCD4A44073F4ULL,
		0x6B18FADE523423CBULL,
		0x190636680B9AD81AULL,
		0xBD7AEA2C1F19D94EULL
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
		0xB6C55204574CF97EULL,
		0xEF7A4F7E494F5985ULL,
		0x835EB4665AA65F92ULL,
		0x958A784299C169E5ULL,
		0xB61D174C220ECB0EULL,
		0xEFD0BBD82E93EDF7ULL,
		0x351B0A9608B06D78ULL,
		0xB4CEEA540C0855F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87CDC8307E7701CULL,
		0xE0DB8C379C761CE2ULL,
		0xCFBF8D0343115F20ULL,
		0x9B0151789A2035A6ULL,
		0xFD8D6BB4E549335DULL,
		0x7278A6A66149F401ULL,
		0x00FEB6CEC371A879ULL,
		0xDAB35A19AF92425AULL
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
		0xC5CB31FE4D23EC75ULL,
		0xD5281DEC8D41B4C9ULL,
		0x3A3E2F5443313204ULL,
		0xDE18632575BFF234ULL,
		0xC5730BEB904DB22FULL,
		0x4BA21347F4C9C45AULL,
		0x83B9ADC96B9FB87AULL,
		0xC234E48F41FB8AFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42D0163DEA8E1BCULL,
		0xD15B77CE520360D0ULL,
		0x1D5929CE4EB5D319ULL,
		0x651C566A35E39F42ULL,
		0x43A9DA71745F2E8AULL,
		0x7D72FF6F7190C1B1ULL,
		0x0F986C0BA9862070ULL,
		0x97FDBFD6ABBB9E94ULL
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
		0x73C557CE1B661666ULL,
		0xEF8BB3C040FC24BAULL,
		0x623B6198490535BBULL,
		0x2C49B6F67441BAA5ULL,
		0x59AFD17E4B093243ULL,
		0x742544F2E0FBC2C6ULL,
		0x454173265EEBF42BULL,
		0xD0C60906EF85151CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C557CE1B661666ULL,
		0xEF8BB3C040FC24BAULL,
		0x623B6198490535BBULL,
		0x2C49B6F67441BAA5ULL,
		0x59AFD17E4B093243ULL,
		0x742544F2E0FBC2C6ULL,
		0x454173265EEBF42BULL,
		0xD0C60906EF85151CULL
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
		0x4F1F1F3E1C95DF7FULL,
		0x4EF090D51031306EULL,
		0xD9FB4F4282A016D7ULL,
		0x4B9A518C1F181DA5ULL,
		0xE0ABFB0DB49A1E26ULL,
		0x76DD3D95DF3EE561ULL,
		0x5A492ED36EDC38CAULL,
		0x0269642397ACAE2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6FB6C2088A89FE2ULL,
		0xFC281067BA6C8A6CULL,
		0xC6D8F696212C4D29ULL,
		0x383EB12C2E488C7DULL,
		0x5830C5A2B3E81AEAULL,
		0x823779D423B569AAULL,
		0x06DFBCEB42F52A95ULL,
		0xF7B39D4FD9F39D45ULL
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
		0x51C8A72F57B7A569ULL,
		0xF880F1F9742D8234ULL,
		0x70ED01FA292654C9ULL,
		0x952E8F133C9FAF33ULL,
		0x8BDA5ED585A442FCULL,
		0x97FEE44181DA9FAEULL,
		0xF12D19E4D231218DULL,
		0x1D9288CDCA3E91C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F367A0A8A092646ULL,
		0x1BCB9216D9FEF81DULL,
		0x0BE769CEA4C1BB8BULL,
		0x7CE02E48C9035EA2ULL,
		0xFB224D31CC2D8F5CULL,
		0xB107A69819DB5287ULL,
		0x75A0C80D66F86776ULL,
		0x6938DDBBDE050E41ULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF8DF75F609D5AE67ULL,
		0x41FA3518D2F35071ULL,
		0xE501075A0927CBAEULL,
		0x535AB100C3E2C05CULL,
		0x6E210EDB900BF2B6ULL,
		0xF53DA120D503D7DEULL,
		0xB04135870A9D222FULL,
		0x55D9DD54001D2131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF540381B74CAD0ULL,
		0xEDB01D2CB41D166FULL,
		0x98732FF9B379917FULL,
		0xE0F7F577903AB193ULL,
		0x80573D112209AE61ULL,
		0x858CFA5F24EA1308ULL,
		0xBE8508B20A44ACA3ULL,
		0x4600B58DAAC3B284ULL
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
		0xC0501BDA22412083ULL,
		0x63651A19F80FF0C8ULL,
		0x0D647A59D7B8E02BULL,
		0xBE4C725CECCEAE23ULL,
		0x53066A9D26BA6ADBULL,
		0x30003CDA051EBC0CULL,
		0x6416ABD54A48D252ULL,
		0x6A9548CF8321D596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0501BDA22412083ULL,
		0x63651A19F80FF0C8ULL,
		0x0D647A59D7B8E02BULL,
		0xBE4C725CECCEAE23ULL,
		0x53066A9D26BA6ADBULL,
		0x30003CDA051EBC0CULL,
		0x6416ABD54A48D252ULL,
		0x6A9548CF8321D596ULL
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
		0x2F0107FA86792420ULL,
		0xD5778C91E0C1A9F8ULL,
		0x261EAF4AB883B5B5ULL,
		0x6AC77C7F2EC9A51CULL,
		0xBD191855E1A75B50ULL,
		0x573F7CE224279A4CULL,
		0x1A3AC7E5ED068884ULL,
		0xD61D0F2FE0EA5244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597C289F59A5175DULL,
		0x4A37D2D9FC07EB6BULL,
		0x3743176B08CD7DA3ULL,
		0x8B184D8FAC18E10BULL,
		0x007BA4D8168D9C8FULL,
		0x9285A2FB6AB117D9ULL,
		0x18D4BA1155FB7CC4ULL,
		0x919883EB8DED4D91ULL
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
		0xBF46BE213780DCA7ULL,
		0x69A7B002FE6F2925ULL,
		0xF062953FA28A7D8DULL,
		0xE358BD1904F60AF8ULL,
		0x0AED25CC81079079ULL,
		0xF39B5E2079CCEDA6ULL,
		0xDA8E1F3709FB5C56ULL,
		0x5D219DE3E56C0436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D4D97C9A6E5EDDULL,
		0xD361D0B696230D6FULL,
		0x6A136D39C05E719CULL,
		0x630F05CAB5AD7638ULL,
		0xDE9070B059F1DF94ULL,
		0x19E61C00ACD0DF75ULL,
		0x1576EE3F111271EFULL,
		0xD6B1570A8557BF38ULL
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
		0x032A4FC6751AE04CULL,
		0xA0AD6A71702E3877ULL,
		0xEBECF9568B80F7D8ULL,
		0x3A204D866794AB0EULL,
		0xABE38B94E1DED238ULL,
		0x09E2853384905F21ULL,
		0x66471CED554629B6ULL,
		0x32E00BB5FBE58319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED663DAADC38C26FULL,
		0xE237C9CC74B3AC87ULL,
		0x37E8FC9D39440A84ULL,
		0x8042960E752EEA28ULL,
		0x56BC379A001BA52FULL,
		0x81A9E2B72AAFF478ULL,
		0x7D22B1595A6A8411ULL,
		0x6533722B7F830041ULL
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
		0xD7D15702E723C294ULL,
		0x85B62CDFE6301166ULL,
		0x92FB31F07A401C81ULL,
		0x49A15CFB6253D8B9ULL,
		0x8BF76DAF195DB5F6ULL,
		0x49C9162FCACAF6EFULL,
		0x1B05740A273815FDULL,
		0xC40D7DBB735DE175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D15702E723C294ULL,
		0x85B62CDFE6301166ULL,
		0x92FB31F07A401C81ULL,
		0x49A15CFB6253D8B9ULL,
		0x8BF76DAF195DB5F6ULL,
		0x49C9162FCACAF6EFULL,
		0x1B05740A273815FDULL,
		0xC40D7DBB735DE175ULL
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
		0x23B87D411CA9BEA1ULL,
		0xD0D23478C77FA4A1ULL,
		0xC1DCD01EA01A42BFULL,
		0xEF2A61BCC3CB2725ULL,
		0xEF1967B5651E14E0ULL,
		0x5E62A46A33700B92ULL,
		0x4290FE81EDF0F012ULL,
		0xA24A27A1D740338AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6914B95F2783007ULL,
		0xE8440518AEFF480DULL,
		0x95E5D8DD36E4CA85ULL,
		0xAF156AF54663E768ULL,
		0x321E3E3A18543084ULL,
		0x4E58FEC32ECA8D9FULL,
		0xD4F4BF97B40BB33AULL,
		0x2814B8686CF4816BULL
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
		0xF05ECF3045237600ULL,
		0xC9F2875F18E27C76ULL,
		0x6A0E2B1A51A57D2FULL,
		0xBBCA4B34B4AA9F1AULL,
		0x9E3A6B8902C34182ULL,
		0x8AF7BBEC51D616E9ULL,
		0xE94AF3B3E9DD6F52ULL,
		0x596A6526ED77D90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA219C6880BC00D72ULL,
		0xD26D6DE9FC699CD6ULL,
		0xC44970BFE0CF621EULL,
		0x5347B94ABE152B84ULL,
		0x3C1F5603CF006260ULL,
		0x33813120233DA44DULL,
		0x3F947BBB3557968BULL,
		0x5ED86862D601644BULL
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
		0x187DBBD4516FDFF8ULL,
		0x88BB248C8B32D177ULL,
		0xFA82E12A6A839200ULL,
		0x4123FD00ABC79B86ULL,
		0xB70651A4C9630B5FULL,
		0xFC7BC601EB86ACAFULL,
		0xABE44FBCB318286EULL,
		0x67AF93EE24EEF196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF013630EE05BFE58ULL,
		0xF0E75C96E0B222F4ULL,
		0xD11C98597AE20B79ULL,
		0xE2B870E5B667D682ULL,
		0x53DDCE256E490A87ULL,
		0x1FDB6AD0734F1047ULL,
		0x87C6372DB33C277AULL,
		0x595F616C5A837732ULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC3C4910BC3A3D6F6ULL,
		0x0018737916D22402ULL,
		0x6E23B5D5F2D6C7F6ULL,
		0xCFBFC246BC35F84EULL,
		0x2215D0D6B4C5C7EBULL,
		0xAAA657EAD74951B2ULL,
		0x0E88615B8F42180FULL,
		0xDD38A0F14BBE1B40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C4910BC3A3D6F6ULL,
		0x0018737916D22402ULL,
		0x6E23B5D5F2D6C7F6ULL,
		0xCFBFC246BC35F84EULL,
		0x2215D0D6B4C5C7EBULL,
		0xAAA657EAD74951B2ULL,
		0x0E88615B8F42180FULL,
		0xDD38A0F14BBE1B40ULL
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
		0xA9AED2BB94F7D3F0ULL,
		0xF4265A6E265322C1ULL,
		0xB6FA488CA5C4B979ULL,
		0x0AC3FE2F13C89458ULL,
		0xCED72AC51981F827ULL,
		0x207C75E44BEE6FC1ULL,
		0x093F3AB07653E9EDULL,
		0x3520D74A02E298B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27294E7CE2D9E344ULL,
		0xEC38B3D78D43697AULL,
		0xF9625ACCEDF3234CULL,
		0x14E2DF6845821E0DULL,
		0x8496D23E9404B50DULL,
		0x4EC7B9CD066F354BULL,
		0x14CACD5CD4D7778AULL,
		0xDF0D5814DDAC7ED4ULL
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
		0x4E348CE0156D02ACULL,
		0x2FD54EBCF0BBAAFBULL,
		0xCE13204F6A90E3D0ULL,
		0x0CEB2CD3A9457C40ULL,
		0x7C034989A8F24D5DULL,
		0x4996B65FDC25ACF7ULL,
		0xC574C602C0B1FEFFULL,
		0xE3E484BECCD54997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7F2DACD60244ACULL,
		0x3D4086FF4CBED745ULL,
		0x0A33B62DF71A24EEULL,
		0xE7FEC26AE0BF6F5FULL,
		0xD5B0FB873A3FF925ULL,
		0x35F1870F8C777738ULL,
		0x0869C199CD301748ULL,
		0xD3C26C3BCED729EDULL
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
		0x0D6794170A17695AULL,
		0x8FE9E7339897C299ULL,
		0x5EBA2768D1F05E36ULL,
		0x9D454AECCDB36A23ULL,
		0x42801E9743B43427ULL,
		0xCE597E2B8DFB4A45ULL,
		0x8F1C00935D647430ULL,
		0xB75ECCD47D838318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83C104D9CFB808DULL,
		0xF528045F0E50244FULL,
		0x969E38F2CF59CFA8ULL,
		0x616B0C8F75D86C3AULL,
		0xC2714883BFBBD6BFULL,
		0x79BA80E87C532A44ULL,
		0x5401DFBF4D720854ULL,
		0x3140C1D4BBDD5AC0ULL
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
		0xE2C01E8FBAD656E0ULL,
		0xEBC148E6BE892A1FULL,
		0x1E1DA829A74A0EE3ULL,
		0xD082AE63BA9204ACULL,
		0xED324D6B1A7A423DULL,
		0x8692A746C420A4BFULL,
		0xC57FF6BFB56720CAULL,
		0x39085F10302F8CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C01E8FBAD656E0ULL,
		0xEBC148E6BE892A1FULL,
		0x1E1DA829A74A0EE3ULL,
		0xD082AE63BA9204ACULL,
		0xED324D6B1A7A423DULL,
		0x8692A746C420A4BFULL,
		0xC57FF6BFB56720CAULL,
		0x39085F10302F8CCAULL
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
		0x4C20142481F78E22ULL,
		0x15452BA9F2401D3CULL,
		0x2C7516D4F9C284E5ULL,
		0x2439A173399ADC6BULL,
		0x7AF1E6AF7B9DF764ULL,
		0xCF8122AC13721516ULL,
		0x1A50CB4CE0B69137ULL,
		0x1B682CE90429732BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA8F5990C17387EULL,
		0x5355530AB07F4D33ULL,
		0xC3BE71A998A55B76ULL,
		0x13597E7D51ADFEC0ULL,
		0xC52727E8B0BA356FULL,
		0x42D8F6F5CD190282ULL,
		0x294C906AA0B15389ULL,
		0x3D8AA047840706B2ULL
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
		0xBBDD3F03BDAF077BULL,
		0xDBCC23A232058915ULL,
		0xA76B9A76683941B3ULL,
		0x70EBE51450881015ULL,
		0xA49A8FF1CB3952EFULL,
		0xE9D0C661E039845AULL,
		0x50A0DB394C62FD0CULL,
		0x6F2E8DBD620A8FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D5BC1D8AB0E6AFULL,
		0xAE6C99F8D44882C4ULL,
		0xEF8BA2579DE03C5FULL,
		0x9C7E2189DD93755AULL,
		0xEA396521BC4A1397ULL,
		0xC30BF5D974801C7CULL,
		0x6CB72FB0F37A495FULL,
		0x4E1D76B929B90DC9ULL
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
		0xA31EE77DC04575B0ULL,
		0x4352ADA3845E93E0ULL,
		0x6E2236937F22E7B6ULL,
		0x3BE8D798962A2E69ULL,
		0xF69675171C3499CDULL,
		0x447E501A3872816DULL,
		0x06164742095B0A19ULL,
		0xE1027531A0F29BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BAFAA66569B98ABULL,
		0x69AA904DA60FEC87ULL,
		0x14DE61455A39C67CULL,
		0x4B3220271134A239ULL,
		0xC44560DE92BEB087ULL,
		0xDD12A262A72BB18EULL,
		0x753D4AEB559B7EA4ULL,
		0xBA83C5A9BB447C52ULL
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
		0x8EB239114F81646AULL,
		0xDA431ED4ED68D8ACULL,
		0x49956DBE274BBFFAULL,
		0x1F36467DF02DCDE7ULL,
		0x524B8E610341395EULL,
		0xD17FC8AD4C53849CULL,
		0x8D65D6E38237AABFULL,
		0x2099647DEA50FBBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB239114F81646AULL,
		0xDA431ED4ED68D8ACULL,
		0x49956DBE274BBFFAULL,
		0x1F36467DF02DCDE7ULL,
		0x524B8E610341395EULL,
		0xD17FC8AD4C53849CULL,
		0x8D65D6E38237AABFULL,
		0x2099647DEA50FBBDULL
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
		0xB940FD1DFFCFE99BULL,
		0xF8AB43ECC10A3163ULL,
		0xB44974B9F3F75D49ULL,
		0x93F717C81D307554ULL,
		0x33494EE9FDD5F9A0ULL,
		0x108AF6573476FA18ULL,
		0xB2F5DBD608CBDF15ULL,
		0xCE64D141688F6688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B4EC105AA5CD18ULL,
		0xC43B4F62CF2D6969ULL,
		0x5B5C07B71B2BD719ULL,
		0x5EF57A1F0CE61EF3ULL,
		0x7853B7C17A8B699BULL,
		0x8FA0EBCB5AC4E07BULL,
		0x8FC87673914F31AFULL,
		0xAC92690BB32D7C65ULL
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
		0xAAD24F5DB99E5F8EULL,
		0xA5AC526090B68F94ULL,
		0xBFF445B05ACC8CEFULL,
		0xB191ADC579024B78ULL,
		0x677523E3009F555DULL,
		0xDE75C97AE0D751EDULL,
		0x50C391EBFEEEF737ULL,
		0xC7E8801AD0D84731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD4D4E249C1C484ULL,
		0x4C24DCC0D9F54904ULL,
		0xB3285A43DC655F9FULL,
		0xBD4EC03EF850206AULL,
		0xAE0B5B48774D2BA6ULL,
		0x9A52BAC81486E603ULL,
		0xD718DD8D7B36AFD9ULL,
		0x3F7C86D81624779EULL
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
		0x784E7AD972D5E9C1ULL,
		0x97495868C790FF40ULL,
		0x0F762C4E47203B44ULL,
		0x81F95B8887A538D2ULL,
		0x5326EA970F0FE501ULL,
		0x0CD631A699C329ABULL,
		0x773604B7E49246E8ULL,
		0x5F0750ECF0F078A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814C2738C74C1059ULL,
		0x8D9E3350C6CF5360ULL,
		0xF561EC80B7C0BCB6ULL,
		0x48ED69D600C85826ULL,
		0xB74CF37F245BCF35ULL,
		0xC74AB10717B7AFB5ULL,
		0xFD7FF7282170666FULL,
		0x858649727E59C652ULL
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
		0x5F59DD13F309AECEULL,
		0xDF465169A8D778A9ULL,
		0xD5D77FC70A2EA7DEULL,
		0xAE655E5372D7D98DULL,
		0xD698B2A68DF1483AULL,
		0xB1B83D8DC54D962EULL,
		0xBFBB36954B4DC94EULL,
		0x2966BC66B2E47FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F59DD13F309AECEULL,
		0xDF465169A8D778A9ULL,
		0xD5D77FC70A2EA7DEULL,
		0xAE655E5372D7D98DULL,
		0xD698B2A68DF1483AULL,
		0xB1B83D8DC54D962EULL,
		0xBFBB36954B4DC94EULL,
		0x2966BC66B2E47FAEULL
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
		0xE2FCEDB93F576FC5ULL,
		0xF97818CF83247AC6ULL,
		0xB222ED5AE69AA9CFULL,
		0xBEC324D2AC4A79A7ULL,
		0xCCCFCCFE6187482EULL,
		0xA1BD455A37C52372ULL,
		0x893AC4A6F4DBCCF3ULL,
		0x935406EBDA15D816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C827E1649FE2CEULL,
		0x56AB47B7D80F4D80ULL,
		0xBE90CCD0C0887A50ULL,
		0x17C7CACA8A165688ULL,
		0xECFF80E219A871A4ULL,
		0xFE25A418DDC5644DULL,
		0xCFBA800D7BC93097ULL,
		0x3E965787054EDC94ULL
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
		0x0BD45DA8FD60C268ULL,
		0xAC0DDBEE5E434C50ULL,
		0xE4CE52ADF9AA074EULL,
		0x97479412974F7660ULL,
		0x426A5119F777764CULL,
		0x7D4DF386161A38D1ULL,
		0x5DF5BB335EDF7234ULL,
		0xF5BBDE6DDFD83B69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E68BB34CB87C7E9ULL,
		0x2067A388AD08D39EULL,
		0x018D84D264DF6865ULL,
		0x93A265B445EBFB5AULL,
		0x4877AA2B48112A89ULL,
		0x7CF68CA636330C02ULL,
		0x4054FBE835745665ULL,
		0x3730B1B7317BFBBEULL
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
		0x7CD5DDA3F4F5A069ULL,
		0x45AAACE602AFB60BULL,
		0xE26060C7A5EBEFEDULL,
		0x4ED9A8B99DC5604EULL,
		0x12902F98143D8C9AULL,
		0x077DABA2D3A9C0CCULL,
		0xD5C4FE437C83E8F7ULL,
		0x07A49822B1A57E9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4051060B63D4E2ULL,
		0x45ED714EC8BCE92EULL,
		0x3B92F65E493D77F6ULL,
		0x92D6EEEBD7DE2258ULL,
		0xF686C01055515A20ULL,
		0xFED4867286126B41ULL,
		0x0164802FB55CCDC7ULL,
		0xBF8ED836104DDCC6ULL
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
		0xCD4A0D8F4858966AULL,
		0x7A812944411B36F1ULL,
		0x7ABA4F6EB37ABC57ULL,
		0x23D0437D94E6BEA7ULL,
		0x12889E0671969FFCULL,
		0xE200738E13104C1FULL,
		0x90BF1001C630C60BULL,
		0xE8552DE597C453C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4A0D8F4858966AULL,
		0x7A812944411B36F1ULL,
		0x7ABA4F6EB37ABC57ULL,
		0x23D0437D94E6BEA7ULL,
		0x12889E0671969FFCULL,
		0xE200738E13104C1FULL,
		0x90BF1001C630C60BULL,
		0xE8552DE597C453C2ULL
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
		0x9FB6AA1A761B0216ULL,
		0xF84EB42DDD3DDFEDULL,
		0x6103748122BC2FDDULL,
		0x615D484A0732965FULL,
		0x3BD6319B7A5660C6ULL,
		0xE4A37A0789057543ULL,
		0x4ECA22C1B4CAAF90ULL,
		0xADE70051B0D167ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA7A693E47058449ULL,
		0x2FDFED699FE9A44BULL,
		0x0F0C29A2B47F9B84ULL,
		0x4747400727208562ULL,
		0x96061FB1ABFE5BB5ULL,
		0x60AAED8D3A1C8C4BULL,
		0xA1910E2E233444B7ULL,
		0xA1332B5029E527D2ULL
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
		0xCB09E033E2F8F33BULL,
		0xFFAE9B80FA1C47B9ULL,
		0x2315B16811CC5C66ULL,
		0x7E1FA092512CFBFCULL,
		0x8869CDE09B753185ULL,
		0x86ECAA5FEB03AFD6ULL,
		0x59B3E19298B9F7DFULL,
		0x38F7DCE06E02B6B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EBD562F9E4AB0CDULL,
		0xA59FE4BDF13D05FAULL,
		0x64D1DE9C1AC70E9FULL,
		0x563DACC363227B12ULL,
		0x3BE20C4BBE61F932ULL,
		0xD6700CA2A6A01E43ULL,
		0x5E53C8DA07BF9CA1ULL,
		0x643B50D33226681EULL
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
		0xD2BED4070D3BF175ULL,
		0x96F5DC9A599312A9ULL,
		0x0DC0AF4662133C6FULL,
		0x21B19E0AED2CBA53ULL,
		0x709F3BFB442BE7C7ULL,
		0x7FD8608BC4BBED1BULL,
		0x2EE05B6115B1C76AULL,
		0x0C9148A484DA4F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B303BB0FFE4EE7ULL,
		0xB47D8B48073A5D18ULL,
		0x91881196E971F1D2ULL,
		0x0E25F2F3044A3337ULL,
		0x752404CCF9CD1450ULL,
		0x77EBC1909838D342ULL,
		0x848B78638B358201ULL,
		0x75693048A66958D1ULL
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
		0x803CFB3F5F63B958ULL,
		0x9ACA4016E0198502ULL,
		0x52B30FFA12FE9E7CULL,
		0xDB2BB25B4B15BB57ULL,
		0x4637179DE3750B11ULL,
		0xE52D88F9B28781A7ULL,
		0x4E170DBF4318FFEDULL,
		0x4D7C790A0950210DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x803CFB3F5F63B958ULL,
		0x9ACA4016E0198502ULL,
		0x52B30FFA12FE9E7CULL,
		0xDB2BB25B4B15BB57ULL,
		0x4637179DE3750B11ULL,
		0xE52D88F9B28781A7ULL,
		0x4E170DBF4318FFEDULL,
		0x4D7C790A0950210DULL
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
		0xC135401F80D488C4ULL,
		0x58176B2DAE1BF6C1ULL,
		0xD21111B2ADC86365ULL,
		0x71896C402FCA8237ULL,
		0x13CCF928A4F68AA7ULL,
		0x73762E9A658B609FULL,
		0x6524984800F43C09ULL,
		0x81934E950C23D8BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3908DCF7D7DCAF4FULL,
		0x336F0D20CE590271ULL,
		0x78AE69BF06896429ULL,
		0x162E3F2946B07589ULL,
		0xD0A66E763C3C20BAULL,
		0x5980080DBB853120ULL,
		0xB6AC6CBD0EA8B5F3ULL,
		0xE3EC125561E8314BULL
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
		0x4BD49FA005AAC4A7ULL,
		0x13650850CBDB839AULL,
		0x4F6452C1E14C28D5ULL,
		0xE8ABBAA1C8C2B736ULL,
		0x1A77C2F0F87DCCBCULL,
		0x7AAC843CF3C8AB4DULL,
		0xAD44465BDE6B68EEULL,
		0x20E8CA8B30669AC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBFC6A1DD309B09EULL,
		0x63C1EB6FA1DF96D1ULL,
		0x90AE224D787BACE2ULL,
		0x8200B29572788735ULL,
		0xC17A2AE5DB8DE482ULL,
		0x19E300F847C53031ULL,
		0x0CEA4E8AD0058D1AULL,
		0x6F72B11C8E938A22ULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCE967914AE32A85BULL,
		0x51338EB26E05959EULL,
		0x77DEA71A2AE29C8EULL,
		0x1F10520F147CBC5CULL,
		0x55A0058FA062ACE9ULL,
		0x8B57C5D383C86B5CULL,
		0x3AAD1D2B213010ECULL,
		0x45BE47E47C2B298DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB74460B606A983A8ULL,
		0x37E8B52C9CA47404ULL,
		0xF79D603AA98C0557ULL,
		0xFDFE0EBA777F0374ULL,
		0xE720D666011C8E61ULL,
		0xC80765A6AC3F354FULL,
		0x9E2C0912E4D7E584ULL,
		0xA14B03F6D6A2E798ULL
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
		0xA6C81BBC4FDB6813ULL,
		0x326BC11898E47324ULL,
		0x281A14B8676298DCULL,
		0x9D7CF08CFBFC311FULL,
		0x4161E49701852780ULL,
		0xCEDC87B90B868A91ULL,
		0x9897E0F05FBFEA7AULL,
		0xC6E99CBD0CD71A02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6C81BBC4FDB6813ULL,
		0x326BC11898E47324ULL,
		0x281A14B8676298DCULL,
		0x9D7CF08CFBFC311FULL,
		0x4161E49701852780ULL,
		0xCEDC87B90B868A91ULL,
		0x9897E0F05FBFEA7AULL,
		0xC6E99CBD0CD71A02ULL
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
		0xA3D4298108B6FE57ULL,
		0x9BED26118C7B0364ULL,
		0x650F48A1150FA691ULL,
		0xE40B1DF768780BE0ULL,
		0x3D06DC5D502E2EB6ULL,
		0xDC8901A15913EAB0ULL,
		0x94EC6F34776E4634ULL,
		0xB077B8AD3592B852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A82C1132968085EULL,
		0xB4FE8FB72E05A7B4ULL,
		0x25B3CA4B2699C8F0ULL,
		0x5DC45246B3115409ULL,
		0xEA8E471AA259A995ULL,
		0x53EFB05BD56D0214ULL,
		0xFE0412CCE094395EULL,
		0xE81830C0A80A4587ULL
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
		0x7A5F546B8A06E1B2ULL,
		0x480F5122A07D0033ULL,
		0x6687B1F3EA638EE3ULL,
		0xF195078C193FD9A3ULL,
		0x7861CAAE64308664ULL,
		0x3FB156E84B4FD7B1ULL,
		0xE00E2E25DE698F48ULL,
		0x3C34F2D2A68BA9C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DAFE02798A97DAEULL,
		0x1807FFEFE05885A4ULL,
		0x8F5AF778397C4685ULL,
		0x3D79BBB046FB83D8ULL,
		0xDB52EA40EA2D07A6ULL,
		0x59245CC40F9BB35EULL,
		0x60DDD0B37BD635D3ULL,
		0x82CB27B83AEC8829ULL
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
		0x82D7F27C6448521CULL,
		0x21C23CC6444F50D2ULL,
		0x2F0762F2A654FC29ULL,
		0x18AD7357AE389203ULL,
		0x9096BA4BBE0D17CAULL,
		0xF269E0C09B49A10CULL,
		0x291FB38CDE490DC5ULL,
		0x6282792FE322B56CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD72A2CAAD4869AULL,
		0x235A689FFEE45E66ULL,
		0x79F809DDF92974B9ULL,
		0x41D11DAF9E619471ULL,
		0x894C6ABD222C5452ULL,
		0x99D85032D918895DULL,
		0x0B3E1A7D977FD6E0ULL,
		0xB127CD6E98C6BE0DULL
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