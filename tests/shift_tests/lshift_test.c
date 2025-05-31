#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x97D929CF711D45BCULL,
		0x899298461DFD83C1ULL,
		0x7FE038A55558D53CULL,
		0x00F3E932C8614785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA73DC47516F00000ULL,
		0x611877F60F065F64ULL,
		0xE295556354F2264AULL,
		0xA4CB21851E15FF80ULL,
		0x00000000000003CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int shift = 18;
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
		0xAC9E718BF03B8F87ULL,
		0x863044169B349ECFULL,
		0xDA9E4E3A1F7C9C14ULL,
		0x31AC8243E0B0BE07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF870000000000000ULL,
		0xECFAC9E718BF03B8ULL,
		0xC14863044169B349ULL,
		0xE07DA9E4E3A1F7C9ULL,
		0x00031AC8243E0B0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x5B612DBC97876C18ULL,
		0x623E4A10E4E9E1A5ULL,
		0x57ED30609186F574ULL,
		0x1350EE1ECD9C5C56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E1DB06000000000ULL,
		0x93A786956D84B6F2ULL,
		0x461BD5D188F92843ULL,
		0x367171595FB4C182ULL,
		0x000000004D43B87BULL
	}};
	shift = 226;
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
		0xB44C30007037849BULL,
		0x159C2F30E69F45E9ULL,
		0xB0E423DFE69DE1F4ULL,
		0x29FBF1F2E082CF17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C30007037849B00ULL,
		0x9C2F30E69F45E9B4ULL,
		0xE423DFE69DE1F415ULL,
		0xFBF1F2E082CF17B0ULL,
		0x0000000000000029ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
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
		0x8ABD0633DCB865C1ULL,
		0x75B72547B69E11ADULL,
		0x647E63A17305C314ULL,
		0x4E22FDA10740DB50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5E8319EE5C32E080ULL,
		0xDB92A3DB4F08D6C5ULL,
		0x3F31D0B982E18A3AULL,
		0x117ED083A06DA832ULL,
		0x0000000000000027ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
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
		0x767DDBA2DA1CE3BCULL,
		0x74691E0781CCE29AULL,
		0x0CD60359FAF875DCULL,
		0x295DF91C99640FD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x439C778000000000ULL,
		0x399C534ECFBB745BULL,
		0x5F0EBB8E8D23C0F0ULL,
		0x2C81FAC19AC06B3FULL,
		0x000000052BBF2393ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x3276E92E45FC3423ULL,
		0x0CD564A3019BDE86ULL,
		0x1907EDAD55407B67ULL,
		0x71AE0E88475107A0ULL,
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
		0x8C9DBA4B917F0D08ULL,
		0xC3355928C066F7A1ULL,
		0x0641FB6B55501ED9ULL,
		0x1C6B83A211D441E8ULL
	}};
	shift = 254;
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
		0x8BE1D277611EC829ULL,
		0xE14CD4ED652A4BEBULL,
		0x9C125AA6A886D024ULL,
		0x1C8DFF40D96C0757ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D90520000000000ULL,
		0x5497D717C3A4EEC2ULL,
		0x0DA049C299A9DACAULL,
		0xD80EAF3824B54D51ULL,
		0x000000391BFE81B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x0EABD585519183A8ULL,
		0x9E28FDF3B04F7DACULL,
		0xA792AADC89059ADDULL,
		0x194483A6BFB17950ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D40000000000000ULL,
		0xED60755EAC2A8C8CULL,
		0xD6ECF147EF9D827BULL,
		0xCA853C9556E4482CULL,
		0x0000CA241D35FD8BULL,
		0x0000000000000000ULL
	}};
	shift = 179;
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
		0x90DAC851C85226EEULL,
		0x5ECFFA3478805DFCULL,
		0xF5CDEC7B454CAD26ULL,
		0x25C08929DB0FA858ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390A44DDC0000000ULL,
		0x8F100BBF921B590AULL,
		0x68A995A4CBD9FF46ULL,
		0x3B61F50B1EB9BD8FULL,
		0x0000000004B81125ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x3BA31E3362357503ULL,
		0xC648DB60BCA4143FULL,
		0xB1C74E5869A56014ULL,
		0x2D60DFAB39FC1585ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D5D40C000000000ULL,
		0x29050FCEE8C78CD8ULL,
		0x695805319236D82FULL,
		0x7F05616C71D3961AULL,
		0x0000000B5837EACEULL
	}};
	shift = 230;
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
		0x18DA13417F24B2CDULL,
		0xF1C491B3E935F188ULL,
		0x75D8D0DA991685DEULL,
		0x0B4AC6D21055E830ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5966800000000000ULL,
		0xF8C40C6D09A0BF92ULL,
		0x42EF78E248D9F49AULL,
		0xF4183AEC686D4C8BULL,
		0x000005A56369082AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0xDB20663A3123DA36ULL,
		0x0D32DE17E331DBE7ULL,
		0x98FF3FE3B7CE0871ULL,
		0x006C3393A4AB63F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xF6C8198E8C48F68DULL,
		0x434CB785F8CC76F9ULL,
		0x663FCFF8EDF3821CULL,
		0x001B0CE4E92AD8FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0x436437BC57269231ULL,
		0x67CA12000A6121B5ULL,
		0x30EEB763EC7638BCULL,
		0x46B594B47DD512B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9349188000000000ULL,
		0x3090DAA1B21BDE2BULL,
		0x3B1C5E33E5090005ULL,
		0xEA895B18775BB1F6ULL,
		0x000000235ACA5A3EULL,
		0x0000000000000000ULL
	}};
	shift = 167;
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
		0x6B8A4DEC9D03296DULL,
		0xDF0E5293E6B19071ULL,
		0x3AC36782D2561D98ULL,
		0x5A0BC92C4F657831ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CA5B40000000000ULL,
		0xC641C5AE2937B274ULL,
		0x5876637C394A4F9AULL,
		0x95E0C4EB0D9E0B49ULL,
		0x000001682F24B13DULL
	}};
	shift = 234;
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
		0xEFB6E3D4BC439957ULL,
		0x057C445CC684898BULL,
		0xF5E1A314D033051BULL,
		0x55792A878EE5BB2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC439957000000000ULL,
		0x684898BEFB6E3D4BULL,
		0x033051B057C445CCULL,
		0xEE5BB2EF5E1A314DULL,
		0x000000055792A878ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xD4DC86595CDCB5E5ULL,
		0x6F0EDA565A0ACD41ULL,
		0x6439CC17DAA7265FULL,
		0x56B76DD7DE7336B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2CAE6E5AF2800000ULL,
		0x2B2D0566A0EA6E43ULL,
		0x0BED53932FB7876DULL,
		0xEBEF399B58B21CE6ULL,
		0x00000000002B5BB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0xBFA130095AE672BCULL,
		0xD6AF07A5D4FEEBFBULL,
		0x5AE24341C3028FEAULL,
		0x02F473B54A3570A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x77F426012B5CCE57ULL,
		0x5AD5E0F4BA9FDD7FULL,
		0x0B5C4868386051FDULL,
		0x005E8E76A946AE15ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0xBCBF1C84D6332661ULL,
		0x943A4A79E064290FULL,
		0xB8BF5F07D580DF34ULL,
		0x7F61E41C7B8DFF18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B19933080000000ULL,
		0xF0321487DE5F8E42ULL,
		0xEAC06F9A4A1D253CULL,
		0x3DC6FF8C5C5FAF83ULL,
		0x000000003FB0F20EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xFF83904CBDBB1B02ULL,
		0x55C8665F3696454AULL,
		0x2A63985FF0BE6E1FULL,
		0x0384B895ECC79814ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8265EDD8D8100000ULL,
		0x32F9B4B22A57FC1CULL,
		0xC2FF85F370FAAE43ULL,
		0xC4AF663CC0A1531CULL,
		0x0000000000001C25ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
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
		0xADB9C3EC4F06BF23ULL,
		0xFF9F93C176A98DA5ULL,
		0x5FD9DDCF4C41B1B8ULL,
		0x32A8E2B7A87AEBE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D89E0D7E4600000ULL,
		0x782ED531B4B5B738ULL,
		0xB9E98836371FF3F2ULL,
		0x56F50F5D7C6BFB3BULL,
		0x000000000006551CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x49EA80AEB7328E70ULL,
		0xF79A655879F5A666ULL,
		0xC5BC394AF78C6016ULL,
		0x5070B84EC5425B42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x540575B994738000ULL,
		0xD32AC3CFAD33324FULL,
		0xE1CA57BC6300B7BCULL,
		0x85C2762A12DA162DULL,
		0x0000000000000283ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xA80B82B686F7E1DFULL,
		0x664BD99CC4F29C30ULL,
		0xC21E4DDC699AC191ULL,
		0x71EE3AF2F429D1CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3BE000000000000ULL,
		0x38615017056D0DEFULL,
		0x8322CC97B33989E5ULL,
		0xA39B843C9BB8D335ULL,
		0x0000E3DC75E5E853ULL
	}};
	shift = 241;
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
		0xC80E3474ED75106AULL,
		0xEB4202BA72A731A9ULL,
		0xD548A11A14275481ULL,
		0x365841ED42EDF602ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED75106A0000000ULL,
		0xA72A731A9C80E347ULL,
		0xA14275481EB4202BULL,
		0xD42EDF602D548A11ULL,
		0x000000000365841EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xC81174A71CAB0373ULL,
		0x6950F862517D6CDAULL,
		0xD84DD75205560864ULL,
		0x02F3DFAADD1B5FBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE94E395606E60000ULL,
		0xF0C4A2FAD9B59022ULL,
		0xAEA40AAC10C8D2A1ULL,
		0xBF55BA36BF7DB09BULL,
		0x00000000000005E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
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
		0xEA03EECBF54CB625ULL,
		0x9C33FD0E9F365A9BULL,
		0x6581650BD5B2C54AULL,
		0x64C71694EC8D7B45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0xBEA03EECBF54CB62ULL,
		0xA9C33FD0E9F365A9ULL,
		0x56581650BD5B2C54ULL,
		0x064C71694EC8D7B4ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0x24B1A864B6C222C9ULL,
		0xCFD9305558946D70ULL,
		0xFA91B590C473DF87ULL,
		0x0A54B237E32E5044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB088B2400000000ULL,
		0x6251B5C092C6A192ULL,
		0x11CF7E1F3F64C155ULL,
		0x8CB94113EA46D643ULL,
		0x000000002952C8DFULL,
		0x0000000000000000ULL
	}};
	shift = 162;
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
		0x8B727B179CB6CFC6ULL,
		0xFF963EECD4185665ULL,
		0xF70C0911BBF484A8ULL,
		0x4DB40B1AFD61EFDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC600000000000000ULL,
		0x658B727B179CB6CFULL,
		0xA8FF963EECD41856ULL,
		0xDAF70C0911BBF484ULL,
		0x004DB40B1AFD61EFULL
	}};
	shift = 248;
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
		0x5B7E304528EEA3BBULL,
		0x434486B8A00C8876ULL,
		0x1FAD9A6A534DA1C9ULL,
		0x1EC45193C09E7C93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E304528EEA3BB00ULL,
		0x4486B8A00C88765BULL,
		0xAD9A6A534DA1C943ULL,
		0xC45193C09E7C931FULL,
		0x000000000000001EULL,
		0x0000000000000000ULL
	}};
	shift = 136;
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
		0xD8EE1AD60421135BULL,
		0xF4B79A106CD54C73ULL,
		0x9B327F98D178117EULL,
		0x43319BED6DA24276ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8EE1AD60421135BULL,
		0xF4B79A106CD54C73ULL,
		0x9B327F98D178117EULL,
		0x43319BED6DA24276ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0xF03133B1D58CB8E1ULL,
		0x6F25F5066524960EULL,
		0x3CA18FECCFAFCCD9ULL,
		0x55E9D03E66A17E3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0xEF03133B1D58CB8EULL,
		0x96F25F5066524960ULL,
		0xE3CA18FECCFAFCCDULL,
		0x055E9D03E66A17E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
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
		0xFEC0818809F63471ULL,
		0xA2E65F9E6CE75A36ULL,
		0x04003A41DC2FBF69ULL,
		0x5060F7134E8BFE35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xDFD81031013EC68EULL,
		0x345CCBF3CD9CEB46ULL,
		0xA08007483B85F7EDULL,
		0x0A0C1EE269D17FC6ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x2236330C42B4290AULL,
		0xDC8199816BFAC4F1ULL,
		0xDB0DDC72BBA625A9ULL,
		0x65A56473EAD6E108ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x290A000000000000ULL,
		0xC4F12236330C42B4ULL,
		0x25A9DC8199816BFAULL,
		0xE108DB0DDC72BBA6ULL,
		0x000065A56473EAD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xCCA517A5BDBEE412ULL,
		0xBD8E3AD46E6B5644ULL,
		0x3DB7ADFCFF9625A7ULL,
		0x3A4F3E6616E17BFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5BDBEE412000000ULL,
		0xD46E6B5644CCA517ULL,
		0xFCFF9625A7BD8E3AULL,
		0x6616E17BFC3DB7ADULL,
		0x00000000003A4F3EULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x3BFEF591354BC689ULL,
		0xFF77B0898A51D3CAULL,
		0x8A54837AADB22D13ULL,
		0x1679A18153A2099FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDEB226A978D120ULL,
		0xEEF611314A3A7947ULL,
		0x4A906F55B645A27FULL,
		0xCF34302A744133F1ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x0C980DF7FD172829ULL,
		0x5C99AC6D1214735AULL,
		0x1F21C89D60CA11DAULL,
		0x3975490603159978ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x8326037DFF45CA0AULL,
		0x97266B1B44851CD6ULL,
		0x07C8722758328476ULL,
		0x0E5D524180C5665EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0x58E9B19610093D33ULL,
		0xB61931175BE8E8B9ULL,
		0x5546A2D4C1A29264ULL,
		0x075A8DC37DCE34E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x049E998000000000ULL,
		0xF4745CAC74D8CB08ULL,
		0xD149325B0C988BADULL,
		0xE71A72AAA3516A60ULL,
		0x00000003AD46E1BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x33D6B33633B0AF59ULL,
		0x5C915B9F7810B5E8ULL,
		0x413DF47167E7FB38ULL,
		0x40BA912348121D41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC2BD64000000000ULL,
		0x042D7A0CF5ACCD8CULL,
		0xF9FECE172456E7DEULL,
		0x048750504F7D1C59ULL,
		0x000000102EA448D2ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
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
		0xFABD65B71AAA1B98ULL,
		0xF62976A9F436F6E9ULL,
		0x30455B4C5413E650ULL,
		0x19B5CE1AFD83B00EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB980000000000000ULL,
		0x6E9FABD65B71AAA1ULL,
		0x650F62976A9F436FULL,
		0x00E30455B4C5413EULL,
		0x00019B5CE1AFD83BULL
	}};
	shift = 244;
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
		0x7A45CFB75DDF51A0ULL,
		0xBDAD57D3881592E0ULL,
		0xB6AA3E9B94D041E5ULL,
		0x38A9D16DC66CF92CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9173EDD777D46800ULL,
		0x6B55F4E20564B81EULL,
		0xAA8FA6E53410796FULL,
		0x2A745B719B3E4B2DULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 134;
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
		0x116C4C528C651E8DULL,
		0xCF301C08726EC10AULL,
		0xC3E10B2CA2C9E03BULL,
		0x5522A10813F14E23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F46800000000000ULL,
		0x608508B626294632ULL,
		0xF01DE7980E043937ULL,
		0xA711E1F085965164ULL,
		0x00002A91508409F8ULL
	}};
	shift = 239;
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
		0x88A604A1552E7C37ULL,
		0x5FCAF1828E5E18BFULL,
		0x0AC441C8519011ECULL,
		0x24EADBCE5B2F9CB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5CF86E00000000ULL,
		0x1CBC317F114C0942ULL,
		0xA32023D8BF95E305ULL,
		0xB65F396815888390ULL,
		0x0000000049D5B79CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xBEB6BDC5F2BE975FULL,
		0x14986EA0CC2B0559ULL,
		0xAB7ED8D87265F078ULL,
		0x760CCA7FAECD8B92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADAF717CAFA5D7CULL,
		0x5261BA8330AC1566ULL,
		0xADFB6361C997C1E0ULL,
		0xD83329FEBB362E4AULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x7C66B467D8D807FDULL,
		0x50819FBB8962D18AULL,
		0xECEFF9D363501F58ULL,
		0x3B3FD2F31882CA9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB467D8D807FD0000ULL,
		0x9FBB8962D18A7C66ULL,
		0xF9D363501F585081ULL,
		0xD2F31882CA9CECEFULL,
		0x0000000000003B3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
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
		0x643C31648039AF15ULL,
		0xEF952ECB8678E606ULL,
		0x074765B06C206AF8ULL,
		0x68042E2D0C7DA27DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8039AF1500000000ULL,
		0x8678E606643C3164ULL,
		0x6C206AF8EF952ECBULL,
		0x0C7DA27D074765B0ULL,
		0x0000000068042E2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x8FC6F30C8073CE17ULL,
		0xFA84DDF4F95BDB48ULL,
		0x1711DAE1E935FC81ULL,
		0x2083D4CD8CC68DD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7E379864039E70B8ULL,
		0xD426EFA7CADEDA44ULL,
		0xB88ED70F49AFE40FULL,
		0x041EA66C66346EB0ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
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
		0x9C77007B03043C7CULL,
		0x188599E5A1A88EE1ULL,
		0x5DC320DB224A22B4ULL,
		0x3CBC5ABFFF41E7D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x007B03043C7C0000ULL,
		0x99E5A1A88EE19C77ULL,
		0x20DB224A22B41885ULL,
		0x5ABFFF41E7D45DC3ULL,
		0x0000000000003CBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
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
		0x3EB54C2A73344C31ULL,
		0xEE824F4B0807ED26ULL,
		0x1EE6508180E35D76ULL,
		0x4A8C7379436ABFDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAD530A9CCD130C4ULL,
		0xBA093D2C201FB498ULL,
		0x7B994206038D75DBULL,
		0x2A31CDE50DAAFF7CULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
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
		0x83D53691767F87E9ULL,
		0x89BB572585FF543DULL,
		0x87FF0190EDFC0B58ULL,
		0x1C876D9DA2539B5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F87E90000000000ULL,
		0xFF543D83D5369176ULL,
		0xFC0B5889BB572585ULL,
		0x539B5C87FF0190EDULL,
		0x0000001C876D9DA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x613ED19839F50303ULL,
		0x2E73C8055EDB6FC0ULL,
		0x1EDF8EACE5642FEFULL,
		0x73CEF9724882B2FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0x0613ED19839F5030ULL,
		0xF2E73C8055EDB6FCULL,
		0xF1EDF8EACE5642FEULL,
		0x073CEF9724882B2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0xE6605B40D97BDD10ULL,
		0x8B68037322605B4EULL,
		0xA437F2DD68F4A771ULL,
		0x23ED3DEA8D0F3EB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DA06CBDEE880000ULL,
		0x01B991302DA77330ULL,
		0xF96EB47A53B8C5B4ULL,
		0x9EF546879F5A521BULL,
		0x00000000000011F6ULL
	}};
	shift = 207;
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
		0x74CC5C341204F7BAULL,
		0xB411581613640C33ULL,
		0xED5CE83EAB0A85A7ULL,
		0x5F6B5F3B3CC66E4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A09027BDD000000ULL,
		0x0B09B20619BA662EULL,
		0x1F558542D3DA08ACULL,
		0x9D9E633726F6AE74ULL,
		0x00000000002FB5AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x9F467497D23C7D81ULL,
		0xEF6C8258B7EF6723ULL,
		0x86F78DB7A779911EULL,
		0x5E034F758D634AA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xCFA33A4BE91E3EC0ULL,
		0x77B6412C5BF7B391ULL,
		0x437BC6DBD3BCC88FULL,
		0x2F01A7BAC6B1A550ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0xD32D31B0F400C743ULL,
		0x40AC1543E217F126ULL,
		0xE715889ED942C351ULL,
		0x6B332F30F7753027ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4C6C3D0031D0C0ULL,
		0x2B0550F885FC49B4ULL,
		0xC56227B650B0D450ULL,
		0xCCCBCC3DDD4C09F9ULL,
		0x000000000000001AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x61383E76BEF8EFDBULL,
		0x090A453C704A8B59ULL,
		0x7C5ACD103907603DULL,
		0x42DE1A97C938D1CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7CED7DF1DFB60000ULL,
		0x8A78E09516B2C270ULL,
		0x9A20720EC07A1214ULL,
		0x352F9271A39EF8B5ULL,
		0x00000000000085BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
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
		0xCAA085722BE31232ULL,
		0x11E1FD30B4E23A00ULL,
		0x165769AA26A42AE6ULL,
		0x52EE148A0820512BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85722BE312320000ULL,
		0xFD30B4E23A00CAA0ULL,
		0x69AA26A42AE611E1ULL,
		0x148A0820512B1657ULL,
		0x00000000000052EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x7441F2AD7ADE2F72ULL,
		0x941C361B2BBD322CULL,
		0xB6D329CD713D2F29ULL,
		0x34DDB3D1791C6421ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BD6F17B90000000ULL,
		0xD95DE99163A20F95ULL,
		0x6B89E9794CA0E1B0ULL,
		0x8BC8E3210DB6994EULL,
		0x0000000001A6ED9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x8BBE6BF8E8ED185BULL,
		0x8744E86C546DF374ULL,
		0xA999F330C28086FBULL,
		0x27AFA16983CFF58AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEF9AFE3A3B4616C0ULL,
		0xD13A1B151B7CDD22ULL,
		0x667CCC30A021BEE1ULL,
		0xEBE85A60F3FD62AAULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
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
		0x531B89E640FA406AULL,
		0xBD979859E5BD1856ULL,
		0x49138F0A2976E345ULL,
		0x42B7B889022A16F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x713CC81F480D4000ULL,
		0xF30B3CB7A30ACA63ULL,
		0x71E1452EDC68B7B2ULL,
		0xF711204542DEC922ULL,
		0x0000000000000856ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xF0E970CAA24378EBULL,
		0x20D98D60E2C0EDFAULL,
		0x96DE629C31ECC7FFULL,
		0x345E69F966CC33E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D60000000000000ULL,
		0xBF5E1D2E1954486FULL,
		0xFFE41B31AC1C581DULL,
		0x7D32DBCC53863D98ULL,
		0x00068BCD3F2CD986ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x1CE8EE25D8315F2CULL,
		0x7501EDCFA62B0B80ULL,
		0x4A9760850D52F5A4ULL,
		0x06B06DF3B2E4109BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB89760C57CB00000ULL,
		0xB73E98AC2E0073A3ULL,
		0x8214354BD691D407ULL,
		0xB7CECB90426D2A5DULL,
		0x0000000000001AC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
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
		0xA88C579BC336B354ULL,
		0xB0EB91F37E3D0279ULL,
		0x533B69813B331260ULL,
		0x401526973DA9D894ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66D66A8000000000ULL,
		0xC7A04F35118AF378ULL,
		0x66624C161D723E6FULL,
		0xB53B128A676D3027ULL,
		0x0000000802A4D2E7ULL
	}};
	shift = 229;
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
		0x60EECD7FBBA91ED7ULL,
		0x55302CBA583D1430ULL,
		0xD14E3A41C63A3577ULL,
		0x0E7B165ED4998423ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EECD7FBBA91ED70ULL,
		0x5302CBA583D14306ULL,
		0x14E3A41C63A35775ULL,
		0xE7B165ED4998423DULL,
		0x0000000000000000ULL
	}};
	shift = 196;
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
		0x6382C12794F1F4B1ULL,
		0x70225785B6578B99ULL,
		0x4F9EB57F21152EB4ULL,
		0x29115EA4A7F2FFE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12794F1F4B100000ULL,
		0x785B6578B996382CULL,
		0x57F21152EB470225ULL,
		0xEA4A7F2FFE04F9EBULL,
		0x0000000000029115ULL
	}};
	shift = 212;
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
		0xD269E991AC20E1F7ULL,
		0xC7E7E05EB7C96DCFULL,
		0xF902DAB0001FFF6DULL,
		0x6939279F30F4D9D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E991AC20E1F7000ULL,
		0x7E05EB7C96DCFD26ULL,
		0x2DAB0001FFF6DC7EULL,
		0x9279F30F4D9D2F90ULL,
		0x0000000000000693ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xD82A5AE06253138FULL,
		0xB097BFBF516E3365ULL,
		0x1544496B41533250ULL,
		0x149AE0DFC47EE03EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E3C00000000000ULL,
		0x8CD9760A96B81894ULL,
		0xCC942C25EFEFD45BULL,
		0xB80F8551125AD054ULL,
		0x00000526B837F11FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x7ABC0D3D5C2D214FULL,
		0xD2C9C08C5B831ECCULL,
		0xCB6444FFBF7F3077ULL,
		0x058C34898A095667ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7ABC0D3D5C2D214FULL,
		0xD2C9C08C5B831ECCULL,
		0xCB6444FFBF7F3077ULL,
		0x058C34898A095667ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0xB72F5FB94E4453B8ULL,
		0xA4111A81622DEBD3ULL,
		0xD16A6E6D8E70A094ULL,
		0x3A68B0A284C515E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEE00000000000000ULL,
		0xF4EDCBD7EE539114ULL,
		0x25290446A0588B7AULL,
		0x78745A9B9B639C28ULL,
		0x000E9A2C28A13145ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0xE79E7F70C7419CA8ULL,
		0xAB36B7813F738FA3ULL,
		0xF327CF22C34387ABULL,
		0x683C81A93CEB80CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79E7F70C7419CA80ULL,
		0xB36B7813F738FA3EULL,
		0x327CF22C34387ABAULL,
		0x83C81A93CEB80CDFULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x842BEFCF6D24AB3BULL,
		0xD770E314F5EE306AULL,
		0xF3E01CCD8F046648ULL,
		0x752560676D04F313ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFBF3DB492ACEC00ULL,
		0xC38C53D7B8C1AA10ULL,
		0x8073363C1199235DULL,
		0x95819DB413CC4FCFULL,
		0x00000000000001D4ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
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
		0x2D30181C1CD717A5ULL,
		0x62A022E64189D4E5ULL,
		0x68B783D55E8DB727ULL,
		0x4F31FCE8E201618FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x839AE2F4A0000000ULL,
		0xC8313A9CA5A60303ULL,
		0xABD1B6E4EC54045CULL,
		0x1C402C31ED16F07AULL,
		0x0000000009E63F9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
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
		0x01823B9377F5D162ULL,
		0xA667314FC3D3261BULL,
		0xC986DB875D8EB566ULL,
		0x44854F4EE5768438ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C11DC9BBFAE8B10ULL,
		0x33398A7E1E9930D8ULL,
		0x4C36DC3AEC75AB35ULL,
		0x242A7A772BB421C6ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x4DEA368BEB6D76F6ULL,
		0x45CAF4645E79519EULL,
		0xEE6334954C18181AULL,
		0x63A1EA270865A06BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x937A8DA2FADB5DBDULL,
		0x9172BD19179E5467ULL,
		0xFB98CD2553060606ULL,
		0x18E87A89C219681AULL,
		0x0000000000000000ULL
	}};
	shift = 190;
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
		0xC8851C2D9657CCE6ULL,
		0xFF0B9CAA1A171B74ULL,
		0xB517168112071B4BULL,
		0x3CB07497DCE3F835ULL,
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
		0x9910A385B2CAF99CULL,
		0x7FE173954342E36EULL,
		0xB6A2E2D02240E369ULL,
		0x07960E92FB9C7F06ULL
	}};
	shift = 253;
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
		0xA267036C7F9C0669ULL,
		0x1695DC87294DFA6FULL,
		0x028DDA66840612BDULL,
		0x4A95640CEA4E8DCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380CD20000000000ULL,
		0x9BF4DF44CE06D8FFULL,
		0x0C257A2D2BB90E52ULL,
		0x9D1B9C051BB4CD08ULL,
		0x000000952AC819D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x4EF98058227A8F4EULL,
		0x63760F081BD3C4D3ULL,
		0x3D3FF7A2A36DFA1CULL,
		0x49109AF653781B8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16089EA3D3800000ULL,
		0xC206F4F134D3BE60ULL,
		0xE8A8DB7E8718DD83ULL,
		0xBD94DE06E38F4FFDULL,
		0x0000000000124426ULL
	}};
	shift = 214;
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
		0x961E7F1BDE07D57FULL,
		0x887CCD9439068376ULL,
		0xF7AA0D6DB93F9B12ULL,
		0x161EA47A168B4A19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB0F3F8DEF03EABF8ULL,
		0x43E66CA1C8341BB4ULL,
		0xBD506B6DC9FCD894ULL,
		0xB0F523D0B45A50CFULL,
		0x0000000000000000ULL
	}};
	shift = 195;
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
		0x8BBF77CEB9CD279DULL,
		0x66383B1960FB1A79ULL,
		0xC2120AEA1B97BDE7ULL,
		0x66C2A3C95B22D0C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7349E74000000000ULL,
		0x3EC69E62EFDDF3AEULL,
		0xE5EF79D98E0EC658ULL,
		0xC8B430F08482BA86ULL,
		0x00000019B0A8F256ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xC99AC0C6B743DCCCULL,
		0x351BE74CF2F78FB5ULL,
		0x5A3CF19BBAC10F06ULL,
		0x4914735AEFB6F049ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC99AC0C6B743DCCCULL,
		0x351BE74CF2F78FB5ULL,
		0x5A3CF19BBAC10F06ULL,
		0x4914735AEFB6F049ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0x44165CF9BE5A5348ULL,
		0x46ACD2012EA52D23ULL,
		0xC933AE77D582D713ULL,
		0x1769E18DC4CE012EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B2E7CDF2D29A400ULL,
		0x56690097529691A2ULL,
		0x99D73BEAC16B89A3ULL,
		0xB4F0C6E267009764ULL,
		0x000000000000000BULL
	}};
	shift = 199;
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
		0xD283780D921D60DFULL,
		0x9041AE3725772326ULL,
		0x5BD423988CF0F440ULL,
		0x74F003FFACCB4CB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1BC06C90EB06F800ULL,
		0x0D71B92BB9193694ULL,
		0xA11CC46787A20482ULL,
		0x801FFD665A6592DEULL,
		0x00000000000003A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
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
		0x6509984F1EC92240ULL,
		0xDC27B0E0CE0920AAULL,
		0xC2901A56108D4DACULL,
		0x15F38EAD0CD459A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CC278F649120000ULL,
		0x3D87067049055328ULL,
		0x80D2B0846A6D66E1ULL,
		0x9C756866A2CD3E14ULL,
		0x00000000000000AFULL
	}};
	shift = 203;
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
		0xEEAC325752162352ULL,
		0x8E4D8D2FD4B51C5BULL,
		0xF3AFD8B20CA45519ULL,
		0x3BFCC17404953EC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x7DD5864AEA42C46AULL,
		0x31C9B1A5FA96A38BULL,
		0x1E75FB1641948AA3ULL,
		0x077F982E8092A7D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
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
		0x99E75468F19FE4F1ULL,
		0xBB46F5D911F3FCE2ULL,
		0x2C3E20AB45059A3BULL,
		0x457B90C24323FCB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CFF278800000000ULL,
		0x8F9FE714CF3AA347ULL,
		0x282CD1DDDA37AEC8ULL,
		0x191FE5C161F1055AULL,
		0x000000022BDC8612ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
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
		0xD50ABFB42B5C4585ULL,
		0xCD656EE28497B6D0ULL,
		0x7B2BAF0B38EB1867ULL,
		0x1D1929EC8999DEC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xED0AD71161400000ULL,
		0xB8A125EDB43542AFULL,
		0xC2CE3AC619F3595BULL,
		0x7B226677B15ECAEBULL,
		0x000000000007464AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x123F3639BA28B9D2ULL,
		0xE0D335F2AF91D5B4ULL,
		0xC003D5A0B2480579ULL,
		0x1CCA90A8FBD78C39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBA28B9D200000000ULL,
		0xAF91D5B4123F3639ULL,
		0xB2480579E0D335F2ULL,
		0xFBD78C39C003D5A0ULL,
		0x000000001CCA90A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0xE27FCB0DD9E26898ULL,
		0x6666E4AE1B50D123ULL,
		0x87D51DCEAA56FD71ULL,
		0x5A2917A25AACA392ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD9E26898000000ULL,
		0xAE1B50D123E27FCBULL,
		0xCEAA56FD716666E4ULL,
		0xA25AACA39287D51DULL,
		0x00000000005A2917ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xDCBF6884CB8EDFB8ULL,
		0x44035383257B5B19ULL,
		0xFD8649DF09390953ULL,
		0x0A30FAEF072EC857ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0x33B97ED109971DBFULL,
		0xA68806A7064AF6B6ULL,
		0xAFFB0C93BE127212ULL,
		0x001461F5DE0E5D90ULL
	}};
	shift = 249;
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
		0xE45233241388E9C5ULL,
		0x238CA0383C4600B7ULL,
		0xACE444E5B5E19E17ULL,
		0x75AD6B4C3F3BAA60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4E28000000000000ULL,
		0x05BF229199209C47ULL,
		0xF0B91C6501C1E230ULL,
		0x53056722272DAF0CULL,
		0x0003AD6B5A61F9DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
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
		0x808511CEB3BC3D06ULL,
		0x419F3F56D1781E0EULL,
		0x6F339474854256DEULL,
		0x7FAC55E141FF7FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F41800000000000ULL,
		0x0783A0214473ACEFULL,
		0x95B79067CFD5B45EULL,
		0xDFF21BCCE51D2150ULL,
		0x00001FEB1578507FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x1D098AC40A25A802ULL,
		0x41D55A57E2F18498ULL,
		0x8F519F03BD24F668ULL,
		0x0E8AC93E93E2FDF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0512D40100000000ULL,
		0xF178C24C0E84C562ULL,
		0xDE927B3420EAAD2BULL,
		0x49F17EF9C7A8CF81ULL,
		0x000000000745649FULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0xCA0250019FF6FEB1ULL,
		0xA961A6BB342960F0ULL,
		0x9643145349431D54ULL,
		0x22BF2E494602E731ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A0033FEDFD62000ULL,
		0x34D766852C1E1940ULL,
		0x628A692863AA952CULL,
		0xE5C928C05CE632C8ULL,
		0x0000000000000457ULL
	}};
	shift = 205;
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
		0x3398D33DBE06DB21ULL,
		0xDF47974C5EF3EB61ULL,
		0xEE1E08AFB80872D8ULL,
		0x48DE942D48D71F71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF036D9080000000ULL,
		0x2F79F5B099CC699EULL,
		0xDC04396C6FA3CBA6ULL,
		0xA46B8FB8F70F0457ULL,
		0x00000000246F4A16ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0xED092D143DAC5535ULL,
		0xCBFCAEF32152D3E8ULL,
		0x66FB47DC8979F7B2ULL,
		0x687221FBF73B1D53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5350000000000000ULL,
		0x3E8ED092D143DAC5ULL,
		0x7B2CBFCAEF32152DULL,
		0xD5366FB47DC8979FULL,
		0x000687221FBF73B1ULL
	}};
	shift = 244;
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
		0xB0BBB46649F9D89AULL,
		0xC8B8606DE6D1B5AFULL,
		0x87F88B234FEE2F98ULL,
		0x79262D0E178FF8DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x85DDA3324FCEC4D0ULL,
		0x45C3036F368DAD7DULL,
		0x3FC4591A7F717CC6ULL,
		0xC9316870BC7FC6DCULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x020F72EBCCA019E4ULL,
		0x06C43D87EEA38C94ULL,
		0x699176D75C8108C7ULL,
		0x6DFF7473E1F86D95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x041EE5D7994033C8ULL,
		0x0D887B0FDD471928ULL,
		0xD322EDAEB902118EULL,
		0xDBFEE8E7C3F0DB2AULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x1F260EE28CE44E2AULL,
		0x0CDD2E41E74FDCBAULL,
		0x7499C9446DCF526DULL,
		0x18629CB77F3B43EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE28CE44E2A000000ULL,
		0x41E74FDCBA1F260EULL,
		0x446DCF526D0CDD2EULL,
		0xB77F3B43EA7499C9ULL,
		0x000000000018629CULL
	}};
	shift = 216;
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
		0x4F197E1FEC55DA3BULL,
		0x0F131C37F07492FAULL,
		0x78747BC04229A7E1ULL,
		0x39277E83C9A8A0CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7600000000000000ULL,
		0xF49E32FC3FD8ABB4ULL,
		0xC21E26386FE0E925ULL,
		0x96F0E8F78084534FULL,
		0x00724EFD07935141ULL
	}};
	shift = 249;
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
		0x858A9A626D32AB5DULL,
		0xEC8802244A0E7306ULL,
		0xD0873C52EE7A1F23ULL,
		0x3C2ACEB48FBB52D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6556BA000000000ULL,
		0x41CE60D0B1534C4DULL,
		0xCF43E47D91004489ULL,
		0xF76A5A5A10E78A5DULL,
		0x000000078559D691ULL
	}};
	shift = 229;
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
		0xC2EBF78B92C5318BULL,
		0xD1A1FC0B656191E4ULL,
		0x3C524D2FC27F1280ULL,
		0x124E2381C579A4A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF78B92C5318B000ULL,
		0x1FC0B656191E4C2EULL,
		0x24D2FC27F1280D1AULL,
		0xE2381C579A4A63C5ULL,
		0x0000000000000124ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x7E91E03AE5B21459ULL,
		0x26B514340181DC8BULL,
		0x927F0882666D415DULL,
		0x71132BC2EDAA7BF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96C8516400000000ULL,
		0x0607722DFA4780EBULL,
		0x99B505749AD450D0ULL,
		0xB6A9EFC249FC2209ULL,
		0x00000001C44CAF0BULL
	}};
	shift = 226;
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
		0xF15496EB613925C9ULL,
		0x70DE9B6DAD615FFDULL,
		0xB4DE11B2AC168B95ULL,
		0x6DC0EAA12D25FC52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA4B75B09C92E480ULL,
		0x6F4DB6D6B0AFFEF8ULL,
		0x6F08D9560B45CAB8ULL,
		0xE075509692FE295AULL,
		0x0000000000000036ULL
	}};
	shift = 199;
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
		0x03C43F00E7D3D41AULL,
		0x413424A9EC4B24B0ULL,
		0x8C5835F5D07C5ED7ULL,
		0x6DD2CB9A091E3160ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC039F4F506800000ULL,
		0x2A7B12C92C00F10FULL,
		0x7D741F17B5D04D09ULL,
		0xE682478C5823160DULL,
		0x00000000001B74B2ULL
	}};
	shift = 214;
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
		0x0866D7F257EEC85BULL,
		0xA4EBA2D2C7FA42C5ULL,
		0x1B4F51C03F594D6AULL,
		0x59A6060141C4089AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB5FC95FBB216C000ULL,
		0xE8B4B1FE90B14219ULL,
		0xD4700FD6535AA93AULL,
		0x81805071022686D3ULL,
		0x0000000000001669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
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
		0xF7DC716E1922606DULL,
		0x36A0E77753377AEEULL,
		0x9F54015C4C5396D6ULL,
		0x5F0ACDA4F9F00DC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC5B8648981B40000ULL,
		0x9DDD4CDDEBBBDF71ULL,
		0x0571314E5B58DA83ULL,
		0x3693E7C0370A7D50ULL,
		0x0000000000017C2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
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
		0x666C69FD87E99A49ULL,
		0xE9669EFC72C727CDULL,
		0xB2ED9DCB3541D745ULL,
		0x7CF6C8DBBAED5BB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x666C69FD87E99A49ULL,
		0xE9669EFC72C727CDULL,
		0xB2ED9DCB3541D745ULL,
		0x7CF6C8DBBAED5BB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0xBB80F047E2ED25E1ULL,
		0x858CC6AFF3315F58ULL,
		0x001B56EA08E3738DULL,
		0x75729F0CC8BECFE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3C11F8BB49784000ULL,
		0x31ABFCCC57D62EE0ULL,
		0xD5BA8238DCE36163ULL,
		0xA7C3322FB3F8C006ULL,
		0x0000000000001D5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
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
		0x1CF3FC48EF215F31ULL,
		0x9BBDD9610CB3CBA9ULL,
		0xF09AEF11E6685C68ULL,
		0x4457AEE5B570AB4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF3FC48EF215F3100ULL,
		0xBDD9610CB3CBA91CULL,
		0x9AEF11E6685C689BULL,
		0x57AEE5B570AB4FF0ULL,
		0x0000000000000044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
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
		0x45CD9E1DD931B4E6ULL,
		0x60F52C852DAF1C98ULL,
		0x0AD31325BE295EC4ULL,
		0x33993A6FA8A058FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD931B4E60000000ULL,
		0x52DAF1C9845CD9E1ULL,
		0x5BE295EC460F52C8ULL,
		0xFA8A058FE0AD3132ULL,
		0x00000000033993A6ULL
	}};
	shift = 220;
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
		0x3D4D2F68AD8BB963ULL,
		0x118A8E0A0F999194ULL,
		0x040C2A6401E39F8FULL,
		0x6A0C72C6A7E26C2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x534BDA2B62EE58C0ULL,
		0x62A38283E664650FULL,
		0x030A990078E7E3C4ULL,
		0x831CB1A9F89B0BC1ULL,
		0x000000000000001AULL
	}};
	shift = 198;
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
		0x308286B362D7A594ULL,
		0x215A8C8004CFD5D4ULL,
		0x59C1BC33E7EFC397ULL,
		0x1D1349557FCE4E26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1ACD8B5E9650000ULL,
		0xA3200133F5750C20ULL,
		0x6F0CF9FBF0E5C856ULL,
		0xD2555FF393899670ULL,
		0x0000000000000744ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x59E8A93F252950BDULL,
		0x7519C71645954E76ULL,
		0x7D0D36DC70A6AAA0ULL,
		0x673025DFAA814435ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC94A542F40000000ULL,
		0x9165539D967A2A4FULL,
		0x1C29AAA81D4671C5ULL,
		0xEAA0510D5F434DB7ULL,
		0x0000000019CC0977ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x27E0E99FD2CE8EC5ULL,
		0x6A5445EC94D435BAULL,
		0x6A0434001FC09102ULL,
		0x3E6B825B0B072C02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59D1D8A000000000ULL,
		0x9A86B744FC1D33FAULL,
		0xF812204D4A88BD92ULL,
		0x60E5804D40868003ULL,
		0x00000007CD704B61ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
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
		0xB7BB01D3ACFA65D7ULL,
		0x301A60FF38CBC2D3ULL,
		0xB8DDD74F3D2AA36FULL,
		0x371615B3524E48D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D3ACFA65D700000ULL,
		0x0FF38CBC2D3B7BB0ULL,
		0x74F3D2AA36F301A6ULL,
		0x5B3524E48D9B8DDDULL,
		0x0000000000037161ULL
	}};
	shift = 212;
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
		0xFF6A3EE41D7C36CEULL,
		0x28D6A21E4A1A1224ULL,
		0x2B497A8E46FDE17CULL,
		0x5BFF8CA59753A152ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47DC83AF86D9C000ULL,
		0xD443C94342449FEDULL,
		0x2F51C8DFBC2F851AULL,
		0xF194B2EA742A4569ULL,
		0x0000000000000B7FULL
	}};
	shift = 205;
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
		0x8C3E5127791B40D2ULL,
		0xC8B6879EB6900F78ULL,
		0x9110243B5B81D7BCULL,
		0x559F3504A8711F47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F9449DE46D03480ULL,
		0x2DA1E7ADA403DE23ULL,
		0x44090ED6E075EF32ULL,
		0x67CD412A1C47D1E4ULL,
		0x0000000000000015ULL
	}};
	shift = 198;
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
		0xFAA6F91411CF5600ULL,
		0x13E80793E3C59DD4ULL,
		0x5DF037D42E7B4849ULL,
		0x7318B6BFA1DC85F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x753EA9BE450473D5ULL,
		0x1244FA01E4F8F167ULL,
		0x7D977C0DF50B9ED2ULL,
		0x001CC62DAFE87721ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x81A7B039932E3258ULL,
		0x8BB0D7D3B2BAAE26ULL,
		0x1163518720E3754FULL,
		0x206D5A3EE318D44EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC997192C0000000ULL,
		0x9D95D571340D3D81ULL,
		0x39071BAA7C5D86BEULL,
		0xF718C6A2708B1A8CULL,
		0x0000000001036AD1ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
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
		0x77F0490F401CB3EEULL,
		0x6EE8114C318C017CULL,
		0x9357211248401FA6ULL,
		0x00361E2E9A98A7CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72CFB80000000000ULL,
		0x3005F1DFC1243D00ULL,
		0x007E99BBA04530C6ULL,
		0x629F3E4D5C844921ULL,
		0x00000000D878BA6AULL
	}};
	shift = 234;
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
		0xA226E93EB7D042C9ULL,
		0x5B34BD32D2BA88ABULL,
		0x26797871821A99E8ULL,
		0x2CB16B4B0179712BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA08592000000000ULL,
		0x5751157444DD27D6ULL,
		0x43533D0B6697A65AULL,
		0x2F2E2564CF2F0E30ULL,
		0x00000005962D6960ULL
	}};
	shift = 229;
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
		0x4056BDB513197603ULL,
		0x32811C3BD4C698DBULL,
		0xD2574C181B51E8DDULL,
		0x6FE63410C13C6E78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF6D44C65D80C000ULL,
		0x470EF531A636D015ULL,
		0xD30606D47A374CA0ULL,
		0x8D04304F1B9E3495ULL,
		0x0000000000001BF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xD0ADEF0AF33FAE51ULL,
		0x0339B28FFDA46A0DULL,
		0xDD28AAD9E82E0EB3ULL,
		0x41CD8634E8225117ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBDE15E67F5CA2000ULL,
		0x3651FFB48D41BA15ULL,
		0x155B3D05C1D66067ULL,
		0xB0C69D044A22FBA5ULL,
		0x0000000000000839ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
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
		0x559CD7B57DEEE8C6ULL,
		0xB2C763C3D939E813ULL,
		0x9F9426E0956178D1ULL,
		0x536879E479511F40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBA31800000000000ULL,
		0x7A04D56735ED5F7BULL,
		0x5E346CB1D8F0F64EULL,
		0x47D027E509B82558ULL,
		0x000014DA1E791E54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0xEE2EAC352EFB25ABULL,
		0x45B3AD4DC49D2D13ULL,
		0xAADD7AD6FDF955B3ULL,
		0x16FD1D980BBB443AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5800000000000000ULL,
		0x9F717561A977D92DULL,
		0x9A2D9D6A6E24E968ULL,
		0xD556EBD6B7EFCAADULL,
		0x00B7E8ECC05DDA21ULL
	}};
	shift = 251;
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
		0xFD440C8C04855218ULL,
		0xE92E8C4A480D2449ULL,
		0x3C7CBBE19EB68FBEULL,
		0x6F6330458C96C50BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA881918090AA430ULL,
		0xD25D1894901A4893ULL,
		0x78F977C33D6D1F7DULL,
		0xDEC6608B192D8A16ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0xE16980AE7F33AE99ULL,
		0x5D7A3EA01862FD9BULL,
		0x331BDD9135CE4442ULL,
		0x1F1C0159D702F87CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE675D3200000000ULL,
		0x30C5FB37C2D3015CULL,
		0x6B9C8884BAF47D40ULL,
		0xAE05F0F86637BB22ULL,
		0x000000003E3802B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0x1E1515C518B2AA51ULL,
		0x073840FB185293C0ULL,
		0xA31D65AC23A53371ULL,
		0x306078D585FB21A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8800000000000000ULL,
		0x00F0A8AE28C59552ULL,
		0x8839C207D8C2949EULL,
		0x3518EB2D611D299BULL,
		0x018303C6AC2FD90DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0xF502E2AC0AC94964ULL,
		0x4D9734A2B3064926ULL,
		0x5FFCF5A8338F912DULL,
		0x1397FB52352953AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9496400000000000ULL,
		0x64926F502E2AC0ACULL,
		0xF912D4D9734A2B30ULL,
		0x953AE5FFCF5A8338ULL,
		0x000001397FB52352ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
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
		0x69A04D231AAFF902ULL,
		0x738F1B909E50E2BEULL,
		0xBA92F6807F772B21ULL,
		0x48038FC3B62E45C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF204000000000000ULL,
		0xC57CD3409A46355FULL,
		0x5642E71E37213CA1ULL,
		0x8B817525ED00FEEEULL,
		0x000090071F876C5CULL
	}};
	shift = 241;
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
		0x30A0842378809F69ULL,
		0xA449DA2BFD735DB4ULL,
		0x314541448208AF74ULL,
		0x6983F2946D9E3AD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xED20000000000000ULL,
		0xB6861410846F1013ULL,
		0xEE94893B457FAE6BULL,
		0x5AA628A828904115ULL,
		0x000D307E528DB3C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
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
		0x57B97D5A9FAB97DDULL,
		0xFAD1BFEFEA9A8E67ULL,
		0x3E2D1760D9F8391DULL,
		0x16B8E1FB4D8A69E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7400000000000000ULL,
		0x9D5EE5F56A7EAE5FULL,
		0x77EB46FFBFAA6A39ULL,
		0x80F8B45D8367E0E4ULL,
		0x005AE387ED3629A7ULL
	}};
	shift = 250;
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
		0xE5047F8D866C811AULL,
		0x88CF1E29EAA0CF01ULL,
		0x2E087DBFE8F4126DULL,
		0x6AEC2B15578AB439ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66C811A000000000ULL,
		0xAA0CF01E5047F8D8ULL,
		0x8F4126D88CF1E29EULL,
		0x78AB4392E087DBFEULL,
		0x00000006AEC2B155ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x2027FDC649C22608ULL,
		0xD76D12C17E0A6685ULL,
		0x0C4CC08569A77A1CULL,
		0x690CC52973235444ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC93844C100000000ULL,
		0x2FC14CD0A404FFB8ULL,
		0xAD34EF439AEDA258ULL,
		0x2E646A8881899810ULL,
		0x000000000D2198A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
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
		0x4A9ED5E1CB38D49AULL,
		0x04CC659E64DA8A7AULL,
		0xB6071ABCC3833A45ULL,
		0x7C883F3E281B7975ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA934000000000000ULL,
		0x14F4953DABC39671ULL,
		0x748A0998CB3CC9B5ULL,
		0xF2EB6C0E35798706ULL,
		0x0000F9107E7C5036ULL
	}};
	shift = 241;
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
		0x1312581539EA9294ULL,
		0x394A6167C85E7B11ULL,
		0xCC5B342895D9A4A2ULL,
		0x4EB651D2CB453139ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5280000000000000ULL,
		0x6222624B02A73D52ULL,
		0x9447294C2CF90BCFULL,
		0x27398B668512BB34ULL,
		0x0009D6CA3A5968A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
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
		0x090F21F3B1EDA7F1ULL,
		0xBE6437B90440E828ULL,
		0xBFA539FB50566B6DULL,
		0x3CD990100DD1B3D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x90F21F3B1EDA7F10ULL,
		0xE6437B90440E8280ULL,
		0xFA539FB50566B6DBULL,
		0xCD990100DD1B3D9BULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
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
		0x0A861D13906EFF35ULL,
		0x6C7EE0A9D30AE0D3ULL,
		0x2132DC14909E16C0ULL,
		0x5FBF21014C7FEBD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F9A80000000000ULL,
		0x5706985430E89C83ULL,
		0xF0B60363F7054E98ULL,
		0xFF5EC90996E0A484ULL,
		0x000002FDF9080A63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x343BE35798825CBAULL,
		0xD352D908AF8DE517ULL,
		0x720BB2D27E574CB8ULL,
		0x57311ED86D2732C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E80000000000000ULL,
		0x45CD0EF8D5E62097ULL,
		0x2E34D4B6422BE379ULL,
		0xB05C82ECB49F95D3ULL,
		0x0015CC47B61B49CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x38B421E100A8351CULL,
		0x055A0AE10A1FD138ULL,
		0x64F2DA098B24B994ULL,
		0x2DAADE6142650076ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1506A38000000000ULL,
		0x43FA270716843C20ULL,
		0x64973280AB415C21ULL,
		0x4CA00ECC9E5B4131ULL,
		0x00000005B55BCC28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x9AC7BC112E644CDEULL,
		0x51BD9CA058275A57ULL,
		0x3EC11FCFF0730F0AULL,
		0x2B8CDD223CE9FE20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4B99133780000000ULL,
		0x1609D695E6B1EF04ULL,
		0xFC1CC3C2946F6728ULL,
		0x8F3A7F880FB047F3ULL,
		0x000000000AE33748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
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
		0xB607D5AE7ACBB9E7ULL,
		0x37CF4ED06C84F79DULL,
		0x48FF8B302D01A3A2ULL,
		0x208A3F270BD08E80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB5CF59773CE00000ULL,
		0xDA0D909EF3B6C0FAULL,
		0x6605A0347446F9E9ULL,
		0xE4E17A11D0091FF1ULL,
		0x0000000000041147ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
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
		0xA83A6F595C815758ULL,
		0x0EAE989135BDD667ULL,
		0x28665F61CC6E656CULL,
		0x32DBDCA408EF56BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB2B902AEB000000ULL,
		0x1226B7BACCF5074DULL,
		0xEC398DCCAD81D5D3ULL,
		0x94811DEAD7650CCBULL,
		0x0000000000065B7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xA7AF68B59CC6C64AULL,
		0x174AB06E8B1FBFB2ULL,
		0xD8AE3BBA869FC9DEULL,
		0x5CAB7D35AE3F35E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x953D7B45ACE63632ULL,
		0xF0BA55837458FDFDULL,
		0x36C571DDD434FE4EULL,
		0x02E55BE9AD71F9AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0x50EEE67DD0740147ULL,
		0x53ED81E127A3DAAFULL,
		0xCADEDB48D4968DB2ULL,
		0x5A2E2E9978CAD980ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDCCFBA0E8028E000ULL,
		0xB03C24F47B55EA1DULL,
		0xDB691A92D1B64A7DULL,
		0xC5D32F195B30195BULL,
		0x0000000000000B45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
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
		0x0D56BB8220ED7952ULL,
		0x18AAEB689169A2FEULL,
		0x3E457D684D1886DEULL,
		0x5541F42BDD8F9F23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE0883B5E5480000ULL,
		0xADA245A68BF8355AULL,
		0xF5A134621B7862ABULL,
		0xD0AF763E7C8CF915ULL,
		0x0000000000015507ULL
	}};
	shift = 210;
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
		0x6D0FECE7403EE293ULL,
		0x216AB6825E548467ULL,
		0xD64B4745E65BD26DULL,
		0x3DA6843DFE36ABDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2930000000000000ULL,
		0x4676D0FECE7403EEULL,
		0x26D216AB6825E548ULL,
		0xBDBD64B4745E65BDULL,
		0x0003DA6843DFE36AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x51D32F589C889F8BULL,
		0x700765331657AA91ULL,
		0xE5069465264ED3F9ULL,
		0x7C4987B753FAED7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC4E444FC580000ULL,
		0x2998B2BD548A8E99ULL,
		0xA32932769FCB803BULL,
		0x3DBA9FD76BDF2834ULL,
		0x000000000003E24CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xE33E1CDD267DA302ULL,
		0xC2FD175051E87214ULL,
		0x9B8A630F70AD46C2ULL,
		0x2067BD6D146FA445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x4E33E1CDD267DA30ULL,
		0x2C2FD175051E8721ULL,
		0x59B8A630F70AD46CULL,
		0x02067BD6D146FA44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0xF33FFE981C226086ULL,
		0xA0D3BA281ACA546BULL,
		0xA114F1A439183E2CULL,
		0x4C6FFAE4F7263365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6070898218000000ULL,
		0xA06B2951AFCCFFFAULL,
		0x90E460F8B2834EE8ULL,
		0x93DC98CD968453C6ULL,
		0x000000000131BFEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
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
		0xAF040062D1E68E66ULL,
		0x43ABB84E77540ED3ULL,
		0x9BAC51FE52410D6EULL,
		0x443D2E22EBBC7ABCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2003168F34733000ULL,
		0x5DC273BAA0769D78ULL,
		0x628FF292086B721DULL,
		0xE971175DE3D5E4DDULL,
		0x0000000000000221ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
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
		0xF306C1C2B2AAD32EULL,
		0xE6E4E4E606A175DAULL,
		0xBA2C31ECF4E60A32ULL,
		0x3E206DFA23119C19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B2AAD32E0000000ULL,
		0x606A175DAF306C1CULL,
		0xCF4E60A32E6E4E4EULL,
		0xA23119C19BA2C31EULL,
		0x0000000003E206DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x9640A50D15896431ULL,
		0xD70914FC46E7377DULL,
		0x25A8059CAB6A3576ULL,
		0x329B2A28931FB059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62590C4000000000ULL,
		0xB9CDDF6590294345ULL,
		0xDA8D5DB5C2453F11ULL,
		0xC7EC16496A01672AULL,
		0x0000000CA6CA8A24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x3D07062330F18D61ULL,
		0x8B5FA1369EDB4069ULL,
		0x5960B1B528EE310CULL,
		0x4AB8B4FB621A257DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x330F18D610000000ULL,
		0x69EDB40693D07062ULL,
		0x528EE310C8B5FA13ULL,
		0xB621A257D5960B1BULL,
		0x0000000004AB8B4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
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
		0xDC691BD046C97261ULL,
		0xF8CAED72B7402663ULL,
		0x81D76E429C06848FULL,
		0x11124AD765A35900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E4C200000000000ULL,
		0x04CC7B8D237A08D9ULL,
		0xD091FF195DAE56E8ULL,
		0x6B20103AEDC85380ULL,
		0x00000222495AECB4ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
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
		0x7DD6F1A7133DE664ULL,
		0xBE1FF944F9565500ULL,
		0x61ACF69948DC06CDULL,
		0x7695107025DEBA16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB78D3899EF332000ULL,
		0xFFCA27CAB2A803EEULL,
		0x67B4CA46E0366DF0ULL,
		0xA883812EF5D0B30DULL,
		0x00000000000003B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xBFC555698CD40468ULL,
		0xEFCBA4DC55CB8770ULL,
		0x4B4372AE265FE911ULL,
		0x24F1BC39654FED26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FE2AAB4C66A0234ULL,
		0xF7E5D26E2AE5C3B8ULL,
		0x25A1B957132FF488ULL,
		0x1278DE1CB2A7F693ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0x5F32C8FE380DF405ULL,
		0x17AEE56E06D2798FULL,
		0x10E214E101B7F7E5ULL,
		0x230CDB9130818073ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BE80A0000000000ULL,
		0xA4F31EBE6591FC70ULL,
		0x6FEFCA2F5DCADC0DULL,
		0x0300E621C429C203ULL,
		0x0000004619B72261ULL
	}};
	shift = 233;
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
		0xE23E78E4507241F6ULL,
		0x575258A8E2CB6003ULL,
		0xC8B671EB83E1D47EULL,
		0x5085EB85918AC748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CF1C8A0E483EC00ULL,
		0xA4B151C596C007C4ULL,
		0x6CE3D707C3A8FCAEULL,
		0x0BD70B23158E9191ULL,
		0x00000000000000A1ULL
	}};
	shift = 201;
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
		0x1E9085204786BE0DULL,
		0x634913691CBC7889ULL,
		0xFC8C46E1BDE2537AULL,
		0x6BFD305F7CCA08E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8F0D7C1A00000000ULL,
		0x3978F1123D210A40ULL,
		0x7BC4A6F4C69226D2ULL,
		0xF99411C7F9188DC3ULL,
		0x00000000D7FA60BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0x66CF6A5482C57C9FULL,
		0x1C5F379A04055FE4ULL,
		0xC10616A8C7AEE203ULL,
		0x14E33EE59EEEAD26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9520B15F27C0000ULL,
		0xDE6810157F919B3DULL,
		0x5AA31EBB880C717CULL,
		0xFB967BBAB49B0418ULL,
		0x000000000000538CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xC916EBF9FE462955ULL,
		0x91A2CFC495F4A53AULL,
		0x86933D13C6AC14BAULL,
		0x35600CA91FF36F64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2955000000000000ULL,
		0xA53AC916EBF9FE46ULL,
		0x14BA91A2CFC495F4ULL,
		0x6F6486933D13C6ACULL,
		0x000035600CA91FF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x4ED38D5FF9F0CE8EULL,
		0x592CB1CD8E166731ULL,
		0xA1CF9B3DC8102BECULL,
		0x0D35462C3164629AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCF8674700000000ULL,
		0xC70B3398A769C6AFULL,
		0xE40815F62C9658E6ULL,
		0x18B2314D50E7CD9EULL,
		0x00000000069AA316ULL
	}};
	shift = 223;
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
		0x2F96352EE85F0617ULL,
		0x7EACE0E3F5619BDBULL,
		0x68262C978FAA72A1ULL,
		0x2CAF843144EB2C98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A97742F830B8000ULL,
		0x7071FAB0CDED97CBULL,
		0x164BC7D53950BF56ULL,
		0xC218A275964C3413ULL,
		0x0000000000001657ULL
	}};
	shift = 207;
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
		0x7A618C3FC2B3BA17ULL,
		0x8E6F05F96191E640ULL,
		0x4E7ED003B8B8A810ULL,
		0x514ED55D9EAE52FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x0F4C3187F8567742ULL,
		0x11CDE0BF2C323CC8ULL,
		0x49CFDA0077171502ULL,
		0x0A29DAABB3D5CA5FULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x225C06DCB5793731ULL,
		0x0673E201F35A3268ULL,
		0x57F202BCA5D4389DULL,
		0x7EE2327E622C89F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44B80DB96AF26E62ULL,
		0x0CE7C403E6B464D0ULL,
		0xAFE405794BA8713AULL,
		0xFDC464FCC45913F0ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0xD00469E677E63918ULL,
		0xC9C02E7E18677801ULL,
		0x08049EFE7A659F36ULL,
		0x28268E5D086B0146ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0234F33BF31C8C00ULL,
		0xE0173F0C33BC00E8ULL,
		0x024F7F3D32CF9B64ULL,
		0x13472E843580A304ULL,
		0x0000000000000014ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
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
		0xCF27AAD46C745BF4ULL,
		0x06BB8ACF7A94B512ULL,
		0x64732F1033353594ULL,
		0x71817A55750ADEC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD46C745BF4000000ULL,
		0xCF7A94B512CF27AAULL,
		0x103335359406BB8AULL,
		0x55750ADEC164732FULL,
		0x000000000071817AULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x9C380BED52F3B7D1ULL,
		0x882C423741A9053EULL,
		0xB04FED1EAC6B1ACCULL,
		0x708EFCA0571C8012ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9C380BED52F3B7D1ULL,
		0x882C423741A9053EULL,
		0xB04FED1EAC6B1ACCULL,
		0x708EFCA0571C8012ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0x50EA606C18BD81D5ULL,
		0xEEAFF265C8C83FACULL,
		0xAB743B1B5C06B80CULL,
		0x38D900CD7562D213ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3AA0000000000000ULL,
		0xF58A1D4C0D8317B0ULL,
		0x019DD5FE4CB91907ULL,
		0x42756E87636B80D7ULL,
		0x00071B2019AEAC5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 117;
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
		0x5EE0A47638B39F9FULL,
		0x7ACD664F44D84D1AULL,
		0x6433C42A7217D12CULL,
		0x3A60235B1BFC39FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8291D8E2CE7E7C0ULL,
		0xB35993D136134697ULL,
		0x0CF10A9C85F44B1EULL,
		0x9808D6C6FF0E7FD9ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 134;
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
		0x490C5C3120B5A4E3ULL,
		0xBE3B904833A6B4DAULL,
		0x4412619B1DDACC4CULL,
		0x3AB4112F36BB31CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x862E18905AD27180ULL,
		0x1DC82419D35A6D24ULL,
		0x0930CD8EED66265FULL,
		0x5A08979B5D98E522ULL,
		0x000000000000001DULL,
		0x0000000000000000ULL
	}};
	shift = 135;
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
		0x0F7F4D2C5BF8B29BULL,
		0x95CC492F1F0B8D17ULL,
		0x47D541F503BEF508ULL,
		0x333572EC45BC379BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD34B16FE2CA6C00ULL,
		0x3124BC7C2E345C3DULL,
		0x5507D40EFBD42257ULL,
		0xD5CBB116F0DE6D1FULL,
		0x00000000000000CCULL
	}};
	shift = 202;
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
		0x4136D0EF45C2DEA9ULL,
		0x3806A6E78B1E8B14ULL,
		0x6704E8E9B62CEBFCULL,
		0x79611EAE8913A8C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x826DA1DE8B85BD52ULL,
		0x700D4DCF163D1628ULL,
		0xCE09D1D36C59D7F8ULL,
		0xF2C23D5D1227518CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
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
		0x8686FCCC98206A45ULL,
		0x696AE69B13AA9538ULL,
		0xE7467AC556E86B75ULL,
		0x232D5DA452F14F36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0DF9993040D48AULL,
		0xD2D5CD3627552A71ULL,
		0xCE8CF58AADD0D6EAULL,
		0x465ABB48A5E29E6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xBB3B560A4DF1AF9DULL,
		0x3B247A60B3A3A327ULL,
		0x3845DDAE43368D2EULL,
		0x62C9214C646E6DFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5F3A000000000000ULL,
		0x464F7676AC149BE3ULL,
		0x1A5C7648F4C16747ULL,
		0xDBF4708BBB5C866DULL,
		0x0000C5924298C8DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
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
		0x856203851E6FBD93ULL,
		0xD90B2B389EB2FCFEULL,
		0x21D27289CDDF8562ULL,
		0x662878EEB6B43EE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70A3CDF7B2600000ULL,
		0x6713D65F9FD0AC40ULL,
		0x5139BBF0AC5B2165ULL,
		0x1DD6D687DCE43A4EULL,
		0x00000000000CC50FULL
	}};
	shift = 213;
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
		0x4FEBE31D339C08DCULL,
		0x77F6B0EAE5310CDCULL,
		0xE3295BEF6742525CULL,
		0x3A512400B054A522ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x339C08DC00000000ULL,
		0xE5310CDC4FEBE31DULL,
		0x6742525C77F6B0EAULL,
		0xB054A522E3295BEFULL,
		0x000000003A512400ULL
	}};
	shift = 224;
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
		0xD78D6E4BC4232B10ULL,
		0xFD2E50B47EC602C8ULL,
		0xC809F1EB46F4E011ULL,
		0x08746968A34AB1A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8CAC400000000000ULL,
		0x180B235E35B92F10ULL,
		0xD38047F4B942D1FBULL,
		0x2AC68F2027C7AD1BULL,
		0x00000021D1A5A28DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
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
		0xC5F2D468CE6DA948ULL,
		0xEED3CFF69C0F2477ULL,
		0x126CF0FD9905AF83ULL,
		0x0F3DAE68E6E9A31DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5290000000000000ULL,
		0x48EF8BE5A8D19CDBULL,
		0x5F07DDA79FED381EULL,
		0x463A24D9E1FB320BULL,
		0x00001E7B5CD1CDD3ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0x30F5C7D6FD9BB826ULL,
		0x6309F909DC9D7B3BULL,
		0x98819389DA28A49EULL,
		0x7133D673633F62A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7ECDDC130000000ULL,
		0x4EE4EBD9D987AE3EULL,
		0x4ED14524F3184FC8ULL,
		0x9B19FB153CC40C9CULL,
		0x0000000003899EB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x320B7DB73D98FECBULL,
		0xA247AB0206290D2FULL,
		0x1974E1CB052EE1B8ULL,
		0x0A8C959A21BFEB7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05BEDB9ECC7F6580ULL,
		0x23D5810314869799ULL,
		0xBA70E5829770DC51ULL,
		0x464ACD10DFF5BE0CULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x0A68FFC740CB7362ULL,
		0x59D81ABC7E303D0CULL,
		0x7034841A6AB7F30CULL,
		0x07358815B24A32FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD8800000000000ULL,
		0x0F43029A3FF1D032ULL,
		0xFCC3167606AF1F8CULL,
		0x8CBF9C0D21069AADULL,
		0x000001CD62056C92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x14B6A4654E662563ULL,
		0xD46AF47E5B0EB1AEULL,
		0xB72308091AEFD28FULL,
		0x2910D28533FB5CA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC4AC60000000000ULL,
		0x1D635C296D48CA9CULL,
		0xDFA51FA8D5E8FCB6ULL,
		0xF6B94B6E46101235ULL,
		0x0000005221A50A67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x40506B8831096101ULL,
		0x95480E1ACE7D2A7FULL,
		0x1D264D884BE234EFULL,
		0x698E724459E2D141ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41AE20C425840400ULL,
		0x20386B39F4A9FD01ULL,
		0x9936212F88D3BE55ULL,
		0x39C911678B450474ULL,
		0x00000000000001A6ULL
	}};
	shift = 202;
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
		0x2C72DF600E96EC2EULL,
		0xB096768481FB548BULL,
		0x7EFEF17CA40AC420ULL,
		0x373A1A8048AE54FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7617000000000000ULL,
		0xAA4596396FB0074BULL,
		0x6210584B3B4240FDULL,
		0x2A7F3F7F78BE5205ULL,
		0x00001B9D0D402457ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x80A7F3205C24C7B6ULL,
		0x46D3180DFEB6D31BULL,
		0xA6D49D7618824C7FULL,
		0x34E1BD4440ACA6EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53F9902E1263DB00ULL,
		0x698C06FF5B698DC0ULL,
		0x6A4EBB0C41263FA3ULL,
		0x70DEA22056537553ULL,
		0x000000000000001AULL
	}};
	shift = 199;
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
		0xE0191247AEE80E61ULL,
		0xFB3AF8D290F10979ULL,
		0xD6465398DF746F59ULL,
		0x1A6A834BCF502792ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD01CC20000000000ULL,
		0xE212F3C032248F5DULL,
		0xE8DEB3F675F1A521ULL,
		0xA04F25AC8CA731BEULL,
		0x00000034D506979EULL
	}};
	shift = 233;
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
		0x2524EC8BD369D251ULL,
		0x8745094256A94A70ULL,
		0x8365DE97FCD2F96CULL,
		0x03F965D35C10400EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC8BD369D2510000ULL,
		0x094256A94A702524ULL,
		0xDE97FCD2F96C8745ULL,
		0x65D35C10400E8365ULL,
		0x00000000000003F9ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x6B2B270FE5BCE499ULL,
		0x9A25B5479848DE0DULL,
		0x764EE09CA3898479ULL,
		0x3CB570BEBF588160ULL,
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
		0x6B2B270FE5BCE499ULL,
		0x9A25B5479848DE0DULL,
		0x764EE09CA3898479ULL,
		0x3CB570BEBF588160ULL
	}};
	shift = 256;
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
		0x38AFBC01F0B43AFEULL,
		0xE0BE0D1CFA49EEF5ULL,
		0xEBDF6BFB3838C649ULL,
		0x41002B784EF23717ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F7803E16875FC00ULL,
		0x7C1A39F493DDEA71ULL,
		0xBED7F670718C93C1ULL,
		0x0056F09DE46E2FD7ULL,
		0x0000000000000082ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0xDE4E08BCEF079AD7ULL,
		0x6346C597DC8FA65AULL,
		0x56128D208DDB9E5CULL,
		0x3A3C8E420758D529ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F35AE0000000000ULL,
		0x1F4CB5BC9C1179DEULL,
		0xB73CB8C68D8B2FB9ULL,
		0xB1AA52AC251A411BULL,
		0x00000074791C840EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0x8930F9882961C9C2ULL,
		0xDE9D81342BB2A26CULL,
		0xDB16CDB29848056DULL,
		0x1AE88A41FEAF1A75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9C20000000000000ULL,
		0x26C8930F9882961CULL,
		0x56DDE9D81342BB2AULL,
		0xA75DB16CDB298480ULL,
		0x0001AE88A41FEAF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
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
		0x76F53C8195E24045ULL,
		0x695DA01E90006462ULL,
		0xEB8D76FDF4FCA197ULL,
		0x7E2B92AECAC32F5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0114000000000000ULL,
		0x9189DBD4F2065789ULL,
		0x865DA576807A4001ULL,
		0xBD77AE35DBF7D3F2ULL,
		0x0001F8AE4ABB2B0CULL,
		0x0000000000000000ULL
	}};
	shift = 178;
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
		0x2CA2FBE955D3085DULL,
		0x48F906DFBA5445D3ULL,
		0xE97F4884DF1CA1BEULL,
		0x610585E6A9724E0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xCB28BEFA5574C217ULL,
		0x923E41B7EE951174ULL,
		0xFA5FD22137C7286FULL,
		0x18416179AA5C9382ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
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
		0xAAAAC655AE3569EAULL,
		0xB6E515B18F7A7DA1ULL,
		0x09417DFFE71D8798ULL,
		0x1DAB96F1E96BE58FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6AD3D40000000000ULL,
		0xF4FB4355558CAB5CULL,
		0x3B0F316DCA2B631EULL,
		0xD7CB1E1282FBFFCEULL,
		0x0000003B572DE3D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0x4BB5417BA3B4FAEDULL,
		0xF03658E3B3B3490FULL,
		0xA23B37A5D6E0775DULL,
		0x048E136FB3577BCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4769F5DA00000000ULL,
		0x6766921E976A82F7ULL,
		0xADC0EEBBE06CB1C7ULL,
		0x66AEF79D44766F4BULL,
		0x00000000091C26DFULL
	}};
	shift = 225;
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
		0x267D3A87E0807A8EULL,
		0x68448853575D66CCULL,
		0xB054832B4FF5B3A6ULL,
		0x18FD901E8EB68C8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x43F0403D47000000ULL,
		0x29ABAEB366133E9DULL,
		0x95A7FAD9D3342244ULL,
		0x0F475B4647D82A41ULL,
		0x00000000000C7EC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x889135D4D86F9DC3ULL,
		0x8C2235A502880640ULL,
		0xCCBF3EFF3FC07BA2ULL,
		0x4570070BB490A8A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC30000000000000ULL,
		0x640889135D4D86F9ULL,
		0xBA28C2235A502880ULL,
		0x8A5CCBF3EFF3FC07ULL,
		0x0004570070BB490AULL,
		0x0000000000000000ULL
	}};
	shift = 180;
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
		0x541E7968D3B8EAF8ULL,
		0x6D1EC8DB806B8C40ULL,
		0x7D87008ECE64E731ULL,
		0x0F4339D96253575DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0A83CF2D1A771D5FULL,
		0x2DA3D91B700D7188ULL,
		0xAFB0E011D9CC9CE6ULL,
		0x01E8673B2C4A6AEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0xC6631AA68698CE35ULL,
		0x6676406F9CF196E5ULL,
		0xB3E6E66AA7C5E5C7ULL,
		0x605ABF9B5C984B90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA68698CE3500000ULL,
		0x06F9CF196E5C6631ULL,
		0x66AA7C5E5C766764ULL,
		0xF9B5C984B90B3E6EULL,
		0x00000000000605ABULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x8503E2474BAF85A1ULL,
		0x14D566205D298779ULL,
		0x203CD094BABD6F66ULL,
		0x45B5FF2817519762ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x03E2474BAF85A100ULL,
		0xD566205D29877985ULL,
		0x3CD094BABD6F6614ULL,
		0xB5FF281751976220ULL,
		0x0000000000000045ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
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
		0x5C237A8489E01069ULL,
		0xBADC4B3B84570EE9ULL,
		0xEFC9CBD282E5A257ULL,
		0x07A9F48671467FB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB846F50913C020D2ULL,
		0x75B8967708AE1DD2ULL,
		0xDF9397A505CB44AFULL,
		0x0F53E90CE28CFF71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x225F3F1DC8CD5EA0ULL,
		0x8E231085C3EF57C0ULL,
		0xDC8C4A6B777154C0ULL,
		0x45BF895BE923C3C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97CFC7723357A800ULL,
		0x88C42170FBD5F008ULL,
		0x23129ADDDC553023ULL,
		0x6FE256FA48F0F0B7ULL,
		0x0000000000000011ULL
	}};
	shift = 198;
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
		0x87D155260D952C8FULL,
		0x677B3E1BCD94AA62ULL,
		0x2C22238BA116A438ULL,
		0x6760C1481CD9BED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3C00000000000000ULL,
		0x8A1F4554983654B2ULL,
		0xE19DECF86F3652A9ULL,
		0x48B0888E2E845A90ULL,
		0x019D8305207366FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
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
		0x7A518C3A9139E71DULL,
		0x59A2482DDCDB0DB8ULL,
		0x7EFB424825C6DBD0ULL,
		0x490756266D707CC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E71D00000000000ULL,
		0xB0DB87A518C3A913ULL,
		0x6DBD059A2482DDCDULL,
		0x07CC57EFB424825CULL,
		0x00000490756266D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x18F4ADE3361BDB2FULL,
		0x064ECA7721A0C99EULL,
		0x8932350E12126075ULL,
		0x4B37A6EFCEB68755ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65E0000000000000ULL,
		0x33C31E95BC66C37BULL,
		0x0EA0C9D94EE43419ULL,
		0xEAB12646A1C2424CULL,
		0x000966F4DDF9D6D0ULL
	}};
	shift = 245;
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
		0x7FA07182999CD427ULL,
		0x0DD1951D64D6A200ULL,
		0x44EA33925A8C9D74ULL,
		0x0569B765A9F7D02FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3053339A84E00000ULL,
		0xA3AC9AD4400FF40EULL,
		0x724B5193AE81BA32ULL,
		0xECB53EFA05E89D46ULL,
		0x000000000000AD36ULL
	}};
	shift = 213;
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
		0x563E1E427F26CF9EULL,
		0xB4C95AEEF8D24956ULL,
		0xC3A52873A3A2EFE6ULL,
		0x1E4AC6DBAC514F4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9367CF0000000000ULL,
		0x6924AB2B1F0F213FULL,
		0xD177F35A64AD777CULL,
		0x28A7A5E1D29439D1ULL,
		0x0000000F25636DD6ULL
	}};
	shift = 231;
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
		0xA73B8E3CAA0EC43CULL,
		0x73F2AC0A0D2484D0ULL,
		0x7F0931C157A04A77ULL,
		0x138DA6301C408350ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x541D887800000000ULL,
		0x1A4909A14E771C79ULL,
		0xAF4094EEE7E55814ULL,
		0x388106A0FE126382ULL,
		0x00000000271B4C60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x245E03494EE77891ULL,
		0xD63FA6C7AF7E03DBULL,
		0x74E2CED66E30118CULL,
		0x741443BF176584D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC4880000000000ULL,
		0xF01ED922F01A4A77ULL,
		0x808C66B1FD363D7BULL,
		0x2C26ABA71676B371ULL,
		0x000003A0A21DF8BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x4CD69620D2A2E62EULL,
		0x35196E42EBAD74EBULL,
		0xBE32C1E1E456934DULL,
		0x61441CCBF54B196DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A2E62E000000000ULL,
		0xBAD74EB4CD69620DULL,
		0x456934D35196E42EULL,
		0x54B196DBE32C1E1EULL,
		0x000000061441CCBFULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x1F29E1945BF535FAULL,
		0x8303427D8F2916BDULL,
		0x4C1DCBC272ED9AF1ULL,
		0x700A9FA3F1E71C71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x945BF535FA000000ULL,
		0x7D8F2916BD1F29E1ULL,
		0xC272ED9AF1830342ULL,
		0xA3F1E71C714C1DCBULL,
		0x0000000000700A9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x20A92C39BCA5B47CULL,
		0x8915D12BCE8A6BA2ULL,
		0x4B99D7080A3BFB3AULL,
		0x276144104D095E5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0x8882A4B0E6F296D1ULL,
		0xEA245744AF3A29AEULL,
		0x6D2E675C2028EFECULL,
		0x009D851041342579ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
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
		0x6E9613611AA392F5ULL,
		0xC75FD64E5CCC86EFULL,
		0x1E160164A2C165D3ULL,
		0x090AA83581AE9D72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B08D51C97A80000ULL,
		0xB272E664377B74B0ULL,
		0x0B25160B2E9E3AFEULL,
		0x41AC0D74EB90F0B0ULL,
		0x0000000000004855ULL
	}};
	shift = 211;
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
		0xB7A434AD7CFC3858ULL,
		0xEC766D6FB291E7B3ULL,
		0x1079F5278F1F7328ULL,
		0x262736DE19A7865AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE160000000000000ULL,
		0x9ECEDE90D2B5F3F0ULL,
		0xCCA3B1D9B5BECA47ULL,
		0x196841E7D49E3C7DULL,
		0x0000989CDB78669EULL
	}};
	shift = 242;
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
		0x0A1081839C3CBA15ULL,
		0x4F05F7B919C0F5CDULL,
		0x060BF5676EE59750ULL,
		0x7EE48A53CB9F78F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8540000000000000ULL,
		0x7342842060E70F2EULL,
		0xD413C17DEE46703DULL,
		0x3E4182FD59DBB965ULL,
		0x001FB92294F2E7DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xC9DEC55A72119839ULL,
		0xD5211D1AD9002275ULL,
		0xFBE03D57C6991621ULL,
		0x7A6B03D293824E25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC800000000000000ULL,
		0xAE4EF62AD3908CC1ULL,
		0x0EA908E8D6C80113ULL,
		0x2FDF01EABE34C8B1ULL,
		0x03D3581E949C1271ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
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
		0x78FEE4AB9DD63986ULL,
		0x2FB98211D9FFA1EAULL,
		0xFB196CF25A5B0CD7ULL,
		0x79A7FBBB061D59C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFDC9573BAC730C00ULL,
		0x730423B3FF43D4F1ULL,
		0x32D9E4B4B619AE5FULL,
		0x4FF7760C3AB38DF6ULL,
		0x00000000000000F3ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
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
		0x4E43A3AB757EEB39ULL,
		0xE66A0E0CED2890B0ULL,
		0xB63BCF736776B08FULL,
		0x167343F0E5055DD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7200000000000000ULL,
		0x609C874756EAFDD6ULL,
		0x1FCCD41C19DA5121ULL,
		0xA96C779EE6CEED61ULL,
		0x002CE687E1CA0ABBULL,
		0x0000000000000000ULL
	}};
	shift = 185;
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
		0xDD14A10414C7FB97ULL,
		0xB693EBB432251167ULL,
		0x9C3F4E494871D60DULL,
		0x684D6BB2E57FA8E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FF72E0000000000ULL,
		0x4A22CFBA29420829ULL,
		0xE3AC1B6D27D76864ULL,
		0xFF51C1387E9C9290ULL,
		0x000000D09AD765CAULL
	}};
	shift = 233;
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
		0x5C5E1B58FDE1F9C6ULL,
		0xB6264810F6901F2EULL,
		0x880892ED743347EEULL,
		0x1D30658BFA943841ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB1FBC3F38C000000ULL,
		0x21ED203E5CB8BC36ULL,
		0xDAE8668FDD6C4C90ULL,
		0x17F5287083101125ULL,
		0x00000000003A60CBULL,
		0x0000000000000000ULL
	}};
	shift = 153;
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
		0xD0B4EBE52A87F25CULL,
		0xE6318900C39D2D6BULL,
		0x20558A6FD9C3466DULL,
		0x23E26920D24F6E79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF42D3AF94AA1FC97ULL,
		0x798C624030E74B5AULL,
		0x4815629BF670D19BULL,
		0x08F89A483493DB9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0xB7C7010A7119A4DEULL,
		0x1CF2716CDEA2ACCFULL,
		0x9E06DEDB14399376ULL,
		0x37766B056D2954B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3780000000000000ULL,
		0x33EDF1C0429C4669ULL,
		0xDD873C9C5B37A8ABULL,
		0x2CE781B7B6C50E64ULL,
		0x000DDD9AC15B4A55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xF465692D8DA758B5ULL,
		0xA9A6776E68244CD4ULL,
		0x5CB272F1679F5338ULL,
		0x505F3ECC4E4EA8B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A4B6369D62D400ULL,
		0x99DDB9A0913353D1ULL,
		0xC9CBC59E7D4CE2A6ULL,
		0x7CFB31393AA2DD72ULL,
		0x0000000000000141ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x5977DBA87C7BE08DULL,
		0x10FC29C53ED758D5ULL,
		0xA7BAAE2B16ACD886ULL,
		0x382597B35E8C06E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1F1EF8234000000ULL,
		0x14FB5D635565DF6EULL,
		0xAC5AB3621843F0A7ULL,
		0xCD7A301BA69EEAB8ULL,
		0x0000000000E0965EULL
	}};
	shift = 218;
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
		0xBEA21B8684A13867ULL,
		0xA504F4544C26174BULL,
		0xB2B5218077AE0C40ULL,
		0x2111441296B4F08BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC342509C3380000ULL,
		0xA2A26130BA5DF510ULL,
		0x0C03BD7062052827ULL,
		0x2094B5A7845D95A9ULL,
		0x000000000001088AULL,
		0x0000000000000000ULL
	}};
	shift = 147;
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
		0xCFDE2B4DB76ADE7BULL,
		0x6A35B93A06AE5D44ULL,
		0xC7B5043716424951ULL,
		0x4EA2254328FE10D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79EC000000000000ULL,
		0x75133F78AD36DDABULL,
		0x2545A8D6E4E81AB9ULL,
		0x434F1ED410DC5909ULL,
		0x00013A88950CA3F8ULL
	}};
	shift = 242;
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
		0xE63F22116EEEEC41ULL,
		0x4BB3B9E08F6429F5ULL,
		0x9B8B32BA70D58338ULL,
		0x18576F3D1BF43D94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF22116EEEEC41000ULL,
		0x3B9E08F6429F5E63ULL,
		0xB32BA70D583384BBULL,
		0x76F3D1BF43D949B8ULL,
		0x0000000000000185ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x6126385D24045856ULL,
		0xF437426A84DFF22CULL,
		0x4B476ED7A36E4E57ULL,
		0x029A9579BAC20DB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1161580000000000ULL,
		0x7FC8B18498E17490ULL,
		0xB9395FD0DD09AA13ULL,
		0x0836E12D1DBB5E8DULL,
		0x0000000A6A55E6EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
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
		0x64925C2D21D5E278ULL,
		0x1B56D077012707AFULL,
		0xA1A37B1C934D0939ULL,
		0x3BAB853D101E5259ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4925C2D21D5E2780ULL,
		0xB56D077012707AF6ULL,
		0x1A37B1C934D09391ULL,
		0xBAB853D101E5259AULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
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
		0xACEDA6BB5AA37751ULL,
		0x7F364DA44E4DD249ULL,
		0xD29A299A40153E59ULL,
		0x250B56E8905164ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6EEA200000000000ULL,
		0xBA49359DB4D76B54ULL,
		0xA7CB2FE6C9B489C9ULL,
		0x2C957A5345334802ULL,
		0x000004A16ADD120AULL
	}};
	shift = 237;
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
		0xC7FFE5C446BE5188ULL,
		0x024EAB5E5A4C186CULL,
		0xB2D52CECD099B74EULL,
		0x700D27732B32670DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x88D7CA3100000000ULL,
		0xCB49830D98FFFCB8ULL,
		0x9A1336E9C049D56BULL,
		0x65664CE1B65AA59DULL,
		0x000000000E01A4EEULL
	}};
	shift = 221;
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
		0xDE824024192B7E4EULL,
		0xF22B7C065F2CE880ULL,
		0x57E621859C603A0FULL,
		0x7FA58137181C0B52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC95BF27000000000ULL,
		0xF9674406F4120120ULL,
		0xE301D07F915BE032ULL,
		0xC0E05A92BF310C2CULL,
		0x00000003FD2C09B8ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
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
		0x261822F0C58F933CULL,
		0x5AE5483203B667F0ULL,
		0xFD8D8F8C421FE8A4ULL,
		0x3DA6BE4A9CDC3EF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3163E4CF0000000ULL,
		0xC80ED99FC098608BULL,
		0x31087FA2916B9520ULL,
		0x2A7370FBDFF6363EULL,
		0x0000000000F69AF9ULL
	}};
	shift = 218;
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
		0x100C042A7E940EE2ULL,
		0xD54C7D6D792FDB26ULL,
		0x8022C8E34C7F8A91ULL,
		0x76CC1461D0DC34F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0180854FD281DC40ULL,
		0xA98FADAF25FB64C2ULL,
		0x04591C698FF1523AULL,
		0xD9828C3A1B869E30ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0xC2492075429DE640ULL,
		0x5BD1AB35EF132F43ULL,
		0x8DEE61F4A14257C1ULL,
		0x2C8D261CEA72BA52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DE6400000000000ULL,
		0x132F43C249207542ULL,
		0x4257C15BD1AB35EFULL,
		0x72BA528DEE61F4A1ULL,
		0x0000002C8D261CEAULL
	}};
	shift = 232;
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
		0x78534177684B7ADAULL,
		0x043FB808A1AC9291ULL,
		0x9E3275B33D498682ULL,
		0x451F9BF314D7AAB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29A0BBB425BD6D00ULL,
		0x1FDC0450D64948BCULL,
		0x193AD99EA4C34102ULL,
		0x8FCDF98A6BD559CFULL,
		0x0000000000000022ULL
	}};
	shift = 199;
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
		0xB1C62352088F444BULL,
		0xA20603D1A7714DD5ULL,
		0xFC9E180395572D3AULL,
		0x55C525361407A297ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0xB638C46A4111E889ULL,
		0x5440C07A34EE29BAULL,
		0xFF93C30072AAE5A7ULL,
		0x0AB8A4A6C280F452ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x1404747BC6C21881ULL,
		0xE49234D3F0CCB840ULL,
		0xDFFFE2334953D612ULL,
		0x659532C0C7A46161ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8620400000000000ULL,
		0x2E1005011D1EF1B0ULL,
		0xF584B9248D34FC33ULL,
		0x185877FFF88CD254ULL,
		0x000019654CB031E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0xFE0E8EA121D90CDFULL,
		0xF9E5E2D539A2BE2FULL,
		0xECBC82F26693EB93ULL,
		0x7691627A719B367AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7475090EC866F800ULL,
		0x2F16A9CD15F17FF0ULL,
		0xE41793349F5C9FCFULL,
		0x8B13D38CD9B3D765ULL,
		0x00000000000003B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x02945D845132CF6BULL,
		0x70CA841BFE001763ULL,
		0x699DADE2534FB726ULL,
		0x26F30C49D1293FFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2EC2289967B58000ULL,
		0x420DFF000BB1814AULL,
		0xD6F129A7DB933865ULL,
		0x8624E8949FFF34CEULL,
		0x0000000000001379ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0xA62EBD992BC96673ULL,
		0x57AE0A43D2BAB759ULL,
		0x02EB9808860407EFULL,
		0x25A306350371DB74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5D7B325792CCE6ULL,
		0xAF5C1487A5756EB3ULL,
		0x05D730110C080FDEULL,
		0x4B460C6A06E3B6E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xB7E34651FE3414F9ULL,
		0x634890C920476E24ULL,
		0x7DEDFEB9297FF18DULL,
		0x436DC6B4BF5C3B6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51FE3414F9000000ULL,
		0xC920476E24B7E346ULL,
		0xB9297FF18D634890ULL,
		0xB4BF5C3B6B7DEDFEULL,
		0x0000000000436DC6ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x9A385E5F43491C0EULL,
		0xF1780A053A563B4CULL,
		0xA9386CAABBF78859ULL,
		0x5FAAD793F3BA5298ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2381C00000000000ULL,
		0xC76993470BCBE869ULL,
		0xF10B3E2F0140A74AULL,
		0x4A5315270D95577EULL,
		0x00000BF55AF27E77ULL
	}};
	shift = 237;
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
		0xC9030981330B2A98ULL,
		0x076FD88EDB94C8C5ULL,
		0x63FB8CB265A600BFULL,
		0x7DEE08644B4158EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x5C9030981330B2A9ULL,
		0xF076FD88EDB94C8CULL,
		0xB63FB8CB265A600BULL,
		0x07DEE08644B4158EULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0x8CA4585574802D7FULL,
		0x41920ECC8D027723ULL,
		0x4AC3F80D719345A3ULL,
		0x56E835B087612FA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x585574802D7F0000ULL,
		0x0ECC8D0277238CA4ULL,
		0xF80D719345A34192ULL,
		0x35B087612FA14AC3ULL,
		0x00000000000056E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xB10112382CC7AD8AULL,
		0x149AB3928F41412FULL,
		0xE8E7FC48E0F36AE7ULL,
		0x2D2027FC6E24F750ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1C1663D6C5000000ULL,
		0xC947A0A097D88089ULL,
		0x247079B5738A4D59ULL,
		0xFE37127BA87473FEULL,
		0x0000000000169013ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0xCC1715A85E15184FULL,
		0xB91635959372141DULL,
		0xCA5421FBEEB1F48FULL,
		0x6618C4BBF1DBC736ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x854613C000000000ULL,
		0xDC85077305C56A17ULL,
		0xAC7D23EE458D6564ULL,
		0x76F1CDB295087EFBULL,
		0x0000001986312EFCULL
	}};
	shift = 230;
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
		0xB33D6E5B250A348DULL,
		0x5EA80307BD65D3EBULL,
		0x86F07B370BB14011ULL,
		0x114D1E4513F885AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xD99EB72D92851A46ULL,
		0xAF540183DEB2E9F5ULL,
		0xC3783D9B85D8A008ULL,
		0x08A68F2289FC42D7ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0xC1249AC5CD9361B1ULL,
		0x082A281B847C77DEULL,
		0xE93B41F26A862040ULL,
		0x6265E501F5E962FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C36200000000000ULL,
		0x8EFBD8249358B9B2ULL,
		0xC40801054503708FULL,
		0x2C5FFD27683E4D50ULL,
		0x00000C4CBCA03EBDULL,
		0x0000000000000000ULL
	}};
	shift = 173;
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
		0x5712EC9EE4B6DD6FULL,
		0x031F2C27B9FDF0EEULL,
		0x75EF591B02F67C99ULL,
		0x485F5E91564F9142ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x764F725B6EB78000ULL,
		0x9613DCFEF8772B89ULL,
		0xAC8D817B3E4C818FULL,
		0xAF48AB27C8A13AF7ULL,
		0x000000000000242FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
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
		0x8310CB4DF1908220ULL,
		0x223F109A51EC002CULL,
		0x5DCF6B14EEA657B5ULL,
		0x198B2171339BFC66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8C8411000000000ULL,
		0x28F60016418865A6ULL,
		0x77532BDA911F884DULL,
		0x99CDFE332EE7B58AULL,
		0x000000000CC590B8ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x93332172F7DC4EEDULL,
		0x45FAED01FC60FE13ULL,
		0xB702D88E92E6A63EULL,
		0x50F74064F4207F44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CCC85CBDF713BB4ULL,
		0x17EBB407F183F84EULL,
		0xDC0B623A4B9A98F9ULL,
		0x43DD0193D081FD12ULL,
		0x0000000000000001ULL
	}};
	shift = 194;
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
		0x309ADCD42DEF2BF7ULL,
		0x62CF18FFE8469EF2ULL,
		0x72424B5FF7BD8F4CULL,
		0x103DC25AC1AC0750ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA85BDE57EE000000ULL,
		0xFFD08D3DE46135B9ULL,
		0xBFEF7B1E98C59E31ULL,
		0xB583580EA0E48496ULL,
		0x0000000000207B84ULL
	}};
	shift = 217;
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
		0xAD2D778E150055AAULL,
		0x2A46DBE7CBBC9294ULL,
		0x0BFD81ECF937F9FFULL,
		0x1219207F47E02387ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5AEF1C2A00AB540ULL,
		0x48DB7CF977925295ULL,
		0x7FB03D9F26FF3FE5ULL,
		0x43240FE8FC0470E1ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
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
		0xD7092DE0651E6F8DULL,
		0x05814EC90B734269ULL,
		0xAC251D435CD75B63ULL,
		0x266427B1D5A2FFC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBE34000000000000ULL,
		0x09A75C24B7819479ULL,
		0x6D8C16053B242DCDULL,
		0xFF26B094750D735DULL,
		0x000099909EC7568BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0x1EA41B0E8035DDE6ULL,
		0xB8FEE8438500D62DULL,
		0x9E9BE28E72D370BBULL,
		0x4831EDE8023126E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDDE6000000000000ULL,
		0xD62D1EA41B0E8035ULL,
		0x70BBB8FEE8438500ULL,
		0x26E39E9BE28E72D3ULL,
		0x00004831EDE80231ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x6898646261332F50ULL,
		0x97818A519F89F0CBULL,
		0xFD5F663EA5E1EEE7ULL,
		0x385639D921B5AABCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x984CCBD400000000ULL,
		0x67E27C32DA261918ULL,
		0xA9787BB9E5E06294ULL,
		0x486D6AAF3F57D98FULL,
		0x000000000E158E76ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
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
		0x49C9BBB0CA253B1DULL,
		0x3A79CB475A7CE86DULL,
		0x00A379CF0F5B3186ULL,
		0x52783F66113309C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBB0CA253B1D000ULL,
		0x9CB475A7CE86D49CULL,
		0x379CF0F5B31863A7ULL,
		0x83F66113309C900AULL,
		0x0000000000000527ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xA47DBC2D59B571F6ULL,
		0x282B2E50A888B048ULL,
		0xEC125C60D8E4D432ULL,
		0x7C51B55A5792A426ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACDAB8FB00000000ULL,
		0x54445824523EDE16ULL,
		0x6C726A1914159728ULL,
		0x2BC9521376092E30ULL,
		0x000000003E28DAADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xAB7225AAA559623DULL,
		0x9677469CE1F057A8ULL,
		0x4FC18E82A7BFE704ULL,
		0x517290ACD04724BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C47A00000000000ULL,
		0x0AF5156E44B554ABULL,
		0xFCE092CEE8D39C3EULL,
		0xE497A9F831D054F7ULL,
		0x00000A2E52159A08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
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
		0xF124603F2B262FFBULL,
		0x23FFF950B563BF3EULL,
		0x6E484E2DD1C8884FULL,
		0x787C03C7395F9BA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFEC0000000000000ULL,
		0xCFBC49180FCAC98BULL,
		0x13C8FFFE542D58EFULL,
		0xE89B92138B747222ULL,
		0x001E1F00F1CE57E6ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x716A10111D80018BULL,
		0xB69D7992F09E2EFBULL,
		0x09C1CD59BE94C0DBULL,
		0x35166F7B3126D2A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B00000000000000ULL,
		0xFB716A10111D8001ULL,
		0xDBB69D7992F09E2EULL,
		0xA309C1CD59BE94C0ULL,
		0x0035166F7B3126D2ULL
	}};
	shift = 248;
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
		0x38C9A86AAA6DD898ULL,
		0x455D34396F0996A3ULL,
		0x7E11C7780E8D15EAULL,
		0x6F6C4E376F0F70A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6DD8980000000000ULL,
		0x0996A338C9A86AAAULL,
		0x8D15EA455D34396FULL,
		0x0F70A67E11C7780EULL,
		0x0000006F6C4E376FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0x040B1FC2FE80C4EEULL,
		0xFEAEBDAF0A58F2E8ULL,
		0x01D65C164B7678F8ULL,
		0x6067157000C04300ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7700000000000000ULL,
		0x7402058FE17F4062ULL,
		0x7C7F575ED7852C79ULL,
		0x8000EB2E0B25BB3CULL,
		0x0030338AB8006021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0xD146F77DCDFCFA02ULL,
		0xB117FFC6E3E50639ULL,
		0x10CBDEFAB4A063D8ULL,
		0x25CE8245727775AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28DEEFB9BF9F4040ULL,
		0x22FFF8DC7CA0C73AULL,
		0x197BDF56940C7B16ULL,
		0xB9D048AE4EEEB542ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
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
		0xD4FD1ADC09E071FAULL,
		0x6282AF91559B03C0ULL,
		0x69718FF1006BE48EULL,
		0x2727AD210AC5E375ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1C7E800000000000ULL,
		0xC0F0353F46B70278ULL,
		0xF92398A0ABE45566ULL,
		0x78DD5A5C63FC401AULL,
		0x000009C9EB4842B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0xAF92494D50D6832CULL,
		0x9AEB6DC0466FF609ULL,
		0x84A7AAF9FE4B846BULL,
		0x0FC539BCAFC17206ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929AA1AD06580000ULL,
		0xDB808CDFEC135F24ULL,
		0x55F3FC9708D735D6ULL,
		0x73795F82E40D094FULL,
		0x0000000000001F8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x888D144E23CD9CD4ULL,
		0xE559EDDBBBBFF756ULL,
		0xED0E81901D7C1F44ULL,
		0x62B1FB895F790845ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1388F36735000000ULL,
		0x76EEEFFDD5A22345ULL,
		0x64075F07D139567BULL,
		0xE257DE42117B43A0ULL,
		0x000000000018AC7EULL,
		0x0000000000000000ULL
	}};
	shift = 150;
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
		0x63970D6B622D039CULL,
		0x7E10EEF3862A4FD9ULL,
		0xF90D05B87A9CAF77ULL,
		0x4C3797A87BF22271ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D6B622D039C0000ULL,
		0xEEF3862A4FD96397ULL,
		0x05B87A9CAF777E10ULL,
		0x97A87BF22271F90DULL,
		0x0000000000004C37ULL
	}};
	shift = 208;
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
		0x8E18C5E5843A1319ULL,
		0xE02B20A1332674D2ULL,
		0xC09A7EEAE5FFAA0DULL,
		0x6E4D01446C72BE0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x843A131900000000ULL,
		0x332674D28E18C5E5ULL,
		0xE5FFAA0DE02B20A1ULL,
		0x6C72BE0AC09A7EEAULL,
		0x000000006E4D0144ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0x94E6D9D1BA3BA993ULL,
		0x146F3DD6BAE795C2ULL,
		0xA8D4CE9F766E409CULL,
		0x35BC400617AA8E81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3A3747753260000ULL,
		0x7BAD75CF2B8529CDULL,
		0x9D3EECDC813828DEULL,
		0x800C2F551D0351A9ULL,
		0x0000000000006B78ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
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
		0xF832424CA3A05E5BULL,
		0xA2D343A72667CEECULL,
		0x877443493CD545B2ULL,
		0x08ADF8DDA2FCDA02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC19212651D02F2D8ULL,
		0x169A1D39333E7767ULL,
		0x3BA21A49E6AA2D95ULL,
		0x456FC6ED17E6D014ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
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
		0x85A89648FCB61084ULL,
		0x2084019B20A0D5E6ULL,
		0xC39193FF64E0C0D2ULL,
		0x29796C6409EDE93EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A89648FCB610840ULL,
		0x084019B20A0D5E68ULL,
		0x39193FF64E0C0D22ULL,
		0x9796C6409EDE93ECULL,
		0x0000000000000002ULL
	}};
	shift = 196;
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
		0x127D449F13B77960ULL,
		0x096C8E7F45ABFE64ULL,
		0x2E487786ED722D73ULL,
		0x105EF9477A1C8EE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x049F5127C4EDDE58ULL,
		0xC25B239FD16AFF99ULL,
		0xCB921DE1BB5C8B5CULL,
		0x0417BE51DE8723B8ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
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
		0xB0F60FABE9300C1BULL,
		0xF1FB488B021DBD65ULL,
		0x9595B3AB208B324FULL,
		0x2A8A8EE07868A51FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x60D8000000000000ULL,
		0xEB2D87B07D5F4980ULL,
		0x927F8FDA445810EDULL,
		0x28FCACAD9D590459ULL,
		0x000154547703C345ULL,
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
		0xBF65CD99174D929DULL,
		0x4D21DE16C8FA1E4DULL,
		0x0DCE9BF73D296767ULL,
		0x20EB8D5099B244C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E6CC8BA6C94E800ULL,
		0x0EF0B647D0F26DFBULL,
		0x74DFB9E94B3B3A69ULL,
		0x5C6A84CD9226086EULL,
		0x0000000000000107ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x32A2DA1E4967E010ULL,
		0x6AF40CE943C148D2ULL,
		0xA178F945BA28732AULL,
		0x193CA1E32161B35DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x16D0F24B3F008000ULL,
		0xA0674A1E0A469195ULL,
		0xC7CA2DD143995357ULL,
		0xE50F190B0D9AED0BULL,
		0x00000000000000C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
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
		0xAD4CD3178490F1ABULL,
		0x12AE4BF167A9013FULL,
		0xB4A88434D052EFA8ULL,
		0x6198C4C8166E9576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0921E35600000000ULL,
		0xCF52027F5A99A62FULL,
		0xA0A5DF50255C97E2ULL,
		0x2CDD2AED69510869ULL,
		0x00000000C3318990ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0xCEB2BB813C858065ULL,
		0x1A2435313BE027FCULL,
		0xDAD695A4329C4200ULL,
		0x4B19F8F810D5D3CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAEE04F2160194000ULL,
		0x0D4C4EF809FF33ACULL,
		0xA5690CA710800689ULL,
		0x7E3E043574F2F6B5ULL,
		0x00000000000012C6ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
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
		0x85358B0FA576A7D6ULL,
		0x6D4CD5721A7D89B0ULL,
		0xE1E4EC5FBEED01C1ULL,
		0x2A2876032130DC26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x87D2BB53EB000000ULL,
		0xB90D3EC4D8429AC5ULL,
		0x2FDF7680E0B6A66AULL,
		0x0190986E1370F276ULL,
		0x000000000015143BULL
	}};
	shift = 215;
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
		0x787E93254C8A9688ULL,
		0xF93017F715F12184ULL,
		0xDEB07466E47A9818ULL,
		0x2183916B6402C991ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2A6454B440000000ULL,
		0xB8AF890C23C3F499ULL,
		0x3723D4C0C7C980BFULL,
		0x5B20164C8EF583A3ULL,
		0x00000000010C1C8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
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
		0xB4D3CCA5DCC2AE32ULL,
		0xF7FB7B4BB337E580ULL,
		0xEDF323E3315EBFC2ULL,
		0x03CBAF62630263C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3200000000000000ULL,
		0x80B4D3CCA5DCC2AEULL,
		0xC2F7FB7B4BB337E5ULL,
		0xC1EDF323E3315EBFULL,
		0x0003CBAF62630263ULL
	}};
	shift = 248;
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
		0x207C5BB26D881D33ULL,
		0xFE42D2FDDF24C5CBULL,
		0xD8D586F6875BB18DULL,
		0x76C3A31E26611459ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB62074CC00000000ULL,
		0x7C93172C81F16EC9ULL,
		0x1D6EC637F90B4BF7ULL,
		0x9984516763561BDAULL,
		0x00000001DB0E8C78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
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
		0xF16F30FF8FCA8BFFULL,
		0x37A829BF5514B4C7ULL,
		0x8F1E09238BABCF2CULL,
		0x03278DDD54068404ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xFE2DE61FF1F9517FULL,
		0x86F50537EAA29698ULL,
		0x91E3C124717579E5ULL,
		0x0064F1BBAA80D080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
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
		0x6B4143B1D6F52212ULL,
		0x68E60CE4A368A7C4ULL,
		0x67D00D8FB0973940ULL,
		0x2D0F8F72FE93544AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50EC75BD48848000ULL,
		0x833928DA29F11AD0ULL,
		0x0363EC25CE501A39ULL,
		0xE3DCBFA4D51299F4ULL,
		0x0000000000000B43ULL
	}};
	shift = 206;
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
		0xBE4821264BE52E28ULL,
		0x5960CFD20873A197ULL,
		0x79A8A7D6C5D20C56ULL,
		0x7ED543DDFD4DDCA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x92084992F94B8A00ULL,
		0x5833F4821CE865EFULL,
		0x6A29F5B174831596ULL,
		0xB550F77F5377281EULL,
		0x000000000000001FULL
	}};
	shift = 198;
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
		0x8B45777EF1A145B3ULL,
		0xDF52E64BFB4D07DEULL,
		0x155FF95309B278F6ULL,
		0x74F46E5278B30328ULL,
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
		0x45A2BBBF78D0A2D9ULL,
		0x6FA97325FDA683EFULL,
		0x0AAFFCA984D93C7BULL,
		0x3A7A37293C598194ULL
	}};
	shift = 255;
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
		0xCE11B82CFF35B490ULL,
		0xE63864E95D1C39A3ULL,
		0x10D266C97F18D7AFULL,
		0x1FDE59B902A256D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC237059FE6B69200ULL,
		0xC70C9D2BA3873479ULL,
		0x1A4CD92FE31AF5FCULL,
		0xFBCB3720544ADA22ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
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
		0x83FCD2AD0506E20EULL,
		0xD8ED273BFD306CA4ULL,
		0x469A6C79DF4A4081ULL,
		0x2BC6F3659CDC58C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x483FCD2AD0506E20ULL,
		0x1D8ED273BFD306CAULL,
		0x6469A6C79DF4A408ULL,
		0x02BC6F3659CDC58CULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0xB34AE6CDAAF29D53ULL,
		0x9DC3CDC75A0F34FAULL,
		0x75E2A504D537A645ULL,
		0x3E5D86193796AD58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7366D5794EA98000ULL,
		0xE6E3AD079A7D59A5ULL,
		0x52826A9BD322CEE1ULL,
		0xC30C9BCB56AC3AF1ULL,
		0x0000000000001F2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
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
		0xEE13424C146708C4ULL,
		0xF0BF63D0369D00C4ULL,
		0x44C105B13942BEA6ULL,
		0x1FF2E8DA7F7CE601ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x930519C231000000ULL,
		0xF40DA740313B84D0ULL,
		0x6C4E50AFA9BC2FD8ULL,
		0x369FDF3980513041ULL,
		0x000000000007FCBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x0EBD344A51BEDC58ULL,
		0xB9123ED12045B553ULL,
		0x6EFF5D7571F0A77EULL,
		0x6A7B4331AD647011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8B0000000000000ULL,
		0x6AA61D7A6894A37DULL,
		0x4EFD72247DA2408BULL,
		0xE022DDFEBAEAE3E1ULL,
		0x0000D4F686635AC8ULL
	}};
	shift = 241;
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
		0x6681CF3FCC7F916FULL,
		0x7595412407F0A03FULL,
		0x83320C3B1E17FCD3ULL,
		0x17EA947FD9F1C9B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x916F000000000000ULL,
		0xA03F6681CF3FCC7FULL,
		0xFCD37595412407F0ULL,
		0xC9B783320C3B1E17ULL,
		0x000017EA947FD9F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x0A95FCB09175BF87ULL,
		0x6E1418E3B10EA38EULL,
		0x026B07E5667A784EULL,
		0x114612B4911D71C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C245D6FE1C0000ULL,
		0x638EC43A8E382A57ULL,
		0x1F9599E9E139B850ULL,
		0x4AD24475C71009ACULL,
		0x0000000000004518ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x99884B93C7AAF4E6ULL,
		0xD0AB7FC5A6DF8F05ULL,
		0x98AF7A68E6535B6EULL,
		0x22E34BD196A24114ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4F1EABD3980000ULL,
		0xFF169B7E3C166621ULL,
		0xE9A3994D6DBB42ADULL,
		0x2F465A89045262BDULL,
		0x0000000000008B8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x2CF268CDCC2C5BC9ULL,
		0x54A524ACFDAC3226ULL,
		0x2950F73ABEA3D257ULL,
		0x7793BC766295912CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9200000000000000ULL,
		0x4C59E4D19B9858B7ULL,
		0xAEA94A4959FB5864ULL,
		0x5852A1EE757D47A4ULL,
		0x00EF2778ECC52B22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x975AA61AFC24631EULL,
		0xCAA81458C658CBADULL,
		0xF15942C113E492BFULL,
		0x39411482B0FD3172ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E00000000000000ULL,
		0xAD975AA61AFC2463ULL,
		0xBFCAA81458C658CBULL,
		0x72F15942C113E492ULL,
		0x0039411482B0FD31ULL
	}};
	shift = 248;
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
		0xEBA5DC40D7181DA5ULL,
		0x819B86EFCB27C076ULL,
		0x965D4F82AAAC6791ULL,
		0x59AB799D4846EB68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD2EE206B8C0ED280ULL,
		0xCDC377E593E03B75ULL,
		0x2EA7C1555633C8C0ULL,
		0xD5BCCEA42375B44BULL,
		0x000000000000002CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
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
		0x23B2F9E755408413ULL,
		0xA1206B4110336FE8ULL,
		0x35D66676A2FFCE2BULL,
		0x5FB1FA307FD936B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x502104C000000000ULL,
		0x0CDBFA08ECBE79D5ULL,
		0xBFF38AE8481AD044ULL,
		0xF64DADCD75999DA8ULL,
		0x00000017EC7E8C1FULL,
		0x0000000000000000ULL
	}};
	shift = 166;
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
		0x0712DD9FA205B3C7ULL,
		0xB6EF4F52B40B2746ULL,
		0x2A30FE5C10C800BDULL,
		0x6A3F3678602BDFAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x896ECFD102D9E380ULL,
		0x77A7A95A0593A303ULL,
		0x187F2E0864005EDBULL,
		0x1F9B3C3015EFD795ULL,
		0x0000000000000035ULL
	}};
	shift = 199;
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
		0xAC702D1D27E85BB3ULL,
		0x757771B87F998E0FULL,
		0x3E6110232273562AULL,
		0x42807A57C3BBF50FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6600000000000000ULL,
		0x1F58E05A3A4FD0B7ULL,
		0x54EAEEE370FF331CULL,
		0x1E7CC2204644E6ACULL,
		0x008500F4AF8777EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
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
		0xA3AC657E2FABC026ULL,
		0x9B3B92D57159F658ULL,
		0xFC9EEF52A68E9970ULL,
		0x035290A1147897A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F8BEAF00980000ULL,
		0x4B55C567D9628EB1ULL,
		0xBD4A9A3A65C26CEEULL,
		0x428451E25E93F27BULL,
		0x0000000000000D4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x5CDBF67BE4D6C369ULL,
		0x72A82790BE712924ULL,
		0x6EA82E2A85024B31ULL,
		0x0DFDA7C17C17D9D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BE4D6C369000000ULL,
		0x90BE7129245CDBF6ULL,
		0x2A85024B3172A827ULL,
		0xC17C17D9D76EA82EULL,
		0x00000000000DFDA7ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x45B672E2CF91360AULL,
		0x52BD4011F1CA7FA9ULL,
		0xA8F807F1D2B08F8DULL,
		0x1FF6146DB6BE80B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E2CF91360A00000ULL,
		0x011F1CA7FA945B67ULL,
		0x7F1D2B08F8D52BD4ULL,
		0x46DB6BE80B4A8F80ULL,
		0x000000000001FF61ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x7BC890C45A518A36ULL,
		0xBE564FAC0FEFC8D5ULL,
		0xCEF723B18820B62DULL,
		0x199AC9F1844B2AACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5A518A3600000000ULL,
		0x0FEFC8D57BC890C4ULL,
		0x8820B62DBE564FACULL,
		0x844B2AACCEF723B1ULL,
		0x00000000199AC9F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0xE594C1760BADB08DULL,
		0xC844B2D71D3453B9ULL,
		0x1A1C3A3B8D5D0578ULL,
		0x6E48A8B104CC4EACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08D0000000000000ULL,
		0x3B9E594C1760BADBULL,
		0x578C844B2D71D345ULL,
		0xEAC1A1C3A3B8D5D0ULL,
		0x0006E48A8B104CC4ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
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
		0x25B64170D48C2164ULL,
		0x011CD499CEDBCB8FULL,
		0x673CBAE5E2EA4F02ULL,
		0x09D59BE21441D7CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0859000000000000ULL,
		0xF2E3C96D905C3523ULL,
		0x93C08047352673B6ULL,
		0x75F359CF2EB978BAULL,
		0x0000027566F88510ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x5EC008E1A3E1D884ULL,
		0xB912505A3F867AAEULL,
		0x5A7012FC7619D985ULL,
		0x78914E1A6C62EEE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1C347C3B10800000ULL,
		0x0B47F0CF55CBD801ULL,
		0x5F8EC33B30B7224AULL,
		0xC34D8C5DDCCB4E02ULL,
		0x00000000000F1229ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
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
		0x37310279849A1DADULL,
		0x4FEC3489E236A3E5ULL,
		0xAD35E52518FB73B9ULL,
		0x5E1A447F23F84377ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5A00000000000000ULL,
		0xCA6E6204F309343BULL,
		0x729FD86913C46D47ULL,
		0xEF5A6BCA4A31F6E7ULL,
		0x00BC3488FE47F086ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
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
		0x41CC03164E147024ULL,
		0xA507C82B5FA52E9AULL,
		0xBB30512BD2E8257CULL,
		0x43B6F55298537CE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2400000000000000ULL,
		0x9A41CC03164E1470ULL,
		0x7CA507C82B5FA52EULL,
		0xE3BB30512BD2E825ULL,
		0x0043B6F55298537CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x8A7CAAEA93A85F16ULL,
		0xC7E8A06E1CEB2DCFULL,
		0x3A7588896B7A45BBULL,
		0x2AB31A8898A99BABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A7CAAEA93A85F16ULL,
		0xC7E8A06E1CEB2DCFULL,
		0x3A7588896B7A45BBULL,
		0x2AB31A8898A99BABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xD313A5B71EA8AAABULL,
		0xE35936A6DC5E75A6ULL,
		0xB255E90E0035977BULL,
		0x4871B60220341586ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5580000000000000ULL,
		0xD36989D2DB8F5455ULL,
		0xBDF1AC9B536E2F3AULL,
		0xC3592AF487001ACBULL,
		0x002438DB01101A0AULL
	}};
	shift = 247;
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
		0xD7F778FDFAA2C3A5ULL,
		0x06544A52C5FFD8A9ULL,
		0x58FD039390B1EAE2ULL,
		0x7EB14707FDC7B707ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDFAA2C3A50000000ULL,
		0x2C5FFD8A9D7F778FULL,
		0x390B1EAE206544A5ULL,
		0x7FDC7B70758FD039ULL,
		0x0000000007EB1470ULL
	}};
	shift = 220;
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
		0x46D44ED2B58DB784ULL,
		0x835AD66F45C965B3ULL,
		0x76F7E22D157E8554ULL,
		0x282CA2C6C06CC395ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC6DBC20000000000ULL,
		0xE4B2D9A36A27695AULL,
		0xBF42AA41AD6B37A2ULL,
		0x3661CABB7BF1168AULL,
		0x0000001416516360ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x26C5157363934519ULL,
		0x99AC9B6E874CACB7ULL,
		0xF0E2CA4AE4BE19D6ULL,
		0x5D700E2BB522C746ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8AB9B1C9A28C8000ULL,
		0x4DB743A6565B9362ULL,
		0x6525725F0CEB4CD6ULL,
		0x0715DA9163A37871ULL,
		0x0000000000002EB8ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0xDAEECFFDF067FCD3ULL,
		0x2473F7A96BB66265ULL,
		0xFC54B129752095D5ULL,
		0x276A06E9CC40117EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CFF9A6000000000ULL,
		0x76CC4CBB5DD9FFBEULL,
		0xA412BAA48E7EF52DULL,
		0x88022FDF8A96252EULL,
		0x00000004ED40DD39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x12D7419ADA9E9088ULL,
		0xB2739F5B0313AACBULL,
		0xB5F8FBA0AE7CD8F9ULL,
		0x6CE3E4D062D963BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x2C4B5D066B6A7A42ULL,
		0xE6C9CE7D6C0C4EABULL,
		0xF6D7E3EE82B9F363ULL,
		0x01B38F93418B658EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
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
		0xC777C26B328521B6ULL,
		0x29E328C9B5A680B2ULL,
		0x24685D13C97D259FULL,
		0x4A08331F03F2B556ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA436C00000000000ULL,
		0xD01658EEF84D6650ULL,
		0xA4B3E53C651936B4ULL,
		0x56AAC48D0BA2792FULL,
		0x000009410663E07EULL
	}};
	shift = 237;
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
		0x3D88588254240946ULL,
		0x63BF3B9EE6BD5327ULL,
		0xE4E6E62DB6982BA3ULL,
		0x126F85A4677E142AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA300000000000000ULL,
		0x939EC42C412A1204ULL,
		0xD1B1DF9DCF735EA9ULL,
		0x1572737316DB4C15ULL,
		0x000937C2D233BF0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x6A7BE87AAF09961FULL,
		0x1017411205B76DE6ULL,
		0x6E6C5576FC5AF131ULL,
		0x6F6F2AF5F3583350ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFA1EABC26587C000ULL,
		0xD044816DDB799A9EULL,
		0x155DBF16BC4C4405ULL,
		0xCABD7CD60CD41B9BULL,
		0x0000000000001BDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
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
		0x96E28457290B1BE6ULL,
		0xFF75F44A652A3F3FULL,
		0xC8D6A1FEB2471741ULL,
		0x388F6E1E54D037F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37CC000000000000ULL,
		0x7E7F2DC508AE5216ULL,
		0x2E83FEEBE894CA54ULL,
		0x6FE591AD43FD648EULL,
		0x0000711EDC3CA9A0ULL
	}};
	shift = 241;
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
		0x0FC4A8C19131BD33ULL,
		0xC393A22DA97BD619ULL,
		0x2958F36C866DEDF3ULL,
		0x20198B82134B8CC5ULL,
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
		0x90FC4A8C19131BD3ULL,
		0x3C393A22DA97BD61ULL,
		0x52958F36C866DEDFULL,
		0x020198B82134B8CCULL
	}};
	shift = 252;
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
		0xA5BA4774FBDDE756ULL,
		0x2C0EBDDA78ABDAD4ULL,
		0x75798B636185AE42ULL,
		0x30BD80CE12CA8914ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD3EF779D5800000ULL,
		0x769E2AF6B5296E91ULL,
		0xD8D8616B908B03AFULL,
		0x3384B2A2451D5E62ULL,
		0x00000000000C2F60ULL
	}};
	shift = 214;
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
		0x7722148B29223C30ULL,
		0xD19B6F53D54255D5ULL,
		0xDC547E1D2B22F48CULL,
		0x6A3DB577B3F53EF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4594911E18000000ULL,
		0xA9EAA12AEABB910AULL,
		0x0E95917A4668CDB7ULL,
		0xBBD9FA9F786E2A3FULL,
		0x0000000000351EDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x5347CA2F3743A7B5ULL,
		0xD37C6A978D91226FULL,
		0xE588BE5FCDCF1235ULL,
		0x201DA0A41B1C03E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9ED400000000000ULL,
		0x489BD4D1F28BCDD0ULL,
		0xC48D74DF1AA5E364ULL,
		0x00F8F9622F97F373ULL,
		0x00000807682906C7ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
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
		0x00B7B663476C4FF6ULL,
		0xD0A597438A5659ADULL,
		0xA2FC56BC9C16D13DULL,
		0x1B6B3D410FFDA622ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9FEC000000000000ULL,
		0xB35A016F6CC68ED8ULL,
		0xA27BA14B2E8714ACULL,
		0x4C4545F8AD79382DULL,
		0x000036D67A821FFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
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
		0x01CEA02AADEED6C4ULL,
		0xDDDD967E82800542ULL,
		0x00970601902B911DULL,
		0x00AC6B906511FB13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEED6C4000000000ULL,
		0x280054201CEA02AAULL,
		0x02B911DDDDD967E8ULL,
		0x511FB13009706019ULL,
		0x000000000AC6B906ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x03561E196B6547B8ULL,
		0x05D0F6546F9A0CDDULL,
		0x41E36B40F00FDD83ULL,
		0x29D752C6D0358DDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xE81AB0F0CB5B2A3DULL,
		0x182E87B2A37CD066ULL,
		0xFA0F1B5A07807EECULL,
		0x014EBA963681AC6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0x2454DEBA5F67D9FAULL,
		0x50B53EE7CC3ADF52ULL,
		0x34920D3AFEACFE65ULL,
		0x0D150306C38307EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5D2FB3ECFD00000ULL,
		0xF73E61D6FA9122A6ULL,
		0x69D7F567F32A85A9ULL,
		0x18361C183F69A490ULL,
		0x00000000000068A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x7591D1D0EA3301FDULL,
		0x362B4844D5BF383EULL,
		0xA3D5129B6558351EULL,
		0x236830FDFAB1C8BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x3AC8E8E8751980FEULL,
		0x1B15A4226ADF9C1FULL,
		0xD1EA894DB2AC1A8FULL,
		0x11B4187EFD58E45DULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0x40C640E1AAA4B6ACULL,
		0xA05CDE3823A55BADULL,
		0xD267B0AA84E6E4A5ULL,
		0x1573DFE13C57AEF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAB0000000000000ULL,
		0x6EB503190386AA92ULL,
		0x9296817378E08E95ULL,
		0xBBDB499EC2AA139BULL,
		0x000055CF7F84F15EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x5475D1CB88FB390CULL,
		0x3D35C687790F1223ULL,
		0x53A3470D1377BB96ULL,
		0x022B69DA32C3ED46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8600000000000000ULL,
		0x11AA3AE8E5C47D9CULL,
		0xCB1E9AE343BC8789ULL,
		0xA329D1A38689BBDDULL,
		0x000115B4ED1961F6ULL
	}};
	shift = 247;
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
		0x8566ACABC39D0DD3ULL,
		0xC705BBD995C75CAEULL,
		0x7EA22678C07AEB3FULL,
		0x0C8119D89A988FA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1BA60000000000ULL,
		0x8EB95D0ACD595787ULL,
		0xF5D67F8E0B77B32BULL,
		0x311F4EFD444CF180ULL,
		0x000000190233B135ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xBD0DB3DE459EF0EEULL,
		0x7C5F443B9F52B082ULL,
		0x9B9EB3B701DC068FULL,
		0x78EE5AD2275285E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x2BD0DB3DE459EF0EULL,
		0xF7C5F443B9F52B08ULL,
		0x89B9EB3B701DC068ULL,
		0x078EE5AD2275285EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0xD1417D7BB47F98EBULL,
		0xBE9874123B26F226ULL,
		0x5ECE5EE63113D8E7ULL,
		0x09248A73D334CD64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xB4505F5EED1FE63AULL,
		0xEFA61D048EC9BC89ULL,
		0x17B397B98C44F639ULL,
		0x0249229CF4CD3359ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
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
		0x922CFB426751C8EDULL,
		0x9A0B8CBA885E1A63ULL,
		0x8EFB778BCE98A3B6ULL,
		0x38A2F2ED6114FC47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x459F684CEA391DA0ULL,
		0x417197510BC34C72ULL,
		0xDF6EF179D31476D3ULL,
		0x145E5DAC229F88F1ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x953FFB28B9BA9772ULL,
		0x57C4A1A377D4D0ABULL,
		0x7EFCA0BA5F996CAFULL,
		0x36E23A87BCDF198CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2EE4000000000000ULL,
		0xA1572A7FF6517375ULL,
		0xD95EAF894346EFA9ULL,
		0x3318FDF94174BF32ULL,
		0x00006DC4750F79BEULL
	}};
	shift = 241;
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
		0x84C97B168EBDC8B5ULL,
		0xC26AF87627C84A0CULL,
		0x5BC8611EBB9000C7ULL,
		0x45B402089D63F420ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC97B168EBDC8B500ULL,
		0x6AF87627C84A0C84ULL,
		0xC8611EBB9000C7C2ULL,
		0xB402089D63F4205BULL,
		0x0000000000000045ULL
	}};
	shift = 200;
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
		0x55C11639A4627C1AULL,
		0xA2E653172E75B4D0ULL,
		0x0E2455598214A238ULL,
		0x6EAC1BDB6C50FFACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C7348C4F8340000ULL,
		0xA62E5CEB69A0AB82ULL,
		0xAAB30429447145CCULL,
		0x37B6D8A1FF581C48ULL,
		0x000000000000DD58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
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
		0x4A4307AF449B10ADULL,
		0x90A76D06B3B2940DULL,
		0x4480FA5140FE4416ULL,
		0x58E600BFE828E5B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBD126C42B400000ULL,
		0x41ACECA5035290C1ULL,
		0x94503F9105A429DBULL,
		0x2FFA0A396DD1203EULL,
		0x0000000000163980ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x758936FAAFCB9F57ULL,
		0xA8252C9187318966ULL,
		0x658C93F9E5F76674ULL,
		0x2D4C4F2A6A691A2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E7D5C0000000000ULL,
		0xC62599D624DBEABFULL,
		0xDD99D2A094B2461CULL,
		0xA468BD96324FE797ULL,
		0x000000B5313CA9A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
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
		0x7894BFDF25B54D9DULL,
		0x2AB0D1F520BFE726ULL,
		0x9F965A491BB48058ULL,
		0x554E1995C02BF867ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1297FBE4B6A9B3A0ULL,
		0x561A3EA417FCE4CFULL,
		0xF2CB492376900B05ULL,
		0xA9C332B8057F0CF3ULL,
		0x000000000000000AULL
	}};
	shift = 197;
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
		0x68EE1C16A82D701AULL,
		0xBCAB269383077954ULL,
		0xDB3AF2710AAE4E76ULL,
		0x2BCD0E0B42028969ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x416B80D000000000ULL,
		0x183BCAA34770E0B5ULL,
		0x557273B5E559349CULL,
		0x10144B4ED9D79388ULL,
		0x000000015E68705AULL
	}};
	shift = 227;
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
		0xE72EE47CA3A9D97CULL,
		0x7AB4D741A4D40DDCULL,
		0x7C910D6B0245A385ULL,
		0x2FB53995011EB5EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8F94753B2F800000ULL,
		0xE8349A81BB9CE5DCULL,
		0xAD6048B470AF569AULL,
		0x32A023D6BDAF9221ULL,
		0x000000000005F6A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
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
		0x542F7115CCC0601BULL,
		0xB24F192370DC16F2ULL,
		0xAB2814B00C1B05A2ULL,
		0x2D5BB7B6FDFC3420ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73301806C0000000ULL,
		0xDC3705BC950BDC45ULL,
		0x0306C168AC93C648ULL,
		0xBF7F0D082ACA052CULL,
		0x000000000B56EDEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x930B8F20D6F13EF0ULL,
		0x0396C85C9EDE5A39ULL,
		0x68A741DC45F69402ULL,
		0x796FF885710D7748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27DE000000000000ULL,
		0xCB47326171E41ADEULL,
		0xD2804072D90B93DBULL,
		0xAEE90D14E83B88BEULL,
		0x00000F2DFF10AE21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
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
		0x801A3A02EF1DC5DFULL,
		0xBAABFF866DAAE320ULL,
		0xF75614E3DFDF030DULL,
		0x42FB905055F99251ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x01778EE2EF800000ULL,
		0xC336D57190400D1DULL,
		0x71EFEF8186DD55FFULL,
		0x282AFCC928FBAB0AULL,
		0x0000000000217DC8ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0xB04E773F307C5FA8ULL,
		0x24E088391429EAFFULL,
		0xA9E0EEA82AB8B5B8ULL,
		0x57B17D07FB265911ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x39DCFCC1F17EA000ULL,
		0x8220E450A7ABFEC1ULL,
		0x83BAA0AAE2D6E093ULL,
		0xC5F41FEC996446A7ULL,
		0x000000000000015EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
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
		0xB4615A3A7E9E47D9ULL,
		0xF30B80607AD196D7ULL,
		0x4D06C270ECA09DB8ULL,
		0x0036F90984E08E7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x474FD3C8FB200000ULL,
		0x0C0F5A32DAF68C2BULL,
		0x4E1D9413B71E6170ULL,
		0x21309C11CF69A0D8ULL,
		0x00000000000006DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
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
		0x346ECF37D8D45379ULL,
		0x1D820AF85EBD6429ULL,
		0x91403D0D4690BDB6ULL,
		0x0C9B4912478953CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x679BEC6A29BC8000ULL,
		0x057C2F5EB2149A37ULL,
		0x1E86A3485EDB0EC1ULL,
		0xA48923C4A9E5C8A0ULL,
		0x000000000000064DULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x58CC5713329F44EDULL,
		0xFD7D065F04C56B22ULL,
		0xCD06AB997EBEF014ULL,
		0x1E1F09B9E959BE9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994FA27680000000ULL,
		0x8262B5912C662B89ULL,
		0xBF5F780A7EBE832FULL,
		0xF4ACDF4FE68355CCULL,
		0x000000000F0F84DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xE2A3CB886032185CULL,
		0x3F24467A5D1475FDULL,
		0x4CDF3906FD025A67ULL,
		0x41C5CF196C966044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC06430B800000000ULL,
		0xBA28EBFBC5479710ULL,
		0xFA04B4CE7E488CF4ULL,
		0xD92CC08899BE720DULL,
		0x00000000838B9E32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
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
		0x17B24B0C5202848EULL,
		0xA951E961A936AB49ULL,
		0x00552F5C5E053961ULL,
		0x4CB5DD0C783E593CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4247000000000000ULL,
		0x55A48BD925862901ULL,
		0x9CB0D4A8F4B0D49BULL,
		0x2C9E002A97AE2F02ULL,
		0x0000265AEE863C1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x89984436BDD98C12ULL,
		0xA7AD8AAEBE943581ULL,
		0xCD4D9781D68F0D2CULL,
		0x56DC535E9A713292ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84436BDD98C12000ULL,
		0xD8AAEBE943581899ULL,
		0xD9781D68F0D2CA7AULL,
		0xC535E9A713292CD4ULL,
		0x000000000000056DULL
	}};
	shift = 204;
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
		0x82FFE9A59FDE42F0ULL,
		0x2AF36AA5AF2FAC6BULL,
		0xAB1F9114A64E94D7ULL,
		0x26B70296992E0FAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F00000000000000ULL,
		0xC6B82FFE9A59FDE4ULL,
		0x4D72AF36AA5AF2FAULL,
		0xFAFAB1F9114A64E9ULL,
		0x00026B70296992E0ULL
	}};
	shift = 244;
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
		0xC08C0EEEAC25260CULL,
		0x398123A2AE550EF8ULL,
		0x6419019E01C0F3E4ULL,
		0x73DFFEA3573E04F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC08C0EEEAC25260CULL,
		0x398123A2AE550EF8ULL,
		0x6419019E01C0F3E4ULL,
		0x73DFFEA3573E04F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0x651024C83BC12946ULL,
		0xE2030B3F71551772ULL,
		0xDB4522553E3F9551ULL,
		0x048C34D74344BE54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x782528C000000000ULL,
		0x2AA2EE4CA2049907ULL,
		0xC7F2AA3C406167EEULL,
		0x6897CA9B68A44AA7ULL,
		0x0000000091869AE8ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
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
		0xF93C0932533B0D0DULL,
		0xC8244CDE648979E3ULL,
		0x7E713564C2707294ULL,
		0x65A99CE92899147CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0499299D86868000ULL,
		0x266F3244BCF1FC9EULL,
		0x9AB26138394A6412ULL,
		0xCE74944C8A3E3F38ULL,
		0x00000000000032D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x882E26CE2620FC0DULL,
		0x6C25134A718751E0ULL,
		0xEB7BAC081E132192ULL,
		0x654C1600FCC7E842ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x713107E068000000ULL,
		0x538C3A8F04417136ULL,
		0x40F0990C9361289AULL,
		0x07E63F42175BDD60ULL,
		0x00000000032A60B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
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
		0x8E11C93D0ECB845FULL,
		0x14708B5B9149BDFDULL,
		0x0F7B17B7FF789A97ULL,
		0x6FF7AF3CA0915710ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF43B2E117C000000ULL,
		0x6E4526F7F6384724ULL,
		0xDFFDE26A5C51C22DULL,
		0xF282455C403DEC5EULL,
		0x0000000001BFDEBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x1FE0241F56903D8BULL,
		0x8A516E756AEC42F8ULL,
		0xAEBF72793FE977C4ULL,
		0x5321C9CE8457B02AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FAB481EC5800000ULL,
		0x3AB576217C0FF012ULL,
		0x3C9FF4BBE24528B7ULL,
		0xE7422BD815575FB9ULL,
		0x00000000002990E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x8DB3CDF5E9F1B04EULL,
		0x5CB8377D91DE0938ULL,
		0xD0AEB1714892ABCFULL,
		0x6A05ADC502958939ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFAF4F8D827000000ULL,
		0xBEC8EF049C46D9E6ULL,
		0xB8A44955E7AE5C1BULL,
		0xE2814AC49CE85758ULL,
		0x00000000003502D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x3AE140FD76BE2939ULL,
		0x5D856400EC8CEE35ULL,
		0xD1A3B13DF1499656ULL,
		0x34A67D47076033D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DAF8A4E40000000ULL,
		0x3B233B8D4EB8503FULL,
		0x7C52659597615900ULL,
		0xC1D80CF47468EC4FULL,
		0x000000000D299F51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xAB9382660E38C32AULL,
		0xA5E0F081D14474D1ULL,
		0xD7B68FC842519A96ULL,
		0x46590A4F914528B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x04CC1C7186540000ULL,
		0xE103A288E9A35727ULL,
		0x1F9084A3352D4BC1ULL,
		0x149F228A5161AF6DULL,
		0x0000000000008CB2ULL
	}};
	shift = 209;
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
		0x7B424A6BD7ABCF9FULL,
		0x8ABC6C3107656D9CULL,
		0xF9D4811AB80F5093ULL,
		0x62BF859B1E340184ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12535EBD5E7CF800ULL,
		0xE361883B2B6CE3DAULL,
		0xA408D5C07A849C55ULL,
		0xFC2CD8F1A00C27CEULL,
		0x0000000000000315ULL
	}};
	shift = 203;
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
		0x266F592220268A57ULL,
		0xEC43BAE85D1F50CAULL,
		0x3CD295863A991759ULL,
		0x3D13663A769409B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x911013452B800000ULL,
		0x742E8FA8651337ACULL,
		0xC31D4C8BACF621DDULL,
		0x1D3B4A04DC1E694AULL,
		0x00000000001E89B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x87E69CD8A0428ED2ULL,
		0x841E7647923FCD73ULL,
		0x32D96EAC07C5693BULL,
		0x3B5466BD4B62AC82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x387E69CD8A0428EDULL,
		0xB841E7647923FCD7ULL,
		0x232D96EAC07C5693ULL,
		0x03B5466BD4B62AC8ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0xB774793448F5A0CAULL,
		0x555305A05B0DFB64ULL,
		0x9DE4E2D3C0FD5BBDULL,
		0x6C2E195C61424BC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F26891EB4194000ULL,
		0x60B40B61BF6C96EEULL,
		0x9C5A781FAB77AAAAULL,
		0xC32B8C28497853BCULL,
		0x0000000000000D85ULL
	}};
	shift = 205;
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
		0x5096A15101E61D02ULL,
		0xF53E35194A5720E1ULL,
		0x45D18988576EF721ULL,
		0x05B87DF263D1D9D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB50A880F30E81000ULL,
		0xF1A8CA52B9070A84ULL,
		0x8C4C42BB77B90FA9ULL,
		0xC3EF931E8ECEAA2EULL,
		0x000000000000002DULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x13803A48434B6918ULL,
		0xB3C49606BF7FCF13ULL,
		0x61D2A534065297A1ULL,
		0x11731C8B24D11E1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9C01D2421A5B48C0ULL,
		0x9E24B035FBFE7898ULL,
		0x0E9529A03294BD0DULL,
		0x8B98E4592688F0F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x912F44FCA882C765ULL,
		0xF76009789E4F6002ULL,
		0xDD9200B884C053A6ULL,
		0x5D688D169F4F0383ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x544163B280000000ULL,
		0x4F27B0014897A27EULL,
		0x426029D37BB004BCULL,
		0x4FA781C1EEC9005CULL,
		0x000000002EB4468BULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x4C761A00B10223A2ULL,
		0x6C200EBB9C15B16FULL,
		0xF276C2E969A55185ULL,
		0x47AE118A5F1943D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C761A00B10223A2ULL,
		0x6C200EBB9C15B16FULL,
		0xF276C2E969A55185ULL,
		0x47AE118A5F1943D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
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
		0x4F40C382F4F1CD39ULL,
		0x9657577C447B4CF1ULL,
		0x4DCE2F1AEF2CBDB8ULL,
		0x27454D3318D791F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C382F4F1CD39000ULL,
		0x7577C447B4CF14F4ULL,
		0xE2F1AEF2CBDB8965ULL,
		0x54D3318D791F24DCULL,
		0x0000000000000274ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x6C7964273A196563ULL,
		0xC55B332B80057174ULL,
		0x257D743F064E06A1ULL,
		0x7E316BEE5797F399ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6300000000000000ULL,
		0x746C7964273A1965ULL,
		0xA1C55B332B800571ULL,
		0x99257D743F064E06ULL,
		0x007E316BEE5797F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
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
		0x933C5645681156A5ULL,
		0x735F6DF5AD87A4DDULL,
		0x6D436A9549CD9F4BULL,
		0x2C2E0CD4E2F8B790ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5915A0455A940000ULL,
		0xB7D6B61E93764CF1ULL,
		0xAA5527367D2DCD7DULL,
		0x33538BE2DE41B50DULL,
		0x000000000000B0B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x73182BC1296BBCEFULL,
		0x1B29CC5FDDD48874ULL,
		0xB574734D9B4D1646ULL,
		0x6E4EEE3BA24678BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE630578252D779DEULL,
		0x365398BFBBA910E8ULL,
		0x6AE8E69B369A2C8CULL,
		0xDC9DDC77448CF17BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
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
		0x265D7AF0E95D381AULL,
		0x289E42196F942696ULL,
		0xBE9F0E4FEEAEDE97ULL,
		0x746FBEEC151BB898ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0680000000000000ULL,
		0xA589975EBC3A574EULL,
		0xA5CA2790865BE509ULL,
		0x262FA7C393FBABB7ULL,
		0x001D1BEFBB0546EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0x4C42D51427D15558ULL,
		0x09BA68B5AD0D6AA5ULL,
		0x7BD0ADBB05588F0AULL,
		0x045A6F385994E76BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D15558000000000ULL,
		0xD0D6AA54C42D5142ULL,
		0x5588F0A09BA68B5AULL,
		0x994E76B7BD0ADBB0ULL,
		0x0000000045A6F385ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x62021C1FD55D2024ULL,
		0x4E2E590AB2D51EA7ULL,
		0x22D5133DEF0D4395ULL,
		0x64DC7A1E62A12AC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021C1FD55D202400ULL,
		0x2E590AB2D51EA762ULL,
		0xD5133DEF0D43954EULL,
		0xDC7A1E62A12AC622ULL,
		0x0000000000000064ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xDD8B6DCEF91F531FULL,
		0x061DBD006AFB6DF6ULL,
		0xF89343120849F260ULL,
		0x2B6F13523773A715ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xDBB16DB9DF23EA63ULL,
		0x00C3B7A00D5F6DBEULL,
		0xBF12686241093E4CULL,
		0x056DE26A46EE74E2ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x260EECEA2856FC93ULL,
		0x65251BA282B68BA0ULL,
		0xC839E76873DABA2AULL,
		0x7AD7A3612E5573EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A15BF24C0000000ULL,
		0xA0ADA2E80983BB3AULL,
		0x1CF6AE8A994946E8ULL,
		0x4B955CFB720E79DAULL,
		0x000000001EB5E8D8ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
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
		0xFEF7ED4F4B5A56BFULL,
		0xAD6FA38F32F07E11ULL,
		0xBFE7DD5474841CF8ULL,
		0x4FB600BAA99E5FE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F4B5A56BF00000ULL,
		0x38F32F07E11FEF7EULL,
		0xD5474841CF8AD6FAULL,
		0x0BAA99E5FE5BFE7DULL,
		0x000000000004FB60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xCDC1EA8D7D11D135ULL,
		0x48210A3E493C6324ULL,
		0x73B96BB1D9D71F35ULL,
		0x7AAF403347A2E711ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA800000000000000ULL,
		0x266E0F546BE88E89ULL,
		0xAA410851F249E319ULL,
		0x8B9DCB5D8ECEB8F9ULL,
		0x03D57A019A3D1738ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
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
		0xD0F91A7D257E6726ULL,
		0x5788513569638C7CULL,
		0x3DAA8C8143790173ULL,
		0x714737884B870C82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7260000000000000ULL,
		0xC7CD0F91A7D257E6ULL,
		0x1735788513569638ULL,
		0xC823DAA8C8143790ULL,
		0x000714737884B870ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
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
		0xF2EBB44C0735C0B1ULL,
		0x8D675F2F59C6F7E7ULL,
		0x8EAA5B26CEDE07DDULL,
		0x44F33B5C955C5433ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE5D768980E6B8162ULL,
		0x1ACEBE5EB38DEFCFULL,
		0x1D54B64D9DBC0FBBULL,
		0x89E676B92AB8A867ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
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
		0x81F317E0A5A908DDULL,
		0x5F3DCF2A064B12E3ULL,
		0xB38492995D970E12ULL,
		0x52BE4857E7EC4BECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5F8296A42374000ULL,
		0x73CA8192C4B8E07CULL,
		0x24A65765C38497CFULL,
		0x9215F9FB12FB2CE1ULL,
		0x00000000000014AFULL,
		0x0000000000000000ULL
	}};
	shift = 142;
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
		0xA1A3FD05ACD9E562ULL,
		0xDB0D1D09D9FEBA64ULL,
		0x910A01D34D56BFF0ULL,
		0x4A89BA4941E65698ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9E56200000000000ULL,
		0xEBA64A1A3FD05ACDULL,
		0x6BFF0DB0D1D09D9FULL,
		0x65698910A01D34D5ULL,
		0x000004A89BA4941EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
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
		0xC85D438A9DBE3D29ULL,
		0x6E692FBF1E12A18DULL,
		0x2A255DD702AAA840ULL,
		0x0C04F766DFA222A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE3D290000000000ULL,
		0x12A18DC85D438A9DULL,
		0xAAA8406E692FBF1EULL,
		0xA222A02A255DD702ULL,
		0x0000000C04F766DFULL,
		0x0000000000000000ULL
	}};
	shift = 168;
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
		0x075F09EAEA35AFC9ULL,
		0x1328CAF54B8067D5ULL,
		0x0B8C900B966F5CC0ULL,
		0x0EA70B29C1D46D66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD46B5F9200000000ULL,
		0x9700CFAA0EBE13D5ULL,
		0x2CDEB980265195EAULL,
		0x83A8DACC17192017ULL,
		0x000000001D4E1653ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
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
		0x78983860F431BF3EULL,
		0xE6233778D672BFE6ULL,
		0x5237160D6703B8BAULL,
		0x310DD6A801C6450BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x678983860F431BF3ULL,
		0xAE6233778D672BFEULL,
		0xB5237160D6703B8BULL,
		0x0310DD6A801C6450ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0x9ED742098A386B14ULL,
		0x9B3041F927727F55ULL,
		0x33B03E538B2266B5ULL,
		0x4B44F25DF0C44934ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x567B5D082628E1ACULL,
		0xD66CC107E49DC9FDULL,
		0xD0CEC0F94E2C899AULL,
		0x012D13C977C31124ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
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
		0x4332ADF5A5309B57ULL,
		0x22AEE893BA955649ULL,
		0xBDFE141AC75E8080ULL,
		0x6CFE8668F45E7A85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB80000000000000ULL,
		0x24A19956FAD2984DULL,
		0x4011577449DD4AABULL,
		0x42DEFF0A0D63AF40ULL,
		0x00367F43347A2F3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0xF3B67261AD9FF893ULL,
		0x703EA6A845A8934EULL,
		0xA60776D94CEC763BULL,
		0x1CAED9F6DA1FBB0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC4980000000000ULL,
		0x449A779DB3930D6CULL,
		0x63B1DB81F535422DULL,
		0xFDD875303BB6CA67ULL,
		0x000000E576CFB6D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x02996153CC02EC7BULL,
		0xEC829D227A63BC32ULL,
		0xD65F75B04C2E3A13ULL,
		0x1E2508CB93464042ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65854F300BB1EC00ULL,
		0x0A7489E98EF0C80AULL,
		0x7DD6C130B8E84FB2ULL,
		0x94232E4D19010B59ULL,
		0x0000000000000078ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
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
		0xA37D18E237DDF0E1ULL,
		0x3DAE5D2EFAF7AE64ULL,
		0xE29224DBB0165B06ULL,
		0x1E1DF9AABC9EB443ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DF77C3840000000ULL,
		0xBEBDEB9928DF4638ULL,
		0xEC0596C18F6B974BULL,
		0xAF27AD10F8A48936ULL,
		0x0000000007877E6AULL
	}};
	shift = 222;
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
		0xDAE3CDD48F78F26CULL,
		0xD8DDDBE811D782D4ULL,
		0xAEA3C18131D5702FULL,
		0x568CFD775D02B38DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47BC793600000000ULL,
		0x08EBC16A6D71E6EAULL,
		0x98EAB817EC6EEDF4ULL,
		0xAE8159C6D751E0C0ULL,
		0x000000002B467EBBULL
	}};
	shift = 223;
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
		0x5B0767839EC240C5ULL,
		0x24FE71DD33FE8FB3ULL,
		0x3684547CE1AE8569ULL,
		0x28E6565DC8C10EA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x67839EC240C50000ULL,
		0x71DD33FE8FB35B07ULL,
		0x547CE1AE856924FEULL,
		0x565DC8C10EA13684ULL,
		0x00000000000028E6ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x4B376B55F65E5B77ULL,
		0xD7AEB3E4C00806BAULL,
		0x9D63FC1DEAB14873ULL,
		0x59E2200D9A564812ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B55F65E5B77000ULL,
		0xEB3E4C00806BA4B3ULL,
		0x3FC1DEAB14873D7AULL,
		0x2200D9A5648129D6ULL,
		0x000000000000059EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x0633E8F0F4A86357ULL,
		0x26A8A552F393D5B4ULL,
		0xE6E8CECCF51C96E6ULL,
		0x7204B1A2B9563A8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CFA3C3D2A18D5C0ULL,
		0xAA2954BCE4F56D01ULL,
		0xBA33B33D4725B989ULL,
		0x812C68AE558EA379ULL,
		0x000000000000001CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x8BAA4B7EF9D83586ULL,
		0x6EDEE5C3C8FD30CFULL,
		0x1116F655CBD7973EULL,
		0x16962FADD4F57B64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x760D618000000000ULL,
		0x3F4C33E2EA92DFBEULL,
		0xF5E5CF9BB7B970F2ULL,
		0x3D5ED90445BD9572ULL,
		0x00000005A58BEB75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
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
		0x9A0A1D98D31709FEULL,
		0xCF432176646356BBULL,
		0xE876B186EF0AA674ULL,
		0x3FDF6981E2A2C97CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B31A62E13FC0000ULL,
		0x42ECC8C6AD773414ULL,
		0x630DDE154CE99E86ULL,
		0xD303C54592F9D0EDULL,
		0x0000000000007FBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xFF63F163202FE24FULL,
		0xEBEF31EBB1099815ULL,
		0x500D16FC9E872B34ULL,
		0x4F74E7D9D8E13989ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1278000000000000ULL,
		0xC0AFFB1F8B19017FULL,
		0x59A75F798F5D884CULL,
		0xCC4A8068B7E4F439ULL,
		0x00027BA73ECEC709ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
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
		0xC1F263819DF2117BULL,
		0x28CB4D1F3923AA9FULL,
		0x38BB2F6B50D6A1F4ULL,
		0x0139C41954E03EC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C98E0677C845EC0ULL,
		0x32D347CE48EAA7F0ULL,
		0x2ECBDAD435A87D0AULL,
		0x4E710655380FB20EULL,
		0x0000000000000000ULL
	}};
	shift = 198;
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
		0x979ACC43933CA845ULL,
		0x43D08D3B78317BA1ULL,
		0x42C3EEC3A082FE83ULL,
		0x14594C2894C1D1B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E6B310E4CF2A114ULL,
		0x0F4234EDE0C5EE86ULL,
		0x0B0FBB0E820BFA0DULL,
		0x516530A2530746D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xCA62085DE8279B0DULL,
		0x902A2985A28D9A98ULL,
		0x69F7D36A60A97771ULL,
		0x1D978DBD3F0A63B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77A09E6C34000000ULL,
		0x168A366A63298821ULL,
		0xA982A5DDC640A8A6ULL,
		0xF4FC298ED5A7DF4DULL,
		0x0000000000765E36ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
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
		0x3B84C33E8BD35B0AULL,
		0x20026F2DB9AFA9D8ULL,
		0x4E8FC1DA3292F310ULL,
		0x00BEBB67F6D4F2A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD17A6B6140000000ULL,
		0xB735F53B07709867ULL,
		0x46525E6204004DE5ULL,
		0xFEDA9E54A9D1F83BULL,
		0x000000000017D76CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x58EAB2775D29D442ULL,
		0xCD8E48CBD7A11E99ULL,
		0x7A6E4835A3021C9EULL,
		0x6E328C2BBFF06F08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775D29D442000000ULL,
		0xCBD7A11E9958EAB2ULL,
		0x35A3021C9ECD8E48ULL,
		0x2BBFF06F087A6E48ULL,
		0x00000000006E328CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xA554817F799E31B8ULL,
		0x180F2F635F8D6F73ULL,
		0x0A0327EDB2D56BDEULL,
		0x71765AEC9153BA69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4817F799E31B8000ULL,
		0xF2F635F8D6F73A55ULL,
		0x327EDB2D56BDE180ULL,
		0x65AEC9153BA690A0ULL,
		0x0000000000000717ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x9A1D63A637510DBEULL,
		0x60032BB116674DF6ULL,
		0xD3637BC71F991041ULL,
		0x5B0FDBF9D22C1856ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x637510DBE0000000ULL,
		0x116674DF69A1D63AULL,
		0x71F99104160032BBULL,
		0x9D22C1856D3637BCULL,
		0x0000000005B0FDBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
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
		0xFCC1357B6EB9C231ULL,
		0x796FB6B64C8AA81EULL,
		0xAD54D860B4DE0795ULL,
		0x3CAD61A6857384FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x7E609ABDB75CE118ULL,
		0xBCB7DB5B2645540FULL,
		0xD6AA6C305A6F03CAULL,
		0x1E56B0D342B9C27FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x0C7BB7D7FEBACBAEULL,
		0xF79562B9DD0DBFD0ULL,
		0x3DB486256AB009EEULL,
		0x221A58DB92986D67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDF5FFAEB2EB8000ULL,
		0x58AE77436FF4031EULL,
		0x21895AAC027BBDE5ULL,
		0x9636E4A61B59CF6DULL,
		0x0000000000000886ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
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
		0x6DE469796076921EULL,
		0xA266E1C01E23D97DULL,
		0xCE724E88BDEB807AULL,
		0x30C76E70AF22841BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA487800000000000ULL,
		0xF65F5B791A5E581DULL,
		0xE01EA899B8700788ULL,
		0xA106F39C93A22F7AULL,
		0x00000C31DB9C2BC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0xB50AA81DEB8D11E6ULL,
		0xEEED8527AF183EFEULL,
		0x6EE20B5258B60CF5ULL,
		0x205EF4028E06E914ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23CC000000000000ULL,
		0x7DFD6A15503BD71AULL,
		0x19EBDDDB0A4F5E30ULL,
		0xD228DDC416A4B16CULL,
		0x000040BDE8051C0DULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0x4CF11F565C226DE0ULL,
		0x9E18F52548849CF5ULL,
		0x882E772E7A9B5938ULL,
		0x385BBB2C99505D6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF565C226DE000000ULL,
		0x52548849CF54CF11ULL,
		0x72E7A9B59389E18FULL,
		0xB2C99505D6C882E7ULL,
		0x00000000000385BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xAA97AA13007B6964ULL,
		0xEFC29DBDB67E0AB6ULL,
		0x52FAB1202B189448ULL,
		0x1047344CE9AC5CF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6400000000000000ULL,
		0xB6AA97AA13007B69ULL,
		0x48EFC29DBDB67E0AULL,
		0xF552FAB1202B1894ULL,
		0x001047344CE9AC5CULL
	}};
	shift = 248;
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
		0xE5ACA251D5CD6B16ULL,
		0x2546D5BB1044AC74ULL,
		0xBE83F6559BBCAE21ULL,
		0x5D18F823DFC1BB5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB000000000000000ULL,
		0xA72D65128EAE6B58ULL,
		0x092A36ADD8822563ULL,
		0xFDF41FB2ACDDE571ULL,
		0x02E8C7C11EFE0DDAULL,
		0x0000000000000000ULL
	}};
	shift = 187;
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
		0x0F6A3A13D7EC1E4DULL,
		0xDB4F0B46EB86EA38ULL,
		0xA9674FA90647CEC9ULL,
		0x0317408DA315E091ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB079340000000000ULL,
		0x1BA8E03DA8E84F5FULL,
		0x1F3B276D3C2D1BAEULL,
		0x578246A59D3EA419ULL,
		0x0000000C5D02368CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
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
		0x53BCF16848B68680ULL,
		0x80133207641F656CULL,
		0xFEA9F8CE74A0D4D2ULL,
		0x4ABE7950484FE103ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA1A000000000000ULL,
		0x7D95B14EF3C5A122ULL,
		0x83534A004CC81D90ULL,
		0x3F840FFAA7E339D2ULL,
		0x0000012AF9E54121ULL
	}};
	shift = 234;
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
		0x19A4970B9C9D9E94ULL,
		0x9CA414015E771728ULL,
		0x9867129289EF6F35ULL,
		0x37BB0F75948CC193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A50000000000000ULL,
		0x5CA066925C2E7276ULL,
		0xBCD67290500579DCULL,
		0x064E619C4A4A27BDULL,
		0x0000DEEC3DD65233ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xFB319689E8B3EEE9ULL,
		0xB391236B2E63195EULL,
		0xF519F48D00B88784ULL,
		0x1A11318A773A8CEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB44F459F7748000ULL,
		0x91B597318CAF7D98ULL,
		0xFA46805C43C259C8ULL,
		0x98C53B9D46757A8CULL,
		0x0000000000000D08ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0xFB197789BE04A881ULL,
		0xE85C48623315292DULL,
		0x6612914885A65DA3ULL,
		0x591F374A1198AE97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xFD8CBBC4DF025440ULL,
		0xF42E2431198A9496ULL,
		0xB30948A442D32ED1ULL,
		0x2C8F9BA508CC574BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xD4F1F3023148B994ULL,
		0xE53EA9239CAF6AE5ULL,
		0x0062F0E4E243C303ULL,
		0x5B0B618420B51805ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9E3E60462917328ULL,
		0xCA7D5247395ED5CBULL,
		0x00C5E1C9C4878607ULL,
		0xB616C308416A300AULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x597C7A1837BAC8C7ULL,
		0xF998B723CB743D8FULL,
		0x6C9E282C3ACD4BB1ULL,
		0x12B608AAB1048207ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E00000000000000ULL,
		0x1EB2F8F4306F7591ULL,
		0x63F3316E4796E87BULL,
		0x0ED93C5058759A97ULL,
		0x00256C1155620904ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x34C44D75CF56F88DULL,
		0xA8A601529C743349ULL,
		0x1E297A95A02BC30CULL,
		0x2959661FB3DC12B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x226BAE7AB7C46800ULL,
		0x300A94E3A19A49A6ULL,
		0x4BD4AD015E186545ULL,
		0xCB30FD9EE09580F1ULL,
		0x000000000000014AULL
	}};
	shift = 203;
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
		0xB4F4933E9BA1AFDCULL,
		0xABB1A177A55FEA8DULL,
		0x7C8A8CBB9A2B0CDFULL,
		0x4965D81EB0461DCDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD37435FB80000000ULL,
		0xF4ABFD51B69E9267ULL,
		0x7345619BF576342EULL,
		0xD608C3B9AF915197ULL,
		0x00000000092CBB03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x105CA4F9BE58CE26ULL,
		0xE27456AB4860CD0AULL,
		0x7C4A55CD8CAD1890ULL,
		0x2D7B98948FAAA61EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x105CA4F9BE58CE26ULL,
		0xE27456AB4860CD0AULL,
		0x7C4A55CD8CAD1890ULL,
		0x2D7B98948FAAA61EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0x00A1A4BFC9E99546ULL,
		0xA09C5867042D769AULL,
		0xD26081589BD373E3ULL,
		0x53F8A73D84410BAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27A6551800000000ULL,
		0x10B5DA68028692FFULL,
		0x6F4DCF8E8271619CULL,
		0x11042EBF49820562ULL,
		0x000000014FE29CF6ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
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
		0xB75625AB5784307CULL,
		0x0BA6787A21F479CDULL,
		0x153BD51F5BE985A3ULL,
		0x1C9C00440254D8D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5ABC2183E000000ULL,
		0x3D10FA3CE6DBAB12ULL,
		0x8FADF4C2D185D33CULL,
		0x22012A6C6B0A9DEAULL,
		0x00000000000E4E00ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0x2837391D0781DA2BULL,
		0xDF102C04320BE1C2ULL,
		0xC7B2223BFAF1D3AEULL,
		0x5A2217A7E7F83742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0ED158000000000ULL,
		0x05F0E1141B9C8E83ULL,
		0x78E9D76F88160219ULL,
		0xFC1BA163D9111DFDULL,
		0x0000002D110BD3F3ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
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
		0x915508D59708C2B5ULL,
		0x73CDEFC2395D78C2ULL,
		0xD5B031C75A1587B6ULL,
		0x2240E1ED64F55CC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA846ACB84615A80ULL,
		0xE6F7E11CAEBC6148ULL,
		0xD818E3AD0AC3DB39ULL,
		0x2070F6B27AAE60EAULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x3BBD035286D47D4EULL,
		0x697B3CCDB0322894ULL,
		0x20EE072596C4BFD7ULL,
		0x0A1F3E8ED06B4B30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x43BBD035286D47D4ULL,
		0x7697B3CCDB032289ULL,
		0x020EE072596C4BFDULL,
		0x00A1F3E8ED06B4B3ULL
	}};
	shift = 252;
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
		0xC33B8AC43370644CULL,
		0xF0FF492A712C19F9ULL,
		0x9C813E66F2B63A81ULL,
		0x6FACDF6FCBEF408EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2600000000000000ULL,
		0xFCE19DC56219B832ULL,
		0x40F87FA49538960CULL,
		0x474E409F33795B1DULL,
		0x0037D66FB7E5F7A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0x942864B50E0D727EULL,
		0x0B95E9C7CB930865ULL,
		0x8B53FCA936699879ULL,
		0x044345EEFBAB893AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1C1AE4FC0000000ULL,
		0xF972610CB2850C96ULL,
		0x26CD330F2172BD38ULL,
		0xDF757127516A7F95ULL,
		0x00000000008868BDULL,
		0x0000000000000000ULL
	}};
	shift = 157;
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
		0x8CB76BBF2ADB3CDFULL,
		0x2D0E6814E1C7CEB3ULL,
		0xF0169489534F8B5AULL,
		0x0560D361CF61D911ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x679BE00000000000ULL,
		0xF9D67196ED77E55BULL,
		0xF16B45A1CD029C38ULL,
		0x3B223E02D2912A69ULL,
		0x000000AC1A6C39ECULL,
		0x0000000000000000ULL
	}};
	shift = 173;
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
		0x8BC25ECF9FC55BBCULL,
		0xEFD41356C96A82D9ULL,
		0xDDB59C2F0F5D77BEULL,
		0x1F5418E20F6074CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB778000000000000ULL,
		0x05B31784BD9F3F8AULL,
		0xEF7DDFA826AD92D5ULL,
		0xE99BBB6B385E1EBAULL,
		0x00003EA831C41EC0ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0x24C055DE0C0FD4A7ULL,
		0xDF66215A78B395C4ULL,
		0xCED5D605A9138203ULL,
		0x4F4CBE6D3CB43796ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x55DE0C0FD4A70000ULL,
		0x215A78B395C424C0ULL,
		0xD605A9138203DF66ULL,
		0xBE6D3CB43796CED5ULL,
		0x0000000000004F4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
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
		0x6B7A0A87381B124BULL,
		0x0AC960C8B7365B26ULL,
		0x275C9D01AC68F666ULL,
		0x20CA04A4235B619EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC492C00000000000ULL,
		0x96C99ADE82A1CE06ULL,
		0x3D9982B258322DCDULL,
		0xD86789D727406B1AULL,
		0x00000832812908D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x3E0CDE65B74FB47AULL,
		0x7073561ADC5F783AULL,
		0x816C4736B08EF9B0ULL,
		0x6144772F1B513974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66F32DBA7DA3D000ULL,
		0x9AB0D6E2FBC1D1F0ULL,
		0x6239B58477CD8383ULL,
		0x23B978DA89CBA40BULL,
		0x000000000000030AULL
	}};
	shift = 203;
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
		0x2D558D857D77A32CULL,
		0x5361502746217261ULL,
		0x13B0AA95FF8A8B0EULL,
		0x5DF16C8DA858CA30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x12D558D857D77A32ULL,
		0xE536150274621726ULL,
		0x013B0AA95FF8A8B0ULL,
		0x05DF16C8DA858CA3ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0x4FD02C3216EEB650ULL,
		0xE38BD327F3639109ULL,
		0x528138AF5EFE4C0FULL,
		0x6993E316D6AD37A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD9400000000000ULL,
		0x8E44253F40B0C85BULL,
		0xF9303F8E2F4C9FCDULL,
		0xB4DE814A04E2BD7BULL,
		0x000001A64F8C5B5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
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
		0xA52635426F9309C7ULL,
		0x2D32277BA589331CULL,
		0x2D001A2309CE9AE4ULL,
		0x674104E23E9421E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271C000000000000ULL,
		0xCC729498D509BE4CULL,
		0x6B90B4C89DEE9624ULL,
		0x8780B400688C273AULL,
		0x00019D041388FA50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xB2BEDAA1FE7B7FB0ULL,
		0x802EBCA5C2D1BA38ULL,
		0x389B091C8E5E448CULL,
		0x0B6ADC59A61D526FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB6A87F9EDFEC00ULL,
		0x0BAF2970B46E8E2CULL,
		0x26C2472397912320ULL,
		0xDAB7166987549BCEULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x1F6782599843FA2DULL,
		0x5F9E0EACE5CCB7BDULL,
		0x4605871148B78D8DULL,
		0x30B14A9C9DEB1618ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC21FD1680000000ULL,
		0x72E65BDE8FB3C12CULL,
		0xA45BC6C6AFCF0756ULL,
		0x4EF58B0C2302C388ULL,
		0x000000001858A54EULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x6F11B0FD0E33B4FAULL,
		0x51F55D78E9A885D6ULL,
		0xB21B0F0922C1F3D4ULL,
		0x78B248C8FCF74016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3F438CED3E80000ULL,
		0x75E3A6A21759BC46ULL,
		0x3C248B07CF5147D5ULL,
		0x2323F3DD005AC86CULL,
		0x000000000001E2C9ULL
	}};
	shift = 210;
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
		0x6DE0D7E70EE812C3ULL,
		0x8F8AA644EC5BCA3FULL,
		0x2D3BDCEEA435491FULL,
		0x58AF9926DD245189ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C30000000000000ULL,
		0xA3F6DE0D7E70EE81ULL,
		0x91F8F8AA644EC5BCULL,
		0x1892D3BDCEEA4354ULL,
		0x00058AF9926DD245ULL
	}};
	shift = 244;
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
		0x570505118CFE28C9ULL,
		0x6FCB3083A3AAA1F2ULL,
		0x07306191BDF6F294ULL,
		0x442221C4AB2696CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3240000000000000ULL,
		0x7C95C14144633F8AULL,
		0xA51BF2CC20E8EAA8ULL,
		0xB281CC18646F7DBCULL,
		0x00110888712AC9A5ULL
	}};
	shift = 246;
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
		0x271F57A3805B6546ULL,
		0x4015C0F16D0C0FD5ULL,
		0x006E8C219CA01775ULL,
		0x037EF1DCA6AFB325ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x271F57A3805B6546ULL,
		0x4015C0F16D0C0FD5ULL,
		0x006E8C219CA01775ULL,
		0x037EF1DCA6AFB325ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0x534D9D7BC526AF26ULL,
		0x48A48087195DD152ULL,
		0x12B6052437329068ULL,
		0x467C435AFF321D7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2600000000000000ULL,
		0x52534D9D7BC526AFULL,
		0x6848A48087195DD1ULL,
		0x7B12B60524373290ULL,
		0x00467C435AFF321DULL,
		0x0000000000000000ULL
	}};
	shift = 184;
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
		0x6218D50B5B46DC88ULL,
		0xF7BC6A768795CDA2ULL,
		0x05A43C9C9C8A162DULL,
		0x30AC31381E163905ULL,
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
		0x310C6A85ADA36E44ULL,
		0xFBDE353B43CAE6D1ULL,
		0x82D21E4E4E450B16ULL,
		0x1856189C0F0B1C82ULL
	}};
	shift = 255;
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
		0x9FC7839D7F864FDAULL,
		0xF8F2084836132E31ULL,
		0xD89E24B16FC689C7ULL,
		0x525CDF7A73663955ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F864FDA0000000ULL,
		0x836132E319FC7839ULL,
		0x16FC689C7F8F2084ULL,
		0xA73663955D89E24BULL,
		0x000000000525CDF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x34C8B2C8406B7338ULL,
		0xA78E0C62BB00BA15ULL,
		0x94EF1B132BC0CF21ULL,
		0x08B6440E20282D62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CB2101ADCCE0000ULL,
		0x8318AEC02E854D32ULL,
		0xC6C4CAF033C869E3ULL,
		0x9103880A0B58A53BULL,
		0x000000000000022DULL
	}};
	shift = 206;
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
		0xDB2668DB1419901BULL,
		0x57B606D0CE974490ULL,
		0x93381A9C03E3498BULL,
		0x75A50584DEEEBF05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36C5066406C0000ULL,
		0x1B433A5D12436C99ULL,
		0x6A700F8D262D5ED8ULL,
		0x16137BBAFC164CE0ULL,
		0x000000000001D694ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x5C07E307FFF26F6BULL,
		0x8C7BAF09E83683E3ULL,
		0x1ACEDC4FF4F99DA8ULL,
		0x05146283FBB684D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFFF26F6B00000000ULL,
		0xE83683E35C07E307ULL,
		0xF4F99DA88C7BAF09ULL,
		0xFBB684D71ACEDC4FULL,
		0x0000000005146283ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0x69D89BF62C7BEC9DULL,
		0xFFD3B213760E6D12ULL,
		0xBD7BE2352F8BEBA6ULL,
		0x11F8579835113223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC58F7D93A000000ULL,
		0x26EC1CDA24D3B137ULL,
		0x6A5F17D74DFFA764ULL,
		0x306A2264477AF7C4ULL,
		0x000000000023F0AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0x25B87953387AED1DULL,
		0xA79C073073910DC9ULL,
		0x76348BD308C6A091ULL,
		0x1F1117022C254FB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x87AED1D000000000ULL,
		0x3910DC925B879533ULL,
		0x8C6A091A79C07307ULL,
		0xC254FB076348BD30ULL,
		0x00000001F1117022ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x1FC91018DBC30B53ULL,
		0x7DA2CDC2D96E6CC2ULL,
		0xC3026377D6418A73ULL,
		0x394BC02F8D5BEB18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8616A60000000000ULL,
		0xDCD9843F922031B7ULL,
		0x8314E6FB459B85B2ULL,
		0xB7D6318604C6EFACULL,
		0x0000007297805F1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x390C43F1D6366486ULL,
		0xBB79E146775DD193ULL,
		0x421EF63F6896B3BBULL,
		0x5179316188011150ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x43F1D63664860000ULL,
		0xE146775DD193390CULL,
		0xF63F6896B3BBBB79ULL,
		0x316188011150421EULL,
		0x0000000000005179ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
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
		0x2124FDA5AECBD23AULL,
		0x30522AB5A1AA7B29ULL,
		0xD2ECC439E96D0D69ULL,
		0x44B94C8C2DC1973BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4249FB4B5D97A474ULL,
		0x60A4556B4354F652ULL,
		0xA5D98873D2DA1AD2ULL,
		0x897299185B832E77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
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
		0x711822F0D159D3B3ULL,
		0x14DA605A50060BE7ULL,
		0x432A1B8E17896E5AULL,
		0x18475E5A14EA9FBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08BC345674ECC000ULL,
		0x9816940182F9DC46ULL,
		0x86E385E25B968536ULL,
		0xD796853AA7EF50CAULL,
		0x0000000000000611ULL
	}};
	shift = 206;
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
		0xA6B89D41CFEB2BEEULL,
		0x53F0D5A942C27802ULL,
		0x6EA7522B31D47BA4ULL,
		0x4747B789985B0C78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC00000000000000ULL,
		0x054D713A839FD657ULL,
		0x48A7E1AB528584F0ULL,
		0xF0DD4EA45663A8F7ULL,
		0x008E8F6F1330B618ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x645F20D0D8ABE179ULL,
		0x0E799820C59EBBA5ULL,
		0x0D8EC8E916241B52ULL,
		0x77B65481B217892DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F20D0D8ABE17900ULL,
		0x799820C59EBBA564ULL,
		0x8EC8E916241B520EULL,
		0xB65481B217892D0DULL,
		0x0000000000000077ULL
	}};
	shift = 200;
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
		0x714278ED8B278942ULL,
		0x9598F1012AF26E79ULL,
		0x640FE444634CF083ULL,
		0x2C2396C506609962ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84F1DB164F128400ULL,
		0x31E20255E4DCF2E2ULL,
		0x1FC888C699E1072BULL,
		0x472D8A0CC132C4C8ULL,
		0x0000000000000058ULL
	}};
	shift = 201;
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
		0xCC80762EB9C4385EULL,
		0x06E1428970BDBDBAULL,
		0xE6C1B809038BD8D2ULL,
		0x3D8FE0DDA2E5BBD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E00000000000000ULL,
		0xBACC80762EB9C438ULL,
		0xD206E1428970BDBDULL,
		0xD0E6C1B809038BD8ULL,
		0x003D8FE0DDA2E5BBULL
	}};
	shift = 248;
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
		0xC2DE8E250081E0DFULL,
		0xCACB95B44D545E94ULL,
		0x7672D2675EE259B5ULL,
		0x30BFB81FB83F4264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8940207837C00000ULL,
		0x6D135517A530B7A3ULL,
		0x99D7B8966D72B2E5ULL,
		0x07EE0FD0991D9CB4ULL,
		0x00000000000C2FEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0x1E0AD38DD7FEC8F9ULL,
		0x6FEA61B07C26AD7AULL,
		0x277635A0C7125459ULL,
		0x55B716768C0C6743ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15A71BAFFD91F200ULL,
		0xD4C360F84D5AF43CULL,
		0xEC6B418E24A8B2DFULL,
		0x6E2CED1818CE864EULL,
		0x00000000000000ABULL
	}};
	shift = 201;
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
		0x6070F54A324E8FF5ULL,
		0x05AAB506F008521FULL,
		0xAFCCE2101EE7DF7AULL,
		0x0A5EFFEAB46E2734ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0xEC0E1EA94649D1FEULL,
		0x40B556A0DE010A43ULL,
		0x95F99C4203DCFBEFULL,
		0x014BDFFD568DC4E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0xDA13BB31EFEAFD5FULL,
		0x63FC60E8CECA397CULL,
		0xD3BD1062A011ABD7ULL,
		0x2697686872480BB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FABE00000000000ULL,
		0x472F9B4277663DFDULL,
		0x357AEC7F8C1D19D9ULL,
		0x0176DA77A20C5402ULL,
		0x000004D2ED0D0E49ULL
	}};
	shift = 237;
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
		0x33AF45CAF0BAA648ULL,
		0xB49A34D43324A693ULL,
		0x2F9E74D2DCAB491AULL,
		0x429E289F3DA2BB59ULL,
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
		0x33AF45CAF0BAA648ULL,
		0xB49A34D43324A693ULL,
		0x2F9E74D2DCAB491AULL,
		0x429E289F3DA2BB59ULL
	}};
	shift = 256;
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
		0xDCDC2872EC96F814ULL,
		0x53649647AB5B01B4ULL,
		0xC7404EA327B8439BULL,
		0x5781C682B1B4FA7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0A00000000000000ULL,
		0xDA6E6E1439764B7CULL,
		0xCDA9B24B23D5AD80ULL,
		0x3FE3A0275193DC21ULL,
		0x002BC0E34158DA7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0xC06AA8B7559CC811ULL,
		0x8C51802272F4E5D4ULL,
		0x7C13840D4804C37CULL,
		0x2CEA130E36D3CF9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4400000000000000ULL,
		0x5301AAA2DD567320ULL,
		0xF231460089CBD397ULL,
		0x69F04E103520130DULL,
		0x00B3A84C38DB4F3EULL,
		0x0000000000000000ULL
	}};
	shift = 186;
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
		0xCCA0CEBC87B2D123ULL,
		0xDBBA3C5EE4B09E0FULL,
		0xDA20EAF40BE8756DULL,
		0x33BD44D30911DAEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65A2460000000000ULL,
		0x613C1F99419D790FULL,
		0xD0EADBB77478BDC9ULL,
		0x23B5DDB441D5E817ULL,
		0x000000677A89A612ULL
	}};
	shift = 233;
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
		0x833B9CC3F7400F77ULL,
		0x892D1741BB471C3CULL,
		0x4A7B873B641FDD41ULL,
		0x5F0BEE5B28641B35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE61FBA007BB8000ULL,
		0x8BA0DDA38E1E419DULL,
		0xC39DB20FEEA0C496ULL,
		0xF72D94320D9AA53DULL,
		0x0000000000002F85ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x24697A66628C47D6ULL,
		0xD78A2705E7C15C4EULL,
		0xC223A2A0F1396BBFULL,
		0x385EF4FE2A26B9E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9998A311F5800000ULL,
		0xC179F05713891A5EULL,
		0xA83C4E5AEFF5E289ULL,
		0x3F8A89AE78F088E8ULL,
		0x00000000000E17BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x730272100B9FB886ULL,
		0x10C4563CEFCB7ED2ULL,
		0x622004BDF6E7D3F7ULL,
		0x53176C94BDE45881ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4300000000000000ULL,
		0x693981390805CFDCULL,
		0xFB88622B1E77E5BFULL,
		0x40B110025EFB73E9ULL,
		0x00298BB64A5EF22CULL,
		0x0000000000000000ULL
	}};
	shift = 183;
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
		0x8C259CD87C7B94CDULL,
		0xA47719B52DCD2A36ULL,
		0x680583336D26B8E9ULL,
		0x04781B64EE6A097BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6800000000000000ULL,
		0xB4612CE6C3E3DCA6ULL,
		0x4D23B8CDA96E6951ULL,
		0xDB402C199B6935C7ULL,
		0x0023C0DB2773504BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xCD318A3C555B03FFULL,
		0x12A18B249EA5E0BEULL,
		0x41EB0BE5F6F65233ULL,
		0x00D085EAB2DA7F14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD81FF80000000000ULL,
		0x2F05F6698C51E2AAULL,
		0xB29198950C5924F5ULL,
		0xD3F8A20F585F2FB7ULL,
		0x00000006842F5596ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xA51FA3AADB705848ULL,
		0x9996F88A32A04E44ULL,
		0x4905D7935751A4A1ULL,
		0x0C24AFFC7A68B2A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C24000000000000ULL,
		0x2722528FD1D56DB8ULL,
		0xD250CCCB7C451950ULL,
		0x5950A482EBC9ABA8ULL,
		0x0000061257FE3D34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x59ADC3CCC923939AULL,
		0x9A45D69485D82D23ULL,
		0x112764F86CB1FD8AULL,
		0x4224491B8F40857DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0x1ACD6E1E66491C9CULL,
		0x54D22EB4A42EC169ULL,
		0xE8893B27C3658FECULL,
		0x02112248DC7A042BULL
	}};
	shift = 251;
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
		0x002B19158ECE8F37ULL,
		0x343C9BE253262ECBULL,
		0x5B61367D1E1C54E3ULL,
		0x0CCB0EAD1B429FCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA3CDC00000000000ULL,
		0x8BB2C00AC64563B3ULL,
		0x1538CD0F26F894C9ULL,
		0xA7F3D6D84D9F4787ULL,
		0x00000332C3AB46D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x247C15055D7807D2ULL,
		0x79D0E3B352193046ULL,
		0x9C7F12E70671BD33ULL,
		0x12078D51D0AFB60EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0541575E01F4800ULL,
		0x438ECD4864C11891ULL,
		0xFC4B9C19C6F4CDE7ULL,
		0x1E354742BED83A71ULL,
		0x0000000000000048ULL
	}};
	shift = 202;
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
		0xA5FAB88BB15E632BULL,
		0x0D5A91F725A219ECULL,
		0x37BFBC0B1BE1DB13ULL,
		0x1DBC36C47B5D04ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1958000000000000ULL,
		0xCF652FD5C45D8AF3ULL,
		0xD8986AD48FB92D10ULL,
		0x2569BDFDE058DF0EULL,
		0x0000EDE1B623DAE8ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
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
		0x480408BF506BD79BULL,
		0xC73A33F5B53CEA83ULL,
		0xE45DB633E3B445DBULL,
		0x4673FA42FD6CE29BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x06BD79B000000000ULL,
		0x53CEA83480408BF5ULL,
		0x3B445DBC73A33F5BULL,
		0xD6CE29BE45DB633EULL,
		0x00000004673FA42FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
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
		0x72B8D7BD172356DFULL,
		0x9F5D50BADBA27159ULL,
		0xE4D6E281F436AE08ULL,
		0x569C089C5084ACA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF45C8D5B7C000000ULL,
		0xEB6E89C565CAE35EULL,
		0x07D0DAB8227D7542ULL,
		0x714212B2A7935B8AULL,
		0x00000000015A7022ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
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
		0x8B6F1BFBB367DDB8ULL,
		0x00835FA6851493E9ULL,
		0x1835C310C1F3DC7BULL,
		0x21E96940524FD16EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB367DDB800000000ULL,
		0x851493E98B6F1BFBULL,
		0xC1F3DC7B00835FA6ULL,
		0x524FD16E1835C310ULL,
		0x0000000021E96940ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0x9CABD31D51EBDFC6ULL,
		0xAE55B7A9073CA01DULL,
		0x6A722D668BAF3B7BULL,
		0x13A767097C815E10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFC60000000000000ULL,
		0x01D9CABD31D51EBDULL,
		0xB7BAE55B7A9073CAULL,
		0xE106A722D668BAF3ULL,
		0x00013A767097C815ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
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
		0x73156C8E10B886BDULL,
		0x648FFF62E996AC5EULL,
		0x560B892EA02061DCULL,
		0x7E9AF6EED3E93E60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE21AF40000000000ULL,
		0x5AB179CC55B23842ULL,
		0x818771923FFD8BA6ULL,
		0xA4F981582E24BA80ULL,
		0x000001FA6BDBBB4FULL
	}};
	shift = 234;
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
		0xA6BAB9C5BBBEC6DAULL,
		0x8374CDA59A16DB69ULL,
		0xF9D8E509166A09DBULL,
		0x1B8753D282DEB61DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDDF636D0000000ULL,
		0x2CD0B6DB4D35D5CEULL,
		0x48B3504EDC1BA66DULL,
		0x9416F5B0EFCEC728ULL,
		0x0000000000DC3A9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0xBA53E1B7B406242BULL,
		0x329D9061A0DC2E9BULL,
		0xBD8209F973067E8DULL,
		0x648ACDAAB985E174ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29F0DBDA03121580ULL,
		0x4EC830D06E174DDDULL,
		0xC104FCB9833F4699ULL,
		0x4566D55CC2F0BA5EULL,
		0x0000000000000032ULL
	}};
	shift = 199;
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
		0x581F9998409FBEE0ULL,
		0x6B758FB5C075ADB5ULL,
		0xC9DDEFEC1128768FULL,
		0x2954F3E9DBA1C522ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x04FDF70000000000ULL,
		0x03AD6DAAC0FCCCC2ULL,
		0x8943B47B5BAC7DAEULL,
		0xDD0E29164EEF7F60ULL,
		0x000000014AA79F4EULL
	}};
	shift = 227;
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
		0x9D7C4181726FD6CEULL,
		0x5200C93B57ABD08CULL,
		0x7DE9B0E66F8C5AFAULL,
		0x6B719C8A493B6E15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x275F10605C9BF5B3ULL,
		0x9480324ED5EAF423ULL,
		0x5F7A6C399BE316BEULL,
		0x1ADC6722924EDB85ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
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
		0xFCD9C7F60606E8FBULL,
		0xA4BA91A3E1A48545ULL,
		0xDA9F13127304DCB4ULL,
		0x5CE8034532FF19BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3671FD8181BA3EC0ULL,
		0x2EA468F86921517FULL,
		0xA7C4C49CC1372D29ULL,
		0x3A00D14CBFC66FB6ULL,
		0x0000000000000017ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x659D68E18AE8B33BULL,
		0x8238EA9E16E6821BULL,
		0x563BFD06ED0BADAFULL,
		0x1A5A979AF392338FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6760000000000000ULL,
		0x436CB3AD1C315D16ULL,
		0xB5F0471D53C2DCD0ULL,
		0x71EAC77FA0DDA175ULL,
		0x00034B52F35E7246ULL
	}};
	shift = 245;
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
		0x3FB1D4C9E1949D9EULL,
		0xCAA8B3F729F18A86ULL,
		0x080C3A8CCF3E5475ULL,
		0x27B90CC92A6E5B54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D4C9E1949D9E000ULL,
		0x8B3F729F18A863FBULL,
		0xC3A8CCF3E5475CAAULL,
		0x90CC92A6E5B54080ULL,
		0x000000000000027BULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x891687F5CBDF9B9AULL,
		0x7E02E5DA29D3D4D6ULL,
		0x7723BA5F82FF02D5ULL,
		0x4D2CCCAAF44E0F72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE680000000000000ULL,
		0x35A245A1FD72F7E6ULL,
		0xB55F80B9768A74F5ULL,
		0xDC9DC8EE97E0BFC0ULL,
		0x00134B332ABD1383ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0x4672D03E20819629ULL,
		0xA84E4C4D01FDFEB2ULL,
		0x66F82AED689D6D22ULL,
		0x30708448DEA2BAC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x032C520000000000ULL,
		0xFBFD648CE5A07C41ULL,
		0x3ADA45509C989A03ULL,
		0x457588CDF055DAD1ULL,
		0x00000060E10891BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0xD013A281CFD5C14DULL,
		0x3BF575EB5D564236ULL,
		0xF08B5F4843B3F128ULL,
		0x7288276996320B78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CFD5C14D0000000ULL,
		0xB5D564236D013A28ULL,
		0x843B3F1283BF575EULL,
		0x996320B78F08B5F4ULL,
		0x0000000007288276ULL
	}};
	shift = 220;
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
		0x82934943C07CCD06ULL,
		0x939FBA1DDA1D0906ULL,
		0xA4DD967616132BD4ULL,
		0x42828D013959F967ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8300000000000000ULL,
		0x834149A4A1E03E66ULL,
		0xEA49CFDD0EED0E84ULL,
		0xB3D26ECB3B0B0995ULL,
		0x00214146809CACFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0x483E10D0DE412C00ULL,
		0xD70E6D63B623BFD9ULL,
		0xBC60E4AD4D0959EAULL,
		0x466017CF18BF9A25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1F08686F20960000ULL,
		0x8736B1DB11DFECA4ULL,
		0x307256A684ACF56BULL,
		0x300BE78C5FCD12DEULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
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
		0x026AADAA0DB0DB7BULL,
		0xA416A46FC32096A3ULL,
		0xA5C0D23150DBFA69ULL,
		0x2B5E2F66EA56CC0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x813556D506D86DBDULL,
		0xD20B5237E1904B51ULL,
		0x52E06918A86DFD34ULL,
		0x15AF17B3752B6607ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x0080000000000000ULL,
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
		0x0000000000008000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x0400000000000000ULL,
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
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x0000000000000000ULL,
		0x0000000000000010ULL,
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
		0x0000000000100000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
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
		0x0000020000000000ULL,
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
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x0000000000000000ULL,
		0x0000000000000002ULL,
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
		0x0000002000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0008000000000000ULL,
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
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x0000000000080000ULL,
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
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0x0000000000800000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000800000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x0000000000008000ULL,
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
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
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
		0x0000000000000000ULL,
		0x0000000000800000ULL,
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
		0x0080000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
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