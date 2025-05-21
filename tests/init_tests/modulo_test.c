#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x2F6467519109771DULL,
		0xFFE252677A374621ULL,
		0xB89424750DFD66B4ULL,
		0xC74918499D575EA4ULL,
		0xEE4823F6FFFB4752ULL,
		0x408512A8D21061C7ULL,
		0x6E9331934130ECD3ULL,
		0x11B8CA9EA9BAF6DCULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x8E19BDFB90560DBBULL,
		0x93A31776A8A5C9CEULL,
		0x226D8050BB408E10ULL,
		0x68B72BD6CF18035DULL,
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
	compute_modulo_25519(&k1);
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
		0xCFD9810E83A089E5ULL,
		0x0A6305451B81BBD6ULL,
		0xC9D8A72629F828F3ULL,
		0x839EFEDA10E22AC0ULL,
		0x44EBE89316C62D5DULL,
		0x8442EEFF928D66EFULL,
		0xF865BDD8F9E5A56EULL,
		0x4DDF4A2E45792FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ADE06E3E50B477BULL,
		0xAC527F34DC7F035BULL,
		0xA8F2D55B420EB75AULL,
		0x12C401B860DF3DAFULL,
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
	compute_modulo_25519(&k1);
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
		0x8C813749948CE840ULL,
		0xC5A6598E635D0E17ULL,
		0xC2EE06CEA1A745ACULL,
		0xE3AA7DEE28497502ULL,
		0x9A3346BFD0468578ULL,
		0x20C7C71658C5E700ULL,
		0x72CC9E0B492A86B1ULL,
		0xF9859DACBAA5D574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x701DB7C27F04BDA1ULL,
		0xA34DE6DF90BD582EULL,
		0xCD4D7C7B7DF743F7ULL,
		0x6D7FE591DCE7244BULL,
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
	compute_modulo_25519(&k1);
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
		0xC1821526FD1AAD4FULL,
		0x3EE687BEEF206503ULL,
		0x2B2CF000B4AE5B79ULL,
		0xBCDCC6B19E8C5D83ULL,
		0xDB9B352375F1ACCEULL,
		0x68B4FCA573E1A8AEULL,
		0x14BD38E125E083F8ULL,
		0x3017C09BCDFE5496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8BF86A7EFA5500ULL,
		0xC9C4084E229F6EF8ULL,
		0x3F43616C5401F258ULL,
		0x60635DD2324CEBCAULL,
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
	compute_modulo_25519(&k1);
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
		0x5D4C3F5F4F72B426ULL,
		0x10AC65989DB5E2C2ULL,
		0xEA3F366CAAD54987ULL,
		0xB64A74D46D47B265ULL,
		0x38539A778698EA21ULL,
		0x367DA4D42F7E2E16ULL,
		0x713904AC674815BEULL,
		0x48826CCB5D98D1CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9B52D1D4A2576AEULL,
		0x2752DD17AA70BA0EULL,
		0xB8B5E803FF8883C3ULL,
		0x79A69B0451F6D6BEULL,
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
	compute_modulo_25519(&k1);
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
		0xD8343D1FE57A860FULL,
		0x800E6934526F54B4ULL,
		0x2640591BF73D8B4CULL,
		0x5627FEBC0B0D4557ULL,
		0xECF8BD130483D6A2ULL,
		0xF2E6FE044D702BE7ULL,
		0xEB075103F3AB341CULL,
		0xE4EF0F8580D086ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05204DF2910C6727ULL,
		0x8E581DD7D115D922ULL,
		0x09565FB222A74798ULL,
		0x51A44C8D2A0142DCULL,
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
	compute_modulo_25519(&k1);
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
		0x904C1A3EFAB477DCULL,
		0x5A93659B1F86F53FULL,
		0xF8AC5D2951034523ULL,
		0x5D1786457A6EA767ULL,
		0xF5D5B1051C1A5456ULL,
		0xD33738C9090E8DD1ULL,
		0xCBA5A776C5C38E69ULL,
		0xDA6B8E88B3820C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E046101269D0173ULL,
		0xB4C5D37277B0026AULL,
		0x334338CAAC0A68D8ULL,
		0x490EAE901FBC8474ULL,
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
	compute_modulo_25519(&k1);
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
		0x4A3112A4DB3F00D4ULL,
		0x532C6A9964DEC324ULL,
		0x98AC732885DD9F1AULL,
		0x4DC1B866C1EA51FCULL,
		0xCBA8C5BA70B0D5E8ULL,
		0xBA2ED4C69886009FULL,
		0xAB24FD9253197840ULL,
		0x7BAAF04608473670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x853E6C51957EC403ULL,
		0xF620001408C2DADCULL,
		0x002A16E0DBA578B5ULL,
		0x292162CBFC7C66B6ULL,
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
	compute_modulo_25519(&k1);
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
		0xA2A6842E939E68CEULL,
		0x2230A070B1525DE4ULL,
		0xF1DF44EBD44617D6ULL,
		0xAC1FE9FD21C83BE3ULL,
		0x0C54700EE5C71028ULL,
		0x7E18373058CC829EULL,
		0x17CC3621CA48D2D9ULL,
		0x1383583A3743E7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x772F2664AF2ACF43ULL,
		0xD9C8D19DDFADC15AULL,
		0x7A2F4DEFDB15641EULL,
		0x119F02A155DCAB03ULL,
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
	compute_modulo_25519(&k1);
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
		0xCA82D71C5EBB56FFULL,
		0xE890B5042AD0EF5BULL,
		0x650059EE640E76BEULL,
		0x051A770803FC5B19ULL,
		0x39A7DC72431B7F3FULL,
		0x7F9B6CD8902D7E1EULL,
		0x4D07B93765EC5EC1ULL,
		0xEFE71E38015586D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x596D901254D03F9EULL,
		0xD9A2DD299191A7D8ULL,
		0xD425D82785248777ULL,
		0x2168F35836AE5EC2ULL,
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
	compute_modulo_25519(&k1);
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
		0x4DDC1ADAD72A6CB0ULL,
		0xFD819286EEC679B5ULL,
		0x03B292F9E4044A9BULL,
		0xB52CF467ABB94AA3ULL,
		0x5CD55D8F2470EFC1ULL,
		0xFABFBAC7C781DC84ULL,
		0x2B8ED7B26E0A0A15ULL,
		0x883B4189F7125D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1587FE1A3FEE0661ULL,
		0x35F74C2E8C0D355BULL,
		0x7AE697763981C9DFULL,
		0x6DF8AEE258732CB3ULL,
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
	compute_modulo_25519(&k1);
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
		0xF081D3F6B75FF06FULL,
		0x924792BDF540BA57ULL,
		0x50CDB76BD7694066ULL,
		0xD6530131D5B276F7ULL,
		0xAAB3E60D2AE5D945ULL,
		0xA51D35D6966E373AULL,
		0x82229ED8E9F8BD0EULL,
		0xEBCD7C0DF7C76758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4735F9EB157E35F2ULL,
		0x149D9098499CED0DULL,
		0xA1F14B9E92555093ULL,
		0x56D36B449D4BCE1AULL,
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
	compute_modulo_25519(&k1);
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
		0x6E4CDD442143A2FBULL,
		0x9228884DEC4A2597ULL,
		0x3333CCA367FCE88BULL,
		0xDB9E51AF13A3BA6DULL,
		0xA49A13EDDBBD129AULL,
		0x463C72833D0A6F4AULL,
		0x9DEAA4428231F6C9ULL,
		0x5F642B130D9A93CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2BD292BF546811ULL,
		0xFF2187C8FBD6AAABULL,
		0xA4082E82BB678A6BULL,
		0x047CB6831895AAA6ULL,
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
	compute_modulo_25519(&k1);
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
		0xD450B46C6569AFD2ULL,
		0x9AA45500A6503560ULL,
		0x7F8B7B588967C145ULL,
		0x36459DEA9666A69DULL,
		0x4A898076729C61F4ULL,
		0x72959A2D1D5CDBC0ULL,
		0x5EB34905C4306688ULL,
		0x95F27F7CF1383E29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4B9C60168A03D4EULL,
		0x9CD937B30218D3EBULL,
		0x8E285233A896F986ULL,
		0x78448A7664BFE0C1ULL,
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
	compute_modulo_25519(&k1);
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
		0x4B3CCF2B17F653DBULL,
		0x27857EC0179349F5ULL,
		0x1E2CCEF83C3F4EE3ULL,
		0x63A546F51CF8E5EEULL,
		0xE158E9548775D050ULL,
		0x79BD90FCC382511AULL,
		0x7564AE0BFD71D124ULL,
		0xCBC515695027F161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6F71B733734442ULL,
		0x39A904451CEB53F2ULL,
		0x8B1EA4BFDB245A4DULL,
		0x22E6749702E6BA65ULL,
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
	compute_modulo_25519(&k1);
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
		0x5514A65F954DDA78ULL,
		0x93688D58E89319D0ULL,
		0xE1DCEAAB3EDB2B09ULL,
		0x38F9C9D314BDCCF6ULL,
		0x2C375A29550C467FULL,
		0x222CB678FC90F14EULL,
		0x6CA9DCE53DFF212FULL,
		0xE61CC97894B1559DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE54C08823520565EULL,
		0xA60BA34E6616EB6AULL,
		0x0313B4B272BA1808ULL,
		0x613FB1B927108255ULL,
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
	compute_modulo_25519(&k1);
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
		0x192F776B83D6D207ULL,
		0x1248E508C0CBCE4AULL,
		0x542409978AADA145ULL,
		0xED2B6E022AA7F049ULL,
		0x916E9C89CCA1A38DULL,
		0x2A7BD0A9AC84E826ULL,
		0x47CA1FBFDE33A9A0ULL,
		0x2772ACC983FCA406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF9AB3DFE3D519ECULL,
		0x60A9DE385C864403ULL,
		0xFC24C0128658CF0BULL,
		0x483113EBC2284937ULL,
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
	compute_modulo_25519(&k1);
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
		0xBA85BF6C88993850ULL,
		0xC4BE1EA15CF6065FULL,
		0x98E4F22AE1D17645ULL,
		0x18386307B5A220B9ULL,
		0xF76490888C758A6FULL,
		0x34E3284AEBFA8FE8ULL,
		0x8EC328823E2BA683ULL,
		0x2FFABFAB55FF6E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x737333B1620BC5D4ULL,
		0x9E7619C0642762F4ULL,
		0xC9DCF5801C4C2DBFULL,
		0x3770D676798C7B0AULL,
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
	compute_modulo_25519(&k1);
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
		0x0DD91F36C0388710ULL,
		0xC1CDF755536C9A27ULL,
		0x373A685CB977DA1EULL,
		0x955A017C20154E96ULL,
		0xB4C694DE8E38FC41ULL,
		0xCB4BB5449313FB0DULL,
		0x7238320BA40714D0ULL,
		0x68D5B2004B570686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE353383FDCADFB16ULL,
		0xEF0ADF832863DE2FULL,
		0x2B91D6171284F11CULL,
		0x25126D874F00468BULL,
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
	compute_modulo_25519(&k1);
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
		0x1B646C40E2F450F5ULL,
		0x0123982542B5CC34ULL,
		0xBD371C01F65B6FB3ULL,
		0x57F35B65C57A587FULL,
		0x573D78D1372F79F4ULL,
		0x6258DC1CF950B840ULL,
		0x8E8704736ACC1D60ULL,
		0x60C84C73DC3724D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E845B4F14006D54ULL,
		0x9A54447244B125C1ULL,
		0xE541C523D0A7CC01ULL,
		0x35AEB49875A9D058ULL,
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
	compute_modulo_25519(&k1);
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
		0x9380AAF502D645C7ULL,
		0x6FA364FFD530532EULL,
		0xC91306291307C3C9ULL,
		0xA2A69F78AE08F153ULL,
		0x5184941E6F52DD4AULL,
		0xF88A7FAB68AAC3FBULL,
		0x52436A5415BD7DA0ULL,
		0xF1BBD93ED674E8FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2EA7798923242EULL,
		0x543258715E896A7CULL,
		0xFF14CEA44D2869AEULL,
		0x0488DECC836386EDULL,
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
	compute_modulo_25519(&k1);
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
		0x08E01C19B044804AULL,
		0x5B4FE51D44F06272ULL,
		0xACD8DE18A14A5CDBULL,
		0x6110D74CF6A88E53ULL,
		0xE5272E33878925FEULL,
		0xE79CDEA080E2F3FCULL,
		0x3F660BC71142FEB3ULL,
		0xE1C7AE33C4A05705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB0F7BFCEA028F7ULL,
		0xBC98F0F066A099FCULL,
		0x15FE9DA5313C2B8FULL,
		0x64B4B2FC2675791BULL,
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
	compute_modulo_25519(&k1);
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
		0x6E17BBB1D1F0F15DULL,
		0xDCBB76A91D023B92ULL,
		0xBD67219F0B89C076ULL,
		0x366AF0B6B23D03C8ULL,
		0xDFC14C2A8F8DAC80ULL,
		0x6A2F71C7A97E9C59ULL,
		0x4D7AF759A7517BCCULL,
		0xD6D9ADDC2FD9FA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4C90A0320F8911DULL,
		0x9FC65A4C45CD70E9ULL,
		0x3DA7D8EDE1A220CEULL,
		0x1ABABF65CC982448ULL,
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
	compute_modulo_25519(&k1);
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
		0x57EA7289E9C698A9ULL,
		0xD234922E3A6529B0ULL,
		0xEAD56BF6D7F16CEEULL,
		0x61748AD315AA1697ULL,
		0xD1212445FC067E9DULL,
		0x0BA3A43D7429F29AULL,
		0xEF480CD7346B0CAFULL,
		0x5B8511A779007E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D5D4ED52BD65F8ULL,
		0x8C7EF34D789F2CABULL,
		0x6F8753E89FD54EEAULL,
		0x773529AF0BBCDD95ULL,
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
	compute_modulo_25519(&k1);
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
		0xF435A72228454E89ULL,
		0xF58E0A2558B8B3B5ULL,
		0x3AE0A304FF643552ULL,
		0x4830A8EF5C4B0763ULL,
		0xF46484738EB8FC9CULL,
		0x56D6C721E1146B91ULL,
		0xD33462090F0ABB7FULL,
		0xC90700C41C632425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B21504957BAD225ULL,
		0xD96F992CC1C0AB60ULL,
		0x94A7305D3AFC0A39ULL,
		0x1F3AC60B93026500ULL,
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
	compute_modulo_25519(&k1);
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
		0x1290521E7BCB8D9BULL,
		0xAB26BE52983D3676ULL,
		0xE3442631C457BEECULL,
		0x856440039A1C52B5ULL,
		0xDBD5C88893EBB6A3ULL,
		0xDACB4CC618FACFB7ULL,
		0xEAC62D80A62C5AD0ULL,
		0x17CE95780BF3C91FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44C166470C8AA65ULL,
		0x255423BA4D780BC0ULL,
		0xBCAEE74A6EED39EDULL,
		0x0E0E6FD5604C2D72ULL,
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
	compute_modulo_25519(&k1);
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
		0xE18DCB8B02A29B84ULL,
		0xC92BF9A7683F7A20ULL,
		0x571F779E952D8108ULL,
		0x0D7B1544ECB6DDC6ULL,
		0xA26942289E156963ULL,
		0x51879D113377B18BULL,
		0x87F75F4B47D5430BULL,
		0x7157835E966A3B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD2D9D9279D042A9ULL,
		0xE34D4A350C03D4DAULL,
		0x85D79CCB3ED574B6ULL,
		0x6078954F407BA214ULL,
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
	compute_modulo_25519(&k1);
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
		0x06C7134919F9EDA4ULL,
		0x8AEAFA5B1CF2AB2CULL,
		0x332F5D4943544B19ULL,
		0xB6367BC07CF80CC5ULL,
		0x688E92AA563E288BULL,
		0x59AF3B74BB37FAD2ULL,
		0x4BA26AC736D90D83ULL,
		0x803BEA739474B5C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF0D891E733F52BULL,
		0xDAEDCDAEE741E667ULL,
		0x6D4B36DB678C4C98ULL,
		0x3F1B48E8864B080EULL,
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
	compute_modulo_25519(&k1);
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
		0xCA8F116127AB6983ULL,
		0x77F0E0CFD0F98D18ULL,
		0x6F2BADB4F17BD7BCULL,
		0x937550B93C7B1E87ULL,
		0x790701C468744EF3ULL,
		0x3F3BB81691B10022ULL,
		0x5AAB52BE236BAFC2ULL,
		0x45A0707CCB4E04BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1995488A8EF2324ULL,
		0xDACE3429713F9236ULL,
		0xE499F5EE3377EE91ULL,
		0x6946033F6A0FD2EEULL,
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
	compute_modulo_25519(&k1);
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
		0x954D68A5CD0BAD2AULL,
		0xBBFF2448246D1915ULL,
		0x98BB43E8B6CE1FB0ULL,
		0x57CBF9448DFF5034ULL,
		0xA54946E87935B7A6ULL,
		0xA49A17C0AD5B590CULL,
		0x49A65F314A4D30D3ULL,
		0x87F1ABD19711AC5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2DEF27CB04F2D9ULL,
		0x2ADEAAE1DFFC50F6ULL,
		0x876D6539BE435F1BULL,
		0x05AB7A60FA9EE633ULL,
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
	compute_modulo_25519(&k1);
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
		0xF9CA1DF88CB093BEULL,
		0x120852B0F35366B4ULL,
		0x84D5101314E40E77ULL,
		0xB01FD8C28B4FE3F5ULL,
		0x165357B7D5CE1502ULL,
		0x67E0511A6E76A266ULL,
		0xA5B9132F6736B196ULL,
		0x58A741A63344C17FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2923424947B40BULL,
		0x7D545C9D58EF81DCULL,
		0x1E4DE91C67026ACAULL,
		0x58F3976E27849CE8ULL,
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
	compute_modulo_25519(&k1);
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
		0x769E1C2A42272F54ULL,
		0x319AD51828786CDBULL,
		0xAD484DBE77FA9F66ULL,
		0x0DBA97D25033389CULL,
		0xF5E2BACC9690864BULL,
		0xEA73FFBE59B7DC92ULL,
		0xDDEDAEF733A908D2ULL,
		0xE2975A899D65F12AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF645D6889B9B236FULL,
		0xFED2CB5979C32AABULL,
		0x9E9046702311EEB4ULL,
		0x3032083FAD5504F9ULL,
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
	compute_modulo_25519(&k1);
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
		0x2112D5112A56A2F3ULL,
		0x9EC7F785148A27B4ULL,
		0x5C324AFD6146165CULL,
		0x8BD84003535E51D0ULL,
		0x69B850458F4F2984ULL,
		0xA77F1FE2F938E16AULL,
		0x16BD8F049E722EB8ULL,
		0xAE8FB7317F454CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26EBF647016D067ULL,
		0x7BA6B33612FB9D7FULL,
		0xBC5585ACE63905C5ULL,
		0x752D715C37A7B2C3ULL,
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
	compute_modulo_25519(&k1);
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
		0x55282C9B654F5539ULL,
		0x0CC1043F114151E7ULL,
		0x3951B489CA04E93CULL,
		0x9B588AB130B88214ULL,
		0x4FF9972866DAEE0AULL,
		0x68367CA24498D514ULL,
		0x77B70D2AA17AE7CCULL,
		0x75BDF289DF693D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34349C9AA9CEAD61ULL,
		0x84D784553FF0F2EBULL,
		0xFE7DA8DDC2435193ULL,
		0x158A8B285A579FE1ULL,
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
	compute_modulo_25519(&k1);
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
		0x3577A952598FC1CCULL,
		0x74898A7DA6DE421FULL,
		0x1C92B33BDD11591EULL,
		0x2C90AF1F29197216ULL,
		0xFD289ACDB322A8AAULL,
		0x91AD36E3AC15E806ULL,
		0x37EF25CBA078B9DFULL,
		0x417DB48BABFA8734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97EA3DAF0B4CC71ULL,
		0x143FB049321EB328ULL,
		0x6A124F75AEFCF04EULL,
		0x65397BDAB04983D6ULL,
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
	compute_modulo_25519(&k1);
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
		0xD5DC961FF7039D55ULL,
		0xB4C1C6B2410C7B77ULL,
		0x1C54B9BE14EEF49EULL,
		0x487540E74AD93C63ULL,
		0xB5131D711036DEC8ULL,
		0x93C6879CAEA62EA0ULL,
		0xA87E74F9C92103D8ULL,
		0x95D36F58C719B0FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B2F4E85F28B25CULL,
		0xA439E7F42DB76752ULL,
		0x1F1A16D1EFD586C4ULL,
		0x05D7C814D8A981BEULL,
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
	compute_modulo_25519(&k1);
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
		0x43B82FD96C0C6B64ULL,
		0x0B6653C65F990718ULL,
		0xD3B0CA75CEC49395ULL,
		0x6AC8A14A716D4E6DULL,
		0x1F132019EC61562AULL,
		0x6AF518118E40E361ULL,
		0xE22EAC9EC88DCEFDULL,
		0xA65B6093AC6CF125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08EF3B2827F3956ULL,
		0xEBC7E6617D3AC782ULL,
		0x669E6A0793D14D32ULL,
		0x1C58F73609991A0DULL,
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
	compute_modulo_25519(&k1);
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
		0xC4F2FDAC9BE65DFCULL,
		0x637A2EB23B0B32F6ULL,
		0x6FB5789BCE42E9D1ULL,
		0x1A97D84E50E51A08ULL,
		0xC7EF0EC2396BAACEULL,
		0x0955221464F9FD60ULL,
		0x3CFFBF18AC01675BULL,
		0x42C9C1C271FC0B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x726F2E8121E1BA0CULL,
		0xC61D3DB93826CF54ULL,
		0x7DABD64556784154ULL,
		0x048A9B2B3C4EC4F9ULL,
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
	compute_modulo_25519(&k1);
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
		0xA4EC62DF87AFBE3AULL,
		0x8CDF33B93B312DF2ULL,
		0x4D540830DA5FF34BULL,
		0x3FF968924760D5C6ULL,
		0xB5E07CD94CD5FEF2ULL,
		0xFFEB7D73D5766BBCULL,
		0x36A2C2A1F457BDE0ULL,
		0x425CA10CFC9B425BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA43EEB20EF7397A2ULL,
		0x89D3D2EAEAC52BF5ULL,
		0x697CEC3B1F6622B1ULL,
		0x19B9507FC66CAF50ULL,
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
	compute_modulo_25519(&k1);
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
		0xA4DB8F5D633B8D07ULL,
		0x71DAB8738801638AULL,
		0x6028E8CBFA4BAC49ULL,
		0x9B96E90364E45DAFULL,
		0x73CBE7E88F6B2808ULL,
		0x45BB2DF1B10ECC1DULL,
		0x0DE9882A21434EF6ULL,
		0x8BCF646E1919274AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51FFBE2AD238155ULL,
		0xCBA38A53D033AFE9ULL,
		0x70D31F0CEA4964D7ULL,
		0x5C5FD15B1EA032ADULL,
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
	compute_modulo_25519(&k1);
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
		0x13C389414C3EE142ULL,
		0x67E84799C3C5A39DULL,
		0x9A67B883C5DA097FULL,
		0xA36A74A6D94BBFE1ULL,
		0xBFE179358BF0F431ULL,
		0xA80F19E7B189044FULL,
		0x95E51B1349CC3C28ULL,
		0xB1F160F322798C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F3B87341203248AULL,
		0x5A261FFE1E1C4773ULL,
		0xDA69BD60BA2AF788ULL,
		0x0D3ED8BDF7569319ULL,
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
	compute_modulo_25519(&k1);
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
		0xEAFC9F4AF6382405ULL,
		0x130EDDF2EFE05C09ULL,
		0xE3C86F6A7625290BULL,
		0xDFCF4CCB89AE9908ULL,
		0x7FB698CE98653E0BULL,
		0x6F6F7062FA2933DDULL,
		0x7DE5B681D3F4D128ULL,
		0x337BB0E6916C89E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0174DF5953F5AEAULL,
		0x9D998CA411FE0EEAULL,
		0x93E186AFEC7C350BULL,
		0x042B8F051FCB10A7ULL,
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
	compute_modulo_25519(&k1);
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
		0x53096EF6CBAA09E6ULL,
		0x2A28454AB52457BEULL,
		0xBF3276B3E4DCA219ULL,
		0xA5DF76CC2D423669ULL,
		0x2F7900A5B84748CDULL,
		0xC109D4A591B0D605ULL,
		0x7D6185EB0222F06AULL,
		0xE10EB026E0FF4C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EFF8790263EDD60ULL,
		0xD19DD5DE55641C83ULL,
		0x5BAC5796360C51F1ULL,
		0x0E0D9C919327846CULL,
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
	compute_modulo_25519(&k1);
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
		0xA3C5B58AAB0E7BD1ULL,
		0xCFA285D0628A05AFULL,
		0x2A69830EC2273687ULL,
		0x2846C9580D0174D4ULL,
		0xC67FD5399C6AB02DULL,
		0x929A927B45108CDEULL,
		0xF840D2D6C2A7EBE2ULL,
		0xB5D9F1977AB6D2B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ABF5C17E2E4A681ULL,
		0x9294441CA2FEEEC1ULL,
		0x0408CEEFA7143A29ULL,
		0x26A0A5D44424BC23ULL,
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
	compute_modulo_25519(&k1);
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
		0x7EEF1FF6B96DF743ULL,
		0xAA6E4188F131FF3AULL,
		0xE96773BA870DFF85ULL,
		0x8EFA76F8C5B4FF85ULL,
		0xE399E95DE7986296ULL,
		0x37E49473A766644BULL,
		0xDBC40CCC033A978CULL,
		0xA66AD939D96AC867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47C7C3E71A0C9D3DULL,
		0xF65C4AB3CA64E27EULL,
		0x88815A0301C07E55ULL,
		0x42D6B58F0B8EBEF0ULL,
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
	compute_modulo_25519(&k1);
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
		0x06D555BD0C13DA5AULL,
		0x6CF921DB74B44BB4ULL,
		0x4E4781E335987DEAULL,
		0x876BDEEAF8B96FD0ULL,
		0x246206C14F8CAF37ULL,
		0x7258D1FCDA35F07AULL,
		0x3978389E647D11A4ULL,
		0x6A7D742398A03B83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D62566EDAF5DEE4ULL,
		0x66284D63D8B5FDD5ULL,
		0xD61FE96620291C53ULL,
		0x560B1C33A082454AULL,
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
	compute_modulo_25519(&k1);
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
		0x97736F2F7FF50E65ULL,
		0x851CBA1E27C8953EULL,
		0x4A9E617222934AF9ULL,
		0xF41526EA434850EDULL,
		0x797FB0CE0BDA70AFULL,
		0x69A087FC07642F4AULL,
		0xEC8B4676FAD9BEB9ULL,
		0x063706FD96214DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA067ADC54261C898ULL,
		0x32F0E98740A79A4CULL,
		0x674AD71B5EE59A7FULL,
		0x6040308E8C39E0C2ULL,
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
	compute_modulo_25519(&k1);
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
		0x994021F1A1B2200DULL,
		0xF41AA486EB88CF0EULL,
		0x9116F933CCF746EBULL,
		0xF5EED3632A9D051CULL,
		0xA4483177133FE35FULL,
		0x8096977CFB2BAB76ULL,
		0x11C33DD7A36BC165ULL,
		0x4C3CDD3CAD19D704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF7799E7D2DE1EFULL,
		0x0A752114340442AAULL,
		0x341227360EF5FBFDULL,
		0x46F7AA64DC72EFB7ULL,
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
	compute_modulo_25519(&k1);
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
		0xC3CFC43D85E4FB29ULL,
		0x3EA877D25C48222DULL,
		0x63DCF2653A097613ULL,
		0xE4B56982A3D5950DULL,
		0xF308CCD82E32A717ULL,
		0x73B8D7D1EA886A86ULL,
		0x2DAF2B2865DBA103ULL,
		0x4DA427DCFD693A3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71E2C546169CA5BULL,
		0x6C1880FB2C87F235ULL,
		0x2BDD5A6458A35C96ULL,
		0x6B135450417439D6ULL,
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
	compute_modulo_25519(&k1);
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
		0xE39F6066F02A59ACULL,
		0x13FA2C6F08E6099EULL,
		0xF94E0148AA2730E2ULL,
		0xAF546917E3FB23A3ULL,
		0x60B54C0399CFC44CULL,
		0xD1DEA3B9BD82A7AEULL,
		0x7F78CF7F1A722C41ULL,
		0x9D974160BD227C26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E88A8EFC5018084ULL,
		0x3B067A012A4AED81ULL,
		0xE53CCE269719C2A7ULL,
		0x13C81D73F719915AULL,
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
	compute_modulo_25519(&k1);
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
		0xCDC8900CF371E051ULL,
		0xFE9D981E3AC643C2ULL,
		0xD6B4405EE565568BULL,
		0xA1BB1CB4927133D8ULL,
		0xC36DB6B4BFECEA3BULL,
		0xD82E91C814F7E184ULL,
		0xA0114DE1213BB1F2ULL,
		0x52EE35F0C176AC0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD011AEE1709CA6EEULL,
		0x15873BD15791BD77ULL,
		0x9945CFC9D441C098ULL,
		0x71171E714A0EBE04ULL,
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
	compute_modulo_25519(&k1);
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
		0x1BEAD2C6B2CA1B45ULL,
		0x73B2971AC293EB4BULL,
		0x93CE138CFC1DFF29ULL,
		0xDA1696F7B8257BC1ULL,
		0x91F01A49178DBE79ULL,
		0x1CC5AC8E0390AE89ULL,
		0x71BDB9278029C7E6ULL,
		0x17ADB2F49B0AFD2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58EB9A031D461D3ULL,
		0xB90A342F4A0DD3B6ULL,
		0x75F78F6A0251AB51ULL,
		0x5DDF2746BBC710CCULL,
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
	compute_modulo_25519(&k1);
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
		0x577CE4AF95645C8BULL,
		0x1736FBDBE3A3980CULL,
		0x3B3CF83AAE5A2BE6ULL,
		0x9557AAE04D81F713ULL,
		0x1F91A871C89A0060ULL,
		0xB6735FD0A8347B6CULL,
		0xDB248592E09C1BDBULL,
		0x04EA761576807229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x071BE5935C406AF1ULL,
		0x2C5734D4DB6DEA19ULL,
		0xC2A8CC0805864E83ULL,
		0x5025320FE492E949ULL,
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
	compute_modulo_25519(&k1);
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
		0x20DCF702BD3FF7B4ULL,
		0xAF12B2B292019382ULL,
		0x9279207C51A3AA7AULL,
		0x7D7FE14B2B80D1A2ULL,
		0x9A56FB378E632E11ULL,
		0x31E5EC97C999EB40ULL,
		0xEFA57103868202DAULL,
		0x3A180A3C0A65C9CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C64141DFF8CF90ULL,
		0x1733D13A7EDA7F19ULL,
		0x2507E70248F016DEULL,
		0x1D116634B69CC5C2ULL,
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
	compute_modulo_25519(&k1);
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
		0xA37230630F0F959EULL,
		0xE621811393BE837AULL,
		0x5A12E00DFD20EE97ULL,
		0x1B495A45B8121F98ULL,
		0xC3EE13B4B9ED51F3ULL,
		0x818975875CADDDA7ULL,
		0xB1E5B04CE6ECDD51ULL,
		0x5FEB7C589F5C718CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8C91D36A849C1C4ULL,
		0x2088F32B558D6A61ULL,
		0xC22B0B784449C8B1ULL,
		0x583DCF6D5FCAFA7AULL,
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
	compute_modulo_25519(&k1);
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
		0x02AA674362E2D642ULL,
		0x71A868DF019958A4ULL,
		0xFE399D0FD591BB5EULL,
		0x807CD58F18032595ULL,
		0x901A4A6FD736DFF5ULL,
		0x0940091DB58A43C8ULL,
		0x0B4484F3FC5F5B1BULL,
		0xA060883F42634CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669173DD55081830ULL,
		0xD129C347F41F6869ULL,
		0xAA6559474BB94161ULL,
		0x4ED10EF2F2C09079ULL,
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
	compute_modulo_25519(&k1);
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
		0xBC4007D11EAE37F5ULL,
		0xC0D35529EED7F1CAULL,
		0x2AC4F7A7DA170278ULL,
		0x968836B527A3C1A5ULL,
		0xDCC5C04A4829BCD4ULL,
		0xCDE8E16235F549B6ULL,
		0x235FE71D5DDED515ULL,
		0x4953FCB98449AA9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819A92D7D4E0410FULL,
		0x5164C9BDF140E2EFULL,
		0x6B014603C92AA3B5ULL,
		0x78FFBA3ECA931544ULL,
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
	compute_modulo_25519(&k1);
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
		0xBCC1F410E6873D32ULL,
		0xB055B7E61A0EF1BCULL,
		0xB1F496F9EE2325F3ULL,
		0xD3FFD99F22587172ULL,
		0x508D095A55C199D3ULL,
		0x045889C0293E6F4DULL,
		0xBD670C2ADED71058ULL,
		0x76CFE2DCC050AADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B15779A1441530ULL,
		0x557A2A6C39537736ULL,
		0xCF406557020F9304ULL,
		0x76DB8663AE51CDEAULL,
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
	compute_modulo_25519(&k1);
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
		0xE065CB462AC4D77BULL,
		0x40C94978BDF306EBULL,
		0x84996BC946F5D956ULL,
		0x3EC093601729CDD5ULL,
		0x51A649C2C1395FEBULL,
		0x0105D951AC963CA6ULL,
		0x71998CD9ADB9C8F5ULL,
		0x551A29748F80A00AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF14BE2ED9491638ULL,
		0x67A78B985C40079BULL,
		0x616454191089ADB4ULL,
		0x60A2BAAD64418F62ULL,
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
	compute_modulo_25519(&k1);
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
		0x61A2CDE4153B5D39ULL,
		0xB1285690A87400F5ULL,
		0x5239EE761D5A2561ULL,
		0x55FC233CC82E0746ULL,
		0x9DE59B6614673FDDULL,
		0x7EB6DB975C968891ULL,
		0xD935C60AE4776DEFULL,
		0x15BEBA707E31744EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B7DF0B1C8ED88CULL,
		0x804CEF0866CC4692ULL,
		0x90355414071476EEULL,
		0x104BCFEF83854AFAULL,
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
	compute_modulo_25519(&k1);
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
		0xA31E8802168DC17AULL,
		0xC87FCCCAB31BCA1DULL,
		0xA990B31414F9A993ULL,
		0xE052FD47FB315758ULL,
		0x3DB057B112C1A058ULL,
		0x92A933428A25EE4CULL,
		0x84AAC0A6CA9E4EF0ULL,
		0x300986DDBC34BC71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4B8C4ADF4B8FBAULL,
		0x8D9D68AB34BD296EULL,
		0x5AE94BD628796149ULL,
		0x01BD0231EB055032ULL,
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
	compute_modulo_25519(&k1);
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
		0xCD5671D71225A4C7ULL,
		0x1AE41FDB4A9BF4D5ULL,
		0x10CD17BCB197486EULL,
		0xA743E377C1949E73ULL,
		0x5D549724B00FED51ULL,
		0x3F14901089FDFD88ULL,
		0x5FC702B90C1448A3ULL,
		0x1514899675987E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7E4E1493482DF52ULL,
		0x77F1824FC64F9713ULL,
		0x48577F347C9A10A9ULL,
		0x48504FCD363766FDULL,
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
	compute_modulo_25519(&k1);
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
		0x8A3B251898F250E2ULL,
		0x4B4220897A6E8B39ULL,
		0x6B387B4F59ED3AD4ULL,
		0x9838CE18884B32ADULL,
		0x70CF320332C29A2DULL,
		0xEC358F45B7E1BB7DULL,
		0xB5D2B5C638BD84F7ULL,
		0xA7D517CCB73B34D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48FC919221D53759ULL,
		0x5B3564E2C5F05FD8ULL,
		0x687F76BBC60EF7A1ULL,
		0x01DA567BBB1509F4ULL,
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
	compute_modulo_25519(&k1);
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
		0x6879097296CEE127ULL,
		0x0EFA639DD2A24A3EULL,
		0xBE5F9048EC678D0FULL,
		0x2292E49FD8378E64ULL,
		0xC0CBA2CCF21E07A9ULL,
		0xBC52497C11B20AE4ULL,
		0xCE2E479B78918521ULL,
		0x58278D20AEF42471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B333DE8744062BULL,
		0x03314C08730FE833ULL,
		0x593E315CD2015011ULL,
		0x3871D779D074F749ULL,
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
	compute_modulo_25519(&k1);
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
		0x47B723B68BCB20C7ULL,
		0xF8D479041CC82FBAULL,
		0x6A94614F0AC743F6ULL,
		0xB32CBE7564EC0FE6ULL,
		0x6C9E28E782E6427DULL,
		0xA42974EE094196B0ULL,
		0x2AD4533D4592F0D3ULL,
		0x7E5677F62D9E3168ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67313613F9F90227ULL,
		0x56FBD4597C848DEAULL,
		0xC618BC675E970361ULL,
		0x74028D002A67655CULL,
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
	compute_modulo_25519(&k1);
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
		0x533FC4024C402248ULL,
		0x81BB2031A07760A9ULL,
		0xF6188DDCDA76B284ULL,
		0x3D7451809C54F627ULL,
		0x9579FBBDA70B522DULL,
		0x2E0A24E7E4ECD4B8ULL,
		0x0B02A6A73273753BULL,
		0x0604B249A90BFBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835B222917EE551CULL,
		0x573C9A9D9B9EF40FULL,
		0x987D4AAE579A194DULL,
		0x2226C86FB41C5BEFULL,
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
	compute_modulo_25519(&k1);
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
		0xCEDDBA527C6A0F2EULL,
		0x7572ED214942D17FULL,
		0x4E2C331B919CC81FULL,
		0x53599E6DAC331A35ULL,
		0xBE68D16F66667E21ULL,
		0x85E3BE64145779EFULL,
		0xEA1A178BA28392E2ULL,
		0x185678D4A8C98000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x126CD0DBAFA0C899ULL,
		0x55412FFC4E3EEB16ULL,
		0x0E0BB1D5B12495BFULL,
		0x702F8DFEBA1C1A58ULL,
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
	compute_modulo_25519(&k1);
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
		0xA59FD3FD37048AB2ULL,
		0xCEDFB374AEEB9B85ULL,
		0xD5079B8612A43D23ULL,
		0x7DF0B2999D26C844ULL,
		0x26195163E2CE279AULL,
		0x98ED69776FE99F4BULL,
		0x44201F51E39E424FULL,
		0x143A2409ED20AE2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D61E8D0E19E6C00ULL,
		0x821D5B2F4B9940ADULL,
		0xF1CC41ADDC2214F4ULL,
		0x7E920C12D000A2D6ULL,
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
	compute_modulo_25519(&k1);
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
		0x36859A3C21FB4CA6ULL,
		0x09B8ADF2E100B461ULL,
		0x71817290F7593343ULL,
		0x48679ABA2894BC2CULL,
		0x97FC6C87484FEA8EULL,
		0xB15407B4DAF74CD9ULL,
		0xA17B429F223C8C25ULL,
		0x467F5CF56AD5764FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5FDB650DDD81F49ULL,
		0x5C31D2CB61B61CADULL,
		0x69CD56300C5600DBULL,
		0x3F4F672804444BFEULL,
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
	compute_modulo_25519(&k1);
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
		0xEF6FD8B062F0F5CCULL,
		0x95DBBFAB02BB4C95ULL,
		0x5F58334E07166276ULL,
		0x6CE2B97AEC36A49AULL,
		0x48F63195F1D01F24ULL,
		0xA35BA203927918B6ULL,
		0xE5FC8DCBC3DCF3FEULL,
		0x52746F76C7E2D0B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3FB34F247D596FFULL,
		0xD575CC32C0B4F7A4ULL,
		0x82D53F8D19E29A42ULL,
		0x2A2B451C97E19F28ULL,
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
	compute_modulo_25519(&k1);
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
		0xBAF185A482AAE70EULL,
		0x64C74C237EC55BE0ULL,
		0x9D705F6BFBC51C46ULL,
		0xA616154FA904FD4BULL,
		0xF838DBB5F4A0EEE4ULL,
		0x52F1347EFBD652BAULL,
		0xF423AE3AEDB7B499ULL,
		0x9A16A95426326382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936222A6D28E6063ULL,
		0xB49516FCE095A3A1ULL,
		0xDABC3C2B4509EB08ULL,
		0x057337CD547FC2BBULL,
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
	compute_modulo_25519(&k1);
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
		0x286660168E79D7BEULL,
		0xB920D9D43B1AD078ULL,
		0x5060A06447F16D2DULL,
		0xCFC44828191B64C6ULL,
		0xD760BFE7916A930BULL,
		0xE973FB6D9CDD7C09ULL,
		0xFC908FDA340E08A6ULL,
		0xE1A2A13081C9426DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C2DC76244BB06CULL,
		0x60582C1983FB39EEULL,
		0xCDD5FAC80206B5F4ULL,
		0x4DE8355B5CFB4119ULL,
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
	compute_modulo_25519(&k1);
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
		0x0012A8981A4AB800ULL,
		0x96460D8C41FE0D57ULL,
		0xD956811678CA2543ULL,
		0x0815DC306689FA52ULL,
		0xE7199F402B30B7C8ULL,
		0x5ADDAF12802A864DULL,
		0xBA834532B19CE86FULL,
		0x63A759655F904087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE04C1E838601D7ULL,
		0x132E0A4B484DFCE7ULL,
		0x88D2C69CD614A5CBULL,
		0x52ED213C95F38E78ULL,
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
	compute_modulo_25519(&k1);
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
		0x5BDA1D81F7D35E8CULL,
		0x53723A4FBABC79BBULL,
		0x117153D51881792AULL,
		0x8E235B0ED48BE46CULL,
		0x11D3653116E4EC42ULL,
		0xD6C4C29CB78567AFULL,
		0x552679D1989C0220ULL,
		0x457B90A65F153495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013B22CB5DCE71E7ULL,
		0x34A71D92F889DDB8ULL,
		0xB52768F1BFA9CA0AULL,
		0x5E7AD3C0F1B1B296ULL,
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
	compute_modulo_25519(&k1);
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
		0x5E3FD19E796432E3ULL,
		0x99FC067DC803CD17ULL,
		0x175861272476FE4DULL,
		0xECEE3EFDF62956A2ULL,
		0xF66DE3824313E9A7ULL,
		0xF0FAB1575B00FB65ULL,
		0x300BB8500DF3981BULL,
		0x914E8CBEDED38C4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28F96F46E58E4F1ULL,
		0x5F3259754A291E39ULL,
		0x3915BD09369F9273ULL,
		0x7E972353099029A5ULL,
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
	compute_modulo_25519(&k1);
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
		0x701AEFCC482981DDULL,
		0x90F10829D57FF2CFULL,
		0x0DE794D8160FE944ULL,
		0x2EF195AE7101F197ULL,
		0xE4373E6A68E1CF19ULL,
		0x97062F7C940847F3ULL,
		0x5ABCA9C7D1610E2AULL,
		0x51F3D65175259217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504E3397D9AE415BULL,
		0xFBDC14A7CEBAA103ULL,
		0x85E8C8812A780396ULL,
		0x592365C5D495A10EULL,
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
	compute_modulo_25519(&k1);
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
		0xDB05137ED4A7B760ULL,
		0x4EEEED4CCDB768C1ULL,
		0x789DF5948CB4C880ULL,
		0xC9CDE99671440CF4ULL,
		0x41D5322C4FCE54E7ULL,
		0xFE843BD1CD8A7B14ULL,
		0x7247F1753541D2B3ULL,
		0x7F7BDBE7DBFAE347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0AA8612AD48548FULL,
		0x168FCE715045ADC3ULL,
		0x6F4BCCFA747A0F38ULL,
		0x36308E011881C98FULL,
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
	compute_modulo_25519(&k1);
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
		0x83E6E5FAA510384DULL,
		0xC36463A3E14BAFACULL,
		0xC8F8FE6E085FB0C0ULL,
		0xBA563FA00A885D7EULL,
		0xEE3EB4D66E081184ULL,
		0x3F2F3C96B448B564ULL,
		0xDB70FBAA6B388FF4ULL,
		0xB4842C80C9A79D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE135BDCEFA42D5FAULL,
		0x24676202A4169CA7ULL,
		0x5BBE59B9F2C50F02ULL,
		0x05F4DABDF969B5DDULL,
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
	compute_modulo_25519(&k1);
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
		0x35031780CDB3AC89ULL,
		0x47B51B3CFE7BD7F5ULL,
		0x39D7213677BB4795ULL,
		0xDA1353E39BDC7FB5ULL,
		0x6C9668577D87DD86ULL,
		0x40AEF83CB589F11AULL,
		0xAEC46ED7534CB6BBULL,
		0x89BB5EF64BE43C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5356947D6FDE918BULL,
		0xE1ADF43FF0F5A1E1ULL,
		0x2AFF952CD51E6760ULL,
		0x4BE36C72DFBD752BULL,
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
	compute_modulo_25519(&k1);
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
		0xCECA4C4286B3F2BCULL,
		0x0CA8DB7FF87F94C4ULL,
		0x6B14DA68CBE229B8ULL,
		0xBA0805F49C991447ULL,
		0x0C836F44C846ED24ULL,
		0xA82CA740A4554273ULL,
		0xC342DF304AC14BE6ULL,
		0x4392F00F66819142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4CD078413B27A3ULL,
		0x0349AF185D2771D8ULL,
		0x6701FB93E4936DF5ULL,
		0x41D7A83DD3D4A430ULL,
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
	compute_modulo_25519(&k1);
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
		0x50587F5423EE766FULL,
		0xE69F461B7F2DACDBULL,
		0xAF67CD878C1DE52EULL,
		0x89E0468933030D21ULL,
		0x3870CC4E2C98D5AEULL,
		0x061E94DC5F5864F1ULL,
		0xB3EF4A9D5F1B9486ULL,
		0x914A17DF44F85C3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB116D2EEC29E3187ULL,
		0xCF295ED1A64CA8A9ULL,
		0x64ECE0E3AA35F113ULL,
		0x1ADFD1AD6FE0BE70ULL,
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
	compute_modulo_25519(&k1);
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
		0xCAB36D6C241E4159ULL,
		0xF209BFE6226821BBULL,
		0x784309BA40C9BBD7ULL,
		0x9C2A98EEADCE48ADULL,
		0x3E4174A0827AA26DULL,
		0x1D888DF35D25511FULL,
		0xD0532F6E1FEF9E87ULL,
		0xC1C526D0A4D91B08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x086ABD3F825261D5ULL,
		0x544ED205F5F22C5FULL,
		0x649C1412FE5B43E6ULL,
		0x5F6E5BE726084BFCULL,
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
	compute_modulo_25519(&k1);
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
		0xB8FED49D94234C65ULL,
		0x4421D757BC47590AULL,
		0x713A9BECF839DD10ULL,
		0x4D993BA8B53B9336ULL,
		0xBE42B3D40F77B6FEULL,
		0x12FE614716AFC326ULL,
		0x8EC5EE114400CAD2ULL,
		0x1DBC2B4934AAD0FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E58617DFE876C4ULL,
		0x15E447E51A5E50CAULL,
		0xA29BF27D1057F83FULL,
		0x3787A8868696988DULL,
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
	compute_modulo_25519(&k1);
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
		0xEE38EB4F049DDA80ULL,
		0x0792C77EC511F82EULL,
		0xAB6B399561260713ULL,
		0x375BCA9404E0358FULL,
		0xF3F4346ACBC0B275ULL,
		0x18AD3E5A6AD541FBULL,
		0xC8FC8900C094F69AULL,
		0x47BDBE8014292A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2478B3294338596DULL,
		0xB14A08EAA0B9C395ULL,
		0x80E78FB1F742A1F2ULL,
		0x5D86119702FC72B7ULL,
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
	compute_modulo_25519(&k1);
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
		0x3D8CC1251A11CD7DULL,
		0xABD0215FE323C711ULL,
		0x116B403D38A9A5C2ULL,
		0x0A144B58CACCD439ULL,
		0x494B3BE3A5E702E2ULL,
		0x85F07A2DB3482E2DULL,
		0xB97BD14D20B4C6F6ULL,
		0x76717EA406776E48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EB7A4EFBA5C3DA2ULL,
		0x8D8244287FDAA1CAULL,
		0x99CC51B0137F2E5AULL,
		0x1EED17B1C0873304ULL,
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
	compute_modulo_25519(&k1);
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
		0x075AC1F7A6640312ULL,
		0xFE2A8A8DB7A69BD4ULL,
		0x59F3C51DAA9C2C02ULL,
		0x459860DB80DED6D5ULL,
		0x10C7753860597F62ULL,
		0xFB7F6849CA036293ULL,
		0x4187C7AAA8259ED5ULL,
		0xEB45030403E41E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F62855F3ACF0D0ULL,
		0x53140581B4273DA8ULL,
		0x141B6872A031BFC6ULL,
		0x31D6D37414BB5B7FULL,
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
	compute_modulo_25519(&k1);
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
		0xAD939FC4E8871406ULL,
		0xCDDC428E2E35BE15ULL,
		0xDD41342C48F95CD0ULL,
		0x664E6063A50F7252ULL,
		0xD416A462AAF67DC5ULL,
		0x845A250D9675010DULL,
		0xBD43B2FFC61B4213ULL,
		0xFB5883F6AAA5D8D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F0066A491DC4D5ULL,
		0x733DC2928393E623ULL,
		0xF54DC623B1052BB6ULL,
		0x3571F700F9ADA20CULL,
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
	compute_modulo_25519(&k1);
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
		0x0CE923068BAD829EULL,
		0xDB7638E45272A065ULL,
		0x36D72D1448E59DCEULL,
		0x2BC1F23EE559B652ULL,
		0xF7DECDABF78116E4ULL,
		0xCB29EF02859051BDULL,
		0x3521BDF63E431B7DULL,
		0xF6FF97A2AB33CAFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7FBAA8D48D6EDE1ULL,
		0x03AFB34425DEC297ULL,
		0x19D95FA186DBB27BULL,
		0x55B274644F09D79CULL,
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
	compute_modulo_25519(&k1);
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
		0x798D71209EC43260ULL,
		0x21A59126012091B8ULL,
		0xFDFEEDCFA7D141E1ULL,
		0x22742312133E352CULL,
		0xF03B22C17353DBB2ULL,
		0x8C85DA6C68D82597ULL,
		0x38409382E1565315ULL,
		0xE6584DF79D27ED2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x225499D7BD36D3D8ULL,
		0xFD83FD3D91362646ULL,
		0x5794D33D1AA19713ULL,
		0x538FB5D3672B6997ULL,
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
	compute_modulo_25519(&k1);
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
		0x95E911B45F157AE1ULL,
		0x326A896D900C1372ULL,
		0x9CD9EF4D78348BFEULL,
		0x32F9F2992D475CE0ULL,
		0x9D79E1DCF428505CULL,
		0x40EB74C53526907AULL,
		0x12D2C9E5960EC956ULL,
		0x5676BC9DCCA959F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60098809D116A77ULL,
		0xD55DDEB373C585A5ULL,
		0x6823E761BE666ECBULL,
		0x0899F2058E6AB6CFULL,
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
	compute_modulo_25519(&k1);
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
		0x0628EFAAA8632727ULL,
		0x3AD0656A91F5DE2BULL,
		0x811A7447A63F6A4FULL,
		0x78244CE96609ABCCULL,
		0xF2BF427CD5E539D9ULL,
		0x904C3CB86AE05942ULL,
		0x94038C899B238635ULL,
		0xF10A7E81A5B0461AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E8CCE326869C2B5ULL,
		0xA62168CA6F431E1BULL,
		0x79A150B4AD855642ULL,
		0x3FB31427FE3413BEULL,
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
	compute_modulo_25519(&k1);
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
		0x8225C90B065A1D83ULL,
		0x522ECCF3D6805E5BULL,
		0xA978A6101F6DA4E2ULL,
		0x2CDBB1422D48D2B2ULL,
		0xD90DEC26C2A8BB39ULL,
		0x56ECA60ADC615B42ULL,
		0x19A53CD2DD47402CULL,
		0x02EEB075D29355AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA36D6CBEB65E80CULL,
		0x394F72908CF3EA47ULL,
		0x77FFAD5CF8012B77ULL,
		0x1C49E2BF6F278A8AULL,
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
	compute_modulo_25519(&k1);
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
		0xAEC71F9C19A60C8CULL,
		0x521B85A3B675E84EULL,
		0xAE5E2B94704FBC22ULL,
		0xD028A8F5B7BDDD34ULL,
		0xB6F404A53AA1F2F3ULL,
		0x1B0A891810A0A8B8ULL,
		0xA44AB14AD02EDA8CULL,
		0xE4E1B077B4413E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FFD022CDB021BDULL,
		0x55ABDF362E4EF3B9ULL,
		0x11747CAF57442CEEULL,
		0x49A8DABA796D271FULL,
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
	compute_modulo_25519(&k1);
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
		0x7FBE27C67D925B9DULL,
		0x157EEB60D87A4742ULL,
		0x27540B892C530FE0ULL,
		0x94A134E5927B5740ULL,
		0x31CCFB54FC329FC6ULL,
		0xEB70AF1C90F5FCF9ULL,
		0xA5B75DE6F8D96441ULL,
		0x19E1D19A40AC9578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE42B7663ED161399ULL,
		0x0838E99E5CFDD43FULL,
		0xC08BFBD21C97F1A9ULL,
		0x6C2651CB2C198728ULL,
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
	compute_modulo_25519(&k1);
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
		0x2F2F1FC867AF9DBFULL,
		0x33D76CB5777BCA2FULL,
		0x4D8974F8B1449613ULL,
		0x00A76A5559A5771DULL,
		0x6124067DB7E8C4D0ULL,
		0x62B1A06BCFCCF6ADULL,
		0x4F382759D4256983ULL,
		0xD281BA4F8857CE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A881671B43CD939ULL,
		0xDA353CB64FE867EBULL,
		0x0FDF4C4E2ED23F93ULL,
		0x3FE9122396AE2277ULL,
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
	compute_modulo_25519(&k1);
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
		0x00E3408EA8ED487DULL,
		0x5FB8D88E1EA6E3EAULL,
		0xAD12D70373A67822ULL,
		0x7482542A21873207ULL,
		0xD5DB3144F04DACC4ULL,
		0x9FF209F74375177CULL,
		0xBD02ED9066BB30B2ULL,
		0xBF483027EBB25E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF6C90CA5474F1D0ULL,
		0x1DA6534222086071ULL,
		0xBB821A72B36FB2A6ULL,
		0x59397A171E013145ULL,
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
	compute_modulo_25519(&k1);
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
		0x2BA4FBC1EB01842AULL,
		0x29ECD0EBF7A9BA72ULL,
		0x60DFFE97D488668BULL,
		0x159B28E9CD6C5BB4ULL,
		0xDE74FBE4B0625946ULL,
		0xF82294D43C7D8373ULL,
		0x02436FB3152D7476ULL,
		0x94B735D3F4ED0BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31025FB4199AC7D2ULL,
		0xFF0EE86CF24B3DA5ULL,
		0xB6E2932CF947B033ULL,
		0x28CD2660289C2342ULL,
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
	compute_modulo_25519(&k1);
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
		0x45B41DB75E9A5669ULL,
		0xB8B5093F158AD561ULL,
		0x9AEA2E1F9A989F99ULL,
		0xD61E0106AB7B4365ULL,
		0x254376E61CD5A726ULL,
		0xB4401898FD7085DFULL,
		0x6CD2AC461A75CB95ULL,
		0x97CE72B78571DEFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB7C3DFA6512977ULL,
		0x7A38AFF4B43EB480ULL,
		0xC22FC0878814D7D2ULL,
		0x5EC308447A625D03ULL,
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
	compute_modulo_25519(&k1);
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
		0xBDB6F85DA1334DFCULL,
		0x4E69E4B8594FB0D1ULL,
		0x9D32663AD09E3B1DULL,
		0x8EB6F16E547E3555ULL,
		0x5618D1D6B87144FDULL,
		0x88389F6CE1BB1F2EULL,
		0x6D3ADCD00C273612ULL,
		0x67EE210C24D0682AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85661E3D02038DD7ULL,
		0x86D18EE1DB1651B2ULL,
		0xD3EF2D1C9E7041DDULL,
		0x7C0FD93BCB6DABA1ULL,
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
	compute_modulo_25519(&k1);
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
		0xDA2EBEF37F75A1ECULL,
		0xA41BDC9BC0D1B926ULL,
		0xE1115FB3C2233558ULL,
		0xE0ECD4EAE4E79A57ULL,
		0xB740F95975832266ULL,
		0x17D969698D6B745AULL,
		0x3A3C4A22878C9465ULL,
		0xA5565C2E85AB721AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD3C23AF0ECC0C6ULL,
		0x2E618246BEC4FE9EULL,
		0x860460D3E1013C5AULL,
		0x6BBE83D2BC5A8A3CULL,
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
	compute_modulo_25519(&k1);
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
		0x0ADA068FF6CCEBB9ULL,
		0x56137C2F1E7D6A7BULL,
		0xBE0F1DD9BF0B862CULL,
		0xAD02D18709AE9F01ULL,
		0x9DA6CE43AEDF54B3ULL,
		0x4E97088E7F54A9C6ULL,
		0xB70794EEFBEAA070ULL,
		0x1F877A9BAA01A97BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719CA49BEBF37F09ULL,
		0x007EC156050E9DF6ULL,
		0xE92F395323DF56D8ULL,
		0x5B1F04A245EDC75EULL,
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
	compute_modulo_25519(&k1);
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
		0x7042CC3D3234A220ULL,
		0xAA30156E8F65B395ULL,
		0xA92DCE64D34D646FULL,
		0xAA9E3E17B08286DBULL,
		0x823FB0C0103EBFB6ULL,
		0xB2C9F6DA9BFB1414ULL,
		0xC21D5C99907E61D3ULL,
		0x20A95B8D3D42B48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B708BF9B8517F5ULL,
		0x342AB9E1B6AAAEA0ULL,
		0x79898D30460FE9DCULL,
		0x03C1D50EC86953E6ULL,
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
	compute_modulo_25519(&k1);
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
		0xCF85C91D408BA563ULL,
		0xCF8D2DF0F9428C9CULL,
		0xA8815FA4456DF437ULL,
		0x8B8ACBA9EC02F892ULL,
		0x4B5504729446035EULL,
		0xEC2850AE8552F4A6ULL,
		0x2C0E970D08B822E9ULL,
		0x762EDA9105245DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE24721F42F02803ULL,
		0xDD8927D8C392DD4BULL,
		0x32ABCB9390C322F0ULL,
		0x167F3D30AF68E579ULL,
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
	compute_modulo_25519(&k1);
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
		0x67EE3294A5D0CC42ULL,
		0xB7BF91A87F362474ULL,
		0x12C0F8A645C960C9ULL,
		0xE8EEAFAAC13E042EULL,
		0xE5F79CBCE5B94DBCULL,
		0xBA3C7EC24BC63B24ULL,
		0x2A32AB7881AE7F64ULL,
		0x3BBD7BDF83959DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AAF769EBF525793ULL,
		0x5CBA627FBEA2EBEEULL,
		0x56466C8985B049BDULL,
		0x470F12D849736A40ULL,
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
	compute_modulo_25519(&k1);
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
		0x76A22B63F3DC0880ULL,
		0x53E47F8AE5E1F0DEULL,
		0x063C0A89BA408C1DULL,
		0xE9DE48C97D5D4EA7ULL,
		0xEA2DBEC454F4B68DULL,
		0x7127E5FA0ABA3EBCULL,
		0xDEB9D04D4F50D3BDULL,
		0x0B0C726DDBC9D2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x396C7C88902F21CDULL,
		0x1FD0A2A87D8740E9ULL,
		0x15D0F603803FFA3CULL,
		0x0DB745181D529F00ULL,
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
	compute_modulo_25519(&k1);
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
		0xE2F85F9FDB6602E2ULL,
		0x2335ABADC81635B8ULL,
		0xD59A7F08C2983825ULL,
		0xD4FAC9DBFDC42E94ULL,
		0xCA12BCD0275BE7A2ULL,
		0x6E9488DEDE8D0759ULL,
		0xD76B8019C2939D07ULL,
		0x152698040C759F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C06685B30A6573ULL,
		0x8D41FCC2D1054D0CULL,
		0xCF8F82DBA481873FULL,
		0x78B55A75D739DD7CULL,
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
	compute_modulo_25519(&k1);
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
		0x5C1383D1C4ACD25DULL,
		0xEF864D4194DE9011ULL,
		0x0545D244AA180D41ULL,
		0x0C2511A50FE09D6FULL,
		0x38DAE5BC48FE7247ULL,
		0x04C4E83EB74D478AULL,
		0x4A11ADA61AFA1CCAULL,
		0x9D7F5FB481510B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC919DC49A71CC51ULL,
		0xA4C0C690CA572E95ULL,
		0x03E598ECAB38533EULL,
		0x6D0D467041E85312ULL,
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
	compute_modulo_25519(&k1);
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
		0x47FB6C2D0F0D1515ULL,
		0xC719F735DC2A8C8BULL,
		0xF89FE176C25083C5ULL,
		0x57E3E802B3870E4FULL,
		0x7F93C808C7B44B0DULL,
		0x43E30FAEEA2166F5ULL,
		0x4E6694E9F6C36FB7ULL,
		0xEC9F4BE861957390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37EB1D7AB3D03E35ULL,
		0xDACE4B2C9D1FD4FCULL,
		0x9BD9FC31635318F9ULL,
		0x77892C812FB635BBULL,
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
	compute_modulo_25519(&k1);
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
		0xD33F3B41F2E0C146ULL,
		0x4DD0EA39598B19AEULL,
		0x4B381A7D49BF3020ULL,
		0x413F3AEC6BD9EE5EULL,
		0x0E93F4C483423E9EULL,
		0x302EE4E5D88D8C75ULL,
		0x73522CE61EC76EDFULL,
		0x4B6E91CABEF1F24EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD35906D6EB60E5CULL,
		0x74C6E4577E8DF30EULL,
		0x696AC4A5DB59A541ULL,
		0x73A8DF04C3C3E603ULL,
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
	compute_modulo_25519(&k1);
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
		0xBC3155ECAC668E02ULL,
		0x22FD232B3BA9BB45ULL,
		0xF854F1533F838BC4ULL,
		0x1868AF7E9B41C755ULL,
		0xA738C1067E52DDCEULL,
		0x7E0935AF998ACF89ULL,
		0x3228EAE5092E8360ULL,
		0x95202B0D96E8CD50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9DFCE36CB37DDAULL,
		0xD85B1B3C064489B4ULL,
		0x6A67CF529C6B0C16ULL,
		0x3B2F138301D0413DULL,
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
	compute_modulo_25519(&k1);
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
		0xB6F00BC45A6515C7ULL,
		0x99C732B37442C962ULL,
		0x8B13E155EE2658D6ULL,
		0xAA8956E3BB389DF2ULL,
		0x26558165A18F7355ULL,
		0x1FC4393DC5869036ULL,
		0xF1DC24D489F65EB2ULL,
		0x2949D5EFDEC25089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A140DA55B0355CULL,
		0x50E7B1DEC63C316CULL,
		0x71C158E268B86747ULL,
		0x4B7F187ECC10926CULL,
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
	compute_modulo_25519(&k1);
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
		0xE39048B618D51858ULL,
		0x6DFEEE01FE94CB5CULL,
		0x3E5587275AE73102ULL,
		0x9EB45459EE90DEECULL,
		0x9308FAD389A00D47ULL,
		0x962BE79D957B844DULL,
		0x106F38A053ECBA04ULL,
		0xBE9FDA5A9BA507EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E5841C8697151DULL,
		0xB8834F662EEA6EE0ULL,
		0xAED7EEF3D00ACDB0ULL,
		0x6A6EBDCD09100C42ULL,
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
	compute_modulo_25519(&k1);
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
		0x2F329AE744770B5DULL,
		0xEDB67491759959ABULL,
		0x4EF30C19BCA1C6D5ULL,
		0x6EB23CAB82934A45ULL,
		0xEC707AB8F552BDC0ULL,
		0x05F98D1549FDD26AULL,
		0x2935E8A57725CBD5ULL,
		0x037CDA50051100DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E4D25BAEBF35F0ULL,
		0xD0C165BA7146958AULL,
		0x6CF394A96C3E0874ULL,
		0x733AA48C43196AA7ULL,
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
	compute_modulo_25519(&k1);
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
		0xB93ED51A2D16DEDAULL,
		0xB2656849CAC7CF8EULL,
		0xB9488F9D3D217C41ULL,
		0xD640B431799D9899ULL,
		0xDCE37E8D27967017ULL,
		0xF41663391AB401C1ULL,
		0xBE420DA6A9A13048ULL,
		0x5DD53ED85EFD3616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83039E0E0D6B846BULL,
		0xEDB822C3C1801255ULL,
		0xF716965A6B0EA715ULL,
		0x43E8084F93339FF9ULL,
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
	compute_modulo_25519(&k1);
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
		0xDA98E21E19669ED8ULL,
		0x0187E48148A60151ULL,
		0xBF3D3449D336662DULL,
		0x6B5331EA5405B723ULL,
		0x419EA035DD522A34ULL,
		0x9529DBF7C9B915FEULL,
		0x943ED47A6D4D2084ULL,
		0xA396924225C7DA0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9824AA1CF398E633ULL,
		0x25BE8B493A1F450FULL,
		0xC090BE760CA939DBULL,
		0x33ACE7BBEFB01501ULL,
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
	compute_modulo_25519(&k1);
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
		0xE9797D7366E87F8AULL,
		0x25E24E0A282715C8ULL,
		0xCC71770B98CD9A4EULL,
		0x6FA0F89774CD9663ULL,
		0x330F4ACADFD376B7ULL,
		0xB7CC217B9CD02DBCULL,
		0xBD05EE7E7300D634ULL,
		0x1B79FE9F0AD01680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DBE9790A04C1F5FULL,
		0x6E2F46636F0DDFB8ULL,
		0xDB52DDD0AAED6621ULL,
		0x03BCC4330FB0ED7FULL,
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
	compute_modulo_25519(&k1);
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
		0xA43A24AC660677DEULL,
		0xBDF683DE55D0E6A7ULL,
		0x1229ECA866C79165ULL,
		0xCBB5064B613B6387ULL,
		0x2F4999FB32204AE0ULL,
		0xC4BE117D8C1FF3EBULL,
		0xF4B5A3008B9A0F7AULL,
		0x697D7963C5421264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA926FFF5D6D1977EULL,
		0xF22D1C81228F1B90ULL,
		0x65201EBD1FA5DD9EULL,
		0x74550B1AA90A1E83ULL,
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
	compute_modulo_25519(&k1);
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
		0x846C643EED3D1A21ULL,
		0x86C3557B31458F2AULL,
		0xDA8A713AF5482415ULL,
		0x30D3853C12E8A6C7ULL,
		0xFD532C40D75FACF8ULL,
		0xA6A0C107945EE14DULL,
		0x605E2E53A353236FULL,
		0xF243CE17F44FF712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EC4F5DEE570CC49ULL,
		0x429FFC9B375B00BEULL,
		0x288551A5339F66A8ULL,
		0x26E41CCA56C75382ULL,
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
	compute_modulo_25519(&k1);
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
		0x3A6C7271426627DCULL,
		0xA9A743BEA2C604EBULL,
		0x772AE0D545394E93ULL,
		0x825B5588D738C3CFULL,
		0xCD248E8A2D797A23ULL,
		0x5CCB4DA952B25077ULL,
		0xE2A0F84B82917E52ULL,
		0xBA9F21CD133E95C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD99AF4026E4D36ULL,
		0x6FD4CAE0E93DF6B3ULL,
		0x1B0FBC0AA6D20ECDULL,
		0x35FA59F9B282FFC7ULL,
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
	compute_modulo_25519(&k1);
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
		0x4F736A52D1C7B6B3ULL,
		0xB7DF07D115ECA70BULL,
		0xAB3FF5C20D29578DULL,
		0x50DE53F009665A48ULL,
		0xBC216EBE7D41F5DEULL,
		0x267E764BC3962724ULL,
		0x5FE3418268ABEB84ULL,
		0x73D455B0B50733F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C69DA9969923840ULL,
		0x6EA497101E36767FULL,
		0xE6FBAF1D96AE4D2BULL,
		0x02630C2AE87810B4ULL,
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
	compute_modulo_25519(&k1);
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
		0x5ECC22BB19906C47ULL,
		0x05CB6EB6400315FFULL,
		0xF2D4CDFC45C266F0ULL,
		0x5F7EB8E8120054D2ULL,
		0x7A2736B5B1730ED1ULL,
		0xBAAEDF6DED70BDB1ULL,
		0x86FB0A31EE35013AULL,
		0x6660CE1A1F91B8B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809E41B370A4A19AULL,
		0xBBC099077EBF3E57ULL,
		0xFC185165A1A095A7ULL,
		0x11DD50C8C1A1BF52ULL,
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
	compute_modulo_25519(&k1);
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
		0x93B690F0323B3334ULL,
		0x8E6481401E957CE8ULL,
		0x3C8EA2D7B129AF81ULL,
		0x78131F0473AE7FFFULL,
		0xBE49EF3ABC1DAF74ULL,
		0x8CF240B5EC388808ULL,
		0x217DBBC3B46CA16EULL,
		0xE841194DFBE9EB76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B013A81EA3438BULL,
		0x7A5A1C412EF9AE34ULL,
		0x353881E47949A5EAULL,
		0x71BCE097D8677388ULL,
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
	compute_modulo_25519(&k1);
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
		0x83F82277B16AD30AULL,
		0x552266D2D205D6CAULL,
		0xAF09E6DC7B53E93DULL,
		0x96C193B406129EA1ULL,
		0x75E015F730A50511ULL,
		0xE75D490649779886ULL,
		0xF88272B029051837ULL,
		0x014E05C8B2836A39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x033B6528E9E993A3ULL,
		0xACFB3DC1B9C67AC0ULL,
		0x9266ED0292158189ULL,
		0x48566F7E8594633CULL,
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
	compute_modulo_25519(&k1);
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
		0xD169974D8D78B086ULL,
		0x802028E7B8E4E03DULL,
		0x0487E74B7845FF02ULL,
		0x869E748EF65FB2E4ULL,
		0x371F25B4735F0B09ULL,
		0x5BC9724CC9091787ULL,
		0xAC0620406EFCBD77ULL,
		0x9376B07356BA1756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00093016AD945720ULL,
		0x2007204D903E5E50ULL,
		0x8D70B0DBF1CA1EBAULL,
		0x6A3CA5ADD5FF29C1ULL,
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
	compute_modulo_25519(&k1);
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
		0x791955BB3525A376ULL,
		0x9A0A2FCE3C5BEF59ULL,
		0x67ED8E7832A1BB20ULL,
		0x4288480E523E75D3ULL,
		0x3462E7A42DF01029ULL,
		0x1F1F66D680DBD2BCULL,
		0xC7569F86284E39C6ULL,
		0x7766DFC54A49E5F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC7B81A06C80C25ULL,
		0x38B373A55CFD3749ULL,
		0xFEC93C622E3E4E89ULL,
		0x7BCD7F5759369828ULL,
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
	compute_modulo_25519(&k1);
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
		0x4B5B1E6A01123FFEULL,
		0x9A55734681044E09ULL,
		0x5E952A948EA25A0DULL,
		0x5F9F92A9D4E055F7ULL,
		0xEA9E69A787384D46ULL,
		0x4418C2A38D4D766AULL,
		0x921C61AA296A535CULL,
		0xEF90AD2894ADF1ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EDECD48136DBDA7ULL,
		0xB602578D7A83E1E8ULL,
		0x0ECBA9D6B46AB9BFULL,
		0x6F1946AFE6B23595ULL,
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
	compute_modulo_25519(&k1);
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
		0xCF8F81913781790CULL,
		0x084A8269BC2D24E3ULL,
		0x301ECE48C16EEC29ULL,
		0x50FDFC09148A5270ULL,
		0x816766944D3EB48DULL,
		0x1945C0BA272CB028ULL,
		0x3E1EC700972A44F8ULL,
		0xEFF4660059AEBF07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E8BB94AED04B3FULL,
		0xC8A51E0B8CCF4AE7ULL,
		0x68B0585F31B528FCULL,
		0x6F452016647AAD83ULL,
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
	compute_modulo_25519(&k1);
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
		0x8502C16FA7B90C67ULL,
		0xCF6EA247B8DD49DFULL,
		0xF4B080221245BA9CULL,
		0x90E6384A8A34325AULL,
		0xA2DBF9D8E721D3E9ULL,
		0xF3AF20B96329148DULL,
		0x304A23869F029175ULL,
		0xC6A7015281327C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1A9D7A1F6BE8571ULL,
		0xFB6D7DCC70F656E5ULL,
		0x1FB1C61DACA7521EULL,
		0x0DB06A89B7B29A62ULL,
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
	compute_modulo_25519(&k1);
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
		0x0D709044B1C7A5A0ULL,
		0x9A38A83694B2C6F3ULL,
		0xD72614606405C00DULL,
		0x62E2FC3A2D0FEC39ULL,
		0x68609A6363C1C0B7ULL,
		0x685DB11466444859ULL,
		0xEFC39D0C5DC66082ULL,
		0x3734080CC6B8DB93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BC77B05808A420DULL,
		0x1820F13DC2D58438ULL,
		0x6E2F64364F781369ULL,
		0x149C2E1FAC80842FULL,
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
	compute_modulo_25519(&k1);
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
		0xAD421086708F470FULL,
		0xE0C05AA9360E2202ULL,
		0x1A4AD1F403EB98DEULL,
		0xCA9AF5C2AA47A9DAULL,
		0xF8D1E8198D4F19A4ULL,
		0x47CF9D8E20E4EFD3ULL,
		0x01C8B5887F131800ULL,
		0x9D2D13BC05B93C47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6A84516A4D18F7ULL,
		0x8991BDC21809BB79ULL,
		0x5E15C436E0C128E9ULL,
		0x1F4BE3AB83C69C64ULL,
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
	compute_modulo_25519(&k1);
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
		0x7B79B69E545D4069ULL,
		0xD78CE660D5476865ULL,
		0xC2E102D2EAE560BCULL,
		0x08425E84BA3C4216ULL,
		0xC95DEB33E4840571ULL,
		0xBE06AF17B750D9A3ULL,
		0x9C8E07CA866AF767ULL,
		0x677DFD38011849F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F6AA0523FF61169ULL,
		0x0C8AE3E60B47B6B5ULL,
		0xFFF62AE2DEC61A23ULL,
		0x64F5F4D4E3D73C3FULL,
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
	compute_modulo_25519(&k1);
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
		0x5BBB56BABF4F02A8ULL,
		0x4EAECE9D5C5E00B0ULL,
		0xECCF54E5809345C0ULL,
		0xBC7EFCB5080FF03EULL,
		0xC5AEE15E3AFE19ABULL,
		0xCF0C092681889A07ULL,
		0x1681DDB275D0564CULL,
		0xD426008ED234BC0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B0CAB78106D6CAULL,
		0x0A782A5496A4DDD7ULL,
		0x44163D62FD801527ULL,
		0x3A2311E83BE3DA0AULL,
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
	compute_modulo_25519(&k1);
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
		0x017072BA501B1616ULL,
		0x9CF2AF03CD8C4E72ULL,
		0x1816E6308D549ED8ULL,
		0x5067FE6818D6B644ULL,
		0xBBD6D0DF44ADFE67ULL,
		0x22C53C7ED9FB7980ULL,
		0x2507AEBA95072207ULL,
		0xBCEBA6E6A873E3F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35373DE81EEDD88ULL,
		0xC639A9D828E0578DULL,
		0x973AD5E2AC63ABE7ULL,
		0x5B62C4A51A0A8CCDULL,
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
	compute_modulo_25519(&k1);
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
		0x6E88E855CE788CF5ULL,
		0x9B0FE9A018737C1FULL,
		0x8C236CC23E4C7419ULL,
		0xBAA7467B588C4172ULL,
		0x3862B46F67351193ULL,
		0x9431414788527D39ULL,
		0x64A80DE601D05E49ULL,
		0x411394006BE26ED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD2FB0DF20592A43ULL,
		0x9A5F9A3E54B2129DULL,
		0x7D157CE6833A7305ULL,
		0x638F3E8B5C28B4ADULL,
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
	compute_modulo_25519(&k1);
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
		0x952BAC560F7FD87EULL,
		0xA0BB60A8DBA59555ULL,
		0xEE946FA0DBAE4C00ULL,
		0x08367D6F31CFD2FBULL,
		0xAE05650A3462A781ULL,
		0x903E024572C2510BULL,
		0xD65088EA54BDBD32ULL,
		0x8FEFFEB9082DA177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69F8ABD9D624B8C2ULL,
		0x09EFB6F7E47D9D11ULL,
		0xBE88C2696FD86182ULL,
		0x65D64CE66895CAC5ULL,
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
	compute_modulo_25519(&k1);
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
		0xEFCEF6202B1911DDULL,
		0x3F4F51FD9E076C02ULL,
		0xED586DACFA5951DBULL,
		0xF25A053BC4DD91A0ULL,
		0x74BBA10CA0050AC0ULL,
		0xB019ACE2569D74C9ULL,
		0xD33F2D2AEE35F13DULL,
		0x30D0F16626CB0A8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43A8DDFFEBD8AB8DULL,
		0x631EFB967966C1EAULL,
		0x48B9220C565B2103ULL,
		0x315DDA65870122AEULL,
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
	compute_modulo_25519(&k1);
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
		0xDB537ED09CD9A647ULL,
		0xD451FB1B1B5FF283ULL,
		0xFD4E25050F260C52ULL,
		0x2A4D09B3E785507BULL,
		0x73E0DE5CFCD0F538ULL,
		0x1CADA89767D9D536ULL,
		0xB6D510FECFFAE901ULL,
		0xEFAF220C3FB4D0D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB4809E23DE11DCULL,
		0x1619019485B59899ULL,
		0x20EEAAD7EE64A27DULL,
		0x3E4C17855C5C5081ULL,
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
	compute_modulo_25519(&k1);
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
		0xD5FC8027D1ED5F73ULL,
		0x786E1397B6954E66ULL,
		0xFA8C254BA72DF7E7ULL,
		0x734750F2CCAB4264ULL,
		0xA00264D373B78CAFULL,
		0xA70F15199B7FA08EULL,
		0x8AA3A72B5ED0ECC1ULL,
		0xB1EFACA2ACD14E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9657778AFF2C455CULL,
		0x44AB3564CB872392ULL,
		0x8ED6F5BBBA311CA6ULL,
		0x5CDAF11873BCDDBFULL,
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
	compute_modulo_25519(&k1);
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
		0x05B4839C34288B3EULL,
		0x141F88996AE63199ULL,
		0xC6568CA46DECBEBDULL,
		0x5D3CAB8D7A6275FCULL,
		0xCE846C34D5C21DBEULL,
		0x29F8FF21D11BDF65ULL,
		0x3E9A0894ED4DFAF9ULL,
		0xA9C7A7686B783DB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5C9373EEF8F93BULL,
		0x4F15679E75095AB5ULL,
		0x1133D2BFA77FFFB9ULL,
		0x10DF850D6E3B9E72ULL,
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
	compute_modulo_25519(&k1);
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
		0x0BC3EF2D51A79466ULL,
		0xEE44A95CCC02D840ULL,
		0x54A6B81D529895B7ULL,
		0xB156AB727590F15DULL,
		0xB63E3289512BC027ULL,
		0x8080F624190E6658ULL,
		0x2509C14618EEE06CULL,
		0x15E4D7200292E475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18FF6F8F5E261AB5ULL,
		0x016932B88426096BULL,
		0xD4196885060DE5D3ULL,
		0x714E9A32D75EDAC0ULL,
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
	compute_modulo_25519(&k1);
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
		0x37A9D502AF9C2F9CULL,
		0x4A02E332CFF2C241ULL,
		0xCA3DA59379E7A295ULL,
		0x8A683A3D322E7FE1ULL,
		0x5A87E0060767EF38ULL,
		0xBFA0DBCCC7AB2CE8ULL,
		0x5D0AA60FC7A111E3ULL,
		0x6D4805C9EB681C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D515E7C909B45FULL,
		0xBBE38398735B6CBEULL,
		0x99D24BEB1BD04A63ULL,
		0x4319163623A2ACFBULL,
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
	compute_modulo_25519(&k1);
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
		0x2696C8AF5ADB1E4FULL,
		0x1BA95D9CCE6CC5AFULL,
		0x928F934B45FCFFDBULL,
		0xCCB7AFC7B841BBE9ULL,
		0xB2512A3AEAECD06FULL,
		0x3114E7C74BD95257ULL,
		0x1A12F5868FA06848ULL,
		0x5B084A253C44344EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA30D6E3A0210DDULL,
		0x64C3C53210AEFEB3ULL,
		0x7160054497CC7A92ULL,
		0x4FF2B14EAA617F81ULL,
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
	compute_modulo_25519(&k1);
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
		0x7B98C67F0CF99594ULL,
		0x54C0BDB5DD83E878ULL,
		0x0D2217AE8967CACAULL,
		0x6E2A9926375458ACULL,
		0xAE4B8D423ECA79F2ULL,
		0xD6DDA3B7DD621FF5ULL,
		0x85F5DFD6737B6416ULL,
		0xF57D6D57089F5FBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ACFBE545F07B4EBULL,
		0x39A70B00BA14A6F0ULL,
		0xEFA15183ADB8A62EULL,
		0x5EC8D4117EFC8EA7ULL,
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
	compute_modulo_25519(&k1);
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
		0xFD9C8D400372AD85ULL,
		0x9E39F9ED441F88F6ULL,
		0x7584E6183680A73CULL,
		0x448DB4DFCCCA4574ULL,
		0x9A436A1B5BBAE726ULL,
		0x65C77BF2A2408AA4ULL,
		0x7DE6DE59F3D541E9ULL,
		0xC8740304B2B7644EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE39E4D4FA131019DULL,
		0xB9D65FF159B41D65ULL,
		0x25C9E77268286FE1ULL,
		0x05C627925403291BULL,
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
	compute_modulo_25519(&k1);
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
		0x951756F258B4F807ULL,
		0x58E4928F6F97A6A2ULL,
		0xF813E7CBF3F07D42ULL,
		0xFEF78F822A6ABE2BULL,
		0xBF9132C956D0A0BDULL,
		0x8490562C6BE3A658ULL,
		0x75642326B8BFA823ULL,
		0x5341EE165F26A8B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A4E0D53BACD603ULL,
		0x06515D27736257CFULL,
		0x64F11F8B60637288ULL,
		0x5AC0E6D44A27C9B3ULL,
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
	compute_modulo_25519(&k1);
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
		0x0A098D6D2A02F543ULL,
		0x1C22685067893B1CULL,
		0xDEE16A94FC34F393ULL,
		0x9CE7BBA8221AA0AFULL,
		0x2C30AD14F0F793E7ULL,
		0xEA043DAFEDE828DEULL,
		0x1C8989E637539FB9ULL,
		0x57B4357716499BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99433E88EEC2EB8EULL,
		0xD8C3906DB7FF4C16ULL,
		0x1B4BE2C1329EA92BULL,
		0x21A7AB557107BF80ULL,
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
	compute_modulo_25519(&k1);
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
		0xFB3C7E87C28A0299ULL,
		0xC10F1FBBFDF6F543ULL,
		0xF4212D874799F8E8ULL,
		0x6AA4A254BB52F1DFULL,
		0xB3C10FFFF4C99AB8ULL,
		0xFD0D58CC4851224EULL,
		0xF3994EEB9BDE122CULL,
		0xE4AFE85B54738874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E4DE861876FEF5ULL,
		0x510A4E0EBA020CF2ULL,
		0x1CE2E4806A90AB96ULL,
		0x5CC11FE34479333CULL,
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
	compute_modulo_25519(&k1);
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
		0x7A0D218F7F6B5E66ULL,
		0x52E1DE7D82B771DEULL,
		0x369FA5F062E5369EULL,
		0x21266D6499EDA1C0ULL,
		0x0C3A49BD3FD2E38EULL,
		0x8B85C788A77B0CFBULL,
		0x16FB1DA3A59852C1ULL,
		0x69177235843A608DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB413A6F8B927C7ULL,
		0x08BD7CC65EFB5F22ULL,
		0x9FE60C3AF7817F59ULL,
		0x3AA161563A97F6B1ULL,
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
	compute_modulo_25519(&k1);
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
		0xC97FD5623B929F58ULL,
		0x1217143686C58076ULL,
		0x1483C257857A9E61ULL,
		0x55ECCF741DAC425FULL,
		0x634F3F277F020FA1ULL,
		0x2E9A5C233B29CDFEULL,
		0x1763D1DFDCEFE60EULL,
		0xF955972ED7B525C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8743353F15E0F6BCULL,
		0xFD00C1714EFA1439ULL,
		0x8D54E9925116C47BULL,
		0x58A14068228FDDA0ULL,
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
	compute_modulo_25519(&k1);
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
		0xC667311562BB7FA5ULL,
		0x50509E298CF4449EULL,
		0xEABE65B28CDB4B6DULL,
		0x60DE42287B01CE8EULL,
		0x7F7C4F6AC8FB49F5ULL,
		0x730D11A5841CE385ULL,
		0xD0780AAC4A37AA3EULL,
		0x45D3B8FB94A20752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2DAFAEF38087B92ULL,
		0x64413CBB293E0A6FULL,
		0xDC8FFB45911E90B2ULL,
		0x3E4BB7808B0EE4D9ULL,
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
	compute_modulo_25519(&k1);
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
		0x1B9563E636A338E4ULL,
		0xE3D1B3D11C450835ULL,
		0x5D2FC1BBBEB85A3AULL,
		0x61A569A542B14F10ULL,
		0x51CCC9A0E3E469E7ULL,
		0x126984290B22106AULL,
		0xFDC5D7BB72314CB5ULL,
		0x334B4B0D677F11DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FFB51C80A8AF24BULL,
		0x9F7B51E8C35377FDULL,
		0x088DC78EB209BD1BULL,
		0x7ED28DA29F8DF604ULL,
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
	compute_modulo_25519(&k1);
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
		0x4A417E8C3E23C7DFULL,
		0x953532B234D34E2DULL,
		0x0EF11806D32E4701ULL,
		0xDB198DA09D718DDAULL,
		0x2D78BF5A7A954C9FULL,
		0x981058481756624AULL,
		0xD4158352080F52EDULL,
		0xA88EFE59F7E26DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2DE5FA704D2B42ULL,
		0x27A24D65ABA5E530ULL,
		0x8A22963405749646ULL,
		0x60534EFB690DD477ULL,
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
	compute_modulo_25519(&k1);
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
		0x5CC23423E493B44DULL,
		0xAB2FA072F3F92A4FULL,
		0xB2E22C2E04CE57ACULL,
		0x1CC1E28F63A048AFULL,
		0xD939079C9D9073CFULL,
		0x7A8766360E374818ULL,
		0xE8D2DCCAB3FFBAB8ULL,
		0x27748477A83902C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B3955634804E5D8ULL,
		0xDB48CC79102DDDFFULL,
		0x422EF244BCC40F0EULL,
		0x780D8C525C16B25CULL,
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
	compute_modulo_25519(&k1);
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
		0xA5A75BB9EC4DAF34ULL,
		0xCF0377F614139724ULL,
		0xED60098960261997ULL,
		0x01B3D7CD232A4218ULL,
		0x57E7DB41B38DCD7EULL,
		0xC1EA2C3C0D42A320ULL,
		0x2548FDB77313D371ULL,
		0x9B112AC2B3177B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB211E77A935A3352ULL,
		0x97C608E00BF7CDF1ULL,
		0x7635B2C475177C7AULL,
		0x064030B3B8A68820ULL,
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
	compute_modulo_25519(&k1);
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
		0xD2B4DA9534B40FFFULL,
		0x4852205895565D7CULL,
		0xC9BA527B13D45BD6ULL,
		0x7AC6723CB220040CULL,
		0xC2E3B3DFFFADFEFAULL,
		0x37E8BB616C2BF0A0ULL,
		0xAE59E4C70AFFAC0EULL,
		0xE3651A3DC9A9DF67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0818DD52887EE27ULL,
		0x94DDF0CEA3DC1559ULL,
		0xAB124806B5C7E5F2ULL,
		0x3BC85768A1572D70ULL,
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
	compute_modulo_25519(&k1);
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
		0x0F4BDD4A3EEDD0A7ULL,
		0x1DB82BB479715E56ULL,
		0xA4D4E7EC4C6FFBC9ULL,
		0x47F4C46D1D9D3A8BULL,
		0x4A508352121B523AULL,
		0xD79EACFD6F24838AULL,
		0xAF6AE2A8CD38D3B6ULL,
		0x5D7795CA5128D61FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x173F5B78EEFC0757ULL,
		0x1F45D952F8DCE4DDULL,
		0xAEB28CFAC2DF68EDULL,
		0x27B5007529AD033FULL,
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
	compute_modulo_25519(&k1);
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
		0x5C9A91043D25B799ULL,
		0x319932E635062E4AULL,
		0x87C2929649EE5867ULL,
		0xAFA4B364BC0B0303ULL,
		0xCB18C45BF9913341ULL,
		0x4F8DACBE8DB6091FULL,
		0x9F781F7AB17A55E5ULL,
		0x21D11A5ECFBA8824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8247B6AB48B35410ULL,
		0x00A0D72F3E0B8902ULL,
		0x33973ECCA2171871ULL,
		0x34AE9D7791BB3873ULL,
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
	compute_modulo_25519(&k1);
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
		0x8A327DBA3536205AULL,
		0xF146BEEF79CE7A19ULL,
		0xC93C25B7F8EE9753ULL,
		0xC1395F2C4E56E7B0ULL,
		0x6A6F5A705BC336E1ULL,
		0xD19D5754F81E3276ULL,
		0x4A3EB9B8214B3C68ULL,
		0x16EE89462FD5630AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B9EA67D4304658ULL,
		0x0EA1B58C4E49F7ADULL,
		0xCE8BB70CEA198EE3ULL,
		0x28A1BF9768039B37ULL,
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
	compute_modulo_25519(&k1);
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
		0x51FAC4EC1A2BCFA4ULL,
		0x1259511F0F50AE5EULL,
		0x1535650BB523D039ULL,
		0xAF846BD131E52FA5ULL,
		0xF409D213F8F9FFE3ULL,
		0xB3DBDDE125F826E2ULL,
		0xA7D7370FE52B4693ULL,
		0xAB3DB1126BEEED58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B6FF3E30F47CF32ULL,
		0xC4FC408AB226740EULL,
		0xFF279167B9904A25ULL,
		0x1AACB48D375C6ACDULL,
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
	compute_modulo_25519(&k1);
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
		0x86CA41FD9C9D9695ULL,
		0x724BB8911C98EE4BULL,
		0xB2D532E2D14BB359ULL,
		0x53B39D3DF3F5BCB7ULL,
		0xA13C0F19D4E22443ULL,
		0x231DE2CFDAE67602ULL,
		0xB9D062B2C1AE4274ULL,
		0x92B0459CEF7C37B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75B47FD3362EFBCBULL,
		0xA8BB636B9ACE72AFULL,
		0x47C3D96B91299096ULL,
		0x19DDF289806600F3ULL,
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
	compute_modulo_25519(&k1);
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
		0x6E004936A7700D1FULL,
		0xA15E8B496815AAFAULL,
		0x7DBCA1DB53E47F4BULL,
		0xE874FAA31D86E819ULL,
		0x212FCF433E05D75AULL,
		0x4A571B2C6BF206CCULL,
		0x84A49AB549628D99ULL,
		0xA0D537463A308DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B190D31DC4E081EULL,
		0xAA4C93E16E02AD47ULL,
		0x2E2B98C43885840CULL,
		0x481B2F0FC0BBF95BULL,
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
	compute_modulo_25519(&k1);
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
		0x138E8D278BDA84B6ULL,
		0x0DC53430D9456F25ULL,
		0xA0055FA063695190ULL,
		0xE52E0AB93937CBC3ULL,
		0x76904BB2C8049FD1ULL,
		0xA01D50C63B2B1286ULL,
		0x7D8E9D4A33DD440CULL,
		0x8C38654555516379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF9C9B13C8A40EDULL,
		0xD21F319DA1AA2F1AULL,
		0x4330B8A416416B6FULL,
		0x358D1303E34C8FCCULL,
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
	compute_modulo_25519(&k1);
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
		0xD87B119F86328DDAULL,
		0x68D41FC04DFBB3F0ULL,
		0xF983F197DDC43BF9ULL,
		0xD22875DA594F917DULL,
		0x0F09855409D26DFAULL,
		0x0A64719CA36D6D0BULL,
		0xB55F06569DDE7563ULL,
		0x8B02092A23F03CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13E4DC18FB6EE414ULL,
		0xF3BCFD009039E395ULL,
		0xE59EE2734CC9A8ACULL,
		0x7475D21BAEF8936CULL,
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
	compute_modulo_25519(&k1);
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
		0x8E79F2513B4FF723ULL,
		0xBA6C271DE0441185ULL,
		0x517E16526E4E4557ULL,
		0x9DA3E290733F93A4ULL,
		0xE6AC30205297C6AFULL,
		0x41E6F251EC42608EULL,
		0xBDDE9A8F74B6FB38ULL,
		0x7048D7FC7094A004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC09171D7DD777A3ULL,
		0x82B41F46F21E66BBULL,
		0x8089079DC1778FB1ULL,
		0x4873F209294F5458ULL,
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
	compute_modulo_25519(&k1);
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
		0xFFA5EFFE09FD42DAULL,
		0x66D68C228B12A02BULL,
		0x1DD3FCBE1AC1916BULL,
		0xB70E4E13A6FF31BDULL,
		0xE013A1645DF8A80EULL,
		0xD28A08BFA1B07932ULL,
		0x442DE82A565C56DBULL,
		0x56471397042F2E97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428FE4E3FCE636EFULL,
		0xA753D8948B449DB9ULL,
		0x3CA47306EC76760CULL,
		0x059B367E46001C31ULL,
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
	compute_modulo_25519(&k1);
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
		0x445BE4E0DFEE1A88ULL,
		0x5262AE76E89A0104ULL,
		0x404A2C22F638D43CULL,
		0x3CF68ADF7334F2A9ULL,
		0xC2324B726C6C67CEULL,
		0x0FDC2DD4B77CB845ULL,
		0xE4B5864D0A3B0640ULL,
		0x20FB8A5450DD19C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17D317DCF80583DAULL,
		0xAD117C0A251D5B5FULL,
		0x333C1B927AFBC1BEULL,
		0x224D13637406C609ULL,
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
	compute_modulo_25519(&k1);
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
		0x1BAC9D4273E22631ULL,
		0xCC15956369A4E3DDULL,
		0xEF8630FBF66ED4C6ULL,
		0xE874B1D2431D7DCEULL,
		0x9D6FC0FFB2E94852ULL,
		0x88942094554FBF0CULL,
		0x2EA2AA52D634A3DCULL,
		0x0592078B0B30FEE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4343370282E296ULL,
		0x12126B68137B3FBCULL,
		0xDBAB7947C23F2783ULL,
		0x3C21D075EC6353F9ULL,
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
	compute_modulo_25519(&k1);
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
		0x81BD2C8921D9364DULL,
		0xD3EBD8123C7EE9E9ULL,
		0x30603105B4940761ULL,
		0xA432203862B20E5BULL,
		0xAA2838BC802C6E27ULL,
		0x500D47EEB1709BF5ULL,
		0x3439F520619338A2ULL,
		0x8658DFFCA3506632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3B5988428719322ULL,
		0xB5E4858093361060ULL,
		0xF0FA93D4306E6F79ULL,
		0x15635FB8A0A139CEULL,
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
	compute_modulo_25519(&k1);
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
		0xA825FF1EE88973E5ULL,
		0xE2E2FF784EDAFFF5ULL,
		0xBC8DE66F0BFF0BBDULL,
		0x519CCBFF51AE1C95ULL,
		0x101227F5B0F38E7FULL,
		0x420AF638BC096DB8ULL,
		0xC4E52C47275BACCCULL,
		0xB213A0436C132A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD7ED972CB09EAEULL,
		0xB0838BE438414948ULL,
		0xF69278FEE39AB20FULL,
		0x408696015C865E0AULL,
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
	compute_modulo_25519(&k1);
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
		0x01950EF240CF1B42ULL,
		0xF303BAD729F30199ULL,
		0xD3C693BE01EC8A1FULL,
		0x04BC369C32A1FE71ULL,
		0x84505B032A4171FBULL,
		0xB624D84275B5787FULL,
		0x36082912D0BFADDDULL,
		0x9FDEF83BCBE69519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA582916A86860A01ULL,
		0xFC7BD4B4A2E2E486ULL,
		0xD8FCAC88FE605908ULL,
		0x3FD50F7C76DC202FULL,
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
	compute_modulo_25519(&k1);
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
		0x22795D915A226AD0ULL,
		0x2552AF3FF44849D7ULL,
		0xD73317D0608D8923ULL,
		0xD983E7BF9D6E188EULL,
		0x3BF4468E0A2F21FEULL,
		0xE76F5D62609E51D1ULL,
		0x8A3999B5EBB1F1B1ULL,
		0x19F3FACF9E77C3C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08BBD6A6DD21772FULL,
		0x7FDA8BDA4BC86EE6ULL,
		0x5BBFE8D15CF7698BULL,
		0x33BB229123352795ULL,
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
	compute_modulo_25519(&k1);
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
		0x177AE4DC4BA92ABDULL,
		0x589724B4C1C09ECCULL,
		0xE6113996210BDF67ULL,
		0x1714DF42A34CB65CULL,
		0x62DBE3A51D256724ULL,
		0xB881DC12ECA50AA5ULL,
		0xE87A7F530C20CCDEULL,
		0xCE9AF5A01DE000ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41EAF5E9F367E9CULL,
		0xBBDDCF83E2403358ULL,
		0x68401FE9EDEA4876ULL,
		0x42155507128CD987ULL,
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
	compute_modulo_25519(&k1);
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
		0x12B924D959279945ULL,
		0x02F0419EA78B3A6EULL,
		0x628D3F887B011937ULL,
		0x7369A54D0DE4D619ULL,
		0x2BD0BAB7A06CFDEFULL,
		0x048917E88A43350CULL,
		0x274EC19361FB1940ULL,
		0x9406FF485BF334C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B4DC1B29554E03ULL,
		0xAF49CE232D851A3CULL,
		0x383DFB690646D8B7ULL,
		0x6C738A0AB3FEABF5ULL,
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
	compute_modulo_25519(&k1);
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
		0x84B6BF19377A47E3ULL,
		0x48275347BC8B313CULL,
		0xAB6AD9BADC168941ULL,
		0x41F4C67ABC1D397CULL,
		0x3E62E5CF1E3A6B15ULL,
		0x738BFCD719648C2DULL,
		0x3CD5C3303C7B2B77ULL,
		0x327C97CD8810762DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC764DBD7B4262E1EULL,
		0x6EEEDB358177FFF3ULL,
		0xB325D2E3D65EFCFCULL,
		0x40734EFCEE8EC433ULL,
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
	compute_modulo_25519(&k1);
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
		0x3A1232A376E16357ULL,
		0xC2C807DECECCF414ULL,
		0x3DA1BF55C1C0753BULL,
		0x52CEFE2176D8EB3EULL,
		0x429116EBB29491C9ULL,
		0x8D1932C5D6F6D938ULL,
		0xCB4AC2BD4884D5D2ULL,
		0x393A2D77F3411F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B9B999FF8EF0870ULL,
		0xB485913CB771326EULL,
		0x6ABAA76E8578327CULL,
		0x5171BDEF92838EDCULL,
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
	compute_modulo_25519(&k1);
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
		0xCEBD8AAD6C9605BBULL,
		0xC5300148340901FFULL,
		0x41E9994377EE8C94ULL,
		0xD93A1B02577C3E47ULL,
		0xEB46FC76CFF40C0EULL,
		0x332ED1A4906FAD37ULL,
		0xED10D15CA43F4435ULL,
		0x3439B07193B65C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB4704504ACFD112ULL,
		0x5E231FB5A49CB84CULL,
		0x7268AD03D952AC7AULL,
		0x19CA4BDE448DF32EULL,
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
	compute_modulo_25519(&k1);
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
		0xAB6BBDD61BCB5F3EULL,
		0xB808B10BA923DE8CULL,
		0x1A774F341E0755F4ULL,
		0xEFFFEFD66D2A4527ULL,
		0x894C521558EB3E2DULL,
		0xFF0285FD5659FE2BULL,
		0x9D0CB151FE903B33ULL,
		0x81EF3C7560886A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CBFED014EB69CE4ULL,
		0x926894A67A7F9903ULL,
		0x6A59A15FE7701FACULL,
		0x3982E942C16A0B0AULL,
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
	compute_modulo_25519(&k1);
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
		0x280963C0AA815C99ULL,
		0x6AE8C02974D29591ULL,
		0x7EE65A9FED7B0D00ULL,
		0xFECB91D844A8764DULL,
		0xE6582BAC2C94B6EBULL,
		0x14795F41EE3AF119ULL,
		0x9668E1FB1B2D4059ULL,
		0xE203EA1B9C2CB2A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x591FDF4F4894889AULL,
		0x74ECE3F2D1925F69ULL,
		0xD277E5E5F6329A39ULL,
		0x0B6051F1734AFB07ULL,
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
	compute_modulo_25519(&k1);
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
		0x1DB04BA4CAA024FEULL,
		0x3A1ABFA2F3FC7A7EULL,
		0x29FCD2CC87CE3F37ULL,
		0x576A843E898C9DA7ULL,
		0xCC23EA8ED89856A6ULL,
		0x9062DD83A177218FULL,
		0x62652FEF9F338EE7ULL,
		0xB15184AC94544464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B051CD8F13D0591ULL,
		0xA8C7A12CEBAB75D6ULL,
		0xC501F05E29757596ULL,
		0x298435DC8E0EC48DULL,
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
	compute_modulo_25519(&k1);
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
		0x62DCD7FC91FB092BULL,
		0x9C19384AA715EED3ULL,
		0xC7556BC283605BA0ULL,
		0x23110E465035AB70ULL,
		0x4FB4E6C120D0C697ULL,
		0x38731745BB17D835ULL,
		0xC5F48B9B73999BB7ULL,
		0x69F0868EFF161A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B718A770F885E2ULL,
		0xFD2EACA46CA006BDULL,
		0x29A224D5AC2D78D2ULL,
		0x5CC507802D7D9770ULL,
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
	compute_modulo_25519(&k1);
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
		0x4441BFB1C306AFA4ULL,
		0xB7889C30EAE79DA1ULL,
		0x6417A3445EECFAAFULL,
		0x6D80671EB3947C76ULL,
		0x4C56034575D7BCB8ULL,
		0x16132CBCD8B4A8A3ULL,
		0x04A51650EE96E500ULL,
		0x17187042D4F4D576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99063C01410CB379ULL,
		0xFE61403915B8A5DEULL,
		0x1498F347C952F8B2ULL,
		0x5B21110A4FEC2BFBULL,
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
	compute_modulo_25519(&k1);
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
		0xEBD0B81B6BE70646ULL,
		0xBBBCE05DE6F96A53ULL,
		0x49D0A27EE142D20CULL,
		0x91F6F050CFF86209ULL,
		0x42A81B4BE7D9E383ULL,
		0x57AC02EA24E31E45ULL,
		0x285E82FA3180E9C3ULL,
		0x680BCD61D03C1AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0C4C55FD63ECE18ULL,
		0xBF454F1F60AFE89BULL,
		0x47D813A23A65850BULL,
		0x03B76CD5B8E45809ULL,
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
	compute_modulo_25519(&k1);
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
		0x834E2BC47B194372ULL,
		0xADDE12FED22E1D10ULL,
		0x16F11615A5C9FD99ULL,
		0xF93DEAA0482EAF7CULL,
		0xE234B9206556769CULL,
		0x600641CC0018BB56ULL,
		0x113F2F0D77C6C3D9ULL,
		0x2AEC057D1E2C9DFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1721A69385EEDFA4ULL,
		0xEECBD746D5D9EBF6ULL,
		0xA65212156D4B0FDDULL,
		0x5846BB32C2CE230CULL,
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
	compute_modulo_25519(&k1);
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
		0x3923900BE59BD003ULL,
		0x0C52453A9F3CC4D3ULL,
		0x4AD59A01EDD05D8DULL,
		0x11BCB4CF568D666BULL,
		0x3055DDD5281D4A9EULL,
		0xF0B78540F9E4724EULL,
		0x421FA364172A886BULL,
		0x98F345A67650F1F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E27DAFD9F4E6CEULL,
		0xC7900CDFB725BC6EULL,
		0x1B87DADD5E209D92ULL,
		0x45D90B84E69150D3ULL,
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
	compute_modulo_25519(&k1);
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
		0x15C0DB2635D0629AULL,
		0x677F26485DC67E58ULL,
		0xA9FF22EEED1289DDULL,
		0x81B7C7492BA7668AULL,
		0x49A34D6F4E0F6693ULL,
		0x8C37F00E4EC8887AULL,
		0x74948FFB2EA3B5B9ULL,
		0x79BF35A6AC56AE28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03FE59ABCC199F2BULL,
		0x37CCC8680F8AC07FULL,
		0xF80C8237D95F8368ULL,
		0x1419BE06C085408BULL,
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
	compute_modulo_25519(&k1);
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
		0xA173A49D69BF9170ULL,
		0xAC89733B0ECA14FDULL,
		0xC41445B5BE0B4707ULL,
		0xB037486D805586F3ULL,
		0x68BFDD44C6A8C1FFULL,
		0x2CB1B0A503EB287AULL,
		0xFE3698B5BC89993EULL,
		0x80382206736A5A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DEE7CD2E6CC602FULL,
		0x4EE9ABB9A3B21729ULL,
		0x802EF0AFBA780642ULL,
		0x388C5562A21EEEF9ULL,
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
	compute_modulo_25519(&k1);
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
		0xDDE831DEC6E87F38ULL,
		0x0899E6B0FEF90D9AULL,
		0xF7A674318909E3DEULL,
		0xA41E444D5675DA20ULL,
		0x66C837001DF1DC87ULL,
		0xA7445D7FBE14C9AFULL,
		0x6EA66C3408A5CE6DULL,
		0x7530ECE51E036C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA05BE338CF3DEEULL,
		0xDCBFC7A7360EFDA4ULL,
		0x645A83EAD1A68824ULL,
		0x09616E4FCAF7EAF3ULL,
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
	compute_modulo_25519(&k1);
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
		0xC347468EA9547CCBULL,
		0x73A7B1C28EE17D68ULL,
		0x854850D6C88DE725ULL,
		0x55984E1B192DDE8BULL,
		0x93B49E0CF97823C4ULL,
		0x11E0ED397200A005ULL,
		0xF2B636CD77323C58ULL,
		0x4879307B84C8BC33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB016BC7BB129CD85ULL,
		0x1B0AE8497AF93E3CULL,
		0x8C5473567A02DC38ULL,
		0x17958070CEF9CE41ULL,
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
	compute_modulo_25519(&k1);
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
		0xCF85C9909B5F4B94ULL,
		0x4ADD39FC70F43A78ULL,
		0xAC35150D78C268D9ULL,
		0x514FBC3D4FF7F917ULL,
		0x89014040E9BD7A01ULL,
		0x73DEA44B7D94FF8DULL,
		0x5D63F6601944E68EULL,
		0x345401408333A448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B553334D7F68EAULL,
		0x7DE99D311512297BULL,
		0x890BA75138FCA1FEULL,
		0x15C7EBD0C9A25BD5ULL,
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
	compute_modulo_25519(&k1);
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
		0x8F68CED80557F632ULL,
		0x63788CC3C1766AFFULL,
		0xF77EF3FC5339AFFDULL,
		0xD8DE1F1EA95C06FCULL,
		0xF88AE122935997C6ULL,
		0x9F7F4939A8DD1EABULL,
		0xB11221E93A79D995ULL,
		0x20C9B4E3EDE9C573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740639F9E4A47E67ULL,
		0x105D6B52D248F886ULL,
		0x402FFC9B014FFC33ULL,
		0x36CEF8F3FA0F5629ULL,
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
	compute_modulo_25519(&k1);
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
		0x6E53A6E34627489FULL,
		0xA82BEFEA00C66B71ULL,
		0x945FF059B4F28E24ULL,
		0xB111DBAC4C78DD6DULL,
		0xA2EBD591EA75FD7FULL,
		0xAC9A478F0B732D9AULL,
		0xE42DCFD858A45DCDULL,
		0xA66393FBF7B1F16CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D555A8C13AAED2FULL,
		0x47128F25B3DF3065ULL,
		0x732CCA76DD587AACULL,
		0x63D9D31310E2B397ULL,
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
	compute_modulo_25519(&k1);
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
		0xE3C718C04DB9F035ULL,
		0x8484ACDE39610E03ULL,
		0xE5DC7D78F38D70EAULL,
		0x66C30D7BE7428915ULL,
		0x1B9B5442DA994AA0ULL,
		0x28924D09F1E8FED2ULL,
		0x569B8E5C47FC4D3AULL,
		0x3A7AABDFDA0E97C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD59AACC07B054BULL,
		0x8A3C1C5821F6E133ULL,
		0xC0F39F2BA300E78CULL,
		0x14F890B6456D0FA2ULL,
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
	compute_modulo_25519(&k1);
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
		0x1285501CFB80A2A0ULL,
		0x72D9BAE6D1574955ULL,
		0xAB8F7D8BD1B3A0C5ULL,
		0xF61596CF1A5B1422ULL,
		0xE5161FF0291ECCE1ULL,
		0x7E1900D5EE5CB5D0ULL,
		0x2E8E09577201737DULL,
		0x648250ABA23E83DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13CE0DC316130E53ULL,
		0x2A8FDAA8331A4657ULL,
		0x94A4E086BDEAC566ULL,
		0x616D90492FA2A71DULL,
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
	compute_modulo_25519(&k1);
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
		0xE9EA9A16EC9EA204ULL,
		0x06CCBEFE38667B8EULL,
		0xA73EDB9BA01B274EULL,
		0xB70D073AB8C1067AULL,
		0xCAEA109258D5F451ULL,
		0xEF292E718936AE0BULL,
		0xA1E0494E8F299047ULL,
		0xCFD81E294AF0A397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08A90FD01C60EAB7ULL,
		0x86E9A3D89684514FULL,
		0xAE89BD44E04691FBULL,
		0x1121815BD8794EFCULL,
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
	compute_modulo_25519(&k1);
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
		0x7C694F78AA488E71ULL,
		0x8F60A91DF35A82C9ULL,
		0x971A6528CD3DEEC2ULL,
		0xA8DB9435E5768647ULL,
		0x4E743FEF6F6698FBULL,
		0xEED8034EDB3E97F5ULL,
		0xD6922A09701D346EULL,
		0xE4120FC9C5FA0984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21AACD03338348D2ULL,
		0x037126D27EA51133ULL,
		0x70CCA28F7193B73AULL,
		0x0389EC294893EFFFULL,
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
	compute_modulo_25519(&k1);
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
		0x9C30634B2E08576AULL,
		0x0A8F3E1296EEEF7FULL,
		0xF366D974A6477E04ULL,
		0xFE913A2A01FA5683ULL,
		0xB37AA1D9E741F7D4ULL,
		0x4792BB8C550F6B80ULL,
		0x77EC27E3FCB8D4D4ULL,
		0xC1C4A699E89B79FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x406469A381D32543ULL,
		0xAA5714E73738E49AULL,
		0xC074C54C29B71586ULL,
		0x41C1F502890E71D7ULL,
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
	compute_modulo_25519(&k1);
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
		0x1694D4F9A00F17BCULL,
		0xB6CC7CB35075AFA1ULL,
		0xBCA455E0E17B91FCULL,
		0xD6BC550C868F2252ULL,
		0x7AB799A2C5A94F3FULL,
		0xD2A018B55028C8F5ULL,
		0x028D124C29D4B383ULL,
		0x74BFBB5920FE0ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD5A322F730DDC2ULL,
		0xFA90279D36838411ULL,
		0x1D950D2F170E378DULL,
		0x2B3224476C44BC9BULL,
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
	compute_modulo_25519(&k1);
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
		0xCB414BAAEF0E5C48ULL,
		0xCCAC58B6EC670B12ULL,
		0x21FB0F8CE6E8065AULL,
		0xD22632978E844997ULL,
		0xD2D9E0F9C9FF2903ULL,
		0xC6A14FD4A2BC0544ULL,
		0xCD5C993852DFA3C3ULL,
		0xDEA7DB1820B9FCA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1798B0BEEAEE77B3ULL,
		0x489E3247144FD34AULL,
		0x9DB9CDE9341A556AULL,
		0x5F10B82C6A1FCA0DULL,
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
	compute_modulo_25519(&k1);
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
		0x8C37C29AC6BB83AAULL,
		0x6A8DD6083F269E92ULL,
		0x46C37D756E62AA6CULL,
		0x3CBFC9CB8BB7589BULL,
		0xECB7AE9A982C68B1ULL,
		0xCA828E36B19CEB0EULL,
		0x5AB267DAF2BFA102ULL,
		0x87EC48027973B1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7BAD8D5D5310E8ULL,
		0x79EEF2269C7182C9ULL,
		0xBD3EE7F576D490D6ULL,
		0x69D27A2992E3BC32ULL,
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
	compute_modulo_25519(&k1);
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
		0x4E115306BB666D95ULL,
		0x46BC16A0AB62C057ULL,
		0x8B20CB7287BADF75ULL,
		0x92C061D148FE07F9ULL,
		0x222AAC74E23BEFBAULL,
		0xCD93DC91F0BA90D2ULL,
		0x0E54C7AC93F2DB59ULL,
		0x915304217C1A82BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6066EC60504C0675ULL,
		0xCAAED44A67143F88ULL,
		0xABB66F107DC76EC9ULL,
		0x2512FEC9B4ED7055ULL,
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
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}