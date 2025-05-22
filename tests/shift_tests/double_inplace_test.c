#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6079785E63393B69ULL,
		0x3C959906F179C5A5ULL,
		0xC4F95861F3F36CE8ULL,
		0xCA64613E2B6501DDULL,
		0xE4C48DCF9764AC18ULL,
		0x7C5A3F1EB7F70AA4ULL,
		0x576BFBC2C3007F7CULL,
		0x23446BB2DBACB361ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xC0F2F0BCC67276D2ULL,
		0x792B320DE2F38B4AULL,
		0x89F2B0C3E7E6D9D0ULL,
		0x94C8C27C56CA03BBULL,
		0xC9891B9F2EC95831ULL,
		0xF8B47E3D6FEE1549ULL,
		0xAED7F7858600FEF8ULL,
		0x4688D765B75966C2ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBC180DA6D39AA865ULL,
		0x14677ADA4C72F56CULL,
		0xF7FE4F67EFD8AE5DULL,
		0xE543BE08F84EDE72ULL,
		0x535BE88D3B374764ULL,
		0x55286AECB722E866ULL,
		0x8065703B0C332517ULL,
		0x17A007F3E476CC34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78301B4DA73550CAULL,
		0x28CEF5B498E5EAD9ULL,
		0xEFFC9ECFDFB15CBAULL,
		0xCA877C11F09DBCE5ULL,
		0xA6B7D11A766E8EC9ULL,
		0xAA50D5D96E45D0CCULL,
		0x00CAE07618664A2EULL,
		0x2F400FE7C8ED9869ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2C4B9A816DB6ABDFULL,
		0xE1FF9272CE8A46D9ULL,
		0x410AA746882D1F2AULL,
		0xE4A7EC8951D758ABULL,
		0x429B9137360AEFD5ULL,
		0xA68860CFA8E5DCE7ULL,
		0x6F467295E43265F4ULL,
		0x0B89409F0771D583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58973502DB6D57BEULL,
		0xC3FF24E59D148DB2ULL,
		0x82154E8D105A3E55ULL,
		0xC94FD912A3AEB156ULL,
		0x8537226E6C15DFABULL,
		0x4D10C19F51CBB9CEULL,
		0xDE8CE52BC864CBE9ULL,
		0x1712813E0EE3AB06ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4F11963D747027EEULL,
		0x6FB36B29052E1B4BULL,
		0xF496C584E46C458BULL,
		0x52067750293E200BULL,
		0x732EBAA910EBEDF2ULL,
		0x3F35A21E0C275090ULL,
		0xBD49A7D84A1CE78CULL,
		0x0CF8CFED087B2170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E232C7AE8E04FDCULL,
		0xDF66D6520A5C3696ULL,
		0xE92D8B09C8D88B16ULL,
		0xA40CEEA0527C4017ULL,
		0xE65D755221D7DBE4ULL,
		0x7E6B443C184EA120ULL,
		0x7A934FB09439CF18ULL,
		0x19F19FDA10F642E1ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x168598FF9BFAA9FEULL,
		0x86240B9FC23BDC63ULL,
		0xF79C614CB0F93832ULL,
		0xE062652DB2E6E1E6ULL,
		0x230FD27D00AFED85ULL,
		0x23487CC005F870E2ULL,
		0x813FA9430CEB3FADULL,
		0x34B6A0058B569028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0B31FF37F553FCULL,
		0x0C48173F8477B8C6ULL,
		0xEF38C29961F27065ULL,
		0xC0C4CA5B65CDC3CDULL,
		0x461FA4FA015FDB0BULL,
		0x4690F9800BF0E1C4ULL,
		0x027F528619D67F5AULL,
		0x696D400B16AD2051ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2FB430333B61EA29ULL,
		0x8AD636DB51777968ULL,
		0x85A2DAC8D977B478ULL,
		0xE6AA07C2D41B028EULL,
		0x4526FAF51D72CF5EULL,
		0xD095F904F4AF6438ULL,
		0x444F9E269E6BE9F4ULL,
		0x11DDAD13E3A67E7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F68606676C3D452ULL,
		0x15AC6DB6A2EEF2D0ULL,
		0x0B45B591B2EF68F1ULL,
		0xCD540F85A836051DULL,
		0x8A4DF5EA3AE59EBDULL,
		0xA12BF209E95EC870ULL,
		0x889F3C4D3CD7D3E9ULL,
		0x23BB5A27C74CFCFAULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x10FE979850DE6266ULL,
		0x890E4584B91E8786ULL,
		0xCA4703A9D872EA8FULL,
		0x68A69C6A25040A5AULL,
		0x91D3DFC19B23A309ULL,
		0xFACF38E431C15CDEULL,
		0x3E061C30EC3DC782ULL,
		0x313E0DC4B2D8627AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FD2F30A1BCC4CCULL,
		0x121C8B09723D0F0CULL,
		0x948E0753B0E5D51FULL,
		0xD14D38D44A0814B5ULL,
		0x23A7BF8336474612ULL,
		0xF59E71C86382B9BDULL,
		0x7C0C3861D87B8F05ULL,
		0x627C1B8965B0C4F4ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x00C39BC3B17C206BULL,
		0x0A39E1701D3B4FF4ULL,
		0x1B8809CF0426E19EULL,
		0x51B21BFD17915AC3ULL,
		0x82A3EF5FAFABB077ULL,
		0x28A31E53EE886686ULL,
		0x3D97862A07980B41ULL,
		0x064A94C4534A27C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0187378762F840D6ULL,
		0x1473C2E03A769FE8ULL,
		0x3710139E084DC33CULL,
		0xA36437FA2F22B586ULL,
		0x0547DEBF5F5760EEULL,
		0x51463CA7DD10CD0DULL,
		0x7B2F0C540F301682ULL,
		0x0C952988A6944F82ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x83B688D99AE3D66CULL,
		0xBC9E681C156BF9F7ULL,
		0x51F2AE87CDD35D63ULL,
		0x40650340E37AEE6AULL,
		0xDED0E8EF1E0FB0A0ULL,
		0x3F26AFAABEDE6AF3ULL,
		0x363ED895BBA15C36ULL,
		0x1EE0B7C7EE553335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x076D11B335C7ACD8ULL,
		0x793CD0382AD7F3EFULL,
		0xA3E55D0F9BA6BAC7ULL,
		0x80CA0681C6F5DCD4ULL,
		0xBDA1D1DE3C1F6140ULL,
		0x7E4D5F557DBCD5E7ULL,
		0x6C7DB12B7742B86CULL,
		0x3DC16F8FDCAA666AULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8F59553579D09F0AULL,
		0x5B484C323F40C78DULL,
		0xB5B12124C80FDF21ULL,
		0x05C359D898C26BFAULL,
		0x38FA130FA450A81DULL,
		0xB8EBB6AC4FADE0B6ULL,
		0x2D31287991BA54C2ULL,
		0x210186C980171D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EB2AA6AF3A13E14ULL,
		0xB69098647E818F1BULL,
		0x6B624249901FBE42ULL,
		0x0B86B3B13184D7F5ULL,
		0x71F4261F48A1503AULL,
		0x71D76D589F5BC16CULL,
		0x5A6250F32374A985ULL,
		0x42030D93002E3A98ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x15AF1052010ABA39ULL,
		0x3D2634DB63322FA7ULL,
		0x4FACFD0CB61C66E7ULL,
		0xCF34C595956193D7ULL,
		0x3E1A6EFDFB8D82CCULL,
		0x45507FBA4FBAF636ULL,
		0xD63819B5A3621701ULL,
		0x1A772DD4ED7EB615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5E20A402157472ULL,
		0x7A4C69B6C6645F4EULL,
		0x9F59FA196C38CDCEULL,
		0x9E698B2B2AC327AEULL,
		0x7C34DDFBF71B0599ULL,
		0x8AA0FF749F75EC6CULL,
		0xAC70336B46C42E02ULL,
		0x34EE5BA9DAFD6C2BULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD4AB66D2B39A6370ULL,
		0x60BCF04B873EC16BULL,
		0x78DAAB9AA30CECC6ULL,
		0x207C3D28696AA5C4ULL,
		0xF04741E036CBAD37ULL,
		0x11B083108E535E74ULL,
		0x5887BA2B60F3FE5BULL,
		0x1137EF1BC40F99F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA956CDA56734C6E0ULL,
		0xC179E0970E7D82D7ULL,
		0xF1B557354619D98CULL,
		0x40F87A50D2D54B88ULL,
		0xE08E83C06D975A6EULL,
		0x236106211CA6BCE9ULL,
		0xB10F7456C1E7FCB6ULL,
		0x226FDE37881F33E2ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFE6BA5093EE06D79ULL,
		0x6CCB6ADD89909476ULL,
		0xFBFB4B5D71D34F9EULL,
		0x14D59406A90331B7ULL,
		0x4B60C30EADC79B15ULL,
		0x83833D7E5F0CD9F7ULL,
		0x73C9FACC25292CCAULL,
		0x2AC4C3938E746AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD74A127DC0DAF2ULL,
		0xD996D5BB132128EDULL,
		0xF7F696BAE3A69F3CULL,
		0x29AB280D5206636FULL,
		0x96C1861D5B8F362AULL,
		0x07067AFCBE19B3EEULL,
		0xE793F5984A525995ULL,
		0x558987271CE8D556ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB976A3B2D7B45EFDULL,
		0xE20577A4F0B73FE9ULL,
		0x0E1D571CEC6542E5ULL,
		0xA2C591AECCB87AECULL,
		0x424B55B5D82D5B65ULL,
		0x64D8F610F707B7A0ULL,
		0xE9502996E21D3E07ULL,
		0x19FC5E255D118AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72ED4765AF68BDFAULL,
		0xC40AEF49E16E7FD3ULL,
		0x1C3AAE39D8CA85CBULL,
		0x458B235D9970F5D8ULL,
		0x8496AB6BB05AB6CBULL,
		0xC9B1EC21EE0F6F40ULL,
		0xD2A0532DC43A7C0EULL,
		0x33F8BC4ABA2315CFULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1BA18B0ABBF390FBULL,
		0x9E2A4C967BB72BF3ULL,
		0x284EAB807F4B0F5EULL,
		0xC31E55DFC1D52F70ULL,
		0x6BD2575AB343157AULL,
		0xBFCB0B3824311A26ULL,
		0x1CFEA23CB24A2A15ULL,
		0x3E64DD279DBD9398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3743161577E721F6ULL,
		0x3C54992CF76E57E6ULL,
		0x509D5700FE961EBDULL,
		0x863CABBF83AA5EE0ULL,
		0xD7A4AEB566862AF5ULL,
		0x7F9616704862344CULL,
		0x39FD44796494542BULL,
		0x7CC9BA4F3B7B2730ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x92964A7259893EA5ULL,
		0x3A1299C6DB6A0C96ULL,
		0x09FBCC9FF7E2F059ULL,
		0x710470E48F89CF25ULL,
		0x4A04B67A5E9BDC21ULL,
		0x873FD31BED468778ULL,
		0xE7C1A9E246F2F2D3ULL,
		0x0A6F09E8AF53C411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252C94E4B3127D4AULL,
		0x7425338DB6D4192DULL,
		0x13F7993FEFC5E0B2ULL,
		0xE208E1C91F139E4AULL,
		0x94096CF4BD37B842ULL,
		0x0E7FA637DA8D0EF0ULL,
		0xCF8353C48DE5E5A7ULL,
		0x14DE13D15EA78823ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1135F0CB3284D0F1ULL,
		0x94A88470E4EB4BB2ULL,
		0x9EF61A6DB6F3E0C3ULL,
		0x2283C1599E8663B3ULL,
		0x825BA784B21F7AA4ULL,
		0x2BEA1DB31B100F57ULL,
		0x46BBFC143C75D573ULL,
		0x29089520A1F79E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x226BE1966509A1E2ULL,
		0x295108E1C9D69764ULL,
		0x3DEC34DB6DE7C187ULL,
		0x450782B33D0CC767ULL,
		0x04B74F09643EF548ULL,
		0x57D43B6636201EAFULL,
		0x8D77F82878EBAAE6ULL,
		0x52112A4143EF3D14ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6CA88CF93854B195ULL,
		0x268429A89FB9DD6BULL,
		0xCD08F32DA89822CBULL,
		0x38101CA34909F606ULL,
		0x4E393A4250DB7B14ULL,
		0xD197DCCC7569F0B2ULL,
		0xF9E7243B4F36FAA5ULL,
		0x2A9E0C595A20E6A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD95119F270A9632AULL,
		0x4D0853513F73BAD6ULL,
		0x9A11E65B51304596ULL,
		0x702039469213EC0DULL,
		0x9C727484A1B6F628ULL,
		0xA32FB998EAD3E164ULL,
		0xF3CE48769E6DF54BULL,
		0x553C18B2B441CD4BULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD1AB1C4E9BE4ABFEULL,
		0xDE7839A8051C8E33ULL,
		0xE54C6ABE5FBBF658ULL,
		0x5B25D4A0B49E9E9BULL,
		0xBA78F3A90B777B2BULL,
		0x4764CBFFCE1002CDULL,
		0x0D5A16BA74DA5CD1ULL,
		0x1E8EAEE9D55C455BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA356389D37C957FCULL,
		0xBCF073500A391C67ULL,
		0xCA98D57CBF77ECB1ULL,
		0xB64BA941693D3D37ULL,
		0x74F1E75216EEF656ULL,
		0x8EC997FF9C20059BULL,
		0x1AB42D74E9B4B9A2ULL,
		0x3D1D5DD3AAB88AB6ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD529A8D74ACFF491ULL,
		0xBDC6F408C4F9DF02ULL,
		0xD16F0CC8CEC93A34ULL,
		0xD56EE60252B6EF4FULL,
		0x296380DD040890ADULL,
		0x33738D7B2F728638ULL,
		0x522A411C45AD2436ULL,
		0x3E8FD2B8D22687FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5351AE959FE922ULL,
		0x7B8DE81189F3BE05ULL,
		0xA2DE19919D927469ULL,
		0xAADDCC04A56DDE9FULL,
		0x52C701BA0811215BULL,
		0x66E71AF65EE50C70ULL,
		0xA45482388B5A486CULL,
		0x7D1FA571A44D0FF6ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1D12AD8A3AAF3811ULL,
		0x3F0D1FF288FECB0DULL,
		0xD6365A3E01AFBDFBULL,
		0x462614BEE32E791EULL,
		0x6C609CD220A0AEC4ULL,
		0x050133D26C4086A0ULL,
		0xF9D4E50742BC2F1EULL,
		0x21790F0FA3F00B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A255B14755E7022ULL,
		0x7E1A3FE511FD961AULL,
		0xAC6CB47C035F7BF6ULL,
		0x8C4C297DC65CF23DULL,
		0xD8C139A441415D88ULL,
		0x0A0267A4D8810D40ULL,
		0xF3A9CA0E85785E3CULL,
		0x42F21E1F47E0173BULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE5763CCADD38E7AULL,
		0x3F6B64FF8C961FB2ULL,
		0x281D9C8566F662C6ULL,
		0x247C006F5C8D7A8FULL,
		0xB347012B6AAF3047ULL,
		0x915522AF75168121ULL,
		0x224B92AFE2BD5C30ULL,
		0x012DDE39E192F14FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAEC7995BA71CF4ULL,
		0x7ED6C9FF192C3F65ULL,
		0x503B390ACDECC58CULL,
		0x48F800DEB91AF51EULL,
		0x668E0256D55E608EULL,
		0x22AA455EEA2D0243ULL,
		0x4497255FC57AB861ULL,
		0x025BBC73C325E29EULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4EE8740206AC58A6ULL,
		0x1FCCAC76CD60DF2BULL,
		0x69A30FEB8FF29382ULL,
		0x8F796830F75A6D2EULL,
		0xD2CE60952BD79426ULL,
		0x64C9A514FD3120D8ULL,
		0x3B88A27926241E54ULL,
		0x318128300C6A4F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DD0E8040D58B14CULL,
		0x3F9958ED9AC1BE56ULL,
		0xD3461FD71FE52704ULL,
		0x1EF2D061EEB4DA5CULL,
		0xA59CC12A57AF284DULL,
		0xC9934A29FA6241B1ULL,
		0x771144F24C483CA8ULL,
		0x6302506018D49F04ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E31D0DFB70515DBULL,
		0xBD59ADEECB3C7F4AULL,
		0x30CDD737CF974718ULL,
		0xE9B0442789850954ULL,
		0x91B6CF7196BC6DBFULL,
		0x22B5379B370CC207ULL,
		0xEDF9C336B8BCDCABULL,
		0x38E5849D93762219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C63A1BF6E0A2BB6ULL,
		0x7AB35BDD9678FE94ULL,
		0x619BAE6F9F2E8E31ULL,
		0xD360884F130A12A8ULL,
		0x236D9EE32D78DB7FULL,
		0x456A6F366E19840FULL,
		0xDBF3866D7179B956ULL,
		0x71CB093B26EC4433ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC91D07181C3CF59AULL,
		0x9212872B18E45DCBULL,
		0x9BE5ADC71A27ABA9ULL,
		0x7394C2190D8C98F7ULL,
		0xCB305E18DD650730ULL,
		0xDC4FE57CB2BB0523ULL,
		0x713B051B9794FF5AULL,
		0x2FF3CF294131F568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923A0E303879EB34ULL,
		0x24250E5631C8BB97ULL,
		0x37CB5B8E344F5753ULL,
		0xE72984321B1931EFULL,
		0x9660BC31BACA0E60ULL,
		0xB89FCAF965760A47ULL,
		0xE2760A372F29FEB5ULL,
		0x5FE79E528263EAD0ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD8B2542A063214C0ULL,
		0xCD340AD9C7C14C4BULL,
		0xEED55476A2F53E8CULL,
		0x3FD862C3D9106774ULL,
		0xC689C4ECEAB2FD0CULL,
		0xE3E2F7FEC7EB30FEULL,
		0x3A19D159CFB14CB5ULL,
		0x0CA46C027040E25DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB164A8540C642980ULL,
		0x9A6815B38F829897ULL,
		0xDDAAA8ED45EA7D19ULL,
		0x7FB0C587B220CEE9ULL,
		0x8D1389D9D565FA18ULL,
		0xC7C5EFFD8FD661FDULL,
		0x7433A2B39F62996BULL,
		0x1948D804E081C4BAULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDC3866587FED9E8FULL,
		0x33FAD1A3BD36AB03ULL,
		0x3D369D41883F5D0FULL,
		0xB3A32653D65444CBULL,
		0xD27B17EA93025089ULL,
		0xFE919E9CEA67436DULL,
		0xAFA61F604385A5C7ULL,
		0x1A257371730A6EDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB870CCB0FFDB3D1EULL,
		0x67F5A3477A6D5607ULL,
		0x7A6D3A83107EBA1EULL,
		0x67464CA7ACA88996ULL,
		0xA4F62FD52604A113ULL,
		0xFD233D39D4CE86DBULL,
		0x5F4C3EC0870B4B8FULL,
		0x344AE6E2E614DDB9ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC5C0DBAD050A3E94ULL,
		0x46FBBA55EFF26D8CULL,
		0x8298D83EDA419575ULL,
		0x4C9FE0B8749A5CB9ULL,
		0x5E1B4A10EAF97C31ULL,
		0xFD021A3355F016F6ULL,
		0xECC270D0F23E8314ULL,
		0x18128D239927BEC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B81B75A0A147D28ULL,
		0x8DF774ABDFE4DB19ULL,
		0x0531B07DB4832AEAULL,
		0x993FC170E934B973ULL,
		0xBC369421D5F2F862ULL,
		0xFA043466ABE02DECULL,
		0xD984E1A1E47D0629ULL,
		0x30251A47324F7D81ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4B68EEBE4C1263FAULL,
		0xF1283660A78A2FE7ULL,
		0xA0866424365137A7ULL,
		0x9B651FE816428F8FULL,
		0xA9162015D2FABB6DULL,
		0xC89BB51E322E30C6ULL,
		0x74EBD4B57C97A553ULL,
		0x2077E305A4D26BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D1DD7C9824C7F4ULL,
		0xE2506CC14F145FCEULL,
		0x410CC8486CA26F4FULL,
		0x36CA3FD02C851F1FULL,
		0x522C402BA5F576DBULL,
		0x91376A3C645C618DULL,
		0xE9D7A96AF92F4AA7ULL,
		0x40EFC60B49A4D7F2ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81A7A4D7292591F1ULL,
		0xC5E4681D6F034032ULL,
		0xF6EDF457345E29B5ULL,
		0x3C15C45B7CE42596ULL,
		0x41118C65F9AC8414ULL,
		0x2019EC71A44BE559ULL,
		0x8EE089B5B8D2FA34ULL,
		0x0FBCFBB0B884B43EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034F49AE524B23E2ULL,
		0x8BC8D03ADE068065ULL,
		0xEDDBE8AE68BC536BULL,
		0x782B88B6F9C84B2DULL,
		0x822318CBF3590828ULL,
		0x4033D8E34897CAB2ULL,
		0x1DC1136B71A5F468ULL,
		0x1F79F7617109687DULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x83793FF5EBA725F0ULL,
		0x394D4B45397DF624ULL,
		0x2864B28C0A6C6FAEULL,
		0xBCC58C80D54BF062ULL,
		0xA18FB11760BBCDD9ULL,
		0x12F92C81E2FAE0AEULL,
		0xB8A5DDBD737A6D75ULL,
		0x304351B0BB1DE88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F27FEBD74E4BE0ULL,
		0x729A968A72FBEC49ULL,
		0x50C9651814D8DF5CULL,
		0x798B1901AA97E0C4ULL,
		0x431F622EC1779BB3ULL,
		0x25F25903C5F5C15DULL,
		0x714BBB7AE6F4DAEAULL,
		0x6086A361763BD119ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x375F05B303F7885DULL,
		0xF26194136FD94FFFULL,
		0x32D877CA7D2FC8C1ULL,
		0x9EE39B2396AB0552ULL,
		0x9C40BAB13DD5CB47ULL,
		0xAF1F2BB3A84D7262ULL,
		0xF150337F60B4D0A0ULL,
		0x326FAAB8EDAC5BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBE0B6607EF10BAULL,
		0xE4C32826DFB29FFEULL,
		0x65B0EF94FA5F9183ULL,
		0x3DC736472D560AA4ULL,
		0x388175627BAB968FULL,
		0x5E3E5767509AE4C5ULL,
		0xE2A066FEC169A141ULL,
		0x64DF5571DB58B79FULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x584EC1A931044D77ULL,
		0x32C1E0D20FCD69A5ULL,
		0x0177FF5BAFE096DCULL,
		0x5691FFA2C38632B1ULL,
		0x2A1AE5DC5B0239ECULL,
		0xCA0757E19E8DE3A5ULL,
		0x0F38A3A394CD82FFULL,
		0x194F4EFA036D750EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09D835262089AEEULL,
		0x6583C1A41F9AD34AULL,
		0x02EFFEB75FC12DB8ULL,
		0xAD23FF45870C6562ULL,
		0x5435CBB8B60473D8ULL,
		0x940EAFC33D1BC74AULL,
		0x1E714747299B05FFULL,
		0x329E9DF406DAEA1CULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08182F36447D1A77ULL,
		0xB15DA3B0F2C75657ULL,
		0xED0BEC2521A354C7ULL,
		0xEAAF059F179EEABEULL,
		0x6B2705784296ACADULL,
		0x6878FB15C86830FDULL,
		0xF642F90301FD43ECULL,
		0x0640B3AF6F638C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10305E6C88FA34EEULL,
		0x62BB4761E58EACAEULL,
		0xDA17D84A4346A98FULL,
		0xD55E0B3E2F3DD57DULL,
		0xD64E0AF0852D595BULL,
		0xD0F1F62B90D061FAULL,
		0xEC85F20603FA87D8ULL,
		0x0C81675EDEC718E3ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6622980CD37B7D02ULL,
		0x5A636193B608242FULL,
		0xD4A0C60B522BF17CULL,
		0x37DA415B5DC08ED0ULL,
		0xE3A701167FF2D71DULL,
		0xE31E1CA474780B96ULL,
		0xAAAAF1C1E830FBA3ULL,
		0x1FDC0D7042EACCBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC453019A6F6FA04ULL,
		0xB4C6C3276C10485EULL,
		0xA9418C16A457E2F8ULL,
		0x6FB482B6BB811DA1ULL,
		0xC74E022CFFE5AE3AULL,
		0xC63C3948E8F0172DULL,
		0x5555E383D061F747ULL,
		0x3FB81AE085D5997DULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x38A0D7B7D5CE72CDULL,
		0x7BC0C3683ED4445AULL,
		0xABE9E1539D0832D3ULL,
		0x1B6E9F28B69228CFULL,
		0x4254718741D83446ULL,
		0xDE61485EB3491E9DULL,
		0x9E2E322B3B8C6FCBULL,
		0x282B38EDE3B3CA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7141AF6FAB9CE59AULL,
		0xF78186D07DA888B4ULL,
		0x57D3C2A73A1065A6ULL,
		0x36DD3E516D24519FULL,
		0x84A8E30E83B0688CULL,
		0xBCC290BD66923D3AULL,
		0x3C5C64567718DF97ULL,
		0x505671DBC767943DULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0533C9DC27157CC6ULL,
		0xEBE9D2D9311C3D2CULL,
		0x0DEC468D58F1691EULL,
		0x3A2165C4577B2024ULL,
		0x546BD03C6DD4C067ULL,
		0xE0EE4F4D420BA00FULL,
		0xF64D1D3EC7B17792ULL,
		0x2C6DF88747F0E6ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6793B84E2AF98CULL,
		0xD7D3A5B262387A58ULL,
		0x1BD88D1AB1E2D23DULL,
		0x7442CB88AEF64048ULL,
		0xA8D7A078DBA980CEULL,
		0xC1DC9E9A8417401EULL,
		0xEC9A3A7D8F62EF25ULL,
		0x58DBF10E8FE1CD59ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8A3F49C2F1CBD7EFULL,
		0xB7E9FF3CFAB30DD2ULL,
		0x3E5C56B817FEA423ULL,
		0x549692C6ABC8EDC4ULL,
		0x9F7FB533ECF760B2ULL,
		0x9E0CA8056EEC8A2DULL,
		0xA4ACC7FF5F416257ULL,
		0x1A5833E948208C0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x147E9385E397AFDEULL,
		0x6FD3FE79F5661BA5ULL,
		0x7CB8AD702FFD4847ULL,
		0xA92D258D5791DB88ULL,
		0x3EFF6A67D9EEC164ULL,
		0x3C19500ADDD9145BULL,
		0x49598FFEBE82C4AFULL,
		0x34B067D29041181FULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7577A069BF980516ULL,
		0xED75471961477377ULL,
		0xC8E336E29AA6683FULL,
		0x55FCE83790C5313CULL,
		0xDB87E974642805D2ULL,
		0xB77859278E38C847ULL,
		0x23A37653986A137FULL,
		0x36984D0D9E740196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAEF40D37F300A2CULL,
		0xDAEA8E32C28EE6EEULL,
		0x91C66DC5354CD07FULL,
		0xABF9D06F218A6279ULL,
		0xB70FD2E8C8500BA4ULL,
		0x6EF0B24F1C71908FULL,
		0x4746ECA730D426FFULL,
		0x6D309A1B3CE8032CULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4DD3566DF980525CULL,
		0x05C16C7FDE6A1257ULL,
		0xE67880A7A4165F25ULL,
		0x454D13C227E88534ULL,
		0x347FBBC3DAEA3E86ULL,
		0x2B1D87B924EAA142ULL,
		0x26FAFFB625820F22ULL,
		0x234871F695394D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BA6ACDBF300A4B8ULL,
		0x0B82D8FFBCD424AEULL,
		0xCCF1014F482CBE4AULL,
		0x8A9A27844FD10A69ULL,
		0x68FF7787B5D47D0CULL,
		0x563B0F7249D54284ULL,
		0x4DF5FF6C4B041E44ULL,
		0x4690E3ED2A729A1EULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC526F2882B2136AULL,
		0xD5DE635F4E50401BULL,
		0x04B9CD10FD6B7340ULL,
		0x4C8155FD8060BFA0ULL,
		0x509BBB6668E29790ULL,
		0x60500ED9B254707DULL,
		0xF4F4561D2D865DCDULL,
		0x1407402CDB8AAA2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58A4DE51056426D4ULL,
		0xABBCC6BE9CA08037ULL,
		0x09739A21FAD6E681ULL,
		0x9902ABFB00C17F40ULL,
		0xA13776CCD1C52F20ULL,
		0xC0A01DB364A8E0FAULL,
		0xE9E8AC3A5B0CBB9AULL,
		0x280E8059B715545BULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1F14E6EFA5D044BDULL,
		0xEF06F2C7FD46C9BEULL,
		0xE269284C4DECE324ULL,
		0xEF3E0988EBB7C69FULL,
		0x30A58359975959C6ULL,
		0xD646616263D8B69FULL,
		0xDF2DEBAECD2B0B7EULL,
		0x0D79D194D22FE802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E29CDDF4BA0897AULL,
		0xDE0DE58FFA8D937CULL,
		0xC4D250989BD9C649ULL,
		0xDE7C1311D76F8D3FULL,
		0x614B06B32EB2B38DULL,
		0xAC8CC2C4C7B16D3EULL,
		0xBE5BD75D9A5616FDULL,
		0x1AF3A329A45FD005ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE1AD78ABF246E9CDULL,
		0x1E95B85AD122B1F7ULL,
		0x4F09C4AC47264CF4ULL,
		0x32396710FB975167ULL,
		0xB0E54BAA18F10188ULL,
		0x310B4C9D4C2E7D5AULL,
		0xF9451F620F7F3803ULL,
		0x21B02711D83CAC59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC35AF157E48DD39AULL,
		0x3D2B70B5A24563EFULL,
		0x9E1389588E4C99E8ULL,
		0x6472CE21F72EA2CEULL,
		0x61CA975431E20310ULL,
		0x6216993A985CFAB5ULL,
		0xF28A3EC41EFE7006ULL,
		0x43604E23B07958B3ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3FC3774268599DFFULL,
		0xDECFF244721D7527ULL,
		0xA708B41607847683ULL,
		0x99C29D85ECC5F4C6ULL,
		0x813D472E62AD1198ULL,
		0x74363CF9DD7217C2ULL,
		0x99FA7B429CBAEBC0ULL,
		0x03FA7B22C3A4A64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F86EE84D0B33BFEULL,
		0xBD9FE488E43AEA4EULL,
		0x4E11682C0F08ED07ULL,
		0x33853B0BD98BE98DULL,
		0x027A8E5CC55A2331ULL,
		0xE86C79F3BAE42F85ULL,
		0x33F4F6853975D780ULL,
		0x07F4F64587494C9FULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC62FA507AC4DE971ULL,
		0xD4A5C262DDC610F1ULL,
		0x945FF3E12C2201F3ULL,
		0xC12F39FF760D8AE8ULL,
		0x19D20B0D2778A995ULL,
		0x2775229D26A524C8ULL,
		0x2A130197CF80D507ULL,
		0x16265A392051E3EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5F4A0F589BD2E2ULL,
		0xA94B84C5BB8C21E3ULL,
		0x28BFE7C2584403E7ULL,
		0x825E73FEEC1B15D1ULL,
		0x33A4161A4EF1532BULL,
		0x4EEA453A4D4A4990ULL,
		0x5426032F9F01AA0EULL,
		0x2C4CB47240A3C7D4ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB8F3D416D843DAFULL,
		0x7A10FCAD26731D3DULL,
		0xE590DD69966F2C2AULL,
		0x883E672531550276ULL,
		0x5F22B6E745AEDA8DULL,
		0xFC47D16CBA5124E4ULL,
		0xD19DAF39F0EFE402ULL,
		0x0B83720526B5D607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x571E7A82DB087B5EULL,
		0xF421F95A4CE63A7BULL,
		0xCB21BAD32CDE5854ULL,
		0x107CCE4A62AA04EDULL,
		0xBE456DCE8B5DB51BULL,
		0xF88FA2D974A249C8ULL,
		0xA33B5E73E1DFC805ULL,
		0x1706E40A4D6BAC0FULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x65D7F10C5EF789AFULL,
		0x7CC22B8D1578C4E7ULL,
		0xB54E8156F5918408ULL,
		0xF02DDCE8D3214E6BULL,
		0xF94E8ED8976EB5AFULL,
		0xB732DB3AF383B552ULL,
		0x89FC9B30192A5C77ULL,
		0x124C5E3AB90E358FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBAFE218BDEF135EULL,
		0xF984571A2AF189CEULL,
		0x6A9D02ADEB230810ULL,
		0xE05BB9D1A6429CD7ULL,
		0xF29D1DB12EDD6B5FULL,
		0x6E65B675E7076AA5ULL,
		0x13F936603254B8EFULL,
		0x2498BC75721C6B1FULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD743B7137CDB3308ULL,
		0x13C4481BB7299579ULL,
		0x97FF0943A2274404ULL,
		0x3BC33447AD735957ULL,
		0xD9FF7FCD509A0D65ULL,
		0xE4B4DC83485B909AULL,
		0x83EF5B0582CC110FULL,
		0x0EBBE157FC24E3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE876E26F9B66610ULL,
		0x278890376E532AF3ULL,
		0x2FFE1287444E8808ULL,
		0x7786688F5AE6B2AFULL,
		0xB3FEFF9AA1341ACAULL,
		0xC969B90690B72135ULL,
		0x07DEB60B0598221FULL,
		0x1D77C2AFF849C779ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x847332925901A42BULL,
		0x71193EC255131D83ULL,
		0x381484840A6FC072ULL,
		0x3133C97E76BF3BB9ULL,
		0xB2A4ECAE43DC5445ULL,
		0x86112D7A96EF5594ULL,
		0x13E1FC94E7B52981ULL,
		0x1A10EE90A98E3A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E66524B2034856ULL,
		0xE2327D84AA263B07ULL,
		0x7029090814DF80E4ULL,
		0x626792FCED7E7772ULL,
		0x6549D95C87B8A88AULL,
		0x0C225AF52DDEAB29ULL,
		0x27C3F929CF6A5303ULL,
		0x3421DD21531C74A4ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x683C70377A7EF661ULL,
		0xC84DDD54991D7512ULL,
		0xC1BA744F61B27A09ULL,
		0x2BBDE8A90C66B1ADULL,
		0x8A5CF45979B74CF0ULL,
		0xB4CF42AFD5327701ULL,
		0xFE141BEF631E4308ULL,
		0x01EB88A292AC44FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD078E06EF4FDECC2ULL,
		0x909BBAA9323AEA24ULL,
		0x8374E89EC364F413ULL,
		0x577BD15218CD635BULL,
		0x14B9E8B2F36E99E0ULL,
		0x699E855FAA64EE03ULL,
		0xFC2837DEC63C8611ULL,
		0x03D71145255889FFULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x93325A25E3402DC5ULL,
		0x1B25E5C1FE564C73ULL,
		0x51E1CA15D2CFCFF5ULL,
		0x378A768BC282AFD8ULL,
		0x1B6F20980371A792ULL,
		0xDF4C26325FDC6205ULL,
		0xB2DA74C2CF55F53FULL,
		0x2C99A7A3F767C882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2664B44BC6805B8AULL,
		0x364BCB83FCAC98E7ULL,
		0xA3C3942BA59F9FEAULL,
		0x6F14ED1785055FB0ULL,
		0x36DE413006E34F24ULL,
		0xBE984C64BFB8C40AULL,
		0x65B4E9859EABEA7FULL,
		0x59334F47EECF9105ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCF5C9B0ECEB6DA89ULL,
		0x70CA26DA4EBCE9A0ULL,
		0x6F422DDCB7AD61FEULL,
		0xEA238F2FCEFF4520ULL,
		0xE8E6425C67A15DACULL,
		0xBEC453B765A075C4ULL,
		0x4D81EBED97719CE6ULL,
		0x0D06B710526D0998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB9361D9D6DB512ULL,
		0xE1944DB49D79D341ULL,
		0xDE845BB96F5AC3FCULL,
		0xD4471E5F9DFE8A40ULL,
		0xD1CC84B8CF42BB59ULL,
		0x7D88A76ECB40EB89ULL,
		0x9B03D7DB2EE339CDULL,
		0x1A0D6E20A4DA1330ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF355877953DCE514ULL,
		0x841A1F41EA6921B4ULL,
		0x2C793459700D0FBAULL,
		0x7D7C6BB73BFF1EBDULL,
		0xA5F4C100CD07FCC8ULL,
		0xFC8955F30EE3C0E3ULL,
		0xEF6D834A855F87A3ULL,
		0x083FC5B46388A4EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6AB0EF2A7B9CA28ULL,
		0x08343E83D4D24369ULL,
		0x58F268B2E01A1F75ULL,
		0xFAF8D76E77FE3D7AULL,
		0x4BE982019A0FF990ULL,
		0xF912ABE61DC781C7ULL,
		0xDEDB06950ABF0F47ULL,
		0x107F8B68C71149DFULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB62CBDC5121D482ULL,
		0x0794C49F937C83B4ULL,
		0x320412C70AA786F0ULL,
		0x6BD24DC8DCD22CB7ULL,
		0x14B848F51FED24DCULL,
		0x3FB9D01899508620ULL,
		0x3B71611F05F085E1ULL,
		0x192E93E1DF7A23DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96C597B8A243A904ULL,
		0x0F29893F26F90769ULL,
		0x6408258E154F0DE0ULL,
		0xD7A49B91B9A4596EULL,
		0x297091EA3FDA49B8ULL,
		0x7F73A03132A10C40ULL,
		0x76E2C23E0BE10BC2ULL,
		0x325D27C3BEF447B8ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2C0F6F6497D1241EULL,
		0x0AD91FE07EC0E000ULL,
		0x74587C73B1359741ULL,
		0xCF620E881DF0BB0FULL,
		0x51E628DC35F78FFEULL,
		0xE87ABFC1360C527DULL,
		0x906EDE510D88B5E2ULL,
		0x34997355B932AA6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x581EDEC92FA2483CULL,
		0x15B23FC0FD81C000ULL,
		0xE8B0F8E7626B2E82ULL,
		0x9EC41D103BE1761EULL,
		0xA3CC51B86BEF1FFDULL,
		0xD0F57F826C18A4FAULL,
		0x20DDBCA21B116BC5ULL,
		0x6932E6AB726554DDULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x745F189C4DB876C4ULL,
		0x68D139CB7F2D0F50ULL,
		0x61D1C8124E464D1AULL,
		0x7DB4B9AA6C46BFE2ULL,
		0xAFC642C3ED3779DBULL,
		0x041089A3035B4975ULL,
		0x4A79AF05B93E3B62ULL,
		0x20613CB7EEFD3188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8BE31389B70ED88ULL,
		0xD1A27396FE5A1EA0ULL,
		0xC3A390249C8C9A34ULL,
		0xFB697354D88D7FC4ULL,
		0x5F8C8587DA6EF3B6ULL,
		0x0821134606B692EBULL,
		0x94F35E0B727C76C4ULL,
		0x40C2796FDDFA6310ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2A7FFF5D133DC783ULL,
		0x84BE3C0C1422AB2EULL,
		0xE79F5F7AA0D7E44BULL,
		0x0699A38AD2F48BD1ULL,
		0xCBBE06D05E262501ULL,
		0xF647C3D82BFF483CULL,
		0xC280DAEE52DCEE85ULL,
		0x121876F3CC192265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54FFFEBA267B8F06ULL,
		0x097C78182845565CULL,
		0xCF3EBEF541AFC897ULL,
		0x0D334715A5E917A3ULL,
		0x977C0DA0BC4C4A02ULL,
		0xEC8F87B057FE9079ULL,
		0x8501B5DCA5B9DD0BULL,
		0x2430EDE7983244CBULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4A024725228C61CBULL,
		0x13D6CB0E7EBBA8C3ULL,
		0xAA58A2A14DC3CE3DULL,
		0x4E4F70C3D7E2FC32ULL,
		0x924A56C8E1C473B7ULL,
		0xDEAE92E2FE03E0E6ULL,
		0xC152FC852C291F9DULL,
		0x32ACB426A4C312D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94048E4A4518C396ULL,
		0x27AD961CFD775186ULL,
		0x54B145429B879C7AULL,
		0x9C9EE187AFC5F865ULL,
		0x2494AD91C388E76EULL,
		0xBD5D25C5FC07C1CDULL,
		0x82A5F90A58523F3BULL,
		0x6559684D498625A3ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAFE747417BF61D06ULL,
		0x12C5F6D9403B3BCAULL,
		0xD05716E4607E141AULL,
		0x9D6F2CB754B6FF8AULL,
		0xF0B041FC816D32AFULL,
		0x9D2CBDA784C874DCULL,
		0x2C52234CA8BDBD54ULL,
		0x3D2D2E5708BB8AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FCE8E82F7EC3A0CULL,
		0x258BEDB280767795ULL,
		0xA0AE2DC8C0FC2834ULL,
		0x3ADE596EA96DFF15ULL,
		0xE16083F902DA655FULL,
		0x3A597B4F0990E9B9ULL,
		0x58A44699517B7AA9ULL,
		0x7A5A5CAE117715B2ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8AD0F153704973E6ULL,
		0x13C598F77C9C10F5ULL,
		0xFA595F9D92FD9D4DULL,
		0x6FB1AD62824178ABULL,
		0x1AFCFF0D7EF8C8D6ULL,
		0xE64974A5285D27BDULL,
		0x5DB174EC0DBE9379ULL,
		0x285E2D8A84F69063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A1E2A6E092E7CCULL,
		0x278B31EEF93821EBULL,
		0xF4B2BF3B25FB3A9AULL,
		0xDF635AC50482F157ULL,
		0x35F9FE1AFDF191ACULL,
		0xCC92E94A50BA4F7AULL,
		0xBB62E9D81B7D26F3ULL,
		0x50BC5B1509ED20C6ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x068610C9763218BEULL,
		0xF0DD361162A4D2A5ULL,
		0x56150BEA5E1EC176ULL,
		0x157D104550FA783BULL,
		0x9F96DF3DB784BED0ULL,
		0x6A453D6A70FB4320ULL,
		0x71A0998F8643A40CULL,
		0x0BDDC709EC4CF408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0C2192EC64317CULL,
		0xE1BA6C22C549A54AULL,
		0xAC2A17D4BC3D82EDULL,
		0x2AFA208AA1F4F076ULL,
		0x3F2DBE7B6F097DA0ULL,
		0xD48A7AD4E1F68641ULL,
		0xE341331F0C874818ULL,
		0x17BB8E13D899E810ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA04FAC6FD1A4D2FAULL,
		0x5650A95C68D46411ULL,
		0xD1209887957A6D9CULL,
		0x3B02B9E4D68C7077ULL,
		0xA2DCB07643D6CA93ULL,
		0xFBAD790612C4E995ULL,
		0xE05F6D9E26EAC7CCULL,
		0x3BA5D1F7D2513C12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409F58DFA349A5F4ULL,
		0xACA152B8D1A8C823ULL,
		0xA241310F2AF4DB38ULL,
		0x760573C9AD18E0EFULL,
		0x45B960EC87AD9526ULL,
		0xF75AF20C2589D32BULL,
		0xC0BEDB3C4DD58F99ULL,
		0x774BA3EFA4A27825ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81164E3B4E0C225DULL,
		0x3C7F1A4A275F6F6EULL,
		0xFDCECF6E3C26B005ULL,
		0x2FB03C44978B0883ULL,
		0x873A113AB5E7423FULL,
		0x681CD3BE70B1DE4CULL,
		0xD6E577F484620D3BULL,
		0x18AD9D3217EBCD45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022C9C769C1844BAULL,
		0x78FE34944EBEDEDDULL,
		0xFB9D9EDC784D600AULL,
		0x5F6078892F161107ULL,
		0x0E7422756BCE847EULL,
		0xD039A77CE163BC99ULL,
		0xADCAEFE908C41A76ULL,
		0x315B3A642FD79A8BULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x61058C40ABA5E8A3ULL,
		0x6750BAF39A8B9EE7ULL,
		0x6DCC60EC14A1E70FULL,
		0x5B18D4D73E80B299ULL,
		0x550FA738270D4E88ULL,
		0xCFB5D4A64F73216DULL,
		0x8F9BDA39D9561971ULL,
		0x12E184A214B5965BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20B1881574BD146ULL,
		0xCEA175E735173DCEULL,
		0xDB98C1D82943CE1EULL,
		0xB631A9AE7D016532ULL,
		0xAA1F4E704E1A9D10ULL,
		0x9F6BA94C9EE642DAULL,
		0x1F37B473B2AC32E3ULL,
		0x25C30944296B2CB7ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB3AA087CA94264CULL,
		0xE52E8B06D90B6CEBULL,
		0xA0C23F4E9422BCC0ULL,
		0xBB890B3D555178CFULL,
		0xAD61A0EBC3DC45BDULL,
		0x10AF688967884488ULL,
		0xDF48D90F16AB4C8FULL,
		0x1D4664D71A5FE0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9675410F95284C98ULL,
		0xCA5D160DB216D9D7ULL,
		0x41847E9D28457981ULL,
		0x7712167AAAA2F19FULL,
		0x5AC341D787B88B7BULL,
		0x215ED112CF108911ULL,
		0xBE91B21E2D56991EULL,
		0x3A8CC9AE34BFC143ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x611DBEBB629B3DF9ULL,
		0x08ACC1C67BA36258ULL,
		0xBB5C6CBED366D406ULL,
		0x9333B7F4C76257E4ULL,
		0xB7FC4FD30E652C66ULL,
		0xAF02FC973847272AULL,
		0x83F070DF259D6B06ULL,
		0x0982F6B499191CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC23B7D76C5367BF2ULL,
		0x1159838CF746C4B0ULL,
		0x76B8D97DA6CDA80CULL,
		0x26676FE98EC4AFC9ULL,
		0x6FF89FA61CCA58CDULL,
		0x5E05F92E708E4E55ULL,
		0x07E0E1BE4B3AD60DULL,
		0x1305ED69323239F3ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1597FA17FD7EA7FCULL,
		0xA26A848277A5419AULL,
		0xB5D953577C1FFCE7ULL,
		0x68977E52C888B06AULL,
		0x747F6C18649BED2AULL,
		0xF1413D9D9DBEE8B7ULL,
		0x6B6DC0CD92A0446CULL,
		0x168B1832440368DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B2FF42FFAFD4FF8ULL,
		0x44D50904EF4A8334ULL,
		0x6BB2A6AEF83FF9CFULL,
		0xD12EFCA5911160D5ULL,
		0xE8FED830C937DA54ULL,
		0xE2827B3B3B7DD16EULL,
		0xD6DB819B254088D9ULL,
		0x2D1630648806D1BEULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x884369164DE2CCDBULL,
		0x2FC8AFA8A2BEEE9CULL,
		0xB43D3FE24FAAEDACULL,
		0xCA1CA5F74AAFF240ULL,
		0xC45E05F21696DF82ULL,
		0x99DE10A2283BD2AEULL,
		0x28174F1E5816FED9ULL,
		0x189F0F776BBC0BA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1086D22C9BC599B6ULL,
		0x5F915F51457DDD39ULL,
		0x687A7FC49F55DB58ULL,
		0x94394BEE955FE481ULL,
		0x88BC0BE42D2DBF05ULL,
		0x33BC21445077A55DULL,
		0x502E9E3CB02DFDB3ULL,
		0x313E1EEED7781750ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC315F5BE51E0412DULL,
		0xC0060B3AEE53188EULL,
		0x89D1C953D4ED19E3ULL,
		0x4C94C8D6153B7D7EULL,
		0xBFA8903591E2A34DULL,
		0xD5B908A4339C2B05ULL,
		0xEB390DFFB432B0A6ULL,
		0x26735ECFAC69D6B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862BEB7CA3C0825AULL,
		0x800C1675DCA6311DULL,
		0x13A392A7A9DA33C7ULL,
		0x992991AC2A76FAFDULL,
		0x7F51206B23C5469AULL,
		0xAB7211486738560BULL,
		0xD6721BFF6865614DULL,
		0x4CE6BD9F58D3AD67ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E75960B5D1FDF11ULL,
		0x5816FD3C5509DECDULL,
		0x89A34922A8627699ULL,
		0xD2CEDD03E1205366ULL,
		0x1A85CA5AA326BC5CULL,
		0x15E5E2B3D400FF51ULL,
		0xBA226187A40E09B2ULL,
		0x01320B411369C2F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CEB2C16BA3FBE22ULL,
		0xB02DFA78AA13BD9AULL,
		0x1346924550C4ED32ULL,
		0xA59DBA07C240A6CDULL,
		0x350B94B5464D78B9ULL,
		0x2BCBC567A801FEA2ULL,
		0x7444C30F481C1364ULL,
		0x0264168226D385EBULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9811A677C95D12FEULL,
		0xB3FDB1BF70FE1A07ULL,
		0xB254FB86170C90BFULL,
		0xC1D6C7DB0301C76EULL,
		0x304BF64F48B57220ULL,
		0x51F896B9DA9B09B0ULL,
		0x2E97857DFBD3B0D7ULL,
		0x3FC2EA3A79C478F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30234CEF92BA25FCULL,
		0x67FB637EE1FC340FULL,
		0x64A9F70C2E19217FULL,
		0x83AD8FB606038EDDULL,
		0x6097EC9E916AE441ULL,
		0xA3F12D73B5361360ULL,
		0x5D2F0AFBF7A761AEULL,
		0x7F85D474F388F1ECULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8BA09320DA63DB8BULL,
		0xC8574CEF127323FBULL,
		0x10F4A678E042D3B6ULL,
		0xF4566B879B7AC8EFULL,
		0x0FDD29BEF13C421CULL,
		0xCDB3DA4CDCD4BED5ULL,
		0xF617D8006E78D5FBULL,
		0x1CC575797551208EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17412641B4C7B716ULL,
		0x90AE99DE24E647F7ULL,
		0x21E94CF1C085A76DULL,
		0xE8ACD70F36F591DEULL,
		0x1FBA537DE2788439ULL,
		0x9B67B499B9A97DAAULL,
		0xEC2FB000DCF1ABF7ULL,
		0x398AEAF2EAA2411DULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB1D44E2E94C76631ULL,
		0x154B7477FE5F4392ULL,
		0xFE5217BC99140DC7ULL,
		0x74089A4AF58AC8D9ULL,
		0x067C26C2A9FD1E5FULL,
		0x0A78202AC6332A25ULL,
		0xA86E2928E3DAF6E6ULL,
		0x31CC28849962E54BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63A89C5D298ECC62ULL,
		0x2A96E8EFFCBE8725ULL,
		0xFCA42F7932281B8EULL,
		0xE8113495EB1591B3ULL,
		0x0CF84D8553FA3CBEULL,
		0x14F040558C66544AULL,
		0x50DC5251C7B5EDCCULL,
		0x6398510932C5CA97ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD90B266A154DD980ULL,
		0x81061587364552A7ULL,
		0x8DF1DD3726771E62ULL,
		0xF69EF8655C9BA436ULL,
		0x794D6D2CC6FA44C3ULL,
		0xA9B9D4116571506AULL,
		0x4C93518C3543E197ULL,
		0x346F3A89C7F66CC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2164CD42A9BB300ULL,
		0x020C2B0E6C8AA54FULL,
		0x1BE3BA6E4CEE3CC5ULL,
		0xED3DF0CAB937486DULL,
		0xF29ADA598DF48987ULL,
		0x5373A822CAE2A0D4ULL,
		0x9926A3186A87C32FULL,
		0x68DE75138FECD988ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0E7F5505F21880EULL,
		0x8E9A681C56015472ULL,
		0x28AA6F1AE7608524ULL,
		0x1A611B38D1AC2E74ULL,
		0x1C0FC3E166FCA690ULL,
		0x1252EF3173B912DEULL,
		0xFD7170F29DAE682AULL,
		0x1507A7E46593CB58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1CFEAA0BE43101CULL,
		0x1D34D038AC02A8E5ULL,
		0x5154DE35CEC10A49ULL,
		0x34C23671A3585CE8ULL,
		0x381F87C2CDF94D20ULL,
		0x24A5DE62E77225BCULL,
		0xFAE2E1E53B5CD054ULL,
		0x2A0F4FC8CB2796B1ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6C0D6124B4B76882ULL,
		0x548E04A1697E043CULL,
		0xA29DB0FE99DCFD70ULL,
		0xC7EE503085CCAC54ULL,
		0x6E008752E57BEBCBULL,
		0xB9534A8D1437015BULL,
		0xAB9F3D226B44CE4FULL,
		0x08A61D97BBD8B263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD81AC249696ED104ULL,
		0xA91C0942D2FC0878ULL,
		0x453B61FD33B9FAE0ULL,
		0x8FDCA0610B9958A9ULL,
		0xDC010EA5CAF7D797ULL,
		0x72A6951A286E02B6ULL,
		0x573E7A44D6899C9FULL,
		0x114C3B2F77B164C7ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x48C5DE8812C395DFULL,
		0xA56E3D6BED229FD3ULL,
		0x2E51967F07ECFF9BULL,
		0x7DA64C6229F40419ULL,
		0x87A021C278E81E51ULL,
		0xDEA976A6D2E52552ULL,
		0x13DAA855D56347C6ULL,
		0x022601DF63A9C6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918BBD1025872BBEULL,
		0x4ADC7AD7DA453FA6ULL,
		0x5CA32CFE0FD9FF37ULL,
		0xFB4C98C453E80832ULL,
		0x0F404384F1D03CA2ULL,
		0xBD52ED4DA5CA4AA5ULL,
		0x27B550ABAAC68F8DULL,
		0x044C03BEC7538D5AULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D9B27CA56F9C469ULL,
		0xA411E985521FD7C3ULL,
		0xA0F87BBD0A88204EULL,
		0xF88BE669AC94A6A6ULL,
		0x65115490DE0F33DFULL,
		0x99A902D3AB0F1BA7ULL,
		0x5811177030BFD880ULL,
		0x00C5B06DA5B46670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B364F94ADF388D2ULL,
		0x4823D30AA43FAF86ULL,
		0x41F0F77A1510409DULL,
		0xF117CCD359294D4DULL,
		0xCA22A921BC1E67BFULL,
		0x335205A7561E374EULL,
		0xB0222EE0617FB101ULL,
		0x018B60DB4B68CCE0ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA6BE2C368AF61DAEULL,
		0x850706B89FBA2589ULL,
		0xFA33C68BFAAF4977ULL,
		0x6FD08B227C33FD00ULL,
		0xD58210C73C68F60AULL,
		0x99DD409CFFF75454ULL,
		0x3A16D78F8D3B06B0ULL,
		0x07E53CFA9C23BDA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D7C586D15EC3B5CULL,
		0x0A0E0D713F744B13ULL,
		0xF4678D17F55E92EFULL,
		0xDFA11644F867FA01ULL,
		0xAB04218E78D1EC14ULL,
		0x33BA8139FFEEA8A9ULL,
		0x742DAF1F1A760D61ULL,
		0x0FCA79F538477B44ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB499765EB66B3910ULL,
		0x1CF880ECA7F151B8ULL,
		0x231282E1CBA1AAC2ULL,
		0x7F12048661D16DB7ULL,
		0x7DFDBA7E4E2C030BULL,
		0x6290E04412A558FEULL,
		0xF3D69F20A39C375BULL,
		0x21D3C9452CEEAEFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6932ECBD6CD67220ULL,
		0x39F101D94FE2A371ULL,
		0x462505C397435584ULL,
		0xFE24090CC3A2DB6EULL,
		0xFBFB74FC9C580616ULL,
		0xC521C088254AB1FCULL,
		0xE7AD3E4147386EB6ULL,
		0x43A7928A59DD5DFDULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8DF4AE3C360A65B4ULL,
		0x59E5C3351BE425E2ULL,
		0x2E1F60046ADE582EULL,
		0x7CAD46C3EEB36A1EULL,
		0x13C93C87FB320E1CULL,
		0xF51E8D1822D78F32ULL,
		0x8FA4D77CC1C29605ULL,
		0x1E6A6512B6EF346AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE95C786C14CB68ULL,
		0xB3CB866A37C84BC5ULL,
		0x5C3EC008D5BCB05CULL,
		0xF95A8D87DD66D43CULL,
		0x2792790FF6641C38ULL,
		0xEA3D1A3045AF1E64ULL,
		0x1F49AEF983852C0BULL,
		0x3CD4CA256DDE68D5ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9D5F5197AE0CB4BCULL,
		0x19F69A0058B63719ULL,
		0x73970D9714BEFC1EULL,
		0x67E709651EBB73BBULL,
		0x383EED8CE9A40AC4ULL,
		0x0809E5829B6C0404ULL,
		0x30D55977C5A0F9D4ULL,
		0x1FEB6E72877EE138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ABEA32F5C196978ULL,
		0x33ED3400B16C6E33ULL,
		0xE72E1B2E297DF83CULL,
		0xCFCE12CA3D76E776ULL,
		0x707DDB19D3481588ULL,
		0x1013CB0536D80808ULL,
		0x61AAB2EF8B41F3A8ULL,
		0x3FD6DCE50EFDC270ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFE98F2319287242AULL,
		0x677A2FBA88516D27ULL,
		0xE06EA13A6F8EE572ULL,
		0x43EDD47AEF600059ULL,
		0x307F41E0C6D8C428ULL,
		0x1774DD1FBDA54C29ULL,
		0x79888E1A53CAC8B3ULL,
		0x147CE94B4FFC7084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD31E463250E4854ULL,
		0xCEF45F7510A2DA4FULL,
		0xC0DD4274DF1DCAE4ULL,
		0x87DBA8F5DEC000B3ULL,
		0x60FE83C18DB18850ULL,
		0x2EE9BA3F7B4A9852ULL,
		0xF3111C34A7959166ULL,
		0x28F9D2969FF8E108ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB32A4A5222001B6ULL,
		0x6D771FFFBB682DBAULL,
		0xBAE0830BCD977408ULL,
		0x68A6264D0A3E006CULL,
		0x9060A1C60343C42FULL,
		0x46B7EF8B717E304FULL,
		0x8EF0B4DB685237A6ULL,
		0x1E0AB245424C8DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5665494A4440036CULL,
		0xDAEE3FFF76D05B75ULL,
		0x75C106179B2EE810ULL,
		0xD14C4C9A147C00D9ULL,
		0x20C1438C0687885EULL,
		0x8D6FDF16E2FC609FULL,
		0x1DE169B6D0A46F4CULL,
		0x3C15648A84991B63ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E6F8EEDE68240B7ULL,
		0xE4CCD1025C77B734ULL,
		0x00917C840D670525ULL,
		0x19188F49C73AC69BULL,
		0x832F7E5DC8A30925ULL,
		0x0BF377E484CDC9AAULL,
		0xE88B82614D75A466ULL,
		0x1113952E23A32E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDF1DDBCD04816EULL,
		0xC999A204B8EF6E68ULL,
		0x0122F9081ACE0A4BULL,
		0x32311E938E758D36ULL,
		0x065EFCBB9146124AULL,
		0x17E6EFC9099B9355ULL,
		0xD11704C29AEB48CCULL,
		0x22272A5C47465C49ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFAFBA1EC67458A3CULL,
		0xFA178369F4586868ULL,
		0x080E45BCF52B2E89ULL,
		0x88C749E4B519BB0DULL,
		0x936562B15E043808ULL,
		0xAD265544139DC1C7ULL,
		0xB9E0DB7E40C7C256ULL,
		0x22B49DD362486D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F743D8CE8B1478ULL,
		0xF42F06D3E8B0D0D1ULL,
		0x101C8B79EA565D13ULL,
		0x118E93C96A33761AULL,
		0x26CAC562BC087011ULL,
		0x5A4CAA88273B838FULL,
		0x73C1B6FC818F84ADULL,
		0x45693BA6C490DAC3ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0D1C3B4D2BE1EB95ULL,
		0x76F03CF3DB02345FULL,
		0x632EFD0B0F0B0F8EULL,
		0x588B41C18745C06FULL,
		0x923631709ED4128DULL,
		0x84A660D7968C6CF5ULL,
		0x00A1ADD20CF33157ULL,
		0x1C2F79A0FB8C80E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A38769A57C3D72AULL,
		0xEDE079E7B60468BEULL,
		0xC65DFA161E161F1CULL,
		0xB11683830E8B80DEULL,
		0x246C62E13DA8251AULL,
		0x094CC1AF2D18D9EBULL,
		0x01435BA419E662AFULL,
		0x385EF341F71901CAULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x509797DC89A6C91DULL,
		0xB675DD33DB12C013ULL,
		0x00DFC98A6B949A84ULL,
		0x50FD0D19E963A187ULL,
		0x9925048E3F5D6516ULL,
		0xFD29DB012DE97547ULL,
		0x4AB5AA8A308E9A6AULL,
		0x18491A0EF5EBD2E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12F2FB9134D923AULL,
		0x6CEBBA67B6258026ULL,
		0x01BF9314D7293509ULL,
		0xA1FA1A33D2C7430EULL,
		0x324A091C7EBACA2CULL,
		0xFA53B6025BD2EA8FULL,
		0x956B5514611D34D5ULL,
		0x3092341DEBD7A5CAULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8EEA77209D0C89BEULL,
		0x87E663042D6E8638ULL,
		0x1FAF32432E2519F9ULL,
		0x9F0637338C358814ULL,
		0x5C23C838F5C502A6ULL,
		0x441F0746473E0BE8ULL,
		0x2FFA20E42145C606ULL,
		0x1706CDE3CEC2642DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DD4EE413A19137CULL,
		0x0FCCC6085ADD0C71ULL,
		0x3F5E64865C4A33F3ULL,
		0x3E0C6E67186B1028ULL,
		0xB8479071EB8A054DULL,
		0x883E0E8C8E7C17D0ULL,
		0x5FF441C8428B8C0CULL,
		0x2E0D9BC79D84C85AULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEF51A99BCACD8F60ULL,
		0x3D2BE6C6A5BC127FULL,
		0x1C06DF97B2415588ULL,
		0xD392B88D39C15A06ULL,
		0x9B46ED8F7CF22484ULL,
		0x9C912E44FDF7DB4FULL,
		0x8B60A8E3FEF29254ULL,
		0x020ECF92399D1675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEA35337959B1EC0ULL,
		0x7A57CD8D4B7824FFULL,
		0x380DBF2F6482AB10ULL,
		0xA725711A7382B40CULL,
		0x368DDB1EF9E44909ULL,
		0x39225C89FBEFB69FULL,
		0x16C151C7FDE524A9ULL,
		0x041D9F24733A2CEBULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x85EDE129493745A4ULL,
		0xD912246162D09671ULL,
		0x6A3FD5D29A7A2568ULL,
		0xE825774BA8BEAD0CULL,
		0x51070573A03E65DFULL,
		0x8936B23BE89F56AFULL,
		0x351627A6D5EC1D1EULL,
		0x2C52AAEDB85D5638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BDBC252926E8B48ULL,
		0xB22448C2C5A12CE3ULL,
		0xD47FABA534F44AD1ULL,
		0xD04AEE97517D5A18ULL,
		0xA20E0AE7407CCBBFULL,
		0x126D6477D13EAD5EULL,
		0x6A2C4F4DABD83A3DULL,
		0x58A555DB70BAAC70ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x64D60365F9FCF343ULL,
		0x1ADB12FD8B4E096BULL,
		0xA8B7A481D0633B9EULL,
		0xF30E6CE24C87D1D4ULL,
		0x800138EE89BAEDDAULL,
		0x5F35FDEB3966A273ULL,
		0x56F85B9C9CA1B2F4ULL,
		0x2BFE3EBF4635A383ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AC06CBF3F9E686ULL,
		0x35B625FB169C12D6ULL,
		0x516F4903A0C6773CULL,
		0xE61CD9C4990FA3A9ULL,
		0x000271DD1375DBB5ULL,
		0xBE6BFBD672CD44E7ULL,
		0xADF0B739394365E8ULL,
		0x57FC7D7E8C6B4706ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C7A4376D61B0970ULL,
		0xFF8E23D57CA8E064ULL,
		0x16394AE8CB68FCA9ULL,
		0x8800AD8F2DE49F57ULL,
		0x1E297DF5A68E76C0ULL,
		0xC3025B97D94334FDULL,
		0xFE1D8BE6BD48EDD4ULL,
		0x1B6AF1B816BFB559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F486EDAC3612E0ULL,
		0xFF1C47AAF951C0C9ULL,
		0x2C7295D196D1F953ULL,
		0x10015B1E5BC93EAEULL,
		0x3C52FBEB4D1CED81ULL,
		0x8604B72FB28669FAULL,
		0xFC3B17CD7A91DBA9ULL,
		0x36D5E3702D7F6AB3ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x22DA548D474F9663ULL,
		0xBF457294A5B70649ULL,
		0x80E0EFCC6ABC0825ULL,
		0xAA05A663CAC7FFCBULL,
		0x93B803528342BDE7ULL,
		0x6A6FA4121875DF39ULL,
		0x48DC04F1F038F4AAULL,
		0x25AFED4378B94B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B4A91A8E9F2CC6ULL,
		0x7E8AE5294B6E0C92ULL,
		0x01C1DF98D578104BULL,
		0x540B4CC7958FFF97ULL,
		0x277006A506857BCFULL,
		0xD4DF482430EBBE73ULL,
		0x91B809E3E071E954ULL,
		0x4B5FDA86F17296D0ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC11C190F1186B0F8ULL,
		0xC6D37607ACD53686ULL,
		0x969C9D4C8BF28B47ULL,
		0xA53F3A5436769A72ULL,
		0xDAEC8B18112A17D0ULL,
		0xFBA3B8A75771D4EEULL,
		0xF961C44D58B3B454ULL,
		0x2C9B4E9273C9C8B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8238321E230D61F0ULL,
		0x8DA6EC0F59AA6D0DULL,
		0x2D393A9917E5168FULL,
		0x4A7E74A86CED34E5ULL,
		0xB5D9163022542FA1ULL,
		0xF747714EAEE3A9DDULL,
		0xF2C3889AB16768A9ULL,
		0x59369D24E7939167ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC98AA0696B536420ULL,
		0x73907864192CEA39ULL,
		0xC0EF17B9E62DF945ULL,
		0x9B8A33DE1793418FULL,
		0xAE233B75A402DAE4ULL,
		0x48BC531B61F912CFULL,
		0x69AF1D8CB7927F89ULL,
		0x27DAD5A629E9A9D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931540D2D6A6C840ULL,
		0xE720F0C83259D473ULL,
		0x81DE2F73CC5BF28AULL,
		0x371467BC2F26831FULL,
		0x5C4676EB4805B5C9ULL,
		0x9178A636C3F2259FULL,
		0xD35E3B196F24FF12ULL,
		0x4FB5AB4C53D353B0ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x210DBF1B31653A89ULL,
		0xE45A7332CF98AEFAULL,
		0x61FD966002547190ULL,
		0x5D9068DF9F562150ULL,
		0x13055C3A100865C7ULL,
		0x82A95ABF749D2E0BULL,
		0x0E66A5690F483C05ULL,
		0x2E129E89AED08FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421B7E3662CA7512ULL,
		0xC8B4E6659F315DF4ULL,
		0xC3FB2CC004A8E321ULL,
		0xBB20D1BF3EAC42A0ULL,
		0x260AB8742010CB8EULL,
		0x0552B57EE93A5C16ULL,
		0x1CCD4AD21E90780BULL,
		0x5C253D135DA11FDAULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C5A808F094ADD3FULL,
		0x7E1BE4B3623E9DA0ULL,
		0x6577B3E7B822F810ULL,
		0x041CF210B4EC0026ULL,
		0x73334D586396FFBEULL,
		0x01F6A6B6F923765AULL,
		0x947305FE54C790C3ULL,
		0x2673851C4F0E4655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B5011E1295BA7EULL,
		0xFC37C966C47D3B40ULL,
		0xCAEF67CF7045F020ULL,
		0x0839E42169D8004CULL,
		0xE6669AB0C72DFF7CULL,
		0x03ED4D6DF246ECB4ULL,
		0x28E60BFCA98F2186ULL,
		0x4CE70A389E1C8CABULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8474CF56095E704AULL,
		0xB13D2068E3AB2076ULL,
		0x6586ECDCA80B6B31ULL,
		0xE7B4D96CF6DAFA09ULL,
		0xC4F1ED750B3EBB7FULL,
		0x8D9955E073EC8BE6ULL,
		0x08CC32CC7B4844CDULL,
		0x35A83322BCA7FD83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E99EAC12BCE094ULL,
		0x627A40D1C75640EDULL,
		0xCB0DD9B95016D663ULL,
		0xCF69B2D9EDB5F412ULL,
		0x89E3DAEA167D76FFULL,
		0x1B32ABC0E7D917CDULL,
		0x11986598F690899BULL,
		0x6B506645794FFB06ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB95DB9D48748C925ULL,
		0xC5DED5A2A863E321ULL,
		0xED31AC3918AA2F8FULL,
		0xB342CF82FC7A99B6ULL,
		0x2BBB76AA464B1E41ULL,
		0x3EB087EB271E7866ULL,
		0x7A4A0DB695F47826ULL,
		0x39D0670FAAEE56C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72BB73A90E91924AULL,
		0x8BBDAB4550C7C643ULL,
		0xDA63587231545F1FULL,
		0x66859F05F8F5336DULL,
		0x5776ED548C963C83ULL,
		0x7D610FD64E3CF0CCULL,
		0xF4941B6D2BE8F04CULL,
		0x73A0CE1F55DCAD84ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5A39556FCDFDCC0EULL,
		0x402130CD5D77F98AULL,
		0xE3FEB8C38B508830ULL,
		0xA213507B47D8222BULL,
		0x601CC62BFE4A8672ULL,
		0xC2567F16C96C9F0EULL,
		0x404029CC6C3E313FULL,
		0x29C7E8E2DAE40032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB472AADF9BFB981CULL,
		0x8042619ABAEFF314ULL,
		0xC7FD718716A11060ULL,
		0x4426A0F68FB04457ULL,
		0xC0398C57FC950CE5ULL,
		0x84ACFE2D92D93E1CULL,
		0x80805398D87C627FULL,
		0x538FD1C5B5C80064ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C00F7532B6258D4ULL,
		0x82890019911F2101ULL,
		0x354D157420D5D682ULL,
		0x91BC422D62024EB3ULL,
		0x8F0B412D696823D4ULL,
		0xDC21B651BD72CBAFULL,
		0xF0CBAB90FA568C34ULL,
		0x3F4B1629243E17BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1801EEA656C4B1A8ULL,
		0x05120033223E4203ULL,
		0x6A9A2AE841ABAD05ULL,
		0x2378845AC4049D66ULL,
		0x1E16825AD2D047A9ULL,
		0xB8436CA37AE5975FULL,
		0xE1975721F4AD1869ULL,
		0x7E962C52487C2F7DULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x39150CB8479096CAULL,
		0xF7A29E8F68FD521DULL,
		0x5818A9B943733C49ULL,
		0xBD7C3B03C4D9E3CAULL,
		0x1BB7EDA54B4B17CEULL,
		0x63ED79BE36234B56ULL,
		0xE201B69C07A6A2BFULL,
		0x0709F6DAD5D3CE08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x722A19708F212D94ULL,
		0xEF453D1ED1FAA43AULL,
		0xB031537286E67893ULL,
		0x7AF8760789B3C794ULL,
		0x376FDB4A96962F9DULL,
		0xC7DAF37C6C4696ACULL,
		0xC4036D380F4D457EULL,
		0x0E13EDB5ABA79C11ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE6A105AB948A965ULL,
		0x3E468EA6D0A2A98CULL,
		0x756AD447BE623EA1ULL,
		0x4D60D52CD1821AC3ULL,
		0xCEC8C4B86FF04A73ULL,
		0x862CD7E1D3272671ULL,
		0x41B2DF8C60F5B14DULL,
		0x043D66FC6223F2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCD420B5729152CAULL,
		0x7C8D1D4DA1455319ULL,
		0xEAD5A88F7CC47D42ULL,
		0x9AC1AA59A3043586ULL,
		0x9D918970DFE094E6ULL,
		0x0C59AFC3A64E4CE3ULL,
		0x8365BF18C1EB629BULL,
		0x087ACDF8C447E548ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCFEAB9B0576CA4D7ULL,
		0x0CCEE43CE4743DEEULL,
		0xF26B5908104BDD34ULL,
		0x3827C7C0F72FAA72ULL,
		0xB7D487C2C74713D3ULL,
		0x596F07B23DDE8917ULL,
		0xC2E319E690B735CEULL,
		0x0B6459E45E00CF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD57360AED949AEULL,
		0x199DC879C8E87BDDULL,
		0xE4D6B2102097BA68ULL,
		0x704F8F81EE5F54E5ULL,
		0x6FA90F858E8E27A6ULL,
		0xB2DE0F647BBD122FULL,
		0x85C633CD216E6B9CULL,
		0x16C8B3C8BC019EAFULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDDC9DDA4F3BC607CULL,
		0xD8E4A7BC38D1DBDEULL,
		0xA42A53960BAF5AA2ULL,
		0x7B97EA6501C24E89ULL,
		0x2FD6DAECBB41793FULL,
		0x7E54040ADC1863C8ULL,
		0x8107B00DF7C0CD95ULL,
		0x33E0A04B237BC959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB93BB49E778C0F8ULL,
		0xB1C94F7871A3B7BDULL,
		0x4854A72C175EB545ULL,
		0xF72FD4CA03849D13ULL,
		0x5FADB5D97682F27EULL,
		0xFCA80815B830C790ULL,
		0x020F601BEF819B2AULL,
		0x67C1409646F792B3ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E193718730AB6E3ULL,
		0x5AAA91B617E7471EULL,
		0x1D2710B25845E24FULL,
		0x50C89E92F7A43667ULL,
		0xBA737EE20D289A57ULL,
		0xCD022D4DFDDD6B9BULL,
		0x3B5BA051867148E7ULL,
		0x2F6F6C80C12439FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC326E30E6156DC6ULL,
		0xB555236C2FCE8E3CULL,
		0x3A4E2164B08BC49EULL,
		0xA1913D25EF486CCEULL,
		0x74E6FDC41A5134AEULL,
		0x9A045A9BFBBAD737ULL,
		0x76B740A30CE291CFULL,
		0x5EDED901824873FCULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0C58883596CE90EULL,
		0x1698F533E67E9549ULL,
		0xCC23797D33C619D0ULL,
		0x96F819EE09CEBB46ULL,
		0x18E6757B97E4356BULL,
		0xE981810274AB7FADULL,
		0xF05B53A634AF0806ULL,
		0x1E35FC9C0F9A42C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC18B1106B2D9D21CULL,
		0x2D31EA67CCFD2A93ULL,
		0x9846F2FA678C33A0ULL,
		0x2DF033DC139D768DULL,
		0x31CCEAF72FC86AD7ULL,
		0xD3030204E956FF5AULL,
		0xE0B6A74C695E100DULL,
		0x3C6BF9381F348593ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4EF937B626B3B221ULL,
		0x16059F18071A88BAULL,
		0x988192CDCF882AC6ULL,
		0x8BE4C4482FAD81C9ULL,
		0x4358D6512C179C1AULL,
		0xD88939A05B8D869DULL,
		0x9BA42D0CF73EC62BULL,
		0x23A8B323E2C0A5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF26F6C4D676442ULL,
		0x2C0B3E300E351174ULL,
		0x3103259B9F10558CULL,
		0x17C988905F5B0393ULL,
		0x86B1ACA2582F3835ULL,
		0xB1127340B71B0D3AULL,
		0x37485A19EE7D8C57ULL,
		0x47516647C5814BCBULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3A526FD0382D345ULL,
		0x88F84B74D7B9BD9DULL,
		0x017AB332F1C4A133ULL,
		0xA0E1ACF9EBBA4C39ULL,
		0xAB8E61CA64F22399ULL,
		0xF08EF55F87A0B13EULL,
		0xFAF5D3C622FEEB2EULL,
		0x33F689A62E1E3C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x474A4DFA0705A68AULL,
		0x11F096E9AF737B3BULL,
		0x02F56665E3894267ULL,
		0x41C359F3D7749872ULL,
		0x571CC394C9E44733ULL,
		0xE11DEABF0F41627DULL,
		0xF5EBA78C45FDD65DULL,
		0x67ED134C5C3C785DULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x56095C5365F8E334ULL,
		0xC018CFCC1239237BULL,
		0xB31C3FCAB84EF929ULL,
		0xE88440CDCB9D770AULL,
		0x21B9E7520B9EFCD5ULL,
		0x5480FFDE3E6C19F9ULL,
		0x50DC183F4197FB1CULL,
		0x068B03654D41E514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC12B8A6CBF1C668ULL,
		0x80319F98247246F6ULL,
		0x66387F95709DF253ULL,
		0xD108819B973AEE15ULL,
		0x4373CEA4173DF9ABULL,
		0xA901FFBC7CD833F2ULL,
		0xA1B8307E832FF638ULL,
		0x0D1606CA9A83CA28ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x63EBF6A810C8A72FULL,
		0x39B2A440DC66B2FEULL,
		0x712FAF7979F185F1ULL,
		0xCD43A211AF3FC35EULL,
		0x1DC03AB0925CE8C3ULL,
		0xD3CDB0A00F1DCC8AULL,
		0x137E4984D4D809FBULL,
		0x210DD795E5EC7617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D7ED5021914E5EULL,
		0x73654881B8CD65FCULL,
		0xE25F5EF2F3E30BE2ULL,
		0x9A8744235E7F86BCULL,
		0x3B80756124B9D187ULL,
		0xA79B61401E3B9914ULL,
		0x26FC9309A9B013F7ULL,
		0x421BAF2BCBD8EC2EULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB6739A117F76BF2BULL,
		0x8A1753EE902BA821ULL,
		0x23428DC4BE71DB7BULL,
		0xAAF32C719B2DEDC4ULL,
		0x253D27EBF9650F9BULL,
		0x844C7F00E7071BBFULL,
		0x490612C9DF87B7B5ULL,
		0x3AE0F7A77C6536FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE73422FEED7E56ULL,
		0x142EA7DD20575043ULL,
		0x46851B897CE3B6F7ULL,
		0x55E658E3365BDB88ULL,
		0x4A7A4FD7F2CA1F37ULL,
		0x0898FE01CE0E377EULL,
		0x920C2593BF0F6F6BULL,
		0x75C1EF4EF8CA6DF6ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC554EACFAD825022ULL,
		0x8C707DDCB70B9DBDULL,
		0x47EAF00CD394DDFEULL,
		0x2E30C1375743C29CULL,
		0x783FE6F650618CD5ULL,
		0x361655B645F0CEBCULL,
		0x0262952799FF4125ULL,
		0x0B55AF464428F907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA9D59F5B04A044ULL,
		0x18E0FBB96E173B7BULL,
		0x8FD5E019A729BBFDULL,
		0x5C61826EAE878538ULL,
		0xF07FCDECA0C319AAULL,
		0x6C2CAB6C8BE19D78ULL,
		0x04C52A4F33FE824AULL,
		0x16AB5E8C8851F20EULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3E149144960FA274ULL,
		0xDBEF1080C261287EULL,
		0x917D309280419B9DULL,
		0x51E787DEEFB9AE47ULL,
		0x820E84F5CDA8C9BFULL,
		0x5BADE0C457991E7CULL,
		0x538FF2BC0C720792ULL,
		0x362BAB5B97346932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2922892C1F44E8ULL,
		0xB7DE210184C250FCULL,
		0x22FA61250083373BULL,
		0xA3CF0FBDDF735C8FULL,
		0x041D09EB9B51937EULL,
		0xB75BC188AF323CF9ULL,
		0xA71FE57818E40F24ULL,
		0x6C5756B72E68D264ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7B94DE8F134EF8DULL,
		0x6AA62F951EBB5EB2ULL,
		0xDBE62D8DF3627EBEULL,
		0x45F9F73CB00D90B4ULL,
		0x5987452EB1DD3CC5ULL,
		0x5E3CB2CEC9F1B5B8ULL,
		0x55C52F610B2C3EB5ULL,
		0x157A33EE8FAE0196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F729BD1E269DF1AULL,
		0xD54C5F2A3D76BD65ULL,
		0xB7CC5B1BE6C4FD7CULL,
		0x8BF3EE79601B2169ULL,
		0xB30E8A5D63BA798AULL,
		0xBC79659D93E36B70ULL,
		0xAB8A5EC216587D6AULL,
		0x2AF467DD1F5C032CULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF68093B3F728CC77ULL,
		0xA97A504FAF34AC21ULL,
		0x346A9670E78E8756ULL,
		0x60F9A38553056B43ULL,
		0x76D70EFB05BF6D3AULL,
		0xD5C5D3FA2E8481E1ULL,
		0x17FE01EF9FB2111EULL,
		0x1027075CA1158030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED012767EE5198EEULL,
		0x52F4A09F5E695843ULL,
		0x68D52CE1CF1D0EADULL,
		0xC1F3470AA60AD686ULL,
		0xEDAE1DF60B7EDA74ULL,
		0xAB8BA7F45D0903C2ULL,
		0x2FFC03DF3F64223DULL,
		0x204E0EB9422B0060ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC403DD605F2C9ECULL,
		0x58258A992A08195DULL,
		0xB70240627C90E527ULL,
		0x8B680B6B01FBFCA2ULL,
		0x95CBF645E142AA5EULL,
		0x640F72BA2F69B352ULL,
		0x4DECE4165EA619EFULL,
		0x2F8E0B0EED1843A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58807BAC0BE593D8ULL,
		0xB04B1532541032BBULL,
		0x6E0480C4F921CA4EULL,
		0x16D016D603F7F945ULL,
		0x2B97EC8BC28554BDULL,
		0xC81EE5745ED366A5ULL,
		0x9BD9C82CBD4C33DEULL,
		0x5F1C161DDA308744ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x76C85ABC997FCD4AULL,
		0x0849A2C2B2D58412ULL,
		0xD8730D871DD8E16EULL,
		0x1CF22313E21A57E1ULL,
		0x263A05DC37ADDAB9ULL,
		0x63BE58338C65AEA0ULL,
		0x32BF5C24D72D4E1FULL,
		0x2BBCB5A3EBF66D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED90B57932FF9A94ULL,
		0x1093458565AB0824ULL,
		0xB0E61B0E3BB1C2DCULL,
		0x39E44627C434AFC3ULL,
		0x4C740BB86F5BB572ULL,
		0xC77CB06718CB5D40ULL,
		0x657EB849AE5A9C3EULL,
		0x57796B47D7ECDAFEULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE9AE97F182BCEA58ULL,
		0x6CF8B7E891CD2668ULL,
		0xD7FBF1045AA3DC36ULL,
		0x981D876FC9907715ULL,
		0xCBF72B4E46461F3EULL,
		0x0B153B50BD72637AULL,
		0xEDC9B714E1199655ULL,
		0x016C74D547F2E7B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35D2FE30579D4B0ULL,
		0xD9F16FD1239A4CD1ULL,
		0xAFF7E208B547B86CULL,
		0x303B0EDF9320EE2BULL,
		0x97EE569C8C8C3E7DULL,
		0x162A76A17AE4C6F5ULL,
		0xDB936E29C2332CAAULL,
		0x02D8E9AA8FE5CF65ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x66A585B49E003CACULL,
		0x85FB9B87A6513D6EULL,
		0xFCA037CC6816E6A2ULL,
		0xF4B6D865EDE4112BULL,
		0x04E8DB52EEE81D40ULL,
		0xAFF7FBBE4053DC3DULL,
		0xD92CCE5DF7DE42E1ULL,
		0x27F4B38245732148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4B0B693C007958ULL,
		0x0BF7370F4CA27ADCULL,
		0xF9406F98D02DCD45ULL,
		0xE96DB0CBDBC82257ULL,
		0x09D1B6A5DDD03A81ULL,
		0x5FEFF77C80A7B87AULL,
		0xB2599CBBEFBC85C3ULL,
		0x4FE967048AE64291ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDAD521121FDF5F32ULL,
		0x1EAA56BE22164292ULL,
		0x7EECEEEDDCDF761CULL,
		0xABE72097DEE1F064ULL,
		0x220C50162FE3BAB2ULL,
		0x8D3CB8F4FD9F8A9FULL,
		0xB11103BE2D0E2C3DULL,
		0x2FDBEDA8CB0BD0C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5AA42243FBEBE64ULL,
		0x3D54AD7C442C8525ULL,
		0xFDD9DDDBB9BEEC38ULL,
		0x57CE412FBDC3E0C8ULL,
		0x4418A02C5FC77565ULL,
		0x1A7971E9FB3F153EULL,
		0x6222077C5A1C587BULL,
		0x5FB7DB519617A181ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x54B1D8FA2F781B1AULL,
		0x4466A52B499C54F0ULL,
		0x5BED86367ACF20A2ULL,
		0x6D6B2888584A5EF0ULL,
		0x0F9C9BCDBBE4AD7BULL,
		0xCF5F0BD80AD3C7DFULL,
		0x08C1945FB851DAE0ULL,
		0x0F6C2B70ADE6FFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA963B1F45EF03634ULL,
		0x88CD4A569338A9E0ULL,
		0xB7DB0C6CF59E4144ULL,
		0xDAD65110B094BDE0ULL,
		0x1F39379B77C95AF6ULL,
		0x9EBE17B015A78FBEULL,
		0x118328BF70A3B5C1ULL,
		0x1ED856E15BCDFFFAULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x564B7093E7E1726FULL,
		0x6723811A48757029ULL,
		0x781E4DD72EC793F5ULL,
		0xBB064F45620F548EULL,
		0xB0C2AAEB06023827ULL,
		0xFC34B2F5B61B8282ULL,
		0x795FF9AE1E31A044ULL,
		0x31F0A5E7A649AABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC96E127CFC2E4DEULL,
		0xCE47023490EAE052ULL,
		0xF03C9BAE5D8F27EAULL,
		0x760C9E8AC41EA91CULL,
		0x618555D60C04704FULL,
		0xF86965EB6C370505ULL,
		0xF2BFF35C3C634089ULL,
		0x63E14BCF4C935576ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC7F0A4233C6E7949ULL,
		0xA3850B8A874A9349ULL,
		0x7B5A178FB4FB0AF0ULL,
		0x10F151CBB2CC33D3ULL,
		0xB763C2A54E216EF8ULL,
		0x2214264461947CCFULL,
		0x81AB8578EDAF3A1DULL,
		0x0DD19BD7EE0D8700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE1484678DCF292ULL,
		0x470A17150E952693ULL,
		0xF6B42F1F69F615E1ULL,
		0x21E2A397659867A6ULL,
		0x6EC7854A9C42DDF0ULL,
		0x44284C88C328F99FULL,
		0x03570AF1DB5E743AULL,
		0x1BA337AFDC1B0E01ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB325DE02E18FFDA7ULL,
		0xE751D8A6500D7E7AULL,
		0xA389305A0F633A23ULL,
		0xF60025D87F0F46DEULL,
		0x26B1455F0691E528ULL,
		0x01FD6DDE196A1F2DULL,
		0x002F448CA9CEBDCEULL,
		0x1688F5ED20905821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x664BBC05C31FFB4EULL,
		0xCEA3B14CA01AFCF5ULL,
		0x471260B41EC67447ULL,
		0xEC004BB0FE1E8DBDULL,
		0x4D628ABE0D23CA51ULL,
		0x03FADBBC32D43E5AULL,
		0x005E8919539D7B9CULL,
		0x2D11EBDA4120B042ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x88B803E987B1F10BULL,
		0x7B1B130983448E5DULL,
		0x88553611818B3E71ULL,
		0x77ED4C3C542AA172ULL,
		0x7B4992CABEB92A19ULL,
		0x530D8B2CBD903E05ULL,
		0x252D993A4C1CC870ULL,
		0x1F244001594D9971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117007D30F63E216ULL,
		0xF636261306891CBBULL,
		0x10AA6C2303167CE2ULL,
		0xEFDA9878A85542E5ULL,
		0xF69325957D725432ULL,
		0xA61B16597B207C0AULL,
		0x4A5B3274983990E0ULL,
		0x3E488002B29B32E2ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA8B7E8F7DD973920ULL,
		0x319CE21D8E5A2E9DULL,
		0x9A2F2738CEA4CFAEULL,
		0xC91911762290B7D4ULL,
		0xB607DE1EA0DABF11ULL,
		0xB03BB361BF308B5EULL,
		0xE9BB5E695304BD35ULL,
		0x37B5F6B1C3F3F84AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516FD1EFBB2E7240ULL,
		0x6339C43B1CB45D3BULL,
		0x345E4E719D499F5CULL,
		0x923222EC45216FA9ULL,
		0x6C0FBC3D41B57E23ULL,
		0x607766C37E6116BDULL,
		0xD376BCD2A6097A6BULL,
		0x6F6BED6387E7F095ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC26F54576AB377F4ULL,
		0x673166B71D4024DAULL,
		0x6A4B608630D0DB3EULL,
		0xAA19359E3C94572AULL,
		0x2621B7F13321282AULL,
		0xAADC2BDFCE3AA9D0ULL,
		0xB38E7AB9E95722B7ULL,
		0x00147DCB9A237FC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84DEA8AED566EFE8ULL,
		0xCE62CD6E3A8049B5ULL,
		0xD496C10C61A1B67CULL,
		0x54326B3C7928AE54ULL,
		0x4C436FE266425055ULL,
		0x55B857BF9C7553A0ULL,
		0x671CF573D2AE456FULL,
		0x0028FB973446FF8BULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6B570008E292FF1BULL,
		0x16F4AA060A296CD6ULL,
		0xD58B9266FB01CC28ULL,
		0xCBDB22781C79114AULL,
		0x8FE8090910A9DB47ULL,
		0xF5AFD5E20A8FB15AULL,
		0xA403EE5A6B71916BULL,
		0x143940F6AA48B5A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6AE0011C525FE36ULL,
		0x2DE9540C1452D9ACULL,
		0xAB1724CDF6039850ULL,
		0x97B644F038F22295ULL,
		0x1FD012122153B68FULL,
		0xEB5FABC4151F62B5ULL,
		0x4807DCB4D6E322D7ULL,
		0x287281ED54916B41ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5B209820BB200DF0ULL,
		0xC475F3AA81554073ULL,
		0x80EA5BEC75485D17ULL,
		0x04D4B55A7DE2B070ULL,
		0x14542402A819049BULL,
		0x886524EBEF8FA982ULL,
		0x07F7533A18F93AE1ULL,
		0x38502B562651E75EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB641304176401BE0ULL,
		0x88EBE75502AA80E6ULL,
		0x01D4B7D8EA90BA2FULL,
		0x09A96AB4FBC560E1ULL,
		0x28A8480550320936ULL,
		0x10CA49D7DF1F5304ULL,
		0x0FEEA67431F275C3ULL,
		0x70A056AC4CA3CEBCULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x51AD4770E2CCC3DEULL,
		0xD5BF734F850BFAC6ULL,
		0x9204A180E498049AULL,
		0x9115893796F96A60ULL,
		0xD064959AAC59C64BULL,
		0x29AFD8A61D2E6E91ULL,
		0x0B748AE7136AE0D4ULL,
		0x37A7658E8C9F33D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35A8EE1C59987BCULL,
		0xAB7EE69F0A17F58CULL,
		0x24094301C9300935ULL,
		0x222B126F2DF2D4C1ULL,
		0xA0C92B3558B38C97ULL,
		0x535FB14C3A5CDD23ULL,
		0x16E915CE26D5C1A8ULL,
		0x6F4ECB1D193E67A4ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xABD759CA22D8284FULL,
		0xC6CE262AB50E245DULL,
		0x3A401C0AF528B5F7ULL,
		0xD519254C07115FE5ULL,
		0x0A13C8719005B40DULL,
		0xCEBAA9AEE447C23AULL,
		0xC86844800B253478ULL,
		0x20DA8140C5EE44BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AEB39445B0509EULL,
		0x8D9C4C556A1C48BBULL,
		0x74803815EA516BEFULL,
		0xAA324A980E22BFCAULL,
		0x142790E3200B681BULL,
		0x9D75535DC88F8474ULL,
		0x90D08900164A68F1ULL,
		0x41B502818BDC897DULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1BFA9365CFACF28DULL,
		0xAF83F90A87F8E69FULL,
		0x18A0C34DCB3D0EA9ULL,
		0x5F55654F22249C5BULL,
		0xBCC3131194C7F7DAULL,
		0xABBBE97D12AA826CULL,
		0x88BEB46980FF348FULL,
		0x0F623D90A3D85B83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F526CB9F59E51AULL,
		0x5F07F2150FF1CD3EULL,
		0x3141869B967A1D53ULL,
		0xBEAACA9E444938B6ULL,
		0x79862623298FEFB4ULL,
		0x5777D2FA255504D9ULL,
		0x117D68D301FE691FULL,
		0x1EC47B2147B0B707ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2785405FF2630C72ULL,
		0x59C009F28AC63782ULL,
		0x88C7797769227514ULL,
		0xA009011EE9B3C70BULL,
		0x9E3684C7341490DFULL,
		0xD637D64827FD812DULL,
		0x78FF6B478DDE232CULL,
		0x0A9636BA84C23993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F0A80BFE4C618E4ULL,
		0xB38013E5158C6F04ULL,
		0x118EF2EED244EA28ULL,
		0x4012023DD3678E17ULL,
		0x3C6D098E682921BFULL,
		0xAC6FAC904FFB025BULL,
		0xF1FED68F1BBC4659ULL,
		0x152C6D7509847326ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E0FF1506B866D5BULL,
		0x31F40D7AEC64FEF5ULL,
		0xD683A8FC01C32051ULL,
		0x72EA3C332483FE60ULL,
		0x0EAE14E102879403ULL,
		0x8F20D8A9B5B4BF49ULL,
		0xFDC3ECE4E4AB0EC7ULL,
		0x0F65FAE9559C8986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1FE2A0D70CDAB6ULL,
		0x63E81AF5D8C9FDEAULL,
		0xAD0751F8038640A2ULL,
		0xE5D478664907FCC1ULL,
		0x1D5C29C2050F2806ULL,
		0x1E41B1536B697E92ULL,
		0xFB87D9C9C9561D8FULL,
		0x1ECBF5D2AB39130DULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20721400602FE534ULL,
		0x26D5767D7DCD16D2ULL,
		0x9462C508114BE510ULL,
		0x0377ECE803927DD4ULL,
		0x499A2F44384E865DULL,
		0xB85B13ED97C780CFULL,
		0xB0267360C755010EULL,
		0x2D9CF1491E2806C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E42800C05FCA68ULL,
		0x4DAAECFAFB9A2DA4ULL,
		0x28C58A102297CA20ULL,
		0x06EFD9D00724FBA9ULL,
		0x93345E88709D0CBAULL,
		0x70B627DB2F8F019EULL,
		0x604CE6C18EAA021DULL,
		0x5B39E2923C500D8BULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4A8C6F6975061982ULL,
		0xFFBF6D6825750421ULL,
		0xFE52A6F68A15701AULL,
		0x17C6AD6DDDE1DFAAULL,
		0xEDC459B26ED34349ULL,
		0x8776C5FC4B343CC3ULL,
		0xD6178E1D8E5E75BAULL,
		0x12B2B73090814880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9518DED2EA0C3304ULL,
		0xFF7EDAD04AEA0842ULL,
		0xFCA54DED142AE035ULL,
		0x2F8D5ADBBBC3BF55ULL,
		0xDB88B364DDA68692ULL,
		0x0EED8BF896687987ULL,
		0xAC2F1C3B1CBCEB75ULL,
		0x25656E6121029101ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC41F5AC3E2EB63AULL,
		0xF307C248CE2F2786ULL,
		0xF4EFF4F465C2EF1CULL,
		0x7A30EA6B2247DB9AULL,
		0x8EFB4C4E85835252ULL,
		0x5702E79402D220A0ULL,
		0x4BF2A163C6584B30ULL,
		0x347A18EFF6EDB80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5883EB587C5D6C74ULL,
		0xE60F84919C5E4F0DULL,
		0xE9DFE9E8CB85DE39ULL,
		0xF461D4D6448FB735ULL,
		0x1DF6989D0B06A4A4ULL,
		0xAE05CF2805A44141ULL,
		0x97E542C78CB09660ULL,
		0x68F431DFEDDB701AULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x16615BB040874C83ULL,
		0x1DAB7B958377C370ULL,
		0xAA53D90AEAE85026ULL,
		0xE94BF2108A38B70AULL,
		0x91198BF87A23B56FULL,
		0x049F29FA27D976AFULL,
		0x84EFF6805C31E758ULL,
		0x305E56ABD9C1AFB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC2B760810E9906ULL,
		0x3B56F72B06EF86E0ULL,
		0x54A7B215D5D0A04CULL,
		0xD297E42114716E15ULL,
		0x223317F0F4476ADFULL,
		0x093E53F44FB2ED5FULL,
		0x09DFED00B863CEB0ULL,
		0x60BCAD57B3835F6FULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x83DEA3D164D4D612ULL,
		0xC584031DC0036DA3ULL,
		0x9E1E5B9BFADA6FEBULL,
		0xA7DB9FEBE495174BULL,
		0xA4D026BC4A29AE39ULL,
		0x74859CCF88561277ULL,
		0x45BED65F61F43734ULL,
		0x332F7893B7252D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BD47A2C9A9AC24ULL,
		0x8B08063B8006DB47ULL,
		0x3C3CB737F5B4DFD7ULL,
		0x4FB73FD7C92A2E97ULL,
		0x49A04D7894535C73ULL,
		0xE90B399F10AC24EFULL,
		0x8B7DACBEC3E86E68ULL,
		0x665EF1276E4A5B32ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2D6928E9A18A242DULL,
		0xF389A1AD5F2EF5D2ULL,
		0x7133C53946631414ULL,
		0x201BE6C6CFB817F3ULL,
		0x8CF3DFEA18D97768ULL,
		0x44EC82379FEEC529ULL,
		0xF36638F5BBB7CA35ULL,
		0x1E756676E2CA712CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD251D34314485AULL,
		0xE713435ABE5DEBA4ULL,
		0xE2678A728CC62829ULL,
		0x4037CD8D9F702FE6ULL,
		0x19E7BFD431B2EED0ULL,
		0x89D9046F3FDD8A53ULL,
		0xE6CC71EB776F946AULL,
		0x3CEACCEDC594E259ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1E31E8E8603E1FE8ULL,
		0x421619013009CC2AULL,
		0x90F4CD6F22E2B8F3ULL,
		0x8EC648F5B72BF9C2ULL,
		0xB92C06519AC0B2E8ULL,
		0x737DB085FB7F4272ULL,
		0x9B0F95C2697ABBD7ULL,
		0x1015F10E336A669CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C63D1D0C07C3FD0ULL,
		0x842C320260139854ULL,
		0x21E99ADE45C571E6ULL,
		0x1D8C91EB6E57F385ULL,
		0x72580CA3358165D1ULL,
		0xE6FB610BF6FE84E5ULL,
		0x361F2B84D2F577AEULL,
		0x202BE21C66D4CD39ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDFE2A5458E992059ULL,
		0xCD4451FDECDFDE4AULL,
		0x853AC88EEA8EF637ULL,
		0x7BF5A8DD59EAD82CULL,
		0xE5A9A147688110B6ULL,
		0xA5122618B75B38A5ULL,
		0xD6472A8A185EEDCBULL,
		0x3A9193B9E6485A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC54A8B1D3240B2ULL,
		0x9A88A3FBD9BFBC95ULL,
		0x0A75911DD51DEC6FULL,
		0xF7EB51BAB3D5B059ULL,
		0xCB53428ED102216CULL,
		0x4A244C316EB6714BULL,
		0xAC8E551430BDDB97ULL,
		0x75232773CC90B4C3ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B600F9FA137FAB5ULL,
		0xE37D87836509D269ULL,
		0x990A7D5807929742ULL,
		0x2B0E6DF88CA1EE96ULL,
		0xA41848A0F3AD4BF1ULL,
		0x93D84B191A99FAC6ULL,
		0xB67CCBB41E76FFACULL,
		0x1B3196AF382540DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C01F3F426FF56AULL,
		0xC6FB0F06CA13A4D2ULL,
		0x3214FAB00F252E85ULL,
		0x561CDBF11943DD2DULL,
		0x48309141E75A97E2ULL,
		0x27B096323533F58DULL,
		0x6CF997683CEDFF59ULL,
		0x36632D5E704A81BBULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08CC8103248CEA2BULL,
		0x340CCC88ADB0B8EBULL,
		0x8FAA9C2921DA8C50ULL,
		0x0433157E0256FEACULL,
		0xF636E125BE7FCA68ULL,
		0xF1B0CC05310F8F77ULL,
		0x374CF85B820A5782ULL,
		0x39DB009DE2CDA881ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119902064919D456ULL,
		0x681999115B6171D6ULL,
		0x1F55385243B518A0ULL,
		0x08662AFC04ADFD59ULL,
		0xEC6DC24B7CFF94D0ULL,
		0xE361980A621F1EEFULL,
		0x6E99F0B70414AF05ULL,
		0x73B6013BC59B5102ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x45E0B72F304270F3ULL,
		0xCAA370819FCCFB67ULL,
		0x33C1E17DD449DE57ULL,
		0x3BA6AA9D9EBC3A1EULL,
		0x77BDF34D6B7CB42DULL,
		0x945C8B847A245EFBULL,
		0xACD44C00F70FF9A7ULL,
		0x161A1A59722A6129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BC16E5E6084E1E6ULL,
		0x9546E1033F99F6CEULL,
		0x6783C2FBA893BCAFULL,
		0x774D553B3D78743CULL,
		0xEF7BE69AD6F9685AULL,
		0x28B91708F448BDF6ULL,
		0x59A89801EE1FF34FULL,
		0x2C3434B2E454C253ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD6538CA64E832277ULL,
		0x35F45CC0E3F10161ULL,
		0xEADBE50F02B35601ULL,
		0x875C66B709FA7AC5ULL,
		0x0387418C51C266DFULL,
		0x49D3C46DC063A5C3ULL,
		0x646A717F35ADB8B1ULL,
		0x096BCF529341F991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA7194C9D0644EEULL,
		0x6BE8B981C7E202C3ULL,
		0xD5B7CA1E0566AC02ULL,
		0x0EB8CD6E13F4F58BULL,
		0x070E8318A384CDBFULL,
		0x93A788DB80C74B86ULL,
		0xC8D4E2FE6B5B7162ULL,
		0x12D79EA52683F322ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07728A50A1F4E978ULL,
		0x34EB23F15BAE8BEEULL,
		0xB9EE15E3EE06A7C0ULL,
		0x52F86FF03B2F1620ULL,
		0x08A957EFEC8A2DB0ULL,
		0xA6685481196EC3B0ULL,
		0x8E5AF8D038B5F253ULL,
		0x2FD6108ACE4BA3A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE514A143E9D2F0ULL,
		0x69D647E2B75D17DCULL,
		0x73DC2BC7DC0D4F80ULL,
		0xA5F0DFE0765E2C41ULL,
		0x1152AFDFD9145B60ULL,
		0x4CD0A90232DD8760ULL,
		0x1CB5F1A0716BE4A7ULL,
		0x5FAC21159C974743ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3BF3D8E54052408DULL,
		0xA9CAAF9CEE16E49EULL,
		0x259B373CFD0F6C1FULL,
		0x26658F6884952454ULL,
		0xDE6A062202FFF234ULL,
		0xD7E228A698ED4E4DULL,
		0x2FBAA6A1B5C23C3EULL,
		0x157C85975DE6795EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77E7B1CA80A4811AULL,
		0x53955F39DC2DC93CULL,
		0x4B366E79FA1ED83FULL,
		0x4CCB1ED1092A48A8ULL,
		0xBCD40C4405FFE468ULL,
		0xAFC4514D31DA9C9BULL,
		0x5F754D436B84787DULL,
		0x2AF90B2EBBCCF2BCULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2EF159270DC8334FULL,
		0xBED45E0C957A48C0ULL,
		0xDC5B1BF6F509B447ULL,
		0x9052B67CFAC4F999ULL,
		0xBB37C51BC3276B70ULL,
		0x560192E877ED0727ULL,
		0x8822F9801774BFDBULL,
		0x1E4ED0DBCB8EC475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DE2B24E1B90669EULL,
		0x7DA8BC192AF49180ULL,
		0xB8B637EDEA13688FULL,
		0x20A56CF9F589F333ULL,
		0x766F8A37864ED6E1ULL,
		0xAC0325D0EFDA0E4FULL,
		0x1045F3002EE97FB6ULL,
		0x3C9DA1B7971D88EBULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12CFEB297E010F26ULL,
		0x00F032057927E3CFULL,
		0x1B808FDBD71F9ACEULL,
		0x95DF9F891DF01294ULL,
		0x2AAF6EC6F4FF1A0FULL,
		0x8EBDAE7869316C50ULL,
		0xE9E32D4EE368AF14ULL,
		0x2476B28CA70A22DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x259FD652FC021E4CULL,
		0x01E0640AF24FC79EULL,
		0x37011FB7AE3F359CULL,
		0x2BBF3F123BE02528ULL,
		0x555EDD8DE9FE341FULL,
		0x1D7B5CF0D262D8A0ULL,
		0xD3C65A9DC6D15E29ULL,
		0x48ED65194E1445BBULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF06E600D3F646845ULL,
		0xAC8A82DE6D4F1F09ULL,
		0x30A877C83D71DC9BULL,
		0xC3F91BB4DEDE75EAULL,
		0x452A08E8F3F9C044ULL,
		0x5737549B73F5E8C3ULL,
		0xBEE55AEB1290B902ULL,
		0x2DA4B24E699F775CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0DCC01A7EC8D08AULL,
		0x591505BCDA9E3E13ULL,
		0x6150EF907AE3B937ULL,
		0x87F23769BDBCEBD4ULL,
		0x8A5411D1E7F38089ULL,
		0xAE6EA936E7EBD186ULL,
		0x7DCAB5D625217204ULL,
		0x5B49649CD33EEEB9ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2439EC02F06D05EDULL,
		0xEEA4FB8D6AC3E28AULL,
		0xC7A350D1A8693A5DULL,
		0xF5BCEA90EE0E1226ULL,
		0x118270A9A8B19609ULL,
		0xFDEBB75AA06BE7C6ULL,
		0x1FA3964712ACB8B3ULL,
		0x2D4D046C443305B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4873D805E0DA0BDAULL,
		0xDD49F71AD587C514ULL,
		0x8F46A1A350D274BBULL,
		0xEB79D521DC1C244DULL,
		0x2304E15351632C13ULL,
		0xFBD76EB540D7CF8CULL,
		0x3F472C8E25597167ULL,
		0x5A9A08D888660B64ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDE9492A581624660ULL,
		0x292B28979EAF1AC7ULL,
		0x3ADD55C650AAC7B6ULL,
		0xE740CC549B972271ULL,
		0xE87CA693768B6C90ULL,
		0x3467675C116245ECULL,
		0xB78BE4B7D234A20DULL,
		0x1CDD4182032BFC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD29254B02C48CC0ULL,
		0x5256512F3D5E358FULL,
		0x75BAAB8CA1558F6CULL,
		0xCE8198A9372E44E2ULL,
		0xD0F94D26ED16D921ULL,
		0x68CECEB822C48BD9ULL,
		0x6F17C96FA469441AULL,
		0x39BA83040657F90BULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE039D7E13188B89BULL,
		0x745D960BAD193627ULL,
		0x18CE3B6BCDB605EBULL,
		0x9433A3EAEBB336BEULL,
		0xAA478EE54E0EC798ULL,
		0x7F6B9C34683ED203ULL,
		0x4B5B197EE81F1590ULL,
		0x2415D573B67A38F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC073AFC263117136ULL,
		0xE8BB2C175A326C4FULL,
		0x319C76D79B6C0BD6ULL,
		0x286747D5D7666D7CULL,
		0x548F1DCA9C1D8F31ULL,
		0xFED73868D07DA407ULL,
		0x96B632FDD03E2B20ULL,
		0x482BAAE76CF471E0ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x88A33799EB3F0400ULL,
		0x051C5B6181D94D91ULL,
		0x58E4C836EA5A8BA3ULL,
		0xFB3D134AE88C6B3FULL,
		0x9612D881BAFC43B6ULL,
		0x03C75743A9E06DE9ULL,
		0x0AD87B69F9F31490ULL,
		0x2DFD727D1A44E651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11466F33D67E0800ULL,
		0x0A38B6C303B29B23ULL,
		0xB1C9906DD4B51746ULL,
		0xF67A2695D118D67EULL,
		0x2C25B10375F8876DULL,
		0x078EAE8753C0DBD3ULL,
		0x15B0F6D3F3E62920ULL,
		0x5BFAE4FA3489CCA2ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6043AFC5FDAD3B24ULL,
		0xB3D68D4F446F215EULL,
		0xE81991081B354D7DULL,
		0x8E2450345CE44E42ULL,
		0xFED67B7FA176067DULL,
		0x6138DA3238107803ULL,
		0x31405262F80E0EABULL,
		0x3B721F57E352F019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0875F8BFB5A7648ULL,
		0x67AD1A9E88DE42BCULL,
		0xD0332210366A9AFBULL,
		0x1C48A068B9C89C85ULL,
		0xFDACF6FF42EC0CFBULL,
		0xC271B4647020F007ULL,
		0x6280A4C5F01C1D56ULL,
		0x76E43EAFC6A5E032ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFAF2F8829B4E0B85ULL,
		0x0AA9109D27FACB2BULL,
		0x0352404EFF59EC6CULL,
		0x275A91E78B5B153EULL,
		0x15CBE75F9E1FBC84ULL,
		0x4E579746AC3440F5ULL,
		0xC40E728DCF9F8DF2ULL,
		0x22F892C5C27CBAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E5F105369C170AULL,
		0x1552213A4FF59657ULL,
		0x06A4809DFEB3D8D8ULL,
		0x4EB523CF16B62A7CULL,
		0x2B97CEBF3C3F7908ULL,
		0x9CAF2E8D586881EAULL,
		0x881CE51B9F3F1BE4ULL,
		0x45F1258B84F975DBULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6479E13700110D61ULL,
		0x26C34862AEBDAB1CULL,
		0x8D04B16FA9AF9429ULL,
		0x11D2AFAF7AE7FD96ULL,
		0xDE42D2B487E4EB0EULL,
		0xAB47B52D5828DA99ULL,
		0xF1A4F71EFE484FF8ULL,
		0x1555B7DDB401015FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F3C26E00221AC2ULL,
		0x4D8690C55D7B5638ULL,
		0x1A0962DF535F2852ULL,
		0x23A55F5EF5CFFB2DULL,
		0xBC85A5690FC9D61CULL,
		0x568F6A5AB051B533ULL,
		0xE349EE3DFC909FF1ULL,
		0x2AAB6FBB680202BFULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x650989BB01D0E2A6ULL,
		0xFEE58B0F1EA4518EULL,
		0x0FB14996E77C67EAULL,
		0x4ACFA49A0093DEBAULL,
		0x6E7075989E673657ULL,
		0x9F3EC702F2E14C98ULL,
		0x0151B1A79B4B230DULL,
		0x3A20B1C94C82D887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA13137603A1C54CULL,
		0xFDCB161E3D48A31CULL,
		0x1F62932DCEF8CFD5ULL,
		0x959F49340127BD74ULL,
		0xDCE0EB313CCE6CAEULL,
		0x3E7D8E05E5C29930ULL,
		0x02A3634F3696461BULL,
		0x744163929905B10EULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x53994FCEEDCBCF2CULL,
		0x17ED5A2DDB20CA66ULL,
		0xECA1CB0D0D33B611ULL,
		0xBA19596AA5B595B9ULL,
		0xA77BCB10D4E07B5DULL,
		0x5BE7A32C83B70F03ULL,
		0x0119DEDF1A96B53FULL,
		0x0D4A9626CC4ABD9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7329F9DDB979E58ULL,
		0x2FDAB45BB64194CCULL,
		0xD943961A1A676C22ULL,
		0x7432B2D54B6B2B73ULL,
		0x4EF79621A9C0F6BBULL,
		0xB7CF4659076E1E07ULL,
		0x0233BDBE352D6A7EULL,
		0x1A952C4D98957B38ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x80F9942CE1CF82D6ULL,
		0x2C34172A0FE8CF31ULL,
		0x3D22150B2A4609BCULL,
		0xAE7B37853A5EA4D7ULL,
		0xF51E666750D4AD49ULL,
		0x28156A3A91F465CFULL,
		0xFB7252E3BC0D0033ULL,
		0x27F0485B2CF7E9D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F32859C39F05ACULL,
		0x58682E541FD19E63ULL,
		0x7A442A16548C1378ULL,
		0x5CF66F0A74BD49AEULL,
		0xEA3CCCCEA1A95A93ULL,
		0x502AD47523E8CB9FULL,
		0xF6E4A5C7781A0066ULL,
		0x4FE090B659EFD3B1ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7CBD07D8FE782EBEULL,
		0xBDDE9D89B6557C57ULL,
		0xC972BAF7845752A9ULL,
		0x579E714A2150AFC8ULL,
		0xC0A8FAC7E01A59EBULL,
		0x1BED294B99D272ECULL,
		0x093661F3F25B9B27ULL,
		0x2506DCB8AA2FD21BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97A0FB1FCF05D7CULL,
		0x7BBD3B136CAAF8AEULL,
		0x92E575EF08AEA553ULL,
		0xAF3CE29442A15F91ULL,
		0x8151F58FC034B3D6ULL,
		0x37DA529733A4E5D9ULL,
		0x126CC3E7E4B7364EULL,
		0x4A0DB971545FA436ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x22EEEFE0B07868F4ULL,
		0x2C97FB2578B9647DULL,
		0x1D72A30CAB03D807ULL,
		0x85D7AE7FF74D810FULL,
		0x75317E5678EA5D2AULL,
		0x89DAAA18289E66DFULL,
		0x4B33D41B38D14661ULL,
		0x073D5322CEE519CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45DDDFC160F0D1E8ULL,
		0x592FF64AF172C8FAULL,
		0x3AE546195607B00EULL,
		0x0BAF5CFFEE9B021EULL,
		0xEA62FCACF1D4BA55ULL,
		0x13B55430513CCDBEULL,
		0x9667A83671A28CC3ULL,
		0x0E7AA6459DCA339CULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBDA07AF13E17952EULL,
		0x391AB529C0C26F7EULL,
		0x169EBE1DFB738F0DULL,
		0x7E267F9BFCE0216BULL,
		0xD1BF843E320A47B5ULL,
		0x6E962CEEBD8DD6E3ULL,
		0xB5FDD4728B9A67BAULL,
		0x014C083811AF6EEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B40F5E27C2F2A5CULL,
		0x72356A538184DEFDULL,
		0x2D3D7C3BF6E71E1AULL,
		0xFC4CFF37F9C042D6ULL,
		0xA37F087C64148F6AULL,
		0xDD2C59DD7B1BADC7ULL,
		0x6BFBA8E51734CF74ULL,
		0x02981070235EDDDBULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEC62830BC9EB25E8ULL,
		0x825D18C8E0FD688EULL,
		0xE5BEEBC48E95B3AAULL,
		0x9BEDD76FA2025CE4ULL,
		0x6185F9BCC77EF632ULL,
		0xAA6CFFDB311F917AULL,
		0x395CE6FB51A14B40ULL,
		0x1BF2246C222516EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C5061793D64BD0ULL,
		0x04BA3191C1FAD11DULL,
		0xCB7DD7891D2B6755ULL,
		0x37DBAEDF4404B9C9ULL,
		0xC30BF3798EFDEC65ULL,
		0x54D9FFB6623F22F4ULL,
		0x72B9CDF6A3429681ULL,
		0x37E448D8444A2DDEULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4E470FEFCD7BC56AULL,
		0xF5E2FAC2F74C1A33ULL,
		0xE3C2CD0D9E8B7AA4ULL,
		0x5D1E78B82739D72FULL,
		0xBD638B1B928DA6E6ULL,
		0xEA77E700A64D7391ULL,
		0x57F907C492916FC0ULL,
		0x018C24E2EC28D17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8E1FDF9AF78AD4ULL,
		0xEBC5F585EE983466ULL,
		0xC7859A1B3D16F549ULL,
		0xBA3CF1704E73AE5FULL,
		0x7AC71637251B4DCCULL,
		0xD4EFCE014C9AE723ULL,
		0xAFF20F892522DF81ULL,
		0x031849C5D851A2FCULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2FAF6832E7A73068ULL,
		0xC37542D8D3001320ULL,
		0x30097A0D1EF8303CULL,
		0x66DD5CDD8D37A857ULL,
		0xAA5CABBFFA476C59ULL,
		0x2674F0B4AC92FFEDULL,
		0x31204EE581890BC3ULL,
		0x19A834ADF125A5FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F5ED065CF4E60D0ULL,
		0x86EA85B1A6002640ULL,
		0x6012F41A3DF06079ULL,
		0xCDBAB9BB1A6F50AEULL,
		0x54B9577FF48ED8B2ULL,
		0x4CE9E1695925FFDBULL,
		0x62409DCB03121786ULL,
		0x3350695BE24B4BF8ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x324F9C06C0018621ULL,
		0x812D85D07A8D3DA6ULL,
		0xAF4A21372D347980ULL,
		0x3B0A7F03224EE078ULL,
		0x2D53233FADB1637FULL,
		0x44154EB11D753E42ULL,
		0x91C3FED088D2EBAAULL,
		0x01337FC6FCFB9614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x649F380D80030C42ULL,
		0x025B0BA0F51A7B4CULL,
		0x5E94426E5A68F301ULL,
		0x7614FE06449DC0F1ULL,
		0x5AA6467F5B62C6FEULL,
		0x882A9D623AEA7C84ULL,
		0x2387FDA111A5D754ULL,
		0x0266FF8DF9F72C29ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9174BDF1AF5E387BULL,
		0xA1446540EB10E00DULL,
		0xC85D58D65A0EF4BBULL,
		0x22CEEF211367018FULL,
		0x03FD118EE7092285ULL,
		0x0627CA4EA373FD7FULL,
		0xB602FF2B46CEA42BULL,
		0x354B31B4AE4B1C26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E97BE35EBC70F6ULL,
		0x4288CA81D621C01BULL,
		0x90BAB1ACB41DE977ULL,
		0x459DDE4226CE031FULL,
		0x07FA231DCE12450AULL,
		0x0C4F949D46E7FAFEULL,
		0x6C05FE568D9D4856ULL,
		0x6A9663695C96384DULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDF934362F1FE91FFULL,
		0xEFA9A3F2CCA94DE5ULL,
		0x52E5A3ACBC17B51DULL,
		0x9116A6F3981A0F39ULL,
		0x7DBA06099A18A0FBULL,
		0xBBC897CA5244FF65ULL,
		0x55C9DD9E05865A66ULL,
		0x28AA484CC53995DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2686C5E3FD23FEULL,
		0xDF5347E599529BCBULL,
		0xA5CB4759782F6A3BULL,
		0x222D4DE730341E72ULL,
		0xFB740C13343141F7ULL,
		0x77912F94A489FECAULL,
		0xAB93BB3C0B0CB4CDULL,
		0x515490998A732BBCULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC886E11C25E68C0FULL,
		0xC2044F2D095E40C5ULL,
		0x95234C3D321C0402ULL,
		0x9375D39BF967B1A3ULL,
		0x264899D0BA360D0EULL,
		0x9BD41BAE125339ACULL,
		0x99D50977DC7D8F91ULL,
		0x3CD5888D95364047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x910DC2384BCD181EULL,
		0x84089E5A12BC818BULL,
		0x2A46987A64380805ULL,
		0x26EBA737F2CF6347ULL,
		0x4C9133A1746C1A1DULL,
		0x37A8375C24A67358ULL,
		0x33AA12EFB8FB1F23ULL,
		0x79AB111B2A6C808FULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x34C3E11BF2ABB67BULL,
		0x7888A4A0FAE7ED5FULL,
		0x2F8F0C230EC107BAULL,
		0x4EFB9791605F5D02ULL,
		0x1BD0C07BA6FFBAB4ULL,
		0x59DFE86DDF583CAFULL,
		0xDFABFFE83C3ED9DEULL,
		0x36FC312049812D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6987C237E5576CF6ULL,
		0xF1114941F5CFDABEULL,
		0x5F1E18461D820F74ULL,
		0x9DF72F22C0BEBA04ULL,
		0x37A180F74DFF7568ULL,
		0xB3BFD0DBBEB0795EULL,
		0xBF57FFD0787DB3BCULL,
		0x6DF8624093025AD5ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF83A09A7B0EAD1ADULL,
		0xDBA16C6AFCFD945EULL,
		0x7A55E3129C70F902ULL,
		0x89704BF172AF6D50ULL,
		0x9F68B956A0263956ULL,
		0x1B9BD59EFC7D8CC6ULL,
		0xBCB2DC75641CFBC9ULL,
		0x05ACE4CB806D22F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF074134F61D5A35AULL,
		0xB742D8D5F9FB28BDULL,
		0xF4ABC62538E1F205ULL,
		0x12E097E2E55EDAA0ULL,
		0x3ED172AD404C72ADULL,
		0x3737AB3DF8FB198DULL,
		0x7965B8EAC839F792ULL,
		0x0B59C99700DA45EDULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x164602A6C5E78B84ULL,
		0xFD09BE747655FA3EULL,
		0x9BE07D87698BE00BULL,
		0x0AF7E247A46E78DEULL,
		0x2824FC8B19317531ULL,
		0x89B135ED82DA9567ULL,
		0x19658D99C2EA8580ULL,
		0x1F7F6F91A28790E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8C054D8BCF1708ULL,
		0xFA137CE8ECABF47CULL,
		0x37C0FB0ED317C017ULL,
		0x15EFC48F48DCF1BDULL,
		0x5049F9163262EA62ULL,
		0x13626BDB05B52ACEULL,
		0x32CB1B3385D50B01ULL,
		0x3EFEDF23450F21C0ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA7FF7CCF053591B1ULL,
		0xA4B03F068F0CDE91ULL,
		0x88C9FB59823280AFULL,
		0x839892F512DFBC97ULL,
		0x28186388A42FC7A0ULL,
		0x1572BE7662685ED1ULL,
		0x569ECA45A78BCB0EULL,
		0x1942FCE87C01F18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFEF99E0A6B2362ULL,
		0x49607E0D1E19BD23ULL,
		0x1193F6B30465015FULL,
		0x073125EA25BF792FULL,
		0x5030C711485F8F41ULL,
		0x2AE57CECC4D0BDA2ULL,
		0xAD3D948B4F17961CULL,
		0x3285F9D0F803E31EULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB5E6B19301CA7B5AULL,
		0xF3BF9AB097470902ULL,
		0xC19EE8E03D19A296ULL,
		0x384A88B7449FC06AULL,
		0x442376D7833EB6D5ULL,
		0x26C2A9C7ECA233AFULL,
		0x41F9EBBDF6033E2BULL,
		0x25BE8137B1F7ACA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BCD63260394F6B4ULL,
		0xE77F35612E8E1205ULL,
		0x833DD1C07A33452DULL,
		0x7095116E893F80D5ULL,
		0x8846EDAF067D6DAAULL,
		0x4D85538FD944675EULL,
		0x83F3D77BEC067C56ULL,
		0x4B7D026F63EF594EULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAB9ABFA94614D52FULL,
		0x67BC9802A0A6093AULL,
		0x772B99128E0A5896ULL,
		0x9F4E8C6ED3C03051ULL,
		0x3838AC776FA905E5ULL,
		0xC2C79E8B68A0C145ULL,
		0xEF3DCA14FD052E0FULL,
		0x3493E9F7009FD4F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57357F528C29AA5EULL,
		0xCF793005414C1275ULL,
		0xEE5732251C14B12CULL,
		0x3E9D18DDA78060A2ULL,
		0x707158EEDF520BCBULL,
		0x858F3D16D141828AULL,
		0xDE7B9429FA0A5C1FULL,
		0x6927D3EE013FA9F3ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3581144F05A21AE5ULL,
		0xACF7EC78FC327087ULL,
		0x0F5C076717A7BE37ULL,
		0x79B6A86C714A5973ULL,
		0x9394EF4E1E5B0EA1ULL,
		0x4D7DEAC544A21D04ULL,
		0x2D1B66EEC0DCAFFEULL,
		0x04631DB673F09B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B02289E0B4435CAULL,
		0x59EFD8F1F864E10EULL,
		0x1EB80ECE2F4F7C6FULL,
		0xF36D50D8E294B2E6ULL,
		0x2729DE9C3CB61D42ULL,
		0x9AFBD58A89443A09ULL,
		0x5A36CDDD81B95FFCULL,
		0x08C63B6CE7E1360EULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9803CC8337BAFCB3ULL,
		0x8F63D78C908FBAE8ULL,
		0xB4A39F9EEF54123CULL,
		0xDB3B9EA791DADB49ULL,
		0xBC391E83CC9FFF2EULL,
		0xE6BEED67F72D1190ULL,
		0x4A021BBBB020138AULL,
		0x3615CCC34A589888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x300799066F75F966ULL,
		0x1EC7AF19211F75D1ULL,
		0x69473F3DDEA82479ULL,
		0xB6773D4F23B5B693ULL,
		0x78723D07993FFE5DULL,
		0xCD7DDACFEE5A2321ULL,
		0x9404377760402715ULL,
		0x6C2B998694B13110ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F11FDB67FE88CADULL,
		0xCBFAAC2FBA78C11FULL,
		0x7961D3BC24433547ULL,
		0x7050CA77521AB79EULL,
		0x413579BA4C852318ULL,
		0xF32F7B4371C6B123ULL,
		0x782B60AB23C3C03AULL,
		0x2BAC2F3D0AF51C76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E23FB6CFFD1195AULL,
		0x97F5585F74F1823EULL,
		0xF2C3A77848866A8FULL,
		0xE0A194EEA4356F3CULL,
		0x826AF374990A4630ULL,
		0xE65EF686E38D6246ULL,
		0xF056C15647878075ULL,
		0x57585E7A15EA38ECULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x78E27BB205128229ULL,
		0xD66F7F50BEBBA5FFULL,
		0x320A59C9CEB85497ULL,
		0xB9CFB93A59386212ULL,
		0x6A4E67F080E6B360ULL,
		0x79709933244CCB9EULL,
		0xD75D596ECA368DA1ULL,
		0x384044F51092FAF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1C4F7640A250452ULL,
		0xACDEFEA17D774BFEULL,
		0x6414B3939D70A92FULL,
		0x739F7274B270C424ULL,
		0xD49CCFE101CD66C1ULL,
		0xF2E132664899973CULL,
		0xAEBAB2DD946D1B42ULL,
		0x708089EA2125F5EDULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB3CB3812375CED50ULL,
		0x6D861ADAE43178BEULL,
		0x1C92AF7E728B3073ULL,
		0x2AB6876D94F10AB3ULL,
		0x82A7FB3BEFB8BD11ULL,
		0x56BBD8ACC2952F53ULL,
		0x4F48B8A77E0D6C3DULL,
		0x2929344CF818D5FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679670246EB9DAA0ULL,
		0xDB0C35B5C862F17DULL,
		0x39255EFCE51660E6ULL,
		0x556D0EDB29E21566ULL,
		0x054FF677DF717A22ULL,
		0xAD77B159852A5EA7ULL,
		0x9E91714EFC1AD87AULL,
		0x52526899F031ABF8ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C6AA6331C160574ULL,
		0xD1CDB9053C9BD10BULL,
		0x9B027A1C9DF464B9ULL,
		0xCC7BAB54ED99E0CEULL,
		0x684D93DF76C43124ULL,
		0x5A9C7660B5A15FC7ULL,
		0xFDEEFB08605313A1ULL,
		0x13C7603B1ABA99FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D54C66382C0AE8ULL,
		0xA39B720A7937A216ULL,
		0x3604F4393BE8C973ULL,
		0x98F756A9DB33C19DULL,
		0xD09B27BEED886249ULL,
		0xB538ECC16B42BF8EULL,
		0xFBDDF610C0A62742ULL,
		0x278EC076357533FFULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8D3D8AF8C68F85E3ULL,
		0xC666CDB21D62A8DCULL,
		0x4946FB4F3A60CD98ULL,
		0x356829F2B7D7FAD7ULL,
		0x7C540A932179609AULL,
		0xF82643461376D5E2ULL,
		0x7A3C562306DD460AULL,
		0x3588A8E9F7ABE6EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7B15F18D1F0BC6ULL,
		0x8CCD9B643AC551B9ULL,
		0x928DF69E74C19B31ULL,
		0x6AD053E56FAFF5AEULL,
		0xF8A8152642F2C134ULL,
		0xF04C868C26EDABC4ULL,
		0xF478AC460DBA8C15ULL,
		0x6B1151D3EF57CDDAULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD8E64B27410E48B6ULL,
		0x610E3F23F0F18570ULL,
		0x915D5658097D72FEULL,
		0xBD9BC23D1625D4DCULL,
		0x4A0DD61D94F640F7ULL,
		0xAC2B73ADB2301486ULL,
		0x8A4E5402EF6173A1ULL,
		0x0B69AC8986CB8E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CC964E821C916CULL,
		0xC21C7E47E1E30AE1ULL,
		0x22BAACB012FAE5FCULL,
		0x7B37847A2C4BA9B9ULL,
		0x941BAC3B29EC81EFULL,
		0x5856E75B6460290CULL,
		0x149CA805DEC2E743ULL,
		0x16D359130D971CF1ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9C5A6DDE8060FE95ULL,
		0x0B12F675EBC9A3B7ULL,
		0x420D82997D1D5FE9ULL,
		0xD0EFCAB135A7DBCCULL,
		0xAEAF81C207E2FD9AULL,
		0x5745B02C8D1E286CULL,
		0xA881C580B50ED7EFULL,
		0x0CCD08D64E8B738EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B4DBBD00C1FD2AULL,
		0x1625ECEBD793476FULL,
		0x841B0532FA3ABFD2ULL,
		0xA1DF95626B4FB798ULL,
		0x5D5F03840FC5FB35ULL,
		0xAE8B60591A3C50D9ULL,
		0x51038B016A1DAFDEULL,
		0x199A11AC9D16E71DULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB64069E47FE16B1ULL,
		0xF4F83C0726CCC0BAULL,
		0xED34BB9D56AE7CE6ULL,
		0x3F48FD007B004E33ULL,
		0xBC8EF7633CD4866EULL,
		0x7F9182D5DE4E0511ULL,
		0xE6DA41F5AE46927AULL,
		0x2EFB7E5A83BA9AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96C80D3C8FFC2D62ULL,
		0xE9F0780E4D998175ULL,
		0xDA69773AAD5CF9CDULL,
		0x7E91FA00F6009C67ULL,
		0x791DEEC679A90CDCULL,
		0xFF2305ABBC9C0A23ULL,
		0xCDB483EB5C8D24F4ULL,
		0x5DF6FCB50775358FULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCCA8B7C18429AA97ULL,
		0x585809294D7A240BULL,
		0xD7982C90874E5DDDULL,
		0x9139EAF2921F21CCULL,
		0x2A38366C20BCD33BULL,
		0x0CE82CC44ED768FBULL,
		0x12473AC2CEB7C8EBULL,
		0x04C131587C293B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99516F830853552EULL,
		0xB0B012529AF44817ULL,
		0xAF3059210E9CBBBAULL,
		0x2273D5E5243E4399ULL,
		0x54706CD84179A677ULL,
		0x19D059889DAED1F6ULL,
		0x248E75859D6F91D6ULL,
		0x098262B0F85276A4ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x30D72B371353C910ULL,
		0x8500067866918DC3ULL,
		0x6CC494974E496EFFULL,
		0x3956A4A7511F37DBULL,
		0x3B5208FA33888BB6ULL,
		0x78C2CAFC861ED5F6ULL,
		0xD532134814BB7FF2ULL,
		0x1085292920A32029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61AE566E26A79220ULL,
		0x0A000CF0CD231B86ULL,
		0xD989292E9C92DDFFULL,
		0x72AD494EA23E6FB6ULL,
		0x76A411F46711176CULL,
		0xF18595F90C3DABECULL,
		0xAA6426902976FFE4ULL,
		0x210A525241464053ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xACF58656AC7EDF76ULL,
		0x5FBC01AD05D1C26BULL,
		0x74A525948ED0FA2FULL,
		0xA23482C920096B78ULL,
		0x4987E1FA10F1B8EAULL,
		0x3325AD80AC0C588DULL,
		0xA3ABFA3080927C9BULL,
		0x253744AB7616CAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59EB0CAD58FDBEECULL,
		0xBF78035A0BA384D7ULL,
		0xE94A4B291DA1F45EULL,
		0x446905924012D6F0ULL,
		0x930FC3F421E371D5ULL,
		0x664B5B015818B11AULL,
		0x4757F4610124F936ULL,
		0x4A6E8956EC2D95F9ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCA6842DD6CD45370ULL,
		0x8E795ED7B69965D4ULL,
		0xD1959DAD4F588F0CULL,
		0xD361B89E353FBA9DULL,
		0xC1ED737D385AA0EAULL,
		0x9346B59B30116BA9ULL,
		0x67D3B00FC22813E4ULL,
		0x12ADFA6D71E56434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D085BAD9A8A6E0ULL,
		0x1CF2BDAF6D32CBA9ULL,
		0xA32B3B5A9EB11E19ULL,
		0xA6C3713C6A7F753BULL,
		0x83DAE6FA70B541D5ULL,
		0x268D6B366022D753ULL,
		0xCFA7601F845027C9ULL,
		0x255BF4DAE3CAC868ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD2DCF296ED57D80EULL,
		0xB0E5EE33937F33BEULL,
		0x58D32BBC7E760203ULL,
		0x14364ACA655EC5D0ULL,
		0x49561AAEC4E68F86ULL,
		0xDAC6818F9991C14EULL,
		0x51D4D7BE75FE473EULL,
		0x124732EC3CA06E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B9E52DDAAFB01CULL,
		0x61CBDC6726FE677DULL,
		0xB1A65778FCEC0407ULL,
		0x286C9594CABD8BA0ULL,
		0x92AC355D89CD1F0CULL,
		0xB58D031F3323829CULL,
		0xA3A9AF7CEBFC8E7DULL,
		0x248E65D87940DC32ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E665292C3C32626ULL,
		0x340F13D49A85D494ULL,
		0xD40FEC28E7EA99D5ULL,
		0xE4208B65A134F3A3ULL,
		0x48E15D484EB2BB69ULL,
		0xBEE8E4F10D57134BULL,
		0x294EA07647B918FEULL,
		0x1BB2DFF7A0BEC502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CCCA52587864C4CULL,
		0x681E27A9350BA929ULL,
		0xA81FD851CFD533AAULL,
		0xC84116CB4269E747ULL,
		0x91C2BA909D6576D3ULL,
		0x7DD1C9E21AAE2696ULL,
		0x529D40EC8F7231FDULL,
		0x3765BFEF417D8A04ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7BC77BDC3CFFC09CULL,
		0xB6788B13B615D944ULL,
		0x3C2B8D05BA9F435BULL,
		0xE8A885F0F2D8A0ACULL,
		0x4A49034B09C3D056ULL,
		0xC8507B12C25F21ADULL,
		0xA9E4C74B722E1C53ULL,
		0x3B76E5445A3276C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78EF7B879FF8138ULL,
		0x6CF116276C2BB288ULL,
		0x78571A0B753E86B7ULL,
		0xD1510BE1E5B14158ULL,
		0x949206961387A0ADULL,
		0x90A0F62584BE435AULL,
		0x53C98E96E45C38A7ULL,
		0x76EDCA88B464ED91ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D53A8FD561030C6ULL,
		0xACAE619EDB879DE7ULL,
		0x41181F231C1A23C2ULL,
		0x84815909FB480087ULL,
		0xA1EE93AD958162CEULL,
		0x98C65075126EEFECULL,
		0x8D7694F6F5B86394ULL,
		0x3DD7B074B45255A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA751FAAC20618CULL,
		0x595CC33DB70F3BCEULL,
		0x82303E4638344785ULL,
		0x0902B213F690010EULL,
		0x43DD275B2B02C59DULL,
		0x318CA0EA24DDDFD9ULL,
		0x1AED29EDEB70C729ULL,
		0x7BAF60E968A4AB4BULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x656D46EA1146D33EULL,
		0xB9BC4BB55A9F4CA1ULL,
		0x022CA2CDA186384CULL,
		0x1D7686CDD10280EAULL,
		0xE3CD5E805FD667F9ULL,
		0x82C85C0738CE8013ULL,
		0x7DCD593C7CD651A9ULL,
		0x0445A2021B3653F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADA8DD4228DA67CULL,
		0x7378976AB53E9942ULL,
		0x0459459B430C7099ULL,
		0x3AED0D9BA20501D4ULL,
		0xC79ABD00BFACCFF2ULL,
		0x0590B80E719D0027ULL,
		0xFB9AB278F9ACA353ULL,
		0x088B4404366CA7E2ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C0A3861C9C19818ULL,
		0xB2B43434CD211F3BULL,
		0xEF017DBADA81D71EULL,
		0xC6590AE97FE293A3ULL,
		0xFA4452F96005AA06ULL,
		0x3427D46048D8EDCBULL,
		0xE9F6EB3DA8F0BB8BULL,
		0x0DBFD0F8B6C520E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF81470C393833030ULL,
		0x656868699A423E76ULL,
		0xDE02FB75B503AE3DULL,
		0x8CB215D2FFC52747ULL,
		0xF488A5F2C00B540DULL,
		0x684FA8C091B1DB97ULL,
		0xD3EDD67B51E17716ULL,
		0x1B7FA1F16D8A41CFULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7E3E5744926E34D4ULL,
		0xCBA951B9BB3A4A3CULL,
		0x99E44332AC2CEE48ULL,
		0x9BAA1C8D39B10113ULL,
		0xBC289D71F765E2C5ULL,
		0xBFA6454BB86E6B95ULL,
		0xE87B127BA02F6CFDULL,
		0x13549B83C90BA547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC7CAE8924DC69A8ULL,
		0x9752A37376749478ULL,
		0x33C886655859DC91ULL,
		0x3754391A73620227ULL,
		0x78513AE3EECBC58BULL,
		0x7F4C8A9770DCD72BULL,
		0xD0F624F7405ED9FBULL,
		0x26A9370792174A8FULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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