#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA1266B7A5F0D15D8ULL,
		0xCA0AD9274D094842ULL,
		0xDAF084806CA3252BULL,
		0x9206CE539753E67DULL,
		0xB2CC9DE64152ABD4ULL,
		0x8388B30ABDBF0515ULL,
		0x230ACCA455F261BDULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF0D15D8000000000ULL,
		0xD094842A1266B7A5ULL,
		0xCA3252BCA0AD9274ULL,
		0x753E67DDAF084806ULL,
		0x152ABD49206CE539ULL,
		0xDBF0515B2CC9DE64ULL,
		0x5F261BD8388B30ABULL,
		0x0000000230ACCA45ULL
	}};
	int shift = 36;
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
		0xE6B4F897783575A8ULL,
		0x51E0F7ADAB29AE32ULL,
		0xB0024A15F38733CDULL,
		0x0C7F8B34EEE444C3ULL,
		0x1C991D9A8BD6C3C2ULL,
		0xE5AE63D0D049476BULL,
		0xBFC612EA6A112F77ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E6B4F897783575AULL,
		0xD51E0F7ADAB29AE3ULL,
		0x3B0024A15F38733CULL,
		0x20C7F8B34EEE444CULL,
		0xB1C991D9A8BD6C3CULL,
		0x7E5AE63D0D049476ULL,
		0x0BFC612EA6A112F7ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xE2C476C8A62CFE24ULL,
		0x12AC2C8D3F115109ULL,
		0xE677EAB988072C23ULL,
		0xE6699DBA88AFAE4CULL,
		0x993F0614843C0D75ULL,
		0x968946CE02731CD0ULL,
		0x806E6443F38DA8B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F88A884F1623B64ULL,
		0xC403961189561646ULL,
		0x4457D726733BF55CULL,
		0x421E06BAF334CEDDULL,
		0x01398E684C9F830AULL,
		0xF9C6D45ACB44A367ULL,
		0x0000000040373221ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xBCC0EDCE88D54A6FULL,
		0xA34FF17865001EE0ULL,
		0x77543B59E6500675ULL,
		0x97E087CC38893631ULL,
		0xB8298EA5FCE26DD8ULL,
		0x4F55259EC67FB26FULL,
		0x580B660CE2371920ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA003DC17981DB9D1ULL,
		0xCA00CEB469FE2F0CULL,
		0x1126C62EEA876B3CULL,
		0x9C4DBB12FC10F987ULL,
		0xCFF64DF70531D4BFULL,
		0x46E32409EAA4B3D8ULL,
		0x0000000B016CC19CULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x519B96A4287C2919ULL,
		0xB0EBB35E1DFAEE38ULL,
		0x93C8A4AC96B95280ULL,
		0x0E99D24FF279D172ULL,
		0xEE86956405D6269BULL,
		0x728C31AAC5AE844CULL,
		0x53CBA192C82D5C46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC70A3372D4850F85ULL,
		0x50161D766BC3BF5DULL,
		0x2E5279149592D72AULL,
		0xD361D33A49FE4F3AULL,
		0x899DD0D2AC80BAC4ULL,
		0x88CE51863558B5D0ULL,
		0x000A7974325905ABULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xF5FDB9746BD38545ULL,
		0xD907F39A7428AECDULL,
		0x19D0544939F8E1B0ULL,
		0xC03317D66FC3AB57ULL,
		0x87F6417F1EC80277ULL,
		0xD88CA92AD4F8111AULL,
		0x33C34689B3DBE02FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5766FAFEDCBA35E9ULL,
		0x70D86C83F9CD3A14ULL,
		0xD5AB8CE82A249CFCULL,
		0x013BE0198BEB37E1ULL,
		0x088D43FB20BF8F64ULL,
		0xF017EC4654956A7CULL,
		0x000019E1A344D9EDULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x205778AA8548DE93ULL,
		0xB744957D123A5938ULL,
		0xDDFC88EA55C5D0C9ULL,
		0xF5902E3D9732F64FULL,
		0x202EB419D733FC8AULL,
		0x34E205DA15D0D7E3ULL,
		0x337971A3D013C67BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2474B27040AEF155ULL,
		0xAB8BA1936E892AFAULL,
		0x2E65EC9FBBF911D4ULL,
		0xAE67F915EB205C7BULL,
		0x2BA1AFC6405D6833ULL,
		0xA0278CF669C40BB4ULL,
		0x0000000066F2E347ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x72B74EC0A9A5C613ULL,
		0xAF37BC7E21883655ULL,
		0x750178F758B5D1B0ULL,
		0x61258FF7E56EFB35ULL,
		0x5860DC4DEAFA930EULL,
		0x50ACE572878EBB30ULL,
		0xEDF41ABCE9C61CCAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF88620D955CADD3BULL,
		0xDD62D746C2BCDEF1ULL,
		0xDF95BBECD5D405E3ULL,
		0x37ABEA4C3984963FULL,
		0xCA1E3AECC1618371ULL,
		0xF3A718732942B395ULL,
		0x0000000003B7D06AULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x0E26060167D123DDULL,
		0x9B9F22B7116F7F71ULL,
		0x11627EE377274B15ULL,
		0x9EFEEA7207052555ULL,
		0xF17818232CD9FA89ULL,
		0x3D773EB4666DEBE9ULL,
		0x027DA5BE4560BBADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DEFEE21C4C0C02CULL,
		0xE4E962B373E456E2ULL,
		0xE0A4AAA22C4FDC6EULL,
		0x9B3F5133DFDD4E40ULL,
		0xCDBD7D3E2F030465ULL,
		0xAC1775A7AEE7D68CULL,
		0x000000004FB4B7C8ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x3A8DFD1A318CF6F1ULL,
		0x84184F1FC714E657ULL,
		0x825FDAD65FBF558CULL,
		0x6F9218E89BA6208FULL,
		0xA11E860C4017FAB5ULL,
		0xA1D58241FB0A5E37ULL,
		0xA50C573D6F144C36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995CEA37F468C633ULL,
		0x563210613C7F1C53ULL,
		0x823E097F6B597EFDULL,
		0xEAD5BE4863A26E98ULL,
		0x78DE847A1831005FULL,
		0x30DA87560907EC29ULL,
		0x000294315CF5BC51ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xC010B1ED3CDACF3DULL,
		0xD39C6DA72800C918ULL,
		0x2CBDEF8415127D44ULL,
		0xB40E0A5F79D4B60BULL,
		0xE7384E454B4963B4ULL,
		0x88386A7FCC53E27BULL,
		0x27DBEC05A1A6A111ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C010B1ED3CDACF3ULL,
		0x4D39C6DA72800C91ULL,
		0xB2CBDEF8415127D4ULL,
		0x4B40E0A5F79D4B60ULL,
		0xBE7384E454B4963BULL,
		0x188386A7FCC53E27ULL,
		0x027DBEC05A1A6A11ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xDE108AF7B93971CFULL,
		0xBB479AA47C07AF80ULL,
		0xFD697E2D21C4868DULL,
		0x80EE6FE7C776B4B6ULL,
		0x884690EF1FC117D5ULL,
		0xB9AD9F1B5FAB5285ULL,
		0x108411B3CC134057ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DE108AF7B93971ULL,
		0x8DBB479AA47C07AFULL,
		0xB6FD697E2D21C486ULL,
		0xD580EE6FE7C776B4ULL,
		0x85884690EF1FC117ULL,
		0x57B9AD9F1B5FAB52ULL,
		0x00108411B3CC1340ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xD81A85543CC1EF56ULL,
		0x8541C931A1323047ULL,
		0x57BE253B900EDC16ULL,
		0xC34F62CBC6FE1A09ULL,
		0x1CD62FB16BB3BF12ULL,
		0x33D0ED883ECFA33CULL,
		0x6BEB386017B1896FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C8C11F606A1550ULL,
		0x403B705A150724C6ULL,
		0x1BF868255EF894EEULL,
		0xAECEFC4B0D3D8B2FULL,
		0xFB3E8CF07358BEC5ULL,
		0x5EC625BCCF43B620ULL,
		0x00000001AFACE180ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x6258AF4BDCB439CAULL,
		0xFD889F164388BDFEULL,
		0x8098752B750CD3EFULL,
		0x351C4F1FEC378864ULL,
		0x1995F37A7285D67AULL,
		0xB93A1138455BF47AULL,
		0x55953D5E9B82582EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4388BDFE6258AF4BULL,
		0x750CD3EFFD889F16ULL,
		0xEC3788648098752BULL,
		0x7285D67A351C4F1FULL,
		0x455BF47A1995F37AULL,
		0x9B82582EB93A1138ULL,
		0x0000000055953D5EULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x55262E58294EF816ULL,
		0xC1C38A4E7F75B7E9ULL,
		0xC8F26F0449C0A823ULL,
		0xC951D0E412737D5AULL,
		0x75CC5214DF05C3A8ULL,
		0xD4D0FAEB629EFFB2ULL,
		0x67D7CE891086ADB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2939FDD6DFA554ULL,
		0xC9BC112702A08F07ULL,
		0x47439049CDF56B23ULL,
		0x3148537C170EA325ULL,
		0x43EBAD8A7BFEC9D7ULL,
		0x5F3A24421AB6D753ULL,
		0x000000000000019FULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xD1FC613DF292D30EULL,
		0x80283C83CBE16B13ULL,
		0x42D647CB22D808C0ULL,
		0xBE2A3A253D7C14C1ULL,
		0x05BD82A5FA0AA975ULL,
		0xFCA950675EB4A364ULL,
		0xE4D9D84083E4EF35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B13D1FC613DF29ULL,
		0x808C080283C83CBEULL,
		0xC14C142D647CB22DULL,
		0xAA975BE2A3A253D7ULL,
		0x4A36405BD82A5FA0ULL,
		0x4EF35FCA950675EBULL,
		0x00000E4D9D84083EULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x462B1D745405E678ULL,
		0x87EBF54D1FFF8F04ULL,
		0x0CD548109AFA6BFAULL,
		0x5351DC6504FD19F6ULL,
		0x323C538774C78865ULL,
		0xF3FC499B676E44B9ULL,
		0xB3CB3D68D148AF9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23158EBA2A02F33CULL,
		0x43F5FAA68FFFC782ULL,
		0x066AA4084D7D35FDULL,
		0xA9A8EE32827E8CFBULL,
		0x991E29C3BA63C432ULL,
		0x79FE24CDB3B7225CULL,
		0x59E59EB468A457CFULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xD9855B619B375AEDULL,
		0x8E4B613244475832ULL,
		0x8E66A43337E9E7B3ULL,
		0xBED358FA32DE1E71ULL,
		0xB9BFCF4F93437CA4ULL,
		0xAA685A4FA5E4E961ULL,
		0xA3A14B7BC467E2EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x196CC2ADB0CD9BADULL,
		0xD9C725B0992223ACULL,
		0x38C73352199BF4F3ULL,
		0x525F69AC7D196F0FULL,
		0xB0DCDFE7A7C9A1BEULL,
		0x7755342D27D2F274ULL,
		0x0051D0A5BDE233F1ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0x925770ACC3E9DFE6ULL,
		0xB8536F808580D3DDULL,
		0xF2FCBFB15180B9AFULL,
		0xDCE20B68E445365DULL,
		0x3E4EFAD40F0F16FFULL,
		0x23E2939F1A7CFC95ULL,
		0xCEAA3D5F02507D73ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042C069EEC92BB85ULL,
		0x8A8C05CD7DC29B7CULL,
		0x472229B2EF97E5FDULL,
		0xA07878B7FEE7105BULL,
		0xF8D3E7E4A9F277D6ULL,
		0xF81283EB991F149CULL,
		0x00000000067551EAULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0xEDD894492F633013ULL,
		0x62A6A892D2A2EEDBULL,
		0x848D6A143104C73FULL,
		0x0C1100C02B0ED36DULL,
		0x5F5900B60E646DD5ULL,
		0x95DA242841A794AFULL,
		0xF3931E8DF274D5A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF6EC4A2497B1980ULL,
		0xFB15354496951776ULL,
		0x6C246B50A1882639ULL,
		0xA86088060158769BULL,
		0x7AFAC805B073236EULL,
		0x04AED121420D3CA5ULL,
		0x079C98F46F93A6ADULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0xFFE0426B3EF07034ULL,
		0xB950E072EB8F4FA6ULL,
		0xDA6BB93589FC1D78ULL,
		0x95A379A1EEAE5A4BULL,
		0x2E8DE8A2007BD036ULL,
		0x69A54CBA68852627ULL,
		0xF906185D91B64133ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4FA6FFE0426B3EFULL,
		0xC1D78B950E072EB8ULL,
		0xE5A4BDA6BB93589FULL,
		0xBD03695A379A1EEAULL,
		0x526272E8DE8A2007ULL,
		0x6413369A54CBA688ULL,
		0x00000F906185D91BULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xABB1A1263B11C69DULL,
		0xD4A02F09746B5519ULL,
		0x989116C90D4B8004ULL,
		0x98E835BA109398C5ULL,
		0x483BEE40D9117C81ULL,
		0x11AC4A7FE9314AFCULL,
		0x8C3FE391FF1B6F76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9746B5519ABB1A12ULL,
		0x90D4B8004D4A02F0ULL,
		0xA109398C5989116CULL,
		0x0D9117C8198E835BULL,
		0xFE9314AFC483BEE4ULL,
		0x1FF1B6F7611AC4A7ULL,
		0x0000000008C3FE39ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x0844F1668C7A07F9ULL,
		0x1387AB90E6FA4F2FULL,
		0xD07F6B54FB3E2B05ULL,
		0x1702850587CF5011ULL,
		0xFB5ABB9208AB985CULL,
		0xF98D323A355ACA0BULL,
		0x69097BD3E2AFFAA1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E5E1089E2CD18F4ULL,
		0x560A270F5721CDF4ULL,
		0xA023A0FED6A9F67CULL,
		0x30B82E050A0B0F9EULL,
		0x9417F6B577241157ULL,
		0xF543F31A64746AB5ULL,
		0x0000D212F7A7C55FULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xAAD494BC314A5F9FULL,
		0x2D9945176A6F114FULL,
		0xA30F1C8A2C9DC9F6ULL,
		0x56F8A8D28831656AULL,
		0xA9A728B4CF1E671FULL,
		0xA0FDF6F87078CF0DULL,
		0xF759E7A2058CF109ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EAB5252F0C5297EULL,
		0xD8B665145DA9BC45ULL,
		0xAA8C3C7228B27727ULL,
		0x7D5BE2A34A20C595ULL,
		0x36A69CA2D33C799CULL,
		0x2683F7DBE1C1E33CULL,
		0x03DD679E881633C4ULL,
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
		0xE31C4D6DDC3452C2ULL,
		0xB9D3DF6AB0356F49ULL,
		0xB831C965581D54A4ULL,
		0xC692B12BE2FE97ECULL,
		0xA123460EC8047552ULL,
		0x5DAB9449F96B5C2BULL,
		0x7BECB3D2520F8F8CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F18E26B6EE1A296ULL,
		0x25CE9EFB5581AB7AULL,
		0x65C18E4B2AC0EAA5ULL,
		0x963495895F17F4BFULL,
		0x5D091A30764023AAULL,
		0x62ED5CA24FCB5AE1ULL,
		0x03DF659E92907C7CULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x71293C83D7962655ULL,
		0x54384A9EBAF5021EULL,
		0x0C7121DD43D0E211ULL,
		0x0A71AD541C1D45FFULL,
		0xCAC9289387BAB17CULL,
		0x1FC06AD4CC3C07E2ULL,
		0x3EF295330EE8ECE8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043CE2527907AF2CULL,
		0xC422A870953D75EAULL,
		0x8BFE18E243BA87A1ULL,
		0x62F814E35AA8383AULL,
		0x0FC5959251270F75ULL,
		0xD9D03F80D5A99878ULL,
		0x00007DE52A661DD1ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xBD758FB1D1DA3CD9ULL,
		0xABE92B1E55B5FB2BULL,
		0x8521ECC1CA7A54B6ULL,
		0x76121333E86B02DBULL,
		0x30713E2E23F4531AULL,
		0x514F1C9AB398B58CULL,
		0xDFD5F33CAC879CCDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD758FB1D1DA3CDULL,
		0x6ABE92B1E55B5FB2ULL,
		0xB8521ECC1CA7A54BULL,
		0xA76121333E86B02DULL,
		0xC30713E2E23F4531ULL,
		0xD514F1C9AB398B58ULL,
		0x0DFD5F33CAC879CCULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xCC0D76B9DADEB821ULL,
		0x4917D18AFDEE1716ULL,
		0x4E55B0F6D8E27876ULL,
		0xFB42D67FC03766FCULL,
		0xD01B4095507E9BAEULL,
		0xBED0F332084624D8ULL,
		0xEEE8434437BB94B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B6606BB5CED6F5CULL,
		0x3B248BE8C57EF70BULL,
		0x7E272AD87B6C713CULL,
		0xD77DA16B3FE01BB3ULL,
		0x6C680DA04AA83F4DULL,
		0x5CDF687999042312ULL,
		0x00777421A21BDDCAULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0xCE6FF9014C786260ULL,
		0x395DE14051690DF9ULL,
		0xA5015C8BAA349478ULL,
		0x3DB9A77D69906EC2ULL,
		0x3745AB38DB2158ECULL,
		0x1DA568451059F432ULL,
		0xB61E38CDCF935756ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D21BF39CDFF2029ULL,
		0x46928F072BBC280AULL,
		0x320DD854A02B9175ULL,
		0x642B1D87B734EFADULL,
		0x0B3E8646E8B5671BULL,
		0xF26AEAC3B4AD08A2ULL,
		0x00000016C3C719B9ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0xF29DF4170E9768E7ULL,
		0xD172E952C3F777B3ULL,
		0x250745AEB27EB3C1ULL,
		0x8D4EB0FFFBC1CE67ULL,
		0xF41C9F0C95D6DD7CULL,
		0xD34619228A062D39ULL,
		0x41BDADBA9029CDBFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F29DF4170E9768ULL,
		0xC1D172E952C3F777ULL,
		0x67250745AEB27EB3ULL,
		0x7C8D4EB0FFFBC1CEULL,
		0x39F41C9F0C95D6DDULL,
		0xBFD34619228A062DULL,
		0x0041BDADBA9029CDULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x67EF67CD413E8B27ULL,
		0x4355B829E11047B5ULL,
		0xFFBE326C04D9BD4AULL,
		0xF9FBDFBCF0636140ULL,
		0x18726AC2EDCA4C7DULL,
		0xFB51B01D557B8CACULL,
		0xB901AAEC0A751326ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6ACFDECF9A827DULL,
		0x7A9486AB7053C220ULL,
		0xC281FF7C64D809B3ULL,
		0x98FBF3F7BF79E0C6ULL,
		0x195830E4D585DB94ULL,
		0x264DF6A3603AAAF7ULL,
		0x0001720355D814EAULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x4AD05B5F64124C54ULL,
		0xA8CC5462E0B6BC24ULL,
		0xCDBC76D85BC74556ULL,
		0x87B2B032F3186190ULL,
		0x795052B964950605ULL,
		0xC93B5D1355393534ULL,
		0xE463A5B933C75DE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C16D784895A0B6BULL,
		0x0B78E8AAD5198A8CULL,
		0x5E630C3219B78EDBULL,
		0x2C92A0C0B0F65606ULL,
		0x6AA726A68F2A0A57ULL,
		0x2678EBBC19276BA2ULL,
		0x000000001C8C74B7ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x52F00203417B4A25ULL,
		0x6C32DC9F15828154ULL,
		0x6CCEA22BF991664DULL,
		0x6D8571FE69D54DDAULL,
		0x9DAA11D29E53D3E5ULL,
		0x10B596F539ED1C4FULL,
		0x36159C66D3AB7B39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5E0040682F6944ULL,
		0xAD865B93E2B0502AULL,
		0x4D99D4457F322CC9ULL,
		0xADB0AE3FCD3AA9BBULL,
		0xF3B5423A53CA7A7CULL,
		0x2216B2DEA73DA389ULL,
		0x06C2B38CDA756F67ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0x78A97BF6A94F1AC4ULL,
		0xB192EEC5B6BCC914ULL,
		0x7E313CA67B17EAC0ULL,
		0x2EFCE1D78BA42E2AULL,
		0x27429175E6BF16BBULL,
		0x82D151AB3EE3A878ULL,
		0xB6E51C313678CDF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EEC5B6BCC91478AULL,
		0x13CA67B17EAC0B19ULL,
		0xCE1D78BA42E2A7E3ULL,
		0x29175E6BF16BB2EFULL,
		0x151AB3EE3A878274ULL,
		0x51C313678CDF882DULL,
		0x0000000000000B6EULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x1828E8195ECDE550ULL,
		0x7BFA601027894387ULL,
		0x11E5D2DC7207891BULL,
		0xE54EC24E1F1ECBF5ULL,
		0xB355916030259136ULL,
		0x9F3B3F4D4F09B7B5ULL,
		0x71D21EDA33A0E5C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF12870E3051D032BULL,
		0x40F1236F7F4C0204ULL,
		0xE3D97EA23CBA5B8EULL,
		0x04B226DCA9D849C3ULL,
		0xE136F6B66AB22C06ULL,
		0x741CB8D3E767E9A9ULL,
		0x0000000E3A43DB46ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x5363D578E8A31EF1ULL,
		0x3D0958493B52C704ULL,
		0xAB0FD073260B9084ULL,
		0xEAA25E672269CEF2ULL,
		0x05A6DF922DAAD5C8ULL,
		0xF2B846FA0D004851ULL,
		0x9A6DB405F99FEB50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08A6C7AAF1D1463ULL,
		0x1087A12B09276A58ULL,
		0xDE5561FA0E64C172ULL,
		0xB91D544BCCE44D39ULL,
		0x0A20B4DBF245B55AULL,
		0x6A1E5708DF41A009ULL,
		0x00134DB680BF33FDULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x830A0AF5E5F25E5DULL,
		0x975756E31DB9C16DULL,
		0xFB2BF52EB7084371ULL,
		0x0F89E93C323FF03BULL,
		0xD34D065CCBAE9781ULL,
		0xFFF8E8AA27ECBE69ULL,
		0x186E82F1FC60AF87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63B7382DB061415ULL,
		0x5D6E1086E32EAEADULL,
		0x78647FE077F657EAULL,
		0xB9975D2F021F13D2ULL,
		0x544FD97CD3A69A0CULL,
		0xE3F8C15F0FFFF1D1ULL,
		0x000000000030DD05ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xC0507ECB82348A12ULL,
		0x7A9F8513D4DFF6C3ULL,
		0xF33654CBA933C4F6ULL,
		0x82AD1219A657432CULL,
		0xDF754B97F928B886ULL,
		0xB9ABE92C5B73F660ULL,
		0xCD9CE77C6B2B41EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB61E0283F65C11AULL,
		0xE27B3D4FC289EA6FULL,
		0xA196799B2A65D499ULL,
		0x5C434156890CD32BULL,
		0xFB306FBAA5CBFC94ULL,
		0xA0F55CD5F4962DB9ULL,
		0x000066CE73BE3595ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xD38C6D111D8D09C1ULL,
		0xAB8DFA50EFDADDAEULL,
		0x97AF30D461055BB5ULL,
		0x9DA375D3FC3E7DC4ULL,
		0x11A3B2440159E76BULL,
		0x9F1018524D1D7AB6ULL,
		0x7D7309A62700069EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76BB4E31B444763ULL,
		0x56ED6AE37E943BF6ULL,
		0x9F7125EBCC351841ULL,
		0x79DAE768DD74FF0FULL,
		0x5EAD8468EC910056ULL,
		0x01A7A7C406149347ULL,
		0x00001F5CC26989C0ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x207A8615C1706209ULL,
		0x25D1D611D1369B82ULL,
		0x961CE4561639BD4CULL,
		0x8329B3ACE9DD1F5CULL,
		0x448B090E9B0E65FDULL,
		0x677434A1E86BDB8AULL,
		0xD298861FFA413ED1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC23A26D370440F5ULL,
		0xC8AC2C737A984BA3ULL,
		0x6759D3BA3EB92C39ULL,
		0x121D361CCBFB0653ULL,
		0x6943D0D7B7148916ULL,
		0x0C3FF4827DA2CEE8ULL,
		0x000000000001A531ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x8EB6F1196108AE3CULL,
		0x32C54C4C96A806E8ULL,
		0xDD7D2B5659ECA34AULL,
		0x797D4FFC546F0844ULL,
		0x9DEDE78B54C371F4ULL,
		0x6019FEEAF164309CULL,
		0xFE586EE27F34C731ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40374475B788CB08ULL,
		0x651A51962A6264B5ULL,
		0x784226EBE95AB2CFULL,
		0x1B8FA3CBEA7FE2A3ULL,
		0x2184E4EF6F3C5AA6ULL,
		0xA6398B00CFF7578BULL,
		0x000007F2C37713F9ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xF822010D88E29028ULL,
		0xD11981E4300112E4ULL,
		0x25E7E6EACD6909C6ULL,
		0x37AEF9B599F5D8E5ULL,
		0xAAD8A60308700F92ULL,
		0xEB3256438295E050ULL,
		0x6B54673D46B24D9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0225C9F044021B11ULL,
		0xD2138DA23303C860ULL,
		0xEBB1CA4BCFCDD59AULL,
		0xE01F246F5DF36B33ULL,
		0x2BC0A155B14C0610ULL,
		0x649B39D664AC8705ULL,
		0x000000D6A8CE7A8DULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x10CC6E49E9914159ULL,
		0xBD2BED4A76F2BF8FULL,
		0x95805113427FF958ULL,
		0x197F48423AF4D5ACULL,
		0x9CC9FDBA14EEA2FBULL,
		0xF5D1D7F29DA46E03ULL,
		0x2133B594304964FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED4A76F2BF8F10CCULL,
		0x5113427FF958BD2BULL,
		0x48423AF4D5AC9580ULL,
		0xFDBA14EEA2FB197FULL,
		0xD7F29DA46E039CC9ULL,
		0xB594304964FCF5D1ULL,
		0x0000000000002133ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xBC9FFE2F89BFAB49ULL,
		0xE6FB566C1D5F0DF9ULL,
		0xB4037D777728BFF9ULL,
		0x58173EB16AA94EC7ULL,
		0x5BFDE63AE53D248FULL,
		0x8C88C566D1684474ULL,
		0x0FA95721DEB656FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83ABE1BF3793FFCULL,
		0xEEEE517FF3CDF6ACULL,
		0x62D5529D8F6806FAULL,
		0x75CA7A491EB02E7DULL,
		0xCDA2D088E8B7FBCCULL,
		0x43BD6CADF519118AULL,
		0x00000000001F52AEULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x1479965C029A9982ULL,
		0xA6A83E22482DE4F6ULL,
		0x2788BCC783028753ULL,
		0x242DDE3BAA101791ULL,
		0x78BCD79B01D4725EULL,
		0xE4FEF9BDEC96BAFAULL,
		0x91302B96BB17B70EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x541F112416F27B0AULL,
		0xC45E63C18143A9D3ULL,
		0x16EF1DD5080BC893ULL,
		0x5E6BCD80EA392F12ULL,
		0x7F7CDEF64B5D7D3CULL,
		0x9815CB5D8BDB8772ULL,
		0x0000000000000048ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0xDF29D165DC3A1728ULL,
		0x35BC38696A1E68C9ULL,
		0xAC639FE161797ECBULL,
		0xBC783483A84041BCULL,
		0x4392B540F1BAC309ULL,
		0x95CF8FCF953AED59ULL,
		0x8B3311FA8101B6ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A879A3277CA7459ULL,
		0x585E5FB2CD6F0E1AULL,
		0xEA10106F2B18E7F8ULL,
		0x3C6EB0C26F1E0D20ULL,
		0xE54EBB5650E4AD50ULL,
		0xA0406DAB6573E3F3ULL,
		0x0000000022CCC47EULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xE279BE8C8CD56A0DULL,
		0xAF56EE150535CF24ULL,
		0xE9C801F71606381FULL,
		0x30C4BC9BDD4F6B7DULL,
		0x96E45B1700DFAFE8ULL,
		0x328D7E88F0502B7EULL,
		0xB6E9B2EBF967EFA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A0A6B9E49C4F37ULL,
		0x3EE2C0C703F5EADDULL,
		0x937BA9ED6FBD3900ULL,
		0x62E01BF5FD061897ULL,
		0xD11E0A056FD2DC8BULL,
		0x5D7F2CFDF48651AFULL,
		0x000000000016DD36ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x3E2609E5CEBB5BE3ULL,
		0x29F504618C9FF46AULL,
		0x08CFB48EA97604FDULL,
		0x7B4BB6FBB65D0578ULL,
		0x01D34662ED1AA48DULL,
		0xC6D62A41D82E7D68ULL,
		0x3D7EE324041025BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504618C9FF46A3E2ULL,
		0xFB48EA97604FD29FULL,
		0xBB6FBB65D057808CULL,
		0x34662ED1AA48D7B4ULL,
		0x62A41D82E7D6801DULL,
		0xEE324041025BFC6DULL,
		0x00000000000003D7ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x3B7D2BF1E6CDEA43ULL,
		0x49820D55653F22CBULL,
		0xBA206545D61D64D9ULL,
		0x19FCCE55C4C3F898ULL,
		0x860AB3E71456C97FULL,
		0xD1650EF435EC94EFULL,
		0x865DD7D0851C2A99ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x041AAACA7E459676ULL,
		0x40CA8BAC3AC9B293ULL,
		0xF99CAB8987F13174ULL,
		0x1567CE28AD92FE33ULL,
		0xCA1DE86BD929DF0CULL,
		0xBBAFA10A385533A2ULL,
		0x000000000000010CULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0xE38A92ABF5A3E422ULL,
		0x5FFAE6F0E2C9A489ULL,
		0x0719328A3673B432ULL,
		0xD98AFAEB8A253AAAULL,
		0xC6147FB7E919DF53ULL,
		0xADFA29ED74A3DD64ULL,
		0x730E004915766E27ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC38B2692278E2AULL,
		0xCA28D9CED0C97FEBULL,
		0xEBAE2894EAA81C64ULL,
		0xFEDFA4677D4F662BULL,
		0xA7B5D28F75931851ULL,
		0x012455D9B89EB7E8ULL,
		0x000000000001CC38ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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