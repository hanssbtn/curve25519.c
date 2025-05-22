#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x50B1ACB3904282EAULL,
		0xD861CF4A99C0FADFULL,
		0x72BBE896078DF6B8ULL,
		0x29B59344406D924AULL,
		0x0EFA01992CA93B52ULL,
		0xA691FEB78B87E157ULL,
		0x506585DB49CED3ACULL,
		0x48DD1E8F6735AF72ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x89CDE970316152A5ULL,
		0x920D9E894FEC6DCBULL,
		0x61CDC722FC416259ULL,
		0x7A881C8D92659D42ULL,
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
		0xE41F16CF5072A2C6ULL,
		0xEA687A44FA2DC044ULL,
		0xA6C0AB53994D7DC8ULL,
		0x619B20B221C07CC1ULL,
		0x03A6E0F6EC68A0ECULL,
		0x1BB538593437C99CULL,
		0xAF3266C48145F1B4ULL,
		0xC11FBF02A253BE38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE47B7667FA8A1CULL,
		0x074ED782BA75AD6DULL,
		0xA83BEC7EC9AF5E85ULL,
		0x0C517B163A2EB92BULL,
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
		0x272E354F29A14E89ULL,
		0xD2C1F122AC2B88ADULL,
		0x7BCB5147AE7E7F9AULL,
		0x336B42C88567A180ULL,
		0x7E83C3C596A8A6AFULL,
		0x403E230545D49447ULL,
		0xB1A40B7D73D29628ULL,
		0x3721228BC5E10630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEBD44A386AA0DB3ULL,
		0x5BFB23EB09B98B49ULL,
		0xDA2505E6DFC0C994ULL,
		0x62566387E4CE8CBAULL,
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
		0x1F36815FC87DC54CULL,
		0xDD86CC3EAA5C09EAULL,
		0x0AFFD2F0AF61459AULL,
		0x023D897B49C1E9B7ULL,
		0x6A2B05770CB09129ULL,
		0x760618E6B9F67487ULL,
		0x7416A391F9C51AA6ULL,
		0x0809CDC14ECFA0A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE199510BAAB35188ULL,
		0x626E7E7E44F15603ULL,
		0x465C1A9BC2A33A50ULL,
		0x33B2142CFC93C220ULL,
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
		0x25C7680D9AE81660ULL,
		0x6C632D7BF140D094ULL,
		0xBE923B243C461E3DULL,
		0x0FB9A657E5A310E3ULL,
		0xC0694721D0A7A6F7ULL,
		0x97CBAF1BB5CF5650ULL,
		0x04BBF2E2706CF29AULL,
		0xFD774B9EB3F91E1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB567F71293CAE49BULL,
		0xF49F2B98EE07A090ULL,
		0x727848C0EC72212FULL,
		0x2F6EDFE69C9D88C0ULL,
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
		0x6DCA8DB60AD0F264ULL,
		0x5FAE1B6604CE3379ULL,
		0xEA3EC911EA8A9218ULL,
		0xF2B92A23CE5DDD57ULL,
		0x8E2E2012C91C2C49ULL,
		0xC3D7090456F827E4ULL,
		0xC199CA19E9F6A369ULL,
		0x639CBCB372899EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88A3507FE4FF8787ULL,
		0x7199720AEDA41F66ULL,
		0xA712C8EAA526D3CBULL,
		0x3BFD2CC6CECB74EEULL,
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
		0xEF263F770A73691DULL,
		0xB6640A1F794C6C24ULL,
		0x333BFE6BFE2931DEULL,
		0x53669A79AACABE2EULL,
		0x3005CEBAD1332CBFULL,
		0xD7EBE14EBD32BEE8ULL,
		0x694324EF7C049404ULL,
		0x8B4DD6D1FC026820ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1002EF32180C1095ULL,
		0xC3677BCF8ED4C29CULL,
		0xD33379F866D72A96ULL,
		0x00F47DA5132632FDULL,
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
		0x1CA78760C4F0D44FULL,
		0x714D552AB5E91F5AULL,
		0xAE21E7C038D89E21ULL,
		0x222725CA7E3CD35BULL,
		0x5530475934BDC779ULL,
		0x838228ACE87C41CCULL,
		0xEF0AA25BEE281095ULL,
		0xB12BFAA935CC3807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D21E9E991C7421ULL,
		0xF69F5ED5385AE3AEULL,
		0x29B6016592CB1452ULL,
		0x6EAE5AE87A8D2489ULL,
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
		0xBAAA469A1E7DDEDBULL,
		0xC9E17AB0258A2090ULL,
		0x24C4F982EFB0CB92ULL,
		0x118374B5839A4EADULL,
		0xC582EF21F6D39D4FULL,
		0x3982F035B46D99AAULL,
		0xC270041B02A49E91ULL,
		0xEC9878FB8C0AF913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C19C5A4C1E73DC7ULL,
		0x535122A8EDCEEFEAULL,
		0x0165958554205521ULL,
		0x30256A0C4D3B479CULL,
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
		0xB42198E8578D9410ULL,
		0x8D001AD75C48D009ULL,
		0xD01DE938C9566C76ULL,
		0x1F2242AF0B088BFEULL,
		0x057D69727865F7D5ULL,
		0xD08EE100ADE28E88ULL,
		0x55EA50CB9CB4A1B6ULL,
		0xC401956BB2DD43A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84BF3FE636B061FCULL,
		0x823580F12BE9F83AULL,
		0x90E5E7720C266D99ULL,
		0x375E70AB97E095CBULL,
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
		0xBE840B72809E927AULL,
		0x15F7BF322ED8385FULL,
		0x1239E9CC0E141F91ULL,
		0xD82EED66C17BF236ULL,
		0xE0A8CC7959C7BD76ULL,
		0x9E6E71AE30670A18ULL,
		0xB5DBD60C5E796EDBULL,
		0x26348D5E6A237EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17926575D444B2F5ULL,
		0x9A5C9F0D5E23B811ULL,
		0x10DBAFA2141A942AULL,
		0x03FBE96A82C0BE5DULL,
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
		0xA5590E48E4060824ULL,
		0x06FBD814EFD5FB09ULL,
		0xB746E448AA8EF4ABULL,
		0xA10E8916FD5FB134ULL,
		0x7C699C1A99E83B4BULL,
		0xC038B07BB28E2A4DULL,
		0x49452C0D217A1CDCULL,
		0x44C8C258B3B38CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D063A3BBC7ED6D5ULL,
		0x8F660A7170F0428AULL,
		0x978B6E3BA2AF3D6FULL,
		0x56DB6241AA0695BFULL,
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
		0x4DA51915A1430980ULL,
		0x9238224AA616AA0BULL,
		0x71A8C92165059312ULL,
		0xE987FBABA515E653ULL,
		0x11C5E9B9FF207D2CULL,
		0x12E9E1400AB5969CULL,
		0x4B513229581C2E2BULL,
		0x97120681B9FE1566ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF105CAB18015A172ULL,
		0x60EF91CC3D0B0535ULL,
		0x9FB63B4479346D77ULL,
		0x5634F2ED40CD1382ULL,
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
		0x12627D469D617F1BULL,
		0xF929847EE699C124ULL,
		0x370D9923E30657DCULL,
		0xB0938F66555C9F8AULL,
		0xB2D0EAA1BA10825DULL,
		0x23F5CB587A5E3391ULL,
		0x42091C33058E3D9BULL,
		0x996AF003197B49F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6551483BD4DC53ULL,
		0x4FA5B3A1109568C4ULL,
		0x0467C8B6B6237CE4ULL,
		0x76732FDC1DA99980ULL,
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
		0x0BB39DF4C45E158AULL,
		0x550D0719FB81E5F8ULL,
		0x79B4CC1A68946521ULL,
		0xD6C3CA55E2CF82B8ULL,
		0x6412FA87925330EAULL,
		0x9479CD65BD9BAC04ULL,
		0x887DAF0685D47E7FULL,
		0x2E535211D8BACE53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE684CE147CB75963ULL,
		0x5F218434209D6E9EULL,
		0xBC5CC712461F2C11ULL,
		0x3721F8FC0E8A231EULL,
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
		0x182348F7909CD016ULL,
		0x6C80F8E4ACDDAFCFULL,
		0xDEEBF92266BDABEBULL,
		0x5A918B6D5FEBE236ULL,
		0x67A9B54CC3E86B6EULL,
		0x3E2FD6752E21C5C8ULL,
		0xC2B75DE29F1C7184ULL,
		0xEF273B05A0DBDBBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B54325CA51CC7AFULL,
		0xA79ACE4985E10B8EULL,
		0xC623E8C604F6858CULL,
		0x5A644E43408E8087ULL,
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
		0x2EC40FA9C8693D57ULL,
		0x37254BB00FF2808CULL,
		0x4186DFFC7D32BABAULL,
		0x82B925964B6ADE54ULL,
		0x0A7A878290C1DA15ULL,
		0x62B8249EFDF735E1ULL,
		0x207D237D229BAA15ULL,
		0xF830918E4B3A99D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCF42D0B452FA1F3ULL,
		0xDE7ABB49C2A47FF3ULL,
		0x141A248FA04DF9E6ULL,
		0x59EEC0B5761DB469ULL,
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
		0x9C67978D0AC3E028ULL,
		0x9E3AB80F84744E9DULL,
		0x9762EA57BB12159FULL,
		0x7F5B4F599CAB9F20ULL,
		0x5BBB3EED2FA70003ULL,
		0xF06B7747A6B8C221ULL,
		0x5446DECCEE64883BULL,
		0xAD1E1A63FE415C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A32EEC21D8DE476ULL,
		0x4E2E6CB243E11F91ULL,
		0x19E7FCC31DFE4E85ULL,
		0x31D33A315A5F570FULL,
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
		0x9838BA0AFC59F53FULL,
		0xFC03CD2B013A706DULL,
		0xB53410489BBBB80DULL,
		0x7420FB12E6B3A7CDULL,
		0x56331F2C4F5AA392ULL,
		0xC76A105C61AC4B47ULL,
		0x5BD17CEA8B79F539ULL,
		0xCEB57AA2BA76401EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63CF5A9EC3CE4185ULL,
		0x95C23AE180CD9D04ULL,
		0x564C9B194FD61EA1ULL,
		0x23112F3A94412C4FULL,
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
		0xF1F1C315EA88810AULL,
		0xBA33C4321A37EE48ULL,
		0x82ED1EE8F240C215ULL,
		0x8A2C03D44BAFFB2BULL,
		0xD53E382CB0D36A1FULL,
		0x761F28404F187CAEULL,
		0x886DADFB93EAE5A5ULL,
		0x57941D4C0FD0A21EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x992E19B829EA43A5ULL,
		0x42D3BDBDD7DA703CULL,
		0xC334F240E71ED8A5ULL,
		0x0A285D1EA4A80BB3ULL,
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
		0x6FA8654765CF843CULL,
		0x34B1D3CF90133496ULL,
		0xAE29B5B4EA294234ULL,
		0xD12CC21D250AA1B3ULL,
		0xE1E894EA43F1319DULL,
		0xF37F1E08AA626D98ULL,
		0x8352D489743CBEFAULL,
		0x82F16839B875D0F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82E800D7B9CE482ULL,
		0x59904918DAAF7947ULL,
		0x2C75421C2B2D9B74ULL,
		0x41023AAE8687A5D9ULL,
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
		0x7180BEA9A4D36391ULL,
		0x1D8C26AA0FB7DD1CULL,
		0x6AF36CE1409658AAULL,
		0x2CF20AB3CFBFD0B1ULL,
		0x7C04BDB3693651DFULL,
		0xD08A55033C7F2076ULL,
		0xB387166BA8AC6D2AULL,
		0x2F85273DA50831D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA34E74B42E38BB5ULL,
		0x1214C5250A96AEB2ULL,
		0x1100C0DC4A2E8D05ULL,
		0x3AB5DDDA4EF736DCULL,
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
		0x14404D562A272444ULL,
		0x4158B9ED5ABB74F5ULL,
		0x225C7479095EEB62ULL,
		0xE57D96A468A4C1FAULL,
		0xDA6FF42AEE42E638ULL,
		0xBB3C9C0D3FD554EBULL,
		0x8C2C4E89D49DA1C7ULL,
		0xC17A26BE7ABFC24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DE8BB5881554F5ULL,
		0x0C57E3E4D4660FF7ULL,
		0xF0F01CEE98C4EF08ULL,
		0x1D9F56EAA11B997CULL,
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
		0x13B47C71404444C1ULL,
		0x94678F3EAACD7F0CULL,
		0xC04C0A0D2E3EA1E2ULL,
		0x3B963B08D5BA0808ULL,
		0xF8FED8F00D03EA1BULL,
		0x4A06BD8F121FE43EULL,
		0x69EAEFE8A7E7DC69ULL,
		0x539EA71C4D3AA268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0988B0132ED9069EULL,
		0x9167B27B5B896065ULL,
		0x792BA6961AA95983ULL,
		0x2523093C4C6E2388ULL,
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
		0x3B75F80E990DB122ULL,
		0x31C83779F2EC0FE4ULL,
		0x3E80BDED840D6A94ULL,
		0xE57B440B8A8D0EBDULL,
		0x0273E4A540B58104ULL,
		0x8427818512A74FE6ULL,
		0x3C6341FA761C13D2ULL,
		0xCA1E68136242CEF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A9E89633FEDC41ULL,
		0xCFA5713AB7C1EC08ULL,
		0x353C891B0C385BD3ULL,
		0x65FEB6EC2077C796ULL,
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
		0xF20430BECE89E171ULL,
		0x7CBFC4BD99F856C4ULL,
		0xFD5B3F6EE5FA9221ULL,
		0xD91D63215DFAC9F0ULL,
		0xC86DA5E2537E082CULL,
		0x508BB20F34A5D497ULL,
		0xB12BB4BC8671C719ULL,
		0x37587618D3E10D4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB24AD057333F194FULL,
		0x717C32FF6A95E54CULL,
		0x49D8136ADADE1FE3ULL,
		0x103EEAD0D162C3C5ULL,
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
		0x9A529458F36D3984ULL,
		0x047C8A1B596D6D04ULL,
		0xDA49E75CF23221EDULL,
		0xB8DDC2F28E45673FULL,
		0x8E0C0E72D338241DULL,
		0xF46446D6EB1A5FD1ULL,
		0x44260F84C1DF6ACCULL,
		0xCE1E40D46EE454B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01CB9644DC29A6CULL,
		0x4B5F0E023F57A61FULL,
		0xF7F03511B95BFC59ULL,
		0x515B627B0429FA27ULL,
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
		0x0F8C080FDAC7E1A2ULL,
		0xBFAC3FE0E2AFC4D2ULL,
		0x36D511E3C664F0E6ULL,
		0x10A6E3AF2B730DFCULL,
		0x000D502666DFE967ULL,
		0xC55AD370015EDC7DULL,
		0x803DD03A3AD8D665ULL,
		0xF1B366FB041D4422ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1185EDC320048C31ULL,
		0x0B27A28116C47F60ULL,
		0x4001FA888294C402ULL,
		0x71482CF1C7CB2B1BULL,
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
		0xE71A042D087235ADULL,
		0xEB0FF834F8696960ULL,
		0xEC42303B03C03AA1ULL,
		0x3FB08B10717E0341ULL,
		0x13113B444093E3DEULL,
		0xAA8D1178C288D9AAULL,
		0xD3C1767D6D75FBE4ULL,
		0xD69BE79A34D6E6ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA8D04E9E660D61ULL,
		0x3C009021D8B9B89FULL,
		0x5AF9C6D943439E93ULL,
		0x1AD4EBF449644A69ULL,
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
		0x1EEC1647B8EB1BBFULL,
		0x2B2115C71FB00CE2ULL,
		0x889FF2B2024C2A35ULL,
		0x715F2EBAE592B09CULL,
		0x51AB8D2F4C8ED60CULL,
		0x88A703308C34BB48ULL,
		0x593F97ECF212B992ULL,
		0xDE8EBB440758A184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E630B4D161EE66DULL,
		0x73EB8EFBEF83D99EULL,
		0xC8107FDDF113B5F5ULL,
		0x7A8EFAD3FCBAAA41ULL,
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
		0xC44AAC0BFECC4056ULL,
		0x55148EF840727647ULL,
		0x7F6D01B2E81CE7F5ULL,
		0x22895CFDDC2E528CULL,
		0xA4A64410A30572F8ULL,
		0x85647AF09577E95FULL,
		0xDC8B6E5C7FB8251CULL,
		0xD2E03743A65EC430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F8C684319B55C0ULL,
		0x21FECEAE703F1A7AULL,
		0x3C1F636DDD726A31ULL,
		0x6FD191088E3F71CDULL,
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
		0xDE049A4ADBD87673ULL,
		0xD2E3B9A69A66004EULL,
		0x3A7131E3FCEF391EULL,
		0x048B0E62B9580DD0ULL,
		0x22D30A45C794F977ULL,
		0x1713A32BDD53EA79ULL,
		0x5DEAB40AF50272B4ULL,
		0xF4516A3D6F79A316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095820A67BF58375ULL,
		0x3FCDF22974DACE4AULL,
		0x2B47EB845B4C3FDAULL,
		0x48A0D38145664322ULL,
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
		0xEC69A0A07DAD349EULL,
		0xC4B2EFE05EBEC68EULL,
		0xFE2FB8C4A8742064ULL,
		0x191A2EDBA1E11EDBULL,
		0x9A9664B15BFC0AAEULL,
		0x4D7CC611DA544C83ULL,
		0x93B7D9AA3664D107ULL,
		0x9CDACE6B7761330AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBC92F42516CDDCULL,
		0x45385686C7422217ULL,
		0xEB7A0808BB6B277AULL,
		0x6194D2CF5A4EB26DULL,
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
		0xF58D30CB48A64823ULL,
		0x696ADEFAEA04E84CULL,
		0x8A56DD256896F76CULL,
		0xB8B3A401A2B4F6D9ULL,
		0x22130C7332977239ULL,
		0xE134055275B6403DULL,
		0x5D9C0CE2ACB56978ULL,
		0xA46BEB40C0AFE021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x046109E4CB21404FULL,
		0xD723A93863127160ULL,
		0x6F80C6CB0B849F5DULL,
		0x20B88F9E3CD03BCDULL,
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
		0x1E514A062F760A25ULL,
		0x6B49732CEAED4599ULL,
		0x86A8F6E3F8116D14ULL,
		0x1128CC191A951661ULL,
		0x4AE3978D7E4BD96EULL,
		0xAC348716244CB266ULL,
		0x00E2945A960E84CCULL,
		0x860A25F5280DE45EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C19C906EEB8535EULL,
		0xFB1580764E4FC0C8ULL,
		0xA84AFC563E392375ULL,
		0x76AA6E7D0CA4FC55ULL,
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
		0x0EC62EE7E0E71888ULL,
		0x12D715B96A87526AULL,
		0xE55772B9DB9CE883ULL,
		0xA3E9B3C0C6EE91D1ULL,
		0xCAE2EF1C9908734DULL,
		0x8B8E71EE1EC419ACULL,
		0x6CECF33E9E685183ULL,
		0x3159A790095E2BA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C75AD2698283713ULL,
		0xC9FBFF11FBA32210ULL,
		0x10838E055F190209ULL,
		0x773893222AE90CF8ULL,
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
		0xF45FF3425F1DF724ULL,
		0xAC640811BB2B53AAULL,
		0x31933F0914165243ULL,
		0x33655035DC7962C5ULL,
		0x5FEAE479F728D500ULL,
		0x7A3FABE1937F6C3DULL,
		0x9C8D4ADA85865083ULL,
		0x4EED5FEC2BD45617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x313DDD5D0F2D96D9ULL,
		0xD1D78B8DA01564C7ULL,
		0x6E8C5B78E60645C7ULL,
		0x6AA18D445DFE2A46ULL,
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
		0x3149E5DBE38D2988ULL,
		0xAF8AD085C790553EULL,
		0x121C22EFE868593DULL,
		0x420671C1DEB2718CULL,
		0xE39EC38D4318D043ULL,
		0x31B4F751DCD91E9DULL,
		0x80C7D5B7E211B84AULL,
		0x99F86AB1DB033429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADAECD3D93C16E4ULL,
		0x106786AC8FCAE0ADULL,
		0x2FC5DC3B7709B441ULL,
		0x1CE64828612C2FB5ULL,
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
		0x330494B658B6D567ULL,
		0x6DE06F634C64AE8CULL,
		0x5AFC43D32B23BC87ULL,
		0xBCAEA0D8FD97C0E8ULL,
		0x3BD6C8AA06282B87ULL,
		0x1FAE60F6EDD63451ULL,
		0x19F4B06CAE5081FEULL,
		0x7FE97E5246683A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E65DF342AD4E56ULL,
		0x21C2D40A9A30729BULL,
		0x354E73F50B170840ULL,
		0x3957610F711070AAULL,
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
		0x7EF9AE4176EB5F9EULL,
		0x45BC9998C358C26BULL,
		0xE0FABDEC52EDEE98ULL,
		0xB2AA03C90D577C13ULL,
		0x076386442EF72356ULL,
		0xF1DBC0E340AE1F4DULL,
		0x9D7A287FCB0F1D5BULL,
		0xEB9CB38F494CCB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97BF9C606F9AA3A7ULL,
		0x2C5B3B545D3167DAULL,
		0x411CC0E4772C4A3EULL,
		0x2BECAB0DEEBDAE0DULL,
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
		0xD13B3617F09E4335ULL,
		0x8CBDCF7D1B0968E3ULL,
		0x2D2E9345F9E5004DULL,
		0x93CEDCA023062AAFULL,
		0x93C28656FFE06EB0ULL,
		0xD01C402F6B384451ULL,
		0xFFA2B8A9D398AADAULL,
		0x1B3FE6447A50D3B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC01B2701EBEEB200ULL,
		0x70EF568705638CFFULL,
		0x1F55FC7B628E5CC8ULL,
		0x1F4B0ACA4B05984BULL,
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
		0x4438C6114B02330FULL,
		0xC871EE4DD132C156ULL,
		0x9007D91D05DEE001ULL,
		0x159E319367CFAA71ULL,
		0x026ADCEA1437CE29ULL,
		0x2B365F3ADC79899DULL,
		0x2E31C94B33D20A5BULL,
		0xBD8A78D8BB982BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA01590D04B4AD14DULL,
		0x3284110A8B3D2EA4ULL,
		0x6B6BBA46B70C698AULL,
		0x382C21BF4066245EULL,
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
		0x672E3010A2E56A0CULL,
		0x1A9096B4AE9F795FULL,
		0x6BDAE1AF2E8CEFAFULL,
		0x793E991594065E0CULL,
		0x0CF4D8975B671A05ULL,
		0xC18B917AD5F51FBBULL,
		0x5A1A43C5B58D68A9ULL,
		0xE775F589BB4C7760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5386568834334BE9ULL,
		0xD5482EF071022F23ULL,
		0xCBC0F108218A78E1ULL,
		0x54C10B8761601659ULL,
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
		0xE7E2400A1F207DB2ULL,
		0x28D6AB6FF4724CD1ULL,
		0x2B1C00856D82F595ULL,
		0x8855211553F1956FULL,
		0xAF28A22A05E706B1ULL,
		0xAEA299877638F257ULL,
		0xD7F90DC988E0E6D2ULL,
		0x6776D0A35F7B492FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EA5246FF6B7E45ULL,
		0x14F9758B80E645D5ULL,
		0x3A140C6FBEE538DBULL,
		0x63F81955803E7289ULL,
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
		0x6B606666E74BC213ULL,
		0x915F236F186558B1ULL,
		0xCFC94780A50F7D5CULL,
		0x33460AEDF9612FE3ULL,
		0xDA898BC14CD648D0ULL,
		0xA7597A6521C49C96ULL,
		0x5995FF48540DB8C5ULL,
		0x0733CEBE718F00E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBCB25184F1A9119ULL,
		0x68A74E721B949715ULL,
		0x1C0D2C3D1F18EAB3ULL,
		0x44F6BB32D49B5131ULL,
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
		0x1BBDEFB34572B2B4ULL,
		0x9754223320AB7992ULL,
		0xCC967ABC0D085E9BULL,
		0xB10F6F96C35507D2ULL,
		0x6DC7CC6C6627CB6BULL,
		0x1DADEB3B7FF3D7E6ULL,
		0x97C29B4DDC95A74BULL,
		0x33164D48E55AB071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x676647CA6F5AE5C6ULL,
		0xFF250D081EDD85C6ULL,
		0x5379884ACB3F33C1ULL,
		0x465EE868CECB38AFULL,
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
		0xD512C9D521968E38ULL,
		0xF7BC7BD15D664DC5ULL,
		0xEDAFB92019D4BEA2ULL,
		0x90C20BAB717324F1ULL,
		0xE3A96760FA2560C5ULL,
		0x40BF7C316ECFF341ULL,
		0x4F20FB2D21029791ULL,
		0x156164641F312133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA038223A4322EBFBULL,
		0x9428EB27D044698DULL,
		0xAC9501D300373E32ULL,
		0x3D36F28812BE128FULL,
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
		0xD25A723D6FEB0BECULL,
		0x280335B51A97AED5ULL,
		0x7903CB68422CBCF3ULL,
		0xECACCF96211661CFULL,
		0x8B19FFE3F73D9D1FULL,
		0xCE7CDB5635DDCD30ULL,
		0xE41D2D1F33DDC6CAULL,
		0x3C3FD1633E4D4622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78366E1423105FEFULL,
		0xCE8BC4811984240AULL,
		0x55587E09F5183F0DULL,
		0x5E25E451608ECAFDULL,
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
		0x4BE7C5BE4D037F7CULL,
		0xB580FE00A513675CULL,
		0x73D1BF014730DF01ULL,
		0x8FB72052A086CFE5ULL,
		0x68F82402B382B3B6ULL,
		0xE255B9E4B410324FULL,
		0x2BFAB689A83514E9ULL,
		0x6A6B02F2B7DBBE51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0BD1E24F26A2EE0ULL,
		0x4E3A95F35F7ADF25ULL,
		0xFB08D7703F11F9B9ULL,
		0x5B999059EB250FF1ULL,
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
		0x26DE731708C490FAULL,
		0xD97DC8AD619D25BEULL,
		0x391D6AF1CA376CB3ULL,
		0x751BA228456B14A0ULL,
		0xCF4D30F9F9F8EE32ULL,
		0x29A847CEED53A634ULL,
		0xB005888930F970A7ULL,
		0x7B6DCC5983D02550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC53B83223B7EF25ULL,
		0x087871649C07D194ULL,
		0x59EFAF4F0F3E2584ULL,
		0x4767F771D6509E9AULL,
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
		0x26B9FD2EB99AC525ULL,
		0x217752F3BA71D446ULL,
		0x67E14E209C6AC9C3ULL,
		0x5363F40F27C1DA5BULL,
		0x2758B3B383104760ULL,
		0xE765FBD263DBEC29ULL,
		0x410781B52A47733CULL,
		0x339399EEC9BC637DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE4A9D42E055E82ULL,
		0x7A9AB42E8D16E261ULL,
		0x0EFE8F04E305E4CDULL,
		0x7B4CCD8119B89EF3ULL,
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
		0x7699B44A89CF02FDULL,
		0xDB79D65C275FA2ABULL,
		0x19FA15E60E6A253FULL,
		0x274EA7CFC9168C0EULL,
		0x66436CA11563709DULL,
		0x5E8A17787C3EF032ULL,
		0xC127B5673D8CAC7EULL,
		0x1974CF3B603B5699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49BD433B691BAD0ULL,
		0xE3F9523E98B74A26ULL,
		0xC5DF0339314BC001ULL,
		0x6EA56AA011E566E0ULL,
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
		0x2105D66983864941ULL,
		0x12BA952A92DC6D2BULL,
		0xEBC5D74ACD0D8C0DULL,
		0xDEBA1684D149C168ULL,
		0xBE7B871081B1334AULL,
		0x11510C2524D2FB1CULL,
		0xAB5F3E6CB76BB4D4ULL,
		0xFE4D57BE5CB72F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x675BE2DCC3D3EBF4ULL,
		0xA4C262AE0A2DB36FULL,
		0x5BE91B6E070A6387ULL,
		0x1E351CC6947AC92AULL,
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
		0x75094A984614F951ULL,
		0xC225D9661B23FACDULL,
		0x115ADE6727D939BBULL,
		0xBE9E97721F4E2996ULL,
		0xFB72D8AB7A2BAA59ULL,
		0x8B47653F446723CEULL,
		0x7C54510D48F4E224ULL,
		0xE0FA94B755410447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC815740C68904793ULL,
		0x6EBEE0CA42734B86ULL,
		0x85DEE65FFC32CB28ULL,
		0x23D0AAA8C6F4CC32ULL,
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
		0x91360309E7035917ULL,
		0x86E1968883427C13ULL,
		0x4575F49A94573149ULL,
		0x51A9B7DD2168AFE5ULL,
		0xD7BB35E9C7A95637ULL,
		0x57B98A0E65167069ULL,
		0x82DDE7EC875A4417ULL,
		0x3720B05BC5A1216FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x970003BD8A262684ULL,
		0x8C6C14AB84972BC9ULL,
		0xB26661B6ABBD4CC0ULL,
		0x0083E57C7753A672ULL,
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
		0xBB922B3804535510ULL,
		0x7FD1C409E23E9231ULL,
		0x1CDB60A27DF33FA4ULL,
		0xBE02CDEDEA212845ULL,
		0xE414FF805A083959ULL,
		0x5FBE0152D75BC673ULL,
		0xA6944264221619C4ULL,
		0x6937C9AEAE74492BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B01845618BDAA6ULL,
		0xB605F655D9DE0765ULL,
		0xD6DD3B7F8D3B12CAULL,
		0x5C4ABDDBCF6404BFULL,
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
		0xFF1FB8092D9734E8ULL,
		0xDBBA1D36F98AB311ULL,
		0xD6B76E99584419CDULL,
		0x46AD08D24E53FF4AULL,
		0x13969EA609D54DEDULL,
		0x85051CCC971BA73BULL,
		0xA13E3AFD1948ED56ULL,
		0x351C5090BC85DFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE77B44AEA340C746ULL,
		0x9A7C639567A585D6ULL,
		0xC5F4302B191754A5ULL,
		0x28E0FE4E4A3332C4ULL,
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
		0xDB8EAAC8EDBAF466ULL,
		0x37A0756AFA0BF64AULL,
		0x4E919519976323E8ULL,
		0x64116B9A8DB2F5BBULL,
		0x9536C44817B7A2FFULL,
		0x0495619745116307ULL,
		0xF7F1E5A48C971A4AULL,
		0x47B6E0D3B8BB5946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AFCD7C72FD27E2ULL,
		0xE5CCF1DF3AA0A96BULL,
		0x1C79AB8675D10AE4ULL,
		0x0936CB07F9823644ULL,
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
		0x68647483F5BC57E5ULL,
		0x0570849FF6A02C09ULL,
		0x1F38DD8686DF23A9ULL,
		0xFAA6E1630E8BB4BCULL,
		0x5068BF5CCD8C3960ULL,
		0xA8CE64B97DA8D275ULL,
		0xC1748CCFC832E5D6ULL,
		0x2586CE89A526A3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F0DC4A788CDD1CULL,
		0x141378289DAF6973ULL,
		0xD685C45E3E6D4186ULL,
		0x0CA989D19247FFA2ULL,
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
		0x17E560FA1AE50CCBULL,
		0x38013C376AA6F723ULL,
		0x5B37FA047251E21EULL,
		0xDAE88393ACBF4262ULL,
		0x8C6BA2D48BEBCC62ULL,
		0xEB34E495F3C22EC7ULL,
		0xC815E9A16DC38303ULL,
		0xD94F0A2F49EE5B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFDF8C86DFE5683DULL,
		0x21DB2A799979E8C1ULL,
		0x0E78A7FABD5754B3ULL,
		0x1CA40698A620CA96ULL,
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
		0xD2809BF6FA02C119ULL,
		0xBAB1583F0BF003D5ULL,
		0x8A44DC22A1E65A86ULL,
		0x8BA1DB763EB3DDDCULL,
		0xA4412B00706636C2ULL,
		0xA3E4E03CBE908DA6ULL,
		0x2A35CAB2A598CB29ULL,
		0xDF25FB77804AEF62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342CFE07A92EE6DEULL,
		0x0EAAA14355650A92ULL,
		0xCE40F2A7369482B5ULL,
		0x2B452F3349D3666EULL,
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
		0xDD374116C85BEF50ULL,
		0xFB7CE25A5B836FC1ULL,
		0xB8046A11EA88AEB7ULL,
		0x3F187023B9FB9AF6ULL,
		0x5FAB966FFD37D234ULL,
		0xB8FCA9D69AF56EA8ULL,
		0x82483624236D83BFULL,
		0x8ADBF6E3E071E3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10AF95B65EA52613ULL,
		0x70FE18355BF1DCC0ULL,
		0x0EBC736F2CCA3D2DULL,
		0x5BBF15F70AE36588ULL,
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
		0x25C17297E4E8346CULL,
		0x9FA727A3D660C26EULL,
		0x929AF8C4B08EE3EBULL,
		0xF35F727798EAB6ECULL,
		0xE715221D67E80DE1ULL,
		0x1DF506E379C0DE81ULL,
		0xB86C204366C139C5ULL,
		0xF11C641ABF56AB99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72E482F5515A493DULL,
		0x12062D67E901C9B6ULL,
		0xF2A7C2C5F13D772EULL,
		0x3D964E6FFFC82FBDULL,
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
		0xFCF0C0F49D83A1F7ULL,
		0x1422A281F04A8C76ULL,
		0x570B6EDDC430F683ULL,
		0x30CA2791B6D8CDE7ULL,
		0xB5FBFCE3B180968AULL,
		0x4AE1F09ED106AF20ULL,
		0xEB5D01CA74015492ULL,
		0xD9E1B7488E00666EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00584AC0F699FF46ULL,
		0x31AC5A14F7488B52ULL,
		0x46D9B2EAFC63843AULL,
		0x084B5C56CAE8025EULL,
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
		0x924035E948589D41ULL,
		0x050F1F26A3FC7334ULL,
		0xFAD85FE2750FB096ULL,
		0x3933F22C72A8B537ULL,
		0x9EDC7543554C007EULL,
		0xA6A669464808DDCAULL,
		0x614C3D976612521AULL,
		0xAFACA529363D56AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26F99DE7F1A0B3D1ULL,
		0xC1C2BF95554D5F48ULL,
		0x6C29845B9BC7E08AULL,
		0x4CD4764A7FC39282ULL,
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
		0xF8D27200CFB7CA7FULL,
		0x1D44512F838EB16BULL,
		0xB61C0D2C26F43936ULL,
		0xF99A046AD50C32E3ULL,
		0x7EC923FBD24DB8FAULL,
		0xA07AFC46AA0FE8B8ULL,
		0xAE57A22E6964B427ULL,
		0xB5030114B0D6B4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAADC962074143B0ULL,
		0xEF85C3ACC1EB3CCEULL,
		0x971E200FCBE6F717ULL,
		0x580C2D7D14EB09B7ULL,
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
		0xC4C2BDDBFFDAC62EULL,
		0x8CD157EB3C6D3BF1ULL,
		0x8F727499E2287D09ULL,
		0xE9E6495F49BF44E1ULL,
		0xD614A62AC2558935ULL,
		0x43837B6F0A718E6CULL,
		0xE942D6E399D78EE8ULL,
		0x6369030596E85009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD36834D88D2659ULL,
		0x9255AA66C9486019ULL,
		0x2F5E5A62B827B383ULL,
		0x2B7CBC33B03B265AULL,
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
		0x334016D5D4A7B2EEULL,
		0x287D1EEA40178493ULL,
		0xD453831E0F65EC1FULL,
		0x1AC366C9BE7F6C47ULL,
		0x3AA7C12123E82D0BULL,
		0xAA12B702E6219D39ULL,
		0xA99A391D793C8D77ULL,
		0x06B7FF7F71B7BF9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE826C1C1291E62B6ULL,
		0x674449586914DB11ULL,
		0x0137FD7E0E62EBE2ULL,
		0x1A1353B49FC5DDAFULL,
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
		0xC44DB14A5B1F2D21ULL,
		0x14C98C7F53315602ULL,
		0x0915667AD6ECFFF5ULL,
		0xBC6EE5594670F3D3ULL,
		0xAD41F18D04135921ULL,
		0x9C4547C745F9934CULL,
		0x4841EADC4EE49BAFULL,
		0x4E0710F2DAAA23B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C178C38F5FE69CFULL,
		0x47123413B63D3364ULL,
		0xC2DE432E8CDC1C06ULL,
		0x517B6965BBB23FFDULL,
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
		0xE6542E7F28D132EAULL,
		0xDC1B717B50327C48ULL,
		0x27D0D04965A17E89ULL,
		0xBB778F590F4F9288ULL,
		0xA068DC5633063189ULL,
		0xB4A2230A8D8AA49BULL,
		0xFCA7F39F4811F0F7ULL,
		0xE754DCDF61358684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E4E34ABBBC9272ULL,
		0xAC2CA50C52C6EB62ULL,
		0xA8BEF9EE184B434EULL,
		0x121058817D418A45ULL,
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
		0x1A35B7D9064BB93FULL,
		0xC279A54132A15C44ULL,
		0x0B57FFE5AAEF9A43ULL,
		0xBDC0606548E23B09ULL,
		0x3ACEB0F271E50F3CULL,
		0xDEF322DE5AEDC575ULL,
		0xDA228D5835584FE4ULL,
		0x6B2EEC3C5E25E9D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4E3FBD5EE4BFE9AULL,
		0xDA90D242B1ECABAAULL,
		0x6C78FAFD960B763CULL,
		0x26B7715B4282F009ULL,
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
		0x1AED23A809C364D6ULL,
		0x1A0125BDD9CE35C2ULL,
		0x9C0CA91374F7E638ULL,
		0x1E1CEE96D91D8A82ULL,
		0xACCFC56F944787A6ULL,
		0x675D2043D041A8E0ULL,
		0x83482431AE0645E7ULL,
		0x8189E1C194C09125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C472380C618A4CULL,
		0x71D3EFCEC38D471BULL,
		0x18C2087349E64691ULL,
		0x58947152EDB31614ULL,
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
		0xC7A83EA43C0D398FULL,
		0xF455517B238BB38CULL,
		0xC75A87046D56B35EULL,
		0x9233BCDC1F9A6E73ULL,
		0xB659356956DC5044ULL,
		0xBA4C65B3E76B9D5FULL,
		0xCD0F16D9341A3F8BULL,
		0xF33D97E9C9905C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8E62C4720C12912ULL,
		0x9BAC6A2F7D850FC1ULL,
		0x3797EB42293C221CULL,
		0x2D5849900B08180EULL,
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
		0xBE0A527D47A5BA7BULL,
		0x16F9E244D8DAEDE8ULL,
		0xC24AB133970E8E6DULL,
		0x56F9354A2DFB69A0ULL,
		0xB039B0F00EFB40ADULL,
		0x9C823D964384D705ULL,
		0xF6EBEDE32E6D0DADULL,
		0x2E8BDA80587322F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE69A961F80F15533ULL,
		0x524F0692DE92D8C0ULL,
		0x695000EC7B3E9632ULL,
		0x3FBBA4574F129A49ULL,
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
		0xCBC81A4CB9B1B6E3ULL,
		0xF360603AD83A16BDULL,
		0xC2F8AC6B611FBEAEULL,
		0x66BCF55E5F23E046ULL,
		0x1A592BE124212520ULL,
		0x30563982C478550FULL,
		0x235716E1E283BABBULL,
		0x4F4E192DE28C814CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5049DB8169D3B6BULL,
		0x202CE9A40216B6FBULL,
		0x01E611F300AD7678ULL,
		0x2C54B22DFFFF1194ULL,
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
		0xD0DAC8BF2222CF94ULL,
		0x7D89B8070F884B91ULL,
		0x34545F501EF04458ULL,
		0x175ED527C572AFE6ULL,
		0x5639E8BE55B6BD35ULL,
		0xE48B416360E6E4EBULL,
		0x69E291D50C4CBD63ULL,
		0x0664AFC1ED52FA1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7354FFDB42E598ULL,
		0x6A356CC771CE4680ULL,
		0xEBF604EFF254612CULL,
		0x0A50EBF0FFC3D08FULL,
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
		0x3E42078DA4FE8B0DULL,
		0x3C955A202EFDDB99ULL,
		0x2FA9D70C68C76AE2ULL,
		0xD71B9B0CCF3C5325ULL,
		0xDAEC7A786A383690ULL,
		0xB1261CFCAE2580FEULL,
		0x0FE95A3F58B796B6ULL,
		0xB6623CC84B7A24E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5C356D6956A882ULL,
		0x883DA7A2088F016DULL,
		0x8C4D3C739407CA00ULL,
		0x69B0A0C8035DCD71ULL,
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
		0xB563B29EAF995445ULL,
		0x757CA4660EA04538ULL,
		0x9F85FC4AC1086975ULL,
		0x8937D184CE2C5A72ULL,
		0x32B8A26D40053DF1ULL,
		0x30C2FB6FBD0F8767ULL,
		0x34FA3359203DA6DAULL,
		0x75722995883D18FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CCBCED6306088A4ULL,
		0xB26DF6FC1EEE5E8AULL,
		0x7CA99B858A2F2DD8ULL,
		0x7829FDB7073E1008ULL,
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
		0x4C26F7B04FFB7895ULL,
		0x51D39BBB9BEF2B39ULL,
		0x4384A5098AE905AAULL,
		0x61963905F9804F74ULL,
		0x40AB32CD9EF4E027ULL,
		0xC975D4BC9A4121FAULL,
		0x4D90FC301F6CEFB6ULL,
		0x9E1CC25984D5A827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5908235E854C1DCULL,
		0x39512FBA819A365EULL,
		0xC70A142E35149ACCULL,
		0x59DB124FB1374549ULL,
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
		0x26B3CDD93ED24A55ULL,
		0xA94241D8C31389E6ULL,
		0x50CC8D0C5131C0B6ULL,
		0x088B9F44ECD2F0EAULL,
		0xDC70CF7A352C5533ULL,
		0xC5392A700F8C0BFBULL,
		0xCB9B2A42173FDF2FULL,
		0xBD0CC01AA73D0D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF7299FD2366F40FULL,
		0xEFBE8E7B11DD5148ULL,
		0x89D4D2DBC4ACE1CDULL,
		0x18702339BFE2E1B4ULL,
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
		0xA5BB8F9905B153D1ULL,
		0x205709BFE2821BD5ULL,
		0x6652943F8FE1C1D4ULL,
		0x241F355FE93CBCA3ULL,
		0xEEC9B2BD07F92483ULL,
		0x66C27FCE938820FFULL,
		0x037B2A048D554059ULL,
		0x2307D90FC23DC914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17AC17A834ACC001ULL,
		0x61360269C8B701D3ULL,
		0xEA9AD0EC8A894F19ULL,
		0x57496DB6BE68959BULL,
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
		0x3394396315AC7CBCULL,
		0x5DD0E3B5EE056C56ULL,
		0x3597C5359A94E005ULL,
		0xD3FEBD1E380E0DDBULL,
		0xEA6908E81DF4616BULL,
		0x29D128A997A2D11DULL,
		0x0BF9C65611FD44DFULL,
		0x1E656055539F7A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF2B8BD787F2F35CULL,
		0x92DCECE2703076C6ULL,
		0xFCAB35FC462D1925ULL,
		0x570B09C8A1BA34FEULL,
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
		0xC6A02EB7571A938DULL,
		0x52DE90221EA7281FULL,
		0x661A0A08A51669F4ULL,
		0xF8A707839B7CBB5BULL,
		0xA7ED3D51A393702BULL,
		0x9B2B241A9C5948CAULL,
		0xB7F21CF6617DA610ULL,
		0x4CDB368006015869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D748D59EFD3BB7ULL,
		0x5B45EC1553E7F634ULL,
		0xB40A569B1DBD106BULL,
		0x61311E847FAFDB0CULL,
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
		0xFD2D784C5901281AULL,
		0x560477D9CAB32B0AULL,
		0xB571544C3B7B6AC4ULL,
		0x7B710D8F6BA287C2ULL,
		0xEC7B2CBF29E675B5ULL,
		0x6B5B80FDA238B95AULL,
		0x5B38CAFF7781747AULL,
		0xC938F949F0525C46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17761CAC9136A56CULL,
		0x45999D7FDF1EAE8AULL,
		0x3FDF7637F8B2B4F0ULL,
		0x59E60E8917DC3A34ULL,
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
		0x265396C83ED1B7E5ULL,
		0x50660351438F8F9AULL,
		0xEC5A91B925570DC4ULL,
		0x2EA3BFE8F7435CA5ULL,
		0x75EDD4C79D1154BAULL,
		0x97C6E703D9B74E19ULL,
		0xE72C121F7FA0F3B7ULL,
		0x15B9E4FB63C16C14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A12C698F644BF3ULL,
		0xD7EC4DE394C52761ULL,
		0x3CE54266173B3B04ULL,
		0x683BBD39C5F967C0ULL,
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
		0xDBAE15B503AA147BULL,
		0x85660E54C6A5E9C1ULL,
		0xE9D4ACD21C5506AAULL,
		0x28699A703C867F11ULL,
		0x4623B0FDCDBA723BULL,
		0x03D76CA31D038897ULL,
		0x0AB410E236DB5B91ULL,
		0xF1A90ACE7A6F0FD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44FA5B618D570E95ULL,
		0x17602E8B152C3036ULL,
		0x808F2E6640E49E31ULL,
		0x078135166902D923ULL,
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
		0x67BAB08AC50ACB7DULL,
		0xE4A290D194B0E35CULL,
		0xDEE2D8938A918F7EULL,
		0x7D4B8678CE1E28F7ULL,
		0xCA1D8AF171FD2D7FULL,
		0xB28A74466617E5F1ULL,
		0x0A734E8146538767ULL,
		0x309350FEC17F5800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681D5061B09F8D74ULL,
		0x652FD344BC3D0540ULL,
		0x6C007FC3FAF7A8E3ULL,
		0x33298C49870538F9ULL,
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
		0x371815ED87159E3CULL,
		0x52B91C5395CDBFE5ULL,
		0x9787299459703250ULL,
		0x5DB773A1E5C71294ULL,
		0x9DA13AD3AE31B833ULL,
		0x4EDAF6D79AE7BAB5ULL,
		0x043793B34AA438E5ULL,
		0xDAD0BC6EF735B34FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D06D1596276FAA1ULL,
		0x0739C054943376DAULL,
		0x37C716316DD0A45AULL,
		0x58B36C1A97BFB04FULL,
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
		0x6504324E41B1002CULL,
		0x31E2E32128ECCDA9ULL,
		0xD57BEB9026BC6B83ULL,
		0x6A45101791912BF8ULL,
		0x14286434AB81AA69ULL,
		0xE26BAEBE574BB6F1ULL,
		0x67A9162960DC124DULL,
		0x09AC85119CA0DB7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6303121FB6F04BFBULL,
		0xCDDED3621E29F572ULL,
		0x389535B487672312ULL,
		0x59E0D0B4D171C0BCULL,
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
		0x916D8110829C319AULL,
		0x7C89BB12B4817640ULL,
		0x57AF29C4DA0E15E6ULL,
		0x4FC6DF8E3C7A9899ULL,
		0x1DDDA32BCA5CD1E9ULL,
		0xB9267387E48C2816ULL,
		0x776C8D00B3B0B16FULL,
		0x02520F231AAAF4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0053B9908C635A43ULL,
		0xF83EE13EA14F6989ULL,
		0x11CC17DF86486C7BULL,
		0x27F51EC431DAF3FFULL,
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
		0x0D5A4AA362BD3EF4ULL,
		0x11F56914B19052FDULL,
		0x4D84ACA2D10B5193ULL,
		0x6E5855AE369D0AACULL,
		0x4A846895F20436BFULL,
		0x6254D50C5F3D58A1ULL,
		0xE550E5E15C9ED0F3ULL,
		0x73D6C0BE13EF097DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D01D0E54F5D61E7ULL,
		0xAA8D08EAD4AB7AEEULL,
		0x5786CC16909E55B3ULL,
		0x2038F1E52C18735CULL,
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
		0xC9AC90D574CE76ABULL,
		0x12EB2077F139D195ULL,
		0x75EF38BFBDDF0AACULL,
		0x2199914233E1EDD4ULL,
		0xAF6AE67EF0FCC71AULL,
		0xAF5B8B21221E967FULL,
		0x55CA1D2E596CEB4CULL,
		0x4138FFF1B870915CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38AC7AD3A5405F0ULL,
		0x1A81C76301C42889ULL,
		0x31EF8DA10409F80EULL,
		0x500F8F2394978189ULL,
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
		0x9A0FC3335B8D22A0ULL,
		0x4D0ED14EC9A47EDEULL,
		0x3C4CF1FA7FBA6F46ULL,
		0x2138E1F7268C1A0FULL,
		0x20C120C67ED8E4A5ULL,
		0xB2A2B77E1AD4FDA2ULL,
		0x00B4EA0CF99F3F8CULL,
		0xEA187740B78A9D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BAA0AA2FBF183DULL,
		0xD1360E06C54224EFULL,
		0x5727AFE78D5DDE28ULL,
		0x60DA9592651F6919ULL,
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
		0x5E86A012A48284D6ULL,
		0x56E31A3E5DD7B07AULL,
		0x427D62EB8FCF91ECULL,
		0x97D017A03BD3F967ULL,
		0x5F5574D40757EC60ULL,
		0x3AAEE13A1C452D87ULL,
		0x559261F6F57A5255ULL,
		0x6910BEEF1D78D320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8535F78BBB8F9D76ULL,
		0x0CD888DE901C7292ULL,
		0xF637ED93FFF7CA93ULL,
		0x304C6F1E9BC35033ULL,
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
		0x09FD5E7D5778AFDDULL,
		0xFCFCC9EEFCF360DBULL,
		0x8CB3987F177375E1ULL,
		0x68146E4D5668890FULL,
		0x8697C2921549EAFBULL,
		0xC7FDB92B1F653D9FULL,
		0x9DD73FB3E726002FULL,
		0x9AAA4E69FB81E9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0484402C80719489ULL,
		0xACA64655A5FA8689ULL,
		0xFAA70D3367177CF9ULL,
		0x5D5C1208ABB13920ULL,
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
		0xD506F6A3FCBA72DAULL,
		0xEC2EE57B7A6CAEB9ULL,
		0x2574482C14C70564ULL,
		0xD3CFE4D6D39030D9ULL,
		0xA80EF5E576AEA81AULL,
		0xBE637D0C54C0961EULL,
		0x3D3FF636D59DF785ULL,
		0xEB0588ACE7BFB550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73F76B39AA76BFBULL,
		0x2EF375500F02F746ULL,
		0x3CF2D44FCA39C33FULL,
		0x36A22E813A051AC2ULL,
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
		0x6418A3CEA5C48B0CULL,
		0x36B8D1B4CEDF48BAULL,
		0xD0AB653774EDCC3AULL,
		0x0129D7F2172CC8D8ULL,
		0x1123C564ABBFFDEAULL,
		0x840B9CBA0916727FULL,
		0xB394A08D502BF88CULL,
		0x10C9AFB80205374EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF67F0C024443C14ULL,
		0xD072155228344796ULL,
		0x78BB3A315B74B115ULL,
		0x7F19ED4263F2FE87ULL,
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
		0xC9712B25A639DE00ULL,
		0x343C629358B4F4F3ULL,
		0xA61BAE2FD01CDB6DULL,
		0x5FEF5620C49D4C1AULL,
		0x651187216A2667BAULL,
		0x9AAC9343866BE045ULL,
		0xAB70C7FFFE0087A1ULL,
		0xE2BDC88CE98F6EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0B3A1B67ED48A8ULL,
		0x29DA3E994CB83F40ULL,
		0x18D95E2F8430FD6AULL,
		0x081B1B0B6FE7C492ULL,
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
		0x68C36C2739820010ULL,
		0xE72C8B16A5F283E9ULL,
		0x6253420B30CDA002ULL,
		0x46BB133A46223414ULL,
		0x5C7F52B1C5B62AA5ULL,
		0xCA9164EABC983503ULL,
		0x55961D38F1EC7115ULL,
		0x54A817B06AE65B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A9B28A928C5669ULL,
		0xF8C185EEA48A6269ULL,
		0x169B987F19E6693EULL,
		0x57AE976A2453C77FULL,
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
		0x9129387AD394C853ULL,
		0xBB33CBAB009D5E3BULL,
		0x83400D8084DA71F1ULL,
		0xA78829F0ACF19D7EULL,
		0xEFAE1A5A536FD23DULL,
		0xF680E95B2580EC28ULL,
		0x3698B9C9F9CB8791ULL,
		0xFB05D7C5AD0A8CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x250121E3362E02F2ULL,
		0x52566F3291C06C4FULL,
		0x9DEBA17B9910919CULL,
		0x6A6631485C8283A8ULL,
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
		0x6A24DF1A8E7C6B74ULL,
		0xC8E472051C045EA7ULL,
		0x85DD1D43ECA4B445ULL,
		0x85AC064DA68A33A0ULL,
		0x7BFC518C03B66E44ULL,
		0x1C68AAA877AA4A3DULL,
		0x603945E64B448C7CULL,
		0x4D60D680B94AA9DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD198F9E31B90CB54ULL,
		0x006DC706DF4B63C7ULL,
		0xCE5D7D7318D18EB2ULL,
		0x020BDD69279F6A56ULL,
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
		0x580A7826EDE89354ULL,
		0xB0D8842B3388C09DULL,
		0x9765C2A41B38BD1DULL,
		0x39D004B5012352ACULL,
		0x3FAC8D7F1933F3D5ULL,
		0x8D441D94F138BDCDULL,
		0x637A02BD189108B3ULL,
		0xD2A8D86DE95BC659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA77904AB9EC98CULL,
		0xA8F4E84701F4ED14ULL,
		0x5B822AB5C0C007C4ULL,
		0x7EE02505A4C2C3F1ULL,
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
		0x2326123076D255A7ULL,
		0x46F023FBAD41B20EULL,
		0xF3ACBF11F44ECE53ULL,
		0x2E2E0C52C0658251ULL,
		0x51A82E060284A6A8ULL,
		0xB2E76C79FBD319A8ULL,
		0x45B53C70E40E75BAULL,
		0xC718DC9E4020DFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421CE714D68316F8ULL,
		0xD54A3E170E97810AULL,
		0x4C93B7D3CE744809ULL,
		0x3BDECBD04546C1EAULL,
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
		0x742C9C78D5954E5AULL,
		0xF20B7B5C85B81066ULL,
		0x4F458C76728B090AULL,
		0x82B1601F8B3DB586ULL,
		0xF27CBCFC41EC382EULL,
		0x1BB2A5DD9264D151ULL,
		0x8D99F6814A4AD52CULL,
		0xB8AD2BE1F4A21707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72B0A9EA9EA5A943ULL,
		0x0E901A4040AF2290ULL,
		0x542023A779A6AD97ULL,
		0x6C65E3A9DB4D20A5ULL,
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
		0x956A2A93CA9A8967ULL,
		0x4130FBDBBC32C34DULL,
		0x90B1E42C8E3472EDULL,
		0x1F80490C9B2482EFULL,
		0xCFE12C67D865F2F7ULL,
		0xD7D175758B46C78CULL,
		0x721FF65D7869EC33ULL,
		0xEF6A21AB41C58B8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D6C1FDE9BC9F56ULL,
		0x4A486B4E68B46234ULL,
		0x8170760C6DED829FULL,
		0x294148785E7739A2ULL,
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
		0xCFA99C998DFBA17EULL,
		0x27AA00739A548038ULL,
		0xAB9098B1A494D179ULL,
		0xCA7076DEB556ACC2ULL,
		0xC558FF4B6EAC3E78ULL,
		0xF79817CD5634ADE7ULL,
		0xAB811748C61586B8ULL,
		0x8EF64C89B08054F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADF81CBFB8CEA92ULL,
		0xE83D88EE662650A0ULL,
		0x20BA0D7F0BC6D0EDULL,
		0x02FFD34EE86349ACULL,
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
		0xF739B80CE1EEC92CULL,
		0x52E373D1A2BC8563ULL,
		0xAE3FB2D41559EE2AULL,
		0xB2FDC7E605E34F09ULL,
		0x0D98CED2809D590AULL,
		0x226AF61503EAC600ULL,
		0x290489E7674F9111ULL,
		0x62EBFD22753F4D70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE86B4BF94A02E2ULL,
		0x6EC3FAF03795E965ULL,
		0xC4EC2B2D6B2976B5ULL,
		0x62055B036D48CDAFULL,
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
		0x29E4FF323EAE11E6ULL,
		0x808FF972E4D8145FULL,
		0x3B8EE90BB8D6D310ULL,
		0x9845115CC62E4BACULL,
		0xF1DCD334CCCAB968ULL,
		0x7242B0AE0A9FB518ULL,
		0x92D4402E13E17FD6ULL,
		0x9BF235518AE6E518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10AC5908A4C59AD3ULL,
		0x76763348788CF613ULL,
		0x07106FE2AC4FCCE5ULL,
		0x3E38FB7764744D52ULL,
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
		0xDA6D128E4AC81555ULL,
		0xC39061576207F71DULL,
		0x85A8C2E0680A679EULL,
		0x17E5EE2948DE5524ULL,
		0x6F2998E363291DF6ULL,
		0x31150E558F188D56ULL,
		0x0E6233B37C0337ECULL,
		0x2E80E75066B07634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A99C44F02E288D0ULL,
		0x0CB0820A9FACF1F2ULL,
		0xA83C6F84D084B4AEULL,
		0x7F084418870FE0DEULL,
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
		0x51678729B5E8B816ULL,
		0xED5192DCAA4C0836ULL,
		0x5D140AF67E136EFEULL,
		0xD724CD7E6B565326ULL,
		0x82AFBCF1563EEED7ULL,
		0x3E6EB7F3BEE1F8E5ULL,
		0x6EF453FFB089DA2CULL,
		0x0B9D5AD68E2917A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77D92FC83402C5FULL,
		0x31C0E10AFFD6FA47ULL,
		0xD55882EAB289D190ULL,
		0x10804957856FD5B4ULL,
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
		0xD66321F609150D75ULL,
		0x4F8BF8147187879BULL,
		0x4CCD725514AF29A2ULL,
		0xC99CEAB48198ECB4ULL,
		0x4A85F8834773A2EFULL,
		0x10F828C1A227D3B2ULL,
		0x1B4B09A2E2703648ULL,
		0xA883A9A9E4972C8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6460572A43F40B8ULL,
		0xD46204D28370F412ULL,
		0x59F0E082B1573854ULL,
		0x4D2819EC70098980ULL,
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
		0x0FB4655C809C2F21ULL,
		0xB3F77AFF2DB80F53ULL,
		0x0459470B68006C90ULL,
		0x7E995BBCCA145078ULL,
		0x03367BBBF5582B40ULL,
		0x6D8A7E57A2D304FFULL,
		0x4A6F28BA81F59D1CULL,
		0x678C108B35C6F1C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89CAC342EBB29CEEULL,
		0xF6863C01590ACD2DULL,
		0x10D952BAB275BEC8ULL,
		0x5D63D066C59C3375ULL,
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
		0x45BA88DE2E1D50D2ULL,
		0x8BD610D29E8D58FDULL,
		0xE6EA17C0D7F99E30ULL,
		0x537C7DA7CE652C3EULL,
		0x7676F7BA6618B0E6ULL,
		0xFF5A7FCC1B05248EULL,
		0x91519C846CAE82E9ULL,
		0xC1E065D8AB24DC96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB634E8955C79744ULL,
		0x7345091EA150C622ULL,
		0x79075368F9E10CECULL,
		0x1ACB9BD135DDEA98ULL,
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
		0x9C1F7A528492C5EFULL,
		0xB7931A668EEDE299ULL,
		0xBE5A3E843B5249CEULL,
		0xA25F330D34EC572DULL,
		0x02C9A0B8C3AC2389ULL,
		0xDF4DC1B1ACD1A164ULL,
		0x99121372AC8A8889ULL,
		0xDF67A8B4A047115CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060D55BF9020113EULL,
		0xDD1DDAC6360BD772ULL,
		0x77092189D7E28E45ULL,
		0x4BC23DDCFF78EAECULL,
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
		0x3180B3104267DAF2ULL,
		0xBF253FD01B679066ULL,
		0xC6FCDE8DFB0FE332ULL,
		0xBB4634D8DECF23F7ULL,
		0x38A08B8A296051BDULL,
		0xD1BE19FE2663A2DEULL,
		0xECEB7C882D864884ULL,
		0x7840086D4C74FD83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9955699266B3FFBFULL,
		0xE15D1B89CE31BD62ULL,
		0xF1F15AC4BCFEA6E9ULL,
		0x14C77512382CC58CULL,
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
		0x17D2B6A05710BC2BULL,
		0xF6E0EC76DEBCECFCULL,
		0x2AE11B7B849598F2ULL,
		0x18FC7B2A4D875C99ULL,
		0x3646F70EE061E9C4ULL,
		0xE7AC08FF3EEE1060ULL,
		0x0919B49945636E6EULL,
		0x9EB00B63146EB23FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x265B62D5A59972C0ULL,
		0x5A6A425A36135B44ULL,
		0x84B1EA3BD157FD69ULL,
		0x271E2BDF55F5D1F4ULL,
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
		0x16B02BA26C8F6A6AULL,
		0xA311218C6BBF13BDULL,
		0xD7F611567329766FULL,
		0x607201A4E0F3A3DFULL,
		0x2CDEB124472D00D9ULL,
		0xFC028E6AD7A23C5EULL,
		0xEBB3BC496299D170ULL,
		0x59AE42EE316993F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFBE7704FD3D8CA1ULL,
		0x0B7245686DD409B7ULL,
		0xD4A4043B15FE8D35ULL,
		0x304FF100369F9AACULL,
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
		0x1DBAEBB36B3249CDULL,
		0x167A7C60033A7BB1ULL,
		0x41655CDBDF614116ULL,
		0x4FB501082140073EULL,
		0x03C299C53BF919EAULL,
		0xB5E69D13CB8C4C29ULL,
		0xA6605C591D1470C5ULL,
		0x110C6C044A66638EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9DBEFA522C22E8ULL,
		0x16B5CD503A0DC9C7ULL,
		0xF3B312163069FE6FULL,
		0x578D09AB2C72CE6AULL,
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
		0x025E6BE07CF2C0E8ULL,
		0xD3D18C81EA31BFCBULL,
		0x0A032BE7F2E4C766ULL,
		0x3723B9DD5009BDEFULL,
		0xE77B48BD7FFABA4DULL,
		0xD97027C267CC4249ULL,
		0x0CFD614C3997B4A8ULL,
		0xF98C68547C715C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAB38017C2A6DD4ULL,
		0x1A77735D528396C3ULL,
		0xF79F9D387F699877ULL,
		0x41FB3667C8DD76B6ULL,
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
		0x2A8E28EAB60F09E2ULL,
		0x3FADA0B419B1F448ULL,
		0x08440B831A42A7F6ULL,
		0x547D02BD88BC74D3ULL,
		0x831053545010D65FULL,
		0x3E880FBE425BAF22ULL,
		0x62E3CD963E84B518ULL,
		0x902B2F55F24D5A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EFA876E988EDF2DULL,
		0x87DFF6F1F34DF367ULL,
		0xB6148FD061F5898FULL,
		0x3AE6097F8037E725ULL,
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
		0x6EF79D4EF7A5AE4BULL,
		0x513B7B00C899E27BULL,
		0xBC90224DCDDB93D5ULL,
		0xAE69232453966F3CULL,
		0x4CA73A62F1D0F5DFULL,
		0xDD43C62D9BAF9CD5ULL,
		0x6386404D5D6410B9ULL,
		0x79A530079D711B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFCA47FEDCAA3024ULL,
		0x294AE5C5E4AB2A24ULL,
		0x827DADC9AAB60F6CULL,
		0x3CEE4445B2607929ULL,
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
		0x429BBAC2EA03D369ULL,
		0xAD991933B4965AFEULL,
		0xF7E2EA1A158F4D26ULL,
		0xDD7BA29501262D4DULL,
		0x02B26D2C2E084EBFULL,
		0x1790B41037FB5A92ULL,
		0x5B3A808C2B7268D3ULL,
		0x41B835A4FAD26DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA917EF51BF3F8552ULL,
		0x2D13D39C03E5CCAAULL,
		0x8291FEE8888ADC7CULL,
		0x1ED399123C627A61ULL,
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
		0x1E44256361946BF4ULL,
		0x203E6C2C26E43F38ULL,
		0x49AB2EAAE9CBE6EFULL,
		0x75CDFB400274AC47ULL,
		0x9D4088E02BA2FFBBULL,
		0xB287F9D08A2DF9C7ULL,
		0x8F727CAC539BD597ULL,
		0x48CA07FFA6EA2FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D876A9DBC66358ULL,
		0xA06D8120A9B752D9ULL,
		0x94A9B03F52ED9B73ULL,
		0x43CB2B32C937C8F2ULL,
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
		0xAAC1F6D421E4A2FCULL,
		0x1E78C1B3C2A452B4ULL,
		0x7168F3052F89C405ULL,
		0x6D697B167CA07C80ULL,
		0xAF8516612E724AB8ULL,
		0xFB818657850B840CULL,
		0x5F2043E78106DCF1ULL,
		0x67F0E1FA9CAF2AC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB883494106DBBC99ULL,
		0x73B2B2B18259EC96ULL,
		0x90330762568E8FF0ULL,
		0x5B2B0649BEA0D664ULL,
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
		0xCAD627E7E7E63594ULL,
		0x59C501174A2AE934ULL,
		0xF45092F6195F85E3ULL,
		0xB0688030BA48C098ULL,
		0xCA49B92271FE05AAULL,
		0x1ADF3757CEA048D0ULL,
		0xE6C03AEABB19294AULL,
		0x9C1A790D8C8A68C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C7A304D39B104DULL,
		0x56E7381FF5F5B832ULL,
		0x34D951CDDF1BA6E3ULL,
		0x5C56783396D44E1FULL,
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
		0x36F3672D33AADB61ULL,
		0xF78A9089D0CB6A4EULL,
		0x98A6A6E574B0B181ULL,
		0x93695F833BB0DCFBULL,
		0x113750C39FA77506ULL,
		0xA6223D6EA87F7B77ULL,
		0x7D3467A0FA1F13F6ULL,
		0x0BE6E96D792DE193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5296436E6863A91ULL,
		0xA09FAEF6D3B7BDFAULL,
		0x2E6E08CA954DA81EULL,
		0x57B005C3388058E0ULL,
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
		0x43E0D1C8D3B92A1AULL,
		0xE53BA454AA686F85ULL,
		0x8ECD905F06E62373ULL,
		0xB7A402389B3342C4ULL,
		0xD4BDE58EE4C3001EULL,
		0xF8DE4638D4B156A4ULL,
		0x70CDD9BDDC2FECBAULL,
		0x0676007FA6F3CD02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD810E4FEC8AB2EC7ULL,
		0xD63A10C43CBB4BFCULL,
		0x4D5BE28DB6034734ULL,
		0x2D28152B6363B121ULL,
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
		0x4E16E2930E80CF37ULL,
		0xCFDDEF2A4528924FULL,
		0xF01A1FEA90F672C6ULL,
		0xBF92A8FA7C55591DULL,
		0x27B9EAA94B137EC9ULL,
		0xAC8421FE3F540314ULL,
		0x096136EAF4E89F58ULL,
		0x77460EED75FFF420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33AFB7B43365A3B9ULL,
		0x6B7AFAE7ABA1074DULL,
		0x548846CAEB7E19F0ULL,
		0x73F8E03A005395DFULL,
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
		0x798207D467D48EA6ULL,
		0x70666BC96F0F5AB6ULL,
		0x5F045E34558C1DC4ULL,
		0x46CB35352BB69442ULL,
		0xF303981726A8F4FFULL,
		0xFD6DBFF60C364663ULL,
		0xFB8FFD8773CD10B5ULL,
		0xE61B08C7B5704AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0A9B4424E8F18CULL,
		0x0EB0EA4F3F1DCD8CULL,
		0xB664004F85FC98C8ULL,
		0x6ECE82DA1A61B02BULL,
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
		0x6215185ED1F90A76ULL,
		0x1F29488D2D2F068BULL,
		0x5935FB127DCD764FULL,
		0x06476590C3D2CA26ULL,
		0x61DD7CF1AB23DE58ULL,
		0x9D3435321AC05929ULL,
		0xEF75160C53F98D7BULL,
		0x383DF5BCAB329074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F5A43E394C0CB6ULL,
		0x74E92DFD25BC42AFULL,
		0xE49740E6F4D876A8ULL,
		0x5F79DF922D543B81ULL,
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
		0x3633CDCC4D050C08ULL,
		0xA81348296AFB601EULL,
		0xE7E95C77CFFEFE13ULL,
		0x5BEBBDC4EA696309ULL,
		0x6C6AF3854F5FEDE7ULL,
		0xFB6BE1CA4B8D13A9ULL,
		0x3CB809381AB4AD90ULL,
		0xB4989B58085E5C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E13F39615426054ULL,
		0xFA16CC30A1EC4B44ULL,
		0xEB3ABACBC6D0C198ULL,
		0x2A92CCD6286B1174ULL,
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
		0xAF5B4AA9F3A7F1DDULL,
		0xA5D0BF68D717F44FULL,
		0x9CD2E9D4908EAFCAULL,
		0xF5F487B3D267A0B2ULL,
		0xFAD2FCD82EE53B89ULL,
		0xFBD6F1D4EF331142ULL,
		0x02C83F4A19BAC20BULL,
		0xBE82735B2B89EDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAACD2C0E9AECC81ULL,
		0x07B8A50458AC8440ULL,
		0x068C4ED462477D92ULL,
		0x3D51A73C48E0F195ULL,
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
		0x987CE54F72E77E61ULL,
		0xA1E80B61E1116309ULL,
		0xB59BC2619CE23D3CULL,
		0x8DD0633136A36CBEULL,
		0x2AC3C6DFC8A9CA8DULL,
		0x911A03F938755CC9ULL,
		0x9A92DFE83BC9B411ULL,
		0x31CE1E3676B856A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18C6A873C1B906CULL,
		0x2BC4A260427D28E5ULL,
		0xA768FEDA7CD2F7D8ULL,
		0x7268DF46D6004953ULL,
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
		0xBBF39BA2C851FEE6ULL,
		0x723BADB1EE71D7CAULL,
		0xB58A944CCD29B86AULL,
		0xE8F424CFDDB7B216ULL,
		0x914DFE0C4875529DULL,
		0xD77892F6C10303C1ULL,
		0x3A6DFE013D97145FULL,
		0xAB76CB9E8AB8D35AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D87517589BC4610ULL,
		0x6E217E5294E46686ULL,
		0x61DE487BF196BEA4ULL,
		0x5C965E587527117BULL,
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
		0xAE84C87C5D3F0E59ULL,
		0xE6531F5C4015BD2BULL,
		0xDAD31CFE1149DE59ULL,
		0x0B00B4FBFF7D91C3ULL,
		0x3000AA87425C0B8DULL,
		0x2CC1CE2365F59D89ULL,
		0x4120B4A0A39E8150ULL,
		0x9FB34C72126FC0D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9E189036E8C8C4ULL,
		0x8B17B89D628B1F88ULL,
		0x85ADECD65AD11040ULL,
		0x3F9E0DEABC143203ULL,
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
		0xED020EA6459824AEULL,
		0xB55D4C7ECA10A32EULL,
		0x8B6E5749A3D49A16ULL,
		0xCB6E2515F69E5D67ULL,
		0x9B713F4588C25C44ULL,
		0x8DD6B18BA7E80EEDULL,
		0xC098AD6DAEC5CD4CULL,
		0x2FB026EDCF31E234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD172F89271D7E3ULL,
		0xC33BA739B682DA73ULL,
		0x2218159195311373ULL,
		0x5F93EC62B805F13CULL,
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
		0xEE5AF955FB0B8D35ULL,
		0x0277897072896BA6ULL,
		0x7DADFA34F8C99754ULL,
		0x22168641C9AA772DULL,
		0x0603CD3C7218D634ULL,
		0xD998B765B41C3C89ULL,
		0x8790A02A1D0D63EBULL,
		0xB8432110E62EE962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EB704EEABB5CEFULL,
		0x4F22C2892EBA67FDULL,
		0x9D25C07548C66C56ULL,
		0x7C0D6EC3F4A11BCDULL,
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
		0xBB9478BC37D6CC4EULL,
		0x1D2382DC2D5952B5ULL,
		0x249FC9BD0F17772EULL,
		0xB6E09FBB1307B3EFULL,
		0xA5FF6E85AFBE0FE7ULL,
		0x3FDF31E4D778EF35ULL,
		0x4CD1E79CCED93F58ULL,
		0x6683B6CB3A3E46BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F7EE0944E0D2AE5ULL,
		0x9844EAD4294CD4ACULL,
		0x8BC82B03C356DE47ULL,
		0x6E6DC1E5B84633E2ULL,
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
		0x71616EFD2C250877ULL,
		0x43EDF07CB2178AB9ULL,
		0x74A5F87FBC7078E6ULL,
		0x6921430F8E4D307CULL,
		0x59B0DAC2BC2BDC70ULL,
		0xEED9A652C47CEB88ULL,
		0xA7A54115ACE31636ULL,
		0x255D326EA1F17957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A1E7E51AA7C1E8ULL,
		0xB83CA0C5DCA280F6ULL,
		0x572DA1B76625C50DULL,
		0x74F6BF7B9825337FULL,
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
		0x22E3060FB48E0870ULL,
		0xD044286586E287E4ULL,
		0x38D388802C1AF28DULL,
		0x004E46E39C1DD07FULL,
		0x2A90A6983181029CULL,
		0x3B0E1A3ACC94A76CULL,
		0x570B66ED8F09A1B8ULL,
		0x108074C67B961CEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745BC0A70DB46BE4ULL,
		0x945C0D1FE4F361F2ULL,
		0x2484CFC36788F3E6ULL,
		0x735F9C59F4661C06ULL,
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
		0xBA868A86723D8F39ULL,
		0x93FCE66B752252DBULL,
		0x58CF1617A87765D3ULL,
		0x67EB85BCB4F9A504ULL,
		0xD5E751703E990D49ULL,
		0x41737EB0B32D0D38ULL,
		0x96604C9E44452108ULL,
		0x1E1F09B6E84EF0F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ADCA12FBCF588BAULL,
		0x4B21B4A60DD2494BULL,
		0xAB1A7595CABA4D0DULL,
		0x6086F6E330B1699EULL,
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
		0x0C3C7E9EC06F31E0ULL,
		0x6F802B9E375724D4ULL,
		0x89A5BD01770304E2ULL,
		0x6313E83224668268ULL,
		0x88AE77C4E052CA87ULL,
		0xC43DA257FB4929ACULL,
		0x88CCC1016A740A14ULL,
		0x25657B6441A1ED52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x562245D80CB942BBULL,
		0x90A644AD84335470ULL,
		0xD80A6337443C83F7ULL,
		0x70243913E26FBCA8ULL,
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
		0x5E2BA651A69CF425ULL,
		0x13BEA421DD392754ULL,
		0xFC3610D5BA63B13FULL,
		0x1BF2FA78B54AF61BULL,
		0x508C8068FF420ED4ULL,
		0x7448EE18D939FA58ULL,
		0x38BC7796DF962001ULL,
		0x9D95F3CAE5DC9EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5306B5E78A6B2B1AULL,
		0x5691FBD21BD45070ULL,
		0x682FD13AEAAC7176ULL,
		0x00352A96D40A8EA8ULL,
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
		0xBAC30F5A9F90B324ULL,
		0x2BF344449743F1D3ULL,
		0xABDC7CA47E75FF46ULL,
		0x4FBEA124DECA6683ULL,
		0xA0D4D509DEA210F8ULL,
		0x9C3702C907001088ULL,
		0xEBE301551D14A22EULL,
		0x7D3B92820D88F52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5AAED1AB9F3AB3ULL,
		0x5C1DAE1BA146661BULL,
		0xAF8EAF46CF861231ULL,
		0x66966072E11ECB2EULL,
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
		0xD28E0144EBD7BC5DULL,
		0x30E7AF17A1D14602ULL,
		0xAD0281A2DD514E37ULL,
		0x8DCCA8B67FE49A3CULL,
		0xBA8EE6CC3BF5FC77ULL,
		0x38F7939AE875ACF6ULL,
		0x13E30DDE01981E2DULL,
		0x09AEA43D948780ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C44395D25B3640ULL,
		0xA5A798162348F2A2ULL,
		0xA0B6909719E5C8EDULL,
		0x7DB909DA8C01B3A1ULL,
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
		0xEE13425E87EB40C4ULL,
		0x5B3C73457E696210ULL,
		0x22FF8704D7BAECFCULL,
		0x2FCB55CDA71FEB7EULL,
		0x485ED9C1F911FB7EULL,
		0xE9072BD9BC1AEB4FULL,
		0x3BF674E5E7960693ULL,
		0x0B76F8DE332F5526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC279529809695B1ULL,
		0xF24CF5976A684FD5ULL,
		0x0994E12537FFE6F0ULL,
		0x637446C940268F2BULL,
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
		0x1368586EF4520889ULL,
		0x7CB0BF6F0463C50BULL,
		0x18C549AF9FA43A04ULL,
		0x26694233DFD3FE09ULL,
		0x0B29F5C39188194DULL,
		0xAD0227F0A81E31DDULL,
		0x3401A10DC34A1F79ULL,
		0x0853378D87D59395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA2D3768E85CA1DULL,
		0x2B02AD27F8DF2BDAULL,
		0xD10331BA9CA4E614ULL,
		0x62C381360987E62EULL,
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
		0x683CC3CA6AB154AAULL,
		0x56FB8282B6725BC0ULL,
		0xAFD280EB68F06B6EULL,
		0x5BB852507158F9C8ULL,
		0x8325D6FAD9B9F3DDULL,
		0x60CFF5C5F37AA724ULL,
		0x98754650CBA4D863ULL,
		0xE2DDE572813ECD1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFDAAD06BC4B8C84ULL,
		0xB5D9FDE4DAA72B2BULL,
		0x513AF0E9A3688A2EULL,
		0x08A8614FA0AB6C79ULL,
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
		0x682826A557E5A592ULL,
		0x51E2E9534B53921AULL,
		0x0D40D647CCF747B0ULL,
		0xB3770A3339018C5AULL,
		0x4D2023BAEAFD1F11ULL,
		0x4769F0470795F3EAULL,
		0x5727F7A38F28B1ECULL,
		0xB98D9905B9016B0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAED746439784640ULL,
		0xEB9C93DE6B95C6E1ULL,
		0xFD2F988F0D01B0C2ULL,
		0x3E7BC10CAF377008ULL,
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
		0xD57A40618D4FC145ULL,
		0xAEFA5D3B5BB1F509ULL,
		0x439AD3A5D0AA3DB6ULL,
		0xFE91381E6552D59DULL,
		0x9863D7858EC17EFAULL,
		0x8C5ABA41C1752C2CULL,
		0xE50BDCC12D5AC977ULL,
		0x765768222C1F187DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x744C3E34BE089D20ULL,
		0x847202FE131683A8ULL,
		0x435D98528C242575ULL,
		0x0F8AAD30F1F0784DULL,
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
		0x206F23F48E7681CEULL,
		0xF9B0479A0F045008ULL,
		0x13BE5FD5ED737FD1ULL,
		0x6ABF680B2C6F247BULL,
		0xF2860A4A347E5D32ULL,
		0x384FB71814C90165ULL,
		0x0AAE94B5C3399C6BULL,
		0x3004B043BDC3278EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2054AAF859385857ULL,
		0x5585752D24DA852AULL,
		0xA9A872D0E800B7BCULL,
		0x0B71921957670390ULL,
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
		0xE4A0D6A754D3B422ULL,
		0xC0E680AC247936CDULL,
		0xAA00B5705E2F4A6FULL,
		0x23AEA5F9978BC8CAULL,
		0xE443FB906BD053F4ULL,
		0x613B002772065F46ULL,
		0xE8187B4B52DE6E6CULL,
		0xCD485D19AB0F5600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B82E1755C02EE1ULL,
		0x2FA88687116B5B53ULL,
		0x1DA3029EAB33AE86ULL,
		0x1C6C77C8FBD28CEDULL,
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
		0x26AF3CC0B8590154ULL,
		0x2CCFBA097D2D9E28ULL,
		0x2A36843AE617D260ULL,
		0x36EE0B70CFA3EF6BULL,
		0x8303E207103EE495ULL,
		0x13AEEE84BB604167ULL,
		0x5953F46CBFFCB44AULL,
		0x38AD3B99424EEEC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9942C9CD21AEF0B5ULL,
		0x18C721BD4D775385ULL,
		0x6CACCC5F659A955FULL,
		0x20A4E430A75B6128ULL,
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
		0x101846FBA2D496B8ULL,
		0xDF007562444C532FULL,
		0x0E93EB932FE33E56ULL,
		0x8191AD5D20E2EC41ULL,
		0x7EC76CEA284C73BFULL,
		0x4CFB6570EAA0FB99ULL,
		0x0F7610126A0179E5ULL,
		0x6C5D4113183B2489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B271BD9E2DC785ULL,
		0x4C5184251831ABF7ULL,
		0x5A1A4E4EEC1B5660ULL,
		0x17695632B9AA5899ULL,
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
		0xEEAE20C812D8AE7AULL,
		0x7AA7D17D10B16DADULL,
		0x7A4F8AFCFB01978FULL,
		0x2142DA704F125FD3ULL,
		0x4460C20F9A335E27ULL,
		0xB3F7DC097B38DF02ULL,
		0xFC2CD923C62E9B2DULL,
		0x7C1D32B364DFA535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150AEF18F678AB03ULL,
		0x31727AE55B228804ULL,
		0xE8F7C64C65ECA058ULL,
		0x0D9861114844E5D6ULL,
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
		0x4FC8DC77EBE49031ULL,
		0x0E5F6B375902199CULL,
		0xAEE4978953B0A6A1ULL,
		0xF3D9E9DD0390850FULL,
		0xBA40CCBAFBA30D00ULL,
		0xB8594DEEF8FACEFDULL,
		0x85FEB097EBF6A500ULL,
		0xD3FAB8FE6D53A30EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5674039461882F1ULL,
		0x6BA0FCB04E3CD345ULL,
		0x92B2CE165A4D24BCULL,
		0x6B115FA13DFAB937ULL,
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
		0xB0FB917BB8197B53ULL,
		0x5E4D40F66420FF03ULL,
		0xF7D273D91464E74AULL,
		0xAB0DAEA72D4D3BAFULL,
		0xD1E6E0D5B0FFF774ULL,
		0xE07F87922B7E63A7ULL,
		0x11CF952E8B1B0964ULL,
		0xA2F7F0FAEE85CD48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD940F133FE183A2EULL,
		0xB13B60A8D8E3C9ECULL,
		0x9CA298C1BA684C43ULL,
		0x5BDB73E69529B462ULL,
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
		0x8622E02321CBECF9ULL,
		0x93B5980259DDF6EBULL,
		0xF1D3B0881819CA9FULL,
		0x11D32FFF86484529ULL,
		0xA6DDEC92FEA9A988ULL,
		0x2F7535E2C67BEE1AULL,
		0xD231FD32A5EE59BEULL,
		0x3914D4170F2BF59CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B13FDF4EEFB186CULL,
		0x9F1B97ABD0434EE0ULL,
		0x253F460CB97B1CDAULL,
		0x0AEAAB6BC6CEBA71ULL,
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
		0xDD69310646A3DE28ULL,
		0xAE88717083920F47ULL,
		0x5335B98C0A4D8274ULL,
		0x14A2FCEFB9A16E17ULL,
		0x89C9C024BA310CEFULL,
		0x052E77949785AB2AULL,
		0x5E52133D5099AA17ULL,
		0x758577325C3D7AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515BB679E9EBCC3BULL,
		0x736E317F01697798ULL,
		0x536494A6011CC1DFULL,
		0x0672AE696AC1A7AFULL,
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
		0xD57998F313C30726ULL,
		0xD75159326D7F8E67ULL,
		0xC88BF34D5A4111BEULL,
		0x9D08D245B4E83426ULL,
		0x99B0E103E5765283ULL,
		0x3C9BB1EC62CFC372ULL,
		0xD82F817FF836F08DULL,
		0x4E92552F28014066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5BAFF8723534860ULL,
		0xD66DC2491856916AULL,
		0xDF992C4C3268C6B5ULL,
		0x46C17745A517C36AULL,
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
		0x0D9035A4658F7A00ULL,
		0xE01E98F861309B6CULL,
		0x56E4536194596AD3ULL,
		0xC53AB6348152CF7BULL,
		0x1528EB48F0362553ULL,
		0x0DF82E96A1239352ULL,
		0x7DFE5457AA5C863FULL,
		0x9EB4758EC4398A92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A322780D9907E2ULL,
		0xF2F583544C78799BULL,
		0x0AA4D864DE15582FULL,
		0x54042965A1DD613AULL,
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
		0x2118746FBA57AF61ULL,
		0xCCC39638BB13D4C5ULL,
		0x0E89C25A5D5360F1ULL,
		0x7752B7A6A779613BULL,
		0xB7E2A189F6F37832ULL,
		0x3047801347C016FFULL,
		0x7CD3B3276F029E4BULL,
		0x5755AB5D579476FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CBC6EEA627B88BBULL,
		0xF760991561973EBAULL,
		0x95F65A34D7B6E01AULL,
		0x6E0A2781A7830AB5ULL,
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
		0x04F62D6A00269776ULL,
		0x53E5CFE82CC89CA1ULL,
		0xE4BC357C8A6CC912ULL,
		0xC7C0F9A61AD88FF2ULL,
		0x986D272664B032FBULL,
		0xE0F84FC86B6738E5ULL,
		0x713810304D6EF537ULL,
		0x5DDF6F6E3BE292E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA529FD1CF24E2ADFULL,
		0xB8C1A7A81E1B0EB5ULL,
		0xB30E9CA808E52F5DULL,
		0x36EB8402FE7A5E27ULL,
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
		0x34D35820351F644DULL,
		0xE27D765352B1A4B0ULL,
		0x4CEF875BF297B3A2ULL,
		0x82F2708A2EAC23BBULL,
		0x4E836B9C3F3FB01DULL,
		0x9AE34C7D9446C25BULL,
		0xEA937A27AAD85B4FULL,
		0xD55FDC73969DB335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC55515198938D5BULL,
		0xE03AD0F755327E3DULL,
		0x1ED3A93F4EB54173ULL,
		0x2F2D29B28A14BDBCULL,
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
		0x88ED837FE5CC6DF8ULL,
		0x14B22D20A9687198ULL,
		0xBC2EE5408A3AAD4EULL,
		0x2E51FFAEA8954F76ULL,
		0x2C5F018A27530C60ULL,
		0xAFEF912EDBC8A2ECULL,
		0xCF59BC6DF3B8FA7AULL,
		0x33DA12293DAC73E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F07BE01BC204555ULL,
		0x3241BA154930A0A7ULL,
		0x8380DD92B7AFDB84ULL,
		0x60B0B1CDD02E8347ULL,
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
		0x4DBA5CDF31FD63B0ULL,
		0x575895259EE8C4BCULL,
		0xF078B1C985DF6E0EULL,
		0x548D9DD013852295ULL,
		0x2E64E23CC74E4E33ULL,
		0x1BCE3B22A89D4FBBULL,
		0x3CB29334AE646A5EULL,
		0x685ED60E49F87266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B3F1E4C79D018FULL,
		0x77F55C4AA6429A85ULL,
		0xF2FA8B9B68C73806ULL,
		0x52A163EF0E661DC2ULL,
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
		0xD135BD0532E670FFULL,
		0x5449D8A475B9880BULL,
		0x7D80E84E9184ACB5ULL,
		0xDF1D4B6414EBB20FULL,
		0xDC23FDABB514F6D8ULL,
		0x84BD5D4D055CC27AULL,
		0x1EE73C2049CF666DULL,
		0xB5628984601F63BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E8D648214031924ULL,
		0x0865B213417E6648ULL,
		0x13D3D519864DE0F7ULL,
		0x4BBDB50A5994806EULL,
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
		0x30D3FADC562D9669ULL,
		0xE2E65E6E31327616ULL,
		0xBAC3FF52ED3AD540ULL,
		0xCF980DA24C13176CULL,
		0xDC20A84625DF26EBULL,
		0xCFE1DDF785B1B00AULL,
		0x4D78812AFAB9F547ULL,
		0xDEFFCBDEA1F96399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDACF545F54D6244ULL,
		0xBE6D512C099297B2ULL,
		0x3AA72BB424D53DE9ULL,
		0x699050AE5717E02EULL,
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
		0x341ED960E010BF66ULL,
		0xC7296298DC82BB47ULL,
		0x9A09D3A3F15BA45AULL,
		0xD88B946CB00C7197ULL,
		0x32442B0A15C002DCULL,
		0xD6C4C0981B123552ULL,
		0x3437BD9D51F405C2ULL,
		0x0FB656AF3D209BECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3D3CE01A912C80ULL,
		0xA85DF92CE136A57AULL,
		0x5A4FF8FE1B947F46ULL,
		0x2D9C726FC2E396A7ULL,
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
		0xF497C13EFB8D28EBULL,
		0x4B0772B6890A42E9ULL,
		0x9F40C0057992F72EULL,
		0xFCA97E7FD94DC6ECULL,
		0xCC1666CB800EEDBCULL,
		0x9FCE2CC529D274D7ULL,
		0x7D4ACD8FA459CDB7ULL,
		0x1805E72FE7781C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FEB0373FDC4737EULL,
		0x03A217FABE479AF2ULL,
		0x385B4357DEE78070ULL,
		0x0D89CF9C352205B5ULL,
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
		0x9C87CA77359E51F0ULL,
		0xF743A0782EA01CEFULL,
		0xD9E332A61F87309DULL,
		0x2685AAA35D73F997ULL,
		0xC22FB4B0FF95DCB7ULL,
		0xDA1C63F7CED36D49ULL,
		0xFB0511344A2B7093ULL,
		0xE4CC97FDCB576AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9C9CBD25DD1A26ULL,
		0x577A7740E20255E2ULL,
		0x1CA3C06921F9E690ULL,
		0x1CE43A4F8C6DCF45ULL,
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
		0x2006220E8E5A522AULL,
		0x7831F685CB5F9FDDULL,
		0xBC593A8167044E29ULL,
		0x4D81FF235D5CBADAULL,
		0x0357F80414C68373ULL,
		0x64074A92E6B34C38ULL,
		0x0F659918A7B81424ULL,
		0xA21757F06A0B1CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F14F2A9A3D1D8CCULL,
		0x5147085409FCF02DULL,
		0x056DF42A4C574B90ULL,
		0x5CF90CD31B0303F7ULL,
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
		0xBB6C3B2644BA82F6ULL,
		0xBF8AB8BB5363AE9CULL,
		0x3F2A4B5D17D0C3F6ULL,
		0x7B5F1E70EA1386E6ULL,
		0x2388911D2E63AB7FULL,
		0xF9A3085FBCA11832ULL,
		0x0C4B5D6A4ABB2C35ULL,
		0xA65E8BE435757BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01B1C57B2785FB86ULL,
		0xCDBDF6F1534D460EULL,
		0x125A29242F9953F9ULL,
		0x2D67E250D983EA9AULL,
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
		0xA9C30DE66F053BC6ULL,
		0xA19A333C8714E8F2ULL,
		0x8FE664CFECD2133CULL,
		0xCC217D2B6732D7BEULL,
		0xCF0FD5A58CCAB0DEULL,
		0xF0E99BB6290C790DULL,
		0x1A97FA8CD4A74D7BULL,
		0x915D557AD9AD58EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661CC479551B7FFEULL,
		0x644750469EEEE0FFULL,
		0x827595B77DA793A2ULL,
		0x5FFC2D67B6EE0B16ULL,
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
		0x42C6AFCBE0C8397CULL,
		0x4FBAE47578348052ULL,
		0xE3486EDBF3CB547BULL,
		0x53AF7914E950E0CCULL,
		0x6EF382D8BF72A188ULL,
		0x89D6005CC90CC1C6ULL,
		0xD728CF65991EF620ULL,
		0x271C2154733A47E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAEC1BF84BCC3490ULL,
		0xC57EF23B501943C6ULL,
		0xD35737F0AE63DD4FULL,
		0x21DC6B9E03F78D10ULL,
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
		0x45645047AA9CC567ULL,
		0x33580011300CC396ULL,
		0x9F985BCDD1341A42ULL,
		0xA31916BAC153E33EULL,
		0xB799D90D090F08E5ULL,
		0xCACA382187797EA4ULL,
		0x3E4F78A877E475A6ULL,
		0xBEAA53755DE45CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863A883702D81BA0ULL,
		0x4D5C550B4C159009ULL,
		0xDF6444CF9D1D9104ULL,
		0x70617A26B139B089ULL,
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
		0x7A4289B8838246D6ULL,
		0xC75D041D55C6D97AULL,
		0x4DAA16EE6CE226EBULL,
		0x1333FD4196E58769ULL,
		0xEF36C73CC8A7E107ULL,
		0x75305C25B86E88CDULL,
		0x20BE22CA230DDBAAULL,
		0xF739079D7543C5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC641CBE4C6DB34BULL,
		0x2C8AB1B6B62F280BULL,
		0x29E340EFA0F0C239ULL,
		0x45AB1EA0FEF4E4C0ULL,
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
		0x6A4C58932F2E62EEULL,
		0xD04B0A6599E77AAAULL,
		0xC561843A7DFCED40ULL,
		0x5D763D6729A699C6ULL,
		0x9ACD66286674C22AULL,
		0x978D4536E41A0B8BULL,
		0xE5F61E62187EF75DULL,
		0x2BDCC82E4BC45CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64C9829264833621ULL,
		0x4F43508B75C53163ULL,
		0xE7EA06CA20D5A525ULL,
		0x603BF44668CC59CEULL,
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
		0x78D61BC0BE05E599ULL,
		0xA18495A6E37AC2C0ULL,
		0x5752E9AA14194A18ULL,
		0xCECD060D4F3924BAULL,
		0xBA78E4E0DFD673E9ULL,
		0xEFB3E3E5EB7AD8D8ULL,
		0xA6C3BC2B028C0F20ULL,
		0x0164B7DF9D51493BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C81521F7DB1A55ULL,
		0x363869C7D7B6F2ECULL,
		0x1860D80C74E388FCULL,
		0x03C0513EA94A0395ULL,
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
		0x9A5CEC5F637439FCULL,
		0x26BA654F6F29415FULL,
		0x96FA0E258ACB3158ULL,
		0xC3FAE7303D4E5003ULL,
		0xF977D410D60B2A11ULL,
		0xFD70FCF01C08D4CEULL,
		0x802939A448078EA7ULL,
		0xDE207F3BD65FA31EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22666DF291C7D7BULL,
		0xC57FF0F39878D818ULL,
		0x9D189C883BEA5E47ULL,
		0x3CCDCA120F80868AULL,
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
		0xD05675842A0D395AULL,
		0x963A48901CDBCE90ULL,
		0x25AB70BE825AEB23ULL,
		0xC3EE10EF5D9ACA62ULL,
		0x6A9DAEE49726A1D0ULL,
		0xB89128F4D727D4C6ULL,
		0x2565AD2009AE2098ULL,
		0x7ECB65ED5802FE3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3BE6B7299C9411FULL,
		0xFBC65CE80CC56404ULL,
		0xB2C3237FF233C1CEULL,
		0x161F322A6E0C874FULL,
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
		0x09CFF5460636B639ULL,
		0x6EDF1E4690F3344EULL,
		0x39AABC9D7D768A59ULL,
		0xD28D56660E0BEF5EULL,
		0xCF6F0171E4624756ULL,
		0x8932AA6B265BDB9EULL,
		0xE6C86E1D57DF2F6CULL,
		0x11F660BDC1723DC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD44A2C2DECCD4D6FULL,
		0xCC646A2E4295CDE0ULL,
		0x7B6B14F888979475ULL,
		0x7D1FB290C5011A98ULL,
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
		0x2CB08A0A33E976FBULL,
		0xF7E98B7CE1379A39ULL,
		0x936BEC656AB4D123ULL,
		0x3C86D085F43627FAULL,
		0x1C840211E154FEEAULL,
		0x47ADE97B9DB6B388ULL,
		0x08A75B18AF16D8C8ULL,
		0xA687D34A56C2577FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6848D8B1A687515AULL,
		0x9BBA33D64A56406DULL,
		0xDC43720F6818FEDEULL,
		0x74B02D8ED50F24D5ULL,
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
		0x2897343A6A99E905ULL,
		0x4AF0158CD3B32CF0ULL,
		0xE16E9E1B31C49D9BULL,
		0xBA281E05E7E24D2DULL,
		0x9FA0D1AB5FE4ADDBULL,
		0x4C98E17C4411D742ULL,
		0xA1D631DA32249454ULL,
		0xB2EEE04C5EFC5A22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA7653AAA68BBB89ULL,
		0xA9A18DFEEE5920D3ULL,
		0xE73A047EA332A21EULL,
		0x499D695C0157AE51ULL,
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
		0x1EB129E76AAD001BULL,
		0x9322851FA1644E7BULL,
		0x3BBBF4B52A3E6CC4ULL,
		0x967BBCFF1AF6CC83ULL,
		0xE24151767B9CDF1BULL,
		0x100E70231C259D8EULL,
		0x82685E98964A98A5ULL,
		0x6738F1102FD2D60CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB463417DC3F6206AULL,
		0xF5472A55CEF9B1B0ULL,
		0x9739FF5B79511544ULL,
		0x68EF85663442925EULL,
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
		0x8B82BC50DD09CEA4ULL,
		0xC634C2CE247B1278ULL,
		0x582102BCE194056CULL,
		0x459331DBDB3F33D2ULL,
		0xB2A5F8497E724486ULL,
		0xDD81EE370EB6C5B6ULL,
		0xCEE65254516C1BCCULL,
		0xB92C604BF7156593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10259739A1FFFE9DULL,
		0xA77E1EFA539C6B97ULL,
		0x0E513B40F7A025D5ULL,
		0x42297D22886C47C3ULL,
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
		0xCA30CFB62DFF7955ULL,
		0xAE09013A02582C34ULL,
		0x168AA8A9ECE5CBC2ULL,
		0xD9505E4FEBA47726ULL,
		0x01EF582DDB4B70D5ULL,
		0xC2FBC59C47684F4FULL,
		0x3217CC7EAFBB3377ULL,
		0xF139E22070DE95A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B7E684BB323E5EULL,
		0x9F68566C9BD3F1EFULL,
		0x8613037802AF6F89ULL,
		0x27E7EF20ACAEAD39ULL,
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
		0x9D05A018DCABAB8CULL,
		0x6D50551C5CD2765BULL,
		0xDCF83B848F060B1CULL,
		0x31DDDF28BAD09F19ULL,
		0x840EE2FF019DB6E1ULL,
		0xC937E1326C1735E1ULL,
		0x365379F6B264234AULL,
		0x216251C8CB46176EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373B51F31A14D1B0ULL,
		0x4B9BC298684475D5ULL,
		0xED5C562309E34836ULL,
		0x267602F6E7381975ULL,
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
		0x926CE2AC9DE78C0FULL,
		0xFC225F88600E8665ULL,
		0x1607EDFAE77C428DULL,
		0xDAF1A010FF19F249ULL,
		0xED6386F1687324D2ULL,
		0x6D7FDC5BD0E2B5E5ULL,
		0x37CF2B4B72A637CCULL,
		0xCDD986F873971C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF32EA821EFF07D5ULL,
		0x3D1D152961B58686ULL,
		0x5EC85B2DEC288AE6ULL,
		0x693BA8F2278831C5ULL,
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
		0xDE88152EE6FC0F27ULL,
		0xF303A54FB8A347C0ULL,
		0x12B10489C7FAC4B4ULL,
		0xCD8A1C3B73315510ULL,
		0xD76A515B363B7210ULL,
		0x0B0F023EB8537964ULL,
		0x6BF82932B423976CULL,
		0xDDFF1F62EA3DABF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85028B8F3CF0280ULL,
		0x973DFA9F15074CB8ULL,
		0x1987221085433EBEULL,
		0x4168C4EA3858DB58ULL,
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
		0xE8BEBA849AD3B2C1ULL,
		0x823691496DCBEFEEULL,
		0x5C2EB0DD145CA1C7ULL,
		0xFC10665780F3D2B6ULL,
		0x021FD274EB03FE04ULL,
		0xB63ED70CAD3C66B6ULL,
		0x9384F9DF9EAC5FF5ULL,
		0x8C6B37522B419915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3977F7DF7D6B6A8AULL,
		0x8F8A7D2B24C32EF3ULL,
		0x41EBC80EA1F2E040ULL,
		0x53FA9C89ECB08BEAULL,
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
		0xD83283B76FAE0632ULL,
		0x002110D6E32543CEULL,
		0xC77B56C5D507E893ULL,
		0x07B07257BF4BD749ULL,
		0x8869CBAA483957CFULL,
		0x5D8DCC4EC14A569FULL,
		0xB8448238854F499DULL,
		0x2CB851638C3860CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17E6BEFE28310FE3ULL,
		0xE32D6487942E1F7DULL,
		0x21A6AB299ECCD5EEULL,
		0x2B0C871E8FAA3587ULL,
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
		0x1160B35F26C71290ULL,
		0x8005194E78A30069ULL,
		0xB6A799CBA678F5B0ULL,
		0x0183CFE1057A1645ULL,
		0x70DAF2D348FD232CULL,
		0x6640403793F66EADULL,
		0xBD8E5DE6ADBD6C7FULL,
		0xB36492751D86736AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E0BEBBFC5A4F07ULL,
		0xAD8EA18E6F376E27ULL,
		0xD9C98A0970971099ULL,
		0x22718D43676F381DULL,
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
		0x42A45F0FBB4ECE39ULL,
		0x3E8F8BE512B821C2ULL,
		0x1B675F87FD82065FULL,
		0x75BF6F590C3CDBB7ULL,
		0xD544AEAE50A733F9ULL,
		0x2DCF6833098410D5ULL,
		0x768D10EE5B59878FULL,
		0x06702D17BD411726ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAD64CEFB4208555ULL,
		0x0B5903787C52A17FULL,
		0xB457E2E98CCC25A0ULL,
		0x6A6620DF23E64B6CULL,
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
		0x0461E57F54DE2A1BULL,
		0xFA73B06A7B321F66ULL,
		0x6253CB07990A35CBULL,
		0x74A4E22188B6CD66ULL,
		0x0FA863060D6CD653ULL,
		0xCD5AA5F1ACE6C6D1ULL,
		0x716035FA86F2A50BULL,
		0xD1301C1C42CE5063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x576098655305FF1AULL,
		0x75E8524A2573A26EULL,
		0x369BCE37A10EB58CULL,
		0x01C90E537356BC29ULL,
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
		0x09E56CC9763CC35DULL,
		0x4F68E187FEEC9716ULL,
		0x0268B5968A320EA6ULL,
		0x727CC1B7F270E25FULL,
		0x3C2A8B6A85D8D0D7ULL,
		0xDC15B41A0F31FF8FULL,
		0x5109257EF935B109ULL,
		0xE67D24C8E835BA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8361E99546BC866ULL,
		0xFAA19D6640588658ULL,
		0x09C4466F882A561CULL,
		0x2910378A6A6A916BULL,
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
		0x3199D4B086015E3AULL,
		0x056C4C1F77F86BC0ULL,
		0x43F8595E6659B687ULL,
		0x17880DFD53E2777BULL,
		0x181F477B25244A24ULL,
		0x1C8D3DF74EFCAB8DULL,
		0x88DE587955D3991BULL,
		0x69CD6EBEF9CE6A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC63E70F8096461DFULL,
		0x42637ED53179E2B1ULL,
		0x94F97B6123C2708DULL,
		0x4C067E5668863401ULL,
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
		0x527EDC08C1812A36ULL,
		0xDC69C8433AA5EDABULL,
		0xECB16B86613780B2ULL,
		0x101BE9549DEDD821ULL,
		0x0FFD75C69B60B17AULL,
		0xBA9667DF3A4210B0ULL,
		0xC92532EBCDB61A73ULL,
		0x913048FA64146AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB21E5783D1DB8583ULL,
		0x8EBD3365E07467CDULL,
		0xC836FA86EA3F6DE0ULL,
		0x1D46BE7F78F5AF43ULL,
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
		0xE67827D6A369AEE3ULL,
		0x4A53177AF4B2AB61ULL,
		0x09172DE9FD8A5D17ULL,
		0x95FDD6125F507809ULL,
		0x570B625CB29D19C2ULL,
		0x0705877D98EC50BFULL,
		0x69E1E9056BFBF5A2ULL,
		0xAFD28AFBF2BF6B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD228C19926BB859EULL,
		0x5525341FA7C6A7C8ULL,
		0xC09FC4B804F0D324ULL,
		0x2F3E777867BA5B94ULL,
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
		0x396ADA32E80FBA28ULL,
		0xE81E354345F2B41DULL,
		0x34AEDD53BEDCA66BULL,
		0x0AD7B3DA8F45CFAFULL,
		0xD9DF7F2E7350AAA8ULL,
		0xD8D1C63359C28D72ULL,
		0x92BD5A7A69C8A306ULL,
		0xA1D29A19B90C238CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9097BB18060912A8ULL,
		0x1741A0E298D3B329ULL,
		0xFCCA4B7F72A4D970ULL,
		0x101A93AC0713168CULL,
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