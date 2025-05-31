#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xAE986A57A415D3ACULL,
		0xCFA08CBBAEDCAC18ULL,
		0x2FAA0642220CEE39ULL,
		0x11386FD10F6677E1ULL,
		0x76D635DB5A1F3FE3ULL,
		0xAB93BC9E3993CF9CULL,
		0x7E1A462FE2E61732ULL,
		0xA195D10945A884B9ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x526468E704B952EEULL,
		0x478E8C383ACD7D52ULL,
		0xE790715DD0345FBFULL,
		0x0D757731666A2B69ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDE2BF701B6749E0DULL,
		0xC944144742CF974BULL,
		0xFDED6EBDFF1587ECULL,
		0xDB18160BA569495DULL,
		0xB6BFF7A3B8999ECEULL,
		0xA9BFC9FE16CAD6D5ULL,
		0xCB8BD3D11F05509FULL,
		0xC62B9C4105691920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEAAB94F1D423515ULL,
		0xFBBC0FFEA4EB7B04ULL,
		0x34AEDFC899DF7F9FULL,
		0x459147B27303043CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC5312827A3FD478AULL,
		0x2D8FE7498657147CULL,
		0xFD6B4EF263BD188EULL,
		0xCBB9F87595EBBDDCULL,
		0x8F227889457FC3E7ULL,
		0xE5DF92E86F5CAECCULL,
		0x775A81357B9BEE11ULL,
		0x1A97D7A6F2CDBC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044F0C87F4F45C7FULL,
		0x4CBFB5CA0E1906DAULL,
		0xB4DA7CE2BCE26F36ULL,
		0x3E43FB3DA075B9ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x876CA85423FA93EEULL,
		0x8DF21184B3A55C41ULL,
		0x639961DB4C643E95ULL,
		0xC98D954E08D23ACBULL,
		0xD46895309A7D6849ULL,
		0x80223B9494F332A5ULL,
		0x255852C7BF1B5CF7ULL,
		0x56D697CF639A24CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF2CD8B129810C5ULL,
		0x9306E992CFBEE0DFULL,
		0xEEB5AB81AA740B52ULL,
		0x2D681E16D1B3B164ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1B217C6CBC309549ULL,
		0x2DFCB0BFF9050F69ULL,
		0x93DCD12AB10D8C81ULL,
		0x252853DA14485840ULL,
		0x2F95B38BD979FA8FULL,
		0xA58B881CE6E82BBEULL,
		0x32F69DC392683288ULL,
		0xF8D1CBBCFA7E4895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5A232F044BCC01ULL,
		0xC0B2E50A3F7B8DA4ULL,
		0x24783C326C850CC9ULL,
		0x144C91E743071E66ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0B07EF82190B72EFULL,
		0xF8B5E377E7F59205ULL,
		0xE20CD4C445C3ADDBULL,
		0x4B249D21738D5794ULL,
		0x04F8AF37F6E12D8BULL,
		0xC948238E57F746C6ULL,
		0x9D68BE2B22A4BD79ULL,
		0x793B9201A78F130BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F1F1D0BE78383DULL,
		0xD96B2A98F6AA1369ULL,
		0x3F990F2B6A37CDEFULL,
		0x49FC496052CA2B4EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x06B60E093C53921AULL,
		0xDE8EFBD38BCFAAA5ULL,
		0x1EF45D0591C178DDULL,
		0xF2C76067E5ADC0F9ULL,
		0x97B7172C189CC7CCULL,
		0x9B6FB20399D011F4ULL,
		0x80AFEFCAB37F40A8ULL,
		0xD2CF5EAD429FCD75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE37E94E3993F22ULL,
		0xF123685C60B254F3ULL,
		0x3911F51C36A511E4ULL,
		0x3D8F6E1FC966406AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x89B6ED657BDFD7EEULL,
		0xAA36E89F8502CA98ULL,
		0x1A42896F065ED96EULL,
		0x8DF233285A1F33F3ULL,
		0xA6A4E22E898FBD33ULL,
		0x46C0B97A392A60D3ULL,
		0xBF5700528BFCB215ULL,
		0x8FF77B760A0ADDD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4630804DE735F0B1ULL,
		0x2AD270C4014D2A03ULL,
		0x812C95AFCDE14897ULL,
		0x6CAE86ADD7BC2115ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0B44AD08FFD30E0EULL,
		0x1D1FF53B251DB284ULL,
		0x9EF7C78F4D30FE18ULL,
		0xB7FA02AA42E60CD4ULL,
		0x28AE4A84DEEBE971ULL,
		0x0DB2D5BF05BA1641ULL,
		0x8DD66B1310D1E45CULL,
		0xDF964F23273FB153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1523BCC216D7B9CDULL,
		0x25ABAF95FEBD0030ULL,
		0xACCBAC63CC58E3C2ULL,
		0x6849C1E2165A5F3BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7E321F5401BC0A70ULL,
		0x4ECCB80BD595D787ULL,
		0xDF02027939CA67F9ULL,
		0xBDD340CAAB6D03C4ULL,
		0x9B79901A900915F8ULL,
		0x29035D65AD6C248FULL,
		0xACF3413BEDAAE9E9ULL,
		0xFA7B92E7422B11DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923D8345631552D1ULL,
		0x654C952393A344D8ULL,
		0x8B1DB15E81292095ULL,
		0x6C2B0F1E7DD1AAF8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x89BB4950D50FD107ULL,
		0xBD4E9685F952F0F5ULL,
		0x77900314B1B951A5ULL,
		0x220EBA47823464D9ULL,
		0x38ADA59606F68E0CULL,
		0x8893BC371EB50D32ULL,
		0xE2DCD2F2C4373131ULL,
		0xFF038618224DD660ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF381DD95DDA8EC60ULL,
		0x033C86B48832E669ULL,
		0x2457531DD1EA9F00ULL,
		0x7C94A1DC99C2373BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0F9C438C15B7A6CFULL,
		0xD8FD8BFB6FB5DEB9ULL,
		0xCDE9D94636F8A90CULL,
		0x5AFAA9D8A49B7623ULL,
		0xFAB3838B4447B891ULL,
		0xE2DDF79025FEE5BFULL,
		0x9E31F96D3BB35F16ULL,
		0xD7984B81F01A9BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4641CA38385D1115ULL,
		0x85F04B61138BF938ULL,
		0x4954DF7D1398C672ULL,
		0x5B95DF22488E9449ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD883CF3A089DC0B6ULL,
		0xB3BCFF28773879FDULL,
		0x666FD388D437E5D8ULL,
		0x6ABAA6745AE9EE79ULL,
		0xAC698FD566F1BD86ULL,
		0x2AB64C531DCDC692ULL,
		0x7956BDB97706148DULL,
		0x86402F60CFC03534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702F28E7507FE592ULL,
		0x0ACC537EE3C3F3C3ULL,
		0x694FFD107F1EF2CDULL,
		0x5841AED33171D443ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x93B43A70084B8D0DULL,
		0x06BE256953B67677ULL,
		0x0464F513B2DAE198ULL,
		0x83448DE9DC6ED1B6ULL,
		0x8F8FE0DBF9974E24ULL,
		0x8994599BC116623BULL,
		0x330C0A8E05F4EE7FULL,
		0x0D9135882FFD303FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE30F9B1714C126C4ULL,
		0x72C37287FD090B4EULL,
		0x982E862895364886ULL,
		0x06D28020FC03FB17ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC15568F64DCB9894ULL,
		0xFD5AE0FCF7FB7DF5ULL,
		0xF0271999AFFD3211ULL,
		0x3A064F6C636BA06DULL,
		0x14AB5B122CFCF48EULL,
		0x6C9314228A774BEAULL,
		0x8842AC69A0CEE6CFULL,
		0x97B51972B30E7845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2C4EDA8FB57E8FFULL,
		0x1B2FDE1D85B0C2B4ULL,
		0x2A0CB1478EB374DCULL,
		0x3EE81672F7917AC0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9C7283F7CB222D93ULL,
		0xFD6551E7B0C34C50ULL,
		0x6B7C384EDEEE5944ULL,
		0xBC1B4E4CAF9221A9ULL,
		0xD88C9A3A865E707AULL,
		0xBE612A764192B1B0ULL,
		0x778BF393A8552406ULL,
		0xC6778302D56B73F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15168A7BD26E423ULL,
		0x3FD19F756C89AC90ULL,
		0x2A426039DB91B245ULL,
		0x31D8C0B85D8557A7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDF99BBE316F32DBCULL,
		0xB9F2B12409FC62FBULL,
		0xFFD62426B957F662ULL,
		0x123D1BACDB9FA55FULL,
		0x4105A5F9DB98CF64ULL,
		0x9C0C55B94CE21169ULL,
		0x8BE45729F0D9007AULL,
		0xBDBF42514DCE2711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86705EF9AFA1FABCULL,
		0xE3C76AA5738AF89BULL,
		0xC3BB1460798E0895ULL,
		0x3CA0F3BE683971FAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x77248851BA757E8DULL,
		0x8A7CA806FE9BD241ULL,
		0xDDDA77705530CF34ULL,
		0x0E93BEF7490F0F86ULL,
		0xE0004D16BD814B3FULL,
		0x2CDAAA416E21A91CULL,
		0xEA018092162CC7A5ULL,
		0x04997D3BB35707B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB72FF9B1DBA6A9FAULL,
		0x32F1EDBD579AEC8AULL,
		0x9A138D1F9FD671B9ULL,
		0x3D5C55D3E7FA3487ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3199D07B3CBA4F14ULL,
		0x7D6D2B074937B6CCULL,
		0xE3F32CEF036BC61BULL,
		0x39E082B13C633597ULL,
		0x50027395CAACA1F8ULL,
		0x3ECD6A8D0EFDE31FULL,
		0xD594511DEB12059FULL,
		0x84C2EB629BB491E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11F6F8B7525A5CC9ULL,
		0xCFEAFBF782E76D72ULL,
		0x97F7375FE8189BBEULL,
		0x6ECF73545930DDB5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3B29C8527775B33AULL,
		0xEE4ED2A2E0F3C498ULL,
		0x1B0926AEBE396F3FULL,
		0xA6CF65EF407DFE21ULL,
		0xAAD8C7CEDAA1AD8BULL,
		0xF51334BD671B8CE9ULL,
		0x8953B7878BA69786ULL,
		0xDF9AEA898B655D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97577106EB757AD5ULL,
		0x4F28A6C02F0AAF47ULL,
		0x7D7664CD78F3ED48ULL,
		0x57CE3659F189CE6FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2B3F9534AC86D5FDULL,
		0x016CA53533ABAE5BULL,
		0x3B590E34B678AFA4ULL,
		0x517C7A47DAD7322BULL,
		0x645A0C34212ED754ULL,
		0x1626D262F242EDF6ULL,
		0xDB65A25CE3BF3BDEULL,
		0x628CAB7D915DB7CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x109D64F1997ACE9CULL,
		0x4B2FDFE5299B00EEULL,
		0xCC6F27FE84DB929BULL,
		0x725DEEEB6EC07A6DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3945DAC895DC8AB0ULL,
		0xBB142D49CA9486F2ULL,
		0xB2BBC7598C18E738ULL,
		0xF154251161A8EB3CULL,
		0x76E05B4135408384ULL,
		0xB8D4B2D0C55EB390ULL,
		0x7D95725F94194B0AULL,
		0x27B9E77933490113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9366767D70113FULL,
		0x2AA6B84716A32E63ULL,
		0x56EAC18987DA0AD0ULL,
		0x56EC810EFE7F1421ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB696DE44E4109028ULL,
		0x0D03778801CB6410ULL,
		0x20D84F97EAED34C9ULL,
		0xB8FFCEFC575D4771ULL,
		0xF0C0C10634135A24ULL,
		0xEDDD47DD3D4D479AULL,
		0x1A3F0BAAE314D584ULL,
		0x4711532A27CC8A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733385309EEFF322ULL,
		0x5BDC225F1B440510ULL,
		0x06340AF5A004E684ULL,
		0x4592273E3FB9D357ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1878A2FB35F73558ULL,
		0x48B86556B62B8266ULL,
		0x8871946B60A4CD91ULL,
		0x042015D090ED78CDULL,
		0xD5E43E44C7397CA9ULL,
		0xDAACC67A131A5C8FULL,
		0x5540CC5D415D7C6EULL,
		0xB49C6D19C9F979A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD859E130C87FBA5DULL,
		0xBE5DDB758C153FBFULL,
		0x300FEA4314854605ULL,
		0x535847A48BF586E6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x97969F1165CCBC0CULL,
		0x7CD86361B01C0E3DULL,
		0x500819289E1EF1EBULL,
		0x98BE23B965D4F2DCULL,
		0xB0338C40528495B7ULL,
		0x551603E75FAD6A58ULL,
		0x59D72F090ACAF9ABULL,
		0xBE20A32897E7164CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF3D709DA57AF971ULL,
		0x1E1CF7B9E3D9D767ULL,
		0xA5F914803840015AULL,
		0x51965BBFF2224231ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7E3B6AB1FD7F4545ULL,
		0xF0DE9B41A8635FC1ULL,
		0xF27E1F7603812DA6ULL,
		0x630013ABDD772342ULL,
		0x2E6ECC7A66246C6DULL,
		0x53C1965C919AE4CDULL,
		0xBDD352345A6B9F41ULL,
		0x107B22525E9B5983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62ADC4DD26E75DD2ULL,
		0x5F9AECFF45615636ULL,
		0x1FDC533B6F7AD159ULL,
		0x55472BE5E8866CD1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD198C9DCF99EBD56ULL,
		0x47D0AA728D506946ULL,
		0x844907E1B602EFC6ULL,
		0xB4A1C309DBB6FD9DULL,
		0xD16252D928FD672CULL,
		0x5DA7087B23A07574ULL,
		0xE9770EE5F7DF751CULL,
		0x38D99A36F20AB4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63116190F3C0F34ULL,
		0x2E9BECB9D721D89DULL,
		0x2BF53E04812E51FCULL,
		0x24EEA731C94DD9F8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x398B6C7056AB831EULL,
		0xE7BF2F6CAB26DE77ULL,
		0x77F702A32A8C423AULL,
		0x5D2ED472824F0063ULL,
		0x0DD1E1C5D29F9A38ULL,
		0x4A55526D9778F87CULL,
		0x62C1BFC5CCA9695EULL,
		0x0CDA70ECD6FEAE4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B2EFCD9A5C67BAULL,
		0xF0696BB1271BC0E1ULL,
		0x20B979FF8BB1E639ULL,
		0x459B979A6C1CDFE0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEEAF495A3DBF4F10ULL,
		0xE614664AC57DCEF9ULL,
		0xF14768BB054D8731ULL,
		0x6C2B26A2A6CD0832ULL,
		0x8033BCCF8613CA48ULL,
		0xAC4211DC1D87D2D8ULL,
		0x236FC09BEFA4050FULL,
		0x5A1B5C6EBD719466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF65D502824AF57C1ULL,
		0x77E30CF727A71B1CULL,
		0x33DDFFE097A64785ULL,
		0x4C3ADF12C5A90F5CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x905ED2E4612966E8ULL,
		0x2DACDA36FF63117CULL,
		0x6B6DDEF4F3A3A112ULL,
		0x198E2B7F35E1A411ULL,
		0x0304A28708EBC968ULL,
		0xEA80084FB69687CFULL,
		0xE5CF02D46FCA5612ULL,
		0xE8C6CA1EAC64ADB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030EF2EFB4295177ULL,
		0xFCAE160C19BB3A37ULL,
		0x88284A7D8BAC67E0ULL,
		0x27102C0CCCD36C9FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1C810CE909610BC6ULL,
		0x45FB487D4C8CB4DFULL,
		0x7F817CA71F209388ULL,
		0x9696AFBB9BBB0ED1ULL,
		0x688EF008A865608BULL,
		0x619F236C826980FEULL,
		0x54E8F69626A5719FULL,
		0xBF6AA611145D63B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B8AE32086D64B6ULL,
		0xC39A8A98A835DAA2ULL,
		0x1A1616F0DBAF7130ULL,
		0x006B5644A197DC2EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6AF8A575FB1625EAULL,
		0x71042AF3937BB960ULL,
		0x3587D9FCE9017803ULL,
		0xB866C211E953CB07ULL,
		0xA9A03C43EC3F2E4DULL,
		0x904CE1B2FE743DCAULL,
		0x11A779B4153A2C68ULL,
		0xC9A68F31AC2ED03DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C1978B0C7709DFULL,
		0xDC6DAB8558BCE575ULL,
		0xD463EAB80FA40F88ULL,
		0x272003717846B417ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x305F6F85845B114AULL,
		0x8870A4F68442FFC9ULL,
		0xCAAABAEEF9013EAAULL,
		0x5ED9801CDCA9616EULL,
		0x2B3F3C4FE640F55EULL,
		0x904D65B34BDA799EULL,
		0x8530F9F1EA016E68ULL,
		0x667070F0B56346AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC26361B1FF7F8BULL,
		0xF3EDBD93C6B10D43ULL,
		0x8FEFD4D7B537A22FULL,
		0x138A43D7C965DF7CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEB1A5619A6F5DF80ULL,
		0x986A162334DD6EE6ULL,
		0xB1EBA808DF223B10ULL,
		0xDA9D9ECF574895D1ULL,
		0x7C4E3680A352E352ULL,
		0x3F9ACEC43D766C38ULL,
		0x53B8676C56658066ULL,
		0xF5B87BBCD6D5EFEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB66D31E543A32AULL,
		0x0964C74454717F49ULL,
		0x1F4B021DB2334A3EULL,
		0x53FFFCD73B0A330CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x09259BA5CB6DFBA8ULL,
		0x8B20E77BC5B0B14CULL,
		0x1CEF577E67622ECAULL,
		0x894143CC38382B74ULL,
		0x107F47ED965EB676ULL,
		0x7A80E62BBE6A46EDULL,
		0x3EDF1193B386D1DDULL,
		0x3D2D47F836897247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0A48EA1D7D1295ULL,
		0xBA4311FA0977387CULL,
		0x720BF36B0D6555AAULL,
		0x1DF9F2A4509F2207ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7F828015834B7AA7ULL,
		0x36E019E41152CF48ULL,
		0x3E52A408322DFC3AULL,
		0x3A9020339B6E4CA6ULL,
		0x79E99F9D34FB0657ULL,
		0xAE4058F57542E0E6ULL,
		0xE0A21E6D614B31D2ULL,
		0xB55E41212D36DB75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9830316B608E6F93ULL,
		0x146D4E537940317EULL,
		0x96632844A3576180ULL,
		0x268DCB205192E025ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8F8D7B853C4963E7ULL,
		0x42F80E7CE3D3D40AULL,
		0xD43FC1CA313F8C33ULL,
		0x3160984443CA36D7ULL,
		0x1F43ECA01FDFB37AULL,
		0x37DA924031089BA4ULL,
		0xB91A062692D1CCA7ULL,
		0x37ECDF29B5939E2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33A29B49F77E0933ULL,
		0x8D69C4042B1AEE67ULL,
		0x4E1CAB83FC63ED05ULL,
		0x7E89B87537B3B1A1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEF50CFAF3B0E2879ULL,
		0x81E21CA052D1E96FULL,
		0x8E5E12AF0166FB85ULL,
		0x8AAA92EB8AD3FDA3ULL,
		0x5AE5E810010921D5ULL,
		0x011FCA04DE28E6ADULL,
		0xD916A6CF426C9317ULL,
		0xD14CEF2E2CE66AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D71420F626932C4ULL,
		0xAC9A19594CE4272BULL,
		0xC7BAD572DD84D0EFULL,
		0x1C1613C63507D9F9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x66F255C12F1161FFULL,
		0x3CD0F2EC8C4582B3ULL,
		0x94B7ADAD0271E5E1ULL,
		0x4F9C7625CC55171DULL,
		0xA189FDF5929BD4D6ULL,
		0x3FDBC22C5F07608CULL,
		0x2770BDEEA20F99F0ULL,
		0xAF45F09595D01D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x616E0834F232FD9FULL,
		0xB76FC582A75DD793ULL,
		0x6F73DF1910C2BF8AULL,
		0x53FE2C5A09397317ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9A5FCA7CA0AF6DEFULL,
		0x5CA2E7A6F88E99EAULL,
		0xDFDBA17A99543DBEULL,
		0x74922899AAA22898ULL,
		0xD6A568031AD628EBULL,
		0xBEBD0D4EF92DE29DULL,
		0x490ACCC08946546DULL,
		0xE84D8E000CAFF178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76ED3AF29C7985F0ULL,
		0xACB2E15FF55E3D58ULL,
		0xB776060EF9C4C608ULL,
		0x70153C9B8CC00073ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD168C583D51EA882ULL,
		0x0F2674AC950BC0CCULL,
		0x55ADCEBA52073058ULL,
		0x47C9E6897D7DA5FFULL,
		0x3E32D48FB43A32B2ULL,
		0x9B22B5F409E259D1ULL,
		0x7D52F27574DC32A6ULL,
		0xBEB978F676E751C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CF452D895C23329ULL,
		0x164D76E60CA515DCULL,
		0xEFFDCC29AAB6B513ULL,
		0x1751DB1F23D3C99BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAB1EB54CE7BDF922ULL,
		0x10FAFFB3CD738C80ULL,
		0x1C9FC303F8968CE3ULL,
		0xDCB7BAE8B8AA0C6DULL,
		0x8B953C584BE45047ULL,
		0x2B8F41C7420643B7ULL,
		0x03E4C589B9BE9A6FULL,
		0xEAFA69428E613E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6345AA682BA1E8F1ULL,
		0x883EC3479A6199BFULL,
		0xB09515758AE17963ULL,
		0x3DE35AC9DB194FDDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBD93F18B0234A2FFULL,
		0xC829D0FAC99764C3ULL,
		0x83F3DEE5E36C9BF4ULL,
		0x6A8BDB625474254DULL,
		0x778F26A73C84D617ULL,
		0x1F8DECBE5C8D4245ULL,
		0x5C5701F1E5A1CC23ULL,
		0x768F4F27655AAB6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CD3AE5DFDEC6D15ULL,
		0x773AF53C868F3B13ULL,
		0x38DE28CDF970E92BULL,
		0x03D19B3B5FE997AFULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE9F351D227DC55E5ULL,
		0xD0687F10D66087D9ULL,
		0x1A19520B953A295AULL,
		0x02016F523C1ED712ULL,
		0xA8035E22875BF507ULL,
		0xA9043BD32CA6AB0AULL,
		0xF9EE7ADD5A0D74B3ULL,
		0xACF6D5CB69E8B251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA734AF23F82B8B8ULL,
		0xE7096069771DEB6EULL,
		0x337F8EE6F3397C05ULL,
		0x2EA52B83F4A94F3DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC01FCA1914AEB8EDULL,
		0x6342C7DBD37DAB94ULL,
		0x0B0D7D44FBE472D3ULL,
		0xF2040C185F7B7129ULL,
		0x928CC9C11D58C61CULL,
		0x32B4BD9E1D0FF0B3ULL,
		0xC21C3597A59B26FCULL,
		0xCE67C4A8D3F9F812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8105BCC36FDC25C2ULL,
		0xEA16ED5423DB663CULL,
		0xDB3D71C790EC3C42ULL,
		0x156B3D27D69643F1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x895D95532100853EULL,
		0xA7C595C8B4040BBBULL,
		0x8BE3270F083B69D0ULL,
		0xC91F4831AA1F5297ULL,
		0x0F83897369FC47C2ULL,
		0x49D059843B4D1CB7ULL,
		0x35FD95417FFA632CULL,
		0xF7E4415A74FC6811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E3FC74DC73319BULL,
		0x9CB2DF6981764EE7ULL,
		0x8F874EC807662263ULL,
		0x1500FB9F0796C525ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0C21F9D29E51A884ULL,
		0xDAE276D8CB41EA01ULL,
		0x8EC032D351B96DC3ULL,
		0x6DFF55742C9345ADULL,
		0x7615AD84473C68C1ULL,
		0x6DEEA740477C37D9ULL,
		0xF5394D4F5C7FF79CULL,
		0xB2149C10C444DC34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9359BB7531493919ULL,
		0x2C4F4A6367B23448ULL,
		0xF541AC9B0CB82EFCULL,
		0x5D0E7FF14ECBF589ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2D3838D1A39CF3F6ULL,
		0x09CD02AD7C429242ULL,
		0xB2A2AD46530251CFULL,
		0x6C8DE85EB6105F17ULL,
		0x0CD33429A14D85B6ULL,
		0x5295E25ED098E3E7ULL,
		0xF576A776307E183FULL,
		0xD3E481C992BAE86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1491F6FF951ED1A7ULL,
		0x4C0C9CC072F4668EULL,
		0x223F88D185B9EB35ULL,
		0x60792C4A7DCEDFB6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x01C8C692C982A0C7ULL,
		0x297AB728875F8B90ULL,
		0x13C6A0D79D00E830ULL,
		0xE48D3F0597B1EF49ULL,
		0xBC26ADD0D5428F77ULL,
		0x6453E37493DE52F0ULL,
		0xC97D7B8BB5522F2CULL,
		0x0AB81CB02F94CC5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8693927163ECBDULL,
		0x0DEE7A767A5FDB4BULL,
		0xFC66F7948733E8C7ULL,
		0x7BE1812CA7C844E8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1DB21799FE420CE2ULL,
		0x81724145FFC28B61ULL,
		0x8B5DDEE11F74AB50ULL,
		0xD1D8CF5F4CE1BA4FULL,
		0x79C421CA2794EFAEULL,
		0x526592EE3B27CB97ULL,
		0x7C3A1101B0333CC0ULL,
		0x6ADF5F2FE15FE3DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30CF1B9BDE5DA329ULL,
		0xBC8610A2C7AAC3DDULL,
		0xFBFC6521470FAFDCULL,
		0x2F00F07AC11D8D55ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA1D94FE481B3CB95ULL,
		0x6D61097447AC0736ULL,
		0x401D323B634EB8ABULL,
		0x4119F1B3186E1EEAULL,
		0xBD289A46849D62B1ULL,
		0x977D90661AFAC9B8ULL,
		0x76C99549E3DEF1FEULL,
		0xD78B38F9CF55AA90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E0365C3110769BULL,
		0xEA04789C48E5F8A2ULL,
		0xE2095B333666A475ULL,
		0x3FC466C7DF25705BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2ED4736C973A60EAULL,
		0x5880CDB0436BFA2BULL,
		0xEEFF2AC5661EF97CULL,
		0xD1E5C47166614FADULL,
		0x43BAA20065B43EBBULL,
		0x2D9EAA1F698B6195ULL,
		0x71F9FF3B04DFD768ULL,
		0x4829E680F19E1815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C887F7BAFFBB261ULL,
		0x1E0E0E59EE1C7653ULL,
		0xDA1B0D881F58F2F3ULL,
		0x081DFB9543D8E2DCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF54E9C37BF7C6012ULL,
		0x1687408D7B75330AULL,
		0xC07C3EE25427F6B8ULL,
		0x13A5BCBD005CE753ULL,
		0xB20B3C35E1CC1D6FULL,
		0x381BC977A8310FB1ULL,
		0x16544A71C8810098ULL,
		0x13A6DCA0D6B58F48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F98C3743C8BEEBULL,
		0x6AA7285072BD876BULL,
		0x10FF4BC6174E0D50ULL,
		0x7E6A7C9CDF502C07ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA9E5929613A81449ULL,
		0x26B56C5759BD1F37ULL,
		0x40FC666D236FC7B1ULL,
		0x373C25BCEF10B2FCULL,
		0xF1C922703F8FEF3AULL,
		0x6BA1BB815D8F3194ULL,
		0x5BD414A934ADFEB4ULL,
		0x04010C51929F4880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC0AF3F830596F8ULL,
		0x20B7418B3CFE7B53ULL,
		0xE277778AF5439679ULL,
		0x4F63F9D8B2B57609ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x28C98518BE6C6EE5ULL,
		0xA99E9D1D3507F6C4ULL,
		0x0E59D27E936D1543ULL,
		0x510E9465A2F3BFFCULL,
		0xD1BE7E6CB0D585A8ULL,
		0xCCD15A08F78831EEULL,
		0x72FFCC42965135EFULL,
		0x6227A318CE43A96AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B10493AFE1E47FCULL,
		0x10B1FA71F33F6037ULL,
		0x20522460E37B16DCULL,
		0x62F0CA1440FEE5C9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE930677091AD2E08ULL,
		0x476EC5849AE66A4DULL,
		0x6EB7D4E4F81BF8A4ULL,
		0x7C10B1833BBE1233ULL,
		0x044F163C3C96A894ULL,
		0x278BC47A204A4543ULL,
		0x8DBEA7A1FB436E85ULL,
		0xDF0FFA8230106976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEDB461900A38F9ULL,
		0x262DEFA565ECB240ULL,
		0x7904B6F0441E6068ULL,
		0x186FE0D65E2DB9CCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E687C10F2FD024AULL,
		0xC80D34046EC20940ULL,
		0xEB2466846F3831EBULL,
		0x5076E5942E9E433EULL,
		0xC1E6292A8BAEA3F9ULL,
		0x23E3B9590E13EF3FULL,
		0x73AC843D717E2BDBULL,
		0x6820C3DE03C670E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36929861AEE95B8DULL,
		0x1BDAB73C85B78CB7ULL,
		0x16C007A347F2B473ULL,
		0x4553F888BE1304DCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5849762A56BCC805ULL,
		0x46666BE2A4A321CBULL,
		0x82BA0E6808DEC750ULL,
		0xA187CC5540920D0AULL,
		0xA66829DF9CAD052CULL,
		0x120CBB3F49A557EDULL,
		0x0F5CB87016D55FABULL,
		0xE3F4947E6093781FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BBFAD5B986B9199ULL,
		0xF44A3747932E2F12ULL,
		0xCA7D6F0B6C8AFAB4ULL,
		0x77D5D7179675E1A6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3E85A5915FE1415BULL,
		0xCD8622BF4BE8219DULL,
		0xFC3C5ADB8C9A500EULL,
		0x37CEE4887DBA734BULL,
		0xB1983C8F785F4B2CULL,
		0xC2E507CDCABC0FC3ULL,
		0x124DEC410076A61FULL,
		0x325749616792BFA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1EA2DD3E066B00ULL,
		0xBB854B4B63D278A9ULL,
		0xB3CD6C819E36F8C5ULL,
		0x30C3C8FDDD82E50EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x94A034DCD4D27650ULL,
		0x53CF0159042F2844ULL,
		0xDB9AB793588119D5ULL,
		0xAB4B4B4306658EACULL,
		0x8158BC3C75918FCBULL,
		0xC52854662AD443F6ULL,
		0xD5FE8BD55BAF8233ULL,
		0x575F6F26F0548EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CC25D6486DD073ULL,
		0x97CB88835FB13EDBULL,
		0x9F63793EF48E6D84ULL,
		0x2375CB0AB2F2BFBEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2E5CC41B07DCA28CULL,
		0x8F28C34524C8C01EULL,
		0x09E8F680083C85A7ULL,
		0xFE99E128184B1BD0ULL,
		0xBB6AE5B91613FE92ULL,
		0xE9BC202E399E175EULL,
		0x35FAFDD84B168D90ULL,
		0x3ECB27EE49FA8987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003ADD944ED46DB4ULL,
		0x41158A21B240382EULL,
		0x0D2AA49B2D95892AULL,
		0x50C1CE87137B85E2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3EEE9D66CFE26249ULL,
		0x88AC628349AAFDD2ULL,
		0x44851CA037F380BAULL,
		0x7D9BB9F93CF53A0BULL,
		0xF384FA56E1B58A98ULL,
		0xE4E5923C7F96AF04ULL,
		0x2762FBD56157C09AULL,
		0x88895619C0EB8B7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64ABC64C50D4F7E4ULL,
		0x82C0177E3A08F88EULL,
		0x1D367E4CAAFA17B8ULL,
		0x41FE81CBDFEBEEEBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBD344D7A07DC05A7ULL,
		0xE54B786002A4D225ULL,
		0x29D1E681538D34F8ULL,
		0x43DF00F408C15463ULL,
		0x86BEF76E72B4051CULL,
		0x807DD52D4ECF79BDULL,
		0xB59A5EC6CA3268DAULL,
		0xB1C90175AC40FCEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8D07DF0E94CBBEULL,
		0xF7F91D19B570E447ULL,
		0x1EBBF8035708C567ULL,
		0x27B5386B9A66DFF8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7DDEC55450213DA6ULL,
		0xABF46BB9CD04F3FDULL,
		0xF232B5896F639071ULL,
		0x5553BCD2C647E28AULL,
		0xF1DEB25096E518A9ULL,
		0xB2C0067E143C08BEULL,
		0x21EECCF622A0F6ADULL,
		0x0552A8155E6FFFBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64ED3D4AB622E6E2ULL,
		0x34756270CDEE4055ULL,
		0xFBA5221293482E3AULL,
		0x1F98AFFECAE7D877ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3A45EEFD807D2C06ULL,
		0x9BA7DF7A5FC2891AULL,
		0xF9C2876202D9FBD9ULL,
		0x0FEA3539B6BB42F7ULL,
		0x917B543A5025D8CCULL,
		0xC16EE3E06BE0135BULL,
		0x60345959C05B6BBAULL,
		0x86321014B25ECE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2946FA5661B5D33ULL,
		0x521DB2CA630568B1ULL,
		0x4187CAB4906BF992ULL,
		0x7B58984C30CDE0ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCEA38B64F24BA634ULL,
		0x50C221B761AFFC7AULL,
		0xE8993C2610032629ULL,
		0x24B9EED599F222BCULL,
		0xDF9E3A1C6469EE29ULL,
		0x03A99B896167F611ULL,
		0x25F6FE7839BD0ADDULL,
		0xC180D52C5F45A9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00202B9BDA050485ULL,
		0xDBEF381BD71E8322ULL,
		0x8B4301FEA212C2F7ULL,
		0x5DD9936BBE495A02ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1457A3F1B5E07BB4ULL,
		0x91939EECAE1E548CULL,
		0x7DEE9ED4B37A5795ULL,
		0x9A30C2FB302391B1ULL,
		0x863D15D3241F2FABULL,
		0xA010686BEEA31F80ULL,
		0x110FC5CE735EA29AULL,
		0x760C678DC992B878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0168E149128191C2ULL,
		0x54031EF21A5501A0ULL,
		0x0645FB79D3867A89ULL,
		0x200822071BEAF384ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x70DFE5C864BFF3F3ULL,
		0x72F902E535487E75ULL,
		0x5F641B4889AE0871ULL,
		0xC4E57AB56E1A88A8ULL,
		0xC7471E75A5B054D6ULL,
		0x9C26E1239939F712ULL,
		0x7951A9BEAEC4C193ULL,
		0x8B53469A0E063F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056E6B3EFCEC8ED5ULL,
		0xA0BE6E2DF3E32B3FULL,
		0x61834D967AE2C45AULL,
		0x7341F5938307F9E2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x580A113EF8B08E80ULL,
		0x796BED595665D06FULL,
		0xE352BAECDD1673B8ULL,
		0x3EEE8F0AF6490C2FULL,
		0x00C50F8D4EB282E7ULL,
		0x800D022731278CD8ULL,
		0x996DB48B8DB2BD7CULL,
		0xCE0117FDF05304FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754A6038A7300151ULL,
		0x7B5A3F2AA244B87FULL,
		0xA99B87A3E59E9433ULL,
		0x53181EBCA29BCA20ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x208F696EBE02FF90ULL,
		0xD41D65445B87B478ULL,
		0x5DECE2501C264F1FULL,
		0x44D08316755D5CCEULL,
		0x943C25A88312B258ULL,
		0x8F0CE0A0E10D6B81ULL,
		0x8C8201AF93322B35ULL,
		0x231B3CC452FCCD02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x217D007232C9795EULL,
		0x1006BD25C385A9B4ULL,
		0x3939225FF598B913ULL,
		0x7ADB883AC6E3CB2FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE3ED2B9FD888BDC9ULL,
		0x60AA6277C26E1F4AULL,
		0xBA87B038B43EA58BULL,
		0x34EFFD3FDD844762ULL,
		0x4AF16ECEC4339BDDULL,
		0x126F0DD353D71AA5ULL,
		0xDA6C3F7292150331ULL,
		0x9A414973DC015944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C39E50F831E401ULL,
		0x1D266FD6345C13D4ULL,
		0x26991B3A635D1ED4ULL,
		0x1AA0E47285B7879BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x59711D6396676806ULL,
		0xCFD383E2A7408BF3ULL,
		0x96EE977A4828F259ULL,
		0x5D2A50830E5ADAB8ULL,
		0x45ED61E1B00A6CCDULL,
		0x1A1A63BC98890AC6ULL,
		0x62E3B507D878820CULL,
		0x8F8AAFA20327D2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAADA4E3B7F391A5ULL,
		0xAFBE51E14B982561ULL,
		0x44BB76A46A0C4025ULL,
		0x2BC0628F864423B9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF5566D8FC4B97C6FULL,
		0xEECE5F7C725D8448ULL,
		0xF6346E2BC20B9142ULL,
		0xD66F97B99F7D2F7CULL,
		0x008024F72AF53F60ULL,
		0x43BF07A21CF3C656ULL,
		0x2CE8CF7ACEBBAF4FULL,
		0x7531F67ECECAC666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085BEA402520E75BULL,
		0xFD29818CBE8CF50DULL,
		0xA0C33A6671E79706ULL,
		0x3BDA2E8C5196A2A7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x0762EF8CABCC77D7ULL,
		0xA530E06813936F09ULL,
		0xFB7759AF9356AC43ULL,
		0x86B1EAA0AC42EB74ULL,
		0x000813056C41471CULL,
		0xAD7A5F26A6CEE1EEULL,
		0x2C3471B5C8B42855ULL,
		0x691ACBAD27571129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0895C25ABD7D085FULL,
		0x655B0024D648F85DULL,
		0x8B403AAB5E14A8FBULL,
		0x20AC2654832F7791ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDA4AA4CA2B2F7392ULL,
		0x93D673962FB5BB7BULL,
		0x10671002257D2354ULL,
		0x144CAA06B3900BA9ULL,
		0x23B2D33C67CAA172ULL,
		0x739BC6798DB0BD10ULL,
		0xB9B15349B13D1007ULL,
		0x020D34EC75CC2C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D5FFC193436A7EULL,
		0xBCF5E9A137F1CBE1ULL,
		0xA0B96CF2748D846FULL,
		0x624285202FDEA81AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD643B0DF92F8B4E2ULL,
		0xDDD0BBFBA852E8E0ULL,
		0x74D6C8DFD5684CA5ULL,
		0x8E02A0897FAEC504ULL,
		0xE0BFEA232E9AAF9FULL,
		0xDD24803CF93E6FC2ULL,
		0x3870C250901C3BC9ULL,
		0x18B33477205FFEFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C072187DEEC714ULL,
		0xB13BC508A7977FCEULL,
		0xD593A0D539992C9CULL,
		0x389C6A384DEE9E4EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x9DD5361D53AEA01BULL,
		0x8C7FFAE83651868AULL,
		0x9CB5AAA37800FDE2ULL,
		0xAF6CDECB5A39EA95ULL,
		0xEF23B9811DB11C8DULL,
		0x7193251399B2E38EULL,
		0xAF14093BC27A5BD3ULL,
		0x05FCC2F4BF631F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D22BF47BBF8DD42ULL,
		0x68577BD106DF4DC2ULL,
		0x99AF0982562A9F45ULL,
		0x12F1CF1FC2F0927DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC53A5EE030FBB1A9ULL,
		0xB4348B5DE138CAECULL,
		0x89B9A59FA31F16A4ULL,
		0x7292733555CDC31FULL,
		0x61D2D4C0C4AB1724ULL,
		0x5C895B020CEFED99ULL,
		0x46960881429D1D50ULL,
		0x63C9E05CCB59A4BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A85F37D6261233BULL,
		0x70980DABCCD60FB1ULL,
		0x03FEE8CF86717092ULL,
		0x4289C0FB851C36C6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x10A0EFABFD13157CULL,
		0xA5BD70439A55035AULL,
		0x4A1F817510310E26ULL,
		0x1875FFDD5A4BB89FULL,
		0xC06A84A8F3FA43B9ULL,
		0x648C36B1C1948F96ULL,
		0x00CC1130F43C02AAULL,
		0xACC0BA776A3C37FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA070A0C0343926BBULL,
		0x928D8EA6566253BAULL,
		0x686A0EB951197371ULL,
		0x3D11AD971F3C082DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA98D8EBB850B99F3ULL,
		0x09E41EF30EB7A58EULL,
		0xAF9CEFEF74FCC912ULL,
		0xFAA17E5F564AA768ULL,
		0x2DB96A3AC4623A59ULL,
		0xB6298931CE8DD0C6ULL,
		0x13CB51057402DB62ULL,
		0x047AF48A27E16D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73135374ABA04362ULL,
		0x140E7C57B7C4A2F9ULL,
		0x9FCAF6BEAD6959B9ULL,
		0x24E1CAE141C0DD95ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x67F4D86B7F2C3282ULL,
		0x20EDE35DF56EE491ULL,
		0x0A0D8822CBA17F1EULL,
		0x86E5562DB9DCD614ULL,
		0xE6F5C01F1194D29DULL,
		0x716860F6C5F3ECD0ULL,
		0x3C3A0C97146CDAB6ULL,
		0xF320CF3C28C81EA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06F5D081B437B3BULL,
		0xF66C47FF57A40B93ULL,
		0xFAAB668FD3C9F632ULL,
		0x1DC4191BC791624EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD62FE80D798AFC11ULL,
		0x2D78D9D5EE8B599DULL,
		0xB4E1877E4317E73FULL,
		0xDB04E889D3AB6F18ULL,
		0x7B057EDC3ABF1BD5ULL,
		0x9E970533BA0CE5E1ULL,
		0xCCA7622060D585E3ULL,
		0xBB74EE76DC5FAC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1900BCBE31E921EAULL,
		0xB7E39F838C757916ULL,
		0x15BA184CA2C9C708ULL,
		0x2E604E2E89DEFF3BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB70E78BE89DC9C83ULL,
		0x8D3D45A081352106ULL,
		0x5ACD9A0F94378937ULL,
		0xFAB851321B0536ABULL,
		0xD175A878AF831B49ULL,
		0xBCA80379A18711D0ULL,
		0xE33611C0A9D32E1BULL,
		0x373EBCBCBA269B1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE857AA89752AAAFULL,
		0x8E2DC9AE7B41C605ULL,
		0x14D43CA8C9906155ULL,
		0x2E085535BCC03D67ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1A0054471802B916ULL,
		0xC0AACEAFA7DDD786ULL,
		0xD858EF7D33E546FEULL,
		0x876D8CA135334103ULL,
		0xA4C93A1ADE4739C2ULL,
		0xE52148990C61702AULL,
		0xAE6D7266D4367322ULL,
		0x5142D5DF4793455FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FDEF44416954DBDULL,
		0xC39B95677E547DDAULL,
		0xBC97EAC0B3FA5E2CULL,
		0x17594BC5D50F8D37ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E1D28AE0B9A6FA2ULL,
		0xF872759895583641ULL,
		0x33684E4A7066050FULL,
		0xB5F7C667AA652536ULL,
		0x61B42D1510178E5CULL,
		0x96B750DCD3B64858ULL,
		0xF967965781609DB5ULL,
		0xEA139EB871EF23A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEDBD9CE6F19967CULL,
		0x57A876600266F35FULL,
		0x38C89F47A4BD6E04ULL,
		0x74E155C893E46F67ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x24BF9F43D83AF60AULL,
		0xAA1F47C7033F8255ULL,
		0x4F2CC3A5A24153DEULL,
		0xAC7A63030071E286ULL,
		0x083A1CEA9C43B8D8ULL,
		0xBB7A4BD9CCBCD372ULL,
		0x2E1FEDF8DDE60AEAULL,
		0x7F98A23C1A1D3EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5FEA170A4868FFULL,
		0x7E468A1B6746E542ULL,
		0x27EA16969266F2B6ULL,
		0x1D2277EEE0C931B7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x46E0D19B8F12D274ULL,
		0x626EC3D403193969ULL,
		0xA5218C1EED4187B4ULL,
		0xF2AE12D9D63A00F6ULL,
		0x1F2134CB09C0AF18ULL,
		0xDFD5D571B9796BC1ULL,
		0x60AB7A291556911EULL,
		0xFAB3E2DEABF6FE61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5CEA7BF01ACD5A8ULL,
		0x9C2C72B58B1F3813ULL,
		0xFE95AE38181B1249ULL,
		0x2961BFE75CE3C36AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE109FC3CF404A231ULL,
		0xA6ED9A6ED06BDC13ULL,
		0xE1CF6AC5AFFF4B71ULL,
		0x5E933EA8963F6638ULL,
		0xEC64E1BE3FE03DA6ULL,
		0x51F3800531222274ULL,
		0xEFDE28BC22061F25ULL,
		0x3BC684F990FE8F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8037E7A6F4DCA2BULL,
		0xD1129B341B7CF96EULL,
		0x7CC976B2BCE7EAFBULL,
		0x3E0AFBB41C08B382ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2EAD98167C487090ULL,
		0xE996143A822FA5ACULL,
		0x022DCC2F139B6525ULL,
		0x9C409BB76F8F8C1DULL,
		0xD4F6A55F83EB67FCULL,
		0x9EFDF310E40368EEULL,
		0x0C8D30DB9B74DBCAULL,
		0xAFE56B44F25820C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4A24441139E3E7ULL,
		0x834828BC5AB1391FULL,
		0xDF230CC826F40539ULL,
		0x384E87F368A4695CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC8371DD91539AF22ULL,
		0x4B641BF05B2377F8ULL,
		0x68C3C8FC3C481643ULL,
		0x8CDC4BCA5B4137E5ULL,
		0x1120F8A44763DFB4ULL,
		0x824055245727D515ULL,
		0x1E383EA8559D1FD6ULL,
		0xAF105F98163750B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x531C063BAE0CE7C9ULL,
		0xA0F0BF554B0D1919ULL,
		0xE51D15F8F19AD01AULL,
		0x094A7C5DA77732C7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x56740A49BE24CBE9ULL,
		0x267DD1D211FD3FECULL,
		0x83642D9D68F90A22ULL,
		0xC730610C5022E0B2ULL,
		0xF19CF50E902E1C3BULL,
		0xD53BF0405B07EF6DULL,
		0xA2B9E3F535F60FD6ULL,
		0x22FF155422583E6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C06A7324FCFD7CULL,
		0xCD637B5F952ACA3EULL,
		0xAAFC04036B7F6405ULL,
		0x790D8B89693C24F8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x64BEEA815E8DE9A6ULL,
		0xB7742DD2382E2616ULL,
		0x78B01B65AA235F18ULL,
		0x1563B9FC0756BBE6ULL,
		0x38F007CE0051027EULL,
		0x0140464BAEAC0E8BULL,
		0x8D29DC936E445C9EULL,
		0xD9213B2E4EF803FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86013156A944D1AULL,
		0xE6FE9D0E25B84EC0ULL,
		0x6CE6D94808491E8CULL,
		0x505282DBC0275317ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x70168F8CD327E85AULL,
		0x455E845AEE60D802ULL,
		0xB364D4C3491D0324ULL,
		0x0F6AEDDC3C757EC8ULL,
		0xA769096CE7B1259FULL,
		0x07F9C2B67002987DULL,
		0xD018142649126791ULL,
		0x7FC088238992FF1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49ADF5B7377380C6ULL,
		0x74716B6F8EC37AA9ULL,
		0x96F7D27221D862ABULL,
		0x05FF2322A8475D5BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE0BB7C97E0CAA624ULL,
		0x62895CDFD8EBA040ULL,
		0x5FF1FF3611A13044ULL,
		0xC7997445208A5D3BULL,
		0x151265F15189D5ABULL,
		0x5416AAB970D6A55CULL,
		0x1DE5C0A832CC4D90ULL,
		0x748E66B0052BE930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01769E69FB406032ULL,
		0xDDE6B46698C82BECULL,
		0xD00C982D9BF4B3B0ULL,
		0x14BCB265E50EFA5FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x88A288D4EBDBD9D6ULL,
		0xBD7E1C8E6D28B131ULL,
		0xB306CE65AD057D33ULL,
		0xE8666877BD3147E0ULL,
		0x7AE0617AFEFB5748ULL,
		0xA4B062BE35A6F831ULL,
		0x69A7A9FCC0646F15ULL,
		0xE93D67D8A44DC35FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F10116C52AD3CBULL,
		0x2FACC4CA63F18889ULL,
		0x61EA09EA3BEDFA6AULL,
		0x0783D2A020BC480AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x551534AC346E5DC7ULL,
		0x4705CFE06AE09EC6ULL,
		0x46E586C338BECCCFULL,
		0x2724FA3A014C3F15ULL,
		0xA2E35C9E925323F2ULL,
		0xEFB154545CE28CA9ULL,
		0xB223FB2358840FD7ULL,
		0x28C191B307C83A0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82D4F435ECC5B497ULL,
		0xDB58546634817FF4ULL,
		0xB83CCE025C5926DCULL,
		0x33E09ACD2904DD69ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAF7BF90755002D1CULL,
		0x2052AD9325161D5AULL,
		0xFB28ADDFA5A85AF4ULL,
		0xEBA7F359444B88E7ULL,
		0xA4690FFB53E8A924ULL,
		0xE1B6A04B0AA95FE8ULL,
		0xF69D4D82B890A612ULL,
		0x28CC788485185B94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17145855C989496BULL,
		0xA16E78B6BA3A59E3ULL,
		0x96822F470B2101C1ULL,
		0x7A01D70505E92104ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAD83FE858AC507EDULL,
		0xA5DFE7F593973DB0ULL,
		0x0083E103BFACEF8FULL,
		0x6B0E9699463C323EULL,
		0x49F1CCCCDFB4FEB2ULL,
		0x390386DBAF859568ULL,
		0x7B092FD2873E2747ULL,
		0x6A51F14085A78F42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76864EEBFA2D8B9ULL,
		0x1C65EC91A16B6B2BULL,
		0x43E0FA43D2E6C422ULL,
		0x3338662D1D1B761CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2257B949E49FC069ULL,
		0xE46A5BADDE55144FULL,
		0x98C24AB457FACE64ULL,
		0x9FEFFE7A2FF461B8ULL,
		0xE9DAB4F1ADA63F4CULL,
		0x59C3B70CAE72BB10ULL,
		0x6EC90BECFE0EA867ULL,
		0x34F29DACADAEFF22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CE9529AB4D26E1ULL,
		0x3777878FC35CD8D1ULL,
		0x0A9A0FE20E27CDBCULL,
		0x7BF3661BF7EE40D5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC3B022A3A3DD5376ULL,
		0xD6A30B31A6DEFC0CULL,
		0xDC779EAFF507EDD0ULL,
		0xAE203D845510B6C3ULL,
		0xB928AC0C81EC382DULL,
		0xD577907F94BE5052ULL,
		0x04C7F0D008064D36ULL,
		0x723490CF3490E90DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB9AC7EECEDACBDULL,
		0x86627E21BB1EE854ULL,
		0x92255D9125F763F4ULL,
		0x21EDBC4622934EB2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x504637FD057A6E46ULL,
		0xA9004CD3C1795099ULL,
		0xD8B10DD16E1FC86DULL,
		0x4A966A7B81662D99ULL,
		0xFC794A565DBEDCA2ULL,
		0x62B84861C6707E65ULL,
		0x122838BE87394A8BULL,
		0xF5236A62BC428E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4740CEEFCF33BDULL,
		0x505B0B57362C13BCULL,
		0x8AA97A1980A0D91EULL,
		0x2DD835237347419CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x56325C1F59E3BDE9ULL,
		0xEB09C476D055D137ULL,
		0x584761F1A4F60679ULL,
		0x9A1CD3D8D2DA2FA2ULL,
		0x3E8BF8926F083254ULL,
		0x7DB9C0D24D46590DULL,
		0xE2C8F5F8A696779BULL,
		0xF46DD7E888D39447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF941DBD51B3BCCULL,
		0x949C63AE48C7092EULL,
		0x021BE4DA5F4BC78EULL,
		0x626AE05D2242324EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8CEE1092AD4CA880ULL,
		0x6973F84AB9BA008DULL,
		0x85E02912B20F9AFCULL,
		0x60E7A37254735B49ULL,
		0x6928126554AE6215ULL,
		0x4D980A227FC452F8ULL,
		0xB9487726AC0F0D2EULL,
		0xB4CBA720977100DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E0CB9D3F2F3BA0ULL,
		0xEE057969B0DE516DULL,
		0x06A1D8D03C4B8FDBULL,
		0x37227248CF397BC1ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xABF49412A90125C7ULL,
		0x88A1D97A707731E0ULL,
		0xF4F89FE20D383493ULL,
		0xE6D6028F36E6DA78ULL,
		0x89D34F50DC7891A9ULL,
		0xEB72E52FA220B021ULL,
		0x9BCDA2C4DA2FBFCDULL,
		0x51F42F564672CDADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21525A1362E6C6CBULL,
		0x7BAFDE8C815156DBULL,
		0x157EC91A704EAD24ULL,
		0x1115095DABF1623EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x85D3774DAFFAFFBEULL,
		0x8322A8B59707DFD7ULL,
		0x55B41C9EE038A4DAULL,
		0xB6A1AAED977552ADULL,
		0x65230AD6E9D2B844ULL,
		0xE11B7BE62D9EEED6ULL,
		0xD004EBBC48CEC198ULL,
		0x702F04C684C2C798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8907133465425C5CULL,
		0xED370CE05C9F53AAULL,
		0x366F1A91AEE9618BULL,
		0x5D9C60654C5EF35CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x88954B9B6F0B3AEBULL,
		0xDD655170B0ACCC84ULL,
		0xEC2644C184170EF5ULL,
		0x9A023C0FD096AE98ULL,
		0xBF8F0FC4BDABA50DULL,
		0xD6D28CF120B57837ULL,
		0x725DACF052E6BCCDULL,
		0x1D948004998289B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7D1A2CF9685BB84ULL,
		0xC0A63D3B8B9CA4CAULL,
		0xE60DF06DD2571583ULL,
		0x7E0D3CBE99F71F87ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBA156E92C4916FC2ULL,
		0xA0A9307D009463E7ULL,
		0x3E8CEC2E598A87E3ULL,
		0xF5AB7E542C908FA6ULL,
		0xCBDCFE8C00EBD3BBULL,
		0x3AA16F4A13818173ULL,
		0x3A96B1967A919D67ULL,
		0x52CCC579B9169BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCE3375AE792DF72ULL,
		0x549FB57BE5CD9B17ULL,
		0xF0EB48848B27E536ULL,
		0x4010CE65A5EBB360ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1BED44FA5F90795AULL,
		0x42F4B195AB9D2475ULL,
		0x747D8BB23A21D264ULL,
		0xA39FF1E7C4EDEC17ULL,
		0xAB9DBBF68433F651ULL,
		0xA86175904E9ECE16ULL,
		0x881D1FDB52B08971ULL,
		0x79713377089CC7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95572B91FF470C1FULL,
		0x416C2501572FBBD2ULL,
		0xA8D0464080563943ULL,
		0x2A6D95930C338FB3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x366C30ED85B4F213ULL,
		0x09881580F957086EULL,
		0x9D2DBCF50C34BBA4ULL,
		0x838ECF9671E9BB73ULL,
		0x1A4062146871F12BULL,
		0xF15BDA55A81FB451ULL,
		0x2DC7DFB765487617ULL,
		0x6AFD8DCF3DF5DE6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFABFF5069EC0D5ULL,
		0xDD2A7E37EE0BCC78ULL,
		0x68D8F22E14F64331ULL,
		0x6531DC59A468BFCEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x65D4B091DDCF811DULL,
		0x7CE22AA68BE77700ULL,
		0xA1FD6189234F377FULL,
		0x73B6CA6CEE54C9FFULL,
		0xB62981E420CB3DF1ULL,
		0x98F30AC955913233ULL,
		0x9966CEA326FF212DULL,
		0x6448E3EB91E3A4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFDF86EBBFAB51DULL,
		0x30F5C4893F74EAADULL,
		0x67400DC0ED2E2444ULL,
		0x56889F64961F45DCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8E1861AA945BCFABULL,
		0xDBE79F0569528915ULL,
		0xC0C001385F1B5976ULL,
		0xF65C7FAE217FDE7CULL,
		0x193C30C8C7BA3E36ULL,
		0x5B2F20D51976B1F0ULL,
		0x1DC2B3B7B9D7938BULL,
		0x25C657A7974E3E9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D079F783A010CA6ULL,
		0x64E67EA730F0F2B9ULL,
		0x2BA6AE7DF51B4026ULL,
		0x11CD828E971D29A9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB3798FA350DA78FEULL,
		0x67CF4906F7CDB9AAULL,
		0x184B93D60D6F43A4ULL,
		0xB46CF798699FD83DULL,
		0x1D2A498716A6E321ULL,
		0x99FCEC59D8DF95C2ULL,
		0xBE659EFA6F2A6213ULL,
		0x74CB7C28C072D4D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C079B0ADA03290ULL,
		0x435A5E5D28FDF47BULL,
		0x5B612D028DB9D28DULL,
		0x0AA165A4FAAB7043ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x904AB3C63F0F5CF9ULL,
		0xD57C7893716D0F54ULL,
		0x785291B500AF8B87ULL,
		0x23C97C6E2D9E181FULL,
		0x4FABFD88C600E00EULL,
		0x3C65DF4932592662ULL,
		0xC8F1C687F4E6A2E2ULL,
		0x9C1F780FC29EA1EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D25613A330A277ULL,
		0xCC9B9D70EAA8C1ECULL,
		0x4C3609E35AEBB91CULL,
		0x50754EC5112A2191ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5DBEEBA4E6DFA18CULL,
		0x10A61F24D4D1F6D5ULL,
		0xE0985A32DF5F8B55ULL,
		0x31EF75E31A2DDF91ULL,
		0xE7701D2CE0208852ULL,
		0xE6EF7A80AFA50023ULL,
		0x8E2C328B9CF372A8ULL,
		0xE4C8FE62A8B7F9B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB863404E2BB3E2C4ULL,
		0x58324E3EE74FFC29ULL,
		0xFB27DAEC2B829067ULL,
		0x27C53888257CEFECULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3C3CB75C56175703ULL,
		0xDBB138CB5897DDE0ULL,
		0xCBE2F3C116ED3422ULL,
		0x48796AE1752E8F55ULL,
		0xD9405216F85FEDECULL,
		0x68CBAF98BDAEA406ULL,
		0x44DE9CB8A8722872ULL,
		0x81EDF80F55A23D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BC8E6C53454AAF0ULL,
		0x69ED4977808436E4ULL,
		0x04EE372A17DF351EULL,
		0x11CC3D282B439DD2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x950D045C9A5D1F5EULL,
		0xB93459E4CBC3D4E1ULL,
		0xE7270626693BF49AULL,
		0x2D9324D96D1C0E32ULL,
		0x4E54C7B998F175F1ULL,
		0x1229BCB381023464ULL,
		0x62C11EA7C3EB3E7CULL,
		0x512CD17EF7881612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A2A9E94E34A2ECULL,
		0x6B665C89F2179BC5ULL,
		0x8FD1930D7E273B05ULL,
		0x3A3A3DB22B4F54EDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x089030CF2CBE9832ULL,
		0x7E113BA62953A78FULL,
		0x23FA0162323EA09EULL,
		0x5F9B331E05134593ULL,
		0xB05968DB9E19B1FFULL,
		0x3118750A2526C95BULL,
		0x7FD6558310779CE9ULL,
		0xE09F525F9CA03EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D5C168A48F0905ULL,
		0xC7B29B27AD158B2BULL,
		0x1DCAB2D6A3FFEB3BULL,
		0x37416D4F44DC9D92ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC4A5024126D5B089ULL,
		0x19CC5128EB99802BULL,
		0xBD7621AF09B0DCB3ULL,
		0xAB9986110C0EA1F8ULL,
		0x5AFD170E9C19F303ULL,
		0x66DA3CDA2CEE4348ULL,
		0x4FE71420FCED3A5EULL,
		0xFBB3B2FB4763F748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46366E6C52AFC89FULL,
		0x5E31598B96F77CE9ULL,
		0x99C31E9494E786B6ULL,
		0x0846175DA4E556B4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3046FEB8A5889E70ULL,
		0xD3A5A3FF68E3DA9FULL,
		0xB9FEB194C4250534ULL,
		0xC50C0D3EF60F0845ULL,
		0x7F85352AF375D084ULL,
		0xCD23CAC9F2F96566ULL,
		0x1588963DEEA40A45ULL,
		0x504AA15D1DA35B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0CE318C90593E3ULL,
		0x46F5BDF979E8E7D6ULL,
		0xEC44FEC6307E8B91ULL,
		0x302001115C4E8A94ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFD2810CE94B3FFDAULL,
		0xE3B4C2BFC42285F6ULL,
		0x54BF6438A7065826ULL,
		0xFC4E92D6273AB12DULL,
		0xFC73F73EDD8109B0ULL,
		0x808E8CD20602D910ULL,
		0x4862B943103661A6ULL,
		0x0250305037D86500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x765EC42375DB7020ULL,
		0xF8DDA9ECA88EBE7CULL,
		0x1366E42D0F18D6DDULL,
		0x5435BEBE7159AF38ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8B95C4A67D812044ULL,
		0xFD413382A0E71394ULL,
		0x40AFA290710E98F7ULL,
		0xEC197CBA288EB819ULL,
		0x377B6124A39C8B6DULL,
		0xE2498531DB82145CULL,
		0x7183E96AE590E892ULL,
		0x84F715CD4FDCCFC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E63016C6BDD57DULL,
		0x942AF8E936361944ULL,
		0x1A44486E84911EC5ULL,
		0x28C6B93403559000ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2B439A5AE3030544ULL,
		0xA6F248D6502B6F77ULL,
		0x625796B24B036ED6ULL,
		0x344041E8D38FC705ULL,
		0xD417EDF8F663992EULL,
		0x0F0B6F68389DF5CEULL,
		0x90CF13807795F932ULL,
		0x0DC151EF2C9DA59FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D0ED4F75CBC264ULL,
		0xE2A4D24EB79DEC2AULL,
		0xE1147BC40B466C44ULL,
		0x3EF26B6972F65CB4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA1CBFBC8CB6437A6ULL,
		0x22928A502E288DEAULL,
		0x7F05BE1DCEBDCFE5ULL,
		0x435ECEDE79588389ULL,
		0xA31AAF9F02D68FD6ULL,
		0x6E342F24D52A3697ULL,
		0x0C223BC374498828ULL,
		0xED89E6CC56BC07E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C20D63373D96AFULL,
		0x7E5189C7D26CA86CULL,
		0x4C1A9D2111A805E5ULL,
		0x05D711335941AF17ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x850C9C1B4E4EE3C8ULL,
		0xD53BCA2B99F02087ULL,
		0x79B68583EC4497BDULL,
		0xA0F2E6FC89EFA6E8ULL,
		0x73AF08D2772B1280ULL,
		0x4470236975FED84FULL,
		0x4AC0FE4B93715D35ULL,
		0x1C5B4E86E057CBFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB107EB58FEB3A373ULL,
		0xFDE10BD31DC43C52ULL,
		0x925C44BBCF186DA5ULL,
		0x56808F01D6F7EEA7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3E3FBF8201903AA8ULL,
		0xA3282E507942D740ULL,
		0x32264A05B7FF1E64ULL,
		0x8137045037C2700BULL,
		0x2D934D605F6610A3ULL,
		0xC5AF64BAC1282130ULL,
		0x22E9FA46E24115A1ULL,
		0x2E4577FE16BD19DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021D3BD02AB6B3E4ULL,
		0xFB3122092537C467ULL,
		0x60E1708B4DA85467ULL,
		0x5F86D40797D446B8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x12361F9CFCDAC320ULL,
		0x99FE788C03859719ULL,
		0x795CDCB2C38414B7ULL,
		0xFFA571A222C986B7ULL,
		0xBEC9DFAE4314A909ULL,
		0x42F58CD0C6873B60ULL,
		0x99A9CAD10D28090FULL,
		0x4991BD6C81CCCDA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642D537AF1EBDC2BULL,
		0x8A715F897B986775ULL,
		0x4890F7BAB7756CFBULL,
		0x6B478FBD67300D4CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD872D3DAD1947AB9ULL,
		0xF611FF79BE2F1772ULL,
		0x998FD977B1403F5FULL,
		0xB0857E6BAC296609ULL,
		0x031FDCE89A33CDBEULL,
		0x5C25711C508C96C3ULL,
		0xEB6EFD39049C9620ULL,
		0xCF3F2E1C342C985FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F2D9E61B5450987ULL,
		0xA3A0C9ADB30D7865ULL,
		0x8C096FEE607E882DULL,
		0x73E6569B6AC80446ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1CE7E86AEBA24ACDULL,
		0xCDEA4B602F037627ULL,
		0x655CB980DCA304B1ULL,
		0x42EC9B7357C5596FULL,
		0xBB5AF3F2A994CD89ULL,
		0xFB624080125F4BD1ULL,
		0x7740D9BA2F951FA0ULL,
		0xACD367DF1FB73C81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC681E7017B8D0ECULL,
		0x1E7FDE62E928B748ULL,
		0x18FD0B23ECC5B697ULL,
		0x6A4E06920CF854A7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB9BA016A5C80E4CAULL,
		0xC9BADD49C8FF4CF2ULL,
		0x0D22355753DC74C2ULL,
		0x7FE7D0560EE824A3ULL,
		0x6AAF88928371A693ULL,
		0x7E289020F77412F8ULL,
		0x04296CFB4780F5FCULL,
		0xE0585048EA56A011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC84729DF5FA395ULL,
		0x83C0422E843A1DD2ULL,
		0xAB4862A3F100F83DULL,
		0x4D03BB28D7C3E729ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x333AFDAC7D4C3D7FULL,
		0x83B34162616FC800ULL,
		0x5289712728B47C90ULL,
		0x13352F48AA139004ULL,
		0xAD14ABE6E2CB1BA9ULL,
		0xBA7DA18EF0F7B087ULL,
		0x2BD5CC25E76E7C9AULL,
		0x308EDCE7A8BC4423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE44C81F22772599FULL,
		0x32593C9A2633FC23ULL,
		0xD445BEC7831AFB88ULL,
		0x4869F9ABB605AD3CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xA608333CC0C0F339ULL,
		0x6F9483795ECFF341ULL,
		0xCE993AED27479C97ULL,
		0x93C1C41D03A406D0ULL,
		0x3B451096EC639FB4ULL,
		0x097AD66098770528ULL,
		0xE0C43448AA4410B9ULL,
		0x07A5A6DDC8544123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7248A9A3D78AA82AULL,
		0xD7D055D0007AB73AULL,
		0x2BB8FDB66D62180EULL,
		0x36588908C025B224ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x10DC08A0F55D7EA5ULL,
		0xD794A9E176895C1CULL,
		0xFA09BCAC54695EFFULL,
		0x7136706B158224B8ULL,
		0x472D1907A4B79A04ULL,
		0x582DADA4B9CAE668ULL,
		0xA84685163EF9161FULL,
		0x5F6F5835CBE1DDF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18DBFC3689E5D64ULL,
		0xEE5C70550AA78F96ULL,
		0xF4817DF9AD62A7A6ULL,
		0x1BBD886759091709ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8C6DC77F3C06A6C4ULL,
		0xE4591D12EB65FCF9ULL,
		0xB1BD774D756BFE5FULL,
		0xC3F9B467D4194801ULL,
		0xC549F529BBC28C01ULL,
		0x0B5BA6DE10980A85ULL,
		0x9805422D70FC5415ULL,
		0x4D6E4E6EE7056C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5682BB11AE770B2ULL,
		0x93F3E20961F78CD4ULL,
		0x42854A0C3AE0797FULL,
		0x425958DE1EE75018ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2D493EC5414EEB72ULL,
		0x5D657A1613CE295DULL,
		0x50993D8E91BD86F0ULL,
		0xB103011525C116DCULL,
		0x495D8418A03AC331ULL,
		0xDAA866FCCD70DFD0ULL,
		0x93171873F12D68E3ULL,
		0x10A47CEC28F0988FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x112ADA6D0A07E52AULL,
		0xD264C39C928F6248ULL,
		0x2606DEC45E7B18C2ULL,
		0x296D8C233977BC2CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6552FB5414C066DFULL,
		0x56C1A6AD35F0FAE8ULL,
		0x9402508E2814AE32ULL,
		0xFC79B4D00D872A8AULL,
		0xA779926CA798FD87ULL,
		0x35A1DF99B7EFB19BULL,
		0xF8415C128FB2EC03ULL,
		0xB18821F3D16304FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415EB774F5760CEBULL,
		0x4CC8D77E83855803ULL,
		0x6DB5FB4F7CA3B6ACULL,
		0x56AEBF012239E7CBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x63153E7DC735ECA2ULL,
		0xA42D9D898688D318ULL,
		0x1B81EC27CA755B94ULL,
		0x3E3F8DBFB3AFC559ULL,
		0x111EDCC94ED4C3EBULL,
		0x91DB1C12BAE7F29BULL,
		0x797FEC5F4ACF8E55ULL,
		0x7A65E8A93C8F825BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDAA045F7ACB0430ULL,
		0x4AB3C85144F6D61CULL,
		0x247F024CE5447C48ULL,
		0x696016DEB0FD1EEDULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8DC174222A9F8EA6ULL,
		0x89835E2DF37B7CC9ULL,
		0xB612F67CE5FDA7DDULL,
		0xDE08DAA7246C0C0BULL,
		0x8F0FB451326CBB56ULL,
		0x296673377786D62CULL,
		0x9C0BDB0A749246F5ULL,
		0x8D62CE0C968444ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA16382FA6C3609BULL,
		0xAEB87869B17F4766ULL,
		0xDFD57A0A33B43041ULL,
		0x5AB370857C0E3D84ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xDBEAC1DAF99CAB42ULL,
		0xADEA07257BDE2A8BULL,
		0x3096DBF5AE5154C7ULL,
		0x81917AD3EE566870ULL,
		0x5D47FA84CA90EFC9ULL,
		0x892ACABB432186FFULL,
		0x81166A58E1196499ULL,
		0x3EAD8BC29E9D799AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB499F1910B204481ULL,
		0x0A441EF172D83473ULL,
		0x59EAA52718164392ULL,
		0x4F5439B779B6755FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB97B2EE19EDE26E2ULL,
		0xFA87E86511330399ULL,
		0xAB83F3F30645DC8CULL,
		0x6D4E316377391152ULL,
		0x738FF3AFE0DB2E19ULL,
		0xEBAA77CB6EFB70FBULL,
		0xBADFB0D060F72BC0ULL,
		0xCC6A6DA70A40D4A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0D95AFCFF67031FULL,
		0xF5D5B0978A85C8ECULL,
		0x68B832E16AF65B2FULL,
		0x451A782EFCD8A284ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5EE77F206C738116ULL,
		0x1B82BECAB4B166CAULL,
		0xD11B001772DE1251ULL,
		0x385FCBAE79524948ULL,
		0x3DC7FAC858EFEB33ULL,
		0x738361CEC380470CULL,
		0xD895FD258445175EULL,
		0x8E5FB85A09BC7D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A96B8DDA0106DC6ULL,
		0x4103437BB9BBF29BULL,
		0xF75E93A9151F8A56ULL,
		0x5A95290BEB4CDAD2ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFC01BD8E6BD9430DULL,
		0x376C05A5B5125016ULL,
		0x60CD684085F1074AULL,
		0xBFBB4DAAB7E53522ULL,
		0xC5154C687E7E5713ULL,
		0x603804EAEA5EEA03ULL,
		0x4611749D1C01ED0AULL,
		0x85E9761D344582BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D2B1511329A32EAULL,
		0x7FBCC0847F290CA6ULL,
		0xC764B792AE3A36D4ULL,
		0x2062D6007A369D3AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x87846E4DFD267C76ULL,
		0x08CF41A04BE42EE8ULL,
		0x302A36CE445DE2F1ULL,
		0x0A29470CF4FC3D09ULL,
		0xB3BAF3FD9193A964ULL,
		0x8995AA9677BC1ECCULL,
		0x5B315FC04AE9BE24ULL,
		0xB0E92B3530E1B3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3544A5F19911A52AULL,
		0x750693F611D0C14BULL,
		0xB97E6D5963101C5DULL,
		0x4CC5B0F2367CF1ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC62BC158A3F9AA23ULL,
		0x2931B708676A2951ULL,
		0xD283A48442DB5BDCULL,
		0xCD3AD8A9C1178E7FULL,
		0x356DBB1FA650E019ULL,
		0xBA12E8A1B180D0F6ULL,
		0xA9749269B03C51EDULL,
		0x225243E1D1171BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB475880B53FAEEAAULL,
		0xC8003F08C0892DDDULL,
		0xF9D160346BCF8525ULL,
		0x6570EC2ECA85B4AAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x83B597AB0144EAFCULL,
		0x56474CD76D7E0A7FULL,
		0xB756CF7FDF194BD4ULL,
		0x766EF3778E4525B4ULL,
		0xD748B1CAEB72665FULL,
		0xCAE3E5FF3D87387DULL,
		0xAD1EFCA9589E6153ULL,
		0x03E46825655EDE29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x787FFBC9F4401D3CULL,
		0x741B70BA8F906D2DULL,
		0x69F050A3069BBE44ULL,
		0x0A5669049A5A1FE4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x78BB09B582F03F33ULL,
		0xB675056CD0347F9DULL,
		0xDB9C4742B7B978B4ULL,
		0x746174AD0EE142EAULL,
		0x0BA2B85CE6185C57ULL,
		0x15B7E8FBB5843527ULL,
		0xDDA6C3BF5512EAF0ULL,
		0xC56F9D80121F3E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E2677FAA8DF87EULL,
		0xEFC19AC9C1D46369ULL,
		0xC25D55A958885857ULL,
		0x42F2D5AFBF84770BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x57E1F2E6541449FEULL,
		0x2D1040369CA639F6ULL,
		0x0E06F5B725833571ULL,
		0x5E1320A89A9456BEULL,
		0x6E06BC506A1E171DULL,
		0x25B72B6570916D3AULL,
		0xE60F1783F49806B3ULL,
		0x9956252BC90B9188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE1E6D6148BBBB6ULL,
		0xC640B145523C70A2ULL,
		0x3444734D74143408ULL,
		0x20DCA528724BF110ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCA517E5126B027EBULL,
		0xED1545F63EAA8D99ULL,
		0xEE205A3E0ACDF188ULL,
		0x7448B5B03FBB5223ULL,
		0xE957B083F9D01CD7ULL,
		0x940A49149B7CB8CBULL,
		0xF28E1005F278130BULL,
		0xCC534F01372E82DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D55B1E83B94745CULL,
		0xE69C1F05532DFBDEULL,
		0xEF36BB2008A0C540ULL,
		0x48A66FDE70A2BF61ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC572D34033742BCAULL,
		0xA4C9534E4D45E85CULL,
		0x9002BA6AD280A168ULL,
		0xF67DD2122A0D6D36ULL,
		0x45BE012185901B8EULL,
		0x0F027B548346DE45ULL,
		0xB2EE4C7EC0777DB1ULL,
		0xF7B47EBB6C6509BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA6FE3A06D8486FULL,
		0xDF27A1D9C9CAE6A5ULL,
		0x1F62153B643D49B0ULL,
		0x3B48A1E4410CDF85ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2D20BA0EF971FA51ULL,
		0x9043646087282640ULL,
		0x78355D653154E267ULL,
		0xE20683DEE882E23DULL,
		0xFF8D252AB1E24308ULL,
		0x028EB14235AF0D9FULL,
		0xC401B82DC49B1720ULL,
		0x9B0011311793B629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C143E656107F0FEULL,
		0xF171B4347F242C00ULL,
		0x9076B430605A5127ULL,
		0x64091128686FEC70ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1F7A0E9CAA5C6083ULL,
		0x6B164CF2C77340FAULL,
		0x95DF141C82E28BCDULL,
		0x511E0EA21907BF9FULL,
		0xA902042D0A7EF2DBULL,
		0x0B77A4B55D6D0BE4ULL,
		0xB604588D23A14E8CULL,
		0x8A976D6EA140DF96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35C6AD4C39347010ULL,
		0x1ED8BFDEA5A304EBULL,
		0x9A84390FCCD43497ULL,
		0x63984D0E08A8EFFEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1F5D7CC357FE4B01ULL,
		0x8C4ACFE52EA89DE9ULL,
		0x5B48A3686D7DF7EFULL,
		0x98B13E8383E73135ULL,
		0x951179A7CCA30BBFULL,
		0xD9D03C5C128D8515ULL,
		0xB8F0521D65452EB2ULL,
		0x1FC1B93C04485938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF58BABB8320A19ULL,
		0xE133C58FEFAA5F1DULL,
		0xCEF4D3C575C2E67BULL,
		0x4F72BD6C26A46FA0ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5E639ED53EBBCD4CULL,
		0xC8500BE766607663ULL,
		0xC59D50A7C041C8A0ULL,
		0x148FA67E2723BAD9ULL,
		0x4ADA3C603C2EE223ULL,
		0x9925E009680069D6ULL,
		0xB44956881CFCC93EULL,
		0x7D1F760C0820D034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AC8951E2DB1613DULL,
		0x83EF4D4CD6702C32ULL,
		0x888028DC0DC7A7EBULL,
		0x273B2C475C02A2ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x307A3EDA148CF4D2ULL,
		0xC3341A10556DFDF4ULL,
		0x51C46EE0152231FDULL,
		0x77398C7EA749F293ULL,
		0x9191CD9DD80FC168ULL,
		0x1E07DE6438FDE952ULL,
		0xA4B21BEED19193A8ULL,
		0x748A7B55CB659D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC1EC44826E3ACDBULL,
		0x385F1CF0CB1EA035ULL,
		0xC434945330BE1CF2ULL,
		0x43C7DB3AD85F4461ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB00F9BD1A6BFDF21ULL,
		0x33BE9F2022E9F8D4ULL,
		0xC8CB355B1EB263E9ULL,
		0x4CB27DBEEBC12365ULL,
		0x0A366967077DC364ULL,
		0xAD801B9627EA7E16ULL,
		0x6F8B40FBBC6BDDA4ULL,
		0x6841E0FBBF42A3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3423411CC36AE246ULL,
		0xF4C2B76A0FB8B01AULL,
		0x5776DAB916B54A5AULL,
		0x4679E31D4FA5728EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE2F9908EC4D9DA30ULL,
		0xDECBAC237EFDF7E6ULL,
		0x501ECBE600E691C9ULL,
		0xC82739D027950E4CULL,
		0x77ED06323949C87EULL,
		0xA6E712BF7E998DBEULL,
		0x26A4B0C52228D36CULL,
		0xD2742710C514F732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0287C0345CDA1A4ULL,
		0xA518749049C9022CULL,
		0x0C91092912F5F3EAULL,
		0x0565064D68B1BFBEULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x02220D0917316160ULL,
		0x2C873A56B4A9E0DCULL,
		0xC790BA5E8859D93DULL,
		0xB8F2FFEF0A213A2EULL,
		0x319368DBCDA06FC3ULL,
		0x2DA0A25B5C29EA63ULL,
		0x45926A2A448EF68BULL,
		0x26AC34ABD4DBC1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E039DA99D01F936ULL,
		0xF25F53E662E2AB95ULL,
		0x1B4C7CA4B59271E5ULL,
		0x7682D170A2BFFA59ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEBB19C5219638EE0ULL,
		0x55E9384152434CF2ULL,
		0xF7A140DE6EF905DCULL,
		0xE6696CFB1525A6FFULL,
		0xE7314A46A64EA066ULL,
		0xE13F0A3071416948ULL,
		0x48BD39F142A5A408ULL,
		0x489470CEC03415E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D02A2CEC90F5FB9ULL,
		0xC544BB7221F8EDC5ULL,
		0xC3B7DAAE538F5F2DULL,
		0x2C722BAB9CE0E6BCULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x49280126975039BDULL,
		0xD3DCBC4DAAE5EFC7ULL,
		0xD917194FF4809D53ULL,
		0x1B1A6DF175D6674DULL,
		0xF7803660E7698B9CULL,
		0x168EED9F45F29659ULL,
		0xD11360A48C664E27ULL,
		0x1908A1CD1737F9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06301388F0FAF36AULL,
		0x2D1401F20CE84122ULL,
		0xE1F771BCCBB03721ULL,
		0x52627262E825809AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x2A0D7F4BECB99A02ULL,
		0x7082629C1CD7D309ULL,
		0x6EFCC1D7D3B62B74ULL,
		0x0C4FFD212ED124E7ULL,
		0x4C661A03265F94A3ULL,
		0xC4F32EF8D837C0C9ULL,
		0x4790D51027F2476CULL,
		0xBC46D37E12AEC05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81355BC39EE9AE49ULL,
		0xAC9B5B8C351E70EAULL,
		0x0E7C623DC1ACC599ULL,
		0x7ED361D7F4C1B30CULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6BCFF4E27793FF9AULL,
		0x4591F78C8E2EE8F0ULL,
		0x40055B43EB7A085DULL,
		0x748AC53F82AE704EULL,
		0x947FBC137DC2B6F2ULL,
		0x0C0CCEAB4475B020ULL,
		0x960037016D3F069BULL,
		0xFEA2FBFF64789D6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76C5DFC7227B2D2AULL,
		0x0F78A4F8B7A70DC6ULL,
		0x840D857A22D50361ULL,
		0x40BC2D286C95CEB8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xD1995752F07EFADAULL,
		0xA479699B5360AADAULL,
		0x0E33D485531E6398ULL,
		0x7D2113A8958494E7ULL,
		0xBA7803AE752B588BULL,
		0x4147D559BB2F18BCULL,
		0x522C71C336438516ULL,
		0x6F974B0FBD083A92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F69E33854EE2202ULL,
		0x552314ED1C5E56DEULL,
		0x40CCB77F612424E6ULL,
		0x0D9637FEA4BD469FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6C1ACF2257AFBC10ULL,
		0xFFCF2308FF18EAE0ULL,
		0x1FA6E7CB72728E27ULL,
		0xD7864A11FE5BDFE7ULL,
		0x3D353C56D6AC4964ULL,
		0xB04F45AD9947DBC8ULL,
		0x1A96151E6FD2D256ULL,
		0xE1B4392C5F85E822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8201C4063542A5F4ULL,
		0x2B937ACDBFC38A99ULL,
		0x11EE0A500BBDC706ULL,
		0x5846C6A82C3C54F7ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x1766DD8AA9D99556ULL,
		0x3EDF61A56E8ADE06ULL,
		0x3C8C1B692C288E3BULL,
		0x5A9CFAF96327DA90ULL,
		0x4F5630197FE92F87ULL,
		0x486899DE56238AADULL,
		0x0FCB777A8ABB52DAULL,
		0x52601EF80392A484ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE320153A676A53BULL,
		0xFE6638A637D173BFULL,
		0x94BFD799C3F6DAA1ULL,
		0x14E193C9EAEC462AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xCC8CA066AD308E6EULL,
		0x65D85B26617FDD2AULL,
		0x2E641882B85FF05AULL,
		0xAF020AC15B8F22D3ULL,
		0x50DFF9D413879788ULL,
		0xB8D7F1E0187DE252ULL,
		0x5A65B8DFE973D04FULL,
		0x923B19616381EC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDCBB5E193510FE2ULL,
		0xD5E6426A042F7562ULL,
		0x997D89BF5F90DC2FULL,
		0x63C7CF3620D832E4ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x24099C71DB812A24ULL,
		0xF179650BDE964BD7ULL,
		0x5268B1D20075D672ULL,
		0x7FECDEADAED250A6ULL,
		0x42994103F58EA09EULL,
		0x452C1DBE9A6F1C0BULL,
		0x9CB370B8E90C4974ULL,
		0x02A02525ABA5620CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C943084EAD01ABULL,
		0x3605CF56CB147583ULL,
		0x950B6D449848BDB5ULL,
		0x63B26245295EDE85ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xF066314620087740ULL,
		0x954A8FF72DD44987ULL,
		0x83368977568CF32DULL,
		0x0A39966E8E4AA3C4ULL,
		0xE8EA251293F182EBULL,
		0xA58E3B41DF07D79FULL,
		0x5D3B7B32C2AD050CULL,
		0x4B3318D6FEC3F690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8327B20815E1E7C4ULL,
		0x28675BBE48FE4B44ULL,
		0x5A0AD3003C3BB30EULL,
		0x33CF46585F613D32ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xC0C5D077224B2528ULL,
		0x87790DA3D53C6489ULL,
		0x5777ABF47D0EBD65ULL,
		0x9D7ECC55F7C7F781ULL,
		0xC4B51C4F6BDA47F5ULL,
		0xFE4BA6D2CA168819ULL,
		0x6C3AED9C1BD640F0ULL,
		0x640E6AF3169C62F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A8044124B1D5C0ULL,
		0x46B3D0EDD494985CULL,
		0x6836F1209EDC612BULL,
		0x77A2AC6B52FEA83BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7EA11E4EAD739A55ULL,
		0xC454DAC1ADBC534BULL,
		0x18898180C1D46C21ULL,
		0x867BB73C3B9E333FULL,
		0xD4FF873107BF3693ULL,
		0xFB888B5743FC5138ULL,
		0x2ACDC4541583517BULL,
		0xE45B06F71DF31625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C8F2F95D3D5B933ULL,
		0x1A9989B5C53061BBULL,
		0x7314A5FBF3528489ULL,
		0x6BFEBFEAADB37CC3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x411940BF04E67A11ULL,
		0x9AB6FBB53EE6F15CULL,
		0x306E1902218453D3ULL,
		0x485F76AA51ED8E21ULL,
		0xA0A7101451D48305ULL,
		0xE17EAC931BB87BB6ULL,
		0xCF4B42857903D2E1ULL,
		0x2368D2F80DBEB442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19E5A3C32A71EDA0ULL,
		0x1384998B5C494E78ULL,
		0xF599F8D21815A15BULL,
		0x09EEC77C5C3C500BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x79B716E325DF90C4ULL,
		0x81E40ABFF4A947E9ULL,
		0x4FF8241DCF3CCA2BULL,
		0x71F11C018CE92E32ULL,
		0x7F8FDB9FFEF6DFADULL,
		0x018049DF872D42CEULL,
		0x69C9464966789214ULL,
		0x01443A808757167CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6911B0A2FE84C485ULL,
		0xBAEF01EE05613290ULL,
		0x03D8930305227923ULL,
		0x2211CB15A3D684AAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3265E00949936AA1ULL,
		0x8E64579375DABA3DULL,
		0x15A9ECADD7DC5BDEULL,
		0x2A85705E0936C5ACULL,
		0xC936F1768B0CEA93ULL,
		0x1E104AE18BA336D7ULL,
		0xB882EDBEF176ACDDULL,
		0xD6B251E60DFC3A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108DB7A1ED7E4133ULL,
		0x04CF750E3014DE45ULL,
		0x79193705AF7A04B1ULL,
		0x08FD98841CA76AFBULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x082919BDF12D29EEULL,
		0x874CAD78DA2E122BULL,
		0xFDAA25579D3B047AULL,
		0x57722DDE0DB39893ULL,
		0x566FB57B30DFFDC0ULL,
		0x9E4DB9407B887298ULL,
		0x5D406AD5A19398F2ULL,
		0xBCFC82982A297425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBE0A07326CD896ULL,
		0x06D62D0B306F14C7ULL,
		0xD53A010D9923B87EULL,
		0x64ED90744FDAD61FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8DBC7551134D5A71ULL,
		0x7C2A6AA9E8668FB8ULL,
		0xD09BD3853E7B8682ULL,
		0xB94C29958F94BEB3ULL,
		0xEAFD97E312232407ULL,
		0x2276C2B47F46DC48ULL,
		0x749C7B335B12AC05ULL,
		0x2074FBF3F00DDBACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F610105C484B44CULL,
		0x99CB5174CCEB428BULL,
		0x1FD61D24C3410F45ULL,
		0x0AA98FCB31A35A4DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x705BC628071E617AULL,
		0xD0737CF0AE1B6B27ULL,
		0xC190E26374B07D33ULL,
		0x1801B3BA2B618D1EULL,
		0x47FB972B40703F4EULL,
		0xEA5F786B24462434ULL,
		0xE43428E15E90EA60ULL,
		0xB3C6A6525B794CB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FB4369397C7CAFDULL,
		0x9A9F5CD81084CAEAULL,
		0xA14EF3D77E334796ULL,
		0x477E63F3BF62F06AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x50EF10DF012978DEULL,
		0xC2D9F7FECB7BD901ULL,
		0x24792F4563954A3BULL,
		0xC296EF1CF8CAB3AFULL,
		0x0C055416477F8B11ULL,
		0xA0084F7962479143ULL,
		0x34597494F5E03C01ULL,
		0x1E2BB805CDDED42EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19B98C2D9E181E22ULL,
		0x8415C403621B68F5ULL,
		0xE9C07D61E2DE3279ULL,
		0x3D143FF987DE328AULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x40788005420F5FABULL,
		0x199C9D04F9DDE1FBULL,
		0xE6B57F4A5D9DD2BFULL,
		0x35DA40226DE01851ULL,
		0xD694343B116A9E78ULL,
		0xFFCCEFDDE2E6227EULL,
		0x6A5D970B91153C13ULL,
		0x8EB21C9551495E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7840C9D7E2E899ULL,
		0x120837F4A80700CFULL,
		0xB099EB01E6C4BDB7ULL,
		0x644A7E4C7EC416C5ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x8C780EAA2344FDB3ULL,
		0x2520A848DD01C0A7ULL,
		0x1A8766FE9C3635FFULL,
		0xF14BAE9503FF1B3FULL,
		0x7A55EF5EE0B08FCCULL,
		0xBF8D7178230859EDULL,
		0xC8622F6358523596ULL,
		0x7C411A8EE1919C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB53996BF7D7A58CDULL,
		0x941F801E103F19E7ULL,
		0xD91A6FBDB86A2A5FULL,
		0x62F59FCA7F9C5AAAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB1AE5EA1EA0416DFULL,
		0xF5AAC6CF9A3523C6ULL,
		0x8EDC458CA8AB3126ULL,
		0x1FE37B628DF17834ULL,
		0x35E628E2DA8F5657ULL,
		0xFFCEBD6D2B5D6506ULL,
		0x5A79B58FE9DCF42EULL,
		0x09A025FE4E5DEE5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D8704E5B4AE802ULL,
		0xEE5AE5040A1222B2ULL,
		0xFCED38E95F777020ULL,
		0x0DA91F222FE2D9E9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x96BA0D0B6AA004E2ULL,
		0x1482F25E6D87A752ULL,
		0xBD3DE8FAF487D373ULL,
		0x45B8798565553BD5ULL,
		0x90A4C884C888F4BFULL,
		0xA5F51E67C461D210ULL,
		0x9130A829E47E1873ULL,
		0x649E9A2DAF88BBB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F2FD0C12EF45B76ULL,
		0xB6E575C5940CD5C8ULL,
		0x4A76DF32DF3F749DULL,
		0x35435C4D73A11831ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7A6DE91E8D754147ULL,
		0x8422159842592CA4ULL,
		0xBF40F58FC54CB8F5ULL,
		0x048737A01C060D86ULL,
		0x2CE8C626DCB74941ULL,
		0x7F14991E6516BAD7ULL,
		0x1CA19CE94A710E31ULL,
		0x766CB12A893BE21FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24FB52E350AA2386ULL,
		0x6130D01B43B8E895ULL,
		0xFF3E4030D214D44EULL,
		0x18A983F07AE99E24ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x39B0284DBDD20DDEULL,
		0xB72C800200373A57ULL,
		0xC298B9B2896BEE7EULL,
		0xEAF2CB539E9B1DD1ULL,
		0x97DE539FFD4C8A33ULL,
		0x3C6E749E3F6DE921ULL,
		0x77602CEC63A10545ULL,
		0xB9B0690E956E5E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B0920D572E9598ULL,
		0xAF91CF7F6A87D553ULL,
		0x7ADF64C95352B6C5ULL,
		0x7B22637DCCFD1F8BULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x965E8F0BB374C3EFULL,
		0xA0CC640FE9221353ULL,
		0x384670E1D749F526ULL,
		0xA6E7506B79850CCFULL,
		0x2E196D95AD81B3A9ULL,
		0xBDC35E7D374C046AULL,
		0xD3808F7C1E6AE48EULL,
		0xCA3A1A83BDB91768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E24D34374B5738CULL,
		0xCBCC6AA61E6ABB16ULL,
		0x9D5BBD4E5B27E256ULL,
		0x2B873FF9A2FE865EULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x26538D14887E66DBULL,
		0xCEA3274021A3CAAAULL,
		0xEED56F0200720930ULL,
		0xC7CF44C04E955582ULL,
		0xA3AB6C3EB071AA40ULL,
		0x8806D3CB47CFEF2DULL,
		0x3D7D9971A67ED69CULL,
		0xDE10B5220D3443A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C59E62B95DB154ULL,
		0xFFA6976CCA814B70ULL,
		0x0F7A35E0B745E46CULL,
		0x3E4A27CE44576030ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x438AE607C0F28E66ULL,
		0x415F77C9FC7C6D05ULL,
		0xA71A72653B4077CCULL,
		0xD804A94D02E3D3E4ULL,
		0xE6F7FC5F91BE63D6ULL,
		0x7BF0EC36D5EDA64DULL,
		0xA85E00D82E06555FULL,
		0x3D93631A62F993ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C5A5C3763356193ULL,
		0xA72287EDBDC31C95ULL,
		0xA50E927C103123F8ULL,
		0x7BE55F37B3EFBF85ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xEE74C3D257D32A89ULL,
		0x16C4C73CD40DA3A2ULL,
		0x5E4B795D6A9B80ADULL,
		0x572D19AF88EC84A7ULL,
		0xC82308E6D52EDB24ULL,
		0xF0F079AFF0D6D7CEULL,
		0xA661498B8A24A3FBULL,
		0x277DBFBC90E9E029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A81615FCC7B2C5ULL,
		0xDA76D75A93F1AC54ULL,
		0x10BC6413EC0BD812ULL,
		0x33D78FAD0BA3CAD6ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAEC2AA6140916498ULL,
		0x182786F1D0D136AEULL,
		0x53D71ABAEDC3A8D5ULL,
		0x5524FAA54EA5369AULL,
		0x922AF57F394931CDULL,
		0xE0CC9B4E3E37D14DULL,
		0xFA27853033D393C7ULL,
		0x077CC7028F7CF30FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61231B43C16EC92CULL,
		0x7686948F0D1A4832ULL,
		0x75B4DFE29F2B9880ULL,
		0x71AA85069B314AF9ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5D3F206FCAD3EE76ULL,
		0xFB828FEF6A871738ULL,
		0x525D5FAC37C8D930ULL,
		0x2CC1A7D9F807FD24ULL,
		0x282F185EBA85D0A5ULL,
		0x7F2425D977620354ULL,
		0x32829AE39AAC7F9CULL,
		0x268B702566F1A7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543CBE7F7AB0E7C5ULL,
		0xDAE02E37231395B6ULL,
		0xD1C05D752D63CA6BULL,
		0x65744D673FE6E35FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x3A765F3EC0655F2EULL,
		0xD7C22ED45A568C0AULL,
		0x8EF52A5232512F1EULL,
		0x49DF19D0048761A2ULL,
		0x9094CBD0D9E3AC12ULL,
		0xE8F487EC2AC6BFBBULL,
		0x9C068282C3C81BF1ULL,
		0x0BA9DF2491F32138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB08CA03F1830EA26ULL,
		0x6C0E5BE2B3D701E1ULL,
		0xB7EC89BB42055507ULL,
		0x0516393DAE9E5009ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x6E866592944360DDULL,
		0x4B7097FB2B1753F4ULL,
		0xB6276F39ACD8CFA7ULL,
		0x1984E8D40A6204ABULL,
		0xD31B3AC4B26B24B7ULL,
		0x88BE02D3AB1AEB02ULL,
		0x40AE939AAD1E07D6ULL,
		0x3D6FC994B226699EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4911EC5102AD55DULL,
		0x97A503669116365FULL,
		0x5011582F5F4DF97FULL,
		0x381CD4E67C15B229ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x286543E851E89572ULL,
		0x10204431CFD1E7C0ULL,
		0x529F32CD4488B764ULL,
		0x98BCAF357F30D471ULL,
		0xA96C5160DBD013EBULL,
		0x783792570B38428EULL,
		0xA29816F4F971FCDBULL,
		0x38171AEBCCA0D829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E795848F2CB8B97ULL,
		0xE85FFD1D7A2BC8EDULL,
		0x75329B2A4B743FF7ULL,
		0x6C2AAE35DF10EA9FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x160724A80348EDE1ULL,
		0xE6F5C9CECDF44C7DULL,
		0x1CB3984A370135DDULL,
		0x4504E86EB14DFCF4ULL,
		0x2D0D89A18082B7DDULL,
		0x9673007524E968DDULL,
		0xF4250838A488D4EDULL,
		0x33000BFA76C0874EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC60992A116B039CCULL,
		0x3C07DB324899DD51ULL,
		0x5A32D0B2A350D122ULL,
		0x5706AF9C51E212ACULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x567C4CF1D4EE0022ULL,
		0x7A3025C8F46BEDE3ULL,
		0x9E246A6BC57A7A9CULL,
		0x0CD34E04C4B5BB19ULL,
		0xB5A6FCD718951DEBULL,
		0x3DC9182942E40CD8ULL,
		0xD46A28620BD0DBC7ULL,
		0x0CDDC2E0A9D9735AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D45D4DF7B10713DULL,
		0xA609BBE8E245D60EULL,
		0x25E668F9867B1A2FULL,
		0x75BE3B5DFAFCDA95ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE6C7F0848B3DFBFEULL,
		0x8BE7EA98A8BE159EULL,
		0x39407BE9CF4FE082ULL,
		0xDBF2E07A3935EAFAULL,
		0x41097034DBC4BC31ULL,
		0xCB70209E3F9A97BFULL,
		0xC867921B91EF011AULL,
		0x2D699E35C58FE3CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2E985D2A71EC61ULL,
		0xBE8CC21619B09C02ULL,
		0xF8A02C0178CA0A7CULL,
		0x19A05C758C91BB5FULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xAB47AFA77F624BA5ULL,
		0x269A5F446C75119FULL,
		0x23BBFF48C66F24E7ULL,
		0x624EAE6AE1080837ULL,
		0xA466EE92699C1D9CULL,
		0xA6E843A5E937D0CFULL,
		0xE0661039E00E25E0ULL,
		0x30575EA78E9038B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128F19632C8EB1EAULL,
		0xED1469E50ABE1072ULL,
		0x72E267E00888C43FULL,
		0x0F46BB4A0A707278ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xBC28742012850CA9ULL,
		0x690378F6B965B2DAULL,
		0x1C54889CEE2E34F7ULL,
		0xD55E0AAFED167FECULL,
		0x42ADAC2817AC3360ULL,
		0x491C69BA915CEDE1ULL,
		0xCDC90E4B795BD150ULL,
		0x511934FEF9A5CE25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F002139614AEC4ULL,
		0x433B2AA84D31024AULL,
		0xA82CA7D0F1CF46E2ULL,
		0x5F1BE888FBB31988ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xB595E2D3217212FEULL,
		0xDB4A4E51938D4C95ULL,
		0xE07A7817AC46A7DFULL,
		0x6EE1C2F6FDF8A1B2ULL,
		0x56AE2CC05A296476ULL,
		0xD5D37FAD2C320368ULL,
		0x9BB0916BBB38A8B2ULL,
		0xB34F2CFA9BF97E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9370876083970084ULL,
		0x98AF420622F9CE12ULL,
		0xFCB00E1576AFB26BULL,
		0x0CA2702A2501602DULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xFA296CFA5C1DFC2DULL,
		0x4CDDEE43DE1DA21EULL,
		0xD4D6C6EBDD85B1ADULL,
		0x9930328A38E94289ULL,
		0x9ED54B402427387EULL,
		0x1F95FAA6ADA0F20CULL,
		0x6A71C71B7D1D1CAAULL,
		0x3D0B69D7FFCBDC3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DD2987FB9F0604AULL,
		0xFD212301A4018FFEULL,
		0xA1BA55006FD7F2EDULL,
		0x28E1E89A312BF3F3ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x7B7D6C63F6C4B432ULL,
		0xE210181B28FE9AC7ULL,
		0x22D56C8FFFCEBC22ULL,
		0x1CC8FDB40F8E97E4ULL,
		0x53E6D88E72EF0715ULL,
		0xAF76BA65AF599F31ULL,
		0x2DA8126FF3A57338ULL,
		0x8032926D1AA766DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC19189063FC422ULL,
		0xEDAFC333304C3C19ULL,
		0xE9C8292E2A5DD68CULL,
		0x244AB9E60467DCB8ULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0x5E0085EFEF88172CULL,
		0xD019C7B366C46BF2ULL,
		0x5EE3B02B48B3CA0BULL,
		0x03377BCE7A2E9548ULL,
		0x56EB0EF825D7EA3CULL,
		0x190613C4F4293FBAULL,
		0xA259481C510327AEULL,
		0x931502DC2FDBCCC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E4BEC58D94DF45ULL,
		0x8700B6EFA4E3E19BULL,
		0x7824645F4F2BADE3ULL,
		0x5855E87D94CEFAEAULL,
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
	curve25519_key_compute_modulo(&k1);
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
		0xE63BA21C74B881A7ULL,
		0xE14CD7C91DEFC553ULL,
		0xDFDDD967A0E4F765ULL,
		0xB9EE4F7EBD8D11EBULL,
		0xAC707D9D31E558AEULL,
		0x5D2C185EEFA8A3CBULL,
		0x64106C65CD2C801AULL,
		0xD15DF6106178FE9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EEE4771DCC3B028ULL,
		0xB5D875E0B0F8158FULL,
		0xBA4DF084157FFB4FULL,
		0x4DE0D5ED3582DD94ULL,
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
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0289F3611E93DF0FULL,
		0x0AB94EB8B175783DULL,
		0x170EC4224D145CF4ULL,
		0x637236F032E7FE4EULL,
		0xC9324BE5DE0454BEULL,
		0x44393612B59E8D98ULL,
		0xC06554FD138053A8ULL,
		0x716AD2FDDC71A8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0013780133875C9ULL,
		0x2B37557FA6FE7CEAULL,
		0xA61961B33220C7EEULL,
		0x394D889EEBC706E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BA24271CF402833ULL,
		0xCADAA610F532F742ULL,
		0xCFF6A947AC70601AULL,
		0x18B880DA916C8999ULL,
		0x4A25D4D84DEF7A72ULL,
		0x08233D58386FE417ULL,
		0xE9AFC5514AD16705ULL,
		0x3F303EDE5ACEB652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3FDA8D60CC5675ULL,
		0x0015C12955CED2B7ULL,
		0x800DF358C785AADAULL,
		0x79E1D5DC0C1B99E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE19806E9EE7253ULL,
		0xBB506036CFC60E5EULL,
		0x8B5CEDFE89E03106ULL,
		0x73349CE1CAFE1211ULL,
		0x4475D448EA92D625ULL,
		0xF3AB3047F9706A43ULL,
		0xE400E2666E42D331ULL,
		0x5BED85084DD721F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345F1AD9BBBA3DE5ULL,
		0xE6B98AE5D675D45AULL,
		0x637E8932E7CB8A70ULL,
		0x18765C1D58ED1CDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB12C9EAC4441F191ULL,
		0x19BB55911043CE7CULL,
		0xF56E906688E6BC25ULL,
		0x3D5F6FE6BC3C8F54ULL,
		0xC62E963715E2C280ULL,
		0xAC8C8F2E5A9A51CFULL,
		0xEA4612AABD0F4FFBULL,
		0xE6B84141C446EECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C16EAD983EAD59DULL,
		0xB6989672832BF354ULL,
		0xBBD555BE992C9B80ULL,
		0x7CB91FA9DEC401E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8326D6319FEBBF8EULL,
		0x18D86C8B3B314630ULL,
		0xECA3C4CA2E4A12E6ULL,
		0xA484E7F7036ED791ULL,
		0x0C3336045E44CF63ULL,
		0x5AB55243940BDDBCULL,
		0x7832D37B6F90E771ULL,
		0xA5C4FBAA4BB363C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C0DAD79E228BF6ULL,
		0x8FC2A29334F4301AULL,
		0xC42F291CBDCC6DB9ULL,
		0x3FC2433E400FA649ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BA8043EEFA13A33ULL,
		0xE780546A5C3C6E02ULL,
		0x8736080C5EEA6CC9ULL,
		0xAFC2FB3A9B7D289EULL,
		0x7821EC72A4A37FB2ULL,
		0x50F70DB14E5CC207ULL,
		0x7CBE64E677E046C6ULL,
		0xE6D1584310FD83D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B11D435FE633BEULL,
		0xEC2C5CBBFE013B1EULL,
		0x0B7902422A34EE39ULL,
		0x72D6152F211EBA4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB838F976BDC2BB5ULL,
		0xE3C0DAEB226F1CEFULL,
		0x06CF54EEA44C9E3EULL,
		0xAC153EEA4E0A3832ULL,
		0x99256694F5414527ULL,
		0x3E56DED15E33D690ULL,
		0x88F74688C83CACCAULL,
		0x3E065F74DAFFE34DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9710C9B3D38C70E8ULL,
		0x24A5EDFF1E20F666ULL,
		0x5B83CD3C5D4E4444ULL,
		0x61076A42D005F5B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6F8606A5DF3D49ULL,
		0x49C607552B1B606CULL,
		0x5FE5C4D685ECCAC1ULL,
		0xEB3EED42629F2412ULL,
		0x245586857C7759E5ULL,
		0xE81006A69E68EA05ULL,
		0xFBCE33EE210E02A3ULL,
		0x122F9971302E0385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F217DD71F9695CCULL,
		0xBC270410AEAE1D30ULL,
		0xC0817A2F6E012F15ULL,
		0x1E4FB40F8973A9F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F216034C946BFB6ULL,
		0x1718083C0A41A188ULL,
		0x4D1349430723CC9AULL,
		0x6076B62088E6FDF1ULL,
		0x6F165AE77D266FFEULL,
		0x7C5DD990CB76B173ULL,
		0x84C0EE5B0890E933ULL,
		0xE0BE8F420D9871B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C72DE915CFB6463ULL,
		0x8D0653BA3DDFF8AAULL,
		0x01B6AAC64CA66A3EULL,
		0x3CBFF9EE8D87DE97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0B0FF05746A2722ULL,
		0xB901FEFFE2E4F7CDULL,
		0xF8866DE7E28D877FULL,
		0x8B690B7537E0008DULL,
		0x4563FD028E92BBB9ULL,
		0xA10232FC9EEAA106ULL,
		0xE04989DFD3B5DC80ULL,
		0xF48F78CD2B5A62AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD888D669E320A03ULL,
		0x9F55907F79B8DEBBULL,
		0x4370E5214F8C4297ULL,
		0x58B4F9E9A74AA5EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91C993D3905C86C2ULL,
		0x3C0D38B3B5AB63D6ULL,
		0x1894D6CAC4634336ULL,
		0x4AA8E41438A6EFDCULL,
		0xE9EC893CFE712432ULL,
		0xD2A42D5C9C50E87BULL,
		0x8C5099AECF4620A6ULL,
		0xD846676469A8F83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE5F2E15527EAEEULL,
		0x806BF472E9ADE63BULL,
		0xEC8BA6BD88CC1BF9ULL,
		0x651C3CFBE7BBC88CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18E7222D3CF2F424ULL,
		0x595E1E5A29EE1EFFULL,
		0x7DCC41E97BE0D755ULL,
		0x2B3E189991CF768FULL,
		0xBC2E4BC9A684CE35ULL,
		0xB673AE5BB0CE4EA8ULL,
		0xFB06303134BDF752ULL,
		0x7A9F6C680B05930EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C6621BF4A992AEULL,
		0x6E89FFF6688DCC0BULL,
		0xC0B7693750138D9CULL,
		0x5EE8300B34A34AC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D12DB20157AFCC4ULL,
		0xB402C1484C37E953ULL,
		0x9B25E6E956361A68ULL,
		0x9BC5BDFFD9DAA6D7ULL,
		0x6C093A5A8B0C8633ULL,
		0xE994D6CEECB5DC50ULL,
		0xED0879CF625FA76AULL,
		0x9EB08D08422F489FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56718490B956EBE6ULL,
		0x601AA3FF6F369D43ULL,
		0xCA67FBB1F068F447ULL,
		0x29FAAD39ACDF6E94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEB148B2079FDA1FULL,
		0xB788F8CD23D64801ULL,
		0x8505E0E7255B3529ULL,
		0xF41FCBF5D9062F0EULL,
		0x5CE74C91160DF011ULL,
		0x360125ABE031C33DULL,
		0xADE3B4B535A952E3ULL,
		0xE326B145D4657142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8906A63B4DB181C4ULL,
		0xBBB490506B39431DULL,
		0x54D2B3CD1C7D82E3ULL,
		0x2BDE1C536014FEF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD60A88CC13501D78ULL,
		0x26CE92BDB7E9DACCULL,
		0xB0951191FEA276D8ULL,
		0x92432EB0BDCB10CEULL,
		0x8977CC09B4AE5CCCULL,
		0xA45606C8A07AB2ECULL,
		0x5C2D17FEE39C37C9ULL,
		0x99CD8643E9F66EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD2D23CE531E72AULL,
		0x8B9394858A2069E9ULL,
		0x5F46A167C7D2BEC6ULL,
		0x66C51CC5785F80EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92A0192253F9DE89ULL,
		0xE038C35D0BD2DCD3ULL,
		0x26E0EB1FEABB0A91ULL,
		0xD6A7881644298846ULL,
		0x0D363A91FA1BD950ULL,
		0xC93E2A07BA9FD697ULL,
		0xD9A31258AE554AF0ULL,
		0x020BA3D5117EDC40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88ACCACD741C208FULL,
		0xBF730082BF8CB73FULL,
		0x7515A449CB642A4FULL,
		0x2461D9B6DCFE39E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC113B7898F070057ULL,
		0x23AF590CD0E1E4F1ULL,
		0xA32CE8C047CB9491ULL,
		0xD9957D2896D024D2ULL,
		0xAB66E9DF45D45D18ULL,
		0xE9CD50D78C06C7E2ULL,
		0xAB0CD0F9D57D45C2ULL,
		0xEFC739BC7391B34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x325A6EADEC8CD73FULL,
		0xD829590B99E39097ULL,
		0x0713EDD5F863EF7FULL,
		0x71280F21BE70C20EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75EADD21CC612025ULL,
		0x9663F3F9A6519C58ULL,
		0x2BD171D8CCAF2F56ULL,
		0xEDB7C37F818A8A61ULL,
		0x0DABC7FC48B8154CULL,
		0xE9CB61756D7671A8ULL,
		0x7DB5F1A48185F8AFULL,
		0x0F7E03A33C23AA00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6A8C9497B449DFULL,
		0x4A946B67E5E67B4AULL,
		0xD4D3504406921973ULL,
		0x3A6C4DBA6ED5C673ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF824734CD4F672CDULL,
		0xE381588E468A824CULL,
		0xDF4EAEE52E7E70C1ULL,
		0x6B1D70CC0133F1F1ULL,
		0x34AE3A619AE0FAD4ULL,
		0xBF5F7033C542A82BULL,
		0xB6A5D43687F65C1CULL,
		0xFE81FAE06F8D0515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA011DC9D25BB3E9ULL,
		0x4BAC003D8E6F78B6ULL,
		0xFBEC2EFD5D101D06ULL,
		0x3268AE1C9022B32AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70F931F714652677ULL,
		0x2AAFE46237C70CC7ULL,
		0x92A6FD5FF15CFE40ULL,
		0x6DFBB7F4D9B7AF99ULL,
		0xD68FF41FF4D6E289ULL,
		0xDFC773B4C94E9E1BULL,
		0x96BF7D35C7034369ULL,
		0x022460AEB27F4E22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A576EB56C4AC6E0ULL,
		0x624B1138197284E9ULL,
		0xF313935B7BD8FFF7ULL,
		0x3F6211E3589D48BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8ABAD5094491CFEAULL,
		0x1E7DEBA7B5A86783ULL,
		0x344B6CF82F9964A0ULL,
		0x5619ABC67AC2E18BULL,
		0xF6825E8CF3102B19ULL,
		0xEC5EA2A3997DEA76ULL,
		0x7733941ACCF24B2FULL,
		0x17A2884F95D8C174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2214DDF558F83625ULL,
		0x348A0FF07E59352CULL,
		0xE5F368F29B908DBDULL,
		0x5839E796B8EF98D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC79EE441F468124ULL,
		0xD76D6C733E783856ULL,
		0x65872C51D0EFF274ULL,
		0x3866E6C4C3E5F384ULL,
		0xAC20081BFC0AAE0EULL,
		0x3D3D83BFF76A377BULL,
		0x928AD188D615ADCBULL,
		0x5199552B6FDE9ACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893B226B88DC5900ULL,
		0xEE8EFAF1F83C74B2ULL,
		0x262246A19827BE9FULL,
		0x55298B375EF0EE54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D3CBFE989A4909ULL,
		0xB8F1DA55CE65782CULL,
		0x1C12CDFBC5C9E2D6ULL,
		0x6D40B99EEAA6FCBCULL,
		0xE9E2B4E285A0E11EULL,
		0x67CA73AA8ACEC56BULL,
		0x0B6C007C3CDA4AB3ULL,
		0xAF79F77E48DCAA46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7AA59E6E7BB759ULL,
		0x20FF05A66916C631ULL,
		0xCE1AE06CCE30F978ULL,
		0x795B765DBB684321ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4968CE00A0E5546ULL,
		0x05DDD68A41521276ULL,
		0xEA87839B896657D7ULL,
		0x1DF1F657E003A2C4ULL,
		0xFA551ADDC86CC52AULL,
		0x66E49D9DBFF2B513ULL,
		0x56FA55CBD8174E96ULL,
		0x064FABE9E1CCC13EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D3889CBCA3399A8ULL,
		0x4BCD3BF4BF58F36EULL,
		0xD3B03FDD9CDC022AULL,
		0x0DC57B0F64685205ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x444EDCA2233B78E2ULL,
		0x3CABF8249E974B7EULL,
		0x413275E01B6ED2D4ULL,
		0xF6A0958971942523ULL,
		0xAD3F15DAB91CCB12ULL,
		0xAAF147028CF3F97CULL,
		0x00EA933D55E6E2EBULL,
		0x8F7A3B01B3909676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBAC1B199D81A0D2ULL,
		0x9C7C82858ACE53FFULL,
		0x640450FADBB481CFULL,
		0x42C557CA190A7AA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51DAE1E3894F4B79ULL,
		0x3B5EAF2EB0E99141ULL,
		0x98D36F2B6C102304ULL,
		0x0606E367C934F474ULL,
		0x565ABC65DCD9008FULL,
		0x9F95812A6235C69AULL,
		0xD8DC8B2DD108FE28ULL,
		0xC25FC5F8B6528619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2352D902518564EEULL,
		0xEB8FDB7944E50C2AULL,
		0xC99017F87365DD0BULL,
		0x603E4652D974DC4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7E9E0BA2952B1FCULL,
		0xA1222097A4FD1F62ULL,
		0xC3847A3E21031D13ULL,
		0xE625E3D9F0061C5AULL,
		0xC8C66DDC09E73DAAULL,
		0xAF252F314FB1824AULL,
		0xE652D8021FCA34ABULL,
		0x2B5093C6440362CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB55E2F63A1A5DA42ULL,
		0xA0A721E97956767CULL,
		0xF3D08A8ED906EE8FULL,
		0x541BD3480886C6C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x252A918644854075ULL,
		0x73706465497193ABULL,
		0xB23343A15A9929A9ULL,
		0x526250F84DCA690EULL,
		0xDC95EAC195D5B61BULL,
		0xA6BB1B7D1C6209DDULL,
		0x3078652D8F3C75FFULL,
		0x90EAAE7E4CF01CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36B6A42823E4BA8ULL,
		0x333678F77FFF0A99ULL,
		0xE41248649D92AD9CULL,
		0x553837B7B96EB60BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F2755C185E7460CULL,
		0x337D57D000A550B0ULL,
		0x12F10E5D3F85391AULL,
		0x2817343AB5616312ULL,
		0x6247170D37FAB45EULL,
		0xA2D86C9B5F211A0CULL,
		0xBF00A0F221EA38CEULL,
		0x73C1DCCE9E336EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B4C1B7D51E0E86ULL,
		0x5F9D76E01F8F2E87ULL,
		0x6D08F24E4849A7C6ULL,
		0x56DDFAE63103DAA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x611E330783290DA2ULL,
		0x046E722229D36EBDULL,
		0x3AB2E451CB854C11ULL,
		0x557F33DE7FD1F1F0ULL,
		0x18BBA31897A9EBF5ULL,
		0x729B011EC0A99268ULL,
		0x713F41C926AF13E6ULL,
		0xBEBE3006F5FA6A2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CF868AE0662183BULL,
		0x07709CB2C2FF2A31ULL,
		0x0A16A82D89824046ULL,
		0x25BA54E702FDB463ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4848EB78D9C66776ULL,
		0xE8CF998DA687131DULL,
		0x8C03EE9AE46BE0A6ULL,
		0xB4FA543A4050AB6BULL,
		0x5527F71625A51974ULL,
		0x59CD8F0E382DBA2BULL,
		0x7EF91ECBF9DDAFCDULL,
		0x20CDF876E86130DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC3798C270482F7FULL,
		0x3D52D5A9FD50B58BULL,
		0x64FE80E1FB53F922ULL,
		0x138D35E0BEBDEC72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1FF0101C657973CULL,
		0x846AAFCF1E090CF6ULL,
		0xB79667B268E179B6ULL,
		0xD7C889A6E95BA6F4ULL,
		0xD0F9E6519D08F1D5ULL,
		0x71DFF1E5A8D01ECEULL,
		0x4D6899380AEFC3E5ULL,
		0xF1B1F3DC8406C971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA717311F15AB8245ULL,
		0x6BA897E62CED9FA9ULL,
		0x351D260408788DC5ULL,
		0x3832BC62825D8DC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0F4E9BDAB648E62ULL,
		0x75D358736C44DDD5ULL,
		0x4C8470FC7DAF1534ULL,
		0xA4D40D56ECB5C936ULL,
		0xBD620B2407326EB6ULL,
		0x2E9A54B2CEB19C21ULL,
		0x199202DC9A170DDFULL,
		0xF12110E43090D619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D829116BCE102BEULL,
		0x60BBEAFE1AA20AD8ULL,
		0x1830DDBB5D1B2455ULL,
		0x6FBC8F36223590F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB575FD2A247C40DCULL,
		0xB66A8103387A82CCULL,
		0x47FC3ADDDBD91CBBULL,
		0xE2E2E12A9F217FB4ULL,
		0xD9C973941125D677ULL,
		0x6B88635D52DD0DCAULL,
		0x63AD5D85B2E2CA91ULL,
		0xA8D7A80456E038E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x095D2524B01A1A4FULL,
		0xACA940DD854A8EE9ULL,
		0x13B81CB669832E51ULL,
		0x72E5D1CF8469F233ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57790B91A832F8CDULL,
		0x65F6651D3273503AULL,
		0x7DD0FEB27D0FE8A0ULL,
		0xBD3F113E437E41C0ULL,
		0xD9C7013178C61BAEULL,
		0x25A1408BA24E27FFULL,
		0xBA38B7B24113696BULL,
		0x6111080BE56108B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB0338E9959B16DBULL,
		0xFBE5F9D74A0D4034ULL,
		0x223C432825F18E87ULL,
		0x25C643024FE58D2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CDA49B8923B1860ULL,
		0x930A851855F33B61ULL,
		0xF172A10DA2D7F580ULL,
		0x1BB6F0907F13A8C6ULL,
		0xD6911622FED2A1BEULL,
		0x3EA5461301CE66CFULL,
		0xC5814E2E6A4B9682ULL,
		0x0D359F02EF0D0139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666392EA657F1AE0ULL,
		0xDF92EBEA9A967E3BULL,
		0x42A43BF16A104CD5ULL,
		0x11AC8AFFFB01D75AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF33DC98BB7114CB0ULL,
		0x706EB3D53FF45B3FULL,
		0x76C4E88E557A89C0ULL,
		0xE5DADBCC954158B3ULL,
		0x81DCF098C39974ABULL,
		0x6CDBFDA15867900BULL,
		0x56085F605E25F4D1ULL,
		0xD965543B5DFCC91EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A098038BFD8A2F8ULL,
		0x991659C85F53BCF5ULL,
		0x3C0310DC4F1CE0D6ULL,
		0x2AE55C9C88C73334ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCFE8EAF938283F9ULL,
		0x7FBC8DF92F6063E2ULL,
		0xFC18FD4C8FBCD06AULL,
		0x7B25EAA37E8C151FULL,
		0x32B4EE78BC384B15ULL,
		0x2B83C8EFE2D3821DULL,
		0x4EBB06997419A98BULL,
		0x8CDEC0E9DBE5D0D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83D9F49B83DDAC35ULL,
		0xF54C6194DAC5B438ULL,
		0xABDBF813CB8BFB12ULL,
		0x64368D5A22A9153BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD51CF0571631ECB0ULL,
		0x5A7E5C1D75387130ULL,
		0x596BC5C58931E9FCULL,
		0xA07696F00BD5A439ULL,
		0xC1726D4A7FA5840CULL,
		0x02211D7CFC29F5E1ULL,
		0xD0C0581991A08D44ULL,
		0xA4E2EF764D36AE10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C19296608C38A2EULL,
		0xAB68BCAAE372F0B3ULL,
		0x55F8D9912706E214ULL,
		0x1A26227F81F37AB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CA5FAC2E1F6025BULL,
		0xF564EAA2E1EE5666ULL,
		0x80D0ACBD77CDD0D6ULL,
		0x85C09066146CBAF4ULL,
		0x813EABC9AE67C35BULL,
		0xAA01669D491F262FULL,
		0xEA0B670925492BD3ULL,
		0x5FC288AB76FBD5E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBF37AB2C55D0404ULL,
		0x319A25FBBC8E0173ULL,
		0x3E81F81900AA5242ULL,
		0x3CA0D9D9BDCE7AA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22AF12E896B1ACBAULL,
		0xDE39E825A1E3BEC4ULL,
		0xF086F9547D5B7282ULL,
		0x16E111664DFCB093ULL,
		0xA78AFDBF072D4935ULL,
		0xEC24270B7925DAF8ULL,
		0xD9C93AAD3F783667ULL,
		0xEEAF24E658F14ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0150BD43A76A8FDDULL,
		0xEB97B3D99D823FADULL,
		0x4465AF0BE93385EFULL,
		0x04E08B9781CE6322ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A03265B1BE2D2F8ULL,
		0x45AFC149D305676BULL,
		0xA0F7901DFF397D9FULL,
		0x18DD9A7108C3339FULL,
		0x743F68BCFB2CC60CULL,
		0xF566C22781833E5FULL,
		0xB5799A5AED7107C2ULL,
		0x4B93619D9C965586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B6CB26864883A62ULL,
		0xB2F093270C80A996ULL,
		0x9104799D3E00A48FULL,
		0x50BE17D64713E59EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A62F16BFBAF176BULL,
		0x543B3875F5CA4309ULL,
		0xE458D82BF4B8A5B1ULL,
		0x48F03B3B4CF92160ULL,
		0xDB3BF639B5E4CC0FULL,
		0x1946F6E4CAFFAA8FULL,
		0x3A12CCE7B42DCF03ULL,
		0xF7B0DC626968AE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95497DFCFBA56723ULL,
		0x14C3DE6C17BD9463ULL,
		0x83234290B3856027ULL,
		0x0D30F1D6F28309BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB84E2FC82803DA7ULL,
		0x298B76B0A59AD146ULL,
		0x7A0B94273285A090ULL,
		0xC07ECB5F5C6B36C8ULL,
		0x391B319D572325B1ULL,
		0xD7E955A648D37A0BULL,
		0xE66E9F469945981CULL,
		0xAA1BE4E682B295F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458E405771B7D9C9ULL,
		0x362E2D5F74FEEEF1ULL,
		0xAE7738A1F2DA34D8ULL,
		0x00A2C596C2ED788AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22EF02287049AAB7ULL,
		0x2DEACE4DE11C71ABULL,
		0x4BB44A7881E648FAULL,
		0x0D418068E0E6C362ULL,
		0xD47A82A9E76F11FCULL,
		0x78026E0205AD40E0ULL,
		0xDC033855705D46A5ULL,
		0xC3EC3C29E447981EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD1E6760CAC65A6DULL,
		0xFE47229AB8D4130AULL,
		0xF42EA7272FBEC589ULL,
		0x22526EA0C38757F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A444E24F4C79D3FULL,
		0xAA48BEEDDA419318ULL,
		0x42BA6202881DD497ULL,
		0x2F913CD8EA096760ULL,
		0x31FF35537131E335ULL,
		0x5B8A4B1ED9CD66CCULL,
		0x7C63BD9BB3A094D4ULL,
		0x365A9E1EA561F1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86263887C22F584DULL,
		0x40CFE5822EBED567ULL,
		0xB988871F31F3EC1DULL,
		0x4104B56576935112ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD6142FD984DA636ULL,
		0x284B62BD9A4C7FF8ULL,
		0xFB3BBE59FF6F6A0CULL,
		0x5F3082EF20DD67B6ULL,
		0x53D6C5E1062714D5ULL,
		0xCB0760CB09AE10D9ULL,
		0x615DD19D0B8D9018ULL,
		0x107730749E53CAFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F42A264821ABE33ULL,
		0x4B63C0E10A23003BULL,
		0x6F28DBA9B672CDBAULL,
		0x50E1B43EA14D8953ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x300B96FA85B83C61ULL,
		0x628C3600C0D366E5ULL,
		0xB91C6838803F7CBBULL,
		0xAAB7357BA5792AD0ULL,
		0x1843763B03AF43D8ULL,
		0xEA0AF8F7310AE21AULL,
		0xD22401DE8B5CAD0DULL,
		0x1459F22347F19FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0F23BD11BC4EF6ULL,
		0x202D2AB20870F6C4ULL,
		0xEA74AF4130012CCCULL,
		0x301126B85356EA57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFAD2401B042BDE3ULL,
		0x6A6B62B5370A6A6CULL,
		0x6A03E895BE4CBCF6ULL,
		0xFEF9A1130C29A27DULL,
		0x0F963CA45D9F140CULL,
		0x423FD866BF0131EFULL,
		0x717C3A0DF2755732ULL,
		0x32AFE4E7499855BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FFA246795DFB8EEULL,
		0x3FE581F59137D3E9ULL,
		0x427486A7BBB7AE6CULL,
		0x05159B67F8C65C50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3913B5FAE64BE677ULL,
		0x074C58E37CBC2DF1ULL,
		0x283509AA4CC10809ULL,
		0x070BEDE9C584132DULL,
		0xA5C7554D74FDA80DULL,
		0x62ACF2DAB65C5F19ULL,
		0x25260ADD64789E0CULL,
		0x988493BD390B1202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AA5F7A43F2DBBCULL,
		0xACF8655A8E724BBFULL,
		0xABDAA68736A87DDFULL,
		0x2AB9DC003D28BF7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A4B1F2AE8E00735ULL,
		0xF8FA72DC8C9E4F67ULL,
		0x6BB6DA51A02A03CAULL,
		0x17AA5AF7EE3488E8ULL,
		0xEF45A6F6D1A416FEULL,
		0x4CE89709A8B58DFDULL,
		0x23AC17DE64E1F2AFULL,
		0x10C12A6CD5657B69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEA1E7CE073B7148ULL,
		0x6380DE4B97916318ULL,
		0xB742655499B409D0ULL,
		0x1456A71F9B44DA83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9087C7A695ADC7F2ULL,
		0x7CA533CB2D49DA5DULL,
		0x3B9AF385665C4017ULL,
		0x27B9415A413D0E5EULL,
		0x86647092AF182D20ULL,
		0xE898DC833E22503EULL,
		0xEBCCFC198701E313ULL,
		0x5E5832E77BC0A0ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83707D6C93447CC6ULL,
		0x0355EF466661C3A5ULL,
		0x3C085F4F70A3F50CULL,
		0x28D0CFB69FD4E82FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53A3EFB3AABEC997ULL,
		0x6ADC853D9EEC127BULL,
		0x72680D83CE48AA98ULL,
		0x13E48449DB2A6EF8ULL,
		0x04E3362C3C2DCC09ULL,
		0x3BD4AFDD352C0F73ULL,
		0x1C5F5B117908DDF2ULL,
		0x42AC0918822118BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D5DFA44998B1456ULL,
		0x4C6EA01383765D8EULL,
		0xA88F921BC5999C8DULL,
		0x796DDDED2C141A98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0428DF0521B1BE2BULL,
		0x59AE81BC4666DBD0ULL,
		0xA92B63C0FED81187ULL,
		0x4E6BBF8CABC7701AULL,
		0x7318079902DC6E14ULL,
		0xC47D4283704CEFABULL,
		0x624C369B700D0ABFULL,
		0xF94D1160475C549BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19B9FFBB8E6A1AA1ULL,
		0x8446613EF1D26F43ULL,
		0x407B7ED3A0C7A9FEULL,
		0x4FDC53D7437BFF2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC6E68DDDD291484ULL,
		0x90A6CDA95CB0811EULL,
		0x9543FB03D11183DDULL,
		0xDA040877743284F1ULL,
		0xB29AAA1B87A28D73ULL,
		0x370E8CCF056BDCE9ULL,
		0x88E27A0F83DF6AB2ULL,
		0x3D9117DFB74340F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F63A8F3FF4A14FFULL,
		0xBCCFB4642AB34BCFULL,
		0xE6E21951643B5A51ULL,
		0x7D8D93ACA82E28A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD50640DD00C19E49ULL,
		0xC0FF5E4E1089EA5CULL,
		0x18BBD9FE336ABD8DULL,
		0x684F927D946E21DFULL,
		0x4D10485AEE2A76E0ULL,
		0xB130BCCC0A8FD7FEULL,
		0xFC9F6A460658D0F1ULL,
		0x3C54D7551A14499DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4570FE5C5B0F44DFULL,
		0x0E3B6497A1E3FA1CULL,
		0x9865A0632499C16EULL,
		0x5CE7891F73710F52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68AFC36E0668E273ULL,
		0x106F9EE5C80A920BULL,
		0x7EF5140773911B81ULL,
		0x78ACDD8544891199ULL,
		0x6EFD01DB98D7D58AULL,
		0x7E652308E34108DDULL,
		0xF94E34E7DE64C503ULL,
		0xE3F2850C7AE3267AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE23E0A06B67299FBULL,
		0xD372D23783B1E2E9ULL,
		0x8090EE7276865A05ULL,
		0x4EAC9D5F8240C7DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F6352357A0B8B03ULL,
		0x326879B2D5217D71ULL,
		0xCA9E7F1914CCD435ULL,
		0xF7CEE6F4C347D9C6ULL,
		0x3AA3CA4E4094D1A5ULL,
		0xE46A6FD31BEDFE00ULL,
		0xE76AE31EF5816EFDULL,
		0x9FA184DB9099F6DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3B359D31022AD24ULL,
		0x1A351308FA753179ULL,
		0x247C35B186034DE5ULL,
		0x29C89F8C3A227E45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD60B988C7C387F77ULL,
		0x8D8AD10C8649DD9FULL,
		0xF350C4C281733BB4ULL,
		0xB69592B1EF5ADD6DULL,
		0xD3E3898778E11E3AULL,
		0xC956AB662B231A92ULL,
		0x7CB837F2DCC3084AULL,
		0x58569240D8CE8AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D202A86DA2FE14ULL,
		0x70684236ED7FCF6BULL,
		0x76A912CF466676CEULL,
		0x536F48521E0372E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x083E4B7DB38F11A5ULL,
		0xAACFB9D7C3ECC635ULL,
		0xB7594E4AF589BDA2ULL,
		0x08B0AA123EF981A8ULL,
		0xD90A70BDC6623BA2ULL,
		0x64192BFF83BEE340ULL,
		0xA7CEDE84F1B1B42BULL,
		0x0B1931899D07A0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FCB07A92623EBEAULL,
		0x868C41C5524281D5ULL,
		0xA00E5606D5EA7C13ULL,
		0x2E6E047F8E1B640BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F6D9497D7BCFE08ULL,
		0x3ADB5C7454599703ULL,
		0x979BE073C02E9336ULL,
		0xE4C3656163EF117AULL,
		0x1ECA65237DE83FEDULL,
		0x9CD13A869FB848B5ULL,
		0xF672F6FBA163CB59ULL,
		0xFF03F36CE2556E30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317897DC883680EDULL,
		0x81EA0C7009B461E6ULL,
		0x2CAC89CDB4FEC283ULL,
		0x3F59878AFC9D6CBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD5636A6455BA6F0ULL,
		0x55558888C927C454ULL,
		0x5CBAD2FC8C42141EULL,
		0x5E9A36A9D17D7A1BULL,
		0x149A014435A4FD92ULL,
		0x15ECF083D9CC0889ULL,
		0xBBC57598E20B9573ULL,
		0xE7EACC82502BC566ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC3266C63BD94FBBULL,
		0x96813C1B1D7108ADULL,
		0x3C0A47AE19FA4333ULL,
		0x4B749201B7FCC75BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F0F411B9BE61A0CULL,
		0x0E18C932D03DA0CDULL,
		0x1C989CEA6F9F4959ULL,
		0x375689684DF3FB06ULL,
		0x9B1BD306F9B69B15ULL,
		0x07FD6F54E43D39F9ULL,
		0xD453F394EE6619A2ULL,
		0x7879C4A756F614E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55309424AD0121D6ULL,
		0x3DB74FCCB1543BDAULL,
		0xA10EC505D2C71766ULL,
		0x1969BA3F367B15BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BBA3ED761C514BBULL,
		0xEF15AFE7910B7609ULL,
		0x5CA2BD9C08B4370CULL,
		0xDFF5FE67B72E08ABULL,
		0x084FDD7F5E9A5B42ULL,
		0x27C2A38B1483E71DULL,
		0x76CA16F5D543612FULL,
		0x8D055846ABFED921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77951FBF6CAEA3B8ULL,
		0xD5F9F68C9C9FC458ULL,
		0xFEA22619B0B4A40CULL,
		0x4EC118E53F0243A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F9E70934DC9FA25ULL,
		0x2B75FE995D307B25ULL,
		0xC6BFC7FAAA722F22ULL,
		0xDDFD1E6AC2A7E1F1ULL,
		0x4F496A7C2755C150ULL,
		0x5BC59C9A8829BFB0ULL,
		0x5F1FA4913845893BULL,
		0x264D02990B2E058FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34843F012484ACFCULL,
		0xCACB3D899362EF51ULL,
		0xE572358904C48DF1ULL,
		0x0D6B81226B7CB539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD10ED41DB96A8DCFULL,
		0x1767CC60E420D3B2ULL,
		0x69013AEB00AD064AULL,
		0x4649833B6D1E1BC4ULL,
		0xE82B5001A24AA347ULL,
		0xD3615FD2D2881723ULL,
		0xC515735C4F8057A0ULL,
		0x185E396E485EFCBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477CB45BD07ECADEULL,
		0x77DC05AC24544307ULL,
		0xAA305A9ECDBA0829ULL,
		0x6446099A2B379FA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DAAF545E5C282FCULL,
		0x2FA91695B9DE3B1AULL,
		0xF89E2BD974313881ULL,
		0x8654FDE137E27D0BULL,
		0x1CB8493E70219AE3ULL,
		0x2AAFEEB1165D088EULL,
		0x3A775A07890E9847ULL,
		0x9E762AD72802FF0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5105D48A8ABF843EULL,
		0x85C684DF0BAD8032ULL,
		0xA65588F7CC5BD311ULL,
		0x0BDF59D128545890ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8247B4AFC55CD655ULL,
		0x6C172AFF80CE208EULL,
		0x948458CD867A62A1ULL,
		0x3428C2A2827A0596ULL,
		0x796CB35205287F47ULL,
		0x1A9C5D5E9E0E80C3ULL,
		0x40973FECF769F8D5ULL,
		0xAB042780067F4AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886A52DC895FBEA8ULL,
		0x5F4D070AF6F53D92ULL,
		0x2AF7D5FA40355243ULL,
		0x16C69FA3795F213EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC9A1D074EDEAD56ULL,
		0xBEC58F0713FE7E10ULL,
		0xEE6B5BAAAF37CD7CULL,
		0x0EAA76FC0F26AC00ULL,
		0x560E4DDF37F34CB4ULL,
		0x5D6607A453F7C8D7ULL,
		0x911BA71F6AE65347ULL,
		0xC8F5313B21641B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B9AC299CFC146FULL,
		0x9BEAB16B8AC64E07ULL,
		0x78862A548D682A14ULL,
		0x630FC5C30402C246ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FB7C2938ABC5EADULL,
		0xFCECF5D5272BAD2EULL,
		0x3C411458B5C9DAA3ULL,
		0x5F3ADE9EF7112E37ULL,
		0x0750D700DE52F9E2ULL,
		0xF690D4930709ED1BULL,
		0x095BB6A14871B4F8ULL,
		0x156CDA61607F41FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B7ACB48B0D76BEULL,
		0x966C83A832A4DF31ULL,
		0x9FDE304976AAB798ULL,
		0x0D63491349F4F9C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC48073CB9FA7BBB7ULL,
		0xCF790070F3EEB691ULL,
		0x01EA93EBA9A3E3C6ULL,
		0x3B48673CACACFAFFULL,
		0xD39512A399E8FD37ULL,
		0xCBC2A129861AA528ULL,
		0x8B6BAFA61123439DULL,
		0x390D770DA3BB9FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA13814783D5324ULL,
		0x0E5CEC9ADBE33AA1ULL,
		0xB3E6A69234DFED33ULL,
		0x33481342FA86ADDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11C86ED2763C1DFBULL,
		0x0903272E39DA70C5ULL,
		0x418850DFCF140686ULL,
		0x1D1C6835F75A620FULL,
		0xE2839278FB3DA906ULL,
		0x94CEF0D7298B6EA6ULL,
		0x95829DC5DD4908A1ULL,
		0xDDCD10CF82C1C92FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1502CC7C16339C5ULL,
		0x1FBAE71E648CDD8AULL,
		0x72EBBC3EA7EB4E82ULL,
		0x098CE703601E3F1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FED6AA732B50392ULL,
		0xF9502F024812E33BULL,
		0x2959922C0DB7F372ULL,
		0x5F94E89273AA3384ULL,
		0x45B4D361A3D50B90ULL,
		0xEA3061DA51B90F2CULL,
		0x77554F275E6451D1ULL,
		0x464257CA08897649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C4CB258454BC81ULL,
		0xBC7EB56A698B23CDULL,
		0xE0035204109C189BULL,
		0x4D6DF08FB811C26BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E8BF5A035C84E00ULL,
		0xEAD0A4C32A3FA8EAULL,
		0x449EAAA6869F69B6ULL,
		0xD19026E2B0CE1C2FULL,
		0x5655C53512AD79DEULL,
		0x9A20F9E58B85A3A7ULL,
		0xD13E17101EA69581ULL,
		0xEA5F152721575602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F473B80FB886A39ULL,
		0xCBB5BCD5E015F3C1ULL,
		0x53D6170B13599AF3ULL,
		0x1BAD4AB1A3C4E09AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97FEC55E45DF278EULL,
		0x1AEF9BCF8DD7E11EULL,
		0xC530285864FD45D2ULL,
		0x69ADF6D3DF3AF63BULL,
		0xFDA528B67E35FF12ULL,
		0xDD63D5C71AFF92B3ULL,
		0x3948C0F4B4CE74CCULL,
		0x8AFE2C04D530D719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E82D07501E30758ULL,
		0xF7C1575D8FC7A7D6ULL,
		0x45FCCCAB3BA29C3AULL,
		0x0B687F8B847AE3FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2C774F53ED56F70ULL,
		0x53A61DC9DA78091CULL,
		0x76FD0D93185914BAULL,
		0x88185327BC7CEF1FULL,
		0x103D588B389A6F0AULL,
		0xE88A6F750AB50060ULL,
		0xC38F8C20B6F4342EULL,
		0xBEE160CC8091A924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE2999FA5C1EF27ULL,
		0xD832A9297156175FULL,
		0x7E4BDA6E4098D3B0ULL,
		0x5D8CB182D21C0A94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFCDDA022E266C28ULL,
		0xF129383D9B519F27ULL,
		0xF84C828F6A7339E1ULL,
		0x125095AE67F231FDULL,
		0x3010316A42D7EF53ULL,
		0xDEBB49D009E99349ULL,
		0xC2EFEB1D220CCF51ULL,
		0x67D65719315F6693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2352FC81A33F4B4ULL,
		0x00F62D1F13FD7C04ULL,
		0xE7E968E2785A0009ULL,
		0x7C21836BBC1B6BECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84A2DE8A4FE9F3F2ULL,
		0x005B8504B933247DULL,
		0x10F0B4119E456EEEULL,
		0xB5F259A67AA5CCBDULL,
		0x3FF70261DDCCF6CCULL,
		0x02FE848465DA2316ULL,
		0xD3A7FD3A10B2105DULL,
		0xFD7B7FB206DD0C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034D39113C569BDEULL,
		0x722330ABD79459CBULL,
		0x7BE04AB018B3DCBCULL,
		0x56474E137F7599E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8190EDF2F5563EEULL,
		0x2C9BB8EAB774B4AEULL,
		0x3445674FAFF4068DULL,
		0x531C00D16B6726DFULL,
		0xE0A06B44B4F3FF2AULL,
		0xC14EBC9F5AFABCE5ULL,
		0x3BE3626C24294BE8ULL,
		0xEEEDE8D3724578DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE8FB120B8D496FULL,
		0xDE4BB89238ACBECEULL,
		0x1806035D0E154B19ULL,
		0x4A6C903461B717DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9842C70A469A1F11ULL,
		0xCCF7860B959C5C31ULL,
		0x26C7CBFDAE770170ULL,
		0x48548D8B916A520CULL,
		0x9498CBBDDBFE9C73ULL,
		0x51D8CF3F08864B40ULL,
		0xA5CEBACAC8A0CB8CULL,
		0x7A5EE59ECDA5A685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F10538EE655ACFULL,
		0xF3264966D98B87C7ULL,
		0xC377861776553844ULL,
		0x726AA31E180109E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B2BE47A13F8C04AULL,
		0xB8C5D59CE971E5B4ULL,
		0x6EC10A83C5731363ULL,
		0xB363B1BF3FACCD37ULL,
		0xF1F4EE51EB75D93AULL,
		0xB479C5731F10F98FULL,
		0xD5EE09F384B220F7ULL,
		0xCE637D5CC275C432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658744A307770380ULL,
		0x82D924B385F6F112ULL,
		0x301684A977E3F828ULL,
		0x56284D841D27ECC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8BE1991F70D9929ULL,
		0x93D05F30D2B5D39AULL,
		0x8F607A831F468E31ULL,
		0x87629A954FA38218ULL,
		0xB3A3C9F837CC8DA4ULL,
		0x05068E489981499BULL,
		0xD269083AC01A11B7ULL,
		0x1172AE10B69AB251ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930E146A3F6A9FF3ULL,
		0x52C97DF79BE6C0B7ULL,
		0xCAF7B33BA3252F5CULL,
		0x1E6871106A99FA3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x359FE7748FEF9435ULL,
		0x5BA25251BC2FA8A3ULL,
		0xDD37A9CBEE8310DAULL,
		0x7DAD88EF3A488384ULL,
		0x9D1FC4183A9770F1ULL,
		0x92F55EDADEDC3286ULL,
		0x770BCE46DF2BFCF1ULL,
		0xE65477302F463155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8857030D426A5D1AULL,
		0x2C0E66CED0DF289EULL,
		0x88F848510F0A9CB6ULL,
		0x2E373A163EB3D634ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCC97115808A22F2ULL,
		0x52B55C2E38E50264ULL,
		0x4C296BCAE0C5190CULL,
		0xE432A64731FF9E44ULL,
		0x97B7D61B002ED811ULL,
		0x088598C7FDEBCEABULL,
		0x09DB5FE8C6CE158DULL,
		0xD46C9731218706F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82133917877E3A38ULL,
		0x968A09DDE9E5AFDDULL,
		0xC2B9A858635C4BFBULL,
		0x6C5117922C0AA6C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x604FF335144698FCULL,
		0xAA3ABCD19D3D8F8AULL,
		0xED80677BD4E3B2CCULL,
		0x631D529537BCE8DFULL,
		0xAAA88BA822964EA2ULL,
		0x3080533A3E223598ULL,
		0x7E3F8A3C9BFB0470ULL,
		0xCC3C9D88B5779740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB554AE2A3696498FULL,
		0xDD471776D6518433ULL,
		0xAAEEEC7AFC265B73ULL,
		0x341CB4E0277D5C72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB4008A5637DB378ULL,
		0x8CE9092C31D3C8ADULL,
		0x9786ACD2BC90800FULL,
		0xE482D3CDF874EC6BULL,
		0xD8EE99727741A5AEULL,
		0x62BF5ADB2A4FCC64ULL,
		0x3A9731DC13F0EF08ULL,
		0xFBCE6E478C655489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAACFA3173C50F0ULL,
		0x355085B479AC1FA6ULL,
		0x49F8137DB253FB4EULL,
		0x4527326CCF7F78CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x408393DE11114D9DULL,
		0xB205A0E40A7EEFFBULL,
		0xBDD73E0D83B19E06ULL,
		0xC13BD841D4FCDE02ULL,
		0x810EB948E8B03283ULL,
		0x75B2D82D4EAB65EEULL,
		0x276BD598776465F7ULL,
		0x521E93BFCC31FE80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B314B09B38CEEAULL,
		0x2A91B79DB7F01162ULL,
		0x97D8F2AF3C98C0C2ULL,
		0x71C5C6BA2468A508ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC072CB69D06440D7ULL,
		0x55DF66F74723170CULL,
		0x34C1D76739B8E96FULL,
		0xBA174AA813AF5C8AULL,
		0x2B1D9C0CE5C7ED10ULL,
		0x54EC945907823A1BULL,
		0x8274D7750130020CULL,
		0x1210201EEE5BD494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D7F553EC1171A9ULL,
		0xF0FD6C2E6477B715ULL,
		0x9219D2C566D93743ULL,
		0x687C0F3F7550EA95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37EBAA0BF368AFDAULL,
		0xAF3629A149E75D51ULL,
		0x6B14D888708D3491ULL,
		0x1D7818E3C18873C3ULL,
		0x9C7DFE2D584CBC19ULL,
		0x42FA22618ED58675ULL,
		0xB567F23C661CBFDBULL,
		0x4432E27C53A31CF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x729F64C70ECC9D0CULL,
		0xA057441C7D9952C6ULL,
		0x5882CD7F98D1AF1DULL,
		0x3D05B7582BBEBF7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F721EE041D93A0CULL,
		0x9972237955F6D07EULL,
		0x76CCD78AED0EEF10ULL,
		0xABE62CDE2EFC4851ULL,
		0xA1A59AC84BBB70D8ULL,
		0xF5BDEC487C1000FCULL,
		0xA01981D3E5FC0721ULL,
		0xB036C092B6EDFAC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E07189B7FABFE0BULL,
		0x13A3363BC056F5FEULL,
		0x3A961CFF1077FE1BULL,
		0x5406C2A5564F8135ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37540D92A61D2547ULL,
		0x17B5FBC516C9E437ULL,
		0x7DD10DCF65EAF6FAULL,
		0x5B11DA03E5D2B459ULL,
		0x1F046D9B5D36E394ULL,
		0xCF0B398D6A05F1A9ULL,
		0x1AA128BC1DBE61F4ULL,
		0x0DE7F93783833066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1FC52A27C42ED8BULL,
		0xD36086C2D3ABC351ULL,
		0x71BD19BBD02D8150ULL,
		0x6B80D8416B4BE381ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B1906E2DFD8653DULL,
		0x98AFCA26CD7D87BFULL,
		0x7BEFE11A4A8A81CCULL,
		0xB72BC5B4CCBDDA65ULL,
		0x6637C685149BBEC8ULL,
		0x7DD3065AECAF822CULL,
		0x111B7BF6F5039F5FULL,
		0xBC8404FA69590B3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47607EA3EEF6BB28ULL,
		0x4602BBA5EF8ADA56ULL,
		0x060447C2A91429F9ULL,
		0x32C482E06FF58576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2DBB90EC1D0B760ULL,
		0xF1B0BA466A69445DULL,
		0xFB6D121D1E6EF707ULL,
		0xF2E02E59124164D7ULL,
		0x2F4D2209679E0BD6ULL,
		0x225FA996CF07FB19ULL,
		0x69DA16C28A8C66CBULL,
		0x035B771AFD219D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD84EC6742346794AULL,
		0x0BE3E6A925988A1AULL,
		0xB1CC72FDAF46392FULL,
		0x7273DC5AA53EC8DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE71144A9FA8C254ULL,
		0x971EB4FC0A3CC527ULL,
		0x2B9DB746219AE7DCULL,
		0x89FF8F5673828B2DULL,
		0xE201ECCF6C079753ULL,
		0xAA0DC124B172B244ULL,
		0xB8B599DC6DB12165ULL,
		0xE861E589E7E1B765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ABA3B14A8C93DD8ULL,
		0xD529606E61433B61ULL,
		0x96928DFE69E5DCF3ULL,
		0x0887A1CEDF03C446ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6901B05AD9772F63ULL,
		0xBCB8C6F1A6308CB4ULL,
		0x28F7E6B75CF07664ULL,
		0xF42BB4499101025AULL,
		0xFED9B7CD0281ACD5ULL,
		0xC230C218037420B3ULL,
		0x9F9B6F680EACD63EULL,
		0xC801CF26E469AD57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D52F8C938B6DB88ULL,
		0x8FF59682296D676CULL,
		0xDA0A70298A9843B5ULL,
		0x2470740F78B0BD5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7576477D91A972CULL,
		0xDE43BCC175147637ULL,
		0xA39D434DCC252CA3ULL,
		0x976FCD6DB1588A8CULL,
		0x611230F2A61DE4EEULL,
		0xC4BAECB4F4761C58ULL,
		0x5D950136732C04C8ULL,
		0x4997B95469FE62C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x400AA87C818A9435ULL,
		0x1202DF9DBE9CAB56ULL,
		0x87BB7162E4ADE271ULL,
		0x03F54FF56D1B3424ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC0424AAD6FE2DE0ULL,
		0xDE677C1D9DC12AE1ULL,
		0xC9F4F1D77737BC81ULL,
		0x5556EBA67E31823FULL,
		0xA6E8441174388D32ULL,
		0xA162BA82ACB752C4ULL,
		0xA10A2C4489BE481BULL,
		0x08AC10258FCE3184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x927E3F4217632385ULL,
		0xD30F2B8340F77412ULL,
		0xB1778403E976709BULL,
		0x1EE15139D6CCDBEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ED6373EC872A3D6ULL,
		0xD21616E8B76803C8ULL,
		0x2A0BAC0B8C1E14ABULL,
		0x766A696F5F471091ULL,
		0x2DAA05FCADB0259AULL,
		0x1C891C05C8F85865ULL,
		0x608D46F73DDCDDEFULL,
		0x455D2F03BF1BC24AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6131AC090983A41ULL,
		0x0E703FC48C4522CCULL,
		0x7F0434BEBAE7062AULL,
		0x423F63FDBD65E79BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD430717C0D85F38FULL,
		0xCA058A45C435D6DCULL,
		0x13266E8742CE2F5BULL,
		0xA314A6AC9C9A3DAFULL,
		0xD2B2F98B0EF06118ULL,
		0xD33D872B4035DF63ULL,
		0x7DEF5A7198AA8153ULL,
		0x62E1D34CAAC24884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC17C2045345F59ULL,
		0x25279AB14C34FFAEULL,
		0xC4ADDB63EC1D61CDULL,
		0x509A040DF5710159ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F6E5D8CFB3FF693ULL,
		0xD74877E2C9B1050AULL,
		0x228608F89410B4FBULL,
		0xB09643CC49997751ULL,
		0xC3EEA1E07EC876C0ULL,
		0x8B500B6AB703F03DULL,
		0x30C3BD9CF6AB5BD9ULL,
		0x9F847E461FB58ACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24DA64DFCD019AA3ULL,
		0x852A29B9F446AE35ULL,
		0x5F942E4531805746ULL,
		0x5E410234FE8C1212ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAC44E268F4F97DAULL,
		0x1666C30EBC6BE400ULL,
		0x28D35172BC856FFFULL,
		0x9B37FC9A8C0E0B68ULL,
		0xC3F32D75FB5A351FULL,
		0x90AC73753FC1E103ULL,
		0x1D07C0B3CB71AB6AULL,
		0x383075185D6C21EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0DD0DA9DEB37BB7ULL,
		0x8FFFE67633334A8FULL,
		0x77F9EC22EF64E1D0ULL,
		0x72695E386A1B14E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3E8D2DEB4DFB950ULL,
		0xD9D1132C5215DBE7ULL,
		0xA12CC6323225CB1AULL,
		0x61CFF1CEF466D4CEULL,
		0x045B31C5635B9D28ULL,
		0x8E28CA36A493F29CULL,
		0x69EBA16215BC50E4ULL,
		0x063760613CC66F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6972362B74790D66ULL,
		0xF3DF1748C00BDF10ULL,
		0x5A26BAC16C19CD07ULL,
		0x4E08403DF9DB5A98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC58192CE6CA20DD5ULL,
		0xE0B50CB420FAEE35ULL,
		0xB7F82866002DDFA0ULL,
		0x166B325ACD1D642FULL,
		0x68F3508A808054DBULL,
		0xFD2802BFE0F89B37ULL,
		0x69E7B3D6A25C508FULL,
		0x1F00F5BEFE33D110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599F875D7FAEA702ULL,
		0x74A5752F85E1F86FULL,
		0x705CDA4219E1D500ULL,
		0x308FACB488CE6C9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF393DA28EA8413CULL,
		0x311549602C26C612ULL,
		0x4C116AABF117365AULL,
		0xAABF1BFEF50C1CE5ULL,
		0x9AB6C71E9194EE42ULL,
		0x1B663AB3A3E90661ULL,
		0x160E48D969CF24F9ULL,
		0x2B5BF54B15D91154ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE65ACC2C2AC3A012ULL,
		0x4242000A80BDB88FULL,
		0x92303AF1A5D6B354ULL,
		0x1A6585243344AF60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88B3AC88DC6BFB60ULL,
		0xD1C45688CA1B7685ULL,
		0xB3A6CDED5CBC8FFDULL,
		0xDD48C8780D06E934ULL,
		0x76BEC102930EA3BDULL,
		0x66EEDF429AFB1F7CULL,
		0x293E6A78D5150F1AULL,
		0xFF5BB0C24C25AFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x290452EAB0984F25ULL,
		0x19397A6BCB6222FFULL,
		0xD2EA9BDCFDDCCDE9ULL,
		0x44E5054F5A9F074CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21FD6B0F3902A7CAULL,
		0xD8E1B775F26C35AAULL,
		0x7AEF5BAB613CBA5DULL,
		0xADDA63AD15B29A5BULL,
		0x0812DCCB1E3A0E2EULL,
		0xE2280A2F3E881151ULL,
		0xC75EB2D5EFE06A3DULL,
		0x864A65C58F226CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54CA3135B5A0C5A9ULL,
		0x6AD33A793A9EC7B1ULL,
		0x12FDE76CFC8C7F8DULL,
		0x1CE57F0054CEBF6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9504EC7DFC425276ULL,
		0x6528D201C6EC2B54ULL,
		0x2E4BD298FDB2F522ULL,
		0x44F1FFE64BAE9B15ULL,
		0xFEEE5C5CC276FFD6ULL,
		0xFB43AFA6EC0F8D17ULL,
		0xE7EA040784331A3BULL,
		0x2B6909825BC7C110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C66A242D9EC4D31ULL,
		0xB134E4C8D13B1CE4ULL,
		0x9B086BB69D48DA09ULL,
		0x3689693FEB554397ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x272D8FA00390E849ULL,
		0x05AF1BCD556C9F4CULL,
		0x02B215E9194F4CD4ULL,
		0xA96CE00CE69EC7B7ULL,
		0x9B8357B8219259A2ULL,
		0x5E0C17E7177E6881ULL,
		0x327B1A67F9A78A83ULL,
		0x8A2AF34B81A1DE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CAC94F4FF4A3973ULL,
		0xFB7AA81AD2302289ULL,
		0x80F80158282DDC53ULL,
		0x2BCCFD4224A5CF7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E7AA7384206C106ULL,
		0x8B10411BB1CB7A5DULL,
		0x63DC68F60D2374F6ULL,
		0x7E2E04685404193FULL,
		0x68040B7EB7529F34ULL,
		0x64A85F2DF20CAC9BULL,
		0x333E2D998426BB80ULL,
		0xB207F7F26DF0CAF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF145C07784A66ADULL,
		0x7C0E61ED9FAD196EULL,
		0xFF172DBFAAE34A05ULL,
		0x6B5CD264A5C239A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC07CF9E7F6A34C93ULL,
		0xEB0816FF84CC2C42ULL,
		0x72D8BF67CBB1BB8FULL,
		0x9665F39C091B1129ULL,
		0x19131E004F16FACCULL,
		0x40312BCF21952836ULL,
		0xBA8471495A00A588ULL,
		0x073704F497F0C008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79536DF3B40C8714ULL,
		0x725497BE80F0244AULL,
		0x2281904B27CA4DC9ULL,
		0x2890AFEA96D79275ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE55018F2C4E2FBULL,
		0x2CBBAC59EED75BB3ULL,
		0x1CDA710B6BF52048ULL,
		0x32A936429820D3FCULL,
		0x56CADE2AAA2B084CULL,
		0xFBFA6DFBE4B8D42FULL,
		0xD380FC064F35FE3DULL,
		0x35B38D47A1B9446AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F024A6E35281F73ULL,
		0x93E7FFBDE246DABAULL,
		0x81FFD9FB2DF8DD7BULL,
		0x2B502EE499A0FBD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB5D9CCC2760E7CULL,
		0x2CDB927A76DE87DBULL,
		0x54E1A054561CF5B1ULL,
		0xAAEDF5E54FBB33F8ULL,
		0xA04E273BD8E0F0B7ULL,
		0x3405E59AC4B2E8BBULL,
		0xA56314BF8964B936ULL,
		0xF7FB47160EE3FA7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4FACAEF3D9CF24ULL,
		0xE5BBA773A96D13B4ULL,
		0xE196B4C2BB1073BCULL,
		0x7A3A832B85926252ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD522E5FF76AD61B7ULL,
		0x1E4C773515DD9C91ULL,
		0x3C402086F46AB1A3ULL,
		0xBF97D3F7CA2377C6ULL,
		0xB431A6A6E904905FULL,
		0x410B33F2162F9D14ULL,
		0x26CE897F206F741AULL,
		0x007EF513B233B1F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9481A2C60D5ACFE4ULL,
		0xC5F62D2460EEEDA4ULL,
		0xFEE88965C4F5ED88ULL,
		0x527034E43DCFE2C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22C9B3739117CC16ULL,
		0xD27A4BF453314C82ULL,
		0x0CB109F0766EDF0FULL,
		0xE1575C252C909348ULL,
		0xAAD051CC6039C678ULL,
		0x5D500F197F6551F6ULL,
		0xB5296194749E17A6ULL,
		0x026712810DC12153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB5D7C9D9AB420CULL,
		0xAC5C89BD3C3B771FULL,
		0xF0D585F9C5E661C1ULL,
		0x3CA41B4D373B85B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5641E73493314C2ULL,
		0x405A04496E42DBEEULL,
		0x5BFA68AD1D242F81ULL,
		0xD9590F1E92F567B3ULL,
		0xD57D8D1260EECC3FULL,
		0x004643D1AB207ABDULL,
		0xA03C973588612479ULL,
		0x73DAFED062CBB556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96070F2DACA568C8ULL,
		0x4AC81568D515141CULL,
		0x24F8DA9F5B8F9977ULL,
		0x0BDAE20D3D32528FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF78A8B6FC8F75D77ULL,
		0x747B6587F46E2CBDULL,
		0x86E10FD30A464EB2ULL,
		0x9912B2ED990AD24EULL,
		0xC0EE7DB567F065FBULL,
		0xE58E7EBDE0D2A67FULL,
		0x50009E936D787A97ULL,
		0x07E7713F18FF24BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF1345D36A680F2ULL,
		0x87A235B753B2E3B4ULL,
		0x66F899B54A28813EULL,
		0x456D824B4EEA4642ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5C9E0544278BCD7ULL,
		0xF45827DDCC6101B4ULL,
		0x0C9D092610C0D6C8ULL,
		0x26092E7FABA0109CULL,
		0x6C724944712B2F55ULL,
		0x38DA99FCC1E06965ULL,
		0x03B1606F91690B8CULL,
		0xC22705059A3C820CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC0C07D0EE1C7B0ULL,
		0x64CB036293B0A6C2ULL,
		0x98F159B5A6588D99ULL,
		0x77D3ED54909B5E64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA56822F68EC70432ULL,
		0xAD5C03798643AE41ULL,
		0x0756534D324CAA50ULL,
		0x5104279C9BDE6C59ULL,
		0x721089868150294DULL,
		0x31778AC2FF1CACB9ULL,
		0x5A82BBDC227FAF2FULL,
		0xE3F2D9A438BF56B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93DC8CEDC0AD2AACULL,
		0x051A9C6B648551C8ULL,
		0x76BE35FA5140AB52ULL,
		0x271075FD08454BB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57D7BDB50B4CAECDULL,
		0x08F342704852AFDBULL,
		0xBAEC915AE9FE91B4ULL,
		0x004739CC6E268676ULL,
		0xB3CF9A768B2B650AULL,
		0x1A55943967192E41ULL,
		0x3EAF50D63E4A03EAULL,
		0x4AEC67BE8CFC2D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08A8AB4DB3BDAFEBULL,
		0xF1A742F5960F8D9CULL,
		0x08F2912828FB2673ULL,
		0x1F5EA0155B953FA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A08E0C55925A726ULL,
		0x466604CC1E223C0AULL,
		0x5B289EDCE4C1BE19ULL,
		0x9D48F83A0234E3FAULL,
		0x0850D2C67CBBEF61ULL,
		0xE38F656E895272B0ULL,
		0x7D7C2772D1C001B2ULL,
		0x3EA961D3222D7905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6082A3BDD0B30F5ULL,
		0x0DAF1334805F422BULL,
		0xFB9679E80741FEA7ULL,
		0x6A6D7D9114F4DACAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5822D79776337CCULL,
		0x23E48C26421ECD7BULL,
		0x65366213C4657501ULL,
		0xBB29916F6AB52849ULL,
		0x5D87A0EBCD265CCBULL,
		0x18DF95E463C8D1ECULL,
		0x34127C6266771963ULL,
		0xE31DA997E351ED84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A41079EB1502FAULL,
		0xD514CC0D11EDF691ULL,
		0x1FF4D8AEFA1339B6ULL,
		0x7190BDFB28DE69E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFD79A8925CBE546ULL,
		0xAE88DF7B830C0D87ULL,
		0xFD27B655DB655E71ULL,
		0xAA0C1F67F0F75910ULL,
		0xFAECAE73824764F2ULL,
		0x7CE9C7A15EC28C5DULL,
		0x30F9886BFE101357ULL,
		0xDFC1633BFF1D11B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF97FAE7C64E62BULL,
		0x393C816F93ECE37BULL,
		0x4231F65D91C83D6EULL,
		0x60C0DA4FCF47F95EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x385396DEF3C37193ULL,
		0xCE791FC7999D866EULL,
		0x39C8BD8079442297ULL,
		0x2055C26F97F37946ULL,
		0x66FA6C6135552C66ULL,
		0x346F752DA237C79DULL,
		0xCAB7F5772491065DULL,
		0x238685DEE869F0C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x817FAD4CDE680975ULL,
		0x9704848DADE527CBULL,
		0x51172D2FE6CB146DULL,
		0x664DA18617AD360AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FF2D21E6FE286BDULL,
		0x344FC2D25278644BULL,
		0xA4261AE022F2CB89ULL,
		0x75AC4382BC4767CCULL,
		0xA51BF6688DE490A9ULL,
		0xCD1A6A88C4EC597AULL,
		0x9C062A55D3C8AAAFULL,
		0x43FD3FE486FB99B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21965A37FD00162ULL,
		0xA63B931F8D8DAC7FULL,
		0xCD10639D92BC21A1ULL,
		0x0D43BF6EC5A0390DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E12CD1511397DDCULL,
		0x42F6F1A29C04B2B3ULL,
		0xE30FF93747D8728EULL,
		0x0232FB86A2FE36B7ULL,
		0x684DC415BD80ABF0ULL,
		0x6C43E465DC63B1CAULL,
		0x5BA62420EC1F1363ULL,
		0xD31CFCD217B053B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA99DE84F32530816ULL,
		0x550AD8C152D116BEULL,
		0x7DB9561A54755350ULL,
		0x588082B6272AA357ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x803D63B97083BDF0ULL,
		0xD3FCEDEBE68A46FBULL,
		0x091055BF304DDF87ULL,
		0x4EB82B4616AD4920ULL,
		0x7C7F952BF19CA54EULL,
		0xEE09C89A56030D77ULL,
		0xC2A96EFB7E01EE09ULL,
		0xB33FBC47FFA6D8EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2D883F4DC44B73ULL,
		0x2970B4D4AAFE46B7ULL,
		0xEE36CF13E4973501ULL,
		0x6A2E1DF609717C90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F5CBD3F5C62FF4CULL,
		0x2ECEB12660B4BB05ULL,
		0x02880D34FCBAE23BULL,
		0x8B297C03E751076DULL,
		0x419BC15C7586E952ULL,
		0xE19C8359121E35EDULL,
		0xCAF81D208103A81EULL,
		0x5364B411ADE8EB4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C7B70F8CE69A353ULL,
		0xAC0A305F1130BC3DULL,
		0x235C60082345D6D0ULL,
		0x6C1C36A3B7E3F51FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1524EB56128C277ULL,
		0xB72F7D419D6CCA61ULL,
		0x17C5342FB1F51293ULL,
		0x01229759B8E113CCULL,
		0x4AE2283422F1A279ULL,
		0x9712BD9CB95893C0ULL,
		0xEEAD20C1A2571056ULL,
		0x063482B18DFD1E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE446729106E080ULL,
		0x23F7A2852092B8EDULL,
		0x857810EDCAE17F6EULL,
		0x6CEDFDB4CC739C6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42D230D6A382F4E9ULL,
		0x9ECFAA9DB84F57D9ULL,
		0x0155985CE7B382D3ULL,
		0xA624BDDA46702F10ULL,
		0x16C335425228BBC9ULL,
		0x415FCEFCAE7946CCULL,
		0x9C72E095CEE1DF16ULL,
		0x855591542D15EE43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CC18AED58ED7B7ULL,
		0x5308641F9E4FDA24ULL,
		0x3A62EE999D3AA021ULL,
		0x70D85058F7B18D19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED21F267A2C7A668ULL,
		0x7F1FB204DFA5F792ULL,
		0xCAABD9933091EA7DULL,
		0x60493A1D6A3F40FCULL,
		0xADA5B7B8E4AAE3A5ULL,
		0x65DB52FC74443D5FULL,
		0x8D75C19CB82624C4ULL,
		0x65739479E0869358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3BB37D994257320ULL,
		0x9DAE037E21C713C6ULL,
		0xCA2696D6863B5FA4ULL,
		0x6F714434BE392021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB959EEA5598D15E2ULL,
		0xCCD48F4B94138284ULL,
		0x67D25A342AAC643DULL,
		0x285E7C98C3AD16D6ULL,
		0xB104AB7636AB7D66ULL,
		0xFEC02D296C23F9E2ULL,
		0x8A1C8BEF095183D4ULL,
		0x7D33E359EB613976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x000B62317701B5C5ULL,
		0x9D5B4371A16A9A2BULL,
		0xE80F1FAF8CC5F5DBULL,
		0x3E123BF1B41B9E6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x367B17BE36D512A3ULL,
		0x5F756D103D9F717EULL,
		0xCF2A3DF8A432500AULL,
		0xFE886970E69BD5F1ULL,
		0xF7DBA7344B117578ULL,
		0x9C0E142E3B938DF9ULL,
		0xAC0689587FDD74E6ULL,
		0x3C7162BA01734C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0115E9815B6C83DCULL,
		0x898C6BED15868499ULL,
		0x5822A11B9F11AA45ULL,
		0x775D110D1DB92389ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE33EBEC553CF5DE4ULL,
		0x754FAA10721E0CCBULL,
		0x4A12B5ED868CCA3AULL,
		0x6B8CB6C88F210819ULL,
		0x2231DE7FAA129BCBULL,
		0xF3E1C67C878D7164ULL,
		0xD6EEC0321899371BULL,
		0x2536C42A9F731EF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A5C5B892927ED7ULL,
		0xA8D3208C911CE1A8ULL,
		0x31833D5D2D4AF860ULL,
		0x71ADD51C3A37A109ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2C82C5AFED6640CULL,
		0xAAD62A3F4E7092FFULL,
		0xDDEE9B74C92ECF80ULL,
		0x64B6757E938985D6ULL,
		0xEB50055D44A5B48BULL,
		0x98F8F9FB4EC245DBULL,
		0xA2578317857E744AULL,
		0x18A53BDE04633ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A8F8332F6F3146ULL,
		0x5FCB458CFF46F1A4ULL,
		0xF6EC10F299F41293ULL,
		0x0D3D58733A44D8A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD26EF965673FE1B3ULL,
		0xA00BE54394A92FF2ULL,
		0xDFE68DE81D2EDE07ULL,
		0xEE41E17C480B9A4FULL,
		0x21175B434C485197ULL,
		0x70EA5F79FFBA8A06ULL,
		0x7006100A048EDC09ULL,
		0x2C40E748D0AA1E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBE68562B9FBFF27ULL,
		0x62D6115F8A59ACDBULL,
		0x80CCEF64CA63876EULL,
		0x7FE4364B414C1346ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A9F157FE2780AEDULL,
		0xBAF1432E821AA05DULL,
		0x75C56765D9659670ULL,
		0x245C24A1D2FDA3DFULL,
		0xBD817BB09229D383ULL,
		0x6A98A3B6776155D1ULL,
		0xC0F89F282CA09863ULL,
		0x71F908C8BCF6FF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BD771B594AD72E5ULL,
		0x8D9990443A8D5D7FULL,
		0x1AAD075C793C3532ULL,
		0x0F53726DDFA782E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDE71286CFE57A60ULL,
		0xB5E2C784CACC9B47ULL,
		0xF5219BA8F2D6777BULL,
		0x72EB1A871F66D9F3ULL,
		0x4D569B4BBEEABE83ULL,
		0x7DB77312CD4A1D7BULL,
		0x97315D1A1893E991ULL,
		0x1C851CE600C6F22DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C21FC526BDC27DULL,
		0x5F1DDC4F43CCFB95ULL,
		0x66756D8898CB2314ULL,
		0x2EAD64AB3CEECCB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x696F77283CBBF6CCULL,
		0x53A03B10149F657AULL,
		0x3608A51A292D3A47ULL,
		0x7FABC48D6AF7AA08ULL,
		0x5DB934CDBE94131FULL,
		0x189A4F4395BC0E3DULL,
		0xE78FB8F147ABF988ULL,
		0x897798677BF20A81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52ED4DB286B6D071ULL,
		0xFA87FF184E898296ULL,
		0x955E18EACCB4447AULL,
		0x676C63E9D0E53950ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2624AA22BE9C80CULL,
		0xE07C54B250DAC37CULL,
		0x781281A4CF5A1462ULL,
		0x9BEA2DBBC3906B06ULL,
		0x697F62A0F404D0B8ULL,
		0xEA86E48195727240ULL,
		0x0F44DE5B19BD69BFULL,
		0x7708CFE2BD6D6074ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4AEE8664A0C608ULL,
		0xB0823FEE7FD7B90CULL,
		0xBC4B832AA177C6DFULL,
		0x47390963E1CCBC40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE973CD0EE6BB30ECULL,
		0x1A33E7FA3165778EULL,
		0x65574AF9BB8F9176ULL,
		0x27428FE00680005FULL,
		0x581BB134CA4BABEDULL,
		0x09ECEF403CBB49E9ULL,
		0x718032CDE1AFF86FULL,
		0xBB9F2C9DF19162BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD901AE4EDF6BA42ULL,
		0x935F6B8335327031ULL,
		0x3E5ED5893BAE71F1ULL,
		0x00E32F51E214A8CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x564998ED11F3F776ULL,
		0x622C57D69644A6FCULL,
		0x285888150CECD6AFULL,
		0xA2C24ADA25BE0A64ULL,
		0x139EBB823CDE5B41ULL,
		0xDB20A8FEA2326F9BULL,
		0xF637F411CBC87A44ULL,
		0x68F7845DFEB1982DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD96E421AF5857CULL,
		0xE9056DA2A9C13801ULL,
		0xB4A6C2B94CAEFCE7ULL,
		0x377FF0CDF41AA136ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF275AF6CA9F668FDULL,
		0x78FBB65FBB121000ULL,
		0x45F20FF2CB9A26CBULL,
		0x76C905E158AAAD40ULL,
		0xB3A520D9CCC45F7DULL,
		0xF8C1ACF9F0063DE3ULL,
		0xC8C65DE955D2B2EFULL,
		0x13F9FDBFCFEFCF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CF88FC10F1C95FDULL,
		0x65BB63795BFF3FCDULL,
		0x1364009588E0B66AULL,
		0x6DE4B05A36436B86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE80805BA54309450ULL,
		0x9CD65BF3D728A86DULL,
		0xC52FE49B76361DB1ULL,
		0x3D12F8A8569BA129ULL,
		0x1FEAAAFB21D2AC64ULL,
		0xD1A2F1A73E5D9D71ULL,
		0xC84A08985E8D8035ULL,
		0xEE222D9B2A656EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4DD67015976306DULL,
		0xBB063AC7190E0738ULL,
		0x802D2B397F3725AEULL,
		0x1625BDB0A1AA112FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x644FAB9D0FB82A35ULL,
		0xD2C7C281071C49B3ULL,
		0xCD89BB634D4BEBFFULL,
		0x57F3ED9AFBC9A424ULL,
		0xFC275C524CF84A58ULL,
		0x0B7770BD773595B7ULL,
		0xC508F3F11860525BULL,
		0x1C7D39976FD9D2F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2275FD47C9333F0ULL,
		0x86827EA0B9108302ULL,
		0x0CDDF12CEB982583ULL,
		0x128A7A15961EF4C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD13122A40008DA32ULL,
		0x24775F15F03200CFULL,
		0x393D8B949B2DD5F9ULL,
		0x5003164646C79D62ULL,
		0x7F18FF0B579FFDC9ULL,
		0x85FDFD5847637745ULL,
		0xDB7093731BD4558AULL,
		0xD0ABDA99F1283938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEE6FE5301C88AA2ULL,
		0x082AFA3088F5B520ULL,
		0xCBF36EAABCB28889ULL,
		0x4985892012C01BD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x877436C48B3E7770ULL,
		0xEA60846031CDE503ULL,
		0xA3976F8305A4B74CULL,
		0xD6748EB715DC691EULL,
		0x1F393593FF3B8C86ULL,
		0x66D78E52835B3676ULL,
		0x1577E0B9A489F05EULL,
		0xCA91F1EA8A211140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F22ABC6E1557DBULL,
		0x2E5FA49FB157FA8CULL,
		0xD362CB11721E6550ULL,
		0x681E778796C4F8A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0525F8B2097F8EBAULL,
		0x4D9BFEF22855C360ULL,
		0x2170B6517269343BULL,
		0x463B763D53012621ULL,
		0xA14960AC72475754ULL,
		0x788698D2098BB77BULL,
		0x7DD17C8C0C37978BULL,
		0x9A4B3EAC9A6CE4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60A524B0016889CULL,
		0x3196AE1F9312FFB9ULL,
		0xCE89331B42A9B2EFULL,
		0x2D66C3DC3F2B1A8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4057ABE6770A9998ULL,
		0xED3563E203C3A9B8ULL,
		0xDFA2685D0A2E0A23ULL,
		0xD61FA93C11BC849DULL,
		0x68ABF712BD262370ULL,
		0x2FAB3605FE3C8456ULL,
		0xF5BD96C913027E62ULL,
		0x3B7C5ADEBB156079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9DE58AE8AB3DDA1ULL,
		0x009F68C5C0BF4E8BULL,
		0x59C6CA35DC8CCCB7ULL,
		0x2A95264BD6E8D6B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x068491C703F866C9ULL,
		0xED957F68E33E3E66ULL,
		0x41623FBEF5992079ULL,
		0x030FCD4B2C100C07ULL,
		0xE50AC0AF667BEBE4ULL,
		0xCE68689B43A4D26DULL,
		0x4447AB03557F11ADULL,
		0x7296BE2A2972728AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061D2BD03A5D6D27ULL,
		0x91150674EDB57AB6ULL,
		0x6405A23DA675C046ULL,
		0x0570078D530D0C8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD08F7AE2DEE1232AULL,
		0x99AD840222779FF7ULL,
		0x129856CE8D7722DBULL,
		0xE416EC86759FD581ULL,
		0x5F839640D4B99BBFULL,
		0x95B5589CF9205B3CULL,
		0x86390BCC9F0A2EE1ULL,
		0xC931A6374D2E97C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE17C882726E460BULL,
		0xD298AB4F1D452AEDULL,
		0xFF10172E28FA1857ULL,
		0x417598BBEA8A5D1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C328326B01D8728ULL,
		0xBB961AE75F379EDDULL,
		0x25DC350858217D08ULL,
		0x3568F15A4BE3422BULL,
		0xA27F0AF79084CD55ULL,
		0xBDB45F6A9D2004B1ULL,
		0xFDE9BD72BE0460ACULL,
		0x42459163EA7F06DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B0E23E623D40342ULL,
		0xE45C44BAB1F8513BULL,
		0xD68E54108CC7D6ACULL,
		0x0BBC862F1ABE471EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EE4959FBB753390ULL,
		0x4400A2FE4CCA1926ULL,
		0x485F816DA2A7E2D8ULL,
		0x6857AFDF6A021AB8ULL,
		0x0CB0AF5F5E4A125FULL,
		0x18BE719C1B0DF535ULL,
		0xE312A06CC44F63D6ULL,
		0x9DCE0FF84E8BB408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x011E9DC7BA73F127ULL,
		0xF045802A50DC7F06ULL,
		0xFD235192C670B49FULL,
		0x54EE0EBB12BED409ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2A6403A17E1094AULL,
		0xC15BB6EA4690CCABULL,
		0x74264A3C5E0DDDD7ULL,
		0x58AE166D2FD41C29ULL,
		0xC5F631018F6CDDC7ULL,
		0xA27E156FD1C6D71FULL,
		0xC9C2DCBD3B8CE5F3ULL,
		0x52420CCE05A6870CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x553186756209F6AFULL,
		0xE012E5836A14BB63ULL,
		0x67130E5334F80001ULL,
		0x0E7BFD02068C280FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD26C8903D295C9CULL,
		0xFD1B1260CCF0DEF3ULL,
		0xE2D1762DF9D71787ULL,
		0xB0D62DEB429D3D75ULL,
		0xF78AFC2E60457392ULL,
		0x14632717DAC9E162ULL,
		0x92DA18CA5FF4769BULL,
		0xA40E0E2206674178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BC83772877887FEULL,
		0x03D2DFEB46E853A4ULL,
		0xAF3124383820B28DULL,
		0x0AEC46F835F0F55BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC57149D57C4615AULL,
		0x688D32B11F14BDB3ULL,
		0x4770E9B7BDF4D8BEULL,
		0x0EC01CAE7F2D1282ULL,
		0xB1B285CB41530059ULL,
		0x87CDC0688677C0D1ULL,
		0xDB323513964F0E36ULL,
		0x0659FA0D4F320419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD6F0C90A166EB6ULL,
		0x9117C23514DB5CD4ULL,
		0xD0E4CAA00DB0F4D6ULL,
		0x001B3AA84099AE58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15B812B901A064E7ULL,
		0xBA9A395A5AB9956BULL,
		0x575AFE61F2210A39ULL,
		0x264534BA98DA40E9ULL,
		0x22C22F5D40C0E6DBULL,
		0x5F904C8A077C22E9ULL,
		0xE2586BF53E0DB332ULL,
		0x45CEB0A019F4BA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E8B1A909E42AAF8ULL,
		0xEA0595D77726C406ULL,
		0xF07B04C92829A3B3ULL,
		0x02F36C7E732DE5CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2748669D80D6F672ULL,
		0xF0C92B869C14C3D3ULL,
		0xF1B37855BB071C35ULL,
		0xFE178A3C44792176ULL,
		0x4570B1ECDE47E840ULL,
		0x9F713C141DF3E356ULL,
		0x9A6AC8BEAC9B58D0ULL,
		0x864CE58A7D702B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7602CFC67F8372FDULL,
		0x9B9816830E4882A1ULL,
		0xDD8D44A35A164B2DULL,
		0x6D819CCAE31F9511ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE88F5121B703D36AULL,
		0xDC851BDF59556429ULL,
		0xF15FB2555F33A2F2ULL,
		0x1CE9F93EB743124EULL,
		0x302C4CDE27788E94ULL,
		0x8D5B600C1AC01E80ULL,
		0x6B448891DAFF871AULL,
		0x6E1C3BFAC7081860ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F22BA1B92E8FFC2ULL,
		0xD8155DAB51D9EB31ULL,
		0xDD8BF7FBE121B0E3ULL,
		0x751AE0784276B09EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B32A28D2D6F870BULL,
		0xC15041B006DB40D4ULL,
		0x3AD2EB45475D93FDULL,
		0x4A0EFD1F80E94186ULL,
		0x5ECF8A126159C164ULL,
		0x990FA40CFAE80633ULL,
		0xC08B5AB1202A08D8ULL,
		0xFFE2FC8DCCA76472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E012147A0C24187ULL,
		0x79A29B9D454C2C74ULL,
		0xCF8261900D9AE424ULL,
		0x45C07A2BE1C22A8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9A838E674B24B86ULL,
		0x958F0399B58B4137ULL,
		0xAB31B6877AA7B4D6ULL,
		0x4FD5F291B668D0B9ULL,
		0x044F4C75091B2B2CULL,
		0x40F51E8ACB40C19AULL,
		0x2058755775E14E16ULL,
		0x3DDB2D10FC7D3450ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6D9245CEBAB564ULL,
		0x39F18C33E127FE14ULL,
		0x78532182FA194C24ULL,
		0x7E5EA31730FE949EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x973B84EDC33B5C94ULL,
		0x4570D4A49EC98AD0ULL,
		0xBAAF3C08E686949DULL,
		0xB8829C7011335F63ULL,
		0x90E3026FD416F36CULL,
		0xE0B6A4086A1995B8ULL,
		0x0AD5E85EA50896D6ULL,
		0x608B879CB281C5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18EDE1873EA380D6ULL,
		0xA08D2DE45E95C436ULL,
		0x566FBA1565CCF882ULL,
		0x0D38BDB29076B9BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2605EEA855BD5F3BULL,
		0xB744532157F67AE6ULL,
		0x204BF6CE78EF80B1ULL,
		0x6DD8EF87B0698D08ULL,
		0x048EE71021B5EDBEULL,
		0x0770F61984FF0C1FULL,
		0x96566FE159A3B974ULL,
		0xA1D7B87C5B9F0057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD33C3B0D56BEACFFULL,
		0xD208DAEB15D24780ULL,
		0x71209241C73D07EAULL,
		0x73DE51FD4A039A08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A8BA87DA88C99F4ULL,
		0xF62457641BC9E553ULL,
		0xE2A28F2FE03FE9DDULL,
		0xD67F0568A6E68FC9ULL,
		0xF6F3EB961F835B58ULL,
		0x2B3F5792496982B5ULL,
		0xA6F4C234BB1151CAULL,
		0x7285C01A285F7712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22C0A0C6560C2B9DULL,
		0x618B571B01734C56ULL,
		0xAAF76303A4D20DE0ULL,
		0x5659894AA5123C8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ABB9168D1DAE96CULL,
		0xA4868546BD089882ULL,
		0xE28AA0CCF4123B76ULL,
		0xFF348D4A18D14C11ULL,
		0x55722A5362C5A45AULL,
		0x58AAE0C0CB0FB0F3ULL,
		0xD52A9B9864F091B8ULL,
		0xEF484350EC1C07BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19ADD9C97B315433ULL,
		0xCDE3E1E4E15CDCA1ULL,
		0x86DDB96BEFC7DCD3ULL,
		0x03EE8B4D24FA7219ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8EDFD5B9FD514A5ULL,
		0x1B3E212A82F89D4FULL,
		0xED8CC1BFF3C6CFE6ULL,
		0x47DD5E234EF803C8ULL,
		0x459A05474D44E734ULL,
		0x049C50D7B9506FD8ULL,
		0x258DED90982D9F0BULL,
		0x938A0AE54E245E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DCAC5F1180F69A1ULL,
		0xCA72213004E9376AULL,
		0x809E05368A8C6B88ULL,
		0x2E5AFC2CE85E0B40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB40D08D50FCA23C7ULL,
		0x768F0B249FADFE13ULL,
		0x75448459EED7CAD8ULL,
		0x791F57A6F731E45FULL,
		0x05C5417C996E113CULL,
		0xEEB33A874F696346ULL,
		0x355B46F33F2404BCULL,
		0x20FC1AA4F1142B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F54C153D620B36DULL,
		0xE529BB3A6952BA78ULL,
		0x60D10C754E307EE3ULL,
		0x5E8B4C22C0305C13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF43A667F59C51B6ULL,
		0xB0FF5333382E7B0CULL,
		0x8348CB6ED939A7B2ULL,
		0x4E7E1DE95FE96BC7ULL,
		0xA6B0D072657BA764ULL,
		0x9CAD5596E516B466ULL,
		0xF71F1D13A37528DDULL,
		0xBCE78A6D8541103EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD82976305F72EB6ULL,
		0xF2BA0799398D4249ULL,
		0x31E71C591C9DB897ULL,
		0x58DCAA2B2791D520ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56FC8AF640F42308ULL,
		0xE00FDB8A6CCE8C7AULL,
		0x9B6420191029DADEULL,
		0xB3B9227D1DE281FEULL,
		0x34FFC2C4EB44D0B1ULL,
		0x63E179E5C7ABD7A1ULL,
		0xF53A599D76B42AACULL,
		0xC119820C0DF1D933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F374312D2B219CULL,
		0xB387F3A610508E68ULL,
		0x020D6D78AEE83075ULL,
		0x5D8270472FC8BFB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F4E4A865229A5A1ULL,
		0x263F6F01D7DC41BEULL,
		0x72C5373EF7AC9BBFULL,
		0x35ED4376C3F0A8A9ULL,
		0x6BD1C353733BEBC4ULL,
		0xBA74FFFF74501206ULL,
		0x1782CD5018879BEFULL,
		0xCDA1D94DF858A516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107148E96D0EA940ULL,
		0xD39D6EED1BBEEEB2ULL,
		0xF02FB1229BCDC154ULL,
		0x3BF38509A11929F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x873C5093275D23F8ULL,
		0x9C995162375CB5F3ULL,
		0x0BE5EA2B1AF94089ULL,
		0x964A4F0C88DBDA04ULL,
		0x939C5E84D03224A9ULL,
		0x24785F35229EEDC9ULL,
		0x15BDCE0E7879E00EULL,
		0xD12842F0FCAEBF0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7072584A0ECE99BBULL,
		0x067773455AF401DFULL,
		0x46128050FD1082A3ULL,
		0x22443ED20ACC3641ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18BD2125EEE7EDCAULL,
		0x538B6AEF394F03A6ULL,
		0xFEB618903D84BEFEULL,
		0x8D351A2E3B7ED3CBULL,
		0x049240CB791372D5ULL,
		0xF338E79E64160923ULL,
		0xEF5B90C96F580B43ULL,
		0x9B2C413F44BD00FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC672BF59E7CAFCE5ULL,
		0x6DFDCC7214945ED8ULL,
		0x864D9676C4966B14ULL,
		0x15C6C9926F8CF97DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCFE1E332915A7E4ULL,
		0xE3CC229CCD135C3CULL,
		0x537C724294A9B095ULL,
		0x57545CC5E0316A27ULL,
		0xF5F4AB60EA1B433DULL,
		0x7CB6B8F0848DD62CULL,
		0xECFAF69C5D54B84DULL,
		0x9222F4B161234461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F4F8E95E921A636ULL,
		0x66EB96507A2126E9ULL,
		0x80BD0D786F3D0C16ULL,
		0x0884AF1A4B6D90B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A4817419D108570ULL,
		0xD2BD43937B871E59ULL,
		0x6132C4B454A103E7ULL,
		0x24C0E402E5CD4A7EULL,
		0x6E4069D96550A321ULL,
		0x846BB7E27B69CFE4ULL,
		0x1936F4EFD9A9CBC3ULL,
		0x389D3A821DA59354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D7CD86A708BD99ULL,
		0x7ABA8F31CD3BFA41ULL,
		0x1F5B204EA3D542EDULL,
		0x0C1793534C6128FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEC5D1862CE4AF9CULL,
		0xFD018105D4456084ULL,
		0xDF35AEFE347AB793ULL,
		0x3025533D443336C9ULL,
		0x80BA2AB0CC634750ULL,
		0xC631EBBA9968965FULL,
		0x29CFCCFC7D9E74C4ULL,
		0xD08142B790E348A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6827C483A14A16ULL,
		0x686A7EB899CBB2B1ULL,
		0x140E1C78DA000CC9ULL,
		0x23553A7CC5EFFF02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0BC77CD253C5EABULL,
		0xB5B9B960A55A0C30ULL,
		0x3208E71921CE115AULL,
		0x282DE9BAC7B65A07ULL,
		0x501E1E25D2DC6D35ULL,
		0x13A92EAFD877498CULL,
		0xCA4005E9C9F00620ULL,
		0x31CC536BDC3F0CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8534F16A71F495A6ULL,
		0xA0D6A77AC70EF704ULL,
		0x3789C7CD1B6EFA1DULL,
		0x0C824BBD791245EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B671775B3C90526ULL,
		0x6FAAD090946A2793ULL,
		0xD9BF3EE1341AD416ULL,
		0x522EAEDD9DACF7C5ULL,
		0x30C9473D110FBB10ULL,
		0x3EF485BD86CC5EBDULL,
		0x76BE99C84E797C46ULL,
		0xE43C12624DC6EDDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4947AA863C1ECE92ULL,
		0xC7F6AAB296C037A8ULL,
		0x7A0A129CDA234683ULL,
		0x33196975293446CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFCA69653EB05AE8ULL,
		0x701B36D7F831C5F9ULL,
		0x1BA0E51ABD99E9F5ULL,
		0xA00BCB0D7612E31AULL,
		0x32E13EA8F0165293ULL,
		0x9333418CA3B945EBULL,
		0x6F0DBC52E0D86A15ULL,
		0xB4A88EDFB06AA0DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D39B678E200A0BCULL,
		0x49B6F1B845B226E3ULL,
		0x97AAD9681DB9A929ULL,
		0x71110041A5E6C386ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x935DB7BE8D13F950ULL,
		0xDCC294F05F80F44DULL,
		0x35AAEFDB2728A5DCULL,
		0x9991CFC3287E06D1ULL,
		0x4962E3BAC7C20821ULL,
		0xCE354C8EE05238CAULL,
		0x0E6D9AB5DF05D3C2ULL,
		0xC6F0B850B116BBBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780B857833E132AAULL,
		0x78ABF225ABB56254ULL,
		0x59EFE6DA420614C7ULL,
		0x214D2BBD71DDE52DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40D9C4A63FF8DB4CULL,
		0x42026C1312A4D110ULL,
		0xFCDDDFF98AEF2D0DULL,
		0x908BB30322ACB51FULL,
		0xDE5C9542AB654F1CULL,
		0x6E220EEF16DA8576ULL,
		0xF37113B4DDE6E807ULL,
		0xC1B3E520539FD8AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4297EC8BB1029DC2ULL,
		0x9B10A3907714A0B5ULL,
		0x1FA6CCD27B359E27ULL,
		0x513FB5CF8C66DE80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F3F6A330E498957ULL,
		0x3EB120535F936B0DULL,
		0x913549B9F2517883ULL,
		0xC7F22263DEA1DDD3ULL,
		0x2A7A400F5A30A976ULL,
		0x5172FFA92D7FD56CULL,
		0x0C31E0109951E797ULL,
		0xFE7735A8C66AE781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD64EC7A7182B692ULL,
		0x55C31370208D191BULL,
		0x609C8C30B479D8F9ULL,
		0x0DA4197152803AFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF26167C19FA0D2AULL,
		0x2957909B73A4374BULL,
		0x4C06B67AB1DE4A4EULL,
		0xBA489848AA523838ULL,
		0x6285C9A42403BDEDULL,
		0xDAC94ACCC38132FBULL,
		0xD43A5F9E0FEA6C81ULL,
		0x26401C3ECEE418ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0204D972883F3CULL,
		0xA338AB0078D1C89CULL,
		0xCCB0E7F10EAA6594ULL,
		0x67CCC99B602DE205ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE309DBF63B2D5DC3ULL,
		0xBB6210F39EF05842ULL,
		0x1A424A5EE178ECB6ULL,
		0xE4FB64ABE1900C52ULL,
		0x49956410D1BCD126ULL,
		0xCDC8A21076B12018ULL,
		0x59986B7F26B72EDAULL,
		0x7F91BD812EBB9033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF36B6755D346C4CULL,
		0x472A1F653D3B1BDDULL,
		0x66E23F3EA0A9E131ULL,
		0x549D85D8D16773F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEFF0D83CBCCAEE7ULL,
		0x2A174EB8D951A64FULL,
		0x1FF85E156EB0B6B9ULL,
		0x7A8BCDC58C35A030ULL,
		0xCB9BA74704853A8AULL,
		0xF54BD0B98B5918A2ULL,
		0xE48692B34B09A6FCULL,
		0xF72A145583E79B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2819E20E779364E1ULL,
		0x93584A43888B4E7AULL,
		0x0BF224B2921F8045ULL,
		0x2ACAD2772096B896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D3C4BA758B5B8A0ULL,
		0x93BFBBD967958D8DULL,
		0xDEF95D3363E6FF88ULL,
		0x125A6A7FFC59D9F1ULL,
		0x0A4899E737708428ULL,
		0xF795793F68486216ULL,
		0xF0468746AFFA9FC3ULL,
		0x59138F4BBD6457A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB40323F99369587EULL,
		0x53EFBB42E2541CD2ULL,
		0x897171B1831AB69FULL,
		0x4B41AFBE193EDC21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67E1903221BAC2BULL,
		0x1B93778C1C91C7ABULL,
		0x4C34C5C532AFD192ULL,
		0x67B921D581D34B6CULL,
		0xF86B405E08A85C30ULL,
		0x6DFF131969006459ULL,
		0x68A136A3BDA8E577ULL,
		0xA764E67EEB0951B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA669A6F86B195F01ULL,
		0x6F704D51B2A0AD06ULL,
		0xD422E21359C1E14CULL,
		0x40B358AC65356C59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42274DE87400C36BULL,
		0xD90307F1546EE125ULL,
		0x70BBF26678EA9839ULL,
		0x113165516E2DFEFDULL,
		0x75D724DB632832E1ULL,
		0xC54E766232DB1A1FULL,
		0x321D46D3FE30646DULL,
		0xEF35C278E15C1E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC016C6792BF85616ULL,
		0x22A89A84E0F4C1D0ULL,
		0xE11475DE34198085ULL,
		0x132C4342E1DA7622ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5068CC972E17471EULL,
		0x89BDAC0FDB549632ULL,
		0xD29A9DAEACB98D2EULL,
		0x0FA43F7A92E34450ULL,
		0x974A8A3A9146977CULL,
		0x6533B6E8BB69D196ULL,
		0xE3C46391E8C5F42BULL,
		0x1618E6F4D8D5AA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5795148BE91C3F8ULL,
		0x8F6AD29BAD09B28CULL,
		0xA1C165573A1BCB9FULL,
		0x575687D2C29A9560ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC92A00D5715B6D4ULL,
		0x747F52F5A0C14A9AULL,
		0x9882C5BDA71874CBULL,
		0xFC2CB5725F042F40ULL,
		0x9E7F955171B475A1ULL,
		0xAD20E1F90C8CC49EULL,
		0x22A9640D3A77DD8AULL,
		0x5692D0CE27B3835DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8382CA2437DF2EBBULL,
		0x2760DDED7DA67A26ULL,
		0xBDA79FB454E35761ULL,
		0x55F7B40C43A9AF13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87A70B0EB5AD898DULL,
		0x467EA73822F04216ULL,
		0x975EDD4276E0736EULL,
		0x28031568A4629717ULL,
		0x8F3B279ED5CEA371ULL,
		0xB88B1BF17A5ECAD7ULL,
		0xD2E6FD272EDF517DULL,
		0x788D962846D21845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA6EECA27259CEFFULL,
		0xAB24CD104D025E15ULL,
		0xE5A871136C068C17ULL,
		0x0D075F6327923174ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F9565DAC7B14C00ULL,
		0x5C5C1E0AE7CF7C6AULL,
		0x13F06F95F241DF8AULL,
		0x32F8295DBC249A73ULL,
		0xA218B594629F4C54ULL,
		0xF90ECFC6692A6C96ULL,
		0x6731E863E78266A2ULL,
		0x124F41E4B2821AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4059E16B56A0D7ULL,
		0x548EF57E841B9AC6ULL,
		0x6558EE6A4F9D1BBBULL,
		0x6ABBF1503B7496B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E2CE12E923A3533ULL,
		0x734590EDCBFEE8A4ULL,
		0x88B4D5C49D9E2184ULL,
		0x478A519E62E0980CULL,
		0xE04E97BF9886AF2AULL,
		0x711F1FBA81A8B47CULL,
		0xC7B332F557FA43BAULL,
		0x14C12883563E644AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D7679F363835E1ULL,
		0x3DE4469D0B09B32DULL,
		0x2D4E662FACC42F31ULL,
		0x5C36551D30237B26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25498AD52037405CULL,
		0x00BDFF581798484DULL,
		0xA05FB554A05C28EDULL,
		0xABA1FCF0BF5C9DB4ULL,
		0xDCFBC68EF5431796ULL,
		0x9CADFA3B968F7BB5ULL,
		0xD7AF9A0EF910A980ULL,
		0xD563D8797FD37958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2A9040D882CC560ULL,
		0x4291243070E4A54BULL,
		0xA470938D98D55204ULL,
		0x58741EF9B8C0A0E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA73599103262B21AULL,
		0x5D72FEDEEF29B87CULL,
		0x03943735278F7E7FULL,
		0x86BFDB18309C05DBULL,
		0x71C43E2D920E00E2ULL,
		0x5D51CEEB876B063CULL,
		0xF0C6D188C7B69006ULL,
		0x54EB2D98AB229136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A56D3D3E076D594ULL,
		0x3797B5D5090CA575ULL,
		0xC1175182CCA8DF71ULL,
		0x21A89FC197BD9402ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0E57186347F08FAULL,
		0x1D7C73F2ED8B5EE7ULL,
		0x4F1F99CA667AFDDEULL,
		0x8169CD0B89964795ULL,
		0xC3B4AE7948B0B782ULL,
		0xFDBC5C07C6D7436EULL,
		0x764B9D0BFC0621BFULL,
		0x90F8D67AA80078F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB75786FEBA498AULL,
		0xC7721D1A717F6158ULL,
		0xDE58E991CF64005DULL,
		0x0659A34079A83C76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD13772F43880B317ULL,
		0x7ACE82FF6410B086ULL,
		0x10A3DC6C6F5C1A79ULL,
		0xBA71FE59BDB096BEULL,
		0x283691F3C4590B92ULL,
		0xD99C85DB17441275ULL,
		0xDD107AFCB9E1AE0CULL,
		0x84601480A77584C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9511D235DB86DBBULL,
		0xC80A6184D82B6DEAULL,
		0xE1161DF006DBF061ULL,
		0x60B5097299224BD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x793CA7F99F4ADE6CULL,
		0x0F8421DA7A11EDF0ULL,
		0x115B2ED570C3A411ULL,
		0x72C573F13AE5A60EULL,
		0x1E061C6B30EE3CADULL,
		0x5983E21BBBEE5BC3ULL,
		0x2FDEF19F0D130B23ULL,
		0xB1FCDCDD8ECAF49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE24DFE2E2A7E409ULL,
		0x5917B1F85F738CE6ULL,
		0x2C730C7161974B50ULL,
		0x5E4E3CD46D05F53DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A9BE44C2D9A5637ULL,
		0xCFB038E700A409B3ULL,
		0x1090BB3980BAD193ULL,
		0xFCF354456950A06BULL,
		0x525B97B38AD34E75ULL,
		0x7CEC604B6F6DE8D8ULL,
		0x15A7434C9B8E3F2BULL,
		0x451877503EC71A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x743468F2C8F7FD37ULL,
		0x5AC684198AF499CFULL,
		0x4764B89897D83208ULL,
		0x3E950A2EBADE8C9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12CD92A4F13828F5ULL,
		0x11ECB62A67A37185ULL,
		0xD8CC7F853A5EB58EULL,
		0x72345BE5DF37BA35ULL,
		0x4D0FE9A0171CE9DAULL,
		0x450E7917EEB370EBULL,
		0xC8484032596CE9EEULL,
		0x2ADC681660C94012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x832A40685F82E048ULL,
		0x5212AFB7D6463472ULL,
		0x938606FE80896EECULL,
		0x4EEBCF383D173CFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7226E71803344495ULL,
		0x9EBF6BFDBBBFCD54ULL,
		0x965826019D9CF11EULL,
		0x6C7FDF5AE5D734E6ULL,
		0xB99CB913E2C0114BULL,
		0x6596620143A4A249ULL,
		0x52FA4B89B7DAC81BULL,
		0xF6748064DD4462CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF6A600BABB6DB35ULL,
		0xB311F82DC62FE445ULL,
		0xE77F5C72E816A52FULL,
		0x01CAEE53BDFDDF60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9107C107F1537DC7ULL,
		0xD47B25A23CD0DE6FULL,
		0x2C3C3B664C98CFD6ULL,
		0xF2D6348B05EE7DE2ULL,
		0x03D1BAD4EA177226ULL,
		0x0EBB134FE5D93F39ULL,
		0x55FC9299A7E7FDE2ULL,
		0xF26E021945D4F41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22297CA2B0CE74D6ULL,
		0x0440037E5B1040E6ULL,
		0xEFB9FE3539087F65ULL,
		0x6F2A844B638AB9F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BF686BBA1A02CA1ULL,
		0xED254D5E5C2E388FULL,
		0x459BF0C1285DCDBDULL,
		0x1B3706E4D1D20965ULL,
		0xE81E847F31A62FF1ULL,
		0xE9AFCE810092C35CULL,
		0xBD85A23C54FE82EDULL,
		0x4BC6D0C0A7686E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107E319D004B4C09ULL,
		0x9D3DF48471F7385AULL,
		0x677205B5C6253D0EULL,
		0x5ABA037DAB52661DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3B6C48CC944A79EULL,
		0x3259E6A794A63F24ULL,
		0xDC81CFFBB302A9EAULL,
		0x6A77C5CC20321714ULL,
		0x4E6E2FE4DC94E264ULL,
		0x6CF859BCD63C6418ULL,
		0x0AB7CF9B70179B4FULL,
		0x706CE5016DA3E60DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7811E085875E44FCULL,
		0x5F3738AF619D1AC0ULL,
		0x73CAA10E5683B7B4ULL,
		0x1AA1C40266863D04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73B068F4A82FF2CFULL,
		0xC3608B87822A8A13ULL,
		0x570C067286968BBCULL,
		0x06C0A9D326A5E78DULL,
		0xC2494385BDA37CF3ULL,
		0x9C3A0107B901A794ULL,
		0x2BA1197CF0785BA7ULL,
		0x2EAE4980ACDAD76DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A906ECECE747FD8ULL,
		0xF3FCB2ACF8696A28ULL,
		0xD0F5CEFE3874269DULL,
		0x749F92ECCF21E1C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22A003E11EAA7184ULL,
		0x53B7754A04B3C395ULL,
		0x26698CF1DE5411C4ULL,
		0xD1CA941A3D0A01FCULL,
		0x15A5F1D5C93AAE3EULL,
		0xF8342337A70D8D91ULL,
		0x81FDE5EF77826E4BULL,
		0x3EFA6DA6FF18F880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5941E99CFD605034ULL,
		0x2B74AF8CD0B6C71EULL,
		0x7219AE7D9BB0710BULL,
		0x2AF6DAE41ABEE50FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1052A291B2DDEF3AULL,
		0x41F880353CE1C0CCULL,
		0xAFA78CF273A4EEC8ULL,
		0x66F07D2C1DEFA2BEULL,
		0x5E790A640A57743AULL,
		0xEB03CB31A9945705ULL,
		0xC44FFB2ECF5070EAULL,
		0x5795B4C0999AFD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x164A2D6B3BD931C4ULL,
		0x2488A99468E6AB98ULL,
		0xD386D5E53995B1A7ULL,
		0x672951C2EAF13EF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x497FED9093DDA4F5ULL,
		0x4B213A2EE12DEB7EULL,
		0x0EFC0803E475770DULL,
		0x8A07F1E67945FB9DULL,
		0xAF2DB7F99348B0FEULL,
		0xCF664C562DC26976ULL,
		0xDBF97C96885EA384ULL,
		0x6677FA838FE4AC0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A493C9C70A7ECF6ULL,
		0x14508EF9AC09931CULL,
		0xB604865C2281BCC4ULL,
		0x3FD7216DD5378539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x350C500B3F7C4A97ULL,
		0x757979B60FFC5F5AULL,
		0x2501E835E3B7BB50ULL,
		0x901F3EABEB5F8595ULL,
		0x7E3600DD263D8562ULL,
		0x3CDB85DE9C420869ULL,
		0xF16F12130BA5061CULL,
		0xFB45FA263CB51F37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11070DEEC9E1CB4ULL,
		0x7E0F58C141C99F02ULL,
		0xFB7E97099E36A381ULL,
		0x5C826058EE4227E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4CC80A9E1715146ULL,
		0x8E84606EF38A43CEULL,
		0x6BD3D352F4E4B081ULL,
		0xA61F76C2FE161827ULL,
		0x40F836C70BAC2DF5ULL,
		0xFF2025018FB42BC4ULL,
		0xCBD94DAD89FBF4B2ULL,
		0x086C753B004FBF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A4A2359D0023DDULL,
		0x6D49DEAA4848C2F0ULL,
		0xAE155B15704B0313ULL,
		0x6638DD8509EC785BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE98D3D8943C0FDC7ULL,
		0xF7B10E00CEAD6BCDULL,
		0xA98B7379BC147C1CULL,
		0x57EC1547539B4D2CULL,
		0xDC0EA5E6CF27EE7CULL,
		0x7753DC582B05D9D1ULL,
		0x6CB2459A5AC210BEULL,
		0x057E56D2C2F34194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B9DDCC03AE6455ULL,
		0xAE23C317318BC0F4ULL,
		0xCC01C86334E2F862ULL,
		0x28ACF89043B70934ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x557563F93B06907CULL,
		0x7DCDFBC2F1269797ULL,
		0x4111C8BA946D373AULL,
		0xB963F1382D44CD1BULL,
		0x0D2FAA6F78EB4D8EULL,
		0xBFF8C72B0AF0811DULL,
		0x185B5A0E2FC3751CULL,
		0x190445FF49A77DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A88B0852DF41428ULL,
		0xFCBB8C2690D9C1E7ULL,
		0xDEA126D5AB70997EULL,
		0x7006551D1C217304ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x624AF149B6228066ULL,
		0x5683CFEE25D61869ULL,
		0xDB6B6BDC358F04CEULL,
		0x67DECD1E060C6A00ULL,
		0xEDE8CE4B7E57CEC6ULL,
		0x5B5F699A742D70DCULL,
		0x0F76768AAF7373E1ULL,
		0x192B4398D8C6D854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D9907E772B3262ULL,
		0xE6AD7CDB6494D934ULL,
		0x2701047240B23841ULL,
		0x244AD5CE3390867BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD2F47824C70DC59ULL,
		0x8401AF1CD453A59CULL,
		0xB9449EFA68DADE5DULL,
		0x6556177FEAFAB2F6ULL,
		0x3961F3F62CE44BEBULL,
		0x2F4D8413799DAE73ULL,
		0x18C37F6072CB62C9ULL,
		0xBA885F4C4261EBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B97E0CF6542563ULL,
		0x89834A00E1BB8AB7ULL,
		0x6649874B730B883AULL,
		0x15943CD1C583B5EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC14152B36E4FB768ULL,
		0x51820C3E1767891AULL,
		0x2D072A58FBCA653AULL,
		0x46A2B8BC0A257908ULL,
		0x75526985C2FA13E6ULL,
		0x8A6AA339A28FD934ULL,
		0x512B1467C13D90F5ULL,
		0x70FA7E6841A3D587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7CFC8E5F6EAE12ULL,
		0xDD5646CC38C1C6E4ULL,
		0x396C31BFAAEDE9ACULL,
		0x0BD17C35C8772B1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85B7EA8BA8CE2275ULL,
		0xA8B1DA22ADC95D0CULL,
		0x7CE98314DAC237B2ULL,
		0x2F0B4E3AAF7186F8ULL,
		0x516B934B3A6EE62AULL,
		0x257D9B9BB819825AULL,
		0xBA31C8BC55E5C8A5ULL,
		0x21ABE8D2F143473DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BAFC7B655444D6FULL,
		0x3956F3400192B674ULL,
		0x204D4F099ADE0036ULL,
		0x2E8FDD8A7F6E1A22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36DE3C9434FE690FULL,
		0xB68CD4AB45DAC380ULL,
		0x6A2EA191A4DA2CB7ULL,
		0x062C6D48F84AD5E7ULL,
		0x3BEF4DED4523E1E1ULL,
		0xDC2B0237D46F7032ULL,
		0xBBAA9B05202718CBULL,
		0xB1B7C01D7AA286B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C63CDCC7851F451ULL,
		0x64EF28F4CE656AF5ULL,
		0x4581A4546AA7DAFAULL,
		0x6772F1A92C6AD4BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6F003AF0C027D9FULL,
		0x53D466B358FA806EULL,
		0xA368681884BD097EULL,
		0x45EE869AE72296F7ULL,
		0xCAE5FA63E36A8840ULL,
		0xEAB8EE3E9376192CULL,
		0x7F04ED7F04ECAACCULL,
		0x9DB69D64C4A97F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5132E82CDD2BA9CULL,
		0x2B47C3FD3C823D14ULL,
		0x7E23A8F33FDE63E9ULL,
		0x2F09E390184B73B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6972DFAFFD294388ULL,
		0x884B7C14BE95F75FULL,
		0xA77961E9E3F131FCULL,
		0x80D1C285DE64E49CULL,
		0x1971DD97837D331FULL,
		0x75DE49641B9071C6ULL,
		0x61C97392F614CB85ULL,
		0xFFC81E926FC6D547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3059C42D81BEDFC6ULL,
		0x074A60F0D606DAC7ULL,
		0x2B6089BA6B0767CCULL,
		0x78864C4275E88D35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC794EB2299C9FBAEULL,
		0xC3BD79D37CCEB2D8ULL,
		0xE9FACB1D8E87E90FULL,
		0xC44821A887DD36C9ULL,
		0x7CF761E3F2D528BDULL,
		0x4C36BD4270951A77ULL,
		0xD561466C1E1F3C8FULL,
		0x7BA5B9602754AF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x544D72F8A56E0A8EULL,
		0x13DD91B032F0A095ULL,
		0x966B3F2A072AE655ULL,
		0x1EE1A5EE5E6F3BBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEF48F866050CF33ULL,
		0x09B0462A6B5A67B8ULL,
		0xC3D736FC38EF6344ULL,
		0x28E2DB647D731651ULL,
		0xB1219F1DEF24BDDAULL,
		0x843032CB7BD652DFULL,
		0x494520FCE35C91A3ULL,
		0xBE223C1CBE38A36CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39F22DF7DFC501B7ULL,
		0xA8D7D05ECD2AB4EDULL,
		0xA41A1C85F8AD0189ULL,
		0x61F7C7A8B9DB5864ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E32A1E49BE46817ULL,
		0xC1B6AF33F272B417ULL,
		0x35BDFE0CB11F28BCULL,
		0x27F584DB5559525DULL,
		0x65468C19F6006AB7ULL,
		0x8CE4292167346915ULL,
		0x70BF2EA34C9E9E5DULL,
		0x25D8616139371295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26AB6DBF1FF44012ULL,
		0xAB94CA29443A4D44ULL,
		0xF21EEA4A10AAAA9FULL,
		0x4613F949D386148BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88643ADCD440C3E2ULL,
		0x90C0330C5D8316E2ULL,
		0x35714662DE59A870ULL,
		0x87D675E5F0BBB34CULL,
		0x2F384756A8519852ULL,
		0xAE2C9C54760CC257ULL,
		0xC307427FECFC7EA3ULL,
		0xB86C61E4BBBD993CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ABED1B9D05D6423ULL,
		0x6B5F6795E367EFD3ULL,
		0x288525600BD474BCULL,
		0x67ECFDD9CEE07251ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0169FC8D240A641DULL,
		0x3D165595045C9FF7ULL,
		0xAB3A2C753542C8FFULL,
		0x755B90B2B3B72A18ULL,
		0xAABD8D37B89E6511ULL,
		0xE74DC152AC68DA6AULL,
		0xC123495F886535A9ULL,
		0x0635D40E82CDBE3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x598CF2D28B8D64C9ULL,
		0x92A107DA9BED0BCCULL,
		0x567710A37448C037ULL,
		0x61590ADA1E41671DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BAD63E56FF0A99AULL,
		0xD397D62A9BC30682ULL,
		0x5A4F710FD8C285DCULL,
		0x742CA2A16A260651ULL,
		0xEAAC5E636F0FA76BULL,
		0x816F8AB098D5652DULL,
		0x22C9FB1F2A456556ULL,
		0x124ED98B39296281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x114366A7EC4383EEULL,
		0x0A266C614B700B53ULL,
		0x844AB7B01F0F90B4ULL,
		0x2BE0ED4BE64AA57CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E282D778A5A498ULL,
		0x93FF389E7927A970ULL,
		0x5B514C8603F0F875ULL,
		0xF8F0D2D9C64765FDULL,
		0xC5C2EC76FCBF49F3ULL,
		0xF6182E7CD35F7604ULL,
		0x083B49D41B8AEC0AULL,
		0x8DA90A735E11D142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D19C80FD0AA1EEULL,
		0x1B961F25D9532E25ULL,
		0x941E42021A900216ULL,
		0x00085FF9BCEC75CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11FAC96081C2AA98ULL,
		0x98A7E806CB29A5ECULL,
		0xA1B5964AF232E73AULL,
		0xCC49076A5F89CD2BULL,
		0x225E354972EC61A3ULL,
		0x12EA751026F5928CULL,
		0x695CA168566E85C9ULL,
		0x85190EBFB845358FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF6B24790D92BD5ULL,
		0x6775486C939D66B9ULL,
		0x45758BC7C69AC313ULL,
		0x0E0137DFB9CFC075ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CB261B3B3593487ULL,
		0x940C39466B485579ULL,
		0x8E823B5C1457A811ULL,
		0x1CC0F38D252A4896ULL,
		0x137D2231ACE4612FULL,
		0x9BF085A3E8548AEDULL,
		0x287E8D1EE491B13AULL,
		0x0CEA1DC096358774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x314575135D3FA1CDULL,
		0xB9C00F9AE7D4F4AAULL,
		0x914B2DF201F7F6C4ULL,
		0x07815E23711C63D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D6971C942384E0AULL,
		0x8DC0C04D43C26B22ULL,
		0x5850539EA2957EC8ULL,
		0x623B06A024AA6808ULL,
		0x6E7E4E80E6E9F044ULL,
		0x7A2CB198AFBB3EABULL,
		0x1A47EB5757EA0BF1ULL,
		0x342D930B1ADBBD20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42918EB88F1F952ULL,
		0xB0631CF7598DB894ULL,
		0x3EFD4295AF5344A0ULL,
		0x20FEDA4621487ACCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C26127A7A844776ULL,
		0xBA4EF177E29BDD2AULL,
		0xDB94EB151487B7CDULL,
		0x5B5A891C2AADF858ULL,
		0xE1713A11B3F026FAULL,
		0xCA74928001A28BB9ULL,
		0xF6D6C95175484E45ULL,
		0xD61E2FAD1A497093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F4B11B302A1552ULL,
		0xC79CB07820BC9AC1ULL,
		0x7F76CD2C7D435629ULL,
		0x23D59CCE1194AE4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC877B8970B460C2ULL,
		0x58351279440D453CULL,
		0xF9ACEAA023B3A172ULL,
		0x5861A52031076A31ULL,
		0xF5ED0DA9A2DB4CECULL,
		0x33A756281332518DULL,
		0xF4258A156126EA48ULL,
		0xDC9F627BFAC9D4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB782B79D41D0B0ULL,
		0x030BDC6C1D85604FULL,
		0x373F69CC8F7A682AULL,
		0x180A43876AFD068EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA2C3E33B0383ABAULL,
		0x5B2573E7593A3120ULL,
		0x6997E16F66B2080BULL,
		0x6D041755AF846499ULL,
		0xE19BD8D2C0439B4DULL,
		0x7A99415743C45BAEULL,
		0x5DD843257037E452ULL,
		0x8A79190109BE0CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x274E6D7C3A414B33ULL,
		0x8DE526DB685FCD16ULL,
		0x57B1D8FE0EFDEC49ULL,
		0x7AFDCD7D21BA4ECBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1188F1067176BBA9ULL,
		0xA37368E3A9871213ULL,
		0x7643A49BBF388115ULL,
		0x663C612588A79323ULL,
		0x3963A29F7180C08FULL,
		0x7B73E2B7C62EACFBULL,
		0x7FD8F282B8BAAE1EULL,
		0x9A687A128A5A3D1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x965314B14A93544DULL,
		0xF6A7102B1474BF5DULL,
		0x7077A4032AEE599BULL,
		0x51BE7FE6120CA55EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4988282225EAE59ULL,
		0x1A3CD0D4D224D4E1ULL,
		0xDFBFE3FA4DFD7319ULL,
		0xB8871BB6B2AA4044ULL,
		0xA499D46BB98A0E66ULL,
		0xA7C635CC18BFB78AULL,
		0xD7D313D93D024B02ULL,
		0x131E31341326CB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x436E0A7FACDCD202ULL,
		0x01A8CD207E9A1376ULL,
		0xE914D6395C54957EULL,
		0x0F0269718A6C66D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB287BD472648EB2ULL,
		0x2B4A6A9CD1BD75B9ULL,
		0xF4AADBF54AC842CFULL,
		0x9D79A43F56BD0648ULL,
		0xF0734DF5361261C7ULL,
		0x02D8A47A262CB163ULL,
		0x9E65AB863517AF55ULL,
		0x9063BE37F6EA9316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C460E3A791F1580ULL,
		0x9772D4BE7C5FCA8FULL,
		0x77C251E12C4C496DULL,
		0x0C47E08DFD8EDBA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF16284FB656A84EBULL,
		0x883B05B79AE66A0BULL,
		0x99FC869DB74FA3D0ULL,
		0xE09755D57C00AC35ULL,
		0xBBCA0B2B1A79C582ULL,
		0xC8426D540DB96FDFULL,
		0x8FE1C02FEFE8E46EULL,
		0x456B583623E07C2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1602D61537DD7D9ULL,
		0x42174031A46D0541ULL,
		0xF57F0DBB53E18C42ULL,
		0x2E866DDECF531AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x760AA5E0F07E3FC8ULL,
		0xCF0CE42814D985B5ULL,
		0x0CBEDB364B239F8CULL,
		0xCDD39159C9B8C2F2ULL,
		0xBB4F026407803FABULL,
		0xA50326F5426C573FULL,
		0xEC07138B3B652775ULL,
		0xC1B72F19A99ACD68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C500BA0D87B78BULL,
		0x4D84AC8FF0EE792BULL,
		0x15CBC1E11C277B03ULL,
		0x0F048F28F6B34085ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC91E4BA9E8898E9ULL,
		0x49CA4AF33BEE2441ULL,
		0x54142E736516DF5CULL,
		0xE5995AE95D7E513AULL,
		0x696185EC32AEA2C2ULL,
		0xCCEB04E8AF33C590ULL,
		0x9BBE2871C978CADDULL,
		0x619509489D9CE96DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x710BC5CA2474C3EFULL,
		0xB4AD057D3D9D77B1ULL,
		0x724E2F574D04FC48ULL,
		0x61B8BBB0C2C8F77FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x239F1B1E1F389012ULL,
		0xB7F6731E1DFFBF94ULL,
		0x49CE88FD5F3BE6D2ULL,
		0x0E6BE338D095AD5EULL,
		0xA0B4E09644854645ULL,
		0x3FA681DBF8A375E1ULL,
		0xEBABDDE27A0F9E12ULL,
		0x71CB4599B7AE6B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE78716C4B0100C3ULL,
		0x2AADB9C506433F11ULL,
		0x4551789B7D8D5D88ULL,
		0x7298380A14799CB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E22C25E89DB3D1AULL,
		0x54D82DB27B50A42CULL,
		0x6D226E78DC3C36E2ULL,
		0xD6FE850B6A69D599ULL,
		0x841AD1732EB24744ULL,
		0x2C5C833400375D13ULL,
		0x8DD82E6B33E746EDULL,
		0x6B48C17AAA2C3BCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA1DD9777851D3A5ULL,
		0xEA93A76A83887511ULL,
		0x7B3952629090BE16ULL,
		0x43CB3D40ACFAB61CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D15D1EEF549D5ABULL,
		0x2A88D232E221B4CFULL,
		0xD26099B2FF6B07F9ULL,
		0x3F5CADB93003CBB0ULL,
		0x763475A33D77646AULL,
		0xA1FB9BABD1BC9027ULL,
		0x98F9437121F90FD3ULL,
		0x9B96A49359B88D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8DF482A1502C0D1ULL,
		0x35E1EDB4041F1AAAULL,
		0x87609C7E0A636163ULL,
		0x57B91B988168C50FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28E167640BD92D23ULL,
		0x173F96CB5451716FULL,
		0x80A0C00202A6CB25ULL,
		0x08AF0FAA6190793CULL,
		0xDCDF4B5701B48EE4ULL,
		0xAD4F5E2C9048C713ULL,
		0xC3C8DBFA66888CA2ULL,
		0x54E55349FBB7D0EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF206964E4CA664D6ULL,
		0xD1079168BF1EFE61ULL,
		0x9071672D3AEBAB4AULL,
		0x22B96CA5BED97C15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBFDB840AA9A389EULL,
		0xF8516A85247F1BF4ULL,
		0x8DCAC66599E8790DULL,
		0x8968BB9EAAC2872CULL,
		0x2CC10719D0278735ULL,
		0xF602675B422F0F64ULL,
		0x28C99885A145031CULL,
		0x0B7EC1B669648D47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A4C61590784AC8ULL,
		0x7CACC210F77B64D3ULL,
		0x9BB76A3B8A26EF5AULL,
		0x3E397CB24FAF7FBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDD710A63E8BDC68ULL,
		0x767935059F7D44F9ULL,
		0xD56DFB8CE68C6148ULL,
		0xEFAA640B94CB436EULL,
		0xCD3A7057D4F53486ULL,
		0x8E6F8348A44050D7ULL,
		0xEBB62E987A03254EULL,
		0x61CC79F33774715CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3483BDAFDAF1AA86ULL,
		0x9B06B1CE01094502ULL,
		0xD278E62F0303EAF1ULL,
		0x74047E25D0141739ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D84BC7C0F9482E5ULL,
		0x4C8248A75434F634ULL,
		0x88775CFDA6CBDB6FULL,
		0xB41F03E81FE79EF0ULL,
		0x23EDA82203E4D625ULL,
		0xF4E228777DAA3B06ULL,
		0xD2C753D34417A71FULL,
		0xF4CEBAFDDBD18C70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CBB188A38C51E1ULL,
		0xA6144A63FB79B91DULL,
		0xD20DCE59C24EAA2DULL,
		0x0ACEC596C10277AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2729AC3F8E1A13D1ULL,
		0xAE5DB93AA51304FDULL,
		0x0EDB7233AD9C5DDBULL,
		0xC1F7460472716FFAULL,
		0xB5CBD1F3D042E82EULL,
		0x3C291D013E19A72AULL,
		0xBFA7656A7E84E202ULL,
		0x142EE89CC4F50257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x236AD67078088B2AULL,
		0x9C780769DCE1D554ULL,
		0x81B480027555EA30ULL,
		0x40EDCD49AECFC900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x729A43BCC8BCC85BULL,
		0xC15A34AAB892B848ULL,
		0xE12483DD8B5E6A24ULL,
		0x9F2A1F4EE5063C44ULL,
		0x2C005FC09B248812ULL,
		0x6EF416127E7C1932ULL,
		0xE992BC2DD88D27D0ULL,
		0x778B3A3F182A9B27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA87A53D028FDB3ULL,
		0x39957B697EFE75BAULL,
		0x8CEC72ABB0525315ULL,
		0x5DD4C4AC7B594431ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F9F2F7F62DB5E2FULL,
		0xE700139075FCCB83ULL,
		0x57617A91C8AADD3DULL,
		0x397F64460580736DULL,
		0x728ACEF9B6B57759ULL,
		0x217DB761D4EF2891ULL,
		0x06A13C808FA45980ULL,
		0x63ECACB4FDAE09A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6039E89081CB179FULL,
		0xDFA94C16117CD11AULL,
		0x535075A71B102642ULL,
		0x0EA10723AD55E1C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAEF46B39FE93D9AULL,
		0x5397795B7C2D5ADFULL,
		0xABD1C53AC39D3DE3ULL,
		0x58C6C10A00C6BE9DULL,
		0x927D1B2CED6D07F1ULL,
		0xAF669DFCC2547B99ULL,
		0x5FED3C0E49467D9CULL,
		0x03076CC3176107CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69814F5EDE186B73ULL,
		0x5CD2ECE054B7B3ABULL,
		0xE908AF59A413E325ULL,
		0x4BE0E5FF792DE719ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7570D30AA8448832ULL,
		0xF1FB394A6015B795ULL,
		0xDFC1A72717617536ULL,
		0x0CD4FBE5E1F0329BULL,
		0x9CBE3992EC72CBCCULL,
		0xDC4623C36EB7F79BULL,
		0xFFCF769F4A74359FULL,
		0x1B7B4E1DC0D3D0BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9AD5ED9C14EC912ULL,
		0xA464884CCF6478AEULL,
		0xD88D42CC24A16AF1ULL,
		0x2122945081612F1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CA45F92F8724F99ULL,
		0xA95088D31E0E65BEULL,
		0x30942A4AD8C55FACULL,
		0x47FB5860BA074EDAULL,
		0x905F08529815B6C7ULL,
		0xFA5D53E38330E3CBULL,
		0x07158185B1FCAAC4ULL,
		0x56AF1370F77BAB7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ABF9BD58BAB7311ULL,
		0xD32AFC98975035F5ULL,
		0x3DC564234446B8E9ULL,
		0x25F83B257662C369ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35637291ADFC23D8ULL,
		0x0F7BA44A8A9A143CULL,
		0x2C0581F384FF19A2ULL,
		0x33D956865E2AE876ULL,
		0xF9804E67CECC1E1DULL,
		0x5D07ED3F53226CE8ULL,
		0xBF645ABE0F17D31AULL,
		0x7CFC241752052073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E6F15FA60489EE5ULL,
		0xDEA8DBB0E1B63ED1ULL,
		0x94EAFA29C2886F8BULL,
		0x4146B1FC8AEDB9A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x702D3A45300471F2ULL,
		0x22BDC5869B2D20A1ULL,
		0x3220E04789EAB45FULL,
		0x1625E07C969774D3ULL,
		0x67765DACD3AAEC7AULL,
		0x07B9003ECD48B159ULL,
		0xBEE0C85209432243ULL,
		0x8AE66895BF1435C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBF21EC9B638F19ULL,
		0x4833CED913F773E6ULL,
		0x877E9C74E9E1CA52ULL,
		0x345966B6F39770C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70D78C2663E48309ULL,
		0x36039A41EF5AAEDBULL,
		0x2EE7998848A2E27BULL,
		0x36529C9C22B1F4EBULL,
		0x90F35634FDA8B13BULL,
		0xAAEF4FC7099C6F8BULL,
		0xCF37D5E45381988AULL,
		0x7D4340E7EE634259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F658040AEED48AULL,
		0x958971CD5C933D92ULL,
		0xF131596CADDF8710ULL,
		0x4E4E3F09856DCE3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x030A6272A5C8B81CULL,
		0x5277692CE4691B35ULL,
		0x0AB2117945020C7CULL,
		0xBCC26F0B2836D928ULL,
		0x96BFF478CE693978ULL,
		0x941D0097A0FB7232ULL,
		0x3709B83577108AF2ULL,
		0x8A8DCE5F843D9BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6388AC614967430AULL,
		0x4EC57FAEC9BC0EB7ULL,
		0x36236968F176AC7EULL,
		0x4DCF1138C95BF9EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2398C73FFC4E2A0DULL,
		0x818B987EC3755B66ULL,
		0x5FEB5B3BC88F933BULL,
		0xE9A701F1E8C45ADDULL,
		0x6F27B045C215E1EDULL,
		0x34C0EE1171B83378ULL,
		0xD3294B8CF6C342E7ULL,
		0x12E97E7C1FBD4DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA37CF19ACB8DB3C0ULL,
		0x562EEF15A4CCFF46ULL,
		0xB80C9228698B818DULL,
		0x384FC85E9EDDEA62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33F968983CE4D9F8ULL,
		0xACD2996484C99AA8ULL,
		0x3F19277250298A54ULL,
		0xE3811B5A4BB18084ULL,
		0x01DFEF53C961D2EBULL,
		0x3016B70200A702ECULL,
		0x08FA6384E791B45BULL,
		0x5AB3B300376B2A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B36EF08216A2AEEULL,
		0xD031C3B09D9409B0ULL,
		0x9443ED2CAFCA4FDDULL,
		0x5A2DAD628599C6C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB96869B99A3B5F49ULL,
		0xBE7138D6CA805F4AULL,
		0x97664E3D53B377ADULL,
		0x4A0AB389949A25ECULL,
		0xE1532D19A78F5A11ULL,
		0xF4C7478AD6816488ULL,
		0x3DFBE92B726B473AULL,
		0xF27749F4FB1403EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BC11B887982C327ULL,
		0x1405D772A1B54B9CULL,
		0xCACAEAB04FA00A6EULL,
		0x47BFADE6D992BB6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28D178803CB8B2B1ULL,
		0xCB1C7F108D9A7E31ULL,
		0x1D08F72D4F918888ULL,
		0x773EB05F2BD275AEULL,
		0xECE9359A9974071BULL,
		0xDBF6E8EC17F74DF5ULL,
		0xA41D7B2559D7977FULL,
		0x1456B15CF138BA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536F6D7303F1C125ULL,
		0x71C3121C1C5010B2ULL,
		0x79693EB8A5920583ULL,
		0x7C1D042AFA3E2584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88A7FF9AFFC92E4DULL,
		0x8F3D0DAEAC4F9F7EULL,
		0x51A6095F96522325ULL,
		0x63E5DCC56D0E6109ULL,
		0x8C407EE348E11A1EULL,
		0x97C3F0747D86313BULL,
		0x385FD84AE7DF8029ULL,
		0x128232BD2912A1CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3AD557D1330F33ULL,
		0x1652BEF94E3AEE55ULL,
		0xAFE0247E017F2952ULL,
		0x233964D985D26559ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD0E48AC37160C72ULL,
		0xCADF567E678D3B12ULL,
		0x317E5976E5B3324EULL,
		0xB88CF5C264C392DFULL,
		0xAC2FF72B53B86097ULL,
		0x68127BABCE560A1DULL,
		0x3F59B317F6790451ULL,
		0x64E14F324FC8DADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2CF91AA4746529ULL,
		0x3D9DB1FF0852BB7AULL,
		0x98CEEF057BA9D664ULL,
		0x31FEB73A3C941002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C84A7046783828BULL,
		0x183B23ADF6798994ULL,
		0xDED4AB31A170F8DBULL,
		0xB474DFE09FE0F6E9ULL,
		0xD0895CC544D37C31ULL,
		0xF4E62003982C423DULL,
		0xBA7DBC1C63738B11ULL,
		0x6166317F0634C48CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30E86C4C9EE7F40BULL,
		0x7263E4368D0B5EC1ULL,
		0x8D7E976864979D85ULL,
		0x29A038BB8BB623CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF05A7375142C2D3ULL,
		0x8C0EC73DB5C18057ULL,
		0x3853D5FA6C9E78B2ULL,
		0x1792B5B27A3E198AULL,
		0x8C596C4B3C0C8248ULL,
		0x4E6BC8E8F37A17E5ULL,
		0x467994158B23C430ULL,
		0xD440CF27CB242EEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44BBA623B1E1E30ULL,
		0x300E99D1D9E10C6AULL,
		0xAE5FD12D13ED97DEULL,
		0x1931759AA19D10C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4D366D107F70846ULL,
		0xA1BCAABAEA15B620ULL,
		0xC8B8A7D220FA10A6ULL,
		0xBF7CA96534B73F4CULL,
		0x3119366456285270ULL,
		0x492B04B989A9170FULL,
		0x0AC69D6B4C546877ULL,
		0x92B707FE72DF22E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9179B5D1F3483DULL,
		0x7E1F5E45592F2262ULL,
		0x623405BF7581925BULL,
		0x06A7D92A41D66DE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x286388062460D4AAULL,
		0x679814673281275AULL,
		0xCB23368A885ACF04ULL,
		0xDEA805108233ED39ULL,
		0x30C30C8BF58E340FULL,
		0x9552F8E27B1CF76DULL,
		0xDAEEF2163CA4F201ULL,
		0x85100FC2D497A89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655764CC977C91EFULL,
		0x91E9060578CDE18FULL,
		0x4A9B25D788D6BB40ULL,
		0x1F0A5BFC10B6F4A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x748E0993AB17898AULL,
		0x772A1536CD1FFB4BULL,
		0xD3DB2A016DCA9268ULL,
		0x969767B446CCE552ULL,
		0x45F19A11E0420CC4ULL,
		0x4088B46C014C0A76ULL,
		0x14E8401CCEC6A6A0ULL,
		0x3732B0325732F147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD66AE83AF4E56FE5ULL,
		0x0B74DD3EFE6988D9ULL,
		0xEE54AE481F474E32ULL,
		0x481D8F2D385CB5DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17DB5E11D0C07DD8ULL,
		0xC68CDBD27EE91BF0ULL,
		0x1E8A816FA9DB3D46ULL,
		0x5DCFA1DD8D574C2BULL,
		0xA0A91D20BBEF68C3ULL,
		0xD91AFA106CA8DAB0ULL,
		0x16564AA204F1668DULL,
		0xA97C040EB7A5CA8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F5B0EDB64A0E93ULL,
		0x008DFA429FF99227ULL,
		0x6F59957C65B07655ULL,
		0x06383C0CCFF35D1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x118C824F3AB78987ULL,
		0x5038C8C165234FBAULL,
		0x45DFFC6BED9FE931ULL,
		0xFF0E83A6FB42FACFULL,
		0xA762FB347F15C2BBULL,
		0xF8184ADB633ABA8FULL,
		0x55B11582538C34C1ULL,
		0xBC2B0F028E4C5CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3DCC1A17F27584ULL,
		0x23D3E5521FDB010CULL,
		0xFE292DC4546FBDFCULL,
		0x6D72BE081A98BB7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E383CC0BFF2BBACULL,
		0x0585A530A070B410ULL,
		0x3463CA8E00C67079ULL,
		0x09B11BD32D979CF8ULL,
		0x2DF61CB9E7139A77ULL,
		0x52805209C7CD0486ULL,
		0xA1DFE93BF85DACB2ULL,
		0xF4A658E1424FE5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C080590CDBAEAEULL,
		0x4491D2A448DF5FFAULL,
		0x3BA06974DEAE12F1ULL,
		0x5A624D430573BC2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48E1FA6E96E81C19ULL,
		0x1748A183EB924922ULL,
		0x8E6AE719971E90BBULL,
		0xE2A1EA542C00F3C9ULL,
		0xE142D7156661F9B0ULL,
		0x93B1798D445142E5ULL,
		0x0FA7C85C79102B46ULL,
		0x00758C59E01A2489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8CDE79BC9732C4CULL,
		0x03A0AC7C0FA23741ULL,
		0xE152A4D38F84FD35ULL,
		0x7414BFAB6FE26021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2E134816C9C9774ULL,
		0xFF54A807C52AB09BULL,
		0x5482004F025F0CBDULL,
		0xF828D5F322C86CA1ULL,
		0xFF8328AEFFCE1F54ULL,
		0xA49D007B09640712ULL,
		0xA94DFADBE577C890ULL,
		0x7AB7BDE81B4D65DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0593E7B653540BEULL,
		0x6EA2BA4B2A03BD6DULL,
		0x76153CF31226D236ULL,
		0x2F6F066730458B3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BF1749336074F89ULL,
		0x2B7EE5FC8AC70AC2ULL,
		0x2033FDE3422C3E64ULL,
		0x99B7E7D2460D121CULL,
		0xE5BCFE544A1CBEC0ULL,
		0x797E21B549C6A0C6ULL,
		0x89C1C95479802097ULL,
		0x219D31205746B467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35FF3516364BA0DAULL,
		0x3437E6E57E42E848ULL,
		0x92F7E06D4B3114E0ULL,
		0x170D329F3A8BD97AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x043E541197392400ULL,
		0x6188D9075B9AE92BULL,
		0xD02466A9EA3C5238ULL,
		0x59DD9C196ABA8872ULL,
		0x1804E8C97B676150ULL,
		0x9F25342EC9D569F2ULL,
		0xCA249DE3989992D0ULL,
		0xF09DDCF8679581CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F8E1F9E8919B38ULL,
		0x010E97F95148A31AULL,
		0xD193D67291081D30ULL,
		0x114C68F8CAEBCCFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A1CA46E4ADC2F9AULL,
		0x97A8212B78B55E8AULL,
		0xFC785B407727A6D5ULL,
		0x18990676B9B9B9FFULL,
		0xAD0A357C22B02067ULL,
		0xDDCEEA5DE5989E3CULL,
		0xF0F7B978AA9A41D3ULL,
		0xB4E4967F319EE87DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A094DB710102D3ULL,
		0x845EEB1B8D5CDB8CULL,
		0xC13DE329CA0D6C48ULL,
		0x72875D5817503CB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A18769E892CA087ULL,
		0x04DC32086933F3CDULL,
		0x0927C12BB0A03336ULL,
		0x372D772E9A3288BDULL,
		0x17BEE15133A0CA24ULL,
		0x29DCA18D373EA88CULL,
		0x0B833402231DA585ULL,
		0x1934BEE026349594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906DE8AC330AA264ULL,
		0x3B9C2CFE9C80F898ULL,
		0xBEA1797CE706C4FAULL,
		0x7501CC744600BCB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB973F2B9F9291373ULL,
		0x912EFDCB2D376E72ULL,
		0xE73F05C2AD75CB34ULL,
		0xA0EAD7582563D4ADULL,
		0x4FFF883C8994257AULL,
		0xCCC576ABADC5C65FULL,
		0x77184BF77F70C3FEULL,
		0x4C4DAFBB80253AC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99622BB66526A544ULL,
		0xF67E9B46F892E098ULL,
		0x94DA4C7F9832E306ULL,
		0x7472ED2D2AEA8D3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEA2123D03E7C97CULL,
		0x8BF2667A90392128ULL,
		0x16FFB2EAF9DF3FF3ULL,
		0xB47B21FF51B30055ULL,
		0xC18F000195638925ULL,
		0x01EAF1B0531B4BF9ULL,
		0xD051ADE39479488CULL,
		0x813D2D102427E6E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9DC127930AE27DFULL,
		0xD4D246A6E646683BULL,
		0x031F82B303E004BBULL,
		0x638FD264AF9F464CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0619D9176F1A4BF1ULL,
		0xD3D780C01741C856ULL,
		0xAD2917922F70E9B7ULL,
		0x7BA1F4C2FA416494ULL,
		0x5ACB043E632330E0ULL,
		0x7EA39C5ADED62FDFULL,
		0xAF05C434FB7CB779ULL,
		0xF23291588B34C00BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x803C7A5A26539289ULL,
		0xA020B63D2B0CE37DULL,
		0xA804376F83F425C0ULL,
		0x6F2387E7A415E650ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37FE87947B854919ULL,
		0xF257B891CB7FF987ULL,
		0x9A405F62206EFC9DULL,
		0x51A1E70EC5724987ULL,
		0xCD68C0A963148CB4ULL,
		0x2AE2A3DE666B92B8ULL,
		0x0343B059B8AF9817ULL,
		0x54160011E8633733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58B20B930922DACULL,
		0x4FFC0B94FF77C0F5ULL,
		0x164C8CB38A7F900EULL,
		0x4CE5E9B7442C7B1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CF4716637A1F999ULL,
		0x35EFCFAC575A7318ULL,
		0x0F0D915E67DC1352ULL,
		0xA129AC42C27AA59CULL,
		0xA8329CC9490DE46AULL,
		0x6B0831C91A701D6EULL,
		0xB06DF6662ECC43B9ULL,
		0x6E0D4C38C4AEC9DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6477B7470FB1E3C8ULL,
		0x1927338643FED185ULL,
		0x3F6024895A2E20D8ULL,
		0x7722FCAFF46C9CAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC5E45616287BE29ULL,
		0x3010412A9D0C123FULL,
		0x3D3D6FA948F3314EULL,
		0xC694B4D80AE6FB01ULL,
		0xEB53446A72773C60ULL,
		0xEC837798ABAD5B3AULL,
		0x4D90043D2F7F0B51ULL,
		0x103066A1C0EB961DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAABA6D2E603AB4DBULL,
		0x4B9401D418C79CFEULL,
		0xC09E10BE55CEDF77ULL,
		0x2DC3F0DAADDF435AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5ED96E3BCEFAA93ULL,
		0xE593397CFFFF6AEFULL,
		0xA0429865BF84BE86ULL,
		0xEB217C00430824A6ULL,
		0x1F29C0AB3B3A98CFULL,
		0x203BE4DF36665D18ULL,
		0xD97A4F59C9D4F14BULL,
		0x9B9E4AE991074968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7620304E87A25CDDULL,
		0xAE77329F13313C84ULL,
		0xE86A5FB9B5208FADULL,
		0x04A09AABCA1D0A36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x523C46E06BB4D12AULL,
		0xBD515AF80F79B35BULL,
		0xD51FDA2C3CD9C2D3ULL,
		0xB04F450F277D0F77ULL,
		0x8CCCD98D5DED4068ULL,
		0x6CE154ECB5D5252AULL,
		0xC2453BE4E92FCFBCULL,
		0x1EB79588194E103AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38A491DC5CEC6158ULL,
		0xE6C3F61B0D1D37ACULL,
		0xAB66BE26D9F298CBULL,
		0x3F8F7742E9137830ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEE616604A22FB0AULL,
		0xE8873AE54F83CF62ULL,
		0x6D4C1118A2EF92D4ULL,
		0x4EE9F8A8663BE621ULL,
		0x9354D72AE50FECA5ULL,
		0x4C862C842301A15BULL,
		0xD83D4CF59566F464ULL,
		0x065FCC37470F7EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7E06BE4A801BAEULL,
		0x4471D68281C1C2FAULL,
		0x86657D8CD037D9B8ULL,
		0x412248DCF288B77FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34A21E72AA3E6E80ULL,
		0x88E86D7EAFCDB2E8ULL,
		0x26DCBD1CD7AA1918ULL,
		0xEC895497D92326E6ULL,
		0x61DF813253F5FF92ULL,
		0x1241C76F59FB810BULL,
		0xE1C129475A3D7109ULL,
		0xAF896F5CBCCAE02CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBCF4BEB20C2621BULL,
		0x3EAC08060B22DA98ULL,
		0xA988DDB43CC8E071ULL,
		0x7AEFDC5BDF406D8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AA51397984948DEULL,
		0x295670E4D5AFA950ULL,
		0xE742A728D7747F78ULL,
		0xA66F9190BD50FD35ULL,
		0x0385DC21068C3B65ULL,
		0x5F366FB30DA68DC1ULL,
		0xE360ADB926526882ULL,
		0x27CE4541371EF483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1083C07E911A1AD3ULL,
		0x4B6B0578DC68B3F7ULL,
		0xA79C70A487B002D2ULL,
		0x0F0DD93EEBE948C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31BDFBA7BDB07C04ULL,
		0x4E8B00272F84E6C7ULL,
		0x7CC42DF3B51B6AF5ULL,
		0xBF41D71D0E2686E9ULL,
		0xDDA096A80C12D900ULL,
		0xEDB7419070040470ULL,
		0x27EB58DAC9C9DF67ULL,
		0x486F33DD7AA266A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17945899887CB3A6ULL,
		0x97BEBB97D01D8F88ULL,
		0x69B35E6DA9129462ULL,
		0x7FC389FD4241C3DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A39B80510C11D5EULL,
		0x77863207B4B916AEULL,
		0x4BDAF14E9520F08FULL,
		0x7474C59DD92735D5ULL,
		0xF980CD77D928810DULL,
		0xF3A07285529366A6ULL,
		0xBC3D2C1FE4D3EFB0ULL,
		0xE5C82BD6FE088164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935837CF4CC44A6BULL,
		0xA15731D1F69A5377ULL,
		0x3CEF7E0A8C9684D3ULL,
		0x102B47878E6A6AC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF827832C530C6A2ULL,
		0x97F526C680038195ULL,
		0xD6A8C098D7224932ULL,
		0x161556F3EC2F9515ULL,
		0x0B0982216C480F27ULL,
		0xD54D75D754F25130ULL,
		0x70189C8985CA387AULL,
		0x9B0A274B3F9310BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62EBC928D7E309D6ULL,
		0x4174A4BD1BFB8EB7ULL,
		0x7A4FFD02B326AB6EULL,
		0x19972C1F5C041180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D214646DFAD2794ULL,
		0x2A7CD6283F4A32B5ULL,
		0x986712821DFF2424ULL,
		0x04B8CCEFF8ABF3ACULL,
		0xEA0D327CC31C7EE1ULL,
		0xA9B9B7A57FD30B2CULL,
		0xAA27D17FC15D7BB4ULL,
		0xADEDFACA7F76CDEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B16C4CBD5E800C3ULL,
		0x5C0E18B9389DDB60ULL,
		0xDA502B78D1DF80F5ULL,
		0x560C06FEE44E8481ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE40BC94F5B1BAF53ULL,
		0x0E3F5304636D12B9ULL,
		0x9FAB2032A4F6F951ULL,
		0xC95D99CD1F08F27CULL,
		0xDF27C2A94AE96965ULL,
		0x1E35565F379834F1ULL,
		0x93F208737F7C6CCEULL,
		0x909AFEC4409EB479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03F2AE7079C15795ULL,
		0x8A2A2526A404EEA1ULL,
		0x95986157916F1FE9ULL,
		0x405F6AEEB697BC88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F97C26AE0630D1ULL,
		0xBD5E1D32E149BBD9ULL,
		0xA7D7114821C5620EULL,
		0x012BAA693DD814F9ULL,
		0xCB9D0926571E3767ULL,
		0xB956B2B43AD6C53EULL,
		0x3CC8CE1736FB1447ULL,
		0x9A0F4B94FC4390F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B48D7D79C826D72ULL,
		0x403CA3F39D2B032BULL,
		0xADA5A8BA4B0A64B4ULL,
		0x5F70E286AFDF993AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D28EA4A469A129AULL,
		0x71AFD23317BB339AULL,
		0x4D4417EA373962FDULL,
		0xD78CB20D204151D9ULL,
		0xE4970E08E33E2D70ULL,
		0xFA21A105DCDCFEA6ULL,
		0x62E07F3ACEC4CE5FULL,
		0xABBD58ADA3B46390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B94FF9C01D4D516ULL,
		0x92ADB911E0890060ULL,
		0xFA96FAA4E870053CULL,
		0x55A7DBD36D081947ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4306A53DB2FD5427ULL,
		0x493870E88393C768ULL,
		0xC8778148910812B3ULL,
		0x77057FDCEA42F49AULL,
		0x969C1CA3AB8F0555ULL,
		0xD0E8C408E8849DA8ULL,
		0x0874F48F07FB3000ULL,
		0x1CB9D562E941DA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E32E5892A381F70ULL,
		0x4BC58A3B07432E6EULL,
		0x09D3CE83C05132D2ULL,
		0x3A9B2C8B8A09561AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x186A07F233283052ULL,
		0xEE6C099FDEF86C42ULL,
		0x7B4F22D90819DE50ULL,
		0xD1C1A7B6F9758ABFULL,
		0xA5E25782F73DE9EFULL,
		0x964E1A4CB2DCB01AULL,
		0x4DBF13708D0B6696ULL,
		0x148AABC54E030692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8030562E658EA51ULL,
		0x3E03F1026BBA9036ULL,
		0x05AC058DF7CB18ABULL,
		0x5E5727008DE88477ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1646CFB22EA2620BULL,
		0x600B924C2862F0D4ULL,
		0x570791E5D55E2F95ULL,
		0x3DF7B7CA93B00CE0ULL,
		0x5EF2B3FA0C160DE2ULL,
		0x462AD9DDDDD94DFDULL,
		0xFAA96D6DA0B0B310ULL,
		0x9FADDCBFCC6CB155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4D86CFF9E87514ULL,
		0xCA67E93B16A48470ULL,
		0x8C2DD02BAF98C3FFULL,
		0x71C67C42EBD25FA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD22D17D78321F7B7ULL,
		0x887AFD704171723EULL,
		0x245B5C3F15BBCEBAULL,
		0xF465E0CC493382ECULL,
		0xBD25C9755E270304ULL,
		0xE9E57DF355D2CDF5ULL,
		0x1F8A8CE1129C3873ULL,
		0x73AB275BB55AA076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C8FF437CEC6CFBULL,
		0x408BAF8EFEBC04B8ULL,
		0xD2EC45A7D8EC2FEFULL,
		0x1FCDB86934A75474ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE04C751148008D2FULL,
		0xBB5686A869D12E33ULL,
		0xFEBC8800C99C9B00ULL,
		0xE58317652F8E39EFULL,
		0x6C5240BF209D7875ULL,
		0xC39BB04C592B6359ULL,
		0xC0DDCA09960A77ECULL,
		0x7578DC35141550C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF48211701F607139ULL,
		0xC472B1FDA641ED79ULL,
		0x9FA8856D0F2A6825ULL,
		0x5573C7462AB83724ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC399BC9640271DA3ULL,
		0xDF2CA99545DB73A6ULL,
		0xB6074C7604218400ULL,
		0x6091B945C3B845FDULL,
		0x5AB9D0E49B82E072ULL,
		0x3D52981DD5E9D10DULL,
		0xF1E09EC9F35D7BFCULL,
		0xB4530789AC0A03FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B2EBE8555947291ULL,
		0xF96F3E0306907BA2ULL,
		0x9D5EDE702401EB71ULL,
		0x24E4D7B54D34DD3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1820442E39BF7D6FULL,
		0xF3C54A65E6C90A61ULL,
		0x890D224FF0924FCEULL,
		0x113B9DDEE595A32DULL,
		0x0B5E793B1970ABFDULL,
		0x59D3E195BD9FEE7BULL,
		0xF0F66A0A192B14AAULL,
		0x7961CA3B50811292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC82642F4007907A9ULL,
		0x4938C6A00C8670A4ULL,
		0x4DA0DFCFACF76118ULL,
		0x15BFA2ACD8BE64FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFD5CD7D7711F5F7ULL,
		0xC5C6DED3573B836DULL,
		0x8050C1FA265B4455ULL,
		0xC06E75233833ACFEULL,
		0x5965ACA22F6C41E3ULL,
		0x2CB59CC6B2F4966DULL,
		0xF8A1F1D0BF4992DAULL,
		0x4D2F4096E7C71E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34ED6D908123BF71ULL,
		0x68BC2451E789D7A9ULL,
		0x685AA6F68B4710B8ULL,
		0x35720B899FC225BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1AE2A7165A36AFAULL,
		0x4F337E28D49D6B7EULL,
		0x50A89821504CCFA6ULL,
		0x645CFAB5BCA24D65ULL,
		0x20D3A7BCDB66D2C6ULL,
		0xA7A2849A3ABF6716ULL,
		0x4D95B33C076BA581ULL,
		0xC2CE2E2AE878F1E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1191079F6E6B8ACULL,
		0x31532D0D8D06B8C7ULL,
		0xD4E1330A6A4760E5ULL,
		0x4EF7D5143E9634D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}