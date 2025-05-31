#include "../tests.h"

int32_t curve25519_key_sub_modulo_test(void) {
	printf("Modular Key Subtraction Test\n");
	curve25519_key_t r = { };
	curve25519_key_t k1 = {.key64 = {
		0x96434A024C1D49BCULL,
		0x3EDACF025AAAAF69ULL,
		0xDF4CFC874F2884CAULL,
		0xB7D85B84B4951A60ULL,
		0xB030D30BB7B95378ULL,
		0x40696CF4C1A48C07ULL,
		0x1B850A07234FAB78ULL,
		0x0F96B9FC74C6C210ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x5A4D314FF58ADF75ULL,
		0xD08EA729826A24BCULL,
		0x057F47D9254142EDULL,
		0x5D8C58B3986CC32FULL,
		0x28CC3EEA36637460ULL,
		0x9F3969D4F058E59AULL,
		0xB86F9E1825F8317DULL,
		0xD72F82F104C158FBULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x54E415AB89518376ULL,
		0x5B6C9E91E97B3EEFULL,
		0x8EFBBA27C4E35D10ULL,
		0x399E2E83BCF5F038ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68619496DBAA7E5AULL,
		0x47737442812761BDULL,
		0x0B62F4A47235CF63ULL,
		0xBA1823B57D432F3FULL,
		0xCEF7F0C05ADB2485ULL,
		0x4CD47C2883DEB415ULL,
		0x10F00E9E59C5E972ULL,
		0x0FA883D4E216764BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE263C50959B060DAULL,
		0x0F539D7BB749B375ULL,
		0xE1BF189B4714945AULL,
		0xFB469ED8CEAD938EULL,
		0xE8ED7010EF1A3A77ULL,
		0x16D9EF0DC60FFF97ULL,
		0x58835D2456A74258ULL,
		0x4B8F97A9DE8D1619ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB8CE997809CDA2BULL,
		0x3B50C8BEF68C78F7ULL,
		0x89C63425A1AE08EDULL,
		0x5A84933F34F9E311ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E5286337F90D86CULL,
		0xDDEB2BE591845780ULL,
		0xEFB882E76C283C18ULL,
		0x8B8E30525AC55D05ULL,
		0x6EAEB01DD3A18D30ULL,
		0x78D5F15EB9FFC489ULL,
		0x04A9022A4FCF3C2AULL,
		0x24699A85D967B5A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2969C8F8DAF85867ULL,
		0x8197A76AAD653E29ULL,
		0x3CB3F3C39CB8226CULL,
		0x38AE466D4FC0F4D5ULL,
		0x4284136D17602817ULL,
		0xB1C78644606D7A3AULL,
		0x56C77B1A4FBEB399ULL,
		0xCC78D7E54BE44AF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD33BFF76964D7E05ULL,
		0xE8776A642FD62117ULL,
		0x827E9B83D1E45F29ULL,
		0x609CCDBA0C863D86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CAC805E59837F22ULL,
		0x82CA4FB1D91C6FDDULL,
		0xD7D83AD64AC8DC21ULL,
		0xDF263414093E84DCULL,
		0xC5031106D4214850ULL,
		0xE0C73B3C6EEB5C85ULL,
		0x33A433062E1B5C1BULL,
		0xA6C33A3BB89F1B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920688FD9F82D09EULL,
		0x493EEED4169529B0ULL,
		0xCD62031FEC5BB009ULL,
		0x6662D78B70FBCAF3ULL,
		0x3DD97A3B40FF91EAULL,
		0xCD9E68EECE2011B8ULL,
		0x05A3A804F158A38AULL,
		0x0B565C8258D3C385ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AD259989101C525ULL,
		0x119A9863A0B460AEULL,
		0xDE8AD9E5635491A1ULL,
		0x0AEC460CD071BEA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D7B718D630963C9ULL,
		0x3C7FD63435EA99B4ULL,
		0x69ECAB06ABEB9111ULL,
		0x8648BFACC411F4A8ULL,
		0x414B319D56F4AAD7ULL,
		0xBEF9F62170945C30ULL,
		0xD24E2730B43F3CE3ULL,
		0x5B8117A511FA575BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22E06340DC234B2EULL,
		0x5188FB036F10B9FBULL,
		0x07DB7FE6E2F2BFD1ULL,
		0xB6F1702251154E4EULL,
		0x10C58D765DF9C9A4ULL,
		0x3109E5C107E5CB3DULL,
		0xDB6BC51272FD985EULL,
		0xDD2474F789D16B6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E716C157C238348ULL,
		0xFC99498050C363D2ULL,
		0x07ABBB9D78B73D12ULL,
		0x1117754CA90FAB61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA0102FA64FB2938ULL,
		0xD2244A739B174989ULL,
		0xC73F81551A42959AULL,
		0xA3945E2A29C81986ULL,
		0xF6F2736A0442947EULL,
		0x84A9B2E09C0DD8FCULL,
		0xCB7095FBE3E39B32ULL,
		0x2F6103C2C75D08A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC38B79B94778929ULL,
		0xB99CF9708F7F1DD2ULL,
		0xEDA5CF063D930F97ULL,
		0x20F2AC117B841917ULL,
		0x8793D22EFF48AB2FULL,
		0xBED120D6D6C69211ULL,
		0xAA93A78C4187DA9BULL,
		0x89982BBDD074D395ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65D43A218D9C3FDBULL,
		0x76ACFE76542CB2A9ULL,
		0xBA6516E0F64E1C64ULL,
		0x1E71C2D554BBE0F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64CF9FD6DC2D131AULL,
		0x644912FEDF5A3CEAULL,
		0x7E8D67AEE10B4728ULL,
		0x0BE16ACC3E28A475ULL,
		0x57993D37B080BD68ULL,
		0x45DFBFC9AA03541FULL,
		0xBBD22EA231842565ULL,
		0x293013DCFEFED7ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA24409FD982CA1B5ULL,
		0x56808B23BC28E328ULL,
		0xF361303D8A2A6EF2ULL,
		0x519B89C8DF21396CULL,
		0xEBE5394F05BFDB13ULL,
		0x946E848A55589EC3ULL,
		0x2E60337FAC06583CULL,
		0x9C27AE1A88C08D6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF442A629CA2076AULL,
		0x64975341B4884553ULL,
		0x8A177E91278D4C40ULL,
		0x2984FBE0EC46702BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52C4DE0E72B9D642ULL,
		0xD41F9F9BE07032EEULL,
		0x8DD61F457971648DULL,
		0x350A66A194681810ULL,
		0xE09595680592AECAULL,
		0x5F03487B6CF06C0EULL,
		0x66D052772333BAF1ULL,
		0xFDF7E43C795F46CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x136922E2A92063A0ULL,
		0x61D4C7AAE2DBAA43ULL,
		0xACCCC3246F39E189ULL,
		0x9F80FB455D736F06ULL,
		0x848730662D945312ULL,
		0x08C97425C98208F8ULL,
		0xA4987243EB8488C4ULL,
		0xBF67415BABFEE352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE97EB971D95B1135ULL,
		0x3EE05CA73FF73DFCULL,
		0xB554A3BB4E38F5BFULL,
		0x5F0198BAB3436CF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE91B594E2347343ULL,
		0x7E61B18E9613E84AULL,
		0xFE19217AF758EA42ULL,
		0x0ED1FD169C667F79ULL,
		0xF1BC62D43CB57819ULL,
		0xFD9BF8C31C0F1DB7ULL,
		0xF4CAF95245FC8656ULL,
		0x9F09B93B08B5A528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF40C3BC8BC3CEE06ULL,
		0xA328A621C634E335ULL,
		0xE6ECAE678631E189ULL,
		0xC8B5CFE1882A2175ULL,
		0x02E7641822E94587ULL,
		0x02B3B8FF12E4BA3AULL,
		0x2B66C417DED2889BULL,
		0xEC9A9D69644E714DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E2349B7FA47050EULL,
		0x19B282862C29C9C6ULL,
		0xFC0C59BEC162B2A0ULL,
		0x429A4E537B8E10A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD501FFC5051D476ULL,
		0x3EAF6E29F4196085ULL,
		0xE6A7FC23EF71588AULL,
		0xAF47E790171AAB56ULL,
		0xE4791ABC20551FA5ULL,
		0xECF9CB8744E529B1ULL,
		0x125B0142F7119845ULL,
		0x70B06116A6FEF984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E678724E6A4E93EULL,
		0xECC3EE03D27B1852ULL,
		0x54B7BDC976EAA9B7ULL,
		0x5BD7F555A57DAB4DULL,
		0x921A141431146F3FULL,
		0xC424E49588708F22ULL,
		0x5BAB5887CD1B6219ULL,
		0x2E115E447221C449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x890395C4ED471BD8ULL,
		0x6185C8081AED3979ULL,
		0xB0034A22B312B960ULL,
		0x370A5D6E4A72E6C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA736C3E48A2107AULL,
		0xB586BDC2927B38FDULL,
		0xDE2EB620ABC972A5ULL,
		0xB24137CE30583073ULL,
		0x181215D691AC2B16ULL,
		0x5C182B7FD1E5C8C7ULL,
		0x4D6FEA116C21E9C0ULL,
		0x1237E8F3AA7B02E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E8A9B90DBBA95DULL,
		0xB62273E8FEF89DA4ULL,
		0x0950FAAFD7A967AEULL,
		0xE967449B4187E41FULL,
		0x261E7CD4C9DDFF93ULL,
		0x51A008D09214CEB6ULL,
		0x9CCA1A3FB8E7928AULL,
		0x7E8E054E2949E2BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3B378C8E380DA1CULL,
		0x8D396FDD0C87B9DCULL,
		0x0D7A94916EC8FCFCULL,
		0x3411BDC41C1B1343ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD99AD3CFDBABA6BEULL,
		0xD2388B1202F78DBAULL,
		0x6919CE4ED15ED7A9ULL,
		0xDCB3D09A71EB42B5ULL,
		0x9A4E1AA0245CF997ULL,
		0x85BA225CD4CBDC12ULL,
		0x5687EC44403F7382ULL,
		0x81219E112DF13BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12DB469B59A9AA56ULL,
		0x48C401483EDEFB0BULL,
		0x4750331F66FC2DC2ULL,
		0x753A5EF0384AE9C3ULL,
		0xEB03F2EC8B0E962CULL,
		0x74279D1F2E2F516BULL,
		0x2783B7A67B6AA37FULL,
		0x28F152FB5CC50665ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBC171DD43A4C038ULL,
		0x253450F07F55276DULL,
		0x1C696A9AA1F98A5CULL,
		0x7EA496E7463041F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F92F8BD37F8EA08ULL,
		0x1F6ED24F1B881ADAULL,
		0x67445ECE063BD4D2ULL,
		0x49DABB25B6F1BA7EULL,
		0x18FA9F8513E4C262ULL,
		0x7F36741F4A46545CULL,
		0xAB5DD2431AD48D5EULL,
		0x1613FC21B8E1F1FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE316E087F3C92751ULL,
		0x14B62070A497EA3DULL,
		0x86BD67FCF0454524ULL,
		0xB0287747DE2CCE27ULL,
		0xEAF457241E0266C0ULL,
		0x0B02070F7510A38AULL,
		0xE89A2C04E67EA784ULL,
		0xC1778B18EB14253BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x216AD699C3C958E7ULL,
		0x4A80E2381CE86FA9ULL,
		0xC991A40CDAB6AE1BULL,
		0x28EB0B2C655150F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82CAEC414B862897ULL,
		0x0AE2741456873B11ULL,
		0xFD52AFAFA4B5CC7CULL,
		0x6F7C1899E11F8156ULL,
		0x5EDCFF8CB564736AULL,
		0x8C1A2D4EEB472DFDULL,
		0xD69CECB3DAE7A60DULL,
		0xAA8568C6351FF9FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D53E99CEFC32E4ULL,
		0xC4D1651BB022FF71ULL,
		0x511F147B2AD89732ULL,
		0x5D7EC6C30417E475ULL,
		0xD4EB49568CDB642EULL,
		0x2EA9A4419BB91443ULL,
		0xB2491E2A8DD8E1B4ULL,
		0xCA3EBB8F9612E322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66D6B9B180E237DDULL,
		0x24C566F2757C0D2AULL,
		0x10A44395EA0E5A8DULL,
		0x5C7B07F278F90143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA92247A4536E89DULL,
		0x1C8460E1A5B1C351ULL,
		0x4E302BAD5938398AULL,
		0x83941E0824EF326FULL,
		0x4F8519F72CDC86FDULL,
		0x8F89984F5DD4119DULL,
		0x321D9609BC67709AULL,
		0x6255EBDA7E5888EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CEF6C4F54141DA6ULL,
		0x739E9D121CAE3ADAULL,
		0x6E7C35EB215E5EC9ULL,
		0xA53CB94A3BC41AECULL,
		0x776CFD3FD18B57F2ULL,
		0xDD0B07B51F6D7879ULL,
		0x7F02C97BA1AD9216ULL,
		0x1F2474601C4E178CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7136FB627F2FC802ULL,
		0x27AF3AB4CC3E43C9ULL,
		0x75AE52DA2F70E24DULL,
		0x57AF20E876B7EC03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAD521CF74A41E42ULL,
		0xD7815509BC880E39ULL,
		0xB561A6207EF51F2FULL,
		0x918249076EDF7B41ULL,
		0xC49FA5031CE2799FULL,
		0xAC3CA67E48190613ULL,
		0x2E91979190EADA1DULL,
		0x35BA1D4A24EB74B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C9A32046F5176BULL,
		0x0B0DD42A94EFA6F0ULL,
		0xEFD73414424E555AULL,
		0x26E4A535243FB655ULL,
		0xA0D147273C5857F7ULL,
		0xE7D33BA6E6A21CA4ULL,
		0x95ED49BAE4FAEC38ULL,
		0x83A3FE22630D82F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8AD6D5282300412ULL,
		0xF4195CD79F3F0DC8ULL,
		0x6DEDFFE9C24419CAULL,
		0x59E643B91191A81AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x094A877FB246BE74ULL,
		0x31F8A19E03EDCB1AULL,
		0x6D964FDA57B63A7AULL,
		0x3FB694BDE3DD9C33ULL,
		0x0717AADF4CD0C586ULL,
		0xF4F6183CF9918E2CULL,
		0xF333F2CEC4874A51ULL,
		0x814D52827AC71073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCD134A66AE3B8AULL,
		0xBCD020CF5DC14656ULL,
		0x15111EBBE82A5878ULL,
		0xFB420B78F1149D17ULL,
		0x61D6564A9964F83EULL,
		0x5CD69E28D28DF687ULL,
		0xD5A02501EC9F6FEBULL,
		0xAE762C380766A2F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5300247ED98FA7DULL,
		0x09D49FCC70B50733ULL,
		0xBC75BD867BF64D3CULL,
		0x1064385213193F62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FF678D60CCF365AULL,
		0xB3BB1B662A7A0315ULL,
		0x7EA281E74AA9025CULL,
		0xAD55508615ADDF33ULL,
		0xBAD771DA0D5F1DF5ULL,
		0xB6DC8B891E7C4D52ULL,
		0xD1C3CA89228A2FB6ULL,
		0xDC880C6B67BC19C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9CAAFCC8458675ULL,
		0x7D84B44BD4887B29ULL,
		0x451830A2B6C691E7ULL,
		0xE5A6FDA5A261692CULL,
		0x7C7DA4DDFCF07578ULL,
		0xE0EA2DCB1E154A78ULL,
		0x3BD49439785AC663ULL,
		0x41FD208D1FF7D976ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64AE3B43B4F6B5CAULL,
		0xF830514E653BF451ULL,
		0x7B0C6117D6EC12C0ULL,
		0x384D55DF1A6E01B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B6ED0E93A3FBCDCULL,
		0x7B761FCD8C27C5A5ULL,
		0x4D63A5C20BB90E0CULL,
		0xB8DA8EEFEF6C2A42ULL,
		0x6B61440DC1B1EF06ULL,
		0x05805FCA669F08A0ULL,
		0x0480091F0434F872ULL,
		0xFFFD464BDA6741FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FA0AB9F0986B5EAULL,
		0x14A4C4B1054EF30DULL,
		0x5491163962C3989CULL,
		0xCE48377675F10743ULL,
		0x230904FE56D0EC31ULL,
		0xF37818382F2F6295ULL,
		0x23AE8367506851ABULL,
		0xDE9AC138E4797950ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8E781940E1F733BULL,
		0x140BFAD0C16B7844ULL,
		0x57EC68CD595636D7ULL,
		0x5F321849FAC6EC82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0A13248D707371ULL,
		0x3962B66DA7273AF6ULL,
		0x8A2837194D86ED0FULL,
		0x97B061933438D67CULL,
		0x61FF7454F614ED93ULL,
		0xA47FEB07A00C9E2DULL,
		0xC31E824135E64393ULL,
		0xC333CFF3D9E8667BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE11114A505D7D5ULL,
		0xF47D2D3CDBF38203ULL,
		0x2353F467E487D1C9ULL,
		0x60F6FBC3F199EBCBULL,
		0x45027A12E5CE6163ULL,
		0x9DFA0A627CE816C9ULL,
		0xD14E58043D4DDD39ULL,
		0x7AC10129017F7CDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BB627DE52E36C4BULL,
		0x3CC4E1B4029FD1CFULL,
		0x4BBA87BE4F9E4CA2ULL,
		0x77C417EB62319849ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4077D1396581E9ACULL,
		0xE919E8AE09D0B034ULL,
		0xCF13F7A7579C5BD7ULL,
		0x37BDFD0B8C020644ULL,
		0x97A74477958F6EFDULL,
		0x445DA6ACCE21460AULL,
		0xD355DFDCDB13263EULL,
		0xB094B4C90B619B8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6BEC5A71C68ED80ULL,
		0x61385C2BB6D9B89EULL,
		0xDB5A44582D46A3CAULL,
		0x1B692E87FA8300D6ULL,
		0xCA28A50BDAC1AA72ULL,
		0xB0CC2123EA846CBAULL,
		0xE7591D9C65769DA9ULL,
		0x55F2142C2E18E9F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA84B59003A42ACFULL,
		0x6F7B5ED41C3F396DULL,
		0xFB3E88E09F91FE1BULL,
		0x1078A5CC6A49626CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AF502883AE68689ULL,
		0x90F1DAE3C9547DC2ULL,
		0x7149DA74576F7B36ULL,
		0x18116558799F09E3ULL,
		0xE9C83665819340D9ULL,
		0xEC33417E12AEC3DBULL,
		0x72793362A8C811EFULL,
		0x18308F0244A638A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AAE32220F795A0ULL,
		0x8A4C7D39CE474B51ULL,
		0xBF740FBFB7016670ULL,
		0xFC98C15427F58D10ULL,
		0xCB6B3B75A7F43FD2ULL,
		0x17C2A5CC80ABEA13ULL,
		0xA1CC1E26173824AAULL,
		0xD8E7AF68D6E55C08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35175F0067891392ULL,
		0x8F5C7A05A7798625ULL,
		0xAB86F1B23BCB4D23ULL,
		0x0049D4CA9C4A3B81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B6F01B53BFE1195ULL,
		0xD4B06466458115C7ULL,
		0x754126999EC00A34ULL,
		0xD52E72FE6B9A9AE5ULL,
		0x13E1FD5E52853A76ULL,
		0xB8D81D2A2B494AA6ULL,
		0xAFF913EB700637B0ULL,
		0xF366F396A3CB1E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B033F003D6D7ADDULL,
		0x32C769EE658A8B4EULL,
		0xC1B4F42F3C27FB0BULL,
		0x22DF729BDE3BB5C9ULL,
		0x30877D248997AC27ULL,
		0x0CE8B555621E54CDULL,
		0x5428EF09F6F7C1D0ULL,
		0xD8CEC50A69C5046FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFDACB48D1D3B71DULL,
		0x2772640DBC5708AAULL,
		0x5471ABE25ABD8E83ULL,
		0x24E5E9332A46C259ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE65010EF27D6FB43ULL,
		0x0E03E46352756593ULL,
		0x1C96E3AB792AB284ULL,
		0xE4D356407FB8248EULL,
		0x0CC9BAEE52738BC5ULL,
		0xA0FC112A465C320AULL,
		0x5DFBD4E79DFAD49BULL,
		0x0941A465070DEB60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E35F5D91ED8299ULL,
		0x1199A372C20F134EULL,
		0xE257372C2F0E0784ULL,
		0xB63A48C96B935780ULL,
		0xA0C45960ECC234A1ULL,
		0x4755EB0DD669A93DULL,
		0xB8F9ACC8958EFF04ULL,
		0xA5CA1F64E3989550ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45392C8EAE3C6485ULL,
		0x4B13E9292E66A09DULL,
		0xB891A11A8A1E5F77ULL,
		0x7256CB7C578F935FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83042A768A61AE44ULL,
		0x02070F1E779015B1ULL,
		0x55BA91204785F1C2ULL,
		0x00841E73E6331002ULL,
		0xB0CBF741342CF36EULL,
		0x83BE3134201C129CULL,
		0xC6456E58A6EAFF31ULL,
		0xB2A1477686B41E85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53B0A8ABA128D89ULL,
		0x08136A2CF2F40409ULL,
		0x685120E5EB48A28DULL,
		0xF79147CCAA3FAB02ULL,
		0x37AF3B299B11C082ULL,
		0xECD9D017643DB1EFULL,
		0x333A7482A3B4A97CULL,
		0xAECE28DC61148D39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x980D0B6C8A58AFB0ULL,
		0x5FDA0F35679E6B67ULL,
		0xC10A85FED64E0803ULL,
		0x1A496188D1A2F65DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF449A550DCDDEB5ULL,
		0xFC1A11EC90C1CFC0ULL,
		0xF60F701D534AF05EULL,
		0x43879E74B0BE5669ULL,
		0x2B9720AC93F5CE4BULL,
		0x68BC1CB898F059D4ULL,
		0xB2A52E6A62151D8DULL,
		0x1DA99D14C7BDEA21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47452E2A05F10638ULL,
		0xF14EB9A49F7D77D4ULL,
		0xD2821B88ADE53E48ULL,
		0x11A39CE058436E92ULL,
		0xD290415D14EC5347ULL,
		0x5C866E6F9DEF0C09ULL,
		0xE629D5545AB2DA72ULL,
		0xD4BC8B88D2DE7899ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF0491F7E3451713ULL,
		0xDAC3371D3375E3F5ULL,
		0x7DDC8DD9BDFBA819ULL,
		0x05149C5AB1A5C1FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9580DEF6BE1A38F5ULL,
		0xAC6C9443580F7A55ULL,
		0x5B8CAB8E8B99B1B2ULL,
		0xE871E105A37437BFULL,
		0xFF93E41C9AAFDF63ULL,
		0x200D59828E94A61BULL,
		0x28844B2977AC7473ULL,
		0x00B992B2089A6077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A31BA3DBB23F4D1ULL,
		0x8883759CB4AB225BULL,
		0x298DE09906841515ULL,
		0x1C9DD198F595953EULL,
		0xD72A4037762A46DFULL,
		0xC175495A131ED16DULL,
		0xA97F7FAB8F183DB5ULL,
		0x43F79E63B33C497AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AFD78BC6ECAE653ULL,
		0x2E7B84A8F6E1E9D4ULL,
		0x0CB4FFA60B15BCB9ULL,
		0x509E530D59D60BFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42006D707D693958ULL,
		0x477E2DF0337C2969ULL,
		0xE3BF220220E94D9CULL,
		0x9B19790DDD5D57E4ULL,
		0x307D10175816FE4CULL,
		0x17EBEB7F7D9C7148ULL,
		0x2A4552853EE03AD4ULL,
		0x836A6447799BEB55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA3051A7839381FULL,
		0xD1C9D02250C35E57ULL,
		0x3478AC0605854F17ULL,
		0x48094C03C58D779EULL,
		0xE43BA722D865B243ULL,
		0x4E0FAC95C135B282ULL,
		0x7D782ECE026A3862ULL,
		0xB3D77D8C59D11D11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6712FCA0F9814985ULL,
		0x6C65B47FD9F91C5BULL,
		0x55B9C32F14E85B68ULL,
		0x22DE6CD0CFEA7E52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75916F0503373722ULL,
		0xD748A9E9A2BBA302ULL,
		0x580BF0A3D3960A3EULL,
		0x1A8376DAD3A845D3ULL,
		0x7EAF57AE5115BD3AULL,
		0x6C9698861CBE8C9AULL,
		0x2156EE8A1B2F8972ULL,
		0x340F1B26A710E418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x614F0A936074DCFCULL,
		0x8F8D8F1C9218A880ULL,
		0x1C540C9D3AAEAF6FULL,
		0x401FBC6FEFD26777ULL,
		0xF02AD1EAE538E07DULL,
		0xE07CBCB02D67D47EULL,
		0xD338BA2AEAF3C4F9ULL,
		0x253F45A06F531CBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BEE3F73A58B1E80ULL,
		0x1391BC8E97824E99ULL,
		0xD433AA27C1C684B4ULL,
		0x0D3D6C572A0175E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07FC1A615D70E017ULL,
		0x5D3A73628C6A3C12ULL,
		0xBCC43B5633A7F2F5ULL,
		0xB2166C3C86D3E92EULL,
		0x53CD8FEF9827F440ULL,
		0xF5521BA529AE9759ULL,
		0x67DC70EA22B76F7DULL,
		0x9A9B18BE7B67226CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FBB76D3E42088CCULL,
		0xD9510F703C6580C7ULL,
		0x9022441F30D431E0ULL,
		0x1BE6880517A8B89AULL,
		0x571191158BDE4E95ULL,
		0x021892E988CD7A63ULL,
		0x1A633660F3C2E1D0ULL,
		0x7BDC1B43AA93A23DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC2877EB4C3EEF6BULL,
		0x9E73AFCC316F07CDULL,
		0xACA0A793FB20C8E6ULL,
		0x268984726E903799ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x754A8388D916C247ULL,
		0x14134F90A4D23874ULL,
		0xE043AEA1B4A664EFULL,
		0x9B58C0A392C599FAULL,
		0xAED4490C46CA6E1CULL,
		0x40CE5DF35E3D5AA7ULL,
		0xBC6D15BB04A0127BULL,
		0x3A8A206DFA87C6CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC812AAAD1CAEFE26ULL,
		0xCF8F997EDA42AA6BULL,
		0x260194EA08579D34ULL,
		0x60204C0F6D9AF760ULL,
		0xA844DBE58D39CB67ULL,
		0xA664D68E562B3DD4ULL,
		0x3A62CBDF958324CAULL,
		0x0FEADFCA87FB304AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6820C9B47DFEBF6ULL,
		0x302DCF10FD3FD55BULL,
		0x07C9104A2A9A0FF1ULL,
		0x0EDC0CD72608F9D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE07AC2F6301D06A7ULL,
		0x6D02B0E2BBB46D07ULL,
		0xA5BED3DB9B5BF88DULL,
		0x54CBB6A6E1E8AEF3ULL,
		0xFF86831F4C17AF14ULL,
		0x6612F0733972D585ULL,
		0x4DE401015E76D704ULL,
		0x0F53DB244CB5BF55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E1E4055EB790C1ULL,
		0x82BA3C0DCE9357B0ULL,
		0xC3DCB32234DC78BCULL,
		0x0E792905279F94EFULL,
		0x293A6CACC4E20BD4ULL,
		0x7939E53DAAE411F8ULL,
		0xFDD9DC3DC2910A65ULL,
		0x393A4ACEF0D4B7CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DE433F0E35BB082ULL,
		0x12801EC816521C65ULL,
		0xC36395C28A9BDF68ULL,
		0x0E1DFA4D5DB037CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E30188E2DCE913ULL,
		0x217FD10AF89F8FEFULL,
		0xD4D4CB135BC9E1D6ULL,
		0x2CD38F185805640DULL,
		0xD86D22BAB84B1100ULL,
		0x8DAB77583FE7D24BULL,
		0x56051816591A3F9EULL,
		0x3F8EDF19C42B4E36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34486D842C16737FULL,
		0x5E18436345719974ULL,
		0x0144E8920CB7BD22ULL,
		0x8F86E040072E0156ULL,
		0xE7F656A0C81D90BBULL,
		0xBA029DA6E7B36309ULL,
		0xCFB4EE02357E8465ULL,
		0xC19088D7AC1A1FF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x433CDFDE5D877CDAULL,
		0x2E77DDFACAF67A45ULL,
		0xC376217E982FEF23ULL,
		0x510D7CA7E36440BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBFCBE64BF67E2B8ULL,
		0xB4F2C0C4F3950195ULL,
		0x2FB8C900BF825968ULL,
		0x56FFB42EB45E9F81ULL,
		0xF589B216B7623783ULL,
		0x820B88AB31F08D19ULL,
		0x39C314546B8B7446ULL,
		0xF5B95C1ED927B601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2658A96EAAF9005ULL,
		0xE48485DA11440064ULL,
		0xD453F2CFF43BB5EFULL,
		0x452FE6D3E2F5BC7EULL,
		0x554F867CB29F939FULL,
		0x5EE3A3EC9FCDB093ULL,
		0xAF813CBF9B7FBFE5ULL,
		0x09EFC5D0D236C5EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD239ACAA899CABBDULL,
		0x085A2F34937DBD2CULL,
		0xE12AD647AD0369E4ULL,
		0x11BC1CEFD92C85E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x735AEE9284024707ULL,
		0xBB2B060785BDB24BULL,
		0xBE8B255AE3314F06ULL,
		0x5E1752A22E4E8BB7ULL,
		0x561E772C890871DDULL,
		0xCDFF3B48A171F22CULL,
		0xCBC18419C828499FULL,
		0xD07DAD4FB441B201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF014683228698133ULL,
		0xC437B3D52F92E74DULL,
		0xB449EA8E0E3D9401ULL,
		0x92075C642ACBA191ULL,
		0x5D032BBE959E476DULL,
		0xE5643E99F42959F3ULL,
		0x2FF376B534447067ULL,
		0xAA65A48A1253BA90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D53B8B27D5B1332ULL,
		0x7DF4D4200EF16372ULL,
		0x2AD737BAC8C5F951ULL,
		0x73A143940CD5A503ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47F15EF51DDD5AE7ULL,
		0x2637998FFC499D5FULL,
		0x6DDDCEBFECD896E7ULL,
		0x96802F4BF3B602D9ULL,
		0x897000E359B2F6CDULL,
		0x7D0E4876CD3903D4ULL,
		0xA90E40AEE663D7BDULL,
		0x35120786E78565A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF476D1944AE81BULL,
		0xCBDF7154377EE043ULL,
		0x24E7665DD5790001ULL,
		0xCA82D4BD426F7085ULL,
		0x943AB1A9CEAE7C67ULL,
		0xCF72DE1E07F4DF55ULL,
		0x6661A417E2DEE79FULL,
		0x2AAB18F60979FE90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92E6AAAE2C3C9E16ULL,
		0x1F69F1690CE827F4ULL,
		0x2E95A6CC9D1B3B4DULL,
		0x5744C40FA6F7DFC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B7535EF0DF85506ULL,
		0xFBB1E41ED339231CULL,
		0x978C3EC2498C0C8BULL,
		0x89E95FDCC92B24B2ULL,
		0xFAA41E21F77FF62EULL,
		0x985EBA71515DA069ULL,
		0x11ADA0898A9A5C87ULL,
		0x524891B67F57A6FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48B06A9CBB72D7DDULL,
		0x279ED891C469218FULL,
		0xD312977FBE11045EULL,
		0x8E1E6CCAFB8DEEEEULL,
		0x47AD98BD1A1565ACULL,
		0xF216066D647A1C34ULL,
		0x81D485B9696E7DB6ULL,
		0x7856D54E484EED98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x635C984B3056EF91ULL,
		0x82DDC4223895A185ULL,
		0x1EB3A22777FE1B26ULL,
		0x55ACEA89F8E8BAFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12958BF95A692A4FULL,
		0xD6928A0D94E3E8D0ULL,
		0xC5CFEDE959603439ULL,
		0x07C57C1514DEC98CULL,
		0x8E6FB02704B8EFB7ULL,
		0x89D7D9E8791E7BC3ULL,
		0xC61C932A42B2DB3AULL,
		0xA0DC03C4254CE06AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC882C5550EB999DEULL,
		0x440056FC8E2A9C84ULL,
		0xB147296FA77F4EBBULL,
		0x2A6AF7C7ACF910C6ULL,
		0x459BC16ACA8615E1ULL,
		0x3C44E647A28A7B70ULL,
		0x5E91FD086E53C3BFULL,
		0xAF80314F5F2AEC4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19883694EF3BE5D6ULL,
		0x16625CF0E0B158A8ULL,
		0x731B0D7F37FE61CCULL,
		0x30FBC1A2D0EFF4FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D3EA71D70C5A08DULL,
		0x2C421DEFD92B3BFFULL,
		0xED840D1D97B0EE83ULL,
		0x8F20C011C617A155ULL,
		0xBD3F8DA0CCAA97C9ULL,
		0x68881DE2ED06B326ULL,
		0x3A80B1975DC28F48ULL,
		0xD9C7F7BEF80D5C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x036C9DB54035C88FULL,
		0x57102156F6C24153ULL,
		0x576E95BF0299A6D2ULL,
		0x5AAB0EAAAAB0FCB9ULL,
		0x79F0D1E34476D954ULL,
		0x3B6CFE8B666D0345ULL,
		0xC21803872FFBC096ULL,
		0x9C14C78E264F60BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3781E78A683E1EB2ULL,
		0x8738A396DD39161CULL,
		0x759F4DC56099F623ULL,
		0x5D0ED8A63D9A011AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2477901155985C7BULL,
		0x131D1917105CE046ULL,
		0xE7422A8E4B94D08CULL,
		0xABB8F5C265C9CC58ULL,
		0x0D1F2972FB1C7481ULL,
		0x12021F6E9AA1F10AULL,
		0x63AA7BD9CA9AF0A5ULL,
		0x524C216494E5BA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6874F948AF185A8AULL,
		0xEF59BDFDBA95FA62ULL,
		0xE7F1F27633B663C3ULL,
		0x239F76A7BC586FC8ULL,
		0xF0C933A71AE5EE7CULL,
		0x44F7D235BF73AE29ULL,
		0x61AB2E2CD9E119A8ULL,
		0xD99B3BD87B53D884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0C5130BEE97E3B7ULL,
		0x934AD189DEA4D327ULL,
		0x4B35BFC3D374564EULL,
		0x725B91E67518E902ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EC16C99DFCE4151ULL,
		0x220A956E139A726EULL,
		0x378C67617BB08AB0ULL,
		0x632F45EB57CE8C2CULL,
		0x6FCF73E13AACC7C5ULL,
		0x484C7732FA97DDBCULL,
		0x74C9F06D2BFAD266ULL,
		0x66563F29ECE112F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFFAD1BD2DA4BC17ULL,
		0x90AB20B2AD9EA0B8ULL,
		0x26A53217042F84DEULL,
		0xF94F0BAC5B914EB1ULL,
		0x101EBF7C4F772284ULL,
		0x00DCF7A15A7F95F7ULL,
		0x4424F2AD34DBA1AEULL,
		0x2A8318144C0F7719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA30161D79C200E10ULL,
		0x2BEC645929967901ULL,
		0x4964DFC92622412CULL,
		0x4B380774DB5A5F6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1928AE03BB4BA7A0ULL,
		0x7AA4B176813475FAULL,
		0xA2D9B5ED053F2EF3ULL,
		0x649A4C3BAA86B49CULL,
		0xBCB566557BD5D91AULL,
		0xE295228832C4C1C1ULL,
		0x763D3F6755E559B8ULL,
		0x2A152625E3A55D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E034BAAE20981FULL,
		0x34AD24898175C128ULL,
		0xA23071ADAC96B2B6ULL,
		0x4B87D28D4D1DFF05ULL,
		0xCFEDF0AB7E65981FULL,
		0xABACC4308BF1D3DEULL,
		0x53F23F4EEF776B20ULL,
		0x139BA2D30FABC704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDE3F084ABD4B535ULL,
		0x6C758DEFC30E0480ULL,
		0x17CB47DE8CF9E6D5ULL,
		0x6F1BF7F9D4750BDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x633FE6DD765D5F77ULL,
		0x1C3EA01ED5C37C0CULL,
		0xE33ABF29FE5B023EULL,
		0x5A6EB9A2BCCB0B26ULL,
		0xE7FCE427B080F563ULL,
		0xD9F5C4E3C38558FDULL,
		0xEC948130BE0650FFULL,
		0x2E4DB16DF9CD7C9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E797796D4E7E2E0ULL,
		0x7A04B46FD0C395C3ULL,
		0x513F692A26E9FF58ULL,
		0xBA6175621821AF11ULL,
		0xB7FBCC277A030D43ULL,
		0x0C55B9229E746D03ULL,
		0x32B7FADDF1CCD811ULL,
		0x2F703F05D3E72761ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64EFFF4EB825F131ULL,
		0x27FBAA5A8582ED6CULL,
		0x28B7464A27F8F658ULL,
		0x74EC3FB644DA02A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AD71ADD9A1148D9ULL,
		0x14A464B20E428746ULL,
		0x67F424D48BF0DA52ULL,
		0x1C4B5A7228FA46E6ULL,
		0x655CC83CE6E26E71ULL,
		0xA35BB7D4C5DA50F5ULL,
		0xDBC6B9946C85C752ULL,
		0xFB2A66CCAEE17C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F889BA2BED75685ULL,
		0xB94FDACADE3BA5ECULL,
		0x4B83F732ED841076ULL,
		0xF624502155050AD7ULL,
		0x027A0C57D806D18AULL,
		0x2627D46CF5252E29ULL,
		0xF0B5BBDA5FBD611DULL,
		0x23498AB08929D8CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8F6633B0FD34138ULL,
		0xF1084B502AEA0BB0ULL,
		0x00F5D73F842BF5CBULL,
		0x3187B67E6D3779C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x819C3BFF3D67973EULL,
		0x8F25B3BA5C52B512ULL,
		0x737D50B1259B0702ULL,
		0x8099E0E4CFD7EC01ULL,
		0x76D23D7FB57F8F6DULL,
		0xE26ED28AE2140DF8ULL,
		0x23B97AD4FDF654AEULL,
		0xC688B01E22618B72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B58C2532A795C6ULL,
		0x7C95D613CA2B368CULL,
		0x783958EAD66A01A0ULL,
		0x4C5D79E1CDDB63C9ULL,
		0xEA3C93CAA11E881DULL,
		0x9F84C2250F51F802ULL,
		0xA817E5B0C5A970C7ULL,
		0xEA3DE54F4468FDBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x791DE0BB11271687ULL,
		0x014E4CC3DAF6C0F8ULL,
		0x55401B26AA9AD9B6ULL,
		0x675681B7F4E19174ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0D447741E552E04ULL,
		0x952B7F2E827DF042ULL,
		0x947F612204622397ULL,
		0x2B4C22CBF209C639ULL,
		0x7E2E4662E7F8693EULL,
		0xEB34CDC1282751BEULL,
		0x81BA879E4A6C739BULL,
		0x508C2E2BE20ABC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4A2B01DD07903DULL,
		0x2BD44EDD38D7C456ULL,
		0xDF321C1ECD9989FEULL,
		0x2E442101BD994771ULL,
		0xA33004CF46210010ULL,
		0x968EBD262F95FB65ULL,
		0x0C3BC9F119AAA971ULL,
		0x22CC0A9712BACDF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5447D85C47473B92ULL,
		0xF9FDA7522F38FD1CULL,
		0x261D6CB8738C9BE1ULL,
		0x478D49E0FA4DEA73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x178497352E993FF6ULL,
		0x7F78A4D0856FD247ULL,
		0x29E80EC637FF5D0EULL,
		0x8B06B8421906FD0EULL,
		0x34110F32AD625FB8ULL,
		0xF5CE44CC9FDEF0D1ULL,
		0x6C02B338A405D4CEULL,
		0x90F1A0F7CEB91FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2226E86C218C29A8ULL,
		0x8F0599DE94B7F244ULL,
		0x31D8B161789FBC0DULL,
		0x8A1F09CD3038A049ULL,
		0xDFDD69FE6ECD5E3DULL,
		0x0E0B7DB833F184BEULL,
		0x05CDC396E1F49EE2ULL,
		0xD376790CEE680AD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7508348A572B4D14ULL,
		0x575C97F9F5F5EABBULL,
		0x23EAEF678DEDA22BULL,
		0x212F9B5234D7789AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA66EA671C8A35ABEULL,
		0x3BC417A1CBDC0C28ULL,
		0x7B61D66EE3469A3DULL,
		0x73718B649304366DULL,
		0xEF1572BD39AD77B6ULL,
		0xC5B80D3594583774ULL,
		0x93F3EE5E3B4F1A09ULL,
		0x5A800C0F3F23BE15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x492F9755A49E9041ULL,
		0x6B16735FE31BA9EEULL,
		0x83D92ABCAB6F3388ULL,
		0xCDD21FDECA3692A8ULL,
		0xDDDEB2F18B719C20ULL,
		0x4BF17D703CCC33DDULL,
		0xE7F8A9786CFF13A2ULL,
		0x65661AB867D59978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB5F875800E76275ULL,
		0xE426FB8CE788EAA6ULL,
		0x7ED4E5CED7B85A10ULL,
		0x07793E69BE671306ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38F7F8EDBD337588ULL,
		0xEB12471D049D0D65ULL,
		0x652F627DCCAF2BEFULL,
		0x02C52F54A59E9DC5ULL,
		0xA249E5B5BF46BC7AULL,
		0xF798E122EA7AF15DULL,
		0x047AC2934C322406ULL,
		0xD83571A9C36E4008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95120F56AC2BB4E4ULL,
		0x50DB88E6D91121F2ULL,
		0x2A45FE60C7DB1687ULL,
		0x84B2B4926D1A1EF8ULL,
		0x83BB1BFCF8F1EF93ULL,
		0x760D88A48B1538D8ULL,
		0xF8ED5C036F935C33ULL,
		0x91E9882C92F88420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D17DB04819E2C57ULL,
		0xD4E5E0F854A54F35ULL,
		0xF1E69D77C465BECDULL,
		0x6D57235769FE6318ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC45992DEDB350FE8ULL,
		0x4A101BCE8630522BULL,
		0x45AE8FE6CF740D4DULL,
		0x7B660DC0A6C52197ULL,
		0xF2BBA092D6BE6460ULL,
		0x28DBF5E5AA842026ULL,
		0x7ED562ECE97943FAULL,
		0x8D7D26A007269C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBBF5EE62700C2DULL,
		0xE25FBA2D67E3234CULL,
		0x544CCFCCD24356C9ULL,
		0xC1F84582F185D8F5ULL,
		0xB8B2BCE860F68D0DULL,
		0xEE9080471E33DFDFULL,
		0x485A697459609798ULL,
		0x8238D92ABD6C4682ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75EF683DF46EFA33ULL,
		0x0EE3D729F236B971ULL,
		0x07A2C7FF60DA4CF2ULL,
		0x659147A6A6E80E4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70005D257CAB7807ULL,
		0x101718C12FAF3A75ULL,
		0x1DE321645B2269DCULL,
		0x914600AB88629D09ULL,
		0x39BF165180D318E7ULL,
		0xA14C428619819402ULL,
		0x269A8DFF508CD62BULL,
		0x20B9790D6510E45EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CCF36B87EE3EA3ULL,
		0xC70B4656327169CBULL,
		0xD158387911D8DC6CULL,
		0x8331F193BFBF6FBCULL,
		0xF5221B72639F9ECAULL,
		0x1F365103DA6DA741ULL,
		0xECCE37268013ECB8ULL,
		0x5A4FFAD7C09FE8F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB80A6D84A61586FULL,
		0x984DABC05A32F533ULL,
		0xE0DFCD1A3B3C3494ULL,
		0x01BCCB0E31687F10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0F561B0D6F5AE7DULL,
		0x61E62F524B614362ULL,
		0x54A0ECE377E0C783ULL,
		0xFDC6C02A047F00E1ULL,
		0xD22053D59997B4B3ULL,
		0xF98AC439CD6372E3ULL,
		0x09BFDB266F5EBA79ULL,
		0xFB9954E702C43DA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1429FB4DC7F4E7BFULL,
		0x0FEDFD4F060FCC9CULL,
		0x7C30A30CC4ACF230ULL,
		0xF589D25103CAD79BULL,
		0xDE7130336DB80AD3ULL,
		0x3D2DCFFD5A54DAFAULL,
		0x2B44D6D0CDCE8C74ULL,
		0xBEE39BE1361869F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8CAB0759233FF54ULL,
		0x47C472FC597C035AULL,
		0xDEB2EE8CAE9AAA2DULL,
		0x0B3664B5623595D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74FA3D8A6A5EC0E9ULL,
		0x97FDF2A94F08FF30ULL,
		0x514FC180C42426E9ULL,
		0x00E60BA1F1704FA8ULL,
		0xB6FCB67F7E94CC3FULL,
		0x4AA14A759AA41EA2ULL,
		0x1400AC840E38B819ULL,
		0x45EA3BC36E2D6957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4751823FA502CC3DULL,
		0xB7F9448FC4E4D484ULL,
		0x6D2DADE31E489EBFULL,
		0x30695A2697B02005ULL,
		0x5F584633704E7832ULL,
		0x7E4F905967F3CF38ULL,
		0x8FAE034FAA528285ULL,
		0xB1267F85DE4643ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30116694E3CC6C27ULL,
		0x34264E49104FF475ULL,
		0x886731647A077C1AULL,
		0x658AA29EB60FC6F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F0DE5CECCEDD04AULL,
		0x779120CD7D5F8A87ULL,
		0x03C2F404FCE6CF89ULL,
		0x3D891946C9F4C3F6ULL,
		0xD35F896171B6B886ULL,
		0x9133D0B10E458371ULL,
		0xC775C64B301B2516ULL,
		0xC05A0A537B7E193CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4EA7292B811FB3ULL,
		0xC9E30D9FE158ECF2ULL,
		0xE8A6711B63D5416CULL,
		0x9B66E8FC2D50AF51ULL,
		0x6FB64692162F8109ULL,
		0x5F71FF9100A857F2ULL,
		0x2278FE5D05AA491EULL,
		0x7F65C1DB181BE094ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAADF296D377EEE7BULL,
		0x10731DEFA15B127DULL,
		0x98A23043E5D234F4ULL,
		0x4664F2295D387DACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89ACB879D4152572ULL,
		0xC57326C4D56E58AFULL,
		0x59DC40B089472B75ULL,
		0x73518FBD4CE37A13ULL,
		0x6E2CA71B831F4B8EULL,
		0x45D00B92ECFBDF66ULL,
		0x82D2ECD4A4F17BE9ULL,
		0x7D18141D786314C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x963674362A96D28AULL,
		0x37F4B6330A7BD0B0ULL,
		0x2ED05DCFC3C92F08ULL,
		0x092E630844ABB04CULL,
		0x4D49DAF3F49BFEBAULL,
		0x0D74B6BAFC4F802AULL,
		0x6FC24DF472756064ULL,
		0xFEE7E4A9CC82694DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5209222D0FBB78EULL,
		0xEB0D089F8488AAEBULL,
		0xFF83782843EA1233ULL,
		0x254A37E08B913D4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB7278D6140461F8ULL,
		0xA0DA9D9D8BEE1D42ULL,
		0x17E8697ECC1F2B65ULL,
		0xC05B7E346F61E506ULL,
		0x09F924C1FDFB07DBULL,
		0x699BAE596E29E747ULL,
		0x4412C0693F3A5DEEULL,
		0x394DDB2C6D405BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1950750C13C0D9ULL,
		0x17DFAD6D2AAB9CF7ULL,
		0x1EA7722A3CCE40F1ULL,
		0x86FABF7791DBBABCULL,
		0xA74E2EBB31B81D92ULL,
		0x2236CE72567ED792ULL,
		0xCD5CBD5FE4AA3D80ULL,
		0xE717B79B559F5E9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76B9AD6359DF6419ULL,
		0x21F42C7DE4A6D512ULL,
		0x98456AB800B5BAD3ULL,
		0x6D6A06465F6BBCCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8876DAC097935784ULL,
		0x7643C5D87FD38699ULL,
		0x15406AF894149BD0ULL,
		0xC2E102B5769C420BULL,
		0x1FAF9091F480E7CFULL,
		0xEC2FD53B17D73398ULL,
		0xF371095ED6408A4AULL,
		0x0762F35641812B97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD42E5A966272337ULL,
		0x1CD03AF5A429EE28ULL,
		0x7E524FBD640DC987ULL,
		0xE696FDB9AB01BAC1ULL,
		0xD8345412F7EE43FAULL,
		0xE660ACE3F884F353ULL,
		0x9D2C328DC7B5FB3FULL,
		0x6D8D9ED29C98D5FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x577EEFF0AF30839EULL,
		0x363387D181DF2293ULL,
		0x6525FE4358980DECULL,
		0x31F4908646173C58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C05B9962421A1D9ULL,
		0xF41A65D0738A6EF1ULL,
		0xE37A3DF566F942CDULL,
		0xDBE10A4C9D12E527ULL,
		0x495C25662A97C5BFULL,
		0x49873B2E6D1B1E97ULL,
		0xDB97B8455CF4D355ULL,
		0xD966D2465C78AC15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BDF2E6467C0026ULL,
		0xF65D3EB807EAB32FULL,
		0xB27160EA9303F966ULL,
		0x674D8B7823875AD9ULL,
		0x87CF1C539B0EE25BULL,
		0x9FD0E1C5F7DA4A00ULL,
		0x4BF8DB15471D05A6ULL,
		0xA24B28EFF5930FC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2371F712BF763CEULL,
		0x2ECE6C99D33F4A22ULL,
		0x829DB22E11FDD154ULL,
		0x22AEA1A7BFA0BE69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E04E5E416131EA6ULL,
		0x5194419F9324230DULL,
		0x708BD69BB874EFEBULL,
		0x26E652EFB7AE4389ULL,
		0xC2A95CF21A0FDD47ULL,
		0xA6D006D6DDDB714CULL,
		0x37D7B1D8A5A3E2BCULL,
		0xB19DCC07BFD8A528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFCE48836C2F4FC4ULL,
		0x82897ADD8821B2E1ULL,
		0x6904A00264D26E15ULL,
		0x1DE62588529519CEULL,
		0xD44DB46230280850ULL,
		0xE482BC15007B9B5AULL,
		0x8DEE98026FFF9440ULL,
		0xAB5BFC774BF9403AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD1A2BD624D6B9FULL,
		0xA683DF88E73C3214ULL,
		0x40210C654A062834ULL,
		0x76C4FCD898422502ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE40BA6D1F85BE6FDULL,
		0xB2C95D9298377981ULL,
		0xC841CB0D49D762CDULL,
		0x994DD491A83F8730ULL,
		0xF8D30533080C155AULL,
		0x0BC5E7CA7CBA607BULL,
		0xD7262FA342E801D9ULL,
		0xFA3F96C9949396A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D7B9E4E468494AULL,
		0x11FFBE2C2E7416D2ULL,
		0x40CCECA1D6FDB395ULL,
		0x80FA516DCE6B6932ULL,
		0x6AC85FDE521412A4ULL,
		0x89A2DB4CB94722BDULL,
		0xCF2ED4A2FBC43932ULL,
		0xDAED989545D1A0E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C8778016C40562ULL,
		0xF1FD7A116CDE8CF8ULL,
		0xB62C6076022977EFULL,
		0x3E7F3EE78A9E9963ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BD1B3AFEEB35AE9ULL,
		0x777F69045650355DULL,
		0x49901EDE23201E9AULL,
		0xEBC126AC114C2B0CULL,
		0x62F4A5CBEA3BEF07ULL,
		0xDDD2B49A42A218C7ULL,
		0x709E2A4AA0D35819ULL,
		0x5258A5BFAC50AEFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9167DCCDD3A086ULL,
		0xD2A9DB27F4D8D015ULL,
		0xF3AC8A11FECBFC6CULL,
		0x5EF92159B6BC88CFULL,
		0x180498BC757D7B98ULL,
		0xE4EF0B99EF3F51BCULL,
		0x24805CFA7E073EC3ULL,
		0x6AF74EC21049520FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EE23C1E7524DC58ULL,
		0x96A0A3E8C220F0F5ULL,
		0xA2500EB14E9FE4F0ULL,
		0x653AEEF783A76D29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9844509E078E41CULL,
		0xC807FF361D412503ULL,
		0x9B0578DD29BED4ADULL,
		0x532CBFAC3E01E12EULL,
		0x5FFC1B8C2D813D46ULL,
		0xD4863E1FD94E13DEULL,
		0x1C70EDFAD4BC25AFULL,
		0x06F7CA18F83F0FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1DFDE29724C769ULL,
		0x019EFBD5E024D1D3ULL,
		0x760C8DEEDB6A7D52ULL,
		0xE4E33AA35BEA43A1ULL,
		0xC0E1F5199CB7BEF3ULL,
		0x66D86D5CF99183E8ULL,
		0x2606DAC5F7348C26ULL,
		0x9A0D309FA592A935ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D47FC28C73CD9AEULL,
		0x0E36004D7319B1A6ULL,
		0xB8B7C4C7307521C2ULL,
		0x191C4D0B27AEDEC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEB82CB353792F97ULL,
		0x5138B34690B693CAULL,
		0xE9C8B507256688A1ULL,
		0xCBFEF3BCFD1B8ED9ULL,
		0x89A30930C7162CA4ULL,
		0xFAFAB9E3A6994216ULL,
		0x676E08DAC316F142ULL,
		0xA435F943C1985F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24BC3E2E98FB7167ULL,
		0xEF3F788C1963A72AULL,
		0x98E777419A6EDFF5ULL,
		0x4E90F28B326052B2ULL,
		0xB75916544269756CULL,
		0x999CE56226B51865ULL,
		0xF1273C960A89EE71ULL,
		0x9157D06770E7220CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0F5FB406C20F0F2ULL,
		0xD5E6C5F373311CDFULL,
		0xDF638FF8EFE613BFULL,
		0x4A6811E5C50A5132ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x706A8657DF2D38AAULL,
		0x0B0E00E85FBBB2F5ULL,
		0x612E6B6DB5E48684ULL,
		0xD0CFB9E366739F00ULL,
		0x6506975DDEDF4E3BULL,
		0x20A5807647FE4109ULL,
		0x208717861EB80EEFULL,
		0x2E9F94C79F7CC517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D68C48C4816D6EULL,
		0x07FE703A7113CF7AULL,
		0x47DA916779AF7725ULL,
		0x5BC1CEA4A84B127BULL,
		0x86890314FA44BB54ULL,
		0x3FE310D025904979ULL,
		0x42EC64BC10BCD3ADULL,
		0x371D72620CA66EC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD37FCE1099D9960ULL,
		0x5FEC23570AFAA2D5ULL,
		0xFE4A64044F7FDB26ULL,
		0x325F065289F95CABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB4C4F8A6EF161F7ULL,
		0x6C4F70165927EFAAULL,
		0xBE052D44E6A7D405ULL,
		0xB69A3278BACC2BD7ULL,
		0x15629A19B0570CDCULL,
		0xA97A0CD28FB5C9F2ULL,
		0x68BA94E6435F5835ULL,
		0xF9F02A9C1093B28BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDCCAC1F94FDE27FULL,
		0xB73BF9B936FF88DBULL,
		0x082F940ACC0F5F94ULL,
		0x7CD7DAF33AF51D9EULL,
		0xEBFC5D95584BFB99ULL,
		0xEBB75BBCE8EE9216ULL,
		0x473B20B54F19D4D7ULL,
		0xC93BA89144031F7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22AC9F0FEB981074ULL,
		0xDFF9BF93E3BAB157ULL,
		0xAEC0D87E5CE9F45AULL,
		0x748DA51FDD4CE278ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD850D7908AE1000ULL,
		0x2EC9E9DC0F26FCE9ULL,
		0x54A7832672638394ULL,
		0xD4C7CD423617BC7EULL,
		0x95FB46152C41F768ULL,
		0x7E24F70047BDD2F2ULL,
		0x6D614C0930FC4D91ULL,
		0xF4EB78C65C20E531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4DF84A9B9733EBULL,
		0x94F31082B242D0F7ULL,
		0xB749B15C9807722FULL,
		0x62C36DE16B5FD860ULL,
		0xC41CCB36F7490B0AULL,
		0xBBEE50CF5EF64453ULL,
		0xD9B2F655D0753839ULL,
		0x4959DDCCDB2DB412ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x973D522A4A09F5D2ULL,
		0x6DF3849BEA835785ULL,
		0x893E8A6A2E693C6BULL,
		0x69A16069EED12EA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC395249C5F6CC590ULL,
		0x48FC1341E1AE1605ULL,
		0x875819B97D076E90ULL,
		0x8CD090CB6E937AE8ULL,
		0x68A563B7583AB51EULL,
		0x8824B696B809BA14ULL,
		0x7AD70887D9B32010ULL,
		0x695E9AFF9CC0B0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x761AA4AB935CD481ULL,
		0x13521CF25BD3E61AULL,
		0x8958CA06C2B790EEULL,
		0x97839F2D4B5B0F59ULL,
		0x6098867634C7DC56ULL,
		0x814F989F207853A0ULL,
		0x135385968A647F6DULL,
		0x35FFDAC64E163B7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F63579C0F1C1FDCULL,
		0x394C6910056F6524ULL,
		0x5B84BF847FFBB5D5ULL,
		0x155D7A1FD085CEF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13FC35FF4F5473B3ULL,
		0x7F4553B4C488CF41ULL,
		0x066D8D49D07F10E1ULL,
		0x5E1036E1E1FBA739ULL,
		0xF2CEE15280A60FD0ULL,
		0x99EB72FD8C8D3CF0ULL,
		0x8FDE3FD71159D0E3ULL,
		0xB1E1C037FE563082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDACBF0B43961F75DULL,
		0xF73F135F79F810B2ULL,
		0x47585B6DA8466FBBULL,
		0x7F37084F75E03C47ULL,
		0xF853AE55FD74D3BDULL,
		0x3CA432EBAC364288ULL,
		0x63E38B6BD3375FBFULL,
		0x92C9B387154B286BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6779D6C68F4167C0ULL,
		0x6099C2FC9779E9FDULL,
		0x464BF9C761556C8BULL,
		0x7C6B10D503BE9E62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB02B49051F5896CCULL,
		0x31013FBAB39357BAULL,
		0x22AE90EE452D4952ULL,
		0x5E00BD1CC31C0FE6ULL,
		0x3A9C48474F8141BCULL,
		0x74B5DD2035C4D00CULL,
		0x9D67771B930140E6ULL,
		0x953DC01D8D1DEBD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975E6431594C5D51ULL,
		0x423F1C2E31224681ULL,
		0xA10D4C0A33D664DFULL,
		0x18C4349E4CB98550ULL,
		0xA454AD84B169AA60ULL,
		0xEDBFA22AC3509866ULL,
		0x6E366CEA641AC382ULL,
		0x3EBF6D15B49C53BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x676DDDB73D8CB311ULL,
		0xF74EE3FB7FB153CDULL,
		0x82E8C831078D8138ULL,
		0x1BFCDBA8999F1E06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE74BDC901AF6A730ULL,
		0x39D4B050A9FED1BEULL,
		0x1DEEB29F0FC97840ULL,
		0x9C2E752240E1F0CEULL,
		0xABE4438F559F3739ULL,
		0xC7BE1C6EB76B3CE1ULL,
		0x891129584E5C5DFEULL,
		0xFE5DF18FD4EDA7B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962D62D713F08966ULL,
		0x366AF5007285738DULL,
		0x9A7B696D0B5F7691ULL,
		0x1BE9773DA3604566ULL,
		0x76C892297B601B76ULL,
		0x7C171BF78A01E385ULL,
		0x12D4FA399337BC6AULL,
		0xF6F08AC3491FD45AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x333ACED76C643CF5ULL,
		0x3E33CD00F51CA1E1ULL,
		0x106247C1CBD9FDB2ULL,
		0x1A8240415E0F0AD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF9ACAB8A958F60CULL,
		0xD1BF538326E8F60BULL,
		0xA33FCC74F2025C53ULL,
		0x3A059A638D646954ULL,
		0xA11112B5127B6825ULL,
		0x1A51B4462B2248B6ULL,
		0x693E93D339697645ULL,
		0x614779B94B317DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09A024FD09CEFA52ULL,
		0xCB88EA1826BCE59AULL,
		0x19D128353F4B4883ULL,
		0xD2267465A26C877AULL,
		0xC191315927581AE0ULL,
		0x653AA5DCF5EAACC3ULL,
		0x59F40CEC3BF4B0AFULL,
		0xC2A949C0D925BC21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2F6196086C771ABULL,
		0xE7A28D08E66D367EULL,
		0xCE7EAA89520C6808ULL,
		0x735A44DED8B69D3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E46E1325993AC80ULL,
		0x82548ADA567B6D28ULL,
		0xF36AD6CDB0E9D62AULL,
		0x655EB165EDEDCB27ULL,
		0xE21AB75C88CB3FA9ULL,
		0x90DCEFF4D1DE333BULL,
		0xC6ADF58CBC752B55ULL,
		0xBB8716BC63BFD00FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3451F1421872B58EULL,
		0xB1404DA9A7EC5679ULL,
		0xFC62FE865420ED04ULL,
		0xA99E9EF4EA695A68ULL,
		0xB8F501DB01DC7EDFULL,
		0x9A8F066AAB2F836AULL,
		0x2342F9DA5CEF4593ULL,
		0x52AA090C07EC79B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x258DE12A48919728ULL,
		0x60A4E7B26C7D2FBBULL,
		0x38E934C18AA903F0ULL,
		0x4C901A9EA4E3420DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0F3DC97734C69D4ULL,
		0x8F2EC17FCF56B4BBULL,
		0x7FD6BA618B9C3EE2ULL,
		0x07CC84AF8977B364ULL,
		0x5B677D40FFA50D1DULL,
		0x98497F6BBEA5B5F6ULL,
		0x621BCCC5F102B330ULL,
		0x31A6C03FF2815986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D134F950A5152CAULL,
		0x3A684FCCE7318AE4ULL,
		0x167F14B47E29BBE9ULL,
		0xB614331ECC3684A1ULL,
		0xE36D021C08A6F8B5ULL,
		0xBC551C0CEDC7A91EULL,
		0x703EC1991AE362C2ULL,
		0x537633D930C78B2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA30ED47F12B21D96ULL,
		0xFB0D31C5E91B11D3ULL,
		0x50274E54D6187347ULL,
		0x4CED28D17ED5CFD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF988FFE9B75C525AULL,
		0x9FB01D2BCC4B3ABBULL,
		0xAB3777E1B98F864AULL,
		0x1F5F418EB973B439ULL,
		0x7B74F5348B4C49C3ULL,
		0xFBEF71985DD4B4A5ULL,
		0x425F8601D756F2A3ULL,
		0x827B5650B5E45667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA4727B1C2F0BA4EULL,
		0xA17C159B2E5B64F2ULL,
		0x29F7F38FFD126983ULL,
		0xF0B2598BD3C29D22ULL,
		0xC6051F6BE058AA0EULL,
		0x4415A901868F7AD4ULL,
		0xD2A7FEBAEE43DBF0ULL,
		0x0ACC1A90D39DFD46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DDB940154954F5DULL,
		0x4887CDF492366AC4ULL,
		0x167D98D855527B74ULL,
		0x72AFC67E7C2251E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x724D01B73EBCEAF0ULL,
		0xB8596844F7C11367ULL,
		0xC23447DD0FD8250BULL,
		0x712869337285C5ECULL,
		0x5CF5EEEF11D32436ULL,
		0xEAAAB76F8374D7C2ULL,
		0xB64F26367D213DE2ULL,
		0x9F67DD50C62ECC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x560F4908CD20D9A4ULL,
		0x2B33B23170D33727ULL,
		0x6090094EF08B382FULL,
		0xDD18E7FE92C0A5B1ULL,
		0x7C78044EB6562CF8ULL,
		0xF071F1EC78902B30ULL,
		0x81FE510F5D6443A7ULL,
		0xFAA3E1740C67A9A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EEE8C7C0628C26CULL,
		0xB193078724DF79E7ULL,
		0x25A3E25CD55A119DULL,
		0x0926E3F873544D83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB53C2B51450EE620ULL,
		0x814233622A67B828ULL,
		0x093353BE54808A2EULL,
		0x5A5BEE38FAFE5261ULL,
		0x6E8A64C5731E0A7FULL,
		0xD2BB996E03CED4D0ULL,
		0x30AC09A88B182322ULL,
		0xC858F700B646EA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4D8951CC8C30B5CULL,
		0xB9D6FA14E4AE205DULL,
		0xAD4F274C994BED29ULL,
		0x7F5AD6023856BAF2ULL,
		0x17C331F80636F2F9ULL,
		0x4480693ECAF22E42ULL,
		0xAE609658F39C4237ULL,
		0x88F6486675C7DCF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F520B2A69959FEULL,
		0xE434604FB67A50EBULL,
		0xB3174A423797FFFBULL,
		0x43A7031C55839965ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56F0C031A994FF77ULL,
		0x1766B85FD7F519E7ULL,
		0xC0D9F6FED9EAD36CULL,
		0x062BB031582ACF21ULL,
		0x7E4210165126602BULL,
		0xF80BCDB5D06A504EULL,
		0x00F489A2669CDEFBULL,
		0xF5DD667F067CA286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49734853245ED680ULL,
		0x7755947F8FB7F41EULL,
		0x5873F5881648289BULL,
		0x177D07DD2A329405ULL,
		0xE941814647C129DBULL,
		0x25BDA3BC1AF9921EULL,
		0x22D021BD899942ADULL,
		0xEABA33DC9E4174ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B92AABFEA3C3910ULL,
		0xD7AB5EF136F960D9ULL,
		0x61CD6D6F922BDE83ULL,
		0x15E82C6FA6C1094DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36F052C252924B8CULL,
		0xC1126B4DB98F714BULL,
		0x25B753C05BF55418ULL,
		0xC196C3B3DEC64481ULL,
		0x866C2DEDF4FDFA1DULL,
		0xC47A3A9C71C9C7C8ULL,
		0x73C43A963CB709E9ULL,
		0xAD3D430890E92B96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0505C9978E1FEC69ULL,
		0xECB9DE741D76E581ULL,
		0x132E12060DEC19BBULL,
		0x9EC7FC027424BDD8ULL,
		0x31CAD947960C7CA7ULL,
		0x5E0E945FB20C235EULL,
		0x1CC6332E79563D77ULL,
		0x851224B12CC45F93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1DD19DCDC4AFF8BULL,
		0x085339DE123EF392ULL,
		0xFC3E5B214E679358ULL,
		0x193548AA4817CF27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80357A511E857C88ULL,
		0x4772F8E89FAACE7FULL,
		0x146B83D908BE816DULL,
		0x65B1F5D1B79C5FD9ULL,
		0x947349E2A6787F71ULL,
		0x98F3B1B8093550ECULL,
		0xAC03B42EEBCC419CULL,
		0x1E8AF75FA97ED7C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x880F242535F1873BULL,
		0xE63D1E41F664201DULL,
		0x1804C2DC46C9A163ULL,
		0x00AD5282ECAE9333ULL,
		0x27BB23F60547E9C5ULL,
		0x9EF8296784180BC8ULL,
		0xA529ECE36033F716ULL,
		0x96588E5F9BEC16D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B7BF74BD5CA2A3CULL,
		0x7C8C169A6B9EF1CAULL,
		0x00BA56337A8FEFECULL,
		0x1C803950CEB66FD5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x511AC6252DAF3049ULL,
		0xF6CD566832342D8BULL,
		0x4056C766E044533AULL,
		0x5F19F5DA2D9FA5BAULL,
		0xE4F0C23A59341D26ULL,
		0x11B8B0F284394489ULL,
		0x70583B8372C7A995ULL,
		0xC845A9CA2C5C8CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA61699CE968F5D8DULL,
		0x578D5A14227ABF2CULL,
		0x605F1C19B9A54865ULL,
		0xAEAC254C9387FE99ULL,
		0x27BC83B4D16A264AULL,
		0x114E6F99B3240A25ULL,
		0x90B68D35A724E431ULL,
		0xD6D6E4B62A41095DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0C57428BF1A7705ULL,
		0xAF05AF8318E01952ULL,
		0x11F78AD960C857ADULL,
		0x06DF1185EA2D3044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19564A5285CDA5D0ULL,
		0x75F4F69F2AA64E62ULL,
		0xB23D2F966A95699AULL,
		0x6AD7C576C8325F31ULL,
		0xDC2A24964EA5D9D2ULL,
		0xD5879E50A6D8DE3EULL,
		0x12FD29213EC76F7CULL,
		0x2618A071C051E888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA918F4B1D7101BAFULL,
		0xDAE5E3AA1697F830ULL,
		0xBF109E77D8454076ULL,
		0xE393FCB0EC912A93ULL,
		0xEF5314C9E2C02EF2ULL,
		0x21A9677B01A1F899ULL,
		0xCF3DAD02E5E98E2AULL,
		0x90464868B1FD38E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9829ADF8B2D4E4EEULL,
		0x4E0B36AB9A346CACULL,
		0x0198FD9FC33F9B6AULL,
		0x447CDA1DFC33461CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80C1E9FC06179E2DULL,
		0x9B34531FE6CD30C9ULL,
		0x35F87D84BDE59662ULL,
		0x78548187975B73C0ULL,
		0x34566B9E0464FC99ULL,
		0x9E0107F7552C62C7ULL,
		0xA59E7F59F04FFD63ULL,
		0x5E180D8161A11BA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB4F0D13691B786ULL,
		0x7307CAD11CD3EE39ULL,
		0x319BBA7AA34B9BEAULL,
		0x3F927D19652CB1D7ULL,
		0x2EA2537138580B99ULL,
		0x360C2DED9DD8C120ULL,
		0x129D87D77E5F6C07ULL,
		0x7E9594B7781A2A51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19C88FD11971ABE9ULL,
		0x9684E5C00063415BULL,
		0xD6818067044F8E2FULL,
		0x661FF266DC36942AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AADE166C027EFF0ULL,
		0xAFC2F9A4086BD9EEULL,
		0x770588E5E94C1DB8ULL,
		0xC7D1618127F4D6D1ULL,
		0xE90B7B31057278A6ULL,
		0xCD9B123E5F2B3AEFULL,
		0x5FBDA4DF4CFCF9F7ULL,
		0xC89CCC336B7B94CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEF09753EAB59601ULL,
		0x33363D1F7798246CULL,
		0x9402DA38FB96E6DCULL,
		0xF510FEB003B8B32EULL,
		0x8244818DE2FCA3E7ULL,
		0xA278AF0AE0770026ULL,
		0x534C49490DF4242FULL,
		0x3518197803FA3A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD465849F2EFF17AULL,
		0xE3A776295F946F66ULL,
		0xBBD646FA4904F292ULL,
		0x3872EAA2816F9A82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ABB7B33ABA3303FULL,
		0x5C07F27D8427F7B9ULL,
		0xEFD566D28B0E660FULL,
		0xF7561E2833B14840ULL,
		0x277000F06377B787ULL,
		0x02A7AAC3ED584D79ULL,
		0x359A26C4967D31DAULL,
		0x6D3984BEF329ECA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34AADF4B9F5EE2A4ULL,
		0x78865E6013EE5E78ULL,
		0xD1476D590F50C9F9ULL,
		0x3454757156EFE67EULL,
		0x368743E7D7E73CC4ULL,
		0x841B5095C879025AULL,
		0xCF7975E98386EC93ULL,
		0x924822B09575BDFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089CAB2CC3B685CFULL,
		0xAC56F6F6E95EBFD9ULL,
		0x476839FE4C4BE48CULL,
		0x42D636D8C5804E9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02001D461888EAD4ULL,
		0x06F5385713550F15ULL,
		0x15ADBB1289C84305ULL,
		0x4902E6A002B0C8C6ULL,
		0x499DC948CE8ED772ULL,
		0x59CA83D13D5EED20ULL,
		0x25D09DB97EBA22ECULL,
		0x40A7E27144B71749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15FD922EA9F5085ULL,
		0x8185610941B745D4ULL,
		0x70B17ACD1330F394ULL,
		0x9DF2DF80FAABCE40ULL,
		0x9D40D606BC1BF0BEULL,
		0x3E1B1FF5D6584F68ULL,
		0x3DA780A1AF7E2102ULL,
		0x1254ECB0DFD66BD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC66C5FF1EAF7D9FEULL,
		0xA178A9DF1C993283ULL,
		0x1B1691CE397F9830ULL,
		0x0B6081AE015E6D6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E99E5BE024CA140ULL,
		0xC657E92B249EFB8DULL,
		0x874FF194A5554987ULL,
		0x70263027D2971379ULL,
		0x200E2A4A2A4BDD09ULL,
		0x9841FFED34D9D391ULL,
		0xB8AFA9A69399D10DULL,
		0x0812208EB686EC21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F50ED93942F24BULL,
		0xAACE4C5C3A267602ULL,
		0x70B4E00F236FFE43ULL,
		0x867084C5F98FC8DBULL,
		0xB6C74A22C5392CDCULL,
		0xE61B472C50F2091AULL,
		0x90A3D4A6378B752AULL,
		0x907F73E72EC76D3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C2A1CBDC9CFD298ULL,
		0x8D490970BEE0931EULL,
		0x085CAF932C06EEEAULL,
		0x297B4C3FFF7420A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63CCE9277497ED5AULL,
		0xF39B326C0E3AADD4ULL,
		0x777AF3DF1080B66BULL,
		0x93CEDEABD11046F0ULL,
		0x335B371D45AB4878ULL,
		0x58BE9BF7E4BAE31DULL,
		0xF6CC70C96F26A5A7ULL,
		0xACA362F6C54CF71AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD7AF7413A31A4D0ULL,
		0x3C45D8C0C37BE13EULL,
		0x51EBC8E217E99211ULL,
		0x32CFF44AA403DA4CULL,
		0x9538F156A3A21A56ULL,
		0x33442C92CC3F4322ULL,
		0x044790FFF6D1B1FFULL,
		0xAA20AFFBB74254B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF684D6247C321A9ULL,
		0x4781E2ACED188BC8ULL,
		0x254862E4D5334F50ULL,
		0x40657BA542A087ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA219C86441B58EBFULL,
		0xE306F63775F77F36ULL,
		0xAD0B12D6AC8C4EB9ULL,
		0x3CB2E72A4708C428ULL,
		0x4805DFF750ACEF52ULL,
		0xE97FCC5482F7911FULL,
		0x287CD2023780463CULL,
		0x7890A7AD6CDE16DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D0D00E4BBE397FULL,
		0xE2889E85B37BB51DULL,
		0x1D0B8D0730FCAFAAULL,
		0xA690E3EDABF28FA1ULL,
		0x63CBCFF255E16AF2ULL,
		0x3519A097F77FED84ULL,
		0x39AFC2D9D4A777DCULL,
		0xAF15F994DE43FEA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAE75913302CFA2AULL,
		0xC7A8D5AE763E1316ULL,
		0x026FC5CE27BE4169ULL,
		0x7E57DAE1C5F5CC3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB41C22B7973D9E2ULL,
		0x1026A734DF6400F9ULL,
		0xCDF4ECB8B8D0B0D5ULL,
		0x8CA280E7A1A09864ULL,
		0x8132DBCA5E49F429ULL,
		0x77EAAC3822302AFCULL,
		0x044D6CD18813D3B5ULL,
		0xEF223E77712574AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C41F1A8A5403C3ULL,
		0x728CA291A4569009ULL,
		0xACE60FCFD6DAE978ULL,
		0x894915C5110F064EULL,
		0x4F455F104036CF2AULL,
		0xACE3E48A5C78E62AULL,
		0xCD70C8C476BA50B0ULL,
		0xEB66BE4D4C1CD065ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EBE26B165F7540CULL,
		0xC09BA86E9441A823ULL,
		0x45CF36D9753F3A12ULL,
		0x112E71640FD9F436ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44DC0EBFA5965CBBULL,
		0x3ECEAEA0C1F936E8ULL,
		0x5F2B4228B86626EDULL,
		0x3785415D6CD8F508ULL,
		0xEC42B0B7682F8C22ULL,
		0x22B5618D1EB13C69ULL,
		0x519E2A45C1F5FA01ULL,
		0x962EB5EE019E0740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4119ADCE34184250ULL,
		0xD148BC57BE75CE36ULL,
		0x0EBEEB2A11B35E1EULL,
		0x685D78B389FB3414ULL,
		0x8BFCAD802D33A005ULL,
		0xCE98E47838642004ULL,
		0x75E8EFBFC74CB101ULL,
		0x3D26A902607B577EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E26DB2432E328A7ULL,
		0xE9C0836332F59FBEULL,
		0xED5306E1DBD39EB4ULL,
		0x0659B3A3CE03D7BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE8B521F49B959FEULL,
		0x5C82DA1FD89272E7ULL,
		0xF513E4445DD600C1ULL,
		0x1270D102012A2909ULL,
		0x565F80EE90974195ULL,
		0x6EE3FF4B9A1D7FB3ULL,
		0x707F624D0BAC02CFULL,
		0xEB27CAFE2B3E91D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF64AB27F06B6829ULL,
		0x8C141F7EC3FF1EA1ULL,
		0x5DBA758A3A67597AULL,
		0x6DDB1B56D4C72DE9ULL,
		0x7A166AAF189C6C42ULL,
		0xEF4A758242605DDDULL,
		0xF524D17D3A2F5E57ULL,
		0x636BE9E11847DEECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81FFF46328899F0CULL,
		0xC1392E841AA65A04ULL,
		0xE6CAED933BEF1103ULL,
		0x4A791FFBFD018A3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x447603B6942E8897ULL,
		0x523C5036054BBE85ULL,
		0xB405AA384FF40B74ULL,
		0xAC93884E0DFE641CULL,
		0x953AA4FD913BA10DULL,
		0x7659781312E5707DULL,
		0xC1340A15C95B0435ULL,
		0xEE555D94476CE32BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE36AF1C0B0EE972AULL,
		0x2F424EB0762A66C1ULL,
		0xF7B0CC898529FBF5ULL,
		0x8140A63BC4D1B2BBULL,
		0xAC8E232662B48FC0ULL,
		0x57AB04A30347FD98ULL,
		0x154984BF8A3ADC70ULL,
		0x599C745C02A8B63BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAA657E6CB4C861FULL,
		0xB0DF2427E08065BDULL,
		0x4124A87C298FF6C1ULL,
		0x3EC5806C7E4B5D1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x456EDCED8A07CA28ULL,
		0xC7B7AF86DDAA7F2DULL,
		0x408B0517B77E0B92ULL,
		0xAC8113BC32AC0AD1ULL,
		0xFC8DE808B6927140ULL,
		0x5879BA711218D564ULL,
		0xDE4F4F7BBAD607B7ULL,
		0x310C872E76E4438FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70091116A73B8E46ULL,
		0xE83F3A40AE3ED0EFULL,
		0xC1B369DC38621AA3ULL,
		0x8ADFA5A76DE5EAFAULL,
		0xF479EE4EBE1CFE11ULL,
		0x7DF0E99CADDA8417ULL,
		0xE35F5DFE9035AD55ULL,
		0x213ADC36B2C7D8FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x085CDD71C43B5528ULL,
		0x4FC774CD10ABBFADULL,
		0xBE7573CFD2E95B75ULL,
		0x7AC0CEDBE0FDF1A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18798E21FF0A03DCULL,
		0x80EFEAE75A65FBCAULL,
		0xBA9275DE3F6EAB3FULL,
		0x8917084B253B7CD7ULL,
		0x6E90B96B070A4036ULL,
		0xCEAD57C0C170C24FULL,
		0xD3F997140CE6F93BULL,
		0x3A8A62EA71156005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CB58B07DE19590ULL,
		0x04677032C64C1AADULL,
		0x811A6C4089748DEAULL,
		0x715FDE544B4256B4ULL,
		0x49DCFF74B148ADEAULL,
		0x7CDD4115C6860BB3ULL,
		0x96C34ADA2ABC1225ULL,
		0x1242C4AD276DD49CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x595BD0023BE42678ULL,
		0xA16BD815D2F0FC4AULL,
		0x4F875A3548586AA5ULL,
		0x1258A70FC8D7D7C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E6A7EFE1025EE2BULL,
		0x44F6F9E0D3A9A5EEULL,
		0xC8AF70A0BF119F13ULL,
		0x0D3E1F2372114367ULL,
		0x134D8EB3E8315A30ULL,
		0x607BF4984313B773ULL,
		0x8D434AEC17F979F9ULL,
		0x9C78BAFAB8A142CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCFE3E8576AFC339ULL,
		0xBD0ADF9C746A34C3ULL,
		0x217C473AC732D506ULL,
		0x23505954AFF98D47ULL,
		0x69FDFDF35D85DB57ULL,
		0xD2CBE783785F72BEULL,
		0xA81314238CF5B63CULL,
		0x844DA6508BDF7D64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE33BBD0D2EEAFFADULL,
		0x900E0B5A7601A3FBULL,
		0xAC5B4B2A9A6DD809ULL,
		0x0052D71166DB03B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E4452DB1BA196CFULL,
		0x25A782E3FE5EBFB6ULL,
		0xFC199EDCA2A6AAD4ULL,
		0x4C76A9466C937CBAULL,
		0x34B95B94A30AB84AULL,
		0x25A9E1B9882A6D03ULL,
		0xA91388750B8F02CCULL,
		0x69A5C5D14EC876D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4191EA0A66BB8AA3ULL,
		0xB4C3EE2470DDF382ULL,
		0x7EA1A2E13AA0F3A7ULL,
		0xEB91C49B485D3838ULL,
		0x0730F1A248AB85D6ULL,
		0x8F45CA589991A5E8ULL,
		0xA77AED26E87077D2ULL,
		0xD24A5387B3170EF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEF222CA1F0786F1ULL,
		0xC3BF0D22F82E5A3CULL,
		0xBA1F09949E8E5838ULL,
		0x5877DB98408BAFE8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4134D5F159DA771ULL,
		0x6A3FCCDC8D01DEC8ULL,
		0xB8F5B2E612688FD8ULL,
		0xFD4356381CAFF2F0ULL,
		0x67B4158396ECE852ULL,
		0x6F9B2D6ACB826ABCULL,
		0x7694E2BEFFAF15C1ULL,
		0xA2B9500FC6B9D5FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x905411EFE4B17531ULL,
		0xB8440C3C402DCDAAULL,
		0x001D417DECEEF7ECULL,
		0x702A38206ED94A91ULL,
		0x3FC64D8FD7C7C6CFULL,
		0x5046D8735705C76DULL,
		0xEEBC2E2D214FADDFULL,
		0xA98834C70A4D50AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410AE99D906F2B9FULL,
		0x58805D5B97544EDEULL,
		0xE3033F0F27A3037CULL,
		0x0A632AE3A5F2722DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3845051FFD2D1C65ULL,
		0xB9EA8DC3FA063EE7ULL,
		0xF18C3C88DFBD4C74ULL,
		0x9E5480FA2537656BULL,
		0x1F9CA9434D5BCD8CULL,
		0xAD63C2B03B753AE4ULL,
		0x191F5DA284E98B8CULL,
		0xF9E4EB89D0CF8F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E3632D57E506CCULL,
		0x1BDC43E56129D1E7ULL,
		0x80643AD8450E8355ULL,
		0x08BDB232084C103FULL,
		0x91659D9139F3322EULL,
		0xB0AED770C3339A2EULL,
		0xD386B6A0726B3BEEULL,
		0x073370BA219A2308ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE08D5E6186CF2AF8ULL,
		0x20E9354A729A47F2ULL,
		0xC5D0CBFF596E9A93ULL,
		0x1BEF099C1ED96DFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BD96C8030EA6A9DULL,
		0x8FD9970B5C9BD133ULL,
		0x002D3A990261651DULL,
		0xE94F26D9145AE0BBULL,
		0x998165E411C1C70CULL,
		0x2143EB57EFC18BB6ULL,
		0xC443750522BE2388ULL,
		0xCFD105CFDF7F57FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373FAE3C8DC69D91ULL,
		0x1519364B644D9E3FULL,
		0x4BF57ED1ECA5E54AULL,
		0x86E186721DFBB610ULL,
		0xECB44BA16ABBD7C8ULL,
		0xDCE1E68E281E266BULL,
		0x3938C97006108A42ULL,
		0xE439A72E1EC78FD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB0BA4286E0550B2ULL,
		0xA14D16B39A8F3C09ULL,
		0x57CD33E95780401BULL,
		0x5AE5AC6991A6E0D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF49AE1AFA2D02CAULL,
		0xCAC4681E62BA55E7ULL,
		0x3548616019179D3DULL,
		0xB7D0D3F8F2156914ULL,
		0x4390E9A1DA235250ULL,
		0xCC0E751BED5393E4ULL,
		0x9486F12CA1EF3A95ULL,
		0x87EF172114FAA110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB474642ECB0914EULL,
		0x16A3A3368723729DULL,
		0x76A8BD1437943074ULL,
		0x865EECD16786A68FULL,
		0x4781FBA72284E896ULL,
		0xCF51962D48AA2CE2ULL,
		0xA76A9ABCAEE7DEEFULL,
		0xFDE799D4E724135BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E39BB0F4F00207FULL,
		0x3829DC544CBC2D95ULL,
		0xF0D478E9F49B076DULL,
		0x2E8E80765867CB5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B8C906D401BD2DDULL,
		0x96619B7529245078ULL,
		0x9E400FD8B9BDB249ULL,
		0xAED141B8AB931712ULL,
		0x9C6267F009337EB1ULL,
		0x7D4D044664C5E0F7ULL,
		0xDEF36A646A92B304ULL,
		0xFE77624B3D97B43BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF93D9A32950DC606ULL,
		0xE0F2DFD0E8EBCD52ULL,
		0x35AB5D967E5B4FA9ULL,
		0x8BD346CA6284978AULL,
		0xB362E7337D5EB59DULL,
		0xD84CDE5A84959B94ULL,
		0xCF36D8FA8FC6E86DULL,
		0x020918D0168A7743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC83C12376CA3EB60ULL,
		0x33745CA78762CFD3ULL,
		0xBE9247F8B5A274FCULL,
		0x1B5CE33615058C5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF38A206CCB9BB93ULL,
		0x86B38B5BBE7D00AAULL,
		0x3C28EF401D0A8428ULL,
		0x7AC33829DC82FBC3ULL,
		0xC61FDD8669DFB599ULL,
		0xECB286D816791045ULL,
		0x03545DC0B12F3B93ULL,
		0xA6EB334843C0A836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B8C37B5CC04F21BULL,
		0x58F656D3F9B30AEBULL,
		0x82A32FE7525D9ABFULL,
		0x8DF2528294EF409FULL,
		0xEDF7621615AA433FULL,
		0x926E7880E411AC28ULL,
		0xD84C99B2EB0F48D7ULL,
		0x26B463FA162579FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99AEBCFD80A3C593ULL,
		0x93D755794022D207ULL,
		0x1CACD964336AF15EULL,
		0x74F3AB420C9C97C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C6120CEB2BD8C76ULL,
		0x35C4DD0A16B53BCEULL,
		0xF50541C9F46C9684ULL,
		0x28FE91EE4DBD5156ULL,
		0x79E91C7039816F7DULL,
		0xAC2329E0BD5FB3C6ULL,
		0x4A345937D4E6FC87ULL,
		0x392E43863A60E1D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C05B07F9FB6BC1ULL,
		0xD30261E2B7135DC2ULL,
		0x54BBA4846CAFF35FULL,
		0xBCFD511D95527FB7ULL,
		0x71B824965B1AE619ULL,
		0xDA841A3F57B7F36EULL,
		0xBB3C5C75E007B53EULL,
		0x083B51B940C74A40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91E5901DBBFA8684ULL,
		0x805ECD1C76886B1CULL,
		0xD919220FE0E137F3ULL,
		0x3011253DC5375186ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE1A243199106685ULL,
		0xAA8111A9C91E907BULL,
		0xA978AA3D6B2A8215ULL,
		0x729BAB73F006CF60ULL,
		0x1205AD3141FAEF4FULL,
		0xB54E4F4A55B2800DULL,
		0xC57AAD93C64DB326ULL,
		0xF0AC5DFAC860DA4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B6E2948CE7A341ULL,
		0x061800E0FA2E7716ULL,
		0x65986D3B1FBCD169ULL,
		0x4A35B87266DAACA2ULL,
		0x779B003AD3B0F1C1ULL,
		0xB3CF44A58498D254ULL,
		0xBADF66299CB0EB3DULL,
		0xF245F1C5A4A10866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0038EE316B246645ULL,
		0xDD44A53FD8BFE2CCULL,
		0xD6ECD6C478B35D42ULL,
		0x6B9A02E4D7A54AE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C22B7A9DA237DB9ULL,
		0x81812CE2975AC3C7ULL,
		0x7A040B5BC62591B7ULL,
		0xA536D10A1B03314EULL,
		0xA4E390A8A5CED1FAULL,
		0xD74BFB267712DB1BULL,
		0x944437B93CD51675ULL,
		0x9E1C5C5114F564CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D702604B6FAE32ULL,
		0x122B9356F39FFD81ULL,
		0x8448DB18F9A5985FULL,
		0x5960FE0A169B8A6AULL,
		0x417BE4E1A864C4F5ULL,
		0x17679BBEBA8A2F01ULL,
		0x436F6FB03FB334A2ULL,
		0x98B38EDCD3C82B25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6AF34D32C71BE6BULL,
		0xEB3BC2F1A004522FULL,
		0xF550E1985F877EC6ULL,
		0x19645241B11E3605ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDECF1D9EB62E7E2ULL,
		0xFBD1871FBC32A184ULL,
		0xD64FF193616ED9F5ULL,
		0x938BAB2EFFDDADE6ULL,
		0x89E080C65A2D0E59ULL,
		0x4EA65CB114A88E75ULL,
		0x5E8CC0AA6086572BULL,
		0xB48716B055D8218DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA61BDF4382A06957ULL,
		0x38690C5620E699C7ULL,
		0x7877582239BF2F95ULL,
		0xC739D2ED1F405DF1ULL,
		0xBE48DF2576BABCA7ULL,
		0xE25C660FD328A1ECULL,
		0xC0984F2EFC8C3592ULL,
		0xA3B8B64FE45F39CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x605310782BBA9F43ULL,
		0xD66316B95449240BULL,
		0xD02171C1FED0A700ULL,
		0x4AF42692B88FB640ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41FA08EA5268966BULL,
		0x6406633CFD98CBA7ULL,
		0x4302F52F7BAD8026ULL,
		0x6DA46187C2358A1EULL,
		0x74140C8BE8E83804ULL,
		0x03A6479D3B22D025ULL,
		0x1761C8DA296A4268ULL,
		0x1963EF5F0FF5AED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC91E79FB5DF762ULL,
		0xEC0D1265BEA34389ULL,
		0x35709935867DB4C6ULL,
		0x2EE437D4AB9E2CB3ULL,
		0x0F2D0CF47AE5257CULL,
		0x5363A401BA093801ULL,
		0x132764346E0F6DC3ULL,
		0xB78EA97D738C70D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D7ADAEAAB7F5BBCULL,
		0xA1DD99EC68C21D84ULL,
		0xAE3D4C93C4AB5BD1ULL,
		0x446889304E36911FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975B9365FDC6826AULL,
		0x4BF711E5BA4527A6ULL,
		0x4B686F056AB27440ULL,
		0x93B8B2C41D0BECCBULL,
		0xDAC8D7A9F58A6BE3ULL,
		0x6ADDDA70BBC4131CULL,
		0x6F524A8E8673ABADULL,
		0xA7E60E06097C116BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91BA19E91A98688AULL,
		0x406FA46E644EAD52ULL,
		0x771AB3A8E5D4A3AAULL,
		0x50B42C469362C313ULL,
		0xB790AFF71AF14A03ULL,
		0x93C33AA2D4F67962ULL,
		0x40E2D371FDB9E7ADULL,
		0x47364A33DA3891D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FF75E0955E92347ULL,
		0xF97B2607987B4BF5ULL,
		0xB8D96998D070E88FULL,
		0x1D1B97B08DAE1990ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0E742C8011318FULL,
		0x4180127389B6BCEFULL,
		0x4AFC48852CB6B91EULL,
		0xC9F2B74556EDB40EULL,
		0xA41C053707B05786ULL,
		0x9CC23E98A3EB5073ULL,
		0x4D073FAB22362809ULL,
		0xFD9EB2999E9CFD19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634906DF7A97F93DULL,
		0x621735ACC0701EA7ULL,
		0x85A86F72046E2F75ULL,
		0x9E6D9FAE821BEB36ULL,
		0x120378CFD749368EULL,
		0xB8679072DC256F2EULL,
		0xFB9014D2756586EAULL,
		0x72CBC9C4EC57C335ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC96A449E34C8202DULL,
		0xC4DEB66270A60E9BULL,
		0xDD04353CCF40743EULL,
		0x46D3A7294B186095ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09D0135A00DA1153ULL,
		0xDF2DF3E267BCC3B3ULL,
		0xB717555A7F329C51ULL,
		0x46471FEA9CC36F19ULL,
		0xB407883FB11BBFF8ULL,
		0xD77B202A5E68476DULL,
		0xA0F04B1D299BB507ULL,
		0xD11C3C310CDFB773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ED9DA5BC6C48795ULL,
		0x70A52F4CA3886E70ULL,
		0x145C1170866C2F25ULL,
		0xB7DFCE126F7741B0ULL,
		0x16D46B85C728369CULL,
		0x5BCDEF3EE5CF7CA1ULL,
		0x5A502D550F519085ULL,
		0xDCF63CDBCA651E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408C7C96F43BED07ULL,
		0xCA3E0789AAE26FA2ULL,
		0x1E7FAF9DDFC7D88AULL,
		0x4C0B38800B7EDE68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74FFC5E14ADB17F3ULL,
		0xC74457688D675213ULL,
		0xD054FB0C3EF1DD30ULL,
		0xB767B974F67B5BCEULL,
		0xC6A240620CA3B1DEULL,
		0x6CD7AC2388A0A6D5ULL,
		0x460675DE8A3F256CULL,
		0x35C5BC0AA917DC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D02693FD93E7E5EULL,
		0x2C3787719B8E692EULL,
		0x991924AAD9178829ULL,
		0x8346917FB3B1A4BFULL,
		0xF8890054DDC94F36ULL,
		0xA5CD4FAF75B79159ULL,
		0x762AAB80E898FB9FULL,
		0x80EE00ABC9E5C96FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFBCDE9666073CE3ULL,
		0x26968931C0721945ULL,
		0x11DBE0476484896DULL,
		0x0C26F80A643878B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB7656F6EB9C5274ULL,
		0xE67F4778B5E34FD5ULL,
		0xEEEC88E4BD444F4BULL,
		0xE1D17FF51A5971E1ULL,
		0x479D7DC46AD82A2EULL,
		0xE014827359E4C393ULL,
		0x2C4A92C5B9D9DB19ULL,
		0x8CD313295F5611B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EB6D6ABEA3E312ULL,
		0x02499E1D743D912CULL,
		0xA48DF7F88C902E62ULL,
		0xAF4F9A979C540987ULL,
		0x0B484826F2F990A8ULL,
		0x8DC5999CDFB0E500ULL,
		0x43A733D1C3699558ULL,
		0x6921478BA6DA8B27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A30DEEBF8033A04ULL,
		0x1BEC39316558C884ULL,
		0xD29EA922C55E7B9CULL,
		0x7EE61EC6E05B616AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08F2ED12A0F34194ULL,
		0x0A280C645CE2DB66ULL,
		0x0F0FE0034E9B11DCULL,
		0xA3B23140F18DD749ULL,
		0x6615712D7CD8B3D7ULL,
		0xC7866CD6397BC2E2ULL,
		0x4F6253E154C76D5BULL,
		0xAB5BAB1A438F29C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE01B5BDD7A50F50BULL,
		0xD88E14AE53E02A4EULL,
		0x19C769033B135C75ULL,
		0x6E00B2C9CFB6706FULL,
		0x339C0B0F1A7E0007ULL,
		0xFA33E2040EB8BF31ULL,
		0xC72FDF8472EC4579ULL,
		0x32F92E32971C8832ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6DCB9B7C0190015ULL,
		0xABDA92E861F53D64ULL,
		0x2CC5BCC99A0FA0EAULL,
		0x145008DABADB62E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB83676CBC09DD5CEULL,
		0x7A9D864D094B4CA6ULL,
		0x2C3711B72C33E152ULL,
		0x441DA316DB418D2CULL,
		0x572F639837192B21ULL,
		0x6CC435CAD190E91BULL,
		0x3A689A5D99AFD8D0ULL,
		0x8195408FCB2A38E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x020824283BCFB443ULL,
		0xB498293828878208ULL,
		0x144E4B4A086E8655ULL,
		0x2F7823999F8ECCFAULL,
		0xB6DAB5F9A0F46164ULL,
		0x06C570FE7B852006ULL,
		0x5FF57B05CBB43145ULL,
		0x9396996CC8D36056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82C0182DCE441327ULL,
		0xE9D69369A683A3AEULL,
		0x84FF6D75B72039ADULL,
		0x68724EAF9496E4A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED1F17DFA831F5E5ULL,
		0xA50803F51059182EULL,
		0x582A156815713854ULL,
		0xAE907B9AEC7770C5ULL,
		0x7C9E4ABA4197FF7CULL,
		0x00C0FC71DE79246CULL,
		0x0CDDD5D30712560CULL,
		0x7145A2FAD38B4744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23E3739C3D2A2835ULL,
		0x79E9D96144E79383ULL,
		0x477DA698207D44BCULL,
		0x1F5E2005093D0A9EULL,
		0xA1FD887012BDF855ULL,
		0x2570397DB9A123E3ULL,
		0xE95CC872953A8F4CULL,
		0x95CA803E00179D8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D187B465F64DCBCULL,
		0xB91B1AD1438198FCULL,
		0x55D46B20DAFB7412ULL,
		0x2379839D4665977CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98413BDC4AC6E006ULL,
		0x672A170681750A60ULL,
		0xCE54C4896064DD92ULL,
		0x4FE9C27EE227F865ULL,
		0x51ABC0505C1D2C8AULL,
		0xB174F819774A2C6FULL,
		0x33A5E8FB2C2D7947ULL,
		0xE195CC6A9D6A6838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x321648FFD45D4259ULL,
		0x88C1D089ADF2AC22ULL,
		0xACFBABA8F27DF83FULL,
		0x36021D5ABA2CEF16ULL,
		0xC1DA17A183AEA40DULL,
		0x1BC34D700A86D59BULL,
		0xEB4D84DC5027730BULL,
		0x11321CB19896F917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF49FCD096D1E4D5ULL,
		0x16C79BA2F88141A5ULL,
		0xDE77F57516CBD251ULL,
		0x08B3BA9ADF5D8819ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94C4AEC815C6493AULL,
		0xEE7A5950B0F0C11CULL,
		0x729907A9378AE0F1ULL,
		0x00B3E2E7EEF8E502ULL,
		0x0DD75E43DAB6A7C4ULL,
		0x0F2D23B3649E69EDULL,
		0x5F4BC37B48B6081BULL,
		0xFF4C58A56E03DD2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1D92700D91A442ULL,
		0xFCF3A55CD8FAF69DULL,
		0x915F081F3A7FCBC7ULL,
		0x4098103CCDFE2A6DULL,
		0x68D9F60783814AD5ULL,
		0xF49417E1A9739004ULL,
		0x868D1CDC8E776C56ULL,
		0x53B66366D83BD93BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1444954CFA207428ULL,
		0xE43E7515A0522307ULL,
		0x0D86BB19A2563445ULL,
		0x385E39F55CAB50C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0757CCE1616D4EEULL,
		0x2FB142224EDBAB10ULL,
		0xE1D79C607EEFDA45ULL,
		0x77CE45D6F7B07352ULL,
		0xC038BBAF056BB7EEULL,
		0xF98497645CDE8AF7ULL,
		0x42310D0F1846D3F2ULL,
		0xF42CD53299937449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA968CF1DA7283467ULL,
		0xDEA0597209B3A160ULL,
		0xD2AD95B9776AC66CULL,
		0xC255E70EA7F5DE0DULL,
		0x6CA78F908F6734BEULL,
		0x204D0C04FF061E2CULL,
		0x178011845C25AE35ULL,
		0x1476769DDD79E65FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E993A35F39A1E7AULL,
		0x8F4F98D833482FDEULL,
		0x656F5D3EF470AE06ULL,
		0x6A8A68DC3B85A607ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x757DB9961A793DADULL,
		0x05A4BE0BD9E43B66ULL,
		0x76682B494197C358ULL,
		0x4B7D18BF805FFD95ULL,
		0x754AB05AE8004550ULL,
		0x148B01D93DECCDA1ULL,
		0xC8243AD1687C5823ULL,
		0x80DD7B38ABBD82C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948975A6DCF61E0EULL,
		0xE711B18BFCC22BBAULL,
		0x680B78A9F419738FULL,
		0x98B2784F939AC46FULL,
		0x99F425FEF266EFA0ULL,
		0xE8F726DC9DD4B13DULL,
		0xF2BB609C6935CEB6ULL,
		0x48C42F4B48C60731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FCCCD95B245D8EFULL,
		0x96858DFFA0B6467EULL,
		0xBBED167D31F6B5D6ULL,
		0x068BE5AC9D819059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA35983E48CFAB28FULL,
		0x7988F80BC73A4F8BULL,
		0xF0552335926C6323ULL,
		0xFC23B5E027FC3032ULL,
		0xC562F51639AC2948ULL,
		0xB0C9FAB11B8944BBULL,
		0xD097C95039D6B3A7ULL,
		0xB916A3828D637130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x051339380BF72E03ULL,
		0xDE7ACEDB64605EE2ULL,
		0x71D6C1B87B397931ULL,
		0x07A2252EC3F5A676ULL,
		0xF10827EA88565513ULL,
		0x14A53F615C2683C3ULL,
		0xCF0BD23B5AD41EF8ULL,
		0x71DC101E0770D376ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23C0BF28D3C1061FULL,
		0xC881F706CB829573ULL,
		0xB9450E963194FC02ULL,
		0x0733719D4609F358ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A46D5990713D5BCULL,
		0x3E7D6FA9B5090538ULL,
		0x1B73677D55D90D87ULL,
		0x2FD151068C3ED133ULL,
		0x7D9AA0CB4F5C3458ULL,
		0x3DEAFC1AD586165DULL,
		0x9865DA568C5B4D1EULL,
		0xD763D7345C19741DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49C109E79EEB458ULL,
		0xD8AA95AFAD9C567FULL,
		0xF7831E314B6C56D4ULL,
		0x67CDE683B8CA6869ULL,
		0x4141F02DADEBB363ULL,
		0x7C407CECEEBE3012ULL,
		0xA7A9AFA7ADE82DB6ULL,
		0xDBCA1157A6D13C4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AD4FC6083D8459CULL,
		0x2521BACA4918DDE3ULL,
		0xDFDE9F410F836019ULL,
		0x20D6C945BC2CB1F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AEBC35BF8E3C6A2ULL,
		0xD43D25F2E5049D3FULL,
		0xA38FEF098095FADAULL,
		0x79B6E046941C4ACFULL,
		0xBF56E79B7D841D3FULL,
		0xAF8D78F09EFEA805ULL,
		0x79AA7A68FCB27521ULL,
		0xCE40A07445DDEDDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD883E277EC9809A9ULL,
		0xEE530CE461CBF224ULL,
		0x8AAAF805924BC1B2ULL,
		0x3D2F436F8318FE75ULL,
		0x111CC69E965EC61CULL,
		0xF7961D09286841F5ULL,
		0x40A23B056181F132ULL,
		0xE2A5A0FD68CB88FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F08C66E5BD6ABB9ULL,
		0x34A1BD6A1D8BD194ULL,
		0x901E5FCCF77DCE97ULL,
		0x3589887BE1BE45C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC54F155E93F990A0ULL,
		0x94B9EBEA489BD57BULL,
		0x162E1A07F75B4506ULL,
		0x8E348BA9B306959CULL,
		0x442C2266A2B6FFCDULL,
		0x89E9B2A8F9D4DC3EULL,
		0x27387C423AC61A1FULL,
		0x289548499594153AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3403FACEDD84036ULL,
		0xC598CACE5ECF1E78ULL,
		0xDAC665567ED2233FULL,
		0x05B1035D87095DD1ULL,
		0x06DA279219E73E37ULL,
		0x191A9BF3A4292C9CULL,
		0xAD899D726BE46208ULL,
		0x3467636E06A12E80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C3A113DF4F80C75ULL,
		0x8DDE8006A148C918ULL,
		0x4B5CC78A2E0A7541ULL,
		0x475380E3640B7752ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAA1455DAB02EAF3ULL,
		0x25CEDAB27E7F5E51ULL,
		0x47A7360A0F9A5238ULL,
		0x17E4367564B06614ULL,
		0xD8C8CDB777EBFD1BULL,
		0x07C8D2D3DD837400ULL,
		0x938F950E7BC01740ULL,
		0x5429C6E49C38B4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA90ABBA541DA96CFULL,
		0x22EE72022AF6CB0AULL,
		0x541DFAAA41F416AEULL,
		0xB50A941EB88BF9A1ULL,
		0xB9AA41D7D42774C0ULL,
		0xE3E18E6DCA2D3DA2ULL,
		0x2CEA881222C3C5D5ULL,
		0x2C4A82ED99F544D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB01F4CEAB8549264ULL,
		0x57348FD73254A53FULL,
		0x300928D5031A514BULL,
		0x4DFDB90102270DFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C0541079D49D087ULL,
		0x63A117189BA93AC6ULL,
		0x3F050181EE2312DEULL,
		0xC3416E110477287AULL,
		0xDE15312AA628AF49ULL,
		0x46EEBE61DA114D1BULL,
		0xDE5DF07CBCDAB6ABULL,
		0xCB01C53E244B486FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71800AF31875833ULL,
		0xE35E2C2D6D8E776FULL,
		0xA161661CFF68EDD4ULL,
		0x8402425FADF6F341ULL,
		0x05D6C6EA1F08DA0FULL,
		0x7061B933A8074B5FULL,
		0xEE11C99D895E6863ULL,
		0x8F9536AF783F16D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E3105EC7A7C2046ULL,
		0x5931AFC69B97055EULL,
		0x48F16086932DC3B3ULL,
		0x115C54DEE04F917AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7D7CD8B401CEE41ULL,
		0x4ECD11B429DC3C98ULL,
		0xADD1F672C98B1874ULL,
		0xABED1C4B24C7FA4BULL,
		0x0BA2DC79CF8EA5E2ULL,
		0x3EF7ACBCD3EAE09FULL,
		0x3DF88CC1138B0327ULL,
		0x71DBD63BACC2BD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5161D65755F9E1A5ULL,
		0x82BC02F3A9596107ULL,
		0xBB01368A96D95E05ULL,
		0xE9BFAD3014A88992ULL,
		0x38074DF75EE7C91CULL,
		0x6105E3E1A4F409E4ULL,
		0xE504319DF336994FULL,
		0x228C75C2733A4025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF8D1E90A2E7D3B5ULL,
		0xBDF4DF497926BB4CULL,
		0x2716471EFF397079ULL,
		0x07F5C1199A620ECEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C15A85558205D56ULL,
		0xB1F80323241E2C07ULL,
		0x9B704EB320D9D170ULL,
		0x8D35A8574576050BULL,
		0x6E90A9E8549CE058ULL,
		0x9F33ABCF2A89992FULL,
		0x42C7BCBB4C447A61ULL,
		0xC45463C3454C7556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8178DAA961D5FDULL,
		0x3C0D2D8B54F6883FULL,
		0x7EE8388DD6D066E7ULL,
		0x05444DAED4CE8FE3ULL,
		0x3B3CDFF2F1D6F5F5ULL,
		0x204E4304D30234ECULL,
		0x170200D911E2B6B4ULL,
		0x711CFF559D2C8675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD00429E7581F53E6ULL,
		0x4BF863A0CD4085C1ULL,
		0x9BE1F9B9F48C764AULL,
		0x622A42EF6564EA94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20E7B0F380AA4B99ULL,
		0xF8B6B2FAC456DA06ULL,
		0xF3F7E2EBFBB77E1BULL,
		0x8CD6905B137D401CULL,
		0x9315105F7850CF35ULL,
		0x86452FF6BFF6EEA6ULL,
		0x5CFF3228B0438259ULL,
		0xFF3399C1F59E9E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A101E5E932994F2ULL,
		0x1EDE0D040B6010B4ULL,
		0x5378211570BC180BULL,
		0x11EC73C1CDEFBE22ULL,
		0xB58DD73C911CC8C7ULL,
		0xDBDE4AE53389420FULL,
		0xA4B7624F34304384ULL,
		0x80B06465B95076D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8EA0DC33F39ADCDULL,
		0x251EA691913E67B6ULL,
		0xFB289C1EF5D6B9A2ULL,
		0x4264084A392763D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A870CC3FC81C262ULL,
		0x6B17ECE8055BD827ULL,
		0xC7871C4706BE3E0BULL,
		0x6CA3C0307DAB2B84ULL,
		0x2E4DE188B845661CULL,
		0x25788A198AE0EE2FULL,
		0x606763B3354E08CFULL,
		0x86461A6E448A2043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97AB74273694FDF9ULL,
		0x248C3F220B618E21ULL,
		0x17BFB6A4F068848BULL,
		0x458C8555AE317248ULL,
		0x4AC62CF07C445AA1ULL,
		0xA1216C333A27B557ULL,
		0x053154C82F6C90D2ULL,
		0x615D765EEFC8D7ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39006735AE14797CULL,
		0xEB7A1DF5F578BA11ULL,
		0x39CD9C84F5CD88FBULL,
		0x219F9521642A7634ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83F460B3F5D5A1EEULL,
		0xA92F618381798DB1ULL,
		0x0C34856F903033F2ULL,
		0x7C8A31D9C050832BULL,
		0xBC0D4037155221C0ULL,
		0x1D2A6DC2D6C13032ULL,
		0x45ED64368A2E5C46ULL,
		0x6132FF0033FE3517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB603FEBF817472FULL,
		0xE1A18B6EED94935CULL,
		0x5BF96D5482D3E54DULL,
		0x94C128096035F5FAULL,
		0x9E5C04BA24E8C7F1ULL,
		0xE118DB3934A0445BULL,
		0x631BF772C983C6E2ULL,
		0xD3F54C44758424A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20E2F553AD61ACE0ULL,
		0xB2299682A4C7FC43ULL,
		0x5B513D29A6AE7B5FULL,
		0x5EF191AEA638FD80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA4ABA55145A6AB0ULL,
		0xF8BDED63514C7453ULL,
		0xECD18A13918322AAULL,
		0xE065C4E5CCBCD1B9ULL,
		0x645B787DC03B401FULL,
		0x24B3C5515127A1ABULL,
		0x1506FE2A2E3DAB8FULL,
		0x38E7E249CA0BD5EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EFE676D3614EA9ULL,
		0xEFBB5C9335E57824ULL,
		0x83972729A809978AULL,
		0xFFA4057658A95A5AULL,
		0x2C31CEFA2B997B9AULL,
		0xEBAAF854BDF803D0ULL,
		0x8099E17684485784ULL,
		0xFD5C38EFF81D35DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC89FD6650FC4364ULL,
		0x8050FE4DF4786AB9ULL,
		0x716CA59523E404A4ULL,
		0x377CE2C49D7F3989ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27998598EA14D2ECULL,
		0x08DD7788AD2D6C33ULL,
		0xA562D3F47F8A6700ULL,
		0x4E30E9517F304CD7ULL,
		0x9C318B549B11E5B7ULL,
		0xADC41FF304A09BDFULL,
		0x3B6FF505D742EEE3ULL,
		0xA896BA2523938C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C503E334DFF4CBULL,
		0x5D06DEAE5266DD90ULL,
		0xD6A531F9098863A2ULL,
		0x440E8D3D463460A1ULL,
		0xDD53F17F5949C442ULL,
		0xF0B1455491060445ULL,
		0x99DC47F227E3C23BULL,
		0xCA2148B38A553658ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7B9575D78E9D4C1ULL,
		0xBCA30C5F83B90F74ULL,
		0xCAA952E77E22A443ULL,
		0x0F9132F0F83CAFDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x242FE64F3FE018CCULL,
		0x1B215D96FD733A10ULL,
		0xD17096BBCFEA3CBDULL,
		0x44001C5AD9F7109EULL,
		0x434B6D6E76B86E15ULL,
		0xF40522281476FDE9ULL,
		0x94F42FAB7BDE0681ULL,
		0x93D589842CB2186BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC957EBC42F08959EULL,
		0xAB80EBDDD3C70A49ULL,
		0x5C7129FA948446F3ULL,
		0x593CE74F51111E19ULL,
		0x060F9E44BDCD6D99ULL,
		0xA179D02F1AB39A4EULL,
		0x3F3CF7CA13E5C9E5ULL,
		0x18D087A7DD389152ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71B8BABC83B99842ULL,
		0xB04E9CAE3CACF8D1ULL,
		0x2E31B836AA3EF4FDULL,
		0x2D817BBF54F00048ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0CB988D07EFE6BBULL,
		0x3861C3A83985748FULL,
		0x127730517123513DULL,
		0xE13A64AD4B88CD15ULL,
		0x1640423CA679E95FULL,
		0x3DE94698EC1E797AULL,
		0x3CA7F85CAEDBC6CFULL,
		0x0AD9093BD7ED7235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6EC14269FE0439ULL,
		0x59D33755F320A3CCULL,
		0x67FC8058DA5401DEULL,
		0x8DB5E3F23C100813ULL,
		0x138E4B4AE212703DULL,
		0xA3606FF53C91D8F2ULL,
		0xAEB12E9A22530BDBULL,
		0x12350D77D1AEA8E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69C77F2DC54DDD68ULL,
		0xCEDE689E5544A4F3ULL,
		0xBD1CA2D9731B0F87ULL,
		0x3BDBDFD3FCCAA638ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8B4201E760D873ULL,
		0x04E6C41BEC8C5F7CULL,
		0x6679B7ECB6283F23ULL,
		0xF7A7BFE252EDFF05ULL,
		0x055056DB7D78308FULL,
		0x43B84107C276B3A3ULL,
		0x48267C1528926EECULL,
		0xF06233838596F9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96ACEBA3847B2EA6ULL,
		0xEDDC7C03921DB4ECULL,
		0x4E6D0DC83F98E8FBULL,
		0x190E0BA84D239039ULL,
		0xE57034D26E59C8C0ULL,
		0x17134162BCF0F6EDULL,
		0x10EE35E7B32B201CULL,
		0x80D051D24FEA6166ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x602363B6A169150DULL,
		0xB7883A972C48AD72ULL,
		0x4A6714E3E3E5090DULL,
		0x6E413487FD6912DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAADBB15325607C87ULL,
		0xD4B7023F655B7D4AULL,
		0x3858F2E95C2FFCA2ULL,
		0xA027B917937D3B56ULL,
		0x8A143176BD189182ULL,
		0xED86806DEE77F00CULL,
		0x0ECA39757C07DE94ULL,
		0x8CF0E50C8DD16444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C03201470373D6ULL,
		0x94BFC73A669A22BEULL,
		0x168D1E4DCABC8F25ULL,
		0x4B1C4FEBA50DFEE7ULL,
		0xE609BDEAF7836DB0ULL,
		0xA447B973C01E280DULL,
		0x0EFF52F60C640A05ULL,
		0x47CD10E9C74DCEDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CA8A61132805B6CULL,
		0x1F48C427E0150A58ULL,
		0x19EA0B8623C4FAC2ULL,
		0x185CE65565F76A2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDFA6AB836EF064DULL,
		0xFEC9C0CC82869B98ULL,
		0x1148E1B4D8D1F05EULL,
		0xC8F7BD99CC2F7C4EULL,
		0x44476B0249E19B0BULL,
		0xAF93F85596FB2F27ULL,
		0x45738E045E1C9BCCULL,
		0x0352BB25DE09260FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D71107363C1322ULL,
		0xF9A5D83C5E892589ULL,
		0x1623A76E6036E274ULL,
		0x0CFB309DA65A4A8BULL,
		0x9C57214BF4789E6DULL,
		0xAB8C0350403828F5ULL,
		0xD77729B172B124C9ULL,
		0xD2A352F5C0288B29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9CE4AC1AE486E18ULL,
		0x9E52475B04F0616EULL,
		0x4E9C1E956A8EB85CULL,
		0x76060420952C2FD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58F4BF7315C6E9A6ULL,
		0x64BFA39BBAC355E4ULL,
		0x35BAEA961A701E52ULL,
		0xAFE9DF43535CBDDFULL,
		0x4596BA458C06543AULL,
		0xFF910B22A1167372ULL,
		0x1BB33BCEE39A4ABFULL,
		0x20C88C22D128A1F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F315AA31327E8CFULL,
		0x7F90340224C03738ULL,
		0xFB9F10B2E4201D65ULL,
		0x9788268B5607EFCCULL,
		0x5E1B0E1B839831AEULL,
		0x672591E2AA058EA3ULL,
		0xA155F92C171DF05DULL,
		0xE87AE198F410E6B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x861EF30D42F81D2BULL,
		0x85236F1842851562ULL,
		0x63F3BE0D90C56B8FULL,
		0x73E9092ECEDA99F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8184017FB063B143ULL,
		0xE8B5A00986A7D3F6ULL,
		0xEF780CA29E641272ULL,
		0x201D75395946741FULL,
		0x556DC82D366F637FULL,
		0x25D73CBB76E97157ULL,
		0xADD42E4B8A25F901ULL,
		0x8B2C28297AE06807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158D8FB3D5AD57ACULL,
		0x0BCDB4D3BBE520C4ULL,
		0x24BB8D810CE5F67BULL,
		0x4691DE7CBD851BFAULL,
		0x686B2B1383728262ULL,
		0xDFE31AC832ADAE5DULL,
		0xA0B86C5703B7453CULL,
		0x99709329EE66808BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A59C39C6C3FC386ULL,
		0x3F24F551EBA1A44BULL,
		0xBCDB496D85ECCB1AULL,
		0x3B63B4AB75D9B48FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01094BF2234D3D21ULL,
		0xA109D149FA209C18ULL,
		0x24561295A35FF835ULL,
		0xDA8796ACF2969151ULL,
		0x53A39DA7DBCEF1C0ULL,
		0xB85EBD83B7C778C6ULL,
		0x828E9982475AC0D6ULL,
		0xE7E3D7B2AB66DECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE76C0AEE6D1C89ULL,
		0x48C21C547929DBE9ULL,
		0x8D6D69FD40C9E47AULL,
		0xA7D4CD699991A3E9ULL,
		0x5357421666A8E493ULL,
		0xB572D8B25FE61200ULL,
		0xF76CA13DB3C9A99BULL,
		0x497777D95D412757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8177777E988618C3ULL,
		0xC74BAC088C6C0192ULL,
		0x3DF382C64A1F867DULL,
		0x36C90384F29E28DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA773B44EB5E9C4EULL,
		0xA018CC810E0C9292ULL,
		0x6C24760AEDAE4E7CULL,
		0x0FFF738F2FB965E6ULL,
		0x71EF5E5BF3F2C54EULL,
		0xBBBCDC486A370A90ULL,
		0xAE846BAA343A6D8DULL,
		0xF4F3DDC18232E6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE50A313310484FD7ULL,
		0x1C7C3CAFBCE2B18BULL,
		0x1E0CDF639AF68E98ULL,
		0x2ED328507CEA69CEULL,
		0x6E26E28AB5ACC16BULL,
		0xCCC87FCDD3A8EC75ULL,
		0x3FA2DBA235837048ULL,
		0xCD762895AC595CC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x752F6B21197AE0FAULL,
		0xFBE24A03AA425909ULL,
		0xC392F7D721E1581FULL,
		0x3DD52FC071197530ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4BC5506E08A37B6ULL,
		0xF862B06A690F0148ULL,
		0x12C9D63D0292FD99ULL,
		0x7D40E9B5747DA266ULL,
		0xFAAAA92322EBD3E4ULL,
		0xC0516AA5A4425724ULL,
		0xFBCA452B0F9228BDULL,
		0x489C6C09C0526D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E1A397B410F05EULL,
		0x12EF5622B13DF5B6ULL,
		0x6E29A20FA8008ACEULL,
		0x977BF1731A7AC9B1ULL,
		0x75A9DFFE70FDB7D3ULL,
		0x33C3FC7117AEF4E9ULL,
		0xCCF81249A152AB55ULL,
		0xE4DD58419D48DBC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FF88CE195D16E61ULL,
		0xC271B61495B1A067ULL,
		0x97D3C1A3B7FF1050ULL,
		0x3421E7F78D6E7F63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B6FA4628CD4931EULL,
		0xD0E35F62881E4635ULL,
		0x3999F0B380D61EAAULL,
		0x471F77C92CEC4438ULL,
		0x4F8B3E69DD2304ECULL,
		0x5ED48949A7BA6E23ULL,
		0x7DBADE2212F4C846ULL,
		0x87FD79FACDEDD7C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C078556CC3A343AULL,
		0x55BCFF5F99100C9DULL,
		0x104399DD67F3DD3CULL,
		0x1B468622F574A78EULL,
		0x355C2343C3F21790ULL,
		0x95CAC8B3AAD07648ULL,
		0x4EC9E3985947138FULL,
		0x959AB62F9B8DF3BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA26626B37DDD9A40ULL,
		0x5298F64679C9041DULL,
		0x211B8747A8AB1490ULL,
		0x268201CFB1B37595ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9974210660B35856ULL,
		0x63E6D1EF4B0422C7ULL,
		0xBA1B3EBE50702E05ULL,
		0x1E7A315038742D84ULL,
		0xCC2B939B1DB54D5CULL,
		0x89B4E1A58F9DA700ULL,
		0xBEE748FE5D0DB18DULL,
		0xD83AC1A6D379FE50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF41680278202BD3ULL,
		0x587D1CD04BBC52E6ULL,
		0x94FE2F2E8CC87829ULL,
		0x6962B380C73F68BAULL,
		0x1DBA4935EF4813A3ULL,
		0xCC9A99DB70C5D9B6ULL,
		0x7D98FA6371BE744DULL,
		0x73A69A25D7D64F70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF03C408CCC9C020ULL,
		0x1D505D1F935048F6ULL,
		0xD6BCBA8EB16ACD52ULL,
		0x23155AF4CB80BA13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97EB7C96617CB38EULL,
		0x919C757E2FF85B5EULL,
		0xEF8721AB055F1E3BULL,
		0x4370E2FDABE4016BULL,
		0x358241477B130A7AULL,
		0xCE3E6CAE6CA955C6ULL,
		0x85FECBA31525A66CULL,
		0x6970D3EFD21BDA65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D385D0DB63A2A5AULL,
		0xC4B298E814FF21ECULL,
		0x2AC044CC5AAAE8C6ULL,
		0xBCC0B5546352846AULL,
		0x355BA4698547B145ULL,
		0xB0FCEFD5F5438FF9ULL,
		0xF8B4F9DE5935D686ULL,
		0x5422DB76ABFCA3FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x206E687B2771C771ULL,
		0x24A264B7D41495E0ULL,
		0xBDBC0012904D119DULL,
		0x30430FA4F13390ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x772DC2DA4884039FULL,
		0x06716DDEED21E4E0ULL,
		0x5EED8FB8E8D152C6ULL,
		0xE584EA98C808C300ULL,
		0xB38F9FC86009264CULL,
		0x08BB8BC23C95E7CBULL,
		0x7B1991D7BCD8C32EULL,
		0xE2F54653029B7398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x036724E63B674F06ULL,
		0x2CB2D4C81950BB11ULL,
		0xBE0CEB5CE4E16B56ULL,
		0xE8591D62D4AED74FULL,
		0xDDC88B6F54D2D9BDULL,
		0x814EEA55CCF21A25ULL,
		0x1B02B77490E2C3B4ULL,
		0x2A1CF9C460A429F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F53A32BB72C15D5ULL,
		0xF3DE8F2F6621B06DULL,
		0xE4450F148A73D379ULL,
		0x6D472A61FE0EDA62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2F789AE63392243ULL,
		0xA061408367D1C88CULL,
		0xA84634A0802015E3ULL,
		0xD1A93501FAD4FC01ULL,
		0x5C96B3C7B772E6CBULL,
		0x94AE8A7E10F83131ULL,
		0x13344CE505213B82ULL,
		0x126E79CBFDA499F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD93C065BEBB8BA63ULL,
		0xA0C44791FFE85752ULL,
		0xD5709717B7E389C0ULL,
		0x58C1E2A884D7FA2FULL,
		0xEC8EAAC3260428A3ULL,
		0xD0A4FB3DC03ABF28ULL,
		0xF343D82F80FD81B7ULL,
		0x73794DAB79CDCC92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAECDA000DF09FBCULL,
		0x19083C7D64085E7AULL,
		0x9086F07A658A203CULL,
		0x114BDF2D07DF7E3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF6FDAA38C1A8D0DULL,
		0xD209990904F66D20ULL,
		0xEBD2CC407C3489B8ULL,
		0x6F2A389D1482B6FAULL,
		0x40D11543A1858D8DULL,
		0x29C8F484ACC661C8ULL,
		0x65ED25E727F963A6ULL,
		0x439F0B0CD87B0394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3AEB7639F9A2D15ULL,
		0x6DAC267C2346EF33ULL,
		0xEF51D3D9F832C92EULL,
		0xF940C67A20044F74ULL,
		0xEACD2FCC7ADBC2D2ULL,
		0x4FBE982182163302ULL,
		0xE9E2575E1D68FE45ULL,
		0x3AFC1EB92C0C07C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB05532EFA9B477CDULL,
		0xC1E7294537D66F37ULL,
		0x661BA0BE1570CCEAULL,
		0x3E18868E8CF7C878ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1E7859A9DC60A9DULL,
		0x93B07370ACB7DEECULL,
		0x113CC2A675041D44ULL,
		0x899491809BC9EF1BULL,
		0x98B1313A5BA73E4FULL,
		0x3EF02C6F4A0BAFD3ULL,
		0x5BD91B4D608C9121ULL,
		0xB43ECCDB856239E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0ADEA964CF68C0AULL,
		0x3DEA7116B3A18722ULL,
		0x6E68F63C2B9BCA78ULL,
		0x2C1C9C8380DBAC5BULL,
		0x516A3934B4AFBB7DULL,
		0xCECE6330174CC43AULL,
		0x93746462335E05A5ULL,
		0x9A1C84DAB2E3FE9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55C26BDB198CEA57ULL,
		0xFAC9E1BB816D508AULL,
		0x61C6F352FE51071EULL,
		0x3E8EA51C59AB0EF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6BCAD63668187C7ULL,
		0xCEBEE8713A6CF7EEULL,
		0x66C403F1666EBF3EULL,
		0x0CF84A04D00260CFULL,
		0x4FF204864AAE94A8ULL,
		0x4DBD2F433E69B0A2ULL,
		0xEE4210B91581B231ULL,
		0x1BA54108E81014E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C415C61B5C9038ULL,
		0x6794787D079AE145ULL,
		0x8894897EC6161681ULL,
		0x23F5853C8C16DF02ULL,
		0x52A0F94383AE7553ULL,
		0x5FC4E09D95B87EE3ULL,
		0xC0E23279CA3519ECULL,
		0x496E43B4CD0734B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0004386D5299D23ULL,
		0xBA061C8B3D1F7902ULL,
		0x9A6A77D7CDB742F8ULL,
		0x1D2C5F44473CC85BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA17232EE22AD0687ULL,
		0x8CADDD956F55932BULL,
		0x42D94FC11E992752ULL,
		0x34A9D28DFFC43B21ULL,
		0xD06CFD1C7AD944BCULL,
		0x45FC458512FDABE7ULL,
		0x306A8C99F05B282FULL,
		0xBF2DC571512EB85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF32ACEDDDB5EC7ULL,
		0x400F21295EBEC251ULL,
		0x7FFFC7F25BE4D434ULL,
		0x83B333C781ED97D3ULL,
		0xA4BFF5A8A65F34E3ULL,
		0x1D98FB07F4F8AE27ULL,
		0x0B4FFCC4095D112AULL,
		0xE4C105A51F79E523ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D2E2350CEF00112ULL,
		0x4B5BCAFE85547B60ULL,
		0x44CAE18F0C6BBDE2ULL,
		0x1D1B1715DEADFE3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61D0B37C5E865F4DULL,
		0xF9070039CC615DAAULL,
		0x34F32C0AB3B5E3A9ULL,
		0x915003798CE3E4F7ULL,
		0xEEE60129C6CEE02CULL,
		0x1130A5D3F3A1FB3CULL,
		0x1D3507CE78CAF6DEULL,
		0x024730677560D3A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFBCD3E3DFCDAEC4ULL,
		0x5083B0DEA628CD5FULL,
		0x85735B776956C5ECULL,
		0xC882B951F66B133AULL,
		0x817128D1CD557BBEULL,
		0x646F98B467D86446ULL,
		0x775C025403C15C4DULL,
		0x7A01512C73BFA0B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB16BFCA786BD9631ULL,
		0x4D2B4209E624F8DEULL,
		0x4DB6A0C0A9CC0F37ULL,
		0x032C6CE9D466614FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB73EC2DE6881755BULL,
		0xDB35B753CA50247DULL,
		0x4BB67D2BE6F19517ULL,
		0xEE5FCA9017DF5135ULL,
		0x188301D3DBBEE586ULL,
		0xCACCAF734A89D46AULL,
		0x1B24B829F032D265ULL,
		0xA200B271D8006EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB32C105D826B9CEULL,
		0xBA79B4BBF15C1D28ULL,
		0x2F5451E24CED9C62ULL,
		0x975252D3AD4A174EULL,
		0x02B32BFF020D8E8AULL,
		0x5F8E84DF7558331AULL,
		0x196DFD258EA9CC04ULL,
		0x78D6E71AA6012700ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18E5BF70E0ADA5D9ULL,
		0x0BF654897E51F938ULL,
		0x5D81EDF0145AEB2BULL,
		0x7341A6ADD679DD6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0480EB301D19E1BEULL,
		0x38435FF8FC65348AULL,
		0xA51B4B3CE74A89D2ULL,
		0x4B08DA7C64EE942FULL,
		0x324E8505FEAC9BC7ULL,
		0x5F8A2C9223104379ULL,
		0x68FD41F1AB834119ULL,
		0x3356DB4320C25F18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61306C77399C2DB7ULL,
		0x23848978CD72B154ULL,
		0x534E316DBD6ED4F6ULL,
		0x6C79FC8E65704270ULL,
		0xAB9628A91E361A88ULL,
		0x8D72D553D225B0A5ULL,
		0x0173C33EED954DC2ULL,
		0x5EE988A78A73AE85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2AE34823514E257ULL,
		0x4435C9C031C44E9BULL,
		0xB035E8575B2DD3BFULL,
		0x66C921064F2C87A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4024E75415B053DEULL,
		0xD06459959415DF83ULL,
		0x304408BD789085FCULL,
		0xDBF2C92B1DFB2189ULL,
		0x73EC9789478E5559ULL,
		0xE5EF2F7C98DD5BFAULL,
		0x109E52902E13631DULL,
		0xFAA3EE969DC998F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D471B89B0B8EECULL,
		0xA6884B8C0008C4E0ULL,
		0x0FD22B929BDDC6C0ULL,
		0xF7A5A4A91D5AB74EULL,
		0x65A9FF97553FA87BULL,
		0x674D603D1EB73648ULL,
		0xDA751FCB2C4312CCULL,
		0xE03C759B33653D46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC433038572526E6BULL,
		0xF5E0D175B5B6B310ULL,
		0x2A8F6669219EAB54ULL,
		0x4FA919D3CB860663ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F50A3D1BF241957ULL,
		0xC1C223D9939135E1ULL,
		0x67A7BBB395D27CE0ULL,
		0x1651B9B9BBB2CBAFULL,
		0xC49321016F18071BULL,
		0xAE92428CBCC8992FULL,
		0xFE10C858B346E323ULL,
		0x6B9BBED613C53666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF97028555C541A9ULL,
		0x5571A4972B2D4920ULL,
		0x6B3D67E79848FFDCULL,
		0xC8829F8E41951592ULL,
		0x8F082EA37E1ABEA0ULL,
		0xD4DBD5855949244EULL,
		0x4D611B370B75B41FULL,
		0x05FCDB52A8E97B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2599B3E2EF79C04ULL,
		0xBD64AE5B2D4F462EULL,
		0x367E06CAE6967796ULL,
		0x6364DFAD56BB8735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8608CA379518ED2ULL,
		0x853CFE540F7CB2A1ULL,
		0x80CC8D8885E3980EULL,
		0x2E268055DCB4E8ABULL,
		0x5EEF968048B54B8BULL,
		0x36ED2ECA59C7D21BULL,
		0x750F972A3DC28F3CULL,
		0xCDBDE795CDFE5C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EED371335322DAULL,
		0xE68847E3316DBBE0ULL,
		0xD51EC160D302EF82ULL,
		0x404EB50393EB6637ULL,
		0xEA5A86CABA624D1AULL,
		0x5F789A4374DBEE5DULL,
		0xC8296E19482CFCB8ULL,
		0x65CA10D9651B7D6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1920E25665032F8ULL,
		0x9A02C276D912C4E0ULL,
		0x55D7E4AC2714681DULL,
		0x5C09AB49DA769DBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056D19A650A41256ULL,
		0xAD3BDB5D01DD3DEBULL,
		0x97FD6167DC228FD0ULL,
		0xF25D44C7D0E6663AULL,
		0xE1A6E62865EC5ACBULL,
		0xE58C286DC0490360ULL,
		0x4BFBBC7EAAEA7741ULL,
		0x6A03619DBE95A255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C07BAB3DAE5E335ULL,
		0x0C1EFDCAF5CBC693ULL,
		0x8C53030447DDB732ULL,
		0xEAEFA34DD3C9238EULL,
		0x2AAA12343D36647BULL,
		0x444781A173A1E4A4ULL,
		0xEC6A4BD5388748F0ULL,
		0xA0F29BE28074E18DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2ECD53080C0BDBEULL,
		0x914D9FE56CE0075AULL,
		0x3B41178A8EFDB8BCULL,
		0x5FEAFB4535F9E044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x690B87A8199F0918ULL,
		0x051B36C200983AEAULL,
		0x4ACFE28CE64C590CULL,
		0x3BD9BD6DF4419084ULL,
		0x3877F060BD56F6A7ULL,
		0x28A92D1D0727FC7CULL,
		0xBC7CF1C2DF29C66FULL,
		0x48181C936BB59C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F374C17E9FD6FCULL,
		0xD5AA7CAC6EA1B71BULL,
		0xAFF4E4D2A1B278E9ULL,
		0xE355E8350FE68308ULL,
		0x8E45CA6A4451DE58ULL,
		0x30DFB915B3308B77ULL,
		0x8541F6A3AE8C17FEULL,
		0xF32C6236936C42D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4389B57C91C0C9E7ULL,
		0xF757F32C08B14A80ULL,
		0xCD9C445B7C01C4E6ULL,
		0x73817F00FF3E5EADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB7B3C94E2D18CAEULL,
		0x374A5DC4C5EB60E4ULL,
		0xF391A98BDB7C8054ULL,
		0xAD83951756DAC366ULL,
		0x6A1FC5B0477A10F0ULL,
		0xBB624745412FE23BULL,
		0xFE70409713F1A1B5ULL,
		0xB38640CD53D65AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6AD908651B17A20ULL,
		0xABAB2F2FB855C767ULL,
		0x460552B3556AB4D2ULL,
		0xF44D775A468DFAF7ULL,
		0xA25B6C8D68AC3C45ULL,
		0x96E09B30C1DD37E3ULL,
		0x5F72A3853B26F016ULL,
		0x3DBE94638AF589F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BF2E73BA3ADA676ULL,
		0xF6DEB99FF3DAE284ULL,
		0x4731A77EB4282920ULL,
		0x34D9B570E1ABCEADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB672F4A076EB1BULL,
		0x304E42F0E44164AEULL,
		0x52B51944C18C8E03ULL,
		0x993135058D9B9A7CULL,
		0xF1FA0DACACEA5501ULL,
		0x62689F2B3713FEC5ULL,
		0xB8D65EEEF267CFAAULL,
		0x2A7103AF2C1498D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19F960AE1A175F2ULL,
		0x427220921689898DULL,
		0xB8EDDA86C39A7913ULL,
		0x02E4433BF3A20A0AULL,
		0xBCC64607DB9318DEULL,
		0x7B6162311F6F4153ULL,
		0x3E7910BEE0C553D1ULL,
		0xB574B49E48F007EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C67F60D1C85F50ULL,
		0x38EF2F7E502BFA15ULL,
		0xC3A0D9E09C107722ULL,
		0x73C0AE4B51671365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0564E8B5FEEF8DC7ULL,
		0x2A76E881BBBDC9B7ULL,
		0x4754304DF0AC83BDULL,
		0x1B62E4BF32DF5764ULL,
		0x2FD41503700A09ADULL,
		0xA39F4D9D6214CA1BULL,
		0xF3E0CE34E3CDDEFAULL,
		0x7401054CCA431CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x861AA09A613A44ACULL,
		0x128FB602300C3D10ULL,
		0x4EA345423890668AULL,
		0x736AD9769FDEF75EULL,
		0x6536DBF328622132ULL,
		0x4113D7CDED470526ULL,
		0x2204E6BB64CDCE68ULL,
		0xACDB7C70DA27176CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92A0C08640A1CA07ULL,
		0xB89AAF4AE23CC8FCULL,
		0x1F554714921E92EDULL,
		0x378A5BEE3729301BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD75CD02DCB143031ULL,
		0x5055F0EB6E43FA55ULL,
		0xE16D70F72DF214DFULL,
		0x793DD8247B3A8497ULL,
		0x8A6201EC2506B911ULL,
		0xED46D0E32B269044ULL,
		0x0F330A7FD610007DULL,
		0x5ECB64FDF378B95BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790635554CF6938CULL,
		0xDB748E00FC97BA1EULL,
		0xA3ACEBC5B71E80BBULL,
		0x829470331BB59DC1ULL,
		0xDF12E980D5A49C49ULL,
		0xB85AB89E1EC76EB2ULL,
		0x9C21049AF5BAF26CULL,
		0xC201C86F69D93C58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC143AC646ADE01BULL,
		0x4FECFD2A47CB3BD6ULL,
		0x526D652AC373AAB1ULL,
		0x3C96A519CD317533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5A8BD5CA0A5F52FULL,
		0xE7EC3579A2A16622ULL,
		0x9064449D881660BFULL,
		0xDBCE72B4A98C00DDULL,
		0x2F18A20A92DF9AE1ULL,
		0x1227B4F7E0732EB7ULL,
		0xEC9FC34FA49D6E97ULL,
		0x2D728AB8AD30AF12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C226C5394615AC7ULL,
		0xCA77CA254DE85E05ULL,
		0x30761FA69678AB38ULL,
		0x47E9B82E0F102CD5ULL,
		0xA99CF6DC5C14ECF1ULL,
		0xE556374C91D3C6B4ULL,
		0x2293C13703B52996ULL,
		0xD11B79565A9EB323ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E1B9E52E5A6878ULL,
		0xC48D12C20062787DULL,
		0x5DB6749ED417F38DULL,
		0x48D14F1EDC2739A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD01F03CA12629C23ULL,
		0xD5DD8077720030C9ULL,
		0xCC3CB805D81214C7ULL,
		0x31B3ACF76E78BFBFULL,
		0xDD50610A49303AC2ULL,
		0x0126B35C926B45BFULL,
		0xE39C0E1770A8FD52ULL,
		0x864ACC7FEDFD8587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x280F0027424B35DAULL,
		0x017C88632C69D6A6ULL,
		0xA9B7E98D399C825DULL,
		0x8905DF6A50C8DF43ULL,
		0x4EC0C93B45FB5572ULL,
		0xEB6423E39629018AULL,
		0xCB393E9D3610B6D2ULL,
		0x21566EE25EC1D4BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1608C5D49F17250ULL,
		0x0F424409B76C7A16ULL,
		0xC12F9A9D51100948ULL,
		0x24F3B2F0608C1E55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41702B67B104E351ULL,
		0x5C217D891F20A2E4ULL,
		0x3F765D23FE58D5D3ULL,
		0xD8BF30B4B9AD021CULL,
		0xD2393C9FC0836E18ULL,
		0x48A6D91D3D85D879ULL,
		0x4311A15C71F40293ULL,
		0x0C01BBEA7650E68BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF6E4ED78F37EA8ULL,
		0xCFEFB8950256BE8DULL,
		0x06CEE15A3A766378ULL,
		0xA77BAC592EB96F54ULL,
		0x7EC3E40628F07AABULL,
		0x10B366850DB5F167ULL,
		0xD3E7C54CAE5A3B30ULL,
		0xC8514F4F9F7EF855ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96E46D46B7E182AFULL,
		0xDA54C78B35A6310FULL,
		0xB8DE2620CCB60B14ULL,
		0x3D73A3576E1CEEB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A2D8D9C62D2D24DULL,
		0xDA1B89C9A3F3FC98ULL,
		0x627EE00C94B35283ULL,
		0x233EE655C62EBFD1ULL,
		0x2DB306E684D151E2ULL,
		0x6914ABAF4D795AEAULL,
		0x9C4EF11AFCFCDAFEULL,
		0x5F06C54DAEDB97D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B58128BFE42307ULL,
		0x78AE367D1E5F28F7ULL,
		0xB9573F03E9C1CD07ULL,
		0xCD26EC7EC274847AULL,
		0xC950E03C1A38BAC7ULL,
		0xFB4EB9914B71CF27ULL,
		0xC418CCD76505335DULL,
		0xD59A07497252A260ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C09C9BF75951A89ULL,
		0xACCF43C0D2B3927CULL,
		0xC131031139B4674CULL,
		0x3C3C2E78000EAA16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2896AA1FBAA26E7CULL,
		0xA49FD930653FF908ULL,
		0x37D1DBF93AAA43BCULL,
		0xB75A648400943A53ULL,
		0x7B79EFC7DB86CC77ULL,
		0xF6A68F94053D2661ULL,
		0xBB27EBA86AD05475ULL,
		0xE1A071E494C87E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDF2E0ACEEFCD51ULL,
		0xA4A590B838139CB0ULL,
		0xE37708463511CC1DULL,
		0x30B2F80AB7B91D52ULL,
		0x3519914CD4F00F8AULL,
		0x7328E3B8456FC2B9ULL,
		0xE5FE8BE0F74C9EF8ULL,
		0xCEDEAF45BA6C82D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D058257E612ACCBULL,
		0x84A1CB16A5A92752ULL,
		0xF87F0B4E2B256840ULL,
		0x4F6A500DB28270C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA17A98EA8E32D8B2ULL,
		0xD47097E62D1AB4B3ULL,
		0xDDFCFA1875843E97ULL,
		0x25166878F3FE2168ULL,
		0x3BFEB8D19B2A4865ULL,
		0x5763584E976A3A75ULL,
		0xFF842DACC884D401ULL,
		0x5DFE0785103BD053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C5F8B7C03064EFULL,
		0xA51BFAFFBC912F07ULL,
		0xD3FC3E4B6F7A87E2ULL,
		0x60A0C60E76ADC717ULL,
		0xB8CC6D062C01DF9EULL,
		0x7C094E89E020BFFBULL,
		0x0A7D1398D21A5EA5ULL,
		0x59B546C827F935C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x112BE0654E02014DULL,
		0xBEB21019A571B3B6ULL,
		0x690E9AC399D72257ULL,
		0x67423E74F7334B3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x913A7D3A1994602DULL,
		0x859E7111CFA2E52BULL,
		0xF6AB83ACF068F88DULL,
		0x721E90B16DA56937ULL,
		0x2F42284654F8A6EEULL,
		0xA60674210879338AULL,
		0x3101497172830EB4ULL,
		0xBCD2419249975DA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731AB5F522E3F59BULL,
		0xEB10C24651DAB5E6ULL,
		0x8C4990414FB23FCAULL,
		0x0E2803735CECDCBCULL,
		0x63E50079D76E26FFULL,
		0xF81D317B3806486AULL,
		0x0068EF5AFB707550ULL,
		0x24E93EA02C8A4477ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DF3AF9F993F6B63ULL,
		0x6B2D93686ED715FDULL,
		0xA0FF52C14D797D8EULL,
		0x708CFD2E60AA49EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0DCD02FA78B0920ULL,
		0x6FD9639F0CCE2BC9ULL,
		0x4C4FEE4DA16BB463ULL,
		0xA3B6B9ED797A26C0ULL,
		0xA0C42F43BC7F7551ULL,
		0x2E6C4133462013BFULL,
		0x024D2F4F9ACF80FDULL,
		0x40754ADB6D60302CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF1E1F2E45DD4FBULL,
		0xCB1F2EF3E8E8EDABULL,
		0x0CDF2926D4015209ULL,
		0xFD5549B5B9CEAC1DULL,
		0x62527426B12CD3F1ULL,
		0x8A6D4150B03490D6ULL,
		0x4DFB7E89F66661A3ULL,
		0xE2BB65C76388B300ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68CCB48C717124C2ULL,
		0xFC94304D64DAACBDULL,
		0x0391027D350509A7ULL,
		0x0FF9713135A80F20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D9FE1C9F4E954E6ULL,
		0x515FAF70D6184220ULL,
		0x3E1049D4A0FB5F6FULL,
		0xE1CAA60458229AF0ULL,
		0x9A25053948AF1C27ULL,
		0xDEE7BC29D9D2CAB1ULL,
		0x6C4290D8829439FAULL,
		0xF4AE172E9A055B42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B62765D40AD3513ULL,
		0x3F79F4032712942FULL,
		0xFA6E79C62D3F4708ULL,
		0xD4747D9A9BB23793ULL,
		0x8413EC58DD1A2B9FULL,
		0x2B4801AA7EEE0939ULL,
		0x3E0A2ED41340B92BULL,
		0x5C576F299BF5BBB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98C71CBCAC57D75AULL,
		0xBB9B6A552CFA65C4ULL,
		0x20005CB6FA21373BULL,
		0x2A33192772C2122BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD43A9B7F453836B9ULL,
		0x90D38D81D1C663DDULL,
		0xD7028BE2AA02C429ULL,
		0xF864331879492E90ULL,
		0xD10A1E1359F9A5E9ULL,
		0x2B9CCA8817D507F0ULL,
		0x7BBF6EB73BF0A6D2ULL,
		0x42EB1461E3B933C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A042097E4F82CE7ULL,
		0xA961C785A988427CULL,
		0xC48E8CB188A76804ULL,
		0x81090691EC2CF9BAULL,
		0xE199E14B41A90481ULL,
		0xE71875A413A7159FULL,
		0x82DB64610D49F1CAULL,
		0x7D3FBF4838DD62D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4DF809AFC37FDFFULL,
		0x13165FD4C7101964ULL,
		0x044D87FC0E1A3B39ULL,
		0x4EC9CE55E9BD384FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92F86F7986AC138AULL,
		0x03FEFE906F9F6230ULL,
		0x7558ADA4CD77E315ULL,
		0xB93B362350233C8FULL,
		0x691D5F0BFB3CD67AULL,
		0xBF62ED9DEE6E8FC6ULL,
		0x606966AB79657FABULL,
		0xCADF05E60AC0CCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E9A7B0272E61117ULL,
		0xBFB21AFEB0887C21ULL,
		0x68D86EA47AA6BDFAULL,
		0xF67D117C24880B5FULL,
		0xBB29758B3EC707DEULL,
		0xB918F74A6A086F76ULL,
		0x6C9E585E40E2E4CBULL,
		0x5EF4357F55E277A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6929D930D42AFE8ULL,
		0x334773F7663FB1E2ULL,
		0x3CA45E76B634225BULL,
		0x479913E6049BD77EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0081316C485C4029ULL,
		0xBC29B205DF8F3D5BULL,
		0x4AA17BAABCBC82A6ULL,
		0x46051A448FF09A02ULL,
		0xFE6EC45F421828B5ULL,
		0x1B87D0D04D004A2CULL,
		0xCA751DF5640C2931ULL,
		0x13A8A1ADA297D952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458E7693A8B68E0EULL,
		0x0B3660A49A76FBCCULL,
		0x6FBD5E732CE0F7E8ULL,
		0x662D16B5C929A9C4ULL,
		0xB6E863487B385A4EULL,
		0x8F02D746A3FE7504ULL,
		0xBF7FB5FF518353CDULL,
		0x41822D278C41027AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58E5243A24DE545BULL,
		0x8CB05BD05B5DE589ULL,
		0x7B518BBE502B3785ULL,
		0x118D4F7617AAD44FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4782449F6A28B1ECULL,
		0xC4C202203DB1CEF2ULL,
		0x74BD7DE115699633ULL,
		0xA268127F0EEA9E17ULL,
		0xFAC06A60F76A8E4DULL,
		0x9DC8A23C2B384223ULL,
		0xA252F3667D8AC1F2ULL,
		0x767D127C2821D681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD7F3374FE67AF00ULL,
		0xF52EE893E80E21B4ULL,
		0xF0883242E6EDD960ULL,
		0xEB4B63BD499FF130ULL,
		0xEE21CEC88A7F8476ULL,
		0xD1DE6486C8C201EEULL,
		0x1382011F0BF1BCBDULL,
		0xD378C87A6C0C493CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x498E29CA96A476AFULL,
		0x14584278F331351DULL,
		0xB73942390B3282A9ULL,
		0x69BFAB03B07DA539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x299C740A906593F2ULL,
		0xF570B37C3FF35039ULL,
		0xE3718B70DACBE95CULL,
		0x95B1B0BA668A8A15ULL,
		0xF020CF239129D162ULL,
		0x042F1C0BB9ADA1D3ULL,
		0x19EA79F19C188E59ULL,
		0xA813D3A630011DB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CD1467FFA98EAA9ULL,
		0x9C6CB254CA3C55A9ULL,
		0xBA6986CB2CC8244DULL,
		0x4A607366542845A0ULL,
		0xF21BE771A638C5BDULL,
		0x3AE56FA0DCAF7ED5ULL,
		0x5B5AEA457315264CULL,
		0x200BC8483593DAD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x418591F3759466BFULL,
		0x39F3990443702C43ULL,
		0x72575833C48536F5ULL,
		0x7C82ED473E9A3185ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5FDD39ADB28BA9AULL,
		0xFDF308D51DEA8B8FULL,
		0x66B832A3F6E698E0ULL,
		0x7DB82E050CE61F62ULL,
		0xE80E3AF2CBEDE66AULL,
		0xEF80D686020975DAULL,
		0x351E0BB8399FF5FBULL,
		0x7DDF43465BC07037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91F2955081A9BAFULL,
		0x7599104C40DE657AULL,
		0x0740B0C241730F4DULL,
		0xCAFB9087832874BAULL,
		0x2A55EE286DD42653ULL,
		0xB4A963027DC34282ULL,
		0xF040AFF063730E40ULL,
		0xB0CFE06441D1A4FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x563A104FCAE0A125ULL,
		0x44551E0E7F77C541ULL,
		0x9853218B801DEF5EULL,
		0x23054B0D632FD54EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF30998F0AD3DEC86ULL,
		0xE681797EA78521EBULL,
		0x22F8F669C3912954ULL,
		0xAAE0EB4FB9FD4528ULL,
		0x78FE8DDA8864CC74ULL,
		0xDCF6125F3CD2D61AULL,
		0x20A31221984667D1ULL,
		0x1407179AD0D958D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1592495AA0D38CULL,
		0xDBCC9D07D349E615ULL,
		0x96FBE73D55440BEAULL,
		0x41DCC06EEE4722B7ULL,
		0x6E99EFE1FF8EFAE5ULL,
		0xA5DA974B737A25D7ULL,
		0xD3DF05F46FF65CADULL,
		0x9514EBD1978FC4C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2E3798BA25A3162ULL,
		0x38C92166B76565C9ULL,
		0xF116DDE06A2EC4CAULL,
		0x40F6AABF4CA21C43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7A91C988BFA6F37ULL,
		0x801D3734372BA654ULL,
		0x78203C47026C43F3ULL,
		0xDE15D39B5F60FE40ULL,
		0x7892C82C03E33817ULL,
		0xBB2222B94391B7E8ULL,
		0x194A747B6F0F5FFEULL,
		0xF4AD604FAE7F323FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19691B66F3EA0E6EULL,
		0xB88BA98202363BE7ULL,
		0xFF341A9782EB1151ULL,
		0x68839699307ECD6FULL,
		0x379283DC1E8FD658ULL,
		0x537E956D6CA6E72BULL,
		0xBDA822B29399042FULL,
		0x9FFF172AFDE94E08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x344A250DA270E511ULL,
		0x29D886F41BD06685ULL,
		0x130445801312D36BULL,
		0x07711874652210E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7EABECF99A786C8ULL,
		0xF641A3423958629FULL,
		0x78299165280C6393ULL,
		0x92E7BA25B7E492D7ULL,
		0xC93C998C07E4C810ULL,
		0x47EBE1F6D0B18A75ULL,
		0x9CA51895452B9396ULL,
		0x68206A8D8F9AFD82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x672270096F4FBDDDULL,
		0x30EF3BDEAFC6BDE7ULL,
		0x93118DEEA70C3DABULL,
		0xF542DD1470E261D9ULL,
		0xAF58B02D0BDA91D6ULL,
		0x4509CA69116EC685ULL,
		0xE02932CD91D03753ULL,
		0x7F9DFDE5F384AD82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x689CF2DF93DBD4EFULL,
		0x32E1E66DED7ABA5CULL,
		0xDF7C1F1B208FD7DBULL,
		0x2100FDF2725210F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC27FCD4CA3E7478ULL,
		0x9A7F69760C33F0DEULL,
		0x7867A1FC54A762D9ULL,
		0x524FE40FF01DAADEULL,
		0x911BEA0A8268D00EULL,
		0x9A1A81D8071CA986ULL,
		0xD3B2A432088D5733ULL,
		0xE62CE08A1FA4FEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB0A2F0D79714F0ULL,
		0x9FA5C4DB2BC76049ULL,
		0xA9558E681A84394EULL,
		0xFBC78E09555F7982ULL,
		0xB1AE2EAA2096D44AULL,
		0x63141AF912D7C79BULL,
		0x86D4AA857A004D22ULL,
		0x08E3DCC405A63D88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66C12A3277D2C360ULL,
		0x25CCE9B322A61972ULL,
		0x380523316312A819ULL,
		0x2F5EE56E768EDDA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C61516613EC1B18ULL,
		0xEC974EB42D377F24ULL,
		0xABDFBAB6622565E1ULL,
		0xEF0661713A7AE50CULL,
		0xD3DCA852BA18E523ULL,
		0x44DA50E9BBDD7F56ULL,
		0xF8023933743369DCULL,
		0xA13C8C95020CB533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39135508D6E3A1D1ULL,
		0x84176908FD66C332ULL,
		0x63B73B85086C1772ULL,
		0xB9650429D308F2F9ULL,
		0xC2D1853F91170FC3ULL,
		0xC1828C1820BD94FFULL,
		0x953F413EB143E86DULL,
		0x35B65903A9F6437EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AF53135534E27E7ULL,
		0xE7871CC8368D84DEULL,
		0xF1194D86494684D6ULL,
		0x2B8D04DA7AC6D2FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A28FA83275D4F45ULL,
		0xA09D24565352ED65ULL,
		0x136528D42DDCE54EULL,
		0x16C6DAA54D04E9C2ULL,
		0xBAE37C6F8C7E2767ULL,
		0x75AD003E0E136057ULL,
		0x51EC7D487C289961ULL,
		0x97E7CC3BA3A30229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D132495814C957EULL,
		0x0679D430814A9639ULL,
		0xE13825382332B9CBULL,
		0xD4232FB05B71571EULL,
		0xB194A51D63035B77ULL,
		0xA950EADB9DD9AF0BULL,
		0x95D05ABF2C7622DBULL,
		0x1B272BAD09534CFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEC9CC1FCE4B0200ULL,
		0xEFCE7CC27A98A875ULL,
		0x1E5A23FDDF27C35FULL,
		0x473B801FD968776DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA937AB68F549989AULL,
		0xBA1F3D03B792A4B0ULL,
		0xA43F694BA0318E50ULL,
		0xAD15F853441BB0FAULL,
		0x09F28C27D7827368ULL,
		0x0F1D0A34FF4C4EA5ULL,
		0xF28F3CB580CC922BULL,
		0x69B41730D84930A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB79438F916786B2ULL,
		0xCE823B22E4620560ULL,
		0x1A57D8237C490CFFULL,
		0xC9335B08092288EFULL,
		0x69D6E189EF4A2A88ULL,
		0xE6CAE72A648846C8ULL,
		0x9013B4F0485E9F2FULL,
		0x45A792BFE2FB9263ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71D9BB49DC3CE3E6ULL,
		0xE7CE3573CC49CA0FULL,
		0x283DB86E843A9298ULL,
		0x3DBE460FA47EA60CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D5CC8D38D37A765ULL,
		0x86BD89D46ADB4AD6ULL,
		0x492241F61E691ED5ULL,
		0xF103CD32296A1CCEULL,
		0xE157AA8758C9ADF7ULL,
		0x59B8D9D02D0173A3ULL,
		0x38300D2E1007F737ULL,
		0xB5B91592E60703C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770E575FCDCA9B30ULL,
		0xFD00087319F1BA80ULL,
		0xC72F65E8E0F4F038ULL,
		0xC741A280039DF8DEULL,
		0x814B25E7B0D008F2ULL,
		0xCC7F01F0FF991AC3ULL,
		0x897329EF201EB704ULL,
		0x07ECA81DF64F1EA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x682A2126AE7B8EBCULL,
		0x80538C820E66C1A4ULL,
		0x71FC9764DA13B61DULL,
		0x761A6A0DBB182787ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6822349F45BEC52EULL,
		0xDD7FFCED13131EB2ULL,
		0x29C737157C502204ULL,
		0x4B423FDC14611070ULL,
		0x40864B84AB27ACFBULL,
		0x04F97C96A6C50BC7ULL,
		0xC3B020D3031F292EULL,
		0x466C958520A1E1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7596106FC1ED1ECFULL,
		0x21FF8CA943984500ULL,
		0x7AA4F031C1A0E712ULL,
		0x67E770D98EF8D437ULL,
		0x5EA90CCD6DACA2FDULL,
		0x36DDEB6C23FA2550ULL,
		0xB41355326F3EDA4EULL,
		0xD9BB041BC785F595ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79637362A4151ECFULL,
		0x5397FC9339990F57ULL,
		0x006880B9ADFAF02BULL,
		0x05B664A5BF8D4BA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49E25219184F3F7CULL,
		0x069CE0A30B347FD9ULL,
		0x812E2C95702AD6FBULL,
		0x779491E772E1F1F9ULL,
		0x6A9334FB185892B5ULL,
		0x8432D1B0609A70CAULL,
		0x9EEDDF474F9931E3ULL,
		0x025A671C56CD420FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD20F3D1480856AC7ULL,
		0x1A6F19A747440CA9ULL,
		0xF0D6E128DB289531ULL,
		0x18F5F98BE476866FULL,
		0x59BC2D992A982452ULL,
		0xB0A0C418178BF3A4ULL,
		0x3849C6EB641C6FD3ULL,
		0x39B02FFAA30AC714ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7BE2D8DE25A3637ULL,
		0x53DBCB969C1706D5ULL,
		0xCCB2E91189871023ULL,
		0x27E2C75C3D49ACDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x550BF9B98C1F306AULL,
		0xA9242FA08C8C64BDULL,
		0x766A2E1649712492ULL,
		0xFD75522B05C3FD43ULL,
		0x384187F0C70CC2FCULL,
		0xF6AFD0EE09331AD5ULL,
		0xB669E2CEA17C0F50ULL,
		0xD057422177F91BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A5AE53182F3226ULL,
		0x0161938FF936D2F7ULL,
		0x8940E44717918B32ULL,
		0x16EC17BC5EDA6A56ULL,
		0xBB5EBFC85001C476ULL,
		0xD95266314C66E531ULL,
		0xDBB72325A3BD31BFULL,
		0x780C0EB95809DFA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C1001681F91C83CULL,
		0x03A0741499A5880AULL,
		0x63B1BCE4DC347CEBULL,
		0x01B2DBE3646C7CFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85D7295C90A79740ULL,
		0xC161E561B621AFB5ULL,
		0xF51A6D2C1839F119ULL,
		0x048CE99074A77484ULL,
		0xC62E14A5E280D1E8ULL,
		0x4914486F429845E1ULL,
		0x541F164C74DAA633ULL,
		0xCB99339EF9DA80E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D024744A2CF8CC5ULL,
		0x6C77B861EA45CF76ULL,
		0x75B30D81F8C3CE53ULL,
		0x1F80AE2EF66C7D16ULL,
		0x0ADA3D1F740EB41BULL,
		0x700E206BC1EEC216ULL,
		0xE302ECAA9C5FA53BULL,
		0x48F18CBE854CD481ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1746E00C52C879BBULL,
		0x8BD41D84E505707DULL,
		0x49958DB041B84790ULL,
		0x49EF00B2CB428E0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD101A782E19B5DB9ULL,
		0x4AC252AFAE2129B5ULL,
		0xEDC34F3FFA4E869BULL,
		0x9C0CDA670F178CC4ULL,
		0x7AC77BD60135E3D0ULL,
		0x74933BC15F1FFCBFULL,
		0x8A8D6C016BE1A314ULL,
		0x08E490F5BE7AE43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC599ACDA97D5EF2ULL,
		0xB7B557287F249711ULL,
		0xF1CDF0644C0713F8ULL,
		0x7E79FDD6EB7BBDCBULL,
		0xA00B06E2EB890F05ULL,
		0x4B1E281F675177EDULL,
		0x0C36B018D1B05DB9ULL,
		0xE624CED3999CD2AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CA168CA6FC59003ULL,
		0xBA6DE591F7A449CAULL,
		0xBCD543629197BE2AULL,
		0x4609ADA19C926B29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C878AF253DA563FULL,
		0x39153C6E7684986BULL,
		0xEB0913A0BC85F8EAULL,
		0x6E85729800563612ULL,
		0xFA9CB49AE61E1F24ULL,
		0xFC647BAC06B78B07ULL,
		0x735B068CF232F7FCULL,
		0xD43DC92C2EA9B347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040B45609F2C4CA5ULL,
		0xF06334AE485A86D1ULL,
		0x98BEB2B6E78DC66AULL,
		0x00675AB6B83D9504ULL,
		0x53D93E13B34CD30DULL,
		0xECD977FB3E0BEA78ULL,
		0x0B894554029D5777ULL,
		0x2B990C3BF0CCA14FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD97FDDA33FBF58BAULL,
		0x975493FDF7A3E6ECULL,
		0xBB6D0F5D652E063FULL,
		0x7692238A76E94BEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94FF6B2417C158C6ULL,
		0xDAEF3EC5670039B8ULL,
		0x5BD92B8EC1CDE5BEULL,
		0xE1DDB38D56553A47ULL,
		0xCF7CF0708FCDF59BULL,
		0x016966D3214A12D8ULL,
		0x1F9A24BD0250F0A4ULL,
		0x62DE0F989641CEA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A8244E0E37748CULL,
		0xDF56B2FA4D3AB80CULL,
		0xD69CC9914DF63D18ULL,
		0x6DE27F2EEF0EB986ULL,
		0x66178ED2C9B095E9ULL,
		0xBD06C7FE1051C726ULL,
		0x8A4D8C896C41ADBDULL,
		0xC009351F1A8CDBA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB063C44171E616A5ULL,
		0x223C1F6B9EA0BE27ULL,
		0xAE9AF9A5BA1B96D4ULL,
		0x1F93A266C42292B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04D4FF8FCC00F4A8ULL,
		0xE18E1C02F0F9CBD1ULL,
		0x70D5EF74C62201D6ULL,
		0x467F4431A22B6D89ULL,
		0x7FD7982E8959C2D2ULL,
		0x231D3D05596AC399ULL,
		0x611ECB5672D2CFA4ULL,
		0x19FBDE41AEF377F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD8578520F9D1A7ULL,
		0xDA2EDBF2780B355BULL,
		0xDCA896FA170B2980ULL,
		0x29FAEDDDC449B42FULL,
		0xEAFC6DC90B8F35D0ULL,
		0x52E6B9B643176BF4ULL,
		0x9164ACCC0891D6F7ULL,
		0x8A0A4C9B63E70808ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC084F31B57180EC7ULL,
		0xEF76BDCDC94D98E3ULL,
		0x69CDE10674BBC1FCULL,
		0x7A5FF50301BA5680ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8873DF44BE7F07EULL,
		0x25AEAF253037E245ULL,
		0x9FF3F6AF64864BC7ULL,
		0xF10121B86C5AE544ULL,
		0xDAE0A9C43FA3CD86ULL,
		0xD3204AFDC0433298ULL,
		0xAB6D5F4B638EF3ACULL,
		0xE579C22103209F17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C702CB787664D7ULL,
		0xB501D6522620E6C3ULL,
		0x66B2034290A77910ULL,
		0xF4C7578808781910ULL,
		0x474646DC9592E611ULL,
		0x57DB704AD7EF0C23ULL,
		0x7F1ED2CCC9C4CDB7ULL,
		0xE13457DCA3F41FFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABAAE98C11F3E718ULL,
		0xBCE54F618694B0F6ULL,
		0xCCEACE37A7E07526ULL,
		0x1E879056847DAA3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D7D6DDB062E63A7ULL,
		0xD5AA17E3D33CDEFCULL,
		0x23311E701EDA2134ULL,
		0x32592425CCD536E2ULL,
		0x005F904B334295FCULL,
		0x2F59C2C0B2B1A0ABULL,
		0x11EFCD744C65C5C6ULL,
		0xF3914D97BA8741FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B3EC02F5ACF449ULL,
		0xF51E4A543DCD3657ULL,
		0x3EB6E70CAE0419ADULL,
		0xE435054FC973CBA9ULL,
		0xB51AFB7A36A70FA2ULL,
		0xFE72CE858AEE2B75ULL,
		0xE64B0A208B59CCCCULL,
		0xB50FAA9D2499CD12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35F798DD8F9761FDULL,
		0x22D40E577C730E8EULL,
		0x5EEF35D2189CFC84ULL,
		0x1562500844A0C647ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC44682A4B497F888ULL,
		0x4E0B1FDD0A43294DULL,
		0x65C24ED1B74A10DAULL,
		0x544BB8DCD534AD0BULL,
		0x711FAC959F5712CDULL,
		0xBEB78EA8F7FA0181ULL,
		0xC0023757345552B2ULL,
		0xAEFF17DB82E18A37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38A8EB82B6F2C2C5ULL,
		0x6F089958265F0E32ULL,
		0x0F7F199C244535D3ULL,
		0x30B6C70FCB642499ULL,
		0x807C8E3E9A182A53ULL,
		0x434E210521AC5BDFULL,
		0x86E8243DCAB813B8ULL,
		0x904777E0B4F04645ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43D4180CC4FBB88AULL,
		0x30A8CCD6B36AB125ULL,
		0xD0220AFB405C3435ULL,
		0x32D6B1079BA09E66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41A2AE5CDE4924F1ULL,
		0x4E2348D668E89FE4ULL,
		0xF7A909EF90527E96ULL,
		0xF0EFD3203003B143ULL,
		0xB48FA512DA636880ULL,
		0x3139419DECDDBC0EULL,
		0xB4EF3C072AFF5E28ULL,
		0x976F2F935A8436E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26DAEF6F96DAE60ULL,
		0x3F839B95CE56E1FFULL,
		0x790A83B81A72C1ECULL,
		0xB581B6A6240F9BB4ULL,
		0x95E987785CA41EC5ULL,
		0x5E0A7285995D5B67ULL,
		0x5A46D71B76C09E14ULL,
		0x0AD140F3D1F9832BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBDD64548F406B71ULL,
		0x67926ADCFFA016B2ULL,
		0xF39D813437303F9BULL,
		0x1ADF8828508AC35EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12F6DD9AE93AA554ULL,
		0xFE1E7ED357421F39ULL,
		0xB5646D80BBBD97F4ULL,
		0xF4BBC9E61FD77992ULL,
		0xFFE6A073F2BB0B66ULL,
		0xC4E6B57B1A48C8BCULL,
		0x0A06C431EEA349D4ULL,
		0x4975AF89B0E12AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE32BDA44C3CD53ULL,
		0x8C9DE4B48FF0EDCFULL,
		0x277B589C03DDB13BULL,
		0x669F63994514EE7CULL,
		0x70DC35BAB747D24CULL,
		0x68D1BFFD946845CDULL,
		0xF111E827D4FC0E8EULL,
		0xF1D557EF160B6BB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC09F893F77914E3AULL,
		0x1C9D0AC0A6A4A0F8ULL,
		0x4241BE6486B2B32BULL,
		0x0FE9673FD67CE7C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E8216A0333A88E6ULL,
		0x8BC36ABABDDB5732ULL,
		0x2A14C30CCD213B7EULL,
		0xA25E496700B71706ULL,
		0xC46BB5003E29ACA7ULL,
		0x51214204ABBE8D4CULL,
		0x817D0BA52D96BA26ULL,
		0x95030D6073AC2201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58D7DB2596D22A35ULL,
		0x76173A4CAE3F1200ULL,
		0xAFAB96BFDDC78F22ULL,
		0xB1163E946D2DA163ULL,
		0x476878F37EDF33E9ULL,
		0x482F94A93D314755ULL,
		0xF2B05CE553727155ULL,
		0xBF989E85432FC176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA425255F017649EEULL,
		0x698BEC007894A7EEULL,
		0xACCB1CC750BC7B63ULL,
		0x1F147F5BC5FFCA33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6157F4022F9174DULL,
		0xD186E1FD854833B4ULL,
		0xBD32BE1319A9B18CULL,
		0x0FF0E77B61098848ULL,
		0xF6512C788B3FC0B3ULL,
		0x71E89CAD1691D55FULL,
		0x334F3C286A37DCBCULL,
		0x1C30EAA7C3A3F4ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B139C5DE058177ULL,
		0x9799EECEAD7E0CD4ULL,
		0x9E09D3F7C068F61BULL,
		0x483A630669842A56ULL,
		0x41F5F120F001BEBFULL,
		0xF8D5E78E4112F1C8ULL,
		0xF9A34D34E06FC7CBULL,
		0x7650E9C491D285BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4EF147B5027DDFAULL,
		0x32B3D5C2889FEF64ULL,
		0xAEAE6241CCF3D723ULL,
		0x66F6A62E5C9BD574ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x913578A97D99907DULL,
		0x0D5972AF78A4CD29ULL,
		0xCA277FEB9010D08FULL,
		0xE92E3F5A5ED15586ULL,
		0x7D579C591C84C752ULL,
		0x18545063C08621C7ULL,
		0x28ADDBDA29A49C8DULL,
		0x441AAD78F74144D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA4F70B7702D8EFULL,
		0x82E9698DFA8E3B54ULL,
		0xFC44145A1D90F8BEULL,
		0x5227B06B8424DB43ULL,
		0x5C3139DB895F7FABULL,
		0x11B09C3855C0DFAFULL,
		0x516ACE13A50CC45EULL,
		0x3B0D0371298EDC7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D432041DE1F5A91ULL,
		0x86BCC793575E6169ULL,
		0xC1D777092109EECBULL,
		0x6F0DCC176327F726ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x263AAD33A793CD00ULL,
		0xBC083FDAF6B4D77AULL,
		0x174375770A2EB1BBULL,
		0x6EAAC96BD91E9DF6ULL,
		0x0295FF1A97867C11ULL,
		0xAE467DE3AAA1956EULL,
		0xF41F3008E7D3F299ULL,
		0x4EAF42BDE953C0F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B865E84CD9947DULL,
		0x92FB63892DC9C079ULL,
		0xAB8ABB0E79858480ULL,
		0x0C20FA51DAC26B29ULL,
		0xEC8627FD01AD8128ULL,
		0x3B54A262F4F4FA95ULL,
		0x740244A70D355861ULL,
		0xB1CEF1BF3FD4AFC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83DC35AF98EF74F2ULL,
		0x38F3716CC08A1313ULL,
		0x7003AAEF0434119CULL,
		0x2BD5D4E72738C025ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33C4AB30F466C103ULL,
		0xF56804FD417214D5ULL,
		0x9B93DD58670A2C05ULL,
		0x6636C89EB2AC81A8ULL,
		0xFB788AAFEAB1A0F8ULL,
		0x130881F02B2D13CBULL,
		0x65A08B80CD85EC96ULL,
		0xE9E1C73B6F30A032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88104C680DBF78A3ULL,
		0xA1CF0124B8DE2FD8ULL,
		0x89505D46712648C3ULL,
		0x34BBE7E1C8F71CACULL,
		0x6F08BDF0EBEF861CULL,
		0x7EC59B2173C1DAA2ULL,
		0x4BBDEF0178FE3595ULL,
		0xFE5C027D5C835518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x844CC322B7774496ULL,
		0x55874687C27E6127ULL,
		0xE9E6BAF882090D58ULL,
		0x275614F3AF6E8ADBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4475C5466CD0395ULL,
		0xF5D32BE8A6F45E8DULL,
		0x852D3D4FA0D18192ULL,
		0x22A4DB4FE1BE53DAULL,
		0xA82DC03D4E52F226ULL,
		0x89EA76FEEF9B4AF8ULL,
		0x1927415E588CBE21ULL,
		0x2ECC9530D6A8195BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEE72C57EDDCD00ULL,
		0x709DA432534FF666ULL,
		0x5856EA352F8E0098ULL,
		0xD3157F17F1FE0C33ULL,
		0xCD6AD015C075500EULL,
		0x6F52A623BB12BF5DULL,
		0xD602115AABB9C1FDULL,
		0xC7C7F6F4D4E1F141ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D488F6DF6D542A8ULL,
		0x77BE88401FE92123ULL,
		0x245B73A61894EE56ULL,
		0x1A3ED920332A3B67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61819902A46EE8DFULL,
		0xE3FC37EE249AE971ULL,
		0x8BA2F85D183688B2ULL,
		0xA3ACB213DB0D3F76ULL,
		0x769D4D5BA9FB7074ULL,
		0x8E462B186EF2BA8AULL,
		0xE43CFF711AB1503FULL,
		0x2B4BF7871DDC7B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC83871035F6716ABULL,
		0x87EDA7102F9BEA22ULL,
		0x825FE9596D8BD472ULL,
		0x93AA5ABFD1B7A478ULL,
		0xB9A488A29D1CC7DEULL,
		0x7DF5F91D605661B6ULL,
		0xD8FC2E96E8C6E32AULL,
		0x04A2558A211D3F48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6365B772E14D949ULL,
		0xC7F5FC2220342EBCULL,
		0xB4E20F671376E560ULL,
		0x4D3062E18DB87A89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6731F1C05087530EULL,
		0xA896993028FF964EULL,
		0x392098C118DE587BULL,
		0x05A03015D2A28072ULL,
		0x83269DFC6E1B267CULL,
		0x2A26892453F347E8ULL,
		0x55494DCB7F2AFF02ULL,
		0xACF5AA40C7F61682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30BE9C066F04284BULL,
		0x9BCE8503A97C33FDULL,
		0x0CFA6918C1B7CE92ULL,
		0xED3414C6F32888CBULL,
		0x59CBA12CD83D29B5ULL,
		0xA9956330461D8341ULL,
		0xA272A65BE78E44FDULL,
		0x9D53DE2EB6E2F85FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59F4DC8A2076B073ULL,
		0x2253B6668D3E9321ULL,
		0xB8030A38D86A2694ULL,
		0x6A7065FD685070CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B8395E1D5C7417AULL,
		0xBC293DC483205335ULL,
		0xC19D21B8C14EA811ULL,
		0xDFD2AA681D2495C7ULL,
		0x7A356424219BF942ULL,
		0x0083397FB40964D4ULL,
		0x66DBCB26B06BC5CAULL,
		0xF836DD836DD23BA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B174180E183376FULL,
		0xB9C43260F28A8BBDULL,
		0x5EE637A2603564A2ULL,
		0x21140F528974024EULL,
		0x032C6DB917A49825ULL,
		0xDAE6C64145CEE799ULL,
		0x5F78B13DB3F67F0AULL,
		0x9C76BED2E5FC8397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABC0E8446EFC766DULL,
		0x979E26A7ED445E4BULL,
		0x7B6CC2ABDA81C3CEULL,
		0x5D432949BD69E4F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE087C33382327B64ULL,
		0xAD0656B1243AB43CULL,
		0x1AFC460697F03FD3ULL,
		0x666518A953764DE7ULL,
		0x8ACDC6DC657D7972ULL,
		0x1DC3CAE2C9062622ULL,
		0x09C19EC510A3A889ULL,
		0x3BD8ECAFCEB1944EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F355E90343A83CULL,
		0xBFE4A1D487861B43ULL,
		0x11F129541AF9FEE9ULL,
		0x667517AA346EE9FCULL,
		0xA3BE5C8FB39A5CBAULL,
		0x7016A872D9606266ULL,
		0xD86C524422790265ULL,
		0x5919E1A9DF707334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4DE34ACE6A515CDULL,
		0xB4D4D17A2F4FA6DDULL,
		0x5BB477D5D74AEA35ULL,
		0x284BA3E0A2B24DA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5762B5BAA4E7033BULL,
		0x5B1232D1C3046484ULL,
		0x212416D1054A34D9ULL,
		0x63186E338393155BULL,
		0xFB48D515F88C1910ULL,
		0x739F5848EFB03A50ULL,
		0x5F43A67FEEE4B6B3ULL,
		0x32EB20F8B7FB4104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45C192C61C506633ULL,
		0x6854C15AE80B6EDBULL,
		0x8EF84F751998D247ULL,
		0x93020AAF5451A0D8ULL,
		0x386C2F77F52867D5ULL,
		0xAAD9DB4AE0C04B5BULL,
		0x9E5BCDAEEDA2A865ULL,
		0xB925133AF13FE89EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE61B8690962E8BFULL,
		0xC00DFF2D12966E23ULL,
		0x3495F6621B7F821DULL,
		0x637C6DAFAF10939DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F58F78BBA60F512ULL,
		0x4AC9729456B8B109ULL,
		0x047AA35DB5D29C37ULL,
		0xA4A7DFDDF7FB3034ULL,
		0x3795EEF3DE2C6347ULL,
		0xDFC119471007FC7EULL,
		0x67FA6BD86A494760ULL,
		0x05473ACB546EBF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B5787FABBAFF66ULL,
		0xB9ADEE8243AC8934ULL,
		0x632C23E7E6494E86ULL,
		0x9FC168EB2B83FB6BULL,
		0xDC7EF45BF3292B86ULL,
		0x15DF5561A52339D4ULL,
		0xCC09E52F486B2D85ULL,
		0xBCA4BDFD8AB170EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920CB198F120383DULL,
		0x889E981FF1010CF8ULL,
		0xC7027C90D6812450ULL,
		0x4D04FD7EBE90CC23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EF8CF6C15684205ULL,
		0xC286404A7D0D5E3BULL,
		0xD798FF93CA9C15EEULL,
		0xF4AF4BABE41B8B0DULL,
		0xE7E00979E9EAAA4CULL,
		0x9EA7CCBA4AF3767CULL,
		0xEADA5816B51BDC62ULL,
		0xB03367154503D3EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642C39C6E8012B93ULL,
		0xD8BD8A7798742121ULL,
		0xE48CEDB6860CA601ULL,
		0x98CF0B35D1B2E04DULL,
		0x9B36EE0DB52E2C35ULL,
		0xF5FEFC3DB60E001CULL,
		0x99050F4219E45512ULL,
		0xE9BDDFF56CE4C499ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BE6A7B50161CC99ULL,
		0xF2D7A850FEA8CF65ULL,
		0x18B4E16C4ECD85BFULL,
		0x51524F302704F0D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB093ED392DF0A7FULL,
		0xEA9900599A95CAF7ULL,
		0x62335DF028272DB9ULL,
		0x40EF8C06E947C7A2ULL,
		0x49C663942FCBBA65ULL,
		0x284D57464E6725B7ULL,
		0x93D78A806AD599C4ULL,
		0x212E804571C0267EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE866311F8387600BULL,
		0xBDBB23B3E48B3B4EULL,
		0x36D1FB78D772FF31ULL,
		0xF726239B92336130ULL,
		0x3B4571ACA9E7A1D3ULL,
		0x7A5606CD0DCB420FULL,
		0x033A3240C0104E4EULL,
		0x8EA4523E8F70D12AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9C6F611EF334D9AULL,
		0xFF93CEA54D2E5A9AULL,
		0xA2BC7BEAA9FD61FFULL,
		0x0A4C3D70EEDB10FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF98EE8805A7BF7E7ULL,
		0x62570C52DA1368DAULL,
		0x3DEE3CD4C7EE2856ULL,
		0x4A5A6ECA3E2452C4ULL,
		0xC9AF57695B94231EULL,
		0xA60FEAD0EBBFE99CULL,
		0x933336A94993EE5BULL,
		0x3D97CA67F7ADAD0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30C01922BD3A7234ULL,
		0xAA39DCBE78C3DDEAULL,
		0x9CAF552013AB08AAULL,
		0x4197162D59704750ULL,
		0x56B100E9DFAD4F73ULL,
		0x5A110D595BAB2B3BULL,
		0x415D4DF733596540ULL,
		0xF2C09902C1D12C17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA8FA64A0184ED13ULL,
		0xFFF20F53C463CD67ULL,
		0xC6FF722400F379B8ULL,
		0x24B4ADA2E36F2F91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9190F6E6CC655283ULL,
		0xAE1A9D5144328436ULL,
		0x7357232FB4299AFCULL,
		0x0DBD529E5BF4BD2FULL,
		0xABFA85D584B77A34ULL,
		0xC9A518678B9260A6ULL,
		0x9AE314AEF658417AULL,
		0x6FE5CA3F24B096B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE2A4E862AD1912FULL,
		0x641625CB0D43F1DAULL,
		0x451AA43B632D3C99ULL,
		0x8D375A742F868F69ULL,
		0x115FC387BAFB06C2ULL,
		0xD75483FF17CFA3EFULL,
		0xD1CDF5FFD2A709D5ULL,
		0x07CDAB5CABF5CB35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA65F7FEC938CE667ULL,
		0x41FA7F0765D6959CULL,
		0x075F0CF39D4AA0DFULL,
		0x741A8DC81828624CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01196F3CB26A4F8EULL,
		0x9D316CB227AA1A25ULL,
		0x371C114F4FD141BFULL,
		0x36EC6318E7C91FEAULL,
		0x4365E9CDD5C413D6ULL,
		0x28AF998B34F810C2ULL,
		0x8D7FD826D5142473ULL,
		0xEE7934A90106AEF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x293F6D03FAF863D8ULL,
		0xE06CCE73500245B6ULL,
		0x99E89432EF35CD01ULL,
		0x5741E642C98DCE60ULL,
		0xA1D33A25003D1487ULL,
		0xD9CBA03D6E00713CULL,
		0x905BA4AF93F5F3BFULL,
		0x6731CD8231E23F3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3A01548697BD455ULL,
		0x729B9FCA60698244ULL,
		0x309320D00B16AF5BULL,
		0x7443CC98DDA3E6D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57694EE9D3AF9F29ULL,
		0x8E207222015E473CULL,
		0x07299BE6B290E46EULL,
		0x6FF6E8154F24CF84ULL,
		0xCCFF971343B7A46CULL,
		0xB1955E5DA14233CEULL,
		0x2F5196DDA4CA54BFULL,
		0x3B98729D7A9F7AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED270214AA22454ULL,
		0x7D04A6EE57B214C8ULL,
		0x93F0DE440C93EE99ULL,
		0xF43F4222C75AAC9DULL,
		0xD40B2F1256019113ULL,
		0x493D3212D8773F12ULL,
		0x36448A50EC010ABBULL,
		0xC5604688BAEC4A63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CDE4EEBD21456EDULL,
		0x8E325E4D77CC865AULL,
		0x6B289A8613DDF27CULL,
		0x080E3106FC635929ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x207B783352C1DFB7ULL,
		0xE57A082552CE0BF3ULL,
		0x117A64629F0BC5E2ULL,
		0x64B3D599AF52F791ULL,
		0x1343FB82EE799D15ULL,
		0xC35D4CC90BF47203ULL,
		0x0AC654242E7EE8CCULL,
		0xC6ADB21DD2E88AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7565AA7234F5AF01ULL,
		0x1D1A6A83C3DD7EC7ULL,
		0xF213F6E128ACB79CULL,
		0x94336CB57CEFC0FFULL,
		0xA2D4B7A9019AC146ULL,
		0x17EDB6895AC5DE42ULL,
		0x0EA158C2E66660CCULL,
		0x9D771B7AABE5044CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B99E01A46E0D241ULL,
		0x3AEFEB15DBDA7BBCULL,
		0x8CE3BDF22A033E60ULL,
		0x6E9AC51BFCE9329CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72B0D07DF39D9352ULL,
		0x349FE39E1BBE3332ULL,
		0xA4A17B8CCB02D37AULL,
		0xA8A0B7EFD281219DULL,
		0xC4CD73DA40D58FC6ULL,
		0xABB2EB42DB5017B9ULL,
		0xA4B6223FF997095CULL,
		0x2926B17923B4E7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A7579158686D0C8ULL,
		0xF5417011B908D1FEULL,
		0x066030B82EA3DAA8ULL,
		0x0EBEE9B2BA36DE2DULL,
		0x3DADC05B29CACD23ULL,
		0xFE8AC3F4EB4EADF3ULL,
		0x98A22C420261F46CULL,
		0xB7273922CE62BB83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26EFFC45D8AFA3B1ULL,
		0xF354491E02EB14ACULL,
		0x6937CE874E401464ULL,
		0x05CDAB0DC27CDD1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C87C8CF93D0AF7FULL,
		0xD65D26FF26162FBBULL,
		0x5DBEFB60DB6B8921ULL,
		0x428FB4BC2FBE2C38ULL,
		0xE1D145CB531AD827ULL,
		0x0555170FCBB79048ULL,
		0xCF6DA06B1B09A20AULL,
		0x16CF55FB6F6EB3B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD1535B869EC062CULL,
		0x079D363757FF4776ULL,
		0x956FEFB2219DEB47ULL,
		0x045027C7DC8D9D34ULL,
		0x162FB48A64C01E0AULL,
		0xB3C7BD4AFD08A1F2ULL,
		0x4E65554CD89918AFULL,
		0xC6D87C4E2483FA24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96E22BA8B5C45C5ULL,
		0xE9BB43FE7C0E4926ULL,
		0xEF8A322C96820142ULL,
		0x1CE3DCAD72081AC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DB067D689E57FCAULL,
		0xF86F9C228FCD2AB9ULL,
		0xDB138808D838F2DEULL,
		0x6EA3CE9AFBDA52B5ULL,
		0x89B3BBAEFB31888DULL,
		0xE7BA52B4456ECD1AULL,
		0x3C08081F84E3A894ULL,
		0x93217BBA638C60D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC786509382A1F7ULL,
		0x3A622967F498C9D1ULL,
		0x2960B15255962B0FULL,
		0xBA12AB7445A554D8ULL,
		0xFA55CBA3283A2DCAULL,
		0x2CF1D49FF877DBA7ULL,
		0xCB51F3046FF3BA01ULL,
		0xC5A686E1466C9CB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98DA8347471A5595ULL,
		0x77D029BE07DC37E8ULL,
		0x6CB9F8BB9E4031BDULL,
		0x34D17B6108EC1AAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC77B7286B4C52C60ULL,
		0x26EB634D2A64B339ULL,
		0xABCD0725607F7AB1ULL,
		0xB7BE9CAEAE46A2FEULL,
		0xAB43F1ADB0B74435ULL,
		0xAB16621236DDD025ULL,
		0xCDE11E36B57A0A58ULL,
		0x598774B6E65DF9C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE72A13B6D27B5996ULL,
		0x46629F9BD4420DF3ULL,
		0x61D5262EF7E5202FULL,
		0x4240643A5BD3531AULL,
		0x8D85098A1598D74DULL,
		0xDD2E5688EF5FA01EULL,
		0xFAF46DB1C88312B7ULL,
		0x4BB39CF543D64BD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AA7D418E8CDFD99ULL,
		0x70FA7A11F2DDC654ULL,
		0x991A14B195431C60ULL,
		0x02F03F32729720E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61E4A9BDC8FAADD1ULL,
		0x6C3D786228756EE9ULL,
		0xBA7D57DC11D28FB1ULL,
		0xDAE001DBAB0F69D1ULL,
		0x2FBB26229CE000DEULL,
		0xD8DA214EA7091CFAULL,
		0xB2264D2DA20061CEULL,
		0xE6D9520D335455DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE884E5B4B023F50ULL,
		0xB99438207FAE45CFULL,
		0x67267E3E8E71D40EULL,
		0x29D5F1DA5C043869ULL,
		0xC28ED569B068F82AULL,
		0xF63F4E757CA9E2A1ULL,
		0x6BCF5030348CBB4FULL,
		0xB4813684B0C6E156ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7F056D597A3BA69ULL,
		0x55A48C7DF2E9D239ULL,
		0xC440673BC28B7278ULL,
		0x2A1E2644B00A7D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFFB90C53CDF74F1ULL,
		0x5343609EB99ECE0BULL,
		0x2B83DE83FE971F9FULL,
		0xC5A43E1028316A48ULL,
		0xC62FCF267AC9DB07ULL,
		0x68AD06B653800140ULL,
		0x1A97B0270A6221C3ULL,
		0x81EFD9651756C4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86EE894DF66BA7BULL,
		0x4F0E4D25C0C4E204ULL,
		0xB34D802456D81468ULL,
		0x137EF53BFB884277ULL,
		0x0F426394E306EFABULL,
		0x8EBA26F524637D77ULL,
		0x5A9AC0D8D1C23D62ULL,
		0x38AD0E421E19685AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ECA9FCCE467ABD3ULL,
		0x5E424A25F7157BF8ULL,
		0xF7C1E3FC0F7AF197ULL,
		0x120F70052BC4E170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB649601985F91CE9ULL,
		0x6ED8A9CC7319925CULL,
		0xC027F32640EA1607ULL,
		0xF47D4BF62696E9B7ULL,
		0xC35FE01E102E6450ULL,
		0x46C3267234D5C2BBULL,
		0xECA095AA552919BCULL,
		0x03C0F241811FDE9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EDF2541106ECABFULL,
		0x13BE39053DDA3A41ULL,
		0x22E35A5B49B41015ULL,
		0xBC833F1295D239CDULL,
		0x09EC15ED3FE785ABULL,
		0x4CB67D8492B26911ULL,
		0x9135CE828AB7C30EULL,
		0x4E8E4386DB78DB0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E9A3E17600F5D06ULL,
		0x78FB840D467EA773ULL,
		0x2F1E28B30408E3C5ULL,
		0x1D7FFC98278F36C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE43E4311272BC72FULL,
		0x4A79CBEA2C5639CEULL,
		0x884F2FCD76CB914DULL,
		0x8998B7D06EC5FF62ULL,
		0x1E5066B82C331A0DULL,
		0x6FCF5904EFF59843ULL,
		0x19180825EB997C1BULL,
		0x9D8A0F45579C03D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E2FC5E358A263FULL,
		0x0772CE93EA476822ULL,
		0xFF127BDC91ED00F7ULL,
		0xED500829AE1BD670ULL,
		0x89C5EB12294C08A9ULL,
		0xAF4879AEED2CD9C0ULL,
		0xF860C747453F7673ULL,
		0x350455B954C55499ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EE9A1575FEE3802ULL,
		0xD70C241AABDB190EULL,
		0x647054FD963B673CULL,
		0x20223A6F2C882B20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4631288FFCD28043ULL,
		0x8A439EED9D5C1E44ULL,
		0xAD25A27E7329F7B7ULL,
		0x42034C26A332B9E8ULL,
		0xEB7630A03C21B861ULL,
		0xA5954BC2E84A4FE7ULL,
		0x1688417DF92B1556ULL,
		0x7B2220C5A90A9C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C3DEA37C8BF81BULL,
		0xD5A1759E2F3D3629ULL,
		0x31A3E36F63B6CF3FULL,
		0x4FE94148B27CE5C8ULL,
		0x2BE671859BD88C42ULL,
		0x33EC5E6024CEC68FULL,
		0x77DB532537C671B8ULL,
		0x088BCAEC1D8A53D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BC3A7E04B231735ULL,
		0x93B565F872754B47ULL,
		0x092D203BC46371FCULL,
		0x746AC928A5C08FA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CA43B2BE2F071C2ULL,
		0x0A133DE9B4BB9FD7ULL,
		0xD423088B7C175F72ULL,
		0x2CF1F00A312F1D70ULL,
		0x8FF50C4B1644042DULL,
		0xA7A03EDB1154951BULL,
		0x8A154EF918D8010CULL,
		0xE958E60E824256EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E096DA4E2A78D7ULL,
		0x36B67924E30C2549ULL,
		0xFAF5AA57991A6672ULL,
		0xEB219DF406CB3F9CULL,
		0xD2619691A86F5AE6ULL,
		0xC57E1DC279A2CC98ULL,
		0x17E09E7ABDBA1942ULL,
		0x565E8C55F439A7C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09A71DD7E2571C93ULL,
		0x646DAE6B56133DF6ULL,
		0xCCFF90F5696D60F7ULL,
		0x12F9A37B3FADDE6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5955AEAF222D4C11ULL,
		0x04411CE3B3F0206BULL,
		0x5B1D119D318991AEULL,
		0xAE2764093B191BA3ULL,
		0x3B34757429820586ULL,
		0x6FEDEA5EB2D72F46ULL,
		0x0645C6778738FD5CULL,
		0x7FC3AD77E0C3D2D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA64127EC0E2FB33DULL,
		0x43A9F2AEC004B0D5ULL,
		0xAE6EC467668E1893ULL,
		0xDE60805EB3D384CDULL,
		0xA3A1D5916F2A01B2ULL,
		0x1780D1CE7B76C1E0ULL,
		0xDCDBF34BF57253E9ULL,
		0x6CEA62FE1791E286ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32D8426ABD0E2AABULL,
		0xE0C8CF9D2C3BACAAULL,
		0xD263A5AD6E78A039ULL,
		0x1C07F1BE64AF41B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x386FEB167849E145ULL,
		0xA88922D46E655CAEULL,
		0x254CC64134E29A59ULL,
		0x13AE72E8676F5441ULL,
		0xFA2F3CECE8DDDF8BULL,
		0x3717D7ACBE899D3FULL,
		0xD402FE102A20DE58ULL,
		0xB7EDBCB9261EFC86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC441338CB2A71063ULL,
		0xE71B3C37357B0A3FULL,
		0x50366D050A451A89ULL,
		0x93D91D4B96D520C3ULL,
		0x07E0EF6F0791D218ULL,
		0x46BDC2AF8B5A43E2ULL,
		0xB5FE7572C535315DULL,
		0x7A4E7772A7FD7601ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BCE383936ECD137ULL,
		0x6ECD0432D1F19660ULL,
		0x49C2A09925992D0FULL,
		0x25799E1389942B40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54C014316EFBCB94ULL,
		0x5F7947DBE04FDB83ULL,
		0x878779885BF9281AULL,
		0x2A0AF01E847A4354ULL,
		0x918A3C21949214ACULL,
		0xB41332BE36017A3BULL,
		0x76474418499DFBD5ULL,
		0x69936F50517DA1E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57C42849BE321EAEULL,
		0x26A732A6A454F0BEULL,
		0xC5A6CFD08C85BDD4ULL,
		0x885FB31BC2662076ULL,
		0x0E59FD63F4025CBEULL,
		0x833A463666C3791DULL,
		0x7BBD761C668760B5ULL,
		0x95A6E0726425DD9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76253C0D861EF930ULL,
		0x7905315DFF2F154CULL,
		0xF2553D1B84CE710DULL,
		0x16C871F3FD1B44CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98B1D227FEADE8F3ULL,
		0x4B38D9516D42045CULL,
		0xB5FF34FC871A0347ULL,
		0x74B8462CDC7C5266ULL,
		0xBAE948EEC136A702ULL,
		0x74942C0BDBE5A578ULL,
		0x08321F1BA38F0C6BULL,
		0x2563778324C67DF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B4D01141AFC5E8ULL,
		0x835EC4E29C74805AULL,
		0x3BAF99E52253D9DCULL,
		0x0E0349BA1CE10CC5ULL,
		0x54B74E4AC926D451ULL,
		0xF7B90A443C35119CULL,
		0x34115C3EAA2F022EULL,
		0x7F0BB3DDE155C632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F68366D8F576763ULL,
		0x50611810850376B9ULL,
		0xF72C87E46907AE65ULL,
		0x17BC06FAC2568CD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0B45DCA95C58BBDULL,
		0xD201865336631BDAULL,
		0xFA7516D16C5FAB6FULL,
		0x7F75EB3E07BB167AULL,
		0x07A538C4C87D2876ULL,
		0x24FEE2D2A93DA7D5ULL,
		0xFE00D8C578A3928AULL,
		0xA108E24341E02F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8DD4FE72A0F7751ULL,
		0xF5D653BE59D770B8ULL,
		0x4A5E1FC21F6B4AA2ULL,
		0x8E43412164C8FD53ULL,
		0x1CBFBAE9E4158F1CULL,
		0xD36AE5FF3D2C7C16ULL,
		0x0DF231C7B25A80CEULL,
		0xD9E3F6308073D061ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5E7BC615316D685ULL,
		0xF822B9F6E7182978ULL,
		0x5243C0BABBCD029AULL,
		0x00ADB4E55908387DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9768F11FEADB58A9ULL,
		0x8012DC1A3C24A0E9ULL,
		0xEC62BEC42A317F03ULL,
		0x93D957C7E20817DBULL,
		0x87D6AF30D6F39220ULL,
		0xE2758BF6A9BB7B2FULL,
		0xEF6F2D968765383DULL,
		0xE17DC70EF0A960D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF78B47E69FE1F0ULL,
		0xEC55AF1E3AEA7E1CULL,
		0x5E0EDE456901E0A7ULL,
		0x906B3A04BE4B9BDCULL,
		0xAF65D32F66331C97ULL,
		0x8C405B9B58EF0547ULL,
		0x42C9F54104C5338FULL,
		0x86E0D4FC7B57D52DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB320E0EC0CCEAFDULL,
		0x5FA25A89FF93A336ULL,
		0x2EDA3D3024F0503CULL,
		0x76BA0C808DD736E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84EBAC4A1ACAE0AEULL,
		0x922AEB5DA97BCD77ULL,
		0x897727A9F10BD6F7ULL,
		0xB7E5E4B0F306D370ULL,
		0x98FA3442A5088329ULL,
		0xE2072FCAA5A45483ULL,
		0xF0AE2D815512BB34ULL,
		0x57E7B300AD05E0E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7E35458658739EULL,
		0xE282CA180FAF07CCULL,
		0x337B5311EC5CAA31ULL,
		0x060E8E6D35B24674ULL,
		0x8E17BB1CB77000BCULL,
		0x65A02C8EB671FE39ULL,
		0xA1B680C78FE7D545ULL,
		0x2F954AFAFB822D6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB60B72A5D915CA35ULL,
		0x26F29C2B1B4594A8ULL,
		0x0EBF782B490D4E52ULL,
		0x2E12C71C16E1308CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40421ACDF5EE445FULL,
		0x2D2150FD1EC7280EULL,
		0x0F5CD181FA1E1A10ULL,
		0x5F30F50D97ADA551ULL,
		0x443E1C34D3608EEAULL,
		0xB59F4CE95B33A3ABULL,
		0xDCB75C3C0E02616CULL,
		0x9C355EFE830C2AC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CAC92BE7620CE7EULL,
		0xDF25D39A63243F52ULL,
		0x7CB5C09F59690979ULL,
		0xDCDDEC0744D2F284ULL,
		0x791A0B79EE27DA2AULL,
		0xC1FC5581DCBE35F5ULL,
		0x12EC7C297CA499DDULL,
		0x790983C05E02C153ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAF003CD86384B0CULL,
		0x782C36BF811131B7ULL,
		0x86C453A434A0AFCEULL,
		0x3AD5943FD240593EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EC189403E0DA374ULL,
		0x68008B8055BCACF5ULL,
		0x4BADBEF0110E655BULL,
		0x0DA652812D1DD567ULL,
		0xC4104C9076508EC7ULL,
		0xE5B908CF0DB20548ULL,
		0xF3D388053292C82AULL,
		0xDCB4B2F7E58BACE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F3965DCBB668ABULL,
		0xA19AEDBC3484F81EULL,
		0x93EEA9B17DF6F5B6ULL,
		0xC8A62CFDEA4A0130ULL,
		0x854221D9FC61ED39ULL,
		0x3142DAC579289C78ULL,
		0x7101375EE9A92FBEULL,
		0xF9FD3738A821801AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD6849F88BC3350CULL,
		0x8FF073302D9D43BFULL,
		0x22F70DED65C40FC7ULL,
		0x6C3C83E660967A20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x840DD5E53334E795ULL,
		0xF87528652DE7D073ULL,
		0x9C248F32F26AE1E9ULL,
		0xAB8C3C974B497F02ULL,
		0x354E97A023C25A17ULL,
		0xB1B191476A07B06DULL,
		0xEBD4D754D0170C3AULL,
		0x30CBAA53D8E44B19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A07E091FE96C14DULL,
		0x08E8FA0C82D57BD4ULL,
		0x909ECF1B3B2A6669ULL,
		0x42A91D66B32BDDAFULL,
		0x98D75F2C416F829FULL,
		0x5CCA541980D86D24ULL,
		0x8D7651BB00536AA1ULL,
		0xEBF39655879083CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B85686CCEA1E03ULL,
		0x89DF432948165166ULL,
		0x0D8D94EC8E4A7843ULL,
		0x20F616F0AA8D36A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54AEC362D13A5E30ULL,
		0xDF444809BC9BE994ULL,
		0x8346BAC4D91E4795ULL,
		0xFB5B0BBFD1C0AFA1ULL,
		0xE4E48A99E3885FB0ULL,
		0x520344B5A29DCD47ULL,
		0x54BD332AC2E59E11ULL,
		0x0E2D2206B3E78F62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F08659B602F4222ULL,
		0xC8D4648B4EDA6990ULL,
		0xFE4EDEFF9180BA9BULL,
		0x3CD37505107BC2ADULL,
		0xE6B3EA437538795FULL,
		0x2D25DA7C2E720B42ULL,
		0x64A6BF879615DB3AULL,
		0x7A19D8810ED15973ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0DE2A9BD0E749C7ULL,
		0x8F4DA805AC404CC1ULL,
		0x284D05FDEE7478E9ULL,
		0x396480914290EE6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20858A0B2D231705ULL,
		0xB8333950F566ABE7ULL,
		0x9452C39D37918537ULL,
		0x55EC3F57A8DA4A05ULL,
		0xA8215EC422454D54ULL,
		0xC4846905BACD8B04ULL,
		0x85CD146B45354B03ULL,
		0xCA275C32C32B5492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD44D488E9231E99ULL,
		0x7488E3D1078B36BFULL,
		0x1D6FB23EE3C7AF47ULL,
		0x9E5C54C6707BD4CCULL,
		0xB04A435AB5559C61ULL,
		0x7E60D11E73D7CA20ULL,
		0x6A2B8C07DD39390FULL,
		0x67F947A41F33F099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED2EC7286F943E92ULL,
		0xACF2E1D4765616FDULL,
		0x90DD501FC3348032ULL,
		0x4A66F7BD8F174C33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA6AA95C3DB44C6FULL,
		0x7B4DAE301BA05DD6ULL,
		0xFBC27F88FDBAF6AEULL,
		0x760ADFA6DF182069ULL,
		0xE2FF89BB80A2C7A6ULL,
		0xFA10C1EF34FBD91EULL,
		0x0560AB055C720D31ULL,
		0xE613D48804A95CCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF31E81A05FD9215EULL,
		0x8A49621225F75E97ULL,
		0x68A582B1E7F9BFA6ULL,
		0x14539AB668A5738BULL,
		0x2DFCE0311F978B94ULL,
		0x3CD88D67B588D79EULL,
		0x26ACCF3CBDD610A4ULL,
		0x8762E5E2A37EF4FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5B15246458617D1ULL,
		0x075C183AE0BB3859ULL,
		0xA1CF9C9EA0E8B412ULL,
		0x6FFAB17CE2BE1547ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9094EB6C49442AD5ULL,
		0x37D8C5C8CAB47561ULL,
		0xBF7B13809FC0D424ULL,
		0x12307AA5AE62F69AULL,
		0xA923585D2648549AULL,
		0x9FAC180B7A8AB7CAULL,
		0x1E5AEAE57D0EB0F0ULL,
		0xDFAC8FAC4160E45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC127FDA63452099ULL,
		0xE33A7E646F6FA09DULL,
		0x6FF4FAD36F9D2C95ULL,
		0xC05DCB42BFA2BE21ULL,
		0x4F328E481215BCACULL,
		0x24BC8421A9702747ULL,
		0x3607462AC232248EULL,
		0x55D09100ACBAE7D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE406AB2E5819A75ULL,
		0x942E3C1965364842ULL,
		0xCBF08C64ECE07E2CULL,
		0x487A7CDAFF63B4F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE859D8C2D053294BULL,
		0x8E92C5C9C6D99F82ULL,
		0x6D50AE161224606FULL,
		0x9C81B0E68098CF84ULL,
		0xBB3CC539364C08E9ULL,
		0xCF0FCBC7BA5CDC62ULL,
		0x172C7A962B2BB250ULL,
		0x9E115C421EE482E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7250E8C52B3C4FULL,
		0x01AF4F0008DA052BULL,
		0xE32DBE72FB1A88EBULL,
		0x28876FD154E98A95ULL,
		0xE7B56DC4EAA6C644ULL,
		0xD8CAB2FC0133853BULL,
		0xC833C41D55162EF2ULL,
		0x4B526F38EAF4E64CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EFE831D45AFD355ULL,
		0x1B2525073A228A1AULL,
		0x430E0592DE3B5777ULL,
		0x3C517072E140838AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD4DADDA2695C6F9ULL,
		0x381CD79F14658E68ULL,
		0x19D851AF05206403ULL,
		0xD87564309636B5FFULL,
		0xBAE5736E360A55F2ULL,
		0xE97FE90519B0F4A0ULL,
		0xA291EC6EB4A82601ULL,
		0x1F0918470B685E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8859545A9A857455ULL,
		0x3C567B0DC0232526ULL,
		0x7C339EBA1B96F15AULL,
		0x5BBA2D81F30B8F65ULL,
		0x7BFC7653504EB434ULL,
		0xC9825BBA493FE7FAULL,
		0xBA2866D66E406CD8ULL,
		0x8F82AD2F502962CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB89EB7DA5EA5265ULL,
		0xBB6955AC450A49EFULL,
		0x1D4E878F5CEEEEC3ULL,
		0x4AAF1C346E847A66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E19DECF9A0E722FULL,
		0x1BEAF09E03D06FC6ULL,
		0x61A8C17C33139CDAULL,
		0xF377300760F08ADDULL,
		0xD830E50BBFAFE99BULL,
		0x4D49F9A438F2F215ULL,
		0x32AD84EF4218BB9BULL,
		0x748E0E67FFE056C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0B489E9788B1E45ULL,
		0x8F3C069878C009EBULL,
		0x1C746F9C3D48D364ULL,
		0x753C486586E62B9DULL,
		0xA88C67194A30556FULL,
		0xFB96121F142C6135ULL,
		0x2A5B411F5D0151A8ULL,
		0x3A0904D91BDC780FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FD006E3927353C8ULL,
		0xAD6347C90089E721ULL,
		0x816A62BBF744836DULL,
		0x2DFA52D7B29D6EB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BD0D40DA27437E8ULL,
		0x93F5FDC53E3E6008ULL,
		0x8A51675DFCBBCF6BULL,
		0xC3CC7CDC5EF10C9AULL,
		0xAD0EC1171359D7FBULL,
		0x3B82972C5B75C2C3ULL,
		0xFAD71381C2245F0FULL,
		0xF1EC65E107A741A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8801F998F7FC79ULL,
		0x2F94D932A3243F73ULL,
		0xFBE2454CCDEDF079ULL,
		0xD037DC4BA83EFB62ULL,
		0x2E747FDDACFD2764ULL,
		0x9BBD4739A160EAFAULL,
		0x0299B7C2608AFC62ULL,
		0x2D63BF725E27F8FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA92E80993B3E7627ULL,
		0x1BAB029A3A32287DULL,
		0x678AC079AB928492ULL,
		0x1FDD54FDDF96DA00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF3496795B9142E3ULL,
		0x4FA3C58526338739ULL,
		0x7EA04D3481BF3406ULL,
		0x8FFD063F4FAB816FULL,
		0xF7A5824D263E8FB8ULL,
		0x44BB8FC664F1CBD4ULL,
		0x34B58F804A3AD5EBULL,
		0x1C122475CA02BF43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F2B3587B42F200ULL,
		0x7072707FABB5A2A0ULL,
		0x455F171E1228E41BULL,
		0x8CD0D95CCD8F7D8BULL,
		0x782F1AB7487D8868ULL,
		0xB0EA075A5147D510ULL,
		0x3173DCF7DEC8268DULL,
		0x4EAB5D05C0FA8494ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51D5435FCAF565A6ULL,
		0xD04B951065B885C4ULL,
		0xB501B656629C57CEULL,
		0x006DC783D954B9DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FC79EE1083993B2ULL,
		0x63A476F1F21258DAULL,
		0x460EDC2A8B4047E3ULL,
		0x07AFB85CA7F80783ULL,
		0xD3DAA3680FC2B3CCULL,
		0x15FEF0E79912F76EULL,
		0x2833D7C2F0C2753CULL,
		0xB397654C0372169FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A3E78E2D40BAAEBULL,
		0x7F0E968D4B552DE0ULL,
		0x68FD6B6EF6D457FFULL,
		0x4CCBEB1939F0893CULL,
		0xE2BD597D24963568ULL,
		0x5B45D069A623D2F1ULL,
		0xE8FCD8FAD5974458ULL,
		0xD98B2921336F8340ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE21EDD1CC8AABBULL,
		0x9C10B316B63C9585ULL,
		0x3F3B426F9CD531B1ULL,
		0x18B4BB9E4E695E44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6FE45BCAD8377C9ULL,
		0x598F627FF48F193BULL,
		0x717476840AB31252ULL,
		0x1A443130BEB9CDF3ULL,
		0x0EE1092D98859883ULL,
		0x854646438C813E9EULL,
		0x033202950CE3AE53ULL,
		0xD8DAC6A722EDAFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3170E99A8C45484ULL,
		0x018C0BDB549F149BULL,
		0x57A1B9AA5EC27067ULL,
		0x65FEB1D3CDB2BB4EULL,
		0xBFE3623F21A584FDULL,
		0xF1960F6D86740FBCULL,
		0xBD40EDC22C1A6243ULL,
		0x489BA8C178BDDE49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD8DFE88AA020C47ULL,
		0x442B7A6985E4FA11ULL,
		0x7B9BD42709D1EC3BULL,
		0x1DA3EF7434203153ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9705AE931ACB23ULL,
		0x007F954C98F97CF2ULL,
		0x8E6187DEC54F7A4AULL,
		0x807E054EAF591C25ULL,
		0x9137633CF1F7FBB4ULL,
		0x53DA95844EEF2DFDULL,
		0xAE5ADE551ADF354EULL,
		0xE139B5088692B510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD74F25470D5C1CCAULL,
		0x95735B62F5A4CFEDULL,
		0x73A0EF199133D30CULL,
		0xF07427BDDE2520ACULL,
		0x649D71956632A3D4ULL,
		0xA0264CBD447897B3ULL,
		0x41D8225EAF249364ULL,
		0x66C77217569666F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9221BF464509BC32ULL,
		0x17CF077530EEFC07ULL,
		0x36287F5931CFAFEEULL,
		0x3CFFCD5DF0A79423ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D8CDB8736705C18ULL,
		0x8047E83EF7D2BC5FULL,
		0x43285F452E973F79ULL,
		0xE853D749F60DB8D4ULL,
		0xC479CD338BEB9719ULL,
		0x07497561E4DBB12EULL,
		0x68F70F7AFBDA1ED1ULL,
		0xB1CA98F52BD70AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4A31C8CF3EF889ULL,
		0xC7A8721EE05DD2D4ULL,
		0x4C1948D47244A6DCULL,
		0x2F6B134B89CFEE23ULL,
		0xC36EDFB51BC5F424ULL,
		0x21AECF41C9B15814ULL,
		0xC8B5CC7BDE32346BULL,
		0x2B4FD79A8BCDE084ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25E1EA830CC796F8ULL,
		0xCD941EE41FBE2367ULL,
		0xC0BF084F233F63BCULL,
		0x2F2177722D9A0C6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F6A5F7D83D2947FULL,
		0x1E003EC1C588E0F7ULL,
		0xA1879FED77274A87ULL,
		0x4934F55FF6AAB71AULL,
		0x505BD8B6373000A9ULL,
		0x8884AC0A49443897ULL,
		0xF2A4D33AB1641B43ULL,
		0xF37EA4ED7E3B06B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC48E16FB4386FB96ULL,
		0x20971937CDC2ED9DULL,
		0xB73F0197D88D16C1ULL,
		0xBCFB93355F41057FULL,
		0x232EA0A232BD91F8ULL,
		0x65BBB05C12D87D2AULL,
		0xAC74F894DD3AADDFULL,
		0xEEE0B739B83047B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F929B7AE948072FULL,
		0x273E81660BC3C58EULL,
		0x556312F31CC070A3ULL,
		0x3BAAAAD9FD020BCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D110ED38A8C748BULL,
		0x475FF41E551038BAULL,
		0x887207EBBCF75B67ULL,
		0xFC12E54436FFBCD6ULL,
		0x4CFD91BE34D5E79FULL,
		0x9ADAB7B708D04FC9ULL,
		0x58E9075ADE841D21ULL,
		0x3A8CF5EA2054B4B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFAF5452D7E5B6A6ULL,
		0x229E29E4D78DC2BFULL,
		0xF63649DBA424107CULL,
		0x8901578CCA743592ULL,
		0xFEFCE37BB08A01B4ULL,
		0x79E33298117D4D6CULL,
		0xD15B650B4152DE72ULL,
		0x89221FE3F3B2039BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC17B986055EADD12ULL,
		0x097F8CD233D4CFADULL,
		0xB141D5E16E2298EAULL,
		0x48ED52A20CB1D0E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B3D8CC1891A0B4ULL,
		0x54DD70CAC9396CA1ULL,
		0x9668B5C12AF0A26BULL,
		0xEBED1D96915978B4ULL,
		0xE1CEAB01C1CA765CULL,
		0xAA21186097AF3CAEULL,
		0x9E43B9CD1E0AC356ULL,
		0xB47D493D1B6566DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3172AD209661A4CULL,
		0xF2CFFD30864FE580ULL,
		0x84374791A5F477E3ULL,
		0x44D69C51783D33C1ULL,
		0x7A371610EE38FCB0ULL,
		0x9DC52377A994FE21ULL,
		0xA5CE64E04C17A2A5ULL,
		0xA263C5EAE50A0857ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x071CC9B976C39662ULL,
		0x37B3CE2D9ACED01EULL,
		0xF39C0956AF1304CFULL,
		0x56DFFF792AAC4C63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C6BD52A1682D6A6ULL,
		0x33E9491C8AF9EC04ULL,
		0xE4CAE9A97A817997ULL,
		0xE3FA137D1D705733ULL,
		0x724E4735EA1CEA6BULL,
		0x56BC73CDFF913069ULL,
		0x57328CE158D3FD7FULL,
		0xA0A614B7CEE6D627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F6C52106BDCC4FULL,
		0xF4E1B55ABCA75353ULL,
		0x28400CB12872FD93ULL,
		0x44022AD39486CD4FULL,
		0xCA0FC3F92D341041ULL,
		0x1AA9E7D8C672CDB9ULL,
		0xDF781C6F7260AC82ULL,
		0x3E55BF9A89BED1A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FBC8B0D1A556ECDULL,
		0x29C85A2848D53EC4ULL,
		0x82378DE0872C819AULL,
		0x37E48B01CCDA34D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3891D6B255A7EA26ULL,
		0xC8F25C8D5FEA1B19ULL,
		0x6A6A235A7AEAE1E0ULL,
		0x1278AC7117DFD073ULL,
		0xB6852F5856BBCD61ULL,
		0x015D15C64CD76BEBULL,
		0x2B5468C2636EDFCEULL,
		0x3B3DBD564890DB77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736D83DDB3D3109CULL,
		0x18DF0C0E6455140DULL,
		0x6EBC284ABFBFE77EULL,
		0xD9966CDB11608A5DULL,
		0x4DEA914A188EF1ABULL,
		0x83B23AF62D02737CULL,
		0xC43195ADBE117132ULL,
		0x2D858BCE9F07F7EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C17C8F1DC7D76B4ULL,
		0x576FCB63B531E795ULL,
		0x4AD9502047096577ULL,
		0x423999B930D10C7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2053AF18B333D4EULL,
		0x7C3B954ECF054A02ULL,
		0x3CB1F5F838822F0EULL,
		0xBB57A49CF893911DULL,
		0xD1A14E02B3F75DF6ULL,
		0x4181FD0AF6DDA3A5ULL,
		0xEB0E0045BD6F6D6CULL,
		0x4EECD4A72FE8AAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x379B3457118AE71BULL,
		0x2310D069F998F155ULL,
		0x1BB1E3C9D02B5C43ULL,
		0xE2B42A170DB06B68ULL,
		0x78B5E57EE1C99A3AULL,
		0x45EE1AFC00DEADC2ULL,
		0xC018C03B6F6D4DF9ULL,
		0x55E5EAA0ACFBA4FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD5B8A2BAC7363E2ULL,
		0xB11E531D5944D86CULL,
		0x816793B5FCA77DDCULL,
		0x4FAA377D5A11FCABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056972B792F23AD5ULL,
		0x9C809F7CAFCC31CEULL,
		0xE271ED8C44EB0409ULL,
		0x43B9DC501F283803ULL,
		0x1737E293185A441CULL,
		0xD67D386627FEADF7ULL,
		0xD6BC11AAD323C816ULL,
		0x3F07D210B83284ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC939BCE09FA34DULL,
		0xFECA6DD455D93F54ULL,
		0xA1BBDB05A0C9872BULL,
		0x77D4C0914995B365ULL,
		0x031E932E177B6FDCULL,
		0xCB3AEA062A70421EULL,
		0x04192B3A1CBE8F4AULL,
		0x3DAF89D81899108AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x736201F8D36618F5ULL,
		0x498DD3E7FD16F4B2ULL,
		0x84E44741B727EB27ULL,
		0x7EFFD4268659C1A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2773FF380337FFF7ULL,
		0xABC3188F5940CDC6ULL,
		0x25F6E2380A63AAC0ULL,
		0x6B208E877170610CULL,
		0x2E6EB4C43F0F0878ULL,
		0x49FA38CD521CA306ULL,
		0x555F8332064E62ADULL,
		0x296E8227D97EAFFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6554E73A4860F27ULL,
		0x3997E0F246E25724ULL,
		0x136BC6EE2DA08AFDULL,
		0x8A012489936229DCULL,
		0x13FD5C021A9974D1ULL,
		0x35E3F9C1B035605DULL,
		0xA6D9F606215BABFAULL,
		0xBB07327873C1DB16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DF1DD95C825D856ULL,
		0x6D7893571AB25BBBULL,
		0xFA5E0FCDD8CA3E58ULL,
		0x44753E06F815D193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66FF4BA2A5C0DB55ULL,
		0x98B2D65FEF6D01AAULL,
		0x4A7C3AC1E41F9362ULL,
		0xA7E71D70EB7D92FEULL,
		0xE816A00FB6C56FE2ULL,
		0xD15B699CE8FE73F5ULL,
		0x8D7B35002869429DULL,
		0xB50666C0A3700270ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14C31A44D0D3840ULL,
		0x46B286137AFDF00EULL,
		0x0B68B791414DD61FULL,
		0xB723D3B389226B19ULL,
		0x682E2A5DC0770880ULL,
		0x70BFC0A6806352A1ULL,
		0x38429050D0E45DDAULL,
		0x258E7411CCC67D1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82349268E856FEBFULL,
		0xA91B64DFFB760426ULL,
		0xE57BF537A08BB243ULL,
		0x3C914FB13F84F21DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DA9CB688A2754A7ULL,
		0x8CDE87C25E26AA62ULL,
		0xD301B67EF8FF28D3ULL,
		0xA98D78CC85B13689ULL,
		0x4B9A0E7A63EDAC87ULL,
		0xBB872367E9BD686AULL,
		0x04AA7E7F73CDE90AULL,
		0x0A0C2E5C92F3AD80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C81FC8C2F2B8273ULL,
		0x368B195DEDEE36C6ULL,
		0x7684F7B3BA6DB323ULL,
		0xD2CA04A8E3D5EE22ULL,
		0x9B4DD2E036BC2230ULL,
		0x50E61D573D3AE5DAULL,
		0xC745BE566C63CCB5ULL,
		0xEAB70729B660447DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C78A7BF10565612ULL,
		0x2A3A54DE0B97D4F0ULL,
		0x797144E25851AA5EULL,
		0x7D6745B05FBCDEBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6256A5A3E2BDB79AULL,
		0x4008043DAC8118CEULL,
		0xAAA0FCB6DF7711B3ULL,
		0xBAB9BDCD4B770A98ULL,
		0x0101E72BB0C0D369ULL,
		0x0DCDD91E2858F3DBULL,
		0x5D85B718F4205EF2ULL,
		0x76BAD8C39EE6CBA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A5332DB3137183ULL,
		0x72590FCC4ED1B015ULL,
		0x55A976411FA114DCULL,
		0xF387401A7E67F8D1ULL,
		0x662A409713910A3EULL,
		0x227FEB5E05A912F2ULL,
		0xCDB20DAE3296B731ULL,
		0xB76E7A0332C221A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BB42C8584C220FDULL,
		0xBB403EF683CACB40ULL,
		0xAE62AC4E7A44E379ULL,
		0x2C888E42DA804EC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C468A17EACBB8D0ULL,
		0x9D0C7F1307486EA8ULL,
		0x17D58F011B0B1148ULL,
		0xB0BD610A038275E0ULL,
		0x412CAFFDB3274214ULL,
		0xF840638DB1C4F779ULL,
		0x63B3120A34A705D1ULL,
		0x3584AD93AEC8AC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00395E2EF6D4581ULL,
		0xFA9495E10435BA58ULL,
		0x60AA418B7E2A2A69ULL,
		0x43B33D0CF0E4B656ULL,
		0x20261B23CBB9FA20ULL,
		0x6280827DB94A1C88ULL,
		0x4406B73AEB75BF41ULL,
		0x02E11F3D83822131ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA33D0C8D559722A4ULL,
		0xDCF35190E54F341AULL,
		0x6AC0C83A7A316054ULL,
		0x715144C77F167170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AD7058E7F93C42AULL,
		0xEC2D1296C1AD5B81ULL,
		0x4C41FAC052566EF7ULL,
		0x0D5C5BAAF73DD3F8ULL,
		0x319114C7E2F30A77ULL,
		0x1958C9B03970C478ULL,
		0x647FD8266E3D8582ULL,
		0x085E963FE0145681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4756CB94D420916AULL,
		0xC9E61C8FBB375EAAULL,
		0x3F7F44954AAFD758ULL,
		0x144092616BC2A5F9ULL,
		0xA3F4C3E43B5F36F8ULL,
		0xE8FAA8B8A9C02578ULL,
		0x9230F1E1D557CE6DULL,
		0xA16E12C3522047ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18B43BC48B649430ULL,
		0x503FDAC65AAD96C6ULL,
		0x4478E459B9BFC49EULL,
		0x40CF4DC69DB56170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC360357853C41267ULL,
		0xCD294EB84DB15E97ULL,
		0x3A3C18A013694337ULL,
		0x0F836DE21446DF58ULL,
		0x4B63128EFFF655B9ULL,
		0x476D1DECAB8CCCA0ULL,
		0x85A1535530A80EF0ULL,
		0x86917AC9032FBCDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7749143FFEDFBBC7ULL,
		0x34F48A7C91CB593FULL,
		0x0BEAECCB0F463EF2ULL,
		0x8A4C0D5CE4F8B1C6ULL,
		0x1ACD9D755D1C514FULL,
		0xDE020BC19086C4A3ULL,
		0x8BBC2F4006F249CFULL,
		0x5E7E63D87A355B41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x824683068140FF1AULL,
		0x3E1976A1BECB34EDULL,
		0x465486F9351E4715ULL,
		0x780CC8398478AB05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E095C03024F0F1ULL,
		0xFC2EB4796330E2D4ULL,
		0xCD692C735FB2649BULL,
		0x3BDCC10B69BC18FAULL,
		0x73882863CF4327FCULL,
		0x19FA63E5BD0CAB2EULL,
		0xC9E10E80890B1FAFULL,
		0x47502C60BC340262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x257F8FADBCDA8A89ULL,
		0x5056552EA981A523ULL,
		0xB5BEA3F106B7A74CULL,
		0x87DD1BF01D510B23ULL,
		0xB812F27494A251CEULL,
		0xBDB292A0F2C6CDCCULL,
		0x9669AAA29FA6B702ULL,
		0x71E328F561E15470ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73C70795272A3032ULL,
		0x5E816F80C00E1A33ULL,
		0xBB635B72FDE246E5ULL,
		0x622E270AB4B0DFCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F28394A4A9E11ECULL,
		0x60C09E1D7E6BD89BULL,
		0x800085051EC0E6C9ULL,
		0xE6C9B665DEE8A2FDULL,
		0x6A7E225E1E4955DBULL,
		0xE8FC1D334A186BBFULL,
		0x83531BCBDFE0982EULL,
		0x27F731ED4C6A350EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A43F6AF636A35BULL,
		0x64E16C622555A491ULL,
		0x458100E69D46D57BULL,
		0x239E4EFC473DC222ULL,
		0x705B755241508B50ULL,
		0xDC8D6A38C358D061ULL,
		0x5B0A5F9AD6F49A8CULL,
		0x7AF435A3B459C842ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86A9A9A221557D6BULL,
		0xD44DC2EB598743FCULL,
		0x354B7365D481B75BULL,
		0x719CDA562A1B0729ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9E453C52ADE8281ULL,
		0x741F4E8C4B75AFC1ULL,
		0x40616B1ACED3135EULL,
		0x692F23C19AC683D8ULL,
		0xE00EAE1AFDA4ACF7ULL,
		0x893C96A4D423A8FBULL,
		0x55C4C479526ABD6DULL,
		0x9B21A06CFA98CC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE430263C4188A4BFULL,
		0x0F18EAC9B85EBDC6ULL,
		0x5D080BD8030DC643ULL,
		0x2A7560F4EC1EA921ULL,
		0xD3E2017072D376ACULL,
		0xB8A07A8B412A8210ULL,
		0x1A3C4F7E6BDF0EE1ULL,
		0x6236FD3A1880A60FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD455CED98463EE27ULL,
		0x5C328F8E6412B8DEULL,
		0xB99ABC81048135DCULL,
		0x318DFC5A3E3D862BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1005557395DEF797ULL,
		0x05BE3D38994F720BULL,
		0xF72597FFB2738242ULL,
		0xDDB2F248C1FB8C5EULL,
		0xECC8C96E8CA20215ULL,
		0x95469FEA28FAC0D9ULL,
		0x8D7F232109EDA0D9ULL,
		0x22A990AB80DCEBA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42E883528898457ULL,
		0x8AAD6B690D717858ULL,
		0x878E90325B6B3FB4ULL,
		0xA5555C8C43FA654CULL,
		0x4DD37A9F9E214E12ULL,
		0x80CD3E1C1A19B30DULL,
		0xEAEA9B317B40B8A5ULL,
		0x1317F5DFC31F916CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4407FF5D4702C11ULL,
		0x85155665C1460611ULL,
		0x91A3355C84B2BA48ULL,
		0x07FA8FFAA81C8ABCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3986AE7B65A08AE0ULL,
		0x94E20CFA7308F985ULL,
		0x33DC5416A782995EULL,
		0xD62BBE657F93F72DULL,
		0x9E20CDD76FFD09D2ULL,
		0x0729EF48D79CB2D1ULL,
		0x2F1ABC64C4574AFEULL,
		0x19B647578F577752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C76596FA37E674BULL,
		0x520410FCC8DB8A5AULL,
		0x68D1C343FD7329F0ULL,
		0x63807A7B968DD840ULL,
		0x522F5EE8F6226636ULL,
		0x6A8DEBBEA6F4678DULL,
		0xCCFB4102EB84D2A8ULL,
		0x8C8647D70C3B1719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72E6CC71D8966A37ULL,
		0x82068280E3289B4EULL,
		0x5BB6E158D94D4C23ULL,
		0x67CB30FD5F3C674BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5FEDD0FEAF84441ULL,
		0xAB1D4826B58FBB55ULL,
		0x8DFCBABD17BDCFBDULL,
		0xB4366E0CBC368E98ULL,
		0x3D649D1B4C05D4E6ULL,
		0x370367382D7378B4ULL,
		0x77FB0B21BB230989ULL,
		0x5A8B07635BCA92B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C54B3FDBAC0108ULL,
		0x916A7A1FE04CC0DBULL,
		0x93FC3DC01793B02AULL,
		0xFE24858812081D7DULL,
		0x358443C2BC477F42ULL,
		0x613EAA24D378CC7AULL,
		0xF24BD3460A670FC0ULL,
		0x0473F25FC1ABE275ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF086D4F5658CFB59ULL,
		0xD4E6DEE630788B17ULL,
		0xD202C7993C113362ULL,
		0x7D7F070D8ABC9B20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8520F077A54795DULL,
		0xD46D4E3514E9F3ABULL,
		0xD9E72E5CE7E66B3CULL,
		0xA448D59471314A32ULL,
		0xDD9A61A82E1171DFULL,
		0xF872C8196C27385BULL,
		0x9FF299E291DED8ECULL,
		0x67F63833311F4670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59D0C11F82D146CBULL,
		0x1EEFF82FAD3907CEULL,
		0xB804F3B8690A89DDULL,
		0xF0F909816BD035DCULL,
		0xD8AFC56D9003DE78ULL,
		0xEA6449D1F3993BE9ULL,
		0x48AEA4B9B226B2B6ULL,
		0x1775F9C176662C3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09547E9B6D871591ULL,
		0xCBA414A14CC464CAULL,
		0x15F89EB5B4318D65ULL,
		0x265910F4BCDAF81BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3CED391ED42182AULL,
		0xC021AD0AD27EF5F0ULL,
		0xB65BB5C9EB2EB1D8ULL,
		0xFA003EBC21189D9BULL,
		0xF9D321F1D08BA120ULL,
		0x2C1171BBBA089A47ULL,
		0xE30ADED434A8E445ULL,
		0xE5C0269C9F16C102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684C54828CBAC886ULL,
		0xAEE5CFADA19C2F24ULL,
		0xC0D8FCCDF53FC750ULL,
		0x1D145E7AD1B99FA3ULL,
		0xFA1DCF1282226E66ULL,
		0x29BDFCAAF9627062ULL,
		0x72347D31151BF611ULL,
		0x711D70AF9443F704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x706CCC350424D9ECULL,
		0x699F3DD9C98CFECAULL,
		0xB5553732A4DA4640ULL,
		0x2D12E170EAA8F9BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA72AA30B54A8E190ULL,
		0xF39CE02A85C360B5ULL,
		0x75063D271D0176C7ULL,
		0x9AA1E9CEFC08A69DULL,
		0x9113CA21D02BC548ULL,
		0x3B4D390303F5D9E0ULL,
		0xE89FEB9D4C6749D1ULL,
		0x26508E41183B8B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1C710F13AD0DCB3ULL,
		0x89ACB7AF8262C3FBULL,
		0xA6AC9598D28A8065ULL,
		0x58DE60227EF63FE6ULL,
		0x3641CDB230DA8CAAULL,
		0x3344C7F95D987ACCULL,
		0x9EE6D041BF71634EULL,
		0xF9A80FAB1521639CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808F0AABBFE667A4ULL,
		0x9B30EFE9B53CB9BFULL,
		0xBFD3B72536F72DD5ULL,
		0x62C653F0F2F4485BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4343827082461AE7ULL,
		0x7FA178905BEEE154ULL,
		0xE85A3FF4C57386B9ULL,
		0x81D599505D6FD8B0ULL,
		0x0AC325C2519ACB59ULL,
		0xE7672383D207A132ULL,
		0xCAEB73E46494D6A4ULL,
		0x8F5A0446CC6F7E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x588FFA75CCC32BF3ULL,
		0x9A0BB972A6EE9407ULL,
		0x8638399D0A20A411ULL,
		0x5E14F9EB0667A521ULL,
		0x250DC7C3DA6EB73DULL,
		0x62C1746273606D70ULL,
		0x1A0C84B0C90D1300ULL,
		0xE2B4AA8F5B3ADFE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x039F7BC0660DE941ULL,
		0x962DBE11C1D1FC15ULL,
		0xA3398800D179ED13ULL,
		0x444BF0A024D7B46DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDA455CAD3E9F308ULL,
		0x7008FBA307589874ULL,
		0x7A53F9C7107215DCULL,
		0x2C236B5B6E92272CULL,
		0x777245ABBDEB1D1DULL,
		0x54CDB6D56632006CULL,
		0xF7C0160110D82C7AULL,
		0xBF86620215C5765DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBB3CC1331799118ULL,
		0x5F09C0A069818208ULL,
		0x198EC6BB6F717688ULL,
		0x6C50EA3F342B64E5ULL,
		0x2EFAB5850593C049ULL,
		0xC753D495C9703CF9ULL,
		0x025664FBE4A76C01ULL,
		0x3EB6716DBD11C2ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3AFEF76FF682C27ULL,
		0x1116D073E29A1988ULL,
		0xCE7579D0303D3139ULL,
		0x5EB0372165136EB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08B5A8DF321EA8DDULL,
		0x9B373121BC136E41ULL,
		0x5654109974E0F3B9ULL,
		0x3AD9AA65CD5BEA00ULL,
		0xD973D52F7FE8CE72ULL,
		0xE5845D94D63FFA63ULL,
		0xD0EDD0A6999E4C2FULL,
		0xEF2BA21C9CC5621FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7331BD5C60089A5FULL,
		0xF5DF94BA694EC70EULL,
		0x09F220FDA3ED0948ULL,
		0xC811D064B197E3C7ULL,
		0xA54553FF15BF7A37ULL,
		0x9B74B68C2798B1C1ULL,
		0x5BB1D10648F7BE55ULL,
		0x8EB68B986707873DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x546B18B294389141ULL,
		0xA3AA67B13F996F46ULL,
		0xB349E167C9ACF8D7ULL,
		0x442931A115F283D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B9D8761F8F325AEULL,
		0xF83D267587ADA0E7ULL,
		0xBC6529AFBC5C9F5BULL,
		0x57DA6A253CC45A62ULL,
		0x82F350A1B6FBA5C8ULL,
		0x0AE1B82D9D21382DULL,
		0xC89936D10BF8DDEBULL,
		0xBBD16FE13A18ABE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78BA476734C3D99DULL,
		0x8C33D4C3DCBF8211ULL,
		0x7DE28D18EC02A9A5ULL,
		0xFEF0456F9514D5AEULL,
		0x420E12FC4DABF573ULL,
		0xAF2AD2CF1537A6D5ULL,
		0x1945FA65809A9CF7ULL,
		0xD5E52AA32A2EE1DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64EA6688660377F1ULL,
		0x092F5DB9D799B1EFULL,
		0x44DD948D805799D6ULL,
		0x79FC6BEC04638224ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF577E90CDB9DCA09ULL,
		0x9A8944E06CF0CFBDULL,
		0x68D3AB279DCD3B33ULL,
		0x0070036B6AE2179BULL,
		0x09A23377CD2E9A50ULL,
		0x1325C6441BBAD93DULL,
		0xEF8E82C205670106ULL,
		0x0F17AF0CCCC09260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C20350E6E0829D2ULL,
		0xF06DB61603D4B08BULL,
		0xFA2A3B132DA1DDACULL,
		0xBD24293F7D2BAF93ULL,
		0x5ED2B9B0B17A692BULL,
		0x57444A2A5E21291BULL,
		0x128DEAB3FB408670ULL,
		0xFAF255C2AEC2E831ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2423C78C8A54E65DULL,
		0x8D93FA9C8DEC4432ULL,
		0x3CC00229F1E18FC0ULL,
		0x40D71B2C615DAB22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x510EDEFE966FCA32ULL,
		0x3D4A0B4707E1FBFBULL,
		0x2D699ADDD30AF5C5ULL,
		0xC6B223B14D5E4DA8ULL,
		0x0002F5888181B594ULL,
		0xCA8BCB917D5A2427ULL,
		0xE53F5614BA586E33ULL,
		0x696A41A2F49FF0E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB581B6D8833E7D2ULL,
		0x3E745643DAB5B332ULL,
		0x9F65F228AA0E5D84ULL,
		0xAE73C3F43C524B97ULL,
		0x8AF1D47AB7A2CA5DULL,
		0x7547204A3024B275ULL,
		0x40B4D7894FCFA88CULL,
		0xCA9F9C25474B31F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF641AB9D0552CA63ULL,
		0xA7072198A31B291FULL,
		0xFA927166F949EF17ULL,
		0x2A52F064CBA05AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x411B89CC95EA0B59ULL,
		0x9617A6AA33B5F7BAULL,
		0xD3EB5EDDFC891123ULL,
		0x41A7E6A87BAA0BE3ULL,
		0xAF12E21131C4FACEULL,
		0xED1CBDDA8D11B115ULL,
		0x6BF6AE5256FA7DD8ULL,
		0x9B0ED6D174ADD539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0595B96EE75BFB77ULL,
		0xF93DB3B6F99E4B24ULL,
		0xC7D5BABD21EA5E75ULL,
		0xD05B5E74801FD1FBULL,
		0x9AC12B4DABDBC8F9ULL,
		0xD1312CE42B847DCBULL,
		0x26D2E31FA228D19DULL,
		0xD933A5BDCB2F375CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FA6F1638F2B7404ULL,
		0xC1D17785B50D4995ULL,
		0x4F65CDA7B1BE4373ULL,
		0x37D5D11F2455A8C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66DE33BA3D8F0659ULL,
		0xEB93C408C55708F0ULL,
		0x3AF28FFEEE40A52CULL,
		0x92C520B93B031E4CULL,
		0xD610C2EA2DC0475CULL,
		0xB04ECBE65DE5DAB5ULL,
		0x8A6710AB7BE81669ULL,
		0xF386FF98027C4529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9951C74B9BEB17BULL,
		0xCE211547655DD3A6ULL,
		0x1DB7C051E1E5F91CULL,
		0xEA93EB5AF25E6CB5ULL,
		0x7DB796519EF90DF6ULL,
		0x1D8B3EB8160B8062ULL,
		0x6FF2B50ACF2F41B8ULL,
		0xF9EDB495D3C8E190ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A85B5EAB562D9C9ULL,
		0xE679A3A00A629DA8ULL,
		0x0A806986AFCA3E6BULL,
		0x34F257B137457A51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF91F5F82B64AD099ULL,
		0x1A14834641425399ULL,
		0x1ECE37AFF4D4EE4FULL,
		0x3BE5CADEE66B30CBULL,
		0xF1CB2D17CE8095E6ULL,
		0x6A448F38FBF3D3C8ULL,
		0x595F5B1FA71ADB25ULL,
		0x85D2955FF69E50C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1471BB45EC7FF5B3ULL,
		0x5880AED78A206BACULL,
		0xCC7071AF5402B25EULL,
		0xE37709658098C67AULL,
		0xABA82F17AAB3BBACULL,
		0xB3BE0384E32802DBULL,
		0xF55925B1BE691D7DULL,
		0x08DF1DAE6B4B68CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DDF58421A33421BULL,
		0xD98C912A6562EB26ULL,
		0x2B49B4512B3462D5ULL,
		0x649285D41420D897ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBD48BA795C8C935ULL,
		0xBC953546202D8979ULL,
		0xC9D799BD7CD840E1ULL,
		0x0C0B8D1D6F233BDCULL,
		0x29B994BC161FC40EULL,
		0xBEF54FA94A7DDE8FULL,
		0x35B95719D7D51039ULL,
		0x37014143801AA8F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8FC40659365AA94ULL,
		0x2E12A62628D95199ULL,
		0x165850E616E953B4ULL,
		0x188503B0D553FE51ULL,
		0x4DA64A634C197165ULL,
		0xAA08B57E8367BC2BULL,
		0xD63F83EBC60F0A3AULL,
		0x52A3B3B1E43F7DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDB5546FFF53630CULL,
		0xA9A17179849D52B2ULL,
		0xDF94A1AE0953D10AULL,
		0x59698D09BC57AB07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31FE882C4C360951ULL,
		0xF91586CF6DFC80AAULL,
		0x05502D6D4B591541ULL,
		0x44CA827A1E7059C1ULL,
		0x07D0D12F23CF676FULL,
		0x42DB5570FB416F63ULL,
		0xF285256B8CD9C975ULL,
		0x94E4B8502417B873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D29126E67756376ULL,
		0x1748404DD1BFB90AULL,
		0x7D4CAE67568B7E76ULL,
		0x20B5CCD7904D1C6BULL,
		0x393450991C0E8F63ULL,
		0x451AE5A0716EC5CCULL,
		0x687ED6F01E5772DFULL,
		0xCBA5446EDD2A68DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70108C030B60B673ULL,
		0x8C5DDF761181F402ULL,
		0x04F325585C26710FULL,
		0x037FE913155D0DD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD79C69D3002603C4ULL,
		0x4F4E240D5D0244C7ULL,
		0x81989A553E7FB901ULL,
		0xADE2E1827FAB1422ULL,
		0xF1243494D1F3221EULL,
		0xDA35CF23E83A169FULL,
		0xAF50520334B0B7AFULL,
		0xF46F99681EEA8B78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155D27C79EB57285ULL,
		0xC4440FBD6C4EDD8CULL,
		0x94D1AE29FA8EE62EULL,
		0xEB8575412A4E12B5ULL,
		0xA021C80DCBB73B54ULL,
		0x874A938549CC93CAULL,
		0x1A06FB515933954EULL,
		0x9C84E56A5C31D0FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC89B5E164E54D516ULL,
		0xD9F4EDDB74F4D2E5ULL,
		0x15A9CA91D883ED44ULL,
		0x4F3423EC3CC8AF79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26ECB891960DADD2ULL,
		0xAEAB60DF974975C8ULL,
		0x0E66492C7B20E87FULL,
		0x0081CDA546DEC726ULL,
		0xCC38C52336DF7992ULL,
		0x685261715FBACFBEULL,
		0xFDD476E7EB866A8CULL,
		0x39D0074A88B68B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x680A4C43967DC653ULL,
		0xA8A24703F3958E18ULL,
		0x616EB730B43AE5B4ULL,
		0x9E16A984F711985FULL,
		0xD712363757497A26ULL,
		0x3958E0D878ADB4F6ULL,
		0x4B31CC0378BC1524ULL,
		0x380EFA5210510614ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x229BA3512FD3D174ULL,
		0xFF12308DEFA5E15EULL,
		0x311CEFE4D0EEB041ULL,
		0x251311022EDEEC6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A7FEA5D2B3D5BBAULL,
		0x2DF33356B3709719ULL,
		0x4653AA50BDE99C3DULL,
		0x8B76BDD0BAB0F5BEULL,
		0x90DB6C9211A2148BULL,
		0xED7197219987F231ULL,
		0xF4B703E2F2AD588FULL,
		0xC39509F3B5D294F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8801817718A846BCULL,
		0x022AF58D1F06DC38ULL,
		0xC2C193E3CCFF86E6ULL,
		0xF0B9C2B66155BE3EULL,
		0xC9B1BF23CC1B0129ULL,
		0xE67D2241113E3FB0ULL,
		0xDBBD61CE7C2C5A00ULL,
		0xB95B2D3B4157E4BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12AE274464A1F5B0ULL,
		0x3411971DCF5A39FEULL,
		0x38A02576880FDE92ULL,
		0x1F53BE7BA3915F61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6284E1B4D228C13EULL,
		0xE4F1FD3136074A11ULL,
		0x1C4E68EF529D3202ULL,
		0x4F365D3CF39AF9EFULL,
		0x0F478958EEE956CDULL,
		0x805502437F6F684DULL,
		0x00A255F172322EAEULL,
		0xC0B7C433C5316AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77068E5D1C4861ADULL,
		0xCB350D4FA69A5BF7ULL,
		0xA499D2BA6A4108B1ULL,
		0xC4025033A7604669ULL,
		0x3AFD508604C086E3ULL,
		0x0D20CC35A6452FAEULL,
		0xFCC6C41B2E7D64BBULL,
		0x14A8E0DAE18C6DA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E82C2A677EF4003ULL,
		0x337CF5EFCBB155ADULL,
		0x0A4C3C02F5322374ULL,
		0x1569CC3B16B843C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA10E3817A317B78AULL,
		0x094A5D0FA6654940ULL,
		0xD2C90403DC8712D6ULL,
		0x6922896DA0A89864ULL,
		0xB50F0F0A6F13B629ULL,
		0x6A68F8B88A19AE26ULL,
		0x81ACB7DD60B4681FULL,
		0x4619C1DA577D5AC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB4B092D28BC29BULL,
		0xC548DB1E55640842ULL,
		0xABBE764180427761ULL,
		0x5D510A394D8C3F1DULL,
		0x63893F4A733DD294ULL,
		0xAD258CE0BC5897D2ULL,
		0x11354CB965275752ULL,
		0xA0DF59E1E65BCE5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D365E04324BBB0CULL,
		0x5C0383F9DBAA9182ULL,
		0xD8C47519B33519D8ULL,
		0x127CEE151E1730A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4F0D60DBBFD0356ULL,
		0x574787B8377ED96DULL,
		0xABD92FF20DE20E3CULL,
		0xAF37E8F34DB5744EULL,
		0xA30B88CDEFF86AEEULL,
		0x5225F2A504FB3B9DULL,
		0x83D2F5629B8CEF92ULL,
		0x9AD7409D5A2CFFFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEE589085F443BEFULL,
		0xC1B85348F26C840FULL,
		0x0B1CEFD76E0B01C3ULL,
		0xD1AFEB88DBEA11D2ULL,
		0x408C1E0F4BEB8824ULL,
		0x5B200E26EA1D6554ULL,
		0x8D2F37621AB00529ULL,
		0x4622A4CE790AE0D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4F52551B6A2732BULL,
		0x406F1F2742002442ULL,
		0x3D0A742DC0A1D80DULL,
		0x70571E1FDCDC01F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D91F98357B7B0FCULL,
		0x4B76048E9DC4CFEBULL,
		0x2216CCC470756F9BULL,
		0x2F79383C569BAF7AULL,
		0x7A7A77CD5CF69327ULL,
		0x3D2B0209697F35FAULL,
		0x934CF1BBC6CC4BE8ULL,
		0xB52B5F7D84569FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5C18171E7980D1DULL,
		0x72144767ED09FD63ULL,
		0xFA36AC465264311BULL,
		0x1A26E75C2F4D4352ULL,
		0x1D40740AE60E4635ULL,
		0xF231B99B025DA1BBULL,
		0x3F3CB4FB504C3C4CULL,
		0xB08844BCE1566F0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E6D06EF169B0FDEULL,
		0xFA627D89FFB6D3EFULL,
		0xA249250FB5138F8CULL,
		0x458849785955AB39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD823CFB68C6ECCFCULL,
		0x255ED255A97D7E9BULL,
		0x39420C386DAE3DE2ULL,
		0x318DA40AB28B5A23ULL,
		0x03C420A4D3833359ULL,
		0x530C5B83F8251ED1ULL,
		0x1C3912DC5A8496EBULL,
		0x6D3F225863996F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E258FA059D0EFCAULL,
		0x3A4CA2B8FA253095ULL,
		0x5A920C7D68173126ULL,
		0x266B7936C8F067EAULL,
		0xB00C68A20FFB4691ULL,
		0x88B163B8D51F950FULL,
		0xE26612FACE3D829EULL,
		0x463ADA4F84F8508AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA743907F38CB03B3ULL,
		0xF492F7C3E22AC0B8ULL,
		0x7401FB35D8241021ULL,
		0x55C4DC24F5858087ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FE0D17A3EC89B6BULL,
		0xEF81F8121FD42B15ULL,
		0xFAEE4A4C79C4DD82ULL,
		0x26D09A4D4949476DULL,
		0x8478A9DA29A97D07ULL,
		0x809E0382FA19DE97ULL,
		0xAD98A01535C7FCA0ULL,
		0x7C6A4FCC64AE2AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650F572198E58EFBULL,
		0xEAD28E837714FB47ULL,
		0xA0F025F470D73005ULL,
		0x2810C0E1AAE42709ULL,
		0x69D639F76A5CAF8CULL,
		0x7B8683DCB4633AB4ULL,
		0xBB096B89A12D0BDEULL,
		0x9137B3E79649BCD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EEE16010B498C2DULL,
		0xC62C5C3D01DB8384ULL,
		0x5B3FF11017ED6A49ULL,
		0x6842FD62414D783EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x902EC09C091EEA6AULL,
		0x31290A338C95648CULL,
		0x38D74BACCA35F286ULL,
		0x310796556B159911ULL,
		0x7E28944CD6D74931ULL,
		0xE8EB1FF157EFDD56ULL,
		0x40F9C939A43ED93BULL,
		0xA51DD21A1D43EABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFBB6370D115331BULL,
		0xFA2106FE17890764ULL,
		0xF2F5D90017C421EFULL,
		0x84D3341E7C68BBBDULL,
		0x2FFED9648C2044E9ULL,
		0x167C32967F86490AULL,
		0x4D5A0D76177FC128ULL,
		0x5DF3CD54ADD39BD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AA51BA64F345B7BULL,
		0x737F3EB194B8607BULL,
		0x6F9751B396CF6387ULL,
		0x3C7117857958940DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC722C45D65B1AAF2ULL,
		0x468F07BDECA78B75ULL,
		0xB27653735C586F26ULL,
		0xD9624C62BBB9FAB6ULL,
		0xD001FF1B695AD33EULL,
		0xAC22A4EB8C37EF1CULL,
		0x83E5D99BB22A58FDULL,
		0xEFD94F7959AC3B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2E481814AEB90BULL,
		0xBB2A3F754F0AC063ULL,
		0xABC0E18A52BA11FDULL,
		0xA4B533C828822642ULL,
		0xA1FCD9382CCC7DD6ULL,
		0x210A7FFCB3FD62F6ULL,
		0x70E12459B009507CULL,
		0x2DD3C5778162564EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB81C004E23A3A5ULL,
		0x30FA43BCB64D98BDULL,
		0xD96859B55A85A063ULL,
		0x017F94E0AE2FD4B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8413BA64C1D5AADEULL,
		0xE31AAED90DCC6325ULL,
		0x986CC99393C8F0EFULL,
		0x1F591CC43B7AB8B3ULL,
		0xF817FB98E79F48C8ULL,
		0x1CC264E9FDACD026ULL,
		0xA60D575D0D086F37ULL,
		0x07A44DDBA18CB31BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7282D23DEA39087BULL,
		0xA21B42D0C9D6A7DDULL,
		0xE2427BE236F30898ULL,
		0x00D08EFE59539731ULL,
		0x2A07D00D634AD932ULL,
		0x6B710B04512ED12CULL,
		0x3FF3488159A0AE7BULL,
		0x50486C56D2C856D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7F75EDC7C253105ULL,
		0x9312C41FDEA99482ULL,
		0xDE08824DFE3C8433ULL,
		0x562C077C934CD48CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60E178ECD5EA216AULL,
		0xDD755AE64117CBB4ULL,
		0x7DA4AB6EAC3E4447ULL,
		0x8C0C2C42F9418590ULL,
		0x072D066DFE94D317ULL,
		0x02ACCEDA0109DEBEULL,
		0xE1430219E59E6A72ULL,
		0x710912C42B3EC2C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D35608F0CD37CDULL,
		0xC9A0807641C3D7F9ULL,
		0x8A50211826781766ULL,
		0xE56A135639DD112AULL,
		0xC376F99598876337ULL,
		0x138D2BD2DC2408ECULL,
		0x40C69E035DF92D82ULL,
		0xEFB8354333B6076EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D140B030B1B81F8ULL,
		0x92870D7F7971B0CBULL,
		0xC5CB65AEA84D387EULL,
		0x58A2FA117DB043B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x901A4A6B2AEBD559ULL,
		0xF5F1974653B090A5ULL,
		0x74D53983A1209C23ULL,
		0xC64D1DEF1CA90FC2ULL,
		0x9A7AD28210DC9674ULL,
		0x12DB21B53BAD4E34ULL,
		0xB411F668D5957A77ULL,
		0x3061C9D7E0855D5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6539BD442CB788DULL,
		0xC663D1697B1B4BBBULL,
		0x1259F008A9ABDE21ULL,
		0xD22673B82E4FA976ULL,
		0x1AE9FA8A2B20578EULL,
		0x558C968E028D712FULL,
		0x695ED9155A19A6B1ULL,
		0x050F6B3A80BD218DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC946BD630211B3D4ULL,
		0x49366DAF535013BAULL,
		0x7911A3DF4BD62D5CULL,
		0x6260B59326124737ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A41DEC6F16B043AULL,
		0x1A3F66622842EEA8ULL,
		0x1933A540521A8EC9ULL,
		0x1AE21EAB34DD3A01ULL,
		0x5321F53EAA7BE215ULL,
		0xBF0C5D4C886FA576ULL,
		0x8350B8DDBE00D04EULL,
		0xB33C461DE89182A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E24EC38C86E8B8CULL,
		0xEC8E75DD7A5A5A9FULL,
		0x98F797ACC084D192ULL,
		0x9437ADF85907514AULL,
		0x78DB63C15C13E93EULL,
		0xA15D408B00E0369AULL,
		0x01A895E273A1DE97ULL,
		0x179788ADDECA0AAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52968B27CC6B6BEFULL,
		0x95AF353ECD3308ABULL,
		0xBF313EE09BAD9E64ULL,
		0x211E8F544F71B74DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7360F244EFDEED51ULL,
		0xEBF4A4E33B358AF9ULL,
		0x85C15D27A528726CULL,
		0xA7C03AC402766EDEULL,
		0x24DB2F1C1FA1A8A1ULL,
		0x47DA7FD05E722031ULL,
		0xAA630D8289CBD723ULL,
		0x7251F0111283B2BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAEFCFCBBFB4482ULL,
		0xD34D2B06492084E8ULL,
		0x03BB9A63FE01B48AULL,
		0x60241B2F4D27F033ULL,
		0x43825FFF3A89215DULL,
		0xD2C681233D353E5BULL,
		0x0630597B89B6413FULL,
		0xE5CAC524C47E6497ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BE0B3923587BA61ULL,
		0x799F478FE11E8BD0ULL,
		0xE18C7BCDAA5AFDA5ULL,
		0x23AC7EA84A181867ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEF95FC0FE4018DAULL,
		0xD6CD446C23461DDCULL,
		0x08F5B04C6E48519BULL,
		0x134B41FD15324303ULL,
		0x6217F4E8D9342F03ULL,
		0x1A1B2AB2C9344034ULL,
		0xAEEC046EF69109D0ULL,
		0xAD6E1063E3D13481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC547B01BC73E54ULL,
		0x3B9CE9CDD55FDC2BULL,
		0xA7B50ECAC4C6B1E8ULL,
		0xF0ED5A8660B2EB89ULL,
		0x6C2E0436F481296FULL,
		0x9975200D2F6EC92CULL,
		0xCEC5DFA16CCB3F0DULL,
		0x4A54CD7D496D5787ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44EDD278D50BB07FULL,
		0xB3D5EF332135ECE0ULL,
		0xA6EA18041CDDB892ULL,
		0x581DD5B19F522490ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6147102C2DC32B75ULL,
		0xAC5D9EA61C6349C2ULL,
		0xF9DEE8054FF11EB9ULL,
		0x2FA9FB5A5D80F5A2ULL,
		0x4133FD5C58873671ULL,
		0xCE90AF36216F1D14ULL,
		0x8890877225CE57DBULL,
		0x0532E7918BEB6695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D6B9BA5269E5D1ULL,
		0x55BDD364FDC1FE0EULL,
		0xF61E7B2C62C0374EULL,
		0x3B25AB1E7DD8EC06ULL,
		0x0D8ACD0860422883ULL,
		0xA317BDC64E456937ULL,
		0x2C663D6866677825ULL,
		0x9A1779D4856F252DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE98D82E8B59953A1ULL,
		0xCA93A1DA76D1FE89ULL,
		0xB2076A4B56761C75ULL,
		0x5A969A4AD619BF19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67758BDC21C911BEULL,
		0xB567C83CC500C112ULL,
		0xB8511FC919B43EFCULL,
		0x5B139E611874568AULL,
		0x0A88937FF3FA6A3AULL,
		0x03A97510B242057CULL,
		0x4E4A574C90A92385ULL,
		0x9C03861224B00870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x397D8D8DE30E30F4ULL,
		0x956F04EC2074B8EAULL,
		0xF476679216AB2422ULL,
		0xA4242BAAC7499769ULL,
		0x2C10BB31C669DB0CULL,
		0x98DBF77E1B5C5B7EULL,
		0x20C0486CAC3F0DE6ULL,
		0xF760305E62A6EACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C219E902301F8AULL,
		0xFA7967130AA343D7ULL,
		0x8658ED72EAC8505DULL,
		0x272E2B651E85257FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56A4C83852F34B1AULL,
		0x1F00D33A5006DE03ULL,
		0x1C3F5CC21DFDA778ULL,
		0x900CC232FBF458F2ULL,
		0xB321BE032919A42BULL,
		0xA9F8F9A096DFBC4CULL,
		0x8873B6ABAEC153A1ULL,
		0x9D2C24F8AC075FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6346B8DAE00DF419ULL,
		0xA52FDC7A74537DFDULL,
		0x40AC2246096925BFULL,
		0xA8DE7237BD0011EAULL,
		0xAEF1F3A09772E237ULL,
		0x2702C41EA1339717ULL,
		0xE614A5C8A5A1890BULL,
		0x62BBC0C63E46CE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x927619FF11A6227CULL,
		0xEA5CE80A5340E5E4ULL,
		0xF5AFBC2F6F4C940FULL,
		0x13DD2F778989E3D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BD3B2B1075C3AADULL,
		0x28A86D867E36F23FULL,
		0xD054B5CFD2DA2F5CULL,
		0x0FCAAA4CA6114C6EULL,
		0xA0DCF90A46733121ULL,
		0x98AD356917154552ULL,
		0xBDE9D09C33FFF20BULL,
		0x16A5BAD3FA6E9F34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EA2802E79827D6ULL,
		0xB10632E598B33B19ULL,
		0x717FF36365D7872FULL,
		0xF945594859A78453ULL,
		0xA0BB27AA95FB56FFULL,
		0x38FD9746391BD8CCULL,
		0xD1E68922E8F2530CULL,
		0x232E381AB92BE4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DEE9EE2518E7371ULL,
		0xABB3B3CDD889D309ULL,
		0x67515E6D91084214ULL,
		0x3A42B883FC517680ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB72FF40BB4C23B8ULL,
		0x6DB06BD16B9C2ECBULL,
		0x28867894C5931B0EULL,
		0x340E88FFD58632CCULL,
		0x231B2A970E5EFDA2ULL,
		0xF5779093A292B339ULL,
		0x2ED0D8900675CB85ULL,
		0x680CE57E4A38FB20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22280AB6E3A922FULL,
		0x66E3084C7D07E106ULL,
		0x28E3B27134098B18ULL,
		0x10BDF52D2019BD77ULL,
		0x0C70BA3F3BAEE761ULL,
		0xBC546A3D0827B4CBULL,
		0x8B4DFC7B2FFC2DE6ULL,
		0x050F13BE164F610DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x769D2B9E9334E156ULL,
		0x8205145FDA76121CULL,
		0x450F713B6796F598ULL,
		0x54FDB65A6A195419ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0440D8F85B4AFA68ULL,
		0x51B2992F94F4667FULL,
		0x9DE748B8E07C73EAULL,
		0x726B222259A6533BULL,
		0xC191CB518D62E868ULL,
		0x6D60231D011E3E55ULL,
		0x2E59FE4F80921097ULL,
		0xF2450B5362EE8E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B3B1B0A7061711ULL,
		0x0F9CF38941083F81ULL,
		0x7DDA5E5B6DB1628CULL,
		0x90ADB113C6F7C019ULL,
		0x0D753E6C01925FEDULL,
		0x0F583DB809DC50B3ULL,
		0x3583ED8A6E6F2A28ULL,
		0x6678911A2A604085ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BCA115A753928A4ULL,
		0x3741B2A307B56D24ULL,
		0x0FD3679E23F945E6ULL,
		0x2217958CF7CE2345ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F20826173B1BD9CULL,
		0x1F7081C6FE223C9FULL,
		0x09C06CE506BAF91EULL,
		0x3CF38755F29FC468ULL,
		0xD245DC01EA12DEE0ULL,
		0x6211FF582DF454ACULL,
		0x90832D7AB18EF51BULL,
		0x8CE9A9290CDCF4B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC484A02B5EE1F84ULL,
		0xC069C784FDDB8BE9ULL,
		0x4462B1C3211A0016ULL,
		0x7B53C4F2D52B27FBULL,
		0x74A400DC85357247ULL,
		0x9F8F0735B33EE6AAULL,
		0x9F09F331A73AC5E1ULL,
		0x66B53F87A544D22FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48DEBFEBB6A1BD8CULL,
		0x3E778F603735050FULL,
		0x9D5C61F96E1FFB9AULL,
		0x6D6770587E09BBDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C1EE1DFB7CF1C95ULL,
		0x076E7626AEC3907EULL,
		0xC37DA0F337730276ULL,
		0x6F09C56A04799610ULL,
		0x782844E30BB5FA02ULL,
		0x39D2ADE9C7335AE8ULL,
		0x59057D628186540BULL,
		0x51129478AD127ABDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x059003D225596091ULL,
		0xE9139CAD72210B21ULL,
		0xDECCF8D57FA4B82DULL,
		0x09BF9450F2DB56A2ULL,
		0xF04F5AF2D6FD579AULL,
		0x97AA0D818C0E7CC2ULL,
		0x517467013CA6CE08ULL,
		0xD48A4F01DA7BCDC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90C197B565DDD48FULL,
		0x3062A8F2041B7EEFULL,
		0x0439FA8DF0FC2EACULL,
		0x618480BC53FBECFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CD9AB430C873D01ULL,
		0x5B56B279069226E6ULL,
		0xEFE24577E4524CD4ULL,
		0x4801073709FD8562ULL,
		0xBD935193278BE360ULL,
		0xCE8325E62EF8B6ECULL,
		0x7E869889B418CBC6ULL,
		0xAA514EBA46596F4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF8BB73AD8D39259ULL,
		0x605DC863246497E2ULL,
		0x9DAE7FF20F41072BULL,
		0x94A3976460A3D8EEULL,
		0x5F5D6FFE5612DA2BULL,
		0xDCDE01059163D09AULL,
		0xE072DF98F5116A8CULL,
		0x8A9F02F3641C89DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x394D701F4BAB091EULL,
		0xD97C636D4647BF3DULL,
		0xC92139423029B442ULL,
		0x67D4AF583E63BB51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A9DE2DB91854534ULL,
		0x16B1284B66004177ULL,
		0xD19A5A6475779969ULL,
		0x0215F2D9B18EDD33ULL,
		0x786434C9CD54D0FCULL,
		0x2EF75176B1FEB84CULL,
		0xCAF8F4A93E075899ULL,
		0x1C2D512939D3CC65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE198D7F6CAAD3743ULL,
		0x8C72FC022B79246CULL,
		0xE1A6E3805EF07BCAULL,
		0xD104DC38F8D32771ULL,
		0x2DB944E1165B1291ULL,
		0x32509BDA45DDEB9EULL,
		0x4D04B63EA006DB3DULL,
		0xC99156113F4A3B47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E64A76FEFEA4DD1ULL,
		0x0AFD218147657EE9ULL,
		0xA234BAB78A99B946ULL,
		0x74385C2FE9274048ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EC4993E263C6996ULL,
		0xD985F04A9C7054E8ULL,
		0x622BAA53A4A35D08ULL,
		0xFCEEFFA6E03CCEF5ULL,
		0x0A3EA741496AB990ULL,
		0x30CE450F1328BDF7ULL,
		0xED4C2E1E7DAA36EFULL,
		0xD90843D36EB5E806ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x092158DE6DCC761DULL,
		0x18B9F06E77BEEAA5ULL,
		0x9952FC3E00FFEE75ULL,
		0xBC95A6C0B3FDF2AEULL,
		0x421083BF06C74EA6ULL,
		0x841B2B66C4A30EA3ULL,
		0x7AE58091D90100BDULL,
		0x5A4D4E0B5825929BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC7C85B59CB1D507ULL,
		0x6361CED7CC8970B2ULL,
		0xC41670F614C179F3ULL,
		0x1019D49985AB8A39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x757E51254124C7EAULL,
		0x9BA1B19B0CB24426ULL,
		0xE44FB2AEA9A74C58ULL,
		0xCAC126974C34CACBULL,
		0x6A06FFFAB19D2F93ULL,
		0xA7E503466E7ABDBCULL,
		0x90D5228BFB481BAFULL,
		0x5F51809A37ABD638ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4238AAEF1A9F69ULL,
		0x21DF945A011B950EULL,
		0xCD0FACA7426A977CULL,
		0xFF56F3C4C4583DA1ULL,
		0xDE7D6FF82CA48703ULL,
		0x740C8193BDBFC901ULL,
		0x0E9AEFDB77F0FCD5ULL,
		0x2D33FB7A59FDDBB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41A778DA0EF32EEBULL,
		0x2BE55DC7475702C8ULL,
		0x6BE38C3AE62B4940ULL,
		0x3BCBF58D6FAFBC17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5652C4D1C77587AULL,
		0x707A326285CF677CULL,
		0x181ECB9F3BB8BDD1ULL,
		0x045C2152988CBC3CULL,
		0xAA955C426253CF91ULL,
		0x6397F927014D452FULL,
		0x1B2EC90AF4B6C108ULL,
		0xB58074D5C323ED99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14105EFA2555C306ULL,
		0x84342FC593C79DBCULL,
		0x03E8D11586F4161FULL,
		0xF5AE783FE9FBFB8DULL,
		0xD24A077E23B4C88DULL,
		0xB2DDA18C07E95EBAULL,
		0xB1DAF0E0A8FDB33FULL,
		0x900D96E91F5A5776ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC83627442BCA0B7ULL,
		0x27EF039DF6DBFF18ULL,
		0xB6A810D0F23CB37CULL,
		0x1DBA9A32FE7D09CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B75715061D2A3F7ULL,
		0x08A700798A00EF1BULL,
		0x533ECC20C6B68539ULL,
		0xF97231976B96DD84ULL,
		0x12FCAE7DBC5F48E1ULL,
		0x5CD685A77F0C14BCULL,
		0x1B0FB2D001B899C7ULL,
		0xD42629E48F85D6B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F01A1B81BF69CCULL,
		0x7F2F627A440E2096ULL,
		0xF7DFEB1ED1EB8BE7ULL,
		0x528B18EC388B30B5ULL,
		0xD8D62262DEF430E8ULL,
		0x94BE7D5F381964C5ULL,
		0x74411380A4CDBE29ULL,
		0x82034895369CD2A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x973E2331BDF8CAFCULL,
		0x3D08D8B9CDF8ED11ULL,
		0x1E0A86C9BFA792BDULL,
		0x58148A7265A247B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE53FE0E55E407424ULL,
		0x64A0369518F055F4ULL,
		0xB8D32C08CF7C6177ULL,
		0x7E5E08CD75CBC823ULL,
		0x6B9043D015FD5915ULL,
		0x2A138AA2F78D1FA7ULL,
		0x2E1769504A549682ULL,
		0x0760AEF394E5AB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D98126EFF50D19DULL,
		0xBE4BF4B886DE5B96ULL,
		0xD30C5BC38AA48E95ULL,
		0x48A8EF374507C048ULL,
		0xBE5897FC92B4D4D1ULL,
		0x6920E1EE12C7C9F6ULL,
		0x30BCE2A3ACE335F4ULL,
		0x1520E95FFC5DB1BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDEB4FDBDBB34453ULL,
		0x4A594CB6875CB297ULL,
		0x8136CDE4A3AC27ECULL,
		0x2B2C6D7ED4F31B64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x759D90F4681F1A0CULL,
		0xE912E251793738E1ULL,
		0xDBF43E1868C0D283ULL,
		0x5FCC85387760AD72ULL,
		0xAD533FB2E3E372D3ULL,
		0x77D782406FD9F519ULL,
		0xFD5E124D8916172BULL,
		0x5AB7475CD7E3F8E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C2EFEFFA608A0DCULL,
		0xB3AC3F3A88CF9F80ULL,
		0x720A3E0DB89C1524ULL,
		0x5E5F6A8DD4746E57ULL,
		0x7500682925B9FBB0ULL,
		0x7019E5E9231E48CAULL,
		0xD1342F3147F1082AULL,
		0xE024235707205194ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35BA9066FC3E256AULL,
		0x5B8BD80C54432D23ULL,
		0xF821B63C5BA4F786ULL,
		0x334473879FF7148FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA83A4CD936CDD36ULL,
		0x6E27657007AD18CEULL,
		0x4A395702E8FC098CULL,
		0x612B361470B9AB58ULL,
		0x627EE54095D8B96CULL,
		0x16BAC69590DACEDCULL,
		0x7E4FB6B81DA4C9D1ULL,
		0xD138E766FBFEED48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34769150613AF6BBULL,
		0x2B5373DB958BDA76ULL,
		0xF2CD1153C4A84E3CULL,
		0x591F9EB42E42290EULL,
		0x4055B3A612EC8760ULL,
		0xAF1832A682F3F042ULL,
		0xD408C6A204BCF7ADULL,
		0xEEFED188AFA8BD4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB82A706CA1415398ULL,
		0xA4F5E71082664939ULL,
		0x9DF3E8F6D6BCEC91ULL,
		0x1CAAD65F9742A17EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1E706A8FA9F7D09ULL,
		0x2F2A57CA34397384ULL,
		0x7AAC7B5365A4C627ULL,
		0x2ECB5946718ED63BULL,
		0x2C34CE26EBB96B0CULL,
		0xD34896AE87F0B546ULL,
		0xB84539AB41654A1AULL,
		0x1D846C376C3011DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60A0133F064AE53ULL,
		0x369CD193399D3179ULL,
		0x08D827D4B4192932ULL,
		0x6B1D5369C3CB5761ULL,
		0x0FFA5A7068608EAEULL,
		0x608ED9DCD6AB82DCULL,
		0x7AC80A3E527A85E1ULL,
		0x02639E5B6428E468ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC8A328C896B852FULL,
		0x001F8D574AE1BDCAULL,
		0x92695DAA2864BD7CULL,
		0x4A8C9485DED43E41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x523A2605A4C024BAULL,
		0x20D18FDB9DC4A543ULL,
		0x9AD5CC821AB75398ULL,
		0xB81357430CF2DC5CULL,
		0xBFEB2B37B341E522ULL,
		0x069A677B0E7629F3ULL,
		0x38EDE2DD9CF626B4ULL,
		0x0BB7B1FC16FF44ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5499A532126B7AD2ULL,
		0xE4AB4D88B8DD811FULL,
		0x6CD449D3FD0CD801ULL,
		0x3F2C00434DBB4414ULL,
		0x4859CE94EBAF6A79ULL,
		0x91E12F6803438292ULL,
		0xEBDFB2AA29241084ULL,
		0xB6B85995DF35FAC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD3440FD3212DB48ULL,
		0x8FA495268E6BFC9BULL,
		0x9E1CAA514ED9C6A1ULL,
		0x16CE762C071890E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54ED71430965FFADULL,
		0x4A07CC83488DD900ULL,
		0xD90F40DEF37902D0ULL,
		0xB036F19CACAE6E00ULL,
		0xAA711971CB9E9DA1ULL,
		0x8FE34B222D756979ULL,
		0x59D684E783C1A41FULL,
		0xFEC672D6C5281235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6B80AF888D81D5ULL,
		0x0121E8B0F43D276BULL,
		0x43D83D139F94DEEBULL,
		0x693BA9C4A17B2787ULL,
		0x45952BF1A2509EBAULL,
		0x98663464C7B81E73ULL,
		0x4BD5D642B06718DEULL,
		0x64A9084F77D1F6E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0273199A26C578CULL,
		0x057743EF6E69D487ULL,
		0xA950F042B354CF8AULL,
		0x275917ED85FB54F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x325834405E40F241ULL,
		0x4E521721922C80EDULL,
		0x2A4F37F9D0827438ULL,
		0xC0EC4D6FE270BDE7ULL,
		0xAE48AD69F79E4FF4ULL,
		0x77C9A7DAB1965CA6ULL,
		0x58E157B5575B986CULL,
		0x03F0B1FAED53722EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF971A7A1BB8573B2ULL,
		0x2BDC8E152D349C52ULL,
		0x67D6D0A236621218ULL,
		0xF4BF98D03FBA6A04ULL,
		0x39868849899EE920ULL,
		0xA3C1E5B28CAC3C51ULL,
		0x854C1E3EE6163A3DULL,
		0x5795AB243053C06DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DB80F6EF6A4C019ULL,
		0x9B9C5B01DFB8B149ULL,
		0x2A9EEEEC6A6C5D13ULL,
		0x61AFB87FB0AAB682ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F7C482B05A3BA91ULL,
		0x9432633559CE7634ULL,
		0x8A8F7BBFCCF7C610ULL,
		0x4B9045CE61D23E58ULL,
		0x0F57B010DA7994B1ULL,
		0x1342D38E251473F2ULL,
		0xEDE08C070A7ABBCDULL,
		0xAC51BC190E4731BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2830AD7DBC4ABE5ULL,
		0x6AD7053FFD3B13D1ULL,
		0x336D643D40AB0CCDULL,
		0xDA1374CED7F664C6ULL,
		0x27A648DD11DCB2D2ULL,
		0xB24D91EEA319C9B4ULL,
		0xB9B7B09A82338A34ULL,
		0xF70C14CB10D2B28BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB14E8F02F12893FEULL,
		0x8DC31BA2A7C8A792ULL,
		0x1532A99EC6DE15E1ULL,
		0x59D3A6932926BB06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF5BC80319E79830ULL,
		0xF6152275848C8EA5ULL,
		0xFFC52E882D4573FDULL,
		0x223E2E4039E7FA6CULL,
		0x47070A0688B3C3C7ULL,
		0x09DC75E4268A8806ULL,
		0x4C72ED1751627FD8ULL,
		0x3FF67BAEA2A79661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403EC74FC59B2457ULL,
		0x5B083FA0D955E83BULL,
		0x4630B303DE50DA0DULL,
		0xE89F4973E009C7C5ULL,
		0x9883D8E1824907C3ULL,
		0xD65ED07A7B49BAE9ULL,
		0x0C778F4EA2280ED9ULL,
		0x8BA4ED6EA6BA8635ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96964C3248245A96ULL,
		0x3FB3708416D518ACULL,
		0x38E4674E51A15FACULL,
		0x7DBA024BBF0E9939ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECEE88BDC668DDF3ULL,
		0xBC690D5A681C270BULL,
		0xA992F6DC098B2A91ULL,
		0xE0262773B8898717ULL,
		0x976B8C20E9D7993BULL,
		0x4837F68FFAFC7554ULL,
		0x038933F181EC2280ULL,
		0xC3C755755089DB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4039D0AF7873B0F9ULL,
		0x7FA6A9E068DDFC01ULL,
		0x49E9A7F86F88B3B5ULL,
		0x35B7F568355E9EEFULL,
		0x711BE31F19435B91ULL,
		0x96E8476D78E0E4E5ULL,
		0x8FACEE428D9B750EULL,
		0xFCBC1074EA392110ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C87CE5343F65306ULL,
		0x8E9662994F559B8AULL,
		0x925BA6DBDDFC35BCULL,
		0x361A701AB32688F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47C849B6CB7E66E7ULL,
		0x65F79D5E733A0303ULL,
		0x3A96039EF9BB3192ULL,
		0x17B1CEE71E0CE382ULL,
		0xDCDAC3C6BF79AB3EULL,
		0xA0534EBA2866E730ULL,
		0xD03237798007F737ULL,
		0x4891C7F3CD6A0518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB18D82DA78F0C83BULL,
		0x7A65F4691CAF5A1CULL,
		0x6A925393C843E901ULL,
		0x531639693988B443ULL,
		0x771DB494D33781F5ULL,
		0xF6C5BD9E7429AC8FULL,
		0x2840C20E9155063EULL,
		0x954F9F443EDC2529ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB04B0845645FBDBAULL,
		0x1695331217A15CDBULL,
		0xBDDB1DEAA0070D7AULL,
		0x606D9F8D0D936CD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D597C5C71932AEFULL,
		0xF732F4B613D4FB81ULL,
		0x073E122F4D5E680AULL,
		0xC253DF6CCCA3325BULL,
		0x9535E24FD8EEFB9DULL,
		0x5305DC6369F4658DULL,
		0xA3DED79E987D3F6EULL,
		0x050A8C73CC2AE5DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A4FC7FEBE00DC3ULL,
		0x18B0283CE9FC1BAAULL,
		0xFAD6A9730B4680CFULL,
		0xDAB4BADDDAF76B22ULL,
		0xE377140F25675EBEULL,
		0xF049897517B659C2ULL,
		0x86AB4C231449DCF4ULL,
		0x89A9E9513C7C308FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E071D772BD4634EULL,
		0x86771BD95F0E9FEDULL,
		0x620E1D11E1B88540ULL,
		0x37F75BB0459AB0AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9482E2EA2EE5F96CULL,
		0x6EF9232BA9C9C006ULL,
		0xF6BC73940F8FF67FULL,
		0xC7BBE6E5F25D0606ULL,
		0x6992033D27E5F997ULL,
		0x80E0D0A9D09B9915ULL,
		0xDCA07533EDA9FE3EULL,
		0x9570B5C9F2F1CFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0D68D2A85FF1E9ULL,
		0x8B51BB3E7353E244ULL,
		0x7DFF5A55E463B6B2ULL,
		0x6182D19030A72385ULL,
		0xC7E617FBCF69FE42ULL,
		0xB243B80BA0C85A7FULL,
		0x3E855480575DF212ULL,
		0x11B0D588F54A6231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9FA65CAA8ED5906ULL,
		0x8EF90F684FD127F7ULL,
		0xF0C3F3E67A760E4DULL,
		0x74B45EFB68902D64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FE9377B63FF25DAULL,
		0x6E1C09FD03A0DAB9ULL,
		0x22DE1CDBF14D3AB6ULL,
		0xF2FDE4F530EF3B18ULL,
		0x365A2204B9476D42ULL,
		0xE0FA97B48FE37259ULL,
		0x3E54D77998781902ULL,
		0xA305E72282468F68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED219EF332D7175ULL,
		0xFF0C287024CAC362ULL,
		0x1DF736ACD0739366ULL,
		0x6E6DD1DA971E9337ULL,
		0x1BA869294077AEB8ULL,
		0xAB0577AF9D371811ULL,
		0xFDBE8B39A065A5A5ULL,
		0x59CEFEBD832F8357ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27788E201FA7FE83ULL,
		0x7172A248E46B7E0BULL,
		0x9B3637ADF396C725ULL,
		0x62B69218773C724AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA92FB58F858A3D2AULL,
		0xB1F0DC7110119AB6ULL,
		0x9FC9431F6882A891ULL,
		0x7FBA119D9DCAA96DULL,
		0x3BABE227D0B42C2CULL,
		0xB14E80D182ACB551ULL,
		0xF3D9EFE587E780FEULL,
		0x0F22AA38D7806794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8AFE4F5D906BF49ULL,
		0xCA4DB5D4EAFDB7C8ULL,
		0x524814A51F03DB7FULL,
		0xE68EC9997BE0ED5CULL,
		0x9AFD115DB3F6B03AULL,
		0xBE4B76BBD69ACA49ULL,
		0x395C2A6DC2BF3750ULL,
		0x25C28C756B0B042EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA72CE99F0A3E335ULL,
		0xFA16A5D3AFBCC60FULL,
		0xFC2C7E418D79BCE3ULL,
		0x3D6FB3063B567D50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF487E50E247D8420ULL,
		0xB7C8980015CA0675ULL,
		0x3DE18855C8852109ULL,
		0x56B98741CBB96562ULL,
		0x481B032775FD3F48ULL,
		0xA60DFCF63AE8E71BULL,
		0xC91D79A0BB6FCF2AULL,
		0x24E7A3BCC3861D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EBAFD9C2FC66A34ULL,
		0x8F5A84F77FCB753DULL,
		0xD798793C62A702C5ULL,
		0xE6A8241F8F75BAF8ULL,
		0xC5A2FF71CB69667BULL,
		0x7DA8B8F0D76F2F11ULL,
		0xE4432C3ED634B0AAULL,
		0xB195650150E68F5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339D746946A94529ULL,
		0x27762BD55A0FE2A2ULL,
		0x5EB08BA16CA4A54AULL,
		0x0E46B2F53FF2BA63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29958EDBC98036F8ULL,
		0x81E52BB513C82055ULL,
		0xC553027928BDCC1CULL,
		0xD2B00B5DA6BF4314ULL,
		0x5AADB5D2D57119F0ULL,
		0x967200ECD13E634CULL,
		0xFF2547A2BB334022ULL,
		0x402631E308A0BBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6700B5D636E00416ULL,
		0xCBB3D6185EF41009ULL,
		0xA484D27455995D59ULL,
		0x36E48C5DCE97267FULL,
		0x2414146576917312ULL,
		0xD3FA06C16F227B52ULL,
		0x08F36188790C4FC5ULL,
		0xA7DF2408BCB60294ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD62CF41A7D2F59CULL,
		0x9400780D44F87F6FULL,
		0xAC3657EAA4EC1C87ULL,
		0x36578D671CFF96BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC314B1FF55D60008ULL,
		0xC2925EEF817F3D1BULL,
		0x567101CADBD4D843ULL,
		0xD214A0A522651BBBULL,
		0x90222ABEA17465DCULL,
		0x2FA197DCBFA18EABULL,
		0x84448E1289309DC2ULL,
		0x9C68F316AC3FB83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D4CB7D6E51222F2ULL,
		0xF6C60AA0E22BE763ULL,
		0xD39E011FDC049B74ULL,
		0xDFC36623AB52E146ULL,
		0xADA4BBBFBAA1C52CULL,
		0x35C7EF1BBD8257E4ULL,
		0xE81611686E8F5019ULL,
		0x770E3B08B1AD1897ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x546673FEB407B7F4ULL,
		0xE21B60F4EFF5773EULL,
		0xB1B981EAF3C1C3E3ULL,
		0x7DC88C94A8D5EC97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E1B5DB7C827AA68ULL,
		0x5F91523E4A6F9FE8ULL,
		0x276A9FDE8D6BA82EULL,
		0xC7BC32827470A3CCULL,
		0xA24DD640CDAA407CULL,
		0xBCB26E0A16D49559ULL,
		0x70F9639EE08861A2ULL,
		0x435E14A7F7C4C1EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E325EAAB57213AULL,
		0x6FB186D48ADD3AAEULL,
		0xDD00D82C297F5AB7ULL,
		0xE68C75C648E36B0DULL,
		0x8A260769CF6514B7ULL,
		0xE926BC733103EDF9ULL,
		0xA541DAD59B9B21B4ULL,
		0x4AFBF200BD665841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC220EBB6DB150833ULL,
		0x569C27CFDC8B3D7DULL,
		0x87A815929F23CAC4ULL,
		0x3FC0E18ED590E88AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61DE7A6D860A3678ULL,
		0xA897427EA01FC4EDULL,
		0xD4FC90898B62C36FULL,
		0xDBE0B58EF7E04783ULL,
		0x17B44F9403027110ULL,
		0x3D78A574AFE51983ULL,
		0x853177352A1B65DEULL,
		0xFEA4A6275A6E7740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A19AC309FDC431ULL,
		0x1DC9DDD821901726ULL,
		0x631278BC3D760C5BULL,
		0x21CF316CB4253E87ULL,
		0x4C60BC9681B7D194ULL,
		0x3936A41EF26A3CF9ULL,
		0xEFFD832D575897FEULL,
		0x92405178711E62C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEA4B14BAD202122ULL,
		0x2C9997609ECC6A3AULL,
		0x97A050F696D74655ULL,
		0x50F61618E59E13ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02309FF6DD4936F7ULL,
		0x1515B6372C6F7FEAULL,
		0x6D149C9996EAAFF2ULL,
		0xAA224953306705ADULL,
		0xEFF84EF7AF907B3DULL,
		0xDB121EF82B26C6D0ULL,
		0x8E40482C61076195ULL,
		0x90306E9CB50DD102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AFBE6580A4B8D3EULL,
		0x121B11A1C223B621ULL,
		0xD2228E0D69030D29ULL,
		0x5DDFE891E235A3D2ULL,
		0x30A1546F87AFA3C9ULL,
		0xA43DD49D37094519ULL,
		0xEEFF536618C13BFEULL,
		0x659150BEE9EA93ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE1DE9D4BE5DA5E8ULL,
		0x267DAE15A6AD0B0EULL,
		0x3E9663FAE851373BULL,
		0x1FE0CFAD756C7C90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB861B64DB269365ULL,
		0xF5965C6CBB3C9BA9ULL,
		0x5571F6CB0FCB8CB1ULL,
		0x4784BAF675011740ULL,
		0xA0537204EADEC9E7ULL,
		0x60A42C0A1B7278D1ULL,
		0x98298EDE06A96890ULL,
		0xF94ABAE3D2841545ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2458B37ADBEDD43ULL,
		0x7A8B17FA4118CFC3ULL,
		0xB2C427FDF005FC50ULL,
		0xC381A6D28480F181ULL,
		0x1DD86C6E50A83F32ULL,
		0x3822D99360A83004ULL,
		0xA42F27B626B75753ULL,
		0xCF228B44E1E740C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1783648811804DD1ULL,
		0x7E3D8212342A9A67ULL,
		0xD9D91EB85DB41F75ULL,
		0x45FA25BBA7C7B0E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64E6681646439F85ULL,
		0xC7E9138724378406ULL,
		0x8D1E148F1344E747ULL,
		0xD720E684FB1686C7ULL,
		0x15058732CA18FDFBULL,
		0x0474ADA210A0173EULL,
		0xBB7D85EDF688E81AULL,
		0x985EDAF8E10A60A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F8A71B16D51433ULL,
		0xDCF8BD955C7746D1ULL,
		0x2425C7A3BF5F4E50ULL,
		0x43840FB50092337FULL,
		0x8BD9DD0ECD7DA099ULL,
		0x5B060AC826B68D6FULL,
		0x44C6CF9A7FF436B9ULL,
		0x4EF91A757FA20D10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B690252AE7E6980ULL,
		0x115C824A806AB1DDULL,
		0x08175D4EEDF7ED50ULL,
		0x78B76A507000BB78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9F0A25FBC7FFD60ULL,
		0xD589BEE0C473CE2BULL,
		0x304E0AF4CD89DDADULL,
		0x5AD8B75E9108E2D9ULL,
		0xA907C6C1CCDA9815ULL,
		0x41B909BD882A20C4ULL,
		0xEECF9FC8E2F0B083ULL,
		0xB7B6F00F5889ECF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9B91B398BD84318ULL,
		0xF2A9279781984EF2ULL,
		0x753F2D4B9C9A86A2ULL,
		0x4BE017F7A471008BULL,
		0x1E671EF44E47AEABULL,
		0x62D5E3CE7414BACFULL,
		0x7F574F8C92BE2375ULL,
		0xB4ABD38805025BFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84106FA6FA766017ULL,
		0xF89838C63E08A1ABULL,
		0x46EAC69D18704719ULL,
		0x029EDB7D52B766BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59FAA453AC9A9598ULL,
		0x9828105665F5531AULL,
		0xDA76DCE42C179ACCULL,
		0x5370A3EAEE363202ULL,
		0xC1BB27A4598019BEULL,
		0xD45AB1F8A9E27FD0ULL,
		0xDB97E569C2ED1A2AULL,
		0x451AF87BD32E6B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8133060D6B9E1D8ULL,
		0x44E594089106CA85ULL,
		0x3E2B4F7FAF7E2154ULL,
		0x21BF777030DCC4E7ULL,
		0x8C6685D019102643ULL,
		0x8A97C7DF744B1965ULL,
		0x82D4E1070493FC3BULL,
		0x270B3B4ADEF85FEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C777974667ED8ADULL,
		0x46313C0BC967BC7EULL,
		0xC93E340CBDD3EAFDULL,
		0x280741BEFD5F21B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF2F4A4CB72C961CULL,
		0x060971AD3390E253ULL,
		0x367C5340FED42236ULL,
		0xFBB53247284B23C4ULL,
		0x11143D529997082BULL,
		0xE8E717C5D51A0255ULL,
		0xFC8CEA4CA86DEE1AULL,
		0x0323AAA99E604205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FB3B8419035A70FULL,
		0x10822BC39E45F9B2ULL,
		0x829906C2F30EDB64ULL,
		0xF7EBA59229D0FCE6ULL,
		0xD7D864623BF76B65ULL,
		0xBC897758434289A1ULL,
		0xEB7C235BEDF82A51ULL,
		0xFA17E3BE2C204178ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E5DC5B90CA82EF3ULL,
		0x8B6D162D3B46D33CULL,
		0x3C60D439B94056AEULL,
		0x5B8913A7F3FA3BCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7116905B33F66EC6ULL,
		0x84168C7612459EDEULL,
		0xA0B55BFB024DA6ABULL,
		0xB146D9856405FE65ULL,
		0xE66FC5948E9FCD05ULL,
		0xBA2AE7CFA77A1C89ULL,
		0x05FD3C309896DFE3ULL,
		0x64DB229BBE279FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35406D68CE37EA47ULL,
		0x872774515FAE5470ULL,
		0x7067CC04C9E6A415ULL,
		0x4D33E89D0D51BAEBULL,
		0x9647D3CD7DAF22F8ULL,
		0x4DEB1FA3BB04FCB8ULL,
		0xD75770E909E58B88ULL,
		0xCE95BA075C2F179EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21C4067EE977C020ULL,
		0x0E66CEA9CBFA0380ULL,
		0x1CE9BC9566B98828ULL,
		0x326076EEE19879E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29FB323FC1632A71ULL,
		0x9C686445FA4E7177ULL,
		0x615028F8F17AFB9EULL,
		0x6B9217F725C40BA6ULL,
		0x979780688B52C892ULL,
		0xB61F8402F8AC2B47ULL,
		0x561D5A48D3734627ULL,
		0xC8D161CDF10195B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8918E844B5E73F26ULL,
		0x7F55D066950C9C2BULL,
		0x53754D3E1B0D32D9ULL,
		0xCA828DFC15E512F9ULL,
		0xFF7E581BB5D59E9AULL,
		0xEC2B39A11CDA5290ULL,
		0xF5C09ACFA6EDFB70ULL,
		0xA00F265C3A0AFDF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x349E4562BC1026ECULL,
		0x17559E6606680066ULL,
		0x5B9F47B77236DFE7ULL,
		0x2DE45CDC38797DE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C3B7C6FF7506EADULL,
		0x8E10B4A453C8C450ULL,
		0x14F4CB31D5DF5475ULL,
		0x3EF36717B64CA030ULL,
		0x17D9F12BA035F1F3ULL,
		0x410911B2A2AD7D43ULL,
		0x4A7EAAD602097D32ULL,
		0xDB28C4CD7FBAD887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x351EA66CC38FA074ULL,
		0xC0029BDC0BE1D220ULL,
		0xF2635AC7A00ADDF8ULL,
		0x0E989699DBC9B9DEULL,
		0x048CACB721387E36ULL,
		0xA4A5CAC550C5858BULL,
		0xFD82940748D7512DULL,
		0x990DB68F64601D41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3494FF4E0D5FFDC3ULL,
		0x04CAA0027055B783ULL,
		0x8FFCD319B346FF2CULL,
		0x005EEDB5E9FAB29AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24635A77C42BD7A7ULL,
		0x34F0E2C2C4DE27B6ULL,
		0x9E048F56A84AE17CULL,
		0x605F0521C391CFDBULL,
		0x5779C5F283359CE9ULL,
		0xD345489836B62F03ULL,
		0x57CBEEAB8D5E5AF9ULL,
		0xAD3C0DA29B74E90FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EA3D4A0D582A370ULL,
		0x90B7CF55F95D2869ULL,
		0xF2C6EA74E96DE263ULL,
		0xACF3B0CB234A073CULL,
		0xC194C8A35ACC9E61ULL,
		0x7A8B2B7FCC44B692ULL,
		0xEE5C61BD35CA5B39ULL,
		0x41ED73FC171BA6E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45BD1F96EE3EFEB4ULL,
		0xCFD9650C9858E003ULL,
		0x51CC9042BED4F5A5ULL,
		0x2116230E45879AEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x813AF1ED7D99CF98ULL,
		0x876FAF251D5A12ACULL,
		0xD78DBF84597ECB27ULL,
		0x4EB66BFEC7B1C5B8ULL,
		0x53154BDCEBBE9C61ULL,
		0xD620375E33C344CFULL,
		0x24A4EE613B5883D9ULL,
		0x81D133CEEF760F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB75CF5BC26315AF2ULL,
		0x3467F1500E4E3305ULL,
		0xF58A7AC62F098E2CULL,
		0xFEB144329D9162ECULL,
		0xD832892ACADDA1B2ULL,
		0xC0F8A8B5A420E0D6ULL,
		0x265325FC56B5DE7DULL,
		0x9C1A578147E6C05AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0786E2A238CDA9E2ULL,
		0x76E6EADA6126B689ULL,
		0xA22703B81A99C8A6ULL,
		0x6929DB5309662437ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A4ED0CEBAF0036EULL,
		0x81430F288D6A1BB9ULL,
		0x3979AF364F409B9EULL,
		0x7DC2A9C343CBA9DFULL,
		0xF426335193ACB932ULL,
		0x16784A7A5D2D030EULL,
		0xA375D3F4D2CB00B5ULL,
		0x7E1D0C75E2E0350BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F5A7A746810400ULL,
		0x45648FA87D416F67ULL,
		0x660E6E4F940B30BBULL,
		0x46622FED284FD12EULL,
		0x73676E50E67C0186ULL,
		0x13F993538744F78FULL,
		0x2E5A87864FE565B4ULL,
		0xD3EC8CD2FAB54394ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45AA674129AA4108ULL,
		0x9AADAF43D09A613FULL,
		0x3578994E294A6D09ULL,
		0x7A936C0491DBB06CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x844047413DD457AFULL,
		0x5950D79F346E5EAFULL,
		0x9070347D5F9F5D3CULL,
		0x53F95EF89B4E4E04ULL,
		0xBD2E0EFB36D895A1ULL,
		0xFBBF674A9DC7301FULL,
		0x3EEABA91FA54C252ULL,
		0x199EE0FDB2A9C5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06963D500852437BULL,
		0x5B25DAB0BC6190C4ULL,
		0xFDE2120A8AC25362ULL,
		0x086120F6A486FA67ULL,
		0xA406EA4A8AD5A2D1ULL,
		0x4DC42C6717D37F90ULL,
		0xA7EFBB366B66CB72ULL,
		0x1D09C53279C62C73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39797C2ABDF21F01ULL,
		0xD175BAB45A390329ULL,
		0xFBD00A0A0C2FAF33ULL,
		0x49BA5E2C68901BA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7F316A46C5CE637ULL,
		0xD4BC0D60F4FDA71DULL,
		0x36C925CC64DE8CC8ULL,
		0xEEFD4B9587958CBFULL,
		0x7586E5E2708CDD9DULL,
		0x0125907CA700FE6AULL,
		0xA0E77CE91F55B471ULL,
		0x2C4639BA7F99460DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61794BC4ADF1A8D1ULL,
		0x20F284EEF3025E2BULL,
		0x3B23FAD5110A1A05ULL,
		0xA3AE92C7772C73AAULL,
		0xCACC683895B6C71FULL,
		0xC7A5BD39E1D9602FULL,
		0x8ED1C5F709C77964ULL,
		0x7E5B47AA7FE43BD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE2872163A329252ULL,
		0x3CC2E45B45DCC5A7ULL,
		0xAADE52E686F13694ULL,
		0x1C2EA72E05489CF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29B164CB87526F4EULL,
		0x76A2315754CA2EF3ULL,
		0xBBB771DB1282113AULL,
		0xE242A0F3F7DB0A34ULL,
		0x92CDD51A0F5ED00AULL,
		0x94E81143E8AA26A4ULL,
		0xD39A97FCABE244A1ULL,
		0x0CA50FC4544F9F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC935FBFF39BD8477ULL,
		0xF1ADEFA0F769485AULL,
		0xAB6E8C3CA4D149E0ULL,
		0xBAA6A6684B480DD6ULL,
		0xB58B06726F7F77A5ULL,
		0x6561D346DE3ECA60ULL,
		0xC3A31B9ECD1C7DF9ULL,
		0xFA2858AAF2DBEA1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x386615AE08BC0490ULL,
		0x92E17545E95098ABULL,
		0x6F055B8D7F0C4450ULL,
		0x661F285023BFE23EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD31C631B5DFC1410ULL,
		0xF5172F435F12224BULL,
		0xDED6978CAF916668ULL,
		0x5CC4016AF6F43C4EULL,
		0x2E96EEAA608B9562ULL,
		0xD2C9135603E48A56ULL,
		0x4CF2A76F2EAEE928ULL,
		0x4B6A9C6F1D4F2E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A81999F07EBEC0ULL,
		0xBA2AA48DC876E1B5ULL,
		0xA9D796796A2E4176ULL,
		0x3A1E916220E33515ULL,
		0x3C011E24C79E2F0DULL,
		0x7A4AE61D4FBA1D20ULL,
		0x51494DA2EA5C13F6ULL,
		0xCB43C9D68CD97DE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94B13D5620BA831CULL,
		0x5DA7412054E77698ULL,
		0x9022556569AECA6BULL,
		0x2868B2AE47893824ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE2F5108FFF21259ULL,
		0x78A0715A02C68A4EULL,
		0xA5F614D8C60E6A06ULL,
		0x1E6D562E4093C628ULL,
		0x017B3EE59A930D8AULL,
		0xA44D093DD0771DF4ULL,
		0xEBD4978E2FAD071DULL,
		0x59201818AB458DA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x674009A0962DD2CFULL,
		0xDEB82E2C5CBF3627ULL,
		0xE3B83A8813499D38ULL,
		0x0DEDBDC3B895874DULL,
		0x267D73596F20E7D6ULL,
		0x2007BE94C293BD00ULL,
		0x4571E54C855B3B98ULL,
		0x34BC3B3FCF11B856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x089B7E36DCB5D900ULL,
		0x3C315845B5C7B85AULL,
		0x74E4500FFAE9029FULL,
		0x7752609B37AFE8F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x360BCC5D5B6CC2BAULL,
		0x13ACBF6FC71A2D89ULL,
		0x81AAE190E6D65BA3ULL,
		0x2D2542F32EEDAC25ULL,
		0x96D3CCA2A2950A60ULL,
		0xBF1740166C3A5FA1ULL,
		0x81BF1A67048D32CCULL,
		0x93F95D817B471FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2878EBD1BA8337ULL,
		0x5F23DC0C3BEA1E64ULL,
		0x4FF79D4A4ADF5597ULL,
		0x3709F427813771BBULL,
		0xDAEA0244F6F291B1ULL,
		0x9BBBF92B96393703ULL,
		0x12B5B6FCA5FB94C1ULL,
		0xACFD3CD8C44C62E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C975D5903D028E5ULL,
		0xF4156A3F4F5C168EULL,
		0xAD180610A5947BB2ULL,
		0x3F8827D6D6EE3DF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B01A666C056E834ULL,
		0x74E7A09F33732B8EULL,
		0x3C0B3372C86A03B8ULL,
		0x64248E396A0E2A89ULL,
		0xB2DE2906314D1282ULL,
		0x72AD565B09BDFB41ULL,
		0xD19D8AE7A2084B11ULL,
		0xD2ADA298E8C0A80BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF725FE8FA5D13299ULL,
		0x4572ECAEF998AD79ULL,
		0x3A60AA1B45D699B4ULL,
		0x4BB19EF4EE6E6C18ULL,
		0x17668E10F0D25284ULL,
		0xF97030A044B472CDULL,
		0x60107F3E146435A5ULL,
		0xFFFD6E5C5BF0AC16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x479CA83EACBE3445ULL,
		0x2E884DA97944BF63ULL,
		0xDC9A448288EE97F8ULL,
		0x5E9AB041627F24DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFA8D8BBAE57AF59ULL,
		0xA831E79C71D5B4C0ULL,
		0x229A661CA0556278ULL,
		0xB9D8C011CCFFDEF2ULL,
		0xBEAB7F8C608CEB4CULL,
		0x32CB08F8C994198AULL,
		0x972CD96FB2113094ULL,
		0x8A4EC28FC3BF2BBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BBD88D9EB0B499DULL,
		0x5985022A70707FBFULL,
		0x7E729CD3B49EF275ULL,
		0x503659F32DC8A226ULL,
		0x22B399A6E3164F73ULL,
		0xDAF97F3057F0FB45ULL,
		0x9D7F935B659657B9ULL,
		0xF447972502F23EE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AB76FF262E785A5ULL,
		0x57C75932DF9BB356ULL,
		0xB3E0304C45F2A06CULL,
		0x2EB2D7F73DA26572ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F57DAC3765356AAULL,
		0x8FD2F869884AD678ULL,
		0xAC900969FBFE8CECULL,
		0x62E944D4F60756F4ULL,
		0xAAF0E202B1D299E9ULL,
		0xE000C39016ADEFC8ULL,
		0x08B521A5174F5D7CULL,
		0xF2C86189598B563AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1666A810E8D0EF1ULL,
		0xEB79DB5B1092B302ULL,
		0x721F2E254F0B211AULL,
		0xB94EC8F5694FA6CAULL,
		0x8E8986CCAE9476B0ULL,
		0x9223EBAEE03365B8ULL,
		0x453DF5AD57C7AE10ULL,
		0xC1A1396B071B1647ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0548FA46E2FF8326ULL,
		0x3321287C8DE8A1DAULL,
		0x3E21620B1B1775E5ULL,
		0x756A705FC9612E33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84E4FED31EA253B8ULL,
		0x1AE3490391077998ULL,
		0x129A5F770DD83977ULL,
		0xE847AB4E550EFE25ULL,
		0xB15BD34AD94D18E9ULL,
		0x53E255DA9B8F918DULL,
		0xC7E69C69ADE28586ULL,
		0x25E350226DEA5245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A625EBCD20C105ULL,
		0x4B528C877C44BF82ULL,
		0x3A97F2ED459D6678ULL,
		0x3BF274D6A504C22CULL,
		0xA7557ADA520F9AD4ULL,
		0xCFA88C05B1DBFF28ULL,
		0x1FDF1AE21253B69DULL,
		0xE10F9FBEFA9D930EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA2FF99B64A245BCULL,
		0x7024B216C56A7515ULL,
		0xC91FA6AADF6D8982ULL,
		0x63C1653ACD6E9E3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE64136DF7B6E55DFULL,
		0x433537E8941E0EB2ULL,
		0x00108DAF42448898ULL,
		0x207EFDF0864DBC76ULL,
		0x86E087E315ABF3E6ULL,
		0x6F7AD33CB6DD15A8ULL,
		0xD91E5CDD192784D3ULL,
		0x3C7439615FD7E434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A066498B072FA9EULL,
		0x6E7EAAAE56F43E49ULL,
		0x01A6B44C6BF9DCB7ULL,
		0x0B26B12C7656BF66ULL,
		0xC190E8E7B1D64639ULL,
		0x1C06A57D9F33B549ULL,
		0x9A7F1430D992C9BDULL,
		0x9AD946A0C95BDCA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x060C6B979CB320DBULL,
		0x37F55797C04E1E7BULL,
		0x4A0EA2F4465E7131ULL,
		0x1258555A66601BE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x853A6DD43F576607ULL,
		0x31B9C54096003E58ULL,
		0xFF996412D931C5CDULL,
		0x1EC3CE28A8092637ULL,
		0x74563D35ADC93668ULL,
		0xD1A7BD6372F6193CULL,
		0x90190D303654AF42ULL,
		0xA53F5766F1D2CB8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA96BC496D890EB09ULL,
		0x3EAE604B523114F2ULL,
		0x64D0A872B54AA117ULL,
		0x45FEFAFAF7FAE72EULL,
		0xD9C4DDCD04022D4AULL,
		0xC6785C88EA11FFCBULL,
		0x4DA6D91D53A833A3ULL,
		0x3272E1E9382DA140ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD62D2C69A51D7E5ULL,
		0x9C13C56595AAF01CULL,
		0x77BC766DC9817E51ULL,
		0x631E43D73E928635ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0719CC362A6CBDF0ULL,
		0x0B39D32AA3FAB036ULL,
		0x7DED8615E3A3440DULL,
		0xD898B0BAFCB45EE6ULL,
		0x8A1D3AE27D8E48F4ULL,
		0x1833BF869C92C0A3ULL,
		0x8258441162FDFDF0ULL,
		0xD3C3DA7D4FB51033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5147BAF0D3D9F5FDULL,
		0xC8BACB76752B20ABULL,
		0xB4AF09974A697354ULL,
		0x3D401B9E758B7873ULL,
		0x7FF1E40AEF22CC34ULL,
		0x21E466341852C146ULL,
		0xDCA38762245AFBD6ULL,
		0xC8890E9CDD9005D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3840F5447A874CBFULL,
		0xD24649F3D04F775AULL,
		0x62127E81E56C2092ULL,
		0x4612D86D78A870F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x319B4D0430E52CFEULL,
		0xD000D63229C987EDULL,
		0xBFD7576EAA4C0C07ULL,
		0x2B35EDA311B06DFEULL,
		0xCE86E61A65C268CAULL,
		0xB4E852BCD8A1C4ECULL,
		0xBC2C3A5419C4BB4BULL,
		0xF73F4381F840F6BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0406BA94D4661D5FULL,
		0x044C10ABB050905EULL,
		0xB8AB1787F885E445ULL,
		0x8E537484A854D80DULL,
		0xCF0E0B2BBE2B8187ULL,
		0x9E524447E90FA3B9ULL,
		0xA6C877FADA548772ULL,
		0x5CB5BBF4E1BEE205ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x198511DC3CE566E8ULL,
		0x25FAEAE20929E521ULL,
		0x33FB19261C6DD9FCULL,
		0x0D4C980FC0AAA944ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D3DAD3C93BBC21ULL,
		0xEC9A3895A65563B3ULL,
		0xD9320FE6873E1BD0ULL,
		0x1EF34291D5A9841BULL,
		0xF1CE518BD7936039ULL,
		0x4C7078CB978B59A9ULL,
		0xF626936C0B0A6833ULL,
		0xBCAD4326A7DB81EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A48EC3ECDCBEBAULL,
		0xAD3E4BF02937BE3EULL,
		0x1368A69BF62C96EBULL,
		0x34C4B6C08B9254E6ULL,
		0x7B97E4074D300385ULL,
		0x67CC1EB14F251EFCULL,
		0xA4E99A725C59A572ULL,
		0x63B8EADD3F3266B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28438DBC671EC20DULL,
		0x2FC14C8C3C4A5B34ULL,
		0xD4D65E5A7F4E6D87ULL,
		0x1E73A6B6D3313945ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95C1CAD3701E18CBULL,
		0x7591C8D7BBB32FC1ULL,
		0x658006CA5A9F1B80ULL,
		0xFFC2D89D30A30852ULL,
		0x0A832A86E086588EULL,
		0x806BB96B811CF5BCULL,
		0xC0D30A6307C20218ULL,
		0xC3E33DAB3DD84609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22738003522F930ULL,
		0x312D245195E87BD1ULL,
		0x2BFEB3C8CA2F0E55ULL,
		0xB45E8EB0EEF266ACULL,
		0xACA6900D14790DDBULL,
		0xC6B6BE601969C94DULL,
		0xDCD9A43F049B1D65ULL,
		0xA1CD5E191D4145FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA25980E784F436EBULL,
		0xD541E8378A634C51ULL,
		0x10867C5A0835FFB2ULL,
		0x5AA3799D181AA390ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE7EC14B248F525ULL,
		0xD5FCB25BD33F1D22ULL,
		0x08C0D17FFA106781ULL,
		0xCC502E29064DBC3EULL,
		0x5B3859F52CCB6329ULL,
		0xE52D2734A683E540ULL,
		0x76A39CAAE861E977ULL,
		0x4666457179E27375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BABA58FC1E42E0ULL,
		0xF5F6F307B14BAA3EULL,
		0xA7EB1B36C47C89FFULL,
		0x32B379E8CFBA6EA6ULL,
		0x9E31217FAC85E336ULL,
		0xD1D43A3CEFCD1AF4ULL,
		0x7CB80A5010890B88ULL,
		0x3836F30C8917979CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA3F932CC07BB0B6ULL,
		0xBF38EC1941157A21ULL,
		0x79CD6FC53FC4CEFEULL,
		0x34A2EF3BF4AFEFCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE1F5476736AD5CULL,
		0x0EE6A8A1A675F295ULL,
		0x57DF957C7E2CBFAFULL,
		0x5DEB2AD33E83B8BEULL,
		0xBFB86543A699E9EEULL,
		0x468EFCCA2E9631E4ULL,
		0xD1B8956072949F6BULL,
		0x103186204A62FF30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38868B9D3F53455FULL,
		0xB17BC8608E833A6AULL,
		0xE119FC9849BB8084ULL,
		0xFA685F5D5DE3AEA0ULL,
		0x11EFFA1E192A79A3ULL,
		0xA496B167C0DC6270ULL,
		0x7914A2A867F2E2DBULL,
		0xB1D727933F9248C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01B513D266E0F69ULL,
		0x684610DD6187837CULL,
		0x9F1BA035C8733C7CULL,
		0x64ECD4657B9B1E0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4581C255B42C9E18ULL,
		0x2F1D0C2B3DD7744EULL,
		0xC77F3D8AA5C9FA73ULL,
		0x8D6E7818228619C0ULL,
		0x105E194D80FCB891ULL,
		0x289D86D53AF58BA0ULL,
		0x9A42D649B1F58269ULL,
		0xB6C53846D35B845FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x308DFF6D920E8892ULL,
		0xA35BA05C911091D1ULL,
		0x73F87C1F3E68BCABULL,
		0x3D054CE1F41CD037ULL,
		0x2EEABF41AFDA5CD5ULL,
		0x75BE8AE6497E7261ULL,
		0xFA0FB1D5DBC39DD1ULL,
		0xFE472F41BE9D6281ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C1320A92D37B1DFULL,
		0x18DAD1468474A1D2ULL,
		0x1B1E2A9D32C92C4CULL,
		0x331E81F742A2506FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC809A2C188455BULL,
		0x51C56586DACE88FEULL,
		0x68E5D766AA2078D7ULL,
		0xF514ACA5C5081795ULL,
		0x89F4E850A479DC3DULL,
		0x9875FBECC8F2E37FULL,
		0x9ACE13E8089E584AULL,
		0x9FEE0F1050680C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642F5E0F467C7270ULL,
		0x0F7FA63078AC15CAULL,
		0xAC7B375441678E88ULL,
		0xB8EDF377A215755EULL,
		0x3D366D22AB13A7E9ULL,
		0x045B99491CB32339ULL,
		0x326D4EAADB74FF7EULL,
		0x4BBAB9599B70CA15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCDEF4668037993EULL,
		0x3E3063A1F398FDA3ULL,
		0x3AC7E7271CDC18ADULL,
		0x3BC5724CFFA68016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D285A5837D06BCDULL,
		0x05686DF4B83DC8CDULL,
		0x4473A4A03EAC04F0ULL,
		0x4E90394B17414F15ULL,
		0x9FC2EA50ABA3965FULL,
		0xDE3EB3697598A003ULL,
		0x85151F49EB67E20DULL,
		0xC5D8BADCA458ABA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45C382BD353E827ULL,
		0xB45BC726183255A5ULL,
		0x2A6BE1B4492D2061ULL,
		0x9C19257447F56599ULL,
		0x640B3D06B22DBCEEULL,
		0x989038FBF7635ADBULL,
		0x822E980D82D18634ULL,
		0xD132D874FA0E998CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x660FDB276BFACA20ULL,
		0xA8F2D30F5BF3B720ULL,
		0x883FD5E37BD086CEULL,
		0x0316AF3A164A99A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BCFD52CA510BA41ULL,
		0x0C65B395BD852418ULL,
		0x89C96724AE78FE7EULL,
		0x5C1140A28879A0F2ULL,
		0x55DCE9236D260F66ULL,
		0x056859042737BE88ULL,
		0xF7617BC3F6CE93AAULL,
		0x20DAB443F7CAF73BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C14EEBE5312D1FBULL,
		0xAEF615346D84A99AULL,
		0xF62A6298A9378DF5ULL,
		0xB5816FE73B72CFDBULL,
		0x2B3C530A1A81C13CULL,
		0x60D0DED8EBACA766ULL,
		0xC1661CC67BB6F102ULL,
		0xFB3E98EEC02A7D37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3912E3096617D9CULL,
		0xCBEBC0CC26A5E990ULL,
		0x96EF1E2C4AC3956AULL,
		0x3BBBDF618ED8EDB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CAEBC90A435121CULL,
		0xB453ACB2773656DBULL,
		0x6F14546A3B287E93ULL,
		0xAEF68C27CADF666DULL,
		0x86F0D7B8285C117CULL,
		0xC16F5A2B4B0D1521ULL,
		0x9176C7FB300A3956ULL,
		0x91655FC6A1678A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB01914F9E78F89ULL,
		0xC2C9030CFEA1BA78ULL,
		0xF969E981D1F048A9ULL,
		0x2B5775E2C71B2631ULL,
		0xEC4B2A95FACB418BULL,
		0x08F67B793D0B4617ULL,
		0x5283FABB9E2BF247ULL,
		0xCAF6AF18A08CEDF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0396568E6DCC5F16ULL,
		0x537BB8138CD957D0ULL,
		0xCDB4E2581036C23FULL,
		0x780D50192437725CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89F26104357C0306ULL,
		0xD077485D7B230C61ULL,
		0x81422B2210A710C2ULL,
		0x02256E7948E756E6ULL,
		0x3B638592F2C12E6DULL,
		0x5760C47A69AE7AD1ULL,
		0x8156A294B4256783ULL,
		0xF833B2F16F7FB9A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14E09E1F5D9DCBCULL,
		0xC535F56171FFF6E7ULL,
		0x42B37CC60AEAC25EULL,
		0xDD6186E67162E2F1ULL,
		0x042390F4AFB08ABDULL,
		0x25247AA5424B2908ULL,
		0xF59D4712243AF0C9ULL,
		0xEAA69FA1CCDDFB1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC22A6A0341A7290ULL,
		0x8034489FE1E13957ULL,
		0xFC1243BD6289EE07ULL,
		0x27B4C564FB86BB7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C8672F2B83DEEFULL,
		0x3A5FDB3AA210B9C4ULL,
		0x23828A15117CE293ULL,
		0x6B5C14353F9182E9ULL,
		0x2C5113D8EE15E2A4ULL,
		0x1250AD729465C6BAULL,
		0xFA48A59AABAB4B06ULL,
		0x1002D5BED3D4C694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2534DB0263680CFBULL,
		0x3D7AA41725F4B793ULL,
		0x31A8A3EF6D0857CAULL,
		0x09D810BE86870DC2ULL,
		0xEE0FA9CC018F75B6ULL,
		0xAD05949FFD8268C7ULL,
		0xC0AB9E14662DAFA3ULL,
		0x9204250373BA909AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22494A17E40FFA76ULL,
		0x060AE665E1DBF426ULL,
		0x7F290413F5199B64ULL,
		0x15523F46FCEE784BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA59A4388C102D95DULL,
		0xCA44BF5B37C592F5ULL,
		0xEC3E400666BD0001ULL,
		0x389C7F29ED154C52ULL,
		0x3CB3964BAFF70057ULL,
		0x7AC6150017B73545ULL,
		0x24B7D94D62A73DD2ULL,
		0xEBEB05F7AF15A04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B1824554911A2EULL,
		0x5CCBCB729AF25151ULL,
		0xA8D787259591815BULL,
		0xACE80323766D9289ULL,
		0xF526B02777ACE6DBULL,
		0x16A207828E7DF947ULL,
		0x6A6A1F79DE3E7C34ULL,
		0x650866D5E3039DD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1D2EAA3C7718A7CULL,
		0x4AD2F48AFB52293CULL,
		0xEAF04E4678B83C29ULL,
		0x11581B0AC15416F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BBB92CEF8EC014EULL,
		0x6BE13BE115A7C289ULL,
		0xA69629A02727B491ULL,
		0x757881108CA4459BULL,
		0x7EEDA5D50AD4DA4EULL,
		0x247EC9627F046116ULL,
		0xDBCF570C44A0A418ULL,
		0x132CADC0AA64C230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48DF8AE4DA9FC90ULL,
		0x67C233202CF8A11DULL,
		0xAD488715FB8C623AULL,
		0x39DF4598E86F044EULL,
		0xCF23F76D65FFA4A6ULL,
		0x0D8AD10E84DFBB97ULL,
		0x17FAD803BCA31A15ULL,
		0xA7A3F96D375635CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF1D7D8322E7F86AULL,
		0x6C55E5380A1FB239ULL,
		0x0AD87DCE5B3DCECCULL,
		0x31E3FFDAB85E181CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67AF597AAD437CB3ULL,
		0xEDF6B32417B7C1F6ULL,
		0x5BFEF1979BE05B8DULL,
		0xDA55BEDC809417F4ULL,
		0x20A739F072C22109ULL,
		0x56C7BB68EB100025ULL,
		0x242EBEC1B24BEF79ULL,
		0x70912CEFF8B262D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D1A32046E499C95ULL,
		0xB1588D6C76AEBE8FULL,
		0x97BEBEBCB992D677ULL,
		0x06DEF95A0F745E5AULL,
		0x98C99FA7D5C342C8ULL,
		0x6E792E6C85173AFFULL,
		0x063AD2A1E6FE3936ULL,
		0x5346B5313B258702ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x757A0E3D8CCEDE82ULL,
		0xB847132EC3F646F9ULL,
		0x36753F930FD69304ULL,
		0x2C848BD294085A32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA6A3B581A454CAULL,
		0x2FBEE0CF240881F1ULL,
		0x82ACF1DE07A796AEULL,
		0x4D3D8D65CD0BD91DULL,
		0x1BCF47C56FECD59AULL,
		0x6647880ED86C1AE7ULL,
		0xD41A49C34C9DF0CBULL,
		0x290B8A5340E2AC27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6868FF36F2CEB894ULL,
		0xF67B10A8DD55603DULL,
		0x8D6F68DAF0787544ULL,
		0xB478E432E220BB6EULL,
		0x505C57270438E492ULL,
		0x723064A64437EED2ULL,
		0x450910D91CC6B975ULL,
		0x74906FE4DAF7087CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x254D5C028B8B619EULL,
		0x74B311AC4671ACCAULL,
		0x31CBFBC63121582BULL,
		0x630A95960BE56926ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BD3CE09A4E8C66DULL,
		0x4629219DBDFE27FEULL,
		0xD29F73470CC88BE4ULL,
		0x1ED08506A1789C6DULL,
		0x03583D6A1AF78155ULL,
		0x7EC5FD9EC1FE449BULL,
		0xF5DE71484117D8C2ULL,
		0xAF2E7A1D0765E517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B503566A492E9ACULL,
		0xB56025A5A1717C58ULL,
		0x178C1781656DD07FULL,
		0xE83349D6DEB0F26CULL,
		0x7DB5641CAD6D9B6DULL,
		0xDA1B793BBBB7D862ULL,
		0x9FEF1247492A1200ULL,
		0x90DABA3AFE5695A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76AFDA2142CDFDB6ULL,
		0x0218A2AB0B00BC09ULL,
		0x7C9B75EA74A63C23ULL,
		0x370BB6BD1B0D74D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x515E6C339806DB56ULL,
		0x0BA0DFD5C47D9862ULL,
		0xFF5BB58FBA0FCBE0ULL,
		0x0DDF33BA606D64E9ULL,
		0x95FFA9A21847B4ABULL,
		0x4409FD3A0C8321EEULL,
		0x21537758022ACE1EULL,
		0x67F74657E8CE8B53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9841FD80C32DB0C7ULL,
		0xF751659EEE03CF23ULL,
		0x62EC5979A7ADCCA3ULL,
		0xEA403079024D913AULL,
		0x572E7CAB5987B752ULL,
		0x494022E3AECFCB41ULL,
		0x73E8D61619FF9BD1ULL,
		0x7859E0072831EEB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C291B532558C540ULL,
		0x4E45E308BF18A6F6ULL,
		0x5A434BDE88CB76A9ULL,
		0x34FC333DF55F133DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8807FB7CD345A17ULL,
		0x54026324515BFEAEULL,
		0x38F4135C7356A5E2ULL,
		0xE9280F6A223BE9A1ULL,
		0x0967C97A08F04D5EULL,
		0x1A4E691FA53754A4ULL,
		0x6B095E04E8A28F97ULL,
		0x8CED61A2D0514341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30245745D2CA3542ULL,
		0xA9954C3FC508A447ULL,
		0x7BD6C03EA4A16E50ULL,
		0xB4320F8FBEB437E3ULL,
		0x641F07677EBD0558ULL,
		0xD298C214FF1B914BULL,
		0x5EBA612F8BCD5676ULL,
		0xA8A91C47DC7F7EC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0128F7327E06D521ULL,
		0x4F63E27934725990ULL,
		0x90D6DAC9965BB25CULL,
		0x17184B5A94AADBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC41AAE8BE28A498CULL,
		0x975F0DADBE78D3F9ULL,
		0x8F13BF419FE72700ULL,
		0x8C3EE9169B9D90CAULL,
		0x355F98201E1629BEULL,
		0x695A789CD3FA96DFULL,
		0xE35A1C64D5026482ULL,
		0x012371D906F5B9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB62E6AC4A21979ULL,
		0xCC820A609B9F6473ULL,
		0xBD4C08F780AC3A4FULL,
		0x189CF645FB2048BFULL,
		0x66A38B912940815DULL,
		0x8420C8257568BE49ULL,
		0x244EBEDD7BFA39B6ULL,
		0xE0CE762B82715958ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD84E5D59759F2993ULL,
		0xD16D35052C7F95C2ULL,
		0x2D779861567146F4ULL,
		0x403F4E924C239A69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2941E1ECEE71F3BCULL,
		0xE60A278C07121A8FULL,
		0xF726526C07D2B50BULL,
		0x768156BE72CB076AULL,
		0x01FDD6B0D6AB11DBULL,
		0xB828228BB23200A2ULL,
		0x2EBED584659B9C2CULL,
		0xE8C671F623B5DFF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF1D7BFD2C75DCD1ULL,
		0x85E9F64F978DC1F1ULL,
		0xDC87ECB334EEB8E3ULL,
		0xF9F09D0B4F3AF2C8ULL,
		0x7768AD6A1C9634D7ULL,
		0x9D5B66FEAC9800E2ULL,
		0x315BB372582449D7ULL,
		0x1253E7664CDF561DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC48866F6114EA1DULL,
		0x5A84082B44604F0BULL,
		0xB7557466D29A34CAULL,
		0x51914B0D07688AB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EAE2C03C96F4A1AULL,
		0xCCE8BC20FBC9D3E8ULL,
		0x88A6DDB3FC231EF9ULL,
		0xE6585CC7D592BC85ULL,
		0x4719CDCD66F73B24ULL,
		0x705834D4686C143AULL,
		0x844F538FFD6C526FULL,
		0xEE621E5C05E02F31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8655E7AD1943CBEULL,
		0x23DD60A3E805ACD3ULL,
		0x233B3557DFA065FFULL,
		0xC728F04EAD18808AULL,
		0xE7A65253E3A3EB61ULL,
		0xB992202801C29D2CULL,
		0x8F23B44457E8D1CDULL,
		0xEBD35C414AC90060ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD16D21927638E461ULL,
		0xCA726D1450EBD310ULL,
		0xC9E54D96AE07D0FBULL,
		0x00603C70EDEB2EFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7A397B663814BCBULL,
		0xF74CE29FB801CA24ULL,
		0xF6EFDFC009395340ULL,
		0xC6B833CBE6CF1FC9ULL,
		0x5E4FAACE46C3011EULL,
		0x2473799CA9727799ULL,
		0x45E5B5D3409BF8D4ULL,
		0x60EEDACC4E6EF4F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6649BD72247AC96DULL,
		0xFCC5F6D48C4B7CD8ULL,
		0x3178CCA0C769CC91ULL,
		0xD04438CF18D39D95ULL,
		0x3AEB532C96B52571ULL,
		0x996153B38BB9593DULL,
		0x2AD277E40BEDC1CAULL,
		0x3AA502978DA34936ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC23EDC4461151EDDULL,
		0x9F388C659530CEF9ULL,
		0xCA5244A113ABB219ULL,
		0x256A12D16C370104ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE16409E7B7B93A4EULL,
		0x7A5340FA439D199AULL,
		0xD82E95679D9743FEULL,
		0x88ED6B266DE9C0CFULL,
		0xA9CF6F03C1E3E821ULL,
		0xA2C9400F55B775F2ULL,
		0xF1F1C63414496F91ULL,
		0xAF08BD4D5C7CEBF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76D64915F5E4C5EULL,
		0x92A5BD33D7FB75A4ULL,
		0x93D5EEFEBCE81544ULL,
		0xE9190346F137E224ULL,
		0xCB61DA78F2F4D780ULL,
		0x16E950A27AD6639BULL,
		0x9E9B1AB4FA0854F4ULL,
		0x4279B551552292E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E3AB1F10FD76823ULL,
		0xAAEB0DEEE90A5CDBULL,
		0xA3361B46C659221CULL,
		0x3D0F9748941B16A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87ED77ADC9AEFD40ULL,
		0xD994EF8EF90D8A99ULL,
		0xF08DE8FBD6004F42ULL,
		0x6ABF4D31BE7246CBULL,
		0x894246418F90BA86ULL,
		0x78C26D902FE9B2DFULL,
		0x5F55AB8242E90E18ULL,
		0xCDD715E1888EE721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE77C8CAB0B212C57ULL,
		0xB1E925B672DF6CA2ULL,
		0x6C474A0B19F6BBCEULL,
		0xDE176253E3BBE88CULL,
		0xA90A1C25550D0EACULL,
		0x5B5265ED2450F904ULL,
		0x307DE1A0F10CEC46ULL,
		0xDC4ED8F547D82337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8C72B336E1952D3ULL,
		0x864CEC0C3ED9B473ULL,
		0x784E9662E2B698A4ULL,
		0x66E0F5EF75D77302ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58B4ED1F9FDF453CULL,
		0x6A34460F91B9EBF3ULL,
		0x6BFC1FD6BBD3861AULL,
		0x8E7BC9F893374E70ULL,
		0xB6CE244A50D29AA1ULL,
		0xE43C1EF4A3771679ULL,
		0xF0BD7B9CE210B4C5ULL,
		0xCFF505D72CD9D8D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121AC8FCB8C486F6ULL,
		0x6008D054A9ED5890ULL,
		0xF7E1AE56D5AE2801ULL,
		0x58F5C314509897C5ULL,
		0x302D0C2406984672ULL,
		0x617916DF461E81BCULL,
		0x5040B3169FAC57E6ULL,
		0x2615C07E9885DC26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4283B9D1EBC340F6ULL,
		0x731EA8E6C2F2A785ULL,
		0x46A0356DC10B2746ULL,
		0x6CAA520A4716384AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2694C8849F3CB3CCULL,
		0x8ABF88A971407443ULL,
		0x7C9BCC258EED2293ULL,
		0xACDD8418E612AE58ULL,
		0xA5C6FD5F3DDE4E4CULL,
		0xC1F632576A73FC23ULL,
		0xCE58F793EB6D22F4ULL,
		0xC3E67E670DDFACEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6734B70B8607B273ULL,
		0x76AA4496A5639257ULL,
		0x8D04D5F71612BADDULL,
		0x302D10BD0336E073ULL,
		0xA2DF7932BBB8D2D3ULL,
		0x7AE39996D0CD6AEBULL,
		0xA011E7C891B5FD1BULL,
		0xC98DE7923C091E33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DBDB0146AC5553CULL,
		0xA0D7F0A99A96703CULL,
		0xCE234E5DCA0A05F6ULL,
		0x25D6D6F308B4FDD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BD812A63967F209ULL,
		0x80A7799C355DBA57ULL,
		0x1B6E6BEB9487728AULL,
		0xEF62AB1CE642BA27ULL,
		0xE1B2F0F54FAAEF4DULL,
		0xDFDBE0C7DC39B3F6ULL,
		0x1F53CCF4D8319D00ULL,
		0x6FBD632E7690BE70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50613AFC2F13AC89ULL,
		0x0141C56C24EDBBBAULL,
		0x5EA00BCC29336C14ULL,
		0x383B4D48351FCD68ULL,
		0xC587AFCCB05E9CAFULL,
		0x44D084C3351B979EULL,
		0x8DEF7D9B4B942598ULL,
		0xBED7AA7DE61ECE1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09E283B1AFA8873FULL,
		0x83155CE0DEE833B1ULL,
		0x51B2276A4AB3BFFDULL,
		0x7940C80A220C9926ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C511B83CF05B2F8ULL,
		0x1FFF152B8A8ADE54ULL,
		0x0691EDFDA8FA9FD6ULL,
		0xACF1594A56593A0FULL,
		0xABD879D80F945494ULL,
		0x8260F97F8D391C69ULL,
		0xFAF67B42EC45F495ULL,
		0x8360B4247AE09863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x723B878562DC7F36ULL,
		0xA593F89A929AA831ULL,
		0x578E1DDCD60BEEBFULL,
		0x4A4BE0B9DE7A6887ULL,
		0x4B79972A14ED97E9ULL,
		0x1D239B6B610170FCULL,
		0x86C9559ED4DC46DEULL,
		0xC88F52EC085FF454ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x482B39D1A0E933A8ULL,
		0x8187138F8833A85FULL,
		0xEDB7667C4C9E7A4FULL,
		0x1DB9E6F176F72BD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF11A4D3596FFA70FULL,
		0x5E4E6F92A7CABB18ULL,
		0xE7690BC59ADCE28DULL,
		0x624D4F0876B7C5F3ULL,
		0x81CDD7E35EBCE99EULL,
		0x2047A319E05857D1ULL,
		0xD4695FF4A9E844EAULL,
		0x79AC10BC21837F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x265F6FE0121F08D8ULL,
		0x34C15FF60E476F46ULL,
		0x88521F38DB2ECB12ULL,
		0x49BBA642FDF17DE1ULL,
		0x5C7F452A542B40D1ULL,
		0x8DC5A6684BBC1E60ULL,
		0x903446A9095FDBA8ULL,
		0x464152C4C3604B44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5464A4CD167FADC2ULL,
		0xE8D891F8A8B3D29EULL,
		0x7EF8ADC693EDB736ULL,
		0x3A69DB7D720006F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD64D5BC87F8914EBULL,
		0x2E4D45414E0EF4ABULL,
		0x63BE6686E870705EULL,
		0xD6E4A083FFB6D4DCULL,
		0x9CADD19A5F35D416ULL,
		0x48BA321DC4C9ED90ULL,
		0x72E390334306D5CBULL,
		0xACFE5F323F3275F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35CDC98D41888A0ULL,
		0x05E918957A21FED8ULL,
		0x2C08EC9E7E210AF8ULL,
		0x7FC0A15E11E6775BULL,
		0x7EC2AD81B1598E72ULL,
		0xBC1FD88579FDDF45ULL,
		0xD21C08D9026FE5BFULL,
		0xD9A47E4F83B2A5E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63D7DAD97A22E1ACULL,
		0x074D7946EE3714F9ULL,
		0x1553914E00B7071DULL,
		0x367B60CDC2C94045ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC140B10A8F79A81ULL,
		0x3D08C62D50E94158ULL,
		0x7C94050E1AA59334ULL,
		0x357A98369040C49FULL,
		0x64421254F5E4C40FULL,
		0xB6A667DF4D62EEA9ULL,
		0xA7041E979D674C9EULL,
		0x1CCF085F7E27D921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254742D14D7BA3FEULL,
		0x0B04C9093B38CB76ULL,
		0x838F5BF46CE1F388ULL,
		0xDF60A27755FE65B4ULL,
		0x0A4FB7EC5FEDF392ULL,
		0x7E153F5E83DA3CB8ULL,
		0xC2C8656666E1DFEFULL,
		0xC591F32DE8AB629CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30C633C59E1EE535ULL,
		0x97900041FFFADFB6ULL,
		0xD9E22667C591C1AEULL,
		0x492B1B1B6ABBF6A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC587B45FE2251C02ULL,
		0x26FD41E2BB993F20ULL,
		0x9EE16B2C32796524ULL,
		0x86A46D969EC19E37ULL,
		0xB5904BFC001BCF51ULL,
		0xA2A41A68C6E2D24BULL,
		0xC3D56DD4918CA2E2ULL,
		0x54EE2EC90758896FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB71DB09A77C08853ULL,
		0xB066DB3B0119C2A0ULL,
		0x984C9E683E5737E4ULL,
		0x4F927E3342D78744ULL,
		0x51F2687D9BF471E4ULL,
		0x8AE473F50067884EULL,
		0x8C36CF2211A83C33ULL,
		0x1F36FCBD83951A21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7D9C888483C730DULL,
		0xFD091BD730CC781CULL,
		0x48205B42F0096B3CULL,
		0x30435D18EAEC9C8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D1459DAC0173685ULL,
		0x13537FB2A8DD17EDULL,
		0x297F1D6FD9D445FEULL,
		0x9F9CAC63ABA37CD9ULL,
		0x987081D95D9B2F77ULL,
		0x32856F0DB5A9F273ULL,
		0x2C5EF5A496A4C239ULL,
		0x3FAB31BD14BEEE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A77A681FC3B5F03ULL,
		0x926F21DAD03CDFB4ULL,
		0x500DE0A450E44402ULL,
		0x85D5CCB07C256718ULL,
		0x590B268529F33066ULL,
		0x65D2893598C0F9AAULL,
		0x663B54287E87B008ULL,
		0x14E07E0D51C31BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BA841D86ECBB4ECULL,
		0xE3727BEC23352618ULL,
		0x42BB35371D40B539ULL,
		0x73DD8BCA20DF4380ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEFF221CCA5CB77AULL,
		0xB8488A8B54D20991ULL,
		0x8094F8264EF93287ULL,
		0xC5C2B10714533997ULL,
		0x533F7625BC05DBBBULL,
		0xC4EA18D0FC2249B5ULL,
		0x8276E509AFD13673ULL,
		0x559B8CFBD1E0CBB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85450F751AADD205ULL,
		0xF9A6F60EBE47BF89ULL,
		0x528766CFD68DDBF4ULL,
		0xA878C67F1A22D168ULL,
		0xE08106384A0536B7ULL,
		0xCC8EDE2411421F50ULL,
		0x370A399CD0A650EFULL,
		0x2702556E6A7EBE69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31FEAFE69BC76517ULL,
		0x9C2C4A2773D094F1ULL,
		0x602F037F98C96829ULL,
		0x0808298552BE621AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E3BF6E82A75BAA2ULL,
		0xDB67C7CDFA25605AULL,
		0x3B5C1F1BD854D302ULL,
		0x79746932E5F8063CULL,
		0x2F025B3FB73C7947ULL,
		0x97543C86F724AE63ULL,
		0x62E8A8BDBC30B82FULL,
		0x61C900D4409F15E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B5BA76E7808721ULL,
		0x1770C6FF50B6E853ULL,
		0x1E5AFDD80C4B96A0ULL,
		0x75E07DB12AA7B68EULL,
		0x692C46204082BE88ULL,
		0xCE2A91923F48252EULL,
		0xB6F286E708C65953ULL,
		0xB982C8841BCE12F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x194D5F1CE286E9DAULL,
		0xA0266121F42AD5DCULL,
		0xA38A27226DD35102ULL,
		0x7E0047673256C04BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA461A1106088C21EULL,
		0x007A2F3C5A106F75ULL,
		0x5A0D43C031946CA7ULL,
		0xAF90EF0C31246C6CULL,
		0x65BD3BB6ABB5D90AULL,
		0xB5E1C3ECD3685C96ULL,
		0x7D1ADC11E68F39EDULL,
		0x110C61B8FC81DA2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A151920BA5D614BULL,
		0x006F537C8E532E9DULL,
		0x54882E45FFD37DA6ULL,
		0x1DD90F72C8183CAFULL,
		0x10D633060B2AECC8ULL,
		0x14B912BF4F1E88BEULL,
		0x72ECC5CDE64D9520ULL,
		0x6AE80243B54BBA57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF497D2277ACA70B1ULL,
		0xEC1528816EB2B2F4ULL,
		0x885C63923B7F6586ULL,
		0x3B1E0B01FB14E9A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78B99723178D3BC6ULL,
		0x5E67BE34F7BBC21FULL,
		0x53B7A6181853382EULL,
		0xD3D017A6D14767B7ULL,
		0xBB15090DC62CF61BULL,
		0x0E86B26442BF4445ULL,
		0xA34AFF6543C56F7FULL,
		0xA8555A7B05272F7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8669ED46D6F235ULL,
		0xEDDB62C21E6E4184ULL,
		0x6C4AB75CF9AB799CULL,
		0xD1035E01DB7D7DA0ULL,
		0x985066CB74C6A2B5ULL,
		0x7AC5AB8AB3D311D5ULL,
		0x75D012A43FB0FB77ULL,
		0x41B689B110C283F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6263430DE5E6ACEFULL,
		0x5F335FBE105CFD40ULL,
		0xA7AC1361B9B0F7B1ULL,
		0x3E5FB79F3CBB5FB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B9865638F8AB653ULL,
		0x43BB5FEE5B3AF945ULL,
		0xFE6FA2171A2D4D3BULL,
		0xC70BE1ADBBF1F612ULL,
		0x4FD9F036BE8E77F1ULL,
		0xD7ACA2D6EEED2C43ULL,
		0x6064E04DC3A700ADULL,
		0x17F31F2C5F742A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E7522B8F15CF5CULL,
		0xF0BBC5FB40AE97FAULL,
		0x4658F3318BD2733FULL,
		0xAA3CF9E2DCBDBDABULL,
		0x60BB11B564D5D559ULL,
		0x611B71077C2D8B41ULL,
		0x91C3FD89F51EB6E1ULL,
		0x8326C6F69230F8DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1461A6B51DD0727ULL,
		0xEC8CFEBE22FE4794ULL,
		0x63F857F63695CE54ULL,
		0x3323FFC7572D993EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA563F20A167AD47ULL,
		0x96EFC04BBECD7413ULL,
		0xEED3F9C0B210D368ULL,
		0x6C7583283DCB279EULL,
		0xD801BACE549369A5ULL,
		0x74F144863A9F5F4EULL,
		0x0A66F9C1476E5D24ULL,
		0x258E63F2D3552518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A0BFF5ED5ED25CDULL,
		0x897B250BDDB7D751ULL,
		0xEC5DD5541CA231AEULL,
		0x6D09580247E6D39DULL,
		0xAF9A76C97A7C890AULL,
		0x82D9E58A7E33A112ULL,
		0x65813EBB95471E85ULL,
		0x799BBCD9C27C15F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF9E587A2ADFDCA1ULL,
		0xFCECB49DD913D9B0ULL,
		0x7C8FE7450741ED51ULL,
		0x0570F8DE761C93E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x912FE806A5EC6BC9ULL,
		0xB8FC065339E773D3ULL,
		0x31B100B5A799F230ULL,
		0x9EF4E406DFDE60EAULL,
		0x4ED421669ADF45DFULL,
		0x58EE744520994B76ULL,
		0x4D89F3277B7E2F88ULL,
		0xC8068CB84B68FC0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0124596C12B397CBULL,
		0x328EA016EDB10636ULL,
		0xFBE01CBA07EAA6ABULL,
		0x97A43597C14F73FAULL,
		0x269E8BAF67EB2398ULL,
		0x3D524ED4041C1D6AULL,
		0xB0B5019A4181BCE9ULL,
		0xF7B457A07652EE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87FFC7CC2375E96BULL,
		0x9F9AF50686CB436BULL,
		0x7D6CBEF23B284F23ULL,
		0x73848FF8BFD4FAF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x460A34A91D41C207ULL,
		0x4F564FBA0511DB5BULL,
		0xB44D1550BF5329B2ULL,
		0x5CB89F93434260C2ULL,
		0xA81D0D2ADAA1B7F6ULL,
		0x559CAE06EF1F78DFULL,
		0x1332CF98D9A82B0FULL,
		0x91CE2DE853295673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D1212749D7C007ULL,
		0xEB680773830687FAULL,
		0xA57BE3B2BCD6CCECULL,
		0x701D53872C742E41ULL,
		0xF120940AB08820EBULL,
		0xAD86C7AE60E96C1BULL,
		0x939D34960C2BC7C7ULL,
		0x0C7F3B2019B34299ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7B30E4813367087ULL,
		0x572E796B9E11386DULL,
		0xFF06340882F31968ULL,
		0x365355C49E5524C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE2685530036DE23ULL,
		0xD73CDEDCE37BD9C2ULL,
		0x17C6DEB25DCA9BEBULL,
		0x73A499D942AD0719ULL,
		0xB9C52D53EB593518ULL,
		0x15EEDC2B7A235E9BULL,
		0x19B5E021DBF50CAAULL,
		0x2F4BAA68B1D66BF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E46EFA1F82FFB53ULL,
		0xA3B720A1543BBB1FULL,
		0x93557831EA0BB0EFULL,
		0x5E838F37089ED583ULL,
		0x4A811B089BBEF750ULL,
		0x55D40E5C3EB3D67BULL,
		0x02254DC213EEB5B4ULL,
		0x12D332520CE7EBA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3FA4CDED8EC0F18ULL,
		0xB7804AFE61CE5373ULL,
		0x03E720B824AFD376ULL,
		0x4F02DDFEB5753C95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC378453B06165EFBULL,
		0xEEBBE12D41865EC8ULL,
		0x3B21A04DD676AD19ULL,
		0x9B568B80E36B1E31ULL,
		0x659C0E551E205BD2ULL,
		0x3F7901CB3D6FF076ULL,
		0x8E3940D73FA92273ULL,
		0xF7BA32F5CD0B8BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCCF5994F26BB7CULL,
		0x123746B0AA0BAE05ULL,
		0xC83AAB2546C01130ULL,
		0xABEEA9D1ED4A7333ULL,
		0x1E4069A25EAD3A84ULL,
		0x93BBB874D9186F92ULL,
		0x3CA1B650159C0CF6ULL,
		0xC725DABCF9EF9FA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE45C22A2206961DULL,
		0x5A9D7D4F7C77D2A5ULL,
		0x8F658538CDA7CC6BULL,
		0x256CFA1E4C45B699ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07A90BA50EE0083DULL,
		0x35B8215222B030FAULL,
		0x9896296550D9A47FULL,
		0x3321338CE61E9A08ULL,
		0x71CCE6D43B744B92ULL,
		0xD11C6FDCD5FD43F1ULL,
		0x1FEC8F78987CBAC8ULL,
		0xE44D32716AFD7040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD37B6D2B0FF93019ULL,
		0x677BC2E0DB254866ULL,
		0x60D5337D7E681342ULL,
		0x1245016D2B15BFC2ULL,
		0x78EA365E1C83F3D2ULL,
		0x48F4DBD955713020ULL,
		0x1BBEAB3C077AAE18ULL,
		0xA39999DEBBE8DD1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25D3D0029693E00DULL,
		0x041C56F65C55D998ULL,
		0xD690D6E558BF7371ULL,
		0x3B84D7E5B816B178ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8D3C90F18B4A609ULL,
		0x34081BCF125A39A8ULL,
		0x0F36F5776539C29CULL,
		0x0BDBCAE5CBE1FF2CULL,
		0x669570DFDCBFD63DULL,
		0x17C691AC74954A4AULL,
		0x38C4C50AE50F1DC9ULL,
		0x77D69239D36FCE92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9605DD483A992B6BULL,
		0xC6FCC0FB66D002AEULL,
		0xF0AD505D2CD5032FULL,
		0x33F9116865398B85ULL,
		0x4ACEB3E12EDD5FCEULL,
		0xF8A782DBE2903715ULL,
		0xEDCBC9BDC5B67BB4ULL,
		0x3356E743A99094A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x724DF994ADB91094ULL,
		0x0BA78DC9584B10DCULL,
		0x3F7EF28CDF8CCE69ULL,
		0x02D61A079DCB0D05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40E5A564360AB298ULL,
		0x0AD0AC46F2736E74ULL,
		0xC904E1772D0E8164ULL,
		0x37EBA1489E86618AULL,
		0x34146BCCB492D39BULL,
		0x5CA90FD99C7AE075ULL,
		0xBA104EFCA00A322AULL,
		0x5B63B00FFD23D04AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E447C95C48CD253ULL,
		0xBB5EDD74F9F5603FULL,
		0xB4C4145F8922AD0CULL,
		0xCE33A7D0345B7321ULL,
		0x0C71EA4DE0856327ULL,
		0x04D0D76EA248EC0AULL,
		0x89F16D41C781C15FULL,
		0x19E84A018BAA9EBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94C061A1EB7C92D3ULL,
		0x598A2EB31BE8561CULL,
		0x38D64ED3C82C9286ULL,
		0x22091F9D42284912ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x239D21C1B41D71E7ULL,
		0xA6E1CC26E691E1CCULL,
		0xCD165271C9E33C4EULL,
		0x332AA340DE30EFC3ULL,
		0x1FC5A9803866119FULL,
		0xA79FF93868461BD8ULL,
		0xF94A420FA8165AEFULL,
		0x065F4955EF15EB5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FEABED4035BB051ULL,
		0x655EA8C44C4C11C0ULL,
		0xEABBD478544A8E5BULL,
		0xC1B3158C1C3CDA48ULL,
		0xAC809EDA37CA9AEEULL,
		0xDF5D5E3EEFCF1EBEULL,
		0x8CBFBDA6DD8F1F1DULL,
		0xF5403710F3F70A03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFF1F791C7D55A71ULL,
		0xFB66246A7BEF61D2ULL,
		0xFEEA258785AB8F16ULL,
		0x7C1443F208898932ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD04F5172A95AAAA4ULL,
		0x82E36531342F2770ULL,
		0x363D4915AA1A2672ULL,
		0xBA79D511659B94DCULL,
		0xFFEDD6B77BEC9942ULL,
		0x7C682AB957DB7B9AULL,
		0xEAD8B24F9EFF66CDULL,
		0x9543D56D772A070CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B14318965EC431FULL,
		0xFC5A56B04CFCD3ADULL,
		0xDF3DBC12BF3897D2ULL,
		0x8BAE926A12A50344ULL,
		0x2B2B49B51A995382ULL,
		0x83C5EA39D994EC61ULL,
		0x08F48915B5E0DC84ULL,
		0x0CF3741E73A837C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A1C0E43B5CAC4FDULL,
		0x6E9EA16DA5AB9659ULL,
		0xDEDDAB9B856A1574ULL,
		0x6AB9B461D83B55F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4867F5478377BE57ULL,
		0x30A82DE18C7E83C3ULL,
		0xB021BC535684ECEDULL,
		0x1C2B75BE78402615ULL,
		0x0A87C7DD7C7C4006ULL,
		0xD6298B7B837A0322ULL,
		0xD923FBDCC469FF23ULL,
		0x4623CE1BA644D122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E616789CD4A83BAULL,
		0xC545C1A89E9CC0BDULL,
		0x1346B318EC1BC042ULL,
		0x6FC524B1443ECA17ULL,
		0x4727D5F5101FAFFBULL,
		0x4EC5E00B0E9D72A0ULL,
		0x3BACC660B332E3E1ULL,
		0x42B196B08B2222A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA44763DCBEA9C3FULL,
		0x842DDEEA469F3648ULL,
		0xFC8CF9A4F897388AULL,
		0x2F5A8AF33B274257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3CB2445B5EA23D6ULL,
		0x17028C06BE44CC40ULL,
		0x1E32ED7D46EEA7D9ULL,
		0xAC64BEC6E39741F8ULL,
		0x47764E625EF4CC60ULL,
		0x8831108D1206E7DCULL,
		0x1D57FB7F7542D484ULL,
		0x2147D0967F67E916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B0A3EE47B998B4ULL,
		0xB2710BA711551639ULL,
		0x81ED003293DCDF88ULL,
		0xDE45162AC9BDB7AFULL,
		0xB86D44C28398ED6FULL,
		0x20E5C135D2FD5A67ULL,
		0xDA14714CAC8F0B3AULL,
		0xF9B1C7AD24574B39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED71EE11FDD39E15ULL,
		0xB9BF4753085AB553ULL,
		0x984C70D47DC1A95BULL,
		0x2E64FB3F9E50F8FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39E87434643FB0FEULL,
		0x9F0121542FADF57AULL,
		0x6620DC32B8A9FC2EULL,
		0x7F0F65FE45D6EB17ULL,
		0xBB3892E6ED44936EULL,
		0x8261B33CDA4F8D7AULL,
		0xA44FDE46AE858EECULL,
		0xF106321354634AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5DF6BA2DDC230ECULL,
		0x12343A7E40A35F6DULL,
		0xFF0EDC6FB1BB2398ULL,
		0x8782BF53B566FDB8ULL,
		0x822F6DFC0BAEEBA6ULL,
		0x834D9721D43739D1ULL,
		0x90DB495683951B18ULL,
		0xE245400F7CE262ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB64836F02B4680EULL,
		0x69C912D8D6A7012AULL,
		0x4A601B6966A00A0EULL,
		0x2830933C8D92542DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89B2DC31AF0F3DFEULL,
		0xEB9EEFF26CCD4C53ULL,
		0x622267470B14444AULL,
		0x08C7962F8EA98305ULL,
		0x6BBAF39896DA1805ULL,
		0xD27DFDE19E274375ULL,
		0x6764E2D4BF651974ULL,
		0x2E2B5909907444B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EE0E2D5AA33CD38ULL,
		0x929CAD269FAC4C14ULL,
		0x5F1A5ECD4DA1F970ULL,
		0xCD8E8331BF29FA4CULL,
		0xC9C32B77620BA31FULL,
		0xB41CBBFFBE0D3F8AULL,
		0xABE2CD94403FC2C4ULL,
		0x1ABD0879A0A53E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF599AE49DB80CB36ULL,
		0xDB720A5310FD9512ULL,
		0xD857300C9CFD28FEULL,
		0x1D99085B683A7FD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x144F578085570894ULL,
		0x5C34ACCAC5F92808ULL,
		0x9067EEB927BA4F20ULL,
		0xE1392BE43C29065AULL,
		0xDC37AF22B56877CFULL,
		0x8EC497D39FB2F33EULL,
		0x9071247222EAA120ULL,
		0xD7B2E13B07419CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E1EDA8CD859F08ULL,
		0x5CEC089734D428A7ULL,
		0xFC3EFFCCDC6C24DEULL,
		0xA7FBA52E854AAF0AULL,
		0x85F7695427246C1BULL,
		0x140E9106B62B00EAULL,
		0x79A2F5503AC7E02AULL,
		0xF201DAA1E605B31CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAF7C680D5EB25ACULL,
		0x364DA69E3B52F7E5ULL,
		0xF6C3EDF4C076CED8ULL,
		0x51848170A5C3034AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ABABBBED150E57BULL,
		0x4F348DC67FD00E7CULL,
		0xB99730B4DE07BE10ULL,
		0x65A488C4CD684DFDULL,
		0x25139C8BCFC71C80ULL,
		0x2F4BC2FEEF868328ULL,
		0x1EAC6999478DB03DULL,
		0xA759ACE3B4F5FA35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60EEA64108A6CF47ULL,
		0x4014B7C97CC63F30ULL,
		0xCBF27F0E7A75CA55ULL,
		0xF56B791E3DADFC8FULL,
		0x2D69220176C7C6D8ULL,
		0x73357DC9C8D0BAF4ULL,
		0x8BE6219A8185EC58ULL,
		0x43D2A2E3965D3CE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD1A4606FE90CF38ULL,
		0xFA6E1BE0C2058702ULL,
		0xB7136177C8B907AEULL,
		0x36448BAB1A666B63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6CCBDBB27A142CCULL,
		0xCBAB144158981537ULL,
		0x2D87D6C95B911F22ULL,
		0xD0C9479217BCB50BULL,
		0xC297402899E17417ULL,
		0x9755D75DD4C09BB3ULL,
		0x8FA467C52CF51655ULL,
		0x8013D4211CBFADB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x038BAFD5A8CA66CFULL,
		0x86D1AE78A8B48501ULL,
		0x71F810F7E1C50415ULL,
		0xCBB32AC31A05E01AULL,
		0x790A3C89FDCF3182ULL,
		0xA717ED4674C6AAB3ULL,
		0x9AA54FAAD3D4B6A8ULL,
		0xEB76CC866D3FBFBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE2F9770A98CBBBBULL,
		0xEE0A2540EEFD5641ULL,
		0x196D59BAB49A4EB8ULL,
		0x14653DC50AB4287DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A841601A142BAA3ULL,
		0x0CD5FD5F270DAE92ULL,
		0xC2C74A308170A371ULL,
		0x767C461BE94F9E9AULL,
		0x76711465C39ED7E5ULL,
		0x011485C5A05B952AULL,
		0x2D6682671B8EF2A4ULL,
		0x01B478066F7BB513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8298AEE4074C6981ULL,
		0xDFAD149EC69B73A3ULL,
		0x8FD6149CD0378C26ULL,
		0x54963CE0A47E4986ULL,
		0x551689E18063A17CULL,
		0x3401ADF2DB0F0021ULL,
		0xFA5F014098C8115CULL,
		0xEDD9E59B64299E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB5BF6BF94C05F86ULL,
		0x9DF4F209A9D05A49ULL,
		0xC60E614B1ABE87F2ULL,
		0x1457C51EF300B633ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80D826963CF6F5B0ULL,
		0xDD4532CFBF6CBD54ULL,
		0x0622EF6F07054AD1ULL,
		0x688147C9AE092724ULL,
		0xF97364D833F006EBULL,
		0x0870A74CEB72195EULL,
		0x483936396C37E213ULL,
		0x8603EECCD17D3F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B7052EB737782CULL,
		0xAC896BA04997F86BULL,
		0xAE79394C5183F16DULL,
		0x2CD21DABB48A0EA7ULL,
		0xD2FF46835001B5A9ULL,
		0x65CA5DD9EB39E8E2ULL,
		0x70CAC947486011EBULL,
		0x1A8401FDD8359320ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF5DA2015B1F8FB0ULL,
		0x556AAE417E2BF756ULL,
		0x520DE214078A3F46ULL,
		0x30AC50D6FA22A2D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D845AE52D2C3742ULL,
		0xA0B92CB35CE4921BULL,
		0xD3E02E2BBC02F894ULL,
		0x81F80D4C4EA1D083ULL,
		0xB7A80D2D580CC6FDULL,
		0xA318ACAAFC0881DFULL,
		0xCE39D28E09470EC5ULL,
		0xF244CB9A21881050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B04FC36DC3A5BFULL,
		0x20C1095A4DFD93D5ULL,
		0xA0621F62F0945383ULL,
		0x2EDF6F080CAE09CBULL,
		0x829100F18F55379EULL,
		0x77EECF09310387E7ULL,
		0x692B1A79E2AA5C71ULL,
		0x281E9421E3AB6B59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B3FDC018AA7DE11ULL,
		0xE82F095D31A4191EULL,
		0x33AD61C686B11D8FULL,
		0x54C4DA1D70B44371ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E84936B1CCC30F4ULL,
		0xC138C9F95A6598EDULL,
		0x7A10E49FC361DC2DULL,
		0x2FB096A0A3020C75ULL,
		0xE96F603B432C2853ULL,
		0x465911861401EBC9ULL,
		0x4F481C59AE1E05DCULL,
		0xFAF705C9B57538BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FFA704EF450117FULL,
		0xD6B04A73E3566760ULL,
		0x96CE0082E681BBA8ULL,
		0xDAC1E055932D551EULL,
		0x937904F00383910BULL,
		0xAC69FDEC1DBB4ECAULL,
		0x4AA6608A83B92DC2ULL,
		0x1F08B03331061CECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC11BB0479B8298D2ULL,
		0xC4056860058A7F73ULL,
		0x9344C4DD27D83451ULL,
		0x7A4F6AA2B852D837ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CAC2A561F73A562ULL,
		0x321602ACA7EAA97FULL,
		0xAF790E75076087A3ULL,
		0x078DC29C19A3A810ULL,
		0x353C33698188ABC6ULL,
		0xB33575150B3851A4ULL,
		0x22DC383D429D86DAULL,
		0x42272E78A4159901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91A671C6A03B877CULL,
		0x3672EE0F074517B8ULL,
		0xE33EF49DA20AB93AULL,
		0xDA59B07C1E288471ULL,
		0xC6595A423EB6E0F1ULL,
		0x20EB1A1AEF0792E1ULL,
		0x5C83975C8D468E9BULL,
		0x6B47D4BAFD0FEB4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70B1F4636A5C387AULL,
		0xB2AC95BDCFE1E2A3ULL,
		0x3D61FB32503EA7D8ULL,
		0x125B6446C652EC9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1E55CF0C2B19874ULL,
		0x87380004E99F8AD2ULL,
		0xA178AB318E1B8FA9ULL,
		0xA6FE6343D1106D8FULL,
		0x371CE1303AF28185ULL,
		0x064BDDC54823314BULL,
		0x6BE21D0B5F5EE329ULL,
		0x6CF2093C8E348E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2628357DA613B47ULL,
		0x62CD97D174A98956ULL,
		0x927B368FBB70588EULL,
		0x1B3DF12958EABF6EULL,
		0xACEF895F1ACF5719ULL,
		0xF1FD9AB4552A69A6ULL,
		0x9B1519CE3582C61DULL,
		0x85265BDC4B4CCF8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA23DE2A3AD88A8B0ULL,
		0x28085CB785E3A3E8ULL,
		0x0D6BEFB6095786C0ULL,
		0x73FC2E64668BFBC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5FEC744627B69E5ULL,
		0x9E1790D7251DFB3FULL,
		0x01C9D4F899DAE445ULL,
		0xB693017D8BBA1887ULL,
		0x5FA5CB6FFAFD0FC3ULL,
		0x24E7723175AEDE56ULL,
		0xC96C6D57FAC79859ULL,
		0xEAB680B39ECD77C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85597193A6B6DB7AULL,
		0xFBFDCA094C03DFEDULL,
		0xA676D84D7D8FB31FULL,
		0x0814D185035A79B9ULL,
		0x1186A165E672720CULL,
		0x64A2101CBF8740CDULL,
		0xC29567DA75852F0FULL,
		0x92572A9B3C1CA8C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC945932FC857F996ULL,
		0x2C6655E0E2FB7DB3ULL,
		0x5F3DCD4CE426D218ULL,
		0x4CA4F7972E9E58A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AFB6DC8A11ED3D8ULL,
		0x0212B237C87F9D53ULL,
		0x66B577C5B86B12EFULL,
		0x437D6CA5975D07E1ULL,
		0x2EE4F69AC4B17034ULL,
		0x03E97239E97F8B16ULL,
		0xC6FFDDE7B098702AULL,
		0x79D5AEB052A119D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85F3535364E124E1ULL,
		0x7A109EB2AFF89DC2ULL,
		0x0B5550D718C60A9AULL,
		0x65CCF23FDBA10E76ULL,
		0x96E9DFE42D6348A2ULL,
		0xC212EA4BE1F9ADFFULL,
		0xF90EA01EDCAAEF0FULL,
		0x43C232E43A65735AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x344D798FB1D78FC0ULL,
		0x4DDA40DA3665D0EBULL,
		0xED2F52BE14E6323AULL,
		0x6494DAB15496AF33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A57EA0F2A5DC4FAULL,
		0xB16B31F27A936056ULL,
		0xBB00D245C1B8F36AULL,
		0xB11F74E77C5AE576ULL,
		0x0B2314992FDCE822ULL,
		0xA909D37F4C6F8649ULL,
		0x3E48D96ABAF5A359ULL,
		0xAF448BDDF0980DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49F6157D7B48487ULL,
		0xEAE5F6318526F423ULL,
		0x2DFFA7D271778A4AULL,
		0xC620608C121D5185ULL,
		0x4C1637BED6FA1A18ULL,
		0x82E1E69D7F847610ULL,
		0x3DB3C56D1164AA71ULL,
		0xA605E9D4CD2D944FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1A151208453D615ULL,
		0x707265456050D49EULL,
		0xA322221A7BC65B95ULL,
		0x4A4B21B6AC0BA0F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F13FBE44645FD89ULL,
		0x6C08A786A25CD320ULL,
		0x77384149ED1A1030ULL,
		0xA7686832E4A503B6ULL,
		0xF05061EE79FCD5CCULL,
		0x4BFE2664EF7DF414ULL,
		0x051C24702E0316A9ULL,
		0x463BD35EFEEB7ED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x451198029E766973ULL,
		0x3BBFDCF308ED4B80ULL,
		0x2EE1558E90474F25ULL,
		0xDE9DFFD74A7D3C65ULL,
		0x6F730A493E581BC8ULL,
		0xA745EDC7E37A1991ULL,
		0xC8FFDBD04A851EC8ULL,
		0xB3D86595A605E891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ADD666882432E3BULL,
		0xA3A131E36201F725ULL,
		0x3489B37721858C63ULL,
		0x038CB43ECC3C1526ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x510BF850C8125CB5ULL,
		0x4B61E6F4F4FE4741ULL,
		0x7310D522A5A5EC94ULL,
		0xFFE7EA46AF840D78ULL,
		0xE3225A31E59996DCULL,
		0x6BB9D7E91A3B3126ULL,
		0x5663903B730F5934ULL,
		0x3E3AB7A53E74C039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0900CB8C85235C5ULL,
		0x416EB6AB16C2A98BULL,
		0xD62D37D954EC0B11ULL,
		0xE6D600B771F754E7ULL,
		0xB139D876738507E1ULL,
		0x29FF4E2843DB3BBCULL,
		0x10EA541AD3C4CAF8ULL,
		0xB44A2CF44F3B8490ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8FF2D6AEECD5D99ULL,
		0xCBA3A2E9B07A0B78ULL,
		0xECE28A20F5CAFE74ULL,
		0x12C67FD2C00B93B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0D3F87955B07858ULL,
		0x737356CF3CF4718CULL,
		0xD197AB83FC36F49BULL,
		0xD1B769D1DEE8062AULL,
		0x1CDD4AA9F4FAEBA1ULL,
		0x5617C2D79D19088DULL,
		0x743EE89AD87E1274ULL,
		0x98E4CCBD949F69DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39DC178E2F73F1A6ULL,
		0xEA81AEA80C710A20ULL,
		0x035EBCE3744B1B39ULL,
		0x476F5AB6171D5A53ULL,
		0x75563098BFF34608ULL,
		0xA482EF0CF09A3D94ULL,
		0x096997993D333CA4ULL,
		0x71A3859061EFDF05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4505BF79055F1C4CULL,
		0xE509183CCB558855ULL,
		0xA9E2F4DD95079635ULL,
		0x5DF89FD14DD94843ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E3DB34E3B00C61AULL,
		0x69953EFA921E62F6ULL,
		0x5EEC7DB819EB2314ULL,
		0x314E43EEDB674F13ULL,
		0xD576D5DDB1B7A634ULL,
		0x9307AE0680896AF3ULL,
		0x1DEC58EE4444F072ULL,
		0x23A0C69AD27DCE90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C9EEBF317B37179ULL,
		0x3887FB1103C652D4ULL,
		0x290D76343999900DULL,
		0xDCD7DFE29AEAE8CBULL,
		0xBEEAEA10AB8D874CULL,
		0x404A5FADDBB0D77BULL,
		0x98562A6023F92950ULL,
		0xD4BF9E268DADFBE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A63C7CA0D8DE70FULL,
		0x7926E512067DF3F5ULL,
		0x0A29F09CAB91221FULL,
		0x09E2654E7755AC56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3876E4495BBC66E5ULL,
		0x9B5A2E460B074921ULL,
		0x0E2B0D37A0421CC6ULL,
		0xA242425DDFF74F0FULL,
		0x0B2A34A976EF262FULL,
		0xD1CF0BD96FBDA26BULL,
		0x45713EDF7FB672A7ULL,
		0xDA166B72C2928DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886C8281DF6EE34CULL,
		0xA8B64E025CEC9846ULL,
		0x804F35307149F0E6ULL,
		0x6BE28E2A7F152155ULL,
		0x426BB852B23ABF41ULL,
		0x59C3994316244F09ULL,
		0x6C7A4BDC12D75724ULL,
		0x40A867206ADAEE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C50D6A8AF14CE44ULL,
		0xC456E294FADD115EULL,
		0xC283EA8958164163ULL,
		0x7CB4586C6623DAD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5228F63B4D176B7BULL,
		0x37002369F23BCDDDULL,
		0xA926E2AC7C1DD815ULL,
		0x6522D6707BC3A517ULL,
		0x519A60752FB5C4A9ULL,
		0xE0F51820F634E471ULL,
		0x4352DCC26FD69572ULL,
		0xCE963258A6B42287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1FE0F445E58D769ULL,
		0xEC8CEEF81AF7C57BULL,
		0x0DE1D0F56D30B277ULL,
		0x0D8CA35ED818266EULL,
		0x910C9969A27CF9C0ULL,
		0x20873D7400ED4BA5ULL,
		0x86B0A33F27637D6CULL,
		0x55F6AB960EC01F9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x353672ADE52CB554ULL,
		0xDAC1AA1E3FE4B6A0ULL,
		0x9B599B33D002B69DULL,
		0x3F4433F431E3ED0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3B793CC80CBDD0CULL,
		0x897F1649A629DD6EULL,
		0x4327CB4253C63DF4ULL,
		0x73CCDA119FF3AC84ULL,
		0x8DF66A7380D807C8ULL,
		0xA3A6DECBD5E5CAA0ULL,
		0x792E15BA26D4F154ULL,
		0x5378EA2D3BDBBB4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x937133E9AE36B71BULL,
		0x5647867C57B96F61ULL,
		0x9F3B2B3349E2F166ULL,
		0x93FCE0F180F4F673ULL,
		0xE33C37FA5542458FULL,
		0xBBF646048461C923ULL,
		0xAD9F5BC0EA18D7B2ULL,
		0xD667D022D10C5BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7E9DDDF4ACFF76FULL,
		0x976E3D636808A68EULL,
		0xDB1C3B0E0DCF1A96ULL,
		0x7059D6ABF9C6DF2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B131CB6D9EAE78DULL,
		0x843CE952E7D62869ULL,
		0xA31E8D7A0654A9F0ULL,
		0x9C0F41B2CD2BC367ULL,
		0x812C67D9DA955228ULL,
		0x953B1758DFE5D424ULL,
		0x81AC95A57C8FBD26ULL,
		0x880AFB8BDED7B1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6558890326505463ULL,
		0x78DD977724FD1285ULL,
		0x85606D0265378812ULL,
		0x19C4454FC6CCD7B3ULL,
		0x37FFA8A54509AAA3ULL,
		0xB964DF0372004308ULL,
		0xD9F08183069D5CCCULL,
		0xAF75C9C084499AAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x925EF581E6557017ULL,
		0xAD2BAE8A12ECA016ULL,
		0x03A91D9523176F34ULL,
		0x28706092777658EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x531BA39F48B10BCBULL,
		0xB59ACE3C440AEBFEULL,
		0xEEFD12EDA0CCB480ULL,
		0x6FC44D2C6F9DC8EAULL,
		0xAB8417810CF693C6ULL,
		0x272C55FCCECE5807ULL,
		0xC0A112C7DDDAB95AULL,
		0xBEC66B11F60EFE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AC9FCB8392B3CFULL,
		0x6F4849C25EDAC058ULL,
		0x6B0580691A6A7C67ULL,
		0x7D0E3FD8C7BD9689ULL,
		0xAF21FA3F7B6D87AEULL,
		0xDA815D8651C880E6ULL,
		0x050654C61EA61D41ULL,
		0x96F331CB886EC996ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6FF5B8F5F76245DULL,
		0xA7B36610740E1A8AULL,
		0x5CEFC6C6E83163B4ULL,
		0x5C108DC7EDA81187ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECC89C2C35731EC1ULL,
		0x3682BAF01EC6F1F8ULL,
		0x7FB434E7865B7EEBULL,
		0x14608E3379C8320AULL,
		0x090D92FA0DE2A9BAULL,
		0x611E0484D1349873ULL,
		0x94F62FC662F62C52ULL,
		0x422A0D3AEF039059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2650F5ED27E76921ULL,
		0x3BC801EB20D97927ULL,
		0xAA29978D0A9D9D8AULL,
		0xF5FAABA2B8C56BE9ULL,
		0xB4372518ACA42E1BULL,
		0x5083AB6096CDB79AULL,
		0x675BE928A4952FFEULL,
		0xB3E9242CC2BDF098ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E4BF5B37CD20C8EULL,
		0x71A3F465A932D8EEULL,
		0x9A7118C4BE2355DBULL,
		0x3C087AAB53587CCDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE40935A32753264CULL,
		0x5FE958122047F246ULL,
		0x914895AE30EB9AFFULL,
		0x29AAB43C8C97A26DULL,
		0x8ED4613EB18147C6ULL,
		0x8268DEADE31595F9ULL,
		0x619B9D8D206E3CDAULL,
		0x24B668BE2650CCBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A589E38949C5EE2ULL,
		0xA03A744DA4B800E9ULL,
		0x8B7E6797F7474805ULL,
		0xA3AE8581CD0D5FF8ULL,
		0x32605177FA1B9A4DULL,
		0x0934314897D23AAAULL,
		0xEE861C10DDBEFBDAULL,
		0xE001390715DA4E3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42EAEEE9CBCE8325ULL,
		0xBD80A0CDA78F7F25ULL,
		0x1AFB66881FA7F90BULL,
		0x38E143E7312109ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86FEAC3F28E784A4ULL,
		0xFE5DBB4822E39A02ULL,
		0x7F13B561CF0DBA63ULL,
		0x2045703C7F2D87B0ULL,
		0x9B1F288DB43B44E1ULL,
		0xF355903F528947DFULL,
		0x778836C414EAF972ULL,
		0x3A561FD9F930F7D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F228348525259AULL,
		0xD465D54F96C19F08ULL,
		0xDE9B1708323117ECULL,
		0xC571286ACE537446ULL,
		0x6254574455CA595AULL,
		0x0741FE5923614FEBULL,
		0x39566DEB92B5E6F7ULL,
		0xA0F4891C9CE6CBE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD12794EEA88552B4ULL,
		0x34DF8E238C10C93AULL,
		0xDBDC6E7CF0BD60DCULL,
		0x1F50A7ED63DC9854ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED75EE049CC1FD73ULL,
		0x62E8260BAE130906ULL,
		0x96DF84668B687D82ULL,
		0x6B1545435A13E3EBULL,
		0x596E4DAAF2539526ULL,
		0xDD7E706BF8A80ECEULL,
		0x4E88A4C1815243BDULL,
		0xF4528DD703BA765DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC131E43EC42E6396ULL,
		0x5A430DEC8BE7A40AULL,
		0x705883CC15603FCAULL,
		0x37EC2476533E9B0DULL,
		0x4A849DAE445CC339ULL,
		0xDEF790E1D121CF43ULL,
		0xEFF0A5B24C281EA0ULL,
		0xD7418FC377C533E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62F42947AB36C3B6ULL,
		0xD0AA46A10018D3A0ULL,
		0x3116DCDC5A49C005ULL,
		0x03AED7B3CD3D272EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2866FEE3712BD08EULL,
		0xD6EA96D7C0498385ULL,
		0x78C4D7A57ADD27E2ULL,
		0x4E3C806F3A72505CULL,
		0x4E26C1ABBEE58411ULL,
		0x74791C4D15FF9664ULL,
		0xC0C42AF1852811D4ULL,
		0xB3444B5A8FDD460FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC65C3038ABA077ULL,
		0x1E917008602C02AAULL,
		0x1E9D6232321F427FULL,
		0xF742E682152B5C48ULL,
		0xF071D83F251EB08AULL,
		0x839353D69A4BB3DDULL,
		0x8964CD9BA2F2608CULL,
		0xF8FD28B73002A443ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x427B48D20C03946CULL,
		0x7A74E865BCD120CCULL,
		0x924F5032DCB63611ULL,
		0x7D88BE2D5FBAF864ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x961028BAF4CE104CULL,
		0x6B8A0A11E3D76228ULL,
		0x8D7DDF69EBE05E52ULL,
		0x7E5D27C78BDACDD0ULL,
		0xA655146A4D74FA3EULL,
		0xC1DD4E25D67E85D5ULL,
		0xD7CFD738472092C2ULL,
		0xBAE37062EABB0F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1343E766CE5D709ULL,
		0x38942C2F1693F379ULL,
		0xD61D3048E513A64DULL,
		0xD0E089B5FBE9FE8CULL,
		0x380899376B2A954AULL,
		0x16E59D6FED70A08EULL,
		0xAF2BAD40EAE1A727ULL,
		0xCBF131E7F04E9B38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x443633D21EF33509ULL,
		0x93BA18E365537749ULL,
		0xBFBEE9D8B823B120ULL,
		0x2571E452BC09FEF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFF33F3575D2C99CULL,
		0x92B7CCDF340F0F5EULL,
		0xB45ACAD700ED1082ULL,
		0x32BF67FB95E63DD6ULL,
		0xC823A8DC06613D69ULL,
		0x9518469153AE166FULL,
		0xE4F1B88C8860C246ULL,
		0x2E9C65E723FA5E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4C21D75AF4511FULL,
		0xC8645EE5B4BDDCA3ULL,
		0xA2B7562F4F618CCFULL,
		0x4D3297241D079866ULL,
		0xF9EBAD340843264AULL,
		0x000FDE898B5B0CEFULL,
		0x2B8CA42A88A379AFULL,
		0xDDF9FEB9C4E78656ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CF6784DD355E328ULL,
		0xE992DF213BA49BB3ULL,
		0x96A47B33A7A44A32ULL,
		0x5DA8219395AABA25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF1F0374B561A7B1ULL,
		0xD208DDFFDBF7BDBBULL,
		0x031CF724F369368CULL,
		0xFDDCA05F22C2E8DAULL,
		0x95F60E73C6F507CCULL,
		0x2B84B8DD544988D5ULL,
		0x252B6AD16FDD740BULL,
		0x720FEC11D5A5C4E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB965CBFF70B9B3ULL,
		0xADEE067AE8C5A8A8ULL,
		0x239E5C82F7F40B41ULL,
		0xFD79B08408B05A50ULL,
		0x0E289FC507B8732AULL,
		0x1357EA93081B695EULL,
		0x55EF13AFB1924AF7ULL,
		0x361367F412A0362EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79E40B9918EEFF4DULL,
		0xBAC1768C420AC0D1ULL,
		0xA27389A43A9D4446ULL,
		0x67DE8C460CE5BE44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0B0DE6443518C41ULL,
		0x20AC39C41F52C8F9ULL,
		0x7DBE7506C6BE31E6ULL,
		0x8EE321FCC674A2FCULL,
		0x5650BF037022BE76ULL,
		0x4F0AF8D3C0EB12BFULL,
		0x31D55667AF4C6A6EULL,
		0xA5A9F0EDDE884F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5CC7EFFA8A494B0ULL,
		0x4D06EBBE7F7B2BD4ULL,
		0x0AC462A4C08FC2F0ULL,
		0xA60BB8DA80D2DECAULL,
		0x090AC61D4EF195ECULL,
		0x48DB4CB288BDF3ADULL,
		0x6C530B3ED4A98AE9ULL,
		0x4FE015E148403D7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5347518D87F8FDE8ULL,
		0xBEB8DAF3F68A39DCULL,
		0xC4513A727A5B9CB4ULL,
		0x24CDED0094546021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x619CD07AE5BE8E09ULL,
		0x636698D1DD647BC5ULL,
		0x13442FA4FE93CEECULL,
		0x60504CC96B88BA9BULL,
		0x554ED2E136184F8CULL,
		0x89C50ECC3100DD83ULL,
		0x7DC1A22C6C2F6F2FULL,
		0x3678FAE9F2A65100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x079F4B82F467C0F2ULL,
		0x17C821A3FECE1D62ULL,
		0x6B5EC55F4FF6997EULL,
		0xEE5DD1140A486694ULL,
		0x6D1717F7A90160CFULL,
		0x5C3C319C2DDA839EULL,
		0x108BFFBE207410B0ULL,
		0x590FD42CF2554753ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD24343A2E2BE3C41ULL,
		0x0DEF4C4E5647B65DULL,
		0xDDDB86A4EC6D3C4FULL,
		0x4F8E3BC36D47C3C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE285E6482D100D8BULL,
		0x718728E97E1BADAAULL,
		0xD245FC12720916CDULL,
		0x7379E89C37E15ACBULL,
		0x7F785740A8309540ULL,
		0x65CBEFD4E84CAFC7ULL,
		0xB11F8E219615BB34ULL,
		0xA94EBBB62BCE4DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ECB5D1A002C9C31ULL,
		0x6BFBD5119B4DE952ULL,
		0x9E4DECA6C1411EE8ULL,
		0x1FC81479F4D77EBDULL,
		0x5BDA2E110C891BCCULL,
		0xB7CF19096668FBD3ULL,
		0xFD12E83199C0036DULL,
		0xE66FFF8F4FF1B481ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD34A63F47BF773CULL,
		0xD913360D2A9A7A95ULL,
		0xEDD8B10B25813F62ULL,
		0x40C1C1E6E5C8A0B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44C5D73CDE84E985ULL,
		0x5597213B582B4017ULL,
		0x1896CB06B8417871ULL,
		0x042BF2B9D905B85DULL,
		0xB81611A21547D406ULL,
		0xD0BD21F3607CB93DULL,
		0xF5C90AE15B8A69F7ULL,
		0x5600CB4F3E4087FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF475785A0F283ECAULL,
		0x0264117AA1526980ULL,
		0x69CA17DFD80D44F1ULL,
		0xBA85DB04E9203FB2ULL,
		0x1D1178DB2AB04205ULL,
		0x37644B2F71FD406EULL,
		0xCDE57DADC3178BBEULL,
		0x12E8CE6B967C2278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52FF0C69A1DC5837ULL,
		0x1662F0D61DC4C567ULL,
		0x9A93A8CF8141300DULL,
		0x3F35A17FD70C8A22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D0210971A8E0366ULL,
		0x09FA28949FD65E05ULL,
		0xB65D22CE34429587ULL,
		0xCABF4ECC2623457AULL,
		0x9CF50D3E08DD081DULL,
		0x95234626A3678762ULL,
		0xDA0618E49627ED2FULL,
		0xEA781747B7092AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF71D0B8C0718ACULL,
		0x7039D0757A0314DAULL,
		0x97D3AFE1652CBD03ULL,
		0xF6241946B7E8CC2EULL,
		0xF998EC7C57830629ULL,
		0x17C5A08406170321ULL,
		0xAC912A8AA98A82DDULL,
		0xFFAE43C93C0B16DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DB7D04BE1E3346DULL,
		0x35A6EE427FC6EAC3ULL,
		0xDDE4D445EE73A0C2ULL,
		0x2E909A4BAFF171EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46797F2B9AEBF08CULL,
		0x1E2F78B6BD91E67BULL,
		0x99AEEEFC82F37B6FULL,
		0x542C1901A61CC84AULL,
		0xA1C089CF6F5ABBB1ULL,
		0x13D70CB9B74F2C91ULL,
		0x7733743EDA40E32CULL,
		0x5FA6A75A135FD7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FEE8F417EE74629ULL,
		0x19575F89003BF9C1ULL,
		0x507BFCBE80EFF6B7ULL,
		0x9804487A67741FBFULL,
		0xEAE2C1FE51843AA3ULL,
		0x0D092F6926ED8C39ULL,
		0x519133D3C122C98CULL,
		0xCBC7D67CF23E4CF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B7698F489DBD004ULL,
		0x0766F3232BD3B9BFULL,
		0xDF488223BC7B5279ULL,
		0x2F3AD15A29A34B9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x048DB61E214CF7F0ULL,
		0x63D765E9BE0650DEULL,
		0xE7B33C9BFFD680BDULL,
		0xE5737954EAB4327BULL,
		0x214FDD32A9A9D7DCULL,
		0xFA70F1BA2B0EFFF4ULL,
		0xAD5A8F5DBBDDEBCAULL,
		0xDE5360EDAE692C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8C12D37BAF1D5AULL,
		0x2FACA26F848B24B1ULL,
		0x6F47DCF846940057ULL,
		0xD8AB2D152C74023AULL,
		0x0775E4635A4CB44EULL,
		0x3326CD6104F3ACFAULL,
		0xBC2E8E19C1F27B32ULL,
		0x376FD18AAE3C63BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE05C92106D71254DULL,
		0xC92C28B5E1897D4BULL,
		0x44F38FBAD2353713ULL,
		0x528F94F1C4E5F909ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB97EF36E5D8D657AULL,
		0x9A6DB41D461EB569ULL,
		0x38E67A5CE74731C8ULL,
		0x666201F6D9817966ULL,
		0x494C8472E0866365ULL,
		0xF262A6276D6B670EULL,
		0x55C49D36B88D9C55ULL,
		0x6C873E4AD20EA497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BEE2B6B92D503BFULL,
		0x67DE00671A9C157DULL,
		0xA35998EF115BEFA1ULL,
		0x95F9B446F5B63B47ULL,
		0x94CFCA33C6529A01ULL,
		0x3DD1CFA74864360FULL,
		0x863A68502F5CAC03ULL,
		0x5A4701A4D73D36F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58146D60AE6846F2ULL,
		0x000F8ABBAA93E5BBULL,
		0x6410BBA6332EEE6EULL,
		0x05F14E531EE18423ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCFA90338E784EE9ULL,
		0xBF58A0EDD7FA0DCAULL,
		0xFA6062302EE2BE6AULL,
		0xC5C8DD5551023C5FULL,
		0x6006AD7E4A3FFAA6ULL,
		0x3F0CDA932F1965B8ULL,
		0x58AC3576C452B32FULL,
		0xC4BDF614E6F452B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x992C5DD926A80926ULL,
		0xDB886B82579DA852ULL,
		0x8999990BFF410DF9ULL,
		0x6CEFFFC777666279ULL,
		0xD1A4FBC3087EB890ULL,
		0x2E7125236276818FULL,
		0x636CD36715B9852DULL,
		0x23B07B8A24D64C1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x464E94262A801897ULL,
		0x5AED2403E08A437DULL,
		0xD82F57781A5E84BFULL,
		0x40D90E26AA10D428ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B6D18D3AF26368FULL,
		0xDC8BD0AB603A9F9EULL,
		0xCA872F63492082D6ULL,
		0xFFCADD5B449F9361ULL,
		0x87287B6D01C4A228ULL,
		0x989C77B87F34C3B3ULL,
		0xA8E9E13C2246F19CULL,
		0x3CAA71E948BB8FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89004FD0DC7E5E7ULL,
		0xEFA21FE93277CC16ULL,
		0x18EECDA505C15846ULL,
		0x203A95B06E486B65ULL,
		0x17AF37848128797FULL,
		0x87E01C1D1B9089E4ULL,
		0x2E38E3B691CAE2BBULL,
		0x31975A43EDCFF644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEDD2859B88C5A1DULL,
		0x68DF49D2F8236851ULL,
		0xE7DE0391B5C95FF8ULL,
		0x0465CA36554FF49EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC66EA2F21183AE7FULL,
		0x3E75B99FA42B7BBEULL,
		0x8EE2D3ECCC23C7A8ULL,
		0x5358124E07BF8CE7ULL,
		0x8227E1514D128D03ULL,
		0x6D431C72827A2A49ULL,
		0x8E571229093CEE9EULL,
		0x382E71648922E3DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CC2CF25C16F7D6DULL,
		0x9F005859B939D5ACULL,
		0x182A1A51774D98BDULL,
		0xEE25C88F572CEF4FULL,
		0x8E7FABF6E29DA6F3ULL,
		0x94F623823D54F92BULL,
		0xFA0F469DAE20DCA0ULL,
		0x19B94909BFA7634FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4A3BF381D6E57F7ULL,
		0xBAE254F02E76F084ULL,
		0x7960F04ADB00DA98ULL,
		0x6A96473898E7B22AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82D83526D99B7302ULL,
		0x870C04381DC735E1ULL,
		0x1961F59BFD92DDE7ULL,
		0x8F5CDFF3EB990481ULL,
		0x0CD2208C8B909886ULL,
		0x1A3C39D166334CB5ULL,
		0xD8C3AD0D398F4F63ULL,
		0x17A4D488C08FE4B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ECA53F76B98F7C5ULL,
		0x19323A5651953614ULL,
		0xD4E1355E42F89644ULL,
		0x5C9003C4F2EC08DCULL,
		0x6882752283596EDFULL,
		0x9C86E21664D6F612ULL,
		0xF58F7B027A0DD524ULL,
		0xA8D506E6C366F774ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67E152ECA632A6D6ULL,
		0x16C4CFA3FFE6DBF1ULL,
		0xFE402DD627D26CEAULL,
		0x25A5623A8CC0336BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4263D58D03089659ULL,
		0x7C9E6FC768C3D097ULL,
		0x1FDF1804FA16EF73ULL,
		0x71E509B3AB4F2B80ULL,
		0x7F421F49852A4897ULL,
		0xE7740E17A1507EB7ULL,
		0x3BEB172A03A864AAULL,
		0xDDC0C449F9CB529CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD04E1C86E82290BULL,
		0x148C53D8F6EF87B5ULL,
		0xAED042DFE65F80D3ULL,
		0x734C160C34F2CB02ULL,
		0x454659E47DFE0313ULL,
		0xFE8CCE08EEC0D259ULL,
		0xA82A50D4E7EF5888ULL,
		0xD5C0755FB0A6740BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20BE40C3A518BF0CULL,
		0xFA659E1CF327DEDEULL,
		0x5FAC45C7312F3BA8ULL,
		0x2EA4AA6E51D569F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE996DA75C679AEB7ULL,
		0x6F4A2B9BC218CAEAULL,
		0xE9692AD11535159DULL,
		0x511369A9697DBC3FULL,
		0x999A749F02F072FCULL,
		0xBB7E6D3AF467D09AULL,
		0xCB31B2DEAFA8A113ULL,
		0x28210D3B94B6DE01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC4DD14F2206B0AULL,
		0xE83B956F97AF7074ULL,
		0x3263F9F6A4190C2DULL,
		0xC6E518350C12EA9FULL,
		0xC6A2393853959120ULL,
		0x1083C8D918CC26B0ULL,
		0xDA6C9A93AF6D473FULL,
		0x1C0CDAE42E1346C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DAACE9EDBD6CA7BULL,
		0xE842FCB2C384932BULL,
		0x7446CBFC79EB5F00ULL,
		0x552DCA6D99B344D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91DD4856E867BB6FULL,
		0x1308762260B7F49EULL,
		0x9BD35573B55D9CF8ULL,
		0xC93014414F924079ULL,
		0xEC75BB4237F20A31ULL,
		0x73A8B2035FD8B01CULL,
		0x0A08E8F12D02C13EULL,
		0x4318AA189D208527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2760FD44CB5A247DULL,
		0xFD7763FB54D52346ULL,
		0xFCEB7ADEFF9A4F97ULL,
		0xBF33A92BF43FEADCULL,
		0xE544CB407358DD57ULL,
		0xCBDC259FE64C1378ULL,
		0x854532DE6F6C02E3ULL,
		0x0FFE88253FAF52D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BBFEB554BCA406BULL,
		0xFDEDE8EB16C211B1ULL,
		0x53F4E15CDA238ED4ULL,
		0x1FDD75353A1FCE74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA19D21AD7CDEA050ULL,
		0x73219D3FCDE9F4F1ULL,
		0x04B70E78D41F642EULL,
		0x742A1D06CB8DE85EULL,
		0x03F8B5A47E51657BULL,
		0x9C51A1686281A760ULL,
		0x4AFDEFC9CD9DD8BFULL,
		0x37445888774DE403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x960207CA5E5B7236ULL,
		0x974E19FC5A71F951ULL,
		0x6B996D7AEDD69464ULL,
		0xB1BE76DBB919979FULL,
		0x8F6DF136FF72E520ULL,
		0x2F0059C92A8F1A36ULL,
		0x17BC5201416B37D9ULL,
		0x8D5B417BB13CA4BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58344223F38A399BULL,
		0x15E424E5C178EFC7ULL,
		0x34DB0CC2B5CCB1FEULL,
		0x7B0512107903B550ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC75BA6EF8BD8213ULL,
		0x398F88597F466B28ULL,
		0x61E2A6A08916C7C7ULL,
		0x90BB6C5F8AD4FC15ULL,
		0x304B353378DFD924ULL,
		0x51239E0984D73685ULL,
		0xA6CF912CC94FBADCULL,
		0x1169436124D2F3EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0E70DE5BD397A1EULL,
		0x275FF594158B6F18ULL,
		0x1E69F902F251E5D6ULL,
		0xBB86AEEF4282BC89ULL,
		0xEF00D6DBACAB238BULL,
		0x03D858C6C28A06B5ULL,
		0xEBAB93F4940F2380ULL,
		0x67863530BCE05C79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC98AD918B56FABDULL,
		0x8B5BDAAE413014D3ULL,
		0x0AD043F57E5B59A4ULL,
		0x0CE8D89FB654BB06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3131BDD8E613B34ULL,
		0x01B805B5219D4FC4ULL,
		0x6D35610B5701558EULL,
		0x4E2CC0EB3C0EA687ULL,
		0xE2CE599B0C4C00D4ULL,
		0x9C2D3243AAE20082ULL,
		0xC6A5002BF8F5C969ULL,
		0x2E55B530FFE7DD96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2527A9FCE90C9FDBULL,
		0x3BAA12899F14655AULL,
		0xF221C2FD8AE01C44ULL,
		0x375B0A808857686FULL,
		0x57D51A7A25ACED5AULL,
		0x9B47086344D48618ULL,
		0x47C61943D81312B5ULL,
		0xF43A81772F35FF1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EEAD0C2E0F17B14ULL,
		0xE8382A7AA889163BULL,
		0x5029E482ADC85801ULL,
		0x36DB63FFAE1E446CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB76F2DF2FE3798D8ULL,
		0xF1CB0614923BB5DEULL,
		0xF3BFA82C59699C0BULL,
		0x54E8A45DEA3D4540ULL,
		0xCA3562FFA2E29615ULL,
		0x52A597818E991047ULL,
		0xB4B1DA62B0819DF5ULL,
		0x6D3D877B8B9BA89BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x159745D3C535EDA0ULL,
		0x0F637E50088FDABCULL,
		0xBD93B0E91C146871ULL,
		0x769E3C25D0FE0FB1ULL,
		0xF5839624A7D17D95ULL,
		0xF9076FFF43775023ULL,
		0xDF93954A93EBBEF5ULL,
		0xDAC487E154D2D983ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x343C50A07D8B4BC5ULL,
		0x2FE1651BB0AE6074ULL,
		0xD8AA38D77B944D82ULL,
		0x1C40591C3B0DF318ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0997DD8D5CFF2A05ULL,
		0xF2C79C743A2F81D1ULL,
		0x4C1B3DD6B6B22E82ULL,
		0x037C0C0210EB12FEULL,
		0xE14B0DE4D0B8543AULL,
		0xD3176A9178B5ED44ULL,
		0x08E6B950980890F1ULL,
		0xA307878B537C5F64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E56BCE4B91687F8ULL,
		0xFDD2E8F27FF7ADF3ULL,
		0x2CED80C51259C76BULL,
		0x9BA3D31331E31FE8ULL,
		0xA4B1AA59CABF0B4FULL,
		0xE2FA9C052D67104EULL,
		0x0CAAFA9B5DFAF642ULL,
		0x9424CA3FB794A404ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA05E74B86E97528ULL,
		0x993B5C54E7ECA06AULL,
		0x900C0BF8425D5D0EULL,
		0x1D805228036DC355ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4C3CFD20ED3223ULL,
		0x61EA6AFA4A0BE65BULL,
		0xEE215652E3F1CDA6ULL,
		0xD2F6260C13E3A81DULL,
		0xB6FCD6D78E96B188ULL,
		0x237120F45A4A3074ULL,
		0xE60C9A37C0EC371EULL,
		0x3E96876F8F9A474FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53BC39C42ED0CAE8ULL,
		0xBAD9D190B3ADBE95ULL,
		0x9BC0CA5A7FEE406DULL,
		0x6C451FBF7FB15AEAULL,
		0x7EC2CE0A6F00E1F7ULL,
		0xBE131953CB20805AULL,
		0x34BA8670C86DB125ULL,
		0xE48CF3F2AFD2E176ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB12D51ABA259331EULL,
		0xB305BB3ED68E4BAAULL,
		0xA48F7B8146CB7017ULL,
		0x441CEAD5CBCB6B83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE4FB6B545202132ULL,
		0x8F5EE72047F4EA72ULL,
		0x515D1E2EAB679C75ULL,
		0xDF39F7AFBE7CA8FEULL,
		0x6F72E17CB9AEF735ULL,
		0xE2EB3A617A4A2F16ULL,
		0xEA0E8443CAB72A3CULL,
		0x62EBC063F9519D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x298C781AC8CFFA3DULL,
		0xF80D9C4FDBFCE32CULL,
		0x2D69FA709A18369BULL,
		0x3336A7533E2C6CC5ULL,
		0xEB0CD2FA69AF8B09ULL,
		0x90C3F3E0571741F1ULL,
		0xD26E583BFC2A05A8ULL,
		0x148B8BCE0E6DD008ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BE965F25C3A3745ULL,
		0xC925C1FBA5873AB2ULL,
		0xA5B9ACE6BA42D3DDULL,
		0x4E4B1E9D5E20A97EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0413FBBF63888039ULL,
		0x2ADFDBC542D8255BULL,
		0x07220787360B59DBULL,
		0x0C28E7D423321577ULL,
		0x3B91953DAAB92048ULL,
		0x4DA41E48EF399D3FULL,
		0xF44C2C2D3D4379B9ULL,
		0xC87B6A9D144CB02CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3242AE4768BE251FULL,
		0x8A73D44CDD42EDA6ULL,
		0x8B43DA5AECAB1731ULL,
		0xCA9800DC39878757ULL,
		0x4AD8663735EEF9BDULL,
		0xAD30AB7A194A7641ULL,
		0x554AAC7BA172F0F1ULL,
		0x956A891070C4E5D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D4E486D50CC14B3ULL,
		0x718F122C27150166ULL,
		0x161721896A54904BULL,
		0x561261D82FD296FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF38EAD704C785BCULL,
		0x6B48F65EDF9ED0B2ULL,
		0x4C3DCCC26C33C1E9ULL,
		0xA0E334E7CDDC06DFULL,
		0x8EBBA20FF982AFFEULL,
		0x7EAA79C412645213ULL,
		0x9C1FBFCDF2094280ULL,
		0xBBA1F5C58141DB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70856A832ABE21EULL,
		0xE2D7246E2FF9B479ULL,
		0x8F74D35E38400D69ULL,
		0xE7756D0AD0C24E82ULL,
		0xFEFF088BB2D6B2A5ULL,
		0x617BDD2C82C64888ULL,
		0x4389186CC498F24FULL,
		0x5130131012C21E2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E2F5DD14FA34121ULL,
		0xDD5D1070011A86CAULL,
		0xE325D1D0F29F9BC9ULL,
		0x06556ECB640FC857ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31B83BCBDD2D308EULL,
		0x7EDF453FC1FCC653ULL,
		0x0E6C41D281D2366EULL,
		0x07609832EECB3DCEULL,
		0x522BC0154685066AULL,
		0xBCD9A027B4FB51A4ULL,
		0x70D73AE8F968636CULL,
		0x0FE2C77E83B7D67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574076F07AA69531ULL,
		0x918378D15CCD7B48ULL,
		0xAE0348B9D7B0219BULL,
		0x2DBC5C606C69D4B5ULL,
		0x52AF5BB9F11B0A65ULL,
		0xBF89CC0DE733ABBCULL,
		0x6F930D9C0DAAC49CULL,
		0x69512364AB5850FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6EEAA6A1042021AULL,
		0x87354842F0D1EB7AULL,
		0x9087B283A847A7B2ULL,
		0x134297A8A08F3A18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB56CA1E31B70B9FAULL,
		0x2AC967A13BA9BE34ULL,
		0x40564FBDF8473721ULL,
		0xE1D195C468872BBAULL,
		0x9E13FA0A6535A1ADULL,
		0xA1F89B31DA3E393DULL,
		0xA35A3F8A9E90A9CDULL,
		0x5A759059D5409037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15FF84520559CCCULL,
		0x4974C11435496AE8ULL,
		0x63AAF19EB0044685ULL,
		0x658FE54C02DD0872ULL,
		0x4603E81CC69C3CDAULL,
		0x1812DDBBACD524A4ULL,
		0x7B77A1DFFCDEE6B6ULL,
		0xD99861F17DA2992AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE66F52E385E011C1ULL,
		0x596EC617C3F9620EULL,
		0xC84EC57348A5E61AULL,
		0x1D1693F5671CCF3BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x667313221E447A4EULL,
		0x3E56939FB301A852ULL,
		0x60D92F76D8946219ULL,
		0x21069A08FA457E0BULL,
		0x4DDE7799B7E49C76ULL,
		0xDC9A231586F0F0FCULL,
		0x872B2EF012B82511ULL,
		0x5255EA63F8996F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE35C2888E684F62ULL,
		0x27B4D555EF607C51ULL,
		0xD8FBB77AB7AC99E8ULL,
		0xE61E53911628C7BBULL,
		0xC4C989889F7BCF70ULL,
		0x1394F9BE2455BC71ULL,
		0x83CD76EEE8B719F2ULL,
		0xD647D2E108FE99B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE158A7232F6A96C5ULL,
		0xED65E14266AAF890ULL,
		0x07C6C8285D0F6EE8ULL,
		0x24FFC3E775186B52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA311F4974E99043ULL,
		0x5B9784C63FE25D4FULL,
		0x3218F3CA20DCEB85ULL,
		0x2F5FEE07E4AD1A7EULL,
		0xD6035BA78EFCF9E5ULL,
		0x3C2DBBCC2CD53864ULL,
		0xD398DF1D5D06BD46ULL,
		0x9E08BE9579C7D083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E87BC9BE5D67ACULL,
		0xD97DD96AEDD34DAAULL,
		0xD1F397CDC439CF38ULL,
		0x435393162BC17F4CULL,
		0x40F52ACDF3A92276ULL,
		0x98DDB1DD4CFF2939ULL,
		0x5140D34648167218ULL,
		0x769F6A9690B648EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE063E3CCC4FE23E2ULL,
		0xBFFB24D08BD5501DULL,
		0xB9371DE9784E4512ULL,
		0x45AED2C85185BB62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC684BDF05242C687ULL,
		0xA798A8C84CC57A19ULL,
		0x7E7A668848B02BFCULL,
		0xE693D38F2FA40060ULL,
		0xFFA1B0809ECD229FULL,
		0x439DEC11446E4BE5ULL,
		0xF066B2C1935C03E0ULL,
		0x4D7881A5876A4332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43474107D527D7C4ULL,
		0x839D506F27366290ULL,
		0xF65A38E6F235B095ULL,
		0x88C6574024E70728ULL,
		0x6056DDADD7193536ULL,
		0x2DB052819D0DE1D2ULL,
		0x0E9CE5EA1C0B4B38ULL,
		0x250CE52A71FB3146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2858C83221D02D3DULL,
		0x654023ABFDDED673ULL,
		0x0C14959D0C75E45AULL,
		0x5DC6B6943939A261ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB911C81B6697A160ULL,
		0xC63F484F515D7DB2ULL,
		0xDF16F2DA87340E70ULL,
		0x87903467CA1DC0AAULL,
		0xB547E22374BB6EDFULL,
		0x0353AC5FAEFB88D2ULL,
		0xC5A6C98A4C242585ULL,
		0x3F7D89F9C0BE9F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6BDB36A9CB0AB8ULL,
		0xF8B8060736B65BE6ULL,
		0x83A8A9D10B191872ULL,
		0x41D1428CE6E3E824ULL,
		0xF555A4C81A4BBFBDULL,
		0x4BF1515B746E3139ULL,
		0x4580B073E746B88EULL,
		0x27123A7246ECD7FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A9B087429609639ULL,
		0x0620C4E8CBA22278ULL,
		0x6116025C74F9229DULL,
		0x65ACBFF6F85D7ACBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B127E52E21315AEULL,
		0x7D97D596484B109DULL,
		0xBC03941799FBC18AULL,
		0x69CDCFF5632B4C45ULL,
		0x6B9C9CB9EC2FCDFBULL,
		0xD3AA96E094E2E231ULL,
		0x4F5CCA8E96F4C8DAULL,
		0x265D8C274B3DAAD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021646A4FF47C9D3ULL,
		0x84BABE1B8E4BB682ULL,
		0x9D6E3E2F637F0BDDULL,
		0x0675921C2B426119ULL,
		0xEAC8539560A99575ULL,
		0x598968F2B7B3E65DULL,
		0x251C8E741ABE440CULL,
		0x8C3EFE372D160B8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287F131A98B7AD85ULL,
		0x19C9E8C98EF8BB80ULL,
		0x641E41D6A6946C53ULL,
		0x43E14F7DB1CA8F4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x858B43CFCDF0F9D9ULL,
		0xF70D45FBEFF8F366ULL,
		0x2BDBDF297B1E6598ULL,
		0x3CEB4B2D3230B13DULL,
		0x88D4EF53FD60DF59ULL,
		0xA14746C00251436CULL,
		0x1D4E84168BFBB858ULL,
		0xEBA828512ED5060DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA40D3300374BACC5ULL,
		0x56FF5E154C9A0299ULL,
		0x30BE943DF0418C09ULL,
		0x0B0DA2534301B614ULL,
		0x1A2E2FDC6C91A958ULL,
		0xA2D73CB67C7E2375ULL,
		0xB1AAE4A49A7B442DULL,
		0x630BCEA1FE45C9A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E3E7C8F15675432ULL,
		0x64AF655080B5AF87ULL,
		0xF566F5D563EE17F1ULL,
		0x7912F8DB2471F2F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C4A4DD0A9CA692ULL,
		0x9CFC15BBAF632555ULL,
		0x1AB20DA4FED12A30ULL,
		0x193B18485A086B3EULL,
		0xA9FD375036427B22ULL,
		0x750669D830CF9196ULL,
		0xA828D46088E9F75BULL,
		0x7509E1B60851B88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE003204C2D705FULL,
		0x8D6CDEA33840A0B0ULL,
		0x6A4863516E14865BULL,
		0xC9FBA4933FD9EE40ULL,
		0x443CAFCBA6DBF5FEULL,
		0xF1D9BD7E7B164F11ULL,
		0x21AAE624E1FF056AULL,
		0x193941C716C1E41FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC778BF6A07A6FB66ULL,
		0x8830CC6970A26471ULL,
		0xA71B072E579C8D88ULL,
		0x7037312CF588053FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54807C6DCE34D4DDULL,
		0x1F875522CC37CB6AULL,
		0xA1414986E02444C9ULL,
		0x485FD589CA888E27ULL,
		0x03DC85A514361205ULL,
		0x8AEEC90F9B469BEDULL,
		0xA83A2C2D7FCA2D18ULL,
		0xE1F151B14258E6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E837105B9506A77ULL,
		0x841809A0236E2214ULL,
		0x691C3140D7B2EDA3ULL,
		0x7B632D34F4A2069FULL,
		0x5894FF6130BC7884ULL,
		0x6B9A5FBE3557FD3EULL,
		0x17230D1252ABE5E9ULL,
		0xF065C91A244F9CA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x829AF97BD8F1332DULL,
		0x41F6ED97CA353743ULL,
		0xC193B64EBAEFE824ULL,
		0x27B2EEC34B478BEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5C8010C09700B0FULL,
		0xE13F6407C680844AULL,
		0x6E29F6147CEDE50CULL,
		0x51FF02041ACF4E23ULL,
		0x16E92B5A4996B061ULL,
		0x4C4C89D5CE2E50A6ULL,
		0x86C4D0BD8857517CULL,
		0x6B0543FCAC937BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16FCBD01F8242197ULL,
		0xDC456AB7DFD533D9ULL,
		0x779D5E6E952CA212ULL,
		0xAB627059A4E1C70BULL,
		0x2D93D1385DF46FA8ULL,
		0xB469B26AEEC9B307ULL,
		0x7BC0795781F4B9B6ULL,
		0xDF9B8D2BAF73E2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8176A5130B618242ULL,
		0x90A5F32D0F9AB608ULL,
		0x993190CADA63CA4EULL,
		0x584DB4B0089E3A47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D95C9005F81D153ULL,
		0xA0801CB6D87CA3B0ULL,
		0xD8D802FBE6F2BE6AULL,
		0x5719A921FBE0BF8CULL,
		0xA946ACD2994A7A3BULL,
		0x2A0709E5D88C0005ULL,
		0xF829E904A0812076ULL,
		0x18B2274C08B9668EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E2A5A555202DE9ULL,
		0x02FB253B175B58B0ULL,
		0x8CC1DA74CDBFDC9CULL,
		0xEFBE30BE504EFCE3ULL,
		0x4138F987AB7A0E37ULL,
		0xB475E86A69E59A68ULL,
		0x1FBAA8D2FCF6230AULL,
		0xB8839CB2C648A722ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEBBC07A5751A85FULL,
		0x110FEFCE2DD4605CULL,
		0x6C99AFE55FD47FC2ULL,
		0x2E440B23884E2CD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53774511B85A2FB5ULL,
		0xF0C538D50CD6F4F4ULL,
		0xFAAE291A12BCECF5ULL,
		0xBE5C59731F153F82ULL,
		0x1F121E6B96F0F2EEULL,
		0x6954EA2507623443ULL,
		0xD68BDF2E92E2AF8CULL,
		0xF5B87BFD5CA96CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750059E32124D02FULL,
		0x9B1AB7ABC6C5E1BAULL,
		0x122A6703A235B54BULL,
		0x1CC198EE649610BCULL,
		0xEB54F2D460C03CD6ULL,
		0xB99BECAAE3CFB0AFULL,
		0x8D74C788D3E8806FULL,
		0xD143568A94D8B083ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8B63A0A27067FAULL,
		0x6B20214A8DD09B13ULL,
		0xC1F144B0C9AA35ECULL,
		0x0AFE4F8E637B1FDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B13F00A0A9E7EAEULL,
		0x9BC3FCEDB5152802ULL,
		0x81B69B5FA12596A5ULL,
		0xAA964640E460F089ULL,
		0x75706B05328271B0ULL,
		0xDC8A5FCA520FAF95ULL,
		0xB8AAF381F616464BULL,
		0x30CD92F7A901EA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8C2F9644736011ULL,
		0x705ACE350D7B025DULL,
		0xA4B98750A601B500ULL,
		0x3A8D4BB71CBFB969ULL,
		0xDE2E9DF26720B405ULL,
		0x8CEC23CE8D0F3956ULL,
		0x7CC92CFDC7E1F2F8ULL,
		0xCFA85336D1AF5CA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x924C313DF6AD4282ULL,
		0xFCE61617E5ABB2EFULL,
		0xC0808BADD6E84002ULL,
		0x5B907129BDE23A3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9019180B94A5FA88ULL,
		0x4D7A6608CFB2E559ULL,
		0x10EB65AC97561CB7ULL,
		0x64F6F0120D25DE79ULL,
		0xCF6E1395CA2EB6BFULL,
		0x9EF9FE319C127305ULL,
		0xBDEF07188653C16CULL,
		0x9C426FABC7968695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20BB43F2740709B0ULL,
		0x8BD3CBF4A9DD2CA7ULL,
		0xC85699C8D7B68C86ULL,
		0x40009513DE666F1DULL,
		0xB1ECDE12E8EE5572ULL,
		0xF4D9C8F38486EED2ULL,
		0xE2B66DDA5570CCB6ULL,
		0x01E0AE1CA8216C67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD08BC586902D65B0ULL,
		0x026E814BA48B5848ULL,
		0xD2FB8B1F014FE328ULL,
		0x0F79163CDA215229ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1C8C38F113DEB79ULL,
		0xC232FD4EAF23F7E8ULL,
		0x132EE78E4E72D806ULL,
		0xA93CDB3B76F18905ULL,
		0xC6F371025E40752BULL,
		0xCD9DAD021D159297ULL,
		0x2F985FBABCA1D7D6ULL,
		0x87996D8BB9F4B5B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC07E049477A900ULL,
		0xA23E30BFD95CD3E3ULL,
		0x763A7C1C4D96C510ULL,
		0x57713D1D592C3BE2ULL,
		0x120DCFC6D60C69F4ULL,
		0xB7B49B7742411A69ULL,
		0xB1634798F6B06AFBULL,
		0x6335C53FB740D83DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x111E3460B47FED74ULL,
		0x608D672B5150FAF4ULL,
		0x58D6007562B23B7BULL,
		0x3896996684782D05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x037235CC652E8950ULL,
		0x3DB3773EAF26DA53ULL,
		0x07B61A89B9BDCCBEULL,
		0xCCC31F2B2BDCF3E3ULL,
		0xC9D32671E9E45FF2ULL,
		0x7CFA516047BB58DBULL,
		0x27F22448CBF972CAULL,
		0x5E1E21D04E295C5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF1DDF28DF6A24DULL,
		0xE07A8E6B4314D3FAULL,
		0x45680065B3A43E79ULL,
		0x4A0D26AA8D3B06D1ULL,
		0x25364B38B9B08572ULL,
		0xBFDE061DFD654C51ULL,
		0xBB827AE0BD09A966ULL,
		0x353F198B4471AC68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13C8E256FEEA56FAULL,
		0x6F6C14AA74D7E2EDULL,
		0xDAE13F963DB17312ULL,
		0x13D132C00FE60BA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC724DC8E97EE2B0ULL,
		0xF9FECF2B0E4A36B7ULL,
		0xEBCFEF3E72934586ULL,
		0xA3D242F2437B7CD9ULL,
		0x66D1F63E808995E0ULL,
		0xEC71ACC9211A81D5ULL,
		0xC4DB2A5B19EBE383ULL,
		0xD94AC8DF9A9A4216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9441E30CF484E8F9ULL,
		0xC6326537A901120DULL,
		0x863DB2F7E22B679AULL,
		0x990B1DE82183C760ULL,
		0x8179015568CC155FULL,
		0xAC7225B42FAA3FBBULL,
		0xDC9A88CC5D675D53ULL,
		0x23BA17F401A63398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4364C5557B1B10CCULL,
		0xB3BA770F3BF2F482ULL,
		0xDF2A37768C13C915ULL,
		0x7E416802D631DC29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208244941AB3F0E9ULL,
		0x25027D3E4E26662CULL,
		0x5ECFDE4EE861F9F1ULL,
		0x69C4D6440080310BULL,
		0x7D8982DF5F13CC40ULL,
		0xD9680F25C1ECC107ULL,
		0x50BD073AC3CE57EDULL,
		0xDCF4292472585957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC448C12A19BF5A4ULL,
		0xD03D2DD50D82A00FULL,
		0xDB8519536570E32EULL,
		0x3E3C187ADA6D88B1ULL,
		0x0B1CE1F2FB144F11ULL,
		0x75B3534D853200AAULL,
		0xB7F0FD50D6E52095ULL,
		0xEE24FDE4D98E77C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x305D9B9851048FE0ULL,
		0x21993182445C53FBULL,
		0x31943DB4AD8F4DE1ULL,
		0x1E492939D40A2468ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CF7178EE2FB2DFEULL,
		0xD96E4A044406393EULL,
		0x41C62320750AE146ULL,
		0x9F79848CA0954623ULL,
		0xA967DF0B06CB15D0ULL,
		0x3303172F1A8A1B36ULL,
		0x3023C49468ADA643ULL,
		0x875578432AC9AC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F1EE89B07E9401ULL,
		0x8A96200761EA06E4ULL,
		0x10B29F50FC3E6AC8ULL,
		0xBF1F69248A6F52CAULL,
		0x9A9260B97CE2933EULL,
		0x392349B54D0CFA1CULL,
		0xD107B61CAB0DB1A5ULL,
		0x9925B310EEABBAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7B5E91FAAFFFB37ULL,
		0x6610AA1162AF1C37ULL,
		0x4F3DA9959E8AC5F1ULL,
		0x3B7160DD0297D6CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x876FEBDAF65B759AULL,
		0x558C8BD824AB1CA1ULL,
		0xF37A978E9B01CC9BULL,
		0x69E7C20D03CB45E1ULL,
		0xD95D2AFEE6A0B4DAULL,
		0x200DBE21900BE0D0ULL,
		0x337677578D3DC22AULL,
		0x42CD7D6ED3248CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D17FF959F95455BULL,
		0xCCD68AA0F270A558ULL,
		0xC1D4ED7B839A96CEULL,
		0x848959D25733A87EULL,
		0x835EF5C8C9731365ULL,
		0x665ACB2FDF005AB3ULL,
		0xD1D605130E992238ULL,
		0xA158E03328C7F8A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E13D24DAB8C2576ULL,
		0x1946111779F05FA4ULL,
		0xAF76A03DE3D6F3AEULL,
		0x5CADBF15F655981DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x306FBB85370D0FCCULL,
		0x0084CBC2853A5876ULL,
		0xC0F773AAA8E4EAC7ULL,
		0x1B0F445FA0568A94ULL,
		0xB96930E2DF6DCF83ULL,
		0x00DBA882F0BF2056ULL,
		0xAE2B2C2A083FBD40ULL,
		0x3C0684D6D4488296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76DD9947F0BE69DAULL,
		0x0A50313B508B121CULL,
		0x469B93BB1E4852A7ULL,
		0x589A6303EB7F7FF2ULL,
		0xC9B987033A50AEBEULL,
		0xDAD704E3D0064282ULL,
		0xFA58F1D6EA28D6B7ULL,
		0xFAFD3860B52BCF3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DA5596FC8A17EE2ULL,
		0x9AE4E426102033CFULL,
		0x2B9088460202D055ULL,
		0x69D63AE45319A9CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1036F4AF881239F8ULL,
		0xB90C6EFD553CF977ULL,
		0xC88C76124983AD76ULL,
		0x679BDAE2D37D1CDFULL,
		0xEF65F99BC78BF733ULL,
		0x58F6B0A99590DE7DULL,
		0x79A987BB4510DFB4ULL,
		0x827CB7D4B99DCAF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6F488222A99D54ULL,
		0xBF5DBE9311357CB8ULL,
		0xF480E937B9688101ULL,
		0x85968EBD40158EDDULL,
		0x7A52DED506F8FEFFULL,
		0xF07414A9182EE569ULL,
		0x98FB227767002EF1ULL,
		0xD04F3ED09BC7B920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE69DA5ADFB397294ULL,
		0x7D11D87CE09275C7ULL,
		0x2DEE94ED86956950ULL,
		0x54C542C2012E334FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x144C7E11EB74F24DULL,
		0xA0D29FFDDB3BA4AFULL,
		0x05EB273E3D9872A7ULL,
		0x56565D0A30C2C503ULL,
		0x556870CDDB6D598EULL,
		0x6DFDBEF32AF595D3ULL,
		0xF58587BC3999E921ULL,
		0x223D047040A65CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4751A2954E864C7DULL,
		0xDC98DEFE28B3356CULL,
		0x1B73552ECA1381C1ULL,
		0xB25C20D88DD948D6ULL,
		0x4874F234AE057043ULL,
		0x4B4BC797EF8CCC31ULL,
		0xAF7051A0EC0CDF53ULL,
		0xDF0341E26AB1B3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB91FA6395A5B42B7ULL,
		0xEAA4788A84165D50ULL,
		0x519DDA1CF674657EULL,
		0x1E8D1D3F653A99EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE465C48363C4919AULL,
		0x29DDC5DD06465858ULL,
		0xB4306E28B74CD8F6ULL,
		0x7DB42F7E9E19902AULL,
		0xC8E1B937AF60F0C9ULL,
		0x26CDC3A5E7AEF312ULL,
		0x63614BD70D217BEDULL,
		0x46BCEC3D2BDDD356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060F888135A905A1ULL,
		0xF0AE6624DAFF04D2ULL,
		0x2CB1367E77B809F4ULL,
		0x38C2B498F79A235CULL,
		0x7DC08D8FB068045BULL,
		0xEE78DBFD1068E935ULL,
		0x712B1342DDEFA788ULL,
		0x8A7AC871DC32267EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0542B6F2070EA2D1ULL,
		0x95C9C2C81FACCA60ULL,
		0x7B8B9DA940FA55E1ULL,
		0x36C2CB1379FB14DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EAAE2F7D181A5D5ULL,
		0x0E00559F15F42E33ULL,
		0x8CD2DB5F87204521ULL,
		0xA5288ABD5EC6F6B3ULL,
		0x22752727C16A7029ULL,
		0xD645DB7A80D2D15BULL,
		0xA9BA88728FAA5F57ULL,
		0xE69255E6CE83ABCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF033BCF1CDB0FE8ULL,
		0x5BEB45C2D07E06F6ULL,
		0x39EE06939FB228A4ULL,
		0xAC74C35E9192B6FDULL,
		0xB1BC918162266194ULL,
		0xA89281CA58095072ULL,
		0xAB93F24C7D0B31D2ULL,
		0x9C291CEE4189F09BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B0DDDDAD8C0C1ADULL,
		0x7AB46002535F49BDULL,
		0x0C9F1E72AB0EDE41ULL,
		0x04523C43BA460922ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6902FC49BE4284CULL,
		0x5C131E0C0DC6E7C6ULL,
		0x651554DE4EC74AB8ULL,
		0x2D29442183CB0064ULL,
		0x24451BC6A77E9294ULL,
		0x4A6C2F683893363EULL,
		0x94E12809E20A37C0ULL,
		0xD946E62BFE3DD3B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73A42F327F5F6F5DULL,
		0x7A36EEFC9B521A17ULL,
		0xB96BF715585EA0C4ULL,
		0x8EAE262C502E9162ULL,
		0x7663B0353AABAAE5ULL,
		0x0453BC88F10AC9A9ULL,
		0xC5CFE7B9AF845D1EULL,
		0x0C5D2D3AD9937404ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3261F82843D3215DULL,
		0x497D3C3410B4EBC1ULL,
		0x6838E9B076471E0AULL,
		0x092C91C0A4E6A340ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB90BEA52875B0E4AULL,
		0xD34F80933D27820CULL,
		0x6DA93DC2E7496E13ULL,
		0x6E6C35FE7781A25AULL,
		0x2E36482B1ABACC95ULL,
		0x0FFEE65DEB5C4862ULL,
		0xE44D2A18CB4B7B9CULL,
		0xFDD1740275F7ADE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03E0E79798D1FBFULL,
		0x02CC89CFC18265FFULL,
		0x7753D7CE8A534A89ULL,
		0x425FB166BF1FCD98ULL,
		0xADDF11575CEEF82BULL,
		0x2327BB00F2BE7A53ULL,
		0x6DA15A1EFFA7580AULL,
		0x9992E3501DD916B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05BFFF473A0F7881ULL,
		0xF87366906311B234ULL,
		0x93D6450897536B33ULL,
		0x0D55FF10CCEC463FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x416248D6D43DDF2CULL,
		0xBD581636A87F35CFULL,
		0xE093DC47F039E7B1ULL,
		0x773323165167D8C5ULL,
		0xCEE7199BB6FA004BULL,
		0xAB9AFC3DEE542CC4ULL,
		0x7A116EA381D88D20ULL,
		0x58118EE3EB7F71EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2B04ADB30684E5CULL,
		0x468E4A3678352C7BULL,
		0x125388E1D018759DULL,
		0x36D31305DEBA824EULL,
		0x9D7B71ED848E605EULL,
		0x0645804E1DF5BFCBULL,
		0xB00211E767E3520DULL,
		0x70C0FADC5E1CC077ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4ACE1D71FCF4D79ULL,
		0x017A31991E4E3650ULL,
		0xCC881751FA8836FFULL,
		0x1656092F6F53AE3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2777EF0D5635B996ULL,
		0x39284851658A226EULL,
		0xEA1D53ED8AEBA65BULL,
		0x9BADAB68650CB90BULL,
		0x4D3EFBBAAE629F42ULL,
		0x60A183D1AFCA9E5AULL,
		0x2222544BBA0A5C2DULL,
		0x80614BC8CFA40F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x111217EC17029FAEULL,
		0x2A2F9AE751EEE85DULL,
		0xB263016C113CFD19ULL,
		0x940ADA5BCB761464ULL,
		0x251C1A004459BF38ULL,
		0xE65B0723D574332FULL,
		0xC69F6274AD9E07E9ULL,
		0x2A6557E7F2F1D5D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B9358CCFC845D3FULL,
		0x356F2F387C6F2279ULL,
		0xCD2A386D51C32B46ULL,
		0x4B09046D5C0B29B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8B3F7A2204DA8CCULL,
		0xF74117E5709104FDULL,
		0xBAB2B25D8DB2B9EAULL,
		0x835D743CE2D9A27FULL,
		0x00A10001B10A2761ULL,
		0xB4DD5E47F144E776ULL,
		0x9CBF1D422C6EC1D6ULL,
		0x56051D5F2824B6EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44EB78269647CF6ULL,
		0x572A7C7DD497D358ULL,
		0xD3F9C34D9483480EULL,
		0x76A36DD09EC8DC90ULL,
		0xAADE5384B48FE819ULL,
		0x8F9D3CC70CD6D7C8ULL,
		0xDD678F9241195A68ULL,
		0x65213C41A19AB593ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF4ADAAD310E9027ULL,
		0x279B9489844F855FULL,
		0x4DB7F72CE7DCCC36ULL,
		0x4E8D70CE3C8CF8CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AC74C9C1813A4BFULL,
		0x9D52D04F4E48637BULL,
		0x0678C566413E4077ULL,
		0xDDC61D29729CA2E5ULL,
		0xBDD77C910821B0C1ULL,
		0xB95B03D50EE3ACD0ULL,
		0xC09E9D86530C501BULL,
		0x4B7BF7231CC7E5A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0B91F66B07BA6F7ULL,
		0x1716B8EA35E74B99ULL,
		0xD72EAA458AF4EC27ULL,
		0xEE2BC5F038A95657ULL,
		0xE758AC286D44B65DULL,
		0x48B632F6F1CB37ABULL,
		0x1C5E2F4D980660B8ULL,
		0xEB910AED50D8D3DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40E11CBC64652510ULL,
		0x3EB3185D6A027B59ULL,
		0x90DA778C792ADD13ULL,
		0x2C7967357F6FF0C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7938C7F9C9D317EDULL,
		0x3EC02166D6D13BE4ULL,
		0x6E86A52A180F8ADAULL,
		0xF1397354D6A00C91ULL,
		0xB28E1C8F83C54993ULL,
		0x980CEC3348FBB4E6ULL,
		0x142426B58945BF88ULL,
		0x536F762229006146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07C7BFB6F36D8B69ULL,
		0x5D5AF9FED5434415ULL,
		0xD5502735BBA9FAB5ULL,
		0x81FA80F7F68C94E0ULL,
		0xACEDF4E0C6523610ULL,
		0xFAC60BCB069BE591ULL,
		0x90FC9FF475AC53D9ULL,
		0x74BBEA780278805BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4736EC32F57A7138ULL,
		0x39EA76E1DBC6BE6EULL,
		0x11147E9D452B8C10ULL,
		0x7DE5AD9E983EDA80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r, COMPLETE);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 501\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}