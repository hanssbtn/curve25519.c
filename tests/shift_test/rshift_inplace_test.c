#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x146F49E4C0ED7C31ULL,
		0x0FCD23336703BE55ULL,
		0x382AA138A3E7A8D3ULL,
		0x252F968A3F420E78ULL,
		0x0499E9466BC0C7BDULL,
		0x59CDF61EF7F5CE6EULL,
		0xA7E6FC333C4A62DEULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xCAA28DE93C981DAFULL,
		0x1A61F9A4666CE077ULL,
		0xCF07055427147CF5ULL,
		0xF7A4A5F2D147E841ULL,
		0xCDC0933D28CD7818ULL,
		0x5BCB39BEC3DEFEB9ULL,
		0x0014FCDF8667894CULL,
		0x0000000000000000ULL
	}};
	int shift = 11;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6ED3EA5DAF4AE0F5ULL,
		0xC8B864BE63039775ULL,
		0x9122F6837DED3931ULL,
		0x8D3DD1B79A12D349ULL,
		0x8FB7EE27EF5A8B09ULL,
		0x90A744902E0BE047ULL,
		0x874AA26397E03261ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97756ED3EA5DAF4AULL,
		0x3931C8B864BE6303ULL,
		0xD3499122F6837DEDULL,
		0x8B098D3DD1B79A12ULL,
		0xE0478FB7EE27EF5AULL,
		0x326190A744902E0BULL,
		0x0000874AA26397E0ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x31A1DA74E743A36CULL,
		0xB3CFC70084A334E6ULL,
		0x7E0701ED1C7B9513ULL,
		0xB07A8A1E5C91BFA8ULL,
		0xED8FE1098CAEAD64ULL,
		0x1D284610D83A6591ULL,
		0x4D48657073427FF6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6343B4E9CE8746ULL,
		0x27679F8E01094669ULL,
		0x50FC0E03DA38F72AULL,
		0xC960F5143CB9237FULL,
		0x23DB1FC213195D5AULL,
		0xEC3A508C21B074CBULL,
		0x009A90CAE0E684FFULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xFB45FA77E76D5B41ULL,
		0xB390B5A7667D4F68ULL,
		0xC31F862C53D832F9ULL,
		0xDB5B978B1D1C9932ULL,
		0x98C8144737B5860FULL,
		0x84531E58009CA1D9ULL,
		0x585F7C4073E918E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4ECCFA9ED1F68BULL,
		0x0C58A7B065F36721ULL,
		0x2F163A393265863FULL,
		0x288E6F6B0C1FB6B7ULL,
		0x3CB0013943B33190ULL,
		0xF880E7D231C908A6ULL,
		0x000000000000B0BEULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xCEDEE717E2AF8C7FULL,
		0x3484DF6A34493233ULL,
		0xBBC75C961A1351A3ULL,
		0xC16B75020AFE17ABULL,
		0x6DDAB8E137E9FBB6ULL,
		0x506A6F5C74D0B768ULL,
		0x56A8E69D235465D2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA34493233CEDEE71ULL,
		0x61A1351A33484DF6ULL,
		0x20AFE17ABBBC75C9ULL,
		0x137E9FBB6C16B750ULL,
		0xC74D0B7686DDAB8EULL,
		0xD235465D2506A6F5ULL,
		0x00000000056A8E69ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x5758059D995B17A9ULL,
		0x5851C1697B802586ULL,
		0xCDB1A49414992D6CULL,
		0x4812EE23455884DFULL,
		0x055BAD16F1D90DBAULL,
		0xA3B949CC4F9209E4ULL,
		0xDC4002600F9AFB07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C32BAC02CECCAD8ULL,
		0x6B62C28E0B4BDC01ULL,
		0x26FE6D8D24A0A4C9ULL,
		0x6DD24097711A2AC4ULL,
		0x4F202ADD68B78EC8ULL,
		0xD83D1DCA4E627C90ULL,
		0x0006E20013007CD7ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x2CFB1596E073AB7FULL,
		0x3E5E32350B029CF5ULL,
		0x170E420845BDB1F1ULL,
		0xC62940CCBF55FD9EULL,
		0xD492A0FA5926DF00ULL,
		0xB4746058B217815CULL,
		0xB66D64649001113DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60539EA59F62B2DCULL,
		0xB7B63E27CBC646A1ULL,
		0xEABFB3C2E1C84108ULL,
		0x24DBE018C5281997ULL,
		0x42F02B9A92541F4BULL,
		0x002227B68E8C0B16ULL,
		0x00000016CDAC8C92ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x240AD3EB609EAC97ULL,
		0x41D24C4CCE2DD765ULL,
		0x3B0B63722915EAF1ULL,
		0x5219605ACECA2C6BULL,
		0x46361D91A77F2C84ULL,
		0x9CBDA4D40FE8C96CULL,
		0xBC1D60B000144272ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C5BAECA4815A7D6ULL,
		0x522BD5E283A49899ULL,
		0x9D9458D67616C6E4ULL,
		0x4EFE5908A432C0B5ULL,
		0x1FD192D88C6C3B23ULL,
		0x002884E5397B49A8ULL,
		0x00000001783AC160ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x78F4602124513C59ULL,
		0x2F6378D46F91EEA7ULL,
		0x8E44A58C15B0A1F9ULL,
		0x0F3D72ADAA07C753ULL,
		0xCC5E4AF188DF5323ULL,
		0xFDEB0347F2D8FD23ULL,
		0xEB3CDA6462315938ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA778F4602124513CULL,
		0xF92F6378D46F91EEULL,
		0x538E44A58C15B0A1ULL,
		0x230F3D72ADAA07C7ULL,
		0x23CC5E4AF188DF53ULL,
		0x38FDEB0347F2D8FDULL,
		0x00EB3CDA64623159ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBA4F35E9A016CFFDULL,
		0x9A3CD236AA7CDBF6ULL,
		0xB114E5B8C8D4B09AULL,
		0xF70BE2C2BF7E4A6DULL,
		0x39B617E513D05623ULL,
		0x81C674F210EE8F5AULL,
		0x58AAEBC502DDE733ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46D54F9B7ED749E6ULL,
		0xB7191A961353479AULL,
		0x5857EFC94DB6229CULL,
		0xFCA27A0AC47EE17CULL,
		0x9E421DD1EB4736C2ULL,
		0x78A05BBCE67038CEULL,
		0x00000000000B155DULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xFF75C3717FEC5719ULL,
		0x0D67F25CF098FF93ULL,
		0xA8BD0C01A586A034ULL,
		0xDE577CE5375616A2ULL,
		0x350B2F054222B519ULL,
		0x9C0BB80446CAF55DULL,
		0x36F5620F613D77BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE131FF27FEEB86E2ULL,
		0x4B0D40681ACFE4B9ULL,
		0x6EAC2D45517A1803ULL,
		0x84456A33BCAEF9CAULL,
		0x8D95EABA6A165E0AULL,
		0xC27AEF7B38177008ULL,
		0x000000006DEAC41EULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xCDFEAA35D1AE67C4ULL,
		0x2D5D19BDC7799FD7ULL,
		0x53D6C85BB8D8C803ULL,
		0xC684EB54F6960530ULL,
		0x3FA73BB04597FB3EULL,
		0x51786C4066658D47ULL,
		0xADB45D2BC697D8ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71DE67F5F37FAA8DULL,
		0xEE363200CB57466FULL,
		0x3DA5814C14F5B216ULL,
		0x1165FECFB1A13AD5ULL,
		0x19996351CFE9CEECULL,
		0xF1A5F63B145E1B10ULL,
		0x000000002B6D174AULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB11F0E58FC4ECE7AULL,
		0xD3B01D16C8FAF235ULL,
		0xBF2063C0F083B754ULL,
		0x5EE62586EACB8027ULL,
		0x5AAA555186139236ULL,
		0xF7D458AD350D8C50ULL,
		0xB7F6BF924FB0E512ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF235B11F0E58FCULL,
		0x83B754D3B01D16C8ULL,
		0xCB8027BF2063C0F0ULL,
		0x1392365EE62586EAULL,
		0x0D8C505AAA555186ULL,
		0xB0E512F7D458AD35ULL,
		0x000000B7F6BF924FULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA36DB716AFD46930ULL,
		0x9E50BBE718EE46B7ULL,
		0x6531E2AF0D8FF16DULL,
		0x524CDE8EFB99640CULL,
		0x4F8252089476F2E6ULL,
		0x5193E35989A87A7DULL,
		0x805D0B5F3AEF9BC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF38C77235BD1B6DBULL,
		0x5786C7F8B6CF285DULL,
		0x477DCCB2063298F1ULL,
		0x044A3B797329266FULL,
		0xACC4D43D3EA7C129ULL,
		0xAF9D77CDE028C9F1ULL,
		0x0000000000402E85ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x377ECDEA0A4C5445ULL,
		0x3343532335825E45ULL,
		0x4E7A1F468BEF8A18ULL,
		0xCD187D5B44AB88DDULL,
		0x148EDFF2E8808992ULL,
		0xF62DFFF1C9AF5A1AULL,
		0xBB4162EFC46DF965ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x335825E45377ECDEULL,
		0x68BEF8A183343532ULL,
		0xB44AB88DD4E7A1F4ULL,
		0x2E8808992CD187D5ULL,
		0x1C9AF5A1A148EDFFULL,
		0xFC46DF965F62DFFFULL,
		0x000000000BB4162EULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x07FE5836454D115FULL,
		0x3C01C6985F86FBA4ULL,
		0xE06866AE2097A82CULL,
		0xEB7422B8161C785EULL,
		0xCE42F126B1C916BCULL,
		0x103818F4F7B719ECULL,
		0x549B7BEF99437AF6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FF960D91534457ULL,
		0x0F0071A617E1BEE9ULL,
		0xB81A19AB8825EA0BULL,
		0x3ADD08AE05871E17ULL,
		0x3390BC49AC7245AFULL,
		0x840E063D3DEDC67BULL,
		0x1526DEFBE650DEBDULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB778EECB2C806D80ULL,
		0x252F60FB22FB9DA3ULL,
		0x72ABE2E8C6B454F3ULL,
		0xE11E829778E33D45ULL,
		0xD264FBC2260A97EBULL,
		0x8715085646FEE01AULL,
		0x097610F244B47D8BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE768EDDE3BB2CB2ULL,
		0xD153CC94BD83EC8BULL,
		0x8CF515CAAF8BA31AULL,
		0x2A5FAF847A0A5DE3ULL,
		0xFB806B4993EF0898ULL,
		0xD1F62E1C5421591BULL,
		0x00000025D843C912ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3B3646724C802CD7ULL,
		0xB06E1D044B9FCCFEULL,
		0x2DE6E89A7DA4137CULL,
		0xAB19E4C69F037F1EULL,
		0x750C02A3927ADCAFULL,
		0x371B07C01A1EE86BULL,
		0xE06D1827E3484A9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E7F33F8ECD919CULL,
		0x9F6904DF2C1B8741ULL,
		0xA7C0DFC78B79BA26ULL,
		0xE49EB72BEAC67931ULL,
		0x0687BA1ADD4300A8ULL,
		0xF8D212A74DC6C1F0ULL,
		0x00000000381B4609ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x91EF7E25B4709942ULL,
		0xEC32F5076AD64CC2ULL,
		0xC57D62B83BFAFC34ULL,
		0x78B592E892C750E3ULL,
		0x4EC874AE5782A777ULL,
		0x68D1C36E1FD0F3DEULL,
		0x9225DA77253826C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998523DEFC4B68E1ULL,
		0xF869D865EA0ED5ACULL,
		0xA1C78AFAC57077F5ULL,
		0x4EEEF16B25D1258EULL,
		0xE7BC9D90E95CAF05ULL,
		0x4D84D1A386DC3FA1ULL,
		0x0001244BB4EE4A70ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xF9523A9E3597B261ULL,
		0xDD2CCA2B983459D7ULL,
		0x5B65F8EF843A0F8FULL,
		0x74C85CAFD7E9A8FFULL,
		0x878D722CCC4971F8ULL,
		0x0E60BF3B60C1F1E7ULL,
		0x3026450BA8E1089DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F9523A9E3597B26ULL,
		0xFDD2CCA2B983459DULL,
		0xF5B65F8EF843A0F8ULL,
		0x874C85CAFD7E9A8FULL,
		0x7878D722CCC4971FULL,
		0xD0E60BF3B60C1F1EULL,
		0x03026450BA8E1089ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD48F607C074B42F6ULL,
		0x0F1EA1E1D847357EULL,
		0x8A5482F0CA3C91A7ULL,
		0xE5E7E5E2F14B7580ULL,
		0x150A2CD60664782AULL,
		0x3864756DF3145E6BULL,
		0x785ABD90C3140C1BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA91EC0F80E9685ULL,
		0x4E1E3D43C3B08E6AULL,
		0x0114A905E1947923ULL,
		0x55CBCFCBC5E296EBULL,
		0xD62A1459AC0CC8F0ULL,
		0x3670C8EADBE628BCULL,
		0x00F0B57B21862818ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3ED480B649D35B07ULL,
		0x0A97EF8B1B212183ULL,
		0x35CACB020777595CULL,
		0xBA35A46239340D39ULL,
		0x6F29755EA6F14847ULL,
		0x0A0B855FE69200F5ULL,
		0x11F0CA5AFCD103A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF16364243067DA9ULL,
		0x96040EEEB2B8152FULL,
		0x48C472681A726B95ULL,
		0xEABD4DE2908F746BULL,
		0x0ABFCD2401EADE52ULL,
		0x94B5F9A207521417ULL,
		0x00000000000023E1ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x74CC69826DAADC0DULL,
		0xE1E89F6FFF77CFDCULL,
		0x5B1ABE043D9E15F3ULL,
		0x94D02A606E0F92D7ULL,
		0x03327C095482FCEDULL,
		0x5493E07FC77E6A7DULL,
		0xD6B3F2AC659CFE31ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6FFF77CFDC74CC6ULL,
		0xE043D9E15F3E1E89ULL,
		0xA606E0F92D75B1ABULL,
		0xC095482FCED94D02ULL,
		0x07FC77E6A7D03327ULL,
		0x2AC659CFE315493EULL,
		0x00000000000D6B3FULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x8313BF07AAB37BB7ULL,
		0x6DC74BBE18BAEF4FULL,
		0x42B2C47A97395987ULL,
		0x9ED08A9420F28AF0ULL,
		0x5F24F8773CB1145BULL,
		0xA01770942CB9E478ULL,
		0xDE903DCD456D3912ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C4EFC1EAACDEEDULL,
		0xDB71D2EF862EBBD3ULL,
		0x10ACB11EA5CE5661ULL,
		0xE7B422A5083CA2BCULL,
		0x17C93E1DCF2C4516ULL,
		0xA805DC250B2E791EULL,
		0x37A40F73515B4E44ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC6DEA7B49D604010ULL,
		0x57F71BAF4B2E8EFBULL,
		0xD0A8A82436D0D405ULL,
		0x8D529C8B0F6D43D5ULL,
		0x41E98F2D6B841DACULL,
		0x80A1E8F47FF3FE97ULL,
		0xADE8A459BDE5E39CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A597477DE36F53DULL,
		0x21B686A02ABFB8DDULL,
		0x587B6A1EAE854541ULL,
		0x6B5C20ED646A94E4ULL,
		0xA3FF9FF4BA0F4C79ULL,
		0xCDEF2F1CE4050F47ULL,
		0x00000000056F4522ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xE788835C72BD57FFULL,
		0xA8D99A5985E4D7BDULL,
		0xD9483537BBC73913ULL,
		0x316DDF9FEAFC94C3ULL,
		0xEDEF053AFCD46C01ULL,
		0x3AA33364A2F34B17ULL,
		0x6F498EBA322EF5D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AF7BCF1106B8E5ULL,
		0x8E722751B334B30BULL,
		0xF92987B2906A6F77ULL,
		0xA8D80262DBBF3FD5ULL,
		0xE6962FDBDE0A75F9ULL,
		0x5DEBA8754666C945ULL,
		0x000000DE931D7464ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC7FBFACE4AC2A0D3ULL,
		0x677FCEE853DA8F25ULL,
		0x67D860F14F147A24ULL,
		0x68BE1723E42B29E4ULL,
		0x672A7672B1505602ULL,
		0xB24B4950DA6BFC48ULL,
		0x81B8E6A132430DE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x429ED4792E3FDFD6ULL,
		0x8A78A3D1233BFE77ULL,
		0x1F21594F233EC307ULL,
		0x958A82B01345F0B9ULL,
		0x86D35FE2433953B3ULL,
		0x0992186F35925A4AULL,
		0x00000000040DC735ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4C78B9FE460CFAB2ULL,
		0x151E81DE76354573ULL,
		0x51D74EB9E8FB7156ULL,
		0xAC4D4E8ED9E20773ULL,
		0xA009076B3337E7F3ULL,
		0xA8637D9ECDA07290ULL,
		0x254849AB52AD6D6AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D515CD31E2E7F91ULL,
		0x3EDC558547A0779DULL,
		0x7881DCD475D3AE7AULL,
		0xCDF9FCEB1353A3B6ULL,
		0x681CA4280241DACCULL,
		0xAB5B5AAA18DF67B3ULL,
		0x0000000952126AD4ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x537986D81BD71CC3ULL,
		0x58AD2AFE422551A4ULL,
		0x02A36F07E9299F20ULL,
		0x6F136B714D3A8D85ULL,
		0xA3FFBDADEFB0417AULL,
		0xB4DE85DE337DCB8EULL,
		0x0FAB96A5DE94B347ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC844AA348A6F30ULL,
		0xE0FD2533E40B15A5ULL,
		0x6E29A751B0A0546DULL,
		0xB5BDF6082F4DE26DULL,
		0xBBC66FB971D47FF7ULL,
		0xD4BBD29668F69BD0ULL,
		0x000000000001F572ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x536BA187DD8657C1ULL,
		0x8AAB387208A639C0ULL,
		0xBDD5E5BA94BF18CEULL,
		0x46D9BE025AD05207ULL,
		0x4598C53242BCB0D4ULL,
		0xF96589C09CFB4064ULL,
		0xC152CDDBB57C6CF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4114C7380A6D74ULL,
		0xB75297E319D15567ULL,
		0xC04B5A0A40F7BABCULL,
		0xA64857961A88DB37ULL,
		0x38139F680C88B318ULL,
		0xBB76AF8D9EBF2CB1ULL,
		0x0000000000182A59ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xA83B3C3DD7DC39A3ULL,
		0x81BB2E382CB55683ULL,
		0xD975725092A4B8C6ULL,
		0xE8A98480A54A8E1EULL,
		0xB51586935E367195ULL,
		0x6F3078478CDC2FCBULL,
		0x6FA299BFCC5468E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41D41D9E1EEBEE1ULL,
		0xC6340DD971C165AAULL,
		0x70F6CBAB92849525ULL,
		0x8CAF454C24052A54ULL,
		0x7E5DA8AC349AF1B3ULL,
		0x474B7983C23C66E1ULL,
		0x00037D14CDFE62A3ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x92C3ADB2A96AA7E6ULL,
		0x26C9FE47C3AFF37AULL,
		0x1FCC221AEB97C1CFULL,
		0x7B7E2F10D532F978ULL,
		0x70832FB7B99D8A2DULL,
		0xFA424EB05CF79046ULL,
		0xA781F38D3D98D649ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCDEA4B0EB6CAA5AULL,
		0xF073C9B27F91F0EBULL,
		0xBE5E07F30886BAE5ULL,
		0x628B5EDF8BC4354CULL,
		0xE4119C20CBEDEE67ULL,
		0x35927E9093AC173DULL,
		0x000029E07CE34F66ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4984E9DA7A4220F5ULL,
		0xAF37B3B7CA9091EEULL,
		0x44E93AACB565F414ULL,
		0xBF43CA4DBC5C1016ULL,
		0xB0899B2461B2E108ULL,
		0xD88A1C9C7E640D34ULL,
		0xD485A971D2DE3113ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDECEDF2A4247B926ULL,
		0xA4EAB2D597D052BCULL,
		0x0F2936F170405913ULL,
		0x266C9186CB8422FDULL,
		0x287271F99034D2C2ULL,
		0x16A5C74B78C44F62ULL,
		0x0000000000000352ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1A267F236A8AC443ULL,
		0x88835498CD4EA449ULL,
		0x741DE5D1B2ADAA4DULL,
		0xF7BB083957869D43ULL,
		0x7DC34F12C60331F8ULL,
		0xC31335090E68E44AULL,
		0xF9DE44994D0C5845ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9319A9D4892344ULL,
		0xBCBA3655B549B110ULL,
		0x61072AF0D3A86E83ULL,
		0x69E258C0663F1EF7ULL,
		0x66A121CD1C894FB8ULL,
		0xC89329A18B08B862ULL,
		0x0000000000001F3BULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x4844531189C97007ULL,
		0x8AC2B30F940175D1ULL,
		0x36CB484CB48885D2ULL,
		0x1FE730DF3D7D0FB0ULL,
		0x44FCB2DEA4DE3450ULL,
		0xF09FE4E1CED3B59DULL,
		0x104A8ADE027B6546ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ACC3E5005D74521ULL,
		0x2D2132D222174A2BULL,
		0x9CC37CF5F43EC0DBULL,
		0xF2CB7A9378D1407FULL,
		0x7F93873B4ED67513ULL,
		0x2A2B7809ED951BC2ULL,
		0x0000000000000041ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xC7FBB639FED6EEA0ULL,
		0xEB96007CCD63ADF1ULL,
		0xCE1E6EE99CEA529EULL,
		0xC9A8819C5EFBB822ULL,
		0xA1F33D8E7B167E0DULL,
		0x0DFAE274132F46BAULL,
		0x24814CD1C7133746ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB7C71FEED8E7FBULL,
		0xA94A7BAE5801F335ULL,
		0xEEE08B3879BBA673ULL,
		0x59F83726A206717BULL,
		0xBD1AEA87CCF639ECULL,
		0x4CDD1837EB89D04CULL,
		0x000000920533471CULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x0DEB3A92A0D61026ULL,
		0x86569C19E57DB48CULL,
		0xDC9C445EA8D3288EULL,
		0x352FD90F6AE5E2E9ULL,
		0x676D912D45231DE5ULL,
		0x305EFB8FBD970BA8ULL,
		0xB8235F744EAD2ECFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E57DB48C0DEB3A9ULL,
		0xEA8D3288E86569C1ULL,
		0xF6AE5E2E9DC9C445ULL,
		0xD45231DE5352FD90ULL,
		0xFBD970BA8676D912ULL,
		0x44EAD2ECF305EFB8ULL,
		0x000000000B8235F7ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB4606A1E65BCC8B6ULL,
		0x402D06806CEF8E40ULL,
		0x98CFF33885317B49ULL,
		0xC3E5C1759357C7F1ULL,
		0x46B167B1D02427AEULL,
		0xA44448DEC25DABFFULL,
		0xBC614125E85EBBE4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6806CEF8E40B4606ULL,
		0x33885317B49402D0ULL,
		0x1759357C7F198CFFULL,
		0x7B1D02427AEC3E5CULL,
		0x8DEC25DABFF46B16ULL,
		0x125E85EBBE4A4444ULL,
		0x00000000000BC614ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x929AC47521955B44ULL,
		0x613ECC3C5F2EA06AULL,
		0xC942A2C15CED28F3ULL,
		0xC6E764A6856A3E5CULL,
		0x035142E8F15C0F6EULL,
		0xACD86A6AEE37D239ULL,
		0x407F0F0F2EEA743CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40D5253588EA432ULL,
		0xA51E6C27D9878BE5ULL,
		0x47CB992854582B9DULL,
		0x81EDD8DCEC94D0ADULL,
		0xFA47206A285D1E2BULL,
		0x4E87959B0D4D5DC6ULL,
		0x0000080FE1E1E5DDULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x6A0FB6DE0FF51517ULL,
		0x6A2A1496D044A1FEULL,
		0x31B8910A88E9EC22ULL,
		0x367124DED5FE63EAULL,
		0x9FC7E7D75BF7E19EULL,
		0x3C7BC1AD1770F8F4ULL,
		0x8297EB31AECFCA4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682250FF3507DB6FULL,
		0x4474F61135150A4BULL,
		0x6AFF31F518DC4885ULL,
		0xADFBF0CF1B38926FULL,
		0x8BB87C7A4FE3F3EBULL,
		0xD767E5269E3DE0D6ULL,
		0x00000000414BF598ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xABB4C4C38F2231E2ULL,
		0x53F3A71CD9E6BE9DULL,
		0x2362619371F93395ULL,
		0x495D783442263623ULL,
		0x347251AB2DDDFC29ULL,
		0xF2A481C3B8423A39ULL,
		0x4FF1F5BE15FB5974ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B3CD7D3B5769898ULL,
		0x6E3F2672AA7E74E3ULL,
		0x8844C6C4646C4C32ULL,
		0x65BBBF85292BAF06ULL,
		0x77084747268E4A35ULL,
		0xC2BF6B2E9E549038ULL,
		0x0000000009FE3EB7ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x1229AE3D3FD0B904ULL,
		0x4A53A01E83CAC2A3ULL,
		0x5A1E865C55F56709ULL,
		0x69A543E7CB3D5FB8ULL,
		0xE3830369DE0A5686ULL,
		0x08AFEF88616515B5ULL,
		0x8C84695F631E5B1FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0A8C48A6B8F4FFULL,
		0xD59C25294E807A0FULL,
		0xF57EE1687A197157ULL,
		0x295A19A6950F9F2CULL,
		0x9456D78E0C0DA778ULL,
		0x796C7C22BFBE2185ULL,
		0x0000023211A57D8CULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xB24EDB95EDF7EF9DULL,
		0xF4116ECAFDFDF9E7ULL,
		0xD8548515FB8792EDULL,
		0x3FEF3F47AD0923AEULL,
		0x6CA797BA96F55F9DULL,
		0xBF09742BD6104950ULL,
		0x0BF937FC01235869ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF9E7B24EDB95EDFULL,
		0x792EDF4116ECAFDFULL,
		0x923AED8548515FB8ULL,
		0x55F9D3FEF3F47AD0ULL,
		0x049506CA797BA96FULL,
		0x35869BF09742BD61ULL,
		0x000000BF937FC012ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x3A445619D0F335F6ULL,
		0x476857B98F163CBDULL,
		0x9EF308FB998775C8ULL,
		0xF22ECB3A8AD1180CULL,
		0x19D270AFB8A1761DULL,
		0xCCB4A2811D3B06CAULL,
		0x73E02C30CBC033F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED0AF731E2C797A7ULL,
		0xDE611F7330EEB908ULL,
		0x45D967515A230193ULL,
		0x3A4E15F7142EC3BEULL,
		0x96945023A760D943ULL,
		0x7C05861978067E79ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xAE62C02C8AD5A947ULL,
		0x12641AB95A8E0465ULL,
		0x7F69CAAD6058BC9CULL,
		0x1E38E8C8A6471823ULL,
		0xCC2647123D650BF4ULL,
		0xB6E5A7D471364762ULL,
		0xF57E6741995BBB8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x196B98B00B22B56AULL,
		0x27049906AE56A381ULL,
		0x08DFDA72AB58162FULL,
		0xFD078E3A322991C6ULL,
		0xD8B30991C48F5942ULL,
		0xE2ADB969F51C4D91ULL,
		0x003D5F99D06656EEULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xBE04C6B004750C49ULL,
		0x65A325A5C198EB50ULL,
		0x859180AF3893F53BULL,
		0xAF83F04C6D834F8DULL,
		0x44F004EDFEBB6962ULL,
		0x68A4AA872C3BD3E2ULL,
		0x08E5D2A71980DFD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD192D2E0CC75A85FULL,
		0xC8C0579C49FA9DB2ULL,
		0xC1F82636C1A7C6C2ULL,
		0x780276FF5DB4B157ULL,
		0x525543961DE9F122ULL,
		0x72E9538CC06FE8B4ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x83C003A2A01AD3BEULL,
		0x522E49E2A2AA01D3ULL,
		0x5C4A890AF3AF87A4ULL,
		0xA8E7AB6F5044F114ULL,
		0x074E02468C2FB362ULL,
		0xECE25E1E892A5270ULL,
		0xBFB900CD542806FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278A8AA8074E0F00ULL,
		0x242BCEBE1E9148B9ULL,
		0xADBD4113C451712AULL,
		0x091A30BECD8AA39EULL,
		0x787A24A949C01D38ULL,
		0x033550A01BEBB389ULL,
		0x000000000002FEE4ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xFF5ADCDA4E7E9C0FULL,
		0xE0AAB0BF54302FFAULL,
		0xFD49770C8B2D8A3DULL,
		0xD1BDB5A658E2EE06ULL,
		0x9993E6741C915341ULL,
		0x056005D7199C1691ULL,
		0xC6E391D9C0D328D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFEBFD6B736939FAULL,
		0x28F782AAC2FD50C0ULL,
		0xB81BF525DC322CB6ULL,
		0x4D0746F6D699638BULL,
		0x5A46664F99D07245ULL,
		0xA34C1580175C6670ULL,
		0x00031B8E4767034CULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0x65362F3875E5EDC2ULL,
		0x7AD563EDE1CAC731ULL,
		0x73CEBCA8E524359FULL,
		0x753CB203E0C9FBE0ULL,
		0x7A6C32ACA5E9B1C3ULL,
		0xA817355C82C39E32ULL,
		0x25C8712FE0A11230ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DBC3958E62CA6CULL,
		0x7951CA486B3EF5AAULL,
		0x6407C193F7C0E79DULL,
		0x65594BD36386EA79ULL,
		0x6AB905873C64F4D8ULL,
		0xE25FC1422461502EULL,
		0x0000000000004B90ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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
		0xD4F1CA1B7C99B261ULL,
		0x94CFCA2AA5808C84ULL,
		0x97D86A6723A2510BULL,
		0x982A6F48A8B1F0F5ULL,
		0x540A15AB39581958ULL,
		0x9C1005F1A6C16232ULL,
		0x740331118EDE44A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA67E51552C046426ULL,
		0xBEC353391D12885CULL,
		0xC1537A45458F87ACULL,
		0xA050AD59CAC0CAC4ULL,
		0xE0802F8D360B1192ULL,
		0xA019888C76F22534ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
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