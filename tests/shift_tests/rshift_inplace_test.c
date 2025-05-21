#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5D92D19B74F29F9FULL,
		0x147E4C70E6641ECAULL,
		0x1B8166DD8F028858ULL,
		0xB8C839FC68002733ULL,
		0xA2E9DD6DC7636216ULL,
		0x1A8121F375851D7FULL,
		0x774FF58378F53224ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB29764B466DD3CA7ULL,
		0x16051F931C399907ULL,
		0xCCC6E059B763C0A2ULL,
		0x85AE320E7F1A0009ULL,
		0x5FE8BA775B71D8D8ULL,
		0x8906A0487CDD6147ULL,
		0x001DD3FD60DE3D4CULL,
		0x0000000000000000ULL
	}};
	int shift = 10;
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
		0x3B9E2D5B4DC4A4A8ULL,
		0x8F7A63E6C1F90D93ULL,
		0x6B6AEA07F74346F9ULL,
		0x75330C82F83598D5ULL,
		0xB8ABCC0785C292D3ULL,
		0xDD9A29B0322136E4ULL,
		0x85073B5F5B3EEE59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F9B07E4364CEE7ULL,
		0xBA81FDD0D1BE63DEULL,
		0xC320BE0D66355ADAULL,
		0xF301E170A4B4DD4CULL,
		0x8A6C0C884DB92E2AULL,
		0xCED7D6CFBB967766ULL,
		0x0000000000002141ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x4DB22FE1951195F7ULL,
		0x481B97A9A558416EULL,
		0xED6A64234A1C84BCULL,
		0x6FB5467304E8B906ULL,
		0xDCD3243CA692D477ULL,
		0xFCA39E2B3F0262A1ULL,
		0x245EBB4F2E39976EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B936C8BF8654465ULL,
		0x2F1206E5EA695610ULL,
		0x41BB5A9908D28721ULL,
		0x1DDBED519CC13A2EULL,
		0xA87734C90F29A4B5ULL,
		0xDBBF28E78ACFC098ULL,
		0x000917AED3CB8E65ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0xA7D5C9E4DCF38216ULL,
		0x6C2553E4B82A367BULL,
		0x0B5FA5C0975049B4ULL,
		0x34A59C4D6F4FFFD3ULL,
		0x83106B1F9037BAD9ULL,
		0x2265671772B96D42ULL,
		0x6C28AA52B695D5AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C151B3DD3EAE4F2ULL,
		0x4BA824DA3612A9F2ULL,
		0xB7A7FFE985AFD2E0ULL,
		0xC81BDD6C9A52CE26ULL,
		0xB95CB6A14188358FULL,
		0x5B4AEAD71132B38BULL,
		0x0000000036145529ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x035D0567EBC1C2AAULL,
		0xF75B01147562A954ULL,
		0x1B195CF565D8FA5EULL,
		0xB93E6E54CA630D87ULL,
		0x2792A5CD1C826414ULL,
		0x772E10B98EF8B6E7ULL,
		0x845D7D30989E5CD1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0228EAC552A806BAULL,
		0xB9EACBB1F4BDEEB6ULL,
		0xDCA994C61B0E3632ULL,
		0x4B9A3904C829727CULL,
		0x21731DF16DCE4F25ULL,
		0xFA61313CB9A2EE5CULL,
		0x00000000000108BAULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0xC5766F217752A02BULL,
		0x07C6A8E691654DE0ULL,
		0x37464AC88D509431ULL,
		0xB3BE76CBF73F27D8ULL,
		0x1F3B566ACC7D907DULL,
		0x103E48199DC0473FULL,
		0xC1A549F9B8015C02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA39A4595378315DULL,
		0x92B22354250C41F1ULL,
		0x9DB2FDCFC9F60DD1ULL,
		0xD59AB31F641F6CEFULL,
		0x9206677011CFC7CEULL,
		0x527E6E005700840FULL,
		0x0000000000003069ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x499B98F01AB2BF6DULL,
		0x4CC5162454AB62EAULL,
		0x908033DFD75F4589ULL,
		0x0D70A66F606F5B12ULL,
		0x5739AB45C01216B0ULL,
		0xEF7B9AD50BA714DDULL,
		0x1DF17C602651FFADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x152AD8BA9266E63CULL,
		0xF5D7D16253314589ULL,
		0xD81BD6C4A4200CF7ULL,
		0x700485AC035C299BULL,
		0x42E9C53755CE6AD1ULL,
		0x09947FEB7BDEE6B5ULL,
		0x00000000077C5F18ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x619D801486054C38ULL,
		0x6212F28D18ADFC08ULL,
		0x4400184022B2504DULL,
		0x999150F7561D0818ULL,
		0xC54E148CCED2A7C6ULL,
		0xF16CE2BB33A8B2C7ULL,
		0x5BEC15901A915419ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x186760052181530EULL,
		0x5884BCA3462B7F02ULL,
		0x1100061008AC9413ULL,
		0xA664543DD5874206ULL,
		0xF153852333B4A9F1ULL,
		0x7C5B38AECCEA2CB1ULL,
		0x16FB056406A45506ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xC176580E135ADFF2ULL,
		0xB15D13F176D6E15BULL,
		0xD0C6C8ECE2CCB657ULL,
		0xFB341840CF7EE3B8ULL,
		0xFA2BDE79EA77CEF0ULL,
		0x107D475B9EA29A6EULL,
		0x479A9996E0265D40ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70ADE0BB2C0709ADULL,
		0x5B2BD8AE89F8BB6BULL,
		0x71DC686364767166ULL,
		0xE7787D9A0C2067BFULL,
		0x4D377D15EF3CF53BULL,
		0x2EA0083EA3ADCF51ULL,
		0x000023CD4CCB7013ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xFC63B7CE2E965CDEULL,
		0x0BAAC11175F71D94ULL,
		0x8E144D349753D5DFULL,
		0x181967313889F122ULL,
		0xABA809B5797F0FB3ULL,
		0xFD4C04548DF106FCULL,
		0x4F077C1690204E0BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11175F71D94FC63BULL,
		0xD349753D5DF0BAACULL,
		0x7313889F1228E144ULL,
		0x9B5797F0FB318196ULL,
		0x4548DF106FCABA80ULL,
		0xC1690204E0BFD4C0ULL,
		0x000000000004F077ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x6E58D9AD3C620590ULL,
		0x1609C24DE1C052BDULL,
		0xBC28CA04781E28C3ULL,
		0x13A130963FDD5021ULL,
		0xF3EE0DB3229A274AULL,
		0xDED97DA2DB77EEBAULL,
		0xDDDE4FE40E74E5A5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3849BC380A57ADCBULL,
		0x19408F03C51862C1ULL,
		0x2612C7FBAA043785ULL,
		0xC1B6645344E94274ULL,
		0x2FB45B6EFDD75E7DULL,
		0xC9FC81CE9CB4BBDBULL,
		0x0000000000001BBBULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0xFF4FD680D3470618ULL,
		0x9961C624E2351C58ULL,
		0x57E47A022C200A46ULL,
		0x86E162DB2D9AC62FULL,
		0xA553F95737A50EBCULL,
		0x80C6F8E41879D016ULL,
		0x3E7273E0133FABC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1FE9FAD01A68E0CULL,
		0x8D32C38C49C46A38ULL,
		0x5EAFC8F404584014ULL,
		0x790DC2C5B65B358CULL,
		0x2D4AA7F2AE6F4A1DULL,
		0x87018DF1C830F3A0ULL,
		0x007CE4E7C0267F57ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x27DDE2A1395FC228ULL,
		0x100841E88B9B6E1BULL,
		0xD9DB13A6790C9B92ULL,
		0x40E6A99DC9F556D4ULL,
		0x282CD62D765F7148ULL,
		0x0C3766E2CA9A0573ULL,
		0xF330D5CAE3AF1B5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D93EEF1509CAFEULL,
		0xDC9080420F445CDBULL,
		0xB6A6CED89D33C864ULL,
		0x8A4207354CEE4FAAULL,
		0x2B994166B16BB2FBULL,
		0xDAE061BB371654D0ULL,
		0x00079986AE571D78ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x5EC6B96E5D457AF7ULL,
		0x40E1DC13D713A9C9ULL,
		0xA6B36E770460BD51ULL,
		0x69AF332B6EB8FA2FULL,
		0x88CED3A8A3758DBAULL,
		0x61B3B9CF9CAC66CAULL,
		0x9D26C16A956B99CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B827AE275392BD8ULL,
		0x6DCEE08C17AA281CULL,
		0xE6656DD71F45F4D6ULL,
		0xDA75146EB1B74D35ULL,
		0x7739F3958CD95119ULL,
		0xD82D52AD73394C36ULL,
		0x00000000000013A4ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0x7040520456A1F6CDULL,
		0xA6B70864F03029DFULL,
		0x47F430000AF213E3ULL,
		0xB80307244249FF1FULL,
		0xA2C46F6FC2C2B526ULL,
		0xF517DFAEED3B5022ULL,
		0xB0A3F86D378F6049ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C0A77DC1014811ULL,
		0x2BC84F8E9ADC2193ULL,
		0x0927FC7D1FD0C000ULL,
		0x0B0AD49AE00C1C91ULL,
		0xB4ED408A8B11BDBFULL,
		0xDE3D8127D45F7EBBULL,
		0x00000002C28FE1B4ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xF0D327BEBEA68595ULL,
		0xAF1E80B4299079B7ULL,
		0x1AC69AD2E88CC9E8ULL,
		0xE507D12050232801ULL,
		0xA2B7FAA134C13AFDULL,
		0x2E34940FDD80B003ULL,
		0xFF0C193AE8B1AE12ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05A14C83CDBF8699ULL,
		0xD69744664F4578F4ULL,
		0x890281194008D634ULL,
		0xD509A609D7EF283EULL,
		0xA07EEC05801D15BFULL,
		0xC9D7458D709171A4ULL,
		0x000000000007F860ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x8BC0E48ABF11E4CAULL,
		0x1A9CA051286705B0ULL,
		0xB612C43126B8C79AULL,
		0x638ED05854D891D3ULL,
		0x752DBE3E2982687CULL,
		0xBF4EBDA83792954FULL,
		0x81DC087EECEF3BFEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3382D845E072455FULL,
		0x5C63CD0D4E502894ULL,
		0x6C48E9DB09621893ULL,
		0xC1343E31C7682C2AULL,
		0xC94AA7BA96DF1F14ULL,
		0x779DFF5FA75ED41BULL,
		0x00000040EE043F76ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0x86D65F135C92A278ULL,
		0xAE86BD293817A352ULL,
		0x438859D83FEE028EULL,
		0x3B8BD99273FD9623ULL,
		0xFA368FCC9791CD99ULL,
		0x694C3C5C2087BBB4ULL,
		0xD765B56C35242550ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35286D65F135C92ULL,
		0x028EAE86BD293817ULL,
		0x9623438859D83FEEULL,
		0xCD993B8BD99273FDULL,
		0xBBB4FA368FCC9791ULL,
		0x2550694C3C5C2087ULL,
		0x0000D765B56C3524ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x4D97ED4A8115A855ULL,
		0x0B1DB4D11742FE4AULL,
		0x4D6FEBBAA72E42C6ULL,
		0x0228935DA88CE121ULL,
		0x1B6B8250A165D338ULL,
		0x71AD45DA0787A758ULL,
		0xD37A296809394E39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B69A22E85FC949ULL,
		0xADFD7754E5C858C1ULL,
		0x45126BB5119C2429ULL,
		0x6D704A142CBA6700ULL,
		0x35A8BB40F0F4EB03ULL,
		0x6F452D012729C72EULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x714F3EC3C483C66EULL,
		0x531994A9D30969B0ULL,
		0x37ABA293A432D742ULL,
		0xDC71330A41B96485ULL,
		0x2A6835F9D479701FULL,
		0xEC57D398487A1D7AULL,
		0x158D6F4A4B47475FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D360E29E7D87890ULL,
		0x5AE84A6332953A61ULL,
		0x2C90A6F574527486ULL,
		0x2E03FB8E26614837ULL,
		0x43AF454D06BF3A8FULL,
		0xE8EBFD8AFA73090FULL,
		0x000002B1ADE94968ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x289A0A457D028536ULL,
		0x22CF3C27E8344FC9ULL,
		0x09FF5F3DAC629C73ULL,
		0x75743E39490F5E5EULL,
		0xBB9B40488EC91465ULL,
		0x21645CEED4CE3BFFULL,
		0x0D6E695576265F13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E8344FC9289A0A4ULL,
		0xDAC629C7322CF3C2ULL,
		0x9490F5E5E09FF5F3ULL,
		0x88EC9146575743E3ULL,
		0xED4CE3BFFBB9B404ULL,
		0x576265F1321645CEULL,
		0x0000000000D6E695ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xADC281792FEB91FFULL,
		0x77C8C70E832B5CAFULL,
		0x82A80824D8C85129ULL,
		0xD022D4A0423D1496ULL,
		0x0C6921B91552F45FULL,
		0x746F636C3158B32CULL,
		0xD8B65992AFDBD973ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0656B95F5B8502FULL,
		0x9B190A252EF918E1ULL,
		0x0847A292D0550104ULL,
		0x22AA5E8BFA045A94ULL,
		0x862B1665818D2437ULL,
		0x55FB7B2E6E8DEC6DULL,
		0x000000001B16CB32ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x3067989F9B90FD03ULL,
		0x6B97171FF9B6FB4CULL,
		0x57265B1809149A08ULL,
		0x029C605EE8863966ULL,
		0xB68FBE450BC6AA8BULL,
		0x67DC9B8426907350ULL,
		0x7A799E716B0C4C75ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3067989F9B90FD03ULL,
		0x6B97171FF9B6FB4CULL,
		0x57265B1809149A08ULL,
		0x029C605EE8863966ULL,
		0xB68FBE450BC6AA8BULL,
		0x67DC9B8426907350ULL,
		0x7A799E716B0C4C75ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x6D7850E72C591899ULL,
		0x2C09AEE30F30F062ULL,
		0x3858901D214B1674ULL,
		0xF2D84C0249FCDBCCULL,
		0x600F119C909D909DULL,
		0xE4856A01FACA829CULL,
		0x42D2330101655FD0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58135DC61E61E0C4ULL,
		0x70B1203A42962CE8ULL,
		0xE5B0980493F9B798ULL,
		0xC01E2339213B213BULL,
		0xC90AD403F5950538ULL,
		0x85A4660202CABFA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x90C5A4319AE8FAD1ULL,
		0xE62A383F7A54A88FULL,
		0x963BA20774C02EFBULL,
		0x6F011444D03EED04ULL,
		0x716956B11B9F8A43ULL,
		0x0352D9177D70B030ULL,
		0xA5211D1E346F6395ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5447C862D218CD74ULL,
		0x177DF3151C1FBD2AULL,
		0x76824B1DD103BA60ULL,
		0xC521B7808A22681FULL,
		0x581838B4AB588DCFULL,
		0xB1CA81A96C8BBEB8ULL,
		0x000052908E8F1A37ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x407C87A3738D74DEULL,
		0x0E05B4F6AAF9B311ULL,
		0xD6B5A1F179C9AA58ULL,
		0xF68072A04A8B1DF3ULL,
		0x751DCCCF8B3E4BD6ULL,
		0xC788F0CC801E125AULL,
		0xC3FAC3F7C245DF0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3816D3DAABE6CC45ULL,
		0x5AD687C5E726A960ULL,
		0xDA01CA812A2C77CFULL,
		0xD477333E2CF92F5BULL,
		0x1E23C33200784969ULL,
		0x0FEB0FDF09177C3FULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xB29225C48562A2D4ULL,
		0x64DBF0777A0B834FULL,
		0x52DD237DEB9809D0ULL,
		0xDD11395A3A9D082EULL,
		0x831F4E5720171A0BULL,
		0x05E2D868F1C44223ULL,
		0x8584DF6CF4DC183CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F65244B890AC545ULL,
		0xA0C9B7E0EEF41706ULL,
		0x5CA5BA46FBD73013ULL,
		0x17BA2272B4753A10ULL,
		0x47063E9CAE402E34ULL,
		0x780BC5B0D1E38884ULL,
		0x010B09BED9E9B830ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0xB536564450EA1875ULL,
		0xB80B96B3A272B1ECULL,
		0x4FA0CA37058B90F6ULL,
		0x5BECBC21D9243148ULL,
		0x9F6ED97D83F9E289ULL,
		0x947B0DAC9FD5099DULL,
		0x332E79066358AD2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A272B1ECB536564ULL,
		0x7058B90F6B80B96BULL,
		0x1D92431484FA0CA3ULL,
		0xD83F9E2895BECBC2ULL,
		0xC9FD5099D9F6ED97ULL,
		0x66358AD2C947B0DAULL,
		0x000000000332E790ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xD744EE39668365B0ULL,
		0xA8637BC6D6330E7AULL,
		0x147E892478514F35ULL,
		0x0C68A445D8FD6441ULL,
		0xCFA6610DC578C3F9ULL,
		0xA053F33199BAEB72ULL,
		0xED372EE830B5DF5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6D6330E7AD744EULL,
		0x92478514F35A8637ULL,
		0x445D8FD6441147E8ULL,
		0x10DC578C3F90C68AULL,
		0x33199BAEB72CFA66ULL,
		0xEE830B5DF5CA053FULL,
		0x00000000000ED372ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x79AE6848376A36E9ULL,
		0x55937141F5321B58ULL,
		0xF96563D288BE5317ULL,
		0x24B793A20EE60124ULL,
		0x9D65922DC1859F91ULL,
		0xF93F436720870551ULL,
		0xA10329555EC797A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B0F35CD0906ED46ULL,
		0x62EAB26E283EA643ULL,
		0x249F2CAC7A5117CAULL,
		0xF22496F27441DCC0ULL,
		0xAA33ACB245B830B3ULL,
		0xF4FF27E86CE410E0ULL,
		0x001420652AABD8F2ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x2A10A5A1EEFEC13EULL,
		0xFF55A8D17483C911ULL,
		0x2772B4A8C5C99E28ULL,
		0x65908E1304F24749ULL,
		0x0BCDAD5015E337EFULL,
		0x5908063E7B9E11FCULL,
		0xB26CD14F1CF19192ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB51A2E90792225ULL,
		0xEE569518B933C51FULL,
		0xB211C2609E48E924ULL,
		0x79B5AA02BC66FDECULL,
		0x2100C7CF73C23F81ULL,
		0x4D9A29E39E32324BULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xA2D979A557BF76FCULL,
		0x7DC6E96845B0310FULL,
		0x7B7A54B4E2851E40ULL,
		0xE1BE875AF6D8403FULL,
		0x8BA58AD35C6367B4ULL,
		0x1D9803A6E01917F9ULL,
		0x8999C420D05200E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA116C0C43E8B65E6ULL,
		0xD38A147901F71BA5ULL,
		0x6BDB6100FDEDE952ULL,
		0x4D718D9ED386FA1DULL,
		0x9B80645FE62E962BULL,
		0x83414803A076600EULL,
		0x0000000002266710ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xBE3BAEEBCDB50D6FULL,
		0x563D063FCE59B2A9ULL,
		0xB4FA9C53E51A1BBAULL,
		0x2E483261F2D40D57ULL,
		0xE39068813D8D3C34ULL,
		0x7A249B7E5D47A5CDULL,
		0xA138EC76EA1A6977ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54DF1DD775E6DA86ULL,
		0xDD2B1E831FE72CD9ULL,
		0xABDA7D4E29F28D0DULL,
		0x1A17241930F96A06ULL,
		0xE6F1C834409EC69EULL,
		0xBBBD124DBF2EA3D2ULL,
		0x00509C763B750D34ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0x839592720511E1AFULL,
		0x6FFA1A2C110A259FULL,
		0x534EA66190FEB153ULL,
		0x517C85ACD9A5D1BEULL,
		0x1050EF7BB915CC68ULL,
		0x50BA5C505DC8B342ULL,
		0xB293AD4AB07A8F21ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A259F8395927205ULL,
		0xFEB1536FFA1A2C11ULL,
		0xA5D1BE534EA66190ULL,
		0x15CC68517C85ACD9ULL,
		0xC8B3421050EF7BB9ULL,
		0x7A8F2150BA5C505DULL,
		0x000000B293AD4AB0ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x70EA2092CD2D73E9ULL,
		0x685FB60B942962F3ULL,
		0xEBC28C7A6B2B5E1BULL,
		0xF956528190A22FEBULL,
		0x7FEC02422D8D068EULL,
		0x8A3D289B35F8D056ULL,
		0x4AD42212C2585CEBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF6C172852C5E6EULL,
		0x78518F4D656BC36DULL,
		0x2ACA50321445FD7DULL,
		0xFD804845B1A0D1DFULL,
		0x47A51366BF1A0ACFULL,
		0x5A8442584B0B9D71ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xD3538003029E7EB5ULL,
		0x430F651850BC264FULL,
		0xAC163DFC1F10F03EULL,
		0x889D8FAEA6D6B252ULL,
		0x616AD7F5E115BD71ULL,
		0xC35D01CC95CFD92BULL,
		0x7EB337B6E741D013ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1327E9A9C001814FULL,
		0x781F2187B28C285EULL,
		0x5929560B1EFE0F88ULL,
		0xDEB8C44EC7D7536BULL,
		0xEC95B0B56BFAF08AULL,
		0xE809E1AE80E64AE7ULL,
		0x00003F599BDB73A0ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x083A9298EEB2C18BULL,
		0x1C8E8558DA49BE0EULL,
		0xEB73BB95175F04A9ULL,
		0x3DBBA443E60AB362ULL,
		0xF9186DAFECC22561ULL,
		0x53AF319FD30C7CDCULL,
		0x37D58D8EAAACF735ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x391D0AB1B4937C1CULL,
		0xD6E7772A2EBE0952ULL,
		0x7B774887CC1566C5ULL,
		0xF230DB5FD9844AC2ULL,
		0xA75E633FA618F9B9ULL,
		0x6FAB1B1D5559EE6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x8EA288C1327C6E56ULL,
		0x1B29139FA78BA479ULL,
		0xB346FC6A0A7B529CULL,
		0x364EF721A15C05C2ULL,
		0x58C5979204A4DE1FULL,
		0xBDB03B68640CA137ULL,
		0xCEA74196E7867757ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E2E91E63A8A230ULL,
		0x829ED4A706CA44E7ULL,
		0x68570170ACD1BF1AULL,
		0x81293787CD93BDC8ULL,
		0x1903284DD63165E4ULL,
		0xB9E19DD5EF6C0EDAULL,
		0x0000000033A9D065ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xEF453F8ED5555184ULL,
		0x994B9F47EAA0516FULL,
		0xDADF1EC2498CD541ULL,
		0x8B4ECF3CA5A1D0CEULL,
		0x53878B49CA9915B5ULL,
		0x722B041C89A7C6FFULL,
		0x7C9F5519CF7C0AC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD540A2DFDE8A7F1ULL,
		0x49319AA8332973E8ULL,
		0x94B43A19DB5BE3D8ULL,
		0x395322B6B169D9E7ULL,
		0x9134F8DFEA70F169ULL,
		0x39EF81586E456083ULL,
		0x000000000F93EAA3ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x4C2B38A5947CD77BULL,
		0xD6DBC683DAD5FC20ULL,
		0xCB9F4C2B93E0A397ULL,
		0xAA4B8943216C2955ULL,
		0x5BD00FBDB103647AULL,
		0x7B7D6859DBF3A300ULL,
		0x9899C2AFA9810653ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1026159C52CA3E6ULL,
		0x1CBEB6DE341ED6AFULL,
		0x4AAE5CFA615C9F05ULL,
		0x23D5525C4A190B61ULL,
		0x1802DE807DED881BULL,
		0x329BDBEB42CEDF9DULL,
		0x0004C4CE157D4C08ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x79F3E2E6D8E1D9F3ULL,
		0xA568FDA114150742ULL,
		0xC5C898547DF2A4E5ULL,
		0xEC5EE29A0B7285DBULL,
		0xD515F96DEC63A674ULL,
		0x5ECDD35329DDA23AULL,
		0x56BA3FD8EB893BB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42282A0E84F3E7CULL,
		0x0A8FBE549CB4AD1FULL,
		0x53416E50BB78B913ULL,
		0x2DBD8C74CE9D8BDCULL,
		0x6A653BB4475AA2BFULL,
		0xFB1D7127764BD9BAULL,
		0x00000000000AD747ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xFC50F3465F5BF6ACULL,
		0x9D71678D6F20C159ULL,
		0x811C287F4F286D89ULL,
		0x4A11B7FBC7D4F74FULL,
		0xC3F403B20B9698C3ULL,
		0x0CEA1851A97D0E8CULL,
		0xAB820D94E882499DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B79060ACFE2879AULL,
		0xFA79436C4CEB8B3CULL,
		0xDE3EA7BA7C08E143ULL,
		0x905CB4C61A508DBFULL,
		0x8D4BE874661FA01DULL,
		0xA744124CE86750C2ULL,
		0x00000000055C106CULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0xEC2F9898DF4A1A4AULL,
		0xD15F222A4E11B1ECULL,
		0x0D76615B8CB87B5DULL,
		0xC9CAEEE50BDECDD7ULL,
		0xDB32DC99B7FCC950ULL,
		0xE431101713284E5DULL,
		0xBD7C1021F85E8FD6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C7B3B0BE62637D2ULL,
		0x1ED77457C88A9384ULL,
		0xB375C35D9856E32EULL,
		0x32543272BBB942F7ULL,
		0x139776CCB7266DFFULL,
		0xA3F5B90C4405C4CAULL,
		0x00002F5F04087E17ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xE00A12BAFD869587ULL,
		0x792887DFC9D14374ULL,
		0x5561998ADBF785AEULL,
		0x20C64B1C647FF838ULL,
		0xC3FE128941A724C4ULL,
		0x2C1BF78ACBF39E50ULL,
		0xDBCCA11E7878615FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D14374E00A12BAULL,
		0xDBF785AE792887DFULL,
		0x647FF8385561998AULL,
		0x41A724C420C64B1CULL,
		0xCBF39E50C3FE1289ULL,
		0x7878615F2C1BF78AULL,
		0x00000000DBCCA11EULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x99AFC064337EA0C5ULL,
		0xC2427BC8CAD95D2EULL,
		0xB9DD2FCE51EB8BFCULL,
		0x6030DBC0D8D00988ULL,
		0x283D118FE60CCA58ULL,
		0x3EA66FC5D2A92531ULL,
		0x7ECF75B0F03C785AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE4656CAE974CD7ULL,
		0x97E728F5C5FE6121ULL,
		0x6DE06C6804C45CEEULL,
		0x88C7F306652C3018ULL,
		0x37E2E9549298941EULL,
		0xBAD8781E3C2D1F53ULL,
		0x0000000000003F67ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x81FCD9F5C3F9EC60ULL,
		0x16EF3DF348DC04E5ULL,
		0xE5353C226A05B721ULL,
		0xCED482DD969BCCACULL,
		0xE632FD6071618A3BULL,
		0xD204866794D12B38ULL,
		0x1164437081D47676ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0272C0FE6CFAE1FULL,
		0x2DB908B779EF9A46ULL,
		0xDE656729A9E11350ULL,
		0x0C51DE76A416ECB4ULL,
		0x8959C73197EB038BULL,
		0xA3B3B69024333CA6ULL,
		0x0000008B221B840EULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xD30F649B5D6A1478ULL,
		0x99A2F46D829E1CC2ULL,
		0xDB77527BE6C65D0DULL,
		0x8C1091BAC83CEA85ULL,
		0x99F32B69C56E7F78ULL,
		0x96C7E4263D3E0948ULL,
		0x0B66606632DFBED9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85A61EC936BAD428ULL,
		0x1B3345E8DB053C39ULL,
		0x0BB6EEA4F7CD8CBAULL,
		0xF1182123759079D5ULL,
		0x9133E656D38ADCFEULL,
		0xB32D8FC84C7A7C12ULL,
		0x0016CCC0CC65BF7DULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x6365B6E6563BDE6CULL,
		0xC81472C985EC043BULL,
		0x55EFD1B6C77111D0ULL,
		0x40E99939529E2E6FULL,
		0xF87B8828FC06859DULL,
		0xCFBB7C6821288342ULL,
		0xAE8F1625CE199D0BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED8D96DB9958EF7ULL,
		0x7432051CB2617B01ULL,
		0x9BD57BF46DB1DC44ULL,
		0x67503A664E54A78BULL,
		0xD0BE1EE20A3F01A1ULL,
		0x42F3EEDF1A084A20ULL,
		0x002BA3C589738667ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0xA1150AA825ACAA5EULL,
		0x32C19C7DE5408E9CULL,
		0xA72C54543F48CDF6ULL,
		0x618AB1CA74A3F945ULL,
		0x67FD553C73B6DA38ULL,
		0x5ABCAC4AB9CC690FULL,
		0x11EFA09C139E9AF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8338FBCA811D3942ULL,
		0x58A8A87E919BEC65ULL,
		0x156394E947F28B4EULL,
		0xFAAA78E76DB470C3ULL,
		0x7958957398D21ECFULL,
		0xDF4138273D35E6B5ULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0xA7BCFB5C8A1BC8CCULL,
		0x6EC8DB18C655272EULL,
		0x178C5D027B21ED07ULL,
		0x11BF8556923FDE9BULL,
		0x4BA22FAAB236AB5DULL,
		0x7AE687B5899AD002ULL,
		0xF919A51B1BFE8DEBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA7BCFB5C8A1BC8ULL,
		0x076EC8DB18C65527ULL,
		0x9B178C5D027B21EDULL,
		0x5D11BF8556923FDEULL,
		0x024BA22FAAB236ABULL,
		0xEB7AE687B5899AD0ULL,
		0x00F919A51B1BFE8DULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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