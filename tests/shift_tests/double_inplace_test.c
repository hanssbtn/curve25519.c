#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xB5D343F8A3A3E4EBULL,
		0x62AA72F9631AD176ULL,
		0x0700AD8F2E8B219DULL,
		0x23CB9318703374D8ULL,
		0x9FCE95D5B5132077ULL,
		0x979FD0E50C97A2BFULL,
		0x8AD42781243CEDE7ULL,
		0x205EF6236C6F9642ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x6BA687F14747C9D6ULL,
		0xC554E5F2C635A2EDULL,
		0x0E015B1E5D16433AULL,
		0x47972630E066E9B0ULL,
		0x3F9D2BAB6A2640EEULL,
		0x2F3FA1CA192F457FULL,
		0x15A84F024879DBCFULL,
		0x40BDEC46D8DF2C85ULL
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
		0xF06516F656DBA451ULL,
		0x5C39FCB514A3D76CULL,
		0x029CD2D776D8098FULL,
		0xAEA5E8544F2C4F77ULL,
		0x2FFB67B30FDA75EAULL,
		0xED0B4DC517BD7DF5ULL,
		0x6B65E8CC99DCE687ULL,
		0x2CD83F03344668CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0CA2DECADB748A2ULL,
		0xB873F96A2947AED9ULL,
		0x0539A5AEEDB0131EULL,
		0x5D4BD0A89E589EEEULL,
		0x5FF6CF661FB4EBD5ULL,
		0xDA169B8A2F7AFBEAULL,
		0xD6CBD19933B9CD0FULL,
		0x59B07E06688CD198ULL
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
		0xBBEA619758524F68ULL,
		0x591F18843721D13CULL,
		0xFA0623DFF49D8B4AULL,
		0xA8BDAFB74F3DEEA6ULL,
		0x39D2882C27C4AF86ULL,
		0xCAEEAB6B05A0EA66ULL,
		0x3DD5F358676A8663ULL,
		0x3F8D0167B1EBA80FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D4C32EB0A49ED0ULL,
		0xB23E31086E43A279ULL,
		0xF40C47BFE93B1694ULL,
		0x517B5F6E9E7BDD4DULL,
		0x73A510584F895F0DULL,
		0x95DD56D60B41D4CCULL,
		0x7BABE6B0CED50CC7ULL,
		0x7F1A02CF63D7501EULL
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
		0x9B48F11351872F6FULL,
		0x73B71F527F2E468AULL,
		0xA6A799287120DBEDULL,
		0x2DE2774347F9DB97ULL,
		0x133A7780AFD2F8F5ULL,
		0x94772A70C4E9D04DULL,
		0x03175AD46F9CEB2FULL,
		0x34D99318E6745781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3691E226A30E5EDEULL,
		0xE76E3EA4FE5C8D15ULL,
		0x4D4F3250E241B7DAULL,
		0x5BC4EE868FF3B72FULL,
		0x2674EF015FA5F1EAULL,
		0x28EE54E189D3A09AULL,
		0x062EB5A8DF39D65FULL,
		0x69B32631CCE8AF02ULL
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
		0xC41065A08B0E7C6FULL,
		0xEEEC8D46E1DCFFE2ULL,
		0x35A1C0E7C9613B1DULL,
		0x44EEFE18AB91084FULL,
		0x2AD361B677B50094ULL,
		0x04A4B64F699B21A6ULL,
		0xBEE0699574AEB52EULL,
		0x268885404C0A6C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8820CB41161CF8DEULL,
		0xDDD91A8DC3B9FFC5ULL,
		0x6B4381CF92C2763BULL,
		0x89DDFC315722109EULL,
		0x55A6C36CEF6A0128ULL,
		0x09496C9ED336434CULL,
		0x7DC0D32AE95D6A5CULL,
		0x4D110A809814D939ULL
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
		0x2D1B87424049D21EULL,
		0x4E578AE6A637334FULL,
		0x6A4C04265BF252A4ULL,
		0xB725C2277E3C55FDULL,
		0x6937BF8788092311ULL,
		0x7102E9DEBA90F9EBULL,
		0xF3D2B6369C16EC0CULL,
		0x18E3A8C404AFFF77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A370E848093A43CULL,
		0x9CAF15CD4C6E669EULL,
		0xD498084CB7E4A548ULL,
		0x6E4B844EFC78ABFAULL,
		0xD26F7F0F10124623ULL,
		0xE205D3BD7521F3D6ULL,
		0xE7A56C6D382DD818ULL,
		0x31C75188095FFEEFULL
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
		0x922FFC7121185F7AULL,
		0xE51654E51B9D25D9ULL,
		0x8B777E806F9F587EULL,
		0xF8888EB4AC855B96ULL,
		0x951A64FC5CD24FBDULL,
		0x4527969E3D80DA8EULL,
		0x4571D89592A79D46ULL,
		0x3F3E24777E8CDA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x245FF8E24230BEF4ULL,
		0xCA2CA9CA373A4BB3ULL,
		0x16EEFD00DF3EB0FDULL,
		0xF1111D69590AB72DULL,
		0x2A34C9F8B9A49F7BULL,
		0x8A4F2D3C7B01B51DULL,
		0x8AE3B12B254F3A8CULL,
		0x7E7C48EEFD19B492ULL
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
		0x6A88B68B5ACFD0FBULL,
		0xFADFED6771DFB06CULL,
		0xF39B1F47EB9C29D7ULL,
		0x0B4D700667930EC0ULL,
		0x0AFA0D7852E49FC2ULL,
		0x5EC61D4C2C011EDAULL,
		0x17BF071CA22BE2EAULL,
		0x1BE69AA9BEDE6838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5116D16B59FA1F6ULL,
		0xF5BFDACEE3BF60D8ULL,
		0xE7363E8FD73853AFULL,
		0x169AE00CCF261D81ULL,
		0x15F41AF0A5C93F84ULL,
		0xBD8C3A9858023DB4ULL,
		0x2F7E0E394457C5D4ULL,
		0x37CD35537DBCD070ULL
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
		0x47D3B43D75039B44ULL,
		0x610F95F146702C13ULL,
		0x28214B1AD2CC93B8ULL,
		0x33C1BC3F18C52D6EULL,
		0xE90E210B7ABB9A68ULL,
		0x7F4E0A78090BF896ULL,
		0x2E31C2156133FB87ULL,
		0x1913F8483BF44E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FA7687AEA073688ULL,
		0xC21F2BE28CE05826ULL,
		0x50429635A5992770ULL,
		0x6783787E318A5ADCULL,
		0xD21C4216F57734D0ULL,
		0xFE9C14F01217F12DULL,
		0x5C63842AC267F70EULL,
		0x3227F09077E89CEAULL
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
		0x9FF58B38836C6873ULL,
		0x29E31539352F5606ULL,
		0x5FFC6B9E80B37342ULL,
		0xA8A651E994AA576FULL,
		0x4C286B584A5C80CEULL,
		0xF78F149189B7A7ECULL,
		0x40122DF86478BF3EULL,
		0x2AE153389E934626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FEB167106D8D0E6ULL,
		0x53C62A726A5EAC0DULL,
		0xBFF8D73D0166E684ULL,
		0x514CA3D32954AEDEULL,
		0x9850D6B094B9019DULL,
		0xEF1E2923136F4FD8ULL,
		0x80245BF0C8F17E7DULL,
		0x55C2A6713D268C4CULL
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
		0x732EA661603F5B9EULL,
		0xDC04521FBD76FA46ULL,
		0xCEB87B8B2EFC7AB5ULL,
		0x60128D11C728E7B1ULL,
		0xD1C99CFE5FE5E3BEULL,
		0xBED8DEDC6E2B9478ULL,
		0x838528B7D03A04BBULL,
		0x08B016B2C76FE8F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE65D4CC2C07EB73CULL,
		0xB808A43F7AEDF48CULL,
		0x9D70F7165DF8F56BULL,
		0xC0251A238E51CF63ULL,
		0xA39339FCBFCBC77CULL,
		0x7DB1BDB8DC5728F1ULL,
		0x070A516FA0740977ULL,
		0x11602D658EDFD1E3ULL
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
		0x14D2DB4FE48CBA18ULL,
		0xDD615321D1A7B64EULL,
		0x8F2C2B934C1864A4ULL,
		0x64A283436800CD2DULL,
		0xF4BBC0DC1FBCC428ULL,
		0x66BEF05C11C62F4CULL,
		0x16743B9F334295ABULL,
		0x21FD0DABD4680A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29A5B69FC9197430ULL,
		0xBAC2A643A34F6C9CULL,
		0x1E5857269830C949ULL,
		0xC9450686D0019A5BULL,
		0xE97781B83F798850ULL,
		0xCD7DE0B8238C5E99ULL,
		0x2CE8773E66852B56ULL,
		0x43FA1B57A8D0153EULL
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
		0x3C50F2D6461357C8ULL,
		0xB4621BAF867A5DDAULL,
		0xB6345231E43E9DD6ULL,
		0x7A394C3B0468838BULL,
		0x559AF387A263AF41ULL,
		0x0782BD34DBDEF9D3ULL,
		0x6FFBC086C37AFD98ULL,
		0x3657E2CDEC11C529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A1E5AC8C26AF90ULL,
		0x68C4375F0CF4BBB4ULL,
		0x6C68A463C87D3BADULL,
		0xF472987608D10717ULL,
		0xAB35E70F44C75E82ULL,
		0x0F057A69B7BDF3A6ULL,
		0xDFF7810D86F5FB30ULL,
		0x6CAFC59BD8238A52ULL
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
		0x1F514CE8AF0D9490ULL,
		0x1AF16FAA31188B87ULL,
		0xE5AD866B925442A3ULL,
		0x512680B681E3131BULL,
		0xD7168D0F0DF7BE8AULL,
		0xA8A45BAA9A70DDBCULL,
		0xED5D239B3D01E1B4ULL,
		0x1FE1FC9E0F885824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA299D15E1B2920ULL,
		0x35E2DF546231170EULL,
		0xCB5B0CD724A88546ULL,
		0xA24D016D03C62637ULL,
		0xAE2D1A1E1BEF7D14ULL,
		0x5148B75534E1BB79ULL,
		0xDABA47367A03C369ULL,
		0x3FC3F93C1F10B049ULL
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
		0x3A8B15B77B1893F2ULL,
		0x4EFEF5DFA1384497ULL,
		0xCB35C206187A6301ULL,
		0x8700E18C154DAB36ULL,
		0x32D396583F2D9D01ULL,
		0xE4F5CC4CDD789198ULL,
		0xE5F9F2D754661E97ULL,
		0x38DC154BC51038F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75162B6EF63127E4ULL,
		0x9DFDEBBF4270892EULL,
		0x966B840C30F4C602ULL,
		0x0E01C3182A9B566DULL,
		0x65A72CB07E5B3A03ULL,
		0xC9EB9899BAF12330ULL,
		0xCBF3E5AEA8CC3D2FULL,
		0x71B82A978A2071EDULL
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
		0x14DAA6ECE2E792B7ULL,
		0x89D981493CB52DC7ULL,
		0xD3BE7E57A1A5528CULL,
		0x498E754201B91B7EULL,
		0xCC0C840D39B1945AULL,
		0x9AC09F58AFFCBCFDULL,
		0xF38EC5FF52B7EC87ULL,
		0x02E56936A598E319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29B54DD9C5CF256EULL,
		0x13B30292796A5B8EULL,
		0xA77CFCAF434AA519ULL,
		0x931CEA84037236FDULL,
		0x9819081A736328B4ULL,
		0x35813EB15FF979FBULL,
		0xE71D8BFEA56FD90FULL,
		0x05CAD26D4B31C633ULL
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
		0xEE6EBDB397877C42ULL,
		0x8E3E9AB73A976A9CULL,
		0x8468D423AA2305B6ULL,
		0x24389AAA022849DDULL,
		0x4D9E8CDAAB8FCC01ULL,
		0x1AE782DB65AC5CC5ULL,
		0xD786118F14D35C6EULL,
		0x21952530FCB9BB94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDD7B672F0EF884ULL,
		0x1C7D356E752ED539ULL,
		0x08D1A84754460B6DULL,
		0x48713554045093BBULL,
		0x9B3D19B5571F9802ULL,
		0x35CF05B6CB58B98AULL,
		0xAF0C231E29A6B8DCULL,
		0x432A4A61F9737729ULL
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
		0x13196E16A4813D8EULL,
		0x97976AD464C2E602ULL,
		0xDABE1C182F5A3EEBULL,
		0xB6075B14CDB0277BULL,
		0x9D2B5B4B5B9965D6ULL,
		0x2F2EC6B7AB3F7208ULL,
		0xB5668CA6FBF696D5ULL,
		0x344D271734216481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2632DC2D49027B1CULL,
		0x2F2ED5A8C985CC04ULL,
		0xB57C38305EB47DD7ULL,
		0x6C0EB6299B604EF7ULL,
		0x3A56B696B732CBADULL,
		0x5E5D8D6F567EE411ULL,
		0x6ACD194DF7ED2DAAULL,
		0x689A4E2E6842C903ULL
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
		0x58CC66B06DE6E80FULL,
		0x0D003F139806BD92ULL,
		0x5E67B6510EE515DAULL,
		0xE19295811C4186B2ULL,
		0xCDC60AC982C490F2ULL,
		0xB3EA806E41AC4E28ULL,
		0x715F009DBD7A1080ULL,
		0x2EFD1BEF57916D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB198CD60DBCDD01EULL,
		0x1A007E27300D7B24ULL,
		0xBCCF6CA21DCA2BB4ULL,
		0xC3252B0238830D64ULL,
		0x9B8C1593058921E5ULL,
		0x67D500DC83589C51ULL,
		0xE2BE013B7AF42101ULL,
		0x5DFA37DEAF22DA9CULL
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
		0xC27BE2561E850572ULL,
		0xCA8A5D76B9076755ULL,
		0x16BB23A9C6138A5DULL,
		0xAD046C98BF69AD80ULL,
		0xD5071AF2829DADCDULL,
		0xD5EEE7BFEEBD3E36ULL,
		0xDE6E6E016ADE1985ULL,
		0x27D04081F40BB92FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F7C4AC3D0A0AE4ULL,
		0x9514BAED720ECEABULL,
		0x2D7647538C2714BBULL,
		0x5A08D9317ED35B00ULL,
		0xAA0E35E5053B5B9BULL,
		0xABDDCF7FDD7A7C6DULL,
		0xBCDCDC02D5BC330BULL,
		0x4FA08103E817725FULL
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
		0x3BD902AA9E8BB6CCULL,
		0xC8581C95AEB4F434ULL,
		0x53DA4873E4CDCCD5ULL,
		0xB0A87B560B0A4048ULL,
		0x2F190B55E486F3D0ULL,
		0xCAB748E28D3FDE7BULL,
		0x13D0B2EE0F9B8200ULL,
		0x2B5E5501460251E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77B205553D176D98ULL,
		0x90B0392B5D69E868ULL,
		0xA7B490E7C99B99ABULL,
		0x6150F6AC16148090ULL,
		0x5E3216ABC90DE7A1ULL,
		0x956E91C51A7FBCF6ULL,
		0x27A165DC1F370401ULL,
		0x56BCAA028C04A3CEULL
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
		0x1CC0A67F18C3B778ULL,
		0xDCECC140CD41E166ULL,
		0x4E552ED563BA1E40ULL,
		0x9DB531622BE22D2CULL,
		0xF3BE1234DF188AC0ULL,
		0x2724181C4856D2B8ULL,
		0x0A275E98D74F7CA3ULL,
		0x23A6179B8B1E7BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39814CFE31876EF0ULL,
		0xB9D982819A83C2CCULL,
		0x9CAA5DAAC7743C81ULL,
		0x3B6A62C457C45A58ULL,
		0xE77C2469BE311581ULL,
		0x4E48303890ADA571ULL,
		0x144EBD31AE9EF946ULL,
		0x474C2F37163CF7FEULL
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
		0xF07FF8249639FE85ULL,
		0xFE3F5A2B333BCC14ULL,
		0xA646525D57984868ULL,
		0x532FEBDE030B675DULL,
		0x653236FFA0F596BBULL,
		0xFC13CE80417081D1ULL,
		0x2BBBE36440D5D54AULL,
		0x33A25EFBFEF7D8F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0FFF0492C73FD0AULL,
		0xFC7EB45666779829ULL,
		0x4C8CA4BAAF3090D1ULL,
		0xA65FD7BC0616CEBBULL,
		0xCA646DFF41EB2D76ULL,
		0xF8279D0082E103A2ULL,
		0x5777C6C881ABAA95ULL,
		0x6744BDF7FDEFB1ECULL
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
		0x826BF3E4BAFC30A2ULL,
		0x4C23BBE4AFC6D0A6ULL,
		0x06D4FEDDD049490BULL,
		0x97918ACE6DC380F0ULL,
		0x73007B9F81458B41ULL,
		0xB55194D849666F9AULL,
		0x4EC9DE6B7E67C389ULL,
		0x05E77AA6E877264FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04D7E7C975F86144ULL,
		0x984777C95F8DA14DULL,
		0x0DA9FDBBA0929216ULL,
		0x2F23159CDB8701E0ULL,
		0xE600F73F028B1683ULL,
		0x6AA329B092CCDF34ULL,
		0x9D93BCD6FCCF8713ULL,
		0x0BCEF54DD0EE4C9EULL
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
		0x6F6CE028D7C2F055ULL,
		0x2126502EE15DE114ULL,
		0x7154506CD42EB70DULL,
		0xCAB1AFD0FD4483AFULL,
		0x337F056C2557E990ULL,
		0xF9512875736EC6D5ULL,
		0xA132E55302730666ULL,
		0x129F31F440EB7710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDED9C051AF85E0AAULL,
		0x424CA05DC2BBC228ULL,
		0xE2A8A0D9A85D6E1AULL,
		0x95635FA1FA89075EULL,
		0x66FE0AD84AAFD321ULL,
		0xF2A250EAE6DD8DAAULL,
		0x4265CAA604E60CCDULL,
		0x253E63E881D6EE21ULL
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
		0x08E6F2B5D370454AULL,
		0x61904F0EBC717FD9ULL,
		0x70335B7BAF77E9EAULL,
		0x45FA869EF7E9DCA5ULL,
		0x2CCF6B25A62ACBAFULL,
		0x0600FA02BB8D985FULL,
		0xBAB65F7135423B27ULL,
		0x09D977CB36C94D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11CDE56BA6E08A94ULL,
		0xC3209E1D78E2FFB2ULL,
		0xE066B6F75EEFD3D4ULL,
		0x8BF50D3DEFD3B94AULL,
		0x599ED64B4C55975EULL,
		0x0C01F405771B30BEULL,
		0x756CBEE26A84764EULL,
		0x13B2EF966D929A43ULL
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
		0xD7C0AC4D0A724AEBULL,
		0x047A8B264FC6A23DULL,
		0x28A05ADA25EFAB1EULL,
		0x556694736E877715ULL,
		0xE3BEBE0CCACCF28EULL,
		0xAAC3D2ECA59506C7ULL,
		0x55F3F13ED93A99D3ULL,
		0x3392F3F3EEAD5333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF81589A14E495D6ULL,
		0x08F5164C9F8D447BULL,
		0x5140B5B44BDF563CULL,
		0xAACD28E6DD0EEE2AULL,
		0xC77D7C199599E51CULL,
		0x5587A5D94B2A0D8FULL,
		0xABE7E27DB27533A7ULL,
		0x6725E7E7DD5AA666ULL
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
		0xD95C3B30CE62F951ULL,
		0xFFF69A1F25F74545ULL,
		0x3FE77C76C4CFA192ULL,
		0x4995E4D4378A5FB7ULL,
		0xB52C959C42C8D901ULL,
		0x362F0C0E60C276A2ULL,
		0x2FFDD98AE700BD82ULL,
		0x04EBD2A83E2106DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B876619CC5F2A2ULL,
		0xFFED343E4BEE8A8BULL,
		0x7FCEF8ED899F4325ULL,
		0x932BC9A86F14BF6EULL,
		0x6A592B388591B202ULL,
		0x6C5E181CC184ED45ULL,
		0x5FFBB315CE017B04ULL,
		0x09D7A5507C420DB4ULL
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
		0xDB8A2F6588A58D04ULL,
		0xF6FBACF0A804DCB9ULL,
		0x7F03F77D6D14D7EBULL,
		0xD8F8AF3A59679A2DULL,
		0x099A901225E73D30ULL,
		0xEB63AABC50BFC465ULL,
		0xE23A9FB204F9C2D2ULL,
		0x33887ACE7C7FE15FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7145ECB114B1A08ULL,
		0xEDF759E15009B973ULL,
		0xFE07EEFADA29AFD7ULL,
		0xB1F15E74B2CF345AULL,
		0x133520244BCE7A61ULL,
		0xD6C75578A17F88CAULL,
		0xC4753F6409F385A5ULL,
		0x6710F59CF8FFC2BFULL
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
		0xE61C15EBA058D464ULL,
		0xA1708889E0F3F8DDULL,
		0xEC097EEDD8CC06D8ULL,
		0x8F0DAB86FA906748ULL,
		0x353FD94B1FF92BDAULL,
		0x8EA8E28CAADE912FULL,
		0x4CBE1220978C347BULL,
		0x2815FB179DAFF6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC382BD740B1A8C8ULL,
		0x42E11113C1E7F1BBULL,
		0xD812FDDBB1980DB1ULL,
		0x1E1B570DF520CE91ULL,
		0x6A7FB2963FF257B5ULL,
		0x1D51C51955BD225EULL,
		0x997C24412F1868F7ULL,
		0x502BF62F3B5FED5AULL
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
		0xE17862759DEDC82EULL,
		0x6FAC6BEA0030532DULL,
		0xC8CE9977AB1E02C2ULL,
		0x07BE267118CCD140ULL,
		0x4BB166811C2A0CF2ULL,
		0xBA993E59DDEC5358ULL,
		0xCA9EE1C0CE2B0BEBULL,
		0x19471EC53AFE9C16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F0C4EB3BDB905CULL,
		0xDF58D7D40060A65BULL,
		0x919D32EF563C0584ULL,
		0x0F7C4CE23199A281ULL,
		0x9762CD02385419E4ULL,
		0x75327CB3BBD8A6B0ULL,
		0x953DC3819C5617D7ULL,
		0x328E3D8A75FD382DULL
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
		0x253699B6B183A39BULL,
		0xCE783CC7672B9AA5ULL,
		0x469FBA24F12FC587ULL,
		0xF2EF5951C62A91CEULL,
		0x321FE9C6D1EA85A8ULL,
		0x2EBCA9D7E7059BEBULL,
		0xCF610F21B8745B06ULL,
		0x2FF6117B3932D904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6D336D63074736ULL,
		0x9CF0798ECE57354AULL,
		0x8D3F7449E25F8B0FULL,
		0xE5DEB2A38C55239CULL,
		0x643FD38DA3D50B51ULL,
		0x5D7953AFCE0B37D6ULL,
		0x9EC21E4370E8B60CULL,
		0x5FEC22F67265B209ULL
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
		0xD90D34D65D0C9254ULL,
		0x7BA02E04F388860AULL,
		0x6FBD32F1A363C856ULL,
		0xAAF69AAA5C1DD17AULL,
		0x6F683EB537EB4DA6ULL,
		0x4A0073E2DEC3B0ABULL,
		0xE0B1759171C99105ULL,
		0x24D1F4016788EE8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB21A69ACBA1924A8ULL,
		0xF7405C09E7110C15ULL,
		0xDF7A65E346C790ACULL,
		0x55ED3554B83BA2F4ULL,
		0xDED07D6A6FD69B4DULL,
		0x9400E7C5BD876156ULL,
		0xC162EB22E393220AULL,
		0x49A3E802CF11DD1DULL
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
		0x14642F867F40D0A3ULL,
		0xCEE5696D539637CDULL,
		0x3EE7D67D99DC41CAULL,
		0xE1D70ED0285462DEULL,
		0x102EAB98953F7DD5ULL,
		0x0A4BCD0638D8DADEULL,
		0x8DEC8C22CBF9D30BULL,
		0x01C8890A4FA6FB56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C85F0CFE81A146ULL,
		0x9DCAD2DAA72C6F9AULL,
		0x7DCFACFB33B88395ULL,
		0xC3AE1DA050A8C5BCULL,
		0x205D57312A7EFBABULL,
		0x14979A0C71B1B5BCULL,
		0x1BD9184597F3A616ULL,
		0x039112149F4DF6ADULL
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
		0x2DE1121140751B42ULL,
		0x7FB7003DBCB91D03ULL,
		0x8AC3D1E131A8563DULL,
		0x776B60804066640EULL,
		0xD51717761CAC6AD1ULL,
		0x813A810E660D23FCULL,
		0xD03536FB661EA486ULL,
		0x01FA6AD0FCF30BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC2242280EA3684ULL,
		0xFF6E007B79723A06ULL,
		0x1587A3C26350AC7AULL,
		0xEED6C10080CCC81DULL,
		0xAA2E2EEC3958D5A2ULL,
		0x0275021CCC1A47F9ULL,
		0xA06A6DF6CC3D490DULL,
		0x03F4D5A1F9E61767ULL
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
		0xEFC14FCC52D559EAULL,
		0x7849659081F7DB5FULL,
		0xF751DFA4C7F66419ULL,
		0xAC7B7271E62053C4ULL,
		0x97302C1310139008ULL,
		0x4ADD04EED6642436ULL,
		0x62F1A3C75CD4F954ULL,
		0x1262E86A7343AFE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF829F98A5AAB3D4ULL,
		0xF092CB2103EFB6BFULL,
		0xEEA3BF498FECC832ULL,
		0x58F6E4E3CC40A789ULL,
		0x2E60582620272011ULL,
		0x95BA09DDACC8486DULL,
		0xC5E3478EB9A9F2A8ULL,
		0x24C5D0D4E6875FCEULL
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
		0xAD2E7E77404C86B9ULL,
		0x0A8DE1DAD4C479BDULL,
		0x34118175467B231BULL,
		0xDD679D063A955CEEULL,
		0xD11C9D609A2C21E0ULL,
		0x925F53009D134D89ULL,
		0xFE9D69CB75B70C24ULL,
		0x1A066416447B789CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A5CFCEE80990D72ULL,
		0x151BC3B5A988F37BULL,
		0x682302EA8CF64636ULL,
		0xBACF3A0C752AB9DCULL,
		0xA2393AC1345843C1ULL,
		0x24BEA6013A269B13ULL,
		0xFD3AD396EB6E1849ULL,
		0x340CC82C88F6F139ULL
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
		0xD4076B6C1D6AAD0FULL,
		0xD3576DB8AAB67F65ULL,
		0xBB2898D992D1D36EULL,
		0xEEFF249E34EB09DBULL,
		0xCE320A25EE04F39DULL,
		0x016564CED0217B77ULL,
		0x59D4AF0278FE1B7FULL,
		0x1CF1473324D3B4F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA80ED6D83AD55A1EULL,
		0xA6AEDB71556CFECBULL,
		0x765131B325A3A6DDULL,
		0xDDFE493C69D613B7ULL,
		0x9C64144BDC09E73BULL,
		0x02CAC99DA042F6EFULL,
		0xB3A95E04F1FC36FEULL,
		0x39E28E6649A769F2ULL
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
		0x266AADEC34876D90ULL,
		0x56D10A68E19C37AAULL,
		0xB02522ED6833A26DULL,
		0xF6116DA4591CE33BULL,
		0x3DA65D2F6866B8FBULL,
		0xD1FA0EAF9950A45FULL,
		0xC70C44EDA43D12A8ULL,
		0x30903C2AEDA9BA9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD55BD8690EDB20ULL,
		0xADA214D1C3386F54ULL,
		0x604A45DAD06744DAULL,
		0xEC22DB48B239C677ULL,
		0x7B4CBA5ED0CD71F7ULL,
		0xA3F41D5F32A148BEULL,
		0x8E1889DB487A2551ULL,
		0x61207855DB53753DULL
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
		0x56E07A4A9DE7A969ULL,
		0x0AEACBF36AE7CE1FULL,
		0xC3CFE15C8B1DB5ACULL,
		0xD0281C64A4381E58ULL,
		0xB1E1AC231AA2C405ULL,
		0xCEAB4EB2B7CD0012ULL,
		0x0A9BD3BF6237E248ULL,
		0x009E58A4D52326E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC0F4953BCF52D2ULL,
		0x15D597E6D5CF9C3EULL,
		0x879FC2B9163B6B58ULL,
		0xA05038C948703CB1ULL,
		0x63C358463545880BULL,
		0x9D569D656F9A0025ULL,
		0x1537A77EC46FC491ULL,
		0x013CB149AA464DC4ULL
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
		0x6629A13B01E7FD12ULL,
		0x240A672999B09CCFULL,
		0xA97F98CD4FB2FF69ULL,
		0xD7087CE07F3D2949ULL,
		0x409011548341220DULL,
		0xD926AA0CAB1A116FULL,
		0xF39CA1A29F217D61ULL,
		0x27E33E70AF7E8EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC53427603CFFA24ULL,
		0x4814CE533361399EULL,
		0x52FF319A9F65FED2ULL,
		0xAE10F9C0FE7A5293ULL,
		0x812022A90682441BULL,
		0xB24D5419563422DEULL,
		0xE73943453E42FAC3ULL,
		0x4FC67CE15EFD1DD3ULL
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
		0x7A3AA56C9E1A487BULL,
		0x4C82EED602B9BE1BULL,
		0x314BC69E37078EC0ULL,
		0x4658EFCCE52BEF2DULL,
		0x33B6BFF6863DD065ULL,
		0xD1F3FE53FCEB242AULL,
		0xE682A848587AACD6ULL,
		0x17A5E6AA3BE4C3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4754AD93C3490F6ULL,
		0x9905DDAC05737C36ULL,
		0x62978D3C6E0F1D80ULL,
		0x8CB1DF99CA57DE5AULL,
		0x676D7FED0C7BA0CAULL,
		0xA3E7FCA7F9D64854ULL,
		0xCD055090B0F559ADULL,
		0x2F4BCD5477C98779ULL
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
		0x7D3C4AFDA4DE15ABULL,
		0xD624B036DA99B4F2ULL,
		0xF94DC0D6D351F553ULL,
		0x585DD379545B43CCULL,
		0x99762752C747B14BULL,
		0x2CB6A24993C7964AULL,
		0xEC92D9601C9F1C1BULL,
		0x11B7750363E94D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA7895FB49BC2B56ULL,
		0xAC49606DB53369E4ULL,
		0xF29B81ADA6A3EAA7ULL,
		0xB0BBA6F2A8B68799ULL,
		0x32EC4EA58E8F6296ULL,
		0x596D4493278F2C95ULL,
		0xD925B2C0393E3836ULL,
		0x236EEA06C7D29B17ULL
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
		0x83132D477E8C6E84ULL,
		0xC764ED0087C56A34ULL,
		0x6E5B42E2660047A2ULL,
		0x8C00E117517A7E93ULL,
		0x7BEFAAF794B295C2ULL,
		0x2F1552A3A836A07BULL,
		0x6634F85AA946F403ULL,
		0x32838595F851A637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06265A8EFD18DD08ULL,
		0x8EC9DA010F8AD469ULL,
		0xDCB685C4CC008F45ULL,
		0x1801C22EA2F4FD26ULL,
		0xF7DF55EF29652B85ULL,
		0x5E2AA547506D40F6ULL,
		0xCC69F0B5528DE806ULL,
		0x65070B2BF0A34C6EULL
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
		0xD4465936230F1B87ULL,
		0xC5173D75071DA0BEULL,
		0x5BE7A92850794C2FULL,
		0x75D10471D375CAABULL,
		0x007218417612C1ECULL,
		0xE38336DC2865E781ULL,
		0xF29367E0C115E480ULL,
		0x2AEC9D04BBC81FF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA88CB26C461E370EULL,
		0x8A2E7AEA0E3B417DULL,
		0xB7CF5250A0F2985FULL,
		0xEBA208E3A6EB9556ULL,
		0x00E43082EC2583D8ULL,
		0xC7066DB850CBCF02ULL,
		0xE526CFC1822BC901ULL,
		0x55D93A0977903FEBULL
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
		0x1D7549EBCE4F3009ULL,
		0xA2F042CB7D3523CCULL,
		0xFE1409719395FA39ULL,
		0x49FCC7B7D2FE9364ULL,
		0x4F3475B7556127CFULL,
		0x97EDC4572FB1F82DULL,
		0x0A946FB368B54BC8ULL,
		0x294F1E8E6B0D0203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AEA93D79C9E6012ULL,
		0x45E08596FA6A4798ULL,
		0xFC2812E3272BF473ULL,
		0x93F98F6FA5FD26C9ULL,
		0x9E68EB6EAAC24F9EULL,
		0x2FDB88AE5F63F05AULL,
		0x1528DF66D16A9791ULL,
		0x529E3D1CD61A0406ULL
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
		0xA2BCD863B2176E28ULL,
		0xC9CEF2FCBD3BD8BDULL,
		0xE4C0414ADC68EC1FULL,
		0xCDF83FC497A46C66ULL,
		0x0DFEEE26FFA4B5DDULL,
		0xC1D358514832BA25ULL,
		0x0DCA33273B53B602ULL,
		0x23F85B234D551A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4579B0C7642EDC50ULL,
		0x939DE5F97A77B17BULL,
		0xC9808295B8D1D83FULL,
		0x9BF07F892F48D8CDULL,
		0x1BFDDC4DFF496BBBULL,
		0x83A6B0A29065744AULL,
		0x1B94664E76A76C05ULL,
		0x47F0B6469AAA352EULL
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
		0xAEDB83DD9C473D41ULL,
		0x2856F62395167BC9ULL,
		0x123C12817628D31CULL,
		0x40C751262ADB4C8CULL,
		0x6B56BA74197D5776ULL,
		0x447EE8A0C20F917AULL,
		0xF502E9EC1FBFDDB9ULL,
		0x287E84254E1DD983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB707BB388E7A82ULL,
		0x50ADEC472A2CF793ULL,
		0x24782502EC51A638ULL,
		0x818EA24C55B69918ULL,
		0xD6AD74E832FAAEECULL,
		0x88FDD141841F22F4ULL,
		0xEA05D3D83F7FBB72ULL,
		0x50FD084A9C3BB307ULL
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
		0x28BA3E77421D78FCULL,
		0x39F5F515D2DE3BFCULL,
		0x1CFAE838BA82E4F0ULL,
		0xCEB21497CD466161ULL,
		0x353DFBD805160FF4ULL,
		0x4827F1AAD4F55517ULL,
		0xFB3301BB07A94027ULL,
		0x2CEF5D1989A830ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51747CEE843AF1F8ULL,
		0x73EBEA2BA5BC77F8ULL,
		0x39F5D0717505C9E0ULL,
		0x9D64292F9A8CC2C2ULL,
		0x6A7BF7B00A2C1FE9ULL,
		0x904FE355A9EAAA2EULL,
		0xF66603760F52804EULL,
		0x59DEBA3313506157ULL
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
		0x82AC1A69B6785ABDULL,
		0x1364E4CA57BEC85AULL,
		0x459868F0DD9E4E09ULL,
		0x2F6595DE526A959BULL,
		0x2AEBDB8FAF31E9B3ULL,
		0x64A3983EAAF886ADULL,
		0x92219132662A54B7ULL,
		0x3C9E4ABAD0F13798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055834D36CF0B57AULL,
		0x26C9C994AF7D90B5ULL,
		0x8B30D1E1BB3C9C12ULL,
		0x5ECB2BBCA4D52B36ULL,
		0x55D7B71F5E63D366ULL,
		0xC947307D55F10D5AULL,
		0x24432264CC54A96EULL,
		0x793C9575A1E26F31ULL
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
		0xE2F6B61098E91BF5ULL,
		0x76BF0D1DA63F1439ULL,
		0x2B7291CF9921B611ULL,
		0x66FC1B19B42EBB87ULL,
		0xB576D2812B8204E8ULL,
		0x07E4E3A632795BB1ULL,
		0xDE0C03CCC46487BFULL,
		0x12C9EC69E8F132C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5ED6C2131D237EAULL,
		0xED7E1A3B4C7E2873ULL,
		0x56E5239F32436C22ULL,
		0xCDF83633685D770EULL,
		0x6AEDA502570409D0ULL,
		0x0FC9C74C64F2B763ULL,
		0xBC18079988C90F7EULL,
		0x2593D8D3D1E26585ULL
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
		0x42D55615AD68A61EULL,
		0x3FF9E387465A581AULL,
		0x1611C00D643A15BDULL,
		0xD2FB8181EA7EC7E8ULL,
		0x7DB7351E9175F97EULL,
		0xA042D72FBCA15B63ULL,
		0xBA02B7A99579AD4BULL,
		0x0341AB5AA5E73E57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85AAAC2B5AD14C3CULL,
		0x7FF3C70E8CB4B034ULL,
		0x2C23801AC8742B7AULL,
		0xA5F70303D4FD8FD0ULL,
		0xFB6E6A3D22EBF2FDULL,
		0x4085AE5F7942B6C6ULL,
		0x74056F532AF35A97ULL,
		0x068356B54BCE7CAFULL
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
		0x865F8FFA326B5D73ULL,
		0x4A6F99F815E2F44FULL,
		0x11BDEAD34609FF3DULL,
		0xCC0F0859A0876042ULL,
		0xBD16EFA98C7C411EULL,
		0x77E17560CD331B6DULL,
		0xB3FFF2973CAC3542ULL,
		0x2102711DBB707349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CBF1FF464D6BAE6ULL,
		0x94DF33F02BC5E89FULL,
		0x237BD5A68C13FE7AULL,
		0x981E10B3410EC084ULL,
		0x7A2DDF5318F8823DULL,
		0xEFC2EAC19A6636DBULL,
		0x67FFE52E79586A84ULL,
		0x4204E23B76E0E693ULL
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
		0x839C567639DE9393ULL,
		0x3817D75A9E1059C6ULL,
		0x8EE5CC24B52AAA1DULL,
		0xF24C87541453BD7BULL,
		0x88DD7782ACAADBBAULL,
		0xEBFD495C057EAFC9ULL,
		0xA0336DB4B307010EULL,
		0x23A9C37A34EAEF12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0738ACEC73BD2726ULL,
		0x702FAEB53C20B38DULL,
		0x1DCB98496A55543AULL,
		0xE4990EA828A77AF7ULL,
		0x11BAEF055955B775ULL,
		0xD7FA92B80AFD5F93ULL,
		0x4066DB69660E021DULL,
		0x475386F469D5DE25ULL
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
		0x639677F3E522CD3CULL,
		0x6B9996F6FDE0E12AULL,
		0x00F5A65F0C58B2FBULL,
		0x2E92F2F383D2C046ULL,
		0xE734D103A3188053ULL,
		0x4D7F305EC0E588A6ULL,
		0x27B16ABA3C7FE2A8ULL,
		0x03A1DA14EE068C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC72CEFE7CA459A78ULL,
		0xD7332DEDFBC1C254ULL,
		0x01EB4CBE18B165F6ULL,
		0x5D25E5E707A5808CULL,
		0xCE69A207463100A6ULL,
		0x9AFE60BD81CB114DULL,
		0x4F62D57478FFC550ULL,
		0x0743B429DC0D18A4ULL
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
		0xD426DB2AAA9429BDULL,
		0x1D5B67FD4BAA091CULL,
		0x7AEAF16495228876ULL,
		0x1D979ADC52101CE9ULL,
		0x0D0B4B3B189C1B3CULL,
		0x648210E76A5CEB35ULL,
		0xEB741A591EBCBF03ULL,
		0x39753D489D633794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84DB6555528537AULL,
		0x3AB6CFFA97541239ULL,
		0xF5D5E2C92A4510ECULL,
		0x3B2F35B8A42039D2ULL,
		0x1A16967631383678ULL,
		0xC90421CED4B9D66AULL,
		0xD6E834B23D797E06ULL,
		0x72EA7A913AC66F29ULL
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
		0x6273E6C06E200B08ULL,
		0xCEEE78F9A5D26FA0ULL,
		0x068B797474138564ULL,
		0x428124BFC49A0A93ULL,
		0x73A822DAEA5A5A53ULL,
		0xA516F5CBCEEA1823ULL,
		0x1B7295AA1D97DE1CULL,
		0x3CC1B5A34A5ACB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E7CD80DC401610ULL,
		0x9DDCF1F34BA4DF40ULL,
		0x0D16F2E8E8270AC9ULL,
		0x8502497F89341526ULL,
		0xE75045B5D4B4B4A6ULL,
		0x4A2DEB979DD43046ULL,
		0x36E52B543B2FBC39ULL,
		0x79836B4694B59676ULL
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
		0x25B3805D271B064AULL,
		0x60A6DAFF8103CF13ULL,
		0xEBBDD97BCCB89E49ULL,
		0xF0120AC7FAB9388CULL,
		0xADE65E555991EA85ULL,
		0xD26F3B5362FD7CABULL,
		0x0B9C1C44B425F2A9ULL,
		0x1F5815286528E544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B6700BA4E360C94ULL,
		0xC14DB5FF02079E26ULL,
		0xD77BB2F799713C92ULL,
		0xE024158FF5727119ULL,
		0x5BCCBCAAB323D50BULL,
		0xA4DE76A6C5FAF957ULL,
		0x17383889684BE553ULL,
		0x3EB02A50CA51CA88ULL
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
		0x6CDAB7D61E893F11ULL,
		0x8E1F6C268AEC4486ULL,
		0x3F5AAE4B6B551178ULL,
		0x86CA32FF7DA964F6ULL,
		0xD0070CFBF7158C44ULL,
		0xCE2677B142AF51CCULL,
		0x2946D9D6E234BDD4ULL,
		0x086C5367F09920F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9B56FAC3D127E22ULL,
		0x1C3ED84D15D8890CULL,
		0x7EB55C96D6AA22F1ULL,
		0x0D9465FEFB52C9ECULL,
		0xA00E19F7EE2B1889ULL,
		0x9C4CEF62855EA399ULL,
		0x528DB3ADC4697BA9ULL,
		0x10D8A6CFE13241F2ULL
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
		0x371BC2043370C4B6ULL,
		0x8F68A33304F44843ULL,
		0xC5C7D97C652B78FEULL,
		0x93D75658C7B12D25ULL,
		0xD241F5987DF4AD00ULL,
		0x14E25B95FF6C66F4ULL,
		0x6CE62442A127C4F7ULL,
		0x1A7AC59C634F12D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E37840866E1896CULL,
		0x1ED1466609E89086ULL,
		0x8B8FB2F8CA56F1FDULL,
		0x27AEACB18F625A4BULL,
		0xA483EB30FBE95A01ULL,
		0x29C4B72BFED8CDE9ULL,
		0xD9CC4885424F89EEULL,
		0x34F58B38C69E25A6ULL
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
		0x354F2441B1856010ULL,
		0x68ACA7184B2E0640ULL,
		0xCE7FA286F3940289ULL,
		0xE41828497FDAA0F7ULL,
		0x5B89E332F66E9305ULL,
		0xBA955C29E74F68C3ULL,
		0x82B43D51D86B510BULL,
		0x200B45665872C555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9E4883630AC020ULL,
		0xD1594E30965C0C80ULL,
		0x9CFF450DE7280512ULL,
		0xC8305092FFB541EFULL,
		0xB713C665ECDD260BULL,
		0x752AB853CE9ED186ULL,
		0x05687AA3B0D6A217ULL,
		0x40168ACCB0E58AABULL
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
		0xA39B20803311F24CULL,
		0x17E850ED67C8581CULL,
		0xF96696DAF0C40DF5ULL,
		0x9696C0B93B6E6827ULL,
		0x13FD9E0AE7D4A1ABULL,
		0x5572DB0AEAD03728ULL,
		0x599434F9104930F6ULL,
		0x0BD04BA0C3F6A9ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x473641006623E498ULL,
		0x2FD0A1DACF90B039ULL,
		0xF2CD2DB5E1881BEAULL,
		0x2D2D817276DCD04FULL,
		0x27FB3C15CFA94357ULL,
		0xAAE5B615D5A06E50ULL,
		0xB32869F2209261ECULL,
		0x17A0974187ED5358ULL
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
		0x478606C7A7559C0FULL,
		0x3AA869549170F1C2ULL,
		0xBD32588E0AE21155ULL,
		0xC00E6BDBA2C09984ULL,
		0x9F071BD06CA8670AULL,
		0xFA93DA1DC0967F91ULL,
		0xF808C4816E475FAAULL,
		0x3913A181F08E55FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0C0D8F4EAB381EULL,
		0x7550D2A922E1E384ULL,
		0x7A64B11C15C422AAULL,
		0x801CD7B745813309ULL,
		0x3E0E37A0D950CE15ULL,
		0xF527B43B812CFF23ULL,
		0xF0118902DC8EBF55ULL,
		0x72274303E11CABFFULL
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
		0x2BFB511778DB0078ULL,
		0xDB860141FFED7281ULL,
		0xD0D45F36C59FD4B0ULL,
		0x24334409668CBF47ULL,
		0xAE26C60F3EC9BE3DULL,
		0x67F4647FC7DD0CA0ULL,
		0x1DCA853DCC9DE15DULL,
		0x0DFFC762A9FCB00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F6A22EF1B600F0ULL,
		0xB70C0283FFDAE502ULL,
		0xA1A8BE6D8B3FA961ULL,
		0x48668812CD197E8FULL,
		0x5C4D8C1E7D937C7AULL,
		0xCFE8C8FF8FBA1941ULL,
		0x3B950A7B993BC2BAULL,
		0x1BFF8EC553F9601CULL
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
		0xEE675456C8D3DEC8ULL,
		0x4AB7E3B93BE96BBAULL,
		0xFCA687F0D8BDB3B0ULL,
		0xAC0236427EDA3CF4ULL,
		0xCB6287438E57D844ULL,
		0xE3F6100E8EB63C4AULL,
		0x47FE3710F21F5BFCULL,
		0x2C8355A5719CDDCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCCEA8AD91A7BD90ULL,
		0x956FC77277D2D775ULL,
		0xF94D0FE1B17B6760ULL,
		0x58046C84FDB479E9ULL,
		0x96C50E871CAFB089ULL,
		0xC7EC201D1D6C7895ULL,
		0x8FFC6E21E43EB7F9ULL,
		0x5906AB4AE339BB94ULL
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
		0x2D8B2A7AD7E30029ULL,
		0xEE2E5EBD9BB4CC9EULL,
		0x39BEDCB9E27EBF8FULL,
		0x4779503319353768ULL,
		0x06CE0395BA0EB0BBULL,
		0xFFF8251A07255DD8ULL,
		0x06D1E5B3A92137D3ULL,
		0x2BB4B5A13B5FEFCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B1654F5AFC60052ULL,
		0xDC5CBD7B3769993CULL,
		0x737DB973C4FD7F1FULL,
		0x8EF2A066326A6ED0ULL,
		0x0D9C072B741D6176ULL,
		0xFFF04A340E4ABBB0ULL,
		0x0DA3CB6752426FA7ULL,
		0x57696B4276BFDF9EULL
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
		0xB28A919014683609ULL,
		0x691B5EF6D525B111ULL,
		0x2E3D339BDDC2B453ULL,
		0x9433E3AAA5B15517ULL,
		0x3197828663FB6AA0ULL,
		0xF3940C4520B1F2F4ULL,
		0xC3FA1DBFE7CD2D65ULL,
		0x15F16453E1FCC702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6515232028D06C12ULL,
		0xD236BDEDAA4B6223ULL,
		0x5C7A6737BB8568A6ULL,
		0x2867C7554B62AA2EULL,
		0x632F050CC7F6D541ULL,
		0xE728188A4163E5E8ULL,
		0x87F43B7FCF9A5ACBULL,
		0x2BE2C8A7C3F98E05ULL
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
		0xDFE9E87AD14E7271ULL,
		0x0817D036B802871AULL,
		0x6E04BEF98E157943ULL,
		0xF1491161A548FD8FULL,
		0xE4FC79F5C2858B06ULL,
		0x13D76C93E1C387CCULL,
		0x7FF35E4AD2657FB2ULL,
		0x089751F84FA3A092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD3D0F5A29CE4E2ULL,
		0x102FA06D70050E35ULL,
		0xDC097DF31C2AF286ULL,
		0xE29222C34A91FB1EULL,
		0xC9F8F3EB850B160DULL,
		0x27AED927C3870F99ULL,
		0xFFE6BC95A4CAFF64ULL,
		0x112EA3F09F474124ULL
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
		0x209CC776ACA9B4EDULL,
		0x71BB3DE6A2859680ULL,
		0xA883A18478E38A19ULL,
		0xDAA71856262C70F9ULL,
		0x47BC1DD88FD36E94ULL,
		0xE47D280F59BFC62BULL,
		0x5D6CE3EE1D2D5B8BULL,
		0x3B0C604655F4E418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41398EED595369DAULL,
		0xE3767BCD450B2D00ULL,
		0x51074308F1C71432ULL,
		0xB54E30AC4C58E1F3ULL,
		0x8F783BB11FA6DD29ULL,
		0xC8FA501EB37F8C56ULL,
		0xBAD9C7DC3A5AB717ULL,
		0x7618C08CABE9C830ULL
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
		0x64893A68AFD8983CULL,
		0x71882A381ECEA14BULL,
		0xEEA03727C2EADA3BULL,
		0x2581DDA29CE6E494ULL,
		0xB5A63FD570A4A5C8ULL,
		0x3813B76F59B61E6BULL,
		0x8F3446322D3A860DULL,
		0x200935B4B997F783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC91274D15FB13078ULL,
		0xE31054703D9D4296ULL,
		0xDD406E4F85D5B476ULL,
		0x4B03BB4539CDC929ULL,
		0x6B4C7FAAE1494B90ULL,
		0x70276EDEB36C3CD7ULL,
		0x1E688C645A750C1AULL,
		0x40126B69732FEF07ULL
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
		0xB998539423237CF1ULL,
		0x333491AB40617AEBULL,
		0x446E16ED85619F4CULL,
		0xBE3A9B87437191EBULL,
		0x3970EC7C56B33AD3ULL,
		0x1E2C3903D7FB4CDDULL,
		0xA9C33A4D5236A881ULL,
		0x2A3EC0518C233B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7330A7284646F9E2ULL,
		0x6669235680C2F5D7ULL,
		0x88DC2DDB0AC33E98ULL,
		0x7C75370E86E323D6ULL,
		0x72E1D8F8AD6675A7ULL,
		0x3C587207AFF699BAULL,
		0x5386749AA46D5102ULL,
		0x547D80A318467605ULL
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
		0xA58495B8E2D92FCAULL,
		0xEB6BE4916170062DULL,
		0x4FBFF78BC5B5BC1AULL,
		0xA447E411AC209415ULL,
		0x262CA8E4695092B7ULL,
		0xE49DABF4634A4620ULL,
		0xA6006F22471E5A3CULL,
		0x071F05A334C6389AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B092B71C5B25F94ULL,
		0xD6D7C922C2E00C5BULL,
		0x9F7FEF178B6B7835ULL,
		0x488FC8235841282AULL,
		0x4C5951C8D2A1256FULL,
		0xC93B57E8C6948C40ULL,
		0x4C00DE448E3CB479ULL,
		0x0E3E0B46698C7135ULL
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
		0x6663BC028AC12C9CULL,
		0xD2CDA7D7B8AA28F2ULL,
		0xCBB4707573B5F8A6ULL,
		0xA22CABEB8DCA2B88ULL,
		0xFEC51659F1145B98ULL,
		0x5A63DFEA0CFF47F1ULL,
		0x5634F83C9D50E90BULL,
		0x30F1A423C1D0CB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC7780515825938ULL,
		0xA59B4FAF715451E4ULL,
		0x9768E0EAE76BF14DULL,
		0x445957D71B945711ULL,
		0xFD8A2CB3E228B731ULL,
		0xB4C7BFD419FE8FE3ULL,
		0xAC69F0793AA1D216ULL,
		0x61E3484783A196E8ULL
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
		0xDF4B4E12F93BCC74ULL,
		0xB4EBFDBBE6DC87ADULL,
		0xAD0A7DF716DE479DULL,
		0x881B09CF520B7E46ULL,
		0xF1E8804CD80FB69EULL,
		0xA641A52D71E26E75ULL,
		0xF46B2AFB9DB18FD6ULL,
		0x3665773F23D77ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE969C25F27798E8ULL,
		0x69D7FB77CDB90F5BULL,
		0x5A14FBEE2DBC8F3BULL,
		0x1036139EA416FC8DULL,
		0xE3D10099B01F6D3DULL,
		0x4C834A5AE3C4DCEBULL,
		0xE8D655F73B631FADULL,
		0x6CCAEE7E47AEF599ULL
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
		0x8B469DC06A8C478FULL,
		0xAFDF3474963A218EULL,
		0x92BAC14A344C1C70ULL,
		0x3C34FA67AACD97BEULL,
		0xCA1619DA4117053AULL,
		0xA4B11D8B9B6288FBULL,
		0x241BEC4D26108860ULL,
		0x1E854690D5173BE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x168D3B80D5188F1EULL,
		0x5FBE68E92C74431DULL,
		0x25758294689838E1ULL,
		0x7869F4CF559B2F7DULL,
		0x942C33B4822E0A74ULL,
		0x49623B1736C511F7ULL,
		0x4837D89A4C2110C1ULL,
		0x3D0A8D21AA2E77CAULL
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
		0x9DA4262F64BE634DULL,
		0x2612BA478DD04E52ULL,
		0x1A5D0BD570ADEE35ULL,
		0x2F15943D943345BDULL,
		0xCFC32463799B8BB6ULL,
		0x890897B11EDBC9E8ULL,
		0xCD903FF0B6AA0569ULL,
		0x2D772B2C5386DF51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B484C5EC97CC69AULL,
		0x4C25748F1BA09CA5ULL,
		0x34BA17AAE15BDC6AULL,
		0x5E2B287B28668B7AULL,
		0x9F8648C6F337176CULL,
		0x12112F623DB793D1ULL,
		0x9B207FE16D540AD3ULL,
		0x5AEE5658A70DBEA3ULL
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
		0xC6922758AA1C9E6DULL,
		0x9F711D6B11F62193ULL,
		0x7D3A85A9EEF98618ULL,
		0xD04093BA05D25413ULL,
		0xF69756EE5816E01AULL,
		0xD5C0CEB9615E214DULL,
		0x347CCD0DBF0DE7E0ULL,
		0x3F6C31D329E3B696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D244EB154393CDAULL,
		0x3EE23AD623EC4327ULL,
		0xFA750B53DDF30C31ULL,
		0xA08127740BA4A826ULL,
		0xED2EADDCB02DC035ULL,
		0xAB819D72C2BC429BULL,
		0x68F99A1B7E1BCFC1ULL,
		0x7ED863A653C76D2CULL
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
		0x05F4EB4E034760A0ULL,
		0xCD70C962DD8EA7D2ULL,
		0xE75E53136DDAFEEDULL,
		0x767491BB349E9A97ULL,
		0x7F5CD8F6D5D666D5ULL,
		0x2C2BBBDFCB6876F7ULL,
		0xB583788437F1936DULL,
		0x34320950C7B800B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE9D69C068EC140ULL,
		0x9AE192C5BB1D4FA4ULL,
		0xCEBCA626DBB5FDDBULL,
		0xECE92376693D352FULL,
		0xFEB9B1EDABACCDAAULL,
		0x585777BF96D0EDEEULL,
		0x6B06F1086FE326DAULL,
		0x686412A18F700163ULL
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
		0x894E7BF1BD43332FULL,
		0x19B28CACA6BFF874ULL,
		0x4BB83985C3CE2B62ULL,
		0x5675F8145C773EF7ULL,
		0x4116FDB7FF2273FCULL,
		0xC748F368CF5E0150ULL,
		0xAB480129431CFCD9ULL,
		0x0A644F88E9C382C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129CF7E37A86665EULL,
		0x336519594D7FF0E9ULL,
		0x9770730B879C56C4ULL,
		0xACEBF028B8EE7DEEULL,
		0x822DFB6FFE44E7F8ULL,
		0x8E91E6D19EBC02A0ULL,
		0x569002528639F9B3ULL,
		0x14C89F11D387058BULL
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
		0xDE9976D317732662ULL,
		0x033E9755F8CA5BF3ULL,
		0xC7CCB40AB2E8F06BULL,
		0x5264D2EE8E6FFFF5ULL,
		0xCC8582D971FA9210ULL,
		0x8F3BCDABE15906D9ULL,
		0x95E8B339933B190AULL,
		0x0E832B3BE25465A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD32EDA62EE64CC4ULL,
		0x067D2EABF194B7E7ULL,
		0x8F99681565D1E0D6ULL,
		0xA4C9A5DD1CDFFFEBULL,
		0x990B05B2E3F52420ULL,
		0x1E779B57C2B20DB3ULL,
		0x2BD1667326763215ULL,
		0x1D065677C4A8CB41ULL
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
		0x1D93E12F0C16C273ULL,
		0x90CC63A96B54E49FULL,
		0x83CEA3110A33BE91ULL,
		0x820BF69D4C413C0DULL,
		0x2C4ABEE1E585E971ULL,
		0x31CBC60104BEDE17ULL,
		0x6BF7228EC1D15B2AULL,
		0x3022B2AC47E37397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B27C25E182D84E6ULL,
		0x2198C752D6A9C93EULL,
		0x079D462214677D23ULL,
		0x0417ED3A9882781BULL,
		0x58957DC3CB0BD2E3ULL,
		0x63978C02097DBC2EULL,
		0xD7EE451D83A2B654ULL,
		0x604565588FC6E72EULL
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
		0xC09D1B70E69787F4ULL,
		0x76202FE0C892B984ULL,
		0x89CB1485BF5C0E55ULL,
		0xEF6285D3F2D780F8ULL,
		0x18F8D237526ED0A4ULL,
		0x57DABB867B26EB01ULL,
		0xBC334648C20C106BULL,
		0x1B3F750342F5F686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x813A36E1CD2F0FE8ULL,
		0xEC405FC191257309ULL,
		0x1396290B7EB81CAAULL,
		0xDEC50BA7E5AF01F1ULL,
		0x31F1A46EA4DDA149ULL,
		0xAFB5770CF64DD602ULL,
		0x78668C91841820D6ULL,
		0x367EEA0685EBED0DULL
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
		0x307A4BC635075FBFULL,
		0x706471065CF12266ULL,
		0xDC8BAD25BA261062ULL,
		0xD9F416E21F41B7DAULL,
		0xC047C4917742983BULL,
		0xD78E032A4BE11C7DULL,
		0x8A7AC34253F33DE0ULL,
		0x294AEB4AD49F239CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60F4978C6A0EBF7EULL,
		0xE0C8E20CB9E244CCULL,
		0xB9175A4B744C20C4ULL,
		0xB3E82DC43E836FB5ULL,
		0x808F8922EE853077ULL,
		0xAF1C065497C238FBULL,
		0x14F58684A7E67BC1ULL,
		0x5295D695A93E4739ULL
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
		0x0AD98A6647132FEBULL,
		0x387DE8C474ABF86FULL,
		0xF5037903EDFC939DULL,
		0xDBC67F0D06E40F68ULL,
		0x8945A6794C91F38CULL,
		0x1B3F440CEA58B103ULL,
		0x3C0B7E478DE3182FULL,
		0x0BB858ED9DAA79F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15B314CC8E265FD6ULL,
		0x70FBD188E957F0DEULL,
		0xEA06F207DBF9273AULL,
		0xB78CFE1A0DC81ED1ULL,
		0x128B4CF29923E719ULL,
		0x367E8819D4B16207ULL,
		0x7816FC8F1BC6305EULL,
		0x1770B1DB3B54F3EEULL
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
		0xA3B0BA432B7E30B2ULL,
		0xA3EE86AC6E8C30C9ULL,
		0x7745A546AF38A50FULL,
		0xDD23C09EEFCABC70ULL,
		0xB2B9043977A835A1ULL,
		0x8FD8FD3B8DCD0EACULL,
		0x7E47DAD27CFA5B5CULL,
		0x22610D9EB1E766CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4761748656FC6164ULL,
		0x47DD0D58DD186193ULL,
		0xEE8B4A8D5E714A1FULL,
		0xBA47813DDF9578E0ULL,
		0x65720872EF506B43ULL,
		0x1FB1FA771B9A1D59ULL,
		0xFC8FB5A4F9F4B6B9ULL,
		0x44C21B3D63CECD94ULL
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
		0xF26A83A9020B8C90ULL,
		0x9751EB23245296A1ULL,
		0xF546936ED1BAA80AULL,
		0x00D71011F17E1D80ULL,
		0x028BC3EB9679165FULL,
		0x0FB9B7AF75B29877ULL,
		0x970D5A19365C8192ULL,
		0x356CF9EFF4F5A05DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D5075204171920ULL,
		0x2EA3D64648A52D43ULL,
		0xEA8D26DDA3755015ULL,
		0x01AE2023E2FC3B01ULL,
		0x051787D72CF22CBEULL,
		0x1F736F5EEB6530EEULL,
		0x2E1AB4326CB90324ULL,
		0x6AD9F3DFE9EB40BBULL
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
		0xFDEE04961F0878DCULL,
		0x309240C3C2A052A3ULL,
		0x908C582FEF3C94D2ULL,
		0x5D0333DFD16B6275ULL,
		0xDE49B3D40F00CC01ULL,
		0xDEA37D97F9C48C0EULL,
		0x835D5552FB5A8121ULL,
		0x0AC4131972B324E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBDC092C3E10F1B8ULL,
		0x612481878540A547ULL,
		0x2118B05FDE7929A4ULL,
		0xBA0667BFA2D6C4EBULL,
		0xBC9367A81E019802ULL,
		0xBD46FB2FF389181DULL,
		0x06BAAAA5F6B50243ULL,
		0x15882632E56649C7ULL
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
		0xEDFA6252FF62294CULL,
		0x415B460DFA063B4AULL,
		0xFD7471163ACD4170ULL,
		0xBE64B3E2C4F14BA9ULL,
		0xC8BE3537B8C1860EULL,
		0xF0EA4D0147D8832EULL,
		0x691E716AEFA665A4ULL,
		0x3B337036C03AC5FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF4C4A5FEC45298ULL,
		0x82B68C1BF40C7695ULL,
		0xFAE8E22C759A82E0ULL,
		0x7CC967C589E29753ULL,
		0x917C6A6F71830C1DULL,
		0xE1D49A028FB1065DULL,
		0xD23CE2D5DF4CCB49ULL,
		0x7666E06D80758BFCULL
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
		0xD600B16A65472351ULL,
		0xC907DF131B4BB883ULL,
		0x89B706AD02E5E6E3ULL,
		0x842E39DED0811029ULL,
		0x18581C9B236A68E4ULL,
		0x008D5E822C807B41ULL,
		0x552B53BB42CD58F8ULL,
		0x1381D750419892BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0162D4CA8E46A2ULL,
		0x920FBE2636977107ULL,
		0x136E0D5A05CBCDC7ULL,
		0x085C73BDA1022053ULL,
		0x30B0393646D4D1C9ULL,
		0x011ABD045900F682ULL,
		0xAA56A776859AB1F0ULL,
		0x2703AEA083312576ULL
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
		0xBAF7D34656EBBEE7ULL,
		0xDB8565A6EA294FDEULL,
		0xBDC9FD5B077CFC99ULL,
		0x1F71278F101D9F17ULL,
		0x2A4EA8750FFED11AULL,
		0x16F0E2BF6E8AC0B5ULL,
		0x1C4BA5FADA03DFBDULL,
		0x36CF426BF4F5F5F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75EFA68CADD77DCEULL,
		0xB70ACB4DD4529FBDULL,
		0x7B93FAB60EF9F933ULL,
		0x3EE24F1E203B3E2FULL,
		0x549D50EA1FFDA234ULL,
		0x2DE1C57EDD15816AULL,
		0x38974BF5B407BF7AULL,
		0x6D9E84D7E9EBEBE0ULL
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
		0x3C9F5418FFD2B830ULL,
		0x7578766412999A54ULL,
		0xBEB1DC70EC8A8F5AULL,
		0xF8BED0918FF9AE16ULL,
		0x365D075CC33703D3ULL,
		0x7D0ADD5E901944BAULL,
		0x79FB303ACF247C56ULL,
		0x18C5FD46D8F1B2A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x793EA831FFA57060ULL,
		0xEAF0ECC8253334A8ULL,
		0x7D63B8E1D9151EB4ULL,
		0xF17DA1231FF35C2DULL,
		0x6CBA0EB9866E07A7ULL,
		0xFA15BABD20328974ULL,
		0xF3F660759E48F8ACULL,
		0x318BFA8DB1E36542ULL
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
		0x4DFFBACA9877DD30ULL,
		0x508B5B851AE296A3ULL,
		0x17070981062D31E6ULL,
		0x60ECECE0B226CAD3ULL,
		0xDD9D1C8709C3E48BULL,
		0xC89244F0693DD36CULL,
		0x27E7265EE9110A51ULL,
		0x0EC69CBB1812196BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFF759530EFBA60ULL,
		0xA116B70A35C52D46ULL,
		0x2E0E13020C5A63CCULL,
		0xC1D9D9C1644D95A6ULL,
		0xBB3A390E1387C916ULL,
		0x912489E0D27BA6D9ULL,
		0x4FCE4CBDD22214A3ULL,
		0x1D8D3976302432D6ULL
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
		0x6175D3EAFF715530ULL,
		0xB1B4D330B12CA456ULL,
		0x02F2E1D9312BE766ULL,
		0xE588ABF240DF96D4ULL,
		0x6C88954AC07C29A7ULL,
		0x6DD5452F6264D148ULL,
		0xE20CA6598A3CD4E8ULL,
		0x39CC2CBAFE46AFC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2EBA7D5FEE2AA60ULL,
		0x6369A661625948ACULL,
		0x05E5C3B26257CECDULL,
		0xCB1157E481BF2DA8ULL,
		0xD9112A9580F8534FULL,
		0xDBAA8A5EC4C9A290ULL,
		0xC4194CB31479A9D0ULL,
		0x73985975FC8D5F87ULL
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
		0x5A4DD58F5ECB9B0BULL,
		0x4CC9E473E7E41AFFULL,
		0xE1E70161B3147348ULL,
		0x40F448AFE190A695ULL,
		0x27520C35B51DED59ULL,
		0x95121031CB4B0565ULL,
		0x639E2941E9086F91ULL,
		0x181F58155251C600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB49BAB1EBD973616ULL,
		0x9993C8E7CFC835FEULL,
		0xC3CE02C36628E690ULL,
		0x81E8915FC3214D2BULL,
		0x4EA4186B6A3BDAB2ULL,
		0x2A24206396960ACAULL,
		0xC73C5283D210DF23ULL,
		0x303EB02AA4A38C00ULL
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
		0x3E7E22D1A519E0D4ULL,
		0x10F70B1D13C6CB41ULL,
		0x0C4FC02FEAB60BC0ULL,
		0xE123EE185716058AULL,
		0x822F1FC75FC50C6FULL,
		0xF1C89934773E4BBAULL,
		0x01BE663150C99083ULL,
		0x379BA8734956AB8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFC45A34A33C1A8ULL,
		0x21EE163A278D9682ULL,
		0x189F805FD56C1780ULL,
		0xC247DC30AE2C0B14ULL,
		0x045E3F8EBF8A18DFULL,
		0xE3913268EE7C9775ULL,
		0x037CCC62A1932107ULL,
		0x6F3750E692AD571AULL
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
		0xCBA746EC1A71D4C1ULL,
		0xABA395C08D2FACFBULL,
		0x6DEF1508043FA3B3ULL,
		0xE257ED7C60AA40C4ULL,
		0xF904D380078EF145ULL,
		0xA70B7D013A22FF44ULL,
		0xE898EA78113B1135ULL,
		0x38CCBFB8053D1ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x974E8DD834E3A982ULL,
		0x57472B811A5F59F7ULL,
		0xDBDE2A10087F4767ULL,
		0xC4AFDAF8C1548188ULL,
		0xF209A7000F1DE28BULL,
		0x4E16FA027445FE89ULL,
		0xD131D4F02276226BULL,
		0x71997F700A7A3DA3ULL
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
		0x719A79340B5CC34BULL,
		0x72286107E9FC74ECULL,
		0x65EDA7B0963623D6ULL,
		0xE96B37C81A85601FULL,
		0x19B5D42498761AC5ULL,
		0x8D5A216DE5E63B4BULL,
		0x9F9983AD69743C05ULL,
		0x1ED19C87D5487AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE334F26816B98696ULL,
		0xE450C20FD3F8E9D8ULL,
		0xCBDB4F612C6C47ACULL,
		0xD2D66F90350AC03EULL,
		0x336BA84930EC358BULL,
		0x1AB442DBCBCC7696ULL,
		0x3F33075AD2E8780BULL,
		0x3DA3390FAA90F54DULL
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
		0x1FE40F1C071A5B23ULL,
		0x159AF7DFFC0981B9ULL,
		0xE458049D4666598EULL,
		0x29763A3F8289BE9FULL,
		0x64E51BD24AFEF601ULL,
		0xAD2028452C496CF2ULL,
		0x72ECD9C814A87C48ULL,
		0x0788501A5D1C5EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC81E380E34B646ULL,
		0x2B35EFBFF8130372ULL,
		0xC8B0093A8CCCB31CULL,
		0x52EC747F05137D3FULL,
		0xC9CA37A495FDEC02ULL,
		0x5A40508A5892D9E4ULL,
		0xE5D9B3902950F891ULL,
		0x0F10A034BA38BD68ULL
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
		0x368F2A01884CC437ULL,
		0x89D1108A1ECAE2C1ULL,
		0xA9E14A7F32679E39ULL,
		0x03F7EA42CC23F800ULL,
		0x0DA014F405CACC28ULL,
		0xEAF4C92903E1D138ULL,
		0xEEE89365098B9CC1ULL,
		0x3E0FB805EDA763A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D1E54031099886EULL,
		0x13A221143D95C582ULL,
		0x53C294FE64CF3C73ULL,
		0x07EFD4859847F001ULL,
		0x1B4029E80B959850ULL,
		0xD5E9925207C3A270ULL,
		0xDDD126CA13173983ULL,
		0x7C1F700BDB4EC741ULL
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
		0x40985010DC2E2241ULL,
		0x405D4F7A11AC2228ULL,
		0x1C927218A3E93B05ULL,
		0x1DC53C93B6934F7DULL,
		0x5FDA0FE84419E498ULL,
		0xD2C0D0B9A9237763ULL,
		0xF22BA075BCE69F8EULL,
		0x187592CDF4C35778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8130A021B85C4482ULL,
		0x80BA9EF423584450ULL,
		0x3924E43147D2760AULL,
		0x3B8A79276D269EFAULL,
		0xBFB41FD08833C930ULL,
		0xA581A1735246EEC6ULL,
		0xE45740EB79CD3F1DULL,
		0x30EB259BE986AEF1ULL
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
		0xBE78EB89F5940A45ULL,
		0x845337E87C028298ULL,
		0x8DB24F194D9F7C0BULL,
		0x85B1D7DE056C7A32ULL,
		0xB8A3CE80917D8869ULL,
		0x411D7CF4FC4D6927ULL,
		0x5E1E4859922141C9ULL,
		0x23290CACFF179312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF1D713EB28148AULL,
		0x08A66FD0F8050531ULL,
		0x1B649E329B3EF817ULL,
		0x0B63AFBC0AD8F465ULL,
		0x71479D0122FB10D3ULL,
		0x823AF9E9F89AD24FULL,
		0xBC3C90B324428392ULL,
		0x46521959FE2F2624ULL
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
		0x4F4624D1C15707C3ULL,
		0xAD2DB8202BB6D779ULL,
		0x2BDCCFEF6B14DDC1ULL,
		0x291CA6DDCEF23C0BULL,
		0x401D20483A69FA99ULL,
		0x0F2E25284AB970C9ULL,
		0x5A38C5B80377AF0DULL,
		0x02C2308A3C2A643AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E8C49A382AE0F86ULL,
		0x5A5B7040576DAEF2ULL,
		0x57B99FDED629BB83ULL,
		0x52394DBB9DE47816ULL,
		0x803A409074D3F532ULL,
		0x1E5C4A509572E192ULL,
		0xB4718B7006EF5E1AULL,
		0x058461147854C874ULL
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
		0x94922AE902519E0DULL,
		0xA25DB5BCC6296CF8ULL,
		0x4383118A6CBF1FCDULL,
		0xCE5799812E952135ULL,
		0xBBAF34C0B2671F1AULL,
		0x195093D777218E15ULL,
		0xDED7E3E54944783BULL,
		0x132F11547C280159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x292455D204A33C1AULL,
		0x44BB6B798C52D9F1ULL,
		0x87062314D97E3F9BULL,
		0x9CAF33025D2A426AULL,
		0x775E698164CE3E35ULL,
		0x32A127AEEE431C2BULL,
		0xBDAFC7CA9288F076ULL,
		0x265E22A8F85002B3ULL
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
		0x84EB940E17EBA52CULL,
		0x4AF03EEE96E9D6F3ULL,
		0x191BE77AAFB54B73ULL,
		0x70C948DC18D1DE1BULL,
		0x913A3C24CB2B2BA7ULL,
		0x7AA2D6792E6C2371ULL,
		0xF255CE14F3CF41EBULL,
		0x3BF2724BAB7EA09FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D7281C2FD74A58ULL,
		0x95E07DDD2DD3ADE7ULL,
		0x3237CEF55F6A96E6ULL,
		0xE19291B831A3BC36ULL,
		0x227478499656574EULL,
		0xF545ACF25CD846E3ULL,
		0xE4AB9C29E79E83D6ULL,
		0x77E4E49756FD413FULL
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
		0x2D418A64E70A4FA6ULL,
		0xC1DE657293F76487ULL,
		0x0985B808911AF6DBULL,
		0xCABC10829562629DULL,
		0x986521B996800BA6ULL,
		0xDD5E1B0D36E6023CULL,
		0x1F95069CB954F75DULL,
		0x3ED103017F521A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8314C9CE149F4CULL,
		0x83BCCAE527EEC90EULL,
		0x130B70112235EDB7ULL,
		0x957821052AC4C53AULL,
		0x30CA43732D00174DULL,
		0xBABC361A6DCC0479ULL,
		0x3F2A0D3972A9EEBBULL,
		0x7DA20602FEA434B2ULL
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
		0x3C4F5DA277CFF4E7ULL,
		0x446EC367AFA99D25ULL,
		0xDA7C2479EE79DE68ULL,
		0x4A9A5B2D22C4588CULL,
		0xE27017AAEB913C5CULL,
		0xF95077643A891F60ULL,
		0xC6732F08B565B510ULL,
		0x1FBE745CDDAA5B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x789EBB44EF9FE9CEULL,
		0x88DD86CF5F533A4AULL,
		0xB4F848F3DCF3BCD0ULL,
		0x9534B65A4588B119ULL,
		0xC4E02F55D72278B8ULL,
		0xF2A0EEC875123EC1ULL,
		0x8CE65E116ACB6A21ULL,
		0x3F7CE8B9BB54B6D1ULL
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
		0x506ACE31878654CFULL,
		0xF610CB8B126A6820ULL,
		0x420232FA725BD99DULL,
		0xD6BD9FD9C8D9E27BULL,
		0x243EE87B2EE4FA39ULL,
		0xF4933C802AB8358DULL,
		0x2259447AE39C7BD4ULL,
		0x17ED2AB896A481C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0D59C630F0CA99EULL,
		0xEC21971624D4D040ULL,
		0x840465F4E4B7B33BULL,
		0xAD7B3FB391B3C4F6ULL,
		0x487DD0F65DC9F473ULL,
		0xE926790055706B1AULL,
		0x44B288F5C738F7A9ULL,
		0x2FDA55712D490390ULL
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
		0xE33E5FCD4E6C9EA9ULL,
		0x720272699AC28819ULL,
		0xFA33A8FA3D9760ABULL,
		0x1F67A6E4CEEA9B0DULL,
		0x94FE42EC446E03D8ULL,
		0x73A94294FF597E85ULL,
		0x44982763EA6E9D29ULL,
		0x16ED1A9694B21D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC67CBF9A9CD93D52ULL,
		0xE404E4D335851033ULL,
		0xF46751F47B2EC156ULL,
		0x3ECF4DC99DD5361BULL,
		0x29FC85D888DC07B0ULL,
		0xE7528529FEB2FD0BULL,
		0x89304EC7D4DD3A52ULL,
		0x2DDA352D29643A34ULL
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
		0xDBAA8B02769AED25ULL,
		0x9BFE9A6DDBF54118ULL,
		0xD5B3070323D2F774ULL,
		0x1879E68A36E00D30ULL,
		0xC599F1E3FAB60C86ULL,
		0x62AA35555DD86553ULL,
		0x4736D2CB25C05903ULL,
		0x1912F7ADCB490DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7551604ED35DA4AULL,
		0x37FD34DBB7EA8231ULL,
		0xAB660E0647A5EEE9ULL,
		0x30F3CD146DC01A61ULL,
		0x8B33E3C7F56C190CULL,
		0xC5546AAABBB0CAA7ULL,
		0x8E6DA5964B80B206ULL,
		0x3225EF5B96921B62ULL
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
		0x3C181F67FC141B22ULL,
		0x45E6192E9500716DULL,
		0x98E204D306650BE7ULL,
		0x4BB95A2D879931C3ULL,
		0xDA0A6F7481F88254ULL,
		0x9FA15D01F073D6B1ULL,
		0x4066B819BE786701ULL,
		0x08F1479FFF37573AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78303ECFF8283644ULL,
		0x8BCC325D2A00E2DAULL,
		0x31C409A60CCA17CEULL,
		0x9772B45B0F326387ULL,
		0xB414DEE903F104A8ULL,
		0x3F42BA03E0E7AD63ULL,
		0x80CD70337CF0CE03ULL,
		0x11E28F3FFE6EAE74ULL
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
		0x5404ECAE95C36A4BULL,
		0x01F97A99E4FAF5BCULL,
		0xD3DB40AB03FC8E9FULL,
		0xEDDC619D40B9CB23ULL,
		0x0851A21AEC1579F0ULL,
		0x2A989A0AC061E023ULL,
		0x29F28F12B64A2143ULL,
		0x2E85E1B2E45857E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA809D95D2B86D496ULL,
		0x03F2F533C9F5EB78ULL,
		0xA7B6815607F91D3EULL,
		0xDBB8C33A81739647ULL,
		0x10A34435D82AF3E1ULL,
		0x5531341580C3C046ULL,
		0x53E51E256C944286ULL,
		0x5D0BC365C8B0AFCAULL
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
		0x2A36A75C477403DBULL,
		0x903F6946979E0CD0ULL,
		0xCA8D61AC4285C841ULL,
		0x5CD1398DEDA4D060ULL,
		0x5A1F1B5DC2973493ULL,
		0xB0A64F312DB98335ULL,
		0x239352849D76CA67ULL,
		0x3C706C235C3679FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x546D4EB88EE807B6ULL,
		0x207ED28D2F3C19A0ULL,
		0x951AC358850B9083ULL,
		0xB9A2731BDB49A0C1ULL,
		0xB43E36BB852E6926ULL,
		0x614C9E625B73066AULL,
		0x4726A5093AED94CFULL,
		0x78E0D846B86CF3FEULL
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
		0x751C0F39967CF945ULL,
		0x3D6C15A32E5B713DULL,
		0xB06C4D0AA0B72995ULL,
		0x4EE5441781E1026BULL,
		0xBB53FD9A88721180ULL,
		0x174C3054D0D81597ULL,
		0x5C8653BDE3AA298FULL,
		0x1C504C0B8D300194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA381E732CF9F28AULL,
		0x7AD82B465CB6E27AULL,
		0x60D89A15416E532AULL,
		0x9DCA882F03C204D7ULL,
		0x76A7FB3510E42300ULL,
		0x2E9860A9A1B02B2FULL,
		0xB90CA77BC754531EULL,
		0x38A098171A600328ULL
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
		0x643A43C7E96A7C04ULL,
		0xBD504A6F0B3B13D5ULL,
		0x43665C1597D3BB79ULL,
		0x93201501AE3756D5ULL,
		0xDA4FFED29A4633C2ULL,
		0xD7972CC057FCBD8EULL,
		0xD112C63F84A06E1AULL,
		0x39BD1E7C8C64A13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC874878FD2D4F808ULL,
		0x7AA094DE167627AAULL,
		0x86CCB82B2FA776F3ULL,
		0x26402A035C6EADAAULL,
		0xB49FFDA5348C6785ULL,
		0xAF2E5980AFF97B1DULL,
		0xA2258C7F0940DC35ULL,
		0x737A3CF918C94277ULL
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
		0x9D70320751B0D9B0ULL,
		0x13B7CF42041F5B67ULL,
		0xFAA71F2989143073ULL,
		0xB5512999ACCF8E33ULL,
		0x06FE8879F4204B3DULL,
		0x6755640B3579FDD5ULL,
		0xB10873AE8954E1B7ULL,
		0x0BF836414E25BB50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE0640EA361B360ULL,
		0x276F9E84083EB6CFULL,
		0xF54E3E53122860E6ULL,
		0x6AA25333599F1C67ULL,
		0x0DFD10F3E840967BULL,
		0xCEAAC8166AF3FBAAULL,
		0x6210E75D12A9C36EULL,
		0x17F06C829C4B76A1ULL
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
		0x551DD2E7D87D8AF6ULL,
		0xA7E77C758C73A21DULL,
		0x8196AE82D48783DBULL,
		0x256D45D96E5DB3A9ULL,
		0x459346DE25550928ULL,
		0xB18D14B135EE8C45ULL,
		0x640449D8E1C8B9FDULL,
		0x10D40CDF2C9C7915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3BA5CFB0FB15ECULL,
		0x4FCEF8EB18E7443AULL,
		0x032D5D05A90F07B7ULL,
		0x4ADA8BB2DCBB6753ULL,
		0x8B268DBC4AAA1250ULL,
		0x631A29626BDD188AULL,
		0xC80893B1C39173FBULL,
		0x21A819BE5938F22AULL
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
		0x83610FF0EE33642AULL,
		0xF3F74120E7C78984ULL,
		0x536DBB38CF09ED24ULL,
		0xB7FC68CD0B0CD07BULL,
		0x8A28034C590D1CF9ULL,
		0xA899D2ADCACF558DULL,
		0xC93719B6F3582046ULL,
		0x0DE9404DB3E7380AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C21FE1DC66C854ULL,
		0xE7EE8241CF8F1309ULL,
		0xA6DB76719E13DA49ULL,
		0x6FF8D19A1619A0F6ULL,
		0x14500698B21A39F3ULL,
		0x5133A55B959EAB1BULL,
		0x926E336DE6B0408DULL,
		0x1BD2809B67CE7015ULL
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
		0x45A3B316D20571C9ULL,
		0x50A2FD7699F70561ULL,
		0xA1BFE21A056DD91AULL,
		0x3F2C91061CD89DE0ULL,
		0x4C0806E71D5EEC12ULL,
		0xC9458DFA84293839ULL,
		0x1502FCB026F858E9ULL,
		0x1562E50992A492D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B47662DA40AE392ULL,
		0xA145FAED33EE0AC2ULL,
		0x437FC4340ADBB234ULL,
		0x7E59220C39B13BC1ULL,
		0x98100DCE3ABDD824ULL,
		0x928B1BF508527072ULL,
		0x2A05F9604DF0B1D3ULL,
		0x2AC5CA13254925A4ULL
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
		0x1F3C3A661D8BFD50ULL,
		0xA5682516A61D215FULL,
		0xDB3381019A3C6C4EULL,
		0x3504816B6589129CULL,
		0xE9ADE329A74CE20FULL,
		0xEAAEFB4FDC82DB7FULL,
		0x1B549FC34AE16EF9ULL,
		0x20AAB126C4715570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E7874CC3B17FAA0ULL,
		0x4AD04A2D4C3A42BEULL,
		0xB66702033478D89DULL,
		0x6A0902D6CB122539ULL,
		0xD35BC6534E99C41EULL,
		0xD55DF69FB905B6FFULL,
		0x36A93F8695C2DDF3ULL,
		0x4155624D88E2AAE0ULL
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
		0x49827848BE23385DULL,
		0x3E611DC24346654AULL,
		0x0909930A54707EDCULL,
		0xCD8F3A9DA819E3FCULL,
		0xAFB28D045602D416ULL,
		0x2D2EEDDC630E5DF8ULL,
		0x9EB1BE993FC25576ULL,
		0x00A61CE1EC1CDE76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9304F0917C4670BAULL,
		0x7CC23B84868CCA94ULL,
		0x12132614A8E0FDB8ULL,
		0x9B1E753B5033C7F8ULL,
		0x5F651A08AC05A82DULL,
		0x5A5DDBB8C61CBBF1ULL,
		0x3D637D327F84AAECULL,
		0x014C39C3D839BCEDULL
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
		0x4A79534C0662FF67ULL,
		0x775818B980E1EFC1ULL,
		0x862D771E6EF59264ULL,
		0x5D899DB6A5CC75F0ULL,
		0xA95525B5CF5E5BE9ULL,
		0x254D05EE6EF6FAF3ULL,
		0x47AEF115F123EDD7ULL,
		0x13594477DA5C69A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F2A6980CC5FECEULL,
		0xEEB0317301C3DF82ULL,
		0x0C5AEE3CDDEB24C8ULL,
		0xBB133B6D4B98EBE1ULL,
		0x52AA4B6B9EBCB7D2ULL,
		0x4A9A0BDCDDEDF5E7ULL,
		0x8F5DE22BE247DBAEULL,
		0x26B288EFB4B8D344ULL
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
		0xB30F93C647C80AF2ULL,
		0x780241CEF25E079CULL,
		0xF4959E40CC88B8E3ULL,
		0x1369A4682E0AA5ADULL,
		0x6E31353985906D52ULL,
		0x9718E68BA408831BULL,
		0xC5FAF7B024466B2CULL,
		0x204D0C4A2DDC8FB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661F278C8F9015E4ULL,
		0xF004839DE4BC0F39ULL,
		0xE92B3C81991171C6ULL,
		0x26D348D05C154B5BULL,
		0xDC626A730B20DAA4ULL,
		0x2E31CD1748110636ULL,
		0x8BF5EF60488CD659ULL,
		0x409A18945BB91F71ULL
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
		0xE2D9562B36751EF9ULL,
		0xBAA967912D494500ULL,
		0xD6A95167477CEB9FULL,
		0xB00DDE9EB1251C6CULL,
		0x62CB18B0B9A6035BULL,
		0x730F13CA1A1E57B2ULL,
		0x6F2D96A9518AC84CULL,
		0x165CEDC47989861AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B2AC566CEA3DF2ULL,
		0x7552CF225A928A01ULL,
		0xAD52A2CE8EF9D73FULL,
		0x601BBD3D624A38D9ULL,
		0xC5963161734C06B7ULL,
		0xE61E2794343CAF64ULL,
		0xDE5B2D52A3159098ULL,
		0x2CB9DB88F3130C34ULL
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
		0xA3DA8FE943AF937AULL,
		0x4E1DB5C9DBD446F3ULL,
		0x443D66630FF5CA17ULL,
		0xBBE30063752D4E3EULL,
		0xA418FA0C66467FB8ULL,
		0x49CA5FA0D44603F4ULL,
		0x387E4D2B48C1D9A7ULL,
		0x20031FD75F2F63AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B51FD2875F26F4ULL,
		0x9C3B6B93B7A88DE7ULL,
		0x887ACCC61FEB942EULL,
		0x77C600C6EA5A9C7CULL,
		0x4831F418CC8CFF71ULL,
		0x9394BF41A88C07E9ULL,
		0x70FC9A569183B34EULL,
		0x40063FAEBE5EC75EULL
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
		0x0A9968CB3E32419CULL,
		0x8822EF48B53AC179ULL,
		0x46374D6909C75448ULL,
		0x567F8716AE8C051FULL,
		0xE30B10CB17A9351AULL,
		0x9F97D71B54AF70E8ULL,
		0x0639470524B1624FULL,
		0x2F41A335CC9D5E22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1532D1967C648338ULL,
		0x1045DE916A7582F2ULL,
		0x8C6E9AD2138EA891ULL,
		0xACFF0E2D5D180A3EULL,
		0xC61621962F526A34ULL,
		0x3F2FAE36A95EE1D1ULL,
		0x0C728E0A4962C49FULL,
		0x5E83466B993ABC44ULL
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
		0xE6DF93C870AEDDF3ULL,
		0xD9D516BDD33A767AULL,
		0x78EAB5DAC5FC76E1ULL,
		0x92801EA96553C392ULL,
		0x03338F3AC55764B0ULL,
		0x9AF520B0A34F8EB5ULL,
		0xD233113018172514ULL,
		0x299EBABB19D1BBF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDBF2790E15DBBE6ULL,
		0xB3AA2D7BA674ECF5ULL,
		0xF1D56BB58BF8EDC3ULL,
		0x25003D52CAA78724ULL,
		0x06671E758AAEC961ULL,
		0x35EA4161469F1D6AULL,
		0xA4662260302E4A29ULL,
		0x533D757633A377E9ULL
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
		0xD9D50AA277F5220BULL,
		0xF16817A19AA835B8ULL,
		0x9114E6E4387BDECCULL,
		0x20B8D009C7B78CA1ULL,
		0x6D11443BF4B71BB0ULL,
		0xA02A05F0DB5C3524ULL,
		0x2ADEF8A7F65FB20FULL,
		0x13E2E7E15278842CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3AA1544EFEA4416ULL,
		0xE2D02F4335506B71ULL,
		0x2229CDC870F7BD99ULL,
		0x4171A0138F6F1943ULL,
		0xDA228877E96E3760ULL,
		0x40540BE1B6B86A48ULL,
		0x55BDF14FECBF641FULL,
		0x27C5CFC2A4F10858ULL
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
		0xE9B426949249CFB2ULL,
		0x54F36186D9AB6D76ULL,
		0x14F4732BCFCE1E13ULL,
		0xB72C5B905F7FBE87ULL,
		0x52E8BCDB8B616212ULL,
		0x8AFD7640ABC36960ULL,
		0xEA3DC6D0FA6649E0ULL,
		0x397D40FA86F15A71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3684D2924939F64ULL,
		0xA9E6C30DB356DAEDULL,
		0x29E8E6579F9C3C26ULL,
		0x6E58B720BEFF7D0EULL,
		0xA5D179B716C2C425ULL,
		0x15FAEC815786D2C0ULL,
		0xD47B8DA1F4CC93C1ULL,
		0x72FA81F50DE2B4E3ULL
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
		0x0B6D6F533FBF5FA9ULL,
		0xB67DCF600EE04EDDULL,
		0x90A02289C4B4E522ULL,
		0xEFED8CB6CE535CD2ULL,
		0x686DB7506E5152E7ULL,
		0x6186F78AD641221CULL,
		0x96102029C94B52E0ULL,
		0x268935E268D98018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DADEA67F7EBF52ULL,
		0x6CFB9EC01DC09DBAULL,
		0x214045138969CA45ULL,
		0xDFDB196D9CA6B9A5ULL,
		0xD0DB6EA0DCA2A5CFULL,
		0xC30DEF15AC824438ULL,
		0x2C2040539296A5C0ULL,
		0x4D126BC4D1B30031ULL
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
		0x1A3F5DAF9E88B811ULL,
		0xEB94C0303B02A520ULL,
		0x1D02EDFCD5DFAB70ULL,
		0x1DD16D81507F1B4CULL,
		0x53E3F4D151DA0F34ULL,
		0x5F27A0F24E553B19ULL,
		0xE404AA78AEEDFA23ULL,
		0x1EB1F7A8A7C1924DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x347EBB5F3D117022ULL,
		0xD729806076054A40ULL,
		0x3A05DBF9ABBF56E1ULL,
		0x3BA2DB02A0FE3698ULL,
		0xA7C7E9A2A3B41E68ULL,
		0xBE4F41E49CAA7632ULL,
		0xC80954F15DDBF446ULL,
		0x3D63EF514F83249BULL
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
		0x341113FB687CD35CULL,
		0x55AB3EF3347915ECULL,
		0x2C28DCD2BAFF42FEULL,
		0x60A3FC3AEB42FCE9ULL,
		0x4BF04C1509994075ULL,
		0x5B0F747AED8FA572ULL,
		0x2A151BCCF338C31BULL,
		0x1815176E91513F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682227F6D0F9A6B8ULL,
		0xAB567DE668F22BD8ULL,
		0x5851B9A575FE85FCULL,
		0xC147F875D685F9D2ULL,
		0x97E0982A133280EAULL,
		0xB61EE8F5DB1F4AE4ULL,
		0x542A3799E6718636ULL,
		0x302A2EDD22A27E06ULL
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
		0x2E4E7E2E49D29194ULL,
		0x4CB43FBA5A5810A4ULL,
		0x0EC72E55A67B8212ULL,
		0xBEF24268CEE562E6ULL,
		0xD3F49E83A54E695BULL,
		0x31BE7090C4981446ULL,
		0x5C7987CD2250669CULL,
		0x33C6EA2323696EAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C9CFC5C93A52328ULL,
		0x99687F74B4B02148ULL,
		0x1D8E5CAB4CF70424ULL,
		0x7DE484D19DCAC5CCULL,
		0xA7E93D074A9CD2B7ULL,
		0x637CE1218930288DULL,
		0xB8F30F9A44A0CD38ULL,
		0x678DD44646D2DD54ULL
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
		0x22803B91A28EA094ULL,
		0x59A5579493C72E56ULL,
		0xF34CB27AD641D0B5ULL,
		0x50C7BB7F2FEBDA36ULL,
		0xD2563C3998AD1E1FULL,
		0x39BCBB9A67872778ULL,
		0xE5AF197E9D045A19ULL,
		0x1E4AF890DB8A5B22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45007723451D4128ULL,
		0xB34AAF29278E5CACULL,
		0xE69964F5AC83A16AULL,
		0xA18F76FE5FD7B46DULL,
		0xA4AC7873315A3C3EULL,
		0x73797734CF0E4EF1ULL,
		0xCB5E32FD3A08B432ULL,
		0x3C95F121B714B645ULL
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
		0x838B9A1F73A8C2DBULL,
		0x91768737BC5304B7ULL,
		0x18839F15938F371CULL,
		0xA07A7ED81644E8E3ULL,
		0x349C07EE930AAE65ULL,
		0x06F5DB7A3D9DD0F3ULL,
		0x18ACBEB57BB89EA9ULL,
		0x1FF5E64719EC9E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0717343EE75185B6ULL,
		0x22ED0E6F78A6096FULL,
		0x31073E2B271E6E39ULL,
		0x40F4FDB02C89D1C6ULL,
		0x69380FDD26155CCBULL,
		0x0DEBB6F47B3BA1E6ULL,
		0x31597D6AF7713D52ULL,
		0x3FEBCC8E33D93C0EULL
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
		0xDC1D79AE5E7CC0A1ULL,
		0xE07FEFF7457420A1ULL,
		0xBE57F59BDCCF1851ULL,
		0x5C6C1A58407C728DULL,
		0xE5C3B95CA02A8D76ULL,
		0x50885F2886FC11CAULL,
		0x1F1F0CC6426462D6ULL,
		0x20203D1C072D67E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB83AF35CBCF98142ULL,
		0xC0FFDFEE8AE84143ULL,
		0x7CAFEB37B99E30A3ULL,
		0xB8D834B080F8E51BULL,
		0xCB8772B940551AECULL,
		0xA110BE510DF82395ULL,
		0x3E3E198C84C8C5ACULL,
		0x40407A380E5ACFC2ULL
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
		0x7ADC620B4FBF9538ULL,
		0x7890E78062DDB0FDULL,
		0x8DE653E400B3708CULL,
		0x3F9A7B0297DE4D39ULL,
		0x33A27A1758F0B974ULL,
		0xDDB1A93F8210ADEBULL,
		0x0B14276FD81A2F1FULL,
		0x04B9E1FF418F0101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B8C4169F7F2A70ULL,
		0xF121CF00C5BB61FAULL,
		0x1BCCA7C80166E118ULL,
		0x7F34F6052FBC9A73ULL,
		0x6744F42EB1E172E8ULL,
		0xBB63527F04215BD6ULL,
		0x16284EDFB0345E3FULL,
		0x0973C3FE831E0202ULL
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
		0x35098F59C42BEAF6ULL,
		0x2D1ECCA1466575E0ULL,
		0xAC3287007C972FBDULL,
		0x7CCEBAACC54DAD90ULL,
		0x5329EF1F542C3D3AULL,
		0x7A3F82C5F91B7954ULL,
		0xE079C45B74D9034DULL,
		0x288296FDA8E02B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A131EB38857D5ECULL,
		0x5A3D99428CCAEBC0ULL,
		0x58650E00F92E5F7AULL,
		0xF99D75598A9B5B21ULL,
		0xA653DE3EA8587A74ULL,
		0xF47F058BF236F2A8ULL,
		0xC0F388B6E9B2069AULL,
		0x51052DFB51C05613ULL
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
		0x9000B2013705AEBBULL,
		0x5F0C7502DAE6330AULL,
		0xF3E03C333B6B3806ULL,
		0x61EEE3BC96317B5DULL,
		0xCAD5F9208947EEBAULL,
		0x8FDE5706B39C1EB6ULL,
		0xD7B06A649323B66DULL,
		0x0287A4CD9CBCD439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x200164026E0B5D76ULL,
		0xBE18EA05B5CC6615ULL,
		0xE7C0786676D6700CULL,
		0xC3DDC7792C62F6BBULL,
		0x95ABF241128FDD74ULL,
		0x1FBCAE0D67383D6DULL,
		0xAF60D4C926476CDBULL,
		0x050F499B3979A873ULL
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
		0x6E3E99438A6F4C34ULL,
		0xFC34706B35BE518FULL,
		0xEDCF7268FF452222ULL,
		0xFA1922B91825FB71ULL,
		0x8AD7CA5CFF156AAEULL,
		0xB8809E02723FDC42ULL,
		0xAE54EB723C4621EEULL,
		0x3CDCC10B00F4A923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC7D328714DE9868ULL,
		0xF868E0D66B7CA31EULL,
		0xDB9EE4D1FE8A4445ULL,
		0xF4324572304BF6E3ULL,
		0x15AF94B9FE2AD55DULL,
		0x71013C04E47FB885ULL,
		0x5CA9D6E4788C43DDULL,
		0x79B9821601E95247ULL
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
		0xC6027649DD68361AULL,
		0x1D6DFD7C309A19CFULL,
		0x0811D00D3181AD65ULL,
		0x932DB8CEEBD618ADULL,
		0xA4FF80AA51ACB296ULL,
		0x42D852FA82E77560ULL,
		0x709CACA303D3D56DULL,
		0x25527E021244BB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C04EC93BAD06C34ULL,
		0x3ADBFAF86134339FULL,
		0x1023A01A63035ACAULL,
		0x265B719DD7AC315AULL,
		0x49FF0154A359652DULL,
		0x85B0A5F505CEEAC1ULL,
		0xE139594607A7AADAULL,
		0x4AA4FC0424897730ULL
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
		0x6C8DAD69B4878654ULL,
		0xF74620A56403BE4CULL,
		0xDC3E6E065298DBB4ULL,
		0x2D27015A78B0471AULL,
		0x4C3DF3F9CBDC8CF8ULL,
		0xAD0D7B7FF2C7EF27ULL,
		0x84408E327478667AULL,
		0x3CDE5E12D27194DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD91B5AD3690F0CA8ULL,
		0xEE8C414AC8077C98ULL,
		0xB87CDC0CA531B769ULL,
		0x5A4E02B4F1608E35ULL,
		0x987BE7F397B919F0ULL,
		0x5A1AF6FFE58FDE4EULL,
		0x08811C64E8F0CCF5ULL,
		0x79BCBC25A4E329B5ULL
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
		0xF2AD8B6966A36857ULL,
		0x07718544D740CAA9ULL,
		0x50D7FE61A3BDEC23ULL,
		0x078A204AAD7F8FEFULL,
		0x59E2238E4AF9C17DULL,
		0xEC91565BE35B91C5ULL,
		0x5E816FD94EA890AAULL,
		0x0C53A7B0F4BE5FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55B16D2CD46D0AEULL,
		0x0EE30A89AE819553ULL,
		0xA1AFFCC3477BD846ULL,
		0x0F1440955AFF1FDEULL,
		0xB3C4471C95F382FAULL,
		0xD922ACB7C6B7238AULL,
		0xBD02DFB29D512155ULL,
		0x18A74F61E97CBFDCULL
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
		0x68A5E800EA728410ULL,
		0x9C9F37E797CB1DCEULL,
		0x387C53E4785DCE01ULL,
		0x0BBA2317D1784556ULL,
		0xE680AF5AA868ED47ULL,
		0xF8208DF723B51AC1ULL,
		0x9D5465F970C09D32ULL,
		0x2B15DA65016723DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14BD001D4E50820ULL,
		0x393E6FCF2F963B9CULL,
		0x70F8A7C8F0BB9C03ULL,
		0x1774462FA2F08AACULL,
		0xCD015EB550D1DA8EULL,
		0xF0411BEE476A3583ULL,
		0x3AA8CBF2E1813A65ULL,
		0x562BB4CA02CE47B9ULL
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
		0x9769D600CA026FFEULL,
		0x9198D7DB1B4ABC10ULL,
		0x379501EE1BC7B8A5ULL,
		0xE943679D7C4408DBULL,
		0x2BAF433AB6002CECULL,
		0x2A4A3D5462B070F4ULL,
		0xAAC294F34EAADA36ULL,
		0x1F6D5FDF27F0922CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED3AC019404DFFCULL,
		0x2331AFB636957821ULL,
		0x6F2A03DC378F714BULL,
		0xD286CF3AF88811B6ULL,
		0x575E86756C0059D9ULL,
		0x54947AA8C560E1E8ULL,
		0x558529E69D55B46CULL,
		0x3EDABFBE4FE12459ULL
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
		0x215C794DD508D66AULL,
		0xE90D7C7BEAD25BD3ULL,
		0x631E056B565E3B9BULL,
		0x609C0E73EC83A1F5ULL,
		0xB0E1C729A457A4D6ULL,
		0xB286479F3D1583CFULL,
		0x6617645C97E90410ULL,
		0x220AABB2FE60AB07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42B8F29BAA11ACD4ULL,
		0xD21AF8F7D5A4B7A6ULL,
		0xC63C0AD6ACBC7737ULL,
		0xC1381CE7D90743EAULL,
		0x61C38E5348AF49ACULL,
		0x650C8F3E7A2B079FULL,
		0xCC2EC8B92FD20821ULL,
		0x44155765FCC1560EULL
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
		0xFC15EBC67A559F40ULL,
		0xD71734607EA2D589ULL,
		0xB31DF3930A837AA0ULL,
		0x0A01B1CC9B1A17A3ULL,
		0xF0EB1A342B650A87ULL,
		0xD95BEE4E4895436AULL,
		0x326D96C2A464C958ULL,
		0x0CC01A34F1577F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82BD78CF4AB3E80ULL,
		0xAE2E68C0FD45AB13ULL,
		0x663BE7261506F541ULL,
		0x1403639936342F47ULL,
		0xE1D6346856CA150EULL,
		0xB2B7DC9C912A86D5ULL,
		0x64DB2D8548C992B1ULL,
		0x19803469E2AEFED8ULL
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
		0xA48A1046D63ED65DULL,
		0x59A65839CA3F53B9ULL,
		0x7B7D4DE3117CE1D5ULL,
		0x8301090DEEA3C78BULL,
		0xB8032BA53250305DULL,
		0x064E06FE0FDBCB4EULL,
		0x988EDC684A9CE520ULL,
		0x2AA64BDFDE0191AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4914208DAC7DACBAULL,
		0xB34CB073947EA773ULL,
		0xF6FA9BC622F9C3AAULL,
		0x0602121BDD478F16ULL,
		0x7006574A64A060BBULL,
		0x0C9C0DFC1FB7969DULL,
		0x311DB8D09539CA40ULL,
		0x554C97BFBC03235DULL
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
		0xBDDE754C3EE00959ULL,
		0x675C0D6F409D43AFULL,
		0x261302635614DAC6ULL,
		0x5893E14745476771ULL,
		0xB2A9D18ABC565722ULL,
		0x8BA6BCB71D5FCFE7ULL,
		0x91F4C9D1E2FE1275ULL,
		0x2D1F10F0C0516001ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBCEA987DC012B2ULL,
		0xCEB81ADE813A875FULL,
		0x4C2604C6AC29B58CULL,
		0xB127C28E8A8ECEE2ULL,
		0x6553A31578ACAE44ULL,
		0x174D796E3ABF9FCFULL,
		0x23E993A3C5FC24EBULL,
		0x5A3E21E180A2C003ULL
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
		0xFCF2715FF627602EULL,
		0x40095F83F9645C13ULL,
		0xBA366B6AE913A811ULL,
		0x3BC4AD4FF0468A11ULL,
		0x66DE87337EB594D8ULL,
		0xAF61AF2B2D197678ULL,
		0xC30F7C445952C278ULL,
		0x35B7167BC753D098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9E4E2BFEC4EC05CULL,
		0x8012BF07F2C8B827ULL,
		0x746CD6D5D2275022ULL,
		0x77895A9FE08D1423ULL,
		0xCDBD0E66FD6B29B0ULL,
		0x5EC35E565A32ECF0ULL,
		0x861EF888B2A584F1ULL,
		0x6B6E2CF78EA7A131ULL
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
		0x9C0DD2A126D1E2EBULL,
		0x5263CD7F57076523ULL,
		0xF2A2182414B4F6FFULL,
		0xBF84E37BEF8B02FAULL,
		0xF08A9031AE305FDFULL,
		0x8E7B9EFEC758F12DULL,
		0x634ABE046225A008ULL,
		0x049FB013FFC6B14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381BA5424DA3C5D6ULL,
		0xA4C79AFEAE0ECA47ULL,
		0xE54430482969EDFEULL,
		0x7F09C6F7DF1605F5ULL,
		0xE11520635C60BFBFULL,
		0x1CF73DFD8EB1E25BULL,
		0xC6957C08C44B4011ULL,
		0x093F6027FF8D6298ULL
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
		0xA097401C1216F6CEULL,
		0x696B15D665724CFEULL,
		0x4D9562D8DA91A9B1ULL,
		0x1819B9058B507E2EULL,
		0x9BE74AD778CB4053ULL,
		0x37691FF6DA09E691ULL,
		0xD3EE7810A5EDB2D7ULL,
		0x278FAD940E984453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x412E8038242DED9CULL,
		0xD2D62BACCAE499FDULL,
		0x9B2AC5B1B5235362ULL,
		0x3033720B16A0FC5CULL,
		0x37CE95AEF19680A6ULL,
		0x6ED23FEDB413CD23ULL,
		0xA7DCF0214BDB65AEULL,
		0x4F1F5B281D3088A7ULL
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
		0xA1379CE916B2ED56ULL,
		0x297590B20B159585ULL,
		0xC442816AE13AFA87ULL,
		0x52E75EAB88178293ULL,
		0x68EAC932FB2F536EULL,
		0xE894527579BE6BE2ULL,
		0x5CA7D55D98A43FBBULL,
		0x2435155DA371D713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x426F39D22D65DAACULL,
		0x52EB2164162B2B0BULL,
		0x888502D5C275F50EULL,
		0xA5CEBD57102F0527ULL,
		0xD1D59265F65EA6DCULL,
		0xD128A4EAF37CD7C4ULL,
		0xB94FAABB31487F77ULL,
		0x486A2ABB46E3AE26ULL
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
		0x006ACA08D7808205ULL,
		0xC3059068FDF2F093ULL,
		0x6DAC786EACB16BCFULL,
		0x4BB2717602840763ULL,
		0x1B72469570D55407ULL,
		0xF28CD7987541E4BDULL,
		0x9DFA7B6BCB254A94ULL,
		0x0FA64CAD83BB812BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D59411AF01040AULL,
		0x860B20D1FBE5E126ULL,
		0xDB58F0DD5962D79FULL,
		0x9764E2EC05080EC6ULL,
		0x36E48D2AE1AAA80EULL,
		0xE519AF30EA83C97AULL,
		0x3BF4F6D7964A9529ULL,
		0x1F4C995B07770257ULL
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
		0x26F6C0DA19B8B8E4ULL,
		0x1AAF0370A3EC6956ULL,
		0xE3C26AD078767C5DULL,
		0xEF0359D6F47B8156ULL,
		0x56A51A3D1B2234EBULL,
		0x2A46B51DAB77A8FEULL,
		0x8C6463A5D650CAF7ULL,
		0x2B3BCE25F4AADE11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DED81B4337171C8ULL,
		0x355E06E147D8D2ACULL,
		0xC784D5A0F0ECF8BAULL,
		0xDE06B3ADE8F702ADULL,
		0xAD4A347A364469D7ULL,
		0x548D6A3B56EF51FCULL,
		0x18C8C74BACA195EEULL,
		0x56779C4BE955BC23ULL
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
		0xA4CD36FA458DFF7EULL,
		0x72878560B41B3B9AULL,
		0x484A6CC1081A3FB6ULL,
		0x982F5467C9057CBDULL,
		0xAE3DAAEF238C43FEULL,
		0xE6EE53FA279FAB1DULL,
		0xFDDDD9783203D05AULL,
		0x08A2AD656795300DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499A6DF48B1BFEFCULL,
		0xE50F0AC168367735ULL,
		0x9094D98210347F6CULL,
		0x305EA8CF920AF97AULL,
		0x5C7B55DE471887FDULL,
		0xCDDCA7F44F3F563BULL,
		0xFBBBB2F06407A0B5ULL,
		0x11455ACACF2A601BULL
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
		0x322749B5BFF25F4AULL,
		0xCE649495FB3D91F5ULL,
		0xEC5D547BFF510727ULL,
		0xDC455A00C54C0E9BULL,
		0x1C5A88F0DD256937ULL,
		0x8EF40F7FE1033024ULL,
		0x8FD3C91772083500ULL,
		0x16EC99D2287CD40EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x644E936B7FE4BE94ULL,
		0x9CC9292BF67B23EAULL,
		0xD8BAA8F7FEA20E4FULL,
		0xB88AB4018A981D37ULL,
		0x38B511E1BA4AD26FULL,
		0x1DE81EFFC2066048ULL,
		0x1FA7922EE4106A01ULL,
		0x2DD933A450F9A81DULL
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
		0x38576D133DB5BBABULL,
		0x5E71A039D57753A9ULL,
		0xEC67AE8726DD23E4ULL,
		0xEEC63A0CE095A38AULL,
		0xF232ADDD2451075DULL,
		0x9559BF60C2528678ULL,
		0xD20C941B0F8795E3ULL,
		0x175B2CA24683C675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70AEDA267B6B7756ULL,
		0xBCE34073AAEEA752ULL,
		0xD8CF5D0E4DBA47C8ULL,
		0xDD8C7419C12B4715ULL,
		0xE4655BBA48A20EBBULL,
		0x2AB37EC184A50CF1ULL,
		0xA41928361F0F2BC7ULL,
		0x2EB659448D078CEBULL
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
		0x8F57B03C577FD4AEULL,
		0xF7B180FBA0E87D9CULL,
		0xD7F97743C9794B22ULL,
		0x8BF9590DF6E755D8ULL,
		0x80EA741F81AE4508ULL,
		0x6EED41FECF02A2B6ULL,
		0xFD0E2964526A5440ULL,
		0x0B45871C0F6CBF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EAF6078AEFFA95CULL,
		0xEF6301F741D0FB39ULL,
		0xAFF2EE8792F29645ULL,
		0x17F2B21BEDCEABB1ULL,
		0x01D4E83F035C8A11ULL,
		0xDDDA83FD9E05456DULL,
		0xFA1C52C8A4D4A880ULL,
		0x168B0E381ED97F1BULL
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
		0x04303198AE0E7D9DULL,
		0x34857EA0455639A3ULL,
		0x9098DD3C08F0EB82ULL,
		0x6505E74FB435924AULL,
		0x955724941DC8A4E3ULL,
		0xD6C261F9FFD65F2AULL,
		0x02A05793DC867DEAULL,
		0x3081DCF5B355C372ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x086063315C1CFB3AULL,
		0x690AFD408AAC7346ULL,
		0x2131BA7811E1D704ULL,
		0xCA0BCE9F686B2495ULL,
		0x2AAE49283B9149C6ULL,
		0xAD84C3F3FFACBE55ULL,
		0x0540AF27B90CFBD5ULL,
		0x6103B9EB66AB86E4ULL
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
		0x42063FA2FB4F9763ULL,
		0xA22139F14ADFE502ULL,
		0xFC36DBAD783E64C6ULL,
		0xA2F3692320C4F9FEULL,
		0xF20FF988B712D829ULL,
		0x3221A1D95B882EB0ULL,
		0x7F2BD916EB668461ULL,
		0x0DA0A8188457AC46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x840C7F45F69F2EC6ULL,
		0x444273E295BFCA04ULL,
		0xF86DB75AF07CC98DULL,
		0x45E6D2464189F3FDULL,
		0xE41FF3116E25B053ULL,
		0x644343B2B7105D61ULL,
		0xFE57B22DD6CD08C2ULL,
		0x1B41503108AF588CULL
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
		0x0B3DE9FA4351344FULL,
		0x71E73F42E5E2030EULL,
		0xD5C92A93876E6504ULL,
		0xFC7C2447DA468418ULL,
		0xB091A14B2FDD1798ULL,
		0x28F62AAA4D3BFF2CULL,
		0xA9EB642C413F470DULL,
		0x248C35BC515AB780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167BD3F486A2689EULL,
		0xE3CE7E85CBC4061CULL,
		0xAB9255270EDCCA08ULL,
		0xF8F8488FB48D0831ULL,
		0x612342965FBA2F31ULL,
		0x51EC55549A77FE59ULL,
		0x53D6C858827E8E1AULL,
		0x49186B78A2B56F01ULL
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
		0x05FB14F935D54530ULL,
		0x9D644C980583CCE4ULL,
		0x2F893C7151BBED73ULL,
		0x9C966736B547C5E7ULL,
		0x035AE665FF2961E5ULL,
		0xF8FFF4D682863006ULL,
		0x932AE90F53C2A2A8ULL,
		0x2CAB60FA2821C0B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF629F26BAA8A60ULL,
		0x3AC899300B0799C8ULL,
		0x5F1278E2A377DAE7ULL,
		0x392CCE6D6A8F8BCEULL,
		0x06B5CCCBFE52C3CBULL,
		0xF1FFE9AD050C600CULL,
		0x2655D21EA7854551ULL,
		0x5956C1F450438173ULL
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
		0x5875AAC2BDECF498ULL,
		0xB400399B111BA83CULL,
		0x846842E3ACFD87EAULL,
		0x10B08D2D931EF8CBULL,
		0xA15B492D994A4AB0ULL,
		0xAD8A001CD850128AULL,
		0x111FDA4BE3E31FAFULL,
		0x1BD08E6F9028FA96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0EB55857BD9E930ULL,
		0x6800733622375078ULL,
		0x08D085C759FB0FD5ULL,
		0x21611A5B263DF197ULL,
		0x42B6925B32949560ULL,
		0x5B140039B0A02515ULL,
		0x223FB497C7C63F5FULL,
		0x37A11CDF2051F52CULL
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
		0x0629BB1D9640E561ULL,
		0x64B6752E15E88AC8ULL,
		0x9F7E6D63F7BD5F3FULL,
		0x71C39E93874BE478ULL,
		0xA624F2B089BDB2A7ULL,
		0x8F2A9AE88C1DFF2BULL,
		0x9F1530FCB0E623AFULL,
		0x13185A8FEB3593A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C53763B2C81CAC2ULL,
		0xC96CEA5C2BD11590ULL,
		0x3EFCDAC7EF7ABE7EULL,
		0xE3873D270E97C8F1ULL,
		0x4C49E561137B654EULL,
		0x1E5535D1183BFE57ULL,
		0x3E2A61F961CC475FULL,
		0x2630B51FD66B274DULL
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
		0xEE696C34394D9533ULL,
		0x4485A5253EAC6B1CULL,
		0xF68761A9C7EFA17BULL,
		0xFF14862BAE391946ULL,
		0x75815E6071DBD7B0ULL,
		0x65C36790C5722C19ULL,
		0xC36C8B4175DC5BCEULL,
		0x30BDE708F07FC6C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD2D868729B2A66ULL,
		0x890B4A4A7D58D639ULL,
		0xED0EC3538FDF42F6ULL,
		0xFE290C575C72328DULL,
		0xEB02BCC0E3B7AF61ULL,
		0xCB86CF218AE45832ULL,
		0x86D91682EBB8B79CULL,
		0x617BCE11E0FF8D85ULL
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
		0xA188229EBF6BE89AULL,
		0x9443110384ECF9D9ULL,
		0xF5F2F0D3AAA5F71DULL,
		0x41CC44B4EE4AE4AEULL,
		0xF04214F6C8855024ULL,
		0xDF012CE030042C6EULL,
		0xD4D6246188AE5962ULL,
		0x1E2CAE8B82E2B79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4310453D7ED7D134ULL,
		0x2886220709D9F3B3ULL,
		0xEBE5E1A7554BEE3BULL,
		0x83988969DC95C95DULL,
		0xE08429ED910AA048ULL,
		0xBE0259C0600858DDULL,
		0xA9AC48C3115CB2C5ULL,
		0x3C595D1705C56F35ULL
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
		0x03A4C2E14DC41670ULL,
		0xAE4227CCE541DECEULL,
		0xA7EB66B9B9D20FA4ULL,
		0x3061DC1E7448671FULL,
		0x61C9DA786B7DC0E3ULL,
		0xAB6A25142C2E0A67ULL,
		0x400A0549BD03A4E6ULL,
		0x1248F4ED0C517025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074985C29B882CE0ULL,
		0x5C844F99CA83BD9CULL,
		0x4FD6CD7373A41F49ULL,
		0x60C3B83CE890CE3FULL,
		0xC393B4F0D6FB81C6ULL,
		0x56D44A28585C14CEULL,
		0x80140A937A0749CDULL,
		0x2491E9DA18A2E04AULL
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
		0xD1571F2B1DF158E4ULL,
		0xD71415C1C96536BEULL,
		0xE1169FCBB886EC56ULL,
		0x1C8F68539D608865ULL,
		0x786248969A19078AULL,
		0xA56387A2028598CBULL,
		0x4D7055E8EA8C7EA1ULL,
		0x15B34F20DC6CB017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AE3E563BE2B1C8ULL,
		0xAE282B8392CA6D7DULL,
		0xC22D3F97710DD8ADULL,
		0x391ED0A73AC110CBULL,
		0xF0C4912D34320F14ULL,
		0x4AC70F44050B3196ULL,
		0x9AE0ABD1D518FD43ULL,
		0x2B669E41B8D9602EULL
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
		0x9EB1E9670D767338ULL,
		0x4106C5D623A5A627ULL,
		0x1E6D3727A6C36E27ULL,
		0x9D3D47DEED580AADULL,
		0x1D8B29916E13BD03ULL,
		0xC6FEF66EA7D7398DULL,
		0x5E7825FA4C9C72F2ULL,
		0x34B20A5022A653A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D63D2CE1AECE670ULL,
		0x820D8BAC474B4C4FULL,
		0x3CDA6E4F4D86DC4EULL,
		0x3A7A8FBDDAB0155AULL,
		0x3B165322DC277A07ULL,
		0x8DFDECDD4FAE731AULL,
		0xBCF04BF49938E5E5ULL,
		0x696414A0454CA752ULL
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
		0x8E486FCA432DB132ULL,
		0x9A9805394A6EAB69ULL,
		0x0F30E3AA31A083F1ULL,
		0x51467C22A4C978B7ULL,
		0xB535F9CD919F7C3FULL,
		0xB9318FD1FB76EED0ULL,
		0xAE6B0EDC19DFA43CULL,
		0x2E1C4F9B36389F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C90DF94865B6264ULL,
		0x35300A7294DD56D3ULL,
		0x1E61C754634107E3ULL,
		0xA28CF8454992F16EULL,
		0x6A6BF39B233EF87EULL,
		0x72631FA3F6EDDDA1ULL,
		0x5CD61DB833BF4879ULL,
		0x5C389F366C713E25ULL
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
		0xE98B3EA31ED64F81ULL,
		0x7A84CBE8D9108122ULL,
		0xDA408D0BE718607BULL,
		0x087DDD01CC30120AULL,
		0x62D9C9A994FAF81FULL,
		0x7D632615CD71C417ULL,
		0x2B6DC64628DD9286ULL,
		0x360DF2759A2601DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3167D463DAC9F02ULL,
		0xF50997D1B2210245ULL,
		0xB4811A17CE30C0F6ULL,
		0x10FBBA0398602415ULL,
		0xC5B3935329F5F03EULL,
		0xFAC64C2B9AE3882EULL,
		0x56DB8C8C51BB250CULL,
		0x6C1BE4EB344C03B4ULL
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
		0xCD8B6824D3C734F8ULL,
		0xD2766E3E99837E0CULL,
		0x0A94CEE5F3F3E001ULL,
		0xF3BF01C02E3930BEULL,
		0xA6150FA1C7F68B5FULL,
		0xC0A5EAAFA22A54C3ULL,
		0x016DD7CD013F3469ULL,
		0x0EA40349B4555C1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B16D049A78E69F0ULL,
		0xA4ECDC7D3306FC19ULL,
		0x15299DCBE7E7C003ULL,
		0xE77E03805C72617CULL,
		0x4C2A1F438FED16BFULL,
		0x814BD55F4454A987ULL,
		0x02DBAF9A027E68D3ULL,
		0x1D48069368AAB83AULL
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
		0xFEAF5EECD6D336E4ULL,
		0x5B2C94EA6DD2D03EULL,
		0x2E02094F6BCE8BBDULL,
		0x6E296BEEBC594674ULL,
		0x8CF416B02F6332AFULL,
		0x90FA230538240CA4ULL,
		0x2A0F3B620656799BULL,
		0x2A56A4F227B9A6D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5EBDD9ADA66DC8ULL,
		0xB65929D4DBA5A07DULL,
		0x5C04129ED79D177AULL,
		0xDC52D7DD78B28CE8ULL,
		0x19E82D605EC6655EULL,
		0x21F4460A70481949ULL,
		0x541E76C40CACF337ULL,
		0x54AD49E44F734DA6ULL
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
		0x73DA96AF130329A6ULL,
		0xA1E24EF98CB8F38FULL,
		0x338DEE9F9AD6E511ULL,
		0xCB8E47948CDA9167ULL,
		0x72AFC81E27E1F107ULL,
		0xD061C912427AE14DULL,
		0x004E83D49F12070FULL,
		0x355F175314D22344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B52D5E2606534CULL,
		0x43C49DF31971E71EULL,
		0x671BDD3F35ADCA23ULL,
		0x971C8F2919B522CEULL,
		0xE55F903C4FC3E20FULL,
		0xA0C3922484F5C29AULL,
		0x009D07A93E240E1FULL,
		0x6ABE2EA629A44688ULL
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
		0x2653406261FD18B4ULL,
		0x353F6CCDE7C181E3ULL,
		0x8371CA04EBE4398BULL,
		0x5B3C55B4921CD187ULL,
		0x753D90B18FED1AA5ULL,
		0xA1465CF21BD2E645ULL,
		0xC23C0CDC71FC3E0CULL,
		0x02E9715562FB7D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CA680C4C3FA3168ULL,
		0x6A7ED99BCF8303C6ULL,
		0x06E39409D7C87316ULL,
		0xB678AB692439A30FULL,
		0xEA7B21631FDA354AULL,
		0x428CB9E437A5CC8AULL,
		0x847819B8E3F87C19ULL,
		0x05D2E2AAC5F6FA87ULL
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
		0x766430334C8C6DF1ULL,
		0x2DB52A2D93E119BEULL,
		0xAF6738FC61D68FBDULL,
		0x75B3DC29B15185D3ULL,
		0xFD1630FA9B956C95ULL,
		0xE784017AD2F47F42ULL,
		0xE2E244C788D2DEACULL,
		0x2A09045BE7E862A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC860669918DBE2ULL,
		0x5B6A545B27C2337CULL,
		0x5ECE71F8C3AD1F7AULL,
		0xEB67B85362A30BA7ULL,
		0xFA2C61F5372AD92AULL,
		0xCF0802F5A5E8FE85ULL,
		0xC5C4898F11A5BD59ULL,
		0x541208B7CFD0C541ULL
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
		0x5E214669A3855B2DULL,
		0xE7EC4C761E1389E6ULL,
		0xA9AAE871527A6DADULL,
		0xF78C6F83F02404B1ULL,
		0xF35318F9D315F7B6ULL,
		0x0052ACE43C74756DULL,
		0x2D7313C9ACA90595ULL,
		0x3ECBE9C223C6D29FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC428CD3470AB65AULL,
		0xCFD898EC3C2713CCULL,
		0x5355D0E2A4F4DB5BULL,
		0xEF18DF07E0480963ULL,
		0xE6A631F3A62BEF6DULL,
		0x00A559C878E8EADBULL,
		0x5AE6279359520B2AULL,
		0x7D97D384478DA53EULL
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
		0xC05DF8FB02067BA2ULL,
		0x878433299594AC72ULL,
		0x145BFD516B97B576ULL,
		0x0AE06754DDEDF8A7ULL,
		0x34C539BD8D8F85EBULL,
		0x52718EEB21EBDA08ULL,
		0x3300C1E314C072F3ULL,
		0x16B16733B57514C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BBF1F6040CF744ULL,
		0x0F0866532B2958E5ULL,
		0x28B7FAA2D72F6AEDULL,
		0x15C0CEA9BBDBF14EULL,
		0x698A737B1B1F0BD6ULL,
		0xA4E31DD643D7B410ULL,
		0x660183C62980E5E6ULL,
		0x2D62CE676AEA298CULL
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
		0x8CD8D8E911AC60F6ULL,
		0x332BF32136237536ULL,
		0xE75C8D0503DE4B54ULL,
		0xFD3CE1F18D20780EULL,
		0xAD613275C87FFF9DULL,
		0x7B39AECD6FF6477CULL,
		0x49FDE5B76A41F59BULL,
		0x12C83F22C511F589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19B1B1D22358C1ECULL,
		0x6657E6426C46EA6DULL,
		0xCEB91A0A07BC96A8ULL,
		0xFA79C3E31A40F01DULL,
		0x5AC264EB90FFFF3BULL,
		0xF6735D9ADFEC8EF9ULL,
		0x93FBCB6ED483EB36ULL,
		0x25907E458A23EB12ULL
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
		0x23D7708E714A6C6DULL,
		0x5DCE2673C7D3CED0ULL,
		0xF57C51EF7A1D58BFULL,
		0xE8A74C13040E94D9ULL,
		0x22E45BCEEA36EF90ULL,
		0x55A213DFC757C00CULL,
		0xB3CA18774D0824B5ULL,
		0x1602A21D729080CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AEE11CE294D8DAULL,
		0xBB9C4CE78FA79DA0ULL,
		0xEAF8A3DEF43AB17EULL,
		0xD14E9826081D29B3ULL,
		0x45C8B79DD46DDF21ULL,
		0xAB4427BF8EAF8018ULL,
		0x679430EE9A10496AULL,
		0x2C05443AE521019DULL
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
		0x31FB4DE9224F67EFULL,
		0x688C190D7C165D4BULL,
		0xBC6236DE6970387EULL,
		0x9A696B226EA8BA6BULL,
		0x86843EAC29EF2243ULL,
		0xAE09F03E766E06E2ULL,
		0xD5C9153ED8877457ULL,
		0x0E0F8BA970197E01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F69BD2449ECFDEULL,
		0xD118321AF82CBA96ULL,
		0x78C46DBCD2E070FCULL,
		0x34D2D644DD5174D7ULL,
		0x0D087D5853DE4487ULL,
		0x5C13E07CECDC0DC5ULL,
		0xAB922A7DB10EE8AFULL,
		0x1C1F1752E032FC03ULL
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
		0xDF33D5E3D6E724EFULL,
		0x58357157204BA4C5ULL,
		0x3656A4BF701F4544ULL,
		0x819FF4FEE56555E1ULL,
		0xC8BB1D05779D18DDULL,
		0x2886FE6593DA4FB9ULL,
		0x9100B9E1E0E966E2ULL,
		0x02F1782126E02602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE67ABC7ADCE49DEULL,
		0xB06AE2AE4097498BULL,
		0x6CAD497EE03E8A88ULL,
		0x033FE9FDCACAABC2ULL,
		0x91763A0AEF3A31BBULL,
		0x510DFCCB27B49F73ULL,
		0x220173C3C1D2CDC4ULL,
		0x05E2F0424DC04C05ULL
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
		0x2A8C3507F180F7B9ULL,
		0x5432AF43B7143068ULL,
		0xB3FFF95480214806ULL,
		0xD6CA2B93CF1419F4ULL,
		0xF481F9BE99933339ULL,
		0xADC98C3BACE921C8ULL,
		0xA7A6D530618F8C38ULL,
		0x17CA13E2A3785B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55186A0FE301EF72ULL,
		0xA8655E876E2860D0ULL,
		0x67FFF2A90042900CULL,
		0xAD9457279E2833E9ULL,
		0xE903F37D33266673ULL,
		0x5B93187759D24391ULL,
		0x4F4DAA60C31F1871ULL,
		0x2F9427C546F0B70DULL
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
		0xF1062E32DA1DADA7ULL,
		0x7781AA1F7452AFFAULL,
		0x9B3F925EC8741993ULL,
		0x4F410A68E5DB04C3ULL,
		0x2F19BC86C2F99459ULL,
		0x7B1BAEEB0B4DC7F6ULL,
		0xBB94642EDD1FDC22ULL,
		0x2C59F3BCA6F6FEC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20C5C65B43B5B4EULL,
		0xEF03543EE8A55FF5ULL,
		0x367F24BD90E83326ULL,
		0x9E8214D1CBB60987ULL,
		0x5E33790D85F328B2ULL,
		0xF6375DD6169B8FECULL,
		0x7728C85DBA3FB844ULL,
		0x58B3E7794DEDFD83ULL
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
		0x1ECBD87E5B31C92BULL,
		0xFA921FD96053C1F4ULL,
		0xC89B31FBF0AD5709ULL,
		0x16781CC518A55BC6ULL,
		0xA8A40701876BDD8FULL,
		0x83E8BDBBE6660E8BULL,
		0x15563FC21A46FBABULL,
		0x27265BEDC078CA52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D97B0FCB6639256ULL,
		0xF5243FB2C0A783E8ULL,
		0x913663F7E15AAE13ULL,
		0x2CF0398A314AB78DULL,
		0x51480E030ED7BB1EULL,
		0x07D17B77CCCC1D17ULL,
		0x2AAC7F84348DF757ULL,
		0x4E4CB7DB80F194A4ULL
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
		0x04ECDB73A034746BULL,
		0x21311A0014ED1C83ULL,
		0x773093712EBF613EULL,
		0xE8F1E8E519424C1CULL,
		0x85CD0756E0343FDFULL,
		0x0FE9835B8C0964DBULL,
		0x064BA74C3FB0642DULL,
		0x3ABC3038ACCD2719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D9B6E74068E8D6ULL,
		0x4262340029DA3906ULL,
		0xEE6126E25D7EC27CULL,
		0xD1E3D1CA32849838ULL,
		0x0B9A0EADC0687FBFULL,
		0x1FD306B71812C9B7ULL,
		0x0C974E987F60C85AULL,
		0x75786071599A4E32ULL
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
		0x0AAC6F2E20DB0B34ULL,
		0x85BB355F0902279EULL,
		0xFC7E920CA8DA420BULL,
		0xC5BD64B3F912EA5DULL,
		0x9EEF53C8F2F35DAAULL,
		0xA371E107DC8AC8A0ULL,
		0x9809A9E50592FE76ULL,
		0x38CA5CA7DBFB13EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1558DE5C41B61668ULL,
		0x0B766ABE12044F3CULL,
		0xF8FD241951B48417ULL,
		0x8B7AC967F225D4BBULL,
		0x3DDEA791E5E6BB55ULL,
		0x46E3C20FB9159141ULL,
		0x301353CA0B25FCEDULL,
		0x7194B94FB7F627D7ULL
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
		0xA5C472A0E12BC313ULL,
		0x91A8202FD0F3BF68ULL,
		0x11A45A814538E024ULL,
		0x89BB5930D05D6EC9ULL,
		0x589E8220BEE676CEULL,
		0x306E42BB2EED753CULL,
		0x3EFD8A83AF4C8DACULL,
		0x1420987344D63B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B88E541C2578626ULL,
		0x2350405FA1E77ED1ULL,
		0x2348B5028A71C049ULL,
		0x1376B261A0BADD92ULL,
		0xB13D04417DCCED9DULL,
		0x60DC85765DDAEA78ULL,
		0x7DFB15075E991B58ULL,
		0x284130E689AC7736ULL
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
		0x802653C15B9FD238ULL,
		0xF47CE5F4419ECD47ULL,
		0x0015B5D3B82C81F2ULL,
		0x162FDD5929BB2921ULL,
		0xD07368E8F6C2A5A1ULL,
		0xDA62068FAFA3EE23ULL,
		0x25BEA3C0004DEB06ULL,
		0x342022BF8F3AF48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x004CA782B73FA470ULL,
		0xE8F9CBE8833D9A8FULL,
		0x002B6BA7705903E5ULL,
		0x2C5FBAB253765242ULL,
		0xA0E6D1D1ED854B42ULL,
		0xB4C40D1F5F47DC47ULL,
		0x4B7D4780009BD60DULL,
		0x6840457F1E75E91AULL
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
		0x20AA2F860BF1A6F3ULL,
		0xC4FBE526273CFDFCULL,
		0x32B0F65EBA9BF692ULL,
		0xE8AEEFDAC8C3AC31ULL,
		0xF4AE8D2CAD4F87E1ULL,
		0x94EF1ED4C791A5FEULL,
		0x3F853AA40913334EULL,
		0x31D1616D56563021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41545F0C17E34DE6ULL,
		0x89F7CA4C4E79FBF8ULL,
		0x6561ECBD7537ED25ULL,
		0xD15DDFB591875862ULL,
		0xE95D1A595A9F0FC3ULL,
		0x29DE3DA98F234BFDULL,
		0x7F0A75481226669DULL,
		0x63A2C2DAACAC6042ULL
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
		0xC942F2AA91777E39ULL,
		0x188804CA35D5E2A7ULL,
		0xBF528134157BC54BULL,
		0xBDC17C988841F614ULL,
		0x604A5B2C86F01F6AULL,
		0xAF3180F66F4FBCD2ULL,
		0xDB9FE2B0C4BDE938ULL,
		0x1DDA0C756B70FE4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9285E55522EEFC72ULL,
		0x311009946BABC54FULL,
		0x7EA502682AF78A96ULL,
		0x7B82F9311083EC29ULL,
		0xC094B6590DE03ED5ULL,
		0x5E6301ECDE9F79A4ULL,
		0xB73FC561897BD271ULL,
		0x3BB418EAD6E1FC9BULL
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
		0xA7E4CDA0ACB05230ULL,
		0x1E26C41B44A550FDULL,
		0x13312BF3B71D60A0ULL,
		0x57AB12E037269F05ULL,
		0x175E6FBD546AFD39ULL,
		0xF91211A2C8C04E81ULL,
		0xD6B7667D4728FB45ULL,
		0x31138E4566237937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC99B415960A460ULL,
		0x3C4D8836894AA1FBULL,
		0x266257E76E3AC140ULL,
		0xAF5625C06E4D3E0AULL,
		0x2EBCDF7AA8D5FA72ULL,
		0xF224234591809D02ULL,
		0xAD6ECCFA8E51F68BULL,
		0x62271C8ACC46F26FULL
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
		0x6A2D9FCF700F191AULL,
		0x52988452EB7E668DULL,
		0x58BCA0B5473E1E49ULL,
		0xF80891399A7F6DFFULL,
		0x8F6B914D7E394996ULL,
		0x7CA200927D132A75ULL,
		0x10D090A13F761BAEULL,
		0x15680A0BB5788882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45B3F9EE01E3234ULL,
		0xA53108A5D6FCCD1AULL,
		0xB179416A8E7C3C92ULL,
		0xF011227334FEDBFEULL,
		0x1ED7229AFC72932DULL,
		0xF9440124FA2654EBULL,
		0x21A121427EEC375CULL,
		0x2AD014176AF11104ULL
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
		0xB23E9345B6B105C0ULL,
		0x4CF111DBB27E8B35ULL,
		0xAA7E4FC5500447D3ULL,
		0x1ADC0041474080E6ULL,
		0xBF8A828C4B4AE6D2ULL,
		0x7FF9100E23C5AEE2ULL,
		0x47AF0CC6526B952AULL,
		0x3307044A69182FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647D268B6D620B80ULL,
		0x99E223B764FD166BULL,
		0x54FC9F8AA0088FA6ULL,
		0x35B800828E8101CDULL,
		0x7F1505189695CDA4ULL,
		0xFFF2201C478B5DC5ULL,
		0x8F5E198CA4D72A54ULL,
		0x660E0894D2305F54ULL
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
		0x9AFFF481DA44ED8AULL,
		0x9A89C9673D8E56DAULL,
		0x0515F9A626C6A690ULL,
		0xE22A7D5E163F0120ULL,
		0xAF3DC275A10BDABEULL,
		0xEF99679F23FEB6EFULL,
		0x5EE192C0D2BFC613ULL,
		0x0AE4DD8E91EE7B5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35FFE903B489DB14ULL,
		0x351392CE7B1CADB5ULL,
		0x0A2BF34C4D8D4D21ULL,
		0xC454FABC2C7E0240ULL,
		0x5E7B84EB4217B57DULL,
		0xDF32CF3E47FD6DDFULL,
		0xBDC32581A57F8C27ULL,
		0x15C9BB1D23DCF6B8ULL
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
		0x8F0FCFBE1AA403AFULL,
		0xAF484E2401906716ULL,
		0x1BD5FB7C09D54F15ULL,
		0x00BA3B40316CF3D6ULL,
		0xC1D53EBBD96C76D0ULL,
		0xF7B6F3565A5C0295ULL,
		0x9C06F2E4833EAEE1ULL,
		0x393CBEC7A364FAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1F9F7C3548075EULL,
		0x5E909C480320CE2DULL,
		0x37ABF6F813AA9E2BULL,
		0x0174768062D9E7ACULL,
		0x83AA7D77B2D8EDA0ULL,
		0xEF6DE6ACB4B8052BULL,
		0x380DE5C9067D5DC3ULL,
		0x72797D8F46C9F5E9ULL
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
		0x44FD7DD644BCC873ULL,
		0x3123262FD9626F67ULL,
		0x747A598AACDA6DC5ULL,
		0x4FA1E4DEE0B86358ULL,
		0x02783F94750BCBBBULL,
		0xE9423BE0532043C2ULL,
		0x7D385E17F3400FD4ULL,
		0x191768F01C87E673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89FAFBAC897990E6ULL,
		0x62464C5FB2C4DECEULL,
		0xE8F4B31559B4DB8AULL,
		0x9F43C9BDC170C6B0ULL,
		0x04F07F28EA179776ULL,
		0xD28477C0A6408784ULL,
		0xFA70BC2FE6801FA9ULL,
		0x322ED1E0390FCCE6ULL
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
		0x3BBB8104C71C251DULL,
		0x98B5711B6A5ABB57ULL,
		0x483B0E837DA3E05FULL,
		0x100BEF4DE0EFA40AULL,
		0xB65AE0C586A390D0ULL,
		0x9FD763FEEFA03834ULL,
		0xACBC5019A79A0CB2ULL,
		0x0D2E62F61F0AB64CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777702098E384A3AULL,
		0x316AE236D4B576AEULL,
		0x90761D06FB47C0BFULL,
		0x2017DE9BC1DF4814ULL,
		0x6CB5C18B0D4721A0ULL,
		0x3FAEC7FDDF407069ULL,
		0x5978A0334F341965ULL,
		0x1A5CC5EC3E156C99ULL
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
		0x0093B48B344D3889ULL,
		0x1803218AB1F4EF60ULL,
		0x38F72BB3D1CF64A6ULL,
		0xCEBD7B3BA281399BULL,
		0x08B88221F9E36AA9ULL,
		0x87D97BB62C56B0A6ULL,
		0x202C5839242B2705ULL,
		0x3287631E97B46B45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01276916689A7112ULL,
		0x3006431563E9DEC0ULL,
		0x71EE5767A39EC94CULL,
		0x9D7AF67745027336ULL,
		0x11710443F3C6D553ULL,
		0x0FB2F76C58AD614CULL,
		0x4058B07248564E0BULL,
		0x650EC63D2F68D68AULL
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
		0xE14EC2A46EE7B9F4ULL,
		0x45E1AFF81CBEB2E3ULL,
		0xC9D9A783C12A3DB2ULL,
		0x1C9D0F08600153E0ULL,
		0xD4B24498410B2188ULL,
		0xB97BD2AD4DF80165ULL,
		0x847942AC58EF82B5ULL,
		0x14F38FC615C4E1EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29D8548DDCF73E8ULL,
		0x8BC35FF0397D65C7ULL,
		0x93B34F0782547B64ULL,
		0x393A1E10C002A7C1ULL,
		0xA964893082164310ULL,
		0x72F7A55A9BF002CBULL,
		0x08F28558B1DF056BULL,
		0x29E71F8C2B89C3DDULL
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