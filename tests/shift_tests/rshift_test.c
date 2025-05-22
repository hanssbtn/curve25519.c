#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6E75A095AD818C6BULL,
		0x73E5116B20506803ULL,
		0xFAFA45E70AB76B1CULL,
		0x321FB32FB6E40CDAULL,
		0x4BF144DF0B241DF2ULL,
		0x99B421102E958222ULL,
		0xAA94640009AF4A55ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA00DB9D68256B606ULL,
		0xAC71CF9445AC8141ULL,
		0x336BEBE9179C2ADDULL,
		0x77C8C87ECCBEDB90ULL,
		0x08892FC5137C2C90ULL,
		0x295666D08440BA56ULL,
		0x0002AA51900026BDULL,
		0x0000000000000000ULL
	}};
	int shift = 14;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2A56AF7DFE68A9A8ULL,
		0xA5705C80855C4010ULL,
		0x59B38E4EB4DD7B75ULL,
		0x62AF07D25315DD50ULL,
		0xDBD3D98B642C751EULL,
		0x8E6D687D0CDE9D38ULL,
		0x60FEC1E64BCCDB24ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9010AB8802054ADULL,
		0x1C9D69BAF6EB4AE0ULL,
		0x0FA4A62BBAA0B367ULL,
		0xB316C858EA3CC55EULL,
		0xD0FA19BD3A71B7A7ULL,
		0x83CC9799B6491CDAULL,
		0x000000000000C1FDULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2E9BD14B27E8895EULL,
		0x6069C4C442750B8EULL,
		0x102A8EB0D5D032E7ULL,
		0xBC9A5BF543F143B4ULL,
		0x9B6480014D856A3EULL,
		0xBFDC7E17AE9A3945ULL,
		0x8FD5399F3BFDFBA1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13A85C7174DE8A59ULL,
		0xAE81973B034E2622ULL,
		0x1F8A1DA081547586ULL,
		0x6C2B51F5E4D2DFAAULL,
		0x74D1CA2CDB24000AULL,
		0xDFEFDD0DFEE3F0BDULL,
		0x000000047EA9CCF9ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7B6DF348D4F7676AULL,
		0xA140EA02C21DE61BULL,
		0xD0BC0CD8E8FD6750ULL,
		0xAA76741A0DB5A8C6ULL,
		0xFD417BB5E5445C64ULL,
		0x93740A847720440AULL,
		0x55270355D51A225CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77986DEDB7CD2353ULL,
		0xF59D428503A80B08ULL,
		0xD6A31B42F03363A3ULL,
		0x117192A9D9D06836ULL,
		0x81102BF505EED795ULL,
		0x6889724DD02A11DCULL,
		0x000001549C0D5754ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB5FA1CB010148BADULL,
		0x9996F8792D136A79ULL,
		0x6B1C9FA81E779618ULL,
		0xF0383F30D328EA65ULL,
		0x78A8E73BCBD98557ULL,
		0x7051ECE0674D68ECULL,
		0x0595FE9C52740514ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A26D4F36BF43960ULL,
		0x3CEF2C31332DF0F2ULL,
		0xA651D4CAD6393F50ULL,
		0x97B30AAFE0707E61ULL,
		0xCE9AD1D8F151CE77ULL,
		0xA4E80A28E0A3D9C0ULL,
		0x000000000B2BFD38ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4A0325787E11F6A5ULL,
		0x294D2F12B6B3BA59ULL,
		0xA353D14FC4634FA6ULL,
		0xF8DDDF80121BE331ULL,
		0x7CCC30DF55785028ULL,
		0x95B3783408BD109BULL,
		0x1AC747FC7F3FD898ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5280C95E1F847DA9ULL,
		0x8A534BC4ADACEE96ULL,
		0x68D4F453F118D3E9ULL,
		0x3E3777E00486F8CCULL,
		0xDF330C37D55E140AULL,
		0x256CDE0D022F4426ULL,
		0x06B1D1FF1FCFF626ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC7B81448F9EEA6B0ULL,
		0x9B5E434BE2F25C5BULL,
		0xAB8BF3B4FB78D258ULL,
		0x3370B4872C0DC223ULL,
		0xB2BBD6B9893E1B0EULL,
		0xD404AC25ED07F8C8ULL,
		0x292F82950013B145ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F8BC9716F1EE05ULL,
		0xED3EDE349626D790ULL,
		0x21CB037088EAE2FCULL,
		0xAE624F86C38CDC2DULL,
		0x097B41FE322CAEF5ULL,
		0xA54004EC5175012BULL,
		0x00000000000A4BE0ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC3CDD64540F31F45ULL,
		0x8CE0ECA7F013F076ULL,
		0xD3A5EEA1BF1B2377ULL,
		0x2D05B909EF3A3ECCULL,
		0x83C5A072B8C355FDULL,
		0x1E99963878947038ULL,
		0x41F7190BABC56EA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC04FC1DB0F37591ULL,
		0x6FC6C8DDE3383B29ULL,
		0x7BCE8FB334E97BA8ULL,
		0xAE30D57F4B416E42ULL,
		0x1E251C0E20F1681CULL,
		0xEAF15BA887A6658EULL,
		0x00000000107DC642ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD52FAC4997B0E168ULL,
		0x55629D994F1BA994ULL,
		0xEE040F29AE608783ULL,
		0x3342ECFE6945E766ULL,
		0x4D071193627370FBULL,
		0xDB5D498D14BF1760ULL,
		0xBD340CB95CF6EE9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C6EA65354BEB12ULL,
		0x6B9821E0D558A766ULL,
		0x9A5179D9BB8103CAULL,
		0xD89CDC3ECCD0BB3FULL,
		0x452FC5D81341C464ULL,
		0x573DBBA736D75263ULL,
		0x000000002F4D032EULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1F3A49C237ED1B97ULL,
		0x86A2CB50CE67F997ULL,
		0xA1BE572C181BE9F4ULL,
		0x18B3580A40C132E2ULL,
		0x876EDB0D5BE2FA34ULL,
		0x0E3B5426CDAA577AULL,
		0xA8F34C1B994A365DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86733FCCB8F9D24ULL,
		0x960C0DF4FA435165ULL,
		0x052060997150DF2BULL,
		0x86ADF17D1A0C59ACULL,
		0x1366D52BBD43B76DULL,
		0x0DCCA51B2E871DAAULL,
		0x00000000005479A6ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB4C4223AF7D5DB43ULL,
		0x487E18B31B255A12ULL,
		0xD4870201CADEF7DCULL,
		0x40201650BD421558ULL,
		0x82E8F52300E65281ULL,
		0x05B1C22A622B4A48ULL,
		0x1AEBC8AA3C6DCC9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66364AB425698844ULL,
		0x0395BDEFB890FC31ULL,
		0xA17A842AB1A90E04ULL,
		0x4601CCA50280402CULL,
		0x54C456949105D1EAULL,
		0x5478DB993A0B6384ULL,
		0x000000000035D791ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x14E5D72C814DE978ULL,
		0x73BF23389587C17EULL,
		0x446B5877C75AE4C8ULL,
		0x588A57887850A25BULL,
		0xA4D326157720C305ULL,
		0xD1CFCA2552906F72ULL,
		0x0551DD17015CD3F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F05F853975CB20ULL,
		0xD6B9321CEFC8CE25ULL,
		0x142896D11AD61DF1ULL,
		0xC830C1562295E21EULL,
		0xA41BDCA934C9855DULL,
		0x5734FCF473F28954ULL,
		0x00000001547745C0ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x62D58415597A4FDEULL,
		0x4B0610EA153214C2ULL,
		0x035BF527B40E3E1BULL,
		0xF9C9A7F117F9C71DULL,
		0xC842ED300154DC15ULL,
		0xC1B6D8C1E6C88F8AULL,
		0x61A7EA12BFFAAFF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A854C853098B561ULL,
		0x49ED038F86D2C184ULL,
		0xFC45FE71C740D6FDULL,
		0x4C005537057E7269ULL,
		0x3079B223E2B210BBULL,
		0x84AFFEABFD706DB6ULL,
		0x00000000001869FAULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8AB925C41704F24CULL,
		0xA07A68857E2CB1C1ULL,
		0xC1013E693995CD04ULL,
		0x5456D826950A01DFULL,
		0xAAEC4FC82CDCEFF5ULL,
		0xAFCBAC596B201169ULL,
		0xAADE8590EC9A0221ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C7062AE497105C1ULL,
		0x7341281E9A215F8BULL,
		0x8077F0404F9A4E65ULL,
		0x3BFD5515B609A542ULL,
		0x045A6ABB13F20B37ULL,
		0x80886BF2EB165AC8ULL,
		0x00002AB7A1643B26ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x204F98B4EB0289F2ULL,
		0xA6090F5C533BCD70ULL,
		0xC4276F383B9A9559ULL,
		0xA4879B8C6735B5EAULL,
		0xA931C0C7BC5E9F4FULL,
		0xFD82F2554E16F14BULL,
		0xFB8A48EDC31D1E6CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5C533BCD70204F9ULL,
		0xF383B9A9559A6090ULL,
		0xB8C6735B5EAC4276ULL,
		0x0C7BC5E9F4FA4879ULL,
		0x2554E16F14BA931CULL,
		0x8EDC31D1E6CFD82FULL,
		0x00000000000FB8A4ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6695D9B9390F3184ULL,
		0xFB5B4B74D12E9B91ULL,
		0x3C4D30E99D48F87EULL,
		0x45943A5FBD54F309ULL,
		0x2964EADC2308DB6AULL,
		0x48B4A7C32B7DD933ULL,
		0x54DD170156CBAD72ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A25D3722CD2BB3ULL,
		0xD33A91F0FDF6B696ULL,
		0xBF7AA9E612789A61ULL,
		0xB84611B6D48B2874ULL,
		0x8656FBB26652C9D5ULL,
		0x02AD975AE491694FULL,
		0x0000000000A9BA2EULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4108CAEC15B1AE83ULL,
		0xD65EF63DF73F6784ULL,
		0x60DC4D97460369E3ULL,
		0x741FB88800B2C687ULL,
		0x6D7C17D3CDE2F240ULL,
		0x8DD8EDEA58330E3FULL,
		0x85FAD534FB6F1153ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF73F67844108CAEULL,
		0x7460369E3D65EF63ULL,
		0x800B2C68760DC4D9ULL,
		0x3CDE2F240741FB88ULL,
		0xA58330E3F6D7C17DULL,
		0x4FB6F11538DD8EDEULL,
		0x00000000085FAD53ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5E04039CF2D09B2CULL,
		0x4AC7CC355041F945ULL,
		0x6F653AB862B4DF25ULL,
		0xAAB3BE57D7F93664ULL,
		0x5E79402EF8A1FAC2ULL,
		0x50FCFF7F40FCB6F0ULL,
		0xBF83349A5F3E8C2EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA820FCA2AF0201CULL,
		0xC315A6F92A563E61ULL,
		0xBEBFC9B3237B29D5ULL,
		0x77C50FD615559DF2ULL,
		0xFA07E5B782F3CA01ULL,
		0xD2F9F4617287E7FBULL,
		0x0000000005FC19A4ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEDE86E42AC3F8F0CULL,
		0x8E8E1458C81A55D5ULL,
		0x2D3A48588AD8BB3BULL,
		0xFD67C1BFC99C2098ULL,
		0xC4F364466DBBFFF4ULL,
		0xE48B8099CF8ACF20ULL,
		0x36A144B0B9436694ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D5EDE86E42AC3FULL,
		0xBB3B8E8E1458C81AULL,
		0x20982D3A48588AD8ULL,
		0xFFF4FD67C1BFC99CULL,
		0xCF20C4F364466DBBULL,
		0x6694E48B8099CF8AULL,
		0x000036A144B0B943ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFBE335145CBB5A85ULL,
		0xD02606AFFD5F73D3ULL,
		0x616940A2E9DC27CCULL,
		0x36AC7AD823B54091ULL,
		0x2F1801206A7CA93BULL,
		0x419DE827364FD98BULL,
		0x006BE1D12E55775EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8130357FEAFB9E9FULL,
		0x0B4A05174EE13E66ULL,
		0xB563D6C11DAA048BULL,
		0x78C0090353E549D9ULL,
		0x0CEF4139B27ECC59ULL,
		0x035F0E8972ABBAF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x48351C68CE6A2EC3ULL,
		0x31A00E6A6D6E16E7ULL,
		0xF8A0B2E335D6D7E7ULL,
		0x2512097E142D564BULL,
		0x157884BC2717D640ULL,
		0x6B9726FCB45F88AEULL,
		0xD4A9F58BBEE04CD5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0073536B70B73A4ULL,
		0x5059719AEB6BF398ULL,
		0x8904BF0A16AB25FCULL,
		0xBC425E138BEB2012ULL,
		0xCB937E5A2FC4570AULL,
		0x54FAC5DF70266AB5ULL,
		0x000000000000006AULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAC383954328D2B43ULL,
		0xE3A08536AA93D27EULL,
		0xDE27901D2FEEFB5EULL,
		0x73AC9A518BCCF3FBULL,
		0x3C1531593A01FB85ULL,
		0xC4A496A65945046FULL,
		0x178A31B2564C59E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7410A6D5527A4FDULL,
		0xBC4F203A5FDDF6BDULL,
		0xE75934A31799E7F7ULL,
		0x782A62B27403F70AULL,
		0x89492D4CB28A08DEULL,
		0x2F146364AC98B3CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAA5F3B2B4E8EF39FULL,
		0xFA5FD67D3C27B900ULL,
		0xA58A02D14D8491E5ULL,
		0x843A21968AD0D383ULL,
		0xC71DBB18556147F2ULL,
		0xE72F7267964AEDEBULL,
		0xA74FCDB39F41F16AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA784F720154BE76ULL,
		0xA29B0923CBF4BFACULL,
		0x2D15A1A7074B1405ULL,
		0x30AAC28FE5087443ULL,
		0xCF2C95DBD78E3B76ULL,
		0x673E83E2D5CE5EE4ULL,
		0x00000000014E9F9BULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBA5287D8F4B9D830ULL,
		0xF5E3EE3BC9737493ULL,
		0x4D51B915930E9AC8ULL,
		0x0733E8CCF906FEFBULL,
		0xA0B1AA085ED5BCF3ULL,
		0x2997A580D402A7E3ULL,
		0x9B45DE8EAAB11F74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3BC9737493BA52ULL,
		0xB915930E9AC8F5E3ULL,
		0xE8CCF906FEFB4D51ULL,
		0xAA085ED5BCF30733ULL,
		0xA580D402A7E3A0B1ULL,
		0xDE8EAAB11F742997ULL,
		0x0000000000009B45ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA0CAF0C4B3B9FD95ULL,
		0x708E9FF24B7C2EE6ULL,
		0x78C6CC86317F78DDULL,
		0x97F4F60E9EF4A659ULL,
		0x52136DF77335632DULL,
		0x2EC4DB72BFE7C2D4ULL,
		0xCA6CD00FD852F7C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2EE6A0CAF0C4B3ULL,
		0x7F78DD708E9FF24BULL,
		0xF4A65978C6CC8631ULL,
		0x35632D97F4F60E9EULL,
		0xE7C2D452136DF773ULL,
		0x52F7C62EC4DB72BFULL,
		0x000000CA6CD00FD8ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8447A4A9E13B923CULL,
		0x2FB4C47C9F941DBFULL,
		0x68D822ED5DFE3FCEULL,
		0x8280074478244FC1ULL,
		0x9E1DCC6C823668CEULL,
		0x3A12B556FF046E83ULL,
		0x2214568694C1C4A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF8447A4A9E13B9ULL,
		0xFCE2FB4C47C9F941ULL,
		0xFC168D822ED5DFE3ULL,
		0x8CE8280074478244ULL,
		0xE839E1DCC6C82366ULL,
		0x4A23A12B556FF046ULL,
		0x0002214568694C1CULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC684F7C3C86C5DCEULL,
		0xC584E19FB1434078ULL,
		0xB17C5A99777865C1ULL,
		0xA0D5A1D86B426381ULL,
		0x0C8CD4CF9B9311D1ULL,
		0x5A891C1E8F7FEE75ULL,
		0x3B76F80FD8B6A74AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28680F18D09EF879ULL,
		0xEF0CB838B09C33F6ULL,
		0x684C70362F8B532EULL,
		0x72623A341AB43B0DULL,
		0xEFFDCEA1919A99F3ULL,
		0x16D4E94B512383D1ULL,
		0x000000076EDF01FBULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA55772F7523F81B2ULL,
		0xE4AF0B9DD8743537ULL,
		0x275D1FAB1C8E045FULL,
		0x2B23546D5FEC6109ULL,
		0xE6A659E24829FE5AULL,
		0x13A7538092586497ULL,
		0x2A890A09E5C3B5E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E7761D0D4DE955DULL,
		0x7EAC7238117F92BCULL,
		0x51B57FB184249D74ULL,
		0x678920A7F968AC8DULL,
		0x4E024961925F9A99ULL,
		0x2827970ED79C4E9DULL,
		0x000000000000AA24ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2B30185B7B8FB44CULL,
		0x06501C461E499541ULL,
		0x23BD2DAFE6B52B37ULL,
		0xD601782D4815E05EULL,
		0x115C392803E09E1AULL,
		0x4833E520C977273BULL,
		0xD6752884CC671F2BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3C932A82566030ULL,
		0x5FCD6A566E0CA038ULL,
		0x5A902BC0BC477A5BULL,
		0x5007C13C35AC02F0ULL,
		0x4192EE4E7622B872ULL,
		0x0998CE3E569067CAULL,
		0x0000000001ACEA51ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA4CAC3FA974F731DULL,
		0xE975EF44D087AEB0ULL,
		0x7B4ACADF7D5D5BBDULL,
		0x76B01295504FAFB7ULL,
		0xD7FB4DE2D0AEB535ULL,
		0x66EEEC67E7D01F9CULL,
		0xD0508234720BA61BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BAF7A26843D7585ULL,
		0xDA5656FBEAEADDEFULL,
		0xB58094AA827D7DBBULL,
		0xBFDA6F168575A9ABULL,
		0x3777633F3E80FCE6ULL,
		0x828411A3905D30DBULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFE1FBE41B41FA437ULL,
		0x3265DF4A9180C585ULL,
		0xA9C3D99DCC56E695ULL,
		0x1589DD55D676D528ULL,
		0x9B17D014C84FB7FAULL,
		0xECC15B3B6D939A29ULL,
		0x7C61634156A454F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F87EF906D07E90DULL,
		0x4C9977D2A4603161ULL,
		0x2A70F6677315B9A5ULL,
		0x85627755759DB54AULL,
		0x66C5F4053213EDFEULL,
		0xFB3056CEDB64E68AULL,
		0x1F1858D055A9153CULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x607CEAE226E02F9EULL,
		0xB8C624B64A77106BULL,
		0x25A359C90401BADFULL,
		0xBD91EABF3D5B45EFULL,
		0x62A80DEB4969FF56ULL,
		0xF070A505D9F05FC5ULL,
		0x7858C755953FF450ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x718C496C94EE20D6ULL,
		0x4B46B392080375BFULL,
		0x7B23D57E7AB68BDEULL,
		0xC5501BD692D3FEADULL,
		0xE0E14A0BB3E0BF8AULL,
		0xF0B18EAB2A7FE8A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB83FCCEC686A7371ULL,
		0x253ED5C6333FE63FULL,
		0x3D0165B825F97A5DULL,
		0xB7F9DB660222AC21ULL,
		0x990DA7AE98ADC9BAULL,
		0xA8408EF297117C71ULL,
		0x15A3F59FD3AC5251ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98FEE0FF33B1A1A9ULL,
		0xE97494FB5718CCFFULL,
		0xB084F40596E097E5ULL,
		0x26EADFE76D98088AULL,
		0xF1C664369EBA62B7ULL,
		0x4946A1023BCA5C45ULL,
		0x0000568FD67F4EB1ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC493E39104E07A1BULL,
		0xF744C7B97CF5FA73ULL,
		0x81901644AB14BC6CULL,
		0x7D9CD2DA991AC004ULL,
		0x709B18AFE74BB559ULL,
		0x1FCBC6E0F6974289ULL,
		0x294FAA88F739A1B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E249F1C882703D0ULL,
		0x67BA263DCBE7AFD3ULL,
		0x240C80B22558A5E3ULL,
		0xCBECE696D4C8D600ULL,
		0x4B84D8C57F3A5DAAULL,
		0xB8FE5E3707B4BA14ULL,
		0x014A7D5447B9CD0DULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBA9AA61B0A181873ULL,
		0x860541302DE05DDFULL,
		0x1D907542CAB57E2FULL,
		0xD5DD9F6A88A0973AULL,
		0x6ED78CFF328B5334ULL,
		0x74E517249AF1D986ULL,
		0xFE79F91B3090FE43ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75354C36143030EULL,
		0xF0C0A82605BC0BBBULL,
		0x43B20EA85956AFC5ULL,
		0x9ABBB3ED511412E7ULL,
		0xCDDAF19FE6516A66ULL,
		0x6E9CA2E4935E3B30ULL,
		0x1FCF3F2366121FC8ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDD2D299B8BA58982ULL,
		0x30DE59BC017BEE37ULL,
		0xB852379EE4D9619FULL,
		0xFB898DEB836D4DB8ULL,
		0x20B582EA76A09674ULL,
		0xD2F61569AE3A7987ULL,
		0x6B48545A9E366930ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF74B4A66E2E9626ULL,
		0x7CC37966F005EFB8ULL,
		0xE2E148DE7B936586ULL,
		0xD3EE2637AE0DB536ULL,
		0x1C82D60BA9DA8259ULL,
		0xC34BD855A6B8E9E6ULL,
		0x01AD21516A78D9A4ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB94558B3CC938303ULL,
		0x4039003E9C90BECDULL,
		0xEB8A7B3571DFAD1CULL,
		0xBC89D532FB625ADCULL,
		0x762F38B0CDF576D7ULL,
		0x8B95BF61597FB749ULL,
		0x8503AB3C5F23381CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36E51562CF324E0ULL,
		0x47100E400FA7242FULL,
		0xB73AE29ECD5C77EBULL,
		0xB5EF22754CBED896ULL,
		0xD25D8BCE2C337D5DULL,
		0x0722E56FD8565FEDULL,
		0x002140EACF17C8CEULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x992FA477B7FE396BULL,
		0xE63ABD39F52B87C6ULL,
		0x0100368FE2E10A18ULL,
		0xE016541B41044343ULL,
		0x23F2F4CAA79BE4EBULL,
		0xD7077CD513660B97ULL,
		0x09381B5244CFB5BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F8D325F48EF6FFULL,
		0x21431CC757A73EA5ULL,
		0x8868602006D1FC5CULL,
		0x7C9D7C02CA836820ULL,
		0xC172E47E5E9954F3ULL,
		0xF6B7BAE0EF9AA26CULL,
		0x00000127036A4899ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC8BD323A23008C81ULL,
		0xA72D58A12026578CULL,
		0x8E84C50D4CA76C65ULL,
		0xE98B9D5A3648FB66ULL,
		0x182EC8BC62D92099ULL,
		0xA1E59683F979858EULL,
		0xEEE3ADA2876C8066ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x396AC5090132BC66ULL,
		0x7426286A653B632DULL,
		0x4C5CEAD1B247DB34ULL,
		0xC17645E316C904CFULL,
		0x0F2CB41FCBCC2C70ULL,
		0x771D6D143B640335ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD5A0FD5C7BDEA575ULL,
		0xDA57586934DF1719ULL,
		0x060A6BE7F352BC5DULL,
		0xF1CD1EC467FB87BCULL,
		0x70F4249FD3C79A1FULL,
		0x7E7364A533FCA3B3ULL,
		0x30574A4C4C219377ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BE2E33AB41FAB8ULL,
		0xE6A578BBB4AEB0D2ULL,
		0xCFF70F780C14D7CFULL,
		0xA78F343FE39A3D88ULL,
		0x67F94766E1E8493FULL,
		0x984326EEFCE6C94AULL,
		0x0000000060AE9498ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1E41D3888D2E0640ULL,
		0x6D84AFBCE82F6102ULL,
		0xFBD88C1E9207CE4DULL,
		0xADF54DD28970F2E5ULL,
		0x45940476A3E30FF6ULL,
		0xA6BAF00C0AF168B9ULL,
		0x50314D6C96699C36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE82F61021E41D388ULL,
		0x9207CE4D6D84AFBCULL,
		0x8970F2E5FBD88C1EULL,
		0xA3E30FF6ADF54DD2ULL,
		0x0AF168B945940476ULL,
		0x96699C36A6BAF00CULL,
		0x0000000050314D6CULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD7C6D6F23CFBF43FULL,
		0x9718D3CD890CE190ULL,
		0x4AD1675772DBFBD5ULL,
		0xCC9F33AF3284E2D4ULL,
		0xBFC2B0311B005A9CULL,
		0x0112183FE54FB9ECULL,
		0xBA465A5DC7168759ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3386435F1B5BC8F3ULL,
		0x6FEF565C634F3624ULL,
		0x138B512B459D5DCBULL,
		0x016A73327CCEBCCAULL,
		0x3EE7B2FF0AC0C46CULL,
		0x5A1D64044860FF95ULL,
		0x000002E91969771CULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA5666791CB2696C5ULL,
		0xC9A90B7889FF3DA4ULL,
		0x8EBAD5207139CCB8ULL,
		0x959101C510922D9FULL,
		0xA55994510E49BB85ULL,
		0x732606C4795C6AE2ULL,
		0x1A38A81E445E8B10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC44FF9ED252B333ULL,
		0x90389CE65C64D485ULL,
		0xE2884916CFC75D6AULL,
		0x288724DDC2CAC880ULL,
		0x623CAE357152ACCAULL,
		0x0F222F4588399303ULL,
		0x00000000000D1C54ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x380C5DBC8A0D53E3ULL,
		0x9784DC8C4F49FC36ULL,
		0xE6CE55907C58C775ULL,
		0x9DD5B71250EA37F5ULL,
		0xBCAD870F60E06E20ULL,
		0xDEEB91B0CCA97089ULL,
		0x7D301CE57D0B8CD9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36380C5DBC8A0D53ULL,
		0x759784DC8C4F49FCULL,
		0xF5E6CE55907C58C7ULL,
		0x209DD5B71250EA37ULL,
		0x89BCAD870F60E06EULL,
		0xD9DEEB91B0CCA970ULL,
		0x007D301CE57D0B8CULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x698DC80DE902D30CULL,
		0x4D1A9789021A9D51ULL,
		0x6CB5EE2FBADBBBCAULL,
		0x4647871FDE15B72BULL,
		0x8FF5C9A11342E390ULL,
		0x40BC1B8D5BAC04CDULL,
		0xF744737E5CF6B875ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x086A7545A6372037ULL,
		0xEB6EEF29346A5E24ULL,
		0x7856DCADB2D7B8BEULL,
		0x4D0B8E41191E1C7FULL,
		0x6EB013363FD72684ULL,
		0x73DAE1D502F06E35ULL,
		0x00000003DD11CDF9ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x61F5E483306215CAULL,
		0x6B1FF665986436A0ULL,
		0x125EF26A9360813CULL,
		0x0737F2D47C5A9042ULL,
		0x62E2B873ED08EBE0ULL,
		0xDABF267C8D2B8ACBULL,
		0x5E5CE99499D8492FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C3EBC90660C42BULL,
		0x78D63FECCB30C86DULL,
		0x8424BDE4D526C102ULL,
		0xC00E6FE5A8F8B520ULL,
		0x96C5C570E7DA11D7ULL,
		0x5FB57E4CF91A5715ULL,
		0x00BCB9D32933B092ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4EDB54743B8849EEULL,
		0x0C7FF8534E57ED7AULL,
		0x641D58010D8FF01AULL,
		0x27952A31296AAAB8ULL,
		0x5BCC70180BE432D6ULL,
		0x80ACF4845E4C6F25ULL,
		0x8099168CED575B24ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A72BF6BD276DAA3ULL,
		0x086C7F80D063FFC2ULL,
		0x894B5555C320EAC0ULL,
		0xC05F2196B13CA951ULL,
		0x22F263792ADE6380ULL,
		0x676ABAD9240567A4ULL,
		0x000000000404C8B4ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0F0122008C90CEC3ULL,
		0x6549B0EDE6E2C909ULL,
		0xA7D306F787052626ULL,
		0xE9583805334279E1ULL,
		0x83DB1A81131EB8BDULL,
		0xDEF2B15EC9F55CE7ULL,
		0xA9BB4DC8C1859072ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121E02440119219DULL,
		0x4CCA9361DBCDC592ULL,
		0xC34FA60DEF0E0A4CULL,
		0x7BD2B0700A6684F3ULL,
		0xCF07B63502263D71ULL,
		0xE5BDE562BD93EAB9ULL,
		0x0153769B91830B20ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5627F22D8F7FEA2BULL,
		0xE955DC2F2392BB85ULL,
		0x915927924DC740F8ULL,
		0xE419FC5E49FD0BB9ULL,
		0xDA75D694EDA80432ULL,
		0xAB94B6F0A74F0163ULL,
		0x37ABB3676CA15223ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E4AEE15589FC8BULL,
		0x9371D03E3A55770BULL,
		0x927F42EE645649E4ULL,
		0x3B6A010CB9067F17ULL,
		0x29D3C058F69D75A5ULL,
		0xDB285488EAE52DBCULL,
		0x000000000DEAECD9ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4517FF726DCEE7B9ULL,
		0xF890AD541CD61F6BULL,
		0x50B64659BCFDA367ULL,
		0x46B02C5510AA008FULL,
		0x4BC55D74B4F565B2ULL,
		0x4B9284426A8D0675ULL,
		0xC80109FF3CEBF09BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FB5A28BFFB936E7ULL,
		0xD1B3FC4856AA0E6BULL,
		0x0047A85B232CDE7EULL,
		0xB2D92358162A8855ULL,
		0x833AA5E2AEBA5A7AULL,
		0xF84DA5C942213546ULL,
		0x0000640084FF9E75ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6DB78DE8BC454071ULL,
		0xBCBCF71E9A6AE5E4ULL,
		0xCD77F0E23034E9F8ULL,
		0x1A542E2D31A83F72ULL,
		0x60DD95AAAA8CC2D4ULL,
		0x492EF73995DB43F4ULL,
		0xC2061D057732A220ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9A6AE5E46DB78DULL,
		0xE23034E9F8BCBCF7ULL,
		0x2D31A83F72CD77F0ULL,
		0xAAAA8CC2D41A542EULL,
		0x3995DB43F460DD95ULL,
		0x057732A220492EF7ULL,
		0x0000000000C2061DULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1CA9EAE15A67A67CULL,
		0x2A88884C5DE6E946ULL,
		0x9A420EE5867E90BBULL,
		0x8EE7266FC5619A71ULL,
		0x7DD28FF6C6FBDEB2ULL,
		0x685495D25F189747ULL,
		0xCAA1F7BD7A5D3D21ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5DE6E9461CA9EAEULL,
		0x5867E90BB2A88884ULL,
		0xFC5619A719A420EEULL,
		0x6C6FBDEB28EE7266ULL,
		0x25F1897477DD28FFULL,
		0xD7A5D3D21685495DULL,
		0x000000000CAA1F7BULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0808BFF86C892382ULL,
		0x941D35A62B05EE45ULL,
		0x46B65A41313B0015ULL,
		0x0C6F775B64BBBD57ULL,
		0x70FEF7BE0D1E0477ULL,
		0x8B06FB78C043A76BULL,
		0x60CBE4290D2B678AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10117FF0D912470ULL,
		0xB283A6B4C560BDC8ULL,
		0xE8D6CB4826276002ULL,
		0xE18DEEEB6C9777AAULL,
		0x6E1FDEF7C1A3C08EULL,
		0x5160DF6F180874EDULL,
		0x0C197C8521A56CF1ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x99A6289D8AC5FF9CULL,
		0xCFBCC0C05305FB62ULL,
		0x136E19C15197AB56ULL,
		0xDD0D49BB0824DF6DULL,
		0x91A9ABEA46E8B07DULL,
		0x834FAB76232EE65CULL,
		0xE1E7DEF4B224200CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299A6289D8AC5FF9ULL,
		0x6CFBCC0C05305FB6ULL,
		0xD136E19C15197AB5ULL,
		0xDDD0D49BB0824DF6ULL,
		0xC91A9ABEA46E8B07ULL,
		0xC834FAB76232EE65ULL,
		0x0E1E7DEF4B224200ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x74CD8A83CD588D51ULL,
		0xD34FA0AD51422CCDULL,
		0xBE6032198CBFC5A2ULL,
		0x0D87C2EF16F8AEE4ULL,
		0xCD057A1579CDD03DULL,
		0x8051405D7CF550AFULL,
		0x854B2A3499333558ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x599AE99B15079AB1ULL,
		0x8B45A69F415AA284ULL,
		0x5DC97CC06433197FULL,
		0xA07A1B0F85DE2DF1ULL,
		0xA15F9A0AF42AF39BULL,
		0x6AB100A280BAF9EAULL,
		0x00010A9654693266ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBBCF69D18829C85CULL,
		0x755291A21056B0CEULL,
		0x0F5614758E1FC563ULL,
		0xF0CFC0B6438DE264ULL,
		0xC9DD904557BE1D29ULL,
		0x6979388EBC8088B7ULL,
		0x78056E51EC3A780EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B58675DE7B4E8CULL,
		0x70FE2B1BAA948D10ULL,
		0x1C6F13207AB0A3ACULL,
		0xBDF0E94F867E05B2ULL,
		0xE40445BE4EEC822AULL,
		0x61D3C0734BC9C475ULL,
		0x00000003C02B728FULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x623AD1D82C115EC7ULL,
		0xBBB11B574D0BC2A0ULL,
		0x591D3040402F3038ULL,
		0xD2E91B43CE89D0DBULL,
		0xD6D681F9AB15B262ULL,
		0x49931ECEBCB63154ULL,
		0x8759A8AEC13BA1AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0BC2A0623AD1D82ULL,
		0x02F3038BBB11B574ULL,
		0xE89D0DB591D30404ULL,
		0xB15B262D2E91B43CULL,
		0xCB63154D6D681F9AULL,
		0x13BA1AE49931ECEBULL,
		0x00000008759A8AECULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF6E3C953BCE287E1ULL,
		0x5E656F055A10AAECULL,
		0x185B95F544052174ULL,
		0x5AA2F06D93DA719AULL,
		0x257EEF7EBCB529DAULL,
		0x230718B52ADAACE8ULL,
		0xC4D7F1C6E150B22AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCCADE0AB42155D9ULL,
		0x30B72BEA880A42E8ULL,
		0xB545E0DB27B4E334ULL,
		0x4AFDDEFD796A53B4ULL,
		0x460E316A55B559D0ULL,
		0x89AFE38DC2A16454ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xDC92F1F68D6F5B16ULL,
		0xDAE7AFCC28DEDA7EULL,
		0x1868A0464E980138ULL,
		0xECF9EA271DB5DCDEULL,
		0x00E4A53ED5CF1E3CULL,
		0x3774B3B81584DF45ULL,
		0x8C315FEFF5285FB1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDB4FDB925E3ED1ULL,
		0xD300271B5CF5F985ULL,
		0xB6BB9BC30D1408C9ULL,
		0xB9E3C79D9F3D44E3ULL,
		0xB09BE8A01C94A7DAULL,
		0xA50BF626EE967702ULL,
		0x00000011862BFDFEULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5356A2A2988C5B30ULL,
		0xB7F383D20FF44171ULL,
		0xE3D201903787E0C2ULL,
		0x4B54642108DB7727ULL,
		0x668FB2CA907ADB9AULL,
		0x471FF393040E99B9ULL,
		0xE1A11FC766EAB325ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCE0F483FD105C54ULL,
		0xF480640DE1F830ADULL,
		0xD519084236DDC9F8ULL,
		0xA3ECB2A41EB6E692ULL,
		0xC7FCE4C103A66E59ULL,
		0x6847F1D9BAACC951ULL,
		0x0000000000000038ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x396A369CC96048DFULL,
		0x530FF781DC324E77ULL,
		0xCC00EB165DF024DDULL,
		0xC373F3BD52E4F1E4ULL,
		0xDAF1BC0738DCD02EULL,
		0xFBD61924427238FCULL,
		0xF3444EA7C0D4B54CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE0770C939DCE5AULL,
		0x3AC5977C093754C3ULL,
		0xFCEF54B93C793300ULL,
		0x6F01CE37340BB0DCULL,
		0x8649109C8E3F36BCULL,
		0x13A9F0352D533EF5ULL,
		0x0000000000003CD1ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x491A318F87F819C3ULL,
		0x6CE8B18594B823D3ULL,
		0x3EFF7546F69C2EB2ULL,
		0x9D767C615649DF4FULL,
		0x1A5A0FE73F2A1425ULL,
		0xE2F0437D946F933CULL,
		0xBA5D0F51B3CC5B14ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2C61652E08F4D24ULL,
		0xFDD51BDA70BAC9B3ULL,
		0xD9F18559277D3CFBULL,
		0x683F9CFCA8509675ULL,
		0xC10DF651BE4CF069ULL,
		0x743D46CF316C538BULL,
		0x00000000000002E9ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x319B062F596EAB77ULL,
		0xA7F7DF7057693819ULL,
		0x597314FE5F93CF74ULL,
		0xA0457E3EAE7C7AEAULL,
		0x9DE4A7DED68E5189ULL,
		0x60A51758206CB286ULL,
		0x63FB5187DCA54EB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819319B062F596EAULL,
		0xF74A7F7DF7057693ULL,
		0xAEA597314FE5F93CULL,
		0x189A0457E3EAE7C7ULL,
		0x2869DE4A7DED68E5ULL,
		0xEB460A51758206CBULL,
		0x00063FB5187DCA54ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF74DCF42B335EBA2ULL,
		0xE6B7EBE9386676C8ULL,
		0xD68180C10FC80B18ULL,
		0x03EFA7C3D5612455ULL,
		0x2FA67D9E21D4F128ULL,
		0x562244DE24BCF589ULL,
		0x42C661D126243651ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C333B647BA6E7AULL,
		0x087E4058C735BF5FULL,
		0x1EAB0922AEB40C06ULL,
		0xF10EA789401F7D3EULL,
		0xF125E7AC497D33ECULL,
		0x893121B28AB11226ULL,
		0x000000000216330EULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF558F997B1F1C4CEULL,
		0xFD64200216834E89ULL,
		0xBA051E21BEFBEA67ULL,
		0x8878222E9C8EC7F9ULL,
		0x14FFF4ACD83DEF36ULL,
		0x02DC551267F9DE6EULL,
		0xCC8BA7F3E56C0B8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0042D069D13EAB1FULL,
		0xC437DF7D4CFFAC84ULL,
		0x45D391D8FF3740A3ULL,
		0x959B07BDE6D10F04ULL,
		0xA24CFF3BCDC29FFEULL,
		0xFE7CAD8171405B8AULL,
		0x0000000000199174ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x48A09D4990C9F73CULL,
		0x7CB323D625DC8CF9ULL,
		0x112EE0B8D066058BULL,
		0x645F8160CCB692E7ULL,
		0xA4199A173D9A7DDCULL,
		0x64BECDF489C8654CULL,
		0x759C3C4805268AA1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12EE467CA4504EA4ULL,
		0x683302C5BE5991EBULL,
		0x665B49738897705CULL,
		0x9ECD3EEE322FC0B0ULL,
		0x44E432A6520CCD0BULL,
		0x02934550B25F66FAULL,
		0x000000003ACE1E24ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCBA6B1C90AEB1F36ULL,
		0x73DBE86AFB35F1A0ULL,
		0xA40E44CA34F881C3ULL,
		0x118FE36D26741ECFULL,
		0xA7A35D8336F57E04ULL,
		0x594754863B43D230ULL,
		0x42E772C40422D8F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35F1A0CBA6B1C90AULL,
		0xF881C373DBE86AFBULL,
		0x741ECFA40E44CA34ULL,
		0xF57E04118FE36D26ULL,
		0x43D230A7A35D8336ULL,
		0x22D8F1594754863BULL,
		0x00000042E772C404ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8645359164CA892AULL,
		0x976CDB60F5DFB3D9ULL,
		0x93748174D21FB8CBULL,
		0xD9F4C17AAF78E78AULL,
		0xE7AA2461F810F7F4ULL,
		0x2BC1D1EED0089F2EULL,
		0x381D355940A5DC47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CDB60F5DFB3D986ULL,
		0x748174D21FB8CB97ULL,
		0xF4C17AAF78E78A93ULL,
		0xAA2461F810F7F4D9ULL,
		0xC1D1EED0089F2EE7ULL,
		0x1D355940A5DC472BULL,
		0x0000000000000038ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x97C34848DB4E5933ULL,
		0x9B975045E162AE3AULL,
		0xD82477B7F798ECAEULL,
		0x4CC1CFC66B9E3E15ULL,
		0xC809CDA0AD61725EULL,
		0x1F02A34FC40DD281ULL,
		0x4875DC7D8C8F5604ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC55C752F869091B6ULL,
		0x31D95D372EA08BC2ULL,
		0x3C7C2BB048EF6FEFULL,
		0xC2E4BC99839F8CD7ULL,
		0x1BA50390139B415AULL,
		0x1EAC083E05469F88ULL,
		0x00000090EBB8FB19ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF63C2D708A3B083DULL,
		0xC410730181493349ULL,
		0xE666C2BF246C8FE2ULL,
		0x6BF898B5F9455D8FULL,
		0xD28BB208707E9B7AULL,
		0x1BE77902F46E9EBBULL,
		0x8B264A842B73E797ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA499A4FB1E16B845ULL,
		0x3647F162083980C0ULL,
		0xA2AEC7F333615F92ULL,
		0x3F4DBD35FC4C5AFCULL,
		0x374F5DE945D90438ULL,
		0xB9F3CB8DF3BC817AULL,
		0x0000004593254215ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x64856DF204F4FEC6ULL,
		0xBA70DB4F3266A350ULL,
		0xBC9F48E8EE295BC0ULL,
		0xE3F4B767B53EAF72ULL,
		0x3C1811FA49DB4CEDULL,
		0x04C450BE140472FEULL,
		0x92DEA3F2DF7E88CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86DA7993351A8324ULL,
		0xFA4747714ADE05D3ULL,
		0xA5BB3DA9F57B95E4ULL,
		0xC08FD24EDA676F1FULL,
		0x2285F0A02397F1E0ULL,
		0xF51F96FBF4467026ULL,
		0x0000000000000496ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB9DC65BEC97CE9BAULL,
		0xB81A599319F9B9B5ULL,
		0xEE9F1E79E834A827ULL,
		0xD2756E19CC4D7F5CULL,
		0x9BDE96208176792AULL,
		0x69109CAB599EC9A8ULL,
		0xCE46E3A101A20253ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9DC65BEC97CE9BULL,
		0x7B81A599319F9B9BULL,
		0xCEE9F1E79E834A82ULL,
		0xAD2756E19CC4D7F5ULL,
		0x89BDE96208176792ULL,
		0x369109CAB599EC9AULL,
		0x0CE46E3A101A2025ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6A219C122563EA9CULL,
		0x433342812DF50B2AULL,
		0x9F1E441966A8A300ULL,
		0x7749D7852FC25FD0ULL,
		0x8E2494F8DD254FC7ULL,
		0x64D15F47E65859E2ULL,
		0x7F1EC1248B626B67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD0A04B7D42CA9AULL,
		0xC7910659AA28C010ULL,
		0xD275E14BF097F427ULL,
		0x89253E374953F1DDULL,
		0x3457D1F9961678A3ULL,
		0xC7B04922D89AD9D9ULL,
		0x000000000000001FULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x315E84901E1094F4ULL,
		0x14815B1E80E7C07BULL,
		0x3E65EF32B420616BULL,
		0xC66003A258EE5784ULL,
		0xA2AE1D6475D27F8AULL,
		0xDC6A87B8B3BF75D3ULL,
		0x5446A71633A1940BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4073E03D98AF42ULL,
		0x995A1030B58A40ADULL,
		0xD12C772BC21F32F7ULL,
		0xB23AE93FC5633001ULL,
		0xDC59DFBAE9D1570EULL,
		0x8B19D0CA05EE3543ULL,
		0x00000000002A2353ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x740A19196F762996ULL,
		0x734020E69822A6BFULL,
		0x445B8D16E1CD3467ULL,
		0x321CA8A7D655396FULL,
		0xD75CC3B908014684ULL,
		0x5EC05AA6EBBF970AULL,
		0x2B5D206B82A5E52BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBA050C8CB7BB14CULL,
		0x3B9A010734C11535ULL,
		0x7A22DC68B70E69A3ULL,
		0x2190E5453EB2A9CBULL,
		0x56BAE61DC8400A34ULL,
		0x5AF602D5375DFCB8ULL,
		0x015AE9035C152F29ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0622CA8D66417AD8ULL,
		0x0195AB6E869950EDULL,
		0x8DF746CB2D0B5FC7ULL,
		0xCA8ACA4F08FBA7D6ULL,
		0x2EC9E879A544E9CCULL,
		0x87792840838A88BAULL,
		0x115BFC556FCCE941ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87683116546B320ULL,
		0xAFE380CAD5B7434CULL,
		0xD3EB46FBA3659685ULL,
		0x74E665456527847DULL,
		0x445D1764F43CD2A2ULL,
		0x74A0C3BC942041C5ULL,
		0x000008ADFE2AB7E6ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x038AAE074839D50DULL,
		0x01A57DDF26F337E2ULL,
		0x1ABDE0D6896B2993ULL,
		0x3F70074B5CE21D1FULL,
		0x5752F8D18F1E3769ULL,
		0xC0DD1E602F80B0AFULL,
		0x629AB1BC79D92C57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99BF101C55703A41ULL,
		0x594C980D2BEEF937ULL,
		0x10E8F8D5EF06B44BULL,
		0xF1BB49FB803A5AE7ULL,
		0x05857ABA97C68C78ULL,
		0xC962BE06E8F3017CULL,
		0x00000314D58DE3CEULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6556CA59463D5B2EULL,
		0xB85E63983FCF2AAAULL,
		0xEF01D6AF12441F5FULL,
		0x85F960ACECA29CE4ULL,
		0x28BEE8531AA0A194ULL,
		0x413698F39562190FULL,
		0x1F985443CE5CA254ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E60FF3CAAA9955ULL,
		0x75ABC49107D7EE17ULL,
		0x582B3B28A7393BC0ULL,
		0xBA14C6A82865217EULL,
		0xA63CE5588643CA2FULL,
		0x1510F3972895104DULL,
		0x00000000000007E6ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x426EC4DBE56BDDFEULL,
		0xD738F14B31A13809ULL,
		0x4FD642F80C243BA2ULL,
		0x4B1627ECFAB3FBA6ULL,
		0xF5520B783C71F150ULL,
		0x84802E97E400482CULL,
		0x2CFCB5FE22BDCD35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA137626DF2B5EEFFULL,
		0x6B9C78A598D09C04ULL,
		0x27EB217C06121DD1ULL,
		0x258B13F67D59FDD3ULL,
		0x7AA905BC1E38F8A8ULL,
		0xC240174BF2002416ULL,
		0x167E5AFF115EE69AULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5CD30DCFF5558735ULL,
		0x2AF37FA3809BB37BULL,
		0xD0067808EC231CA7ULL,
		0x3D1A8BC6797F6680ULL,
		0xACC1ABCA16798A78ULL,
		0xB3EA43C76F331918ULL,
		0x8571C983DFAB08C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9BDAE6986E7FAAULL,
		0x18E539579BFD1C04ULL,
		0xFB34068033C04761ULL,
		0xCC53C1E8D45E33CBULL,
		0x98C8C5660D5E50B3ULL,
		0x5846459F521E3B79ULL,
		0x0000042B8E4C1EFDULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x131BA6EA12A58AB9ULL,
		0x0D1B6D59022C943AULL,
		0x673B6C10297483B2ULL,
		0x12738D2C8DF6A732ULL,
		0x661E521B9862B544ULL,
		0x6C9D8CF293B29BEDULL,
		0xFACB0F0F02FC3E17ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DAB204592874263ULL,
		0x6D82052E907641A3ULL,
		0x71A591BED4E64CE7ULL,
		0xCA43730C56A8824EULL,
		0xB19E5276537DACC3ULL,
		0x61E1E05F87C2ED93ULL,
		0x0000000000001F59ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD864AAFC76F17A2DULL,
		0xDA009E2F9B72FFCFULL,
		0x8180719B259C2B59ULL,
		0x064E3B69A4D939A4ULL,
		0xF5B569557AA80DC7ULL,
		0xF131A18B48D2A971ULL,
		0x0AB077A03A8E8E5FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FB0C955F8EDE2FULL,
		0x6B3B4013C5F36E5FULL,
		0x3490300E3364B385ULL,
		0xB8E0C9C76D349B27ULL,
		0x2E3EB6AD2AAF5501ULL,
		0xCBFE263431691A55ULL,
		0x0001560EF40751D1ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB4F4ACEAE795EEBAULL,
		0xE0AC120B2B5FC82DULL,
		0xDA90221BA210552AULL,
		0xB08AA8FD68C176A2ULL,
		0x5C3EFA3C3BAD351EULL,
		0x7F2E358ECE80AEBCULL,
		0x40EF62CE0BA992F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC82DB4F4ACEAE79ULL,
		0x0552AE0AC120B2B5ULL,
		0x176A2DA90221BA21ULL,
		0xD351EB08AA8FD68CULL,
		0x0AEBC5C3EFA3C3BAULL,
		0x992F67F2E358ECE8ULL,
		0x0000040EF62CE0BAULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC55C8629F447BC1CULL,
		0xF8400435AAD6CBFEULL,
		0x9C9ADBC5FDF08B66ULL,
		0x2CED038EAEEADAD0ULL,
		0xE30604DC0E3CB099ULL,
		0x22FC99F7A195E5F8ULL,
		0xD382DB446340E5F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD56B65FF62AE43ULL,
		0xE2FEF845B37C2002ULL,
		0xC757756D684E4D6DULL,
		0x6E071E584C967681ULL,
		0xFBD0CAF2FC718302ULL,
		0xA231A072FC917E4CULL,
		0x000000000069C16DULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x004A692944319CE6ULL,
		0x0E75268473681F38ULL,
		0x5BF6CAA1700A9359ULL,
		0xCD9FC7D14B3DE922ULL,
		0x57C1A3C5BF49610FULL,
		0x520CECA5DB5A59FBULL,
		0xE57D3CA3433D3907ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDA07CE00129A4A5ULL,
		0xC02A4D6439D49A11ULL,
		0x2CF7A4896FDB2A85ULL,
		0xFD25843F367F1F45ULL,
		0x6D6967ED5F068F16ULL,
		0x0CF4E41D4833B297ULL,
		0x0000000395F4F28DULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE6B6DC74F2876842ULL,
		0x8A7F9E47AF69C96EULL,
		0x80C2B80509149722ULL,
		0x6F5E149ABF0888D8ULL,
		0x15AA594F69967464ULL,
		0x2C65138A3F3049D4ULL,
		0x12CB8885894CA79FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B6DC74F2876842ULL,
		0x8A7F9E47AF69C96EULL,
		0x80C2B80509149722ULL,
		0x6F5E149ABF0888D8ULL,
		0x15AA594F69967464ULL,
		0x2C65138A3F3049D4ULL,
		0x12CB8885894CA79FULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8FE5DBC3D73E3BC4ULL,
		0x7D2EF446374C4151ULL,
		0x2992DDAB7D0A7E81ULL,
		0x0B4A5AC2C4090B72ULL,
		0xB28A9C70D40C1281ULL,
		0x6B4348FE916825AFULL,
		0xFCA0024C378B2AB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE88C6E9882A31FCULL,
		0x5BB56FA14FD02FA5ULL,
		0x4B585881216E4532ULL,
		0x538E1A8182502169ULL,
		0x691FD22D04B5F651ULL,
		0x004986F16556AD68ULL,
		0x0000000000001F94ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD7B6978B69868E05ULL,
		0xB2BFEFEF3AB8C874ULL,
		0x201A6701DD4E8B88ULL,
		0xF992DB06D61AC3B2ULL,
		0xAB5209944A2BCED2ULL,
		0x3BD917FEDAEDEBCDULL,
		0xE896DE3BA9DF310CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9AF6D2F16D30D1CULL,
		0x11657FDFDE757190ULL,
		0x644034CE03BA9D17ULL,
		0xA5F325B60DAC3587ULL,
		0x9B56A4132894579DULL,
		0x1877B22FFDB5DBD7ULL,
		0x01D12DBC7753BE62ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7C3E1B8AD6A863E9ULL,
		0x84786EDDF3707AC0ULL,
		0xD3E020E20551DA33ULL,
		0xD9B6348EFD87482AULL,
		0xD3AE2A108583B4E4ULL,
		0x97CB6A885E400DF1ULL,
		0x36B8B623BDA4BD07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDBBE6E0F580F87ULL,
		0x041C40AA3B46708FULL,
		0xC691DFB0E9055A7CULL,
		0xC54210B0769C9B36ULL,
		0x6D510BC801BE3A75ULL,
		0x16C477B497A0F2F9ULL,
		0x00000000000006D7ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xFE139C402B8FDF2DULL,
		0x59F4AB553F1D3E8CULL,
		0xE4150E307B50B60AULL,
		0x726C5A306484AD57ULL,
		0xDA9BF710C83246C1ULL,
		0x9E5FAE19A59E8734ULL,
		0xDDA3939D3B8F4EBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AA7E3A7D19FC27ULL,
		0x1C60F6A16C14B3E9ULL,
		0xB460C9095AAFC82AULL,
		0xEE2190648D82E4D8ULL,
		0x5C334B3D0E69B537ULL,
		0x273A771E9D793CBFULL,
		0x000000000001BB47ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF6BC0A5F4F8E0CA9ULL,
		0x7D303A3E2AB967DDULL,
		0xF920C78490B316FAULL,
		0x511EBA5AE6E70863ULL,
		0x23B240B368EE0653ULL,
		0xA4423B23F8DD890BULL,
		0x0984BDFBC063B949ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB967DDF6BC0A5F4ULL,
		0x0B316FA7D303A3E2ULL,
		0x6E70863F920C7849ULL,
		0x8EE0653511EBA5AEULL,
		0x8DD890B23B240B36ULL,
		0x063B949A4423B23FULL,
		0x00000000984BDFBCULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x24AF1368DAF1C183ULL,
		0x8483897A90108A82ULL,
		0xC46DC028CAF662CDULL,
		0xF59B816A0790EBABULL,
		0x9B0453460A256374ULL,
		0xDA7C422E9304425CULL,
		0x542282D5AB8E26EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211504495E26D1B5ULL,
		0xECC59B090712F520ULL,
		0x21D75788DB805195ULL,
		0x4AC6E9EB3702D40FULL,
		0x0884B93608A68C14ULL,
		0x1C4DDFB4F8845D26ULL,
		0x000000A84505AB57ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBB936B8A7D5D585AULL,
		0x431732BA270AF061ULL,
		0x5614C476BD58F99AULL,
		0x4D49E32A76E5CD35ULL,
		0x6F9F2FA02E548B0CULL,
		0x197D3390D64C8517ULL,
		0xD9C27493E0D892BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BC186EE4DAE29FULL,
		0x563E6690C5CCAE89ULL,
		0xB9734D5585311DAFULL,
		0x9522C3135278CA9DULL,
		0x932145DBE7CBE80BULL,
		0x3624AF065F4CE435ULL,
		0x00000036709D24F8ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCC2602ADEBEE4734ULL,
		0xBDF23623E486D040ULL,
		0xC7FBCE8F10042CA9ULL,
		0x5D46F1E710B97EF5ULL,
		0xFD1FD67881300A49ULL,
		0xB3B2562AD025B546ULL,
		0x1C416E803852D8B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF23623E486D040CULL,
		0x7FBCE8F10042CA9BULL,
		0xD46F1E710B97EF5CULL,
		0xD1FD67881300A495ULL,
		0x3B2562AD025B546FULL,
		0xC416E803852D8B1BULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE964DBAF5500CE4BULL,
		0xBF2A4185EBF12BF0ULL,
		0x82BD206519ADF4A4ULL,
		0x16CA0CE6F062EBE1ULL,
		0x12FEECC06976B89DULL,
		0x6E8338497D4897B7ULL,
		0xB2B2979D44872B3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7E257E1D2C9B75EULL,
		0x335BE9497E54830BULL,
		0xE0C5D7C3057A40CAULL,
		0xD2ED713A2D9419CDULL,
		0xFA912F6E25FDD980ULL,
		0x890E5676DD067092ULL,
		0x0000000165652F3AULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3ED78A1D3B97CCF8ULL,
		0x7F88257FAA8148E5ULL,
		0xB179CF34F91CC644ULL,
		0xE641E1086B2B05ADULL,
		0xDC63907F63EB0945ULL,
		0x26E7FC3E041B453EULL,
		0x47070ACF3A0F40B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FAA8148E53ED78ULL,
		0xF34F91CC6447F882ULL,
		0x1086B2B05ADB179CULL,
		0x07F63EB0945E641EULL,
		0xC3E041B453EDC639ULL,
		0xACF3A0F40B526E7FULL,
		0x0000000000047070ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x42505899CD629A3AULL,
		0x7C80D8759CF457F9ULL,
		0x187A964405704DE2ULL,
		0x43832F9B41F5BC1FULL,
		0x46E2144A04B08227ULL,
		0xCE754F6842C897C5ULL,
		0x2F91511CF82372B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB39E8AFF284A0B1ULL,
		0x880AE09BC4F901B0ULL,
		0x3683EB783E30F52CULL,
		0x940961044E87065FULL,
		0xD085912F8A8DC428ULL,
		0x39F046E56F9CEA9EULL,
		0x00000000005F22A2ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA15303296720B5A4ULL,
		0xF5FFB2EA2826F83CULL,
		0x7D4A92B204D7C582ULL,
		0x9F075E3178832E49ULL,
		0xDCD6569D9A6275FEULL,
		0x2195FF5B4B2806D0ULL,
		0x78C63718DA56FCEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA8A09BE0F2854C0ULL,
		0xAC8135F160BD7FECULL,
		0x8C5E20CB925F52A4ULL,
		0xA766989D7FA7C1D7ULL,
		0xD6D2CA01B4373595ULL,
		0xC63695BF3A88657FULL,
		0x00000000001E318DULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCF5D39C8C3A0D248ULL,
		0x1E3DAD454A7584E3ULL,
		0x8E23529B80E4D7A8ULL,
		0xA1F9B835AE3F8B36ULL,
		0x0E875768EFBC9F2FULL,
		0xFD5F5BF09BAB1297ULL,
		0x1FB149E7674D56D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B5A8A94EB09C79ULL,
		0xC46A53701C9AF503ULL,
		0x3F3706B5C7F166D1ULL,
		0xD0EAED1DF793E5F4ULL,
		0xABEB7E13756252E1ULL,
		0xF6293CECE9AADADFULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE30B75469B901138ULL,
		0xFE56E7EABC8A0AC4ULL,
		0x35DB817298FFF851ULL,
		0x2F1F3B868A54DFDAULL,
		0x3CD5E8595B0889FDULL,
		0xED7F97B736D20E0AULL,
		0x9320F55BFB10568AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2282B138C2DD51A6ULL,
		0x3FFE147F95B9FAAFULL,
		0x9537F68D76E05CA6ULL,
		0xC2227F4BC7CEE1A2ULL,
		0xB483828F357A1656ULL,
		0xC415A2BB5FE5EDCDULL,
		0x00000024C83D56FEULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x83CF50CB9E2C35BAULL,
		0x878B788C7CE6C099ULL,
		0xB2E29750648F6F6FULL,
		0xB3F2CD3F36476013ULL,
		0x7E0030333B1689F2ULL,
		0xF192F5EEBE4AC6DDULL,
		0x413A8CF180D45316ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE231F39B02660F3ULL,
		0xA5D41923DBDBE1E2ULL,
		0xB34FCD91D804ECB8ULL,
		0x0C0CCEC5A27CACFCULL,
		0xBD7BAF92B1B75F80ULL,
		0xA33C603514C5BC64ULL,
		0x000000000000104EULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA34DF6D7DFEB0DE8ULL,
		0x50086F3302B3E85EULL,
		0xE39E4BB5D299DA32ULL,
		0xD37A4ABC63A76204ULL,
		0xE70E2E0A988A5398ULL,
		0x730A7107CB98E479ULL,
		0x8CB0DA34B480ECF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF51A6FB6BEFF586FULL,
		0x9280437998159F42ULL,
		0x271CF25DAE94CED1ULL,
		0xC69BD255E31D3B10ULL,
		0xCF38717054C4529CULL,
		0xA39853883E5CC723ULL,
		0x046586D1A5A40767ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x36E7B525A719147AULL,
		0xB2EFD06C160436B2ULL,
		0xF24658C35EAC590AULL,
		0x38B4C568063914D4ULL,
		0x6577DAD8A633A391ULL,
		0xC81DA92C8651B4BEULL,
		0xA93D566B157A5F02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAC8DB9ED4969C64ULL,
		0x642ACBBF41B05810ULL,
		0x5353C919630D7AB1ULL,
		0x8E44E2D315A018E4ULL,
		0xD2F995DF6B6298CEULL,
		0x7C0B2076A4B21946ULL,
		0x0002A4F559AC55E9ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8E2CF13B83F651E0ULL,
		0x0D422DC5B0ADDF99ULL,
		0x10573B8AECC708F5ULL,
		0x10056A4BCE3253C0ULL,
		0x82A3F78BB4F169ACULL,
		0xFABC21F458D66387ULL,
		0x77B898C36D27F2BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF998E2CF13B83F65ULL,
		0x8F50D422DC5B0ADDULL,
		0x3C010573B8AECC70ULL,
		0x9AC10056A4BCE325ULL,
		0x38782A3F78BB4F16ULL,
		0x2BCFABC21F458D66ULL,
		0x00077B898C36D27FULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x6567EB46D0A1446FULL,
		0xCFF7DC3A7A0940CEULL,
		0xAAA84DF3190F874CULL,
		0x4B40685EB51C2D12ULL,
		0x89336408C1B3DC39ULL,
		0x03FD6E97D6091337ULL,
		0xA9F80AFA49C2E10FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0339959FAD1B4285ULL,
		0x1D333FDF70E9E825ULL,
		0xB44AAAA137CC643EULL,
		0x70E52D01A17AD470ULL,
		0x4CDE24CD902306CFULL,
		0x843C0FF5BA5F5824ULL,
		0x0002A7E02BE9270BULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x08866E4CDD6EA341ULL,
		0x1FB9622019F42FA9ULL,
		0x1EA794231B0BC0C0ULL,
		0xFA6DEDECCF31CA6FULL,
		0xD7A9C60D07349E92ULL,
		0x3E07113A7D4805DCULL,
		0x85F97B8BCF8D5908ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F72C44033E85F52ULL,
		0x3D4F284636178180ULL,
		0xF4DBDBD99E6394DEULL,
		0xAF538C1A0E693D25ULL,
		0x7C0E2274FA900BB9ULL,
		0x0BF2F7179F1AB210ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x716FD817193C9C53ULL,
		0x05DF240405153C84ULL,
		0xB45F2D430CF109D0ULL,
		0xF3F978D41C8B73C9ULL,
		0x9FC85B8D615E882FULL,
		0x8BBA676D2F88D7CBULL,
		0x1C3633CFE42217EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC90101454F211C5BULL,
		0xCB50C33C42740177ULL,
		0x5E350722DCF26D17ULL,
		0x16E35857A20BFCFEULL,
		0x99DB4BE235F2E7F2ULL,
		0x8CF3F90885FAE2EEULL,
		0x000000000000070DULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA33AAECF0CDE3955ULL,
		0xC742B06B3B4AF607ULL,
		0x798ED641FD027953ULL,
		0x7C1E684C5FA247C0ULL,
		0x3A69EA4181A1F123ULL,
		0xB3F614D8303E03A0ULL,
		0x4A679AE8E1D82687ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33AAECF0CDE3955ULL,
		0xC742B06B3B4AF607ULL,
		0x798ED641FD027953ULL,
		0x7C1E684C5FA247C0ULL,
		0x3A69EA4181A1F123ULL,
		0xB3F614D8303E03A0ULL,
		0x4A679AE8E1D82687ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3A7989F52587539CULL,
		0x02DAA9C52E0B846DULL,
		0xD053A4F226B0416DULL,
		0xBCCEFEDD85048B90ULL,
		0x3432AFF4BE688841ULL,
		0xF2F6501EC9396211ULL,
		0xA19F5B2B051180BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E0B846D3A7989F5ULL,
		0x26B0416D02DAA9C5ULL,
		0x85048B90D053A4F2ULL,
		0xBE688841BCCEFEDDULL,
		0xC93962113432AFF4ULL,
		0x051180BEF2F6501EULL,
		0x00000000A19F5B2BULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x925BAF3A161E5BF7ULL,
		0x6DA2CA86DB244E28ULL,
		0xA2CEBD04A28C822FULL,
		0xCD9605248EE547D3ULL,
		0xAAB3DA892DF5B81CULL,
		0x99BECFD0DFF6E40CULL,
		0x04DA3B2B54B5A3B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA2CA86DB244E289ULL,
		0x2CEBD04A28C822F6ULL,
		0xD9605248EE547D3AULL,
		0xAB3DA892DF5B81CCULL,
		0x9BECFD0DFF6E40CAULL,
		0x4DA3B2B54B5A3B39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4A16D77CE45C6011ULL,
		0xA10360ED3EE99630ULL,
		0x391F2669C1E2AD82ULL,
		0x8C9E9F06E2D50794ULL,
		0x0A271356D7277589ULL,
		0x83C5FC4C1D1D63A0ULL,
		0x1DF48D8B9B560C50ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB18250B6BBE722EULL,
		0x56C15081B0769F74ULL,
		0x83CA1C8F9334E0F1ULL,
		0xBAC4C64F4F83716AULL,
		0xB1D0051389AB6B93ULL,
		0x062841E2FE260E8EULL,
		0x00000EFA46C5CDABULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1F24A72BBE6C7F8EULL,
		0xA9CF2DF284020D33ULL,
		0xA9D92E0941746469ULL,
		0x40F45797E00D7E9EULL,
		0x9C1D9AE67916AAEEULL,
		0xD20AFD43F1BEF0EAULL,
		0x2A25168D5A69B603ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E494E577CD8FF1ULL,
		0x3539E5BE508041A6ULL,
		0xD53B25C1282E8C8DULL,
		0xC81E8AF2FC01AFD3ULL,
		0x5383B35CCF22D55DULL,
		0x7A415FA87E37DE1DULL,
		0x0544A2D1AB4D36C0ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x875841C24A906BE6ULL,
		0xA6CBE1EDDF9DE128ULL,
		0x73D7CDCDB7B5334FULL,
		0xC06D13BAD09CCFDAULL,
		0x1D96C3725FA93535ULL,
		0x0501E3D2BD41F9FCULL,
		0xC154B4AEEB5AE77AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC2510EB0838495ULL,
		0x6A669F4D97C3DBBFULL,
		0x399FB4E7AF9B9B6FULL,
		0x526A6B80DA2775A1ULL,
		0x83F3F83B2D86E4BFULL,
		0xB5CEF40A03C7A57AULL,
		0x00000182A9695DD6ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBD125BDE01480776ULL,
		0xB47460156C9A275DULL,
		0xA0FC226571BC5842ULL,
		0x9C787179E581EA0AULL,
		0xE104B0F4D6A790C9ULL,
		0x41C6CE0F49240E42ULL,
		0x9D2FDDBD18A2AE60ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7A24B7BC02900EULL,
		0x8568E8C02AD9344EULL,
		0x1541F844CAE378B0ULL,
		0x9338F0E2F3CB03D4ULL,
		0x85C20961E9AD4F21ULL,
		0xC0838D9C1E92481CULL,
		0x013A5FBB7A31455CULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD7AA425D1CF56971ULL,
		0x63C19E4C70CF046AULL,
		0x46D73A7191E9FD57ULL,
		0x4A7A161F8429C4E7ULL,
		0xC25043BF27C6241EULL,
		0xFEFE99E22D14169BULL,
		0xBB7BB303EC3E2E32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33C11AB5EA90974ULL,
		0x47A7F55D8F067931ULL,
		0x10A7139D1B5CE9C6ULL,
		0x9F18907929E8587EULL,
		0xB4505A6F09410EFCULL,
		0xB0F8B8CBFBFA6788ULL,
		0x00000002EDEECC0FULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA24CDD097B50C4A8ULL,
		0xE61A9855AA25A344ULL,
		0xCD7289FD037B0989ULL,
		0x85C4897A52FB87D9ULL,
		0xE3A15B7CBC491B62ULL,
		0x05E6345D5D5B7BEFULL,
		0x6CBEC662D824E6CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x251266E84BDA8625ULL,
		0x4F30D4C2AD512D1AULL,
		0xCE6B944FE81BD84CULL,
		0x142E244BD297DC3EULL,
		0x7F1D0ADBE5E248DBULL,
		0x682F31A2EAEADBDFULL,
		0x0365F63316C12736ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x97665F2C97005C80ULL,
		0x6D20F2743E465143ULL,
		0x1F8ED5E6AA4DA0E7ULL,
		0x6B8B0FADF3A5863AULL,
		0x5025CE03AAFABA3FULL,
		0x42781D10C8203632ULL,
		0xE5DEF407A72BA8DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90793A1F2328A1CBULL,
		0xC76AF35526D073B6ULL,
		0xC587D6F9D2C31D0FULL,
		0x12E701D57D5D1FB5ULL,
		0x3C0E8864101B1928ULL,
		0xEF7A03D395D46EA1ULL,
		0x0000000000000072ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5B43ADC76771F97CULL,
		0x84BAD5AC8C190FFBULL,
		0x7F1789F5914E11D3ULL,
		0x0CF5064D3CB8D86BULL,
		0x95109344ABCD929EULL,
		0x84343C0ED13BCE6BULL,
		0x5842CC9BF9C83628ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12EB56B230643FEDULL,
		0xFC5E27D64538474EULL,
		0x33D41934F2E361ADULL,
		0x54424D12AF364A78ULL,
		0x10D0F03B44EF39AEULL,
		0x610B326FE720D8A2ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE6B81E18395A5AE2ULL,
		0x2F5066A4C21A2977ULL,
		0xE40314ABCB80DAD9ULL,
		0xD20C7C6B5DCF8525ULL,
		0x53772B483C082895ULL,
		0x716012100203E4A4ULL,
		0x3580B0A0E3647E4AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA930868A5DF9AE07ULL,
		0x2AF2E036B64BD419ULL,
		0x1AD773E1497900C5ULL,
		0xD20F020A2574831FULL,
		0x840080F92914DDCAULL,
		0x2838D91F929C5804ULL,
		0x00000000000D602CULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7248417B900D54F1ULL,
		0xE3450A674FA1DAEFULL,
		0x27F75642F2750AA8ULL,
		0xFE70EAA953283E16ULL,
		0xC70150C8AAEC716BULL,
		0xFEBD1E622F5BA25DULL,
		0x359303C58E59B901ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF7248417B900D54ULL,
		0xA8E3450A674FA1DAULL,
		0x1627F75642F2750AULL,
		0x6BFE70EAA953283EULL,
		0x5DC70150C8AAEC71ULL,
		0x01FEBD1E622F5BA2ULL,
		0x00359303C58E59B9ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x67390C69CD716E1FULL,
		0xCE01A96D08726CAEULL,
		0xDD31863DDC52830EULL,
		0xB50370D6E0DD956DULL,
		0x405650832B449E67ULL,
		0xE48AD0366A2C0776ULL,
		0x60EE01F596B9A3CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7339C8634E6B8B70ULL,
		0x76700D4B68439365ULL,
		0x6EE98C31EEE29418ULL,
		0x3DA81B86B706ECABULL,
		0xB202B284195A24F3ULL,
		0x57245681B351603BULL,
		0x0307700FACB5CD1EULL,
		0x0000000000000000ULL
	}};
	shift = 5;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8FF3FACEB79410BBULL,
		0xB9BDC46A506D7F5BULL,
		0x67F7DBBFB723BFD4ULL,
		0xA79229C754E3EE80ULL,
		0x0B0871F1F7F6172FULL,
		0xD1C1E857B0A34886ULL,
		0x6E82AFA65CA9BB1BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB71FE7F59D6F2821ULL,
		0xA9737B88D4A0DAFEULL,
		0x00CFEFB77F6E477FULL,
		0x5F4F24538EA9C7DDULL,
		0x0C1610E3E3EFEC2EULL,
		0x37A383D0AF614691ULL,
		0x00DD055F4CB95376ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x372D4798FAC0E63CULL,
		0x34D151BF57C03738ULL,
		0x37820AE147774BACULL,
		0x95B28ACDA29E6EBBULL,
		0xF5AA0E21FB6519C9ULL,
		0x0C35B05F745048F4ULL,
		0x013F6DD96E287ADFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF806E706E5A8F31FULL,
		0xEEE975869A2A37EAULL,
		0x53CDD766F0415C28ULL,
		0x6CA33932B65159B4ULL,
		0x8A091E9EB541C43FULL,
		0xC50F5BE186B60BEEULL,
		0x0000000027EDBB2DULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x142F0C281B4AC031ULL,
		0x53B377D48A87A056ULL,
		0x7FA9240285123009ULL,
		0x3FF3E29FC404F2C2ULL,
		0x495A539D998B485FULL,
		0x968F33D6B66B9DC6ULL,
		0xBD79B161ED7C3522ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A056142F0C281B4ULL,
		0x2300953B377D48A8ULL,
		0x4F2C27FA92402851ULL,
		0xB485F3FF3E29FC40ULL,
		0xB9DC6495A539D998ULL,
		0xC3522968F33D6B66ULL,
		0x00000BD79B161ED7ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7FDD92BBFD452920ULL,
		0x7EFAB8633D7E27D3ULL,
		0xA0EE3F12A48A557DULL,
		0x2229F16AE37722F4ULL,
		0x53FA05C756298CA6ULL,
		0x3A92B6DA464AFE0DULL,
		0xC8BAEDC7FA821F54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13E9BFEEC95DFEA2ULL,
		0x2ABEBF7D5C319EBFULL,
		0x917A50771F895245ULL,
		0xC6531114F8B571BBULL,
		0x7F06A9FD02E3AB14ULL,
		0x0FAA1D495B6D2325ULL,
		0x0000645D76E3FD41ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x88219013622D2AA3ULL,
		0x3645E7DE988BC797ULL,
		0xDA7747066FC46181ULL,
		0xECE510234F4D4DD6ULL,
		0x85FDD5EE3BBBDC9AULL,
		0x8FBBBA3BD0F04C13ULL,
		0xD5D83FFB1F08BCC8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C45E3CBC410C809ULL,
		0x37E230C09B22F3EFULL,
		0xA7A6A6EB6D3BA383ULL,
		0x1DDDEE4D76728811ULL,
		0xE8782609C2FEEAF7ULL,
		0x8F845E6447DDDD1DULL,
		0x000000006AEC1FFDULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x960404AFF3DE3294ULL,
		0x105FD26419BE0B64ULL,
		0x7918B1F540861732ULL,
		0x88C0E1A8DE320A85ULL,
		0xCB2DA66BFA9AE744ULL,
		0x02BEAF0460810743ULL,
		0xF45BCC462CC398B2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B24B020257F9EF1ULL,
		0xB99082FE9320CDF0ULL,
		0x542BC8C58FAA0430ULL,
		0x3A2446070D46F190ULL,
		0x3A1E596D335FD4D7ULL,
		0xC59015F578230408ULL,
		0x0007A2DE6231661CULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA2C80C05ABDE10B5ULL,
		0xFF4BFD758C35102CULL,
		0x00AB1C1553D472DBULL,
		0xF7EA9E9EB2CD4500ULL,
		0x28F36066A7ED3F3AULL,
		0x79B6880A9AAFEB76ULL,
		0x7EB87D9FF53B5181ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB186A20594590180ULL,
		0xAA7A8E5B7FE97FAEULL,
		0xD659A8A000156382ULL,
		0xD4FDA7E75EFD53D3ULL,
		0x5355FD6EC51E6C0CULL,
		0xFEA76A302F36D101ULL,
		0x000000000FD70FB3ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x48A45B14091F5DD5ULL,
		0xEB02ED99D7B20A40ULL,
		0x1CB46175330874BAULL,
		0xE33C9BAA8A13790AULL,
		0xBF433F59F4F981B2ULL,
		0x79E5CC768AE6EA8EULL,
		0x1CDDC9FDA1DB93C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0BB6675EC82901ULL,
		0x72D185D4CC21D2EBULL,
		0x8CF26EAA284DE428ULL,
		0xFD0CFD67D3E606CBULL,
		0xE79731DA2B9BAA3AULL,
		0x737727F6876E4F19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7C4EEB5F80C69388ULL,
		0x2AEEC7CFF421348CULL,
		0x876B39FE37A1DDDBULL,
		0x21AD9FB608D6F0FBULL,
		0x61A97084C9E6D87FULL,
		0x7CADF913C567BC90ULL,
		0xE6CB864F43E771AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFF421348C7C4EEULL,
		0x9FE37A1DDDB2AEECULL,
		0xFB608D6F0FB876B3ULL,
		0x084C9E6D87F21AD9ULL,
		0x913C567BC9061A97ULL,
		0x64F43E771AF7CADFULL,
		0x00000000000E6CB8ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xAABBE99CD079DD28ULL,
		0x1582CA4F70FE1DCCULL,
		0x8FC19BC3B5069F6CULL,
		0xEBE0329C5856B3F0ULL,
		0x5C2B9F69B584DEA3ULL,
		0x02F8DCB777FB9314ULL,
		0x3B9C45A837F5AC09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FE1DCCAABBE99CULL,
		0xB5069F6C1582CA4FULL,
		0x5856B3F08FC19BC3ULL,
		0xB584DEA3EBE0329CULL,
		0x77FB93145C2B9F69ULL,
		0x37F5AC0902F8DCB7ULL,
		0x000000003B9C45A8ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3163932160476CDDULL,
		0x3E2C7903657774A1ULL,
		0x21D698F41BF248E0ULL,
		0x658F497ACC1D70DDULL,
		0xA7AE13FD51AF2D1BULL,
		0x30395FCF2B80E1F1ULL,
		0x267EE1445B70D255ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903657774A131639ULL,
		0x8F41BF248E03E2C7ULL,
		0x97ACC1D70DD21D69ULL,
		0x3FD51AF2D1B658F4ULL,
		0xFCF2B80E1F1A7AE1ULL,
		0x1445B70D25530395ULL,
		0x00000000000267EEULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x873C4DBBC15CB40BULL,
		0x4AC3A4BC8270F6F4ULL,
		0x87F57CBEF2C36D85ULL,
		0xB6D54C05581ABE86ULL,
		0x61F438ADD362D1A4ULL,
		0xDB5A78D9A1A9A6F3ULL,
		0x76CE478AB48FE213ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E41387B7A439E26ULL,
		0x5F7961B6C2A561D2ULL,
		0x02AC0D5F4343FABEULL,
		0x56E9B168D25B6AA6ULL,
		0x6CD0D4D379B0FA1CULL,
		0xC55A47F109EDAD3CULL,
		0x00000000003B6723ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x2CE2A4C0018F2115ULL,
		0xDCD30C46F6F825B4ULL,
		0xF7A4BF27BCAF8FE6ULL,
		0x03B14C02810860CEULL,
		0x589B71BBF2525F47ULL,
		0x471B12B82D01F032ULL,
		0xA03E0B49D07B62BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D0B38A9300063CULL,
		0x3F9B734C311BDBE0ULL,
		0x833BDE92FC9EF2BEULL,
		0x7D1C0EC5300A0421ULL,
		0xC0C9626DC6EFC949ULL,
		0x8AF91C6C4AE0B407ULL,
		0x000280F82D2741EDULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE1287341C4DC4044ULL,
		0xA1D239D837A9F58EULL,
		0x5822477A0D3FC628ULL,
		0xD129539AF885FB89ULL,
		0x341A678A34F35472ULL,
		0x5245777AB0771488ULL,
		0xF2F35C06721CA26CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE1287341C4DC40ULL,
		0x28A1D239D837A9F5ULL,
		0x895822477A0D3FC6ULL,
		0x72D129539AF885FBULL,
		0x88341A678A34F354ULL,
		0x6C5245777AB07714ULL,
		0x00F2F35C06721CA2ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBD08A7F0D4C0CD82ULL,
		0x412E7FDF41A3EB46ULL,
		0x7ED247952D350BA4ULL,
		0x949CF5F0CE1DDA4DULL,
		0x60B9AF511E8B7E07ULL,
		0xF8E59B603DCE3433ULL,
		0x29D077CA67356BCBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAD1AF4229FC3530ULL,
		0x42E9104B9FF7D068ULL,
		0x76935FB491E54B4DULL,
		0xDF81E5273D7C3387ULL,
		0x8D0CD82E6BD447A2ULL,
		0x5AF2FE3966D80F73ULL,
		0x00000A741DF299CDULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1F007F18DC8A3430ULL,
		0x72E5551C32AEA1A1ULL,
		0x7328AA80CF8CF4CEULL,
		0x3E11D499C23563FCULL,
		0x0BEB1A72AB12943DULL,
		0x477D50A336969091ULL,
		0x670FB91A2991315EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA86847C01FC637ULL,
		0xE33D339CB955470CULL,
		0x8D58FF1CCA2AA033ULL,
		0xC4A50F4F84752670ULL,
		0xA5A42442FAC69CAAULL,
		0x644C5791DF5428CDULL,
		0x00000019C3EE468AULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x52446B4DF2433CA5ULL,
		0x443239F4716D45C4ULL,
		0x0EF0312D82AA0E1FULL,
		0x3DCB8F3DEC594607ULL,
		0x2BD859AF922A208BULL,
		0xCAD685C997D0CF7FULL,
		0xCE59FFCD3B2D7995ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716D45C452446B4DULL,
		0x82AA0E1F443239F4ULL,
		0xEC5946070EF0312DULL,
		0x922A208B3DCB8F3DULL,
		0x97D0CF7F2BD859AFULL,
		0x3B2D7995CAD685C9ULL,
		0x00000000CE59FFCDULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x16047398748AA142ULL,
		0xE162AAFE2F5DF215ULL,
		0x921185C12A09EC1DULL,
		0xAA07DD64B18633ACULL,
		0x130272BC9417A94BULL,
		0x25A0D0F61711CD74ULL,
		0x948EC4A7F0FF0F35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE42A2C08E730E915ULL,
		0xD83BC2C555FC5EBBULL,
		0x675924230B825413ULL,
		0x5297540FBAC9630CULL,
		0x9AE82604E579282FULL,
		0x1E6A4B41A1EC2E23ULL,
		0x0001291D894FE1FEULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7863C4FEE92C775DULL,
		0x200A769F304B5DABULL,
		0xE10BDB08BA2618E4ULL,
		0x508E9C9BD64E42F0ULL,
		0x4BE28D615BFFF506ULL,
		0xFDE745BB4FD28508ULL,
		0x87EEB8439FF027C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA7CC12D76ADE18ULL,
		0xF6C22E8986390802ULL,
		0xA726F59390BC3842ULL,
		0xA35856FFFD419423ULL,
		0xD16ED3F4A14212F8ULL,
		0xAE10E7FC09F0BF79ULL,
		0x00000000000021FBULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5EFF4696C0360813ULL,
		0x673AB423757B1DE0ULL,
		0x3727EE6F490E89EBULL,
		0x41C721AA1EFCB3DBULL,
		0x7430B9C02641B558ULL,
		0x7589D3B56B437D59ULL,
		0xE05341E6A0B3C7B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7FA34B601B0409ULL,
		0xB39D5A11BABD8EF0ULL,
		0x9B93F737A48744F5ULL,
		0x20E390D50F7E59EDULL,
		0xBA185CE01320DAACULL,
		0xBAC4E9DAB5A1BEACULL,
		0x7029A0F35059E3D9ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x142AE0B840935D8BULL,
		0xE6D6A22B43E4E76BULL,
		0xE5BCB88D670974DCULL,
		0x4B59B22AC817390AULL,
		0x8DB395BA4C606B91ULL,
		0x8B6F11AE1BBB3293ULL,
		0xE1F5402D28685CCBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x687C9CED62855C17ULL,
		0xACE12E9B9CDAD445ULL,
		0x5902E7215CB79711ULL,
		0x498C0D72296B3645ULL,
		0xC377665271B672B7ULL,
		0xA50D0B99716DE235ULL,
		0x000000001C3EA805ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8FA7116E1D7F1782ULL,
		0x5F2B08AE02390904ULL,
		0x4799BA4C85B265ADULL,
		0xDBF69EAE5372923BULL,
		0xE913153F4AE5F2AFULL,
		0xBFC563D208BEB6BCULL,
		0x2265B1F9B0B838D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC047212091F4E22DULL,
		0x90B64CB5ABE56115ULL,
		0xCA6E524768F33749ULL,
		0xE95CBE55FB7ED3D5ULL,
		0x4117D6D79D2262A7ULL,
		0x3617071AD7F8AC7AULL,
		0x00000000044CB63FULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC2887E8BB2EE53EDULL,
		0x4FD2E545C78786F1ULL,
		0x96A5CCE5BB608847ULL,
		0x12A78616E36DCBF1ULL,
		0x55CD620B2CFF59A4ULL,
		0xDF382C3A7DB64311ULL,
		0xBEE078F1A42CA165ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1C2887E8BB2EE5ULL,
		0x8474FD2E545C7878ULL,
		0xBF196A5CCE5BB608ULL,
		0x9A412A78616E36DCULL,
		0x31155CD620B2CFF5ULL,
		0x165DF382C3A7DB64ULL,
		0x000BEE078F1A42CAULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xF9B3D08BB54666F2ULL,
		0x3023B4560075DD04ULL,
		0x290D1F671B521CF1ULL,
		0x0CCFC4D33F62A75DULL,
		0x4D40312046CE5E3EULL,
		0x29FADC07B9941496ULL,
		0x73E3F071B750CD71ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC00EBBA09F367A1ULL,
		0xCE36A439E2604768ULL,
		0xA67EC54EBA521A3EULL,
		0x408D9CBC7C199F89ULL,
		0x0F7328292C9A8062ULL,
		0xE36EA19AE253F5B8ULL,
		0x0000000000E7C7E0ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC6FBC33E5A141ECDULL,
		0xC6FB9E0F57718CFEULL,
		0x730323672C0A40AFULL,
		0xBA0B1469463A4C96ULL,
		0xB0A41672E382253DULL,
		0xFB1D9A8F0E1A7439ULL,
		0x035F9B93776CEF83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEE783D5DC633FB1ULL,
		0xC0C8D9CB02902BF1ULL,
		0x82C51A518E93259CULL,
		0x29059CB8E0894F6EULL,
		0xC766A3C3869D0E6CULL,
		0xD7E6E4DDDB3BE0FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x74CA70F6D134E612ULL,
		0x7CB1345484CA2880ULL,
		0xE39F29A090CB5077ULL,
		0xA77F97543335F72CULL,
		0xEB9C8FF036B7DBADULL,
		0x721FD6E94C44AD9EULL,
		0xBDE1C713ADC1A837ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5484CA288074CA70ULL,
		0xA090CB50777CB134ULL,
		0x543335F72CE39F29ULL,
		0xF036B7DBADA77F97ULL,
		0xE94C44AD9EEB9C8FULL,
		0x13ADC1A837721FD6ULL,
		0x0000000000BDE1C7ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x63E7BCB1004329A8ULL,
		0x31958D89951DE459ULL,
		0x542CE70C3A208C65ULL,
		0xEA636D9831F49EE3ULL,
		0x16330B2E79608ADFULL,
		0x88E60C18285FF7C6ULL,
		0x2A249B0B6F03EB06ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x547791658F9EF2C4ULL,
		0xE8823194C6563626ULL,
		0xC7D27B8D50B39C30ULL,
		0xE5822B7FA98DB660ULL,
		0xA17FDF1858CC2CB9ULL,
		0xBC0FAC1A23983060ULL,
		0x00000000A8926C2DULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x07B7FD46BF31FC2EULL,
		0xE9040A7EDDB5D198ULL,
		0x81D5C6B14CB5A2E6ULL,
		0xA6672E164E1107E6ULL,
		0x13F41E1A3DE00951ULL,
		0x4243971E9AB9E01AULL,
		0x06DA00A964086F33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FB76D746601EDFULL,
		0x1AC532D68B9BA410ULL,
		0xB85938441F9A0757ULL,
		0x7868F7802546999CULL,
		0x5C7A6AE780684FD0ULL,
		0x02A59021BCCD090EULL,
		0x0000000000001B68ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x44F644A0A6C36122ULL,
		0xD3D3B87E4A544208ULL,
		0x42E8E529AC3D3FE4ULL,
		0x2C09B01CDA972C27ULL,
		0xED0399A0ACED3E5AULL,
		0x9AB03E4D21FD3E75ULL,
		0xA40842752CE243E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1089EC89414D86C2ULL,
		0xC9A7A770FC94A884ULL,
		0x4E85D1CA53587A7FULL,
		0xB458136039B52E58ULL,
		0xEBDA07334159DA7CULL,
		0xCF35607C9A43FA7CULL,
		0x01481084EA59C487ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x55FCB6DDC423DF66ULL,
		0x7B4B349F4E985BE1ULL,
		0x363EF661343DF3FCULL,
		0x6D8FAC6C338C2A27ULL,
		0xAA45B4AAAFBB22D4ULL,
		0xFAC5C67A879F2676ULL,
		0x26604C42910943D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6693E9D30B7C2ABFULL,
		0xDECC2687BE7F8F69ULL,
		0xF58D86718544E6C7ULL,
		0xB69555F7645A8DB1ULL,
		0xB8CF50F3E4CED548ULL,
		0x09885221287A3F58ULL,
		0x00000000000004CCULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x067C12F8C2CFE1BFULL,
		0x68F5E14E01CA0C9EULL,
		0x4F93F94A16DCCEAAULL,
		0xB741CDDE74F13309ULL,
		0x47F838C9BE20D96DULL,
		0x621035AF687E2777ULL,
		0x632464311DE27228ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE01CA0C9E067C12FULL,
		0xA16DCCEAA68F5E14ULL,
		0xE74F133094F93F94ULL,
		0x9BE20D96DB741CDDULL,
		0xF687E277747F838CULL,
		0x11DE27228621035AULL,
		0x0000000006324643ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD7B498A63571A783ULL,
		0x59B4D1417DB2B2A1ULL,
		0x6D9903702B28E1FBULL,
		0x75D192F4301B76CAULL,
		0xDC6351905A9A7BD4ULL,
		0x2F9062809A476A24ULL,
		0x2EAE6B9594FA5B23ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34505F6CACA875EDULL,
		0x40DC0ACA387ED66DULL,
		0x64BD0C06DDB29B66ULL,
		0xD46416A69EF51D74ULL,
		0x18A02691DA893718ULL,
		0x9AE5653E96C8CBE4ULL,
		0x0000000000000BABULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x58348C81DFE7705BULL,
		0x8C96179DB0420C23ULL,
		0x1D4D4865200B0924ULL,
		0xF8010A03D923AB93ULL,
		0x98E6FFD4A24610C5ULL,
		0x6420E0FF74028596ULL,
		0xCADDD3DB27C72D9AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79DB0420C2358348ULL,
		0x865200B09248C961ULL,
		0xA03D923AB931D4D4ULL,
		0xFD4A24610C5F8010ULL,
		0x0FF7402859698E6FULL,
		0x3DB27C72D9A6420EULL,
		0x00000000000CADDDULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xB0B631B3DE48623CULL,
		0x0398B031AC011124ULL,
		0x71D497B2BF9E9A00ULL,
		0x69BC328827AC33F8ULL,
		0xF5A0F160E4BF4140ULL,
		0x7957479DE6BE6FD9ULL,
		0xC54238BDF9D78FDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC011124B0B631BULL,
		0x2BF9E9A000398B03ULL,
		0x827AC33F871D497BULL,
		0x0E4BF414069BC328ULL,
		0xDE6BE6FD9F5A0F16ULL,
		0xDF9D78FDE7957479ULL,
		0x000000000C54238BULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0321F99A2062D8BCULL,
		0x0DBC05B8E167E1E5ULL,
		0x40E09F47E2FE6D6DULL,
		0x06AED155F5CF8472ULL,
		0x03DF32501039463FULL,
		0xA5AE771CF60BD1AFULL,
		0x51FFE3A7C6DC3911ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B8E167E1E50321ULL,
		0x9F47E2FE6D6D0DBCULL,
		0xD155F5CF847240E0ULL,
		0x32501039463F06AEULL,
		0x771CF60BD1AF03DFULL,
		0xE3A7C6DC3911A5AEULL,
		0x00000000000051FFULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1C9E1C0B9F59A594ULL,
		0x8691732E77E51F41ULL,
		0x21F222FC6C15D033ULL,
		0xED81D0022733B2CBULL,
		0x82EDC7F758DDCB0FULL,
		0xAE8A1AC0DAA5B2C0ULL,
		0x4D5E5FF3897B04C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x691732E77E51F411ULL,
		0x1F222FC6C15D0338ULL,
		0xD81D0022733B2CB2ULL,
		0x2EDC7F758DDCB0FEULL,
		0xE8A1AC0DAA5B2C08ULL,
		0xD5E5FF3897B04C5AULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC4E99E896818BCB6ULL,
		0xE2AAFE7AACDEA227ULL,
		0x6AB7973BA3EDF531ULL,
		0x5E65696C2B526A1DULL,
		0x83E9503EC90494E6ULL,
		0x5083D868C5BCF5E9ULL,
		0x2BE92ED5A15AFB59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF89D33D12D031796ULL,
		0x3C555FCF559BD444ULL,
		0xAD56F2E7747DBEA6ULL,
		0xCBCCAD2D856A4D43ULL,
		0x307D2A07D920929CULL,
		0x2A107B0D18B79EBDULL,
		0x057D25DAB42B5F6BULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7D17B2EB4369F87DULL,
		0xC74B46F5C4285B7BULL,
		0x49C8F1CF030E3C85ULL,
		0xC4D44BD76BD6A1D2ULL,
		0x30407CC50D021FFFULL,
		0xCF77BE9BA8AE6A57ULL,
		0xEF8B21E4C58761E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B6F6FA2F65D686DULL,
		0xC790B8E968DEB885ULL,
		0xD43A49391E39E061ULL,
		0x43FFF89A897AED7AULL,
		0xCD4AE6080F98A1A0ULL,
		0xEC3C19EEF7D37515ULL,
		0x00001DF1643C98B0ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3C69F6FA7A2537D1ULL,
		0x32C4ED6B8AB23A45ULL,
		0xFD23EEC7BAB149E1ULL,
		0x399537AEDF1CBDA2ULL,
		0xF5359737818EDE9AULL,
		0xC66EEAFF5EA4DAF3ULL,
		0x5D188583C54FB679ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DAD71564748A78ULL,
		0x47DD8F756293C265ULL,
		0x2A6F5DBE397B45FAULL,
		0x6B2E6F031DBD3473ULL,
		0xDDD5FEBD49B5E7EAULL,
		0x310B078A9F6CF38CULL,
		0x00000000000000BAULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0A08EB5B14751D73ULL,
		0x3D4018A8DF1A3397ULL,
		0x26004066C1A27F6EULL,
		0x966ADC576534F7CEULL,
		0xF65585B44A5654B5ULL,
		0x5DE53423966B77D5ULL,
		0x99D3F75417DE1EDFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A8DF1A33970A08ULL,
		0x4066C1A27F6E3D40ULL,
		0xDC576534F7CE2600ULL,
		0x85B44A5654B5966AULL,
		0x3423966B77D5F655ULL,
		0xF75417DE1EDF5DE5ULL,
		0x00000000000099D3ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x278E1271D867C17DULL,
		0x33D170139BE6DC47ULL,
		0x76253F3BE8139F4DULL,
		0x65D98CE2E80C849DULL,
		0xF26B70ADE5EFCFC3ULL,
		0x96587430CC13224BULL,
		0x1E163BE3EBC3C747ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE6DC47278E1271ULL,
		0xE8139F4D33D17013ULL,
		0xE80C849D76253F3BULL,
		0xE5EFCFC365D98CE2ULL,
		0xCC13224BF26B70ADULL,
		0xEBC3C74796587430ULL,
		0x000000001E163BE3ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x067EF2A1A5EE6147ULL,
		0x4500DA95FFD06E8AULL,
		0x28A8C0902059C9F1ULL,
		0xDEFB4130AAFD17BCULL,
		0x61F89DB831B8E8A2ULL,
		0xFCE1B9657A32C184ULL,
		0xF96370FDBC5961E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06E8A067EF2A1A5ULL,
		0x59C9F14500DA95FFULL,
		0xFD17BC28A8C09020ULL,
		0xB8E8A2DEFB4130AAULL,
		0x32C18461F89DB831ULL,
		0x5961E8FCE1B9657AULL,
		0x000000F96370FDBCULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA48254FEE2246CE0ULL,
		0x87C46D92603D7AC4ULL,
		0xB35E299510DDC855ULL,
		0xCC218D8D563D21CEULL,
		0x318B41428D04A35CULL,
		0xB4664D9E6ECFE3CCULL,
		0x5AF09CD853F39089ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94904A9FDC448D9CULL,
		0xB0F88DB24C07AF58ULL,
		0xD66BC532A21BB90AULL,
		0x998431B1AAC7A439ULL,
		0x8631682851A0946BULL,
		0x368CC9B3CDD9FC79ULL,
		0x0B5E139B0A7E7211ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD9165FA23A6607D6ULL,
		0x521E7F6E0B5040E7ULL,
		0xD49462BD8D171C26ULL,
		0x65E7F3AA29ED697DULL,
		0x2B4F397132F8BEAEULL,
		0x376774C79B430412ULL,
		0xD67A33A933221EB8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEDC16A081CFB22ULL,
		0x8C57B1A2E384CA43ULL,
		0xFE75453DAD2FBA92ULL,
		0xE72E265F17D5CCBCULL,
		0xEE98F36860824569ULL,
		0x4675266443D706ECULL,
		0x0000000000001ACFULL,
		0x0000000000000000ULL
	}};
	shift = 51;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBF9A30BADF311927ULL,
		0x36AE048B83FF4D5CULL,
		0x9EC5DBB57A7AF19CULL,
		0x36F3E9D5D689287DULL,
		0xD826B90D47F858B1ULL,
		0xDEFB1DF521645F80ULL,
		0x7C7CA09D233D2845ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5CBF9A30BADF311ULL,
		0x19C36AE048B83FF4ULL,
		0x87D9EC5DBB57A7AFULL,
		0x8B136F3E9D5D6892ULL,
		0xF80D826B90D47F85ULL,
		0x845DEFB1DF521645ULL,
		0x0007C7CA09D233D2ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x53361A59685D5F16ULL,
		0x2C7711CADEA2627CULL,
		0xBF369676CB619780ULL,
		0x3A6C26A1EE4427BAULL,
		0xC3A49E7058630984ULL,
		0x49F9B05342EC42E0ULL,
		0x79CC089B01A737AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE56F51313E299B0DULL,
		0x3B65B0CBC0163B88ULL,
		0x50F72213DD5F9B4BULL,
		0x382C3184C21D3613ULL,
		0x29A176217061D24FULL,
		0x4D80D39BD524FCD8ULL,
		0x00000000003CE604ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x84729CBCA8E298EFULL,
		0x22AEC1A817A8E99EULL,
		0xFBD32C8FA8F30115ULL,
		0x429AEC62A22829C3ULL,
		0xF755E694A5AA75AFULL,
		0x30503536DF39AADFULL,
		0x05F605D323C692F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06A05EA3A67A11CULL,
		0xCB23EA3CC04548ABULL,
		0xBB18A88A0A70FEF4ULL,
		0x79A5296A9D6BD0A6ULL,
		0x0D4DB7CE6AB7FDD5ULL,
		0x8174C8F1A4BD4C14ULL,
		0x000000000000017DULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA92488D0E1F08E10ULL,
		0x6AF7C2E470021D88ULL,
		0x4C6BD622BF8FA4D9ULL,
		0xEC7C0C463F218F7DULL,
		0xA0EFAB33477D00ADULL,
		0x89BBD3714E1D9679ULL,
		0x0A1BF1EF0D8AC13DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B11524911A1C3E1ULL,
		0x49B2D5EF85C8E004ULL,
		0x1EFA98D7AC457F1FULL,
		0x015BD8F8188C7E43ULL,
		0x2CF341DF56668EFAULL,
		0x827B1377A6E29C3BULL,
		0x00001437E3DE1B15ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEBB92E31C8EA5D6AULL,
		0x878D0DB6CEC26BE9ULL,
		0x1EAE451A0A99D148ULL,
		0x847320A97753B6F9ULL,
		0x134D36B46D960D52ULL,
		0x29BA56E8DA3680C6ULL,
		0xBD6DE178EE7EC735ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC686DB676135F4F5ULL,
		0x57228D054CE8A443ULL,
		0x399054BBA9DB7C8FULL,
		0xA69B5A36CB06A942ULL,
		0xDD2B746D1B406309ULL,
		0xB6F0BC773F639A94ULL,
		0x000000000000005EULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9CA46D270F2BAD17ULL,
		0x75BF8EE547D25746ULL,
		0xB1D299816CB2F9A0ULL,
		0x1922938DC470033BULL,
		0x0C25467DE3E6901EULL,
		0xD882E4575B165BDAULL,
		0x49829D215D0935D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE547D257469CA46ULL,
		0x9816CB2F9A075BF8ULL,
		0x38DC470033BB1D29ULL,
		0x67DE3E6901E19229ULL,
		0x4575B165BDA0C254ULL,
		0xD215D0935D4D882EULL,
		0x0000000000049829ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xBFC599A22B35F08EULL,
		0x032B02FEA3DFBEA3ULL,
		0x1287D5C3BDE95A44ULL,
		0x851270BC6CA8462FULL,
		0x5EE3805E0FCA8949ULL,
		0x921DA4C70850AFE6ULL,
		0x1E46B66C6632B3AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3DFBEA3BFC599AULL,
		0x3BDE95A44032B02FULL,
		0xC6CA8462F1287D5CULL,
		0xE0FCA8949851270BULL,
		0x70850AFE65EE3805ULL,
		0xC6632B3AE921DA4CULL,
		0x0000000001E46B66ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x30D87053FDDECB00ULL,
		0x29C0DC7851C894ACULL,
		0xBC05F55F78324C5BULL,
		0xEF8C3FE692FCEE0DULL,
		0x37FF6D058DA1EB6BULL,
		0x226BF1DD9EDB5C66ULL,
		0x5CB4B150ECE8665BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A391295861B0E0AULL,
		0xEF06498B65381B8FULL,
		0xD25F9DC1B780BEABULL,
		0xB1B43D6D7DF187FCULL,
		0xB3DB6B8CC6FFEDA0ULL,
		0x1D9D0CCB644D7E3BULL,
		0x000000000B96962AULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xE9BF72EAEA17498EULL,
		0xED4E9064FED189ADULL,
		0xF23F1042A51B4B62ULL,
		0x27E9AB4045D8F926ULL,
		0x10C2FE2C4EF61107ULL,
		0xD8457CB5C8D32301ULL,
		0x1F6ED29342B26141ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFED189ADE9BF72EAULL,
		0xA51B4B62ED4E9064ULL,
		0x45D8F926F23F1042ULL,
		0x4EF6110727E9AB40ULL,
		0xC8D3230110C2FE2CULL,
		0x42B26141D8457CB5ULL,
		0x000000001F6ED293ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8E82BE153C616625ULL,
		0xC010D0C87807AA6CULL,
		0x427BC4C79E962707ULL,
		0x36AF7A0BD5FF733DULL,
		0x63E272372B8D3015ULL,
		0xEEEB9B1804192744ULL,
		0xB51705BE6BEED80BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54D91D057C2A78C2ULL,
		0x4E0F8021A190F00FULL,
		0xE67A84F7898F3D2CULL,
		0x602A6D5EF417ABFEULL,
		0x4E88C7C4E46E571AULL,
		0xB017DDD736300832ULL,
		0x00016A2E0B7CD7DDULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1CFEF316BF67D5D6ULL,
		0xC9FD69C0D18B075EULL,
		0xD2ED89D86F7F7392ULL,
		0xD160BC4321FEFA93ULL,
		0x3FE4F30560D58B7BULL,
		0xD1DFE11E8D594146ULL,
		0x018B870DB609BEAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB4E068C583AF0EULL,
		0x76C4EC37BFB9C964ULL,
		0xB05E2190FF7D49E9ULL,
		0xF27982B06AC5BDE8ULL,
		0xEFF08F46ACA0A31FULL,
		0xC5C386DB04DF57E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x00143A37986D78E4ULL,
		0x9640B2C6554B23BCULL,
		0x77A2B8913D4747D7ULL,
		0xF025BE6BDE733D7FULL,
		0x7F990AC2014A66B9ULL,
		0xA4183E8B11C0808BULL,
		0x400F57DDAA2D5DDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00050E8DE61B5E39ULL,
		0xE5902CB19552C8EFULL,
		0xDDE8AE244F51D1F5ULL,
		0x7C096F9AF79CCF5FULL,
		0xDFE642B0805299AEULL,
		0xA9060FA2C4702022ULL,
		0x1003D5F76A8B5776ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xD2BEC2742CDDA663ULL,
		0x7E215B7DDDF5484DULL,
		0xA24AEDBF494A9669ULL,
		0x8D6CD3918D7E2A51ULL,
		0x735A2A89F16F241CULL,
		0x7DC9D6D8EAE67623ULL,
		0xF0E64F73D443BAD0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF5484DD2BEC2742ULL,
		0x94A96697E215B7DDULL,
		0xD7E2A51A24AEDBF4ULL,
		0x16F241C8D6CD3918ULL,
		0xAE67623735A2A89FULL,
		0x443BAD07DC9D6D8EULL,
		0x0000000F0E64F73DULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x3E6A120D8A2F6B34ULL,
		0x70BE93619B91412FULL,
		0x9EF5C88FB11BBAD5ULL,
		0xBC0CD0675439E12CULL,
		0x4A2FC64A96B4C7BBULL,
		0x056F22B8CEABFB25ULL,
		0xF94E09F496F8858DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDC8A0979F35090ULL,
		0x7D88DDD6AB85F49BULL,
		0x3AA1CF0964F7AE44ULL,
		0x54B5A63DDDE06683ULL,
		0xC6755FD92A517E32ULL,
		0xA4B7C42C682B7915ULL,
		0x0000000007CA704FULL,
		0x0000000000000000ULL
	}};
	shift = 37;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0EFB49FFC91C0BD6ULL,
		0x032AFAF836B763CBULL,
		0x5F5FE15C05C92233ULL,
		0x3FD57CE400C92FF7ULL,
		0x7DD257E44268548EULL,
		0x12790252B2D0FBF9ULL,
		0xB36990FCC96D60E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5BB1E5877DA4FFEULL,
		0x2E4911981957D7C1ULL,
		0x06497FBAFAFF0AE0ULL,
		0x1342A471FEABE720ULL,
		0x9687DFCBEE92BF22ULL,
		0x4B6B070893C81295ULL,
		0x000000059B4C87E6ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x7BA52BDF105F7D12ULL,
		0xDC5DC93A68753DFEULL,
		0x8FD23267BFFE60C6ULL,
		0x18C3103E71AFFF1FULL,
		0x3D21E9B66F972F84ULL,
		0xBE9F69CF9ED6ED6DULL,
		0x33A52821FF260BF1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4F7F9EE94AF7C4ULL,
		0xFF9831B717724E9AULL,
		0x6BFFC7E3F48C99EFULL,
		0xE5CBE10630C40F9CULL,
		0xB5BB5B4F487A6D9BULL,
		0xC982FC6FA7DA73E7ULL,
		0x0000000CE94A087FULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xC338FC7841E8187AULL,
		0xF760487876F13FC2ULL,
		0x99D7C4091CE44EDAULL,
		0x1D359181E7824194ULL,
		0x207385D12150BF77ULL,
		0x2ABDFECAF15D4838ULL,
		0xA774F87B47091CD2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858671F8F083D030ULL,
		0xB5EEC090F0EDE27FULL,
		0x2933AF881239C89DULL,
		0xEE3A6B2303CF0483ULL,
		0x7040E70BA242A17EULL,
		0xA4557BFD95E2BA90ULL,
		0x014EE9F0F68E1239ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x727FA16362195F23ULL,
		0xF3A7EDC74F4CA193ULL,
		0xC10D3BB511DE65FFULL,
		0x58011FD17A6DC081ULL,
		0xA64AB7EA428DF53BULL,
		0xD369040F1ACB4110ULL,
		0xEC67925B0DD00B4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2864DC9FE858D886ULL,
		0x997FFCE9FB71D3D3ULL,
		0x702070434EED4477ULL,
		0x7D4ED60047F45E9BULL,
		0xD0442992ADFA90A3ULL,
		0x02D374DA4103C6B2ULL,
		0x00003B19E496C374ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0C40DAD42787C44AULL,
		0x4A14779E9DADE5ACULL,
		0x88D188B661100254ULL,
		0xE7F236B282978190ULL,
		0xACF3A7AFB3A73697ULL,
		0x548DE6F2C3D805B3ULL,
		0x5AA33AE7BD2F6AA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B5BCB581881B5AULL,
		0xCC22004A89428EF3ULL,
		0x5052F032111A3116ULL,
		0xF674E6D2FCFE46D6ULL,
		0x587B00B6759E74F5ULL,
		0xF7A5ED546A91BCDEULL,
		0x000000000B54675CULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x37DAEE2CDD7C2C95ULL,
		0x0F30FEDDDC405DD3ULL,
		0xC61B0C4CA612F839ULL,
		0xCDB663C931BF730CULL,
		0x03605C9BBF708E6BULL,
		0xD48631DEB5A5129CULL,
		0x19286F81582FA92FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB880BBA66FB5DCULL,
		0x994C25F0721E61FDULL,
		0x92637EE6198C3618ULL,
		0x377EE11CD79B6CC7ULL,
		0xBD6B4A253806C0B9ULL,
		0x02B05F525FA90C63ULL,
		0x00000000003250DFULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x95BF7051C6051080ULL,
		0x28744DEDD6084964ULL,
		0x7C599CCAFB7CE018ULL,
		0x6F6F07C7F4DF3CA9ULL,
		0xCA68180FA0F2AA35ULL,
		0x0CC7E465BF968350ULL,
		0xA06FA9F3DED54523ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256FDC1471814420ULL,
		0x0A1D137B75821259ULL,
		0x5F166732BEDF3806ULL,
		0x5BDBC1F1FD37CF2AULL,
		0x329A0603E83CAA8DULL,
		0xC331F9196FE5A0D4ULL,
		0x281BEA7CF7B55148ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x5DE655D5617980E6ULL,
		0xF123459191AE3A7FULL,
		0x5C73275B5A8BEE5DULL,
		0xB759D4DBDD2BE152ULL,
		0x3AB02A6E8DD498D1ULL,
		0x09AC1516AA45729DULL,
		0x48A63C71E8A087DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D164646B8E9FD77ULL,
		0xCC9D6D6A2FB977C4ULL,
		0x67536F74AF854971ULL,
		0xC0A9BA37526346DDULL,
		0xB0545AA915CA74EAULL,
		0x98F1C7A2821F7C26ULL,
		0x0000000000000122ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x24576AC427526D91ULL,
		0x9C889706FF409D7AULL,
		0xA6A8C776E5EBF919ULL,
		0x99938761B368A1C5ULL,
		0x38934EFFB0E67B03ULL,
		0x8BE15BD00753E8A6ULL,
		0xFAD100BC8ACCC1EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE813AF448AED58ULL,
		0xDCBD7F23339112E0ULL,
		0x366D1438B4D518EEULL,
		0xF61CCF60733270ECULL,
		0x00EA7D14C71269DFULL,
		0x9159983D717C2B7AULL,
		0x000000001F5A2017ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x9404848D910FBF8EULL,
		0xEEFD1A0A0E26F928ULL,
		0xE338A4ECD618048BULL,
		0x7CD2536AF9828D9AULL,
		0x5BE569D5682319AFULL,
		0x8A34B4DF55B04201ULL,
		0x817FFF8FD332F24BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDFA34141C4DF251ULL,
		0xC67149D9AC300917ULL,
		0xF9A4A6D5F3051B35ULL,
		0xB7CAD3AAD046335EULL,
		0x146969BEAB608402ULL,
		0x02FFFF1FA665E497ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xA435EBB074E3FA63ULL,
		0x63CDAFE963E0EC4CULL,
		0xFAB9D5A08F87BCA5ULL,
		0xAA29DE5EB63FDC9FULL,
		0x492D04885CBAF413ULL,
		0x050101AE65D22F54ULL,
		0xD87BDE625B03593AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9486BD760E9C7F4CULL,
		0xAC79B5FD2C7C1D89ULL,
		0xFF573AB411F0F794ULL,
		0x75453BCBD6C7FB93ULL,
		0x8925A0910B975E82ULL,
		0x40A02035CCBA45EAULL,
		0x1B0F7BCC4B606B27ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x52F664E7A628BFAAULL,
		0xEDBDC808CD1ADA45ULL,
		0x99544EA74516B640ULL,
		0x0BEA427428D248F9ULL,
		0x4B2BBCA70B54C51EULL,
		0xA53902DD4AAA1CFFULL,
		0x25F2821F5CA1DC90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x552F664E7A628BFAULL,
		0x0EDBDC808CD1ADA4ULL,
		0x999544EA74516B64ULL,
		0xE0BEA427428D248FULL,
		0xF4B2BBCA70B54C51ULL,
		0x0A53902DD4AAA1CFULL,
		0x025F2821F5CA1DC9ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x8461F532E12F5DD4ULL,
		0x372F46F7A065D417ULL,
		0x888603AB2BC0F242ULL,
		0x0A6E769A157F3EC4ULL,
		0x0C86ACAEF7A7376FULL,
		0xF8BA5BF50D0503F8ULL,
		0x954A619B5A262AA7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF40CBA82F08C3EAULL,
		0x565781E4846E5E8DULL,
		0x342AFE7D89110C07ULL,
		0x5DEF4E6EDE14DCEDULL,
		0xEA1A0A07F0190D59ULL,
		0x36B44C554FF174B7ULL,
		0x00000000012A94C3ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x57346D14B45779B0ULL,
		0xBB5199B6E5FF84B2ULL,
		0xDAD2016864510220ULL,
		0xB6562C69ECFBEDA7ULL,
		0x19B39F9A9142AFF7ULL,
		0x9662B20E3FEA62E0ULL,
		0x64FB7B86630FBB03ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DB97FE12C95CD1BULL,
		0x5A191440882ED466ULL,
		0x1A7B3EFB69F6B480ULL,
		0xE6A450ABFDED958BULL,
		0x838FFA98B8066CE7ULL,
		0xE198C3EEC0E598ACULL,
		0x0000000000193EDEULL,
		0x0000000000000000ULL
	}};
	shift = 42;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x1485451F558E85A4ULL,
		0x5A8EEFAFAC889744ULL,
		0x3EBCFC30183D5ED2ULL,
		0x535DBFEA6F757DC0ULL,
		0x7F6D2D987F9ACE5BULL,
		0xC0792C194C112A70ULL,
		0xDCEA6F9FED6BFABCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BA20A42A28FAACULL,
		0xEAF692D4777D7D64ULL,
		0xABEE01F5E7E180C1ULL,
		0xD672DA9AEDFF537BULL,
		0x895383FB696CC3FCULL,
		0x5FD5E603C960CA60ULL,
		0x000006E7537CFF6BULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x4BE117498FA3F647ULL,
		0x4F3C6323B0D00D20ULL,
		0x5645F9474BD3EA41ULL,
		0xD5A1AB17227CBF3CULL,
		0x56CB9A047A6D8FD0ULL,
		0xEE724CBD44CC21BAULL,
		0xC0202AEC21106FC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4812F845D263E8FDULL,
		0x9053CF18C8EC3403ULL,
		0xCF15917E51D2F4FAULL,
		0xF435686AC5C89F2FULL,
		0x6E95B2E6811E9B63ULL,
		0xF03B9C932F513308ULL,
		0x0030080ABB08441BULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xCE2076DD74CE0788ULL,
		0x9AE89DE38CB889B2ULL,
		0xC6ED042AEB043782ULL,
		0x954C1D34AB2A21EDULL,
		0x3E12AF3066AFB5C1ULL,
		0xAD493D8671DF0145ULL,
		0x69F36C38139C7000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE2076DD74CE078ULL,
		0x29AE89DE38CB889BULL,
		0xDC6ED042AEB04378ULL,
		0x1954C1D34AB2A21EULL,
		0x53E12AF3066AFB5CULL,
		0x0AD493D8671DF014ULL,
		0x069F36C38139C700ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x99D168DA5631BA31ULL,
		0x2BF4ED10D49B9D1BULL,
		0x575D5A35C5CAAE1AULL,
		0x021BE71BFAD2389FULL,
		0x9486FBFECF481F6FULL,
		0x37010189F4173F8BULL,
		0x67E315B7A3D2FBCFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4DCE8DCCE8B46D2ULL,
		0x2E5570D15FA76886ULL,
		0xD691C4FABAEAD1AEULL,
		0x7A40FB7810DF38DFULL,
		0xA0B9FC5CA437DFF6ULL,
		0x1E97DE79B8080C4FULL,
		0x000000033F18ADBDULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0xEF5A4332A6A5BDD5ULL,
		0x2DD88BFD79D8309AULL,
		0x28C3C611ED6C0547ULL,
		0xE9709E3A4A0481FFULL,
		0x9A179BA8CA3E2CF2ULL,
		0x8047532DDBDF3EC5ULL,
		0x573D2F2922900BB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEC184D77AD2199ULL,
		0xF6B602A396EC45FEULL,
		0x250240FF9461E308ULL,
		0x651F167974B84F1DULL,
		0xEDEF9F62CD0BCDD4ULL,
		0x914805DB4023A996ULL,
		0x000000002B9E9794ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x30AB7D70BE3E3B3AULL,
		0x6B4FF081F67B4F8DULL,
		0x4E0D9DFE35D83691ULL,
		0x81C6A9936C570D2AULL,
		0xCD8F5194FAACB446ULL,
		0x31E0D1D3BA784E27ULL,
		0xA754763B72106186ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C69855BEB85F1F1ULL,
		0xB48B5A7F840FB3DAULL,
		0x6952706CEFF1AEC1ULL,
		0xA2340E354C9B62B8ULL,
		0x713E6C7A8CA7D565ULL,
		0x0C318F068E9DD3C2ULL,
		0x00053AA3B1DB9083ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x36AF19307359BBC4ULL,
		0x4BEE0EE92442F3A0ULL,
		0xDAAE0C5AF3B255C6ULL,
		0x39B94128800CC975ULL,
		0x49453CE8A1152358ULL,
		0xF0CA185DD7D76EA4ULL,
		0x339E786B1FF971CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB83BA4910BCE80DAULL,
		0xB8316BCEC957192FULL,
		0xE504A2003325D76AULL,
		0x14F3A284548D60E6ULL,
		0x2861775F5DBA9125ULL,
		0x79E1AC7FE5C737C3ULL,
		0x00000000000000CEULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000800000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000010000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000400000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000004000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000008000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000400000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000010000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000200000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000020000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000200000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000800000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}