#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x3779F4D3F474083CULL,
		0x279932C48C5F3D31ULL,
		0x04BDAD5863ABE190ULL,
		0xE7BC9FE61820CDA2ULL,
		0x23A2CD9968AAD539ULL,
		0x53C4E937BD7FD48CULL,
		0xE695E8CB1E9400DAULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x69FA3A041E000000ULL,
		0x62462F9E989BBCFAULL,
		0xAC31D5F0C813CC99ULL,
		0xF30C1066D1025ED6ULL,
		0xCCB4556A9CF3DE4FULL,
		0x9BDEBFEA4611D166ULL,
		0x658F4A006D29E274ULL,
		0x0000000000734AF4ULL
	}};
	int shift = 23;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x53374914CAC7A75EULL,
		0x67AB88FD3F45C999ULL,
		0x6413F7DFCE2D489DULL,
		0x16BDF593F08FF4F1ULL,
		0x79DFEBB8572645D4ULL,
		0x3A58042FCA97B2FFULL,
		0x3A0B77F336C31500ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF0000000000000ULL,
		0x4CCA99BA48A6563DULL,
		0x44EB3D5C47E9FA2EULL,
		0xA78B209FBEFE716AULL,
		0x2EA0B5EFAC9F847FULL,
		0x97FBCEFF5DC2B932ULL,
		0xA801D2C0217E54BDULL,
		0x0001D05BBF99B618ULL
	}};
	shift = 51;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBE2B2C00B40CD96CULL,
		0x1EE8B054317088B2ULL,
		0xB7DA377F4B42CCC4ULL,
		0xBA05FDF9A06B6F4FULL,
		0x899DDA3A413F9487ULL,
		0x5F76BF4610C961BDULL,
		0xC9312746B7C97E45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658016819B2D8000ULL,
		0x160A862E111657C5ULL,
		0x46EFE968599883DDULL,
		0xBFBF340D6DE9F6FBULL,
		0xBB474827F290F740ULL,
		0xD7E8C2192C37B133ULL,
		0x24E8D6F92FC8ABEEULL,
		0x0000000000001926ULL
	}};
	shift = 13;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3D74FF2C698563B5ULL,
		0x94D1BF021BEA7917ULL,
		0xB55BC9518030CD33ULL,
		0x14B5A26D3AE22342ULL,
		0x2B16751E075EF62AULL,
		0xD743CA390E3A2307ULL,
		0xDE907F129B60B1BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x9EBA7F9634C2B1DAULL,
		0xCA68DF810DF53C8BULL,
		0x5AADE4A8C0186699ULL,
		0x0A5AD1369D7111A1ULL,
		0x958B3A8F03AF7B15ULL,
		0x6BA1E51C871D1183ULL,
		0x6F483F894DB058DEULL
	}};
	shift = 63;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x64FA27279DAFB84EULL,
		0x0B5C32DC9F42AEE4ULL,
		0x226428EC6EF803B2ULL,
		0xFC4CABD32F54D704ULL,
		0x3229996435527E8CULL,
		0xD19BDCDD2E31F2CCULL,
		0xFB7BC19CDF477131ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76BEE1380000000ULL,
		0x27D0ABB9193E89C9ULL,
		0x1BBE00EC82D70CB7ULL,
		0xCBD535C108990A3BULL,
		0x0D549FA33F132AF4ULL,
		0x4B8C7CB30C8A6659ULL,
		0x37D1DC4C7466F737ULL,
		0x000000003EDEF067ULL
	}};
	shift = 30;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA2B832BC76FFB032ULL,
		0x950E5B2644CE8366ULL,
		0x3F209A38DFEB3EC9ULL,
		0x92784862B49A4A4CULL,
		0x827FE31EB25E2E22ULL,
		0x81869647250B24A9ULL,
		0xC3259D21FAE2BC8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6578EDFF60640000ULL,
		0xB64C899D06CD4570ULL,
		0x3471BFD67D932A1CULL,
		0x90C5693494987E41ULL,
		0xC63D64BC5C4524F0ULL,
		0x2C8E4A16495304FFULL,
		0x3A43F5C57915030DULL,
		0x000000000001864BULL
	}};
	shift = 17;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x67539F9F1ACDEC76ULL,
		0xE3C78CDC7485666FULL,
		0xE64E8E17E723DA54ULL,
		0xA53091CBA3A76E67ULL,
		0xCD9B5251D75A75D9ULL,
		0x246C4A7E2F415C3CULL,
		0x8CBC0B08D6FB0934ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC7600000000000ULL,
		0x5666F67539F9F1ACULL,
		0x3DA54E3C78CDC748ULL,
		0x76E67E64E8E17E72ULL,
		0xA75D9A53091CBA3AULL,
		0x15C3CCD9B5251D75ULL,
		0xB0934246C4A7E2F4ULL,
		0x000008CBC0B08D6FULL
	}};
	shift = 44;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC0477003A5864A07ULL,
		0xBFE1316FDE0A4947ULL,
		0xD8C2ED249E04B40FULL,
		0x0CEA9284443FA4BBULL,
		0x3790D88361EE9E2BULL,
		0xC3EC8A2F968061ACULL,
		0x12D86BC1FB372B6AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5864A07000000000ULL,
		0xE0A4947C0477003AULL,
		0xE04B40FBFE1316FDULL,
		0x43FA4BBD8C2ED249ULL,
		0x1EE9E2B0CEA92844ULL,
		0x68061AC3790D8836ULL,
		0xB372B6AC3EC8A2F9ULL,
		0x000000012D86BC1FULL
	}};
	shift = 36;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9802D119F31C21AFULL,
		0x81A2293ECF9C24B4ULL,
		0x3434A2F4E4D7225EULL,
		0x2D00BF5E0C475BFFULL,
		0x59731531F1D5055FULL,
		0x509C25A55D121B3BULL,
		0x652E2102818AEE08ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600B4467CC7086BCULL,
		0x0688A4FB3E7092D2ULL,
		0xD0D28BD3935C897AULL,
		0xB402FD78311D6FFCULL,
		0x65CC54C7C754157CULL,
		0x4270969574486CEDULL,
		0x94B8840A062BB821ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x18CB815F5BA7F430ULL,
		0x58B33C96BCAE2AB7ULL,
		0x28022417515D94B7ULL,
		0x6E3CB762793469F1ULL,
		0xB5AC16B0CC7D6AE6ULL,
		0xA579351AC95F2A33ULL,
		0x57BBEC11539F9107ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD0C00000000000ULL,
		0xB8AADC632E057D6EULL,
		0x7652DD62CCF25AF2ULL,
		0xD1A7C4A008905D45ULL,
		0xF5AB99B8F2DD89E4ULL,
		0x7CA8CED6B05AC331ULL,
		0x7E441E95E4D46B25ULL,
		0x0000015EEFB0454EULL
	}};
	shift = 42;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x555E808F3337F838ULL,
		0x48B3B8B3E6A1DF75ULL,
		0xE6E6A25B312C1C79ULL,
		0x5B654CBE9AF5CE66ULL,
		0x1C68EA120462D7DFULL,
		0x9CE06A0E0E3C6A8FULL,
		0x7178DECCEAF51829ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x5555E808F3337F83ULL,
		0x948B3B8B3E6A1DF7ULL,
		0x6E6E6A25B312C1C7ULL,
		0xF5B654CBE9AF5CE6ULL,
		0xF1C68EA120462D7DULL,
		0x99CE06A0E0E3C6A8ULL,
		0x07178DECCEAF5182ULL
	}};
	shift = 60;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBE3A1930ED0B3659ULL,
		0x68B80BCB09E7381DULL,
		0xF849A161BAFCDDB7ULL,
		0x63AE70DF50B8C68AULL,
		0x44FAAA228DA91DF8ULL,
		0x02C439F7DCCCFB96ULL,
		0x01E6D1DC8DA16564ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB20000000000000ULL,
		0x03B7C743261DA166ULL,
		0xB6ED170179613CE7ULL,
		0xD15F09342C375F9BULL,
		0xBF0C75CE1BEA1718ULL,
		0x72C89F554451B523ULL,
		0xAC8058873EFB999FULL,
		0x00003CDA3B91B42CULL
	}};
	shift = 53;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x068A061E6EA6AED3ULL,
		0x75935527B7DC736DULL,
		0x48CF3DE680C5EE1EULL,
		0xC7AE3ABCBFDA27FCULL,
		0x1D2B647EEC3D87E9ULL,
		0xEF18F3EF47A2F977ULL,
		0xF1906FB6ED256013ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDD4D5DA60000000ULL,
		0xF6FB8E6DA0D140C3ULL,
		0xD018BDC3CEB26AA4ULL,
		0x97FB44FF8919E7BCULL,
		0xDD87B0FD38F5C757ULL,
		0xE8F45F2EE3A56C8FULL,
		0xDDA4AC027DE31E7DULL,
		0x000000001E320DF6ULL
	}};
	shift = 29;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1432ECCC3B622BDFULL,
		0xD222B57346A96A9EULL,
		0x47D6F003917C6486ULL,
		0xFDB9AADD377467CCULL,
		0x916A6AF965CC3AF8ULL,
		0x09F126FFB1DA959FULL,
		0x9F0330011031723DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99876C457BE00000ULL,
		0xAE68D52D53C2865DULL,
		0x00722F8C90DA4456ULL,
		0x5BA6EE8CF988FADEULL,
		0x5F2CB9875F1FB735ULL,
		0xDFF63B52B3F22D4DULL,
		0x0022062E47A13E24ULL,
		0x000000000013E066ULL
	}};
	shift = 21;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6A67473900F49DD0ULL,
		0xFAE08407CA38EF12ULL,
		0x565E9972A34965DCULL,
		0x62FC4AFBD296AF53ULL,
		0x2931FE8E991BFA89ULL,
		0x274FE6A90CCC3D6CULL,
		0xE55DBA43AF6B0993ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BA0000000000000ULL,
		0xDE24D4CE8E7201E9ULL,
		0xCBB9F5C1080F9471ULL,
		0x5EA6ACBD32E54692ULL,
		0xF512C5F895F7A52DULL,
		0x7AD85263FD1D3237ULL,
		0x13264E9FCD521998ULL,
		0x0001CABB74875ED6ULL
	}};
	shift = 49;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x014FB79B1F2314B4ULL,
		0xB1F02FB615F0CD75ULL,
		0x3A16465AB192F5ACULL,
		0x4FD6EFB3BEA0AC29ULL,
		0x5FFDCF4101AC44F2ULL,
		0xEE75804A873003ACULL,
		0x918AE79FE62C0732ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE6C7C8C52D00000ULL,
		0xBED857C335D4053EULL,
		0x196AC64BD6B2C7C0ULL,
		0xBECEFA82B0A4E859ULL,
		0x3D0406B113C93F5BULL,
		0x012A1CC00EB17FF7ULL,
		0x9E7F98B01CCBB9D6ULL,
		0x000000000002462BULL
	}};
	shift = 18;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E81D107C7156443ULL,
		0x8974E2F469972B42ULL,
		0x253EB3DFFC76BB34ULL,
		0x59E05B721981F52FULL,
		0x01C4CB831C5D47C6ULL,
		0x5A785A52FEE1F893ULL,
		0xF0019D1015C0CEE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB221800000000000ULL,
		0x95A12F40E883E38AULL,
		0x5D9A44BA717A34CBULL,
		0xFA97929F59EFFE3BULL,
		0xA3E32CF02DB90CC0ULL,
		0xFC4980E265C18E2EULL,
		0x67702D3C2D297F70ULL,
		0x00007800CE880AE0ULL
	}};
	shift = 47;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8E921EAE083E555DULL,
		0xE2454A9A4F1B7A46ULL,
		0x3269DBD53D4D240CULL,
		0xC19606E3D364729EULL,
		0xE20301B48A27C916ULL,
		0x9A1A6991C4FC07CAULL,
		0xB3DCC3A055479218ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F95574000000000ULL,
		0xC6DE91A3A487AB82ULL,
		0x534903389152A693ULL,
		0xD91CA78C9A76F54FULL,
		0x89F245B06581B8F4ULL,
		0x3F01F2B880C06D22ULL,
		0x51E48626869A6471ULL,
		0x0000002CF730E815ULL
	}};
	shift = 38;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB9FEE7D69816E056ULL,
		0xDCDD95FFCB55DF50ULL,
		0x2C8F3F13E0306B79ULL,
		0x078B0E15E93CF055ULL,
		0xCD341E3622DAD5B8ULL,
		0x1B75A392FA3F674FULL,
		0x923A85AD285C13AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B8158000000000ULL,
		0xD577D42E7FB9F5A6ULL,
		0x0C1ADE7737657FF2ULL,
		0x4F3C154B23CFC4F8ULL,
		0xB6B56E01E2C3857AULL,
		0x8FD9D3F34D078D88ULL,
		0x1704EB86DD68E4BEULL,
		0x000000248EA16B4AULL
	}};
	shift = 38;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x16CD536E7EE3D1B1ULL,
		0x13204C797C79E9EDULL,
		0xA450C6912EEAE7DEULL,
		0x1C62B5D52F492D44ULL,
		0xED681028F8C00F63ULL,
		0xAA3B8A61A57A7F9FULL,
		0x232D47F1A09632F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F46C40000000000ULL,
		0xE7A7B45B354DB9FBULL,
		0xAB9F784C8131E5F1ULL,
		0x24B51291431A44BBULL,
		0x003D8C718AD754BDULL,
		0xE9FE7FB5A040A3E3ULL,
		0x58CBE6A8EE298695ULL,
		0x0000008CB51FC682ULL
	}};
	shift = 42;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x69094D0695BA5AB2ULL,
		0xAE92E89269137CE2ULL,
		0x726F3568165617C1ULL,
		0x4DB1F3CE83EDA9E5ULL,
		0xB231E8863D8738DCULL,
		0xB897F0DB3F1A4D76ULL,
		0x20A98C132591B810ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25341A56E96AC800ULL,
		0x4BA249A44DF389A4ULL,
		0xBCD5A059585F06BAULL,
		0xC7CF3A0FB6A795C9ULL,
		0xC7A218F61CE37136ULL,
		0x5FC36CFC6935DAC8ULL,
		0xA6304C9646E042E2ULL,
		0x0000000000000082ULL
	}};
	shift = 10;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDC902EB5C094AC76ULL,
		0x1471F54D01297F77ULL,
		0x420A595AA2EF6322ULL,
		0x739F64828AB739E4ULL,
		0x743B14D4CE00EC49ULL,
		0x73A15ABB97DB6C58ULL,
		0x318F5F3D8B76B0D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x094AC76000000000ULL,
		0x1297F77DC902EB5CULL,
		0x2EF63221471F54D0ULL,
		0xAB739E4420A595AAULL,
		0xE00EC49739F64828ULL,
		0x7DB6C58743B14D4CULL,
		0xB76B0D973A15ABB9ULL,
		0x0000000318F5F3D8ULL
	}};
	shift = 36;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6712DCAEFF90CAFBULL,
		0xC17CEF96717715E6ULL,
		0xB7CCC49EE9E735D0ULL,
		0x04375284403303C3ULL,
		0x70FB22FE8BF6A1E4ULL,
		0x05EE6A7BE3E5CD6FULL,
		0x00EDC9B7C8ABB152ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x33896E577FC8657DULL,
		0x60BE77CB38BB8AF3ULL,
		0xDBE6624F74F39AE8ULL,
		0x021BA942201981E1ULL,
		0xB87D917F45FB50F2ULL,
		0x02F7353DF1F2E6B7ULL,
		0x0076E4DBE455D8A9ULL
	}};
	shift = 63;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBFAACA12270153A5ULL,
		0x4CB961AB6B3175B8ULL,
		0x23D7B114EB5947E1ULL,
		0x54D710E706C13B10ULL,
		0xEA8B022DC1E4E855ULL,
		0xF23B0161706F30DAULL,
		0xE3986AEF4633EDE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5091380A9D280000ULL,
		0x0D5B598BADC5FD56ULL,
		0x88A75ACA3F0A65CBULL,
		0x87383609D8811EBDULL,
		0x116E0F2742AAA6B8ULL,
		0x0B0B837986D75458ULL,
		0x577A319F6F3F91D8ULL,
		0x0000000000071CC3ULL
	}};
	shift = 19;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9E35C8EB07039F85ULL,
		0xCEC0F5BD12265D8EULL,
		0xEB0CFA2875558BAAULL,
		0xDEEC43D12C03ADBBULL,
		0xAD1F022E5C8FF0FEULL,
		0xD029956D8D7A1763ULL,
		0x0AF1CF71C848E8D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AC1C0E7E140000ULL,
		0xD6F44899763A78D7ULL,
		0xE8A1D5562EAB3B03ULL,
		0x0F44B00EB6EFAC33ULL,
		0x08B9723FC3FB7BB1ULL,
		0x55B635E85D8EB47CULL,
		0x3DC72123A35B40A6ULL,
		0x0000000000002BC7ULL
	}};
	shift = 18;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x725567F47D11D994ULL,
		0xF3F0B675B596B570ULL,
		0x7D8979AE37C49CC4ULL,
		0x062A10EC3438226BULL,
		0xC5019E213A695E87ULL,
		0x7BA03FF6ED91851EULL,
		0xB917C32C4994B2D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD1F44766500000ULL,
		0xD9D6D65AD5C1C955ULL,
		0xE6B8DF127313CFC2ULL,
		0x43B0D0E089ADF625ULL,
		0x7884E9A57A1C18A8ULL,
		0xFFDBB646147B1406ULL,
		0x0CB12652CB5DEE80ULL,
		0x000000000002E45FULL
	}};
	shift = 18;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF580FCAF73FCC360ULL,
		0xBBC9916F51D5AF1DULL,
		0x99C1D9D06AB6D5D5ULL,
		0xE957AE5E6F4761E9ULL,
		0x85BCF70245040DEEULL,
		0xA23B9D4FA2BDCF42ULL,
		0x9A3ED1CF3CAD7BDFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FCC360000000000ULL,
		0x1D5AF1DF580FCAF7ULL,
		0xAB6D5D5BBC9916F5ULL,
		0xF4761E999C1D9D06ULL,
		0x5040DEEE957AE5E6ULL,
		0x2BDCF4285BCF7024ULL,
		0xCAD7BDFA23B9D4FAULL,
		0x00000009A3ED1CF3ULL
	}};
	shift = 36;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x145378DD6D8C6F14ULL,
		0xFD5C329FB2438A4EULL,
		0xCBD00737F7251CABULL,
		0x9213EC684DF0A8F5ULL,
		0x0C306B5075F7E28CULL,
		0xE8EF802C8A3392F8ULL,
		0x832B948A823F44BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A6F1BADB18DE28ULL,
		0xFAB8653F6487149CULL,
		0x97A00E6FEE4A3957ULL,
		0x2427D8D09BE151EBULL,
		0x1860D6A0EBEFC519ULL,
		0xD1DF0059146725F0ULL,
		0x06572915047E897FULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x319B188FEB450D80ULL,
		0x91694713920D0B55ULL,
		0xAC3B5C06A613C561ULL,
		0xC5AD26C671726787ULL,
		0x2C68E97CECA05391ULL,
		0x51C9AA19D3779FE0ULL,
		0xBC0BF08C4BBA540DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC623FAD143600000ULL,
		0x51C4E48342D54C66ULL,
		0xD701A984F158645AULL,
		0x49B19C5C99E1EB0EULL,
		0x3A5F3B2814E4716BULL,
		0x6A8674DDE7F80B1AULL,
		0xFC2312EE95035472ULL,
		0x0000000000002F02ULL
	}};
	shift = 14;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9DD5245F76058BAEULL,
		0xFF8FEFFF76DC00D6ULL,
		0x7BC62197F9004C0EULL,
		0x1CB8531C0F1E701EULL,
		0xA9270C0A2EBBB3B8ULL,
		0x167136A7615B8047ULL,
		0xBCD2202AE47AA0F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FBB02C5D7000000ULL,
		0xFFBB6E006B4EEA92ULL,
		0xCBFC8026077FC7F7ULL,
		0x8E078F380F3DE310ULL,
		0x05175DD9DC0E5C29ULL,
		0x53B0ADC023D49386ULL,
		0x15723D50798B389BULL,
		0x00000000005E6910ULL
	}};
	shift = 23;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC48C24EBFF854D31ULL,
		0x2B6AE4679DEB4243ULL,
		0x188D45E5135FEA46ULL,
		0xF72EB2A45CA1E561ULL,
		0x1682CD8D996B0051ULL,
		0x3B274AB30F527DB7ULL,
		0x46F11F1701B9AC06ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFE1534C4000000ULL,
		0x9E77AD090F123093ULL,
		0x944D7FA918ADAB91ULL,
		0x9172879584623517ULL,
		0x3665AC0147DCBACAULL,
		0xCC3D49F6DC5A0B36ULL,
		0x5C06E6B018EC9D2AULL,
		0x00000000011BC47CULL
	}};
	shift = 26;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD88875A249A8D390ULL,
		0x88B585A4780E4366ULL,
		0x58CF800C67D05819ULL,
		0x7CEFBECCC0BF1DACULL,
		0xF017312F28F9776FULL,
		0xF3C26778797315CBULL,
		0xFBEFA47CA47E29B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68926A34E4000000ULL,
		0x691E0390D9B6221DULL,
		0x0319F41606622D61ULL,
		0xB3302FC76B1633E0ULL,
		0x4BCA3E5DDBDF3BEFULL,
		0xDE1E5CC572FC05CCULL,
		0x1F291F8A6E3CF099ULL,
		0x00000000003EFBE9ULL
	}};
	shift = 22;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFED160C6234423E7ULL,
		0x0C10E1801D451E80ULL,
		0x7CE9BC162DDF854AULL,
		0xDFE933B4AA3FC415ULL,
		0xDC7013BEA61CA21FULL,
		0x86ACF490834F5A48ULL,
		0x565909848BC97802ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F38000000000000ULL,
		0xF407F68B06311A21ULL,
		0x2A5060870C00EA28ULL,
		0x20ABE74DE0B16EFCULL,
		0x10FEFF499DA551FEULL,
		0xD246E3809DF530E5ULL,
		0xC0143567A4841A7AULL,
		0x0002B2C84C245E4BULL
	}};
	shift = 51;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA1113D72483C9A21ULL,
		0xF3CD46D9E6CF2578ULL,
		0xE1059135AA0AE53AULL,
		0x3233E3BD5163D82AULL,
		0xD97AC5575D225B51ULL,
		0xDA0388853BA2DD19ULL,
		0x689D190C45E9B5CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8840000000000000ULL,
		0x5E28444F5C920F26ULL,
		0x4EBCF351B679B3C9ULL,
		0x0AB841644D6A82B9ULL,
		0xD44C8CF8EF5458F6ULL,
		0x46765EB155D74896ULL,
		0x73F680E2214EE8B7ULL,
		0x001A274643117A6DULL
	}};
	shift = 54;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3553C56CA13D18C4ULL,
		0xE53ABF8AB0327527ULL,
		0xBC2E6EA848B42D3BULL,
		0x2DC02FC3E24D2394ULL,
		0x51C1F6F13A9A12F5ULL,
		0xD1B9EED71AFCC3D8ULL,
		0xA937CCF1E2879B93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4631000000000000ULL,
		0x9D49CD54F15B284FULL,
		0x0B4EF94EAFE2AC0CULL,
		0x48E52F0B9BAA122DULL,
		0x84BD4B700BF0F893ULL,
		0x30F614707DBC4EA6ULL,
		0xE6E4F46E7BB5C6BFULL,
		0x00002A4DF33C78A1ULL
	}};
	shift = 46;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6A3E20819F56EDB3ULL,
		0xAEC4CB1E298161D7ULL,
		0xB2896D32B46DB709ULL,
		0x85945BDA3AA102EEULL,
		0xA19AAF9283D16F23ULL,
		0x0685E9729D705DAEULL,
		0x94E75DA7F477E0B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F882067D5BB6CC0ULL,
		0xB132C78A605875DAULL,
		0xA25B4CAD1B6DC26BULL,
		0x6516F68EA840BBACULL,
		0x66ABE4A0F45BC8E1ULL,
		0xA17A5CA75C176BA8ULL,
		0x39D769FD1DF82C01ULL,
		0x0000000000000025ULL
	}};
	shift = 6;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCF1040DDCB497CE6ULL,
		0x610EA1CFFA6C4F12ULL,
		0x5729FA7ADCC9AF47ULL,
		0x0A1C722A0FF7D11AULL,
		0x300E3EE0D0B7EC4EULL,
		0x786AC97A9E760D3FULL,
		0xABF7B6CB5FA2263CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97CE600000000000ULL,
		0xC4F12CF1040DDCB4ULL,
		0x9AF47610EA1CFFA6ULL,
		0x7D11A5729FA7ADCCULL,
		0x7EC4E0A1C722A0FFULL,
		0x60D3F300E3EE0D0BULL,
		0x2263C786AC97A9E7ULL,
		0x00000ABF7B6CB5FAULL
	}};
	shift = 44;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0835709D21C19D6DULL,
		0xE94861D87C309847ULL,
		0x38285C760C90AA42ULL,
		0xD16CFFFC8E8E8EEDULL,
		0x8FB3D01B2084AE3AULL,
		0x290446E3EE836882ULL,
		0xC3829DCC352D5E91ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC19D6D0000000000ULL,
		0x3098470835709D21ULL,
		0x90AA42E94861D87CULL,
		0x8E8EED38285C760CULL,
		0x84AE3AD16CFFFC8EULL,
		0x8368828FB3D01B20ULL,
		0x2D5E91290446E3EEULL,
		0x000000C3829DCC35ULL
	}};
	shift = 40;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6C25CA041CF1A458ULL,
		0x905406AC3C069A40ULL,
		0x4D5676C3E67C2299ULL,
		0xC3221198E81D0224ULL,
		0xCD1E7EDD5CFEC0C1ULL,
		0xC0BB9F919288DDF1ULL,
		0xF2D28247D561B133ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CA041CF1A458000ULL,
		0x406AC3C069A406C2ULL,
		0x676C3E67C2299905ULL,
		0x21198E81D02244D5ULL,
		0xE7EDD5CFEC0C1C32ULL,
		0xB9F919288DDF1CD1ULL,
		0x28247D561B133C0BULL,
		0x0000000000000F2DULL
	}};
	shift = 12;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD4AEB7C8775D3DB2ULL,
		0x89DB9D6B5BB1BC29ULL,
		0xEDFD7B3CE8E1AC49ULL,
		0x4E2AFEEB30447728ULL,
		0x199E9A07F3D95D84ULL,
		0x7583314CFAF8FE7FULL,
		0xD200CDB455C8CFA5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8775D3DB2000000ULL,
		0x6B5BB1BC29D4AEB7ULL,
		0x3CE8E1AC4989DB9DULL,
		0xEB30447728EDFD7BULL,
		0x07F3D95D844E2AFEULL,
		0x4CFAF8FE7F199E9AULL,
		0xB455C8CFA5758331ULL,
		0x0000000000D200CDULL
	}};
	shift = 24;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3511E8B9D2CF4967ULL,
		0xC4C9A8D3C9B08E5BULL,
		0xB8D0B331CF32DDE6ULL,
		0xC968D060D076F382ULL,
		0xDFC69D201389CDA6ULL,
		0x048DC58BFA3C5F9AULL,
		0xC91A0106F31594C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0xB3511E8B9D2CF496ULL,
		0x6C4C9A8D3C9B08E5ULL,
		0x2B8D0B331CF32DDEULL,
		0x6C968D060D076F38ULL,
		0xADFC69D201389CDAULL,
		0x6048DC58BFA3C5F9ULL,
		0x0C91A0106F31594CULL
	}};
	shift = 60;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF2B50B15DAE5375CULL,
		0x01361964E615D6A1ULL,
		0x7A651119DA44A70FULL,
		0x9655E941BC7E70A1ULL,
		0x0B9DF56FE6133948ULL,
		0x8968BEFE68E69A46ULL,
		0xF87DE7A001FA01FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB15DAE5375C00000ULL,
		0x964E615D6A1F2B50ULL,
		0x119DA44A70F01361ULL,
		0x941BC7E70A17A651ULL,
		0x56FE61339489655EULL,
		0xEFE68E69A460B9DFULL,
		0x7A001FA01FC8968BULL,
		0x00000000000F87DEULL
	}};
	shift = 20;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6F376BDF1F3D86E9ULL,
		0xF9E2D1452524977BULL,
		0xB8E596BC9C11D3E9ULL,
		0xA3A05FB640E55CD7ULL,
		0xFF85977C0584ABC2ULL,
		0xAC7D905FD37D2561ULL,
		0x38ECB541F9DA3284ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BE3E7B0DD200000ULL,
		0x28A4A492EF6DE6EDULL,
		0xD793823A7D3F3C5AULL,
		0xF6C81CAB9AF71CB2ULL,
		0xEF80B0957854740BULL,
		0x0BFA6FA4AC3FF0B2ULL,
		0xA83F3B4650958FB2ULL,
		0x0000000000071D96ULL
	}};
	shift = 21;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x986C6B877C0D379EULL,
		0xE0BEF7A50550F9D3ULL,
		0x7D0B4E96825726D9ULL,
		0x8DCEDBA1B7FA270FULL,
		0x2F74979653E36236ULL,
		0x96E06EA4C1C0068CULL,
		0x6A948FC97BC747C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C6B877C0D379E00ULL,
		0xBEF7A50550F9D398ULL,
		0x0B4E96825726D9E0ULL,
		0xCEDBA1B7FA270F7DULL,
		0x74979653E362368DULL,
		0xE06EA4C1C0068C2FULL,
		0x948FC97BC747C596ULL,
		0x000000000000006AULL
	}};
	shift = 8;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB6AC39740BD97C4FULL,
		0x9070A652461D8D99ULL,
		0x16B0977BB56E94A2ULL,
		0xFA31405ACF53DB37ULL,
		0x98BBC27487BA3016ULL,
		0x769F0CD9BCE7D705ULL,
		0xA7D776F3836A2A70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72E817B2F89E0000ULL,
		0x4CA48C3B1B336D58ULL,
		0x2EF76ADD294520E1ULL,
		0x80B59EA7B66E2D61ULL,
		0x84E90F74602DF462ULL,
		0x19B379CFAE0B3177ULL,
		0xEDE706D454E0ED3EULL,
		0x0000000000014FAEULL
	}};
	shift = 17;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC7F5965F60EF25ECULL,
		0xBB33B02BD65F9B17ULL,
		0x3A4CD92B4A8AA019ULL,
		0xD34AC2ABDA0121C1ULL,
		0x1C730BF15BB5E376ULL,
		0x5D4B9E2CDBEC357EULL,
		0xE2F7C9B61B495E87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F6000000000000ULL,
		0xCD8BE3FACB2FB077ULL,
		0x500CDD99D815EB2FULL,
		0x90E09D266C95A545ULL,
		0xF1BB69A56155ED00ULL,
		0x1ABF0E3985F8ADDAULL,
		0xAF43AEA5CF166DF6ULL,
		0x0000717BE4DB0DA4ULL
	}};
	shift = 47;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x465E529253278E72ULL,
		0x8964C0E3A3B1065EULL,
		0xAE1B58B5D68F5DACULL,
		0x8F22AFC1353786EBULL,
		0x75D0148DB8410F01ULL,
		0x191E5FDAC146D2C9ULL,
		0xC7BBA80D5BD27EECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA64F1CE400000000ULL,
		0x47620CBC8CBCA524ULL,
		0xAD1EBB5912C981C7ULL,
		0x6A6F0DD75C36B16BULL,
		0x70821E031E455F82ULL,
		0x828DA592EBA0291BULL,
		0xB7A4FDD8323CBFB5ULL,
		0x000000018F77501AULL
	}};
	shift = 33;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8F1CF97B5E4D60CFULL,
		0x131CBBD1870E6368ULL,
		0xC2E36AAE77468578ULL,
		0x0452E8DEFF812EADULL,
		0x739B27C20A86915CULL,
		0x3B24C63F4E0AA76DULL,
		0x38A31AD1900B5AFBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x478E7CBDAF26B067ULL,
		0x098E5DE8C38731B4ULL,
		0xE171B5573BA342BCULL,
		0x0229746F7FC09756ULL,
		0xB9CD93E1054348AEULL,
		0x9D92631FA70553B6ULL,
		0x1C518D68C805AD7DULL
	}};
	shift = 63;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA0ACF3F7E49485A4ULL,
		0xFEE7876EFD4DD4E8ULL,
		0x5E766A3E00B6894CULL,
		0xA42487C6343CA7D1ULL,
		0x9176C8087A4EE0DEULL,
		0x8A1E5354C6C90C12ULL,
		0x1F57C875AC3C4AF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4800000000000000ULL,
		0xD14159E7EFC9290BULL,
		0x99FDCF0EDDFA9BA9ULL,
		0xA2BCECD47C016D12ULL,
		0xBD48490F8C68794FULL,
		0x2522ED9010F49DC1ULL,
		0xEF143CA6A98D9218ULL,
		0x003EAF90EB587895ULL
	}};
	shift = 57;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x34E80D3888B7A9A2ULL,
		0xD0F6DA472B0BD16AULL,
		0xC607EAF7DAA70C6BULL,
		0xDFDD0449A8F60EF1ULL,
		0xBE57C432B5881259ULL,
		0xC2B4AA7E3F9096F5ULL,
		0x9F39EDC8F0184363ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A034E222DEA688ULL,
		0x43DB691CAC2F45A8ULL,
		0x181FABDF6A9C31AFULL,
		0x7F741126A3D83BC7ULL,
		0xF95F10CAD6204967ULL,
		0x0AD2A9F8FE425BD6ULL,
		0x7CE7B723C0610D8FULL,
		0x0000000000000002ULL
	}};
	shift = 2;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5AC3C90CF5B5A029ULL,
		0x02FE035CC80B3F6CULL,
		0x16C66D9296554CBBULL,
		0x072F7E0BAECA9CC3ULL,
		0xF39F1F5C89B7AAC9ULL,
		0xDCDE47717872A823ULL,
		0xD2490B88454F81A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x433D6D680A400000ULL,
		0xD73202CFDB16B0F2ULL,
		0x64A595532EC0BF80ULL,
		0x82EBB2A730C5B19BULL,
		0xD7226DEAB241CBDFULL,
		0xDC5E1CAA08FCE7C7ULL,
		0xE21153E06A773791ULL,
		0x0000000000349242ULL
	}};
	shift = 22;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF3281EDD05B7AC8EULL,
		0xE1640F64AECB610FULL,
		0x6815A5A6371D0F1AULL,
		0xC337F44F5FD068B2ULL,
		0xDB7883D5863B93DDULL,
		0x7999CE4127C54408ULL,
		0xDCDA87A487B6F400ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3281EDD05B7AC8E0ULL,
		0x1640F64AECB610FFULL,
		0x815A5A6371D0F1AEULL,
		0x337F44F5FD068B26ULL,
		0xB7883D5863B93DDCULL,
		0x999CE4127C54408DULL,
		0xCDA87A487B6F4007ULL,
		0x000000000000000DULL
	}};
	shift = 4;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC336CCEFDF785F33ULL,
		0xFEEF6C090DB2A425ULL,
		0x28E7F7DED059561DULL,
		0xFDE2F902B6B4C5DAULL,
		0x267E288003FB65ADULL,
		0x7A84AE131FDC68B1ULL,
		0x20BFB173B9D7BB20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6677EFBC2F9980ULL,
		0x77B60486D95212E1ULL,
		0x73FBEF682CAB0EFFULL,
		0xF17C815B5A62ED14ULL,
		0x3F144001FDB2D6FEULL,
		0x4257098FEE345893ULL,
		0x5FD8B9DCEBDD903DULL,
		0x0000000000000010ULL
	}};
	shift = 7;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5A02B1C4DFD6F11BULL,
		0xD9B6EB7717E821F1ULL,
		0x275FBF5935218151ULL,
		0x9E2DF40196B7FAC4ULL,
		0x92257CD9A191598EULL,
		0xBDA4BD6D992B02C2ULL,
		0x36D3A4DE601680CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B1C4DFD6F11B00ULL,
		0xB6EB7717E821F15AULL,
		0x5FBF5935218151D9ULL,
		0x2DF40196B7FAC427ULL,
		0x257CD9A191598E9EULL,
		0xA4BD6D992B02C292ULL,
		0xD3A4DE601680CEBDULL,
		0x0000000000000036ULL
	}};
	shift = 8;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB541C5D439F52347ULL,
		0x94B35CCF3D79FD90ULL,
		0xE870B7857F26D9D6ULL,
		0x1BE8B8BDD36BDB92ULL,
		0x17F0497F3FAC67CEULL,
		0xEA42356E23BA66B8ULL,
		0xED5A91677DC048D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA838BA873EA468E0ULL,
		0x966B99E7AF3FB216ULL,
		0x0E16F0AFE4DB3AD2ULL,
		0x7D1717BA6D7B725DULL,
		0xFE092FE7F58CF9C3ULL,
		0x4846ADC4774CD702ULL,
		0xAB522CEFB8091B1DULL,
		0x000000000000001DULL
	}};
	shift = 5;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3679215DE2BB059DULL,
		0x30772AEB52EE716FULL,
		0x6EB97D67D363A522ULL,
		0xEEDD77F8E210AE6DULL,
		0x0872C1B1D57022ADULL,
		0x7A69B2C37B0413FFULL,
		0xB627311944410A5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242BBC5760B3A000ULL,
		0xE55D6A5DCE2DE6CFULL,
		0x2FACFA6C74A4460EULL,
		0xAEFF1C4215CDADD7ULL,
		0x58363AAE0455BDDBULL,
		0x36586F60827FE10EULL,
		0xE6232888214B6F4DULL,
		0x00000000000016C4ULL
	}};
	shift = 13;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD43E1522AAF64ECCULL,
		0x15837CA8038F21A3ULL,
		0xE17F801F57FDF8C6ULL,
		0x83265431BE28689DULL,
		0x2416D684C86C8D88ULL,
		0x7963F0EE402EE93AULL,
		0x049B587B3B1BF179ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD980000000000000ULL,
		0x347A87C2A4555EC9ULL,
		0x18C2B06F950071E4ULL,
		0x13BC2FF003EAFFBFULL,
		0xB11064CA8637C50DULL,
		0x274482DAD0990D91ULL,
		0x2F2F2C7E1DC805DDULL,
		0x0000936B0F67637EULL
	}};
	shift = 53;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6B3A30160DCE4E59ULL,
		0xDF84DC74E4B2DF7AULL,
		0x4C20F3DEBD445630ULL,
		0x03753953F003148FULL,
		0xF8030D49E3765CC6ULL,
		0x5B58E9DA3B214744ULL,
		0x26069A4EE36D9A36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30160DCE4E590000ULL,
		0xDC74E4B2DF7A6B3AULL,
		0xF3DEBD445630DF84ULL,
		0x3953F003148F4C20ULL,
		0x0D49E3765CC60375ULL,
		0xE9DA3B214744F803ULL,
		0x9A4EE36D9A365B58ULL,
		0x0000000000002606ULL
	}};
	shift = 16;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFF2F2DD327DB38E3ULL,
		0x5B265A807F43B3B5ULL,
		0x10DBF71AC095D9ABULL,
		0x2EBF049DBF4B9B1EULL,
		0x836FA451E19737DDULL,
		0x3728F25BBBCB191DULL,
		0xB51BED14586F3BF6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB671C6000000000ULL,
		0xE87676BFE5E5BA64ULL,
		0x12BB356B64CB500FULL,
		0xE97363C21B7EE358ULL,
		0x32E6FBA5D7E093B7ULL,
		0x796323B06DF48A3CULL,
		0x0DE77EC6E51E4B77ULL,
		0x00000016A37DA28BULL
	}};
	shift = 37;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC40E355A0BAD1703ULL,
		0xC4ADA820D10CEDA2ULL,
		0xDC24589208DEF683ULL,
		0x2D349832A6CE063CULL,
		0x362C38B6AEEC4F9EULL,
		0x40C634B739B7C13DULL,
		0x75842A99EF504BF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05D68B818000000ULL,
		0x0688676D162071AAULL,
		0x9046F7B41E256D41ULL,
		0x95367031E6E122C4ULL,
		0xB577627CF169A4C1ULL,
		0xB9CDBE09E9B161C5ULL,
		0xCF7A825FAA0631A5ULL,
		0x0000000003AC2154ULL
	}};
	shift = 27;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7D030D4BFF292BCDULL,
		0xF3A315BF11456207ULL,
		0x7ECD8E68F2DE3BCDULL,
		0xADAD285DEDADD9B1ULL,
		0x84DAAFE1DB240E2AULL,
		0x7CA779CDDA733848ULL,
		0x70410DF77AAACFD6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC352FFCA4AF34000ULL,
		0xC56FC4515881DF40ULL,
		0x639A3CB78EF37CE8ULL,
		0x4A177B6B766C5FB3ULL,
		0xABF876C9038AAB6BULL,
		0xDE73769CCE122136ULL,
		0x437DDEAAB3F59F29ULL,
		0x0000000000001C10ULL
	}};
	shift = 14;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x79C08A473193C8B2ULL,
		0x3EDF46917AE915B4ULL,
		0x56490733963C68E6ULL,
		0x004D70915EA26AA7ULL,
		0xDD13B575F71C7DD1ULL,
		0x7715D1C31B22FE01ULL,
		0xFF2C9BA489DECBA3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9000000000000000ULL,
		0xA3CE0452398C9E45ULL,
		0x31F6FA348BD748ADULL,
		0x3AB248399CB1E347ULL,
		0x88026B848AF51355ULL,
		0x0EE89DABAFB8E3EEULL,
		0x1BB8AE8E18D917F0ULL,
		0x07F964DD244EF65DULL
	}};
	shift = 59;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF49DC872973CA1D1ULL,
		0x3F734DBAE541F812ULL,
		0xF79DAEF5455DC8C0ULL,
		0x4F86B94887D04C6FULL,
		0x0425A0A7F7457245ULL,
		0xE81E6AAA672A9856ULL,
		0x2AA6ABBF39B08B5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8744000000000000ULL,
		0xE04BD27721CA5CF2ULL,
		0x2300FDCD36EB9507ULL,
		0x31BFDE76BBD51577ULL,
		0xC9153E1AE5221F41ULL,
		0x61581096829FDD15ULL,
		0x2D6FA079AAA99CAAULL,
		0x0000AA9AAEFCE6C2ULL
	}};
	shift = 50;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x15EA1C37446E633EULL,
		0xE45DF07C50920419ULL,
		0xC7FDDD0902652DB8ULL,
		0xE604ABC1B02BC0FCULL,
		0x7F647309D91785ACULL,
		0xD1CE05EC1AD625CFULL,
		0xA42BABE7D2371B0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C00000000000000ULL,
		0x322BD4386E88DCC6ULL,
		0x71C8BBE0F8A12408ULL,
		0xF98FFBBA1204CA5BULL,
		0x59CC095783605781ULL,
		0x9EFEC8E613B22F0BULL,
		0x1FA39C0BD835AC4BULL,
		0x01485757CFA46E36ULL
	}};
	shift = 57;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA8B959B6A03E8CFBULL,
		0x9F795792AB843AEBULL,
		0x146353F4C63A2A14ULL,
		0x39EFE8AC555CD5E9ULL,
		0xCD8666AE02F9CBBEULL,
		0xEE5F9D985A26AF0AULL,
		0xEEACA518CF991F57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D19F6000000000ULL,
		0x70875D75172B36D4ULL,
		0xC7454293EF2AF255ULL,
		0xAB9ABD228C6A7E98ULL,
		0x5F3977C73DFD158AULL,
		0x44D5E159B0CCD5C0ULL,
		0xF323EAFDCBF3B30BULL,
		0x0000001DD594A319ULL
	}};
	shift = 37;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF1859D3DAA74A49BULL,
		0x63C6031B62482C3DULL,
		0xE02A1F49D8C705A7ULL,
		0x1664648412CC7497ULL,
		0x6E3D1B59AD6B14F4ULL,
		0xC6C49C45C9456EF2ULL,
		0xD8CF628FBBA404CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A7B54E94936000ULL,
		0xC0636C490587BE30ULL,
		0x43E93B18E0B4EC78ULL,
		0x8C9082598E92FC05ULL,
		0xA36B35AD629E82CCULL,
		0x9388B928ADDE4DC7ULL,
		0xEC51F7748099F8D8ULL,
		0x0000000000001B19ULL
	}};
	shift = 13;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x66F917BA8CECBE07ULL,
		0x5721C46858C4BBE6ULL,
		0x7BDA876493313D9DULL,
		0x2851181BD8DF2FB1ULL,
		0x40933435F5D14737ULL,
		0x8C7B387A6847BEA6ULL,
		0xF6CBE42D705988D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD46765F0380000ULL,
		0x2342C625DF3337C8ULL,
		0x3B249989ECEAB90EULL,
		0xC0DEC6F97D8BDED4ULL,
		0xA1AFAE8A39B94288ULL,
		0xC3D3423DF5320499ULL,
		0x216B82CC46A463D9ULL,
		0x000000000007B65FULL
	}};
	shift = 19;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5E038278F5459628ULL,
		0x67704A81FEC5200BULL,
		0x66BB98BE5D8BB787ULL,
		0x65C669425482D615ULL,
		0x79F46E8A48EB8EDEULL,
		0x9C9FD88F900346BBULL,
		0x10FEA197BE1691D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58A0000000000000ULL,
		0x802D780E09E3D516ULL,
		0xDE1D9DC12A07FB14ULL,
		0x58559AEE62F9762EULL,
		0x3B799719A509520BULL,
		0x1AEDE7D1BA2923AEULL,
		0x475E727F623E400DULL,
		0x000043FA865EF85AULL
	}};
	shift = 50;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x25CFEE0B052D1C92ULL,
		0xAAF72A027C1524E9ULL,
		0x44B727E0F8F75454ULL,
		0x7BDD2EF3B829333EULL,
		0x06CBB1387719FEE8ULL,
		0xACF18F9CE1684DBAULL,
		0x0B2E3754F0E29323ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE0B052D1C92000ULL,
		0x72A027C1524E925CULL,
		0x727E0F8F75454AAFULL,
		0xD2EF3B829333E44BULL,
		0xBB1387719FEE87BDULL,
		0x18F9CE1684DBA06CULL,
		0xE3754F0E29323ACFULL,
		0x00000000000000B2ULL
	}};
	shift = 12;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xEF935A71F5D6B383ULL,
		0xB130B4072A12BDE8ULL,
		0x0BA3EBB4AD0AA1C5ULL,
		0x1FD2828F05EB6361ULL,
		0x8AF6B6E2618B9B1AULL,
		0xCC2F33AD835EBE6DULL,
		0x160D1A5BBCD3D2A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D75ACE0C000000ULL,
		0x1CA84AF7A3BE4D69ULL,
		0xD2B42A8716C4C2D0ULL,
		0x3C17AD8D842E8FAEULL,
		0x89862E6C687F4A0AULL,
		0xB60D7AF9B62BDADBULL,
		0x6EF34F4A8330BCCEULL,
		0x0000000000583469ULL
	}};
	shift = 26;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA45FC8521CD1E67FULL,
		0x584362D3BABC1F4CULL,
		0x0141F90D266640F8ULL,
		0x342821B2E189DFEAULL,
		0x09F569C062A23931ULL,
		0x79510AD600DCC09FULL,
		0x07EC0A3FF3B0448AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD1E67F00000000ULL,
		0xBABC1F4CA45FC852ULL,
		0x266640F8584362D3ULL,
		0xE189DFEA0141F90DULL,
		0x62A23931342821B2ULL,
		0x00DCC09F09F569C0ULL,
		0xF3B0448A79510AD6ULL,
		0x0000000007EC0A3FULL
	}};
	shift = 32;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x34E1A74DC5DD636FULL,
		0x8C61811E2E7DAF78ULL,
		0xAE7F9364D9C35745ULL,
		0x09E48CEEE7E9926DULL,
		0x51D9030EA5D548DCULL,
		0x4E31C117918DBC70ULL,
		0x5B989F264694DA09ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70D3A6E2EEB1B78ULL,
		0x630C08F173ED7BC1ULL,
		0x73FC9B26CE1ABA2CULL,
		0x4F2467773F4C936DULL,
		0x8EC818752EAA46E0ULL,
		0x718E08BC8C6DE382ULL,
		0xDCC4F93234A6D04AULL,
		0x0000000000000002ULL
	}};
	shift = 3;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF7D8E1C0DE336201ULL,
		0x6D25A5D6366100F6ULL,
		0xE6983C4FC43E0221ULL,
		0xB33D83A54B7BA431ULL,
		0xB0BC4597A9373DC0ULL,
		0x5C4AB77AE7885E9BULL,
		0xB44F01F1F0BE5316ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC70E06F19B1008ULL,
		0x692D2EB1B30807B7ULL,
		0x34C1E27E21F0110BULL,
		0x99EC1D2A5BDD218FULL,
		0x85E22CBD49B9EE05ULL,
		0xE255BBD73C42F4DDULL,
		0xA2780F8F85F298B2ULL,
		0x0000000000000005ULL
	}};
	shift = 3;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE8C1D5F70AC2BFF2ULL,
		0xFA618C0E0A715952ULL,
		0x8FDA5B570BB59A85ULL,
		0x79D2674FC679CEFCULL,
		0xED1382AB819E7852ULL,
		0xC10E923936A41703ULL,
		0x3EFC0C35B371F152ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15857FE40000000ULL,
		0xC14E2B2A5D183ABEULL,
		0xE176B350BF4C3181ULL,
		0xF8CF39DF91FB4B6AULL,
		0x7033CF0A4F3A4CE9ULL,
		0x26D482E07DA27055ULL,
		0xB66E3E2A5821D247ULL,
		0x0000000007DF8186ULL
	}};
	shift = 29;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0C49F6438081ECA1ULL,
		0x4AEC24D16E0261E8ULL,
		0x50848B54D226025FULL,
		0x9082F84D29D1C825ULL,
		0x5AB94F579A1CEA79ULL,
		0x555988A84BD8AEDCULL,
		0x7D5A10B97C57FFF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB21C040F6508000ULL,
		0x1268B70130F40624ULL,
		0x45AA6913012FA576ULL,
		0x7C2694E8E412A842ULL,
		0xA7ABCD0E753CC841ULL,
		0xC45425EC576E2D5CULL,
		0x085CBE2BFFF82AACULL,
		0x0000000000003EADULL
	}};
	shift = 15;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2285913975E8654AULL,
		0xA5FCBCE89DAE347BULL,
		0x92EFDC0EA857BC6EULL,
		0xA58C5E40DE0F7629ULL,
		0xEC037D1A8D8BAC62ULL,
		0x8F9804A50885EE4FULL,
		0x825DD69B0E8CCEE5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72EBD0CA94000000ULL,
		0xD13B5C68F6450B22ULL,
		0x1D50AF78DD4BF979ULL,
		0x81BC1EEC5325DFB8ULL,
		0x351B1758C54B18BCULL,
		0x4A110BDC9FD806FAULL,
		0x361D199DCB1F3009ULL,
		0x000000000104BBADULL
	}};
	shift = 25;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3ADE65FD6654D758ULL,
		0xD2CA7425FC308274ULL,
		0x6275E319D4AD5024ULL,
		0x8A86AA182B24C3AFULL,
		0xF553F3BDA4432BE7ULL,
		0x80AA652AF97C0F4BULL,
		0x0350ED7949DC95B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32A6BAC00000000ULL,
		0xFE18413A1D6F32FEULL,
		0xEA56A81269653A12ULL,
		0x159261D7B13AF18CULL,
		0xD22195F3C543550CULL,
		0x7CBE07A5FAA9F9DEULL,
		0xA4EE4ADB40553295ULL,
		0x0000000001A876BCULL
	}};
	shift = 31;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x23E93551F81C896EULL,
		0x75EF4B60BE4455DDULL,
		0x1AFA8C6CE552D39CULL,
		0x6BB7518FBBDEBE02ULL,
		0x1193CF95DA947321ULL,
		0x7FA11CBF1F5BA554ULL,
		0xEC709A62F49AE924ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912DC00000000000ULL,
		0x8ABBA47D26AA3F03ULL,
		0x5A738EBDE96C17C8ULL,
		0xD7C0435F518D9CAAULL,
		0x8E642D76EA31F77BULL,
		0x74AA823279F2BB52ULL,
		0x5D248FF42397E3EBULL,
		0x00001D8E134C5E93ULL
	}};
	shift = 45;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE345DDB4769491B8ULL,
		0x2E918687129938D6ULL,
		0x1D020C73EEEBD511ULL,
		0x2535662D0724F510ULL,
		0x73057F30F737FDF1ULL,
		0x427259F5F003E21DULL,
		0xC4E8F045695EA28CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x776D1DA5246E0000ULL,
		0x61A1C4A64E35B8D1ULL,
		0x831CFBBAF5444BA4ULL,
		0x598B41C93D440740ULL,
		0x5FCC3DCDFF7C494DULL,
		0x967D7C00F8875CC1ULL,
		0x3C115A57A8A3109CULL,
		0x000000000000313AULL
	}};
	shift = 14;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xABE0F50F3F935360ULL,
		0x8652931C3FFB3999ULL,
		0x0B01231FC311FFEAULL,
		0xD236DBA65E913C16ULL,
		0x762224AC18CA7C04ULL,
		0xEF95786DEE08475DULL,
		0xCB3456CFDAC562C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D80000000000000ULL,
		0xE666AF83D43CFE4DULL,
		0xFFAA194A4C70FFECULL,
		0xF0582C048C7F0C47ULL,
		0xF01348DB6E997A44ULL,
		0x1D75D88892B06329ULL,
		0x8B13BE55E1B7B821ULL,
		0x00032CD15B3F6B15ULL
	}};
	shift = 50;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF37D6E40EEEB868AULL,
		0x684ED156A45C5B9EULL,
		0x727C66EDA80818B2ULL,
		0x418D2C40FD5532F0ULL,
		0x723B384A72F59A91ULL,
		0xBD5AA0D779667370ULL,
		0xD3CECE43111B5243ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EEEB868A000000ULL,
		0x56A45C5B9EF37D6EULL,
		0xEDA80818B2684ED1ULL,
		0x40FD5532F0727C66ULL,
		0x4A72F59A91418D2CULL,
		0xD779667370723B38ULL,
		0x43111B5243BD5AA0ULL,
		0x0000000000D3CECEULL
	}};
	shift = 24;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8A580EF9E01E7239ULL,
		0x3D927EF916211AABULL,
		0x20ACB05894D7710AULL,
		0x5AFC65BFCD5E6663ULL,
		0x9D85241EA8F3C502ULL,
		0x70E5482167367BF4ULL,
		0x8804ABB2BAB6C927ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE01E723900000000ULL,
		0x16211AAB8A580EF9ULL,
		0x94D7710A3D927EF9ULL,
		0xCD5E666320ACB058ULL,
		0xA8F3C5025AFC65BFULL,
		0x67367BF49D85241EULL,
		0xBAB6C92770E54821ULL,
		0x000000008804ABB2ULL
	}};
	shift = 32;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x72F30ABF0B70EF4FULL,
		0xF3D67830CBABE9B1ULL,
		0x216A5792B1F0B35AULL,
		0x5775BB998D9D9579ULL,
		0x6FE02C8AE863E75BULL,
		0xC240788E6656008DULL,
		0x854CE83B215FADA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD3C00000000000ULL,
		0xFA6C5CBCC2AFC2DCULL,
		0x2CD6BCF59E0C32EAULL,
		0x655E485A95E4AC7CULL,
		0xF9D6D5DD6EE66367ULL,
		0x80235BF80B22BA18ULL,
		0xEB68B0901E239995ULL,
		0x000021533A0EC857ULL
	}};
	shift = 46;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6523378A7D121DDFULL,
		0xF9F28E4A1CDF61F7ULL,
		0xDC827F31B67D04D4ULL,
		0xCFD8A7DC0C9526D5ULL,
		0xE01247EC04C1DC5DULL,
		0x95CA6A823C11BBAEULL,
		0x330AB0B1C008464AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF000000000000000ULL,
		0x76523378A7D121DDULL,
		0x4F9F28E4A1CDF61FULL,
		0x5DC827F31B67D04DULL,
		0xDCFD8A7DC0C9526DULL,
		0xEE01247EC04C1DC5ULL,
		0xA95CA6A823C11BBAULL,
		0x0330AB0B1C008464ULL
	}};
	shift = 60;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC9427C003A43F203ULL,
		0x95D4932369212261ULL,
		0xF4A668123D939224ULL,
		0xEF8A0A9391F9DE36ULL,
		0xA695EC7815C3FB65ULL,
		0xA8995EA6F1F2983BULL,
		0x06807C60F41D457DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7487E40600000000ULL,
		0xD24244C39284F800ULL,
		0x7B2724492BA92646ULL,
		0x23F3BC6DE94CD024ULL,
		0x2B87F6CBDF141527ULL,
		0xE3E530774D2BD8F0ULL,
		0xE83A8AFB5132BD4DULL,
		0x000000000D00F8C1ULL
	}};
	shift = 33;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC58BDCEB51DF4C00ULL,
		0x3C869840652FBE01ULL,
		0xBD71D1267E5463D1ULL,
		0x1111BC95958AE5DAULL,
		0x25D8F67A34931306ULL,
		0xBEDDA67CDBE46551ULL,
		0x579E8F9E107AEAC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4C000000000000ULL,
		0x2FBE01C58BDCEB51ULL,
		0x5463D13C86984065ULL,
		0x8AE5DABD71D1267EULL,
		0x9313061111BC9595ULL,
		0xE4655125D8F67A34ULL,
		0x7AEAC1BEDDA67CDBULL,
		0x000000579E8F9E10ULL
	}};
	shift = 40;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB57792AEDFFC1242ULL,
		0x064D02247FC3AB4CULL,
		0x334984C9BD52F046ULL,
		0xCFE63F8F7398F178ULL,
		0x7594863745F4BB3EULL,
		0x27C018E1D859D8A1ULL,
		0xC34D01EB20126963ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92AEDFFC12420000ULL,
		0x02247FC3AB4CB577ULL,
		0x84C9BD52F046064DULL,
		0x3F8F7398F1783349ULL,
		0x863745F4BB3ECFE6ULL,
		0x18E1D859D8A17594ULL,
		0x01EB2012696327C0ULL,
		0x000000000000C34DULL
	}};
	shift = 16;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4A9D3986448F0D9DULL,
		0xB1BFB9900BEF752CULL,
		0xAD76F4A55BA110CAULL,
		0x278886CAD903FD13ULL,
		0x787A37A7F3B7F4CDULL,
		0x3D13547C3B3E0084ULL,
		0xB37FCC51E08AAB69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D9D00000000000ULL,
		0xF752C4A9D3986448ULL,
		0x110CAB1BFB9900BEULL,
		0x3FD13AD76F4A55BAULL,
		0x7F4CD278886CAD90ULL,
		0xE0084787A37A7F3BULL,
		0xAAB693D13547C3B3ULL,
		0x00000B37FCC51E08ULL
	}};
	shift = 44;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x73A56B5BFDAB748EULL,
		0x17716DEBC0766847ULL,
		0xA7EA800900608945ULL,
		0x6D919553D88BE015ULL,
		0x73D69630BC766A2AULL,
		0x2A524425AE7A9C23ULL,
		0x7864E32D9B8DBC7CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB56E91C000000000ULL,
		0x0ECD08EE74AD6B7FULL,
		0x0C1128A2EE2DBD78ULL,
		0x117C02B4FD500120ULL,
		0x8ECD454DB232AA7BULL,
		0xCF53846E7AD2C617ULL,
		0x71B78F854A4884B5ULL,
		0x0000000F0C9C65B3ULL
	}};
	shift = 37;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7E2DCC68AF52A843ULL,
		0xC15C8E37CED6821DULL,
		0xF3BC442A3A9BD256ULL,
		0x712B9220AF7460BBULL,
		0x0BFF81214F2EAE8BULL,
		0x925203029EE173B5ULL,
		0xEB5F93F774216B57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF52A843000000000ULL,
		0xED6821D7E2DCC68AULL,
		0xA9BD256C15C8E37CULL,
		0xF7460BBF3BC442A3ULL,
		0xF2EAE8B712B9220AULL,
		0xEE173B50BFF81214ULL,
		0x4216B57925203029ULL,
		0x0000000EB5F93F77ULL
	}};
	shift = 36;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA38E4E30B98F68C8ULL,
		0xBF9B06B07079018AULL,
		0x5C161C29E41D3BC8ULL,
		0x9452D4D238B1E220ULL,
		0xCA97CAEE9E42956CULL,
		0x923E262DE561E32BULL,
		0x30A335AB241B30CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63DA32000000000ULL,
		0xC1E4062A8E3938C2ULL,
		0x9074EF22FE6C1AC1ULL,
		0xE2C78881705870A7ULL,
		0x790A55B2514B5348ULL,
		0x95878CAF2A5F2BBAULL,
		0x906CC33E48F898B7ULL,
		0x00000000C28CD6ACULL
	}};
	shift = 34;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3ED210541EECDAC4ULL,
		0xFFC3734B28C04A0CULL,
		0xC20A1DC35434F0B7ULL,
		0xF0C5482AC215D491ULL,
		0xC212A833D23CCAEAULL,
		0xA1D88BAAC1B8BE9BULL,
		0xD52E46120B209B1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1F69082A0F766D62ULL,
		0xFFE1B9A594602506ULL,
		0xE1050EE1AA1A785BULL,
		0x7862A415610AEA48ULL,
		0xE1095419E91E6575ULL,
		0x50EC45D560DC5F4DULL,
		0x6A97230905904D8DULL
	}};
	shift = 63;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9C603DCF4DE7D5CEULL,
		0xD6352B82FB228C6FULL,
		0x8C8F2B4E6CBF8297ULL,
		0x2253E2896AC4928FULL,
		0x5D6F5D7ED988644AULL,
		0xF9D4FF01CCE251FEULL,
		0x2AAF6757D227EF31ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD379F57380000000ULL,
		0xBEC8A31BE7180F73ULL,
		0x9B2FE0A5F58D4AE0ULL,
		0x5AB124A3E323CAD3ULL,
		0xB66219128894F8A2ULL,
		0x7338947F975BD75FULL,
		0xF489FBCC7E753FC0ULL,
		0x000000000AABD9D5ULL
	}};
	shift = 30;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0D5D167BADCD1F98ULL,
		0x4CD42FB8E1094CC6ULL,
		0x68AB02E340131D37ULL,
		0xFDE24588FF8BEAE2ULL,
		0x5818789EB98CFEADULL,
		0x13BF92B468260167ULL,
		0x3981D6F7DC64C054ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75B9A3F30000000ULL,
		0x71C212998C1ABA2CULL,
		0xC680263A6E99A85FULL,
		0x11FF17D5C4D15605ULL,
		0x3D7319FD5BFBC48BULL,
		0x68D04C02CEB030F1ULL,
		0xEFB8C980A8277F25ULL,
		0x00000000007303ADULL
	}};
	shift = 25;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD038E5A3B518CBA4ULL,
		0xAEBA5BB044468960ULL,
		0x706AEC604877EA9EULL,
		0xE560885163D7BA80ULL,
		0xB6CBEAD390D628DDULL,
		0x81EC78069CC93CFEULL,
		0x9C6728B40FD7155AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D1DA8C65D20000ULL,
		0x2DD8222344B0681CULL,
		0x7630243BF54F575DULL,
		0x4428B1EBDD403835ULL,
		0xF569C86B146EF2B0ULL,
		0x3C034E649E7F5B65ULL,
		0x945A07EB8AAD40F6ULL,
		0x0000000000004E33ULL
	}};
	shift = 15;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x43EF9CDA6A4DFADCULL,
		0x5EA7589F043AA3A6ULL,
		0x55EF5097EEA27912ULL,
		0x673691A505157DD7ULL,
		0xFEC8C09EA54FF3C2ULL,
		0x9B9DE00117D83FFBULL,
		0xBB93112A6CA8F432ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x369A937EB7000000ULL,
		0x27C10EA8E990FBE7ULL,
		0x25FBA89E4497A9D6ULL,
		0x6941455F75D57BD4ULL,
		0x27A953FCF099CDA4ULL,
		0x0045F60FFEFFB230ULL,
		0x4A9B2A3D0CA6E778ULL,
		0x00000000002EE4C4ULL
	}};
	shift = 22;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6388742911DE9FE2ULL,
		0x446C727E4A879B4AULL,
		0x92E2B47AF4264ED1ULL,
		0x86220EDD234BC8EEULL,
		0x6F38AE1A866232FDULL,
		0x57C9E6A158443EE8ULL,
		0xB01BBBDAE974A9E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF4FF1000000000ULL,
		0x543CDA531C43A148ULL,
		0xA132768A236393F2ULL,
		0x1A5E47749715A3D7ULL,
		0x331197EC311076E9ULL,
		0xC221F74379C570D4ULL,
		0x4BA54F42BE4F350AULL,
		0x0000000580DDDED7ULL
	}};
	shift = 35;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB300EE57B6FC83D9ULL,
		0x880E108D5BEDBC2FULL,
		0xC955208E01C57A9AULL,
		0x373BE671666392D9ULL,
		0x017151A93FF95ED3ULL,
		0x80A5DF71E70E6695ULL,
		0x50A00D2279674E8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01DCAF6DF907B200ULL,
		0x1C211AB7DB785F66ULL,
		0xAA411C038AF53510ULL,
		0x77CCE2CCC725B392ULL,
		0xE2A3527FF2BDA66EULL,
		0x4BBEE3CE1CCD2A02ULL,
		0x401A44F2CE9D1F01ULL,
		0x00000000000000A1ULL
	}};
	shift = 9;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7FE3638EAD58CB07ULL,
		0xDC6D6FC42AD144DDULL,
		0xBC59E2C033785B4EULL,
		0x839B36141D35D2C0ULL,
		0xB1472AA1A07372CEULL,
		0xF6B8A2CA0546001DULL,
		0xFCB758D08FD99AEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B1C756AC658380ULL,
		0x36B7E21568A26EBFULL,
		0x2CF16019BC2DA76EULL,
		0xCD9B0A0E9AE9605EULL,
		0xA39550D039B96741ULL,
		0x5C516502A3000ED8ULL,
		0x5BAC6847ECCD757BULL,
		0x000000000000007EULL
	}};
	shift = 7;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8BCF92ACF083BBE5ULL,
		0x1E20959BBE160007ULL,
		0x77F65CE48D00FCB2ULL,
		0xF1326B9EA538E3FCULL,
		0x78E9F247164C850DULL,
		0xC7CA106A7D0BE2E0ULL,
		0x987B22381F18140AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3E4AB3C20EEF940ULL,
		0x882566EF858001E2ULL,
		0xFD973923403F2C87ULL,
		0x4C9AE7A94E38FF1DULL,
		0x3A7C91C59321437CULL,
		0xF2841A9F42F8B81EULL,
		0x1EC88E07C60502B1ULL,
		0x0000000000000026ULL
	}};
	shift = 6;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE1DDBF95B5272D7FULL,
		0x172B34B7CA573F44ULL,
		0x72392A2B33AD075AULL,
		0xC34F13C9EA464E78ULL,
		0x3A01B999184726E9ULL,
		0x57C2064484804906ULL,
		0xE22F52E5506D8782ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F0000000000000ULL,
		0xF44E1DDBF95B5272ULL,
		0x75A172B34B7CA573ULL,
		0xE7872392A2B33AD0ULL,
		0x6E9C34F13C9EA464ULL,
		0x9063A01B99918472ULL,
		0x78257C2064484804ULL,
		0x000E22F52E5506D8ULL
	}};
	shift = 52;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC4DACCC2139FFD32ULL,
		0xDA64B4B32B707B98ULL,
		0x8829C5F8974DDF0DULL,
		0xDA64FEE29977A822ULL,
		0x5F17686A9FD780B8ULL,
		0xFA48ED398109C974ULL,
		0x2A3817C585803A20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09CFFE9900000000ULL,
		0x95B83DCC626D6661ULL,
		0x4BA6EF86ED325A59ULL,
		0x4CBBD4114414E2FCULL,
		0x4FEBC05C6D327F71ULL,
		0xC084E4BA2F8BB435ULL,
		0xC2C01D107D24769CULL,
		0x00000000151C0BE2ULL
	}};
	shift = 31;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF95DD40F576BE761ULL,
		0x3C8B6622781C7E7AULL,
		0xAF531AC31FAC944AULL,
		0x34E173EADC6B3FF3ULL,
		0x910C22325BB358AFULL,
		0x384A5CE16D97A913ULL,
		0x7D423B6C107B2DA0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE577503D5DAF9D84ULL,
		0xF22D9889E071F9EBULL,
		0xBD4C6B0C7EB25128ULL,
		0xD385CFAB71ACFFCEULL,
		0x443088C96ECD62BCULL,
		0xE1297385B65EA44EULL,
		0xF508EDB041ECB680ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7234E2C96B170765ULL,
		0x5FE5942F401AA600ULL,
		0xC2C6AE8D3CCA1ED3ULL,
		0x671A0226F963BC12ULL,
		0x1EFAB633B6A98A7DULL,
		0xB75EECEC82A29909ULL,
		0xCC913442D6A11E38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7164B58B83B28000ULL,
		0xCA17A00D5300391AULL,
		0x57469E650F69AFF2ULL,
		0x01137CB1DE096163ULL,
		0x5B19DB54C53EB38DULL,
		0x767641514C848F7DULL,
		0x9A216B508F1C5BAFULL,
		0x0000000000006648ULL
	}};
	shift = 15;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x30F3BCBD0CB5A115ULL,
		0xC26FD04F49D91B6AULL,
		0x0167A2A9E481227CULL,
		0x32A83220C2B103B1ULL,
		0x10C5A06F2F67422DULL,
		0xD5BF10B961F4EDE2ULL,
		0x6686098E6C906DBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x1879DE5E865AD08AULL,
		0x6137E827A4EC8DB5ULL,
		0x80B3D154F240913EULL,
		0x99541910615881D8ULL,
		0x0862D03797B3A116ULL,
		0x6ADF885CB0FA76F1ULL,
		0x334304C7364836DEULL
	}};
	shift = 63;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x600FBB71E629B215ULL,
		0x58EA6D2D03F23AE1ULL,
		0xA0BB3A13CBCECA39ULL,
		0x52239BB843D5DF2FULL,
		0xDD9D42DFF68EA9C7ULL,
		0xBC820C1DFDEF7833ULL,
		0x6D8A2A6AFCB27945ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A00000000000000ULL,
		0xC2C01F76E3CC5364ULL,
		0x72B1D4DA5A07E475ULL,
		0x5F41767427979D94ULL,
		0x8EA447377087ABBEULL,
		0x67BB3A85BFED1D53ULL,
		0x8B7904183BFBDEF0ULL,
		0x00DB1454D5F964F2ULL
	}};
	shift = 57;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x482D1D314FAF5EF0ULL,
		0xF381C8838697D584ULL,
		0x8FDAE39F34BBFF6EULL,
		0x8F930C53A9AB85ACULL,
		0x1E1E45B841AFDE70ULL,
		0x0205A6FF781BDD42ULL,
		0x7DA77623C74C0DE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF5EF0000000000ULL,
		0x697D584482D1D314ULL,
		0x4BBFF6EF381C8838ULL,
		0x9AB85AC8FDAE39F3ULL,
		0x1AFDE708F930C53AULL,
		0x81BDD421E1E45B84ULL,
		0x74C0DE70205A6FF7ULL,
		0x00000007DA77623CULL
	}};
	shift = 36;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x472965370B011D2AULL,
		0x29B45050BD6F47A7ULL,
		0xBAFBE02FAF82EDFBULL,
		0xE596B06F58EBB777ULL,
		0xA8AB46FC57080165ULL,
		0x62857AF6FDAFA061ULL,
		0x42EEA59F96A4556FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA6E16023A540000ULL,
		0xA0A17ADE8F4E8E52ULL,
		0xC05F5F05DBF65368ULL,
		0x60DEB1D76EEF75F7ULL,
		0x8DF8AE1002CBCB2DULL,
		0xF5EDFB5F40C35156ULL,
		0x4B3F2D48AADEC50AULL,
		0x00000000000085DDULL
	}};
	shift = 17;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x258289C0791789B5ULL,
		0x2762384F419C26ADULL,
		0x5F1C2E2EFD339C8BULL,
		0x4921C86941101283ULL,
		0x4AC1659865CF765DULL,
		0x8F7F2E639DC98238ULL,
		0x971640FA1CA7494AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B50000000000000ULL,
		0x6AD258289C079178ULL,
		0xC8B2762384F419C2ULL,
		0x2835F1C2E2EFD339ULL,
		0x65D4921C86941101ULL,
		0x2384AC1659865CF7ULL,
		0x94A8F7F2E639DC98ULL,
		0x000971640FA1CA74ULL
	}};
	shift = 52;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6811D7975D3103ADULL,
		0xC6FB0D3389A76002ULL,
		0x91CBB5E7EC0DD172ULL,
		0xF76FB21398E68427ULL,
		0xB06F6981ADBA5695ULL,
		0x84C124A8AE0BB425ULL,
		0x3FF406465A22E887ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A0000000000000ULL,
		0x004D023AF2EBA620ULL,
		0x2E58DF61A67134ECULL,
		0x84F23976BCFD81BAULL,
		0xD2BEEDF642731CD0ULL,
		0x84B60DED3035B74AULL,
		0x10F098249515C176ULL,
		0x0007FE80C8CB445DULL
	}};
	shift = 53;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB8D8AA3A5B1A07A6ULL,
		0x5B9766B57358DCEAULL,
		0x808ABB8428D405E3ULL,
		0x990EA6D8221C5BA2ULL,
		0xFA9F7FBE25FE4EF4ULL,
		0x3110921B44D9896DULL,
		0x58765F4B27ECB8EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D3000000000000ULL,
		0x6E755C6C551D2D8DULL,
		0x02F1ADCBB35AB9ACULL,
		0x2DD140455DC2146AULL,
		0x277A4C87536C110EULL,
		0xC4B6FD4FBFDF12FFULL,
		0x5C751888490DA26CULL,
		0x00002C3B2FA593F6ULL
	}};
	shift = 47;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x40A7AD36B2931DF7ULL,
		0x8C92E4B84834D0C4ULL,
		0x6B71A3DE2426F7E1ULL,
		0xF3C265BECA922EBDULL,
		0x0A88F6E5A5DC5144ULL,
		0xD7A1B7881913926EULL,
		0xB964B67ABA2AD0FBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x498EFB8000000000ULL,
		0x1A68622053D69B59ULL,
		0x137BF0C649725C24ULL,
		0x49175EB5B8D1EF12ULL,
		0xEE28A279E132DF65ULL,
		0x89C93705447B72D2ULL,
		0x15687DEBD0DBC40CULL,
		0x0000005CB25B3D5DULL
	}};
	shift = 39;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFA2D748CE7FF8992ULL,
		0x32217A4ADC3C26FBULL,
		0xE13B1203782814FBULL,
		0xBFDE612BA88507BAULL,
		0x5193AB4DCBE46C0EULL,
		0x9C3D3B95971EB284ULL,
		0x368E77DA498C6F68ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE919CFFF1324000ULL,
		0x2F495B8784DF7F45ULL,
		0x62406F05029F6644ULL,
		0xCC257510A0F75C27ULL,
		0x7569B97C8D81D7FBULL,
		0xA772B2E3D6508A32ULL,
		0xCEFB49318DED1387ULL,
		0x00000000000006D1ULL
	}};
	shift = 13;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xA5E8AC89A811E688ULL,
		0x421007EB4DBB2049ULL,
		0xBC404F19A42B75F4ULL,
		0xF414B750666539A3ULL,
		0x979E3BB41CB7EE38ULL,
		0x09BE499239225F71ULL,
		0x44E45642B8633360ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E68800000000000ULL,
		0xB2049A5E8AC89A81ULL,
		0xB75F4421007EB4DBULL,
		0x539A3BC404F19A42ULL,
		0x7EE38F414B750666ULL,
		0x25F71979E3BB41CBULL,
		0x3336009BE4992392ULL,
		0x0000044E45642B86ULL
	}};
	shift = 44;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9ECDC8F4B1B7368BULL,
		0xEE20DD208AB423EAULL,
		0xAB4D8946AFCCFBF5ULL,
		0x2CFA28EAB248F239ULL,
		0x563EF4FB382FA2E1ULL,
		0x030B2E2B3E20088FULL,
		0x50A58ED760CFE91FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B91E9636E6D1600ULL,
		0x41BA41156847D53DULL,
		0x9B128D5F99F7EBDCULL,
		0xF451D56491E47356ULL,
		0x7DE9F6705F45C259ULL,
		0x165C567C40111EACULL,
		0x4B1DAEC19FD23E06ULL,
		0x00000000000000A1ULL
	}};
	shift = 9;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x354DCF92DF973BBEULL,
		0x6BCF1544C0EDF14BULL,
		0x2EB915AE5E551B58ULL,
		0x32C448DD69776CCCULL,
		0x87505A70E528A3E6ULL,
		0x55A400E7E63989D0ULL,
		0x7E3FD457C522DD59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF92DF973BBE0000ULL,
		0x1544C0EDF14B354DULL,
		0x15AE5E551B586BCFULL,
		0x48DD69776CCC2EB9ULL,
		0x5A70E528A3E632C4ULL,
		0x00E7E63989D08750ULL,
		0xD457C522DD5955A4ULL,
		0x0000000000007E3FULL
	}};
	shift = 16;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1102570123EBDCB7ULL,
		0xE121D5B5C3474675ULL,
		0xD10D9B7C55A6DE37ULL,
		0x0BDF606103B5C701ULL,
		0x16E1E5B603614E20ULL,
		0x6D501E7E8915633DULL,
		0x991EDF6FB49B70C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB700000000000000ULL,
		0x751102570123EBDCULL,
		0x37E121D5B5C34746ULL,
		0x01D10D9B7C55A6DEULL,
		0x200BDF606103B5C7ULL,
		0x3D16E1E5B603614EULL,
		0xC06D501E7E891563ULL,
		0x00991EDF6FB49B70ULL
	}};
	shift = 56;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6C269934ECCEE534ULL,
		0x82F882F2C03701B0ULL,
		0x82CC10D8CB9F41AAULL,
		0xC44845EBAADE9225ULL,
		0x1A0D8A7C31BA9C06ULL,
		0xA074D444F0CB52FAULL,
		0x484F19E46A604EEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D99DCA680000000ULL,
		0x5806E0360D84D326ULL,
		0x1973E835505F105EULL,
		0x755BD244B059821BULL,
		0x86375380D88908BDULL,
		0x9E196A5F4341B14FULL,
		0x8D4C09DD540E9A88ULL,
		0x000000000909E33CULL
	}};
	shift = 29;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xDEC8015129C6C793ULL,
		0x9B8DAF801DF9F47EULL,
		0x76DC746784205F2AULL,
		0xA6CD606B3A586981ULL,
		0x83D5F0BADB202081ULL,
		0x4A8B4EB4C884A9A6ULL,
		0xD4C79CC1EBCC1D63ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x363C980000000000ULL,
		0xCFA3F6F6400A894EULL,
		0x02F954DC6D7C00EFULL,
		0xC34C0BB6E3A33C21ULL,
		0x01040D366B0359D2ULL,
		0x254D341EAF85D6D9ULL,
		0x60EB1A545A75A644ULL,
		0x000006A63CE60F5EULL
	}};
	shift = 43;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x137D96F7EDEA0B9BULL,
		0xB9CC212D5F64A097ULL,
		0x53084A8FD60FC9E1ULL,
		0x5F41BDF6CC465F14ULL,
		0xED6EB7977C8E73C3ULL,
		0x1EFD895E4D2E7703ULL,
		0x7EFAD7E4091D9BE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B00000000000000ULL,
		0x97137D96F7EDEA0BULL,
		0xE1B9CC212D5F64A0ULL,
		0x1453084A8FD60FC9ULL,
		0xC35F41BDF6CC465FULL,
		0x03ED6EB7977C8E73ULL,
		0xE71EFD895E4D2E77ULL,
		0x007EFAD7E4091D9BULL
	}};
	shift = 56;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x74A26E5679780E2BULL,
		0x21C5D69A1FFA10C1ULL,
		0x03C8D6AB93529803ULL,
		0xC709FB06410ABA6CULL,
		0xFB3A783C5C0578C2ULL,
		0x8C3D6B508D787BF4ULL,
		0x382B69D9D3DADDA9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F01C56000000000ULL,
		0xFF42182E944DCACFULL,
		0x6A53006438BAD343ULL,
		0x21574D80791AD572ULL,
		0x80AF1858E13F60C8ULL,
		0xAF0F7E9F674F078BULL,
		0x7B5BB53187AD6A11ULL,
		0x00000007056D3B3AULL
	}};
	shift = 37;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x26C3D3FB90CDBB5CULL,
		0x6CE58CCC7CE38B4FULL,
		0xD3B767766294E882ULL,
		0x95A1DB38269A105FULL,
		0x962DB994B1CC9A00ULL,
		0x01D85C970ACE8F80ULL,
		0x82E9883F5E4EFE52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDAE000000000000ULL,
		0xC5A79361E9FDC866ULL,
		0x74413672C6663E71ULL,
		0x082FE9DBB3BB314AULL,
		0x4D004AD0ED9C134DULL,
		0x47C04B16DCCA58E6ULL,
		0x7F2900EC2E4B8567ULL,
		0x00004174C41FAF27ULL
	}};
	shift = 47;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC68EED48873F71ADULL,
		0xB1C7FB56CBE05522ULL,
		0xBA9D4E791B21308CULL,
		0x9845A6F96FE4BD25ULL,
		0xAD718D1748751F66ULL,
		0x4FB76DF06DE7FA01ULL,
		0xC6FD652F3CD72A6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EE35A000000000ULL,
		0x7C0AA458D1DDA910ULL,
		0x6426119638FF6AD9ULL,
		0xFC97A4B753A9CF23ULL,
		0x0EA3ECD308B4DF2DULL,
		0xBCFF4035AE31A2E9ULL,
		0x9AE54DC9F6EDBE0DULL,
		0x00000018DFACA5E7ULL
	}};
	shift = 37;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x339071AF4B80E5D5ULL,
		0x8CFC3748EF9CEA8CULL,
		0xDE196901D2C56BB9ULL,
		0x2F3D86F3C1619F17ULL,
		0x28942C1E91D4C107ULL,
		0xD59CF5A674EEDCC6ULL,
		0x90052F7B3C7D0710ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D7A5C072EA8000ULL,
		0x1BA477CE754619C8ULL,
		0xB480E962B5DCC67EULL,
		0xC379E0B0CF8BEF0CULL,
		0x160F48EA6083979EULL,
		0x7AD33A776E63144AULL,
		0x97BD9E3E83886ACEULL,
		0x0000000000004802ULL
	}};
	shift = 15;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6F8B917CECEAA6F8ULL,
		0xE22306CAA7ECB7A4ULL,
		0x0486580824166EB4ULL,
		0x8DC07E7EB88E4312ULL,
		0xFBCE2C02FA5D9BB7ULL,
		0xB9140B61292A1EF4ULL,
		0x8669DB879CE6175CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x237C5C8BE7675537ULL,
		0xA7111836553F65BDULL,
		0x902432C04120B375ULL,
		0xBC6E03F3F5C47218ULL,
		0xA7DE716017D2ECDDULL,
		0xE5C8A05B094950F7ULL,
		0x04334EDC3CE730BAULL
	}};
	shift = 59;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF6637961AD7899B1ULL,
		0x74415CE03BEB3932ULL,
		0xBAFAC904B8E61EFBULL,
		0xFDD716E810269602ULL,
		0x9EE8443262415291ULL,
		0xF5286500C69F7548ULL,
		0x1DD695CCA4D251CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE586B5E266C40000ULL,
		0x7380EFACE4CBD98DULL,
		0x2412E3987BEDD105ULL,
		0x5BA0409A580AEBEBULL,
		0x10C989054A47F75CULL,
		0x94031A7DD5227BA1ULL,
		0x57329349473FD4A1ULL,
		0x000000000000775AULL
	}};
	shift = 18;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD2EFE81BA03B94F1ULL,
		0x7D7CBC161DB0EE73ULL,
		0xBF7DA4CD2F84B9CAULL,
		0x4521AC3AF4BD0CBCULL,
		0x2C7C8376831586CFULL,
		0xDCEA52CE188BC9BCULL,
		0x0AA646AF06E0AFA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C4000000000000ULL,
		0xB9CF4BBFA06E80EEULL,
		0xE729F5F2F05876C3ULL,
		0x32F2FDF69334BE12ULL,
		0x1B3D1486B0EBD2F4ULL,
		0x26F0B1F20DDA0C56ULL,
		0xBE8B73A94B38622FULL,
		0x00002A991ABC1B82ULL
	}};
	shift = 50;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x98B6256EBB013D02ULL,
		0xEE02B6C122A3393BULL,
		0xEE312EF35AC5F964ULL,
		0x00282C9149CE7620ULL,
		0x802FA26762F5DC20ULL,
		0xA029DC825A80EC27ULL,
		0xFCDE20E886D43FD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xE62D895BAEC04F40ULL,
		0x3B80ADB048A8CE4EULL,
		0x3B8C4BBCD6B17E59ULL,
		0x000A0B2452739D88ULL,
		0xE00BE899D8BD7708ULL,
		0xE80A772096A03B09ULL,
		0x3F37883A21B50FF5ULL
	}};
	shift = 62;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xFDFCAA3DC47B5D7DULL,
		0x7BAC927EE3BA1192ULL,
		0xCA1689599BF34C9BULL,
		0xE4BE4BF87F866B23ULL,
		0x27091AC22606661BULL,
		0xC2FD03B38AA3C972ULL,
		0x7EEA4D60FD5AC03AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DC47B5D7D00000ULL,
		0x27EE3BA1192FDFCAULL,
		0x9599BF34C9B7BAC9ULL,
		0xBF87F866B23CA168ULL,
		0xAC22606661BE4BE4ULL,
		0x3B38AA3C97227091ULL,
		0xD60FD5AC03AC2FD0ULL,
		0x000000000007EEA4ULL
	}};
	shift = 20;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x40AAF8D8306C33BDULL,
		0x4E55446875ACC71CULL,
		0x2372422338405041ULL,
		0x4662B6C0BC05AB0CULL,
		0xCCEB7B28FA8A070BULL,
		0x494F185836595D98ULL,
		0x18C594207447FF6AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD0000000000000ULL,
		0x71C40AAF8D8306C3ULL,
		0x0414E55446875ACCULL,
		0xB0C2372422338405ULL,
		0x70B4662B6C0BC05AULL,
		0xD98CCEB7B28FA8A0ULL,
		0xF6A494F185836595ULL,
		0x00018C594207447FULL
	}};
	shift = 52;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0C96041809968A0AULL,
		0x577D8676743F1C55ULL,
		0xB6312A56B782D8F2ULL,
		0x948054DD400D1312ULL,
		0xD4BD41DBA666E543ULL,
		0xCE18E226C1F66898ULL,
		0x0BF167A989834B69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A0A000000000000ULL,
		0x1C550C9604180996ULL,
		0xD8F2577D8676743FULL,
		0x1312B6312A56B782ULL,
		0xE543948054DD400DULL,
		0x6898D4BD41DBA666ULL,
		0x4B69CE18E226C1F6ULL,
		0x00000BF167A98983ULL
	}};
	shift = 48;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6E203092AC7ECF7AULL,
		0x936FD6FB0B8A257AULL,
		0x2223B7D200BDC304ULL,
		0xF44A96A397AAEEC8ULL,
		0xD4E88F6E5D3FEDA6ULL,
		0x489D5BBFE2B391B4ULL,
		0x459B39A6C2267816ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FD9EF4000000000ULL,
		0x7144AF4DC4061255ULL,
		0x17B860926DFADF61ULL,
		0xF55DD9044476FA40ULL,
		0xA7FDB4DE8952D472ULL,
		0x5672369A9D11EDCBULL,
		0x44CF02C913AB77FCULL,
		0x00000008B36734D8ULL
	}};
	shift = 37;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF2730C286809C03CULL,
		0xD4C6126651D925FFULL,
		0x55BC6009C16DC905ULL,
		0xE6E36A169CEC75D7ULL,
		0x235B44E850F84665ULL,
		0x9CFB4E46A838D713ULL,
		0x4A187A7BF594E3FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61850D013807800ULL,
		0x8C24CCA3B24BFFE4ULL,
		0x78C01382DB920BA9ULL,
		0xC6D42D39D8EBAEABULL,
		0xB689D0A1F08CCBCDULL,
		0xF69C8D5071AE2646ULL,
		0x30F4F7EB29C7F539ULL,
		0x0000000000000094ULL
	}};
	shift = 9;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xC9406D74A71A8A47ULL,
		0x9F4C68654CA069E7ULL,
		0x0FEE37272493D99CULL,
		0x2E195A577380346EULL,
		0x707DB2F5E5F90379ULL,
		0x999FB781FE9251CFULL,
		0x1502FE3C1D0ADAB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9406D74A71A8A47ULL,
		0x9F4C68654CA069E7ULL,
		0x0FEE37272493D99CULL,
		0x2E195A577380346EULL,
		0x707DB2F5E5F90379ULL,
		0x999FB781FE9251CFULL,
		0x1502FE3C1D0ADAB6ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3BD8D3E2E5A86FCDULL,
		0x00AE5CA7493872F8ULL,
		0xFED83DE6E7B35C30ULL,
		0x07DE15FB663AF87BULL,
		0xDD328AA484E56692ULL,
		0xF71AFC71CACE7FC0ULL,
		0x0C12EE44A0155535ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF34000000000000ULL,
		0xCBE0EF634F8B96A1ULL,
		0x70C002B9729D24E1ULL,
		0xE1EFFB60F79B9ECDULL,
		0x9A481F7857ED98EBULL,
		0xFF0374CA2A921395ULL,
		0x54D7DC6BF1C72B39ULL,
		0x0000304BB9128055ULL
	}};
	shift = 50;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x942F925C621AED10ULL,
		0x479CD3846964875DULL,
		0x17E305AF4E93D286ULL,
		0x6402A4FDE9746B18ULL,
		0xA03051A634B30A81ULL,
		0x949E07C50DF93752ULL,
		0x48FCEA92ACFD77DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF24B8C435DA20000ULL,
		0x9A708D2C90EBB285ULL,
		0x60B5E9D27A50C8F3ULL,
		0x549FBD2E8D6302FCULL,
		0x0A34C69661502C80ULL,
		0xC0F8A1BF26EA5406ULL,
		0x9D52559FAEFB5293ULL,
		0x000000000000091FULL
	}};
	shift = 13;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x129EB205C6846124ULL,
		0xD184D09FD1EC1AADULL,
		0x2156365E2249BDF6ULL,
		0xF9FF6C59E1EEA148ULL,
		0x4ABFCFA477B15B84ULL,
		0xD2E738C4EFAE36D3ULL,
		0xE310749AB3636E78ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9000000000000000ULL,
		0xB44A7AC8171A1184ULL,
		0xDB4613427F47B06AULL,
		0x208558D9788926F7ULL,
		0x13E7FDB16787BA85ULL,
		0x4D2AFF3E91DEC56EULL,
		0xE34B9CE313BEB8DBULL,
		0x038C41D26ACD8DB9ULL
	}};
	shift = 58;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0B3BB7053039CE59ULL,
		0xFCE13CC6AA1CCA72ULL,
		0xFFAB215EBBB68771ULL,
		0xFE00AAC6770255CDULL,
		0x617DA2EC94C941CBULL,
		0x6ADE7069045408E3ULL,
		0x02DD72E3C715D5C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x416776E0A60739CBULL,
		0x3F9C2798D543994EULL,
		0xBFF5642BD776D0EEULL,
		0x7FC01558CEE04AB9ULL,
		0x6C2FB45D92992839ULL,
		0x4D5BCE0D208A811CULL,
		0x005BAE5C78E2BAB8ULL
	}};
	shift = 61;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x40ADD2DF30281AEAULL,
		0x041F8CBA0C20A058ULL,
		0xA6DCA5D61740A69DULL,
		0x14B08AB96D62AC2FULL,
		0x27B5D149C2D7EE63ULL,
		0xCAAA13EA32047FFDULL,
		0x7539CEE3272C0536ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CC0A06BA8000000ULL,
		0xE83082816102B74BULL,
		0x585D029A74107E32ULL,
		0xE5B58AB0BE9B7297ULL,
		0x270B5FB98C52C22AULL,
		0xA8C811FFF49ED745ULL,
		0x8C9CB014DB2AA84FULL,
		0x0000000001D4E73BULL
	}};
	shift = 26;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD0B72DEF51486A1AULL,
		0x512C8C9AEB8FD61AULL,
		0x79D02567265178E5ULL,
		0xCC30BDDDC9A1945CULL,
		0x90C5875A14A0893EULL,
		0xA9D1877952A016DBULL,
		0x60B5A27E16B268DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3400000000000000ULL,
		0x35A16E5BDEA290D4ULL,
		0xCAA2591935D71FACULL,
		0xB8F3A04ACE4CA2F1ULL,
		0x7D98617BBB934328ULL,
		0xB7218B0EB4294112ULL,
		0xBF53A30EF2A5402DULL,
		0x00C16B44FC2D64D1ULL
	}};
	shift = 57;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x05498F88EE6DEC96ULL,
		0x7945A32D5AE2AD37ULL,
		0x4A08FA113D1C6C8BULL,
		0xC75EA1F67F832D2FULL,
		0x919E78BB9082D243ULL,
		0xE6FE6603BE68EA9BULL,
		0x100171FA4C7F86E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F64B00000000000ULL,
		0x1569B82A4C7C4773ULL,
		0xE3645BCA2D196AD7ULL,
		0x19697A5047D089E8ULL,
		0x16921E3AF50FB3FCULL,
		0x4754DC8CF3C5DC84ULL,
		0xFC371F37F3301DF3ULL,
		0x000000800B8FD263ULL
	}};
	shift = 43;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE8C6B38D19EEE139ULL,
		0x23D1658C76B71870ULL,
		0x4384D2A964055FABULL,
		0x4C9CD1207E45AFCBULL,
		0x4534F20A1D48379BULL,
		0xAA5D3BD0D7FB3AEDULL,
		0x0A59357493924889ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A33DDC272000000ULL,
		0x18ED6E30E1D18D67ULL,
		0x52C80ABF5647A2CBULL,
		0x40FC8B5F968709A5ULL,
		0x143A906F369939A2ULL,
		0xA1AFF675DA8A69E4ULL,
		0xE92724911354BA77ULL,
		0x000000000014B26AULL
	}};
	shift = 25;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBE9D45E2C74FDAECULL,
		0x66FAF8E18A4DF39FULL,
		0xAEE4DC977F29DF63ULL,
		0x38C719DD54CA38B6ULL,
		0x6DECAE5CC69CAF8DULL,
		0xBCA6BC2AA5391AEDULL,
		0xB9619E87D36CC356ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D3F6BB00000000ULL,
		0x62937CE7EFA75178ULL,
		0xDFCA77D8D9BEBE38ULL,
		0x55328E2DABB93725ULL,
		0x31A72BE34E31C677ULL,
		0xA94E46BB5B7B2B97ULL,
		0xF4DB30D5AF29AF0AULL,
		0x000000002E5867A1ULL
	}};
	shift = 30;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7BD2199FA69C3CDBULL,
		0xE8A3A5F762334238ULL,
		0x98D5AFDF97C0AA65ULL,
		0x4C580338834D6AF3ULL,
		0x67D24549C9CD45A4ULL,
		0x827728A0EDD72398ULL,
		0x68BFCCC73978AE6DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF48667E9A70F36CULL,
		0xA28E97DD88CD08E1ULL,
		0x6356BF7E5F02A997ULL,
		0x31600CE20D35ABCEULL,
		0x9F49152727351691ULL,
		0x09DCA283B75C8E61ULL,
		0xA2FF331CE5E2B9B6ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9868E44A6ACCABFDULL,
		0x64616133EAB9FC41ULL,
		0xBD28A15995C8CFAFULL,
		0x4D39AE831E3AEFDFULL,
		0xB3D62AC130863EF1ULL,
		0xF5F657E1BAFEAC2DULL,
		0xE976090BE1017BF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0x0CC347225356655FULL,
		0x7B230B099F55CFE2ULL,
		0xFDE9450ACCAE467DULL,
		0x8A69CD7418F1D77EULL,
		0x6D9EB156098431F7ULL,
		0xC7AFB2BF0DD7F561ULL,
		0x074BB0485F080BDFULL
	}};
	shift = 59;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x87310584B5655EC7ULL,
		0x7972C32341762030ULL,
		0x4495CDBF065FB9D4ULL,
		0x1772A7417EAF5D3AULL,
		0x6602BFCA77EE01CCULL,
		0xA173B95539AC843EULL,
		0x8AE10406472F89A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x882C25AB2AF63800ULL,
		0x96191A0BB1018439ULL,
		0xAE6DF832FDCEA3CBULL,
		0x953A0BF57AE9D224ULL,
		0x15FE53BF700E60BBULL,
		0x9DCAA9CD6421F330ULL,
		0x082032397C4D4D0BULL,
		0x0000000000000457ULL
	}};
	shift = 11;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x67C44791A93CFA6DULL,
		0x5F31457EA23301DDULL,
		0x9C139657D859F73CULL,
		0x85860D30789FF3FFULL,
		0x202E557F651673AEULL,
		0x68766C64EFB2095DULL,
		0x4753748EA1B58CD6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA93CFA6D00000000ULL,
		0xA23301DD67C44791ULL,
		0xD859F73C5F31457EULL,
		0x789FF3FF9C139657ULL,
		0x651673AE85860D30ULL,
		0xEFB2095D202E557FULL,
		0xA1B58CD668766C64ULL,
		0x000000004753748EULL
	}};
	shift = 32;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE58ACBCDF1282434ULL,
		0x4E2DAF156AB234B8ULL,
		0x4C22D32479D8B6DBULL,
		0x41CF7BC91D102DE0ULL,
		0x6B78ADE561AE8817ULL,
		0xCB9DF70C1A198C1EULL,
		0x6871C6AD1057CA6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79BE250486800000ULL,
		0xE2AD5646971CB159ULL,
		0x648F3B16DB69C5B5ULL,
		0x7923A205BC09845AULL,
		0xBCAC35D102E839EFULL,
		0xE183433183CD6F15ULL,
		0xD5A20AF94DD973BEULL,
		0x00000000000D0E38ULL
	}};
	shift = 21;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2D6F2097FF88CD64ULL,
		0xD106A917833709ADULL,
		0xD3297805021A280BULL,
		0xF788E2A728E4CC54ULL,
		0xDFC93008467AEB99ULL,
		0xA94E21DF7E4431FBULL,
		0x98869BAA57E24D0CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BFFC466B2000000ULL,
		0x8BC19B84D696B790ULL,
		0x02810D1405E88354ULL,
		0x539472662A6994BCULL,
		0x04233D75CCFBC471ULL,
		0xEFBF2218FDEFE498ULL,
		0xD52BF1268654A710ULL,
		0x00000000004C434DULL
	}};
	shift = 23;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8E9D5AD2B64679BDULL,
		0x6DF6ED1A6FBCB790ULL,
		0xEC2BA93C53948D4BULL,
		0x9361A6B8387B3339ULL,
		0x6A706BDD67C22A97ULL,
		0xF25CA02818038442ULL,
		0x279BCA3A846000B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF37A0000000000ULL,
		0x796F211D3AB5A56CULL,
		0x291A96DBEDDA34DFULL,
		0xF66673D8575278A7ULL,
		0x84552F26C34D7070ULL,
		0x070884D4E0D7BACFULL,
		0xC0016DE4B9405030ULL,
		0x0000004F37947508ULL
	}};
	shift = 41;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4E43D7D0582849BBULL,
		0xF677E3DA3E05E20DULL,
		0xD26E58BF372DC3ECULL,
		0x0F99CB4ED98D964FULL,
		0xBA0AAEB7BD55BD82ULL,
		0xF93B535B42E885D4ULL,
		0x5DC961E582665356ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849BB00000000000ULL,
		0x5E20D4E43D7D0582ULL,
		0xDC3ECF677E3DA3E0ULL,
		0xD964FD26E58BF372ULL,
		0x5BD820F99CB4ED98ULL,
		0x885D4BA0AAEB7BD5ULL,
		0x65356F93B535B42EULL,
		0x000005DC961E5826ULL
	}};
	shift = 44;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x92179A8290EB0965ULL,
		0x27AD50DCD2ED221EULL,
		0x70C6A1C6A2C7E82EULL,
		0x95537D31F883F0F1ULL,
		0x5E358BF18366730AULL,
		0x336FAE2D031CFA15ULL,
		0xFEFEAF283125198FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD41487584B28000ULL,
		0xA86E6976910F490BULL,
		0x50E35163F41713D6ULL,
		0xBE98FC41F878B863ULL,
		0xC5F8C1B339854AA9ULL,
		0xD716818E7D0AAF1AULL,
		0x579418928CC799B7ULL,
		0x0000000000007F7FULL
	}};
	shift = 15;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x02304641182B621CULL,
		0x901A0F59A5DBAF21ULL,
		0x07909E35B390086CULL,
		0xD7889D2C933EB3CDULL,
		0x0FBB194706F0E30AULL,
		0xA0C6566B72AE81C3ULL,
		0xFB438004A558EB1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4608C823056C4380ULL,
		0x0341EB34BB75E420ULL,
		0xF213C6B672010D92ULL,
		0xF113A59267D679A0ULL,
		0xF76328E0DE1C615AULL,
		0x18CACD6E55D03861ULL,
		0x68700094AB1D6354ULL,
		0x000000000000001FULL
	}};
	shift = 5;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2668E166874EC897ULL,
		0xCE021C499D006ADEULL,
		0x3D0A384CE8072006ULL,
		0x5AF21CC2C4F4EFB1ULL,
		0xB2A5277EB04EDBDDULL,
		0xFAF737DFD05EE1D3ULL,
		0xC8C1380DC26CA98EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3859A1D3B225C000ULL,
		0x871267401AB7899AULL,
		0x8E133A01C801B380ULL,
		0x8730B13D3BEC4F42ULL,
		0x49DFAC13B6F756BCULL,
		0xCDF7F417B874ECA9ULL,
		0x4E03709B2A63BEBDULL,
		0x0000000000003230ULL
	}};
	shift = 14;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6F97D18DDD829289ULL,
		0xFC728DBF03129CE6ULL,
		0x26EAD79D5EE7B6EEULL,
		0xB23DE77B38065652ULL,
		0xEC21BD2A9F8D7B6BULL,
		0xBB6E1241A1807E20ULL,
		0x334FAAC727533E9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB0525120000000ULL,
		0xE062539CCDF2FA31ULL,
		0xABDCF6DDDF8E51B7ULL,
		0x6700CACA44DD5AF3ULL,
		0x53F1AF6D7647BCEFULL,
		0x34300FC41D8437A5ULL,
		0xE4EA67D3D76DC248ULL,
		0x000000000669F558ULL
	}};
	shift = 29;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0B1A4C273C5192D8ULL,
		0xE684855146473399ULL,
		0x06C558A9F2FBE911ULL,
		0x7257991982BF6003ULL,
		0xF2CF2F9F70933E7CULL,
		0xCE67C906CDE7FB73ULL,
		0x89C89B065AF2101FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E28C96C00000000ULL,
		0xA32399CC858D2613ULL,
		0xF97DF488F34242A8ULL,
		0xC15FB0018362AC54ULL,
		0xB8499F3E392BCC8CULL,
		0x66F3FDB9F96797CFULL,
		0x2D79080FE733E483ULL,
		0x0000000044E44D83ULL
	}};
	shift = 31;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x7FCB7C3C9537A07EULL,
		0x08D365E2DC2E1DBAULL,
		0xA057DE3FB619961DULL,
		0xF31AA5F662615E27ULL,
		0x4A2CFD2259389776ULL,
		0xC56F5950EB71A858ULL,
		0x7207D356D531FB38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E00000000000000ULL,
		0xBA7FCB7C3C9537A0ULL,
		0x1D08D365E2DC2E1DULL,
		0x27A057DE3FB61996ULL,
		0x76F31AA5F662615EULL,
		0x584A2CFD22593897ULL,
		0x38C56F5950EB71A8ULL,
		0x007207D356D531FBULL
	}};
	shift = 56;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4F3788896B3D5F34ULL,
		0x19B8012318D50A9BULL,
		0xCEB3628CD34BB40FULL,
		0x34BC7CDD76E442A8ULL,
		0xF44B6DB298437062ULL,
		0x108263C64B482630ULL,
		0x7C038347B9A7240FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1112D67ABE68000ULL,
		0x0024631AA15369E6ULL,
		0x6C519A697681E337ULL,
		0x8F9BAEDC885519D6ULL,
		0x6DB653086E0C4697ULL,
		0x4C78C96904C61E89ULL,
		0x7068F734E481E210ULL,
		0x0000000000000F80ULL
	}};
	shift = 13;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x03F94FF709168682ULL,
		0x8857224E9B4B89FAULL,
		0x5A8460FADE7A2DE2ULL,
		0x89278E7E92736C6EULL,
		0x3FA516F45D462030ULL,
		0x26759E3D030542BCULL,
		0xFC7231BF1A57B17DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FF7091686820000ULL,
		0x224E9B4B89FA03F9ULL,
		0x60FADE7A2DE28857ULL,
		0x8E7E92736C6E5A84ULL,
		0x16F45D4620308927ULL,
		0x9E3D030542BC3FA5ULL,
		0x31BF1A57B17D2675ULL,
		0x000000000000FC72ULL
	}};
	shift = 16;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBFA5031B3B566F26ULL,
		0x2DF9EF7155C8B8E4ULL,
		0x4BB1601F0D95EC72ULL,
		0xA5FEFA01AADC27B1ULL,
		0x0F0FF8DD24EF7F80ULL,
		0x9D2E0CD51C57B7A6ULL,
		0xE433A9C26CF9E909ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63676ACDE4C00000ULL,
		0xEE2AB9171C97F4A0ULL,
		0x03E1B2BD8E45BF3DULL,
		0x40355B84F629762CULL,
		0x1BA49DEFF014BFDFULL,
		0x9AA38AF6F4C1E1FFULL,
		0x384D9F3D2133A5C1ULL,
		0x00000000001C8675ULL
	}};
	shift = 21;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x11598114704096C7ULL,
		0x38405BC71EDBFDCAULL,
		0x2BA1444006B561ACULL,
		0xD55F0B6DD7508CA9ULL,
		0x2522C03043CD9790ULL,
		0x2CC806BA8FF9DAADULL,
		0xBDB0BE213869E3DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x422B30228E0812D8ULL,
		0x87080B78E3DB7FB9ULL,
		0x2574288800D6AC35ULL,
		0x1AABE16DBAEA1195ULL,
		0xA4A458060879B2F2ULL,
		0xE59900D751FF3B55ULL,
		0x17B617C4270D3C7BULL
	}};
	shift = 61;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x88CACD4A18BF20C7ULL,
		0x04C77F21E74E4757ULL,
		0x49411370E3B03237ULL,
		0x5108C51ACDE56C02ULL,
		0x35AFC1A2727646FFULL,
		0xF088DB923195E997ULL,
		0x3A958E3DBE89C631ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xF11959A94317E418ULL,
		0xE098EFE43CE9C8EAULL,
		0x4928226E1C760646ULL,
		0xEA2118A359BCAD80ULL,
		0xE6B5F8344E4EC8DFULL,
		0x3E111B724632BD32ULL,
		0x0752B1C7B7D138C6ULL
	}};
	shift = 61;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x300AE4675B400F5DULL,
		0x798F4E65B1F0317EULL,
		0x9F28E44B29635016ULL,
		0xB1A08A331513D6B9ULL,
		0xD6569AF096990B3CULL,
		0x40121B8A758097E9ULL,
		0x783EA8DFE9C0F3CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0xC6015C8CEB6801EBULL,
		0xCF31E9CCB63E062FULL,
		0x33E51C89652C6A02ULL,
		0x9634114662A27AD7ULL,
		0x3ACAD35E12D32167ULL,
		0x880243714EB012FDULL,
		0x0F07D51BFD381E79ULL
	}};
	shift = 61;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x222D9FD7D41E2805ULL,
		0x3D5432F489F109C8ULL,
		0x4D4D8A33097DF4F8ULL,
		0x22FF5AF8A90DFC34ULL,
		0xE0E2E1CA4384DF50ULL,
		0x99F45A3B3C281D1FULL,
		0x9B065DAFA9EAF4A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41E280500000000ULL,
		0x89F109C8222D9FD7ULL,
		0x097DF4F83D5432F4ULL,
		0xA90DFC344D4D8A33ULL,
		0x4384DF5022FF5AF8ULL,
		0x3C281D1FE0E2E1CAULL,
		0xA9EAF4A499F45A3BULL,
		0x000000009B065DAFULL
	}};
	shift = 32;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4EFC6F3C48F9441CULL,
		0x0C4F1BABE06D8C4EULL,
		0x50CED529E586FC0CULL,
		0x83229D620751737FULL,
		0xBBC5B79D9330D4E9ULL,
		0x665B704FD2EB1DDAULL,
		0x8BCBDFB2C67F844CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E00000000000000ULL,
		0x27277E379E247CA2ULL,
		0x0606278DD5F036C6ULL,
		0xBFA8676A94F2C37EULL,
		0x74C1914EB103A8B9ULL,
		0xED5DE2DBCEC9986AULL,
		0x26332DB827E9758EULL,
		0x0045E5EFD9633FC2ULL
	}};
	shift = 55;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xE2BD96F323846880ULL,
		0x9C6D2BA0A918D981ULL,
		0x3D3598E1F73A2755ULL,
		0x99AEB184669F9C99ULL,
		0x0D1864AA3924603BULL,
		0x1FB61BC479D1C45EULL,
		0x5396CDB4072BCE3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2384688000000000ULL,
		0xA918D981E2BD96F3ULL,
		0xF73A27559C6D2BA0ULL,
		0x669F9C993D3598E1ULL,
		0x3924603B99AEB184ULL,
		0x79D1C45E0D1864AAULL,
		0x072BCE3B1FB61BC4ULL,
		0x000000005396CDB4ULL
	}};
	shift = 32;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9C83570D359EB578ULL,
		0xF6C034D97EAE3B56ULL,
		0x617D404AD2B316CDULL,
		0x9F3657358EC686F4ULL,
		0x28301FA89A746DE1ULL,
		0x354E29266D8691B8ULL,
		0x662BFCE68E298751ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x5A720D5C34D67AD5ULL,
		0x37DB00D365FAB8EDULL,
		0xD185F5012B4ACC5BULL,
		0x867CD95CD63B1A1BULL,
		0xE0A0C07EA269D1B7ULL,
		0x44D538A499B61A46ULL,
		0x0198AFF39A38A61DULL
	}};
	shift = 58;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3A3FC5D3D7646DA8ULL,
		0xD1E415053FA3B5E1ULL,
		0x69E2387EBE97E356ULL,
		0x5D933D87741921B7ULL,
		0xC1272A35936D73BFULL,
		0x1136476378944AF1ULL,
		0x9D7F0DCA36EF8884ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3FC5D3D7646DA8ULL,
		0xD1E415053FA3B5E1ULL,
		0x69E2387EBE97E356ULL,
		0x5D933D87741921B7ULL,
		0xC1272A35936D73BFULL,
		0x1136476378944AF1ULL,
		0x9D7F0DCA36EF8884ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xF7804AECB9AC3AECULL,
		0xE0B9048592EF6F0EULL,
		0x5705C41A1C90C949ULL,
		0x2158BD4DDC2D24D1ULL,
		0x90BD055089B8FEACULL,
		0x37538FB9F06801AFULL,
		0xC46E38588C4F4B54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBDE012BB2E6B0EBBULL,
		0x782E412164BBDBC3ULL,
		0x55C1710687243252ULL,
		0x08562F53770B4934ULL,
		0xE42F4154226E3FABULL,
		0x0DD4E3EE7C1A006BULL,
		0x311B8E162313D2D5ULL
	}};
	shift = 62;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9EC4AE73D3AB44D1ULL,
		0xBE86A27D8968226CULL,
		0xA2D0A55161429F16ULL,
		0xD106A329E70D50E9ULL,
		0x36FFD379CF09594DULL,
		0x82A8C7BA94537FABULL,
		0xAED8A8E03BDE2CD2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D3AB44D10000000ULL,
		0xD8968226C9EC4AE7ULL,
		0x161429F16BE86A27ULL,
		0x9E70D50E9A2D0A55ULL,
		0x9CF09594DD106A32ULL,
		0xA94537FAB36FFD37ULL,
		0x03BDE2CD282A8C7BULL,
		0x000000000AED8A8EULL
	}};
	shift = 28;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAA6A65C70DBBA474ULL,
		0x1B00143F11205602ULL,
		0xEAB40ECFE9F6969BULL,
		0x72CFE85CF57FDF3BULL,
		0xC8B69F6A06A6C08DULL,
		0x25BC8FF4E658E637ULL,
		0x62FD4BBBC91AEFD8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36EE91D000000000ULL,
		0x4481580AA9A9971CULL,
		0xA7DA5A6C6C0050FCULL,
		0xD5FF7CEFAAD03B3FULL,
		0x1A9B0235CB3FA173ULL,
		0x996398DF22DA7DA8ULL,
		0x246BBF6096F23FD3ULL,
		0x000000018BF52EEFULL
	}};
	shift = 34;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x99D7951DA3DC5B0FULL,
		0x57470768C014CB3FULL,
		0x5FE159695A3DDFE7ULL,
		0xC2FF9F23350F1A23ULL,
		0x60123DF3B31DE375ULL,
		0xDC1408A411C04CF8ULL,
		0xF2259897853341A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE54768F716C3C000ULL,
		0xC1DA300532CFE675ULL,
		0x565A568F77F9D5D1ULL,
		0xE7C8CD43C688D7F8ULL,
		0x8F7CECC778DD70BFULL,
		0x02290470133E1804ULL,
		0x6625E14CD068F705ULL,
		0x0000000000003C89ULL
	}};
	shift = 14;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAED7135A3EDC47A9ULL,
		0xC615B1E5E45F64C6ULL,
		0xF7AD182D08D3A145ULL,
		0x96854A662252D1E8ULL,
		0x50C29D84CF847A0EULL,
		0xAE1F8150A67101CBULL,
		0x2BD54CD7BD96C69DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5200000000000000ULL,
		0x8D5DAE26B47DB88FULL,
		0x8B8C2B63CBC8BEC9ULL,
		0xD1EF5A305A11A742ULL,
		0x1D2D0A94CC44A5A3ULL,
		0x96A1853B099F08F4ULL,
		0x3B5C3F02A14CE203ULL,
		0x0057AA99AF7B2D8DULL
	}};
	shift = 57;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x8CA60D245D034046ULL,
		0x09287F3B1EE0938DULL,
		0xF447467EEAE5BB07ULL,
		0x94BC87D3F5CBFE22ULL,
		0x70D6FD3D22466ED5ULL,
		0x0351D6455483B342ULL,
		0x780D23E60B452F2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491740D011800000ULL,
		0xCEC7B824E3632983ULL,
		0x9FBAB96EC1C24A1FULL,
		0xF4FD72FF88BD11D1ULL,
		0x4F48919BB5652F21ULL,
		0x915520ECD09C35BFULL,
		0xF982D14BCB00D475ULL,
		0x00000000001E0348ULL
	}};
	shift = 22;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x6EB5DD3418337AD9ULL,
		0x0140239BFDBF8665ULL,
		0xB223416788CD4AF2ULL,
		0x4E489F1B1FB43B85ULL,
		0xA8DC49B74C08A5BEULL,
		0xB4997205D77E3B47ULL,
		0x9D822EFE53A6BB51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0xADD6BBA683066F5BULL,
		0x402804737FB7F0CCULL,
		0xB644682CF119A95EULL,
		0xC9C913E363F68770ULL,
		0xF51B8936E98114B7ULL,
		0x36932E40BAEFC768ULL,
		0x13B045DFCA74D76AULL
	}};
	shift = 61;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1F5A6BCC57E59507ULL,
		0xF74CDD451EE0A4BCULL,
		0x9AA5EF261814FE3DULL,
		0xD347A814E0FCC6EEULL,
		0x2A5F263DC6710996ULL,
		0x3BA9887EB0F8FFE0ULL,
		0x5B7DF375E3AC5805ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x07D69AF315F96541ULL,
		0x7DD3375147B8292FULL,
		0xA6A97BC986053F8FULL,
		0xB4D1EA05383F31BBULL,
		0x0A97C98F719C4265ULL,
		0x4EEA621FAC3E3FF8ULL,
		0x16DF7CDD78EB1601ULL
	}};
	shift = 62;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x11D0B80302097659ULL,
		0x712FCA1ECEECF909ULL,
		0xEC00357CFABFC623ULL,
		0xB1C48083679D1DBBULL,
		0x6AF3DCA287DAFDBBULL,
		0x99CDF1116FE7687BULL,
		0xA638FAFB7C4102F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2C800000000000ULL,
		0x7C8488E85C018104ULL,
		0xE311B897E50F6776ULL,
		0x8EDDF6001ABE7D5FULL,
		0x7EDDD8E24041B3CEULL,
		0xB43DB579EE5143EDULL,
		0x817A4CE6F888B7F3ULL,
		0x0000531C7D7DBE20ULL
	}};
	shift = 47;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9E75DDBA50DDD838ULL,
		0xA51CFB5C5A425E8CULL,
		0x9EB513005BA2059DULL,
		0xD44168ACF4630BE2ULL,
		0x2150F1C5E426DCB1ULL,
		0x373C59C087D96A2AULL,
		0x98BD55B44498B08BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA50DDD83800000ULL,
		0xB5C5A425E8C9E75DULL,
		0x3005BA2059DA51CFULL,
		0x8ACF4630BE29EB51ULL,
		0x1C5E426DCB1D4416ULL,
		0x9C087D96A2A2150FULL,
		0x5B44498B08B373C5ULL,
		0x0000000000098BD5ULL
	}};
	shift = 20;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x1A986407A8983182ULL,
		0x67BA5DD75EFA2E75ULL,
		0x3DD5228ECD962CEAULL,
		0xACF2C011078F3961ULL,
		0x9647B7740836638AULL,
		0x482F229D0CE6B37BULL,
		0xBED99163154347E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44C18C1000000000ULL,
		0xF7D173A8D4C3203DULL,
		0x6CB167533DD2EEBAULL,
		0x3C79CB09EEA91476ULL,
		0x41B31C5567960088ULL,
		0x67359BDCB23DBBA0ULL,
		0xAA1A3F2A417914E8ULL,
		0x00000005F6CC8B18ULL
	}};
	shift = 35;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x3392CA1997C35B32ULL,
		0x24E411A78EF54A28ULL,
		0xC7C94EA919E14704ULL,
		0xA00596B31DFAC0F2ULL,
		0xEDD37F8948475251ULL,
		0x2E6224063A458FC0ULL,
		0x6B1BD9370675709BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4332F86B66400000ULL,
		0x34F1DEA945067259ULL,
		0xD5233C28E0849C82ULL,
		0xD663BF581E58F929ULL,
		0xF12908EA4A3400B2ULL,
		0x80C748B1F81DBA6FULL,
		0x26E0CEAE1365CC44ULL,
		0x00000000000D637BULL
	}};
	shift = 21;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB3397D09AE6519BBULL,
		0xC1CE1ABEEC795521ULL,
		0xE61694778B8D5E33ULL,
		0xA2D2FA59289D13A9ULL,
		0x7BAB32E82DE0BB1DULL,
		0x2136DBC704E219BAULL,
		0x606D094E642C4724ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97D09AE6519BB000ULL,
		0xE1ABEEC795521B33ULL,
		0x694778B8D5E33C1CULL,
		0x2FA59289D13A9E61ULL,
		0xB32E82DE0BB1DA2DULL,
		0x6DBC704E219BA7BAULL,
		0xD094E642C4724213ULL,
		0x0000000000000606ULL
	}};
	shift = 12;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB85D96BC1AAFD040ULL,
		0xE1280E5DE24D3A09ULL,
		0xB0DED27DAE7D3F0FULL,
		0xDFD42FA72FC9A13DULL,
		0x240374BBED680B52ULL,
		0xD91DA92C3234D691ULL,
		0x79CEF30009B505A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x826E1765AF06ABF4ULL,
		0xC3F84A039778934EULL,
		0x4F6C37B49F6B9F4FULL,
		0xD4B7F50BE9CBF268ULL,
		0xA44900DD2EFB5A02ULL,
		0x6936476A4B0C8D35ULL,
		0x001E73BCC0026D41ULL
	}};
	shift = 54;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x2790C026B21E434AULL,
		0x6DD14D7A4DF0C983ULL,
		0x89CC007F0FF8E225ULL,
		0x408B58FD74428FE0ULL,
		0x5AC2702D3347E8CFULL,
		0x9578B6F4CF9F8BFDULL,
		0x6835489CE0CBB028ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC026B21E434A0000ULL,
		0x4D7A4DF0C9832790ULL,
		0x007F0FF8E2256DD1ULL,
		0x58FD74428FE089CCULL,
		0x702D3347E8CF408BULL,
		0xB6F4CF9F8BFD5AC2ULL,
		0x489CE0CBB0289578ULL,
		0x0000000000006835ULL
	}};
	shift = 16;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5D3903C98E79BC4DULL,
		0x37D146D3E60084CFULL,
		0x42DDEF07CD99DBCDULL,
		0x6BE2C440B89AB2AFULL,
		0x903B0250DCDADFDEULL,
		0x1727D8BFFC060B08ULL,
		0x9D52F024CFAF1F3AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E40F2639E6F1340ULL,
		0xF451B4F9802133D7ULL,
		0xB77BC1F36676F34DULL,
		0xF8B1102E26ACABD0ULL,
		0x0EC0943736B7F79AULL,
		0xC9F62FFF0182C224ULL,
		0x54BC0933EBC7CE85ULL,
		0x0000000000000027ULL
	}};
	shift = 6;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x970589E186CA7200ULL,
		0x4376D0532F8A5FDFULL,
		0x712188368599B4FAULL,
		0xBE3962213956F841ULL,
		0xD67FCE58B133A37DULL,
		0x7B34CF25DD7093E2ULL,
		0xA83AA10A415B6C0BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC800000000000000ULL,
		0x7F7E5C1627861B29ULL,
		0xD3E90DDB414CBE29ULL,
		0xE105C48620DA1666ULL,
		0x8DF6F8E58884E55BULL,
		0x4F8B59FF3962C4CEULL,
		0xB02DECD33C9775C2ULL,
		0x0002A0EA8429056DULL
	}};
	shift = 50;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x210375B592A3335DULL,
		0x8CB348464EB41B5CULL,
		0xE053DAA0CE018CA5ULL,
		0x6CF3798BA9819927ULL,
		0x679E81ABB49324DDULL,
		0x8FC50667C1131A8CULL,
		0x3DE1B2C78857F5B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3335D0000000000ULL,
		0xB41B5C210375B592ULL,
		0x018CA58CB348464EULL,
		0x819927E053DAA0CEULL,
		0x9324DD6CF3798BA9ULL,
		0x131A8C679E81ABB4ULL,
		0x57F5B58FC50667C1ULL,
		0x0000003DE1B2C788ULL
	}};
	shift = 40;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0DF9D989C58677CBULL,
		0x0F0F0E295580C2FEULL,
		0x2A2336B78740B30EULL,
		0xF3B493655CA10036ULL,
		0x4A91C166D2F41FBCULL,
		0xFE561CC824963F90ULL,
		0x07B5487AB90E38C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33BE580000000000ULL,
		0x0617F06FCECC4E2CULL,
		0x0598707878714AACULL,
		0x0801B15119B5BC3AULL,
		0xA0FDE79DA49B2AE5ULL,
		0xB1FC82548E0B3697ULL,
		0x71C637F2B0E64124ULL,
		0x0000003DAA43D5C8ULL
	}};
	shift = 43;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xCB6603F701B0E52DULL,
		0x0FC8741351803782ULL,
		0x0162A8F7C7068B54ULL,
		0x3EDF4CA427AEE9E4ULL,
		0x09F28604062E2418ULL,
		0x8C7D6E916E5EC17FULL,
		0x2AD52B40EF3D4ECAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9680000000000000ULL,
		0xC165B301FB80D872ULL,
		0xAA07E43A09A8C01BULL,
		0xF200B1547BE38345ULL,
		0x0C1F6FA65213D774ULL,
		0xBF84F94302031712ULL,
		0x65463EB748B72F60ULL,
		0x00156A95A0779EA7ULL
	}};
	shift = 55;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x36F598A7BB39E1BFULL,
		0x442AEB23DDC378D8ULL,
		0xC5B5733794F312FEULL,
		0x0C3BB9986DAC92C5ULL,
		0x99E970BB14B0C7E0ULL,
		0xBD00E0A076810A0BULL,
		0x737CDE031C838418ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB39E1BF00000000ULL,
		0xDDC378D836F598A7ULL,
		0x94F312FE442AEB23ULL,
		0x6DAC92C5C5B57337ULL,
		0x14B0C7E00C3BB998ULL,
		0x76810A0B99E970BBULL,
		0x1C838418BD00E0A0ULL,
		0x00000000737CDE03ULL
	}};
	shift = 32;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x5FEC1100F171EAECULL,
		0x83651F53CE6DAD4FULL,
		0x58DD2D06AA6E8698ULL,
		0x0D4D90B6A31F220CULL,
		0xFD0659D8B97100A8ULL,
		0xA7312AACD8BD9A6CULL,
		0x13FD204ADF7D6F2EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xF5FEC1100F171EAEULL,
		0x883651F53CE6DAD4ULL,
		0xC58DD2D06AA6E869ULL,
		0x80D4D90B6A31F220ULL,
		0xCFD0659D8B97100AULL,
		0xEA7312AACD8BD9A6ULL,
		0x013FD204ADF7D6F2ULL
	}};
	shift = 60;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x369EC70DE5E758A7ULL,
		0x4F4F77E02618F111ULL,
		0x4383024C4FA35817ULL,
		0x527002F9C28CFDBCULL,
		0xD3A97953C2F0BB05ULL,
		0xAE1D37E0CA52221CULL,
		0x25C8662DC4B40B8EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F3AC53800000000ULL,
		0x30C78889B4F6386FULL,
		0x7D1AC0BA7A7BBF01ULL,
		0x1467EDE21C181262ULL,
		0x1785D82A938017CEULL,
		0x529110E69D4BCA9EULL,
		0x25A05C7570E9BF06ULL,
		0x000000012E43316EULL
	}};
	shift = 35;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x06BCB6B8617435A2ULL,
		0x3F69D05FF6465FA5ULL,
		0xC9FBA32AA5E6FD52ULL,
		0xA865B277729E9D3FULL,
		0x1FA7C15A07276D34ULL,
		0xCDB6C09B1598F861ULL,
		0xA29A674B1A7B4820ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA1AD1000000000ULL,
		0xB232FD2835E5B5C3ULL,
		0x2F37EA91FB4E82FFULL,
		0x94F4E9FE4FDD1955ULL,
		0x393B69A5432D93BBULL,
		0xACC7C308FD3E0AD0ULL,
		0xD3DA41066DB604D8ULL,
		0x0000000514D33A58ULL
	}};
	shift = 35;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB7155C1131238350ULL,
		0x933ACF042D0163EDULL,
		0x5309ECE26086E5DFULL,
		0x8616E64FE0F6A741ULL,
		0xA37F740FF4FB976FULL,
		0x7739BE71FE87B8D4ULL,
		0x6622C985B7FFDEECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C11312383500000ULL,
		0xCF042D0163EDB715ULL,
		0xECE26086E5DF933AULL,
		0xE64FE0F6A7415309ULL,
		0x740FF4FB976F8616ULL,
		0xBE71FE87B8D4A37FULL,
		0xC985B7FFDEEC7739ULL,
		0x0000000000006622ULL
	}};
	shift = 16;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xB6739E9DCCB9BFA7ULL,
		0x9FEF0FE1E058C72AULL,
		0x837BA426CC7967B2ULL,
		0xC7A1814BF29F201DULL,
		0x5B85526068899B3BULL,
		0x7C0CE5744453F3AEULL,
		0x030C5AF46C8BC971ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6739E9DCCB9BFA7ULL,
		0x9FEF0FE1E058C72AULL,
		0x837BA426CC7967B2ULL,
		0xC7A1814BF29F201DULL,
		0x5B85526068899B3BULL,
		0x7C0CE5744453F3AEULL,
		0x030C5AF46C8BC971ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xBEEB975B6F8C434BULL,
		0xA04BD661E2E50B2BULL,
		0xF7A41F9201B597C1ULL,
		0x95572253278205F1ULL,
		0x63250DDB44AA6909ULL,
		0x1A495EB514493D22ULL,
		0x89D215852849679CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEEB975B6F8C434BULL,
		0xA04BD661E2E50B2BULL,
		0xF7A41F9201B597C1ULL,
		0x95572253278205F1ULL,
		0x63250DDB44AA6909ULL,
		0x1A495EB514493D22ULL,
		0x89D215852849679CULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x116BC43E970FBD26ULL,
		0x8FFAD2BE054D2985ULL,
		0x3C7A9EA613CB7CF6ULL,
		0xA317361FF0CA28C5ULL,
		0x5A799FFC8A2A16C4ULL,
		0xCC8ECEC8510A46BAULL,
		0xC922321951E8EC97ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC43E970FBD26000ULL,
		0xAD2BE054D2985116ULL,
		0xA9EA613CB7CF68FFULL,
		0x7361FF0CA28C53C7ULL,
		0x99FFC8A2A16C4A31ULL,
		0xECEC8510A46BA5A7ULL,
		0x2321951E8EC97CC8ULL,
		0x0000000000000C92ULL
	}};
	shift = 12;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xD4B2BC70DF8DB4CFULL,
		0xBEF751F2B0B868ADULL,
		0x83F0A2321733932DULL,
		0xD90F9FED871AB3BDULL,
		0x94A4FEC3D2AEA9EDULL,
		0x07D3C0D9ABBD508BULL,
		0x3878C8151E1FF6C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4CF00000000000ULL,
		0x868ADD4B2BC70DF8ULL,
		0x3932DBEF751F2B0BULL,
		0xAB3BD83F0A232173ULL,
		0xEA9EDD90F9FED871ULL,
		0xD508B94A4FEC3D2AULL,
		0xFF6C607D3C0D9ABBULL,
		0x000003878C8151E1ULL
	}};
	shift = 44;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0xAA1191FB33885802ULL,
		0x7875FFC374C8190DULL,
		0x1B402AA774BD1386ULL,
		0x8C4E581280372ECFULL,
		0x54AED2033FFFA014ULL,
		0x55C8A5420C1A55DBULL,
		0xAE328CB3B4D70034ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2160080000000000ULL,
		0x206436A84647ECCEULL,
		0xF44E19E1D7FF0DD3ULL,
		0xDCBB3C6D00AA9DD2ULL,
		0xFE80523139604A00ULL,
		0x69576D52BB480CFFULL,
		0x5C00D15722950830ULL,
		0x000002B8CA32CED3ULL
	}};
	shift = 42;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x9CED23ADE9160F87ULL,
		0x4E4B66304F2D942DULL,
		0x5D93A479AFEB15E6ULL,
		0x12337F0AADCBE989ULL,
		0xC1E62FB6E11E501DULL,
		0x5F5636A86F8C27FEULL,
		0xE0E78A00A6F31135ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1F0E00000000000ULL,
		0xB285B39DA475BD22ULL,
		0x62BCC9C96CC609E5ULL,
		0x7D312BB2748F35FDULL,
		0xCA03A2466FE155B9ULL,
		0x84FFD83CC5F6DC23ULL,
		0x6226ABEAC6D50DF1ULL,
		0x00001C1CF14014DEULL
	}};
	shift = 45;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x43D846BF30DB65FEULL,
		0x864EF1F1DB2FF531ULL,
		0x086CFD76DB284D0BULL,
		0x7B4B40C99EA292DBULL,
		0xCC448830C5720D14ULL,
		0xE71AD6C1860A507AULL,
		0x08208EB280DA92D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46BF30DB65FE0000ULL,
		0xF1F1DB2FF53143D8ULL,
		0xFD76DB284D0B864EULL,
		0x40C99EA292DB086CULL,
		0x8830C5720D147B4BULL,
		0xD6C1860A507ACC44ULL,
		0x8EB280DA92D6E71AULL,
		0x0000000000000820ULL
	}};
	shift = 16;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000200000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0001000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000010000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0008000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0008000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000008000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000020000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0002000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000001000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000800000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000100000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
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