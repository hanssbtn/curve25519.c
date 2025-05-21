#include "tests.h"

int32_t curve25519_key_sub_inplace_test(void) {
	printf("Sub Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9CD3BAAEF3BD0F54ULL,
		0xEA5AE3B8490677BFULL,
		0x390700CD0BC6CBC8ULL,
		0x2D8D9CE2E511D3A2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF867F820AFEC8ECEULL,
		0x33C662B1BBDEBCC6ULL,
		0x5B2DB6E1830AEE33ULL,
		0x14B04C88316DB4AAULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xA46BC28E43D08086ULL,
		0xB69481068D27BAF8ULL,
		0xDDD949EB88BBDD95ULL,
		0x18DD505AB3A41EF7ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA20340F13FD6E02AULL,
		0x927A2CED96A6DAEFULL,
		0x303B7308099229BDULL,
		0x0FA4AA018EB69C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x093E9B5D11CD8513ULL,
		0x539FFA1ADBDF5F7DULL,
		0x94A44CF227119F4EULL,
		0x1AAA8B3C0E7502ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98C4A5942E095B04ULL,
		0x3EDA32D2BAC77B72ULL,
		0x9B972615E2808A6FULL,
		0x74FA1EC580419974ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD29ADF62B87A5337ULL,
		0xE04DC31CAC9C08C9ULL,
		0x1152E976C68072EFULL,
		0x26B4AA6DB7757808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1368BDE295EA00ULL,
		0xB17A9361F0F78DE4ULL,
		0x661EA7B7F8483E07ULL,
		0x0BDEBF12D173EC62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x188776A4D5E46937ULL,
		0x2ED32FBABBA47AE5ULL,
		0xAB3441BECE3834E8ULL,
		0x1AD5EB5AE6018BA5ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01C1D151058B831BULL,
		0xB0AF5BC34DCDAE5FULL,
		0x15628C8028AEEE6CULL,
		0x1C06D21A50ED7188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07515320A02391EFULL,
		0x3652AA7E42F242D7ULL,
		0x89812CCBD51EE5CDULL,
		0x5449C00CDFE0D412ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA707E306567F119ULL,
		0x7A5CB1450ADB6B87ULL,
		0x8BE15FB45390089FULL,
		0x47BD120D710C9D75ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01B5CCCEDE4A29D8ULL,
		0x36CAB6B28B84C745ULL,
		0x982FA41223C18406ULL,
		0x79780516478C1E2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD5F01F0DF74FBCULL,
		0x63AE1327EDF41533ULL,
		0xB9F7A6503A92D14EULL,
		0x1870284A9F29CE06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3DFDCAFD052DA1CULL,
		0xD31CA38A9D90B211ULL,
		0xDE37FDC1E92EB2B7ULL,
		0x6107DCCBA8625028ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B33FEBB8C3F114AULL,
		0x32E96E91315CF546ULL,
		0x5555F31EA3A35421ULL,
		0x37F250DA309548AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71FC1E537087D506ULL,
		0x09E5B4B8D2C136A7ULL,
		0x6AF752680290D95AULL,
		0x4C4944ED11D830D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD937E0681BB73C31ULL,
		0x2903B9D85E9BBE9EULL,
		0xEA5EA0B6A1127AC7ULL,
		0x6BA90BED1EBD17D7ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FB6FB1FF0AC0180ULL,
		0x9697FBA7F3B586D9ULL,
		0x8B3C0D62CDE3383AULL,
		0x1ACD13C775C6C464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D364BB8BE29DA7ULL,
		0x7448EF6BEAA5E764ULL,
		0x1CF27000ABACC3A0ULL,
		0x4072EBB1CA19061BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DE3966464C963C6ULL,
		0x224F0C3C090F9F74ULL,
		0x6E499D622236749AULL,
		0x5A5A2815ABADBE49ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE493E53D669F5FAEULL,
		0x3C4A37ED253D4106ULL,
		0xB7DD7DEC86C8EEA5ULL,
		0x3BD61CE8988FF74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9981282FC98896ULL,
		0x4A9D43DB72CA4612ULL,
		0x01F25CFDCDCCC2CAULL,
		0x664F4DE7A26BC7BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6FA641536D5D705ULL,
		0xF1ACF411B272FAF4ULL,
		0xB5EB20EEB8FC2BDAULL,
		0x5586CF00F6242F8FULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x799E948AE6F68ECEULL,
		0xC021E989E11EE7E1ULL,
		0x9FA3F447DEEB3C76ULL,
		0x52DCB103AB3497BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D30F06BAA07050EULL,
		0xA0E7681FCAD9CF0AULL,
		0x656214E56D0F5F27ULL,
		0x725D467E4C5C354BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C6DA41F3CEF89ADULL,
		0x1F3A816A164518D7ULL,
		0x3A41DF6271DBDD4FULL,
		0x607F6A855ED8626FULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x294FE375AEAF47BEULL,
		0x0C5D45FF7E585E4CULL,
		0x0365CFD644AA0B66ULL,
		0x70A2674695E94459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13B9CF27085521FEULL,
		0x63596FEAE8FB013BULL,
		0x7FC266D7FB4CF5D3ULL,
		0x6C9B81B35C5991FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1596144EA65A25C0ULL,
		0xA903D614955D5D11ULL,
		0x83A368FE495D1592ULL,
		0x0406E593398FB25AULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2691C668E976AF7EULL,
		0xE9DAD3E30DA114E4ULL,
		0xF64EB566D0446F94ULL,
		0x0CB10AEF54F1E0CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80402B2CB6525F51ULL,
		0x2FA81B512577B729ULL,
		0x2FE63FC9CC0B9383ULL,
		0x07B347EE8569930AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6519B3C3324502DULL,
		0xBA32B891E8295DBAULL,
		0xC668759D0438DC11ULL,
		0x04FDC300CF884DC5ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE404E004BE4F8B1ULL,
		0xA620BE55B1C64453ULL,
		0x6EB6D50B7E08613CULL,
		0x033728F5572EFAD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745139FEDFCA4E1DULL,
		0x490C4B91C38FE150ULL,
		0x0847FABD01211336ULL,
		0x14C8BDF4F0F984A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79EF14016C1AAA81ULL,
		0x5D1472C3EE366303ULL,
		0x666EDA4E7CE74E06ULL,
		0x6E6E6B0066357630ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67F64C5855F0332BULL,
		0x3141D56BED67434BULL,
		0x9717F4928B9B4E96ULL,
		0x5235A7FCDBB1DAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643F1DFCA31B13C2ULL,
		0x57E0303C769C14F1ULL,
		0x3F80BE0C185CE4A4ULL,
		0x14820961A83794AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03B72E5BB2D51F69ULL,
		0xD961A52F76CB2E5AULL,
		0x57973686733E69F1ULL,
		0x3DB39E9B337A45F3ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB510C2D85090A038ULL,
		0x704BE47A25FED815ULL,
		0xAF77B5CEA94C434EULL,
		0x139C011D67C4771AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA7911C39286DDBULL,
		0xB5E1E1FCB60E3511ULL,
		0xAC0EF0B06B9ECD64ULL,
		0x7B2D04537DDD754CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x856931BC1768324AULL,
		0xBA6A027D6FF0A304ULL,
		0x0368C51E3DAD75E9ULL,
		0x186EFCC9E9E701CEULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x328C70269F703599ULL,
		0x351505CFFBA01224ULL,
		0x612CC017357C34A1ULL,
		0x77D22C7D3C255B88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2909FED2953E9B09ULL,
		0x2572C8E2173BE9DBULL,
		0x073200AE9684EC1CULL,
		0x41C7E73D32C12EEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x098271540A319A90ULL,
		0x0FA23CEDE4642849ULL,
		0x59FABF689EF74885ULL,
		0x360A454009642C99ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x153E25E9FF76E101ULL,
		0xEE43BF24196DBF3DULL,
		0x11822B26A0EE0615ULL,
		0x5FA2742046D146EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4394F8DBF70EF5ULL,
		0xD7BFB6654FA8CE24ULL,
		0x8308889C8A833B2BULL,
		0x3D5D8A018F224FE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39FA90F1237FD20CULL,
		0x168408BEC9C4F118ULL,
		0x8E79A28A166ACAEAULL,
		0x2244EA1EB7AEF701ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEB21D7E2F1A1951ULL,
		0x16A4F9B4952CC851ULL,
		0xB3B710F4E72F38E3ULL,
		0x6FF2A7C45B94D878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x254466951A96E266ULL,
		0xA63DD66F8EFA170AULL,
		0x6343576F1C782E11ULL,
		0x02FF78850E884460ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD96DB6E9148336EBULL,
		0x706723450632B147ULL,
		0x5073B985CAB70AD1ULL,
		0x6CF32F3F4D0C9418ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE13B7DC12EBDF4B1ULL,
		0x3C9A809A7B7E2F1FULL,
		0x0E663DB6E166ACBAULL,
		0x7310ABB563348AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8AE3D1471F82964ULL,
		0x732E8C35028397B7ULL,
		0x9E4E4AECE988F24EULL,
		0x387022993DE9BAC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288D40ACBCC5CB4DULL,
		0xC96BF46578FA9768ULL,
		0x7017F2C9F7DDBA6BULL,
		0x3AA0891C254ACFE2ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDE0F1D099B8E505ULL,
		0xF29764C8502EBF0FULL,
		0xFF092CF892537C55ULL,
		0x0AD5477FADE14453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CEBEBD9D523B7C8ULL,
		0x74C2A54B11F9F428ULL,
		0xE5D0D30B0380C1FAULL,
		0x0F042CADD4721202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0F505F6C4952D2AULL,
		0x7DD4BF7D3E34CAE7ULL,
		0x193859ED8ED2BA5BULL,
		0x7BD11AD1D96F3251ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA93EBAB8BFFFBB0ULL,
		0x27A40CF3620BEEB5ULL,
		0xD40C7F39136E9B22ULL,
		0x05170DF9B4423C93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF845E100647D1F3AULL,
		0x7FEB0E3B21F9FF83ULL,
		0xD6E3EA5AECA39EE6ULL,
		0x07A96BD63D3E5556ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x024E0AAB2782DC63ULL,
		0xA7B8FEB84011EF32ULL,
		0xFD2894DE26CAFC3BULL,
		0x7D6DA2237703E73CULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F706ABFF4108835ULL,
		0xD120AFE904E6B19AULL,
		0x2E36ABE2A9745F76ULL,
		0x505640A2109756C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0F727548396F31ULL,
		0x1FE196D3A82283C0ULL,
		0x3F097871E0AB2E50ULL,
		0x657B38AC73EF5FB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0560F84AABD718F1ULL,
		0xB13F19155CC42DDAULL,
		0xEF2D3370C8C93126ULL,
		0x6ADB07F59CA7F70CULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CC98C63ACB98FDDULL,
		0x363FC1C2C07FDAC1ULL,
		0x7900D8183A1ADC8DULL,
		0x391769786C5C24E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82DC5C8F6B410D98ULL,
		0xFEEA36DDD1D208F7ULL,
		0xA20523ABECCAB0ACULL,
		0x38D9F6FB492CAB51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9ED2FD441788245ULL,
		0x37558AE4EEADD1C9ULL,
		0xD6FBB46C4D502BE0ULL,
		0x003D727D232F7996ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC5D4913F4FD7E24ULL,
		0xDBC6AF2E32F90108ULL,
		0x145B3EC5C06DAD2DULL,
		0x738EB80D1F140E26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF322F071A940C95ULL,
		0x2BE1F507CA091C8EULL,
		0x326EFBA8A739B16CULL,
		0x1F6C7F7FB3FD3839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D2B1A0CDA69718FULL,
		0xAFE4BA2668EFE47AULL,
		0xE1EC431D1933FBC1ULL,
		0x5422388D6B16D5ECULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x167583A18CD857F2ULL,
		0xD7B46CE677EBF202ULL,
		0xA79037E4BAB6C607ULL,
		0x049A996D60E4FD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8212E7C91FA21A39ULL,
		0xE592198F5F16187EULL,
		0xF13AD9ED4E5C61DBULL,
		0x0869171755833041ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94629BD86D363DA6ULL,
		0xF222535718D5D983ULL,
		0xB6555DF76C5A642BULL,
		0x7C3182560B61CD5BULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x775932F80738D799ULL,
		0x40BB0AD01920CC22ULL,
		0xE92E1E59555A847DULL,
		0x128CD44D5800F56AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDEA118288B06A3BULL,
		0xADF11F0DE99B8893ULL,
		0xFC0C3AAD74DA64D9ULL,
		0x79B140821617E863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x796F21757E886D4BULL,
		0x92C9EBC22F85438EULL,
		0xED21E3ABE0801FA3ULL,
		0x18DB93CB41E90D06ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC8D98DDD2D1171AULL,
		0xD8F6F4E157E1EC8FULL,
		0x3C09431D63F997FAULL,
		0x46B95B64B9E5C289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA8F6E037775B08ULL,
		0x0E51AF97681A8C05ULL,
		0x96C4CE5A6D786CFBULL,
		0x5B1B8A876AD05FE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EE4A1FD9B59BBFFULL,
		0xCAA54549EFC7608AULL,
		0xA54474C2F6812AFFULL,
		0x6B9DD0DD4F1562A6ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE490947D9A0B2420ULL,
		0x2F33B1514BAD7A89ULL,
		0xC8477D5513639293ULL,
		0x1BD4F73DCFEE69C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55A884F28B862D7EULL,
		0x9F3080EEF2451184ULL,
		0xF33E7CCA60293F22ULL,
		0x1052BD6E75B77485ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EE80F8B0E84F6A2ULL,
		0x9003306259686905ULL,
		0xD509008AB33A5370ULL,
		0x0B8239CF5A36F542ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB2A8406B34A2C10ULL,
		0x336F07BA930CA590ULL,
		0x58E5C4548B4E5DF0ULL,
		0x586549C9A83B18D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90B5AFA8D1083AF6ULL,
		0xB0930A0225067633ULL,
		0xDC850273F567AE2EULL,
		0x2DCB9216EF7D7927ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A74D45DE241F11AULL,
		0x82DBFDB86E062F5DULL,
		0x7C60C1E095E6AFC1ULL,
		0x2A99B7B2B8BD9FAAULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1F539766546D77ULL,
		0x8058AD9C57342D34ULL,
		0x01064D82BAA277F0ULL,
		0x67A4ECC8727C4085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5642627771965F39ULL,
		0x2A7A25DC1B0E72CEULL,
		0xBAACC54601D51D2AULL,
		0x7455E3C85110ED0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67DCF11FF4BE0E2BULL,
		0x55DE87C03C25BA66ULL,
		0x4659883CB8CD5AC6ULL,
		0x734F0900216B5379ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC2B8E4452CD5026ULL,
		0x807D3A25C958E11EULL,
		0xCD708B4C56C91210ULL,
		0x3EE65F96D565028CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2452AC0BCCBF60BBULL,
		0xB9EBB733C8A7C2D2ULL,
		0xA6607B3F9AA6AFE4ULL,
		0x3154B1F8892103FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87D8E238860DEF6BULL,
		0xC69182F200B11E4CULL,
		0x2710100CBC22622BULL,
		0x0D91AD9E4C43FE90ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0659C2093930AF3FULL,
		0x3B92F5FAC7B40B7AULL,
		0x5089A54939A24EC9ULL,
		0x4377F6EB06165CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51430350601AD935ULL,
		0x36FF735F7D34E666ULL,
		0x8A1B9E514C752AEAULL,
		0x6484B5487D67032AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB516BEB8D915D5F7ULL,
		0x0493829B4A7F2513ULL,
		0xC66E06F7ED2D23DFULL,
		0x5EF341A288AF599BULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF643944D647F5304ULL,
		0xFBE364D7BD4E28C4ULL,
		0xE5179B1CF058ECECULL,
		0x4CA172C09804FB3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1529B4945E4902DULL,
		0xE1FE92C2CD62480BULL,
		0x9E52EC8F43194ECFULL,
		0x7F0319B55EA56068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14F0F9041E9AC2C4ULL,
		0x19E4D214EFEBE0B9ULL,
		0x46C4AE8DAD3F9E1DULL,
		0x4D9E590B395F9AD4ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D16E336A1D2DCE8ULL,
		0x8EC9F5B6F9066CDDULL,
		0xC6C200A764B5BF89ULL,
		0x5C47FE7140AFAAC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9458E0CB09B5887FULL,
		0xF39E25E5D8673875ULL,
		0x914380943536E692ULL,
		0x24E61B06DB9EFFA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88BE026B981D5469ULL,
		0x9B2BCFD1209F3467ULL,
		0x357E80132F7ED8F6ULL,
		0x3761E36A6510AB1EULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x578A2F79EB7C0BB9ULL,
		0x7E2F025A8BB81988ULL,
		0x621EEA0F041EF030ULL,
		0x22B8FDD2CEAA332EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98AD0C44092177A1ULL,
		0x56DA6B09555A42FDULL,
		0x6A8A23BAD82BFBDEULL,
		0x64A0BEAC35B4E5D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEDD2335E25A9405ULL,
		0x27549751365DD68AULL,
		0xF794C6542BF2F452ULL,
		0x3E183F2698F54D56ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCA11E978815A435ULL,
		0x5BF0A8DAE1140242ULL,
		0x86B8D4A89A6C712BULL,
		0x5C36C4BB452979CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE47DA0BE2B654DULL,
		0x6EA48AEA30920BCAULL,
		0xBF8E8F65F3F1C2AAULL,
		0x42E07C80A98244C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DBCA0F6C9EA3EE8ULL,
		0xED4C1DF0B081F678ULL,
		0xC72A4542A67AAE80ULL,
		0x1956483A9BA73500ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10FDEE9A8A750A6FULL,
		0x62AA5E63F297766AULL,
		0xA758C03B03C2B2E1ULL,
		0x1DD26327E36C98B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF19F200831A3A64BULL,
		0x692FD3718E5A9C72ULL,
		0xEDBF406ABEFAA2A5ULL,
		0x610E1C3641A729C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F5ECE9258D16411ULL,
		0xF97A8AF2643CD9F7ULL,
		0xB9997FD044C8103BULL,
		0x3CC446F1A1C56EF2ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44380D887F600725ULL,
		0xBA767C1ACCC3CEA4ULL,
		0x4D67B39ED47794FBULL,
		0x2D4A671B036D9557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6FDF3E6829E6A9ULL,
		0xCD5F6E15130F49F7ULL,
		0x3780BC1591B10388ULL,
		0x7F28F6EDD4B5ECB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7C82E4A17362069ULL,
		0xED170E05B9B484ACULL,
		0x15E6F78942C69172ULL,
		0x2E21702D2EB7A8A7ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x299BD62074655425ULL,
		0x62DB7F8E9E20F1A0ULL,
		0x8A2867E97F0FD3ACULL,
		0x3803822AD6B994A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8D7B1D29E8BD7DULL,
		0xF0803DAD5802DB93ULL,
		0xBC4FDAD79B226714ULL,
		0x7FF76D02042721F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D0E5B034A7C9695ULL,
		0x725B41E1461E160CULL,
		0xCDD88D11E3ED6C97ULL,
		0x380C1528D29272B3ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B64B6C0943C0A5DULL,
		0xBFEF8A65BE039F80ULL,
		0x211C7779B485F747ULL,
		0x162AD479F08F5F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4237FC711BC78F68ULL,
		0x4027057909786247ULL,
		0xBBA21E64D02147B5ULL,
		0x316880A803F1932FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE92CBA4F78747AE2ULL,
		0x7FC884ECB48B3D38ULL,
		0x657A5914E464AF92ULL,
		0x64C253D1EC9DCC0EULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28EE7DEB682C60B4ULL,
		0x480BEC242A6F5162ULL,
		0xE2220D0C25B50CD5ULL,
		0x7DB867837F305690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BEA5C7449E9264ULL,
		0x03FBF85A5BC85B18ULL,
		0x34A25B134C56160AULL,
		0x414C45D9AB22DB19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x772FD824238DCE50ULL,
		0x440FF3C9CEA6F649ULL,
		0xAD7FB1F8D95EF6CBULL,
		0x3C6C21A9D40D7B77ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9E78445D6435616ULL,
		0xD6F3A3FBB3675D28ULL,
		0x776D4B7FBFC9A9E1ULL,
		0x5C3AECBC9BF3B095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677C42E090A9B641ULL,
		0x75C92C618F1BED79ULL,
		0x406BD1D7C2131478ULL,
		0x2C098FB7E7BABD87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x826B416545999FD5ULL,
		0x612A779A244B6FAFULL,
		0x370179A7FDB69569ULL,
		0x30315D04B438F30EULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D1FDF9179F85AACULL,
		0x53D491197380EC94ULL,
		0x8F148875D871A2C1ULL,
		0x3B1DB1F66BB2E524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5349AD6EFF93DAULL,
		0x393125B242B0A86AULL,
		0x4F408D3DD18339B4ULL,
		0x02899BE0D3F71569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2CC95E40AF8C6D2ULL,
		0x1AA36B6730D04429ULL,
		0x3FD3FB3806EE690DULL,
		0x3894161597BBCFBBULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B8F9C0B8459B93ULL,
		0x1F7DE597E9ABB5B3ULL,
		0x7AA10D01E0AFA19EULL,
		0x65E7105B00285684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC55A5E5C8BCEAEULL,
		0x2146D681DB55E881ULL,
		0x87BE5C973E7F22A4ULL,
		0x4BB0C011D9B46369ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53F39F625BB9CCE5ULL,
		0xFE370F160E55CD32ULL,
		0xF2E2B06AA2307EF9ULL,
		0x1A3650492673F31AULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0144378582B3F099ULL,
		0x74E5771E1292E7F9ULL,
		0x55A5B0C7DA17A3CEULL,
		0x300A4D83CCCB64ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6DC1CC5557DD933ULL,
		0x7D345BACB48209E9ULL,
		0xE1304D519585B861ULL,
		0x63B7EC8BAA9CA145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A681AC02D361753ULL,
		0xF7B11B715E10DE0FULL,
		0x747563764491EB6CULL,
		0x4C5260F8222EC366ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x413EFC7A921EBDEEULL,
		0x14CCDF3EA1600C20ULL,
		0x5F8E8FF1E8933A5EULL,
		0x0F2FB38345B88D63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x392BF7C206E96D8EULL,
		0x0F15D389FE12E7DBULL,
		0xBBE0E583FE8F9989ULL,
		0x31D6B6DEDF397A58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081304B88B35504DULL,
		0x05B70BB4A34D2445ULL,
		0xA3ADAA6DEA03A0D5ULL,
		0x5D58FCA4667F130AULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF00D25234706F002ULL,
		0xBF44B11E07A29749ULL,
		0x5D95CC71F4691F18ULL,
		0x450AE70EB11F749BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8D289E60A98C411ULL,
		0xA750ACE5B3A9287EULL,
		0x7343F88DBA292E40ULL,
		0x58491E16B15CA27CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF73A9B3D3C6E2BDEULL,
		0x17F4043853F96ECAULL,
		0xEA51D3E43A3FF0D8ULL,
		0x6CC1C8F7FFC2D21EULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5331F769BCBD2E8BULL,
		0xF94E1DF065C91EB8ULL,
		0xB5763A7C84BC4991ULL,
		0x096D390747BFEBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90FF4ECD4F67F27CULL,
		0xEDD850A2851C1D99ULL,
		0xDA6F726E8713CA19ULL,
		0x433314597BB3759DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC232A89C6D553BFCULL,
		0x0B75CD4DE0AD011EULL,
		0xDB06C80DFDA87F78ULL,
		0x463A24ADCC0C7607ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49DADD604E983E1DULL,
		0xD42525C05D7B5CA8ULL,
		0x3C551708F982A4ECULL,
		0x2A44A552B45C1F1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA95E6C4422703F21ULL,
		0xE237F679CF85BA47ULL,
		0xD9E6B2B50AB3635DULL,
		0x2B718441BCC6F4BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA07C711C2C27FEE9ULL,
		0xF1ED2F468DF5A260ULL,
		0x626E6453EECF418EULL,
		0x7ED32110F7952A61ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3FC902856DE91BCULL,
		0x585C59483EAE135BULL,
		0x83A0C2BEA6EF5B0AULL,
		0x06B94A62E5ED2623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6586C9D9FE9B224ULL,
		0x25B7665D3A18FEE7ULL,
		0x97A6D9737259F695ULL,
		0x76B2E1ABF5F9B17EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDA4238AB6F4DF85ULL,
		0x32A4F2EB04951473ULL,
		0xEBF9E94B34956475ULL,
		0x100668B6EFF374A4ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66FC489904C53751ULL,
		0x146C416BCF924E56ULL,
		0x90241DB6E55D8AC8ULL,
		0x30CD4349A3076F60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67787B8C1777A4AEULL,
		0x8D2E5968DF625716ULL,
		0x2055AF90C37FEFE1ULL,
		0x67FC0D5EBA264432ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF83CD0CED4D9290ULL,
		0x873DE802F02FF73FULL,
		0x6FCE6E2621DD9AE6ULL,
		0x48D135EAE8E12B2EULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x979E20DFA2B30D61ULL,
		0x880328158B1B381DULL,
		0xE07D234E71A84E3FULL,
		0x35A3393B44F41EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03763148F037363FULL,
		0xC3F4185EA7A23DC8ULL,
		0xA17CBC653F58F7ECULL,
		0x57DFED68F4F7C8D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9427EF96B27BD70FULL,
		0xC40F0FB6E378FA55ULL,
		0x3F0066E9324F5652ULL,
		0x5DC34BD24FFC561AULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ED07AA08F5D24F9ULL,
		0x58A120657F7983EDULL,
		0xD91CD281216A9C3EULL,
		0x3D96CAC15E6A1013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F2F2AAEE7D3E241ULL,
		0xC0052FD6F7C2D238ULL,
		0x10C33E720CCBABB3ULL,
		0x7A472043F75B0A3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FA14FF1A78942A5ULL,
		0x989BF08E87B6B1B5ULL,
		0xC859940F149EF08AULL,
		0x434FAA7D670F05D8ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46BFD42FC8C0D53AULL,
		0xD30A9F008168B691ULL,
		0xDE93A81152BE9636ULL,
		0x38E6505772CA1218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD76648912D77F0BULL,
		0x8BD08051234EEB2BULL,
		0xC64F1D1E4E710B30ULL,
		0x3C429449E287949DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89496FA6B5E9561CULL,
		0x473A1EAF5E19CB65ULL,
		0x18448AF3044D8B06ULL,
		0x7CA3BC0D90427D7BULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE1A8F339448FFD5ULL,
		0x297AC4C2BE982791ULL,
		0xF345CD287DD8C4C1ULL,
		0x11569A07EED5585EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D02915686351F1BULL,
		0xD0544B81DECC6201ULL,
		0x15FDEC7A9CE7F6A0ULL,
		0x54FDBF077F369886ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC117FDDD0E13E0A7ULL,
		0x59267940DFCBC590ULL,
		0xDD47E0ADE0F0CE20ULL,
		0x3C58DB006F9EBFD8ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11FF709D9D539E08ULL,
		0x5BFF6BFB76F0A76CULL,
		0x83C57A66BE7A02C8ULL,
		0x757AD7CB661D1B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x506C9D15BBF37405ULL,
		0x599D9D2F7FAAB054ULL,
		0xA9870F87D800F9D9ULL,
		0x32B5C864A0954B54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC192D387E1602A03ULL,
		0x0261CECBF745F717ULL,
		0xDA3E6ADEE67908EFULL,
		0x42C50F66C587D018ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEECD589ED35905BBULL,
		0x6AE796CA3A7CF164ULL,
		0x27C24EC3FD5A51CCULL,
		0x6A6814F5B28BEB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2072C08E57022DEEULL,
		0x640F31758E093B43ULL,
		0xD1030AAE8F05A2E7ULL,
		0x0335425F3D988405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE5A98107C56D7CDULL,
		0x06D86554AC73B621ULL,
		0x56BF44156E54AEE5ULL,
		0x6732D29674F3674CULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BF86B8ADC2C4AF4ULL,
		0x3BA13C922E5B9A0AULL,
		0x9450FA7A16C73341ULL,
		0x670AD320BA563E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0B0A4EBCB48DA5ULL,
		0x42EB715C3A3AA71AULL,
		0x6CF57334C8BAE1F7ULL,
		0x755CDC503C5DD6C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECED613C1F77BD3CULL,
		0xF8B5CB35F420F2EFULL,
		0x275B87454E0C5149ULL,
		0x71ADF6D07DF867A7ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x659F8DA819DBE326ULL,
		0xD420591D6B707D57ULL,
		0x14BFEC6E9F8CD52AULL,
		0x1E8186E20DE7BB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD55049C20279B2ULL,
		0xA7C9C1932202FCB5ULL,
		0xDBE19177BAC48275ULL,
		0x470EE4ED2722D6D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68CA3D5E57D96961ULL,
		0x2C56978A496D80A1ULL,
		0x38DE5AF6E4C852B5ULL,
		0x5772A1F4E6C4E464ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39E3860815072E65ULL,
		0x762F976B5629A7E1ULL,
		0xE73680FDC6F1215DULL,
		0x723E66A0C3F041AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC6C94B7915D8E9ULL,
		0x7BFE04E522E59518ULL,
		0x7703CCD3110FBFF3ULL,
		0x2CE69E00E441940BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F1CBCBC9BF1557CULL,
		0xFA319286334412C8ULL,
		0x7032B42AB5E16169ULL,
		0x4557C89FDFAEADA4ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE15F3CB698D4A33ULL,
		0xBBFC828492D34EC6ULL,
		0xBCDFFCAD9F788240ULL,
		0x6832CB51F20D409EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x519C685FEFE0B25EULL,
		0x77094CC83F8A79FBULL,
		0x209FDCD48F226303ULL,
		0x46FB2F4F3311658CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C798B6B79AC97D5ULL,
		0x44F335BC5348D4CBULL,
		0x9C401FD910561F3DULL,
		0x21379C02BEFBDB12ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A3395019C8EAFDFULL,
		0x0ACF9F6858F5C95FULL,
		0x76885857F485A9A8ULL,
		0x49098416EFD703C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24BCEDE4BD0E0A91ULL,
		0xE34A2C64B55C9E31ULL,
		0x3473FC869C2055A6ULL,
		0x63A3EE6B69A78C9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1576A71CDF80A53BULL,
		0x27857303A3992B2EULL,
		0x42145BD158655401ULL,
		0x656595AB862F7726ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B2F4BA8DBCF1F60ULL,
		0x1EC1A91047172C7FULL,
		0x5204D60FE0193E39ULL,
		0x729B8AF94BACAC9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1CC49377BB1CD1DULL,
		0xE2B6EBEEC9EB3F86ULL,
		0x1F0A3587598D4729ULL,
		0x58FE7CAC013D1EA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99630271601D5243ULL,
		0x3C0ABD217D2BECF8ULL,
		0x32FAA088868BF70FULL,
		0x199D0E4D4A6F8DFCULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB22B7F6FC66A095ULL,
		0x444FC9CD33E9EE22ULL,
		0x71D51B5759A970F4ULL,
		0x2A07D7D192E31702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851FA04B459F349EULL,
		0x02416814E3987B9FULL,
		0xC0D6EFCDA615529FULL,
		0x68F58B1A149A81D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x460317ABB6C76BE4ULL,
		0x420E61B850517283ULL,
		0xB0FE2B89B3941E55ULL,
		0x41124CB77E489531ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x198C229F504136B0ULL,
		0x999830538A184E7EULL,
		0x94EA71BD5FAF5044ULL,
		0x0E816074A1FCF8B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC347B34A56F8D247ULL,
		0x5FE9D3BEF421D40AULL,
		0xB6AAC2179398F8AAULL,
		0x38ECF955B59DD1B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56446F54F9486456ULL,
		0x39AE5C9495F67A73ULL,
		0xDE3FAFA5CC16579AULL,
		0x5594671EEC5F26FDULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C263D805AD1C81AULL,
		0x606CBB54150A458DULL,
		0xB9782BB4D9DDB080ULL,
		0x0D311A7A293585BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9E92FD12E311BFULL,
		0x4625BC60916E3380ULL,
		0xC20086C2FB462271ULL,
		0x5C32B3AE67CBCF31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D87AA8347EEB648ULL,
		0x1A46FEF3839C120CULL,
		0xF777A4F1DE978E0FULL,
		0x30FE66CBC169B68BULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFE4A3E93502BBA9ULL,
		0x1914FA8E6256ED4DULL,
		0xE6D77116A668BE2CULL,
		0x29D92954E34B067BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23C029FA7E4B02D1ULL,
		0x7EC71FFF5C66C9ACULL,
		0x2EBB28926BA6EB87ULL,
		0x5F9E8F873EC2105AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C2479EEB6B7B8C5ULL,
		0x9A4DDA8F05F023A1ULL,
		0xB81C48843AC1D2A4ULL,
		0x4A3A99CDA488F621ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED36ED80DFCD69D7ULL,
		0x9D3A425C61F52E16ULL,
		0x785FF1FBA2E43D4FULL,
		0x6D0DB380BD818A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0893D8D85DF869ULL,
		0x1399CAD0AE66EF64ULL,
		0xCAD44C3172789963ULL,
		0x68330051E2960FB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x412E59A8076F716EULL,
		0x89A0778BB38E3EB2ULL,
		0xAD8BA5CA306BA3ECULL,
		0x04DAB32EDAEB7A50ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0A44160F9417D9CULL,
		0x0B1075E6A0AB607FULL,
		0x84F0038638FC19E2ULL,
		0x3B8EA1FADD1F3E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x454CBCB716024316ULL,
		0x051711E6F3A9E599ULL,
		0x002758DCABD8491FULL,
		0x5E2B9450BF69BA60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B5784A9E33F3A73ULL,
		0x05F963FFAD017AE6ULL,
		0x84C8AAA98D23D0C3ULL,
		0x5D630DAA1DB583E2ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x883549ABE0015222ULL,
		0x964F7463C1853BC4ULL,
		0xC7F090CF2E692770ULL,
		0x011F349284455DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809AC6716E197671ULL,
		0x1B1B69D9ABA2A9D0ULL,
		0x3D98884BE9BA46BAULL,
		0x66B8FEC76C3C87D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x079A833A71E7DB9EULL,
		0x7B340A8A15E291F4ULL,
		0x8A58088344AEE0B6ULL,
		0x1A6635CB1808D5F1ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21BFA6DC65694E0DULL,
		0x49380B33691433CAULL,
		0xC3B591775B6E00CAULL,
		0x012C97C1B4369AACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB573FEF9C77C6825ULL,
		0xD35FCDF7192A5A1CULL,
		0x14F37A4D8827F479ULL,
		0x3E4E878B957F635DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C4BA7E29DECE5D5ULL,
		0x75D83D3C4FE9D9ADULL,
		0xAEC21729D3460C50ULL,
		0x42DE10361EB7374FULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7845063008ADBD6BULL,
		0xFD4C1644C098032AULL,
		0x5176861FC5584807ULL,
		0x7187EA728C461CD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B6AD349B4CCD73ULL,
		0x8D3A0EB5DC7285E0ULL,
		0x32584EA20C53FA9CULL,
		0x7A5C6A17CB60380DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF08E58FB6D60EFE5ULL,
		0x7012078EE4257D49ULL,
		0x1F1E377DB9044D6BULL,
		0x772B805AC0E5E4C9ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAE43E6CCD0DC10DULL,
		0x8E07E9FF8896FC69ULL,
		0x227A7FE9BE23C60CULL,
		0x1B64315054B1C589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5F18E39D192CE0ULL,
		0x41D9AC0F391B364CULL,
		0xF166DD8E30E58027ULL,
		0x42AC2815AB67F667ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008525892FF4941AULL,
		0x4C2E3DF04F7BC61DULL,
		0x3113A25B8D3E45E5ULL,
		0x58B8093AA949CF21ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF2A61AE545D7E5CULL,
		0xD472DE1DFC28E5C5ULL,
		0x19524034FEF33BC1ULL,
		0x1E9F096C924E89CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2432CE036A330F5EULL,
		0xF88F6B5A85AC49DBULL,
		0x7571D8207F927DDBULL,
		0x102150A0C728DC5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AF793AAEA2A6EFEULL,
		0xDBE372C3767C9BEAULL,
		0xA3E068147F60BDE5ULL,
		0x0E7DB8CBCB25AD71ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A98977EF43E3116ULL,
		0x159712FE187DE5B5ULL,
		0xFB6DC0E95530E601ULL,
		0x03C30C3648BD6F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB22E9EBE23C2F23ULL,
		0x136F67D6CE8F2FD6ULL,
		0xDB66AA9D6F1DC375ULL,
		0x74F9004556676E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F75AD93120201E0ULL,
		0x0227AB2749EEB5DEULL,
		0x2007164BE613228CULL,
		0x0ECA0BF0F25600B7ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D3E17E9F0F214DDULL,
		0x81DBD5C2B81623D0ULL,
		0x47F453E25D84A15AULL,
		0x23AE61B306EA9A88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FED6F0859CD378ULL,
		0xA81AF83F70F7F73DULL,
		0x92BA96156AE822B3ULL,
		0x1775BEDFE2CFC636ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x073F40F96B554165ULL,
		0xD9C0DD83471E2C93ULL,
		0xB539BDCCF29C7EA6ULL,
		0x0C38A2D3241AD451ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CD6DB44471CCFB1ULL,
		0x962DA54693FE0FB6ULL,
		0xA2B8BED2E2C27939ULL,
		0x5A0AEBF3BC714291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA2BB22EEC0FF9A9ULL,
		0xFFCFD3B9BCE66747ULL,
		0xF8394F35880956FCULL,
		0x42A0887CA841F400ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42AB29155B0CD608ULL,
		0x965DD18CD717A86EULL,
		0xAA7F6F9D5AB9223CULL,
		0x176A6377142F4E90ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B1D7B3C2CA31387ULL,
		0xDA0A76EE7C905F62ULL,
		0xCC5BB5C408E9083CULL,
		0x712C4096A433EA0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A3CC12945354F3ULL,
		0x1D3CA211676EA50DULL,
		0x4FA928A46AB11042ULL,
		0x4E102E7C55D00C06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF779AF29984FBE94ULL,
		0xBCCDD4DD1521BA54ULL,
		0x7CB28D1F9E37F7FAULL,
		0x231C121A4E63DE08ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01335CBA72CD6C4EULL,
		0x2CEF084C5FDF319FULL,
		0x7445706ECEC2B01AULL,
		0x4A482DA6F2590E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC4CFF91F476A2F7ULL,
		0x91D51761851EB42BULL,
		0xE70298A2BBB8417AULL,
		0x2CECE2A27A9C6553ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E65D287E56C957ULL,
		0x9B19F0EADAC07D73ULL,
		0x8D42D7CC130A6E9FULL,
		0x1D5B4B0477BCA946ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9143B2DD579951EULL,
		0x42A8F58CF98DCAD7ULL,
		0xAA1ACEAEFD11AF46ULL,
		0x6AFD58602A1C49B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86242545103D2D31ULL,
		0x861D53DCE9D8035BULL,
		0xA06B13697D9C7CA9ULL,
		0x100438E196E3C214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52F015E8C53C67EDULL,
		0xBC8BA1B00FB5C77CULL,
		0x09AFBB457F75329CULL,
		0x5AF91F7E933887A3ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF753DAE6295C6E0BULL,
		0x3E9A5EB9A9B2542DULL,
		0xB6172B2953731A9EULL,
		0x2A155531D2CFC921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x188E075C0AB1DF2CULL,
		0xF4685A6EE961C533ULL,
		0x5C9C66AF82FB655BULL,
		0x71B423F976CEC2E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEC5D38A1EAA8ECCULL,
		0x4A32044AC0508EFAULL,
		0x597AC479D077B542ULL,
		0x386131385C01063AULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x113F7E9F0D662ADAULL,
		0x406F4458D865958FULL,
		0xB6A6142616A2EABDULL,
		0x4A3DFF45A08AEEE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8AEA62EF6FD8B5ULL,
		0x0F233E5CC1E270C4ULL,
		0x2C203A3F47ABFF06ULL,
		0x410A0FFE4D208516ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85B4943C1DF65225ULL,
		0x314C05FC168324CAULL,
		0x8A85D9E6CEF6EBB7ULL,
		0x0933EF47536A69D2ULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x545A64E46CF9568DULL,
		0x070E16DC1B2228F8ULL,
		0x5F49800928D4B2E8ULL,
		0x48B07024CB2989F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8AFC0D54E1C8C8ULL,
		0x4C7C7A888D3C0277ULL,
		0xAC6299E909921875ULL,
		0x02B3535663DA6C6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17CF68D718178DC5ULL,
		0xBA919C538DE62681ULL,
		0xB2E6E6201F429A72ULL,
		0x45FD1CCE674F1D8DULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB1A6ADB25B03F53ULL,
		0x996D23559485CF61ULL,
		0x5405D0EB62291D32ULL,
		0x09E4D1A56CFA2A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA44C1ED74505A5ULL,
		0x386E380AB4BD23CAULL,
		0x46B6AFE437986136ULL,
		0x318D9C507F399362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF761EBC4E6B399BULL,
		0x60FEEB4ADFC8AB96ULL,
		0x0D4F21072A90BBFCULL,
		0x58573554EDC096ECULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x531F536CC3A8ECB0ULL,
		0x98ECEE26936A7ABCULL,
		0x4BFB5437B6011EF3ULL,
		0x170588CA060FC0DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53D8FAB833A231B6ULL,
		0x70DB9E599C976989ULL,
		0x93D9BBEBFE7A200FULL,
		0x0CC0769E4276BC28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF4658B49006BAFAULL,
		0x28114FCCF6D31132ULL,
		0xB821984BB786FEE4ULL,
		0x0A45122BC39904B1ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0626049BB46043B0ULL,
		0x924EDF1BEEA7ED16ULL,
		0x97B88F8C1C2762EBULL,
		0x02491758067852AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF38720A49CBAF59ULL,
		0xA3BFA6E3561BCD4DULL,
		0xAB3122ACFDBA74D9ULL,
		0x01C7D9DB3615A57CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06ED92916A949457ULL,
		0xEE8F3838988C1FC8ULL,
		0xEC876CDF1E6CEE11ULL,
		0x00813D7CD062AD32ULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16FCFC0F31D1F6E5ULL,
		0x403CFA69518CECBBULL,
		0x0424E7A9D5CF5676ULL,
		0x241C5C5B75BE0FBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4148EB1846743A6DULL,
		0x82985EE7A638ABA4ULL,
		0x714CEDA1764A5195ULL,
		0x1358279C3EE524CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5B410F6EB5DBC78ULL,
		0xBDA49B81AB544116ULL,
		0x92D7FA085F8504E0ULL,
		0x10C434BF36D8EAF4ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A2D1A4747CDED6ULL,
		0x7E07188C7696BD3FULL,
		0xFE5EDC9DCA8800C1ULL,
		0x07B75AD9E512D564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3DF30FA483153B8ULL,
		0x4FDEEA88670BCD73ULL,
		0x2C154EB08050947DULL,
		0x060D217967389EB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CC3A0AA2C4B8B1EULL,
		0x2E282E040F8AEFCBULL,
		0xD2498DED4A376C44ULL,
		0x01AA39607DDA36ABULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04C9DEDBAEC0A57AULL,
		0x44627D452FD7F87BULL,
		0xD18D0C650935F73EULL,
		0x0B1396F578E0DD45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7906F6110301BEB7ULL,
		0xEEED2CAC131106D3ULL,
		0x6751C3A16D3792A3ULL,
		0x02E88E717BD5323BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BC2E8CAABBEE6C3ULL,
		0x557550991CC6F1A7ULL,
		0x6A3B48C39BFE649AULL,
		0x082B0883FD0BAB0AULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E400EDF35D6256BULL,
		0xD28E5504CB44E4DBULL,
		0x4A2DF4CE70DC90C7ULL,
		0x27CB13B032E30231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B2B4F94E8BA15DULL,
		0xC1D46068BBF35275ULL,
		0xDE8D3077F642B1D4ULL,
		0x4E10E82B22530DF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE58D59E5E74A83FBULL,
		0x10B9F49C0F519265ULL,
		0x6BA0C4567A99DEF3ULL,
		0x59BA2B85108FF43CULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0333B2AD3BF9F2ECULL,
		0x5B5A01AC90E31F70ULL,
		0xA565A430F869CACAULL,
		0x2480347972B7E7C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B207555F03122C6ULL,
		0x7BD5ACFD3192CD84ULL,
		0xF61DF70DF46E2E6BULL,
		0x01794BFE4BF70738ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98133D574BC8D026ULL,
		0xDF8454AF5F5051EBULL,
		0xAF47AD2303FB9C5EULL,
		0x2306E87B26C0E087ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7814F7855BDBC721ULL,
		0x1C2099DC5776D226ULL,
		0x4A9AC42D8A4DC9C2ULL,
		0x7D51797699DFB880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CF25DC0CCABB5BULL,
		0x59BCB39BD7DE6648ULL,
		0x81F58B54FC00765BULL,
		0x193EEAED167ECE61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA645D1A94F110BC6ULL,
		0xC263E6407F986BDDULL,
		0xC8A538D88E4D5366ULL,
		0x64128E898360EA1EULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26BB9E3071E170D2ULL,
		0x4B16273490471C88ULL,
		0x58D7CAC1A36223FDULL,
		0x3EBDF52AB9471B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95721AACAAC6C26DULL,
		0x69EAF59CFB368CA2ULL,
		0x07659AE284C072B4ULL,
		0x68CF0904C5D5FEC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91498383C71AAE52ULL,
		0xE12B319795108FE5ULL,
		0x51722FDF1EA1B148ULL,
		0x55EEEC25F3711CCDULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x268F5B8C8C82D56BULL,
		0x5ACA96FCD6416B0EULL,
		0x8608E94AA83D5692ULL,
		0x1EBFFCE612E5BA36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3416086C43EB6923ULL,
		0x504D44E8446FFC47ULL,
		0xC024EF08D866725EULL,
		0x7EBF8971BB459596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF279532048976C35ULL,
		0x0A7D521491D16EC6ULL,
		0xC5E3FA41CFD6E434ULL,
		0x2000737457A0249FULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92127F09BF7C965DULL,
		0x03A6279E1168C738ULL,
		0xFC532DE9E6C67608ULL,
		0x503CAB7119B02779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97CDE23E6D42190EULL,
		0x363836DE97663A80ULL,
		0x32B0EB76012B3F0FULL,
		0x18468202E522AC18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA449CCB523A7D4FULL,
		0xCD6DF0BF7A028CB7ULL,
		0xC9A24273E59B36F8ULL,
		0x37F6296E348D7B61ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA6EAC007F3A8A2ULL,
		0xD5B2DA76A2AE188FULL,
		0x953BCC69A2121D0DULL,
		0x35FDDAA7179FBA1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC433BEAFCFC6A011ULL,
		0xCB84588B446A8022ULL,
		0xF25C415A77F0738BULL,
		0x4ADF9A2E3B4273C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96732C10382D087EULL,
		0x0A2E81EB5E43986CULL,
		0xA2DF8B0F2A21A982ULL,
		0x6B1E4078DC5D4655ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF99805F646CB5952ULL,
		0xE026D2C25B96ACE4ULL,
		0xB232C3C932014B45ULL,
		0x2ECBCFF0314156BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BA380116A777A93ULL,
		0x9B28C6EB99248D32ULL,
		0x57C379E8FD6D8D79ULL,
		0x25DEB8949DBB5FBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDF485E4DC53DEBFULL,
		0x44FE0BD6C2721FB2ULL,
		0x5A6F49E03493BDCCULL,
		0x08ED175B9385F704ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x918DF6B2466C78E0ULL,
		0xAE667482B3AC4C5BULL,
		0x449437C407E7C104ULL,
		0x75E7798E324D89BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC194134B783D9DULL,
		0xF0A3BE4025B5C388ULL,
		0x2D44FAF2F58204D9ULL,
		0x57C5A8682D181E40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3CC629EFAF43B43ULL,
		0xBDC2B6428DF688D2ULL,
		0x174F3CD11265BC2AULL,
		0x1E21D12605356B7CULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29CAB26283E9468BULL,
		0x966FBC95D20079C3ULL,
		0x56D607BAB4B5AF57ULL,
		0x4DD7C78F3630C146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x337F4B164DC18B8DULL,
		0x83B3AC6AF93C9AC9ULL,
		0xEE56123DE2228FC6ULL,
		0x6D6B49635814A2B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF64B674C3627BAEBULL,
		0x12BC102AD8C3DEF9ULL,
		0x687FF57CD2931F91ULL,
		0x606C7E2BDE1C1E8FULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AC917BE073FBE4FULL,
		0x16895C45F8D7F42FULL,
		0x08A64FD8AE85A3FEULL,
		0x3213B17C296D2974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA6961D9CFF6A1BULL,
		0x43A29D668C95DCEAULL,
		0x411EF961E6AB82D7ULL,
		0x2C6A19D341641D6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E2281A06A405434ULL,
		0xD2E6BEDF6C421745ULL,
		0xC7875676C7DA2126ULL,
		0x05A997A8E8090C06ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF61D224FFE346E35ULL,
		0xD99306C6EF66785EULL,
		0xF8E857F88785A7EBULL,
		0x1B42EF426A952EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26EECE119422A10DULL,
		0x3F92E1BD914C76D4ULL,
		0x33A8AC70E6B55EAAULL,
		0x0AC562A0759188A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF2E543E6A11CD28ULL,
		0x9A0025095E1A018AULL,
		0xC53FAB87A0D04941ULL,
		0x107D8CA1F503A645ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}