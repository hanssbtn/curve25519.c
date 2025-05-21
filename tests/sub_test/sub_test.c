#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x5834EBF24ACAC208ULL,
		0x8AFBE59F2E4ED747ULL,
		0x2BB799B25B267E22ULL,
		0x63DFE948F04887EFULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xDA7BF155C48E4E2EULL,
		0x50E5D7FA902A32D9ULL,
		0x411214B11AB00F9EULL,
		0x254DF10C991FE240ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x7DB8FA9C863C73DAULL,
		0x3A160DA49E24A46DULL,
		0xEAA5850140766E84ULL,
		0x3E91F83C5728A5AEULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
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
		0x8718F94FA2432E2CULL,
		0x5789B5BB026F8A82ULL,
		0x886D7D7A4422F709ULL,
		0x62AFA242E930B420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0812A0033FDEFACULL,
		0x2154A4FDB220A5A9ULL,
		0xA176327D7AD1AC88ULL,
		0x30732B9081400CF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9697CF4F6E453E80ULL,
		0x363510BD504EE4D8ULL,
		0xE6F74AFCC9514A81ULL,
		0x323C76B267F0A72BULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC0F487461795247EULL,
		0x7F5BE1E6575212F6ULL,
		0x685C8F9DE6A078BBULL,
		0x2CB74B46A0AE093AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x555BDE6AB2A89C17ULL,
		0xB65DC8BB71F6890AULL,
		0x17207F370E07F3EAULL,
		0x6113E26C2A415B6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B98A8DB64EC8854ULL,
		0xC8FE192AE55B89ECULL,
		0x513C1066D89884D0ULL,
		0x4BA368DA766CADCFULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x35E52F10AA295B49ULL,
		0x6C151A8164688578ULL,
		0x0554D15F14F5C57AULL,
		0x37FD2E0805F90FA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA861271B87EF696ULL,
		0xA389829B00F8F6AFULL,
		0xCC577B855C47F9E3ULL,
		0x1C4AF7C2B57B6E3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B5F1C9EF1AA64B3ULL,
		0xC88B97E6636F8EC8ULL,
		0x38FD55D9B8ADCB96ULL,
		0x1BB23645507DA161ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2DE1B6F2481C583DULL,
		0xFCE5C07E1A569A81ULL,
		0x1E326EBD46C26B03ULL,
		0x79A45CE87B5EBC5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19743130EC23CBB8ULL,
		0xBC5CA2F07D51922EULL,
		0x2CF1A049602D25BBULL,
		0x63E59CA49769098EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x146D85C15BF88C85ULL,
		0x40891D8D9D050853ULL,
		0xF140CE73E6954548ULL,
		0x15BEC043E3F5B2CCULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3055AF7D55C8BD9EULL,
		0x2A90658FEDCCF061ULL,
		0xB5C1CF16BE3C5CB8ULL,
		0x2AEEF56D265C72F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC89FD13675573A3EULL,
		0xE363855FCBBAD5D8ULL,
		0xA27C622D0CCCD533ULL,
		0x2EF033D8E4310002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67B5DE46E071834DULL,
		0x472CE03022121A88ULL,
		0x13456CE9B16F8784ULL,
		0x7BFEC194422B72F7ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x072841155E81CCE9ULL,
		0x839D7DD7A329E489ULL,
		0x9AC85C113343E073ULL,
		0x485D171A902A0305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1775AC12537D9F0ULL,
		0xF2924750A4183050ULL,
		0xAD9B8B087BC14EBFULL,
		0x1AA18B7B5E8E29DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55B0E6543949F2F9ULL,
		0x910B3686FF11B438ULL,
		0xED2CD108B78291B3ULL,
		0x2DBB8B9F319BD92AULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x4E01493864B5DEC6ULL,
		0x1AE1243EA584B3A4ULL,
		0xEB954E9713FFD003ULL,
		0x27EDD1BAD96B4819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D340A388EC875CULL,
		0x7A63175BE3CEF1DEULL,
		0x1695DB71C7682497ULL,
		0x06D0651B55C6460AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB92E0894DBC9576AULL,
		0xA07E0CE2C1B5C1C5ULL,
		0xD4FF73254C97AB6BULL,
		0x211D6C9F83A5020FULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x15EBECA04A0FE27BULL,
		0x4E4300EAB3279F12ULL,
		0xF4A45B00BB18A985ULL,
		0x0506348829591CDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC7AFEC09766141ULL,
		0x9C3DFED14FF6CAE3ULL,
		0xB2F7E315B6C1E730ULL,
		0x2D0BD550B604E457ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9243CB440998127ULL,
		0xB20502196330D42EULL,
		0x41AC77EB0456C254ULL,
		0x57FA5F3773543885ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x258210CC3E9DB572ULL,
		0xFCFF30B9AA6B0BDDULL,
		0xCEFCBDA546962521ULL,
		0x4CC75B1E138A96EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98F90FEF7A2D1E9FULL,
		0x0E9C335AEFE61720ULL,
		0x24EBA116C3FD0F14ULL,
		0x39B07858F1542C11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8900DCC47096D3ULL,
		0xEE62FD5EBA84F4BCULL,
		0xAA111C8E8299160DULL,
		0x1316E2C522366ADEULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2D1206BA766CF2BEULL,
		0x02819760C8B5AAC5ULL,
		0xC877879A182C874AULL,
		0x6BC2928FC178F680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA4D369A1FD0FC4ULL,
		0xE33D406BAD5BEEECULL,
		0x8A6C2F1486B4D8DAULL,
		0x266CDD64AC996EBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF6D3350D46FE2FAULL,
		0x1F4456F51B59BBD8ULL,
		0x3E0B58859177AE6FULL,
		0x4555B52B14DF87C6ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA8F103207FE2576EULL,
		0xBD282C54CCECB939ULL,
		0xD9087FFC9E80B345ULL,
		0x7BCD9BA06BD0964FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24045BD5DF1E0B0BULL,
		0xD4A32DCD4EFFEAB1ULL,
		0xE640CE351B1EED58ULL,
		0x0FFE6482FAB2B7ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84ECA74AA0C44C63ULL,
		0xE884FE877DECCE88ULL,
		0xF2C7B1C78361C5ECULL,
		0x6BCF371D711DDEA1ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x13C555AEB8A9B304ULL,
		0x0F2CF2CA3301891AULL,
		0x21E3FDC836606050ULL,
		0x242BFB764E4F53D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD7F40017FA96976ULL,
		0x287516CDA4F54B5BULL,
		0x2CF81C7A6BF363BFULL,
		0x7A153D55D8755E69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x164615AD3900497BULL,
		0xE6B7DBFC8E0C3DBEULL,
		0xF4EBE14DCA6CFC90ULL,
		0x2A16BE2075D9F56CULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB5C1541F0537CBDDULL,
		0x946FE1459EA229E2ULL,
		0x0DF78FD02C82AA3BULL,
		0x602FEA9184C38617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20B14B3251D0CF9EULL,
		0xB3EB7792373E9542ULL,
		0xBFBC63A030BE6D54ULL,
		0x33CD4208E0CFFB74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x951008ECB366FC3FULL,
		0xE08469B3676394A0ULL,
		0x4E3B2C2FFBC43CE6ULL,
		0x2C62A888A3F38AA2ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x731FEA7C94E72726ULL,
		0xE8360B20373D69A6ULL,
		0xB3D47B7FFFF3B908ULL,
		0x1A2FEE3EB667AB03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D60BB604B32DA57ULL,
		0x386AD9721C0276A4ULL,
		0xBF644F112A5F5EF4ULL,
		0x5D1A2A3770CA76F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05BF2F1C49B44CBCULL,
		0xAFCB31AE1B3AF302ULL,
		0xF4702C6ED5945A14ULL,
		0x3D15C407459D3409ULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB5DD79960B6AF091ULL,
		0x9A7D0C73B484B96FULL,
		0x2BE91B53228CAAB6ULL,
		0x4B79E2B59622DD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x316D41D5886C43B1ULL,
		0xE9C06DA6F43014F7ULL,
		0x38A8A8E776F9327CULL,
		0x043C0B251D9A4AC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x847037C082FEACE0ULL,
		0xB0BC9ECCC054A478ULL,
		0xF340726BAB937839ULL,
		0x473DD79078889272ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA9EE9F06670B47CEULL,
		0x382D11DF1DA2C091ULL,
		0x5F393268E508E128ULL,
		0x2A24B9B2442A4A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1B87BD5B0F6CBBBULL,
		0xD979B959EAE569A0ULL,
		0x66EFDC149D2BD746ULL,
		0x2E080C91402C2B25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08362330B6147C00ULL,
		0x5EB3588532BD56F1ULL,
		0xF849565447DD09E1ULL,
		0x7C1CAD2103FE1F64ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x3844ADD99BDCECE2ULL,
		0x8AAEA2DA38629038ULL,
		0x97878DA4E3BDBA89ULL,
		0x0BF16A574B187BA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931643EA04D24498ULL,
		0x1ECAD1F5A131E7ADULL,
		0x111E759074E4B913ULL,
		0x427CDE4BC30CE7DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA52E69EF970AA837ULL,
		0x6BE3D0E49730A88AULL,
		0x866918146ED90176ULL,
		0x49748C0B880B93C9ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x2344C0A8BFA23B15ULL,
		0x43C39BF78849E96FULL,
		0x8080B0C588680E0EULL,
		0x740255B056A1F8A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69FFD063EDFA5B1ULL,
		0x81B59B1391E6CF02ULL,
		0x1DA9B16C2CA45792ULL,
		0x5956E4F5B1730D1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5CA4C3A280C29564ULL,
		0xC20E00E3F6631A6CULL,
		0x62D6FF595BC3B67BULL,
		0x1AAB70BAA52EEB89ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x24B6FCCFB73A331EULL,
		0x134558AF178754B3ULL,
		0x87B0F3CC130CD252ULL,
		0x79594A9E4C79BFDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957A6C5D5001BBBAULL,
		0x9EF1E5C98CC81512ULL,
		0xF9264CC0DC0A3B4FULL,
		0x7CA5660C3AA4CFB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F3C907267387751ULL,
		0x745372E58ABF3FA0ULL,
		0x8E8AA70B37029702ULL,
		0x7CB3E49211D4F024ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9510ACA7E5622C04ULL,
		0xA70CA36E91D3A757ULL,
		0xD5B5663D2AEA71FCULL,
		0x188B3985171E166CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4F9FD1848F0568DULL,
		0x50B3C82298661542ULL,
		0x9A9DAAEB04C75757ULL,
		0x462151225B8EE066ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE016AF8F9C71D564ULL,
		0x5658DB4BF96D9214ULL,
		0x3B17BB5226231AA5ULL,
		0x5269E862BB8F3606ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xD2B4BF0E3BBE603BULL,
		0x2A19F9EA9FD104EAULL,
		0x6D6C5F4650B38455ULL,
		0x508DD7D4A76A417DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0481F2A2575F7DA3ULL,
		0xB64B062746B026A2ULL,
		0xF803F3290C8DD917ULL,
		0x4C2D5131D693A28BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE32CC6BE45EE298ULL,
		0x73CEF3C35920DE48ULL,
		0x75686C1D4425AB3DULL,
		0x046086A2D0D69EF1ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC3C72D971ACE16F5ULL,
		0xABB103CCBE2C1565ULL,
		0x75509004537AA6CDULL,
		0x4D83CCB294AE2E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F3FF30BB30713EULL,
		0xF6748E9E07B08951ULL,
		0x17C07FB490BE1412ULL,
		0x5FA5FDF28761ED69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2D32E665F9DA5A4ULL,
		0xB53C752EB67B8C14ULL,
		0x5D90104FC2BC92BAULL,
		0x6DDDCEC00D4C40A0ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x5EA20BAB8FC1B0F0ULL,
		0x765509224A1A1201ULL,
		0x41E7D8A3F53FA03BULL,
		0x30D9B6FEE082B07BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A37605A8E0ECF1ULL,
		0xCD1B1A6D1E175D23ULL,
		0x9ABE1702B658F033ULL,
		0x3EA5F0467D99EB2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CFE95A5E6E0C3ECULL,
		0xA939EEB52C02B4DEULL,
		0xA729C1A13EE6B007ULL,
		0x7233C6B862E8C550ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9834D52F2DB9E4DEULL,
		0x69D7262B2D7C2923ULL,
		0xA0AD71AA842AF5DBULL,
		0x4BE6477AE0981F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFF21C9C1694955ULL,
		0x60E8D465937C63D6ULL,
		0xEB2BFD7AB6D99116ULL,
		0x7338FA64752FE04AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D35B3656C509B76ULL,
		0x08EE51C599FFC54DULL,
		0xB581742FCD5164C5ULL,
		0x58AD4D166B683F14ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC3B229CA1BAF525FULL,
		0xB7A3A493A25F8BE8ULL,
		0xFCFC6483EA9898BDULL,
		0x772F257422E942E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA8E3C2B06B3E841ULL,
		0x31BF57FA0F43B2CEULL,
		0x54095F552F4E27CBULL,
		0x538C624F4B184C1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0923ED9F14FB6A1EULL,
		0x85E44C99931BD91AULL,
		0xA8F3052EBB4A70F2ULL,
		0x23A2C324D7D0F6C6ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xB5C10770B65D14F0ULL,
		0xBCDEFD0665C29CEAULL,
		0x5D71867147AD4AADULL,
		0x6F2EE821773EEA04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E9978A7FE15B72ULL,
		0x12BBF83BEE3DBF1AULL,
		0x9EC0C9270366F3D3ULL,
		0x7F83B7B9E01F07EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1D76FE6367BB96BULL,
		0xAA2304CA7784DDCFULL,
		0xBEB0BD4A444656DAULL,
		0x6FAB3067971FE214ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC3A32320D7D2DFFCULL,
		0x8F892CC45E988C00ULL,
		0x742DB24BC20CFB34ULL,
		0x4B001A3DDB5A0440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DB5A9BE410452CULL,
		0xCDEF33E64168A378ULL,
		0xCB84A9D64BD498A9ULL,
		0x5F02A86A827A33EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C7C884F3C29ABDULL,
		0xC199F8DE1D2FE888ULL,
		0xA8A908757638628AULL,
		0x6BFD71D358DFD051ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x892C141C1081D508ULL,
		0x3632C648973A039AULL,
		0xF0BBB56110D85B08ULL,
		0x2C9DEBF3DE77B262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB23F12374A56D15ULL,
		0x14BA9F312FB670F3ULL,
		0x1421042B326705CBULL,
		0x7066F020BA5B981BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE0822F89BDC67E0ULL,
		0x21782717678392A6ULL,
		0xDC9AB135DE71553DULL,
		0x3C36FBD3241C1A47ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x25BF54AA5C26DA47ULL,
		0xD7E02394C8D41527ULL,
		0x152894DD59963006ULL,
		0x3BBC79ED18FAA818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x747775E4FDAA807CULL,
		0xCB1FEC1DD1409FFFULL,
		0x93F2695B8329E1F7ULL,
		0x16AC072293A8407BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB147DEC55E7C59CBULL,
		0x0CC03776F7937527ULL,
		0x81362B81D66C4E0FULL,
		0x251072CA8552679CULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x8790205EAC280470ULL,
		0xD9742AB8298007B3ULL,
		0xC149FD31ADD9DE85ULL,
		0x3545FFED1B864A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32984F2F7F9B4867ULL,
		0xFBFFA77489600847ULL,
		0x813D811F2E672326ULL,
		0x660ACE4F2FDB4D0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54F7D12F2C8CBBF6ULL,
		0xDD748343A01FFF6CULL,
		0x400C7C127F72BB5EULL,
		0x4F3B319DEBAAFCF8ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x290A90E5DC2C9F99ULL,
		0x2D29DEF900A90E33ULL,
		0xA58A706BF09B7793ULL,
		0x5F321F73E47E7CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7492D2997D4239C2ULL,
		0xBF84522A08454301ULL,
		0x65A6C53BD0EEC3AFULL,
		0x1A0290A5F36F1F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB477BE4C5EEA65D7ULL,
		0x6DA58CCEF863CB31ULL,
		0x3FE3AB301FACB3E3ULL,
		0x452F8ECDF10F5DB1ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9AF901E606F85AD5ULL,
		0x1A4E03A49E228246ULL,
		0xCC23C975E4A5F4F6ULL,
		0x395B4ABADBE1052CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x061A9433442C2790ULL,
		0x241E4B67A44B007DULL,
		0x89AE533A4E5F0429ULL,
		0x651528CFB2498352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94DE6DB2C2CC3332ULL,
		0xF62FB83CF9D781C9ULL,
		0x4275763B9646F0CCULL,
		0x544621EB299781DAULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x1068F21ED30A45EFULL,
		0x4D18F43DA4CB6329ULL,
		0x73CCB6676C2CCED9ULL,
		0x02A5D7CC3A649F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1846A7AFB65582DAULL,
		0x0547D5B14AAA81DAULL,
		0x0EDB26DE230B9081ULL,
		0x6B80A1C8050EDD36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8224A6F1CB4C302ULL,
		0x47D11E8C5A20E14EULL,
		0x64F18F8949213E58ULL,
		0x172536043555C224ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x29636767E6E06750ULL,
		0x4AF275BCEBD55B09ULL,
		0x57F36D8C8A0BDE9AULL,
		0x0389FC66C69FBB87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034C36457EFFEB91ULL,
		0xE9ED95CD74BC5409ULL,
		0x313E952C71655593ULL,
		0x0679D932D9062E09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2617312267E07BACULL,
		0x6104DFEF77190700ULL,
		0x26B4D86018A68906ULL,
		0x7D102333ED998D7EULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x09571C9B5C5255FBULL,
		0x4E7310E81F0015ACULL,
		0x4982C9DAD0FCC071ULL,
		0x7DB0F78C513B81A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x193455EA3C9BF619ULL,
		0xAFD0487DBBD28581ULL,
		0x4570F4E157DA1286ULL,
		0x37B410978B575A28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF022C6B11FB65FE2ULL,
		0x9EA2C86A632D902AULL,
		0x0411D4F97922ADEAULL,
		0x45FCE6F4C5E4277EULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE11428BFEBB17090ULL,
		0xEC1CA0C3B68BEE40ULL,
		0x8645B67805C10A2FULL,
		0x09D2A437C90B5728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1DF31447D507ECULL,
		0x7740741362F1C72BULL,
		0xE997794090968A33ULL,
		0x334945290FCC0547ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04F635ABA3DC6891ULL,
		0x74DC2CB0539A2715ULL,
		0x9CAE3D37752A7FFCULL,
		0x56895F0EB93F51E0ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x78FDEAB99F8BD2C6ULL,
		0x0114A36CBB54AB1DULL,
		0xFD3B01B8CED69357ULL,
		0x05CEF3476CED1355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3375D50989C9FDULL,
		0xAE99EF884F43393DULL,
		0x3C79EC82C46B700DULL,
		0x09C227ED78C73D63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBECA74E4960208B6ULL,
		0x527AB3E46C1171DFULL,
		0xC0C115360A6B2349ULL,
		0x7C0CCB59F425D5F2ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x27B816E11B7FC89EULL,
		0x5C57256E05A7508DULL,
		0x28383A0B5DDC0B95ULL,
		0x7B38275742D8C494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0376941F80AB5452ULL,
		0x45E532D8C3B334FAULL,
		0xC094ABE4EA4378F3ULL,
		0x3F55AB168EF25294ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x244182C19AD4744CULL,
		0x1671F29541F41B93ULL,
		0x67A38E26739892A2ULL,
		0x3BE27C40B3E671FFULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xC21043A65EF92678ULL,
		0xCF519E9C92E549C3ULL,
		0x7E74BC5CC4034100ULL,
		0x355CF18ACC0ECA2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x341058F2D48608F1ULL,
		0x503A60DC9C927BF3ULL,
		0x6EBABC3A02AA0D18ULL,
		0x3BDA8CB05EE1508BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFFEAB38A731D74ULL,
		0x7F173DBFF652CDD0ULL,
		0x0FBA0022C15933E8ULL,
		0x798264DA6D2D79A3ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE106529D6D08E86BULL,
		0x7273A3F283EB4773ULL,
		0xE5E6379CA56A01E3ULL,
		0x01B50651209CCA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891CF95CA5393B86ULL,
		0xA3336D114E094B75ULL,
		0x1B39684013D8A296ULL,
		0x36C80AB5AB33349FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57E95940C7CFACD2ULL,
		0xCF4036E135E1FBFEULL,
		0xCAACCF5C91915F4CULL,
		0x4AECFB9B756995CCULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x87E9804A08C6CBEEULL,
		0xAC59501EC9986927ULL,
		0x19C43C5613D53D78ULL,
		0x4655AF3CB9856CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5402F83C3F08E4ULL,
		0x0D646AF802806682ULL,
		0x15AB973C37AB92B1ULL,
		0x4972B8979B430610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B957D51CC87C2F7ULL,
		0x9EF4E526C71802A5ULL,
		0x0418A519DC29AAC7ULL,
		0x7CE2F6A51E4266EBULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x6B245F08C76E03ABULL,
		0xD39A342DE6AE928AULL,
		0x99A9929173699741ULL,
		0x21F7EB44B836ECBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE88001C934E8E07ULL,
		0xF4D753B9BF6F2673ULL,
		0x998B848CE139B6A4ULL,
		0x036A25DEC413F773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC9C5EEC341F75A4ULL,
		0xDEC2E074273F6C16ULL,
		0x001E0E04922FE09CULL,
		0x1E8DC565F422F548ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA7D7D472161C6FA8ULL,
		0x60B9E48AD2E883A9ULL,
		0x3BEA59AE132001D5ULL,
		0x6616CEF0E6021EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E3C13942983F914ULL,
		0x358A40AC89D16A45ULL,
		0x4FF33B7929A71F23ULL,
		0x2BCBA3F328D03380ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x099BC0DDEC987694ULL,
		0x2B2FA3DE49171964ULL,
		0xEBF71E34E978E2B2ULL,
		0x3A4B2AFDBD31EB6BULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x813065D4476F0094ULL,
		0x30ECA2537DAE42B7ULL,
		0x59FD7F9BE59E0527ULL,
		0x61AA26EC0853D1D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04AE73D6E23DB580ULL,
		0x465AF85E2F3F6670ULL,
		0xABAC08BA0F5F9CCEULL,
		0x3F0D9A98B98CB2DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C81F1FD65314B14ULL,
		0xEA91A9F54E6EDC47ULL,
		0xAE5176E1D63E6858ULL,
		0x229C8C534EC71EF8ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x612588518BDCB61BULL,
		0x5A574089AD45CB4DULL,
		0x5DF2BE6BFF1C90F1ULL,
		0x2495878E7B1628B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A2E16D659CDE20ULL,
		0x0FEBBCE241D47830ULL,
		0xE6945BC967B61FE7ULL,
		0x3E66AB0B330D3668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD82A6E4263FD7E8ULL,
		0x4A6B83A76B71531CULL,
		0x775E62A29766710AULL,
		0x662EDC834808F247ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x85398BB9C0886D3FULL,
		0x178A89F7DB033026ULL,
		0x4DCAEC14FC67BEF8ULL,
		0x69282CE5770501DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB132C7078628F9C8ULL,
		0xDA817B306D888BAFULL,
		0x606C640985576E8AULL,
		0x514332DB0A98BE18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD406C4B23A5F7377ULL,
		0x3D090EC76D7AA476ULL,
		0xED5E880B7710506DULL,
		0x17E4FA0A6C6C43C6ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0x9B160428890A064AULL,
		0x5A6181AE03671127ULL,
		0x751FFC990EAD3BB2ULL,
		0x3C9D5B32393BA391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6887D6D5BD8FAFULL,
		0xC2A08FF327FC67F5ULL,
		0x7BEF9CE04C20E82BULL,
		0x695B4369BEA3C588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EAD7C51B34C7688ULL,
		0x97C0F1BADB6AA931ULL,
		0xF9305FB8C28C5386ULL,
		0x534217C87A97DE08ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xA6EA14AC2CA14B96ULL,
		0x648DA9C0CD939B46ULL,
		0x9D36FBBE1F7B296CULL,
		0x0ADB8A24DDCD18EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76CA95BE3AA1B670ULL,
		0x7C632CEC50EAED80ULL,
		0x69809F2D499AF9E6ULL,
		0x18EF846AA728A066ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x301F7EEDF1FF9513ULL,
		0xE82A7CD47CA8ADC6ULL,
		0x33B65C90D5E02F85ULL,
		0x71EC05BA36A47887ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
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
		0xE446D52D9F48C5E1ULL,
		0x85E3863E03BE96EAULL,
		0x26F94D3D38325E88ULL,
		0x14F1DB261DFAA8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x745A06A31DFD6F8CULL,
		0x09AEFA2F02057D33ULL,
		0x3624B47BBF613B78ULL,
		0x455BC2A49E24E6F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FECCE8A814B5642ULL,
		0x7C348C0F01B919B7ULL,
		0xF0D498C178D12310ULL,
		0x4F9618817FD5C1C5ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}