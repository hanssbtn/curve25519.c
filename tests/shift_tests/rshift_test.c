#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE4E6769E95988C45ULL,
		0x8F132FDB521917F4ULL,
		0xBEA896B4FDA51A9DULL,
		0xEF477147BFBF6CC3ULL,
		0xC18811AEF2832390ULL,
		0xAF9EA438661FF100ULL,
		0xB5C65449512C6514ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3C4CBF6D48645FD3ULL,
		0xFAA25AD3F6946A76ULL,
		0xBD1DC51EFEFDB30EULL,
		0x062046BBCA0C8E43ULL,
		0xBE7A90E1987FC403ULL,
		0xD719512544B19452ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	int shift = 62;
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
		0xF52DC4CDE45ACAEEULL,
		0xF7ACF4F83C7C4753ULL,
		0x6A268EC404199125ULL,
		0x52F084C50CB292C4ULL,
		0xE0C0C09DB4DE8197ULL,
		0x8EDFFE149474C6D5ULL,
		0x94AB5469C506142FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF4F83C7C4753F5ULL,
		0x268EC404199125F7ULL,
		0xF084C50CB292C46AULL,
		0xC0C09DB4DE819752ULL,
		0xDFFE149474C6D5E0ULL,
		0xAB5469C506142F8EULL,
		0x0000000000000094ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x80714DC9BF6C383FULL,
		0x6EE2F359BFF25C26ULL,
		0x4B272837026C8C90ULL,
		0xBB72ECE0E63C1854ULL,
		0xBC8A28EBACC5EF41ULL,
		0xDDC9C5358AFF6491ULL,
		0x419A65B616C71660ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCD66FFC9709A01CULL,
		0xCA0DC09B23241BB8ULL,
		0xBB38398F061512C9ULL,
		0x8A3AEB317BD06EDCULL,
		0x714D62BFD9246F22ULL,
		0x996D85B1C5983772ULL,
		0x0000000000001066ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x98E5F3D691C1CBEBULL,
		0xF3613D29081027E6ULL,
		0x2D6657F27DED6910ULL,
		0x3201B72931EB2DD3ULL,
		0xD0594543EF211C6EULL,
		0x132B560ACB206159ULL,
		0xF28333E2D92EB665ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E5F3D691C1CBEBULL,
		0xF3613D29081027E6ULL,
		0x2D6657F27DED6910ULL,
		0x3201B72931EB2DD3ULL,
		0xD0594543EF211C6EULL,
		0x132B560ACB206159ULL,
		0xF28333E2D92EB665ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xE18E7EBC552EFEFFULL,
		0x77A24B93A78E90FBULL,
		0x1CBC01F75994FFE0ULL,
		0x4EE38DFD2FB0E776ULL,
		0xD609F8CCBDDD575BULL,
		0x7A03441ACB533BF1ULL,
		0xE821686E780585B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125C9D3C7487DF0CULL,
		0xE00FBACCA7FF03BDULL,
		0x1C6FE97D873BB0E5ULL,
		0x4FC665EEEABADA77ULL,
		0x1A20D65A99DF8EB0ULL,
		0x0B4373C02C2D9BD0ULL,
		0x0000000000000741ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x9214BB14D8336AABULL,
		0x38F9AD5EE3EF1412ULL,
		0x65F11F06C0AD3FE0ULL,
		0x102BEAD4AE0ECECBULL,
		0xBECFA1A709E995CFULL,
		0x3F29E737AF48BC56ULL,
		0xEEE1761444BDE106ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ABDC7DE28252429ULL,
		0x3E0D815A7FC071F3ULL,
		0xD5A95C1D9D96CBE2ULL,
		0x434E13D32B9E2057ULL,
		0xCE6F5E9178AD7D9FULL,
		0xEC28897BC20C7E53ULL,
		0x000000000001DDC2ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x4BC4EF6D5CF3123AULL,
		0xAA5F13AF9603740AULL,
		0x5DE4A96361DA461EULL,
		0xBA53C2CFDCD357FBULL,
		0x2555CB700A275F61ULL,
		0x6F5CB190AFB2E6DCULL,
		0x026E271B2A06881CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E8149789DEDAB9EULL,
		0x48C3D54BE275F2C0ULL,
		0x6AFF6BBC952C6C3BULL,
		0xEBEC374A7859FB9AULL,
		0x5CDB84AAB96E0144ULL,
		0xD1038DEB963215F6ULL,
		0x0000004DC4E36540ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xFEC2175606E25B09ULL,
		0x0092BA0A846693FBULL,
		0x3993C7D3B4558D1FULL,
		0x52D79C6F384E7750ULL,
		0xC4BA06ED185F7A3AULL,
		0x137775E0F595DA30ULL,
		0xC3EE017E45640EFEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF610BAB03712D8ULL,
		0xF80495D05423349FULL,
		0x81CC9E3E9DA2AC68ULL,
		0xD296BCE379C273BAULL,
		0x8625D03768C2FBD1ULL,
		0xF09BBBAF07ACAED1ULL,
		0x061F700BF22B2077ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x3390A4F8BAB68B40ULL,
		0x546F63B308913ED0ULL,
		0xA83EB647602AAF4FULL,
		0xFCA699E102F67992ULL,
		0xA4CB1583AD271E71ULL,
		0x3BC5F2BF2AB0589CULL,
		0x0C216F926D3613F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76611227DA067214ULL,
		0xC8EC0555E9EA8DECULL,
		0x3C205ECF325507D6ULL,
		0xB075A4E3CE3F94D3ULL,
		0x57E5560B13949962ULL,
		0xF24DA6C27F0778BEULL,
		0x000000000001842DULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xC294C4FB5EBCC3ECULL,
		0xE86962240A5CFB12ULL,
		0xCF9AC6AA7E9ABFFEULL,
		0xAD50A4F2E6CD5CA8ULL,
		0x02AF3556975816EFULL,
		0x7015BA03D1F2EC8FULL,
		0xAC30372E7C1D6055ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB112052E7D89614AULL,
		0x63553F4D5FFF7434ULL,
		0x52797366AE5467CDULL,
		0x9AAB4BAC0B77D6A8ULL,
		0xDD01E8F976478157ULL,
		0x1B973E0EB02AB80AULL,
		0x0000000000005618ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x1C31546C8D811C09ULL,
		0xCCC44738BA9045ABULL,
		0x598547A13A83FB8AULL,
		0x931D555B54E89B00ULL,
		0xC055B05E9D631549ULL,
		0x53C539F5DC5756D2ULL,
		0xD772B6BAAD56A233ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x111CE2EA4116AC70ULL,
		0x151E84EA0FEE2B33ULL,
		0x75556D53A26C0166ULL,
		0x56C17A758C55264CULL,
		0x14E7D7715D5B4B01ULL,
		0xCADAEAB55A88CD4FULL,
		0x000000000000035DULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x6FD06279F933FAF2ULL,
		0x7B576ACFF6FFE3E3ULL,
		0x8D8E9517FE07A88FULL,
		0x7A12CE8D8A45265DULL,
		0x7D1027D8D127AECAULL,
		0xC0EBD320121077E9ULL,
		0x51A479F0D1BB8260ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E36FD06279F933FULL,
		0x88F7B576ACFF6FFEULL,
		0x65D8D8E9517FE07AULL,
		0xECA7A12CE8D8A452ULL,
		0x7E97D1027D8D127AULL,
		0x260C0EBD32012107ULL,
		0x00051A479F0D1BB8ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xA46D39E02F604E01ULL,
		0x66A1F68C91EFBC40ULL,
		0xC76F355BD9741B20ULL,
		0xBC60757717B6DD5BULL,
		0x018FACEBA3EAB878ULL,
		0x5F57DFC1D7E699E0ULL,
		0xCCDBCC44E649EB3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DA3247BEF10291ULL,
		0xBCD56F65D06C819AULL,
		0x81D5DC5EDB756F1DULL,
		0x3EB3AE8FAAE1E2F1ULL,
		0x5F7F075F9A678006ULL,
		0x6F31139927ACED7DULL,
		0x0000000000000333ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x605DA267B98111D2ULL,
		0x69AF4405FF3CF156ULL,
		0x632EA0541B2FDF3CULL,
		0xF15A00C1B15D5BC6ULL,
		0xD212161E2DF7A385ULL,
		0xC30CF6A74C0893F7ULL,
		0x29DE060C5D481422ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE880BFE79E2ACC0BULL,
		0xD40A8365FBE78D35ULL,
		0x4018362BAB78CC65ULL,
		0x42C3C5BEF470BE2BULL,
		0x9ED4E981127EFA42ULL,
		0xC0C18BA902845861ULL,
		0x000000000000053BULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0xA60A5AD0F87EEF03ULL,
		0x00A7B092C14A0DC3ULL,
		0x3341E8C646EBFF53ULL,
		0x924AD2F16C1D184BULL,
		0xDD3554B12D31D87CULL,
		0x2804A20DEE124C3DULL,
		0xD17758ED5893913FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A0DC3A60A5AD0F8ULL,
		0xEBFF5300A7B092C1ULL,
		0x1D184B3341E8C646ULL,
		0x31D87C924AD2F16CULL,
		0x124C3DDD3554B12DULL,
		0x93913F2804A20DEEULL,
		0x000000D17758ED58ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x292E8ACDB3A4413EULL,
		0x0A85F6499B85B5B4ULL,
		0x0FB8D628E1B977D1ULL,
		0xFB5A51A05333DC6EULL,
		0xC1EECAF3918C4527ULL,
		0x8C7FD797A7DADB42ULL,
		0x4ED21FAD266C65ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D0A4BA2B36CE91ULL,
		0xDF442A17D9266E16ULL,
		0x71B83EE358A386E5ULL,
		0x149FED6946814CCFULL,
		0x6D0B07BB2BCE4631ULL,
		0x97B231FF5E5E9F6BULL,
		0x00013B487EB499B1ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xA059D7FBD222FCBBULL,
		0xFEB54A0093FF429AULL,
		0x8C1F56CFA0FCB999ULL,
		0x61CF98D1B74B9D50ULL,
		0xD25BB2B87DB5B207ULL,
		0x92F27B1FD4E935FCULL,
		0x6B1E920FB294CD45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0093FF429AA059D7ULL,
		0xCFA0FCB999FEB54AULL,
		0xD1B74B9D508C1F56ULL,
		0xB87DB5B20761CF98ULL,
		0x1FD4E935FCD25BB2ULL,
		0x0FB294CD4592F27BULL,
		0x00000000006B1E92ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0xF382DA8A8A8EEF86ULL,
		0xCF2D87D205FD5D42ULL,
		0xB9203C86D7241DFCULL,
		0xBD7B6D1EFC44F677ULL,
		0xF85AAEA083C00A0DULL,
		0x723577BBA41DBCE4ULL,
		0xFDE9AD1FA45DB7D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0FA40BFABA85E7ULL,
		0x40790DAE483BF99EULL,
		0xF6DA3DF889ECEF72ULL,
		0xB55D410780141B7AULL,
		0x6AEF77483B79C9F0ULL,
		0xD35A3F48BB6FAEE4ULL,
		0x00000000000001FBULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0xDD8CF52E7415FF6CULL,
		0xAF60A1FE0DBD42F6ULL,
		0xDB142A7E467E9571ULL,
		0x0A85831674228FA3ULL,
		0x41B8FE586A9A491AULL,
		0x96864E2910895784ULL,
		0x9CC38259DEA8DEEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x287F836F50BDB763ULL,
		0x0A9F919FA55C6BD8ULL,
		0x60C59D08A3E8F6C5ULL,
		0x3F961AA6924682A1ULL,
		0x938A442255E1106EULL,
		0xE09677AA37BAA5A1ULL,
		0x0000000000002730ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xDE21CBF113420274ULL,
		0x93B8F09376BF7B1BULL,
		0x943BD03E52ABCE7CULL,
		0x98FCC4BFF417C9E4ULL,
		0x91480A69ECC5D99FULL,
		0x237CED3BF5B31475ULL,
		0xCE4A8A00E4726E37ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE3C24DDAFDEC6F7ULL,
		0x0EF40F94AAF39F24ULL,
		0x3F312FFD05F27925ULL,
		0x52029A7B317667E6ULL,
		0xDF3B4EFD6CC51D64ULL,
		0x92A280391C9B8DC8ULL,
		0x0000000000000033ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x313963700915E226ULL,
		0x6C201E17F6B72EE1ULL,
		0x38C9EA520EA68936ULL,
		0xBE2C9D852A330B66ULL,
		0x46A158D091730C3FULL,
		0xC598A8F583A6FC9AULL,
		0xA9A49049F3A4FA13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785FDADCBB84C4E5ULL,
		0xA9483A9A24D9B080ULL,
		0x7614A8CC2D98E327ULL,
		0x634245CC30FEF8B2ULL,
		0xA3D60E9BF2691A85ULL,
		0x4127CE93E84F1662ULL,
		0x000000000002A692ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xAEC6C465290B0D31ULL,
		0xB9E182FD6C48F3E1ULL,
		0x14E52C62AE98D318ULL,
		0x05EBCA82CBE9ED2DULL,
		0x466846D232745F64ULL,
		0x2A56BE8A58A3CB2AULL,
		0xA32A5B6B871D908EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC48F3E1AEC6C4652ULL,
		0xE98D318B9E182FD6ULL,
		0xBE9ED2D14E52C62AULL,
		0x2745F6405EBCA82CULL,
		0x8A3CB2A466846D23ULL,
		0x71D908E2A56BE8A5ULL,
		0x0000000A32A5B6B8ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xEFA2CBCDCC3EB68FULL,
		0x50C51453F44DEEE0ULL,
		0x6205B9E085CFA785ULL,
		0xCD291E784F47EE54ULL,
		0x7FBC33C8AE5A249EULL,
		0xF3776892CB28B2A6ULL,
		0xE506F66F3198C6CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE8B2F3730FADA3ULL,
		0x54314514FD137BB8ULL,
		0x18816E782173E9E1ULL,
		0xB34A479E13D1FB95ULL,
		0x9FEF0CF22B968927ULL,
		0xBCDDDA24B2CA2CA9ULL,
		0x3941BD9BCC6631B3ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x442BC840D6D88CF1ULL,
		0x0998D76340003C27ULL,
		0xD5F26E4DA63F7B0CULL,
		0x8C223AAECB234A17ULL,
		0x883FEECCF50F47E0ULL,
		0xE16C4FE968B48955ULL,
		0xB6FD41DFD48EFF53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0001E13A215E420ULL,
		0xD31FBD8604CC6BB1ULL,
		0x6591A50BEAF93726ULL,
		0x7A87A3F046111D57ULL,
		0xB45A44AAC41FF766ULL,
		0xEA477FA9F0B627F4ULL,
		0x000000005B7EA0EFULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xCC1104EBB88BF898ULL,
		0x0A63028EFA205538ULL,
		0xCA6FC63EB09BC48CULL,
		0x33CED432AE4A35EFULL,
		0xE0A4D6FB947AF45FULL,
		0xBFBA17FB8F5C25E3ULL,
		0xABDB3E3B2A09E5D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05538CC1104EBB88ULL,
		0xBC48C0A63028EFA2ULL,
		0xA35EFCA6FC63EB09ULL,
		0xAF45F33CED432AE4ULL,
		0xC25E3E0A4D6FB947ULL,
		0x9E5D4BFBA17FB8F5ULL,
		0x00000ABDB3E3B2A0ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x51578852A41C5C66ULL,
		0x839D08DB9DF0CE33ULL,
		0x28C211E18A6E446DULL,
		0x3F3DD8C4A4ED5D9DULL,
		0xD1387A50C952329EULL,
		0xD40883E6E0E33BADULL,
		0x0D16B9D732A37B36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A11B73BE19C66A2ULL,
		0x8423C314DC88DB07ULL,
		0x7BB18949DABB3A51ULL,
		0x70F4A192A4653C7EULL,
		0x1107CDC1C6775BA2ULL,
		0x2D73AE6546F66DA8ULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x695F069838E8FA7BULL,
		0xF8AEF193A2CF4D81ULL,
		0x3175016BF502940BULL,
		0x1EA43184A82BE658ULL,
		0x33B65870F1495FC7ULL,
		0xE446BF5E7697B404ULL,
		0x42420333A4FC2B49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B3D3605A57C1A60ULL,
		0xD40A502FE2BBC64EULL,
		0xA0AF9960C5D405AFULL,
		0xC5257F1C7A90C612ULL,
		0xDA5ED010CED961C3ULL,
		0x93F0AD27911AFD79ULL,
		0x0000000109080CCEULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x87CA3E436AF5F0F3ULL,
		0xDFE6ADAD9F2DCFEAULL,
		0xE015D3DF9B881FE3ULL,
		0xFDA81B89DD41C450ULL,
		0x36958E7BBA27F7BBULL,
		0x1C5451B0A6ADE137ULL,
		0xF655894960307E48ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B67CB73FAA1F28ULL,
		0x4F7E6E207F8F7F9AULL,
		0x6E27750711438057ULL,
		0x39EEE89FDEEFF6A0ULL,
		0x46C29AB784DCDA56ULL,
		0x252580C1F9207151ULL,
		0x000000000003D956ULL,
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
		0x5B9A696BD42A9AADULL,
		0x9E746113C14B7C5BULL,
		0x555910DE1448C04DULL,
		0xCA7F052D58A28FB6ULL,
		0x473F9020E46D9AE5ULL,
		0x5E9F04766DDE9511ULL,
		0x9FF95CEFEA3E672DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278296F8B6B734D2ULL,
		0xBC2891809B3CE8C2ULL,
		0x5AB1451F6CAAB221ULL,
		0x41C8DB35CB94FE0AULL,
		0xECDBBD2A228E7F20ULL,
		0xDFD47CCE5ABD3E08ULL,
		0x00000000013FF2B9ULL,
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
		0xAFD57C14D7F63925ULL,
		0x3F853CE33AFF1504ULL,
		0xF9BBACD2BBD46DEEULL,
		0x4A905FBCEBC725D9ULL,
		0x88C9631C65B77784ULL,
		0x7BA04E60F962AECBULL,
		0xC52ECCFAB82F41EDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7F8A8257EABE0AULL,
		0x5DEA36F71FC29E71ULL,
		0x75E392ECFCDDD669ULL,
		0x32DBBBC225482FDEULL,
		0x7CB15765C464B18EULL,
		0x5C17A0F6BDD02730ULL,
		0x000000006297667DULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x3D39C9C9FB346E4FULL,
		0xA515EAFFC751FA79ULL,
		0x2B7F19B3B3934874ULL,
		0x41022D414A764C41ULL,
		0x4FFC8DEEEC6BD2ADULL,
		0xD59448325D8B2541ULL,
		0x8BE052B1FA7DABE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47E9E4F4E72727EULL,
		0xE4D21D29457ABFF1ULL,
		0x9D93104ADFC66CECULL,
		0x1AF4AB50408B5052ULL,
		0x62C95053FF237BBBULL,
		0x9F6AF9B565120C97ULL,
		0x00000022F814AC7EULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xC3779B1FDF3933B0ULL,
		0x7E32BD322BF0C0CDULL,
		0x65898686DC992C2BULL,
		0x5BC73A240EDDE524ULL,
		0x916E405E3F0CCE9CULL,
		0x9277C9628839ECB4ULL,
		0x58AFB279E5F60693ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CAF4C8AFC303370ULL,
		0x6261A1B7264B0ADFULL,
		0xF1CE8903B7794919ULL,
		0x5B90178FC333A716ULL,
		0x9DF258A20E7B2D24ULL,
		0x2BEC9E797D81A4E4ULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0xFAAF0ED348418F78ULL,
		0xBAF6E84DE21F6FBBULL,
		0x5B41876CBA9E2654ULL,
		0x1CC0A5C2C78E43AAULL,
		0x7C1090AD7BA8C322ULL,
		0xFFB74ABE09016ED2ULL,
		0x3AB1A2277572CD93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E84DE21F6FBBFAAULL,
		0x1876CBA9E2654BAFULL,
		0x0A5C2C78E43AA5B4ULL,
		0x090AD7BA8C3221CCULL,
		0x74ABE09016ED27C1ULL,
		0x1A2277572CD93FFBULL,
		0x00000000000003ABULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xE440319F352E2ECBULL,
		0xEB129B528C9B44FBULL,
		0x0EBE7602792F7BE8ULL,
		0x3003AF27F140E8C8ULL,
		0x36949C823C5F70DCULL,
		0xA2D7AFBF8883B24EULL,
		0xE14338DC8FC3FE7FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D13EF9100C67CD4ULL,
		0xBDEFA3AC4A6D4A32ULL,
		0x03A3203AF9D809E4ULL,
		0x7DC370C00EBC9FC5ULL,
		0x0EC938DA527208F1ULL,
		0x0FF9FE8B5EBEFE22ULL,
		0x000003850CE3723FULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xE58F0061034A8307ULL,
		0x5337CCABF16EBFC7ULL,
		0xFC0D62C9B0009587ULL,
		0xB148C8C8FEAEDE16ULL,
		0xC268A9AA7FA8D2B5ULL,
		0xA261BC86B03BA972ULL,
		0x76EF7CDBCC0A90AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFF1F963C01840D2ULL,
		0x2561D4CDF32AFC5BULL,
		0xB785BF0358B26C00ULL,
		0x34AD6C5232323FABULL,
		0xEA5CB09A2A6A9FEAULL,
		0xA42BE8986F21AC0EULL,
		0x00001DBBDF36F302ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x0D1A461C1BC5BDBFULL,
		0xF78D3AAFFFF5DF99ULL,
		0x41CB8F34EA5384C4ULL,
		0xAF7CDF0C9802A800ULL,
		0x673411F6AFEE6FB3ULL,
		0x1B9CD4BAA54C275EULL,
		0x8490514D71F90400ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFEBBF321A348C38ULL,
		0xD4A70989EF1A755FULL,
		0x3005500083971E69ULL,
		0x5FDCDF675EF9BE19ULL,
		0x4A984EBCCE6823EDULL,
		0xE3F208003739A975ULL,
		0x000000010920A29AULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x9BD28A7F2DAF73F2ULL,
		0x0BB5AF1F211AAF45ULL,
		0x76D968E26DA3647BULL,
		0xF4E673447F2D9946ULL,
		0x45095FDE54D04127ULL,
		0x1204446777F898C8ULL,
		0x73AAA189570CB086ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5E3E42355E8B37AULL,
		0x2D1C4DB46C8F6176ULL,
		0xCE688FE5B328CEDBULL,
		0x2BFBCA9A0824FE9CULL,
		0x888CEEFF131908A1ULL,
		0x54312AE19610C240ULL,
		0x0000000000000E75ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0xD8AFEA6C0B31627BULL,
		0x58C5767920DFA23BULL,
		0xDC326E6D2E16ABF0ULL,
		0x6762874987A7C2ECULL,
		0x99283EDE7408D85AULL,
		0xE6CFDEC8AB467F03ULL,
		0xB4F95699B158BFF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BF4477B15FD4D8ULL,
		0x5C2D57E0B18AECF2ULL,
		0x0F4F85D9B864DCDAULL,
		0xE811B0B4CEC50E93ULL,
		0x568CFE0732507DBCULL,
		0x62B17FE7CD9FBD91ULL,
		0x0000000169F2AD33ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xDEDDC88551F14BAAULL,
		0x7DD53C482C15C9D4ULL,
		0x23D4F3711EFF9C19ULL,
		0xA8927491057A77B2ULL,
		0x7C34B1B5A0270C1DULL,
		0xB74E9B01CDF41151ULL,
		0xA1F26561533218B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBAA7890582B93A9ULL,
		0x47A9E6E23DFF3832ULL,
		0x5124E9220AF4EF64ULL,
		0xF869636B404E183BULL,
		0x6E9D36039BE822A2ULL,
		0x43E4CAC2A6643169ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xC14737917416E956ULL,
		0x08B82998B0086D4DULL,
		0x1614B948CD7EF291ULL,
		0xA3D998EC0D6F2D72ULL,
		0x32E9CCEB3B1B18ACULL,
		0x4CECD71A76C48AD0ULL,
		0x47EDC2A60EF3068AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB82998B0086D4DC1ULL,
		0x14B948CD7EF29108ULL,
		0xD998EC0D6F2D7216ULL,
		0xE9CCEB3B1B18ACA3ULL,
		0xECD71A76C48AD032ULL,
		0xEDC2A60EF3068A4CULL,
		0x0000000000000047ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x8C4061161BB0B041ULL,
		0x2EE37A63882B36B7ULL,
		0x813D9799CAACB296ULL,
		0xC29CFEFB0EB41389ULL,
		0xF1377A4C00B70F77ULL,
		0x565F46DFA829FB70ULL,
		0x833106A312869662ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C4061161BB0B041ULL,
		0x2EE37A63882B36B7ULL,
		0x813D9799CAACB296ULL,
		0xC29CFEFB0EB41389ULL,
		0xF1377A4C00B70F77ULL,
		0x565F46DFA829FB70ULL,
		0x833106A312869662ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x801F4E418E5BE8B4ULL,
		0x78DCE61FEA999A89ULL,
		0x8517363D11357057ULL,
		0x1DBB2557FE02D48CULL,
		0x2947DD0395CCB0E3ULL,
		0x67181833437DF01FULL,
		0xB248499AFE54B369ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE730FF54CCD44C00ULL,
		0xB9B1E889AB82BBC6ULL,
		0xD92ABFF016A46428ULL,
		0x3EE81CAE658718EDULL,
		0xC0C19A1BEF80F94AULL,
		0x424CD7F2A59B4B38ULL,
		0x0000000000000592ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xB2C84AB877145F58ULL,
		0x1E134CED199E8C48ULL,
		0x6FF270655B1D66F7ULL,
		0x924069E5A9C0DE71ULL,
		0x3E74E47700C1CEDAULL,
		0xC02E607F242A3C1CULL,
		0x97FA382A7383DF9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3122CB212AE1DCULL,
		0x759BDC784D33B466ULL,
		0x0379C5BFC9C1956CULL,
		0x073B6A4901A796A7ULL,
		0xA8F070F9D391DC03ULL,
		0x0F7E7B00B981FC90ULL,
		0x0000025FE8E0A9CEULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0x5458C89318A6EB70ULL,
		0xDE5C63CCE963097FULL,
		0xDA2375BDD0FDC139ULL,
		0x3048D0B92BCA6938ULL,
		0x3BCBE64698C21ECAULL,
		0xBCD7638EB411347BULL,
		0xD9AA9BEB7242AEA1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2C612FEA8B1912ULL,
		0xBA1FB8273BCB8C79ULL,
		0x25794D271B446EB7ULL,
		0xD31843D946091A17ULL,
		0xD682268F67797CC8ULL,
		0x6E4855D4379AEC71ULL,
		0x000000001B35537DULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x28F84BE6BAF63719ULL,
		0x0DE61FF17C4F82C9ULL,
		0x6B3B55BA7D045C90ULL,
		0x697E79D5349C293AULL,
		0xE5C63A2A31B85E12ULL,
		0x3693DAD7F3E79115ULL,
		0x39D55BEAE1CC81F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE27C164947C25F3ULL,
		0x3E822E4806F30FF8ULL,
		0x9A4E149D359DAADDULL,
		0x18DC2F0934BF3CEAULL,
		0xF9F3C88AF2E31D15ULL,
		0x70E640F89B49ED6BULL,
		0x000000001CEAADF5ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x289A7C1A94DEDF15ULL,
		0xFBF178DB6DE01824ULL,
		0x6770EA5A6E515302ULL,
		0x675D575A7E15EB3EULL,
		0x26002F5A23F40DEAULL,
		0xAEB84C437B7AFF49ULL,
		0x0AB2CE8099A30772ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00C12144D3E0D4AULL,
		0x28A9817DF8BC6DB6ULL,
		0x0AF59F33B8752D37ULL,
		0xFA06F533AEABAD3FULL,
		0xBD7FA4930017AD11ULL,
		0xD183B9575C2621BDULL,
		0x000000055967404CULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0x52C9FAD13A504C15ULL,
		0x2BCBEAB5066E300CULL,
		0x4FD2BCBFD36BA865ULL,
		0x1D2B3D6820426431ULL,
		0x321F7135DF26EFC9ULL,
		0xC394428290639CD4ULL,
		0x4D868632B0AA3037ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00C52C9FAD13A504ULL,
		0x8652BCBEAB5066E3ULL,
		0x4314FD2BCBFD36BAULL,
		0xFC91D2B3D6820426ULL,
		0xCD4321F7135DF26EULL,
		0x037C394428290639ULL,
		0x0004D868632B0AA3ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xF54FC3D15998C1C9ULL,
		0x107AD26082D7D175ULL,
		0x5A76D975D5683EB4ULL,
		0x5B4939B68F20C5CFULL,
		0x3A59A9759D930082ULL,
		0xD857E806E17AADF3ULL,
		0x285E8E99D758C013ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41EB49820B5F45D7ULL,
		0x69DB65D755A0FAD0ULL,
		0x6D24E6DA3C83173DULL,
		0xE966A5D6764C0209ULL,
		0x615FA01B85EAB7CCULL,
		0xA17A3A675D63004FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xF4F6CD5E4A2CF8E0ULL,
		0xB1BE818387A3DF60ULL,
		0xF122A5EB12B42238ULL,
		0xE74D621BB33F07E5ULL,
		0xB1F2DA75E2669285ULL,
		0x0641F2B5D075CAA1ULL,
		0xC6CFB65462541270ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3070F47BEC1E9ED9ULL,
		0xBD625684471637D0ULL,
		0x437667E0FCBE2454ULL,
		0x4EBC4CD250BCE9ACULL,
		0x56BA0EB954363E5BULL,
		0xCA8C4A824E00C83EULL,
		0x000000000018D9F6ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x9D720DF7B5506E81ULL,
		0x9130F577B0604498ULL,
		0x68BB0B964E0B9DD8ULL,
		0x279F62E8CF9A5F2FULL,
		0xF6BDEA960A05E7ACULL,
		0xAC5F5A272797424EULL,
		0x9BCD3C8C2A143D63ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81126275C837DED5ULL,
		0x2E776244C3D5DEC1ULL,
		0x697CBDA2EC2E5938ULL,
		0x179EB09E7D8BA33EULL,
		0x5D093BDAF7AA5828ULL,
		0x50F58EB17D689C9EULL,
		0x0000026F34F230A8ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xD8F6A25AB8AEAA21ULL,
		0x14AEE84FFCEA9422ULL,
		0xCF1072137B8EBE31ULL,
		0x1604C2C659442F65ULL,
		0x14D0DDE2EA814DD5ULL,
		0x11D9417A4A5AAB54ULL,
		0x740BBF5E36423910ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9422D8F6A25AB8ULL,
		0x8EBE3114AEE84FFCULL,
		0x442F65CF1072137BULL,
		0x814DD51604C2C659ULL,
		0x5AAB5414D0DDE2EAULL,
		0x42391011D9417A4AULL,
		0x000000740BBF5E36ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xD49836F261F8D6E0ULL,
		0x822501E5C258C175ULL,
		0x71FADEB3F44B20EBULL,
		0x20CC0F43439886EAULL,
		0x990CF11B7526A522ULL,
		0x9FCE0D7560F92596ULL,
		0x48F8B4B51DB0B41EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8940797096305D75ULL,
		0x7EB7ACFD12C83AE0ULL,
		0x3303D0D0E621BA9CULL,
		0x433C46DD49A94888ULL,
		0xF3835D583E4965A6ULL,
		0x3E2D2D476C2D07A7ULL,
		0x0000000000000012ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x65F34342E16A2003ULL,
		0x87D0F4070136D35DULL,
		0x542F0B039F57FE8FULL,
		0xDBD5904B929D5F85ULL,
		0x46A5C7EDFDC533AFULL,
		0x58808C2B5589DEC2ULL,
		0xD53AE839F95F1BC7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB4D7597CD0D0B8ULL,
		0xD5FFA3E1F43D01C0ULL,
		0xA757E1550BC2C0E7ULL,
		0x714CEBF6F56412E4ULL,
		0x6277B091A971FB7FULL,
		0x57C6F1D620230AD5ULL,
		0x000000354EBA0E7EULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x32A0E45CEE811B6EULL,
		0x94B7DE3DDD4254DDULL,
		0x36B814FB02B38293ULL,
		0x7B6CD95D794F29CDULL,
		0xC3C382A518A5900CULL,
		0x4AEFA9F8B84EF663ULL,
		0xFE3C58584FC1A0A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78F775095374CA8ULL,
		0x053EC0ACE0A4E52DULL,
		0x36575E53CA734DAEULL,
		0xE0A9462964031EDBULL,
		0xEA7E2E13BD98F0F0ULL,
		0x161613F0682912BBULL,
		0x0000000000003F8FULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x44B0AC269D29FDDDULL,
		0x7AE2C8CC90DECE31ULL,
		0x49F4887B0D569B7CULL,
		0xDAD9AE051E00D29EULL,
		0x9FA15388A3410EAFULL,
		0xE506B9982E71D186ULL,
		0x59302EF84DEED302ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716466486F6718A2ULL,
		0xFA443D86AB4DBE3DULL,
		0x6CD7028F00694F24ULL,
		0xD0A9C451A08757EDULL,
		0x835CCC1738E8C34FULL,
		0x98177C26F7698172ULL,
		0x000000000000002CULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x6FA91B0376A1A22AULL,
		0xE638758AE00AA4C9ULL,
		0xBDBEBCB57851EAC6ULL,
		0x2992008F6947E8D0ULL,
		0xCB2C007529689EFEULL,
		0x87A44B334D0089D8ULL,
		0xCA72261681C60BC9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758AE00AA4C96FA9ULL,
		0xBCB57851EAC6E638ULL,
		0x008F6947E8D0BDBEULL,
		0x007529689EFE2992ULL,
		0x4B334D0089D8CB2CULL,
		0x261681C60BC987A4ULL,
		0x000000000000CA72ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x236DAE1C7E13ACF1ULL,
		0x41401FA0CB4C7FD0ULL,
		0xAEB00302E807C63EULL,
		0x81AEE6D3A98776BAULL,
		0x60EBB83C40810F1FULL,
		0x3144BC0F87B5D82DULL,
		0x5AE22670F8F1F295ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA046DB5C38FC27ULL,
		0x8C7C82803F419698ULL,
		0xED755D600605D00FULL,
		0x1E3F035DCDA7530EULL,
		0xB05AC1D770788102ULL,
		0xE52A6289781F0F6BULL,
		0x0000B5C44CE1F1E3ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xDE8F2F6B8F89F449ULL,
		0x1E589377FF13B135ULL,
		0x404F41A3841B0359ULL,
		0xBAFF69D9F2B595C0ULL,
		0xDE3E2EF0E4A3354DULL,
		0xE0733F6950BB57F6ULL,
		0xB5E61E8FB339AF69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FF13B135DE8F2FULL,
		0xA3841B03591E5893ULL,
		0xD9F2B595C0404F41ULL,
		0xF0E4A3354DBAFF69ULL,
		0x6950BB57F6DE3E2EULL,
		0x8FB339AF69E0733FULL,
		0x0000000000B5E61EULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x6380865FF62AEB43ULL,
		0x1992FF88DB9EADDDULL,
		0x3A003C4A0B0FC4EEULL,
		0x89A3CFA7D993BCCFULL,
		0x9224F80867A844CAULL,
		0x8FB19B73F23DC658ULL,
		0x5982276ADBB2D263ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FF88DB9EADDD638ULL,
		0x03C4A0B0FC4EE199ULL,
		0x3CFA7D993BCCF3A0ULL,
		0x4F80867A844CA89AULL,
		0x19B73F23DC658922ULL,
		0x2276ADBB2D2638FBULL,
		0x0000000000000598ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x63A57198C0952EC1ULL,
		0xCCA272A8BB83BED0ULL,
		0x0196719154167478ULL,
		0x35777300F38214CBULL,
		0x8B6168C01E869F8EULL,
		0xA1A7390546966246ULL,
		0x16DDFE75548ECB84ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5139545DC1DF6831ULL,
		0xCB38C8AA0B3A3C66ULL,
		0xBBB98079C10A6580ULL,
		0xB0B4600F434FC71AULL,
		0xD39C82A34B312345ULL,
		0x6EFF3AAA4765C250ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x30C8BDAA5395F270ULL,
		0xD171213C50D8BDADULL,
		0x40BA8AF966AE393FULL,
		0xD72333326B956C08ULL,
		0xDABD39659DB5E06EULL,
		0x120B339CCB8F5F6EULL,
		0xBCD25D19E868FC3FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1213C50D8BDAD30CULL,
		0xA8AF966AE393FD17ULL,
		0x333326B956C0840BULL,
		0xD39659DB5E06ED72ULL,
		0xB339CCB8F5F6EDABULL,
		0x25D19E868FC3F120ULL,
		0x0000000000000BCDULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x688571BF45954300ULL,
		0x061A197A93C3A6E0ULL,
		0x84A3B94C77EC4F26ULL,
		0x04D5D31C091CAAF4ULL,
		0xFBE5920A2FDAEA36ULL,
		0xBF70E88C1B2419A0ULL,
		0xA4AB450FEDFA69DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74DC0D10AE37E8B2ULL,
		0x89E4C0C3432F5278ULL,
		0x955E909477298EFDULL,
		0x5D46C09ABA638123ULL,
		0x83341F7CB24145FBULL,
		0x4D3BD7EE1D118364ULL,
		0x0000149568A1FDBFULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x39E7173F95CEE1F3ULL,
		0xE1D0BADF7F5058FCULL,
		0xFD97E99F94A5EA70ULL,
		0x9A9FB8C3C210A3DEULL,
		0x382A1153F61BED4BULL,
		0x9FAE05880B15D27BULL,
		0x0FD8189E4D01DFE2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3A175BEFEA0B1F8ULL,
		0xFB2FD33F294BD4E1ULL,
		0x353F7187842147BDULL,
		0x705422A7EC37DA97ULL,
		0x3F5C0B10162BA4F6ULL,
		0x1FB0313C9A03BFC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x010E88A0E3019277ULL,
		0xFC3CF2626360C640ULL,
		0xD2BAB8960FAB4978ULL,
		0x5420DAD10B709BD1ULL,
		0xC2639AFB958B2D20ULL,
		0x85294C57BE562139ULL,
		0x735281C0674F2496ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C9898D831900043ULL,
		0xAE2583EAD25E3F0FULL,
		0x36B442DC26F474AEULL,
		0xE6BEE562CB481508ULL,
		0x5315EF95884E7098ULL,
		0xA07019D3C925A14AULL,
		0x0000000000001CD4ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xC5C78219B5FD15B4ULL,
		0x4D44A54096D7B582ULL,
		0x948E555FF10F14B4ULL,
		0x8E8D82BC20A2745BULL,
		0xC98D3D0FF0E15649ULL,
		0x702F9507CB0E99E4ULL,
		0x494EF2F4C8C3D495ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD60B171E0866D7F4ULL,
		0x52D1351295025B5EULL,
		0xD16E5239557FC43CULL,
		0x59263A360AF08289ULL,
		0x67932634F43FC385ULL,
		0x5255C0BE541F2C3AULL,
		0x0001253BCBD3230FULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xED4CDF98928CCDDDULL,
		0xDB4B38B0F85EEE37ULL,
		0xDB2886E00B1556E5ULL,
		0x9F92B4CC343C52F1ULL,
		0x6FF2797F879A756FULL,
		0x5B86E119FC447C6EULL,
		0x38F14C1081B93BDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B0F85EEE37ED4CULL,
		0x86E00B1556E5DB4BULL,
		0xB4CC343C52F1DB28ULL,
		0x797F879A756F9F92ULL,
		0xE119FC447C6E6FF2ULL,
		0x4C1081B93BDB5B86ULL,
		0x00000000000038F1ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x163E45FCA2FBD10EULL,
		0x567A47E3852507B7ULL,
		0x35EBDE9179D7A74FULL,
		0x4D150941C5555A0DULL,
		0x5C41EC95C9845591ULL,
		0xAAB60E6366A4EDCFULL,
		0xF6B08CF5E0457FA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC58F917F28BEF44ULL,
		0x3D59E91F8E14941EULL,
		0x34D7AF7A45E75E9DULL,
		0x4534542507155568ULL,
		0x3D7107B257261156ULL,
		0x92AAD8398D9A93B7ULL,
		0x03DAC233D78115FEULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x9B6552DCA2A08D48ULL,
		0x87C8CA662C11C800ULL,
		0x41F220FCC941716BULL,
		0x61F28D2C0FE4FA2EULL,
		0x65C907A3BB2CD55AULL,
		0xCCCE0969B3AF1C34ULL,
		0x124282531C9D2C45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4004DB2A96E51504ULL,
		0x8B5C3E465331608EULL,
		0xD1720F9107E64A0BULL,
		0xAAD30F9469607F27ULL,
		0xE1A32E483D1DD966ULL,
		0x622E66704B4D9D78ULL,
		0x000092141298E4E9ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xE45952409834D308ULL,
		0xB4806C4E7394A4ACULL,
		0x4D6CEF353EAE95DEULL,
		0x24543A123821721FULL,
		0xDE819E9E854CB26AULL,
		0xB3C14E2B8D9D7EF5ULL,
		0xB8EB341B512FF685ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x294959C8B2A48130ULL,
		0x5D2BBD6900D89CE7ULL,
		0x42E43E9AD9DE6A7DULL,
		0x9964D448A8742470ULL,
		0x3AFDEBBD033D3D0AULL,
		0x5FED0B67829C571BULL,
		0x00000171D66836A2ULL,
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
		0xFD7018F45DFA59D4ULL,
		0x775D8F4A68CEE874ULL,
		0x3E1AA3F92A6C579AULL,
		0xCBCA3DF72C5BCFC9ULL,
		0x3FB5531069F0EB51ULL,
		0x6078ABEE265485D4ULL,
		0xD5A6634FE2371228ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53467743A7EB80CULL,
		0xFC95362BCD3BAEC7ULL,
		0xFB962DE7E49F0D51ULL,
		0x8834F875A8E5E51EULL,
		0xF7132A42EA1FDAA9ULL,
		0xA7F11B8914303C55ULL,
		0x00000000006AD331ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x073E221382A6FC8FULL,
		0x812CF2FB89A1E1DCULL,
		0x092C389DC5EDF226ULL,
		0xCB17D1F39317C050ULL,
		0x0E1509EBA5D063B9ULL,
		0x58DA10A8C6CBEE43ULL,
		0xA6B94275C3BF3C92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBEE268787701CF8ULL,
		0xE27717B7C89A04B3ULL,
		0x47CE4C5F014024B0ULL,
		0x27AE97418EE72C5FULL,
		0x42A31B2FB90C3854ULL,
		0x09D70EFCF2496368ULL,
		0x0000000000029AE5ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xBC90C921D1423E50ULL,
		0x27F3D56A12116354ULL,
		0x1E70402C8A1313B1ULL,
		0x50E5250646255288ULL,
		0x4E7B2FD70DCBFD00ULL,
		0x8C62BEA3A7639E51ULL,
		0xEEBE39F06F45857DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA5E486490E8A11ULL,
		0x9D893F9EAB50908BULL,
		0x9440F38201645098ULL,
		0xE80287292832312AULL,
		0xF28A73D97EB86E5FULL,
		0x2BEC6315F51D3B1CULL,
		0x000775F1CF837A2CULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xAA5EBDE89F3C3F9FULL,
		0x15D23513A78DAFC0ULL,
		0x8EF94295564B6B2FULL,
		0xA2ABA0CB747C9765ULL,
		0xB24E491DB26F734BULL,
		0x6A009617090F1B96ULL,
		0x830775118D38A983ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3513A78DAFC0AA5EULL,
		0x4295564B6B2F15D2ULL,
		0xA0CB747C97658EF9ULL,
		0x491DB26F734BA2ABULL,
		0x9617090F1B96B24EULL,
		0x75118D38A9836A00ULL,
		0x0000000000008307ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x7BD452FC7BDE46FEULL,
		0x7F8F525CE40F2EAFULL,
		0x917EAD95F4748DD7ULL,
		0x9454697F83729FC4ULL,
		0xB2C441833662737EULL,
		0x38D1DB928E9CBB10ULL,
		0xFE2336727C5C7632ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F2EAF7BD452FC7ULL,
		0x4748DD77F8F525CEULL,
		0x3729FC4917EAD95FULL,
		0x662737E9454697F8ULL,
		0xE9CBB10B2C441833ULL,
		0xC5C763238D1DB928ULL,
		0x0000000FE2336727ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xF39A7763F26962CBULL,
		0x4CEAE3CDDBAA2FEFULL,
		0xE5075A7FD5C1EF9EULL,
		0x0C7F885CF0575EA6ULL,
		0xFEC71E86D59A87BBULL,
		0x21EF265C0C6D929BULL,
		0x37C98B1F269F3DABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5C79BB7545FDFE7ULL,
		0x0EB4FFAB83DF3C99ULL,
		0xFF10B9E0AEBD4DCAULL,
		0x8E3D0DAB350F7618ULL,
		0xDE4CB818DB2537FDULL,
		0x93163E4D3E7B5643ULL,
		0x000000000000006FULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x2DA295C0BBDCCCD4ULL,
		0x7AB53DE4DF2C28A3ULL,
		0x7019E41AED2DDB0AULL,
		0xB42595FA279AB931ULL,
		0x3E8F9249EB8DE019ULL,
		0x6BBF30122E8F9D0EULL,
		0xD32619B377DB158DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D14AE05DEE666AULL,
		0x3D5A9EF26F961451ULL,
		0xB80CF20D7696ED85ULL,
		0xDA12CAFD13CD5C98ULL,
		0x1F47C924F5C6F00CULL,
		0xB5DF98091747CE87ULL,
		0x69930CD9BBED8AC6ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x1417B6C3E41FD63CULL,
		0x4181719AA5217FD2ULL,
		0x065591E50F02BD51ULL,
		0xC96F3E7B3D0A538FULL,
		0x0F0EE5D026E8BDBDULL,
		0x539308C311D08CE7ULL,
		0x131C2019DAA57D16ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19AA5217FD21417BULL,
		0x1E50F02BD5141817ULL,
		0xE7B3D0A538F06559ULL,
		0x5D026E8BDBDC96F3ULL,
		0x8C311D08CE70F0EEULL,
		0x019DAA57D1653930ULL,
		0x00000000000131C2ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xD8B6A757A41DF69BULL,
		0xCD2FD4FD54172C8FULL,
		0x327F6FA369575370ULL,
		0x0E092A49D012BE91ULL,
		0xA8A71BE727A2538FULL,
		0x930BD226D0D67552ULL,
		0xD962A89D0FA80346ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9647EC5B53ABD20ULL,
		0xBA9B86697EA7EAA0ULL,
		0x95F48993FB7D1B4AULL,
		0x129C787049524E80ULL,
		0xB3AA954538DF393DULL,
		0x401A34985E913686ULL,
		0x000006CB1544E87DULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x7E95A6CE8C3ABDF3ULL,
		0x9C2E3543C871D753ULL,
		0x6E901FF1C4FE188FULL,
		0x3C311648E8951C49ULL,
		0xF3AF37D0B06935BDULL,
		0x1FF48D982299F19EULL,
		0x3C9FE500409F3AD8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF21C75D4DFA569B3ULL,
		0x713F8623E70B8D50ULL,
		0x3A2547125BA407FCULL,
		0x2C1A4D6F4F0C4592ULL,
		0x08A67C67BCEBCDF4ULL,
		0x1027CEB607FD2366ULL,
		0x000000000F27F940ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x1B3520CC18448FA8ULL,
		0x1479B26568FB492BULL,
		0x327484834252C091ULL,
		0x9C44C1D2CE2D7249ULL,
		0xBFE472BACAE3DAD8ULL,
		0xAED5A234546CDD3DULL,
		0x5D934681E7154819ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24AC6CD483306112ULL,
		0x024451E6C995A3EDULL,
		0xC924C9D2120D094BULL,
		0x6B627113074B38B5ULL,
		0x74F6FF91CAEB2B8FULL,
		0x2066BB5688D151B3ULL,
		0x0001764D1A079C55ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xF0C61CAC5930A9FAULL,
		0x9443B1D3BF34F3C3ULL,
		0xBE6F5C3B66A30F9FULL,
		0xE344376A910348A4ULL,
		0x1B971B2C504D2DC3ULL,
		0x9ED9D206C98FBAAAULL,
		0x085CF5F2C8A50A55ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC74EFCD3CF0FC3ULL,
		0xBD70ED9A8C3E7E51ULL,
		0x10DDAA440D2292F9ULL,
		0x5C6CB14134B70F8DULL,
		0x67481B263EEAA86EULL,
		0x73D7CB229429567BULL,
		0x0000000000000021ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xBC079505442967D9ULL,
		0x6FEB9E10E8DB75ABULL,
		0xBAF5E7BB70766293ULL,
		0x5EC29C03D6058E64ULL,
		0xA2EF69845E70ED77ULL,
		0x1D1D4270A8255532ULL,
		0xFEC5F31C71302F1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36DD6AEF01E54151ULL,
		0x1D98A4DBFAE7843AULL,
		0x8163992EBD79EEDCULL,
		0x9C3B5DD7B0A700F5ULL,
		0x09554CA8BBDA6117ULL,
		0x4C0BC78747509C2AULL,
		0x0000003FB17CC71CULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xB74C26113ACDB461ULL,
		0x4C3F4D9A44AB1116ULL,
		0x7A9074A3ABCD093AULL,
		0x6E0488DED83CD659ULL,
		0x140E9F2AA4C9D024ULL,
		0xD71501F378090CD6ULL,
		0x19D2DD33D36E6D67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61FA6CD2255888B5ULL,
		0xD483A51D5E6849D2ULL,
		0x702446F6C1E6B2CBULL,
		0xA074F955264E8123ULL,
		0xB8A80F9BC04866B0ULL,
		0xCE96E99E9B736B3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x2E2AF7974D0474AAULL,
		0x982B0E3025575B66ULL,
		0xFDEB3FB303544DFDULL,
		0x588ACFBC76BC56CBULL,
		0xF90D0A56E2294AF0ULL,
		0xCAED29F4A64A4C0AULL,
		0x0824B504E15D908CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBADB317157BCBA68ULL,
		0xA26FECC15871812AULL,
		0xE2B65FEF59FD981AULL,
		0x4A5782C4567DE3B5ULL,
		0x526057C86852B711ULL,
		0xEC846657694FA532ULL,
		0x0000004125A8270AULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x46A29D0B512E5126ULL,
		0xA96E090C77092CAFULL,
		0xF55B743CB9511230ULL,
		0x6C5173FB2AB41D14ULL,
		0x43148657E77DA102ULL,
		0xEB3C2996BC564191ULL,
		0xD88426F7D2578A11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595E8D453A16A25CULL,
		0x246152DC1218EE12ULL,
		0x3A29EAB6E87972A2ULL,
		0x4204D8A2E7F65568ULL,
		0x832286290CAFCEFBULL,
		0x1423D678532D78ACULL,
		0x0001B1084DEFA4AFULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x16FCB6F6271B4A7EULL,
		0xA62C76740D793702ULL,
		0x14D91F4DEDE73255ULL,
		0x7ED65B62ABD88666ULL,
		0xD131C0B65F7004F4ULL,
		0x9C3C33707C98AB8FULL,
		0x036B54CBB03A188BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A06BC9B810B7E5BULL,
		0xA6F6F3992AD3163BULL,
		0xB155EC43330A6C8FULL,
		0x5B2FB8027A3F6B2DULL,
		0xB83E4C55C7E898E0ULL,
		0x65D81D0C45CE1E19ULL,
		0x000000000001B5AAULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x18CF401B1D513CD7ULL,
		0x35D795D6C3F5715DULL,
		0x84BD3C5574F8D3B2ULL,
		0x4829310FC71EC1A7ULL,
		0x061B13A3BF2E6489ULL,
		0xC45CF78649D5370AULL,
		0x1F4F9B14834C83B2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75E575B0FD5C5746ULL,
		0x2F4F155D3E34EC8DULL,
		0x0A4C43F1C7B069E1ULL,
		0x86C4E8EFCB992252ULL,
		0x173DE192754DC281ULL,
		0xD3E6C520D320ECB1ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0xD1423C5711116FE4ULL,
		0x6DAD0BD068850D6CULL,
		0x8F758F25148ED84EULL,
		0x58F0EAAD2547CFE1ULL,
		0x6868C51F2206D122ULL,
		0x751944F832977C02ULL,
		0x69207589BDB22BDEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D10A1AD9A28478AULL,
		0xA291DB09CDB5A17AULL,
		0xA4A8F9FC31EEB1E4ULL,
		0xE440DA244B1E1D55ULL,
		0x0652EF804D0D18A3ULL,
		0x37B6457BCEA3289FULL,
		0x000000000D240EB1ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x4DC6C257150C241AULL,
		0x4F291542CF2D5E1FULL,
		0x43C9C5A68EC53017ULL,
		0x27239915182F5B1DULL,
		0x39679908DD8E3519ULL,
		0x824BD58C38287883ULL,
		0xBFAF3733A9EFC7C5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B3CB5787D371B09ULL,
		0x9A3B14C05D3CA455ULL,
		0x5460BD6C750F2716ULL,
		0x237638D4649C8E64ULL,
		0x30E0A1E20CE59E64ULL,
		0xCEA7BF1F16092F56ULL,
		0x0000000002FEBCDCULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x0E45424A4E2A2FFFULL,
		0xEF169C6F3EE7E38CULL,
		0xD29014A5112F56C8ULL,
		0xB93B650D89962DB6ULL,
		0xA9E5B2C213E1C926ULL,
		0xC304164C2AD70CC5ULL,
		0x3CD2FCC1029461DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7181C8A84949C54ULL,
		0xAD91DE2D38DE7DCFULL,
		0x5B6DA520294A225EULL,
		0x924D7276CA1B132CULL,
		0x198B53CB658427C3ULL,
		0xC3BF86082C9855AEULL,
		0x000079A5F9820528ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x8FB0408DFD34CBC8ULL,
		0x1D6352D5A9BE05D2ULL,
		0x447B1F4163B2FBC6ULL,
		0x81B28123C5248E8FULL,
		0x6C8E7F8A07A8C811ULL,
		0x5F9565EF5532E758ULL,
		0x5C25AAF2324A8D35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05D28FB0408DFD34ULL,
		0xFBC61D6352D5A9BEULL,
		0x8E8F447B1F4163B2ULL,
		0xC81181B28123C524ULL,
		0xE7586C8E7F8A07A8ULL,
		0x8D355F9565EF5532ULL,
		0x00005C25AAF2324AULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x1F18EBF593C8B911ULL,
		0x2864DDAEF262EF71ULL,
		0xC1CD87DCC6956DAEULL,
		0x7EEAE8890471E483ULL,
		0xA7440EF6F3F23F23ULL,
		0xD065E39EF388DD40ULL,
		0x800BA98CD71A2962ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DEE23E31D7EB279ULL,
		0xADB5C50C9BB5DE4CULL,
		0x3C907839B0FB98D2ULL,
		0x47E46FDD5D11208EULL,
		0x1BA814E881DEDE7EULL,
		0x452C5A0CBC73DE71ULL,
		0x0000100175319AE3ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x053DF482CBC51CAEULL,
		0x8D8BA272633E63CCULL,
		0xDAF47A69F2A6EF2FULL,
		0x1F75917F23455C37ULL,
		0x2C6910D98864C108ULL,
		0x16EDC6435A568ECCULL,
		0x1BF23FFF8B0951B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362E89C98CF98F30ULL,
		0x6BD1E9A7CA9BBCBEULL,
		0x7DD645FC8D1570DFULL,
		0xB1A4436621930420ULL,
		0x5BB7190D695A3B30ULL,
		0x6FC8FFFE2C2546D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x66C131496231D140ULL,
		0x4FA479FF7F11EC78ULL,
		0x4B1A37363D936F68ULL,
		0x0A502EF5B1C821EBULL,
		0x5D3217BB90E44AE7ULL,
		0x69644DBB1A32BE25ULL,
		0x8ECFFB6DCADB543EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CD826292C463A28ULL,
		0x09F48F3FEFE23D8FULL,
		0x696346E6C7B26DEDULL,
		0xE14A05DEB639043DULL,
		0xABA642F7721C895CULL,
		0xCD2C89B7634657C4ULL,
		0x11D9FF6DB95B6A87ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0xFF19DE43DCEBCB65ULL,
		0xDF67A3301A6DF2C6ULL,
		0xC6D0AE2EAE95F685ULL,
		0x906F89F527020EA0ULL,
		0x1CEA2C6111A8D8FFULL,
		0xB3D6D8249B9A8BB7ULL,
		0xA606382775A7C968ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB1BFC67790F73AFULL,
		0xDA177D9E8CC069B7ULL,
		0x3A831B42B8BABA57ULL,
		0x63FE41BE27D49C08ULL,
		0x2EDC73A8B18446A3ULL,
		0x25A2CF5B60926E6AULL,
		0x00029818E09DD69FULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x09F5F1A676E4584CULL,
		0x9B5AFB902F4DD602ULL,
		0x81A97AE3D404D1C8ULL,
		0xD7D89D21B3BB92E9ULL,
		0x10A754CD3656B1CDULL,
		0xC3DF2B56107EA0AFULL,
		0x346D33B249B736E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7DC817A6EB0104FULL,
		0x4BD71EA0268E44DAULL,
		0xC4E90D9DDC974C0DULL,
		0x3AA669B2B58E6EBEULL,
		0xF95AB083F5057885ULL,
		0x699D924DB9B71E1EULL,
		0x00000000000001A3ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xFEC95C19ADC40E2AULL,
		0x5FC2B0B6A87B1E8DULL,
		0x0678A969340F5E57ULL,
		0x98A7A110067E4EA6ULL,
		0x2A9DF6C93C47CAF4ULL,
		0x125A1B402F1E4319ULL,
		0x1C16C6474653A65CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543D8F46FF64AE0CULL,
		0x9A07AF2BAFE1585BULL,
		0x033F2753033C54B4ULL,
		0x9E23E57A4C53D088ULL,
		0x178F218C954EFB64ULL,
		0xA329D32E092D0DA0ULL,
		0x000000000E0B6323ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x0B33246113DDDA26ULL,
		0x2C24CF83405DB40AULL,
		0x43FB89037D869E8AULL,
		0x1795B6E384D119A4ULL,
		0x53CB1579BA00E2E7ULL,
		0x9B5B3AC6B13FF195ULL,
		0xCCCD4F4300120DBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8499F0680BB68141ULL,
		0x7F71206FB0D3D145ULL,
		0xF2B6DC709A233488ULL,
		0x7962AF37401C5CE2ULL,
		0x6B6758D627FE32AAULL,
		0x99A9E8600241B793ULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x2C077D8932FDE4D9ULL,
		0xF57E1658140BBC5BULL,
		0x50309B8A02AFCE11ULL,
		0xC02A0C9F51F2EE52ULL,
		0x7251BD2DC41E0375ULL,
		0xAAE7F556BCAED49AULL,
		0x0E107A61A11AB648ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C077D8932FDE4D9ULL,
		0xF57E1658140BBC5BULL,
		0x50309B8A02AFCE11ULL,
		0xC02A0C9F51F2EE52ULL,
		0x7251BD2DC41E0375ULL,
		0xAAE7F556BCAED49AULL,
		0x0E107A61A11AB648ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xBFC3D1B9E3093135ULL,
		0x8D1851D9E43201B8ULL,
		0x089801584ACB1C37ULL,
		0x12EF037612C46EE4ULL,
		0x6B1FFE0D9D60761CULL,
		0x5462A1B3E6B97DFEULL,
		0xE83C01F788BFEACCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8BFC3D1B9E30931ULL,
		0x378D1851D9E43201ULL,
		0xE4089801584ACB1CULL,
		0x1C12EF037612C46EULL,
		0xFE6B1FFE0D9D6076ULL,
		0xCC5462A1B3E6B97DULL,
		0x00E83C01F788BFEAULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xE0355283094C0666ULL,
		0xAC7C094A080D1082ULL,
		0x737CEAB470F0C82CULL,
		0xB9A69660199DF9DAULL,
		0x3D774EB99E23C6A9ULL,
		0xB954A30C12E43EECULL,
		0x1FDA0D45A065D055ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E04A5040688417ULL,
		0x9BE755A387864165ULL,
		0xCD34B300CCEFCED3ULL,
		0xEBBA75CCF11E354DULL,
		0xCAA518609721F761ULL,
		0xFED06A2D032E82ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x6E947B143CE6F0CCULL,
		0x29229C83C59AD8F8ULL,
		0x336E25D635B2D82AULL,
		0xEF560E944FCFCD2DULL,
		0xF01ACC11ABC96349ULL,
		0xE51C16F62D90E3E1ULL,
		0xB27B4D85221F9FF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x539078B35B1F0DD2ULL,
		0xC4BAC6B65B054524ULL,
		0xC1D289F9F9A5A66DULL,
		0x598235792C693DEAULL,
		0x82DEC5B21C7C3E03ULL,
		0x69B0A443F3FEFCA3ULL,
		0x000000000000164FULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0x38E7201869470F5AULL,
		0x0A5CEBC1FF033D95ULL,
		0xCDAC2E819F867B92ULL,
		0x266A9263C9B5D5A7ULL,
		0x96FF2AE5F40C3F4FULL,
		0x5AA96FD40E7FA096ULL,
		0xF38C13B4D34F057BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D783FE067B2A71ULL,
		0x585D033F0CF72414ULL,
		0xD524C7936BAB4F9BULL,
		0xFE55CBE8187E9E4CULL,
		0x52DFA81CFF412D2DULL,
		0x182769A69E0AF6B5ULL,
		0x00000000000001E7ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x1606C6EB376BB4E6ULL,
		0xD21D4D049E2E84EBULL,
		0x7B41C051349E38D3ULL,
		0x7BD96D341E268020ULL,
		0x28DEFCCE28BB8D16ULL,
		0x1312DD2F21857B61ULL,
		0xADE42B3217DEE129ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75341278BA13AC58ULL,
		0x070144D278E34F48ULL,
		0x65B4D0789A0081EDULL,
		0x7BF338A2EE3459EFULL,
		0x4B74BC8615ED84A3ULL,
		0x90ACC85F7B84A44CULL,
		0x00000000000002B7ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x3ACA3E841D915B33ULL,
		0x8A237239E8B93D7CULL,
		0x935105CD1449B548ULL,
		0xA1366647391D699FULL,
		0xE7353147A216251DULL,
		0x457596F8714184CDULL,
		0x91813EBA73FC38DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x288DC8E7A2E4F5F0ULL,
		0x4D4417345126D522ULL,
		0x84D9991CE475A67EULL,
		0x9CD4C51E88589476ULL,
		0x15D65BE1C5061337ULL,
		0x4604FAE9CFF0E379ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x50DFF408B7A68D4CULL,
		0x41087170BDAA93F1ULL,
		0x3E6C2869AD5882D6ULL,
		0x1C48FAF9D5A6D8DCULL,
		0x7F0A02CF80FD8A9AULL,
		0x9DBD1FED0987AE9EULL,
		0x1F8C9488FE6CD00EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BDAA93F150DFF40ULL,
		0x9AD5882D64108717ULL,
		0x9D5A6D8DC3E6C286ULL,
		0xF80FD8A9A1C48FAFULL,
		0xD0987AE9E7F0A02CULL,
		0x8FE6CD00E9DBD1FEULL,
		0x0000000001F8C948ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xBF9E945C1F090450ULL,
		0xE64A4CC7B99378CEULL,
		0x1232BDA4D814F10DULL,
		0x0E69803FF60000D7ULL,
		0xF3D2EFFAC0181189ULL,
		0x60486E5FCF92CC88ULL,
		0x53D0636D7FDE7B75ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FCF4A2E0F848228ULL,
		0xF3252663DCC9BC67ULL,
		0x89195ED26C0A7886ULL,
		0x8734C01FFB00006BULL,
		0x79E977FD600C08C4ULL,
		0xB024372FE7C96644ULL,
		0x29E831B6BFEF3DBAULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x623ACD8D5C036204ULL,
		0x8A89DF515316DDCDULL,
		0x83D8C2493128EFCEULL,
		0x23E9D63657C70628ULL,
		0xF5527BD37F834A5CULL,
		0xB4DFA984D6DA10F8ULL,
		0xADD1B8FA7DD510FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A62DBB9AC4759B1ULL,
		0x26251DF9D1513BEAULL,
		0xCAF8E0C5107B1849ULL,
		0x6FF0694B847D3AC6ULL,
		0x9ADB421F1EAA4F7AULL,
		0x4FBAA21FD69BF530ULL,
		0x0000000015BA371FULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x8094B76513BE2F70ULL,
		0x0100BD6F11419D27ULL,
		0x0F96348CEF5C5C6EULL,
		0x3B517F453227AF43ULL,
		0x4337C1E5F5BBAF43ULL,
		0x28FA69FC6671C1DAULL,
		0x0F12A34150125C2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78094B76513BE2F7ULL,
		0xE0100BD6F11419D2ULL,
		0x30F96348CEF5C5C6ULL,
		0x33B517F453227AF4ULL,
		0xA4337C1E5F5BBAF4ULL,
		0xC28FA69FC6671C1DULL,
		0x00F12A34150125C2ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xC651607B782A5A67ULL,
		0x40874F8280C4D829ULL,
		0x0E0FD7F236CB7DD6ULL,
		0xBFD4ADF8A1E23E3CULL,
		0x280A761103A20E60ULL,
		0x2FA295604F008DF5ULL,
		0x829F866DAE5F5A36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538CA2C0F6F054B4ULL,
		0xAC810E9F050189B0ULL,
		0x781C1FAFE46D96FBULL,
		0xC17FA95BF143C47CULL,
		0xEA5014EC2207441CULL,
		0x6C5F452AC09E011BULL,
		0x01053F0CDB5CBEB4ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x0E4E12F0C0A91411ULL,
		0x1F5DBEBE0EBDE009ULL,
		0x7C0B13F53BD09CF1ULL,
		0x35DD52C91F8416EFULL,
		0x59BCBF971D832A6CULL,
		0xBF7C7739D9BF776AULL,
		0xFEF030B3858C6B93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1D7BC0121C9C25ULL,
		0xEA77A139E23EBB7DULL,
		0x923F082DDEF81627ULL,
		0x2E3B0654D86BBAA5ULL,
		0x73B37EEED4B3797FULL,
		0x670B18D7277EF8EEULL,
		0x0000000001FDE061ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x1A2B242F4C20D55EULL,
		0xB9F12815B05FF215ULL,
		0x5AD47D80DE7FFAFEULL,
		0x17EC44DF44BDEF3CULL,
		0x02BB93B55767CFB8ULL,
		0x751B56A39C95E682ULL,
		0x082180880864534EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E2502B60BFE42AULL,
		0xB5A8FB01BCFFF5FDULL,
		0x2FD889BE897BDE78ULL,
		0x0577276AAECF9F70ULL,
		0xEA36AD47392BCD04ULL,
		0x1043011010C8A69CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xB1A79B56B6F82A10ULL,
		0x7750281FA748D7F4ULL,
		0xC02989B560A82B2BULL,
		0xF8CFACC2733829BCULL,
		0x374992B6D3B9C5D8ULL,
		0x08886BF35D9E3C29ULL,
		0x751943BEB69BAC25ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4B1A79B56B6F82AULL,
		0x2B7750281FA748D7ULL,
		0xBCC02989B560A82BULL,
		0xD8F8CFACC2733829ULL,
		0x29374992B6D3B9C5ULL,
		0x2508886BF35D9E3CULL,
		0x00751943BEB69BACULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x682A649CACE24E6EULL,
		0xE07FAE90A9FAD390ULL,
		0x22780FA91A1BEBC6ULL,
		0xF6A95AE120B0B535ULL,
		0xE19D816FB3AF07EEULL,
		0x5E1FBB68F7B594D7ULL,
		0xDD360105A2A6CE20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE41A0A99272B3893ULL,
		0xF1B81FEBA42A7EB4ULL,
		0x4D489E03EA4686FAULL,
		0xFBBDAA56B8482C2DULL,
		0x35F867605BECEBC1ULL,
		0x881787EEDA3DED65ULL,
		0x00374D804168A9B3ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x3651FB0E26D9BDF3ULL,
		0x54745F2780995AEAULL,
		0x626C360D8CF38E8FULL,
		0x85DB99F9C57EE7B2ULL,
		0x6ADF0EA3A91676ADULL,
		0xE64BF8311235EFBAULL,
		0xAE74562646DE9D1DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE4F0132B5D46CA3ULL,
		0x6C1B19E71D1EA8E8ULL,
		0x33F38AFDCF64C4D8ULL,
		0x1D47522CED5B0BB7ULL,
		0xF062246BDF74D5BEULL,
		0xAC4C8DBD3A3BCC97ULL,
		0x0000000000015CE8ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x4C722076B9F0CED4ULL,
		0xC236B8AE7510B090ULL,
		0xD09437CF8F52DCAEULL,
		0x456240D2CDAE0DF8ULL,
		0x15B7575C5E108AC9ULL,
		0x4A9E4F1EED56B62DULL,
		0x9D97C34F29C12615ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8482639103B5CF86ULL,
		0xE57611B5C573A885ULL,
		0x6FC684A1BE7C7A96ULL,
		0x564A2B1206966D70ULL,
		0xB168ADBABAE2F084ULL,
		0x30AA54F278F76AB5ULL,
		0x0004ECBE1A794E09ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xD9406433EE901CFEULL,
		0x849608D5AC7AA358ULL,
		0xA47861E3C8E651D1ULL,
		0xF37B62777A43EC62ULL,
		0x219B321C6770F816ULL,
		0x36F54D0ADF5CE6F7ULL,
		0xFA597D5585E2F3C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C11AB58F546B1B2ULL,
		0xF0C3C791CCA3A309ULL,
		0xF6C4EEF487D8C548ULL,
		0x366438CEE1F02DE6ULL,
		0xEA9A15BEB9CDEE43ULL,
		0xB2FAAB0BC5E7866DULL,
		0x00000000000001F4ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x5C60AD983C6A9A54ULL,
		0xDCBF008659C154B4ULL,
		0x547E27C79A5B870DULL,
		0x02A1EA210B949691ULL,
		0xF718230067591E79ULL,
		0x85AF5D412C583671ULL,
		0x48413539E7A0CD42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB382A968B8C15B3ULL,
		0xF34B70E1BB97E010ULL,
		0x217292D22A8FC4F8ULL,
		0x0CEB23CF20543D44ULL,
		0x258B06CE3EE30460ULL,
		0x3CF419A850B5EBA8ULL,
		0x00000000090826A7ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0xE51A32E0E351E1ABULL,
		0xC0EA4088C12C2E39ULL,
		0xE4582B36C5528734ULL,
		0x9EAAB8357362B60CULL,
		0x0EF9B181468E1FBAULL,
		0x8E16C9128E6C29B4ULL,
		0x44A00ED90414C3DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088C12C2E39E51A3ULL,
		0xB36C5528734C0EA4ULL,
		0x8357362B60CE4582ULL,
		0x181468E1FBA9EAABULL,
		0x9128E6C29B40EF9BULL,
		0xED90414C3DE8E16CULL,
		0x0000000000044A00ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xAA217E70C2FB657CULL,
		0xCD5D64A4B4A0131BULL,
		0x97C8140A9122EFBAULL,
		0xF6E1210B7170C0C3ULL,
		0xF36FEA1864D8F51AULL,
		0xF1A5C51F37353ED2ULL,
		0x611D5BC4A12BB00AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC949694026375442ULL,
		0x28152245DF759ABAULL,
		0x4216E2E181872F90ULL,
		0xD430C9B1EA35EDC2ULL,
		0x8A3E6E6A7DA5E6DFULL,
		0xB78942576015E34BULL,
		0x000000000000C23AULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x903191527D0B18BEULL,
		0x7B6CCE55C9AEA3F6ULL,
		0x3325FC45B42920EEULL,
		0x748ACA9EE050B2C8ULL,
		0xF7B317B2B9CA5648ULL,
		0x13927257CE9A1B66ULL,
		0xCAC11231029695CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47ED206322A4FA1ULL,
		0x241DCF6D99CAB935ULL,
		0x16590664BF88B685ULL,
		0x4AC90E915953DC0AULL,
		0x436CDEF662F65739ULL,
		0xD2B942724E4AF9D3ULL,
		0x0000195822462052ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xD144727002257478ULL,
		0x87348B3FAA56B6B1ULL,
		0x99FBB73BF0CAE00CULL,
		0xED515754659E3062ULL,
		0xC1E3DA0B5DC39F71ULL,
		0xF8F9FF8B1AE9376DULL,
		0x93A9E7C500A5D952ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA459FD52B5B58E8AULL,
		0xDDB9DF8657006439ULL,
		0x8ABAA32CF18314CFULL,
		0x1ED05AEE1CFB8F6AULL,
		0xCFFC58D749BB6E0FULL,
		0x4F3E28052ECA97C7ULL,
		0x000000000000049DULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xCC668165E5810685ULL,
		0xC4E331980EA85627ULL,
		0xE790D01664D830A1ULL,
		0x684DE804FA170B66ULL,
		0xD93FC7EDC989FBDFULL,
		0x50E4FB67C3DC0952ULL,
		0x2E7EE76F0E626E8BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B13E63340B2F2C0ULL,
		0x1850E27198CC0754ULL,
		0x85B373C8680B326CULL,
		0xFDEFB426F4027D0BULL,
		0x04A96C9FE3F6E4C4ULL,
		0x3745A8727DB3E1EEULL,
		0x0000173F73B78731ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x86E2DEF2ACAE6BC5ULL,
		0xB960CE3049C0B362ULL,
		0x3076B92DB9787806ULL,
		0x1E5A7719107F31DAULL,
		0x7ED42B5DF096782EULL,
		0x2456C56791676797ULL,
		0x75AEA3DD6F6F66A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38166C50DC5BDE55ULL,
		0x2F0F00D72C19C609ULL,
		0x0FE63B460ED725B7ULL,
		0x12CF05C3CB4EE322ULL,
		0x2CECF2EFDA856BBEULL,
		0xEDECD4248AD8ACF2ULL,
		0x0000000EB5D47BADULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0xBFBB9ADD607ED757ULL,
		0x3C91A748FE1DA352ULL,
		0xD84ABD8021406D0FULL,
		0x3E51942340DE8A91ULL,
		0xF946820F4D1E3CB8ULL,
		0x1FD7027CD565E6A4ULL,
		0x40941C1B694BADA8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3A47F0ED1A95FDULL,
		0x55EC010A036879E4ULL,
		0x8CA11A06F4548EC2ULL,
		0x34107A68F1E5C1F2ULL,
		0xB813E6AB2F3527CAULL,
		0xA0E0DB4A5D6D40FEULL,
		0x0000000000000204ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xBDA304993E8A3E38ULL,
		0x89025A00B7536DC4ULL,
		0xD861D6EA24A28A45ULL,
		0xFDDC5C9AB5A45BB3ULL,
		0x97BC728338C37F93ULL,
		0x370706489606B144ULL,
		0x602ABC08EEB4D582ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB897B4609327D147ULL,
		0x48B1204B4016EA6DULL,
		0x767B0C3ADD449451ULL,
		0xF27FBB8B9356B48BULL,
		0x2892F78E5067186FULL,
		0xB046E0E0C912C0D6ULL,
		0x000C0557811DD69AULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x03FE9B8F69EBB38FULL,
		0x5DF7845F26EED8C9ULL,
		0xA422F8236202F39CULL,
		0x687AE38F27657A88ULL,
		0x8895A83E99FEE76BULL,
		0x41A97B2F17B37528ULL,
		0x609D48485BE68673ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE117C9BBB63240FULL,
		0x8BE08D880BCE7177ULL,
		0xEB8E3C9D95EA2290ULL,
		0x56A0FA67FB9DADA1ULL,
		0xA5ECBC5ECDD4A222ULL,
		0x7521216F9A19CD06ULL,
		0x0000000000000182ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xC5D75001E51D9E91ULL,
		0x42A3D5AF1C3EAC01ULL,
		0x8FB478D38C747E01ULL,
		0xCD31A81EF9525F65ULL,
		0x333E375D1A913196ULL,
		0x8AB0617571CED426ULL,
		0x9C3AA4DE1401289CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007175D400794767ULL,
		0x8050A8F56BC70FABULL,
		0xD963ED1E34E31D1FULL,
		0x65B34C6A07BE5497ULL,
		0x098CCF8DD746A44CULL,
		0x2722AC185D5C73B5ULL,
		0x00270EA93785004AULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x4D2C0356C588A7B5ULL,
		0x4A9B5076CCDA58BCULL,
		0xD58AF55A03C604A4ULL,
		0x7606D2FC05182257ULL,
		0x430D04704CA88E16ULL,
		0xAD9100BDA52D96BEULL,
		0xB043016B350B5D17ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDA58BC4D2C0356CULL,
		0x3C604A44A9B5076CULL,
		0x5182257D58AF55A0ULL,
		0xCA88E167606D2FC0ULL,
		0x52D96BE430D04704ULL,
		0x50B5D17AD9100BDAULL,
		0x0000000B043016B3ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xFF9D676049B4DE67ULL,
		0x533B4DAA054B6AEBULL,
		0xFBC7C734E2B26850ULL,
		0x26FFA4C7E52FEC4CULL,
		0xEDB2B5B2ACE395DAULL,
		0xF991831CB2884DA3ULL,
		0x5ECDF0E80C66F71BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFF9D676049B4DEULL,
		0x50533B4DAA054B6AULL,
		0x4CFBC7C734E2B268ULL,
		0xDA26FFA4C7E52FECULL,
		0xA3EDB2B5B2ACE395ULL,
		0x1BF991831CB2884DULL,
		0x005ECDF0E80C66F7ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xF0330A8C878FFCA8ULL,
		0x745A618476E5F772ULL,
		0xCF2C2EB936898DA5ULL,
		0x9ED380B2B67AD689ULL,
		0xF7FD27D5DFE7B156ULL,
		0xE7315681ECBC4B7BULL,
		0x15251F5DE32305E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18476E5F772F0330ULL,
		0xEB936898DA5745A6ULL,
		0x0B2B67AD689CF2C2ULL,
		0x7D5DFE7B1569ED38ULL,
		0x681ECBC4B7BF7FD2ULL,
		0xF5DE32305E7E7315ULL,
		0x0000000000015251ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x7B6AF1B4E1825676ULL,
		0xC3306E6EC597C969ULL,
		0xE64FB906EA496FF6ULL,
		0xB31F39C789DC2380ULL,
		0x0FF1BC2094B98ADEULL,
		0x79B77F94D8F68720ULL,
		0x27A3CDC78ECB7762ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697B6AF1B4E18256ULL,
		0xF6C3306E6EC597C9ULL,
		0x80E64FB906EA496FULL,
		0xDEB31F39C789DC23ULL,
		0x200FF1BC2094B98AULL,
		0x6279B77F94D8F687ULL,
		0x0027A3CDC78ECB77ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xCE508D9FFBAD3297ULL,
		0x32F47507266DC1E4ULL,
		0xB0D49CAE93442429ULL,
		0xFA2BC1BBAC48323EULL,
		0x9D18A3DD60103498ULL,
		0x3F30A61AE9035290ULL,
		0x21562A096DB152D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE508D9FFBAD329ULL,
		0x932F47507266DC1EULL,
		0xEB0D49CAE9344242ULL,
		0x8FA2BC1BBAC48323ULL,
		0x09D18A3DD6010349ULL,
		0x93F30A61AE903529ULL,
		0x021562A096DB152DULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xF6E8015C70965162ULL,
		0xB401F997E796C72BULL,
		0x6484B6E7C4C73248ULL,
		0xBEE51C77B9905399ULL,
		0xF1A3759CD89CE6B1ULL,
		0x654A5749C9D5EA53ULL,
		0x2808947522597FE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1CAFDBA00571C25ULL,
		0xCC922D007E65F9E5ULL,
		0x14E659212DB9F131ULL,
		0x39AC6FB9471DEE64ULL,
		0x7A94FC68DD673627ULL,
		0x5FF9D95295D27275ULL,
		0x00000A02251D4896ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x396116B977029C7AULL,
		0x8D2184C1C8C54188ULL,
		0xC75CE66DD939EDE7ULL,
		0x6AE0F9C51A2346F2ULL,
		0x672C145151474A45ULL,
		0x9069602732F5CB4EULL,
		0xD50409081B98C850ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A831072C22D72EULL,
		0x273DBCF1A4309839ULL,
		0x4468DE58EB9CCDBBULL,
		0x28E948AD5C1F38A3ULL,
		0x5EB969CCE5828A2AULL,
		0x73190A120D2C04E6ULL,
		0x0000001AA0812103ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x359D80455DA023A0ULL,
		0x2F93E04E753D179FULL,
		0x36EAC36D0E5EF7CFULL,
		0x8D435F6FC1837B12ULL,
		0xAE5062E1E96B6A6EULL,
		0xCF306C096886D767ULL,
		0xF4E97FD6D4EE9B16ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD179F359D80455DAULL,
		0xEF7CF2F93E04E753ULL,
		0x37B1236EAC36D0E5ULL,
		0xB6A6E8D435F6FC18ULL,
		0x6D767AE5062E1E96ULL,
		0xE9B16CF306C09688ULL,
		0x00000F4E97FD6D4EULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x22DE60B943D8CD5CULL,
		0x09779B50C4E511B4ULL,
		0x388A047A60752692ULL,
		0xC363E80794291B33ULL,
		0x71C8DB400D932D40ULL,
		0x0CE8C3D4F0F8EA8CULL,
		0x3EA971C1A92ED3DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x189CA236845BCC17ULL,
		0x4C0EA4D2412EF36AULL,
		0xF28523666711408FULL,
		0x01B265A8186C7D00ULL,
		0x9E1F1D518E391B68ULL,
		0x3525DA7BE19D187AULL,
		0x0000000007D52E38ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0xA5B0E467E72BDD82ULL,
		0x93B4DC62FDFF2FFDULL,
		0xF02926A71B808967ULL,
		0x603C6D68E6CFFB41ULL,
		0x8784138A13A35D07ULL,
		0x291C7BB4E6B06B3AULL,
		0x2C32F363749ABCD3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FED2D87233F395EULL,
		0x4B3C9DA6E317EFF9ULL,
		0xDA0F81493538DC04ULL,
		0xE83B01E36B47367FULL,
		0x59D43C209C509D1AULL,
		0xE69948E3DDA73583ULL,
		0x000161979B1BA4D5ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x79807E146894772FULL,
		0x9A66B293D6E4F8D5ULL,
		0x190D9F9B75544CD8ULL,
		0x60B2726D0A4F5331ULL,
		0xE81E2A56D9B8B0EEULL,
		0x0DFE49BAAE0D98DCULL,
		0x8FD74A9CEAA54611ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1AAF300FC28D12ULL,
		0x899B134CD6527ADCULL,
		0xEA662321B3F36EAAULL,
		0x161DCC164E4DA149ULL,
		0xB31B9D03C54ADB37ULL,
		0xA8C221BFC93755C1ULL,
		0x000011FAE9539D54ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xF68505E9BFA6487CULL,
		0x8B07D522D8EB7CBAULL,
		0xF3345DA454B18E4FULL,
		0xFC5D13974D26157BULL,
		0x1FD420D13373260DULL,
		0x161F00B8BF55231DULL,
		0x621757798F5AEAEFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F975ED0A0BD37F4ULL,
		0x31C9F160FAA45B1DULL,
		0xC2AF7E668BB48A96ULL,
		0x64C1BF8BA272E9A4ULL,
		0xA463A3FA841A266EULL,
		0x5D5DE2C3E01717EAULL,
		0x00000C42EAEF31EBULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x59908E86B8A7CE16ULL,
		0x7BAC2382CA1F3436ULL,
		0xD492756D64559823ULL,
		0xE726E32D0D01A3EBULL,
		0x2A8F014822BBEE8EULL,
		0x8C80F3807C84DA9CULL,
		0x7750E1E6FB240459ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650F9A1B2CC84743ULL,
		0xB22ACC11BDD611C1ULL,
		0x8680D1F5EA493AB6ULL,
		0x115DF74773937196ULL,
		0x3E426D4E154780A4ULL,
		0x7D92022CC64079C0ULL,
		0x000000003BA870F3ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x7BD3CAE830DCFD9BULL,
		0xA2F1B5EB03FE6253ULL,
		0xB21F111AD8C93D4EULL,
		0xD5FF196C53075F96ULL,
		0xD20739BD2E7DCF96ULL,
		0x14CAB991761BCD49ULL,
		0xE41924B7493EF487ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36BD607FCC4A6F7AULL,
		0xE2235B1927A9D45EULL,
		0xE32D8A60EBF2D643ULL,
		0xE737A5CFB9F2DABFULL,
		0x57322EC379A93A40ULL,
		0x2496E927DE90E299ULL,
		0x0000000000001C83ULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0xCDD00EC5472D207FULL,
		0xA5ED990DEE15C475ULL,
		0x52B560AF1D8A7199ULL,
		0xA4FDBDA915E56F7CULL,
		0xBC128EE82B7C0B87ULL,
		0x4511C6072B3E1B1AULL,
		0xD4128DE95B930144ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6437B85711D73740ULL,
		0x82BC7629C66697B6ULL,
		0xF6A45795BDF14AD5ULL,
		0x3BA0ADF02E1E93F6ULL,
		0x181CACF86C6AF04AULL,
		0x37A56E4C05111447ULL,
		0x000000000003504AULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xB7FDFCDBEA8A4BC8ULL,
		0xE024E5C98621B1A0ULL,
		0x174F15ED3EB8805CULL,
		0x143149099093350CULL,
		0x538574FD1F111EDBULL,
		0xAC68740C274DACF2ULL,
		0x117B7247E9A57BB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4363416FFBF9B7D5ULL,
		0x7100B9C049CB930CULL,
		0x266A182E9E2BDA7DULL,
		0x223DB62862921321ULL,
		0x9B59E4A70AE9FA3EULL,
		0x4AF76758D0E8184EULL,
		0x00000022F6E48FD3ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0xBF60543941BEE66EULL,
		0x99995C545A18FF53ULL,
		0x0D6094B243366D41ULL,
		0x8B16543C8E9D7CC5ULL,
		0x44002166751A88D2ULL,
		0x5DBD3EBD6731100DULL,
		0x426139DBA24BB87DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863FD4EFD8150E50ULL,
		0xCD9B506666571516ULL,
		0xA75F314358252C90ULL,
		0x46A234A2C5950F23ULL,
		0xCC4403510008599DULL,
		0x92EE1F576F4FAF59ULL,
		0x00000010984E76E8ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x324AB1F5847F3F30ULL,
		0x7EC538C25F365FDBULL,
		0x114397859A8B5C8BULL,
		0xA990A8C8921A48EEULL,
		0x653ABCE5B50AA478ULL,
		0x5A07586C2B25A684ULL,
		0xAD102D626049B23FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF629C612F9B2FED9ULL,
		0x8A1CBC2CD45AE45BULL,
		0x4C85464490D24770ULL,
		0x29D5E72DA85523C5ULL,
		0xD03AC361592D3423ULL,
		0x68816B13024D91FAULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0xE3EB2179A520FFB8ULL,
		0xD540A023CC3B1701ULL,
		0x29B5BA8599A5CEDEULL,
		0x668C9199FE564CCBULL,
		0x13015807147CBADFULL,
		0xBFB46B07D4505C2DULL,
		0xD76A95361DB0CBFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC078FAC85E69483FULL,
		0xB7B5502808F30EC5ULL,
		0x32CA6D6EA1666973ULL,
		0xB7D9A324667F9593ULL,
		0x0B44C05601C51F2EULL,
		0xFEAFED1AC1F51417ULL,
		0x0035DAA54D876C32ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x2B8E1E69F243212BULL,
		0x11142FEB9757EF8AULL,
		0xB34A47100C96B447ULL,
		0xA30184C34B515309ULL,
		0xD21582A7CD6DE0EDULL,
		0x3509FD45F107A643ULL,
		0x97B018A732B07C0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9757EF8A2B8E1E6ULL,
		0x00C96B44711142FEULL,
		0x34B515309B34A471ULL,
		0x7CD6DE0EDA30184CULL,
		0x5F107A643D21582AULL,
		0x732B07C0F3509FD4ULL,
		0x00000000097B018AULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x05EB69FCDF81E295ULL,
		0xEE0DA52D8B29D53CULL,
		0x0349742F2BCC1E11ULL,
		0xD67D89E83DC58CADULL,
		0xE665B95FBC45EACBULL,
		0xA989454C52548E8EULL,
		0x0F7969CB7F713747ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D53C05EB69FCDF8ULL,
		0xC1E11EE0DA52D8B2ULL,
		0x58CAD0349742F2BCULL,
		0x5EACBD67D89E83DCULL,
		0x48E8EE665B95FBC4ULL,
		0x13747A989454C525ULL,
		0x000000F7969CB7F7ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x07F465C060343959ULL,
		0xD28393B1CA1F8A31ULL,
		0x4831CAB283811C33ULL,
		0x7B3CDD1F16B6D82DULL,
		0x9667CD71FA32AB4EULL,
		0x7C17DD20ABECC9A6ULL,
		0xD14DCD33A75F62CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14620FE8CB80C068ULL,
		0x3867A5072763943FULL,
		0xB05A906395650702ULL,
		0x569CF679BA3E2D6DULL,
		0x934D2CCF9AE3F465ULL,
		0xC59EF82FBA4157D9ULL,
		0x0001A29B9A674EBEULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xD6DF984464F20030ULL,
		0xA41A9C3771DC265DULL,
		0xF30E523796DA5199ULL,
		0x0F02CFB97BF36BACULL,
		0xA34FCE89944135C0ULL,
		0x54B4B2A77A811322ULL,
		0x55A8E70EFFA21FBBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EEB6FCC22327900ULL,
		0xCCD20D4E1BB8EE13ULL,
		0xD67987291BCB6D28ULL,
		0xE0078167DCBDF9B5ULL,
		0x9151A7E744CA209AULL,
		0xDDAA5A5953BD4089ULL,
		0x002AD473877FD10FULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0xFB978B3E5E844EEEULL,
		0x29E263D1DFD3A28DULL,
		0xCEDD22F88ED4EA63ULL,
		0x00D9D93FB48A61C8ULL,
		0xE97BC7CBA4D4A46EULL,
		0x078563975FFE9F97ULL,
		0x2E25C1FC184313E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF131E8EFE9D146FDULL,
		0x6E917C476A753194ULL,
		0x6CEC9FDA4530E467ULL,
		0xBDE3E5D26A523700ULL,
		0xC2B1CBAFFF4FCBF4ULL,
		0x12E0FE0C2189F003ULL,
		0x0000000000000017ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x421BDECF8FCDF8EBULL,
		0xE06FDC9B4021D9DEULL,
		0x08F61A611265EEA7ULL,
		0xAFE663FC9A05D90CULL,
		0x04696835C36B17F9ULL,
		0x2E8041F4CD4C233AULL,
		0xE4B12B0624E304D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43B3BC8437BD9F1FULL,
		0xCBDD4FC0DFB93680ULL,
		0x0BB21811EC34C224ULL,
		0xD62FF35FCCC7F934ULL,
		0x98467408D2D06B86ULL,
		0xC609A65D0083E99AULL,
		0x000001C962560C49ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0xBF2B355B77B61A43ULL,
		0x6ADF36018402CC5FULL,
		0x591DEAE00E5818C4ULL,
		0x9EF565BC0D23FE9BULL,
		0x9BBD3BD60BD062FDULL,
		0x7DA7BEA85BC1466CULL,
		0x2E5A09C6F4C43B39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F9B00C201662FDULL,
		0xC8EF570072C0C623ULL,
		0xF7AB2DE0691FF4DAULL,
		0xDDE9DEB05E8317ECULL,
		0xED3DF542DE0A3364ULL,
		0x72D04E37A621D9CBULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0xBC16DC6D370CC1D5ULL,
		0x0FE7321BCB347776ULL,
		0x0F5B6F8DE9515E75ULL,
		0x7BF836B028478245ULL,
		0xCC4D66CCF53A9EACULL,
		0x655A6282DC773429ULL,
		0x282C099D9BDBF7A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF05B71B4DC33075ULL,
		0x43F9CC86F2CD1DDDULL,
		0x43D6DBE37A54579DULL,
		0x1EFE0DAC0A11E091ULL,
		0x731359B33D4EA7ABULL,
		0x195698A0B71DCD0AULL,
		0x0A0B026766F6FDEAULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x1D2096673CE281A4ULL,
		0xEBE430818238E0DBULL,
		0xEBC82CA562E1FB54ULL,
		0xDBBF51C003A9D98BULL,
		0xAB96756BA058D37BULL,
		0xF4C62D611D69BD30ULL,
		0xB51E22CE96BE9DB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B63A412CCE79C50ULL,
		0x6A9D7C861030471CULL,
		0x317D790594AC5C3FULL,
		0x6F7B77EA3800753BULL,
		0xA61572CEAD740B1AULL,
		0xB61E98C5AC23AD37ULL,
		0x0016A3C459D2D7D3ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x5075852B48EBF615ULL,
		0xEE3180CC4B7B56C7ULL,
		0x9C9299446E656669ULL,
		0xB21E1BB084178D9FULL,
		0x81B0968A80EB79E6ULL,
		0x12CAC1A28E2B3BABULL,
		0x39075B9B03D17AAEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80CC4B7B56C75075ULL,
		0x99446E656669EE31ULL,
		0x1BB084178D9F9C92ULL,
		0x968A80EB79E6B21EULL,
		0xC1A28E2B3BAB81B0ULL,
		0x5B9B03D17AAE12CAULL,
		0x0000000000003907ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x17A813698AE2B4BDULL,
		0x7AF1E4E7F72E5EAFULL,
		0x3C980D81BD7CBF34ULL,
		0x041D3C57B8714768ULL,
		0x68E821B331ADEB57ULL,
		0x466B5011B9E6B07EULL,
		0x30AA93C432E65C61ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7939FDCB97ABC5EULL,
		0x603606F5F2FCD1EBULL,
		0x74F15EE1C51DA0F2ULL,
		0xA086CCC6B7AD5C10ULL,
		0xAD4046E79AC1F9A3ULL,
		0xAA4F10CB99718519ULL,
		0x00000000000000C2ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x3C5D436F7549CF33ULL,
		0x8A461DEACD3D3CA4ULL,
		0xF659BCE6A23CCF9CULL,
		0x64B46484CCBBCA74ULL,
		0x93C47D6E3492DFA2ULL,
		0x69F18A4C9BA34CB6ULL,
		0xFDD3A037FA1FDBAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91877AB34F4F290FULL,
		0x966F39A88F33E722ULL,
		0x2D1921332EF29D3DULL,
		0xF11F5B8D24B7E899ULL,
		0x7C629326E8D32DA4ULL,
		0x74E80DFE87F6EA9AULL,
		0x000000000000003FULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0xE7CC9CF6DFF73562ULL,
		0x41F1A7726FC02B35ULL,
		0x7329D30158A9311DULL,
		0x055C5D79131BB0B7ULL,
		0x9C46914189D17A04ULL,
		0xF86A1B71A1241573ULL,
		0x76134AA9C488335FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7726FC02B35E7CULL,
		0x9D30158A9311D41FULL,
		0xC5D79131BB0B7732ULL,
		0x6914189D17A04055ULL,
		0xA1B71A12415739C4ULL,
		0x34AA9C488335FF86ULL,
		0x0000000000000761ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xB47775C55CA0D260ULL,
		0x926899BFE880EA4BULL,
		0xA836DE5366B08B6BULL,
		0xA6573C5559AA0161ULL,
		0xD804A4685FD199B4ULL,
		0xECBA3CA3D8F8EE02ULL,
		0x5C448C20112A8C06ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37FD101D49768EEEULL,
		0xCA6CD6116D724D13ULL,
		0x8AAB35402C3506DBULL,
		0x8D0BFA333694CAE7ULL,
		0x947B1F1DC05B0094ULL,
		0x8402255180DD9747ULL,
		0x00000000000B8891ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x374C06CCCA05092EULL,
		0x61A1456FB003BAD3ULL,
		0x1C5058222A4AA281ULL,
		0x1B7102E68F4A631FULL,
		0x81556A30E947AE07ULL,
		0xA0D9BAA82FDC8149ULL,
		0x65DCD60675B052FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3374C06CCCA05092ULL,
		0x161A1456FB003BADULL,
		0xF1C5058222A4AA28ULL,
		0x71B7102E68F4A631ULL,
		0x981556A30E947AE0ULL,
		0xCA0D9BAA82FDC814ULL,
		0x065DCD60675B052FULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x8CF1A5ED94BFDCBAULL,
		0x74259DF418215585ULL,
		0xEE1207E8A5EE1B3DULL,
		0x4B29D9A397BA7F42ULL,
		0xF85546F67C6CE4F7ULL,
		0xD0EB80F96A009566ULL,
		0xB60F6195E87B171EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3042AB0B19E34BDBULL,
		0x4BDC367AE84B3BE8ULL,
		0x2F74FE85DC240FD1ULL,
		0xF8D9C9EE9653B347ULL,
		0xD4012ACDF0AA8DECULL,
		0xD0F62E3DA1D701F2ULL,
		0x000000016C1EC32BULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x75CAE06FE3FDCF9DULL,
		0xAB5DA5E1F275A230ULL,
		0x67D5A76C5C40FABDULL,
		0xCC8DB16AFA573BDCULL,
		0x5CBB94B2364E43F6ULL,
		0xD705A8C6C608FCCFULL,
		0x8CAE2A0E80CFE770ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C9D688C1D72B81BULL,
		0x17103EAF6AD76978ULL,
		0xBE95CEF719F569DBULL,
		0x8D9390FDB3236C5AULL,
		0xB1823F33D72EE52CULL,
		0xA033F9DC35C16A31ULL,
		0x00000000232B8A83ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xB0C9810A274BA3BAULL,
		0x799CD2776E296B21ULL,
		0xBE7F2D3D20696801ULL,
		0xD5EEA09933CF4901ULL,
		0xA82C9BB980E112E7ULL,
		0x84D975582021ACB4ULL,
		0x725039CF6A6971CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE693BB714B590D86ULL,
		0xF969E9034B400BCCULL,
		0x7504C99E7A480DF3ULL,
		0x64DDCC0708973EAFULL,
		0xCBAAC1010D65A541ULL,
		0x81CE7B534B8E5426ULL,
		0x0000000000000392ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xA8ECAB7D730D2CCFULL,
		0xC5E7A978EB153BFFULL,
		0xBCF6D1CA14B0E6FDULL,
		0x1AF993B0E7F8E501ULL,
		0xD78EAE103BBC53C0ULL,
		0x2A0303F827B0A9ACULL,
		0x2FC17056031F88FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC758A9DFFD47655BULL,
		0x50A58737EE2F3D4BULL,
		0x873FC7280DE7B68EULL,
		0x81DDE29E00D7CC9DULL,
		0xC13D854D66BC7570ULL,
		0xB018FC47F150181FULL,
		0x00000000017E0B82ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x0BB211156CBF1ACAULL,
		0x0A3F242FDA78CEE0ULL,
		0xB817852565B745ACULL,
		0x48710025D8EE8C10ULL,
		0x497BADF26EEE83EBULL,
		0x3E1A44B9F590420BULL,
		0xCFE0396F9466ECB7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB802EC84455B2FC6ULL,
		0x6B028FC90BF69E33ULL,
		0x042E05E149596DD1ULL,
		0xFAD21C4009763BA3ULL,
		0x82D25EEB7C9BBBA0ULL,
		0x2DCF86912E7D6410ULL,
		0x0033F80E5BE519BBULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0xF08E071678B75BF4ULL,
		0x294B2FF7C9217DC5ULL,
		0x5C23AF08F0DC8CFDULL,
		0x9C3FA3620567A9C7ULL,
		0xB66C4F61F1383801ULL,
		0x14C5B5AA4FB3B3D2ULL,
		0xDD7E1C222620071EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF7C9217DC5F08E0ULL,
		0xF08F0DC8CFD294B2ULL,
		0x3620567A9C75C23AULL,
		0xF61F13838019C3FAULL,
		0x5AA4FB3B3D2B66C4ULL,
		0xC222620071E14C5BULL,
		0x00000000000DD7E1ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xA9257371865C5128ULL,
		0xC90B7DD0EC8F5370ULL,
		0xC6AD08C83C0E4478ULL,
		0x93D17B1F7519C698ULL,
		0xD40796DA0379815AULL,
		0x8EBF8C91CBED8E25ULL,
		0x415202C1BB7F403FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1524AE6E30CB8A2ULL,
		0xF19216FBA1D91EA6ULL,
		0x318D5A1190781C88ULL,
		0xB527A2F63EEA338DULL,
		0x4BA80F2DB406F302ULL,
		0x7F1D7F192397DB1CULL,
		0x0082A4058376FE80ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x3E98F3D289E6DC38ULL,
		0xDEC892DEEFB7FE9DULL,
		0x60A38CDDF067AD86ULL,
		0x4066AF01296B6304ULL,
		0x8F1E2E6E01D7E86FULL,
		0xA3F52EE90743C4C7ULL,
		0x67B8B44152BD45BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DEEFB7FE9D3E98FULL,
		0xCDDF067AD86DEC89ULL,
		0xF01296B630460A38ULL,
		0xE6E01D7E86F4066AULL,
		0xEE90743C4C78F1E2ULL,
		0x44152BD45BCA3F52ULL,
		0x0000000000067B8BULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x0DA784CDF6EE1D92ULL,
		0x0B7F24A86CA1E7C4ULL,
		0xF5A431554BB103FBULL,
		0x8B2E6C685F794BBEULL,
		0x13F8C5F3F2B3A12CULL,
		0x84DCD5036BA79DD5ULL,
		0x44AC2E6978BDE5D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2543650F3E206D3CULL,
		0x8AAA5D881FD85BF9ULL,
		0x6342FBCA5DF7AD21ULL,
		0x2F9F959D09645973ULL,
		0xA81B5D3CEEA89FC6ULL,
		0x734BC5EF2ECC26E6ULL,
		0x0000000000022561ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xA2EC11F1769F2B29ULL,
		0xBB6885E73BBAF72DULL,
		0xD7555B2A37B432BBULL,
		0x97206428A9EC1C4BULL,
		0x4EF9A702B5B6BCB3ULL,
		0xA667D6C2A729562AULL,
		0xC475BABABA68618DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA2EC11F1769F2B2ULL,
		0xBBB6885E73BBAF72ULL,
		0xBD7555B2A37B432BULL,
		0x397206428A9EC1C4ULL,
		0xA4EF9A702B5B6BCBULL,
		0xDA667D6C2A729562ULL,
		0x0C475BABABA68618ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xE8987DDB3974AD56ULL,
		0xFA1AB8DAE2FA9CA6ULL,
		0xD332EF1901825876ULL,
		0x736BD97E3B57A075ULL,
		0x9C9B2D18E73FD0C7ULL,
		0x9C9C4B8A24DB4F67ULL,
		0x3E5F403176AD81C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43571B5C5F5394DDULL,
		0x665DE320304B0EDFULL,
		0x6D7B2FC76AF40EBAULL,
		0x9365A31CE7FA18EEULL,
		0x938971449B69ECF3ULL,
		0xCBE8062ED5B03893ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xD09AD1264D7520B2ULL,
		0x178FCEAAA37AF235ULL,
		0xA72C3094BF6527A5ULL,
		0x42C92580DF8BA9A3ULL,
		0x428E58809D4CEE40ULL,
		0x15897BC11C9A7B49ULL,
		0x7A50F9DF2E1022A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5E46BA135A24C9ULL,
		0xECA4F4A2F1F9D554ULL,
		0xF1753474E5861297ULL,
		0xA99DC8085924B01BULL,
		0x934F692851CB1013ULL,
		0xC2045402B12F7823ULL,
		0x0000000F4A1F3BE5ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x0434B44A44389FC0ULL,
		0x2090B7FADBA6F87BULL,
		0x03954E98BBF573C3ULL,
		0xDBAA9DAE977AF87FULL,
		0x463893CFA9C18021ULL,
		0x78EB3E7DB49BE931ULL,
		0x1593EF824F15D9CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x485BFD6DD37C3D82ULL,
		0xCAA74C5DFAB9E190ULL,
		0xD54ED74BBD7C3F81ULL,
		0x1C49E7D4E0C010EDULL,
		0x759F3EDA4DF498A3ULL,
		0xC9F7C1278AECE53CULL,
		0x000000000000000AULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0xA87178F4663D65F9ULL,
		0x28BFD0DDCA13BD9DULL,
		0x7ED5480CEFBA2355ULL,
		0xB9CB2C0D2B6FA832ULL,
		0x794BFCF916483905ULL,
		0xF471FEDD2DC85286ULL,
		0x98147F4E1913942DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECED438BC7A331EBULL,
		0x1AA945FE86EE509DULL,
		0x4193F6AA40677DD1ULL,
		0xC82DCE5960695B7DULL,
		0x9433CA5FE7C8B241ULL,
		0xA16FA38FF6E96E42ULL,
		0x0004C0A3FA70C89CULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x9261B592AA9B4FE2ULL,
		0x13FB61E446CF00E5ULL,
		0x0A6045BB2A6D5E3EULL,
		0x18C749868FC5E3FEULL,
		0xAC28B0037138ADEDULL,
		0xB48F4B0AB30B89F5ULL,
		0x0FB66CACFFB1FCACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED87911B3C039649ULL,
		0x8116ECA9B578F84FULL,
		0x1D261A3F178FF829ULL,
		0xA2C00DC4E2B7B463ULL,
		0x3D2C2ACC2E27D6B0ULL,
		0xD9B2B3FEC7F2B2D2ULL,
		0x000000000000003EULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0xC4850A7956284ADEULL,
		0xB880720457B3DDFFULL,
		0xD21DD9D3CDCDE133ULL,
		0xB70D7D335F99210BULL,
		0xCE4497DBF05AAE88ULL,
		0xF6E2D884D6B9BDA3ULL,
		0xF406AD7FAD499BE2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BBFF890A14F2ACULL,
		0x9BC2677100E408AFULL,
		0x324217A43BB3A79BULL,
		0xB55D116E1AFA66BFULL,
		0x737B479C892FB7E0ULL,
		0x9337C5EDC5B109ADULL,
		0x000001E80D5AFF5AULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x3CFB0719768DB7F6ULL,
		0x944612239BF14F0AULL,
		0xE07CD90C8DE66E1DULL,
		0xB6E8FAFC3642B057ULL,
		0xC987A3225DF1EB92ULL,
		0xC948437B33A1BF2DULL,
		0xA53F113FE63B99BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44737E29E1479F60ULL,
		0x2191BCCDC3B288C2ULL,
		0x5F86C8560AFC0F9BULL,
		0x644BBE3D7256DD1FULL,
		0x6F667437E5B930F4ULL,
		0x27FCC77337F92908ULL,
		0x000000000014A7E2ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x60668951204BA95BULL,
		0x6295B5A8BC3E52AEULL,
		0xFAA5CD2F57BDDCE9ULL,
		0x183DC3F6FBF092DCULL,
		0xE578A0B1A3A8D236ULL,
		0xD6C5AF30E9027BA1ULL,
		0x9DD9EC317E2F704CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1787CA55CC0CD12AULL,
		0xEAF7BB9D2C52B6B5ULL,
		0xDF7E125B9F54B9A5ULL,
		0x34751A46C307B87EULL,
		0x1D204F743CAF1416ULL,
		0x2FC5EE099AD8B5E6ULL,
		0x0000000013BB3D86ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0xAD091003DD73C197ULL,
		0x2EF5AF41E9015324ULL,
		0x2B41C411BEA5C437ULL,
		0x88254AB7D1FB1DFFULL,
		0x745AF42BE2A781A5ULL,
		0xC7682EA1022E5884ULL,
		0x77867F85690D81C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD6BD07A4054C92ULL,
		0xAD071046FA9710DCULL,
		0x20952ADF47EC77FCULL,
		0xD16BD0AF8A9E0696ULL,
		0x1DA0BA8408B96211ULL,
		0xDE19FE15A436070FULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xCB247676E3F109D3ULL,
		0xFA40F4D5EB5DCFE3ULL,
		0x7271EE1992DE1661ULL,
		0xD202CA108BE0DC44ULL,
		0x9BEB6DB29C6B49DCULL,
		0x406CA0B0DBA07683ULL,
		0x8C85700B373D4A17ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC79648ECEDC7E2ULL,
		0x2CC3F481E9ABD6BBULL,
		0xB888E4E3DC3325BCULL,
		0x93B9A405942117C1ULL,
		0xED0737D6DB6538D6ULL,
		0x942E80D94161B740ULL,
		0x0001190AE0166E7AULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x29EF312FA00EC2E6ULL,
		0x2BCCB709E56CF08BULL,
		0x298606E789861213ULL,
		0xE550400EC6B2AD30ULL,
		0xD595ADC13B62047AULL,
		0x31209A51E18FA2D5ULL,
		0xA79C9A2E73E4AF1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB84F2B6784594F79ULL,
		0x373C4C3090995E65ULL,
		0x0076359569814C30ULL,
		0x6E09DB1023D72A82ULL,
		0xD28F0C7D16AEACADULL,
		0xD1739F2578F18904ULL,
		0x0000000000053CE4ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x71F2F58FA62F9720ULL,
		0x2730C825D1BED9AFULL,
		0xD262F0CB8900157CULL,
		0xCD5391FB48CBCC03ULL,
		0x03916839B13DF8A4ULL,
		0x91C44BE53F6E6663ULL,
		0x88EA93196CB9F144ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF71F2F58FA62F9ULL,
		0x57C2730C825D1BEDULL,
		0xC03D262F0CB89001ULL,
		0x8A4CD5391FB48CBCULL,
		0x66303916839B13DFULL,
		0x14491C44BE53F6E6ULL,
		0x00088EA93196CB9FULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x22127262C07364AAULL,
		0x7D27B16ACBD79887ULL,
		0x87B279D3D01DCAA0ULL,
		0x883EEA7766AFA4D8ULL,
		0xE24B386548786BC1ULL,
		0x85EFED859CF632A5ULL,
		0x7D03BDC2DA0924D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF310E4424E4C580ULL,
		0x3B9540FA4F62D597ULL,
		0x5F49B10F64F3A7A0ULL,
		0xF0D783107DD4EECDULL,
		0xEC654BC49670CA90ULL,
		0x1249B30BDFDB0B39ULL,
		0x000000FA077B85B4ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x4366E7AE1E9359C6ULL,
		0x95059F77090514D7ULL,
		0x5BB25F5653733794ULL,
		0x07AFA7463706FD16ULL,
		0x8551867D5B612D72ULL,
		0xA58051912EC21DC4ULL,
		0xA8A400D2CBC81FE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE120A29AE86CDCULL,
		0xEACA6E66F292A0B3ULL,
		0xE8C6E0DFA2CB764BULL,
		0xCFAB6C25AE40F5F4ULL,
		0x3225D843B890AA30ULL,
		0x1A597903FCD4B00AULL,
		0x0000000000151480ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xE0E13E8CA3C9D932ULL,
		0xB51E2F8FF5F34BBCULL,
		0x25047831CE33F924ULL,
		0x451D6C00DAA49454ULL,
		0x2CD53A41C7A0977EULL,
		0x277B484668EC9801ULL,
		0xA6A4C5F0606549F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE0E13E8CA3C9D93ULL,
		0x4B51E2F8FF5F34BBULL,
		0x425047831CE33F92ULL,
		0xE451D6C00DAA4945ULL,
		0x12CD53A41C7A0977ULL,
		0x7277B484668EC980ULL,
		0x0A6A4C5F0606549FULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x2D68874AF317997AULL,
		0xF43CF2D5BDCA9A75ULL,
		0x25DB4412DF57B2B3ULL,
		0x30AAE413AD4B9F37ULL,
		0x40C22E362463A23CULL,
		0xBDE8506FFD22752EULL,
		0x71978D17395ED991ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA5AD10E95E62F3ULL,
		0x567E879E5AB7B953ULL,
		0xE6E4BB68825BEAF6ULL,
		0x4786155C8275A973ULL,
		0xA5C81845C6C48C74ULL,
		0x3237BD0A0DFFA44EULL,
		0x000E32F1A2E72BDBULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xEE2409002D9085B8ULL,
		0xD81298BB7D8CAD1AULL,
		0xC2AA1531D105AB1BULL,
		0xABB8F3577677996AULL,
		0x6E08D7001569A23AULL,
		0x130EDC42A14AFE2FULL,
		0xDB54DA5FE58E482AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEE2409002D9085ULL,
		0x1BD81298BB7D8CADULL,
		0x6AC2AA1531D105ABULL,
		0x3AABB8F357767799ULL,
		0x2F6E08D7001569A2ULL,
		0x2A130EDC42A14AFEULL,
		0x00DB54DA5FE58E48ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xEA65D419B912084EULL,
		0x248D3590E1D78588ULL,
		0xFD4F994AC32FCE7CULL,
		0x57935B3FD782F73BULL,
		0xF044509706416060ULL,
		0x5E3AA8DBFD95D06DULL,
		0xC32390E4DAA960E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2C47532EA0CDC89ULL,
		0xE73E12469AC870EBULL,
		0x7B9DFEA7CCA56197ULL,
		0xB0302BC9AD9FEBC1ULL,
		0xE836F822284B8320ULL,
		0xB070AF1D546DFECAULL,
		0x00006191C8726D54ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x6A6F3CBD927C11AFULL,
		0x4C4CA9D2B26CFBC4ULL,
		0xDD5C7E27C80EA1BFULL,
		0xF72BF15C734DDAF5ULL,
		0x853FF707D5CAB6B3ULL,
		0x1C8AB00AE0722A53ULL,
		0xB4A6DDEF28CCA2BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A74AC9B3EF11A9ULL,
		0x71F89F203A86FD31ULL,
		0xAFC571CD376BD775ULL,
		0xFFDC1F572ADACFDCULL,
		0x2AC02B81C8A94E14ULL,
		0x9B77BCA3328AF872ULL,
		0x00000000000002D2ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x370052F5AB51E18AULL,
		0x2ABB8BCF9E4345E3ULL,
		0x1CE1F98AB7959728ULL,
		0x7B6190D90F35E0F7ULL,
		0x9A9E7ED822F3E687ULL,
		0x2C18BB424B671B00ULL,
		0x58C31F7D179CDECDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF21A2F19B80297ADULL,
		0xBCACB94155DC5E7CULL,
		0x79AF07B8E70FCC55ULL,
		0x179F343BDB0C86C8ULL,
		0x5B38D804D4F3F6C1ULL,
		0xBCE6F66960C5DA12ULL,
		0x00000002C618FBE8ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0xC8C32F008581730CULL,
		0x66706584A00ED80EULL,
		0x95182EA8CDC5FB37ULL,
		0x0CA67FA9C055A43DULL,
		0x98F9BA4D951A7297ULL,
		0x3BF21263F30E8598ULL,
		0x4A55F6F4732717DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x612803B603B230CBULL,
		0xAA33717ECDD99C19ULL,
		0xEA7015690F65460BULL,
		0x9365469CA5C3299FULL,
		0x98FCC3A166263E6EULL,
		0xBD1CC9C5F68EFC84ULL,
		0x000000000012957DULL,
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
		0x9BD61A1FB2EBA14AULL,
		0xA3C2E4537CE1E616ULL,
		0xF413F225AA075718ULL,
		0x9D893C45A821F096ULL,
		0x44066BFE094333B7ULL,
		0xEF7BF2C9498492B2ULL,
		0x80D9DB013D7CAB35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F30B4DEB0D0FD9ULL,
		0x03AB8C51E17229BEULL,
		0x10F84B7A09F912D5ULL,
		0xA199DBCEC49E22D4ULL,
		0xC24959220335FF04ULL,
		0xBE559AF7BDF964A4ULL,
		0x000000406CED809EULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xAB5B925A0AD725B3ULL,
		0xF0799C1BB5D7D381ULL,
		0x2D177216AA5DF7A4ULL,
		0xA522794BB410A0BBULL,
		0x8767C88721B9BB07ULL,
		0x688B1AC4946B4A6BULL,
		0xDC793EE738E306F2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF338376BAFA70356ULL,
		0x2EE42D54BBEF49E0ULL,
		0x44F297682141765AULL,
		0xCF910E4373760F4AULL,
		0x16358928D694D70EULL,
		0xF27DCE71C60DE4D1ULL,
		0x00000000000001B8ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x35020F614CC13196ULL,
		0xA77EBCA0967E584BULL,
		0x6AEB4623DC628066ULL,
		0x86C8DFF630B0CD4DULL,
		0x9054D12865B181ABULL,
		0xDBE2449A58048023ULL,
		0x518D5C9B9B251D74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCA0967E584B350ULL,
		0xB4623DC628066A77ULL,
		0x8DFF630B0CD4D6AEULL,
		0x4D12865B181AB86CULL,
		0x2449A58048023905ULL,
		0xD5C9B9B251D74DBEULL,
		0x0000000000000518ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xB4A06FE8AE66C62DULL,
		0x33E48794E5580933ULL,
		0x4688CD301B112839ULL,
		0x44BD5CEE32A4AAEAULL,
		0xB9071C711404C09DULL,
		0xB63E60638E454B4BULL,
		0x5A01165E7468DE7CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF243CA72AC0499DAULL,
		0x4466980D88941C99ULL,
		0x5EAE771952557523ULL,
		0x838E388A02604EA2ULL,
		0x1F3031C722A5A5DCULL,
		0x008B2F3A346F3E5BULL,
		0x000000000000002DULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x5DD8D9F50ABFDD47ULL,
		0xB9FB20298263308CULL,
		0x1463990DDEBAE00AULL,
		0x9801A9764DF5EFECULL,
		0x4C4F3AC4368450B5ULL,
		0x4184810C1F4A8825ULL,
		0xA6970E363E6B071AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EC80A6098CC231ULL,
		0x518E64377AEB802AULL,
		0x6006A5D937D7BFB0ULL,
		0x313CEB10DA1142D6ULL,
		0x061204307D2A2095ULL,
		0x9A5C38D8F9AC1C69ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xC91FA4F31F1FDE9CULL,
		0x616BD68D56732490ULL,
		0xC23AF0892751F466ULL,
		0x240AE03A2AE94DAEULL,
		0xA47DDB055E6CD411ULL,
		0x717A28A45B56EC09ULL,
		0x9066D31A75FC9834ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46AB399248648FDULL,
		0x84493A8FA3330B5EULL,
		0x01D1574A6D7611D7ULL,
		0xD82AF366A0892057ULL,
		0x4522DAB7604D23EEULL,
		0x98D3AFE4C1A38BD1ULL,
		0x0000000000048336ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x3F75616BCE912F2AULL,
		0xB53C4507E342B32AULL,
		0xC69A8457B6D812CAULL,
		0x33864246F1ACAA92ULL,
		0x962A65F2B87A460AULL,
		0xD7C1265B91F8D5F7ULL,
		0xC2CA58D85FACF3E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x547EEAC2D79D225EULL,
		0x956A788A0FC68566ULL,
		0x258D3508AF6DB025ULL,
		0x14670C848DE35955ULL,
		0xEF2C54CBE570F48CULL,
		0xD1AF824CB723F1ABULL,
		0x018594B1B0BF59E7ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
}