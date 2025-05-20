#include "tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Double Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x1A9771F4F69B9AE7ULL,
		0x6FFA1B558C28C1B8ULL,
		0x6FEC85E5BCB013F2ULL,
		0x1C0B61B2E98A14B7ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x352EE3E9ED3735CEULL,
		0xDFF436AB18518370ULL,
		0xDFD90BCB796027E4ULL,
		0x3816C365D314296EULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xF2D0DDC1100FC422ULL,
		0x89E21616B833F8DFULL,
		0x0A17875A9D833259ULL,
		0x06776E0FBCAFFB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A1BB82201F8844ULL,
		0x13C42C2D7067F1BFULL,
		0x142F0EB53B0664B3ULL,
		0x0CEEDC1F795FF662ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xDC003DB2B3EFE017ULL,
		0x47A6532E1916BA50ULL,
		0x3A9E656F63EF241EULL,
		0x1EE5C57B71DF8489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8007B6567DFC02EULL,
		0x8F4CA65C322D74A1ULL,
		0x753CCADEC7DE483CULL,
		0x3DCB8AF6E3BF0912ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x2B7606116BF6A997ULL,
		0xB36EAC4A0EBDE6EAULL,
		0x6122F492FF6A7600ULL,
		0x375316042E01C32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56EC0C22D7ED532EULL,
		0x66DD58941D7BCDD4ULL,
		0xC245E925FED4EC01ULL,
		0x6EA62C085C038658ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x242B5F70D938A424ULL,
		0xF5B843FD9CAAF654ULL,
		0x44B9DABD759C8111ULL,
		0x187C301F97CC6D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4856BEE1B2714848ULL,
		0xEB7087FB3955ECA8ULL,
		0x8973B57AEB390223ULL,
		0x30F8603F2F98DAD6ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xEE0D74074DC9B319ULL,
		0x4B11BF25CDC890DBULL,
		0x2EBA631BA83233A7ULL,
		0x436B1C58DDE5D12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1AE80E9B936645ULL,
		0x96237E4B9B9121B7ULL,
		0x5D74C6375064674EULL,
		0x06D638B1BBCBA25AULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x78F18CD90BE0C240ULL,
		0xEFBCB3C41B8F0EECULL,
		0x22F747C3F0CC3F7EULL,
		0x791DC684BC27DD96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1E319B217C18493ULL,
		0xDF796788371E1DD8ULL,
		0x45EE8F87E1987EFDULL,
		0x723B8D09784FBB2CULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x1BC9A471E9A5E5FCULL,
		0x61BBF25F6BED0992ULL,
		0xCDE595A075A866E7ULL,
		0x0D3D92065BCA56E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x379348E3D34BCBF8ULL,
		0xC377E4BED7DA1324ULL,
		0x9BCB2B40EB50CDCEULL,
		0x1A7B240CB794ADC7ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x0F769DE26CECC5D3ULL,
		0xEB06E93008A79F5AULL,
		0x64772CD79F8193B6ULL,
		0x58E228488B3420B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EED3BC4D9D98BB9ULL,
		0xD60DD260114F3EB4ULL,
		0xC8EE59AF3F03276DULL,
		0x31C450911668416AULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x2C5595AE84D16C29ULL,
		0xF07209A54498B9BBULL,
		0x11D583E3A769105EULL,
		0x4C28E35261E8C96EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58AB2B5D09A2D865ULL,
		0xE0E4134A89317376ULL,
		0x23AB07C74ED220BDULL,
		0x1851C6A4C3D192DCULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xBC0D7D124EF693F5ULL,
		0xAE9A4C695F3D6235ULL,
		0xCB1355FD7A9F253FULL,
		0x50754FB3D065173FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x781AFA249DED27FDULL,
		0x5D3498D2BE7AC46BULL,
		0x9626ABFAF53E4A7FULL,
		0x20EA9F67A0CA2E7FULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5894B0A3474F8BC4ULL,
		0xF8AD8D967A1DB411ULL,
		0x6600F57506BE6A53ULL,
		0x649BD2B29725A1C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB12961468E9F179BULL,
		0xF15B1B2CF43B6822ULL,
		0xCC01EAEA0D7CD4A7ULL,
		0x4937A5652E4B4386ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xD5CF11B72B07B91EULL,
		0xCE8207D51D6B7C55ULL,
		0x730FEC6B434F2AFAULL,
		0x1198CDD4D9380759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9E236E560F723CULL,
		0x9D040FAA3AD6F8ABULL,
		0xE61FD8D6869E55F5ULL,
		0x23319BA9B2700EB2ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xCC68B500767D10C9ULL,
		0x9AFB237B8CA609C0ULL,
		0x4C2219EA3CD1B80FULL,
		0x03D4483B615C5492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98D16A00ECFA2192ULL,
		0x35F646F7194C1381ULL,
		0x984433D479A3701FULL,
		0x07A89076C2B8A924ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xBB7EB872D6708D43ULL,
		0x9ED82FAE7AD03AD0ULL,
		0xBED559523C82952FULL,
		0x46DF538AAA8478CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76FD70E5ACE11A99ULL,
		0x3DB05F5CF5A075A1ULL,
		0x7DAAB2A479052A5FULL,
		0x0DBEA7155508F195ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xA2292B1745509513ULL,
		0xDA3315EACEC65BA8ULL,
		0xE8BA8DE26BFC079CULL,
		0x490EDF851BDE997BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4452562E8AA12A39ULL,
		0xB4662BD59D8CB751ULL,
		0xD1751BC4D7F80F39ULL,
		0x121DBF0A37BD32F7ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xF6123E18DEA1899CULL,
		0x90E3AE6678C64C36ULL,
		0x12D55E2058E2E3E8ULL,
		0x776162DC2F96BA17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC247C31BD43134BULL,
		0x21C75CCCF18C986DULL,
		0x25AABC40B1C5C7D1ULL,
		0x6EC2C5B85F2D742EULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xDB38EB555389A68DULL,
		0xECD3FEFFA01D84A2ULL,
		0x95939CEA4E240765ULL,
		0x339D842110C8DBAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB671D6AAA7134D1AULL,
		0xD9A7FDFF403B0945ULL,
		0x2B2739D49C480ECBULL,
		0x673B08422191B755ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x95C34BC5CF5D7E89ULL,
		0x3C1F9204D58C497BULL,
		0x50A89311726AEC17ULL,
		0x0B0B7C227F406669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B86978B9EBAFD12ULL,
		0x783F2409AB1892F7ULL,
		0xA1512622E4D5D82EULL,
		0x1616F844FE80CCD2ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xF4465E99C30A3714ULL,
		0xC1BB882EB3061E2DULL,
		0x6DC54F7D7A0D1965ULL,
		0x6E9615EE4491CFA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE88CBD3386146E3BULL,
		0x8377105D660C3C5BULL,
		0xDB8A9EFAF41A32CBULL,
		0x5D2C2BDC89239F52ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x82923003F8C84C31ULL,
		0x76710C03FEFC0EBCULL,
		0xA23F66492BDBFA10ULL,
		0x29C8B38469AD7F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05246007F1909862ULL,
		0xECE21807FDF81D79ULL,
		0x447ECC9257B7F420ULL,
		0x53916708D35AFE1BULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x7E402E0F775577EBULL,
		0xAA757BC2CBA15474ULL,
		0x8A0AB453B1059B06ULL,
		0x12B79702D665CE06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC805C1EEEAAEFD6ULL,
		0x54EAF7859742A8E8ULL,
		0x141568A7620B360DULL,
		0x256F2E05ACCB9C0DULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x4736CAE6A48B41B7ULL,
		0xCE7BBC17DA88B384ULL,
		0x491B3212AD91BEC1ULL,
		0x4B877A7811218920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E6D95CD49168381ULL,
		0x9CF7782FB5116708ULL,
		0x923664255B237D83ULL,
		0x170EF4F022431240ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xCEC4C4EA57CEC7CFULL,
		0x499AB4A333DC94B8ULL,
		0x8E6BE439FBAF2F62ULL,
		0x7482866D171089B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D8989D4AF9D8FB1ULL,
		0x9335694667B92971ULL,
		0x1CD7C873F75E5EC4ULL,
		0x69050CDA2E211369ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x7F16E70825A195C6ULL,
		0xE9002FCA0AA727F0ULL,
		0x5C4365632D1FF0F1ULL,
		0x0B0A453F7EB9D7ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE2DCE104B432B8CULL,
		0xD2005F94154E4FE0ULL,
		0xB886CAC65A3FE1E3ULL,
		0x16148A7EFD73AFD8ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5D2E1C31E04A91F0ULL,
		0x79227D954EF89FE5ULL,
		0x1AAFA8FED8964E81ULL,
		0x4762C9FFA6EEAE55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA5C3863C09523F3ULL,
		0xF244FB2A9DF13FCAULL,
		0x355F51FDB12C9D02ULL,
		0x0EC593FF4DDD5CAAULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xECB8A658CFD00551ULL,
		0xF31B250780198879ULL,
		0x30D9BC884DC598D7ULL,
		0x44986CC3E142D130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9714CB19FA00AB5ULL,
		0xE6364A0F003310F3ULL,
		0x61B379109B8B31AFULL,
		0x0930D987C285A260ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xC643DC63EED4610AULL,
		0x1B5AB7277B2A846BULL,
		0x613F52ECF9699574ULL,
		0x572C8C815F1B2C5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C87B8C7DDA8C227ULL,
		0x36B56E4EF65508D7ULL,
		0xC27EA5D9F2D32AE8ULL,
		0x2E591902BE3658B4ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xC3B3681D0536CC92ULL,
		0x469F0F5EB16E0D1DULL,
		0xBCA1AE3D9D692E6DULL,
		0x6C79FB9635C14719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8766D03A0A6D9937ULL,
		0x8D3E1EBD62DC1A3BULL,
		0x79435C7B3AD25CDAULL,
		0x58F3F72C6B828E33ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xB7A6CDFEBBA4D242ULL,
		0xBD73547AB155CA50ULL,
		0xD57AAC1687426799ULL,
		0x0B6264E5AD5D037FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F4D9BFD7749A484ULL,
		0x7AE6A8F562AB94A1ULL,
		0xAAF5582D0E84CF33ULL,
		0x16C4C9CB5ABA06FFULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x93FDB3912C4A3D45ULL,
		0x7B4348C69974BC7EULL,
		0xF191B6AB7A0031E7ULL,
		0x5BF792B599AD4097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27FB672258947A9DULL,
		0xF686918D32E978FDULL,
		0xE3236D56F40063CEULL,
		0x37EF256B335A812FULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xB58F8E525DF03752ULL,
		0xBF0C832681E5617FULL,
		0x5679AB5B50BBB11BULL,
		0x13B2C808283721F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1F1CA4BBE06EA4ULL,
		0x7E19064D03CAC2FFULL,
		0xACF356B6A1776237ULL,
		0x27659010506E43E0ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x417FCB6510FC82D7ULL,
		0xD5D1227933EA88BBULL,
		0x134EF87FF22F76C4ULL,
		0x6B17F063C53AE44FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82FF96CA21F905C1ULL,
		0xABA244F267D51176ULL,
		0x269DF0FFE45EED89ULL,
		0x562FE0C78A75C89EULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xEACE16BC52F68B13ULL,
		0x6D5DF3F093A56EF6ULL,
		0x7D2381822F72816FULL,
		0x48EEFCD63A137B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59C2D78A5ED1639ULL,
		0xDABBE7E1274ADDEDULL,
		0xFA4703045EE502DEULL,
		0x11DDF9AC7426F6F6ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x6769092DED97958FULL,
		0x49FBE4B4CF41ACD5ULL,
		0xBF6363315C774B97ULL,
		0x0C2DE94FA7181E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED2125BDB2F2B1EULL,
		0x93F7C9699E8359AAULL,
		0x7EC6C662B8EE972EULL,
		0x185BD29F4E303D1BULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xAB7258DD6F7A8B92ULL,
		0x14940A4F7B2956C8ULL,
		0x7680A0A2FF556D0DULL,
		0x32116834E94C5912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E4B1BADEF51724ULL,
		0x2928149EF652AD91ULL,
		0xED014145FEAADA1AULL,
		0x6422D069D298B224ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5686B055D1B392A5ULL,
		0x872C3F580160A39DULL,
		0x319DE4DD28F1AD70ULL,
		0x59291795E895A859ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0D60ABA367255DULL,
		0x0E587EB002C1473AULL,
		0x633BC9BA51E35AE1ULL,
		0x32522F2BD12B50B2ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xA1F35F23CB5EC74FULL,
		0xC281CD484F93B101ULL,
		0x3E0BE46383943367ULL,
		0x3D4ECF2E517B2A28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E6BE4796BD8E9EULL,
		0x85039A909F276203ULL,
		0x7C17C8C7072866CFULL,
		0x7A9D9E5CA2F65450ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xFB06DB86D450A3F9ULL,
		0xD6E3C0E16310B918ULL,
		0xE3BD683D10EA6131ULL,
		0x6080B8EF77BBDACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60DB70DA8A14805ULL,
		0xADC781C2C6217231ULL,
		0xC77AD07A21D4C263ULL,
		0x410171DEEF77B59FULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x9412BDDC6F4D689BULL,
		0xF40FF528A9E42A04ULL,
		0xF2A6A18746538DBDULL,
		0x2E50C009D6A07CC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28257BB8DE9AD136ULL,
		0xE81FEA5153C85409ULL,
		0xE54D430E8CA71B7BULL,
		0x5CA18013AD40F991ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x1C3FBAFA272E6A5DULL,
		0xBC9530AC3728FD01ULL,
		0x61769CB0827BB39DULL,
		0x52014ABD62BB53BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387F75F44E5CD4CDULL,
		0x792A61586E51FA02ULL,
		0xC2ED396104F7673BULL,
		0x2402957AC576A77EULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5D86B1668E69A9BEULL,
		0x96F5121F95B2B462ULL,
		0x444B686F3372D2D7ULL,
		0x215A8A07CF94B94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0D62CD1CD3537CULL,
		0x2DEA243F2B6568C4ULL,
		0x8896D0DE66E5A5AFULL,
		0x42B5140F9F29729EULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x7408F565988564ABULL,
		0xA057D65C3C6853FAULL,
		0x72A36C71346AB0B7ULL,
		0x78C96F47F7548B60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE811EACB310AC969ULL,
		0x40AFACB878D0A7F4ULL,
		0xE546D8E268D5616FULL,
		0x7192DE8FEEA916C0ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x433530C8D0C36606ULL,
		0x887933516DA0859CULL,
		0xC36236608702A76AULL,
		0x7949137B4214593FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x866A6191A186CC1FULL,
		0x10F266A2DB410B38ULL,
		0x86C46CC10E054ED5ULL,
		0x729226F68428B27FULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xCE6752C987BC6A53ULL,
		0x8D86029CE5FBC432ULL,
		0xE497008F903845E7ULL,
		0x7AB261429F37F2ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CCEA5930F78D4B9ULL,
		0x1B0C0539CBF78865ULL,
		0xC92E011F20708BCFULL,
		0x7564C2853E6FE557ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xDD8778E377EE5DCEULL,
		0x68D4055706574305ULL,
		0x6786BE8DBB271839ULL,
		0x46223E6D4F17D3B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0EF1C6EFDCBBAFULL,
		0xD1A80AAE0CAE860BULL,
		0xCF0D7D1B764E3072ULL,
		0x0C447CDA9E2FA76CULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5D32FC910367DF9DULL,
		0x510E27A4B00A437CULL,
		0x9A668CE0BCC33C50ULL,
		0x23A58FF0FC9AC767ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA65F92206CFBF3AULL,
		0xA21C4F49601486F8ULL,
		0x34CD19C1798678A0ULL,
		0x474B1FE1F9358ECFULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x6932D5AD27824116ULL,
		0x7DABF5A6C77207CBULL,
		0x57A098EEE57E63CAULL,
		0x473201711050935AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD265AB5A4F04823FULL,
		0xFB57EB4D8EE40F96ULL,
		0xAF4131DDCAFCC794ULL,
		0x0E6402E220A126B4ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0x5DD4D21B96922C5DULL,
		0x34AE649550D4CFD2ULL,
		0x96B5D77DF630BE50ULL,
		0x49055364DD16CB6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA9A4372D2458CDULL,
		0x695CC92AA1A99FA4ULL,
		0x2D6BAEFBEC617CA0ULL,
		0x120AA6C9BA2D96DFULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
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
		0xB9F97C8A8363427EULL,
		0xFD622EF4C801B062ULL,
		0xEBC814D087AB4203ULL,
		0x1BA8F83FC501114EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73F2F91506C684FCULL,
		0xFAC45DE9900360C5ULL,
		0xD79029A10F568407ULL,
		0x3751F07F8A02229DULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C90630E0E97750FULL,
		0xFB6B911F5E201738ULL,
		0x247D1B4DFD695640ULL,
		0x2C3D0E63B5E06E6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF920C61C1D2EEA1EULL,
		0xF6D7223EBC402E70ULL,
		0x48FA369BFAD2AC81ULL,
		0x587A1CC76BC0DCDAULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE388538551BCE13ULL,
		0xBDBA3A9B4E855C97ULL,
		0x6DC992B85748A558ULL,
		0x4390EFA7CB5FDECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C710A70AA379C39ULL,
		0x7B7475369D0AB92FULL,
		0xDB932570AE914AB1ULL,
		0x0721DF4F96BFBD94ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x403377583373655CULL,
		0x54DFA23D0E861A0FULL,
		0x6937F26D373B1B51ULL,
		0x3FB8A5E16B23DBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8066EEB066E6CAB8ULL,
		0xA9BF447A1D0C341EULL,
		0xD26FE4DA6E7636A2ULL,
		0x7F714BC2D647B74AULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933118BF1096D23CULL,
		0x50329CDCF2B50845ULL,
		0x95A9DCF6ED973BF8ULL,
		0x50347EA33F8B2885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2662317E212DA48BULL,
		0xA06539B9E56A108BULL,
		0x2B53B9EDDB2E77F0ULL,
		0x2068FD467F16510BULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x823CE7108AF3BE2EULL,
		0x3AB0948E9828FBBDULL,
		0x6A1D33EDA70F358AULL,
		0x1CA6DD71E95795C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0479CE2115E77C5CULL,
		0x7561291D3051F77BULL,
		0xD43A67DB4E1E6B14ULL,
		0x394DBAE3D2AF2B8AULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E27DECB2AC9E692ULL,
		0x0C52E21272CC1264ULL,
		0xD9572E9AEA81C495ULL,
		0x169EA16A02C310F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4FBD965593CD24ULL,
		0x18A5C424E59824C8ULL,
		0xB2AE5D35D503892AULL,
		0x2D3D42D4058621F3ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D6E27CEB9CAFD64ULL,
		0x9B0702F4928A12DAULL,
		0xA956D7CBBE2C93A6ULL,
		0x14267AD5EACDAF3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ADC4F9D7395FAC8ULL,
		0x360E05E9251425B5ULL,
		0x52ADAF977C59274DULL,
		0x284CF5ABD59B5E77ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A1DAFDC4451FBCAULL,
		0x2A5127D33C9B6EB1ULL,
		0x36BD2E15647B968AULL,
		0x37C394E8EDBD6C57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB43B5FB888A3F794ULL,
		0x54A24FA67936DD62ULL,
		0x6D7A5C2AC8F72D14ULL,
		0x6F8729D1DB7AD8AEULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B8418D0CB166D6FULL,
		0x40D167A79937C53CULL,
		0xB249FED705BFAF42ULL,
		0x2D9237FB73F89BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF70831A1962CDADEULL,
		0x81A2CF4F326F8A78ULL,
		0x6493FDAE0B7F5E84ULL,
		0x5B246FF6E7F13799ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7569E2254EACCF16ULL,
		0x1364B8F584BFB4B6ULL,
		0x68B4E0571B58A2AEULL,
		0x64F9CCCBC6116A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAD3C44A9D599E3FULL,
		0x26C971EB097F696CULL,
		0xD169C0AE36B1455CULL,
		0x49F399978C22D4C6ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE90F1BCAF946BB56ULL,
		0x16E8883E6192E913ULL,
		0x75980A5A0BC24250ULL,
		0x179608BE2227FE63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21E3795F28D76ACULL,
		0x2DD1107CC325D227ULL,
		0xEB3014B4178484A0ULL,
		0x2F2C117C444FFCC6ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD36941767EF18E96ULL,
		0x2E38CEBE80D826B7ULL,
		0x6639C6EEB8FE04C2ULL,
		0x70EE616B86965D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D282ECFDE31D3FULL,
		0x5C719D7D01B04D6FULL,
		0xCC738DDD71FC0984ULL,
		0x61DCC2D70D2CBB0AULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3854BAE72F1D2AFULL,
		0x5AC7610921A2CDA5ULL,
		0x390753CA40DE6F2EULL,
		0x479757664669C977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670A975CE5E3A571ULL,
		0xB58EC21243459B4BULL,
		0x720EA79481BCDE5CULL,
		0x0F2EAECC8CD392EEULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F444F67D63E7888ULL,
		0xE6C658B2255115F1ULL,
		0x3BECB0EB5E292193ULL,
		0x52AFD7B9982AF337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E889ECFAC7CF123ULL,
		0xCD8CB1644AA22BE2ULL,
		0x77D961D6BC524327ULL,
		0x255FAF733055E66EULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB00C0C0B69B63B6ULL,
		0x7C6488F5F8DC1760ULL,
		0x7126CF65AA46288CULL,
		0x3687BE4DFB48FB72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x560181816D36C76CULL,
		0xF8C911EBF1B82EC1ULL,
		0xE24D9ECB548C5118ULL,
		0x6D0F7C9BF691F6E4ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02CAD840F7D524F6ULL,
		0x2FC32272ABD15CC2ULL,
		0xF2D117708FF6EA90ULL,
		0x0183C318C9341C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0595B081EFAA49ECULL,
		0x5F8644E557A2B984ULL,
		0xE5A22EE11FEDD520ULL,
		0x030786319268388BULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DAFDBEE47B5500FULL,
		0x8C7FF13942D99D82ULL,
		0xE8E6782704124C4EULL,
		0x00E51294A36CA663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB5FB7DC8F6AA01EULL,
		0x18FFE27285B33B04ULL,
		0xD1CCF04E0824989DULL,
		0x01CA252946D94CC7ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C594B1A12978E35ULL,
		0xD3A7551E6B0DE3B4ULL,
		0x9E48746B4D34CC9EULL,
		0x5EAC27AD020F9A1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B29634252F1C7DULL,
		0xA74EAA3CD61BC768ULL,
		0x3C90E8D69A69993DULL,
		0x3D584F5A041F3437ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8641E92FA0C45338ULL,
		0xBCFAE9B8CFACEA23ULL,
		0x30741B8999FA1565ULL,
		0x23078A0AAF8AC580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C83D25F4188A670ULL,
		0x79F5D3719F59D447ULL,
		0x60E8371333F42ACBULL,
		0x460F14155F158B00ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CADBD65E557225BULL,
		0x82A193DEB7603242ULL,
		0x10A89BEECCD8DFA6ULL,
		0x094B82DC6D7C8B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD95B7ACBCAAE44B6ULL,
		0x054327BD6EC06484ULL,
		0x215137DD99B1BF4DULL,
		0x129705B8DAF9161EULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1581338DB63D1E0FULL,
		0xFBD255D19F46976EULL,
		0x5D0F00FF5C18AC3EULL,
		0x5AF521596F165358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B02671B6C7A3C31ULL,
		0xF7A4ABA33E8D2EDCULL,
		0xBA1E01FEB831587DULL,
		0x35EA42B2DE2CA6B0ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1381EB2C4B0F9339ULL,
		0xBAA8FFBA0F8FE8A2ULL,
		0x047F1AA91AC17A19ULL,
		0x3B1DD94ECC188B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2703D658961F2672ULL,
		0x7551FF741F1FD144ULL,
		0x08FE35523582F433ULL,
		0x763BB29D9831166AULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC36202DAC7F6536ULL,
		0xC8A6A46FA1182EA6ULL,
		0xCACCEA24FE528677ULL,
		0x4E740B2C852002E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x586C405B58FECA7FULL,
		0x914D48DF42305D4DULL,
		0x9599D449FCA50CEFULL,
		0x1CE816590A4005C1ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4071F58DFE374A84ULL,
		0x99CB4218C25BBA85ULL,
		0x5EF7C8BB6522E1B1ULL,
		0x13874CB9BB2BA957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E3EB1BFC6E9508ULL,
		0x3396843184B7750AULL,
		0xBDEF9176CA45C363ULL,
		0x270E9973765752AEULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD308B9CF3FC28F10ULL,
		0x9D68F9344360334CULL,
		0xAB26E08C64342EEBULL,
		0x4CD9C9AA60A69F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA611739E7F851E33ULL,
		0x3AD1F26886C06699ULL,
		0x564DC118C8685DD7ULL,
		0x19B39354C14D3F2BULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B1265B273C8BF7AULL,
		0x4A683340E2B37B6DULL,
		0x69EB119A96F42AD9ULL,
		0x04FC15BB2059697BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD624CB64E7917EF4ULL,
		0x94D06681C566F6DAULL,
		0xD3D623352DE855B2ULL,
		0x09F82B7640B2D2F6ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AB34B08D5BAC14AULL,
		0x5328C944FED820A8ULL,
		0xCA8FF8833CFFFC72ULL,
		0x46A5ACF466991961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35669611AB7582A7ULL,
		0xA6519289FDB04150ULL,
		0x951FF10679FFF8E4ULL,
		0x0D4B59E8CD3232C3ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9DB616D63FFEE89ULL,
		0x340910E05C6182A2ULL,
		0x7213752D53ACF8DAULL,
		0x20C93D72AABECE12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B6C2DAC7FFDD12ULL,
		0x681221C0B8C30545ULL,
		0xE426EA5AA759F1B4ULL,
		0x41927AE5557D9C24ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77C6B56FED900FFAULL,
		0x00B05C9AD72216C1ULL,
		0x45DDC6A4DC0901A7ULL,
		0x1A5152970555E481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF8D6ADFDB201FF4ULL,
		0x0160B935AE442D82ULL,
		0x8BBB8D49B812034EULL,
		0x34A2A52E0AABC902ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE12D84F7393811E6ULL,
		0xC2D9D876C392C376ULL,
		0x4226B132B5FE0CE6ULL,
		0x51685F6FFAF82D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC25B09EE727023DFULL,
		0x85B3B0ED872586EDULL,
		0x844D62656BFC19CDULL,
		0x22D0BEDFF5F05A96ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B63858F12B7A4BEULL,
		0x442FFFACADBAE48EULL,
		0x85291C527ED63D05ULL,
		0x747C2E7C8EED5550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96C70B1E256F498FULL,
		0x885FFF595B75C91CULL,
		0x0A5238A4FDAC7A0AULL,
		0x68F85CF91DDAAAA1ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25CB9EB4CBA838F8ULL,
		0xA95279695D140C0BULL,
		0xA3B6D153E56647C7ULL,
		0x0E6B72B2D0BA805FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B973D69975071F0ULL,
		0x52A4F2D2BA281816ULL,
		0x476DA2A7CACC8F8FULL,
		0x1CD6E565A17500BFULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C2B01529A6868CEULL,
		0x06C51BD15F0193AEULL,
		0xFC7F37AD3FA1BC37ULL,
		0x109BD09A5519412DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x985602A534D0D19CULL,
		0x0D8A37A2BE03275CULL,
		0xF8FE6F5A7F43786EULL,
		0x2137A134AA32825BULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18246544BF38C066ULL,
		0x74A560B8F4BBBC8FULL,
		0xE59C04D368522B05ULL,
		0x3A75BCF4508286AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3048CA897E7180CCULL,
		0xE94AC171E977791EULL,
		0xCB3809A6D0A4560AULL,
		0x74EB79E8A1050D5DULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88DF97B997B9385AULL,
		0x3FB5AC282432E114ULL,
		0xC04CFAE4A5CAD3D8ULL,
		0x68FC29D25544188CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11BF2F732F7270C7ULL,
		0x7F6B58504865C229ULL,
		0x8099F5C94B95A7B0ULL,
		0x51F853A4AA883119ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x612B7C369465DC62ULL,
		0x2C2148193F5D8953ULL,
		0x11FA61A1047CAA21ULL,
		0x0F5BDFFFB6687D70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC256F86D28CBB8C4ULL,
		0x584290327EBB12A6ULL,
		0x23F4C34208F95442ULL,
		0x1EB7BFFF6CD0FAE0ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8718C4879C6EB34AULL,
		0x04BB912F2DD4A7D5ULL,
		0x14A1FB652B47E685ULL,
		0x5B478E7B33266862ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E31890F38DD66A7ULL,
		0x0977225E5BA94FABULL,
		0x2943F6CA568FCD0AULL,
		0x368F1CF6664CD0C4ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33240FBC272D1826ULL,
		0xCAB4C69B80989F6CULL,
		0xE8E957601ED65E81ULL,
		0x5E1C1692264CD993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66481F784E5A305FULL,
		0x95698D3701313ED8ULL,
		0xD1D2AEC03DACBD03ULL,
		0x3C382D244C99B327ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x377C450C9B2184B3ULL,
		0xBBBF5224504DA3C1ULL,
		0x0C76FF308F9D08FBULL,
		0x328F99B2312E90D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF88A1936430966ULL,
		0x777EA448A09B4782ULL,
		0x18EDFE611F3A11F7ULL,
		0x651F3364625D21A2ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x437E16FEBE1C9F31ULL,
		0xDE09EE5693C5BD34ULL,
		0x8B2AE6CEDBE1FD27ULL,
		0x1DB0A1BE35FA5884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86FC2DFD7C393E62ULL,
		0xBC13DCAD278B7A68ULL,
		0x1655CD9DB7C3FA4FULL,
		0x3B61437C6BF4B109ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E7F62B1CF674FEEULL,
		0xB65383A9EFA5B48AULL,
		0x19F46BB23E156DD7ULL,
		0x47AF9DD9354D72B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCFEC5639ECE9FEFULL,
		0x6CA70753DF4B6914ULL,
		0x33E8D7647C2ADBAFULL,
		0x0F5F3BB26A9AE564ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D0F0BD370C0D37FULL,
		0x372AF7901AD466DDULL,
		0x0FCC2874B6A75CEEULL,
		0x755E62E100D8A19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1E17A6E181A711ULL,
		0x6E55EF2035A8CDBAULL,
		0x1F9850E96D4EB9DCULL,
		0x6ABCC5C201B14336ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DDC2831DA4D1FDCULL,
		0xEA2918488DC5E06FULL,
		0x8F49CE39DB8CAB19ULL,
		0x6C5C9B69998E3DD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BB85063B49A3FCBULL,
		0xD45230911B8BC0DFULL,
		0x1E939C73B7195633ULL,
		0x58B936D3331C7BA3ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29320AE9111713FAULL,
		0x42EEAA95795F4588ULL,
		0x793A93F73D912839ULL,
		0x69940458A98F0482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x526415D2222E2807ULL,
		0x85DD552AF2BE8B10ULL,
		0xF27527EE7B225072ULL,
		0x532808B1531E0904ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF29E1A6CC0F2AA92ULL,
		0x1B48562B93151712ULL,
		0xD8514A1074F275B3ULL,
		0x50304CF850D42891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53C34D981E55537ULL,
		0x3690AC57262A2E25ULL,
		0xB0A29420E9E4EB66ULL,
		0x206099F0A1A85123ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15F6819E19BBBB47ULL,
		0x1723697071CB49B3ULL,
		0x6FF83C0C4C4BFA59ULL,
		0x47C51D0DD03AA01AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BED033C337776A1ULL,
		0x2E46D2E0E3969366ULL,
		0xDFF078189897F4B2ULL,
		0x0F8A3A1BA0754034ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D40668D4916FBA6ULL,
		0xFEFFE8E4A0519653ULL,
		0x0E32AAD8F3FE0E54ULL,
		0x7A158EBC3ADD4F41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A80CD1A922DF75FULL,
		0xFDFFD1C940A32CA6ULL,
		0x1C6555B1E7FC1CA9ULL,
		0x742B1D7875BA9E82ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C273C54F2FF7B02ULL,
		0xDFBF03C8F8EF8599ULL,
		0x69AC3EBEA6C9F1B3ULL,
		0x053A288178309A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x384E78A9E5FEF604ULL,
		0xBF7E0791F1DF0B33ULL,
		0xD3587D7D4D93E367ULL,
		0x0A745102F061353EULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB5AC2C7C500AF2AULL,
		0x7519EF356989A2AAULL,
		0x9EC97C3E4A75B293ULL,
		0x1426DF3EFCF6B02AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B5858F8A015E54ULL,
		0xEA33DE6AD3134555ULL,
		0x3D92F87C94EB6526ULL,
		0x284DBE7DF9ED6055ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F7C0445B1DDB3A0ULL,
		0x8E63DD48678AF369ULL,
		0x19EA5534CC0083E4ULL,
		0x7BA426034B3253CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF8088B63BB6753ULL,
		0x1CC7BA90CF15E6D2ULL,
		0x33D4AA69980107C9ULL,
		0x77484C069664A796ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}