#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x54105BAF3B766A00ULL,
		0xA04EDD45F040820CULL,
		0x1FC8B8477BF78BA9ULL,
		0x4F2391B4CD049CEBULL,
		0x0343C67FAED1827AULL,
		0x0155D4788EA6C827ULL,
		0xF10961437D686ABBULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB7517C1020831504ULL,
		0x2E11DEFDE2EA6813ULL,
		0xE46D3341273AC7F2ULL,
		0xF19FEBB4609E93C8ULL,
		0x751E23A9B209C0D0ULL,
		0x5850DF5A1AAEC055ULL,
		0x0000000000003C42ULL,
		0x0000000000000000ULL
	}};
	int shift = 50;
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
		0xD76A64BDF7FAB8B4ULL,
		0x16640847935A1AE2ULL,
		0x1E12A057A17166DEULL,
		0xF5CDCB4B2ED3EC6CULL,
		0x74FBE4A03CF418E6ULL,
		0xFC71445F5D1C70D7ULL,
		0xEAA3F477AED17EA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0211E4D686B8B5DAULL,
		0xA815E85C59B78599ULL,
		0x72D2CBB4FB1B0784ULL,
		0xF9280F3D0639BD73ULL,
		0x5117D7471C35DD3EULL,
		0xFD1DEBB45FA9BF1CULL,
		0x0000000000003AA8ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x32E6E6B3C29844BBULL,
		0xD6563C0F900EA0E5ULL,
		0xE7374C44D745E867ULL,
		0xE397EAA4C3B75D58ULL,
		0x2D8F787F2AD85B09ULL,
		0x526542CF889A91C4ULL,
		0x8A3F8F199B4ECC03ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF900EA0E532E6E6BULL,
		0x4D745E867D6563C0ULL,
		0x4C3B75D58E7374C4ULL,
		0xF2AD85B09E397EAAULL,
		0xF889A91C42D8F787ULL,
		0x99B4ECC03526542CULL,
		0x0000000008A3F8F1ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x76012C4F533B33F5ULL,
		0xBCA251411624B0D0ULL,
		0xA15BE8D938FE436FULL,
		0x755D36B42F3FCD81ULL,
		0xED361A30EC45A909ULL,
		0xDF71DC7A8C37FF2EULL,
		0x6EC99D47CECA8F93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C341D804B13D4CULL,
		0xF90DBEF289450458ULL,
		0xFF3606856FA364E3ULL,
		0x16A425D574DAD0BCULL,
		0xDFFCBBB4D868C3B1ULL,
		0x2A3E4F7DC771EA30ULL,
		0x000001BB26751F3BULL,
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
		0x26E6A14C444E2978ULL,
		0x0C6CC3656D294D8BULL,
		0x98B3C7A83C8FE836ULL,
		0xAC9CC266E0CB942BULL,
		0xF0783F9327F3259EULL,
		0x67F02F149082069FULL,
		0x0163B3F4894FBB75ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC3656D294D8B26ULL,
		0xB3C7A83C8FE8360CULL,
		0x9CC266E0CB942B98ULL,
		0x783F9327F3259EACULL,
		0xF02F149082069FF0ULL,
		0x63B3F4894FBB7567ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0xCBC7EACE4EEF1F15ULL,
		0xABD6E98E1A1A050EULL,
		0xE34354FC053126B8ULL,
		0xF36763CA9C4ECF75ULL,
		0xB2AD1B0B6A3B2393ULL,
		0x527E99FEE76909FCULL,
		0x69AAF434C5D763A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5BA6386868143B2ULL,
		0xD0D53F014C49AE2AULL,
		0xD9D8F2A713B3DD78ULL,
		0xAB46C2DA8EC8E4FCULL,
		0x9FA67FB9DA427F2CULL,
		0x6ABD0D3175D8E814ULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x992279DB7C3420A0ULL,
		0xDEAE2609E731A529ULL,
		0x9BFEBEF0456AB2B2ULL,
		0x60A8FB3D6DE6FE54ULL,
		0x6E98FF2AAA5EAA49ULL,
		0x31527A17A4DF7CAAULL,
		0x3010EFF84ABCAF07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A529992279DB7CULL,
		0x6AB2B2DEAE2609E7ULL,
		0xE6FE549BFEBEF045ULL,
		0x5EAA4960A8FB3D6DULL,
		0xDF7CAA6E98FF2AAAULL,
		0xBCAF0731527A17A4ULL,
		0x0000003010EFF84AULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x53A2A946F7CEE843ULL,
		0x5B13DE09CC808D14ULL,
		0xB483B3F0D4174A5BULL,
		0x5274E5B532D9CF42ULL,
		0xE0534A5B319BE46FULL,
		0x44FF7E9027FF0BF8ULL,
		0xD6B2167E1204D3A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99011A28A745528DULL,
		0xA82E94B6B627BC13ULL,
		0x65B39E85690767E1ULL,
		0x6337C8DEA4E9CB6AULL,
		0x4FFE17F1C0A694B6ULL,
		0x2409A74E89FEFD20ULL,
		0x00000001AD642CFCULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xAEEE8C5DAF19255EULL,
		0x67277049ADF4A662ULL,
		0xC0398581CB2A8BDBULL,
		0xFBCC2C8A08087013ULL,
		0xEAF315900A1A8A30ULL,
		0x04DCF7B0DB61877BULL,
		0xDFC093F06E6749E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B824D6FA5331577ULL,
		0xCC2C0E59545EDB39ULL,
		0x6164504043809E01ULL,
		0x98AC8050D45187DEULL,
		0xE7BD86DB0C3BDF57ULL,
		0x049F83733A4F4826ULL,
		0x00000000000006FEULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xEAF5A9F36A456D5AULL,
		0x0C9E37BAD25EC2F8ULL,
		0x40CCA69DC4582477ULL,
		0x73287F445DDA9462ULL,
		0xAA36ACDFC8153991ULL,
		0xF5EA0F246F6AD87AULL,
		0x952A3A8932B4C16DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F75A4BD85F1D5EBULL,
		0x4D3B88B048EE193CULL,
		0xFE88BBB528C48199ULL,
		0x59BF902A7322E650ULL,
		0x1E48DED5B0F5546DULL,
		0x7512656982DBEBD4ULL,
		0x0000000000012A54ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x44523EF71ADB314FULL,
		0xD982A793FFD16DDEULL,
		0x3698859375C2AF2DULL,
		0xBEA61B8ECAA2CA17ULL,
		0x448534A4EE8E17E6ULL,
		0xE078C9E42AC1F04CULL,
		0xB0BC644DC87D9B8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x153C9FFE8B6EF222ULL,
		0xC42C9BAE15796ECCULL,
		0x30DC76551650B9B4ULL,
		0x29A5277470BF35F5ULL,
		0xC64F21560F826224ULL,
		0xE3226E43ECDC5703ULL,
		0x0000000000000585ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x001DBC44FDCA638EULL,
		0xE6CEB5C4E7F73002ULL,
		0xDB25B4F89673E54AULL,
		0xEEACC8BB410F3D77ULL,
		0x68D185F7A0F5DD43ULL,
		0x84AECD7C9083A48AULL,
		0xAE58D3A4548A777EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E7F73002001DBC4ULL,
		0x89673E54AE6CEB5CULL,
		0xB410F3D77DB25B4FULL,
		0x7A0F5DD43EEACC8BULL,
		0xC9083A48A68D185FULL,
		0x4548A777E84AECD7ULL,
		0x000000000AE58D3AULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x3CFB92AD6F603038ULL,
		0x84F6D69F63AFBE75ULL,
		0x8F225983E70EBEB3ULL,
		0x2C80202F98108229ULL,
		0x1BCB1E6793F325BEULL,
		0x8058025C7EE10198ULL,
		0x050C4BC14BB9C860ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE753CFB92AD6F6ULL,
		0xEBEB384F6D69F63AULL,
		0x082298F225983E70ULL,
		0x325BE2C80202F981ULL,
		0x101981BCB1E6793FULL,
		0x9C8608058025C7EEULL,
		0x00000050C4BC14BBULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xD9FC866FBC3FC93DULL,
		0xAD8F76D54693D83AULL,
		0xD1177E293F5FF8A6ULL,
		0x1E3A16CAE3D24F26ULL,
		0x9EBEBB2C3BE390D4ULL,
		0x37241499772FADF1ULL,
		0x887F72C78F16570DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB075B3F90CDF787FULL,
		0xF14D5B1EEDAA8D27ULL,
		0x9E4DA22EFC527EBFULL,
		0x21A83C742D95C7A4ULL,
		0x5BE33D7D765877C7ULL,
		0xAE1A6E482932EE5FULL,
		0x000110FEE58F1E2CULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xEEDDD74B86A38AE9ULL,
		0xAF7F8DD40DF9E45DULL,
		0x56DDAF74E79E956DULL,
		0x0DA21B0FCE3CE0DDULL,
		0x5B58AA6C2D09926AULL,
		0x15724C80D9E836A2ULL,
		0xE9A97FD3D4B9B688ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BB775D2E1A8E2BAULL,
		0x6BDFE375037E7917ULL,
		0x55B76BDD39E7A55BULL,
		0x836886C3F38F3837ULL,
		0x96D62A9B0B42649AULL,
		0x055C9320367A0DA8ULL,
		0x3A6A5FF4F52E6DA2ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xE14353DA42040774ULL,
		0xCD968B509B09C79BULL,
		0x6A607F301120AF2CULL,
		0xEC0F0FDA1CE29634ULL,
		0x06467DC882A8E2F1ULL,
		0x8F7DA6E5ECDFA7DBULL,
		0x6723A267727CFC3CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E3CDF0A1A9ED21ULL,
		0x90579666CB45A84DULL,
		0x714B1A35303F9808ULL,
		0x547178F60787ED0EULL,
		0x6FD3ED83233EE441ULL,
		0x3E7E1E47BED372F6ULL,
		0x0000003391D133B9ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xF0AE9A07B50C1FDCULL,
		0x824CCEC022671700ULL,
		0x74A0EB385F2AC806ULL,
		0xFB8CF88747254AAAULL,
		0x8578204882BC01EBULL,
		0x060B84D15628759FULL,
		0xE8740D4CD6B7D5CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044CE2E01E15D340ULL,
		0x0BE55900D04999D8ULL,
		0xE8E4A9554E941D67ULL,
		0x1057803D7F719F10ULL,
		0x2AC50EB3F0AF0409ULL,
		0x9AD6FAB9E0C1709AULL,
		0x000000001D0E81A9ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x02C855B6E69C36BFULL,
		0x492AF7D2162E9891ULL,
		0x9D8527F64258DF13ULL,
		0x8437FD8B511FCF81ULL,
		0xE395E92074747FFEULL,
		0xF0DE779D02C2A1CBULL,
		0xF71C616980853AEBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5D31220590AB6DCULL,
		0x4B1BE269255EFA42ULL,
		0x23F9F033B0A4FEC8ULL,
		0x8E8FFFD086FFB16AULL,
		0x5854397C72BD240EULL,
		0x10A75D7E1BCEF3A0ULL,
		0x0000001EE38C2D30ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x2027270C0512C610ULL,
		0x52C9594692170BA8ULL,
		0xDC1FC4B7A1374AEEULL,
		0xA7CE9E6718CEA278ULL,
		0xA1A322C29C4A2439ULL,
		0x1A2C139B811928A7ULL,
		0xDEA3B00AD4AC8FEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA3490B85D410139ULL,
		0x25BD09BA5772964AULL,
		0xF338C67513C6E0FEULL,
		0x1614E25121CD3E74ULL,
		0x9CDC08C9453D0D19ULL,
		0x8056A5647F70D160ULL,
		0x000000000006F51DULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x9195D360F6A2637AULL,
		0x8C43EAAE66762F6CULL,
		0x6E9FE2EA64C37B9FULL,
		0x30715565CF7F0699ULL,
		0xAE1A285B83253ACCULL,
		0x90F93EA86C83AFF5ULL,
		0x0233C7E1496AF1D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CCCEC5ED9232BA6ULL,
		0xD4C986F73F1887D5ULL,
		0xCB9EFE0D32DD3FC5ULL,
		0xB7064A759860E2AAULL,
		0x50D9075FEB5C3450ULL,
		0xC292D5E3B121F27DULL,
		0x000000000004678FULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xE07A63D807944EC0ULL,
		0xB46819BC7024F1AAULL,
		0x84710DD98A265B28ULL,
		0x0F157DD5B2024A7DULL,
		0xA7C6655A12AAA63FULL,
		0x886E248BEC86DD56ULL,
		0xD8D24499E4CC7249ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1AAE07A63D80794ULL,
		0x5B28B46819BC7024ULL,
		0x4A7D84710DD98A26ULL,
		0xA63F0F157DD5B202ULL,
		0xDD56A7C6655A12AAULL,
		0x7249886E248BEC86ULL,
		0x0000D8D24499E4CCULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xD796E364C7D4AEE4ULL,
		0xC86E7FA2B91F730CULL,
		0xE18A37A917CD9511ULL,
		0x56B7E782F28F6651ULL,
		0x348EFB512BA55B67ULL,
		0xE61EA0A84943AF73ULL,
		0x5EA959F944ED842CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45723EE619AF2DCULL,
		0xF522F9B2A2390DCFULL,
		0xF05E51ECCA3C3146ULL,
		0x6A2574AB6CEAD6FCULL,
		0x15092875EE6691DFULL,
		0x3F289DB0859CC3D4ULL,
		0x00000000000BD52BULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x4949B41CF9112907ULL,
		0xF204670497F15BF8ULL,
		0xBD495F927A39333AULL,
		0xE0771BE4B379F484ULL,
		0x606665474543ED58ULL,
		0x6C9393E21CAFF18BULL,
		0x3163C385B1302288ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFC24A4DA0E7C88ULL,
		0x999D790233824BF8ULL,
		0xFA425EA4AFC93D1CULL,
		0xF6AC703B8DF259BCULL,
		0xF8C5B03332A3A2A1ULL,
		0x11443649C9F10E57ULL,
		0x000018B1E1C2D898ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x3F68FF17B43F5658ULL,
		0x57C8CBABE0E05C88ULL,
		0x83D421B513D1732AULL,
		0x54BAB240EA01B10DULL,
		0xEDADAF930FE99132ULL,
		0xB8BCF918FB8629A0ULL,
		0x673CC0AA406DFECFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC883F68FF17B43F5ULL,
		0x32A57C8CBABE0E05ULL,
		0x10D83D421B513D17ULL,
		0x13254BAB240EA01BULL,
		0x9A0EDADAF930FE99ULL,
		0xECFB8BCF918FB862ULL,
		0x000673CC0AA406DFULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x343A62CA417D5C2FULL,
		0xDBB3211064D376A2ULL,
		0x87D72B5CB876BEDDULL,
		0xFF65278BCAB10BD5ULL,
		0xE7E12148CDCF8B75ULL,
		0x1BD0F944891829C5ULL,
		0x96D7FB7B77572A4EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A2343A62CA417D5ULL,
		0xEDDDBB3211064D37ULL,
		0xBD587D72B5CB876BULL,
		0xB75FF65278BCAB10ULL,
		0x9C5E7E12148CDCF8ULL,
		0xA4E1BD0F94489182ULL,
		0x00096D7FB7B77572ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xD65D2ABAFF5C8954ULL,
		0x66DD340B312A76C1ULL,
		0xFC40E15C6F8B7920ULL,
		0x303B4D699022A406ULL,
		0xFB8A368093CE2DE3ULL,
		0x57456BF06B30B924ULL,
		0x24047DB51EC48ED7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D65D2ABAFF5C89ULL,
		0x2066DD340B312A76ULL,
		0x06FC40E15C6F8B79ULL,
		0xE3303B4D699022A4ULL,
		0x24FB8A368093CE2DULL,
		0xD757456BF06B30B9ULL,
		0x0024047DB51EC48EULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xAA6417922BC2FED7ULL,
		0x66ECB8578E94CF2BULL,
		0x8C5A39C2212F9302ULL,
		0xE659173F775804D0ULL,
		0x1F12B8003530A40FULL,
		0x6F0364D1930BBDC3ULL,
		0x76D7596897CE03A5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15E3A533CAEA990ULL,
		0xE70884BE4C099BB2ULL,
		0x5CFDDD6013423168ULL,
		0xE000D4C2903F9964ULL,
		0x93464C2EF70C7C4AULL,
		0x65A25F380E95BC0DULL,
		0x000000000001DB5DULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xAFC87415B323ACA8ULL,
		0x9BA0ACCCE70C2BDFULL,
		0x575F6C3EF5BA3C9BULL,
		0x8677E320D9AD0F69ULL,
		0x3F065532797396E7ULL,
		0x24DC6F08E6EF0CCBULL,
		0xF4618F23E1AF52AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x615EFD7E43A0AD99ULL,
		0xD1E4DCDD05666738ULL,
		0x687B4ABAFB61F7ADULL,
		0x9CB73C33BF1906CDULL,
		0x786659F832A993CBULL,
		0x7A957126E3784737ULL,
		0x000007A30C791F0DULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x9CEE2CB88509719EULL,
		0x3EA1BE673852CA51ULL,
		0xA0CFDB2FB0B9FCCEULL,
		0x56B57713FE93A2E3ULL,
		0x6338ABBC9CEE3AD5ULL,
		0xF34D7517BCAA6319ULL,
		0x35A0B5CA16943B02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA519CEE2CB88509ULL,
		0xFCCE3EA1BE673852ULL,
		0xA2E3A0CFDB2FB0B9ULL,
		0x3AD556B57713FE93ULL,
		0x63196338ABBC9CEEULL,
		0x3B02F34D7517BCAAULL,
		0x000035A0B5CA1694ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x8E6BE2337BED961BULL,
		0x6F8EB9E7D2950891ULL,
		0x90EDDBCEA7FCC35AULL,
		0x4B6EC19A3F0C9004ULL,
		0x6BB8348BD77C1127ULL,
		0x545ED30F75F09DDAULL,
		0x58782143CFA9199CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448C735F119BDF6CULL,
		0x1AD37C75CF3E94A8ULL,
		0x8024876EDE753FE6ULL,
		0x893A5B760CD1F864ULL,
		0xEED35DC1A45EBBE0ULL,
		0xCCE2A2F6987BAF84ULL,
		0x0002C3C10A1E7D48ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x0C77B6913FDF7EBBULL,
		0x47E2F6EBE760F1D1ULL,
		0x2E123F348B496F74ULL,
		0x826D7C2BF2D770C5ULL,
		0xD9EB75ADBE788C80ULL,
		0xB4C1EBE339F75ACAULL,
		0x7E6670B1F07EACF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F3B078E8863BDB4ULL,
		0xA45A4B7BA23F17B7ULL,
		0x5F96BB86297091F9ULL,
		0x6DF3C46404136BE1ULL,
		0x19CFBAD656CF5BADULL,
		0x8F83F5679DA60F5FULL,
		0x0000000003F33385ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x6C110164530CCCA0ULL,
		0x51E16901412436CEULL,
		0x24E97E5ED436B774ULL,
		0x2C6954D6FD1C9C5AULL,
		0x89665197581C4056ULL,
		0x7245377D2FF977BAULL,
		0x0424B5AF9DC754C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36CE6C110164530CULL,
		0xB77451E169014124ULL,
		0x9C5A24E97E5ED436ULL,
		0x40562C6954D6FD1CULL,
		0x77BA89665197581CULL,
		0x54C87245377D2FF9ULL,
		0x00000424B5AF9DC7ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x791AE580AA86E52DULL,
		0x5BFC7E72E8B91A47ULL,
		0x85B16DB40360BAA9ULL,
		0x12A9FF2E870D8DEDULL,
		0xBDC293EC07D37241ULL,
		0xEA372FEDE8785C63ULL,
		0x2201336BC2DB60B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A47791AE580AA86ULL,
		0xBAA95BFC7E72E8B9ULL,
		0x8DED85B16DB40360ULL,
		0x724112A9FF2E870DULL,
		0x5C63BDC293EC07D3ULL,
		0x60B9EA372FEDE878ULL,
		0x00002201336BC2DBULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xD9D4516E58ADB97AULL,
		0x5E637A35FBEE21FCULL,
		0x4237B23F68DB0366ULL,
		0x4D7B79EDC7568104ULL,
		0x7DA3C0FAF08960E1ULL,
		0x8BA3C202286D4B58ULL,
		0x0CFF9B01B3D67032ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FCD9D4516E58ADULL,
		0x03665E637A35FBEEULL,
		0x81044237B23F68DBULL,
		0x60E14D7B79EDC756ULL,
		0x4B587DA3C0FAF089ULL,
		0x70328BA3C202286DULL,
		0x00000CFF9B01B3D6ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x288943185EEB6738ULL,
		0x02F42733010D3379ULL,
		0xC9421435095A22DCULL,
		0xE6957BFB8A69BFF9ULL,
		0xD69010490CB7790FULL,
		0x30930A27C35AC37CULL,
		0x86220CE3FA4ABBD2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A66F251128630BULL,
		0x2B445B805E84E660ULL,
		0x4D37FF39284286A1ULL,
		0x96EF21FCD2AF7F71ULL,
		0x6B586F9AD2020921ULL,
		0x49577A46126144F8ULL,
		0x00000010C4419C7FULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x8812BD060513372DULL,
		0x5217CDA791D284D7ULL,
		0xB532FCAC62933592ULL,
		0x54D8F86DAF884BD3ULL,
		0x6F9ABD2DD555267AULL,
		0x7C39513885E0F26AULL,
		0xAD8A804253A1D8B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A135E204AF4181ULL,
		0xA4CD649485F369E4ULL,
		0xE212F4ED4CBF2B18ULL,
		0x55499E95363E1B6BULL,
		0x783C9A9BE6AF4B75ULL,
		0xE8762CDF0E544E21ULL,
		0x0000002B62A01094ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x3AD04DE554CDF8CBULL,
		0x2D2C5D0BF7125FCAULL,
		0x2518FD390EB07FE7ULL,
		0x997B7DE50E0E1B3BULL,
		0xD0B8DDB681E69C19ULL,
		0x93CF11D51A8B7171ULL,
		0xCCD322318C571BEBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A58BA17EE24BF94ULL,
		0x4A31FA721D60FFCEULL,
		0x32F6FBCA1C1C3676ULL,
		0xA171BB6D03CD3833ULL,
		0x279E23AA3516E2E3ULL,
		0x99A6446318AE37D7ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x4D822257192857F9ULL,
		0xFAFDDFFFE2EC1733ULL,
		0x6C7187000CB503BEULL,
		0xE28C9C8863A47049ULL,
		0x56D5FB42C4C89A35ULL,
		0xE9C6651DC73603E3ULL,
		0x08B559F471259FF6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBBFFFC5D82E669ULL,
		0x8E30E00196A077DFULL,
		0x5193910C748E092DULL,
		0xDABF6858991346BCULL,
		0x38CCA3B8E6C07C6AULL,
		0x16AB3E8E24B3FEDDULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x4232C3ED378C63F9ULL,
		0x2790039BD7911098ULL,
		0x0C8E135B1FF43AF3ULL,
		0xFC6EC8DA1103EF1FULL,
		0xD8974DA2B45A1167ULL,
		0x92713FB1C8B6B795ULL,
		0xBFCFB16F5D9059CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E6F5E44426108CULL,
		0x84D6C7FD0EBCC9E4ULL,
		0xB2368440FBC7C323ULL,
		0xD368AD168459FF1BULL,
		0x4FEC722DADE57625ULL,
		0xEC5BD7641673649CULL,
		0x0000000000002FF3ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0xAC65337CF6D8B976ULL,
		0x12CD4F5437435FF9ULL,
		0x55687FE7C137F1BBULL,
		0xD9CD73261FF968FDULL,
		0x2F08AA568C4D1AE8ULL,
		0x19A448A7CA5B5B23ULL,
		0xE94CF42F7BF6442CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1AFFCD63299BE7ULL,
		0x09BF8DD8966A7AA1ULL,
		0xFFCB47EAAB43FF3EULL,
		0x6268D746CE6B9930ULL,
		0x52DAD919784552B4ULL,
		0xDFB22160CD22453EULL,
		0x000000074A67A17BULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x4997CA627B1AAF34ULL,
		0x99C155ED6581C28EULL,
		0xA8EB3AC60B725EAEULL,
		0xD5E78D585D5ACD40ULL,
		0x2979FEF897599A5CULL,
		0xA43695A2AB4FB07FULL,
		0x7786CEE0EF00010AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF6B2C0E14724CBEULL,
		0xD6305B92F574CE0AULL,
		0x6AC2EAD66A054759ULL,
		0xF7C4BACCD2E6AF3CULL,
		0xAD155A7D83F94BCFULL,
		0x77077800085521B4ULL,
		0x000000000003BC36ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xB079E30DAD502194ULL,
		0x20350088B620A81DULL,
		0xC2F902E9A22B607EULL,
		0xA3CA832D9F795B30ULL,
		0x3C161100B9FC5781ULL,
		0x44CE501A887A90A0ULL,
		0x4B022E969B4CAFBAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B620A81DB079E30ULL,
		0x9A22B607E2035008ULL,
		0xD9F795B30C2F902EULL,
		0x0B9FC5781A3CA832ULL,
		0xA887A90A03C16110ULL,
		0x69B4CAFBA44CE501ULL,
		0x0000000004B022E9ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xAE86D7F643D86011ULL,
		0xEF7C566EF165A1C3ULL,
		0xD6A926398088E0B1ULL,
		0x822AE63888678062ULL,
		0x96382CF6E0C3E430ULL,
		0x4EABA9ACE6482FA3ULL,
		0x554B7C9FFCD3016AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96870EBA1B5FD90FULL,
		0x2382C7BDF159BBC5ULL,
		0x9E018B5AA498E602ULL,
		0x0F90C208AB98E221ULL,
		0x20BE8E58E0B3DB83ULL,
		0x4C05A93AAEA6B399ULL,
		0x000001552DF27FF3ULL,
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
		0x09E1F09C6F5E1EDEULL,
		0x68D5E11420409E41ULL,
		0x44E17EA076C817BDULL,
		0x138A5A60F3B3F406ULL,
		0x2A499EED0498213DULL,
		0xA4D99011B8ABCCF7ULL,
		0xA90E299542A6027BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4109E1F09C6F5E1EULL,
		0xBD68D5E11420409EULL,
		0x0644E17EA076C817ULL,
		0x3D138A5A60F3B3F4ULL,
		0xF72A499EED049821ULL,
		0x7BA4D99011B8ABCCULL,
		0x00A90E299542A602ULL,
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
		0x17FDC228E31FDD9EULL,
		0x52B727B5535E84A2ULL,
		0x2F6C72D5FDC28465ULL,
		0x3F9A26BB85756698ULL,
		0xE7266E1C844033D0ULL,
		0x887201ACDB15C793ULL,
		0xD1F4CE3D8623AFF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ED54D7A12885FF7ULL,
		0xCB57F70A11954ADCULL,
		0x9AEE15D59A60BDB1ULL,
		0xB8721100CF40FE68ULL,
		0x06B36C571E4F9C99ULL,
		0x38F6188EBFE221C8ULL,
		0x00000000000347D3ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xBA01C8C104841CC4ULL,
		0xC451E67CA790CCB8ULL,
		0xE072AA8B6731615FULL,
		0x5B7F3D9B9856FC25ULL,
		0xCF5EF0626DDC70B9ULL,
		0xD8D6655D5EB7CCCFULL,
		0x8E739B225333EFBAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8665C5D00E4608ULL,
		0x398B0AFE228F33E5ULL,
		0xC2B7E12F0395545BULL,
		0x6EE385CADBF9ECDCULL,
		0xF5BE667E7AF78313ULL,
		0x999F7DD6C6B32AEAULL,
		0x00000004739CD912ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x6FFB9D85A350BD1DULL,
		0x030D75D5D7484408ULL,
		0xE5BD95D07AF355AFULL,
		0x256F829BC2426346ULL,
		0x4259D948DF18C455ULL,
		0xBF75005F951B0F17ULL,
		0xDBD2FEBADB599E58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74844086FFB9D85AULL,
		0xAF355AF030D75D5DULL,
		0x2426346E5BD95D07ULL,
		0xF18C455256F829BCULL,
		0x51B0F174259D948DULL,
		0xB599E58BF75005F9ULL,
		0x0000000DBD2FEBADULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0xBE11198A64370503ULL,
		0x8F6CB5344069C0E3ULL,
		0xF10EFDE3376A9DA1ULL,
		0x3B54AE398CF04BFBULL,
		0xB95FB47A812144CCULL,
		0xB414EC940F060D01ULL,
		0xC97384C6210C20B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2034E071DF088CCULL,
		0x19BB54ED0C7B65A9ULL,
		0xCC67825FDF8877EFULL,
		0xD4090A2661DAA571ULL,
		0xA07830680DCAFDA3ULL,
		0x31086105B5A0A764ULL,
		0x00000000064B9C26ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x494470FE1EF7AE0BULL,
		0x07AB025ECC2FA1F7ULL,
		0x2BE224CF1741FA34ULL,
		0xC17CE32566C8F35BULL,
		0xBABC875FB689D82EULL,
		0x41C13E2E9BFA426DULL,
		0xBC121F819EF5DED1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD985F43EE9288E1FULL,
		0xE2E83F4680F5604BULL,
		0xACD91E6B657C4499ULL,
		0xF6D13B05D82F9C64ULL,
		0xD37F484DB75790EBULL,
		0x33DEBBDA283827C5ULL,
		0x00000000178243F0ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x5AE17E6F1C5CE751ULL,
		0xC775B6AB975B4F0AULL,
		0x951ECC69A69E3B9DULL,
		0x227CF1709E5163A5ULL,
		0xFDCE8713A90EFAB0ULL,
		0xEBE7F6EC8EB1508DULL,
		0x39034E2A27E320B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC296B85F9BC71739ULL,
		0xE771DD6DAAE5D6D3ULL,
		0xE96547B31A69A78EULL,
		0xAC089F3C5C279458ULL,
		0x237F73A1C4EA43BEULL,
		0x2CFAF9FDBB23AC54ULL,
		0x000E40D38A89F8C8ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x27FDC6FEF50A2917ULL,
		0x79EC63B3657769BAULL,
		0xAD4772F9054DBD6DULL,
		0xF0B7114CB5574042ULL,
		0xA9D7C796CAD10673ULL,
		0x3B1D609662E6AF5CULL,
		0xA972E3AB3E2F7D13ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13FEE37F7A85148BULL,
		0xBCF631D9B2BBB4DDULL,
		0x56A3B97C82A6DEB6ULL,
		0xF85B88A65AABA021ULL,
		0x54EBE3CB65688339ULL,
		0x9D8EB04B317357AEULL,
		0x54B971D59F17BE89ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x0200AAF3A4E8A8C6ULL,
		0x499D57D861534BA9ULL,
		0x2A45993B5C3F0C03ULL,
		0x333DE5C5C0A0F72AULL,
		0x717910503039B730ULL,
		0xD49E2A0C854ED342ULL,
		0x9E02E13F792A8FB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F61854D2EA40802ULL,
		0x64ED70FC300D2675ULL,
		0x97170283DCA8A916ULL,
		0x4140C0E6DCC0CCF7ULL,
		0xA832153B4D09C5E4ULL,
		0x84FDE4AA3ECF5278ULL,
		0x000000000002780BULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x989741D84B66BCB6ULL,
		0x04358A8DAD449E6FULL,
		0x08515C0C14BA4A56ULL,
		0x766F8C18F1BCC3A0ULL,
		0x1217A0B68B7778FDULL,
		0xA1FF928995B0EC48ULL,
		0x9006803785015847ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x546D6A24F37CC4BAULL,
		0xE060A5D252B021ACULL,
		0x60C78DE61D00428AULL,
		0x05B45BBBC7EBB37CULL,
		0x944CAD87624090BDULL,
		0x01BC280AC23D0FFCULL,
		0x0000000000048034ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xFD95DF2AF900C427ULL,
		0x9F72B110BBC57FD4ULL,
		0x21540AA56624880DULL,
		0x8C76CBA8075606C9ULL,
		0x44DD87B1F87C09DBULL,
		0x1ECDF5B6E8FD04BDULL,
		0xAB2945CA0349D516ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF53F6577CABE403ULL,
		0x20367DCAC442EF15ULL,
		0x1B2485502A959892ULL,
		0x276E31DB2EA01D58ULL,
		0x12F513761EC7E1F0ULL,
		0x54587B37D6DBA3F4ULL,
		0x0002ACA517280D27ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x8E05EEA80B0E92E8ULL,
		0x134CC5217E3144E3ULL,
		0xF8E07130E8DF7ED6ULL,
		0xC38B28964AFBD4A8ULL,
		0xAB73B50549224895ULL,
		0x2E3E6386568A3DE9ULL,
		0xA6C62E9007878332ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144E38E05EEA80B0ULL,
		0xF7ED6134CC5217E3ULL,
		0xBD4A8F8E07130E8DULL,
		0x24895C38B28964AFULL,
		0xA3DE9AB73B505492ULL,
		0x783322E3E6386568ULL,
		0x00000A6C62E90078ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x1E39FFA7D0D9FBEFULL,
		0x89A0303A5EA2F4DDULL,
		0x2C6900391CBCB2D7ULL,
		0x5BFE762324DDA917ULL,
		0x4D07DECD831B384BULL,
		0x0B3477055D6F0E44ULL,
		0x52DFEB102FA91188ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1CFFD3E86CFDF7ULL,
		0xC4D0181D2F517A6EULL,
		0x9634801C8E5E596BULL,
		0xADFF3B11926ED48BULL,
		0x2683EF66C18D9C25ULL,
		0x059A3B82AEB78722ULL,
		0x296FF58817D488C4ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x4F77E189EA4DE225ULL,
		0xDB6175B6CE172C4BULL,
		0xEA20C95D78D20822ULL,
		0x1F24F82B64A53D52ULL,
		0xFC84C0F28D2A7567ULL,
		0x9E7FD2F3DB98D45CULL,
		0x75B54F34EAC25A84ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE172C4B4F77E189EULL,
		0x8D20822DB6175B6CULL,
		0x4A53D52EA20C95D7ULL,
		0xD2A75671F24F82B6ULL,
		0xB98D45CFC84C0F28ULL,
		0xAC25A849E7FD2F3DULL,
		0x000000075B54F34EULL,
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
		0xE63C06619E5B5EA7ULL,
		0x991A5D11BB7D14B8ULL,
		0x86E4CC951C2EDCDCULL,
		0x490562901910B892ULL,
		0xC83C3D472D5E626EULL,
		0x0E59B0E63C775CF8ULL,
		0xF169387C936A1779ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDBE8A5C731E0330ULL,
		0x8E176E6E4C8D2E88ULL,
		0x0C885C494372664AULL,
		0x96AF31372482B148ULL,
		0x1E3BAE7C641E1EA3ULL,
		0x49B50BBC872CD873ULL,
		0x0000000078B49C3EULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xADA398F60409F490ULL,
		0xE92490463DFD2076ULL,
		0xFF6D76956BF07AB4ULL,
		0x5B92BD40AC6A12B0ULL,
		0x02648B20CEC3C41FULL,
		0x4B1CF65ACA104F4AULL,
		0xDA89BEFE11A8FADAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4118F7F481DAB68EULL,
		0xDA55AFC1EAD3A492ULL,
		0xF502B1A84AC3FDB5ULL,
		0x2C833B0F107D6E4AULL,
		0xD96B28413D280992ULL,
		0xFBF846A3EB692C73ULL,
		0x0000000000036A26ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x6ECDCD78DEC658BFULL,
		0x6D9442CAED80CF88ULL,
		0x87C19F72F7331124ULL,
		0x39D130080D86001AULL,
		0x1C569824F9E6604BULL,
		0x4CD5E0C315D3B08BULL,
		0xB7C5B93EED2822ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC43766E6BC6F632CULL,
		0x9236CA216576C067ULL,
		0x0D43E0CFB97B9988ULL,
		0x259CE8980406C300ULL,
		0x458E2B4C127CF330ULL,
		0x56A66AF0618AE9D8ULL,
		0x005BE2DC9F769411ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0xB8C69298202AF7BBULL,
		0x8AA75DE73D5DBB26ULL,
		0xD66F6D9CA9CD6F28ULL,
		0x81EE0A2E5F3CEBE5ULL,
		0x9FD0DBEA9C743934ULL,
		0x4A1379CCD3E477F6ULL,
		0xB205833E83A8CD91ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26B8C69298202AF7ULL,
		0x288AA75DE73D5DBBULL,
		0xE5D66F6D9CA9CD6FULL,
		0x3481EE0A2E5F3CEBULL,
		0xF69FD0DBEA9C7439ULL,
		0x914A1379CCD3E477ULL,
		0x00B205833E83A8CDULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x110D2A90BE459473ULL,
		0x2C4A854CB7E3EFD7ULL,
		0x09EAAC1D5234FB10ULL,
		0x6B89103736DF44FEULL,
		0xADC070D7CE523451ULL,
		0x697D7E6BCC73C771ULL,
		0xD2562CB39BB49CF9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65BF1F7EB8886954ULL,
		0xEA91A7D88162542AULL,
		0xB9B6FA27F04F5560ULL,
		0xBE7291A28B5C4881ULL,
		0x5E639E3B8D6E0386ULL,
		0x9CDDA4E7CB4BEBF3ULL,
		0x000000000692B165ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x772527B392CC0D03ULL,
		0xA89E7266C674D13AULL,
		0xD54C517AEF2947BBULL,
		0x0F54C45DDAE25357ULL,
		0x8CD0A3CC0E96DEB3ULL,
		0x445BC607262179E5ULL,
		0x6194B2A1F041A402ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E7266C674D13A7ULL,
		0x54C517AEF2947BBAULL,
		0xF54C45DDAE25357DULL,
		0xCD0A3CC0E96DEB30ULL,
		0x45BC607262179E58ULL,
		0x194B2A1F041A4024ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x8C1C52C6AFFF3613ULL,
		0x20B5672DD367D481ULL,
		0x3D35F0F67AE89C0FULL,
		0xCFAF744D34585D82ULL,
		0x4D51392A6D0D9BB4ULL,
		0x0E3C017672BC3B09ULL,
		0xF041EEFFAE96F107ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA40C60E296357FULL,
		0x44E07905AB396E9BULL,
		0xC2EC11E9AF87B3D7ULL,
		0x6CDDA67D7BA269A2ULL,
		0xE1D84A6A89C95368ULL,
		0xB7883871E00BB395ULL,
		0x000007820F77FD74ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x0A653314B46CAD6FULL,
		0xDE10FEA102B591E3ULL,
		0x4AF25AE6A532305FULL,
		0xC4E03708C3C25513ULL,
		0xAF9AC43C629E44FAULL,
		0xBF24ADAE14D34F1AULL,
		0x9DC6D495C568A085ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8532998A5A3656B7ULL,
		0xEF087F50815AC8F1ULL,
		0xA5792D735299182FULL,
		0x62701B8461E12A89ULL,
		0x57CD621E314F227DULL,
		0xDF9256D70A69A78DULL,
		0x4EE36A4AE2B45042ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x8D3C11B96B419089ULL,
		0xDFA7B232CBE558CEULL,
		0x416B703596792668ULL,
		0x2B16FCA799CCB5B6ULL,
		0x474E23C3E1565A3EULL,
		0xBA89B8D127E209F7ULL,
		0xD5E9A9B59F6EA158ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB19D1A782372D68ULL,
		0x24CD1BF4F646597CULL,
		0x96B6C82D6E06B2CFULL,
		0xCB47C562DF94F339ULL,
		0x413EE8E9C4787C2AULL,
		0xD42B1751371A24FCULL,
		0x00001ABD3536B3EDULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x505F7819734DDCAAULL,
		0x235E9A1FF9348080ULL,
		0x764302A2CC5482FFULL,
		0x02240E64DE7165B4ULL,
		0x248DF7ADE5E0DBA6ULL,
		0x5698A99323510A7BULL,
		0xDB7CDF384DF175A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040282FBC0CB9A6EULL,
		0x17F91AF4D0FFC9A4ULL,
		0x2DA3B218151662A4ULL,
		0xDD3011207326F38BULL,
		0x53D9246FBD6F2F06ULL,
		0xAD02B4C54C991A88ULL,
		0x0006DBE6F9C26F8BULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x47EC8C76592B9FB6ULL,
		0x166FFC127F13DCBFULL,
		0x5BF4A543CDAD1EFBULL,
		0x287966B5EC387B5EULL,
		0x816CC9CDF4107797ULL,
		0x373E2D81A5BED7FFULL,
		0x0410F66EFE365C9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E8FD918ECB2573ULL,
		0xDF62CDFF824FE27BULL,
		0x6BCB7E94A879B5A3ULL,
		0xF2E50F2CD6BD870FULL,
		0xFFF02D9939BE820EULL,
		0x9386E7C5B034B7DAULL,
		0x0000821ECDDFC6CBULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x5CF6ACEAAFCB69EFULL,
		0xEC16A8BA94659BFAULL,
		0x0E7F4EF968B84D6BULL,
		0xB43AE0309EE1BBEAULL,
		0x029D9A55CC3F4822ULL,
		0x17879D543317C147ULL,
		0x5C3BD5AD10CEB110ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB37F4B9ED59D55FULL,
		0x709AD7D82D517528ULL,
		0xC377D41CFE9DF2D1ULL,
		0x7E90456875C0613DULL,
		0x2F828E053B34AB98ULL,
		0x9D62202F0F3AA866ULL,
		0x000000B877AB5A21ULL,
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
		0xE6AC304FC4EA11A9ULL,
		0xE0088EE257A1B596ULL,
		0x77EC33A1DEB0623AULL,
		0xA923517BFFE1ED29ULL,
		0x74870A9D850B7E49ULL,
		0x77B3CBB99CCEF10AULL,
		0x710167C1EA6DF79CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0111DC4AF436B2DULL,
		0xEFD86743BD60C475ULL,
		0x5246A2F7FFC3DA52ULL,
		0xE90E153B0A16FC93ULL,
		0xEF679773399DE214ULL,
		0xE202CF83D4DBEF38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x82FA04DCFEE46B62ULL,
		0x54629D0AA5AD5F21ULL,
		0x65F1190486214309ULL,
		0xB79FDEF821F514CBULL,
		0x93B917FC05C28ED7ULL,
		0xEEF80A022088368EULL,
		0x9C8EA58042792468ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA314E8552D6AF90CULL,
		0x2F88C824310A184AULL,
		0xBCFEF7C10FA8A65BULL,
		0x9DC8BFE02E1476BDULL,
		0x77C050110441B474ULL,
		0xE4752C0213C92347ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x1A0DA4404F68B8F8ULL,
		0x9EA35029A38CCF0CULL,
		0xF25B9A242985F00DULL,
		0x72B428ECB277B42BULL,
		0xEF4008E0B2E0DCFEULL,
		0x666ACD098AC95647ULL,
		0xE8D9EC7D57D88BF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A0DA4404F68B8FULL,
		0xD9EA35029A38CCF0ULL,
		0xBF25B9A242985F00ULL,
		0xE72B428ECB277B42ULL,
		0x7EF4008E0B2E0DCFULL,
		0x5666ACD098AC9564ULL,
		0x0E8D9EC7D57D88BFULL,
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
		0x1CB949B0131FBBD4ULL,
		0x2AC1D606C7AC00CBULL,
		0xD9D18F34C8FF55C1ULL,
		0xAAE7A16559AAA5A1ULL,
		0xC85475254711DF8BULL,
		0xFF361DAE34F1E626ULL,
		0x72AF1559D53ED29CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D600658E5CA4D8ULL,
		0x647FAAE09560EB03ULL,
		0xACD552D0ECE8C79AULL,
		0xA388EFC5D573D0B2ULL,
		0x1A78F313642A3A92ULL,
		0xEA9F694E7F9B0ED7ULL,
		0x0000000039578AACULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xA21B6D3CC9B281BCULL,
		0xD6B5AF01CB03450AULL,
		0xF27D7335589E51B9ULL,
		0x62352ACA50CB5943ULL,
		0xFCBF51CCA8248DA8ULL,
		0x3AC90F6DF5002387ULL,
		0x9D2B3567AE76B430ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD780E581A285510DULL,
		0xB99AAC4F28DCEB5AULL,
		0x95652865ACA1F93EULL,
		0xA8E6541246D4311AULL,
		0x87B6FA8011C3FE5FULL,
		0x9AB3D73B5A181D64ULL,
		0x0000000000004E95ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0xC1E2FC82D458FBB4ULL,
		0x5D8B2ABE5ACEF03BULL,
		0xD3B6216405EDFD86ULL,
		0x98D8FA4749355953ULL,
		0x94C24B2BE534C68AULL,
		0xEB75A5330BCB3121ULL,
		0x03CD3D33FAF7ACE2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC0EF078BF20B516ULL,
		0x7F619762CAAF96B3ULL,
		0x5654F4ED8859017BULL,
		0x31A2A6363E91D24DULL,
		0xCC48653092CAF94DULL,
		0xEB38BADD694CC2F2ULL,
		0x000000F34F4CFEBDULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xEB52F40342A436FFULL,
		0x25B1EA45AD75314DULL,
		0x23DBDE6DBA8B44A4ULL,
		0xCBFEFC7BCAD05E72ULL,
		0xB0595A0853E69573ULL,
		0x3E54731F85E8B135ULL,
		0x8764AACC73279D59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522D6BA98A6F5A97ULL,
		0xF36DD45A25212D8FULL,
		0xE3DE5682F3911EDEULL,
		0xD0429F34AB9E5FF7ULL,
		0x98FC2F4589AD82CAULL,
		0x5663993CEAC9F2A3ULL,
		0x0000000000043B25ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xA2F377A82E23CF62ULL,
		0x2B2080588EA69758ULL,
		0xF3CCF503DF8AD0A9ULL,
		0x3777276BC6955E25ULL,
		0x6027461269CD15FDULL,
		0x81B4AD8614620DDFULL,
		0x67B4BA7C46BD375BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5D628BCDDEA0B8ULL,
		0x2B42A4AC8201623AULL,
		0x557897CF33D40F7EULL,
		0x3457F4DDDC9DAF1AULL,
		0x88377D809D1849A7ULL,
		0xF4DD6E06D2B61851ULL,
		0x0000019ED2E9F11AULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0x156D56C306F00438ULL,
		0xDA64800DD2566789ULL,
		0x8877DEFBFBB4BFE2ULL,
		0x3C35FFC2332997B0ULL,
		0xF2373227F9C527C7ULL,
		0x00500BCAAECEF8EDULL,
		0x8E2367C633A0AD8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4800DD2566789156ULL,
		0x7DEFBFBB4BFE2DA6ULL,
		0x5FFC2332997B0887ULL,
		0x73227F9C527C73C3ULL,
		0x00BCAAECEF8EDF23ULL,
		0x367C633A0AD8A005ULL,
		0x00000000000008E2ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x205DC689FE85625FULL,
		0x9BDDF420CA2F600BULL,
		0xB64A355501407715ULL,
		0x5DACEFD1A8E540E2ULL,
		0xE8154D58F35FDF99ULL,
		0x2FA5DE33B935FB6BULL,
		0x75D12185DCAEF606ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEFA106517B00590ULL,
		0x251AAA80A03B8ACDULL,
		0xD677E8D472A0715BULL,
		0x0AA6AC79AFEFCCAEULL,
		0xD2EF19DC9AFDB5F4ULL,
		0xE890C2EE577B0317ULL,
		0x000000000000003AULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x79B714859888E449ULL,
		0xDE4C65A211C46C4EULL,
		0x9065A4F5F531FE87ULL,
		0x2AAFEA2E435E7A88ULL,
		0x38D7461B841B7A45ULL,
		0x09476512E080A5AEULL,
		0x0B6A0A62E9467111ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4711B139E6DC5216ULL,
		0xD4C7FA1F79319688ULL,
		0x0D79EA22419693D7ULL,
		0x106DE914AABFA8B9ULL,
		0x820296B8E35D186EULL,
		0xA519C444251D944BULL,
		0x000000002DA8298BULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x0BCB1085B8AACFFFULL,
		0xCD3E354D7B93FF84ULL,
		0x4BF5B12AB7C940ECULL,
		0x93B91639B91B1D72ULL,
		0x5D5F7D2C68859480ULL,
		0xC1882EC51D67EF72ULL,
		0xBB85955E649C4D88ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1AA6BDC9FFC205ULL,
		0xFAD8955BE4A07666ULL,
		0xDC8B1CDC8D8EB925ULL,
		0xAFBE963442CA4049ULL,
		0xC417628EB3F7B92EULL,
		0xC2CAAF324E26C460ULL,
		0x000000000000005DULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0xD81034D705CE71EEULL,
		0xEC09B2D13C28DB9CULL,
		0xA38BC5DB50EA1D81ULL,
		0x4F4276945B879BB7ULL,
		0x32E9920851FF4E7CULL,
		0x791AA02F181E84B0ULL,
		0xC2CDB12782C882CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x604D9689E146DCE6ULL,
		0x1C5E2EDA8750EC0FULL,
		0x7A13B4A2DC3CDDBDULL,
		0x974C90428FFA73E2ULL,
		0xC8D50178C0F42581ULL,
		0x166D893C1644167BULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x9D201D2BFA2E3913ULL,
		0xD285EC2C82A58783ULL,
		0x8FE810EC6F254E1EULL,
		0x789140AB8F2E972CULL,
		0x82F75949E4D1FEFDULL,
		0x81F34BB6430855EEULL,
		0xE3EE350BC3AAC8DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D201D2BFA2E391ULL,
		0xED285EC2C82A5878ULL,
		0xC8FE810EC6F254E1ULL,
		0xD789140AB8F2E972ULL,
		0xE82F75949E4D1FEFULL,
		0xC81F34BB6430855EULL,
		0x0E3EE350BC3AAC8DULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x6A831C85B3F1D09AULL,
		0x28594B09E62E7871ULL,
		0x246C475B87709064ULL,
		0x7ECEC5A27DD92507ULL,
		0x4B3356D57A512E2BULL,
		0xC7A192C790F29167ULL,
		0xC8C8A430EBBA2A65ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5CF0E2D506390B6ULL,
		0xEE120C850B29613CULL,
		0xBB24A0E48D88EB70ULL,
		0x4A25C56FD9D8B44FULL,
		0x1E522CE9666ADAAFULL,
		0x77454CB8F43258F2ULL,
		0x000000191914861DULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0xB2FC410480A68F09ULL,
		0xBD52F4359CD47DFDULL,
		0xF2095072F8EFCBF1ULL,
		0xF946333D4B397F96ULL,
		0x85342C11F9E60BBCULL,
		0xC07D291D60063D3AULL,
		0x020059B69F77709CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACE6A3EFED97E20ULL,
		0x397C77E5F8DEA97AULL,
		0x9EA59CBFCB7904A8ULL,
		0x08FCF305DE7CA319ULL,
		0x8EB0031E9D429A16ULL,
		0xDB4FBBB84E603E94ULL,
		0x000000000001002CULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x2E811DB83E913553ULL,
		0x61C54A8040B0BBC6ULL,
		0x9DE0646AF733FF77ULL,
		0x5AFCC845FE523D67ULL,
		0x32405BCB9EBF6B56ULL,
		0x2A28B6A19ABDED13ULL,
		0x6AE17A4D1193C85FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18BA0476E0FA44D5ULL,
		0xDD87152A0102C2EFULL,
		0x9E778191ABDCCFFDULL,
		0x596BF32117F948F5ULL,
		0x4CC9016F2E7AFDADULL,
		0x7CA8A2DA866AF7B4ULL,
		0x01AB85E934464F21ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0xC7ACC5A0494D3AAFULL,
		0x85D94F66DE40AA8BULL,
		0xD571071062B65C2AULL,
		0x969EC629C0EC7060ULL,
		0x2D58A1FFC9E31B34ULL,
		0xCE150048747954AFULL,
		0x2C3D0CCF53692259ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB36F205545E3D662ULL,
		0x88315B2E1542ECA7ULL,
		0x14E07638306AB883ULL,
		0xFFE4F18D9A4B4F63ULL,
		0x243A3CAA5796AC50ULL,
		0x67A9B4912CE70A80ULL,
		0x0000000000161E86ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xF7359674DB0557F3ULL,
		0xF7418BEFBFD84A97ULL,
		0x49F0331F50D6711AULL,
		0x6C319D9A6679C607ULL,
		0xB1346131B7487AA2ULL,
		0x0D00F1D9CC70DD51ULL,
		0x2E9468142F76F984ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB0952FEE6B2CE9ULL,
		0xA1ACE235EE8317DFULL,
		0xCCF38C0E93E0663EULL,
		0x6E90F544D8633B34ULL,
		0x98E1BAA36268C263ULL,
		0x5EEDF3081A01E3B3ULL,
		0x000000005D28D028ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x6C697F3DEA7415A7ULL,
		0x414DF5AC33C2949AULL,
		0x7AF5E1492FB52068ULL,
		0xC0A19AC8A2DF556DULL,
		0x5C40215EB0820949ULL,
		0xB1DB3071669E6E17ULL,
		0xFCA1238521A0109FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6B0CF0A5269B1AULL,
		0x78524BED481A1053ULL,
		0x66B228B7D55B5EBDULL,
		0x0857AC2082527028ULL,
		0xCC1C59A79B85D710ULL,
		0x48E148680427EC76ULL,
		0x0000000000003F28ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x39DADCC5F80DEC06ULL,
		0xC05FB6F26F478CA7ULL,
		0x8E3BD6FE40BD8C22ULL,
		0x9A216558C71ADC75ULL,
		0x79DC99E567CA74E5ULL,
		0xF43B3B9499A5438CULL,
		0xC04623007C95BF5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBC9BD1E329CE76ULL,
		0xF5BF902F6308B017ULL,
		0x595631C6B71D638EULL,
		0x267959F29D396688ULL,
		0xCEE5266950E31E77ULL,
		0x88C01F256FD6FD0EULL,
		0x0000000000003011ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x5F2AF4664646A23AULL,
		0x3FFC5D81A7AC26D6ULL,
		0x98460868B7016E8FULL,
		0xE1612950629CA9A3ULL,
		0xD69D305270C6308FULL,
		0xB6F115EE7BC7DC2CULL,
		0xCBF36A3006FCA44DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B597CABD199191AULL,
		0xBA3CFFF176069EB0ULL,
		0xA68E611821A2DC05ULL,
		0xC23F8584A5418A72ULL,
		0x70B35A74C149C318ULL,
		0x9136DBC457B9EF1FULL,
		0x00032FCDA8C01BF2ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xD0B0EC27174F4273ULL,
		0x00A047708D465368ULL,
		0xAA6D1802DFD74231ULL,
		0x386BAE45CFC58F87ULL,
		0xE742C9606AF062EEULL,
		0xCB02D39E97C0D9DAULL,
		0x2E5FEC15FDFCF12FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D0B0EC27174F42ULL,
		0x3100A047708D4653ULL,
		0x87AA6D1802DFD742ULL,
		0xEE386BAE45CFC58FULL,
		0xDAE742C9606AF062ULL,
		0x2FCB02D39E97C0D9ULL,
		0x002E5FEC15FDFCF1ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x4BC91FE9D99625B8ULL,
		0xECA3089E9F494FBDULL,
		0xD0069F08A67E25F6ULL,
		0x4DCB0CB75D8C95BFULL,
		0x768C5B42B1836645ULL,
		0x81A98BA53109A082ULL,
		0x9F7E101A56EEC389ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4BC91FE9D99625BULL,
		0x6ECA3089E9F494FBULL,
		0xFD0069F08A67E25FULL,
		0x54DCB0CB75D8C95BULL,
		0x2768C5B42B183664ULL,
		0x981A98BA53109A08ULL,
		0x09F7E101A56EEC38ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xB18E4B4353FE4486ULL,
		0x0997865921607FAFULL,
		0x28AE44635697A9EDULL,
		0x480FF56B2279A42CULL,
		0x3C72ABEAD8416F8DULL,
		0xC1E0E3FA12A2B28CULL,
		0x45D26273891F9B2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07FAFB18E4B4353FULL,
		0x7A9ED09978659216ULL,
		0x9A42C28AE4463569ULL,
		0x16F8D480FF56B227ULL,
		0x2B28C3C72ABEAD84ULL,
		0xF9B2CC1E0E3FA12AULL,
		0x0000045D26273891ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x5EF82F6D9AFDE09CULL,
		0xB714B36E81AA3BC1ULL,
		0x0CC23D5DD604AE4EULL,
		0x073CD7216EEB2C03ULL,
		0xBE90FB89DE57DA28ULL,
		0x029D14F01CA58623ULL,
		0x2B3AA443A83927A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC15EF82F6D9AFDULL,
		0xAE4EB714B36E81AAULL,
		0x2C030CC23D5DD604ULL,
		0xDA28073CD7216EEBULL,
		0x8623BE90FB89DE57ULL,
		0x27A2029D14F01CA5ULL,
		0x00002B3AA443A839ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x42D1C2CD107FA0B2ULL,
		0x131EF225F686FC32ULL,
		0x3A74838120926A11ULL,
		0x40011A23166A6548ULL,
		0xC1AB7A44AA03E216ULL,
		0xB3411BAB1E84CE10ULL,
		0x59454A45261A0B8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DE44BED0DF8648ULL,
		0x4E907024124D4222ULL,
		0x00234462CD4CA907ULL,
		0x356F4895407C42C8ULL,
		0x68237563D099C218ULL,
		0x28A948A4C34171F6ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xF57285E9ADC7BB97ULL,
		0x96F1FBB067A9156AULL,
		0xA36762855927E4EEULL,
		0xDE155752F37CC7C6ULL,
		0x1A607AF68C641822ULL,
		0xA584FB3F718C4F49ULL,
		0x5E084DA9A4CE9789ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5EAE50BD35B8F7ULL,
		0x9DD2DE3F760CF522ULL,
		0xF8D46CEC50AB24FCULL,
		0x045BC2AAEA5E6F98ULL,
		0xE9234C0F5ED18C83ULL,
		0xF134B09F67EE3189ULL,
		0x000BC109B53499D2ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x24FCFA774A109A25ULL,
		0x6E01FB83F6C3896DULL,
		0x844B080C15228822ULL,
		0xBDA5BA1F99ED1596ULL,
		0xCEE924FBD7C27241ULL,
		0x520442E50F0EB2FFULL,
		0x5969AEB4ED025DCCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1FB61C4B6927E7ULL,
		0x4060A9144113700FULL,
		0xD0FCCF68ACB42258ULL,
		0x27DEBE13920DED2DULL,
		0x1728787597FE7749ULL,
		0x75A76812EE629022ULL,
		0x000000000002CB4DULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x04D146076D851A35ULL,
		0xB3BD75B0CC5CC1EBULL,
		0x34039761C2CAE6E1ULL,
		0x2C69820D588A290CULL,
		0xEE083830CE86861EULL,
		0xF35D1A1B06689324ULL,
		0xC11C8FA0F1E30968ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x662E60F58268A303ULL,
		0xE1657370D9DEBAD8ULL,
		0xAC4514861A01CBB0ULL,
		0x6743430F1634C106ULL,
		0x8334499277041C18ULL,
		0x78F184B479AE8D0DULL,
		0x00000000608E47D0ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xA29605D3F503E1CFULL,
		0x30AE0650FC124283ULL,
		0x331FBAF63D486E35ULL,
		0xD963932DDFE5C717ULL,
		0x9D4C40E5D304387FULL,
		0x30F2FF41E90FFB82ULL,
		0x2F0E1B0EACAF8855ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA1F8248507452C0ULL,
		0x5EC7A90DC6A615C0ULL,
		0x65BBFCB8E2E663F7ULL,
		0x1CBA60870FFB2C72ULL,
		0xE83D21FF7053A988ULL,
		0x61D595F10AA61E5FULL,
		0x000000000005E1C3ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x3599262C64A1FD65ULL,
		0x49D6E79326D49AF3ULL,
		0x74C6F4CA4C34CB75ULL,
		0x36E1FC82C12510DDULL,
		0x29F464B041D03A7CULL,
		0x41BBE9C5700330DFULL,
		0x93D2BAA878860FEFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF33599262C64A1FDULL,
		0x7549D6E79326D49AULL,
		0xDD74C6F4CA4C34CBULL,
		0x7C36E1FC82C12510ULL,
		0xDF29F464B041D03AULL,
		0xEF41BBE9C5700330ULL,
		0x0093D2BAA878860FULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x42408255AAC181AAULL,
		0x155DF03AA213E505ULL,
		0xA8A748DFB29C1669ULL,
		0xB0AC35363E1E5A7CULL,
		0x1457EFF20BC7E0F1ULL,
		0xC2A08B5364BEF0C5ULL,
		0x359B78A932CECCE5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x941509020956AB06ULL,
		0x59A45577C0EA884FULL,
		0x69F2A29D237ECA70ULL,
		0x83C6C2B0D4D8F879ULL,
		0xC314515FBFC82F1FULL,
		0x33970A822D4D92FBULL,
		0x0000D66DE2A4CB3BULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xEA9051AE1BD7D6A5ULL,
		0xF711D6D425CF0C96ULL,
		0x81A299F412DD3497ULL,
		0x3BFD441A852D319EULL,
		0x297CB07AB2871A18ULL,
		0x089C3358FD316768ULL,
		0xCDCC09F2CB069FDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BAA4146B86F5F5AULL,
		0x5FDC475B50973C32ULL,
		0x7A068A67D04B74D2ULL,
		0x60EFF5106A14B4C6ULL,
		0xA0A5F2C1EACA1C68ULL,
		0x6C2270CD63F4C59DULL,
		0x03373027CB2C1A7FULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x96E75507A9F03BA9ULL,
		0x8367FDC7930E08C3ULL,
		0x4E7E04E2A27E3880ULL,
		0x7560637C4F0EC2ABULL,
		0xB331624F81331A80ULL,
		0xB1DC2DCB3BD7920AULL,
		0xB35D9EB5D213FD12ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11872DCEAA0F53EULL,
		0xC710106CFFB8F261ULL,
		0xD85569CFC09C544FULL,
		0x63500EAC0C6F89E1ULL,
		0xF24156662C49F026ULL,
		0x7FA2563B85B9677AULL,
		0x0000166BB3D6BA42ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x5D18C2CF443D61AFULL,
		0x8466B375A73E1D7AULL,
		0x9144BDA4B08DED3FULL,
		0x4C50A9225D4B9A8BULL,
		0xFB4E780B2CB67144ULL,
		0xC34CC011F406AC77ULL,
		0xEEC962003161BE2AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69CF875E974630B3ULL,
		0x2C237B4FE119ACDDULL,
		0x9752E6A2E4512F69ULL,
		0xCB2D9C5113142A48ULL,
		0x7D01AB1DFED39E02ULL,
		0x0C586F8AB0D33004ULL,
		0x000000003BB25880ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x4847528147148A10ULL,
		0x710D80A733E18027ULL,
		0xECF621BBD2439A6EULL,
		0x9BB0921B7DAC19F5ULL,
		0xDB4298DAD228A5CFULL,
		0xB540641E8CF3C533ULL,
		0x77F8B4941535F6E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5399F0C013A423A9ULL,
		0xDDE921CD373886C0ULL,
		0x0DBED60CFAF67B10ULL,
		0x6D691452E7CDD849ULL,
		0x0F4679E299EDA14CULL,
		0x4A0A9AFB70DAA032ULL,
		0x00000000003BFC5AULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xC38F836DB79E0A12ULL,
		0xAEC5DC051CA89B85ULL,
		0x4D58B9F8FA2769A8ULL,
		0xBABB125EE78C3BBEULL,
		0xE4E4FB96614562DFULL,
		0x0FD16F8A3BB5AA06ULL,
		0x6DB4A3031228D6A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2E1C7C1B6DBCF0ULL,
		0x4D45762EE028E544ULL,
		0xDDF26AC5CFC7D13BULL,
		0x16FDD5D892F73C61ULL,
		0x50372727DCB30A2BULL,
		0xB5387E8B7C51DDADULL,
		0x00036DA518189146ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xA81A99F0058BAF4DULL,
		0xF4D63F48B870A812ULL,
		0x1B397AD7314CA448ULL,
		0xBDDDA47888B4670EULL,
		0x3317D5C1C847AA4CULL,
		0xDD6352E37817659EULL,
		0x6F6A6B70F8B51D44ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E1C2A04AA06A67CULL,
		0xCC5329123D358FD2ULL,
		0x222D19C386CE5EB5ULL,
		0x7211EA932F77691EULL,
		0xDE05D9678CC5F570ULL,
		0x3E2D47513758D4B8ULL,
		0x000000001BDA9ADCULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xBB63FAE6DF928B9EULL,
		0x4716DCC5261B1CA3ULL,
		0x6C872843373A6717ULL,
		0x2891FB8AE669E9AFULL,
		0xF77AE18314ECB8F8ULL,
		0x1CD9412E28160313ULL,
		0x978D15E9034F9477ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED8FEB9B7E4A2E7ULL,
		0xD1C5B7314986C728ULL,
		0xDB21CA10CDCE99C5ULL,
		0x0A247EE2B99A7A6BULL,
		0xFDDEB860C53B2E3EULL,
		0xC736504B8A0580C4ULL,
		0x25E3457A40D3E51DULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x3B1264D87087FBAAULL,
		0x2EAF170C6311FE7DULL,
		0xA7905C660A3ED3FCULL,
		0x18F851A269099240ULL,
		0x941E8479C4934385ULL,
		0x9E4FEC118CB45EEEULL,
		0x2442B8BE1F9CE546ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE7D3B1264D87087ULL,
		0xD3FC2EAF170C6311ULL,
		0x9240A7905C660A3EULL,
		0x438518F851A26909ULL,
		0x5EEE941E8479C493ULL,
		0xE5469E4FEC118CB4ULL,
		0x00002442B8BE1F9CULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x0761374344B0D98EULL,
		0x92494EE89D908459ULL,
		0x9ABCEC69DEF4278AULL,
		0x16F0613878DFA977ULL,
		0x998BF5FCA023014AULL,
		0x51196389A64E5067ULL,
		0x5053EAB56F159BB7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24A7744EC8422C83ULL,
		0x5E7634EF7A13C549ULL,
		0x78309C3C6FD4BBCDULL,
		0xC5FAFE501180A50BULL,
		0x8CB1C4D3272833CCULL,
		0x29F55AB78ACDDBA8ULL,
		0x0000000000000028ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0xCABD24CD41CAC6F9ULL,
		0x9B1F03680A63EF9EULL,
		0x1E07568F896A2C56ULL,
		0x8F082DF5D3F6452FULL,
		0x19EEF59EDE4CFC07ULL,
		0xC29F3CF2BD109054ULL,
		0x6845A82377F0B2ECULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655E9266A0E5637CULL,
		0x4D8F81B40531F7CFULL,
		0x8F03AB47C4B5162BULL,
		0xC78416FAE9FB2297ULL,
		0x0CF77ACF6F267E03ULL,
		0x614F9E795E88482AULL,
		0x3422D411BBF85976ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x82973A61D28B886CULL,
		0x13283DDC80E31DF3ULL,
		0xF072ECD9392B5773ULL,
		0x566271A98390CF9AULL,
		0x082E38006D9008EBULL,
		0xDA124FD41DEF578DULL,
		0x2A987532A0BCEDDDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E31DF382973A61DULL,
		0x92B577313283DDC8ULL,
		0x390CF9AF072ECD93ULL,
		0xD9008EB566271A98ULL,
		0xDEF578D082E38006ULL,
		0x0BCEDDDDA124FD41ULL,
		0x00000002A987532AULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x58A6FDDB5F5D3032ULL,
		0x12D86DF321846D86ULL,
		0xE85CB78F98C6BBB9ULL,
		0x3F74AC03C28BF146ULL,
		0x9FF8C940F9724049ULL,
		0x48FB80897E6092C4ULL,
		0x659ADB01D409ACB8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C32C537EEDAFAE9ULL,
		0xDDC896C36F990C23ULL,
		0x8A3742E5BC7CC635ULL,
		0x0249FBA5601E145FULL,
		0x9624FFC64A07CB92ULL,
		0x65C247DC044BF304ULL,
		0x00032CD6D80EA04DULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xC947BDDA1B2F2C31ULL,
		0x980B7EC8AA147828ULL,
		0xC72E1C30F94EBA34ULL,
		0x23281EB9C499BDACULL,
		0x3536CDCF10A7FAAFULL,
		0xF6857036FD2317BDULL,
		0x01F1DC0323012747ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B7EC8AA147828CULL,
		0x72E1C30F94EBA349ULL,
		0x3281EB9C499BDACCULL,
		0x536CDCF10A7FAAF2ULL,
		0x6857036FD2317BD3ULL,
		0x1F1DC0323012747FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x279D10EF47CB89E6ULL,
		0x54522B05E5C9E150ULL,
		0x64796E60BC606EE5ULL,
		0x58AF7605A0945715ULL,
		0x2CC52C1AAC86AAE3ULL,
		0x6287DD10579F45CAULL,
		0x5FF4708891F21024ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB93C2A04F3A21DEULL,
		0x78C0DDCAA8A4560BULL,
		0x4128AE2AC8F2DCC1ULL,
		0x590D55C6B15EEC0BULL,
		0xAF3E8B94598A5835ULL,
		0x23E42048C50FBA20ULL,
		0x00000000BFE8E111ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x66CAF5310479C5C1ULL,
		0xA96D124AA3D966C0ULL,
		0x5B78D1A29B6A2CE1ULL,
		0x66AAFC6C65FEA876ULL,
		0x23190CEBD6829803ULL,
		0xA9AFCD93A4B831B3ULL,
		0x0AA94D901F0A20E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x966C066CAF531047ULL,
		0xA2CE1A96D124AA3DULL,
		0xEA8765B78D1A29B6ULL,
		0x2980366AAFC6C65FULL,
		0x831B323190CEBD68ULL,
		0xA20E0A9AFCD93A4BULL,
		0x000000AA94D901F0ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x237F53E4EA8C44AEULL,
		0xF6C06EE0AE17E067ULL,
		0xAE764892CC02478BULL,
		0x618411C69C576864ULL,
		0x3DA04A426ADB3D1FULL,
		0x8FD2CFE750341B1BULL,
		0xAF24037242E1045FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70570BF03391BFA9ULL,
		0x49660123C5FB6037ULL,
		0xE34E2BB432573B24ULL,
		0x21356D9E8FB0C208ULL,
		0xF3A81A0D8D9ED025ULL,
		0xB92170822FC7E967ULL,
		0x0000000000579201ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x9EFBA61C3D1AB775ULL,
		0xF88EA701E2DF305FULL,
		0xD5E63704C27D8DB4ULL,
		0xA0DF58FB0D75EF08ULL,
		0x4B467CFD1543033CULL,
		0x6D363EC087864293ULL,
		0x5036A5FEC83D6A7DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC17E7BEE9870F46AULL,
		0x36D3E23A9C078B7CULL,
		0xBC235798DC1309F6ULL,
		0x0CF2837D63EC35D7ULL,
		0x0A4D2D19F3F4550CULL,
		0xA9F5B4D8FB021E19ULL,
		0x000140DA97FB20F5ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x348E5C3E13E614ADULL,
		0x10985EEF18AD1155ULL,
		0x4ACB87CA2417D96EULL,
		0xDCC10E215F7B6AFAULL,
		0x5765EAECA1B66BA5ULL,
		0xA92691EA74E5643BULL,
		0x409D1C096A3D6602ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A22AA691CB87C2ULL,
		0x82FB2DC2130BDDE3ULL,
		0xEF6D5F495970F944ULL,
		0x36CD74BB9821C42BULL,
		0x9CAC876AECBD5D94ULL,
		0x47ACC05524D23D4EULL,
		0x0000000813A3812DULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x013F04D40918A1E7ULL,
		0xDC4DC806152B142FULL,
		0xF89CA5ED669FE27CULL,
		0xB8E49C7CFA54CC7EULL,
		0xF171255DD4B885F6ULL,
		0x3022F6E84E7FF204ULL,
		0x88F7C701A5527294ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x809F826A048C50F3ULL,
		0x6E26E4030A958A17ULL,
		0x7C4E52F6B34FF13EULL,
		0x5C724E3E7D2A663FULL,
		0x78B892AEEA5C42FBULL,
		0x18117B74273FF902ULL,
		0x447BE380D2A9394AULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xD21C851CE910F9E4ULL,
		0x911EE1FE572EB1D7ULL,
		0xBEC50D6DA2968B7FULL,
		0x191408F09108898EULL,
		0x9C7747A1B3EA13F7ULL,
		0x14C47ADF27DDB9D4ULL,
		0x9B73D473BE50898BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB1D7D21C851CE91ULL,
		0x68B7F911EE1FE572ULL,
		0x8898EBEC50D6DA29ULL,
		0xA13F7191408F0910ULL,
		0xDB9D49C7747A1B3EULL,
		0x0898B14C47ADF27DULL,
		0x000009B73D473BE5ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xF3467B5B541102B1ULL,
		0xC3981ED6395FCCEEULL,
		0xB7E1AAC35340E87CULL,
		0xF1209C565B962DADULL,
		0x621CB52D5307769DULL,
		0x64EEC9C1DAB2A20DULL,
		0x917A821EC08A4738ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6395FCCEEF3467BULL,
		0xC35340E87CC3981EULL,
		0x565B962DADB7E1AAULL,
		0x2D5307769DF1209CULL,
		0xC1DAB2A20D621CB5ULL,
		0x1EC08A473864EEC9ULL,
		0x0000000000917A82ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0xADAF91194BF80C3FULL,
		0x870B054A7CEB75FDULL,
		0xE810D6FF114A7D32ULL,
		0x3ADBDE10C1597DFBULL,
		0x2F50CA04EA0D3010ULL,
		0xAA4028FE06F6A906ULL,
		0x8614AD8ED6DFC81AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1529F3ADD7F6B6BEULL,
		0x5BFC4529F4CA1C2CULL,
		0x78430565F7EFA043ULL,
		0x2813A834C040EB6FULL,
		0xA3F81BDAA418BD43ULL,
		0xB63B5B7F206AA900ULL,
		0x0000000000021852ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x8DAF718AA0020E1FULL,
		0xAF4555ABA9185318ULL,
		0x770574373ACEA964ULL,
		0x89273EE6B3C10713ULL,
		0x416EA2EE86D3FB5EULL,
		0xADCE36C314D93B5DULL,
		0xA10EC99251CEDEC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C46D7B8C550010ULL,
		0x4B257A2AAD5D48C2ULL,
		0x389BB82BA1B9D675ULL,
		0xDAF44939F7359E08ULL,
		0xDAEA0B751774369FULL,
		0xF6056E71B618A6C9ULL,
		0x000508764C928E76ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x9ACFF5775AD30531ULL,
		0xD21DF9B054CDA521ULL,
		0x85443E979841E0BAULL,
		0x82DA35DA8447766AULL,
		0x722AA1FAEAA5DFC8ULL,
		0x1649F5DEF85EBA16ULL,
		0x53A1EC2A0BFBE13BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90EFCD82A66D290CULL,
		0x2A21F4BCC20F05D6ULL,
		0x16D1AED4223BB354ULL,
		0x91550FD7552EFE44ULL,
		0xB24FAEF7C2F5D0B3ULL,
		0x9D0F61505FDF09D8ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x14DE8F706908E3E7ULL,
		0x1C452E57D7A922A8ULL,
		0x8832B5ED09C49D4BULL,
		0xBBE68330A1AFE27DULL,
		0xAC1432AC908F8631ULL,
		0x005A610027687DF8ULL,
		0xDF111A216792D2C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0537A3DC1A4238FULL,
		0x2C7114B95F5EA48AULL,
		0xF620CAD7B4271275ULL,
		0xC6EF9A0CC286BF89ULL,
		0xE2B050CAB2423E18ULL,
		0x04016984009DA1F7ULL,
		0x037C4468859E4B4BULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0x9DA4FA7BFFF641A2ULL,
		0x6817D09064CFCC53ULL,
		0xE27A8297DDE06337ULL,
		0xAB67CDDB72ACF77FULL,
		0x52678722DD747E37ULL,
		0x49DC4D8CD4C6EB15ULL,
		0x29D89A21AB7DE6A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267E629CED27D3DFULL,
		0xEF0319BB40BE8483ULL,
		0x9567BBFF13D414BEULL,
		0xEBA3F1BD5B3E6EDBULL,
		0xA63758AA933C3916ULL,
		0x5BEF35424EE26C66ULL,
		0x000000014EC4D10DULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x36A3C0B422D8D27EULL,
		0xEC86B7633F9DFF0FULL,
		0xF3B76EE1FB835E3BULL,
		0x20FCAB113CB6D1E5ULL,
		0x51E7EA77ACC5ED78ULL,
		0x8518B208D90FED8FULL,
		0x0A6969152C3838B2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FCEFF879B51E05AULL,
		0xFDC1AF1DF6435BB1ULL,
		0x9E5B68F2F9DBB770ULL,
		0xD662F6BC107E5588ULL,
		0x6C87F6C7A8F3F53BULL,
		0x961C1C59428C5904ULL,
		0x000000000534B48AULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xB5309BED5F8AF5FAULL,
		0xA4A723E2358EA509ULL,
		0x7FFA1F74E0E15E19ULL,
		0x5B51C65318EEC3D4ULL,
		0x3D98597F6C038547ULL,
		0x7C8D51742EAAFC33ULL,
		0x9D07DE05A943E3BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F88D63A9426D4C2ULL,
		0x7DD383857866929CULL,
		0x194C63BB0F51FFE8ULL,
		0x65FDB00E151D6D47ULL,
		0x45D0BAABF0CCF661ULL,
		0x7816A50F8EF5F235ULL,
		0x000000000002741FULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xA4B039F559DD3673ULL,
		0xE42647C3C52D9B01ULL,
		0x4DB9325E8A50056DULL,
		0x8AFC38D196E4E193ULL,
		0x0D162C51EAFF743BULL,
		0xC919100EE9B88E3AULL,
		0xC6E4C0B4C6B32405ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A4B039F559DD36ULL,
		0x6DE42647C3C52D9BULL,
		0x934DB9325E8A5005ULL,
		0x3B8AFC38D196E4E1ULL,
		0x3A0D162C51EAFF74ULL,
		0x05C919100EE9B88EULL,
		0x00C6E4C0B4C6B324ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x2B38C6D11B9CC00DULL,
		0xC22CD0A48F185938ULL,
		0x22D4B3407868C568ULL,
		0xACE99661D8F27301ULL,
		0xE2DCD937A617B309ULL,
		0x8EEEE5D6188BED42ULL,
		0x44FF0CE4D3B1CF1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491E30B27056718DULL,
		0x80F0D18AD18459A1ULL,
		0xC3B1E4E60245A966ULL,
		0x6F4C2F661359D32CULL,
		0xAC3117DA85C5B9B2ULL,
		0xC9A7639E3D1DDDCBULL,
		0x000000000089FE19ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xD452F51CE1F2CE24ULL,
		0xB3B3DA6699A4D117ULL,
		0x43D3CD5B0BD905DDULL,
		0x4017FE5CA10D79FEULL,
		0xAA3EBAECE32F6231ULL,
		0xDDC66D4F6500001EULL,
		0x420F89FBF9D30515ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF514BD47387CB389ULL,
		0x6CECF699A6693445ULL,
		0x90F4F356C2F64177ULL,
		0x5005FF9728435E7FULL,
		0xAA8FAEBB38CBD88CULL,
		0x77719B53D9400007ULL,
		0x1083E27EFE74C145ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x6528F71698E25036ULL,
		0x1896278A202758D2ULL,
		0xBD30F676E9250228ULL,
		0x7CE30A9318E3A41AULL,
		0x32AB675F23D0D583ULL,
		0x3541F0713E350CEAULL,
		0xC5919D7AAC4578A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634994A3DC5A6389ULL,
		0x08A062589E28809DULL,
		0x906AF4C3D9DBA494ULL,
		0x560DF38C2A4C638EULL,
		0x33A8CAAD9D7C8F43ULL,
		0xE288D507C1C4F8D4ULL,
		0x0003164675EAB115ULL,
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
		0x3F7B7A6BD2507EEFULL,
		0x35EA63B73ABC0CDEULL,
		0x423AB280C40C26BCULL,
		0xEF223CDDBB4B4460ULL,
		0xFF176D014EF20630ULL,
		0x720DFE97B0591606ULL,
		0xD61860BEAF9724DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5E066F1FBDBD35EULL,
		0x206135E1AF531DB9ULL,
		0xDA5A230211D59406ULL,
		0x779031877911E6EDULL,
		0x82C8B037F8BB680AULL,
		0x7CB926FB906FF4BDULL,
		0x00000006B0C305F5ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0xE01816D599CC9478ULL,
		0xD46C3FC16F1810D5ULL,
		0xCB3D4D57E8117978ULL,
		0x4C3012B98C521027ULL,
		0xBD694F483F216751ULL,
		0x33A6098221650F97ULL,
		0x93A356F2DB96FA3CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82DE3021ABC0302ULL,
		0xAAFD022F2F1A8D87ULL,
		0x57318A4204F967A9ULL,
		0xE907E42CEA298602ULL,
		0x30442CA1F2F7AD29ULL,
		0xDE5B72DF478674C1ULL,
		0x000000000012746AULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xC75EFF9765317C25ULL,
		0x768947501C51E1A3ULL,
		0x3DFDAA035B00FE08ULL,
		0x89ACB4EECAFDEE76ULL,
		0xF6278482291FDD01ULL,
		0xEC8D47F832824ADDULL,
		0x013B9262B0BC02F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3478EBDFF2ECA62FULL,
		0xC10ED128EA038A3CULL,
		0xCEC7BFB5406B601FULL,
		0xA03135969DD95FBDULL,
		0x5BBEC4F0904523FBULL,
		0x5F3D91A8FF065049ULL,
		0x000027724C561780ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x74736BF73664908DULL,
		0x5D4DB5E35CEBAB3BULL,
		0x31EA893F335E65CEULL,
		0xE471783477D4423BULL,
		0x40F2F9A53A1C4185ULL,
		0x0CCC6D4CDAD7663FULL,
		0xC73818BCD3FF6014ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B74736BF7366490ULL,
		0xCE5D4DB5E35CEBABULL,
		0x3B31EA893F335E65ULL,
		0x85E471783477D442ULL,
		0x3F40F2F9A53A1C41ULL,
		0x140CCC6D4CDAD766ULL,
		0x00C73818BCD3FF60ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x9977D51CC702236AULL,
		0x5DCC74ACA88D1283ULL,
		0x8E7C07D0AD710D1DULL,
		0xA70B59321AEF69D7ULL,
		0x7341CD50D2A38C01ULL,
		0x02C6371CC63BBD86ULL,
		0xB2FB34EF6CD68076ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12839977D51CC70ULL,
		0x10D1D5DCC74ACA88ULL,
		0xF69D78E7C07D0AD7ULL,
		0x38C01A70B59321AEULL,
		0xBBD867341CD50D2AULL,
		0x6807602C6371CC63ULL,
		0x00000B2FB34EF6CDULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x2317F978CC20EF94ULL,
		0x4D12F8542DDCC3DEULL,
		0x541C7093096FD858ULL,
		0x9489DDD5C8C0720AULL,
		0x5B1A2365668C688FULL,
		0x245DD859CEB6B68FULL,
		0x8D07BFC56E307A95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61EF118BFCBC6610ULL,
		0xEC2C26897C2A16EEULL,
		0x39052A0E384984B7ULL,
		0x3447CA44EEEAE460ULL,
		0x5B47AD8D11B2B346ULL,
		0x3D4A922EEC2CE75BULL,
		0x00004683DFE2B718ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x13649CDE6F41DDA6ULL,
		0x5EAD292DE0A1AE80ULL,
		0xF96097A6B06B84FCULL,
		0xACE8BA36F800ABF8ULL,
		0x35F81868C92E1557ULL,
		0xFA28FDBC8743A7E2ULL,
		0xF2F048A172409534ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69496F050D74009BULL,
		0x04BD35835C27E2F5ULL,
		0x45D1B7C0055FC7CBULL,
		0xC0C3464970AABD67ULL,
		0x47EDE43A1D3F11AFULL,
		0x82450B9204A9A7D1ULL,
		0x0000000000000797ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x052685E14F65FE5BULL,
		0xADC53C23A7022B9EULL,
		0x2CA32F67194916B1ULL,
		0x06A2B1671BD4F41EULL,
		0x3819E7454D1510F3ULL,
		0x35DBA84DEDBE4766ULL,
		0xED1AA84D329B7605ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9C08AE78149A17ULL,
		0x9C65245AC6B714F0ULL,
		0x9C6F53D078B28CBDULL,
		0x15345443CC1A8AC5ULL,
		0x37B6F91D98E0679DULL,
		0x34CA6DD814D76EA1ULL,
		0x0000000003B46AA1ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xF482480B2BF55A0FULL,
		0xF0D786BC8A3650B9ULL,
		0x09FE160A74E7BDDAULL,
		0x90DE9BE334F27B92ULL,
		0x5655F4096DB1383BULL,
		0xC3E6760D7545FCC1ULL,
		0x8DEF9003727C061CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BC8A3650B9F4824ULL,
		0x60A74E7BDDAF0D78ULL,
		0xBE334F27B9209FE1ULL,
		0x4096DB1383B90DE9ULL,
		0x60D7545FCC15655FULL,
		0x003727C061CC3E67ULL,
		0x000000000008DEF9ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x56B9C3F934CA2574ULL,
		0x40536C81E3A421D1ULL,
		0xB3F16B6AA3F42449ULL,
		0x33AD362D5395B3FEULL,
		0x63307B9959E84C2AULL,
		0x0900D294DAF92158ULL,
		0xD840B8A7AFB7B38BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E9087455AE70FEULL,
		0xA8FD09125014DB20ULL,
		0x54E56CFFACFC5ADAULL,
		0x567A130A8CEB4D8BULL,
		0x36BE485618CC1EE6ULL,
		0xEBEDECE2C24034A5ULL,
		0x0000000036102E29ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xED0B7616600B57C9ULL,
		0x2E8876AE4851161AULL,
		0x7A20608E3A2F46D9ULL,
		0x2AA7E3FA8AB43D1FULL,
		0x3FB3369D11115D88ULL,
		0xF8F2488931EAC728ULL,
		0x780F714A5D7C01B2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x586BB42DD859802DULL,
		0x1B64BA21DAB92144ULL,
		0xF47DE8818238E8BDULL,
		0x7620AA9F8FEA2AD0ULL,
		0x1CA0FECCDA744445ULL,
		0x06CBE3C92224C7ABULL,
		0x0001E03DC52975F0ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x436011D0DF70E4BCULL,
		0x7382EE9BB483542AULL,
		0xA3735F32864ED970ULL,
		0x4676650261A82959ULL,
		0x0D75A64255AD6EF5ULL,
		0x8EC9C0BE6C5DE43BULL,
		0x1634641BD5CB9879ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x774DDA41AA1521B0ULL,
		0xAF9943276CB839C1ULL,
		0x328130D414ACD1B9ULL,
		0xD3212AD6B77AA33BULL,
		0xE05F362EF21D86BAULL,
		0x320DEAE5CC3CC764ULL,
		0x0000000000000B1AULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x425C88A4A02944CCULL,
		0x6606641B10D9A897ULL,
		0xCC4545AF55B883FCULL,
		0xC5DD149443ECABCCULL,
		0x2CC99E5EB193668FULL,
		0x9A546352BBD8C2D6ULL,
		0x53E9546FE0805F4EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C4366A25D097222ULL,
		0xBD56E20FF1981990ULL,
		0x510FB2AF33311516ULL,
		0x7AC64D9A3F177452ULL,
		0x4AEF630B58B32679ULL,
		0xBF82017D3A69518DULL,
		0x00000000014FA551ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x8B1DC259C19B94D8ULL,
		0xFEAEA28FDE34CAB6ULL,
		0xB36EB757B2DF80B4ULL,
		0x03441961EB8B73D7ULL,
		0xF2C759157803FE35ULL,
		0x01C4893961682DF8ULL,
		0x21AA52A1B67FE2E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F78D32ADA2C7709ULL,
		0x5ECB7E02D3FABA8AULL,
		0x87AE2DCF5ECDBADDULL,
		0x55E00FF8D40D1065ULL,
		0xE585A0B7E3CB1D64ULL,
		0x86D9FF8B80071224ULL,
		0x000000000086A94AULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x55BACECC7D63F398ULL,
		0x5445BBF5C7C83BD8ULL,
		0x328F4FA3386D0CD7ULL,
		0x553682D94DF5C03EULL,
		0x8AF12CADB70A342BULL,
		0x2B6A8DB480A67BB5ULL,
		0xD7796BE7133F2A07ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC2ADD67663EB1FULL,
		0x66BAA22DDFAE3E41ULL,
		0x01F1947A7D19C368ULL,
		0xA15AA9B416CA6FAEULL,
		0xDDAC5789656DB851ULL,
		0x50395B546DA40533ULL,
		0x0006BBCB5F3899F9ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xC31E129C186C6AC1ULL,
		0x6236E4A799AF7ED8ULL,
		0xDB8BED95B094A610ULL,
		0x24C7A8B5421DE2FCULL,
		0xC24855606DA7EF5CULL,
		0xED4066A1EA93E101ULL,
		0x47EF901E309B5D92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E66BDFB630C784AULL,
		0x56C252984188DB92ULL,
		0xD508778BF36E2FB6ULL,
		0x81B69FBD70931EA2ULL,
		0x87AA4F8407092155ULL,
		0x78C26D764BB5019AULL,
		0x00000000011FBE40ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x77D65105CCA131EDULL,
		0xC15DFFE67FBB9752ULL,
		0x94E2B7C4B06A1144ULL,
		0xC9FE17DB0F74E982ULL,
		0x617D4BB9022ADFB3ULL,
		0x11C5A34D82BD3E7DULL,
		0x9BCFB9E1A9AE236CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15DFFE67FBB97527ULL,
		0x4E2B7C4B06A1144CULL,
		0x9FE17DB0F74E9829ULL,
		0x17D4BB9022ADFB3CULL,
		0x1C5A34D82BD3E7D6ULL,
		0xBCFB9E1A9AE236C1ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0xE347CF103534BD39ULL,
		0xC50962F81F7E1F52ULL,
		0x25389DDD80EDE12BULL,
		0xEA84613980C199C0ULL,
		0x0E2804E951AF4BD1ULL,
		0xD5515FF2D895117EULL,
		0x5E84A3459ACA6BC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0FBF0FA971A3E78ULL,
		0xEC076F095E284B17ULL,
		0xCC060CCE0129C4EEULL,
		0x4A8D7A5E8F542309ULL,
		0x96C4A88BF0714027ULL,
		0x2CD6535E06AA8AFFULL,
		0x0000000002F4251AULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x29EAB241CD9A706DULL,
		0x68DC13B4EDC9B39FULL,
		0x5EF33195E83BCC86ULL,
		0x735D754C81D8B758ULL,
		0x722CCD208D4978CBULL,
		0xA84CBAF0A93B7E02ULL,
		0xE00ABB5367895C95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9CF94F55920E6CULL,
		0xDE643346E09DA76EULL,
		0xC5BAC2F7998CAF41ULL,
		0x4BC65B9AEBAA640EULL,
		0xDBF013916669046AULL,
		0x4AE4AD4265D78549ULL,
		0x0000070055DA9B3CULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x0340E474561133B0ULL,
		0xA9149925CABB5B7EULL,
		0xDA3051237629CF8EULL,
		0x30DC14F1C3FDEDB5ULL,
		0x1F3F8605DB0B39BEULL,
		0xD785E566913F5676ULL,
		0x549E8FAFEDF93B6FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76B6FC0681C8E8ACULL,
		0x539F1D5229324B95ULL,
		0xFBDB6BB460A246ECULL,
		0x16737C61B829E387ULL,
		0x7EACEC3E7F0C0BB6ULL,
		0xF276DFAF0BCACD22ULL,
		0x000000A93D1F5FDBULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x380734E691AA76ABULL,
		0x94595213FE06C213ULL,
		0x02FC2007A5239A08ULL,
		0x8FF299840172618FULL,
		0xBA2820F5DC9C7E69ULL,
		0x835A1BA47EB44495ULL,
		0x87A296B9D7120AADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1099C039A7348D53ULL,
		0xD044A2CA909FF036ULL,
		0x0C7817E1003D291CULL,
		0xF34C7F94CC200B93ULL,
		0x24ADD14107AEE4E3ULL,
		0x556C1AD0DD23F5A2ULL,
		0x00043D14B5CEB890ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x65DED0C9087FA4FBULL,
		0x4D23E10A6FFBE7E6ULL,
		0x70566301919EFE4BULL,
		0x5CC77C5CC4DB33D7ULL,
		0x891E05BF44D07714ULL,
		0x240727F119040E43ULL,
		0x0CE4B25C8B000429ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF99977B432421FE9ULL,
		0x92D348F8429BFEF9ULL,
		0xF5DC1598C06467BFULL,
		0xC51731DF173136CCULL,
		0x90E247816FD1341DULL,
		0x0A4901C9FC464103ULL,
		0x0003392C9722C001ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x9CC5ACB4740FF242ULL,
		0x04E49C3A7324CD7FULL,
		0xBB18D95DDA61C31AULL,
		0xA7B971717B9A949AULL,
		0x21EE787E391C7041ULL,
		0x03276F616069B5D7ULL,
		0xA9979B5D819F5B8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6499AFF398B5968EULL,
		0x4C3863409C93874EULL,
		0x73529357631B2BBBULL,
		0x238E0834F72E2E2FULL,
		0x0D36BAE43DCF0FC7ULL,
		0x33EB71E064EDEC2CULL,
		0x0000001532F36BB0ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x0D005E03765708BAULL,
		0x833AA39CECE641E6ULL,
		0x439F9A696D60E6CEULL,
		0x0AE28510033B1BD9ULL,
		0x2C4AD9237F56CA06ULL,
		0x4E5B5E789061B179ULL,
		0xCA92DA845C762AEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x739D9CC83CC1A00BULL,
		0x4D2DAC1CD9D06754ULL,
		0xA20067637B2873F3ULL,
		0x246FEAD940C15C50ULL,
		0xCF120C362F25895BULL,
		0x508B8EC55DC9CB6BULL,
		0x000000000019525BULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x65CA2E2104B97FCCULL,
		0x5FCE6B51EA348C60ULL,
		0x7B3DD105E3950D72ULL,
		0xAFB9240B2EA7099AULL,
		0xAD4032BDE302D93DULL,
		0x152B14EE30159709ULL,
		0xF6EF50EE5946B8C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F51A463032E5171ULL,
		0x2F1CA86B92FE735AULL,
		0x5975384CD3D9EE88ULL,
		0xEF1816C9ED7DC920ULL,
		0x7180ACB84D6A0195ULL,
		0x72CA35C640A958A7ULL,
		0x0000000007B77A87ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0xC4B789005433AE0EULL,
		0x96FEB68041BE50ECULL,
		0xF4EFC27C1BD5BB66ULL,
		0xE798603677F9461AULL,
		0xDE378E9FBDBA8869ULL,
		0xE0D2F5A40F67ABFBULL,
		0x0F63C62048CB4F1DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x837CA1D9896F1200ULL,
		0x37AB76CD2DFD6D00ULL,
		0xEFF28C35E9DF84F8ULL,
		0x7B7510D3CF30C06CULL,
		0x1ECF57F7BC6F1D3FULL,
		0x91969E3BC1A5EB48ULL,
		0x000000001EC78C40ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xDC4F6B6354C2105DULL,
		0xD5E5D524A798C742ULL,
		0xBFE32CFCA6BA7ACEULL,
		0x7CD816989DF8C407ULL,
		0x6F8539901865AB20ULL,
		0x8E04EBB29560E280ULL,
		0xBF7367C6A737F1B5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF2EA9253CC63A16ULL,
		0xFF1967E535D3D676ULL,
		0xE6C0B4C4EFC6203DULL,
		0x7C29CC80C32D5903ULL,
		0x70275D94AB071403ULL,
		0xFB9B3E3539BF8DACULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x67EDA6D0C341EE1BULL,
		0xE946E95F5415DCDCULL,
		0x0907C72913E4091CULL,
		0x10D5FB2052711375ULL,
		0x48EE833ADA6147CCULL,
		0x1940AD9F276EE79EULL,
		0xBA5B74676B63FFE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8CFDB4DA18683DCULL,
		0x39D28DD2BEA82BB9ULL,
		0xEA120F8E5227C812ULL,
		0x9821ABF640A4E226ULL,
		0x3C91DD0675B4C28FULL,
		0xCE32815B3E4EDDCFULL,
		0x0174B6E8CED6C7FFULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x5B79E3F3E727AE48ULL,
		0xC995135B03C85E18ULL,
		0xC1B85C8145467D65ULL,
		0x5D26F60326569061ULL,
		0x55B17A49FFE0CDC8ULL,
		0x713FD6C441C22459ULL,
		0x3A249824951CE22DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B79E3F3E727AE48ULL,
		0xC995135B03C85E18ULL,
		0xC1B85C8145467D65ULL,
		0x5D26F60326569061ULL,
		0x55B17A49FFE0CDC8ULL,
		0x713FD6C441C22459ULL,
		0x3A249824951CE22DULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x04D4DE5FF60B13F6ULL,
		0xD0A2EF6339E06151ULL,
		0x68B466363D2F4489ULL,
		0x8DEAE5BEED6D4019ULL,
		0xB76CE47D3ABAB7E2ULL,
		0xA9FF0F12792B8392ULL,
		0x9FC4E19FBB7CA470ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85441353797FD82CULL,
		0x1227428BBD8CE781ULL,
		0x0065A2D198D8F4BDULL,
		0xDF8A37AB96FBB5B5ULL,
		0x0E4ADDB391F4EAEAULL,
		0x91C2A7FC3C49E4AEULL,
		0x00027F13867EEDF2ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xD8863C9FFF0667B5ULL,
		0x1261E3C91656208EULL,
		0x890418E0FE0D785EULL,
		0x11F29F7D3444506DULL,
		0x75D7EEAB142CEFF7ULL,
		0x3A705081BD9167D1ULL,
		0xACF6EE428810BCB1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C7922CAC411DB10ULL,
		0x831C1FC1AF0BC24CULL,
		0x53EFA6888A0DB120ULL,
		0xFDD562859DFEE23EULL,
		0x0A1037B22CFA2EBAULL,
		0xDDC851021796274EULL,
		0x000000000000159EULL,
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
		0xA2418CB17CD4C4C4ULL,
		0x6170B28C953F3FF8ULL,
		0xB09749D8C03FDBE8ULL,
		0xBC05D0543AF068A0ULL,
		0x0487CCE35766E621ULL,
		0x51214633030C8EABULL,
		0x5594B59F2E2F8FB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C953F3FF8A2418CULL,
		0xD8C03FDBE86170B2ULL,
		0x543AF068A0B09749ULL,
		0xE35766E621BC05D0ULL,
		0x33030C8EAB0487CCULL,
		0x9F2E2F8FB5512146ULL,
		0x00000000005594B5ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x0DDAE609F4E84C7BULL,
		0x8955D0FC03D5B4FBULL,
		0x1090A0628D4CD813ULL,
		0x54022536A076BBE0ULL,
		0x6350EDD20CA4B5A0ULL,
		0xDFC2495524A3A858ULL,
		0xE281BAB38982728EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01EADA7D86ED7304ULL,
		0x46A66C09C4AAE87EULL,
		0x503B5DF008485031ULL,
		0x06525AD02A01129BULL,
		0x9251D42C31A876E9ULL,
		0xC4C139476FE124AAULL,
		0x000000007140DD59ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xFDFC016C2A9B34CAULL,
		0xB1FCB1A856F6508EULL,
		0x4458B61E24A62E6CULL,
		0xE64F7D251CA03397ULL,
		0x217B9C7205FA5954ULL,
		0xDF0EAB84673AB8C1ULL,
		0x5403EBF252E3F8F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA11DFBF802D8553ULL,
		0xC5CD963F96350ADEULL,
		0x0672E88B16C3C494ULL,
		0x4B2A9CC9EFA4A394ULL,
		0x5718242F738E40BFULL,
		0x7F1EBBE1D5708CE7ULL,
		0x00000A807D7E4A5CULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xBA6794E9500218A5ULL,
		0x1F6D9173F6104206ULL,
		0x121525D8B6CA3A68ULL,
		0x737B3A159CD231BEULL,
		0xA1A8508A2565E427ULL,
		0x4A2CEEAB3FB8265BULL,
		0xD5CF9BBCF6EFE3B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE99E53A54008629ULL,
		0x07DB645CFD841081ULL,
		0x848549762DB28E9AULL,
		0xDCDECE8567348C6FULL,
		0xE86A142289597909ULL,
		0x128B3BAACFEE0996ULL,
		0x3573E6EF3DBBF8EDULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x4C4D0701ACB3A290ULL,
		0x05E3FC85A0D69263ULL,
		0xEF4C446ACAF19C2BULL,
		0xDECF70B102D7AE80ULL,
		0x4EC0E10DEA008557ULL,
		0x651C576A5276422FULL,
		0xD13310FFB7B62FB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931A6268380D659DULL,
		0xE1582F1FE42D06B4ULL,
		0x74077A622356578CULL,
		0x2ABEF67B858816BDULL,
		0x117A7607086F5004ULL,
		0x7DB328E2BB5293B2ULL,
		0x0006899887FDBDB1ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xD3622C1A4D8ED8DDULL,
		0xC4DE4DA8636F4ED2ULL,
		0x5C1E7627C2720080ULL,
		0x171F342740C3FD2DULL,
		0x3E4BB4AE262A6D71ULL,
		0x8BA43E27F2EFC7B5ULL,
		0x530AA9C36AA837C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C6DE9DA5A6C458ULL,
		0x4F84E4010189BC9BULL,
		0x4E8187FA5AB83CECULL,
		0x5C4C54DAE22E3E68ULL,
		0x4FE5DF8F6A7C9769ULL,
		0x86D5506F8317487CULL,
		0x0000000000A61553ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xC01938731D9FE69FULL,
		0xACA3705F6777FA13ULL,
		0xC15DC602DE73B61DULL,
		0x3C8594BE53CD4405ULL,
		0x5B0E22F695D9B067ULL,
		0x713DCFD6F18F7D58ULL,
		0x989354D877BBA289ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BECEEFF42780327ULL,
		0xC05BCE76C3B5946EULL,
		0x97CA79A880B82BB8ULL,
		0x5ED2BB360CE790B2ULL,
		0xFADE31EFAB0B61C4ULL,
		0x9B0EF774512E27B9ULL,
		0x000000000013126AULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xD079674DCD44F63CULL,
		0xD6A225614E266394ULL,
		0x1887F2A387878A58ULL,
		0x3499517985C5FAD6ULL,
		0xB1CD562AD548BCC7ULL,
		0x8B40FF76C2596EE7ULL,
		0x3CCC4B1FB77BC432ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538998E5341E59D3ULL,
		0xE1E1E29635A88958ULL,
		0x61717EB58621FCA8ULL,
		0xB5522F31CD26545EULL,
		0xB0965BB9EC73558AULL,
		0xEDDEF10CA2D03FDDULL,
		0x000000000F3312C7ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x06D3ABDA1FDEAA9AULL,
		0x1F965B6A70D5ECFFULL,
		0xD6D4ACEA1E6C300AULL,
		0x0A2BDF14064371BEULL,
		0x51282D0C9753AAD3ULL,
		0x8D0FFF998D03669FULL,
		0xBEE488E3293811ADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06D3ABDA1FDEAA9AULL,
		0x1F965B6A70D5ECFFULL,
		0xD6D4ACEA1E6C300AULL,
		0x0A2BDF14064371BEULL,
		0x51282D0C9753AAD3ULL,
		0x8D0FFF998D03669FULL,
		0xBEE488E3293811ADULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x6056D5720C0AF78AULL,
		0x7400B2484CA5BF79ULL,
		0xD4F149C946F77B79ULL,
		0xF3B8F32BD4D40511ULL,
		0x755236046FC50121ULL,
		0x67CF68570F72C6AAULL,
		0x69A7439A0F3814CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B2484CA5BF79605ULL,
		0x149C946F77B79740ULL,
		0x8F32BD4D40511D4FULL,
		0x236046FC50121F3BULL,
		0xF68570F72C6AA755ULL,
		0x7439A0F3814CA67CULL,
		0x000000000000069AULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x7F6C81EFF1132B5EULL,
		0xC1A387BF2F330723ULL,
		0xB84FA61FAB1ED054ULL,
		0x6C5CCE56E93EC9FFULL,
		0x9945C481B6BBE479ULL,
		0x995AAE368CF40D6BULL,
		0x6C6F97DCAF4BDD58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46FED903DFE22656ULL,
		0xA983470F7E5E660EULL,
		0xFF709F4C3F563DA0ULL,
		0xF2D8B99CADD27D93ULL,
		0xD7328B89036D77C8ULL,
		0xB132B55C6D19E81AULL,
		0x00D8DF2FB95E97BAULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x18E560B99209850FULL,
		0x62FB9A7DA2F65CC4ULL,
		0x3A7EE143C01EF786ULL,
		0x939F2556AC0BBDE3ULL,
		0xC7E1A496E8D3ED3EULL,
		0x4310DF4B2142D502ULL,
		0x35CA028EB33196DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FB45ECB98831CACULL,
		0x287803DEF0CC5F73ULL,
		0xAAD58177BC674FDCULL,
		0x92DD1A7DA7D273E4ULL,
		0xE964285AA058FC34ULL,
		0x51D66632DBE8621BULL,
		0x000000000006B940ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xCE6A8F73DAF558C5ULL,
		0x064141256A1FC341ULL,
		0xB8F196AD0C227D8DULL,
		0xAABEE4CC8D956672ULL,
		0x1F41A5287553B92CULL,
		0x97A2EC6D1B380642ULL,
		0xAE4A0997EA992DF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A87F0D0739AA3DCULL,
		0x43089F6341905049ULL,
		0x2365599CAE3C65ABULL,
		0x1D54EE4B2AAFB933ULL,
		0x46CE019087D0694AULL,
		0xFAA64B7C25E8BB1BULL,
		0x000000002B928265ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xE6885DAE4ED05891ULL,
		0xF623C6B1D8732783ULL,
		0x9D15E84748A98655ULL,
		0xAA05A1BAFBCE0AE9ULL,
		0x1E171EEEC64EFBCAULL,
		0x6C52993FBF4743FEULL,
		0xA6DF0C752B9B6187ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07CD10BB5C9DA0BULL,
		0xCABEC478D63B0E64ULL,
		0x5D33A2BD08E91530ULL,
		0x795540B4375F79C1ULL,
		0x7FC3C2E3DDD8C9DFULL,
		0x30ED8A5327F7E8E8ULL,
		0x0014DBE18EA5736CULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x27BA8B3C80128B04ULL,
		0x3ED050890002C83BULL,
		0x2D80AFBCC5F3553FULL,
		0x563CAEE0DC701476ULL,
		0xC01FD9DF407EC98BULL,
		0x2CDB7A642AAB5E50ULL,
		0x0056BAB86FC9778EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6828448001641D9ULL,
		0x6C057DE62F9AA9F9ULL,
		0xB1E57706E380A3B1ULL,
		0x00FECEFA03F64C5AULL,
		0x66DBD321555AF286ULL,
		0x02B5D5C37E4BBC71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x9394E32A27AA70D4ULL,
		0x4541110F7C49747BULL,
		0x8879FCD93AC1B00EULL,
		0xD90ABB0FB8BE5CEFULL,
		0x2FEA0936D9A6359BULL,
		0x3CAA9770E362F088ULL,
		0x596802BBDA0E063CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110F7C49747B9394ULL,
		0xFCD93AC1B00E4541ULL,
		0xBB0FB8BE5CEF8879ULL,
		0x0936D9A6359BD90AULL,
		0x9770E362F0882FEAULL,
		0x02BBDA0E063C3CAAULL,
		0x0000000000005968ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x18526A66B9C1B87AULL,
		0xC893811599ED8936ULL,
		0xB2DA474AE24C472EULL,
		0x45BE17C6A1384F99ULL,
		0xF23ED332B60020C8ULL,
		0x2335330237A1A3EFULL,
		0x7ABDCE49F65A0827ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5667B624D86149A9ULL,
		0x2B89311CBB224E04ULL,
		0x1A84E13E66CB691DULL,
		0xCAD800832116F85FULL,
		0x08DE868FBFC8FB4CULL,
		0x27D968209C8CD4CCULL,
		0x0000000001EAF739ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xEFC55AB20FFCDAA9ULL,
		0xEBEAD2AFE1816EDBULL,
		0xD871339322186984ULL,
		0xAD1C3F23E03F6B73ULL,
		0x3D64BB307344F066ULL,
		0xB46203D1CBD466F5ULL,
		0x39E62735CBE2AE6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F0C0B76DF7E2AD5ULL,
		0x9910C34C275F5695ULL,
		0x1F01FB5B9EC3899CULL,
		0x839A27833568E1F9ULL,
		0x8E5EA337A9EB25D9ULL,
		0xAE5F15735DA3101EULL,
		0x0000000001CF3139ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x4AC9D8254994605FULL,
		0x14C6A393AFFE5E2CULL,
		0x99EFBE63C3C60069ULL,
		0x52770BEECEBB2B32ULL,
		0xDA425FBB2CEF124BULL,
		0xFD781A7BD6E71BF8ULL,
		0x5CB6E80DC48361E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6351C9D7FF2F162ULL,
		0xCF7DF31E1E300348ULL,
		0x93B85F7675D95994ULL,
		0xD212FDD96778925AULL,
		0xEBC0D3DEB738DFC6ULL,
		0xE5B7406E241B0F27ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0x9CF9287C28DDF35DULL,
		0x60D5EB217F31299FULL,
		0x7C51DC6B73DF0AB3ULL,
		0x270C9B2C3B1069A5ULL,
		0x7E15C4F680C66033ULL,
		0x523BE68AAB994048ULL,
		0xBC11E4D4A2D6A6F3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F9CF9287C28DDF3ULL,
		0xB360D5EB217F3129ULL,
		0xA57C51DC6B73DF0AULL,
		0x33270C9B2C3B1069ULL,
		0x487E15C4F680C660ULL,
		0xF3523BE68AAB9940ULL,
		0x00BC11E4D4A2D6A6ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xE190448954D63BF4ULL,
		0xABC6D98A84638846ULL,
		0x4CA614C389E7C535ULL,
		0x270FE4A465D06E53ULL,
		0xC40F02881E66FB2FULL,
		0xD18BBC270DA9C414ULL,
		0x3F94FE4D1901F0DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC54231C42370C822ULL,
		0x61C4F3E29AD5E36CULL,
		0x5232E83729A6530AULL,
		0x440F337D979387F2ULL,
		0x1386D4E20A620781ULL,
		0x268C80F86E68C5DEULL,
		0x00000000001FCA7FULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0xF40056AD7571B7AAULL,
		0x63C7B5CB8661F287ULL,
		0x2A52F0173FF0AFDBULL,
		0x523B8E07CBF70E1FULL,
		0x08991AFC5725D045ULL,
		0x8243A6438545513AULL,
		0xFED62CDCFC05F002ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB970CC3E50FE800AULL,
		0x02E7FE15FB6C78F6ULL,
		0xC0F97EE1C3E54A5EULL,
		0x5F8AE4BA08AA4771ULL,
		0xC870A8AA27411323ULL,
		0x9B9F80BE00504874ULL,
		0x00000000001FDAC5ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0xF900F206D32400CFULL,
		0x012FFA9C279794E2ULL,
		0xD2C19C8CD0E97871ULL,
		0xA27BE36FF1759BA6ULL,
		0x34BBDB3F8991CE8DULL,
		0x27D28259DB4E36EDULL,
		0x7FAAE6ECD5936907ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5E538BE403C81B4ULL,
		0x3A5E1C404BFEA709ULL,
		0x5D66E9B4B0672334ULL,
		0x6473A3689EF8DBFCULL,
		0xD38DBB4D2EF6CFE2ULL,
		0x64DA41C9F4A09676ULL,
		0x0000001FEAB9BB35ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x572A6E745BC09C51ULL,
		0x566B794AB81563F3ULL,
		0xDE83155A8EEF7603ULL,
		0x362863313ABC8FF7ULL,
		0xE02A073990D8E03CULL,
		0xAB03E7F74D026930ULL,
		0xE0F8B982873513FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x572A6E745BC09C51ULL,
		0x566B794AB81563F3ULL,
		0xDE83155A8EEF7603ULL,
		0x362863313ABC8FF7ULL,
		0xE02A073990D8E03CULL,
		0xAB03E7F74D026930ULL,
		0xE0F8B982873513FAULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x8905F7A4B8CC77DBULL,
		0x8C6072FB13263996ULL,
		0xEE7146917676DE93ULL,
		0x0F6284E09E5BAF95ULL,
		0xC679D42F26B658A8ULL,
		0x05ECB0C7171B1989ULL,
		0x177463CBF9A3C21AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4482FBD25C663BEDULL,
		0xC630397D89931CCBULL,
		0xF738A348BB3B6F49ULL,
		0x07B142704F2DD7CAULL,
		0xE33CEA17935B2C54ULL,
		0x02F658638B8D8CC4ULL,
		0x0BBA31E5FCD1E10DULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xD3D4A14A569A2705ULL,
		0x994FB59A570AD675ULL,
		0x5F38062E97662217ULL,
		0xAAADF5CFD61DB3A1ULL,
		0x5F89738FD6F95E38ULL,
		0x44CE983BFD2ECC49ULL,
		0x386FD136E79FA38AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70AD675D3D4A14A5ULL,
		0x7662217994FB59A5ULL,
		0x61DB3A15F38062E9ULL,
		0x6F95E38AAADF5CFDULL,
		0xD2ECC495F89738FDULL,
		0x79FA38A44CE983BFULL,
		0x0000000386FD136EULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x6A168E4DB7608A92ULL,
		0xF3F530D5A5AB9CDCULL,
		0xE3AA70582E0AD64EULL,
		0xCDE4ACA7F8EAFB82ULL,
		0x70DDF91601854DABULL,
		0xAEFDD72FF6C59E02ULL,
		0x5E5762A20E9748BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA61AB4B5739B8D4ULL,
		0x54E0B05C15AC9DE7ULL,
		0xC9594FF1D5F705C7ULL,
		0xBBF22C030A9B579BULL,
		0xFBAE5FED8B3C04E1ULL,
		0xAEC5441D2E917F5DULL,
		0x00000000000000BCULL,
		0x0000000000000000ULL
	}};
	shift = 55;
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
		0x239DA49708E4EBA9ULL,
		0x3766A62F0BBBA513ULL,
		0x110444C168F6B1B9ULL,
		0x2D82AB0B3B7E815AULL,
		0xECB7F59F08525683ULL,
		0x6864EB35D0EBE822ULL,
		0x309DFDE6CEC247CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17774A26473B492ULL,
		0x2D1ED63726ECD4C5ULL,
		0x676FD02B42208898ULL,
		0xE10A4AD065B05561ULL,
		0xBA1D7D045D96FEB3ULL,
		0xD9D848F98D0C9D66ULL,
		0x000000000613BFBCULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x411F3B33E382DFE7ULL,
		0x91BD52618A44EED0ULL,
		0x49EF48AFE87258B0ULL,
		0x3AA6AA888263B2C7ULL,
		0x2E88FAFEEF4CF646ULL,
		0x181D1C4DBD8B81A0ULL,
		0xD7B3F631E043D285ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7768208F9D99F1C1ULL,
		0x2C5848DEA930C522ULL,
		0xD963A4F7A457F439ULL,
		0x7B231D5355444131ULL,
		0xC0D017447D7F77A6ULL,
		0xE9428C0E8E26DEC5ULL,
		0x00006BD9FB18F021ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x11FB21461101FFD1ULL,
		0xA54F5A49B0E16FF9ULL,
		0xCA52553F0C222958ULL,
		0xE2A642FC673B5DD1ULL,
		0x26BD58F4791886F4ULL,
		0x9F8BCC8F64E5E0C7ULL,
		0xEC1ED9D7068178AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EB49361C2DFF22ULL,
		0x4A4AA7E184452B14ULL,
		0x54C85F8CE76BBA39ULL,
		0xD7AB1E8F2310DE9CULL,
		0xF17991EC9CBC18E4ULL,
		0x83DB3AE0D02F15F3ULL,
		0x000000000000001DULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xBF7C12AD96231CBEULL,
		0x6AA694164AFA75F8ULL,
		0xEAE1C2E5E9EB358DULL,
		0x4178A79B18B3E952ULL,
		0xE178AF570B29FF6BULL,
		0x3E542CE5C0E6E089ULL,
		0x0810DC7F8C09640BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFC5FBE0956CB11ULL,
		0x9AC6B5534A0B257DULL,
		0xF4A97570E172F4F5ULL,
		0xFFB5A0BC53CD8C59ULL,
		0x7044F0BC57AB8594ULL,
		0xB2059F2A1672E073ULL,
		0x000004086E3FC604ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xE1C53EF35A55B7EEULL,
		0x5FEED5DC0CA8A79DULL,
		0x69EA982F9CC37EB5ULL,
		0x83BB5B3D25B35282ULL,
		0x822C023E84652054ULL,
		0x699EA62CCB706272ULL,
		0xB30A5B31528B11BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E29F79AD2ADBF7ULL,
		0xAFF76AEE065453CEULL,
		0x34F54C17CE61BF5AULL,
		0x41DDAD9E92D9A941ULL,
		0x4116011F4232902AULL,
		0xB4CF531665B83139ULL,
		0x59852D98A94588DFULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x88ADD2602F92D76EULL,
		0x5CD908DF3C857C00ULL,
		0xB364719CCA8A4557ULL,
		0x12E5B299277DD337ULL,
		0x116859EF84339828ULL,
		0x8CA2F1B690EB7F05ULL,
		0x3E583F9C10CCEE81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4456E93017C96BB7ULL,
		0xAE6C846F9E42BE00ULL,
		0xD9B238CE654522ABULL,
		0x0972D94C93BEE99BULL,
		0x88B42CF7C219CC14ULL,
		0xC65178DB4875BF82ULL,
		0x1F2C1FCE08667740ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x57B923C748B34C20ULL,
		0x98869091983F61EFULL,
		0x5E1697DCE562E353ULL,
		0xCAD1985855D97E63ULL,
		0x457397CCEC6D5257ULL,
		0x33ACDF85C23E6A94ULL,
		0x77C232EED672A993ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF57B923C748B34CULL,
		0x5398869091983F61ULL,
		0x635E1697DCE562E3ULL,
		0x57CAD1985855D97EULL,
		0x94457397CCEC6D52ULL,
		0x9333ACDF85C23E6AULL,
		0x0077C232EED672A9ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x5328ADD4CD7F721CULL,
		0x4C151592A479EB9AULL,
		0x33BEFDA572E0E414ULL,
		0x4232B867E087B3B4ULL,
		0xE8B5DB5D9DC2D704ULL,
		0xA43DE928ECF0824DULL,
		0xE0E92296281E007CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB9A5328ADD4CD7ULL,
		0x0E4144C151592A47ULL,
		0x7B3B433BEFDA572EULL,
		0x2D7044232B867E08ULL,
		0x0824DE8B5DB5D9DCULL,
		0xE007CA43DE928ECFULL,
		0x00000E0E92296281ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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