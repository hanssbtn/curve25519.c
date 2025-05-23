#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA5A926C28789C2AFULL,
		0xBBD0B29DC06950BCULL,
		0xF092E0C8C5632674ULL,
		0x3A4AC3B396321BA5ULL,
		0xC40F491A9C72B1DBULL,
		0xFB28C4F9800FF804ULL,
		0x58FB5E156E8A07FAULL,
		0x2F18760503D85460ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4B524D850F13855EULL,
		0x77A1653B80D2A179ULL,
		0xE125C1918AC64CE9ULL,
		0x749587672C64374BULL,
		0x881E923538E563B6ULL,
		0xF65189F3001FF009ULL,
		0xB1F6BC2ADD140FF5ULL,
		0x5E30EC0A07B0A8C0ULL
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
		0xF316462AD2F721A6ULL,
		0x65D8A1D7D3CCA85AULL,
		0xAA3E4C7816056B12ULL,
		0xF9DE62BAFB35C39AULL,
		0xBBE81139E3DC8CC7ULL,
		0x9536F2C44995541CULL,
		0x22F01AE0BD05AB18ULL,
		0x0822EF93835595ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62C8C55A5EE434CULL,
		0xCBB143AFA79950B5ULL,
		0x547C98F02C0AD624ULL,
		0xF3BCC575F66B8735ULL,
		0x77D02273C7B9198FULL,
		0x2A6DE588932AA839ULL,
		0x45E035C17A0B5631ULL,
		0x1045DF2706AB2B5AULL
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
		0x055B6C7305DA45C4ULL,
		0xA85CAC0E44D9001CULL,
		0x0B98C1C89B929F49ULL,
		0x7774410489E03EAAULL,
		0x09FF52E039B11C5BULL,
		0xF816AB85B913CE19ULL,
		0x7F7BB7BC647883B1ULL,
		0x01BAFEE0BC9CD701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB6D8E60BB48B88ULL,
		0x50B9581C89B20038ULL,
		0x1731839137253E93ULL,
		0xEEE8820913C07D54ULL,
		0x13FEA5C0736238B6ULL,
		0xF02D570B72279C32ULL,
		0xFEF76F78C8F10763ULL,
		0x0375FDC17939AE02ULL
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
		0xAF89CE8DD3E990BCULL,
		0xD1E25AC30729A2D3ULL,
		0x6B50A6EA430A0905ULL,
		0x31BFD6E3301BFB2BULL,
		0xD91E5136FAEAE89FULL,
		0x90DF5134068EDEAFULL,
		0xF1098BE5891DA08FULL,
		0x28A15B38CB0B1A0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F139D1BA7D32178ULL,
		0xA3C4B5860E5345A7ULL,
		0xD6A14DD48614120BULL,
		0x637FADC66037F656ULL,
		0xB23CA26DF5D5D13EULL,
		0x21BEA2680D1DBD5FULL,
		0xE21317CB123B411FULL,
		0x5142B67196163419ULL
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
		0x63FF76AA7B69D943ULL,
		0x5E6123D60F62C293ULL,
		0x90C9A18AFFC11825ULL,
		0xAE754D9DB0C66976ULL,
		0x9D485F9C370561D7ULL,
		0xD3D17F8AA4B88563ULL,
		0x64AE52B173A2179DULL,
		0x317EAEAC7233ADFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FEED54F6D3B286ULL,
		0xBCC247AC1EC58526ULL,
		0x21934315FF82304AULL,
		0x5CEA9B3B618CD2EDULL,
		0x3A90BF386E0AC3AFULL,
		0xA7A2FF1549710AC7ULL,
		0xC95CA562E7442F3BULL,
		0x62FD5D58E4675BFEULL
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
		0x19BB176915DBF341ULL,
		0x922888491B1A17C9ULL,
		0x73A16B6F25AA662EULL,
		0x46CF6FA15F42B913ULL,
		0xE1D59120BEDF78CCULL,
		0xE6B619AC51796B22ULL,
		0x19BD3D6C34070EB8ULL,
		0x2C61F29744C766BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33762ED22BB7E682ULL,
		0x2451109236342F92ULL,
		0xE742D6DE4B54CC5DULL,
		0x8D9EDF42BE857226ULL,
		0xC3AB22417DBEF198ULL,
		0xCD6C3358A2F2D645ULL,
		0x337A7AD8680E1D71ULL,
		0x58C3E52E898ECD74ULL
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
		0x823F8D00D09AC1FFULL,
		0x460EA254811898F9ULL,
		0x3A1763A13D765B58ULL,
		0x94C3CBF0083FE08FULL,
		0x8EF61D61053C65A4ULL,
		0xB1D9BB9E3B99338CULL,
		0xB9CA17A904675FCCULL,
		0x00E3A3A33BF9ADBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x047F1A01A13583FEULL,
		0x8C1D44A9023131F3ULL,
		0x742EC7427AECB6B0ULL,
		0x298797E0107FC11EULL,
		0x1DEC3AC20A78CB49ULL,
		0x63B3773C77326719ULL,
		0x73942F5208CEBF99ULL,
		0x01C7474677F35B7BULL
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
		0xF9758D16948C3CAFULL,
		0xAC04883ED1DEA4E6ULL,
		0x4B6455854F578547ULL,
		0x4700BABD82A981D0ULL,
		0x976417584DB160A4ULL,
		0x8372EF79FDE73A58ULL,
		0x5F49CCB527456A8CULL,
		0x019610A71CC9C89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2EB1A2D2918795EULL,
		0x5809107DA3BD49CDULL,
		0x96C8AB0A9EAF0A8FULL,
		0x8E01757B055303A0ULL,
		0x2EC82EB09B62C148ULL,
		0x06E5DEF3FBCE74B1ULL,
		0xBE93996A4E8AD519ULL,
		0x032C214E3993913AULL
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
		0xA3696E76A1C35BDCULL,
		0x7EAEE51A6A05CED7ULL,
		0xE2D6B120E3FE574CULL,
		0x1866570994D4A74CULL,
		0xDC91C61AE6DA8B78ULL,
		0xBC440487FC0C3E77ULL,
		0xB09A6DD55D874B50ULL,
		0x02107ACE2BD4E631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46D2DCED4386B7B8ULL,
		0xFD5DCA34D40B9DAFULL,
		0xC5AD6241C7FCAE98ULL,
		0x30CCAE1329A94E99ULL,
		0xB9238C35CDB516F0ULL,
		0x7888090FF8187CEFULL,
		0x6134DBAABB0E96A1ULL,
		0x0420F59C57A9CC63ULL
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
		0x44865E58D158189CULL,
		0x74AEB123B66E3E61ULL,
		0x08F79BF59442EF57ULL,
		0xCA3CEF3F7A500CE5ULL,
		0x0ED35E911319E89CULL,
		0xCDED615F6A219A79ULL,
		0x6BDB0794A24D954FULL,
		0x009294B5C43267DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x890CBCB1A2B03138ULL,
		0xE95D62476CDC7CC2ULL,
		0x11EF37EB2885DEAEULL,
		0x9479DE7EF4A019CAULL,
		0x1DA6BD222633D139ULL,
		0x9BDAC2BED44334F2ULL,
		0xD7B60F29449B2A9FULL,
		0x0125296B8864CFB4ULL
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
		0xF288AF8523D32E7FULL,
		0xF8F38AA5AE28D21FULL,
		0x983074427A89427FULL,
		0xD89FF7CFA2FC14A1ULL,
		0xD59F9C5BBA9E1A93ULL,
		0xC4289F5352DCDAA5ULL,
		0x8AB5AFA6881172D0ULL,
		0x312712B1F5017C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5115F0A47A65CFEULL,
		0xF1E7154B5C51A43FULL,
		0x3060E884F51284FFULL,
		0xB13FEF9F45F82943ULL,
		0xAB3F38B7753C3527ULL,
		0x88513EA6A5B9B54BULL,
		0x156B5F4D1022E5A1ULL,
		0x624E2563EA02F8DBULL
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
		0xA85D9C2C73980719ULL,
		0x5B8739254DE2190AULL,
		0xFDBB6EF87CA1CF9DULL,
		0x00805A4A914EDEE9ULL,
		0xE3F9FACE00D261CFULL,
		0x3601A7DC6D18C40EULL,
		0x0BC03F7C0ABC4B8FULL,
		0x297450683C3C62AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BB3858E7300E32ULL,
		0xB70E724A9BC43215ULL,
		0xFB76DDF0F9439F3AULL,
		0x0100B495229DBDD3ULL,
		0xC7F3F59C01A4C39EULL,
		0x6C034FB8DA31881DULL,
		0x17807EF81578971EULL,
		0x52E8A0D07878C55CULL
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
		0x05871552641EBCBFULL,
		0x8AFB4946A0F5FD90ULL,
		0x5DC31684052B9044ULL,
		0x18C51F82AC7DEC52ULL,
		0x2A707CB0623D9909ULL,
		0xAE52ADCAD59A08B0ULL,
		0x16ACF6A27C277D42ULL,
		0x127D4F20A34A5771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B0E2AA4C83D797EULL,
		0x15F6928D41EBFB20ULL,
		0xBB862D080A572089ULL,
		0x318A3F0558FBD8A4ULL,
		0x54E0F960C47B3212ULL,
		0x5CA55B95AB341160ULL,
		0x2D59ED44F84EFA85ULL,
		0x24FA9E414694AEE2ULL
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
		0x87CEAFB5F455785AULL,
		0xBECB252EA6E82E2FULL,
		0x229C677FAD6C16ADULL,
		0xB45143249285515BULL,
		0x19164144460EA26AULL,
		0xF6C96885F1F0576EULL,
		0xE8A6F4A43B13F711ULL,
		0x2DDAC845EE064A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F9D5F6BE8AAF0B4ULL,
		0x7D964A5D4DD05C5FULL,
		0x4538CEFF5AD82D5BULL,
		0x68A28649250AA2B6ULL,
		0x322C82888C1D44D5ULL,
		0xED92D10BE3E0AEDCULL,
		0xD14DE9487627EE23ULL,
		0x5BB5908BDC0C948DULL
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
		0xEC9BAC86A439D231ULL,
		0xE07F9857D4FC703EULL,
		0x3ECE7553A22D7267ULL,
		0x6E973FDB0B19C67BULL,
		0x226C79C2B4CB87A6ULL,
		0x435A0A9D56038666ULL,
		0x6A7A76C3F0A4D651ULL,
		0x3BFD8E68D9F5556BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD937590D4873A462ULL,
		0xC0FF30AFA9F8E07DULL,
		0x7D9CEAA7445AE4CFULL,
		0xDD2E7FB616338CF6ULL,
		0x44D8F38569970F4CULL,
		0x86B4153AAC070CCCULL,
		0xD4F4ED87E149ACA2ULL,
		0x77FB1CD1B3EAAAD6ULL
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
		0xBB724AA98B00E17FULL,
		0x20DA5A99C4B5CC3BULL,
		0x2F7EA9E2FE343C2BULL,
		0xEA88D7B69C326136ULL,
		0xB6818A67AD3627DCULL,
		0x4480CF24296FDDC7ULL,
		0x56F0B2AEA18071ADULL,
		0x2571AC897FD90FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E495531601C2FEULL,
		0x41B4B533896B9877ULL,
		0x5EFD53C5FC687856ULL,
		0xD511AF6D3864C26CULL,
		0x6D0314CF5A6C4FB9ULL,
		0x89019E4852DFBB8FULL,
		0xADE1655D4300E35AULL,
		0x4AE35912FFB21F54ULL
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
		0x67B405F02CEC35BDULL,
		0x7854C4BC12736A1FULL,
		0x3B0363F8D75DB16AULL,
		0xC07B5A744E315461ULL,
		0x9B9E6684ECA3F9F6ULL,
		0xFB861F33CA63D6FBULL,
		0x7F2953BA8123B07DULL,
		0x1CEF2F6DB657133BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF680BE059D86B7AULL,
		0xF0A9897824E6D43EULL,
		0x7606C7F1AEBB62D4ULL,
		0x80F6B4E89C62A8C2ULL,
		0x373CCD09D947F3EDULL,
		0xF70C3E6794C7ADF7ULL,
		0xFE52A775024760FBULL,
		0x39DE5EDB6CAE2676ULL
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
		0x6A37314A30375488ULL,
		0xEC6236DF197E23CAULL,
		0x03A88DDEC6F156A1ULL,
		0xEA621A38AD19C8A2ULL,
		0x981A15BB7174FE58ULL,
		0xE5C17284F9568D44ULL,
		0x147F90C8C3B150C8ULL,
		0x2E883406E20D58F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD46E6294606EA910ULL,
		0xD8C46DBE32FC4794ULL,
		0x07511BBD8DE2AD43ULL,
		0xD4C434715A339144ULL,
		0x30342B76E2E9FCB1ULL,
		0xCB82E509F2AD1A89ULL,
		0x28FF21918762A191ULL,
		0x5D10680DC41AB1E8ULL
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
		0x48B2A517416BBA7BULL,
		0x4FB82B51E1C46BB1ULL,
		0x18C606BEA49C585BULL,
		0x1581E620415AE411ULL,
		0xE1E061434A57B2BFULL,
		0x6441864A5B9ED3DEULL,
		0x2CF05C7A66CFA534ULL,
		0x10592AF0DBE101DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91654A2E82D774F6ULL,
		0x9F7056A3C388D762ULL,
		0x318C0D7D4938B0B6ULL,
		0x2B03CC4082B5C822ULL,
		0xC3C0C28694AF657EULL,
		0xC8830C94B73DA7BDULL,
		0x59E0B8F4CD9F4A68ULL,
		0x20B255E1B7C203B6ULL
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
		0x513888D3D44EBD3FULL,
		0x98D218ADFED86D1FULL,
		0x7B8B58C126FAF275ULL,
		0xEEE21D67DC91E35EULL,
		0x62C87695FA49DA05ULL,
		0x4B4A4C6BEDFE86AFULL,
		0x5D65551BFD94D4C4ULL,
		0x1B866E368A7E9E9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA27111A7A89D7A7EULL,
		0x31A4315BFDB0DA3EULL,
		0xF716B1824DF5E4EBULL,
		0xDDC43ACFB923C6BCULL,
		0xC590ED2BF493B40BULL,
		0x969498D7DBFD0D5EULL,
		0xBACAAA37FB29A988ULL,
		0x370CDC6D14FD3D36ULL
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
		0xE8125BE85DB236D2ULL,
		0xACCC77F8E0CEB0E7ULL,
		0xBDFDF24D32CDEB4BULL,
		0x2C07A0BDD553353BULL,
		0x47362DE56CD58201ULL,
		0xA58E7B7186E2A35DULL,
		0xB5EEF6CB733B2CB7ULL,
		0x3FBCF738AA5CD5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD024B7D0BB646DA4ULL,
		0x5998EFF1C19D61CFULL,
		0x7BFBE49A659BD697ULL,
		0x580F417BAAA66A77ULL,
		0x8E6C5BCAD9AB0402ULL,
		0x4B1CF6E30DC546BAULL,
		0x6BDDED96E676596FULL,
		0x7F79EE7154B9AB51ULL
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
		0xFC80362045A3B667ULL,
		0x04AFAB450DC8357AULL,
		0x8A4F2884B400A200ULL,
		0xB1B865B52EEB39B5ULL,
		0x364DA89E4ED2E30FULL,
		0x03439F0377D76B0DULL,
		0xE2E4E52738FE39E2ULL,
		0x07E4821BC245CD56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9006C408B476CCEULL,
		0x095F568A1B906AF5ULL,
		0x149E510968014400ULL,
		0x6370CB6A5DD6736BULL,
		0x6C9B513C9DA5C61FULL,
		0x06873E06EFAED61AULL,
		0xC5C9CA4E71FC73C4ULL,
		0x0FC90437848B9AADULL
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
		0x57DA5E6DFDE816D8ULL,
		0xB4073D5A77216E6AULL,
		0xA7F7C49EA1D6447EULL,
		0x3B5AF3FE0D735469ULL,
		0x3F8CEC5C4E2E6A0EULL,
		0x092EF1841A349471ULL,
		0xEBF0D635A2FC58BCULL,
		0x0EE8A1FD0BA55DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB4BCDBFBD02DB0ULL,
		0x680E7AB4EE42DCD4ULL,
		0x4FEF893D43AC88FDULL,
		0x76B5E7FC1AE6A8D3ULL,
		0x7F19D8B89C5CD41CULL,
		0x125DE308346928E2ULL,
		0xD7E1AC6B45F8B178ULL,
		0x1DD143FA174ABB7BULL
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
		0x30A8BD0C6D7CD900ULL,
		0xDF1DD9C4D1D18C13ULL,
		0xAC6677A365826DAAULL,
		0x32F4E432EA30697FULL,
		0x027DAB5143C84D9AULL,
		0x69411EF99E3EB5E4ULL,
		0x3387F1B4EA43EA81ULL,
		0x34ED35A58F02DA8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61517A18DAF9B200ULL,
		0xBE3BB389A3A31826ULL,
		0x58CCEF46CB04DB55ULL,
		0x65E9C865D460D2FFULL,
		0x04FB56A287909B34ULL,
		0xD2823DF33C7D6BC8ULL,
		0x670FE369D487D502ULL,
		0x69DA6B4B1E05B518ULL
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
		0x8F9EB3E70AFB631CULL,
		0x6B09E90BAC3D659BULL,
		0x774C92EE9F2043DAULL,
		0x659EEC36A6B00851ULL,
		0x627831E5F4D35AC2ULL,
		0x70B986B9DE1F4069ULL,
		0x49CE7A99D8FA6083ULL,
		0x0C23F3BFB86AD506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F3D67CE15F6C638ULL,
		0xD613D217587ACB37ULL,
		0xEE9925DD3E4087B4ULL,
		0xCB3DD86D4D6010A2ULL,
		0xC4F063CBE9A6B584ULL,
		0xE1730D73BC3E80D2ULL,
		0x939CF533B1F4C106ULL,
		0x1847E77F70D5AA0CULL
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
		0x5A63840E93C42306ULL,
		0x3FB4810184B37E83ULL,
		0xE3D284C219986D4DULL,
		0xB92A397B7D88D59FULL,
		0xDF19C30D8D6C9598ULL,
		0xAB7893306EDF3F52ULL,
		0xB7C28A6755159492ULL,
		0x06B40006F3F2FDD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C7081D2788460CULL,
		0x7F6902030966FD06ULL,
		0xC7A509843330DA9AULL,
		0x725472F6FB11AB3FULL,
		0xBE33861B1AD92B31ULL,
		0x56F12660DDBE7EA5ULL,
		0x6F8514CEAA2B2925ULL,
		0x0D68000DE7E5FBB1ULL
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
		0xB0CDA5F11CBDC6D9ULL,
		0x1236DB22E6CA0983ULL,
		0xE345C1DA43572E09ULL,
		0x095E56D9B62E9894ULL,
		0xF5D7A6E9CFCBAE31ULL,
		0x4C26E20A53DB3545ULL,
		0xF6FD36AB91C4323BULL,
		0x3C2D1B436D834D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619B4BE2397B8DB2ULL,
		0x246DB645CD941307ULL,
		0xC68B83B486AE5C12ULL,
		0x12BCADB36C5D3129ULL,
		0xEBAF4DD39F975C62ULL,
		0x984DC414A7B66A8BULL,
		0xEDFA6D5723886476ULL,
		0x785A3686DB069B07ULL
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
		0x18EAE1D34B7501B4ULL,
		0x6031243CB696184FULL,
		0x7E2DAACCBB79817AULL,
		0xD5940A162DB0AAFCULL,
		0xCBE622DFD34F9530ULL,
		0x629D9BA7A8AA06E8ULL,
		0xC2CEE21651A790C3ULL,
		0x3C4BBB6A558D1AB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D5C3A696EA0368ULL,
		0xC06248796D2C309EULL,
		0xFC5B559976F302F4ULL,
		0xAB28142C5B6155F8ULL,
		0x97CC45BFA69F2A61ULL,
		0xC53B374F51540DD1ULL,
		0x859DC42CA34F2186ULL,
		0x789776D4AB1A3571ULL
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
		0x3617A19870541F19ULL,
		0x833C8ABF57C47478ULL,
		0x977CA2E0F094C633ULL,
		0xFAE4DF3B553CF230ULL,
		0xF6B398261E9C6F71ULL,
		0x6BA9464E90935CE7ULL,
		0x017FD44E581919DBULL,
		0x12745BA373C80AD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C2F4330E0A83E32ULL,
		0x0679157EAF88E8F0ULL,
		0x2EF945C1E1298C67ULL,
		0xF5C9BE76AA79E461ULL,
		0xED67304C3D38DEE3ULL,
		0xD7528C9D2126B9CFULL,
		0x02FFA89CB03233B6ULL,
		0x24E8B746E79015A0ULL
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
		0x508991061B0077F7ULL,
		0xBC5AD2F1AAB0D02CULL,
		0x3B08FEB431E3912BULL,
		0x13E482954A2774D2ULL,
		0x221C5E150860FBB6ULL,
		0xF0645DB7103F534EULL,
		0xF50FFEB084B200C7ULL,
		0x0EA42CAB5B18D665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA113220C3600EFEEULL,
		0x78B5A5E35561A058ULL,
		0x7611FD6863C72257ULL,
		0x27C9052A944EE9A4ULL,
		0x4438BC2A10C1F76CULL,
		0xE0C8BB6E207EA69CULL,
		0xEA1FFD610964018FULL,
		0x1D485956B631ACCBULL
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
		0x0A842C88AD5A8E5FULL,
		0xA7F6EF03D0D18E61ULL,
		0x8F943EA90A4DCF42ULL,
		0xDE838EF134112DB5ULL,
		0xB497FFB8BCC1F798ULL,
		0x507EC977AD8FDAA7ULL,
		0xFDFD7AEB964743F6ULL,
		0x00F9F98C45E2BD8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150859115AB51CBEULL,
		0x4FEDDE07A1A31CC2ULL,
		0x1F287D52149B9E85ULL,
		0xBD071DE268225B6BULL,
		0x692FFF717983EF31ULL,
		0xA0FD92EF5B1FB54FULL,
		0xFBFAF5D72C8E87ECULL,
		0x01F3F3188BC57B17ULL
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
		0x480B23DBB65F732EULL,
		0x06158BB7F24B900BULL,
		0x48726A8AA68BF19EULL,
		0x6A09B438F4A636C9ULL,
		0x64EACDA2DDE5206CULL,
		0x355EF5F35F4210CBULL,
		0x608C45FEADFC512CULL,
		0x126D6BA8A5E09086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901647B76CBEE65CULL,
		0x0C2B176FE4972016ULL,
		0x90E4D5154D17E33CULL,
		0xD4136871E94C6D92ULL,
		0xC9D59B45BBCA40D8ULL,
		0x6ABDEBE6BE842196ULL,
		0xC1188BFD5BF8A258ULL,
		0x24DAD7514BC1210CULL
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
		0x03410E9E78E0FDEBULL,
		0x42C1AF9B4C116B5CULL,
		0x0293093985BE1687ULL,
		0xDC5EC2F2293A773FULL,
		0x719BC76AECA47BE3ULL,
		0x418F774284E7B315ULL,
		0x3C16D84BC37298D8ULL,
		0x156D75E662702AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06821D3CF1C1FBD6ULL,
		0x85835F369822D6B8ULL,
		0x052612730B7C2D0EULL,
		0xB8BD85E45274EE7EULL,
		0xE3378ED5D948F7C7ULL,
		0x831EEE8509CF662AULL,
		0x782DB09786E531B0ULL,
		0x2ADAEBCCC4E055ECULL
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
		0xB1058B94E62423A4ULL,
		0xC0456CEA48FB8697ULL,
		0xE91CCAFEFE05B7B3ULL,
		0xA2261B787FF9B450ULL,
		0xD1A253204E2DB52AULL,
		0x68A7B99A9A6B9128ULL,
		0xE6CE25F0DB33054CULL,
		0x05F9DCE967A7D0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x620B1729CC484748ULL,
		0x808AD9D491F70D2FULL,
		0xD23995FDFC0B6F67ULL,
		0x444C36F0FFF368A1ULL,
		0xA344A6409C5B6A55ULL,
		0xD14F733534D72251ULL,
		0xCD9C4BE1B6660A98ULL,
		0x0BF3B9D2CF4FA1EFULL
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
		0x6FD0524D76AC1344ULL,
		0x8AF1304EC4FCEDD0ULL,
		0x26B8E6FAA5548ED9ULL,
		0xE61847A57B418486ULL,
		0x9D58226007200724ULL,
		0xB91DC55C096E4BD1ULL,
		0xDA030EA50F329AF4ULL,
		0x05C3E428EDD1AE05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA0A49AED582688ULL,
		0x15E2609D89F9DBA0ULL,
		0x4D71CDF54AA91DB3ULL,
		0xCC308F4AF683090CULL,
		0x3AB044C00E400E49ULL,
		0x723B8AB812DC97A3ULL,
		0xB4061D4A1E6535E9ULL,
		0x0B87C851DBA35C0BULL
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
		0xD8ACF901B092DB05ULL,
		0x849EA0CF26FB24E4ULL,
		0xB416692B624A8AC3ULL,
		0x2E92090F1909812AULL,
		0x14D65977C7492BC1ULL,
		0x10E55D37E1C89500ULL,
		0x6A70A98C2C89C6CEULL,
		0x1A408CA27883DD3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB159F2036125B60AULL,
		0x093D419E4DF649C9ULL,
		0x682CD256C4951587ULL,
		0x5D24121E32130255ULL,
		0x29ACB2EF8E925782ULL,
		0x21CABA6FC3912A00ULL,
		0xD4E1531859138D9CULL,
		0x34811944F107BA78ULL
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
		0xDE0AF006D2B4037FULL,
		0xF0CA2DE8E0C8EE79ULL,
		0x7FBE3AAB766240F4ULL,
		0x27CE8480B425D135ULL,
		0x973C7DB0963F1602ULL,
		0x135B483031B78278ULL,
		0x3BDBBA9C0D57F273ULL,
		0x091C8DADAFD26A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC15E00DA56806FEULL,
		0xE1945BD1C191DCF3ULL,
		0xFF7C7556ECC481E9ULL,
		0x4F9D0901684BA26AULL,
		0x2E78FB612C7E2C04ULL,
		0x26B69060636F04F1ULL,
		0x77B775381AAFE4E6ULL,
		0x12391B5B5FA4D51EULL
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
		0x635CCDA71975838EULL,
		0xBFFE020B141BDCF7ULL,
		0xCC8D3A514089C635ULL,
		0xB8B642D7430B5A80ULL,
		0x603F25A5BB5AC8ABULL,
		0x9B95CBDC83658566ULL,
		0x9C574E3E51C9B9C7ULL,
		0x3D4058C8D61562C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B99B4E32EB071CULL,
		0x7FFC04162837B9EEULL,
		0x991A74A281138C6BULL,
		0x716C85AE8616B501ULL,
		0xC07E4B4B76B59157ULL,
		0x372B97B906CB0ACCULL,
		0x38AE9C7CA393738FULL,
		0x7A80B191AC2AC583ULL
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
		0xC39509253FCDF376ULL,
		0x8A62A00730BAA19BULL,
		0xCBD064439D5BF22CULL,
		0x6DA70BBE5DF7B9A7ULL,
		0x3FF4EF4D41F60E98ULL,
		0xBB9A58E303F9CF4BULL,
		0xF192D8AF158D03C3ULL,
		0x14A205EC5C3D8C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x872A124A7F9BE6ECULL,
		0x14C5400E61754337ULL,
		0x97A0C8873AB7E459ULL,
		0xDB4E177CBBEF734FULL,
		0x7FE9DE9A83EC1D30ULL,
		0x7734B1C607F39E96ULL,
		0xE325B15E2B1A0787ULL,
		0x29440BD8B87B182FULL
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
		0x403F72C0EB20BDF6ULL,
		0xBA633EB08BCA4312ULL,
		0x43307837EAA1FF48ULL,
		0x27FFED3E39A45B1CULL,
		0x69641D671E5323EEULL,
		0x8E385A281DD8419EULL,
		0xFD56147B8D398E19ULL,
		0x222C936DDE211421ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807EE581D6417BECULL,
		0x74C67D6117948624ULL,
		0x8660F06FD543FE91ULL,
		0x4FFFDA7C7348B638ULL,
		0xD2C83ACE3CA647DCULL,
		0x1C70B4503BB0833CULL,
		0xFAAC28F71A731C33ULL,
		0x445926DBBC422843ULL
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
		0x991EA177B5257B20ULL,
		0xE75E9EE1233E5A71ULL,
		0x2B3FB195A22F8FF2ULL,
		0x910299CDB76ACD53ULL,
		0xF077C337DBD380DEULL,
		0xE1E2869E655D665DULL,
		0xDEC245F647354336ULL,
		0x21734E78DF820454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323D42EF6A4AF640ULL,
		0xCEBD3DC2467CB4E3ULL,
		0x567F632B445F1FE5ULL,
		0x2205339B6ED59AA6ULL,
		0xE0EF866FB7A701BDULL,
		0xC3C50D3CCABACCBBULL,
		0xBD848BEC8E6A866DULL,
		0x42E69CF1BF0408A9ULL
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
		0xC2307333E74C385CULL,
		0x04A0D29E30A63A47ULL,
		0x818FFA292C5FC4E9ULL,
		0xDB6BE8EC46B517B1ULL,
		0x980B97B5D6B0F82DULL,
		0x6730FCB86090D8DEULL,
		0x9200A898A5B9F5F9ULL,
		0x0429659AD799B272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8460E667CE9870B8ULL,
		0x0941A53C614C748FULL,
		0x031FF45258BF89D2ULL,
		0xB6D7D1D88D6A2F63ULL,
		0x30172F6BAD61F05BULL,
		0xCE61F970C121B1BDULL,
		0x240151314B73EBF2ULL,
		0x0852CB35AF3364E5ULL
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
		0x45BA7E30DEF4BB26ULL,
		0x12AD8FCD8129CA34ULL,
		0x4EF735ABD9D8C9F4ULL,
		0x8F489B96DE6851ACULL,
		0x9D573BE572E80134ULL,
		0xFA9D725CDB430D13ULL,
		0x27EDD4DFB4761A84ULL,
		0x3B8991A467B3F7E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B74FC61BDE9764CULL,
		0x255B1F9B02539468ULL,
		0x9DEE6B57B3B193E8ULL,
		0x1E91372DBCD0A358ULL,
		0x3AAE77CAE5D00269ULL,
		0xF53AE4B9B6861A27ULL,
		0x4FDBA9BF68EC3509ULL,
		0x77132348CF67EFD2ULL
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
		0x19910023CE98B094ULL,
		0x3C526DC04B3F30DAULL,
		0x1F1AAE25FBF11504ULL,
		0x4EA9E83B5CEF8C95ULL,
		0x1E4806AF1B502E0CULL,
		0xD82EB75F52536AC7ULL,
		0xB14D0A22B1AD3BB4ULL,
		0x00ACBDE7FC524A9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x332200479D316128ULL,
		0x78A4DB80967E61B4ULL,
		0x3E355C4BF7E22A08ULL,
		0x9D53D076B9DF192AULL,
		0x3C900D5E36A05C18ULL,
		0xB05D6EBEA4A6D58EULL,
		0x629A1445635A7769ULL,
		0x01597BCFF8A4953BULL
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
		0x0DDB7FDB239CF71EULL,
		0xB68B3B409E590874ULL,
		0x7AB2E358D92DE261ULL,
		0xBDEE35D70E4F7EE4ULL,
		0x78B2DC23B3D6451AULL,
		0x566E00AF1AD75AEDULL,
		0x4B83CD6890130BD8ULL,
		0x27659BEBD0081774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BB6FFB64739EE3CULL,
		0x6D1676813CB210E8ULL,
		0xF565C6B1B25BC4C3ULL,
		0x7BDC6BAE1C9EFDC8ULL,
		0xF165B84767AC8A35ULL,
		0xACDC015E35AEB5DAULL,
		0x97079AD1202617B0ULL,
		0x4ECB37D7A0102EE8ULL
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
		0x23BE20CA79BE19B5ULL,
		0x6B654F22D32DDE29ULL,
		0x834B8842950C3E41ULL,
		0x2465FB90E761A1C3ULL,
		0x71B704F1F429BABBULL,
		0x0761ACE79DF53A33ULL,
		0xF0C69A4BDEE9AB0FULL,
		0x05A2448D83E553A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x477C4194F37C336AULL,
		0xD6CA9E45A65BBC52ULL,
		0x069710852A187C82ULL,
		0x48CBF721CEC34387ULL,
		0xE36E09E3E8537576ULL,
		0x0EC359CF3BEA7466ULL,
		0xE18D3497BDD3561EULL,
		0x0B44891B07CAA747ULL
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
		0xF4141DBA2E4EFF2BULL,
		0xDA973ABF4D5D468DULL,
		0xEE21CFED7679B037ULL,
		0x7ED934F341768788ULL,
		0x24519EB53C9ECAF3ULL,
		0xD903B264EE7CE0E8ULL,
		0xFAD8028DCFCBA9C4ULL,
		0x3A8C90975F24C425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8283B745C9DFE56ULL,
		0xB52E757E9ABA8D1BULL,
		0xDC439FDAECF3606FULL,
		0xFDB269E682ED0F11ULL,
		0x48A33D6A793D95E6ULL,
		0xB20764C9DCF9C1D0ULL,
		0xF5B0051B9F975389ULL,
		0x7519212EBE49884BULL
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
		0xCA0FFF42FC8B623AULL,
		0x69257B7D98EB409DULL,
		0x1AADEF7E26E1AFE7ULL,
		0x08B9E2FB977DC0E5ULL,
		0xAAF2DCA83C214AAEULL,
		0x76683963ECE4ADCAULL,
		0xE11D1DDE231313B5ULL,
		0x32DEBCBCF872D4B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x941FFE85F916C474ULL,
		0xD24AF6FB31D6813BULL,
		0x355BDEFC4DC35FCEULL,
		0x1173C5F72EFB81CAULL,
		0x55E5B9507842955CULL,
		0xECD072C7D9C95B95ULL,
		0xC23A3BBC4626276AULL,
		0x65BD7979F0E5A967ULL
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
		0x546CA978F90B79FDULL,
		0xCFF1BCB9988DD332ULL,
		0x63C8F1657EAE3FBFULL,
		0x463981E6CBE922D0ULL,
		0xD25572FBBECDD27CULL,
		0x4B8E6AA8B9682522ULL,
		0x190D846B1777D6DAULL,
		0x1B6B3127CA3634FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D952F1F216F3FAULL,
		0x9FE37973311BA664ULL,
		0xC791E2CAFD5C7F7FULL,
		0x8C7303CD97D245A0ULL,
		0xA4AAE5F77D9BA4F8ULL,
		0x971CD55172D04A45ULL,
		0x321B08D62EEFADB4ULL,
		0x36D6624F946C69FAULL
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
		0x6B4563633FA9C2D5ULL,
		0xFD7EA6199865B83EULL,
		0xE8C20CE54BEDE576ULL,
		0x328889E9BECEE3E6ULL,
		0x7011F8E54FE11B01ULL,
		0xF1FB6E4EC8B053EBULL,
		0xD2DE855A34F6F73AULL,
		0x34EF5F1D148119DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD68AC6C67F5385AAULL,
		0xFAFD4C3330CB707CULL,
		0xD18419CA97DBCAEDULL,
		0x651113D37D9DC7CDULL,
		0xE023F1CA9FC23602ULL,
		0xE3F6DC9D9160A7D6ULL,
		0xA5BD0AB469EDEE75ULL,
		0x69DEBE3A290233BDULL
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
		0x83B4FA48E2227C45ULL,
		0x6EF9C976747AD334ULL,
		0xCF3E611078ADC1ADULL,
		0x7D60FB401647F4B7ULL,
		0xC40C27D232E911AFULL,
		0x9DECAD2F847EB90BULL,
		0x7D043A8DC670C36CULL,
		0x3ED6C919D2CCD9FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0769F491C444F88AULL,
		0xDDF392ECE8F5A669ULL,
		0x9E7CC220F15B835AULL,
		0xFAC1F6802C8FE96FULL,
		0x88184FA465D2235EULL,
		0x3BD95A5F08FD7217ULL,
		0xFA08751B8CE186D9ULL,
		0x7DAD9233A599B3FCULL
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
		0x752E2AEFC05BF7ECULL,
		0x7A011254ED3E1853ULL,
		0x68045116210820C8ULL,
		0xB8598C0BD1F2D991ULL,
		0xDA3917A7AA3BC4A3ULL,
		0xAF1E99164AEDFDA7ULL,
		0x6932C8E26DD6EA52ULL,
		0x01EA9FCEFA005906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA5C55DF80B7EFD8ULL,
		0xF40224A9DA7C30A6ULL,
		0xD008A22C42104190ULL,
		0x70B31817A3E5B322ULL,
		0xB4722F4F54778947ULL,
		0x5E3D322C95DBFB4FULL,
		0xD26591C4DBADD4A5ULL,
		0x03D53F9DF400B20CULL
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
		0xDBD3F273C5530EDCULL,
		0xB393665394440E77ULL,
		0xE50B87C3B3F556D1ULL,
		0xCCDCE7F9595C2FD0ULL,
		0x0E51DC470C44C32FULL,
		0x077F63D9F286EB2DULL,
		0x930B825474A34ED7ULL,
		0x2FFDAE40540B0128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7A7E4E78AA61DB8ULL,
		0x6726CCA728881CEFULL,
		0xCA170F8767EAADA3ULL,
		0x99B9CFF2B2B85FA1ULL,
		0x1CA3B88E1889865FULL,
		0x0EFEC7B3E50DD65AULL,
		0x261704A8E9469DAEULL,
		0x5FFB5C80A8160251ULL
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
		0xD14BED8A4FD881A4ULL,
		0xF11D2F0F0E8815DDULL,
		0x4D5B9DA8B7659F2FULL,
		0x07CCE11089E5BDEEULL,
		0x10E33477B4020917ULL,
		0x89A0BA67E41F356AULL,
		0x20E06F92A241F989ULL,
		0x3A792ECC9D919F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA297DB149FB10348ULL,
		0xE23A5E1E1D102BBBULL,
		0x9AB73B516ECB3E5FULL,
		0x0F99C22113CB7BDCULL,
		0x21C668EF6804122EULL,
		0x134174CFC83E6AD4ULL,
		0x41C0DF254483F313ULL,
		0x74F25D993B233E48ULL
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
		0x7E9B524DE4621D4CULL,
		0x03D9EB8531B9962AULL,
		0x3CFB721D5414EE6BULL,
		0x5C8D671BD1BA759BULL,
		0x55507B13843E1876ULL,
		0x9BBF382A1AEE007DULL,
		0xBF2318A55FF42A97ULL,
		0x38E9E066EC334E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD36A49BC8C43A98ULL,
		0x07B3D70A63732C54ULL,
		0x79F6E43AA829DCD6ULL,
		0xB91ACE37A374EB36ULL,
		0xAAA0F627087C30ECULL,
		0x377E705435DC00FAULL,
		0x7E46314ABFE8552FULL,
		0x71D3C0CDD8669C13ULL
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
		0x0B4986E76C0F420BULL,
		0xB07837C6ECF546BAULL,
		0xB88FE2FBD9B05A06ULL,
		0xAB54E48DA44F5710ULL,
		0xE56CF5B62F171C37ULL,
		0x2E03F6126BC375E6ULL,
		0xCCDF90534216CE43ULL,
		0x1061AD2FBE82CEF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16930DCED81E8416ULL,
		0x60F06F8DD9EA8D74ULL,
		0x711FC5F7B360B40DULL,
		0x56A9C91B489EAE21ULL,
		0xCAD9EB6C5E2E386FULL,
		0x5C07EC24D786EBCDULL,
		0x99BF20A6842D9C86ULL,
		0x20C35A5F7D059DF3ULL
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
		0x88142752ED6FA629ULL,
		0x52894EF7CF77F6BEULL,
		0x893395891DDEB6FAULL,
		0x6C43B4D06D2CA87DULL,
		0x5B7F4D213B5F7C5FULL,
		0x4921B6D4BA109B73ULL,
		0x039F63968632775EULL,
		0x2DFB8C9EAACB3D80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10284EA5DADF4C52ULL,
		0xA5129DEF9EEFED7DULL,
		0x12672B123BBD6DF4ULL,
		0xD88769A0DA5950FBULL,
		0xB6FE9A4276BEF8BEULL,
		0x92436DA9742136E6ULL,
		0x073EC72D0C64EEBCULL,
		0x5BF7193D55967B00ULL
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
		0x6879ADFBD2DF0B87ULL,
		0x68CBFCBE6F0AA20CULL,
		0xEF73522AEB84E868ULL,
		0x3AAD288F06AAC2DEULL,
		0x39134E7FF73B0139ULL,
		0x64F4EE6684EF4187ULL,
		0x03FB8DFC98FE8868ULL,
		0x22885E102F156614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0F35BF7A5BE170EULL,
		0xD197F97CDE154418ULL,
		0xDEE6A455D709D0D0ULL,
		0x755A511E0D5585BDULL,
		0x72269CFFEE760272ULL,
		0xC9E9DCCD09DE830EULL,
		0x07F71BF931FD10D0ULL,
		0x4510BC205E2ACC28ULL
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
		0xAA99AB723149B464ULL,
		0x4433C3D0027DECA3ULL,
		0x6F65C2861A4924A7ULL,
		0xC6CBC75A7C80DA24ULL,
		0xE0B1BAFA7C02296EULL,
		0x1D9186524CFD2A8FULL,
		0x4743128AA1C78E96ULL,
		0x0F682228404F8189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x553356E4629368C8ULL,
		0x886787A004FBD947ULL,
		0xDECB850C3492494EULL,
		0x8D978EB4F901B448ULL,
		0xC16375F4F80452DDULL,
		0x3B230CA499FA551FULL,
		0x8E862515438F1D2CULL,
		0x1ED04450809F0312ULL
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
		0x566F92CEE6B47A9AULL,
		0x52DC9C91528262CEULL,
		0xE6556A80DD3EBD73ULL,
		0x55418FC844F1FC19ULL,
		0x94063061D3CD5F3EULL,
		0x72B7EA29A576F65DULL,
		0xDF2BED926559D55BULL,
		0x2AD5B45B6572C505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACDF259DCD68F534ULL,
		0xA5B93922A504C59CULL,
		0xCCAAD501BA7D7AE6ULL,
		0xAA831F9089E3F833ULL,
		0x280C60C3A79ABE7CULL,
		0xE56FD4534AEDECBBULL,
		0xBE57DB24CAB3AAB6ULL,
		0x55AB68B6CAE58A0BULL
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
		0xA69694B2511323F7ULL,
		0x6BFB3C8FAFA22583ULL,
		0xC7F9DCE3DB7B63E3ULL,
		0xB453216914AAAC54ULL,
		0xAC313BA54B36556EULL,
		0x78D3400796BE95C3ULL,
		0x390D7A171EFB4E19ULL,
		0x19B68AA62678EA7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D2D2964A22647EEULL,
		0xD7F6791F5F444B07ULL,
		0x8FF3B9C7B6F6C7C6ULL,
		0x68A642D2295558A9ULL,
		0x5862774A966CAADDULL,
		0xF1A6800F2D7D2B87ULL,
		0x721AF42E3DF69C32ULL,
		0x336D154C4CF1D4FCULL
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
		0x364BDA66E5CB6444ULL,
		0x5B3D885B867230EAULL,
		0x7CDFBF4A8581B799ULL,
		0x57DA1B629E3A702EULL,
		0x3EED4BB62F3EDE05ULL,
		0xA01F75602CF7C3CFULL,
		0xEFB682FDCB18A2F6ULL,
		0x37721E3B33C1FC4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C97B4CDCB96C888ULL,
		0xB67B10B70CE461D4ULL,
		0xF9BF7E950B036F32ULL,
		0xAFB436C53C74E05CULL,
		0x7DDA976C5E7DBC0AULL,
		0x403EEAC059EF879EULL,
		0xDF6D05FB963145EDULL,
		0x6EE43C766783F89FULL
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
		0xBF7EF5CA17203142ULL,
		0x36B595BEBE9E384AULL,
		0x03E180D0AB2E413CULL,
		0x31585AF6CBD8C834ULL,
		0x7491A9B2BF3AB777ULL,
		0xCF4002570F26CCFCULL,
		0xF2C5CF26FF31F248ULL,
		0x0ABA807BF220297EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EFDEB942E406284ULL,
		0x6D6B2B7D7D3C7095ULL,
		0x07C301A1565C8278ULL,
		0x62B0B5ED97B19068ULL,
		0xE92353657E756EEEULL,
		0x9E8004AE1E4D99F8ULL,
		0xE58B9E4DFE63E491ULL,
		0x157500F7E44052FDULL
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
		0xD807B23B1B6ACCF2ULL,
		0x6E6DE02DBD38591EULL,
		0xFA18ED1F1D4B8177ULL,
		0x816119AE028A4245ULL,
		0x0DB7D806D53FBEAEULL,
		0x4CB6E88367048148ULL,
		0xFE3A66C73F8B32BFULL,
		0x1BB99AB3A1298E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB00F647636D599E4ULL,
		0xDCDBC05B7A70B23DULL,
		0xF431DA3E3A9702EEULL,
		0x02C2335C0514848BULL,
		0x1B6FB00DAA7F7D5DULL,
		0x996DD106CE090290ULL,
		0xFC74CD8E7F16657EULL,
		0x3773356742531CA9ULL
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
		0x08B42D8D3F3A52E8ULL,
		0x96AC3C3313743231ULL,
		0x3E366CD0ADB2A252ULL,
		0x05CC401DEC675B40ULL,
		0xDA1699D8E1EA8000ULL,
		0xA326A0F7F0102822ULL,
		0xA1A94CA54BB7C77EULL,
		0x367F232F17F5A57EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11685B1A7E74A5D0ULL,
		0x2D58786626E86462ULL,
		0x7C6CD9A15B6544A5ULL,
		0x0B98803BD8CEB680ULL,
		0xB42D33B1C3D50000ULL,
		0x464D41EFE0205045ULL,
		0x4352994A976F8EFDULL,
		0x6CFE465E2FEB4AFDULL
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
		0xFD35E658F1A7788DULL,
		0x1ED8BF6B2D0CE2AEULL,
		0x6243D18A11717AF4ULL,
		0xAB279C62AE4F2C80ULL,
		0x6C6CFFA6CDEF05EBULL,
		0x860E01429B3549D8ULL,
		0x30DC509AD548D4F1ULL,
		0x3D1F0F73A61CFB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA6BCCB1E34EF11AULL,
		0x3DB17ED65A19C55DULL,
		0xC487A31422E2F5E8ULL,
		0x564F38C55C9E5900ULL,
		0xD8D9FF4D9BDE0BD7ULL,
		0x0C1C0285366A93B0ULL,
		0x61B8A135AA91A9E3ULL,
		0x7A3E1EE74C39F68EULL
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
		0xAB24FA73EA4016C3ULL,
		0x8B6376CB0223390BULL,
		0x421FDA60BF239565ULL,
		0x450536157F07360FULL,
		0x5EF308DAABAE40B0ULL,
		0x88D8DD941EB252E2ULL,
		0xDBB9E70602386A06ULL,
		0x1185F5EDD0386639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5649F4E7D4802D86ULL,
		0x16C6ED9604467217ULL,
		0x843FB4C17E472ACBULL,
		0x8A0A6C2AFE0E6C1EULL,
		0xBDE611B5575C8160ULL,
		0x11B1BB283D64A5C4ULL,
		0xB773CE0C0470D40DULL,
		0x230BEBDBA070CC73ULL
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
		0x7946AFB6C7B76435ULL,
		0x517A2BCE86D12B3AULL,
		0xE8E4F7702888FDA5ULL,
		0xF8448D0C35270E40ULL,
		0xFCC1D94F314DE5A1ULL,
		0x5EBE345FB53B4AFFULL,
		0x7124C6FC13F8FAF9ULL,
		0x1BC6D2B37B36247FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28D5F6D8F6EC86AULL,
		0xA2F4579D0DA25674ULL,
		0xD1C9EEE05111FB4AULL,
		0xF0891A186A4E1C81ULL,
		0xF983B29E629BCB43ULL,
		0xBD7C68BF6A7695FFULL,
		0xE2498DF827F1F5F2ULL,
		0x378DA566F66C48FEULL
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
		0x03C3E5F06C85F719ULL,
		0x3BF24588441AB77DULL,
		0x3CF9C7DE336A248AULL,
		0x52F82FCE2A9D6EABULL,
		0x1EB248F0900683A2ULL,
		0x318F7D2F9EDE0ED8ULL,
		0xF332529B840BF27CULL,
		0x1DBA448536029889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0787CBE0D90BEE32ULL,
		0x77E48B1088356EFAULL,
		0x79F38FBC66D44914ULL,
		0xA5F05F9C553ADD56ULL,
		0x3D6491E1200D0744ULL,
		0x631EFA5F3DBC1DB0ULL,
		0xE664A5370817E4F8ULL,
		0x3B74890A6C053113ULL
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
		0xAFFB63D8F57B3567ULL,
		0x513FFFEFE891DDAAULL,
		0xEAD1DB2B1917089FULL,
		0x294D7724BE879C91ULL,
		0x6D9639CDE6591940ULL,
		0x23FD95FEECD9C3DAULL,
		0x4CFC3690EEBF3088ULL,
		0x2323D7BE01FFCB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF6C7B1EAF66ACEULL,
		0xA27FFFDFD123BB55ULL,
		0xD5A3B656322E113EULL,
		0x529AEE497D0F3923ULL,
		0xDB2C739BCCB23280ULL,
		0x47FB2BFDD9B387B4ULL,
		0x99F86D21DD7E6110ULL,
		0x4647AF7C03FF9700ULL
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
		0x4B21219D1B766915ULL,
		0xD40A9C273C75B711ULL,
		0x4F9EAB744B55DB00ULL,
		0x46314ECB7DDBBEFEULL,
		0xB159F82DE8C2C3B9ULL,
		0x91788A76D6F01A67ULL,
		0xB0286DCBFE99CABFULL,
		0x0DA26AC47EE05442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9642433A36ECD22AULL,
		0xA815384E78EB6E22ULL,
		0x9F3D56E896ABB601ULL,
		0x8C629D96FBB77DFCULL,
		0x62B3F05BD1858772ULL,
		0x22F114EDADE034CFULL,
		0x6050DB97FD33957FULL,
		0x1B44D588FDC0A885ULL
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
		0x264263C79E74D24BULL,
		0x182F8F86506B6986ULL,
		0x0A11F9B26108BB60ULL,
		0x6B210DED0BE2128FULL,
		0xEEEFED90199A165FULL,
		0x4F297A3FDD7D1FE2ULL,
		0x9E0893C299E15C64ULL,
		0x2ABDE82F39F4F094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C84C78F3CE9A496ULL,
		0x305F1F0CA0D6D30CULL,
		0x1423F364C21176C0ULL,
		0xD6421BDA17C4251EULL,
		0xDDDFDB2033342CBEULL,
		0x9E52F47FBAFA3FC5ULL,
		0x3C11278533C2B8C8ULL,
		0x557BD05E73E9E129ULL
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
		0xF6774711287401B5ULL,
		0x34BAA8C87575F529ULL,
		0xAF4DAEF1920BD14AULL,
		0x245FF03266848EC5ULL,
		0x9D695507762CA770ULL,
		0x95B43F8A0B5C6926ULL,
		0x724E5165F19B5518ULL,
		0x2F5B5090AC60D149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECEE8E2250E8036AULL,
		0x69755190EAEBEA53ULL,
		0x5E9B5DE32417A294ULL,
		0x48BFE064CD091D8BULL,
		0x3AD2AA0EEC594EE0ULL,
		0x2B687F1416B8D24DULL,
		0xE49CA2CBE336AA31ULL,
		0x5EB6A12158C1A292ULL
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
		0x396AE877C0955BE3ULL,
		0x980F57F2F2A40E9AULL,
		0x3645A3540A9B7210ULL,
		0xBB004BC37E9A8051ULL,
		0x493B6E67602BD14DULL,
		0x0C65BD0130A107FDULL,
		0x69A27390749CBD15ULL,
		0x3FCBCD57D6D05101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D5D0EF812AB7C6ULL,
		0x301EAFE5E5481D34ULL,
		0x6C8B46A81536E421ULL,
		0x76009786FD3500A2ULL,
		0x9276DCCEC057A29BULL,
		0x18CB7A0261420FFAULL,
		0xD344E720E9397A2AULL,
		0x7F979AAFADA0A202ULL
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
		0x86C13FC4FC901F20ULL,
		0x7A82547BEB1E2CC1ULL,
		0x0E06965E2E449D11ULL,
		0xD51E1CFA2F5A2432ULL,
		0xD728968DC348E36EULL,
		0x3171D4095F72F6A6ULL,
		0x9D4233B2DBBAEE86ULL,
		0x3E12B365DCE84D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D827F89F9203E40ULL,
		0xF504A8F7D63C5983ULL,
		0x1C0D2CBC5C893A22ULL,
		0xAA3C39F45EB44864ULL,
		0xAE512D1B8691C6DDULL,
		0x62E3A812BEE5ED4DULL,
		0x3A846765B775DD0CULL,
		0x7C2566CBB9D09ADBULL
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
		0x9F7C9FDACA1E9158ULL,
		0xF269161AF54B7211ULL,
		0x7DC828532E159FD3ULL,
		0x723F52F04CB36288ULL,
		0x0456B4FF2A06BB03ULL,
		0xBAFB9F2EB90B6A6CULL,
		0x56DA81390E77506CULL,
		0x349C79F3DA843C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EF93FB5943D22B0ULL,
		0xE4D22C35EA96E423ULL,
		0xFB9050A65C2B3FA7ULL,
		0xE47EA5E09966C510ULL,
		0x08AD69FE540D7606ULL,
		0x75F73E5D7216D4D8ULL,
		0xADB502721CEEA0D9ULL,
		0x6938F3E7B50878A4ULL
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
		0x6EC58EFF09B3588DULL,
		0x9F9E08EF1A1FF7AAULL,
		0x3A5E79924DE1C41DULL,
		0xB52608C02F00992EULL,
		0xD8B086B8080C747EULL,
		0xB8D12D1745B4DD11ULL,
		0x9B35135A2BE7B773ULL,
		0x0F310F6D28C2ACC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD8B1DFE1366B11AULL,
		0x3F3C11DE343FEF54ULL,
		0x74BCF3249BC3883BULL,
		0x6A4C11805E01325CULL,
		0xB1610D701018E8FDULL,
		0x71A25A2E8B69BA23ULL,
		0x366A26B457CF6EE7ULL,
		0x1E621EDA5185598FULL
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
		0xEF6DE0FE6135073AULL,
		0x86A488F552898E32ULL,
		0x2E8A4B56950D52ABULL,
		0xB113BC53015B664BULL,
		0xB069C4677CE690F8ULL,
		0xB45ED8EF7EBAE953ULL,
		0x90A3E06474A6A4E7ULL,
		0x3ADD8267C1BE8EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEDBC1FCC26A0E74ULL,
		0x0D4911EAA5131C65ULL,
		0x5D1496AD2A1AA557ULL,
		0x622778A602B6CC96ULL,
		0x60D388CEF9CD21F1ULL,
		0x68BDB1DEFD75D2A7ULL,
		0x2147C0C8E94D49CFULL,
		0x75BB04CF837D1D91ULL
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
		0x946CCBF59CDCDED9ULL,
		0xDEF5252298C00218ULL,
		0x8A3C96D057CDC7A7ULL,
		0xCDC8E1B8AC5405E4ULL,
		0x3BA375C5C45EC91CULL,
		0x86093A932DBB1F53ULL,
		0x6028D5B8DF7EC495ULL,
		0x0DEEA790CD91E817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D997EB39B9BDB2ULL,
		0xBDEA4A4531800431ULL,
		0x14792DA0AF9B8F4FULL,
		0x9B91C37158A80BC9ULL,
		0x7746EB8B88BD9239ULL,
		0x0C1275265B763EA6ULL,
		0xC051AB71BEFD892BULL,
		0x1BDD4F219B23D02EULL
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
		0x7C186E138A8249F7ULL,
		0xBC9311752F217A58ULL,
		0xD7BE794F75D39805ULL,
		0x1BEF7E8F164D7781ULL,
		0x71B3E47A738A62EDULL,
		0x60019B2DA09A2D37ULL,
		0xF0D6F2B37B4B0785ULL,
		0x1E861ADA868E89EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF830DC27150493EEULL,
		0x792622EA5E42F4B0ULL,
		0xAF7CF29EEBA7300BULL,
		0x37DEFD1E2C9AEF03ULL,
		0xE367C8F4E714C5DAULL,
		0xC003365B41345A6EULL,
		0xE1ADE566F6960F0AULL,
		0x3D0C35B50D1D13D7ULL
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
		0x7A86CED674B12D9EULL,
		0xFD3F5C2AEAF6EB7CULL,
		0xA37C9752888EDA75ULL,
		0x4FF65A99A7299F42ULL,
		0xBC9C8F5D76DF424BULL,
		0x04B255B5C2A03846ULL,
		0x7BFC3832AF4AA3F1ULL,
		0x0A8308A18FA2056AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF50D9DACE9625B3CULL,
		0xFA7EB855D5EDD6F8ULL,
		0x46F92EA5111DB4EBULL,
		0x9FECB5334E533E85ULL,
		0x79391EBAEDBE8496ULL,
		0x0964AB6B8540708DULL,
		0xF7F870655E9547E2ULL,
		0x150611431F440AD4ULL
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
		0xFC4C50D2F3245A47ULL,
		0xEC86A4F19DB5A827ULL,
		0xDD27D615BF6FDDFEULL,
		0x0F184E4F07F5734FULL,
		0x7F64D1F11A66BCC1ULL,
		0xF9455D6630E3D0D1ULL,
		0x9F499621490453ACULL,
		0x24B435EA6AAC969EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF898A1A5E648B48EULL,
		0xD90D49E33B6B504FULL,
		0xBA4FAC2B7EDFBBFDULL,
		0x1E309C9E0FEAE69FULL,
		0xFEC9A3E234CD7982ULL,
		0xF28ABACC61C7A1A2ULL,
		0x3E932C429208A759ULL,
		0x49686BD4D5592D3DULL
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
		0x6DAB40DBCB2A8FD5ULL,
		0x0FDCD37A239F5D86ULL,
		0xF329EBAFC7130DBCULL,
		0x4663CCED092F25FEULL,
		0x7CED259744C8B40CULL,
		0xB2B55521174A2B08ULL,
		0x65D89FD49500C564ULL,
		0x13930D868E6A654EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB5681B796551FAAULL,
		0x1FB9A6F4473EBB0CULL,
		0xE653D75F8E261B78ULL,
		0x8CC799DA125E4BFDULL,
		0xF9DA4B2E89916818ULL,
		0x656AAA422E945610ULL,
		0xCBB13FA92A018AC9ULL,
		0x27261B0D1CD4CA9CULL
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
		0xA6CB86832B64D398ULL,
		0x0B95E84909C36B66ULL,
		0x71E6EDC5F1257795ULL,
		0xF30F5F2EF6EC2704ULL,
		0x3E7206803DF67B6CULL,
		0x18E7C401C968DDFEULL,
		0x6698AD71EEDD96DBULL,
		0x1500EF001A537A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D970D0656C9A730ULL,
		0x172BD0921386D6CDULL,
		0xE3CDDB8BE24AEF2AULL,
		0xE61EBE5DEDD84E08ULL,
		0x7CE40D007BECF6D9ULL,
		0x31CF880392D1BBFCULL,
		0xCD315AE3DDBB2DB6ULL,
		0x2A01DE0034A6F4F2ULL
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
		0xA82B2C0491B83C93ULL,
		0xCB2DC54B39DE50D9ULL,
		0x252C8CC3B9853835ULL,
		0x834D669E26BF8CC7ULL,
		0x08627CB762FA0963ULL,
		0x42B12A3F43612189ULL,
		0x8DC134CF2341465FULL,
		0x0D4CAB826C117BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5056580923707926ULL,
		0x965B8A9673BCA1B3ULL,
		0x4A591987730A706BULL,
		0x069ACD3C4D7F198EULL,
		0x10C4F96EC5F412C7ULL,
		0x8562547E86C24312ULL,
		0x1B82699E46828CBEULL,
		0x1A995704D822F74DULL
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
		0xA22ABD1D524748CFULL,
		0x89424912229BF9D0ULL,
		0x63CAAE8D7BEC6297ULL,
		0x6C5D7A96AEC79397ULL,
		0xEA24EFCC02AEAD44ULL,
		0xAF90FB46C101EC77ULL,
		0x6079F51C35423CEFULL,
		0x0BEB538C3FD66EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44557A3AA48E919EULL,
		0x128492244537F3A1ULL,
		0xC7955D1AF7D8C52FULL,
		0xD8BAF52D5D8F272EULL,
		0xD449DF98055D5A88ULL,
		0x5F21F68D8203D8EFULL,
		0xC0F3EA386A8479DFULL,
		0x17D6A7187FACDDD2ULL
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
		0x57EF84C8EF0AEC6BULL,
		0xA879C75923787F45ULL,
		0xEA28B9AA21A10607ULL,
		0x14EDEEE9B4F36DF0ULL,
		0x21251DDD4C1E3D66ULL,
		0x0833490FE6D01BE4ULL,
		0x6DB60C0B51C3B0A1ULL,
		0x0ABAE376CB2F9473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFDF0991DE15D8D6ULL,
		0x50F38EB246F0FE8AULL,
		0xD451735443420C0FULL,
		0x29DBDDD369E6DBE1ULL,
		0x424A3BBA983C7ACCULL,
		0x1066921FCDA037C8ULL,
		0xDB6C1816A3876142ULL,
		0x1575C6ED965F28E6ULL
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
		0xA59D98B73095F26BULL,
		0x3247725D993928FCULL,
		0xFA8F594C31D1DB52ULL,
		0xA4A6F6B83433ACC9ULL,
		0x5820D0436BA1DBD3ULL,
		0x8C79621ACB055B27ULL,
		0xD83E22E2419DA55AULL,
		0x374BC70956B4B94FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B3B316E612BE4D6ULL,
		0x648EE4BB327251F9ULL,
		0xF51EB29863A3B6A4ULL,
		0x494DED7068675993ULL,
		0xB041A086D743B7A7ULL,
		0x18F2C435960AB64EULL,
		0xB07C45C4833B4AB5ULL,
		0x6E978E12AD69729FULL
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
		0x70064B2E18F16AD4ULL,
		0xDFE87831F97329EBULL,
		0x064191B5CC9AF631ULL,
		0xC5923FD8F229917DULL,
		0xEF73751BF41E42E8ULL,
		0x6D4F4165D3E86D16ULL,
		0x4F4D4156E6594E2EULL,
		0x28C6B0E2DDC16FE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00C965C31E2D5A8ULL,
		0xBFD0F063F2E653D6ULL,
		0x0C83236B9935EC63ULL,
		0x8B247FB1E45322FAULL,
		0xDEE6EA37E83C85D1ULL,
		0xDA9E82CBA7D0DA2DULL,
		0x9E9A82ADCCB29C5CULL,
		0x518D61C5BB82DFD0ULL
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
		0xE2272D4B2214AD3CULL,
		0x9203091C16362F6EULL,
		0xAD0600587216982FULL,
		0x7EE9B56FF972B799ULL,
		0x58232EA6C4EA1933ULL,
		0x9F32D336A0E6366CULL,
		0xCDD1A5F5F47A3E5BULL,
		0x0565B27AC6B801A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC44E5A9644295A78ULL,
		0x240612382C6C5EDDULL,
		0x5A0C00B0E42D305FULL,
		0xFDD36ADFF2E56F33ULL,
		0xB0465D4D89D43266ULL,
		0x3E65A66D41CC6CD8ULL,
		0x9BA34BEBE8F47CB7ULL,
		0x0ACB64F58D70034FULL
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
		0xC09E6E5A2D63384CULL,
		0x07456FF5704E7C29ULL,
		0x847DFF84AC88FE27ULL,
		0x005F09245A8FCDE5ULL,
		0xE74119B040C54AA9ULL,
		0x170662EFF52D55EAULL,
		0x2A4241E6537731D7ULL,
		0x3758E81778EA16F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x813CDCB45AC67098ULL,
		0x0E8ADFEAE09CF853ULL,
		0x08FBFF095911FC4EULL,
		0x00BE1248B51F9BCBULL,
		0xCE823360818A9552ULL,
		0x2E0CC5DFEA5AABD5ULL,
		0x548483CCA6EE63AEULL,
		0x6EB1D02EF1D42DE0ULL
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
		0xD4ABDFEE589A157BULL,
		0x31DCA7165A6559CDULL,
		0x9244E3023AF5DFD1ULL,
		0xEDC5F44FB88BDC99ULL,
		0xE40E809114FCFEE2ULL,
		0x6D4A60AC83EAD527ULL,
		0x137F70B71FA6CC16ULL,
		0x1CEC4B705FFF61F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA957BFDCB1342AF6ULL,
		0x63B94E2CB4CAB39BULL,
		0x2489C60475EBBFA2ULL,
		0xDB8BE89F7117B933ULL,
		0xC81D012229F9FDC5ULL,
		0xDA94C15907D5AA4FULL,
		0x26FEE16E3F4D982CULL,
		0x39D896E0BFFEC3E2ULL
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
		0xB538705FBC17A6ECULL,
		0xC43B2C1BBBF8C418ULL,
		0xBC75813EC281F1F8ULL,
		0x79862EB7F6DC92D0ULL,
		0x17C09477919439DDULL,
		0x705268D34F63ACD5ULL,
		0xDECE3AE790B30454ULL,
		0x2157401F3044D2EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A70E0BF782F4DD8ULL,
		0x8876583777F18831ULL,
		0x78EB027D8503E3F1ULL,
		0xF30C5D6FEDB925A1ULL,
		0x2F8128EF232873BAULL,
		0xE0A4D1A69EC759AAULL,
		0xBD9C75CF216608A8ULL,
		0x42AE803E6089A5DBULL
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
		0xE2F9EAA60908E48CULL,
		0xAF6CB1F22BA7C577ULL,
		0x29490678F3384EC3ULL,
		0x965AC01BCAC1B8FDULL,
		0x50CB54C306C29EBAULL,
		0x6D322376F40C0E1CULL,
		0x929D2F3DB124E3E0ULL,
		0x10924C02376C2E0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F3D54C1211C918ULL,
		0x5ED963E4574F8AEFULL,
		0x52920CF1E6709D87ULL,
		0x2CB58037958371FAULL,
		0xA196A9860D853D75ULL,
		0xDA6446EDE8181C38ULL,
		0x253A5E7B6249C7C0ULL,
		0x212498046ED85C1DULL
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
		0x8A8F75E8274F280FULL,
		0x30A4C767F28DE5EBULL,
		0x0A8499E82B4F08C8ULL,
		0xDA6EECFDE7AB29A3ULL,
		0xB9176AC688D1E28FULL,
		0x591F1758F531EE61ULL,
		0x54D2CC7F51CDE9F2ULL,
		0x2844CC974C73F5A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x151EEBD04E9E501EULL,
		0x61498ECFE51BCBD7ULL,
		0x150933D0569E1190ULL,
		0xB4DDD9FBCF565346ULL,
		0x722ED58D11A3C51FULL,
		0xB23E2EB1EA63DCC3ULL,
		0xA9A598FEA39BD3E4ULL,
		0x5089992E98E7EB44ULL
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
		0x47F9AD0DAA34AE62ULL,
		0x6BD5B0B45C47A77EULL,
		0x02469BC04E54F6F6ULL,
		0xBE6044F905AAEC13ULL,
		0xE8B84FA7F7E0D992ULL,
		0x2F0C7B3B8A0A4D0CULL,
		0x2FD5C54CB3B8FA77ULL,
		0x27396D53BC97F69BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF35A1B54695CC4ULL,
		0xD7AB6168B88F4EFCULL,
		0x048D37809CA9EDECULL,
		0x7CC089F20B55D826ULL,
		0xD1709F4FEFC1B325ULL,
		0x5E18F67714149A19ULL,
		0x5FAB8A996771F4EEULL,
		0x4E72DAA7792FED36ULL
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
		0xADF28A2E37E3EBF0ULL,
		0x78F0CA2739342F15ULL,
		0xDE7F5E44116A43D9ULL,
		0x17F66F779F836D7FULL,
		0x11FDBE9484F3AFCDULL,
		0x62D70A29D07DE607ULL,
		0xD8612F238AFA9E13ULL,
		0x0432CD6387083023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BE5145C6FC7D7E0ULL,
		0xF1E1944E72685E2BULL,
		0xBCFEBC8822D487B2ULL,
		0x2FECDEEF3F06DAFFULL,
		0x23FB7D2909E75F9AULL,
		0xC5AE1453A0FBCC0EULL,
		0xB0C25E4715F53C26ULL,
		0x08659AC70E106047ULL
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
		0x0463BCD2B616CB84ULL,
		0x7C557A0EDB471A7DULL,
		0x47B25B784689F2B5ULL,
		0x4EE55AD2BB700704ULL,
		0x46332EA22174D843ULL,
		0x50437FFB59A2F89EULL,
		0x0B9B410F98802F58ULL,
		0x04974C3A41F03468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C779A56C2D9708ULL,
		0xF8AAF41DB68E34FAULL,
		0x8F64B6F08D13E56AULL,
		0x9DCAB5A576E00E08ULL,
		0x8C665D4442E9B086ULL,
		0xA086FFF6B345F13CULL,
		0x1736821F31005EB0ULL,
		0x092E987483E068D0ULL
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
		0x22C356EA70121E39ULL,
		0x0617842F290EEED3ULL,
		0x8A1A36B3BE0CE547ULL,
		0xA358DA245B04DD44ULL,
		0x16B6AF4546A7C691ULL,
		0xE8EA39E80F084A84ULL,
		0xC3E18E8CC3D6623FULL,
		0x1D49213768C411BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4586ADD4E0243C72ULL,
		0x0C2F085E521DDDA6ULL,
		0x14346D677C19CA8EULL,
		0x46B1B448B609BA89ULL,
		0x2D6D5E8A8D4F8D23ULL,
		0xD1D473D01E109508ULL,
		0x87C31D1987ACC47FULL,
		0x3A92426ED188237FULL
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
		0xB11A7311B27D006BULL,
		0x1E779C1DD65339A9ULL,
		0xF0B6112DD366E7C9ULL,
		0xFD8F281EB16B292FULL,
		0x2739F0DE64FA2F55ULL,
		0xB8206EF4A9651D48ULL,
		0x2635DC4AE5BF4300ULL,
		0x289C3E8E9DA37294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6234E62364FA00D6ULL,
		0x3CEF383BACA67353ULL,
		0xE16C225BA6CDCF92ULL,
		0xFB1E503D62D6525FULL,
		0x4E73E1BCC9F45EABULL,
		0x7040DDE952CA3A90ULL,
		0x4C6BB895CB7E8601ULL,
		0x51387D1D3B46E528ULL
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
		0x78B5FF4343D16B0CULL,
		0x32CE0C26942C8A98ULL,
		0x3452EC163B357280ULL,
		0x6069D95938BC146BULL,
		0x80D96D4A375F0DB1ULL,
		0xEDB65114FA210229ULL,
		0x1EFA0538C4CFE966ULL,
		0x2EED196CAC2FF70EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16BFE8687A2D618ULL,
		0x659C184D28591530ULL,
		0x68A5D82C766AE500ULL,
		0xC0D3B2B2717828D6ULL,
		0x01B2DA946EBE1B62ULL,
		0xDB6CA229F4420453ULL,
		0x3DF40A71899FD2CDULL,
		0x5DDA32D9585FEE1CULL
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
		0xAEC9DFBC4E3999EBULL,
		0x3D6A4C66F5CF52DBULL,
		0xD700A3DAC9D29EF9ULL,
		0xC0557266F8C343ACULL,
		0x0707AADE220545ECULL,
		0xF1327AB553F04727ULL,
		0xB2F7E769E68896ABULL,
		0x0226B68324C3181FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D93BF789C7333D6ULL,
		0x7AD498CDEB9EA5B7ULL,
		0xAE0147B593A53DF2ULL,
		0x80AAE4CDF1868759ULL,
		0x0E0F55BC440A8BD9ULL,
		0xE264F56AA7E08E4EULL,
		0x65EFCED3CD112D57ULL,
		0x044D6D064986303FULL
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
		0x9A34A547F0D9E646ULL,
		0x82E5A60328C1644FULL,
		0x70CF3337AA165026ULL,
		0xE018B5E882B85B57ULL,
		0xA8361EB7B9702B0CULL,
		0xCD4CA7528E02396BULL,
		0x8E19ACE5E8EC2818ULL,
		0x0D223230B9B931A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34694A8FE1B3CC8CULL,
		0x05CB4C065182C89FULL,
		0xE19E666F542CA04DULL,
		0xC0316BD10570B6AEULL,
		0x506C3D6F72E05619ULL,
		0x9A994EA51C0472D7ULL,
		0x1C3359CBD1D85031ULL,
		0x1A44646173726345ULL
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
		0x10427EFEB52D001EULL,
		0xAAB553425B7A955CULL,
		0xA289862DB52EA92EULL,
		0xD205F096862BA068ULL,
		0xC53BBB18E7BA3019ULL,
		0x04ED873B140A3301ULL,
		0x9CC33CAD4F8688E8ULL,
		0x2F67D88649095E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2084FDFD6A5A003CULL,
		0x556AA684B6F52AB8ULL,
		0x45130C5B6A5D525DULL,
		0xA40BE12D0C5740D1ULL,
		0x8A777631CF746033ULL,
		0x09DB0E7628146603ULL,
		0x3986795A9F0D11D0ULL,
		0x5ECFB10C9212BC21ULL
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
		0x8BB2EA1A47640E92ULL,
		0x476660D01CFD829DULL,
		0x96BDA2DCD741CBA0ULL,
		0x81C34A3DCA168F34ULL,
		0xED1A32CA12C1707CULL,
		0xA8AE9DEB54F81C2DULL,
		0xD5BCD1E7EC143C73ULL,
		0x32E7B813DEC3917EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1765D4348EC81D24ULL,
		0x8ECCC1A039FB053BULL,
		0x2D7B45B9AE839740ULL,
		0x0386947B942D1E69ULL,
		0xDA3465942582E0F9ULL,
		0x515D3BD6A9F0385BULL,
		0xAB79A3CFD82878E7ULL,
		0x65CF7027BD8722FDULL
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
		0xFC863EA3030BDA20ULL,
		0x65171B4718161FCBULL,
		0x941D8F34C7E0F2C6ULL,
		0x3EECDF3A705371DFULL,
		0x8C03AA9CC0FE219FULL,
		0x9BC2C869A874273BULL,
		0x812404069845DA3EULL,
		0x1B91B6F2DBF5A21BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF90C7D460617B440ULL,
		0xCA2E368E302C3F97ULL,
		0x283B1E698FC1E58CULL,
		0x7DD9BE74E0A6E3BFULL,
		0x1807553981FC433EULL,
		0x378590D350E84E77ULL,
		0x0248080D308BB47DULL,
		0x37236DE5B7EB4437ULL
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
		0xA67B2E1EF08A9C30ULL,
		0xC40282EA8A2DBD24ULL,
		0xFB64E0B2D2F7AA01ULL,
		0x16F699D5442C30D0ULL,
		0x86F57142C7785102ULL,
		0xEB9CACD5DBFABE99ULL,
		0x2C0685D517D22120ULL,
		0x31560F9E88884BE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF65C3DE1153860ULL,
		0x880505D5145B7A49ULL,
		0xF6C9C165A5EF5403ULL,
		0x2DED33AA885861A1ULL,
		0x0DEAE2858EF0A204ULL,
		0xD73959ABB7F57D33ULL,
		0x580D0BAA2FA44241ULL,
		0x62AC1F3D111097D2ULL
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
		0xAF2A4F82890048DDULL,
		0x0133E6AA353354DFULL,
		0xA0F854A65B18CDE7ULL,
		0x84F348203716D654ULL,
		0xCEE201CBA2108349ULL,
		0x7D3A347BBA0C22A8ULL,
		0xF22AF0183A9D4CBDULL,
		0x39E422D60CA2000CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E549F05120091BAULL,
		0x0267CD546A66A9BFULL,
		0x41F0A94CB6319BCEULL,
		0x09E690406E2DACA9ULL,
		0x9DC4039744210693ULL,
		0xFA7468F774184551ULL,
		0xE455E030753A997AULL,
		0x73C845AC19440019ULL
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
		0xD0F250E744BBB727ULL,
		0x70328E3D865C9CDDULL,
		0xC66A7D4A3E253884ULL,
		0x181EA1F7BAD2F3C8ULL,
		0xB95B2E201C60704CULL,
		0x5F553B3D013DA1A0ULL,
		0xCA1959940D97C9B8ULL,
		0x14D2DEFF7CB6D45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1E4A1CE89776E4EULL,
		0xE0651C7B0CB939BBULL,
		0x8CD4FA947C4A7108ULL,
		0x303D43EF75A5E791ULL,
		0x72B65C4038C0E098ULL,
		0xBEAA767A027B4341ULL,
		0x9432B3281B2F9370ULL,
		0x29A5BDFEF96DA8BFULL
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
		0x896219E0ABC0CA18ULL,
		0xB5891827A2A50F61ULL,
		0x8D3A23E5C067012AULL,
		0x84A7F8CEF38E48C1ULL,
		0x48B4BC79D386794DULL,
		0x091FADA82EFE3FCAULL,
		0xB78BCE58DE94328CULL,
		0x0373F6A0D08B6E4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C433C157819430ULL,
		0x6B12304F454A1EC3ULL,
		0x1A7447CB80CE0255ULL,
		0x094FF19DE71C9183ULL,
		0x916978F3A70CF29BULL,
		0x123F5B505DFC7F94ULL,
		0x6F179CB1BD286518ULL,
		0x06E7ED41A116DC95ULL
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
		0xD09AE31F45A40A72ULL,
		0x6F07E4D85DE6D5C3ULL,
		0xE2102C272D1ACF46ULL,
		0x66A4AF3F13EEE77BULL,
		0x7E12CC052FE8A1F4ULL,
		0x001C36F8ADC27D09ULL,
		0x1D95B2495ED1E77FULL,
		0x10DB453AD98914F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA135C63E8B4814E4ULL,
		0xDE0FC9B0BBCDAB87ULL,
		0xC420584E5A359E8CULL,
		0xCD495E7E27DDCEF7ULL,
		0xFC25980A5FD143E8ULL,
		0x00386DF15B84FA12ULL,
		0x3B2B6492BDA3CEFEULL,
		0x21B68A75B31229EEULL
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
		0x398DF6B8866671ADULL,
		0xA40490AD04D0CEB1ULL,
		0x012C3E55D832D49EULL,
		0x56466272FA4E1B13ULL,
		0x4CE8535ACA0BF478ULL,
		0x95F9C91626CB8123ULL,
		0xB02B5EDDFB6C8FC7ULL,
		0x072A728C5D647B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731BED710CCCE35AULL,
		0x4809215A09A19D62ULL,
		0x02587CABB065A93DULL,
		0xAC8CC4E5F49C3626ULL,
		0x99D0A6B59417E8F0ULL,
		0x2BF3922C4D970246ULL,
		0x6056BDBBF6D91F8FULL,
		0x0E54E518BAC8F66FULL
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
		0x0969C6DE9A873F1EULL,
		0x07254366FFEEEF3DULL,
		0x951306A6B9EAB602ULL,
		0xF1F263DB994024F2ULL,
		0x06E4CFDFB00DAE62ULL,
		0x73859740384C27EDULL,
		0x46CAB2A786C9C3A6ULL,
		0x1D65D7AB07CAA26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D38DBD350E7E3CULL,
		0x0E4A86CDFFDDDE7AULL,
		0x2A260D4D73D56C04ULL,
		0xE3E4C7B7328049E5ULL,
		0x0DC99FBF601B5CC5ULL,
		0xE70B2E8070984FDAULL,
		0x8D95654F0D93874CULL,
		0x3ACBAF560F9544D4ULL
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
		0x5882172D1F862BAFULL,
		0xA2476F25F80C4371ULL,
		0x1AD2B132CAD472CDULL,
		0xC7C7E63FF5C02A27ULL,
		0x45B9ED6F07CCD9D9ULL,
		0xE902AD56D68F2EFDULL,
		0xBAC9C4016568D2BBULL,
		0x1C1F58970643AC26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1042E5A3F0C575EULL,
		0x448EDE4BF01886E2ULL,
		0x35A5626595A8E59BULL,
		0x8F8FCC7FEB80544EULL,
		0x8B73DADE0F99B3B3ULL,
		0xD2055AADAD1E5DFAULL,
		0x75938802CAD1A577ULL,
		0x383EB12E0C87584DULL
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
		0x72534B40CB2F4F07ULL,
		0xD9B6923EEEE98917ULL,
		0x2443A218F849ACACULL,
		0xEF71AA99101E9E6DULL,
		0xB1E89DA952A1D7DFULL,
		0xF1471CC657886869ULL,
		0xB592DD3510EAD788ULL,
		0x2DCEE578D6253711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4A69681965E9E0EULL,
		0xB36D247DDDD3122EULL,
		0x48874431F0935959ULL,
		0xDEE35532203D3CDAULL,
		0x63D13B52A543AFBFULL,
		0xE28E398CAF10D0D3ULL,
		0x6B25BA6A21D5AF11ULL,
		0x5B9DCAF1AC4A6E23ULL
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
		0xA516B1DF2D6E47B3ULL,
		0x04E819ADA56EE0CBULL,
		0x4189DA749E678955ULL,
		0x6346676B5F51066CULL,
		0x39B9DD859DD2196DULL,
		0x62BB3ECFAE6580BBULL,
		0x39C3C659B7F859EAULL,
		0x2E115CD820217632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A2D63BE5ADC8F66ULL,
		0x09D0335B4ADDC197ULL,
		0x8313B4E93CCF12AAULL,
		0xC68CCED6BEA20CD8ULL,
		0x7373BB0B3BA432DAULL,
		0xC5767D9F5CCB0176ULL,
		0x73878CB36FF0B3D4ULL,
		0x5C22B9B04042EC64ULL
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
		0x9A99DEC119FD9C30ULL,
		0xE2E0F475D6703952ULL,
		0xE5E9C14BFD4374A9ULL,
		0xF8EF5338640EA73BULL,
		0xF87823D9544B2621ULL,
		0xB0F804098AB3A9BEULL,
		0xCA89AB9379D6D9E9ULL,
		0x2BD7BA7271A01401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3533BD8233FB3860ULL,
		0xC5C1E8EBACE072A5ULL,
		0xCBD38297FA86E953ULL,
		0xF1DEA670C81D4E77ULL,
		0xF0F047B2A8964C43ULL,
		0x61F008131567537DULL,
		0x95135726F3ADB3D3ULL,
		0x57AF74E4E3402803ULL
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
		0x9446F5806BFB0E23ULL,
		0x2B690EECE108A466ULL,
		0xC97EBAE569B6DA25ULL,
		0xA47424F49119044CULL,
		0xEFFCC80A47DB6BAFULL,
		0x5262E103361F2058ULL,
		0x4DA4B41352699495ULL,
		0x3E42394856766683ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x288DEB00D7F61C46ULL,
		0x56D21DD9C21148CDULL,
		0x92FD75CAD36DB44AULL,
		0x48E849E922320899ULL,
		0xDFF990148FB6D75FULL,
		0xA4C5C2066C3E40B1ULL,
		0x9B496826A4D3292AULL,
		0x7C847290ACECCD06ULL
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
		0x0C2A46D9E25DAB89ULL,
		0x0531A0FFE248DE84ULL,
		0x6618F4E464CFDF95ULL,
		0xF64FDD248E0EF3B0ULL,
		0x04580F26090CA9F2ULL,
		0x6E2C4365AC6D3CC9ULL,
		0xAA82B2DEBB25B4CFULL,
		0x0DA9DAD33693D9D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18548DB3C4BB5712ULL,
		0x0A6341FFC491BD08ULL,
		0xCC31E9C8C99FBF2AULL,
		0xEC9FBA491C1DE760ULL,
		0x08B01E4C121953E5ULL,
		0xDC5886CB58DA7992ULL,
		0x550565BD764B699EULL,
		0x1B53B5A66D27B3A5ULL
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
		0x2EBF4088CD85575BULL,
		0xEF2C5DCB7E1FD096ULL,
		0xAC0D1CC0003B1F0AULL,
		0x3BB7CA64E87745ADULL,
		0x0B7852E28837C483ULL,
		0x7C3EB7373909F0CFULL,
		0x8DC2C8DE8D437DA3ULL,
		0x24C847DA80D7FBEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D7E81119B0AAEB6ULL,
		0xDE58BB96FC3FA12CULL,
		0x581A398000763E15ULL,
		0x776F94C9D0EE8B5BULL,
		0x16F0A5C5106F8906ULL,
		0xF87D6E6E7213E19EULL,
		0x1B8591BD1A86FB46ULL,
		0x49908FB501AFF7DDULL
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
		0xC2DAE63C0D3840A1ULL,
		0x649C6967649BE294ULL,
		0x16BB0FD8FE5D9DB9ULL,
		0x8A62F5085F2B17EDULL,
		0x00CFD7DCC3E48186ULL,
		0x09C31B1AC31170F7ULL,
		0x289BE91B9782246FULL,
		0x172C022D751E6233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B5CC781A708142ULL,
		0xC938D2CEC937C529ULL,
		0x2D761FB1FCBB3B72ULL,
		0x14C5EA10BE562FDAULL,
		0x019FAFB987C9030DULL,
		0x138636358622E1EEULL,
		0x5137D2372F0448DEULL,
		0x2E58045AEA3CC466ULL
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
		0x9C58496401F2BA79ULL,
		0x9290194C6838A96CULL,
		0x8E09A48B92000773ULL,
		0xF8862F56F3329C99ULL,
		0x02DA2D83EF22264FULL,
		0x76A9CF75B682997AULL,
		0xA59C33263C5656B7ULL,
		0x1FE4A5158EE38FC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B092C803E574F2ULL,
		0x25203298D07152D9ULL,
		0x1C13491724000EE7ULL,
		0xF10C5EADE6653933ULL,
		0x05B45B07DE444C9FULL,
		0xED539EEB6D0532F4ULL,
		0x4B38664C78ACAD6EULL,
		0x3FC94A2B1DC71F83ULL
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
		0x639CEAC8A46E8B18ULL,
		0x93065226AD5145BEULL,
		0xF84D83C6968C54A6ULL,
		0x29522311E90440C6ULL,
		0x5DFA01996BD417ABULL,
		0x9E25DF6B2A469534ULL,
		0x18AF00F2585A59CBULL,
		0x18FCC595D8A6AE80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC739D59148DD1630ULL,
		0x260CA44D5AA28B7CULL,
		0xF09B078D2D18A94DULL,
		0x52A44623D208818DULL,
		0xBBF40332D7A82F56ULL,
		0x3C4BBED6548D2A68ULL,
		0x315E01E4B0B4B397ULL,
		0x31F98B2BB14D5D00ULL
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
		0x4D250BA55DCDFEE6ULL,
		0xFA0F4041E14219F5ULL,
		0x1952BB289773E9E9ULL,
		0xE02081DC7A26B9AAULL,
		0x662A814011F83242ULL,
		0x1255EFBE8206B5A6ULL,
		0xE80943EFD3AE89E9ULL,
		0x2E9A240789A0782CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A4A174ABB9BFDCCULL,
		0xF41E8083C28433EAULL,
		0x32A576512EE7D3D3ULL,
		0xC04103B8F44D7354ULL,
		0xCC55028023F06485ULL,
		0x24ABDF7D040D6B4CULL,
		0xD01287DFA75D13D2ULL,
		0x5D34480F1340F059ULL
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
		0x753BE21DD45BD9A7ULL,
		0xFF4903FFECBC87FCULL,
		0x966E32B2F4828CE6ULL,
		0xA31936B8D88EECF3ULL,
		0x6409395992B4FEA5ULL,
		0xE03B12560BBB21E0ULL,
		0xA623DF36E5545CD5ULL,
		0x33B1383B3BF6CEAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA77C43BA8B7B34EULL,
		0xFE9207FFD9790FF8ULL,
		0x2CDC6565E90519CDULL,
		0x46326D71B11DD9E7ULL,
		0xC81272B32569FD4BULL,
		0xC07624AC177643C0ULL,
		0x4C47BE6DCAA8B9ABULL,
		0x6762707677ED9D5DULL
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
		0x49D69AA4479E0092ULL,
		0x9CEDC9F8CEA565B3ULL,
		0x47084F21A8B9DB65ULL,
		0xFAA7F34B20ABE5A6ULL,
		0xE1B5CD8C9A142218ULL,
		0x1EF1D227A7959B47ULL,
		0x275FAB5393FA36ADULL,
		0x03B2A2503C3C5897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93AD35488F3C0124ULL,
		0x39DB93F19D4ACB66ULL,
		0x8E109E435173B6CBULL,
		0xF54FE6964157CB4CULL,
		0xC36B9B1934284431ULL,
		0x3DE3A44F4F2B368FULL,
		0x4EBF56A727F46D5AULL,
		0x076544A07878B12EULL
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
		0xC286F7166F6E10ADULL,
		0x188968C7A8B6BC19ULL,
		0xD57E643B54DF3B84ULL,
		0xC3C1F19C8B779EB3ULL,
		0x9EA1E879DAFC93F1ULL,
		0x4269F06CEF4050BCULL,
		0x4144575EF45AE046ULL,
		0x2981242A38896975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x850DEE2CDEDC215AULL,
		0x3112D18F516D7833ULL,
		0xAAFCC876A9BE7708ULL,
		0x8783E33916EF3D67ULL,
		0x3D43D0F3B5F927E3ULL,
		0x84D3E0D9DE80A179ULL,
		0x8288AEBDE8B5C08CULL,
		0x530248547112D2EAULL
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
		0x6709A908749F292CULL,
		0x37B9F3A264192DEBULL,
		0xCCC810324B9BF2B9ULL,
		0xEDBFC869543978E4ULL,
		0x188891CA74981C03ULL,
		0x09CC0D85F5B74A38ULL,
		0x52D652EE89B1A326ULL,
		0x0319B599F4E35B40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE135210E93E5258ULL,
		0x6F73E744C8325BD6ULL,
		0x999020649737E572ULL,
		0xDB7F90D2A872F1C9ULL,
		0x31112394E9303807ULL,
		0x13981B0BEB6E9470ULL,
		0xA5ACA5DD1363464CULL,
		0x06336B33E9C6B680ULL
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
		0xA12D5D058AB5E736ULL,
		0x9E6BE5CA03C38D7EULL,
		0xFBD399FB8B4604C9ULL,
		0xFA394D3DA3C54C88ULL,
		0x22657DD050A10AF7ULL,
		0x1605B6149DBB259FULL,
		0x07539152AB97857FULL,
		0x30107A983A0F6952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425ABA0B156BCE6CULL,
		0x3CD7CB9407871AFDULL,
		0xF7A733F7168C0993ULL,
		0xF4729A7B478A9911ULL,
		0x44CAFBA0A14215EFULL,
		0x2C0B6C293B764B3EULL,
		0x0EA722A5572F0AFEULL,
		0x6020F530741ED2A4ULL
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
		0x9A41CDDC4C52F13BULL,
		0xF59CAF043E8A099CULL,
		0xCA45926B70766F0AULL,
		0x11B4F6A40C8626A6ULL,
		0x976A5D3B5EBE80C0ULL,
		0xB63E14DA12140128ULL,
		0xA6756313C14F9B83ULL,
		0x122FF1E7FAF3B29EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34839BB898A5E276ULL,
		0xEB395E087D141339ULL,
		0x948B24D6E0ECDE15ULL,
		0x2369ED48190C4D4DULL,
		0x2ED4BA76BD7D0180ULL,
		0x6C7C29B424280251ULL,
		0x4CEAC627829F3707ULL,
		0x245FE3CFF5E7653DULL
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
		0xA704A551101D084CULL,
		0x9621DB382E0EAE48ULL,
		0x07E9F8A95E781DB9ULL,
		0x002A635DB57D4B8DULL,
		0xA8F16EE36D30DB34ULL,
		0x08D8DC730432F939ULL,
		0x5302F01CCDC059CAULL,
		0x09B221F4A469D03AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E094AA2203A1098ULL,
		0x2C43B6705C1D5C91ULL,
		0x0FD3F152BCF03B73ULL,
		0x0054C6BB6AFA971AULL,
		0x51E2DDC6DA61B668ULL,
		0x11B1B8E60865F273ULL,
		0xA605E0399B80B394ULL,
		0x136443E948D3A074ULL
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
		0x8780B033271BDA3FULL,
		0xB18F8C126ED43262ULL,
		0xD08A533CAE99D1AFULL,
		0x92428604B8C0D2A4ULL,
		0x368C46261E485362ULL,
		0x8E06D5E4B43BDE0DULL,
		0x8BA58801B81C8E58ULL,
		0x3ACCCB5B28DC0778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0160664E37B47EULL,
		0x631F1824DDA864C5ULL,
		0xA114A6795D33A35FULL,
		0x24850C097181A549ULL,
		0x6D188C4C3C90A6C5ULL,
		0x1C0DABC96877BC1AULL,
		0x174B100370391CB1ULL,
		0x759996B651B80EF1ULL
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
		0x6062E949017B9F61ULL,
		0x78574004C71B5AB9ULL,
		0x618CDF5ACCCCF875ULL,
		0x9144EDF2CF1A74BAULL,
		0xE4CA40076E5E9F84ULL,
		0x4C134268F4871842ULL,
		0x28618C29BC60C065ULL,
		0x030DDF39C674DDBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C5D29202F73EC2ULL,
		0xF0AE80098E36B572ULL,
		0xC319BEB59999F0EAULL,
		0x2289DBE59E34E974ULL,
		0xC994800EDCBD3F09ULL,
		0x982684D1E90E3085ULL,
		0x50C3185378C180CAULL,
		0x061BBE738CE9BB7CULL
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
		0x0870BF87A992BC36ULL,
		0x88F6E3CA69119DCCULL,
		0xBEC58D8D84C757F2ULL,
		0xAF900D344CE80189ULL,
		0xDD511D7BF176A91FULL,
		0x58CB4E3CCD72C7D3ULL,
		0x86F501EF716C854BULL,
		0x1084057056EEE147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E17F0F5325786CULL,
		0x11EDC794D2233B98ULL,
		0x7D8B1B1B098EAFE5ULL,
		0x5F201A6899D00313ULL,
		0xBAA23AF7E2ED523FULL,
		0xB1969C799AE58FA7ULL,
		0x0DEA03DEE2D90A96ULL,
		0x21080AE0ADDDC28FULL
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
		0xFE0505ADEB7013CBULL,
		0x49725BC2C8663991ULL,
		0x50E0E57605D83B5DULL,
		0x3C4212C22231E075ULL,
		0x34CD5B538FD75307ULL,
		0x992CF838E3573E70ULL,
		0xFE95FEC902333C7FULL,
		0x2ED70245D884DB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC0A0B5BD6E02796ULL,
		0x92E4B78590CC7323ULL,
		0xA1C1CAEC0BB076BAULL,
		0x788425844463C0EAULL,
		0x699AB6A71FAEA60EULL,
		0x3259F071C6AE7CE0ULL,
		0xFD2BFD92046678FFULL,
		0x5DAE048BB109B663ULL
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
		0x0B88393A76112FD9ULL,
		0xC1283C07A5A4783FULL,
		0x1F91C1408299AEF9ULL,
		0x99F7DEB67A1EE3E3ULL,
		0x27AF91FBC5B573D1ULL,
		0xE0DC72A64D50AE6DULL,
		0x0B26E6A3E22320A9ULL,
		0x0018B7ECE9BEE8E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17107274EC225FB2ULL,
		0x8250780F4B48F07EULL,
		0x3F23828105335DF3ULL,
		0x33EFBD6CF43DC7C6ULL,
		0x4F5F23F78B6AE7A3ULL,
		0xC1B8E54C9AA15CDAULL,
		0x164DCD47C4464153ULL,
		0x00316FD9D37DD1CCULL
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
		0x1664C3FF7FE87E97ULL,
		0x41D0F375EBF46703ULL,
		0xEC40E05F87EAD39FULL,
		0xBCDCE6F4A1A957B1ULL,
		0x401A207A4908ACC9ULL,
		0xF505BDEAF381F890ULL,
		0xEE24666F718FF330ULL,
		0x27D66447BDD18560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC987FEFFD0FD2EULL,
		0x83A1E6EBD7E8CE06ULL,
		0xD881C0BF0FD5A73EULL,
		0x79B9CDE94352AF63ULL,
		0x803440F492115993ULL,
		0xEA0B7BD5E703F120ULL,
		0xDC48CCDEE31FE661ULL,
		0x4FACC88F7BA30AC1ULL
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
		0x7F32046481189D32ULL,
		0x4CC0AEC768BF6B99ULL,
		0x5244C4FFF22AD675ULL,
		0x02946B0C3FEF34C0ULL,
		0xB8662950419BC06EULL,
		0x6EFB346778A9D297ULL,
		0xAD880F4B94FD7FCFULL,
		0x3D8C3FAF9890E444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE6408C902313A64ULL,
		0x99815D8ED17ED732ULL,
		0xA48989FFE455ACEAULL,
		0x0528D6187FDE6980ULL,
		0x70CC52A0833780DCULL,
		0xDDF668CEF153A52FULL,
		0x5B101E9729FAFF9EULL,
		0x7B187F5F3121C889ULL
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
		0x4C8137730B432156ULL,
		0x66C30DC02D5ECD58ULL,
		0x0E94408C9B7D5A45ULL,
		0xD127A67A97843A7BULL,
		0x35202850805B5AFEULL,
		0xF7A06317CCBBE567ULL,
		0x105025AD9C42BC68ULL,
		0x2301548DA502434AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99026EE6168642ACULL,
		0xCD861B805ABD9AB0ULL,
		0x1D28811936FAB48AULL,
		0xA24F4CF52F0874F6ULL,
		0x6A4050A100B6B5FDULL,
		0xEF40C62F9977CACEULL,
		0x20A04B5B388578D1ULL,
		0x4602A91B4A048694ULL
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
		0x77391BDD2808558BULL,
		0x8D07BD52A8912938ULL,
		0xE067A76845907CFDULL,
		0xD44888A3C2B14E0EULL,
		0xFA0E90562D7BAE03ULL,
		0x0C430BAE59F2D2E2ULL,
		0x252974AA6831CF2EULL,
		0x3F777455382C8B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE7237BA5010AB16ULL,
		0x1A0F7AA551225270ULL,
		0xC0CF4ED08B20F9FBULL,
		0xA891114785629C1DULL,
		0xF41D20AC5AF75C07ULL,
		0x1886175CB3E5A5C5ULL,
		0x4A52E954D0639E5CULL,
		0x7EEEE8AA705916FCULL
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
		0xC5E66C7C47D59DBFULL,
		0xC30C6CB38D751078ULL,
		0xD6E7AD0AEC6AB320ULL,
		0xFED6CEF071EFEF67ULL,
		0xA1643C53390AEF69ULL,
		0xC382A26AF6ECC3EBULL,
		0xC8F0B80787C2AB82ULL,
		0x3040070A90868083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCCD8F88FAB3B7EULL,
		0x8618D9671AEA20F1ULL,
		0xADCF5A15D8D56641ULL,
		0xFDAD9DE0E3DFDECFULL,
		0x42C878A67215DED3ULL,
		0x870544D5EDD987D7ULL,
		0x91E1700F0F855705ULL,
		0x60800E15210D0107ULL
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
		0x92391C6F4E91B087ULL,
		0xD3F9E02DA3227E3CULL,
		0x3FEC8FE3E1ED5E33ULL,
		0x13B067523BE6CFC2ULL,
		0xB545804738B8CEBAULL,
		0x57BE351B1E219ECEULL,
		0xD158BDE576FE3526ULL,
		0x3CCE179B0557C19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247238DE9D23610EULL,
		0xA7F3C05B4644FC79ULL,
		0x7FD91FC7C3DABC67ULL,
		0x2760CEA477CD9F84ULL,
		0x6A8B008E71719D74ULL,
		0xAF7C6A363C433D9DULL,
		0xA2B17BCAEDFC6A4CULL,
		0x799C2F360AAF8337ULL
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
		0xBB8E69DAB483BAC5ULL,
		0xA70C4263C2D0D5B7ULL,
		0x8699C11094B553ADULL,
		0xBDE38512DA9BE674ULL,
		0x5F8F9D126E3EB962ULL,
		0x50D8272DD5F85084ULL,
		0xDAF653AC0CA3BEEFULL,
		0x027A01F30D829E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x771CD3B56907758AULL,
		0x4E1884C785A1AB6FULL,
		0x0D338221296AA75BULL,
		0x7BC70A25B537CCE9ULL,
		0xBF1F3A24DC7D72C5ULL,
		0xA1B04E5BABF0A108ULL,
		0xB5ECA75819477DDEULL,
		0x04F403E61B053D07ULL
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
		0xD529F8CA8F4DEAAEULL,
		0x20CC09248D72A1E9ULL,
		0x1F90C60B04F48041ULL,
		0xAA3FD2FE4B61D194ULL,
		0xE93BAAC9CE7BF6A2ULL,
		0x05F1C828CEE43FD9ULL,
		0x78A4F9638D23DCA4ULL,
		0x23C217782FAEA622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA53F1951E9BD55CULL,
		0x419812491AE543D3ULL,
		0x3F218C1609E90082ULL,
		0x547FA5FC96C3A328ULL,
		0xD27755939CF7ED45ULL,
		0x0BE390519DC87FB3ULL,
		0xF149F2C71A47B948ULL,
		0x47842EF05F5D4C44ULL
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
		0xCD0BC207D751CA52ULL,
		0xE80FCF1EBBF47ACFULL,
		0x22D54B5BE77C4C96ULL,
		0xD9B75C9AE6D07A4DULL,
		0x97040C00737F4442ULL,
		0xD6E6F75F9755358EULL,
		0xA09123E216ADB7DAULL,
		0x0E584C1ACF904C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A17840FAEA394A4ULL,
		0xD01F9E3D77E8F59FULL,
		0x45AA96B7CEF8992DULL,
		0xB36EB935CDA0F49AULL,
		0x2E081800E6FE8885ULL,
		0xADCDEEBF2EAA6B1DULL,
		0x412247C42D5B6FB5ULL,
		0x1CB098359F20988BULL
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
		0xA8AB8054A28F2FBFULL,
		0xF760D9364B8E68BEULL,
		0x38A663D309C7111EULL,
		0xDC08C865235EFE92ULL,
		0xB25178BA33120B2CULL,
		0x571C665DA6E0CCB5ULL,
		0x2C92494BFA180769ULL,
		0x320D1DC522264573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515700A9451E5F7EULL,
		0xEEC1B26C971CD17DULL,
		0x714CC7A6138E223DULL,
		0xB81190CA46BDFD24ULL,
		0x64A2F17466241659ULL,
		0xAE38CCBB4DC1996BULL,
		0x59249297F4300ED2ULL,
		0x641A3B8A444C8AE6ULL
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
		0x6D242B460BA08A24ULL,
		0xDFDDAD1893F42CE6ULL,
		0x4291871A10AF3A7FULL,
		0x17501F7D54B9BAB1ULL,
		0x974E4C7A1021E6C8ULL,
		0xA344094FC44E806AULL,
		0xD05F59E65C192CFAULL,
		0x0BC6B0ADDA59C6EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA48568C17411448ULL,
		0xBFBB5A3127E859CCULL,
		0x85230E34215E74FFULL,
		0x2EA03EFAA9737562ULL,
		0x2E9C98F42043CD90ULL,
		0x4688129F889D00D5ULL,
		0xA0BEB3CCB83259F5ULL,
		0x178D615BB4B38DDBULL
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
		0xF038DE08A97B5F8BULL,
		0xA606905C0805CDF8ULL,
		0x5EC7A387087C78A5ULL,
		0x547DD83F09FA3938ULL,
		0xF83FA58B0632EB42ULL,
		0x46B5A1887D9F428AULL,
		0xF54025AFBF94218AULL,
		0x2DE33F2119FDA0E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE071BC1152F6BF16ULL,
		0x4C0D20B8100B9BF1ULL,
		0xBD8F470E10F8F14BULL,
		0xA8FBB07E13F47270ULL,
		0xF07F4B160C65D684ULL,
		0x8D6B4310FB3E8515ULL,
		0xEA804B5F7F284314ULL,
		0x5BC67E4233FB41CFULL
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
		0xCD1BF117D26DB05CULL,
		0x3097D16B82521B7BULL,
		0x2E7932872D7839E7ULL,
		0x0BB877139D6D0EBFULL,
		0x20D3C7B78802442DULL,
		0x381AC16937994B4AULL,
		0xAF1F4D1FFE5321E0ULL,
		0x116FD1349992BD27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A37E22FA4DB60B8ULL,
		0x612FA2D704A436F7ULL,
		0x5CF2650E5AF073CEULL,
		0x1770EE273ADA1D7EULL,
		0x41A78F6F1004885AULL,
		0x703582D26F329694ULL,
		0x5E3E9A3FFCA643C0ULL,
		0x22DFA26933257A4FULL
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
		0x22B3A86119E31581ULL,
		0x722C4CD63179B050ULL,
		0xD7DB75602AE833F3ULL,
		0x8B0EF81BD1B893A1ULL,
		0x637BF2C64600FEA4ULL,
		0xC31A4F968D94DD11ULL,
		0xF9B9175D054C0AD5ULL,
		0x2706B3DD2CF11AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x456750C233C62B02ULL,
		0xE45899AC62F360A0ULL,
		0xAFB6EAC055D067E6ULL,
		0x161DF037A3712743ULL,
		0xC6F7E58C8C01FD49ULL,
		0x86349F2D1B29BA22ULL,
		0xF3722EBA0A9815ABULL,
		0x4E0D67BA59E235F9ULL
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
		0xDAC5C2BAEE21E206ULL,
		0x23A2E905AF7BC1A3ULL,
		0x39632166A32A216AULL,
		0x93BCDC3E219C5D1EULL,
		0xF34A830138B3381AULL,
		0xF0044A4D76123A73ULL,
		0x9E60CC5F5AF28A6BULL,
		0x0C6D3DDA0F3F0129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58B8575DC43C40CULL,
		0x4745D20B5EF78347ULL,
		0x72C642CD465442D4ULL,
		0x2779B87C4338BA3CULL,
		0xE695060271667035ULL,
		0xE008949AEC2474E7ULL,
		0x3CC198BEB5E514D7ULL,
		0x18DA7BB41E7E0253ULL
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
		0x5FEFE40CBC99B182ULL,
		0x0543EC18DABA28F3ULL,
		0x226F50FC3DD428E5ULL,
		0x198BC0A481CAFB96ULL,
		0x7E2998879B4D880EULL,
		0xB05DDD5C73C32F80ULL,
		0x12D0FDC527B63A6EULL,
		0x181AA401060F2AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFDFC81979336304ULL,
		0x0A87D831B57451E6ULL,
		0x44DEA1F87BA851CAULL,
		0x331781490395F72CULL,
		0xFC53310F369B101CULL,
		0x60BBBAB8E7865F00ULL,
		0x25A1FB8A4F6C74DDULL,
		0x303548020C1E55EEULL
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
		0xEA574F851AC79617ULL,
		0x1CAACDD9D2B63946ULL,
		0x6BE3A29C2B3114DCULL,
		0x1BE11EF73FE181EFULL,
		0xAD9B399AB16AB133ULL,
		0xCBF575A505439D68ULL,
		0x1CD2BF6FF312E045ULL,
		0x371D98E04B8CE33CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AE9F0A358F2C2EULL,
		0x39559BB3A56C728DULL,
		0xD7C74538566229B8ULL,
		0x37C23DEE7FC303DEULL,
		0x5B36733562D56266ULL,
		0x97EAEB4A0A873AD1ULL,
		0x39A57EDFE625C08BULL,
		0x6E3B31C09719C678ULL
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
		0x23E867AF15D4FA26ULL,
		0x95719E0A59BDD4FAULL,
		0x95E3A69899BAB5F9ULL,
		0xEA3A1E25C08E17D2ULL,
		0x3B90DB0A60405E01ULL,
		0xD5C295741991FB17ULL,
		0x1E43B30B8AF41549ULL,
		0x366ECA1C67E21119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D0CF5E2BA9F44CULL,
		0x2AE33C14B37BA9F4ULL,
		0x2BC74D3133756BF3ULL,
		0xD4743C4B811C2FA5ULL,
		0x7721B614C080BC03ULL,
		0xAB852AE83323F62EULL,
		0x3C87661715E82A93ULL,
		0x6CDD9438CFC42232ULL
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
		0x248A59D6A27C3DB2ULL,
		0xB7EA929F3CCEE899ULL,
		0x45E9C6838ECA4B75ULL,
		0x4082761FB7DEF793ULL,
		0xD8B75820A16301DEULL,
		0x167C0EF7B584A21DULL,
		0x823DB80BC5B03C7BULL,
		0x2B36223A31F66CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4914B3AD44F87B64ULL,
		0x6FD5253E799DD132ULL,
		0x8BD38D071D9496EBULL,
		0x8104EC3F6FBDEF26ULL,
		0xB16EB04142C603BCULL,
		0x2CF81DEF6B09443BULL,
		0x047B70178B6078F6ULL,
		0x566C447463ECD99DULL
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
		0x8952645896DF6A7FULL,
		0x888E78BC68634156ULL,
		0x2614D9245374292DULL,
		0x77148ED47FDBC82DULL,
		0xA3CEBD886EBBC495ULL,
		0xB6D6EBEF6A0495ADULL,
		0x2CEBAE0875371083ULL,
		0x2C8E539C80B44497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A4C8B12DBED4FEULL,
		0x111CF178D0C682ADULL,
		0x4C29B248A6E8525BULL,
		0xEE291DA8FFB7905AULL,
		0x479D7B10DD77892AULL,
		0x6DADD7DED4092B5BULL,
		0x59D75C10EA6E2107ULL,
		0x591CA7390168892EULL
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
		0xC86F608EB4781DECULL,
		0x5CE0F0F98E5E1BE5ULL,
		0xC11445C3E278C233ULL,
		0x4F4939775A142391ULL,
		0x4AE4D40D7AED0FFEULL,
		0x50735736939965C8ULL,
		0xAC81E79CDD31B280ULL,
		0x3D5DF677EDB9E80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90DEC11D68F03BD8ULL,
		0xB9C1E1F31CBC37CBULL,
		0x82288B87C4F18466ULL,
		0x9E9272EEB4284723ULL,
		0x95C9A81AF5DA1FFCULL,
		0xA0E6AE6D2732CB90ULL,
		0x5903CF39BA636500ULL,
		0x7ABBECEFDB73D01BULL
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
		0x0A4C3CB2F01F2F3FULL,
		0x68EB199433349562ULL,
		0x61060B642DC83D8AULL,
		0xC0EB7D973AA1276DULL,
		0xF62301AD8EB2E95BULL,
		0x2F1DD731D24AD914ULL,
		0xCB58C90DCC0A2773ULL,
		0x1CED5767E3D4AE1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14987965E03E5E7EULL,
		0xD1D6332866692AC4ULL,
		0xC20C16C85B907B14ULL,
		0x81D6FB2E75424EDAULL,
		0xEC46035B1D65D2B7ULL,
		0x5E3BAE63A495B229ULL,
		0x96B1921B98144EE6ULL,
		0x39DAAECFC7A95C37ULL
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
		0xE40F1702DF301CD5ULL,
		0x8C50C759E38675C0ULL,
		0x4BFE405C2E6D31FFULL,
		0x95395789314C1B4AULL,
		0x4CD87B8098E39581ULL,
		0x6A28F1AE9299C304ULL,
		0x2AE0A3CE11B9E4B1ULL,
		0x2E523905DCCBF50DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81E2E05BE6039AAULL,
		0x18A18EB3C70CEB81ULL,
		0x97FC80B85CDA63FFULL,
		0x2A72AF1262983694ULL,
		0x99B0F70131C72B03ULL,
		0xD451E35D25338608ULL,
		0x55C1479C2373C962ULL,
		0x5CA4720BB997EA1AULL
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
		0x5013FAFC503C540CULL,
		0x3F5F05155E3F019CULL,
		0x5E5D115092A6C325ULL,
		0x5E48218246DDFA91ULL,
		0x2C0DA4D67C8F15A7ULL,
		0xCD3A75A1642B3258ULL,
		0xD667676727261470ULL,
		0x16F1618533BDE131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA027F5F8A078A818ULL,
		0x7EBE0A2ABC7E0338ULL,
		0xBCBA22A1254D864AULL,
		0xBC9043048DBBF522ULL,
		0x581B49ACF91E2B4EULL,
		0x9A74EB42C85664B0ULL,
		0xACCECECE4E4C28E1ULL,
		0x2DE2C30A677BC263ULL
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
		0x345A41DDA5E040AEULL,
		0xF2C4F944B5460EBDULL,
		0x924F9CABF38F7A61ULL,
		0xAE428F8E36D43768ULL,
		0x20B31C1782F41990ULL,
		0x047F72C76359FED0ULL,
		0xA916A409CD9267ADULL,
		0x25759BD217DCF839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B483BB4BC0815CULL,
		0xE589F2896A8C1D7AULL,
		0x249F3957E71EF4C3ULL,
		0x5C851F1C6DA86ED1ULL,
		0x4166382F05E83321ULL,
		0x08FEE58EC6B3FDA0ULL,
		0x522D48139B24CF5AULL,
		0x4AEB37A42FB9F073ULL
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
		0xA00482C6416FF834ULL,
		0x21ABF1342768E219ULL,
		0x0C63252BAA19432AULL,
		0xC2D9192379AB171CULL,
		0x3C5232C0004C73DFULL,
		0x96A0BDC8DB2D3F1AULL,
		0x7ED1D304ECCC379BULL,
		0x1B59692F4F29D973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4009058C82DFF068ULL,
		0x4357E2684ED1C433ULL,
		0x18C64A5754328654ULL,
		0x85B23246F3562E38ULL,
		0x78A465800098E7BFULL,
		0x2D417B91B65A7E34ULL,
		0xFDA3A609D9986F37ULL,
		0x36B2D25E9E53B2E6ULL
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
		0xBD6A05194EE1BE31ULL,
		0x66EC836F4A614C1DULL,
		0xAA26FF7E371DCC28ULL,
		0xC216C16BB198D8C2ULL,
		0x0708DE3C45BE5493ULL,
		0xF3A0918D57672838ULL,
		0x12C5AB764C7BEC62ULL,
		0x32F835A556EA715FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD40A329DC37C62ULL,
		0xCDD906DE94C2983BULL,
		0x544DFEFC6E3B9850ULL,
		0x842D82D76331B185ULL,
		0x0E11BC788B7CA927ULL,
		0xE741231AAECE5070ULL,
		0x258B56EC98F7D8C5ULL,
		0x65F06B4AADD4E2BEULL
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
		0xC71D3564A264C528ULL,
		0xEBE4D52A1E9F3006ULL,
		0xD7B8D088DF14F4DCULL,
		0x0A1F8383117013F7ULL,
		0x7FAC68235E1C26B5ULL,
		0xCD828E84C102BEFDULL,
		0xDF839D7DC538D8C0ULL,
		0x0D606995C815513AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3A6AC944C98A50ULL,
		0xD7C9AA543D3E600DULL,
		0xAF71A111BE29E9B9ULL,
		0x143F070622E027EFULL,
		0xFF58D046BC384D6AULL,
		0x9B051D0982057DFAULL,
		0xBF073AFB8A71B181ULL,
		0x1AC0D32B902AA275ULL
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
		0x5FFFA9B213DC7DECULL,
		0x318A88C000360FDEULL,
		0x51AD69D008A414DAULL,
		0x780D10ADB0335390ULL,
		0x55916485E8A9B7A4ULL,
		0x6F92103B170F8656ULL,
		0x74BFA05D2F74444CULL,
		0x34E0BC034228CA76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFFF536427B8FBD8ULL,
		0x63151180006C1FBCULL,
		0xA35AD3A0114829B4ULL,
		0xF01A215B6066A720ULL,
		0xAB22C90BD1536F48ULL,
		0xDF2420762E1F0CACULL,
		0xE97F40BA5EE88898ULL,
		0x69C17806845194ECULL
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
		0x9CC163CC9AF6E361ULL,
		0x9818233B8254A0EBULL,
		0x8EE2FA52E05E6F1BULL,
		0x5C54E6EBF10DBDF4ULL,
		0xD479824CBCB611ABULL,
		0x8AD6B6C06EF21081ULL,
		0xA15D08057AC2DBFAULL,
		0x3BEF99F84E65D606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3982C79935EDC6C2ULL,
		0x3030467704A941D7ULL,
		0x1DC5F4A5C0BCDE37ULL,
		0xB8A9CDD7E21B7BE9ULL,
		0xA8F30499796C2356ULL,
		0x15AD6D80DDE42103ULL,
		0x42BA100AF585B7F5ULL,
		0x77DF33F09CCBAC0DULL
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
		0x632AB0880E9BC77BULL,
		0x1070841C551AA637ULL,
		0x18C8C5AC08ACF3F2ULL,
		0x4FF3B17717847711ULL,
		0x4E28863E66204751ULL,
		0x9CD22A78CBEF85C6ULL,
		0x8439C7434A3C179EULL,
		0x250717E26363487EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65561101D378EF6ULL,
		0x20E10838AA354C6EULL,
		0x31918B581159E7E4ULL,
		0x9FE762EE2F08EE22ULL,
		0x9C510C7CCC408EA2ULL,
		0x39A454F197DF0B8CULL,
		0x08738E8694782F3DULL,
		0x4A0E2FC4C6C690FDULL
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
		0xD429B6DB7C1D4C7BULL,
		0x746C200D65606DA7ULL,
		0x085B4EFF67F8C4ECULL,
		0x571AC9B704114F4BULL,
		0x50F7AEF4A6D960B2ULL,
		0xCE55C6C9D8358E2CULL,
		0xE1222293BEE01395ULL,
		0x38CD15FB0453A521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8536DB6F83A98F6ULL,
		0xE8D8401ACAC0DB4FULL,
		0x10B69DFECFF189D8ULL,
		0xAE35936E08229E96ULL,
		0xA1EF5DE94DB2C164ULL,
		0x9CAB8D93B06B1C58ULL,
		0xC24445277DC0272BULL,
		0x719A2BF608A74A43ULL
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
		0x7B6A18A437501DE9ULL,
		0xF38A75845292AE03ULL,
		0x8364947081FC9C76ULL,
		0x75FB9287BD28F90BULL,
		0x48F583CF19E6F5B0ULL,
		0xDFCD6AD4B9022195ULL,
		0x5B1757282071379FULL,
		0x00B92ED213FFA98EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D431486EA03BD2ULL,
		0xE714EB08A5255C06ULL,
		0x06C928E103F938EDULL,
		0xEBF7250F7A51F217ULL,
		0x91EB079E33CDEB60ULL,
		0xBF9AD5A97204432AULL,
		0xB62EAE5040E26F3FULL,
		0x01725DA427FF531CULL
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
		0x9031469AC7A1CB24ULL,
		0x162FB3D9A8C65AB5ULL,
		0xA3B1F44B975F3EFBULL,
		0x38D84FFA42C9DB0FULL,
		0x26658F18D78E87A4ULL,
		0xAEAA380584CC3909ULL,
		0x53022F7C37550A89ULL,
		0x13C9AAEE421F7CE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20628D358F439648ULL,
		0x2C5F67B3518CB56BULL,
		0x4763E8972EBE7DF6ULL,
		0x71B09FF48593B61FULL,
		0x4CCB1E31AF1D0F48ULL,
		0x5D54700B09987212ULL,
		0xA6045EF86EAA1513ULL,
		0x279355DC843EF9C8ULL
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
		0x91B901FF976F9CC0ULL,
		0x7F16F273D7DD6E38ULL,
		0x75A6AB181DFF23E5ULL,
		0xF178D08BDF5CA45CULL,
		0x4676688106F6C5F0ULL,
		0x1809A7E1A3749543ULL,
		0x463BF28E982C0DCBULL,
		0x25FB35C8D14AB4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237203FF2EDF3980ULL,
		0xFE2DE4E7AFBADC71ULL,
		0xEB4D56303BFE47CAULL,
		0xE2F1A117BEB948B8ULL,
		0x8CECD1020DED8BE1ULL,
		0x30134FC346E92A86ULL,
		0x8C77E51D30581B96ULL,
		0x4BF66B91A29569D0ULL
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
		0x7CF304207C1CDF53ULL,
		0x3C0A28197345A651ULL,
		0x2F24ECD83631E938ULL,
		0x8F1B73F712132B3BULL,
		0xD9AD2096C07BA7A8ULL,
		0x0A3A17CEDB738AC7ULL,
		0x0585677F722FCFF6ULL,
		0x250BDBB40CAC1829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9E60840F839BEA6ULL,
		0x78145032E68B4CA2ULL,
		0x5E49D9B06C63D270ULL,
		0x1E36E7EE24265676ULL,
		0xB35A412D80F74F51ULL,
		0x14742F9DB6E7158FULL,
		0x0B0ACEFEE45F9FECULL,
		0x4A17B76819583052ULL
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
		0xDCD3D757672EF81DULL,
		0x343458FCF48C9420ULL,
		0x3B09933359D73123ULL,
		0x93A1D1E437331BA0ULL,
		0x36B3B47B059A3A5BULL,
		0xD2738FADFD87E021ULL,
		0xAD638B84267130CAULL,
		0x28725B2BE729814CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A7AEAECE5DF03AULL,
		0x6868B1F9E9192841ULL,
		0x76132666B3AE6246ULL,
		0x2743A3C86E663740ULL,
		0x6D6768F60B3474B7ULL,
		0xA4E71F5BFB0FC042ULL,
		0x5AC717084CE26195ULL,
		0x50E4B657CE530299ULL
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
		0xA3D55A47E276D0B4ULL,
		0xF6159D1A11815A20ULL,
		0x35AE260D21851AF7ULL,
		0x86A942DFB61F8865ULL,
		0xCE4087ED75BC7DD1ULL,
		0x10E7594DCAB05745ULL,
		0x4CC0DFA3697E0C3CULL,
		0x38E9171DB3EC0975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AAB48FC4EDA168ULL,
		0xEC2B3A342302B441ULL,
		0x6B5C4C1A430A35EFULL,
		0x0D5285BF6C3F10CAULL,
		0x9C810FDAEB78FBA3ULL,
		0x21CEB29B9560AE8BULL,
		0x9981BF46D2FC1878ULL,
		0x71D22E3B67D812EAULL
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
		0x9C32B7F925953277ULL,
		0x28D3910D3142ABD2ULL,
		0x4065C10E03045311ULL,
		0xEFEF246E2DE52229ULL,
		0x10D5D97D7DA9BA13ULL,
		0xF27FA1E2CA12B792ULL,
		0xD716BAC7F7D0437AULL,
		0x35DBCA39309C58EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38656FF24B2A64EEULL,
		0x51A7221A628557A5ULL,
		0x80CB821C0608A622ULL,
		0xDFDE48DC5BCA4452ULL,
		0x21ABB2FAFB537427ULL,
		0xE4FF43C594256F24ULL,
		0xAE2D758FEFA086F5ULL,
		0x6BB794726138B1D5ULL
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
		0x67DE620FD3C21546ULL,
		0xC03B9813D91E6DBAULL,
		0x6F5DCE7082D0435DULL,
		0xAC48C872019FCD18ULL,
		0x1857F15B29E32975ULL,
		0x0C6DF3BEEE1BDA86ULL,
		0x1AE2DF63A723436FULL,
		0x0CFC35A99C5C5492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFBCC41FA7842A8CULL,
		0x80773027B23CDB74ULL,
		0xDEBB9CE105A086BBULL,
		0x589190E4033F9A30ULL,
		0x30AFE2B653C652EBULL,
		0x18DBE77DDC37B50CULL,
		0x35C5BEC74E4686DEULL,
		0x19F86B5338B8A924ULL
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
		0xA80CE0A835FAA41AULL,
		0x4BB402922C4AB7CCULL,
		0x92D75E2462A69614ULL,
		0x8660087332033E89ULL,
		0x7144D6A2CE8595B2ULL,
		0xAD712A9111CD3631ULL,
		0x451F5596264B3971ULL,
		0x294AC99D820B5576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5019C1506BF54834ULL,
		0x9768052458956F99ULL,
		0x25AEBC48C54D2C28ULL,
		0x0CC010E664067D13ULL,
		0xE289AD459D0B2B65ULL,
		0x5AE25522239A6C62ULL,
		0x8A3EAB2C4C9672E3ULL,
		0x5295933B0416AAECULL
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
		0x86AC0789484ECE74ULL,
		0x0E2BA1BFD8929139ULL,
		0x642B45E6C8C0AA0EULL,
		0xB30CBFE7BA14F1C6ULL,
		0xD4122C82622CAB61ULL,
		0xEA931A2A412F76B9ULL,
		0xB5CE4302E037C610ULL,
		0x33E65829CE128EF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D580F12909D9CE8ULL,
		0x1C57437FB1252273ULL,
		0xC8568BCD9181541CULL,
		0x66197FCF7429E38CULL,
		0xA8245904C45956C3ULL,
		0xD5263454825EED73ULL,
		0x6B9C8605C06F8C21ULL,
		0x67CCB0539C251DE7ULL
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
		0x7B50B9651ADCDEAAULL,
		0x25BDD7B177FC5D03ULL,
		0x680C8201ABE5F205ULL,
		0xABAC9BF6F6A0AB92ULL,
		0x0B073A9282B2CA74ULL,
		0x68C135AF844C532BULL,
		0xDEB35E8AE4278E18ULL,
		0x157F231227C90834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A172CA35B9BD54ULL,
		0x4B7BAF62EFF8BA06ULL,
		0xD019040357CBE40AULL,
		0x575937EDED415724ULL,
		0x160E7525056594E9ULL,
		0xD1826B5F0898A656ULL,
		0xBD66BD15C84F1C30ULL,
		0x2AFE46244F921069ULL
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
		0xBD83054E0A58256FULL,
		0x3A2583C8548D36BEULL,
		0x6E89F21BF57CB93AULL,
		0xFBACA4FB44DA1DE9ULL,
		0xC845D88EF2873A87ULL,
		0xA2B14F9390D26946ULL,
		0x87FE855A1AE00D7EULL,
		0x13596E82D2CB7BBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B060A9C14B04ADEULL,
		0x744B0790A91A6D7DULL,
		0xDD13E437EAF97274ULL,
		0xF75949F689B43BD2ULL,
		0x908BB11DE50E750FULL,
		0x45629F2721A4D28DULL,
		0x0FFD0AB435C01AFDULL,
		0x26B2DD05A596F775ULL
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
		0xABCE2C5F81FC5154ULL,
		0x46EAA30A22817F4FULL,
		0x2805B52D16673C9EULL,
		0x2A626B42CE5A3A80ULL,
		0x8D6019C23C0D5F96ULL,
		0x14F14BE9090E58FBULL,
		0x918542BB05CA9CDFULL,
		0x3B3F2B27D3F9F5ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x579C58BF03F8A2A8ULL,
		0x8DD546144502FE9FULL,
		0x500B6A5A2CCE793CULL,
		0x54C4D6859CB47500ULL,
		0x1AC03384781ABF2CULL,
		0x29E297D2121CB1F7ULL,
		0x230A85760B9539BEULL,
		0x767E564FA7F3EB57ULL
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
		0x6E6B597D95E559A1ULL,
		0x03F81D8B6BB03DB0ULL,
		0xBC7E524027BF82ACULL,
		0x846EB43FFC77CFBEULL,
		0x99812652C3857079ULL,
		0xEDD4281B4022B134ULL,
		0x1DA17C319208C883ULL,
		0x0A3D9EA9ECD4A132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD6B2FB2BCAB342ULL,
		0x07F03B16D7607B60ULL,
		0x78FCA4804F7F0558ULL,
		0x08DD687FF8EF9F7DULL,
		0x33024CA5870AE0F3ULL,
		0xDBA8503680456269ULL,
		0x3B42F86324119107ULL,
		0x147B3D53D9A94264ULL
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
		0xB8F813582CBC9734ULL,
		0x3798D52C02070AE9ULL,
		0xE084E7691FFB38B7ULL,
		0x7BEBD824B633A492ULL,
		0xC458F967E33045E6ULL,
		0xBFF45AC2DC34095EULL,
		0xA7C0F5C8C0D782E2ULL,
		0x138159C2C34B7AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F026B059792E68ULL,
		0x6F31AA58040E15D3ULL,
		0xC109CED23FF6716EULL,
		0xF7D7B0496C674925ULL,
		0x88B1F2CFC6608BCCULL,
		0x7FE8B585B86812BDULL,
		0x4F81EB9181AF05C5ULL,
		0x2702B3858696F54BULL
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
		0xB3CE7252B3AC31ADULL,
		0xD417852D32D9FDC3ULL,
		0x9C05FF70FB32842DULL,
		0x7D57AD77809CEB87ULL,
		0x953F521FE68E74EDULL,
		0xE773BBAAC8622B27ULL,
		0x74A1A7CBCF5E4135ULL,
		0x01A5F01DD3D341CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679CE4A56758635AULL,
		0xA82F0A5A65B3FB87ULL,
		0x380BFEE1F665085BULL,
		0xFAAF5AEF0139D70FULL,
		0x2A7EA43FCD1CE9DAULL,
		0xCEE7775590C4564FULL,
		0xE9434F979EBC826BULL,
		0x034BE03BA7A68396ULL
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
		0xB05F481ABF2F0981ULL,
		0xAF5D62BBE7D7CA70ULL,
		0x83D33159E80455EDULL,
		0x05518B736271F359ULL,
		0x210D880E1748C57DULL,
		0xF30668F28E0D4752ULL,
		0x5F81F003B56199FAULL,
		0x3079DBB7CE07F4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60BE90357E5E1302ULL,
		0x5EBAC577CFAF94E1ULL,
		0x07A662B3D008ABDBULL,
		0x0AA316E6C4E3E6B3ULL,
		0x421B101C2E918AFAULL,
		0xE60CD1E51C1A8EA4ULL,
		0xBF03E0076AC333F5ULL,
		0x60F3B76F9C0FE9DCULL
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
		0xB571586204670E97ULL,
		0x0C5B9C21F3491ABFULL,
		0x9FC1DA3650717C16ULL,
		0x80BED0B2F7881FEDULL,
		0xC0803B631D319CC9ULL,
		0x5A4861DAB0CC094DULL,
		0x773B6528C73CCD8AULL,
		0x1BAC3C8CDC96CF94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE2B0C408CE1D2EULL,
		0x18B73843E692357FULL,
		0x3F83B46CA0E2F82CULL,
		0x017DA165EF103FDBULL,
		0x810076C63A633993ULL,
		0xB490C3B56198129BULL,
		0xEE76CA518E799B14ULL,
		0x37587919B92D9F28ULL
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
		0x5F27623EE7E02F65ULL,
		0xC0E91578CC3CA430ULL,
		0x85B2C44C12CAE603ULL,
		0x9A054530FE30C4EDULL,
		0x5CD023A737853CD2ULL,
		0x9503208A0355D1C2ULL,
		0x79653655867C89F7ULL,
		0x1EA44846B684A722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE4EC47DCFC05ECAULL,
		0x81D22AF198794860ULL,
		0x0B6588982595CC07ULL,
		0x340A8A61FC6189DBULL,
		0xB9A0474E6F0A79A5ULL,
		0x2A06411406ABA384ULL,
		0xF2CA6CAB0CF913EFULL,
		0x3D48908D6D094E44ULL
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
		0x06E3FD09EDDD9B8AULL,
		0x437938A2B8EE0088ULL,
		0x4193769FB468722DULL,
		0x449ACCAF56F4D29CULL,
		0xD26DCE66501D9860ULL,
		0x5512E7C0224F7591ULL,
		0x298352E8A7F4CFA5ULL,
		0x1D2F02EE284A4570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC7FA13DBBB3714ULL,
		0x86F2714571DC0110ULL,
		0x8326ED3F68D0E45AULL,
		0x8935995EADE9A538ULL,
		0xA4DB9CCCA03B30C0ULL,
		0xAA25CF80449EEB23ULL,
		0x5306A5D14FE99F4AULL,
		0x3A5E05DC50948AE0ULL
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
		0xB33BD6C788182FB3ULL,
		0x3A648C267E20B331ULL,
		0x6EDFBE1263320DF2ULL,
		0x61A8A06126D2CBE1ULL,
		0xC387AEC239662E42ULL,
		0x27E31D8B836B81AEULL,
		0xF65A4060035725C4ULL,
		0x29A2F69AD11314C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6677AD8F10305F66ULL,
		0x74C9184CFC416663ULL,
		0xDDBF7C24C6641BE4ULL,
		0xC35140C24DA597C2ULL,
		0x870F5D8472CC5C84ULL,
		0x4FC63B1706D7035DULL,
		0xECB480C006AE4B88ULL,
		0x5345ED35A2262993ULL
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
		0x1F194E3CF41468C2ULL,
		0xB7E5609F652F2DC2ULL,
		0xCB43EA98C7A0900FULL,
		0x5044E163F1642925ULL,
		0x0A7381D8F536E3C3ULL,
		0x49556AF3C653F8D2ULL,
		0x8AE2AE022234DBE0ULL,
		0x2A9D299AEE9CD7C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E329C79E828D184ULL,
		0x6FCAC13ECA5E5B84ULL,
		0x9687D5318F41201FULL,
		0xA089C2C7E2C8524BULL,
		0x14E703B1EA6DC786ULL,
		0x92AAD5E78CA7F1A4ULL,
		0x15C55C044469B7C0ULL,
		0x553A5335DD39AF81ULL
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
		0xFF9E760C3A57A63CULL,
		0xC424EFA555E36987ULL,
		0xADBB560B8D67A948ULL,
		0xEE0F771033271B1CULL,
		0xC7F11304F0653107ULL,
		0xE2BEC7BDFE269E07ULL,
		0x0AD22D05659D0625ULL,
		0x3ABC7AE38DA3632AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF3CEC1874AF4C78ULL,
		0x8849DF4AABC6D30FULL,
		0x5B76AC171ACF5291ULL,
		0xDC1EEE20664E3639ULL,
		0x8FE22609E0CA620FULL,
		0xC57D8F7BFC4D3C0FULL,
		0x15A45A0ACB3A0C4BULL,
		0x7578F5C71B46C654ULL
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
		0xAE2DD503273F66DFULL,
		0xE64FBBB5DA3F9540ULL,
		0xEA82AA3F22FEEBAFULL,
		0x50506F97AB17F07EULL,
		0xEA1B27D995CC18A8ULL,
		0x22A80009467DA05EULL,
		0x02BC4B72F4129926ULL,
		0x3C0B070D50453B50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5BAA064E7ECDBEULL,
		0xCC9F776BB47F2A81ULL,
		0xD505547E45FDD75FULL,
		0xA0A0DF2F562FE0FDULL,
		0xD4364FB32B983150ULL,
		0x455000128CFB40BDULL,
		0x057896E5E825324CULL,
		0x78160E1AA08A76A0ULL
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
		0x67D14089FFAAC638ULL,
		0x64C4CD273046D779ULL,
		0x20170741DF31298DULL,
		0x1DC9D8C6C940F61BULL,
		0x0D061702621A46BAULL,
		0x24FD851D67732C8AULL,
		0xB81F400F77752E4AULL,
		0x10C2310186CBA4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA28113FF558C70ULL,
		0xC9899A4E608DAEF2ULL,
		0x402E0E83BE62531AULL,
		0x3B93B18D9281EC36ULL,
		0x1A0C2E04C4348D74ULL,
		0x49FB0A3ACEE65914ULL,
		0x703E801EEEEA5C94ULL,
		0x218462030D9749C5ULL
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
		0x05661BCA3EC4A6A4ULL,
		0xDEC635EB832D4A44ULL,
		0x81D177DBDCF47FE6ULL,
		0x32A1A8C7393E4898ULL,
		0xC9A0F140DB594929ULL,
		0xB30849AF4998D5C2ULL,
		0xAF4A8F70D948318FULL,
		0x142C875111C847A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ACC37947D894D48ULL,
		0xBD8C6BD7065A9488ULL,
		0x03A2EFB7B9E8FFCDULL,
		0x6543518E727C9131ULL,
		0x9341E281B6B29252ULL,
		0x6610935E9331AB85ULL,
		0x5E951EE1B290631FULL,
		0x28590EA223908F47ULL
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
		0xC8218127F8596DFCULL,
		0x74E7DBA3B4427984ULL,
		0x182F1B8079DC78CBULL,
		0xD1D48E2F22C34281ULL,
		0xE6E4EB70C516B814ULL,
		0xBB6D89294162D366ULL,
		0x7FA78EC51B6E7711ULL,
		0x07E0AFADF01F2B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9043024FF0B2DBF8ULL,
		0xE9CFB7476884F309ULL,
		0x305E3700F3B8F196ULL,
		0xA3A91C5E45868502ULL,
		0xCDC9D6E18A2D7029ULL,
		0x76DB125282C5A6CDULL,
		0xFF4F1D8A36DCEE23ULL,
		0x0FC15F5BE03E56C8ULL
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
		0x8410E0E8589009BDULL,
		0xFAC2367E880B4348ULL,
		0xAFB7533BDB1FFA2AULL,
		0x63D86A572D7F8A38ULL,
		0x80EA398E0C093007ULL,
		0x2E932D93B118853EULL,
		0xB201C984CFCEF89FULL,
		0x13A0CE8F7060283FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0821C1D0B120137AULL,
		0xF5846CFD10168691ULL,
		0x5F6EA677B63FF455ULL,
		0xC7B0D4AE5AFF1471ULL,
		0x01D4731C1812600EULL,
		0x5D265B2762310A7DULL,
		0x640393099F9DF13EULL,
		0x27419D1EE0C0507FULL
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
		0x7A9254FDFC02A640ULL,
		0xBF6494BE79728691ULL,
		0x90EB3EB9537D9C22ULL,
		0x6BE28843E35E0F8BULL,
		0x5E425C84960E4D99ULL,
		0x733E82D4E0222D2DULL,
		0x258745C557A2F4B4ULL,
		0x105674D385BD5DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF524A9FBF8054C80ULL,
		0x7EC9297CF2E50D22ULL,
		0x21D67D72A6FB3845ULL,
		0xD7C51087C6BC1F17ULL,
		0xBC84B9092C1C9B32ULL,
		0xE67D05A9C0445A5AULL,
		0x4B0E8B8AAF45E968ULL,
		0x20ACE9A70B7ABBC2ULL
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
		0x400214A79B554DADULL,
		0xF699A4D20D0C34ACULL,
		0xDC63A9A13F56A5ACULL,
		0xA250D2A01AFA1E35ULL,
		0x5B0F937BDF992305ULL,
		0x2B07A220CFE76800ULL,
		0xE1E2ED98F5204323ULL,
		0x02A5E97334ACFBFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8004294F36AA9B5AULL,
		0xED3349A41A186958ULL,
		0xB8C753427EAD4B59ULL,
		0x44A1A54035F43C6BULL,
		0xB61F26F7BF32460BULL,
		0x560F44419FCED000ULL,
		0xC3C5DB31EA408646ULL,
		0x054BD2E66959F7FDULL
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
		0x818F2FDC1C2E7694ULL,
		0x6062F9DDE9559B2FULL,
		0xE8C275A6AE8F0844ULL,
		0xC0F8FB9024E28A15ULL,
		0x0F3DFC6A1F45419FULL,
		0x09E25502EE3D8B1FULL,
		0x369CEA19D0D32086ULL,
		0x2A9A4286D3F591BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x031E5FB8385CED28ULL,
		0xC0C5F3BBD2AB365FULL,
		0xD184EB4D5D1E1088ULL,
		0x81F1F72049C5142BULL,
		0x1E7BF8D43E8A833FULL,
		0x13C4AA05DC7B163EULL,
		0x6D39D433A1A6410CULL,
		0x5534850DA7EB2378ULL
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
		0xB21D831E1F5ED691ULL,
		0x04DF5831FF0F8B96ULL,
		0xAD040502A1F88D5CULL,
		0xD68FFD36FA082373ULL,
		0xF2CA397736DB83E4ULL,
		0x7048BDB374252078ULL,
		0xB0F6D36DE33FB0E3ULL,
		0x063FF8B1AFBB81B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643B063C3EBDAD22ULL,
		0x09BEB063FE1F172DULL,
		0x5A080A0543F11AB8ULL,
		0xAD1FFA6DF41046E7ULL,
		0xE59472EE6DB707C9ULL,
		0xE0917B66E84A40F1ULL,
		0x61EDA6DBC67F61C6ULL,
		0x0C7FF1635F770363ULL
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
	k1 = (curve25519_key_t){.key64 = {
		0x3870D38C0DEDEA77ULL,
		0x9ACFEDF8F20DA97BULL,
		0x25B1922145CADB5CULL,
		0xE6CD93E48CA2D7E0ULL,
		0xD11FCAC7C4B36AAFULL,
		0x3A46C4BFA2E0CA70ULL,
		0x5C40FA5288290988ULL,
		0x3343836B83B2A394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E1A7181BDBD4EEULL,
		0x359FDBF1E41B52F6ULL,
		0x4B6324428B95B6B9ULL,
		0xCD9B27C91945AFC0ULL,
		0xA23F958F8966D55FULL,
		0x748D897F45C194E1ULL,
		0xB881F4A510521310ULL,
		0x668706D707654728ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x448F35A24E95CB01ULL,
		0x9E0A3E48F96FACC4ULL,
		0x10BCAC877C25D483ULL,
		0x8685F421782CE249ULL,
		0xD9ED37EAAE505F10ULL,
		0xD6971B7C9A71D4E7ULL,
		0xA71CAABE3F4C730DULL,
		0x32B63B9D0D444FAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891E6B449D2B9602ULL,
		0x3C147C91F2DF5988ULL,
		0x2179590EF84BA907ULL,
		0x0D0BE842F059C492ULL,
		0xB3DA6FD55CA0BE21ULL,
		0xAD2E36F934E3A9CFULL,
		0x4E39557C7E98E61BULL,
		0x656C773A1A889F55ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98ADBAD91F6DD5C2ULL,
		0xAB21F7F83310397BULL,
		0x696720BC6C9ECA1DULL,
		0xA5786879D8C2350DULL,
		0x684B47108FB618E5ULL,
		0xB5B91832B6FAB247ULL,
		0xA5BB810C8C56B871ULL,
		0x16DA2FB3D01C98AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x315B75B23EDBAB84ULL,
		0x5643EFF0662072F7ULL,
		0xD2CE4178D93D943BULL,
		0x4AF0D0F3B1846A1AULL,
		0xD0968E211F6C31CBULL,
		0x6B7230656DF5648EULL,
		0x4B77021918AD70E3ULL,
		0x2DB45F67A039315DULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5171B2B136894B7BULL,
		0x6B2A58B454095953ULL,
		0x9191CA23602E76A5ULL,
		0xC1A736C99E90C415ULL,
		0x0F6E922DC1BB0896ULL,
		0xD0BA892867F569E9ULL,
		0xEB40A3E8AA55FEA1ULL,
		0x0470B03C9182D2F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E365626D1296F6ULL,
		0xD654B168A812B2A6ULL,
		0x23239446C05CED4AULL,
		0x834E6D933D21882BULL,
		0x1EDD245B8376112DULL,
		0xA1751250CFEAD3D2ULL,
		0xD68147D154ABFD43ULL,
		0x08E160792305A5F3ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x494C76C299A735ADULL,
		0x547E02797FFA299CULL,
		0x9A20D76C3ABA8679ULL,
		0x4DCFA7A1584BCDC1ULL,
		0x0E5EA9D58F7404D8ULL,
		0xDA63DCEAB4D116DDULL,
		0x91DEF7BF38847D39ULL,
		0x0BD378EFC4A2C1FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9298ED85334E6B5AULL,
		0xA8FC04F2FFF45338ULL,
		0x3441AED875750CF2ULL,
		0x9B9F4F42B0979B83ULL,
		0x1CBD53AB1EE809B0ULL,
		0xB4C7B9D569A22DBAULL,
		0x23BDEF7E7108FA73ULL,
		0x17A6F1DF894583FBULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF90D8EB082329ED5ULL,
		0x017543E148765664ULL,
		0xA84659EF130CFE04ULL,
		0xE34735A476E99B50ULL,
		0xB65541F0C71453C9ULL,
		0x2B59848CE2B21489ULL,
		0xA32D18D945B91B1EULL,
		0x1D825347A5853D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF21B1D6104653DAAULL,
		0x02EA87C290ECACC9ULL,
		0x508CB3DE2619FC08ULL,
		0xC68E6B48EDD336A1ULL,
		0x6CAA83E18E28A793ULL,
		0x56B30919C5642913ULL,
		0x465A31B28B72363CULL,
		0x3B04A68F4B0A7B09ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF17EE7210ACDA5EULL,
		0xAF20F813F45D4621ULL,
		0x6E05560E7B46F998ULL,
		0xAB46D11296E7A3D7ULL,
		0xED680B418BE6E099ULL,
		0x5BEEAAD82041AD43ULL,
		0xBDEFE5775BE6CE5EULL,
		0x0FF0064E6B2DC9B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E2FDCE42159B4BCULL,
		0x5E41F027E8BA8C43ULL,
		0xDC0AAC1CF68DF331ULL,
		0x568DA2252DCF47AEULL,
		0xDAD0168317CDC133ULL,
		0xB7DD55B040835A87ULL,
		0x7BDFCAEEB7CD9CBCULL,
		0x1FE00C9CD65B9371ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8D636BF64F8BCC0ULL,
		0x5997147D7D8163DDULL,
		0xFF06DB67F64BA05CULL,
		0x98009236CEB5AA4BULL,
		0x208FC9178AFFC169ULL,
		0x200BA8FC419BA613ULL,
		0x4C46AB040A9A3838ULL,
		0x3E24FD67AAB3BBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91AC6D7EC9F17980ULL,
		0xB32E28FAFB02C7BBULL,
		0xFE0DB6CFEC9740B8ULL,
		0x3001246D9D6B5497ULL,
		0x411F922F15FF82D3ULL,
		0x401751F883374C26ULL,
		0x988D560815347070ULL,
		0x7C49FACF556777E2ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A0A5C11D7A0D0C8ULL,
		0x407D8763D849F0D0ULL,
		0xE739C5C4E23DB97AULL,
		0x6D75C04B93AAB396ULL,
		0x31EB46D6F08237E2ULL,
		0xDA2EBC3D3568F717ULL,
		0xB4A760E671DABE61ULL,
		0x256C0E6864872B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3414B823AF41A190ULL,
		0x80FB0EC7B093E1A0ULL,
		0xCE738B89C47B72F4ULL,
		0xDAEB80972755672DULL,
		0x63D68DADE1046FC4ULL,
		0xB45D787A6AD1EE2EULL,
		0x694EC1CCE3B57CC3ULL,
		0x4AD81CD0C90E5647ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE282D3E48B5F6573ULL,
		0x5E93BEF04CC6B13EULL,
		0xB972935A07E87227ULL,
		0x94CDBAB893614F3CULL,
		0x6F0574A02513081CULL,
		0x762D4B6E5B94EC75ULL,
		0x5E69D23FDD479F65ULL,
		0x0A3D6D1EF7295610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC505A7C916BECAE6ULL,
		0xBD277DE0998D627DULL,
		0x72E526B40FD0E44EULL,
		0x299B757126C29E79ULL,
		0xDE0AE9404A261039ULL,
		0xEC5A96DCB729D8EAULL,
		0xBCD3A47FBA8F3ECAULL,
		0x147ADA3DEE52AC20ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7947027FB8F703B7ULL,
		0xD580A633C3C5BB68ULL,
		0xF203AB1BA8BBA2F6ULL,
		0x939D0A4112FAEEC8ULL,
		0xAC8633F9A018A4BBULL,
		0xE92313E5C277F886ULL,
		0x3CA9824706DDFC2CULL,
		0x0FD9CFA9D4877AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF28E04FF71EE076EULL,
		0xAB014C67878B76D0ULL,
		0xE4075637517745EDULL,
		0x273A148225F5DD91ULL,
		0x590C67F340314977ULL,
		0xD24627CB84EFF10DULL,
		0x7953048E0DBBF859ULL,
		0x1FB39F53A90EF5ACULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5817DAF8D06A714ULL,
		0xBEEC57A1B07F99BCULL,
		0x5F1CB21E9A1F65D1ULL,
		0x1104DEE6407832ECULL,
		0xE01C4A65CC6AF1C1ULL,
		0xBDEEF2B34E488D37ULL,
		0xE1209E720A2B625CULL,
		0x0D49BE8F9C41ED96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB02FB5F1A0D4E28ULL,
		0x7DD8AF4360FF3379ULL,
		0xBE39643D343ECBA3ULL,
		0x2209BDCC80F065D8ULL,
		0xC03894CB98D5E382ULL,
		0x7BDDE5669C911A6FULL,
		0xC2413CE41456C4B9ULL,
		0x1A937D1F3883DB2DULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DE19BC42F644BE0ULL,
		0x670611DC2BD07811ULL,
		0xFD1DE10541048684ULL,
		0xE4ABD25BAFA4D39FULL,
		0x228AE13B58DF3EDFULL,
		0x742A68B5661C2193ULL,
		0x59BAD5B9FE03A2ACULL,
		0x053007700CCA96CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC337885EC897C0ULL,
		0xCE0C23B857A0F022ULL,
		0xFA3BC20A82090D08ULL,
		0xC957A4B75F49A73FULL,
		0x4515C276B1BE7DBFULL,
		0xE854D16ACC384326ULL,
		0xB375AB73FC074558ULL,
		0x0A600EE019952D9CULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA38CBEE36600AB04ULL,
		0x0D675ABEF621699DULL,
		0x9BF35201734A3E00ULL,
		0x8687FF36518F87EFULL,
		0xBDE435834A548272ULL,
		0x69CF5FAF2898A404ULL,
		0x60521E438734F640ULL,
		0x088AFF7F90BFB398ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47197DC6CC015608ULL,
		0x1ACEB57DEC42D33BULL,
		0x37E6A402E6947C00ULL,
		0x0D0FFE6CA31F0FDFULL,
		0x7BC86B0694A904E5ULL,
		0xD39EBF5E51314809ULL,
		0xC0A43C870E69EC80ULL,
		0x1115FEFF217F6730ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10140BAD4C2878EFULL,
		0x452A44BB345518A0ULL,
		0x492D1CCC0210AB4EULL,
		0x2CAA31C256442223ULL,
		0xC51F750F71FCF85CULL,
		0xE64E0BCA857DAF53ULL,
		0xAB6065DBE0B0FE81ULL,
		0x28DDC3BB114742DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2028175A9850F1DEULL,
		0x8A54897668AA3140ULL,
		0x925A39980421569CULL,
		0x59546384AC884446ULL,
		0x8A3EEA1EE3F9F0B8ULL,
		0xCC9C17950AFB5EA7ULL,
		0x56C0CBB7C161FD03ULL,
		0x51BB8776228E85B7ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9DF07A9F78B687CULL,
		0x90DE63C41816D85FULL,
		0x5169EAC8515289DDULL,
		0xAE8CC2A97B504B2BULL,
		0xDB1D966D7040CD01ULL,
		0x050A203EC383E18FULL,
		0x4546F199B6DE9A0EULL,
		0x1AC7F92822D5CC33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3BE0F53EF16D0F8ULL,
		0x21BCC788302DB0BFULL,
		0xA2D3D590A2A513BBULL,
		0x5D198552F6A09656ULL,
		0xB63B2CDAE0819A03ULL,
		0x0A14407D8707C31FULL,
		0x8A8DE3336DBD341CULL,
		0x358FF25045AB9866ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7427B275A902B2A8ULL,
		0xAD6AB8DCFDE7CAAAULL,
		0x50703EC260131380ULL,
		0x114F21559586F8C3ULL,
		0x052658C4309D5B81ULL,
		0x620AF9C4B75F087EULL,
		0xB2049003CEBDB09CULL,
		0x1E200650D0AA0D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE84F64EB52056550ULL,
		0x5AD571B9FBCF9554ULL,
		0xA0E07D84C0262701ULL,
		0x229E42AB2B0DF186ULL,
		0x0A4CB188613AB702ULL,
		0xC415F3896EBE10FCULL,
		0x640920079D7B6138ULL,
		0x3C400CA1A1541ABDULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5C78CA60E806113ULL,
		0x82EB625402F17246ULL,
		0x683D11C39B8219C5ULL,
		0x23F9273CAE5E816EULL,
		0x2A35096994CC639DULL,
		0x208B5A5B9BA0F247ULL,
		0x1A6887ED217BB1F2ULL,
		0x1CB2949C0A6BBE06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB8F194C1D00C226ULL,
		0x05D6C4A805E2E48DULL,
		0xD07A23873704338BULL,
		0x47F24E795CBD02DCULL,
		0x546A12D32998C73AULL,
		0x4116B4B73741E48EULL,
		0x34D10FDA42F763E4ULL,
		0x3965293814D77C0CULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47E133EF01D5D093ULL,
		0xFE28573C24E27B5BULL,
		0x917801932E8102E4ULL,
		0x0438034A11118F63ULL,
		0x7DF4BE972155093EULL,
		0x55E093575F4DA817ULL,
		0x7F26C3A4FEBF1BB6ULL,
		0x058C89B08EBF49F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC267DE03ABA126ULL,
		0xFC50AE7849C4F6B6ULL,
		0x22F003265D0205C9ULL,
		0x0870069422231EC7ULL,
		0xFBE97D2E42AA127CULL,
		0xABC126AEBE9B502EULL,
		0xFE4D8749FD7E376CULL,
		0x0B1913611D7E93E8ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x709B0EC48480D8BEULL,
		0x8945B40244AC8C1FULL,
		0x9E9C22D53EB3FC80ULL,
		0x8A37754067A81E3BULL,
		0xB7C8AA445C17887FULL,
		0x23726D46F20883DDULL,
		0xA36B9115C6640F58ULL,
		0x193E931A44F0493EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1361D890901B17CULL,
		0x128B68048959183EULL,
		0x3D3845AA7D67F901ULL,
		0x146EEA80CF503C77ULL,
		0x6F915488B82F10FFULL,
		0x46E4DA8DE41107BBULL,
		0x46D7222B8CC81EB0ULL,
		0x327D263489E0927DULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37585F9DF2766175ULL,
		0x69817174707DEA30ULL,
		0xA92974A48878618FULL,
		0x2637BFC1A4212C08ULL,
		0xDF53AC246681D8B6ULL,
		0x9DC0B350DF7A4963ULL,
		0x3ACF126AD3B6CD1AULL,
		0x22B1A43697798530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB0BF3BE4ECC2EAULL,
		0xD302E2E8E0FBD460ULL,
		0x5252E94910F0C31EULL,
		0x4C6F7F8348425811ULL,
		0xBEA75848CD03B16CULL,
		0x3B8166A1BEF492C7ULL,
		0x759E24D5A76D9A35ULL,
		0x4563486D2EF30A60ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF33ACC296D8A889ULL,
		0x21009713EC4E713FULL,
		0x7AE83641BD31C12BULL,
		0x41162ED739AFDA9CULL,
		0x24F9BB31289363B3ULL,
		0x55CEEF472DBFE806ULL,
		0x516EEF9C7151BF7CULL,
		0x01662C64493908B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6759852DB15112ULL,
		0x42012E27D89CE27FULL,
		0xF5D06C837A638256ULL,
		0x822C5DAE735FB538ULL,
		0x49F376625126C766ULL,
		0xAB9DDE8E5B7FD00CULL,
		0xA2DDDF38E2A37EF8ULL,
		0x02CC58C892721168ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7F2215B871BBEC3ULL,
		0x452C64121A381D21ULL,
		0xFC05F4134A2E9860ULL,
		0x103627965DA984CEULL,
		0x3FDB2C9CDE3A242CULL,
		0xC0C53A0238B6DCC9ULL,
		0x774430C3A066724DULL,
		0x2A2342E4083EC999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE442B70E377D86ULL,
		0x8A58C82434703A43ULL,
		0xF80BE826945D30C0ULL,
		0x206C4F2CBB53099DULL,
		0x7FB65939BC744858ULL,
		0x818A7404716DB992ULL,
		0xEE88618740CCE49BULL,
		0x544685C8107D9332ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52624B512209D60BULL,
		0x9C7E2E4DEF0DDABBULL,
		0x4CE51594B85DD18CULL,
		0xE78AF6E131D79CBBULL,
		0x9153E998995ABF7FULL,
		0xB3FBDF77C0157C1EULL,
		0xBCE19A96669DDDF7ULL,
		0x30042ACF38A20B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4C496A24413AC16ULL,
		0x38FC5C9BDE1BB576ULL,
		0x99CA2B2970BBA319ULL,
		0xCF15EDC263AF3976ULL,
		0x22A7D33132B57EFFULL,
		0x67F7BEEF802AF83DULL,
		0x79C3352CCD3BBBEFULL,
		0x6008559E714416AFULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F9CC64BD51BD2B5ULL,
		0xDC9DAE2861B0D138ULL,
		0x0DCF6D643F7349D8ULL,
		0xEFBFEAFCDB4AD88FULL,
		0xC2464091FB11DC3EULL,
		0x53ADD734653E8904ULL,
		0x9C354A4714F89815ULL,
		0x03A5C95EF03C04EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F398C97AA37A56AULL,
		0xB93B5C50C361A270ULL,
		0x1B9EDAC87EE693B1ULL,
		0xDF7FD5F9B695B11EULL,
		0x848C8123F623B87DULL,
		0xA75BAE68CA7D1209ULL,
		0x386A948E29F1302AULL,
		0x074B92BDE07809DBULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C73B7FD74C77767ULL,
		0x6468351E57C433E7ULL,
		0x7E45AFC2EDE84925ULL,
		0xD41E57415ADA9334ULL,
		0x24BFA696078F6FFAULL,
		0x5E769972D8EACBB1ULL,
		0x7FD7119845A5F60DULL,
		0x1015DA2D7A9131B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E76FFAE98EEECEULL,
		0xC8D06A3CAF8867CEULL,
		0xFC8B5F85DBD0924AULL,
		0xA83CAE82B5B52668ULL,
		0x497F4D2C0F1EDFF5ULL,
		0xBCED32E5B1D59762ULL,
		0xFFAE23308B4BEC1AULL,
		0x202BB45AF5226364ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD0F3AB3DCF5B51ULL,
		0xAE80FC8B02957EEDULL,
		0x238271D53CDC3C36ULL,
		0x6171716ADB4EC503ULL,
		0x565913E181341E31ULL,
		0xB386B66C3A3C68F5ULL,
		0x1BE341DDB4E948E7ULL,
		0x0CEFC3C4A396A6D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A1E7567B9EB6A2ULL,
		0x5D01F916052AFDDBULL,
		0x4704E3AA79B8786DULL,
		0xC2E2E2D5B69D8A06ULL,
		0xACB227C302683C62ULL,
		0x670D6CD87478D1EAULL,
		0x37C683BB69D291CFULL,
		0x19DF8789472D4DB0ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x954B3FFB1C8519B2ULL,
		0x7454E88EF320BDECULL,
		0x2FED0B8447FDC924ULL,
		0xB12D3A5475C93850ULL,
		0x1800CD7F7ACA8D9EULL,
		0xF0635A370BA26A86ULL,
		0x19B8394A0DB18FA4ULL,
		0x2593E24F5F1AFBBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A967FF6390A3364ULL,
		0xE8A9D11DE6417BD9ULL,
		0x5FDA17088FFB9248ULL,
		0x625A74A8EB9270A0ULL,
		0x30019AFEF5951B3DULL,
		0xE0C6B46E1744D50CULL,
		0x337072941B631F49ULL,
		0x4B27C49EBE35F77CULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE88321181B8FE44ULL,
		0x5DB975B893822EA4ULL,
		0xC87DA55D3B0FFD4FULL,
		0xBF40CADD70EBBABBULL,
		0x9C9EA5B60E2A48E6ULL,
		0xE658180A2EF471CFULL,
		0x2658C869BA2FD557ULL,
		0x2C844D8F7F7376BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD1064230371FC88ULL,
		0xBB72EB7127045D49ULL,
		0x90FB4ABA761FFA9EULL,
		0x7E8195BAE1D77577ULL,
		0x393D4B6C1C5491CDULL,
		0xCCB030145DE8E39FULL,
		0x4CB190D3745FAAAFULL,
		0x59089B1EFEE6ED7EULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA941CF6543C2F68FULL,
		0x9D1946D9806E407DULL,
		0x38200EF84889E80EULL,
		0x5A27480FD9B8065DULL,
		0x0605B070F3A56F07ULL,
		0x145BDE6F9BBA21A4ULL,
		0x1D8266AE37D2F6C6ULL,
		0x28D22E6A28D15A99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52839ECA8785ED1EULL,
		0x3A328DB300DC80FBULL,
		0x70401DF09113D01DULL,
		0xB44E901FB3700CBAULL,
		0x0C0B60E1E74ADE0EULL,
		0x28B7BCDF37744348ULL,
		0x3B04CD5C6FA5ED8CULL,
		0x51A45CD451A2B532ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD036BE11F523858ULL,
		0x2B5E72FE334EEF6DULL,
		0x112DC54CD4ABD7D9ULL,
		0x8D9362CDFE38D109ULL,
		0xAD2FAB000FAAD25BULL,
		0x047C0C282FE6F727ULL,
		0x91F0337CD3D8C89CULL,
		0x35ABAFBC2A9603F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A06D7C23EA470B0ULL,
		0x56BCE5FC669DDEDBULL,
		0x225B8A99A957AFB2ULL,
		0x1B26C59BFC71A212ULL,
		0x5A5F56001F55A4B7ULL,
		0x08F818505FCDEE4FULL,
		0x23E066F9A7B19138ULL,
		0x6B575F78552C07E9ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2133048C517CAC6AULL,
		0x2E02D653B10891E3ULL,
		0xAF310BD3F3D88ECAULL,
		0x4487D953079F149AULL,
		0x13BDB474DFF1D398ULL,
		0x7C8450CDE1EDD928ULL,
		0x9AFEB1F193374564ULL,
		0x3FAE58A0CD561A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42660918A2F958D4ULL,
		0x5C05ACA7621123C6ULL,
		0x5E6217A7E7B11D94ULL,
		0x890FB2A60F3E2935ULL,
		0x277B68E9BFE3A730ULL,
		0xF908A19BC3DBB250ULL,
		0x35FD63E3266E8AC8ULL,
		0x7F5CB1419AAC351FULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE11E2D6D83DBEF1ULL,
		0x74D9FD7DF9FAB05BULL,
		0xF58079A88CEF3672ULL,
		0xF35AD7ADDE9661ADULL,
		0xAF4B7F6EC2983CFFULL,
		0x9E4BA51E16229973ULL,
		0xD5022A65E281E39BULL,
		0x3F7CF284D763CF82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC23C5ADB07B7DE2ULL,
		0xE9B3FAFBF3F560B7ULL,
		0xEB00F35119DE6CE4ULL,
		0xE6B5AF5BBD2CC35BULL,
		0x5E96FEDD853079FFULL,
		0x3C974A3C2C4532E7ULL,
		0xAA0454CBC503C737ULL,
		0x7EF9E509AEC79F05ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0033651D0CD0BA47ULL,
		0xE643DE503E85EB21ULL,
		0xEAD4FB90B7F12452ULL,
		0xF68EFE67F0C1E3CEULL,
		0x9C7BD9998D618A47ULL,
		0x6148CF4DF0DDC483ULL,
		0x5B408FB76CBA1D0EULL,
		0x392766487783A499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0066CA3A19A1748EULL,
		0xCC87BCA07D0BD642ULL,
		0xD5A9F7216FE248A5ULL,
		0xED1DFCCFE183C79DULL,
		0x38F7B3331AC3148FULL,
		0xC2919E9BE1BB8907ULL,
		0xB6811F6ED9743A1CULL,
		0x724ECC90EF074932ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB72595EEB4FD584FULL,
		0x2CFD7CA86FFFAE04ULL,
		0x5F3B5892A06CF3BBULL,
		0x9CFA492438C2817DULL,
		0x201CD0F2327CE6E2ULL,
		0xE8DDC7978334FD13ULL,
		0xBB1363AA7E6A37E8ULL,
		0x3F2283CFFEB9AF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4B2BDD69FAB09EULL,
		0x59FAF950DFFF5C09ULL,
		0xBE76B12540D9E776ULL,
		0x39F49248718502FAULL,
		0x4039A1E464F9CDC5ULL,
		0xD1BB8F2F0669FA26ULL,
		0x7626C754FCD46FD1ULL,
		0x7E45079FFD735E93ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA54BD49A1D000AF5ULL,
		0xF469691B1B9045B4ULL,
		0x15F3D4B752AC0224ULL,
		0x15770EFEADA224EFULL,
		0x13B86682F25674E4ULL,
		0xF0FF7006BB7F7B80ULL,
		0x660A652CB4911079ULL,
		0x377B5F7B100E7B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A97A9343A0015EAULL,
		0xE8D2D23637208B69ULL,
		0x2BE7A96EA5580449ULL,
		0x2AEE1DFD5B4449DEULL,
		0x2770CD05E4ACE9C8ULL,
		0xE1FEE00D76FEF700ULL,
		0xCC14CA59692220F3ULL,
		0x6EF6BEF6201CF6F4ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DDE47BAE78EC9B7ULL,
		0x33992FD6ED64CF5EULL,
		0x13AF13C1FB4DE968ULL,
		0x7B8206BA1B3B038DULL,
		0x45EC7363998196E7ULL,
		0x30E0186FEDA80188ULL,
		0x65F5A5B373AA2D70ULL,
		0x302105DE276E88DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBBC8F75CF1D936EULL,
		0x67325FADDAC99EBCULL,
		0x275E2783F69BD2D0ULL,
		0xF7040D743676071AULL,
		0x8BD8E6C733032DCEULL,
		0x61C030DFDB500310ULL,
		0xCBEB4B66E7545AE0ULL,
		0x60420BBC4EDD11BAULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB267BE7B7EF32DF8ULL,
		0xC4AF279112BAD1F7ULL,
		0xCEC5FA1F6F7BD315ULL,
		0xC531A939B6D6FDF9ULL,
		0x2342B11F5BF7738BULL,
		0xB7C71201363060FBULL,
		0x9CDFC9CC9ECF2169ULL,
		0x0E9709AB28FF49F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64CF7CF6FDE65BF0ULL,
		0x895E4F222575A3EFULL,
		0x9D8BF43EDEF7A62BULL,
		0x8A6352736DADFBF3ULL,
		0x4685623EB7EEE717ULL,
		0x6F8E24026C60C1F6ULL,
		0x39BF93993D9E42D3ULL,
		0x1D2E135651FE93EDULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA0F01DF6276EBF6ULL,
		0xC310186FE2AC4E92ULL,
		0xDF0579648D4CC51EULL,
		0xF9F0ABD18DD28E38ULL,
		0x47461D74A09CC0DBULL,
		0xF5B2C7C9410C0C89ULL,
		0xF6144D21BA837508ULL,
		0x3F4F45F8F799C5CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41E03BEC4EDD7ECULL,
		0x862030DFC5589D25ULL,
		0xBE0AF2C91A998A3DULL,
		0xF3E157A31BA51C71ULL,
		0x8E8C3AE9413981B7ULL,
		0xEB658F9282181912ULL,
		0xEC289A437506EA11ULL,
		0x7E9E8BF1EF338B9BULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BB949B98B94902EULL,
		0x52D1127596854351ULL,
		0xAC8A9219D4983521ULL,
		0xD2D47EA2F9E627DFULL,
		0x9EAAE34C1A486981ULL,
		0x38E195604AC61C60ULL,
		0xF497DD12EFEDB263ULL,
		0x18B90EA3EB429249ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977293731729205CULL,
		0xA5A224EB2D0A86A2ULL,
		0x59152433A9306A42ULL,
		0xA5A8FD45F3CC4FBFULL,
		0x3D55C6983490D303ULL,
		0x71C32AC0958C38C1ULL,
		0xE92FBA25DFDB64C6ULL,
		0x31721D47D6852493ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA74084D06389DE3ULL,
		0x629FC9C077A0192CULL,
		0x506ED1BB9F948AAEULL,
		0xB1DD0434305584B7ULL,
		0x511A226B94CF4DC7ULL,
		0xF36ADC00230B3791ULL,
		0xE1E864BD117CEA9DULL,
		0x0E5EE9B3317F1DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E8109A0C713BC6ULL,
		0xC53F9380EF403259ULL,
		0xA0DDA3773F29155CULL,
		0x63BA086860AB096EULL,
		0xA23444D7299E9B8FULL,
		0xE6D5B80046166F22ULL,
		0xC3D0C97A22F9D53BULL,
		0x1CBDD36662FE3BF7ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0573D87E8FEB9626ULL,
		0xDE3E0D01AB865ECFULL,
		0xAEDCC64DA553B7CFULL,
		0xD133645AC6A18D60ULL,
		0xC63A07107A1AF0F8ULL,
		0x4042978E8CF4FA8CULL,
		0x4439F23D31A0DEEFULL,
		0x17F04B057E77DDB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE7B0FD1FD72C4CULL,
		0xBC7C1A03570CBD9EULL,
		0x5DB98C9B4AA76F9FULL,
		0xA266C8B58D431AC1ULL,
		0x8C740E20F435E1F1ULL,
		0x80852F1D19E9F519ULL,
		0x8873E47A6341BDDEULL,
		0x2FE0960AFCEFBB62ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8105414889E027CULL,
		0x384CCEEE78078E10ULL,
		0x74DE2AEBE72BF29AULL,
		0x8B647129D04528DEULL,
		0xB49BE3E46617BBBCULL,
		0x62A2619780610F5FULL,
		0x2FA90E945B1094C9ULL,
		0x0CF6B6A000FE966BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5020A829113C04F8ULL,
		0x70999DDCF00F1C21ULL,
		0xE9BC55D7CE57E534ULL,
		0x16C8E253A08A51BCULL,
		0x6937C7C8CC2F7779ULL,
		0xC544C32F00C21EBFULL,
		0x5F521D28B6212992ULL,
		0x19ED6D4001FD2CD6ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68D1A5AF615D3AE9ULL,
		0x7DC77DEC9978BB9DULL,
		0x5395CDAA7ECF2E3DULL,
		0xB222A466B822A17EULL,
		0xA3F2DD7B2DE54E28ULL,
		0xD3F31A9E76E0AA87ULL,
		0xBD7E453FF262948DULL,
		0x3D9D6B7006C637FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A34B5EC2BA75D2ULL,
		0xFB8EFBD932F1773AULL,
		0xA72B9B54FD9E5C7AULL,
		0x644548CD704542FCULL,
		0x47E5BAF65BCA9C51ULL,
		0xA7E6353CEDC1550FULL,
		0x7AFC8A7FE4C5291BULL,
		0x7B3AD6E00D8C6FFDULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x406E5ECA3448A865ULL,
		0xEC10BD6213DF5951ULL,
		0x456A0911DBC5362FULL,
		0xAB30F8399CF571A7ULL,
		0x80FAF1EB36939698ULL,
		0xDCE7AAF98059B212ULL,
		0x240D66EF37F5113FULL,
		0x31EA67FE82CA7582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DCBD94689150CAULL,
		0xD8217AC427BEB2A2ULL,
		0x8AD41223B78A6C5FULL,
		0x5661F07339EAE34EULL,
		0x01F5E3D66D272D31ULL,
		0xB9CF55F300B36425ULL,
		0x481ACDDE6FEA227FULL,
		0x63D4CFFD0594EB04ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8EFD7712A336BDEULL,
		0x8C7798CC6C62AD6FULL,
		0x1E05B5DE4DDD2DF9ULL,
		0x070C1F864D73E3AEULL,
		0xE1CB8B6682D93C64ULL,
		0x62D999414D1578AFULL,
		0xD38095830AF15621ULL,
		0x20879B94D2DBB537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71DFAEE25466D7BCULL,
		0x18EF3198D8C55ADFULL,
		0x3C0B6BBC9BBA5BF3ULL,
		0x0E183F0C9AE7C75CULL,
		0xC39716CD05B278C8ULL,
		0xC5B332829A2AF15FULL,
		0xA7012B0615E2AC42ULL,
		0x410F3729A5B76A6FULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47365E40FA6D8B10ULL,
		0x755CFF8754FECD1CULL,
		0xA6FB12E830CC5FFBULL,
		0x7C558E3732BCBB7FULL,
		0x84714427D272DDCEULL,
		0x1D2A33DC0A15D148ULL,
		0x1459F14A2B48F26DULL,
		0x3DDA771CB843D0C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E6CBC81F4DB1620ULL,
		0xEAB9FF0EA9FD9A38ULL,
		0x4DF625D06198BFF6ULL,
		0xF8AB1C6E657976FFULL,
		0x08E2884FA4E5BB9CULL,
		0x3A5467B8142BA291ULL,
		0x28B3E2945691E4DAULL,
		0x7BB4EE397087A190ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x250F20F82566EABCULL,
		0x02CB247B1F7FB144ULL,
		0x5AF5E483D5427B8DULL,
		0x324A705D748652EAULL,
		0xD4C973E318159E3FULL,
		0xAD71F6880946A94EULL,
		0x0D5E6262914CF8BAULL,
		0x162F36B731E3E480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1E41F04ACDD578ULL,
		0x059648F63EFF6288ULL,
		0xB5EBC907AA84F71AULL,
		0x6494E0BAE90CA5D4ULL,
		0xA992E7C6302B3C7EULL,
		0x5AE3ED10128D529DULL,
		0x1ABCC4C52299F175ULL,
		0x2C5E6D6E63C7C900ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D11DAFA252D61C7ULL,
		0x3AA3C23F96ECD15CULL,
		0xEBFB96BE547FB23BULL,
		0x1961095487D9D964ULL,
		0xD90EE0465EB39700ULL,
		0x0070337B6CD5C71DULL,
		0x58CE0A8041A6B647ULL,
		0x2D5F0988AAC419B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A23B5F44A5AC38EULL,
		0x7547847F2DD9A2B8ULL,
		0xD7F72D7CA8FF6476ULL,
		0x32C212A90FB3B2C9ULL,
		0xB21DC08CBD672E00ULL,
		0x00E066F6D9AB8E3BULL,
		0xB19C1500834D6C8EULL,
		0x5ABE131155883364ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C5D1E7C167BCF67ULL,
		0x91CBD9AB04A1D916ULL,
		0x911A0FAD298678A4ULL,
		0xEE38B35661DCF2A5ULL,
		0x35E0177B9A06CF26ULL,
		0xCA66C0E5E1DA3B0AULL,
		0x87545BF825D7D4EFULL,
		0x31CC2BACA31E7488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78BA3CF82CF79ECEULL,
		0x2397B3560943B22CULL,
		0x22341F5A530CF149ULL,
		0xDC7166ACC3B9E54BULL,
		0x6BC02EF7340D9E4DULL,
		0x94CD81CBC3B47614ULL,
		0x0EA8B7F04BAFA9DFULL,
		0x63985759463CE911ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D661F787A2E02CBULL,
		0x535410AA09C57068ULL,
		0x8B24FB37225C56F6ULL,
		0xFA3B49D101DF929DULL,
		0xBB1C6D9670F12AA7ULL,
		0xE2EED89EA668FA6DULL,
		0x8854097DB8101381ULL,
		0x390501309D8E150FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ACC3EF0F45C0596ULL,
		0xA6A82154138AE0D1ULL,
		0x1649F66E44B8ADECULL,
		0xF47693A203BF253BULL,
		0x7638DB2CE1E2554FULL,
		0xC5DDB13D4CD1F4DBULL,
		0x10A812FB70202703ULL,
		0x720A02613B1C2A1FULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x982852779385AE38ULL,
		0x0570693A30900A31ULL,
		0xE9885BC9EE04838BULL,
		0x7839AFF8455C8E15ULL,
		0x3140105F0D812F0BULL,
		0xFEC2081916D1EADEULL,
		0x9DC07DF9274A8436ULL,
		0x12506E604C46C951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3050A4EF270B5C70ULL,
		0x0AE0D27461201463ULL,
		0xD310B793DC090716ULL,
		0xF0735FF08AB91C2BULL,
		0x628020BE1B025E16ULL,
		0xFD8410322DA3D5BCULL,
		0x3B80FBF24E95086DULL,
		0x24A0DCC0988D92A3ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D7D0695883187F7ULL,
		0x5F27C14B0414DC0CULL,
		0x046D0AAD1EDC4A9CULL,
		0x1BB0645B3E1318EDULL,
		0xAA630D0C7016B614ULL,
		0x0117C23F71BA5E2DULL,
		0xFC96A5F4E9B20022ULL,
		0x20CCF0A72EDDA320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAFA0D2B10630FEEULL,
		0xBE4F82960829B818ULL,
		0x08DA155A3DB89538ULL,
		0x3760C8B67C2631DAULL,
		0x54C61A18E02D6C28ULL,
		0x022F847EE374BC5BULL,
		0xF92D4BE9D3640044ULL,
		0x4199E14E5DBB4641ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3009E6FA4D240C39ULL,
		0x3ECE981DF31C62D2ULL,
		0x96D3341D87D32969ULL,
		0x6506439796360638ULL,
		0xAC73F4BC909D2F38ULL,
		0x6D011E45B36F4BA0ULL,
		0x568D98B714CF53DDULL,
		0x0256A4720E49D29BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6013CDF49A481872ULL,
		0x7D9D303BE638C5A4ULL,
		0x2DA6683B0FA652D2ULL,
		0xCA0C872F2C6C0C71ULL,
		0x58E7E979213A5E70ULL,
		0xDA023C8B66DE9741ULL,
		0xAD1B316E299EA7BAULL,
		0x04AD48E41C93A536ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x442017759D10F955ULL,
		0x481B80EFAFE0A3BEULL,
		0x4FE2B54AF3110494ULL,
		0xC3989165343C3D24ULL,
		0x52E2D8245B27FEF5ULL,
		0x9DBB8D4FD4D550C8ULL,
		0xE320C458A7395F87ULL,
		0x365BEB3B6AC1C911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88402EEB3A21F2AAULL,
		0x903701DF5FC1477CULL,
		0x9FC56A95E6220928ULL,
		0x873122CA68787A48ULL,
		0xA5C5B048B64FFDEBULL,
		0x3B771A9FA9AAA190ULL,
		0xC64188B14E72BF0FULL,
		0x6CB7D676D5839223ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80C74AF584CB2202ULL,
		0x8A5973880B178217ULL,
		0x818F521C51A338ECULL,
		0x20E381B997CF1937ULL,
		0x8B3991DB316B596FULL,
		0x40AF864552CF6586ULL,
		0x3FB942AC85626907ULL,
		0x3EA7346E6CC53297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018E95EB09964404ULL,
		0x14B2E710162F042FULL,
		0x031EA438A34671D9ULL,
		0x41C703732F9E326FULL,
		0x167323B662D6B2DEULL,
		0x815F0C8AA59ECB0DULL,
		0x7F7285590AC4D20EULL,
		0x7D4E68DCD98A652EULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC6B7CCBA1809331ULL,
		0xE8C46CB8875D82C4ULL,
		0x28A6D304273D8339ULL,
		0xB92CEFCCF45DCFC2ULL,
		0x18C47969A062327FULL,
		0xA2AEEA0DF8322DC9ULL,
		0x715C1D1783D2D34DULL,
		0x20ACDCD4847D6F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D6F99743012662ULL,
		0xD188D9710EBB0589ULL,
		0x514DA6084E7B0673ULL,
		0x7259DF99E8BB9F84ULL,
		0x3188F2D340C464FFULL,
		0x455DD41BF0645B92ULL,
		0xE2B83A2F07A5A69BULL,
		0x4159B9A908FADE00ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9647B234120CB536ULL,
		0xE1891A3703A1CF44ULL,
		0x328B3D32B9DB0702ULL,
		0x1035CDF6F5DA4FC9ULL,
		0xCD00C79D4F3FE2F5ULL,
		0x64B13F788BABC0D3ULL,
		0x64792FCCC1C29281ULL,
		0x07196D9083ECBB36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8F646824196A6CULL,
		0xC312346E07439E89ULL,
		0x65167A6573B60E05ULL,
		0x206B9BEDEBB49F92ULL,
		0x9A018F3A9E7FC5EAULL,
		0xC9627EF1175781A7ULL,
		0xC8F25F9983852502ULL,
		0x0E32DB2107D9766CULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE20CF14A15C268FULL,
		0xD6A8204B6FAB745DULL,
		0x5C271D07646C09F3ULL,
		0x24BF4F8587B25D2CULL,
		0x03867C14BCD31924ULL,
		0x178B91FE456D95E3ULL,
		0xE57B87DB758C4191ULL,
		0x137EE300441FD32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C419E2942B84D1EULL,
		0xAD504096DF56E8BBULL,
		0xB84E3A0EC8D813E7ULL,
		0x497E9F0B0F64BA58ULL,
		0x070CF82979A63248ULL,
		0x2F1723FC8ADB2BC6ULL,
		0xCAF70FB6EB188322ULL,
		0x26FDC600883FA65BULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF095BBC2B6E15BB1ULL,
		0xE0ACE9B8B2E9A769ULL,
		0xDA7A4269E6105639ULL,
		0x0CE898BFDDC54686ULL,
		0x3E71CD70A4A5FFC7ULL,
		0xF34AD472275380C8ULL,
		0x03F082E1370A24FAULL,
		0x035D6A7589CD3778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE12B77856DC2B762ULL,
		0xC159D37165D34ED3ULL,
		0xB4F484D3CC20AC73ULL,
		0x19D1317FBB8A8D0DULL,
		0x7CE39AE1494BFF8EULL,
		0xE695A8E44EA70190ULL,
		0x07E105C26E1449F5ULL,
		0x06BAD4EB139A6EF0ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE16F95CCE06DC036ULL,
		0xB796569D3BE87B45ULL,
		0x85FC0EE7B8246939ULL,
		0xF1ED4BF14921CB51ULL,
		0x6A54F1F82DFEC8EEULL,
		0x6F6DBE545A0DF7BBULL,
		0x76F77F8DD8157F1DULL,
		0x125D9108316488FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DF2B99C0DB806CULL,
		0x6F2CAD3A77D0F68BULL,
		0x0BF81DCF7048D273ULL,
		0xE3DA97E2924396A3ULL,
		0xD4A9E3F05BFD91DDULL,
		0xDEDB7CA8B41BEF76ULL,
		0xEDEEFF1BB02AFE3AULL,
		0x24BB221062C911F8ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DAB70ECC5D613F3ULL,
		0xA72C42D29D6C5D55ULL,
		0x7D25DC4993E47902ULL,
		0x3630F749B03C5DCBULL,
		0x9FC3ED008A4FCCD1ULL,
		0x44B9B13EF8E93E65ULL,
		0x6D9EB033D12D2093ULL,
		0x0FB37A457CD4EBF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB56E1D98BAC27E6ULL,
		0x4E5885A53AD8BAAAULL,
		0xFA4BB89327C8F205ULL,
		0x6C61EE936078BB96ULL,
		0x3F87DA01149F99A2ULL,
		0x8973627DF1D27CCBULL,
		0xDB3D6067A25A4126ULL,
		0x1F66F48AF9A9D7E2ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF45179509EDD3926ULL,
		0xC655E214AA4DB648ULL,
		0x80DE2D3793D5B214ULL,
		0x14FF5386BA84E577ULL,
		0x309D7678A546C7BEULL,
		0x74C96BB6839B4327ULL,
		0x67CE6FEDEA275FDBULL,
		0x027FC2DAF889D911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8A2F2A13DBA724CULL,
		0x8CABC429549B6C91ULL,
		0x01BC5A6F27AB6429ULL,
		0x29FEA70D7509CAEFULL,
		0x613AECF14A8D8F7CULL,
		0xE992D76D0736864EULL,
		0xCF9CDFDBD44EBFB6ULL,
		0x04FF85B5F113B222ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFBCE00FC99EF24BULL,
		0xF7C480437E49B9ABULL,
		0x973C6AD64CE245D1ULL,
		0x2FD561846F6FBF02ULL,
		0x25244E374536D7EFULL,
		0xD89F2C9CAFBB1719ULL,
		0xCBB6156034372462ULL,
		0x175ADA9A250F8818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF79C01F933DE496ULL,
		0xEF890086FC937357ULL,
		0x2E78D5AC99C48BA3ULL,
		0x5FAAC308DEDF7E05ULL,
		0x4A489C6E8A6DAFDEULL,
		0xB13E59395F762E32ULL,
		0x976C2AC0686E48C5ULL,
		0x2EB5B5344A1F1031ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE92EA5C6D4E78924ULL,
		0x8B9F3248AE0FA3FFULL,
		0xC67861C67730C904ULL,
		0xF815F3282E8A2F7EULL,
		0x5178B8B11C6A9031ULL,
		0x6112846DDECB1E5AULL,
		0xCEF8E70B21FB2010ULL,
		0x06EE132C5A7742A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD25D4B8DA9CF1248ULL,
		0x173E64915C1F47FFULL,
		0x8CF0C38CEE619209ULL,
		0xF02BE6505D145EFDULL,
		0xA2F1716238D52063ULL,
		0xC22508DBBD963CB4ULL,
		0x9DF1CE1643F64020ULL,
		0x0DDC2658B4EE8551ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31494453E8511C33ULL,
		0xB0FBDF2738A3E5F2ULL,
		0x6AB311517666383EULL,
		0x530E7BBEDC9FA65AULL,
		0x0E1EB37818F9D96EULL,
		0xD85F289B4CEE3B82ULL,
		0x42AD959F1A30D051ULL,
		0x10FC70F659F8FDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x629288A7D0A23866ULL,
		0x61F7BE4E7147CBE4ULL,
		0xD56622A2ECCC707DULL,
		0xA61CF77DB93F4CB4ULL,
		0x1C3D66F031F3B2DCULL,
		0xB0BE513699DC7704ULL,
		0x855B2B3E3461A0A3ULL,
		0x21F8E1ECB3F1FBD0ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13F7D72F55CFCAEEULL,
		0x7099417071A85CFFULL,
		0x7827CC5830D6A800ULL,
		0x2A8F9257FF7B92DAULL,
		0x5786FA76F0022FC9ULL,
		0xEAD466C0AC48D372ULL,
		0x7216E1B3732BB885ULL,
		0x2160EA7CB97CC6BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27EFAE5EAB9F95DCULL,
		0xE13282E0E350B9FEULL,
		0xF04F98B061AD5000ULL,
		0x551F24AFFEF725B4ULL,
		0xAF0DF4EDE0045F92ULL,
		0xD5A8CD815891A6E4ULL,
		0xE42DC366E657710BULL,
		0x42C1D4F972F98D76ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10086DFE4A231709ULL,
		0x42B54252D71D8636ULL,
		0x3F76578153C0B060ULL,
		0x82C281D2C847B679ULL,
		0x471213C8491846E7ULL,
		0x6A0D99723B1F21DFULL,
		0x558B6B213E9D3871ULL,
		0x1D32C1481CB8567EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2010DBFC94462E12ULL,
		0x856A84A5AE3B0C6CULL,
		0x7EECAF02A78160C0ULL,
		0x058503A5908F6CF2ULL,
		0x8E24279092308DCFULL,
		0xD41B32E4763E43BEULL,
		0xAB16D6427D3A70E2ULL,
		0x3A6582903970ACFCULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF13811BD2E00194EULL,
		0x9DF0D832AAA34C39ULL,
		0x71F775ABFE9BD0EAULL,
		0x5C3D2A6127EB15D0ULL,
		0xD6295684FBEC1CF1ULL,
		0x2F30D2E9DF8CD2D5ULL,
		0xAF133A66C35D6865ULL,
		0x1F2F30BACFAC583FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE270237A5C00329CULL,
		0x3BE1B06555469873ULL,
		0xE3EEEB57FD37A1D5ULL,
		0xB87A54C24FD62BA0ULL,
		0xAC52AD09F7D839E2ULL,
		0x5E61A5D3BF19A5ABULL,
		0x5E2674CD86BAD0CAULL,
		0x3E5E61759F58B07FULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDABFC94BB117844ULL,
		0x6842F4993DDD54DCULL,
		0x01C7236981AF1EA5ULL,
		0x72E214A42F28B240ULL,
		0x6B6CB8B9A37F7F0CULL,
		0x5AF5253DAA1D1D14ULL,
		0x2D120A99CB5E1F0BULL,
		0x22DF33A4FC896D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B57F9297622F088ULL,
		0xD085E9327BBAA9B9ULL,
		0x038E46D3035E3D4AULL,
		0xE5C429485E516480ULL,
		0xD6D9717346FEFE18ULL,
		0xB5EA4A7B543A3A28ULL,
		0x5A24153396BC3E16ULL,
		0x45BE6749F912DA50ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71D4F60A729AE784ULL,
		0x3FDE35F1BED42FCBULL,
		0x169084004E3934D9ULL,
		0x306BB897E8E64140ULL,
		0xA1CF5ECFFB343B6DULL,
		0xC741D323EC45A460ULL,
		0x87F8871FD3CD84C5ULL,
		0x0C26C1982BB10F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3A9EC14E535CF08ULL,
		0x7FBC6BE37DA85F96ULL,
		0x2D2108009C7269B2ULL,
		0x60D7712FD1CC8280ULL,
		0x439EBD9FF66876DAULL,
		0x8E83A647D88B48C1ULL,
		0x0FF10E3FA79B098BULL,
		0x184D833057621E3BULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7ACC0EF8DBD4D4FULL,
		0x2CEB406BBBB7BDF6ULL,
		0xBA72CA349F387746ULL,
		0x94893E3A4455EF74ULL,
		0xDE9AC2ED308BBAECULL,
		0xC81942619C810E9DULL,
		0xA0E423AD0212928BULL,
		0x1292D154016650F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF5981DF1B7A9A9EULL,
		0x59D680D7776F7BEDULL,
		0x74E594693E70EE8CULL,
		0x29127C7488ABDEE9ULL,
		0xBD3585DA611775D9ULL,
		0x903284C339021D3BULL,
		0x41C8475A04252517ULL,
		0x2525A2A802CCA1E5ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F39970AE07B0D4DULL,
		0x22403E569BC4144BULL,
		0xD71B1D47AC6BC254ULL,
		0x66346D63B8F9FE74ULL,
		0xDD444F828FC9D77FULL,
		0xCA060F81777E553AULL,
		0x1C1A2342EDC2A7BFULL,
		0x0C1C58C7AEEC6EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E732E15C0F61A9AULL,
		0x44807CAD37882896ULL,
		0xAE363A8F58D784A8ULL,
		0xCC68DAC771F3FCE9ULL,
		0xBA889F051F93AEFEULL,
		0x940C1F02EEFCAA75ULL,
		0x38344685DB854F7FULL,
		0x1838B18F5DD8DD4AULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DB38A32B29267F2ULL,
		0x2A4AAC029E6F93A6ULL,
		0xA8AC42575D00B740ULL,
		0x429EE22DA60FCB9DULL,
		0x351867DEBCFCFFBBULL,
		0x8856FC427C13C718ULL,
		0x064E593CE3BCD07DULL,
		0x2D8CA69986C2D49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB6714656524CFE4ULL,
		0x549558053CDF274CULL,
		0x515884AEBA016E80ULL,
		0x853DC45B4C1F973BULL,
		0x6A30CFBD79F9FF76ULL,
		0x10ADF884F8278E30ULL,
		0x0C9CB279C779A0FBULL,
		0x5B194D330D85A93EULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E116F279F48FE62ULL,
		0x595AE4FCF7411D1BULL,
		0x224DEE66EAD9FA4DULL,
		0x731E96C61FC7B198ULL,
		0x7E5B19E09D3120E2ULL,
		0x17A92D95308324BFULL,
		0x6784BB2513B2F856ULL,
		0x0F19CACA6B23EA44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C22DE4F3E91FCC4ULL,
		0xB2B5C9F9EE823A36ULL,
		0x449BDCCDD5B3F49AULL,
		0xE63D2D8C3F8F6330ULL,
		0xFCB633C13A6241C4ULL,
		0x2F525B2A6106497EULL,
		0xCF09764A2765F0ACULL,
		0x1E339594D647D488ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CBFCC4955A34A7EULL,
		0x36BB5D7CFEB6B448ULL,
		0x80BE7D0992BC883CULL,
		0x456D952328B4ACD0ULL,
		0x959A7153A9580913ULL,
		0x32F94BF87615D8ABULL,
		0xE628ED9F14FDF561ULL,
		0x30929E487C380D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997F9892AB4694FCULL,
		0x6D76BAF9FD6D6890ULL,
		0x017CFA1325791078ULL,
		0x8ADB2A46516959A1ULL,
		0x2B34E2A752B01226ULL,
		0x65F297F0EC2BB157ULL,
		0xCC51DB3E29FBEAC2ULL,
		0x61253C90F8701A75ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34B2324D397D54FAULL,
		0xF7BAD7DAF2F1A88CULL,
		0x850011F41AE71AE3ULL,
		0x2564A5CA6FF23907ULL,
		0x54D3959937BC0DC8ULL,
		0x26DD50B5573575C5ULL,
		0x97CB62DE692C8BA9ULL,
		0x3FFD16F6B2A142B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6964649A72FAA9F4ULL,
		0xEF75AFB5E5E35118ULL,
		0x0A0023E835CE35C7ULL,
		0x4AC94B94DFE4720FULL,
		0xA9A72B326F781B90ULL,
		0x4DBAA16AAE6AEB8AULL,
		0x2F96C5BCD2591752ULL,
		0x7FFA2DED65428563ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F4C3EF5C3D9590FULL,
		0xCD11B10E488AD2E9ULL,
		0x8C03829FCC929F9FULL,
		0x9FAB387D14A26E45ULL,
		0x969BBF9AB6346D86ULL,
		0x78DD1D41A600E2AAULL,
		0x4E15FBA7ED90B801ULL,
		0x29EF524981B57289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE987DEB87B2B21EULL,
		0x9A23621C9115A5D2ULL,
		0x1807053F99253F3FULL,
		0x3F5670FA2944DC8BULL,
		0x2D377F356C68DB0DULL,
		0xF1BA3A834C01C555ULL,
		0x9C2BF74FDB217002ULL,
		0x53DEA493036AE512ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91FEFF15D125CBAFULL,
		0x826D680C86BC1AF7ULL,
		0x48982A405395BB35ULL,
		0xEDCD69BB5A2DD3A6ULL,
		0xC54706A57B7BC03CULL,
		0x3015EEAB9C437391ULL,
		0xE5EC409F8C41876DULL,
		0x2A371D4BF7B26817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23FDFE2BA24B975EULL,
		0x04DAD0190D7835EFULL,
		0x91305480A72B766BULL,
		0xDB9AD376B45BA74CULL,
		0x8A8E0D4AF6F78079ULL,
		0x602BDD573886E723ULL,
		0xCBD8813F18830EDAULL,
		0x546E3A97EF64D02FULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0701B3DEB6F6D660ULL,
		0x82E920F82F890585ULL,
		0xD84CE45128F648ECULL,
		0x90315D9844D89387ULL,
		0x2EC471A53330E02EULL,
		0x389243DC7F7F344FULL,
		0x77E8D491239187B8ULL,
		0x0F961DA90964CCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0367BD6DEDACC0ULL,
		0x05D241F05F120B0AULL,
		0xB099C8A251EC91D9ULL,
		0x2062BB3089B1270FULL,
		0x5D88E34A6661C05DULL,
		0x712487B8FEFE689EULL,
		0xEFD1A92247230F70ULL,
		0x1F2C3B5212C999BAULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14EADD3BE5E6185CULL,
		0x03A814FAF515D2A6ULL,
		0x44EABFCB8D402FB6ULL,
		0xA5B332AF0CDDF3EAULL,
		0xCB1FBF5BFA580741ULL,
		0x2A8371EAE97B84E5ULL,
		0xAB55EFEAB1698BDDULL,
		0x024BD5E85E987A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D5BA77CBCC30B8ULL,
		0x075029F5EA2BA54CULL,
		0x89D57F971A805F6CULL,
		0x4B66655E19BBE7D4ULL,
		0x963F7EB7F4B00E83ULL,
		0x5506E3D5D2F709CBULL,
		0x56ABDFD562D317BAULL,
		0x0497ABD0BD30F4D1ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA5CFF7201971312ULL,
		0xBE974EC5FD2F1FAEULL,
		0xF45C1141C8DA3524ULL,
		0x92E0A83DB823290FULL,
		0x47BBA6AC2AF18501ULL,
		0x9F3EC6610D5CF36AULL,
		0x1E52A3EFFF83E2D3ULL,
		0x3013AEC63B0DDBC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B9FEE4032E2624ULL,
		0x7D2E9D8BFA5E3F5DULL,
		0xE8B8228391B46A49ULL,
		0x25C1507B7046521FULL,
		0x8F774D5855E30A03ULL,
		0x3E7D8CC21AB9E6D4ULL,
		0x3CA547DFFF07C5A7ULL,
		0x60275D8C761BB792ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB946612089ADC725ULL,
		0xB99EC5EEEA0A43D4ULL,
		0xA1CA8191E3918870ULL,
		0x4765287D1E3A8537ULL,
		0xA3E6028CA440AE8CULL,
		0xE7F5BFF4A6069B5EULL,
		0xCA3EFD5E08044C3FULL,
		0x2BC11702F2F8ED7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728CC241135B8E4AULL,
		0x733D8BDDD41487A9ULL,
		0x43950323C72310E1ULL,
		0x8ECA50FA3C750A6FULL,
		0x47CC051948815D18ULL,
		0xCFEB7FE94C0D36BDULL,
		0x947DFABC1008987FULL,
		0x57822E05E5F1DAFBULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E376A43D39A166CULL,
		0x988EC54C40DD9742ULL,
		0xE7CBED94895B0404ULL,
		0x82D64BAC37C79742ULL,
		0x45BAB5AFC1B0FB97ULL,
		0x48682E61CC9C5092ULL,
		0xB573A91E18496A86ULL,
		0x2B26F8B4CE980667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6ED487A7342CD8ULL,
		0x311D8A9881BB2E84ULL,
		0xCF97DB2912B60809ULL,
		0x05AC97586F8F2E85ULL,
		0x8B756B5F8361F72FULL,
		0x90D05CC39938A124ULL,
		0x6AE7523C3092D50CULL,
		0x564DF1699D300CCFULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C4533E0D49798DDULL,
		0xE398A84A29C16F94ULL,
		0x0EA1C72FC434E2D4ULL,
		0xBEBC6758F44B3976ULL,
		0xAD0E9D4FA24FE0F4ULL,
		0xD1EE4B9CD5DDC988ULL,
		0x5D37DDF5D0E0BFBCULL,
		0x1E09385C8AA1D2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388A67C1A92F31BAULL,
		0xC73150945382DF28ULL,
		0x1D438E5F8869C5A9ULL,
		0x7D78CEB1E89672ECULL,
		0x5A1D3A9F449FC1E9ULL,
		0xA3DC9739ABBB9311ULL,
		0xBA6FBBEBA1C17F79ULL,
		0x3C1270B91543A560ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DB38B057B470BFFULL,
		0xA9F31DB85F3158E2ULL,
		0x2F626262771E20E8ULL,
		0xD1F744DCD9362844ULL,
		0x2F464D1655062FB4ULL,
		0x7D78D80FBE76DE07ULL,
		0x2EB93C36691CD56BULL,
		0x2769D227F46A2021ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB67160AF68E17FEULL,
		0x53E63B70BE62B1C4ULL,
		0x5EC4C4C4EE3C41D1ULL,
		0xA3EE89B9B26C5088ULL,
		0x5E8C9A2CAA0C5F69ULL,
		0xFAF1B01F7CEDBC0EULL,
		0x5D72786CD239AAD6ULL,
		0x4ED3A44FE8D44042ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E8A45CDB7122B04ULL,
		0x5465126476111D28ULL,
		0x32EA9C6CF2A981B8ULL,
		0x1D98FBFC2B9E1386ULL,
		0x3D3A3A029BDC6C17ULL,
		0x187D84A6F71C078AULL,
		0x059654B5F06E1912ULL,
		0x0C1DC1652C166CFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD148B9B6E245608ULL,
		0xA8CA24C8EC223A50ULL,
		0x65D538D9E5530370ULL,
		0x3B31F7F8573C270CULL,
		0x7A74740537B8D82EULL,
		0x30FB094DEE380F14ULL,
		0x0B2CA96BE0DC3224ULL,
		0x183B82CA582CD9F8ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x885CD1F39ED58AAEULL,
		0xDF9B336B94687CDBULL,
		0xBC5296A98BE47587ULL,
		0x5F578BCA12F164AAULL,
		0x1557015FAB1DDDB0ULL,
		0x12C68EA2B2F7BE44ULL,
		0x962184D519916E65ULL,
		0x2C87CF4A2DAF8D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10B9A3E73DAB155CULL,
		0xBF3666D728D0F9B7ULL,
		0x78A52D5317C8EB0FULL,
		0xBEAF179425E2C955ULL,
		0x2AAE02BF563BBB60ULL,
		0x258D1D4565EF7C88ULL,
		0x2C4309AA3322DCCAULL,
		0x590F9E945B5F1A07ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE87AFBE72630A156ULL,
		0x8832D39ECC492E55ULL,
		0x2976BE367CE1E7E7ULL,
		0xF7961544F258BE50ULL,
		0xEA30051291703A21ULL,
		0x0483598A6A0F21F5ULL,
		0x38CF394BCA65F5F0ULL,
		0x172E083F64C1F639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0F5F7CE4C6142ACULL,
		0x1065A73D98925CABULL,
		0x52ED7C6CF9C3CFCFULL,
		0xEF2C2A89E4B17CA0ULL,
		0xD4600A2522E07443ULL,
		0x0906B314D41E43EBULL,
		0x719E729794CBEBE0ULL,
		0x2E5C107EC983EC72ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67CD74334B3A5113ULL,
		0xB010B12BCD9028A9ULL,
		0x74816730266AC783ULL,
		0xD937D01A82F46B49ULL,
		0xB94269DFDEABEA2DULL,
		0x34E4A4B7B9B3F346ULL,
		0x7A53DB8CA6BA302FULL,
		0x0E2BBE8476803585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9AE8669674A226ULL,
		0x602162579B205152ULL,
		0xE902CE604CD58F07ULL,
		0xB26FA03505E8D692ULL,
		0x7284D3BFBD57D45BULL,
		0x69C9496F7367E68DULL,
		0xF4A7B7194D74605EULL,
		0x1C577D08ED006B0AULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98F2C70B01A6064BULL,
		0x7F8ACC8B47A975EAULL,
		0x683D911E69065D35ULL,
		0xDA7D8430C16CAA5DULL,
		0x02E08D767164D663ULL,
		0xB71DC75B4D323902ULL,
		0xBFAC32C30801AFA9ULL,
		0x371C0A30657BC1F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E58E16034C0C96ULL,
		0xFF1599168F52EBD5ULL,
		0xD07B223CD20CBA6AULL,
		0xB4FB086182D954BAULL,
		0x05C11AECE2C9ACC7ULL,
		0x6E3B8EB69A647204ULL,
		0x7F58658610035F53ULL,
		0x6E381460CAF783E9ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0389603F3E9061A4ULL,
		0x1762F73DED3041E3ULL,
		0x0484E75771920450ULL,
		0x3A2FD3788CB49DFCULL,
		0x0828ADCFF7876AB4ULL,
		0x7AB9874B07DCE3DDULL,
		0xBD2935EB8EC135EDULL,
		0x37E6CC9CD137279BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0712C07E7D20C348ULL,
		0x2EC5EE7BDA6083C6ULL,
		0x0909CEAEE32408A0ULL,
		0x745FA6F119693BF8ULL,
		0x10515B9FEF0ED568ULL,
		0xF5730E960FB9C7BAULL,
		0x7A526BD71D826BDAULL,
		0x6FCD9939A26E4F37ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A3C5221101F2559ULL,
		0x506B6AF29A03641DULL,
		0x74027AC241A0DEDFULL,
		0xBA8C613CB8097E7EULL,
		0xA15E2207D5B45F92ULL,
		0xEBF576E805CB6531ULL,
		0x7E4FC3D6F0B15D1BULL,
		0x05F9FAB35365DA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5478A442203E4AB2ULL,
		0xA0D6D5E53406C83AULL,
		0xE804F5848341BDBEULL,
		0x7518C2797012FCFCULL,
		0x42BC440FAB68BF25ULL,
		0xD7EAEDD00B96CA63ULL,
		0xFC9F87ADE162BA37ULL,
		0x0BF3F566A6CBB470ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD293F1270768ECEULL,
		0xF0E79A8513518AF8ULL,
		0x8150CBAFEC2CF6CCULL,
		0x264D6715196D1618ULL,
		0xE01080421D2D430EULL,
		0xCB3B800113568011ULL,
		0x40984F6F165A25CAULL,
		0x0A79E77DAE6553F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA527E24E0ED1D9CULL,
		0xE1CF350A26A315F1ULL,
		0x02A1975FD859ED99ULL,
		0x4C9ACE2A32DA2C31ULL,
		0xC02100843A5A861CULL,
		0x9677000226AD0023ULL,
		0x81309EDE2CB44B95ULL,
		0x14F3CEFB5CCAA7E6ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9ACD54FDDBFAF2FULL,
		0x50848246E6B678D8ULL,
		0x44D684FDBE77A62AULL,
		0x7170D760B653BD04ULL,
		0x8837070AD1D4F307ULL,
		0x0CB9FE5F0F0DCAB7ULL,
		0xCFF5A55C5106BAB5ULL,
		0x3025EF92542D8907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD359AA9FBB7F5E5EULL,
		0xA109048DCD6CF1B1ULL,
		0x89AD09FB7CEF4C54ULL,
		0xE2E1AEC16CA77A08ULL,
		0x106E0E15A3A9E60EULL,
		0x1973FCBE1E1B956FULL,
		0x9FEB4AB8A20D756AULL,
		0x604BDF24A85B120FULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA44AF1955F4BF00CULL,
		0x4C5EF89B51EABFDCULL,
		0xEA8B23249BACF2D8ULL,
		0x7FA7F94105584135ULL,
		0xFA9361015D2850B0ULL,
		0xEA1355ECF8E12F27ULL,
		0xF4BA9A95BE8A1D09ULL,
		0x22E23A928B1DC25FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4895E32ABE97E018ULL,
		0x98BDF136A3D57FB9ULL,
		0xD51646493759E5B0ULL,
		0xFF4FF2820AB0826BULL,
		0xF526C202BA50A160ULL,
		0xD426ABD9F1C25E4FULL,
		0xE975352B7D143A13ULL,
		0x45C47525163B84BFULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98D67DE9CE67C039ULL,
		0xA2CF0447CA08C8A8ULL,
		0x3785956160207EF8ULL,
		0xF8F23AB562459E6CULL,
		0xFAD4B419C657F758ULL,
		0xBAB231417730A242ULL,
		0x8EF38DC553A69175ULL,
		0x0BC2E8F66334C7A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31ACFBD39CCF8072ULL,
		0x459E088F94119151ULL,
		0x6F0B2AC2C040FDF1ULL,
		0xF1E4756AC48B3CD8ULL,
		0xF5A968338CAFEEB1ULL,
		0x75646282EE614485ULL,
		0x1DE71B8AA74D22EBULL,
		0x1785D1ECC6698F41ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x504DEA8264BC56F9ULL,
		0xAB94381BFA701BE5ULL,
		0xC4A6B83CDF701FDCULL,
		0x7521715B70A6A1DAULL,
		0x976D51341A28249FULL,
		0x7318C5C4CAB696BAULL,
		0x3E6B85BAFA844462ULL,
		0x020C7D772CF55070ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA09BD504C978ADF2ULL,
		0x57287037F4E037CAULL,
		0x894D7079BEE03FB9ULL,
		0xEA42E2B6E14D43B5ULL,
		0x2EDAA2683450493EULL,
		0xE6318B89956D2D75ULL,
		0x7CD70B75F50888C4ULL,
		0x0418FAEE59EAA0E0ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AA2AA40B67033EDULL,
		0xF5373F62FF99DA1AULL,
		0x4AC147269B12E0C7ULL,
		0x64B0CD4B44EF8D15ULL,
		0x514D91B94A900E55ULL,
		0x2DDB4EC4600CD9EDULL,
		0x616B0EE0BBCBFCB0ULL,
		0x245AABF0DE1E9DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754554816CE067DAULL,
		0xEA6E7EC5FF33B434ULL,
		0x95828E4D3625C18FULL,
		0xC9619A9689DF1A2AULL,
		0xA29B237295201CAAULL,
		0x5BB69D88C019B3DAULL,
		0xC2D61DC17797F960ULL,
		0x48B557E1BC3D3BCAULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90B77663C54F68E0ULL,
		0xD2414E26AAE66136ULL,
		0x4F8FD4012CEC39D7ULL,
		0x2AEAC754696DF6DAULL,
		0x0E04A11487FC91FAULL,
		0xB0852311B29F1A48ULL,
		0x1B5A6917A33E0659ULL,
		0x1181BB9BD746E4FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x216EECC78A9ED1C0ULL,
		0xA4829C4D55CCC26DULL,
		0x9F1FA80259D873AFULL,
		0x55D58EA8D2DBEDB4ULL,
		0x1C0942290FF923F4ULL,
		0x610A4623653E3490ULL,
		0x36B4D22F467C0CB3ULL,
		0x23037737AE8DC9FCULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x378F2C5FBB87CF3AULL,
		0xC59E459A333732F5ULL,
		0x75B981693520F6A7ULL,
		0x357457EEB2F192AAULL,
		0x8EBF8F219A12BA63ULL,
		0xD7E9143F37E82568ULL,
		0xDE7746B291C5C4DEULL,
		0x3F49A4529A127E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1E58BF770F9E74ULL,
		0x8B3C8B34666E65EAULL,
		0xEB7302D26A41ED4FULL,
		0x6AE8AFDD65E32554ULL,
		0x1D7F1E43342574C6ULL,
		0xAFD2287E6FD04AD1ULL,
		0xBCEE8D65238B89BDULL,
		0x7E9348A53424FCDFULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x367EB0CBC93801F5ULL,
		0x60A0B34A1AD273F4ULL,
		0xA7656073BAB19BC8ULL,
		0x4E9C2A6E3FC77929ULL,
		0x31848DD737533C86ULL,
		0x2DD21A2A7D1A191BULL,
		0x8A40FA7996F2CA70ULL,
		0x0A7BC2DBDC71890DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CFD6197927003EAULL,
		0xC141669435A4E7E8ULL,
		0x4ECAC0E775633790ULL,
		0x9D3854DC7F8EF253ULL,
		0x63091BAE6EA6790CULL,
		0x5BA43454FA343236ULL,
		0x1481F4F32DE594E0ULL,
		0x14F785B7B8E3121BULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09BF7B5B6C607CFCULL,
		0xE366767E5934E0F3ULL,
		0x85E52F5BD6EAB78FULL,
		0xE72D5F8CE54194F3ULL,
		0x0EFDD78B47B1DBB8ULL,
		0xE8B8C924B4A0515DULL,
		0x2EEB51E8B74240C8ULL,
		0x20CDB268F92F6170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x137EF6B6D8C0F9F8ULL,
		0xC6CCECFCB269C1E6ULL,
		0x0BCA5EB7ADD56F1FULL,
		0xCE5ABF19CA8329E7ULL,
		0x1DFBAF168F63B771ULL,
		0xD17192496940A2BAULL,
		0x5DD6A3D16E848191ULL,
		0x419B64D1F25EC2E0ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06FEE2C14744FD66ULL,
		0xC535FDBD8B9E94A3ULL,
		0x71F7F597717298F9ULL,
		0x5BA7FBA5FF312D35ULL,
		0x33B47EA4587623BAULL,
		0x9A9D7697A904AA42ULL,
		0xD7056FB1F4BCC8F3ULL,
		0x2230E058613FA1AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFDC5828E89FACCULL,
		0x8A6BFB7B173D2946ULL,
		0xE3EFEB2EE2E531F3ULL,
		0xB74FF74BFE625A6AULL,
		0x6768FD48B0EC4774ULL,
		0x353AED2F52095484ULL,
		0xAE0ADF63E97991E7ULL,
		0x4461C0B0C27F435FULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C178A4DDF62A3C9ULL,
		0xEBEBB2828F774A2AULL,
		0xFBC43A46AF9BC726ULL,
		0x8E4CDF4F618281F7ULL,
		0x6CBD9935FBFFF051ULL,
		0xB161984C8976EBFDULL,
		0x221EE7CBC4933370ULL,
		0x355E4C9E484B8D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182F149BBEC54792ULL,
		0xD7D765051EEE9455ULL,
		0xF788748D5F378E4DULL,
		0x1C99BE9EC30503EFULL,
		0xD97B326BF7FFE0A3ULL,
		0x62C3309912EDD7FAULL,
		0x443DCF97892666E1ULL,
		0x6ABC993C90971AAAULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD9ACAC68B9BA2A7ULL,
		0xBB463F8B61FC29C2ULL,
		0xE926D7641CA16FD4ULL,
		0xB2336D1C9EB22433ULL,
		0x99A2FC89BF072EF5ULL,
		0x737C7D243BDD1537ULL,
		0x75F6676CF14B75C5ULL,
		0x16DC3080EFA642C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB35958D1737454EULL,
		0x768C7F16C3F85385ULL,
		0xD24DAEC83942DFA9ULL,
		0x6466DA393D644867ULL,
		0x3345F9137E0E5DEBULL,
		0xE6F8FA4877BA2A6FULL,
		0xEBECCED9E296EB8AULL,
		0x2DB86101DF4C858AULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BBD8481170A569DULL,
		0x73E34BEEB4BC9C04ULL,
		0x5E175A65FC105E84ULL,
		0xE714D562DD7D94CFULL,
		0xB29F7A1E92024344ULL,
		0xC318611B708ECE04ULL,
		0x3183148B9E59A227ULL,
		0x0095E303FC910E30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977B09022E14AD3AULL,
		0xE7C697DD69793808ULL,
		0xBC2EB4CBF820BD08ULL,
		0xCE29AAC5BAFB299EULL,
		0x653EF43D24048689ULL,
		0x8630C236E11D9C09ULL,
		0x630629173CB3444FULL,
		0x012BC607F9221C60ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C885ACB0F2A40FFULL,
		0xC71FD0FB3B64CFCBULL,
		0xD26E3C220DA21712ULL,
		0xB10D2548032DB409ULL,
		0x8DDE0C2F95153EB9ULL,
		0x127A154B40FE7B6BULL,
		0x14AFC10539F68323ULL,
		0x3CDB50A3D92E9BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1910B5961E5481FEULL,
		0x8E3FA1F676C99F97ULL,
		0xA4DC78441B442E25ULL,
		0x621A4A90065B6813ULL,
		0x1BBC185F2A2A7D73ULL,
		0x24F42A9681FCF6D7ULL,
		0x295F820A73ED0646ULL,
		0x79B6A147B25D37CEULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3F1AD83888AE714ULL,
		0x0C9335834154F0DCULL,
		0x4D706E6CED54D4B4ULL,
		0xAEA3887FBF7AB8B7ULL,
		0xDC3978975E971E95ULL,
		0x2B537B01F33A0E32ULL,
		0x201968F7A11358EDULL,
		0x3B4B9D79CA3CA8D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E35B071115CE28ULL,
		0x19266B0682A9E1B9ULL,
		0x9AE0DCD9DAA9A968ULL,
		0x5D4710FF7EF5716EULL,
		0xB872F12EBD2E3D2BULL,
		0x56A6F603E6741C65ULL,
		0x4032D1EF4226B1DAULL,
		0x76973AF3947951B0ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED9D6F9D88EF292CULL,
		0x6295CC5947B38300ULL,
		0x7C80203327842DFDULL,
		0x2B99614C2375ED1EULL,
		0x37D32B2626C18668ULL,
		0xD73472E532C4D2E9ULL,
		0xD515FAE207F8C022ULL,
		0x26B65F91470A3F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3ADF3B11DE5258ULL,
		0xC52B98B28F670601ULL,
		0xF90040664F085BFAULL,
		0x5732C29846EBDA3CULL,
		0x6FA6564C4D830CD0ULL,
		0xAE68E5CA6589A5D2ULL,
		0xAA2BF5C40FF18045ULL,
		0x4D6CBF228E147E81ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48A58AB5625D84AEULL,
		0xFA44103CCAECFEB3ULL,
		0xD29FDCB41A670711ULL,
		0x13235D9630123C35ULL,
		0x6AB5908757B75241ULL,
		0xFA3845CDB4207D3BULL,
		0x59EC5C29F60602AEULL,
		0x1451DFE99DB8166AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x914B156AC4BB095CULL,
		0xF488207995D9FD66ULL,
		0xA53FB96834CE0E23ULL,
		0x2646BB2C6024786BULL,
		0xD56B210EAF6EA482ULL,
		0xF4708B9B6840FA76ULL,
		0xB3D8B853EC0C055DULL,
		0x28A3BFD33B702CD4ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0AAC29A007C5104ULL,
		0x1072EEEDF85ABCEEULL,
		0x51EB1CEFDEFD8867ULL,
		0xBB12288BE678FDDEULL,
		0xD3A2B429FA7A9F22ULL,
		0xA60A54304037F7D7ULL,
		0x830236911BE97137ULL,
		0x29A37D807CFDC435ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4155853400F8A208ULL,
		0x20E5DDDBF0B579DDULL,
		0xA3D639DFBDFB10CEULL,
		0x76245117CCF1FBBCULL,
		0xA7456853F4F53E45ULL,
		0x4C14A860806FEFAFULL,
		0x06046D2237D2E26FULL,
		0x5346FB00F9FB886BULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7FB3CC61570F5AULL,
		0x94D06B459588A5FAULL,
		0x306B1D6903745842ULL,
		0x146D8A5A662F9728ULL,
		0xD0CE945A586352C2ULL,
		0xF30070F852E34F7DULL,
		0x4A8CC01AC599911BULL,
		0x2EFD8A4BC30A7645ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEFF6798C2AE1EB4ULL,
		0x29A0D68B2B114BF4ULL,
		0x60D63AD206E8B085ULL,
		0x28DB14B4CC5F2E50ULL,
		0xA19D28B4B0C6A584ULL,
		0xE600E1F0A5C69EFBULL,
		0x951980358B332237ULL,
		0x5DFB14978614EC8AULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A41D91EB413832FULL,
		0x95E8553D620FC2CDULL,
		0x35B5A596AC134239ULL,
		0xEB923716ED7424ABULL,
		0xD15C9C1094F8A92EULL,
		0x44E3F3E027616DC9ULL,
		0xF6180766D640222EULL,
		0x20A9CC5F0DED479BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3483B23D6827065EULL,
		0x2BD0AA7AC41F859BULL,
		0x6B6B4B2D58268473ULL,
		0xD7246E2DDAE84956ULL,
		0xA2B9382129F1525DULL,
		0x89C7E7C04EC2DB93ULL,
		0xEC300ECDAC80445CULL,
		0x415398BE1BDA8F37ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA80932D6796912E1ULL,
		0x50087219E9288C05ULL,
		0x77686DDC3F949C03ULL,
		0x9395BFE8C79B4E6EULL,
		0x7F8A0AE315664B4DULL,
		0xE88E9E223CC672E8ULL,
		0x8DF10FF4D11902CBULL,
		0x16D2149BC13A7992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x501265ACF2D225C2ULL,
		0xA010E433D251180BULL,
		0xEED0DBB87F293806ULL,
		0x272B7FD18F369CDCULL,
		0xFF1415C62ACC969BULL,
		0xD11D3C44798CE5D0ULL,
		0x1BE21FE9A2320597ULL,
		0x2DA429378274F325ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BD9494CE1B42EB2ULL,
		0x5985BF77A3DB2BA4ULL,
		0x96508820505C4950ULL,
		0x1EA14E56B85CD7FCULL,
		0x884DE4CF301259F1ULL,
		0x8202F4EAB9A8FBA2ULL,
		0x3A4C9B82E56F8732ULL,
		0x004801CEDD613DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17B29299C3685D64ULL,
		0xB30B7EEF47B65748ULL,
		0x2CA11040A0B892A0ULL,
		0x3D429CAD70B9AFF9ULL,
		0x109BC99E6024B3E2ULL,
		0x0405E9D57351F745ULL,
		0x74993705CADF0E65ULL,
		0x0090039DBAC27BAAULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77ECD34FBA30783FULL,
		0xA870C22C020FD031ULL,
		0x61E6A2317473F127ULL,
		0xA72F7E7225CB5897ULL,
		0xFAAC6B54F4982653ULL,
		0x65D73E9ADE995893ULL,
		0xC7CC08BD0D12FEA8ULL,
		0x2EE6F16387998740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD9A69F7460F07EULL,
		0x50E18458041FA062ULL,
		0xC3CD4462E8E7E24FULL,
		0x4E5EFCE44B96B12EULL,
		0xF558D6A9E9304CA7ULL,
		0xCBAE7D35BD32B127ULL,
		0x8F98117A1A25FD50ULL,
		0x5DCDE2C70F330E81ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7E8EA24CDEE5C1CULL,
		0x5C90587BD67F7D7AULL,
		0xE836D2D61B6E355FULL,
		0x6D9A9D7BABF37F68ULL,
		0x593F7BFFB4E9222AULL,
		0x4B6BC8033373EC0EULL,
		0x7D29E97409FEE08DULL,
		0x179632B969ED21C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD1D4499BDCB838ULL,
		0xB920B0F7ACFEFAF5ULL,
		0xD06DA5AC36DC6ABEULL,
		0xDB353AF757E6FED1ULL,
		0xB27EF7FF69D24454ULL,
		0x96D7900666E7D81CULL,
		0xFA53D2E813FDC11AULL,
		0x2F2C6572D3DA438EULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBA829F99DE8A185ULL,
		0xAE3A5FFEAD60CDE2ULL,
		0x5180E5C657D61055ULL,
		0xF1499E634ADC4305ULL,
		0xC8148F13A0B11491ULL,
		0xBA8FA7EABAAB888AULL,
		0x2350527F01B44B4BULL,
		0x327E527EB99C1F63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775053F33BD1430AULL,
		0x5C74BFFD5AC19BC5ULL,
		0xA301CB8CAFAC20ABULL,
		0xE2933CC695B8860AULL,
		0x90291E2741622923ULL,
		0x751F4FD575571115ULL,
		0x46A0A4FE03689697ULL,
		0x64FCA4FD73383EC6ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E04EEBE53566290ULL,
		0x3CDF65CCD2A13D87ULL,
		0x4B181B1CBC699982ULL,
		0x46EA306DA8E2330AULL,
		0xA6C1F9B2B93660AEULL,
		0x736D5AA56B3F6333ULL,
		0xB2F2701B2C655EA7ULL,
		0x08309825591B8588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C09DD7CA6ACC520ULL,
		0x79BECB99A5427B0EULL,
		0x9630363978D33304ULL,
		0x8DD460DB51C46614ULL,
		0x4D83F365726CC15CULL,
		0xE6DAB54AD67EC667ULL,
		0x65E4E03658CABD4EULL,
		0x1061304AB2370B11ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8090D03AED56A5BFULL,
		0xBD34EE5273A32085ULL,
		0xB2E3AA9925D49CB0ULL,
		0x0967E947BF983FF2ULL,
		0x57FEE331D92AF08BULL,
		0x5A25F314BAD50E0CULL,
		0x59706E7E2C423354ULL,
		0x2B3F836AAA128BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0121A075DAAD4B7EULL,
		0x7A69DCA4E746410BULL,
		0x65C755324BA93961ULL,
		0x12CFD28F7F307FE5ULL,
		0xAFFDC663B255E116ULL,
		0xB44BE62975AA1C18ULL,
		0xB2E0DCFC588466A8ULL,
		0x567F06D5542517A8ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80D4AD43FF31A996ULL,
		0x98684D2C0F9D6FB3ULL,
		0x67F595F33DAF7AB3ULL,
		0x7C972D917209DD25ULL,
		0xC4EBC957E995CFEFULL,
		0x7AD7FA9FD2C7DEFEULL,
		0x7F4599EDFAC8F70BULL,
		0x2C57116167C06381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A95A87FE63532CULL,
		0x30D09A581F3ADF67ULL,
		0xCFEB2BE67B5EF567ULL,
		0xF92E5B22E413BA4AULL,
		0x89D792AFD32B9FDEULL,
		0xF5AFF53FA58FBDFDULL,
		0xFE8B33DBF591EE16ULL,
		0x58AE22C2CF80C702ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC67522CBD4573C5CULL,
		0x26749E4B715CBF3CULL,
		0x5879370E0072BB99ULL,
		0x5F4D1446DCE98518ULL,
		0x3201E773392D315BULL,
		0xF50B7271A4567D76ULL,
		0xE056404960F7504CULL,
		0x3EB3B939E8162723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEA4597A8AE78B8ULL,
		0x4CE93C96E2B97E79ULL,
		0xB0F26E1C00E57732ULL,
		0xBE9A288DB9D30A30ULL,
		0x6403CEE6725A62B6ULL,
		0xEA16E4E348ACFAECULL,
		0xC0AC8092C1EEA099ULL,
		0x7D677273D02C4E47ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8F56B9857802660ULL,
		0xC6E907017564E7EAULL,
		0x5F80CB772A9CBDDEULL,
		0x04D72D938D2B1B44ULL,
		0x18CC004FE6A65CBCULL,
		0x11357A1EB19D21FEULL,
		0xEEA819FE98C6C9BFULL,
		0x3D017AA0A6C798EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1EAD730AF004CC0ULL,
		0x8DD20E02EAC9CFD5ULL,
		0xBF0196EE55397BBDULL,
		0x09AE5B271A563688ULL,
		0x3198009FCD4CB978ULL,
		0x226AF43D633A43FCULL,
		0xDD5033FD318D937EULL,
		0x7A02F5414D8F31DBULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x245E1CCB5CE3FFA2ULL,
		0x7201F7EE6C99A936ULL,
		0xE5E5DA35D96523D1ULL,
		0xD8DCE2CCF1907790ULL,
		0x17E52985225A076FULL,
		0xAC95975685BB6FD8ULL,
		0x4454F632BC4A8FBDULL,
		0x22EA3EFB1044B5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48BC3996B9C7FF44ULL,
		0xE403EFDCD933526CULL,
		0xCBCBB46BB2CA47A2ULL,
		0xB1B9C599E320EF21ULL,
		0x2FCA530A44B40EDFULL,
		0x592B2EAD0B76DFB0ULL,
		0x88A9EC6578951F7BULL,
		0x45D47DF620896B50ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B1E5FDCFC6261BDULL,
		0xE8D9246D036895D1ULL,
		0xC307C6C9330A9B99ULL,
		0xF1A64B8890F89402ULL,
		0x98E5CE1FAEFF688CULL,
		0xF8D5ED4D0FBF1DF5ULL,
		0x728094C6065A0AF6ULL,
		0x245A8D245F93AED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x963CBFB9F8C4C37AULL,
		0xD1B248DA06D12BA2ULL,
		0x860F8D9266153733ULL,
		0xE34C971121F12805ULL,
		0x31CB9C3F5DFED119ULL,
		0xF1ABDA9A1F7E3BEBULL,
		0xE501298C0CB415EDULL,
		0x48B51A48BF275DA4ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FFBA454342D1BA8ULL,
		0x706FA8629AE17A1FULL,
		0x6C32FB564BD1AF79ULL,
		0x19080DEF141B75F1ULL,
		0x8B4FAC05D497739AULL,
		0x0DA1D3F2F16F079AULL,
		0x4C9C93D6427CC051ULL,
		0x1137F469E26940BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF748A8685A3750ULL,
		0xE0DF50C535C2F43EULL,
		0xD865F6AC97A35EF2ULL,
		0x32101BDE2836EBE2ULL,
		0x169F580BA92EE734ULL,
		0x1B43A7E5E2DE0F35ULL,
		0x993927AC84F980A2ULL,
		0x226FE8D3C4D28178ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66E275153FB234A0ULL,
		0x5A3C510BADBCE5BCULL,
		0x557ABFF39A02BBFBULL,
		0x00238E020E1EBA99ULL,
		0x86232B0CBCDAFD82ULL,
		0xDBE2211C2D31826BULL,
		0x47B437710720BB7AULL,
		0x07981922DCDB9AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC4EA2A7F646940ULL,
		0xB478A2175B79CB78ULL,
		0xAAF57FE7340577F6ULL,
		0x00471C041C3D7532ULL,
		0x0C46561979B5FB04ULL,
		0xB7C442385A6304D7ULL,
		0x8F686EE20E4176F5ULL,
		0x0F303245B9B7358EULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F91D6EB49433B19ULL,
		0x146D9FA5BEDC1934ULL,
		0x2EEA304635C079E5ULL,
		0x8F85CA4D15E170C1ULL,
		0x152F099F20A7CF61ULL,
		0x8D06F49CDA234D8BULL,
		0x0C9543AE5F807124ULL,
		0x2582862756A2323DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF23ADD692867632ULL,
		0x28DB3F4B7DB83268ULL,
		0x5DD4608C6B80F3CAULL,
		0x1F0B949A2BC2E182ULL,
		0x2A5E133E414F9EC3ULL,
		0x1A0DE939B4469B16ULL,
		0x192A875CBF00E249ULL,
		0x4B050C4EAD44647AULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCFEC4E3ED650A8AULL,
		0x2CAA634FA1B2A86CULL,
		0x130E4B125FF1FD8EULL,
		0x6D982FBCC4659DD1ULL,
		0x24912121C5EC7EE1ULL,
		0x748F030B48288BBAULL,
		0xA748ED860A065780ULL,
		0x176A92D2C45DBF52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FD89C7DACA1514ULL,
		0x5954C69F436550D9ULL,
		0x261C9624BFE3FB1CULL,
		0xDB305F7988CB3BA2ULL,
		0x492242438BD8FDC2ULL,
		0xE91E061690511774ULL,
		0x4E91DB0C140CAF00ULL,
		0x2ED525A588BB7EA5ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD1DDC143AB53E92ULL,
		0x7FE19D18609FAA2CULL,
		0x6ACC546024DBA939ULL,
		0xC8A2D5B0A726A689ULL,
		0x54CAE80BA86E43B8ULL,
		0x2AEDAFA01BE711BBULL,
		0x71605A4F4D8D16C5ULL,
		0x09740C6DC0302560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3BB828756A7D24ULL,
		0xFFC33A30C13F5459ULL,
		0xD598A8C049B75272ULL,
		0x9145AB614E4D4D12ULL,
		0xA995D01750DC8771ULL,
		0x55DB5F4037CE2376ULL,
		0xE2C0B49E9B1A2D8AULL,
		0x12E818DB80604AC0ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x092D00E395B119F5ULL,
		0x56FEC50A7B93A7B2ULL,
		0x1366F902079E5411ULL,
		0x0E54CDE75E36EF94ULL,
		0xEFD6EC80601FE1F4ULL,
		0x8A63259A20F8D820ULL,
		0x04D31ED6902C4390ULL,
		0x00A79AAD92A0B1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125A01C72B6233EAULL,
		0xADFD8A14F7274F64ULL,
		0x26CDF2040F3CA822ULL,
		0x1CA99BCEBC6DDF28ULL,
		0xDFADD900C03FC3E8ULL,
		0x14C64B3441F1B041ULL,
		0x09A63DAD20588721ULL,
		0x014F355B254163C4ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF26EC9310EB161BEULL,
		0x3B326A59AEBE0883ULL,
		0xBC8E71788B560CFBULL,
		0xBCD66CBE9DE81080ULL,
		0x4EEE316B587C7F53ULL,
		0xC486DDFB41157AD3ULL,
		0x2CCB09A75452F7E6ULL,
		0x17559546B662FB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4DD92621D62C37CULL,
		0x7664D4B35D7C1107ULL,
		0x791CE2F116AC19F6ULL,
		0x79ACD97D3BD02101ULL,
		0x9DDC62D6B0F8FEA7ULL,
		0x890DBBF6822AF5A6ULL,
		0x5996134EA8A5EFCDULL,
		0x2EAB2A8D6CC5F63CULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDDD8AC0D52A843AULL,
		0xA8AAD5745655C9A9ULL,
		0xC91CD72022F7D766ULL,
		0x87607D30E0507A71ULL,
		0x2BCC7F321C4528C1ULL,
		0x412234D1F5989E49ULL,
		0xFE9D5C143AACC8F0ULL,
		0x0C8377D498DD9EBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBB1581AA550874ULL,
		0x5155AAE8ACAB9353ULL,
		0x9239AE4045EFAECDULL,
		0x0EC0FA61C0A0F4E3ULL,
		0x5798FE64388A5183ULL,
		0x824469A3EB313C92ULL,
		0xFD3AB828755991E0ULL,
		0x1906EFA931BB3D7DULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6AA437EF1040D65ULL,
		0x4F7B1EA4C7F998D4ULL,
		0x79473ACD44260C54ULL,
		0x5AB3095DF6F0F2BEULL,
		0x32BDF1F41086B1DBULL,
		0xDD8FE037706BCDF9ULL,
		0xC9C013CC126FED48ULL,
		0x1DBE6D0A616C449BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5486FDE2081ACAULL,
		0x9EF63D498FF331A9ULL,
		0xF28E759A884C18A8ULL,
		0xB56612BBEDE1E57CULL,
		0x657BE3E8210D63B6ULL,
		0xBB1FC06EE0D79BF2ULL,
		0x9380279824DFDA91ULL,
		0x3B7CDA14C2D88937ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFFB3A72922BD10FULL,
		0xB192600F05B159C9ULL,
		0x0825652A0D0C6275ULL,
		0xBC8A7D951F2EBBB0ULL,
		0xB3CAD312E31B0DD7ULL,
		0x084C051EE7F288B7ULL,
		0x5A76EA24ADB3ED34ULL,
		0x293E6CBB65AC0D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF674E52457A21EULL,
		0x6324C01E0B62B393ULL,
		0x104ACA541A18C4EBULL,
		0x7914FB2A3E5D7760ULL,
		0x6795A625C6361BAFULL,
		0x10980A3DCFE5116FULL,
		0xB4EDD4495B67DA68ULL,
		0x527CD976CB581B18ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BEC0E768D7D5E6BULL,
		0x62E505F0007C887BULL,
		0xC156444EC299023AULL,
		0xFBEC647D83A225F7ULL,
		0x08D012947B214926ULL,
		0x3C8AC8DA6924E094ULL,
		0xE7B864227C9E39C4ULL,
		0x2693A234AB803F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7D81CED1AFABCD6ULL,
		0xC5CA0BE000F910F6ULL,
		0x82AC889D85320474ULL,
		0xF7D8C8FB07444BEFULL,
		0x11A02528F642924DULL,
		0x791591B4D249C128ULL,
		0xCF70C844F93C7388ULL,
		0x4D27446957007EE5ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A4865039000E361ULL,
		0x347EA8177813B9CFULL,
		0x84F81C1A3DF09192ULL,
		0xAA6D5A935647A590ULL,
		0xEBF3CECC9B76403FULL,
		0x0D244AB424DEEBC8ULL,
		0x60E78D582985ABC0ULL,
		0x13A5C70CFD4E400DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1490CA072001C6C2ULL,
		0x68FD502EF027739FULL,
		0x09F038347BE12324ULL,
		0x54DAB526AC8F4B21ULL,
		0xD7E79D9936EC807FULL,
		0x1A48956849BDD791ULL,
		0xC1CF1AB0530B5780ULL,
		0x274B8E19FA9C801AULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x464FC4C8B82AB4F9ULL,
		0xCCACFBC77CDD8D27ULL,
		0x8235649D10CE5FD7ULL,
		0xC7AA5D20A5200818ULL,
		0xBA3EE7CCBDE2983EULL,
		0x6B3A27FC9A0FECA9ULL,
		0x4EF15C5DE9F271A0ULL,
		0x21D7495550D25B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C9F8991705569F2ULL,
		0x9959F78EF9BB1A4EULL,
		0x046AC93A219CBFAFULL,
		0x8F54BA414A401031ULL,
		0x747DCF997BC5307DULL,
		0xD6744FF9341FD953ULL,
		0x9DE2B8BBD3E4E340ULL,
		0x43AE92AAA1A4B672ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38C6F9DD5FB9D85EULL,
		0xB83681D62DDAF54EULL,
		0x87776E5D70B1BEF4ULL,
		0xD95F23F6E41506C7ULL,
		0xF8ED6B87DB8B372DULL,
		0x86D34E5902E463B3ULL,
		0xF0D3C3D25B172FB4ULL,
		0x06E89625CEFC9787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x718DF3BABF73B0BCULL,
		0x706D03AC5BB5EA9CULL,
		0x0EEEDCBAE1637DE9ULL,
		0xB2BE47EDC82A0D8FULL,
		0xF1DAD70FB7166E5BULL,
		0x0DA69CB205C8C767ULL,
		0xE1A787A4B62E5F69ULL,
		0x0DD12C4B9DF92F0FULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AFD04601F18840AULL,
		0x8D5CB64638C7C680ULL,
		0x11A6D7A255BCABD9ULL,
		0xDA2B9267189C2BB3ULL,
		0x5D9484B57B3A0686ULL,
		0x55FA806ECCBBB0E5ULL,
		0xB8FE3BFF1675FF7FULL,
		0x109962A92C8B3EF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15FA08C03E310814ULL,
		0x1AB96C8C718F8D00ULL,
		0x234DAF44AB7957B3ULL,
		0xB45724CE31385766ULL,
		0xBB29096AF6740D0DULL,
		0xABF500DD997761CAULL,
		0x71FC77FE2CEBFEFEULL,
		0x2132C55259167DE7ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A21F538CA4B96B0ULL,
		0xC67A6688239FE6E4ULL,
		0x745E4DD5B252CFA8ULL,
		0x5872AE0404741133ULL,
		0x0341BAB469A68297ULL,
		0x09EDA2430D07B44EULL,
		0x246043629A80958DULL,
		0x2E377BC7D71DDA5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7443EA7194972D60ULL,
		0x8CF4CD10473FCDC8ULL,
		0xE8BC9BAB64A59F51ULL,
		0xB0E55C0808E82266ULL,
		0x06837568D34D052EULL,
		0x13DB44861A0F689CULL,
		0x48C086C535012B1AULL,
		0x5C6EF78FAE3BB4BAULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98BDC1FC18A9D9C0ULL,
		0x49ECA569B0FC9557ULL,
		0x1A68A5251E3793BEULL,
		0x4A85E06EB692C5F5ULL,
		0xFE84FF905BAFF13AULL,
		0xC6632C7757DF5843ULL,
		0x182ED9F81E2C6F2EULL,
		0x39234C6BC114B7F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317B83F83153B380ULL,
		0x93D94AD361F92AAFULL,
		0x34D14A4A3C6F277CULL,
		0x950BC0DD6D258BEAULL,
		0xFD09FF20B75FE274ULL,
		0x8CC658EEAFBEB087ULL,
		0x305DB3F03C58DE5DULL,
		0x724698D782296FF0ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5E6F7D755A3040EULL,
		0x3922F9FBB951CB74ULL,
		0x1E235BCABEE60EB7ULL,
		0xC95AC3BA021CF6C5ULL,
		0x8CC3566165349311ULL,
		0xA928F1FA979A1B7FULL,
		0x2F61F942B8B2F5C6ULL,
		0x3FF913F42E6AFFE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBCDEFAEAB46081CULL,
		0x7245F3F772A396E9ULL,
		0x3C46B7957DCC1D6EULL,
		0x92B587740439ED8AULL,
		0x1986ACC2CA692623ULL,
		0x5251E3F52F3436FFULL,
		0x5EC3F2857165EB8DULL,
		0x7FF227E85CD5FFC2ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2113616A207FA05ULL,
		0xB4C294718252F5D0ULL,
		0xDC23C10C5625E10CULL,
		0x9EDD4A22FEC3ACD1ULL,
		0xA8658DF05110FAEEULL,
		0xA13CA0E7F9F76091ULL,
		0x2B30BD5158282732ULL,
		0x00D6A31560D71749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4226C2D440FF40AULL,
		0x698528E304A5EBA1ULL,
		0xB8478218AC4BC219ULL,
		0x3DBA9445FD8759A3ULL,
		0x50CB1BE0A221F5DDULL,
		0x427941CFF3EEC123ULL,
		0x56617AA2B0504E65ULL,
		0x01AD462AC1AE2E92ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E89F3D29ADFB217ULL,
		0x3D06B651C2633319ULL,
		0x3C3103928C8CFF7BULL,
		0x94A9E77711B07E03ULL,
		0x8B0F4F40CE9D6960ULL,
		0xB3A88EC844EDA2E7ULL,
		0xB6BD203BD16AA2D3ULL,
		0x37EAF2780CC6C63FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D13E7A535BF642EULL,
		0x7A0D6CA384C66632ULL,
		0x786207251919FEF6ULL,
		0x2953CEEE2360FC06ULL,
		0x161E9E819D3AD2C1ULL,
		0x67511D9089DB45CFULL,
		0x6D7A4077A2D545A7ULL,
		0x6FD5E4F0198D8C7FULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92F140B6DE329993ULL,
		0x43AC64449FACF067ULL,
		0x00E71CBDDCFFCA89ULL,
		0x3EEBD16A44EE91EBULL,
		0x99007110CFE72E0EULL,
		0xFB6844B9A5D1E21CULL,
		0x94117044D048FD55ULL,
		0x29B8B914C5A08291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25E2816DBC653326ULL,
		0x8758C8893F59E0CFULL,
		0x01CE397BB9FF9512ULL,
		0x7DD7A2D489DD23D6ULL,
		0x3200E2219FCE5C1CULL,
		0xF6D089734BA3C439ULL,
		0x2822E089A091FAABULL,
		0x537172298B410523ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x744F6ED849DB76D5ULL,
		0x51928AA4C3FEE023ULL,
		0xB250C35C047BCA31ULL,
		0xD3A5F6E3493E693AULL,
		0xF2E78FEBFDA9ECC8ULL,
		0xC174AF99D8EB5231ULL,
		0x9AF1FD7879F4C784ULL,
		0x3C26F3DFB216064AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89EDDB093B6EDAAULL,
		0xA325154987FDC046ULL,
		0x64A186B808F79462ULL,
		0xA74BEDC6927CD275ULL,
		0xE5CF1FD7FB53D991ULL,
		0x82E95F33B1D6A463ULL,
		0x35E3FAF0F3E98F09ULL,
		0x784DE7BF642C0C95ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD802ABB6BAA00EAFULL,
		0x68CB3C1877DDCC11ULL,
		0x1D84D92375BC1CF2ULL,
		0x87CF5A0BB2D5FC9AULL,
		0xE2AC8C85A052AB61ULL,
		0x6E77BB89073975ABULL,
		0x8814C42784FBA73FULL,
		0x233A3F7FB71ABF22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB005576D75401D5EULL,
		0xD1967830EFBB9823ULL,
		0x3B09B246EB7839E4ULL,
		0x0F9EB41765ABF934ULL,
		0xC559190B40A556C3ULL,
		0xDCEF77120E72EB57ULL,
		0x1029884F09F74E7EULL,
		0x46747EFF6E357E45ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43202A0C788DD6D1ULL,
		0xBBA03BA984F096BEULL,
		0x2DB3B2D89A52F7D1ULL,
		0xBAE95013FA4B5E9FULL,
		0xE9E5579240826FDFULL,
		0xF5C37E3674D402E3ULL,
		0x452FF982976AEB93ULL,
		0x32F06E391450EAA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86405418F11BADA2ULL,
		0x7740775309E12D7CULL,
		0x5B6765B134A5EFA3ULL,
		0x75D2A027F496BD3EULL,
		0xD3CAAF248104DFBFULL,
		0xEB86FC6CE9A805C7ULL,
		0x8A5FF3052ED5D727ULL,
		0x65E0DC7228A1D546ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96154C1EC1A59588ULL,
		0x3B820D717D56EDBFULL,
		0xC3EF1FF646B6842AULL,
		0x10390B4CC82AC8EDULL,
		0x7FE248C3B007083AULL,
		0x797B765F010F089CULL,
		0x36285A527F52E555ULL,
		0x3FB93CC7B34199F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C2A983D834B2B10ULL,
		0x77041AE2FAADDB7FULL,
		0x87DE3FEC8D6D0854ULL,
		0x20721699905591DBULL,
		0xFFC49187600E1074ULL,
		0xF2F6ECBE021E1138ULL,
		0x6C50B4A4FEA5CAAAULL,
		0x7F72798F668333E2ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ACFA624BE6E55D7ULL,
		0x80CDCEDDE3B7589CULL,
		0x6559A4456EA9A842ULL,
		0x4A251A8A7EE5D818ULL,
		0x84856D8238275B59ULL,
		0x80107ED1796C9106ULL,
		0x47AAD1964EA98286ULL,
		0x1F5D904A01A4CBF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x159F4C497CDCABAEULL,
		0x019B9DBBC76EB138ULL,
		0xCAB3488ADD535085ULL,
		0x944A3514FDCBB030ULL,
		0x090ADB04704EB6B2ULL,
		0x0020FDA2F2D9220DULL,
		0x8F55A32C9D53050DULL,
		0x3EBB2094034997E8ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB2D6C7B691BC429ULL,
		0x96A46684C022367CULL,
		0x9A871383F74CF57CULL,
		0xCB942B09409BA2B3ULL,
		0xB894993D8677D527ULL,
		0x71B7CD74325FA531ULL,
		0x41D9402C5200F8B3ULL,
		0x04C831626D4B0EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65AD8F6D2378852ULL,
		0x2D48CD0980446CF9ULL,
		0x350E2707EE99EAF9ULL,
		0x9728561281374567ULL,
		0x7129327B0CEFAA4FULL,
		0xE36F9AE864BF4A63ULL,
		0x83B28058A401F166ULL,
		0x099062C4DA961D86ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFA0C74B85CAD7F9ULL,
		0xC3B51A67CC8AF524ULL,
		0xE2B51951B1B4374BULL,
		0xBC9DAFF592CF27AEULL,
		0xCFC0669EE6B5C9A4ULL,
		0xAE26B0405C3FA5A7ULL,
		0x4ED6215188B8149FULL,
		0x1CEA0ECDC2D5A50FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF418E970B95AFF2ULL,
		0x876A34CF9915EA49ULL,
		0xC56A32A363686E97ULL,
		0x793B5FEB259E4F5DULL,
		0x9F80CD3DCD6B9349ULL,
		0x5C4D6080B87F4B4FULL,
		0x9DAC42A31170293FULL,
		0x39D41D9B85AB4A1EULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1942A208F9C6DD83ULL,
		0xA1E2219E639802D9ULL,
		0x17BBE96A1655EDD9ULL,
		0xE300F1CCAA6366F6ULL,
		0x53DFF6CE4D8516C4ULL,
		0xE4A8135F46DAC7EEULL,
		0x26200E45378EB0FBULL,
		0x0346778FBD66E5F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32854411F38DBB06ULL,
		0x43C4433CC73005B2ULL,
		0x2F77D2D42CABDBB3ULL,
		0xC601E39954C6CDECULL,
		0xA7BFED9C9B0A2D89ULL,
		0xC95026BE8DB58FDCULL,
		0x4C401C8A6F1D61F7ULL,
		0x068CEF1F7ACDCBE2ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D710F4EF90B137ULL,
		0x0603AA365F6BF5FEULL,
		0xF554F7AD9D7091C8ULL,
		0x65098A843551BDDEULL,
		0xD437FFF9A1750FA0ULL,
		0x8BA4BDE176EFBADDULL,
		0x6C05839451ECE338ULL,
		0x298AC06720CA257FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5AE21E9DF21626EULL,
		0x0C07546CBED7EBFDULL,
		0xEAA9EF5B3AE12390ULL,
		0xCA1315086AA37BBDULL,
		0xA86FFFF342EA1F40ULL,
		0x17497BC2EDDF75BBULL,
		0xD80B0728A3D9C671ULL,
		0x531580CE41944AFEULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20915A8C4AD94CA3ULL,
		0xBCA78801ACD2B872ULL,
		0xD1A842C8D1EF664CULL,
		0xF14D6BE8440B1517ULL,
		0xBDE703C118597F71ULL,
		0xCC94990D71AE1788ULL,
		0x70817403D96500F7ULL,
		0x3842B6C4C4391ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4122B51895B29946ULL,
		0x794F100359A570E4ULL,
		0xA3508591A3DECC99ULL,
		0xE29AD7D088162A2FULL,
		0x7BCE078230B2FEE3ULL,
		0x9929321AE35C2F11ULL,
		0xE102E807B2CA01EFULL,
		0x70856D8988723DB0ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE8DADADF315A3FULL,
		0xD9F84DC823042675ULL,
		0x295BAB2F9FF82D4AULL,
		0x0A0E65DA5FBA1D05ULL,
		0xD3E119AAA8D9B836ULL,
		0x6D2A284CBBA76BE1ULL,
		0x26556E8E4D114380ULL,
		0x35A6390BCA28E030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D1B5B5BE62B47EULL,
		0xB3F09B9046084CEAULL,
		0x52B7565F3FF05A95ULL,
		0x141CCBB4BF743A0AULL,
		0xA7C2335551B3706CULL,
		0xDA545099774ED7C3ULL,
		0x4CAADD1C9A228700ULL,
		0x6B4C72179451C060ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x216911767E912728ULL,
		0x372F20037675C408ULL,
		0x65ED8C263FEB7105ULL,
		0xBADB30CBC9CD1B50ULL,
		0x2EF35923F3A4F725ULL,
		0x314725A497A92389ULL,
		0x123C374DA0E7A843ULL,
		0x2771AD3DEAEE8F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D222ECFD224E50ULL,
		0x6E5E4006ECEB8810ULL,
		0xCBDB184C7FD6E20AULL,
		0x75B66197939A36A0ULL,
		0x5DE6B247E749EE4BULL,
		0x628E4B492F524712ULL,
		0x24786E9B41CF5086ULL,
		0x4EE35A7BD5DD1E02ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D9DAF6DB205E693ULL,
		0x19AB5C21553A49C8ULL,
		0xDBA23863C1482B72ULL,
		0xEE8194D8124A0D8DULL,
		0x3E613CA2070747B8ULL,
		0xCB37652853A6613AULL,
		0x3740BAA4AEE572ABULL,
		0x29E598302C2A9FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B3B5EDB640BCD26ULL,
		0x3356B842AA749390ULL,
		0xB74470C7829056E4ULL,
		0xDD0329B024941B1BULL,
		0x7CC279440E0E8F71ULL,
		0x966ECA50A74CC274ULL,
		0x6E8175495DCAE557ULL,
		0x53CB306058553FC6ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2188BB0F8AB03403ULL,
		0x1CDEB28D3CC08923ULL,
		0x86F15F233068AF97ULL,
		0xF8E28C82DCCD228FULL,
		0x56F984C0DEA63B12ULL,
		0x409D254C77E7ECF5ULL,
		0xEFA824B3C8187E01ULL,
		0x3E5BB5AC2D3FE40CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4311761F15606806ULL,
		0x39BD651A79811246ULL,
		0x0DE2BE4660D15F2EULL,
		0xF1C51905B99A451FULL,
		0xADF30981BD4C7625ULL,
		0x813A4A98EFCFD9EAULL,
		0xDF5049679030FC02ULL,
		0x7CB76B585A7FC819ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC976A8D174F1411EULL,
		0x666161B91C8DF4A1ULL,
		0x0D75D7599EE855B0ULL,
		0x087CC7F1A58EA660ULL,
		0x56D57C31F491AE9CULL,
		0xBBCBB0619AEE2FE8ULL,
		0xF6B4CBFCC75BABAAULL,
		0x05A6DC35CC2B21EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92ED51A2E9E2823CULL,
		0xCCC2C372391BE943ULL,
		0x1AEBAEB33DD0AB60ULL,
		0x10F98FE34B1D4CC0ULL,
		0xADAAF863E9235D38ULL,
		0x779760C335DC5FD0ULL,
		0xED6997F98EB75755ULL,
		0x0B4DB86B985643DBULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2F26FEAA125C756ULL,
		0x3545DFE3641CA88AULL,
		0xC31CA9EFCC0A1076ULL,
		0xC3F5B3E31ACC4A03ULL,
		0xA1A2EF82B578386BULL,
		0xAF656BA21F1BF7D7ULL,
		0x5E683B18D1FD847BULL,
		0x32B6EC4C4DAAED76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5E4DFD5424B8EACULL,
		0x6A8BBFC6C8395115ULL,
		0x863953DF981420ECULL,
		0x87EB67C635989407ULL,
		0x4345DF056AF070D7ULL,
		0x5ECAD7443E37EFAFULL,
		0xBCD07631A3FB08F7ULL,
		0x656DD8989B55DAECULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB7A7D32308E95EFULL,
		0xF60F1FB5390CA9FBULL,
		0x5517FA3D2F7C44F4ULL,
		0x61D1928DF1058AF4ULL,
		0x7B79F408F7460F5BULL,
		0xA9F1D95D6ADD86E7ULL,
		0xAC6DF518A0AE5F93ULL,
		0x1E383D983BFBB5F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F4FA64611D2BDEULL,
		0xEC1E3F6A721953F7ULL,
		0xAA2FF47A5EF889E9ULL,
		0xC3A3251BE20B15E8ULL,
		0xF6F3E811EE8C1EB6ULL,
		0x53E3B2BAD5BB0DCEULL,
		0x58DBEA31415CBF27ULL,
		0x3C707B3077F76BE5ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x209CCDD5D1669EDDULL,
		0xCD437C959B6CC26AULL,
		0x5298661B2D2E99D4ULL,
		0x360D555D26E9699BULL,
		0xB6AC898805EED3E5ULL,
		0xCAA04B23B8F84189ULL,
		0x7BB65260B35EF316ULL,
		0x3D8B112602F1A5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41399BABA2CD3DBAULL,
		0x9A86F92B36D984D4ULL,
		0xA530CC365A5D33A9ULL,
		0x6C1AAABA4DD2D336ULL,
		0x6D5913100BDDA7CAULL,
		0x9540964771F08313ULL,
		0xF76CA4C166BDE62DULL,
		0x7B16224C05E34BA0ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F4A0960DC0DDB8EULL,
		0x7585F8ABD6671F41ULL,
		0xED47FE9BEF2AFBF0ULL,
		0xC0172D7286FD568EULL,
		0xA2F022BD92B6BE1CULL,
		0x05500DE3B72E3C4CULL,
		0x030B3A0CF9C72EEAULL,
		0x035B02E637F39761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9412C1B81BB71CULL,
		0xEB0BF157ACCE3E82ULL,
		0xDA8FFD37DE55F7E0ULL,
		0x802E5AE50DFAAD1DULL,
		0x45E0457B256D7C39ULL,
		0x0AA01BC76E5C7899ULL,
		0x06167419F38E5DD4ULL,
		0x06B605CC6FE72EC2ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65B374116A60E5F2ULL,
		0xCAECDEA949D6DB8AULL,
		0x9255EEA7CD1B39E0ULL,
		0xB9ACA29E2CC85AD3ULL,
		0xF170239A4C2D826BULL,
		0x5EB192CF8AD449ABULL,
		0x3BBC2DF1FBEC6AE4ULL,
		0x0E2B34ED6A0C6B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB66E822D4C1CBE4ULL,
		0x95D9BD5293ADB714ULL,
		0x24ABDD4F9A3673C1ULL,
		0x7359453C5990B5A7ULL,
		0xE2E04734985B04D7ULL,
		0xBD63259F15A89357ULL,
		0x77785BE3F7D8D5C8ULL,
		0x1C5669DAD418D6B6ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1D2EB2DC672E681ULL,
		0x3D8813AA26DEFD60ULL,
		0x83D9C52596F560A9ULL,
		0xDD5F9FD5AB7C9D83ULL,
		0xC414EF59749D8FB1ULL,
		0xF7CB1AD01683BBDCULL,
		0x0DC3E752C9FAC795ULL,
		0x187C4DEB313B1940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A5D65B8CE5CD02ULL,
		0x7B1027544DBDFAC1ULL,
		0x07B38A4B2DEAC152ULL,
		0xBABF3FAB56F93B07ULL,
		0x8829DEB2E93B1F63ULL,
		0xEF9635A02D0777B9ULL,
		0x1B87CEA593F58F2BULL,
		0x30F89BD662763280ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56A4C013F9B9D12DULL,
		0x17480F99347E27B3ULL,
		0x3A2F279906E40300ULL,
		0x3B52709CFECDCDF1ULL,
		0xBB61426E88E07BFEULL,
		0x45918B48645A8247ULL,
		0x8458D46576D95DECULL,
		0x2687BEC22378D1F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD498027F373A25AULL,
		0x2E901F3268FC4F66ULL,
		0x745E4F320DC80600ULL,
		0x76A4E139FD9B9BE2ULL,
		0x76C284DD11C0F7FCULL,
		0x8B231690C8B5048FULL,
		0x08B1A8CAEDB2BBD8ULL,
		0x4D0F7D8446F1A3E5ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF4EC9F778C09894ULL,
		0xE6044295BCF90B35ULL,
		0x5EC5377CBFC73819ULL,
		0x71B5D6E8F34155E3ULL,
		0x79FDA09D09000F2DULL,
		0x4C550AF20C0B2689ULL,
		0x3FFEFB2FAEC2E78FULL,
		0x0F636DD99E2EB422ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E9D93EEF1813128ULL,
		0xCC08852B79F2166BULL,
		0xBD8A6EF97F8E7033ULL,
		0xE36BADD1E682ABC6ULL,
		0xF3FB413A12001E5AULL,
		0x98AA15E418164D12ULL,
		0x7FFDF65F5D85CF1EULL,
		0x1EC6DBB33C5D6844ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x467360B38234C405ULL,
		0x9E6CFBBCE656A1D1ULL,
		0x9E6FEC91DCF44FB8ULL,
		0xBFA108AFF7FBE16FULL,
		0x6995A6B6CDEE5323ULL,
		0xB8332066BE236E7BULL,
		0x139E152128E304B8ULL,
		0x0118608F6F9A550EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE6C1670469880AULL,
		0x3CD9F779CCAD43A2ULL,
		0x3CDFD923B9E89F71ULL,
		0x7F42115FEFF7C2DFULL,
		0xD32B4D6D9BDCA647ULL,
		0x706640CD7C46DCF6ULL,
		0x273C2A4251C60971ULL,
		0x0230C11EDF34AA1CULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FEF68BBF77E47A9ULL,
		0x85515230F226E8D0ULL,
		0xC88C7BEA4F69D057ULL,
		0x50DD7B25C9F4FD87ULL,
		0xB55FB7774B9896F7ULL,
		0x163CDA762B832F54ULL,
		0xB257235E7BB662FCULL,
		0x31C8196D4B403131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFDED177EEFC8F52ULL,
		0x0AA2A461E44DD1A0ULL,
		0x9118F7D49ED3A0AFULL,
		0xA1BAF64B93E9FB0FULL,
		0x6ABF6EEE97312DEEULL,
		0x2C79B4EC57065EA9ULL,
		0x64AE46BCF76CC5F8ULL,
		0x639032DA96806263ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26353829A8FCDC3FULL,
		0x9234A72C8EA50D47ULL,
		0x885CE3F08E19E490ULL,
		0x2D6043069222CA7DULL,
		0xE4E7FD04BBAC045FULL,
		0x0C094A6A81E62808ULL,
		0x96C5FFD6BEC18036ULL,
		0x0C59376CC355A488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C6A705351F9B87EULL,
		0x24694E591D4A1A8EULL,
		0x10B9C7E11C33C921ULL,
		0x5AC0860D244594FBULL,
		0xC9CFFA09775808BEULL,
		0x181294D503CC5011ULL,
		0x2D8BFFAD7D83006CULL,
		0x18B26ED986AB4911ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x317025F3E6CE021BULL,
		0x7D89AE9E04BD4896ULL,
		0x4F30684BEB8325A4ULL,
		0x4140F84431CB50C8ULL,
		0x6E3077EBF192B882ULL,
		0x7EEEF9EB3BF31F2EULL,
		0x45A5AF93B3B46209ULL,
		0x33DA745223CB3B94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E04BE7CD9C0436ULL,
		0xFB135D3C097A912CULL,
		0x9E60D097D7064B48ULL,
		0x8281F0886396A190ULL,
		0xDC60EFD7E3257104ULL,
		0xFDDDF3D677E63E5CULL,
		0x8B4B5F276768C412ULL,
		0x67B4E8A447967728ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5556F1E7E7046F73ULL,
		0x7763766CE19D6FB6ULL,
		0xB6A9C9442445B464ULL,
		0x15EE8D77066E90BAULL,
		0xD8C40BE8D60999A4ULL,
		0x97C3DE678ADDF2CBULL,
		0x1E58E529A45CCA75ULL,
		0x39AC618CC3286981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAADE3CFCE08DEE6ULL,
		0xEEC6ECD9C33ADF6CULL,
		0x6D539288488B68C8ULL,
		0x2BDD1AEE0CDD2175ULL,
		0xB18817D1AC133348ULL,
		0x2F87BCCF15BBE597ULL,
		0x3CB1CA5348B994EBULL,
		0x7358C3198650D302ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB52A9F3BA4E8E82CULL,
		0xB41F18220D99C021ULL,
		0x84166081E519BD07ULL,
		0xB08E5917B5638CF3ULL,
		0xEA9C08C30D2DF71FULL,
		0xDF36AFC483222F93ULL,
		0x05C5B322C922042AULL,
		0x32F9198F204ED1A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A553E7749D1D058ULL,
		0x683E30441B338043ULL,
		0x082CC103CA337A0FULL,
		0x611CB22F6AC719E7ULL,
		0xD53811861A5BEE3FULL,
		0xBE6D5F8906445F27ULL,
		0x0B8B664592440855ULL,
		0x65F2331E409DA340ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85E2B0BA3D334BDCULL,
		0x0D194FE7889B909BULL,
		0x14874CECAB8D2627ULL,
		0x56593D1316FCBA40ULL,
		0xE4E1CC7EC6CE8BCAULL,
		0xDEB2BA09D2CF1B5AULL,
		0x866BBBA4EC614E02ULL,
		0x2AAC47964056472CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BC561747A6697B8ULL,
		0x1A329FCF11372137ULL,
		0x290E99D9571A4C4EULL,
		0xACB27A262DF97480ULL,
		0xC9C398FD8D9D1794ULL,
		0xBD657413A59E36B5ULL,
		0x0CD77749D8C29C05ULL,
		0x55588F2C80AC8E59ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE77D1C0D3A38607ULL,
		0xFCD52742618EC690ULL,
		0x0990E174DD7CDEBBULL,
		0x3DF39F3D5338301DULL,
		0x57679BB036E2F6A1ULL,
		0x0387B7CC07150C6CULL,
		0x18A809F5673B0CA8ULL,
		0x2A1D359FA92F7BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEFA381A7470C0EULL,
		0xF9AA4E84C31D8D21ULL,
		0x1321C2E9BAF9BD77ULL,
		0x7BE73E7AA670603AULL,
		0xAECF37606DC5ED42ULL,
		0x070F6F980E2A18D8ULL,
		0x315013EACE761950ULL,
		0x543A6B3F525EF756ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61A8D07A4487CDD4ULL,
		0x00BD9A8EE9A20457ULL,
		0x1B1C0D17291ADD3DULL,
		0xFF027C783CD35728ULL,
		0x3154C8385ACBA3D1ULL,
		0x0EFB31D803DFB69FULL,
		0x3F3DEB2DC599C67FULL,
		0x1F57094E9DFE4C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC351A0F4890F9BA8ULL,
		0x017B351DD34408AEULL,
		0x36381A2E5235BA7AULL,
		0xFE04F8F079A6AE50ULL,
		0x62A99070B59747A3ULL,
		0x1DF663B007BF6D3EULL,
		0x7E7BD65B8B338CFEULL,
		0x3EAE129D3BFC9914ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E0C6EF7083A0D65ULL,
		0xEE84A5F743B64735ULL,
		0xA21671978D4908C5ULL,
		0x24A2007F49113CB8ULL,
		0x5B60F0CC040E2C68ULL,
		0xB351A6DD26D9CF00ULL,
		0xD3C7EBDE973F552EULL,
		0x2FA74C39774DD17AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C18DDEE10741ACAULL,
		0xDD094BEE876C8E6BULL,
		0x442CE32F1A92118BULL,
		0x494400FE92227971ULL,
		0xB6C1E198081C58D0ULL,
		0x66A34DBA4DB39E00ULL,
		0xA78FD7BD2E7EAA5DULL,
		0x5F4E9872EE9BA2F5ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCD67269B51D8651ULL,
		0x20631EA5F2138F05ULL,
		0x613A056FC2744501ULL,
		0xA61F52DE3E7BBB80ULL,
		0x3A2D306482D62EB5ULL,
		0x96CB514D59E993DAULL,
		0x8C1CDB54AF160DBEULL,
		0x067EB14526FF0408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9ACE4D36A3B0CA2ULL,
		0x40C63D4BE4271E0BULL,
		0xC2740ADF84E88A02ULL,
		0x4C3EA5BC7CF77700ULL,
		0x745A60C905AC5D6BULL,
		0x2D96A29AB3D327B4ULL,
		0x1839B6A95E2C1B7DULL,
		0x0CFD628A4DFE0811ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0558743AD2B6B09AULL,
		0xF00AD88F1DA910B4ULL,
		0x2E39BF311D3C1540ULL,
		0x1EB6E5115E9BE3C9ULL,
		0x4CABBAE5D320480AULL,
		0x8D2F5986928D5B16ULL,
		0x020CB0615E4A2FBEULL,
		0x32F8858812B686C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB0E875A56D6134ULL,
		0xE015B11E3B522168ULL,
		0x5C737E623A782A81ULL,
		0x3D6DCA22BD37C792ULL,
		0x995775CBA6409014ULL,
		0x1A5EB30D251AB62CULL,
		0x041960C2BC945F7DULL,
		0x65F10B10256D0D92ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D3C6598526C6B27ULL,
		0xE094532813BC1C27ULL,
		0x2000490D38F8B06CULL,
		0x45C696AF40641BA4ULL,
		0xD531094B1CC2E0CAULL,
		0x787B52AD0EC87C22ULL,
		0xB683F00C359DBC1CULL,
		0x17B112B84CE46C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA78CB30A4D8D64EULL,
		0xC128A6502778384EULL,
		0x4000921A71F160D9ULL,
		0x8B8D2D5E80C83748ULL,
		0xAA6212963985C194ULL,
		0xF0F6A55A1D90F845ULL,
		0x6D07E0186B3B7838ULL,
		0x2F62257099C8D891ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6771A5AA6267F33ULL,
		0x98CB5B94895A0671ULL,
		0xBB20BB334FEE0FDDULL,
		0x5D0D5F7E155D8DC9ULL,
		0xA886002D56606BA8ULL,
		0x08185BF77439BBDFULL,
		0x85EFDE4ED1609434ULL,
		0x180D4D9830FDA6D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CEE34B54C4CFE66ULL,
		0x3196B72912B40CE3ULL,
		0x764176669FDC1FBBULL,
		0xBA1ABEFC2ABB1B93ULL,
		0x510C005AACC0D750ULL,
		0x1030B7EEE87377BFULL,
		0x0BDFBC9DA2C12868ULL,
		0x301A9B3061FB4DA3ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65209E28AC863BC9ULL,
		0xE5DB729B7537688AULL,
		0x7ECD83004E14C165ULL,
		0x4D5E0238F782E0E0ULL,
		0x33987C998F85CBA3ULL,
		0x5E44E9846A1D6451ULL,
		0xA22E9F3686F47EA4ULL,
		0x12435B83B5C30957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA413C51590C7792ULL,
		0xCBB6E536EA6ED114ULL,
		0xFD9B06009C2982CBULL,
		0x9ABC0471EF05C1C0ULL,
		0x6730F9331F0B9746ULL,
		0xBC89D308D43AC8A2ULL,
		0x445D3E6D0DE8FD48ULL,
		0x2486B7076B8612AFULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EDA9ED1AD295D40ULL,
		0xDB590AB2ABCE9A43ULL,
		0x19C5A64047B01CA7ULL,
		0x467D0129FF354288ULL,
		0xF1264E073C183967ULL,
		0x724058AB10BCBB85ULL,
		0x3A572E9D454771D1ULL,
		0x3E4F0B61FFD7DEB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB53DA35A52BA80ULL,
		0xB6B21565579D3486ULL,
		0x338B4C808F60394FULL,
		0x8CFA0253FE6A8510ULL,
		0xE24C9C0E783072CEULL,
		0xE480B1562179770BULL,
		0x74AE5D3A8A8EE3A2ULL,
		0x7C9E16C3FFAFBD70ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4325383C61F0220ULL,
		0x74BDB231F0731700ULL,
		0x9EB549B9F180DF69ULL,
		0x281A99086B9678C1ULL,
		0xF19740553E549612ULL,
		0xBC48351A9D5684A0ULL,
		0xF791E47B28038796ULL,
		0x1557D796397F1F92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6864A7078C3E0440ULL,
		0xE97B6463E0E62E01ULL,
		0x3D6A9373E301BED2ULL,
		0x50353210D72CF183ULL,
		0xE32E80AA7CA92C24ULL,
		0x78906A353AAD0941ULL,
		0xEF23C8F650070F2DULL,
		0x2AAFAF2C72FE3F25ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7FA34D0091BFB7AULL,
		0x283D7429E65EA6A3ULL,
		0x5DBE9F015B579592ULL,
		0x8317037BB557881CULL,
		0x1EC10D31F00F1413ULL,
		0xE5575EF31341EC87ULL,
		0x4470A5F5F5422AA6ULL,
		0x206D2D9CDF4E5A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FF469A01237F6F4ULL,
		0x507AE853CCBD4D47ULL,
		0xBB7D3E02B6AF2B24ULL,
		0x062E06F76AAF1038ULL,
		0x3D821A63E01E2827ULL,
		0xCAAEBDE62683D90EULL,
		0x88E14BEBEA84554DULL,
		0x40DA5B39BE9CB452ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFE33BDF370E9F5BULL,
		0x44845E71063E4CB6ULL,
		0x1731C35B78184B6EULL,
		0x1C6C0D183025D0A9ULL,
		0xAEEC15B835210793ULL,
		0xA9890469B9498334ULL,
		0xF9A2D40FC3563C61ULL,
		0x0CE1994C1B8BC876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC677BE6E1D3EB6ULL,
		0x8908BCE20C7C996DULL,
		0x2E6386B6F03096DCULL,
		0x38D81A30604BA152ULL,
		0x5DD82B706A420F26ULL,
		0x531208D372930669ULL,
		0xF345A81F86AC78C3ULL,
		0x19C33298371790EDULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D4303EE44B3D6D7ULL,
		0xF07AF60B89D4D860ULL,
		0xD0C0468D11D1958AULL,
		0x4B59FD03A9D61D38ULL,
		0x569CF0EA5C2311D1ULL,
		0x691E9313BD261B74ULL,
		0xA6BA9425643BA1CFULL,
		0x15E383E9CCD83124ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA8607DC8967ADAEULL,
		0xE0F5EC1713A9B0C0ULL,
		0xA1808D1A23A32B15ULL,
		0x96B3FA0753AC3A71ULL,
		0xAD39E1D4B84623A2ULL,
		0xD23D26277A4C36E8ULL,
		0x4D75284AC877439EULL,
		0x2BC707D399B06249ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE86BF23B3F09C6DULL,
		0x03E830D7605E576CULL,
		0x3E6EC3FFB2A7D26BULL,
		0x8A02D0ECEC51D374ULL,
		0xE9E262202E20399DULL,
		0xC2B30B43E1F1FF9AULL,
		0xCF9DE9C95C899F5AULL,
		0x0081E8DB2A96B53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD0D7E4767E138DAULL,
		0x07D061AEC0BCAED9ULL,
		0x7CDD87FF654FA4D6ULL,
		0x1405A1D9D8A3A6E8ULL,
		0xD3C4C4405C40733BULL,
		0x85661687C3E3FF35ULL,
		0x9F3BD392B9133EB5ULL,
		0x0103D1B6552D6A75ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECC272334C46DB3EULL,
		0xBD56F02D6D7DB234ULL,
		0x5F4615287EFC2BF3ULL,
		0x408B2F1BE0245588ULL,
		0x5C535BDDF9FEC2E3ULL,
		0x4684B0614B1BDB02ULL,
		0xA98B3C0AC248D71FULL,
		0x31A662830CA071ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD984E466988DB67CULL,
		0x7AADE05ADAFB6469ULL,
		0xBE8C2A50FDF857E7ULL,
		0x81165E37C048AB10ULL,
		0xB8A6B7BBF3FD85C6ULL,
		0x8D0960C29637B604ULL,
		0x531678158491AE3EULL,
		0x634CC5061940E359ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D9B3405BB205186ULL,
		0x06894C0D50D45D90ULL,
		0x5050CEE5DE50C733ULL,
		0x3EFFD5C9FD38844FULL,
		0x72C360B16B32B762ULL,
		0x86B383D76D049014ULL,
		0x00E9100F978EC1FCULL,
		0x022FBE137CCD9E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B36680B7640A30CULL,
		0x0D12981AA1A8BB20ULL,
		0xA0A19DCBBCA18E66ULL,
		0x7DFFAB93FA71089EULL,
		0xE586C162D6656EC4ULL,
		0x0D6707AEDA092028ULL,
		0x01D2201F2F1D83F9ULL,
		0x045F7C26F99B3CE6ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC6D6031DEA7402EULL,
		0x422BFAC7F8C1AC64ULL,
		0x1854EE7ACE5AA9A0ULL,
		0x9CAAC72F15A86BF3ULL,
		0x1F5F834E815DA419ULL,
		0x0EF8E11095E10455ULL,
		0x517F4AF4F15188E6ULL,
		0x304BB11249BB0A1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58DAC063BD4E805CULL,
		0x8457F58FF18358C9ULL,
		0x30A9DCF59CB55340ULL,
		0x39558E5E2B50D7E6ULL,
		0x3EBF069D02BB4833ULL,
		0x1DF1C2212BC208AAULL,
		0xA2FE95E9E2A311CCULL,
		0x6097622493761434ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AD6EB476B346782ULL,
		0xB3B8F9B2044BA60AULL,
		0xE7EB72BE21E5C910ULL,
		0x4C7C7D7414217E9FULL,
		0xCA7AD9FA47A6D4B2ULL,
		0x4F4016B17A70BF08ULL,
		0x0580366F22BF2A03ULL,
		0x2CF895604C01D634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55ADD68ED668CF04ULL,
		0x6771F36408974C14ULL,
		0xCFD6E57C43CB9221ULL,
		0x98F8FAE82842FD3FULL,
		0x94F5B3F48F4DA964ULL,
		0x9E802D62F4E17E11ULL,
		0x0B006CDE457E5406ULL,
		0x59F12AC09803AC68ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4E0FDE563EBB4B4ULL,
		0xBF842F0D690142BEULL,
		0x41AE75B6597BA5AAULL,
		0x08CC00068647F748ULL,
		0x2031741B83E3FB52ULL,
		0xB7E3E3ED8D4949B3ULL,
		0x85E6BCA76BA12FF6ULL,
		0x3B8CCF34F3D19619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C1FBCAC7D76968ULL,
		0x7F085E1AD202857DULL,
		0x835CEB6CB2F74B55ULL,
		0x1198000D0C8FEE90ULL,
		0x4062E83707C7F6A4ULL,
		0x6FC7C7DB1A929366ULL,
		0x0BCD794ED7425FEDULL,
		0x77199E69E7A32C33ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B039EFECC42F7C2ULL,
		0xA430ABA3E0EE99F1ULL,
		0x9E14F7B19A25F0A2ULL,
		0x862B8391EF80C248ULL,
		0xE92FD3723ABE8D8BULL,
		0x0AF4A96C5B9AC93BULL,
		0x500FFB07E85FD15DULL,
		0x0539824108A89314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36073DFD9885EF84ULL,
		0x48615747C1DD33E3ULL,
		0x3C29EF63344BE145ULL,
		0x0C570723DF018491ULL,
		0xD25FA6E4757D1B17ULL,
		0x15E952D8B7359277ULL,
		0xA01FF60FD0BFA2BAULL,
		0x0A73048211512628ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43C1C60B543C0D35ULL,
		0xAD2CDF4EB2E1970DULL,
		0x6F7116E3BEB4A784ULL,
		0x1B370E0D67A60378ULL,
		0xAC4ECD35833BCCF3ULL,
		0x60686FDE210189C7ULL,
		0xA99ABAEAAE77BDB9ULL,
		0x2920EF632162796BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87838C16A8781A6AULL,
		0x5A59BE9D65C32E1AULL,
		0xDEE22DC77D694F09ULL,
		0x366E1C1ACF4C06F0ULL,
		0x589D9A6B067799E6ULL,
		0xC0D0DFBC4203138FULL,
		0x533575D55CEF7B72ULL,
		0x5241DEC642C4F2D7ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F8B82CF7AD4E04CULL,
		0xBF287AB2F02A8F80ULL,
		0x3252CD55628C4D0FULL,
		0x2B8C92364C2A0612ULL,
		0x7FADACC2602684EEULL,
		0x78A11E630574E280ULL,
		0x23882400648ABAAEULL,
		0x04B1564F418356AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F17059EF5A9C098ULL,
		0x7E50F565E0551F01ULL,
		0x64A59AAAC5189A1FULL,
		0x5719246C98540C24ULL,
		0xFF5B5984C04D09DCULL,
		0xF1423CC60AE9C500ULL,
		0x47104800C915755CULL,
		0x0962AC9E8306AD5CULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79D75D9BAB4468D3ULL,
		0xA48B9AE72BBE40FDULL,
		0xE5956E0BE5DD129FULL,
		0x479AC37928F44384ULL,
		0xD0E825B0B14BCC15ULL,
		0x4F5F22757AF43937ULL,
		0x30C134FBE8EC3399ULL,
		0x3E9B7E2221A2D5EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3AEBB375688D1A6ULL,
		0x491735CE577C81FAULL,
		0xCB2ADC17CBBA253FULL,
		0x8F3586F251E88709ULL,
		0xA1D04B616297982AULL,
		0x9EBE44EAF5E8726FULL,
		0x618269F7D1D86732ULL,
		0x7D36FC444345ABDEULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2246A5D4A3E8B1FDULL,
		0xFAACE1C0FD996DB6ULL,
		0x844E2D4E0B26420DULL,
		0x024B930E48CAA65BULL,
		0xA0A0EF2C776B7345ULL,
		0x855668ECF231640BULL,
		0xE1AA0B2C2576EF4CULL,
		0x11FD83890791FD54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448D4BA947D163FAULL,
		0xF559C381FB32DB6CULL,
		0x089C5A9C164C841BULL,
		0x0497261C91954CB7ULL,
		0x4141DE58EED6E68AULL,
		0x0AACD1D9E462C817ULL,
		0xC35416584AEDDE99ULL,
		0x23FB07120F23FAA9ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB77025973337AD79ULL,
		0x4D9BA6E058B998FBULL,
		0x038940C7BFC1FB03ULL,
		0x35FEE9E2813D0F2FULL,
		0x1AE9AAF2D830705EULL,
		0xBB470A8A18E1B97BULL,
		0x51BC537FC418D80FULL,
		0x2427838DD8240464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE04B2E666F5AF2ULL,
		0x9B374DC0B17331F7ULL,
		0x0712818F7F83F606ULL,
		0x6BFDD3C5027A1E5EULL,
		0x35D355E5B060E0BCULL,
		0x768E151431C372F6ULL,
		0xA378A6FF8831B01FULL,
		0x484F071BB04808C8ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC74BB6BDA7F116AAULL,
		0xBF6D275F717616DBULL,
		0x65B9824D6E416D42ULL,
		0x0D4B6FFF786A8876ULL,
		0x5B6510518555F260ULL,
		0xF345B49F20B493FEULL,
		0x1C1F36E7C62F1500ULL,
		0x06786AF12D08B0EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E976D7B4FE22D54ULL,
		0x7EDA4EBEE2EC2DB7ULL,
		0xCB73049ADC82DA85ULL,
		0x1A96DFFEF0D510ECULL,
		0xB6CA20A30AABE4C0ULL,
		0xE68B693E416927FCULL,
		0x383E6DCF8C5E2A01ULL,
		0x0CF0D5E25A1161DAULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7B65828FC371E5AULL,
		0x40E19B4CEC94A455ULL,
		0x52A076ED49323EECULL,
		0x01E3DD49E4136AFEULL,
		0xCAD57FE33C71D239ULL,
		0xB916173C7AE45820ULL,
		0xF1E856B8906B3318ULL,
		0x2FEC6D5812892037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF6CB051F86E3CB4ULL,
		0x81C33699D92948ABULL,
		0xA540EDDA92647DD8ULL,
		0x03C7BA93C826D5FCULL,
		0x95AAFFC678E3A472ULL,
		0x722C2E78F5C8B041ULL,
		0xE3D0AD7120D66631ULL,
		0x5FD8DAB02512406FULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ECA7185D5EBAD28ULL,
		0x9799F9EA7393518CULL,
		0x0A249A2AF4ED2FDCULL,
		0x57E57F6A893CE119ULL,
		0x4627B0EA049B3D4BULL,
		0x2CB060FD8DCDDA84ULL,
		0x7A8F114B3C94FB9AULL,
		0x0370EB0F8E670CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D94E30BABD75A50ULL,
		0x2F33F3D4E726A318ULL,
		0x14493455E9DA5FB9ULL,
		0xAFCAFED51279C232ULL,
		0x8C4F61D409367A96ULL,
		0x5960C1FB1B9BB508ULL,
		0xF51E22967929F734ULL,
		0x06E1D61F1CCE19AEULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37A28B484DC302A0ULL,
		0x7B307A306F0FCAA7ULL,
		0xFFB6337F2596A9FFULL,
		0x77CAB90E4518404DULL,
		0xCA192F08F6129457ULL,
		0x064DF2C0BF347FCCULL,
		0x66AE49CA29C012B6ULL,
		0x2137321D7D9DB5E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F4516909B860540ULL,
		0xF660F460DE1F954EULL,
		0xFF6C66FE4B2D53FEULL,
		0xEF95721C8A30809BULL,
		0x94325E11EC2528AEULL,
		0x0C9BE5817E68FF99ULL,
		0xCD5C93945380256CULL,
		0x426E643AFB3B6BD0ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF285F4C7DF53ED19ULL,
		0xEDD876FB446794D7ULL,
		0x4DD88134D2BC74ACULL,
		0xCDD4FA501C6B6B3DULL,
		0x0A49AEE4D5FA40E8ULL,
		0xC6806B72034DD4FDULL,
		0xD0507446844D72CAULL,
		0x070C191C516D7588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE50BE98FBEA7DA32ULL,
		0xDBB0EDF688CF29AFULL,
		0x9BB10269A578E959ULL,
		0x9BA9F4A038D6D67AULL,
		0x14935DC9ABF481D1ULL,
		0x8D00D6E4069BA9FAULL,
		0xA0A0E88D089AE595ULL,
		0x0E183238A2DAEB11ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91D64C2AF368FFFBULL,
		0xA36E870923D71239ULL,
		0xFC4091AC632B56A0ULL,
		0xCBD620E99D18E22FULL,
		0x62A49A91261CAF7AULL,
		0x89FAC7D484D6D06FULL,
		0xE6663D22F91FBCA7ULL,
		0x23CA3F4A263CE466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AC9855E6D1FFF6ULL,
		0x46DD0E1247AE2473ULL,
		0xF8812358C656AD41ULL,
		0x97AC41D33A31C45FULL,
		0xC54935224C395EF5ULL,
		0x13F58FA909ADA0DEULL,
		0xCCCC7A45F23F794FULL,
		0x47947E944C79C8CDULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8979894B9FEDF8FULL,
		0xD867B8A230AC55E9ULL,
		0x2A3AA086FF028A5DULL,
		0x0B76BC42F1EED86CULL,
		0x2DC4A2E3E7D04008ULL,
		0xAEBF706286359AD5ULL,
		0x47EFB1FB0201A58CULL,
		0x254EA03B277A0475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912F312973FDBF1EULL,
		0xB0CF71446158ABD3ULL,
		0x5475410DFE0514BBULL,
		0x16ED7885E3DDB0D8ULL,
		0x5B8945C7CFA08010ULL,
		0x5D7EE0C50C6B35AAULL,
		0x8FDF63F604034B19ULL,
		0x4A9D40764EF408EAULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA589B1748B70C484ULL,
		0xD7AAA4A68028CBE8ULL,
		0x816A92AC982543D1ULL,
		0x418752F0BA921962ULL,
		0xF1AA168A1FB57DD0ULL,
		0x2CBFA28CE08870EBULL,
		0x7626681C2E98DB9BULL,
		0x25304C2503A266AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B1362E916E18908ULL,
		0xAF55494D005197D1ULL,
		0x02D52559304A87A3ULL,
		0x830EA5E1752432C5ULL,
		0xE3542D143F6AFBA0ULL,
		0x597F4519C110E1D7ULL,
		0xEC4CD0385D31B736ULL,
		0x4A60984A0744CD5CULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACF10AF4E1169B72ULL,
		0x2278B983F21D0E20ULL,
		0xC7C55E0F6EE80269ULL,
		0x4542747A200879A4ULL,
		0x3C63DC23121911A2ULL,
		0xDBE3AF945ABC5241ULL,
		0x26854A8519E63865ULL,
		0x33E19DB8B279B071ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E215E9C22D36E4ULL,
		0x44F17307E43A1C41ULL,
		0x8F8ABC1EDDD004D2ULL,
		0x8A84E8F44010F349ULL,
		0x78C7B84624322344ULL,
		0xB7C75F28B578A482ULL,
		0x4D0A950A33CC70CBULL,
		0x67C33B7164F360E2ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD88109E9C0BBFBB1ULL,
		0xA34596E0AAFC2F12ULL,
		0x40F814F804293B8BULL,
		0xBD5D9F2431CBC9D8ULL,
		0x015CF7F799A7E408ULL,
		0xCF9FBCD0DFB616D0ULL,
		0xD89E48CE15D8E2EAULL,
		0x030F4D6D40D27704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB10213D38177F762ULL,
		0x468B2DC155F85E25ULL,
		0x81F029F008527717ULL,
		0x7ABB3E48639793B0ULL,
		0x02B9EFEF334FC811ULL,
		0x9F3F79A1BF6C2DA0ULL,
		0xB13C919C2BB1C5D5ULL,
		0x061E9ADA81A4EE09ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE9563435B41DB4BULL,
		0x9E09D290D1CDD068ULL,
		0x02BEE4B169F7161AULL,
		0x3A03F59650BF305DULL,
		0x7927F7389609EBB0ULL,
		0xF7DFBF622FD82142ULL,
		0x5CCFE1948E29735EULL,
		0x2ABCD6E8C311E5C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D2AC686B683B696ULL,
		0x3C13A521A39BA0D1ULL,
		0x057DC962D3EE2C35ULL,
		0x7407EB2CA17E60BAULL,
		0xF24FEE712C13D760ULL,
		0xEFBF7EC45FB04284ULL,
		0xB99FC3291C52E6BDULL,
		0x5579ADD18623CB8EULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A799FF850E76602ULL,
		0x75C629C02E445B8CULL,
		0x5F397D0C5D554A05ULL,
		0xBD250E7BFDDFC9B4ULL,
		0xDF385E0028D917F4ULL,
		0x788A021DF1AC56FFULL,
		0xE32243273E0EB7DFULL,
		0x291EB43F7A9F60C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F33FF0A1CECC04ULL,
		0xEB8C53805C88B719ULL,
		0xBE72FA18BAAA940AULL,
		0x7A4A1CF7FBBF9368ULL,
		0xBE70BC0051B22FE9ULL,
		0xF114043BE358ADFFULL,
		0xC644864E7C1D6FBEULL,
		0x523D687EF53EC185ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2398904B507F9CE5ULL,
		0xA1CB965CF16CDCD1ULL,
		0xB27F3313BF7B1610ULL,
		0x1E8DA84D5B7EBE2EULL,
		0xA785EEE5F60931EDULL,
		0x133A69E02A6AF542ULL,
		0x16C07D2EF7361720ULL,
		0x31F7213985028692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47312096A0FF39CAULL,
		0x43972CB9E2D9B9A2ULL,
		0x64FE66277EF62C21ULL,
		0x3D1B509AB6FD7C5DULL,
		0x4F0BDDCBEC1263DAULL,
		0x2674D3C054D5EA85ULL,
		0x2D80FA5DEE6C2E40ULL,
		0x63EE42730A050D24ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E512F3A098B0945ULL,
		0xFCC229E63ED76B35ULL,
		0xB280A04A2E1F2323ULL,
		0x73877C272D9C2BE3ULL,
		0x09F8E2AAED17050AULL,
		0xBDC34266D7BB0BA8ULL,
		0x5A46EE0EC9335E9BULL,
		0x1F020DAF82BD76C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA25E741316128AULL,
		0xF98453CC7DAED66AULL,
		0x650140945C3E4647ULL,
		0xE70EF84E5B3857C7ULL,
		0x13F1C555DA2E0A14ULL,
		0x7B8684CDAF761750ULL,
		0xB48DDC1D9266BD37ULL,
		0x3E041B5F057AED8EULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AA2823538228F76ULL,
		0x83D3C719CE347D2FULL,
		0x4C8E1F0CBDB79D8AULL,
		0xE70183973B24FE2DULL,
		0xF255B1246F2FAAD5ULL,
		0x9C0127069AAE2D99ULL,
		0x2514972F91C1A59EULL,
		0x251B09F8674DF7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB545046A70451EECULL,
		0x07A78E339C68FA5EULL,
		0x991C3E197B6F3B15ULL,
		0xCE03072E7649FC5AULL,
		0xE4AB6248DE5F55ABULL,
		0x38024E0D355C5B33ULL,
		0x4A292E5F23834B3DULL,
		0x4A3613F0CE9BEF5AULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD706BCB1836AA47BULL,
		0x2FC1E893F52280AEULL,
		0xB6621BE6060615ACULL,
		0x92AFAA7AE05B2BF7ULL,
		0xCDC376F7442B2839ULL,
		0x1B0691612EC0837BULL,
		0x46AC3F886E94494BULL,
		0x3F2B15D750F329F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE0D796306D548F6ULL,
		0x5F83D127EA45015DULL,
		0x6CC437CC0C0C2B58ULL,
		0x255F54F5C0B657EFULL,
		0x9B86EDEE88565073ULL,
		0x360D22C25D8106F7ULL,
		0x8D587F10DD289296ULL,
		0x7E562BAEA1E653E4ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6169B66AB66EE9AAULL,
		0x7A2056D1BE033AECULL,
		0x0324E7DF8588EA15ULL,
		0xD738495CAE1F86E0ULL,
		0x0C150E88133E3F2FULL,
		0x48BC8E7224E053A6ULL,
		0xE3792F3DF4B0CF51ULL,
		0x1C38AB715FA48359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D36CD56CDDD354ULL,
		0xF440ADA37C0675D8ULL,
		0x0649CFBF0B11D42AULL,
		0xAE7092B95C3F0DC0ULL,
		0x182A1D10267C7E5FULL,
		0x91791CE449C0A74CULL,
		0xC6F25E7BE9619EA2ULL,
		0x387156E2BF4906B3ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89EE94B5AF73579AULL,
		0xD4D47B2B24C0F52AULL,
		0xD140EFF220ADE85BULL,
		0xB0778B875FB9BAFEULL,
		0xC9F4C9A68B5C7DBBULL,
		0x9BD27593D7C5E3FBULL,
		0x8AACB9B1DA7163FBULL,
		0x2EFE632A19D7195AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13DD296B5EE6AF34ULL,
		0xA9A8F6564981EA55ULL,
		0xA281DFE4415BD0B7ULL,
		0x60EF170EBF7375FDULL,
		0x93E9934D16B8FB77ULL,
		0x37A4EB27AF8BC7F7ULL,
		0x15597363B4E2C7F7ULL,
		0x5DFCC65433AE32B5ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6ABBC03F984D8FFULL,
		0xEF0B1C8133489697ULL,
		0xC65CA2E77CDC00CEULL,
		0xBC4E61F1D099F0BCULL,
		0x438D5B17E3D9FADAULL,
		0x64547995746FAD51ULL,
		0x81BFAC736280016EULL,
		0x2AB2FFBF20CD748DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED577807F309B1FEULL,
		0xDE16390266912D2FULL,
		0x8CB945CEF9B8019DULL,
		0x789CC3E3A133E179ULL,
		0x871AB62FC7B3F5B5ULL,
		0xC8A8F32AE8DF5AA2ULL,
		0x037F58E6C50002DCULL,
		0x5565FF7E419AE91BULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81817DD7962E983BULL,
		0x3C7A8796D57102E4ULL,
		0xE2CA6AE08E40DF40ULL,
		0x588657362B58936BULL,
		0x5BCD5D1B9D83361FULL,
		0xA639FE47E4158180ULL,
		0xFE3558661D6602B7ULL,
		0x259DDD7A3401670BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0302FBAF2C5D3076ULL,
		0x78F50F2DAAE205C9ULL,
		0xC594D5C11C81BE80ULL,
		0xB10CAE6C56B126D7ULL,
		0xB79ABA373B066C3EULL,
		0x4C73FC8FC82B0300ULL,
		0xFC6AB0CC3ACC056FULL,
		0x4B3BBAF46802CE17ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA40E8AA202313D9ULL,
		0x8CC2D5538231FC76ULL,
		0x01CA6D36AE4B971EULL,
		0x9B2CA04E61E61F9CULL,
		0x1BFE25C08D6D481CULL,
		0xA2D6CD36DCDB2C58ULL,
		0xA18FAA857903F041ULL,
		0x0C9B532A99FED345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF481D154404627B2ULL,
		0x1985AAA70463F8EDULL,
		0x0394DA6D5C972E3DULL,
		0x3659409CC3CC3F38ULL,
		0x37FC4B811ADA9039ULL,
		0x45AD9A6DB9B658B0ULL,
		0x431F550AF207E083ULL,
		0x1936A65533FDA68BULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE18D90EDB5F8D67ULL,
		0xDBE55498DB646FCEULL,
		0xB6CC3D989EA97D25ULL,
		0xF10A68728FD4C3CEULL,
		0x49FBAF5337746F9DULL,
		0xC35ED46F5C15DA97ULL,
		0x20B8FB34DC300B72ULL,
		0x295710BB19722018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC31B21DB6BF1ACEULL,
		0xB7CAA931B6C8DF9DULL,
		0x6D987B313D52FA4BULL,
		0xE214D0E51FA9879DULL,
		0x93F75EA66EE8DF3BULL,
		0x86BDA8DEB82BB52EULL,
		0x4171F669B86016E5ULL,
		0x52AE217632E44030ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FD115EAD7BA7108ULL,
		0xEE94EEF72A6E980CULL,
		0x3F8CF2A6B927F3D9ULL,
		0x0C63ECF2443305CAULL,
		0xD70C7330AD8F6C3AULL,
		0xED1ABE223D2E64BCULL,
		0x81F6E575C35FA6A1ULL,
		0x214033D39F5DE71FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FA22BD5AF74E210ULL,
		0xDD29DDEE54DD3018ULL,
		0x7F19E54D724FE7B3ULL,
		0x18C7D9E488660B94ULL,
		0xAE18E6615B1ED874ULL,
		0xDA357C447A5CC979ULL,
		0x03EDCAEB86BF4D43ULL,
		0x428067A73EBBCE3FULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4C771500CF8ABD4ULL,
		0x7FC410E322200ACDULL,
		0x00AE3D94B75B755CULL,
		0x794029D292A1929EULL,
		0xE07224459C32449BULL,
		0x7A797FB4F77380ABULL,
		0x553F389DE05CB3F1ULL,
		0x35DD6DA582AB4B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE98EE2A019F157A8ULL,
		0xFF8821C64440159BULL,
		0x015C7B296EB6EAB8ULL,
		0xF28053A52543253CULL,
		0xC0E4488B38648936ULL,
		0xF4F2FF69EEE70157ULL,
		0xAA7E713BC0B967E2ULL,
		0x6BBADB4B05569636ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x475A747C3035ECBAULL,
		0xCF1B4E3EBCE77A5AULL,
		0xFFD6790A233ECCD7ULL,
		0x63E151DE9DE8FB7EULL,
		0xE0EF08EB88F44323ULL,
		0x0655B9DCB3490D97ULL,
		0x4D0EA6C36488672EULL,
		0x1F697DEE4DAF2AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB4E8F8606BD974ULL,
		0x9E369C7D79CEF4B4ULL,
		0xFFACF214467D99AFULL,
		0xC7C2A3BD3BD1F6FDULL,
		0xC1DE11D711E88646ULL,
		0x0CAB73B966921B2FULL,
		0x9A1D4D86C910CE5CULL,
		0x3ED2FBDC9B5E55F2ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3788923D127A8AA3ULL,
		0x97F325738C30F4F1ULL,
		0xF65CABDA53B44B00ULL,
		0xA3343179D735F1F4ULL,
		0x94105CF4EA8ABAE8ULL,
		0xF352DF0563BB8E19ULL,
		0xFDEE97A5F00A193FULL,
		0x1D62C68007AF5DBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F11247A24F51546ULL,
		0x2FE64AE71861E9E2ULL,
		0xECB957B4A7689601ULL,
		0x466862F3AE6BE3E9ULL,
		0x2820B9E9D51575D1ULL,
		0xE6A5BE0AC7771C33ULL,
		0xFBDD2F4BE014327FULL,
		0x3AC58D000F5EBB7BULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08CDF15529EB0503ULL,
		0xB3CA11776377743EULL,
		0x171E8FAB2A52736EULL,
		0xCEC69D53317010D8ULL,
		0x71EF569D958FEC40ULL,
		0xAF013EC6F83A5503ULL,
		0xE2D517ADF28530E9ULL,
		0x2615616E4EE9B7FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119BE2AA53D60A06ULL,
		0x679422EEC6EEE87CULL,
		0x2E3D1F5654A4E6DDULL,
		0x9D8D3AA662E021B0ULL,
		0xE3DEAD3B2B1FD881ULL,
		0x5E027D8DF074AA06ULL,
		0xC5AA2F5BE50A61D3ULL,
		0x4C2AC2DC9DD36FFFULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x647C30F9C6C4FCA7ULL,
		0xD212F042D931B20AULL,
		0x4FC59B410DD554E9ULL,
		0xCF85F2466C7A6DFEULL,
		0x2325B23E0AEFB67DULL,
		0x33E23FC218A27790ULL,
		0x45A8E06AC7D2E0FEULL,
		0x05993C740E41E630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F861F38D89F94EULL,
		0xA425E085B2636414ULL,
		0x9F8B36821BAAA9D3ULL,
		0x9F0BE48CD8F4DBFCULL,
		0x464B647C15DF6CFBULL,
		0x67C47F843144EF20ULL,
		0x8B51C0D58FA5C1FCULL,
		0x0B3278E81C83CC60ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FEE20AF3372654BULL,
		0x6DCA44634D150947ULL,
		0xE88BD749C7326D24ULL,
		0xA05814F68F0837F3ULL,
		0xF52A584C3A15B48EULL,
		0x0F8D55328BCC6D0DULL,
		0xAC48ED2BE91024C1ULL,
		0x212546E9451FA414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDC415E66E4CA96ULL,
		0xDB9488C69A2A128EULL,
		0xD117AE938E64DA48ULL,
		0x40B029ED1E106FE7ULL,
		0xEA54B098742B691DULL,
		0x1F1AAA651798DA1BULL,
		0x5891DA57D2204982ULL,
		0x424A8DD28A3F4829ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD1CBCAB3396A6B7ULL,
		0x4E8C33D8C9C40AD7ULL,
		0xA284A887E430C144ULL,
		0x094C2929B8413DC8ULL,
		0x78E63D32FE1642F2ULL,
		0xA99691D06E95ADC0ULL,
		0x9119E96419A2E6B5ULL,
		0x0B8DA8D8337C2B06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA397956672D4D6EULL,
		0x9D1867B1938815AFULL,
		0x4509510FC8618288ULL,
		0x1298525370827B91ULL,
		0xF1CC7A65FC2C85E4ULL,
		0x532D23A0DD2B5B80ULL,
		0x2233D2C83345CD6BULL,
		0x171B51B066F8560DULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E29372775C8DE44ULL,
		0x04A485830F12AFD5ULL,
		0x8676D2B410B732A3ULL,
		0x65D8D4EF9443E942ULL,
		0x1FFE534E3690F9F7ULL,
		0xE1C2F549CD0D1706ULL,
		0xB32D32263750A7CCULL,
		0x0D9A6C208B1C3193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C526E4EEB91BC88ULL,
		0x09490B061E255FAAULL,
		0x0CEDA568216E6546ULL,
		0xCBB1A9DF2887D285ULL,
		0x3FFCA69C6D21F3EEULL,
		0xC385EA939A1A2E0CULL,
		0x665A644C6EA14F99ULL,
		0x1B34D84116386327ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ABAF0DBC7D62A6FULL,
		0x95A9C1D8920BAAD1ULL,
		0x3D30DE145188560EULL,
		0x03052395C937A6EFULL,
		0x4C948BFF51C6E361ULL,
		0xFC250D7AE9C7E71BULL,
		0xC1F849EE1AF25269ULL,
		0x3F59EB66A0B51BF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3575E1B78FAC54DEULL,
		0x2B5383B1241755A3ULL,
		0x7A61BC28A310AC1DULL,
		0x060A472B926F4DDEULL,
		0x992917FEA38DC6C2ULL,
		0xF84A1AF5D38FCE36ULL,
		0x83F093DC35E4A4D3ULL,
		0x7EB3D6CD416A37EDULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE738B71ED55E0E2AULL,
		0xF1A47E0D049D4F4CULL,
		0x5260A4B836C1EBB7ULL,
		0xF37073397C781407ULL,
		0x8307496BCB033A7BULL,
		0x3B4C13F01A8F5F42ULL,
		0x0F847F9D5236B15FULL,
		0x069B526F78C8A81CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE716E3DAABC1C54ULL,
		0xE348FC1A093A9E99ULL,
		0xA4C149706D83D76FULL,
		0xE6E0E672F8F0280EULL,
		0x060E92D7960674F7ULL,
		0x769827E0351EBE85ULL,
		0x1F08FF3AA46D62BEULL,
		0x0D36A4DEF1915038ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF66A6141B84EA6D9ULL,
		0x71CBB75E2B9A963FULL,
		0x4EBB30C2DDB60FC0ULL,
		0x32B6F8EF88048A0DULL,
		0xD29542FF6DFBD1F0ULL,
		0x0E5EB7CDFBFA7E41ULL,
		0x412CADD177E635DAULL,
		0x332A78C48342090EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD4C283709D4DB2ULL,
		0xE3976EBC57352C7FULL,
		0x9D766185BB6C1F80ULL,
		0x656DF1DF1009141AULL,
		0xA52A85FEDBF7A3E0ULL,
		0x1CBD6F9BF7F4FC83ULL,
		0x82595BA2EFCC6BB4ULL,
		0x6654F1890684121CULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0676FB0C7A1E5B98ULL,
		0xF84B49976357C6AAULL,
		0x1FD3074F8738C9E2ULL,
		0xB1794B8C99EB6479ULL,
		0x852FA7AD208BCABCULL,
		0x35687146DF39FBA9ULL,
		0x62A6579EA43DB63FULL,
		0x15DFE6389B91F578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CEDF618F43CB730ULL,
		0xF096932EC6AF8D54ULL,
		0x3FA60E9F0E7193C5ULL,
		0x62F2971933D6C8F2ULL,
		0x0A5F4F5A41179579ULL,
		0x6AD0E28DBE73F753ULL,
		0xC54CAF3D487B6C7EULL,
		0x2BBFCC713723EAF0ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6A4309F7D64F320ULL,
		0xB6A7008654E523B4ULL,
		0x9EF5302661361B2CULL,
		0xCCEEEB4E6EBBF5ACULL,
		0x81E431A59DBD53D9ULL,
		0x803FA7C03A9D3F3BULL,
		0x0BA288D40D45908DULL,
		0x2C97790883C0DE46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D48613EFAC9E640ULL,
		0x6D4E010CA9CA4769ULL,
		0x3DEA604CC26C3659ULL,
		0x99DDD69CDD77EB59ULL,
		0x03C8634B3B7AA7B3ULL,
		0x007F4F80753A7E77ULL,
		0x174511A81A8B211BULL,
		0x592EF2110781BC8CULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2ECFA3F22B223C1ULL,
		0x3AF172E78790C2FEULL,
		0x4F2AE9C15542F579ULL,
		0xE76325AB4E8CAA7EULL,
		0x113163CF768888A2ULL,
		0x031CFE8604341EB6ULL,
		0x30BB9D93CD06F917ULL,
		0x1753DE4BD108766EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D9F47E45644782ULL,
		0x75E2E5CF0F2185FDULL,
		0x9E55D382AA85EAF2ULL,
		0xCEC64B569D1954FCULL,
		0x2262C79EED111145ULL,
		0x0639FD0C08683D6CULL,
		0x61773B279A0DF22EULL,
		0x2EA7BC97A210ECDCULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15228DA11AF1311FULL,
		0x7A5572548734D8B7ULL,
		0x51FD744ED1E09E3EULL,
		0xD019DE03D97C9583ULL,
		0x565DDB6B60CF070EULL,
		0xC52505968E5D7C89ULL,
		0xFFBD50C0B06E7861ULL,
		0x2FB17331F42C078DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A451B4235E2623EULL,
		0xF4AAE4A90E69B16EULL,
		0xA3FAE89DA3C13C7CULL,
		0xA033BC07B2F92B06ULL,
		0xACBBB6D6C19E0E1DULL,
		0x8A4A0B2D1CBAF912ULL,
		0xFF7AA18160DCF0C3ULL,
		0x5F62E663E8580F1BULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D6F6F892842C66EULL,
		0x8B1EE180B3FEC1BEULL,
		0xE2EC7721AC0812B3ULL,
		0xD17AC7EFB7E6F246ULL,
		0xD87D9033A480A9FBULL,
		0x94DA50ECAC9EC4ECULL,
		0xE1DDEC0D3D2D5813ULL,
		0x318FE16A38037208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADEDF1250858CDCULL,
		0x163DC30167FD837CULL,
		0xC5D8EE4358102567ULL,
		0xA2F58FDF6FCDE48DULL,
		0xB0FB2067490153F7ULL,
		0x29B4A1D9593D89D9ULL,
		0xC3BBD81A7A5AB027ULL,
		0x631FC2D47006E411ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B70EAC457521A23ULL,
		0x75361C99DEB7AF77ULL,
		0x913374CE662E2305ULL,
		0xB233F7BB09E5BDE0ULL,
		0x41BE1836DBDE03FEULL,
		0x177D171087FDEDECULL,
		0x31EB5BD3D7387987ULL,
		0x05D4C432D3ED4C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E1D588AEA43446ULL,
		0xEA6C3933BD6F5EEFULL,
		0x2266E99CCC5C460AULL,
		0x6467EF7613CB7BC1ULL,
		0x837C306DB7BC07FDULL,
		0x2EFA2E210FFBDBD8ULL,
		0x63D6B7A7AE70F30EULL,
		0x0BA98865A7DA986AULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x615482F2E78CF29FULL,
		0x56C02499ACD4B4EEULL,
		0x400D7CD4CF03158DULL,
		0xEBD611942E026194ULL,
		0xA0A1C6E9DC2B4E4DULL,
		0x57E5C29235D3C36AULL,
		0x6D5BE751A0EEB275ULL,
		0x11E7B141E682C061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A905E5CF19E53EULL,
		0xAD80493359A969DCULL,
		0x801AF9A99E062B1AULL,
		0xD7AC23285C04C328ULL,
		0x41438DD3B8569C9BULL,
		0xAFCB85246BA786D5ULL,
		0xDAB7CEA341DD64EAULL,
		0x23CF6283CD0580C2ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37258271E575009EULL,
		0xCD44BBBDF935A7AEULL,
		0x64DAA95B0BBBBAD0ULL,
		0x8903D2AA27967CAAULL,
		0x9EC3F06BB1B1D9E4ULL,
		0x5AF8D5E7007C7559ULL,
		0x2E5ABC09A3D06DF7ULL,
		0x1261CFE07B2F5E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4B04E3CAEA013CULL,
		0x9A89777BF26B4F5CULL,
		0xC9B552B6177775A1ULL,
		0x1207A5544F2CF954ULL,
		0x3D87E0D76363B3C9ULL,
		0xB5F1ABCE00F8EAB3ULL,
		0x5CB5781347A0DBEEULL,
		0x24C39FC0F65EBCBCULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x827F748D767E5286ULL,
		0x45F2D96F50463A6FULL,
		0xE04EBF1D96CB282FULL,
		0x756A94D211B23403ULL,
		0xB90DE77B39FC0C53ULL,
		0x5B1144654012A18DULL,
		0xD4D67B052362A8E7ULL,
		0x1608BD2AD516B2BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FEE91AECFCA50CULL,
		0x8BE5B2DEA08C74DFULL,
		0xC09D7E3B2D96505EULL,
		0xEAD529A423646807ULL,
		0x721BCEF673F818A6ULL,
		0xB62288CA8025431BULL,
		0xA9ACF60A46C551CEULL,
		0x2C117A55AA2D6579ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFFD35CB31E6E2BAULL,
		0x371F721DC04A6D14ULL,
		0xF0A54E15790F1147ULL,
		0x3028AB0970D2E4D4ULL,
		0x8509044470CF57AEULL,
		0x7C9B4AB4E7620B4BULL,
		0x8DC0A475E40DFBE8ULL,
		0x200FB24012D3D33EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFA6B9663CDC574ULL,
		0x6E3EE43B8094DA29ULL,
		0xE14A9C2AF21E228EULL,
		0x60515612E1A5C9A9ULL,
		0x0A120888E19EAF5CULL,
		0xF9369569CEC41697ULL,
		0x1B8148EBC81BF7D0ULL,
		0x401F648025A7A67DULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13BB4A1820A211ACULL,
		0x6618B04C25C057BDULL,
		0x06216224C689AA18ULL,
		0xD1BC4CDF4B554F38ULL,
		0x8C4B16243708B3F7ULL,
		0x6918C22C58E5C1F5ULL,
		0x059EDEDF12B68BC8ULL,
		0x3788E65AED5CA11EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2776943041442358ULL,
		0xCC3160984B80AF7AULL,
		0x0C42C4498D135430ULL,
		0xA37899BE96AA9E70ULL,
		0x18962C486E1167EFULL,
		0xD2318458B1CB83EBULL,
		0x0B3DBDBE256D1790ULL,
		0x6F11CCB5DAB9423CULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB2861FFF1772EE1ULL,
		0xC1DA34625F9C6160ULL,
		0x2311D15C7B9A48DEULL,
		0xAED0FD6F99DD984AULL,
		0x9594ED22BF1B1B9EULL,
		0xFDE75BEF437E1A64ULL,
		0x1A9095DBCE54AE06ULL,
		0x28B87382CE381B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7650C3FFE2EE5DC2ULL,
		0x83B468C4BF38C2C1ULL,
		0x4623A2B8F73491BDULL,
		0x5DA1FADF33BB3094ULL,
		0x2B29DA457E36373DULL,
		0xFBCEB7DE86FC34C9ULL,
		0x35212BB79CA95C0DULL,
		0x5170E7059C7036DAULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85EB1FD0AAC44FE3ULL,
		0xC5F719A57F1394A2ULL,
		0x91B2D52DE758D3FDULL,
		0x66146FDC12D3E3D8ULL,
		0xBC91C550FF0FA293ULL,
		0x33F59451A37A2E63ULL,
		0x0B8779A3D5A12348ULL,
		0x3C75DC2DAF92201CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD63FA155889FC6ULL,
		0x8BEE334AFE272945ULL,
		0x2365AA5BCEB1A7FBULL,
		0xCC28DFB825A7C7B1ULL,
		0x79238AA1FE1F4526ULL,
		0x67EB28A346F45CC7ULL,
		0x170EF347AB424690ULL,
		0x78EBB85B5F244038ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EAF21163CCC93ABULL,
		0x6054C8F634647FF0ULL,
		0x2B60121BDA787573ULL,
		0x32BBF791C62D35FBULL,
		0x97AC4359B3668AE8ULL,
		0xBC8FFFA3A3E4490DULL,
		0x6C858C29B2CEB27BULL,
		0x227EDFC626CA2AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5E422C79992756ULL,
		0xC0A991EC68C8FFE0ULL,
		0x56C02437B4F0EAE6ULL,
		0x6577EF238C5A6BF6ULL,
		0x2F5886B366CD15D0ULL,
		0x791FFF4747C8921BULL,
		0xD90B1853659D64F7ULL,
		0x44FDBF8C4D9455C0ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8882952121D1AF03ULL,
		0xDFB73ABB7DA2E943ULL,
		0x4E7247B62873C36EULL,
		0xEADCDEA2F399AF9AULL,
		0xE43AD39AE47D2A74ULL,
		0x1762D188F041F199ULL,
		0x69537CE2104D7088ULL,
		0x3EF2C0F3EF5AD0D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11052A4243A35E06ULL,
		0xBF6E7576FB45D287ULL,
		0x9CE48F6C50E786DDULL,
		0xD5B9BD45E7335F34ULL,
		0xC875A735C8FA54E9ULL,
		0x2EC5A311E083E333ULL,
		0xD2A6F9C4209AE110ULL,
		0x7DE581E7DEB5A1ACULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B1B0B97B787FD25ULL,
		0x69DB9CB5660F2AB7ULL,
		0x3B76B6E9BF064178ULL,
		0xC7DB0C47ACCE6B5EULL,
		0xC8FF312E16C89AD1ULL,
		0x2A1336118C1BEA30ULL,
		0x93EA4A6ECAC504B7ULL,
		0x3BFC8F7FC6449E99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7636172F6F0FFA4AULL,
		0xD3B7396ACC1E556EULL,
		0x76ED6DD37E0C82F0ULL,
		0x8FB6188F599CD6BCULL,
		0x91FE625C2D9135A3ULL,
		0x54266C231837D461ULL,
		0x27D494DD958A096EULL,
		0x77F91EFF8C893D33ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4E7C6C131F50372ULL,
		0xE40EE8C63D8D0484ULL,
		0x5630C87E4A1245E1ULL,
		0x16CBCEB3092FA209ULL,
		0xBA7D870802DDBFDBULL,
		0x14B70C4A5FF12850ULL,
		0x2BF893377EC4C94CULL,
		0x351E34BF583C39F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CF8D8263EA06E4ULL,
		0xC81DD18C7B1A0909ULL,
		0xAC6190FC94248BC3ULL,
		0x2D979D66125F4412ULL,
		0x74FB0E1005BB7FB6ULL,
		0x296E1894BFE250A1ULL,
		0x57F1266EFD899298ULL,
		0x6A3C697EB07873EEULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3F62E14C9E3339AULL,
		0x1F28084793419C3BULL,
		0xE80D8B41D33987A8ULL,
		0x66B70C1C8440E3A6ULL,
		0xC4584C6FF30EFE70ULL,
		0x7268DAD81FC047ABULL,
		0x049FAC19FBC53C8BULL,
		0x355C235D2370F7C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7EC5C2993C66734ULL,
		0x3E50108F26833877ULL,
		0xD01B1683A6730F50ULL,
		0xCD6E18390881C74DULL,
		0x88B098DFE61DFCE0ULL,
		0xE4D1B5B03F808F57ULL,
		0x093F5833F78A7916ULL,
		0x6AB846BA46E1EF84ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32EFA47D047106ADULL,
		0xE7FE48D30851DF8AULL,
		0x8496286F4A7D00B8ULL,
		0x595881008DA3B485ULL,
		0x23678C8C761D1777ULL,
		0xFD71C965204C08A9ULL,
		0xF7D861092889D581ULL,
		0x1234561454A119ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65DF48FA08E20D5AULL,
		0xCFFC91A610A3BF14ULL,
		0x092C50DE94FA0171ULL,
		0xB2B102011B47690BULL,
		0x46CF1918EC3A2EEEULL,
		0xFAE392CA40981152ULL,
		0xEFB0C2125113AB03ULL,
		0x2468AC28A942335BULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x197B7587DD09AC36ULL,
		0x1C40C8544ED8D86EULL,
		0x38BB02CF28E4EDF6ULL,
		0xFF5C985603C1E9CFULL,
		0xD8EB15F3CC1FE91DULL,
		0x786792673C7255A8ULL,
		0x73243A6520C18295ULL,
		0x2A24BE4D137F2B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32F6EB0FBA13586CULL,
		0x388190A89DB1B0DCULL,
		0x7176059E51C9DBECULL,
		0xFEB930AC0783D39EULL,
		0xB1D62BE7983FD23BULL,
		0xF0CF24CE78E4AB51ULL,
		0xE64874CA4183052AULL,
		0x54497C9A26FE56D8ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18AF59968859B84EULL,
		0x5A812BC3E2D3A4DAULL,
		0x8CCEB811933F6D9EULL,
		0x00C8D62679862929ULL,
		0xF52803FB6C8241BDULL,
		0x5D9FAB9EA95AF7AEULL,
		0x41C6E4418BA5F3F9ULL,
		0x0F1F76C2BBF4F06DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x315EB32D10B3709CULL,
		0xB5025787C5A749B4ULL,
		0x199D7023267EDB3CULL,
		0x0191AC4CF30C5253ULL,
		0xEA5007F6D904837AULL,
		0xBB3F573D52B5EF5DULL,
		0x838DC883174BE7F2ULL,
		0x1E3EED8577E9E0DAULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD00A1E7586C906ADULL,
		0x58D6378DE088FCAFULL,
		0xCEC9052289C29BC3ULL,
		0x3096D1EBEDB6A948ULL,
		0x5B16BE0CA96C88F9ULL,
		0xA2534C2BA262A31CULL,
		0xC225F6DE7B80CF43ULL,
		0x3CEEB593FF9B2C48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0143CEB0D920D5AULL,
		0xB1AC6F1BC111F95FULL,
		0x9D920A4513853786ULL,
		0x612DA3D7DB6D5291ULL,
		0xB62D7C1952D911F2ULL,
		0x44A6985744C54638ULL,
		0x844BEDBCF7019E87ULL,
		0x79DD6B27FF365891ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5391356EA74E7E5ULL,
		0x7114BF6464B21641ULL,
		0xAC2B42B5210A8C48ULL,
		0x3C7674363715729BULL,
		0xC2BF3E0CF1E2925BULL,
		0xB885FF7ED04AEDE9ULL,
		0x43B5927AA5A23C14ULL,
		0x2BDC8219A85769D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A7226ADD4E9CFCAULL,
		0xE2297EC8C9642C83ULL,
		0x5856856A42151890ULL,
		0x78ECE86C6E2AE537ULL,
		0x857E7C19E3C524B6ULL,
		0x710BFEFDA095DBD3ULL,
		0x876B24F54B447829ULL,
		0x57B9043350AED3AEULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B1634179E0BE126ULL,
		0xE2AE85D433E8D871ULL,
		0xD7D57B77EB68FC1FULL,
		0xB3451E8ACF4586B3ULL,
		0x649AFC2AFB4C9415ULL,
		0x7FF429071B2AB189ULL,
		0x10F47038FAE60DF8ULL,
		0x14E13934DE984CDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD62C682F3C17C24CULL,
		0xC55D0BA867D1B0E2ULL,
		0xAFAAF6EFD6D1F83FULL,
		0x668A3D159E8B0D67ULL,
		0xC935F855F699282BULL,
		0xFFE8520E36556312ULL,
		0x21E8E071F5CC1BF0ULL,
		0x29C27269BD3099B4ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD757158314E0B46FULL,
		0x881BA4A3E60E6183ULL,
		0x50634B4B969D83B1ULL,
		0x5D02ACCC8709180AULL,
		0x1DC352D66872710DULL,
		0xD74AF090EBB0F9F8ULL,
		0x5EA755A09529FB49ULL,
		0x0067A0F85321ACD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEAE2B0629C168DEULL,
		0x10374947CC1CC307ULL,
		0xA0C696972D3B0763ULL,
		0xBA0559990E123014ULL,
		0x3B86A5ACD0E4E21AULL,
		0xAE95E121D761F3F0ULL,
		0xBD4EAB412A53F693ULL,
		0x00CF41F0A64359A2ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA202603485554C39ULL,
		0x14563DA6D8A2DB39ULL,
		0x7A51E7E81C5E2F80ULL,
		0x65F85E6C5F4D51C5ULL,
		0xCD7B5954D43B90C9ULL,
		0xDA30D594BCFC1EACULL,
		0x99E2CF972615EC78ULL,
		0x0C7CBD5F63D5F03BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4404C0690AAA9872ULL,
		0x28AC7B4DB145B673ULL,
		0xF4A3CFD038BC5F00ULL,
		0xCBF0BCD8BE9AA38AULL,
		0x9AF6B2A9A8772192ULL,
		0xB461AB2979F83D59ULL,
		0x33C59F2E4C2BD8F1ULL,
		0x18F97ABEC7ABE077ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3952BAB5940B3070ULL,
		0x1B741A410C136CC4ULL,
		0xB09DFB9C0CD51D4AULL,
		0xC7652F9BEDEE35BBULL,
		0xDA975380B563BE86ULL,
		0x6DC750D799370E48ULL,
		0x85D5F0A393B9F397ULL,
		0x1200B2A6E4EA2D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A5756B281660E0ULL,
		0x36E834821826D988ULL,
		0x613BF73819AA3A94ULL,
		0x8ECA5F37DBDC6B77ULL,
		0xB52EA7016AC77D0DULL,
		0xDB8EA1AF326E1C91ULL,
		0x0BABE1472773E72EULL,
		0x2401654DC9D45A07ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3FFA2C5ABBD086BULL,
		0x04D11764BFE95D13ULL,
		0x361311C7B142050FULL,
		0x0AAC43E3AE38A151ULL,
		0x44DAA8344F92349EULL,
		0x31BBA9ADA897CAA8ULL,
		0x364ABC024D788221ULL,
		0x139FCD3AE26CBEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FF458B577A10D6ULL,
		0x09A22EC97FD2BA27ULL,
		0x6C26238F62840A1EULL,
		0x155887C75C7142A2ULL,
		0x89B550689F24693CULL,
		0x6377535B512F9550ULL,
		0x6C9578049AF10442ULL,
		0x273F9A75C4D97DB8ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8554E72CE2FBE48FULL,
		0x9409DBF9845F3F7BULL,
		0xBA9F0E17CBAD03BCULL,
		0x0C97BE5C496F644CULL,
		0x4540F41E984A9D1DULL,
		0xC697CBF4842FE842ULL,
		0x2435E855FE5B376BULL,
		0x3142AE10C4A8541FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA9CE59C5F7C91EULL,
		0x2813B7F308BE7EF7ULL,
		0x753E1C2F975A0779ULL,
		0x192F7CB892DEC899ULL,
		0x8A81E83D30953A3AULL,
		0x8D2F97E9085FD084ULL,
		0x486BD0ABFCB66ED7ULL,
		0x62855C218950A83EULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98E11F49F7160126ULL,
		0x36ACBB637CE0E0F9ULL,
		0x29C85644E29AD601ULL,
		0xABBEE4107F78740EULL,
		0x837B8151CCB52771ULL,
		0x860855AEED543FC9ULL,
		0x543A24712977E6C5ULL,
		0x0BF420B9EC4032E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C23E93EE2C024CULL,
		0x6D5976C6F9C1C1F3ULL,
		0x5390AC89C535AC02ULL,
		0x577DC820FEF0E81CULL,
		0x06F702A3996A4EE3ULL,
		0x0C10AB5DDAA87F93ULL,
		0xA87448E252EFCD8BULL,
		0x17E84173D88065C8ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF49B2648CFE82CDULL,
		0x0B8BAE129B7D7410ULL,
		0xFCA42FDB37F88460ULL,
		0x30BF0BEF83A390F7ULL,
		0x24377FF47F1E82CDULL,
		0x6FDA0E0DA7611238ULL,
		0xF8666F573FCA12C3ULL,
		0x3A8C30B1BC7508C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9364C919FD059AULL,
		0x17175C2536FAE821ULL,
		0xF9485FB66FF108C0ULL,
		0x617E17DF074721EFULL,
		0x486EFFE8FE3D059AULL,
		0xDFB41C1B4EC22470ULL,
		0xF0CCDEAE7F942586ULL,
		0x7518616378EA1187ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF7DBE963278E02DULL,
		0x10BB90F8A03E906FULL,
		0x765D5F77CF45A847ULL,
		0x69142572440EA436ULL,
		0xC6DEA7C77686E559ULL,
		0x7DD99EA89376FA6FULL,
		0xAE8588988A348C78ULL,
		0x1EB40FF1905B5A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEFB7D2C64F1C05AULL,
		0x217721F1407D20DFULL,
		0xECBABEEF9E8B508EULL,
		0xD2284AE4881D486CULL,
		0x8DBD4F8EED0DCAB2ULL,
		0xFBB33D5126EDF4DFULL,
		0x5D0B1131146918F0ULL,
		0x3D681FE320B6B505ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03812C5D68450F15ULL,
		0x36B6C4D20E273D0AULL,
		0x28C4D4DF2F8C9E34ULL,
		0x0ADBFB72A76DF1E4ULL,
		0xD4C1234879D402CDULL,
		0xC893C598C1F2277EULL,
		0x19649C33798BA2B7ULL,
		0x23B1E346B0639045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x070258BAD08A1E2AULL,
		0x6D6D89A41C4E7A14ULL,
		0x5189A9BE5F193C68ULL,
		0x15B7F6E54EDBE3C8ULL,
		0xA9824690F3A8059AULL,
		0x91278B3183E44EFDULL,
		0x32C93866F317456FULL,
		0x4763C68D60C7208AULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF666F09CA8397FULL,
		0x3232818CE325EC2FULL,
		0xF7D7053C19D4FBD9ULL,
		0xBA9C34AD71C9200FULL,
		0x47D777FCB8F751DFULL,
		0x512B151BB7A63540ULL,
		0x879E007349EB7EEFULL,
		0x215CCFC66017293BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95ECCDE1395072FEULL,
		0x64650319C64BD85FULL,
		0xEFAE0A7833A9F7B2ULL,
		0x7538695AE392401FULL,
		0x8FAEEFF971EEA3BFULL,
		0xA2562A376F4C6A80ULL,
		0x0F3C00E693D6FDDEULL,
		0x42B99F8CC02E5277ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4179DF774B24D9DAULL,
		0x52E4378CB3170661ULL,
		0x93CF45714A84048FULL,
		0x9EF32D962D617F06ULL,
		0x716A1C294C6DF97CULL,
		0x23CE3740941B36C1ULL,
		0x2A574588B6416879ULL,
		0x3B6AC4CA23982C60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82F3BEEE9649B3B4ULL,
		0xA5C86F19662E0CC2ULL,
		0x279E8AE29508091EULL,
		0x3DE65B2C5AC2FE0DULL,
		0xE2D4385298DBF2F9ULL,
		0x479C6E8128366D82ULL,
		0x54AE8B116C82D0F2ULL,
		0x76D58994473058C0ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37C3A128DDF3505AULL,
		0xAAFC622E56E87E30ULL,
		0xE15F0E73FB910547ULL,
		0x38792C0D9A2C25BFULL,
		0x76BEF9A1AA15EF44ULL,
		0x6CE2E896DE4E35C8ULL,
		0xC8E1E516673CF279ULL,
		0x30C09759C701CF72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F874251BBE6A0B4ULL,
		0x55F8C45CADD0FC60ULL,
		0xC2BE1CE7F7220A8FULL,
		0x70F2581B34584B7FULL,
		0xED7DF343542BDE88ULL,
		0xD9C5D12DBC9C6B90ULL,
		0x91C3CA2CCE79E4F2ULL,
		0x61812EB38E039EE5ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F68EF9D2D4A4E36ULL,
		0x1FA1E2A6CDBDD25FULL,
		0xAF66132CC2953611ULL,
		0xDACA5879139B636DULL,
		0x6E04D2EAD73F249DULL,
		0x5EB153ECBFA72472ULL,
		0xB47439CB27FA8ADCULL,
		0x010168720DA62B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7ED1DF3A5A949C6CULL,
		0x3F43C54D9B7BA4BEULL,
		0x5ECC2659852A6C22ULL,
		0xB594B0F22736C6DBULL,
		0xDC09A5D5AE7E493BULL,
		0xBD62A7D97F4E48E4ULL,
		0x68E873964FF515B8ULL,
		0x0202D0E41B4C56ADULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3353D0E3293FFBB0ULL,
		0x490A062508B119A7ULL,
		0xC75D51D96491B2AFULL,
		0x64988237202DCBC6ULL,
		0x52278012B9BCBCB8ULL,
		0xDF1C6E21622E99C8ULL,
		0xC6B001314ED800CDULL,
		0x35E329C36C1E36E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A7A1C6527FF760ULL,
		0x92140C4A1162334EULL,
		0x8EBAA3B2C923655EULL,
		0xC931046E405B978DULL,
		0xA44F002573797970ULL,
		0xBE38DC42C45D3390ULL,
		0x8D6002629DB0019BULL,
		0x6BC65386D83C6DCFULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF44DFC8B13762E5ULL,
		0x9D0F564B13C26855ULL,
		0x95B0FD231583ED80ULL,
		0x4C34A49506B0EDA8ULL,
		0x979EE4F96975EAA3ULL,
		0xF7C4BF78325E2CFFULL,
		0xF2714BAE82034F6BULL,
		0x199D1566A46A08C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E89BF91626EC5CAULL,
		0x3A1EAC962784D0ABULL,
		0x2B61FA462B07DB01ULL,
		0x9869492A0D61DB51ULL,
		0x2F3DC9F2D2EBD546ULL,
		0xEF897EF064BC59FFULL,
		0xE4E2975D04069ED7ULL,
		0x333A2ACD48D4118BULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7F28A5345022A41ULL,
		0x2465CC2A7B95B2AAULL,
		0x56977975569804C6ULL,
		0xB34915C3B88ED1F9ULL,
		0xADB2B2895B80C026ULL,
		0xD89CC53175536148ULL,
		0x6EA673BD88EF026AULL,
		0x19C598C33CA792A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFE514A68A045482ULL,
		0x48CB9854F72B6555ULL,
		0xAD2EF2EAAD30098CULL,
		0x66922B87711DA3F2ULL,
		0x5B656512B701804DULL,
		0xB1398A62EAA6C291ULL,
		0xDD4CE77B11DE04D5ULL,
		0x338B3186794F254CULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF91199C516687827ULL,
		0xF19F85AC01720609ULL,
		0x5E235A80E8DB9493ULL,
		0xF5F961938F33BB63ULL,
		0x30022A471C52AD41ULL,
		0x1FDC28C739B38209ULL,
		0xF90F91D4A576D12FULL,
		0x191EE8A4D8316138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF223338A2CD0F04EULL,
		0xE33F0B5802E40C13ULL,
		0xBC46B501D1B72927ULL,
		0xEBF2C3271E6776C6ULL,
		0x6004548E38A55A83ULL,
		0x3FB8518E73670412ULL,
		0xF21F23A94AEDA25EULL,
		0x323DD149B062C271ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C5E2623C5A2A8FCULL,
		0x4ABC687FABA3ADD6ULL,
		0x1537AB43F888F1DDULL,
		0xAA2609565229656AULL,
		0xA5D335FFD2FBDBFCULL,
		0x8979A0C65F0019E8ULL,
		0x510ADCD9690226DCULL,
		0x25BDECA6DC8B38DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38BC4C478B4551F8ULL,
		0x9578D0FF57475BACULL,
		0x2A6F5687F111E3BAULL,
		0x544C12ACA452CAD4ULL,
		0x4BA66BFFA5F7B7F9ULL,
		0x12F3418CBE0033D1ULL,
		0xA215B9B2D2044DB9ULL,
		0x4B7BD94DB91671BEULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA81F59345CCE2FDEULL,
		0x1F689F482767888DULL,
		0x08FC38BDE2A66288ULL,
		0xF0CA3AF2672E3372ULL,
		0xE91EA65FB429028DULL,
		0x723E44747E682D4CULL,
		0x6642EC1A83DD1BEEULL,
		0x19A35AB8F8D0489FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x503EB268B99C5FBCULL,
		0x3ED13E904ECF111BULL,
		0x11F8717BC54CC510ULL,
		0xE19475E4CE5C66E4ULL,
		0xD23D4CBF6852051BULL,
		0xE47C88E8FCD05A99ULL,
		0xCC85D83507BA37DCULL,
		0x3346B571F1A0913EULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC16A86C688F394C4ULL,
		0x62ABA198C5F37D56ULL,
		0x54CCC8ED226EA7EEULL,
		0xEF9681EF1812501DULL,
		0xB072B5A0E3406BB9ULL,
		0x2C3FE0FFD637B51FULL,
		0x11506B85C176B226ULL,
		0x0BCE6F5B147957A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82D50D8D11E72988ULL,
		0xC55743318BE6FAADULL,
		0xA99991DA44DD4FDCULL,
		0xDF2D03DE3024A03AULL,
		0x60E56B41C680D773ULL,
		0x587FC1FFAC6F6A3FULL,
		0x22A0D70B82ED644CULL,
		0x179CDEB628F2AF50ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EC5D6A8D3B4659EULL,
		0x661284B190690DA8ULL,
		0x7289D5E1DFAFF3D5ULL,
		0xE28FCBF9A57505F6ULL,
		0x3AA4A93611E524E7ULL,
		0x4E8098CEC9FF7851ULL,
		0x216B6B14B5E56D5DULL,
		0x336B30EB15A6FFDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8BAD51A768CB3CULL,
		0xCC25096320D21B51ULL,
		0xE513ABC3BF5FE7AAULL,
		0xC51F97F34AEA0BECULL,
		0x7549526C23CA49CFULL,
		0x9D01319D93FEF0A2ULL,
		0x42D6D6296BCADABAULL,
		0x66D661D62B4DFFBAULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47512D27488707FCULL,
		0xAAF7B1217C48978EULL,
		0xD63F68AC6193EFCFULL,
		0x909B72D3A955063AULL,
		0xDC1060BE5D8867EBULL,
		0x3B1AAA996E86B7E3ULL,
		0x7D3A3815C70FAD39ULL,
		0x37BB155BD186C78FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EA25A4E910E0FF8ULL,
		0x55EF6242F8912F1CULL,
		0xAC7ED158C327DF9FULL,
		0x2136E5A752AA0C75ULL,
		0xB820C17CBB10CFD7ULL,
		0x76355532DD0D6FC7ULL,
		0xFA74702B8E1F5A72ULL,
		0x6F762AB7A30D8F1EULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E142469800128E5ULL,
		0x1BE817286DF69233ULL,
		0xD5BA95C32655445EULL,
		0x26C3D3EA4D60CF9BULL,
		0x7C95797064EEADB1ULL,
		0x0C745DE4CE83DF88ULL,
		0x79D8AC7E12BED991ULL,
		0x166B4F0E9EA23E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC2848D3000251CAULL,
		0x37D02E50DBED2466ULL,
		0xAB752B864CAA88BCULL,
		0x4D87A7D49AC19F37ULL,
		0xF92AF2E0C9DD5B62ULL,
		0x18E8BBC99D07BF10ULL,
		0xF3B158FC257DB322ULL,
		0x2CD69E1D3D447CCAULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D8FA5812110E9EEULL,
		0xF76AE00195471E79ULL,
		0x14BA2576B6A7AEAAULL,
		0x6BB43A1E108A78AFULL,
		0xAA480E6B22F04DA0ULL,
		0x74BB1F131324BFD3ULL,
		0xE5A13E7D292A475BULL,
		0x11728691F3E24438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1F4B024221D3DCULL,
		0xEED5C0032A8E3CF2ULL,
		0x29744AED6D4F5D55ULL,
		0xD768743C2114F15EULL,
		0x54901CD645E09B40ULL,
		0xE9763E2626497FA7ULL,
		0xCB427CFA52548EB6ULL,
		0x22E50D23E7C48871ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1E17645C9F248BBULL,
		0x6FBFC337391ADB6EULL,
		0xE46B8287E33E43F8ULL,
		0x475CE7775E1FD2BAULL,
		0xE8AB86B4FB028C41ULL,
		0x36331E5E3CCD1E19ULL,
		0x6ABA822C03B3225DULL,
		0x346AC710587A3C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C2EC8B93E49176ULL,
		0xDF7F866E7235B6DDULL,
		0xC8D7050FC67C87F0ULL,
		0x8EB9CEEEBC3FA575ULL,
		0xD1570D69F6051882ULL,
		0x6C663CBC799A3C33ULL,
		0xD5750458076644BAULL,
		0x68D58E20B0F478D6ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B4B00726865CFFFULL,
		0x0EE9C5C128F5061AULL,
		0xCE71AFA0E56D981CULL,
		0x692253B1CA046A48ULL,
		0xC857ABC7A1281C3CULL,
		0xCDFDC84CAC10A8EBULL,
		0x4F45B9A711F7E3AFULL,
		0x064C9269D06128C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD69600E4D0CB9FFEULL,
		0x1DD38B8251EA0C34ULL,
		0x9CE35F41CADB3038ULL,
		0xD244A7639408D491ULL,
		0x90AF578F42503878ULL,
		0x9BFB9099582151D7ULL,
		0x9E8B734E23EFC75FULL,
		0x0C9924D3A0C2518CULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65BEDD5E62728568ULL,
		0x811B423EC9F58D99ULL,
		0x66F3DF9B8AEE4A30ULL,
		0x1E948F3DAB02656AULL,
		0x75C2736639C76367ULL,
		0x90533F4F7FD4E6F5ULL,
		0xF74EEFB0F6A615F4ULL,
		0x2BD4C6E553CD8FEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7DBABCC4E50AD0ULL,
		0x0236847D93EB1B32ULL,
		0xCDE7BF3715DC9461ULL,
		0x3D291E7B5604CAD4ULL,
		0xEB84E6CC738EC6CEULL,
		0x20A67E9EFFA9CDEAULL,
		0xEE9DDF61ED4C2BE9ULL,
		0x57A98DCAA79B1FD7ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x635B799346EC67F1ULL,
		0x6C66627A5FDFC219ULL,
		0xDCFE534B37B50C73ULL,
		0x0B2FE6A19093EA66ULL,
		0xCCAA2BB0F2BD61D2ULL,
		0x1364151E86E68AB7ULL,
		0x4951EAEBDBA99A19ULL,
		0x0B4FE9CC41C20ABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B6F3268DD8CFE2ULL,
		0xD8CCC4F4BFBF8432ULL,
		0xB9FCA6966F6A18E6ULL,
		0x165FCD432127D4CDULL,
		0x99545761E57AC3A4ULL,
		0x26C82A3D0DCD156FULL,
		0x92A3D5D7B7533432ULL,
		0x169FD3988384157EULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x988BFFBF974A8B51ULL,
		0x5BA5F5BE4069270FULL,
		0x3BD8FC6B7196F4DDULL,
		0x918CB3DB78BDFF78ULL,
		0x626FB9656B95083AULL,
		0x47174B162D64A1C8ULL,
		0xEF608BD007F44B67ULL,
		0x28A7BA4DE625B9BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3117FF7F2E9516A2ULL,
		0xB74BEB7C80D24E1FULL,
		0x77B1F8D6E32DE9BAULL,
		0x231967B6F17BFEF0ULL,
		0xC4DF72CAD72A1075ULL,
		0x8E2E962C5AC94390ULL,
		0xDEC117A00FE896CEULL,
		0x514F749BCC4B7377ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39C4A9322617903EULL,
		0xF8C5BD099DFF6D18ULL,
		0x6F7C232E8F846B92ULL,
		0x1EFEE7AADC2EA572ULL,
		0x70BC4571290D36D9ULL,
		0x7345A1D3CEDBA1C6ULL,
		0x2D4C42CF05F60643ULL,
		0x398E857D6379CD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738952644C2F207CULL,
		0xF18B7A133BFEDA30ULL,
		0xDEF8465D1F08D725ULL,
		0x3DFDCF55B85D4AE4ULL,
		0xE1788AE2521A6DB2ULL,
		0xE68B43A79DB7438CULL,
		0x5A98859E0BEC0C86ULL,
		0x731D0AFAC6F39ABEULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA625609C252842FFULL,
		0x7AC28D58E7AC45CBULL,
		0x5B9409C67E0DE918ULL,
		0x265245097BD475A6ULL,
		0x005EE4EACFC09B30ULL,
		0x58E6F3A643C0025EULL,
		0x67B3820DDAC7D7F5ULL,
		0x0C9231FBB8B5225DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4AC1384A5085FEULL,
		0xF5851AB1CF588B97ULL,
		0xB728138CFC1BD230ULL,
		0x4CA48A12F7A8EB4CULL,
		0x00BDC9D59F813660ULL,
		0xB1CDE74C878004BCULL,
		0xCF67041BB58FAFEAULL,
		0x192463F7716A44BAULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4036F4E25F02317ULL,
		0x62BD06807BE59CD4ULL,
		0x68D45DAA5C08244FULL,
		0x4ECD5AFA9CEC0D62ULL,
		0x2B7558A220463714ULL,
		0xC9137E71CAA6EC05ULL,
		0x842044DC1C250726ULL,
		0x28C0FB0B53059D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8806DE9C4BE0462EULL,
		0xC57A0D00F7CB39A9ULL,
		0xD1A8BB54B810489EULL,
		0x9D9AB5F539D81AC4ULL,
		0x56EAB144408C6E28ULL,
		0x9226FCE3954DD80AULL,
		0x084089B8384A0E4DULL,
		0x5181F616A60B3A51ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1569CE129AC62A57ULL,
		0x533BAC1095D7219DULL,
		0xB50AE0CDB979D54CULL,
		0xDCF500859F9F79EDULL,
		0xA38A16B67441B027ULL,
		0xEF105CB77D19BF6EULL,
		0x87AF2932FE21EDC6ULL,
		0x26D581C7FE23C66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AD39C25358C54AEULL,
		0xA67758212BAE433AULL,
		0x6A15C19B72F3AA98ULL,
		0xB9EA010B3F3EF3DBULL,
		0x47142D6CE883604FULL,
		0xDE20B96EFA337EDDULL,
		0x0F5E5265FC43DB8DULL,
		0x4DAB038FFC478CDDULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x362025254771D4FCULL,
		0xFE94298E057CD6C2ULL,
		0x3EA3D134D07C03EFULL,
		0x835E36DA8EFD51EFULL,
		0x0E4079541ECA2D06ULL,
		0xEEC11A811E026AD6ULL,
		0x17DBD72F13E1AEFBULL,
		0x2F10BA263D8BAD28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C404A4A8EE3A9F8ULL,
		0xFD28531C0AF9AD84ULL,
		0x7D47A269A0F807DFULL,
		0x06BC6DB51DFAA3DEULL,
		0x1C80F2A83D945A0DULL,
		0xDD8235023C04D5ACULL,
		0x2FB7AE5E27C35DF7ULL,
		0x5E21744C7B175A50ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x718C8A7054CE4207ULL,
		0x0908A45F4C229309ULL,
		0x0779647A21ADB20BULL,
		0x90C9DCC8CC2368F4ULL,
		0x5674EC2543C3CD5EULL,
		0x8686CD2D435B3833ULL,
		0x6AA68B9E23984066ULL,
		0x2AFBECFCEE759D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31914E0A99C840EULL,
		0x121148BE98452612ULL,
		0x0EF2C8F4435B6416ULL,
		0x2193B9919846D1E8ULL,
		0xACE9D84A87879ABDULL,
		0x0D0D9A5A86B67066ULL,
		0xD54D173C473080CDULL,
		0x55F7D9F9DCEB3AF6ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x782C33087214481CULL,
		0x7D96DA5081BE36D8ULL,
		0x2203CBB8F3DC0515ULL,
		0xADFA219212392451ULL,
		0x3FE9E420CF12A8B6ULL,
		0xE96EE65A554D54D3ULL,
		0x99E5143A49D0E69FULL,
		0x0F4D997EDCCEA9AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0586610E4289038ULL,
		0xFB2DB4A1037C6DB0ULL,
		0x44079771E7B80A2AULL,
		0x5BF44324247248A2ULL,
		0x7FD3C8419E25516DULL,
		0xD2DDCCB4AA9AA9A6ULL,
		0x33CA287493A1CD3FULL,
		0x1E9B32FDB99D535DULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2D3A85C52E01B18ULL,
		0x6B2E02375A330884ULL,
		0xE00B0457434C9077ULL,
		0x3BB33AF6EC6835AFULL,
		0x03552D9D53242509ULL,
		0xF976AAC6948095ACULL,
		0xF828E73C3C7D6AE8ULL,
		0x032EBB2B38230DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5A750B8A5C03630ULL,
		0xD65C046EB4661109ULL,
		0xC01608AE869920EEULL,
		0x776675EDD8D06B5FULL,
		0x06AA5B3AA6484A12ULL,
		0xF2ED558D29012B58ULL,
		0xF051CE7878FAD5D1ULL,
		0x065D765670461B43ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x066066A39BD5D8B8ULL,
		0x3275AFB2F480FBE9ULL,
		0x8105240FCBF2A848ULL,
		0x6F3B3255BA0C7344ULL,
		0x84796DAE1F907D64ULL,
		0xDBAC2449750C7596ULL,
		0xFEEF55C0D8D7D647ULL,
		0x260C5D01B039A6E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CC0CD4737ABB170ULL,
		0x64EB5F65E901F7D2ULL,
		0x020A481F97E55090ULL,
		0xDE7664AB7418E689ULL,
		0x08F2DB5C3F20FAC8ULL,
		0xB7584892EA18EB2DULL,
		0xFDDEAB81B1AFAC8FULL,
		0x4C18BA0360734DCDULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45D1D67802D42449ULL,
		0xDCC8EA9E11622C13ULL,
		0x914FA60324FE058AULL,
		0x2254C208E2494DA7ULL,
		0x09ED396E6D9F937CULL,
		0xF1E1E7193AD2DFE9ULL,
		0x9909829FABD88D2AULL,
		0x3E6F8C6D3E0A9DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BA3ACF005A84892ULL,
		0xB991D53C22C45826ULL,
		0x229F4C0649FC0B15ULL,
		0x44A98411C4929B4FULL,
		0x13DA72DCDB3F26F8ULL,
		0xE3C3CE3275A5BFD2ULL,
		0x3213053F57B11A55ULL,
		0x7CDF18DA7C153B81ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC170E3602C4BC372ULL,
		0xEE4E38FE052FE372ULL,
		0x9B4BC611D0232088ULL,
		0x844D04D55EFBED03ULL,
		0xCDE94F3934715273ULL,
		0x3ED6F40212E8AA2BULL,
		0x09B679CE4D1BDE99ULL,
		0x1D11855D00340EB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82E1C6C0589786E4ULL,
		0xDC9C71FC0A5FC6E5ULL,
		0x36978C23A0464111ULL,
		0x089A09AABDF7DA07ULL,
		0x9BD29E7268E2A4E7ULL,
		0x7DADE80425D15457ULL,
		0x136CF39C9A37BD32ULL,
		0x3A230ABA00681D6AULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}