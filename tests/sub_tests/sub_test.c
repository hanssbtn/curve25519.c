#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0xC5A7BE7C14DAFF70ULL,
		0x8B036CFF591C3B7CULL,
		0xC00F1F4078EC6D52ULL,
		0x7EA33141F7E89693ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x2F56C405254C9414ULL,
		0x482AF4EEECA835D5ULL,
		0x1441FDD22A51AE51ULL,
		0x7CA3FFCAF7E158BBULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x9650FA76EF8E6B5CULL,
		0x42D878106C7405A7ULL,
		0xABCD216E4E9ABF01ULL,
		0x01FF317700073DD8ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEC76A9989EC8B74ULL,
		0x7CCAF8DB479F4528ULL,
		0xE44A75F33087B9D0ULL,
		0x30ECE2C2625C0D78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x571D1D5641DBB7C4ULL,
		0x1426240D99508499ULL,
		0x04F652C54E2B22A1ULL,
		0x78C36DFA8E9D5019ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87AA4D434810D39DULL,
		0x68A4D4CDAE4EC08FULL,
		0xDF54232DE25C972FULL,
		0x382974C7D3BEBD5FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04151793D26452AFULL,
		0xC1F0EC239D8AC9B0ULL,
		0x81631D198A924526ULL,
		0x72A02C5B9E7750DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DEA3EE3073C10ADULL,
		0xC299335671A173FAULL,
		0xD50455C9850FBAF0ULL,
		0x6E751C40F34DEC24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD62AD8B0CB284202ULL,
		0xFF57B8CD2BE955B5ULL,
		0xAC5EC75005828A35ULL,
		0x042B101AAB2964B9ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1254016DC5655DEULL,
		0x83435886DB742577ULL,
		0xC43BFE127D928B31ULL,
		0x2A2BC846CC90FA72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD43A7500DC6494ULL,
		0x78042D5EB5EFC403ULL,
		0x6A42A4F35F3D1DB7ULL,
		0x64F8544226ACC02BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x545105A1DB79F137ULL,
		0x0B3F2B2825846174ULL,
		0x59F9591F1E556D7AULL,
		0x45337404A5E43A47ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF759BF260551A4F9ULL,
		0x68260DC3B8FB889FULL,
		0x0CA11097D2F8AB97ULL,
		0x5F860D4E1888FACFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8015E33EC13AC340ULL,
		0xCDE0B2B2A2132EBCULL,
		0x0D5FF5168AF13991ULL,
		0x3EEFD636205BC7D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7743DBE74416E1B9ULL,
		0x9A455B1116E859E3ULL,
		0xFF411B8148077205ULL,
		0x20963717F82D32F6ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F3F07B78E58427FULL,
		0x4A0174789D193730ULL,
		0x01943E48FB584CADULL,
		0x458F40780D90BCD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3357DAB07E4D526ULL,
		0xB7E3400D03F9DC08ULL,
		0xD534833A817D7F84ULL,
		0x7D1511F071AC7411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC098A0C86736D46ULL,
		0x921E346B991F5B27ULL,
		0x2C5FBB0E79DACD28ULL,
		0x487A2E879BE448C4ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DF62D88E9DBF69FULL,
		0xA544F6E823261D6CULL,
		0x0CC20865A9D46B1BULL,
		0x00DA9931F6ED7775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D3C4F6A33575E6ULL,
		0x0A57AF5EDC1F0CD5ULL,
		0xED094471DD2DF4F5ULL,
		0x31DD39747991D889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE722689246A680A6ULL,
		0x9AED478947071096ULL,
		0x1FB8C3F3CCA67626ULL,
		0x4EFD5FBD7D5B9EEBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB6BB851460398F0ULL,
		0x982CDEB4F9F15C38ULL,
		0xFB85DD90165F23BAULL,
		0x4641B21F2F3317B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC62275DE10D656ULL,
		0x0616CE27ABCF8BEBULL,
		0x91CAD581C17C155EULL,
		0x51090829B529D3D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCA595DB67F2C287ULL,
		0x9216108D4E21D04CULL,
		0x69BB080E54E30E5CULL,
		0x7538A9F57A0943E0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ED35AA3E6F1C205ULL,
		0xA03F40B388F22C74ULL,
		0x5EB343FD0C75E3EBULL,
		0x3B73F12CBDDC260CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716917633BB573E6ULL,
		0x8E978DC88388E7EBULL,
		0x5893ED2E484D5BDFULL,
		0x571F77B4AA8E6331ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED6A4340AB3C4E0CULL,
		0x11A7B2EB05694488ULL,
		0x061F56CEC428880CULL,
		0x64547978134DC2DBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC235FF8979A1EFC9ULL,
		0x057A583E7D7DD505ULL,
		0xF672191A4BA09969ULL,
		0x25F55DF05B363B65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59FFC2CE4353381ULL,
		0xE1A304FAA28319B9ULL,
		0xAD4C02F42B957D52ULL,
		0x52AA0EB8377DAC70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC96035C956CBC35ULL,
		0x23D75343DAFABB4BULL,
		0x49261626200B1C16ULL,
		0x534B4F3823B88EF5ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3687ECA33E2CFF58ULL,
		0xAE9A83D646200EA1ULL,
		0x02CBD3031937FEFCULL,
		0x2117ECC162D72E39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EDA224BC81737DEULL,
		0xF93F7976C147F513ULL,
		0x954A4E5D03840520ULL,
		0x65CEA3D223A753D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07ADCA577615C767ULL,
		0xB55B0A5F84D8198EULL,
		0x6D8184A615B3F9DBULL,
		0x3B4948EF3F2FDA65ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x706857D05F7A8F44ULL,
		0xEC44C9EFD0EA01B7ULL,
		0x4B38676234E83242ULL,
		0x32E78B2C0099F834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD622BF9A97F1314AULL,
		0x6E475BB4BE8B2120ULL,
		0x236DDDFC51FCE417ULL,
		0x57ACB64C9A7DEDC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A459835C7895DE7ULL,
		0x7DFD6E3B125EE096ULL,
		0x27CA8965E2EB4E2BULL,
		0x5B3AD4DF661C0A71ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF80A2A2F3B1470DCULL,
		0x449722A205D457E0ULL,
		0xE3A77FC5E35F2E7BULL,
		0x5D17A9A198AE33B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE270FA1FE3DE21D0ULL,
		0x51E8968B9A9D76BFULL,
		0x3BAE41A69E5CDEB4ULL,
		0x37EE301B883751E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1599300F57364F0CULL,
		0xF2AE8C166B36E121ULL,
		0xA7F93E1F45024FC6ULL,
		0x252979861076E1C8ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8463D227FD61210ULL,
		0xB314DA156F180738ULL,
		0xF6AA0C955314C9FFULL,
		0x40C1F7CFDAC8DA3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BDE280CFBC4EE1AULL,
		0x3F6247B84BDB0940ULL,
		0xD918D8743932064EULL,
		0x09AE3CB2587DC76FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C681515841123F6ULL,
		0x73B2925D233CFDF8ULL,
		0x1D91342119E2C3B1ULL,
		0x3713BB1D824B12CDULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2DFAF5CE4495C52ULL,
		0x6DD45FC1BA37CEB6ULL,
		0x445A1D8844E6B8C6ULL,
		0x6E7534B42216BCAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x064284421EE381FFULL,
		0xBF17B5FD7E79F1EDULL,
		0xFBA43F4A75A2F36BULL,
		0x6F0A73908779516BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C9D2B1AC565DA40ULL,
		0xAEBCA9C43BBDDCC9ULL,
		0x48B5DE3DCF43C55AULL,
		0x7F6AC1239A9D6B42ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85EC9C92687098B7ULL,
		0xC09855CB3DAB429CULL,
		0x6A16A8FBD0B27B88ULL,
		0x36AD119C448DA2F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1D5C91DC2AE843ULL,
		0x13A702A26B7976E7ULL,
		0x6E592D085D92F246ULL,
		0x540DCDBE70D657AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BCF40008C45B061ULL,
		0xACF15328D231CBB5ULL,
		0xFBBD7BF3731F8942ULL,
		0x629F43DDD3B74B47ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1BE30276307BD6DULL,
		0x348EDE062EAAA880ULL,
		0xA3DBE615291E3683ULL,
		0x0C384CBE80BA692EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF56A7A6C16CCBB3BULL,
		0xF7F53AF2D1581B4FULL,
		0xEDC9607C75ACCF59ULL,
		0x273A4A5F0BAD030CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC53B5BB4C3B021FULL,
		0x3C99A3135D528D30ULL,
		0xB6128598B3716729ULL,
		0x64FE025F750D6621ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E1C4E716D5F73ABULL,
		0x7DBA8CA51C642000ULL,
		0x5BA61F71643284ABULL,
		0x7FA9B278287270BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8616289797AF1450ULL,
		0x9733C87B8E60113DULL,
		0x2C5A9D800C4249DDULL,
		0x305A46D7DC3DFCB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF80625D9D5B05F5BULL,
		0xE686C4298E040EC2ULL,
		0x2F4B81F157F03ACDULL,
		0x4F4F6BA04C347404ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3DF6CD87DF948E6ULL,
		0x2C52BA03D90EE19AULL,
		0xBE9DB8A9CD0D3B9BULL,
		0x331F59229E567AB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDA55DF0A103A1FEULL,
		0x07A3B4CACD15789AULL,
		0x6B4DA39332042B69ULL,
		0x4C7EFAEF90E22A7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB63A0EE7DCF5A6D5ULL,
		0x24AF05390BF968FFULL,
		0x535015169B091032ULL,
		0x66A05E330D74503EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8709ECD0EE451EF6ULL,
		0x509A4CD44D29193DULL,
		0x2DC0C44929CFC94BULL,
		0x7F1B9887A115A9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027A1C77679244F8ULL,
		0xB0A12FC239B223C5ULL,
		0x26DF4370BC1E9A75ULL,
		0x2D3371E0146A4C24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x848FD05986B2D9FEULL,
		0x9FF91D121376F578ULL,
		0x06E180D86DB12ED5ULL,
		0x51E826A78CAB5DB0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x398E64ABF5581899ULL,
		0x1471F5D37E8CE6E7ULL,
		0x16042C3C63E49C30ULL,
		0x5CEF64D6507D38F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x598A3DC70A838EC0ULL,
		0xAE1FA0D637484439ULL,
		0xF02A34845EA1F00BULL,
		0x096A2F052F350877ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE00426E4EAD489D9ULL,
		0x665254FD4744A2ADULL,
		0x25D9F7B80542AC24ULL,
		0x538535D12148307BULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEFC12DB7D7DB61AULL,
		0x1CA9C94F54440939ULL,
		0x69AF8EB487CDB9F8ULL,
		0x6FDE41803A662956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7261C7B81FCE2775ULL,
		0xE56D3D05B1DBDD55ULL,
		0xD4856B378C4DD915ULL,
		0x0FA4CE8011AA4FA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C9A4B235DAF8EA5ULL,
		0x373C8C49A2682BE4ULL,
		0x952A237CFB7FE0E2ULL,
		0x6039730028BBD9B2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BC1B57FEC093FE0ULL,
		0x12328A8A96A7ECD3ULL,
		0x1B4A6FA1027D274DULL,
		0x1C0EE03AE790FC51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACCA704CAA6BA2EULL,
		0xE08B6782990FB14EULL,
		0x90D0E28413FFFE12ULL,
		0x527434BA19BB5903ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0F50E7B2162859FULL,
		0x31A72307FD983B84ULL,
		0x8A798D1CEE7D293AULL,
		0x499AAB80CDD5A34DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5045D86876A5CB6BULL,
		0x3C761261AB496B2DULL,
		0x6053E66BB62080BBULL,
		0x66E729724D8E88A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763302B7EBAA02BAULL,
		0x342B0B592C8DE876ULL,
		0xC75A573309069C7BULL,
		0x18789A9A5E8AFFFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA12D5B08AFBC8B1ULL,
		0x084B07087EBB82B6ULL,
		0x98F98F38AD19E440ULL,
		0x4E6E8ED7EF0388A6ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB28061CB4306C3E0ULL,
		0x0CD2543141705871ULL,
		0x5EE86CDD8BF5A852ULL,
		0x2938974D30B00990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC01396439D26895ULL,
		0x62ED65FC0ED66288ULL,
		0xBC29B1A9786619CFULL,
		0x041FB7ECB49ABC28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC67F286709345B4BULL,
		0xA9E4EE353299F5E8ULL,
		0xA2BEBB34138F8E82ULL,
		0x2518DF607C154D67ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60FA1CF5C577DE46ULL,
		0x2AF22F584CBBD37EULL,
		0x9D10046ACDCD4EDFULL,
		0x45DBD18E87B96DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC0161432E3E751ULL,
		0x13127D2D1781A443ULL,
		0xE2AEE73DA9216B78ULL,
		0x7CFAD727F797D204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x143A06E19293F6E2ULL,
		0x17DFB22B353A2F3BULL,
		0xBA611D2D24ABE367ULL,
		0x48E0FA6690219BB7ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9C2664467011F3AULL,
		0xF6170FF8A5C1C471ULL,
		0xDEF66B51FE1DDCA1ULL,
		0x751A9DE8A29B04CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80E6B548A5C08DD2ULL,
		0x9E7D588393436D86ULL,
		0x2C5B74247B74B459ULL,
		0x7B414DAF2E65D36CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78DBB0FBC1409155ULL,
		0x5799B775127E56EBULL,
		0xB29AF72D82A92848ULL,
		0x79D9503974353162ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AACF82A83455DC3ULL,
		0x898BE44EE9F6F880ULL,
		0x6ACFAB2FB86DB7BCULL,
		0x6511822DDC3AAEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x915430E0CDF0B547ULL,
		0x8EFC4A6A24CD5F6EULL,
		0xD691813AF112B0E8ULL,
		0x02BA7AA98CA71566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC958C749B554A87CULL,
		0xFA8F99E4C5299911ULL,
		0x943E29F4C75B06D3ULL,
		0x625707844F939998ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3ACF3D65412B8C8ULL,
		0xF4394FCE97C3FCD3ULL,
		0x0AD75EBF090E8623ULL,
		0x58E32119570A5D0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3154196F7CC4176ULL,
		0xC869C978B0BE3B27ULL,
		0xF95B027B635109F1ULL,
		0x6BA8E2E9938ED0BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF097B23F5C46773FULL,
		0x2BCF8655E705C1ABULL,
		0x117C5C43A5BD7C32ULL,
		0x6D3A3E2FC37B8C4FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B48C6FF2F119F53ULL,
		0xC72741A2D5189B26ULL,
		0xAAB3312F6A1F6082ULL,
		0x7CC49AFEBC61CEFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF268C8BBB39E6633ULL,
		0x3957C58708A85F2AULL,
		0x26AA99F7DB995BC2ULL,
		0x0EF1DE04F43B94F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78DFFE437B733920ULL,
		0x8DCF7C1BCC703BFBULL,
		0x840897378E8604C0ULL,
		0x6DD2BCF9C8263A09ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49A6AE483B868FBFULL,
		0x3D6CD440AF3A3220ULL,
		0xCA317F3174005663ULL,
		0x6D4B1D2396996DF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C4FBC0E46F8D12EULL,
		0x6D0604013102193CULL,
		0x10D65C627C70A926ULL,
		0x2030882B0C9F85CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D56F239F48DBE91ULL,
		0xD066D03F7E3818E4ULL,
		0xB95B22CEF78FAD3CULL,
		0x4D1A94F889F9E827ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8CC14AA72289DADULL,
		0xFE171249CE8C3CB7ULL,
		0x07BCAFEC2A76CD5EULL,
		0x6306F52FE9DABBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61BEA5B93BFCCAAULL,
		0x1D959FE93AB948D2ULL,
		0xA094B8BF0725A36CULL,
		0x14998E4F8C9D61F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12B02A4EDE68D103ULL,
		0xE081726093D2F3E5ULL,
		0x6727F72D235129F2ULL,
		0x4E6D66E05D3D59DAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA289952A8D200ECFULL,
		0x89244EDBBB754516ULL,
		0xC3E8EB18BBA67B45ULL,
		0x14751FA7BB731163ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB3582266DE4BCA1ULL,
		0xE28F388CE421992BULL,
		0x00AF6E777B7855F0ULL,
		0x7AC0BCC467A8E289ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE75413041F3B521BULL,
		0xA695164ED753ABEAULL,
		0xC3397CA1402E2554ULL,
		0x19B462E353CA2EDAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74BA645704EB422DULL,
		0x6840CD239F9B71CBULL,
		0xF01516A11D5FE306ULL,
		0x614B25A95F736056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6DA62AE8EE2D873ULL,
		0x7632C7A9789EF048ULL,
		0xD1E7C102CC574EDFULL,
		0x67D2EE663DED89A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DE001A8760869A7ULL,
		0xF20E057A26FC8182ULL,
		0x1E2D559E51089426ULL,
		0x797837432185D6B5ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDEB25E099957682ULL,
		0x38EBF073C61FC1AFULL,
		0x9B521A8A3277504AULL,
		0x1EAC786583BDF151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E899046B68036F3ULL,
		0xA295FBECB02F07D9ULL,
		0xAAE72F19FF115065ULL,
		0x44D0D1609C0E704FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F619599E3153F7CULL,
		0x9655F48715F0B9D6ULL,
		0xF06AEB703365FFE4ULL,
		0x59DBA704E7AF8101ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4B73C43DE0FBBBBULL,
		0xB52AC6632C25DC2AULL,
		0x12F21D681D83250BULL,
		0x60D9A247FCC30D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE187CFECE7961FF1ULL,
		0x82F562665C7EFC14ULL,
		0x68A7AFB8157D53C3ULL,
		0x7D2FE3D98429E5B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF32F6C56F6799BB7ULL,
		0x323563FCCFA6E015ULL,
		0xAA4A6DB00805D148ULL,
		0x63A9BE6E78992782ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2759638D9B35EC8ULL,
		0xD25133762C2A3A67ULL,
		0xA7CF1D150B02BD80ULL,
		0x2DC667E8DBE81C44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF1271269B233E69ULL,
		0x96F95215715855F1ULL,
		0x9DFA431E71F7C1CBULL,
		0x0D4ADE24EB3A0B0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE36325123E90205FULL,
		0x3B57E160BAD1E475ULL,
		0x09D4D9F6990AFBB5ULL,
		0x207B89C3F0AE1135ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78BB4F32D5916948ULL,
		0x3A386021C54628A5ULL,
		0x3C8701B789510240ULL,
		0x17C09D8C539B8F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC607A2E417A2D77ULL,
		0x3813617F1399EB41ULL,
		0x2DBCD2DC0D2B762CULL,
		0x04DE4D1AD7A1A4A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC5AD50494173BD1ULL,
		0x0224FEA2B1AC3D63ULL,
		0x0ECA2EDB7C258C14ULL,
		0x12E250717BF9EA9FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED4F9A9F2FE1CC2EULL,
		0xB5944C9073ED48B6ULL,
		0x0B78003B35921F25ULL,
		0x6ACF625F813F02C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835536B32AA3318FULL,
		0xF02FDE9359D52FCDULL,
		0x2492F7BF98F8B2B9ULL,
		0x0A7695F78E032561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69FA63EC053E9A9FULL,
		0xC5646DFD1A1818E9ULL,
		0xE6E5087B9C996C6BULL,
		0x6058CC67F33BDD65ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3342E7837C4D237AULL,
		0xDB01985A11513860ULL,
		0x39EA3697662FFA21ULL,
		0x198F91E5719E73FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x111D87E3CAA2D73AULL,
		0x5D5DEAD5DBD04937ULL,
		0x0C3960CCEF352741ULL,
		0x14B9741351147014ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22255F9FB1AA4C40ULL,
		0x7DA3AD843580EF29ULL,
		0x2DB0D5CA76FAD2E0ULL,
		0x04D61DD2208A03EAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8A1626E2C57322AULL,
		0x08CE827189901480ULL,
		0xC0115B7BD6555391ULL,
		0x46A685E5357F441EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1AD8D6C9FC12E70ULL,
		0x139A85585680C48CULL,
		0x06F749FD3C39CF83ULL,
		0x5F478F1759FCB006ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06F3D5018C9603A7ULL,
		0xF533FD19330F4FF4ULL,
		0xB91A117E9A1B840DULL,
		0x675EF6CDDB829418ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65668245C1B334DCULL,
		0x9073DF75A941F789ULL,
		0x050508DD9318F1EEULL,
		0x54B3DCBA2AB7D838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8C485BED09012EULL,
		0x8526F32284FEB2E7ULL,
		0xBEA959050961D3E0ULL,
		0x09DCAA34A97C406DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59DA39E9D4AA33AEULL,
		0x0B4CEC53244344A2ULL,
		0x465BAFD889B71E0EULL,
		0x4AD73285813B97CAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x016557439D4C1022ULL,
		0x5CF910AC82C4F31DULL,
		0xB0631159BF919F1EULL,
		0x2E876019D83A51E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA43CAE394B73F9AULL,
		0xEDCB0B97BA2B808DULL,
		0x01EA13B2F951F5BFULL,
		0x306773E3D00AB4DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57218C600894D075ULL,
		0x6F2E0514C899728FULL,
		0xAE78FDA6C63FA95EULL,
		0x7E1FEC36082F9D03ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DECF57C48EBD36FULL,
		0xCEC855B81BDC70D8ULL,
		0x61D0046B9E753FAFULL,
		0x02FDAE82C7989053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE465C724424A9AULL,
		0x3C6274537364A973ULL,
		0x1CD1191AB56F121AULL,
		0x1312F41DDFBB41BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11088FB524A988C2ULL,
		0x9265E164A877C765ULL,
		0x44FEEB50E9062D95ULL,
		0x6FEABA64E7DD4E99ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36F231F82BB1168DULL,
		0x876EA56B904AA39FULL,
		0x52A43E1E04778B6AULL,
		0x2BB2137A17F0C7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0BD62CAEAF28632ULL,
		0xF93805F3C305FD0AULL,
		0xE415D18DDF3F3B60ULL,
		0x50075C0FB1347C5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8634CF2D40BE9048ULL,
		0x8E369F77CD44A694ULL,
		0x6E8E6C9025385009ULL,
		0x5BAAB76A66BC4B84ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CA5CE56F517BC61ULL,
		0x760430EFC58492DAULL,
		0x14064BBB7BAD91D1ULL,
		0x4AA6133F311ED981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x352B6598FCBAFC58ULL,
		0xA1F3992F07E74A32ULL,
		0x4960AE1269D91AF2ULL,
		0x4A9B21EDFC235DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF77A68BDF85CC009ULL,
		0xD41097C0BD9D48A7ULL,
		0xCAA59DA911D476DEULL,
		0x000AF15134FB7BBBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEEB0404C276BEDEULL,
		0xDA96A1072F4F246CULL,
		0x6632C0BA94F0C005ULL,
		0x34F759B271DA25AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA76553A4A75A73ULL,
		0xF642E88831BC3984ULL,
		0x0A3D8DEBFD9362FFULL,
		0x761EC7354C51B5CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62439EB11DCF6458ULL,
		0xE453B87EFD92EAE8ULL,
		0x5BF532CE975D5D05ULL,
		0x3ED8927D25886FDCULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B53E293F29644FBULL,
		0xD79CBB3C61782374ULL,
		0x40B4EB347DF02D24ULL,
		0x7BCF24E77CE09EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD30095C74428074EULL,
		0xEB78C1BAE1BBCBE3ULL,
		0x0937AC6BFAF601E9ULL,
		0x6B551F39F4E6BFACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68534CCCAE6E3DADULL,
		0xEC23F9817FBC5790ULL,
		0x377D3EC882FA2B3AULL,
		0x107A05AD87F9DF0EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E2D64FCBA51A837ULL,
		0xF3D0BC378EF5A09FULL,
		0x10368AF18A231BD1ULL,
		0x515ECCC68EBFB3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FFF8444A7FBAA4ULL,
		0x4C37FE45B38BC9E5ULL,
		0x794F79DFE04CE2E4ULL,
		0x635B1BDE3299032FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C2D6CB86FD1ED80ULL,
		0xA798BDF1DB69D6BAULL,
		0x96E71111A9D638EDULL,
		0x6E03B0E85C26B079ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F041759C85C87B6ULL,
		0xE69590CCEEAC668EULL,
		0x13FF699A1FD17E4BULL,
		0x3FEE0BBE92BFC98DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0747ACA33078B9ULL,
		0x9F745346D05D94F3ULL,
		0x80E4FF667F7E695CULL,
		0x300B2F2936900A6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53FCCFAD252C0EFDULL,
		0x47213D861E4ED19BULL,
		0x931A6A33A05314EFULL,
		0x0FE2DC955C2FBF1DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB6264AFD46600B7ULL,
		0x37C926971D409F3DULL,
		0x8D873FCC925F1CADULL,
		0x0287383A1E3843AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x535799AA75A7BD4FULL,
		0x0B72AF3F596CD390ULL,
		0x5159ED5F09C5DFC0ULL,
		0x317BCAA4846E4EA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x680ACB055EBE4355ULL,
		0x2C567757C3D3CBADULL,
		0x3C2D526D88993CEDULL,
		0x510B6D9599C9F50CULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4672DB1EDCF1A556ULL,
		0xA28FD6D990E0014DULL,
		0x0572A3AC3FF9B474ULL,
		0x34F2BD32C420B9D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC1149F6378A293ULL,
		0x1AA1FA8ACFA723E4ULL,
		0x88B4D831DE3C345FULL,
		0x274A5BB03FC1D332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9B1C67F797902C3ULL,
		0x87EDDC4EC138DD68ULL,
		0x7CBDCB7A61BD8015ULL,
		0x0DA86182845EE6A2ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3852ACA5C64B8D78ULL,
		0x8F8A136066C7EFBDULL,
		0x7E5DC954C550308EULL,
		0x6AB7AD1016360F0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFB228766AE4C2BBULL,
		0x496FF8B43EE44B65ULL,
		0xA64871DBCA388A38ULL,
		0x07D56EA459C12A8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38A0842F5B66CABDULL,
		0x461A1AAC27E3A457ULL,
		0xD8155778FB17A656ULL,
		0x62E23E6BBC74E480ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x356B022F63A2A80FULL,
		0x7BF12BAA6DB1835CULL,
		0x763D86276F0F0616ULL,
		0x75A70C2025BE9D68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3535DFD94172B94ULL,
		0xA9999828BB3DAD1CULL,
		0x7AC60121DFA7FC5CULL,
		0x5A11475485912906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8217A431CF8B7C7BULL,
		0xD2579381B273D63FULL,
		0xFB7785058F6709B9ULL,
		0x1B95C4CBA02D7461ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0269723EDCD5E18ULL,
		0xA3AD5F3B91CC1EF8ULL,
		0x18DBBC786F4F0B2AULL,
		0x00E259D89FC71468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4523B40464AD479ULL,
		0x8FF01040F932ECACULL,
		0x9915966429F40DB5ULL,
		0x0DB48D7F021CB56EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABD45BE3A782898CULL,
		0x13BD4EFA9899324BULL,
		0x7FC62614455AFD75ULL,
		0x732DCC599DAA5EF9ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2749B6BEED35B860ULL,
		0x05872AB3083E6F52ULL,
		0xA0114414E9595EFBULL,
		0x2FF374D93541BDE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0492753427F2BB45ULL,
		0x86A37E68DF181C17ULL,
		0xBC4965F9D93390F3ULL,
		0x52FEB930F60F8A60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22B7418AC542FD08ULL,
		0x7EE3AC4A2926533BULL,
		0xE3C7DE1B1025CE07ULL,
		0x5CF4BBA83F323380ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D520AAA565DE31DULL,
		0xA009CD294EC182D6ULL,
		0xF5C02EC51F003016ULL,
		0x48AA56CD1A73B347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BCA8DB6F39B3CFULL,
		0xCA251C05F656387FULL,
		0xC8FDE16A7EBB9116ULL,
		0x4E0BEFB66E541E50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x339561CEE7242F3BULL,
		0xD5E4B123586B4A57ULL,
		0x2CC24D5AA0449EFFULL,
		0x7A9E6716AC1F94F7ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92119BF450CC8C3FULL,
		0x33537DED9EB3451DULL,
		0xCBEBD64A86CB51B2ULL,
		0x42A971C4F0FEB987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0FAB8ED9D3E8C5CULL,
		0xB5EFD051ADC4175DULL,
		0x66DFBBBCAD60C906ULL,
		0x711CC8751E44B16BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA116E306B38DFFD0ULL,
		0x7D63AD9BF0EF2DBFULL,
		0x650C1A8DD96A88ABULL,
		0x518CA94FD2BA081CULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7270D233D0B45D56ULL,
		0x637D7C6B32B1CC8CULL,
		0xF7CC3EF67AA3FC79ULL,
		0x7DB60BDDE8CCD82AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1C6A059D3B1BCDULL,
		0x95199FF1B60D1829ULL,
		0xEFE79F2D7921E40EULL,
		0x01A76A2EA702862BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE354682E33794189ULL,
		0xCE63DC797CA4B462ULL,
		0x07E49FC90182186AULL,
		0x7C0EA1AF41CA51FFULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00DEA8CF7F70F230ULL,
		0x367A0BD733F9781EULL,
		0x121EDD03A41F60AFULL,
		0x7E5F77EBDC5D3F86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C08D43BFF7E89CULL,
		0xBDB257167117AC3BULL,
		0x5A9E65781BC54BE4ULL,
		0x264989BAA70E3EB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E1E1B8BBF790994ULL,
		0x78C7B4C0C2E1CBE2ULL,
		0xB780778B885A14CAULL,
		0x5815EE31354F00CFULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x430374192D8029D1ULL,
		0xAE759C479DE4EA40ULL,
		0xE80A82D364F1F12DULL,
		0x28242E71D72177D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DF887ABA30523DULL,
		0x6AFA957420933E4DULL,
		0x69448F57E8253BB1ULL,
		0x14FEEB0382B2FB40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB23EB9E734FD794ULL,
		0x437B06D37D51ABF2ULL,
		0x7EC5F37B7CCCB57CULL,
		0x1325436E546E7C98ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC06BFBB4B19E3D04ULL,
		0xD6DCAA8040737964ULL,
		0xF2AD281BEFAF4A9CULL,
		0x76F7BF2F51A84024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A49F49F999DCE78ULL,
		0x9E44D5962C28F6CEULL,
		0x17ED20800B64EC86ULL,
		0x4AB8FAC29D1BE5F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9622071518006E8CULL,
		0x3897D4EA144A8296ULL,
		0xDAC0079BE44A5E16ULL,
		0x2C3EC46CB48C5A33ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24A8A3C916ACA4B8ULL,
		0x88379EE44AE964E8ULL,
		0x6E2651400274605CULL,
		0x02EFE48370DCD118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD743F4758DF94EDFULL,
		0xF78D030C3D089573ULL,
		0x4869B673887C255FULL,
		0x3776FFACBB8779A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D64AF5388B355C6ULL,
		0x90AA9BD80DE0CF74ULL,
		0x25BC9ACC79F83AFCULL,
		0x4B78E4D6B5555776ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EBDDC395A452F7BULL,
		0xCAE54B8FC3BB7924ULL,
		0x395EE9E52DA4AACBULL,
		0x6F1FBC011F7B90F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3959BEAAAFF6DEBDULL,
		0x30FE2A3E10441A7EULL,
		0xABF1831F3CC64884ULL,
		0x7E36E7398BB395C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5641D8EAA4E50ABULL,
		0x99E72151B3775EA5ULL,
		0x8D6D66C5F0DE6247ULL,
		0x70E8D4C793C7FB33ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C71D0FF41E608DDULL,
		0x733C2BED83CB482BULL,
		0xBD55D0D81AA314C8ULL,
		0x79BCABE186A0C6B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFB8F7DE23718ABDULL,
		0x112B48F45123BD2EULL,
		0x7EA2A09A04CF8607ULL,
		0x59A6816C0B3E3A29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCB8D9211E747E20ULL,
		0x6210E2F932A78AFCULL,
		0x3EB3303E15D38EC1ULL,
		0x20162A757B628C88ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x853B0D7F2E27D3ADULL,
		0xDA8E1CCF727AAB53ULL,
		0xFBB040E48E352B30ULL,
		0x6749F88933444E35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x225E71613AB59AA5ULL,
		0xAC46304414DB6FB6ULL,
		0xC28AD195B732E97AULL,
		0x410B002B48443A4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62DC9C1DF3723908ULL,
		0x2E47EC8B5D9F3B9DULL,
		0x39256F4ED70241B6ULL,
		0x263EF85DEB0013E9ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9385FFB116F5C0EULL,
		0x383637F4323694F9ULL,
		0x4FC3200DA7A83695ULL,
		0x72D472B2D938A338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E559778CF453741ULL,
		0xC4FE867819FED068ULL,
		0x44F92A4CF73800D2ULL,
		0x63286FAD91F9D252ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE2C882422A24CDULL,
		0x7337B17C1837C491ULL,
		0x0AC9F5C0B07035C2ULL,
		0x0FAC0305473ED0E6ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9555FB08324A32AULL,
		0x2E8DE174077E12A7ULL,
		0x36587548F3D29D04ULL,
		0x3050FEC06718CF40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D61C8DBB3F17F3DULL,
		0x91AECB3D76E9A9C2ULL,
		0xE40FD57FEFF228CAULL,
		0x1C6203260D2FFDC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BF396D4CF3323EDULL,
		0x9CDF1636909468E5ULL,
		0x52489FC903E07439ULL,
		0x13EEFB9A59E8D17BULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A8A63173DE918BULL,
		0x0049F92617D52199ULL,
		0xF9B48C97380AA960ULL,
		0x3E272F1A4F11A27AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x901EAC576FC7F3EFULL,
		0x680AF52D98181BC6ULL,
		0x4B779C4B92258AFAULL,
		0x2211EBE30411652DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4089F9DA04169D9CULL,
		0x983F03F87FBD05D3ULL,
		0xAE3CF04BA5E51E65ULL,
		0x1C1543374B003D4DULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB72EA42F574FB2CULL,
		0xEC7FE5434EF361AAULL,
		0x1A35FA3B58F19787ULL,
		0x1E29276F25BE8DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864DC69CA31E2B50ULL,
		0x38313E168D65D695ULL,
		0x05D6F092BEA1971AULL,
		0x040BA335EA55D9CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x252523A65256CFDCULL,
		0xB44EA72CC18D8B15ULL,
		0x145F09A89A50006DULL,
		0x1A1D84393B68B3F6ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BD102D4890179BAULL,
		0x042111FDD8465C78ULL,
		0x277741EF54F67F02ULL,
		0x407CC2ABFA41C4CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x983A2DEB6D58B44DULL,
		0x77AA6DF955739CFDULL,
		0x7D25AE89D33D2FFFULL,
		0x491CF705AC5BB86EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF396D4E91BA8C55AULL,
		0x8C76A40482D2BF7AULL,
		0xAA51936581B94F02ULL,
		0x775FCBA64DE60C5DULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8294C045E5AB54FBULL,
		0x97292B4AC0F7DEC0ULL,
		0xA9ED9AD5F63842C6ULL,
		0x562D42678C88368FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3609A5A27BA4E1B8ULL,
		0x80D9E732C9A80F9AULL,
		0x297A33039BADD55FULL,
		0x311AF2C162357CD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8B1AA36A067343ULL,
		0x164F4417F74FCF26ULL,
		0x807367D25A8A6D67ULL,
		0x25124FA62A52B9BBULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC97DEC0A80CC8F4ULL,
		0xDFB798EBE750EABFULL,
		0xE6E022DDD04946EFULL,
		0x4B00DD343F3EB946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0168ACB4C1A289A8ULL,
		0x766D3A34130C7421ULL,
		0x64A7DB6E850BEEFDULL,
		0x67BB4B2D5E3CB271ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB2F320BE66A3F39ULL,
		0x694A5EB7D444769EULL,
		0x8238476F4B3D57F2ULL,
		0x63459206E10206D5ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AB579528F73F38CULL,
		0x7EBC49E8E3EF4891ULL,
		0xA8F50ECB59B0B53BULL,
		0x5201244194477D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70BCF5D73BD4B8CAULL,
		0x55DAF8CE6FAA3F3BULL,
		0x8389EA3A640B5A21ULL,
		0x4DF3413CEF70E3C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29F8837B539F3AC2ULL,
		0x28E1511A74450956ULL,
		0x256B2490F5A55B1AULL,
		0x040DE304A4D6997AULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAEB6FD7A59952C7ULL,
		0x1A0E588E8076BDE1ULL,
		0xFD144A3E1D5ACF2CULL,
		0x25710BD971B89F85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC63A90432500ED6ULL,
		0xA6A3DB4009B546F1ULL,
		0x1B142BB9CA000585ULL,
		0x78D54AE816AB40A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E87C6D3734943DEULL,
		0x736A7D4E76C176F0ULL,
		0xE2001E84535AC9A6ULL,
		0x2C9BC0F15B0D5EDCULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA97C39B4756E09ULL,
		0xA922E1C2D7AE00A6ULL,
		0xD967B2B7D4755D40ULL,
		0x72C9C40AD78188DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC770E4024CE0A85ULL,
		0xED3E855FF86CBAD5ULL,
		0x691DAF23DAB337D8ULL,
		0x0B28BECA7916CF79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71326DF98FA76384ULL,
		0xBBE45C62DF4145D0ULL,
		0x704A0393F9C22567ULL,
		0x67A105405E6AB962ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B906CE05C2DDFFEULL,
		0x369EECF7A5480AE0ULL,
		0xEA711C96E81C322FULL,
		0x1E07355D9DF0CAABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ADCBCC2A8D4D2AEULL,
		0x39BD80FD6E2034CDULL,
		0x39B10D7A1F543320ULL,
		0x21C1995B82F6D44DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0B3B01DB3590D3DULL,
		0xFCE16BFA3727D612ULL,
		0xB0C00F1CC8C7FF0EULL,
		0x7C459C021AF9F65EULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A70CEB9185F03ABULL,
		0x748BC8F2C881ADEBULL,
		0xA70B040599B73C80ULL,
		0x112671B896BE0CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6308B311F2AA782ULL,
		0x5D5C7CCAE113BF87ULL,
		0xC9E5B726DD59296EULL,
		0x2F653F5177B2FD91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24404387F9345C16ULL,
		0x172F4C27E76DEE63ULL,
		0xDD254CDEBC5E1312ULL,
		0x61C132671F0B0F14ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C1403312F297609ULL,
		0xE4A66D86CDE01801ULL,
		0x2C2DC517D62FC35EULL,
		0x562B34ED30BD4407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C3AAF36FA55BC96ULL,
		0xC7D81CC695C7FBF7ULL,
		0x103A7E49355BC54EULL,
		0x2C26703C50E54810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFD953FA34D3B973ULL,
		0x1CCE50C038181C09ULL,
		0x1BF346CEA0D3FE10ULL,
		0x2A04C4B0DFD7FBF7ULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA150E7890CAB07CEULL,
		0x768BA2FABCBE1DC2ULL,
		0x78D8A852517CF011ULL,
		0x23FEEDD4BB744F97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x293D693D3B1DCD8CULL,
		0xA3B05DE2E7C600BCULL,
		0xAE192E7A69B7D7BBULL,
		0x79C0A1D7BBA10D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78137E4BD18D3A2FULL,
		0xD2DB4517D4F81D06ULL,
		0xCABF79D7E7C51855ULL,
		0x2A3E4BFCFFD3427FULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0FABACFC19ED9F1ULL,
		0x2FD3713517074515ULL,
		0xA2F05CC25C85835AULL,
		0x173A93DD75A0A5DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DBB5ECCD2309E9ULL,
		0xBCF1AF705638FF35ULL,
		0x0716EE4BDE7811E4ULL,
		0x488A48C660FD0ED0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B1F04E2F47BCFF5ULL,
		0x72E1C1C4C0CE45E0ULL,
		0x9BD96E767E0D7175ULL,
		0x4EB04B1714A3970AULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE49ACFDC1A880794ULL,
		0xB12F9E21E928AA64ULL,
		0xCA924BEB1C695156ULL,
		0x68731E3950682711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71F63C38639DACD3ULL,
		0xB503C3B47E8B990DULL,
		0xF9EE2A24F02C9A6CULL,
		0x272AAF164CE4FA5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72A493A3B6EA5AC1ULL,
		0xFC2BDA6D6A9D1157ULL,
		0xD0A421C62C3CB6E9ULL,
		0x41486F2303832CB5ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE88DFFACC05570AULL,
		0xAAA227BE8AC1C042ULL,
		0x0E1C3A710E806F3DULL,
		0x26493FB2609FCE04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF3945740367D54ULL,
		0xFF75ED6AB843B6AFULL,
		0xA150BBBE8A352C4AULL,
		0x0EE73BBA6C1F8804ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F954BA38BCED9B6ULL,
		0xAB2C3A53D27E0993ULL,
		0x6CCB7EB2844B42F2ULL,
		0x176203F7F48045FFULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5122A7AE43859168ULL,
		0x1127EF8AA23AA5B1ULL,
		0x4266264060D8157AULL,
		0x59C41D440851B503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F1C23AF4C7AB0FULL,
		0x23FD51B62405AC33ULL,
		0x7A2C32C7B9451D1AULL,
		0x238B19C2BB7E6E0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB930E5734EBDE659ULL,
		0xED2A9DD47E34F97DULL,
		0xC839F378A792F85FULL,
		0x363903814CD346F7ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0D3C273D57E8E8EULL,
		0x6D261EFA26D531FCULL,
		0x939780A6C03C1BF2ULL,
		0x2DD4AD762818AAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4483E6BBC0CE7EBULL,
		0x9F8D29BA207956C3ULL,
		0x6ADB33316EE05EF8ULL,
		0x68E173A381A87C55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C8B84081971A690ULL,
		0xCD98F540065BDB39ULL,
		0x28BC4D75515BBCF9ULL,
		0x44F339D2A6702E9CULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94136C6333A54B89ULL,
		0x02FF73F26F10089EULL,
		0x203A5A54BCE53B8BULL,
		0x687459F8ED345B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623E4F1732FFCAF8ULL,
		0xDB0CF6CB7627B1A0ULL,
		0x68D4C02825ABEAB1ULL,
		0x0DAE2C39B310BA19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31D51D4C00A58091ULL,
		0x27F27D26F8E856FEULL,
		0xB7659A2C973950D9ULL,
		0x5AC62DBF3A23A0E9ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC32A7CCFA71831ULL,
		0x3D6735CB790D4620ULL,
		0xBD78DC74E1EBC053ULL,
		0x48DEB2DB3CD73839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22720693598EE91FULL,
		0xCC56C07F5987FD27ULL,
		0x9065C5B83187AB55ULL,
		0x583F16E8A5FEE526ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A5123E976182EFFULL,
		0x7110754C1F8548F9ULL,
		0x2D1316BCB06414FDULL,
		0x709F9BF296D85313ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10B1FD8A086BD382ULL,
		0xEEF403016C8CCC08ULL,
		0x6159A1BF4F39364FULL,
		0x19EEA8B8C8851C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49FC0C5B9F7B06BCULL,
		0x93ADE26FBF3F6CE3ULL,
		0xBE5B198AF6B20692ULL,
		0x15B28196E960C32DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6B5F12E68F0CCC6ULL,
		0x5B462091AD4D5F24ULL,
		0xA2FE883458872FBDULL,
		0x043C2721DF245940ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E258442AEA8088AULL,
		0xD006BEBF9983D8D4ULL,
		0x8F4CD5776D004096ULL,
		0x559ACDA95E687AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98874CB85A816577ULL,
		0x6E88F73D8828CB4BULL,
		0x6B9D0D5E3BE143C2ULL,
		0x340198D2E1E9F68EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD59E378A5426A313ULL,
		0x617DC782115B0D88ULL,
		0x23AFC819311EFCD4ULL,
		0x219934D67C7E8467ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EA7EA9535F5EDC6ULL,
		0xE49CEAAE68BD5749ULL,
		0x762DF7DF205E351BULL,
		0x6547889F03189688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBF874A973ACF633ULL,
		0xD63A945794B2F3A5ULL,
		0x3F6A058162666849ULL,
		0x2BBEFF64EE4F5A7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82AF75EBC248F793ULL,
		0x0E625656D40A63A3ULL,
		0x36C3F25DBDF7CCD2ULL,
		0x3988893A14C93C0AULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x457BAF98A5710CC3ULL,
		0x5114B4BCB10686B5ULL,
		0xA7C08E25EDB53011ULL,
		0x0BCF6274C5994CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x822DB1533BE72FADULL,
		0x84617922F0BA2D2AULL,
		0x901D00EA0D26087BULL,
		0x00340744D2574EFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC34DFE456989DD16ULL,
		0xCCB33B99C04C598AULL,
		0x17A38D3BE08F2795ULL,
		0x0B9B5B2FF341FDF9ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05BBDAD1138B8FB8ULL,
		0x558B6480C4634DBBULL,
		0x2DEF44789299C66BULL,
		0x5274B3713F5D4C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17E13B9FD7B1A22FULL,
		0x6361C94BA04A9154ULL,
		0xCBDC360A87895A72ULL,
		0x7C4940998E2F4EB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDDA9F313BD9ED76ULL,
		0xF2299B352418BC66ULL,
		0x62130E6E0B106BF8ULL,
		0x562B72D7B12DFDE1ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCD3DA1892508E78ULL,
		0xD8964505184F28F9ULL,
		0xA451BCE7501895E6ULL,
		0x4C9743B28A725B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD467E8181C0419DCULL,
		0x8B8EDD268786C821ULL,
		0x22D29FCAFF780967ULL,
		0x1A77D4F7B0631889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE86BF200764C749CULL,
		0x4D0767DE90C860D7ULL,
		0x817F1D1C50A08C7FULL,
		0x321F6EBADA0F4315ULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x116945F6D75C8DCCULL,
		0x8D3766A964435884ULL,
		0x216E3273B9DE2D0DULL,
		0x4CDCE88379CF3092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5FAD80D26E37CBFULL,
		0x87D7915A8B3B933BULL,
		0x94C81ECB921062EFULL,
		0x078BB1ABD59BC6A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B6E6DE9B079110DULL,
		0x055FD54ED907C548ULL,
		0x8CA613A827CDCA1EULL,
		0x455136D7A43369E9ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E31639D0F9E80C0ULL,
		0x569C924189FD7CB1ULL,
		0xBD3C6ECA957BD0EEULL,
		0x08ADDEB7AF3E5295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55953936BC2D6590ULL,
		0x3C77EB233BC16703ULL,
		0xDEFF5E35338519CEULL,
		0x11DC294AB245ABDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB89C2A6653711B1DULL,
		0x1A24A71E4E3C15ADULL,
		0xDE3D109561F6B720ULL,
		0x76D1B56CFCF8A6BAULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x816372CD39DF47E2ULL,
		0x5FEAADEE5B710324ULL,
		0xFB4AF598C2C05799ULL,
		0x24C78B3D158B9CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81BB6910BBCEFEC2ULL,
		0x8E5E7CEC945A9775ULL,
		0x1A1F06C3FAA58206ULL,
		0x75AA278B712ED4ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFA809BC7E10490DULL,
		0xD18C3101C7166BAEULL,
		0xE12BEED4C81AD592ULL,
		0x2F1D63B1A45CC7CFULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B0946B8295F490CULL,
		0x396F06E4D5076741ULL,
		0x942AE92471F92E7EULL,
		0x6CE966EEF2AFC88AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F7EDAEAC0328A2DULL,
		0x2B6CD671974C85E6ULL,
		0xF13DC30D336C7EF5ULL,
		0x2FAB9D53128FB08DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB8A6BCD692CBEDFULL,
		0x0E0230733DBAE15AULL,
		0xA2ED26173E8CAF89ULL,
		0x3D3DC99BE02017FCULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA77F52CC0E3BFF06ULL,
		0x7C487B8E20748F44ULL,
		0x9E70FFEF1DDDD453ULL,
		0x0D3065C8CADF3A65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B8B4E5EF8A596DULL,
		0xA1B3864BF49813C1ULL,
		0x3BD171BAE7973949ULL,
		0x0A69CB6E77EDC051ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13C69DE61EB1A599ULL,
		0xDA94F5422BDC7B83ULL,
		0x629F8E3436469B09ULL,
		0x02C69A5A52F17A14ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0A2EE8C074290A9ULL,
		0x26DB7EB323260A8DULL,
		0x48DDAA761D57F4D0ULL,
		0x7067AC14919E88EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x127661D57FB9B394ULL,
		0xED7EE5075F4C4424ULL,
		0xA0FCD5510BFA61A8ULL,
		0x20045059E71E2AC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E2C8CB68788DD15ULL,
		0x395C99ABC3D9C669ULL,
		0xA7E0D525115D9327ULL,
		0x50635BBAAA805E26ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90E3A7928CEEAC90ULL,
		0xF4647F879B8FC015ULL,
		0x969493F78907F647ULL,
		0x2C96084492E159C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067217EFCC56F4C9ULL,
		0x8C4EDCDCCD44B298ULL,
		0xDBFD8E209B6AAF08ULL,
		0x682B5CE956C4BFA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A718FA2C097B7B4ULL,
		0x6815A2AACE4B0D7DULL,
		0xBA9705D6ED9D473FULL,
		0x446AAB5B3C1C9A21ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33BF728E82B5A3AEULL,
		0xB32A170FE828C24AULL,
		0x488871E6BA3E6CD2ULL,
		0x09C8DB9349C8DD29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BC82A1CDEE0CF9DULL,
		0x61C470B88C95FB0AULL,
		0x11DF03AA1BD0E686ULL,
		0x6D3A5D7A0BAE59FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7F74871A3D4D3FEULL,
		0x5165A6575B92C73FULL,
		0x36A96E3C9E6D864CULL,
		0x1C8E7E193E1A832BULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7849A8AB6DE46233ULL,
		0x22F62CA173312F56ULL,
		0x8B1E2FF2D0872DEAULL,
		0x30F7F72C9BA03501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x973F6AD802FEC58DULL,
		0x9ADA813D8FDCFECAULL,
		0xE7AB74EEBCF8DB6EULL,
		0x7CBEE4ADCFBAB012ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE10A3DD36AE59C93ULL,
		0x881BAB63E354308BULL,
		0xA372BB04138E527BULL,
		0x3439127ECBE584EEULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6571485F4D7502BULL,
		0x39B5C0A85A976344ULL,
		0xDB019EA90D4683C3ULL,
		0x5B16427862CFF527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF186B2B052F5077AULL,
		0x0BC8CAE5D67DFE10ULL,
		0xA41052522A35EC25ULL,
		0x59FC7BDCD31C9902ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4D061D5A1E248B1ULL,
		0x2DECF5C284196533ULL,
		0x36F14C56E310979EULL,
		0x0119C69B8FB35C25ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4BA53F6E3625B2CULL,
		0x702C6DF5A2D7CE76ULL,
		0xEA5EB5741B165D7FULL,
		0x571C0139128C2924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F5E2898A507F91ULL,
		0x78F9AF352B3530DCULL,
		0x03DEF38DD5D0A973ULL,
		0x619BA07FEFC775A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C4716D5911DB88ULL,
		0xF732BEC077A29D9AULL,
		0xE67FC1E64545B40BULL,
		0x758060B922C4B381ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C64BD1B7269ACACULL,
		0x0DD37ACF39ED228FULL,
		0xF7858F67DC2E6380ULL,
		0x72CFFDCBCBD40661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC10627B89F1DD3ULL,
		0xDA2C8D4D1FE4EADDULL,
		0xF910DB67E71A600CULL,
		0x75897A73D5E3087FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA3B6F3B9CA8EC6ULL,
		0x33A6ED821A0837B1ULL,
		0xFE74B3FFF5140373ULL,
		0x7D468357F5F0FDE1ULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF74C1C4ACB4786DULL,
		0xE800C338511E86FBULL,
		0x849A4ABE3F68C592ULL,
		0x720778045E35A5E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB04721945C5B5E6AULL,
		0xBCBD362B41F2BDF3ULL,
		0x1D10995D04DBFE68ULL,
		0x06D19B025A2B5023ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F2DA03050591A03ULL,
		0x2B438D0D0F2BC908ULL,
		0x6789B1613A8CC72AULL,
		0x6B35DD02040A55C2ULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B8BFF2B994DCD1CULL,
		0xCF25B5DD95C74F18ULL,
		0x1515B4250B072B4BULL,
		0x094FAF5A18BB2964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ABD7CD87DBB25AFULL,
		0x23AF87714A28B57FULL,
		0xB255EE9B8B40C1A6ULL,
		0x615C09E9AAE50FAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0CE82531B92A75AULL,
		0xAB762E6C4B9E9998ULL,
		0x62BFC5897FC669A5ULL,
		0x27F3A5706DD619B9ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x971F4F29B36D0321ULL,
		0xEFB188C633644F29ULL,
		0x82010102C170C144ULL,
		0x01CAF28781C0E11DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F1703D5F50A89DULL,
		0x2B8F941D8432C4EFULL,
		0xE8ACC4C32C01D9F1ULL,
		0x658E00705E21FA1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD62DDEEC541C5A71ULL,
		0xC421F4A8AF318A39ULL,
		0x99543C3F956EE753ULL,
		0x1C3CF217239EE6FFULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4A8AB2656BC6B99ULL,
		0xF835E413FE0B75E5ULL,
		0x7165FD0B896C9191ULL,
		0x3119BDFD0DA10DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB85C45D107BD7DCULL,
		0x382BB4A5D9F1566DULL,
		0x52000D179838FE27ULL,
		0x20E93C6FCA10FF28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE922E6C9464093BDULL,
		0xC00A2F6E241A1F77ULL,
		0x1F65EFF3F133936AULL,
		0x1030818D43900E94ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA77B76A8BB880A44ULL,
		0xE4F4BD1309E19A7FULL,
		0x6266E54F960EDF8FULL,
		0x768DBC8EE6D1D7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCB8226734634FA9ULL,
		0x88C1E6BD3F41645CULL,
		0x8144D2C732A6387EULL,
		0x1B519DBA1DA07A32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAC354418724BA9BULL,
		0x5C32D655CAA03622ULL,
		0xE12212886368A711ULL,
		0x5B3C1ED4C9315DC7ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4CA13AB66C284CDULL,
		0xDCCECF70E90487E0ULL,
		0xE462288E91A681C4ULL,
		0x4187D98E06C70EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x274D9F0AFC93FA66ULL,
		0x5A76ED1870233617ULL,
		0x4ACDE1A3F7CB4060ULL,
		0x603726980CA56449ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D7C74A06A2E8A54ULL,
		0x8257E25878E151C9ULL,
		0x999446EA99DB4164ULL,
		0x6150B2F5FA21AA68ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x884F8748ECE76DDCULL,
		0x0DB58F675204E172ULL,
		0xE763E5855383CE48ULL,
		0x4E96CC61B4CF5355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAEF2C120006ACDULL,
		0xB14731BFE4F870E4ULL,
		0x9744F100069D9406ULL,
		0x560D3C4E9E963023ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9A09487CCE702FCULL,
		0x5C6E5DA76D0C708DULL,
		0x501EF4854CE63A41ULL,
		0x7889901316392332ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5597C3276B51F5ULL,
		0x73787C85D2E112E6ULL,
		0x28DEADE4A1A54536ULL,
		0x5EC0B2EAD9FBC95BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E7A71C1385B46FULL,
		0x43E3A09A9A93593CULL,
		0x1645CB639FBC93CBULL,
		0x089B61A9FF808DD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC76DF0A713E59D86ULL,
		0x2F94DBEB384DB9AAULL,
		0x1298E28101E8B16BULL,
		0x56255140DA7B3B8AULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB22DD938500830ADULL,
		0x48BDE5397C80493EULL,
		0x9E13D847E6B22932ULL,
		0x0A7AC273D86A21CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8935D4299FAD85ULL,
		0xB9D04623C0D02768ULL,
		0xCA46A45014688D9EULL,
		0x58DA8E271A868309ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47A4A36426688315ULL,
		0x8EED9F15BBB021D6ULL,
		0xD3CD33F7D2499B93ULL,
		0x31A0344CBDE39EC5ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7152D7C086F79ADULL,
		0x911FF363DC7874B8ULL,
		0xED96717891DDA1E1ULL,
		0x57C1264DE0DF16E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FAFA357E9BB650DULL,
		0x1F3C2250CB6E657BULL,
		0xC6ABCC1B1C67BC45ULL,
		0x0546CD50DFEDC47BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67658A241EB414A0ULL,
		0x71E3D113110A0F3DULL,
		0x26EAA55D7575E59CULL,
		0x527A58FD00F1526CULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77763B91980613F1ULL,
		0xE27F989B07C9636EULL,
		0x0E961314AAAEDADEULL,
		0x59BB572847D74CCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DAB76616D457831ULL,
		0x30E61B78787726C5ULL,
		0x192B9D0F69A29174ULL,
		0x28A9C834FF4A380CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69CAC5302AC09BC0ULL,
		0xB1997D228F523CA9ULL,
		0xF56A7605410C496AULL,
		0x31118EF3488D14C1ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF2FE25BDB27E1D6ULL,
		0x5B383AAF96E0959BULL,
		0x3E5A0EB37CA62053ULL,
		0x4573D1EA1A9ABEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A866414F31CC0C3ULL,
		0xEC57ABD38C870712ULL,
		0x8296731DAF01127EULL,
		0x224CF553124A76C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44A97E46E80B2113ULL,
		0x6EE08EDC0A598E89ULL,
		0xBBC39B95CDA50DD4ULL,
		0x2326DC9708504819ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B6D1FABA7174D9CULL,
		0xCBE8BF112F5E65E3ULL,
		0x510C8BDD0D0C5ADCULL,
		0x4FC6798901774D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x343B3B039C7235BDULL,
		0x5443A819CBFE5C99ULL,
		0x78D27738EB23F81FULL,
		0x03213AC71C65F6C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0731E4A80AA517DFULL,
		0x77A516F76360094AULL,
		0xD83A14A421E862BDULL,
		0x4CA53EC1E51156D0ULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE73177A82961CB9FULL,
		0xE2313E6142EFF647ULL,
		0x7A98873ED8B61F54ULL,
		0x055731F2BCC45CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF133B077D4476AC1ULL,
		0x228BA82E5C46AD6EULL,
		0x37592CCDFC672839ULL,
		0x56DC81A88B878F34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5FDC730551A60CBULL,
		0xBFA59632E6A948D8ULL,
		0x433F5A70DC4EF71BULL,
		0x2E7AB04A313CCDABULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF5A56F2DB7E538DULL,
		0xB61D5D44B1DAC647ULL,
		0x7098FE43D3CE381CULL,
		0x3ECC85A2D3FE6747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45E00FC4C83E7C13ULL,
		0xDEB4A4258BC96218ULL,
		0xC572DB2D9A073D43ULL,
		0x6FDAA9B3D75B38A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x697A472E133FD767ULL,
		0xD768B91F2611642FULL,
		0xAB26231639C6FAD8ULL,
		0x4EF1DBEEFCA32EA6ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9DE2D49940629ACULL,
		0x60FF9C1F98AE7D28ULL,
		0xC4AB22069C0987ACULL,
		0x4B271DD96D8D3625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3637E8507C778F1FULL,
		0xBA4BABDAD64152E3ULL,
		0x4A20994CB8977BBDULL,
		0x76B8E4EAD3301871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A644F9178E9A7AULL,
		0xA6B3F044C26D2A45ULL,
		0x7A8A88B9E3720BEEULL,
		0x546E38EE9A5D1DB4ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BC9E6183BB87B98ULL,
		0x8085E99C695DBDABULL,
		0xEA5C6FFFE46E328EULL,
		0x6A6F796C1402E073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F2E27393827640AULL,
		0x38B6F28E93BAE7C9ULL,
		0xED5AA2BDF9014F34ULL,
		0x46419BF2C0B9D758ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C9BBEDF0391178EULL,
		0x47CEF70DD5A2D5E1ULL,
		0xFD01CD41EB6CE35AULL,
		0x242DDD795349091AULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DC3DDBA4E7B185FULL,
		0x58DB3FA6375864ADULL,
		0x8656D5B9DFA87783ULL,
		0x2311D4E1D2574318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2CFBC7ECAD45184ULL,
		0x7E812507737AA4C8ULL,
		0x19E373039F070712ULL,
		0x1009D58347667BE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF4213B83A6C6DBULL,
		0xDA5A1A9EC3DDBFE4ULL,
		0x6C7362B640A17070ULL,
		0x1307FF5E8AF0C732ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4F799BC531D16FAULL,
		0xD6268CAD679663A9ULL,
		0x8FA8F656D5D75DABULL,
		0x7BC141182F6EFC34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8D27E5444CB4264ULL,
		0xD594D03DF4550F54ULL,
		0x6BD272A70636C1C7ULL,
		0x4901E0988ACF0633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C251B680E51D496ULL,
		0x0091BC6F73415455ULL,
		0x23D683AFCFA09BE4ULL,
		0x32BF607FA49FF601ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x836C00ACF48E12D9ULL,
		0xBFC41455FAA76D21ULL,
		0x4BCF8EF54F030CF4ULL,
		0x7EBAB8E7E15A7DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF26ECDCFCD46B855ULL,
		0x0F9A63BCFE319667ULL,
		0xF0AE481A6C9710FBULL,
		0x5A6056788AF05F59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90FD32DD27475A84ULL,
		0xB029B098FC75D6B9ULL,
		0x5B2146DAE26BFBF9ULL,
		0x245A626F566A1E94ULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A69F90BF5BAD2A4ULL,
		0xEC2F6CE6C8ED402EULL,
		0x0C79F922431451C2ULL,
		0x0CA7FFF62143FD2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56601A941C1628D6ULL,
		0x956ED90CF2D2370CULL,
		0x053ECFB0731BAC75ULL,
		0x6A051ADA8CB9B773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD409DE77D9A4A9BBULL,
		0x56C093D9D61B0921ULL,
		0x073B2971CFF8A54DULL,
		0x22A2E51B948A45B9ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE42FF891365F4C15ULL,
		0x7ADF940FD4D7F8EFULL,
		0xB7F8AD47A8F306DEULL,
		0x24477936754D2AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76FD0A0C1E2BA65EULL,
		0x3C8C3AC8EE88A9F3ULL,
		0xB79B86CD88D8C3D4ULL,
		0x3DCDDFF9EE71204AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D32EE851833A5A4ULL,
		0x3E535946E64F4EFCULL,
		0x005D267A201A430AULL,
		0x6679993C86DC0A5FULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CCE6F58E08ABCBCULL,
		0xCBE74E0AB54F0603ULL,
		0x0D60CF786E8ABC43ULL,
		0x534419E4D83479F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB5C29E2E371A36DULL,
		0x143148048BF664D6ULL,
		0x11B41C022F6BE330ULL,
		0x5AD37FD7E9132933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51724575FD19193CULL,
		0xB7B606062958A12CULL,
		0xFBACB3763F1ED913ULL,
		0x78709A0CEF2150C1ULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE81495D7E9A81335ULL,
		0xA1CB0C42CA84A334ULL,
		0x14951C2476A33C72ULL,
		0x6D0DDFB981655E1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED1E7E9305BA86D1ULL,
		0xCD2C604009583547ULL,
		0xB26F47C4C65B698EULL,
		0x69E64AD3A23B3714ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAF61744E3ED8C64ULL,
		0xD49EAC02C12C6DECULL,
		0x6225D45FB047D2E3ULL,
		0x032794E5DF2A2705ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F1BF06DF52F1E2ULL,
		0xFD4C077B79C09E4DULL,
		0x4F6AAA097C04EAAEULL,
		0x7E4FDF05CEF6E773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0302790B037BE7ULL,
		0x358FF27CD9D5F7AEULL,
		0x508E894E118CFA5EULL,
		0x4B940D9A6273A970ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38EEBC8DD44F75FBULL,
		0xC7BC14FE9FEAA69FULL,
		0xFEDC20BB6A77F050ULL,
		0x32BBD16B6C833E02ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC081816FC1B6DE7EULL,
		0xD57A0267DA13C1A2ULL,
		0x1D88922F258DD2FBULL,
		0x6936BE16D81B2091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5CBA891E667506ULL,
		0x1BF623423E08B674ULL,
		0x4E9019403BD2BA36ULL,
		0x5AAD962A22017743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8124C6E6A3506978ULL,
		0xB983DF259C0B0B2EULL,
		0xCEF878EEE9BB18C5ULL,
		0x0E8927ECB619A94DULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA10820ADCBD907A4ULL,
		0x09948B90739FB0B7ULL,
		0x01BD125A39965C65ULL,
		0x583C50F4A85E0A77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623E51ABA70AEDE8ULL,
		0x1075D4FE540DA490ULL,
		0x25F42C5AA420DC73ULL,
		0x2564460AA71FA032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EC9CF0224CE19BCULL,
		0xF91EB6921F920C27ULL,
		0xDBC8E5FF95757FF1ULL,
		0x32D80AEA013E6A44ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1CE13323814F809CULL,
		0x31D545D5D48C2197ULL,
		0x7EAA76666C044071ULL,
		0x2506DB7B86C7E2CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DD4F52126899E56ULL,
		0x78908F27F4E22941ULL,
		0xE9D5DD24DF79FA59ULL,
		0x114822579A69BB3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F0C3E025AC5E246ULL,
		0xB944B6ADDFA9F856ULL,
		0x94D499418C8A4617ULL,
		0x13BEB923EC5E2793ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x688DFC5854DA753FULL,
		0xAD4FD8D9FA5C65B2ULL,
		0x2B0C5D9616FD1919ULL,
		0x29104B59B94485DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B60B559980C66A2ULL,
		0x8B3A5ACC1695A562ULL,
		0xAA9BD929AFE23448ULL,
		0x4FD935A15FDA3AE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D2D46FEBCCE0E8AULL,
		0x22157E0DE3C6C050ULL,
		0x8070846C671AE4D1ULL,
		0x593715B8596A4AF2ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95D7DEFF2FE998DBULL,
		0x9A6E71E2DB80DCAFULL,
		0x9272327ABE891DB9ULL,
		0x31C424B894A2A447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB15860E1403E2F68ULL,
		0x22F99A625F599EF2ULL,
		0x5492CA8DB0B958D1ULL,
		0x7CD1E27BA5A36C59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE47F7E1DEFAB6960ULL,
		0x7774D7807C273DBCULL,
		0x3DDF67ED0DCFC4E8ULL,
		0x34F2423CEEFF37EEULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E2B8E3776F820C7ULL,
		0xA1D3115669E06AA3ULL,
		0x3135ACA81BB854DAULL,
		0x77079B967341DBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4099880F7E4E4734ULL,
		0x915FAC77560CC5E8ULL,
		0xD01C24B7ED5541CFULL,
		0x4AB3C026B2EF0704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED920627F8A9D993ULL,
		0x107364DF13D3A4BAULL,
		0x611987F02E63130BULL,
		0x2C53DB6FC052D4C9ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AB7DA372ABC9F44ULL,
		0x1D3B7947A148957EULL,
		0xE45635CE170246BAULL,
		0x19568E29E4FDC7A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EFAD8CF06D75CEULL,
		0xD5312A62383B0CF8ULL,
		0xC159DB5C09747CB7ULL,
		0x671A2DE9F6255B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22C82CAA3A4F2963ULL,
		0x480A4EE5690D8886ULL,
		0x22FC5A720D8DCA02ULL,
		0x323C603FEED86C07ULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF744DC0F9A4D609ULL,
		0xDCB058DA6BED11B8ULL,
		0x4E4DEB907E349225ULL,
		0x16FA7294B0A46C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x832A7657DC945574ULL,
		0x1F7CE5DE02C02474ULL,
		0x625362579FD754A2ULL,
		0x218BC73D661F11BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C49D7691D108082ULL,
		0xBD3372FC692CED44ULL,
		0xEBFA8938DE5D3D83ULL,
		0x756EAB574A855A90ULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E5230A6C07BF12BULL,
		0x63FCDC99655ECF40ULL,
		0x6A4E5EAACD425C8EULL,
		0x53AD3D31F888A93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x116F840ED6229E77ULL,
		0x13BA6ADD4946BB3FULL,
		0xCF3CCAAFD8D70ECEULL,
		0x322A735C7377C736ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CE2AC97EA5952B4ULL,
		0x504271BC1C181401ULL,
		0x9B1193FAF46B4DC0ULL,
		0x2182C9D58510E208ULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5541D1DC7BF3EDD0ULL,
		0xCABF1C77CCC9CA39ULL,
		0xBAF89A8F5293729EULL,
		0x5BD0F7E8D3D157A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6620D33D1713EF1ULL,
		0x2B159CE6ED7FC3A4ULL,
		0x018A431008BD0EC4ULL,
		0x1E780A883566DF14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EDFC4A8AA82AEDFULL,
		0x9FA97F90DF4A0694ULL,
		0xB96E577F49D663DAULL,
		0x3D58ED609E6A7895ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6C291E94E89DF1BULL,
		0x1F614F36DB6CF4C7ULL,
		0x602F8465833F8A8FULL,
		0x74E7EA8B389DD81EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D1BEA2B88A860D8ULL,
		0x3CFC159F3C75B976ULL,
		0xC85749F3882C0773ULL,
		0x596C04B6EE11132EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89A6A7BDC5E17E43ULL,
		0xE26539979EF73B51ULL,
		0x97D83A71FB13831BULL,
		0x1B7BE5D44A8CC4EFULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x628AE1C47A366741ULL,
		0x65FDF9281793D605ULL,
		0x42307D5FD37CB8C0ULL,
		0x6B8C606FA0D973DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8059CBE9D1B27E40ULL,
		0x46F48426A950B3E3ULL,
		0xAEE4BF79B29482F2ULL,
		0x50F5683EC8B51134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE23115DAA883E901ULL,
		0x1F0975016E432221ULL,
		0x934BBDE620E835CEULL,
		0x1A96F830D82462A6ULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933F01502F4F10D0ULL,
		0x83C548F3BC37F658ULL,
		0xC73E221031F9BC9DULL,
		0x6A17A1D4A0AFFEADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E9D131C9D8C16DULL,
		0x82B61D98680966BDULL,
		0xB46DA9A3769AA806ULL,
		0x6717B91C775FB690ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A55301E65764F63ULL,
		0x010F2B5B542E8F9BULL,
		0x12D0786CBB5F1497ULL,
		0x02FFE8B82950481DULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x466570306E372F53ULL,
		0xB5BDC1F1D1F194CBULL,
		0x95179A3209F5B40DULL,
		0x57A22074140854DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B37E191D1655681ULL,
		0x506C316AE70AF537ULL,
		0xF260D749637CC37EULL,
		0x420C6F8C45D0FCEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B2D8E9E9CD1D8D2ULL,
		0x65519086EAE69F94ULL,
		0xA2B6C2E8A678F08FULL,
		0x1595B0E7CE3757F4ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4F639C6D88D254BULL,
		0x10389F393B35D467ULL,
		0x75292B586E6AFB19ULL,
		0x613F3A69ADC8BF49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54211498A1007A8FULL,
		0xBAFCF60F29FCB6EFULL,
		0xD2A5264BB1E2F26AULL,
		0x6A88FF4EE15E287AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90D5252E378CAAA9ULL,
		0x553BA92A11391D78ULL,
		0xA284050CBC8808AEULL,
		0x76B63B1ACC6A96CEULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51FF3381375874F2ULL,
		0xF7A0FCCAFE1A790DULL,
		0xE79787D98AA2AAF7ULL,
		0x16BDD656C81ED87FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F4F31097EA48567ULL,
		0x78402375383DCBB9ULL,
		0x3A234952C5F24D96ULL,
		0x6077D35288AE8797ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2B00277B8B3EF78ULL,
		0x7F60D955C5DCAD53ULL,
		0xAD743E86C4B05D61ULL,
		0x364603043F7050E8ULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0389D4EFEB909347ULL,
		0x765C54887FD4E1B3ULL,
		0x7F4512931B0E17D0ULL,
		0x0F01821D9F32DF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA206C1CE1ED2EE4BULL,
		0x3A956C7CE91E3A82ULL,
		0xCE7A4124BE889E82ULL,
		0x16EF0FEEE881C36AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61831321CCBDA4E9ULL,
		0x3BC6E80B96B6A730ULL,
		0xB0CAD16E5C85794EULL,
		0x7812722EB6B11BB4ULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38AF0F79B13D5264ULL,
		0x743C5470C6BA0A6DULL,
		0xA7BBC0A189DCB56CULL,
		0x6208BD45C88F55B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB01829F6546BEAULL,
		0x863A255651517497ULL,
		0xD1969B749D9000A7ULL,
		0x224A318BC953E53CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98FEF74FBAE8E67AULL,
		0xEE022F1A756895D5ULL,
		0xD625252CEC4CB4C4ULL,
		0x3FBE8BB9FF3B7077ULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C60924D4F1349BULL,
		0x43C22A8D515D8CDEULL,
		0x289306CC6ABC3F07ULL,
		0x4E9B79EC3F862407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49B6928DABA993A1ULL,
		0x0C8833D31E2A390CULL,
		0x1B48309228B71A51ULL,
		0x43F882B6173A0325ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x290F76972947A0FAULL,
		0x3739F6BA333353D2ULL,
		0x0D4AD63A420524B6ULL,
		0x0AA2F736284C20E2ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97B4A30505C41E9DULL,
		0xC0A216C7ACCB6FD5ULL,
		0xDA0181DB38E7E6CFULL,
		0x278311E6545C444BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458766B092088E15ULL,
		0x04DA5684E4AF83FEULL,
		0xA746120A7054ECFDULL,
		0x408ADDC08B7CF5BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x522D3C5473BB9075ULL,
		0xBBC7C042C81BEBD7ULL,
		0x32BB6FD0C892F9D2ULL,
		0x66F83425C8DF4E8FULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8B933A8A0CF9F01ULL,
		0x47FF4140F39CDDA1ULL,
		0x3DF414E2AB3EF472ULL,
		0x063B42D25CF367D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14787EA1BA64C13EULL,
		0xC423FA385291BEE6ULL,
		0xFA168379AFC62CE7ULL,
		0x5A5FC861738B1323ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE440B506E66ADDB0ULL,
		0x83DB4708A10B1EBBULL,
		0x43DD9168FB78C78AULL,
		0x2BDB7A70E96854B3ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6871853EC1C11A6ULL,
		0xDE311C835BE2063AULL,
		0x562C5D531440AD6DULL,
		0x69FB42C8322BA018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55438EFEDFBD1411ULL,
		0x1C63365B997C448DULL,
		0x49A396BD6ED14399ULL,
		0x1470B54E38C00C36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x614389550C5EFD95ULL,
		0xC1CDE627C265C1ADULL,
		0x0C88C695A56F69D4ULL,
		0x558A8D79F96B93E2ULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x490A34F01619C96FULL,
		0xDC400E907AA06FFCULL,
		0x1D595AA2681E5F5DULL,
		0x0EA72FF409C77A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F720B2606D25AFFULL,
		0xE1922390F29DE1DFULL,
		0x4C0245F3015B0E6AULL,
		0x5E982A4F1EF6C48FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE99829CA0F476E5DULL,
		0xFAADEAFF88028E1CULL,
		0xD15714AF66C350F2ULL,
		0x300F05A4EAD0B5D8ULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA92AB9F2AE9A54DAULL,
		0x12485098891CFF03ULL,
		0x06878E8B7405D9C3ULL,
		0x1D84B62A70E53336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41C630FC9CB86054ULL,
		0xAEEDA9976C238D1BULL,
		0x7F897ED9C23667F7ULL,
		0x305B6FD2D78330CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x676488F611E1F473ULL,
		0x635AA7011CF971E8ULL,
		0x86FE0FB1B1CF71CBULL,
		0x6D2946579962026BULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FAF5DE89027B014ULL,
		0x34EC51A28A790BC3ULL,
		0xA1D6FD7DE62D81CAULL,
		0x11DC6E500165A994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F87B4FDE5ADAA09ULL,
		0x60498F27D7049993ULL,
		0x6A25DA8D4C354E82ULL,
		0x2BCD748DB5DDC358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF027A8EAAA7A05F8ULL,
		0xD4A2C27AB374722FULL,
		0x37B122F099F83347ULL,
		0x660EF9C24B87E63CULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D11473FBF46D4FFULL,
		0xD934D99A31EA30E7ULL,
		0x9E619507C936A2F9ULL,
		0x7A95D1411381296CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D12509C75BBB69ULL,
		0xB84D950DD27E97F0ULL,
		0xE6B1ADF25D296C20ULL,
		0x31862110954F7B61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27402235F7EB1996ULL,
		0x20E7448C5F6B98F7ULL,
		0xB7AFE7156C0D36D9ULL,
		0x490FB0307E31AE0AULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1852D62F4C9A803ULL,
		0x7429BA4FD9437466ULL,
		0xFEB0E4528CE62CE9ULL,
		0x39359A75A9B07B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8583D955EA2D466EULL,
		0x369C0A178013F0D8ULL,
		0xEDB83E304C1BA18BULL,
		0x582F16418175B1AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C01540D0A9C6182ULL,
		0x3D8DB038592F838EULL,
		0x10F8A62240CA8B5EULL,
		0x61068434283AC9A3ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44AD7412E671D672ULL,
		0xE7F265DE892E18A4ULL,
		0x7FF2FF3CC93F7B2AULL,
		0x142171674C60AB5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD74BD1B9AD707EF6ULL,
		0x20497C1323E91969ULL,
		0x6AD980A0C9C72D60ULL,
		0x15806DA1A57773E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D61A25939015769ULL,
		0xC7A8E9CB6544FF3AULL,
		0x15197E9BFF784DCAULL,
		0x7EA103C5A6E93779ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C046A8E8E5EBFD4ULL,
		0xFC8933FD987AF1B0ULL,
		0x266E96EDB604B041ULL,
		0x617D0F9B65F7364BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x354C019DAB71EBECULL,
		0xD6F19A1246EACF11ULL,
		0x799E79CC0DA19EC9ULL,
		0x56DD31FA59A0A6BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6B868F0E2ECD3E8ULL,
		0x259799EB5190229EULL,
		0xACD01D21A8631178ULL,
		0x0A9FDDA10C568F90ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DCB5A1ECE18BA45ULL,
		0x1E9A5231B5C8D7C7ULL,
		0x140051E1542BF262ULL,
		0x19EEB3EC8A2AF569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC77214DD9A193F14ULL,
		0xBCDCAE7CCEAF87BFULL,
		0x77151624274413E9ULL,
		0x51F1FFAACCB0F6A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5659454133FF7B1EULL,
		0x61BDA3B4E7195007ULL,
		0x9CEB3BBD2CE7DE78ULL,
		0x47FCB441BD79FEC6ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA1D3DC549124C35ULL,
		0xBD08C6187FBDA877ULL,
		0xFFAE1A9DE2284B7AULL,
		0x22F2F2D0020960EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C9902EFD1B1D09EULL,
		0x9047282721170A40ULL,
		0xFB3790333E61F2E2ULL,
		0x4ED486B5CAD79DDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D843AD577607B84ULL,
		0x2CC19DF15EA69E37ULL,
		0x04768A6AA3C65898ULL,
		0x541E6C1A3731C312ULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFFC4F81E553980BULL,
		0xFD7E8C7CE9A335BCULL,
		0x2BBF1EE3CDA29465ULL,
		0x01BACAADFC97A108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ED525A988CAC712ULL,
		0xEE33E9673EB4CBB0ULL,
		0x45B2BC39F085C599ULL,
		0x48944CF1EA2696D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x412729D85C88D0E6ULL,
		0x0F4AA315AAEE6A0CULL,
		0xE60C62A9DD1CCECCULL,
		0x39267DBC12710A36ULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD39C1AE07AFABEF9ULL,
		0x136251CADF6DEE19ULL,
		0xCAAC5D5C6E80DCA2ULL,
		0x6619CD5FF89F06E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52BC96298AF5C92CULL,
		0xB44AE4FC1265687FULL,
		0xD4FDB9F9C50E6403ULL,
		0x58CC9DB4DB930E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80DF84B6F004F5CDULL,
		0x5F176CCECD08859AULL,
		0xF5AEA362A972789EULL,
		0x0D4D2FAB1D0BF8B6ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF25626F309AB19D1ULL,
		0xBF5D27E88EB6107EULL,
		0xAFCA21C9A6B860C5ULL,
		0x162D197DEAD8FAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279101C4BA14613DULL,
		0xDFB46D02319230CFULL,
		0x54ECC85C9ECB9372ULL,
		0x52C11B2EBBCA7130ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAC5252E4F96B881ULL,
		0xDFA8BAE65D23DFAFULL,
		0x5ADD596D07ECCD52ULL,
		0x436BFE4F2F0E89C4ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64075228F2F16FA6ULL,
		0x0A9B20711C24185DULL,
		0xBE1FBC3636B2F034ULL,
		0x694C528E76EC63E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB3E292A6C774BBULL,
		0xDB2D0DF5B4FCD0C1ULL,
		0xE567B93C23AFDCA2ULL,
		0x0301E79785E28BECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8536F964C29FAEBULL,
		0x2F6E127B6727479BULL,
		0xD8B802FA13031391ULL,
		0x664A6AF6F109D7F5ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CB16FC9D25AD86EULL,
		0x0108515B9E31C56FULL,
		0x8130D7F390E0889FULL,
		0x2DD523A8C1DB8AAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71CC18C0F6A16720ULL,
		0xEB911684C1D52AF6ULL,
		0x7DAC509B62743E66ULL,
		0x71D6F6DE5EC5FE37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AE55708DBB9713BULL,
		0x15773AD6DC5C9A79ULL,
		0x038487582E6C4A38ULL,
		0x3BFE2CCA63158C73ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92E9E714930CA8F6ULL,
		0x95D4E21F23753A36ULL,
		0xBF94054DCC807B82ULL,
		0x406A0C4ABF62A8CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFC517359EA2F67ULL,
		0xFB3A7C398E321C1CULL,
		0x5656E9DF9EF30EB1ULL,
		0x55D05A2759A604A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07ED95A13922797CULL,
		0x9A9A65E595431E1AULL,
		0x693D1B6E2D8D6CD0ULL,
		0x6A99B22365BCA426ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AB1CC148E5E5620ULL,
		0x18A04870EE664D21ULL,
		0xF17BBBB2C57A4E26ULL,
		0x411DFA9A141D5AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE556352673A1447ULL,
		0xBD03C023F1CD1134ULL,
		0xCBC04FAE07A93441ULL,
		0x6E7B0B290EFE8146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C5C68C2272441C6ULL,
		0x5B9C884CFC993BECULL,
		0x25BB6C04BDD119E4ULL,
		0x52A2EF71051ED973ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E5677E166B01CB6ULL,
		0x8674869791F773ADULL,
		0xB3CB5E482FDC45DDULL,
		0x64A4ADAB960EACD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94CF2FA5FFB44EAULL,
		0xB044ED2DB0F4DC55ULL,
		0x07AC0C4FBC7BB3F4ULL,
		0x760013C6A6D4DCFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x950984E706B4D7B9ULL,
		0xD62F9969E1029757ULL,
		0xAC1F51F8736091E8ULL,
		0x6EA499E4EF39CFD2ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA42D75375383A8DDULL,
		0xCA8E404178E4179BULL,
		0xCB0A80D4E07B8ECAULL,
		0x2467506B55CC4900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD20383893D4AC9ULL,
		0x1C62E779E5147CF7ULL,
		0x5E938EA36DAA1765ULL,
		0x4A94AABC42136B9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x665B71B3CA465E01ULL,
		0xAE2B58C793CF9AA4ULL,
		0x6C76F23172D17765ULL,
		0x59D2A5AF13B8DD66ULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2B97DFD90C97892ULL,
		0x7F9AA3D7B3D4ED77ULL,
		0xA673B6D3AED143A4ULL,
		0x71118116DE4BBF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCF2F20B85AB4262ULL,
		0xF1C69395D2C88572ULL,
		0x9784B9CEEC28B86CULL,
		0x4868647A38F79FADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5C68BF20B1E3630ULL,
		0x8DD41041E10C6804ULL,
		0x0EEEFD04C2A88B37ULL,
		0x28A91C9CA5541FBDULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x049962C73E9CB447ULL,
		0x14FA4E0C48702BCFULL,
		0x9C2774909D5B0789ULL,
		0x247BF3CB2F85225EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D8D855B82BA7B20ULL,
		0x719FEECE748EB444ULL,
		0x49DF8574008D63A0ULL,
		0x10E9DAEF3AFC58FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD70BDD6BBBE23927ULL,
		0xA35A5F3DD3E1778AULL,
		0x5247EF1C9CCDA3E8ULL,
		0x139218DBF488C962ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44C5DA14326C8C4CULL,
		0xF9CCD0AABBEFDF7FULL,
		0x69DBD95E7818F42AULL,
		0x02BC6960A993A63CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF4E16890D4A6C3ULL,
		0xA1A95FFE87A5DFE5ULL,
		0xEF4F437ECDD087BDULL,
		0x50A6D9D869480317ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D0F8ABA197E576ULL,
		0x582370AC3449FF9AULL,
		0x7A8C95DFAA486C6DULL,
		0x32158F88404BA324ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2003FC3536282240ULL,
		0xA497C81573664F68ULL,
		0x6AF70C365C0B789DULL,
		0x296D53574B525367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A57E581FD378A1ULL,
		0x87389FE383874918ULL,
		0x566DBA1E7336CB11ULL,
		0x12B989231248CFF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F5E7DDD1654A99FULL,
		0x1D5F2831EFDF064FULL,
		0x14895217E8D4AD8CULL,
		0x16B3CA3439098370ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57AB2980138D809CULL,
		0x54D36F48F8DA01F1ULL,
		0x1FF7C323558ED713ULL,
		0x777EBBBF37E1C700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF0E6ADD9D0F756ULL,
		0x40E2B84E7EFF09C3ULL,
		0x978FFFF95B3CC217ULL,
		0x157FEA10444911A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49BA42D239BC8946ULL,
		0x13F0B6FA79DAF82EULL,
		0x8867C329FA5214FCULL,
		0x61FED1AEF398B557ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE05080EA503FA375ULL,
		0xD70EE9A15CCB1D76ULL,
		0x048BF57BD239425DULL,
		0x3B29B05EAC72C101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E8E7A580200AB6ULL,
		0xA3851F7DB5FEF4E2ULL,
		0xDEBB45B924038219ULL,
		0x24FA49FF24F82D4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F679944D01F98BFULL,
		0x3389CA23A6CC2894ULL,
		0x25D0AFC2AE35C044ULL,
		0x162F665F877A93B5ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF1DBBB79D904749ULL,
		0x36FA833203A31447ULL,
		0x986FC768C64F161CULL,
		0x2D513C770D58F018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C615D3CC8472D8ULL,
		0x64D33ECE2687AC38ULL,
		0xA6FDEC073467223EULL,
		0x3D5D2E5D1C685C9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA557A5E3D10BD45EULL,
		0xD2274463DD1B680FULL,
		0xF171DB6191E7F3DDULL,
		0x6FF40E19F0F0937CULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AD96CA9741AC2ECULL,
		0x677A95431AD423C8ULL,
		0x2F50C38001F51447ULL,
		0x03F9B4E32FFDF3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD98F213FEC8C0F6ULL,
		0x1191CB61C03E3720ULL,
		0x75FB94E00CAAFAF3ULL,
		0x05921C44E14628D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D407A95755201E3ULL,
		0x55E8C9E15A95ECA7ULL,
		0xB9552E9FF54A1954ULL,
		0x7E67989E4EB7CAD7ULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F5B05182B451503ULL,
		0x026CEC1CA620857AULL,
		0x16C1DE0A25473420ULL,
		0x65E7B469BAD1FCA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958DBB8776514BF9ULL,
		0xC16C26BEC3294E8FULL,
		0xE0E69DA145A2A02FULL,
		0x44A10BB46D5E7362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9CD4990B4F3C90AULL,
		0x4100C55DE2F736EAULL,
		0x35DB4068DFA493F0ULL,
		0x2146A8B54D738941ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56F60E6ED4270A49ULL,
		0x2FF8F76F284D85FAULL,
		0xECC4CBC7DDD27D6FULL,
		0x64477D064CBFC56FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B995BCF1C83AC33ULL,
		0x14BB111ACF06EB05ULL,
		0x6CAFBD7D9F9B326FULL,
		0x4D02B4E3B399C5F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B5CB29FB7A35E16ULL,
		0x1B3DE65459469AF5ULL,
		0x80150E4A3E374B00ULL,
		0x1744C8229925FF76ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x399C5651418DAFE9ULL,
		0x95521FF2864D0ED3ULL,
		0xCD2AF5172A107E4AULL,
		0x7DDB42B4A131E360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0885842949E790EEULL,
		0xC6D76A7079CBF966ULL,
		0x7EE300ADD69E3C0BULL,
		0x071110C1AB9D3398ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3116D227F7A61EFBULL,
		0xCE7AB5820C81156DULL,
		0x4E47F4695372423EULL,
		0x76CA31F2F594AFC8ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B1295E2232C23A1ULL,
		0x6A757AFF1860DDCAULL,
		0x8167496B97C3B767ULL,
		0x0AFA408B0D15E4F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F11DD47A671A43ULL,
		0x5C78FD0EEAD183B3ULL,
		0xC2066CEC567FAB04ULL,
		0x5ED878BB9C040C4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE821780DA8C5094BULL,
		0x0DFC7DF02D8F5A16ULL,
		0xBF60DC7F41440C63ULL,
		0x2C21C7CF7111D8A6ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50D49E1EA85D7A94ULL,
		0x4FF904803DEACC02ULL,
		0x34CE274DD62AFF85ULL,
		0x114ACF142A8F072EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10832301AF702C94ULL,
		0xD85740917B8EE499ULL,
		0x56C423DF6362F1D9ULL,
		0x7A3573D328099579ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40517B1CF8ED4DEDULL,
		0x77A1C3EEC25BE769ULL,
		0xDE0A036E72C80DABULL,
		0x17155B41028571B4ULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A042E1E03ACC4BBULL,
		0x84F138DE9F6309C5ULL,
		0xBF7C40A014F5C688ULL,
		0x3F828193B3D0C685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75BBEE1C69B199FBULL,
		0xD432367C9388C881ULL,
		0x8722452C336F6494ULL,
		0x609B9DA476B02372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0448400199FB2AADULL,
		0xB0BF02620BDA4144ULL,
		0x3859FB73E18661F3ULL,
		0x5EE6E3EF3D20A313ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEEE7720D091436FULL,
		0x1B672B96033CB0C7ULL,
		0xFAFA434914424B14ULL,
		0x4ED82741D0D82DBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B87C40BA6BDC044ULL,
		0x0D2FB3D282B50F44ULL,
		0xD6956EF2B490E237ULL,
		0x6AFEB9311281EA6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6366B31529D38318ULL,
		0x0E3777C38087A183ULL,
		0x2464D4565FB168DDULL,
		0x63D96E10BE564351ULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC566CE6ABDFEAD72ULL,
		0xAA5028076C96D943ULL,
		0xBCA8AB194379A51EULL,
		0x542ED55B247FC783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44A329B538C758E2ULL,
		0x37DE46C47B0D613AULL,
		0x882BF201575C8E32ULL,
		0x7DDB333350E893B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C3A4B58537547DULL,
		0x7271E142F1897809ULL,
		0x347CB917EC1D16ECULL,
		0x5653A227D39733D3ULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2D4FA9EF8447D4EULL,
		0xC4F69ED255B0B2C6ULL,
		0x36550A1AE5F3773EULL,
		0x36F529793681F05AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD4F2452BBF522CULL,
		0x2A7CCB48E682934AULL,
		0x342395F97989C33FULL,
		0x079558F63885C430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3000859CC852B22ULL,
		0x9A79D3896F2E1F7CULL,
		0x023174216C69B3FFULL,
		0x2F5FD082FDFC2C2AULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00E4D5784D16F13EULL,
		0xC1D9B04C194F3E95ULL,
		0xDA5E09556AF850FFULL,
		0x2DADE891279F883BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B4691D6B23A18DULL,
		0x4105FA05FF0D42F7ULL,
		0x11F27630379689FDULL,
		0x26785DFD857B131EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7306C5AE1F34FB1ULL,
		0x80D3B6461A41FB9DULL,
		0xC86B93253361C702ULL,
		0x07358A93A224751DULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6243BD0FFD303F07ULL,
		0xA1AEB0A62501AE7AULL,
		0xC676A6BDA5406F1EULL,
		0x479086D43E4E2D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA6FCF25C883C54ULL,
		0xF5F2BC2A05FFE046ULL,
		0x502911073FBDA313ULL,
		0x7349D36D0165A65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB49CC01DA0A802A0ULL,
		0xABBBF47C1F01CE33ULL,
		0x764D95B66582CC0AULL,
		0x5446B3673CE886C7ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EFE222698A01B71ULL,
		0xBAA82E8758EA89A3ULL,
		0x1DD578CD1FCDF702ULL,
		0x31504494218630ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC7D444F6C0BA09ULL,
		0x5E99AE5A1219C6C3ULL,
		0xCD06E8350A7CD6FEULL,
		0x70B07F6C2CFA3B10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54364DE1A1DF6155ULL,
		0x5C0E802D46D0C2DFULL,
		0x50CE909815512004ULL,
		0x409FC527F48BF59CULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47F10D68C89B7301ULL,
		0xF910E22163B9AC68ULL,
		0xC368D6BC39259255ULL,
		0x5A12520AA977F043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x508AE285688A8A4FULL,
		0x417801B815B0FA2EULL,
		0x5431655FC792FD6CULL,
		0x372DF0018C108D1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7662AE36010E8B2ULL,
		0xB798E0694E08B239ULL,
		0x6F37715C719294E9ULL,
		0x22E462091D676325ULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51252262221327BFULL,
		0x38C1A7C286D0A937ULL,
		0x692E7233A7C5595DULL,
		0x56C9A9A46FB6241EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9512BAE3708833D5ULL,
		0x68E26F77888FC6C4ULL,
		0x1426FA769165DE95ULL,
		0x51EF7A55F6606160ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC12677EB18AF3EAULL,
		0xCFDF384AFE40E272ULL,
		0x550777BD165F7AC7ULL,
		0x04DA2F4E7955C2BEULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2764F3B62A6D73A3ULL,
		0x2298112F3779CF32ULL,
		0x599E999B156D49C9ULL,
		0x28CD987C904135BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A3F438801C3FF2ULL,
		0xED961A351C2F9744ULL,
		0x0F28B79AEF9AAC16ULL,
		0x379B86A6A7E8EFFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4C0FF7DAA51339EULL,
		0x3501F6FA1B4A37EDULL,
		0x4A75E20025D29DB2ULL,
		0x713211D5E85845BEULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2E2642AFA66CD9CULL,
		0x270BDAE289E912EAULL,
		0x89F428329E32C392ULL,
		0x446CEA3115CA3079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFCC7653C23785BCULL,
		0xE375A993245ECBDAULL,
		0x621CCBDD6FBAA3C5ULL,
		0x29CB2BEC800A9689ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0315EDD7382F47E0ULL,
		0x4396314F658A4710ULL,
		0x27D75C552E781FCCULL,
		0x1AA1BE4495BF99F0ULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25CBFB63486924C4ULL,
		0x8C142C9C79586E97ULL,
		0x73BEC469817671ADULL,
		0x74B879E9061BA5D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78FFFD6470DF7F14ULL,
		0xEBB688069A92E369ULL,
		0x77BA5963B2B87509ULL,
		0x5CC6B845B2820D9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACCBFDFED789A5B0ULL,
		0xA05DA495DEC58B2DULL,
		0xFC046B05CEBDFCA3ULL,
		0x17F1C1A353999834ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79767EF0307BFF5DULL,
		0xB17EA1BBA5A34FC6ULL,
		0xFBED80362A0D91DAULL,
		0x60FB20C1F4C39B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE06D016D8018E68ULL,
		0x41EBCCD55C1FCFA3ULL,
		0xC53F3C3189604C1FULL,
		0x541D0CBDF2A7561CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B6FAED9587A70F5ULL,
		0x6F92D4E649838022ULL,
		0x36AE4404A0AD45BBULL,
		0x0CDE1404021C4532ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31EFF6CAA0CB7FCAULL,
		0xB041A16128F363A0ULL,
		0x8CF9AD643BADC4A0ULL,
		0x31FA8424A63F784FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27881D2FDA83D62BULL,
		0x459228B8CD6E625DULL,
		0x844D8EFF3688E208ULL,
		0x4620532129328DA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A67D99AC647A98CULL,
		0x6AAF78A85B850143ULL,
		0x08AC1E650524E298ULL,
		0x6BDA31037D0CEAAEULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7FDA8D3ECB77C44ULL,
		0x62BCE21F6689121AULL,
		0x1157F05315D427D1ULL,
		0x616C5A2C9976C55DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06778C79503E99DEULL,
		0x64F4C9730436E460ULL,
		0x119351A761849006ULL,
		0x677C584A654DA945ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1861C5A9C78E253ULL,
		0xFDC818AC62522DBAULL,
		0xFFC49EABB44F97CAULL,
		0x79F001E234291C17ULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF14B729667548A9AULL,
		0x8B34FE014D23F9C1ULL,
		0xACF1A8057CD6759EULL,
		0x6A389CC30ECAF4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF82AF88D65D31656ULL,
		0x6611F173EECE1F21ULL,
		0x3F33F62B64B0C33FULL,
		0x735D103E280FEFB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9207A0901817431ULL,
		0x25230C8D5E55DA9FULL,
		0x6DBDB1DA1825B25FULL,
		0x76DB8C84E6BB0507ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9D4BE3AEB4661EEULL,
		0xD6512705FE9B694CULL,
		0xC60CAFDADD7C8757ULL,
		0x5572BB2C379A7B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFA986905C447E6ULL,
		0x4581E5A34CC278FBULL,
		0xA9CCDA3E68EFC859ULL,
		0x12003A0ADD03A3BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59DA25D1E5821A08ULL,
		0x90CF4162B1D8F051ULL,
		0x1C3FD59C748CBEFEULL,
		0x437281215A96D789ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}