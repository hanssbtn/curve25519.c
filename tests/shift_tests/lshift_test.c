#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x1E8690DF84B2B08EULL,
		0xE59D2144AF87E0FAULL,
		0xDB5CD0CF74EDDA7DULL,
		0x7AB463159D520C9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB08E000000000000ULL,
		0xE0FA1E8690DF84B2ULL,
		0xDA7DE59D2144AF87ULL,
		0x0C9CDB5CD0CF74EDULL,
		0x00007AB463159D52ULL
	}};
	int shift = 240;
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
		0x11CDB076B5F0264BULL,
		0x5B569D01953F8792ULL,
		0xB0933183C61CD70AULL,
		0x06DA1A903001F8D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1DAD7C0992C0000ULL,
		0x740654FE1E484736ULL,
		0xC60F18735C296D5AULL,
		0x6A40C007E346C24CULL,
		0x0000000000001B68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xDCE44AC0B82732C1ULL,
		0x8F6A2240E028B75CULL,
		0xCAFB5E02B70431B8ULL,
		0x3194ADA60B85E4A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3996080000000000ULL,
		0x45BAE6E7225605C1ULL,
		0x218DC47B51120701ULL,
		0x2F250657DAF015B8ULL,
		0x0000018CA56D305CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x102E692DA000504BULL,
		0xC83FEB9DBA905109ULL,
		0x467ECA5DEEA59DCFULL,
		0x1D4718CEAC782451ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5CD25B4000A09600ULL,
		0x7FD73B7520A21220ULL,
		0xFD94BBDD4B3B9F90ULL,
		0x8E319D58F048A28CULL,
		0x000000000000003AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
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
		0xBF5801E0A68801F3ULL,
		0xE90B6DA38E190050ULL,
		0x77C5FC164568B095ULL,
		0x56AA19B3E2832070ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC00000000000000ULL,
		0x42FD6007829A2007ULL,
		0x57A42DB68E386401ULL,
		0xC1DF17F05915A2C2ULL,
		0x015AA866CF8A0C81ULL
	}};
	shift = 250;
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
		0x508FDD9ACD2534B0ULL,
		0x982C467F0A72C501ULL,
		0xCB32C27E907ED1C2ULL,
		0x4386A5BE5821046DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA696000000000000ULL,
		0x58A02A11FBB359A4ULL,
		0xDA38530588CFE14EULL,
		0x208DB966584FD20FULL,
		0x00000870D4B7CB04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xAD7C18ACCB0D56DBULL,
		0xBE9B23F6C55F6098ULL,
		0xE2A51C5C3E08BC7EULL,
		0x25651A38A1A379C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6D8000000000000ULL,
		0x04C56BE0C566586AULL,
		0xE3F5F4D91FB62AFBULL,
		0xCE171528E2E1F045ULL,
		0x00012B28D1C50D1BULL
	}};
	shift = 243;
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
		0x179D0A2540E75436ULL,
		0xB6BE5F175C0FD2B7ULL,
		0x8DD53D8CE54B4886ULL,
		0x41A0CF36C7230487ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB000000000000000ULL,
		0xB8BCE8512A073AA1ULL,
		0x35B5F2F8BAE07E95ULL,
		0x3C6EA9EC672A5A44ULL,
		0x020D0679B6391824ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0x3A0ED65522996C7EULL,
		0x4EF81B4405A793D2ULL,
		0xC47575FF8AEFBD7DULL,
		0x7588241BABC13EF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD65522996C7E0000ULL,
		0x1B4405A793D23A0EULL,
		0x75FF8AEFBD7D4EF8ULL,
		0x241BABC13EF9C475ULL,
		0x0000000000007588ULL
	}};
	shift = 208;
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
		0x42F4BAA0F762F057ULL,
		0x33C14B08B6CED27CULL,
		0xFE9189BD2AC4DC15ULL,
		0x49531E829A7F6388ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8BC15C000000000ULL,
		0xB3B49F10BD2EA83DULL,
		0xB137054CF052C22DULL,
		0x9FD8E23FA4626F4AULL,
		0x0000001254C7A0A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
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
		0x6BB6A092268D9648ULL,
		0x66873740524BF3ABULL,
		0x40C2498EAE77B046ULL,
		0x2F60CF36E6F3B61BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x268D964800000000ULL,
		0x524BF3AB6BB6A092ULL,
		0xAE77B04666873740ULL,
		0xE6F3B61B40C2498EULL,
		0x000000002F60CF36ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
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
		0x267F5D4C3FFC33F4ULL,
		0x2DDC50DE5F1432D2ULL,
		0x895A01745FC5B83BULL,
		0x1660A9D1338B0A9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7530FFF0CFD00000ULL,
		0x43797C50CB4899FDULL,
		0x05D17F16E0ECB771ULL,
		0xA744CE2C2A762568ULL,
		0x0000000000005982ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
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
		0x5FC635200F84848DULL,
		0x2F1D165DC958A5CDULL,
		0x7C195F9877F9050CULL,
		0x46AD5176B41EC410ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC242468000000000ULL,
		0xAC52E6AFE31A9007ULL,
		0xFC8286178E8B2EE4ULL,
		0x0F62083E0CAFCC3BULL,
		0x0000002356A8BB5AULL
	}};
	shift = 231;
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
		0x535C019A66113FC3ULL,
		0x3EA908725A40B641ULL,
		0xDCB429C8CC2B0010ULL,
		0x22EDB5D7D1305263ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xA9AE00CD33089FE1ULL,
		0x1F5484392D205B20ULL,
		0xEE5A14E466158008ULL,
		0x1176DAEBE8982931ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
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
		0x5427B7DC622B24B5ULL,
		0xC261E602393A5746ULL,
		0xD3CA6FC291EA6FD9ULL,
		0x27C2861D1C4ABF1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x925A800000000000ULL,
		0x2BA32A13DBEE3115ULL,
		0x37ECE130F3011C9DULL,
		0x5F8D69E537E148F5ULL,
		0x000013E1430E8E25ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
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
		0x717EBF975FE5BFC7ULL,
		0x288101B697DC4F9BULL,
		0x950B1ABE4FD4B253ULL,
		0x18A23547672F0D52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBAFF2DFE38000000ULL,
		0xB4BEE27CDB8BF5FCULL,
		0xF27EA5929944080DULL,
		0x3B39786A94A858D5ULL,
		0x0000000000C511AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
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
		0xBA9F306CF4A10521ULL,
		0xF1CF902665B15BABULL,
		0x01F1DC629C56C724ULL,
		0x6EB4663357FB7172ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9080000000000000ULL,
		0xD5DD4F98367A5082ULL,
		0x9278E7C81332D8ADULL,
		0xB900F8EE314E2B63ULL,
		0x00375A3319ABFDB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0x5EDD81988F71EE05ULL,
		0x3584960658728578ULL,
		0xCEEA7490831F2B1FULL,
		0x21D1B3A7910A8129ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x988F71EE05000000ULL,
		0x06587285785EDD81ULL,
		0x90831F2B1F358496ULL,
		0xA7910A8129CEEA74ULL,
		0x000000000021D1B3ULL
	}};
	shift = 216;
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
		0x957F2D281262FACDULL,
		0x1EAFA6F701F52A10ULL,
		0x21E59A19B15FF38BULL,
		0x429782F88FF59028ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0498BEB34000000ULL,
		0xDC07D4A84255FCB4ULL,
		0x66C57FCE2C7ABE9BULL,
		0xE23FD640A0879668ULL,
		0x00000000010A5E0BULL,
		0x0000000000000000ULL
	}};
	shift = 154;
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
		0xD0CB4F2DC211137CULL,
		0xD067641F976BF8F3ULL,
		0x361C038FA717994EULL,
		0x51CFFAF6BE082AF7ULL,
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
		0xF432D3CB708444DFULL,
		0xB419D907E5DAFE3CULL,
		0xCD8700E3E9C5E653ULL,
		0x1473FEBDAF820ABDULL
	}};
	shift = 254;
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
		0x2A50EFD2E91C5FB0ULL,
		0xDB4E093BECE9D2EDULL,
		0x246C08B4A55D4EF4ULL,
		0x567FC8A53B959FD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB000000000000000ULL,
		0xED2A50EFD2E91C5FULL,
		0xF4DB4E093BECE9D2ULL,
		0xD8246C08B4A55D4EULL,
		0x00567FC8A53B959FULL
	}};
	shift = 248;
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
		0x3F066734D2EF2428ULL,
		0x83B80B02BDBBE8EFULL,
		0x8028992B5661DB84ULL,
		0x5A8B2A35C3037DB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6734D2EF24280000ULL,
		0x0B02BDBBE8EF3F06ULL,
		0x992B5661DB8483B8ULL,
		0x2A35C3037DB18028ULL,
		0x0000000000005A8BULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x5D7DE5857C7EF442ULL,
		0x39815D91FC384BE0ULL,
		0x5820E189874248EBULL,
		0x07F29FDAA7DA3EECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5857C7EF4420000ULL,
		0x5D91FC384BE05D7DULL,
		0xE189874248EB3981ULL,
		0x9FDAA7DA3EEC5820ULL,
		0x00000000000007F2ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x3D38F4D967907AC8ULL,
		0x2F4291E3A3744601ULL,
		0x01B97B8DE06480E4ULL,
		0x1DD9B24549C7A47AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7A6CB3C83D64000ULL,
		0x148F1D1BA23009E9ULL,
		0xCBDC6F032407217AULL,
		0xCD922A4E3D23D00DULL,
		0x00000000000000EEULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x21549DB50A813869ULL,
		0xB21B2D2706D0779BULL,
		0xCCE089B489BA5BB9ULL,
		0x134E2EA706B09201ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1386900000000000ULL,
		0x0779B21549DB50A8ULL,
		0xA5BB9B21B2D2706DULL,
		0x09201CCE089B489BULL,
		0x00000134E2EA706BULL,
		0x0000000000000000ULL
	}};
	shift = 172;
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
		0xDA2F8F2440BF7E69ULL,
		0xDDC8671528E74283ULL,
		0x57E4574AE6BE403DULL,
		0x72CEFA2B2E54E89AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x102FDF9A40000000ULL,
		0x4A39D0A0F68BE3C9ULL,
		0xB9AF900F777219C5ULL,
		0xCB953A2695F915D2ULL,
		0x000000001CB3BE8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
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
		0x37277E7F07391254ULL,
		0x78481A59F4FB7DD6ULL,
		0xDEC04337F77DFBCFULL,
		0x2F7CD6972AF9F0BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x277E7F0739125400ULL,
		0x481A59F4FB7DD637ULL,
		0xC04337F77DFBCF78ULL,
		0x7CD6972AF9F0BBDEULL,
		0x000000000000002FULL,
		0x0000000000000000ULL
	}};
	shift = 136;
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
		0x1CF296B936D0B7D6ULL,
		0x8E82733ED7A2D510ULL,
		0x1130E7CD6518601DULL,
		0x7A9004456B9A3ED1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x685BEB0000000000ULL,
		0xD16A880E794B5C9BULL,
		0x8C300EC741399F6BULL,
		0xCD1F68889873E6B2ULL,
		0x0000003D480222B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xAADB4D31262DA9C1ULL,
		0x1A040B4D52A26D37ULL,
		0xEB105AB8B6218ACDULL,
		0x4911FEB779742425ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6989316D4E08000ULL,
		0x05A6A951369BD56DULL,
		0x2D5C5B10C5668D02ULL,
		0xFF5BBCBA1212F588ULL,
		0x0000000000002488ULL
	}};
	shift = 207;
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
		0x61592050A6A9426CULL,
		0xFAA68BDD9F15225CULL,
		0xD79607D13F03DE28ULL,
		0x7A7A5657926C4E73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA9426C0000000000ULL,
		0x15225C61592050A6ULL,
		0x03DE28FAA68BDD9FULL,
		0x6C4E73D79607D13FULL,
		0x0000007A7A565792ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0xFD0D8489B272EC25ULL,
		0x4A3C4C846352A7BAULL,
		0x25D04E9DF3F6F954ULL,
		0x4615BF4DA95ABF42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0xAFD0D8489B272EC2ULL,
		0x44A3C4C846352A7BULL,
		0x225D04E9DF3F6F95ULL,
		0x04615BF4DA95ABF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x997E6E3066B47553ULL,
		0x5D9D305149D1FA3FULL,
		0xF34AF5D0E618AAC7ULL,
		0x0BC9F3DEB69FED4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x335A3AA980000000ULL,
		0xA4E8FD1FCCBF3718ULL,
		0x730C5563AECE9828ULL,
		0x5B4FF6A679A57AE8ULL,
		0x0000000005E4F9EFULL
	}};
	shift = 223;
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
		0xEE8B179F3B9E9C09ULL,
		0x1E1A63DAB28A6725ULL,
		0x240F9522A81C96BAULL,
		0x73853EA6F2994EC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E0480000000000ULL,
		0x53392F7458BCF9DCULL,
		0xE4B5D0F0D31ED594ULL,
		0xCA7631207CA91540ULL,
		0x0000039C29F53794ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x6038687197F8EE0BULL,
		0x398515B1AE8F7F52ULL,
		0x6A2AFAFFD77138D2ULL,
		0x36966C9198DF4E8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38687197F8EE0B00ULL,
		0x8515B1AE8F7F5260ULL,
		0x2AFAFFD77138D239ULL,
		0x966C9198DF4E8B6AULL,
		0x0000000000000036ULL
	}};
	shift = 200;
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
		0x7C113E87F411879AULL,
		0xA7153A599F070331ULL,
		0xB8F04398568D961BULL,
		0x1BA91EB70F4C0665ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x11879A0000000000ULL,
		0x0703317C113E87F4ULL,
		0x8D961BA7153A599FULL,
		0x4C0665B8F0439856ULL,
		0x0000001BA91EB70FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0x84A81610641BF9D2ULL,
		0x6488F20443D32481ULL,
		0xF38481817EB78E94ULL,
		0x7E52ECDBDC6C2BFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906FE74800000000ULL,
		0x0F4C920612A05841ULL,
		0xFADE3A519223C811ULL,
		0x71B0AFF3CE120605ULL,
		0x00000001F94BB36FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x50E8EED2E8B7B912ULL,
		0xA0846254FDAA298BULL,
		0xCA144A77B7BB37CBULL,
		0x61C2EBF26192D0ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9745BDC890000000ULL,
		0xA7ED514C5A874776ULL,
		0xBDBDD9BE5D042312ULL,
		0x930C96876650A253ULL,
		0x00000000030E175FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x73CCBE3F08B67AECULL,
		0x51D154CD32E24BD5ULL,
		0xD3651D464BF33E1FULL,
		0x49E6E876DCF9E152ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8FC22D9EBB000000ULL,
		0x334CB892F55CF32FULL,
		0x5192FCCF87D47455ULL,
		0x1DB73E7854B4D947ULL,
		0x00000000001279BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
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
		0x92B1CA886690F42CULL,
		0x90B368A915BD0ECCULL,
		0xA1ADECDA5289598AULL,
		0x1ADAFA9CA17F9F6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x925639510CD21E85ULL,
		0x52166D1522B7A1D9ULL,
		0x9435BD9B4A512B31ULL,
		0x035B5F53942FF3EDULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x6289D1318549FFCCULL,
		0x698D55C1006B50FCULL,
		0x5A4D6A94D927DFE1ULL,
		0x37FC6F61A31449D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30A93FF980000000ULL,
		0x200D6A1F8C513A26ULL,
		0x9B24FBFC2D31AAB8ULL,
		0x3462893ACB49AD52ULL,
		0x0000000006FF8DECULL,
		0x0000000000000000ULL
	}};
	shift = 157;
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
		0xBE22AB9DA5F2364BULL,
		0xB19A52C3CA50AF5BULL,
		0xA4DD4BD9ECDC19B2ULL,
		0x2330150271E039D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CED2F91B2580000ULL,
		0x961E52857ADDF115ULL,
		0x5ECF66E0CD958CD2ULL,
		0xA8138F01CE8D26EAULL,
		0x0000000000011980ULL
	}};
	shift = 211;
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
		0x872E0E69E26DA6A6ULL,
		0xFE4BE81A1478B148ULL,
		0x3D743D15E2FC2FE7ULL,
		0x7A6F9F28369432B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3970734F136D3530ULL,
		0xF25F40D0A3C58A44ULL,
		0xEBA1E8AF17E17F3FULL,
		0xD37CF941B4A195B1ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0xF66CE7FE2A544129ULL,
		0x3B09B69F3FF4B84DULL,
		0x60290876D50E1502ULL,
		0x3B61AAB9777F8461ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8825200000000000ULL,
		0x9709BECD9CFFC54AULL,
		0xC2A0476136D3E7FEULL,
		0xF08C2C05210EDAA1ULL,
		0x0000076C35572EEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x47C34E2E25C37BFCULL,
		0x629B95522B8AF9B7ULL,
		0xD3BA6AD76AF0F25BULL,
		0x10E9875F27F96032ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE1BDFE0000000000ULL,
		0xC57CDBA3E1A71712ULL,
		0x78792DB14DCAA915ULL,
		0xFCB01969DD356BB5ULL,
		0x0000000874C3AF93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x14BCA660F954E7EFULL,
		0xFB6030590014DE05ULL,
		0x4C1EDF262A2BB2F4ULL,
		0x579E00C6E031A52DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF780000000000000ULL,
		0x028A5E53307CAA73ULL,
		0x7A7DB0182C800A6FULL,
		0x96A60F6F931515D9ULL,
		0x002BCF00637018D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
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
		0x9C98E5598475FF78ULL,
		0xF3D7B0DB4E3F800AULL,
		0x0824B7D9ADD40FA3ULL,
		0x26E4442491A514FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xACC23AFFBC000000ULL,
		0x6DA71FC0054E4C72ULL,
		0xECD6EA07D1F9EBD8ULL,
		0x1248D28A7E04125BULL,
		0x0000000000137222ULL
	}};
	shift = 215;
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
		0x4A116C60AFB0D82EULL,
		0x71C9F002030EAECEULL,
		0x773E31543EF4A7E5ULL,
		0x14AFEB19E3A9F0CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0x72508B63057D86C1ULL,
		0x2B8E4F8010187576ULL,
		0x73B9F18AA1F7A53FULL,
		0x00A57F58CF1D4F86ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
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
		0x8C639F55AA403CE0ULL,
		0x420F0BC36C4EE77AULL,
		0x15919514A3C18E5EULL,
		0x3CFF4F3F0F8D0571ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA900F38000000000ULL,
		0xB13B9DEA318E7D56ULL,
		0x8F063979083C2F0DULL,
		0x3E3415C456465452ULL,
		0x00000000F3FD3CFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x66EEC45E26FE7B9EULL,
		0x3BDF8A71CB620F39ULL,
		0x2085217F3F802E7CULL,
		0x4F7FD1438899A4F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB11789BF9EE7800ULL,
		0x7E29C72D883CE59BULL,
		0x1485FCFE00B9F0EFULL,
		0xFF450E226693D882ULL,
		0x000000000000013DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x3C58A822B9D7C1AEULL,
		0x9C232D17CF00CF0CULL,
		0x6BCD02A6BB63403EULL,
		0x35D797E094074D64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7C1AE00000000000ULL,
		0x0CF0C3C58A822B9DULL,
		0x3403E9C232D17CF0ULL,
		0x74D646BCD02A6BB6ULL,
		0x0000035D797E0940ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
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
		0x91DBFE178381C918ULL,
		0x5D1FF3502EE36D83ULL,
		0x31F9553F2F96F5E7ULL,
		0x0E39E56A26C6DBA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF85E0E072460000ULL,
		0xFCD40BB8DB60E476ULL,
		0x554FCBE5BD79D747ULL,
		0x795A89B1B6EA4C7EULL,
		0x000000000000038EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x9F03179B94B63022ULL,
		0xC30EDF3EBEAE8611ULL,
		0xCBCFD32B0A3A41A3ULL,
		0x5C8A7115CF29E144ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x96C6044000000000ULL,
		0xD5D0C233E062F372ULL,
		0x4748347861DBE7D7ULL,
		0xE53C289979FA6561ULL,
		0x0000000B914E22B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
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
		0xACEAC2F7939303F6ULL,
		0xA95FD9BF020E10F6ULL,
		0x36A64193C88BDE95ULL,
		0x7A0664672CEF810EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9303F60000000000ULL,
		0x0E10F6ACEAC2F793ULL,
		0x8BDE95A95FD9BF02ULL,
		0xEF810E36A64193C8ULL,
		0x0000007A0664672CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0xD120C60E10D4B4E3ULL,
		0xEF8683FEDFAACCC2ULL,
		0x3EAAC472C88C365DULL,
		0x4A63764B28BF63FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E30000000000000ULL,
		0xCC2D120C60E10D4BULL,
		0x65DEF8683FEDFAACULL,
		0x3FD3EAAC472C88C3ULL,
		0x0004A63764B28BF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x4620C627911FA4AAULL,
		0xFE68CAF33A1D76C1ULL,
		0x6B3CB4F1540BC1C7ULL,
		0x3209029A7E20A76DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC418C4F223F49540ULL,
		0xCD195E6743AED828ULL,
		0x67969E2A817838FFULL,
		0x4120534FC414EDADULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
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
		0x61A56F7B0BF21415ULL,
		0x0D4067A8F8F10AECULL,
		0x3769DEC478A814BAULL,
		0x16552C10029A42EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BD85F90A0A80000ULL,
		0x3D47C78857630D2BULL,
		0xF623C540A5D06A03ULL,
		0x608014D21779BB4EULL,
		0x000000000000B2A9ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
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
		0xDBC14A3004D3F77AULL,
		0xB5A271B74679C8E7ULL,
		0xF9225F04A00502ADULL,
		0x5B3713B49BDF02E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD00000000000000ULL,
		0x73EDE0A5180269FBULL,
		0x56DAD138DBA33CE4ULL,
		0x72FC912F82500281ULL,
		0x002D9B89DA4DEF81ULL
	}};
	shift = 247;
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
		0x1D5C2B3B5D61C48EULL,
		0x0EC1B5FA810DA103ULL,
		0xEB41E4183452461BULL,
		0x4F9D43CA2CD73959ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE247000000000000ULL,
		0xD0818EAE159DAEB0ULL,
		0x230D8760DAFD4086ULL,
		0x9CACF5A0F20C1A29ULL,
		0x000027CEA1E5166BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0x3EFAB1918FF889C4ULL,
		0x2091A6C649D396CAULL,
		0xB82B6715F5D5A7D0ULL,
		0x69C40C79C87CB39FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2710000000000000ULL,
		0x5B28FBEAC6463FE2ULL,
		0x9F4082469B19274EULL,
		0xCE7EE0AD9C57D756ULL,
		0x0001A71031E721F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0xE8C93ABBE7262662ULL,
		0x4A537395266EFE5BULL,
		0x52F9D65F347B7392ULL,
		0x617ABCD88CB14079ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x7D1927577CE4C4CCULL,
		0x494A6E72A4CDDFCBULL,
		0x2A5F3ACBE68F6E72ULL,
		0x0C2F579B1196280FULL
	}};
	shift = 253;
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
		0xEB1A3141788A3784ULL,
		0xC7866F3EB8A2578DULL,
		0xE57EF7C88E9D80A7ULL,
		0x46D1615548A4C064ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1146F0800000000ULL,
		0x7144AF1BD6346282ULL,
		0x1D3B014F8F0CDE7DULL,
		0x914980C9CAFDEF91ULL,
		0x000000008DA2C2AAULL
	}};
	shift = 225;
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
		0x18236D9D50268817ULL,
		0x342C226EB3212C83ULL,
		0xC6E0514200D6DEA6ULL,
		0x53C7DF33BBC585DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA813440B80000000ULL,
		0x599096418C11B6CEULL,
		0x006B6F531A161137ULL,
		0xDDE2C2EF637028A1ULL,
		0x0000000029E3EF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xDF0805D289BBF9BAULL,
		0x8692F1930D617462ULL,
		0xA3B03B3E7CD9AAC2ULL,
		0x40DE0F3FB0710253ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE6E800000000000ULL,
		0x5D18B7C20174A26EULL,
		0x6AB0A1A4BC64C358ULL,
		0x4094E8EC0ECF9F36ULL,
		0x0000103783CFEC1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x41B7BAAB58EFFE0DULL,
		0xC87F8ED5A710AF43ULL,
		0xFFCE84EB9510B2ACULL,
		0x07640E9926868D07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAB58EFFE0D00000ULL,
		0xED5A710AF4341B7BULL,
		0x4EB9510B2ACC87F8ULL,
		0xE9926868D07FFCE8ULL,
		0x0000000000007640ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x54D87E14C52932ACULL,
		0x8CF7E9BE15838F40ULL,
		0xBAC8532C680F46D7ULL,
		0x73B818F3D5FBDE07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC298A5265580000ULL,
		0xD37C2B071E80A9B0ULL,
		0xA658D01E8DAF19EFULL,
		0x31E7ABF7BC0F7590ULL,
		0x000000000000E770ULL
	}};
	shift = 209;
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
		0xF73A76540EB2C9C9ULL,
		0x2014E29E0A0D0FF8ULL,
		0x285527ECE2BD2081ULL,
		0x0BCC5000A2DD6CCDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9C9000000000000ULL,
		0x0FF8F73A76540EB2ULL,
		0x20812014E29E0A0DULL,
		0x6CCD285527ECE2BDULL,
		0x00000BCC5000A2DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xCF43ECEBCA86FD0FULL,
		0xFA7627CD0AC7C824ULL,
		0x685766C533CDDDF0ULL,
		0x1B20147378C9CE10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C00000000000000ULL,
		0x933D0FB3AF2A1BF4ULL,
		0xC3E9D89F342B1F20ULL,
		0x41A15D9B14CF3777ULL,
		0x006C8051CDE32738ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
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
		0xE03968C5E57A356AULL,
		0x31BFB38022F8B1C1ULL,
		0xCCEB82C4FC3642C8ULL,
		0x6FA324F71AFB376DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5A8000000000000ULL,
		0xC70780E5A31795E8ULL,
		0x0B20C6FECE008BE2ULL,
		0xDDB733AE0B13F0D9ULL,
		0x0001BE8C93DC6BECULL,
		0x0000000000000000ULL
	}};
	shift = 178;
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
		0xDC3347417E1C62BAULL,
		0xDAF3C6ACC638ECAFULL,
		0x2943F2150C879066ULL,
		0x35E5CED85C44C16AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17E1C62BA0000000ULL,
		0xCC638ECAFDC33474ULL,
		0x50C879066DAF3C6AULL,
		0x85C44C16A2943F21ULL,
		0x00000000035E5CEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x7C5C148BFF0F3782ULL,
		0x03E3F2BA277B64FDULL,
		0x6E2B4FA83D5182B7ULL,
		0x225E15060088966AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x5F170522FFC3CDE0ULL,
		0xC0F8FCAE89DED93FULL,
		0x9B8AD3EA0F5460ADULL,
		0x089785418022259AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0xCBDAD209D91672ABULL,
		0xDECCE9F83C76E913ULL,
		0x3579AE97E6A5796EULL,
		0x6C8B106141E38C9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9558000000000000ULL,
		0x489E5ED6904EC8B3ULL,
		0xCB76F6674FC1E3B7ULL,
		0x64E1ABCD74BF352BULL,
		0x00036458830A0F1CULL
	}};
	shift = 243;
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
		0x498BFD047351CAB9ULL,
		0x01594C9C45C092EEULL,
		0x9C052E603CBEFBD3ULL,
		0x5F60B471A993B8F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CD472AE40000000ULL,
		0x117024BB9262FF41ULL,
		0x0F2FBEF4C0565327ULL,
		0x6A64EE3CE7014B98ULL,
		0x0000000017D82D1CULL,
		0x0000000000000000ULL
	}};
	shift = 158;
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
		0xE496EC417F48BB11ULL,
		0x352A68EB7EA98AEDULL,
		0xA4882985824C0F0EULL,
		0x58958E33BAFE1D03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDD882FE917622000ULL,
		0x4D1D6FD5315DBC92ULL,
		0x0530B04981E1C6A5ULL,
		0xB1C6775FC3A07491ULL,
		0x0000000000000B12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
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
		0x097EED165CE1A3A9ULL,
		0xC6A5D47CD080413CULL,
		0xD28871D415BDBF0CULL,
		0x03FA0981C50DB52DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3868EA4000000000ULL,
		0x20104F025FBB4597ULL,
		0x6F6FC331A9751F34ULL,
		0x436D4B74A21C7505ULL,
		0x00000000FE826071ULL
	}};
	shift = 230;
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
		0x8774AD6E0BE82E7CULL,
		0xFDDCD08A3B9C4613ULL,
		0x89D75B1584DE5E86ULL,
		0x23456AFAE3F56478ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADC17D05CF800000ULL,
		0x11477388C270EE95ULL,
		0x62B09BCBD0DFBB9AULL,
		0x5F5C7EAC8F113AEBULL,
		0x00000000000468ADULL
	}};
	shift = 213;
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
		0x90896853A099A073ULL,
		0x4E2D0288B7EB257FULL,
		0xF6C89663403385A9ULL,
		0x08D473B2BEF1F646ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40E6000000000000ULL,
		0x4AFF2112D0A74133ULL,
		0x0B529C5A05116FD6ULL,
		0xEC8DED912CC68067ULL,
		0x000011A8E7657DE3ULL
	}};
	shift = 241;
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
		0x341B714CEEEE6993ULL,
		0xDF7417479565D89EULL,
		0x4EE06424BA5F292FULL,
		0x3737B14F1285279FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C98000000000000ULL,
		0xC4F1A0DB8A677773ULL,
		0x497EFBA0BA3CAB2EULL,
		0x3CFA77032125D2F9ULL,
		0x0001B9BD8A789429ULL
	}};
	shift = 243;
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
		0xA5433AFB5EEAE564ULL,
		0x8C3B66F93A2C1CB3ULL,
		0x2DAD6D02FA02D876ULL,
		0x6817A48AD2237861ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC80000000000000ULL,
		0x9674A8675F6BDD5CULL,
		0x0ED1876CDF274583ULL,
		0x0C25B5ADA05F405BULL,
		0x000D02F4915A446FULL
	}};
	shift = 245;
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
		0xF24FB4BD37C0A545ULL,
		0xFFB45F620B5E311DULL,
		0x81606C6590AEF89FULL,
		0x20EA1D20E86514E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814A8A0000000000ULL,
		0xBC623BE49F697A6FULL,
		0x5DF13FFF68BEC416ULL,
		0xCA29C502C0D8CB21ULL,
		0x00000041D43A41D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
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
		0x6C84D1AEEDACDF75ULL,
		0xE227A5539199D920ULL,
		0x20AF7DB72B9AE047ULL,
		0x2E1C18529B0942A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB59BEEA0000000ULL,
		0x72333B240D909A35ULL,
		0xE5735C08FC44F4AAULL,
		0x536128550415EFB6ULL,
		0x0000000005C3830AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x58B6AF32FF2DEDBDULL,
		0xBD4C72C0707396C7ULL,
		0x96F6CBC67AB7E62EULL,
		0x59BCE37D05074161ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE800000000000000ULL,
		0x3AC5B57997F96F6DULL,
		0x75EA639603839CB6ULL,
		0x0CB7B65E33D5BF31ULL,
		0x02CDE71BE8283A0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0x2E8FB651D3F208F8ULL,
		0x3AF21231CBD50C45ULL,
		0x9DD7FA0B5B5EF90BULL,
		0x64CC05A1053A53DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3ED9474FC823E000ULL,
		0xC848C72F543114BAULL,
		0x5FE82D6D7BE42CEBULL,
		0x30168414E94F7E77ULL,
		0x0000000000000193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
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
		0x27E6A5D1BCA637E8ULL,
		0x28673C4FAD64F03AULL,
		0xFF0128C7D32F2EA9ULL,
		0x24E763AE4D1CD2D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD00000000000000ULL,
		0x0744FCD4BA3794C6ULL,
		0xD5250CE789F5AC9EULL,
		0x5A1FE02518FA65E5ULL,
		0x00049CEC75C9A39AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x42879B95C9B985D1ULL,
		0x4AB94A7BC3017F35ULL,
		0xAE382822D843E558ULL,
		0x7A4253C4705FB860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xA143CDCAE4DCC2E8ULL,
		0x255CA53DE180BF9AULL,
		0x571C14116C21F2ACULL,
		0x3D2129E2382FDC30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x109BD59CBB91BD97ULL,
		0x60BBFDCA4AEDB80CULL,
		0xED51FDB0A105BE34ULL,
		0x4ED673B3D036E10CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDEACE5DC8DECB800ULL,
		0xDFEE52576DC06084ULL,
		0x8FED85082DF1A305ULL,
		0xB39D9E81B708676AULL,
		0x0000000000000276ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
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
		0x3009E52626317A0EULL,
		0x64C4A69B1521258FULL,
		0x2A2D16701B2F6A9EULL,
		0x56879B9CD1E1273CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x31318BD070000000ULL,
		0xD8A9092C79804F29ULL,
		0x80D97B54F3262534ULL,
		0xE68F0939E15168B3ULL,
		0x0000000002B43CDCULL
	}};
	shift = 219;
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
		0x7F73CD05DB177D91ULL,
		0x8B5BE40F4DA4CA45ULL,
		0x31BD8A74F77DDC81ULL,
		0x334BB2E9A277CBCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8BBEC8800000000ULL,
		0x6D26522BFB9E682EULL,
		0xBBEEE40C5ADF207AULL,
		0x13BE5E618DEC53A7ULL,
		0x000000019A5D974DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
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
		0x8FA1770A7422253FULL,
		0x5F6A9CE85EAF448DULL,
		0x8B734CED2B2A583DULL,
		0x4F3A91173ED5406AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D0BB853A11129F8ULL,
		0xFB54E742F57A246CULL,
		0x5B9A67695952C1EAULL,
		0x79D488B9F6AA0354ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x4240224F362F2453ULL,
		0x9C6AF6AA39380065ULL,
		0xDA8EF60BF4D64E9BULL,
		0x632AA23768977FB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0x54240224F362F245ULL,
		0xB9C6AF6AA3938006ULL,
		0x1DA8EF60BF4D64E9ULL,
		0x0632AA23768977FBULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0xC1478547DBC4DB2EULL,
		0x29E1010383F48618ULL,
		0x59FC32355C54EA09ULL,
		0x11D3F9417770F57CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x478547DBC4DB2E00ULL,
		0xE1010383F48618C1ULL,
		0xFC32355C54EA0929ULL,
		0xD3F9417770F57C59ULL,
		0x0000000000000011ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xB0D1535ABAE3133BULL,
		0xBAC779C0D8D4FC8DULL,
		0xD5F99E8BEE6EC759ULL,
		0x69E6D4A2DAB59355ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4CEC00000000000ULL,
		0x3F236C3454D6AEB8ULL,
		0xB1D66EB1DE703635ULL,
		0x64D5757E67A2FB9BULL,
		0x00001A79B528B6ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x05C2CB556CA3A20FULL,
		0x7927CA1E5DC829FEULL,
		0x700A787636BEB01AULL,
		0x04E2CB80952F783EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x883C000000000000ULL,
		0xA7F8170B2D55B28EULL,
		0xC069E49F28797720ULL,
		0xE0F9C029E1D8DAFAULL,
		0x0000138B2E0254BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x7C8C369C6DB832C8ULL,
		0x913A8C3AC87CE93FULL,
		0xAA6D17FCF64BEF66ULL,
		0x5C000A7ED14E528FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x36DC196400000000ULL,
		0x643E749FBE461B4EULL,
		0x7B25F7B3489D461DULL,
		0x68A72947D5368BFEULL,
		0x000000002E00053FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
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
		0x5AE3099B652363A9ULL,
		0x35DCAEF2ED78BD7DULL,
		0x831F7064D80B1603ULL,
		0x22D6261DB65368D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D8EA40000000000ULL,
		0xE2F5F56B8C266D94ULL,
		0x2C580CD772BBCBB5ULL,
		0x4DA3560C7DC19360ULL,
		0x0000008B589876D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 42;
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
		0xF37E5D4A324ABB24ULL,
		0xB13D7878B4DE08E5ULL,
		0x7EFC996A53C10BA2ULL,
		0x61E5F4920855CE53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x92AEC90000000000ULL,
		0x3782397CDF97528CULL,
		0xF042E8AC4F5E1E2DULL,
		0x157394DFBF265A94ULL,
		0x00000018797D2482ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
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
		0x6BBE1EE59A359837ULL,
		0xD21FDC531220A718ULL,
		0xC4E0F55530B75574ULL,
		0x4FF7CB316E1CD86CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77C3DCB346B306E0ULL,
		0x43FB8A624414E30DULL,
		0x9C1EAAA616EAAE9AULL,
		0xFEF9662DC39B0D98ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0xD18B7F7FF896DD98ULL,
		0x3B2CC2CFBFDE15FBULL,
		0x70530653D4BA50FCULL,
		0x7F503F8AD2F0E5B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF7FF896DD9800000ULL,
		0x2CFBFDE15FBD18B7ULL,
		0x653D4BA50FC3B2CCULL,
		0xF8AD2F0E5B470530ULL,
		0x000000000007F503ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x67A1B5A05AA488C1ULL,
		0x697D455CA98244B3ULL,
		0xC0AD033E6C05BC91ULL,
		0x7A7A313E20701074ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xB3D0DAD02D524460ULL,
		0xB4BEA2AE54C12259ULL,
		0x6056819F3602DE48ULL,
		0x3D3D189F1038083AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
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
		0xE75FAC8BD66B80CBULL,
		0x620273F8028BEF37ULL,
		0x38B8F3B574BAC101ULL,
		0x34C0D2D1F8504CFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x917ACD7019600000ULL,
		0x7F00517DE6FCEBF5ULL,
		0x76AE9758202C404EULL,
		0x5A3F0A099F67171EULL,
		0x000000000006981AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xA581026ABE65AEDCULL,
		0x4CAF80472680CE47ULL,
		0xA64BB59D121184E8ULL,
		0x4CD4D6F00F3405CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60409AAF996BB700ULL,
		0x2BE011C9A03391E9ULL,
		0x92ED674484613A13ULL,
		0x3535BC03CD0172A9ULL,
		0x0000000000000013ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
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
		0x13E166703CF9CC09ULL,
		0x6215E041C70EFDF3ULL,
		0xF8DB68738D697977ULL,
		0x04FCF6DD168035BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B3381E7CE604800ULL,
		0xAF020E3877EF989FULL,
		0xDB439C6B4BCBBB10ULL,
		0xE7B6E8B401ADD7C6ULL,
		0x0000000000000027ULL
	}};
	shift = 203;
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
		0x7541B4B5261D8D14ULL,
		0xFE8E9622F68FDED5ULL,
		0xAE12E7F1676FEB35ULL,
		0x196287E076828932ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B5261D8D140000ULL,
		0x9622F68FDED57541ULL,
		0xE7F1676FEB35FE8EULL,
		0x87E076828932AE12ULL,
		0x0000000000001962ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x165B64F23E733293ULL,
		0xFB8535FDA09C4D43ULL,
		0xD0A58AE1BB10BB38ULL,
		0x0A7CB1D979672391ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64F23E7332930000ULL,
		0x35FDA09C4D43165BULL,
		0x8AE1BB10BB38FB85ULL,
		0xB1D979672391D0A5ULL,
		0x0000000000000A7CULL
	}};
	shift = 208;
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
		0x375EB0B502E94719ULL,
		0xC964394A9FE1FF3DULL,
		0x291BAE1491E2E6DBULL,
		0x5759A74AB05FBB5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8174A38C80000000ULL,
		0x4FF0FF9E9BAF585AULL,
		0x48F1736DE4B21CA5ULL,
		0x582FDDAF148DD70AULL,
		0x000000002BACD3A5ULL
	}};
	shift = 223;
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
		0xCE26F2DF32262551ULL,
		0xC4AE7EEB0543433BULL,
		0xE86C170826348CDBULL,
		0x39EA61E6D98ADAD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F2DF32262551000ULL,
		0xE7EEB0543433BCE2ULL,
		0xC170826348CDBC4AULL,
		0xA61E6D98ADAD9E86ULL,
		0x000000000000039EULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0xD5DAA1F06DE3AEF9ULL,
		0x924B3053770295B6ULL,
		0x269049774BCF0181ULL,
		0x4948A60B574E94A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36F1D77C80000000ULL,
		0xBB814ADB6AED50F8ULL,
		0xA5E780C0C9259829ULL,
		0xABA74A52934824BBULL,
		0x0000000024A45305ULL
	}};
	shift = 223;
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
		0xA2057E96AD6A998CULL,
		0x49069D6807E4A0CAULL,
		0x6C09CDB8D3361DF7ULL,
		0x090B57982580B721ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAD6A998C00000000ULL,
		0x07E4A0CAA2057E96ULL,
		0xD3361DF749069D68ULL,
		0x2580B7216C09CDB8ULL,
		0x00000000090B5798ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0xC51D21AF7C9DFC22ULL,
		0xDCD4517B11C5DD94ULL,
		0x4E236BD508EA4119ULL,
		0x2D049818B4A7D629ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A3A435EF93BF844ULL,
		0xB9A8A2F6238BBB29ULL,
		0x9C46D7AA11D48233ULL,
		0x5A093031694FAC52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
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
		0xCAD0C3EB6B555EDEULL,
		0xD1EB1B2C38AF13CDULL,
		0x22A241F236C54DC3ULL,
		0x18A3D4677B34D3EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FADAD557B78000ULL,
		0xC6CB0E2BC4F372B4ULL,
		0x907C8DB15370F47AULL,
		0xF519DECD34FAC8A8ULL,
		0x0000000000000628ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xABCD94B3AB9B0C7CULL,
		0x648B3CD286ECC0D1ULL,
		0x5E3F1597C438FDB8ULL,
		0x54DEB8D044B3D6F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x59D5CD863E000000ULL,
		0x6943766068D5E6CAULL,
		0xCBE21C7EDC32459EULL,
		0x682259EB79AF1F8AULL,
		0x00000000002A6F5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
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
		0x2B15D053275E1566ULL,
		0x07854E492B7F124CULL,
		0xF50694F89AD2CE50ULL,
		0x404EF06301624F81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x8562BA0A64EBC2ACULL,
		0x00F0A9C9256FE249ULL,
		0x3EA0D29F135A59CAULL,
		0x0809DE0C602C49F0ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x1C3FD27272A19AFFULL,
		0xF26E901BDB8D6DF1ULL,
		0x229903E8780939BFULL,
		0x2DECB419F4F173CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC3FD27272A19AFF0ULL,
		0x26E901BDB8D6DF11ULL,
		0x29903E8780939BFFULL,
		0xDECB419F4F173CE2ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
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
		0xAC918D822527A2FDULL,
		0x6FF07E2ECC927B4DULL,
		0x4572D3B70237DDFAULL,
		0x6484A68A1F2DB2B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC918D822527A2FD0ULL,
		0xFF07E2ECC927B4DAULL,
		0x572D3B70237DDFA6ULL,
		0x484A68A1F2DB2B44ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
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
		0x99C0707AF73A683DULL,
		0x37F510401E98A5FAULL,
		0xCE3C2410A566024AULL,
		0x788047E03EB60884ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF400000000000000ULL,
		0xEA6701C1EBDCE9A0ULL,
		0x28DFD441007A6297ULL,
		0x1338F09042959809ULL,
		0x01E2011F80FAD822ULL
	}};
	shift = 250;
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
		0x38B52E0785A00AC8ULL,
		0x096542A26169F8C2ULL,
		0xB55554F0B4AB12A4ULL,
		0x010CB41A6DA94521ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE16802B200000000ULL,
		0x985A7E308E2D4B81ULL,
		0x2D2AC4A9025950A8ULL,
		0x9B6A51486D55553CULL,
		0x0000000000432D06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
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
		0xC04602D6F5D4B0A7ULL,
		0x804B681C4C42AF83ULL,
		0x5D1BB61ACC1AF62EULL,
		0x27B32649CB30665AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xE023016B7AEA5853ULL,
		0x4025B40E262157C1ULL,
		0x2E8DDB0D660D7B17ULL,
		0x13D99324E598332DULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0xCB3DF9E9244FE2DBULL,
		0x3D23262437F3CD20ULL,
		0x727F50239C507DEAULL,
		0x1F0558386E5CB4FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D80000000000000ULL,
		0x90659EFCF49227F1ULL,
		0xF51E9193121BF9E6ULL,
		0x7FB93FA811CE283EULL,
		0x000F82AC1C372E5AULL
	}};
	shift = 247;
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
		0x76971A60E770817FULL,
		0x4FD50E5302FF2C62ULL,
		0x0C33409CDC684AEDULL,
		0x237F8BA457475C7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC00000000000000ULL,
		0x89DA5C69839DC205ULL,
		0xB53F54394C0BFCB1ULL,
		0xF430CD027371A12BULL,
		0x008DFE2E915D1D71ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
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
		0x6A535C289BAE7A72ULL,
		0xA982CF45A7337EE9ULL,
		0x7BB56B58AC4291BDULL,
		0x13D11119A552B839ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC800000000000000ULL,
		0xA5A94D70A26EB9E9ULL,
		0xF6A60B3D169CCDFBULL,
		0xE5EED5AD62B10A46ULL,
		0x004F444466954AE0ULL
	}};
	shift = 250;
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
		0xC9C71246880BE7CEULL,
		0xB12363B3AEB95683ULL,
		0x9CC11AF5A3695E6EULL,
		0x04079F754101811EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC491A202F9F38000ULL,
		0xD8ECEBAE55A0F271ULL,
		0x46BD68DA579BAC48ULL,
		0xE7DD50406047A730ULL,
		0x0000000000000101ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
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
		0xB93883F3A908E44FULL,
		0x2A0956477CD8795CULL,
		0xAB12AA73113311B6ULL,
		0x2C2710680FF9EF32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA908E44F00000000ULL,
		0x7CD8795CB93883F3ULL,
		0x113311B62A095647ULL,
		0x0FF9EF32AB12AA73ULL,
		0x000000002C271068ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x0D538EDEFB766CF2ULL,
		0xC5CF2F65477EFF87ULL,
		0x4A5401A696C2D19EULL,
		0x357B844699C74367ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7DBB367900000000ULL,
		0xA3BF7FC386A9C76FULL,
		0x4B6168CF62E797B2ULL,
		0x4CE3A1B3A52A00D3ULL,
		0x000000001ABDC223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
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
		0xD4086E49AD8B2685ULL,
		0x3702E28E7F59C9C3ULL,
		0x836F096D19237563ULL,
		0x646F8AA4A1B4E325ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8500000000000000ULL,
		0xC3D4086E49AD8B26ULL,
		0x633702E28E7F59C9ULL,
		0x25836F096D192375ULL,
		0x00646F8AA4A1B4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
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
		0x22F1010087E52544ULL,
		0xDDB3756A29C776BCULL,
		0xFE56E8B8EDE50C3EULL,
		0x0643FCA0844D88CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2F1010087E525440ULL,
		0xDB3756A29C776BC2ULL,
		0xE56E8B8EDE50C3EDULL,
		0x643FCA0844D88CAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
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
		0x2312E9DC30E4D5CDULL,
		0x9DBB4EA9243A7AACULL,
		0x21733BB48CEC5299ULL,
		0x0AA454675F12933AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9DC30E4D5CD0000ULL,
		0x4EA9243A7AAC2312ULL,
		0x3BB48CEC52999DBBULL,
		0x54675F12933A2173ULL,
		0x0000000000000AA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x09797AECF3AFF1AFULL,
		0xDE8D4B1DCB5F696AULL,
		0x24F98B515BEFD2A8ULL,
		0x4EC9ADB5AF81A69EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0xA09797AECF3AFF1AULL,
		0x8DE8D4B1DCB5F696ULL,
		0xE24F98B515BEFD2AULL,
		0x04EC9ADB5AF81A69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
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
		0x3361B951DFA0F6A1ULL,
		0xB35852F76D2B23E0ULL,
		0xE9852249D02D8E78ULL,
		0x7247FABD180E1F49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x41ED420000000000ULL,
		0x5647C066C372A3BFULL,
		0x5B1CF166B0A5EEDAULL,
		0x1C3E93D30A4493A0ULL,
		0x000000E48FF57A30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0xF2622FED18D7CA58ULL,
		0x0D3EADB9C5C2BCBBULL,
		0x2CA7955C0170B095ULL,
		0x71ED8F05AAFF3F89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC45FDA31AF94B000ULL,
		0x7D5B738B857977E4ULL,
		0x4F2AB802E1612A1AULL,
		0xDB1E0B55FE7F1259ULL,
		0x00000000000000E3ULL
	}};
	shift = 201;
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
		0xD349DE2992A7C72BULL,
		0x6018568291EBF548ULL,
		0x016D88E36C96CC47ULL,
		0x38C51984C9A604DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C953E3958000000ULL,
		0x148F5FAA469A4EF1ULL,
		0x1B64B6623B00C2B4ULL,
		0x264D3026F00B6C47ULL,
		0x0000000001C628CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
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
		0x115C1A04B3FFE09AULL,
		0x9309A792F86A0A92ULL,
		0x4B8EC49441FA177DULL,
		0x24A5CD29B72C8D65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFFF04D0000000000ULL,
		0x35054908AE0D0259ULL,
		0xFD0BBEC984D3C97CULL,
		0x9646B2A5C7624A20ULL,
		0x0000001252E694DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
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
		0x99EC7C38DB74F5ECULL,
		0xDBFCF0D794D09AFFULL,
		0xC6BF655D82F7094BULL,
		0x6D73609BAC5A3332ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F871B6E9EBD8000ULL,
		0x9E1AF29A135FF33DULL,
		0xECABB05EE1297B7FULL,
		0x6C13758B466658D7ULL,
		0x0000000000000DAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x86EC3F1C9F587F8FULL,
		0x2D49A2B50EAE88E5ULL,
		0x36123F11C2F80530ULL,
		0x5792CF48CA15A198ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x61BB0FC727D61FE3ULL,
		0x0B5268AD43ABA239ULL,
		0x0D848FC470BE014CULL,
		0x15E4B3D232856866ULL
	}};
	shift = 254;
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
		0x25FD675895619E99ULL,
		0xF6307A0BD3536DE8ULL,
		0x6D478E2D72B608E0ULL,
		0x3DD1E6738B76985BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3AC4AB0CF4C8000ULL,
		0x3D05E9A9B6F412FEULL,
		0xC716B95B04707B18ULL,
		0xF339C5BB4C2DB6A3ULL,
		0x0000000000001EE8ULL
	}};
	shift = 207;
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
		0x9B1EE3C34722AE95ULL,
		0x3225F1DDE4F96079ULL,
		0xC5780E34569F7845ULL,
		0x770E37F4931B0ADEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA54000000000000ULL,
		0x81E66C7B8F0D1C8AULL,
		0xE114C897C77793E5ULL,
		0x2B7B15E038D15A7DULL,
		0x0001DC38DFD24C6CULL,
		0x0000000000000000ULL
	}};
	shift = 178;
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
		0xBBDC3649DD8AC650ULL,
		0x1819DD4B962B1B3DULL,
		0x7B5A72446695DE60ULL,
		0x42C6E45CC7D6CFF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF70D927762B19400ULL,
		0x067752E58AC6CF6EULL,
		0xD69C9119A5779806ULL,
		0xB1B91731F5B3FD9EULL,
		0x0000000000000010ULL
	}};
	shift = 198;
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
		0x59DD0935A1280E09ULL,
		0x875FEAAFAE36A474ULL,
		0x9A1DC8C6AEEFEA1AULL,
		0x75ECB222C969F373ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59DD0935A1280E09ULL,
		0x875FEAAFAE36A474ULL,
		0x9A1DC8C6AEEFEA1AULL,
		0x75ECB222C969F373ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xF3B286FB4BCDCF21ULL,
		0x1D256FEDA9C2E492ULL,
		0xF887B95F5051C88AULL,
		0x7ADC7A22A1984C65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xBCECA1BED2F373C8ULL,
		0x87495BFB6A70B924ULL,
		0x7E21EE57D4147222ULL,
		0x1EB71E88A8661319ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0x00946A607280E542ULL,
		0x112C995E8E726F8AULL,
		0x39A911738E60D2D1ULL,
		0x3657B3C98C752AF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA039508000000000ULL,
		0x9C9BE280251A981CULL,
		0x9834B4444B2657A3ULL,
		0x1D4ABD4E6A445CE3ULL,
		0x0000000D95ECF263ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
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
		0xF89A4B20901C1D96ULL,
		0x8379802A5882509AULL,
		0xF8C3517DD4992484ULL,
		0x559F9AAD9F60D092ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6580000000000000ULL,
		0x26BE2692C8240707ULL,
		0x2120DE600A962094ULL,
		0x24BE30D45F752649ULL,
		0x001567E6AB67D834ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0x98E53B984F1A7C39ULL,
		0xEC22297A67CBACD0ULL,
		0x5F21A0B00F5B70A1ULL,
		0x2BCC001B125C92D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x69F0E40000000000ULL,
		0x2EB3426394EE613CULL,
		0x6DC287B088A5E99FULL,
		0x724B617C8682C03DULL,
		0x000000AF30006C49ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
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
		0xF4FB6A213E10686EULL,
		0x0F9798889FB7CDE8ULL,
		0x4B0C3D1A776A8CD4ULL,
		0x32A95F95D0905286ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0686E00000000000ULL,
		0x7CDE8F4FB6A213E1ULL,
		0xA8CD40F9798889FBULL,
		0x052864B0C3D1A776ULL,
		0x0000032A95F95D09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xA73055B2CAE9CCB2ULL,
		0xE13C4808AEB6E347ULL,
		0x6A6EA2AEBA6CAAEBULL,
		0x29637EC36378F88FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x95D3996400000000ULL,
		0x5D6DC68F4E60AB65ULL,
		0x74D955D7C2789011ULL,
		0xC6F1F11ED4DD455DULL,
		0x0000000052C6FD86ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
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
		0x84341956CDF2FB98ULL,
		0xF08F4A978C5AAA80ULL,
		0x74194ACA559EB27EULL,
		0x3E02DEAEC8178A93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66F97DCC00000000ULL,
		0xC62D5540421A0CABULL,
		0x2ACF593F7847A54BULL,
		0x640BC549BA0CA565ULL,
		0x000000001F016F57ULL
	}};
	shift = 223;
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
		0x5C7354DB5A03A6B9ULL,
		0x3E51E932F2AA8B29ULL,
		0xBAF9CFDB1023E7C2ULL,
		0x329CD86742ABA3DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9AA6DAD01D35C800ULL,
		0x8F49979554594AE3ULL,
		0xCE7ED8811F3E11F2ULL,
		0xE6C33A155D1EFDD7ULL,
		0x0000000000000194ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0x942EA7632837A924ULL,
		0xCB278285333D482CULL,
		0xE9A395A40580DF4EULL,
		0x7D40B25ED79E662CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA49000000000000ULL,
		0x520B250BA9D8CA0DULL,
		0x37D3B2C9E0A14CCFULL,
		0x998B3A68E5690160ULL,
		0x00001F502C97B5E7ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
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
		0x8991EF30EBD60344ULL,
		0x012AC0F700228BCEULL,
		0xBA696BC1CDD72C3DULL,
		0x3386E8A379066896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF580D10000000000ULL,
		0x08A2F3A2647BCC3AULL,
		0x75CB0F404AB03DC0ULL,
		0x419A25AE9A5AF073ULL,
		0x0000000CE1BA28DEULL
	}};
	shift = 230;
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
		0x847A656C2821C3EDULL,
		0x2FDA627A12F51CC3ULL,
		0xB282B63D3AD9236FULL,
		0x0FBB79E187A64815ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB61410E1F6800000ULL,
		0x3D097A8E61C23D32ULL,
		0x1E9D6C91B797ED31ULL,
		0xF0C3D3240AD9415BULL,
		0x000000000007DDBCULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0x16A0D63FA3A738B4ULL,
		0x97443CA89A5C4358ULL,
		0x7EBD794DFF828DABULL,
		0x5D66D7EC0C582DE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738B400000000000ULL,
		0xC435816A0D63FA3AULL,
		0x28DAB97443CA89A5ULL,
		0x82DE17EBD794DFF8ULL,
		0x000005D66D7EC0C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0xF706649C10EDC9BFULL,
		0x498F60D3C355DCE3ULL,
		0x7CCF135A89278D52ULL,
		0x749FBF771C646E42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21DB937E00000000ULL,
		0x86ABB9C7EE0CC938ULL,
		0x124F1AA4931EC1A7ULL,
		0x38C8DC84F99E26B5ULL,
		0x00000000E93F7EEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x6102E58BC29E7F5DULL,
		0x04551146750BE579ULL,
		0x062615A439E7F69BULL,
		0x11518046BCCA1170ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFAE8000000000000ULL,
		0x2BCB08172C5E14F3ULL,
		0xB4D822A88A33A85FULL,
		0x8B803130AD21CF3FULL,
		0x00008A8C0235E650ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
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
		0xDFAA5EC5239F46FDULL,
		0x104E15FDB4699CBAULL,
		0x723964CCE5594FFCULL,
		0x41F4828241A74CD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0xADFAA5EC5239F46FULL,
		0xC104E15FDB4699CBULL,
		0x0723964CCE5594FFULL,
		0x041F4828241A74CDULL
	}};
	shift = 252;
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
		0x41DCB74AD02AFF61ULL,
		0xDFD09C63F0FF0112ULL,
		0x4DE6A368AE7F576AULL,
		0x357A531E67E7E0EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B40ABFD8400000ULL,
		0x18FC3FC04490772DULL,
		0xDA2B9FD5DAB7F427ULL,
		0xC799F9F83AD379A8ULL,
		0x00000000000D5E94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0x8B39F953F85BCF6BULL,
		0x73B52CADF761E4DAULL,
		0xBBAC711370D7208EULL,
		0x2EB2EE3AFA6BB201ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79ED600000000000ULL,
		0x3C9B51673F2A7F0BULL,
		0xE411CE76A595BEECULL,
		0x764037758E226E1AULL,
		0x000005D65DC75F4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x8F7A2946B8B2628DULL,
		0x5EB7D5546421463BULL,
		0x751DC3B099567805ULL,
		0x08F2F192747EC5AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14A35C5931468000ULL,
		0xEAAA3210A31DC7BDULL,
		0xE1D84CAB3C02AF5BULL,
		0x78C93A3F62D53A8EULL,
		0x0000000000000479ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x0D4B60A606CC1763ULL,
		0x6B4D96A475181A5EULL,
		0xD5BAD381335DA52AULL,
		0x2B97D37E97EF84DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4B60A606CC17630ULL,
		0xB4D96A475181A5E0ULL,
		0x5BAD381335DA52A6ULL,
		0xB97D37E97EF84DCDULL,
		0x0000000000000002ULL
	}};
	shift = 196;
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
		0x79D46CEBD37CEB50ULL,
		0x617508E190139484ULL,
		0x7EDBAD4542F5D730ULL,
		0x5E0643F93FA705F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9D7A6F9D6A000000ULL,
		0x1C320272908F3A8DULL,
		0xA8A85EBAE60C2EA1ULL,
		0x7F27F4E0BE4FDB75ULL,
		0x00000000000BC0C8ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
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
		0x34C1F1B62D16940AULL,
		0x4FDCEEC1CC1E3A5DULL,
		0x8C795E2B82B66D55ULL,
		0x47AA8870C68B17D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D8B45A502800000ULL,
		0xB073078E974D307CULL,
		0x8AE0AD9B5553F73BULL,
		0x1C31A2C5F5631E57ULL,
		0x000000000011EAA2ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
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
		0xF4642A9EDEE3DB41ULL,
		0x83656703D6A081D0ULL,
		0xC8C7EB0229281CBFULL,
		0x61AA476C15381365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF4642A9EDEE3DB41ULL,
		0x83656703D6A081D0ULL,
		0xC8C7EB0229281CBFULL,
		0x61AA476C15381365ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
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
		0xC9F4C823BBB29ECBULL,
		0x9E73CFA4935C312BULL,
		0xF88455D447174EBEULL,
		0x27143709A003C341ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93E9904777653D96ULL,
		0x3CE79F4926B86257ULL,
		0xF108ABA88E2E9D7DULL,
		0x4E286E1340078683ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
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
		0x152229663DE32D6EULL,
		0xAF1F279A6113C3AAULL,
		0x2F91A6B3513CD378ULL,
		0x6BFA96F9547D3D85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x96B7000000000000ULL,
		0xE1D50A9114B31EF1ULL,
		0x69BC578F93CD3089ULL,
		0x9EC297C8D359A89EULL,
		0x000035FD4B7CAA3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
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
		0xA7DE9C99BEE683FAULL,
		0x47ADF22A51333C0DULL,
		0xAF1D87061908680CULL,
		0x21A64B332BCCE8A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41FD000000000000ULL,
		0x9E06D3EF4E4CDF73ULL,
		0x340623D6F9152899ULL,
		0x7454578EC3830C84ULL,
		0x000010D3259995E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x8328198F3EC74D13ULL,
		0x6F2F6239D320DA60ULL,
		0x32FF472D8AFCDF37ULL,
		0x365D88FB16D7BC1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x10650331E7D8E9A2ULL,
		0xEDE5EC473A641B4CULL,
		0x665FE8E5B15F9BE6ULL,
		0x06CBB11F62DAF783ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
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
		0x4D3BF85E0D4EEA03ULL,
		0xA9308F3FE9E8303EULL,
		0xED9E1C632B9F3418ULL,
		0x20A14EF7BBB45D87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF85E0D4EEA03000ULL,
		0x08F3FE9E8303E4D3ULL,
		0xE1C632B9F3418A93ULL,
		0x14EF7BBB45D87ED9ULL,
		0x000000000000020AULL,
		0x0000000000000000ULL
	}};
	shift = 140;
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
		0x3399723079E271AFULL,
		0x528FF6499991BF54ULL,
		0xED05D965D51731E5ULL,
		0x24CA2BE554D57646ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9183CF138D780000ULL,
		0xB24CCC8DFAA19CCBULL,
		0xCB2EA8B98F2A947FULL,
		0x5F2AA6ABB237682EULL,
		0x0000000000012651ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
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
		0x9E39C51F6D502B4EULL,
		0xC284C51E361C01C0ULL,
		0xB008DBC50EE04EA3ULL,
		0x371C1DC0D6143EDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA0569C0000000000ULL,
		0x3803813C738A3EDAULL,
		0xC09D4785098A3C6CULL,
		0x287DBD6011B78A1DULL,
		0x0000006E383B81ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0x038ED7DFAAB3C05CULL,
		0x996A7E9E4B9CDB8AULL,
		0x98D3F3BCA15E128BULL,
		0x7CEC149DCB426118ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEFD559E02E000000ULL,
		0x4F25CE6DC501C76BULL,
		0xDE50AF0945CCB53FULL,
		0x4EE5A1308C4C69F9ULL,
		0x00000000003E760AULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0xA72F9C88B9257A96ULL,
		0xE29EB311F683BF9DULL,
		0xA30AFFF89816D211ULL,
		0x41E662753A47D313ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE495EA5800000000ULL,
		0xDA0EFE769CBE7222ULL,
		0x605B48478A7ACC47ULL,
		0xE91F4C4E8C2BFFE2ULL,
		0x00000001079989D4ULL
	}};
	shift = 226;
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
		0x277419AE74700ECDULL,
		0x3EFC779452F986D9ULL,
		0x9518C19E51C423DBULL,
		0x11BC7E917306238CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x00ECD00000000000ULL,
		0x986D9277419AE747ULL,
		0x423DB3EFC779452FULL,
		0x6238C9518C19E51CULL,
		0x0000011BC7E91730ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
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
		0xD71403E51ACC63BFULL,
		0x0E66BFD56F8A5B36ULL,
		0x471A48CADB431598ULL,
		0x60151E86E53663B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC00000000000000ULL,
		0xDB5C500F946B318EULL,
		0x60399AFF55BE296CULL,
		0xD11C69232B6D0C56ULL,
		0x0180547A1B94D98EULL
	}};
	shift = 250;
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
		0x085D218F4F5FF7F0ULL,
		0x02FB023A5C616101ULL,
		0x85FD499F3A89AD1DULL,
		0x77D66A8DC670929BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBF800000000000ULL,
		0x0B080842E90C7A7AULL,
		0x4D68E817D811D2E3ULL,
		0x8494DC2FEA4CF9D4ULL,
		0x000003BEB3546E33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
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
		0x0E696D77D12D456AULL,
		0xB4AE94F61DA0A113ULL,
		0x35C13DEB520CEC49ULL,
		0x76433862A90DE0B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12D456A000000000ULL,
		0xDA0A1130E696D77DULL,
		0x20CEC49B4AE94F61ULL,
		0x90DE0B535C13DEB5ULL,
		0x000000076433862AULL
	}};
	shift = 228;
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
		0x9C5E581BEE921F0CULL,
		0xE907CCC8912F327EULL,
		0x1D75FCD371F29CD0ULL,
		0x73184EBB07EAD7DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81BEE921F0C00000ULL,
		0xCC8912F327E9C5E5ULL,
		0xCD371F29CD0E907CULL,
		0xEBB07EAD7DB1D75FULL,
		0x0000000000073184ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
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
		0x481D6D1C1D53B81AULL,
		0x1B45FF99CFC454B9ULL,
		0x06FD781C9D104F26ULL,
		0x432CE2583567311AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7703400000000000ULL,
		0x8A972903ADA383AAULL,
		0x09E4C368BFF339F8ULL,
		0xE62340DFAF0393A2ULL,
		0x000008659C4B06ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x0DE342B024070D11ULL,
		0x0B150538987AB504ULL,
		0xC7A753EF0AE5D39AULL,
		0x510EC1D988C75550ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE342B024070D1100ULL,
		0x150538987AB5040DULL,
		0xA753EF0AE5D39A0BULL,
		0x0EC1D988C75550C7ULL,
		0x0000000000000051ULL
	}};
	shift = 200;
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
		0x28CD23F2FBEAD1B3ULL,
		0x170C8AC1CB4C4084ULL,
		0x0427E52328FED11AULL,
		0x46174B8729C108DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19A47E5F7D5A3660ULL,
		0xE191583969881085ULL,
		0x84FCA4651FDA2342ULL,
		0xC2E970E538211BC0ULL,
		0x0000000000000008ULL
	}};
	shift = 197;
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
		0xE4BC1AAF14A485B1ULL,
		0x59CE1A8A670F5FA1ULL,
		0xA139D784B7B4A344ULL,
		0x73EAE2F2A455CA57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC400000000000000ULL,
		0x8792F06ABC529216ULL,
		0x1167386A299C3D7EULL,
		0x5E84E75E12DED28DULL,
		0x01CFAB8BCA915729ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
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
		0xBC08D4AC08E7393CULL,
		0xA6F8FED651D102C5ULL,
		0xAF75F624EC07AFC0ULL,
		0x4DEE2AD0168E53C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE4F000000000000ULL,
		0x40B16F02352B0239ULL,
		0xEBF029BE3FB59474ULL,
		0x94F0EBDD7D893B01ULL,
		0x0000137B8AB405A3ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
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
		0xFAC34B86FF5955B7ULL,
		0x00F1C805B17A62F5ULL,
		0xE186A3EE6E8F7F20ULL,
		0x10CF1E6AD819000AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556DC00000000000ULL,
		0x98BD7EB0D2E1BFD6ULL,
		0xDFC8003C72016C5EULL,
		0x4002B861A8FB9BA3ULL,
		0x00000433C79AB606ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xAE9407349765C57CULL,
		0xE87BC2F8F42A250BULL,
		0xA0BC52D6C450E881ULL,
		0x41A1E119D8DE74DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD25D9715F000000ULL,
		0xBE3D0A8942EBA501ULL,
		0xB5B1143A207A1EF0ULL,
		0x4676379D37A82F14ULL,
		0x0000000000106878ULL
	}};
	shift = 214;
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
		0xD886858F1B395CADULL,
		0x59BAD2C1DC214569ULL,
		0x9B1EBA95A89E349DULL,
		0x1D80D25883B328CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F1B395CAD00000ULL,
		0x2C1DC214569D8868ULL,
		0xA95A89E349D59BADULL,
		0x25883B328CE9B1EBULL,
		0x000000000001D80DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xEC416E9D9272E9D3ULL,
		0x43496694B8D52E24ULL,
		0xBE622C4F042B518EULL,
		0x38A14101895A86C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x416E9D9272E9D300ULL,
		0x496694B8D52E24ECULL,
		0x622C4F042B518E43ULL,
		0xA14101895A86C9BEULL,
		0x0000000000000038ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
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
		0x179670F2BE17F5DBULL,
		0x7FDC349450A2ED27ULL,
		0x962496C6E2AC95ACULL,
		0x031E81B4BC0AF195ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BE17F5DB0000000ULL,
		0x450A2ED27179670FULL,
		0x6E2AC95AC7FDC349ULL,
		0x4BC0AF195962496CULL,
		0x000000000031E81BULL,
		0x0000000000000000ULL
	}};
	shift = 156;
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
		0x0823559AC6C8160EULL,
		0x795042D9AC19C455ULL,
		0x4583FBDCA0ECCE16ULL,
		0x6AEA229F640375A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB358D902C1C00000ULL,
		0x5B3583388AA1046AULL,
		0x7B941D99C2CF2A08ULL,
		0x53EC806EB4E8B07FULL,
		0x00000000000D5D44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x834D6DCB5BD90546ULL,
		0xC5600F471E04C602ULL,
		0x7E7DF7BEBD3462E4ULL,
		0x2276BCC11502DE91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6F64151800000000ULL,
		0x7813180A0D35B72DULL,
		0xF4D18B9315803D1CULL,
		0x540B7A45F9F7DEFAULL,
		0x0000000089DAF304ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
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
		0x445F1F5296FF30E8ULL,
		0x81970AE3031A6242ULL,
		0x322D68FD8D9E659CULL,
		0x11D8BE97FE3C8C22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF30E80000000000ULL,
		0x1A6242445F1F5296ULL,
		0x9E659C81970AE303ULL,
		0x3C8C22322D68FD8DULL,
		0x00000011D8BE97FEULL
	}};
	shift = 232;
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
		0x93D267E78EB68405ULL,
		0xC0D67A327CCF4FB9ULL,
		0xF766228D87293DB9ULL,
		0x007E1FDCD1CB569EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3ADA101400000000ULL,
		0xF33D3EE64F499F9EULL,
		0x1CA4F6E70359E8C9ULL,
		0x472D5A7BDD988A36ULL,
		0x0000000001F87F73ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
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
		0xA85CBD31342CFC6FULL,
		0xB7980B0510F684F2ULL,
		0x2970212B998C8353ULL,
		0x712EF83D8D9A76B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0B97A626859F8DE0ULL,
		0xF30160A21ED09E55ULL,
		0x2E04257331906A76ULL,
		0x25DF07B1B34ED685ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
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
		0x3A73B1123C27B703ULL,
		0x18DCBFE0C609D394ULL,
		0x18DC586765E4A2D4ULL,
		0x1416D3CC607D031EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0C0000000000000ULL,
		0xE50E9CEC448F09EDULL,
		0xB506372FF8318274ULL,
		0xC786371619D97928ULL,
		0x000505B4F3181F40ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x2D9076D3C56974B7ULL,
		0x2F9B75CC6023F49FULL,
		0x2CF1B2421A0AC07EULL,
		0x474E2A723813F199ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD2DC000000000000ULL,
		0xD27CB641DB4F15A5ULL,
		0x01F8BE6DD731808FULL,
		0xC664B3C6C908682BULL,
		0x00011D38A9C8E04FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0xF008C6E4097969DEULL,
		0xA8B1CE27AB39D898ULL,
		0x3CFAFDBD8370C04BULL,
		0x29F8F8BBD3FC881AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3BC00000000000ULL,
		0x3B131E0118DC812FULL,
		0x1809751639C4F567ULL,
		0x9103479F5FB7B06EULL,
		0x0000053F1F177A7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x74B86C5E644914FCULL,
		0xA1C55E3E65234544ULL,
		0xADCB8A7ECB6ACF62ULL,
		0x5D5BFFBD1A5F02A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE970D8BCC89229F8ULL,
		0x438ABC7CCA468A88ULL,
		0x5B9714FD96D59EC5ULL,
		0xBAB7FF7A34BE054FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
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
		0xFD39AEEA57D53B65ULL,
		0x137BB785091C579BULL,
		0x6974A130BB37941FULL,
		0x52B472C60EF1E289ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6500000000000000ULL,
		0x9BFD39AEEA57D53BULL,
		0x1F137BB785091C57ULL,
		0x896974A130BB3794ULL,
		0x0052B472C60EF1E2ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
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
		0x05BC6FF57792F617ULL,
		0xD453577D04E06F4BULL,
		0xD9A7B65D5C4374D3ULL,
		0x78E4958C5681788BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57792F6170000000ULL,
		0xD04E06F4B05BC6FFULL,
		0xD5C4374D3D453577ULL,
		0xC5681788BD9A7B65ULL,
		0x00000000078E4958ULL
	}};
	shift = 220;
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
		0x3BB67B87804E42C6ULL,
		0x623B33E695E35E79ULL,
		0xFB6C01A137EF241CULL,
		0x74D0F677D803505FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC858C00000000000ULL,
		0x6BCF2776CF70F009ULL,
		0xE4838C47667CD2BCULL,
		0x6A0BFF6D803426FDULL,
		0x00000E9A1ECEFB00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
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
		0x264AD799234BD0DEULL,
		0x01CB0C0FB582F779ULL,
		0x35C11A917761463AULL,
		0x2C5B3F70F004B0F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x86F0000000000000ULL,
		0xBBC93256BCC91A5EULL,
		0x31D00E58607DAC17ULL,
		0x87C1AE08D48BBB0AULL,
		0x000162D9FB878025ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
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
		0x757D32EFBD4B228CULL,
		0xAF3CA52EB2D2C9F1ULL,
		0x4136481298850486ULL,
		0x74E7384ABD005E34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE9977DEA59146000ULL,
		0xE5297596964F8BABULL,
		0xB24094C428243579ULL,
		0x39C255E802F1A209ULL,
		0x00000000000003A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
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
		0x9E4929906346E984ULL,
		0xA4DEE7EAD3AD9818ULL,
		0x7B5A239D7E6DC976ULL,
		0x796C21F3FA7E5902ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C68DD3080000000ULL,
		0x5A75B30313C92532ULL,
		0xAFCDB92ED49BDCFDULL,
		0x7F4FCB204F6B4473ULL,
		0x000000000F2D843EULL,
		0x0000000000000000ULL
	}};
	shift = 157;
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
		0x24BF4E3FB60FF50FULL,
		0xA3DDD70C1485DFFDULL,
		0x27F5833681CC28FBULL,
		0x657E7D1BA1DFF436ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA71FDB07FA878000ULL,
		0xEB860A42EFFE925FULL,
		0xC19B40E6147DD1EEULL,
		0x3E8DD0EFFA1B13FAULL,
		0x00000000000032BFULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x43EFCE2C45B86563ULL,
		0xC0B987FD268FD522ULL,
		0x954548E374B76B42ULL,
		0x55D329A935C2008CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x622DC32B18000000ULL,
		0xE9347EA9121F7E71ULL,
		0x1BA5BB5A1605CC3FULL,
		0x49AE100464AA2A47ULL,
		0x0000000002AE994DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x09838F5B30FB49F1ULL,
		0x52AFD5A312E7344BULL,
		0x1709A933A8ED9FACULL,
		0x24D7A4BCCD51013AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38F5B30FB49F1000ULL,
		0xFD5A312E7344B098ULL,
		0x9A933A8ED9FAC52AULL,
		0x7A4BCCD51013A170ULL,
		0x000000000000024DULL
	}};
	shift = 204;
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
		0x0000020000000000ULL,
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
		0x0000000000000000ULL,
		0x0000000002000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x2000000000000000ULL,
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
		0x0000000000000000ULL,
		0x0000002000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
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
		0x0000008000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000010ULL,
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
		0x0000000000000000ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
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
		0x0000000100000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000010000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
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
		0x0000000000000080ULL,
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
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
		0x0000000020000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000020ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
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
		0x0000000000000000ULL,
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x0000000100000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000100000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
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
		0x0000000000000000ULL,
		0x0000008000000000ULL,
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
		0x0000000000000000ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
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