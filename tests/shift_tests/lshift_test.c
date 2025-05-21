#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xAD5A5151DAE6F174ULL,
		0x02D28F936FB73152ULL,
		0x018D67DCA0F54477ULL,
		0x9AE8B4D704B5DC9BULL,
		0x98AEEABEBB253CC9ULL,
		0xAEA9A5522F74BC05ULL,
		0x3980847FA9CCF380ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x45476B9BC5D00000ULL,
		0x3E4DBEDCC54AB569ULL,
		0x9F7283D511DC0B4AULL,
		0xD35C12D7726C0635ULL,
		0xAAFAEC94F3266BA2ULL,
		0x9548BDD2F01662BBULL,
		0x11FEA733CE02BAA6ULL,
		0x000000000000E602ULL
	}};
	int shift = 18;
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
		0x72F7FAC7226830BBULL,
		0x5E8A1000C7C4AED9ULL,
		0x165748D7D17950EBULL,
		0xBF1A22B9997EEB10ULL,
		0x794EEC3E2BA1F694ULL,
		0x30C67E452509FB77ULL,
		0x0727B7C8BF3AB170ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB00000000000000ULL,
		0xD972F7FAC7226830ULL,
		0xEB5E8A1000C7C4AEULL,
		0x10165748D7D17950ULL,
		0x94BF1A22B9997EEBULL,
		0x77794EEC3E2BA1F6ULL,
		0x7030C67E452509FBULL,
		0x000727B7C8BF3AB1ULL
	}};
	shift = 56;
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
		0x27B00719A7F2CD5EULL,
		0x8CFC6A4DCC2A14D4ULL,
		0x76D954D40A87F81BULL,
		0x50F550A26F9A1187ULL,
		0xD1091CAC8CE20C9FULL,
		0xB41A72029E17A0E7ULL,
		0xCB80311CAAD9A93BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8038CD3F966AF00ULL,
		0x7E3526E6150A6A13ULL,
		0x6CAA6A0543FC0DC6ULL,
		0x7AA85137CD08C3BBULL,
		0x848E564671064FA8ULL,
		0x0D39014F0BD073E8ULL,
		0xC0188E556CD49DDAULL,
		0x0000000000000065ULL
	}};
	shift = 7;
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
		0x6B921D5ADA414CB1ULL,
		0x114C097A10C10101ULL,
		0x49E8291712D9F2DFULL,
		0x436EB3EA49C4E80EULL,
		0x43251E3FED565173ULL,
		0x0371528175954CA1ULL,
		0xDC59EBC5E93E6169ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921D5ADA414CB100ULL,
		0x4C097A10C101016BULL,
		0xE8291712D9F2DF11ULL,
		0x6EB3EA49C4E80E49ULL,
		0x251E3FED56517343ULL,
		0x71528175954CA143ULL,
		0x59EBC5E93E616903ULL,
		0x00000000000000DCULL
	}};
	shift = 8;
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
		0x4C539060FF76F53CULL,
		0xBA8E2C2B5B44C827ULL,
		0xEEC59043C09DF528ULL,
		0x88CBBE71350C92EDULL,
		0x09269633AF0DEA1DULL,
		0x67A9338DAE1708A9ULL,
		0x624C8F573104ECFDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEEDEA780000000ULL,
		0x6B689904E98A720CULL,
		0x7813BEA51751C585ULL,
		0x26A1925DBDD8B208ULL,
		0x75E1BD43B11977CEULL,
		0xB5C2E1152124D2C6ULL,
		0xE6209D9FACF52671ULL,
		0x000000000C4991EAULL
	}};
	shift = 29;
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
		0xBDFF9EEE6ED3DA56ULL,
		0x91F5F087E720DA81ULL,
		0x5A2C8B5B29052399ULL,
		0x1FB365CBF5EBB698ULL,
		0x510A345C1BBBF626ULL,
		0x53E53A3446C7FD6DULL,
		0x450615C8E97EA159ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7FE7BB9BB4F6958ULL,
		0x47D7C21F9C836A06ULL,
		0x68B22D6CA4148E66ULL,
		0x7ECD972FD7AEDA61ULL,
		0x4428D1706EEFD898ULL,
		0x4F94E8D11B1FF5B5ULL,
		0x14185723A5FA8565ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
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
		0xBC0BB8F6EADCEA70ULL,
		0xF258B010FCFF0BA4ULL,
		0x2CBFDDD11D6D5771ULL,
		0xB99EDC21609CC3D2ULL,
		0x54AD23396CC15F22ULL,
		0xF85EA443F306DF4FULL,
		0x6CD9C19E7D652576ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C00000000000000ULL,
		0xE92F02EE3DBAB73AULL,
		0xDC7C962C043F3FC2ULL,
		0xF48B2FF774475B55ULL,
		0xC8AE67B708582730ULL,
		0xD3D52B48CE5B3057ULL,
		0x5DBE17A910FCC1B7ULL,
		0x001B3670679F5949ULL
	}};
	shift = 54;
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
		0xBFF92662756D17BDULL,
		0x9C67B7486E81D9FBULL,
		0xD5D5EB9A5DE4F360ULL,
		0xEB1C4C1DDA35AA1BULL,
		0xB3C4AAAD9171C67EULL,
		0xFF4C8D2E20E007A4ULL,
		0x09229014C611CCACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD000000000000000ULL,
		0xBBFF92662756D17BULL,
		0x09C67B7486E81D9FULL,
		0xBD5D5EB9A5DE4F36ULL,
		0xEEB1C4C1DDA35AA1ULL,
		0x4B3C4AAAD9171C67ULL,
		0xCFF4C8D2E20E007AULL,
		0x009229014C611CCAULL
	}};
	shift = 60;
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
		0x212B08F81BC8527CULL,
		0x99225906EAEE66EBULL,
		0x906EDAC0F2B0D16DULL,
		0x0E1DFC4B142E8644ULL,
		0xAE9AC7398169CCEBULL,
		0xB50D4877F5E1E55FULL,
		0x38035292F862A6C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03790A4F8000000ULL,
		0x0DD5DCCDD6425611ULL,
		0x81E561A2DB3244B2ULL,
		0x96285D0C8920DDB5ULL,
		0x7302D399D61C3BF8ULL,
		0xEFEBC3CABF5D358EULL,
		0x25F0C54D816A1A90ULL,
		0x00000000007006A5ULL
	}};
	shift = 25;
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
		0x111C05EF22C09A0DULL,
		0xAF3F17352C5526B7ULL,
		0xB4B9496CD33095F5ULL,
		0xBB63F1AFB322D14CULL,
		0x20E2CFF39A19A09BULL,
		0x447C8632304F36E9ULL,
		0xE271F6F018CCEDC7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB026834000000000ULL,
		0x1549ADC447017BC8ULL,
		0xCC257D6BCFC5CD4BULL,
		0xC8B4532D2E525B34ULL,
		0x866826EED8FC6BECULL,
		0x13CDBA4838B3FCE6ULL,
		0x333B71D11F218C8CULL,
		0x000000389C7DBC06ULL
	}};
	shift = 38;
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
		0x7FFC544E86C3E005ULL,
		0x521FD7A2AD6CF436ULL,
		0xC13B783564EE00C2ULL,
		0x90DF2B78484C1F08ULL,
		0xD51E38F9D17F4314ULL,
		0x13DF2608247EE7EEULL,
		0x40F0611EB6FDD111ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0F801400000000ULL,
		0xB5B3D0D9FFF1513AULL,
		0x93B80309487F5E8AULL,
		0x21307C2304EDE0D5ULL,
		0x45FD0C52437CADE1ULL,
		0x91FB9FBB5478E3E7ULL,
		0xDBF744444F7C9820ULL,
		0x0000000103C1847AULL
	}};
	shift = 34;
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
		0x50E43D1D5A12FD54ULL,
		0x87538223C5C3034DULL,
		0x620045DDECE84FB8ULL,
		0x90372AF54D385044ULL,
		0xE116D20DA1425F09ULL,
		0xB30626917EE0DD69ULL,
		0x786E2B872CCC8ED0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA8721E8EAD097EAAULL,
		0x43A9C111E2E181A6ULL,
		0x310022EEF67427DCULL,
		0xC81B957AA69C2822ULL,
		0xF08B6906D0A12F84ULL,
		0x59831348BF706EB4ULL,
		0x3C3715C396664768ULL
	}};
	shift = 63;
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
		0xF6F86060F2AFC68FULL,
		0xFEAD5B33BD4E34DAULL,
		0x799C56166562EBB6ULL,
		0xD1433BA7918A94EEULL,
		0x9391A71CBDBD2358ULL,
		0xB8D7714E9D4C1624ULL,
		0xB81C416B24606EA5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3478000000000000ULL,
		0xA6D7B7C30307957EULL,
		0x5DB7F56AD99DEA71ULL,
		0xA773CCE2B0B32B17ULL,
		0x1AC68A19DD3C8C54ULL,
		0xB1249C8D38E5EDE9ULL,
		0x752DC6BB8A74EA60ULL,
		0x0005C0E20B592303ULL
	}};
	shift = 51;
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
		0x4E232655C5E49D10ULL,
		0xA2D700441B945ADAULL,
		0x0A6B6FF7BDBFF52EULL,
		0x14DBD7AAAFB88D63ULL,
		0x765E31FF3FDE9F68ULL,
		0xD71A0DDA8DF700A3ULL,
		0x4EAD66EA24D6849CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E49D1000000000ULL,
		0x1B945ADA4E232655ULL,
		0xBDBFF52EA2D70044ULL,
		0xAFB88D630A6B6FF7ULL,
		0x3FDE9F6814DBD7AAULL,
		0x8DF700A3765E31FFULL,
		0x24D6849CD71A0DDAULL,
		0x000000004EAD66EAULL
	}};
	shift = 32;
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
		0x83ADBDC554A9AE00ULL,
		0xC14831CFA8BA9F93ULL,
		0x03DCCB2268B75AD6ULL,
		0x15E6D95D547D62B8ULL,
		0x9B9B1980590E9EA7ULL,
		0xF196D2E8AE0356EEULL,
		0x072513A0F02B793DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27075B7B8AA9535CULL,
		0xAD8290639F51753FULL,
		0x7007B99644D16EB5ULL,
		0x4E2BCDB2BAA8FAC5ULL,
		0xDD37363300B21D3DULL,
		0x7BE32DA5D15C06ADULL,
		0x000E4A2741E056F2ULL
	}};
	shift = 57;
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
		0x25DD643746AB874AULL,
		0xC04EFD11F6412E83ULL,
		0x06006543FDD9C47FULL,
		0x28C53BE210C26265ULL,
		0x352AB47A50DA03ADULL,
		0xD60EFC1B25FFFE1EULL,
		0x600EAF0F6EFFC6EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD643746AB874A000ULL,
		0xEFD11F6412E8325DULL,
		0x06543FDD9C47FC04ULL,
		0x53BE210C26265060ULL,
		0xAB47A50DA03AD28CULL,
		0xEFC1B25FFFE1E352ULL,
		0xEAF0F6EFFC6EED60ULL,
		0x0000000000000600ULL
	}};
	shift = 12;
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
		0x1B805FBD7B565335ULL,
		0x4287B7584521AAD9ULL,
		0xD30FD329AA18CC62ULL,
		0x8A792A726E474C7DULL,
		0xB1AE2BD0F6274045ULL,
		0xD2D73708F504FC7AULL,
		0x8474E70A3A62189DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC02FDEBDAB299A80ULL,
		0x43DBAC2290D56C8DULL,
		0x87E994D50C663121ULL,
		0x3C95393723A63EE9ULL,
		0xD715E87B13A022C5ULL,
		0x6B9B847A827E3D58ULL,
		0x3A73851D310C4EE9ULL,
		0x0000000000000042ULL
	}};
	shift = 7;
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
		0x056F90575180A07DULL,
		0xB834669FEA8C41B8ULL,
		0x6C3B624F0E6313E4ULL,
		0xAAF85A9545A17F47ULL,
		0x9D3E099EDD12956FULL,
		0x8720BF30DA1EAB11ULL,
		0x596DCB49810C728EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE415D460281F4000ULL,
		0x19A7FAA3106E015BULL,
		0xD893C398C4F92E0DULL,
		0x16A551685FD1DB0EULL,
		0x8267B744A55BEABEULL,
		0x2FCC3687AAC4674FULL,
		0x72D260431CA3A1C8ULL,
		0x000000000000165BULL
	}};
	shift = 14;
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
		0x921E24288DFBA910ULL,
		0xA9431EC52CA6BE9CULL,
		0xFBA4F336C6CA8F8EULL,
		0xE81330BD27F4CB27ULL,
		0x1EF211F003B79444ULL,
		0x5816A4663B6158B0ULL,
		0x8034AB2BA0BDDFF0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD4880000000000ULL,
		0x535F4E490F121446ULL,
		0x6547C754A18F6296ULL,
		0xFA6593FDD2799B63ULL,
		0xDBCA227409985E93ULL,
		0xB0AC580F7908F801ULL,
		0x5EEFF82C0B52331DULL,
		0x000000401A5595D0ULL
	}};
	shift = 39;
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
		0x0CA4D6E79B6F16E3ULL,
		0xE3E8C3FEB157A3CDULL,
		0x1D19B506A8A29B0AULL,
		0xB19BE94231E26A7CULL,
		0x261771E93F96B1BBULL,
		0xF16856C01F4C4BD6ULL,
		0xD5ED2207DF661F63ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9E6DBC5B8C0000ULL,
		0x0FFAC55E8F343293ULL,
		0xD41AA28A6C2B8FA3ULL,
		0xA508C789A9F07466ULL,
		0xC7A4FE5AC6EEC66FULL,
		0x5B007D312F58985DULL,
		0x881F7D987D8FC5A1ULL,
		0x00000000000357B4ULL
	}};
	shift = 18;
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
		0xD3878CD9A28967DEULL,
		0x3DEAA4E159F953D2ULL,
		0x0A8C0716E980D648ULL,
		0x3A1A13335E722B3EULL,
		0xA36BE68B8FBEDD5BULL,
		0x26D2090FCB47F1DCULL,
		0xD2EEEC9E936F36F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C66CD144B3EF000ULL,
		0x55270ACFCA9E969CULL,
		0x6038B74C06B241EFULL,
		0xD0999AF39159F054ULL,
		0x5F345C7DF6EAD9D0ULL,
		0x90487E5A3F8EE51BULL,
		0x7764F49B79B78936ULL,
		0x0000000000000697ULL
	}};
	shift = 11;
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
		0x1F23FA6C732E2C9DULL,
		0xE71CEEBAF9D77D0FULL,
		0x81DADA06B7039371ULL,
		0x5D3EF13092768684ULL,
		0xA02192BD4ED91DE4ULL,
		0x540B341442D4BBC8ULL,
		0x6DE4C9BB39E081D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C593A0000000000ULL,
		0xAEFA1E3E47F4D8E6ULL,
		0x0726E3CE39DD75F3ULL,
		0xED0D0903B5B40D6EULL,
		0xB23BC8BA7DE26124ULL,
		0xA977914043257A9DULL,
		0xC103A2A816682885ULL,
		0x000000DBC9937673ULL
	}};
	shift = 41;
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
		0xE6B4B2393FEDCE0DULL,
		0xEE7D7F1FA5DF265EULL,
		0xD7A017FA25FCDFDDULL,
		0x9054A1CA50720FF1ULL,
		0xE070CE1B6D229403ULL,
		0xB45A5286F0D69C27ULL,
		0xB43720C7D2A93BD5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF6E706800000000ULL,
		0x2EF932F735A591C9ULL,
		0x2FE6FEEF73EBF8FDULL,
		0x83907F8EBD00BFD1ULL,
		0x6914A01C82A50E52ULL,
		0x86B4E13F038670DBULL,
		0x9549DEADA2D29437ULL,
		0x00000005A1B9063EULL
	}};
	shift = 35;
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
		0x81C11AEBF3BBC513ULL,
		0xDF585DC50FEDD996ULL,
		0x6E24DE7A1EE788F0ULL,
		0x988A195AA0716F7DULL,
		0x2F815047CFD337D6ULL,
		0x49CFEBF2BAE728C8ULL,
		0x4AB61400C4A4A8D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07046BAFCEEF144CULL,
		0x7D6177143FB7665AULL,
		0xB89379E87B9E23C3ULL,
		0x6228656A81C5BDF5ULL,
		0xBE05411F3F4CDF5AULL,
		0x273FAFCAEB9CA320ULL,
		0x2AD850031292A35DULL,
		0x0000000000000001ULL
	}};
	shift = 2;
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
		0x99C10C63604202F2ULL,
		0x74802D74FE1B22A0ULL,
		0x01B332CA601BF26AULL,
		0x8D61157F54B840ACULL,
		0xE465098833E8B34AULL,
		0x611454C98456F3D9ULL,
		0x98ABF0DDD782CCACULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C63604202F20000ULL,
		0x2D74FE1B22A099C1ULL,
		0x32CA601BF26A7480ULL,
		0x157F54B840AC01B3ULL,
		0x098833E8B34A8D61ULL,
		0x54C98456F3D9E465ULL,
		0xF0DDD782CCAC6114ULL,
		0x00000000000098ABULL
	}};
	shift = 16;
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
		0x091E1AD85D53E748ULL,
		0x60BE824759898E07ULL,
		0x6D752C8CD2B9F858ULL,
		0x632AB6854C0A38FAULL,
		0xCA438DCB76F1EBF2ULL,
		0x9972E19BBE86D5F7ULL,
		0x97B1ABE37EA87C6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE900000000000000ULL,
		0xC0E123C35B0BAA7CULL,
		0x0B0C17D048EB3131ULL,
		0x1F4DAEA5919A573FULL,
		0x7E4C6556D0A98147ULL,
		0xBEF94871B96EDE3DULL,
		0x8DD32E5C3377D0DAULL,
		0x0012F6357C6FD50FULL
	}};
	shift = 53;
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
		0xF72E27D84C65B582ULL,
		0x7ECF89D742CE7AD6ULL,
		0x7FD977730AC5C36AULL,
		0xA89A7D6A9BC454DFULL,
		0xA6955EFFDF1DC61EULL,
		0x03E8FF6780DB5FC6ULL,
		0xBD909863B78319D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x098CB6B040000000ULL,
		0xE859CF5ADEE5C4FBULL,
		0x6158B86D4FD9F13AULL,
		0x53788A9BEFFB2EEEULL,
		0xFBE3B8C3D5134FADULL,
		0xF01B6BF8D4D2ABDFULL,
		0x76F0633B207D1FECULL,
		0x0000000017B2130CULL
	}};
	shift = 29;
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
		0x080024DDCFE874A6ULL,
		0x4665D8C7EC300B35ULL,
		0x1E0F1D42C768A74EULL,
		0x4F57B3879C4A96BCULL,
		0xB74736CC85BDA588ULL,
		0xC3B15788FF6F8B5DULL,
		0x2E0C875DE1F464A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94C0000000000000ULL,
		0x66A100049BB9FD0EULL,
		0xE9C8CCBB18FD8601ULL,
		0xD783C1E3A858ED14ULL,
		0xB109EAF670F38952ULL,
		0x6BB6E8E6D990B7B4ULL,
		0x9518762AF11FEDF1ULL,
		0x0005C190EBBC3E8CULL
	}};
	shift = 53;
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
		0x80476E38A5CF6561ULL,
		0xA233CA884B039D24ULL,
		0xDF482FACEF01BB68ULL,
		0xACE666CC1E85BF52ULL,
		0xB282FC98E268E1ECULL,
		0x17D63404F6674A54ULL,
		0x24A69FA966925F54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC52E7B2B08000000ULL,
		0x42581CE924023B71ULL,
		0x67780DDB45119E54ULL,
		0x60F42DFA96FA417DULL,
		0xC713470F65673336ULL,
		0x27B33A52A59417E4ULL,
		0x4B3492FAA0BEB1A0ULL,
		0x00000000012534FDULL
	}};
	shift = 27;
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
		0x6FDFF072F14FD0E8ULL,
		0x752A35D40072CCEAULL,
		0x68BBE2EBC90C0B5DULL,
		0xBAEA307247688CA8ULL,
		0x4584F9B98D1E0BF6ULL,
		0x68433F3B34D5EEBBULL,
		0x094030D12247450CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7400000000000000ULL,
		0x7537EFF83978A7E8ULL,
		0xAEBA951AEA003966ULL,
		0x54345DF175E48605ULL,
		0xFB5D75183923B446ULL,
		0x5DA2C27CDCC68F05ULL,
		0x8634219F9D9A6AF7ULL,
		0x0004A018689123A2ULL
	}};
	shift = 55;
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
		0x7FCE9B4F740B8E35ULL,
		0xF7070C965CC651B2ULL,
		0x6D197D8835232EE8ULL,
		0xADE5DDC1EE8FE639ULL,
		0xF225042371422040ULL,
		0xD55CA02A78F70377ULL,
		0x12E2CF26605BA79CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02E38D400000000ULL,
		0x731946C9FF3A6D3DULL,
		0xD48CBBA3DC1C3259ULL,
		0xBA3F98E5B465F620ULL,
		0xC5088102B7977707ULL,
		0xE3DC0DDFC894108DULL,
		0x816E9E73557280A9ULL,
		0x000000004B8B3C99ULL
	}};
	shift = 34;
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
		0x4423A05F109A8730ULL,
		0xFF70D76739B59580ULL,
		0xBC838C29F24B3465ULL,
		0x87D9F978342D856FULL,
		0x5B04AE173F2ADDE9ULL,
		0x0C3D30A01ABEA9FFULL,
		0xF0580900EF4EB6AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A1CC0000000000ULL,
		0x6D65601108E817C4ULL,
		0x92CD197FDC35D9CEULL,
		0x0B615BEF20E30A7CULL,
		0xCAB77A61F67E5E0DULL,
		0xAFAA7FD6C12B85CFULL,
		0xD3ADAA830F4C2806ULL,
		0x0000003C1602403BULL
	}};
	shift = 38;
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
		0xDD285410D5094DFDULL,
		0x91BA123458BFBA62ULL,
		0xD1CB97A2CBCE5454ULL,
		0x96F1280E5711D454ULL,
		0x42332C4FA01C2E02ULL,
		0x95A740D804F446F8ULL,
		0x8D473BA99506A5DBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DFD000000000000ULL,
		0xBA62DD285410D509ULL,
		0x545491BA123458BFULL,
		0xD454D1CB97A2CBCEULL,
		0x2E0296F1280E5711ULL,
		0x46F842332C4FA01CULL,
		0xA5DB95A740D804F4ULL,
		0x00008D473BA99506ULL
	}};
	shift = 48;
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
		0x883E8F4E6B272F64ULL,
		0xE8B1682901C37EEBULL,
		0xF007145284CBE734ULL,
		0x07E343E3D4315A18ULL,
		0x3E4EBD2AD36F281FULL,
		0xB71F0EA8A9577B85ULL,
		0x5212C23A85564209ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20FA3D39AC9CBD90ULL,
		0xA2C5A0A4070DFBAEULL,
		0xC01C514A132F9CD3ULL,
		0x1F8D0F8F50C56863ULL,
		0xF93AF4AB4DBCA07CULL,
		0xDC7C3AA2A55DEE14ULL,
		0x484B08EA15590826ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
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
		0x450C58B622FA7ED0ULL,
		0xE5B627104720CEB6ULL,
		0xFD86CBBCCEEA001AULL,
		0x447691FA6FF02B33ULL,
		0xF9B0255F989B921BULL,
		0x7F584205B2BF371AULL,
		0xA0348BC82BB11690ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2862C5B117D3F680ULL,
		0x2DB13882390675B2ULL,
		0xEC365DE6775000D7ULL,
		0x23B48FD37F81599FULL,
		0xCD812AFCC4DC90DAULL,
		0xFAC2102D95F9B8D7ULL,
		0x01A45E415D88B483ULL,
		0x0000000000000005ULL
	}};
	shift = 3;
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
		0x059E984737792942ULL,
		0x360D06E9190F9569ULL,
		0x68C7911BA51055D8ULL,
		0x706700ABCF53622AULL,
		0x3A38F11F17012996ULL,
		0xBF39A04F5F13ABC7ULL,
		0xC4FBA1AEAF0A6131ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4C239BBC94A1000ULL,
		0x683748C87CAB482CULL,
		0x3C88DD2882AEC1B0ULL,
		0x38055E7A9B115346ULL,
		0xC788F8B8094CB383ULL,
		0xCD027AF89D5E39D1ULL,
		0xDD0D757853098DF9ULL,
		0x0000000000000627ULL
	}};
	shift = 11;
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
		0xDABE2158A51C9684ULL,
		0xD406FC3FAFB6B95CULL,
		0xDAEA22BDC96283F8ULL,
		0x0A63DD5E7756D07DULL,
		0x758F0C77BEE94EA7ULL,
		0x5DC5102B36D35787ULL,
		0xD12233B9D128CB94ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDABE2158A51C9684ULL,
		0xD406FC3FAFB6B95CULL,
		0xDAEA22BDC96283F8ULL,
		0x0A63DD5E7756D07DULL,
		0x758F0C77BEE94EA7ULL,
		0x5DC5102B36D35787ULL,
		0xD12233B9D128CB94ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xA960755F123E044FULL,
		0x6CD8AE7325772430ULL,
		0x67785E876CBED1AAULL,
		0xBAEBF746A2677272ULL,
		0xF9E2A83C524270ABULL,
		0x92BE66872D05DDADULL,
		0x3337BEF15324D7D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0755F123E044F000ULL,
		0x8AE7325772430A96ULL,
		0x85E876CBED1AA6CDULL,
		0xBF746A2677272677ULL,
		0x2A83C524270ABBAEULL,
		0xE66872D05DDADF9EULL,
		0x7BEF15324D7D992BULL,
		0x0000000000000333ULL
	}};
	shift = 12;
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
		0xB0D7DF97D9E90AD2ULL,
		0x6736E8DDC73CD77AULL,
		0xA8B91D52FAF9E5EDULL,
		0xC1A48840F18375C7ULL,
		0xE94F2348DFD8B73BULL,
		0x6FE8AAB625DAA217ULL,
		0xE2334CDB39E6A4EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBECF485690000000ULL,
		0xEE39E6BBD586BEFCULL,
		0x97D7CF2F6B39B746ULL,
		0x078C1BAE3D45C8EAULL,
		0x46FEC5B9DE0D2442ULL,
		0xB12ED510BF4A791AULL,
		0xD9CF3527737F4555ULL,
		0x0000000007119A66ULL
	}};
	shift = 27;
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
		0x94EE24908509F460ULL,
		0xC55E2A1537D63CEDULL,
		0x8113C3C109F0BFB6ULL,
		0x0E0567F6CCA10DE8ULL,
		0x7B385969B6A46204ULL,
		0x15751D51D690975CULL,
		0x870965E5055FD8F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DC49210A13E8C0ULL,
		0x8ABC542A6FAC79DBULL,
		0x0227878213E17F6DULL,
		0x1C0ACFED99421BD1ULL,
		0xF670B2D36D48C408ULL,
		0x2AEA3AA3AD212EB8ULL,
		0x0E12CBCA0ABFB1EAULL,
		0x0000000000000001ULL
	}};
	shift = 1;
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
		0xA30047D6122C5208ULL,
		0xE4A07F4FFAE746ADULL,
		0xE39FE6A29B22D8D9ULL,
		0xAEE5F384AF9C7B5DULL,
		0x47BFB1FC73940DFFULL,
		0x4FE77A6F74C39C9DULL,
		0xE3D00D677EA59CF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D6122C52080000ULL,
		0x7F4FFAE746ADA300ULL,
		0xE6A29B22D8D9E4A0ULL,
		0xF384AF9C7B5DE39FULL,
		0xB1FC73940DFFAEE5ULL,
		0x7A6F74C39C9D47BFULL,
		0x0D677EA59CF44FE7ULL,
		0x000000000000E3D0ULL
	}};
	shift = 16;
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
		0x3ECC77A2C36E1076ULL,
		0xD1C1648A80642865ULL,
		0x82BB69037A47525BULL,
		0xE3C807971662D589ULL,
		0x7A0ED28B028DF7A3ULL,
		0x07F8E5AC3C3AFB20ULL,
		0x60B50474B7956937ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61B7083B00000000ULL,
		0x403214329F663BD1ULL,
		0xBD23A92DE8E0B245ULL,
		0x8B316AC4C15DB481ULL,
		0x8146FBD1F1E403CBULL,
		0x1E1D7D903D076945ULL,
		0x5BCAB49B83FC72D6ULL,
		0x00000000305A823AULL
	}};
	shift = 31;
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
		0xA3D0837A190D1B72ULL,
		0x94AF12E3FB41221CULL,
		0xA6ECDE34923913E4ULL,
		0x237336878A0BAFDFULL,
		0xB10A9132BF295878ULL,
		0xA7682BD2A7380D23ULL,
		0xEEDD7EAF879260BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A36E4000000000ULL,
		0x682443947A106F43ULL,
		0x47227C9295E25C7FULL,
		0x4175FBF4DD9BC692ULL,
		0xE52B0F046E66D0F1ULL,
		0xE701A47621522657ULL,
		0xF24C1754ED057A54ULL,
		0x0000001DDBAFD5F0ULL
	}};
	shift = 37;
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
		0x9AEB3FF847159CA1ULL,
		0x80BDFF5C03B33B2CULL,
		0x402F08BD7FAF2E3DULL,
		0x6DD9ABB083679D52ULL,
		0x2A0C183518FF08F6ULL,
		0x4D1FD888ADE7939AULL,
		0xBF99ABA44760D786ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC238ACE50800000ULL,
		0xAE01D99D964D759FULL,
		0x5EBFD7971EC05EFFULL,
		0xD841B3CEA9201784ULL,
		0x1A8C7F847B36ECD5ULL,
		0x4456F3C9CD15060CULL,
		0xD223B06BC3268FECULL,
		0x00000000005FCCD5ULL
	}};
	shift = 23;
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
		0x748F6D2AACE2F254ULL,
		0x40E9BACABAE5E344ULL,
		0x177D0307BA29D66BULL,
		0x5C7A734EE2B57D67ULL,
		0xDABF6FC04BC66E9AULL,
		0x9FDB5C155AA47893ULL,
		0x639EF8788FC7EBE4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B6955671792A00ULL,
		0x74DD655D72F1A23AULL,
		0xBE8183DD14EB35A0ULL,
		0x3D39A7715ABEB38BULL,
		0x5FB7E025E3374D2EULL,
		0xEDAE0AAD523C49EDULL,
		0xCF7C3C47E3F5F24FULL,
		0x0000000000000031ULL
	}};
	shift = 7;
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
		0xABDDCF1B03BB56DFULL,
		0xF5D28334C04A5766ULL,
		0x107A35828FD8E25AULL,
		0x1DB89F35F252F81FULL,
		0xFB755E899DBE2A27ULL,
		0x913F33A2F620ED41ULL,
		0x5DAA9D63EC0C2683ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDAB6F800000000ULL,
		0x0252BB355EEE78D8ULL,
		0x7EC712D7AE9419A6ULL,
		0x9297C0F883D1AC14ULL,
		0xEDF15138EDC4F9AFULL,
		0xB1076A0FDBAAF44CULL,
		0x6061341C89F99D17ULL,
		0x00000002ED54EB1FULL
	}};
	shift = 35;
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
		0x65BB9EDD84479E5CULL,
		0x71041DD0A314CC06ULL,
		0x610DFD7E80DE220AULL,
		0x98C9D9401AEA4BEDULL,
		0x5C7CB504F08DC61AULL,
		0x25EF2651217747DFULL,
		0x0EF2F46C5D6A9687ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C00000000000000ULL,
		0x0665BB9EDD84479EULL,
		0x0A71041DD0A314CCULL,
		0xED610DFD7E80DE22ULL,
		0x1A98C9D9401AEA4BULL,
		0xDF5C7CB504F08DC6ULL,
		0x8725EF2651217747ULL,
		0x000EF2F46C5D6A96ULL
	}};
	shift = 56;
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
		0x70088C095A258B37ULL,
		0x7ECD5AE0789113E6ULL,
		0xD172EA83FF1D422AULL,
		0xD6AE46FE33D37F87ULL,
		0xCD228803FE7B4852ULL,
		0xA0C6F06C179452BCULL,
		0xE15001C8ADBD69F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x568962CDC0000000ULL,
		0x1E2444F99C022302ULL,
		0xFFC7508A9FB356B8ULL,
		0x8CF4DFE1F45CBAA0ULL,
		0xFF9ED214B5AB91BFULL,
		0x05E514AF3348A200ULL,
		0x2B6F5A7C2831BC1BULL,
		0x0000000038540072ULL
	}};
	shift = 30;
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
		0x92B40743DD4A6BECULL,
		0xF1D834016F76F790ULL,
		0x28213523033FC16EULL,
		0x10E06D94CD5F7A06ULL,
		0x758EF11AC9CD3CB4ULL,
		0xE9AC7D7F3280F4B1ULL,
		0x2B0EE7BFAD81FD6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87BA94D7D8000000ULL,
		0x02DEEDEF2125680EULL,
		0x46067F82DDE3B068ULL,
		0x299ABEF40C50426AULL,
		0x35939A796821C0DBULL,
		0xFE6501E962EB1DE2ULL,
		0x7F5B03FAD7D358FAULL,
		0x0000000000561DCFULL
	}};
	shift = 25;
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
		0x29FCC02222D26C1BULL,
		0x15407C57C12D11FCULL,
		0xA35C23009E47EE0DULL,
		0xAC3374BE5DEAAB14ULL,
		0x16233F2960B05863ULL,
		0x229C7D0774C66ABBULL,
		0xE9AC2330409AED29ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9360D80000000000ULL,
		0x688FE14FE6011116ULL,
		0x3F7068AA03E2BE09ULL,
		0x5558A51AE11804F2ULL,
		0x82C31D619BA5F2EFULL,
		0x3355D8B119F94B05ULL,
		0xD7694914E3E83BA6ULL,
		0x0000074D61198204ULL
	}};
	shift = 43;
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
		0x0F5D52D1D9297713ULL,
		0x13B948F70F08A6C0ULL,
		0x81AB5228FE72CC28ULL,
		0x854C8539F84FC05FULL,
		0xA3F9335928AD67E2ULL,
		0xE305561BFB5890B3ULL,
		0x70E5D10D37372561ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EBAA5A3B252EE26ULL,
		0x277291EE1E114D80ULL,
		0x0356A451FCE59850ULL,
		0x0A990A73F09F80BFULL,
		0x47F266B2515ACFC5ULL,
		0xC60AAC37F6B12167ULL,
		0xE1CBA21A6E6E4AC3ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xA9F83AC0C71B288CULL,
		0xA82C18553FF1E37EULL,
		0x9B7044D30518BDC1ULL,
		0xFE8F52B02878378DULL,
		0x187B7E3346393066ULL,
		0x64F7AEE4618365F2ULL,
		0x5F94F62D49D8317FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4600000000000000ULL,
		0xBF54FC1D60638D94ULL,
		0xE0D4160C2A9FF8F1ULL,
		0xC6CDB82269828C5EULL,
		0x337F47A958143C1BULL,
		0xF90C3DBF19A31C98ULL,
		0xBFB27BD77230C1B2ULL,
		0x002FCA7B16A4EC18ULL
	}};
	shift = 55;
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
		0x3EDE32E90FE1B74BULL,
		0x461C28CF9D4C64C6ULL,
		0x9E3153E2D18D99ABULL,
		0x018606D3EE39B5D7ULL,
		0xE03E06E9438C9437ULL,
		0x1C92332F9A23AC69ULL,
		0x28D1C8882FC3B4D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0DBA58000000000ULL,
		0xA632631F6F197487ULL,
		0xC6CCD5A30E1467CEULL,
		0x1CDAEBCF18A9F168ULL,
		0xC64A1B80C30369F7ULL,
		0x11D634F01F0374A1ULL,
		0xE1DA6A0E491997CDULL,
		0x0000001468E44417ULL
	}};
	shift = 39;
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
		0xDE9C40AABCB56C9FULL,
		0x30F7E8D52BE97729ULL,
		0x2068742BA2DF905DULL,
		0x26191C9F1EC07AE8ULL,
		0xB7316C64D564D90FULL,
		0xE5DD7060DD508C9EULL,
		0xE7D85D3052B62434ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7102AAF2D5B27C00ULL,
		0xDFA354AFA5DCA77AULL,
		0xA1D0AE8B7E4174C3ULL,
		0x64727C7B01EBA081ULL,
		0xC5B1935593643C98ULL,
		0x75C1837542327ADCULL,
		0x6174C14AD890D397ULL,
		0x000000000000039FULL
	}};
	shift = 10;
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
		0x1E8ACD5C2806CD24ULL,
		0x06C3935AE749243EULL,
		0x578DDBEF4D3EB390ULL,
		0x22178EEAD34147C0ULL,
		0x986EA025DA4688BBULL,
		0x56A1BAB980B33A41ULL,
		0xF3BC6AAF115EE37DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2806CD240000000ULL,
		0xAE749243E1E8ACD5ULL,
		0xF4D3EB39006C3935ULL,
		0xAD34147C0578DDBEULL,
		0x5DA4688BB22178EEULL,
		0x980B33A41986EA02ULL,
		0xF115EE37D56A1BABULL,
		0x000000000F3BC6AAULL
	}};
	shift = 28;
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
		0x35DCE3A013B9E29FULL,
		0x7D65ADBC35AEEB21ULL,
		0x2CF7E5E825E24EA4ULL,
		0x21B46A43EC347B9BULL,
		0x599E18C2CAC00D55ULL,
		0xDF4B028B9A92F775ULL,
		0x8F41B884657D1546ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E00000000000000ULL,
		0x426BB9C7402773C5ULL,
		0x48FACB5B786B5DD6ULL,
		0x3659EFCBD04BC49DULL,
		0xAA4368D487D868F7ULL,
		0xEAB33C318595801AULL,
		0x8DBE9605173525EEULL,
		0x011E837108CAFA2AULL
	}};
	shift = 57;
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
		0xD78DCBC2BD3CF38BULL,
		0x71E9C1C1EFCC3D8EULL,
		0xFD26C713B796A9DFULL,
		0x6A444C553E8E043CULL,
		0x31933F18C84E3D48ULL,
		0x575D59782B0F61C1ULL,
		0x51EE091C1D8B60F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5E15E9E79C58000ULL,
		0xE0E0F7E61EC76BC6ULL,
		0x6389DBCB54EFB8F4ULL,
		0x262A9F47021E7E93ULL,
		0x9F8C64271EA43522ULL,
		0xACBC1587B0E098C9ULL,
		0x048E0EC5B07BABAEULL,
		0x00000000000028F7ULL
	}};
	shift = 15;
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
		0x81C4E9094419C695ULL,
		0xE5C90DFAA31D8612ULL,
		0x736C2AFA45EEC45AULL,
		0x7A6E09D9C4381094ULL,
		0xE622C8F7B1252AC5ULL,
		0xF0850DE0F85084F5ULL,
		0x0AC1ECE83D8AEEF1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0x940E27484A20CE34ULL,
		0xD72E486FD518EC30ULL,
		0xA39B6157D22F7622ULL,
		0x2BD3704ECE21C084ULL,
		0xAF311647BD892956ULL,
		0x8F84286F07C28427ULL,
		0x00560F6741EC5777ULL
	}};
	shift = 59;
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
		0x80E18A86ED85B005ULL,
		0x67A3D20A030196B7ULL,
		0x7A41B1B157BD7942ULL,
		0xFCD84A8A0C96055BULL,
		0x3327EC70127F7D59ULL,
		0x03E9AFB79D9F8BC5ULL,
		0xA61157829FBD4D1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2800000000000000ULL,
		0xBC070C54376C2D80ULL,
		0x133D1E9050180CB5ULL,
		0xDBD20D8D8ABDEBCAULL,
		0xCFE6C2545064B02AULL,
		0x29993F638093FBEAULL,
		0xF01F4D7DBCECFC5EULL,
		0x05308ABC14FDEA68ULL
	}};
	shift = 59;
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
		0x0DEC4A277D2DD172ULL,
		0x3283C99F4CE90928ULL,
		0x43A9008B7E1DAD61ULL,
		0x4430D32A89B4EEDAULL,
		0xA056AC10BE4E2BFFULL,
		0x9A24424D0D653B42ULL,
		0x6DF4BC358EA74A39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E4000000000000ULL,
		0x12501BD8944EFA5BULL,
		0x5AC26507933E99D2ULL,
		0xDDB487520116FC3BULL,
		0x57FE8861A6551369ULL,
		0x768540AD58217C9CULL,
		0x94733448849A1ACAULL,
		0x0000DBE9786B1D4EULL
	}};
	shift = 49;
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
		0x2340A6E1A390A6ADULL,
		0x3C660E20597C8234ULL,
		0x39DC237F14B3085CULL,
		0xDF0BC86FA7275607ULL,
		0x9647436B54CC883DULL,
		0x668BAC089234036EULL,
		0x6DC516EBD749B9FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6800000000000000ULL,
		0xA11A05370D1C8535ULL,
		0xE1E3307102CBE411ULL,
		0x39CEE11BF8A59842ULL,
		0xEEF85E437D393AB0ULL,
		0x74B23A1B5AA66441ULL,
		0xE3345D604491A01BULL,
		0x036E28B75EBA4DCFULL
	}};
	shift = 59;
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
		0xDDD64466625BDB75ULL,
		0x1A1A505E828339B9ULL,
		0x24F62BECD1CCF140ULL,
		0xB98E44B9330B240FULL,
		0xD211D05F5D71E8C4ULL,
		0x5B5620A15B03C964ULL,
		0xB5697E5B45E92EE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66625BDB75000000ULL,
		0x5E828339B9DDD644ULL,
		0xECD1CCF1401A1A50ULL,
		0xB9330B240F24F62BULL,
		0x5F5D71E8C4B98E44ULL,
		0xA15B03C964D211D0ULL,
		0x5B45E92EE75B5620ULL,
		0x0000000000B5697EULL
	}};
	shift = 24;
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
		0x6548FED19A73FA81ULL,
		0xBFEDD7D8B83C1305ULL,
		0x40E8C29E0D059DFCULL,
		0xFCFB62EE8DD74B26ULL,
		0xF18E82DC8F438C17ULL,
		0x10322B014BA1D93CULL,
		0x4540F55826D54B23ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A47F68CD39FD408ULL,
		0xFF6EBEC5C1E0982BULL,
		0x074614F0682CEFE5ULL,
		0xE7DB17746EBA5932ULL,
		0x8C7416E47A1C60BFULL,
		0x8191580A5D0EC9E7ULL,
		0x2A07AAC136AA5918ULL,
		0x0000000000000002ULL
	}};
	shift = 3;
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
		0x10827F87D2ABF8B0ULL,
		0xAD6D0A92FF176222ULL,
		0xEEC5D07E4A5BFEBFULL,
		0x3F8BD80107969105ULL,
		0x3C3338ED0D9A2BC3ULL,
		0x7CF92D030D969989ULL,
		0xCF5CA6FF8F596D80ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC58000000000000ULL,
		0xB11108413FC3E955ULL,
		0xFF5FD6B685497F8BULL,
		0x4882F762E83F252DULL,
		0x15E19FC5EC0083CBULL,
		0x4CC49E199C7686CDULL,
		0xB6C03E7C968186CBULL,
		0x000067AE537FC7ACULL
	}};
	shift = 47;
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
		0x8BF2D6454AEF5016ULL,
		0xCBCB499AB82A9CDDULL,
		0x61D6321D5CACA67AULL,
		0x9328237449A4F694ULL,
		0xBBC9C30130FF8293ULL,
		0x353CF761BF04D906ULL,
		0x0E81B646AE6B6429ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B22A577A80B000ULL,
		0x5A4CD5C154E6EC5FULL,
		0xB190EAE56533D65EULL,
		0x411BA24D27B4A30EULL,
		0x4E180987FC149C99ULL,
		0xE7BB0DF826C835DEULL,
		0x0DB235735B2149A9ULL,
		0x0000000000000074ULL
	}};
	shift = 11;
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
		0x515699506BDAC564ULL,
		0xA83BB1F2A3173A9BULL,
		0x680DC1C99C610FE2ULL,
		0xA76C7F1776AE6617ULL,
		0xFE35B00F45958343ULL,
		0x6E1D9E63C2C491C5ULL,
		0x86DBB990F40E11BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58AC80000000000ULL,
		0x2E7536A2AD32A0D7ULL,
		0xC21FC5507763E546ULL,
		0x5CCC2ED01B839338ULL,
		0x2B06874ED8FE2EEDULL,
		0x89238BFC6B601E8BULL,
		0x1C237ADC3B3CC785ULL,
		0x0000010DB77321E8ULL
	}};
	shift = 41;
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
		0x09F09CA0A3EB7EF1ULL,
		0xCFD746A886F494CEULL,
		0xF607A1EE3E7FDE5BULL,
		0x42889A5B2315D839ULL,
		0x76D6E214A66366BEULL,
		0xECEAA36FD81BB6D5ULL,
		0xBA6B8531126B54C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3EB7EF100000000ULL,
		0x86F494CE09F09CA0ULL,
		0x3E7FDE5BCFD746A8ULL,
		0x2315D839F607A1EEULL,
		0xA66366BE42889A5BULL,
		0xD81BB6D576D6E214ULL,
		0x126B54C8ECEAA36FULL,
		0x00000000BA6B8531ULL
	}};
	shift = 32;
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
		0x4844F4ED0FA07FB5ULL,
		0xCFA369096A93AD46ULL,
		0x0319866A96038A11ULL,
		0x01789BF5D7BCFC35ULL,
		0x866FEC75F306E158ULL,
		0xBB0F75ED16018621ULL,
		0xC16E99CC79E6C4CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD400000000000000ULL,
		0x192113D3B43E81FEULL,
		0x473E8DA425AA4EB5ULL,
		0xD40C6619AA580E28ULL,
		0x6005E26FD75EF3F0ULL,
		0x8619BFB1D7CC1B85ULL,
		0x36EC3DD7B4580618ULL,
		0x0305BA6731E79B13ULL
	}};
	shift = 58;
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
		0x117B34F58A2575EBULL,
		0xB2D4721681D5DE17ULL,
		0xA88DB055D06FD11DULL,
		0x1F6DEEEA73261ECBULL,
		0xB8AF90375F4A5F30ULL,
		0xDDD3CFCBDE050175ULL,
		0x7F4A9ECEC1D75D12ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D62895D7AC00000ULL,
		0x85A0757785C45ECDULL,
		0x15741BF4476CB51CULL,
		0xBA9CC987B2EA236CULL,
		0x0DD7D297CC07DB7BULL,
		0xF2F781405D6E2BE4ULL,
		0xB3B075D744B774F3ULL,
		0x00000000001FD2A7ULL
	}};
	shift = 22;
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
		0x2AC2A242D9B26E02ULL,
		0x30FD37EEF5D9B10BULL,
		0x06A1EE79BF167BB6ULL,
		0xD08CA2D409424187ULL,
		0x82523A27B7722CB5ULL,
		0x50F07E143C02A95EULL,
		0x7273314BB230F526ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA242D9B26E020000ULL,
		0x37EEF5D9B10B2AC2ULL,
		0xEE79BF167BB630FDULL,
		0xA2D40942418706A1ULL,
		0x3A27B7722CB5D08CULL,
		0x7E143C02A95E8252ULL,
		0x314BB230F52650F0ULL,
		0x0000000000007273ULL
	}};
	shift = 16;
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
		0xE10B29D641431C83ULL,
		0x42649D67573299F3ULL,
		0x276298CF4740EC00ULL,
		0x22D02A09041D5F3AULL,
		0x2A535CC5942A4E87ULL,
		0x1844451384EBAD5EULL,
		0xD9978EEADF0ABF8DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20A18E4180000000ULL,
		0xAB994CF9F08594EBULL,
		0xA3A0760021324EB3ULL,
		0x820EAF9D13B14C67ULL,
		0xCA15274391681504ULL,
		0xC275D6AF1529AE62ULL,
		0x6F855FC68C222289ULL,
		0x000000006CCBC775ULL
	}};
	shift = 31;
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
		0x57B650EC798BE05AULL,
		0xE6AB0E4A81C55009ULL,
		0x9643742DC1D52F24ULL,
		0x3A56EB2215AC74F2ULL,
		0x2271A453E29D3FDDULL,
		0xDC29F1BFA9EB71FDULL,
		0x1B1D10C5428D0AABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x55ED943B1E62F816ULL,
		0x39AAC392A0715402ULL,
		0xA590DD0B70754BC9ULL,
		0x4E95BAC8856B1D3CULL,
		0x489C6914F8A74FF7ULL,
		0xF70A7C6FEA7ADC7FULL,
		0x06C7443150A342AAULL
	}};
	shift = 62;
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
		0x51F56F9E915AA025ULL,
		0xEC448D4B9AC6F64DULL,
		0x935A21375A480DCBULL,
		0xBB86B5B2281F9D54ULL,
		0x6BEEFBF34C6F10C9ULL,
		0x5BB21EFA019447A7ULL,
		0x579965AAC971BDCBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x547D5BE7A456A809ULL,
		0xFB112352E6B1BD93ULL,
		0x24D6884DD6920372ULL,
		0x6EE1AD6C8A07E755ULL,
		0xDAFBBEFCD31BC432ULL,
		0xD6EC87BE806511E9ULL,
		0x15E6596AB25C6F72ULL
	}};
	shift = 62;
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
		0xEFAC429C6E85BAAAULL,
		0xA68EB2A4131E9C42ULL,
		0x60B2B1843A50C3D7ULL,
		0x11F81DB6C028AD7EULL,
		0x8C1E7189806A95ACULL,
		0xA916EC9F28C360F4ULL,
		0x68439F704C252504ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EAA800000000000ULL,
		0xA710BBEB10A71BA1ULL,
		0x30F5E9A3ACA904C7ULL,
		0x2B5F982CAC610E94ULL,
		0xA56B047E076DB00AULL,
		0xD83D23079C62601AULL,
		0x49412A45BB27CA30ULL,
		0x00001A10E7DC1309ULL
	}};
	shift = 46;
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
		0x77F2E5F6FBCB6AD3ULL,
		0xD90DCB2C5923C73BULL,
		0x447817D5DC9A0A86ULL,
		0x5F6EA35C91918037ULL,
		0x8B0D89B326BD416FULL,
		0x0CBAB4E034047E72ULL,
		0x79F04C5E999AA027ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD30000000000000ULL,
		0x73B77F2E5F6FBCB6ULL,
		0xA86D90DCB2C5923CULL,
		0x037447817D5DC9A0ULL,
		0x16F5F6EA35C91918ULL,
		0xE728B0D89B326BD4ULL,
		0x0270CBAB4E034047ULL,
		0x00079F04C5E999AAULL
	}};
	shift = 52;
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
		0x196B725D2C6E6761ULL,
		0x320DEF6745B6619EULL,
		0x85F8328242C4E601ULL,
		0x0C2EDEC096D7CE36ULL,
		0x28F01F4ACEC9CEFBULL,
		0xC9CBABEB3BD843BAULL,
		0x936890D9B21B2D04ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2C6E67610000000ULL,
		0x745B6619E196B725ULL,
		0x242C4E601320DEF6ULL,
		0x096D7CE3685F8328ULL,
		0xACEC9CEFB0C2EDECULL,
		0xB3BD843BA28F01F4ULL,
		0x9B21B2D04C9CBABEULL,
		0x000000000936890DULL
	}};
	shift = 28;
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
		0xE437250AE545D3AFULL,
		0xF2ADAE682289D11DULL,
		0xF7E32AC3AC466D17ULL,
		0xB9963651060E7E05ULL,
		0x6D66E1BC3ACE4086ULL,
		0x0F5B460913552129ULL,
		0xA32A8E018AEF043DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE545D3AF00000000ULL,
		0x2289D11DE437250AULL,
		0xAC466D17F2ADAE68ULL,
		0x060E7E05F7E32AC3ULL,
		0x3ACE4086B9963651ULL,
		0x135521296D66E1BCULL,
		0x8AEF043D0F5B4609ULL,
		0x00000000A32A8E01ULL
	}};
	shift = 32;
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
		0x095192C4E6668469ULL,
		0x476CDA2FE1828287ULL,
		0x3BA51C4811A368CFULL,
		0x17CB45944E0DC066ULL,
		0x7E1E52345AAFF344ULL,
		0x1BFC26DF6EA466C4ULL,
		0x0CEBF8C635C06243ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD08D2000000000ULL,
		0x305050E12A32589CULL,
		0x346D19E8ED9B45FCULL,
		0xC1B80CC774A38902ULL,
		0x55FE6882F968B289ULL,
		0xD48CD88FC3CA468BULL,
		0xB80C48637F84DBEDULL,
		0x000000019D7F18C6ULL
	}};
	shift = 37;
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
		0x58BEA703E44B963EULL,
		0x9AC4BD38D887C4E4ULL,
		0xF35312DA0D70C7AFULL,
		0xA3241EA5E10110CCULL,
		0xF6EFFB177C30DADDULL,
		0xFD496EA022DA114EULL,
		0x93FC404DB3428FF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E58F80000000000ULL,
		0x1F139162FA9C0F91ULL,
		0xC31EBE6B12F4E362ULL,
		0x044333CD4C4B6835ULL,
		0xC36B768C907A9784ULL,
		0x68453BDBBFEC5DF0ULL,
		0x0A3FCFF525BA808BULL,
		0x0000024FF10136CDULL
	}};
	shift = 42;
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
		0xF346D9500ED0C388ULL,
		0x072A3DA88079C1AFULL,
		0xD7510A5C2CFDE9EBULL,
		0x3D1D14BE058A48ADULL,
		0x0F73B70F45078667ULL,
		0x8FF0FCA0CED44C67ULL,
		0x542307F94BAF591BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68DB2A01DA187100ULL,
		0xE547B5100F3835FEULL,
		0xEA214B859FBD3D60ULL,
		0xA3A297C0B14915BAULL,
		0xEE76E1E8A0F0CCE7ULL,
		0xFE1F9419DA898CE1ULL,
		0x8460FF2975EB2371ULL,
		0x000000000000000AULL
	}};
	shift = 5;
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
		0x2B0C47F57D78EB03ULL,
		0x1EAE8C4EB1620408ULL,
		0xEE7F1EE2D2C978AAULL,
		0x7849C3E113869C8FULL,
		0x7CF325E17C9E2981ULL,
		0x3793C47C5CF84D3CULL,
		0x73F13B8BE0B6AF9EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0x82B0C47F57D78EB0ULL,
		0xA1EAE8C4EB162040ULL,
		0xFEE7F1EE2D2C978AULL,
		0x17849C3E113869C8ULL,
		0xC7CF325E17C9E298ULL,
		0xE3793C47C5CF84D3ULL,
		0x073F13B8BE0B6AF9ULL
	}};
	shift = 60;
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
		0xF4DB778BF3C54EB9ULL,
		0xC438761E3C83335CULL,
		0x6FB462BF0CCC3973ULL,
		0x25B590DDD4C24E06ULL,
		0x492B6FECB4EF4FEFULL,
		0x6F21795A65B85CB2ULL,
		0xEF0F16D9F4F6E942ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF153AE400000000ULL,
		0xF20CCD73D36DDE2FULL,
		0x3330E5CF10E1D878ULL,
		0x53093819BED18AFCULL,
		0xD3BD3FBC96D64377ULL,
		0x96E172C924ADBFB2ULL,
		0xD3DBA509BC85E569ULL,
		0x00000003BC3C5B67ULL
	}};
	shift = 34;
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
		0x1496DD056A3371E7ULL,
		0xBA0457E5E5C424FFULL,
		0x24DD94E18658D505ULL,
		0x679F1FAEA738FEB3ULL,
		0x143E0284010CFAA0ULL,
		0x96553EC648D29216ULL,
		0x6ECA25AB3044EA16ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DD056A3371E7000ULL,
		0x457E5E5C424FF149ULL,
		0xD94E18658D505BA0ULL,
		0xF1FAEA738FEB324DULL,
		0xE0284010CFAA0679ULL,
		0x53EC648D29216143ULL,
		0xA25AB3044EA16965ULL,
		0x00000000000006ECULL
	}};
	shift = 12;
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
		0xE4F82B32F83AE833ULL,
		0xF04F7F0400060B1DULL,
		0xBD1BE15D7AF0E379ULL,
		0x4152939E6EF657F8ULL,
		0x589CDE90F1D94F43ULL,
		0xF3748B9A1096A585ULL,
		0xE90FC747B94F3966ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27C15997C1D74198ULL,
		0x827BF820003058EFULL,
		0xE8DF0AEBD7871BCFULL,
		0x0A949CF377B2BFC5ULL,
		0xC4E6F4878ECA7A1AULL,
		0x9BA45CD084B52C2AULL,
		0x487E3A3DCA79CB37ULL,
		0x0000000000000007ULL
	}};
	shift = 3;
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
		0xF095787CE26826DAULL,
		0xE5EBBA9FEBD66984ULL,
		0xE301C1092CF78C9AULL,
		0xF962C20F7C961342ULL,
		0x4194830DB8B92677ULL,
		0x52CD59FCE3EF7A7CULL,
		0xF00EF41DFAF8E496ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x136D000000000000ULL,
		0x34C2784ABC3E7134ULL,
		0xC64D72F5DD4FF5EBULL,
		0x09A17180E084967BULL,
		0x933BFCB16107BE4BULL,
		0xBD3E20CA4186DC5CULL,
		0x724B2966ACFE71F7ULL,
		0x000078077A0EFD7CULL
	}};
	shift = 47;
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
		0x2FC4862EFA35F65FULL,
		0x3F40F0D8C12A10A2ULL,
		0x767B98ADFA2954B8ULL,
		0x398DD2EA53FCF01AULL,
		0x9449E3CF91877684ULL,
		0xF56867B212414643ULL,
		0x2F18F9727E47AC58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4862EFA35F65F000ULL,
		0x0F0D8C12A10A22FCULL,
		0xB98ADFA2954B83F4ULL,
		0xDD2EA53FCF01A767ULL,
		0x9E3CF91877684398ULL,
		0x867B212414643944ULL,
		0x8F9727E47AC58F56ULL,
		0x00000000000002F1ULL
	}};
	shift = 12;
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
		0x62EA8DCBF7422E1CULL,
		0x81FA3FF4028FABD7ULL,
		0xF246AD8A5E717900ULL,
		0xDB0CBE5C8F3EAD74ULL,
		0x32A643A8327F19BDULL,
		0xDD8DD8777DE3250EULL,
		0x1BA4E51907A9F651ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA8DCBF7422E1C00ULL,
		0xFA3FF4028FABD762ULL,
		0x46AD8A5E71790081ULL,
		0x0CBE5C8F3EAD74F2ULL,
		0xA643A8327F19BDDBULL,
		0x8DD8777DE3250E32ULL,
		0xA4E51907A9F651DDULL,
		0x000000000000001BULL
	}};
	shift = 8;
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
		0x8646AB659F47ECFDULL,
		0x93AE7D3155457FA0ULL,
		0xC4E9DFC9F9D467E4ULL,
		0xB065599A4CEFC62CULL,
		0x1110EB10B6969312ULL,
		0xEB3D82876DCF5F5EULL,
		0x84082B1A39F526AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA0000000000000ULL,
		0xF410C8D56CB3E8FDULL,
		0xFC9275CFA62AA8AFULL,
		0xC5989D3BF93F3A8CULL,
		0x62560CAB33499DF8ULL,
		0xEBC2221D6216D2D2ULL,
		0xD5DD67B050EDB9EBULL,
		0x0010810563473EA4ULL
	}};
	shift = 53;
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
		0x0D08578CD897F38CULL,
		0x6829833D6106CBC7ULL,
		0x69F16AE89C62B0A6ULL,
		0xF9E116E534B5FED6ULL,
		0x50FF086BF024F22CULL,
		0x48F3847C6A2C72C8ULL,
		0x955E298B02779EC2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F38C0000000000ULL,
		0x06CBC70D08578CD8ULL,
		0x62B0A66829833D61ULL,
		0xB5FED669F16AE89CULL,
		0x24F22CF9E116E534ULL,
		0x2C72C850FF086BF0ULL,
		0x779EC248F3847C6AULL,
		0x000000955E298B02ULL
	}};
	shift = 40;
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
		0x05C0C33C350636D6ULL,
		0xFA64A55273518D83ULL,
		0x1D9A63A68D36C5FDULL,
		0xF18C0DCEFAE41443ULL,
		0x79D94D952A77C190ULL,
		0xE04EBF3D8FF81234ULL,
		0x5DADD7B09535A9C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x186786A0C6DAC000ULL,
		0x94AA4E6A31B060B8ULL,
		0x4C74D1A6D8BFBF4CULL,
		0x81B9DF5C828863B3ULL,
		0x29B2A54EF8321E31ULL,
		0xD7E7B1FF02468F3BULL,
		0xBAF612A6B5381C09ULL,
		0x0000000000000BB5ULL
	}};
	shift = 13;
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
		0x9EBB6D033AE894F3ULL,
		0x44CFD0DDD26C315BULL,
		0x7E76A02D3A9142BEULL,
		0x590D7E101DA32DBBULL,
		0x51072589AE0ACFA7ULL,
		0x4698E61EAA0A5D7DULL,
		0xEC0B0DB91084DC86ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D129E600000000ULL,
		0xA4D862B73D76DA06ULL,
		0x7522857C899FA1BBULL,
		0x3B465B76FCED405AULL,
		0x5C159F4EB21AFC20ULL,
		0x5414BAFAA20E4B13ULL,
		0x2109B90C8D31CC3DULL,
		0x00000001D8161B72ULL
	}};
	shift = 33;
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
		0x1A8E852A032CCF48ULL,
		0xAFC515033A9855FFULL,
		0xA8955DA163EAD9ECULL,
		0xC6274C7FA57B8872ULL,
		0x9B2471EB6812BB5CULL,
		0x0C22CD70536865D0ULL,
		0x3299FD4BA5AE9121ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6599E90000000000ULL,
		0x530ABFE351D0A540ULL,
		0x7D5B3D95F8A2A067ULL,
		0xAF710E5512ABB42CULL,
		0x02576B98C4E98FF4ULL,
		0x6D0CBA13648E3D6DULL,
		0xB5D224218459AE0AULL,
		0x00000006533FA974ULL
	}};
	shift = 37;
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
		0x2C6EBE8F8F215D46ULL,
		0xCD6990596CFDAB97ULL,
		0x001FBA418466F34CULL,
		0x1AD484D69219CE05ULL,
		0x3BA9BADDE7ACE3EFULL,
		0xD31E811FB9B1BD0AULL,
		0xA742AC74A9C3B68AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D46000000000000ULL,
		0xAB972C6EBE8F8F21ULL,
		0xF34CCD6990596CFDULL,
		0xCE05001FBA418466ULL,
		0xE3EF1AD484D69219ULL,
		0xBD0A3BA9BADDE7ACULL,
		0xB68AD31E811FB9B1ULL,
		0x0000A742AC74A9C3ULL
	}};
	shift = 48;
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
		0xCD28B6C5A2982327ULL,
		0xB50A5F02F9FFD44BULL,
		0xBB69A8FE4461B38FULL,
		0xAE7E4113C15DC49DULL,
		0x9CB9C824E8193AF8ULL,
		0xFD56621E8F015298ULL,
		0x2AAE82D047F45D80ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516D8B4530464E00ULL,
		0x14BE05F3FFA8979AULL,
		0xD351FC88C3671F6AULL,
		0xFC822782BB893B76ULL,
		0x739049D03275F15CULL,
		0xACC43D1E02A53139ULL,
		0x5D05A08FE8BB01FAULL,
		0x0000000000000055ULL
	}};
	shift = 9;
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
		0x3120DF1292CF8CEAULL,
		0xF12A1009AD1B7CBBULL,
		0xD48BFF013B4BBA90ULL,
		0x2A456C5CE7AED6C0ULL,
		0xC2FEE9E10F5435D4ULL,
		0xF4E8037004743E02ULL,
		0xA95C3CB9470D088EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F894967C6750000ULL,
		0x0804D68DBE5D9890ULL,
		0xFF809DA5DD487895ULL,
		0xB62E73D76B606A45ULL,
		0x74F087AA1AEA1522ULL,
		0x01B8023A1F01617FULL,
		0x1E5CA38684477A74ULL,
		0x00000000000054AEULL
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
		0xDE18EA1D1448E1BDULL,
		0x328A69DE92169B03ULL,
		0x11570095708BF996ULL,
		0xB710ADC0FF266FBAULL,
		0xF26C74FD2EEB7038ULL,
		0x8A87CE1DC44A09A6ULL,
		0x5FD3821EFB17346CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D43A2891C37A00ULL,
		0x14D3BD242D3607BCULL,
		0xAE012AE117F32C65ULL,
		0x215B81FE4CDF7422ULL,
		0xD8E9FA5DD6E0716EULL,
		0x0F9C3B8894134DE4ULL,
		0xA7043DF62E68D915ULL,
		0x00000000000000BFULL
	}};
	shift = 9;
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
		0x59160F56BF9C3338ULL,
		0xF6EB62F8D7DDD3F5ULL,
		0x0C452181AB173291ULL,
		0xD4A60B156226ED3FULL,
		0x9A22B844E617DD90ULL,
		0x29BEC3ADDC58C059ULL,
		0x0247E25820D659A2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59160F56BF9C3338ULL,
		0xF6EB62F8D7DDD3F5ULL,
		0x0C452181AB173291ULL,
		0xD4A60B156226ED3FULL,
		0x9A22B844E617DD90ULL,
		0x29BEC3ADDC58C059ULL,
		0x0247E25820D659A2ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x9B0D4E3F5ECF6940ULL,
		0x580E43D007339BBAULL,
		0xA72CF70BE0A2BB13ULL,
		0xF2CF64F4B435DF5AULL,
		0xA9B6EA2DF03BF28CULL,
		0x0FC277BC1BA63450ULL,
		0xB83657F22B209EC5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3538FD7B3DA50000ULL,
		0x390F401CCE6EEA6CULL,
		0xB3DC2F828AEC4D60ULL,
		0x3D93D2D0D77D6A9CULL,
		0xDBA8B7C0EFCA33CBULL,
		0x09DEF06E98D142A6ULL,
		0xD95FC8AC827B143FULL,
		0x00000000000002E0ULL
	}};
	shift = 10;
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
		0xA8FD8A1B0BCBCF15ULL,
		0x32EED8BEE9AF55B4ULL,
		0x9BA30DC75C3C6DBEULL,
		0xDE25FF246E4D38BAULL,
		0xC0E3B61960ED7D71ULL,
		0x9AF60F0BF819CA87ULL,
		0x9631453755C79E4DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x286C2F2F3C540000ULL,
		0x62FBA6BD56D2A3F6ULL,
		0x371D70F1B6F8CBBBULL,
		0xFC91B934E2EA6E8CULL,
		0xD86583B5F5C77897ULL,
		0x3C2FE0672A1F038EULL,
		0x14DD571E79366BD8ULL,
		0x00000000000258C5ULL
	}};
	shift = 18;
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
		0x75E440761B555808ULL,
		0x4DC051385C663641ULL,
		0xCE7CB0B0613F4D9AULL,
		0x05F206396D3AC72DULL,
		0xEE7272FA04C7BBEAULL,
		0x4D4B151828F0C3F2ULL,
		0x362301A1B554F52FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD79101D86D556020ULL,
		0x370144E17198D905ULL,
		0x39F2C2C184FD3669ULL,
		0x17C818E5B4EB1CB7ULL,
		0xB9C9CBE8131EEFA8ULL,
		0x352C5460A3C30FCBULL,
		0xD88C0686D553D4BDULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xFB09287E1E055B3DULL,
		0x6841411527F81B42ULL,
		0x01441448526EE9D7ULL,
		0x77FBDD4154AB010AULL,
		0x783B7CBA2A314573ULL,
		0x6DFE235F19236A83ULL,
		0xF95556A6414F9F4FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56CF400000000000ULL,
		0x06D0BEC24A1F8781ULL,
		0xBA75DA10504549FEULL,
		0xC04280510512149BULL,
		0x515CDDFEF750552AULL,
		0xDAA0DE0EDF2E8A8CULL,
		0xE7D3DB7F88D7C648ULL,
		0x00003E5555A99053ULL
	}};
	shift = 46;
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
		0xCB9648C1D9BC6E39ULL,
		0xB8EDD621E73F837BULL,
		0xAAE1D17E39C66BA2ULL,
		0xB5A797ADBA0F4F14ULL,
		0x9349096B9F486835ULL,
		0xA08D50E012277F02ULL,
		0x5FC45858FAE850EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x7972C9183B378DC7ULL,
		0x571DBAC43CE7F06FULL,
		0x955C3A2FC738CD74ULL,
		0xB6B4F2F5B741E9E2ULL,
		0x5269212D73E90D06ULL,
		0xF411AA1C0244EFE0ULL,
		0x0BF88B0B1F5D0A1DULL
	}};
	shift = 61;
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
		0x57295EB9E58E8CC9ULL,
		0x1A280DF38D03C254ULL,
		0xAEB9E206D80CD68BULL,
		0x8D49ED4AC977000BULL,
		0xA619AA95566C6299ULL,
		0x6778FDB6D43CDFF3ULL,
		0x232134F7FC980BCDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9200000000000000ULL,
		0xA8AE52BD73CB1D19ULL,
		0x1634501BE71A0784ULL,
		0x175D73C40DB019ADULL,
		0x331A93DA9592EE00ULL,
		0xE74C33552AACD8C5ULL,
		0x9ACEF1FB6DA879BFULL,
		0x00464269EFF93017ULL
	}};
	shift = 57;
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
		0x534DD7C24E14C2B9ULL,
		0x2A5AD9C334387E64ULL,
		0x6CC52F576B88B7BDULL,
		0xAA77A0524D8D751CULL,
		0x3888438FF47BB528ULL,
		0x57695554BE61D6DDULL,
		0xB58A15D207A2FF02ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C2985720000000ULL,
		0x66870FCC8A69BAF8ULL,
		0xED7116F7A54B5B38ULL,
		0x49B1AEA38D98A5EAULL,
		0xFE8F76A5154EF40AULL,
		0x97CC3ADBA7110871ULL,
		0x40F45FE04AED2AAAULL,
		0x0000000016B142BAULL
	}};
	shift = 29;
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
		0x9D0EA61067A2AFBDULL,
		0x249DC7A1DAA68010ULL,
		0x2FD196BC1D086656ULL,
		0x16ED6221729E50B9ULL,
		0x0E60F76AB5CF7C4BULL,
		0x42EAD0E93F4B7EA0ULL,
		0xAAA4ED7633795E97ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBD0000000000000ULL,
		0x0109D0EA61067A2AULL,
		0x656249DC7A1DAA68ULL,
		0x0B92FD196BC1D086ULL,
		0xC4B16ED6221729E5ULL,
		0xEA00E60F76AB5CF7ULL,
		0xE9742EAD0E93F4B7ULL,
		0x000AAA4ED7633795ULL
	}};
	shift = 52;
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
		0x08B47FEA5E6BB027ULL,
		0x0F1A740E63FFDEC0ULL,
		0x24663FAD474D6A1EULL,
		0x77DE285D2FF20AD7ULL,
		0xBA7C8C0D3ABD68C1ULL,
		0xB285DFAD72D34E22ULL,
		0x9FEA5776AD477B66ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB02700000000000ULL,
		0xFDEC008B47FEA5E6ULL,
		0xD6A1E0F1A740E63FULL,
		0x20AD724663FAD474ULL,
		0xD68C177DE285D2FFULL,
		0x34E22BA7C8C0D3ABULL,
		0x77B66B285DFAD72DULL,
		0x000009FEA5776AD4ULL
	}};
	shift = 44;
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
		0xEF6BDC377C6108E5ULL,
		0xEA8A8B97EC2D79E2ULL,
		0x31E282B7BDDA7D41ULL,
		0x58AE27F1C849B654ULL,
		0x9F02E36C265AC925ULL,
		0x1D94CB3A87594E53ULL,
		0xB4ABCBF510B747B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDAF70DDF1842394ULL,
		0xAA2A2E5FB0B5E78BULL,
		0xC78A0ADEF769F507ULL,
		0x62B89FC72126D950ULL,
		0x7C0B8DB0996B2495ULL,
		0x76532CEA1D65394EULL,
		0xD2AF2FD442DD1ED0ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
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
		0xAF40A7190D079E96ULL,
		0xDBF7ED783C628889ULL,
		0x7561478660AEE18DULL,
		0xEB63D511FE798501ULL,
		0xDA4F0724D37C40E4ULL,
		0x0D5842E3A6B604E6ULL,
		0x47BD749E33E7C768ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x814E321A0F3D2C00ULL,
		0xEFDAF078C511135EULL,
		0xC28F0CC15DC31BB7ULL,
		0xC7AA23FCF30A02EAULL,
		0x9E0E49A6F881C9D6ULL,
		0xB085C74D6C09CDB4ULL,
		0x7AE93C67CF8ED01AULL,
		0x000000000000008FULL
	}};
	shift = 9;
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
		0x3E3164B36B4E46A4ULL,
		0x1B8C84C8C1B975FAULL,
		0xD91260016EBDD041ULL,
		0xC9CE42B2F890A9DAULL,
		0x2196790C20BA13CAULL,
		0x083B501BD7F4B9D3ULL,
		0x4437B6C87591AC74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C966D69C8D48000ULL,
		0x909918372EBF47C6ULL,
		0x4C002DD7BA082371ULL,
		0xC8565F12153B5B22ULL,
		0xCF21841742795939ULL,
		0x6A037AFE973A6432ULL,
		0xF6D90EB2358E8107ULL,
		0x0000000000000886ULL
	}};
	shift = 13;
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
		0xC7ECBD3ADA6D8871ULL,
		0xD55C344ABBE58F05ULL,
		0xEC10204E867C98F3ULL,
		0xA2AEDEE3D5F76E7DULL,
		0x9EA8A18F2AD19531ULL,
		0x51CB35703282C57CULL,
		0x92BF47C31BFEDF90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6D36C438800000ULL,
		0x255DF2C782E3F65EULL,
		0x27433E4C79EAAE1AULL,
		0x71EAFBB73EF60810ULL,
		0xC79568CA98D1576FULL,
		0xB8194162BE4F5450ULL,
		0xE18DFF6FC828E59AULL,
		0x0000000000495FA3ULL
	}};
	shift = 23;
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
		0x5646E76448F28BEFULL,
		0x6E2529F0CCEAA7FBULL,
		0xB5139D97D94D4881ULL,
		0x6805B8350A09058CULL,
		0x1FFC2CE49F48C05BULL,
		0x37D276049E11C12EULL,
		0xF75AAA880CD87CD9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF000000000000000ULL,
		0xB5646E76448F28BEULL,
		0x16E2529F0CCEAA7FULL,
		0xCB5139D97D94D488ULL,
		0xB6805B8350A09058ULL,
		0xE1FFC2CE49F48C05ULL,
		0x937D276049E11C12ULL,
		0x0F75AAA880CD87CDULL
	}};
	shift = 60;
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
		0x0F8B5AF11094BC51ULL,
		0x277B87EBCF3C820AULL,
		0x179307C2EB1F9D62ULL,
		0x77EBCA458C6E0F14ULL,
		0x06CE782F56C623BAULL,
		0x4E22276F641ACED3ULL,
		0xE91A95FAB42A7FC6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF11094BC510000ULL,
		0x87EBCF3C820A0F8BULL,
		0x07C2EB1F9D62277BULL,
		0xCA458C6E0F141793ULL,
		0x782F56C623BA77EBULL,
		0x276F641ACED306CEULL,
		0x95FAB42A7FC64E22ULL,
		0x000000000000E91AULL
	}};
	shift = 16;
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
		0x91968FEBA4DC8292ULL,
		0x3C3DA5FDEA2FBBB0ULL,
		0xE1FD6F5AF87E6610ULL,
		0xA3A508E932FD4994ULL,
		0x4415867AD19A502CULL,
		0x89B3A74255DEA726ULL,
		0x0D37476DBCE4D72CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720A480000000000ULL,
		0xBEEEC2465A3FAE93ULL,
		0xF99840F0F697F7A8ULL,
		0xF5265387F5BD6BE1ULL,
		0x6940B28E9423A4CBULL,
		0x7A9C99105619EB46ULL,
		0x935CB226CE9D0957ULL,
		0x00000034DD1DB6F3ULL
	}};
	shift = 42;
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
		0xC0086CC3F8531265ULL,
		0xABF57FCE4774670CULL,
		0x89D4C5B97D2DD547ULL,
		0x48968A1435D58803ULL,
		0xC48F9EB101C76EDEULL,
		0x38080726D4BCE307ULL,
		0x64293A4719AD1574ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2650000000000000ULL,
		0x70CC0086CC3F8531ULL,
		0x547ABF57FCE47746ULL,
		0x80389D4C5B97D2DDULL,
		0xEDE48968A1435D58ULL,
		0x307C48F9EB101C76ULL,
		0x57438080726D4BCEULL,
		0x00064293A4719AD1ULL
	}};
	shift = 52;
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
		0x8DFD44484EEF232EULL,
		0x0C37DFD01AD8C653ULL,
		0xA961FF02495066B8ULL,
		0x3219348722B38CA2ULL,
		0xF749E427E835FACBULL,
		0x2AC549C987D46857ULL,
		0x5980EC9E9C3A934FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2777919700000000ULL,
		0x0D6C6329C6FEA224ULL,
		0x24A8335C061BEFE8ULL,
		0x9159C65154B0FF81ULL,
		0xF41AFD65990C9A43ULL,
		0xC3EA342BFBA4F213ULL,
		0x4E1D49A79562A4E4ULL,
		0x000000002CC0764FULL
	}};
	shift = 31;
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
		0x08B06C5705A537B2ULL,
		0xD6E4522B3B478F0FULL,
		0x3369809653FF0188ULL,
		0x878C2DEFDDD88B04ULL,
		0xDE4BD31572229A42ULL,
		0x7236EE273F9B9452ULL,
		0x49128579740702B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82D29BD900000000ULL,
		0x9DA3C7878458362BULL,
		0x29FF80C46B722915ULL,
		0xEEEC458219B4C04BULL,
		0xB9114D2143C616F7ULL,
		0x9FCDCA296F25E98AULL,
		0xBA03815C391B7713ULL,
		0x00000000248942BCULL
	}};
	shift = 31;
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
		0x6755AD1D1542F83AULL,
		0xB98D9F6404AED920ULL,
		0xAD7F675DC88109E4ULL,
		0x9CB02BEC351AF18EULL,
		0x6A51E571712C4419ULL,
		0x9A96D0B7F0FC98FDULL,
		0xA997AC63AE0E1822ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A2A85F07400000ULL,
		0xEC8095DB240CEAB5ULL,
		0xEBB910213C9731B3ULL,
		0x7D86A35E31D5AFECULL,
		0xAE2E258883339605ULL,
		0x16FE1F931FAD4A3CULL,
		0x8C75C1C3045352DAULL,
		0x00000000001532F5ULL
	}};
	shift = 21;
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
		0xE1784397DBF6BD46ULL,
		0x43254FE55DA3CC7EULL,
		0x174F364CDF20A16EULL,
		0xA10E1B8A91604B5DULL,
		0x265F87CA2A3B2F7EULL,
		0x940806C4401F974CULL,
		0x56DA59B51DE2DC52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF518000000000000ULL,
		0x31FB85E10E5F6FDAULL,
		0x85B90C953F95768FULL,
		0x2D745D3CD9337C82ULL,
		0xBDFA84386E2A4581ULL,
		0x5D30997E1F28A8ECULL,
		0x714A50201B11007EULL,
		0x00015B6966D4778BULL
	}};
	shift = 50;
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
		0xCC349B6DFE5F8795ULL,
		0xA1C2F133B23ABF39ULL,
		0xB6210847117D7EDEULL,
		0x76B488FF6C25AF6BULL,
		0xEDE2EA64F56DE324ULL,
		0xB41BFD5C9FD5E353ULL,
		0x619596D2D346E8EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26DB7F97E1E5400ULL,
		0x0BC4CEC8EAFCE730ULL,
		0x84211C45F5FB7A87ULL,
		0xD223FDB096BDAED8ULL,
		0x8BA993D5B78C91DAULL,
		0x6FF5727F578D4FB7ULL,
		0x565B4B4D1BA3BAD0ULL,
		0x0000000000000186ULL
	}};
	shift = 10;
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
		0x933FE669F809D6FDULL,
		0x3ED43B1633918E25ULL,
		0xA0C52932792096AEULL,
		0x17C7C1937A9DE2F6ULL,
		0x0C6CD173FBDE739BULL,
		0xB2669B3433F74DC8ULL,
		0x73C2865FA534D1EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0275BF400000000ULL,
		0xCE4638964CFF99A7ULL,
		0xE4825AB8FB50EC58ULL,
		0xEA778BDA8314A4C9ULL,
		0xEF79CE6C5F1F064DULL,
		0xCFDD372031B345CFULL,
		0x94D347BEC99A6CD0ULL,
		0x00000001CF0A197EULL
	}};
	shift = 34;
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
		0x6580B5F2A8F4CAC9ULL,
		0xB8B70077528E8EF0ULL,
		0xAE10F9B55930309DULL,
		0x343EC09C8EAE75F9ULL,
		0xC6EF2E25A6115048ULL,
		0x5F65D02A795872D1ULL,
		0xE1908F273BDD3F7BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB016BE551E995920ULL,
		0x16E00EEA51D1DE0CULL,
		0xC21F36AB260613B7ULL,
		0x87D81391D5CEBF35ULL,
		0xDDE5C4B4C22A0906ULL,
		0xECBA054F2B0E5A38ULL,
		0x3211E4E77BA7EF6BULL,
		0x000000000000001CULL
	}};
	shift = 5;
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
		0x58B496F85BDECDC1ULL,
		0x188966AC34771D8FULL,
		0xFDAA4880ACF869CFULL,
		0x7C7AD12BCB0D6C53ULL,
		0x455997DD49C9933EULL,
		0x63C910D4CFFE1C68ULL,
		0xEB94DD9940751341ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9B820000000000ULL,
		0xEE3B1EB1692DF0B7ULL,
		0xF0D39E3112CD5868ULL,
		0x1AD8A7FB54910159ULL,
		0x93267CF8F5A25796ULL,
		0xFC38D08AB32FBA93ULL,
		0xEA2682C79221A99FULL,
		0x000001D729BB3280ULL
	}};
	shift = 41;
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
		0x8C524AA07627EB6EULL,
		0x3DD12A9F4ECFC35BULL,
		0x22CC17C6E7BF13F7ULL,
		0x77959516D5FA89D9ULL,
		0x4AE70B507874B23BULL,
		0xBBF2B04E11D99228ULL,
		0x9FF8515D4A5C769FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5B700000000000ULL,
		0x7E1ADC62925503B1ULL,
		0xF89FB9EE8954FA76ULL,
		0xD44EC91660BE373DULL,
		0xA591DBBCACA8B6AFULL,
		0xCC914257385A83C3ULL,
		0xE3B4FDDF9582708EULL,
		0x000004FFC28AEA52ULL
	}};
	shift = 43;
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
		0xAF6B36F4530D4CD8ULL,
		0x48B78122DC18DB82ULL,
		0xE354091E0522FCD8ULL,
		0x02E7801C4362C720ULL,
		0x28ED961F8271E59CULL,
		0x14D38301F12850B3ULL,
		0x4B175205BBBA346FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3600000000000000ULL,
		0xE0ABDACDBD14C353ULL,
		0x36122DE048B70636ULL,
		0xC838D502478148BFULL,
		0x6700B9E00710D8B1ULL,
		0x2CCA3B6587E09C79ULL,
		0x1BC534E0C07C4A14ULL,
		0x0012C5D4816EEE8DULL
	}};
	shift = 54;
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
		0x5AACF5EA1CB82E91ULL,
		0x529724F2D07BD515ULL,
		0x667C1D8A62030346ULL,
		0xDB51440943EE378AULL,
		0x504EC23523EDFC5DULL,
		0x2F071CE1EF83E2CEULL,
		0xB52A046F8519F0F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C1748800000000ULL,
		0x83DEA8AAD567AF50ULL,
		0x10181A3294B92796ULL,
		0x1F71BC5333E0EC53ULL,
		0x1F6FE2EEDA8A204AULL,
		0x7C1F1672827611A9ULL,
		0x28CF87817838E70FULL,
		0x00000005A950237CULL
	}};
	shift = 35;
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
		0xCE9D4BEE55323886ULL,
		0x6A2A2A5CECB73ED3ULL,
		0x7F07C082CFE09D7DULL,
		0xD11945BADA52024AULL,
		0x594E675FA97347EFULL,
		0x0AD44BB44B114715ULL,
		0xE04A7D86887C823EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5532388600000000ULL,
		0xECB73ED3CE9D4BEEULL,
		0xCFE09D7D6A2A2A5CULL,
		0xDA52024A7F07C082ULL,
		0xA97347EFD11945BAULL,
		0x4B114715594E675FULL,
		0x887C823E0AD44BB4ULL,
		0x00000000E04A7D86ULL
	}};
	shift = 32;
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
		0x49C6CC2BD3189E26ULL,
		0xB69D5EB30FF93346ULL,
		0x1162809DA7BBB868ULL,
		0x106EF082184E9F29ULL,
		0x4869FE0990DEDE21ULL,
		0x994E2A91C1944808ULL,
		0xD04C0909B537518BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C4F13000000000ULL,
		0x7FC99A324E36615EULL,
		0x3DDDC345B4EAF598ULL,
		0xC274F9488B1404EDULL,
		0x86F6F10883778410ULL,
		0x0CA24042434FF04CULL,
		0xA9BA8C5CCA71548EULL,
		0x000000068260484DULL
	}};
	shift = 35;
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
		0x283DED89CC1F80C4ULL,
		0xE2CF946B5A01F789ULL,
		0x9BF7FB3C3C9D87A3ULL,
		0x33FE6C677329B013ULL,
		0xD8006E7C3CAE2649ULL,
		0xA82362F899F51F17ULL,
		0xECB248392C5239CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13983F0188000000ULL,
		0xD6B403EF12507BDBULL,
		0x78793B0F47C59F28ULL,
		0xCEE653602737EFF6ULL,
		0xF8795C4C9267FCD8ULL,
		0xF133EA3E2FB000DCULL,
		0x7258A473995046C5ULL,
		0x0000000001D96490ULL
	}};
	shift = 25;
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
		0x5A44B31CD6D18DD3ULL,
		0x8A225FA246BE51C5ULL,
		0xCF65A5263360DA6AULL,
		0xD0CC65AC735E512CULL,
		0xA8BC421E381EDF84ULL,
		0xC79983F6F0CBA519ULL,
		0xB1D209351AC7115EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6912CC735B46374CULL,
		0x28897E891AF94715ULL,
		0x3D969498CD8369AAULL,
		0x433196B1CD7944B3ULL,
		0xA2F10878E07B7E13ULL,
		0x1E660FDBC32E9466ULL,
		0xC74824D46B1C457BULL,
		0x0000000000000002ULL
	}};
	shift = 2;
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
		0x2439993764C20BC7ULL,
		0xD730634ABB0CBC58ULL,
		0xDBDE780841FC3556ULL,
		0x04E7496B3E6AB64CULL,
		0x4AB60E3670DC53B3ULL,
		0x276D198D25E111D1ULL,
		0x10C1DC9C78C5EDD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3800000000000000ULL,
		0xC121CCC9BB26105EULL,
		0xB6B9831A55D865E2ULL,
		0x66DEF3C0420FE1AAULL,
		0x98273A4B59F355B2ULL,
		0x8A55B071B386E29DULL,
		0xB93B68CC692F088EULL,
		0x00860EE4E3C62F6EULL
	}};
	shift = 59;
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
		0xAABBA816168EBEC4ULL,
		0x40B0525CCB446BF0ULL,
		0xCFE2E1CD5BE69EDDULL,
		0xF3AA2DF05E6FDA87ULL,
		0x3B69D755FE0E7903ULL,
		0x238245941ACFEE58ULL,
		0xF0E6CF7AC6E08DF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABBA816168EBEC40ULL,
		0x0B0525CCB446BF0AULL,
		0xFE2E1CD5BE69EDD4ULL,
		0x3AA2DF05E6FDA87CULL,
		0xB69D755FE0E7903FULL,
		0x38245941ACFEE583ULL,
		0x0E6CF7AC6E08DF82ULL,
		0x000000000000000FULL
	}};
	shift = 4;
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
		0xF9FCC53670D8871FULL,
		0xA4ED7265883EE5DCULL,
		0xC0352FE70E369E59ULL,
		0x73ECA71610A3EAC1ULL,
		0xA401CDDC6C83FE2EULL,
		0xC7E4161E3F4BA0AAULL,
		0x2F137D2B1CD968C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3E0000000000000ULL,
		0xBB9F3F98A6CE1B10ULL,
		0xCB349DAE4CB107DCULL,
		0x583806A5FCE1C6D3ULL,
		0xC5CE7D94E2C2147DULL,
		0x15548039BB8D907FULL,
		0x1878FC82C3C7E974ULL,
		0x0005E26FA5639B2DULL
	}};
	shift = 53;
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
		0x38662E9624B1BAD9ULL,
		0xF7C2549AB672462BULL,
		0x7F6F72FBACF1B7F8ULL,
		0x399BFC838B529AB1ULL,
		0xFA7C6EE5EF8280E5ULL,
		0xB320F4493827B49EULL,
		0x06C7EE9B667F7C45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x375B200000000000ULL,
		0x48C5670CC5D2C496ULL,
		0x36FF1EF84A9356CEULL,
		0x53562FEDEE5F759EULL,
		0x501CA7337F90716AULL,
		0xF693DF4F8DDCBDF0ULL,
		0xEF88B6641E892704ULL,
		0x000000D8FDD36CCFULL
	}};
	shift = 45;
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
		0xBFDC93C46752E430ULL,
		0x342B42805B7E2B6FULL,
		0xCDEF97B9A0793673ULL,
		0x642C1A2AA619F767ULL,
		0x03311E8D70F65F55ULL,
		0x404B8D3BAC78CF59ULL,
		0xF71DAA74857BD82CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2788CEA5C8600000ULL,
		0x8500B6FC56DF7FB9ULL,
		0x2F7340F26CE66856ULL,
		0x34554C33EECF9BDFULL,
		0x3D1AE1ECBEAAC858ULL,
		0x1A7758F19EB20662ULL,
		0x54E90AF7B0588097ULL,
		0x000000000001EE3BULL
	}};
	shift = 17;
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
		0x7A24FCE39947DB1CULL,
		0x7D6AA389A652F459ULL,
		0x0CC7E1B6ECB1BE76ULL,
		0xA1DCE2175290F84FULL,
		0xD64D664545165F6FULL,
		0x966F647F2556AD45ULL,
		0xAF0B4B937567711BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24FCE39947DB1C00ULL,
		0x6AA389A652F4597AULL,
		0xC7E1B6ECB1BE767DULL,
		0xDCE2175290F84F0CULL,
		0x4D664545165F6FA1ULL,
		0x6F647F2556AD45D6ULL,
		0x0B4B937567711B96ULL,
		0x00000000000000AFULL
	}};
	shift = 8;
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
		0x76196C426F979774ULL,
		0xAC5DA383B7820FCDULL,
		0xAB6B430B53A10845ULL,
		0x410EE30C63A91DDCULL,
		0x90E1CCA461E00DA8ULL,
		0xCA2EAD24AA761CC7ULL,
		0xF4BCFF8D8B6B2C48ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x884DF2F2EE800000ULL,
		0x7076F041F9AEC32DULL,
		0x616A742108B58BB4ULL,
		0x618C7523BB956D68ULL,
		0x948C3C01B50821DCULL,
		0xA4954EC398F21C39ULL,
		0xF1B16D65891945D5ULL,
		0x00000000001E979FULL
	}};
	shift = 21;
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
		0xDFF8B4B1273100AEULL,
		0xC4B314DC52DBEC5BULL,
		0x9F7C9CC199DC3A30ULL,
		0x00E9720A40B0C33DULL,
		0x82F3C07689B67733ULL,
		0x7A22454A782ECB11ULL,
		0x79585E43CC8DE12FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xBDFF8B4B1273100AULL,
		0x0C4B314DC52DBEC5ULL,
		0xD9F7C9CC199DC3A3ULL,
		0x300E9720A40B0C33ULL,
		0x182F3C07689B6773ULL,
		0xF7A22454A782ECB1ULL,
		0x079585E43CC8DE12ULL
	}};
	shift = 60;
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
		0xC384592803AB6B0DULL,
		0x011D609A42A693EBULL,
		0x5E83D5756662C39FULL,
		0x2B3BEDE6DF4C57E5ULL,
		0xB3AFF7099CA3365DULL,
		0xDD9D2EA65061CC55ULL,
		0x885C0C3B4456DC89ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2500756D61A000ULL,
		0xAC134854D27D7870ULL,
		0x7AAEACCC5873E023ULL,
		0x7DBCDBE98AFCABD0ULL,
		0xFEE1339466CBA567ULL,
		0xA5D4CA0C398AB675ULL,
		0x8187688ADB913BB3ULL,
		0x000000000000110BULL
	}};
	shift = 13;
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
		0x4FC839D5053C97B6ULL,
		0xC97BCE03A4FEBB20ULL,
		0x8C2DB09AA9AA5864ULL,
		0xB65B5D78BD8A562DULL,
		0xB929CA26C7F8E5C4ULL,
		0x2E997A26713B300CULL,
		0xE448041961391871ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B60000000000000ULL,
		0xB204FC839D5053C9ULL,
		0x864C97BCE03A4FEBULL,
		0x62D8C2DB09AA9AA5ULL,
		0x5C4B65B5D78BD8A5ULL,
		0x00CB929CA26C7F8EULL,
		0x8712E997A26713B3ULL,
		0x000E448041961391ULL
	}};
	shift = 52;
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
		0x0CD3A8A3FFACCD05ULL,
		0x03FB096A55E3FF7BULL,
		0xA0330254A7294808ULL,
		0xE73D155AFE94213FULL,
		0xD9A22DC06DB8FCFBULL,
		0x1F8719BE19363EA2ULL,
		0x9E19F0D9B5334850ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5147FF599A0A0000ULL,
		0x12D4ABC7FEF619A7ULL,
		0x04A94E52901007F6ULL,
		0x2AB5FD28427F4066ULL,
		0x5B80DB71F9F7CE7AULL,
		0x337C326C7D45B344ULL,
		0xE1B36A6690A03F0EULL,
		0x0000000000013C33ULL
	}};
	shift = 17;
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
		0x4C8C706AD3649498ULL,
		0xD4DF7E8C48D516ABULL,
		0x58F1DE09E2CE16B3ULL,
		0x3F17C7696715D9B1ULL,
		0x50066159E59848A8ULL,
		0xF35C1C5DA2B9A204ULL,
		0x2B370B489417E15AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918E0D5A6C929300ULL,
		0x9BEFD1891AA2D569ULL,
		0x1E3BC13C59C2D67AULL,
		0xE2F8ED2CE2BB362BULL,
		0x00CC2B3CB3091507ULL,
		0x6B838BB45734408AULL,
		0x66E1691282FC2B5EULL,
		0x0000000000000005ULL
	}};
	shift = 5;
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
		0xF57FA5841396527DULL,
		0x1401570C58CD7C89ULL,
		0x7A563740B903B6B5ULL,
		0x101680268BCB26A2ULL,
		0xCB0FFC13B5BB62BBULL,
		0x35111D4671414532ULL,
		0x41075A0411E6826EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD2C209CB293E800ULL,
		0x0AB862C66BE44FABULL,
		0xB1BA05C81DB5A8A0ULL,
		0xB401345E593513D2ULL,
		0x7FE09DADDB15D880ULL,
		0x88EA338A0A299658ULL,
		0x3AD0208F341371A8ULL,
		0x0000000000000208ULL
	}};
	shift = 11;
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
		0x179547BDBD7CA25BULL,
		0x1224EFC95A8C92C3ULL,
		0x9069CDECFA92B78CULL,
		0x00E2827037D0D32AULL,
		0x3821906AF3AA05A9ULL,
		0x971D602C58DFEF23ULL,
		0x499DF57634345BF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBE512D80000000ULL,
		0xAD4649618BCAA3DEULL,
		0x7D495BC6091277E4ULL,
		0x1BE869954834E6F6ULL,
		0x79D502D480714138ULL,
		0x2C6FF7919C10C835ULL,
		0x1A1A2DFBCB8EB016ULL,
		0x0000000024CEFABBULL
	}};
	shift = 31;
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
		0xF13A42BA159B0BCDULL,
		0xB55DAC9A232740BBULL,
		0x0D27FD24D86A1063ULL,
		0x1F3F7083B7695BA3ULL,
		0x21947DDDAA0112FDULL,
		0xDDD182F3B2093097ULL,
		0x3FC7EF80D9364267ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6179A00000000000ULL,
		0xE8177E27485742B3ULL,
		0x420C76ABB5934464ULL,
		0x2B7461A4FFA49B0DULL,
		0x225FA3E7EE1076EDULL,
		0x2612E4328FBBB540ULL,
		0xC84CFBBA305E7641ULL,
		0x000007F8FDF01B26ULL
	}};
	shift = 45;
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
		0x23C06C2393604373ULL,
		0x5812770D1782CFABULL,
		0xF1D668474FA17ED8ULL,
		0x5B6CE66F286C7105ULL,
		0x0EF621A0F1880382ULL,
		0xD216F78DDE932C7EULL,
		0x8AECB98570D711CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10DCC00000000000ULL,
		0xB3EAC8F01B08E4D8ULL,
		0x5FB616049DC345E0ULL,
		0x1C417C759A11D3E8ULL,
		0x00E096DB399BCA1BULL,
		0xCB1F83BD88683C62ULL,
		0xC4733485BDE377A4ULL,
		0x000022BB2E615C35ULL
	}};
	shift = 46;
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
		0x2FC0337DFD173342ULL,
		0x3A038040866564BCULL,
		0x75B5ADE7604D8387ULL,
		0x4D15EB4538F1F06FULL,
		0x96385A397751D1C7ULL,
		0xCDEE383E92ACB83DULL,
		0x52FE47D2C55C31E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45CCD0800000000ULL,
		0x199592F0BF00CDF7ULL,
		0x81360E1CE80E0102ULL,
		0xE3C7C1BDD6D6B79DULL,
		0xDD47471D3457AD14ULL,
		0x4AB2E0F658E168E5ULL,
		0x1570C78737B8E0FAULL,
		0x000000014BF91F4BULL
	}};
	shift = 34;
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
		0xBFD053D1863ABB36ULL,
		0x9C19505F907724C3ULL,
		0x043BE81471E64FCFULL,
		0x02565F906FCD293CULL,
		0x5BC52D8950B6D4F4ULL,
		0x757EF60ABEA5A479ULL,
		0x36C8921B4A1E9565ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D1863ABB3600000ULL,
		0x05F907724C3BFD05ULL,
		0x81471E64FCF9C195ULL,
		0xF906FCD293C043BEULL,
		0xD8950B6D4F402565ULL,
		0x60ABEA5A4795BC52ULL,
		0x21B4A1E9565757EFULL,
		0x0000000000036C89ULL
	}};
	shift = 20;
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
		0x2DB7C0643C8BD9D9ULL,
		0x69AEE816FC946BA9ULL,
		0xC0FA7F43EF5C480DULL,
		0xBBCBA7BC55260584ULL,
		0x489811EE10395741ULL,
		0x2475EED21B7F926BULL,
		0x1C1A25D04E1B3F53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C0643C8BD9D900ULL,
		0xAEE816FC946BA92DULL,
		0xFA7F43EF5C480D69ULL,
		0xCBA7BC55260584C0ULL,
		0x9811EE10395741BBULL,
		0x75EED21B7F926B48ULL,
		0x1A25D04E1B3F5324ULL,
		0x000000000000001CULL
	}};
	shift = 8;
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
		0x945496D6A5D2694CULL,
		0x267667C40EADFD9CULL,
		0x11B463205F9EAF4EULL,
		0x3511983CF179ADD9ULL,
		0x707886DC9B37F87BULL,
		0x5472BE036B61A976ULL,
		0xC44E67C25549F5D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B6B52E934A60000ULL,
		0x33E20756FECE4A2AULL,
		0x31902FCF57A7133BULL,
		0xCC1E78BCD6EC88DAULL,
		0x436E4D9BFC3D9A88ULL,
		0x5F01B5B0D4BB383CULL,
		0x33E12AA4FAEAAA39ULL,
		0x0000000000006227ULL
	}};
	shift = 15;
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
		0x2565B50571A61CA9ULL,
		0x0DB3AE0F5ED575CAULL,
		0x6FCBD3BABAA7D060ULL,
		0x46B6EF1AB503C594ULL,
		0xF503DE3915266EBDULL,
		0xF4385C12950D3D76ULL,
		0xE91DB7979244D770ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415C69872A400000ULL,
		0x83D7B55D7289596DULL,
		0xEEAEA9F418036CEBULL,
		0xC6AD40F1651BF2F4ULL,
		0x8E45499BAF51ADBBULL,
		0x04A5434F5DBD40F7ULL,
		0xE5E49135DC3D0E17ULL,
		0x00000000003A476DULL
	}};
	shift = 22;
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
		0x72BB430EC2CBEC79ULL,
		0x4EEE79002EF01B61ULL,
		0x719D04B2C67E89CCULL,
		0x4796E1D363BD106FULL,
		0x6E4B69D1502ED186ULL,
		0xF3596F8C4AFCA435ULL,
		0x115563D9F15FA995ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1876165F63C800ULL,
		0x73C8017780DB0B95ULL,
		0xE8259633F44E6277ULL,
		0xB70E9B1DE8837B8CULL,
		0x5B4E8A81768C323CULL,
		0xCB7C6257E521AB72ULL,
		0xAB1ECF8AFD4CAF9AULL,
		0x000000000000008AULL
	}};
	shift = 11;
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
		0x0D859F7C7DE09225ULL,
		0x397EE2218D254FD1ULL,
		0xFD98C1DDF3C49FA1ULL,
		0x6ED0E87D34BA3552ULL,
		0xA8CAE9952292CF7CULL,
		0xFAB1421B7B96A9CBULL,
		0x050B456D25271C0DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x436167DF1F782489ULL,
		0x4E5FB888634953F4ULL,
		0xBF6630777CF127E8ULL,
		0x1BB43A1F4D2E8D54ULL,
		0xEA32BA6548A4B3DFULL,
		0x7EAC5086DEE5AA72ULL,
		0x0142D15B4949C703ULL
	}};
	shift = 62;
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
		0xAF627A9B6BB539BEULL,
		0x3F2F02BBC14EBFC4ULL,
		0x8A25D31119B2AF7AULL,
		0x455B38D20B88C211ULL,
		0xE4E55C5193ED912FULL,
		0xB58BAAE0A288B340ULL,
		0x9D8A7FDEE0DC3C57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF000000000000000ULL,
		0x257B13D4DB5DA9CDULL,
		0xD1F97815DE0A75FEULL,
		0x8C512E9888CD957BULL,
		0x7A2AD9C6905C4610ULL,
		0x07272AE28C9F6C89ULL,
		0xBDAC5D570514459AULL,
		0x04EC53FEF706E1E2ULL
	}};
	shift = 59;
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
		0x23A881CFDB076B8BULL,
		0x4B0B9540BDFB03CBULL,
		0x41DA3F9A17E17CF6ULL,
		0xFBAB8F1B9C9A4F92ULL,
		0xB6E4F4C2C4C12DC2ULL,
		0x989FA4EA9F6E38C8ULL,
		0xFFC6E893454D0BB0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1DAE2C000000000ULL,
		0x7EC0F2C8EA2073F6ULL,
		0xF85F3D92C2E5502FULL,
		0x2693E490768FE685ULL,
		0x304B70BEEAE3C6E7ULL,
		0xDB8E322DB93D30B1ULL,
		0x5342EC2627E93AA7ULL,
		0x0000003FF1BA24D1ULL
	}};
	shift = 38;
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
		0x232DDA417C10BB12ULL,
		0x167B54A61294F6B7ULL,
		0x7AC01E71C7B4048AULL,
		0xBA5FDA46842B3B57ULL,
		0x406CE4968FB6A5B5ULL,
		0xE93425F8A304FE50ULL,
		0x90250698179CEC57ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085D890000000000ULL,
		0x4A7B5B9196ED20BEULL,
		0xDA02450B3DAA5309ULL,
		0x159DABBD600F38E3ULL,
		0xDB52DADD2FED2342ULL,
		0x827F282036724B47ULL,
		0xCE762BF49A12FC51ULL,
		0x0000004812834C0BULL
	}};
	shift = 39;
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
		0x19EE0E891FB8B6B7ULL,
		0xD7C134C1A433FB8DULL,
		0xB713C1670D324014ULL,
		0xB5FEA3146B3B2E7EULL,
		0xA040F804FE40508FULL,
		0x372227693EE83556ULL,
		0x0973A87F0AA812CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DADC00000000000ULL,
		0xFEE3467B83A247EEULL,
		0x900535F04D30690CULL,
		0xCB9FADC4F059C34CULL,
		0x1423ED7FA8C51ACEULL,
		0x0D55A8103E013F90ULL,
		0x04B2CDC889DA4FBAULL,
		0x0000025CEA1FC2AAULL
	}};
	shift = 46;
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
		0xECAA618AF827F05CULL,
		0x9A6259AEE4B4DD87ULL,
		0x4EF3CE807A91DC1FULL,
		0x3B122B51FB9E4DDAULL,
		0xDDE4659809BADEFCULL,
		0xAA7E5FBD08012C39ULL,
		0x1BBE5DEC3D8A1FAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C0000000000000ULL,
		0xD87ECAA618AF827FULL,
		0xC1F9A6259AEE4B4DULL,
		0xDDA4EF3CE807A91DULL,
		0xEFC3B122B51FB9E4ULL,
		0xC39DDE4659809BADULL,
		0xFAAAA7E5FBD08012ULL,
		0x0001BBE5DEC3D8A1ULL
	}};
	shift = 52;
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
		0x5CE1910B98D52F28ULL,
		0x70AC614BFB8CBD42ULL,
		0x973DC4704CB1A3C3ULL,
		0x843958207242A5A2ULL,
		0x57557DF7AAC52E3AULL,
		0x754C6F0C77C9D0C7ULL,
		0x5EF5178D7AF51764ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B98D52F28000000ULL,
		0x4BFB8CBD425CE191ULL,
		0x704CB1A3C370AC61ULL,
		0x207242A5A2973DC4ULL,
		0xF7AAC52E3A843958ULL,
		0x0C77C9D0C757557DULL,
		0x8D7AF51764754C6FULL,
		0x00000000005EF517ULL
	}};
	shift = 24;
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
		0x77B40688E9E4722AULL,
		0xE06494CAE51B5770ULL,
		0xEF063B22848C8BCCULL,
		0xA6D02B91954E1ADAULL,
		0xA360780C34F77FA7ULL,
		0x73148929B92A4C79ULL,
		0xF557367ACE633949ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x077B40688E9E4722ULL,
		0xCE06494CAE51B577ULL,
		0xAEF063B22848C8BCULL,
		0x7A6D02B91954E1ADULL,
		0x9A360780C34F77FAULL,
		0x973148929B92A4C7ULL,
		0x0F557367ACE63394ULL
	}};
	shift = 60;
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
		0xF050D4002F93AB9DULL,
		0x967BA52E6E0B3708ULL,
		0x69BB22E079D53EF1ULL,
		0x3C02F9AFD130C663ULL,
		0x8954F9BF4B7577E3ULL,
		0x4C0FE707FF8A08BFULL,
		0xAABF4493CE2E25A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50D4002F93AB9D00ULL,
		0x7BA52E6E0B3708F0ULL,
		0xBB22E079D53EF196ULL,
		0x02F9AFD130C66369ULL,
		0x54F9BF4B7577E33CULL,
		0x0FE707FF8A08BF89ULL,
		0xBF4493CE2E25A94CULL,
		0x00000000000000AAULL
	}};
	shift = 8;
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
		0xF3FEE486D53DD5EBULL,
		0x8A4C702E9295392CULL,
		0x216FA9087659C368ULL,
		0x03D17AA143C5A4F7ULL,
		0x5D00EC8AAAB5C8C0ULL,
		0x032CF6AD4C0990C0ULL,
		0x15B8FDD8EF034D4AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7BABD600000000ULL,
		0x252A7259E7FDC90DULL,
		0xECB386D11498E05DULL,
		0x878B49EE42DF5210ULL,
		0x556B918007A2F542ULL,
		0x98132180BA01D915ULL,
		0xDE069A940659ED5AULL,
		0x000000002B71FBB1ULL
	}};
	shift = 33;
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
		0x79A7218898FCF27CULL,
		0x52703DA5E700B5C4ULL,
		0xC36AE74E72C53A36ULL,
		0x937F671B1AD10301ULL,
		0x08A1A71799EAB5E1ULL,
		0xEBE56F4C57611B0CULL,
		0x21F696CF387383BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27C0000000000000ULL,
		0x5C479A7218898FCFULL,
		0xA3652703DA5E700BULL,
		0x301C36AE74E72C53ULL,
		0x5E1937F671B1AD10ULL,
		0xB0C08A1A71799EABULL,
		0x3BDEBE56F4C57611ULL,
		0x00021F696CF38738ULL
	}};
	shift = 52;
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
		0x592A45EC930F50C2ULL,
		0x90C7E6BE644801A8ULL,
		0x72AFC4F1EEF2C123ULL,
		0xA24518FE4A6473D7ULL,
		0x62D86BD8B4AF0915ULL,
		0x9ECB1293F6935562ULL,
		0x423FCCB403F1678EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87A8610000000000ULL,
		0x2400D42C9522F649ULL,
		0x796091C863F35F32ULL,
		0x3239EBB957E278F7ULL,
		0x57848AD1228C7F25ULL,
		0x49AAB1316C35EC5AULL,
		0xF8B3C74F658949FBULL,
		0x000000211FE65A01ULL
	}};
	shift = 39;
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
		0x477243CB6C110C17ULL,
		0xAC39886A2D4FCE39ULL,
		0xACBC9CA5CD4CE260ULL,
		0x0B22842A01BB22FBULL,
		0x2B7E7422320AD637ULL,
		0x8B9EC8B928D9F254ULL,
		0x256F8BD79BB4DBF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B921E5B608860B8ULL,
		0x61CC43516A7E71CAULL,
		0x65E4E52E6A671305ULL,
		0x591421500DD917DDULL,
		0x5BF3A1119056B1B8ULL,
		0x5CF645C946CF92A1ULL,
		0x2B7C5EBCDDA6DF9CULL,
		0x0000000000000001ULL
	}};
	shift = 3;
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
		0x4F0213DF4BA256F3ULL,
		0xE80DA12A4ED9E9CBULL,
		0xD2E2BC9A558D4A9CULL,
		0x8408D77F6ED28525ULL,
		0xA29808E7A2F4663FULL,
		0x105792A36B283960ULL,
		0x6A420986B72F476DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5D12B798000000ULL,
		0x5276CF4E5A78109EULL,
		0xD2AC6A54E7406D09ULL,
		0xFB7694292E9715E4ULL,
		0x3D17A331FC2046BBULL,
		0x1B5941CB0514C047ULL,
		0x35B97A3B6882BC95ULL,
		0x000000000352104CULL
	}};
	shift = 27;
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
		0xB257D9D57478121EULL,
		0xF63BC02EE8EC1C1EULL,
		0x89893D8B9994CAE2ULL,
		0x829ACE0BA45752F4ULL,
		0x7DF752716F8425E6ULL,
		0x85D0582B338EB69BULL,
		0xAE73D0877A4CCCABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D1E048780000000ULL,
		0xBA3B0707AC95F675ULL,
		0xE66532B8BD8EF00BULL,
		0xE915D4BD22624F62ULL,
		0x5BE10979A0A6B382ULL,
		0xCCE3ADA6DF7DD49CULL,
		0xDE93332AE174160AULL,
		0x000000002B9CF421ULL
	}};
	shift = 30;
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
		0xBB25716913683326ULL,
		0x8BD51C587B57F01EULL,
		0xC3E67A5B8C309B2EULL,
		0xA124E70F818754F4ULL,
		0x68E19A370366D7EFULL,
		0xD226B8E8A0963EBFULL,
		0x7D360E1DFD7E4812ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD226D0664C000000ULL,
		0xB0F6AFE03D764AE2ULL,
		0xB71861365D17AA38ULL,
		0x1F030EA9E987CCF4ULL,
		0x6E06CDAFDF4249CEULL,
		0xD1412C7D7ED1C334ULL,
		0x3BFAFC9025A44D71ULL,
		0x0000000000FA6C1CULL
	}};
	shift = 25;
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
		0x355B55CE41D8C8DDULL,
		0x7BF07CEA3E05675DULL,
		0x4A0AC1538EF1DABEULL,
		0x743574A426C7CC23ULL,
		0xC861B0D8B8E738E3ULL,
		0xCFE325F2BB46DD20ULL,
		0xDF44FE764D7E68FFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0xE9AADAAE720EC646ULL,
		0xF3DF83E751F02B3AULL,
		0x1A50560A9C778ED5ULL,
		0x1BA1ABA521363E61ULL,
		0x06430D86C5C739C7ULL,
		0xFE7F192F95DA36E9ULL,
		0x06FA27F3B26BF347ULL
	}};
	shift = 59;
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
		0xF99231683FCF56FBULL,
		0x41703B3DEEEE76B2ULL,
		0x233B63495672E68DULL,
		0x4454883B33DCB71EULL,
		0xF3C08AB8D87DA987ULL,
		0x9DA55E0318FBF488ULL,
		0xA9CC9D2978F0C8F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF56FB00000000000ULL,
		0xE76B2F99231683FCULL,
		0x2E68D41703B3DEEEULL,
		0xCB71E233B6349567ULL,
		0xDA9874454883B33DULL,
		0xBF488F3C08AB8D87ULL,
		0x0C8F49DA55E0318FULL,
		0x00000A9CC9D2978FULL
	}};
	shift = 44;
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
		0x789FC1D73036B6A0ULL,
		0xE35D21FA06F34E8FULL,
		0x235612C83366F6E5ULL,
		0x26623A80A29161D2ULL,
		0x279D32AB7D533AA0ULL,
		0x38AB518E53CF531DULL,
		0x18FD03E884A107BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75CC0DADA8000000ULL,
		0x7E81BCD3A3DE27F0ULL,
		0xB20CD9BDB978D748ULL,
		0xA028A4587488D584ULL,
		0xAADF54CEA809988EULL,
		0x6394F3D4C749E74CULL,
		0xFA212841EFCE2AD4ULL,
		0x0000000000063F40ULL
	}};
	shift = 22;
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
		0xA1B2B64D8851E175ULL,
		0xA7658B01FBA44AC1ULL,
		0x56621F03BC3B9AFEULL,
		0xFD87B7FE4A6C3020ULL,
		0xE9BC0644799E4B7AULL,
		0xA5C2BA7F647E7418ULL,
		0x06473CF7E768208DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9B10A3C2EA0000ULL,
		0x1603F74895834365ULL,
		0x3E07787735FD4ECBULL,
		0x6FFC94D86040ACC4ULL,
		0x0C88F33C96F5FB0FULL,
		0x74FEC8FCE831D378ULL,
		0x79EFCED0411B4B85ULL,
		0x0000000000000C8EULL
	}};
	shift = 17;
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
		0x69ADA9246C148C75ULL,
		0xBABFE313D51B9A9BULL,
		0x21DAA6FB94056190ULL,
		0x877365382377297FULL,
		0x299E5869841C3F58ULL,
		0xDBD3335F31BCCFA9ULL,
		0xE44782FAA84DFFC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6D492360A463A8ULL,
		0xD5FF189EA8DCD4DBULL,
		0x0ED537DCA02B0C85ULL,
		0x3B9B29C11BB94BF9ULL,
		0x4CF2C34C20E1FAC4ULL,
		0xDE999AF98DE67D49ULL,
		0x223C17D5426FFE06ULL,
		0x0000000000000007ULL
	}};
	shift = 3;
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
		0x920FF6E5DFC9895AULL,
		0x6ED36CFB343F83CFULL,
		0xB87B3CE26DBD23E6ULL,
		0x8CA172B89CDE55E7ULL,
		0x59B02AAE9917C03FULL,
		0x44CB95474E2B36A3ULL,
		0xBF39A788BE045094ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4C4AD0000000000ULL,
		0x1FC1E7C907FB72EFULL,
		0xDE91F33769B67D9AULL,
		0x6F2AF3DC3D9E7136ULL,
		0x8BE01FC650B95C4EULL,
		0x159B51ACD815574CULL,
		0x02284A2265CAA3A7ULL,
		0x0000005F9CD3C45FULL
	}};
	shift = 39;
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
		0xB002807085826D7EULL,
		0x5F65BDCF08C1583EULL,
		0x11EAF0C53041BB28ULL,
		0xFED58B0600CCC1A6ULL,
		0x49B8CA483AB17C77ULL,
		0x96F30E3D02A93D9EULL,
		0xE5BCE682D7B92E38ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3842C136BF000000ULL,
		0xE78460AC1F580140ULL,
		0x629820DD942FB2DEULL,
		0x83006660D308F578ULL,
		0x241D58BE3BFF6AC5ULL,
		0x1E81549ECF24DC65ULL,
		0x416BDC971C4B7987ULL,
		0x000000000072DE73ULL
	}};
	shift = 23;
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
		0x9378CD02FD9EC3B4ULL,
		0x696BE2E5E773D1C2ULL,
		0xDC730348623E7183ULL,
		0xA92646CE51B6AD31ULL,
		0x16BB98ECF526274DULL,
		0x02EAAD7509B93941ULL,
		0x197498D151D7BF72ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD876800000000000ULL,
		0x7A38526F19A05FB3ULL,
		0xCE306D2D7C5CBCEEULL,
		0xD5A63B8E60690C47ULL,
		0xC4E9B524C8D9CA36ULL,
		0x272822D7731D9EA4ULL,
		0xF7EE405D55AEA137ULL,
		0x0000032E931A2A3AULL
	}};
	shift = 45;
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
		0x43C09EFCC245DDA8ULL,
		0x96CBA9A5EFB3A6C9ULL,
		0x62B63B137C80A02DULL,
		0x3F52F784C0B5DD4AULL,
		0x7BBC2EA107B9B2C6ULL,
		0x47964DB90FED0500ULL,
		0x3CDB8F9213405FF6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDA800000000000ULL,
		0x3A6C943C09EFCC24ULL,
		0x0A02D96CBA9A5EFBULL,
		0x5DD4A62B63B137C8ULL,
		0x9B2C63F52F784C0BULL,
		0xD05007BBC2EA107BULL,
		0x05FF647964DB90FEULL,
		0x000003CDB8F92134ULL
	}};
	shift = 44;
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
		0xFAD27132A72D1CD7ULL,
		0xAA70BCCC50E73F2CULL,
		0x076858136E22DDF5ULL,
		0xDEA95EF397579832ULL,
		0x2E8CD0B1AE1CD91EULL,
		0x82391414D766EBCEULL,
		0x85F1DEBA03CCD141ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD27132A72D1CD70ULL,
		0xA70BCCC50E73F2CFULL,
		0x76858136E22DDF5AULL,
		0xEA95EF3975798320ULL,
		0xE8CD0B1AE1CD91EDULL,
		0x2391414D766EBCE2ULL,
		0x5F1DEBA03CCD1418ULL,
		0x0000000000000008ULL
	}};
	shift = 4;
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
		0x195D73788F25A838ULL,
		0x0A44461C88CEEBE6ULL,
		0x1C372510C11A17C7ULL,
		0x3969C1C715FFB71EULL,
		0x06E5D21643763A45ULL,
		0x817DEBCB9EB88BB3ULL,
		0x2E76351DF904D919ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195D73788F25A838ULL,
		0x0A44461C88CEEBE6ULL,
		0x1C372510C11A17C7ULL,
		0x3969C1C715FFB71EULL,
		0x06E5D21643763A45ULL,
		0x817DEBCB9EB88BB3ULL,
		0x2E76351DF904D919ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x01F44B44EAA6893CULL,
		0x5087EF680C4230F8ULL,
		0xF0F513D0BB5CE585ULL,
		0x2BEDEB86B34B5B5EULL,
		0xC82FEF70F1346EDCULL,
		0x796D14C3F728D336ULL,
		0xEF4CC510EFB03FE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD127800000000000ULL,
		0x461F003E89689D54ULL,
		0x9CB0AA10FDED0188ULL,
		0x6B6BDE1EA27A176BULL,
		0x8DDB857DBD70D669ULL,
		0x1A66D905FDEE1E26ULL,
		0x07FCCF2DA2987EE5ULL,
		0x00001DE998A21DF6ULL
	}};
	shift = 45;
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
		0x163CC353566D2159ULL,
		0x47BE817AC397C525ULL,
		0x1126A705FA79FB72ULL,
		0xB29DBAA60F05A1F8ULL,
		0xE802C1D280666966ULL,
		0x8F284E6AA62613B7ULL,
		0x1B9E6293E786E519ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8564000000000000ULL,
		0x149458F30D4D59B4ULL,
		0xEDC91EFA05EB0E5FULL,
		0x87E0449A9C17E9E7ULL,
		0xA59ACA76EA983C16ULL,
		0x4EDFA00B074A0199ULL,
		0x94663CA139AA9898ULL,
		0x00006E798A4F9E1BULL
	}};
	shift = 50;
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
		0xC72DFA09886E732CULL,
		0xA1764E89BB77B41CULL,
		0xE661CB71F44063A1ULL,
		0xBB2E11B79EA43E5CULL,
		0x1390E503CD7EE1E2ULL,
		0x43F829B3CC0B221AULL,
		0x3E81EE1999100B39ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B9CCB000000000ULL,
		0xEDDED0731CB7E826ULL,
		0xD1018E8685D93A26ULL,
		0x7A90F97399872DC7ULL,
		0x35FB878AECB846DEULL,
		0x302C88684E43940FULL,
		0x64402CE50FE0A6CFULL,
		0x00000000FA07B866ULL
	}};
	shift = 34;
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
		0x1D4BEBE30863D526ULL,
		0xE51CC2BD67F7178AULL,
		0x01393FE908D2686FULL,
		0xDB9262BF5EDCBCAAULL,
		0xB3F9BA7194E6CB68ULL,
		0x10CB1B530748E2C8ULL,
		0x0C3ABD133BF49D86ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE30863D5260000ULL,
		0xC2BD67F7178A1D4BULL,
		0x3FE908D2686FE51CULL,
		0x62BF5EDCBCAA0139ULL,
		0xBA7194E6CB68DB92ULL,
		0x1B530748E2C8B3F9ULL,
		0xBD133BF49D8610CBULL,
		0x0000000000000C3AULL
	}};
	shift = 16;
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
		0x490C692FA34159DAULL,
		0xE322B0B8ACF7B443ULL,
		0x526F9E8495E082D7ULL,
		0xB928EE8756036504ULL,
		0x701FB7BCCDE2C6DBULL,
		0xB70586F0C232636CULL,
		0x20AE82A190A478C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F4682B3B400000ULL,
		0x17159EF68869218DULL,
		0xD092BC105AFC6456ULL,
		0xD0EAC06CA08A4DF3ULL,
		0xF799BC58DB77251DULL,
		0xDE18464C6D8E03F6ULL,
		0x5432148F1876E0B0ULL,
		0x00000000000415D0ULL
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
		0x46BB261B82DA1261ULL,
		0xCB57F0779CDFFC4CULL,
		0x8D050B82482498A3ULL,
		0x20D10B653EBB22CDULL,
		0xB354BF1F3EE53420ULL,
		0xA4913B7E127B3799ULL,
		0x178AAC75567FE90FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x88D764C3705B424CULL,
		0x796AFE0EF39BFF89ULL,
		0xB1A0A17049049314ULL,
		0x041A216CA7D76459ULL,
		0x366A97E3E7DCA684ULL,
		0xF492276FC24F66F3ULL,
		0x02F1558EAACFFD21ULL
	}};
	shift = 61;
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
		0xFA04232CAF98EF61ULL,
		0x274B94BF7EDD0A3FULL,
		0x686A12A9755B980BULL,
		0x97022C6B25216009ULL,
		0x9FBA8CBE7D78900AULL,
		0xCC350636D44516C3ULL,
		0xA6971773A17B0793ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02119657CC77B080ULL,
		0xA5CA5FBF6E851FFDULL,
		0x350954BAADCC0593ULL,
		0x8116359290B004B4ULL,
		0xDD465F3EBC48054BULL,
		0x1A831B6A228B61CFULL,
		0x4B8BB9D0BD83C9E6ULL,
		0x0000000000000053ULL
	}};
	shift = 7;
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
		0x623CDB7681A560B5ULL,
		0x15C4594BCC1ED70AULL,
		0x6AD2382B0FD39ECCULL,
		0x9E05CC076E32B266ULL,
		0x1D1D1E38BECB874AULL,
		0xC1B865E0F8ED0B3DULL,
		0x2158A7E11D9F823FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B05A80000000000ULL,
		0xF6B85311E6DBB40DULL,
		0x9CF660AE22CA5E60ULL,
		0x9593335691C1587EULL,
		0x5C3A54F02E603B71ULL,
		0x6859E8E8E8F1C5F6ULL,
		0xFC11FE0DC32F07C7ULL,
		0x0000010AC53F08ECULL
	}};
	shift = 43;
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
		0x45B7D4DBE2BD3A90ULL,
		0x5091C858FDE1987CULL,
		0x50F318557CB82442ULL,
		0xEF1901E4EAD22543ULL,
		0x8C4128CA59D8A148ULL,
		0xC36B6C643BD8E901ULL,
		0x5592CEFC38FC4CE8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA6DF15E9D480000ULL,
		0xE42C7EF0CC3E22DBULL,
		0x8C2ABE5C12212848ULL,
		0x80F2756912A1A879ULL,
		0x94652CEC50A4778CULL,
		0xB6321DEC7480C620ULL,
		0x677E1C7E267461B5ULL,
		0x0000000000002AC9ULL
	}};
	shift = 15;
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
		0x8B0F6F33A0C2120FULL,
		0x6CE3FFE45867D07EULL,
		0x10014F3C4673F1F0ULL,
		0x19AB48079098EF58ULL,
		0xDFFD24B182170852ULL,
		0xF463CE9ED4FF57A9ULL,
		0x60CB794C8BF46D74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x241E000000000000ULL,
		0xA0FD161EDE674184ULL,
		0xE3E0D9C7FFC8B0CFULL,
		0xDEB020029E788CE7ULL,
		0x10A43356900F2131ULL,
		0xAF53BFFA4963042EULL,
		0xDAE9E8C79D3DA9FEULL,
		0x0000C196F29917E8ULL
	}};
	shift = 49;
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
		0x2E4D7CD69CE5FE34ULL,
		0x0E1DC1DBD80B6BECULL,
		0xA83A32CBBE986BCEULL,
		0x88842ED4965AB6A9ULL,
		0x424C64D3A0E60B09ULL,
		0xB8252030431DD7BAULL,
		0xB02881E728E94742ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A0000000000000ULL,
		0x5F61726BE6B4E72FULL,
		0x5E7070EE0EDEC05BULL,
		0xB54D41D1965DF4C3ULL,
		0x584C442176A4B2D5ULL,
		0xBDD21263269D0730ULL,
		0x3A15C129018218EEULL,
		0x000581440F39474AULL
	}};
	shift = 51;
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
		0x3C0B6C987C8FCA9BULL,
		0xD2D6EA3C88732E89ULL,
		0x618157745BD97C83ULL,
		0xA70160C864F62013ULL,
		0xE30A7EA95CBA3DC7ULL,
		0x599D27D093328074ULL,
		0xC552B6AA64F6EA53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0x93C0B6C987C8FCA9ULL,
		0x3D2D6EA3C88732E8ULL,
		0x3618157745BD97C8ULL,
		0x7A70160C864F6201ULL,
		0x4E30A7EA95CBA3DCULL,
		0x3599D27D09332807ULL,
		0x0C552B6AA64F6EA5ULL
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
		0x745C27DEF1DCE7A1ULL,
		0x678A377D169A4E2DULL,
		0x63C3911016E9E387ULL,
		0x122F7A2BDE613FB3ULL,
		0xE4D0E766E7951E3CULL,
		0x8BA76243776EC011ULL,
		0x622778209E29613BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA100000000000000ULL,
		0x2D745C27DEF1DCE7ULL,
		0x87678A377D169A4EULL,
		0xB363C3911016E9E3ULL,
		0x3C122F7A2BDE613FULL,
		0x11E4D0E766E7951EULL,
		0x3B8BA76243776EC0ULL,
		0x00622778209E2961ULL
	}};
	shift = 56;
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
		0xDFDE8F323FAEC6EEULL,
		0x2A1F85AB3F23E0F0ULL,
		0x1D06A6C6C0005E0BULL,
		0x75EA4BC18CAB2CB3ULL,
		0x56DB6F684F459A2BULL,
		0x5DC51A79116F09CCULL,
		0xEFBE39794E824898ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1E647F5D8DDC00ULL,
		0x3F0B567E47C1E1BFULL,
		0x0D4D8D8000BC1654ULL,
		0xD49783195659663AULL,
		0xB6DED09E8B3456EBULL,
		0x8A34F222DE1398ADULL,
		0x7C72F29D049130BBULL,
		0x00000000000001DFULL
	}};
	shift = 9;
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
		0x946F80BCED6024B1ULL,
		0xCF17F90F8D414034ULL,
		0x06B01440BAD11187ULL,
		0x3FFC2770347FA873ULL,
		0x69E1D4976C3E263EULL,
		0xBEB6FDA56E4E5B65ULL,
		0xA0CA380EFDA4943CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C4000000000000ULL,
		0x00D251BE02F3B580ULL,
		0x461F3C5FE43E3505ULL,
		0xA1CC1AC05102EB44ULL,
		0x98F8FFF09DC0D1FEULL,
		0x6D95A787525DB0F8ULL,
		0x50F2FADBF695B939ULL,
		0x00028328E03BF692ULL
	}};
	shift = 50;
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
		0x9AE92BE7F6CAD123ULL,
		0x51E1F898DBEC4DB6ULL,
		0x1ABF71543162C51BULL,
		0x35401C7AB4BE2A3FULL,
		0xC20AC78B865B68DDULL,
		0x486147E4BF8B6C18ULL,
		0x6102806DB6F3503EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2300000000000000ULL,
		0xB69AE92BE7F6CAD1ULL,
		0x1B51E1F898DBEC4DULL,
		0x3F1ABF71543162C5ULL,
		0xDD35401C7AB4BE2AULL,
		0x18C20AC78B865B68ULL,
		0x3E486147E4BF8B6CULL,
		0x006102806DB6F350ULL
	}};
	shift = 56;
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
		0x50207809D0F0124BULL,
		0x9C16DFAD07EE231DULL,
		0x4DE18EA99458F73DULL,
		0xB473909694FE5B7DULL,
		0x3A20B0E65392A90BULL,
		0xB2C82977D5BB8477ULL,
		0x8991578B49D2E679ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0492C00000000000ULL,
		0x88C754081E02743CULL,
		0x3DCF6705B7EB41FBULL,
		0x96DF537863AA6516ULL,
		0xAA42ED1CE425A53FULL,
		0xE11DCE882C3994E4ULL,
		0xB99E6CB20A5DF56EULL,
		0x0000226455E2D274ULL
	}};
	shift = 46;
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
		0x224B0C4C33DA1612ULL,
		0x7B987DD8E9DF03F7ULL,
		0x983515DEFF748FCCULL,
		0x46B91AAB63711DC8ULL,
		0xE55738796E85BE84ULL,
		0xDAC94CDF2231A565ULL,
		0x422A65E46FF6262CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B0900000000000ULL,
		0xF81FB9125862619EULL,
		0xA47E63DCC3EEC74EULL,
		0x88EE44C1A8AEF7FBULL,
		0x2DF42235C8D55B1BULL,
		0x8D2B2F2AB9C3CB74ULL,
		0xB13166D64A66F911ULL,
		0x00000211532F237FULL
	}};
	shift = 43;
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
		0xCA1B4924D0967D2CULL,
		0xE3F764093E5DA1CCULL,
		0xB2367D497A1EB97BULL,
		0x9792E717ADA4F879ULL,
		0xC934102CBA1D945CULL,
		0xD730B23DE1E5A010ULL,
		0xB3F3E0E9BDF2F2AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934259F4B0000000ULL,
		0x24F9768733286D24ULL,
		0x25E87AE5EF8FDD90ULL,
		0x5EB693E1E6C8D9F5ULL,
		0xB2E87651725E4B9CULL,
		0xF78796804324D040ULL,
		0xA6F7CBCABF5CC2C8ULL,
		0x0000000002CFCF83ULL
	}};
	shift = 26;
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
		0x86DB2B07E6434287ULL,
		0x148F9C694A46D9EDULL,
		0x7C1EF3F8336FF2A3ULL,
		0x6F21B58334AE7D55ULL,
		0xAC52B632F4BCFEE5ULL,
		0x0F92B6EA4955B0ADULL,
		0x1817CDC4772E2DC2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990D0A1C00000000ULL,
		0x291B67B61B6CAC1FULL,
		0xCDBFCA8C523E71A5ULL,
		0xD2B9F555F07BCFE0ULL,
		0xD2F3FB95BC86D60CULL,
		0x2556C2B6B14AD8CBULL,
		0xDCB8B7083E4ADBA9ULL,
		0x00000000605F3711ULL
	}};
	shift = 34;
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
		0xA194227CDFC33512ULL,
		0xFE95FA00B5230A61ULL,
		0x97F47113E095E0B8ULL,
		0x4FD7BF1AE6391151ULL,
		0x6C2D03F856F3BDF3ULL,
		0x1F1A2523E28BCF68ULL,
		0x35CDBF7FA25E81EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD0CA113E6FE19A89ULL,
		0x7F4AFD005A918530ULL,
		0xCBFA3889F04AF05CULL,
		0xA7EBDF8D731C88A8ULL,
		0x361681FC2B79DEF9ULL,
		0x0F8D1291F145E7B4ULL,
		0x1AE6DFBFD12F40F5ULL
	}};
	shift = 63;
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
		0x6B01F89620124481ULL,
		0x6851A1F7B87B0DC8ULL,
		0x6A29AB01CFB0B5A1ULL,
		0x6D555B313BC0CABFULL,
		0xF5ABFD7151D84686ULL,
		0x62F8BC31D7360A6DULL,
		0x2C2CC1403CC6809FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2240800000000000ULL,
		0x86E43580FC4B1009ULL,
		0x5AD0B428D0FBDC3DULL,
		0x655FB514D580E7D8ULL,
		0x234336AAAD989DE0ULL,
		0x0536FAD5FEB8A8ECULL,
		0x404FB17C5E18EB9BULL,
		0x0000161660A01E63ULL
	}};
	shift = 47;
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
	return 0;
}