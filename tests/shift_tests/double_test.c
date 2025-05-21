#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA70C4AB44CD66C4CULL,
		0x8D1E463535D12C90ULL,
		0x2C395CBE356A688FULL,
		0x566B6C3864945BCCULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x4E18956899ACD8ABULL,
		0x1A3C8C6A6BA25921ULL,
		0x5872B97C6AD4D11FULL,
		0x2CD6D870C928B798ULL
	}};
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB16ED882A5D76E1ULL,
		0x97B19192A97546B3ULL,
		0x8DCBE0BE10740402ULL,
		0x58E426CA881F2F2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x762DDB1054BAEDD5ULL,
		0x2F63232552EA8D67ULL,
		0x1B97C17C20E80805ULL,
		0x31C84D95103E5E5FULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CD468DFC577B240ULL,
		0x3F0BF53DA71CEF4CULL,
		0xD4F50399CE7D7BBDULL,
		0x37BBEB5B07A41187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A8D1BF8AEF6480ULL,
		0x7E17EA7B4E39DE98ULL,
		0xA9EA07339CFAF77AULL,
		0x6F77D6B60F48230FULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6459B3943BB81C63ULL,
		0x56D7A5C81E2A0C37ULL,
		0x406145AFDAE3D1C4ULL,
		0x4A71C829342E72EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B36728777038D9ULL,
		0xADAF4B903C54186EULL,
		0x80C28B5FB5C7A388ULL,
		0x14E39052685CE5D6ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE80F9435FA658FEULL,
		0xFA1FFB691D2A5108ULL,
		0x68E44AA8B1AC7D20ULL,
		0x577AE006D2BB4F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D01F286BF4CB20FULL,
		0xF43FF6D23A54A211ULL,
		0xD1C895516358FA41ULL,
		0x2EF5C00DA5769ED6ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29D32BB47B891B24ULL,
		0xDBE54BA0DCF5322CULL,
		0x454937664CED7027ULL,
		0x3BEFD1083EF8EEC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A65768F7123648ULL,
		0xB7CA9741B9EA6458ULL,
		0x8A926ECC99DAE04FULL,
		0x77DFA2107DF1DD8AULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x871C7D56F4F91530ULL,
		0x3A0FDF7433C93C42ULL,
		0xEAECD15922A8720EULL,
		0x4D11A8F9D51B084EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E38FAADE9F22A73ULL,
		0x741FBEE867927885ULL,
		0xD5D9A2B24550E41CULL,
		0x1A2351F3AA36109DULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28BA49DDA9BEB777ULL,
		0x39E9F206168E5090ULL,
		0x51D287316F122340ULL,
		0x0618C1D3B4CA78DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517493BB537D6EEEULL,
		0x73D3E40C2D1CA120ULL,
		0xA3A50E62DE244680ULL,
		0x0C3183A76994F1B8ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x888310F4751D03BBULL,
		0xA60579E607BD76B7ULL,
		0x3B81D56F643B42ACULL,
		0x2E7B3E51AFBA8599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110621E8EA3A0776ULL,
		0x4C0AF3CC0F7AED6FULL,
		0x7703AADEC8768559ULL,
		0x5CF67CA35F750B32ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2F3197524DAB458ULL,
		0x2F00A201DED36BD1ULL,
		0x03DF1657CE7CC185ULL,
		0x76D9B054B8C8225EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E632EA49B568C3ULL,
		0x5E014403BDA6D7A3ULL,
		0x07BE2CAF9CF9830AULL,
		0x6DB360A9719044BCULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26CFCC5C8CD4CF24ULL,
		0xF92C6F7EF646C494ULL,
		0xAF3B0A9CABA3B9F0ULL,
		0x4EC4C86F3D096121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9F98B919A99E5BULL,
		0xF258DEFDEC8D8928ULL,
		0x5E761539574773E1ULL,
		0x1D8990DE7A12C243ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74964132A7C49ED8ULL,
		0x23A23551F0D895C6ULL,
		0x6145DB9C4A2CA014ULL,
		0x748138E8D0A59863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE92C82654F893DC3ULL,
		0x47446AA3E1B12B8CULL,
		0xC28BB73894594028ULL,
		0x690271D1A14B30C6ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A2A361DF306B5C5ULL,
		0xE11455754D4E213FULL,
		0x245D53B0D86E016BULL,
		0x7DC5DD77D763D20EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74546C3BE60D6B9DULL,
		0xC228AAEA9A9C427EULL,
		0x48BAA761B0DC02D7ULL,
		0x7B8BBAEFAEC7A41CULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2802674039DD223CULL,
		0x7A134E2D152A2286ULL,
		0xC3DEF255AE86865EULL,
		0x23F1E2719BB71A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5004CE8073BA4478ULL,
		0xF4269C5A2A54450CULL,
		0x87BDE4AB5D0D0CBCULL,
		0x47E3C4E3376E3501ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA23D4C0A7EED01B8ULL,
		0x9809D0C7899F6112ULL,
		0x8E955890563687B8ULL,
		0x31B26EDDD2B18979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x447A9814FDDA0370ULL,
		0x3013A18F133EC225ULL,
		0x1D2AB120AC6D0F71ULL,
		0x6364DDBBA56312F3ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DD9BC322B950F08ULL,
		0xA7EA2DF8538753B3ULL,
		0x2DEC2F5F98DFEBD9ULL,
		0x64B7BCC47FB00108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB37864572A1E23ULL,
		0x4FD45BF0A70EA767ULL,
		0x5BD85EBF31BFD7B3ULL,
		0x496F7988FF600210ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2AA91EB75E245C5ULL,
		0xA3352BE60EA8211CULL,
		0x0231CAE719497995ULL,
		0x73FC1DFF54734175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55523D6EBC48B9DULL,
		0x466A57CC1D504239ULL,
		0x046395CE3292F32BULL,
		0x67F83BFEA8E682EAULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD3F70E6D6712A9FULL,
		0x53489B539B5A1186ULL,
		0xCA742073D8E9489DULL,
		0x0AAA2603BE2278B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A7EE1CDACE2553EULL,
		0xA69136A736B4230DULL,
		0x94E840E7B1D2913AULL,
		0x15544C077C44F163ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7E7EF5C68AF977ULL,
		0xE50EFCC778AE8D70ULL,
		0xDA108B6826E0ABFAULL,
		0x5BAB771EB723C46CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AFCFDEB8D15F301ULL,
		0xCA1DF98EF15D1AE1ULL,
		0xB42116D04DC157F5ULL,
		0x3756EE3D6E4788D9ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3298BECEA4ACAC84ULL,
		0xDCBFBD0A6ADC8981ULL,
		0x7624AB3736A141A6ULL,
		0x179579D7830FB128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65317D9D49595908ULL,
		0xB97F7A14D5B91302ULL,
		0xEC49566E6D42834DULL,
		0x2F2AF3AF061F6250ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB83833B8A342D05FULL,
		0x2ADAFDBF4A8B5974ULL,
		0xB33F8F36343EC083ULL,
		0x55C0B0A86EB46853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707067714685A0D1ULL,
		0x55B5FB7E9516B2E9ULL,
		0x667F1E6C687D8106ULL,
		0x2B816150DD68D0A7ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB93CA944632970C3ULL,
		0xFFA56EF0BC134E9AULL,
		0xE7C646F01E735F2DULL,
		0x4BDA70D6D2D7A7C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72795288C652E199ULL,
		0xFF4ADDE178269D35ULL,
		0xCF8C8DE03CE6BE5BULL,
		0x17B4E1ADA5AF4F81ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C09F4F42A2E3431ULL,
		0xEDC1AC2537D599F8ULL,
		0xD0E2F523ADDE1F49ULL,
		0x3CC0F5CDC0F1AC2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9813E9E8545C6862ULL,
		0xDB83584A6FAB33F0ULL,
		0xA1C5EA475BBC3E93ULL,
		0x7981EB9B81E35857ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54FB5BF38C21E459ULL,
		0x5E77EB0207DF9DCDULL,
		0x0A61E1E16FA5F216ULL,
		0x376701D653445DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9F6B7E71843C8B2ULL,
		0xBCEFD6040FBF3B9AULL,
		0x14C3C3C2DF4BE42CULL,
		0x6ECE03ACA688BB9CULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEBFDA553CC8C7D9ULL,
		0x6ED6164E74373EADULL,
		0x61B9A69567DA7361ULL,
		0x626C61E8E3EA7FF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D7FB4AA79918FC5ULL,
		0xDDAC2C9CE86E7D5BULL,
		0xC3734D2ACFB4E6C2ULL,
		0x44D8C3D1C7D4FFE4ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABDE0A52BDD4E56AULL,
		0x2025362303418B7DULL,
		0xFAC56ACB927090D2ULL,
		0x1BE1BDDBAEAA5468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57BC14A57BA9CAD4ULL,
		0x404A6C46068316FBULL,
		0xF58AD59724E121A4ULL,
		0x37C37BB75D54A8D1ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41AD3DABAA26447CULL,
		0x0873DD3C94758018ULL,
		0xBC42B75DC59BCC00ULL,
		0x2FDA33CA69E49785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835A7B57544C88F8ULL,
		0x10E7BA7928EB0030ULL,
		0x78856EBB8B379800ULL,
		0x5FB46794D3C92F0BULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x346845629D559E2FULL,
		0x0434DAB92FE94A59ULL,
		0x686D8CEB2DF5DCEFULL,
		0x3B13688E6CE02144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D08AC53AAB3C5EULL,
		0x0869B5725FD294B2ULL,
		0xD0DB19D65BEBB9DEULL,
		0x7626D11CD9C04288ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49B761CFB5C37D4EULL,
		0x4BC06E99DE966EF6ULL,
		0xD99B69DBAE8A8F6FULL,
		0x4286FE3DAFD0B551ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x936EC39F6B86FAAFULL,
		0x9780DD33BD2CDDECULL,
		0xB336D3B75D151EDEULL,
		0x050DFC7B5FA16AA3ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36F32268217D5F1EULL,
		0x9D1624F228614569ULL,
		0xFE400E050734AD08ULL,
		0x2375A763EEBDAA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE644D042FABE3CULL,
		0x3A2C49E450C28AD2ULL,
		0xFC801C0A0E695A11ULL,
		0x46EB4EC7DD7B544FULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF83573DD580E17EBULL,
		0xF968E5D0F59DB1A1ULL,
		0xFC712FF060F31B3EULL,
		0x259999BA611FB0ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06AE7BAB01C2FD6ULL,
		0xF2D1CBA1EB3B6343ULL,
		0xF8E25FE0C1E6367DULL,
		0x4B333374C23F6159ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E053A49CC64D4AULL,
		0x5805FA6628BA744FULL,
		0x718540EF6AE6D745ULL,
		0x792FC3B0F9D5ADC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C0A749398C9AA7ULL,
		0xB00BF4CC5174E89EULL,
		0xE30A81DED5CDAE8AULL,
		0x725F8761F3AB5B88ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31715E81BBCA7CD7ULL,
		0x61FB25B2780D1BA5ULL,
		0x54F9CCE8E5BFF339ULL,
		0x49DAF7A135E977DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E2BD037794F9C1ULL,
		0xC3F64B64F01A374AULL,
		0xA9F399D1CB7FE672ULL,
		0x13B5EF426BD2EFBAULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49C11CCD20A0BA29ULL,
		0xE53BF5133D8306BBULL,
		0xA55AB848D7855468ULL,
		0x4F09E8D8171F20DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9382399A41417465ULL,
		0xCA77EA267B060D76ULL,
		0x4AB57091AF0AA8D1ULL,
		0x1E13D1B02E3E41B9ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDC4ADF4D1804A5BULL,
		0x4B5785A4F75A16D6ULL,
		0x8B8A381CDDC63886ULL,
		0x6D96D19FC693499CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B895BE9A30094C9ULL,
		0x96AF0B49EEB42DADULL,
		0x17147039BB8C710CULL,
		0x5B2DA33F8D269339ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8C432382F93B1BEULL,
		0x3CC4D9C361CB2A22ULL,
		0xABFB5F6B6A532A29ULL,
		0x712EBA9442398D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18864705F27638FULL,
		0x7989B386C3965445ULL,
		0x57F6BED6D4A65452ULL,
		0x625D752884731A63ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA71EAA0045D9AFEULL,
		0x2E08C25CB1A2403AULL,
		0xA2D2B82600743D0FULL,
		0x48C8865D53E1127CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E3D54008BB360FULL,
		0x5C1184B963448075ULL,
		0x45A5704C00E87A1EULL,
		0x11910CBAA7C224F9ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15FDA344067FB831ULL,
		0x007B9F3B0E4D3894ULL,
		0x2057D2C064F48EABULL,
		0x697C4D030875F3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BFB46880CFF7075ULL,
		0x00F73E761C9A7128ULL,
		0x40AFA580C9E91D56ULL,
		0x52F89A0610EBE74AULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC593D07902A143C6ULL,
		0x4249FE14E6875054ULL,
		0x5227D25014BF3DC5ULL,
		0x2F379E964E704176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B27A0F20542878CULL,
		0x8493FC29CD0EA0A9ULL,
		0xA44FA4A0297E7B8AULL,
		0x5E6F3D2C9CE082ECULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x965D95DBFA587502ULL,
		0xAD0EE951A9E78F4FULL,
		0xD6DB271E8047BBC9ULL,
		0x40BD9050EA17AF56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CBB2BB7F4B0EA17ULL,
		0x5A1DD2A353CF1E9FULL,
		0xADB64E3D008F7793ULL,
		0x017B20A1D42F5EADULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC9ACCA9BC68E421ULL,
		0x649BD6EA02FCB8A7ULL,
		0x7EAF28512B189045ULL,
		0x0CBDEE985F70A7A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF935995378D1C842ULL,
		0xC937ADD405F9714FULL,
		0xFD5E50A25631208AULL,
		0x197BDD30BEE14F44ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82185595E760FF10ULL,
		0x139E6539C5F9C6F1ULL,
		0xFA7F78AC92C3EC9BULL,
		0x4F91A5C0F1D6F920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0430AB2BCEC1FE33ULL,
		0x273CCA738BF38DE3ULL,
		0xF4FEF1592587D936ULL,
		0x1F234B81E3ADF241ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8A784DBA4EADD6CULL,
		0x964ECD2FADB32B8CULL,
		0x7434BCA356D7DD31ULL,
		0x74A3DBC5F4430FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14F09B749D5BAEBULL,
		0x2C9D9A5F5B665719ULL,
		0xE8697946ADAFBA63ULL,
		0x6947B78BE8861F44ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5892E72DAD1D21C1ULL,
		0x7C8A2D782DA0F7C6ULL,
		0x8EB6AB6841D12CFFULL,
		0x313FB34896224F7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB125CE5B5A3A4382ULL,
		0xF9145AF05B41EF8CULL,
		0x1D6D56D083A259FEULL,
		0x627F66912C449EFDULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3805B2230D999CBFULL,
		0xEC8664E5BB754EDCULL,
		0x62B14C4AA7577CE6ULL,
		0x03FD1BFFAE121E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700B64461B33397EULL,
		0xD90CC9CB76EA9DB8ULL,
		0xC56298954EAEF9CDULL,
		0x07FA37FF5C243C10ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCFDD1A2F44A7B85ULL,
		0xB12A0C1A34325C8EULL,
		0x665E92F1C1C9F151ULL,
		0x53CDA7EE336F2DB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79FBA345E894F71DULL,
		0x625418346864B91DULL,
		0xCCBD25E38393E2A3ULL,
		0x279B4FDC66DE5B66ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18DA0A77C5C4E995ULL,
		0x86C0FC76E1656848ULL,
		0xC7EF62143D1B5307ULL,
		0x2DC50AE0AD1230A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B414EF8B89D32AULL,
		0x0D81F8EDC2CAD090ULL,
		0x8FDEC4287A36A60FULL,
		0x5B8A15C15A246143ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94987AF84F6B0D75ULL,
		0xE905038FFA463F78ULL,
		0x949DCC9F8F8353AFULL,
		0x383498F4F3062E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2930F5F09ED61AEAULL,
		0xD20A071FF48C7EF1ULL,
		0x293B993F1F06A75FULL,
		0x706931E9E60C5C55ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F923EBB91A93A8FULL,
		0xE71DDF1DCD01F340ULL,
		0xA6014708824792DEULL,
		0x469CA834AD951EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F247D7723527531ULL,
		0xCE3BBE3B9A03E680ULL,
		0x4C028E11048F25BDULL,
		0x0D3950695B2A3D63ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F676511E55EC6E9ULL,
		0x1B1FFAB7DD90C669ULL,
		0xADCCD7EBB4DDBF6DULL,
		0x74589709B2B5CA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECECA23CABD8DE5ULL,
		0x363FF56FBB218CD2ULL,
		0x5B99AFD769BB7EDAULL,
		0x68B12E13656B9537ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}