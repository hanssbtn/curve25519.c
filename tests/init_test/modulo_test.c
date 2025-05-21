#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0604C564105393A0ULL,
		0x4FA256D488886C91ULL,
		0xD0A07B48292E1074ULL,
		0x8C3CC2C6A3DE179AULL,
		0x4CBB6B597638C6BCULL,
		0xAB997A4492930F45ULL,
		0xDE520027732831E3ULL,
		0x5F4FFC8AB371C19CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0E4A32905B9B9A68ULL,
		0x6369FC3A03E072A8ULL,
		0x2A0571CDBC3150E7ULL,
		0xDF2FE2016604C942ULL,
		0x3FB85C773692D206ULL,
		0xDB0C1A5EA975D3E7ULL,
		0xC352FBCDC4F83B37ULL,
		0x26DB4E2FE946B776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5509A18DFE93B9E7ULL,
		0x68D5F7EA7A2BDF9CULL,
		0x0F406365D38B2FEEULL,
		0xC595F73427251ED4ULL,
		0xA5BA94590A86BE47ULL,
		0xDB208B176CE5035BULL,
		0xD90FC819BA9ED72FULL,
		0xA457FFD2982E232EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE52122F9F1F6C2CAULL,
		0x60EBCE0F38F0E4DEULL,
		0x7224EBDD8CD99D24ULL,
		0xB5D93C9436DCED1EULL,
		0xDEEA3F597960BE0EULL,
		0x1B81685366758FDBULL,
		0xDD9EF0D3C7396940ULL,
		0xD2001FCC58DA402BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x08F4E06C933E17CDULL,
		0x7672FA2EE4344FA4ULL,
		0x1CBA4F7BA25B8A80ULL,
		0x098120256C629CD5ULL,
		0xE79E9AB56EEE84A6ULL,
		0xD4967B35442640A5ULL,
		0x5EEDCA6ABDB18FBEULL,
		0x036107313B81C30CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x69F4265C72006A78ULL,
		0xA5B7B034F4160A62ULL,
		0x766ADA4B4B283A07ULL,
		0xBE66E2CA1DC85029ULL,
		0xBC8E2E164894BE23ULL,
		0x2AC3773D9D47BCCCULL,
		0x5AEB73C030EF6411ULL,
		0x41A86C76A75E2ADAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3F4B27100BDE4508ULL,
		0xB51EECB84B486970ULL,
		0xD7943C5CFFE456D7ULL,
		0xBDA2D742B46EA959ULL,
		0x74C33D9AF59EE6D3ULL,
		0xA742C7C06569A23AULL,
		0xBFBFDCF89E6532A0ULL,
		0x555557D2938CB3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC2347DC9488183E8ULL,
		0x198535776D3C281AULL,
		0x1D61B1F3C9665B09ULL,
		0x47BF0395EC0DC8E6ULL,
		0xF53FA1068D000063ULL,
		0x637BD31222D541B4ULL,
		0xDE6D7C05A8CC9169ULL,
		0x9FF7D35279F2D7DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x15A5E73B3D36AA08ULL,
		0x5DAA3DB749E0FBEEULL,
		0x0FF67395DC0888A6ULL,
		0x2AFE0B91556E2BDDULL,
		0x64B993EB93709ABEULL,
		0x7FEC47A36E6DDA6BULL,
		0x758D3F20AB5C58F3ULL,
		0x4F8C56F634E88515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x69D5291FE2B483DDULL,
		0x382E1056A4B245E8ULL,
		0x6E6B5B12639EAB53ULL,
		0x8849FCC631E0D2E3ULL,
		0xEEE0D45F4D24D86BULL,
		0x4C9F8A13E0215696ULL,
		0xE7AB538771D24E33ULL,
		0xACF91C40B6D2A518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE22F9A79A7503567ULL,
		0xA5D7F75980298339ULL,
		0xB37EAF2B3D6B6C03ULL,
		0xCE821A176E5AF710ULL,
		0xC1713A1B320B9C12ULL,
		0x818E33BA9849287DULL,
		0xBEDF864150B42B46ULL,
		0x0CF30DD848A1A53CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x402C3096E75B9525ULL,
		0xCD4C8F7C4FBA6099ULL,
		0x83EC02A6F82EDB67ULL,
		0x18E16E3529CBB004ULL,
		0x3B548BC3A7446089ULL,
		0xEED71AE76DCBFB2EULL,
		0x057B223372FB2F43ULL,
		0x844BEA3DC55E5544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF974562FD54E9133ULL,
		0x56539C833A4E3408ULL,
		0x1CE1FA15F0C7DBECULL,
		0x2CF095D6D2520441ULL,
		0x0C585ABA9FA9B8DBULL,
		0x04CDDE7E9D613BC8ULL,
		0x981AF08BE6DD3712ULL,
		0xF64F94E80FFC3AEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x518F312EA15687EBULL,
		0xF1B21D5FB31E65EDULL,
		0xA13D66C8D9884958ULL,
		0x81F7BFEA2E35C51EULL,
		0x5F0C1E7417A579AAULL,
		0x408E39BA17C7C3FCULL,
		0xF95D81297A1D36E1ULL,
		0xC7BF3EA6B6D7A375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x542194FB411B0026ULL,
		0x1EE85856A13DC774ULL,
		0xAFD95F46B77E0411ULL,
		0xF2C34EAFDF68E750ULL,
		0xD06E44CF0B166AAAULL,
		0x29718B87714E06D5ULL,
		0xBF0429B13A72FA0CULL,
		0x7A53F5806349D00CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9E7DFEEE026DFFB0ULL,
		0x8E47B1D603BAB444ULL,
		0x1DE85158A6501DF8ULL,
		0xA78EE58F392E80DFULL,
		0xF8CE6240E9508135ULL,
		0xF4D9DDA846281954ULL,
		0x246B3A79AED98EAEULL,
		0x9267EC7D978DF6EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF05E19F11D67F8B6ULL,
		0xCEA9A43318D4A242ULL,
		0x441216544B6F622FULL,
		0x6879332BA3438EBFULL,
		0x5354FB5F521E00B1ULL,
		0x667BBE329F52CEFEULL,
		0x24DB38DD873C1751ULL,
		0x3826D04A6DE48A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B16F545B6D1BBEAULL,
		0x2C988CE46DDE0D5AULL,
		0x3C9D74F405C4299BULL,
		0x78FD9DBD60984BEFULL,
		0xEB3EDAC3DE6FA491ULL,
		0xE8BEE868ED40EE60ULL,
		0xB2F1A72F7C8F2832ULL,
		0xFA99480AC0FBE2F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xED07901BA8CA1C74ULL,
		0xFBFD8D509595B339ULL,
		0x5B65D5DAF19228DAULL,
		0x6E9E6483C369FEE6ULL,
		0xE630EDF729D39D23ULL,
		0xDA892B8FE97126BDULL,
		0xF1C8039D39969E0EULL,
		0x9739E5425EF8699CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9EF552AA2D9A7210ULL,
		0xE1ECF93F12E3B87BULL,
		0x70AF180A3EAC8C12ULL,
		0x1E3191D95D5FC47DULL,
		0xEDD2092650A0CB50ULL,
		0x0606A373843EB75CULL,
		0xA15967BCE5CCD68BULL,
		0xF98AA19AA12E7D6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x808700C32EEDB4F2ULL,
		0x397D6B83ADF26BB6ULL,
		0x1E970A77B056D699ULL,
		0x8E9134E1C9F250F8ULL,
		0x657742A971292615ULL,
		0xAB2941E31C65C634ULL,
		0x9ECEDDFF0580A8C4ULL,
		0xA307D3CB32221CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD50184522F6C4F78ULL,
		0x4E64FAF7CCAC6D8AULL,
		0x4CAD90E544F37E9AULL,
		0xB972FECE8CE0B618ULL,
		0xE178819B6755B49EULL,
		0x5ADAC4B035DFF1CDULL,
		0x986FC12DC6A6EDD9ULL,
		0xF245E0DFE3BA7DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x885BAE2160D57865ULL,
		0x6BC1563A2775F71EULL,
		0xAD2CC5D6E76DDABBULL,
		0xE8D3739993E72E3CULL,
		0xE14CB7746D062AEFULL,
		0x0E84E3AC8651919FULL,
		0x692E69C9A5A6C6FAULL,
		0x242E4FC24C5D6887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x972671AE6FD59D4FULL,
		0x2E655CD2377B0FA1ULL,
		0xE5B0811C892448EFULL,
		0xA62834EF55FE2DF9ULL,
		0x03D910F123834CE0ULL,
		0xB322BFFA61ABC9DAULL,
		0x552AB63E987A0688ULL,
		0x6964E4F39DC96A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9F3298C2A5C11587ULL,
		0x22AD2AAD33C49393ULL,
		0xA5213B3468A54F52ULL,
		0x3502DF6EFA6BA19EULL,
		0x582762DF987EB46CULL,
		0x6F842E45507689B8ULL,
		0xCA9FD4FD01D3A669ULL,
		0xB3E285AC82BAD64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x160C263B6545C589ULL,
		0xF44527A2ADF31C8EULL,
		0xB0B90EEE7F5E3F7EULL,
		0x8CE1492ECABC5D45ULL,
		0x4B08F3EA7DA55500ULL,
		0x31BFCEAE4C80B278ULL,
		0x1C002F48DEF43C90ULL,
		0x6A88D8F4479E9CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCA7FADC82B902B32ULL,
		0x2AC0151E1B3617DDULL,
		0x7D067506CCC985F2ULL,
		0xE3D99387EDB44EF9ULL,
		0x681BF0B3163F42E1ULL,
		0xE0076E42177DACA9ULL,
		0x84D6F06D0D9650E4ULL,
		0x008BFACC5BF09901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCF4BB18A09A26EF5ULL,
		0xA925FDC3B8481014ULL,
		0xC25699BF210C7F10ULL,
		0xFCD4B40A810FC784ULL,
		0xC21F536A28F64A9FULL,
		0xDB50FD08B446E116ULL,
		0xEA2C5D83A44E3690ULL,
		0xFDB22A0F0702CF83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3135FE240B025283ULL,
		0x13E849D9BAC86761ULL,
		0xDA218BB5D66E1606ULL,
		0x8CA9E7781B3524F8ULL,
		0x0695CE1F819F238BULL,
		0xD53880281093B3B7ULL,
		0xD48C8E70F3167984ULL,
		0x920F112183C7F192ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7AF97DBBDA22AEC2ULL,
		0x252429F9EBB52A2AULL,
		0xAA21414BD08E0A35ULL,
		0x48DBFF35FD4634F5ULL,
		0x33554650AEA0EA00ULL,
		0x29CD3FD0CAEBBBD3ULL,
		0xCCEE403B9CF520E1ULL,
		0x7A18D1DD7BF0BAE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEDA449CCB9C4648EULL,
		0x18BE5303A88E1559ULL,
		0xB2FAE1625288845DULL,
		0x72F41A6D63070E77ULL,
		0xD4DA7323885A47CFULL,
		0x1F59FA76B3349271ULL,
		0x2BE803F1AE575D30ULL,
		0x994A7D0A1F8EAD0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3A2B9D7F86CA3D05ULL,
		0xD483D899EAC07D8CULL,
		0x6AEBC4968D0E2DECULL,
		0x7A083DA2EE8EF3B7ULL,
		0x53BFD5B2124CA55DULL,
		0x55161AFDD33CCEF0ULL,
		0x2898359971163031ULL,
		0xC38AC1BDFEC6DC0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8845CD8CCB9A48E3ULL,
		0xB6EC4C0663F8DACDULL,
		0xDD0A91CAA11F18AEULL,
		0xE646CDFD0BA985A1ULL,
		0xDE6B143E193D2DF2ULL,
		0x3281BC2EE4E24F84ULL,
		0x3CFAABB0E78042CAULL,
		0x2739311D32134C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x48F0EBD683E506FEULL,
		0x3A551AD3C5360BA8ULL,
		0x7B5D52F992EC099BULL,
		0x0D300E893AE0739BULL,
		0x78DC4B92B925968CULL,
		0x8FFAA62F9BCC5625ULL,
		0x76A7CFD63AB09782ULL,
		0x842AFA215E997130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF01BB6E568456907ULL,
		0x33B15CBA79769468ULL,
		0xAC10A473CCD477ADULL,
		0xEAEE156CE70373E3ULL,
		0xCA0AE77A0517B7E2ULL,
		0x95F4AFEC9815C907ULL,
		0xC168989F388709EFULL,
		0xC3E9B4545D27FBFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x359F12D8C6643EBAULL,
		0xB87D3D9F1AEC0F2EULL,
		0x03F8D469A1BA4B25ULL,
		0x9CD8275D47229805ULL,
		0xBD7A53AE25E1FFDBULL,
		0x898594546F1476E9ULL,
		0x119E65B5D50BA4F2ULL,
		0xF54527AA62E04562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9F859580F34641EAULL,
		0x220052FCD7B23173ULL,
		0x89AB930F7AB005A0ULL,
		0x54439F2F31FEF6CEULL,
		0x951BB9F29555C96EULL,
		0x6E3BC73B532C2D05ULL,
		0x1A286F428A0B7AC7ULL,
		0x5C4899908FB6459DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDF7BEEBDFBE9CEE0ULL,
		0xA0164AA3A3DB34CDULL,
		0xD22D39F7909C5D63ULL,
		0x19E3591F6B148E55ULL,
		0x6BA052832FAA766AULL,
		0x323E6EC6BC365EC5ULL,
		0x3868C669242BFD5DULL,
		0x5E4EA3B60E06F838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEAAF9EA6100F1898ULL,
		0x0285314A8424D4F3ULL,
		0xF412B930AC628823ULL,
		0xE34E23EC661D0443ULL,
		0x919D5957636D0782ULL,
		0xC0811D652251B0BFULL,
		0x43258A0BB82EC196ULL,
		0xAB672A1E73D35FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBB1726F142848DC9ULL,
		0x300DF004A5AEEFA1ULL,
		0x7118980B7FD996B7ULL,
		0x4FA3C71190431E07ULL,
		0x0EC074A3832B83F1ULL,
		0x282B3EB7A5D216FAULL,
		0x74021AF8745A7E6EULL,
		0xA1EAC490C529A72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7CED6A74D972935CULL,
		0x2B6D19710F340BEBULL,
		0xE76C506A12F1A204ULL,
		0x7242AD0113005442ULL,
		0x7CDF2FB7C1EE37B0ULL,
		0x9CCE9050E9E7574FULL,
		0x6BBA498295831B50ULL,
		0x40B06505F8415A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD6101F72FB13243BULL,
		0x3E737ACE03B6592CULL,
		0xB55828D72A41609BULL,
		0x30941C85AE5CFE3CULL,
		0xEF3748BB7D74852CULL,
		0x583B4A68DF9C62BEULL,
		0xA3575A4947F94CF7ULL,
		0x426A7D82AC3DCF39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF6AF6B5015057698ULL,
		0xD208BF484D6AC063ULL,
		0xC329D444FD12E387ULL,
		0xC22C83F4637CA58DULL,
		0x09F12FA3F8B69FA1ULL,
		0xA668A7B17280B622ULL,
		0xFF7B860375400979ULL,
		0x9749399262A43C20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x79EDFC0CD7D2CBCFULL,
		0xE97DA3D715FA2F85ULL,
		0x8E9AF48E292B7825ULL,
		0x2ED1CA255B624343ULL,
		0x05639E63FC0A51E8ULL,
		0x5CB3E7248A9939E4ULL,
		0x792808D52635F9A0ULL,
		0x1C4ED2FAF9CA052CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5EBD048DDA99A6BFULL,
		0x70EC86AB817557EAULL,
		0x0D2E635C9092B460ULL,
		0x8436333853FC86F3ULL,
		0x482B8C3235BF7820ULL,
		0x19FFDF331926FF1FULL,
		0x1602DBFAE0E44558ULL,
		0x6BDAC7259F0D3424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3FDF25008D285BE9ULL,
		0x926B453AAD104D23ULL,
		0x1580C5B41E5809B6ULL,
		0xD3463AA4AC376768ULL,
		0xAF186662DB7A5027ULL,
		0x6B6A5DC8A61F79AFULL,
		0x739BFCFA491A9A19ULL,
		0xD4D974EF505A6E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x91DA7E690B0E9F97ULL,
		0x49BF08C2620D35D7ULL,
		0xF6EF5F3AF52AD40BULL,
		0x73588027D9F7C27DULL,
		0x005E96D5EA2F6267ULL,
		0x7A3D3C1F93EF9138ULL,
		0x910E8B667EAD2909ULL,
		0xE635B40C9B3CB09FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x173381C725544872ULL,
		0x96F23569E7D4D441ULL,
		0x99EDF714F10C30D4ULL,
		0x8A36481C657C9147ULL,
		0xB2D2CD6F2C954660ULL,
		0x190D5BDDF9D00B9DULL,
		0xAB5CE29FFBDD1FFAULL,
		0x5353590BA3A63FBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8D6B42AECC9AF525ULL,
		0x5E88852753AAF5AFULL,
		0xF1D0DDCC948E2F84ULL,
		0x22A3B46892057BF4ULL,
		0xD974EEB12833AB48ULL,
		0x7337B28952996FA2ULL,
		0xFF7068C12D5452DBULL,
		0x2C490E454C5A8AF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC9D0B6D259348638ULL,
		0x395DC49850B97696ULL,
		0x8C95A83A87BD02AAULL,
		0x50B44E67D84CA9C1ULL,
		0xADCAC901008CB51EULL,
		0xACE9BAEC26BB5469ULL,
		0x2761FA7EFE553F57ULL,
		0x21685353FAD0E3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D6B4AB9CC115AFULL,
		0xC86A7D024A5CB0DAULL,
		0xD0CC81234125783FULL,
		0x321C3F5D46C0D4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
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