#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x1804433803F5849DULL,
		0x7B620FB7F09AC686ULL,
		0x4F4E11E0D9B0E9DAULL,
		0xE039313F2A2F32C7ULL,
		0x3FF39E6AF5E80340ULL,
		0x1A15D8AFE269F918ULL,
		0xB47DDCECB427C5C1ULL,
		0xF3C5136D91D6221CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x962DC7188466059BULL,
		0x5AA039D38C55C01FULL,
		0x19FCDD0397984484ULL,
		0x0F7A1382CFF8430AULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD08119936A9BE8E7ULL,
		0x5DE9FDBA391D34ECULL,
		0xB61E9B3D3A987417ULL,
		0x396296188100C231ULL,
		0x3B0F898D13D8A1D7ULL,
		0xF62AE622F101B1E1ULL,
		0xDC0CC66374B1E432ULL,
		0x6DC06EE96C5ED464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94CF84845CC3F144ULL,
		0xE84826E9FF5D9C5BULL,
		0x60040E008D0053A7ULL,
		0x03F30CBE9714492AULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF71162BAF0F1DA8FULL,
		0xC1F41240D4694F8AULL,
		0xCFF2648A88B3E6E4ULL,
		0x6986AA0B56FECD9BULL,
		0xEF28378C25BE4804ULL,
		0x9DFFB9AA24C1B94DULL,
		0x2318F71FF49DBD95ULL,
		0x17D6EA1DA6EF72C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7709A1888B308BACULL,
		0x35E9A182492AD11CULL,
		0x05A71348D81E0B1AULL,
		0x736D6A721E89D66DULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2DACB7272E4628AULL,
		0x758A27C92C216DE5ULL,
		0x54E124D30052273AULL,
		0xBDC1B19AC930005EULL,
		0x98DA44EDD277DF13ULL,
		0x08D51B2117F830EEULL,
		0xF0DF4303C1586BBDULL,
		0x7DF79441E4CC6C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x534106BFB0AF822EULL,
		0xC52C2EB2BAF8B150ULL,
		0x16051761B3722549ULL,
		0x7081B362BF88188AULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A27D3338D86D7ABULL,
		0x15992A54AC882746ULL,
		0xF547F67F96201F3EULL,
		0x3ED317BA13581D68ULL,
		0x8D3BD249369EEDF2ULL,
		0x5C979AB750A57666ULL,
		0xB223FC27FE4AFF22ULL,
		0x27ED2357AD1C2483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01090A11A91E2A7BULL,
		0xD41A218AA517BA7FULL,
		0x669F646F5541FE57ULL,
		0x2C0656BDC58588F5ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1541AEAA80B10AF0ULL,
		0xF16002D1B5DA9B4AULL,
		0x8B20259D08B57603ULL,
		0xA6AC0DEC5C96C1E7ULL,
		0x3B62E86E7720CDCCULL,
		0x2AA22FD935B0C78BULL,
		0x891B81508F5E194EULL,
		0xD4A00433C211BB10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F02F102F8F9BF8ULL,
		0x45731D0FAE1839F4ULL,
		0xE535579250AD379EULL,
		0x366CAD9B2B38865BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81070B02509A11C9ULL,
		0x7C0981BDFD20BB50ULL,
		0x3BDFA58252EB674FULL,
		0x906B4A31ED9E76BFULL,
		0xAFDB5B4E8EFE1232ULL,
		0x73B26603DC26739DULL,
		0x631C2083B32F889FULL,
		0x578C6AE4FE9B6B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B9698AB8A50C736ULL,
		0xA884A650AAD5E4B8ULL,
		0xF20C790EEBF9AEFAULL,
		0x0F43282FB8B05919ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23650113D061928FULL,
		0x5A2DE06EC7994B82ULL,
		0xD9F964180776A9BBULL,
		0xBF9B3B6E8787D1F2ULL,
		0xEF7B2EE6BA8B7358ULL,
		0x6AC0976E3AAAB2DEULL,
		0xD1CBF79194F619CAULL,
		0x4EC971CD583A754FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFADF7538114B367ULL,
		0x32C45ACB7CEFD899ULL,
		0xFE4023B423FE7DC7ULL,
		0x71821FE9A0353BCBULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F2352A4CC5AB04FULL,
		0x70A8984814FF1325ULL,
		0xDA83B6E89FE50F89ULL,
		0x8DA855AB7FC3F4DCULL,
		0xA1006C7E4121B9D0ULL,
		0xAA5E159FD106CC14ULL,
		0xED85B68D32938752ULL,
		0x7DE78119C123B5C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55336D62775C4801ULL,
		0xBA9FCE011C015E35ULL,
		0x1C5CCFDE21CB25CEULL,
		0x3E057F7E2B10F064ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17924FECB51FEF39ULL,
		0xBAE090E30DA6BABAULL,
		0x74062D72E1A6E9A1ULL,
		0x57E9A0CD383EFB7FULL,
		0x89163E5E7BF1832DULL,
		0x081E75840A9628CCULL,
		0x7E6805A69012E73AULL,
		0xABE6F9A33862EB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70DF91F31AF96BB0ULL,
		0xEF66027C9FF0C916ULL,
		0x3777042C44753C3EULL,
		0x5C32AF0796EDF494ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CFCA2547794D3A5ULL,
		0xCEAD9CDCCE6A3E87ULL,
		0x30B7050579EA7FE0ULL,
		0x69625FCE006CC2ADULL,
		0x78A12AADD98CC20CULL,
		0x10A61037D56ADCA8ULL,
		0x07B1F640EF9DF5AAULL,
		0x3100D7C5126DC5A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E8F822C279A28AULL,
		0x475405267C46FF89ULL,
		0x552192A90B5CF71FULL,
		0x2F82670EBCB81894ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD30EE0476749165ULL,
		0xCD7942A5EC5CC9DCULL,
		0x0337B60E6D21C013ULL,
		0x9745C14F640CC300ULL,
		0x8DCCA1C9AE2B6383ULL,
		0x9DF92C5CC59024CEULL,
		0x839CE913282A728AULL,
		0x303F87B88AA96A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0990F1F450E557F4ULL,
		0x4075D86B3FC24086ULL,
		0x8C824EE6636EC0A7ULL,
		0x40B3E6B3F93280B5ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28F898326C9DE39DULL,
		0xDD5A3B3F2F149821ULL,
		0x6ED2224420AC0556ULL,
		0x4444716490303E6BULL,
		0x5B160D46BBEE454CULL,
		0x6B7F4CC1544860A7ULL,
		0x3D55E71C251BA833ULL,
		0x4717FAC3211BA172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE3E90B251FC2E74ULL,
		0xD23F9FF1B1D2F0F8ULL,
		0x89927071A2C6FCF8ULL,
		0x51D3AA5B7A4A3560ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58CC13480F9A474EULL,
		0xF2D491A7FC2A385AULL,
		0xFC7E7EA09783D9BDULL,
		0xC9E51D20609F2F56ULL,
		0xADC5EB4C44B96AE5ULL,
		0x43397F8B5C8144DAULL,
		0x070770FE6175C284ULL,
		0x82D6213357F53D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242D009A43202844ULL,
		0xED5D8057B75A70D0ULL,
		0x079944630EFEB95FULL,
		0x35AE0ABF6F064B4CULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0F41AF2F690BA6EULL,
		0x8CDA63D40A201BF4ULL,
		0x5792E30AE0E4C7CBULL,
		0x20EB7F024CF08135ULL,
		0x806AC10508C8766AULL,
		0xD0F04C770E447CA7ULL,
		0x7242F20AE3E969D4ULL,
		0x71143296B773F95DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0CCC1B24452509DULL,
		0x9085BD80284A9CD1ULL,
		0x4D82D0A8B58A7D62ULL,
		0x69EB016188278514ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9644C111AC106EC8ULL,
		0x5BBB081F53C81F93ULL,
		0x4F7AF0A2A4DED1D8ULL,
		0xDE4E41F6831F26E7ULL,
		0x0AC4908AA7E86500ULL,
		0xE7E8F4F694354743ULL,
		0x7CC1E026999A61BCULL,
		0x6DAF0FEE7A250C80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F7235A6988F6F4EULL,
		0xC84F64B953B0B387ULL,
		0xD442365D71C953E2ULL,
		0x264A9F5CA49F01F9ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02C776E3E54351CAULL,
		0xC89808316DED74C6ULL,
		0xBFB1B5168E512EE1ULL,
		0x290D8F4E0F161FF1ULL,
		0xE1800F832131B6CDULL,
		0xF08E07E567123073ULL,
		0xF3476277D75F2E04ULL,
		0x580D6EC937C18E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BC9C45AD2A47626ULL,
		0x7DAD343EBAA0A5F9ULL,
		0xDC4A52E08672039DULL,
		0x3B0C012C55D13E53ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x577D521F694FD798ULL,
		0x82EB2191A545CC0EULL,
		0x3544F01C8821C9ECULL,
		0x8768192392D34348ULL,
		0xEDF539D70586A92FULL,
		0x7464309572F7F46CULL,
		0xA038CD80BCCAC5D4ULL,
		0x64C012D3C0A2DB4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E3E80A3B4CF6CCULL,
		0xC9CA57C0B6141439ULL,
		0xFDB371388E3B2775ULL,
		0x7BEAE4922AFFD0A7ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8295975401E66415ULL,
		0x3FCA170C4DF3D190ULL,
		0x81B75E8F687DABD4ULL,
		0x977AC7E6990D5AACULL,
		0x80B0C5DB975A8DDAULL,
		0x2AE74005CBD302AEULL,
		0x7CB5C8485D54B486ULL,
		0x39C5BF55BAAB4B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CD2F5EC795773C7ULL,
		0x9E1D97E88F463777ULL,
		0x04B3194D431077BEULL,
		0x2AD52EA04E7A8D39ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE102907E7FF26C8BULL,
		0x9F39CC3A53BCC741ULL,
		0x200732412A22D5B0ULL,
		0x0FE67AAE3E731B7BULL,
		0xAA2B6253EB585F51ULL,
		0x5467ECD25CF71F0DULL,
		0xE034B5B89026B7A6ULL,
		0x4E7D7DCB9037B68BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x237328F36F109446ULL,
		0x26A6F374206B6349ULL,
		0x67DA2BA68FE21861ULL,
		0x368726E5A6B8343EULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C7A96407AE77D88ULL,
		0x1FCBD3A76FF58E6AULL,
		0x01DB1F5BB526C5E3ULL,
		0xE83B00A06A5973B6ULL,
		0x42D1826EA960799CULL,
		0x18848F1C014F0D50ULL,
		0x919894A517F79677ULL,
		0x176F387B78998E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3793F2AD9F398B48ULL,
		0xC37911CFA1B18854ULL,
		0x9E812FDD43E71B90ULL,
		0x62BD62F4512499C1ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6D366CDB8A3A8D5ULL,
		0x39583F045554B41AULL,
		0x6266E2F7285BCCF4ULL,
		0x44A893E8690B9273ULL,
		0x521208C6CEB5D06DULL,
		0x111E2881386DCC3AULL,
		0x41B90270A61D9B82ULL,
		0xEA4C0D98F9618AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0580B45067A09E35ULL,
		0xC3D24232B5A104C3ULL,
		0x23DD3FAFD0C0E242ULL,
		0x0BF2989D6D8632DBULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F74222EB67BE57ULL,
		0xBACB3A09088082B0ULL,
		0xEE646C87891AB582ULL,
		0x30D4D1DB76083E3DULL,
		0x4BB365866A7EE845ULL,
		0xB1BAEDBFA8E557F1ULL,
		0x0523C0C22F5F1EFCULL,
		0xF7898A134153663DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0985416BA3E3E00ULL,
		0x1C8A847C1A8B9081ULL,
		0xB1B3095A91394F05ULL,
		0x6F3F50B728696B4CULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A32127C31F544CDULL,
		0x979975E83A847049ULL,
		0xB27B2DD4ED5EA91FULL,
		0x7FADCAC3609B73C9ULL,
		0x7CBE619417837C68ULL,
		0x9ECD90F5D718E7FAULL,
		0x4D04567407ED2D34ULL,
		0xF67E628F4DEF1F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE748E77AF79C1BBULL,
		0x2A1CFA662836DF77ULL,
		0x2120030E1A935EEFULL,
		0x16706C08F21A0DFBULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x928978A905DF9795ULL,
		0xA27B32664C23D96BULL,
		0xC97A3FAFD93E7019ULL,
		0x9F7637CCD4228A8EULL,
		0x86728DD6DA395186ULL,
		0x17953179E960FED0ULL,
		0x2F498038B4CB79E7ULL,
		0x6632F1B1DD20A09CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x878A868D6A61B3C6ULL,
		0x22A08A7EF089AC5FULL,
		0xCE63481AAF728867ULL,
		0x4B061833A6FA61BDULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71004D3A2CBA7163ULL,
		0x5EF152B0F381114CULL,
		0x8804D593E6BBDAFFULL,
		0x57A43F16C785D14AULL,
		0xCA194296E6C43ADFULL,
		0x3235E480E4CCC894ULL,
		0xB29E4EBD07560DC0ULL,
		0xAC2D98BF3026D799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C02FA06DDB3246ULL,
		0xD2F13DD2E9E6D762ULL,
		0x0B8485A2FD81E586ULL,
		0x6668EB77ED49D21BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF247EA751B188A69ULL,
		0xD40E9D109859CC21ULL,
		0x8043D15B14F8AD45ULL,
		0x37666F1917FFB958ULL,
		0xCCDAF30104C71768ULL,
		0xA37F56EF4F5127E1ULL,
		0x106AA04487279FCBULL,
		0xD2BEFCED362E0F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC7FC9BD0A60873ULL,
		0x18F584965E65B7A6ULL,
		0xF0179B8724DA6580ULL,
		0x7FBFFA4F22D6014EULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12B960AE253A1FFFULL,
		0x4B4F06E06C165B8EULL,
		0xA32EDD5143C5C230ULL,
		0xF107D277F49798CDULL,
		0xB5549C0AE51316C4ULL,
		0x2F4E86C9EC021EB8ULL,
		0xDAFE37788E42B51FULL,
		0xDB46732A2A5BE54AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD488A4C260F85FDULL,
		0x50F708D97466EAF8ULL,
		0x24EB193661ACA4D1ULL,
		0x7D7CEABA3E3BA1EAULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x739BC425EB4431BBULL,
		0x3F7DF4EC7DEABECAULL,
		0xCD04F537F792C3A9ULL,
		0x3747ED1EF3A0656AULL,
		0x11CE180F9794D371ULL,
		0x96E7EBC8D8102132ULL,
		0x0E2E6F6EE13566E1ULL,
		0xC81D0712A90365E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x183356766B5B98E2ULL,
		0xA5EAF4BC904FAC39ULL,
		0xE7E97FAD65800925ULL,
		0x6B96F9E40A2184D2ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D2340E4AFDDF79CULL,
		0x335513FABD06AD33ULL,
		0xDCE6B2B622D50BF7ULL,
		0xB11E00890055891EULL,
		0xA06263B0946DDCA3ULL,
		0xBDA6636235BE67ABULL,
		0xB4926B10C531B3E5ULL,
		0x7A5D1F6F9CDA2A02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBBE0D1AB82CBA8DULL,
		0x5A07D48EB74A10ACULL,
		0xAAA297336835C011ULL,
		0x5AF0AB1A48B7C585ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04E6B761461ADE0AULL,
		0x7CCE3CCB89BE915AULL,
		0xC50784081A7F6A9CULL,
		0x1D95B95E12AE48CCULL,
		0x111550C721C93BF1ULL,
		0x925B20E42E75A089ULL,
		0x209DD45B95A6F620ULL,
		0x2690BFEEBBA07F4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E10B4F049F9C4A1ULL,
		0x36551EAA6F3465B2ULL,
		0x9C7509A05147F372ULL,
		0x571236CDEC812E19ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE64EC7FB12FD7322ULL,
		0xD02BCDB4B0248D9EULL,
		0xAD620FD84C241737ULL,
		0x597AA8370D029DEBULL,
		0x38A90BA5B6528F06ULL,
		0xB40D052E1B78CD9BULL,
		0x806B6C6F04A7C5F4ULL,
		0x6264616DE75527BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F668294233EB02DULL,
		0x8A1A928CC41312A9ULL,
		0xBD542852FD0B798AULL,
		0x74611E8763A683E6ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x719FCAD2265D82CDULL,
		0x1759EAB32C6293F3ULL,
		0x9136DFEE157404EFULL,
		0x5E5B910FB41FD8ADULL,
		0xB18CC2B4E8BF202AULL,
		0x0C4B45635A0A5C32ULL,
		0xB6159CD04F8F2554ULL,
		0xB03D97A33791F7A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC84B1ACB2BC4CF8ULL,
		0xEA86377289EC4379ULL,
		0x986C26D9E4B38F68ULL,
		0x07801349F3CA9AD4ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD83BF2DEF3FD4B56ULL,
		0xA2ED3CFA7C7E758FULL,
		0x0C0CE10DB2B92A50ULL,
		0x5E923C35079A69BDULL,
		0xBF4C903D1A13AE29ULL,
		0xEEF39D34067BE642ULL,
		0xB682546BFEB604F3ULL,
		0x216BE6E1F7F7791FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D995BF0D2E9262AULL,
		0x1B1692B372E2A378ULL,
		0x2365691581BDE686ULL,
		0x549681BFD6566472ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6909EA793475B92ULL,
		0x9233D31A4E476FFBULL,
		0x279CC54CD2FB3480ULL,
		0x8189771256512BB9ULL,
		0x22BCF9189C8972A7ULL,
		0x9E67ACB95ED2C335ULL,
		0xFAF63E69B06C2175ULL,
		0x35B7D3A5DB1B9385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9D984ECFAE618CULL,
		0x1597769E619069DFULL,
		0x682A08FD03082BF6ULL,
		0x7AD2E1B0DC69119CULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70697FDB416C538CULL,
		0x468EF640F189983CULL,
		0x207E419172C0DAD2ULL,
		0x45A8471738C14D45ULL,
		0x550E5BB7FEA08749ULL,
		0x7DDB9500F9F9B5E5ULL,
		0x4101B7FE859FA4D6ULL,
		0x89226139E4DC2F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108B1D2B0D406B6DULL,
		0xF52714660C9A9847ULL,
		0xC6BF9159487352A8ULL,
		0x20C2B5AF31705730ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02BC2E54CB73ADA9ULL,
		0x6086C43860A4241DULL,
		0x47F64BCA076A390AULL,
		0xB41A0E5B475A7714ULL,
		0xA0EC25BC172F2342ULL,
		0x0F01EC0093A0FE8BULL,
		0x23D325B0C54D7EF2ULL,
		0x648014D970E7FF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C9C8403C72EBC2ULL,
		0x9ACFCC4E4A89ECD6ULL,
		0x994DE40750EB10F8ULL,
		0x1F1D26A209CA5541ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF520077A052BD50ULL,
		0x5BB545883F8E5143ULL,
		0xE645439260E83414ULL,
		0x63B81168FA3DC8B9ULL,
		0x9A1D440C2529CCB3ULL,
		0x38DF86C5D0BC51D5ULL,
		0x30725903639FB1BCULL,
		0xF01B07A3AFDBA727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFAA1A452487253AULL,
		0xCCE346E53B8276F8ULL,
		0x173E7A132A9C9604ULL,
		0x07BB33B514D8988BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x592A8CC09189A080ULL,
		0x5ACE3A2C0BC0F6F1ULL,
		0x686DCDC3AF11740FULL,
		0x3B108BE82BE5DAB2ULL,
		0xEB976713933614EEULL,
		0x25404E6C34A44C27ULL,
		0xF7F1CEB6A01E10EAULL,
		0x14865E8DBB132B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A3D9A86B90BC46ULL,
		0xE259DE3BDC2444DEULL,
		0x36527CDF7387F6D0ULL,
		0x470294F1F0BE4AA5ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EEFD93F69D80A09ULL,
		0x632D60DDA652B0DEULL,
		0x998A53A1457B6DFDULL,
		0x4409E1CE4DF3BEA8ULL,
		0x04F161D633205611ULL,
		0x3955C95FF14B2471ULL,
		0xF2B7F67E1FE40699ULL,
		0xDC2427351A77C917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AC45F0B00A4D562ULL,
		0xE5E9451B777A19A5ULL,
		0xA0D8EA5A015468BBULL,
		0x7167B3B03BBB9836ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x895DB91BDD2F5A01ULL,
		0x35FD65816F44B84CULL,
		0x32627E9ECB0346B0ULL,
		0x25249BE21715F1F6ULL,
		0x66EAFEC4B7254EA5ULL,
		0x7C7F65006AF17DA8ULL,
		0xED07C144D1ECD4FCULL,
		0xDD94A3B7D63CE07AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD03F8A4F0CB90B65ULL,
		0xB0E663914F1D5F4BULL,
		0x61892ED5F42AE42AULL,
		0x0934E92BE41F4435ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9A370BC6B2299E0ULL,
		0x927C35032A51FE88ULL,
		0x85D204EDA502EE32ULL,
		0x134D5B2EFB646A5FULL,
		0x75C25DE6E5660E29ULL,
		0x769E0BB7357F3943ULL,
		0x6C643A14785151AEULL,
		0x07E951E569B04DCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x747D61027848B41CULL,
		0x2DF1F2351B347E8CULL,
		0x9CB2A3F781150E18ULL,
		0x3FEF833CAB8FF691ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7A5A343D120E61ULL,
		0xEA33BEB8C1FEB558ULL,
		0x113EB8768214ED3AULL,
		0xDDFD883C5750CC5BULL,
		0x7CC7CD72EE020D12ULL,
		0x8D42A0F18722088DULL,
		0x843B6957853ECFA9ULL,
		0x5BA9D7EAD9B37083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0522D94391600121ULL,
		0xE217A292D10BFA59ULL,
		0xB2105B744967C065ULL,
		0x79339518A7F37FE0ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CD396EED7660828ULL,
		0xFBB2D25CD7000E85ULL,
		0x6E4A2DF6347BEAA5ULL,
		0x12A897CBFAF7AC15ULL,
		0x46D9CD13580DDF86ULL,
		0xBDCC9A93A98BA4E5ULL,
		0x19031A667CA2B517ULL,
		0x175627121DFC226BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD12807CDE9753691ULL,
		0x2811C44801BA888DULL,
		0x24C0192CB4A2CC2CULL,
		0x0972647C6E64C7FBULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA50DA72020F3323CULL,
		0x5A116A9F88C73CCDULL,
		0x52A2293555F40086ULL,
		0x33DE09F61256D1C7ULL,
		0x7DBAFAF3C47BDA8CULL,
		0x69C030FF12CF0139ULL,
		0x7C6A14C47D75DFD4ULL,
		0x4402997E6BC8B784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECEE74F4B55A480ULL,
		0x0C98B07C53816B56ULL,
		0xCA613E5FF5733A0EULL,
		0x4C40D2BA12220F71ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x421C072FC4CC082EULL,
		0x75AA5B04B64C8C0FULL,
		0xEF4DC8A8F781BE3BULL,
		0x196D8EAA2E4BB8B0ULL,
		0x5A2B5A22A32B9816ULL,
		0xEA605F205EC75826ULL,
		0x9C03BA5EB3B3F108ULL,
		0xDC45F00E23887E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA48B6853FD44A045ULL,
		0x3FF879D2C7E3A1C0ULL,
		0x17DB72B7A437858EULL,
		0x4BCF30C3748E8190ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x691D7555863C4CD6ULL,
		0xF30DFA2AC86BA9DCULL,
		0xCCD2A25F2DA5B826ULL,
		0xE0DFEBF827B39984ULL,
		0x52727745E990D212ULL,
		0x242B10B43BF36E43ULL,
		0x7E00C199DB2EB464ULL,
		0x9016275E686AD094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA61B29B631BB7EC6ULL,
		0x517274EBAE8E07DAULL,
		0x80EF5F35B6947F04ULL,
		0x4429C3FBA78E8F8FULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B585EFC588A8C8ULL,
		0x2C09F4934001F11DULL,
		0xED24ED4FFCDA2BC2ULL,
		0xAC3F9D3D64012661ULL,
		0x7BBE3FDE0DD1CEE5ULL,
		0xBA853E77F63F499AULL,
		0x2DA49ABBF69D3DBFULL,
		0xBACCE952C8AA4392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F300E5D2AD62EEULL,
		0xDBD13A61CD66DE0BULL,
		0xB393E53698315637ULL,
		0x66AA3F872D472E14ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB75A75F57469C57ULL,
		0xF38B8E0CD2F264A3ULL,
		0x27E4532BF5D86FC5ULL,
		0xC20DAA1505BA41A3ULL,
		0x1088177B26C9EFD4ULL,
		0xA17551C7AC7E076EULL,
		0x80A413E0098FF3CAULL,
		0x6D03B44719FF653BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA923A719403842ULL,
		0xEAF5B1B06DA77EFAULL,
		0x403F466D61369FD9ULL,
		0x709A6CA2E1A34878ULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36261E4D62F03A1DULL,
		0xC4752687B0965896ULL,
		0x66FAF13B71276655ULL,
		0xF6F86D62C4D2919CULL,
		0x5F25898C020FD20FULL,
		0x16456B1689367BBFULL,
		0xEC24C9C60140093BULL,
		0x092C28CF78DF6D8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55B88915B14968A3ULL,
		0x12C30BE00EACB6FEULL,
		0x7470E49FA0A8C51BULL,
		0x53867C2EB5FCD43BULL,
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
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C3DA5BF44A98E30ULL,
		0xC5853779207D7A1AULL,
		0x46C8604794E7C063ULL,
		0x46F5AD29F561368EULL,
		0x6A7DCB410744363BULL,
		0x8E98196FCFA4DDA5ULL,
		0xE959996CCF2527B4ULL,
		0xBA45B1ED9F4E9541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE9D16658C99F07ULL,
		0xF018FE11F2F660A8ULL,
		0xEA15266E546BA530ULL,
		0x6D4E166F9B0B5E56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA0E32EA61C11B70FULL,
		0xDF13D97EE828DCCEULL,
		0xFAC554E241129E56ULL,
		0x83E074CDBC9A7139ULL,
		0x52B3404947BBF3A5ULL,
		0xEB8687ABAA4558D1ULL,
		0x51093D6B3B0A7D64ULL,
		0x5B6D609D1930EFF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE77EB986C1F7E3A1ULL,
		0xD50BFCFA2E740BE0ULL,
		0x022472CD04A13B51ULL,
		0x161CCC1F79DE0F7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBD42F429A24003F2ULL,
		0x8AE76D35B31F056BULL,
		0xE084FE91EF771901ULL,
		0x13A0634F37BD17D5ULL,
		0x9456F56ABAAA342CULL,
		0xFE92F6ABE98779AFULL,
		0xD134E9D2AC4676F1ULL,
		0x1899D8E781D2060BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC22B62015783C2FFULL,
		0x54B80ABA5D3B157BULL,
		0xEE5FB3D781ECC0EDULL,
		0x3A7695AC7CE9FD96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2E938ACA177D297BULL,
		0x1173C213CA0371DDULL,
		0x9712D5CABE787AA4ULL,
		0x789C99E1A05372D7ULL,
		0xA086F7EEB45A4D9AULL,
		0xDF1A594194A40C49ULL,
		0xC6F516D75989F00CULL,
		0xDE5AB0596D260AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x029C5838DCE4B33DULL,
		0x2F5D01CFDA5D44CBULL,
		0x1F7439C208F21C8DULL,
		0x7A12C727D3F90727ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x341E6A34E495A1B6ULL,
		0xDC933FD9D2C862FFULL,
		0xAF43035DB3C24E4BULL,
		0x3806B5C5595B7CDAULL,
		0x895E76C3A57C3E84ULL,
		0x2893EB6CB0EB9917ULL,
		0x2F6C10C235FD500AULL,
		0xC73494CE9B09D7DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98240B3F7506EDAFULL,
		0xE28831FC15C11C7DULL,
		0xB94D8031B75C2FCDULL,
		0x49D4CC705CD187FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDBFD1994D727B52CULL,
		0x2F8AA679768FB1BAULL,
		0xD1C2163F7C25A020ULL,
		0xD007F93A5A5C7184ULL,
		0xCB95EA31417A76F6ULL,
		0xA027C6505FF92460ULL,
		0xB40D40CCA21D3B8BULL,
		0x7724E4561FFA9D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143DDCE48F55605CULL,
		0xF5721667B58B1819ULL,
		0x8BB9B49F8C7C76D9ULL,
		0x7F81DE03198FC141ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5D77C7957CFAEDD3ULL,
		0x9A01AB577744A59BULL,
		0xB9326595B864B15CULL,
		0x7BA343B929A18E60ULL,
		0x3CB5368A25BC1C83ULL,
		0x5F33B8E4346B10D6ULL,
		0x6E5FCB29B9053A0CULL,
		0xBDC33FE99448FB82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605DE01716E72D80ULL,
		0xBBAF1D373F292568ULL,
		0x1B6A8DC72F2B4F32ULL,
		0x269EC0652C76E3BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE0CBA6ABB27DE37EULL,
		0x3D876FFC762C383DULL,
		0x2662402348E21013ULL,
		0xA57D9BE2012444ACULL,
		0x7045D75D4A4F0BCCULL,
		0xAB7C333A2CEBC54CULL,
		0x926F49BEFF3DA4D1ULL,
		0xA19EC623A698D89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B299E84BA39A769ULL,
		0xB1F70A9F212B8196ULL,
		0xE2E7327D2C088732ULL,
		0x230F052CBBD46C0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE8FCCA35DBFAA60EULL,
		0x39CBC2A73FC5A5CCULL,
		0x658841648D1BF54CULL,
		0x64B6AA9C43BAF0D7ULL,
		0xACA37662B196749DULL,
		0xF8A9D5AFEA3793A9ULL,
		0xB39A14E687301A82ULL,
		0x6D8A0633CEE1BB1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89405CDC384FF7CFULL,
		0x23017AC4040590FCULL,
		0x0E675B9C9E3FE4BDULL,
		0x2733964CF93CB740ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x47E8E6CE592DDFF3ULL,
		0x559D70AF454A4646ULL,
		0x2E7A56920AF5268AULL,
		0x1D18DC7F5F4CE56AULL,
		0xA6A1A98207710F4AULL,
		0x8E083A1BF0189D29ULL,
		0x576972EB42AF14A2ULL,
		0x32670F43F5F27B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E8101B73F6260CULL,
		0x6AD610D4E8F19A75ULL,
		0x2821657DF0F236ABULL,
		0x18652095E14B3545ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB95B795F9CE66F9BULL,
		0x8ED1951C083A5C71ULL,
		0x7B586D489DD52CD0ULL,
		0x5560F2BE759E7F26ULL,
		0x3AAD5793D08E6EA0ULL,
		0x0938C7337EA3EB84ULL,
		0xB4DD4BD7B1EBC32CULL,
		0xAA444BF9295568AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F167950920ADF24ULL,
		0xED3F26C0D48F5212ULL,
		0x5431AF4D06D42559ULL,
		0x1B8439BA984C0915ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x80A95BA59F998A19ULL,
		0xC70347C1B2087C0DULL,
		0x0060BD1ABC4534D5ULL,
		0x9F217ED1F3BF0140ULL,
		0x7DCE3BBF3D253A7AULL,
		0xACAE04EF187E8485ULL,
		0xD716C2A426787DA3ULL,
		0x44D64C3CF54DAA3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D463A08B32039C4ULL,
		0x68D8033F54D027DEULL,
		0xEDC1A1787227DB21ULL,
		0x56F0CFDE5D46466DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x90C252FC66966346ULL,
		0x07DE041CA4594770ULL,
		0x3CDB66576317842BULL,
		0x90BBAA59BA6D3EE1ULL,
		0x3B032A13AEDA97B0ULL,
		0xE25C5956C295F559ULL,
		0xD147829DB990A7AEULL,
		0x00B8027678DC0C25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x533A91E85B08E779ULL,
		0xA19346FD869BB2AFULL,
		0x4D78C9C0EE906820ULL,
		0x2C0C07EFAB170C7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE40487B4D9A28B64ULL,
		0xD3B220E68A17E9B7ULL,
		0x655453A57D3D5633ULL,
		0x67239050DE520C46ULL,
		0x6162FAB4B1218268ULL,
		0x7840A6FFDF900D3FULL,
		0x252CBB1A5E4CE1EAULL,
		0x039E05EAB9F319A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58B5BE87249BE6E7ULL,
		0xAD4AEAE1B979E120ULL,
		0xE9F8198F7CA6DF01ULL,
		0x709871287867DAC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFB2CB2A0ABF0AC0EULL,
		0xF9CFF1C839D2123FULL,
		0xC9EFB8EB6FE47B49ULL,
		0x275361F045AFCA85ULL,
		0x86C9CE3EFDD0F289ULL,
		0xECE7FAD006C46863ULL,
		0x3339EB4A2BEEEEA8ULL,
		0xA87DA4BC9B047D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD214FFA58F4B01AULL,
		0x243F2CA93AF99105ULL,
		0x6488A5EDF55BE85DULL,
		0x29F9D5EF485A6F8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE69286A489F35334ULL,
		0xFE84321E18BCE99AULL,
		0xE9140B1247229F33ULL,
		0x5BE52787D100DB9AULL,
		0x052FE80E9A4D011BULL,
		0x3055E4961EC1E09DULL,
		0x2CFF6D5571F4DA7EULL,
		0x393B7AF062B4040FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAEF8CF71617E79ULL,
		0x2B442066A98440E9ULL,
		0x96FE45C1317B0DEFULL,
		0x5AB9673677B975DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEFCBF2CF424D8BBAULL,
		0xE6253E82EB1EEA58ULL,
		0x415B4647B88E3E5EULL,
		0xA04CFD0FD404555FULL,
		0x869F90080A53E94BULL,
		0x40DD957FB5E148D2ULL,
		0x36BA19C7E8576E00ULL,
		0x66A6197C955A472DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB7B5400CAC22F29ULL,
		0x87096F77EA8FB998ULL,
		0x60FB19F435889268ULL,
		0x5CF4C58DFF6AE615ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x55B30FCB1FBCF398ULL,
		0x7E1F7D4511D69EA4ULL,
		0x50B11B30516CEB8EULL,
		0xC228EEB3249EFB86ULL,
		0xEA1E265F067AE2AEULL,
		0xC5EBD7A005D68882ULL,
		0x1D0814FB19B523D9ULL,
		0xBF92CA362E9E4FA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x162CC1E615FA9DBAULL,
		0xDF217F05EFAEE213ULL,
		0x9FE4387622503DE1ULL,
		0x31F2F2BE101ECDBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBA4962C1F6C7D60DULL,
		0xF228A071CC3487DCULL,
		0x1D0720004033A171ULL,
		0x3A6D29B513EF2BE1ULL,
		0x05276FA7F34F8CC3ULL,
		0x94ECFBF4331FB1C6ULL,
		0x0D09FDF507827B6EULL,
		0x747346AFBB893356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E23F5B01496BD98ULL,
		0x0D5606B162E8EB41ULL,
		0x0C82D25F5D91F3DCULL,
		0x0389A7CAEA4CCAA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x48F402B3872CA0B7ULL,
		0xEE45F8FC1BE7CE06ULL,
		0x631BAB2C65514992ULL,
		0xBA3E9DEEEA3664CBULL,
		0x3341FB49A0B755EAULL,
		0x4B96B8E0B979A895ULL,
		0x9C978020787BE0BDULL,
		0xEFC90339F00799FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4BF4FA1626366CBULL,
		0x26A56A57A3F6D42BULL,
		0xA198AFFE47B4A5ACULL,
		0x521518888B574070ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF8ADB1D540901ADFULL,
		0x5AA5EBDB33FE643FULL,
		0xDB901C72037EE257ULL,
		0xE991D0E81E91384EULL,
		0xF5A178CB920FAC5DULL,
		0xAD7AC99CECBEDB28ULL,
		0xA44456E0499865F2ULL,
		0x174580B1A2B11337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA5A00CEEE3B145ULL,
		0x1ADFD9265852EC54ULL,
		0x3DB501BCF01E045DULL,
		0x5DE2EB4644DA1291ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4EBB998B970D1367ULL,
		0x99BB85D6E9DB7154ULL,
		0xF8745CB7FE154144ULL,
		0x7C2EB1626DB969B6ULL,
		0x2B87475C8464DF40ULL,
		0x706593DDE9D417B0ULL,
		0xDEC7C02DB4E59ED6ULL,
		0x466CAC584C79BE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D031473E063876ULL,
		0x48CF78C79F56F57AULL,
		0x0A1AE380D82AD519ULL,
		0x7050467DC7CBA486ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBA961B9F0C696D1EULL,
		0xE344C397E9F86E5AULL,
		0x2CC6A1E174839DADULL,
		0xA406F754D3BB7CFAULL,
		0x310A6A9567EAB2C2ULL,
		0xD195F1FB9A576660ULL,
		0x0E2C305E6B8FFEC5ULL,
		0x96C604D7B6C23DA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0221EDCC793FF954ULL,
		0xFF86AEF0D2F1A0A2ULL,
		0x4755CFE56BE36F0AULL,
		0x056BAF59F490A3ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2C1825169A35FA85ULL,
		0x1D0A962CF6C16BE3ULL,
		0x0CEE3730ABEB6612ULL,
		0x6088D797ED45A921ULL,
		0x5C225AF852797C89ULL,
		0x2204592020815E89ULL,
		0x85F2F77B1467B059ULL,
		0x21F3AD17DF51F129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD931A5F2D83E7799ULL,
		0x29AFD0F1C9F57446ULL,
		0xEEFEF375B34F934DULL,
		0x6AB48923136F754AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8C5BA298A7FA7A26ULL,
		0x5169F200B4F805D5ULL,
		0xFC57BD902018CF01ULL,
		0x8918B89A0F97767AULL,
		0x2924E9059B704F38ULL,
		0xE1CDEC6830623345ULL,
		0xAC57145E99E71457ULL,
		0x15728DB90BB24F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D6396DBAA63CFBULL,
		0xD5FB0977E38BA219ULL,
		0x9144C39AF865D40CULL,
		0x3819C211CC0F3554ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA99F8ECF5872AE08ULL,
		0x250D599DCBA119CCULL,
		0x074552BFDB0298DDULL,
		0x6D7A939E460CD625ULL,
		0x6305709F3275F69CULL,
		0xAFB9F14DB9ABF093ULL,
		0x4FA409A11DACE405ULL,
		0x766FA74DDC5F9726ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6E4670D5F54BDCULL,
		0x3AA72B275B26CFADULL,
		0xD99EC0AA42AC71B5ULL,
		0x020D692CFC3D45D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x68208A36895D8027ULL,
		0x4EA176DCAE927316ULL,
		0x003298F1D73D0B8BULL,
		0x9E9705F7057161F4ULL,
		0x8AC8A9FCFFA5E70DULL,
		0xFAE322D3F89D9DE0ULL,
		0x1CFE10EBC6F75A21ULL,
		0xD39392965F6577C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E9C5C47BFDD0D5ULL,
		0x8C58A25395F7E26BULL,
		0x4DE91BF15FF46C96ULL,
		0x067EC8492E8128EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x371445972D00D049ULL,
		0x5ACF81D3603809D9ULL,
		0x558506B62A362BD4ULL,
		0x83E18C1C691B05DAULL,
		0x345157C17E788615ULL,
		0x08127C5BEE0109CFULL,
		0x31BDF038037D9E5FULL,
		0xB3FDEF7953A8E8D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB274C4FF2E4BB69ULL,
		0x8D8DF778B45F7E9AULL,
		0xB7B6AF06AEDBADEFULL,
		0x3B93181ED42D9533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x90380FF2C1DA4265ULL,
		0x96B715CE92C84D7DULL,
		0x462B7B629711C38EULL,
		0x00D58CE0E455EA81ULL,
		0x1047AE6798F72458ULL,
		0xF3B57CE92116162DULL,
		0x00A23BF64FDBD89AULL,
		0x8834F53200F8C4C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADBF3537689AA6DULL,
		0xC3A7A0697C0F982DULL,
		0x5E4061F271B3EA8EULL,
		0x38B1F24D09432057ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x383C9492CABC498DULL,
		0x3EE6D8C9DB7BE4CBULL,
		0xF6C5D1948FE57133ULL,
		0x2EA16DE5F856723FULL,
		0xB0F2E025430BDAE3ULL,
		0xD37DB79D948A59DAULL,
		0x98CAF6A52D0F3E44ULL,
		0x67CDD664795C5D74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C49DA1ABE7EC98CULL,
		0xA3901A2DE8053B41ULL,
		0xA4E66E194028AF6AULL,
		0x172F40CFFC0C518EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x403626E89F81D3E0ULL,
		0x6C38BF1E12301DFCULL,
		0x05CDDA2F3C1145FCULL,
		0x4326924556BCE01AULL,
		0xAEA901B36D57488FULL,
		0x3C8AFAE91887DC35ULL,
		0xE5483EEB0CBCC346ULL,
		0x6ED8F338406C189CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D4C678ADA769B8DULL,
		0x68D9FDB7B65ACDF4ULL,
		0x0E87311320164269ULL,
		0x375AAC9EE6C88764ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0054493DF0EF7227ULL,
		0x45761B7C171ACA09ULL,
		0x082DB5DD50927CDFULL,
		0x040E14565E0C0F69ULL,
		0xC29CA7E4E532EFB1ULL,
		0x84268CCA9C9E25C7ULL,
		0xA2F61BFD70859095ULL,
		0x90A043241A0F40D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3953537F67F098BULL,
		0xE32F018F569465AFULL,
		0x38B5DD7C0465F310ULL,
		0x7BD80BB23C4FAFB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2605216714BDA0FBULL,
		0x2DB18A840BCDBD79ULL,
		0xF1D769F025729274ULL,
		0x34B9CC98AFD353B6ULL,
		0x2A7E364FE978FA0DULL,
		0xC5E9F9B58393253AULL,
		0xFA7B015C76FA218AULL,
		0xC879D590E039332BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74C13143BCB2C34AULL,
		0x8E6C9B7593A5441BULL,
		0x20199DA9CE938D0DULL,
		0x76CF8019F850EC3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8AC2583397F524BBULL,
		0xBD252D414135D133ULL,
		0x41A733F6E395A6ACULL,
		0x403504CB0032A1A1ULL,
		0x45A9AD69F053B870ULL,
		0x748255AA02BDA749ULL,
		0x7FFA920EDF1C6578ULL,
		0x1F9555C19BE7000AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1F215ED44628606ULL,
		0x087DE47DA95CA613ULL,
		0x40D8E22C01CCB68EULL,
		0x705FBF88247CA330ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8734B1FF71360DD5ULL,
		0x8014BFD348CD104FULL,
		0xA0AC04B32B67005AULL,
		0x3BE9D4555C1D324DULL,
		0x4305CD20762FB949ULL,
		0xA65536B9E5858D31ULL,
		0x6E2BD93AA9D821B3ULL,
		0x7F802A98A5354DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A1124D0FC4B917DULL,
		0x30BADF6B5AA0059FULL,
		0xFB2E4368617C0105ULL,
		0x28F026FDE206BCDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x51C046C1D6036C31ULL,
		0x9D316CC626DB77E2ULL,
		0xB3AAB7FCD5228F18ULL,
		0xE135FA7E6F92D532ULL,
		0x532A0EC4586EC454ULL,
		0x7D32A9821EC44887ULL,
		0x71B5A02644A117D9ULL,
		0xE47BAEA46C2D34EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9FE77E6F67495C8ULL,
		0x32B69616B7FE3BF8ULL,
		0x94A07DAB050C1961ULL,
		0x4B91E6E67E48B025ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2DCBE6C677DACFE2ULL,
		0xBAB977D045E1C27AULL,
		0x3EE2BC6CDB7D6966ULL,
		0x817D025AB8B702F2ULL,
		0x4DBE1178C0123345ULL,
		0xD8A8191E1AAEB05CULL,
		0xA931EB2CE413B6F3ULL,
		0x1A6012B40F7428BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8027EB2FA8E6CB8ULL,
		0xE3AD32483BCFF02DULL,
		0x5C4BA516B66A9198ULL,
		0x6BBFC91503F50EA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5E7E0A486F535109ULL,
		0x4E323F54C2452449ULL,
		0xFBA5599C1D13E5F4ULL,
		0x866952882A537331ULL,
		0x577B789F9129B8E4ULL,
		0xF826E68AF3C3FE41ULL,
		0xB5784E1C2A500EC0ULL,
		0x15A07C71BD7EC8BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD1F1F7FB84C366ULL,
		0x23F877F4F15CE1FCULL,
		0xEB80F1CA64F61699ULL,
		0x3C3BCB6A4B253F5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8CEED35F9BC75D5DULL,
		0x78612087E7B573CBULL,
		0x190956FD60B5ECA1ULL,
		0x1F09DDCA7130E778ULL,
		0xA1E20D9E19F67A9AULL,
		0x1B15C61D1A412ACFULL,
		0xCA2F2C01DD6FBCB0ULL,
		0xE34A54B87B68FE83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x947CD8D7765D9532ULL,
		0x7D9C88D9CD61CE9DULL,
		0x1C09DF443F4BEEC5ULL,
		0x5C12712CC2C6AF08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD68DE02DEC57FD06ULL,
		0xCA62F9E8B1BC2386ULL,
		0xA4F1273A0051144FULL,
		0xFCD8F25E74F763E0ULL,
		0x0E727755483EDC0EULL,
		0x2565916F048B518FULL,
		0xBDD08C44D652159EULL,
		0xA243E6724DBC5B72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8B96D6A5ACAAD0ULL,
		0x577690635E6A3EC2ULL,
		0xD1E5F971D08049C9ULL,
		0x12ED2755FEECF6E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x54D5222FDC208B8FULL,
		0x14A53199D5285441ULL,
		0x66104BF9299BCEF8ULL,
		0x1D972D8DCD5C5179ULL,
		0x6DDC07B661D233BBULL,
		0xF656606BB629D4B4ULL,
		0xDC038C1BCE56440FULL,
		0x609D3E8AAC9348A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA37E474261543B65ULL,
		0xA5778196DF5DE709ULL,
		0x0E971819CA69E956ULL,
		0x74EE76236B391A18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBF59B21A526EC7FAULL,
		0x9C0E586419D4B388ULL,
		0x443F540C7CC5CD72ULL,
		0xE298353CBD66C22AULL,
		0x8FA6395B55435378ULL,
		0xEE6621AB0843ABB3ULL,
		0x3B35127DC7039553ULL,
		0x3E67FB0277D349C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120635A8FA6D2D46ULL,
		0xFF3757C753E03030ULL,
		0x0E2012B8074DF7E7ULL,
		0x2607779A86C3B4FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x33BBF17089154725ULL,
		0x4525D00E32A51DC8ULL,
		0x5913C22A4440436BULL,
		0x929DD3AB6F3FCC86ULL,
		0x329246C94724904FULL,
		0xA542C1829A344992ULL,
		0x11EABF2EBFEA9BF0ULL,
		0xD340E27C09CE8519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB57273511882B78CULL,
		0xCD0E89711668097BULL,
		0x01EC231AC1136923ULL,
		0x6E3F7214E3E78E3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA495F7B4DBF68733ULL,
		0x30369FFB40458B59ULL,
		0x13EA97E0E33E3754ULL,
		0x89A8FAC4507EEF8DULL,
		0x1F9AF81A25C7EA1EULL,
		0xCF6DFF49CB50F43DULL,
		0x1CB43352AECD5B2FULL,
		0xDD15DB7027086D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5596CB9677A34C8DULL,
		0xFA8A84EF6E49CC6CULL,
		0x56AA3626D5B9C06CULL,
		0x5AE78D6A1BBF31C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8BA593867AF1F417ULL,
		0x4CA950FE36510547ULL,
		0x56525BAD7D060943ULL,
		0x410441ED71DD323AULL,
		0x123D0D752C080934ULL,
		0x1C589C4A009B41C6ULL,
		0xDEF5BD932D4B1325ULL,
		0xDFC742E7D0D02DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B592EB042356B5ULL,
		0x81D083FA4D5CC8AEULL,
		0x6ECC7F86362AE0C5ULL,
		0x7898305670C3FBD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA8A46E0B5173CB81ULL,
		0x6879BFA92608A76EULL,
		0xC2EA3D710CE4EEF4ULL,
		0xC6E2FFFC8529F183ULL,
		0x561527C0148BB2AEULL,
		0x4D36AB9F7FA24060ULL,
		0xBF23B329257E5BC3ULL,
		0x11A1376CA5F4DDFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FC8548E5E3051C7ULL,
		0xDE973956181E35BBULL,
		0x2236D58C9DA68DF1ULL,
		0x64D13A1D2782E4E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x64FBF576941DDD4BULL,
		0xA71CA5C680D6F237ULL,
		0x406694A105CA4189ULL,
		0x4515A64B099D82D8ULL,
		0x32598E6F60C6F912ULL,
		0x0B169FD00B2C96CFULL,
		0xD72CF101F55D0B1CULL,
		0x17934DA8F90A45E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4719FEF1A6D67CULL,
		0x4C785EA8297554F8ULL,
		0x31125AEB7199E7B3ULL,
		0x44F32D600123E31CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x187B202C78EA8C34ULL,
		0xC480DBE30D0B17E6ULL,
		0x81D3681F93CAA6BBULL,
		0x70F0920930F21BACULL,
		0x611DF13193B32C1FULL,
		0x2F1716CF69ED6F76ULL,
		0x22CE6247AF715E96ULL,
		0x948CFF402DD93914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82ECED8865831C12ULL,
		0xC1EE3EACC649A378ULL,
		0xAC75FEC39E9EB106ULL,
		0x7DDE758FFF3094A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA148B5620AAC6C88ULL,
		0xA911840729E44FF0ULL,
		0x05E0A351B09AD392ULL,
		0x153F784EBABEB0A5ULL,
		0x37FFC4AB749CF92AULL,
		0x2F77D81274545A7FULL,
		0x9DF4987D02B50294ULL,
		0x8BD6F0A8D19ADE27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13FE6D559F96BCFULL,
		0xB4DB96C46E69BED2ULL,
		0x782F45E017793591ULL,
		0x5727315DD7BBAA86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7DEF6909170E0CB7ULL,
		0x7ECA8A9175F0DB50ULL,
		0x310BA63F17010B3EULL,
		0xC3007258C1C8718BULL,
		0x4D7A2E9EE57D979CULL,
		0xA164583D60131080ULL,
		0xE0850FE39864B767ULL,
		0x07BD5968709F1714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE12549F27B28E18ULL,
		0x73AFA3ADB8C54E5BULL,
		0x84CC0207B5F444A0ULL,
		0x691BB7D97965DEA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x74581B71670D8CC6ULL,
		0x3954F5EAE7EDE048ULL,
		0xF94AEF0E9691D611ULL,
		0x902C58A2052F90F9ULL,
		0x7054550786B4B11FULL,
		0x5A2B029525914D83ULL,
		0xA4F6D8B46902CEEEULL,
		0x693D654067D6AD4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DCBA8F65DFD9C0ULL,
		0x9BB7580E7B7F61CBULL,
		0x75EF19D62CFC8D72ULL,
		0x2F4960316F0D4A5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x580393D432F9C7B8ULL,
		0x030BBDE84BF889AEULL,
		0xFDA06A445B0E12ADULL,
		0x5395A9D68D90F547ULL,
		0x598B257074C8FCEEULL,
		0xF1BB94A5BAE8E841ULL,
		0x267613ECBD41A877ULL,
		0x16B5CB36B17EE1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AB228588CF5391ULL,
		0xE4E3CE820A8B0361ULL,
		0xB3275F6872CD147AULL,
		0x3291D3F4E6667EEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x761C863563EAFCEBULL,
		0xE4D96E6DBBB15D70ULL,
		0x13FDF2F918FD3A6AULL,
		0x0D90FDB17966800AULL,
		0x34092AD23E311745ULL,
		0x72FC2724E762A667ULL,
		0x9D8B11D80AD79F72ULL,
		0x84C3D52286DC57E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F78E16A9F34740EULL,
		0xF6473DE8145610C2ULL,
		0x76A2990AB4FEE567ULL,
		0x42A2A0D17E1B8B61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x83C42B04BEC34FCFULL,
		0x0689DBE9AC73EC6BULL,
		0xBCA8B4B48C7BC291ULL,
		0x06A62E4C525862F4ULL,
		0x3B6CE526E7017449ULL,
		0x982DAEE3CEA4933CULL,
		0x4AC0EE790370339EULL,
		0x8BAC3F0CB5197AE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55EE2ECB08FA95B0ULL,
		0x9D51D1BA58E1C75CULL,
		0xD54C1AAB0F236C1BULL,
		0x42378A2F3420A065ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD5629296DFAC5E12ULL,
		0x99E81409D6F16508ULL,
		0x1FE6659F7F9590DDULL,
		0x0E8534FBF18D18A5ULL,
		0x291DF2BF5224C316ULL,
		0x9C404F1E1DE7D910ULL,
		0xD709EA2DC5E45344ULL,
		0xE6D53EB2D9B12904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD49AFD11215862ULL,
		0xCB73D282475B9D6EULL,
		0x0B5F286ADF79ED0CULL,
		0x522C838841D92F5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5FC119FEF7DEDA7BULL,
		0xFC2B0C5CC94022F1ULL,
		0xA18BB830997834DAULL,
		0x8B3350A0508A9182ULL,
		0x5CF6201BB9B9FA7AULL,
		0xE4E5F05B86416BE7ULL,
		0xC12A9414E1F4C5F2ULL,
		0xA3271EE846901EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C49DE1C897A0C3AULL,
		0xF64CB9F2B6F62749ULL,
		0x4DDDB34A23CD96E8ULL,
		0x4301E71AC9EF2187ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB7BE20F1BE9062CEULL,
		0xD3BC7B25FC179F36ULL,
		0xEB7A5AAFC773DB85ULL,
		0x97569F7F70179E1EULL,
		0x451BDF34F7AAD3E8ULL,
		0x88548900A1A41888ULL,
		0x9EEA6BA74D3A1CBFULL,
		0xC791C879E2D80344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9E142CE81EBDBB2ULL,
		0x1048D13DFA734370ULL,
		0x824655853E141FF4ULL,
		0x36FA61971C281A4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xBAD0E7F6FF17C331ULL,
		0x22C5C9C848854379ULL,
		0xB07C645A7111F47CULL,
		0x3BAA08302BD6965DULL,
		0xE14B7D00D29A294BULL,
		0xE8E5C591DA8D90AAULL,
		0x23A32DDBAAD6F29BULL,
		0xC37E5DFD06AA2C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C05761641F9E8A1ULL,
		0xB4E11D6EB988BCD7ULL,
		0xFAB532F5CCF9F7A0ULL,
		0x406BFBBF29192348ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB324B13CFABF2317ULL,
		0x963056C4841655C6ULL,
		0xE70EDAFA776FD888ULL,
		0x353921268C919449ULL,
		0x1CBE2F8ECC7117E0ULL,
		0x4BE7E75EEC741EF3ULL,
		0x769A26F14B587CA7ULL,
		0xAFF2FF7FEFDE2C0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75FC06F5388B233ULL,
		0xDA9CAEDB9D52EDDCULL,
		0x81F0A2CBA692595DULL,
		0x534B0E24278C1E6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2512C1E0D9FC062EULL,
		0x0A448C087E741DFBULL,
		0x5D3A5ED7DA1B426FULL,
		0x983C3A2D90B255DDULL,
		0x160851C11A42E14AULL,
		0xE0F50432069F8E02ULL,
		0x6C0B48CEB6017C7DULL,
		0x0B5E3750832BD7E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A4EE48ABFE97776ULL,
		0x6EA32B757A23324AULL,
		0x66E72D86DE53BD1EULL,
		0x4838702109346153ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x70C305A719C576C2ULL,
		0x57BA97CB5C774C8CULL,
		0x0FB989C902A1F535ULL,
		0x7841C0CED8B9D55BULL,
		0x1954C148CE8589CEULL,
		0x2462BD45ABA3FE4DULL,
		0x6CF9E02A61BF0458ULL,
		0xBC7AAF574C62802CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3357B675C197EF7EULL,
		0xBE62B022D6CF0BFEULL,
		0x3CD0D01384FC9A4AULL,
		0x7277C7C42F58DBF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x317881A120A39AFFULL,
		0x172256C04042747FULL,
		0x0FDE631036199F95ULL,
		0x9A99BD730A2CB222ULL,
		0x1EFB785D5DA379A8ULL,
		0xFB8DCD83C4E8ED09ULL,
		0x9D9F8B2F5526B095ULL,
		0x4BC65CF669229B38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCACC5F7D06E7ABA4ULL,
		0x6E2ED84F7AD5A3D9ULL,
		0x758D0C16D9D7D5D8ULL,
		0x5A0B8A06A54FBC89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1EFDAA344753BD61ULL,
		0x79643B47F5E8F62EULL,
		0xFAFD7B47BBEF890EULL,
		0x2E7EB0A940D541A5ULL,
		0x2BC637EF025FF846ULL,
		0xF3908700A10D35D2ULL,
		0x387E6202B3EFAF6CULL,
		0x6EE4446C08767BA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E69F7AEA1929A38ULL,
		0xA0D8455FDDDEF360ULL,
		0x5DC007AE7183933AULL,
		0x2460D8B2826B9C78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCB84D415F8082045ULL,
		0x8FFCFD81DC89D79BULL,
		0x5ECE2E90F8DA5D0FULL,
		0xD70DA386E051D559ULL,
		0xD7F1CBA2D5A0BFB3ULL,
		0x0FD8E8EB71829035ULL,
		0x49614D3AD61C326BULL,
		0xE9FAF20AE45E1441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9690E41ADE49A1CULL,
		0xEA2F9074B5EB3F99ULL,
		0x433FA54CC109D8F3ULL,
		0x124D9124C648D70AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC0DB32DE56450D4EULL,
		0x0033E74761C90853ULL,
		0x9F3D2166A1340B54ULL,
		0xBB16D5797AEC442DULL,
		0xEBFB8D396108BDF8ULL,
		0x3813B681FA3D72FEULL,
		0xD00A8CBD661B98F9ULL,
		0xC417FDDA195C2FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8322962BD91447FULL,
		0x5320FE9286E81A2AULL,
		0x80CE0583C94CC052ULL,
		0x56A683D93E9B6108ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3371B8BC138BB0F4ULL,
		0x23F39891BA70BE29ULL,
		0x1668069EFC023EA3ULL,
		0x28DFDB2B4F8C2B60ULL,
		0x069F57A7C6AF70A0ULL,
		0x128BE0F948A9CCA5ULL,
		0xE5999E59BC4162E8ULL,
		0xDDEBBD9918966157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F18BBA391966D9AULL,
		0xE4B6FD9283A51EA8ULL,
		0x2B3587F0EDB6ED15ULL,
		0x19DDFFE4F5DE9E6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x7B078E455D35E8DCULL,
		0xEAFA6F0A7AE596DBULL,
		0x79838732E1B37FF5ULL,
		0x878311B098AD4B4BULL,
		0xB7A0CE15D4EA7B16ULL,
		0xC10A12829D5ED36DULL,
		0x9298E9453EB8E395ULL,
		0xE4FEB9315843ADC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE62582F804333FULL,
		0x92792E6DD6F8F924ULL,
		0x3C36277A31254830ULL,
		0x05528F03B2B91711ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF9CB2D0227A057ACULL,
		0xA03BABD430DF8D9DULL,
		0x2B544168E073BE9DULL,
		0xDB996F1B4CE41A58ULL,
		0xB5CE996CA46C7A3EULL,
		0x2857FB2A2A65847EULL,
		0x6E1A11E14BC29162ULL,
		0x22EB9BA014C55ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF675F3228FBA7DC4ULL,
		0x9D4AF4167BF1386CULL,
		0x8332E8DA1F55532FULL,
		0x0A9288DE62302D22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5A018D6D3B4E6F5DULL,
		0x023EF093C5FCCE69ULL,
		0xA9005461DAB49B78ULL,
		0x4FBA5186A52E4C17ULL,
		0xFF661963FBAECB88ULL,
		0x53EDED6E22CC7B81ULL,
		0x40018738CD327376ULL,
		0x9414BD385FF1DDF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432952449740A8D1ULL,
		0x77902EECF05723B5ULL,
		0x293A66D05031BF08ULL,
		0x4ACE67E4E3153F17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC530ABD522BBD573ULL,
		0xA5F0578C58E54736ULL,
		0x4B0B35F9B6109B24ULL,
		0x5737DA24F7B6BBB4ULL,
		0xB6E1955B7AC93FACULL,
		0x19585F7FB0A67460ULL,
		0x641456F133E9A109ULL,
		0x5814498477555439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAACD7695C9B4AE9ULL,
		0x690E8480919A8D91ULL,
		0x26101DC76ABE827EULL,
		0x6A3AC3CEAE613C39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9959CA20A21AE04CULL,
		0xACB09BB2ED91F55CULL,
		0x086B96DC7E6269A4ULL,
		0x7E7783FA84B9C447ULL,
		0x1977687F59DB982FULL,
		0x9BFF23A71F106E06ULL,
		0x34778A519D7775C6ULL,
		0x8CE65E6BF91DE7D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61134D07F8B37A64ULL,
		0xD48FE6818A024A44ULL,
		0xD22A1EF9DE1DE51FULL,
		0x68A988017F2A2DC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x74FB4CC0DB93D70AULL,
		0x5D04EE2114C69111ULL,
		0x58BEEBD6CF1DC44EULL,
		0x4DC9AFA3204B9179ULL,
		0xEF7D8551DD62803CULL,
		0xF46833ED8705D2BCULL,
		0x0F82493BC31B4FBCULL,
		0x26FAD5FAB790400BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x019D16E7B832E0D6ULL,
		0xA47CA3631FA3D91DULL,
		0xA615CAB5C52B9A5AULL,
		0x170572DA5FB5131DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9A45B625393016FEULL,
		0x8047C2CDD9E4DA5FULL,
		0xFF8E52B6ED1272BEULL,
		0x6F70D0F413CC1911ULL,
		0x8209E8D50CA01ED0ULL,
		0xA3822883CF9A1B4BULL,
		0xDEF448A37242DB80ULL,
		0x3DE0D88C553440F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7BE45C518F4AB47ULL,
		0xC599C65EAAC4E794ULL,
		0x17D11AF9E2FF07D6ULL,
		0x1ED0F5C8B98DBE03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xEF226546F2644357ULL,
		0xC8A587F9D7AFDB03ULL,
		0xF232FCCFA872D0F4ULL,
		0xCC43705105EB6B74ULL,
		0x6754A60CEE3D11EFULL,
		0xA58D9A1B3A1DD433ULL,
		0x18343AAE9D066B13ULL,
		0x44217524FC3145BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B30B324F74EE60ULL,
		0x5BAA6804781D5AA5ULL,
		0x89F3B2BAF766B5DFULL,
		0x693AD3CE753BC5D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD3D969F7E840998DULL,
		0x4C6DFFC965A4E9ABULL,
		0x24710066306EC8CEULL,
		0x227FA5E5CCD3A981ULL,
		0x738C958D1C7054F5ULL,
		0x30F1296B2B966B95ULL,
		0x698F2136E2F41145ULL,
		0x2670ACE8738B0FE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB79CEA20ED36BCULL,
		0x903A25B1DDF8E1DAULL,
		0xCFAFEE8BE0A95913ULL,
		0x57395066F378051CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF67DD2E37B04AB46ULL,
		0x3C237E4363E6BCC6ULL,
		0x35693FD38A9C83B2ULL,
		0x001736BFC88DD169ULL,
		0x16BEF3BD924BB5F7ULL,
		0x2CFA2A8C27551DD3ULL,
		0x4B9E77EE3453CA47ULL,
		0xF8382BFCDD2B1275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D601073241B35BULL,
		0xE945CF113A892A1CULL,
		0x6EEF0D2F4F0C8A42ULL,
		0x586DBE489CF28ED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x00343F11DC4FC070ULL,
		0x3FC9AB56FA6952F1ULL,
		0x5D7A29982CBDBD17ULL,
		0xA120686A2E9B06F8ULL,
		0x93374D0CC8556444ULL,
		0x77ED27492A200876ULL,
		0xCE72257CADB5A21BULL,
		0xF938BC46C546D279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA69AEF798FCA819ULL,
		0x0CFD80333B2A948AULL,
		0x026BBA19F5B3CD2BULL,
		0x1F8C5AEB771E450DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD36834BAC32FE8ADULL,
		0x38C41E795ABBD3F4ULL,
		0xE5B93C04067D42F4ULL,
		0x20DA4CBCEEDDDD84ULL,
		0xC1B9AB85ACCE7963ULL,
		0x12DD1359EE14ACE5ULL,
		0xC912FA7D671C485CULL,
		0xE7DBF9D3FAA7FB01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94F7AA9269D5F27EULL,
		0x0594FDD2B1CD7E0FULL,
		0xBE8A6AA154B0009FULL,
		0x0B81623423CD1FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFF35986678F91F52ULL,
		0xCF3995FCA17DD993ULL,
		0x8A0D988CC7E8B591ULL,
		0xD38150B99665FC66ULL,
		0x7F18E446F123C58CULL,
		0xE9765A2B3FC335D7ULL,
		0x09EC4F4433A073FEULL,
		0xADD720C00867B024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCE77AEE44487609ULL,
		0x76CAF8681877D790ULL,
		0x03215CAC71B9ED68ULL,
		0x21702D3AD5CA21C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF6179134FCBB8DD5ULL,
		0x7C1CB997EBE69537ULL,
		0xEE1046EFE1EB4D2DULL,
		0xEC007E84FA8203B9ULL,
		0x96707949ACAC360FULL,
		0x1968181C9284738BULL,
		0xB65802998468CE57ULL,
		0xFEDE63BF7AE460F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AC992249E4B99C6ULL,
		0x41904DD5AB8FBBF0ULL,
		0xFF20A9B98979EE1BULL,
		0x41034CF13868680CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCCE686BCECB1F6BCULL,
		0x28372C7D6527D5D9ULL,
		0xBA2779DBD44FB29FULL,
		0x361D3443ABC01D09ULL,
		0x7346EDA068A6A2A2ULL,
		0x69AF82CEA27E1956ULL,
		0x1EF58155FC0C7EA6ULL,
		0xC92234C3F8723718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE96DCC8C756E1F3CULL,
		0xD844972983DF98AEULL,
		0x5298AC9F3E2A7F52ULL,
		0x1131095A8CB44A9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x569E8BC6A5827FCCULL,
		0x4AC45908819AE442ULL,
		0x0177CF5A4CBBF3E9ULL,
		0x0C277182514C2D0FULL,
		0xBAB17582A8967DEEULL,
		0x9CE6FBD0E461F545ULL,
		0xE8FD7AA4CA9C8E12ULL,
		0xC4E09BCDD0FE8756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CF5FD2BABD9356EULL,
		0x950DBA0A68254C9CULL,
		0x971803D05FF90AACULL,
		0x457E920F571443F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0BCDC4A946D92590ULL,
		0x01A8F7A0FFBA4DC6ULL,
		0xED9208729A8F650AULL,
		0xEEBE1E0D84A194E3ULL,
		0x6509D263C64A4D4DULL,
		0xF6E5559486DD745FULL,
		0x6210491349F6C671ULL,
		0x2E10B62B65403B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B42FF78B5E0A01BULL,
		0xA7B3ABAD049993EFULL,
		0x7BFCE14F9530D9F4ULL,
		0x4539287E8C2A6E8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8BB77841DF3DD4C9ULL,
		0x5FF8C1A2E4F2A0A2ULL,
		0xCD871141D000708CULL,
		0x2651B3AFDFC4DD9EULL,
		0xA1C4A391B96BF11CULL,
		0xCF2C7667E33CEF88ULL,
		0x3AED1B74CEF847CAULL,
		0xA3C73FACA5F95A15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE7BFE36543A281ULL,
		0x2092550E9FFE2EEAULL,
		0x8CB9249888DB18A7ULL,
		0x75E5275082C83CC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB4420A8AA7164CA0ULL,
		0x917BCB32FCF22AEFULL,
		0xA21D1E9B56C6AFE2ULL,
		0x73290579C27AF622ULL,
		0x59CABCDF9AE7CF54ULL,
		0x59C194678C3AD780ULL,
		0x12AB36AB25F36427ULL,
		0xBCDD45C33D2ED291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085A13BBA57F1740ULL,
		0xE437D291CDAE27FDULL,
		0x67873C02F8E78DB9ULL,
		0x7C016074D76E37ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8019455D00B86146ULL,
		0xB815261FD9522D46ULL,
		0x864D782C54542AB7ULL,
		0x549EFAFF51EF771CULL,
		0xA4FCFB563409F88EULL,
		0x739C00666CFD8C24ULL,
		0x902383A7303C352DULL,
		0x1410E7B09DAD49F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA69428BA3346CCULL,
		0xE13D355406F4FAB6ULL,
		0xEB9302FD7D440F76ULL,
		0x4F215F36B9A87143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xDD3B2CBAE3E438F2ULL,
		0x2B65630FFB775271ULL,
		0xE129BBA4AAF9F3B6ULL,
		0x47BA15E4539F4928ULL,
		0x0F33C5E8C3E021DFULL,
		0xC6D7132125AED90FULL,
		0x31A9703FBB563BB1ULL,
		0x6F56C314F3AE6979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEA8D47F729427FULL,
		0xAF5239FB936B8AAEULL,
		0x4050651A79C6D019ULL,
		0x4E9B0B007F82F126ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0B69E0A23F7E7259ULL,
		0x47A67CFDAC1A1B13ULL,
		0xB18D5847F2EA1B60ULL,
		0x36827147FAB055BCULL,
		0x6B0EDEB1457260B5ULL,
		0x91EC760E9FBE09C0ULL,
		0xC572AE88D78C95BAULL,
		0x8691E1052CCBE424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF9EEEF28E78D02FULL,
		0xF0C00329624F8DA2ULL,
		0x00934097F1C85511ULL,
		0x3029D80CA0F43332ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3B67CB35D9807833ULL,
		0x7BBF078D8DB46510ULL,
		0xC0EB690D89EB9705ULL,
		0x84922250145639C2ULL,
		0xA96115AFDDE185ABULL,
		0x14B896B109435B51ULL,
		0xB50FA56A4A29A5CCULL,
		0x8ED474C6CDCB6EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD10350C8FA52C6ULL,
		0x8F2565D4EDB3F32FULL,
		0xA13DF6D48C1A3350ULL,
		0x381B77D2A088B157ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xB0239F110BFA0358ULL,
		0x5A59178BC585A40AULL,
		0x6E3ACEA11FFA0065ULL,
		0xA005388405989370ULL,
		0x903C7CF66B1D4847ULL,
		0x9D9C209CD040782CULL,
		0x64A58E7A04C21AEFULL,
		0x4A5471C5612FE7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x191E2BA4F252BF97ULL,
		0xBF85EED2AF177AA8ULL,
		0x5ECDF4BDD4C9FFF6ULL,
		0x288E1BD072B4F9B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x07F93D69239D0F4DULL,
		0xBD09C396EDC86DDCULL,
		0xD656CF664BF54E77ULL,
		0xA3DC9B213C7519E0ULL,
		0xD22C9321DF7BD411ULL,
		0xA48CD521B5A07CA6ULL,
		0x874C0C3A240584F1ULL,
		0x14ECDA05C1763C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A9714704FFE8A58ULL,
		0x29F16697E39AEE9FULL,
		0xEBA0A007A4C70A56ULL,
		0x3F04F7FBF4020856ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x0F24E966452226F1ULL,
		0x27D1AFB160104561ULL,
		0x84614AE2ED7814F4ULL,
		0x7DD0157281848F4AULL,
		0xFFA3DBC4B51E1A8CULL,
		0x8366EDAAF2CA2135ULL,
		0x2E3792062C17F27AULL,
		0xF9B8E20AE6D7059BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01778899279A1D4AULL,
		0xA918F7116A113365ULL,
		0x60A0F7CD79061323ULL,
		0x0F41A310C56F6453ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x04735ACFE4D7A9B6ULL,
		0xFB8A5BC078F503FDULL,
		0x309E0B13573E9A2BULL,
		0x2ACDBD1544562CDCULL,
		0xEE32B779E0A4AA98ULL,
		0xBC444ABD8285B88CULL,
		0x4736C9F9486287BCULL,
		0x01D7C296EC54D919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FFA96E73D48FC46ULL,
		0xEDAD73E1D8CE68E8ULL,
		0xC2C0061415DEC02FULL,
		0x70D49F7C58EE669CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x353A3A29868C4EFBULL,
		0x18C0EA1EF57F1313ULL,
		0x7ECEC6D7C4A26063ULL,
		0x68AC41731B126F79ULL,
		0x47442EF5BF9092F3ULL,
		0x025301EE6A7B6A9DULL,
		0xE8C16FE7A93815E5ULL,
		0x8106DDCADB53CAD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC95932A3F60221F2ULL,
		0x71133382C3D0E66BULL,
		0x0B85633AE2F5A061ULL,
		0x0FB12D8FA9828AA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA4F382280DF3AAF4ULL,
		0x2434ECDFA60EB9A0ULL,
		0x836D13D216C76C9DULL,
		0x9AA64E2FBC3FA949ULL,
		0x5F386D85D30AE4CAULL,
		0x670F9E4F6A1D9F72ULL,
		0x59AFB16796369353ULL,
		0x6381F2390B33FC70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC753C4056191A32AULL,
		0x70866CA96674649AULL,
		0xD381693262E14AFEULL,
		0x5FF042A765F721F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF11A1CD29E723732ULL,
		0x7A025C098B9E7309ULL,
		0xC5F2C5DC25AF9B72ULL,
		0x1203468FF62AD6AFULL,
		0x54B62C41829BC151ULL,
		0x0F3ADAF448AD8523ULL,
		0xCAEC4AD60BD48FDCULL,
		0xB790522B29A6BA47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8424AE8C0190ED3AULL,
		0xBCBEDC4C55603648ULL,
		0xE505E1A1E73CF61CULL,
		0x516F78F824EA7D57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xCCA87CEF1CE77383ULL,
		0x98F03F4F79A62860ULL,
		0x9154E56067671FA8ULL,
		0x33F6CDAB7F160AABULL,
		0x194095960F7C13A9ULL,
		0x16D21CFC9951416BULL,
		0x81F5F6D92693E995ULL,
		0xC11F06973B8018DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3EB135695262D4ULL,
		0xFC208CCE3BB5DE46ULL,
		0xDBD7899C215BCBC9ULL,
		0x5E91C81E5419BB66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x20BB00407B1289A0ULL,
		0x096677369610F18FULL,
		0x7914F0643C039D39ULL,
		0xB70DC6317FF992DFULL,
		0x8B8FA3FBE1E5D300ULL,
		0x655E182080ECFC5AULL,
		0xC2E865083D5EECDCULL,
		0xB5127558B09AD642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80D57A4032FDFB5ULL,
		0x155E0C09B93E66FFULL,
		0x6793EF9D581AC5F0ULL,
		0x17CB315BB6F560C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3F1DB1562BEF5266ULL,
		0x0DA3C439A1EB7C2BULL,
		0x521765EE80F6B262ULL,
		0xAC239636E1B804DAULL,
		0x4B218FAF4FCEEA47ULL,
		0xAED237E7E2974B98ULL,
		0x88D890A4BCF1883EULL,
		0xCCF23FB7CB103E99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6619055C04A61D8AULL,
		0x00D810A54460B4C6ULL,
		0xA23CDE628CD0EBB0ULL,
		0x18190B7F06214FA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA3A31CBA4F25E8C3ULL,
		0xE8F5E4DBA92EFDA4ULL,
		0xFDB47DCCC2B6B925ULL,
		0x7265C7CC26ED0E07ULL,
		0x40AF905EACCA7443ULL,
		0xC0016657931AA470ULL,
		0xC2FE76777DB7758EULL,
		0x78A8FBA3B2194063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DB28AC7F5332D61ULL,
		0x692B15DB7F23664EULL,
		0xEF7A13896BF22C56ULL,
		0x5B7B221896AC9CD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3A456BFEA6D89526ULL,
		0x8003188B28198136ULL,
		0x246135A0B5B2CA62ULL,
		0xC5826F08A3B90CDBULL,
		0x4A1AD8D91DA663B6ULL,
		0xA171CBDCC94C97E9ULL,
		0xBD9BE3BAF8C9EB7BULL,
		0xD570FB221D60F646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A419C390D8B66EAULL,
		0x76E75B5109780DD7ULL,
		0x49850361A3ABBEBCULL,
		0x7447B619001D9B5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x24656C215195FE35ULL,
		0xBB930891973E7F48ULL,
		0xF95CC28A48332E88ULL,
		0xE553F6A6AC765612ULL,
		0xA6875D7099A90941ULL,
		0x43D7305E7E594783ULL,
		0xDEF49C860029027FULL,
		0xE6D3A70E5AA13E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC7D4AD820AD630DULL,
		0xCD843698587F1CD2ULL,
		0x11ABFE6E4E498D6CULL,
		0x28BEC2C820659BDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4D93006EDF22332FULL,
		0x4E6900150C18B118ULL,
		0x63200C1A944D41E7ULL,
		0x07EA3061279F3FAEULL,
		0xE72076756B6CA943ULL,
		0xF449207E15C6C382ULL,
		0xCBA328C22083C0E6ULL,
		0x286C24F26BFAF05BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6495DCD1435405ULL,
		0x9143D2CC4799B686ULL,
		0x9D5818EB67DBE42FULL,
		0x07F7AC5D2EDEED4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xAB3FD70258D22769ULL,
		0x8FEB82D905BA0031ULL,
		0x14034DE9AF9513E8ULL,
		0x2EB5E722EC552AD6ULL,
		0x668011CE8191AA21ULL,
		0x097238EA1D181F88ULL,
		0x37C918501A61DAB7ULL,
		0x47EAD5AE8AD703A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2427BA9947169DEULL,
		0xF6DFF599574EAE70ULL,
		0x5BDCE9CD9A1B8B13ULL,
		0x5B919F0B883FB5CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x84854E87D7A2B5C2ULL,
		0xAB7C6564861CB3A1ULL,
		0xA8FBB558C05B994AULL,
		0xA4F560BB75448942ULL,
		0xE6E5148A448940D1ULL,
		0xC3EADC80C1EA9008ULL,
		0xC83F0CF87502D1FCULL,
		0x5C16F43443B3315FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA865B0E040256DCULL,
		0xC05920814EEE14F3ULL,
		0x6257A23A1EC6C4CFULL,
		0x505DA07D81DDDD7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x266ED95CD3C12512ULL,
		0x564FC5A655348DA9ULL,
		0x22C36E2C6494BEEAULL,
		0x439E115B649C334AULL,
		0x794812ADBAAC69EFULL,
		0xB42C401D7572E373ULL,
		0x80E2411A2122071CULL,
		0x1A4314841D6F5EE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27219F268958DF24ULL,
		0x14E14A05C44250CDULL,
		0x4459180D4FA1CD2DULL,
		0x29931CF7C3244981ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5E6083E350C18D4AULL,
		0x6AF99C74EEE687F9ULL,
		0xDA0A82FB20E63B74ULL,
		0xE601F6B644E650ECULL,
		0x9B2FC5B1F48C45D8ULL,
		0xA7919E1C100B26FBULL,
		0xC917AF5E14ECB53DULL,
		0xAF2CEF28604225F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6777DC4D9D93EF49ULL,
		0x4A97149F508E5152ULL,
		0xB38E8AF23C09229BULL,
		0x66AD76B48EB7F3DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA0DDF030A8A2B3E3ULL,
		0xE74E80689A759970ULL,
		0x137D4D3DB8B80E19ULL,
		0xF00ABA712685DCBBULL,
		0x5DB7DE808989C4DBULL,
		0x4CDD82BD7B45FC03ULL,
		0xFA375F85C46889A2ULL,
		0x286D5B578F6E43FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A28F7451315ED5CULL,
		0x502FE888E6D901F0ULL,
		0x37B57B18E03C7C31ULL,
		0x7046497070E3F4BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x5168211864C8D0A0ULL,
		0xB07C238EFE4F1429ULL,
		0xE9F6087B903DA50FULL,
		0xAC7942741EAA8885ULL,
		0x3FEE95D95D57E0EDULL,
		0xE9B8605F4A97EBBEULL,
		0xD40BB848411530F4ULL,
		0xC9F1D04757A028ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED25F5C3FD43855ULL,
		0x61DA71B410DC1266ULL,
		0x63B363353962E96AULL,
		0x265E2D0B20709253ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x175AC53F127C4828ULL,
		0x5441E6E9121346DBULL,
		0xC6753FCE7DFEC408ULL,
		0xEB6B8EE6E35558E6ULL,
		0x5CC0B87487936AD5ULL,
		0xA64BB0A15DE75693ULL,
		0xECEAD1720CB37DAFULL,
		0x3B4BDFC56D9FA874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBF6268B325E252FULL,
		0x037E1EDD026A20BAULL,
		0xF15056BC60A36C1BULL,
		0x38AEC63529085A41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x88F2054BCD749E4FULL,
		0x1779CAE013BF8AD9ULL,
		0x2DEE5C4E3FF6B7CDULL,
		0x07E0D0727D1ACC1DULL,
		0xB42E69D2D126DEF2ULL,
		0x64B83F2C46A5CA44ULL,
		0x9A75FBDCAAE05D9AULL,
		0x2975CAB54814746FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D5BA96D939B71FULL,
		0x0AD32B72905B910CULL,
		0x1B71BF0F9D449CB8ULL,
		0x2F5CE75B302414AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x59097FED8BC2110EULL,
		0xA17DE746D3B1C652ULL,
		0x4B1B65F56BFB517AULL,
		0x8465C1DCDCE46FC2ULL,
		0x7E005AFE257F3695ULL,
		0xC0EF2983528312EAULL,
		0xC94B89A909A2F97FULL,
		0x09907AC141A307E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1701A71CA42B65ULL,
		0x44FE10C513269521ULL,
		0x2C51D50CDA2C5A71ULL,
		0x6FD7FA8C9B179BDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x1EC732A1B79A7693ULL,
		0x51C3DCD0DAC3150DULL,
		0xEDCDDBA5A47B1227ULL,
		0x897DE879870A3773ULL,
		0xBCB9D3C004BB7BE9ULL,
		0xA10436159EC11F32ULL,
		0x696E0DB661CE46CCULL,
		0xD943509597D382B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x225CA1226B6EDFFCULL,
		0x3863E4066B6DB695ULL,
		0x9423E4B829199487ULL,
		0x497BDEAE106F9DC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x441D80F27EA1B6B3ULL,
		0x7418446F841D3A2CULL,
		0x88C035C5C9D5DE1AULL,
		0x0B212FBD4A2C4650ULL,
		0x06BA6AAA538E9E3CULL,
		0xC211D24018403A2EULL,
		0x8E576AA356F77D22ULL,
		0xBF745E3D9D8BABC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C9563AE5CD37C3ULL,
		0x42BD79F31DA5DD01ULL,
		0xA9BA0A04B2927143ULL,
		0x76672CE2ACE7C5C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9B1F35FD1EFFEBC9ULL,
		0x743C411C2FEEF35EULL,
		0x3E27259C93460DF3ULL,
		0x062E577760634207ULL,
		0x99CD5C8CB4C26E01ULL,
		0x2D6BF8EC3D032D71ULL,
		0xF29BB30A6FC25622ULL,
		0xF50E6B7B9F8E6753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9AF2DFF3DC4547ULL,
		0x3243342D3E67B23BULL,
		0x4143B9292A1ED706ULL,
		0x66524BD10F86987DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9A898C006A19599DULL,
		0xCFEF0EB70285358DULL,
		0x122B586B75B483FFULL,
		0xA1158BA9F95B30B2ULL,
		0x5A8482182AE2C78CULL,
		0xD98B553BE8449173ULL,
		0x48DDA6FF090645E0ULL,
		0x41DA32F978637FB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A34DB96C7C2F9E1ULL,
		0x1A9DB59B7CB2CCADULL,
		0xE3122246CCA2E360ULL,
		0x67791CB1D82025E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8E08BD70D1DF5235ULL,
		0x305CD1851E26545EULL,
		0x341A60C19607ECBEULL,
		0xB729A15F0DE41233ULL,
		0x3DB52A9487217566ULL,
		0xBA96F130E4FDFAD3ULL,
		0x7082854E170F0222ULL,
		0x5B61D2E14305C4FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6ED0F7CE0D6C16DULL,
		0xE2C49EC71BD98FB9ULL,
		0xE77A2A5902423DE5ULL,
		0x47AEEECF00BF501DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x8B4D41908A71A3A3ULL,
		0x6656523D419CE117ULL,
		0x75D7AD15E74238DAULL,
		0xB48F98CC4BB0E0EAULL,
		0xD4F04565C68D648AULL,
		0xDB8113E7A54C3D2EULL,
		0x4796FD75FFAEA993ULL,
		0xF1F025EE7B3EECE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26F78EAC036E958AULL,
		0xFB7F469FCAEDF60BULL,
		0x16414C99DB2F64CCULL,
		0x1E353A3297080AA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2068DA292AD31047ULL,
		0x459A5E275E6F71CEULL,
		0x57CBFD18C7C71822ULL,
		0x0E99382143CAC9C2ULL,
		0x4856E5133AF4AAF1ULL,
		0xDA01B4DCB50A7A67ULL,
		0xC50C4A1EF905B07CULL,
		0xA05C66637D17DD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD4EDB03EB24738AULL,
		0xA1DB36EA3DFD9D22ULL,
		0x979EFDB1BE9F4AAAULL,
		0x5C506AE5D555A0A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x73A6FF12BF5ADFEAULL,
		0x5B77A5F94D817F69ULL,
		0x9D672D4886A10E46ULL,
		0x319222677972238BULL,
		0xAB9C9D6778C47C55ULL,
		0x219B26B0DF5D2630ULL,
		0x7CC0A49D3822F983ULL,
		0x4CDDCB7CC5555FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE65C6EAC85563DULL,
		0x587F643A75552AA2ULL,
		0x21FF9C9EDBD217BDULL,
		0x1A7E56ECC41E5B02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x891310EB61170E17ULL,
		0x744565C88E1F580FULL,
		0x3147F9BF00AFC75AULL,
		0x5E5D5FFFA21A17C9ULL,
		0xC66E7669099E8740ULL,
		0xB35AD27EB1E89578ULL,
		0x8AC421BC01B292D2ULL,
		0x5356E20940EEEFF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD78A482CE9F2372ULL,
		0x13C0A496F6A587FCULL,
		0xCA64FBA7413192A1ULL,
		0x3D42ED5F4591B6D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x040F0DFF7E1AA079ULL,
		0xC155400AF02726C6ULL,
		0x2F653E11BAD1AAB8ULL,
		0x8D6A28C2937E327CULL,
		0x1FC3001E14DBC104ULL,
		0x91547CA37EECD1D7ULL,
		0x761B2ABA0CCAA7D4ULL,
		0xD08F3C9859094596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB01127696B94BBEULL,
		0x53DFC04FC74E4CB4ULL,
		0xB76D95AFA0E69446ULL,
		0x02AD275FCADE86D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x675F85F57E47FACFULL,
		0xF77622403233F6A7ULL,
		0x6C59A912BC2B8358ULL,
		0x657B267D83BD0BEAULL,
		0x2CCA4B372D99D1D9ULL,
		0x44A914E1D551C2A1ULL,
		0x3F2337A6346E9957ULL,
		0x9B8098EA80CE84ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D66B026431D246FULL,
		0x288F3BC5DC56DA94ULL,
		0xCB93EBBE8496464DULL,
		0x7A91D94CA264C6FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFBA288CDE1DEC270ULL,
		0xD776C5CA25F745F0ULL,
		0x24AB052BCC596DF1ULL,
		0x871657046624FF20ULL,
		0x961ECB3AE61B6BC3ULL,
		0x0D3B5F5B51F6448AULL,
		0x2CBE50A8A39AEBABULL,
		0x39F7184A909DE027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4434B38C09F0C2B8ULL,
		0xCE46ED5850857283ULL,
		0xC8EAFE3415586955ULL,
		0x21C3F215DD9444F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xF0F0C626E33DC1A3ULL,
		0xB1BB23649A90A277ULL,
		0x1E8141E5BEA3E9C0ULL,
		0xB26CDA2458B0DAFEULL,
		0xB910525231B00A2DULL,
		0x5DED7C98D4933FE7ULL,
		0xC55579F447FECF31ULL,
		0x0B4255371C2AA81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x695CFE5A435F449DULL,
		0xA2FBA214286C1EDDULL,
		0x69315C286E76AB14ULL,
		0x5E4580528705CF1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD09B1853C95F1FECULL,
		0x3A8491DBF03FE8C5ULL,
		0x2912D2946E531F05ULL,
		0x7A5234430160CDC4ULL,
		0x91820DA95A338BADULL,
		0xBFCA96C32CB35FA3ULL,
		0x762780C331D3C260ULL,
		0xD4694407A9DE4FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E91F772D05E05AULL,
		0xB296F2D492E01B0DULL,
		0xB2EFEF8DD3C1F961ULL,
		0x01F24D663860AB4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE3A4C767B554AEDBULL,
		0x6F1327DCAE4BF5F4ULL,
		0xA212AFF81D108146ULL,
		0xCDEDBDBFB1EE1621ULL,
		0x8106082747BE8F80ULL,
		0x51D6DF974886CC7DULL,
		0x255383DDCD08200FULL,
		0xD24079C6645CEF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A89FD3C5B9E009BULL,
		0x94F85851724E5096ULL,
		0x2C7842E48C45438CULL,
		0x037FD13297B99C79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x739B70944E549F8EULL,
		0xCFA93D8E70C17B8DULL,
		0x0ED91336BB30AB2BULL,
		0x59FEE2F05AD41366ULL,
		0x139849B4FF17EA0BULL,
		0x92FB2442F6301CF6ULL,
		0xC81AE5B69D87A031ULL,
		0xF3F33D30AE379E30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3661722BE1629BULL,
		0xA0F09F7EFBE5C814ULL,
		0xC2D72C521D527287ULL,
		0x1019F82A37158EA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA9A6C1F1C56510EAULL,
		0x4A796CACA745BDFFULL,
		0xAB4F9EFD217CCD7BULL,
		0xD97F4374F71FE8D6ULL,
		0x085C73168598EE06ULL,
		0xDE442C8FB28C2562ULL,
		0x13945127F8742EC2ULL,
		0xB4EB5EF415CA4625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE75FD7499A1869E3ULL,
		0x48980A0128134A8CULL,
		0x9353AAEC02BBBE68ULL,
		0x346F5BB033265257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFA037CE77A080AA5ULL,
		0xE2162012AA85BFF3ULL,
		0xEC0D4D58A374E3C6ULL,
		0x5747FE2DB9543F72ULL,
		0xB275AE57F9F28C81ULL,
		0x84F656F195BE2D4BULL,
		0x5438A5D73800D40DULL,
		0x10331431F68A7CE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777B5DF69408E62AULL,
		0x9EA707EEE4C07930ULL,
		0x6C75EB4AF3945DC8ULL,
		0x3EDCFD9851E2C957ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x35683B07FE8322B6ULL,
		0xB186E03FC603F16DULL,
		0xF19E50E546C19376ULL,
		0xF868BC00DFF7EEECULL,
		0x55624B11507A82CFULL,
		0xA6C5FC60A4EB6A9FULL,
		0x8A5D76ECE3F34449ULL,
		0x58330C2563E66517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FF5F99F0B28F84ULL,
		0x72EA569840F5C513ULL,
		0x7B7DF80F1CDDB665ULL,
		0x0FFC898DB42AF06BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2BDAF561CB4D5294ULL,
		0xD97589909A7C98B7ULL,
		0x001DBFD3308F21FAULL,
		0x841C6515DC69CEE1ULL,
		0x4FC104A0A5D61766ULL,
		0x462D6770D08CDA1AULL,
		0xA5C898409B43E2DAULL,
		0x33612C45BE252676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0281A53A6914CCE8ULL,
		0x4432E44F8F64F89FULL,
		0x9BE4596A3CA2CE61ULL,
		0x2488F77015ED847DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x920A508805455AFBULL,
		0x09DD95A8F7E35BFDULL,
		0x05C6CBF3B1BCCBEEULL,
		0x31701EC4F44DDEB7ULL,
		0x7A375F7C88629C60ULL,
		0x6A9D3CB78CE311CBULL,
		0x6D9F4649BAD4F3D1ULL,
		0xA9F1C5CC4FCF7AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6427D0443E894F1ULL,
		0xDD3498E7E1980031ULL,
		0x4B6B3AE56D58FD03ULL,
		0x6B537B18CD1A1C79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xD37F4339ECDAD0E1ULL,
		0x5FAA1A40EF9DA6B3ULL,
		0x9C7799B7CE0029BFULL,
		0xFE94784F9ECF8154ULL,
		0xB3798EB366B91E5AULL,
		0xD99DEFA58A1B7B0AULL,
		0xD44BF6AB69EA3F7CULL,
		0xF2EAEAE66CD20187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778A71DB2C5557BBULL,
		0xAD1BACD36FB1EA4AULL,
		0x1FBE372986C59647ULL,
		0x0D735683C5FBBB7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x90ECCE96E66F6235ULL,
		0x4FE33DAF706CE554ULL,
		0x4CA97470B36A4C25ULL,
		0xE73F5385521239D3ULL,
		0x666CAD50C0005511ULL,
		0xC1D94ECC93A199D4ULL,
		0xADDAC3E35E8C806EULL,
		0x512D1028B07669DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC50E8893667C0496ULL,
		0x1624F00D5A69BADBULL,
		0x1B228830BC455C96ULL,
		0x73EFB98F83A5F06FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC83223C37D3CBFA9ULL,
		0xD435358ADEEF6457ULL,
		0xA36D6123AD882A44ULL,
		0x1AB54253CDCCA34EULL,
		0xB29BE45A8D9C2ECCULL,
		0xE1A1F54BFC81681CULL,
		0xA429E1784E30D630ULL,
		0x59EAA02E5CF035EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B560934826BB3DFULL,
		0x523F9ED25A24D89AULL,
		0x01A4D8FF48C7F586ULL,
		0x738909359974A449ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xFFF6F3A5D01A4BC4ULL,
		0x1965D31230F547F1ULL,
		0x866AA02881F7E30FULL,
		0x1760F53F0ABE944BULL,
		0xF77695E1093A34C6ULL,
		0x3779332D28014858ULL,
		0x60385E8079DA182AULL,
		0xF22E01C9B020D584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB91330D2EBE2680ULL,
		0x55636BC621260526ULL,
		0xCEC8A73A98577953ULL,
		0x0A35392F2F9E45F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9EB71D1A803C1620ULL,
		0xF950B8BC1962FAF3ULL,
		0x0C1C7CD058F6B524ULL,
		0xADAEB11F95179304ULL,
		0x1775E2E3AC489060ULL,
		0xFA942AA8B336B5ACULL,
		0xFA615D01DC26A47DULL,
		0x85ED8A7A6FA8417AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A36CAE61301876BULL,
		0x2B4F0DC6B381F27FULL,
		0x36904B1706B31FD8ULL,
		0x0EF13F4C28114B45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x2ED3FD83B9ABFB44ULL,
		0xF3F4E155EB512F59ULL,
		0x2FD361F9CD12E04EULL,
		0x3BD74E2C5E395527ULL,
		0x7D776B1DCFF45D8BULL,
		0x3706737834BEB032ULL,
		0xB6335D3406C76EC3ULL,
		0xA513588B8EA97ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE8DE3F097F1E189ULL,
		0x1EEA052DBF9F56D7ULL,
		0x3B7337B2CEAD5149ULL,
		0x3CB672E38B618FB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9197D7A57A369D5BULL,
		0x2A7F15232B3614E6ULL,
		0x95619B81B20267E0ULL,
		0xE6751AA3FA404397ULL,
		0xCF92C025D4F8BD01ULL,
		0x8F77241812E2BFAFULL,
		0x31E1B0B143C0EA57ULL,
		0xB1B8D61B9905E5CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61605D431722AF83ULL,
		0x762E70B5F8DE88FFULL,
		0xFCE1D5D1C0A530DFULL,
		0x47E4E2BCB1206058ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x9C25BB5B369EBB38ULL,
		0x4EFE2F7337A207C6ULL,
		0xAD2C7F238C15B7A5ULL,
		0xB99657329EEB5592ULL,
		0x775A7B8F74E5346DULL,
		0x3728FA965871D504ULL,
		0xC92EB8F1A99DEE15ULL,
		0xFC7837E05AFEEBC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x539412A690A4890AULL,
		0x7F1361C45887A670ULL,
		0x8A1BF302B9870ECBULL,
		0x336EA28020C25586ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xE93D9084E05A7B9AULL,
		0x535F17B66E8A4BBAULL,
		0x19091FD2E4E8BEE8ULL,
		0x249AB10D19278169ULL,
		0xB77C82FC67E9B6ADULL,
		0xE69539885DD9344FULL,
		0x1A5E5BFFCC1C2E89ULL,
		0xC47BDBA007EF0E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B901FC4D0B9D96ULL,
		0x8D85A1F45CC80F90ULL,
		0x030AC7CB3117A760ULL,
		0x4EFD4ACE46A39CFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x3BA81B714681BCFFULL,
		0x99B4BA98CCF68AA0ULL,
		0x049898609382A605ULL,
		0xEC8F0A656AEF4647ULL,
		0x25E8E18C28DB76E6ULL,
		0xB25CF1692CAE9B92ULL,
		0x4D7AEF5175C88E22ULL,
		0x94457D5B0F9BBA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC39963F5715667AULL,
		0x138090356EE1A251ULL,
		0x84D81E780F47BF2CULL,
		0x6EDFA5E9BC0CF954ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x15AD06AF3BB5857CULL,
		0x6E828E29D6232D5BULL,
		0x4153EBCF1595D131ULL,
		0xAD441473BE98273BULL,
		0xF5D2B5A319BE5F24ULL,
		0x07F4F85EB04CAD52ULL,
		0x888BF61FFC12EA3CULL,
		0xF998141AADCE942EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F3FCE50DF7AA65ULL,
		0x9CDF6C380184E7ABULL,
		0x861A748E8064961AULL,
		0x39D710698B422623ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x4003243464410523ULL,
		0xB8883113FAB9EBC9ULL,
		0x7156F0CE7FA4BFFAULL,
		0xA086D845DC6343D1ULL,
		0x97327F43875556E8ULL,
		0x15FB144C24B62D75ULL,
		0xDFEB95C1055CF246ULL,
		0xB1FDC0F785F6ADEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB182083A7AEBEF95ULL,
		0xFBCD34616DC4AB3DULL,
		0xAE4F2B754B70B661ULL,
		0x0C317D03BF01156CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xC63F0241FE111D02ULL,
		0xEDAF33CA261FE04BULL,
		0x7D2D018039FC42DDULL,
		0xF528E567E195F8FAULL,
		0x43C064373B761C34ULL,
		0xCC5681CC5A572032ULL,
		0x3E8852264EB4AEB0ULL,
		0xCB473FB718E30A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4CDE274D1995154ULL,
		0x4286781F8F0EA7C1ULL,
		0xC569332FE8CE311CULL,
		0x21BC5A95934985EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x121C8BCE8F5A8A6EULL,
		0x2DDBB84E29003AC0ULL,
		0x90DDEC3F99415B62ULL,
		0x3E6C170681BB1D01ULL,
		0x1EAB21E7BA198CFBULL,
		0x18DF1D5A374EB70EULL,
		0xBC52F1BC7FB4AE98ULL,
		0x476119BC682D10F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8394342F25793FULL,
		0xDEFA13B25EAF66D8ULL,
		0x852DCE3A8E1345F5ULL,
		0x56D5E8FDF86BA155ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0xA5896C660FFCC1B9ULL,
		0x87E44AAE11E9A842ULL,
		0x843B920D06D2BB98ULL,
		0x9E27AA6A69C4FBEEULL,
		0x86621F32916ADF61ULL,
		0x5F178C29DB467063ULL,
		0x46D827D80901E341ULL,
		0xF2AB3237B009281DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x981A0DE7A5D9EF8AULL,
		0xA56318E49E5E5708ULL,
		0x08517C1E5D1A774CULL,
		0x23911EAE8B20F047ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x40894B3778E970FEULL,
		0x0AE09C245141B2F9ULL,
		0xCC8A56B4131F88CAULL,
		0x8525886E996C0A5BULL,
		0x8609D4A017EA6402ULL,
		0x333403143F7B1084ULL,
		0xF40DE83F92A3F547ULL,
		0xC258B5523E99FC57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25FEDAFB05B44D98ULL,
		0xA4991125BD8626A5ULL,
		0x069AD023D775F15BULL,
		0x5E5072A3E4477F6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
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
		0x05D15B601D7E81B1ULL,
		0x7C69EFE4F8EE9047ULL,
		0xA119B38E7B4049C5ULL,
		0xB25A8164248501E3ULL,
		0x7912EF86B1CE53A7ULL,
		0x0E2BA879E2A16FD7ULL,
		0x4ADB6E3F2B148990ULL,
		0xE8249BCAEF132E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA0E95E821EF1ADULL,
		0x96E4F1FC9CE52A42ULL,
		0xBDAC10EEE04CB527ULL,
		0x27C9A183A15DEBC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
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