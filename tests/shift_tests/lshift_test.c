#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6936798C3A155F3FULL,
		0xB5E8E3609023DB6DULL,
		0x458870BBE924CC89ULL,
		0xA39957CDF9BC9E45ULL,
		0x351E2A9418EADDB5ULL,
		0x721A4A5CF048979DULL,
		0x0EF35DF7FFE9CB9FULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x6798C3A155F3F000ULL,
		0x8E3609023DB6D693ULL,
		0x870BBE924CC89B5EULL,
		0x957CDF9BC9E45458ULL,
		0xE2A9418EADDB5A39ULL,
		0xA4A5CF048979D351ULL,
		0x35DF7FFE9CB9F721ULL,
		0x00000000000000EFULL
	}};
	int shift = 12;
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
		0x4CC9C0E03E7720E8ULL,
		0x7581FDDAA3770DDBULL,
		0x1D43E55A4B2CCD42ULL,
		0xE1E36ED73ED813F5ULL,
		0x89573F8B8BA9F96FULL,
		0xE3B88AC6937C84F3ULL,
		0x72F432A24684F5EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20E8000000000000ULL,
		0x0DDB4CC9C0E03E77ULL,
		0xCD427581FDDAA377ULL,
		0x13F51D43E55A4B2CULL,
		0xF96FE1E36ED73ED8ULL,
		0x84F389573F8B8BA9ULL,
		0xF5EFE3B88AC6937CULL,
		0x000072F432A24684ULL
	}};
	shift = 48;
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
		0xB9C09123949AAF97ULL,
		0x6A9192F19D9CE520ULL,
		0x27668868D5C1B365ULL,
		0xA2A3D5835310D392ULL,
		0x785CECE3B17A05F5ULL,
		0x1A8C29B945D37C73ULL,
		0x41BEB592C9C5F2DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D57CB8000000000ULL,
		0xCE72905CE04891CAULL,
		0xE0D9B2B548C978CEULL,
		0x8869C913B344346AULL,
		0xBD02FAD151EAC1A9ULL,
		0xE9BE39BC2E7671D8ULL,
		0xE2F96F8D4614DCA2ULL,
		0x00000020DF5AC964ULL
	}};
	shift = 39;
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
		0xA71928DEB8791F78ULL,
		0xB108973A2B6E8E8CULL,
		0xC4B13B5A6F626685ULL,
		0xFD206B0ED0A7896DULL,
		0x1E974D00FBB7915EULL,
		0xB311095DEE1BD5EFULL,
		0x506FCEBE4B6BF47CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC0000000000000ULL,
		0x746538C946F5C3C8ULL,
		0x342D8844B9D15B74ULL,
		0x4B6E2589DAD37B13ULL,
		0x8AF7E9035876853CULL,
		0xAF78F4BA6807DDBCULL,
		0xA3E598884AEF70DEULL,
		0x0002837E75F25B5FULL
	}};
	shift = 51;
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
		0x54D638EBF0D1C245ULL,
		0xDF514B197F063C6AULL,
		0x91513E730526C3F3ULL,
		0x52D3337E9266577FULL,
		0x841878DB91B34997ULL,
		0xAD301D0AD29EEBFBULL,
		0xAC99ACBED661406AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBF0D1C245000000ULL,
		0x197F063C6A54D638ULL,
		0x730526C3F3DF514BULL,
		0x7E9266577F91513EULL,
		0xDB91B3499752D333ULL,
		0x0AD29EEBFB841878ULL,
		0xBED661406AAD301DULL,
		0x0000000000AC99ACULL
	}};
	shift = 24;
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
		0xF4C4ED3949453947ULL,
		0xBAC23EBB245691F6ULL,
		0x3167A37CD6D99AA7ULL,
		0xC4863053987FF42DULL,
		0x93EFC40E8626E915ULL,
		0xAC84E166488AE784ULL,
		0xF9BCD4F2ED812EAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0x6F4C4ED394945394ULL,
		0x7BAC23EBB245691FULL,
		0xD3167A37CD6D99AAULL,
		0x5C4863053987FF42ULL,
		0x493EFC40E8626E91ULL,
		0xAAC84E166488AE78ULL,
		0x0F9BCD4F2ED812EAULL
	}};
	shift = 60;
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
		0x880CC47446F71C02ULL,
		0x655B919F9AD25F97ULL,
		0x2967D5F5558F386EULL,
		0xC82EF8244AF0169BULL,
		0xC85C4BE88B7DB975ULL,
		0x96989DC96C40ECC2ULL,
		0xD40CE5F93D393A8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01988E88DEE38040ULL,
		0xAB7233F35A4BF2F1ULL,
		0x2CFABEAAB1E70DCCULL,
		0x05DF04895E02D365ULL,
		0x0B897D116FB72EB9ULL,
		0xD313B92D881D9859ULL,
		0x819CBF27A7275152ULL,
		0x000000000000001AULL
	}};
	shift = 5;
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
		0x90BAAAF6FA1508DCULL,
		0x81754B493FA750BAULL,
		0x722080E934434A91ULL,
		0xE66054CF1904FF3EULL,
		0xAB957E01AEF8DFD0ULL,
		0xE0CBF9E21B1E3D55ULL,
		0xFAF5010AA767B149ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8542370000000000ULL,
		0xE9D42EA42EAABDBEULL,
		0x10D2A4605D52D24FULL,
		0x413FCF9C88203A4DULL,
		0xBE37F439981533C6ULL,
		0xC78F556AE55F806BULL,
		0xD9EC527832FE7886ULL,
		0x0000003EBD4042A9ULL
	}};
	shift = 38;
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
		0x7BD8696AD412D6DCULL,
		0x8A3DCB9291C5D229ULL,
		0xA1FEA9236930D757ULL,
		0xFD2D572BE04DF0CCULL,
		0x191532038AD112D3ULL,
		0xBE82AC3C215DEFEFULL,
		0x202A897A6595EAFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD8696AD412D6DCULL,
		0x8A3DCB9291C5D229ULL,
		0xA1FEA9236930D757ULL,
		0xFD2D572BE04DF0CCULL,
		0x191532038AD112D3ULL,
		0xBE82AC3C215DEFEFULL,
		0x202A897A6595EAFCULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x998D0A6F7EE9177CULL,
		0xAEF44A6A34BDC071ULL,
		0x44B8A3362247E91EULL,
		0x6B76A383C17F20C3ULL,
		0xB080DBBCA91BAA43ULL,
		0x11A3AC0AF4DC2BA2ULL,
		0x82FE104A5A098411ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0A6F7EE9177C000ULL,
		0x44A6A34BDC071998ULL,
		0x8A3362247E91EAEFULL,
		0x6A383C17F20C344BULL,
		0x0DBBCA91BAA436B7ULL,
		0x3AC0AF4DC2BA2B08ULL,
		0xE104A5A09841111AULL,
		0x000000000000082FULL
	}};
	shift = 12;
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
		0x9EB7FA15EBCC0508ULL,
		0x7861C51C1A43B643ULL,
		0x8A1EAC6507E9DEABULL,
		0x1F9C95E880D8A87BULL,
		0x4F03F97740E3CE08ULL,
		0x3AA3CE3907E27ECAULL,
		0x2A903C60CAE8D1A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857AF30142000000ULL,
		0x470690ED90E7ADFEULL,
		0x1941FA77AADE1871ULL,
		0x7A20362A1EE287ABULL,
		0x5DD038F38207E725ULL,
		0x8E41F89FB293C0FEULL,
		0x1832BA34684EA8F3ULL,
		0x00000000000AA40FULL
	}};
	shift = 22;
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
		0xE03D0F423A39E122ULL,
		0x5332D4A4E120F9DCULL,
		0x6A6B12AD536D2129ULL,
		0x9469E94AA855F7A5ULL,
		0x023717D37524B83BULL,
		0x2CA80EB3E8973902ULL,
		0x293FF9CECD3A34EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0xCE03D0F423A39E12ULL,
		0x95332D4A4E120F9DULL,
		0x56A6B12AD536D212ULL,
		0xB9469E94AA855F7AULL,
		0x2023717D37524B83ULL,
		0xB2CA80EB3E897390ULL,
		0x0293FF9CECD3A34EULL
	}};
	shift = 60;
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
		0xEA080D76CEFDACCCULL,
		0xAB257EBDDA47CE78ULL,
		0xD6CB44D6B87C2904ULL,
		0x6378413F35C35109ULL,
		0xE79AB23DD024252CULL,
		0xD971828A6870A50BULL,
		0xAAA687D9F60D1D96ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50406BB677ED6660ULL,
		0x592BF5EED23E73C7ULL,
		0xB65A26B5C3E14825ULL,
		0x1BC209F9AE1A884EULL,
		0x3CD591EE81212963ULL,
		0xCB8C14534385285FULL,
		0x55343ECFB068ECB6ULL,
		0x0000000000000005ULL
	}};
	shift = 3;
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
		0x339D3D15D15B743BULL,
		0x0302CA34D93BEFB3ULL,
		0x0FDD30B89D0136BFULL,
		0x018C491DA85C6E65ULL,
		0xA680F5A46151291DULL,
		0x2470A4A6B2210D22ULL,
		0xD1A797D0D8CD88FBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8760000000000000ULL,
		0xF66673A7A2BA2B6EULL,
		0xD7E06059469B277DULL,
		0xCCA1FBA61713A026ULL,
		0x23A0318923B50B8DULL,
		0xA454D01EB48C2A25ULL,
		0x1F648E1494D64421ULL,
		0x001A34F2FA1B19B1ULL
	}};
	shift = 53;
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
		0xF974D6794C9CBA41ULL,
		0xD507C5A7C3917C42ULL,
		0x3235D80DC4069EEEULL,
		0xEE1BAFA2C7DE6626ULL,
		0xD8E7512DB70214E4ULL,
		0x0D26348366BE2FDCULL,
		0xB25D03303A2A4BEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59E53272E9040000ULL,
		0x169F0E45F10BE5D3ULL,
		0x6037101A7BBB541FULL,
		0xBE8B1F799898C8D7ULL,
		0x44B6DC085393B86EULL,
		0xD20D9AF8BF73639DULL,
		0x0CC0E8A92FA83498ULL,
		0x000000000002C974ULL
	}};
	shift = 18;
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
		0xB187A53AC16110AFULL,
		0x897C361FFB1CF9AFULL,
		0x2B4353827B156F72ULL,
		0x6C84DA5BC30BF676ULL,
		0x4CB56EA92EB473ECULL,
		0x0E72041EFBB04C49ULL,
		0xB185187A10EDCD51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BC000000000000ULL,
		0xE6BEC61E94EB0584ULL,
		0xBDCA25F0D87FEC73ULL,
		0xD9D8AD0D4E09EC55ULL,
		0xCFB1B213696F0C2FULL,
		0x312532D5BAA4BAD1ULL,
		0x354439C8107BEEC1ULL,
		0x0002C61461E843B7ULL
	}};
	shift = 50;
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
		0x97714778FE5FA233ULL,
		0x1AAFE72B3E20C579ULL,
		0x72DE6A8D681CBF6CULL,
		0x1F1E968018A90DF5ULL,
		0x9CEA08BBC6F41C14ULL,
		0x94BA64036FF7BB47ULL,
		0xE0EA760663F607D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC51DE3F97E88CC0ULL,
		0xABF9CACF88315E65ULL,
		0xB79AA35A072FDB06ULL,
		0xC7A5A0062A437D5CULL,
		0x3A822EF1BD070507ULL,
		0x2E9900DBFDEED1E7ULL,
		0x3A9D8198FD81F5E5ULL,
		0x0000000000000038ULL
	}};
	shift = 6;
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
		0xFD83E8634D91F364ULL,
		0xB302014B1EFB1EF6ULL,
		0x127B6B4CFB9DC7D6ULL,
		0x370410ED382F13E1ULL,
		0x27E0F841E5CDCD75ULL,
		0x888281C1CC1492DDULL,
		0xF00EB6B2BCC87AF7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34D91F3640000000ULL,
		0xB1EFB1EF6FD83E86ULL,
		0xCFB9DC7D6B302014ULL,
		0xD382F13E1127B6B4ULL,
		0x1E5CDCD75370410EULL,
		0x1CC1492DD27E0F84ULL,
		0x2BCC87AF7888281CULL,
		0x000000000F00EB6BULL
	}};
	shift = 28;
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
		0x7ED954EC237BDDA6ULL,
		0x2473E48606C731C8ULL,
		0x7815A35B1DB7B3E4ULL,
		0x188328CDB3412E43ULL,
		0xB36FF191014C83ACULL,
		0x2A16A02D4544CF0AULL,
		0x8B0C70ABAA38BA9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6CAA7611BDEED30ULL,
		0x239F243036398E43ULL,
		0xC0AD1AD8EDBD9F21ULL,
		0xC419466D9A09721BULL,
		0x9B7F8C880A641D60ULL,
		0x50B5016A2A267855ULL,
		0x5863855D51C5D4E1ULL,
		0x0000000000000004ULL
	}};
	shift = 3;
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
		0xB9F8C6A3AD08D642ULL,
		0x4606946A10F41200ULL,
		0x3DD6238F98481336ULL,
		0x35261436CDB2D46FULL,
		0x1FB0F1C8F159BD68ULL,
		0xDC201675084BE497ULL,
		0x0127C957E1F88C65ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6846B21000000000ULL,
		0x87A09005CFC6351DULL,
		0xC24099B23034A350ULL,
		0x6D96A379EEB11C7CULL,
		0x8ACDEB41A930A1B6ULL,
		0x425F24B8FD878E47ULL,
		0x0FC4632EE100B3A8ULL,
		0x00000000093E4ABFULL
	}};
	shift = 35;
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
		0x59BF6951BC5085CFULL,
		0xF543BFFE78E77027ULL,
		0xE93237B770A4E2E0ULL,
		0x4000CA175EE2F8A7ULL,
		0x856A0F010F1AD4B9ULL,
		0x8323BD0867FAD899ULL,
		0x25B432235C75C05AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C00000000000000ULL,
		0x9D66FDA546F14217ULL,
		0x83D50EFFF9E39DC0ULL,
		0x9FA4C8DEDDC2938BULL,
		0xE50003285D7B8BE2ULL,
		0x6615A83C043C6B52ULL,
		0x6A0C8EF4219FEB62ULL,
		0x0096D0C88D71D701ULL
	}};
	shift = 58;
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
		0xD0F2BD8D777556AEULL,
		0x0014016388C84BF2ULL,
		0x967FD5EB9D863141ULL,
		0x538A1F5A6ED10E92ULL,
		0x4D0E9C0141474347ULL,
		0x86D9631BACD40906ULL,
		0x659E43BE442342D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE0000000000000ULL,
		0xBF2D0F2BD8D77755ULL,
		0x1410014016388C84ULL,
		0xE92967FD5EB9D863ULL,
		0x347538A1F5A6ED10ULL,
		0x9064D0E9C0141474ULL,
		0x2D186D9631BACD40ULL,
		0x000659E43BE44234ULL
	}};
	shift = 52;
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
		0x6410D649E62058EAULL,
		0xAEF4BB0004B6B617ULL,
		0xC50D1D4F53D581C1ULL,
		0x049E4022F2DBDDF3ULL,
		0x134A6011838DE510ULL,
		0x269192AFEA16D498ULL,
		0x354A6A36B8AE7C1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0x5D90435927988163ULL,
		0x06BBD2EC0012DAD8ULL,
		0xCF1434753D4F5607ULL,
		0x401279008BCB6F77ULL,
		0x604D2980460E3794ULL,
		0x689A464ABFA85B52ULL,
		0x00D529A8DAE2B9F0ULL
	}};
	shift = 58;
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
		0x434494FBC5EF7A98ULL,
		0x570221E33A27F6BFULL,
		0xE5FEB615C9785C1DULL,
		0x455E482E2B1316A3ULL,
		0x4CF158C224B6D52FULL,
		0xBE1C7400921130ADULL,
		0xCF390D49367B073BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A7DE2F7BD4C0000ULL,
		0x10F19D13FB5FA1A2ULL,
		0x5B0AE4BC2E0EAB81ULL,
		0x241715898B51F2FFULL,
		0xAC61125B6A97A2AFULL,
		0x3A0049089856A678ULL,
		0x86A49B3D839DDF0EULL,
		0x000000000000679CULL
	}};
	shift = 15;
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
		0xCF5424BCB97BAA21ULL,
		0x697946D328E2AF9CULL,
		0xEABCE1E397168AB0ULL,
		0x4729B8F297ADD575ULL,
		0x0DAF0A97FE0268E7ULL,
		0xD276F05ACD61D2DDULL,
		0x04ED60FFE1988879ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7972F75442000000ULL,
		0xA651C55F399EA849ULL,
		0xC72E2D1560D2F28DULL,
		0xE52F5BAAEBD579C3ULL,
		0x2FFC04D1CE8E5371ULL,
		0xB59AC3A5BA1B5E15ULL,
		0xFFC33110F3A4EDE0ULL,
		0x000000000009DAC1ULL
	}};
	shift = 25;
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
		0xD2DC81E3E1752FD3ULL,
		0xE9CCA2F0C58133E9ULL,
		0x1B0D713CAC52BFDDULL,
		0x5010D48F09F3F993ULL,
		0x7C37918C168D5293ULL,
		0xD29C69D65FD1C9B5ULL,
		0x646830A24691B3A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F1F0BA97E98000ULL,
		0x517862C099F4E96EULL,
		0xB89E56295FEEF4E6ULL,
		0x6A4784F9FCC98D86ULL,
		0xC8C60B46A949A808ULL,
		0x34EB2FE8E4DABE1BULL,
		0x18512348D9D3694EULL,
		0x0000000000003234ULL
	}};
	shift = 15;
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
		0x84995FDDA2A624E7ULL,
		0x3FC8D3637EE5E913ULL,
		0x7E957D0110961519ULL,
		0xDB00E95AF271127BULL,
		0x2120A499CD32DE5FULL,
		0x4C19257378A7B9D5ULL,
		0xD288323594171B1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDA2A624E700000ULL,
		0x3637EE5E91384995ULL,
		0xD01109615193FC8DULL,
		0x95AF271127B7E957ULL,
		0x499CD32DE5FDB00EULL,
		0x57378A7B9D52120AULL,
		0x23594171B1A4C192ULL,
		0x00000000000D2883ULL
	}};
	shift = 20;
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
		0xF993C453E680DCEEULL,
		0x28B987D46EE07FC4ULL,
		0xC43D14C2601C6D6AULL,
		0x0C8BAEA72BBAFCDAULL,
		0x232426785C11B450ULL,
		0xF257A8C3FA13C094ULL,
		0x811A1B6059D42C67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993C453E680DCEE0ULL,
		0x8B987D46EE07FC4FULL,
		0x43D14C2601C6D6A2ULL,
		0xC8BAEA72BBAFCDACULL,
		0x32426785C11B4500ULL,
		0x257A8C3FA13C0942ULL,
		0x11A1B6059D42C67FULL,
		0x0000000000000008ULL
	}};
	shift = 4;
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
		0x0A125456233E48D9ULL,
		0x8C697DACD14528F7ULL,
		0xA853E314C57D72BFULL,
		0x58F3D44A109AF60DULL,
		0xF67011D0327FC252ULL,
		0x9E03DAAC18C39416ULL,
		0x13DD3FC435576790ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2B119F246C80000ULL,
		0xED668A2947B85092ULL,
		0x18A62BEB95FC634BULL,
		0xA25084D7B06D429FULL,
		0x8E8193FE1292C79EULL,
		0xD560C61CA0B7B380ULL,
		0xFE21AABB3C84F01EULL,
		0x0000000000009EE9ULL
	}};
	shift = 19;
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
		0x226F380A6FD2B092ULL,
		0xCF509CCE1E5A7A92ULL,
		0x0211687426D05B1AULL,
		0x64D76DC50DBB3525ULL,
		0x560E76F8686F5CF7ULL,
		0xAD3450F3EDBA4483ULL,
		0x44F215B15E3B1CCEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC248000000000000ULL,
		0xEA4889BCE029BF4AULL,
		0x6C6B3D4273387969ULL,
		0xD4940845A1D09B41ULL,
		0x73DD935DB71436ECULL,
		0x120D5839DBE1A1BDULL,
		0x733AB4D143CFB6E9ULL,
		0x000113C856C578ECULL
	}};
	shift = 50;
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
		0x859EC2AA43C6D4CCULL,
		0x9A487ACDD4960C69ULL,
		0xFC2FB24955A68652ULL,
		0xA2042C9B38700A26ULL,
		0xFFC9426BED57D247ULL,
		0xF0ED6EEB38E9CF1FULL,
		0x9F96478DB88A6F30ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x615521E36A660000ULL,
		0x3D66EA4B0634C2CFULL,
		0xD924AAD343294D24ULL,
		0x164D9C3805137E17ULL,
		0xA135F6ABE923D102ULL,
		0xB7759C74E78FFFE4ULL,
		0x23C6DC4537987876ULL,
		0x0000000000004FCBULL
	}};
	shift = 15;
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
		0xF8005723FFC4ADF5ULL,
		0x798505696B5A4873ULL,
		0x0AC2E60CDCAE79B5ULL,
		0x0A4FB2B06702FD39ULL,
		0x47DCABE1D23596B9ULL,
		0x2C633C41A5433E24ULL,
		0xD9AF0A1875DD3742ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B91FFE256FA800ULL,
		0x282B4B5AD2439FC0ULL,
		0x173066E573CDABCCULL,
		0x7D95833817E9C856ULL,
		0xE55F0E91ACB5C852ULL,
		0x19E20D2A19F1223EULL,
		0x7850C3AEE9BA1163ULL,
		0x00000000000006CDULL
	}};
	shift = 11;
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
		0x685B31BF4517FB9DULL,
		0x5EA50D58B4B320F8ULL,
		0x481709E7E3A00CB7ULL,
		0xB7D694C221DA0DAAULL,
		0x54BFF889EBE43D06ULL,
		0x86673C03F2B02787ULL,
		0x202703CAB127D89AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC6FD145FEE7400ULL,
		0x943562D2CC83E1A1ULL,
		0x5C279F8E8032DD7AULL,
		0x5A5308876836A920ULL,
		0xFFE227AF90F41ADFULL,
		0x9CF00FCAC09E1D52ULL,
		0x9C0F2AC49F626A19ULL,
		0x0000000000000080ULL
	}};
	shift = 10;
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
		0x1B5A0DFDDD1EC4A9ULL,
		0xC41975C3EA1C35E6ULL,
		0x4E0D7DC44E27D43DULL,
		0x0C6BF16D5B4BAA48ULL,
		0xF41358BBA3160029ULL,
		0x2F7FF151B96E1C70ULL,
		0x445876D2AA3624F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEEE8F6254800000ULL,
		0xE1F50E1AF30DAD06ULL,
		0xE22713EA1EE20CBAULL,
		0xB6ADA5D5242706BEULL,
		0x5DD18B00148635F8ULL,
		0xA8DCB70E387A09ACULL,
		0x69551B127B97BFF8ULL,
		0x0000000000222C3BULL
	}};
	shift = 23;
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
		0x43CF8C684430C910ULL,
		0xD683B8759223C76EULL,
		0x7D938F7F481D8F91ULL,
		0x22C63901597385D0ULL,
		0x3ACFD84FC08130C7ULL,
		0x894E51FEE5E213B3ULL,
		0x5FCE0E5ECF9AD9A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x6E43CF8C684430C9ULL,
		0x91D683B8759223C7ULL,
		0xD07D938F7F481D8FULL,
		0xC722C63901597385ULL,
		0xB33ACFD84FC08130ULL,
		0xA4894E51FEE5E213ULL,
		0x005FCE0E5ECF9AD9ULL
	}};
	shift = 56;
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
		0xD0611B9EA4EF9AA5ULL,
		0xE2DA10542D626024ULL,
		0xC5D05332F811DAA5ULL,
		0xCD2E2429E1C786CCULL,
		0xBA38880A24D796FAULL,
		0x71D95E0D967FCD00ULL,
		0xAFED20C2620BEE2EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2800000000000000ULL,
		0x268308DCF5277CD5ULL,
		0x2F16D082A16B1301ULL,
		0x662E829997C08ED5ULL,
		0xD66971214F0E3C36ULL,
		0x05D1C4405126BCB7ULL,
		0x738ECAF06CB3FE68ULL,
		0x057F690613105F71ULL
	}};
	shift = 59;
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
		0x09C263816EDADECCULL,
		0xD3CC9FF035C106F9ULL,
		0x6D68EC97176F2A62ULL,
		0xF3DD5F1056F0AF31ULL,
		0x844D388DDB8B415DULL,
		0xAE4326956A73877FULL,
		0x5404672ACD501925ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05BB6B7B30000000ULL,
		0xC0D7041BE427098EULL,
		0x5C5DBCA98B4F327FULL,
		0x415BC2BCC5B5A3B2ULL,
		0x376E2D0577CF757CULL,
		0x55A9CE1DFE1134E2ULL,
		0xAB35406496B90C9AULL,
		0x000000000150119CULL
	}};
	shift = 26;
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
		0x6EB7978CB1EDC80DULL,
		0xCC6537CFFEB49E88ULL,
		0x7370F30EAF47C96EULL,
		0x789B15429B5DD774ULL,
		0x9FEAE92147A28EBFULL,
		0x92E3C1CE1A783F0AULL,
		0x97920B7E05EC9264ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B7203400000000ULL,
		0xFAD27A21BADE5E32ULL,
		0xBD1F25BB3194DF3FULL,
		0x6D775DD1CDC3CC3AULL,
		0x1E8A3AFDE26C550AULL,
		0x69E0FC2A7FABA485ULL,
		0x17B249924B8F0738ULL,
		0x000000025E482DF8ULL
	}};
	shift = 34;
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
		0xE4511A10D8F0C5A0ULL,
		0xA0722FB9801D8216ULL,
		0x37A5D9156D525973ULL,
		0xEC47D5B1E7C2A9B7ULL,
		0x4565D229763FEADAULL,
		0xA33968327F488E1BULL,
		0x1D6280B1EB4E26E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684363C316800000ULL,
		0xBEE60076085B9144ULL,
		0x6455B54965CE81C8ULL,
		0x56C79F0AA6DCDE97ULL,
		0x48A5D8FFAB6BB11FULL,
		0xA0C9FD22386D1597ULL,
		0x02C7AD389B868CE5ULL,
		0x000000000000758AULL
	}};
	shift = 18;
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
		0x312943C1C7FB20DCULL,
		0x4C0AF9F93F9EFC26ULL,
		0xAB37FB0F85338067ULL,
		0x56DC55DFA6B5C4A1ULL,
		0x322FF61C91641D84ULL,
		0x27D07F8D0BEEFC16ULL,
		0x56F67F41C9C57916ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x31894A1E0E3FD906ULL,
		0x3A6057CFC9FCF7E1ULL,
		0x0D59BFD87C299C03ULL,
		0x22B6E2AEFD35AE25ULL,
		0xB1917FB0E48B20ECULL,
		0xB13E83FC685F77E0ULL,
		0x02B7B3FA0E4E2BC8ULL
	}};
	shift = 59;
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
		0x27B2527CC6152E66ULL,
		0xF3DE6B7FA2E86BE6ULL,
		0x1C09D5A24D445E8BULL,
		0xEA4A9B247D002EF8ULL,
		0x6E04DF53810A1FA3ULL,
		0xD0D1EE9EEB46188AULL,
		0x67CB9A0EFD17ADD5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31854B9980000000ULL,
		0xE8BA1AF989EC949FULL,
		0x935117A2FCF79ADFULL,
		0x1F400BBE07027568ULL,
		0xE04287E8FA92A6C9ULL,
		0xBAD186229B8137D4ULL,
		0xBF45EB7574347BA7ULL,
		0x0000000019F2E683ULL
	}};
	shift = 30;
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
		0x9EE803C383B9214BULL,
		0x33001D7237064BABULL,
		0x7F4D20D62574DBDEULL,
		0xD5234EF2302DDC9AULL,
		0x2509D51A8C284636ULL,
		0x5909139F0DB2E19BULL,
		0x1C2526B37B71D3E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x401E1C1DC90A5800ULL,
		0x00EB91B8325D5CF7ULL,
		0x6906B12BA6DEF198ULL,
		0x1A7791816EE4D3FAULL,
		0x4EA8D4614231B6A9ULL,
		0x489CF86D970CD928ULL,
		0x29359BDB8E9F22C8ULL,
		0x00000000000000E1ULL
	}};
	shift = 11;
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
		0x67EECC8AD485E5B7ULL,
		0xED62E9B41E335684ULL,
		0xA2121E23FCB1E256ULL,
		0xB042362814B1B0B1ULL,
		0x4D43CC845FD9A51DULL,
		0x159E5401AA6C8D5CULL,
		0xA79C4EAC6C5F6E74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EECC8AD485E5B70ULL,
		0xD62E9B41E3356846ULL,
		0x2121E23FCB1E256EULL,
		0x042362814B1B0B1AULL,
		0xD43CC845FD9A51DBULL,
		0x59E5401AA6C8D5C4ULL,
		0x79C4EAC6C5F6E741ULL,
		0x000000000000000AULL
	}};
	shift = 4;
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
		0x24F6902B1B13EC86ULL,
		0x1C7283A4990229F8ULL,
		0x3EB08FC143C06E31ULL,
		0xD1F4DDB761B43588ULL,
		0x8ED62DC22AC6F15EULL,
		0x92A2CC8D55E62EB4ULL,
		0x83358EB4924A1F6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6902B1B13EC860ULL,
		0xC7283A4990229F82ULL,
		0xEB08FC143C06E311ULL,
		0x1F4DDB761B435883ULL,
		0xED62DC22AC6F15EDULL,
		0x2A2CC8D55E62EB48ULL,
		0x3358EB4924A1F6B9ULL,
		0x0000000000000008ULL
	}};
	shift = 4;
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
		0x1E9A05E270C36BA4ULL,
		0x06E42CBF9859B75EULL,
		0x6C398DCE158EE010ULL,
		0xE69DED96BF111253ULL,
		0x33BEB14C60C9A165ULL,
		0x902483ADB5707800ULL,
		0xCBDE4335A8721357ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A05E270C36BA400ULL,
		0xE42CBF9859B75E1EULL,
		0x398DCE158EE01006ULL,
		0x9DED96BF1112536CULL,
		0xBEB14C60C9A165E6ULL,
		0x2483ADB570780033ULL,
		0xDE4335A872135790ULL,
		0x00000000000000CBULL
	}};
	shift = 8;
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
		0x9F398DB99BFE19CAULL,
		0xE1733E1AC8139D3DULL,
		0xD3F0DF250AA2368CULL,
		0x259626834DB3092AULL,
		0x4809312EA7B3027DULL,
		0x2017E8B7BBFB40CCULL,
		0x86F4205B37CC6935ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE731B7337FC33940ULL,
		0x2E67C3590273A7B3ULL,
		0x7E1BE4A15446D19CULL,
		0xB2C4D069B661255AULL,
		0x012625D4F6604FA4ULL,
		0x02FD16F77F681989ULL,
		0xDE840B66F98D26A4ULL,
		0x0000000000000010ULL
	}};
	shift = 5;
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
		0xEA3F1E4FD446BEF6ULL,
		0xCA9F16FDFD8C5740ULL,
		0x0DC21A407B75AB36ULL,
		0x305FCF05CAC00A7DULL,
		0xF7A20B27BB2F5A58ULL,
		0x52613FCB1C1DECA6ULL,
		0x9BCA2C4EC10DB2E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA88D7DEC000000ULL,
		0xFBFB18AE81D47E3CULL,
		0x80F6EB566D953E2DULL,
		0x0B958014FA1B8434ULL,
		0x4F765EB4B060BF9EULL,
		0x96383BD94DEF4416ULL,
		0x9D821B65C0A4C27FULL,
		0x0000000001379458ULL
	}};
	shift = 25;
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
		0x93BBBB2DEE67B13EULL,
		0x170C931D03A63289ULL,
		0x791FA0A54D6ADFABULL,
		0x7E2AD7989D8AC536ULL,
		0x32ED6B49DB2F8FE9ULL,
		0xC2063BA02BABF826ULL,
		0x5569D36D7E2D6888ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2DEE67B13E0000ULL,
		0x931D03A6328993BBULL,
		0xA0A54D6ADFAB170CULL,
		0xD7989D8AC536791FULL,
		0x6B49DB2F8FE97E2AULL,
		0x3BA02BABF82632EDULL,
		0xD36D7E2D6888C206ULL,
		0x0000000000005569ULL
	}};
	shift = 16;
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
		0x5584787DEA927D64ULL,
		0x28329B61CCFD6D55ULL,
		0xDBE9CC7BEDCA00B7ULL,
		0x9B9C551897EBD6DCULL,
		0xE05F5E895D3F71CEULL,
		0xE03E16AEF6877324ULL,
		0x9B9A3664ED907C68ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FBD524FAC800000ULL,
		0x6C399FADAAAAB08FULL,
		0x8F7DB94016E50653ULL,
		0xA312FD7ADB9B7D39ULL,
		0xD12BA7EE39D3738AULL,
		0xD5DED0EE649C0BEBULL,
		0xCC9DB20F8D1C07C2ULL,
		0x0000000000137346ULL
	}};
	shift = 21;
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
		0x5CCE65B757BDE12AULL,
		0x865C15455992F30FULL,
		0xB14FD1D3BC052244ULL,
		0xD3A5B2C665F38CC2ULL,
		0x403AB6306133124AULL,
		0x42CB4631A804178BULL,
		0xDC2568635ACDA004ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBABDEF0950000000ULL,
		0x2ACC97987AE6732DULL,
		0x9DE029122432E0AAULL,
		0x332F9C66158A7E8EULL,
		0x83099892569D2D96ULL,
		0x8D4020BC5A01D5B1ULL,
		0x1AD66D0022165A31ULL,
		0x0000000006E12B43ULL
	}};
	shift = 27;
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
		0xE2C2E8876D009A8DULL,
		0x707FF71D702482D3ULL,
		0xFDF72F6B26D33C61ULL,
		0x24D1CB8D05622616ULL,
		0xC3F63BD0BF17AA5BULL,
		0xA9714597DCFE7930ULL,
		0xE086CC7F35B50E51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D10EDA01351A000ULL,
		0xFEE3AE04905A7C58ULL,
		0xE5ED64DA678C2E0FULL,
		0x3971A0AC44C2DFBEULL,
		0xC77A17E2F54B649AULL,
		0x28B2FB9FCF26187EULL,
		0xD98FE6B6A1CA352EULL,
		0x0000000000001C10ULL
	}};
	shift = 13;
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
		0x41FB08B432BA88D8ULL,
		0x94C60F61CDB50D1EULL,
		0x560E7D968E437455ULL,
		0x600F7B98703B0A11ULL,
		0xDD889F859C2CF14FULL,
		0x4F07AC3E55D39067ULL,
		0x6C3A3AD7B23E77BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xF20FD845A195D446ULL,
		0xACA6307B0E6DA868ULL,
		0x8AB073ECB4721BA2ULL,
		0x7B007BDCC381D850ULL,
		0x3EEC44FC2CE1678AULL,
		0xE2783D61F2AE9C83ULL,
		0x0361D1D6BD91F3BDULL
	}};
	shift = 59;
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
		0x0E8E4F4D1A6783ECULL,
		0x19A15F044B67D540ULL,
		0xC140E6EF84391283ULL,
		0x7EDF05DC723032D6ULL,
		0xAF47302AB4C766E9ULL,
		0x85132F2385B4E999ULL,
		0x13B6FC81E3C2D7B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA68D33C1F6000000ULL,
		0x8225B3EAA0074727ULL,
		0x77C21C89418CD0AFULL,
		0xEE3918196B60A073ULL,
		0x155A63B374BF6F82ULL,
		0x91C2DA74CCD7A398ULL,
		0x40F1E16BD8C28997ULL,
		0x000000000009DB7EULL
	}};
	shift = 23;
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
		0xFBA4EA64A733569FULL,
		0x7D1B6608E2605251ULL,
		0x51B8298007F2484FULL,
		0x88B7B17E49ED819AULL,
		0x677E17F40B18D008ULL,
		0x4E32235F13EDE191ULL,
		0xB842ACF804976B05ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69F0000000000000ULL,
		0x251FBA4EA64A7335ULL,
		0x84F7D1B6608E2605ULL,
		0x19A51B8298007F24ULL,
		0x00888B7B17E49ED8ULL,
		0x191677E17F40B18DULL,
		0xB054E32235F13EDEULL,
		0x000B842ACF804976ULL
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
		0x2029EFC4B759170EULL,
		0x55ACB37419D5E90CULL,
		0xCC7343CFD4E5F32DULL,
		0x206CC10E71D7B9E0ULL,
		0xFA2D7E08FA62D952ULL,
		0x768E464BA8DE5556ULL,
		0x2DE8E9C801359255ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB870000000000000ULL,
		0x4861014F7E25BAC8ULL,
		0x996AAD659BA0CEAFULL,
		0xCF06639A1E7EA72FULL,
		0xCA91036608738EBDULL,
		0xAAB7D16BF047D316ULL,
		0x92ABB472325D46F2ULL,
		0x00016F474E4009ACULL
	}};
	shift = 51;
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
		0x33F2A4CD9E1C89DEULL,
		0x4B5A3D5BAC8E21E1ULL,
		0xED58C5CFE16B3789ULL,
		0x39AA4D66D5CCF3DEULL,
		0x6924965E2BE9F762ULL,
		0x0B0A2E8E1A926E21ULL,
		0x4811302D5468F23FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33F2A4CD9E1C89DEULL,
		0x4B5A3D5BAC8E21E1ULL,
		0xED58C5CFE16B3789ULL,
		0x39AA4D66D5CCF3DEULL,
		0x6924965E2BE9F762ULL,
		0x0B0A2E8E1A926E21ULL,
		0x4811302D5468F23FULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x6897F60DA59AA313ULL,
		0xA03534199A3663AEULL,
		0x3C1A593BE77235EEULL,
		0xAB26EE059FD3E624ULL,
		0xE2049CF9DB5C1DD8ULL,
		0xE631C26191B9BF39ULL,
		0xBF8AF986F5587E18ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D2CD51898000000ULL,
		0xCCD1B31D7344BFB0ULL,
		0xDF3B91AF7501A9A0ULL,
		0x2CFE9F3121E0D2C9ULL,
		0xCEDAE0EEC5593770ULL,
		0x0C8DCDF9CF1024E7ULL,
		0x37AAC3F0C7318E13ULL,
		0x0000000005FC57CCULL
	}};
	shift = 27;
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
		0xA92301754180DD57ULL,
		0x56072382A10A2CFCULL,
		0x8D738E1A5C81CEB6ULL,
		0x7EF84E6074AD5E39ULL,
		0x67BD3C513921DA30ULL,
		0xD5F9A6BE6ACC53A8ULL,
		0x20578EAE84A74647ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC05D50603755C000ULL,
		0xC8E0A8428B3F2A48ULL,
		0xE386972073AD9581ULL,
		0x13981D2B578E635CULL,
		0x4F144E48768C1FBEULL,
		0x69AF9AB314EA19EFULL,
		0xE3ABA129D191F57EULL,
		0x0000000000000815ULL
	}};
	shift = 14;
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
		0xFE60CCF68E702965ULL,
		0x0BDECDA0C363E0E8ULL,
		0xE90857E35303B196ULL,
		0x7DDB718A9628A115ULL,
		0x24C29D3CE642D29EULL,
		0x28F845BB196FC8CDULL,
		0x155304B482BED3D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68E7029650000000ULL,
		0x0C363E0E8FE60CCFULL,
		0x35303B1960BDECDAULL,
		0xA9628A115E90857EULL,
		0xCE642D29E7DDB718ULL,
		0xB196FC8CD24C29D3ULL,
		0x482BED3D528F845BULL,
		0x000000000155304BULL
	}};
	shift = 28;
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
		0xB41455E3DCCE2B5BULL,
		0xA3B5A633E0416E84ULL,
		0xDEEE27A1E68EEE41ULL,
		0x5A7AD7DE7EFB3FF3ULL,
		0x170F2D2CFFCD431CULL,
		0xBE821935A14FC4B1ULL,
		0x095ABB1919B8931FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ABC7B99C56B6000ULL,
		0xB4C67C082DD09682ULL,
		0xC4F43CD1DDC83476ULL,
		0x5AFBCFDF67FE7BDDULL,
		0xE5A59FF9A8638B4FULL,
		0x4326B429F89622E1ULL,
		0x576323371263F7D0ULL,
		0x000000000000012BULL
	}};
	shift = 13;
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
		0x6182F96D4F031ABEULL,
		0x9B0DAE34E5A3C4FAULL,
		0xC0324E75DA2A2239ULL,
		0x8494AD8CD1E479FFULL,
		0x85FE246BBF30F494ULL,
		0x7482941F98959868ULL,
		0xDF5E9101F04CE6B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B53C0C6AF800000ULL,
		0x8D3968F13E9860BEULL,
		0x9D768A888E66C36BULL,
		0x6334791E7FF00C93ULL,
		0x1AEFCC3D2521252BULL,
		0x07E625661A217F89ULL,
		0x407C1339AE5D20A5ULL,
		0x000000000037D7A4ULL
	}};
	shift = 22;
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
		0xE14FF2559A67AAEEULL,
		0x5CE21C7035A3062DULL,
		0x36CE6C85693C9616ULL,
		0x882531AE63CE864CULL,
		0x7A89694BEEC609F4ULL,
		0xACE8B1F9886B676DULL,
		0xBF7D002CA2FE45AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55DC000000000000ULL,
		0x0C5BC29FE4AB34CFULL,
		0x2C2CB9C438E06B46ULL,
		0x0C986D9CD90AD279ULL,
		0x13E9104A635CC79DULL,
		0xCEDAF512D297DD8CULL,
		0x8B5F59D163F310D6ULL,
		0x00017EFA005945FCULL
	}};
	shift = 49;
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
		0x6BCEBC5F0800169FULL,
		0x243AE1A7B2C8DC81ULL,
		0x4CBA8F7536CBE810ULL,
		0x1E0B44491B4D4A0BULL,
		0x9FF41FC80D7D7C6BULL,
		0x631781A4F25EF8FEULL,
		0x1EDE12C4AD3D163EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE10002D3E00000ULL,
		0x34F6591B902D79D7ULL,
		0xEEA6D97D0204875CULL,
		0x892369A941699751ULL,
		0xF901AFAF8D63C168ULL,
		0x349E4BDF1FD3FE83ULL,
		0x5895A7A2C7CC62F0ULL,
		0x000000000003DBC2ULL
	}};
	shift = 21;
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
		0x6490A034D0314493ULL,
		0x20F214A9A199DDD8ULL,
		0x7670B633A6627981ULL,
		0xD0A46075B469781CULL,
		0x04CE033EBA6F21E0ULL,
		0xFEC7E87C2A6F49A8ULL,
		0x292D3DF8621794E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A0628926000000ULL,
		0x534333BBB0C92140ULL,
		0x674CC4F30241E429ULL,
		0xEB68D2F038ECE16CULL,
		0x7D74DE43C1A148C0ULL,
		0xF854DE9350099C06ULL,
		0xF0C42F29CBFD8FD0ULL,
		0x0000000000525A7BULL
	}};
	shift = 25;
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
		0x192A23B0DE4D3073ULL,
		0x0E767ADF8F929356ULL,
		0xFC8E00DFE479C055ULL,
		0xAA4ADC5DA8BF68C1ULL,
		0x3D7FBA7EC64C5EBFULL,
		0xA45B11ED21F9C1BDULL,
		0x3D4F66678E439F8EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9800000000000000ULL,
		0xB0C9511D86F26983ULL,
		0xA873B3D6FC7C949AULL,
		0x0FE47006FF23CE02ULL,
		0xFD5256E2ED45FB46ULL,
		0xE9EBFDD3F63262F5ULL,
		0x7522D88F690FCE0DULL,
		0x01EA7B333C721CFCULL
	}};
	shift = 59;
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
		0x3B7481E6A1778167ULL,
		0xF0BC953D1C8C0DA0ULL,
		0x16CD2145E6976842ULL,
		0x891A32D2D5DAE7ACULL,
		0x1E15F2E6F6E4D36AULL,
		0x1D21782CBEAE5797ULL,
		0x0AAECF27E50D3CC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x0EDD2079A85DE059ULL,
		0xBC2F254F47230368ULL,
		0x05B3485179A5DA10ULL,
		0xA2468CB4B576B9EBULL,
		0xC7857CB9BDB934DAULL,
		0x47485E0B2FAB95E5ULL,
		0x02ABB3C9F9434F30ULL
	}};
	shift = 62;
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
		0x1D36C0F33BF5AE98ULL,
		0xFC4436D982ABE8EEULL,
		0x1A603FF7038177CDULL,
		0xA7E986FAF5E4F24FULL,
		0x8BBEE8883CDC7127ULL,
		0xA7666DC1238D640FULL,
		0xD4B010CD01512BB8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D81E677EB5D300ULL,
		0x8886DB30557D1DC3ULL,
		0x4C07FEE0702EF9BFULL,
		0xFD30DF5EBC9E49E3ULL,
		0x77DD11079B8E24F4ULL,
		0xECCDB82471AC81F1ULL,
		0x960219A02A257714ULL,
		0x000000000000001AULL
	}};
	shift = 5;
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
		0xE300687CCF5ADD83ULL,
		0xFA8B046A455EAEC2ULL,
		0x059AF0EAEFFABDC5ULL,
		0x2C59212D450067ACULL,
		0xAD22DE7F2E1E65E5ULL,
		0x1C4ECCBAC09D5634ULL,
		0x718F5C4E819D7C97ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CCF5ADD83000000ULL,
		0x6A455EAEC2E30068ULL,
		0xEAEFFABDC5FA8B04ULL,
		0x2D450067AC059AF0ULL,
		0x7F2E1E65E52C5921ULL,
		0xBAC09D5634AD22DEULL,
		0x4E819D7C971C4ECCULL,
		0x0000000000718F5CULL
	}};
	shift = 24;
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
		0x2F2FE32C3C73537EULL,
		0xDD91AE2E1B2E10A1ULL,
		0xE36AAE164462F63BULL,
		0x3E672E8FA9F82499ULL,
		0x0CA6AEC5C8FBF37DULL,
		0x3C118A68BA9F5CF8ULL,
		0x100CAA65D2FFAE7CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800000000000000ULL,
		0x84BCBF8CB0F1CD4DULL,
		0xEF7646B8B86CB842ULL,
		0x678DAAB859118BD8ULL,
		0xF4F99CBA3EA7E092ULL,
		0xE0329ABB1723EFCDULL,
		0xF0F04629A2EA7D73ULL,
		0x004032A9974BFEB9ULL
	}};
	shift = 58;
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
		0xBBC022BF001173E1ULL,
		0xA0B9DD71D307AB45ULL,
		0xB29677605105630AULL,
		0x36B2D800D1331349ULL,
		0x8CCED6FD5ECC4D10ULL,
		0x4DEB01040C48730FULL,
		0x3C5BFB9FED4E01B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF008AFC0045CF840ULL,
		0x2E775C74C1EAD16EULL,
		0xA59DD8144158C2A8ULL,
		0xACB600344CC4D26CULL,
		0x33B5BF57B313440DULL,
		0x7AC04103121CC3E3ULL,
		0x16FEE7FB53806DD3ULL,
		0x000000000000000FULL
	}};
	shift = 6;
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
		0xF68E2244A7BF3447ULL,
		0x627423B384D7C2EBULL,
		0xE3F21B2EF7DA5EDFULL,
		0x3E8B764E7E51F5F7ULL,
		0xE9D285E8345F65AAULL,
		0x27732AC9BF4A963AULL,
		0x5E0B3EA7CFFE4D3DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x688E000000000000ULL,
		0x85D7ED1C44894F7EULL,
		0xBDBEC4E8476709AFULL,
		0xEBEFC7E4365DEFB4ULL,
		0xCB547D16EC9CFCA3ULL,
		0x2C75D3A50BD068BEULL,
		0x9A7A4EE655937E95ULL,
		0x0000BC167D4F9FFCULL
	}};
	shift = 49;
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
		0x44DBF7A48F057097ULL,
		0x66C35ACA903467E2ULL,
		0xF8B29FB098E67DE0ULL,
		0x9815BA204E4C18DDULL,
		0xD9B32EF252113F58ULL,
		0xE5AF20064C622681ULL,
		0xA78CF5097F3593D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E0000000000000ULL,
		0xFC489B7EF491E0AEULL,
		0xBC0CD86B5952068CULL,
		0x1BBF1653F6131CCFULL,
		0xEB1302B74409C983ULL,
		0xD03B3665DE4A4227ULL,
		0x7AFCB5E400C98C44ULL,
		0x0014F19EA12FE6B2ULL
	}};
	shift = 53;
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
		0x5B91B6ECA2C3A5A1ULL,
		0xBE02AE11B24F857FULL,
		0x8AD9A7BE51DF66A6ULL,
		0xFF0A78C1D3F19ABCULL,
		0x3D2117D6CE675BBCULL,
		0xCACB3E8CD3E68057ULL,
		0xA65F71375E60D8BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E96840000000000ULL,
		0x3E15FD6E46DBB28BULL,
		0x7D9A9AF80AB846C9ULL,
		0xC66AF22B669EF947ULL,
		0x9D6EF3FC29E3074FULL,
		0x9A015CF4845F5B39ULL,
		0x8362FF2B2CFA334FULL,
		0x000002997DC4DD79ULL
	}};
	shift = 42;
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
		0xF053ACB11E6FB25EULL,
		0x5E589213D636B15BULL,
		0x5A9BD94E6BAD8E4BULL,
		0xD3B858278CAC7D00ULL,
		0xE8DB3880FB4A7D8DULL,
		0x13F83F3957A58024ULL,
		0x1C184100B6ABBAF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC00000000000000ULL,
		0xB7E0A759623CDF64ULL,
		0x96BCB12427AC6D62ULL,
		0x00B537B29CD75B1CULL,
		0x1BA770B04F1958FAULL,
		0x49D1B67101F694FBULL,
		0xE627F07E72AF4B00ULL,
		0x00383082016D5775ULL
	}};
	shift = 57;
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
		0x1E391422E8AD2F21ULL,
		0x7FF310C3DE45757DULL,
		0x743AEBFCB9555848ULL,
		0xFA936B9DF73E0E30ULL,
		0x8E863C8F7E402F5EULL,
		0x73308432F2557A4BULL,
		0xD2067526721C772DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A1174569790800ULL,
		0x98861EF22BABE8F1ULL,
		0xD75FE5CAAAC243FFULL,
		0x9B5CEFB9F07183A1ULL,
		0x31E47BF2017AF7D4ULL,
		0x84219792ABD25C74ULL,
		0x33A93390E3B96B99ULL,
		0x0000000000000690ULL
	}};
	shift = 11;
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
		0xA87C020D184BE13BULL,
		0x0DF4A34C5DD1EC33ULL,
		0x5189D70A53179785ULL,
		0x79E123310AA425D9ULL,
		0xBAA1BBC39FAF5767ULL,
		0x3CEDD0F2CF6BD288ULL,
		0xC7D1D1AFDB99D910ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x097C276000000000ULL,
		0xBA3D86750F8041A3ULL,
		0x62F2F0A1BE94698BULL,
		0x5484BB2A313AE14AULL,
		0xF5EAECEF3C246621ULL,
		0xED7A511754377873ULL,
		0x733B22079DBA1E59ULL,
		0x00000018FA3A35FBULL
	}};
	shift = 37;
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
		0x9C4CA286969B380CULL,
		0x47207DE4A64D73ACULL,
		0xF16385DA5073795EULL,
		0xA08F5D77BA8E144EULL,
		0xAD9E4102D73DACDEULL,
		0x892A7064109A1060ULL,
		0x2257578A9B68F496ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC060000000000000ULL,
		0x9D64E2651434B4D9ULL,
		0xCAF23903EF25326BULL,
		0xA2778B1C2ED2839BULL,
		0x66F5047AEBBDD470ULL,
		0x83056CF20816B9EDULL,
		0xA4B44953832084D0ULL,
		0x000112BABC54DB47ULL
	}};
	shift = 51;
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
		0x2CFDC4DF0F766457ULL,
		0x5BAEC3BFCE493896ULL,
		0x672313EAFDB17DF1ULL,
		0x332DD950432B1679ULL,
		0x036E99D5A01A0646ULL,
		0x8EBA17C49C64FAB7ULL,
		0xE16FEADAF487A6A5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F7137C3DD9915CULL,
		0x6EBB0EFF3924E258ULL,
		0x9C8C4FABF6C5F7C5ULL,
		0xCCB765410CAC59E5ULL,
		0x0DBA675680681918ULL,
		0x3AE85F127193EADCULL,
		0x85BFAB6BD21E9A96ULL,
		0x0000000000000003ULL
	}};
	shift = 2;
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
		0xD4203C12C31DEBCAULL,
		0x11C7C488299BB83BULL,
		0x4156E685A418CCCAULL,
		0xF83FC607DCB05C60ULL,
		0x6C30F9F2F10B9F8FULL,
		0xEE17251F5C2F1F14ULL,
		0x3D6F63E70B9F0A60ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E09618EF5E5000ULL,
		0x3E24414CDDC1DEA1ULL,
		0xB7342D20C666508EULL,
		0xFE303EE582E3020AULL,
		0x87CF97885CFC7FC1ULL,
		0xB928FAE178F8A361ULL,
		0x7B1F385CF8530770ULL,
		0x00000000000001EBULL
	}};
	shift = 11;
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
		0x7051E25BAE651EE0ULL,
		0x22DECC754F9DDE85ULL,
		0x90F0E82C61FD03FFULL,
		0xB95EF79D16CEE643ULL,
		0xA64352E62A961BD0ULL,
		0xA34ECD13BB81CD2FULL,
		0x67615F2987FE878FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB800000000000000ULL,
		0xA15C147896EB9947ULL,
		0xFFC8B7B31D53E777ULL,
		0x90E43C3A0B187F40ULL,
		0xF42E57BDE745B3B9ULL,
		0x4BE990D4B98AA586ULL,
		0xE3E8D3B344EEE073ULL,
		0x0019D857CA61FFA1ULL
	}};
	shift = 54;
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
		0xAB7C6F2796384575ULL,
		0xDB81B902ECF54D74ULL,
		0x5BAB8AE4C5280C29ULL,
		0xD795C330FE177973ULL,
		0xC2BACC6870860B58ULL,
		0xCFF18D759055EB27ULL,
		0x8E4BEA0AACB8051AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF1BC9E58E115D40ULL,
		0xE06E40BB3D535D2AULL,
		0xEAE2B9314A030A76ULL,
		0xE570CC3F85DE5CD6ULL,
		0xAEB31A1C2182D635ULL,
		0xFC635D64157AC9F0ULL,
		0x92FA82AB2E0146B3ULL,
		0x0000000000000023ULL
	}};
	shift = 6;
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
		0x39B6E627301E0BD8ULL,
		0xB9C97152F507C50FULL,
		0xBEAAD4EB4957E77AULL,
		0x49B8399FA3017D3BULL,
		0x96D56523FAFD6AECULL,
		0x8C05999D0EB93E44ULL,
		0x8B9FEE37DB54BB9BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B6E627301E0BD80ULL,
		0x9C97152F507C50F3ULL,
		0xEAAD4EB4957E77ABULL,
		0x9B8399FA3017D3BBULL,
		0x6D56523FAFD6AEC4ULL,
		0xC05999D0EB93E449ULL,
		0xB9FEE37DB54BB9B8ULL,
		0x0000000000000008ULL
	}};
	shift = 4;
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
		0x750C22F18D629E96ULL,
		0x554B54A18320F2A7ULL,
		0x6C0EF8700097806AULL,
		0x864C51FE98EC46CFULL,
		0x698B45DA8A857E7DULL,
		0xAEEAC953D899AEF6ULL,
		0xBFA4502DC13C5F2BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750C22F18D629E96ULL,
		0x554B54A18320F2A7ULL,
		0x6C0EF8700097806AULL,
		0x864C51FE98EC46CFULL,
		0x698B45DA8A857E7DULL,
		0xAEEAC953D899AEF6ULL,
		0xBFA4502DC13C5F2BULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0xE49610D35B044355ULL,
		0x7C37AFE7A3B5FDC8ULL,
		0x6DAD650E57A22478ULL,
		0x359CAB5685ADC9CFULL,
		0x0C58E32B91D63202ULL,
		0xBD5ADD2D4E7F51C2ULL,
		0x7AB1E8FC1419A98DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A6B60886AA0000ULL,
		0x5FCF476BFB91C92CULL,
		0xCA1CAF4448F0F86FULL,
		0x56AD0B5B939EDB5AULL,
		0xC65723AC64046B39ULL,
		0xBA5A9CFEA38418B1ULL,
		0xD1F82833531B7AB5ULL,
		0x000000000000F563ULL
	}};
	shift = 17;
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
		0x08593B2752DB60DAULL,
		0x961446085C27F99DULL,
		0x5D4F4E36E8B549C9ULL,
		0x4FA682A35C4009D2ULL,
		0x6022CABA578E2E6CULL,
		0x170EBBAEE5F2B302ULL,
		0xA7224E06A573EE5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA5B6C1B4000000ULL,
		0x10B84FF33A10B276ULL,
		0x6DD16A93932C288CULL,
		0x46B88013A4BA9E9CULL,
		0x74AF1C5CD89F4D05ULL,
		0x5DCBE56604C04595ULL,
		0x0D4AE7DCB42E1D77ULL,
		0x00000000014E449CULL
	}};
	shift = 25;
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
		0x1C99669229E55ACFULL,
		0x632686F69DE83ED4ULL,
		0x15606EB398844574ULL,
		0x55C7B47ABDFC97BFULL,
		0xEAEDAF8B740CBE7AULL,
		0xE552D99545A45032ULL,
		0xDE9E5090A75087D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7956B3C00000000ULL,
		0x77A0FB5072659A48ULL,
		0x621115D18C9A1BDAULL,
		0xF7F25EFC5581BACEULL,
		0xD032F9E9571ED1EAULL,
		0x169140CBABB6BE2DULL,
		0x9D421F53954B6655ULL,
		0x000000037A794242ULL
	}};
	shift = 34;
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
		0x219B2BA936A9F9D2ULL,
		0x7C3DBCB33ED51640ULL,
		0x8DC7C6EFDD2113CFULL,
		0xE37850DFC87DE3EBULL,
		0x4A95DCCA3B4772F6ULL,
		0x8C4D5C8F91F28570ULL,
		0x3194753BB382DEC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x0219B2BA936A9F9DULL,
		0xF7C3DBCB33ED5164ULL,
		0xB8DC7C6EFDD2113CULL,
		0x6E37850DFC87DE3EULL,
		0x04A95DCCA3B4772FULL,
		0x38C4D5C8F91F2857ULL,
		0x03194753BB382DECULL
	}};
	shift = 60;
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
		0xB45409DFE3313420ULL,
		0x7206AF74FB6278B1ULL,
		0xDECAC2E6FF105272ULL,
		0xC6D4AD2D8D17FD01ULL,
		0xD3D52339A3978022ULL,
		0x07D56ABA9CBB75ACULL,
		0x80F96100513B792AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA813BFC662684000ULL,
		0x0D5EE9F6C4F16368ULL,
		0x9585CDFE20A4E4E4ULL,
		0xA95A5B1A2FFA03BDULL,
		0xAA4673472F00458DULL,
		0xAAD5753976EB59A7ULL,
		0xF2C200A276F2540FULL,
		0x0000000000000101ULL
	}};
	shift = 9;
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
		0xC934E190B51196CDULL,
		0x491F02A53CB72D74ULL,
		0x1C43AD3F9F046CE2ULL,
		0xA299E89A3F0653FCULL,
		0x6BED63097BFBE23AULL,
		0xB6A8EE5D0D77DDDBULL,
		0x4D926935EDA21EE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16A232D9A0000000ULL,
		0xA796E5AE99269C32ULL,
		0xF3E08D9C4923E054ULL,
		0x47E0CA7F838875A7ULL,
		0x2F7F7C4754533D13ULL,
		0xA1AEFBBB6D7DAC61ULL,
		0xBDB443DCD6D51DCBULL,
		0x0000000009B24D26ULL
	}};
	shift = 29;
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
		0x319D621504A31EEFULL,
		0x01591238855BBDAFULL,
		0x0CF088D70ADB8C33ULL,
		0xCEF3BC66C134CA22ULL,
		0x54D6ADDBA497BB2FULL,
		0x2EC64CDAD657E7E8ULL,
		0xA2BC1B8D9AB7CEDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x621504A31EEF0000ULL,
		0x1238855BBDAF319DULL,
		0x88D70ADB8C330159ULL,
		0xBC66C134CA220CF0ULL,
		0xADDBA497BB2FCEF3ULL,
		0x4CDAD657E7E854D6ULL,
		0x1B8D9AB7CEDB2EC6ULL,
		0x000000000000A2BCULL
	}};
	shift = 16;
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
		0x1C28AC5051348ADDULL,
		0xF99EB8249E6DC476ULL,
		0x637B61E3F75A715AULL,
		0x237155CF9CC71A64ULL,
		0x86E99B726F2FF222ULL,
		0xAA3997A98E592E68ULL,
		0x6E5237BAC6C3DA60ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x456E800000000000ULL,
		0xE23B0E145628289AULL,
		0x38AD7CCF5C124F36ULL,
		0x8D3231BDB0F1FBADULL,
		0xF91111B8AAE7CE63ULL,
		0x97344374CDB93797ULL,
		0xED30551CCBD4C72CULL,
		0x000037291BDD6361ULL
	}};
	shift = 47;
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
		0x7665B9A0C342881CULL,
		0x7D37066813928773ULL,
		0x83830A3BDD94037CULL,
		0x1AF2A145BFB77009ULL,
		0xEAC7AB1CD0EE5848ULL,
		0x9171A3D0AA81001DULL,
		0xE43C93E85BD1EADBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x881C000000000000ULL,
		0x87737665B9A0C342ULL,
		0x037C7D3706681392ULL,
		0x700983830A3BDD94ULL,
		0x58481AF2A145BFB7ULL,
		0x001DEAC7AB1CD0EEULL,
		0xEADB9171A3D0AA81ULL,
		0x0000E43C93E85BD1ULL
	}};
	shift = 48;
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
		0xBBE3D7AB4FD5B72FULL,
		0xC66A9F3E1E28A8D7ULL,
		0x944EA0AB8CE87F54ULL,
		0xFA43BF8E481CB89BULL,
		0xCDE194771D9DBE7EULL,
		0x10496C3B0BD820A5ULL,
		0x39713F284251481DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F56DCBC0000000ULL,
		0x878A2A35EEF8F5EAULL,
		0xE33A1FD5319AA7CFULL,
		0x92072E26E513A82AULL,
		0xC7676F9FBE90EFE3ULL,
		0xC2F608297378651DULL,
		0x1094520744125B0EULL,
		0x000000000E5C4FCAULL
	}};
	shift = 30;
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
		0xA2A76BEA1899C335ULL,
		0xDA2E1436015068A6ULL,
		0x849096AE4EEAE38EULL,
		0x8A8171FEE45D6F02ULL,
		0x69D08830C720C94BULL,
		0x7C42A80C3CA6C780ULL,
		0x961A9CCA92A67806ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19A800000000000ULL,
		0x34535153B5F50C4CULL,
		0x71C76D170A1B00A8ULL,
		0xB78142484B572775ULL,
		0x64A5C540B8FF722EULL,
		0x63C034E844186390ULL,
		0x3C033E2154061E53ULL,
		0x00004B0D4E654953ULL
	}};
	shift = 47;
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
		0xF2E61655C5EB8DD8ULL,
		0x563445D0545ECAAEULL,
		0x8F4A3B53595372C5ULL,
		0xA8B9C37F7A127021ULL,
		0x23573F2F7103CDE1ULL,
		0xCF72E1C26EB454B4ULL,
		0x98E4904E34107DFEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB8BD71BB0000000ULL,
		0xA0A8BD955DE5CC2CULL,
		0xA6B2A6E58AAC688BULL,
		0xFEF424E0431E9476ULL,
		0x5EE2079BC3517386ULL,
		0x84DD68A96846AE7EULL,
		0x9C6820FBFD9EE5C3ULL,
		0x000000000131C920ULL
	}};
	shift = 25;
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
		0xC3D2BBAE226DC7EDULL,
		0x0B3DBCF68B379967ULL,
		0x41B800FA25B905EAULL,
		0xA38D194B8CE021E0ULL,
		0x4DF06F1EC2584CF2ULL,
		0x49A964F4AC0B9BF0ULL,
		0xA1E942FA7D51BD3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBAE226DC7ED0000ULL,
		0xBCF68B379967C3D2ULL,
		0x00FA25B905EA0B3DULL,
		0x194B8CE021E041B8ULL,
		0x6F1EC2584CF2A38DULL,
		0x64F4AC0B9BF04DF0ULL,
		0x42FA7D51BD3B49A9ULL,
		0x000000000000A1E9ULL
	}};
	shift = 16;
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
		0x2BD66D8CCEE930C6ULL,
		0x02A430C761E7CE7DULL,
		0x3646429E5FD7DB25ULL,
		0x7ACB3C0B537BF2FFULL,
		0x6F1EAF97BF0E5D33ULL,
		0x67D179711733FF8DULL,
		0x2A1CD53B5CF2F154ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C66774986300000ULL,
		0x863B0F3E73E95EB3ULL,
		0x14F2FEBED9281521ULL,
		0xE05A9BDF97F9B232ULL,
		0x7CBDF872E99BD659ULL,
		0xCB88B99FFC6B78F5ULL,
		0xA9DAE7978AA33E8BULL,
		0x00000000000150E6ULL
	}};
	shift = 19;
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
		0xA9476F980F498623ULL,
		0xFE635B7322558008ULL,
		0xE97CB4BB9E06AC34ULL,
		0xA139C960308BEB38ULL,
		0xF32B07C271219163ULL,
		0xE81B50A10301C431ULL,
		0x48039C41E21E88FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4986230000000000ULL,
		0x558008A9476F980FULL,
		0x06AC34FE635B7322ULL,
		0x8BEB38E97CB4BB9EULL,
		0x219163A139C96030ULL,
		0x01C431F32B07C271ULL,
		0x1E88FAE81B50A103ULL,
		0x00000048039C41E2ULL
	}};
	shift = 40;
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
		0x0F6C135137DA9022ULL,
		0x875915C1F740E006ULL,
		0x3FA641C287E0483EULL,
		0x0B0E34014EAD255FULL,
		0x9B422E8CD7E7CF5BULL,
		0xAE5F80AC60446F01ULL,
		0x8F2DACA377F86837ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD826A26FB5204400ULL,
		0xB22B83EE81C00C1EULL,
		0x4C83850FC0907D0EULL,
		0x1C68029D5A4ABE7FULL,
		0x845D19AFCF9EB616ULL,
		0xBF0158C088DE0336ULL,
		0x5B5946EFF0D06F5CULL,
		0x000000000000011EULL
	}};
	shift = 9;
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
		0x9E55264342F62720ULL,
		0xF3EA17797DF44219ULL,
		0x6E9A635B15432105ULL,
		0x4C795A62B16F0A69ULL,
		0x5EAFB3FF4093DEC4ULL,
		0x244862D0CE620788ULL,
		0xACA40AE36D032D2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5264342F62720000ULL,
		0xA17797DF442199E5ULL,
		0xA635B15432105F3EULL,
		0x95A62B16F0A696E9ULL,
		0xFB3FF4093DEC44C7ULL,
		0x862D0CE6207885EAULL,
		0x40AE36D032D2D244ULL,
		0x0000000000000ACAULL
	}};
	shift = 12;
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
		0x9EFC5BBD0FBB4151ULL,
		0xFC450CC2F5DBF5E7ULL,
		0x2FFEBC3B9C820CD8ULL,
		0x39976D2E8BFB4A46ULL,
		0x018B8AF0A7A9894BULL,
		0x549ECC769D70A4F8ULL,
		0xED3A2FF5333E6F6DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC5BBD0FBB41510ULL,
		0xC450CC2F5DBF5E79ULL,
		0xFFEBC3B9C820CD8FULL,
		0x9976D2E8BFB4A462ULL,
		0x18B8AF0A7A9894B3ULL,
		0x49ECC769D70A4F80ULL,
		0xD3A2FF5333E6F6D5ULL,
		0x000000000000000EULL
	}};
	shift = 4;
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
		0x13A47E76CAC014E3ULL,
		0x7EF6165823724B28ULL,
		0x74D2B01FD66CE674ULL,
		0x065CB0F4F7F6954FULL,
		0x78741A6215ADEC60ULL,
		0xEDA55A93E3D88009ULL,
		0x0DEDE375CBB9DBADULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F9DB2B00538C00ULL,
		0xD859608DC92CA04EULL,
		0x4AC07F59B399D1FBULL,
		0x72C3D3DFDA553DD3ULL,
		0xD0698856B7B18019ULL,
		0x956A4F8F620025E1ULL,
		0xB78DD72EE76EB7B6ULL,
		0x0000000000000037ULL
	}};
	shift = 10;
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
		0x1B04FAB76D0B8D65ULL,
		0xCB221AE5A17160B7ULL,
		0xAA959BD7BD41B63DULL,
		0xF48ACE21FAE519BBULL,
		0x00B88DACB4FE13FCULL,
		0xE1D83F12C598724CULL,
		0x990E51952C70674AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB685C6B280000000ULL,
		0xD0B8B05B8D827D5BULL,
		0xDEA0DB1EE5910D72ULL,
		0xFD728CDDD54ACDEBULL,
		0x5A7F09FE7A456710ULL,
		0x62CC3926005C46D6ULL,
		0x963833A570EC1F89ULL,
		0x000000004C8728CAULL
	}};
	shift = 31;
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
		0x4A201E4F5654B44BULL,
		0x60B42A83A7931EC3ULL,
		0xD702D9BA2C060FE5ULL,
		0xA257663EEC606555ULL,
		0x02E8209B5B861DBDULL,
		0xBC796FF315BECA88ULL,
		0xAE3B3BDDFF7B8E0AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6896000000000000ULL,
		0x3D8694403C9EACA9ULL,
		0x1FCAC16855074F26ULL,
		0xCAABAE05B374580CULL,
		0x3B7B44AECC7DD8C0ULL,
		0x951005D04136B70CULL,
		0x1C1578F2DFE62B7DULL,
		0x00015C7677BBFEF7ULL
	}};
	shift = 49;
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
		0x33E895AC1AD9879AULL,
		0x94AE2FB40EDCB15BULL,
		0xD32B582DE95F6702ULL,
		0xDA910C6E8EF4FB2DULL,
		0x35A2CE9AE085D50CULL,
		0x1E21317EEE3716C5ULL,
		0x522E702D7305FD15ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AD9879A00000000ULL,
		0x0EDCB15B33E895ACULL,
		0xE95F670294AE2FB4ULL,
		0x8EF4FB2DD32B582DULL,
		0xE085D50CDA910C6EULL,
		0xEE3716C535A2CE9AULL,
		0x7305FD151E21317EULL,
		0x00000000522E702DULL
	}};
	shift = 32;
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
		0x5B3AE4B202631EC5ULL,
		0x6EAC06CC415519DEULL,
		0xBC915732DC29F5BEULL,
		0x378582121B16BB3DULL,
		0xBD11EE53D6DA88C5ULL,
		0x7B5AF8E44ACEECC3ULL,
		0xA93CBAF4084F52A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8A000000000000ULL,
		0x33BCB675C96404C6ULL,
		0xEB7CDD580D9882AAULL,
		0x767B7922AE65B853ULL,
		0x118A6F0B0424362DULL,
		0xD9877A23DCA7ADB5ULL,
		0xA540F6B5F1C8959DULL,
		0x0001527975E8109EULL
	}};
	shift = 49;
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
		0x730377EBB068A554ULL,
		0x9A0A61A8C8F1C17EULL,
		0x7773D087540C9336ULL,
		0xEDA00CC700F80351ULL,
		0x4ABEA61530468DF2ULL,
		0x5898655EF1E55746ULL,
		0x64E636FE7E7D3D70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD760D14AA80000ULL,
		0xC35191E382FCE606ULL,
		0xA10EA819266D3414ULL,
		0x198E01F006A2EEE7ULL,
		0x4C2A608D1BE5DB40ULL,
		0xCABDE3CAAE8C957DULL,
		0x6DFCFCFA7AE0B130ULL,
		0x000000000000C9CCULL
	}};
	shift = 17;
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
		0x5767796C960470F3ULL,
		0xEF0F82C8344D3C47ULL,
		0x766A31EA2F572640ULL,
		0x2EB0B8400A539B10ULL,
		0x76C82134FC04252CULL,
		0x181FAF37A508BBCDULL,
		0xA88DB4E49BC1D3B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0xEAECEF2D92C08E1EULL,
		0x1DE1F0590689A788ULL,
		0x0ECD463D45EAE4C8ULL,
		0x85D61708014A7362ULL,
		0xAED904269F8084A5ULL,
		0x8303F5E6F4A11779ULL,
		0x1511B69C93783A76ULL
	}};
	shift = 61;
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
		0x374A05312DBA3642ULL,
		0x004CFD4793F60E1CULL,
		0xA974DAA97C6DC4CCULL,
		0x57F3D31582CC9927ULL,
		0x360677BD165C5C0DULL,
		0x8A3070574CD41CB0ULL,
		0x26CD12BD57F9A66BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29896DD1B2100000ULL,
		0xEA3C9FB070E1BA50ULL,
		0xD54BE36E26600267ULL,
		0x98AC1664C93D4BA6ULL,
		0xBDE8B2E2E06ABF9EULL,
		0x82BA66A0E581B033ULL,
		0x95EABFCD335C5183ULL,
		0x0000000000013668ULL
	}};
	shift = 19;
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
		0x0E7A74929E318943ULL,
		0x008C20D2366EC3DCULL,
		0x221347E4447A6BF9ULL,
		0xE32FC99D06B7653CULL,
		0xBA37EDAA99C60349ULL,
		0xF8F99593D952FBD7ULL,
		0x4C298B8CAB9B2EB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C0000000000000ULL,
		0xF7039E9D24A78C62ULL,
		0xFE402308348D9BB0ULL,
		0x4F0884D1F9111E9AULL,
		0xD278CBF26741ADD9ULL,
		0xF5EE8DFB6AA67180ULL,
		0xACFE3E6564F654BEULL,
		0x00130A62E32AE6CBULL
	}};
	shift = 54;
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
		0x17F8CB48D5DED6E5ULL,
		0x1FE0C260D0ED69FAULL,
		0x2AC2134A99B4FD79ULL,
		0xF194478C2A427614ULL,
		0x143A0264886018C5ULL,
		0xC739814F0F7B8E1EULL,
		0x0799DAD25ED98961ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9691ABBDADCA0000ULL,
		0x84C1A1DAD3F42FF1ULL,
		0x26953369FAF23FC1ULL,
		0x8F185484EC285584ULL,
		0x04C910C0318BE328ULL,
		0x029E1EF71C3C2874ULL,
		0xB5A4BDB312C38E73ULL,
		0x0000000000000F33ULL
	}};
	shift = 17;
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
		0xD195B68C8792F3D8ULL,
		0xE94C16A351870AF4ULL,
		0x885EDF2454E93740ULL,
		0xD7FD0FCB43297C4FULL,
		0xBC971987CE33EFBEULL,
		0x2E2C7577D328AED0ULL,
		0x7BB94664284F18CCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E7B000000000000ULL,
		0xE15E9A32B6D190F2ULL,
		0x26E81D2982D46A30ULL,
		0x2F89F10BDBE48A9DULL,
		0x7DF7DAFFA1F96865ULL,
		0x15DA1792E330F9C6ULL,
		0xE31985C58EAEFA65ULL,
		0x00000F7728CC8509ULL
	}};
	shift = 45;
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
		0x8552091B030A3464ULL,
		0x9F046324E2AB5613ULL,
		0x168AAA13C5D8407BULL,
		0x75D839F8EF771E38ULL,
		0x9CAB67EF52F000CBULL,
		0x19F03BBF03F1305BULL,
		0x1FEE93D6554FFA35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C8000000000000ULL,
		0xAC270AA412360614ULL,
		0x80F73E08C649C556ULL,
		0x3C702D1554278BB0ULL,
		0x0196EBB073F1DEEEULL,
		0x60B73956CFDEA5E0ULL,
		0xF46A33E0777E07E2ULL,
		0x00003FDD27ACAA9FULL
	}};
	shift = 49;
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
		0x6A2ABF920B631F00ULL,
		0x3EAF11D16664BD0FULL,
		0x9EBBEC25064A931AULL,
		0x852F584BD4256F75ULL,
		0x60A6485BA06839F4ULL,
		0x23E33D1806C8EDFAULL,
		0x4EEBEB8B3520BAA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE482D8C7C000000ULL,
		0x47459992F43DA8AAULL,
		0xB094192A4C68FABCULL,
		0x612F5095BDD67AEFULL,
		0x216E81A0E7D214BDULL,
		0xF4601B23B7E98299ULL,
		0xAE2CD482EA988F8CULL,
		0x0000000000013BAFULL
	}};
	shift = 18;
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
		0xE26E56E6774D44A2ULL,
		0x7C83145614545D47ULL,
		0xE9E01F5043CB42C4ULL,
		0xF8669C6AEA158E4CULL,
		0x4FA0EB94CD7EA113ULL,
		0x04762E59FF8E6CF6ULL,
		0xB855D5E76D16DCD8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xFC4DCADCCEE9A894ULL,
		0x8F90628AC28A8BA8ULL,
		0x9D3C03EA08796858ULL,
		0x7F0CD38D5D42B1C9ULL,
		0xC9F41D7299AFD422ULL,
		0x008EC5CB3FF1CD9EULL,
		0x170ABABCEDA2DB9BULL
	}};
	shift = 61;
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
		0x93BA83A19A1575AFULL,
		0x54EB63294F0782AFULL,
		0x777FDDD9B94E8EF4ULL,
		0x8B843483861889DAULL,
		0x9F8F122D3DEAECC0ULL,
		0x838D592E592ED268ULL,
		0xD80D77C0E58667A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3342AEB5E0000000ULL,
		0x29E0F055F2775074ULL,
		0x3729D1DE8A9D6C65ULL,
		0x70C3113B4EEFFBBBULL,
		0xA7BD5D9811708690ULL,
		0xCB25DA4D13F1E245ULL,
		0x1CB0CCF51071AB25ULL,
		0x000000001B01AEF8ULL
	}};
	shift = 29;
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
		0xFAE97FD7275CAA8BULL,
		0x8396DFED75A35944ULL,
		0x40B2C59A87238D08ULL,
		0xFA6F65C297C858C1ULL,
		0xA9E0E86BEEDA00BCULL,
		0xEC7548F2A3C7E60EULL,
		0x223AF2CADAB3D04AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD72AA2C000000000ULL,
		0x68D6513EBA5FF5C9ULL,
		0xC8E34220E5B7FB5DULL,
		0xF21630502CB166A1ULL,
		0xB6802F3E9BD970A5ULL,
		0xF1F983AA783A1AFBULL,
		0xACF412BB1D523CA8ULL,
		0x000000088EBCB2B6ULL
	}};
	shift = 38;
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
		0x7A703B2B2B7B69B2ULL,
		0xEB4E3859B85271D5ULL,
		0xD535FAA1173808A5ULL,
		0xC5976414571987E6ULL,
		0xB4F35EA0F3EE6258ULL,
		0x6AF4A795637BF668ULL,
		0x6FB0A9E4FCA12142ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69B2000000000000ULL,
		0x71D57A703B2B2B7BULL,
		0x08A5EB4E3859B852ULL,
		0x87E6D535FAA11738ULL,
		0x6258C59764145719ULL,
		0xF668B4F35EA0F3EEULL,
		0x21426AF4A795637BULL,
		0x00006FB0A9E4FCA1ULL
	}};
	shift = 48;
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
		0x4E95E625BCCA6287ULL,
		0x64095C498BEC3C9AULL,
		0x23EF3321D327EE2FULL,
		0x7FA7B593995F8046ULL,
		0x284F54D34F1868EDULL,
		0xD197D7418DF31B2CULL,
		0x512E6F8B4B0B866CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E625BCCA6287000ULL,
		0x95C498BEC3C9A4E9ULL,
		0xF3321D327EE2F640ULL,
		0x7B593995F804623EULL,
		0xF54D34F1868ED7FAULL,
		0x7D7418DF31B2C284ULL,
		0xE6F8B4B0B866CD19ULL,
		0x0000000000000512ULL
	}};
	shift = 12;
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
		0x6CDBC146EFB2F72CULL,
		0x759E9A3BF45D9DACULL,
		0x300A591E962E2290ULL,
		0xBF65E2B03F5B5536ULL,
		0xB19878693DBC3535ULL,
		0xDEF4A3B014F9A412ULL,
		0xE6DD6F62D2F427F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x6366DE0A377D97B9ULL,
		0x83ACF4D1DFA2ECEDULL,
		0xB18052C8F4B17114ULL,
		0xADFB2F1581FADAA9ULL,
		0x958CC3C349EDE1A9ULL,
		0xC6F7A51D80A7CD20ULL,
		0x0736EB7B1697A13FULL
	}};
	shift = 59;
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
		0x3F88FDF910D9DE95ULL,
		0xFF205DBF9BD9021CULL,
		0x83FA8B0B5EDD19F3ULL,
		0xACAD2DB7BF12E305ULL,
		0x0A996A579E8206F7ULL,
		0xAAF70A3D7AF219D7ULL,
		0x4DF78E6B9A9FA209ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE95000000000000ULL,
		0x021C3F88FDF910D9ULL,
		0x19F3FF205DBF9BD9ULL,
		0xE30583FA8B0B5EDDULL,
		0x06F7ACAD2DB7BF12ULL,
		0x19D70A996A579E82ULL,
		0xA209AAF70A3D7AF2ULL,
		0x00004DF78E6B9A9FULL
	}};
	shift = 48;
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
		0x080B01FCEC30E2CFULL,
		0x9BEDDDDA46553ABBULL,
		0xB9077DCA7D613FD0ULL,
		0xA088D0EBB4B6117BULL,
		0xEDA67B77B0E63E39ULL,
		0xD7C679DD708FD0A0ULL,
		0x499284FF1B224977ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C07F3B0C38B3C0ULL,
		0xFB777691954EAEC2ULL,
		0x41DF729F584FF426ULL,
		0x22343AED2D845EEEULL,
		0x699EDDEC398F8E68ULL,
		0xF19E775C23F4283BULL,
		0x64A13FC6C8925DF5ULL,
		0x0000000000000012ULL
	}};
	shift = 6;
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
		0x804728CF01990483ULL,
		0xB5EB93EC31274DFDULL,
		0xBEA58841F92B2511ULL,
		0x6F454A89B1637D0BULL,
		0x0697249963B351D5ULL,
		0x860E7B7EC64DF71EULL,
		0x2B1F95865543FE69ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780CC82418000000ULL,
		0x61893A6FEC023946ULL,
		0x0FC959288DAF5C9FULL,
		0x4D8B1BE85DF52C42ULL,
		0xCB1D9A8EAB7A2A54ULL,
		0xF6326FB8F034B924ULL,
		0x32AA1FF34C3073DBULL,
		0x000000000158FCACULL
	}};
	shift = 27;
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
		0xF7109BAB7ED1AD18ULL,
		0xBA0941EA9698A98EULL,
		0xF8DB99587681C248ULL,
		0x1906626127B1AC78ULL,
		0x8D7FAC3F9EF8C975ULL,
		0x0DCC152C4256DEA2ULL,
		0xB8171A62B75D6C30ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC426EADFB46B460ULL,
		0xE82507AA5A62A63BULL,
		0xE36E6561DA070922ULL,
		0x641989849EC6B1E3ULL,
		0x35FEB0FE7BE325D4ULL,
		0x373054B1095B7A8AULL,
		0xE05C698ADD75B0C0ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
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
		0x5D9CE68A6D5B6A7CULL,
		0xF30CE7C1C60BFE12ULL,
		0xB0BB1713B5E969B7ULL,
		0x041DFFF7818D7C89ULL,
		0x0CE5D6FFB0B35454ULL,
		0xEFA0F18F08AA4435ULL,
		0x45E06FD08F20C8C9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4F800000000000ULL,
		0x7FC24BB39CD14DABULL,
		0x2D36FE619CF838C1ULL,
		0xAF91361762E276BDULL,
		0x6A8A8083BFFEF031ULL,
		0x4886A19CBADFF616ULL,
		0x19193DF41E31E115ULL,
		0x000008BC0DFA11E4ULL
	}};
	shift = 45;
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
		0xCAB1927FE1768E7CULL,
		0x53399792FC51F3D5ULL,
		0xF633BBC272AD75A7ULL,
		0x8DBBC4EF13DD3C5EULL,
		0x2B69ED69F4C428F4ULL,
		0xA4B63B3669DC13E7ULL,
		0x6B1B6DC4E4D06A67ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1927FE1768E7C00ULL,
		0x399792FC51F3D5CAULL,
		0x33BBC272AD75A753ULL,
		0xBBC4EF13DD3C5EF6ULL,
		0x69ED69F4C428F48DULL,
		0xB63B3669DC13E72BULL,
		0x1B6DC4E4D06A67A4ULL,
		0x000000000000006BULL
	}};
	shift = 8;
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
		0x780266AE4300BD4CULL,
		0x3758FFBB30120EC1ULL,
		0xD592CF0050B681B0ULL,
		0xBC0E86F87F4DB16AULL,
		0x9D503117F0B43999ULL,
		0x682D7008736B2FE1ULL,
		0x7697964B4DE30CC6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C00000000000000ULL,
		0xC1780266AE4300BDULL,
		0xB03758FFBB30120EULL,
		0x6AD592CF0050B681ULL,
		0x99BC0E86F87F4DB1ULL,
		0xE19D503117F0B439ULL,
		0xC6682D7008736B2FULL,
		0x007697964B4DE30CULL
	}};
	shift = 56;
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
		0x0A4F36F737949705ULL,
		0xE889266FD12BDADBULL,
		0x3A6109A09FC70678ULL,
		0x72AEEEE748F9C50EULL,
		0x87EC008DFD4A9C18ULL,
		0x238CC9CD4C72C621ULL,
		0xEC0F8015C76F62F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x292E0A0000000000ULL,
		0x57B5B6149E6DEE6FULL,
		0x8E0CF1D1124CDFA2ULL,
		0xF38A1C74C213413FULL,
		0x953830E55DDDCE91ULL,
		0xE58C430FD8011BFAULL,
		0xDEC5E04719939A98ULL,
		0x000001D81F002B8EULL
	}};
	shift = 41;
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
		0x4E4158689F672307ULL,
		0x1654967B73C9CC81ULL,
		0x5E5D3501866F9F1DULL,
		0x43423751677FD943ULL,
		0x352E10E7E84D8652ULL,
		0x6FF954FD3A6DC3EFULL,
		0xD92DE4A6181967D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8689F67230700000ULL,
		0x67B73C9CC814E415ULL,
		0x501866F9F1D16549ULL,
		0x751677FD9435E5D3ULL,
		0x0E7E84D865243423ULL,
		0x4FD3A6DC3EF352E1ULL,
		0x4A6181967D96FF95ULL,
		0x00000000000D92DEULL
	}};
	shift = 20;
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
		0xAE26078B1C5925E4ULL,
		0x23451B67022508E9ULL,
		0xA0AC81CBD300A24CULL,
		0x4EF094F2869076ECULL,
		0x86AF166D520ACE32ULL,
		0x9AEB828A837284C0ULL,
		0x0871B5407714E360ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1638B24BC80000ULL,
		0x36CE044A11D35C4CULL,
		0x0397A6014498468AULL,
		0x29E50D20EDD94159ULL,
		0x2CDAA4159C649DE1ULL,
		0x051506E509810D5EULL,
		0x6A80EE29C6C135D7ULL,
		0x00000000000010E3ULL
	}};
	shift = 17;
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
		0xC84329E84013CB93ULL,
		0x69FD3713E3494BA2ULL,
		0x16CAAF00CC647247ULL,
		0x445A4C162395B8C7ULL,
		0x2FABAA1405ED441DULL,
		0x2E93F380DBD722F8ULL,
		0xC1AA97AC77C21EB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D08027972600000ULL,
		0xE27C692974590865ULL,
		0xE0198C8E48ED3FA6ULL,
		0x82C472B718E2D955ULL,
		0x4280BDA883A88B49ULL,
		0x701B7AE45F05F575ULL,
		0xF58EF843D685D27EULL,
		0x0000000000183552ULL
	}};
	shift = 21;
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
		0x1E1888C2C1AF5FBEULL,
		0xB3615DA9CE665FA0ULL,
		0xD3F692C4C2714F80ULL,
		0x4ECD963275735114ULL,
		0x177978F1F8F846A9ULL,
		0x1F1F3D1B3B77A74CULL,
		0xEA08D8ECF986DF51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7AFDF0000000000ULL,
		0x332FD00F0C446160ULL,
		0x38A7C059B0AED4E7ULL,
		0xB9A88A69FB496261ULL,
		0x7C2354A766CB193AULL,
		0xBBD3A60BBCBC78FCULL,
		0xC36FA88F8F9E8D9DULL,
		0x00000075046C767CULL
	}};
	shift = 39;
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
		0x3D5DDC493B92AC1FULL,
		0x9C99D68EBA7D302AULL,
		0x93BB7DBB64B5DAFCULL,
		0x6468CCCC86785B2BULL,
		0x03B256B9E8741246ULL,
		0x7C19CCAD1945D4B2ULL,
		0xE88C12C0AAA5ABA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE4AB07C00000000ULL,
		0xE9F4C0A8F5777124ULL,
		0x92D76BF272675A3AULL,
		0x19E16CAE4EEDF6EDULL,
		0xA1D0491991A33332ULL,
		0x651752C80EC95AE7ULL,
		0xAA96AE91F06732B4ULL,
		0x00000003A2304B02ULL
	}};
	shift = 34;
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
		0xB8CA470BEA23D695ULL,
		0xD3CAE9DC2A79A69CULL,
		0x35C1731367E59ADAULL,
		0xF98AA359899706E2ULL,
		0xF962FF31F7D90457ULL,
		0x90E2F0DFB199FD67ULL,
		0x6DAB681ACCE03284ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x652385F511EB4A80ULL,
		0xE574EE153CD34E5CULL,
		0xE0B989B3F2CD6D69ULL,
		0xC551ACC4CB83711AULL,
		0xB17F98FBEC822BFCULL,
		0x71786FD8CCFEB3FCULL,
		0xD5B40D6670194248ULL,
		0x0000000000000036ULL
	}};
	shift = 7;
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
		0x60AA732C2C8D498CULL,
		0x01DA1F1F4061C854ULL,
		0xB7B21271FFB3214CULL,
		0x96F4FCE9AD428A8EULL,
		0x6F93391207DD5C6AULL,
		0x3D35AD5248C81580ULL,
		0xB4BA091B31B9A0C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A9CCB0B2352630ULL,
		0x07687C7D01872151ULL,
		0xDEC849C7FECC8530ULL,
		0x5BD3F3A6B50A2A3AULL,
		0xBE4CE4481F7571AAULL,
		0xF4D6B54923205601ULL,
		0xD2E8246CC6E68320ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
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
		0x418D56BABD426CA7ULL,
		0xC80E5D773D0BFD94ULL,
		0xF1AD018AF4D251F4ULL,
		0x34918C2AEB72C534ULL,
		0xF8D9BAE04CBB8860ULL,
		0xAF012A57777281C1ULL,
		0x23FB2EB811A15F93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D5EA1365380000ULL,
		0xEBB9E85FECA20C6AULL,
		0x0C57A6928FA64072ULL,
		0x61575B9629A78D68ULL,
		0xD70265DC4301A48CULL,
		0x52BBBB940E0FC6CDULL,
		0x75C08D0AFC9D7809ULL,
		0x0000000000011FD9ULL
	}};
	shift = 19;
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
		0xACF3F328AB06F094ULL,
		0xA97FD03CB078A09EULL,
		0xAF7AB7F50602FFB4ULL,
		0x2D8E595318AF6EF3ULL,
		0xA876DC865CDF0236ULL,
		0x536251143D51D8B4ULL,
		0x05900C651F71B39EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF3F328AB06F094ULL,
		0xA97FD03CB078A09EULL,
		0xAF7AB7F50602FFB4ULL,
		0x2D8E595318AF6EF3ULL,
		0xA876DC865CDF0236ULL,
		0x536251143D51D8B4ULL,
		0x05900C651F71B39EULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x3F1D806CBC641E52ULL,
		0x84FFFAD41BC16D46ULL,
		0x456E91EE56FC6B5EULL,
		0x2724E13E0EAABEAEULL,
		0x6B393F877EF35EC3ULL,
		0x15676C2DC1A42290ULL,
		0xD503405B14B5126DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE320F29000000000ULL,
		0xDE0B6A31F8EC0365ULL,
		0xB7E35AF427FFD6A0ULL,
		0x7555F5722B748F72ULL,
		0xF79AF619392709F0ULL,
		0x0D21148359C9FC3BULL,
		0xA5A89368AB3B616EULL,
		0x00000006A81A02D8ULL
	}};
	shift = 35;
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
		0xD7531BBD35424907ULL,
		0xA2A44695E3080BBDULL,
		0x497818D959B1EDECULL,
		0x80C60C490D5731FDULL,
		0xC15A3D1B636981B5ULL,
		0x9E31C90C8A0202C0ULL,
		0xC28DD1B4EF0E73E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x920E000000000000ULL,
		0x177BAEA6377A6A84ULL,
		0xDBD945488D2BC610ULL,
		0x63FA92F031B2B363ULL,
		0x036B018C18921AAEULL,
		0x058182B47A36C6D3ULL,
		0xE7C53C6392191404ULL,
		0x0001851BA369DE1CULL
	}};
	shift = 49;
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
		0x38716E42AD753E16ULL,
		0xDDDEBE73141DB8DAULL,
		0xE9226B1D53E28AD6ULL,
		0x51004C90FFD5F296ULL,
		0xA208F90239FDFDE0ULL,
		0x4C79689F31ADFFB9ULL,
		0x515D273CFFFA5014ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2DC855AEA7C2C0ULL,
		0xBBD7CE6283B71B47ULL,
		0x244D63AA7C515ADBULL,
		0x2009921FFABE52DDULL,
		0x411F20473FBFBC0AULL,
		0x8F2D13E635BFF734ULL,
		0x2BA4E79FFF4A0289ULL,
		0x000000000000000AULL
	}};
	shift = 5;
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
		0xDE4C9904CA20DD8BULL,
		0x3A6A1180C16EF874ULL,
		0x35BC0904C54974F7ULL,
		0xECECB93D00EA25FFULL,
		0x1D8E2CDF570C1907ULL,
		0xE0213787A1CA2EF8ULL,
		0x6E93E8560235A099ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF264C8265106EC58ULL,
		0xD3508C060B77C3A6ULL,
		0xADE048262A4BA7B9ULL,
		0x6765C9E807512FF9ULL,
		0xEC7166FAB860C83FULL,
		0x0109BC3D0E5177C0ULL,
		0x749F42B011AD04CFULL,
		0x0000000000000003ULL
	}};
	shift = 3;
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
		0xB788321D53CC504DULL,
		0x5076A19F68EE061BULL,
		0x79CA4B11D1AA717DULL,
		0xC822F57CD0354313ULL,
		0x40521A2A255A9875ULL,
		0x5F2E7F9829158160ULL,
		0x33942152623453DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1413400000000000ULL,
		0x8186EDE20C8754F3ULL,
		0x9C5F541DA867DA3BULL,
		0x50C4DE7292C4746AULL,
		0xA61D7208BD5F340DULL,
		0x60581014868A8956ULL,
		0x14F717CB9FE60A45ULL,
		0x00000CE50854988DULL
	}};
	shift = 46;
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
		0x11F6C662A2F0CF3AULL,
		0x70CEBE6B9F6875A0ULL,
		0xED28DBDCB8C92869ULL,
		0x4441FBAD60CAFC0AULL,
		0x25CB47FF70569C99ULL,
		0xE17B599E33068D29ULL,
		0x3BF08C5C9BB4CE42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E74000000000000ULL,
		0xEB4023ED8CC545E1ULL,
		0x50D2E19D7CD73ED0ULL,
		0xF815DA51B7B97192ULL,
		0x39328883F75AC195ULL,
		0x1A524B968FFEE0ADULL,
		0x9C85C2F6B33C660DULL,
		0x000077E118B93769ULL
	}};
	shift = 49;
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
		0x4F87F4D9A4036763ULL,
		0xA21811E3B72D22BDULL,
		0xB30015F1518BCA84ULL,
		0x0718294CC8266149ULL,
		0x2815C27F2B94AD4AULL,
		0x07512207AFB943A4ULL,
		0x3AE88DD8F79CDE11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1FD366900D9D8CULL,
		0x8860478EDCB48AF5ULL,
		0xCC0057C5462F2A12ULL,
		0x1C60A53320998526ULL,
		0xA05709FCAE52B528ULL,
		0x1D44881EBEE50E90ULL,
		0xEBA23763DE737844ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x7D25A7A498E0142DULL,
		0xD08EEEFBE65F4158ULL,
		0xE5A6699FEAD97782ULL,
		0x607614F0383BDAE5ULL,
		0xA52A34A357D63061ULL,
		0xCC0B41D1B3BB1902ULL,
		0x316CCC38F72CF74FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B4F4931C0285A00ULL,
		0x1DDDF7CCBE82B0FAULL,
		0x4CD33FD5B2EF05A1ULL,
		0xEC29E07077B5CBCBULL,
		0x546946AFAC60C2C0ULL,
		0x1683A3677632054AULL,
		0xD99871EE59EE9F98ULL,
		0x0000000000000062ULL
	}};
	shift = 9;
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
		0xDB621DCFFE7D68BFULL,
		0xD9E9F033E8665856ULL,
		0x8A7BCD0E8D15B2CCULL,
		0x4C2BCBB0E90ADE9AULL,
		0xAF9D6155CE2B5B06ULL,
		0xCDC6D6617309C7F0ULL,
		0xCCDBECD8FB7C97E0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF00000000000000ULL,
		0x56DB621DCFFE7D68ULL,
		0xCCD9E9F033E86658ULL,
		0x9A8A7BCD0E8D15B2ULL,
		0x064C2BCBB0E90ADEULL,
		0xF0AF9D6155CE2B5BULL,
		0xE0CDC6D6617309C7ULL,
		0x00CCDBECD8FB7C97ULL
	}};
	shift = 56;
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
		0xF4BA581C6D68D2D0ULL,
		0xF68D9566E8722287ULL,
		0xFA03D566D88AA7C8ULL,
		0xDC9BE7387836AEBEULL,
		0xB1A0EA2041F4B8F4ULL,
		0x686C6BA34A207375ULL,
		0xBFBD7382FD272895ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D68D2D000000000ULL,
		0xE8722287F4BA581CULL,
		0xD88AA7C8F68D9566ULL,
		0x7836AEBEFA03D566ULL,
		0x41F4B8F4DC9BE738ULL,
		0x4A207375B1A0EA20ULL,
		0xFD272895686C6BA3ULL,
		0x00000000BFBD7382ULL
	}};
	shift = 32;
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
		0xB48DB1ADD2CD0E00ULL,
		0xF7E30EDB6B5F40A1ULL,
		0xF8B6D34D2E1AA430ULL,
		0x1303D0B4CFE9DB56ULL,
		0xAFBF1FB6301437DFULL,
		0x6B20163D3B5D8742ULL,
		0x53B0146B180C5482ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA59A1C00000000ULL,
		0xB6D6BE8143691B63ULL,
		0x9A5C354861EFC61DULL,
		0x699FD3B6ADF16DA6ULL,
		0x6C60286FBE2607A1ULL,
		0x7A76BB0E855F7E3FULL,
		0xD63018A904D6402CULL,
		0x0000000000A76028ULL
	}};
	shift = 25;
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
		0x9AF2E680DCB7AC09ULL,
		0x1CCA681E82F661D8ULL,
		0x277489F052DFE9BEULL,
		0xAE28CC159231A88BULL,
		0x609E8A47AE2ADB6CULL,
		0xED00396BC9510979ULL,
		0xF8AE6F6EF599195CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73406E5BD6048000ULL,
		0x340F417B30EC4D79ULL,
		0x44F8296FF4DF0E65ULL,
		0x660AC918D44593BAULL,
		0x4523D7156DB65714ULL,
		0x1CB5E4A884BCB04FULL,
		0x37B77ACC8CAE7680ULL,
		0x0000000000007C57ULL
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
		0xCCD46997B36DB8E8ULL,
		0x986FD85D07113996ULL,
		0x7DF46C953A1C56E4ULL,
		0x726C72C07C30C6EBULL,
		0xA9FDAF6915AD4524ULL,
		0x33D7D881A4F40E18ULL,
		0x163299F37F2922B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC7400000000000ULL,
		0x89CCB666A34CBD9BULL,
		0xE2B724C37EC2E838ULL,
		0x86375BEFA364A9D0ULL,
		0x6A292393639603E1ULL,
		0xA070C54FED7B48ADULL,
		0x4915C99EBEC40D27ULL,
		0x000000B194CF9BF9ULL
	}};
	shift = 43;
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
		0x0DB28AA9D4A20180ULL,
		0x9D04B9477E47EB74ULL,
		0x602041ABAEDCE2BEULL,
		0xA9A213AAE073D387ULL,
		0xBBA69A70BD187058ULL,
		0x8AAB3790D0240679ULL,
		0x30F3BF4EFC715F06ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x554EA5100C000000ULL,
		0xCA3BF23F5BA06D94ULL,
		0x0D5D76E715F4E825ULL,
		0x9D57039E9C3B0102ULL,
		0xD385E8C382C54D10ULL,
		0xBC86812033CDDD34ULL,
		0xFA77E38AF8345559ULL,
		0x000000000001879DULL
	}};
	shift = 19;
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
		0x84AB4A42C9FD37DAULL,
		0x4C21192A4FF8AF34ULL,
		0x86937B1A9FC184B3ULL,
		0xBF8B47CC2B2B743FULL,
		0x91EE6356594414F2ULL,
		0xA936210670105F37ULL,
		0xF63D467F5D2BC503ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD37DA0000000000ULL,
		0xF8AF3484AB4A42C9ULL,
		0xC184B34C21192A4FULL,
		0x2B743F86937B1A9FULL,
		0x4414F2BF8B47CC2BULL,
		0x105F3791EE635659ULL,
		0x2BC503A936210670ULL,
		0x000000F63D467F5DULL
	}};
	shift = 40;
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
		0x4B4031625A4633C0ULL,
		0x0AA23C8882316D1CULL,
		0x0064182061953F11ULL,
		0x257A3B5E27DE187BULL,
		0xFE25CC5EBADC6D97ULL,
		0x74A5643D69ABC650ULL,
		0xCB4D87EE27DDC8A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x38968062C4B48C67ULL,
		0x22154479110462DAULL,
		0xF600C83040C32A7EULL,
		0x2E4AF476BC4FBC30ULL,
		0xA1FC4B98BD75B8DBULL,
		0x48E94AC87AD3578CULL,
		0x01969B0FDC4FBB91ULL
	}};
	shift = 57;
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
		0xC1E680B1A1568FB7ULL,
		0xC5EEF53E02A88E55ULL,
		0xCE6059E640DC32A8ULL,
		0x0DEF68F65181A2F6ULL,
		0xD2C6899737947681ULL,
		0xFBC31FC42057DD67ULL,
		0xABD6167146A1CB95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB47DB8000000000ULL,
		0x54472AE0F34058D0ULL,
		0x6E195462F77A9F01ULL,
		0xC0D17B67302CF320ULL,
		0xCA3B4086F7B47B28ULL,
		0x2BEEB3E96344CB9BULL,
		0x50E5CAFDE18FE210ULL,
		0x00000055EB0B38A3ULL
	}};
	shift = 39;
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
		0xB1BFF313809ADA7DULL,
		0x46D35B6D4969B6C3ULL,
		0x9B6FCA5DBC983AB4ULL,
		0x39C505B429E44DF4ULL,
		0x806921ECC69FB232ULL,
		0x6F186A060E26199CULL,
		0x56DFB0FC268709E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D3E80000000000ULL,
		0x4DB61D8DFF989C04ULL,
		0xC1D5A2369ADB6A4BULL,
		0x226FA4DB7E52EDE4ULL,
		0xFD9191CE282DA14FULL,
		0x30CCE403490F6634ULL,
		0x384F2378C3503071ULL,
		0x000002B6FD87E134ULL
	}};
	shift = 43;
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
		0xBB7DC86EB7AE2555ULL,
		0x45CB85BA069CEEF1ULL,
		0xB8FE45DD84B96B1BULL,
		0x5448E46BCD315F8CULL,
		0x10E1F2D05BF58286ULL,
		0xE90EA158AA7D8FE5ULL,
		0x991CEF8513E44CAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5C4AAA000000000ULL,
		0xD39DDE376FB90DD6ULL,
		0x972D6368B970B740ULL,
		0xA62BF1971FC8BBB0ULL,
		0x7EB050CA891C8D79ULL,
		0x4FB1FCA21C3E5A0BULL,
		0x7C89955D21D42B15ULL,
		0x00000013239DF0A2ULL
	}};
	shift = 37;
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
		0x1719E6D2485B10B9ULL,
		0xFCC8839AE5190708ULL,
		0xF3A4A1F574D0A4F1ULL,
		0x2DAEA9ED78BD2ABAULL,
		0x350C40EEA88F20ABULL,
		0xC3B29A3428C072CDULL,
		0x76307697A0F1FB5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719E6D2485B10B90ULL,
		0xCC8839AE51907081ULL,
		0x3A4A1F574D0A4F1FULL,
		0xDAEA9ED78BD2ABAFULL,
		0x50C40EEA88F20AB2ULL,
		0x3B29A3428C072CD3ULL,
		0x6307697A0F1FB5CCULL,
		0x0000000000000007ULL
	}};
	shift = 4;
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
		0x95721B7806DB5B22ULL,
		0xC78D96177AC80B19ULL,
		0x8D5E4B3911212C3BULL,
		0xC9FA6F9250932B36ULL,
		0x26FEB6E5B839A744ULL,
		0xCA246BFF13F1E51BULL,
		0xB961B306B1327227ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0x6655C86DE01B6D6CULL,
		0xEF1E36585DEB202CULL,
		0xDA35792CE44484B0ULL,
		0x1327E9BE49424CACULL,
		0x6C9BFADB96E0E69DULL,
		0x9F2891AFFC4FC794ULL,
		0x02E586CC1AC4C9C8ULL
	}};
	shift = 58;
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
		0x860425D6C95E709EULL,
		0x59D6789B7F5A992BULL,
		0xB0EE2399E4B8BCE0ULL,
		0x69A76A4A318DBD92ULL,
		0x69AF34A24B93BCDCULL,
		0x247722F1CBC19DE7ULL,
		0x8A2F588849DCBA8EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BCE13C000000000ULL,
		0xEB532570C084BAD9ULL,
		0x97179C0B3ACF136FULL,
		0x31B7B2561DC4733CULL,
		0x72779B8D34ED4946ULL,
		0x7833BCED35E69449ULL,
		0x3B9751C48EE45E39ULL,
		0x0000001145EB1109ULL
	}};
	shift = 37;
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
		0x2119CA5489F5C519ULL,
		0x772062ECCC658FB4ULL,
		0xEA75F082B87163DCULL,
		0x605BEFBA6D08CC52ULL,
		0x9E98229919DAD1ACULL,
		0x8255569F80CDAE0EULL,
		0x3D90B42CE7910BE9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA913EB8A32000000ULL,
		0xD998CB1F68423394ULL,
		0x0570E2C7B8EE40C5ULL,
		0x74DA1198A5D4EBE1ULL,
		0x3233B5A358C0B7DFULL,
		0x3F019B5C1D3D3045ULL,
		0x59CF2217D304AAADULL,
		0x00000000007B2168ULL
	}};
	shift = 25;
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
		0x741712DDB4D1A15CULL,
		0xD91523A6A74C6E4FULL,
		0xA925FA0ED59B79B1ULL,
		0x9322826DD94B4109ULL,
		0x40AEEC0D8A242C18ULL,
		0x17241E2221A66797ULL,
		0x4C4ECD50C7D907E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB69A342B800000ULL,
		0x74D4E98DC9EE82E2ULL,
		0x41DAB36F363B22A4ULL,
		0x4DBB2968213524BFULL,
		0x81B1448583126450ULL,
		0xC44434CCF2E815DDULL,
		0xAA18FB20FD02E483ULL,
		0x00000000000989D9ULL
	}};
	shift = 21;
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
		0xFC815408ACF7E0A4ULL,
		0x179F03E685F1D19AULL,
		0xCA983198CFEB6EECULL,
		0xAB502718F004F9E5ULL,
		0xDFF3AC26F25ABF5AULL,
		0x589F18E3EF52D62DULL,
		0xDA5064BE4FE87536ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF829000000000000ULL,
		0x7466BF2055022B3DULL,
		0xDBBB05E7C0F9A17CULL,
		0x3E7972A60C6633FAULL,
		0xAFD6AAD409C63C01ULL,
		0xB58B77FCEB09BC96ULL,
		0x1D4D9627C638FBD4ULL,
		0x00003694192F93FAULL
	}};
	shift = 46;
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
		0xDA8FE7EAA7FF04BCULL,
		0xC9B250F420DBF0F9ULL,
		0x1556539CAC7D40E5ULL,
		0x2892107D00FE8222ULL,
		0x487B41B56BE47C93ULL,
		0x149AF779FE8AEF56ULL,
		0x670684E7AA6F1860ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F9FAA9FFC12F00ULL,
		0x6C943D0836FC3E76ULL,
		0x5594E72B1F503972ULL,
		0x24841F403FA08885ULL,
		0x1ED06D5AF91F24CAULL,
		0x26BDDE7FA2BBD592ULL,
		0xC1A139EA9BC61805ULL,
		0x0000000000000019ULL
	}};
	shift = 6;
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
		0x028DE030C003417BULL,
		0x5F0FB7461F94A080ULL,
		0xBA24A68C0FB7B711ULL,
		0xF02271CE85DD8D31ULL,
		0xEC83229891C0F2F8ULL,
		0x5E748142D67F59F9ULL,
		0x64A8673D4B890FC4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0186001A0BD80000ULL,
		0xBA30FCA50400146FULL,
		0x34607DBDB88AF87DULL,
		0x8E742EEC698DD125ULL,
		0x14C48E0797C78113ULL,
		0x0A16B3FACFCF6419ULL,
		0x39EA5C487E22F3A4ULL,
		0x0000000000032543ULL
	}};
	shift = 19;
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
		0xA86133FE8FA98853ULL,
		0x882756D752775BB7ULL,
		0xBBAA6B74D164B212ULL,
		0xBD8A3B1FADAC6E71ULL,
		0x7083CC5A93D8C7C6ULL,
		0xD344FE0EA9C3E6EFULL,
		0x50B49A2A813FA3C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D4C42980000000ULL,
		0xA93BADDBD43099FFULL,
		0x68B259094413AB6BULL,
		0xD6D63738DDD535BAULL,
		0x49EC63E35EC51D8FULL,
		0x54E1F377B841E62DULL,
		0x409FD1E069A27F07ULL,
		0x00000000285A4D15ULL
	}};
	shift = 31;
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
		0x6213B43A98C2C339ULL,
		0x142905621B9FE054ULL,
		0x7127D2521208753FULL,
		0xA8135D2BE1C75A75ULL,
		0xEEBF428448B7D0E1ULL,
		0x183BC5F89A3C67B6ULL,
		0x094365007391168BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2C339000000000ULL,
		0xB9FE0546213B43A9ULL,
		0x208753F142905621ULL,
		0x1C75A757127D2521ULL,
		0x8B7D0E1A8135D2BEULL,
		0xA3C67B6EEBF42844ULL,
		0x391168B183BC5F89ULL,
		0x0000000094365007ULL
	}};
	shift = 36;
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
		0xF37BF0C15E089C9EULL,
		0x301092A1C7413B74ULL,
		0xE177E9A4B55366BCULL,
		0xEC72DDE07C158E9FULL,
		0x54211001F1A7F730ULL,
		0xB76D8E58C8B9728CULL,
		0x8C03F42F89FF21FBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2727800000000000ULL,
		0x4EDD3CDEFC305782ULL,
		0xD9AF0C0424A871D0ULL,
		0x63A7F85DFA692D54ULL,
		0xFDCC3B1CB7781F05ULL,
		0x5CA3150844007C69ULL,
		0xC87EEDDB6396322EULL,
		0x00002300FD0BE27FULL
	}};
	shift = 46;
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
		0x65F368BFA2BBC64BULL,
		0x12528CBE15EBBFA6ULL,
		0x36184587F9926F02ULL,
		0xBDB6E4018112AB56ULL,
		0xE96DBF4662265118ULL,
		0x6EEBF383C8ED2F8EULL,
		0x04E9C9EC78C7A3F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x778C960000000000ULL,
		0xD77F4CCBE6D17F45ULL,
		0x24DE0424A5197C2BULL,
		0x2556AC6C308B0FF3ULL,
		0x4CA2317B6DC80302ULL,
		0xDA5F1DD2DB7E8CC4ULL,
		0x8F47ECDDD7E70791ULL,
		0x00000009D393D8F1ULL
	}};
	shift = 41;
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
		0xCFC336719F1E8FF7ULL,
		0xEE2BC8B86D8EF1AFULL,
		0x51B6CADAF1F453B3ULL,
		0x872DB51092ADDDB8ULL,
		0x13FED850608FE925ULL,
		0xC8FD07F63DA1EEF7ULL,
		0x4177A0FAA29041C9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1FEE00000000000ULL,
		0xDE35F9F866CE33E3ULL,
		0x8A767DC579170DB1ULL,
		0xBBB70A36D95B5E3EULL,
		0xFD24B0E5B6A21255ULL,
		0x3DDEE27FDB0A0C11ULL,
		0x0839391FA0FEC7B4ULL,
		0x0000082EF41F5452ULL
	}};
	shift = 45;
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
		0xABA8D02194AC9013ULL,
		0x88B7F33EE398E2F1ULL,
		0xB503CBFA21E02759ULL,
		0x8C48552BA8C62091ULL,
		0x84B4897D9AAC6193ULL,
		0xF749396BE4C41BB3ULL,
		0xA2BA38B36848E96CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46810CA564809800ULL,
		0xBF99F71CC7178D5DULL,
		0x1E5FD10F013ACC45ULL,
		0x42A95D4631048DA8ULL,
		0xA44BECD5630C9C62ULL,
		0x49CB5F2620DD9C25ULL,
		0xD1C59B42474B67BAULL,
		0x0000000000000515ULL
	}};
	shift = 11;
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
		0x0A49675F35EE2CC9ULL,
		0x55A0247DA10BFEE4ULL,
		0xD5CF393C40055BD9ULL,
		0xE14B02AC1115B342ULL,
		0xB4B98EEDBB1A2092ULL,
		0x50674226ED237729ULL,
		0x30FA0FADD3D02499ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF9AF7166480000ULL,
		0x23ED085FF720524BULL,
		0xC9E2002ADECAAD01ULL,
		0x156088AD9A16AE79ULL,
		0x776DD8D104970A58ULL,
		0x1137691BB94DA5CCULL,
		0x7D6E9E8124CA833AULL,
		0x00000000000187D0ULL
	}};
	shift = 19;
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
		0xC3426715ABB7BEB8ULL,
		0xCF4F33FD37DBCA30ULL,
		0xE58E67643A4CE81DULL,
		0xC651C25143C5FFEFULL,
		0xE7EABFD2F44F518FULL,
		0x85E7DD9A9FBEA246ULL,
		0x86E843215E4F6709ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61A1338AD5DBDF5CULL,
		0xE7A799FE9BEDE518ULL,
		0xF2C733B21D26740EULL,
		0xE328E128A1E2FFF7ULL,
		0x73F55FE97A27A8C7ULL,
		0xC2F3EECD4FDF5123ULL,
		0x43742190AF27B384ULL
	}};
	shift = 63;
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
		0xBD99E685E4B763CFULL,
		0xDA5D0BA00FC949CDULL,
		0x7C8EE5E86928CD38ULL,
		0xDAEF42D9135C425CULL,
		0x2C6FA81C0DBEE31BULL,
		0x28A241A9E2BB3194ULL,
		0x443FF523C7F58D99ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C0000000000000ULL,
		0x736F6679A1792DD8ULL,
		0x4E369742E803F252ULL,
		0x971F23B97A1A4A33ULL,
		0xC6F6BBD0B644D710ULL,
		0x650B1BEA07036FB8ULL,
		0x664A28906A78AECCULL,
		0x00110FFD48F1FD63ULL
	}};
	shift = 54;
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
		0x25EB86C4ABB73597ULL,
		0xE1967D612820DB12ULL,
		0xD51F34CC661D32B8ULL,
		0xA8B1E90E22DDC598ULL,
		0xF44D2C28A1F270EBULL,
		0x4C8CBEBAF8069155ULL,
		0x5A5C95E64358DC11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B12AEDCD65C000ULL,
		0x9F584A0836C4897AULL,
		0xCD3319874CAE3865ULL,
		0x7A4388B771663547ULL,
		0x4B0A287C9C3AEA2CULL,
		0x2FAEBE01A4557D13ULL,
		0x257990D637045323ULL,
		0x0000000000001697ULL
	}};
	shift = 14;
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
		0x38371CDCF5C274DBULL,
		0x7D6EC68C02A121E3ULL,
		0x8092E8BD6F4149F7ULL,
		0x69E36659B8C21AA0ULL,
		0xB93379FE6407F05DULL,
		0xB8A488C3B48A83B4ULL,
		0x0B0C75D7B9597239ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE39B9EB84E9B6000ULL,
		0xD8D18054243C6706ULL,
		0x5D17ADE8293EEFADULL,
		0x6CCB371843541012ULL,
		0x6F3FCC80FE0BAD3CULL,
		0x9118769150769726ULL,
		0x8EBAF72B2E473714ULL,
		0x0000000000000161ULL
	}};
	shift = 13;
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
		0x5B5900300D7F28D6ULL,
		0xB58CA578D7DEF0CDULL,
		0xAB01EB6B97C9400AULL,
		0x03B2907B3A4F82B6ULL,
		0x28DA3B42849582D9ULL,
		0xEA3289B84FE1EE0CULL,
		0x513D8F22F6A7478FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA358000000000000ULL,
		0xC3356D6400C035FCULL,
		0x002AD63295E35F7BULL,
		0x0ADAAC07ADAE5F25ULL,
		0x0B640ECA41ECE93EULL,
		0xB830A368ED0A1256ULL,
		0x1E3FA8CA26E13F87ULL,
		0x000144F63C8BDA9DULL
	}};
	shift = 50;
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
		0x24EE5788420AA1BCULL,
		0xD5ACCDAE33E8A08DULL,
		0xAEB296C072BBFBD0ULL,
		0x77F0B949778A44CCULL,
		0x0AEBC418682E61FAULL,
		0x67F4CA53637F9A2DULL,
		0x1284CFA8DAAFB206ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x92772BC4210550DEULL,
		0x6AD666D719F45046ULL,
		0x57594B60395DFDE8ULL,
		0x3BF85CA4BBC52266ULL,
		0x8575E20C341730FDULL,
		0x33FA6529B1BFCD16ULL,
		0x094267D46D57D903ULL
	}};
	shift = 63;
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
		0xDE2B45D1FD230CDDULL,
		0xE875DFA61113F63BULL,
		0xEB26927204039076ULL,
		0xEA6F206D5FD8BC23ULL,
		0xD899C8447A6EC918ULL,
		0x8736EF5F13FBB580ULL,
		0x5B351033775E3932ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230CDD0000000000ULL,
		0x13F63BDE2B45D1FDULL,
		0x039076E875DFA611ULL,
		0xD8BC23EB26927204ULL,
		0x6EC918EA6F206D5FULL,
		0xFBB580D899C8447AULL,
		0x5E39328736EF5F13ULL,
		0x0000005B35103377ULL
	}};
	shift = 40;
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
		0xB7AA48C31128E061ULL,
		0x370BF6C779D19947ULL,
		0xD3317349E09A9FB9ULL,
		0x2B462C844E0D4BE8ULL,
		0x14590B854EAF0D7EULL,
		0xD19BCFA705AE7AAAULL,
		0x2F0B4E728B9B573DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3818400000000000ULL,
		0x6651EDEA9230C44AULL,
		0xA7EE4DC2FDB1DE74ULL,
		0x52FA34CC5CD27826ULL,
		0xC35F8AD18B211383ULL,
		0x9EAA851642E153ABULL,
		0xD5CF7466F3E9C16BULL,
		0x00000BC2D39CA2E6ULL
	}};
	shift = 46;
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
		0x922A84C0E23C8A8EULL,
		0xDA41D504EE50A6DDULL,
		0x9BD02CFE94BB6074ULL,
		0x9771CD96757D81A6ULL,
		0xBF33D1AEF3B777CDULL,
		0x1A4C6B48C17573DAULL,
		0x6E4ADF4EF127CC10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4550981C479151C0ULL,
		0x483AA09DCA14DBB2ULL,
		0x7A059FD2976C0E9BULL,
		0xEE39B2CEAFB034D3ULL,
		0xE67A35DE76EEF9B2ULL,
		0x498D69182EAE7B57ULL,
		0xC95BE9DE24F98203ULL,
		0x000000000000000DULL
	}};
	shift = 5;
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
		0x91E77D9323D6FC95ULL,
		0x6EEE9838EDBAC60CULL,
		0xF818344B45CA71BFULL,
		0xAA69EF20BF04E08CULL,
		0xC17C4CFBA262399CULL,
		0xBFB1A07A414BE4EDULL,
		0xDAEDE67C2C5EEEEAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0x648F3BEC991EB7E4ULL,
		0xFB7774C1C76DD630ULL,
		0x67C0C1A25A2E538DULL,
		0xE5534F7905F82704ULL,
		0x6E0BE267DD1311CCULL,
		0x55FD8D03D20A5F27ULL,
		0x06D76F33E162F777ULL
	}};
	shift = 59;
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
		0x0D4D7F2989B1A16AULL,
		0xDE09B821E26C7393ULL,
		0x88677578A1ADFFAEULL,
		0x018CF9DBD0477CDBULL,
		0x9CC0BB7DE9F81B2FULL,
		0xB959D85BF0756880ULL,
		0xBAF256FBE623B3E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCA626C685A80000ULL,
		0xE08789B1CE4C3535ULL,
		0xD5E286B7FEBB7826ULL,
		0xE76F411DF36E219DULL,
		0xEDF7A7E06CBC0633ULL,
		0x616FC1D5A2027302ULL,
		0x5BEF988ECF9EE567ULL,
		0x000000000002EBC9ULL
	}};
	shift = 18;
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
		0x68F59FF9B9AE2E1CULL,
		0x32DDF61BB4D25959ULL,
		0xAA7F89294837380DULL,
		0x0B4A14CF274DA5A7ULL,
		0xB4E2E074A25F918EULL,
		0x9B7D6AE746F0DD6CULL,
		0x30EB8ECD6F347768ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1EB3FF3735C5C38ULL,
		0x65BBEC3769A4B2B2ULL,
		0x54FF1252906E701AULL,
		0x1694299E4E9B4B4FULL,
		0x69C5C0E944BF231CULL,
		0x36FAD5CE8DE1BAD9ULL,
		0x61D71D9ADE68EED1ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xC8AC64D6DE8F8274ULL,
		0x0B5955B4445F9290ULL,
		0x9969AFB8DA0DA8D6ULL,
		0xE09DA9B59FEFBC40ULL,
		0xD787D6D304E47AFAULL,
		0x48AD3938A33CFED0ULL,
		0x11F0361C2A6CC155ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE8F827400000000ULL,
		0x445F9290C8AC64D6ULL,
		0xDA0DA8D60B5955B4ULL,
		0x9FEFBC409969AFB8ULL,
		0x04E47AFAE09DA9B5ULL,
		0xA33CFED0D787D6D3ULL,
		0x2A6CC15548AD3938ULL,
		0x0000000011F0361CULL
	}};
	shift = 32;
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
		0xF1303E75D2482468ULL,
		0x4C653055456CB86DULL,
		0xF37BCD166E9D5E24ULL,
		0x0467848FADBBF5F0ULL,
		0x5283CD9F2778CA89ULL,
		0xD280D45D074CE391ULL,
		0xFD81402AEB23EAC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9D7492091A00000ULL,
		0xC15515B2E1B7C4C0ULL,
		0x3459BA7578913194ULL,
		0x123EB6EFD7C3CDEFULL,
		0x367C9DE32A24119EULL,
		0x51741D338E454A0FULL,
		0x00ABAC8FAB074A03ULL,
		0x000000000003F605ULL
	}};
	shift = 18;
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
		0xEB3ED0839D12884FULL,
		0xA409FEAF779D42AFULL,
		0xE48E53DEE645DC83ULL,
		0x7A751C0C06590B08ULL,
		0x35AF12D3EBA99D2BULL,
		0xD3ACE59EA7C7C267ULL,
		0x9E92C048BD56F811ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACFB420E744A213CULL,
		0x9027FABDDE750ABFULL,
		0x92394F7B9917720EULL,
		0xE9D4703019642C23ULL,
		0xD6BC4B4FAEA674ADULL,
		0x4EB3967A9F1F099CULL,
		0x7A4B0122F55BE047ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
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
		0xB6B1D728B68C0B87ULL,
		0x01FAED57DD74FB3BULL,
		0x96346B19CCF0320EULL,
		0x20C281298DDBA02EULL,
		0x9B1AAE7643B3C8CEULL,
		0xCECBA6D63A8A8B50ULL,
		0x01A002D9398EEBCCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C3800000000000ULL,
		0x7D9DDB58EB945B46ULL,
		0x190700FD76ABEEBAULL,
		0xD0174B1A358CE678ULL,
		0xE46710614094C6EDULL,
		0x45A84D8D573B21D9ULL,
		0x75E66765D36B1D45ULL,
		0x000000D0016C9CC7ULL
	}};
	shift = 47;
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
		0xC6DAB95E13B03305ULL,
		0x1C4767A303683B48ULL,
		0xEEBE1143D0945CF8ULL,
		0x8EB9EF8356F8E093ULL,
		0xDA2AB8410FAA43E1ULL,
		0xF6D86FECC3CB61F7ULL,
		0x24A5CE4EE11D379DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D8198280000000ULL,
		0x81B41DA4636D5CAFULL,
		0xE84A2E7C0E23B3D1ULL,
		0xAB7C7049F75F08A1ULL,
		0x87D521F0C75CF7C1ULL,
		0x61E5B0FBED155C20ULL,
		0x708E9BCEFB6C37F6ULL,
		0x000000001252E727ULL
	}};
	shift = 31;
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
		0xA8056CD7B5AA1A1EULL,
		0xD116E0AF8A40ABFDULL,
		0x0A07AF73EF0C9146ULL,
		0x9DE1F33C66371C7DULL,
		0xE39386F254659180ULL,
		0xA94844CD0EE20753ULL,
		0x8009EC96922AEDC7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x500AD9AF6B54343CULL,
		0xA22DC15F148157FBULL,
		0x140F5EE7DE19228DULL,
		0x3BC3E678CC6E38FAULL,
		0xC7270DE4A8CB2301ULL,
		0x5290899A1DC40EA7ULL,
		0x0013D92D2455DB8FULL,
		0x0000000000000001ULL
	}};
	shift = 1;
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
		0xD91A823303F2132DULL,
		0xF0A8010204FC71CCULL,
		0x12D1180EA091D4D2ULL,
		0x24F7F1F1A98D451BULL,
		0x395C15B50EAB7683ULL,
		0x9FFA25274537DA50ULL,
		0x9BA666816AD9D222ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607E4265A0000000ULL,
		0x409F8E399B235046ULL,
		0xD4123A9A5E150020ULL,
		0x3531A8A3625A2301ULL,
		0xA1D56ED0649EFE3EULL,
		0xE8A6FB4A072B82B6ULL,
		0x2D5B3A4453FF44A4ULL,
		0x000000001374CCD0ULL
	}};
	shift = 29;
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
		0xA97695FB0895414CULL,
		0xB62CF47A512A0847ULL,
		0x15A71646994DF595ULL,
		0xCB01FAE49BB63C97ULL,
		0x23EEF933D52F7EF5ULL,
		0x3C1948601B26C1EDULL,
		0x38418721E1F9B43BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57EC225505300000ULL,
		0xD1E944A8211EA5DAULL,
		0x591A6537D656D8B3ULL,
		0xEB926ED8F25C569CULL,
		0xE4CF54BDFBD72C07ULL,
		0x21806C9B07B48FBBULL,
		0x1C8787E6D0ECF065ULL,
		0x000000000000E106ULL
	}};
	shift = 18;
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
		0xCFACA77CA0471BB3ULL,
		0x663D4A3125A1918AULL,
		0x0A1F67E89D6A4DB8ULL,
		0xCD388D0B03DCEF14ULL,
		0x111A09E1EC3B0925ULL,
		0xEDE22849D97954E7ULL,
		0x0AEC583223E722C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB30000000000000ULL,
		0x18ACFACA77CA0471ULL,
		0xDB8663D4A3125A19ULL,
		0xF140A1F67E89D6A4ULL,
		0x925CD388D0B03DCEULL,
		0x4E7111A09E1EC3B0ULL,
		0x2C4EDE22849D9795ULL,
		0x0000AEC583223E72ULL
	}};
	shift = 52;
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
		0xE802DF8E981AADEEULL,
		0x34A466F4F6E4B57BULL,
		0x2F454D241EFC31F4ULL,
		0x2A9886BB106CD7A1ULL,
		0xDF4BDE42AA75999EULL,
		0x8BEF5F5E7ECE2EF5ULL,
		0x30D9B7A92FAA0DAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB800000000000000ULL,
		0xEFA00B7E3A606AB7ULL,
		0xD0D2919BD3DB92D5ULL,
		0x84BD1534907BF0C7ULL,
		0x78AA621AEC41B35EULL,
		0xD77D2F790AA9D666ULL,
		0xAA2FBD7D79FB38BBULL,
		0x00C366DEA4BEA836ULL
	}};
	shift = 58;
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
		0x1A98868C8917584AULL,
		0x7497E6C9458B1EDEULL,
		0xFD7FA153CDDDF4CAULL,
		0x8614DFDFA7967B5DULL,
		0xEF2910FC723B140EULL,
		0x2575C6F727B83506ULL,
		0x06F16A7111720745ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19122EB094000000ULL,
		0x928B163DBC35310DULL,
		0xA79BBBE994E92FCDULL,
		0xBF4F2CF6BBFAFF42ULL,
		0xF8E476281D0C29BFULL,
		0xEE4F706A0DDE5221ULL,
		0xE222E40E8A4AEB8DULL,
		0x00000000000DE2D4ULL
	}};
	shift = 25;
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
		0xF3D55A4C9562B12AULL,
		0x1111530BD5C4FD09ULL,
		0xEBFEE740543C8750ULL,
		0xA01C22072DD278CFULL,
		0xD499DDB101937983ULL,
		0x18B64F00AA12B8F1ULL,
		0xD1ECD382E169F91CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56932558AC4A8000ULL,
		0x54C2F5713F427CF5ULL,
		0xB9D0150F21D40444ULL,
		0x0881CB749E33FAFFULL,
		0x776C4064DE60E807ULL,
		0x93C02A84AE3C7526ULL,
		0x34E0B85A7E47062DULL,
		0x000000000000347BULL
	}};
	shift = 14;
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
		0x28C0ACEBDC8E98E8ULL,
		0xB829EAAC55753500ULL,
		0x16EADB62FB3D7AC8ULL,
		0x6A340A6B7EFCD74FULL,
		0x78CEC454D0E01886ULL,
		0xF33CEB0FAE05A227ULL,
		0x2E0D8F96F21560B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA63A000000000000ULL,
		0x4D400A302B3AF723ULL,
		0x5EB22E0A7AAB155DULL,
		0x35D3C5BAB6D8BECFULL,
		0x06219A8D029ADFBFULL,
		0x6889DE33B1153438ULL,
		0x582DFCCF3AC3EB81ULL,
		0x00000B8363E5BC85ULL
	}};
	shift = 46;
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
		0xCE16A4E47622682BULL,
		0x7BA437E360F4F6ABULL,
		0xF601E19225C98732ULL,
		0xB6DA2FE2B13FC03AULL,
		0x46B1EFDB19359166ULL,
		0x31A9DB71BD14F3D1ULL,
		0x8ABE03A6F32F188BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2723B11341580000ULL,
		0xBF1B07A7B55E70B5ULL,
		0x0C912E4C3993DD21ULL,
		0x7F1589FE01D7B00FULL,
		0x7ED8C9AC8B35B6D1ULL,
		0xDB8DE8A79E8A358FULL,
		0x1D379978C4598D4EULL,
		0x00000000000455F0ULL
	}};
	shift = 19;
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
		0x42ABCB8F15386C70ULL,
		0x2379D855FFAAE8FDULL,
		0x048F6494A84EDE0DULL,
		0x753054AE8A3F30EFULL,
		0x8D3BAE0D10303AACULL,
		0xCD43DE2AB3C54958ULL,
		0x8AEDEEC1F3CF261EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD42ABCB8F15386C7ULL,
		0xD2379D855FFAAE8FULL,
		0xF048F6494A84EDE0ULL,
		0xC753054AE8A3F30EULL,
		0x88D3BAE0D10303AAULL,
		0xECD43DE2AB3C5495ULL,
		0x08AEDEEC1F3CF261ULL
	}};
	shift = 60;
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
		0x1898DCAB20E414F8ULL,
		0x5178A28C84D4BF16ULL,
		0x88AC6FB0E14E6B94ULL,
		0xF971F9B04049A3E7ULL,
		0x1AE9AC25C92C93A9ULL,
		0xEA2D5080C4AF07E1ULL,
		0x9E9AE6553CDF6C29ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6E5590720A7C000ULL,
		0xC5146426A5F8B0C4ULL,
		0x637D870A735CA28BULL,
		0x8FCD82024D1F3C45ULL,
		0x4D612E49649D4FCBULL,
		0x6A840625783F08D7ULL,
		0xD732A9E6FB614F51ULL,
		0x00000000000004F4ULL
	}};
	shift = 11;
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
		0xE36E8F288EBEDFEFULL,
		0x54FD2D2FC10ABF0FULL,
		0x7DC3BE0E83023161ULL,
		0xC2238105A6C16962ULL,
		0xB693A10A48F06F06ULL,
		0xEF68231A02F1535EULL,
		0x4925AEF5B15D9357ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F6FF7800000000ULL,
		0x0855F87F1B747944ULL,
		0x18118B0AA7E9697EULL,
		0x360B4B13EE1DF074ULL,
		0x47837836111C082DULL,
		0x178A9AF5B49D0852ULL,
		0x8AEC9ABF7B4118D0ULL,
		0x00000002492D77ADULL
	}};
	shift = 35;
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
		0x0000800000000000ULL,
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
		0x0000000000000080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000200ULL,
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
	shift = 28;
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
		0x0004000000000000ULL,
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
		0x0000004000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x0000000000000800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000800000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000400000000ULL,
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
		0x0000000000000400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x4000000000000000ULL,
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
		0x0000004000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x0001000000000000ULL,
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
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000080000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x0000010000000000ULL,
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
		0x0000000001000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x0000000000000000ULL,
		0x2000000000000000ULL,
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
		0x0000000000000020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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