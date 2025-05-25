#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6CB2351E4071CD2EULL,
		0xB3AF6444656083AFULL,
		0x492C9C88AEA8EDBDULL,
		0x600C4024A5A97038ULL,
		0xFAB78CD37FAF51FFULL,
		0x2AB8C2650AB3B630ULL,
		0xAFF7DC75677BEEA4ULL,
		0x9BD75A0FD0DAC61BULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xDBC03CDDF55846FEULL,
		0xE149EEC196230726ULL,
		0x4F209A3F5A04AFAFULL,
		0xEB48814A90213E05ULL,
		0xBB5568CDC7CCDED8ULL,
		0x065E01D95350A4A5ULL,
		0xFAE1FC11C140E6C3ULL,
		0x1E21EC5458317620ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E35CBE74C805DE6ULL,
		0x1246B1EF28A74CB9ULL,
		0x6DB6F30C154327D5ULL,
		0xD5799C62016AE453ULL,
		0xD7D539E63A6E8641ULL,
		0x2340B018980A2F75ULL,
		0x460D34143D0466EEULL,
		0xCA36DF7988A2AF2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBA714DC2969AD9ULL,
		0x41CB9F61D14EA1E2ULL,
		0xD2F1224149694EA4ULL,
		0x45197ECBF46A9B88ULL,
		0x2D185726DEE8DC6CULL,
		0x6562512BE300861DULL,
		0x2B19F6BA9833E631ULL,
		0xA5FEAD3D4565D59FULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB07928264AFBDE68ULL,
		0x6351FEE68CA3D1A3ULL,
		0x5F19F8C5269F94DCULL,
		0xDF61CD3D6B27B86CULL,
		0xC3301EBCFF839255ULL,
		0x063313F1C942D4C1ULL,
		0xB29C5A6A2FD7FA18ULL,
		0x6ECD92DC729DE233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F074A752F7C0B41ULL,
		0x9EFF3A4C24B3D5A1ULL,
		0x199CEEBA1D2DD286ULL,
		0x0024D449EB04B2D0ULL,
		0x968A5EF910115E82ULL,
		0x18C23DFAA32D536FULL,
		0x6AD0E5DDC25E34C0ULL,
		0x20B265B5B8091B51ULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x564F1E8D06B4BDF6ULL,
		0xE9253D0A4451C894ULL,
		0x5F53F8C6EC71F701ULL,
		0xBF31695960541099ULL,
		0xACF7AFFF26396411ULL,
		0xD906141CC3079A4AULL,
		0x77DAB6FBE30B8423ULL,
		0x9AF0E5ECA7CA7ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BDE189B8DCB3A94ULL,
		0xB851D449C6F36308ULL,
		0xFC48A093671F9353ULL,
		0x28EE6513288367FDULL,
		0xA8BD62162CAC7519ULL,
		0xCF0EC9E083A2625AULL,
		0xB2C2FF39AB974AE8ULL,
		0x8EE900009023B84AULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7EB2334F7553701ULL,
		0x50FC308643923376ULL,
		0xD5C012033DF48D81ULL,
		0x3DD851A5925422D7ULL,
		0x3FBD9541EC0DBD20ULL,
		0x7651E0EFF6FA27C2ULL,
		0x46B62B980790521DULL,
		0x7BED0EAC4E8D06F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7EB2334F7553701ULL,
		0x50FC308643923376ULL,
		0xD5C012033DF48D81ULL,
		0x3DD851A5925422D7ULL,
		0x3FBD9541EC0DBD20ULL,
		0x7651E0EFF6FA27C2ULL,
		0x46B62B980790521DULL,
		0x7BED0EAC4E8D06F4ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAB42BCA61DE7635ULL,
		0x34323B5D5087FC8EULL,
		0x229480366F739D83ULL,
		0xF721256DA1F48FE1ULL,
		0xD0144E5DAF8EA010ULL,
		0x66BB58FF4E181E4FULL,
		0x70CBEDEFFFF3FA9FULL,
		0xC9262DCDF1CF8FCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C82A131BEA542BULL,
		0x4D8CB618C3E56415ULL,
		0x8554FCAE568AC503ULL,
		0x768B4E05455E1484ULL,
		0xAA2CB8C0C273468FULL,
		0xE1D0C8485F24E026ULL,
		0x6EE3BDF407E21851ULL,
		0xE8238A48A4307971ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC6F687476B18512ULL,
		0xAB23819A0FD3232BULL,
		0xAA555C2B6877848DULL,
		0x2F02418C0C85E3C1ULL,
		0x0275909877EF44B5ULL,
		0x904AB88185A3549BULL,
		0x963CB59C16CB3115ULL,
		0x1BBAB26B5FE55765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA10E26AA68671141ULL,
		0xFF1C203C6A24C720ULL,
		0x23E88CEBC2608436ULL,
		0xF159B3E4F86CE6D1ULL,
		0x5317E8553CEA543BULL,
		0xD2658680DE0F9C2CULL,
		0xDA8C627D06C7BE5BULL,
		0xD69B32C9E0C449D8ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF41FA1801347517ULL,
		0x073B527BF791757AULL,
		0x523A63F7E76B2D75ULL,
		0xAF3485255B7F50DFULL,
		0x0B8638DB9CC6F57BULL,
		0x2499F36D2800F1E4ULL,
		0x9E3A7C71D1CA87D1ULL,
		0xB25F2080B3A90B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD97D5EE73EA4084CULL,
		0x06D8CAE2810AEDF7ULL,
		0xE12679409688EB2AULL,
		0x61DA5FB0D21AB756ULL,
		0x20D58C79610D7B71ULL,
		0xDE85BA5D25AEFDFFULL,
		0xA78BD2F730CB801FULL,
		0x7D84F5E60833EB5BULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A38CF51FD723E98ULL,
		0x1EE7D73B16D0CAD7ULL,
		0xB97650486CAF18AAULL,
		0xB14BF95198941AAAULL,
		0x8873C07FCCC62748ULL,
		0x9B0C59993B88F485ULL,
		0x6E40E33CDD28324EULL,
		0x048F909FF49982AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A38CF51FD723E98ULL,
		0x1EE7D73B16D0CAD7ULL,
		0xB97650486CAF18AAULL,
		0xB14BF95198941AAAULL,
		0x8873C07FCCC62748ULL,
		0x9B0C59993B88F485ULL,
		0x6E40E33CDD28324EULL,
		0x048F909FF49982AEULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4ED3229E80F4BB95ULL,
		0x31C9BB9E725E2B39ULL,
		0x3A37A24BF6BF35A0ULL,
		0x445870FF51C6992EULL,
		0x02267A490FDB50DBULL,
		0x4DE4AC93A9D75133ULL,
		0xBA405E863B0B614AULL,
		0x14729E8A6CBDC41AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35D53C5BEE249045ULL,
		0xE379F269D559F899ULL,
		0xEF4778E53A92D6A2ULL,
		0xC28723FCD702DBD1ULL,
		0x193911AFB8AFFEDEULL,
		0xEB0D1C3E1D22A7E6ULL,
		0x727DAE04F174B04EULL,
		0xEA4E4DA63A0CE9DFULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFC78CB58D8F5E09ULL,
		0x444AE0E8758A29B5ULL,
		0x70F4194554182727ULL,
		0xE292D033BF21566FULL,
		0x41513EB5EAD8588AULL,
		0x80DF814A58E077C6ULL,
		0x943197A7A5145588ULL,
		0x1B70B44B7D8E2C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E2BC67629606A58ULL,
		0x7950DCACD1B95AD1ULL,
		0x09A315A74858DAC5ULL,
		0x51C93CC380FE1E1BULL,
		0x07CF39258661D4ECULL,
		0x0B9C80923D973152ULL,
		0xB070D3EB7553782AULL,
		0xBA124DC67BA7552EULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37F1E34A94852AF5ULL,
		0xA4D766604B0828E4ULL,
		0xBDB6DBA969EBD66BULL,
		0xDEAA2CC7974CAFB7ULL,
		0x74DB2BCAAED7F5E1ULL,
		0x525ED5098B1F3D35ULL,
		0x8A628B8689847201ULL,
		0x4AB9BD58F9867ED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7101ABAB542D8DBCULL,
		0xDD4ED5C0E39F6EF4ULL,
		0x9A039E4D8661FBDCULL,
		0xFD75602BDCA06C6AULL,
		0xA46D47C6CC5A1163ULL,
		0xC2812333ADDA13B4ULL,
		0x04E509E195C7AB0EULL,
		0x5519BEC1AF6A4F87ULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0355ED3BBA4DFCF3ULL,
		0x96BB4CEA095D2BFBULL,
		0xC54912CF2CE9EC11ULL,
		0x0A6334EC42484A09ULL,
		0x801BF84F9B130D73ULL,
		0x07ED9D4F7AED1FF6ULL,
		0xEEBDF240945C79ECULL,
		0xE6BFBE8C99240690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0355ED3BBA4DFCF3ULL,
		0x96BB4CEA095D2BFBULL,
		0xC54912CF2CE9EC11ULL,
		0x0A6334EC42484A09ULL,
		0x801BF84F9B130D73ULL,
		0x07ED9D4F7AED1FF6ULL,
		0xEEBDF240945C79ECULL,
		0xE6BFBE8C99240690ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6DA424DAAF0A16CULL,
		0x370D2C1E966D993DULL,
		0x3FDB7B2CF2132A43ULL,
		0x568F0DD48F825290ULL,
		0xE0C45AAF13516475ULL,
		0x672D89FC4C446DA3ULL,
		0xA9CC8C027C449B6FULL,
		0x03CA9037137138E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C05E6850D639BCULL,
		0x30D1BEC4F9A3C57DULL,
		0x5034F1E6D1F9DB33ULL,
		0x7C76F2E899D3D452ULL,
		0xF41617F83C970974ULL,
		0xF3DD3C7DB2BD6776ULL,
		0x01A8AD1835C0F05BULL,
		0x11D44C5C69E7CC17ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A4548FE022C8E8DULL,
		0xBFBF89F815351D2BULL,
		0x75885FF46FDA29CCULL,
		0x9E2A664277109C26ULL,
		0x3B04415AE907E3CDULL,
		0xA4F6E6241C2788F5ULL,
		0x1E814769071F3098ULL,
		0x3EA002BB5B0AD86CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E1A23F94B7D74EULL,
		0x4748CF5440D2B4A0ULL,
		0xE82726743DAA6AC7ULL,
		0x721B109EDFF45889ULL,
		0x206774C8D0E0D3D7ULL,
		0x5DF337E362CD9B8AULL,
		0x95DCE622A7849D05ULL,
		0xF5497624C746E3F4ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A1B03CDAEE53B22ULL,
		0x492799BC374955CEULL,
		0xDCEF4CB4060B7061ULL,
		0x05286826308FD1ACULL,
		0x84B94FF5F83DE005ULL,
		0xED3EAE0F0C1A9AFBULL,
		0x18ACC24F81EC19F6ULL,
		0xA6BCF98BB63C2C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE3331ECCFFAAF1EULL,
		0x902C5336E595CC6FULL,
		0xBCFCFF12C9AC96FEULL,
		0x32A26756FE8BBF51ULL,
		0xC40C141CFA806645ULL,
		0xA7C884E4B43C8A6CULL,
		0x6883DADAE85B02C8ULL,
		0xF272FF399D086155ULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x860E89ED7A4B22ABULL,
		0xE40E6733BB099CAFULL,
		0x61195824C5160B04ULL,
		0x9145D17FD3521B56ULL,
		0xECB8D7290E85A416ULL,
		0x0C5A207EDB896075ULL,
		0x2052C84CB3ADE177ULL,
		0x8A8D03D58962CF13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860E89ED7A4B22ABULL,
		0xE40E6733BB099CAFULL,
		0x61195824C5160B04ULL,
		0x9145D17FD3521B56ULL,
		0xECB8D7290E85A416ULL,
		0x0C5A207EDB896075ULL,
		0x2052C84CB3ADE177ULL,
		0x8A8D03D58962CF13ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87411A6296545F51ULL,
		0x80A75C6F3E5C5062ULL,
		0x07FC45CD71087067ULL,
		0x9C0F103447770F5CULL,
		0xEA24D4F568BA5774ULL,
		0x5290471ECA75CFA9ULL,
		0x2431333B6145C6B2ULL,
		0x452286DE48E24C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55EF93ECD075A10ULL,
		0x6FF7C3F0DE45B0A1ULL,
		0x1380A324F39F97D0ULL,
		0xEA854FBE3AFBDCD8ULL,
		0x8EC474E112A1756DULL,
		0x7EE206CF3E2EDAACULL,
		0x4E7E5A87CB2DF142ULL,
		0x9FDA38BD8C08A818ULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01F6552A74ED3619ULL,
		0x62B180E38B219D8BULL,
		0x0AA811DF555FC3C7ULL,
		0x7FD58764DD5B8F3DULL,
		0xE6672C03498FBB7CULL,
		0x9036653C77A5AD98ULL,
		0x773490F11BB48213ULL,
		0x35A5B6AD0F9F05DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8411978BAC40481ULL,
		0xF8DD1C548E1D0553ULL,
		0x914C3A1EB8A60EA0ULL,
		0x0ADE9EC3EEB362E9ULL,
		0x2F2385A34B32E0C3ULL,
		0x5DF4354007276472ULL,
		0xA370FDAF6499420AULL,
		0xFE7EF20D96D8ADDEULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0230D7061BA2390ULL,
		0x37D6C86B6FD47D91ULL,
		0x0D06486F47E66376ULL,
		0xAAA2F77C89B56176ULL,
		0xA2B6771F328494CBULL,
		0xFC1C57D3D1C92B15ULL,
		0x2C748A66BF29271CULL,
		0x031030D275EE030DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67A859E7443B96AULL,
		0x83EB611832AE7F33ULL,
		0x9A40225C071E6EC1ULL,
		0xFD3EAF2770FE70A8ULL,
		0xA01B589A7EFFF89DULL,
		0xB3C575322FF29C64ULL,
		0x19215753696059D5ULL,
		0x6A45C6F7237FC3DFULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1941BE873BBE43ULL,
		0xE84152D2869B6315ULL,
		0xF2BE95FE5DB92B06ULL,
		0x3F874508E442127EULL,
		0xFA01B5DD971FB7ACULL,
		0x37F1A3F3515B408EULL,
		0x699982F72E7DF669ULL,
		0x2BBB6AB2F64136E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1941BE873BBE43ULL,
		0xE84152D2869B6315ULL,
		0xF2BE95FE5DB92B06ULL,
		0x3F874508E442127EULL,
		0xFA01B5DD971FB7ACULL,
		0x37F1A3F3515B408EULL,
		0x699982F72E7DF669ULL,
		0x2BBB6AB2F64136E0ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E5B2229EF98666CULL,
		0x8060E8A8FA5800BFULL,
		0x23D4675A46871CB9ULL,
		0x8B7EC5C74D9796BDULL,
		0x6C0005854281B14FULL,
		0x4E2CD210DFCABB8AULL,
		0x27D455EA002879E6ULL,
		0xC53206B1137E4C2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9683128B6B260155ULL,
		0x2E064B9FB9EB09B9ULL,
		0xEAC84634780F2145ULL,
		0xC1731B227DE325CCULL,
		0x5B56DBE07226DE85ULL,
		0xCD05A05140007D2FULL,
		0xD18C6D10BD1879B1ULL,
		0xB04FBD38AD7963FFULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA91BC22C7AF80431ULL,
		0x8862892556D08CFBULL,
		0x80FD186B6D55BA79ULL,
		0xC968CF7AD205C554ULL,
		0x0F320A91A5641BBBULL,
		0xC4CFD8D2112CD50BULL,
		0x48DDB0EA2B6CB6BDULL,
		0xC7C062902D4639D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D895F6FC24C34F8ULL,
		0x417A9AB9C1E1C674ULL,
		0xAE132E812E6CA2F2ULL,
		0x8850A0C70D81D257ULL,
		0x38558E2AE75F1B1BULL,
		0xA6106218A22BB253ULL,
		0x8614C0B9BBCDEA63ULL,
		0x7BD20610BA1B6371ULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CDCD97AD17233D9ULL,
		0xCCA2731894EAFBB8ULL,
		0x170009C82ECDC4C2ULL,
		0xC09C0773F3DACE38ULL,
		0x37757ABC77CA4352ULL,
		0x2A07F0B1D64FE9B5ULL,
		0x555869CA2BDD16ECULL,
		0x77FC25D33EAE9D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B62543E0ADAACDULL,
		0x74E9E2310809CE08ULL,
		0xDF641808076A6813ULL,
		0xB31249CBD8B65239ULL,
		0x2ED0094DD3B69D03ULL,
		0x2A547290371F7BBAULL,
		0xBD415142C8E80056ULL,
		0x7CA7B7966B7660A5ULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5E543FE2CA59F24ULL,
		0xA543B6EEE53854F9ULL,
		0xE4A288D69CCD629AULL,
		0x24096E45FFD3B7A2ULL,
		0xD94267DBD4036EA1ULL,
		0xC3B8DB5A5FCB634CULL,
		0x54D280C63FA3205FULL,
		0x62FB3356A8C25D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5E543FE2CA59F24ULL,
		0xA543B6EEE53854F9ULL,
		0xE4A288D69CCD629AULL,
		0x24096E45FFD3B7A2ULL,
		0xD94267DBD4036EA1ULL,
		0xC3B8DB5A5FCB634CULL,
		0x54D280C63FA3205FULL,
		0x62FB3356A8C25D85ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71DB041A200A714AULL,
		0x19384D7CE5FFDD00ULL,
		0x7EFD239CF802596AULL,
		0xBCAA6673BF05579DULL,
		0x52988EFA6959A58FULL,
		0x2AD4E73E7E972763ULL,
		0x042F714D7E281D7FULL,
		0x32B3698D628791B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71044A9F2BCA57B9ULL,
		0x70FE080EB945C1F5ULL,
		0x35C8369F470EAC74ULL,
		0x6A82C70ECD50F058ULL,
		0x8A9E9DDBC347C7DEULL,
		0xF42189DD013DD6B2ULL,
		0x3AF0EE4919DE319CULL,
		0xEB2CB04B08A07B17ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x784F65A614CA1A3CULL,
		0x89DB6A5F06094A64ULL,
		0xF437D2C5A5EB6A4AULL,
		0x0686EBA752B3AF22ULL,
		0xE5EE333EE80BAB64ULL,
		0x6AAAF0FC1BAC2673ULL,
		0x2F0CA159BF0ABAD6ULL,
		0x4FEF7500041746EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48498DAB80D439AAULL,
		0xBE80DD04E030EC80ULL,
		0x22160D5490741EA8ULL,
		0x3D1ACCAC87630F4EULL,
		0x85FD491A2EDACBAEULL,
		0x064522EBBF18724BULL,
		0xC847778AFD66EAB3ULL,
		0xC9132B7B40A23F69ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EF23A6F902E3805ULL,
		0x66976E11401EFCCBULL,
		0x11DE5935CDDFEBBDULL,
		0x2D4049C09E023E6DULL,
		0x31ED4B20AEBA3D21ULL,
		0xA8BB16AED05D5332ULL,
		0x06005C72987CABDDULL,
		0x614E7C7251346FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEA1A5A3B18F55CULL,
		0x5A6810E128EA9751ULL,
		0x732CFBF07AB6F59EULL,
		0x1EA192EE4C794A70ULL,
		0x01591D1D4A19CEABULL,
		0xC9594B9F0CCE61DAULL,
		0xBB214D47C825B7D1ULL,
		0x7C7D930B5C39B03BULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00A03A8E83E279BBULL,
		0x93AA9AB1FEC7AABAULL,
		0x9468E4FFDF4BE71AULL,
		0x9C6BD88A838DDD00ULL,
		0x0BD3D463AD795AB8ULL,
		0x8509348ABC4CF651ULL,
		0x0671EE69B0BC09D8ULL,
		0xFB114CD5587C780DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A03A8E83E279BBULL,
		0x93AA9AB1FEC7AABAULL,
		0x9468E4FFDF4BE71AULL,
		0x9C6BD88A838DDD00ULL,
		0x0BD3D463AD795AB8ULL,
		0x8509348ABC4CF651ULL,
		0x0671EE69B0BC09D8ULL,
		0xFB114CD5587C780DULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB98ED1E589B87F43ULL,
		0x4EDDB1F2D2AC4D1BULL,
		0xE6FFF3B885BAF0D7ULL,
		0x789F4A31BB2BAC50ULL,
		0x7DDA423D7649F676ULL,
		0xB537A82F6AC369AEULL,
		0xBC17D8EB02D7012CULL,
		0xA4E6A623DC658822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81661D777A00E1B6ULL,
		0x58CFF64110295317ULL,
		0x4D9DC5312368DB22ULL,
		0xAA8A6A9C01732E79ULL,
		0xD49CA96F09918851ULL,
		0x0C71DBBFBA8A018FULL,
		0x7060D35D2F055A6BULL,
		0x19F227A51D72C502ULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26272BA85C13AC8FULL,
		0xEC084C2E1E764205ULL,
		0x4E16DB1597E43D93ULL,
		0x315FB1D5AB68F2F2ULL,
		0x27C649E46C876B8BULL,
		0x1221605E74F0835BULL,
		0xBDF8D2321C1A525CULL,
		0x1FA0E91947D68AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEFE684D6D786850ULL,
		0x2B698F3D318733EEULL,
		0x1F8C97DBF67BB29BULL,
		0x5CBE84CCF52FB6B6ULL,
		0x25C79E1C64BC9080ULL,
		0xCA64AB476EF07BFCULL,
		0xCF6869BB950636B7ULL,
		0x8C2605B7B857FC6BULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37EA2D027481E007ULL,
		0x0BC85F267143142FULL,
		0x7DD55D3E49D54751ULL,
		0x2D4573E05456E194ULL,
		0x68B5A46AD7A00EDBULL,
		0x66F296EFE9C5A5C5ULL,
		0x69E67D1453567F4FULL,
		0x652DE287AF1E526BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F24B1EC1D865FDULL,
		0x0B6CAF409748BB6BULL,
		0x0805954D24967E31ULL,
		0xBD76D24EFD7A2857ULL,
		0x86F88DF340FD9C8BULL,
		0xA2D11BD2889A8DDAULL,
		0x2DC85A18C5922873ULL,
		0x53221F06FB6AD404ULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x197DADD4E821FA3AULL,
		0x0822C5E01918A6C9ULL,
		0xC818B91AFD05E772ULL,
		0x2A01DA6ED76E9011ULL,
		0xCB8B377E9BCF09D1ULL,
		0x5F976A1CA2F6C581ULL,
		0xEC048AE94944C255ULL,
		0x581F776887DA1948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x197DADD4E821FA3AULL,
		0x0822C5E01918A6C9ULL,
		0xC818B91AFD05E772ULL,
		0x2A01DA6ED76E9011ULL,
		0xCB8B377E9BCF09D1ULL,
		0x5F976A1CA2F6C581ULL,
		0xEC048AE94944C255ULL,
		0x581F776887DA1948ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DDEF28295932CD4ULL,
		0xA4826581B55842AEULL,
		0xB88E401FB2057D01ULL,
		0x0AAB23BB037F634CULL,
		0x5844897A610C2AFCULL,
		0xE0166A7FBD186585ULL,
		0x5D391028FCC3EA05ULL,
		0x86E02766DBD505BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C59180617F2E4D8ULL,
		0x506ACD51A3526DADULL,
		0xDB7F0F6B4C7F5D24ULL,
		0xC37C87AC20AA7F23ULL,
		0x74E78951A67D9A0AULL,
		0x7517E57BF65828F9ULL,
		0xD25627CF4785C9A0ULL,
		0xDC42F6423A434FA3ULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA56629EFBDB5BE7ULL,
		0x63427F48816BA2EFULL,
		0xCBFBB488817EA6F2ULL,
		0x28692DAE618B3893ULL,
		0x5950A265155BF23CULL,
		0xD2FE940BB6C32FE6ULL,
		0x72573BE2D62E663AULL,
		0xF5F5E97B3D48CBE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8FD1863C4A7DCCULL,
		0x1AED1D1087CD0821ULL,
		0x6FE9FCDF1F6EF2BCULL,
		0x6D45CAAE5678AB1AULL,
		0xCC6CAE820F999239ULL,
		0xA3C4A95A05968E83ULL,
		0x9E7EF1FD503E7276ULL,
		0x9AD50054CD362B96ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x908339105B25353FULL,
		0x8E03D334F6F1323FULL,
		0x56896186B08BAC3CULL,
		0x3E142542D3D9E083ULL,
		0xB9D492BCA32A7E2BULL,
		0x2D48D1AAD0F31C53ULL,
		0xEB67B0274422D997ULL,
		0xE989E8457F2B007CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFB20657456E0B96ULL,
		0x41F915B68BB9ECFBULL,
		0xF82A20B94FF7AA6CULL,
		0xB3CE5BADE76B4BF3ULL,
		0xE28EA3FAB1E7FD3EULL,
		0x7DA6F0C3E7BF8C85ULL,
		0xF6F6E08C03CE8A42ULL,
		0xAF906906647BCF22ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F7CD25EEA56E96BULL,
		0x5F8FF78788F9D7CEULL,
		0xB538F5537F53D92AULL,
		0x917450C1418AD302ULL,
		0x8A76BF2253277DE8ULL,
		0xA56154DC9A31F6A6ULL,
		0x2CE2EA3049DB3EE5ULL,
		0xFB08AF8060A23B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7CD25EEA56E96BULL,
		0x5F8FF78788F9D7CEULL,
		0xB538F5537F53D92AULL,
		0x917450C1418AD302ULL,
		0x8A76BF2253277DE8ULL,
		0xA56154DC9A31F6A6ULL,
		0x2CE2EA3049DB3EE5ULL,
		0xFB08AF8060A23B89ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9E3A6F7E867A528ULL,
		0x8B23211857352C1BULL,
		0x77657DBB6561CCD2ULL,
		0xB885DFE9DB984BCCULL,
		0x7D0911709EF745CCULL,
		0xAB01FBEE4F6E0A6BULL,
		0xE80D7020256729C0ULL,
		0x5A269EC25B89D818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65342D3D10CEA614ULL,
		0x1453B952648B0A34ULL,
		0x374703E23928FC0BULL,
		0xBB43109AD48578CEULL,
		0xB35E961BC8434C65ULL,
		0x0BA421F01FB60D9FULL,
		0xAFBBC4B245ED58C1ULL,
		0x146A0FF422AD3D97ULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4FB9463994AB187ULL,
		0xB472C03FE118B709ULL,
		0xBD99FAFBD8C8FDE5ULL,
		0x0932DAE612000A6EULL,
		0xBF312550A4B69493ULL,
		0xAD6821B6DFA27307ULL,
		0x7A83DD201361ACE6ULL,
		0x57741E3853944CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA17AAE891873AFCDULL,
		0xC24D88D60C03FF83ULL,
		0x1F41896D6F35C1B1ULL,
		0x0A29F46233B2BA9DULL,
		0x145A3125BBB0FAF9ULL,
		0x061E3CD8475FEDAEULL,
		0x2EAAB6EDACB6BB1DULL,
		0x54C817D1AB140428ULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36066FDA2D5F0E3DULL,
		0xDB675A5F2E37D832ULL,
		0x802208807BD172B8ULL,
		0x2CDD7CC46F21A9E1ULL,
		0x427E2712F792B811ULL,
		0x994C73DB55638341ULL,
		0xF2D9E67C7B218E76ULL,
		0x47D647AF47506B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78CE8B91ACD415F5ULL,
		0xDB7D3C207731BFDFULL,
		0xB2A56BC3BCF2B4C7ULL,
		0x2F0A0037DDE75F75ULL,
		0xBA0FE145F69FFC3FULL,
		0x70BB59E49D36A2D3ULL,
		0xFE4FCE8307248E87ULL,
		0x80C5ABFA28326EB2ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0674D0CBCB662FE9ULL,
		0x6DA8ED8B6949819DULL,
		0x419A36BAD6C04CB7ULL,
		0x1A76C19147F62A73ULL,
		0x95E1084D00CBE2CDULL,
		0x044AF77100369373ULL,
		0xE15115035CD55DDBULL,
		0x87A99165E42B878AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0674D0CBCB662FE9ULL,
		0x6DA8ED8B6949819DULL,
		0x419A36BAD6C04CB7ULL,
		0x1A76C19147F62A73ULL,
		0x95E1084D00CBE2CDULL,
		0x044AF77100369373ULL,
		0xE15115035CD55DDBULL,
		0x87A99165E42B878AULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEC178EBCA5807D0ULL,
		0xD980481B1D9CE3BAULL,
		0x0ABAE508B8CEBCB2ULL,
		0x2CD4ED9E733CB368ULL,
		0x3FC070567C6047FDULL,
		0x07A2C0392BC7A0CDULL,
		0xF14592174DD0F73CULL,
		0xAF3974F87C291FEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6CC19264CB70DA6ULL,
		0x0E563D9477E42468ULL,
		0x8FD2A78C9EFE7C30ULL,
		0x0CACD7BDD56B1861ULL,
		0x27DE8FD382E7B672ULL,
		0xC84CE47FFBB843A1ULL,
		0xA2036A2DD290B85AULL,
		0x2D4857DED6AB10F8ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1868318E00B95B0AULL,
		0x07BEDBA4F3A346BAULL,
		0xFCCB60A3198C2DD8ULL,
		0x419D301F3AF07EE8ULL,
		0x66DDC1A79ED6BE4EULL,
		0xAFC8BB5B0B3368C5ULL,
		0x5C9E113AC2EBB1EDULL,
		0x72AD43FF678D2320ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E03A2BE1320DE50ULL,
		0xC2B964D21F44F9EEULL,
		0x639D9E153EAFE95DULL,
		0x5D277CC102BA4BCCULL,
		0xCEB7A617C698ECE5ULL,
		0x4DC0BDB302EC53B4ULL,
		0xFE48CBEC2C9A5E78ULL,
		0x125EAB9C5953ECE8ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4892F7D4FAECA29DULL,
		0x4B0D016CC711392AULL,
		0x94D1967EB5C235F5ULL,
		0x4B527894F77ECB9CULL,
		0x25049E6DCCBB20E3ULL,
		0x822A6831DA0BB12BULL,
		0x4788F835C364A741ULL,
		0x9FE876AF53937018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE1FBB990BE0731ULL,
		0xA44795030A73A0BAULL,
		0xA21E27409317408AULL,
		0x8071FA994E5582A6ULL,
		0x55A9C6CB68869DEAULL,
		0xB5A022DA6D379F6BULL,
		0xD78A26A04CE0F5C5ULL,
		0xA7273B554FA3424DULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB932BE1CA6BED8FULL,
		0x1F1FCED5DB7302C7ULL,
		0x90894B53BA877949ULL,
		0xEB82430DB280C00AULL,
		0x3D3DEF43AEB3A8F8ULL,
		0xE9725813D37B3C91ULL,
		0x084BA8A8E4982A49ULL,
		0x065DC30112E22838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB932BE1CA6BED8FULL,
		0x1F1FCED5DB7302C7ULL,
		0x90894B53BA877949ULL,
		0xEB82430DB280C00AULL,
		0x3D3DEF43AEB3A8F8ULL,
		0xE9725813D37B3C91ULL,
		0x084BA8A8E4982A49ULL,
		0x065DC30112E22838ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE93410365C33D8AULL,
		0x38955FA2798132D6ULL,
		0xDC1E4D872834EFE6ULL,
		0x93827570A5F0C308ULL,
		0x5E8BEF7263EE1A91ULL,
		0x302627CB67270E49ULL,
		0x25BD1CDF08C3B0DFULL,
		0xE9C7DC484AEC7D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39FB8A5E7E132C9EULL,
		0x168D94A32D845999ULL,
		0xDF817724BEE32E8BULL,
		0x71D95739A36A3155ULL,
		0x18CF5147CDBA5CF8ULL,
		0xC298EB391014470FULL,
		0xD12BC60F9A82635EULL,
		0x0DBBDA514D8A54C9ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x669AA944EE880579ULL,
		0xEB4A2FA2BD1EA8BFULL,
		0xDCE68304DCA903D9ULL,
		0xD39FE9EE92B58417ULL,
		0x2A010266FC484FA1ULL,
		0xF1E9ABFA612C77CCULL,
		0x10A0F5D1AA3E2E46ULL,
		0x4C625968DF1A8311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0DC1586F3DB7D5CULL,
		0xAD6E1C37E5A76CA0ULL,
		0x3E0C2D6F58F3FDBFULL,
		0xBA4EBFEF9BF1294BULL,
		0xDCC885EC461F8180ULL,
		0xEE64192966E5AC0CULL,
		0x66413C52D261A927ULL,
		0xB0E6BA3A4D944CFFULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC22A88A61B0B5CCULL,
		0x1234C269F2A5889FULL,
		0x0BADC71B7F0640F2ULL,
		0xA7102F8F66E3D856ULL,
		0x662CC12AB7DB2515ULL,
		0xCF288EBD5D7B8EC6ULL,
		0x8D014A4C049F0CDFULL,
		0x57A8A99F56FBB239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4654429DFF51E9ULL,
		0xBD82AF472FBC5E1AULL,
		0x586F30EC86C9461EULL,
		0xA02797A12393BAB7ULL,
		0x82EE3FC269F5E1BDULL,
		0xAB4BA3E0B1CA7641ULL,
		0xC4BCEE9EB985A2C3ULL,
		0x8C79E0D8CF8CA831ULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9517E6D0549B157ULL,
		0xABFE10E89B6E998FULL,
		0x8532285999C71B6EULL,
		0x6E4619A5A1CCB9F9ULL,
		0xF74039AD2362078CULL,
		0x1FBF80E179D750D2ULL,
		0x94633E432783D8FAULL,
		0xEA705130A9D9FF17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9517E6D0549B157ULL,
		0xABFE10E89B6E998FULL,
		0x8532285999C71B6EULL,
		0x6E4619A5A1CCB9F9ULL,
		0xF74039AD2362078CULL,
		0x1FBF80E179D750D2ULL,
		0x94633E432783D8FAULL,
		0xEA705130A9D9FF17ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57252B1C1F7B1264ULL,
		0xAC0965DA7C4C7A6FULL,
		0xD61E24CE65D3D04BULL,
		0x9C7BE4FFC52EC69FULL,
		0x4F261D4BA538FDB2ULL,
		0xD7ABB90D16FFC156ULL,
		0xF0E8F7D5895939EDULL,
		0xECB7F236FE0A3ECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A125A8BBE8245A4ULL,
		0xC198FE4B3BB0232EULL,
		0xC8CAA819BF86EA97ULL,
		0x7E9BBCCC48532D60ULL,
		0x9F2ECF13F7F3BE44ULL,
		0xF7499EBC68CD2319ULL,
		0xAF268447B0709600ULL,
		0x49E0EA68FD912FD6ULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04ECF0C9B4D38C33ULL,
		0x0CF5EC90553CF43EULL,
		0x389E4B3E83708130ULL,
		0xC840F2CBDA92343AULL,
		0xFA813D8A3A830F1CULL,
		0x0352B22BB9A0A80EULL,
		0x3642ABCF33255BDCULL,
		0x844F21D8A25B8BBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9723A165BC1D35BULL,
		0x2BDA1F33DFBCE819ULL,
		0x85572C3ADB4B67F6ULL,
		0x139111F2A8D3263EULL,
		0xA237CE2D943FC42BULL,
		0x805C23D8B261103DULL,
		0xD513E4B483DBB9A1ULL,
		0x23EB514B663D9ADBULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x000112B993B49BF7ULL,
		0x4C20E340CBDF3266ULL,
		0xFEC4B221EDF52C28ULL,
		0xDA06602B206C67F7ULL,
		0xE72B07CE9CEB7D68ULL,
		0x11B5B0088BFBD2D7ULL,
		0xA5BB55DA2EB34425ULL,
		0x1EE52914D33C2D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3D2B8264097CD53ULL,
		0xCD6F285B76D605C6ULL,
		0x6AEC92C08E83B8DCULL,
		0x2D4B1D592CF07B32ULL,
		0x153886C192F5B6D8ULL,
		0xE94AC897A5361A5BULL,
		0xCFDEE3F8BB57682CULL,
		0xC0F4CFCB8AB07380ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58F9E727CE50DED7ULL,
		0x7AA6303A46AB0CCAULL,
		0xAB50586C44B47A5AULL,
		0x1600102C85D391F5ULL,
		0x0803FB67F0469EE9ULL,
		0x5176FC119F065933ULL,
		0xCFA699865A129BC3ULL,
		0x815589704E95FED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F9E727CE50DED7ULL,
		0x7AA6303A46AB0CCAULL,
		0xAB50586C44B47A5AULL,
		0x1600102C85D391F5ULL,
		0x0803FB67F0469EE9ULL,
		0x5176FC119F065933ULL,
		0xCFA699865A129BC3ULL,
		0x815589704E95FED5ULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5AF243CA59CC9E3ULL,
		0x31E66C3633FB1CEDULL,
		0x2E5C02E2190D9232ULL,
		0x1E057AB1FB800CE9ULL,
		0x16C8D67F44A2A268ULL,
		0x05A8ADB9487CEBC0ULL,
		0x5CC1B4EEC171B0DEULL,
		0x7F5FCDD68BAB540AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BDB46BD8DE1E42ULL,
		0xC972ECA9C2672D25ULL,
		0x07C6D800615B2E15ULL,
		0x8F39BE319767EC6FULL,
		0xE4C2776588907690ULL,
		0x08BCF7B05CACFB0DULL,
		0x158A0B03D43669A8ULL,
		0xDBA1A7B82D701726ULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54937F9E639FDD37ULL,
		0x4DE6BDAA1EFA54A8ULL,
		0xAE1534B823F715ADULL,
		0x438FD2FF205CAE85ULL,
		0x9EF3D821CE9DFCDBULL,
		0x77DFCF21EE25E09EULL,
		0x5C9143581C7C7946ULL,
		0xE6EF0D713BFDEDF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE173BE185978CBULL,
		0xC45F820E24BBB548ULL,
		0xCA75B012681BDA07ULL,
		0x19EC52E74C7442D0ULL,
		0xA3A6E204C78F5930ULL,
		0xB7A462EF54122E99ULL,
		0xFFA08780841D13C8ULL,
		0xD699A522F779A176ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B774F4558819F8CULL,
		0x730F9DCF03BD31CDULL,
		0x74B7571BBAD4ECA0ULL,
		0xC561139B39D05830ULL,
		0x879B9329DA6E98D2ULL,
		0xE278ADE24D0A5FE5ULL,
		0x60E8E26B222A4C9DULL,
		0xF1B9677E746CC67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49A72D60A980A8CULL,
		0xCB25CC972049F7A3ULL,
		0x9CD58BE521FC8CD3ULL,
		0x8BA3F55CF64AC8D4ULL,
		0x6CD3A342E6E502E4ULL,
		0x6375601E0FCFE81BULL,
		0xAF47751A40ABC8CEULL,
		0xE865FF7CA0C6BAAFULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5EFD15C8AD224DCULL,
		0x3B7AEE9F2D05E2FBULL,
		0xD6B1BB32986F27ECULL,
		0xF5717552414583D1ULL,
		0xF1CDB696CB97F61EULL,
		0xD573F7A11E6A05E7ULL,
		0x4B4FF004BF6A4AD3ULL,
		0xE5EEFBB493A8F361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5EFD15C8AD224DCULL,
		0x3B7AEE9F2D05E2FBULL,
		0xD6B1BB32986F27ECULL,
		0xF5717552414583D1ULL,
		0xF1CDB696CB97F61EULL,
		0xD573F7A11E6A05E7ULL,
		0x4B4FF004BF6A4AD3ULL,
		0xE5EEFBB493A8F361ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE919E6FF5AB0BF1AULL,
		0x02F03D92942A12B9ULL,
		0xEA92F1AB350E8221ULL,
		0xDE49C14D839E40EFULL,
		0x6718D7A81E3DFBB9ULL,
		0x918438C9DD11571AULL,
		0x44FB40C663746C10ULL,
		0x2B929612FF0B6483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A4BB63298A09D3ULL,
		0xCAFAC73E4F0BD811ULL,
		0x48CFF332F0A39BECULL,
		0x72C77ECAAB817BF0ULL,
		0xCCFB048388F88F1FULL,
		0xC5E809C17781E1C9ULL,
		0x43ED34B74161A271ULL,
		0x286413E6C5C56E0CULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91798CC2B7F47FEFULL,
		0x41868A0CA8694B80ULL,
		0xAE259929CBA6EA4EULL,
		0x9A97ABF3B4A3CB5DULL,
		0x78FA66E7A8359144ULL,
		0x0D141D0FBEDE1272ULL,
		0xF7CD16A5D1852506ULL,
		0xFA4B7E67CD2E4BD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22F2B5E716EBA9AAULL,
		0xFD6445099122486FULL,
		0x76E121D62F71BB4AULL,
		0x89CFA6B594E20C48ULL,
		0x13FD9BBD99E521CDULL,
		0x02AFA25891CD78BCULL,
		0xD7E12E454A819983ULL,
		0x959899B6FCE22719ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5C340DCD061C646ULL,
		0x9B080840E22D5FC2ULL,
		0xF4338421E62DBFB9ULL,
		0x657BE3BB1B926F34ULL,
		0xDC9A9019872AB97AULL,
		0x669792CC703B21D8ULL,
		0xC60B9D713338B4E5ULL,
		0xD3424E6A13CA2FF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFE0D8EE276E599EULL,
		0x2A7DB75B2CE66D28ULL,
		0x81A41A6731C9BD4CULL,
		0x5C22A796ACDE2773ULL,
		0x6AE52EB724B058ABULL,
		0x95AA4E070953F1B7ULL,
		0xB203A991E3F321AFULL,
		0xCD2FFC94DCEE4ECFULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC17021922EED7708ULL,
		0xFBAE8AD7C1D9E18AULL,
		0xF925E8AFF0BE5EB1ULL,
		0x825823E7FFD74FDCULL,
		0x1F2B16621BDA5C1DULL,
		0xD5DFD6AEE27491CAULL,
		0x7E986BB0CC0BBBF4ULL,
		0x1F1801AF54E0D7F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC17021922EED7708ULL,
		0xFBAE8AD7C1D9E18AULL,
		0xF925E8AFF0BE5EB1ULL,
		0x825823E7FFD74FDCULL,
		0x1F2B16621BDA5C1DULL,
		0xD5DFD6AEE27491CAULL,
		0x7E986BB0CC0BBBF4ULL,
		0x1F1801AF54E0D7F5ULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAA46A5BF2CB21D9ULL,
		0xDD139E93FC8F447AULL,
		0xF00E40013441ECDFULL,
		0x52DB070AB26A18CBULL,
		0xA9C3C38556CC95D5ULL,
		0x3F8ABB61D70F50A0ULL,
		0x65BC04514C4B4499ULL,
		0x11AC4BE9CBC73A28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA96DB5B53E902512ULL,
		0x916ED6D2BCD2461BULL,
		0xC34174D501328B42ULL,
		0x48B6C211E6950680ULL,
		0x556FD1D23F25654EULL,
		0x1E0FDA3B779FDC26ULL,
		0x0929613FF7E30412ULL,
		0x498369E3CA725279ULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D2B387495441226ULL,
		0xBA84BCBF6AD03D0EULL,
		0x85ADB831CF7240F4ULL,
		0xA4F2F548B43679C5ULL,
		0x5CEF09381BAF3FC9ULL,
		0x77F6CC9B62CB7DD0ULL,
		0xC5B378DCC35530ECULL,
		0x893F21CBEA324DFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9F75F69AB2074CULL,
		0x13DA01DEA25EB390ULL,
		0xDE1683D527050E5DULL,
		0x3E00538AEB1EE1B9ULL,
		0x6AC76463EA7694DBULL,
		0xE34B2C4372D736D5ULL,
		0x9D3C9690D4D77921ULL,
		0x243185E7428C358AULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC189AF263B38756CULL,
		0x7A1275F1A6A03644ULL,
		0xC45817D18CD2F3C7ULL,
		0x931D4079EE3C1CC8ULL,
		0x49EC887EE8F5C761ULL,
		0x3D10A665D96448EFULL,
		0xC8171AFD5A4B58F2ULL,
		0x2BC64316F1820312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4158EA0552B920AULL,
		0x519C2A13AB16FBD0ULL,
		0x8E857CE60ED522ECULL,
		0x595E65FED63853A6ULL,
		0x7090BFADDDFD0492ULL,
		0x9417CD1BA20FEB95ULL,
		0x2518BB325821791CULL,
		0x03673A53706B4F5DULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEB4D73788DE1015ULL,
		0x9BC80F7690A151DDULL,
		0x9CC484D81A098E88ULL,
		0x630373F819006A41ULL,
		0x95354AD4600C316AULL,
		0x37C7B52EDA2E3191ULL,
		0x114B73E4D586314DULL,
		0x57A47ACDB9AFC98CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB4D73788DE1015ULL,
		0x9BC80F7690A151DDULL,
		0x9CC484D81A098E88ULL,
		0x630373F819006A41ULL,
		0x95354AD4600C316AULL,
		0x37C7B52EDA2E3191ULL,
		0x114B73E4D586314DULL,
		0x57A47ACDB9AFC98CULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67BC86A7B527165CULL,
		0x9C51995FC60AA0FDULL,
		0x193F2AD24C07FFB6ULL,
		0x409C9ACB6DBE802CULL,
		0x88F1A54CF548AC01ULL,
		0x36063CFE271B79D6ULL,
		0xB9E378A8BA594B64ULL,
		0x0A38CD0D3B2691DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AA87C228C794DFULL,
		0xA8DB009F89F5E179ULL,
		0xFEBB7A1D9634EF88ULL,
		0xF7B66CAB2509FDD6ULL,
		0x7490971E789A9FBBULL,
		0x165A100615232A4EULL,
		0xAC8D38473CB1B4D2ULL,
		0x068C42D5A908B189ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE089DAA76FA952CFULL,
		0x45C2562FCF3918E1ULL,
		0x0EBAAEFC7463918BULL,
		0xBA449429841DCF72ULL,
		0x7D72345F190AD380ULL,
		0x4C5508BADF75F060ULL,
		0xB39F5A7CCFC276AEULL,
		0xFCFAB9C5691CFAEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F5D5E2565D4F6CULL,
		0xAA233994EFC6CE70ULL,
		0xE45EC6711FADA74CULL,
		0x23CE257C8E3278E4ULL,
		0x9A6A575BCA37B9DAULL,
		0x1D41AC2B9EC9B457ULL,
		0xB67099356AE90E7BULL,
		0x36E18A203B4106C7ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x660517CF156CDD03ULL,
		0xA533B1972B8879A7ULL,
		0x9E3BD53BC3371A68ULL,
		0x0627B35036A9D2F0ULL,
		0xC14F7343471A0E6EULL,
		0x69BCD35896690004ULL,
		0xC758367EEDA1EB8FULL,
		0x2EBD56CBF741574DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A159BA92F0A167FULL,
		0x86D93D9C58C7B6C8ULL,
		0xE66819D232B69FF1ULL,
		0x079E4102C1D8847AULL,
		0xEFD7EEDF5FC8E957ULL,
		0x610F386FE608C49CULL,
		0xF73E247070E85941ULL,
		0x56966411AC16A9DAULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2963B876249E4B7AULL,
		0xD20142208F8EFF0DULL,
		0xC75783595465275AULL,
		0xE4343034D95CA827ULL,
		0x8BE532A134206ECCULL,
		0x1BE7AD63C43FEBC9ULL,
		0xA31BB8A1D540CDEEULL,
		0xCBA6EA489BB27B19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2963B876249E4B7AULL,
		0xD20142208F8EFF0DULL,
		0xC75783595465275AULL,
		0xE4343034D95CA827ULL,
		0x8BE532A134206ECCULL,
		0x1BE7AD63C43FEBC9ULL,
		0xA31BB8A1D540CDEEULL,
		0xCBA6EA489BB27B19ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6D02F301AE37A0AULL,
		0xB772259039643B8CULL,
		0xFD7EDA5FC5239AEAULL,
		0xD11FEAB3E4292221ULL,
		0xBF1AAF1BCBB4EBDBULL,
		0xDBB857C254A89420ULL,
		0xB4E039CA32A724EDULL,
		0xE5CD88091A38AFE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D1FAD86F289716BULL,
		0xFC133712B05E9105ULL,
		0xA67D431EDFC3C2E4ULL,
		0x71662352D6319140ULL,
		0xBDA7AEA444166C40ULL,
		0xFC768AD846F3DC40ULL,
		0xDE43A526661301B9ULL,
		0x34F83E76951B743BULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x851D1615254FAC29ULL,
		0x4E9B5CDFE3E23AF8ULL,
		0xA20BB1EB826695E3ULL,
		0xBF7C46BED39F9099ULL,
		0x3E2FBFDEE45C11C9ULL,
		0xAC78BA6087C5C021ULL,
		0x8757CBC9377ED66BULL,
		0xC468B13E19534FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B5E74E4DB3B9B2AULL,
		0x1ECC7E191EEE2678ULL,
		0x3494478F07F651D9ULL,
		0x8F7EBB2F02E0E850ULL,
		0x9C6D91670A0C168FULL,
		0x94812400EE227E1AULL,
		0x1D054CBCEFE20B2BULL,
		0x380A0764144E731BULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB418C27D625F114ULL,
		0x57F186579552D25EULL,
		0x07B65AAC335AC824ULL,
		0x4610F6B712B10062ULL,
		0x5243C54A7EF576DCULL,
		0x11BD54135651B337ULL,
		0x9B70B1722D614239ULL,
		0xE7D7DC59D11DBA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC40F92FC7B1142D0ULL,
		0xF4FC57E4F789E84AULL,
		0x1800B529CA2DC1B8ULL,
		0xBCA1F7A8A736A1B4ULL,
		0x2DB96D1D62897E77ULL,
		0x5A90403B3F5FC6F6ULL,
		0xF7ACDC0F469D4235ULL,
		0x295BDD527C52A710ULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x300F3FDFA9E385C3ULL,
		0x53EAA9255202DAE4ULL,
		0x81BA0F67840C1F98ULL,
		0x52C5D714675014ACULL,
		0xB660F0233259A4CAULL,
		0x58727740DABBF008ULL,
		0x68C9630DF9AD103EULL,
		0xFCDE78FA2C5DD7C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x300F3FDFA9E385C3ULL,
		0x53EAA9255202DAE4ULL,
		0x81BA0F67840C1F98ULL,
		0x52C5D714675014ACULL,
		0xB660F0233259A4CAULL,
		0x58727740DABBF008ULL,
		0x68C9630DF9AD103EULL,
		0xFCDE78FA2C5DD7C7ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5513B8182548ADF4ULL,
		0x4BD4F031B9AA1F26ULL,
		0xCAD24589DDFCE542ULL,
		0x88997CA604860008ULL,
		0x4CAF578449CB7803ULL,
		0x093525D4D447B0A6ULL,
		0x178BD0E23A251AFAULL,
		0xA91E2CB8C9A1B56FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2347621538EA08ULL,
		0xFF20BF9B98C7E363ULL,
		0x72BC9EE711E01A39ULL,
		0x7D4BD0021B51F1C6ULL,
		0x8D4FF07097B06004ULL,
		0xF9906B16C7ECC09FULL,
		0x17D9F35DAF3FED30ULL,
		0x74FAA3D1EAC63B2FULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14681FF70C612672ULL,
		0x0D56CE04AA7A10CAULL,
		0x4D1CCCEDFDE924FAULL,
		0x5E9948E3FFE8A86FULL,
		0x9A98743BFAE46573ULL,
		0x957DB2501739045DULL,
		0x115812D58422F365ULL,
		0x73FA61CFAC76DE21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DDFADFB61DA025BULL,
		0x354D54A4F59BE184ULL,
		0xB4A162BAEE06D37FULL,
		0x76A43CD85E9E5F65ULL,
		0x983168DA7064F4F6ULL,
		0xA08F040431188E54ULL,
		0x3645C4BC2612408FULL,
		0x0F719F7BD45229F9ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0524300E4CDD5B70ULL,
		0x35D3966858E4586BULL,
		0xCFEC267A191BF900ULL,
		0x6358004960AB78D4ULL,
		0x4DD83B4FA9B7B8CAULL,
		0x396D9855B9BF31ABULL,
		0x2B5BF7A29423006FULL,
		0xCABE3D532BE2BD61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C4B878842270A96ULL,
		0xC5A50C39E02E1D3FULL,
		0x2CB34FC07554301DULL,
		0xA846D1B07E1AEF58ULL,
		0xF3151E80D668FCF6ULL,
		0x8BE89010A03F6A05ULL,
		0xA8C10B15885400B1ULL,
		0xF13E0A8C2D985EE9ULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC1E547FAED1D1CULL,
		0x7A7B992F18FEE052ULL,
		0xAF01A6D6CCBD99A9ULL,
		0xF235EF4BBAF51D4DULL,
		0x6FEC1A98F31DFDB8ULL,
		0x1902856AEC96227AULL,
		0x04FC1123627E4DAEULL,
		0x847274B9B668EBA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CC1E547FAED1D1CULL,
		0x7A7B992F18FEE052ULL,
		0xAF01A6D6CCBD99A9ULL,
		0xF235EF4BBAF51D4DULL,
		0x6FEC1A98F31DFDB8ULL,
		0x1902856AEC96227AULL,
		0x04FC1123627E4DAEULL,
		0x847274B9B668EBA4ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61D72D682871828FULL,
		0x1718D717A90D03CBULL,
		0x023EEE070EDAA424ULL,
		0x85B77F8E7334DE49ULL,
		0xF07D4E35D74CAF6DULL,
		0x9DDCFEFD91E65D85ULL,
		0x74B7FB4A7347FAEBULL,
		0x134727A5572DD58AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740B80F6FD6BF141ULL,
		0x84AC3C15E918CE14ULL,
		0x6E8521515BCB5CD8ULL,
		0x74DEE0F7C3FF0F37ULL,
		0x7D24B803DA575413ULL,
		0x31083C74B8297C16ULL,
		0x7995B7B0D3CC42A4ULL,
		0x3D39ED9589864B32ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC71C581C461DA55EULL,
		0xC9C00B2602AE20E5ULL,
		0x2AADB5194072215CULL,
		0x1A9D2C8F9CCF477BULL,
		0x072CBAA2362AC9EAULL,
		0xF8CFFA0314832FAAULL,
		0x472D46711B9C17A3ULL,
		0x3ABB7E29886F180FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C9493B2C0307674ULL,
		0x4F638055B129FE27ULL,
		0xD9EEA33BD6A52380ULL,
		0x9C2EB46095D2AB9DULL,
		0x68DC7925232F50F4ULL,
		0xB56F3F5BA0584D62ULL,
		0xC939AFED67E5607AULL,
		0xD8A37CD89348B6D9ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61ADB727BF2BFE25ULL,
		0x090DA96F22E9A515ULL,
		0x866A9F5CFEE11268ULL,
		0x5D11F453AE61F070ULL,
		0xD619492AE150EAACULL,
		0xDA65B2578AEEEF86ULL,
		0xC9DB490FA1F1C347ULL,
		0x83EFCB3AC065F14FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFEBA6544700534AULL,
		0x33F9CA7DFCFACB00ULL,
		0x83EB455E5711CA9FULL,
		0x9A78A73F28AB75BFULL,
		0x0B1A009ECE53D74FULL,
		0xE2D0BBDF32108FDEULL,
		0x443C38035AEB98C7ULL,
		0xB6ADB167D589E34AULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40605EF3B92A30FAULL,
		0x44DE8A1F0EC7512CULL,
		0x136EEFE1A4699B38ULL,
		0xDD78A5E533F86873ULL,
		0x7F81F7CA53C23F02ULL,
		0x3AFA751AFA46AB40ULL,
		0xA9A94B2220494D67ULL,
		0xAD08D566532406FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40605EF3B92A30FAULL,
		0x44DE8A1F0EC7512CULL,
		0x136EEFE1A4699B38ULL,
		0xDD78A5E533F86873ULL,
		0x7F81F7CA53C23F02ULL,
		0x3AFA751AFA46AB40ULL,
		0xA9A94B2220494D67ULL,
		0xAD08D566532406FAULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64F390BC96A3B03DULL,
		0xD28CC0875E4A0530ULL,
		0x752BD1CCF5C9A4DDULL,
		0x54976F6F3FB8A7A1ULL,
		0xEFB71CD8CFA4DB0EULL,
		0x5B787C28F010E19DULL,
		0x5E26EA6196966E8BULL,
		0xB9DD9A61E0D98771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06AA67B8D9D20B2ULL,
		0xD1648AA92EDD3A09ULL,
		0x5FBF0420CEF0C454ULL,
		0x338CE545AC8B01EFULL,
		0x31BC7BD57493283EULL,
		0xC5DA75C51A31C387ULL,
		0xB695C80F1B4680DFULL,
		0xE364CC6B6D3E02E3ULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B19C72159366868ULL,
		0x53FD6F3F4D8B1018ULL,
		0x2A03A1A4AB83558FULL,
		0x3CCBB6D7821E4057ULL,
		0x4F4AFE1CD0FE7F1EULL,
		0x414B21FF2AC6496FULL,
		0x0E7EB3C6F5031856ULL,
		0x62DD68810FA89E18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC481F04F98239097ULL,
		0x6005A3EE02384788ULL,
		0xCAFEA0A1F69166D4ULL,
		0x24198FE0B8D959F0ULL,
		0xF6580ADA26E1F45FULL,
		0x76DF6BEB9DFCE00EULL,
		0x05AFD51142A09A91ULL,
		0x8C69921E24F0C6E5ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x772190C4C5C28AC7ULL,
		0xD6E649A82760E868ULL,
		0xE2B79B781D7F1C94ULL,
		0x299FFBD3EF2EEBD6ULL,
		0xA96323983F9E8276ULL,
		0xA00336F1C757400CULL,
		0x08502DF4E2285BE5ULL,
		0xEC82F431CF5FD0A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x004CDED6499D5D4BULL,
		0x0F58DB912FABF8F9ULL,
		0x4CEDB2B7C49D772AULL,
		0x74B50AEF0E2B2C96ULL,
		0xF255F8794FC33735ULL,
		0x2AE3863AE5E3D373ULL,
		0x191C1EA02337BDC5ULL,
		0x0346913876007FB2ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x234228A790DC08BDULL,
		0xA920CA81718205B8ULL,
		0x733DD5FC1BA4DD5AULL,
		0x5B1B60857DF97E36ULL,
		0xCAEEB17B6C466B10ULL,
		0xB11780BA739F5111ULL,
		0xC10548973D79377CULL,
		0xB0E379D1EDD9F908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x234228A790DC08BDULL,
		0xA920CA81718205B8ULL,
		0x733DD5FC1BA4DD5AULL,
		0x5B1B60857DF97E36ULL,
		0xCAEEB17B6C466B10ULL,
		0xB11780BA739F5111ULL,
		0xC10548973D79377CULL,
		0xB0E379D1EDD9F908ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2DA282E51E8FCBBULL,
		0x592CE6D0A1F657B2ULL,
		0xE4B013615EB5906FULL,
		0x4DBA27A00DC24305ULL,
		0xC1025342EE1C18E1ULL,
		0x9E2D4394F3047821ULL,
		0xC2DAD250BA634543ULL,
		0x5D43CBC680D4983EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A0F7ABF97899E6ULL,
		0xB9C7AA80F7971B0DULL,
		0xA100305770B853D9ULL,
		0x0C77DA1C23C83F6AULL,
		0xF0EAC904A4121C4CULL,
		0x9584DF381F6750A5ULL,
		0x2649E1FBBFE7F366ULL,
		0xD5B5FD533A419664ULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5AC44A9829C468BULL,
		0xADB423116C379D73ULL,
		0xE3FD35ADB171A523ULL,
		0x710D81F87301E0EBULL,
		0x3193927701780371ULL,
		0x22939535DD50A877ULL,
		0x7A8EA71C7EBEE45EULL,
		0xA479BA09E6091A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B3F4A328D0D1BD4ULL,
		0x46A71A78F32FDAEEULL,
		0x2747938B386363ACULL,
		0x822E9804646E12B4ULL,
		0x8AE2AA62FC4F6A76ULL,
		0x34D2185C5CC99FC8ULL,
		0x138F37B7098E6BEFULL,
		0x8356387FB1028DD0ULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3F1FFA1F91F94DDULL,
		0x16F6194BE38322B9ULL,
		0x4AF68C21AB17B686ULL,
		0x2EA0D75C25135556ULL,
		0x830051BAE745EF95ULL,
		0x9B503A09B6E55327ULL,
		0xA4BB53E4CDB35231ULL,
		0xC95C21D60E601081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D2CAE937FB9B78CULL,
		0x3F7F4FF3EAAC6D12ULL,
		0xFA6CA00DD161963DULL,
		0x70A552B59E581C4CULL,
		0x14D930EF6A125916ULL,
		0x4F838EBAC9C1DB77ULL,
		0x2E511082EF2FB9A1ULL,
		0x9414A15707B1826AULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67D93C52C977EDF7ULL,
		0x54DEABB33AE7AF89ULL,
		0x3A9BDA4D1BFA6B56ULL,
		0x27C20A4A716470D3ULL,
		0xA5BF03A79DBF618EULL,
		0x13DC6186274199E0ULL,
		0x8DD13E01E5B8782DULL,
		0xF2AF99483DC71AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D93C52C977EDF7ULL,
		0x54DEABB33AE7AF89ULL,
		0x3A9BDA4D1BFA6B56ULL,
		0x27C20A4A716470D3ULL,
		0xA5BF03A79DBF618EULL,
		0x13DC6186274199E0ULL,
		0x8DD13E01E5B8782DULL,
		0xF2AF99483DC71AB6ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FFF105A1C07F0C2ULL,
		0xE4F52DDB603DB87FULL,
		0x091D3712021D5060ULL,
		0x7F0B2F4FEE03EA4CULL,
		0x637736BA48592894ULL,
		0x6560F3271FEE60F5ULL,
		0xE3597BBFE6BE30BAULL,
		0x2FDF7595D4A8986AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04E7DA8ABB4559DULL,
		0x956340B3BF1E840DULL,
		0x2D1A83FFBF3E5A54ULL,
		0xBB578103612E3A1DULL,
		0x0837F123ECCB910FULL,
		0x774E35A735DF4BE7ULL,
		0x61EB37973E4CC8D1ULL,
		0x1EAE22607A55F492ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6F8770F00591AFCULL,
		0xB93761A186FA11A6ULL,
		0x0A857A2C2A098A5BULL,
		0xD87826D32750D0F4ULL,
		0x844C620E0233B02EULL,
		0xF21C68F645DF2853ULL,
		0x3B7F914BF0491825ULL,
		0x0F2787A86F528D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54911816452A2D58ULL,
		0x8AFC336AD8A5AD64ULL,
		0x451D84FA3D1D8C62ULL,
		0xA37A776AEAA328FFULL,
		0x95DC04B358002BE1ULL,
		0x8CEE0E47A4768BE1ULL,
		0xF49CC9F85ABCF014ULL,
		0x713FD70463890FB6ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x945310BB0DD697ADULL,
		0x3D98DEEE6C4EAB57ULL,
		0x42179DD707AAC4F3ULL,
		0x06534E5E40DA4529ULL,
		0x2502AEDD468874DAULL,
		0x23B0D8A1F3F3D915ULL,
		0x7A19D4C81EAF5E99ULL,
		0xC359E8D3758DF300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055E5EF4FF79CED7ULL,
		0xD9F48FB4E1034687ULL,
		0xEBDD470C2F5F683BULL,
		0x520AB70F8E34D361ULL,
		0xAE714DB15D19EBE1ULL,
		0x877DE5DD4F6A3A81ULL,
		0x61B0006886B8FDDEULL,
		0x0546A26EB88B2E61ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD88DECFF46B891BULL,
		0x17ABE60C6DA8879EULL,
		0xA9DBB103CD44A3CCULL,
		0x294C19953CA9049BULL,
		0x56B1786647AEA26BULL,
		0x48C344C8F6C9333FULL,
		0xE55119224B9F4D59ULL,
		0x389721D05FEEF31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD88DECFF46B891BULL,
		0x17ABE60C6DA8879EULL,
		0xA9DBB103CD44A3CCULL,
		0x294C19953CA9049BULL,
		0x56B1786647AEA26BULL,
		0x48C344C8F6C9333FULL,
		0xE55119224B9F4D59ULL,
		0x389721D05FEEF31DULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA749D24633B230F0ULL,
		0xEFE9B7FFDACE5F2DULL,
		0xB774C1E352DA3850ULL,
		0x6B1E1C05BEAF947FULL,
		0xC9593A8606B28DAFULL,
		0x5832EB9CB799C664ULL,
		0x0AC6F8DD9FB89F21ULL,
		0x3151E8D9DE25ECAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60BB3306BA91832DULL,
		0x2C5C0B0976E3490EULL,
		0x904919F4DAF36D14ULL,
		0x04ECE4A394E0F00BULL,
		0xDB9EF9412D36BD19ULL,
		0x5960C602FCE92DF2ULL,
		0x1ED06D99FCB9693CULL,
		0xD167ACCA1A3E9476ULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x800557608E6439C2ULL,
		0x0BD3E191618FF1F2ULL,
		0x862E2F337AC712A5ULL,
		0x0076F1E93227A9CEULL,
		0x3DFB16E549811E17ULL,
		0xC086A220F23C5FA8ULL,
		0x14676CB1459E3882ULL,
		0x9B01073719ABDD24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC4C0BA3FBE7F819ULL,
		0x3C58DC1EE312A3CBULL,
		0x678B16EDC1651E48ULL,
		0x907B46E848BC5B8CULL,
		0x3E3CCAB738017D83ULL,
		0x784D63BBC2E561EBULL,
		0x8F23000A64CB8F51ULL,
		0x0FEB295F1163E3FCULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C23FB1486350D1FULL,
		0x95C60743E85FA1A4ULL,
		0x34E02DA3784715EAULL,
		0xCECE7FC307700838ULL,
		0x03473DAC68C62E80ULL,
		0x99519BE573CB7103ULL,
		0xFB904BADBF1DA2B9ULL,
		0x5F049039A8A34DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BE2F03E4C5A62A8ULL,
		0x64700453C07AE389ULL,
		0x30F2FE60F09EA780ULL,
		0x4C6A7BE28A1A0604ULL,
		0x966A7211FE55D8DDULL,
		0x99B9D5D0A7549316ULL,
		0x35129ADC74DA4339ULL,
		0x0F384FD7F946E326ULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF1C76436F27A76EULL,
		0x04054938EA4F39D9ULL,
		0x7D1A21875ADB0849ULL,
		0x2B50CAD965DD1E64ULL,
		0xE4ED8FDAA1E3C41DULL,
		0xE703B9297A6C6841ULL,
		0x3BFE4D461B12EA50ULL,
		0xFE88EE6471FF2DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF1C76436F27A76EULL,
		0x04054938EA4F39D9ULL,
		0x7D1A21875ADB0849ULL,
		0x2B50CAD965DD1E64ULL,
		0xE4ED8FDAA1E3C41DULL,
		0xE703B9297A6C6841ULL,
		0x3BFE4D461B12EA50ULL,
		0xFE88EE6471FF2DF8ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98ADA285E679A589ULL,
		0x696EAD24C7288257ULL,
		0xBC2025BD5784EE28ULL,
		0x9ECB37A80D459714ULL,
		0xE8514F3AD0774FB5ULL,
		0xA898946F4CB1167AULL,
		0xB3D255B9B0163BFBULL,
		0xC14BDA49EDDC8AABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCCAC1F03102A34ULL,
		0x690CBBB89E80EAEAULL,
		0xEEC5D5917991A00FULL,
		0xBEB0D6B9F0276581ULL,
		0x3C10A896A5B99927ULL,
		0x38C76A72663E7D6AULL,
		0xBACE144528B139FCULL,
		0xA3B8F169194A92ADULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AAB14C1880E4A1EULL,
		0xDC03D5C50B989462ULL,
		0x2C2DE47B3F93F5A2ULL,
		0x87F2653A67E02C4CULL,
		0xCC74DCF1A5BA047CULL,
		0xCB08ABBB37FB1E7DULL,
		0x2B2786E50C43F7D5ULL,
		0xEAE3D2BD864F68A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B25358937BBD7FULL,
		0x5DA0D1C0D463A4C2ULL,
		0xF0AE0251F927DA40ULL,
		0x04FB37AEB78ED528ULL,
		0x12732AE74EFAF913ULL,
		0x9B109677F7696DB0ULL,
		0x3ABA4797948D57BBULL,
		0x9EC72F4DB4104CA6ULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB59C8FF242097898ULL,
		0x02CEDAAFF07DA9E8ULL,
		0xBEAC5EAE1CA8B5FDULL,
		0xB2FF740721BCF3B3ULL,
		0x4BA48A84E65909C9ULL,
		0x408B374599AE59F2ULL,
		0x417D7762A943F570ULL,
		0x7D3A6C7650906A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBD2E9AD90A1D7B7ULL,
		0xA108A5F906AF3E7AULL,
		0x66F187D6FB5B8EBEULL,
		0xD95CAF9A8D5E5375ULL,
		0x801F508D5B1597F5ULL,
		0xB7713F879E83486AULL,
		0xACDD286897C6391EULL,
		0x42BC6C49558B7CB4ULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7F0C70B27BA820BULL,
		0x66363113872EB654ULL,
		0x6B442B8099EDCA90ULL,
		0x45EDF2292F527326ULL,
		0xF661176E70900A51ULL,
		0x2B3105C680A81800ULL,
		0x0761683A550FDC11ULL,
		0x075A836EE074E285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F0C70B27BA820BULL,
		0x66363113872EB654ULL,
		0x6B442B8099EDCA90ULL,
		0x45EDF2292F527326ULL,
		0xF661176E70900A51ULL,
		0x2B3105C680A81800ULL,
		0x0761683A550FDC11ULL,
		0x075A836EE074E285ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25256EEF25C0CB64ULL,
		0xD81C2FA885540FF7ULL,
		0x9BF69E035333BB8AULL,
		0x2942D8497A56E0A3ULL,
		0xB4C0DF7BCC0BBFAEULL,
		0xEE5CA02E8AF8289AULL,
		0xF7183B37B66E7B1CULL,
		0xF58E02D4AA70EE44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0AA3259F5B2FFF7ULL,
		0xDEE5372EB84A174CULL,
		0x1D264D67A8714377ULL,
		0xF30F8A4B41BE46D5ULL,
		0xA73A3402CC72EE3DULL,
		0xEC459F9965E87F53ULL,
		0xB8674D326BBFB3BBULL,
		0xB51F65ABBEE132C2ULL
	}};
	t = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE626BC2EEC9554D9ULL,
		0xFCFC375C303D77D4ULL,
		0x845A70C691266193ULL,
		0xDA649A51210405C9ULL,
		0xE6AA2FB6445AAE62ULL,
		0xC9A86F870DA3347FULL,
		0x9BA578B41D64CC99ULL,
		0xF233A1E9D9DBC70CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x471F6ACF9EB4002BULL,
		0xAB07865A46665960ULL,
		0xDFD77C654D3C4523ULL,
		0xA1406436E3A56535ULL,
		0x279A14813366DF2CULL,
		0x00977A53FD5A11DFULL,
		0xDC99F4938BEFCFC9ULL,
		0x9F9842369856D663ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AE88FCD2D27E2F3ULL,
		0x88997FEEFF60FB6BULL,
		0x068CF956397EE028ULL,
		0xDC5034989BB70BC5ULL,
		0x48BD4B6F7D5081AAULL,
		0x7888C982D55D1E0EULL,
		0x373E09CE99ED4E22ULL,
		0xA03172E00B5EBB70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98934997329CF4F4ULL,
		0x7534AD1A7577EDAEULL,
		0x7DAFB76A92E192D8ULL,
		0x8B76E944E31D4CCDULL,
		0x43B58D581C7A6E12ULL,
		0x9C5EF0439AD81326ULL,
		0xAB3A8435F353675BULL,
		0x629917BE308BEAFAULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AD4CD4EA296AEEDULL,
		0xEF857739A781BF76ULL,
		0xD4E4E5095A87A5EBULL,
		0x2BD6FCAD60BF477AULL,
		0x381298B532949384ULL,
		0x8E7E72FB93749F4EULL,
		0x87B1EC8589B4CD0CULL,
		0xBF1923CA7D3E658EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AD4CD4EA296AEEDULL,
		0xEF857739A781BF76ULL,
		0xD4E4E5095A87A5EBULL,
		0x2BD6FCAD60BF477AULL,
		0x381298B532949384ULL,
		0x8E7E72FB93749F4EULL,
		0x87B1EC8589B4CD0CULL,
		0xBF1923CA7D3E658EULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AAEF8693FE9B3A4ULL,
		0x61B2DF034840C0E6ULL,
		0x7548F41A8F74187DULL,
		0x0E12B366C60D8ACFULL,
		0xB8513857433A1DE8ULL,
		0xAB9EEC7ADC1E3AADULL,
		0xDF530064A5EDDFAAULL,
		0x951CEB94CA329723ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB188A6FD93FD29ULL,
		0xCD2BC6DD8BA1069AULL,
		0xF5817A6FC502921DULL,
		0x48C29E6E6EF78A41ULL,
		0xD6CB3F61ED99EED5ULL,
		0xABAC34B75EAB7EFBULL,
		0x2A2D8BE06C6CF136ULL,
		0xB6F313E63F51132CULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB96517A405064FULL,
		0x1D0061C93DAD0376ULL,
		0xE3A1E108BBD155CCULL,
		0x8906436424855BF3ULL,
		0xBB11F8AC4F9CC746ULL,
		0x893547D42B81D5A5ULL,
		0x8524BF51E1EE6CBCULL,
		0x0C122DE9FA45E86AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C7DD7734352D97ULL,
		0x4FD81E88C229A500ULL,
		0xFB677EC805A16136ULL,
		0xBD5FB054795FC096ULL,
		0xB1D413D19425DF5EULL,
		0xB0D6BDA258DB94D5ULL,
		0x2CAF092D16A0F8C7ULL,
		0xD7EF30EC0C688D88ULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00E10E725AC8EC48ULL,
		0xA59ADED767051978ULL,
		0xBA97B8E033512EF7ULL,
		0x6C724995FA0C8409ULL,
		0x499A4EBDF14BA866ULL,
		0xD726299ED5EAEAC8ULL,
		0xFA41CCC3F2F08482ULL,
		0xDA4BC92DB9FD2B2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF2B069F8E2A381ULL,
		0xD333764A628BACDDULL,
		0x1BF8E31DF3718266ULL,
		0xA09B0BB58A0A8D1EULL,
		0x9E9414B939D72C72ULL,
		0xAF40A8EB3F9E3384ULL,
		0x5BBFDF9BE243F753ULL,
		0xBAE1B5F6058525B4ULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D422FB08BD139DEULL,
		0xFFC54CD9CA85BEE5ULL,
		0xDE5542644DA62FB9ULL,
		0x3BB00F0F38C997A3ULL,
		0xDE0FC67780D911A2ULL,
		0x1FBABB05BF4F04EDULL,
		0x1609B0423F9ECBDFULL,
		0xB2E4331C79781D67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D422FB08BD139DEULL,
		0xFFC54CD9CA85BEE5ULL,
		0xDE5542644DA62FB9ULL,
		0x3BB00F0F38C997A3ULL,
		0xDE0FC67780D911A2ULL,
		0x1FBABB05BF4F04EDULL,
		0x1609B0423F9ECBDFULL,
		0xB2E4331C79781D67ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92B41CB263BE13D9ULL,
		0x5DFE068E36C17A20ULL,
		0x01677F29DCB22FDEULL,
		0x036368157D1F6006ULL,
		0x6A4F9053B8B0CFEBULL,
		0xCE9B6ABA7344B923ULL,
		0xC675070072F4C417ULL,
		0xE9A59115341712CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FBD37D015EF7A3EULL,
		0x56BCE605010B43D1ULL,
		0xF4F45154B3F93FB9ULL,
		0xEE6A486EB4854DD5ULL,
		0xFBC9B6BC79FC1121ULL,
		0x151F69697FD590A2ULL,
		0xF7A48DACE6255B6DULL,
		0x182B24F8762348C7ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B3F4A5FE908E6A7ULL,
		0x280F9E224F54FEE6ULL,
		0xBC73820D386B1CF3ULL,
		0x1ACB7B3C1214CEDEULL,
		0xC9197310AB53B3C3ULL,
		0x1E52E6F769A0525AULL,
		0x0E9CF65434A63BC6ULL,
		0x979233D1BBF56C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD247115D2E6909C5ULL,
		0x3A72254A65629E39ULL,
		0xF6DF820BADE903A9ULL,
		0xC2B1E8707460AF63ULL,
		0xD3EB3F0DD4A38BA7ULL,
		0x996C7A077F185870ULL,
		0x3474F77CDE558BCEULL,
		0x21CFCB38464EDECCULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x796E8369DF67FE33ULL,
		0x198CA0D76D6918E6ULL,
		0x528C317EB5108612ULL,
		0x88150C2825EE71BAULL,
		0x83407C23F862223EULL,
		0x523A88AA5476C15CULL,
		0x851A4A02172192BDULL,
		0xC6B744D9AFDFF891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DDEC9694DD9BF5DULL,
		0x915097FB03F11429ULL,
		0x444F91256FA8AA68ULL,
		0xE0E69B5B346C8EFCULL,
		0x6558791E43FB36F9ULL,
		0x58D2FF9FA8068896ULL,
		0xF84E98784DEEA523ULL,
		0xEF312EED1CB15E4CULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE02D19A2096F7868ULL,
		0x2F923313CB44CE09ULL,
		0x26698502EE7CD78AULL,
		0x07A9C476DDC3244FULL,
		0xDA793223268C2B8DULL,
		0x4C995E7B495D84C1ULL,
		0xBF5537DE16136B61ULL,
		0xB3B1850C10823C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02D19A2096F7868ULL,
		0x2F923313CB44CE09ULL,
		0x26698502EE7CD78AULL,
		0x07A9C476DDC3244FULL,
		0xDA793223268C2B8DULL,
		0x4C995E7B495D84C1ULL,
		0xBF5537DE16136B61ULL,
		0xB3B1850C10823C33ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12C59F920C658AAFULL,
		0x47412E038E0FCD1FULL,
		0xD1B93E2ABB79725DULL,
		0x2CE73E2BE3724899ULL,
		0x13C1EF46EEA5EC1AULL,
		0xE39443CD1255CC54ULL,
		0x3A1A84FF00ED1F4CULL,
		0x811D98246140B540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C8B94188AB1AA0DULL,
		0x1BD1A564AF528DCBULL,
		0x0454E2B5BD66C303ULL,
		0x683EC1AA3C66079DULL,
		0xC39F633C477C99C3ULL,
		0x3CD66D99A03B0B04ULL,
		0xD662DE15FED2098DULL,
		0xF0DB1A298D337FE0ULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF12951175B52333ULL,
		0x1AFB9A455664EC43ULL,
		0xDDB68E8C55FFFD72ULL,
		0x0121DB6AFF42449AULL,
		0xCCBDA0C593BD9C36ULL,
		0xDDDE50B255E1446CULL,
		0x63D25D94806448EAULL,
		0xEF9C31105D78971BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69149E0CDA70FA88ULL,
		0x2D2F4FCFB3F31B93ULL,
		0xB09730E1D4715B4DULL,
		0x322171637AC2660EULL,
		0x40595532D75BE682ULL,
		0x73A17099033DB1C4ULL,
		0xB7F4033F6EC3B701ULL,
		0xF983A4FC4241791EULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADF2F6EBC087A1B6ULL,
		0x2CA7484348152365ULL,
		0x7A5BD0ADD96F1C75ULL,
		0x163DE671640C8DBFULL,
		0x7FE926A9DA4165F2ULL,
		0x1EAAC1BE0F5A56B6ULL,
		0x2B73500F90C731D3ULL,
		0x39EB4E216D9A10AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE25CE0E64C0B0CULL,
		0x02EFE8A22F38B7E8ULL,
		0x62B6490F67D3D3D0ULL,
		0x877B27D52F5BE0D6ULL,
		0x66D52DA1A0CF541AULL,
		0xF8ACFCAF351F2609ULL,
		0xE5CC40564E9DB83FULL,
		0xEE59FD746FC2739CULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6886196720E5003AULL,
		0x63A09F4069EF9778ULL,
		0x1C98BFD74E15F6E9ULL,
		0xDCF724E7B48A874CULL,
		0xBC9098FB571A5FF1ULL,
		0x2195A40D7A1C0217ULL,
		0xEF2E9972BE3C3F6EULL,
		0x369B463A43C3785AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6886196720E5003AULL,
		0x63A09F4069EF9778ULL,
		0x1C98BFD74E15F6E9ULL,
		0xDCF724E7B48A874CULL,
		0xBC9098FB571A5FF1ULL,
		0x2195A40D7A1C0217ULL,
		0xEF2E9972BE3C3F6EULL,
		0x369B463A43C3785AULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF8689C20D7C64C5ULL,
		0x51BA2F7E5AE13877ULL,
		0xD4E514CE2267BB19ULL,
		0x91100B804A709F77ULL,
		0x60BAF947A6B066BDULL,
		0x31A0ADDE4760EEB7ULL,
		0x125FCE53AE169F61ULL,
		0x692E3DEA904A3D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90BFD9E1F28EADECULL,
		0x5CCC2C86B90AD855ULL,
		0xF8AFCE9088F07901ULL,
		0x6C65B48A216A306FULL,
		0xB5E2834B5979725DULL,
		0xFA84BE454B03FAE0ULL,
		0x642F422E3B441F79ULL,
		0xB06A14D19B217A9FULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5AB425802B89F75ULL,
		0x45CBDF95328051F6ULL,
		0xC9E38828BE68645CULL,
		0x4EF6C4FD114D1DAFULL,
		0x6F9D06DA31FC5716ULL,
		0x429744865FD96D42ULL,
		0xDE816EF9E89B2E09ULL,
		0x14E4F7882A71FA8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003B911A42D12FFAULL,
		0x95C8C5F204671C63ULL,
		0xB4283131B51673D0ULL,
		0x4FD90F9B631EFE7DULL,
		0xED92164628A6FF69ULL,
		0x36E08C2FDAEDAAE3ULL,
		0xEE8B6BC96FE3A56EULL,
		0xE8EB306D9BD3BAC3ULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17D742748396482BULL,
		0xE2FED13DF36CF6AEULL,
		0xD97282B27DEFC175ULL,
		0x15CD069AE2740122ULL,
		0x73CE649AEDDDB8DCULL,
		0x787A2684E9405094ULL,
		0x3AF5E8489579EC7BULL,
		0x88DB66EFE02FF081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84450046F16E29DBULL,
		0x2CF7100A71305CF1ULL,
		0xB43A1EB751FEF337ULL,
		0x621C6EE3576E50C7ULL,
		0x3EDCAB64AF3CE744ULL,
		0xDB6A2887F0580C36ULL,
		0x6CBD67553ADF4303ULL,
		0x02D2A7AA4BBE3550ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x170F424BFD7EBA3CULL,
		0x385CD5DCA0EF0006ULL,
		0x988EF2A7AC302C80ULL,
		0x0BF801F2CED4DD69ULL,
		0x28110E921D5CAD12ULL,
		0xB32D5B1DBE1EF5BEULL,
		0xEE074EE7E23F746CULL,
		0x03D753410469E4E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x170F424BFD7EBA3CULL,
		0x385CD5DCA0EF0006ULL,
		0x988EF2A7AC302C80ULL,
		0x0BF801F2CED4DD69ULL,
		0x28110E921D5CAD12ULL,
		0xB32D5B1DBE1EF5BEULL,
		0xEE074EE7E23F746CULL,
		0x03D753410469E4E4ULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3D92D750A7C03A2ULL,
		0xBD580834225B7E4BULL,
		0x88C0097E38C5553AULL,
		0xECFB00AA4573A3AAULL,
		0x40BE7031F698FBA1ULL,
		0xB85AC22CFF1B16A0ULL,
		0x34D78E1C3E46452EULL,
		0x970987CF8EFAD90DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C879B00630856B1ULL,
		0x46905E94372FEE84ULL,
		0x164B54399595FDC4ULL,
		0x03F36C17BF90D84DULL,
		0x6E514828C44F23D9ULL,
		0x5B7405208651FE80ULL,
		0x70B3DC539084FB6BULL,
		0x227F0324270BD241ULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78CC4F81577E13D0ULL,
		0xFC009CA18D51BE0CULL,
		0xD4E8DFB44E28DA9CULL,
		0xC5D6FAA8375C710EULL,
		0x140386B8424DA9DBULL,
		0x3148E529BE3EB983ULL,
		0xFE13DA16B7B0B825ULL,
		0x6F92965B8BD57740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCE18F20E2725534ULL,
		0x828B8D8FD585ABDEULL,
		0x77F6AA065124D7E2ULL,
		0xE9BB57FC89FEAAA0ULL,
		0xCE74EC38806D5850ULL,
		0x53A03DE4E7A0E97AULL,
		0x9A7318C14445D20CULL,
		0xC5BDD21E609F4ED5ULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x783A47927AEC49CEULL,
		0x8A6BCCE1EF214588ULL,
		0xC83E1F73386DFD0EULL,
		0x63AA8F1A3419B503ULL,
		0x6A2F34F49839E004ULL,
		0x81D4A57BEE72D2B6ULL,
		0x883C80D36F81F5B8ULL,
		0xAB97EA18516BB012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5846761FF847CBDCULL,
		0xC320A3700CC935B0ULL,
		0xC27949FFBA982791ULL,
		0x7D76C79278232824ULL,
		0xFA39AA96B6FD7F51ULL,
		0xA9C0DA2C081D8A01ULL,
		0x59FBFE7D05F108F3ULL,
		0x23DF4B32730CFCC4ULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A2F475971CA9357ULL,
		0xA39119321881EEBFULL,
		0x41B8BF96C821EB62ULL,
		0x3239CDE9B582A36DULL,
		0x7E9F49C77ED754EFULL,
		0x220C56E17D37D6D0ULL,
		0x11D3F74370FF45D4ULL,
		0xE6B32D2BC6CB17B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A2F475971CA9357ULL,
		0xA39119321881EEBFULL,
		0x41B8BF96C821EB62ULL,
		0x3239CDE9B582A36DULL,
		0x7E9F49C77ED754EFULL,
		0x220C56E17D37D6D0ULL,
		0x11D3F74370FF45D4ULL,
		0xE6B32D2BC6CB17B6ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEB5E54357B030C5ULL,
		0xBD1341383C2288C8ULL,
		0xAB6EC27330BD6813ULL,
		0x68F8F7E1BF45B299ULL,
		0x4F96CAF1EF681023ULL,
		0x7476CF6B2EB0138BULL,
		0xB4D830B76C646B18ULL,
		0x65451E108920FDC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71B84F3379742951ULL,
		0xB127E29BD754F460ULL,
		0xE5DE6CADD8E133DCULL,
		0x91C018F55055780EULL,
		0x8DFD5B27B098C329ULL,
		0x3B3F1565A577C3BCULL,
		0x070CBF6F94B99649ULL,
		0x9112FB5618D55CDDULL
	}};
	t = -1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7108FF79850E0662ULL,
		0x5613D8E571404D38ULL,
		0x975110812DE8C8B3ULL,
		0xE39A2E03763C8E05ULL,
		0xF8460B56133413B8ULL,
		0x12E6806592F4FF16ULL,
		0x94BDF96B6250E07EULL,
		0x92C479206258C747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07894574A6CF58E3ULL,
		0x3296A0F4B68A5EE3ULL,
		0x916419216C281576ULL,
		0x4761E4C377E9FA80ULL,
		0xB6CABEBE209ED47AULL,
		0x882BBF1E41585DD9ULL,
		0xAB35190CC79858DCULL,
		0x64205620CA909EE6ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC599246F78CB70C2ULL,
		0x1A8358845135E6D9ULL,
		0x26CFA352E6E3F0DCULL,
		0x974162D83960BC52ULL,
		0x2349619053907346ULL,
		0xDD9AF7B19167B6B4ULL,
		0xB24D8CE73A0CD3E9ULL,
		0x56FAA228A15806A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCC39D7804B987BULL,
		0x1A4178F3650E06BAULL,
		0x0D1078C9B86A03CCULL,
		0x1587E8A0F7A824D3ULL,
		0x2A9D670200D48F8BULL,
		0xB71B04B647CF773DULL,
		0xCCCB01CFC8797066ULL,
		0x13958D1352BCF42AULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDB61E1634D2B7D2ULL,
		0xD2A74A23EAC5194DULL,
		0x792A32E5FAAA6133ULL,
		0x2994F3E7979ACFF0ULL,
		0xE36EE10B9361555AULL,
		0x96E0A6EE6CB64B01ULL,
		0xE3E018087BD1060FULL,
		0xC46FF5FA341E430DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB61E1634D2B7D2ULL,
		0xD2A74A23EAC5194DULL,
		0x792A32E5FAAA6133ULL,
		0x2994F3E7979ACFF0ULL,
		0xE36EE10B9361555AULL,
		0x96E0A6EE6CB64B01ULL,
		0xE3E018087BD1060FULL,
		0xC46FF5FA341E430DULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83721E566232692CULL,
		0x76D3E3D85DF6D8DAULL,
		0xECA9FE417B2B9445ULL,
		0x4F9988DF3B90E9BFULL,
		0x0C5618EEF76702F0ULL,
		0xC8E1D64BEC159A06ULL,
		0x4079883CD6770A0EULL,
		0x32B03B1E55368486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E869504732A7B10ULL,
		0xCB781B0B86BA9B08ULL,
		0x07E9CEA827F1DE65ULL,
		0x0BEDBD524992B547ULL,
		0x52E761B6EF277919ULL,
		0x4ED76949807A45FDULL,
		0x59F4A384A86ED387ULL,
		0x4A24657BE06BE205ULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6896772797E1F843ULL,
		0x6D76CC81C5EC6728ULL,
		0x826D3B26905D1A1CULL,
		0x7660E543A3341FD8ULL,
		0x576F36CC4A24E7CEULL,
		0x5CF2EE92240BA5DCULL,
		0x5A2538858EA09DEEULL,
		0xC167973D3FDB1B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80EA68AC806D80DEULL,
		0xFB3F1E6042D37B5AULL,
		0xCA8C2801C52516E9ULL,
		0x17620B7C88310FE2ULL,
		0x5DB07B2098A76DF1ULL,
		0xADCF1A2EE95770C1ULL,
		0x4A9CFFDB31B0299FULL,
		0x01F0226FFD0628A7ULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x404EBA7793767518ULL,
		0xC0014C8C3CA189B3ULL,
		0x0797156FF594769FULL,
		0x5773A06D7FD32D33ULL,
		0x75B4C8935B12178CULL,
		0x10ACF8A1C9A49A2CULL,
		0x4AF4B87B8753DEC3ULL,
		0xB32930E8B95F592FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB728BB28EBCEF5E8ULL,
		0xF856DF81697DD358ULL,
		0x0994747C939EA7E6ULL,
		0x31187EB37EF0F8F7ULL,
		0x619860248ADBC36BULL,
		0xB1EB1971EF16E15EULL,
		0xACB65787A818BE43ULL,
		0x02191DFD196961F3ULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3A03D28B75F404EULL,
		0x75BA84E3678BD58AULL,
		0x206CC0CC2CF0190AULL,
		0x8CEF81C6200FCD91ULL,
		0x8565B9622BEE1233ULL,
		0x722ED4B6A387B4B9ULL,
		0x2AF1F2D5DA4E37B7ULL,
		0xFC7C95213DCBF029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3A03D28B75F404EULL,
		0x75BA84E3678BD58AULL,
		0x206CC0CC2CF0190AULL,
		0x8CEF81C6200FCD91ULL,
		0x8565B9622BEE1233ULL,
		0x722ED4B6A387B4B9ULL,
		0x2AF1F2D5DA4E37B7ULL,
		0xFC7C95213DCBF029ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10892805E4A51298ULL,
		0xD843739C36E66763ULL,
		0xD55F94340C2AF9E1ULL,
		0x5B799419BE00133AULL,
		0xC9E170F7D862FE60ULL,
		0xF3C11CD9E7503767ULL,
		0x54C649CC2FE40A38ULL,
		0xA35A8FDAB3561EC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BB125B2DB19302ULL,
		0x390C7F1C537F9BF3ULL,
		0xEFF9259A67478CBEULL,
		0x086F1102BDEBF373ULL,
		0x039BDF5F77FD44BBULL,
		0x74D2E9D064A05BD8ULL,
		0xF5D50198932C183EULL,
		0x699710555F154723ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2B8769BED10AFA8ULL,
		0x6B6222094F810AC3ULL,
		0x0C2C35094369BAB1ULL,
		0x9D6487DE9D764A05ULL,
		0x2E11D4829C65B323ULL,
		0xA97F97E5FB9FF397ULL,
		0x72B38E4FC256AB7FULL,
		0x6B8A4A83B1CC04EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE452D75015638E27ULL,
		0xB53F09B1FE79713DULL,
		0xFD8A928C8A982716ULL,
		0xC78D384DC9851534ULL,
		0xA00296C07B255864ULL,
		0x2547749E0E6F8850ULL,
		0xCFB820C422DADCBAULL,
		0x4FA59857222AB517ULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70D47E6AAB1657D4ULL,
		0x65D9693BA5DBA585ULL,
		0x52ADD642FDB34DE1ULL,
		0xA4224C67E874B28DULL,
		0xDD3B597309C9B664ULL,
		0x628DD2929354171FULL,
		0x7A019BDEC369DAA8ULL,
		0x7106AA3E548F66C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x226460C42239EF97ULL,
		0x0421D7553B4200F0ULL,
		0x471842E886100D9AULL,
		0xA4672244D8230CEFULL,
		0x7934652E6829A7F3ULL,
		0x9AA23E29AC428A94ULL,
		0x9F5FF0E07E81ABE5ULL,
		0x8566482A7DC8E730ULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC2538650CD53D8FULL,
		0x4981CC7A0F74B8AEULL,
		0xC9C896E14F0E9114ULL,
		0x07AF95BAF2CB7385ULL,
		0x70DE682A78830CCFULL,
		0x172AF12115FF52C4ULL,
		0xC05AE4683BD47AD1ULL,
		0x874F346143E03194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC2538650CD53D8FULL,
		0x4981CC7A0F74B8AEULL,
		0xC9C896E14F0E9114ULL,
		0x07AF95BAF2CB7385ULL,
		0x70DE682A78830CCFULL,
		0x172AF12115FF52C4ULL,
		0xC05AE4683BD47AD1ULL,
		0x874F346143E03194ULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9C76BAF4680784ULL,
		0xCF017BEC8C650471ULL,
		0x7651AFD4D81DAF98ULL,
		0x76A9B160F5027995ULL,
		0x239016A87BF5ABD0ULL,
		0xF7BEA87CEEAC6F4BULL,
		0xF0DC0B0257F3F239ULL,
		0x4F2563EBC42DC400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x215BB25FC42CEA1EULL,
		0x1AAD27447E514643ULL,
		0x19D5492C35B58CD3ULL,
		0x0C4EA40ECD6BFD1CULL,
		0x406D78E61C5DFE6BULL,
		0x95AC182D1D7E5E63ULL,
		0x300B9A5F8AF6961DULL,
		0xA293C37006369081ULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4FBF4E568247AFFULL,
		0xF3D59273111C7614ULL,
		0x3D7503529E0CAF3AULL,
		0x927F45C587693F69ULL,
		0x4D8BFB89A003B7D2ULL,
		0x9BAB082094D940C5ULL,
		0x2D2D959CA3A6B8ABULL,
		0x437BEA2EC399A9CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7059E65D4E388F81ULL,
		0x10C225AC460BCCA8ULL,
		0x772885D25A40E385ULL,
		0x7BAFC1B6640FF46AULL,
		0x25EC3F1BC96E957FULL,
		0xDFDB8EB07D448020ULL,
		0x5CC3096E536057E9ULL,
		0xF11FC2C252A542C7ULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0CC72841DC99EB3ULL,
		0xAD35F6039C220F61ULL,
		0x29BF78DDEB41D66DULL,
		0x9D537173B021AD10ULL,
		0x79E6E7DBC1ABC015ULL,
		0x6EB7B7C1E20FAB0FULL,
		0x69897A4CC121343FULL,
		0xD13151C59D56B491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CFE49275859FDBFULL,
		0x932D373EB03EF35DULL,
		0x6CD7BC44A440F046ULL,
		0x722DC8C693F90EABULL,
		0x72179F38B886AF33ULL,
		0x75FA8838779DA7FAULL,
		0x59581C347E339CD5ULL,
		0xDD090C179149E33CULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B595BA2BBDD6D42ULL,
		0xE80EBA61F32105BCULL,
		0x771B7611F2987A74ULL,
		0x70FD1EDADA596A4AULL,
		0x9D32E33F93730F37ULL,
		0xF9214F935EB47E29ULL,
		0x3E033CE9AF405DBDULL,
		0xF9E619758AF8F355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B595BA2BBDD6D42ULL,
		0xE80EBA61F32105BCULL,
		0x771B7611F2987A74ULL,
		0x70FD1EDADA596A4AULL,
		0x9D32E33F93730F37ULL,
		0xF9214F935EB47E29ULL,
		0x3E033CE9AF405DBDULL,
		0xF9E619758AF8F355ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08FC07F7B324E674ULL,
		0x1D5FA2E2C15E84B6ULL,
		0x795934E124F27255ULL,
		0xEDB628E3FC61A97CULL,
		0x3B61C90A4829E0D6ULL,
		0x95CA5B2464643869ULL,
		0x3357B9EDB132FBFCULL,
		0xBF3096E1DBAE424CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B4AA0E77BB1C856ULL,
		0xF99F415A2F8A4213ULL,
		0xB6E94935EAFA5574ULL,
		0x1A948FB1EC432F40ULL,
		0x923349DFBC88FA59ULL,
		0x1FF55BF403D8D46CULL,
		0x462FA8938F58DE16ULL,
		0x17D65A64DCD694ACULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA530830756730FF3ULL,
		0xA5D47D7166532DFCULL,
		0xECEBE666177CB5F4ULL,
		0x42583BB738EAAC3EULL,
		0xE17F294FC58CD518ULL,
		0xCDC603A95B6EF37BULL,
		0x506865603E0A1E98ULL,
		0x531AA84E8DE0B1F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE923A2764BBD5BEULL,
		0xD12A4F994C4ABBD9ULL,
		0xAC7DD87D1F63F172ULL,
		0x197CC9C473FF2813ULL,
		0xC1E0368A71D8E5A7ULL,
		0xB340A74C6E73C68FULL,
		0x69C8AC9B53A0DEACULL,
		0x0AA4C80303FCE540ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3D46F76453222B5ULL,
		0xC0712994E97DA3B9ULL,
		0x89A88A00F42D11B0ULL,
		0x67B022E092618329ULL,
		0x88A631E2C3F7A8A8ULL,
		0x653F170CA823103BULL,
		0xFE9E3B690920CED3ULL,
		0xF3C2869C63901216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02D5D076D66C71BULL,
		0xBDA51BA334119F45ULL,
		0xE8F0BCB574830C57ULL,
		0x6BD067DDA9A22A5AULL,
		0x9320C3A05BC115DBULL,
		0x6A1472E489205B60ULL,
		0x9DB3556BD969D50DULL,
		0x0C1D8CB817A23E66ULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C3B14AC295838DDULL,
		0x826F44907BA411BCULL,
		0x5AD1D1C7D3F907EAULL,
		0xE42FF1095E8E1563ULL,
		0x9F60CC4D303EBF95ULL,
		0x656FF8678717272AULL,
		0x7FA54892FF2B19B7ULL,
		0x32D237DB5A16D823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C3B14AC295838DDULL,
		0x826F44907BA411BCULL,
		0x5AD1D1C7D3F907EAULL,
		0xE42FF1095E8E1563ULL,
		0x9F60CC4D303EBF95ULL,
		0x656FF8678717272AULL,
		0x7FA54892FF2B19B7ULL,
		0x32D237DB5A16D823ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA61E40580D451CABULL,
		0x6A65819DB0C6140CULL,
		0x4CEF26EC8CF0B88AULL,
		0xFC2BA1F4B01E9D83ULL,
		0x0348F3513895AA06ULL,
		0xB2B1C644BC1AAB09ULL,
		0x7F0E3A0DD51EABFAULL,
		0x722E22505C43C79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CB637F8D45263D7ULL,
		0x9D4B5FB0D3D850F6ULL,
		0x37DA2CD08BEC375AULL,
		0x425846307FAE2C45ULL,
		0x9C2FEF77B8D2DD4FULL,
		0x929B123E7849B621ULL,
		0x377EA9068D1E3F4CULL,
		0x9D0C5D93A68FFA6DULL
	}};
	t = -1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7FFFB3821F544A1ULL,
		0x9F4571672AEA9657ULL,
		0x3A355C905F701FD7ULL,
		0x60A9AFF9A3E16BFBULL,
		0xA2FECEA07DECB006ULL,
		0xA2AE7580847629F9ULL,
		0x3CB20F489F5417D7ULL,
		0x147D5F59542203B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC65EAB5014C25A93ULL,
		0x849B773D77740B0FULL,
		0x0D7950C04F1B90EEULL,
		0x5D774013070A24FAULL,
		0x295C257D9E2964DAULL,
		0x64657B775435B4EBULL,
		0xDA91738AC683AA6EULL,
		0x163BB7EA7052B719ULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64F758A62EB5455DULL,
		0x3E1C57412FFC6212ULL,
		0x06C2F6779E901D27ULL,
		0xBC7A6224EDDDD4A0ULL,
		0x252F5BEF3BF6D9DBULL,
		0xB80A9596E8B46C1CULL,
		0x7D52F7B36DFE37EEULL,
		0x4F014993AE85315AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC97CBC907B1358ULL,
		0xB5A2B42DA5D0A581ULL,
		0x0780A6B436EE8EA5ULL,
		0x39CDA81FB444EE53ULL,
		0xCF46A3395BB30546ULL,
		0x791D22FEEF6D1CBAULL,
		0xC4A7A5F97C1C80E0ULL,
		0x4A6DD54CF3472AF5ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43864A55028B5F16ULL,
		0x6E78DCEAC0E26F23ULL,
		0xFFB9A43B3AE1F3B1ULL,
		0x924469C63E6DD17AULL,
		0x4DA662315B2C2379ULL,
		0x7F5D11A5FA88794FULL,
		0xD78BF95DE165919BULL,
		0xA9B64589C24ECE8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43864A55028B5F16ULL,
		0x6E78DCEAC0E26F23ULL,
		0xFFB9A43B3AE1F3B1ULL,
		0x924469C63E6DD17AULL,
		0x4DA662315B2C2379ULL,
		0x7F5D11A5FA88794FULL,
		0xD78BF95DE165919BULL,
		0xA9B64589C24ECE8AULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0458D65C7378349DULL,
		0x8A084228174D1BE8ULL,
		0xD2F5EECD8FB23A8EULL,
		0xD5DCC57D8F28E05AULL,
		0xB6B030D0EF513DCFULL,
		0x10AB2CD64C0B6D14ULL,
		0x972BDDECD51EF7A2ULL,
		0x03ACB3EC712FBEA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6452947DE26EEAA9ULL,
		0x4F50B5C8992C842DULL,
		0x0A5A01DEEE8BF2BFULL,
		0x738734617A440DEFULL,
		0xF125EB4A3E1708ACULL,
		0x0F7C61E4B15123D1ULL,
		0xEE4E54759B6E6366ULL,
		0x6A00C4AFDEC5E3D6ULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EE1E739C6CD53D8ULL,
		0x220715E1EFDA68CBULL,
		0x9F16515400E0666AULL,
		0x13D8F9A176ECFF28ULL,
		0x0AFAF00C49FC487AULL,
		0x2F43DDBC07C2D712ULL,
		0x95C6B878A440C42CULL,
		0x45BD711F3B93356EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA8CF7DCCE1A7B7AULL,
		0x3ACA8B8D9DE10252ULL,
		0x7786D24A9F813960ULL,
		0x34824CF3C607469AULL,
		0x0943670002F84401ULL,
		0xCF107FEDAEC4085DULL,
		0x0B8C493E489644E7ULL,
		0xF7F708AE8A55192CULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FE8747E62E8CC05ULL,
		0xAD4BD9CC4BBB889BULL,
		0x02752E681939C9E1ULL,
		0x44311B8A8E2C5C53ULL,
		0x9C219FDAC9168A83ULL,
		0x3424A252E985A896ULL,
		0x887142F30920248FULL,
		0x430047C6D52A862FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3831982FA80AD830ULL,
		0x338C145DE8536B59ULL,
		0xA86CA7F360417FBDULL,
		0x35D7AF9783D7A722ULL,
		0xCA49830AFB7A80ACULL,
		0x47DA5620DFE1773BULL,
		0x602600258691B68FULL,
		0x5932C2BD3FF6CC08ULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA492EBC7E19859BULL,
		0xAA0ACCBDAFAED6F6ULL,
		0xD6AE6376F3E1A85CULL,
		0x2B6B674740296D02ULL,
		0x09603A6F38C45AD9ULL,
		0xB89758B7E4A0D7DAULL,
		0x783E8BF56DF3E03EULL,
		0xE93226B94200E1D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA492EBC7E19859BULL,
		0xAA0ACCBDAFAED6F6ULL,
		0xD6AE6376F3E1A85CULL,
		0x2B6B674740296D02ULL,
		0x09603A6F38C45AD9ULL,
		0xB89758B7E4A0D7DAULL,
		0x783E8BF56DF3E03EULL,
		0xE93226B94200E1D7ULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE9B62FE8C8E1BC0ULL,
		0x6EA7E4028958C0A0ULL,
		0xCE22B4682B085637ULL,
		0x4C9DE68E6DEEA001ULL,
		0x670A92F065F13DB4ULL,
		0x1ACA7FBC8A41D631ULL,
		0x1C024B5E99374764ULL,
		0x4E5285A9E87C3B65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B8C64EDAE93C84ULL,
		0x1B9361FB20625A76ULL,
		0x1A5172EA09008306ULL,
		0x2DD29B88BDF7FDACULL,
		0x7EEC5572139D2C33ULL,
		0x684FB97FDA8106FAULL,
		0x01F5B1970CC5FDAAULL,
		0x4A5AE46EB1B78B3AULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E1403192D0B284EULL,
		0xA35ADDB764CED1E1ULL,
		0x92BC7EE1AAE14454ULL,
		0x653389D92CA1BEB9ULL,
		0xC1284AB8015198F3ULL,
		0xD5BD5C06192AA457ULL,
		0x79B1869AA1BB3BDFULL,
		0xC4F34765EA8F2968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3AEFCA9837DCCD7ULL,
		0xA113A704B8ECFD0EULL,
		0x696323ACDE8FBCD9ULL,
		0xD6F0BC60AEED2CC0ULL,
		0x1B9EACC0B39A11ECULL,
		0xBD79D54D9AA5499DULL,
		0xD95D050A1923018FULL,
		0xEABBE7CC7DFC9070ULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3964176D2C054BF6ULL,
		0xA14B66C9AFCFE703ULL,
		0xDC32DE3F8F7A7EDCULL,
		0x689882C5016B5185ULL,
		0x596F9E6DA1237C1AULL,
		0xCF11EAF9334676B0ULL,
		0x1DAAB927F0E90D13ULL,
		0x3BFF1CB5E745C680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107A8046E7BD611BULL,
		0xFA813D60A07C47F4ULL,
		0xAFD4152E57E5D021ULL,
		0x9B9F3A05ED72FD4BULL,
		0x682C4081648F80BFULL,
		0x8E6079D02B6D6109ULL,
		0xD8ACEED849A647F7ULL,
		0xD6E6FAEF8860AD85ULL
	}};
	t = -1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B8AA2F77F588A7EULL,
		0xC7B8BF9AC8A0F970ULL,
		0x29189F0A37CD9CF3ULL,
		0x6F4861192256486CULL,
		0xFCA5EB6E2F06C3E6ULL,
		0xDBE0463ABB9C086EULL,
		0xD1B074E5B4568CCCULL,
		0x0F574EA2F5B6EFC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B8AA2F77F588A7EULL,
		0xC7B8BF9AC8A0F970ULL,
		0x29189F0A37CD9CF3ULL,
		0x6F4861192256486CULL,
		0xFCA5EB6E2F06C3E6ULL,
		0xDBE0463ABB9C086EULL,
		0xD1B074E5B4568CCCULL,
		0x0F574EA2F5B6EFC7ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x989A0B6A9CC660DAULL,
		0xD2DD2ECA133F13D7ULL,
		0x4694B43B379AF7C2ULL,
		0xAFF9EC1298950D8BULL,
		0x59CC957E681FC5A8ULL,
		0x8517091087D246C9ULL,
		0xA678F6FA27DDD062ULL,
		0xABA81F64D98D60E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ACEC59970F8E253ULL,
		0xE88DEF8A4E93505EULL,
		0x9F3B817D1BF2B90DULL,
		0xB25E897EA9B69E36ULL,
		0x80886C496F06ED96ULL,
		0x58CB0A2CEFA5DDDFULL,
		0x93B556DCFF0D5571ULL,
		0xEBF103F901BC5877ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA13560A8C9556124ULL,
		0xE3EDF38ED42B7597ULL,
		0x481E068678CDE8F2ULL,
		0x3EB00FD8EF3353BCULL,
		0xF02FA5623D14F7C9ULL,
		0x00AAF5349E3FA02AULL,
		0x188E26636A8738DCULL,
		0x6EC6A1D67EAF9BBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A9997B2A6842EEULL,
		0x41B51941D07E0977ULL,
		0x9367F1181F95D156ULL,
		0xEFE64CE2F9E4A414ULL,
		0xB8DED46F92CA6842ULL,
		0x2D20DF88FBB08671ULL,
		0xBADB569727DC01F8ULL,
		0x92AF0E14C67A84CCULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE78014756FCF20D3ULL,
		0x98183EB66D811B2BULL,
		0x606F8E980821482BULL,
		0x95D039096C4FDB14ULL,
		0xA0F15201B614CA26ULL,
		0x098E628552A9A85BULL,
		0xCDD18BAAA7028A90ULL,
		0xBFBDD66AD737E5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x248F4150D2FDF632ULL,
		0x8A433DD265009DFAULL,
		0x614DE8E62DCBF9ABULL,
		0xC82F171F563CA650ULL,
		0x8D371EBEEB95AB4BULL,
		0x5C572B6A2268818EULL,
		0xE1BF3824C5F26DE4ULL,
		0xB9BFECFEE1A8087EULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35C49B72B24C1229ULL,
		0x928DBE2015EFD995ULL,
		0xBCE47A2C217B6225ULL,
		0x508E8C42E526E358ULL,
		0x00564B353DA5EC7EULL,
		0x971FDF82A0E0926FULL,
		0xBCA72CE0637411C1ULL,
		0xC8CEDE3C5FE48143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35C49B72B24C1229ULL,
		0x928DBE2015EFD995ULL,
		0xBCE47A2C217B6225ULL,
		0x508E8C42E526E358ULL,
		0x00564B353DA5EC7EULL,
		0x971FDF82A0E0926FULL,
		0xBCA72CE0637411C1ULL,
		0xC8CEDE3C5FE48143ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77531772FCE5FA89ULL,
		0x5003A5208B1A06E0ULL,
		0xB4FCAE8C608E7A71ULL,
		0xB756800D32A02D0AULL,
		0x7E09E4DE286B923DULL,
		0xC96071569354EF4DULL,
		0x67527B0C77062AF6ULL,
		0xECCE493C2EE00959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B1691A6F5BE6C5ULL,
		0x56BB89732F9783F7ULL,
		0x44AF47556B646135ULL,
		0xD0BA24E083B20735ULL,
		0x3ED2121F54CF3506ULL,
		0xCF5B42D174A7B899ULL,
		0x9A4D20E7AC693049ULL,
		0x6AF8DF314866964EULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD1BFCEC3161AE4DULL,
		0xFE7CACBDDB4F57D1ULL,
		0x94814AA6B2BD41E3ULL,
		0x8080558A1CA36ABEULL,
		0x6D2B159530B6DAE7ULL,
		0x6B5FEFEEADB8460AULL,
		0x72728CAB501C0A4CULL,
		0x25DC7DE2490986AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8737BEA60BA708ECULL,
		0xFC52283487620A1FULL,
		0x3FDF2ACDEE532630ULL,
		0x103EEDF45DC59D7EULL,
		0x72B56B63516773A7ULL,
		0x18D6286DE3D293F7ULL,
		0xC3DB62DDF30580E5ULL,
		0x31EF2744272217B6ULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62C7BB051EAB2EDFULL,
		0x4F9B2DDDE0D388CEULL,
		0x3382515982FABCDAULL,
		0xCCD78EEA2E47F4E4ULL,
		0x7EE9F5ECCDD819EBULL,
		0xA8C66B64091A87E3ULL,
		0xE8BBD4D6E13B8400ULL,
		0x8160EC500AE3BDAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC67C23DB8A9A696ULL,
		0x826A650B1CEEFD29ULL,
		0xAC83B2BA825C7595ULL,
		0x7706D0798C82B58DULL,
		0xE23953EEEC1432C0ULL,
		0xCFBF9B038AFBE9B0ULL,
		0xEA82C268B631ED97ULL,
		0x570578D46CBF8E88ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60E6AAA8AA1F4185ULL,
		0x6F4010AFACB99222ULL,
		0xD1929B15E1C3C138ULL,
		0x76578DFC4A4F35C5ULL,
		0xCED531609C586DEDULL,
		0x6E997AA62D0C63DEULL,
		0x564C3B603361F69DULL,
		0x354B89080CA5C1D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60E6AAA8AA1F4185ULL,
		0x6F4010AFACB99222ULL,
		0xD1929B15E1C3C138ULL,
		0x76578DFC4A4F35C5ULL,
		0xCED531609C586DEDULL,
		0x6E997AA62D0C63DEULL,
		0x564C3B603361F69DULL,
		0x354B89080CA5C1D3ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCDF8866AFDE87A5ULL,
		0x1514C1EDCC295BB7ULL,
		0xEF9ADE65FC8EFB9CULL,
		0xC740C26C54A0DC8EULL,
		0x76F6585DA321103EULL,
		0x3E41D9D956DE7FC6ULL,
		0x9F26ED42D1833E6CULL,
		0x9FCD43A94C02EF76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6559CA70A5AAFD89ULL,
		0x2B15B33DB209103EULL,
		0x65C6E558EA21FC9EULL,
		0xECC3123483ADA6EEULL,
		0x0FF371AACEFDB0B1ULL,
		0xF8BFBF170D7B3210ULL,
		0xC7058E44A806C96BULL,
		0x5C47780FEB4552B2ULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4B4B796113720CFULL,
		0x2DE2B9CC3DB17F57ULL,
		0xC1886EB51259E54CULL,
		0xBF219043A6ED1E65ULL,
		0x4F9BAFDB8D83EAF6ULL,
		0x2F8650259B24474AULL,
		0xECAC66553AE89F90ULL,
		0xFC7E0737803280D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F280D8F3C9B568ULL,
		0xFC403555ACD8CF50ULL,
		0x63B13E7DEFA88CF3ULL,
		0xEB563F56F6A048F7ULL,
		0x4FFD7231CEE49617ULL,
		0xD5C4B6D7EFB52633ULL,
		0x54DBD8D6A04D7853ULL,
		0x83916316E2919D32ULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA4F55BD079D7C42ULL,
		0x2388B5E4CCD5CC46ULL,
		0xD918966A47EDF2F5ULL,
		0x78C84214F569D866ULL,
		0x23C951D2EFFFE75AULL,
		0x9C12E82E1B6CD04EULL,
		0x87CC6F2CABC7EF68ULL,
		0x60FA56DF95AC60B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0239E5EFBAD1F9ULL,
		0xF5A67491AF8A04E9ULL,
		0x3E08A7DFB1E15A2AULL,
		0x14660C20B4B0AE3BULL,
		0x06AE5E851351D6F8ULL,
		0x97B95BACC04EF44BULL,
		0xC950C95413D39E43ULL,
		0x439EDB21F08A127AULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE8747D472999012ULL,
		0xFBD7429EDA35891EULL,
		0x3690553711FDB1F1ULL,
		0x0F98DFC7CEB202BDULL,
		0x80FF68240F67D350ULL,
		0x33D154F38A589B26ULL,
		0x22379100542B287BULL,
		0x263DA20C1D6B9B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE8747D472999012ULL,
		0xFBD7429EDA35891EULL,
		0x3690553711FDB1F1ULL,
		0x0F98DFC7CEB202BDULL,
		0x80FF68240F67D350ULL,
		0x33D154F38A589B26ULL,
		0x22379100542B287BULL,
		0x263DA20C1D6B9B57ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8591ED802841E7D9ULL,
		0xB28B0F792CE24DF0ULL,
		0x26BFE9DB1D21480FULL,
		0xF5B16EBD9B0D01A1ULL,
		0x6120B35CE5EC08F5ULL,
		0xF52351554D7A7B29ULL,
		0x4BB3AC7B9070B1F9ULL,
		0xB33ABB708E349063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B61F6EE5E1879B1ULL,
		0x7314E42062C26FDCULL,
		0xDFD7BCF24508B121ULL,
		0xB031E8A3EC4EF211ULL,
		0xC6ECE8456266687AULL,
		0x2B7056BCF4B9F3AAULL,
		0xC0E9667CB17BA01DULL,
		0x5EA7B2F36D149925ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C051A230DF24A28ULL,
		0x425996A35F7713BDULL,
		0x81839A9E044958FAULL,
		0xAA644C2BFB2674DBULL,
		0x5F1C8044EB285492ULL,
		0x1CE4E30CB9559DDEULL,
		0xA31E7CFEA8876590ULL,
		0xBF85217926E9A686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28967CE52F37BCFULL,
		0x2EF1F85E880032C7ULL,
		0x7CDEAEC96D7A7840ULL,
		0xF00404E07509FC10ULL,
		0x630D5AD5F3CD4D80ULL,
		0xB8ED255D8E6ACD4FULL,
		0x384030A58FEF3465ULL,
		0x7EC8AA301C6EC5F4ULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x331740848875EC4DULL,
		0x664442DF5BB45A27ULL,
		0x541989D625C0428DULL,
		0x35CDFCFFAC938CFDULL,
		0xC5B87F3317674A24ULL,
		0xEE9CD8AF70C6587AULL,
		0x519D52AF4AF073FAULL,
		0x41159038CC8DE183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0720D43AC1A6EAE3ULL,
		0x65ABE352ACDF3B82ULL,
		0x765A0C2AA7ACC3A4ULL,
		0xA7DE351771A92A98ULL,
		0x7F1D6E08FCEAD77BULL,
		0x9ECC64DE8A379298ULL,
		0x368D01C5A0786F1EULL,
		0x4A52009F1ADD62C8ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AEB9637A062CD76ULL,
		0x87861371BFDB29F0ULL,
		0x711021C506473C0EULL,
		0x5DE97308A34323BCULL,
		0x600AB95E8B3A02B7ULL,
		0xC279BE0D497D465CULL,
		0xFD9E875D65B28DDCULL,
		0x973D4E3A8823C56EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AEB9637A062CD76ULL,
		0x87861371BFDB29F0ULL,
		0x711021C506473C0EULL,
		0x5DE97308A34323BCULL,
		0x600AB95E8B3A02B7ULL,
		0xC279BE0D497D465CULL,
		0xFD9E875D65B28DDCULL,
		0x973D4E3A8823C56EULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C3A8E9396C60E0DULL,
		0xF9DE0BD694D4492DULL,
		0x0041584AC056C858ULL,
		0x0BA8425A749EDAEDULL,
		0x0EE9B8C925CC6280ULL,
		0x52BF26B40138E23AULL,
		0x9E9535042B391686ULL,
		0x43EC51579F273B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94040075CF049CB8ULL,
		0x8A0DF0260B7B3806ULL,
		0x02847A4F1F605392ULL,
		0x2E4B7918DA54F1DAULL,
		0x4917C61D064B26FAULL,
		0x6A9D7A91B08AE555ULL,
		0xE61AFD7DEC72AB29ULL,
		0xEEC19DF4B6312146ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BC2A7BC36FCB0FEULL,
		0xFDA30EB9442D1010ULL,
		0xA1FF287157D64A68ULL,
		0x0C756B5F98787FBFULL,
		0xFAB3F4431C24DBF6ULL,
		0x1F870967D38D6445ULL,
		0xA8760F86BD7A9A90ULL,
		0x34B8750CE82A9658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25A627B2D79041BULL,
		0x09D5866324A1E444ULL,
		0x2A5D0DFAFBFD1443ULL,
		0xF9A4F692203FC00FULL,
		0x530647EF445870D0ULL,
		0x543D37F701C18897ULL,
		0x6D5581AC88C01378ULL,
		0x6C2A10C72C1139AAULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11C6451C225670F0ULL,
		0x0E3D96F07C71F073ULL,
		0x1F0446F6B7402EC3ULL,
		0xC8C7DCBAE6150149ULL,
		0x56BE368DFB42E003ULL,
		0x1812731D43D1EC92ULL,
		0xF08908CD384AF0F6ULL,
		0x3B5AE4188398FBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F4FFABF80DEC8FEULL,
		0xCF4235A1674CD938ULL,
		0xD739EF58602F04AAULL,
		0x95033FD1ADC293F8ULL,
		0x353FF8C1A8DCAE0FULL,
		0xEAD180315A322A8DULL,
		0x6437CEAF5A4662F7ULL,
		0x489F0D823371EEE3ULL
	}};
	t = -1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2127742B5BE23A80ULL,
		0x24F9C65239D4FCFCULL,
		0xD5FBBE45F8E90C0AULL,
		0x2C4BD82F9DE1456BULL,
		0x822AB7564508BA83ULL,
		0x439FC98EB02549CCULL,
		0x278998EC3AE3E1F4ULL,
		0x35B31210394AFC3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2127742B5BE23A80ULL,
		0x24F9C65239D4FCFCULL,
		0xD5FBBE45F8E90C0AULL,
		0x2C4BD82F9DE1456BULL,
		0x822AB7564508BA83ULL,
		0x439FC98EB02549CCULL,
		0x278998EC3AE3E1F4ULL,
		0x35B31210394AFC3CULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x992EAC1F1BE9BCE0ULL,
		0xA38D620FC8F935F0ULL,
		0xF5C782B5BD54E1EEULL,
		0xDCB0F56645614890ULL,
		0x5189A0EB198DA268ULL,
		0x5EC8E03314C6E80CULL,
		0x50025ACE775DCA45ULL,
		0xE329A283E898F698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D49196083201C8AULL,
		0x0512505E1ACB4599ULL,
		0x50987990932E61A7ULL,
		0xBCF3116439A4E0B1ULL,
		0x4F977825AF732ED6ULL,
		0xFC8437650FA40407ULL,
		0x349125F9E8CA7804ULL,
		0xD5CC1BD7E1EA82A6ULL
	}};
	t = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47D395AF97A2B095ULL,
		0x80EB09F3438EBDBEULL,
		0x04E2ECCD7BAB3D42ULL,
		0x4D9497A9F97B3A5DULL,
		0x37D3266ACFC0C60CULL,
		0xAD45942217CA7B57ULL,
		0x5B8889C96DC01434ULL,
		0x4795A533C2BB9E70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0982B56C23EDC8F0ULL,
		0xD6FC62E45C27B72CULL,
		0x9919F7308C48E828ULL,
		0xD7F6E4A3CFC32FFFULL,
		0xF76C1C5856BA4105ULL,
		0x89CFCF9A1867C643ULL,
		0xF058608A673D54A6ULL,
		0x25807B2F179E2E41ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4796CE0EFA0CAA1CULL,
		0x13504C9CF0B9F104ULL,
		0x9C6F24F873F1E59BULL,
		0x4231E5ED9FA5BF63ULL,
		0x180D30AF605A4C16ULL,
		0x062ADF9E3BAFAE96ULL,
		0xD2A1909EA32ECF38ULL,
		0x5B6DC366EB694A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB00C5A52FEB24364ULL,
		0xC68FEC5049430445ULL,
		0x2AF8E1D03C8FFD86ULL,
		0x2E25243E6D3B913EULL,
		0xD65F0670AFD9CD2BULL,
		0xFF60D4EF8D3479E0ULL,
		0xA5634732364D2428ULL,
		0xCB7540F9BE0F87E6ULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD26B33B198504D2FULL,
		0x6E9F91778745F0EDULL,
		0x52C4837157A9E8CEULL,
		0xE2315C5CC8A71729ULL,
		0xDE6F2451F1283B43ULL,
		0xEC82BF5A1135C389ULL,
		0x974D20DD6D1ACA72ULL,
		0xCAAEED9E103B7CFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD26B33B198504D2FULL,
		0x6E9F91778745F0EDULL,
		0x52C4837157A9E8CEULL,
		0xE2315C5CC8A71729ULL,
		0xDE6F2451F1283B43ULL,
		0xEC82BF5A1135C389ULL,
		0x974D20DD6D1ACA72ULL,
		0xCAAEED9E103B7CFFULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D8B0E6887B0BF85ULL,
		0x88F20EC2218CA040ULL,
		0xF6587B21A1483FA1ULL,
		0x622CFA4C3690D0DBULL,
		0x65282B7A5A745086ULL,
		0xCFD1C32BC71980C7ULL,
		0x6C4B3C5F920FA51FULL,
		0x3BFF4F7B6335E005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14CA8C286631B142ULL,
		0x3DA332C24271BCE6ULL,
		0xC5170F628579BDF0ULL,
		0x53F9B0EE1A6A0590ULL,
		0xBD6F5DA03EB04F27ULL,
		0xA504776260A7460EULL,
		0x04C2AEEAB8C218C5ULL,
		0x49888768A379E065ULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE4B451FC33C1D43ULL,
		0xCA53786AD814AB11ULL,
		0x397FD0BE0A7A48A7ULL,
		0x2B1EC7AB5B637ED3ULL,
		0x5499CDE27AA040B1ULL,
		0xF07CE097D722D86FULL,
		0xE4180296349BAFD1ULL,
		0x9080333E85A57966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702523D0687F922AULL,
		0x9A08997994417C03ULL,
		0xE857AD4D5AA74C10ULL,
		0xCEEC3F1408E68F67ULL,
		0x5DCEA469AD3A1173ULL,
		0xE63DA759EAE575C2ULL,
		0x26ACAFA103E43E0BULL,
		0x940DB83B6A53C615ULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7F8B64858B77C1DULL,
		0x8EAC7E240789AD86ULL,
		0xA3994E001F05D764ULL,
		0xC8826589A2159259ULL,
		0xF6D397CDE57BAE1AULL,
		0x8FF8DCA42A0DE561ULL,
		0xCBB7EACEEB2042CAULL,
		0x4702719132513F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7CA5084F6F8D43CULL,
		0xA20FA5E80A29C34EULL,
		0xDFBFC8B5A024C1B3ULL,
		0xE351856E980D3D36ULL,
		0xD8BABA2949B0259BULL,
		0xC4563608FA884E9AULL,
		0xD3C6654184D4DB9EULL,
		0xABA1E5ECABDD1147ULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA2C9E62B64C1DFCULL,
		0x7BB24D31D1343119ULL,
		0xD7D87B8E905C1C24ULL,
		0xD5C1D1E75DB752A9ULL,
		0xAEDA195FD04B0354ULL,
		0x39A65A2CE8F3DF00ULL,
		0x40CDA12FBF41F4DCULL,
		0xB4CF1DB449A169C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA2C9E62B64C1DFCULL,
		0x7BB24D31D1343119ULL,
		0xD7D87B8E905C1C24ULL,
		0xD5C1D1E75DB752A9ULL,
		0xAEDA195FD04B0354ULL,
		0x39A65A2CE8F3DF00ULL,
		0x40CDA12FBF41F4DCULL,
		0xB4CF1DB449A169C8ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20D901B45AD34B33ULL,
		0x70C76FC77350928CULL,
		0x7BF684AB860D26C5ULL,
		0xD02342EE8B09DE89ULL,
		0x3490154939599A41ULL,
		0x2D3BD78793672C89ULL,
		0x5AB531B050CD7466ULL,
		0xC63C59432CB14650ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB8F024CE0B307DULL,
		0xDF8573875FF9D772ULL,
		0xAD2C650198AE7EC5ULL,
		0xED4671204DB10E7BULL,
		0x6B2976C4B6630FB0ULL,
		0x023981796A969719ULL,
		0xF07C4C6602FA874BULL,
		0x441029696C72E2E1ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB1CAB9BDDA5896EULL,
		0x58736806782C8D6FULL,
		0xC03B67026C6253FBULL,
		0xBED2ED847D84C061ULL,
		0x150066A5CDF0F1F8ULL,
		0xC7FB0897CF82EED2ULL,
		0x0A25C0F6B1755148ULL,
		0xB444E8395119C262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95FA0391425D48B6ULL,
		0x49AA0BEC595D09A0ULL,
		0xA655555715A12A2FULL,
		0x1DE312CFF9B0C40CULL,
		0x09073372980629FFULL,
		0xF231A994A849FFF9ULL,
		0x5558CD5C4CCE127BULL,
		0x9C775E6D96A7F1AEULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4718CEE6E7CB57AAULL,
		0x163FAC9458083CDAULL,
		0xB21CAEB8B8B3AA9AULL,
		0xC54BC65AFB18F45BULL,
		0xC92FD0FFF8FAA830ULL,
		0x6CDEEE663B67CD7EULL,
		0x12D85E01409C57CFULL,
		0x798864F5E8750403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD93DF824479068DBULL,
		0xDFC15B609CE8DFF4ULL,
		0x816AFF2E64853201ULL,
		0x5813796FBF85C059ULL,
		0xBEFFFC8623BD77A5ULL,
		0xBB39FECBBC585E81ULL,
		0xB08A901812E8A5B7ULL,
		0xC7490BBC7573AAE0ULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CE4F0956588E15DULL,
		0x11E27AD55356907CULL,
		0x6EB77CE6D4205128ULL,
		0x1BFEE3166F4FDBD1ULL,
		0x858FFEDBE03FC3EBULL,
		0xA016AE75F3E70BA7ULL,
		0xED7390453BE673C0ULL,
		0x4C893F0C37DBA0C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE4F0956588E15DULL,
		0x11E27AD55356907CULL,
		0x6EB77CE6D4205128ULL,
		0x1BFEE3166F4FDBD1ULL,
		0x858FFEDBE03FC3EBULL,
		0xA016AE75F3E70BA7ULL,
		0xED7390453BE673C0ULL,
		0x4C893F0C37DBA0C3ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D1E6C03B190B36CULL,
		0x1F5F97E3CE8616D0ULL,
		0x4CC1AA25ABCC2D74ULL,
		0x90269BC89112852DULL,
		0x223CA6C69DD13DA3ULL,
		0x83705D6D37BCF6B3ULL,
		0xEE888F35C22B87A4ULL,
		0x1DFDD4223DC355D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB0925B4D75ACE57ULL,
		0xAAEEA3332799F0A2ULL,
		0x4593BCB76233C7AAULL,
		0x85B28DB0925684B7ULL,
		0x8093E136B291B0FDULL,
		0x67501D38C9BB619BULL,
		0x47BEC40A225A6899ULL,
		0x35CC2DB1EEC1062AULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF432F82E716491ACULL,
		0xB940E526773D0186ULL,
		0x4D711B11AD4A959BULL,
		0x83AF3437581B9AF0ULL,
		0xB4BFF5D98742E3BDULL,
		0x8079591528B781B7ULL,
		0xC2747281E5DC8114ULL,
		0x21248363DCCCF228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E930FE4ABE5CECULL,
		0x5C2786351B7B1AA8ULL,
		0x2BE44C9176D086AAULL,
		0x9620368C44E80597ULL,
		0xACA622F9A16CC56FULL,
		0xB60EAE1E2A2F86B5ULL,
		0x25596D7784C3EB1AULL,
		0x63CDAF9D967E0AB5ULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42887B41048D93A3ULL,
		0x605C45BFBB5DC586ULL,
		0x96E4E543A33AF7B1ULL,
		0x93191443AE70DE1BULL,
		0xB22FBE10397BF3D5ULL,
		0x6FAC53858A618D68ULL,
		0xDECF8A860DDDF402ULL,
		0x8C88580DCF70A739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEBFBD2C30124817ULL,
		0xDC386F57914E83A1ULL,
		0x66FE4EF87364C188ULL,
		0xE3B164176313E5F5ULL,
		0x95A07132946DCAC5ULL,
		0xBA10AAE1921DDF3BULL,
		0xD6D0015C69AB9023ULL,
		0xB61E08F50B7DC660ULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9CD550312B8F574ULL,
		0x531C8F176BECF5EEULL,
		0xF5E93BDA75CE4A94ULL,
		0xF83E0FD8A6EAB4CDULL,
		0xDF1846EBA1B11216ULL,
		0x51627D1D30522EE1ULL,
		0xF6BB124EB54BC04CULL,
		0x044EAD1A17EECDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CD550312B8F574ULL,
		0x531C8F176BECF5EEULL,
		0xF5E93BDA75CE4A94ULL,
		0xF83E0FD8A6EAB4CDULL,
		0xDF1846EBA1B11216ULL,
		0x51627D1D30522EE1ULL,
		0xF6BB124EB54BC04CULL,
		0x044EAD1A17EECDDAULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5E6B0A19B7B191DULL,
		0x23DA591D0607D9FEULL,
		0xF96FBF58BB3DBF64ULL,
		0x24585F0856BEF270ULL,
		0x1A26C0F2FC049621ULL,
		0xE9749D8390C95B99ULL,
		0x8CE848EDEDD1262CULL,
		0x64A69F95DE25198BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADCCCC534CF205ACULL,
		0x580124AF3E31060CULL,
		0x225373F32D5B7977ULL,
		0xAA73A32D4FCAAED5ULL,
		0x2D88A598EB486FEEULL,
		0x636A3C4346DBA2C2ULL,
		0x63255AC2C9478026ULL,
		0xDFF6151E09A076A8ULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C5BADEED8C6D20DULL,
		0x2B9D09A8316767EBULL,
		0x203A139FEE271E5FULL,
		0x2CFECEEAD92C32A4ULL,
		0x30B31B026B46F8F9ULL,
		0x350D06A003F68FC0ULL,
		0x4E81B599F0830FA8ULL,
		0x6FA38C3BDEFF4301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB1668C30B20F6DULL,
		0xEA6C26ED287C12BEULL,
		0xF8D16B9C59654020ULL,
		0xC0F260B5E670A289ULL,
		0x5F1E1FCC87FDA79AULL,
		0x1684E9D0D301D02EULL,
		0x30388C4291D274FAULL,
		0x811DE56ECAC87319ULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x201A1246FA962D29ULL,
		0x8136242938740B0BULL,
		0xAAFC0F3BD323CAB2ULL,
		0x41F76FE286AF58C4ULL,
		0x3E9F5B49981769A9ULL,
		0x5F1BF20F7097EA99ULL,
		0x96CD43218D714DAAULL,
		0x7ECF40A67D8CA85BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6606076E7BE39182ULL,
		0xC0E6F327221577BDULL,
		0x60B7063B6992EB56ULL,
		0x2A62AC57DDF3ED9BULL,
		0x61DEECA4689C2B96ULL,
		0xF175C6318E788E82ULL,
		0x4EC23C39D2A68DA4ULL,
		0xC69146A1220ED77FULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36C6A573542F24FFULL,
		0x1CA6973545105E6FULL,
		0x819CD08EA9EE46A6ULL,
		0x5A1AEE2C9DC6DF5CULL,
		0xCB0D5C76B45F5AC0ULL,
		0xBA7B3D8E68515801ULL,
		0xBFB837C46071CFE9ULL,
		0xDE178C629EF6DE35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C6A573542F24FFULL,
		0x1CA6973545105E6FULL,
		0x819CD08EA9EE46A6ULL,
		0x5A1AEE2C9DC6DF5CULL,
		0xCB0D5C76B45F5AC0ULL,
		0xBA7B3D8E68515801ULL,
		0xBFB837C46071CFE9ULL,
		0xDE178C629EF6DE35ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC664C556325450E9ULL,
		0x4462E75BC2997C69ULL,
		0xACE9741FF719A3BFULL,
		0xB5A484ECF7B77DB7ULL,
		0x1B2725010A10CF29ULL,
		0x4B6529668F71F76BULL,
		0xE0420EAD824FAC02ULL,
		0x3F2F551F1C3B951EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB4C1D83E61BB69ULL,
		0xB04C4ECD83FB6F70ULL,
		0x7516A3F2E10736BFULL,
		0xE235A46D9C6B1009ULL,
		0x14BE279064657A77ULL,
		0xAA879137886B472EULL,
		0x5FA57938E3181643ULL,
		0x135D0E38FA0E87BCULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D4B00638A315C2BULL,
		0x24DFB2AA26FFE1BCULL,
		0x34F09CE3B271F244ULL,
		0x0B9FFF0D59CDA3BDULL,
		0x9620F1EBBCA56A9BULL,
		0x77E73E86E264A6A8ULL,
		0x3D55DCF666B35530ULL,
		0xE696815F14BA90EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C1C1C9AA4975DBULL,
		0xD21620AC093A4D45ULL,
		0x49C65946A7F7A706ULL,
		0xFD4E1D4B379F0207ULL,
		0x02E6C5BF8A5612CDULL,
		0x662ED96C098CE1DBULL,
		0x4E4B90C8749596E4ULL,
		0x9050A039992CD0F9ULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB415425A34DC61AULL,
		0x2B78479FC71873C4ULL,
		0x578BC115CB1D329AULL,
		0x658AA84E25F580A7ULL,
		0x5FCEEEAAAA2B6D1EULL,
		0xDE16706092DB17D7ULL,
		0x2BE552E47A9CC798ULL,
		0x2B7CA25B35B74F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x244469BCA9DC5BB1ULL,
		0x067324ADCC0B8544ULL,
		0x6CC9008F3A2E621AULL,
		0x43C22D7255C3768EULL,
		0x76FEF2215B63E005ULL,
		0x6AD4D52D05064DA1ULL,
		0x6C8164DFFBDF454EULL,
		0x6BBA7BE482D5A4B8ULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82997275FC784D85ULL,
		0x4EA587495AB76EA7ULL,
		0xDB1E2C38BE023372ULL,
		0x062D74672E46599DULL,
		0x7EE1CF1658C3784FULL,
		0xEC4D1EA86659A8C1ULL,
		0xB44B5202E8347611ULL,
		0xAA047D118D34C616ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82997275FC784D85ULL,
		0x4EA587495AB76EA7ULL,
		0xDB1E2C38BE023372ULL,
		0x062D74672E46599DULL,
		0x7EE1CF1658C3784FULL,
		0xEC4D1EA86659A8C1ULL,
		0xB44B5202E8347611ULL,
		0xAA047D118D34C616ULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CF6B140DDAE756DULL,
		0x26B6DF0FFDDDEBC1ULL,
		0xF105C3BFE20B20A9ULL,
		0x700F1950A4DA2938ULL,
		0x79B49C5110EE6F5EULL,
		0x4B15239EAE36E989ULL,
		0xC01457A5EE9BDAACULL,
		0x2A264EC7F0A93DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x684DB06E8E8AEAD4ULL,
		0x8996FD316CF2C159ULL,
		0xB79874CB4C9C8137ULL,
		0x343350397CC7E9B8ULL,
		0x1CAD76645F969F2FULL,
		0x8F7569039351EF50ULL,
		0x0290698D562C6448ULL,
		0x4DCD7FEE3B89AC9CULL
	}};
	t = -1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F394B65439B8E4FULL,
		0x6AEC7D6246C002EDULL,
		0x87E037C1D60A6527ULL,
		0xCD29FD6E2323033BULL,
		0x600C6F588060CDD8ULL,
		0x610CA15FECB6BE59ULL,
		0xD2242C3523A90F81ULL,
		0x872B236D4EACA1B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41FCBD3C12F9973EULL,
		0x357863366275FDC6ULL,
		0x26089ED40D344218ULL,
		0x1911B89DC51F91CDULL,
		0xACBF7EB9F1F71E5EULL,
		0x7CC9C74B0BE88F18ULL,
		0x85EF88BE10E7343BULL,
		0xA80F52063EEF24F6ULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB38CB7B471658BA2ULL,
		0x2EF9CB023E6CC6EBULL,
		0x9AD754F7E900455CULL,
		0x7D375A26CA168AC8ULL,
		0x8C8703D7219CDF1CULL,
		0x97E602DE906395B8ULL,
		0xCD043CE5F67E3B8CULL,
		0x242D066BBA6FE121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4AF5F81EFBBF515ULL,
		0xF31AB4E43C069234ULL,
		0xBE8519C62D225595ULL,
		0x6A2D558CF3D896E9ULL,
		0xD340E5183A706172ULL,
		0x311DE808736BA7A9ULL,
		0xF4ECE915792D1733ULL,
		0x2906FC43122931C7ULL
	}};
	t = -1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BBDDFD32DCB0CC7ULL,
		0xD626535B70A18287ULL,
		0xD21DB5EC39A8B034ULL,
		0xEFDEDAC2E2230DECULL,
		0x8B5685EEA34DA312ULL,
		0xC906D44546A5A624ULL,
		0x58BB5DED29660B61ULL,
		0x3FF0FD468AB29C5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBDDFD32DCB0CC7ULL,
		0xD626535B70A18287ULL,
		0xD21DB5EC39A8B034ULL,
		0xEFDEDAC2E2230DECULL,
		0x8B5685EEA34DA312ULL,
		0xC906D44546A5A624ULL,
		0x58BB5DED29660B61ULL,
		0x3FF0FD468AB29C5CULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82FB58C7699C86DAULL,
		0x8D8D4833A7C698ADULL,
		0x21700B143E18EE5BULL,
		0x085F909224657EB5ULL,
		0x1D19995621A0FB79ULL,
		0x69C2943174C67DE0ULL,
		0xA6CA963DEA12EA9BULL,
		0x421AA2D9D5FC3376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC385B593EAFEF6B2ULL,
		0x438A731A867922E9ULL,
		0x3F55BA17284D0F2CULL,
		0x5506DBF83354A0ADULL,
		0x193FFEFFE1771BD8ULL,
		0x04743FC612B61708ULL,
		0x33390D64A10EE4F3ULL,
		0x2D2ED19320A33712ULL
	}};
	t = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DED03F27FC84356ULL,
		0x8CCE2B99817EC931ULL,
		0x1465F76244962078ULL,
		0x7AE9649879F3416FULL,
		0x741EF3A1464BE475ULL,
		0xCC53F16D3DB630CDULL,
		0x70F631D635109898ULL,
		0xC9E7486A32BBABF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D85605085C48BB5ULL,
		0x9FC76CA50D951BACULL,
		0x4B0F11C2C1A0E953ULL,
		0x2D2DF814B7F16600ULL,
		0x453E0FEBF9442CFFULL,
		0x699A6206160136EAULL,
		0x6873CC732EEDC4BEULL,
		0xA250027227F02BA6ULL
	}};
	t = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE27D243C9D7D8755ULL,
		0xCC89FF4EE5EB1F71ULL,
		0x595BD0EB25E48335ULL,
		0x49879635AFC8B99FULL,
		0xB0B786A5340F8220ULL,
		0xCCE57A99690C216EULL,
		0xCED18DC967863E41ULL,
		0xDD4674F3CFDB3BFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21902CF0CBECBA4ULL,
		0x7BBAFBD9FB758FE6ULL,
		0xDFDE532A0F063943ULL,
		0x0D6D7AF0DE3B4EF8ULL,
		0x2B7D34B51E7FB897ULL,
		0x9F3C3446D7895FF6ULL,
		0x5695F979F5DD3C97ULL,
		0x469F0C64FF57C5F2ULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CE1996FEC9FE76CULL,
		0xC69A6F9A0EBB57B3ULL,
		0x395C298F4985D49FULL,
		0xCB13387F0D9806DBULL,
		0xEAB131C2E5BC0726ULL,
		0x15621F854EBD3C02ULL,
		0xDC0B5894F5AC13AFULL,
		0x441B5D452FA6DDD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE1996FEC9FE76CULL,
		0xC69A6F9A0EBB57B3ULL,
		0x395C298F4985D49FULL,
		0xCB13387F0D9806DBULL,
		0xEAB131C2E5BC0726ULL,
		0x15621F854EBD3C02ULL,
		0xDC0B5894F5AC13AFULL,
		0x441B5D452FA6DDD9ULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7E9E36FCF598CC4ULL,
		0xF9E6D38AC1B7AD7DULL,
		0xEA9CA422F4A136E3ULL,
		0x87748B14FAAA3A1DULL,
		0x2F43F4997155AE65ULL,
		0x1A84FAA671B0E93EULL,
		0x0937A83D684A5EFBULL,
		0x731400147C9A86DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C200370DECD051EULL,
		0x04D6DD9136FC3723ULL,
		0xD1AF2ACB45C8DC1EULL,
		0xC134296ED08D306CULL,
		0x269A086134984B8BULL,
		0x2BF49966CBF8852BULL,
		0xC5EABAD5750FB992ULL,
		0xAF7A0C3DF1A63C4CULL
	}};
	t = -1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E95A353A20597AFULL,
		0x3E62906CE4B1C4B7ULL,
		0xE1A6274656F96094ULL,
		0x9789616447E899C4ULL,
		0x6279BE05723A1E24ULL,
		0xE50F03AD92BD654AULL,
		0x229EE6125223AE2EULL,
		0x5BBF2CF5EAF64AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD70A447B3A59B35ULL,
		0xC6C9ED365DB68B90ULL,
		0x2BF87981339936B1ULL,
		0x4D4DF38BA2BF398FULL,
		0x6969CEF4B15ED7BDULL,
		0x59B3FF78FA379974ULL,
		0x224D359B7E0FA8D8ULL,
		0xCD77E9A5C912825CULL
	}};
	t = -1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D521560DC7B22B1ULL,
		0xBDADB0D41914E82BULL,
		0x8054758487D7D5B4ULL,
		0x6278804B1D82D978ULL,
		0xAE496FCD2CF87FF7ULL,
		0xFCDC410BB8C40119ULL,
		0xA515743DBEB42754ULL,
		0xC25271F2CF481CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCAC899DC1DBEAEDULL,
		0x7D4569012CD15EABULL,
		0x54968E094861C3D3ULL,
		0x3B8A56097E81BA8BULL,
		0xCD72A54F3B86144FULL,
		0x56CB49A6D2DA0780ULL,
		0x87DF2A67A0FEB3BCULL,
		0x39E9D666C18BC007ULL
	}};
	t = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4918C5B0E6ADB0C8ULL,
		0x05284D52D6982285ULL,
		0x89F3072448CA3701ULL,
		0xC2FAFC58E86CA225ULL,
		0xC1426B3D143D3A79ULL,
		0x2B91F3CD07E9E92CULL,
		0xCB7963B3EE34A316ULL,
		0xC3CBD30A1C2582C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4918C5B0E6ADB0C8ULL,
		0x05284D52D6982285ULL,
		0x89F3072448CA3701ULL,
		0xC2FAFC58E86CA225ULL,
		0xC1426B3D143D3A79ULL,
		0x2B91F3CD07E9E92CULL,
		0xCB7963B3EE34A316ULL,
		0xC3CBD30A1C2582C5ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E89F8587278F3EDULL,
		0xE3E5F50D9C476D5EULL,
		0x63FF138B97981055ULL,
		0x6AB09926BC71AF2EULL,
		0x50A41AC9D0F7ADBBULL,
		0x35151C593C67B67EULL,
		0x05D9E1FF6F53A1FEULL,
		0x6F51245F5EDF0936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C79B0538ED2306AULL,
		0x3FBD970948EF4D06ULL,
		0x396A0D2450A9EBDAULL,
		0x0024756F8AB28B1BULL,
		0x7D2AAB21F29FFDB1ULL,
		0x80221E2BB156D772ULL,
		0x6593BDD1D1D500C4ULL,
		0x60B37380A68FCEEAULL
	}};
	t = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71E43A33153B29B1ULL,
		0x7BC329860B213B95ULL,
		0x1D7BDCD66F3DC5B8ULL,
		0xFF234FF6C5DF0056ULL,
		0xBF96A336310EEE3BULL,
		0x2F078D2556EBDB96ULL,
		0x478F97922782F24EULL,
		0x52E38E9786DC378AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A3B9CC1A9C95C66ULL,
		0x094EFC2C16545D05ULL,
		0x0FE977B628564F9EULL,
		0xA4AEDD7FA6B63695ULL,
		0x92625EF930E72E5AULL,
		0xF33FDC75C570EA53ULL,
		0x016B7DD23977A7FEULL,
		0x34CA97EF3C4B0318ULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BDCD60582EA0F98ULL,
		0x499090F2BA8EC226ULL,
		0x4D64866CD2831164ULL,
		0x0898FEEF83C9CF0AULL,
		0x9A5D1C46EAB96030ULL,
		0x14AC44CF491E6AA8ULL,
		0x51205CDD9CB86BC2ULL,
		0x547BD2DE7BD2FD8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827636545DACE740ULL,
		0xD5D2BC978C60567AULL,
		0x7624FB610EFB18FCULL,
		0x9A0AE5A5721E25C5ULL,
		0x4BB53AC3063497F0ULL,
		0xEEBDC7C1DEA4DF6AULL,
		0x61A14E2F8FF3720AULL,
		0x14911B534E576390ULL
	}};
	t = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D3AE05D02C3142EULL,
		0xA977EB8C17C552C1ULL,
		0x57F39BCDB3C03313ULL,
		0x584421A25C900B4BULL,
		0xFFF70960161B2F8BULL,
		0xF131B8E98BE9EBC6ULL,
		0x03497A0F2389CA72ULL,
		0x92A49309BEC42440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D3AE05D02C3142EULL,
		0xA977EB8C17C552C1ULL,
		0x57F39BCDB3C03313ULL,
		0x584421A25C900B4BULL,
		0xFFF70960161B2F8BULL,
		0xF131B8E98BE9EBC6ULL,
		0x03497A0F2389CA72ULL,
		0x92A49309BEC42440ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38271D228EADC63EULL,
		0x0B79070F23392BC2ULL,
		0x905826C434463235ULL,
		0x780D5657536A7D5EULL,
		0x17DFA71AB5142EF5ULL,
		0x6202D9617E1DE34AULL,
		0x4245602BF50AEDB8ULL,
		0x64D7C049E5CA9F2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF462ACD2AF37C6ULL,
		0x0804BBF8225FAA03ULL,
		0x510923D8F0DA6F4BULL,
		0x72303DCB64CC43C2ULL,
		0x3F24A8F8C617C542ULL,
		0x80A0588C866B2D3DULL,
		0x766D55CBBC048FF7ULL,
		0xF9B6839B392E87A2ULL
	}};
	t = -1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB45C98C86BBA73AULL,
		0x064ECF81DA731B79ULL,
		0xFE692E0487E9A6DCULL,
		0x6CE7361DE51166BEULL,
		0xC9DF24FA5E41B44BULL,
		0x90271029DCBED649ULL,
		0x87898C5A0A1706BEULL,
		0xFC08D0DFA7CD3C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E940136C982C722ULL,
		0x16DFBF0B427BD251ULL,
		0xABEA1A41ABBC67E2ULL,
		0x8346E29964217ECEULL,
		0x01744486E2407E19ULL,
		0x37A716183B302C95ULL,
		0x2C1379152710C3D0ULL,
		0x0171D2BCF3F1C0E3ULL
	}};
	t = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6767231FB553CA9BULL,
		0xC7757EE782440655ULL,
		0xF76C3AF67FB7A600ULL,
		0xFA8CD6ED22999869ULL,
		0x8A561A9ECFFCA397ULL,
		0xCB3B44852EE26814ULL,
		0x2EA9EAC268DE839EULL,
		0x6BDBD145D9F70666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x038DFB5F7D335236ULL,
		0x18D60903B4CD0DC8ULL,
		0x6AD0BC720391CFADULL,
		0x9E56F25C43FA06F5ULL,
		0x23F01C53A9874203ULL,
		0x7D376561EEBE9D94ULL,
		0x1282FFF4A355171CULL,
		0x71EB6C253C8C9F55ULL
	}};
	t = -1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x717CC505328A5B1CULL,
		0xFD0D8848075DA8C4ULL,
		0xF7D4B60673B435DFULL,
		0x86CA47F9D4F18EFAULL,
		0x4810DBB1C1957F05ULL,
		0xBA225F9B3B65429BULL,
		0x8FECF4E6489728D7ULL,
		0x93F8FC3DC9E83FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x717CC505328A5B1CULL,
		0xFD0D8848075DA8C4ULL,
		0xF7D4B60673B435DFULL,
		0x86CA47F9D4F18EFAULL,
		0x4810DBB1C1957F05ULL,
		0xBA225F9B3B65429BULL,
		0x8FECF4E6489728D7ULL,
		0x93F8FC3DC9E83FFEULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23C26E82381D9785ULL,
		0x70517DE362589CD9ULL,
		0xD14D23431C2B6496ULL,
		0x1D2CADD9D65DC13BULL,
		0x47EB71501DF3C0DAULL,
		0xFF68B5831D6932C2ULL,
		0x0C42018300D4D032ULL,
		0x6A52F36754D620DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CA94DF9D0F6C190ULL,
		0x447D4619AD360387ULL,
		0xC0BC64CF4EDFAEA4ULL,
		0x27FB9FDC8076E539ULL,
		0x7D481FD03334E2A5ULL,
		0xB6FC21E0859819F5ULL,
		0xE80BBD03E84F612CULL,
		0xD01B3465244B613BULL
	}};
	t = -1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F1D81A0697094FCULL,
		0xC1E29FF9EE648E70ULL,
		0xBC4EE61A92BDE676ULL,
		0x75A0817D6F898711ULL,
		0x51F010BC02418FA7ULL,
		0x839D37B1C44DC8EFULL,
		0x1F6D4E9BFE2980F9ULL,
		0xB0D122AC5820CAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAD2E97726997958ULL,
		0xAFA4740514020F9EULL,
		0x2ED813B2325266B5ULL,
		0x18CEDF452B1E8C18ULL,
		0x92BFAD3DDB0DA899ULL,
		0xECDF8A83EE2082FCULL,
		0xCAC284671F0C413FULL,
		0x8C675C1BEE3ECD18ULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6E36E67A58131BBULL,
		0x5D9C263ED261B337ULL,
		0x95E981B1DBE8D825ULL,
		0xF0F31DA3894C782CULL,
		0x6CF5D62BAEC82E59ULL,
		0x56BDE98C139C22E0ULL,
		0x44C89D958E1715A6ULL,
		0xD3C837E8CE9499E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14A0ACB4808F14CULL,
		0x434DEA3DA2B9FA8FULL,
		0xD86EDE627E97D884ULL,
		0x64AC422D7336F955ULL,
		0x41C5D64996AEBF9CULL,
		0x7DBE346CC6D20B1BULL,
		0x39D681B38AF83819ULL,
		0x6D5EC214E43368E0ULL
	}};
	t = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC1B41B8FD291AC5ULL,
		0xE8B61CEEEC98D6BBULL,
		0x484C6251DED3C288ULL,
		0x26B19250F735997FULL,
		0x7384B771663C3054ULL,
		0xDC6C5B5AE1F4BB13ULL,
		0x3A8D21404082A916ULL,
		0x344F3FEA9CC7E633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC1B41B8FD291AC5ULL,
		0xE8B61CEEEC98D6BBULL,
		0x484C6251DED3C288ULL,
		0x26B19250F735997FULL,
		0x7384B771663C3054ULL,
		0xDC6C5B5AE1F4BB13ULL,
		0x3A8D21404082A916ULL,
		0x344F3FEA9CC7E633ULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x004F75817ACBC8DBULL,
		0xA0C041FB05402413ULL,
		0xD2FF536687B77CD1ULL,
		0x64649BF497CC55B4ULL,
		0x19EB19123A70CF5AULL,
		0x0840EB93AFB30D65ULL,
		0x58BEF11D9FAC0C7AULL,
		0x184FD0334D367E01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68109FDB9C8C487ULL,
		0x35C34095810A3603ULL,
		0xE1D3E4BB72CAD7DCULL,
		0x04DF3A40E4F13611ULL,
		0x064011865D2E7923ULL,
		0x3F4AA3FC2CC31404ULL,
		0xF94F6FAD1AED0C55ULL,
		0x1F767CE221055F30ULL
	}};
	t = -1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1486B053AD4251D0ULL,
		0xA3E5CF6BE4051B4BULL,
		0x1F042CB2DFE739B6ULL,
		0xC764A8E399113058ULL,
		0xCCD162CE434031AFULL,
		0xC036F3EEA74C30E4ULL,
		0x50C1A7783786E71DULL,
		0x829FBCC227F7860CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D2AEEA1DFD6086ULL,
		0xB6E234E4AF3BCA02ULL,
		0xF8106E894622D163ULL,
		0x796C7E43F7B0E5F0ULL,
		0xDC6F55C6EF196844ULL,
		0xDF63F1237499D176ULL,
		0xE15FEE6368383996ULL,
		0xDC47B914A07C1B62ULL
	}};
	t = -1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF4A0BF9C401B479ULL,
		0x5930C749CC4C895EULL,
		0x6743E96355F60B1AULL,
		0x36E38C30CF4B1A4DULL,
		0x7009A20AB5961DD0ULL,
		0x1E1035D77E1F3C06ULL,
		0x41BA992A516DFA6CULL,
		0xDE8C184C2C576FBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F62DD067F8E9C6AULL,
		0x3952ECCB80CA5659ULL,
		0x9AB23B9918877244ULL,
		0x14CC1A900257B8FBULL,
		0xFE6791AAE6E367FFULL,
		0xE81F0A7B0CC22F03ULL,
		0xC20F550ABDAA3554ULL,
		0x2332ECDB49B62F5DULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE3441A668A9F0B3ULL,
		0x2C53FED56677DA57ULL,
		0xC68616F08773D044ULL,
		0x97CE98B186CD3391ULL,
		0x0CDAE83B8F282D87ULL,
		0xA4362818F0D2F5D5ULL,
		0x79C5E21507E21D0BULL,
		0x339F12876DCFD84DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE3441A668A9F0B3ULL,
		0x2C53FED56677DA57ULL,
		0xC68616F08773D044ULL,
		0x97CE98B186CD3391ULL,
		0x0CDAE83B8F282D87ULL,
		0xA4362818F0D2F5D5ULL,
		0x79C5E21507E21D0BULL,
		0x339F12876DCFD84DULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9DB789848A6956ULL,
		0x67A7A8FFB864BC61ULL,
		0x32E4DFFE5570386BULL,
		0x8DC0CBBF8122EB98ULL,
		0x16EF42AB15E29D52ULL,
		0x6D42524F3E894BF3ULL,
		0x4190158317C60D26ULL,
		0xFCD7C318CE5FBAB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB1ACCE7E78B725ULL,
		0xDC2A60A87AE8F791ULL,
		0x65995A671FD2BA60ULL,
		0xE028AEB798962F43ULL,
		0x4B796DB3A83F30CFULL,
		0x2FC7617839BA73EFULL,
		0x9FDF92EF77F03B3DULL,
		0x0C5C3E4C7459E066ULL
	}};
	t = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1F5489D7A9B5475ULL,
		0xBB1A9EF6C097552CULL,
		0xE4BE7E10C25A2736ULL,
		0x8A1A1C656F3EEEFAULL,
		0x04D3D4F7F2145B99ULL,
		0x89AC5DA45902531CULL,
		0xFEB945A544D902A4ULL,
		0xFD541F281117FC53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FFA1A424DE69FC4ULL,
		0xCC431A3E06CE55FFULL,
		0x02596CF29ACBA3EAULL,
		0x434C289F3976AD99ULL,
		0x94569F1902077F17ULL,
		0xAA457DD353D57DEDULL,
		0x98384FA812CEE57EULL,
		0x38C3FD1A4CD1944DULL
	}};
	t = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39B165C6C3DFCFEAULL,
		0xE955807A687FB93DULL,
		0x6A631084DD3FFEBFULL,
		0xCFF6693D8729BA45ULL,
		0xF80CA75A40EC9F4CULL,
		0xD9B206E2A3182948ULL,
		0x4DCC3D1E53F7D37EULL,
		0x54A7AA18317F7F34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F88B6B06F10B39ULL,
		0x8B0153D2A9AE75ACULL,
		0x5F7355BC14B05CECULL,
		0x293C3C11521155DAULL,
		0x859258080CB031C1ULL,
		0x5C677E3214066E3BULL,
		0x549FD1EF1604A2F5ULL,
		0xDBAE33AC0C01AD5EULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB44101F2F3BC4AA0ULL,
		0x8E689F766F25835AULL,
		0x71C913E30DF1E39BULL,
		0x82FD93DB4B54AB3CULL,
		0x30AE733C53BBF751ULL,
		0x7265A764BE50D96DULL,
		0xC706A1F5A1231D13ULL,
		0xF0794A9F22887B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44101F2F3BC4AA0ULL,
		0x8E689F766F25835AULL,
		0x71C913E30DF1E39BULL,
		0x82FD93DB4B54AB3CULL,
		0x30AE733C53BBF751ULL,
		0x7265A764BE50D96DULL,
		0xC706A1F5A1231D13ULL,
		0xF0794A9F22887B89ULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A6A567CC7D711A4ULL,
		0x2410F07C5AF39870ULL,
		0xA60CC79BC9610E5CULL,
		0x5355BF91D6AEB10AULL,
		0x57CEC2F5D8FEAAF0ULL,
		0x1A1164AA8AAF8C40ULL,
		0xB8346197669D9747ULL,
		0x1563B1529EC43884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4670778306EC641FULL,
		0xB20C9981772492DEULL,
		0x724C0D8FB47AF64DULL,
		0x88198FD152A6B86AULL,
		0xDC7E0115C38AE78FULL,
		0x141B42D3CBE17DDBULL,
		0xE7EAD3F4CE8B7B4EULL,
		0xCC5E7BCC987ED17AULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E7DF0560B932FDULL,
		0x1A4534A4A3983155ULL,
		0xC6061D19C7306B88ULL,
		0xDA5D810198DA9819ULL,
		0xF50FCDD2D56F15D1ULL,
		0x43EFBC5FBF27A7D5ULL,
		0x76F0B8B8B6819825ULL,
		0xADD29A520AFA68C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x851CE7A5F6853355ULL,
		0x9CE99218D686ABCCULL,
		0x09B72AB30EE5FEBDULL,
		0x6FBCE74543934916ULL,
		0x9FB46F7D51BA8073ULL,
		0xA09469140D2C9053ULL,
		0x10CF257DAB5770A5ULL,
		0x33839342F8A29DB4ULL
	}};
	t = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55499F1AF7039624ULL,
		0xDCC300AEE619C1A0ULL,
		0xB9EF9887E422F0B6ULL,
		0xECE89993AD766473ULL,
		0xEA3EB644C3BFB3E0ULL,
		0x89D5E960B15D5251ULL,
		0xB398071826B9B977ULL,
		0x5573906B30015F3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C0DB2E2410BB3FULL,
		0x7C23F5C841AE4D32ULL,
		0x989FA5B73EC4DF94ULL,
		0xC6F018060B163259ULL,
		0x0ED39DDBB848D47DULL,
		0x06AE1DECB07AFC34ULL,
		0x6517AE1354D6F597ULL,
		0x0776B2E1306F366CULL
	}};
	t = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0C2659807C4300AULL,
		0xDCD8C91F6FD8E43AULL,
		0x12696D3A38E18833ULL,
		0xCAF337B982A41368ULL,
		0xDC1C040E14685B64ULL,
		0xA1E9B30EFBB190E1ULL,
		0x5EEB0D57F437D6BDULL,
		0x0CA108567613C6B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0C2659807C4300AULL,
		0xDCD8C91F6FD8E43AULL,
		0x12696D3A38E18833ULL,
		0xCAF337B982A41368ULL,
		0xDC1C040E14685B64ULL,
		0xA1E9B30EFBB190E1ULL,
		0x5EEB0D57F437D6BDULL,
		0x0CA108567613C6B3ULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8E33302368E015AULL,
		0x6F7305F1C1C7D8DFULL,
		0xAEC77F80C89268C0ULL,
		0xE680C5A31CCC0329ULL,
		0x29E870DC2887A78FULL,
		0x87DCFE5907612A69ULL,
		0x42889C03F3FB5915ULL,
		0xED8E1BF203A85C5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F8D30476336EC28ULL,
		0x40ECC3DC7E855C55ULL,
		0x9E28A0BB33BBF01DULL,
		0xEC38EE3200B3F690ULL,
		0x26D883411880350BULL,
		0x79471A5346D7BBE9ULL,
		0x80E44E5DED843BB1ULL,
		0x44F7DAD10AC9A217ULL
	}};
	t = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CA2A1BF2B83B586ULL,
		0x610AA09900A4D614ULL,
		0x8491952C9F3F8DB1ULL,
		0x03B83F535AD908F4ULL,
		0xA33243660A32EB74ULL,
		0xBACC148754144B34ULL,
		0xE810350C881EF35FULL,
		0x0218B06B8102C1BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1646D50461B4641ULL,
		0x323656F7564341BCULL,
		0xE1A3BE08365FC254ULL,
		0x53F9C8435BABD716ULL,
		0xFEC12638BF158429ULL,
		0xDF5D01AE63FE700DULL,
		0xA429FEFD27FED827ULL,
		0xAED4A3B51E5CC7A5ULL
	}};
	t = -1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE9CDC0D7C5E4B01ULL,
		0xF1314779670A569EULL,
		0xE877D464DA7D2366ULL,
		0xF12B23C52F564C08ULL,
		0x25DD4092CE1F8185ULL,
		0x56C23C728AE609A8ULL,
		0x1AAD452939819766ULL,
		0xB8E6F28C5983C78DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6323BD3AE1F48E8ULL,
		0x0408794BC3E04B1CULL,
		0xE0FAE881EBCFD8D8ULL,
		0xDDC4BA0717B32D42ULL,
		0x5AA28BE7A94F472EULL,
		0x758C5C68707948DAULL,
		0x4C12303A5F6F6D2DULL,
		0x671CBF8A9E49597BULL
	}};
	t = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x749971F4939E918DULL,
		0x9FC343D363A99492ULL,
		0x860B7DC36345640FULL,
		0x484A4312E0CCFCF8ULL,
		0xF3266EC64C519ADDULL,
		0x00819E8ED5043CB3ULL,
		0xC17A1D08E224DE43ULL,
		0xE4FE970C54EC7AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x749971F4939E918DULL,
		0x9FC343D363A99492ULL,
		0x860B7DC36345640FULL,
		0x484A4312E0CCFCF8ULL,
		0xF3266EC64C519ADDULL,
		0x00819E8ED5043CB3ULL,
		0xC17A1D08E224DE43ULL,
		0xE4FE970C54EC7AD7ULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F1FC44716579B7BULL,
		0x07B7443E31A67BF8ULL,
		0xBA85C9C990060D44ULL,
		0x3707EDF865C73D9CULL,
		0x3BE77D16FEDA33EFULL,
		0x7E102A18A6E37888ULL,
		0x9F1FE6C619258051ULL,
		0xBFB420715DADD677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35F85572D0D52B4ULL,
		0x33C7F729E0A19E8EULL,
		0x42938939820637EEULL,
		0x002D821DA70EF7ABULL,
		0x2A2D07CEE97F20E1ULL,
		0x4BD02590C53713CCULL,
		0x2077DCD63E18B3B6ULL,
		0x47E91B3CC45D0623ULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA054AB460A7C1EF0ULL,
		0x1F376430CD7AFA0AULL,
		0xAF5B855F572E9281ULL,
		0x7C55D84FFC5339B1ULL,
		0x07D69A28C46E27AEULL,
		0xB8836618B71A3AB5ULL,
		0x8D9F23EA750D0A6AULL,
		0x9680D89DE53C0D5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44EF1D5ACF8B317AULL,
		0xDDB3E7F8A33E145DULL,
		0x72D0845BEAE3C00AULL,
		0xFE5F60CED120DECEULL,
		0x731ECBD1889A02BDULL,
		0xC804AEF6F3C4C39AULL,
		0xADC56BB32DFCDA83ULL,
		0x87A3E16D64919527ULL
	}};
	t = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D8C2D0D471CBD9DULL,
		0x86C29A04CB049043ULL,
		0x0BAFBEEFAEA84770ULL,
		0x01EDDB9FC892942BULL,
		0xB1F40BAC803EBFD5ULL,
		0xF93AA2DD40E3FC08ULL,
		0x427637FFEC46BA75ULL,
		0xC15A11405E67569AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0762452D521D83FULL,
		0xD27FCAE6798320C4ULL,
		0x26975AAC78484F2CULL,
		0x6F129781882D7D29ULL,
		0x7A6F70B8E905EAE0ULL,
		0x3C094437D31E45B0ULL,
		0xE843D3036FF62A6EULL,
		0xB1CA14C5986D4230ULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB55813837D4B4DBAULL,
		0xA9EDE8498D9467D1ULL,
		0x7022561F7CD11A75ULL,
		0x12CAE92246404F08ULL,
		0xCACA570AA8577A90ULL,
		0x55E7A293954AC46FULL,
		0x2B4812617173A9B2ULL,
		0x227760778C47114AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB55813837D4B4DBAULL,
		0xA9EDE8498D9467D1ULL,
		0x7022561F7CD11A75ULL,
		0x12CAE92246404F08ULL,
		0xCACA570AA8577A90ULL,
		0x55E7A293954AC46FULL,
		0x2B4812617173A9B2ULL,
		0x227760778C47114AULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB843609CE7B3FEE6ULL,
		0xBA1DADD6A1A51C37ULL,
		0xFE50D236A6987496ULL,
		0x5EAD47A8E92DB7A2ULL,
		0xFF37E31529636692ULL,
		0xF4A0BD6E04FE6115ULL,
		0x05055DC1A3709609ULL,
		0xFB8227B1A027972BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3484C89C1B7395CULL,
		0xCEAC07C22CAE2C8FULL,
		0x1FC6DDD35AB82EDEULL,
		0x22A2AA14E2EA62DDULL,
		0x86C5545FB8AF7C36ULL,
		0x6551FAC69C32C280ULL,
		0x9C83D46A5B1E53A2ULL,
		0x25A3E24590A1E523ULL
	}};
	t = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10D790A8D19DD7FFULL,
		0x109F28844D22C2E6ULL,
		0xB67ADE8555ADCBC7ULL,
		0xB70E24327B0C84B3ULL,
		0x72BB7C126C628406ULL,
		0x7DA80DEDBDD91A0DULL,
		0x2ACD455C6A586020ULL,
		0x4C2AE1B916C51F78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50097CC09CD85E61ULL,
		0xE6A0B97D9CC0270EULL,
		0x4CAAB9C121D03FFBULL,
		0xEEA9CC9B3AE1D635ULL,
		0x571CECE9EE43E162ULL,
		0x75097FADEC074ED7ULL,
		0x82751B04AB437774ULL,
		0x12287FF8153EDF3AULL
	}};
	t = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DEC5A6761FBB6E6ULL,
		0xB79BD3C4DAF73136ULL,
		0x4CD0CE0E090977B3ULL,
		0x4BE3008D44D8FB26ULL,
		0x41950568701DC571ULL,
		0x3D01C85D99ACB5A8ULL,
		0x38D5ABA04CF9D3BAULL,
		0xD874974ADFA8885EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DDEE332E1D8CF17ULL,
		0xBB4BFEF718E2E083ULL,
		0x732366E108C00A03ULL,
		0x216AE233CD0D1855ULL,
		0xAC5F4ECB0FB6DCD5ULL,
		0x585D5EEE8BD3A75FULL,
		0x25EDA2D5E69EB7A1ULL,
		0x24F1CBB3A1CE0793ULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE52478201E304D9AULL,
		0xC47DC6FA658A8BF5ULL,
		0x4BB6A5A3D14C91B0ULL,
		0x581D45FDA174B622ULL,
		0x5ED98AFF52EFBFE7ULL,
		0x287B010BAADC3CA7ULL,
		0x17FBAA68708C4A55ULL,
		0x8F6AC777468724DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52478201E304D9AULL,
		0xC47DC6FA658A8BF5ULL,
		0x4BB6A5A3D14C91B0ULL,
		0x581D45FDA174B622ULL,
		0x5ED98AFF52EFBFE7ULL,
		0x287B010BAADC3CA7ULL,
		0x17FBAA68708C4A55ULL,
		0x8F6AC777468724DAULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABD4D4DD94E085CBULL,
		0x929DD64BB583B1BEULL,
		0x516555775E0F8059ULL,
		0xDF8B0DC87A263B6AULL,
		0x37A3A084927B99A8ULL,
		0x0129C096320C7EDDULL,
		0x6C00AECB0C02D318ULL,
		0xFB294D03B76CDAC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03683343A84DAAEEULL,
		0x0816634DC7A198CDULL,
		0x5393EAE57AEA89CDULL,
		0x29F48641F1C33E1CULL,
		0x423C8DA7B0F6DBBAULL,
		0xC882FFF2616DFC6CULL,
		0x192FD5E290006ED3ULL,
		0xCE88A94066BBA827ULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5F857125F8D32FFULL,
		0x4942FDEFDF492A40ULL,
		0xF626BFE98DB3A230ULL,
		0xC7448740B66F9B09ULL,
		0x0A66541A1A2FE689ULL,
		0x815F4B628500D4CCULL,
		0x9BBF752310837EA2ULL,
		0x1C99C9C5F23CC440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2927071234CCF704ULL,
		0x513061C3961C250FULL,
		0xF0CB5BD857C09DB1ULL,
		0x98DE983B55B9233EULL,
		0x1447EE3D35AF668EULL,
		0xCFB99507E2AD5860ULL,
		0x6961AA5AB30DB9DFULL,
		0x6DADAEFA7CECE7D6ULL
	}};
	t = -1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ADEE9F68C82FDF9ULL,
		0xCD73E78E0C16C7BBULL,
		0x7F47E2214D6142D1ULL,
		0xE473CDF8DE1E5706ULL,
		0x0B76005A955B5697ULL,
		0x83344B8ECF13F558ULL,
		0x0ED33B78F298F2EFULL,
		0xCFA8B11C212FC79DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6C9F1E950CD1FEULL,
		0xB043254AC8A1DCAFULL,
		0x1EC0CEFC5AEA7A48ULL,
		0x3292B61FCA064414ULL,
		0x98848AAC6174AC31ULL,
		0x4CA8D4290CD6956DULL,
		0x93809F6B0E88CF89ULL,
		0x267363DCCADCE284ULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B5A92DBB4D16847ULL,
		0xBE0CB9B02123E4ECULL,
		0x9279492A47E7D7E7ULL,
		0xFB0C5914972D9500ULL,
		0xCCE073A3AF4F0EBBULL,
		0x93FB899374FB0715ULL,
		0xDFD865E939B938CDULL,
		0xA54137E78A9FCEF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B5A92DBB4D16847ULL,
		0xBE0CB9B02123E4ECULL,
		0x9279492A47E7D7E7ULL,
		0xFB0C5914972D9500ULL,
		0xCCE073A3AF4F0EBBULL,
		0x93FB899374FB0715ULL,
		0xDFD865E939B938CDULL,
		0xA54137E78A9FCEF9ULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D4CE01370FEF9BAULL,
		0xDED1180C55CDE45FULL,
		0x4A2C50CDA5632502ULL,
		0xF55E2444DB4B4C13ULL,
		0x8321A0A03E1A3251ULL,
		0x8784238955B6EA36ULL,
		0x52472318CFBD27D4ULL,
		0xF5FD1329C27112B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF89CA7CD8196B1ULL,
		0x1ECC978F1A1D406EULL,
		0xF0C19F90E8B460A3ULL,
		0xC19FB72D20D336AAULL,
		0x1C4ACBD8BDB1798FULL,
		0x0B0243B0395AD37CULL,
		0xD1629CB96ADA2553ULL,
		0x4C36F4D3E5969FD0ULL
	}};
	t = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77C6B1F2F72488E8ULL,
		0x8CB232361CA33B02ULL,
		0x90D0F3C6CAC8EE41ULL,
		0x1CF6C8CBCF0F9B34ULL,
		0x606AFF868524FC3BULL,
		0x6B2072869432AEE8ULL,
		0x24FF7B7B85AC2008ULL,
		0x80E34C4ED1125408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D489C3C4C5B63A7ULL,
		0xB70ED3FD5FE848E2ULL,
		0xAD82A3CCA1BC2254ULL,
		0x357970633AA852D2ULL,
		0x99F0B3E92369F11FULL,
		0x8FE630ED7930A1A6ULL,
		0x9E09B33FC7E43C5AULL,
		0x01752ECFC219D724ULL
	}};
	t = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE974AA96B72925DULL,
		0x1369750BDF623037ULL,
		0x5D792E835C5B991EULL,
		0x0187F0FE5DF3B84AULL,
		0x9DE0D956BA122E73ULL,
		0xDD77496B520D3443ULL,
		0x0A61279035529B22ULL,
		0x195B5C147544C266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32F05190B5602409ULL,
		0xDEF618BD8F7B3757ULL,
		0x03E30F057C411837ULL,
		0xF46381B2EA2328DCULL,
		0x0B6A8D428100E2E0ULL,
		0x3D2E9E08C2318FA3ULL,
		0x87C081A3F71D763AULL,
		0x6B95DDE7738EBD18ULL
	}};
	t = -1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76D3E236ECB746FBULL,
		0xC5AFA5E426940973ULL,
		0xE31C4226D7878020ULL,
		0xD1721C7C24343684ULL,
		0x5F5DCC23669B263DULL,
		0x8264E86227C656D3ULL,
		0xE59EDE0A88ED244AULL,
		0xE40210E163E1C122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76D3E236ECB746FBULL,
		0xC5AFA5E426940973ULL,
		0xE31C4226D7878020ULL,
		0xD1721C7C24343684ULL,
		0x5F5DCC23669B263DULL,
		0x8264E86227C656D3ULL,
		0xE59EDE0A88ED244AULL,
		0xE40210E163E1C122ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE438BAA534FE0E1ULL,
		0x79110CA8EB304554ULL,
		0xEE0A25074647896CULL,
		0x563430CD4A6BDABBULL,
		0x46AB6716AE05F15AULL,
		0x8D46227250B8F577ULL,
		0x76F2E46B08077AB0ULL,
		0x9A360F7522302A06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ED47C6DC723368FULL,
		0x022BE74B40454316ULL,
		0xE232A7A5E047EF4EULL,
		0x36578D28165CF7CFULL,
		0xEDBD0E678BB01853ULL,
		0xCF1C648ED9B7987BULL,
		0x3976B6A07EDA6657ULL,
		0xBCF94001DDB4D0B2ULL
	}};
	t = -1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8C3B48273D3E432ULL,
		0x697773A5D1FF651AULL,
		0x74D9913FA4AF3D5AULL,
		0x65F0E40334903AE8ULL,
		0x0798BCD7188AC25FULL,
		0xBC2040259FC17468ULL,
		0xB9DE513B7537A9F1ULL,
		0xF5FD09F400742F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4AA5D1BC942CC80ULL,
		0x6E89ECEA0C375121ULL,
		0x1B284BAAF36EA2EBULL,
		0x340DB87086A233BCULL,
		0x4B7CC0CBF41509FBULL,
		0x2040E436869E2A34ULL,
		0x4D86348FCC2D8B8EULL,
		0x53D9C5E3C2449488ULL
	}};
	t = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x209049AC3BD35ED9ULL,
		0x7582A7BE347D6B3BULL,
		0xCCE5543B0E3B9CC3ULL,
		0x6C3E88BCDB00D60BULL,
		0x16C8487A22AF0726ULL,
		0x5907F41A96895181ULL,
		0x1D8670E810426793ULL,
		0x72572052ED91DBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA8F0CE3B55E6AB4ULL,
		0xCFCD0FAFC3C4C9C5ULL,
		0x42F9D15DDC3C2971ULL,
		0x3141D3EB32328C81ULL,
		0xD4A305C110CDA5CEULL,
		0x1B4FBF5FD3E28034ULL,
		0xBED46E502F91DD4FULL,
		0x92961033E228D9BEULL
	}};
	t = -1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7166067E2DF53B7ULL,
		0xA519E9755DD2CF0BULL,
		0x54C80DA467823DCDULL,
		0xF5D080DFA37CB1F6ULL,
		0xEBA135A7E354AE0BULL,
		0x33079D2EF93D1382ULL,
		0xE3B14048DAFAAFFDULL,
		0x6AB4013AE3E71B47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7166067E2DF53B7ULL,
		0xA519E9755DD2CF0BULL,
		0x54C80DA467823DCDULL,
		0xF5D080DFA37CB1F6ULL,
		0xEBA135A7E354AE0BULL,
		0x33079D2EF93D1382ULL,
		0xE3B14048DAFAAFFDULL,
		0x6AB4013AE3E71B47ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7508946DB2C8EFDAULL,
		0x24611B07DACC8DC8ULL,
		0x2A0994D55C97E7E1ULL,
		0x011FA92249C9C7E3ULL,
		0x303435FA6FD53BE5ULL,
		0x2D995145338054EDULL,
		0x35868556D416FD75ULL,
		0xE55EDA8AFD3036A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1866604BA955C7ULL,
		0x8D2C40DF6FCD9B3BULL,
		0x19F7063E906F6C71ULL,
		0xF8B9E746D9CFAA29ULL,
		0x7366E29107EE91F9ULL,
		0x4168DF02073101A4ULL,
		0x00A3A0C88D9E37F4ULL,
		0x4B0A6F647E811F6AULL
	}};
	t = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D70CE375A73E918ULL,
		0xBB52A2C5D1BE02FEULL,
		0x3AB15D80CFB41356ULL,
		0xC1FAAAFB39577121ULL,
		0xBBE453F357030216ULL,
		0x10E91133815D563AULL,
		0xE137FE4CD66A5B55ULL,
		0xA9252BDB5E3788B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7709667DB77BD328ULL,
		0xA65222280F3ABC1FULL,
		0xDC5C8410C5136623ULL,
		0x43802CAADE94591EULL,
		0xC3E4D8B506A29CB4ULL,
		0x361503DE21A72B03ULL,
		0x8CC25C5E27061821ULL,
		0xA8E2EABEDBD927F7ULL
	}};
	t = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2F423147CB75FD0ULL,
		0x42499ECF3D9BDE51ULL,
		0xD96062B0E4A3CB71ULL,
		0x94C7329027DA3DA2ULL,
		0xE1A8B9760C9B9CC0ULL,
		0x0D6C67B8B56740E6ULL,
		0xF62E0DCEAE9DBD02ULL,
		0x79843AEB15EC300EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15C211BC9ACF7DFULL,
		0x8969C42C1B45A72BULL,
		0xED5BAD606EE9C827ULL,
		0xE6B662D0B104EA47ULL,
		0xE8700FC93A4F49C0ULL,
		0xAA5F90E3FA065F5FULL,
		0x3A6842950B5D6A1FULL,
		0x69E88D7F7C3E897BULL
	}};
	t = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36A7A08C04E7ABE1ULL,
		0x5FEEA76D94936C7DULL,
		0x3746152BE02198C8ULL,
		0x1A8B825142AAAAE3ULL,
		0x6264071D5027514CULL,
		0x1B077654C06EE105ULL,
		0x5BD9FAB82D1DB00FULL,
		0xFE9FAE9EDF431871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36A7A08C04E7ABE1ULL,
		0x5FEEA76D94936C7DULL,
		0x3746152BE02198C8ULL,
		0x1A8B825142AAAAE3ULL,
		0x6264071D5027514CULL,
		0x1B077654C06EE105ULL,
		0x5BD9FAB82D1DB00FULL,
		0xFE9FAE9EDF431871ULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CC56B75A19E9477ULL,
		0x611E35F0232090CAULL,
		0xD5D6A5AAE7DAD2D5ULL,
		0x54EA584C1F24C726ULL,
		0x2D97FA26C3D27F8AULL,
		0xB61367426D147373ULL,
		0x1866008DBE293B9EULL,
		0x8F6AD7E3D452C6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB3D4318BAF47E0ULL,
		0xA49711A31BC779A2ULL,
		0x0708D79FE0734D60ULL,
		0x35B89951B13756F4ULL,
		0x2D12FF2D534F11A4ULL,
		0x66C9E8DEDAB88B5EULL,
		0x02D69602A76105FBULL,
		0x9F9903418A89BB1DULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3FE443022E0ABB7ULL,
		0xFACDE1D07A8C9A9CULL,
		0x7B1E95E52890D350ULL,
		0xDC43ACEDC465C956ULL,
		0xF279C67726878EFDULL,
		0xB832331A93C31FF4ULL,
		0xC4B91577BEDCBBF3ULL,
		0xD2BE71291FD251DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A95D0283C67031EULL,
		0x11EEA5204CFF0D20ULL,
		0xEC9EB31B6A910EF9ULL,
		0xA2DA52BA74A9950CULL,
		0x47A488C5FABDC1C3ULL,
		0xE4B05993E67BB5A2ULL,
		0x4129965C5D53657EULL,
		0xBD5DFA0C8408BDE5ULL
	}};
	t = 1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x491A59A69C07F4CFULL,
		0xCF531EB24D9AE6A2ULL,
		0x503E952B2AE97CC5ULL,
		0x9931ADB940243317ULL,
		0xF84DF33EE3E6A9D7ULL,
		0xD4DA3934DC5917D4ULL,
		0x6F8F5E9E888D4985ULL,
		0xEA26E14B8C69BDAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B68DF88EFE6D16ULL,
		0x19F0B5AC6DBCF032ULL,
		0xC861B31E009A6929ULL,
		0xEE1AC0512E8F2CC1ULL,
		0xE50471FC4EC53249ULL,
		0xDC42FEE05C17C897ULL,
		0x3AF2948A9D5125A8ULL,
		0x3822628976EE54E8ULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F26EDC26D56E476ULL,
		0x64E534301086F2C3ULL,
		0xA536E3B4AE6C4623ULL,
		0xA0B5F35C52B437E5ULL,
		0xD29484509A1A7C3AULL,
		0xD05BC818CBB7EBA2ULL,
		0x482DF9A4B226D8E4ULL,
		0xAD2237AC9DC4018DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F26EDC26D56E476ULL,
		0x64E534301086F2C3ULL,
		0xA536E3B4AE6C4623ULL,
		0xA0B5F35C52B437E5ULL,
		0xD29484509A1A7C3AULL,
		0xD05BC818CBB7EBA2ULL,
		0x482DF9A4B226D8E4ULL,
		0xAD2237AC9DC4018DULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x326AB18210A42C0CULL,
		0x1BF3CF03FB9123E6ULL,
		0x484969FCFB1B3CEDULL,
		0x9281EB51BA8FE9ACULL,
		0x4284B00EC21AB077ULL,
		0xAAE2D98E8A75AA71ULL,
		0xCB88DC0B51E3C8E6ULL,
		0x15A9BC2BA8FF4AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE87A9A2AF44D066DULL,
		0xDE0F5CDB755326D9ULL,
		0x9BD966EE03BA2261ULL,
		0xD7F4921B76639C65ULL,
		0x0D82A354B40860CDULL,
		0xC101309D973F1416ULL,
		0xE775A2599C05C2E2ULL,
		0x4F9887940B9C2644ULL
	}};
	t = -1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC70DB10F78FB0E0ULL,
		0x34FAECEAEF0B8043ULL,
		0xD1436A4FDB71EA00ULL,
		0x6050D3B69385F4BAULL,
		0xD4F4A1CCF8F0D642ULL,
		0xF7382DA6E613E511ULL,
		0x18020E8971E790ADULL,
		0x5AD52E7584BEDB44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DBDA48CEF74C931ULL,
		0x62BBE0D707F9FB9DULL,
		0x7BFA8F0492EE7A46ULL,
		0x6E63F4EC6FD93EF2ULL,
		0x2B9FDFE6D39E771BULL,
		0x5D29077D536E0AC7ULL,
		0x4256E320D73D7835ULL,
		0x09CE1DA529411996ULL
	}};
	t = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABAA9F54D76F1896ULL,
		0xF8110CF38F0764E9ULL,
		0x65A93651FDC2091FULL,
		0x7F91316A682F980DULL,
		0x97357AC58D7F008DULL,
		0x23ED0677D5E907C4ULL,
		0xF815FCE92676142EULL,
		0x14F4771461C6C4FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0170A0E9893CE8BFULL,
		0x8F9BDBF5C8E66875ULL,
		0xFBB9B462E8C2E2A9ULL,
		0xF7DA4BCB2850769CULL,
		0xC1FBEF2967327BF8ULL,
		0x86FDD89B7C2D9CC6ULL,
		0x899425BCFBB80BB8ULL,
		0xDB3153FD7FB83A2CULL
	}};
	t = -1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA12ADA0C36FC2A6ULL,
		0x87D0D65272ABC606ULL,
		0x63D0CA8783F4EB03ULL,
		0x760EF69D9279A118ULL,
		0xEA024B54CDB03D05ULL,
		0x8E525577F87AB315ULL,
		0x9A5FD7BB500EEEA7ULL,
		0x33ADA6604C7860D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA12ADA0C36FC2A6ULL,
		0x87D0D65272ABC606ULL,
		0x63D0CA8783F4EB03ULL,
		0x760EF69D9279A118ULL,
		0xEA024B54CDB03D05ULL,
		0x8E525577F87AB315ULL,
		0x9A5FD7BB500EEEA7ULL,
		0x33ADA6604C7860D9ULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FBF0164C4ACA410ULL,
		0xD5D99ABE7E45AB61ULL,
		0x1885ED98F586F87EULL,
		0xBE304549B4EA617CULL,
		0xBA32F0D695662DD7ULL,
		0x3049CDFCE556DE10ULL,
		0x7C857A3F1D42B189ULL,
		0x12E977678273EEACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DE3D009937A19CULL,
		0x005D7EA9752314C3ULL,
		0x4728132768B1FBD8ULL,
		0x6CEAE8171DC56918ULL,
		0x052BB59E612E86B9ULL,
		0x2BAC58BF79869483ULL,
		0xDF6B9AC0EAD5DEF2ULL,
		0x5955052E211EC343ULL
	}};
	t = -1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDE2C4137DE68F58ULL,
		0xCB8FC8F041BA62E3ULL,
		0xB24F3E220D4025E6ULL,
		0x0A46D94C437F3B2EULL,
		0x8CEE2750C2546B72ULL,
		0xA27EF7A0D5D82740ULL,
		0x2F8A6538264403A2ULL,
		0xF8BE1189A08942A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A60C622A5DB46CULL,
		0xF679B433AB31C8EFULL,
		0xFEAA4EEC79256772ULL,
		0x857E55EB15E64B26ULL,
		0x2E2E59C08EE2D429ULL,
		0x341EAF0D4A765BD1ULL,
		0xFE45371163A35798ULL,
		0x4260B7C55D35631CULL
	}};
	t = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A6C14858391DD44ULL,
		0x19C5193BABDB11F7ULL,
		0x7C90EF62EEB18E27ULL,
		0xCA2D2D9A09CD3DFFULL,
		0x13F7A0813022E640ULL,
		0x29EED276CDBFAE2DULL,
		0x9529B59120A86313ULL,
		0xB788CCD20A74B737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C0B21DFB6F42C1ULL,
		0x3A7F936D1687ED73ULL,
		0xFDE2DDC44B3482B0ULL,
		0x40CC439A79E21883ULL,
		0x5C11904D2D5EB475ULL,
		0x406E828A6237E80BULL,
		0x25255E53674CF164ULL,
		0x6492262288E57D88ULL
	}};
	t = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5490666F24702E5ULL,
		0x1CE1ED784E8FCFDDULL,
		0xEB5318407443666FULL,
		0x277107B7D41D1CFFULL,
		0x918474394FBE10E0ULL,
		0xC42A1994628FD714ULL,
		0xE5C0EC258724A8D6ULL,
		0x29D2C8BDBDAC474AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5490666F24702E5ULL,
		0x1CE1ED784E8FCFDDULL,
		0xEB5318407443666FULL,
		0x277107B7D41D1CFFULL,
		0x918474394FBE10E0ULL,
		0xC42A1994628FD714ULL,
		0xE5C0EC258724A8D6ULL,
		0x29D2C8BDBDAC474AULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88FFCEDF81AE2F4AULL,
		0x6F4908BEEC150CD7ULL,
		0xD88E35C729DBC9AEULL,
		0x7A59079C55C3ECF3ULL,
		0xCF2EE4520B9D867CULL,
		0xB027A0C78541645FULL,
		0xAE9CD11D8FC0F63FULL,
		0x65528D2A799C0119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C81A6B972213D1ULL,
		0x0E20925525572C20ULL,
		0x941760C97B748233ULL,
		0xFF99EB2C88BB0C61ULL,
		0xD515DD8D5100B762ULL,
		0x8D0742AA4A70A33EULL,
		0x5D99BB5292E39F1FULL,
		0x588DC5F811285BB1ULL
	}};
	t = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BCBAD22F78DD60EULL,
		0x7A7E70CA4FB2A79EULL,
		0x48DB591461B3062BULL,
		0x2F224F11FDF47EBAULL,
		0xE5112F02FDB5A915ULL,
		0xCDF518E420CA592FULL,
		0xEAFF7E4DBD90CF52ULL,
		0xBA16B2602824894FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC7E80C837EA5A9BULL,
		0xE6924DB27AE2047EULL,
		0x203632E434C58BCCULL,
		0x74A1D67E0C40FE1AULL,
		0x83CB1BE23468043BULL,
		0x297CCC23F7225B51ULL,
		0x4AFD7152E1889CB1ULL,
		0x667882B0BD3D59C8ULL
	}};
	t = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x746D09437D5B93AFULL,
		0x759E8CD06BD0F4EBULL,
		0x384D99B527EA9471ULL,
		0x90B53A0DD0F918F5ULL,
		0xD78D1519430FC050ULL,
		0x4CDD91B9E0C9A463ULL,
		0x98122C57D7D8297EULL,
		0x2F86A396AB4F1CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x771E5B60CB2A754FULL,
		0x63181C2B5C7CD091ULL,
		0x9E66084D538498A5ULL,
		0x3E8DAEF020B4DB3DULL,
		0x4C47CD3C0D28A92CULL,
		0xEC79A41625889E48ULL,
		0xC629D6FDA11D52E1ULL,
		0x0BFB0DDA4181E948ULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4FC033BE27270D5ULL,
		0x4A628962D584EA73ULL,
		0x194C74193DADE077ULL,
		0x7AC0BE056469CA56ULL,
		0x520E77AC13C2926FULL,
		0x6D0C28C0296C7CA7ULL,
		0xB82DD91B1F17DACAULL,
		0x809FDBFF97098671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4FC033BE27270D5ULL,
		0x4A628962D584EA73ULL,
		0x194C74193DADE077ULL,
		0x7AC0BE056469CA56ULL,
		0x520E77AC13C2926FULL,
		0x6D0C28C0296C7CA7ULL,
		0xB82DD91B1F17DACAULL,
		0x809FDBFF97098671ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCE80C5A20912104ULL,
		0xBC0B0396087990E6ULL,
		0x72B3B48C58C951B8ULL,
		0xE1C0830E77768633ULL,
		0xCBEF813E0C4E7E86ULL,
		0xD37761B382C4C8C0ULL,
		0xC97745C7E0B8017CULL,
		0xCA697322E810B268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F240765FCFBA15ULL,
		0xD5E3971E8C3EBBA8ULL,
		0x110504D81AE7F7E4ULL,
		0x94C677289707E06EULL,
		0x5749D9FB8C0A2C41ULL,
		0xF324EDFF3C1A9176ULL,
		0xB95530CAB58A6920ULL,
		0x974E7D11A967B953ULL
	}};
	t = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13B9AE5E5729381CULL,
		0xA34ED2494F610912ULL,
		0x3370D90999330811ULL,
		0x77D876BAC0D0F492ULL,
		0xBBDED84E58518374ULL,
		0xE08677D09A718A60ULL,
		0x144B7090B14DEE18ULL,
		0x1246D2966D5E8299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECBC20A22EC0EBDULL,
		0xA20D4CBCB404EB16ULL,
		0xED7809EF80508C0DULL,
		0xB2AA0AA4EF23B0E3ULL,
		0xDEAECA4F681BFD34ULL,
		0xA91957766D95B734ULL,
		0x19D491091C007C62ULL,
		0xDA0804A61E4B728FULL
	}};
	t = -1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2513FA88CE88311EULL,
		0x88E7FA59DCC433C5ULL,
		0x16C7B05173BBC962ULL,
		0x8FAAB9E2003BF275ULL,
		0x89B167A542BC1D83ULL,
		0xCD645C290DAFCF3EULL,
		0xBD5FCE216C5E6987ULL,
		0x7610E5F71DBD1224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C52784A4D340721ULL,
		0x08142900A0DBB5D8ULL,
		0x9F10684CF91C90FDULL,
		0x85A6CE7A5985A3FAULL,
		0xE1302AA75DA0578AULL,
		0xEE8FAAFE997728A9ULL,
		0x06EF32CA1893086FULL,
		0xBC56922F45BE392BULL
	}};
	t = -1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55F993C820ED47A3ULL,
		0x33BAF2EF55A50F45ULL,
		0x249455E71B71A5A3ULL,
		0x7242FA418B82C806ULL,
		0x98F1E4A1CFA32B0CULL,
		0xCC111F2C297B4A77ULL,
		0x69125B921A93C826ULL,
		0xD7638973471E2670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F993C820ED47A3ULL,
		0x33BAF2EF55A50F45ULL,
		0x249455E71B71A5A3ULL,
		0x7242FA418B82C806ULL,
		0x98F1E4A1CFA32B0CULL,
		0xCC111F2C297B4A77ULL,
		0x69125B921A93C826ULL,
		0xD7638973471E2670ULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0292417F33EF2821ULL,
		0xDEBEEEB5103D6A17ULL,
		0x2600D9A719F53E8AULL,
		0x37C1ECCCDF48EB11ULL,
		0xE1BE5B50B56DF144ULL,
		0x4BC0EF10C1E0005EULL,
		0xEF5E3E9C5D2892DEULL,
		0x9599F5175A58A69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x698823B2CAFB59EBULL,
		0x2202BB125785CB3CULL,
		0x252C0B236B84716EULL,
		0x092B1219E634DD25ULL,
		0xBA220F00CB18ED1BULL,
		0x08B8856433E059ECULL,
		0x79037B0C9E1C6FB2ULL,
		0x91FFF2269D557723ULL
	}};
	t = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6022481C9A6AB82ULL,
		0x7F91F93ADE7388DFULL,
		0x2E78FD5BBF1AA7C9ULL,
		0x1318EAB2EC6896ABULL,
		0xB563CA8DC02B7773ULL,
		0x5EE9A3F52F90285BULL,
		0x03191E6DB77CCBAEULL,
		0x0D8D52C5BC1F33E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939CCC21513D43ECULL,
		0x5B13D7BE3FE468BDULL,
		0xD623A6093EA8409FULL,
		0x6C09431868185318ULL,
		0x08E871CB3DFC7A34ULL,
		0xE5054F740722A61AULL,
		0x66BB4C9EFB92EA7EULL,
		0x73D04946F7A0BF81ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC278C958A1779220ULL,
		0x3BB8ECD463173A09ULL,
		0x7B5D66FDFC2F9C30ULL,
		0x5F6D252E682E9C4DULL,
		0x4DB621F96B74A3E7ULL,
		0x069BA00665416F11ULL,
		0xF65443478B5E3CE5ULL,
		0xC8A0B2A5D44237FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E5A76ACFBB2767ULL,
		0xBCC766FC08C80757ULL,
		0xE405128F100BF469ULL,
		0x4F0DFAA27402F306ULL,
		0x34ABA9959FEC2659ULL,
		0xB426DCE561DC6E1EULL,
		0xDE4826504C4829E1ULL,
		0xBBC131E7E4E91730ULL
	}};
	t = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x080D91272AEC67ADULL,
		0xDD0DE6397F4FE754ULL,
		0x5D0FD8EABB2A4A7EULL,
		0x6166B53C0F22CF5FULL,
		0x63B9F57E2A06538FULL,
		0x8AAB336F95D5963EULL,
		0xBEC93DBE8C085556ULL,
		0x7AE39AC5DCC24AE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x080D91272AEC67ADULL,
		0xDD0DE6397F4FE754ULL,
		0x5D0FD8EABB2A4A7EULL,
		0x6166B53C0F22CF5FULL,
		0x63B9F57E2A06538FULL,
		0x8AAB336F95D5963EULL,
		0xBEC93DBE8C085556ULL,
		0x7AE39AC5DCC24AE6ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB96561D5695A8C9AULL,
		0xCD1D0E16734870F5ULL,
		0x27425BED25DED282ULL,
		0x57D399C76BE5CA10ULL,
		0xFDEB37703D14878AULL,
		0xB10B13138C7DDD7DULL,
		0xC2D786D810E88B08ULL,
		0x2C706F168B2E3B83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9CEE774DDDDE4BAULL,
		0x29C402507CBECCC2ULL,
		0x9F3DE87C883A9830ULL,
		0x7C5FDAB11BF0BADBULL,
		0x2722BCA0B2999D66ULL,
		0x64E8D82B063637B7ULL,
		0xB820C7ACB892028DULL,
		0x7BBB25FAF8DE3A2EULL
	}};
	t = -1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x644A7CB701DFCD73ULL,
		0xDA480610FBF3CCA4ULL,
		0xEBBE38D0353ACAFFULL,
		0x0E4E5FA89E615542ULL,
		0x7E03E7F54C3FF966ULL,
		0x4644C6C09FF4CD67ULL,
		0xB77619EBA9908E7EULL,
		0xCEED73849DE3E72AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8A6C4F62FC80892ULL,
		0xE2040E1AD87D4AD7ULL,
		0x932579A410D8A435ULL,
		0x1A574D46EFA7A62BULL,
		0xBA042FC55D076204ULL,
		0xEC7539E6EDFCA763ULL,
		0xC088A4D9A9A435BDULL,
		0x520B43B1A8FDAA36ULL
	}};
	t = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A5E0EF530C5B713ULL,
		0x74DF1FBCE0755DEEULL,
		0xF9654A5666A44522ULL,
		0x8931170269513602ULL,
		0x7CD74246F8772B89ULL,
		0x2E81FCE42F937B05ULL,
		0x495C017F537042B5ULL,
		0xBA9D05F969A5CD8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4142568BA18987ULL,
		0xA62F05F14CE2FBDDULL,
		0x06E30E13A4E85B56ULL,
		0xBE1B58B45F46A63FULL,
		0x31B72D2FB9F1C30EULL,
		0x06B3068E8F22B2AEULL,
		0xAD25EF4732CE5546ULL,
		0xFF89351E647B8CD0ULL
	}};
	t = -1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62664EEBF269A854ULL,
		0xBC4A9641E7F09B20ULL,
		0xC22BD9F4F6436895ULL,
		0xDA5BAD9782B66254ULL,
		0x3536EB075A5CBA1BULL,
		0x3EAA4A12A846A335ULL,
		0xF76F83D7BA35F80AULL,
		0xA903F5DD886E9CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62664EEBF269A854ULL,
		0xBC4A9641E7F09B20ULL,
		0xC22BD9F4F6436895ULL,
		0xDA5BAD9782B66254ULL,
		0x3536EB075A5CBA1BULL,
		0x3EAA4A12A846A335ULL,
		0xF76F83D7BA35F80AULL,
		0xA903F5DD886E9CB6ULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADB96A54FF96D8DBULL,
		0xA36CE98372298D45ULL,
		0xA90CCF3D8CBF3218ULL,
		0xD35BCF20264DFF9BULL,
		0x4A71C2DC44EFDDDDULL,
		0x742899905DDBC528ULL,
		0xF33BEEBA26307C54ULL,
		0x5837902C081F4335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957B01BB00001DDEULL,
		0x1BE06F8076AC95C4ULL,
		0x78F5B0C17580A5F7ULL,
		0x63F123FAE3AFC13FULL,
		0x282692C5888C8B57ULL,
		0x401799DEA646A69DULL,
		0x1C0C3510DFC347ECULL,
		0xABF23DDB21A9000CULL
	}};
	t = -1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86CFAF42630015D5ULL,
		0xA6A3438828E7D21DULL,
		0x58BCF34549FC829AULL,
		0xB95D67ADA4AADC4AULL,
		0xE486CAC1CE158703ULL,
		0x59A481A2CF8A5092ULL,
		0x644034704C315091ULL,
		0xE394B0079496A26BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42AA3ACCDBB893FAULL,
		0xC7A3BF647F004068ULL,
		0xDF8A1908AEDCE4C7ULL,
		0x223F4889FFCF9DF6ULL,
		0xC4A8944447C42008ULL,
		0xF1B66413A0C6595FULL,
		0x0CB64711257B714CULL,
		0xBA21AEF611DEC903ULL
	}};
	t = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE96CD4B8280CA8FEULL,
		0xF6F9E615B4BF5508ULL,
		0x3EEA1D1B0769688FULL,
		0x913FA44B1EDF15DFULL,
		0x923A9568F8848BD0ULL,
		0x610D8CC28C47FC84ULL,
		0xF75A9AB74B88FB66ULL,
		0xBF7C6C57DC7E57FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0309028AB4F4F3AULL,
		0xC0D1569BD79C34ACULL,
		0x8AE93C4384D7A836ULL,
		0x869D3A3416C96B3FULL,
		0x64EE8A4357318FEAULL,
		0x7F22BD4EA1F8DA9FULL,
		0xAAC9BD5EE517C631ULL,
		0xA3A4DC87605472BEULL
	}};
	t = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2CF1FDB68BDB77BULL,
		0x30B44A0CDE4A5667ULL,
		0xA98D458F36AF7117ULL,
		0x99B85ADDA4AAED0EULL,
		0x781161641A3EE6B0ULL,
		0xF4B76283BD9F1D26ULL,
		0xED208A04F92ADAFFULL,
		0x8000E6AC77335E2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CF1FDB68BDB77BULL,
		0x30B44A0CDE4A5667ULL,
		0xA98D458F36AF7117ULL,
		0x99B85ADDA4AAED0EULL,
		0x781161641A3EE6B0ULL,
		0xF4B76283BD9F1D26ULL,
		0xED208A04F92ADAFFULL,
		0x8000E6AC77335E2BULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BE0FD1B37E2B5D0ULL,
		0x0BA96D5041A636D3ULL,
		0x397D5AE078777D17ULL,
		0x77DAC35612533BBAULL,
		0x530956498436E756ULL,
		0xAC8D5559EE358F83ULL,
		0x81896C8CA177DE7BULL,
		0x0DD2DE9100566A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD689DEAC07B2DFULL,
		0x94C298B309C2956CULL,
		0xE161E0FA69190988ULL,
		0xE0264F363A290E3DULL,
		0x984FF61FEFE4FC37ULL,
		0xDBBA3E3057838FBFULL,
		0x1487891E109F9B9AULL,
		0x5CD15B1017628558ULL
	}};
	t = -1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4E0509B7FE55260ULL,
		0xD8358658399F66DFULL,
		0x4C2F48FD5570D143ULL,
		0xF31DD9D54F677430ULL,
		0x9D743C0787068C46ULL,
		0x1CF7540069258470ULL,
		0x3874C47FD70F554FULL,
		0x275385816FD6E8A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B54A4C17F95DB3ULL,
		0x7C9EBA4DF5971320ULL,
		0xE2FC56FFB03EFFDAULL,
		0x86BBBF4B90E85A19ULL,
		0x0E8B9D6D45CE676CULL,
		0x28B01C535E2C807EULL,
		0x88141115B2603C33ULL,
		0x75EA260D91874AB8ULL
	}};
	t = -1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78048988D753DB49ULL,
		0x27CCC8DC53240503ULL,
		0x4DA490196BD35EB6ULL,
		0x8076ADC5B168B496ULL,
		0x57752A94A647F7D5ULL,
		0x93DEF8A0332984CDULL,
		0xFCE2492104FE75C2ULL,
		0xA60ADDD5A7976F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAADEEAD6E266322DULL,
		0xAED6703FAB37A8DFULL,
		0x24C222427DCC12F7ULL,
		0x6D33352601FFCD9DULL,
		0x625E8E5E76F9D3D4ULL,
		0xD92E7F43182D8459ULL,
		0x6783C2DB5B5CB990ULL,
		0x7D1908ECFAE60A5AULL
	}};
	t = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4137A403AE4DBC57ULL,
		0xDF04E95A9F8D1288ULL,
		0x1E536EC51D1F2AFBULL,
		0xC918F15B9D6F4E1CULL,
		0x9C7C43FA421CE390ULL,
		0x25093D56980C3B7BULL,
		0xA6F22ECF34714A9DULL,
		0x6A6810BC92076186ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4137A403AE4DBC57ULL,
		0xDF04E95A9F8D1288ULL,
		0x1E536EC51D1F2AFBULL,
		0xC918F15B9D6F4E1CULL,
		0x9C7C43FA421CE390ULL,
		0x25093D56980C3B7BULL,
		0xA6F22ECF34714A9DULL,
		0x6A6810BC92076186ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FE2BB4488154A53ULL,
		0x8AD6A24E6D751180ULL,
		0x41BD635C98612CE5ULL,
		0x242BEE8E6C447C7DULL,
		0x499661748DA5DD1EULL,
		0x8E00A5A7B3B2400DULL,
		0x974E1AEFF94B473DULL,
		0xD6DA9540F476637EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7C3DE12F282E898ULL,
		0x15BE0215536210BEULL,
		0x492906311D90C7E1ULL,
		0xC043B899DA5CDCBDULL,
		0xCC77AF2FE466B5A6ULL,
		0x510AF45E805DCEE0ULL,
		0x45258809B66552B6ULL,
		0x1DD3A8ACBB743C60ULL
	}};
	t = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA62E777DF857E4F5ULL,
		0x0C8D06DBCBFDF817ULL,
		0xA5DCFC056D6B35E8ULL,
		0x4990C428A06DE137ULL,
		0xAE23DB887736089EULL,
		0x7D491ADB82328759ULL,
		0xA8EF2A601E627589ULL,
		0xC56E21C802008413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB21715238CDF4FDULL,
		0x498C290573B5AB55ULL,
		0xF8F22FC33ECB0966ULL,
		0xFA152D597D39E1ACULL,
		0x8CB19ECB2701E59DULL,
		0xBEBAA8C000397025ULL,
		0xFDE9E2B7E723D2C2ULL,
		0xCF8CDFA1D344D6AEULL
	}};
	t = -1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x607D108A8437CECEULL,
		0x9EBA9EE50FB58341ULL,
		0xE127C719774F0137ULL,
		0x9C5E1169F31EAC74ULL,
		0x00FB38E04380858EULL,
		0x7707C435392A0816ULL,
		0xF7F2506BF4097741ULL,
		0xFEDEC99D383CB592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D739361CA9B1DB2ULL,
		0x8B3B8B792BA4A246ULL,
		0xBD317D133B4AF828ULL,
		0xCA5C2BDC98337E54ULL,
		0xB8AAED47C0EB0E74ULL,
		0xA3275D693A8BD4E3ULL,
		0x0F4B6EB7787329F3ULL,
		0xE6EDCB8B26C75AD8ULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC916CBEB34020EULL,
		0x629A00C3EFEC1B5AULL,
		0x7B3CF77285203339ULL,
		0x8A572FDD1880D374ULL,
		0x3807CA6C15EC54CFULL,
		0x4BFA27B34E5BB710ULL,
		0x595801C51138A627ULL,
		0x6AFA90A077CD141CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BC916CBEB34020EULL,
		0x629A00C3EFEC1B5AULL,
		0x7B3CF77285203339ULL,
		0x8A572FDD1880D374ULL,
		0x3807CA6C15EC54CFULL,
		0x4BFA27B34E5BB710ULL,
		0x595801C51138A627ULL,
		0x6AFA90A077CD141CULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F28BC2D537DF008ULL,
		0x99C3CAA78B9B86C2ULL,
		0xFE12D821BE7E5F08ULL,
		0x607433E5A8E3F3CDULL,
		0x0815DF2F9611DBFFULL,
		0xDA07925C5829E03DULL,
		0x564DEB58506CECE7ULL,
		0xF0899DD25AA49AF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D829A1B46EFBF19ULL,
		0x8A871F2B254196A3ULL,
		0x68A52EF41107EB4BULL,
		0x5530CC2C5CBA0D37ULL,
		0xBE450DADF44720B2ULL,
		0x5D542E323CBE7A2DULL,
		0xA056FC18E7F2F5EFULL,
		0x3D8EFCD977801F85ULL
	}};
	t = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91FBFD4CC3914617ULL,
		0x3B08AA8565979E2FULL,
		0x2DE0AEF42195166CULL,
		0x95652B7EFD0983A9ULL,
		0xBEB24540C37B035FULL,
		0xA4DD6CF7536EDA10ULL,
		0x7D563B6FD4B4ECFCULL,
		0xF9657F93DC52AD1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3A1CFE1202AAB3ULL,
		0xCC1A51A660A291E2ULL,
		0x10C9D483582A62FEULL,
		0xF310215D7ED2154DULL,
		0xF55F7BD5A13BEA3FULL,
		0xE790F417A87969EDULL,
		0xC37A7F72B78D658AULL,
		0xAD210E0B6C7F1311ULL
	}};
	t = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC69B7EB7D92AFF91ULL,
		0x7868A9A85EC1F5BCULL,
		0x411E88246734AD67ULL,
		0xF556E8D2F14C305AULL,
		0xDE787DE192230737ULL,
		0xA517409CFA0160CEULL,
		0x30833952A182A077ULL,
		0x7A037CCF6AA7660AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAEDAFEEEED25BFFULL,
		0x244DB01DE3671AC2ULL,
		0xE31D8A1A7E1B1766ULL,
		0x901B3BB72D140334ULL,
		0xB1547B2EF6C782ADULL,
		0xA3C7E72272F897BFULL,
		0xC0AC4C14D503462BULL,
		0xC95806DCF8E25D65ULL
	}};
	t = -1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA06AA7800402CA3ULL,
		0x98F2C2BE16424F8EULL,
		0x4417301E53E7FF45ULL,
		0x20C6485A113E3CA5ULL,
		0x1E100A1FA51EB9B9ULL,
		0x1B74817BFB585DB7ULL,
		0x12DF63ADF9A5402DULL,
		0x9A05344174F51AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA06AA7800402CA3ULL,
		0x98F2C2BE16424F8EULL,
		0x4417301E53E7FF45ULL,
		0x20C6485A113E3CA5ULL,
		0x1E100A1FA51EB9B9ULL,
		0x1B74817BFB585DB7ULL,
		0x12DF63ADF9A5402DULL,
		0x9A05344174F51AEDULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFB209E70C2B9309ULL,
		0x4A3A4DB8A1B47EACULL,
		0xA5E9410831712CFAULL,
		0x3EA05CB3C36BBE71ULL,
		0x2DBAD5DF13E5D33FULL,
		0x8B42FCDE5BC0C474ULL,
		0xAEC9AA2B1D38EA9CULL,
		0xB836FB9E51841C2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84DA9DC0D8E498B9ULL,
		0x44C4C4672032205EULL,
		0xEDE9012FB6BC8BA3ULL,
		0x8D7EE8FF75FAF18CULL,
		0x571A6FA0505CC492ULL,
		0xFCAD85FBB0132030ULL,
		0x3AAB5F61765062A1ULL,
		0xF6585A65DB813C51ULL
	}};
	t = -1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0C78D63B6F24F97ULL,
		0x9623BA8AE6E2CA77ULL,
		0xC2B40E6094ECFA58ULL,
		0x10DA0679ED6F7339ULL,
		0xD2CFEF0ED5249BBBULL,
		0x2B6DE55F589768AFULL,
		0x3B6CE8C3B9F3401FULL,
		0xD409EA505059DFF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E59114A782838FULL,
		0x4024C4D1FCCE9DD5ULL,
		0x484B39162B881518ULL,
		0xE6C42081A8E248A8ULL,
		0xCF4ACBBA130B51ADULL,
		0xA05B052C6F25A820ULL,
		0x630870B054934294ULL,
		0x1FD09C6C21B168AAULL
	}};
	t = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x172D3B90168AB184ULL,
		0xAA738074C8AB9FEEULL,
		0xCF058B5AC3E6ED54ULL,
		0x3E4650AAACF6C873ULL,
		0xF5F3F1947EB7B5C5ULL,
		0xBD573B17678C048AULL,
		0xFAA310328185749CULL,
		0xB53E9F446D46A2B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859E37BD24BC1FC3ULL,
		0xF67307CE4D0A1B36ULL,
		0x0A83A92FC69CFABAULL,
		0x8416B63669E5C11DULL,
		0xF4E9C7C506447B42ULL,
		0x88905D2905032C27ULL,
		0x1B0115D07AAA1828ULL,
		0xA15D71D94A8369E4ULL
	}};
	t = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EF902C877C50F27ULL,
		0xDBF2A84CB79C6DF2ULL,
		0xC4C0808E6B71BC98ULL,
		0x152CE0FBA87242A4ULL,
		0x87351232393A17FAULL,
		0x38E4883F44EF7BDFULL,
		0xCF65AAC25B6DC0DDULL,
		0x9F85909DCC603466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF902C877C50F27ULL,
		0xDBF2A84CB79C6DF2ULL,
		0xC4C0808E6B71BC98ULL,
		0x152CE0FBA87242A4ULL,
		0x87351232393A17FAULL,
		0x38E4883F44EF7BDFULL,
		0xCF65AAC25B6DC0DDULL,
		0x9F85909DCC603466ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01A57FFBD0D5BE43ULL,
		0xDA81CC91D460AE1EULL,
		0xF6CF33131201E285ULL,
		0x7D6BDDA035B37528ULL,
		0xDF898D8F2260D072ULL,
		0xDF986C20B03F674CULL,
		0x306E8A2A057F8333ULL,
		0x022BBA91C5F516EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889A5D3AB0B7D32FULL,
		0x476A3B920F312A5FULL,
		0x444FBA69241C10C2ULL,
		0x1AEE5CC5554D7AC7ULL,
		0x2B836DA139950A6DULL,
		0x601E3EF865821FDCULL,
		0x0AD35360347D052DULL,
		0x3674527E4808A300ULL
	}};
	t = -1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33D5432FD973A00AULL,
		0xE072CA7FDE63F49DULL,
		0xBA9F3CE97DA47F8DULL,
		0x5C6D3244BEAE399AULL,
		0x3F69B7AD022B93DEULL,
		0x4F4888E468C52B40ULL,
		0x585173E008BE674EULL,
		0x6781DDC9B562993EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A3BF3FE94677FDAULL,
		0x32FE7857B325EB93ULL,
		0x4817746319A75365ULL,
		0xB555230D2F7373D0ULL,
		0x9BA08413E24E7E74ULL,
		0xF80894DC3595D8D4ULL,
		0xC96FB12A3E41731BULL,
		0x8E836F360A518C83ULL
	}};
	t = -1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87EBE78BE69D1E8AULL,
		0x0DD3F59D48DE4963ULL,
		0xADCD236E382125B0ULL,
		0xEE04C83A6E0DA586ULL,
		0x4E32DDB5E3E84410ULL,
		0x23CC9EFB99F93147ULL,
		0xF2873F12EEA34757ULL,
		0xF7105751581FA5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F864E1FBEC338E3ULL,
		0xEEA44E30E6AD5296ULL,
		0x6AD0F7555EE100A5ULL,
		0x162BFD7E46235EB7ULL,
		0x13B99FFACDA0096EULL,
		0xF7AE0BACDDBB168CULL,
		0xE901D9BFE130C84EULL,
		0x174B2D759EF1BDA2ULL
	}};
	t = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9734C7133463A1B0ULL,
		0xB290A668938C2A2DULL,
		0x11D8FA337286D281ULL,
		0x10D4209D123443C2ULL,
		0xC8890557471D8A17ULL,
		0x3781FABFF0F18168ULL,
		0xB1AF08611BBDE37EULL,
		0x5D8CD13907D78C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9734C7133463A1B0ULL,
		0xB290A668938C2A2DULL,
		0x11D8FA337286D281ULL,
		0x10D4209D123443C2ULL,
		0xC8890557471D8A17ULL,
		0x3781FABFF0F18168ULL,
		0xB1AF08611BBDE37EULL,
		0x5D8CD13907D78C97ULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9052F562D497EA12ULL,
		0x85986E63D7F34C0EULL,
		0xE99B44324FAABB20ULL,
		0x1B5FCBD3E66A258EULL,
		0x0A51B21970B51EAFULL,
		0xD67BCCBBE1F80BDEULL,
		0x17BE1B251973363EULL,
		0xF537B1A242165013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3386376326E9692ULL,
		0xCA57DF3587B9C69FULL,
		0xD352A8CF0D1553D3ULL,
		0xAA5FF72704DE63E6ULL,
		0x1B46871D7BBF6CC6ULL,
		0x08BA134ECA32EF62ULL,
		0x3922B0C89D02A299ULL,
		0xEDF324E352DA1FAFULL
	}};
	t = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FE9E15EB4C5007AULL,
		0x610890CE017F91F2ULL,
		0xB102431C24491069ULL,
		0x2FC4C8930C32AA9FULL,
		0x3EE5FA4D6E14A8F0ULL,
		0x187879AADBDC8A7AULL,
		0xD66E5E979CFDB65FULL,
		0xF0B39ADF08E2A348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403304C470A93934ULL,
		0x231A79C2C6B18AF0ULL,
		0x2732A997CA6039FAULL,
		0x9B0413FE6741C427ULL,
		0x73022267ECB4AA0FULL,
		0x6E1193203D8116F1ULL,
		0x18359DC5C71CD474ULL,
		0x75B1E6FD73E7F956ULL
	}};
	t = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18F4B8F003CE4B93ULL,
		0xFB6A79323B43CF52ULL,
		0xBF1413C3E0871C99ULL,
		0x115B2872C01145EDULL,
		0x3AB14F5BC5442624ULL,
		0x95335266874E4286ULL,
		0x201E6F92CB4C67E9ULL,
		0x0B6151733F312D28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7211120AE31DF499ULL,
		0x07E5ED0D51BD5BF9ULL,
		0x501510555005222EULL,
		0xC84D3867E6612B59ULL,
		0x7361B8DB8EC122FCULL,
		0xE3AE33F2EAD73695ULL,
		0xF4548CCA0AFBE722ULL,
		0xE15254B09B87EBEEULL
	}};
	t = -1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3868B9A70B9730C3ULL,
		0x70A07B14F5130EABULL,
		0xA595BF092F9774E9ULL,
		0x70A9C71441617D9BULL,
		0x75B98983679F3A1CULL,
		0xDD6C236D2508ECA6ULL,
		0xEDECFF7F5DAB22B5ULL,
		0xDE80598E8DAE686FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3868B9A70B9730C3ULL,
		0x70A07B14F5130EABULL,
		0xA595BF092F9774E9ULL,
		0x70A9C71441617D9BULL,
		0x75B98983679F3A1CULL,
		0xDD6C236D2508ECA6ULL,
		0xEDECFF7F5DAB22B5ULL,
		0xDE80598E8DAE686FULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1EF4F83246702F5ULL,
		0x13A2F3BC526F1445ULL,
		0x7E37A11D2482254EULL,
		0x8A5009EF04D93751ULL,
		0xACD7D7BF8A42F247ULL,
		0x4ECD83F9695D4A06ULL,
		0x8DCDC355894ED3CDULL,
		0x168060F8DDA8DAF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB309909947A166E7ULL,
		0x57B321BF656CF6C7ULL,
		0x42287A462B3600CDULL,
		0x3177F2714D071D8FULL,
		0x58EF689D01B69E0BULL,
		0xE5F362D396463C04ULL,
		0x62D98B8E530B02D4ULL,
		0x4DFB765BA3C45BEFULL
	}};
	t = -1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB708C140F0917418ULL,
		0xF545AC16B299F14AULL,
		0xF108A0E76EE85DBDULL,
		0xFD86D7B7F273E3D2ULL,
		0x8FCED86A60494275ULL,
		0x521C082198B0CFA0ULL,
		0xB43676CB4CDD62A8ULL,
		0x72F5122AE8E71FD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF34BB327029E821EULL,
		0x354078389CBF61DFULL,
		0x8AE60D1D25341E52ULL,
		0xD24030BACED995D9ULL,
		0x973B7CDFD2CDA5F4ULL,
		0xA8EE85DCC32F59C5ULL,
		0x843DCD2A57B7FDF2ULL,
		0x1365F318BCA6BFB2ULL
	}};
	t = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AFF087F56051920ULL,
		0x69CE266917866114ULL,
		0xC1D091C86EB8ED2BULL,
		0x2EE169E23838A47FULL,
		0x31E869FCFC3BCF62ULL,
		0xB52B60BF1AB0A905ULL,
		0xDAF372047A1AF6BFULL,
		0x612FF01EA538A1C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5E708D77FAE9000ULL,
		0xC368733AAAB6F9C9ULL,
		0xCE80520A21E4EFC3ULL,
		0x80F2F5A9E9A24798ULL,
		0x108501997A1032B5ULL,
		0xD3EB1377BE653A35ULL,
		0x12C1F4539F03C4FFULL,
		0x42DA2CCFA95430E6ULL
	}};
	t = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B7289583BF6CB4DULL,
		0x083B70C56A0975C6ULL,
		0xEC5F6DDC96A04C82ULL,
		0x1073977725CC5866ULL,
		0xCA3053CF9CBDC868ULL,
		0x3C19E91891D93EE8ULL,
		0xED5694D325326725ULL,
		0x88308D4DB87546CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B7289583BF6CB4DULL,
		0x083B70C56A0975C6ULL,
		0xEC5F6DDC96A04C82ULL,
		0x1073977725CC5866ULL,
		0xCA3053CF9CBDC868ULL,
		0x3C19E91891D93EE8ULL,
		0xED5694D325326725ULL,
		0x88308D4DB87546CCULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB34B2EDF71DBB3AULL,
		0x7F2350CF534AF508ULL,
		0xADB4938CFB96776FULL,
		0x3A88D1C88C3D4A7AULL,
		0x2FBDD87D48B23427ULL,
		0x24942DD00FAA70B2ULL,
		0x509A4590EC6F85A9ULL,
		0xBF41190914E4BA99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C926E73B65C5CCULL,
		0xA779A38491D9342FULL,
		0xD4E09D983BD229FAULL,
		0x3DE208D3C16C3AC5ULL,
		0xD12C9E19FAC8929FULL,
		0x146779DA3642EA4FULL,
		0x014B5544EBFACF8DULL,
		0x07EB9F902ECB5373ULL
	}};
	t = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB64FF13480B397BULL,
		0x11E99D2961832FE8ULL,
		0x4C84CB9FBE1BA01AULL,
		0xD42119810C53DB39ULL,
		0x14CE58AA965B9A51ULL,
		0x07888AE3B55AEE02ULL,
		0xA2B2CE7E9138FE26ULL,
		0xF1988C38DD6C7759ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F72F56B6DD89EAULL,
		0x72487750DB095230ULL,
		0x049EBDBC98645C66ULL,
		0xA0F1C20C70080EBCULL,
		0xBBAD57C4CFF9FA18ULL,
		0x9DF747FAC7EF0E6AULL,
		0xEDE954820DEC6141ULL,
		0x3C5AEA6FF1F162CBULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0E854F8941F2132ULL,
		0x4FA8FD264E17E266ULL,
		0x555A249638EAF256ULL,
		0xD551C5E9A2D94FCFULL,
		0xC16EEB64B46DF14AULL,
		0x7281F8475DC08B5EULL,
		0x7A1E0799173DE9A1ULL,
		0x6359933BDF23E32EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95816CE9BDF53B5ULL,
		0x94875E77C7427275ULL,
		0x6D2D8584FAC1F2C2ULL,
		0x6B6B1CA2AF7B197BULL,
		0xB345D78114C30151ULL,
		0x2C6E2A4F1CC9542BULL,
		0x69FB623F1C307A40ULL,
		0x94ED0A7D6FC3EE02ULL
	}};
	t = -1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x424AC6216D5B1FFCULL,
		0xD160FA84B8DDFC3DULL,
		0xC01B100FA6A33D4AULL,
		0x9D8DB7004730BD9BULL,
		0x32E64A35ABFCF662ULL,
		0xEE64A79676258D22ULL,
		0x4D59CB2F14102A67ULL,
		0x09F4B6629C3452ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424AC6216D5B1FFCULL,
		0xD160FA84B8DDFC3DULL,
		0xC01B100FA6A33D4AULL,
		0x9D8DB7004730BD9BULL,
		0x32E64A35ABFCF662ULL,
		0xEE64A79676258D22ULL,
		0x4D59CB2F14102A67ULL,
		0x09F4B6629C3452ABULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E84855F1FF42277ULL,
		0x21E61243F87BB159ULL,
		0x25354B11EC74AABCULL,
		0x2D48F11EB9EF67A5ULL,
		0xD16AB547F7C150AFULL,
		0x4EF1CE4895C624CFULL,
		0x9EC1926DFB6B3D66ULL,
		0x5C647F53A1DB8EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2D0EC3A2CBBD8C1ULL,
		0x581D568664914DFBULL,
		0x22D2F2F5BBA57A73ULL,
		0xDBF84A1822F44D32ULL,
		0xE97803F416168ABFULL,
		0x7361D72787626679ULL,
		0xEC9F1B92382EF55FULL,
		0x828DA44BC70BF045ULL
	}};
	t = -1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC310C8AC5759F58CULL,
		0x7FB7603145E46D9DULL,
		0x9D5356E93551CB16ULL,
		0xA263D823ACAA57A8ULL,
		0xBBA2052DE4C7FCB9ULL,
		0x0E41E16D0002B847ULL,
		0x7496E62629A5921FULL,
		0x7FB6A447A04A9962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36FE22D09633CAD9ULL,
		0x6BCEB28ECC1BE36EULL,
		0x26AB2FA0A1B40407ULL,
		0xA38AD725851AF4B2ULL,
		0xF17E375B10646E8EULL,
		0x34E796367F0685BCULL,
		0x56C2F0A7F72A8BBFULL,
		0x6DFB1F7EFB13B5C5ULL
	}};
	t = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AC9C872F46D275CULL,
		0x3AAB557B6C25AED9ULL,
		0x3B93497E048B0057ULL,
		0xEB102ECCFDECF26DULL,
		0xDC6B41C84DADB58CULL,
		0xC49CB7C48E3A9058ULL,
		0x237E97D622122ADBULL,
		0x1A69FB6FD8D49084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5EFFACE054C4C0DULL,
		0x4357ADA458E93339ULL,
		0xB6924806FD62AC50ULL,
		0xA22F56E8A95515D2ULL,
		0x6DEBFE50858FA45BULL,
		0x8CB804FF1DE6A26EULL,
		0xB6FBCB64925568CFULL,
		0x13ADD66937F7451BULL
	}};
	t = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDB780CEBC2EA5F4ULL,
		0x54DBD9280D2FE4CAULL,
		0x260C61B117834DACULL,
		0x4837B4BF46084625ULL,
		0x67B9C611B9176293ULL,
		0x5E49B6C03B4D551BULL,
		0x0143E5CF9AA7E3A3ULL,
		0x33C493CA5B8493EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDB780CEBC2EA5F4ULL,
		0x54DBD9280D2FE4CAULL,
		0x260C61B117834DACULL,
		0x4837B4BF46084625ULL,
		0x67B9C611B9176293ULL,
		0x5E49B6C03B4D551BULL,
		0x0143E5CF9AA7E3A3ULL,
		0x33C493CA5B8493EFULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CAA56AB410EEA92ULL,
		0x5CB1B4BE32DC97F9ULL,
		0x8995126E2EAD535CULL,
		0x26D9042E95418CBCULL,
		0x55B03656575ADBC1ULL,
		0x9A2311D676CB3F84ULL,
		0xFD3EE41AA902AA33ULL,
		0xDFFBE67424C8F502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FCD47F3AA1EE5EULL,
		0xB5B955080549F0FDULL,
		0xFF5DA93472718390ULL,
		0x73D4FA20682B96A7ULL,
		0x7376EA9BB4CAA51BULL,
		0x40B94671F232D6A7ULL,
		0xB72084A3A7A09F3DULL,
		0xDD2DE8D007807E7AULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9217CD1F51DD067EULL,
		0x2E55E426B785CAECULL,
		0x93356828433AC2BFULL,
		0xEAAB293C8E045E61ULL,
		0x1B0FC722C9CE4E0EULL,
		0xB1374E997D028F12ULL,
		0x3508A6EE5A6D705CULL,
		0x36FDCE4E722F7BA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91DB883AB347EAB7ULL,
		0xFBF1B2628AB79F3DULL,
		0x3C77B2FAD03E6C90ULL,
		0x23C8173C49D15C3FULL,
		0x5693C0DDDE92E237ULL,
		0x9BFA5469943ABD3BULL,
		0x3C812805FFE209B1ULL,
		0xFB85BCC4A646ED86ULL
	}};
	t = -1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x239A25CAC3D701CBULL,
		0xD00E48F58F8B7228ULL,
		0xD9EFC0CB462A54B1ULL,
		0xA4A3BE1EC016B704ULL,
		0xADBBF9F759666FB1ULL,
		0xD326659C50D66747ULL,
		0x7BACD74C4CA0C080ULL,
		0x794CF1E79C52113BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B9A84A9B0876980ULL,
		0x35EBE2EE03C8380AULL,
		0x908D13DA548489BBULL,
		0x3EE736DE0DD340F9ULL,
		0x7A95A95447153D44ULL,
		0xBD83A8FFD6FF91FBULL,
		0x8843F673B44AA64CULL,
		0xFA243AF7DA15D2A0ULL
	}};
	t = -1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4753A232068A540DULL,
		0x19B4B1676DAB35E2ULL,
		0x402B4FDFCB159528ULL,
		0x2C182B147309FBC1ULL,
		0x38383A519264D297ULL,
		0x34F8D7FCA5F11501ULL,
		0x9F13B0E73B55089AULL,
		0x8A3461D46CA6DA28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4753A232068A540DULL,
		0x19B4B1676DAB35E2ULL,
		0x402B4FDFCB159528ULL,
		0x2C182B147309FBC1ULL,
		0x38383A519264D297ULL,
		0x34F8D7FCA5F11501ULL,
		0x9F13B0E73B55089AULL,
		0x8A3461D46CA6DA28ULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0864992F92B8948EULL,
		0x2E21B350A3B3E79DULL,
		0x6CA897AFC4D876DAULL,
		0xEC99B9796481316DULL,
		0xE57052A93C694F41ULL,
		0x91C2F75448BEB224ULL,
		0xA366241BFCA96BAFULL,
		0x3C0AA458D85F1EE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CEBFA95AB6B1B8BULL,
		0x02DECAD6DD21E9A4ULL,
		0xCF5B26FE22779015ULL,
		0x4F14CE1C69C35E75ULL,
		0x25F7838FCED49245ULL,
		0x9FAD088528067255ULL,
		0x35444EDD71D263F6ULL,
		0xA63348F61C7A53A8ULL
	}};
	t = -1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46F3C75AD3FCBEC5ULL,
		0x2A174DF3C0E74DBBULL,
		0xA4DA2FDD943B426AULL,
		0x57B1148827E3F03FULL,
		0x6C9DCBF0A566AD19ULL,
		0x417F88A18B0BDB98ULL,
		0x3787D069AB63E1EEULL,
		0x4F674C366DC5F153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1BD0A9F6807CB2EULL,
		0x932C0280DE74919CULL,
		0xD9D1F1C3FEB93AD1ULL,
		0xE0D5DDC7967107FFULL,
		0x0F7778B0C7BFA976ULL,
		0x3EE239D4956EA82DULL,
		0xEED8E39AD051A7B4ULL,
		0xC0335AB086E73234ULL
	}};
	t = -1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B46847C5B8856FFULL,
		0x1A34CCE73ECFC302ULL,
		0xDF4762E8EB2F1431ULL,
		0xA2F7812D52321D20ULL,
		0xC7C73B77008ADE2CULL,
		0xE0BBD33EC6F57821ULL,
		0xB124E3AE6086F009ULL,
		0xA957D5D4477FD225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B90BB0ED2F9E8DULL,
		0x69AA094C10B4B2F0ULL,
		0x4B0B0D18F4C2D74CULL,
		0xB66F5C33696DF54FULL,
		0xF1C0EC668393AE07ULL,
		0xF23457D14539BD64ULL,
		0x2B378FEF4A9D46F5ULL,
		0x56AD4032FE4D914FULL
	}};
	t = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x850A689D52F8D95EULL,
		0x50BC2E27A29FD787ULL,
		0x117C5703B17117D4ULL,
		0x151A32A8BE50EBC6ULL,
		0x538904270C6B9E75ULL,
		0xCEA8A6CC764DF6AAULL,
		0x8B2F2FA0467ECB03ULL,
		0x81AE99B078E52ECAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x850A689D52F8D95EULL,
		0x50BC2E27A29FD787ULL,
		0x117C5703B17117D4ULL,
		0x151A32A8BE50EBC6ULL,
		0x538904270C6B9E75ULL,
		0xCEA8A6CC764DF6AAULL,
		0x8B2F2FA0467ECB03ULL,
		0x81AE99B078E52ECAULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2AE94B6E8D279B2ULL,
		0xFA53FCD488BF8614ULL,
		0x4CFD42D5F520D0B4ULL,
		0x759D4CECBB553770ULL,
		0x21883C089F3E28B0ULL,
		0xA686DB57E8A9CDABULL,
		0xBA2A179E65D88842ULL,
		0x4CAD09BB7B43A7D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8168D08061CEE51EULL,
		0x0672C539B326565BULL,
		0x997D25E844C32F27ULL,
		0xD5C62C5483F5ED88ULL,
		0xED8260ED4406956AULL,
		0xB81ED3D298BD1E32ULL,
		0xC3F9423B666B9080ULL,
		0xAC21505D20E7F825ULL
	}};
	t = -1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x192A886C6AA3A737ULL,
		0x4F8F99DBBEA21A70ULL,
		0x7D9EA45AB2CDAA04ULL,
		0x563DE9D714F1A616ULL,
		0xE0C59F7EE5FC0707ULL,
		0xA952827350178D00ULL,
		0x9A49196DF786302AULL,
		0x8F17AB3453133B78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22C2D9E4763611FULL,
		0x0FC23C53126DF1A2ULL,
		0x58EA47BAA2679B08ULL,
		0x3D2072E45B5889A6ULL,
		0xC41EB857B210483EULL,
		0x24B67DF075520AC0ULL,
		0xE8F70E36C248093FULL,
		0xCCC0721299B36099ULL
	}};
	t = -1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36F7D92AB4490026ULL,
		0x52AF422963B84560ULL,
		0x5FD895777C36D150ULL,
		0x09C205FD04E16428ULL,
		0x1CB7C495F5560EA9ULL,
		0xD3080C3BC9271DCFULL,
		0x2FB6AB1ED317C349ULL,
		0x09408CCE98670AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECD5937E1537E4FULL,
		0xB4862E1E645513B8ULL,
		0xFAA641F8EC00BFCAULL,
		0x8D915135E8B23FAEULL,
		0x3AD3D70FFBAC965CULL,
		0x825F07F6E88F9DE7ULL,
		0xEAC467D0BBDDE823ULL,
		0x932A2C5DB45C83DCULL
	}};
	t = -1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0361C928841BF8BULL,
		0xF74248C47650708DULL,
		0x29381D58C4A445FFULL,
		0xB569535E9F7F0FC2ULL,
		0x1D8A2ECBC15E7D7FULL,
		0x0EA284C80873D0FFULL,
		0x74F187F1D7C82F12ULL,
		0xF0D016357BBE6BE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0361C928841BF8BULL,
		0xF74248C47650708DULL,
		0x29381D58C4A445FFULL,
		0xB569535E9F7F0FC2ULL,
		0x1D8A2ECBC15E7D7FULL,
		0x0EA284C80873D0FFULL,
		0x74F187F1D7C82F12ULL,
		0xF0D016357BBE6BE4ULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F82EB3A4A35FD6BULL,
		0x094B0F2629E1BAAFULL,
		0xDBB9BEEA990659BEULL,
		0x8FFBEE85E999E34CULL,
		0xB18826C376BD8FA4ULL,
		0x307F8E264B70BD19ULL,
		0xC5DC740D3472E789ULL,
		0x6DF039B69C686851ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82BF2A5D47DF0F2ULL,
		0x03957304C2720253ULL,
		0x2269BE8450B87301ULL,
		0x9057AF49DB8953E4ULL,
		0x1AFEC53FA000853BULL,
		0x2B8E3207042BC138ULL,
		0x0217783B2275E150ULL,
		0x5B02620E814B5B91ULL
	}};
	t = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53985CDBA754EFA5ULL,
		0x6E628E33F4EAC7AEULL,
		0x2921376F9C50227DULL,
		0x0B0F6403437A23ACULL,
		0x9F63F5FCBDDAAF18ULL,
		0xB2BF1A754B62DF82ULL,
		0xAD72C05BF98A2A51ULL,
		0x178397DB993AC3A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41A473A242A506E6ULL,
		0x33E9CE0A0880BBC7ULL,
		0x62DC6196DBAC41D5ULL,
		0xDA45D3CC26803AD1ULL,
		0x17E6AD7AB4C4E7FDULL,
		0xA7E99DE749768846ULL,
		0xDCF69DADD5977935ULL,
		0x583D7D35EB93CD0EULL
	}};
	t = -1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91C237776932786BULL,
		0xBEFBF34F92A64C52ULL,
		0x110AA0BC85A66FBEULL,
		0x66B02C6BC367ABB2ULL,
		0x076D1AD35E82C367ULL,
		0x2EDC5265F6AB3883ULL,
		0x6698409552B33AD2ULL,
		0x12E6819DF25FFB8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4FB0ED844AC7EAULL,
		0x40844FBFC98C511BULL,
		0xF19EA99E54C8B371ULL,
		0x35B68246E9962748ULL,
		0x2F85072761B1B13BULL,
		0x91C6B2B0070B0EF2ULL,
		0xBC8057A112088BDBULL,
		0x75236D011CDA2492ULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x021ADAAA97A2A74AULL,
		0xCC631BAC8B9839EBULL,
		0x2CA9759E0DEF478FULL,
		0x27F321CDD0ED9CB8ULL,
		0xADE38B52807D0666ULL,
		0x9E064F34F32E635DULL,
		0x0C85DDD7F9703F36ULL,
		0x1FE73ED49776FCADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021ADAAA97A2A74AULL,
		0xCC631BAC8B9839EBULL,
		0x2CA9759E0DEF478FULL,
		0x27F321CDD0ED9CB8ULL,
		0xADE38B52807D0666ULL,
		0x9E064F34F32E635DULL,
		0x0C85DDD7F9703F36ULL,
		0x1FE73ED49776FCADULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BDA59450645EBDAULL,
		0x8982C47BC717EA90ULL,
		0xE536BADBB1763A52ULL,
		0xA6BF714C4B8F4A61ULL,
		0x5F670A2A99CF3C52ULL,
		0x31CBCFE913DA4091ULL,
		0x954B1D54CD2F091EULL,
		0xE3C104DF4E9B94BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B5DDB50D16CBAD9ULL,
		0x2B2C5CE4D56B7745ULL,
		0x49DAF98E1DAF3EA9ULL,
		0xA0841974BBB0309BULL,
		0x1CAAF5B94A07D2EAULL,
		0xD63255C4958261BBULL,
		0x2F4CCDB600B7943CULL,
		0xFAFE85F822BF4927ULL
	}};
	t = -1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x200EBEC278C49104ULL,
		0x9946D099D00FC916ULL,
		0x772F82F6EA627D8AULL,
		0xAA73D44A982E8BE3ULL,
		0xF0DD295951ECD278ULL,
		0x30E18CF79ED55936ULL,
		0x9114AE035933C2BFULL,
		0x8BEDBCDD09E26DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F67E3E4AD26927ULL,
		0x3314626DC1349232ULL,
		0x7EDC36111A7F5A1FULL,
		0x9F9F699EC60638BAULL,
		0xA3E5D459867FD127ULL,
		0x93E77DE8329F2547ULL,
		0xF376114824492A24ULL,
		0x902C91F07A749A46ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6678451436A4FA52ULL,
		0xD020866DFAA8418CULL,
		0x751829B91B107B36ULL,
		0xB84755571AF09831ULL,
		0x2AEE345DB3C2C117ULL,
		0x411BBB460E9D8580ULL,
		0xD0670873DA3CA4A9ULL,
		0x786B68564A73413BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4186BC0D33F4E437ULL,
		0x7D3A29AAE36DCA62ULL,
		0x4F09CC5954703E24ULL,
		0xA2F502CD848D8156ULL,
		0xBFDB0BBBE759F22EULL,
		0x70EDF691B7B20F48ULL,
		0xD93E054906D55D8BULL,
		0x288F9D356F178FE1ULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF86D6D774CACED98ULL,
		0x71CBBD6DC7637312ULL,
		0x94566F656C26B22AULL,
		0xC06DC0B68A5066F0ULL,
		0xC0B61CF925FDE27CULL,
		0x86E22533F8837B53ULL,
		0xDF7985F45EC6CCDBULL,
		0x85FFD00075B3ADCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF86D6D774CACED98ULL,
		0x71CBBD6DC7637312ULL,
		0x94566F656C26B22AULL,
		0xC06DC0B68A5066F0ULL,
		0xC0B61CF925FDE27CULL,
		0x86E22533F8837B53ULL,
		0xDF7985F45EC6CCDBULL,
		0x85FFD00075B3ADCDULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86293E17B06904C4ULL,
		0x684752E72C1A0F32ULL,
		0xEEE3DB7399E968BFULL,
		0xA81896727A023848ULL,
		0x60817687EDF4B9B0ULL,
		0x7A0FD0C7CE811EC6ULL,
		0x60CC8E242289F6F3ULL,
		0x857C9C2881E868E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC44693728FB758A7ULL,
		0x8503B73E38FF271DULL,
		0x2FA0F4FF3C920694ULL,
		0xC05B911F4ADEE945ULL,
		0xD4ED5AE306C3C021ULL,
		0xB01491237FE4AB87ULL,
		0x48F072B1F179A80BULL,
		0x7D527CFEBD14F3A9ULL
	}};
	t = 1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x565658B702B86D18ULL,
		0xB845B0F01D0D5AFFULL,
		0xC09B1A712B329EF8ULL,
		0x4E337352B9FB59A1ULL,
		0xC8C5C8003B70E997ULL,
		0xB6E3D21B4F27CFCCULL,
		0xA66D6B798DAB17F9ULL,
		0x330222E8EAB85E67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26E5C38EE549EABEULL,
		0xAE0C566FBA06A85EULL,
		0x76A08859CB346BEBULL,
		0x774E2A2DF430E489ULL,
		0xDCBE9A7220DF70C2ULL,
		0x987E5BD55B371145ULL,
		0x94FB18D98C9FD7BBULL,
		0x2DFB6EB769F0432EULL
	}};
	t = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x639FCE76E7B6378BULL,
		0x7B5DCBA128CE3DF9ULL,
		0xC0493B212606C202ULL,
		0x269397FD88D33630ULL,
		0xC73BC05D261649EDULL,
		0x27ED4A78DECD374EULL,
		0x27F7ECE358CE1DF2ULL,
		0x7E790AA7C33B4F7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E61A39470926916ULL,
		0x8B63EBD0064E2C82ULL,
		0x9A03343A76577BCDULL,
		0x69786AD47B1CC75EULL,
		0xE1274DB6CAC4303FULL,
		0x61F3D3C939324B1FULL,
		0xC3225B7B7843303DULL,
		0xDDC4550C9CB703E2ULL
	}};
	t = -1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6EC3559631620D8ULL,
		0x8E21F7FC64CFCD70ULL,
		0x6338FFB7009D6FEBULL,
		0x4ED7BE9A2A827D29ULL,
		0xEF8880198A55A1D7ULL,
		0x746276713243C81EULL,
		0xC1C4091A3B7C1FE4ULL,
		0x679E611ED24680BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6EC3559631620D8ULL,
		0x8E21F7FC64CFCD70ULL,
		0x6338FFB7009D6FEBULL,
		0x4ED7BE9A2A827D29ULL,
		0xEF8880198A55A1D7ULL,
		0x746276713243C81EULL,
		0xC1C4091A3B7C1FE4ULL,
		0x679E611ED24680BDULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x002C97F5167FADA4ULL,
		0xD4FA83064DAC2015ULL,
		0x246F774C0EB4A2B1ULL,
		0x281461EF6D45027CULL,
		0x62254902139DB76AULL,
		0xEC787715BA71CB34ULL,
		0x400569591A5E533FULL,
		0xA7ABB484522C7879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E44EC1AAA4721CULL,
		0xB05EBD36A73B49D3ULL,
		0x6516161904EC9884ULL,
		0xAFFBF01772C5ABABULL,
		0x4FEA67A5C7CFE5FEULL,
		0x7639452D0C6069D7ULL,
		0x0A07D6F05FAC658FULL,
		0xDA3C41A789A78D4FULL
	}};
	t = -1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C76E486860B7626ULL,
		0x583ACBC3617D5B08ULL,
		0x67C8CF25805207CCULL,
		0x95DE45C0510E285FULL,
		0xEAA8BF1C6DB73E2DULL,
		0xBFFA63C94820BE31ULL,
		0x15D09E9C5FB94C1EULL,
		0x5C6255396DAD2835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8382995F4A4762EDULL,
		0x919D6750109CDA97ULL,
		0x7CC7805ECCA9599AULL,
		0x7A518E62FC406C75ULL,
		0x2E4FBF611686ABB0ULL,
		0xB23F4E2AD1897AD3ULL,
		0xEAC9856B3385C3D6ULL,
		0x7D0C35571AD4539FULL
	}};
	t = -1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7740C7DACF9DFA8EULL,
		0x953446AF3A9BD9A3ULL,
		0x42CB6BB68DCA1E94ULL,
		0x1CD108C6426F4FC6ULL,
		0xDE7A1BA6AA9640A3ULL,
		0x80B771F6FFF0660FULL,
		0xAA82819C45F94AE8ULL,
		0x1B86386B8674FF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9721E8772CADE935ULL,
		0xB4C35998D8F6188FULL,
		0xC1FB7D9F98213213ULL,
		0xF12389B5664757A2ULL,
		0x7867301138328A17ULL,
		0x10B5D9D62E4B62EAULL,
		0xF6DEB68403BF3885ULL,
		0xB42F3DD8C2F791D0ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75DC7E7DF62CD2D2ULL,
		0x952055FC4A7A8B80ULL,
		0x057EEDEFDC584500ULL,
		0x18D275FBDFBD4994ULL,
		0xD69275D6F82CC3A9ULL,
		0x7E9D0EE5EE4A0B29ULL,
		0xFDA6161498E8C521ULL,
		0x9CAA61C0C4742573ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DC7E7DF62CD2D2ULL,
		0x952055FC4A7A8B80ULL,
		0x057EEDEFDC584500ULL,
		0x18D275FBDFBD4994ULL,
		0xD69275D6F82CC3A9ULL,
		0x7E9D0EE5EE4A0B29ULL,
		0xFDA6161498E8C521ULL,
		0x9CAA61C0C4742573ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC69EE3F1F002BA0ULL,
		0x079103D0966DF86AULL,
		0x4A4F019C471245B4ULL,
		0xFD5E04DF58A23852ULL,
		0x3EBAC13F6A7E8907ULL,
		0x3CAB686C4E348DB0ULL,
		0xA97EDE1D439F97BDULL,
		0x3AAA747F15F43234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC2F1DC9584FC59ULL,
		0xC5FDF941ADF41900ULL,
		0x3181C6E33595F78CULL,
		0x2CC4512B2CB349A5ULL,
		0xBA805AE772B32B3AULL,
		0x5861ED81C683AEC4ULL,
		0x0A09FFD471FD731DULL,
		0x8340A8A679EC6EC0ULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08E2CDB69FFA73D3ULL,
		0x25964FC2C7F00324ULL,
		0x7C4C3B61FB42A081ULL,
		0xC8FD322849E690D9ULL,
		0x12CF7E7DF07FF2CDULL,
		0x29191FB8B4759C6AULL,
		0x5AA9A86DAD906032ULL,
		0x7DE5CF22DD42C98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x168C3555D3CEEB2FULL,
		0x952E02176C5150A5ULL,
		0x14BD0BFF89123201ULL,
		0x6E49193494BC7BE8ULL,
		0xE37C1705CE4B79BDULL,
		0x775150D52A45AF6EULL,
		0x89641CB2E330018AULL,
		0x4B2EBB2BD9934A57ULL
	}};
	t = 1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29BEA2B680F01884ULL,
		0x9A32FFA559CDCD18ULL,
		0x076394F872CC396FULL,
		0xF3E1D07A799D26BBULL,
		0xEE8BBE9B51D32934ULL,
		0x84038E5A781D4C36ULL,
		0x8272B7721200A98CULL,
		0xF0FC48807ED963B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993A784778F21B6EULL,
		0x17D7E6CC53517A66ULL,
		0x2D1C92929417A133ULL,
		0xA085827BFE959F9FULL,
		0x49526BB587063C9DULL,
		0x4BCE9D472CB63D1CULL,
		0x7A3A916276965BC6ULL,
		0x9B12BDF252A6E314ULL
	}};
	t = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C0E6B13010239F5ULL,
		0xFB47D112188140F4ULL,
		0x1F1A16877D846B92ULL,
		0x0155A566E3DAE6E3ULL,
		0xB6769C25926FF39EULL,
		0x8669859D21703EE9ULL,
		0x5681FD4379CFC158ULL,
		0xF31C205C41B96928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0E6B13010239F5ULL,
		0xFB47D112188140F4ULL,
		0x1F1A16877D846B92ULL,
		0x0155A566E3DAE6E3ULL,
		0xB6769C25926FF39EULL,
		0x8669859D21703EE9ULL,
		0x5681FD4379CFC158ULL,
		0xF31C205C41B96928ULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5E047B0A7CB1614ULL,
		0x2981D2DA3AC69829ULL,
		0xF2E88CEE7CB0E371ULL,
		0x7C2C028E2FBE468CULL,
		0x85EFF1FE1D3FD058ULL,
		0x499E928112AA416FULL,
		0xF97F7F4720441C78ULL,
		0xFFB0CE6D2F059958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2C092ED6E138932ULL,
		0xBB7F2457340C987EULL,
		0xBB7A601EBA49607EULL,
		0x3132EA02ED2D2E55ULL,
		0x73077D894950B860ULL,
		0xD40868834F65F98BULL,
		0xC202A08EAF8A5E1AULL,
		0x2219A81F009D5216ULL
	}};
	t = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51409100AE6BF566ULL,
		0x1A1EB9F1FAFCC9D3ULL,
		0x75587AE216B35E3FULL,
		0xB03C90C61A3BE282ULL,
		0x0DBDE0B605FA2EFBULL,
		0x245C04709010D4B8ULL,
		0x91662B968000A839ULL,
		0x913EB243696867D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30462F6794BAE651ULL,
		0x1A1E037BDD65FBEBULL,
		0x3A204006B6EE5AB2ULL,
		0xF9B951D675F222F7ULL,
		0x0615702B37478DB4ULL,
		0xAB33F121E6B40170ULL,
		0xF780D3D5FE6D51CAULL,
		0x121E7391D0F0371CULL
	}};
	t = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x902DE8DAD41E648BULL,
		0xB788584FF10266DCULL,
		0x8B647C3D209ACCE2ULL,
		0x4DBA047F41553F53ULL,
		0x3130ED550860122FULL,
		0xFA3C748A6644BB03ULL,
		0x43F9C76BBF78ACCAULL,
		0x60A21BE7F05D7EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4FD08614FFA91FEULL,
		0x4D5303CCA82D5ECFULL,
		0x1D4B91B0FDF84B9CULL,
		0x06F966378290AFE9ULL,
		0xF92801BA435489B4ULL,
		0x9820E38CB52EBA4AULL,
		0x977CBFB848DF7B01ULL,
		0x7B7E415C791802FCULL
	}};
	t = -1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD08D17376D9280ULL,
		0x1BE6F506DB10CE95ULL,
		0x88D19C88051B2F28ULL,
		0x51779EAD26C7A077ULL,
		0x699F431DB0D4348FULL,
		0x16BB9A527F6A3584ULL,
		0x402A0863EDE6D2BDULL,
		0x2186D58B0F459AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AD08D17376D9280ULL,
		0x1BE6F506DB10CE95ULL,
		0x88D19C88051B2F28ULL,
		0x51779EAD26C7A077ULL,
		0x699F431DB0D4348FULL,
		0x16BB9A527F6A3584ULL,
		0x402A0863EDE6D2BDULL,
		0x2186D58B0F459AD6ULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129CF0D3BBF46CA8ULL,
		0x21D7B039FA08616AULL,
		0x1177047E24161A3EULL,
		0x7E368C606A5EE493ULL,
		0x4CDBA73BF8C567CAULL,
		0x4F07E612B6740DAEULL,
		0x7D15BBBF8C4003ACULL,
		0x5B52A2115A0AFA56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FEA66EB5B26E32EULL,
		0xBEB4423163CE83CCULL,
		0x11D4613008AC9003ULL,
		0x668C4A272B47322FULL,
		0x81ACC12DA80D22ADULL,
		0xA80E969505E70731ULL,
		0xE985110FD90A9872ULL,
		0xBBAF6EA4E4C4B2A3ULL
	}};
	t = -1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83E3E57DB05F499DULL,
		0xA3FA4B4F5D8EA1D7ULL,
		0x1B10B5F2C03430CEULL,
		0x6D7FEADF4E7351C9ULL,
		0x5060C034F40CAB3AULL,
		0x472525DB6403E803ULL,
		0xB1F4FDA8B997F8D6ULL,
		0x6F0E91F23C51A673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0649DECC1BB34A8EULL,
		0x121443AEE242F914ULL,
		0xDC2A17BEF2D36502ULL,
		0xFE25948C6D271453ULL,
		0x823DBF2FC40F5B6CULL,
		0xA9717793D13DDEDCULL,
		0x47E1129374ABE27EULL,
		0x04B9D6E148F5E2E6ULL
	}};
	t = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0593D68C63C50D62ULL,
		0x92918295CDA15F65ULL,
		0xF1D9D67F82BA6D43ULL,
		0x45C884324EA3E809ULL,
		0xFCA2DA096D67EF46ULL,
		0xE8A26E3D942AE21EULL,
		0xF3CF8FBB4E6D764DULL,
		0x95830D6ABA76F322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72E860B6ABFDA3DEULL,
		0x37FB2307EEF9E7E1ULL,
		0xD5A64C065FD2EECFULL,
		0xAA3B200DB54DB19AULL,
		0xD1B680B5C20208C2ULL,
		0xFFA1455EE81B86B2ULL,
		0x5B4F3330AE5AA986ULL,
		0x295873ADAF3699B0ULL
	}};
	t = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF8DB260B2D3726BULL,
		0x79D43AE16DEBA649ULL,
		0x222A6BDA6AFE910EULL,
		0xFA25F50A54CB89C9ULL,
		0x93B12B883EDE2AADULL,
		0x0B3A6392EC19FE23ULL,
		0x2569378E50141B86ULL,
		0x651C54D35C5EBCA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF8DB260B2D3726BULL,
		0x79D43AE16DEBA649ULL,
		0x222A6BDA6AFE910EULL,
		0xFA25F50A54CB89C9ULL,
		0x93B12B883EDE2AADULL,
		0x0B3A6392EC19FE23ULL,
		0x2569378E50141B86ULL,
		0x651C54D35C5EBCA4ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA420A72837D9F409ULL,
		0x019CB643EF7D4DF9ULL,
		0x51C2372CBFFFB0E4ULL,
		0xDDD91D24C5833ED2ULL,
		0x093B74B4549F6436ULL,
		0x6773C9337ACA6021ULL,
		0xC399972C4A63150EULL,
		0x6E33C8EEE51D6D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C9AEE35C9F76F9ULL,
		0xC786B584011E417BULL,
		0x88FAD5EA11D487E8ULL,
		0xCE3647E104755447ULL,
		0x44CAE1FBAAF36023ULL,
		0x6B7E04331F12DF6DULL,
		0x90D03ECDCC4BDB4DULL,
		0x73C8E25582AF311BULL
	}};
	t = -1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933E71401E02F427ULL,
		0x3F48EE04A233186CULL,
		0x969E87F0D171EE35ULL,
		0x60427DEEA8D239E6ULL,
		0x26E1103344846C2BULL,
		0x3A3514BD8EF8AF83ULL,
		0x7FE2C543DCA61103ULL,
		0x3CF747D321EE7593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C218B2F5AA05F7ULL,
		0xC6B443E54AE67304ULL,
		0xC45A1B9949101F0AULL,
		0xB06360CE92A4CF5DULL,
		0x194CC16910022EEBULL,
		0x8199ECA758E845FBULL,
		0x839291347EB94218ULL,
		0x0E4A1CBD920807DAULL
	}};
	t = 1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C36A436F7FAB1D6ULL,
		0x93AFCEAC5A75ED9AULL,
		0x6DB4CC5145C9194EULL,
		0x9609523AAB86813EULL,
		0x2FABE7EF2637E7C2ULL,
		0x61EC6DB790567783ULL,
		0x1EC753CDB522E529ULL,
		0x897A803679F60CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C61289C5739D418ULL,
		0x9F15C9FFBF8D4062ULL,
		0xAC318E94F64A7C96ULL,
		0x08755CEB72AA36BCULL,
		0xEF3F1FA55E853307ULL,
		0xCB71121ACB3ADDDDULL,
		0xB805BD093C86B265ULL,
		0x51FAC4F44A86DC76ULL
	}};
	t = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC999FCDBFC1683CULL,
		0x3651EDFDD2140215ULL,
		0x5AE0BD18658D23D0ULL,
		0x3D6305F6CDD4139CULL,
		0x0D7FA175C6BEBCEFULL,
		0x53825E9A286D8A13ULL,
		0x6E9717146E27C72AULL,
		0x70F0465F2FA7F501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC999FCDBFC1683CULL,
		0x3651EDFDD2140215ULL,
		0x5AE0BD18658D23D0ULL,
		0x3D6305F6CDD4139CULL,
		0x0D7FA175C6BEBCEFULL,
		0x53825E9A286D8A13ULL,
		0x6E9717146E27C72AULL,
		0x70F0465F2FA7F501ULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD44BFE87615B2D64ULL,
		0x1366604C50387491ULL,
		0xE217C475A0706A7EULL,
		0xE372F359CE9DE5A2ULL,
		0x9C3041FE7F28A313ULL,
		0x8CC3953B6B8E9ABBULL,
		0x70ACA6723058DB0BULL,
		0x26ACC8835423528EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5AA4466158C3EF2ULL,
		0x3C2E24851517659BULL,
		0xFFDD3034116F70E7ULL,
		0xA188B374BD99809FULL,
		0xC5094404E5B4E3CBULL,
		0x02FDBB28188873B5ULL,
		0x05A627D51E58788BULL,
		0x6D8A944101C054EFULL
	}};
	t = -1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B583AE4270D7A1ULL,
		0x4ABF9E6445A5DFB4ULL,
		0x5B882A1D7C9CABF1ULL,
		0x03473E74A5E47AB3ULL,
		0x5FC6920123220438ULL,
		0xC4CA4F769566080BULL,
		0x078F71ABAFC0457DULL,
		0xD481CC02A4B4B87BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x290D88770E15DD48ULL,
		0xB07C170442EEA489ULL,
		0x5ADEC54FBA16AE0BULL,
		0x2CD513C42A720A55ULL,
		0x35C3E18064157A76ULL,
		0xA9060F01469CE709ULL,
		0x07F427C196CF5CBCULL,
		0x20717E836D905E17ULL
	}};
	t = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x752C41A60E175830ULL,
		0x49E2A4E02E91E00BULL,
		0xFB76C99962AF0EB8ULL,
		0xB227D4FDB436A904ULL,
		0x188212792ED9E451ULL,
		0xF88EFCE1A720F2E9ULL,
		0xD7E8564562A2A2EBULL,
		0x4663DFE7DA55481EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x104F84DA3730B86CULL,
		0xDDB9AE0C61F64C5BULL,
		0x3F3FBD181E783CF7ULL,
		0x9A581CDA9EF5DCDDULL,
		0x622E2213BB6FCDE5ULL,
		0x53EC4D08F9A1DFC7ULL,
		0x37D1094179560AFAULL,
		0x5A2C1AE4CBCF5D6FULL
	}};
	t = -1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD635D307F18C107BULL,
		0xE1826F8629FE5507ULL,
		0xD716AA0D973F73D9ULL,
		0x067FAFCEAE040769ULL,
		0xA4581E12E8A67BBCULL,
		0x63D8C54422BA9EE1ULL,
		0xE3F88BB3AB1265E5ULL,
		0x4B200F420F0BE04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD635D307F18C107BULL,
		0xE1826F8629FE5507ULL,
		0xD716AA0D973F73D9ULL,
		0x067FAFCEAE040769ULL,
		0xA4581E12E8A67BBCULL,
		0x63D8C54422BA9EE1ULL,
		0xE3F88BB3AB1265E5ULL,
		0x4B200F420F0BE04DULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0248355CA102040FULL,
		0xBB4DED09964132A8ULL,
		0x35DA9C92743B7849ULL,
		0x2A4AFBF9687CD244ULL,
		0x1CAF5702E700453DULL,
		0x9C28B5317064C06BULL,
		0x54ED78D26A057D68ULL,
		0x90D2014866F25A37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32A604E31CF05C6ULL,
		0xAF2ABD76EDC5590CULL,
		0xED8D338E933FD6BDULL,
		0x93762F33739FCB64ULL,
		0x7BEB5075E2414BB1ULL,
		0x07028E49670D7723ULL,
		0x229F30CB1FCCDB23ULL,
		0x9646B780F70F2DEFULL
	}};
	t = -1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x951EEF87233E49ADULL,
		0x437D70DCA0587197ULL,
		0xA2C7385CAE5E23C4ULL,
		0x18B8578CA0FA6AAAULL,
		0xE076C9B4C3E351E0ULL,
		0xCE7B45BB323468BCULL,
		0xA759E899EE73D02CULL,
		0x41FB3D0A70E14504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0ED629D2109C95BULL,
		0xCA6A94A2F4C99B8EULL,
		0x107CC2F0C5E76D24ULL,
		0xED29B4EE4138FDFCULL,
		0xA13F5248C257EE98ULL,
		0x0531E725960D2D11ULL,
		0x3D4D5F4287DF37EAULL,
		0xC0A40E0D11E5C669ULL
	}};
	t = -1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4DFB170E012A448ULL,
		0x2C573F5F72B551FBULL,
		0x0F8DF5AE62D497B0ULL,
		0x3E28AFAC31229C1FULL,
		0x64882961D5E275A4ULL,
		0x767607729B2C8E0BULL,
		0x1FDC3A3967381AFBULL,
		0xB2A74A4741DEF883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148FE01811A9A6DBULL,
		0x9EA0D1DEE5D65C18ULL,
		0x20F0B6314D07B91FULL,
		0xA59D5DD831976BC8ULL,
		0x57E14CF5B64998D1ULL,
		0x8A12A052ECAC755FULL,
		0xC156B3956C3FF03EULL,
		0xEF9E63976E483D8CULL
	}};
	t = -1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DDC0BBD4D7CA062ULL,
		0x3FF37F03742A1CFFULL,
		0xBE0A112D746CF874ULL,
		0x52823B1EC8848364ULL,
		0xDA75EAC6122C3703ULL,
		0x2D8EE3B162092F2EULL,
		0xDB068E5AE7B57D6EULL,
		0x01134ECBD335B7DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DDC0BBD4D7CA062ULL,
		0x3FF37F03742A1CFFULL,
		0xBE0A112D746CF874ULL,
		0x52823B1EC8848364ULL,
		0xDA75EAC6122C3703ULL,
		0x2D8EE3B162092F2EULL,
		0xDB068E5AE7B57D6EULL,
		0x01134ECBD335B7DAULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8964947176668402ULL,
		0x39E882788D10DC6AULL,
		0x1176058FB83D5FA5ULL,
		0xC113DC88C3DFDE9BULL,
		0x0028B2695293C8FFULL,
		0x2FDC94B236E688D5ULL,
		0x7AB363EFBD26E33EULL,
		0x5AE57F0308C2A878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x816446F02B9CB94EULL,
		0xDA2DD40643F63EADULL,
		0x544A52266D8CC78DULL,
		0x5748C3DE87FF8189ULL,
		0x17E8852438147851ULL,
		0x20230327F8378CC6ULL,
		0x0E5B8A3FD4938FF3ULL,
		0x19E8B6432530660AULL
	}};
	t = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29F3509FD0858B6FULL,
		0xB9E02E09A954F67DULL,
		0x3A8ABA08AC57713FULL,
		0xA6BDC6CEDF185A82ULL,
		0x68D4425B6A82E9FAULL,
		0xAB7E9319B5BAB4E5ULL,
		0x47CF560BFA65709AULL,
		0xD69B136ACE548F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67B4F5BAD776F83ULL,
		0x17633653B29E914EULL,
		0x39178C6077495E20ULL,
		0xCC1D2DB5236F2B38ULL,
		0x668B970BA21C5BD5ULL,
		0x2E693967F545035FULL,
		0xE269B4CF4F50528FULL,
		0xF29CBC415E541E41ULL
	}};
	t = -1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x206739AE49750E8EULL,
		0x27D4919CFD319F6FULL,
		0xB64D96F28BF173B1ULL,
		0x6589F9EAEFE40D09ULL,
		0x452BE4895C478132ULL,
		0x6CEFFDC5BF257008ULL,
		0xA32DF865AE8F447FULL,
		0x604116CCF8C2356DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0B96E082055242CULL,
		0x4B53BDFA1C2413A2ULL,
		0x27DE5D14F5170377ULL,
		0x44B5DC92C9BE8C46ULL,
		0x8CF565B13E7F8E0FULL,
		0xA6A02BC1B0C03413ULL,
		0x5A3F222594581159ULL,
		0x75453C54B22DC742ULL
	}};
	t = -1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31DC1808CC9639F6ULL,
		0x7B87A740D392DCBEULL,
		0x9051386B1849FE47ULL,
		0x942327476CB09D26ULL,
		0xB5F9C6241651F63FULL,
		0x2D54452A1529A08DULL,
		0x4B873F6B6FAA6ED1ULL,
		0x5786EA02D2BD254DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31DC1808CC9639F6ULL,
		0x7B87A740D392DCBEULL,
		0x9051386B1849FE47ULL,
		0x942327476CB09D26ULL,
		0xB5F9C6241651F63FULL,
		0x2D54452A1529A08DULL,
		0x4B873F6B6FAA6ED1ULL,
		0x5786EA02D2BD254DULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D88C658C9EE5CDFULL,
		0x254009262233C953ULL,
		0x8C930E13F8F5B71FULL,
		0x6B23BF4CAF8DD66BULL,
		0x401614FC51682594ULL,
		0x5A57F9DC92680EF3ULL,
		0x989FB616C960DA8FULL,
		0xCCB40AD8F3F20E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7924E46668AEADAFULL,
		0x1C7BD6A6902DA1AEULL,
		0x5D7D2589A3086E7FULL,
		0xC14ADE1A01553EADULL,
		0x334EAC69C7E24148ULL,
		0x9D401EC487F730D0ULL,
		0xC5C141D8BE47BD75ULL,
		0xEB43473530088333ULL
	}};
	t = -1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD045F7C3941ECF39ULL,
		0x9403AD5E4179B066ULL,
		0x9D7F7C4D0EE86BEEULL,
		0x111007B67B7E9E57ULL,
		0xEB7D8E4838815FBDULL,
		0xE29F079850E34B39ULL,
		0x519D8543BC20E63EULL,
		0x8D213B3D5D7BB796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0570738E0258F3ULL,
		0x82D028FA0D4C4FACULL,
		0x558210D4DCD6D203ULL,
		0xF7514845BAF31723ULL,
		0x8B3763EADE9E4633ULL,
		0x241A7B2EFBD69049ULL,
		0x86404CFBE4313CECULL,
		0x776C8F73F286FFBBULL
	}};
	t = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DC423C93039B0C8ULL,
		0xF49CCA8A76C5CEFDULL,
		0x2A2529EFC84DCAAFULL,
		0x95959AB164855A62ULL,
		0x0722285E5A355234ULL,
		0x2AA652C4B859766DULL,
		0x558E9C125C4F1D3DULL,
		0xDF011E0DFE60B160ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A55CCC803CE4ACULL,
		0x406BAF9611A1AC54ULL,
		0x993E15C15D161B3EULL,
		0xD00FD573271D9252ULL,
		0x363FE9AEF507C14EULL,
		0xB741957D44A54706ULL,
		0x61E36958F41EABBFULL,
		0xE62BC7A64DBBDA1BULL
	}};
	t = -1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ABACF3C551EF25DULL,
		0x7902D3ED15023EE8ULL,
		0x10C9C13B2097FF6BULL,
		0x42D8C5D9E1875B45ULL,
		0x216493A6EBAC2F6BULL,
		0x7FD08FEB47B7E31FULL,
		0x1BE512ABBBEBD808ULL,
		0x24A6A3D82BCAB0ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ABACF3C551EF25DULL,
		0x7902D3ED15023EE8ULL,
		0x10C9C13B2097FF6BULL,
		0x42D8C5D9E1875B45ULL,
		0x216493A6EBAC2F6BULL,
		0x7FD08FEB47B7E31FULL,
		0x1BE512ABBBEBD808ULL,
		0x24A6A3D82BCAB0ECULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17220710C69E862FULL,
		0x80F54EB48F053DC3ULL,
		0xB9A5D925DB0B62CBULL,
		0x2BD9F053CA6211DFULL,
		0x6E9CC7BE37E0043FULL,
		0xF2DFDB4B622614D7ULL,
		0x3BC6A6EB6E9A52F4ULL,
		0x19BD787F4DC1DC25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716AD5AA2AA92655ULL,
		0x377A493DBD7A0CF9ULL,
		0x0A0BC202925EE3F0ULL,
		0x10C6EC8FD6A7495DULL,
		0x08BB9FDACC0D7D23ULL,
		0x868F4964E9967086ULL,
		0x6887B7920FACECDFULL,
		0xD5B5B871956E5F18ULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x390DAF4097650884ULL,
		0xBB29B07743DEB935ULL,
		0xD4649DC008A12718ULL,
		0xEB8DB3525E9DC96CULL,
		0x013F9A56E20879B7ULL,
		0xC27465E510C0C7D1ULL,
		0x53250EA48EE12FDAULL,
		0x41D031BCA7867C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x450C531476C0FC43ULL,
		0xD0BE9108FF75F5E2ULL,
		0x04BFC0E2F05658ADULL,
		0xF3EFC42E93EC8940ULL,
		0xF070CE7E6BA09949ULL,
		0xBF44F231446A9743ULL,
		0x4CCF26DD7394381EULL,
		0x2D1E7F2A8D2ABD5EULL
	}};
	t = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3946C75107A304C9ULL,
		0xEEF92329D9263998ULL,
		0x449C3819E436F16FULL,
		0xB804524279112E47ULL,
		0x798CE2C16C31F6ABULL,
		0x002B6E71F4790C2EULL,
		0xCC83D757F9247F39ULL,
		0x9A753E21E2DADC25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EC236969BAEDAE0ULL,
		0xF4F26586A4F69427ULL,
		0xA295681FBA3A648EULL,
		0xC091979AE2265E41ULL,
		0x51A01683EB7BBDC9ULL,
		0x10BB995D424BE58EULL,
		0x70AC103F20F7FC18ULL,
		0xC96B95876342CD72ULL
	}};
	t = -1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129303A0832D1070ULL,
		0xCC59686A602DC3BDULL,
		0xDCDDAD998AA91AFDULL,
		0x3005D5D99859D32CULL,
		0x3C3665D96D96F303ULL,
		0xFCEB41449CD332B9ULL,
		0xF7983BC10C2ECADDULL,
		0x7038022B3A261F89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129303A0832D1070ULL,
		0xCC59686A602DC3BDULL,
		0xDCDDAD998AA91AFDULL,
		0x3005D5D99859D32CULL,
		0x3C3665D96D96F303ULL,
		0xFCEB41449CD332B9ULL,
		0xF7983BC10C2ECADDULL,
		0x7038022B3A261F89ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86F9FE29B118F621ULL,
		0x040C7C63CAA73B0BULL,
		0x572CEB0685C93581ULL,
		0xB871029BD9376351ULL,
		0x594FE9D0CFA283D9ULL,
		0x273DD7D53A219571ULL,
		0xBFE18A3F8B847D61ULL,
		0x7C35D8E5F5A02D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E21A4270E870B84ULL,
		0x598ED7B28D2B38D3ULL,
		0x21D61DEF3C31A648ULL,
		0x14F9DA708FD8BDAAULL,
		0x86865A17D7F50EB1ULL,
		0x514553C310A75F9AULL,
		0x04E1B2AFDC60DE1BULL,
		0xD2B71A228DB7301DULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4826DEA11EBA50BULL,
		0x477C1997EE930508ULL,
		0x90C332117827234DULL,
		0x3594EDE9ECD05CA1ULL,
		0x731DD81A9FD51BA2ULL,
		0x02064C36A496D451ULL,
		0x8C42F05B624AFA53ULL,
		0x076C3E26DD7404F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DECF8DD9EBC4CA1ULL,
		0xCC288D29B26C7A1AULL,
		0xB1953354F3308B02ULL,
		0xBB298C82715097ABULL,
		0xC1AFAE2E227CD034ULL,
		0x83A4B107D91F539FULL,
		0x36FDE415DC217A7FULL,
		0x29017B616208AF99ULL
	}};
	t = -1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x020E3F2C19DB723BULL,
		0x0DA450071902B914ULL,
		0xD98CEA16AAFB0212ULL,
		0xE138829838B8920BULL,
		0xCDBE7632C11A2499ULL,
		0x4FE7CF0E30818EF7ULL,
		0xD3C4BA145E3FFD2BULL,
		0xF2194DC3D02145ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B630E835473833ULL,
		0x89527CDF3E0812DDULL,
		0x651622814C87A5D7ULL,
		0x191727B95DAE9BAAULL,
		0xA3848E3C5C542CAFULL,
		0x9014FF0788825061ULL,
		0xAD5AB704BDC4D1F8ULL,
		0xB0BC1D989E3CC027ULL
	}};
	t = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F72FE5C9F93E499ULL,
		0x18E23CEDB857C568ULL,
		0x3ABDA8AC0516F947ULL,
		0x9976174D01BF44F9ULL,
		0x60E3167568438F8DULL,
		0x9F378259E5316166ULL,
		0x5180EACFD3FF47BFULL,
		0x35E42BD7C1F4C24DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F72FE5C9F93E499ULL,
		0x18E23CEDB857C568ULL,
		0x3ABDA8AC0516F947ULL,
		0x9976174D01BF44F9ULL,
		0x60E3167568438F8DULL,
		0x9F378259E5316166ULL,
		0x5180EACFD3FF47BFULL,
		0x35E42BD7C1F4C24DULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6389EEDF37247C71ULL,
		0x8B06EA2569222443ULL,
		0x9BC124336877F361ULL,
		0x9589D182E7FE0E7CULL,
		0x69314BF7FB623086ULL,
		0x497FDC4BE61962FAULL,
		0xADC66986696CD03DULL,
		0xE6A64DFA98E31E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x829019C4D3287BC7ULL,
		0x87AE25B8EF2E8AC2ULL,
		0xFFADF19E66591FBEULL,
		0x44AC54560415313AULL,
		0x696D7CF1768B39B2ULL,
		0x9B88E9D29E534D13ULL,
		0x9A0D414488BD412AULL,
		0xECA34E5668360C57ULL
	}};
	t = -1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8535E5EBBD89BCBULL,
		0x52405F966D18E57EULL,
		0x52FC013797B64313ULL,
		0x3829DD67ED7E8D1AULL,
		0xA261B85248C0A7CDULL,
		0x79435DB9972B47B4ULL,
		0x45201039242E79E1ULL,
		0xFD19F45992E58999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF40F521F11529D1ULL,
		0xE460369820014F50ULL,
		0x4E0D063B67BA23E7ULL,
		0xCF666CB7A78F28CAULL,
		0x7DAA1DC26E1EA695ULL,
		0x40652E9D7241AF99ULL,
		0x8EB44A8245AAA9AFULL,
		0x362F24B6F196FEA8ULL
	}};
	t = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF720A39CBE9868A6ULL,
		0x50E535A9544ED475ULL,
		0x7DF4D27CACC07BDCULL,
		0xDA299148036A9D31ULL,
		0x114B92C90B0206EDULL,
		0x64EAA109EED4D0DCULL,
		0xB05DA6A1DE37EEA8ULL,
		0x80CE6E87C9F0D51BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4DB6DAF0CD9600EULL,
		0x524B4F7EEB13CD0FULL,
		0x797A998E9B7D6E5CULL,
		0x6DD99B7EC433F369ULL,
		0xDB1A9B16E0537D91ULL,
		0xE101EA6A84584BA5ULL,
		0x8D6586BA0C00EC04ULL,
		0xD6ADC8A36FEABE57ULL
	}};
	t = -1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75CCEE4399EC05E1ULL,
		0xC66E3CA2F7ABBC83ULL,
		0xE97FCFF02D6EF89DULL,
		0x899651CCBD8429D6ULL,
		0x10955486DD25966BULL,
		0x118964D541BB248BULL,
		0x846C3F8C4815A7D2ULL,
		0x33AEF47C7BC65477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75CCEE4399EC05E1ULL,
		0xC66E3CA2F7ABBC83ULL,
		0xE97FCFF02D6EF89DULL,
		0x899651CCBD8429D6ULL,
		0x10955486DD25966BULL,
		0x118964D541BB248BULL,
		0x846C3F8C4815A7D2ULL,
		0x33AEF47C7BC65477ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC20FE860F445F7ULL,
		0x286EFC9DF1B0E2E5ULL,
		0x8416075BC2ADCBB2ULL,
		0x31381F20537EA3D8ULL,
		0x0203AEB092624756ULL,
		0x1ECC260643561C0EULL,
		0x7DCA516C54BA5D67ULL,
		0x93FC9D5053CE2C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEC4684454977A8ULL,
		0x4D45DDCA07880267ULL,
		0x906CC07105EE4141ULL,
		0xB385B602EB5C0B04ULL,
		0x65D84BC50CA429AFULL,
		0xA593A347B4D27756ULL,
		0xF93715B158E45780ULL,
		0x507FCE8745C7F7B0ULL
	}};
	t = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76527972EBEEAC3AULL,
		0xD8139F30B7CF509EULL,
		0xD7C296DCE7A33B5CULL,
		0x4CA156ADFBD4CE42ULL,
		0x195104F6C4D4F71DULL,
		0x0DF643CF0DB6E8CCULL,
		0x8B0B04B69B2A45B4ULL,
		0xB2E35CB5D1674414ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E565BE956859B16ULL,
		0x1FB6EB69C256E0EDULL,
		0x4EC62996EF3545B1ULL,
		0x335C59F04A014906ULL,
		0x9291828C675B8833ULL,
		0x2EB4F2F9F9ADD168ULL,
		0x70E3CBDE4ECCA1F0ULL,
		0xCE67A205109CB802ULL
	}};
	t = -1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x044EE42E255F3D96ULL,
		0x48FA4630EFF6945DULL,
		0x2D7451C264233752ULL,
		0xF990A79063467F84ULL,
		0x1A4EAFA3DD6E856BULL,
		0x36625EF8AA32F732ULL,
		0x917779056129F33FULL,
		0xBE1798545258A343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20764ADA1D70E27FULL,
		0x7BEFC0AA320640E5ULL,
		0xFB7A7A96D58A4AA2ULL,
		0x2D208D024E7275E0ULL,
		0x8942024CB5BDD216ULL,
		0x1EC940088266D222ULL,
		0xDAC8BD3FFCD67F44ULL,
		0x95CD92D3E7253015ULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66279496507668F7ULL,
		0x9930E550D2DC8816ULL,
		0x95EA0AB76906D87AULL,
		0xEF9454AA70397ED6ULL,
		0x23A4C0EBC70AE18BULL,
		0x816465E272B20B7CULL,
		0x16DDA3FC1E01503BULL,
		0xFFECB375F56A6699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66279496507668F7ULL,
		0x9930E550D2DC8816ULL,
		0x95EA0AB76906D87AULL,
		0xEF9454AA70397ED6ULL,
		0x23A4C0EBC70AE18BULL,
		0x816465E272B20B7CULL,
		0x16DDA3FC1E01503BULL,
		0xFFECB375F56A6699ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x552188807BF42DEDULL,
		0x2D6990795312E566ULL,
		0x50139C091590C9C5ULL,
		0xAEE3591E34572137ULL,
		0x1E1C5014018F6936ULL,
		0xDA727313212177A6ULL,
		0x681953A09DA927F4ULL,
		0x8B41FFEC7959BA0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57EAB18F124E908BULL,
		0xF37608634368DF23ULL,
		0x5B2631DD73293732ULL,
		0x9ACFF1342E0BAC32ULL,
		0x16E31E184E690CE0ULL,
		0x7FE65EB9D3F699CCULL,
		0xDF6464B4B64DAEA9ULL,
		0x716DE5E7CDEABC84ULL
	}};
	t = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4FD261BF5895A0ULL,
		0xC7919CB62F04375BULL,
		0xE5D0211DD7C31137ULL,
		0x96B5FDC2E9EE302AULL,
		0x8D89119E3139DD55ULL,
		0x39BD25FB13B4923BULL,
		0xA563E73CCEBE3E08ULL,
		0x9770131A9D44FE36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26348305511E73E4ULL,
		0x4B6775F6D4994904ULL,
		0x1A8EF540D680A90AULL,
		0xB253CA0B2C96FA23ULL,
		0x2EC68C608114D6DEULL,
		0x9BB7EFFFE509AC3CULL,
		0x49E9D6FC5F6B82F2ULL,
		0x8D46A6C4403DD2CAULL
	}};
	t = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1582AC9AB2B4041CULL,
		0x6BCED785A49CBFA0ULL,
		0x9DBD147FF06FDDAFULL,
		0x9CE0E4B670FC6197ULL,
		0x993676ECCF63C9C8ULL,
		0x5DEB540699D34B1CULL,
		0x7702E8548F6B7480ULL,
		0x71CBCB1C2E313A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5485D557F9F3D20DULL,
		0xBC9A857C9CD94D33ULL,
		0xD5DD8FF20164F429ULL,
		0xCD61EDCAEB3C2248ULL,
		0xF67872510F17E698ULL,
		0x681658CE8D718675ULL,
		0x085AD9744521B291ULL,
		0x5E6E9541F3426F8AULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC914907D3789AE5ULL,
		0x03D339034EB41D06ULL,
		0xD668567C260FF69AULL,
		0x377D18C607B23B65ULL,
		0x2F1FFCF2B4048327ULL,
		0xBCA8A0CCF86F2A06ULL,
		0x07821C2127DD0BC9ULL,
		0x2140171F89CCC611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC914907D3789AE5ULL,
		0x03D339034EB41D06ULL,
		0xD668567C260FF69AULL,
		0x377D18C607B23B65ULL,
		0x2F1FFCF2B4048327ULL,
		0xBCA8A0CCF86F2A06ULL,
		0x07821C2127DD0BC9ULL,
		0x2140171F89CCC611ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D0C48D88093C669ULL,
		0xCF20BF7A6DAD2E0BULL,
		0xDA33C89BCF40423FULL,
		0xEF28432733282968ULL,
		0xFB7226936E080B54ULL,
		0x87A20813738A298DULL,
		0x795C2D5EEB437722ULL,
		0x9D10729DBA9C38D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC58A54026243E4ULL,
		0xFED96F9981EF4721ULL,
		0x1ED5FD21776A018AULL,
		0x52ABF24526E9B8EFULL,
		0x86EE96C48DEFF010ULL,
		0x7B61118C82E5D66BULL,
		0xBD5147EEF6102FDAULL,
		0x7B6F55E86F648269ULL
	}};
	t = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4D6948631BF1A2BULL,
		0x45D03BE9F55642D3ULL,
		0x8D4696EC68884EB9ULL,
		0xA3FB0F34A79A94C2ULL,
		0x58C70608EFA3D58FULL,
		0xF4C081BD24A75364ULL,
		0x919766989AD06CF3ULL,
		0x3AFFDA5308F38763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFA1F8A696E6383ULL,
		0x0B064E1ACE040DDBULL,
		0xFE491E7E57E8DB6BULL,
		0x3656180FF1AFECDBULL,
		0xB2DD4B1A4DFE01E6ULL,
		0xF033BFCD7FF3124BULL,
		0xD540642B85791BF0ULL,
		0x28EB148EAE5B183BULL
	}};
	t = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCB020FD79FF1BA8ULL,
		0xE5230051C7C553C5ULL,
		0x811E911D6FED05BBULL,
		0x8A211448A53A2FC3ULL,
		0xC656F618A9AA4E51ULL,
		0x38997E9A053B3E17ULL,
		0xF19A05611DED6598ULL,
		0xB1428C15F04BE2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D3725358639824ULL,
		0xAAA69852F248B5D5ULL,
		0x323074D9C67D4F18ULL,
		0x2450D6534B9EB117ULL,
		0x47615EF126EC961DULL,
		0x640159D4A04A43D6ULL,
		0x5DE54B11799345A8ULL,
		0xC7F3F2DACAE39649ULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EF043B69832C5A1ULL,
		0x2651DE7C85C24FB5ULL,
		0xDF6617AE43F00FE6ULL,
		0xE4D3B3DDE6259AB4ULL,
		0x338AEFA74B538AC1ULL,
		0x29895AD820B8E16DULL,
		0x606FA49D53C5593BULL,
		0x7395328D15630AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EF043B69832C5A1ULL,
		0x2651DE7C85C24FB5ULL,
		0xDF6617AE43F00FE6ULL,
		0xE4D3B3DDE6259AB4ULL,
		0x338AEFA74B538AC1ULL,
		0x29895AD820B8E16DULL,
		0x606FA49D53C5593BULL,
		0x7395328D15630AA5ULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC346A3EA6B3DC3B5ULL,
		0xBEFCC522B036E119ULL,
		0xB2CF4A079C50B02BULL,
		0xCF32DBADA1963B10ULL,
		0xFDD401740C744B2FULL,
		0x88F4322E0D731C7AULL,
		0xBAEB6DD4D9234DF6ULL,
		0x70F7BD62F79A55BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2BE539E8C5D28DFULL,
		0x3111710C6FCC3911ULL,
		0x2253D7753ECD266BULL,
		0xF7A2DFE0633BFBEEULL,
		0x36F50A48EF1D3F0AULL,
		0x5C3E55FD0D381B03ULL,
		0x594C0771870FBF77ULL,
		0xD5F901187D2E94E7ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2A400250A56DC40ULL,
		0xC6E2E6272428FB4EULL,
		0x347B83A6EB5E70F5ULL,
		0x760398A1F17A300CULL,
		0xC2485E9F75D9D004ULL,
		0xDC3416665BFC314FULL,
		0x3D3C8823C19529D8ULL,
		0x420FCCBF8FFC651AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3980E06CB3715A16ULL,
		0x9AAAA2C4CF409489ULL,
		0xC7B63CBA606C8B17ULL,
		0xBA0CC55C5B51D465ULL,
		0x2D31C760B5101566ULL,
		0xEC83022FF04D113AULL,
		0xBBD79F675199059BULL,
		0x94DD91969F847981ULL
	}};
	t = -1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x421938B3163D1D86ULL,
		0x6FFE34930C3DAE50ULL,
		0xDDE9B65B8DCD70C3ULL,
		0x6A452C1940EFDF61ULL,
		0xCE3D0A573D256F7CULL,
		0xBE1B66E3FC3383D4ULL,
		0x862C91B7C0BDCD31ULL,
		0x0CD40F43FA60CFB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF7B9576C6C7E9B4ULL,
		0x02FDA85316591A5AULL,
		0x52704B2AAA4ECD0BULL,
		0x84E8B6E9925A1029ULL,
		0x636F79C8284EB7C1ULL,
		0xA8E2B6E89941B582ULL,
		0x67685012440F5913ULL,
		0x6F2E50427EF3AA40ULL
	}};
	t = -1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80DF09872F2A3BD4ULL,
		0x57EEFF3952181C2DULL,
		0xE56FD04953DAD17BULL,
		0x101C0AF8C88A7534ULL,
		0x9765B17B09311CC5ULL,
		0x752AB292B2AB284FULL,
		0x111A628C336F5256ULL,
		0x6D874FF96361CC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80DF09872F2A3BD4ULL,
		0x57EEFF3952181C2DULL,
		0xE56FD04953DAD17BULL,
		0x101C0AF8C88A7534ULL,
		0x9765B17B09311CC5ULL,
		0x752AB292B2AB284FULL,
		0x111A628C336F5256ULL,
		0x6D874FF96361CC2CULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEDC478AE38CC1A0ULL,
		0xED0C735A4FFBBB6DULL,
		0x839E3FF7312F7782ULL,
		0xDF49F541A31C88EDULL,
		0x314805F56190360CULL,
		0xAA6BC176279ED0FCULL,
		0x187843FEB6B8DFB4ULL,
		0x3E09721B354C56E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DE253DD2F103ADULL,
		0x9CC7855F328CBC4CULL,
		0x6D0A4F7AF7BC661FULL,
		0xEA1226E256A41CCDULL,
		0x2DE777766021C101ULL,
		0x239ECFC20BD03B93ULL,
		0x4CA3800F02CECEAFULL,
		0x76591DBB3AD00D3AULL
	}};
	t = -1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0047C4149C6BDE10ULL,
		0x46B0293F457EBD62ULL,
		0x0A0D5D2A21152801ULL,
		0x4C9BC226EB4B75FCULL,
		0x232AB78394EC687CULL,
		0x2463F5481AB75B66ULL,
		0x31694325BA4FB449ULL,
		0x74B91C4D8C11AA66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x090A3095BDBA990AULL,
		0x972ABA80F604690CULL,
		0x1937993F2494B8CBULL,
		0x7AFA9E260F75C70EULL,
		0x2549721FC3CE5262ULL,
		0xB95C342371446686ULL,
		0xA2DB4901678F6B58ULL,
		0xEE7448840C569CD2ULL
	}};
	t = -1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CB218F8C6A31685ULL,
		0xE0D9F87EAAEAE823ULL,
		0xB3F05DF7711AF036ULL,
		0x388C94BEE6A4B61FULL,
		0x013F3A19D4CE852DULL,
		0xCD0B58EEEEC7AE7FULL,
		0xF4AA23EC7865738CULL,
		0x148F162F83A4331AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD492A6FC1170DF6ULL,
		0x0AECDF72D6CA181EULL,
		0xD65DE0449AF5F473ULL,
		0xA1AFB78535069B16ULL,
		0x514E98D9A2D4B143ULL,
		0x8F47E66E50F06EC4ULL,
		0x95D03A9482F82A46ULL,
		0x374F3554889F4D52ULL
	}};
	t = -1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3C7EEE6669193AFULL,
		0x1625978DBD09D4DEULL,
		0x7F8A074336706402ULL,
		0xC21D593882C40DCEULL,
		0x8D7ED2D21463D4A8ULL,
		0x1FC217592D766186ULL,
		0x23351435CCCF1649ULL,
		0x32C71DF87E834845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C7EEE6669193AFULL,
		0x1625978DBD09D4DEULL,
		0x7F8A074336706402ULL,
		0xC21D593882C40DCEULL,
		0x8D7ED2D21463D4A8ULL,
		0x1FC217592D766186ULL,
		0x23351435CCCF1649ULL,
		0x32C71DF87E834845ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CCBC81CF5D89E02ULL,
		0x34EA2A3B600DCFE8ULL,
		0x087569398475A26DULL,
		0x757763BCFDF5E81AULL,
		0x62C92151EC744575ULL,
		0xD7004167E338503EULL,
		0xD610245D8B6CA428ULL,
		0xC77DA60BDD120A2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x090F561910FC88A0ULL,
		0xAA822579B936BEA2ULL,
		0x5360135357573606ULL,
		0x3AA123F998C341DCULL,
		0x4D873909896686DFULL,
		0x0B5056C96D1BFC40ULL,
		0x9E7F83D02A31489AULL,
		0x54031B2F7A73BED5ULL
	}};
	t = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E8CECB6FF63BD74ULL,
		0x482F7D759785C602ULL,
		0x0A5E638B4736D862ULL,
		0xAE763CD695194979ULL,
		0xC25B688D9F817DD5ULL,
		0xCB3B3B1AB7BFE784ULL,
		0xFE4EF4194E85B80AULL,
		0x6925B83E3DB5EBC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D963CD06EAEB449ULL,
		0x4C879DC057EFE743ULL,
		0x407F493928B68C0AULL,
		0xA3CA4F3B852AB85CULL,
		0xE1840F8165F15E52ULL,
		0xEFF50ED509D6315FULL,
		0xECF7730C02429B2FULL,
		0xE0D76A74466502E1ULL
	}};
	t = -1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3FC6F78D035982FULL,
		0x4249993A66E85C12ULL,
		0xF0ADD039026D5E23ULL,
		0xCA4DFC7C79850241ULL,
		0x65F8BCD9B3BB8B4BULL,
		0x3BA18FA8987BC26BULL,
		0x2914E1C5A41279FCULL,
		0x68CEC4437D0680AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E6E87859FD8E422ULL,
		0x3341210215DB6E55ULL,
		0x595A98D8E7394F39ULL,
		0x04A26CD25A1F279CULL,
		0xA13CA772C8F5FC36ULL,
		0xDA7BD3210C8C1BF9ULL,
		0xBED4AC66F9B551A4ULL,
		0xF421B03950FB9351ULL
	}};
	t = -1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE9AAD0CC8FAC93AULL,
		0xE1BCB427A55024D5ULL,
		0x326522E73064CA55ULL,
		0xC3FCAAE553572668ULL,
		0x6657D68645782A6FULL,
		0x051FA8C80C45A939ULL,
		0xE600E60AFC888E7EULL,
		0x63D24DADC00954B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9AAD0CC8FAC93AULL,
		0xE1BCB427A55024D5ULL,
		0x326522E73064CA55ULL,
		0xC3FCAAE553572668ULL,
		0x6657D68645782A6FULL,
		0x051FA8C80C45A939ULL,
		0xE600E60AFC888E7EULL,
		0x63D24DADC00954B9ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x617A206C31EBF027ULL,
		0x57C90504411F27B5ULL,
		0x5678D3324251821BULL,
		0x3E6FFCE2849166FDULL,
		0xC09990999E5148A4ULL,
		0x833135DFE0674CF0ULL,
		0x680AA8FF6491F69BULL,
		0xF484E7405F4DAF14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2ED8314C7B8DEA8ULL,
		0x6825FA878A8874A1ULL,
		0xA4F299909D6FF4B1ULL,
		0xF5F3D596C51B7BFBULL,
		0x216D672A3051E251ULL,
		0x2AEDF270DA1346D6ULL,
		0x291AB0ABBC43AA6FULL,
		0x66F0101674952DB2ULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43DFECE860D31CC7ULL,
		0xB9B16F94A106810FULL,
		0x8758DA4C3225226CULL,
		0xB9CCBD8E58B2F5A2ULL,
		0xB94536D8B5889E88ULL,
		0xF644DA52B936C190ULL,
		0x45C8749E378AF477ULL,
		0x078EA127D2B28DC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A378580EBD3514ULL,
		0xC2A590C04F9F3BD0ULL,
		0xAF0985F3989BEE93ULL,
		0xB4FA06F8B1D5F1FBULL,
		0x1B7D7E3C1F76F21EULL,
		0xF0228F9A1A50B08DULL,
		0x7689A66DFCD5793CULL,
		0x41300585A2CC8A72ULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB36F02A562E7FAE2ULL,
		0xF433D22A5373B8BFULL,
		0x82C969851F74B99FULL,
		0x780EB9C1012ACFD3ULL,
		0xAF0F0A1E7ADEAB1FULL,
		0xEA617911215136DFULL,
		0xE361C546FC3D9A79ULL,
		0xFA9E648B3AD8BC42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA17605A8AA542F10ULL,
		0x865C129B038D078EULL,
		0xE437B960156AE080ULL,
		0xFF1DF529FF63AB94ULL,
		0x7FBB50C82E23D87BULL,
		0xFC6D3D0AF541AB34ULL,
		0x2CAE4E125ED20C5AULL,
		0x01928B8A85A253A3ULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48C4EDEF477FA442ULL,
		0xF8BA06CFF5BBC063ULL,
		0x224D37643DF981EFULL,
		0xC4B1FA5D25BAF6C8ULL,
		0x7C40CEC24E95FC80ULL,
		0xFBBE9559B3099CE7ULL,
		0x07DF05C2493141E0ULL,
		0x7C0AF4E3E8E41088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C4EDEF477FA442ULL,
		0xF8BA06CFF5BBC063ULL,
		0x224D37643DF981EFULL,
		0xC4B1FA5D25BAF6C8ULL,
		0x7C40CEC24E95FC80ULL,
		0xFBBE9559B3099CE7ULL,
		0x07DF05C2493141E0ULL,
		0x7C0AF4E3E8E41088ULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0C7AA1C33241174ULL,
		0x1B589E526C2E94F3ULL,
		0xB2C462B8E376CACBULL,
		0xAB29721024A38CE1ULL,
		0xC12F939D79DC5914ULL,
		0xA9C46CEB2CC9CED3ULL,
		0x988C19D93E0A1A0DULL,
		0x9BD3177D2AD51F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x476A7E7BC3763207ULL,
		0x9D96A60A81E29201ULL,
		0x951E1524CB2FEBA9ULL,
		0x0C844BF5BA8A4326ULL,
		0xCCFA364EBA88D3D8ULL,
		0x9B45A05593A11C27ULL,
		0xF252B8D1E1F2B3A2ULL,
		0x3FC409EBEC0BDD5CULL
	}};
	t = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAB6FB31B798E504ULL,
		0xEAD7F59F903591A8ULL,
		0x21245CF09DE9910BULL,
		0x18A180D5FD9ED882ULL,
		0x239BDFDDAF65E814ULL,
		0x85E3E7430AD45DFAULL,
		0x9A60C7322414F8DFULL,
		0x8F9F717D50FCE26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE966CCE53768BBF2ULL,
		0xF42461FDF6C91B0EULL,
		0xD4E75C1CDC0DB330ULL,
		0x52B7A9CEDAFE6544ULL,
		0x3A1CD470F07F455EULL,
		0x69E4A88A2B542738ULL,
		0xE632C740F422CF76ULL,
		0x0123A59F966BA147ULL
	}};
	t = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC3B4C4BD8743D3DULL,
		0xBEB354AAF3B6F461ULL,
		0x3AE6861E081A8988ULL,
		0x6D30DACD3AA0A455ULL,
		0xF29CA3723379EEF5ULL,
		0xEECB498CF7278B0EULL,
		0x8E7A41283F86B35EULL,
		0x37E8459C7673A9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C28CC7056C63847ULL,
		0x72CBF1541FE4AC9FULL,
		0xDF943F0A67A573B8ULL,
		0x7CCC248C8E74F471ULL,
		0x7A53E06556CC3BFBULL,
		0x634957A77D8034E5ULL,
		0x145D9ED84C439E34ULL,
		0xDF08BE0840B5AAD4ULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F7E4DDB7F5D8877ULL,
		0xBEE5E6A0B2E586D6ULL,
		0x0B41F560C4271CFCULL,
		0xDB0BCDB11816AAFBULL,
		0x76619136FA9D6402ULL,
		0x36273393A0DDEC14ULL,
		0x4F9796532B5648DAULL,
		0x6FC8BE20206B55BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7E4DDB7F5D8877ULL,
		0xBEE5E6A0B2E586D6ULL,
		0x0B41F560C4271CFCULL,
		0xDB0BCDB11816AAFBULL,
		0x76619136FA9D6402ULL,
		0x36273393A0DDEC14ULL,
		0x4F9796532B5648DAULL,
		0x6FC8BE20206B55BEULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x820339E6EECBDA87ULL,
		0x6414285372F52EFAULL,
		0xA82B3AD4EF647076ULL,
		0xDF8A8A219BD8160AULL,
		0x9235FA658B98D28FULL,
		0xE2986916E6A062E5ULL,
		0xF63AFE85583C9BDEULL,
		0x2E3E88307466AC20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x509FC56AA3A97240ULL,
		0x3FC014DAEBBD616DULL,
		0x2EE4312722976FC0ULL,
		0x4D0161CCA58BF692ULL,
		0xF71F9F91FEB95290ULL,
		0x7204FD9546278773ULL,
		0x3A0057E22DCA6927ULL,
		0xF20DF16F7E0D9A46ULL
	}};
	t = -1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF650B8B988ED3ABBULL,
		0x586F298F01844E1FULL,
		0x50508026BA63738DULL,
		0xB229531076FD07FFULL,
		0x7E89FBA638FD7D57ULL,
		0xAB3F4AD9249453A0ULL,
		0xC81EEEF59F30BA58ULL,
		0x323905BC959861B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB906F5C97A769AULL,
		0xD996F638F8EA2AA0ULL,
		0x0A0CB6C3FFBABACBULL,
		0x2C6AA6D3BD4EA71BULL,
		0x95EC5B5B741F7586ULL,
		0x8F9D9E52599B017AULL,
		0x1BDF744C3488171AULL,
		0x058D0286E2482138ULL
	}};
	t = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD82A6F6E2D166461ULL,
		0x7C0158ACFF688C0BULL,
		0x6E960901D4EC2F10ULL,
		0x9FF05B810BD6F02DULL,
		0x39B47AC9DF92FC0BULL,
		0xD0C669C789F385F7ULL,
		0x4A9CF5CB2456F091ULL,
		0x581ED729B9F2B90FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2025703B19D158D6ULL,
		0xA5E75EAD431E6799ULL,
		0xE53C6F72BD334EAAULL,
		0x0C788F135001F175ULL,
		0x07B2BFB407315CCDULL,
		0xD0ACC28628052FE6ULL,
		0xF9944ED68257A311ULL,
		0x95696B79F8FF1F33ULL
	}};
	t = -1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40EED57633EF245FULL,
		0xC4CC0B04F85B0FD3ULL,
		0x1C04EDED1AB4F7CDULL,
		0x837A23C19CF19693ULL,
		0x9AA3436128D97746ULL,
		0x7EA09F5F17A51482ULL,
		0x43F6BC227CE640B9ULL,
		0xF096483314E0AC79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EED57633EF245FULL,
		0xC4CC0B04F85B0FD3ULL,
		0x1C04EDED1AB4F7CDULL,
		0x837A23C19CF19693ULL,
		0x9AA3436128D97746ULL,
		0x7EA09F5F17A51482ULL,
		0x43F6BC227CE640B9ULL,
		0xF096483314E0AC79ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE70C9E2AFE6A3F93ULL,
		0x60608102D9D92D92ULL,
		0x6FFB26A0BDAFC4EBULL,
		0x9FDB1D436C8A16F2ULL,
		0x33BA5B3146830F97ULL,
		0xABBD8B2CC25869F0ULL,
		0x36CD32BBDBA494C8ULL,
		0xC6D37C6BEBDE559AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536B4C9E1BE22410ULL,
		0xE2E30FB28F36BC97ULL,
		0xA7BFE14431CDC812ULL,
		0x02AF06B222D9FCC2ULL,
		0x86C8592561C05EB1ULL,
		0x581943E301385705ULL,
		0xBCA94BBFB278F95FULL,
		0x2C56BB59C577AE96ULL
	}};
	t = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F58A40DB452DF73ULL,
		0x84F8DE205CC3788BULL,
		0x51CFFF1F74D93C03ULL,
		0x8ADE497886523EDEULL,
		0x9675A7CB36DE9CBFULL,
		0x4C4244A6A991FBDFULL,
		0x5FC7BF15E39B8F61ULL,
		0x89D1B15435F5228FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC05376B5B9406B9ULL,
		0x8762B35FF62B5081ULL,
		0x9CE9A6072E98B899ULL,
		0xADB0C9FB47156164ULL,
		0x97CE497823535DD9ULL,
		0x10C1D9F236E2EAD1ULL,
		0xC73E4F73D9F5F66FULL,
		0xECB1B1584D879492ULL
	}};
	t = -1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDF43F1B5FEC6BEAULL,
		0x26112A6CA7649EB7ULL,
		0x2413640BF9B61794ULL,
		0x1ABEF754CF5132F3ULL,
		0x6FEB020D3545E0B8ULL,
		0x3656F2A78539F594ULL,
		0x239860F1FAE2DFB9ULL,
		0x7FB88E30A702D85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3032D6DC08A10D5FULL,
		0xCBB4F3F6D163325FULL,
		0x981021AF13E3EAFBULL,
		0x5CFCF0988A6070DFULL,
		0xCFA49C23DA45B8C2ULL,
		0xE4BC0C061EADAE5DULL,
		0xD1E23A73548B0293ULL,
		0x9C6480D3F1A68BF3ULL
	}};
	t = -1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA30288094AC4A37ULL,
		0x26281BD10ED3F3CBULL,
		0xF826F7F8FABE1370ULL,
		0x91B7643C15C9B968ULL,
		0x5731C244FCE2C197ULL,
		0x4ADCF579EEF07AA3ULL,
		0x76FA193A2533F7B6ULL,
		0x64F338E6BEA77057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA30288094AC4A37ULL,
		0x26281BD10ED3F3CBULL,
		0xF826F7F8FABE1370ULL,
		0x91B7643C15C9B968ULL,
		0x5731C244FCE2C197ULL,
		0x4ADCF579EEF07AA3ULL,
		0x76FA193A2533F7B6ULL,
		0x64F338E6BEA77057ULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A5FDAE52453EEDBULL,
		0x7A35166DA77562D4ULL,
		0xFE44BB1900171364ULL,
		0x730132166621C4F4ULL,
		0xBE8187E34F8EDFACULL,
		0x7BB8C90D728C6C77ULL,
		0x4815A8E467471E32ULL,
		0x67106C0647EDDF3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7902F3A15577D365ULL,
		0xB7AD91711F66319DULL,
		0xAC29A44F4A94A3F9ULL,
		0xE77D3CA07075A725ULL,
		0xBB737B61D770DC18ULL,
		0x1688257FB0407033ULL,
		0xCD11DECD6396B6C9ULL,
		0xB705188880E5A43EULL
	}};
	t = -1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD13BF8B8D92CD123ULL,
		0x002BD0B487D32868ULL,
		0x648576B2DEC68BC6ULL,
		0x7FD23A8120CBF973ULL,
		0x0D6275DC11F3A061ULL,
		0x3874C5ED6A956105ULL,
		0xEE5A9CE875DE34C2ULL,
		0x3CB1FD702B2DCE5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFA6F24EDB11BFABULL,
		0xF75E356067B7A15EULL,
		0x454935553E9A5054ULL,
		0xD867CD6D5D929E07ULL,
		0x9A910CAB051E9920ULL,
		0x640B8536F98822CFULL,
		0x55D2F3ED3B32A554ULL,
		0xB5BEBA01E87DBF8AULL
	}};
	t = -1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE14F114777442CEDULL,
		0xA470A60311207D4BULL,
		0x06EC53F6FBF47E1EULL,
		0x250939EAB5788C51ULL,
		0xEF96547A8B1FE1EAULL,
		0x9F51B9E16324DAC4ULL,
		0x70A6DD686FE6C562ULL,
		0x3D2C8CFAAEFE6802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F80CAAE0F8079EULL,
		0x7D4A2A7BEAFE9333ULL,
		0xFC4D4120261C4858ULL,
		0x94FE373343903DE8ULL,
		0x89912BA1D3D1DB9DULL,
		0x9E0C3F529130EBE0ULL,
		0x4CDFF66DA9344450ULL,
		0x35286E482EBE22F5ULL
	}};
	t = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x403A4D539BBE097EULL,
		0xC71C0EE1A54AD176ULL,
		0x62427066A95E3845ULL,
		0x13FB3B07D97884A8ULL,
		0xF8C5BD3818BE131BULL,
		0x814009C7DDF40A64ULL,
		0x2ED5915DE7400579ULL,
		0xDC4811B93A710E09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403A4D539BBE097EULL,
		0xC71C0EE1A54AD176ULL,
		0x62427066A95E3845ULL,
		0x13FB3B07D97884A8ULL,
		0xF8C5BD3818BE131BULL,
		0x814009C7DDF40A64ULL,
		0x2ED5915DE7400579ULL,
		0xDC4811B93A710E09ULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EE44AFA0D01228BULL,
		0x402D73192E9ABF64ULL,
		0x8266327570B8C2A3ULL,
		0xD74507CF965CC335ULL,
		0xBB879D0219E0F3A5ULL,
		0x91020A370EF284D6ULL,
		0x4AB65E9D6AE40990ULL,
		0x6181E41727DFE75DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA0AC11ECB5094B6ULL,
		0x2A3A41A902B29A39ULL,
		0x4D2CBB4ECB70FAB2ULL,
		0xF99B79658D1E7037ULL,
		0x468696E783692DE3ULL,
		0x6996A3AB1D5513AAULL,
		0xBF48EDCCC40B167FULL,
		0xC6CF663C3E08666BULL
	}};
	t = -1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE09F060FC0666B54ULL,
		0xEAA17AEAF54C8A1AULL,
		0x325AE1F6E54ED26DULL,
		0xBB42F841E100AA82ULL,
		0xDF4D49B8FFD7F64BULL,
		0x8B2F4C6624E410C2ULL,
		0xADC86BC19A736605ULL,
		0xC97D16B3A9E68FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DEE2D029E8E8D2ULL,
		0x5179548804CDFBB7ULL,
		0x4FF7E33FAC8EEDE1ULL,
		0x841CFDD07EF4288EULL,
		0x10A2C9EA3F3ACDCBULL,
		0xC33631A5266BDAF0ULL,
		0x07DCCC7BBCC4CEFDULL,
		0x1E1786FFB0F7E84BULL
	}};
	t = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2E6A09C65F65CCCULL,
		0xC8E07D285DDC3D72ULL,
		0xF9745DE252D5FDE0ULL,
		0x293E774943C6A935ULL,
		0x08EC1840CCC6841AULL,
		0x5597484A78FB7401ULL,
		0xAA756BA684D1ABF0ULL,
		0x2AD856121FB6D087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FE4975D6A7099BFULL,
		0xE945B4EA947F1428ULL,
		0xFC6CFAC29428141CULL,
		0x59B12228459BAFE8ULL,
		0xE89982F5669C914BULL,
		0xE29C1F8D31623256ULL,
		0x985C488CAE115788ULL,
		0x92969098FDD3B01DULL
	}};
	t = -1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A64F7A428CF5084ULL,
		0x17AE6A119538E887ULL,
		0x74B7B9CDDBFD0913ULL,
		0x9F32CDE16C573F62ULL,
		0x609ECCE603F4FE9AULL,
		0xBD9C8DA421FB0ACCULL,
		0x4E1BB447024B3652ULL,
		0x48D989F78E5E0E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A64F7A428CF5084ULL,
		0x17AE6A119538E887ULL,
		0x74B7B9CDDBFD0913ULL,
		0x9F32CDE16C573F62ULL,
		0x609ECCE603F4FE9AULL,
		0xBD9C8DA421FB0ACCULL,
		0x4E1BB447024B3652ULL,
		0x48D989F78E5E0E87ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53A0F593571687DCULL,
		0x7CDE992769A8C31DULL,
		0xF13D6211A6F310F2ULL,
		0x496B5959CC4EF2C7ULL,
		0x85E788D6C6E3D5DAULL,
		0xB54A6C69B769EAEDULL,
		0xCD6DAE546CFA1ED8ULL,
		0xE3504D908F4D3AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3E508BE48E9D93ULL,
		0x01D96E61AA2077C1ULL,
		0xBCE1BD392D08F0F9ULL,
		0xEFAE01F6E60BEF0BULL,
		0x0D2C01061BFF70ECULL,
		0x8DC762329B7A1277ULL,
		0x129A57E22CE13962ULL,
		0x85310C899FB7E35DULL
	}};
	t = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x582C2DC0FBE48E3EULL,
		0x60A11284818BA476ULL,
		0xFA34E7FA5B203747ULL,
		0xD9DE6F3D2DD92218ULL,
		0x07F9EF47AD2ADCF5ULL,
		0xA6F38E2EE8209A50ULL,
		0xDF03F7AADE041678ULL,
		0x75DE8E7C6D0D025DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52AE12506EADCD41ULL,
		0x96263E6E2331A237ULL,
		0x1D3633B66D4076D7ULL,
		0xB2C8B4B86FCA0E5BULL,
		0x6FC2FC5FC19381B4ULL,
		0x6D4A72ED94D956ECULL,
		0xF3F800855449000CULL,
		0x583FC620CCA3164AULL
	}};
	t = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x132F21A28A223BA6ULL,
		0x57BD5F8DC71108FCULL,
		0x4EC6F63C6D5C3C68ULL,
		0x131D2EB5C7FFC686ULL,
		0xAB847BBD2AFFB334ULL,
		0x9123C0847CAE5F89ULL,
		0xD5C35BFED2E7785AULL,
		0x22864C7C4E3C3473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2F5FFBA9AEBDD5ULL,
		0x8C145630E0F8DED9ULL,
		0x5919F803A8E2E117ULL,
		0xB0D1032C53F488D4ULL,
		0xEE421419ABA25A8BULL,
		0x50EBBC1D80472CE6ULL,
		0x979C66C9F21D882CULL,
		0xBBF6B18483F15CCEULL
	}};
	t = -1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49F4543458E35A72ULL,
		0x8F99E993B2C69DEDULL,
		0x0E6BBC714B7D85E5ULL,
		0xE30B65910AA292E7ULL,
		0xC44D3E850D3C7C3EULL,
		0xADEEE1A3D264E20BULL,
		0xD9DA1655B4E47E73ULL,
		0x57B5B745884C97C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F4543458E35A72ULL,
		0x8F99E993B2C69DEDULL,
		0x0E6BBC714B7D85E5ULL,
		0xE30B65910AA292E7ULL,
		0xC44D3E850D3C7C3EULL,
		0xADEEE1A3D264E20BULL,
		0xD9DA1655B4E47E73ULL,
		0x57B5B745884C97C2ULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFBC8F4715398BFFULL,
		0x583352FA6D6D09C1ULL,
		0x8E0707300005D3AFULL,
		0xDED2F2DCBD972228ULL,
		0xE65889E08C300AC7ULL,
		0xADB7E6B9F97DDD44ULL,
		0xE0E3B2618188FF71ULL,
		0x64A820BA5B22E793ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEC59DB21D16311ULL,
		0xABC9D6D9B56A2635ULL,
		0xE7B15E48E3056136ULL,
		0x6C77E922260B9219ULL,
		0x101ACA7EAA8A2962ULL,
		0xC1B5D9A24C567A49ULL,
		0x5A1406CE7C638023ULL,
		0x46D0E31AC7F32DC4ULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F76C9665A641718ULL,
		0x800D9B29D6EE34E6ULL,
		0xDCD14915E6C8EBB7ULL,
		0x18FF8E23BC5F66A3ULL,
		0xCC8E446979904ACBULL,
		0x281B6978686021CDULL,
		0x1532DE6FE3604277ULL,
		0xD256158AEE78BE03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C9900AD436CF11BULL,
		0xEDCB48CDCD6E7060ULL,
		0xC1184C1D2781745FULL,
		0xABA5F281DE256F05ULL,
		0xD235CC4F57001602ULL,
		0xF4A37D4F71A2AE1EULL,
		0x136F0DAC79EE8C1EULL,
		0x8D040DD5FA6230A5ULL
	}};
	t = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA89CBE46887116AULL,
		0x1FAFC07371C866A5ULL,
		0xD7219FD8E4DD2A18ULL,
		0xBB84F66811319284ULL,
		0x06205BA32783CADFULL,
		0x1C923F07BB31D169ULL,
		0x4C680158B8B5E3D3ULL,
		0xB804D4CA05C9823AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16E5EA5B7E4118AULL,
		0xD80574A41A7C3E92ULL,
		0x17B7BF1D2A7A02D3ULL,
		0xD670681CD8666C47ULL,
		0xB982AF452BFE3DA2ULL,
		0x2759C4C5B86A1C8CULL,
		0x9A99BA525DD31B71ULL,
		0x299054BF3FB8D85AULL
	}};
	t = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF205040ECEEBA501ULL,
		0x14DB3446A70E548AULL,
		0xA1DB07D71F049BEAULL,
		0x499E4B078793DFE9ULL,
		0xE87499A78EC9CF9CULL,
		0x0782DBEA0D30B970ULL,
		0x7181B3762B48D71BULL,
		0x22A0138690519678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF205040ECEEBA501ULL,
		0x14DB3446A70E548AULL,
		0xA1DB07D71F049BEAULL,
		0x499E4B078793DFE9ULL,
		0xE87499A78EC9CF9CULL,
		0x0782DBEA0D30B970ULL,
		0x7181B3762B48D71BULL,
		0x22A0138690519678ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF5D3903B6B4C3CBULL,
		0x2E22613FB11F0FCEULL,
		0xAA4D9CF4F0B63E3AULL,
		0x496FD5BD5BFD6E56ULL,
		0x6A92BDE6E22FD877ULL,
		0x769905F09BE38C00ULL,
		0xE159072B11905DD7ULL,
		0xC0C4513B18EE3DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9AECE5E8E1F97FULL,
		0xEED410851DDDAE73ULL,
		0xDADAC3681BFAACB3ULL,
		0xBC109F4E64BA66EEULL,
		0x185EB7A3F7F608E4ULL,
		0xCC9F18F4620CC6D2ULL,
		0x90C269DA782DC19FULL,
		0x71861451A71D14A1ULL
	}};
	t = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0974F17A1BBAA020ULL,
		0x0A8CFA9B67D85413ULL,
		0x6DAB9242EE66B32EULL,
		0x1F74EB24CB380C27ULL,
		0x3F2EF346DAD3E5BCULL,
		0xFBE6B6B21AA067F2ULL,
		0x63A1C773C5B4726FULL,
		0x0D80808294CBCC8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5378E45CE8EF904FULL,
		0xDA443CDA38217668ULL,
		0xF50932F6D4EDA20CULL,
		0x015265CFA19F796FULL,
		0x60B38FA1830B1FBCULL,
		0xBE7B4F3D410C0C42ULL,
		0x3A1B3F7EE6C107F2ULL,
		0x9F126914AAF56ABCULL
	}};
	t = -1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B91C015420B0AC4ULL,
		0x517DAA3DD2DF7ACAULL,
		0xD5F25EB131877E5FULL,
		0xDC8BC7198C92F346ULL,
		0x214F4343A5CED12BULL,
		0x9F73C836D7833DABULL,
		0x019F96B9C1EEEE84ULL,
		0x70C10C3F66E8CFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA7E31206C606195ULL,
		0xA8EE7AE70FFA861DULL,
		0xAB39D512B1F24504ULL,
		0x6096D557B585A826ULL,
		0x9CF873F754A28362ULL,
		0x0A5BEEAD4EFA5E23ULL,
		0xE37E6FE73AAA0803ULL,
		0x393AFAC3809C1D27ULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x570DF415CEAF9A02ULL,
		0x72DD536B8388A502ULL,
		0xC2D25D2C31DE2453ULL,
		0xDB2938DA41364E8DULL,
		0xE6FF7A077D839C25ULL,
		0x885E2FAF3BF3CFF2ULL,
		0x31BA92129E8DF9A2ULL,
		0xA8F38F526EC26D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570DF415CEAF9A02ULL,
		0x72DD536B8388A502ULL,
		0xC2D25D2C31DE2453ULL,
		0xDB2938DA41364E8DULL,
		0xE6FF7A077D839C25ULL,
		0x885E2FAF3BF3CFF2ULL,
		0x31BA92129E8DF9A2ULL,
		0xA8F38F526EC26D57ULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x255ECA04BF98C454ULL,
		0x1F030BEF025008F7ULL,
		0x91FAB4BFB65971CFULL,
		0x06E403174DE6572CULL,
		0x9FAABDC6084A4EE4ULL,
		0xFD6FE0AB42969D97ULL,
		0x7963C64EF8832AA7ULL,
		0x3BCE5FE8EF166716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B19D76B2682C42ULL,
		0xC467666B29113BCDULL,
		0x3DA3C4B35E3A3E45ULL,
		0xB0CDA6C2E2B724E8ULL,
		0x07458C8D5D007159ULL,
		0x03405A8871060898ULL,
		0x5FEEB70F686A39AEULL,
		0x7E1D30957BC6B2B8ULL
	}};
	t = -1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DE81097D6F8CE93ULL,
		0xDA2C6EB974443A1EULL,
		0xB4FB6B98D67C671AULL,
		0xA8A14CF4512B7368ULL,
		0xC14974C5D63A2B59ULL,
		0x4084E2D2F2B1F276ULL,
		0x509DB94189C2DA1EULL,
		0x07854CC8E8AC103FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7613C28D0048C3DAULL,
		0xAFF1FA7726DC047AULL,
		0xBFB126A6FA19441EULL,
		0x25C35CA22F262C71ULL,
		0x4742DE81F11C21F1ULL,
		0xCDDB6FA6B078468DULL,
		0xA33FA38E86E66535ULL,
		0x3C02A19C0ECBC339ULL
	}};
	t = -1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BC321CB657F45E8ULL,
		0xFBBEFFE76CA53726ULL,
		0x3F23F35460B26F47ULL,
		0x6BFCED4F4F157C23ULL,
		0xA22DC402737A811CULL,
		0x1649AB26783E0898ULL,
		0xA278AB4229579DD9ULL,
		0x7C91502114690AF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE46C25CF29F2D99ULL,
		0x68184F96435EEA0FULL,
		0x42B0D527A35F31C1ULL,
		0x3790A4A92B14787DULL,
		0x317E06A62F08A848ULL,
		0xF3440D7BFD50FEF1ULL,
		0x422C69A95BB89A69ULL,
		0x60AE4323A5552CDCULL
	}};
	t = 1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65E49D2C5F6B78C6ULL,
		0x2E397386DD86A362ULL,
		0x0BBBF03BB618FFF3ULL,
		0x9C88778867A47B1FULL,
		0x66BCA813B6D95959ULL,
		0x36945968354697E0ULL,
		0x16B6D16017044B24ULL,
		0xF57A7C32AF38C3E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E49D2C5F6B78C6ULL,
		0x2E397386DD86A362ULL,
		0x0BBBF03BB618FFF3ULL,
		0x9C88778867A47B1FULL,
		0x66BCA813B6D95959ULL,
		0x36945968354697E0ULL,
		0x16B6D16017044B24ULL,
		0xF57A7C32AF38C3E6ULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD5C9372C34067F4ULL,
		0x7071C76591586035ULL,
		0xDCC30F6DE1D1BE11ULL,
		0x2753BEF6BE1EC1B7ULL,
		0x35607147270992C9ULL,
		0xA1DCC0C85864D787ULL,
		0x5F09CF659B606B93ULL,
		0x749BD78B52EFA3BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A5DC4CCE2F3A57AULL,
		0xF1BFAE04A4881A61ULL,
		0xAC66FFD1AFEFF5C9ULL,
		0xE45EF236EDEE8B71ULL,
		0x9C8B2617277A54D6ULL,
		0x271947FDB7E9233EULL,
		0xFE2214C2DABC58F2ULL,
		0xEF3D5CD9DEFCFC6AULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE0F7A895588BD00ULL,
		0xE11BA4A82FCBD0C9ULL,
		0x92F91D9A4FA205F8ULL,
		0x422CF7BEE3BB286EULL,
		0x4EC0A7AEF06941B6ULL,
		0x4FADEA5593908C6BULL,
		0xFC9A1D9F6F358252ULL,
		0x38366B23FC9C4CF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8A2C565EC03175ULL,
		0xD9B21842B3AF5F6CULL,
		0x761D60CFC42E87E2ULL,
		0xEB6960F7BA3DD419ULL,
		0x7DA8D7BB0C8E184BULL,
		0x614EAF32BF9E25C2ULL,
		0xF9D940DE6D8683F5ULL,
		0xF9E2118036833380ULL
	}};
	t = -1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF77EF5846000F723ULL,
		0x2D9A7648C8DE0D27ULL,
		0xCB74861674758ED6ULL,
		0xEBFB0ED189CFB186ULL,
		0xF78126B0607ACDE9ULL,
		0x0B8C1290BFA9D1C6ULL,
		0xF331917E3CFA74B1ULL,
		0x5AE1559461065060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C2FFA23480E1A32ULL,
		0xBD2368CC375E2609ULL,
		0x9812FA2192EE3F40ULL,
		0x8E5F8ACA1AA0436DULL,
		0x6E1BCF4052BCFC44ULL,
		0xB96A4AD3EA7B2C66ULL,
		0xA0726F560923D15FULL,
		0x9A15581F5A5E4BFCULL
	}};
	t = -1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22AD45035B4817F0ULL,
		0x53DAD909EA92F9FEULL,
		0x76B339CF28E7D4C5ULL,
		0x412C0678B98F6919ULL,
		0x5F6685C7109B52EAULL,
		0x83843D8B4DACD5C7ULL,
		0x02A7D5EAAE17DCD7ULL,
		0xFF2EB76E6A6EFE28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22AD45035B4817F0ULL,
		0x53DAD909EA92F9FEULL,
		0x76B339CF28E7D4C5ULL,
		0x412C0678B98F6919ULL,
		0x5F6685C7109B52EAULL,
		0x83843D8B4DACD5C7ULL,
		0x02A7D5EAAE17DCD7ULL,
		0xFF2EB76E6A6EFE28ULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14D4F7986568D32CULL,
		0x12B51BD48D214BD8ULL,
		0xC2D9FCBD25A0EBC5ULL,
		0x5447D85D626C78E7ULL,
		0x6DA9BB15C2E39331ULL,
		0x6F915DD7038AB65FULL,
		0x8271F557749D2112ULL,
		0x4DE677FDCDA0D370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CCF72DF37609D7ULL,
		0x50B986E1A1E6C906ULL,
		0xC073F0E6756ED329ULL,
		0x01514CD36ACCB71DULL,
		0x581A7592A253DAC2ULL,
		0x6E3A4A84986EC480ULL,
		0x9F26511C733B2B2AULL,
		0x456F536B07C47464ULL
	}};
	t = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3182D01F148C91DFULL,
		0x6AA4311D316D23BDULL,
		0x0277BB4F43B4216BULL,
		0x0A780C5476B09021ULL,
		0x321DAE0CC98C21A1ULL,
		0x9084A3A523A68646ULL,
		0x3CAFD38D7118077BULL,
		0x36120A56D2208EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677813E1F1E08019ULL,
		0xBA6C41FA358A2A9FULL,
		0x80055D254B230DCAULL,
		0x9BE2A3EB194F0F33ULL,
		0x2E34A4AD6B6FA2FEULL,
		0x98893B19401FAF65ULL,
		0x92E45EAB79EB570DULL,
		0x01257FD8E8B23CA8ULL
	}};
	t = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BEFA48866A7DCB3ULL,
		0x271E2421E336E156ULL,
		0x97A50E80F2E83DA6ULL,
		0x2A8A097C6D2EFE61ULL,
		0x4BBD205FC675216BULL,
		0xC159F560D67D5888ULL,
		0xAC060F754919AD7DULL,
		0xC3488411817F3002ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBDE086ABA5BF531ULL,
		0x5C00C2D8E6F426FEULL,
		0x1341D926817F739DULL,
		0x8D882CE76DD4945FULL,
		0x99C9CE6905530C31ULL,
		0x6D5F824981354EEAULL,
		0x284B4465795AEC1BULL,
		0x37AFF5ABAFD7F1C8ULL
	}};
	t = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22251241EE504C2EULL,
		0xB827E6D12AF08AA3ULL,
		0x13D0C05180F27C7FULL,
		0x6302579ECBF94F68ULL,
		0xB93C0B0831B84854ULL,
		0xD4D863771C0A5FC9ULL,
		0x5503C2A0CCD31624ULL,
		0xD3C843142E733D6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22251241EE504C2EULL,
		0xB827E6D12AF08AA3ULL,
		0x13D0C05180F27C7FULL,
		0x6302579ECBF94F68ULL,
		0xB93C0B0831B84854ULL,
		0xD4D863771C0A5FC9ULL,
		0x5503C2A0CCD31624ULL,
		0xD3C843142E733D6FULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x460D7368514E0229ULL,
		0xB0E2A0280A246603ULL,
		0xF09FBB58E9617CC9ULL,
		0x9AC8940BDDC57F40ULL,
		0xE60F48AD3EDD98E6ULL,
		0x42311B347D3A8815ULL,
		0x66EF332853054D73ULL,
		0x1DB00B3A718CB50AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B761CE4E6FF629BULL,
		0x2D8565E6E9CD1F01ULL,
		0x61B8777A317F7932ULL,
		0xB99FBB198062CF38ULL,
		0x6B2AA8F6648A0F4FULL,
		0x214527AE88B9943CULL,
		0x9338FC2CC6DBFC36ULL,
		0xBF38B7BAF6B0FF82ULL
	}};
	t = -1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6F05EC1AF68473EULL,
		0x6720D0BD4C6D1DB5ULL,
		0xA0E79A6F01B4C2DBULL,
		0x5D1A20A55BED4AA8ULL,
		0xB7F3FAB220247023ULL,
		0x433CB54A71FC64EAULL,
		0x68981B1DFE7608FFULL,
		0xE563B7B2173127F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A9D422DD40C3992ULL,
		0x8C31CB6A0F2D1262ULL,
		0x1E4902619206F9E8ULL,
		0x8E556178996CD892ULL,
		0x54B433334F40CA20ULL,
		0x63A16B7C4DCC8EFFULL,
		0x2D28595FEEF82390ULL,
		0xFA181A211CADDB4EULL
	}};
	t = -1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0EC895F8A20693DULL,
		0xEF945268352EDBC3ULL,
		0x2526DFF529967E17ULL,
		0x9168B6DE294F49D7ULL,
		0xD8F95A8C21495351ULL,
		0xE9C8A298010298A3ULL,
		0x0A2492150BB4181BULL,
		0x7338F691AFF6228FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A670E6975E2D3B6ULL,
		0xDC2781ED0C022BDFULL,
		0x44BB43D27F1C74BBULL,
		0x7BCC77BB375D5053ULL,
		0x080062266D9AF571ULL,
		0x4EC4B07D409774EAULL,
		0x217708E064DA60AEULL,
		0xB231C90AAA5FCDACULL
	}};
	t = -1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F872A7D537FA437ULL,
		0x7267D811699F9331ULL,
		0x532241A3AA932549ULL,
		0x386BD85F8DC72BCDULL,
		0xD93CA7D455D2D6AFULL,
		0x77725ADACBC53294ULL,
		0xF1B69E48A23E7CACULL,
		0xEB229D4FD897C263ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F872A7D537FA437ULL,
		0x7267D811699F9331ULL,
		0x532241A3AA932549ULL,
		0x386BD85F8DC72BCDULL,
		0xD93CA7D455D2D6AFULL,
		0x77725ADACBC53294ULL,
		0xF1B69E48A23E7CACULL,
		0xEB229D4FD897C263ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB301CCD7629CEAFAULL,
		0x755D38848A033928ULL,
		0x669279A22B2AD9DAULL,
		0x80D36F7E73CC7FE2ULL,
		0x5998C08367CD97FBULL,
		0x9395BDED6646033BULL,
		0x28F496E8BE010637ULL,
		0x918B88F1D2566E40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F7C3A59174E8A8ULL,
		0x461CE47D50FDB6B8ULL,
		0xB8ABDBAA0B985104ULL,
		0xBF654C16E0C83D6FULL,
		0xE34B559F6C96CC4EULL,
		0x38E5D71D457C35E0ULL,
		0x70AD1A56C125E12DULL,
		0x1F3B86835E8EE6A0ULL
	}};
	t = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F2F703663103A17ULL,
		0x39A46D280FCA9CCFULL,
		0x476120C732545C3CULL,
		0x69350C27E2DCB615ULL,
		0xC9B2F906547DB4F0ULL,
		0xE65FA6C0D7D85BF0ULL,
		0x0207EDD699932561ULL,
		0x5F48E1034576C703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5900492A24470B14ULL,
		0xBC4540297D9C6C15ULL,
		0x384561E3E19C7A5CULL,
		0x50262FE75536C101ULL,
		0x0EC7387EA77815A0ULL,
		0xF87341C68E647620ULL,
		0x7B2C2693FD44FCECULL,
		0xD551FB1F866E1142ULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA7D2BDA1093084CULL,
		0x462BBE9F3D75EA73ULL,
		0x24BDF6134BFAA8DFULL,
		0x091A7EF3DA2FDC8BULL,
		0xE9F058E2C8B4358DULL,
		0xE8F03E776615D38CULL,
		0x046EB9D5EDD42859ULL,
		0x9925DBD53CB8434FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A3C50C7473E3BDULL,
		0x530D33958F92BC1CULL,
		0x427792E0C0A63E63ULL,
		0xBA729788BD538C19ULL,
		0xCB6ACD0B4E4C26FEULL,
		0x7D5F5FF707C6B634ULL,
		0x4426C417B5421CECULL,
		0x6C9177E9378F6795ULL
	}};
	t = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5569558B9DA41893ULL,
		0x4942065154E2B6B9ULL,
		0x04BB333611948F35ULL,
		0x542AAED56C8E5D73ULL,
		0xBB581EA61251FADFULL,
		0xCE22AE664539C281ULL,
		0xCD5B6AA4166C5E2CULL,
		0x52D3ED585A6E7529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5569558B9DA41893ULL,
		0x4942065154E2B6B9ULL,
		0x04BB333611948F35ULL,
		0x542AAED56C8E5D73ULL,
		0xBB581EA61251FADFULL,
		0xCE22AE664539C281ULL,
		0xCD5B6AA4166C5E2CULL,
		0x52D3ED585A6E7529ULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD182DECA28C6C4CULL,
		0x4800EF880C48B916ULL,
		0x37A5BC25F8682903ULL,
		0x0EA7031A35481D1FULL,
		0x3FC24D8F5C6A36E2ULL,
		0x3EA40B59D4AC3BE4ULL,
		0x673AD2765F99ADD2ULL,
		0x01BEF692EAEB997FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5142442EB24F711EULL,
		0x5094E5FFA6BC5295ULL,
		0x1F68ED620401EB59ULL,
		0x5C6B059125DBB237ULL,
		0xEE7A16BA900F5332ULL,
		0x0B52BE93E94B1D06ULL,
		0x0B0A5A0DE60645E5ULL,
		0xD1D43DBF5369A99AULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4E0B2FBA483F4F1ULL,
		0x3D02DDB9A02771E2ULL,
		0x20967438B9E19A70ULL,
		0x656F0E72C5918680ULL,
		0x6C05690C13B614F0ULL,
		0x369355E112B4D908ULL,
		0xEF2896E5E3D4E1A7ULL,
		0xA9F49310695EF0F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0FF8A8AD81951C7ULL,
		0xCAEC6A49785FD4CCULL,
		0xCDE3D5D41D79C0E0ULL,
		0x11E4842DD4D59409ULL,
		0x9CAF7424E02049B9ULL,
		0xDBA0723901604603ULL,
		0x1C4E49E0702948C2ULL,
		0xFD5883D10587646FULL
	}};
	t = -1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26E972A4A1C7056AULL,
		0x7D314BCA9E8659A6ULL,
		0xDE616ED9CC63BB4AULL,
		0x7BD8D7C750639D5DULL,
		0x4051524F035AAF3CULL,
		0xDEBF54333B6563B6ULL,
		0xF3F65EB0719F5814ULL,
		0x8A0FD68B940F00E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9743A38736D9C502ULL,
		0x448CD378EEF68EA1ULL,
		0x0ECAEBE8B633B660ULL,
		0x6E78D762D67F47D8ULL,
		0x619242EE58D861CBULL,
		0x88915F80482AD272ULL,
		0x49AC59CB5C5E7711ULL,
		0xA5148FE8D98E8D67ULL
	}};
	t = -1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12B24488976BC05DULL,
		0xFBA5086E3902E666ULL,
		0x2BD30622DC968E9AULL,
		0xFC66C1BE13C2B752ULL,
		0x7AB71EBF10CB3F34ULL,
		0xF3FB68B970D40665ULL,
		0x51BA8A13710341D7ULL,
		0x6518A208B8ACCE50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12B24488976BC05DULL,
		0xFBA5086E3902E666ULL,
		0x2BD30622DC968E9AULL,
		0xFC66C1BE13C2B752ULL,
		0x7AB71EBF10CB3F34ULL,
		0xF3FB68B970D40665ULL,
		0x51BA8A13710341D7ULL,
		0x6518A208B8ACCE50ULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x920569AAB5E7FEE9ULL,
		0xF011FD4E138BA113ULL,
		0x5B4A04235794387CULL,
		0xC5730F7111BEBFB7ULL,
		0xC884DFA8D1263DC5ULL,
		0xA82C898A6CFF8688ULL,
		0x80B17E8068FE4139ULL,
		0x08AA98D7689C737BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CEAA170E845E60AULL,
		0xC3123DC9B51E2C61ULL,
		0xA66E27E06F779125ULL,
		0x5D1C57E3DCE99391ULL,
		0xFA226A0A38DFEB03ULL,
		0x5F3277F45ABFBC1EULL,
		0x53572D47EF261D1AULL,
		0xAC9A3FF01EB90363ULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3248C448EDEC4599ULL,
		0x640C565F8DDC26E2ULL,
		0x2E2C366E0EFE2D17ULL,
		0x58A02CF4CF03CDCAULL,
		0x0173C60EE9E06025ULL,
		0xAEE045524E054CC4ULL,
		0x4A419AC0B1A90CE9ULL,
		0x66B615D04A20A876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62590F7F88A01F42ULL,
		0x9E9695688FA47C2BULL,
		0x1867D8124FC66CB9ULL,
		0xF6D1D18C3D219BC9ULL,
		0x8623A19A6E269515ULL,
		0x28CA43588C777BB9ULL,
		0xE5CF82E6CFAC7663ULL,
		0x57D30C10CDA14E17ULL
	}};
	t = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3740D2800B14A606ULL,
		0x81C6F68E6C36604BULL,
		0x0C7F00FC7092823CULL,
		0x35C651E359256986ULL,
		0xDA6E5BB6A1465D11ULL,
		0x3BAF1D4AB81CEA70ULL,
		0x7BBC90FF58248C1AULL,
		0x77E647F161D5DBA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE26E8CF13233B25ULL,
		0xCEC8BFB4BC5EF7F3ULL,
		0x5269F62EA1B58A39ULL,
		0xDD0B846B3737A6FDULL,
		0x8CF2252B6C546982ULL,
		0xE2FD2B32AB0C0757ULL,
		0x472D772C820193ADULL,
		0x311FCAA8C3695BF5ULL
	}};
	t = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA35D1B5A4BD67C12ULL,
		0x2B8E2F7823FA0DFFULL,
		0x6B08998F88D361C6ULL,
		0xF667930DD30472BDULL,
		0x7D9BF239145ED719ULL,
		0xA256ECFEC5787945ULL,
		0xD4A766716A8558E9ULL,
		0xDBE2C5D0B0008305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35D1B5A4BD67C12ULL,
		0x2B8E2F7823FA0DFFULL,
		0x6B08998F88D361C6ULL,
		0xF667930DD30472BDULL,
		0x7D9BF239145ED719ULL,
		0xA256ECFEC5787945ULL,
		0xD4A766716A8558E9ULL,
		0xDBE2C5D0B0008305ULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x237FB8E056137E44ULL,
		0xD0C2925824C1D85DULL,
		0x868D9256591D4179ULL,
		0xD6A2B8422CD97E4CULL,
		0xEFED2CDB9AA1DB36ULL,
		0xE2051F2723A277C4ULL,
		0x12F473DB222B54ADULL,
		0x0F1878A32D272B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0CFA5D290EF493ULL,
		0x3C2DC4C0A099E991ULL,
		0x4D930B704B85D074ULL,
		0xBE5844007B35A493ULL,
		0x2C5231F64AAD2582ULL,
		0x3CBB1E41D2284355ULL,
		0x1E85C126043B95D2ULL,
		0x2374EF2C84CAC7C3ULL
	}};
	t = -1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECE71089C33A83ABULL,
		0x990311133AF32882ULL,
		0x2EA3A91FA06F71DEULL,
		0x9DF08F3582345242ULL,
		0xA811F1391DCE94EBULL,
		0xAEFF8867D7C21E9CULL,
		0x611A8222C17D4B8DULL,
		0xF430DF72CC8C7E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EDDC71364684FE7ULL,
		0x8437797EED7BA025ULL,
		0xE499B62F7B8B7541ULL,
		0x9A7C088812A367D5ULL,
		0xAB995EA348BF9A64ULL,
		0x9422E1A8923E9221ULL,
		0x52006996B21C7937ULL,
		0xB2A8E8BF13E2E6B4ULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A390BA2E279B079ULL,
		0x612E1465DC875A29ULL,
		0x5F33D613474B1C2EULL,
		0x37EC2B7D1052E4B1ULL,
		0x32989733BC3EE891ULL,
		0xEA42F26758E83ADBULL,
		0x7F737EA78A9C4F1CULL,
		0x8FF370E2ED19675CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171E6C7216B5EAB4ULL,
		0x8BB610E2382D4EDFULL,
		0x4297BC0B119AA164ULL,
		0xC7C37A20DB8F72A3ULL,
		0xED56A5FD317CD97CULL,
		0x4A04BA60557E5CC2ULL,
		0xFF473A19789B7B82ULL,
		0x3D4F0599570679C2ULL
	}};
	t = 1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B71880C23C7FFE8ULL,
		0xF056924F037DD82AULL,
		0x616D446CA0CFC14FULL,
		0x0B2D37DBF9E5B321ULL,
		0x331F42486BB0E580ULL,
		0xF73B18A3CC3A9A76ULL,
		0x0743879585B3E467ULL,
		0x3EC2CDF1E0329ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B71880C23C7FFE8ULL,
		0xF056924F037DD82AULL,
		0x616D446CA0CFC14FULL,
		0x0B2D37DBF9E5B321ULL,
		0x331F42486BB0E580ULL,
		0xF73B18A3CC3A9A76ULL,
		0x0743879585B3E467ULL,
		0x3EC2CDF1E0329ED6ULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6384075CB2783A50ULL,
		0x13DAB9E248BC6533ULL,
		0xE2570290C1145F5CULL,
		0x0DBDCAF8D426ED6AULL,
		0x053B20CDD21C5D7CULL,
		0xC39039306965EABAULL,
		0x66242E5BC3A5A24AULL,
		0x8DA1D9D002CCEA2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F2E49C3634C123ULL,
		0xF7A099102C091E85ULL,
		0x528B04C09D50295FULL,
		0xF811A09082FBD142ULL,
		0x9FE08A7396F894DBULL,
		0x1E4A1F766C46E4ABULL,
		0xB06C1CAA2FA432EFULL,
		0xCB1BA00FEA3E5959ULL
	}};
	t = -1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C17B2EE9076DA04ULL,
		0xFBBD8CD87C2F3E15ULL,
		0xB19A3804AC9FFF07ULL,
		0x12AB5F036242A310ULL,
		0xA047AD5168600F74ULL,
		0x807950C992AC71BAULL,
		0xAC61381DA4609D36ULL,
		0x829C07679ACA2E80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x815D7D86CE7C6B74ULL,
		0x543C0C5BD780CF27ULL,
		0xDF502FF284A76178ULL,
		0x2ACCB0EF0265E4DDULL,
		0x54E33FF01BE4ABDDULL,
		0x73F15E90192A14DFULL,
		0xC03145A12762B7C8ULL,
		0x9AAC16288B0E71A1ULL
	}};
	t = -1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2910B58D523F1559ULL,
		0x4F29391B300AFDD6ULL,
		0x14FBDD66C1B427C5ULL,
		0x35243A900D1B243AULL,
		0xF7EF9144F40241AAULL,
		0x0438A481846059C8ULL,
		0x637B044C0381D7E5ULL,
		0x94CDA7E2B153E48FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA097E96D818BDDULL,
		0xF788A8DB724755C6ULL,
		0x6EC834BA6DADC60DULL,
		0x327DE2464784232EULL,
		0x145D99ABCD42AA48ULL,
		0x97A8BC73EA69E691ULL,
		0x11CC0BD7A4523063ULL,
		0x45A2B354DE0E61CFULL
	}};
	t = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}