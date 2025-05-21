#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6D68F0F05C4F4F7FULL,
		0x47CAFB1505BC9D49ULL,
		0x536D913014D8F5F1ULL,
		0xFF036BB09D98CEA9ULL,
		0x3EEDC35D9168E33BULL,
		0x400C3696DFAC6059ULL,
		0xFF7A3FB56040773EULL,
		0x1B6B6B58AE8E7D5FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xDAD1E1E0B89E9EFEULL,
		0x8F95F62A0B793A92ULL,
		0xA6DB226029B1EBE2ULL,
		0xFE06D7613B319D52ULL,
		0x7DDB86BB22D1C677ULL,
		0x80186D2DBF58C0B2ULL,
		0xFEF47F6AC080EE7CULL,
		0x36D6D6B15D1CFABFULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE543F61078120649ULL,
		0x1F8F60D5BBF618D7ULL,
		0x2A570FAF4953247EULL,
		0x8859D578CC481863ULL,
		0xAF0D60924B1C4EF8ULL,
		0xDD33A33ADC1CE15DULL,
		0xCA5804164FB0E584ULL,
		0x008363503AD437DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA87EC20F0240C92ULL,
		0x3F1EC1AB77EC31AFULL,
		0x54AE1F5E92A648FCULL,
		0x10B3AAF1989030C6ULL,
		0x5E1AC12496389DF1ULL,
		0xBA674675B839C2BBULL,
		0x94B0082C9F61CB09ULL,
		0x0106C6A075A86FB5ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94CD653418E3FB61ULL,
		0x93A356409A079847ULL,
		0x3A311BF34BE00B6FULL,
		0xFAF48F09DEA96DE8ULL,
		0x3B2BE3A6D082339DULL,
		0x6C22275560FE1A9EULL,
		0xF682D28E402E7D92ULL,
		0x08119A0E3E6AD5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x299ACA6831C7F6C2ULL,
		0x2746AC81340F308FULL,
		0x746237E697C016DFULL,
		0xF5E91E13BD52DBD0ULL,
		0x7657C74DA104673BULL,
		0xD8444EAAC1FC353CULL,
		0xED05A51C805CFB24ULL,
		0x1023341C7CD5AB5DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCCF2D4EEAB4BC96ULL,
		0x66A8772A80D2BE5CULL,
		0xD1674D394BFB468DULL,
		0xB4CACF8EE750FF78ULL,
		0xFAADF1E4B92BE681ULL,
		0x2B3D2A1EE2F92429ULL,
		0x0FC7842A5552CB6DULL,
		0x359FF3AD1415F877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF99E5A9DD569792CULL,
		0xCD50EE5501A57CB9ULL,
		0xA2CE9A7297F68D1AULL,
		0x69959F1DCEA1FEF1ULL,
		0xF55BE3C97257CD03ULL,
		0x567A543DC5F24853ULL,
		0x1F8F0854AAA596DAULL,
		0x6B3FE75A282BF0EEULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A09BECCCD2777C7ULL,
		0xCA7E5BA9A0987A05ULL,
		0xDDD5095D9A46AACAULL,
		0xA48AC29926CABB3BULL,
		0xDEA2B53C2414720FULL,
		0xB182A83C1A504CEEULL,
		0x46DF3D49B267B8ACULL,
		0x0B0322F533FD1A43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34137D999A4EEF8EULL,
		0x94FCB7534130F40AULL,
		0xBBAA12BB348D5595ULL,
		0x491585324D957677ULL,
		0xBD456A784828E41FULL,
		0x6305507834A099DDULL,
		0x8DBE7A9364CF7159ULL,
		0x160645EA67FA3486ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1832C4E5B9E561BBULL,
		0x192FB19129555A95ULL,
		0x9D8DA3D82564F8F4ULL,
		0xDA165262D51DAC0CULL,
		0x009BFE993065AA91ULL,
		0x2323F1AA058BC582ULL,
		0x505A0F65A0796A6DULL,
		0x191BC64B8C488CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x306589CB73CAC376ULL,
		0x325F632252AAB52AULL,
		0x3B1B47B04AC9F1E8ULL,
		0xB42CA4C5AA3B5819ULL,
		0x0137FD3260CB5523ULL,
		0x4647E3540B178B04ULL,
		0xA0B41ECB40F2D4DAULL,
		0x32378C97189119BEULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DD76D3807CC4F09ULL,
		0xFCCF7EB9562D8534ULL,
		0x88F3B2105C5E75F5ULL,
		0x6CB46A3519B280EBULL,
		0x5DDBF8816BC33858ULL,
		0xE66070ED35A711BDULL,
		0x6B8F3FC0C9987432ULL,
		0x095D29639EB5539AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BAEDA700F989E12ULL,
		0xF99EFD72AC5B0A68ULL,
		0x11E76420B8BCEBEBULL,
		0xD968D46A336501D7ULL,
		0xBBB7F102D78670B0ULL,
		0xCCC0E1DA6B4E237AULL,
		0xD71E7F819330E865ULL,
		0x12BA52C73D6AA734ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADD3C1056DC783CDULL,
		0x3FF158A1D89F2B30ULL,
		0xB68126075268ABA1ULL,
		0xABFA92899419F056ULL,
		0x02CE84233414434DULL,
		0x94BFBF8757F9E158ULL,
		0xA883D632471139BCULL,
		0x03124910296A49B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA7820ADB8F079AULL,
		0x7FE2B143B13E5661ULL,
		0x6D024C0EA4D15742ULL,
		0x57F525132833E0ADULL,
		0x059D08466828869BULL,
		0x297F7F0EAFF3C2B0ULL,
		0x5107AC648E227379ULL,
		0x0624922052D49369ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F806BF0F4E07B5CULL,
		0x176F39E83B2717EBULL,
		0x5214A9858E255398ULL,
		0x2A90788995FD5D93ULL,
		0x8005E90F1AFC454CULL,
		0x4F8E9ED20118EF67ULL,
		0x8A1C3250E53F2D86ULL,
		0x2446C4BEB764AC1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F00D7E1E9C0F6B8ULL,
		0x2EDE73D0764E2FD7ULL,
		0xA429530B1C4AA730ULL,
		0x5520F1132BFABB26ULL,
		0x000BD21E35F88A98ULL,
		0x9F1D3DA40231DECFULL,
		0x143864A1CA7E5B0CULL,
		0x488D897D6EC9583BULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB7338D62FD4138EULL,
		0x7C4777F3C3F1D2A7ULL,
		0x060AC396223BB719ULL,
		0xB08659144F79DB3BULL,
		0x0F02D2AB650EA39DULL,
		0x57BEE928B0711EF1ULL,
		0x0D71D472D4277E42ULL,
		0x041A2EC0BBA8EDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E671AC5FA8271CULL,
		0xF88EEFE787E3A54FULL,
		0x0C15872C44776E32ULL,
		0x610CB2289EF3B676ULL,
		0x1E05A556CA1D473BULL,
		0xAF7DD25160E23DE2ULL,
		0x1AE3A8E5A84EFC84ULL,
		0x08345D817751DBEAULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53EDC1D2A8AFE661ULL,
		0x9DF7B688C9290362ULL,
		0xAF6E708CE8FE5EF2ULL,
		0x9600500297F088AAULL,
		0x284A6060DC86F9C9ULL,
		0xB307EF34C6B27E3FULL,
		0xE4E7EFC0F62C14B8ULL,
		0x0741D37EDD0E6AEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DB83A5515FCCC2ULL,
		0x3BEF6D11925206C4ULL,
		0x5EDCE119D1FCBDE5ULL,
		0x2C00A0052FE11155ULL,
		0x5094C0C1B90DF393ULL,
		0x660FDE698D64FC7EULL,
		0xC9CFDF81EC582971ULL,
		0x0E83A6FDBA1CD5DFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52FFA9CEE60C31A3ULL,
		0xBD8CB33D46A6F407ULL,
		0x936E9B83CB134CB1ULL,
		0x54F33DC33018490AULL,
		0x2B35BBB361B47CBAULL,
		0xE7A447B3DAE9A57DULL,
		0xB714403893BEA528ULL,
		0x3462E493405EB0DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FF539DCC186346ULL,
		0x7B19667A8D4DE80EULL,
		0x26DD370796269963ULL,
		0xA9E67B8660309215ULL,
		0x566B7766C368F974ULL,
		0xCF488F67B5D34AFAULL,
		0x6E288071277D4A51ULL,
		0x68C5C92680BD61B7ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E6CD0AEF80C939EULL,
		0x573CC20D22A8F842ULL,
		0x77C74DFCB224BFDCULL,
		0x711E46155B8BAC4CULL,
		0x0F14247989B9FD1FULL,
		0x657C2802E10EC768ULL,
		0x876F8071FB37CAA7ULL,
		0x337743C8D13DF677ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD9A15DF019273CULL,
		0xAE79841A4551F085ULL,
		0xEF8E9BF964497FB8ULL,
		0xE23C8C2AB7175898ULL,
		0x1E2848F31373FA3EULL,
		0xCAF85005C21D8ED0ULL,
		0x0EDF00E3F66F954EULL,
		0x66EE8791A27BECEFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE7B69DDCB604E1BULL,
		0x4152EAFBDDA5E019ULL,
		0x0FABE989345C7BD0ULL,
		0x5565BB311CCC1C06ULL,
		0x43D336323D7B3E46ULL,
		0xB76FE7468DBE067FULL,
		0x2C16912027EF415CULL,
		0x36FE6E129B071471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF6D3BB96C09C36ULL,
		0x82A5D5F7BB4BC033ULL,
		0x1F57D31268B8F7A0ULL,
		0xAACB76623998380CULL,
		0x87A66C647AF67C8CULL,
		0x6EDFCE8D1B7C0CFEULL,
		0x582D22404FDE82B9ULL,
		0x6DFCDC25360E28E2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B322CF7E0610C85ULL,
		0x0A8735E060609A36ULL,
		0x6A3D99987B9E899AULL,
		0xCEC0A6C0B8A89B6EULL,
		0xADAE5C47FD3A94ACULL,
		0xC61693B14118DF6DULL,
		0x30DF8421E2BE830EULL,
		0x36445D3A87096A6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD66459EFC0C2190AULL,
		0x150E6BC0C0C1346CULL,
		0xD47B3330F73D1334ULL,
		0x9D814D81715136DCULL,
		0x5B5CB88FFA752959ULL,
		0x8C2D27628231BEDBULL,
		0x61BF0843C57D061DULL,
		0x6C88BA750E12D4DEULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF40C510C1ABC7D6EULL,
		0x1C719AEC41BCDC97ULL,
		0xE80B723B6AD8E6A4ULL,
		0x9DC1AFD5DB506C4CULL,
		0x491D74BF7ED853C1ULL,
		0xAFD2F3B8FD11748BULL,
		0x3116B058FE1A1803ULL,
		0x345C1CF31BED71F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE818A2183578FADCULL,
		0x38E335D88379B92FULL,
		0xD016E476D5B1CD48ULL,
		0x3B835FABB6A0D899ULL,
		0x923AE97EFDB0A783ULL,
		0x5FA5E771FA22E916ULL,
		0x622D60B1FC343007ULL,
		0x68B839E637DAE3F2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD11280397F01484ULL,
		0x3E94034209333BACULL,
		0x2106908303D51306ULL,
		0xA938E01A39035116ULL,
		0x423DA95824E33A78ULL,
		0x40049D901B1CAF24ULL,
		0xC464FA8131A0C3F5ULL,
		0x02217EE891D667BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA2250072FE02908ULL,
		0x7D28068412667759ULL,
		0x420D210607AA260CULL,
		0x5271C0347206A22CULL,
		0x847B52B049C674F1ULL,
		0x80093B2036395E48ULL,
		0x88C9F502634187EAULL,
		0x0442FDD123ACCF77ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED6F666CBDA84052ULL,
		0xE7F3F35985F4086AULL,
		0x8B76E282DCF2BF51ULL,
		0x79029CC2AE6B3BC3ULL,
		0x795BF9AB93B53072ULL,
		0x665B6C17DD188E93ULL,
		0x53F497E2C8C32031ULL,
		0x0F70651B1F939AC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDADECCD97B5080A4ULL,
		0xCFE7E6B30BE810D5ULL,
		0x16EDC505B9E57EA3ULL,
		0xF20539855CD67787ULL,
		0xF2B7F357276A60E4ULL,
		0xCCB6D82FBA311D26ULL,
		0xA7E92FC591864062ULL,
		0x1EE0CA363F273580ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x539D4D5572FF40E4ULL,
		0xCE27C94D2A7EEB18ULL,
		0x33D5F93E5384FB0AULL,
		0xC5F1B4829689E37AULL,
		0x768A95868B1BF948ULL,
		0xF77EBAC78C38B769ULL,
		0x91DEB7DC1A38FA34ULL,
		0x2213EFEF6355DB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA73A9AAAE5FE81C8ULL,
		0x9C4F929A54FDD630ULL,
		0x67ABF27CA709F615ULL,
		0x8BE369052D13C6F4ULL,
		0xED152B0D1637F291ULL,
		0xEEFD758F18716ED2ULL,
		0x23BD6FB83471F469ULL,
		0x4427DFDEC6ABB673ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46D376712683FF06ULL,
		0x5B8799023640C0BEULL,
		0xF6BA42EE282548DAULL,
		0xD6B4E75627A17F15ULL,
		0x04216F05B65C02FDULL,
		0x601943AA998A6D78ULL,
		0xD251C0A31630F31EULL,
		0x2FE0979AE50C4E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA6ECE24D07FE0CULL,
		0xB70F32046C81817CULL,
		0xED7485DC504A91B4ULL,
		0xAD69CEAC4F42FE2BULL,
		0x0842DE0B6CB805FBULL,
		0xC03287553314DAF0ULL,
		0xA4A381462C61E63CULL,
		0x5FC12F35CA189C19ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEBEA86AB65A18CAULL,
		0x7B4D08B89BB6A439ULL,
		0xF2F659A0A953B8FBULL,
		0xF879A33379B3CF18ULL,
		0xB9D3756E27FA8104ULL,
		0xCE4542E77A269C31ULL,
		0xA255AD496349D11EULL,
		0x1C14B55DFF8B5260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D7D50D56CB43194ULL,
		0xF69A1171376D4873ULL,
		0xE5ECB34152A771F6ULL,
		0xF0F34666F3679E31ULL,
		0x73A6EADC4FF50209ULL,
		0x9C8A85CEF44D3863ULL,
		0x44AB5A92C693A23DULL,
		0x38296ABBFF16A4C1ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD508337D21DDDAE7ULL,
		0x7A4CF42788A1CDCDULL,
		0xDF67891BD9744556ULL,
		0x65459AB7445C9CE9ULL,
		0x9EBE4A7DFEFFD914ULL,
		0x56A2484FEF159EBEULL,
		0x8CBD3766BF979EAEULL,
		0x0ABEEC40F5DA50A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA1066FA43BBB5CEULL,
		0xF499E84F11439B9BULL,
		0xBECF1237B2E88AACULL,
		0xCA8B356E88B939D3ULL,
		0x3D7C94FBFDFFB228ULL,
		0xAD44909FDE2B3D7DULL,
		0x197A6ECD7F2F3D5CULL,
		0x157DD881EBB4A145ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF274A2C2864934E2ULL,
		0x1DB075EEB0145B74ULL,
		0xDCCA3EA0EA2D1367ULL,
		0xCB216D654907D4C5ULL,
		0xC6A4935DF58ED2B3ULL,
		0x47272B47CA3BA3D3ULL,
		0x02DFF20B028B12F0ULL,
		0x06BF9A6AEE6E6902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4E945850C9269C4ULL,
		0x3B60EBDD6028B6E9ULL,
		0xB9947D41D45A26CEULL,
		0x9642DACA920FA98BULL,
		0x8D4926BBEB1DA567ULL,
		0x8E4E568F947747A7ULL,
		0x05BFE416051625E0ULL,
		0x0D7F34D5DCDCD204ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD277F069C6922B52ULL,
		0x43A58745C10E4E72ULL,
		0x1245ABA016520179ULL,
		0xFB1B96F09B9DFA3AULL,
		0x49482472D154BA3FULL,
		0x0AC31F9C9B73EF0FULL,
		0xD3A8C2ED4EFDAD14ULL,
		0x113FCC4206F377C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4EFE0D38D2456A4ULL,
		0x874B0E8B821C9CE5ULL,
		0x248B57402CA402F2ULL,
		0xF6372DE1373BF474ULL,
		0x929048E5A2A9747FULL,
		0x15863F3936E7DE1EULL,
		0xA75185DA9DFB5A28ULL,
		0x227F98840DE6EF8FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x882C7160E51775B8ULL,
		0x65E10D7140B17878ULL,
		0x2230CD7A09279D51ULL,
		0xA75AB56FE73DDA35ULL,
		0x02413E012029FF11ULL,
		0x8EBAA28AF1F06EBEULL,
		0x2208B6BC3616AC5DULL,
		0x2717FF776B49B6E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1058E2C1CA2EEB70ULL,
		0xCBC21AE28162F0F1ULL,
		0x44619AF4124F3AA2ULL,
		0x4EB56ADFCE7BB46AULL,
		0x04827C024053FE23ULL,
		0x1D754515E3E0DD7CULL,
		0x44116D786C2D58BBULL,
		0x4E2FFEEED6936DCCULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACF9C440AEC9D026ULL,
		0xA0E54CACF1378A32ULL,
		0x5F9FD19285045A57ULL,
		0x449FC70B05CD878AULL,
		0x57367D7E8CBA6417ULL,
		0xCB8C20701D7C3E11ULL,
		0x2FE9D92B9CD16DDCULL,
		0x0DDAFA8155C14687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F388815D93A04CULL,
		0x41CA9959E26F1465ULL,
		0xBF3FA3250A08B4AFULL,
		0x893F8E160B9B0F14ULL,
		0xAE6CFAFD1974C82EULL,
		0x971840E03AF87C22ULL,
		0x5FD3B25739A2DBB9ULL,
		0x1BB5F502AB828D0EULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD17625C9E5CF0709ULL,
		0x19399BFAE3F064D0ULL,
		0xBE0CE6EA06205E19ULL,
		0x7448FEC404A05ECEULL,
		0x7DC211525E70C812ULL,
		0xD3FACC579331DAA7ULL,
		0xAE99092E836D0D11ULL,
		0x2F43F71276CE5A03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2EC4B93CB9E0E12ULL,
		0x327337F5C7E0C9A1ULL,
		0x7C19CDD40C40BC32ULL,
		0xE891FD880940BD9DULL,
		0xFB8422A4BCE19024ULL,
		0xA7F598AF2663B54EULL,
		0x5D32125D06DA1A23ULL,
		0x5E87EE24ED9CB407ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EB2D917D1BAA5AAULL,
		0x921081303D196012ULL,
		0x345C3498E2BAE8A1ULL,
		0x66738C08796DC1F2ULL,
		0x5BD25AC7FC8FA9C3ULL,
		0x63DBF1D3C261ECC7ULL,
		0x5E78AC7F4B7CD5D6ULL,
		0x3F32BCE58E516325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD65B22FA3754B54ULL,
		0x242102607A32C024ULL,
		0x68B86931C575D143ULL,
		0xCCE71810F2DB83E4ULL,
		0xB7A4B58FF91F5386ULL,
		0xC7B7E3A784C3D98EULL,
		0xBCF158FE96F9ABACULL,
		0x7E6579CB1CA2C64AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C7B34616C819840ULL,
		0xDA9D6160772E9E8DULL,
		0x70A325A29A70CD02ULL,
		0x6116A2FD298D511EULL,
		0x5DFE54546F92473DULL,
		0x6B93373E532C5BD7ULL,
		0x577AE126F5DA3143ULL,
		0x09FD603A2D43E361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F668C2D9033080ULL,
		0xB53AC2C0EE5D3D1AULL,
		0xE1464B4534E19A05ULL,
		0xC22D45FA531AA23CULL,
		0xBBFCA8A8DF248E7AULL,
		0xD7266E7CA658B7AEULL,
		0xAEF5C24DEBB46286ULL,
		0x13FAC0745A87C6C2ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B49F81708CC0E02ULL,
		0x9059A76F30368119ULL,
		0xE7C0DE0E796DFA44ULL,
		0xF7EAA0CDC54F2C38ULL,
		0xD76A4494E8A1FBE5ULL,
		0x3A7F4A2D99501A44ULL,
		0xDE6FB8BF0E14DC73ULL,
		0x251629FF8FE2F6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1693F02E11981C04ULL,
		0x20B34EDE606D0233ULL,
		0xCF81BC1CF2DBF489ULL,
		0xEFD5419B8A9E5871ULL,
		0xAED48929D143F7CBULL,
		0x74FE945B32A03489ULL,
		0xBCDF717E1C29B8E6ULL,
		0x4A2C53FF1FC5EDB7ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26ED0103D91818CBULL,
		0xEC7AA85079C13E7CULL,
		0x881C2C2FD0E9CD69ULL,
		0x3935E86E5D65DFFEULL,
		0xCD52688BF8A66231ULL,
		0x3960EEDFFBFD6945ULL,
		0xBD37D9B2F671A7F6ULL,
		0x27E753824A069DC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DDA0207B2303196ULL,
		0xD8F550A0F3827CF8ULL,
		0x1038585FA1D39AD3ULL,
		0x726BD0DCBACBBFFDULL,
		0x9AA4D117F14CC462ULL,
		0x72C1DDBFF7FAD28BULL,
		0x7A6FB365ECE34FECULL,
		0x4FCEA704940D3B93ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44BB0D3B6B23F73AULL,
		0xBF29D05F2B70D195ULL,
		0xA7FFA5A7EBA3FFA1ULL,
		0xA019D876A451BE48ULL,
		0xBCBBA4A21FC1C077ULL,
		0x3D9875FA80D378A7ULL,
		0x0D90BD54281AE250ULL,
		0x2DD1880BDE4028ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89761A76D647EE74ULL,
		0x7E53A0BE56E1A32AULL,
		0x4FFF4B4FD747FF43ULL,
		0x4033B0ED48A37C91ULL,
		0x797749443F8380EFULL,
		0x7B30EBF501A6F14FULL,
		0x1B217AA85035C4A0ULL,
		0x5BA31017BC805158ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44D4169DD1102046ULL,
		0xE9A1E362E916CEA8ULL,
		0xC0B56C90576BF175ULL,
		0xBB9560A66FE59C8FULL,
		0x72DC678BDAFB4ED2ULL,
		0x3DBBBFCD15C3C395ULL,
		0x90421B84EDF9CD07ULL,
		0x38211CA8F53A130BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A82D3BA220408CULL,
		0xD343C6C5D22D9D50ULL,
		0x816AD920AED7E2EBULL,
		0x772AC14CDFCB391FULL,
		0xE5B8CF17B5F69DA5ULL,
		0x7B777F9A2B87872AULL,
		0x20843709DBF39A0EULL,
		0x70423951EA742617ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393C08F12A701B67ULL,
		0x6DAFA7549FE4DE33ULL,
		0x4669249F45CF1856ULL,
		0x9F4C1262FCD2A87FULL,
		0x5DEE93482863A2E4ULL,
		0xB37F919D7577C4FAULL,
		0xC39C81AC39F0BE30ULL,
		0x1788CEED795700F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x727811E254E036CEULL,
		0xDB5F4EA93FC9BC66ULL,
		0x8CD2493E8B9E30ACULL,
		0x3E9824C5F9A550FEULL,
		0xBBDD269050C745C9ULL,
		0x66FF233AEAEF89F4ULL,
		0x8739035873E17C61ULL,
		0x2F119DDAF2AE01EBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x928FAC71C85DF38EULL,
		0x4FE8732FA1A00FFFULL,
		0x37E0A17A7D8372C1ULL,
		0xAB603967E8AEF96EULL,
		0x4C71BC2151547920ULL,
		0x7154B05CBA46B2F2ULL,
		0x95F65F55401EEB0AULL,
		0x3210EAA852BB108EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x251F58E390BBE71CULL,
		0x9FD0E65F43401FFFULL,
		0x6FC142F4FB06E582ULL,
		0x56C072CFD15DF2DCULL,
		0x98E37842A2A8F241ULL,
		0xE2A960B9748D65E4ULL,
		0x2BECBEAA803DD614ULL,
		0x6421D550A576211DULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0A286748769B9D1ULL,
		0x15A5989C903C25E6ULL,
		0xF2E18C83D825FB70ULL,
		0xD36AE0809707AAC0ULL,
		0xFEB8AE327DD36D98ULL,
		0x42F3C802058029ABULL,
		0x992834B63D86CEEAULL,
		0x135FCA01407A6A67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1450CE90ED373A2ULL,
		0x2B4B313920784BCDULL,
		0xE5C31907B04BF6E0ULL,
		0xA6D5C1012E0F5581ULL,
		0xFD715C64FBA6DB31ULL,
		0x85E790040B005357ULL,
		0x3250696C7B0D9DD4ULL,
		0x26BF940280F4D4CFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E52C9AD0DDB009DULL,
		0xCA90B69C5CFE4E66ULL,
		0xBFF0A250C83843C8ULL,
		0xFD34C62D34D19611ULL,
		0x5994B2E51856A67EULL,
		0xC9C9BC0C73351FF4ULL,
		0x590C6A44F800A456ULL,
		0x2204A63567FF8DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CA5935A1BB6013AULL,
		0x95216D38B9FC9CCCULL,
		0x7FE144A190708791ULL,
		0xFA698C5A69A32C23ULL,
		0xB32965CA30AD4CFDULL,
		0x93937818E66A3FE8ULL,
		0xB218D489F00148ADULL,
		0x44094C6ACFFF1BF0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x257BECFB9E983BECULL,
		0xD1CF3C768B0465BCULL,
		0x6B0C34687124498AULL,
		0x41C047C7B23F1DFEULL,
		0x43A8DDE6AE78FD52ULL,
		0x39C1CBDDAF9A282AULL,
		0x832A7E04A275E77FULL,
		0x203C48D4F77BAE9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF7D9F73D3077D8ULL,
		0xA39E78ED1608CB78ULL,
		0xD61868D0E2489315ULL,
		0x83808F8F647E3BFCULL,
		0x8751BBCD5CF1FAA4ULL,
		0x738397BB5F345054ULL,
		0x0654FC0944EBCEFEULL,
		0x407891A9EEF75D3BULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57D6DB3C9CF1DA82ULL,
		0x7E5716214A8EBE8EULL,
		0x40504132B5188BF7ULL,
		0x4E0AE7008CB04C62ULL,
		0x15E4DED9AA0C463CULL,
		0xC025DE5E90003AF6ULL,
		0x505DCB697512F13BULL,
		0x05E8844136DB0133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFADB67939E3B504ULL,
		0xFCAE2C42951D7D1CULL,
		0x80A082656A3117EEULL,
		0x9C15CE01196098C4ULL,
		0x2BC9BDB354188C78ULL,
		0x804BBCBD200075ECULL,
		0xA0BB96D2EA25E277ULL,
		0x0BD108826DB60266ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91631AB6926952B8ULL,
		0xCE6374E62A61BCE1ULL,
		0xA73F6FDE5390B4E6ULL,
		0x2598698005F8D3D3ULL,
		0xF5E029912635C542ULL,
		0x92C11D9E39BCCE49ULL,
		0xBC01D57971534C12ULL,
		0x3B90D307CFBD0FF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22C6356D24D2A570ULL,
		0x9CC6E9CC54C379C3ULL,
		0x4E7EDFBCA72169CDULL,
		0x4B30D3000BF1A7A7ULL,
		0xEBC053224C6B8A84ULL,
		0x25823B3C73799C93ULL,
		0x7803AAF2E2A69825ULL,
		0x7721A60F9F7A1FE1ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E6D8EB070F2794DULL,
		0x2631712A43790919ULL,
		0x0C5DE38ACE0E3943ULL,
		0xB6E971F484FBCBF4ULL,
		0xB0DA0C7D518C0CE2ULL,
		0x2898B69C903C1062ULL,
		0x419F5E3250D62157ULL,
		0x154B59C91669BEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDB1D60E1E4F29AULL,
		0x4C62E25486F21232ULL,
		0x18BBC7159C1C7286ULL,
		0x6DD2E3E909F797E8ULL,
		0x61B418FAA31819C5ULL,
		0x51316D39207820C5ULL,
		0x833EBC64A1AC42AEULL,
		0x2A96B3922CD37DB4ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6916B31663B6BBA6ULL,
		0x9125FC8647E1A6EDULL,
		0x31800BDC5268F817ULL,
		0x7F5E8146C47FA171ULL,
		0x32250F79A3E56B89ULL,
		0x0FB932CBD0FD8AC5ULL,
		0x5CEBAB7FE4F79E50ULL,
		0x3033536B43F71485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22D662CC76D774CULL,
		0x224BF90C8FC34DDAULL,
		0x630017B8A4D1F02FULL,
		0xFEBD028D88FF42E2ULL,
		0x644A1EF347CAD712ULL,
		0x1F726597A1FB158AULL,
		0xB9D756FFC9EF3CA0ULL,
		0x6066A6D687EE290AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD29A2323388201BFULL,
		0xC5B824F784B4FAC9ULL,
		0xD387FDF1945AF2D9ULL,
		0xB2A0E6DADF753C44ULL,
		0xDF9EE711B6968248ULL,
		0xB902E48CE1AC06FBULL,
		0x55C72D1D0A4603DEULL,
		0x3A4DD83D6B5E8218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53446467104037EULL,
		0x8B7049EF0969F593ULL,
		0xA70FFBE328B5E5B3ULL,
		0x6541CDB5BEEA7889ULL,
		0xBF3DCE236D2D0491ULL,
		0x7205C919C3580DF7ULL,
		0xAB8E5A3A148C07BDULL,
		0x749BB07AD6BD0430ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5D809DFA08AC434ULL,
		0x2486A2B4A81DDA0AULL,
		0xD44C344A78A953FBULL,
		0xEEAA77F9D65D5ABAULL,
		0x403934D8E09B6EDBULL,
		0xA6270F1E2086C238ULL,
		0x00939A6A49651DA1ULL,
		0x1406F276B1743DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB013BF41158868ULL,
		0x490D4569503BB415ULL,
		0xA8986894F152A7F6ULL,
		0xDD54EFF3ACBAB575ULL,
		0x807269B1C136DDB7ULL,
		0x4C4E1E3C410D8470ULL,
		0x012734D492CA3B43ULL,
		0x280DE4ED62E87B8AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0687D595DE6E169ULL,
		0x8924E81B1484FDECULL,
		0x7A3D82E6FA67F8BCULL,
		0x44CB1B258688995FULL,
		0xE9BFFDF1BA190778ULL,
		0xE6DEF856E3C9AFA9ULL,
		0xDBDA67EAE236C762ULL,
		0x141B90311CC24AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D0FAB2BBCDC2D2ULL,
		0x1249D0362909FBD9ULL,
		0xF47B05CDF4CFF179ULL,
		0x8996364B0D1132BEULL,
		0xD37FFBE374320EF0ULL,
		0xCDBDF0ADC7935F53ULL,
		0xB7B4CFD5C46D8EC5ULL,
		0x28372062398495DBULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x715D5680E75D4F4EULL,
		0x94ECC1385712BC6EULL,
		0xB768B410EBF432B7ULL,
		0x91FA5863B16FAF42ULL,
		0x223D24B97AC538D2ULL,
		0x2318F96B40B96CEDULL,
		0xEE5321959E3B831AULL,
		0x38FC792F13ABC957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2BAAD01CEBA9E9CULL,
		0x29D98270AE2578DCULL,
		0x6ED16821D7E8656FULL,
		0x23F4B0C762DF5E85ULL,
		0x447A4972F58A71A5ULL,
		0x4631F2D68172D9DAULL,
		0xDCA6432B3C770634ULL,
		0x71F8F25E275792AFULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54D0E1432448AB13ULL,
		0x3EC5FDA741BBC37CULL,
		0x192E4C0E92683A68ULL,
		0x2EEC0D7997344875ULL,
		0xDA50623100463AE4ULL,
		0xC3EA15E32250A383ULL,
		0x789F80B5C5FC6583ULL,
		0x08C1C4703544AF92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9A1C28648915626ULL,
		0x7D8BFB4E837786F8ULL,
		0x325C981D24D074D0ULL,
		0x5DD81AF32E6890EAULL,
		0xB4A0C462008C75C8ULL,
		0x87D42BC644A14707ULL,
		0xF13F016B8BF8CB07ULL,
		0x118388E06A895F24ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76F422A0360BC557ULL,
		0x4EF14B46897A0F4DULL,
		0xBCA686DCC48BFC55ULL,
		0x0D5AA2039B795FFEULL,
		0x057C89C4098F4728ULL,
		0x425C224F1E3D18E6ULL,
		0x43DCF8B243858979ULL,
		0x12F4D1C3DC90E9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE845406C178AAEULL,
		0x9DE2968D12F41E9AULL,
		0x794D0DB98917F8AAULL,
		0x1AB5440736F2BFFDULL,
		0x0AF91388131E8E50ULL,
		0x84B8449E3C7A31CCULL,
		0x87B9F164870B12F2ULL,
		0x25E9A387B921D3E0ULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFCBECBFB372C35BULL,
		0x5C1899DD487D679BULL,
		0x9B0FFC660537ED95ULL,
		0x18D3037A56B1F7EAULL,
		0xCB28A4F0F316557BULL,
		0xC68D89B37AFBB7EBULL,
		0x6860577DD12FEC28ULL,
		0x2C4B3D2AC70686C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF97D97F66E586B6ULL,
		0xB83133BA90FACF37ULL,
		0x361FF8CC0A6FDB2AULL,
		0x31A606F4AD63EFD5ULL,
		0x965149E1E62CAAF6ULL,
		0x8D1B1366F5F76FD7ULL,
		0xD0C0AEFBA25FD851ULL,
		0x58967A558E0D0D8AULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D2FD3FF9E28DF76ULL,
		0x9F3849AA17AADDABULL,
		0x68AB18E8F3450BAFULL,
		0xB9E4BC748A5A306BULL,
		0xED37020C251290C6ULL,
		0xEC9331916374703DULL,
		0x8CA44C3428C0B9D9ULL,
		0x1C0741357751B93FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5FA7FF3C51BEECULL,
		0x3E7093542F55BB56ULL,
		0xD15631D1E68A175FULL,
		0x73C978E914B460D6ULL,
		0xDA6E04184A25218DULL,
		0xD9266322C6E8E07BULL,
		0x19489868518173B3ULL,
		0x380E826AEEA3727FULL
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
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB37798BAFE765AD0ULL,
		0x3BD58F64A2419D2DULL,
		0x73EB2625A44BEC87ULL,
		0xBF977988E4063486ULL,
		0xCB7BE491C80F3A90ULL,
		0xEE408AD825270ECDULL,
		0x158B673D1DBE1D18ULL,
		0x00E7971D2CE55FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66EF3175FCECB5A0ULL,
		0x77AB1EC944833A5BULL,
		0xE7D64C4B4897D90EULL,
		0x7F2EF311C80C690CULL,
		0x96F7C923901E7521ULL,
		0xDC8115B04A4E1D9BULL,
		0x2B16CE7A3B7C3A31ULL,
		0x01CF2E3A59CABFA0ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4B3C13F5771F751AULL,
		0x5420E0E1745B69EEULL,
		0x7C12ACAE98114AE7ULL,
		0xCCD6F50ECD01D7A5ULL,
		0xF95A18722A248FB5ULL,
		0x471B25BFC1630A01ULL,
		0xD130DA9C2CC77E68ULL,
		0x252FF11B4D205DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x967827EAEE3EEA34ULL,
		0xA841C1C2E8B6D3DCULL,
		0xF825595D302295CEULL,
		0x99ADEA1D9A03AF4AULL,
		0xF2B430E454491F6BULL,
		0x8E364B7F82C61403ULL,
		0xA261B538598EFCD0ULL,
		0x4A5FE2369A40BB9FULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x269D2D5CDED7F89AULL,
		0x69311818BC8358D9ULL,
		0x0E681A2405E90242ULL,
		0xEEBE94DB87C7E771ULL,
		0xE3E3013E6140EB95ULL,
		0x6D08DA6EC0222484ULL,
		0x7CA861CD0354BF27ULL,
		0x2CA622A79459F452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3A5AB9BDAFF134ULL,
		0xD26230317906B1B2ULL,
		0x1CD034480BD20484ULL,
		0xDD7D29B70F8FCEE2ULL,
		0xC7C6027CC281D72BULL,
		0xDA11B4DD80444909ULL,
		0xF950C39A06A97E4EULL,
		0x594C454F28B3E8A4ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2B159B9E548F28C9ULL,
		0x398C9BF60BE628BEULL,
		0x5214A95E3F974009ULL,
		0x9CDFAA442DB88FE1ULL,
		0xD51EE8BF0B793659ULL,
		0xD37F38C98B3E1E33ULL,
		0xE09CC1DEFD68EA38ULL,
		0x18A83C0139389FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x562B373CA91E5192ULL,
		0x731937EC17CC517CULL,
		0xA42952BC7F2E8012ULL,
		0x39BF54885B711FC2ULL,
		0xAA3DD17E16F26CB3ULL,
		0xA6FE7193167C3C67ULL,
		0xC13983BDFAD1D471ULL,
		0x3150780272713FEFULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x646D7F78D944DBEFULL,
		0x0AE81D42B1FA3C41ULL,
		0x4060D5DA88E63F4EULL,
		0x84BAE55CABDA9F42ULL,
		0xEC97F0815068AEB2ULL,
		0x54285F096FBB3A86ULL,
		0x4A0508A425E6527CULL,
		0x15AF6C4E0C830D5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8DAFEF1B289B7DEULL,
		0x15D03A8563F47882ULL,
		0x80C1ABB511CC7E9CULL,
		0x0975CAB957B53E84ULL,
		0xD92FE102A0D15D65ULL,
		0xA850BE12DF76750DULL,
		0x940A11484BCCA4F8ULL,
		0x2B5ED89C19061AB6ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA74A7662004CB025ULL,
		0x33AFAFD06A93A231ULL,
		0x58288E7DA74FFC61ULL,
		0x480EE267A6115428ULL,
		0x872468DFD84E6DCDULL,
		0x63BDAC5857C55CA1ULL,
		0xE4FFD7A2998EF116ULL,
		0x3EAA8DC421B1A508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E94ECC40099604AULL,
		0x675F5FA0D5274463ULL,
		0xB0511CFB4E9FF8C2ULL,
		0x901DC4CF4C22A850ULL,
		0x0E48D1BFB09CDB9AULL,
		0xC77B58B0AF8AB943ULL,
		0xC9FFAF45331DE22CULL,
		0x7D551B8843634A11ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x45C5B10B300CA654ULL,
		0xF2D79B1560AF89A4ULL,
		0xCC1D548F19CC4419ULL,
		0x09ED5A3BD77E94CEULL,
		0xFC61E862E2288A6DULL,
		0x406716B4C3AAD551ULL,
		0x3159601DC019C4BFULL,
		0x019A13DC57C557B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B8B621660194CA8ULL,
		0xE5AF362AC15F1348ULL,
		0x983AA91E33988833ULL,
		0x13DAB477AEFD299DULL,
		0xF8C3D0C5C45114DAULL,
		0x80CE2D698755AAA3ULL,
		0x62B2C03B8033897EULL,
		0x033427B8AF8AAF66ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3B2F724E986FDE2EULL,
		0x148D134908A794F0ULL,
		0x10C2F61840FD53FAULL,
		0x9DE7E6EF2F231F22ULL,
		0x20A7C1BE943DBC0DULL,
		0xE1C93C529B26B85FULL,
		0x6F2D49241081F4AAULL,
		0x3A1E8C9F4583B061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x765EE49D30DFBC5CULL,
		0x291A2692114F29E0ULL,
		0x2185EC3081FAA7F4ULL,
		0x3BCFCDDE5E463E44ULL,
		0x414F837D287B781BULL,
		0xC39278A5364D70BEULL,
		0xDE5A92482103E955ULL,
		0x743D193E8B0760C2ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x082F3C84ADD486D0ULL,
		0x02804319398599C7ULL,
		0x84617FEBB030DBA6ULL,
		0xD403BC102C2AB4E5ULL,
		0x80042CB8242E0324ULL,
		0x07DAA28896ECEB7AULL,
		0x5B991E934EFA03FBULL,
		0x1D005E02286846F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105E79095BA90DA0ULL,
		0x05008632730B338EULL,
		0x08C2FFD76061B74CULL,
		0xA8077820585569CBULL,
		0x00085970485C0649ULL,
		0x0FB545112DD9D6F5ULL,
		0xB7323D269DF407F6ULL,
		0x3A00BC0450D08DEEULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7013F0FABB0C6D7DULL,
		0x0CAA606D7398FBCDULL,
		0x5176084D66A304B1ULL,
		0x4C40B6EE247C9F83ULL,
		0x227733914F5F6310ULL,
		0x8FF545312B1A46A9ULL,
		0xD09E9EA59902BD98ULL,
		0x277453AAB0CBE1AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE027E1F57618DAFAULL,
		0x1954C0DAE731F79AULL,
		0xA2EC109ACD460962ULL,
		0x98816DDC48F93F06ULL,
		0x44EE67229EBEC620ULL,
		0x1FEA8A6256348D52ULL,
		0xA13D3D4B32057B31ULL,
		0x4EE8A7556197C35DULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8E7795DB791DFFD0ULL,
		0x26B2F2E83E4F5EC1ULL,
		0xF25501B1072ECF14ULL,
		0x8F5813F8A73E63AAULL,
		0x3E5D191BB69F258BULL,
		0x83E2672192D1800CULL,
		0x57852855EA89012AULL,
		0x1112D1873A18BB01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEF2BB6F23BFFA0ULL,
		0x4D65E5D07C9EBD83ULL,
		0xE4AA03620E5D9E28ULL,
		0x1EB027F14E7CC755ULL,
		0x7CBA32376D3E4B17ULL,
		0x07C4CE4325A30018ULL,
		0xAF0A50ABD5120255ULL,
		0x2225A30E74317602ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x20DD3845224D39A7ULL,
		0x722E39A8D920E3C2ULL,
		0x96E71FA143F89AE3ULL,
		0x9ACAE82D31C56754ULL,
		0xEF4E2A5470760CDBULL,
		0x020ED861F13A21DCULL,
		0xC121D7649C967BE0ULL,
		0x2ECCE1EBD93B8315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BA708A449A734EULL,
		0xE45C7351B241C784ULL,
		0x2DCE3F4287F135C6ULL,
		0x3595D05A638ACEA9ULL,
		0xDE9C54A8E0EC19B7ULL,
		0x041DB0C3E27443B9ULL,
		0x8243AEC9392CF7C0ULL,
		0x5D99C3D7B277062BULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE099F5AA37623AE7ULL,
		0x496D33A360873A46ULL,
		0x703347EF5440A0CCULL,
		0xF2FF8FD254E59730ULL,
		0x20DE5A589B3C3A33ULL,
		0xDF2A89E16D39D996ULL,
		0xBA460039840238B0ULL,
		0x2421248D05E8F139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC133EB546EC475CEULL,
		0x92DA6746C10E748DULL,
		0xE0668FDEA8814198ULL,
		0xE5FF1FA4A9CB2E60ULL,
		0x41BCB4B136787467ULL,
		0xBE5513C2DA73B32CULL,
		0x748C007308047161ULL,
		0x4842491A0BD1E273ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xCAD6F1D2E8A9F373ULL,
		0x058AA75B50CC6696ULL,
		0x78E79E4C5AED083DULL,
		0xA2A255D20C1B2F7EULL,
		0xACCA202E20A591E3ULL,
		0xB21244A35A188D19ULL,
		0x8DF79087CAC38C27ULL,
		0x2E8F343981E12261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95ADE3A5D153E6E6ULL,
		0x0B154EB6A198CD2DULL,
		0xF1CF3C98B5DA107AULL,
		0x4544ABA418365EFCULL,
		0x5994405C414B23C7ULL,
		0x64248946B4311A33ULL,
		0x1BEF210F9587184FULL,
		0x5D1E687303C244C3ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x77A08AB5FCA7FA0BULL,
		0xFE34F782C1CD4AE2ULL,
		0xD0348BC53982B134ULL,
		0x6F0D44C38B23414FULL,
		0x5BF3565CEE11EC8BULL,
		0x26D2491A0D3D58ABULL,
		0x4B2D343DB80CD02DULL,
		0x0EA5E5DB807017BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF41156BF94FF416ULL,
		0xFC69EF05839A95C4ULL,
		0xA069178A73056269ULL,
		0xDE1A89871646829FULL,
		0xB7E6ACB9DC23D916ULL,
		0x4DA492341A7AB156ULL,
		0x965A687B7019A05AULL,
		0x1D4BCBB700E02F74ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9D0654BE588D19B6ULL,
		0xEBAEECF73A15F1CEULL,
		0x1F602553A9183788ULL,
		0xFBFD8912DE49C610ULL,
		0xD4FB162E5139A875ULL,
		0xF67F8B8FFFB98DC1ULL,
		0x09A877EB8BB960C7ULL,
		0x21852E1DA52CA4B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A0CA97CB11A336CULL,
		0xD75DD9EE742BE39DULL,
		0x3EC04AA752306F11ULL,
		0xF7FB1225BC938C20ULL,
		0xA9F62C5CA27350EBULL,
		0xECFF171FFF731B83ULL,
		0x1350EFD71772C18FULL,
		0x430A5C3B4A59496CULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDC244E6D8428710EULL,
		0x84F4729CDF3D3C1FULL,
		0x3727DDA4D5D84C8AULL,
		0xDEA112A97A9DB339ULL,
		0x940FED2558D0D01AULL,
		0x66DEE9B68867C5F6ULL,
		0xA9A147B56FDD2781ULL,
		0x07CF08633C71542BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8489CDB0850E21CULL,
		0x09E8E539BE7A783FULL,
		0x6E4FBB49ABB09915ULL,
		0xBD422552F53B6672ULL,
		0x281FDA4AB1A1A035ULL,
		0xCDBDD36D10CF8BEDULL,
		0x53428F6ADFBA4F02ULL,
		0x0F9E10C678E2A857ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x042FC06C07489B4AULL,
		0x9967DEB576A741B2ULL,
		0xE227C230ADB64673ULL,
		0x3A77AE149291C06DULL,
		0x0BAE31A3DC23C386ULL,
		0x1C9CCDB31BE869E4ULL,
		0xAAAE1B466B2F814FULL,
		0x3561C7C4F2E2B1A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085F80D80E913694ULL,
		0x32CFBD6AED4E8364ULL,
		0xC44F84615B6C8CE7ULL,
		0x74EF5C29252380DBULL,
		0x175C6347B847870CULL,
		0x39399B6637D0D3C8ULL,
		0x555C368CD65F029EULL,
		0x6AC38F89E5C5634BULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x391B493CB8232BD3ULL,
		0xED9F011611B0513FULL,
		0x12183785A6C841AEULL,
		0x51AFB8BAFA7DD775ULL,
		0x3E7CA02370936588ULL,
		0xF925969A4E615933ULL,
		0x8CAA0013B30B69F4ULL,
		0x3B75A8CFE99BFC18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72369279704657A6ULL,
		0xDB3E022C2360A27EULL,
		0x24306F0B4D90835DULL,
		0xA35F7175F4FBAEEAULL,
		0x7CF94046E126CB10ULL,
		0xF24B2D349CC2B266ULL,
		0x195400276616D3E9ULL,
		0x76EB519FD337F831ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x57FD5FCB64DA7E06ULL,
		0xB5C1C066E3FE5106ULL,
		0x967A7098D8D1B3D9ULL,
		0x301526F24ECABE11ULL,
		0xAB839011427EF0C7ULL,
		0x3B1C80AC32705832ULL,
		0x25F382C11B6AA973ULL,
		0x1376539EF79FB12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFABF96C9B4FC0CULL,
		0x6B8380CDC7FCA20CULL,
		0x2CF4E131B1A367B3ULL,
		0x602A4DE49D957C23ULL,
		0x5707202284FDE18EULL,
		0x7639015864E0B065ULL,
		0x4BE7058236D552E6ULL,
		0x26ECA73DEF3F625CULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x24B46CE44535549AULL,
		0x46E2FC42F4BE5B54ULL,
		0xF535E7258F9C51B1ULL,
		0x18EA331AB6E76E21ULL,
		0x46E11820A4DBEA78ULL,
		0x5D451154DD0E774DULL,
		0x5E85B0848B1073EFULL,
		0x1AB47923CCEC9B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4968D9C88A6AA934ULL,
		0x8DC5F885E97CB6A8ULL,
		0xEA6BCE4B1F38A362ULL,
		0x31D466356DCEDC43ULL,
		0x8DC2304149B7D4F0ULL,
		0xBA8A22A9BA1CEE9AULL,
		0xBD0B61091620E7DEULL,
		0x3568F24799D93642ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA3DF0983B10B2BDDULL,
		0x549CC3CCBA551932ULL,
		0x78AFC380A6DD2365ULL,
		0xAB1BCC35510595CAULL,
		0x01CC3BE204B3839AULL,
		0x23E556871DF2167BULL,
		0x2628B17E7FAE79FFULL,
		0x1512993B6B66EE31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47BE1307621657BAULL,
		0xA939879974AA3265ULL,
		0xF15F87014DBA46CAULL,
		0x5637986AA20B2B94ULL,
		0x039877C409670735ULL,
		0x47CAAD0E3BE42CF6ULL,
		0x4C5162FCFF5CF3FEULL,
		0x2A253276D6CDDC62ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x43A468C49F598EAFULL,
		0x053794731352FF69ULL,
		0x3814A2C6D302F18DULL,
		0x1A01CD1D9A95E6CDULL,
		0x6242026CF96A0E70ULL,
		0x5568831A3D560864ULL,
		0x1062B8C0FF25CE5CULL,
		0x2817D2659EDBCA9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8748D1893EB31D5EULL,
		0x0A6F28E626A5FED2ULL,
		0x7029458DA605E31AULL,
		0x34039A3B352BCD9AULL,
		0xC48404D9F2D41CE0ULL,
		0xAAD106347AAC10C8ULL,
		0x20C57181FE4B9CB8ULL,
		0x502FA4CB3DB7953EULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x46DD0B510E00FB1CULL,
		0x10E86C5DBD5FBA3CULL,
		0xC6F1133CDC2E787DULL,
		0x9491A68EC0E8C22BULL,
		0x1F3232E8F1EE4FFCULL,
		0x16FB69BF174F0320ULL,
		0xC6C7F7CEE11E365FULL,
		0x3D14E7D0969D76FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBA16A21C01F638ULL,
		0x21D0D8BB7ABF7478ULL,
		0x8DE22679B85CF0FAULL,
		0x29234D1D81D18457ULL,
		0x3E6465D1E3DC9FF9ULL,
		0x2DF6D37E2E9E0640ULL,
		0x8D8FEF9DC23C6CBEULL,
		0x7A29CFA12D3AEDF7ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x80FDB51752FF235AULL,
		0xEC21406357933ACBULL,
		0xD176C2CF687B5885ULL,
		0x2C6E45B23A645E39ULL,
		0x4F0B884B4483D483ULL,
		0x4C843B08C6711524ULL,
		0xC8F542B0516BE3E1ULL,
		0x3FC4C20CA81451F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FB6A2EA5FE46B4ULL,
		0xD84280C6AF267597ULL,
		0xA2ED859ED0F6B10BULL,
		0x58DC8B6474C8BC73ULL,
		0x9E1710968907A906ULL,
		0x990876118CE22A48ULL,
		0x91EA8560A2D7C7C2ULL,
		0x7F8984195028A3F1ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x457E297D229DAB06ULL,
		0x1CA7AA3724271018ULL,
		0x88EC862A63A9D207ULL,
		0xDD23D5A0C211E45EULL,
		0x52DC47079DA2BA79ULL,
		0x7B8683C5A0493C32ULL,
		0x9334D29C9F8B29A6ULL,
		0x0943E79A9391956EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFC52FA453B560CULL,
		0x394F546E484E2030ULL,
		0x11D90C54C753A40EULL,
		0xBA47AB418423C8BDULL,
		0xA5B88E0F3B4574F3ULL,
		0xF70D078B40927864ULL,
		0x2669A5393F16534CULL,
		0x1287CF3527232ADDULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9E2B1966959AAC91ULL,
		0xE480743E3BD8D79EULL,
		0xE69B2A7072EA1BEAULL,
		0x9A7DC925E16FAAF1ULL,
		0x02062727594BBF7EULL,
		0x4AD344702799C454ULL,
		0x6E74602469A856E2ULL,
		0x03AA97039A8C95F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5632CD2B355922ULL,
		0xC900E87C77B1AF3DULL,
		0xCD3654E0E5D437D5ULL,
		0x34FB924BC2DF55E3ULL,
		0x040C4E4EB2977EFDULL,
		0x95A688E04F3388A8ULL,
		0xDCE8C048D350ADC4ULL,
		0x07552E0735192BECULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x691C9552483F4B83ULL,
		0x2C299D4BB187A6E6ULL,
		0xD858F7DDF0384B33ULL,
		0x7A0BEED214D02C85ULL,
		0x1F64195AB8807ECCULL,
		0x8ACBF08794D79AA4ULL,
		0x42D60C28A9939347ULL,
		0x0CCE35201AA58830ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2392AA4907E9706ULL,
		0x58533A97630F4DCCULL,
		0xB0B1EFBBE0709666ULL,
		0xF417DDA429A0590BULL,
		0x3EC832B57100FD98ULL,
		0x1597E10F29AF3548ULL,
		0x85AC18515327268FULL,
		0x199C6A40354B1060ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC3EDD59EFB22FE8CULL,
		0x1D0792E20A47D78DULL,
		0xEAB7F5630B2CC797ULL,
		0x1D5C9AEDD20E2036ULL,
		0x028C0AB799735EE9ULL,
		0x26F6B2581E2E8D9CULL,
		0xA5B4C94617D58429ULL,
		0x393E627A6E12816DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87DBAB3DF645FD18ULL,
		0x3A0F25C4148FAF1BULL,
		0xD56FEAC616598F2EULL,
		0x3AB935DBA41C406DULL,
		0x0518156F32E6BDD2ULL,
		0x4DED64B03C5D1B38ULL,
		0x4B69928C2FAB0852ULL,
		0x727CC4F4DC2502DBULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x88AFC8AE4A6B9639ULL,
		0x613022B920EC0422ULL,
		0x1435EAEAF9AA6DD2ULL,
		0x2F6BCF5D3C81669BULL,
		0x2ED90C0BD0DD3659ULL,
		0xB60506C273EFD9CBULL,
		0x41AF2FE46CB3AA56ULL,
		0x18016B81F437DEA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115F915C94D72C72ULL,
		0xC260457241D80845ULL,
		0x286BD5D5F354DBA4ULL,
		0x5ED79EBA7902CD36ULL,
		0x5DB21817A1BA6CB2ULL,
		0x6C0A0D84E7DFB396ULL,
		0x835E5FC8D96754ADULL,
		0x3002D703E86FBD46ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7EE12C8FDBD5631DULL,
		0x330F2BC1BB429FCCULL,
		0x197C09714F46D122ULL,
		0x93A175E53DD517DCULL,
		0x6D2280622D96F3B9ULL,
		0xDC125BDC09F303E6ULL,
		0xCB8F9E79D556C758ULL,
		0x1FFB2D327D8714EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC2591FB7AAC63AULL,
		0x661E578376853F98ULL,
		0x32F812E29E8DA244ULL,
		0x2742EBCA7BAA2FB8ULL,
		0xDA4500C45B2DE773ULL,
		0xB824B7B813E607CCULL,
		0x971F3CF3AAAD8EB1ULL,
		0x3FF65A64FB0E29DDULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x96206A4DF4451A4EULL,
		0x4A23677ECACC5A7DULL,
		0xBA3BB319A1CD9CD5ULL,
		0x7FE1A919E3D66CE9ULL,
		0x3C71D09DBEBA55A5ULL,
		0x25D98C9F6E75EF72ULL,
		0xA38C1A5A74C6AB4FULL,
		0x17008A915166AA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C40D49BE88A349CULL,
		0x9446CEFD9598B4FBULL,
		0x74776633439B39AAULL,
		0xFFC35233C7ACD9D3ULL,
		0x78E3A13B7D74AB4AULL,
		0x4BB3193EDCEBDEE4ULL,
		0x471834B4E98D569EULL,
		0x2E011522A2CD5433ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC45AB0044A603561ULL,
		0xD3D616CF43DCFF47ULL,
		0x6D0A458E6B29295CULL,
		0x5F38C9EC430C385BULL,
		0x7998B6C0D8E67798ULL,
		0x078056F91D593D0CULL,
		0x76EF3BDCCE4995C0ULL,
		0x0AB4F9703FE73C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B5600894C06AC2ULL,
		0xA7AC2D9E87B9FE8FULL,
		0xDA148B1CD65252B9ULL,
		0xBE7193D8861870B6ULL,
		0xF3316D81B1CCEF30ULL,
		0x0F00ADF23AB27A18ULL,
		0xEDDE77B99C932B80ULL,
		0x1569F2E07FCE788AULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDE554984B94B8E43ULL,
		0x5E48BAF04DA52FC3ULL,
		0x4E2AEE0465D1A534ULL,
		0xB7AA417838E496ADULL,
		0x045A13D8F8FF383FULL,
		0xA829392CC07DF711ULL,
		0x86A606A9DB6C34EDULL,
		0x231BF9BD89CEB3F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAA930972971C86ULL,
		0xBC9175E09B4A5F87ULL,
		0x9C55DC08CBA34A68ULL,
		0x6F5482F071C92D5AULL,
		0x08B427B1F1FE707FULL,
		0x5052725980FBEE22ULL,
		0x0D4C0D53B6D869DBULL,
		0x4637F37B139D67EFULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE2CC882FC52A0A5CULL,
		0xAD857A13C8CF3DFEULL,
		0x18B5C59A69C59694ULL,
		0xE5A6E0CE7E0F3C7EULL,
		0xAD5E1327D4F3A186ULL,
		0x0DCCE23E62771C2BULL,
		0x4CDB2DEFDCCD46A2ULL,
		0x30C3042ADD003A6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC599105F8A5414B8ULL,
		0x5B0AF427919E7BFDULL,
		0x316B8B34D38B2D29ULL,
		0xCB4DC19CFC1E78FCULL,
		0x5ABC264FA9E7430DULL,
		0x1B99C47CC4EE3857ULL,
		0x99B65BDFB99A8D44ULL,
		0x61860855BA0074D8ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5ACD13A03280EC7EULL,
		0x0FD6E2DAC651E66EULL,
		0x9CE14A43B5CB1864ULL,
		0xE05132FC4C92F62EULL,
		0x85C545F87B29353AULL,
		0x7A688B52377A9DE1ULL,
		0xBC87AACE2F55DB8DULL,
		0x04EAD1A7AA3B6DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59A27406501D8FCULL,
		0x1FADC5B58CA3CCDCULL,
		0x39C294876B9630C8ULL,
		0xC0A265F89925EC5DULL,
		0x0B8A8BF0F6526A75ULL,
		0xF4D116A46EF53BC3ULL,
		0x790F559C5EABB71AULL,
		0x09D5A34F5476DB71ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAC9A78CE1ED210C7ULL,
		0x06F333BE13C330BAULL,
		0xB1F4235093E78027ULL,
		0x1392C6857327AC1DULL,
		0xBE9118387BECF2B5ULL,
		0x6DB6838BBD1BC9B7ULL,
		0x1E115ADFBF10A513ULL,
		0x27D1F811CF257375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5934F19C3DA4218EULL,
		0x0DE6677C27866175ULL,
		0x63E846A127CF004EULL,
		0x27258D0AE64F583BULL,
		0x7D223070F7D9E56AULL,
		0xDB6D07177A37936FULL,
		0x3C22B5BF7E214A26ULL,
		0x4FA3F0239E4AE6EAULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC3CC06186DBBEE19ULL,
		0x0F153935EC8ADC46ULL,
		0xC276455537562668ULL,
		0x0C4215395BD778FCULL,
		0xB2BDAA1DE2095D9FULL,
		0x079BA690C766BF32ULL,
		0x5F650BA8FE9E8038ULL,
		0x3A815D79BAE0E3C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87980C30DB77DC32ULL,
		0x1E2A726BD915B88DULL,
		0x84EC8AAA6EAC4CD0ULL,
		0x18842A72B7AEF1F9ULL,
		0x657B543BC412BB3EULL,
		0x0F374D218ECD7E65ULL,
		0xBECA1751FD3D0070ULL,
		0x7502BAF375C1C780ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x84EA2E06F342E8BCULL,
		0x678F3D7090437D3FULL,
		0x6584F739D0CFC5B3ULL,
		0xC9205C9262E20B95ULL,
		0x676B904305771B2FULL,
		0xCB7C2381F1172FBFULL,
		0x000E3B473256C5D2ULL,
		0x03B66DFA2AF49A7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D45C0DE685D178ULL,
		0xCF1E7AE12086FA7FULL,
		0xCB09EE73A19F8B66ULL,
		0x9240B924C5C4172AULL,
		0xCED720860AEE365FULL,
		0x96F84703E22E5F7EULL,
		0x001C768E64AD8BA5ULL,
		0x076CDBF455E934FAULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE8AE0301C4B7A253ULL,
		0x3EBADECCBB6248EDULL,
		0x18508D4FBA6C9E16ULL,
		0x6DD78458E572D37DULL,
		0xDBACD5BAA0B856D8ULL,
		0xDBA29B02E7BC06EAULL,
		0xD49C467AF34B3EC4ULL,
		0x26CB173A426072FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15C0603896F44A6ULL,
		0x7D75BD9976C491DBULL,
		0x30A11A9F74D93C2CULL,
		0xDBAF08B1CAE5A6FAULL,
		0xB759AB754170ADB0ULL,
		0xB7453605CF780DD5ULL,
		0xA9388CF5E6967D89ULL,
		0x4D962E7484C0E5FBULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB81819F014E6BF75ULL,
		0xA07FDA10AA079F1CULL,
		0x5B41248AE36DE22BULL,
		0x83DD2839C2073242ULL,
		0xAFD7C57AF828E287ULL,
		0x6BAC7D2BC2FBAC31ULL,
		0xBEED11C3AD984FA8ULL,
		0x27EDCC1E0DF30090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x703033E029CD7EEAULL,
		0x40FFB421540F3E39ULL,
		0xB6824915C6DBC457ULL,
		0x07BA5073840E6484ULL,
		0x5FAF8AF5F051C50FULL,
		0xD758FA5785F75863ULL,
		0x7DDA23875B309F50ULL,
		0x4FDB983C1BE60121ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA7797D376B56EFD1ULL,
		0xC750708DF037F781ULL,
		0x23E4413EF4C80631ULL,
		0x881EA8D187466863ULL,
		0x19E7D1C7B4C5D4D0ULL,
		0x61E3BEA4BDB6F6ABULL,
		0x8C55F06FD8DCDB4EULL,
		0x3D0B9897D8A3BB01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF2FA6ED6ADDFA2ULL,
		0x8EA0E11BE06FEF03ULL,
		0x47C8827DE9900C63ULL,
		0x103D51A30E8CD0C6ULL,
		0x33CFA38F698BA9A1ULL,
		0xC3C77D497B6DED56ULL,
		0x18ABE0DFB1B9B69CULL,
		0x7A17312FB1477603ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x711A637541BF65D6ULL,
		0x8F423D621CFBD0FBULL,
		0x0FDA956D6136224CULL,
		0x786E958D9701DF53ULL,
		0x86261642ADBEF65DULL,
		0xB328B307602C063AULL,
		0x77B69366ED43C4B1ULL,
		0x2E2BD878A76A3AE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE234C6EA837ECBACULL,
		0x1E847AC439F7A1F6ULL,
		0x1FB52ADAC26C4499ULL,
		0xF0DD2B1B2E03BEA6ULL,
		0x0C4C2C855B7DECBAULL,
		0x6651660EC0580C75ULL,
		0xEF6D26CDDA878963ULL,
		0x5C57B0F14ED475C2ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x633AA7F816C26E6AULL,
		0x4E58310737241BAAULL,
		0x199C3DA454D7EDD1ULL,
		0x251BFAE37D995B2AULL,
		0x2ED4AABA04FD620AULL,
		0x5A328D69563DD4C9ULL,
		0x797860934BC0B11FULL,
		0x02D9CCDC001EFCCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6754FF02D84DCD4ULL,
		0x9CB0620E6E483754ULL,
		0x33387B48A9AFDBA2ULL,
		0x4A37F5C6FB32B654ULL,
		0x5DA9557409FAC414ULL,
		0xB4651AD2AC7BA992ULL,
		0xF2F0C1269781623EULL,
		0x05B399B8003DF99EULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE26ED7765D33BE52ULL,
		0x3DB6DCDCADB1F57DULL,
		0x046167D2DB8A742EULL,
		0xA611665144B9571EULL,
		0xB829C60BD2268FE5ULL,
		0x226333F77B3A9858ULL,
		0xC0976B44C6C25894ULL,
		0x134BE06B93F920FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4DDAEECBA677CA4ULL,
		0x7B6DB9B95B63EAFBULL,
		0x08C2CFA5B714E85CULL,
		0x4C22CCA28972AE3CULL,
		0x70538C17A44D1FCBULL,
		0x44C667EEF67530B1ULL,
		0x812ED6898D84B128ULL,
		0x2697C0D727F241F5ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x39198CCE4396A58BULL,
		0x0A64C93AED172BA5ULL,
		0x98CF7A35A099616EULL,
		0x8298D4B342CFD965ULL,
		0x2DDF6176D5E8CA99ULL,
		0x53AA98FD23ECE145ULL,
		0x76588D9118008A2DULL,
		0x23B064777A9FA4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7233199C872D4B16ULL,
		0x14C99275DA2E574AULL,
		0x319EF46B4132C2DCULL,
		0x0531A966859FB2CBULL,
		0x5BBEC2EDABD19533ULL,
		0xA75531FA47D9C28AULL,
		0xECB11B223001145AULL,
		0x4760C8EEF53F49F6ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x09B9630208375AFFULL,
		0x6BB018FEDC0C99F0ULL,
		0x732294C4FB1C1B88ULL,
		0xBBCA442CEEE09CC9ULL,
		0x1E4845C1E51113CAULL,
		0x25794573054B8029ULL,
		0x2DBF54BC4477090CULL,
		0x3CA8215AEA777135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1372C604106EB5FEULL,
		0xD76031FDB81933E0ULL,
		0xE6452989F6383710ULL,
		0x77948859DDC13992ULL,
		0x3C908B83CA222795ULL,
		0x4AF28AE60A970052ULL,
		0x5B7EA97888EE1218ULL,
		0x795042B5D4EEE26AULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA8E36E9E118C69CAULL,
		0xB6844BAC8AAFA040ULL,
		0x53ECFB2F071BCC6EULL,
		0x32159C122978F2FDULL,
		0x6D88F4D665993BBDULL,
		0x47132EA6FD3D8AABULL,
		0x887ADA266289B316ULL,
		0x168423692B31EB6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51C6DD3C2318D394ULL,
		0x6D089759155F4081ULL,
		0xA7D9F65E0E3798DDULL,
		0x642B382452F1E5FAULL,
		0xDB11E9ACCB32777AULL,
		0x8E265D4DFA7B1556ULL,
		0x10F5B44CC513662CULL,
		0x2D0846D25663D6DDULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x37F552657E68F365ULL,
		0x52E5C563426C405DULL,
		0xD8E457BADAF18C28ULL,
		0x250CF94CAAF054B1ULL,
		0x734920D8F20523B0ULL,
		0x24ECA46D7275475CULL,
		0x300A5E331BC34B41ULL,
		0x0345B1F70F9CF60DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FEAA4CAFCD1E6CAULL,
		0xA5CB8AC684D880BAULL,
		0xB1C8AF75B5E31850ULL,
		0x4A19F29955E0A963ULL,
		0xE69241B1E40A4760ULL,
		0x49D948DAE4EA8EB8ULL,
		0x6014BC6637869682ULL,
		0x068B63EE1F39EC1AULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x136C2097A69E0894ULL,
		0x825F67AF9971FFDCULL,
		0x094DC9DB9BE4F478ULL,
		0xD198592FA9A40F98ULL,
		0x4CEE086D47F6D6C0ULL,
		0xB25FFAA3A483812DULL,
		0xD23FBFB31038935DULL,
		0x2F7A7FFCFDC4607FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D8412F4D3C1128ULL,
		0x04BECF5F32E3FFB8ULL,
		0x129B93B737C9E8F1ULL,
		0xA330B25F53481F30ULL,
		0x99DC10DA8FEDAD81ULL,
		0x64BFF5474907025AULL,
		0xA47F7F66207126BBULL,
		0x5EF4FFF9FB88C0FFULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9F74BFE7033AD4D1ULL,
		0x918E86177DFBF211ULL,
		0x1BBD3B3EBA6FE47FULL,
		0xA02DB5361B41565DULL,
		0x7C44C58CD925A52EULL,
		0x418316455C578185ULL,
		0x48E58FECA138A544ULL,
		0x26DF369517D53162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EE97FCE0675A9A2ULL,
		0x231D0C2EFBF7E423ULL,
		0x377A767D74DFC8FFULL,
		0x405B6A6C3682ACBAULL,
		0xF8898B19B24B4A5DULL,
		0x83062C8AB8AF030AULL,
		0x91CB1FD942714A88ULL,
		0x4DBE6D2A2FAA62C4ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x02203D8E4856C888ULL,
		0x628EC23ADDCD1C19ULL,
		0xD2C03290A8B03CBFULL,
		0xE7FF213CC4DBAB30ULL,
		0x9AD8489A9CD84209ULL,
		0x57BE102AE9255BB5ULL,
		0x85FAE774DABB5A01ULL,
		0x3DB904B246F4E8C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04407B1C90AD9110ULL,
		0xC51D8475BB9A3832ULL,
		0xA58065215160797EULL,
		0xCFFE427989B75661ULL,
		0x35B0913539B08413ULL,
		0xAF7C2055D24AB76BULL,
		0x0BF5CEE9B576B402ULL,
		0x7B7209648DE9D183ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF32814E9D5EF3179ULL,
		0xA0D087D21DE3E20BULL,
		0x6A5F1CCDA52CDB0DULL,
		0xBFC762143E979C42ULL,
		0x833EEEA4076EAF0DULL,
		0x29D9CA8F4BEA61F3ULL,
		0xE6FB8F08C74C1D37ULL,
		0x1FFF5F2A3F8FAC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE65029D3ABDE62F2ULL,
		0x41A10FA43BC7C417ULL,
		0xD4BE399B4A59B61BULL,
		0x7F8EC4287D2F3884ULL,
		0x067DDD480EDD5E1BULL,
		0x53B3951E97D4C3E7ULL,
		0xCDF71E118E983A6EULL,
		0x3FFEBE547F1F5883ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x14242CC12C7CDBFCULL,
		0x874E6D4E20A0F9B2ULL,
		0x560A83B473AE0A25ULL,
		0xC49ADEA583B1CB47ULL,
		0x49C72CA267011ACBULL,
		0x595ACB7EE95FACADULL,
		0xCFF57EAB93D8BC15ULL,
		0x156D402EF9332FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2848598258F9B7F8ULL,
		0x0E9CDA9C4141F364ULL,
		0xAC150768E75C144BULL,
		0x8935BD4B0763968EULL,
		0x938E5944CE023597ULL,
		0xB2B596FDD2BF595AULL,
		0x9FEAFD5727B1782AULL,
		0x2ADA805DF2665F87ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6808F702BCE2385AULL,
		0x7819DB2DB8463A3CULL,
		0x7D6B3286845FD22DULL,
		0x438738CC811785B5ULL,
		0x483D355277272F52ULL,
		0xD663B508D9D134FBULL,
		0x51FD4607073395C3ULL,
		0x1EE554CA96F07205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD011EE0579C470B4ULL,
		0xF033B65B708C7478ULL,
		0xFAD6650D08BFA45AULL,
		0x870E7199022F0B6AULL,
		0x907A6AA4EE4E5EA4ULL,
		0xACC76A11B3A269F6ULL,
		0xA3FA8C0E0E672B87ULL,
		0x3DCAA9952DE0E40AULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDA5BC492DA73B81FULL,
		0x0F0A6271566AB6D5ULL,
		0x342675CADAD46663ULL,
		0x21468C8C7E8F7973ULL,
		0x8F331500838751FCULL,
		0x17647F83F2D9EE20ULL,
		0xBE56E341D597D43CULL,
		0x29FE5E20293DAF32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B78925B4E7703EULL,
		0x1E14C4E2ACD56DABULL,
		0x684CEB95B5A8CCC6ULL,
		0x428D1918FD1EF2E6ULL,
		0x1E662A01070EA3F8ULL,
		0x2EC8FF07E5B3DC41ULL,
		0x7CADC683AB2FA878ULL,
		0x53FCBC40527B5E65ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x763E1A6B093C9D0FULL,
		0x5624C67657895A8BULL,
		0x54AB20CBF1006726ULL,
		0x7A792A11246612E6ULL,
		0x72AA94362E8DD49CULL,
		0x6CB26ADCB22FE757ULL,
		0xD57DDDE965D86F0BULL,
		0x32AD86D81D353179ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC7C34D612793A1EULL,
		0xAC498CECAF12B516ULL,
		0xA9564197E200CE4CULL,
		0xF4F2542248CC25CCULL,
		0xE555286C5D1BA938ULL,
		0xD964D5B9645FCEAEULL,
		0xAAFBBBD2CBB0DE16ULL,
		0x655B0DB03A6A62F3ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xED69A34150E7658FULL,
		0x49B148B80AFEEC0DULL,
		0x45CF5E2C38F11D02ULL,
		0x40353D3FCC9E06D7ULL,
		0x8CDBCAEF1322D09CULL,
		0x2BAD86C5B158CA13ULL,
		0xF90D01BA398A07F8ULL,
		0x3B6B8C95F333FB8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD34682A1CECB1EULL,
		0x9362917015FDD81BULL,
		0x8B9EBC5871E23A04ULL,
		0x806A7A7F993C0DAEULL,
		0x19B795DE2645A138ULL,
		0x575B0D8B62B19427ULL,
		0xF21A037473140FF0ULL,
		0x76D7192BE667F719ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x025794E11491D3F3ULL,
		0xE4C5DED03EF08D1FULL,
		0x671ED9C777154C62ULL,
		0x449EE28E4F449D92ULL,
		0x88E067DFF8B94C95ULL,
		0x7711B93CF2E50C99ULL,
		0x21E88D818E57430AULL,
		0x33CB6B716094CCCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04AF29C22923A7E6ULL,
		0xC98BBDA07DE11A3EULL,
		0xCE3DB38EEE2A98C5ULL,
		0x893DC51C9E893B24ULL,
		0x11C0CFBFF172992AULL,
		0xEE237279E5CA1933ULL,
		0x43D11B031CAE8614ULL,
		0x6796D6E2C1299998ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x45F5CFCD36FD347AULL,
		0x130D9D06640754D3ULL,
		0x84C0F41CA0268AFCULL,
		0x679235C2C2067CFBULL,
		0x3A91E6F5E71E5044ULL,
		0x9BB74C12FD2B691DULL,
		0x5CF4AE0E173B0054ULL,
		0x3C581D9E6CF46436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BEB9F9A6DFA68F4ULL,
		0x261B3A0CC80EA9A6ULL,
		0x0981E839404D15F8ULL,
		0xCF246B85840CF9F7ULL,
		0x7523CDEBCE3CA088ULL,
		0x376E9825FA56D23AULL,
		0xB9E95C1C2E7600A9ULL,
		0x78B03B3CD9E8C86CULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3043B1166AA5925DULL,
		0x6DB8273C2ED7CA6DULL,
		0x84CE0FC5E8A32818ULL,
		0x170F191EBCE9C291ULL,
		0xD6C0FB8259EAC7FEULL,
		0xC35B2C522167D038ULL,
		0xE078FB111C4B243BULL,
		0x11DE9D1E3AB107FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6087622CD54B24BAULL,
		0xDB704E785DAF94DAULL,
		0x099C1F8BD1465030ULL,
		0x2E1E323D79D38523ULL,
		0xAD81F704B3D58FFCULL,
		0x86B658A442CFA071ULL,
		0xC0F1F62238964877ULL,
		0x23BD3A3C75620FFDULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5D416C66556E5FDEULL,
		0xFF3B94C816DE3B68ULL,
		0x59D56CAADA34E1C3ULL,
		0x1AF10EC8230C1B09ULL,
		0x424787EA52ED1E58ULL,
		0x331693943A1E1079ULL,
		0xA06DD6629FB8777FULL,
		0x0B61BE66EC94D487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA82D8CCAADCBFBCULL,
		0xFE7729902DBC76D0ULL,
		0xB3AAD955B469C387ULL,
		0x35E21D9046183612ULL,
		0x848F0FD4A5DA3CB0ULL,
		0x662D2728743C20F2ULL,
		0x40DBACC53F70EEFEULL,
		0x16C37CCDD929A90FULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0F66500E5BF08F7EULL,
		0x543756802DB048F6ULL,
		0x2C3C0681D8BDD8F7ULL,
		0x65680E84D562989EULL,
		0xD42C01F6BBF41CECULL,
		0x3D9BC6121B6CB5DDULL,
		0x4726B6A618C7E4C4ULL,
		0x3BE2986AB6F79188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ECCA01CB7E11EFCULL,
		0xA86EAD005B6091ECULL,
		0x58780D03B17BB1EEULL,
		0xCAD01D09AAC5313CULL,
		0xA85803ED77E839D8ULL,
		0x7B378C2436D96BBBULL,
		0x8E4D6D4C318FC988ULL,
		0x77C530D56DEF2310ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4E86181C38C30BDCULL,
		0xFDC06E870F4C023CULL,
		0x1163DD8866136201ULL,
		0xDF754F4D81DA485AULL,
		0xC7A0AA45A0DDBB72ULL,
		0xEC089E6BF8C06F2DULL,
		0xA92137B248326515ULL,
		0x3F1F8C7741F4F5FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D0C3038718617B8ULL,
		0xFB80DD0E1E980478ULL,
		0x22C7BB10CC26C403ULL,
		0xBEEA9E9B03B490B4ULL,
		0x8F41548B41BB76E5ULL,
		0xD8113CD7F180DE5BULL,
		0x52426F649064CA2BULL,
		0x7E3F18EE83E9EBF5ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0F41B4166E4A843FULL,
		0xC462CC78A2CABE7FULL,
		0xAF28CD010636EFFFULL,
		0xD508D56E82089ECBULL,
		0x67FA1E2AC7F749F4ULL,
		0x27FCD9F343D25F12ULL,
		0x1050FF889E6D6727ULL,
		0x1AA956F48F2B5372ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E83682CDC95087EULL,
		0x88C598F145957CFEULL,
		0x5E519A020C6DDFFFULL,
		0xAA11AADD04113D97ULL,
		0xCFF43C558FEE93E9ULL,
		0x4FF9B3E687A4BE24ULL,
		0x20A1FF113CDACE4EULL,
		0x3552ADE91E56A6E4ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE40B392115433EF3ULL,
		0x373055B021F442B3ULL,
		0x6BAAD05531071865ULL,
		0xBCB6A428AE69BF17ULL,
		0xF4592D4916A5AC93ULL,
		0x2E2668F29837A4ACULL,
		0x79C9862D52DC0B07ULL,
		0x37C1E5AA37084E54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81672422A867DE6ULL,
		0x6E60AB6043E88567ULL,
		0xD755A0AA620E30CAULL,
		0x796D48515CD37E2EULL,
		0xE8B25A922D4B5927ULL,
		0x5C4CD1E5306F4959ULL,
		0xF3930C5AA5B8160EULL,
		0x6F83CB546E109CA8ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB46BC5ACD143D090ULL,
		0x2A618D0DD65734CFULL,
		0x7EADA2405AC3DBFFULL,
		0xCADA04CFCF697014ULL,
		0x5C721F73678F1038ULL,
		0xBA5534127A0F973CULL,
		0xEB295F86A3F2ED99ULL,
		0x189B115728269717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D78B59A287A120ULL,
		0x54C31A1BACAE699FULL,
		0xFD5B4480B587B7FEULL,
		0x95B4099F9ED2E028ULL,
		0xB8E43EE6CF1E2071ULL,
		0x74AA6824F41F2E78ULL,
		0xD652BF0D47E5DB33ULL,
		0x313622AE504D2E2FULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA086F144222435CDULL,
		0xD5D7D23844BEF068ULL,
		0x5C02E1804CB4AC82ULL,
		0x60A8BFFE92219F01ULL,
		0x08598976EDD47800ULL,
		0x46FEA75A336AE7EBULL,
		0x3C431997FFEA8CB5ULL,
		0x322CAD45AD731B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410DE28844486B9AULL,
		0xABAFA470897DE0D1ULL,
		0xB805C30099695905ULL,
		0xC1517FFD24433E02ULL,
		0x10B312EDDBA8F000ULL,
		0x8DFD4EB466D5CFD6ULL,
		0x7886332FFFD5196AULL,
		0x64595A8B5AE6373EULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC2CCD6397BA672F4ULL,
		0x9F0CA034089DC281ULL,
		0x74EF2442FED6A9CFULL,
		0x8EE79D7D87E2D219ULL,
		0xE1C3E65177BD2BE4ULL,
		0xE29A8E00F8DFF37BULL,
		0x339443746B9E36F4ULL,
		0x05BE50D113CFAB68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8599AC72F74CE5E8ULL,
		0x3E194068113B8503ULL,
		0xE9DE4885FDAD539FULL,
		0x1DCF3AFB0FC5A432ULL,
		0xC387CCA2EF7A57C9ULL,
		0xC5351C01F1BFE6F7ULL,
		0x672886E8D73C6DE9ULL,
		0x0B7CA1A2279F56D0ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8863BD6650D0B217ULL,
		0x1A9B20D589DABCBBULL,
		0x49AA3531A3A694FAULL,
		0xC9982BDE8B4C5FEFULL,
		0xD982B4FD18C2AEAFULL,
		0xA78D00B849E994CBULL,
		0x4766D2013722C9C9ULL,
		0x277A0813D2B4576FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10C77ACCA1A1642EULL,
		0x353641AB13B57977ULL,
		0x93546A63474D29F4ULL,
		0x933057BD1698BFDEULL,
		0xB30569FA31855D5FULL,
		0x4F1A017093D32997ULL,
		0x8ECDA4026E459393ULL,
		0x4EF41027A568AEDEULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA5AF5CB8E6EA5685ULL,
		0x128B68311E9A44E8ULL,
		0x98609336E673603AULL,
		0xB6976B06D743F056ULL,
		0x39922365FD89A503ULL,
		0x789C52EE7B0265B2ULL,
		0xC836B6F1BF40B250ULL,
		0x27D6F2D75BE7FD63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B5EB971CDD4AD0AULL,
		0x2516D0623D3489D1ULL,
		0x30C1266DCCE6C074ULL,
		0x6D2ED60DAE87E0ADULL,
		0x732446CBFB134A07ULL,
		0xF138A5DCF604CB64ULL,
		0x906D6DE37E8164A0ULL,
		0x4FADE5AEB7CFFAC7ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFC42C7B5FD2B06BCULL,
		0xE19960D20106E159ULL,
		0xB64EF36D534F92AEULL,
		0x5DA5B98ECBC0DAFCULL,
		0x94749940E4580B9AULL,
		0x9EF5E109C86E85ACULL,
		0x441E039CA67D6AB5ULL,
		0x3F64F0ADE1B4EB71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8858F6BFA560D78ULL,
		0xC332C1A4020DC2B3ULL,
		0x6C9DE6DAA69F255DULL,
		0xBB4B731D9781B5F9ULL,
		0x28E93281C8B01734ULL,
		0x3DEBC21390DD0B59ULL,
		0x883C07394CFAD56BULL,
		0x7EC9E15BC369D6E2ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4C9362B164B668D5ULL,
		0xF55325A3F7E03AF7ULL,
		0x580A28A20D898851ULL,
		0xA2752F7336FEF897ULL,
		0xB794D4E868CAE2D5ULL,
		0x3CDDA45EB6CB1E08ULL,
		0x939B3D0426331FEBULL,
		0x1F64BCAE8DA71C67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9926C562C96CD1AAULL,
		0xEAA64B47EFC075EEULL,
		0xB01451441B1310A3ULL,
		0x44EA5EE66DFDF12EULL,
		0x6F29A9D0D195C5ABULL,
		0x79BB48BD6D963C11ULL,
		0x27367A084C663FD6ULL,
		0x3EC9795D1B4E38CFULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAB5828995E9BEF13ULL,
		0x0C1CE5F0E6BB5398ULL,
		0xE9A5BB05ECFA4995ULL,
		0xC9837648FB9A5779ULL,
		0xF6C8DE1346E1C4ACULL,
		0x4CD3537687550C15ULL,
		0x4B3FDE475A5A75EBULL,
		0x3DEA6A3584F6B67EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B05132BD37DE26ULL,
		0x1839CBE1CD76A731ULL,
		0xD34B760BD9F4932AULL,
		0x9306EC91F734AEF3ULL,
		0xED91BC268DC38959ULL,
		0x99A6A6ED0EAA182BULL,
		0x967FBC8EB4B4EBD6ULL,
		0x7BD4D46B09ED6CFCULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7098F45040C64F4BULL,
		0x341A8FB01862556DULL,
		0x356EFE8660E2BA0AULL,
		0x6209E34AAD357F22ULL,
		0x72A194DCE083719BULL,
		0x78E3E6D9472337F1ULL,
		0x46A727D336425895ULL,
		0x3A7F9B8BAADC7F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE131E8A0818C9E96ULL,
		0x68351F6030C4AADAULL,
		0x6ADDFD0CC1C57414ULL,
		0xC413C6955A6AFE44ULL,
		0xE54329B9C106E336ULL,
		0xF1C7CDB28E466FE2ULL,
		0x8D4E4FA66C84B12AULL,
		0x74FF371755B8FF02ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5E0F413DA30A6F70ULL,
		0x5E40BAFAA05C017BULL,
		0x004706EDC837F2A4ULL,
		0x20B1B8C512CD238CULL,
		0x7F15E33741374115ULL,
		0xECBDB42E70F961B9ULL,
		0xE3367E2431014156ULL,
		0x28C7CA994F700AC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC1E827B4614DEE0ULL,
		0xBC8175F540B802F6ULL,
		0x008E0DDB906FE548ULL,
		0x4163718A259A4718ULL,
		0xFE2BC66E826E822AULL,
		0xD97B685CE1F2C372ULL,
		0xC66CFC48620282ADULL,
		0x518F95329EE0158DULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2A60CF887D7C37DAULL,
		0xA9FCEB63F83A6D8CULL,
		0x37460C469CF53E0EULL,
		0xEA2BD6D547867138ULL,
		0x3D1BFD35DCA10036ULL,
		0x05EBFC2D044098F5ULL,
		0x2E2282325B1F450BULL,
		0x34901C064C55F11BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C19F10FAF86FB4ULL,
		0x53F9D6C7F074DB18ULL,
		0x6E8C188D39EA7C1DULL,
		0xD457ADAA8F0CE270ULL,
		0x7A37FA6BB942006DULL,
		0x0BD7F85A088131EAULL,
		0x5C450464B63E8A16ULL,
		0x6920380C98ABE236ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2482A50BF3D4D104ULL,
		0xA92CB76701A9CCA9ULL,
		0x8FA442D055E5A8A1ULL,
		0xFE66D5A51B3E54D5ULL,
		0xF9327654465848CAULL,
		0xAB8A798D7E19EF70ULL,
		0x22A221D51DB3052AULL,
		0x002138C138594411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49054A17E7A9A208ULL,
		0x52596ECE03539952ULL,
		0x1F4885A0ABCB5143ULL,
		0xFCCDAB4A367CA9ABULL,
		0xF264ECA88CB09195ULL,
		0x5714F31AFC33DEE1ULL,
		0x454443AA3B660A55ULL,
		0x0042718270B28822ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x54C0EEED8823BEAEULL,
		0xC1EA23989DD31986ULL,
		0xA5463785C3806302ULL,
		0x5305F848FDA5B196ULL,
		0x5DC5D7FA8D45153BULL,
		0x94080CC94A0BDCDBULL,
		0x20E34FAC05269F3AULL,
		0x31ED4F5DB028E9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA981DDDB10477D5CULL,
		0x83D447313BA6330CULL,
		0x4A8C6F0B8700C605ULL,
		0xA60BF091FB4B632DULL,
		0xBB8BAFF51A8A2A76ULL,
		0x281019929417B9B6ULL,
		0x41C69F580A4D3E75ULL,
		0x63DA9EBB6051D3AEULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA6ADC69D86B66903ULL,
		0x426C2F09367B9421ULL,
		0x1D1FDC28E2786059ULL,
		0xF397928E833A181CULL,
		0xCFD768FF259A355EULL,
		0xF99F41F354DF089BULL,
		0xB17F5608FE21ACEBULL,
		0x2D94773BEA9762DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5B8D3B0D6CD206ULL,
		0x84D85E126CF72843ULL,
		0x3A3FB851C4F0C0B2ULL,
		0xE72F251D06743038ULL,
		0x9FAED1FE4B346ABDULL,
		0xF33E83E6A9BE1137ULL,
		0x62FEAC11FC4359D7ULL,
		0x5B28EE77D52EC5B9ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2E90CCF48BD2DDD6ULL,
		0x2CEA47F213A3F16DULL,
		0x1B8D9AA99DEABAEFULL,
		0x34BB64D172B1EBD2ULL,
		0xBF79717380931B90ULL,
		0x5258C2F83DBEDF78ULL,
		0x70EC3B508ABB4AB5ULL,
		0x3AE64247800A95E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2199E917A5BBACULL,
		0x59D48FE42747E2DAULL,
		0x371B35533BD575DEULL,
		0x6976C9A2E563D7A4ULL,
		0x7EF2E2E701263720ULL,
		0xA4B185F07B7DBEF1ULL,
		0xE1D876A11576956AULL,
		0x75CC848F00152BCEULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6455EBE0AE6A1D8FULL,
		0x9C2D270F1CACAC7DULL,
		0x3CFFC2B89A38652FULL,
		0xD00A7CFD33A81EA5ULL,
		0x66218159ADF996DBULL,
		0xAAE7CE7C7BA072D3ULL,
		0x51039A2C1CD71E99ULL,
		0x0E3C8A55314B6DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8ABD7C15CD43B1EULL,
		0x385A4E1E395958FAULL,
		0x79FF85713470CA5FULL,
		0xA014F9FA67503D4AULL,
		0xCC4302B35BF32DB7ULL,
		0x55CF9CF8F740E5A6ULL,
		0xA207345839AE3D33ULL,
		0x1C7914AA6296DBA4ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4526C732DEA6E67CULL,
		0xBBD152D29D2D6031ULL,
		0x694869D244F76FDFULL,
		0x53A55E49A3181FA3ULL,
		0x938566231BFC0EC1ULL,
		0xCB83D995E4E24607ULL,
		0xB95AAD7E8D44D356ULL,
		0x255DD342CB917496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A4D8E65BD4DCCF8ULL,
		0x77A2A5A53A5AC062ULL,
		0xD290D3A489EEDFBFULL,
		0xA74ABC9346303F46ULL,
		0x270ACC4637F81D82ULL,
		0x9707B32BC9C48C0FULL,
		0x72B55AFD1A89A6ADULL,
		0x4ABBA6859722E92DULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD43151DF37386CE9ULL,
		0x48237104ABBE498CULL,
		0x7D922EB11F331B57ULL,
		0xD189598E1C33069CULL,
		0x5893D89A0E94F0BEULL,
		0x9030F101D2E51C3FULL,
		0x6C83CBDA4143473DULL,
		0x1C8036ED245405F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA862A3BE6E70D9D2ULL,
		0x9046E209577C9319ULL,
		0xFB245D623E6636AEULL,
		0xA312B31C38660D38ULL,
		0xB127B1341D29E17DULL,
		0x2061E203A5CA387EULL,
		0xD90797B482868E7BULL,
		0x39006DDA48A80BE8ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8310263FB66DDA4EULL,
		0x362B43582A802087ULL,
		0x3DA50805691BC016ULL,
		0x7FD561623375EA4DULL,
		0x076D084BFE9ACA81ULL,
		0xB7BAD8D99ABD03C7ULL,
		0x3F7D69CA52CF5071ULL,
		0x1D6F44052AC5A60EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06204C7F6CDBB49CULL,
		0x6C5686B05500410FULL,
		0x7B4A100AD237802CULL,
		0xFFAAC2C466EBD49AULL,
		0x0EDA1097FD359502ULL,
		0x6F75B1B3357A078EULL,
		0x7EFAD394A59EA0E3ULL,
		0x3ADE880A558B4C1CULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x593063263DFB6234ULL,
		0x9863A9C028C7E330ULL,
		0x4642DF70FBE75613ULL,
		0xF9BC0CD5960CA891ULL,
		0x769149D5712ED75CULL,
		0xAC6A6497B58DD99BULL,
		0x7460B23216CA978FULL,
		0x2F45B1EC10B7EE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB260C64C7BF6C468ULL,
		0x30C75380518FC660ULL,
		0x8C85BEE1F7CEAC27ULL,
		0xF37819AB2C195122ULL,
		0xED2293AAE25DAEB9ULL,
		0x58D4C92F6B1BB336ULL,
		0xE8C164642D952F1FULL,
		0x5E8B63D8216FDCF2ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB82324A1C286A9E9ULL,
		0xC3B9CFC284471BCCULL,
		0xBC065C9F6BFDBCC9ULL,
		0x6A211416F914EB39ULL,
		0xC5E6B2EA01C1240AULL,
		0x2299489B9AA1333EULL,
		0xB38C52417B1F97D6ULL,
		0x33D613834E68682AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70464943850D53D2ULL,
		0x87739F85088E3799ULL,
		0x780CB93ED7FB7993ULL,
		0xD442282DF229D673ULL,
		0x8BCD65D403824814ULL,
		0x453291373542667DULL,
		0x6718A482F63F2FACULL,
		0x67AC27069CD0D055ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF5F01B9147D01693ULL,
		0x8063F5AEECA44A99ULL,
		0xC75F90EE44CDB634ULL,
		0xB7E6BC8A3C6C6562ULL,
		0x38929A1BCC432CF9ULL,
		0xFEB60021EF927CE7ULL,
		0x5C4CEDEFC0D60385ULL,
		0x2617BB1EF203EF46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE037228FA02D26ULL,
		0x00C7EB5DD9489533ULL,
		0x8EBF21DC899B6C69ULL,
		0x6FCD791478D8CAC5ULL,
		0x71253437988659F3ULL,
		0xFD6C0043DF24F9CEULL,
		0xB899DBDF81AC070BULL,
		0x4C2F763DE407DE8CULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x01D3CEBE2E171162ULL,
		0x24BBEA1DAA8D854AULL,
		0xFD9422A8B9AB9691ULL,
		0x67BCB503AEDCEFE5ULL,
		0xB3C78DD82DD6A083ULL,
		0xFC7C9C84C40CF998ULL,
		0x1E9A4F98028ED500ULL,
		0x26AB7A4ACDD8F65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A79D7C5C2E22C4ULL,
		0x4977D43B551B0A94ULL,
		0xFB28455173572D22ULL,
		0xCF796A075DB9DFCBULL,
		0x678F1BB05BAD4106ULL,
		0xF8F939098819F331ULL,
		0x3D349F30051DAA01ULL,
		0x4D56F4959BB1ECB6ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8E5D2C9F9A73507BULL,
		0xDC297983E29C20CDULL,
		0x045254379B606F87ULL,
		0xB74388436B61146CULL,
		0x797AD629EB7A542CULL,
		0x495690417876D1EFULL,
		0x48E1257D33606B80ULL,
		0x002D494D429614A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CBA593F34E6A0F6ULL,
		0xB852F307C538419BULL,
		0x08A4A86F36C0DF0FULL,
		0x6E871086D6C228D8ULL,
		0xF2F5AC53D6F4A859ULL,
		0x92AD2082F0EDA3DEULL,
		0x91C24AFA66C0D700ULL,
		0x005A929A852C2952ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x50D4C01AF7FAF15DULL,
		0xF940195C6F59A530ULL,
		0x8FBCBCEEEB9721ACULL,
		0xBDD4691996E97807ULL,
		0x2DA67307B239130FULL,
		0x07985C26FE5D806AULL,
		0x040DB958C281741FULL,
		0x372FCCCAB0586F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A98035EFF5E2BAULL,
		0xF28032B8DEB34A60ULL,
		0x1F7979DDD72E4359ULL,
		0x7BA8D2332DD2F00FULL,
		0x5B4CE60F6472261FULL,
		0x0F30B84DFCBB00D4ULL,
		0x081B72B18502E83EULL,
		0x6E5F999560B0DEE2ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x224064E79AEC93D0ULL,
		0x3433885E5BE4A949ULL,
		0xA72B753A33F6E232ULL,
		0xEC12317ECC745183ULL,
		0x134B0F0C13D93A3AULL,
		0x1B5AA5B10F01C089ULL,
		0xA699B548C6928F67ULL,
		0x3A92A74B0BBE60E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4480C9CF35D927A0ULL,
		0x686710BCB7C95292ULL,
		0x4E56EA7467EDC464ULL,
		0xD82462FD98E8A307ULL,
		0x26961E1827B27475ULL,
		0x36B54B621E038112ULL,
		0x4D336A918D251ECEULL,
		0x75254E96177CC1C5ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFFD2BCF7198A4BFBULL,
		0x579266EC1294C48DULL,
		0xC8CE649D7F28A28CULL,
		0xAFC74C1F32E2FD12ULL,
		0x81D659778543B42DULL,
		0x0BEB60211D12CD59ULL,
		0x017B0700906817BAULL,
		0x26400F9287F7D79CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA579EE331497F6ULL,
		0xAF24CDD82529891BULL,
		0x919CC93AFE514518ULL,
		0x5F8E983E65C5FA25ULL,
		0x03ACB2EF0A87685BULL,
		0x17D6C0423A259AB3ULL,
		0x02F60E0120D02F74ULL,
		0x4C801F250FEFAF38ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3C92E9AF1542A10DULL,
		0xD2FA1C44B04E7F95ULL,
		0xBDFBCD708630F81DULL,
		0x8107E50BAC34A9C9ULL,
		0xD0245915A383C028ULL,
		0xDF6D356DDA327CAFULL,
		0xD20C9BFA51A22F17ULL,
		0x15B49055297EA22DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7925D35E2A85421AULL,
		0xA5F43889609CFF2AULL,
		0x7BF79AE10C61F03BULL,
		0x020FCA1758695393ULL,
		0xA048B22B47078051ULL,
		0xBEDA6ADBB464F95FULL,
		0xA41937F4A3445E2FULL,
		0x2B6920AA52FD445BULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x325B7488AE747C81ULL,
		0xBFDDCD3EDB20BBAAULL,
		0x53DFB3534CE62D81ULL,
		0xDA33A39E085BCCB9ULL,
		0x19983DD3F532DE29ULL,
		0xA6634389BE576FC7ULL,
		0xF18A96C2404AC89CULL,
		0x36242535962ED312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64B6E9115CE8F902ULL,
		0x7FBB9A7DB6417754ULL,
		0xA7BF66A699CC5B03ULL,
		0xB467473C10B79972ULL,
		0x33307BA7EA65BC53ULL,
		0x4CC687137CAEDF8EULL,
		0xE3152D8480959139ULL,
		0x6C484A6B2C5DA625ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x97CC4FE28CDDABE7ULL,
		0xD52EA224AAD62D73ULL,
		0x2570F23538A83E6FULL,
		0x7C11DEFAD2E77A73ULL,
		0xC730B36DD1359884ULL,
		0xDA188D5DFE68E6D4ULL,
		0x3A37F4AC284F9E50ULL,
		0x02D273893A0F8FA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F989FC519BB57CEULL,
		0xAA5D444955AC5AE7ULL,
		0x4AE1E46A71507CDFULL,
		0xF823BDF5A5CEF4E6ULL,
		0x8E6166DBA26B3108ULL,
		0xB4311ABBFCD1CDA9ULL,
		0x746FE958509F3CA1ULL,
		0x05A4E712741F1F40ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1065EB098B56913DULL,
		0xCF04F342D50D8A42ULL,
		0x3441F9DB3091DD79ULL,
		0x15D304BC8D1A5030ULL,
		0xFD954A62DFBBE4C2ULL,
		0xF3C75482798F4E1DULL,
		0x21C3C4EFA4BA7D19ULL,
		0x32D44F1E600C6F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20CBD61316AD227AULL,
		0x9E09E685AA1B1484ULL,
		0x6883F3B66123BAF3ULL,
		0x2BA609791A34A060ULL,
		0xFB2A94C5BF77C984ULL,
		0xE78EA904F31E9C3BULL,
		0x438789DF4974FA33ULL,
		0x65A89E3CC018DE40ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xEC3EE1A55943970BULL,
		0x29C38A44EE9A2D0AULL,
		0x6AF9DB75B00628D2ULL,
		0x6A1BB380C4F463A5ULL,
		0x06DE457EFD0CA0ECULL,
		0x2DD598A8418A46BBULL,
		0x2AB7501F1DBC02A5ULL,
		0x1F87A15272DD277DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD87DC34AB2872E16ULL,
		0x53871489DD345A15ULL,
		0xD5F3B6EB600C51A4ULL,
		0xD437670189E8C74AULL,
		0x0DBC8AFDFA1941D8ULL,
		0x5BAB315083148D76ULL,
		0x556EA03E3B78054AULL,
		0x3F0F42A4E5BA4EFAULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x38B9D0A662E0DE53ULL,
		0xF7FB8611F91AB19BULL,
		0x68C2DFE35AD6E691ULL,
		0xCEF948A6F0B6B825ULL,
		0x6DBAB65CB3C3EBF4ULL,
		0xFE6CF9B849661138ULL,
		0xFD129020ADF6C7FDULL,
		0x1FE0A896C858EAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7173A14CC5C1BCA6ULL,
		0xEFF70C23F2356336ULL,
		0xD185BFC6B5ADCD23ULL,
		0x9DF2914DE16D704AULL,
		0xDB756CB96787D7E9ULL,
		0xFCD9F37092CC2270ULL,
		0xFA2520415BED8FFBULL,
		0x3FC1512D90B1D561ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0322389BD8BFCF39ULL,
		0x8B26CA9B3AB0DC35ULL,
		0xCAE965AE233F8217ULL,
		0xE39B59CE36D4CC0AULL,
		0xB082A00B2C5CAE6EULL,
		0xC29302672735417CULL,
		0xFD04CED9A5CC7D45ULL,
		0x1AB1AB23F37E2880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06447137B17F9E72ULL,
		0x164D95367561B86AULL,
		0x95D2CB5C467F042FULL,
		0xC736B39C6DA99815ULL,
		0x6105401658B95CDDULL,
		0x852604CE4E6A82F9ULL,
		0xFA099DB34B98FA8BULL,
		0x35635647E6FC5101ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1C3FE7F4B59F7256ULL,
		0x51E5B716D3FF9D42ULL,
		0xD326A23801BEA269ULL,
		0x8EE9183D93C642E7ULL,
		0xB9ECC9F867D9DD15ULL,
		0xC8213A7A9B1C13B1ULL,
		0x46A91B6DEA61AF3EULL,
		0x12C898B44809C28BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387FCFE96B3EE4ACULL,
		0xA3CB6E2DA7FF3A84ULL,
		0xA64D4470037D44D2ULL,
		0x1DD2307B278C85CFULL,
		0x73D993F0CFB3BA2BULL,
		0x904274F536382763ULL,
		0x8D5236DBD4C35E7DULL,
		0x2591316890138516ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8543CAE4B755FA15ULL,
		0xAE88EFA985F2BC22ULL,
		0xDD51B4CE909D658DULL,
		0x802BBA459DAA8CB3ULL,
		0xF22C9BB8BD6C895CULL,
		0x6B2A3C506C03E680ULL,
		0x54C17420C36F5BDAULL,
		0x0DC3B1612F36DCADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A8795C96EABF42AULL,
		0x5D11DF530BE57845ULL,
		0xBAA3699D213ACB1BULL,
		0x0057748B3B551967ULL,
		0xE45937717AD912B9ULL,
		0xD65478A0D807CD01ULL,
		0xA982E84186DEB7B4ULL,
		0x1B8762C25E6DB95AULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x635B476E703F7B24ULL,
		0x4C3A2022E254528AULL,
		0xE2F3AA430A7B81F5ULL,
		0x14FC052629B0A45EULL,
		0x33B9857214D0C926ULL,
		0x8ADC03C40E1F50D6ULL,
		0x6730371D5D29441EULL,
		0x14CA31FFCCA98710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6B68EDCE07EF648ULL,
		0x98744045C4A8A514ULL,
		0xC5E7548614F703EAULL,
		0x29F80A4C536148BDULL,
		0x67730AE429A1924CULL,
		0x15B807881C3EA1ACULL,
		0xCE606E3ABA52883DULL,
		0x299463FF99530E20ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2BAB40A8BF6BCD87ULL,
		0xF301F4D79D26CE7AULL,
		0xA7AA5EE49E994B0BULL,
		0x498E12316F9C2C78ULL,
		0x8BFCA7711F1A240FULL,
		0xB661CE345A1B0F5AULL,
		0xCCD8BDD173C21900ULL,
		0x2408E59084185FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x575681517ED79B0EULL,
		0xE603E9AF3A4D9CF4ULL,
		0x4F54BDC93D329617ULL,
		0x931C2462DF3858F1ULL,
		0x17F94EE23E34481EULL,
		0x6CC39C68B4361EB5ULL,
		0x99B17BA2E7843201ULL,
		0x4811CB210830BF5DULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7598D8C444AB5BF7ULL,
		0x2AF8450FBFA5EE86ULL,
		0x43F3B0551D416EA9ULL,
		0xF7346BD083A02326ULL,
		0x097A96F32EC5295FULL,
		0x45FE986F609CC67FULL,
		0x7B2B303575A249A0ULL,
		0x2EAA2A1DF43C1D72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB31B1888956B7EEULL,
		0x55F08A1F7F4BDD0CULL,
		0x87E760AA3A82DD52ULL,
		0xEE68D7A10740464CULL,
		0x12F52DE65D8A52BFULL,
		0x8BFD30DEC1398CFEULL,
		0xF656606AEB449340ULL,
		0x5D54543BE8783AE4ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1B2844C9BF609B11ULL,
		0x61F9EF3B951D7280ULL,
		0x47317E1BD4CB0A39ULL,
		0xC740DA7BC4C2931EULL,
		0xFC2B01C22D5EBF19ULL,
		0x2C812E1EF753BB2DULL,
		0x44620C17D5C6DD09ULL,
		0x32C705BB68903369ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x365089937EC13622ULL,
		0xC3F3DE772A3AE500ULL,
		0x8E62FC37A9961472ULL,
		0x8E81B4F78985263CULL,
		0xF85603845ABD7E33ULL,
		0x59025C3DEEA7765BULL,
		0x88C4182FAB8DBA12ULL,
		0x658E0B76D12066D2ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA0979E02CA79BB82ULL,
		0xFC0CB1C420082D5AULL,
		0x1B118E2125CC0479ULL,
		0xE4C7D88DED44BBFAULL,
		0xFE6602A2B1C0E76EULL,
		0x4B4FAFC935A6FDFCULL,
		0x37D49A00E7891F2AULL,
		0x3D8D0758F0D9A4F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x412F3C0594F37704ULL,
		0xF819638840105AB5ULL,
		0x36231C424B9808F3ULL,
		0xC98FB11BDA8977F4ULL,
		0xFCCC05456381CEDDULL,
		0x969F5F926B4DFBF9ULL,
		0x6FA93401CF123E54ULL,
		0x7B1A0EB1E1B349F2ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB86FC4E07E5D4B0CULL,
		0x4E52353D29C30C40ULL,
		0x79B0B91349E4C147ULL,
		0x4B21A5D56D8D08B2ULL,
		0x3FE03A9A762FED9CULL,
		0x1E92DDA5500476D1ULL,
		0x3A1BD7A8154FDE8EULL,
		0x38EE9E1075F2753EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70DF89C0FCBA9618ULL,
		0x9CA46A7A53861881ULL,
		0xF361722693C9828EULL,
		0x96434BAADB1A1164ULL,
		0x7FC07534EC5FDB38ULL,
		0x3D25BB4AA008EDA2ULL,
		0x7437AF502A9FBD1CULL,
		0x71DD3C20EBE4EA7CULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE510CF1068DA2770ULL,
		0x7759300323D426A7ULL,
		0x3399F21A89C5E84BULL,
		0x4A487DA5EB2FB8DEULL,
		0x543CC1F16893F98EULL,
		0xC49C454B68AB6F55ULL,
		0x8CFAF74404A72F70ULL,
		0x28D9DFD06045E952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA219E20D1B44EE0ULL,
		0xEEB2600647A84D4FULL,
		0x6733E435138BD096ULL,
		0x9490FB4BD65F71BCULL,
		0xA87983E2D127F31CULL,
		0x89388A96D156DEAAULL,
		0x19F5EE88094E5EE1ULL,
		0x51B3BFA0C08BD2A5ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x26BA8F1080A164A1ULL,
		0xB490B5EEA2B4ED9FULL,
		0xF5BEB9EA5802BA4FULL,
		0x495ED7624D9D2F99ULL,
		0x2227F233102389A1ULL,
		0x1310538471F23EEFULL,
		0x12CA99F8852109DEULL,
		0x19CB5B3CF1A884BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D751E210142C942ULL,
		0x69216BDD4569DB3EULL,
		0xEB7D73D4B005749FULL,
		0x92BDAEC49B3A5F33ULL,
		0x444FE46620471342ULL,
		0x2620A708E3E47DDEULL,
		0x259533F10A4213BCULL,
		0x3396B679E3510978ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC43884A1598D9950ULL,
		0xF84C7385FEA27205ULL,
		0xFCDEF530AC1A43A0ULL,
		0x8F8CCAF80D02D839ULL,
		0xFA778EB995DB6F9AULL,
		0xD24ADBE2CFACFC79ULL,
		0xF96042A809767AD7ULL,
		0x32B4BDCDACC0C92AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88710942B31B32A0ULL,
		0xF098E70BFD44E40BULL,
		0xF9BDEA6158348741ULL,
		0x1F1995F01A05B073ULL,
		0xF4EF1D732BB6DF35ULL,
		0xA495B7C59F59F8F3ULL,
		0xF2C0855012ECF5AFULL,
		0x65697B9B59819255ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAEA53ECD2F373AD8ULL,
		0x78F1363EBA17B192ULL,
		0xA1C2D9019B89CB18ULL,
		0x93B8458E92805EE3ULL,
		0xF6659A5C4E10CF89ULL,
		0x5C53EF01FFD8EE4DULL,
		0x5205491670E1AC80ULL,
		0x107E4C794B1C77FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4A7D9A5E6E75B0ULL,
		0xF1E26C7D742F6325ULL,
		0x4385B20337139630ULL,
		0x27708B1D2500BDC7ULL,
		0xECCB34B89C219F13ULL,
		0xB8A7DE03FFB1DC9BULL,
		0xA40A922CE1C35900ULL,
		0x20FC98F29638EFFAULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x64C04F2860427245ULL,
		0x31FA2E493B45FAA5ULL,
		0x92BF0F34A6426EAEULL,
		0x6704932684AA30D1ULL,
		0x69B9ADCF11292D40ULL,
		0x3D6B84A09ADF3847ULL,
		0x30ED343BCBA7599FULL,
		0x2890EDCB64955898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9809E50C084E48AULL,
		0x63F45C92768BF54AULL,
		0x257E1E694C84DD5CULL,
		0xCE09264D095461A3ULL,
		0xD3735B9E22525A80ULL,
		0x7AD7094135BE708EULL,
		0x61DA6877974EB33EULL,
		0x5121DB96C92AB130ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAAECA6E7A8BE39B9ULL,
		0xCEBD4269CDCD3759ULL,
		0x8EFCB798D59FF4D3ULL,
		0x0D17B4C95A28733CULL,
		0x264EA23904015A67ULL,
		0x15FCEBC40A708784ULL,
		0x2D91F18751151FD3ULL,
		0x2A0CB90A0767D87BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D94DCF517C7372ULL,
		0x9D7A84D39B9A6EB3ULL,
		0x1DF96F31AB3FE9A7ULL,
		0x1A2F6992B450E679ULL,
		0x4C9D44720802B4CEULL,
		0x2BF9D78814E10F08ULL,
		0x5B23E30EA22A3FA6ULL,
		0x541972140ECFB0F6ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x565B4C7F6871B812ULL,
		0x531CA3E2738CA4E9ULL,
		0x20CC5FD194A17BADULL,
		0x99B178C654B57676ULL,
		0xD2C1ADA5EEEA6FB2ULL,
		0xB299DE075E8D8BE4ULL,
		0x08EA7F4142CFCC04ULL,
		0x06BF2186CC4EB2F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACB698FED0E37024ULL,
		0xA63947C4E71949D2ULL,
		0x4198BFA32942F75AULL,
		0x3362F18CA96AECECULL,
		0xA5835B4BDDD4DF65ULL,
		0x6533BC0EBD1B17C9ULL,
		0x11D4FE82859F9809ULL,
		0x0D7E430D989D65E0ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2E6B471B8F3ADAC8ULL,
		0x75E6FFA9417E9081ULL,
		0xE0858153C79A4A10ULL,
		0xD780AA45CB723538ULL,
		0x3681B3CBE9A7A943ULL,
		0x82DD8B1FDBAEF286ULL,
		0x3CC7D77F91EBAB14ULL,
		0x22A4D8C7136A2085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD68E371E75B590ULL,
		0xEBCDFF5282FD2102ULL,
		0xC10B02A78F349420ULL,
		0xAF01548B96E46A71ULL,
		0x6D036797D34F5287ULL,
		0x05BB163FB75DE50CULL,
		0x798FAEFF23D75629ULL,
		0x4549B18E26D4410AULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5E2FE3034C720CD9ULL,
		0x014C18DDFE242510ULL,
		0xF91779D72612DFA9ULL,
		0x0748FB17BABE659DULL,
		0xE86E849BF26B5B20ULL,
		0x12C858034467943EULL,
		0x2BEF0820C27FD0FDULL,
		0x233AE5EF71EF051BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5FC60698E419B2ULL,
		0x029831BBFC484A20ULL,
		0xF22EF3AE4C25BF52ULL,
		0x0E91F62F757CCB3BULL,
		0xD0DD0937E4D6B640ULL,
		0x2590B00688CF287DULL,
		0x57DE104184FFA1FAULL,
		0x4675CBDEE3DE0A36ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7F21DD42FD4F392CULL,
		0xC85454709925840DULL,
		0x4024F6CC0F28A6ABULL,
		0xB2E416E82906E11BULL,
		0x9637C17E278F4B21ULL,
		0x537F44EFCF77A2E3ULL,
		0x6B1A34B42D20480CULL,
		0x2DDE897EC2C571D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE43BA85FA9E7258ULL,
		0x90A8A8E1324B081AULL,
		0x8049ED981E514D57ULL,
		0x65C82DD0520DC236ULL,
		0x2C6F82FC4F1E9643ULL,
		0xA6FE89DF9EEF45C7ULL,
		0xD63469685A409018ULL,
		0x5BBD12FD858AE3A0ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7FEAE04D9B6EC76EULL,
		0x28EC7D4525FC1536ULL,
		0xEDC6D2F700FC51EAULL,
		0xB99D80CB94C98576ULL,
		0xF0EB0D6B03C24D5CULL,
		0x073A4718655C9580ULL,
		0x0E594DB2E995F36AULL,
		0x376C552DFDB23201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD5C09B36DD8EDCULL,
		0x51D8FA8A4BF82A6CULL,
		0xDB8DA5EE01F8A3D4ULL,
		0x733B019729930AEDULL,
		0xE1D61AD607849AB9ULL,
		0x0E748E30CAB92B01ULL,
		0x1CB29B65D32BE6D4ULL,
		0x6ED8AA5BFB646402ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD37CAF20525F0DC0ULL,
		0x561AAAC54CE056CAULL,
		0x5F30E634A11B61A9ULL,
		0xEB3DF51EA3CCE3C0ULL,
		0x776F2777CEBEFA6EULL,
		0x74C539B2DB827AB5ULL,
		0x01DF853C300559BCULL,
		0x361BB80AA869CA98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F95E40A4BE1B80ULL,
		0xAC35558A99C0AD95ULL,
		0xBE61CC694236C352ULL,
		0xD67BEA3D4799C780ULL,
		0xEEDE4EEF9D7DF4DDULL,
		0xE98A7365B704F56AULL,
		0x03BF0A78600AB378ULL,
		0x6C37701550D39530ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7C36E3225BCA3A8EULL,
		0x275DE95B0203A5AAULL,
		0x8E1AEB7048330328ULL,
		0x18339C9464697B2BULL,
		0x8CDAB9400B988762ULL,
		0x2087F3A01AB2D17BULL,
		0x97AB05BFA6D31FF0ULL,
		0x1951C08C24E6DF56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF86DC644B794751CULL,
		0x4EBBD2B604074B54ULL,
		0x1C35D6E090660650ULL,
		0x30673928C8D2F657ULL,
		0x19B5728017310EC4ULL,
		0x410FE7403565A2F7ULL,
		0x2F560B7F4DA63FE0ULL,
		0x32A3811849CDBEADULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x441376F6B534380CULL,
		0xF2533AB726879EDCULL,
		0x60C1A9BBF0EB8F01ULL,
		0x1755DF74A5AA8293ULL,
		0x0FA4972E4785F236ULL,
		0xFFEC962F9B4F1934ULL,
		0x2998D70F2C72E2A3ULL,
		0x22015D71AC39A52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8826EDED6A687018ULL,
		0xE4A6756E4D0F3DB8ULL,
		0xC1835377E1D71E03ULL,
		0x2EABBEE94B550526ULL,
		0x1F492E5C8F0BE46CULL,
		0xFFD92C5F369E3268ULL,
		0x5331AE1E58E5C547ULL,
		0x4402BAE358734A58ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAB72DEA6D27F4B18ULL,
		0x4D3A71CCBE329FA4ULL,
		0x65E606AAAB749123ULL,
		0xCC7C31213BB6ECCEULL,
		0x70B9FEB19F1F13E4ULL,
		0xA1BB1932CBEE8343ULL,
		0xF4A356671726D083ULL,
		0x0486D44F49E9480DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E5BD4DA4FE9630ULL,
		0x9A74E3997C653F49ULL,
		0xCBCC0D5556E92246ULL,
		0x98F86242776DD99CULL,
		0xE173FD633E3E27C9ULL,
		0x4376326597DD0686ULL,
		0xE946ACCE2E4DA107ULL,
		0x090DA89E93D2901BULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3E56C205941EEEC0ULL,
		0xD5055DA9759CD916ULL,
		0xE40A2B7856694992ULL,
		0xA339429B170D2782ULL,
		0x24CBFF78ACA19A2CULL,
		0xE2A427E190F92319ULL,
		0xA9DFD37BF49451D5ULL,
		0x3F43BC7CC6D89C0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CAD840B283DDD80ULL,
		0xAA0ABB52EB39B22CULL,
		0xC81456F0ACD29325ULL,
		0x467285362E1A4F05ULL,
		0x4997FEF159433459ULL,
		0xC5484FC321F24632ULL,
		0x53BFA6F7E928A3ABULL,
		0x7E8778F98DB13815ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB7FED4A0CB0ACDBDULL,
		0xCD03E5CFFF1D2C5AULL,
		0x2F5D913A860C1E15ULL,
		0xE06250F56679B49CULL,
		0x6D5FD31B630D91F5ULL,
		0x0F032D726F02945DULL,
		0x2FD7F1043E2DA0BAULL,
		0x3F40238936895E20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FFDA94196159B7AULL,
		0x9A07CB9FFE3A58B5ULL,
		0x5EBB22750C183C2BULL,
		0xC0C4A1EACCF36938ULL,
		0xDABFA636C61B23EBULL,
		0x1E065AE4DE0528BAULL,
		0x5FAFE2087C5B4174ULL,
		0x7E8047126D12BC40ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xEB4450E5CD4417FCULL,
		0x7F3B2509ABA28CB5ULL,
		0xBCA0878166DC85D5ULL,
		0xF4BA8B20DF96BD28ULL,
		0x953A650FDE6216A9ULL,
		0x1721790D6F6E22ACULL,
		0xDB5563FFA1C99866ULL,
		0x3A543C27F34E5B63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD688A1CB9A882FF8ULL,
		0xFE764A135745196BULL,
		0x79410F02CDB90BAAULL,
		0xE9751641BF2D7A51ULL,
		0x2A74CA1FBCC42D53ULL,
		0x2E42F21ADEDC4559ULL,
		0xB6AAC7FF439330CCULL,
		0x74A8784FE69CB6C7ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA8FDCE94D54BB7BAULL,
		0x3D55D743F3059A03ULL,
		0xD8E21E797DDBF5B2ULL,
		0xA8C9BAB855FD0331ULL,
		0xFD34B8BEF794A4E8ULL,
		0x9AF67A6F63E4ECD8ULL,
		0xB3807F3A680F3895ULL,
		0x3FB6054E8678235BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51FB9D29AA976F74ULL,
		0x7AABAE87E60B3407ULL,
		0xB1C43CF2FBB7EB64ULL,
		0x51937570ABFA0663ULL,
		0xFA69717DEF2949D1ULL,
		0x35ECF4DEC7C9D9B1ULL,
		0x6700FE74D01E712BULL,
		0x7F6C0A9D0CF046B7ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFE4624D196511F38ULL,
		0xDA3A30ECF065EBB4ULL,
		0x6D40BC9A559A13D5ULL,
		0x193C3AC92C7015ACULL,
		0x83E7F08BE9A7169AULL,
		0xA69E50D1A1FA5FB6ULL,
		0x0DB58DA3054B562EULL,
		0x2D90947FC46FADE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC8C49A32CA23E70ULL,
		0xB47461D9E0CBD769ULL,
		0xDA817934AB3427ABULL,
		0x3278759258E02B58ULL,
		0x07CFE117D34E2D34ULL,
		0x4D3CA1A343F4BF6DULL,
		0x1B6B1B460A96AC5DULL,
		0x5B2128FF88DF5BD0ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x07FC19A119BD3B08ULL,
		0xF1111A6CFA8382CBULL,
		0x3994C97C30B21794ULL,
		0xC865B22C5CE6E35CULL,
		0xEED796DEE909E112ULL,
		0x2AD1EC595028DBE3ULL,
		0x3B4F919280A053DFULL,
		0x2B3826475CC7331CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF83342337A7610ULL,
		0xE22234D9F5070596ULL,
		0x732992F861642F29ULL,
		0x90CB6458B9CDC6B8ULL,
		0xDDAF2DBDD213C225ULL,
		0x55A3D8B2A051B7C7ULL,
		0x769F23250140A7BEULL,
		0x56704C8EB98E6638ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x862693D064E12794ULL,
		0xD56B31B8E1C23F1BULL,
		0xFE3D5CCF49877120ULL,
		0x5D336673DF823A4FULL,
		0x555B900C5D1A5ECAULL,
		0x4D922FD1F966FF1CULL,
		0x2FC397EE37F95B78ULL,
		0x2BBB61A82B0B2268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C4D27A0C9C24F28ULL,
		0xAAD66371C3847E37ULL,
		0xFC7AB99E930EE241ULL,
		0xBA66CCE7BF04749FULL,
		0xAAB72018BA34BD94ULL,
		0x9B245FA3F2CDFE38ULL,
		0x5F872FDC6FF2B6F0ULL,
		0x5776C350561644D0ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAA19E848163F0373ULL,
		0x44526876FA6EE90BULL,
		0x467B1FC8801C46F7ULL,
		0x555AB8540514D53FULL,
		0xFA89313DE2DA5A02ULL,
		0xB877D34FFA14EC33ULL,
		0x61AE58436571502BULL,
		0x0426D4E0083060E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5433D0902C7E06E6ULL,
		0x88A4D0EDF4DDD217ULL,
		0x8CF63F9100388DEEULL,
		0xAAB570A80A29AA7EULL,
		0xF512627BC5B4B404ULL,
		0x70EFA69FF429D867ULL,
		0xC35CB086CAE2A057ULL,
		0x084DA9C01060C1C4ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xEE954AD124F62AA7ULL,
		0xD92FEA5E98B2EB2FULL,
		0xB9949C74CDA7F334ULL,
		0xF6342F12ED569747ULL,
		0x7120B75CAA15B041ULL,
		0x01833372187A4CABULL,
		0x4924400795D0C2E1ULL,
		0x2C0D020919A57A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD2A95A249EC554EULL,
		0xB25FD4BD3165D65FULL,
		0x732938E99B4FE669ULL,
		0xEC685E25DAAD2E8FULL,
		0xE2416EB9542B6083ULL,
		0x030666E430F49956ULL,
		0x9248800F2BA185C2ULL,
		0x581A0412334AF538ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xEB0333E2388353D7ULL,
		0xC3FF2C8B666EEC08ULL,
		0x5068AD789071FE65ULL,
		0x51B781DC1497C07EULL,
		0xAA1A8713005C4F56ULL,
		0x49C43FA2915E2620ULL,
		0xE70DFDADFED32519ULL,
		0x380B52B0B4BB7909ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD60667C47106A7AEULL,
		0x87FE5916CCDDD811ULL,
		0xA0D15AF120E3FCCBULL,
		0xA36F03B8292F80FCULL,
		0x54350E2600B89EACULL,
		0x93887F4522BC4C41ULL,
		0xCE1BFB5BFDA64A32ULL,
		0x7016A5616976F213ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x45DFD7629DABD0C1ULL,
		0x8505DE03EED06C00ULL,
		0xD8169D60930205EDULL,
		0x13BC90BB9FEF16B1ULL,
		0x49A4B8BA5044603AULL,
		0x00CF517C091D8997ULL,
		0x5E0124D9D2307370ULL,
		0x203A9429F64EA1A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BBFAEC53B57A182ULL,
		0x0A0BBC07DDA0D800ULL,
		0xB02D3AC126040BDBULL,
		0x277921773FDE2D63ULL,
		0x93497174A088C074ULL,
		0x019EA2F8123B132EULL,
		0xBC0249B3A460E6E0ULL,
		0x40752853EC9D4340ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD0FBA6DF78A85F60ULL,
		0x7910CE13A69718A9ULL,
		0x0C05E487F03B109CULL,
		0x4B3C10860A87AA1BULL,
		0x372652DF7B829F06ULL,
		0x464F6EF679E65885ULL,
		0xD8DA9CF9C9637D7EULL,
		0x30FA09D2FE7C3FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F74DBEF150BEC0ULL,
		0xF2219C274D2E3153ULL,
		0x180BC90FE0762138ULL,
		0x9678210C150F5436ULL,
		0x6E4CA5BEF7053E0CULL,
		0x8C9EDDECF3CCB10AULL,
		0xB1B539F392C6FAFCULL,
		0x61F413A5FCF87F4BULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE65A503975A78EB4ULL,
		0xAACE7755C3954B06ULL,
		0x54D7E67377F445E3ULL,
		0x6C8F088E510AE285ULL,
		0xC5B82F28DBD58974ULL,
		0x3B823FA594EFA22AULL,
		0xEE9E8258899A552EULL,
		0x2EC9DCC6A2E0FA73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB4A072EB4F1D68ULL,
		0x559CEEAB872A960DULL,
		0xA9AFCCE6EFE88BC7ULL,
		0xD91E111CA215C50AULL,
		0x8B705E51B7AB12E8ULL,
		0x77047F4B29DF4455ULL,
		0xDD3D04B11334AA5CULL,
		0x5D93B98D45C1F4E7ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x365A74ABD845AEADULL,
		0xD1985D4836D64221ULL,
		0xC8648F7D9FC1B6E6ULL,
		0x182E6EAB69433898ULL,
		0x50C7C93E06A6F917ULL,
		0xD12EA744880C69DAULL,
		0xA965A3CD63047B87ULL,
		0x21E45694FDE887C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CB4E957B08B5D5AULL,
		0xA330BA906DAC8442ULL,
		0x90C91EFB3F836DCDULL,
		0x305CDD56D2867131ULL,
		0xA18F927C0D4DF22EULL,
		0xA25D4E891018D3B4ULL,
		0x52CB479AC608F70FULL,
		0x43C8AD29FBD10F91ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x377C904F6CF5BF36ULL,
		0xCA5B5D0A8B25F344ULL,
		0x096F842ECA7C1C6FULL,
		0x95A60EAA1C6F967FULL,
		0x882679B803AEDDC1ULL,
		0x584F241EDD6716DDULL,
		0x9909B1FF037E2D6EULL,
		0x1728C5E663FB356AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EF9209ED9EB7E6CULL,
		0x94B6BA15164BE688ULL,
		0x12DF085D94F838DFULL,
		0x2B4C1D5438DF2CFEULL,
		0x104CF370075DBB83ULL,
		0xB09E483DBACE2DBBULL,
		0x321363FE06FC5ADCULL,
		0x2E518BCCC7F66AD5ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5E9CD717A990FB81ULL,
		0xC70B3FD154F46E6EULL,
		0x2ABDE1648E08E11EULL,
		0x261E18EDC55E1F4CULL,
		0x4F42C38331EEF843ULL,
		0x8E21586C93C3C5BCULL,
		0x4C68A368C14E319AULL,
		0x04191A3C20955048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD39AE2F5321F702ULL,
		0x8E167FA2A9E8DCDCULL,
		0x557BC2C91C11C23DULL,
		0x4C3C31DB8ABC3E98ULL,
		0x9E85870663DDF086ULL,
		0x1C42B0D927878B78ULL,
		0x98D146D1829C6335ULL,
		0x08323478412AA090ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF4F1F720A31C3E8BULL,
		0xC67245B2678300F0ULL,
		0x5303515F5D532A58ULL,
		0xF7F78E67552CF38FULL,
		0x3755C023E1917685ULL,
		0x0B0B80A02773F222ULL,
		0x4A7AC3ED539A154DULL,
		0x3058C6EB91A391A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E3EE4146387D16ULL,
		0x8CE48B64CF0601E1ULL,
		0xA606A2BEBAA654B1ULL,
		0xEFEF1CCEAA59E71EULL,
		0x6EAB8047C322ED0BULL,
		0x161701404EE7E444ULL,
		0x94F587DAA7342A9AULL,
		0x60B18DD723472350ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x49506ECB5AEC0E02ULL,
		0x03FA9F0A17EB58BDULL,
		0xB3C95ED5E50178A6ULL,
		0x3C1C970071BB389FULL,
		0x08768A93301FCE56ULL,
		0x023E990BFE3F4D81ULL,
		0x89CFE5E203DFA6C5ULL,
		0x2493C206A515D57DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A0DD96B5D81C04ULL,
		0x07F53E142FD6B17AULL,
		0x6792BDABCA02F14CULL,
		0x78392E00E376713FULL,
		0x10ED1526603F9CACULL,
		0x047D3217FC7E9B02ULL,
		0x139FCBC407BF4D8AULL,
		0x4927840D4A2BAAFBULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4682D6E3CC14764AULL,
		0xAE9CA87EB74C57C9ULL,
		0xD34C6DAEBE6D352DULL,
		0xDC84531BC050123AULL,
		0xEE6C2D8A00830624ULL,
		0x792ECE12EB0E6A3CULL,
		0x4AC2B3E55DC61162ULL,
		0x27D6ED3141B0B889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D05ADC79828EC94ULL,
		0x5D3950FD6E98AF92ULL,
		0xA698DB5D7CDA6A5BULL,
		0xB908A63780A02475ULL,
		0xDCD85B1401060C49ULL,
		0xF25D9C25D61CD479ULL,
		0x958567CABB8C22C4ULL,
		0x4FADDA6283617112ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x721A982CBD25C16FULL,
		0x20555F2D98AD9B8CULL,
		0x3720EFAC6DF07925ULL,
		0x089F583B181A3487ULL,
		0xCB5C3F5CDE3BD3D0ULL,
		0x7C5CBABFE85422F6ULL,
		0x9806FEBCC1F0C3A4ULL,
		0x053544E91FEFDD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43530597A4B82DEULL,
		0x40AABE5B315B3718ULL,
		0x6E41DF58DBE0F24AULL,
		0x113EB0763034690EULL,
		0x96B87EB9BC77A7A0ULL,
		0xF8B9757FD0A845EDULL,
		0x300DFD7983E18748ULL,
		0x0A6A89D23FDFBA77ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x87EB49E95F5C578EULL,
		0x5A77C08D8AA2FB16ULL,
		0x63FCBABA12C8BBB6ULL,
		0x1C94CC938063FFFDULL,
		0xCA6D9151C396C5FAULL,
		0x92FCA21E8B62536FULL,
		0xFFFA068CC4BEEB83ULL,
		0x2477BB67CD8B5978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD693D2BEB8AF1CULL,
		0xB4EF811B1545F62DULL,
		0xC7F975742591776CULL,
		0x3929992700C7FFFAULL,
		0x94DB22A3872D8BF4ULL,
		0x25F9443D16C4A6DFULL,
		0xFFF40D19897DD707ULL,
		0x48EF76CF9B16B2F1ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4CFCC1B64E805B36ULL,
		0xBA170275BA300975ULL,
		0x397154129469D0B6ULL,
		0xB8CDD62DDDA0731FULL,
		0x09A6DC666CDCBA05ULL,
		0x498F18EB6A5F688AULL,
		0x6A4FADC3D0F481ACULL,
		0x0D18B178D5F9D238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F9836C9D00B66CULL,
		0x742E04EB746012EAULL,
		0x72E2A82528D3A16DULL,
		0x719BAC5BBB40E63EULL,
		0x134DB8CCD9B9740BULL,
		0x931E31D6D4BED114ULL,
		0xD49F5B87A1E90358ULL,
		0x1A3162F1ABF3A470ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFD301B0E028B6710ULL,
		0xC55254CBCE41E7DDULL,
		0x12CF546C028979ADULL,
		0x7730FD9E97C1643BULL,
		0xFA10EF9CC7EE24FEULL,
		0x7076F0F4687D928DULL,
		0xA855BD073F506733ULL,
		0x00856735967FEA33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA60361C0516CE20ULL,
		0x8AA4A9979C83CFBBULL,
		0x259EA8D80512F35BULL,
		0xEE61FB3D2F82C876ULL,
		0xF421DF398FDC49FCULL,
		0xE0EDE1E8D0FB251BULL,
		0x50AB7A0E7EA0CE66ULL,
		0x010ACE6B2CFFD467ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA7570F71C6C58A42ULL,
		0x409BBC87E622D3FFULL,
		0x6B8C32D84C31E118ULL,
		0x8A14F07EB5CD5A80ULL,
		0x812E3531C5471F4BULL,
		0x7564EAB60954DAA4ULL,
		0x6E753D4BFF73E217ULL,
		0x1EDD52D4036FF196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EAE1EE38D8B1484ULL,
		0x8137790FCC45A7FFULL,
		0xD71865B09863C230ULL,
		0x1429E0FD6B9AB500ULL,
		0x025C6A638A8E3E97ULL,
		0xEAC9D56C12A9B549ULL,
		0xDCEA7A97FEE7C42EULL,
		0x3DBAA5A806DFE32CULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB71F7A49C5B89B2AULL,
		0x9837383B3EA6BECBULL,
		0xE4655FAE981C226CULL,
		0xB21C41B6F1F94C2EULL,
		0xE0E01B4440DA39E5ULL,
		0x1581D22763E3AF9AULL,
		0x5E5F1426F8B2370BULL,
		0x15D63C0BA1D8B6F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E3EF4938B713654ULL,
		0x306E70767D4D7D97ULL,
		0xC8CABF5D303844D9ULL,
		0x6438836DE3F2985DULL,
		0xC1C0368881B473CBULL,
		0x2B03A44EC7C75F35ULL,
		0xBCBE284DF1646E16ULL,
		0x2BAC781743B16DEAULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x926096B2A016A0CAULL,
		0x905A02BBC0F03C45ULL,
		0xD12EA6B879A5CF8AULL,
		0x34377A42BA1AF10BULL,
		0x060569FB56D023EFULL,
		0xA26D18B63CAC76C2ULL,
		0x926D0B8C82A96199ULL,
		0x01F6F9624DCD9A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C12D65402D4194ULL,
		0x20B4057781E0788BULL,
		0xA25D4D70F34B9F15ULL,
		0x686EF4857435E217ULL,
		0x0C0AD3F6ADA047DEULL,
		0x44DA316C7958ED84ULL,
		0x24DA17190552C333ULL,
		0x03EDF2C49B9B3515ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1D01BDA5818799B9ULL,
		0x6A49949C75369CFFULL,
		0x7FBA75F16049E037ULL,
		0xDF2D26EA506E59B0ULL,
		0x5292E12A4AD2E5A9ULL,
		0xFE1B498BA2141090ULL,
		0x77643A0C90B1ED5BULL,
		0x2242DF62AE2B188EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A037B4B030F3372ULL,
		0xD4932938EA6D39FEULL,
		0xFF74EBE2C093C06EULL,
		0xBE5A4DD4A0DCB360ULL,
		0xA525C25495A5CB53ULL,
		0xFC36931744282120ULL,
		0xEEC874192163DAB7ULL,
		0x4485BEC55C56311CULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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