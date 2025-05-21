#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9F1C5F4710C56E7CULL,
		0xF3CF2E329E15EED6ULL,
		0xE8D47840C0174DC0ULL,
		0x2EE2D5E86C5C1A89ULL,
		0x1D6CD4C7A8C0C0BFULL,
		0x31CA0090853745EEULL,
		0x97D61031232DEB86ULL,
		0x2A8D673A22619A52ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3E38BE8E218ADCF8ULL,
		0xE79E5C653C2BDDADULL,
		0xD1A8F081802E9B81ULL,
		0x5DC5ABD0D8B83513ULL,
		0x3AD9A98F5181817EULL,
		0x639401210A6E8BDCULL,
		0x2FAC2062465BD70CULL,
		0x551ACE7444C334A5ULL
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
		0x99E0ACB9A4865AF0ULL,
		0xA4963678C5B97603ULL,
		0x34948895B95AB782ULL,
		0x123D2B331D05E127ULL,
		0x6729EE9FC7B32409ULL,
		0x2C35EB559B526123ULL,
		0x4F10DFDECC52F4A5ULL,
		0x2792ECC82BE1BA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33C15973490CB5E0ULL,
		0x492C6CF18B72EC07ULL,
		0x6929112B72B56F05ULL,
		0x247A56663A0BC24EULL,
		0xCE53DD3F8F664812ULL,
		0x586BD6AB36A4C246ULL,
		0x9E21BFBD98A5E94AULL,
		0x4F25D99057C374D6ULL
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
		0x6BC268B81558C1C5ULL,
		0x5A4D9FE5A4033598ULL,
		0x2D12FA058A9B81C5ULL,
		0x314B1ABD858E40FFULL,
		0x0DD5FEABAEDF2860ULL,
		0xEB132EB7B3BE4618ULL,
		0x5A25A6DDE64FD938ULL,
		0x35A00C69B754EDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD784D1702AB1838AULL,
		0xB49B3FCB48066B30ULL,
		0x5A25F40B1537038AULL,
		0x6296357B0B1C81FEULL,
		0x1BABFD575DBE50C0ULL,
		0xD6265D6F677C8C30ULL,
		0xB44B4DBBCC9FB271ULL,
		0x6B4018D36EA9DBD6ULL
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
		0x6AA6CB085DFF53B9ULL,
		0x50E0793F28448163ULL,
		0x850A28765FFF8E92ULL,
		0x1521C7090EC8F049ULL,
		0xF61124A3F1CB056EULL,
		0xD421987224AB4BA0ULL,
		0x160B3304A979709CULL,
		0x15D8FF0E076CEAEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54D9610BBFEA772ULL,
		0xA1C0F27E508902C6ULL,
		0x0A1450ECBFFF1D24ULL,
		0x2A438E121D91E093ULL,
		0xEC224947E3960ADCULL,
		0xA84330E449569741ULL,
		0x2C16660952F2E139ULL,
		0x2BB1FE1C0ED9D5D6ULL
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
		0xBDC1EF5F8EFD54CCULL,
		0x9CCE7FF1281C649BULL,
		0x18EB218FA5E30097ULL,
		0x313ACCBD27A645C6ULL,
		0xBE5A8558A8FBBFECULL,
		0x80017C662AF7FA27ULL,
		0xA6577C7459EE6352ULL,
		0x339172C022C37DA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B83DEBF1DFAA998ULL,
		0x399CFFE25038C937ULL,
		0x31D6431F4BC6012FULL,
		0x6275997A4F4C8B8CULL,
		0x7CB50AB151F77FD8ULL,
		0x0002F8CC55EFF44FULL,
		0x4CAEF8E8B3DCC6A5ULL,
		0x6722E5804586FB51ULL
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
		0xF5B61D10D4CFFDAFULL,
		0x3023DE58ED0DEF47ULL,
		0x2252CEDEA77AFC9DULL,
		0x3CBCCAC4FC23D0F3ULL,
		0x55929C19157EF62BULL,
		0x9EDB1C4A84DE6715ULL,
		0x29738E1309E0548DULL,
		0x2F6D25E00D0DDDD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6C3A21A99FFB5EULL,
		0x6047BCB1DA1BDE8FULL,
		0x44A59DBD4EF5F93AULL,
		0x79799589F847A1E6ULL,
		0xAB2538322AFDEC56ULL,
		0x3DB6389509BCCE2AULL,
		0x52E71C2613C0A91BULL,
		0x5EDA4BC01A1BBBA0ULL
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
		0xCC0B5BC54E8DA67AULL,
		0x201E1998FC78A67EULL,
		0xC54F78901719E34EULL,
		0xCB40142113A6AFF0ULL,
		0x77D37F23FDEF33A6ULL,
		0x30BA98D2DA231DC5ULL,
		0x623ED89CC788E299ULL,
		0x23534E160CA55E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9816B78A9D1B4CF4ULL,
		0x403C3331F8F14CFDULL,
		0x8A9EF1202E33C69CULL,
		0x96802842274D5FE1ULL,
		0xEFA6FE47FBDE674DULL,
		0x617531A5B4463B8AULL,
		0xC47DB1398F11C532ULL,
		0x46A69C2C194ABC36ULL
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
		0x6E9C2A4A9A2CCC2DULL,
		0x1E88EF189E61827EULL,
		0xA870E7C9335CA4CEULL,
		0x9B1D035C5BA23EAEULL,
		0xFE82B3EEE91574E8ULL,
		0x063F71D7E97B324AULL,
		0x5F2019890C5A0ECEULL,
		0x3B76737EDF1854CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3854953459985AULL,
		0x3D11DE313CC304FCULL,
		0x50E1CF9266B9499CULL,
		0x363A06B8B7447D5DULL,
		0xFD0567DDD22AE9D1ULL,
		0x0C7EE3AFD2F66495ULL,
		0xBE40331218B41D9CULL,
		0x76ECE6FDBE30A996ULL
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
		0x579F2184BF0B068FULL,
		0xC86152F01B29E040ULL,
		0xB327D7207AFF1D83ULL,
		0x67330D895D005D51ULL,
		0xAFEE7CE637E236A9ULL,
		0x56E35314B1589380ULL,
		0x602BBAD677B17186ULL,
		0x2AE7A5129AD39EECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3E43097E160D1EULL,
		0x90C2A5E03653C080ULL,
		0x664FAE40F5FE3B07ULL,
		0xCE661B12BA00BAA3ULL,
		0x5FDCF9CC6FC46D52ULL,
		0xADC6A62962B12701ULL,
		0xC05775ACEF62E30CULL,
		0x55CF4A2535A73DD8ULL
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
		0x3B1073978DB7C3EAULL,
		0x0213A6A479CD07CCULL,
		0xF671748935FA70C7ULL,
		0x0FCB8C761DD58BA6ULL,
		0xB645527109450235ULL,
		0x38994448337E8444ULL,
		0xB6EFF7DE8FCF82C8ULL,
		0x1C1376D7FA1F075FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7620E72F1B6F87D4ULL,
		0x04274D48F39A0F98ULL,
		0xECE2E9126BF4E18EULL,
		0x1F9718EC3BAB174DULL,
		0x6C8AA4E2128A046AULL,
		0x7132889066FD0889ULL,
		0x6DDFEFBD1F9F0590ULL,
		0x3826EDAFF43E0EBFULL
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
		0x5116B85E142F8829ULL,
		0x034C0E7DEDEC0CFBULL,
		0xF8E608BB06E06A50ULL,
		0x48A644169B2B6F7BULL,
		0xDE818660F71F4E5FULL,
		0xABA93DEF6F623D80ULL,
		0x64BDDB062FC8087CULL,
		0x2AAFC2595E1F1A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22D70BC285F1052ULL,
		0x06981CFBDBD819F6ULL,
		0xF1CC11760DC0D4A0ULL,
		0x914C882D3656DEF7ULL,
		0xBD030CC1EE3E9CBEULL,
		0x57527BDEDEC47B01ULL,
		0xC97BB60C5F9010F9ULL,
		0x555F84B2BC3E3496ULL
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
		0x55D6B42C42A7858BULL,
		0x4DC24C022D9F9A61ULL,
		0x82021D7AA90226E7ULL,
		0xE2D45B4696DBE256ULL,
		0xB8926AA8116C9663ULL,
		0xB5B13E9A814C80CCULL,
		0x30CFFEE3AE72CC87ULL,
		0x09BE787C07FFC5ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAD6858854F0B16ULL,
		0x9B8498045B3F34C2ULL,
		0x04043AF552044DCEULL,
		0xC5A8B68D2DB7C4ADULL,
		0x7124D55022D92CC7ULL,
		0x6B627D3502990199ULL,
		0x619FFDC75CE5990FULL,
		0x137CF0F80FFF8B58ULL
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
		0xBAA53B1B096DD66BULL,
		0x8B3004077AF07730ULL,
		0xB6F955EE6DA1BCFFULL,
		0xC5DC791690C982F5ULL,
		0x823F15513C24A316ULL,
		0xECBC070CD0F0C99EULL,
		0x0B4095AE3B51DB28ULL,
		0x25F2D9AF64AB97D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754A763612DBACD6ULL,
		0x1660080EF5E0EE61ULL,
		0x6DF2ABDCDB4379FFULL,
		0x8BB8F22D219305EBULL,
		0x047E2AA27849462DULL,
		0xD9780E19A1E1933DULL,
		0x16812B5C76A3B651ULL,
		0x4BE5B35EC9572FAEULL
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
		0x046E446C90E2D709ULL,
		0x3CF6CCAEA6832758ULL,
		0x396819E901A46EBAULL,
		0x893F86380CC3A008ULL,
		0xABFFB09346AE8E92ULL,
		0x3BFA423B0552ABACULL,
		0xA7A70DF413E7104FULL,
		0x01AB41A09E7DA5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08DC88D921C5AE12ULL,
		0x79ED995D4D064EB0ULL,
		0x72D033D20348DD74ULL,
		0x127F0C7019874010ULL,
		0x57FF61268D5D1D25ULL,
		0x77F484760AA55759ULL,
		0x4F4E1BE827CE209EULL,
		0x035683413CFB4B51ULL
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
		0x42D890950AD11D7BULL,
		0x79C1228CD9EA305BULL,
		0x96CA6D8E65D9E8ABULL,
		0xD3BA35F30473495AULL,
		0x51A3A1C48256A7C9ULL,
		0xD896D4E958DEB20CULL,
		0x47342AB6AE09CF42ULL,
		0x21060ECF19387F09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85B1212A15A23AF6ULL,
		0xF3824519B3D460B6ULL,
		0x2D94DB1CCBB3D156ULL,
		0xA7746BE608E692B5ULL,
		0xA347438904AD4F93ULL,
		0xB12DA9D2B1BD6418ULL,
		0x8E68556D5C139E85ULL,
		0x420C1D9E3270FE12ULL
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
		0xB42C8969E56F2343ULL,
		0x77777F2770E043D6ULL,
		0x49911AE79E945C4DULL,
		0xA5AB9D78F1A2CBF0ULL,
		0x61DFAC41F74AA75BULL,
		0x54DE61503D3FEF53ULL,
		0x2CD889AA2D127435ULL,
		0x0C77AAB6A7F528AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x685912D3CADE4686ULL,
		0xEEEEFE4EE1C087ADULL,
		0x932235CF3D28B89AULL,
		0x4B573AF1E34597E0ULL,
		0xC3BF5883EE954EB7ULL,
		0xA9BCC2A07A7FDEA6ULL,
		0x59B113545A24E86AULL,
		0x18EF556D4FEA5154ULL
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
		0xDD5DF01B4EB98214ULL,
		0x6971D1563B9E81E5ULL,
		0xCF92D96DB8327F21ULL,
		0x1431F99F0AA0B41DULL,
		0xA4DB034E9D82F7D1ULL,
		0xFF781FFE6C44B98CULL,
		0xD9478E1F16540EACULL,
		0x33328D3AB4A91E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBABBE0369D730428ULL,
		0xD2E3A2AC773D03CBULL,
		0x9F25B2DB7064FE42ULL,
		0x2863F33E1541683BULL,
		0x49B6069D3B05EFA2ULL,
		0xFEF03FFCD8897319ULL,
		0xB28F1C3E2CA81D59ULL,
		0x66651A7569523CDFULL
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
		0x4AE734720694A85EULL,
		0xF31019DE65088651ULL,
		0x839EE8E73ADF0D93ULL,
		0xAAD2DF38A5EFA926ULL,
		0x34591410BF045DC9ULL,
		0x17E658DE69C7E74FULL,
		0xD059CDCAA99B59E8ULL,
		0x1A6948EDE0AF108BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CE68E40D2950BCULL,
		0xE62033BCCA110CA2ULL,
		0x073DD1CE75BE1B27ULL,
		0x55A5BE714BDF524DULL,
		0x68B228217E08BB93ULL,
		0x2FCCB1BCD38FCE9EULL,
		0xA0B39B955336B3D0ULL,
		0x34D291DBC15E2117ULL
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
		0x4C558350AB33A46FULL,
		0xA5214A9231265F59ULL,
		0x8BA1D62A75CF3CFCULL,
		0xADC54758330D5417ULL,
		0x76BC4062F535599CULL,
		0x276E16CA72C31A10ULL,
		0x678055AFF95C5F16ULL,
		0x3CB4C8AA54962E47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98AB06A1566748DEULL,
		0x4A429524624CBEB2ULL,
		0x1743AC54EB9E79F9ULL,
		0x5B8A8EB0661AA82FULL,
		0xED7880C5EA6AB339ULL,
		0x4EDC2D94E5863420ULL,
		0xCF00AB5FF2B8BE2CULL,
		0x79699154A92C5C8EULL
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
		0xA87850CE068D51ECULL,
		0xE97228F109B69ECCULL,
		0x75FBBFC78F4C9105ULL,
		0x08BACB37656CDD0AULL,
		0x3CF3715511E6D575ULL,
		0x7416E24300796FDCULL,
		0xF938A5D2B5DD8C1EULL,
		0x2C59C3F87067C5F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F0A19C0D1AA3D8ULL,
		0xD2E451E2136D3D99ULL,
		0xEBF77F8F1E99220BULL,
		0x1175966ECAD9BA14ULL,
		0x79E6E2AA23CDAAEAULL,
		0xE82DC48600F2DFB8ULL,
		0xF2714BA56BBB183CULL,
		0x58B387F0E0CF8BEDULL
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
		0x74BEC5FD6D2C7ABEULL,
		0x8C6C96E5478C6245ULL,
		0x903DEFE6676AD91CULL,
		0x1C081DE84B610FC8ULL,
		0x482C9108AC6FA71BULL,
		0x338DE3FD6745E229ULL,
		0x2E5956A8CD186936ULL,
		0x22AA75E8E6E8B7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97D8BFADA58F57CULL,
		0x18D92DCA8F18C48AULL,
		0x207BDFCCCED5B239ULL,
		0x38103BD096C21F91ULL,
		0x9059221158DF4E36ULL,
		0x671BC7FACE8BC452ULL,
		0x5CB2AD519A30D26CULL,
		0x4554EBD1CDD16FA6ULL
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
		0x7ED1A9C68AE2FBF3ULL,
		0x62A5F63AB035A43CULL,
		0x1059E2D435CA38AEULL,
		0x27E7234945DF7F55ULL,
		0x0CD8178B3A65058FULL,
		0x52DFDE0C5D9170D6ULL,
		0xDB706852557D62A6ULL,
		0x0B55ED668C9E0F52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA3538D15C5F7E6ULL,
		0xC54BEC75606B4878ULL,
		0x20B3C5A86B94715CULL,
		0x4FCE46928BBEFEAAULL,
		0x19B02F1674CA0B1EULL,
		0xA5BFBC18BB22E1ACULL,
		0xB6E0D0A4AAFAC54CULL,
		0x16ABDACD193C1EA5ULL
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
		0x1E552242FC6AF711ULL,
		0xE784BC33A7BEA509ULL,
		0x9A81DD465D2F0FDAULL,
		0xDE95264C4A9A2D64ULL,
		0x2590F29D7B2C71C2ULL,
		0x0D48B3B44F95DEC7ULL,
		0xE01E3041DB6D5963ULL,
		0x0D2F4458493349AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CAA4485F8D5EE22ULL,
		0xCF0978674F7D4A12ULL,
		0x3503BA8CBA5E1FB5ULL,
		0xBD2A4C9895345AC9ULL,
		0x4B21E53AF658E385ULL,
		0x1A9167689F2BBD8EULL,
		0xC03C6083B6DAB2C6ULL,
		0x1A5E88B09266935DULL
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
		0x6311791A7841B8B5ULL,
		0xE85C6859F1E40A74ULL,
		0x6558F834EACC00EAULL,
		0x4C75829E530A56CFULL,
		0xBD83BDCD67AAEFBDULL,
		0xCA27DCFEB4F0B103ULL,
		0x609B496998E31D7FULL,
		0x236647BC7D5932E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC622F234F083716AULL,
		0xD0B8D0B3E3C814E8ULL,
		0xCAB1F069D59801D5ULL,
		0x98EB053CA614AD9EULL,
		0x7B077B9ACF55DF7AULL,
		0x944FB9FD69E16207ULL,
		0xC13692D331C63AFFULL,
		0x46CC8F78FAB265C0ULL
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
		0x853028EC7939B93CULL,
		0x6A8ABE0FA1566D21ULL,
		0x45B04C4FE613E8F5ULL,
		0x4100E42843AADED2ULL,
		0xE0E8D6432DEEF613ULL,
		0x864239AC0D61E9CCULL,
		0x5FDD9D43A69E4C11ULL,
		0x0F988E005EDCDADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6051D8F2737278ULL,
		0xD5157C1F42ACDA43ULL,
		0x8B60989FCC27D1EAULL,
		0x8201C8508755BDA4ULL,
		0xC1D1AC865BDDEC26ULL,
		0x0C8473581AC3D399ULL,
		0xBFBB3A874D3C9823ULL,
		0x1F311C00BDB9B5B6ULL
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
		0x8D4CB91C69805CDEULL,
		0x87BDEC8F80BFABB9ULL,
		0xD886064345CFB798ULL,
		0x6196451DC977717FULL,
		0x01746358B31D4B33ULL,
		0x51B7E676102D9AF6ULL,
		0x4C711613F4A80D25ULL,
		0x001C0570DD1EF4EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A997238D300B9BCULL,
		0x0F7BD91F017F5773ULL,
		0xB10C0C868B9F6F31ULL,
		0xC32C8A3B92EEE2FFULL,
		0x02E8C6B1663A9666ULL,
		0xA36FCCEC205B35ECULL,
		0x98E22C27E9501A4AULL,
		0x00380AE1BA3DE9D4ULL
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
		0x247464C8B7F020ADULL,
		0x90F20E3D81E4CFB3ULL,
		0xB5F1000B65AFF2A3ULL,
		0x25135D8F8B969446ULL,
		0x97C372F5EEC3F731ULL,
		0x9335D24AF56ACD7DULL,
		0x322DD7AAFFB68CADULL,
		0x21E0316BE88E7F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E8C9916FE0415AULL,
		0x21E41C7B03C99F66ULL,
		0x6BE20016CB5FE547ULL,
		0x4A26BB1F172D288DULL,
		0x2F86E5EBDD87EE62ULL,
		0x266BA495EAD59AFBULL,
		0x645BAF55FF6D195BULL,
		0x43C062D7D11CFF20ULL
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
		0x940037DD1995080AULL,
		0x2874682B3598EDE3ULL,
		0x6365F0A548F52726ULL,
		0xAF70E65A053192EAULL,
		0x1E04D056162D4ED1ULL,
		0x36361759AF0C4B46ULL,
		0xC81B0D8823380352ULL,
		0x229A0B02A4F24BCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28006FBA332A1014ULL,
		0x50E8D0566B31DBC7ULL,
		0xC6CBE14A91EA4E4CULL,
		0x5EE1CCB40A6325D4ULL,
		0x3C09A0AC2C5A9DA3ULL,
		0x6C6C2EB35E18968CULL,
		0x90361B10467006A4ULL,
		0x4534160549E4979BULL
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
		0x36A5925F5FE8D3E9ULL,
		0x9AFBE6F796DAC440ULL,
		0x0AEA93B008AC6507ULL,
		0x20BC938B6AE69B08ULL,
		0x5F920A948BB824E0ULL,
		0x9E7BE8D7DED7EF19ULL,
		0x9808FD905C72B6C9ULL,
		0x01967952630FC7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4B24BEBFD1A7D2ULL,
		0x35F7CDEF2DB58880ULL,
		0x15D527601158CA0FULL,
		0x41792716D5CD3610ULL,
		0xBF241529177049C0ULL,
		0x3CF7D1AFBDAFDE32ULL,
		0x3011FB20B8E56D93ULL,
		0x032CF2A4C61F8F79ULL
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
		0x8599520B7BE31E0CULL,
		0xC71927E456E5E833ULL,
		0x5E91C672E7890D53ULL,
		0xE1A843A3A90A257BULL,
		0x126C4B84F6E685B4ULL,
		0xD7DEA5AE502F8DDBULL,
		0x4E1CD4CEEE33FD7BULL,
		0x2271B6CB28941DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B32A416F7C63C18ULL,
		0x8E324FC8ADCBD067ULL,
		0xBD238CE5CF121AA7ULL,
		0xC350874752144AF6ULL,
		0x24D89709EDCD0B69ULL,
		0xAFBD4B5CA05F1BB6ULL,
		0x9C39A99DDC67FAF7ULL,
		0x44E36D9651283B9CULL
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
		0x3305341B49EE56CFULL,
		0xEB6FDEF3DA9C85A5ULL,
		0x3A684C4623634B23ULL,
		0x3CFADC119B6FD34CULL,
		0xB3D2AFFEEBB0FF2DULL,
		0xA4BDDE574C956693ULL,
		0x250033A6770F1251ULL,
		0x3A0A86BA78AE664BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x660A683693DCAD9EULL,
		0xD6DFBDE7B5390B4AULL,
		0x74D0988C46C69647ULL,
		0x79F5B82336DFA698ULL,
		0x67A55FFDD761FE5AULL,
		0x497BBCAE992ACD27ULL,
		0x4A00674CEE1E24A3ULL,
		0x74150D74F15CCC96ULL
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
		0x78236F17CB0D3511ULL,
		0x3360A04F806B1517ULL,
		0xB5A5AB7A43465E28ULL,
		0x443FF5845A5F4ECAULL,
		0x99AFB2878552AF51ULL,
		0xAAF8555A7CECD063ULL,
		0x842DD41C815A8D07ULL,
		0x028E595BDCB8C541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF046DE2F961A6A22ULL,
		0x66C1409F00D62A2EULL,
		0x6B4B56F4868CBC50ULL,
		0x887FEB08B4BE9D95ULL,
		0x335F650F0AA55EA2ULL,
		0x55F0AAB4F9D9A0C7ULL,
		0x085BA83902B51A0FULL,
		0x051CB2B7B9718A83ULL
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
		0x4731383320FDB463ULL,
		0x5F7487FC3BBD0D73ULL,
		0x8C84C6836A9AEA81ULL,
		0x927ECF164B247948ULL,
		0x32DEF43148C74796ULL,
		0xD0E914BD5F2CE5BBULL,
		0x324F6EF7788703D5ULL,
		0x275ED1F5D25317B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E62706641FB68C6ULL,
		0xBEE90FF8777A1AE6ULL,
		0x19098D06D535D502ULL,
		0x24FD9E2C9648F291ULL,
		0x65BDE862918E8F2DULL,
		0xA1D2297ABE59CB76ULL,
		0x649EDDEEF10E07ABULL,
		0x4EBDA3EBA4A62F60ULL
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
		0x38AA7AF4EF79CBDCULL,
		0x33B0CF753F6EBBBDULL,
		0xC1BC667C3A9BC8D1ULL,
		0x3CD174B27E6BF4B8ULL,
		0x9ACE7EACE2CBD4CCULL,
		0x6A0F004EFFCF53AEULL,
		0xF66B253244EF35B3ULL,
		0x3938E490B2B1ABD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7154F5E9DEF397B8ULL,
		0x67619EEA7EDD777AULL,
		0x8378CCF8753791A2ULL,
		0x79A2E964FCD7E971ULL,
		0x359CFD59C597A998ULL,
		0xD41E009DFF9EA75DULL,
		0xECD64A6489DE6B66ULL,
		0x7271C921656357ADULL
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
		0x986E249203E099C5ULL,
		0x1423B9BA92ACA555ULL,
		0x0B8B54285DB3A758ULL,
		0x3104A7456588C835ULL,
		0x819E08F71809E167ULL,
		0xE0B4999E73A96834ULL,
		0xA76E89BC57FDCCBCULL,
		0x120D32513AB11BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30DC492407C1338AULL,
		0x2847737525594AABULL,
		0x1716A850BB674EB0ULL,
		0x62094E8ACB11906AULL,
		0x033C11EE3013C2CEULL,
		0xC169333CE752D069ULL,
		0x4EDD1378AFFB9979ULL,
		0x241A64A2756237B5ULL
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
		0x4016D6973643EAFCULL,
		0x70CF397209F9FC2EULL,
		0xE530830D8449AFBDULL,
		0x48AFB47AE9FBA150ULL,
		0x1F6319C27C0AAFFDULL,
		0xBB069BF2979BF828ULL,
		0xF887D075FC978D73ULL,
		0x13857D45990C27BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802DAD2E6C87D5F8ULL,
		0xE19E72E413F3F85CULL,
		0xCA61061B08935F7AULL,
		0x915F68F5D3F742A1ULL,
		0x3EC63384F8155FFAULL,
		0x760D37E52F37F050ULL,
		0xF10FA0EBF92F1AE7ULL,
		0x270AFA8B32184F7FULL
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
		0xB22D00CF5E895622ULL,
		0xC2A3171F591CFF58ULL,
		0x27C1FC77CB857CE4ULL,
		0x9CAC7F938084FF2BULL,
		0x351C64FDA16B4A4BULL,
		0x64AE1B7150A34AEBULL,
		0x9E3BA52DD38CD7CBULL,
		0x1B0CBD1651E8AA60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x645A019EBD12AC44ULL,
		0x85462E3EB239FEB1ULL,
		0x4F83F8EF970AF9C9ULL,
		0x3958FF270109FE56ULL,
		0x6A38C9FB42D69497ULL,
		0xC95C36E2A14695D6ULL,
		0x3C774A5BA719AF96ULL,
		0x36197A2CA3D154C1ULL
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
		0x0FC2B727CED9BF2CULL,
		0x29C31CE40BA6D1F9ULL,
		0x32EDC179D64201F7ULL,
		0xD4F02088FE1972E6ULL,
		0xD0F9C7CE0D939FF2ULL,
		0x2A25E5CE07522101ULL,
		0xFD103BC7B27D9930ULL,
		0x1A6FA2718E270201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F856E4F9DB37E58ULL,
		0x538639C8174DA3F2ULL,
		0x65DB82F3AC8403EEULL,
		0xA9E04111FC32E5CCULL,
		0xA1F38F9C1B273FE5ULL,
		0x544BCB9C0EA44203ULL,
		0xFA20778F64FB3260ULL,
		0x34DF44E31C4E0403ULL
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
		0x0C81D78645875155ULL,
		0x3CA9A8436ED6E0A7ULL,
		0xB89B0547222211E7ULL,
		0xAAD7E50A1C9B9612ULL,
		0x5ABFE1DDFDAFAC46ULL,
		0x98D14227DD1B8C21ULL,
		0xB2FD1EA9C6E04C22ULL,
		0x3458003054A22778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1903AF0C8B0EA2AAULL,
		0x79535086DDADC14EULL,
		0x71360A8E444423CEULL,
		0x55AFCA1439372C25ULL,
		0xB57FC3BBFB5F588DULL,
		0x31A2844FBA371842ULL,
		0x65FA3D538DC09845ULL,
		0x68B00060A9444EF1ULL
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
		0xABB077E99C71B1E8ULL,
		0x11AF783EB4BA56DEULL,
		0x56E4FB60302B8A3FULL,
		0xCDFCE1135D72A114ULL,
		0xC01CC9B4243535A1ULL,
		0x2E3539D68A169445ULL,
		0xCA4D558B292602AEULL,
		0x10D7D35C7F03DAE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5760EFD338E363D0ULL,
		0x235EF07D6974ADBDULL,
		0xADC9F6C06057147EULL,
		0x9BF9C226BAE54228ULL,
		0x80399368486A6B43ULL,
		0x5C6A73AD142D288BULL,
		0x949AAB16524C055CULL,
		0x21AFA6B8FE07B5C1ULL
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
		0x3C54C3070983524FULL,
		0x7E5DFE65FFA450D9ULL,
		0xD81F337E75BD8B2BULL,
		0x7AD726CF62DBC869ULL,
		0x40550DC4CED74561ULL,
		0x42E926EA2135B8AAULL,
		0x9249DD751CAAE7EBULL,
		0x36F64D9DA24BCDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A9860E1306A49EULL,
		0xFCBBFCCBFF48A1B2ULL,
		0xB03E66FCEB7B1656ULL,
		0xF5AE4D9EC5B790D3ULL,
		0x80AA1B899DAE8AC2ULL,
		0x85D24DD4426B7154ULL,
		0x2493BAEA3955CFD6ULL,
		0x6DEC9B3B44979B8BULL
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
		0xEA39D571BAC309FCULL,
		0x86B753FA90C95947ULL,
		0xE165585BCEB6FCD9ULL,
		0x08E8364305AF24A3ULL,
		0x24866775AA579CCFULL,
		0x834D4655EEB2959AULL,
		0x4A4CCAC036331771ULL,
		0x3589AB7D27B8E5B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD473AAE3758613F8ULL,
		0x0D6EA7F52192B28FULL,
		0xC2CAB0B79D6DF9B3ULL,
		0x11D06C860B5E4947ULL,
		0x490CCEEB54AF399EULL,
		0x069A8CABDD652B34ULL,
		0x949995806C662EE3ULL,
		0x6B1356FA4F71CB60ULL
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
		0xCCB648E5DCD0282AULL,
		0x353BA9E235C481EBULL,
		0xDE7D261DED303869ULL,
		0x0AC6BC1376DCD9D7ULL,
		0x05C4D44C14B17175ULL,
		0x38F1409A545DD1C7ULL,
		0x735FFDE3F2F94E44ULL,
		0x1F901E4FC658526FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x996C91CBB9A05054ULL,
		0x6A7753C46B8903D7ULL,
		0xBCFA4C3BDA6070D2ULL,
		0x158D7826EDB9B3AFULL,
		0x0B89A8982962E2EAULL,
		0x71E28134A8BBA38EULL,
		0xE6BFFBC7E5F29C88ULL,
		0x3F203C9F8CB0A4DEULL
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
		0x7E2ED2BA05811325ULL,
		0x0BF1CF3F6E4B36E6ULL,
		0x56FDE7E2DDDE4FC9ULL,
		0x9D28AD9215586FCDULL,
		0xE4BDEADB79F87E06ULL,
		0xB091C6FD466408AAULL,
		0x124DB6860668697CULL,
		0x1AD13208D665A8C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC5DA5740B02264AULL,
		0x17E39E7EDC966DCCULL,
		0xADFBCFC5BBBC9F92ULL,
		0x3A515B242AB0DF9AULL,
		0xC97BD5B6F3F0FC0DULL,
		0x61238DFA8CC81155ULL,
		0x249B6D0C0CD0D2F9ULL,
		0x35A26411ACCB5182ULL
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
		0x4F23EF218ECD1CCDULL,
		0xB2B372794D6B172DULL,
		0x7EC4D2C711439A66ULL,
		0xF2F68EB55961C845ULL,
		0x224703DE381E7525ULL,
		0x4FE2354A69BFFCF7ULL,
		0x72DA57C03A927E49ULL,
		0x1891666B6F7C89D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E47DE431D9A399AULL,
		0x6566E4F29AD62E5AULL,
		0xFD89A58E228734CDULL,
		0xE5ED1D6AB2C3908AULL,
		0x448E07BC703CEA4BULL,
		0x9FC46A94D37FF9EEULL,
		0xE5B4AF807524FC92ULL,
		0x3122CCD6DEF913A2ULL
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
		0x7DB873BEFA617494ULL,
		0x71161D9A8EC84E5EULL,
		0xA60E2D42E47EBC21ULL,
		0xF416E0D2AC7B5DF8ULL,
		0xD7D5894EE226CF78ULL,
		0xE16D766A7B685866ULL,
		0x327FF49707C3049CULL,
		0x2103F42067935E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB70E77DF4C2E928ULL,
		0xE22C3B351D909CBCULL,
		0x4C1C5A85C8FD7842ULL,
		0xE82DC1A558F6BBF1ULL,
		0xAFAB129DC44D9EF1ULL,
		0xC2DAECD4F6D0B0CDULL,
		0x64FFE92E0F860939ULL,
		0x4207E840CF26BC18ULL
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
		0x75D14468C54A85F3ULL,
		0x5AF20FE5CF3B0CF1ULL,
		0x6D38C8382C161150ULL,
		0xA7B4A2956A965C89ULL,
		0x6E1EF10C05B16620ULL,
		0x9CC3D53287F56658ULL,
		0xB53E5AB05054DBF3ULL,
		0x3166725DBB44D491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA288D18A950BE6ULL,
		0xB5E41FCB9E7619E2ULL,
		0xDA719070582C22A0ULL,
		0x4F69452AD52CB912ULL,
		0xDC3DE2180B62CC41ULL,
		0x3987AA650FEACCB0ULL,
		0x6A7CB560A0A9B7E7ULL,
		0x62CCE4BB7689A923ULL
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
		0x2A182F2E60CF0DEFULL,
		0xDA14DF50AA6BC264ULL,
		0x46E0A496BE3C2BACULL,
		0xEA6B404CB42F80B9ULL,
		0xFF072BC1B4CE35EEULL,
		0x71DE8BF54001E1D0ULL,
		0xA6008DF105D1684CULL,
		0x12FB71FCDE9CAEB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54305E5CC19E1BDEULL,
		0xB429BEA154D784C8ULL,
		0x8DC1492D7C785759ULL,
		0xD4D68099685F0172ULL,
		0xFE0E5783699C6BDDULL,
		0xE3BD17EA8003C3A1ULL,
		0x4C011BE20BA2D098ULL,
		0x25F6E3F9BD395D69ULL
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
		0x2B304CA99AAD746AULL,
		0x61ABF3CB6B426AB9ULL,
		0x120857D53ACE18B9ULL,
		0x3887F26E8ACAED8BULL,
		0x39F99FA4DA1472F6ULL,
		0x251A527E0B84C01BULL,
		0x7D188374AED5021EULL,
		0x20E5E8BF0C74C5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56609953355AE8D4ULL,
		0xC357E796D684D572ULL,
		0x2410AFAA759C3172ULL,
		0x710FE4DD1595DB16ULL,
		0x73F33F49B428E5ECULL,
		0x4A34A4FC17098036ULL,
		0xFA3106E95DAA043CULL,
		0x41CBD17E18E98B80ULL
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
		0xA17746EB841BF3ACULL,
		0x3D8E70B272763C4AULL,
		0xD945F5D0379DF0B4ULL,
		0x6BFD9CD538C6F8E6ULL,
		0xB759649D82F7E755ULL,
		0x089FD29F03FD9925ULL,
		0xC72F1BE3C38232E7ULL,
		0x0E090F93667E9801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42EE8DD70837E758ULL,
		0x7B1CE164E4EC7895ULL,
		0xB28BEBA06F3BE168ULL,
		0xD7FB39AA718DF1CDULL,
		0x6EB2C93B05EFCEAAULL,
		0x113FA53E07FB324BULL,
		0x8E5E37C7870465CEULL,
		0x1C121F26CCFD3003ULL
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
		0xEE22B37760D0D28CULL,
		0x67748287432A8561ULL,
		0xAEF1595305D24F4DULL,
		0x2980D430B822B1CFULL,
		0xB6F8727240B633A5ULL,
		0x5DBE6233C696482FULL,
		0xDAB8BE84BEF78B6FULL,
		0x3B267AD78F6631ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4566EEC1A1A518ULL,
		0xCEE9050E86550AC3ULL,
		0x5DE2B2A60BA49E9AULL,
		0x5301A8617045639FULL,
		0x6DF0E4E4816C674AULL,
		0xBB7CC4678D2C905FULL,
		0xB5717D097DEF16DEULL,
		0x764CF5AF1ECC6359ULL
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
		0xAE24151C0A8AB311ULL,
		0xC64C2B0238C2E2C3ULL,
		0xBF1CEB3DD7A02917ULL,
		0xC7277661F9B8E1C3ULL,
		0x91B4AA15FB90C900ULL,
		0xAF3E20A72CF42858ULL,
		0x511F3BE5D4AB05ACULL,
		0x042A291734C6C799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C482A3815156622ULL,
		0x8C9856047185C587ULL,
		0x7E39D67BAF40522FULL,
		0x8E4EECC3F371C387ULL,
		0x2369542BF7219201ULL,
		0x5E7C414E59E850B1ULL,
		0xA23E77CBA9560B59ULL,
		0x0854522E698D8F32ULL
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
		0x41D08A8014EA5EC2ULL,
		0x39BCB8BB3A866D4AULL,
		0x6F84A8264AC65447ULL,
		0xE0CB0281415C8D8CULL,
		0x6033350D72C7E3E6ULL,
		0xF7A1091EEC99C3BBULL,
		0xC15867EAF96EAB2EULL,
		0x0B78EA31FF879066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A1150029D4BD84ULL,
		0x73797176750CDA94ULL,
		0xDF09504C958CA88EULL,
		0xC196050282B91B18ULL,
		0xC0666A1AE58FC7CDULL,
		0xEF42123DD9338776ULL,
		0x82B0CFD5F2DD565DULL,
		0x16F1D463FF0F20CDULL
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
		0x6CC7023143E94A3DULL,
		0xE317D6D6512056E6ULL,
		0xBF50E18766426D8BULL,
		0xF532789E2378C40CULL,
		0x6BE9D26F7D3B9708ULL,
		0x8FAE086E5BA151ABULL,
		0x37C1F65344D889F8ULL,
		0x3307ECBB282F190CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD98E046287D2947AULL,
		0xC62FADACA240ADCCULL,
		0x7EA1C30ECC84DB17ULL,
		0xEA64F13C46F18819ULL,
		0xD7D3A4DEFA772E11ULL,
		0x1F5C10DCB742A356ULL,
		0x6F83ECA689B113F1ULL,
		0x660FD976505E3218ULL
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
		0xC18F767D153328E5ULL,
		0xA3E33D232C08DB58ULL,
		0x106EA1AEB769B000ULL,
		0x4E9AC8E6266436E2ULL,
		0x24F92CEFCB8A3549ULL,
		0xEBD80FDAD7710E55ULL,
		0x499A57EA93245D56ULL,
		0x0D0F6736D6DF7930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x831EECFA2A6651CAULL,
		0x47C67A465811B6B1ULL,
		0x20DD435D6ED36001ULL,
		0x9D3591CC4CC86DC4ULL,
		0x49F259DF97146A92ULL,
		0xD7B01FB5AEE21CAAULL,
		0x9334AFD52648BAADULL,
		0x1A1ECE6DADBEF260ULL
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
		0xA3F11FE368418418ULL,
		0x2DCCB8A0CF139641ULL,
		0x0B94298A7FF5504FULL,
		0x06E3AAD4BF6E724CULL,
		0x4717B54A618EF15DULL,
		0xEEF4317255CBEC52ULL,
		0xAE60B8051BCEA500ULL,
		0x0EAA32488894334FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47E23FC6D0830830ULL,
		0x5B9971419E272C83ULL,
		0x17285314FFEAA09EULL,
		0x0DC755A97EDCE498ULL,
		0x8E2F6A94C31DE2BAULL,
		0xDDE862E4AB97D8A4ULL,
		0x5CC1700A379D4A01ULL,
		0x1D5464911128669FULL
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
		0xF242FB8755489BEDULL,
		0xCAA9306FC4E2FF4AULL,
		0x3F8676152554C3D4ULL,
		0x28AA300B5BDBA99CULL,
		0xADC05C0F711AC0C7ULL,
		0xD30A4D95DF691B62ULL,
		0xF8B046AC257880C4ULL,
		0x238D52EB439B42A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE485F70EAA9137DAULL,
		0x955260DF89C5FE95ULL,
		0x7F0CEC2A4AA987A9ULL,
		0x51546016B7B75338ULL,
		0x5B80B81EE235818EULL,
		0xA6149B2BBED236C5ULL,
		0xF1608D584AF10189ULL,
		0x471AA5D68736854FULL
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
		0x6B5714A4CA4C2AC5ULL,
		0xAB183CCDB5235BC0ULL,
		0x7DEAAB64C329E253ULL,
		0x6478C7886C8E9DFDULL,
		0xAA89EB697A074633ULL,
		0x2256280D829E14FEULL,
		0x367284D74F3ED7DCULL,
		0x39FC076DDD37571BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6AE29499498558AULL,
		0x5630799B6A46B780ULL,
		0xFBD556C98653C4A7ULL,
		0xC8F18F10D91D3BFAULL,
		0x5513D6D2F40E8C66ULL,
		0x44AC501B053C29FDULL,
		0x6CE509AE9E7DAFB8ULL,
		0x73F80EDBBA6EAE36ULL
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
		0x38AB002BEBC854C6ULL,
		0xCE3E601AA0C32F9FULL,
		0xF2F16EA344C5E58DULL,
		0x8596439C46484F8BULL,
		0x10A8C81F9AA0B9E3ULL,
		0x16C8D66480996944ULL,
		0x285759BAE8C419B0ULL,
		0x3BCC49A6FBEDE595ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71560057D790A98CULL,
		0x9C7CC03541865F3EULL,
		0xE5E2DD46898BCB1BULL,
		0x0B2C87388C909F17ULL,
		0x2151903F354173C7ULL,
		0x2D91ACC90132D288ULL,
		0x50AEB375D1883360ULL,
		0x7798934DF7DBCB2AULL
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
		0xDD442045C64B220DULL,
		0x571D0E280426A748ULL,
		0x9E7680F9A6232DA5ULL,
		0xE0EB7B0465682D70ULL,
		0xD64017C31FFFF736ULL,
		0x23231B48AE30911DULL,
		0xAAB9C62F60A6478DULL,
		0x35B1FE7C6386195DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA88408B8C96441AULL,
		0xAE3A1C50084D4E91ULL,
		0x3CED01F34C465B4AULL,
		0xC1D6F608CAD05AE1ULL,
		0xAC802F863FFFEE6DULL,
		0x464636915C61223BULL,
		0x55738C5EC14C8F1AULL,
		0x6B63FCF8C70C32BBULL
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
		0x3BBFA15FA5ECC383ULL,
		0x781AC5490194D727ULL,
		0xA10EA8EDEBBDA012ULL,
		0x476BCB84FB284B82ULL,
		0x16A54995D0E63518ULL,
		0x65A44CD0990D44A6ULL,
		0x032D6C146B5A2BD3ULL,
		0x158712FB09E33E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777F42BF4BD98706ULL,
		0xF0358A920329AE4EULL,
		0x421D51DBD77B4024ULL,
		0x8ED79709F6509705ULL,
		0x2D4A932BA1CC6A30ULL,
		0xCB4899A1321A894CULL,
		0x065AD828D6B457A6ULL,
		0x2B0E25F613C67CB8ULL
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
		0xB448A8A1A7EE4C66ULL,
		0x66615105339817D4ULL,
		0x3EDC8828061BA05DULL,
		0xB8A07DCF097E3B3EULL,
		0x1B00D02A8CA162F3ULL,
		0x18C110786A960180ULL,
		0xCD7217FD3F54DB3FULL,
		0x2359D14E22D320D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x689151434FDC98CCULL,
		0xCCC2A20A67302FA9ULL,
		0x7DB910500C3740BAULL,
		0x7140FB9E12FC767CULL,
		0x3601A0551942C5E7ULL,
		0x318220F0D52C0300ULL,
		0x9AE42FFA7EA9B67EULL,
		0x46B3A29C45A641A3ULL
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
		0xB87F8D4A4A72A6CBULL,
		0x864A8F760D0D3BA6ULL,
		0x6BD9BF90C77B8AC3ULL,
		0xA169A5F2DE4E817AULL,
		0x785267BB59488513ULL,
		0x1B297B934D7325E8ULL,
		0xE4C0D5D8CEE2AE4CULL,
		0x1C0B6EA6E2666D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FF1A9494E54D96ULL,
		0x0C951EEC1A1A774DULL,
		0xD7B37F218EF71587ULL,
		0x42D34BE5BC9D02F4ULL,
		0xF0A4CF76B2910A27ULL,
		0x3652F7269AE64BD0ULL,
		0xC981ABB19DC55C98ULL,
		0x3816DD4DC4CCDAC5ULL
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
		0x4FDD7FD90CBAF3CCULL,
		0x33299FD1AB5BF3DBULL,
		0x7B82806276ED355CULL,
		0x42D8CB51C8362FE8ULL,
		0x1BEEF52F918879D6ULL,
		0x00C24DCAFA53B9A0ULL,
		0x85A88706643F6D57ULL,
		0x022E36EF049D5B5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBAFFB21975E798ULL,
		0x66533FA356B7E7B6ULL,
		0xF70500C4EDDA6AB8ULL,
		0x85B196A3906C5FD0ULL,
		0x37DDEA5F2310F3ACULL,
		0x01849B95F4A77340ULL,
		0x0B510E0CC87EDAAEULL,
		0x045C6DDE093AB6B5ULL
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
		0x12FE256AE265BB1FULL,
		0xBC60FB5CF95F65E9ULL,
		0x7ADEB74447A999A4ULL,
		0x01EE55F1D2B60802ULL,
		0x53A48C59474233FDULL,
		0x0D2CCC4D6328CE1EULL,
		0xC880633CE19184EFULL,
		0x0921829434F3070FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25FC4AD5C4CB763EULL,
		0x78C1F6B9F2BECBD2ULL,
		0xF5BD6E888F533349ULL,
		0x03DCABE3A56C1004ULL,
		0xA74918B28E8467FAULL,
		0x1A59989AC6519C3CULL,
		0x9100C679C32309DEULL,
		0x1243052869E60E1FULL
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
		0x8049E04BFEB5D42DULL,
		0x9FDF13A0C3ED008BULL,
		0xA0C197523F140F62ULL,
		0x7153E6AB9B3D86FBULL,
		0xCDE4BD0792742AA5ULL,
		0xA3EBD6BE01ECBD50ULL,
		0x3F4742AD7E801408ULL,
		0x34CEAEAF398F66ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0093C097FD6BA85AULL,
		0x3FBE274187DA0117ULL,
		0x41832EA47E281EC5ULL,
		0xE2A7CD57367B0DF7ULL,
		0x9BC97A0F24E8554AULL,
		0x47D7AD7C03D97AA1ULL,
		0x7E8E855AFD002811ULL,
		0x699D5D5E731ECD58ULL
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
		0xE01B83ACC6320200ULL,
		0xCCC4968477585473ULL,
		0x76D00B45755D6E9DULL,
		0x0219621465D87DA8ULL,
		0x59EBBAA3C9D3BF98ULL,
		0x136C9B4223670A00ULL,
		0xD4CB35DEFCC5EC77ULL,
		0x34BDB9C0493CD0B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03707598C640400ULL,
		0x99892D08EEB0A8E7ULL,
		0xEDA0168AEABADD3BULL,
		0x0432C428CBB0FB50ULL,
		0xB3D7754793A77F30ULL,
		0x26D9368446CE1400ULL,
		0xA9966BBDF98BD8EEULL,
		0x697B73809279A171ULL
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
		0x0227A275645DFCD0ULL,
		0x3FAE2FBA2B3E7916ULL,
		0xFF40A4AFA2CDECFFULL,
		0xE0DF4EAB0152CA95ULL,
		0x2707D50CC18879C0ULL,
		0x8F187B63EE3A3CF1ULL,
		0x13C9D1CE44ABD0F6ULL,
		0x2D6702341987EA8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044F44EAC8BBF9A0ULL,
		0x7F5C5F74567CF22CULL,
		0xFE81495F459BD9FEULL,
		0xC1BE9D5602A5952BULL,
		0x4E0FAA198310F381ULL,
		0x1E30F6C7DC7479E2ULL,
		0x2793A39C8957A1EDULL,
		0x5ACE0468330FD514ULL
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
		0xC68069AB389BE03AULL,
		0x7ED3A405EDDB390CULL,
		0x1E1BBC003C1D013BULL,
		0xA9361F984992BF52ULL,
		0xF4E5BAAA02803213ULL,
		0xF046C5017BC9B9DEULL,
		0x3F5B676A8740C2ACULL,
		0x091F9FF6744BF418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D00D3567137C074ULL,
		0xFDA7480BDBB67219ULL,
		0x3C377800783A0276ULL,
		0x526C3F3093257EA4ULL,
		0xE9CB755405006427ULL,
		0xE08D8A02F79373BDULL,
		0x7EB6CED50E818559ULL,
		0x123F3FECE897E830ULL
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
		0x52F94138C56EDC3AULL,
		0xFA9388D833A5B261ULL,
		0x43E6DF3EA7E00A89ULL,
		0x2635749F5450A690ULL,
		0x08DE5DB2DD0AC861ULL,
		0xEEF731CAE48935F2ULL,
		0x4191183DC4E4B145ULL,
		0x2E6AEBEE0A0100FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5F282718ADDB874ULL,
		0xF52711B0674B64C2ULL,
		0x87CDBE7D4FC01513ULL,
		0x4C6AE93EA8A14D20ULL,
		0x11BCBB65BA1590C2ULL,
		0xDDEE6395C9126BE4ULL,
		0x8322307B89C9628BULL,
		0x5CD5D7DC140201FCULL
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
		0x3530E7E011239FD3ULL,
		0xED558ED6A857BE17ULL,
		0xD8D5B460917BD1C9ULL,
		0x4CD16ABEE666C9D9ULL,
		0x8C9BAFE053574B1EULL,
		0xFE9E1487346AA480ULL,
		0xD8CB8F346A2C27F6ULL,
		0x198A56CF08E16557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A61CFC022473FA6ULL,
		0xDAAB1DAD50AF7C2EULL,
		0xB1AB68C122F7A393ULL,
		0x99A2D57DCCCD93B3ULL,
		0x19375FC0A6AE963CULL,
		0xFD3C290E68D54901ULL,
		0xB1971E68D4584FEDULL,
		0x3314AD9E11C2CAAFULL
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
		0x94EF46FD55D87180ULL,
		0xDB77AA1130B7045FULL,
		0x8214F6C438C2CF59ULL,
		0xAC2CCFC89DB504E2ULL,
		0xD624D66F46D12D20ULL,
		0xF8F395747CFA8562ULL,
		0xAFA1126ACCA88F9AULL,
		0x12997ED0B30B9C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DE8DFAABB0E300ULL,
		0xB6EF5422616E08BFULL,
		0x0429ED8871859EB3ULL,
		0x58599F913B6A09C5ULL,
		0xAC49ACDE8DA25A41ULL,
		0xF1E72AE8F9F50AC5ULL,
		0x5F4224D599511F35ULL,
		0x2532FDA16617393FULL
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
		0x2FF6FD5113555738ULL,
		0x56F7703B19340789ULL,
		0xB20C963D71AEC8EAULL,
		0x775702D695AA7FF5ULL,
		0x86B7299386CEAF2AULL,
		0xF26F1194D3AD1F7DULL,
		0xB4A5FB7697B098C4ULL,
		0x086537DC6A98B5C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FEDFAA226AAAE70ULL,
		0xADEEE07632680F12ULL,
		0x64192C7AE35D91D4ULL,
		0xEEAE05AD2B54FFEBULL,
		0x0D6E53270D9D5E54ULL,
		0xE4DE2329A75A3EFBULL,
		0x694BF6ED2F613189ULL,
		0x10CA6FB8D5316B8BULL
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
		0x76712EC45C5F90F5ULL,
		0xA63FEF0ABAFEC131ULL,
		0x721072E7EFF66245ULL,
		0x609943B01D2BDD6EULL,
		0x214666DD460786ADULL,
		0x66FCA05EADFD7458ULL,
		0x5D2D7AE1500E5FA3ULL,
		0x29A8427C38130060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE25D88B8BF21EAULL,
		0x4C7FDE1575FD8262ULL,
		0xE420E5CFDFECC48BULL,
		0xC13287603A57BADCULL,
		0x428CCDBA8C0F0D5AULL,
		0xCDF940BD5BFAE8B0ULL,
		0xBA5AF5C2A01CBF46ULL,
		0x535084F8702600C0ULL
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
		0xA04CC28777E163F9ULL,
		0xE38B1C8DD93018ECULL,
		0x078252B50E15C155ULL,
		0x847DFE5DE76ED0B5ULL,
		0x9C2ECD247E7914BDULL,
		0xEF40F65A4B832BAEULL,
		0x9529EF1846CE6AECULL,
		0x17284CE9B37D7BE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4099850EEFC2C7F2ULL,
		0xC716391BB26031D9ULL,
		0x0F04A56A1C2B82ABULL,
		0x08FBFCBBCEDDA16AULL,
		0x385D9A48FCF2297BULL,
		0xDE81ECB49706575DULL,
		0x2A53DE308D9CD5D9ULL,
		0x2E5099D366FAF7CDULL
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
		0xD80A1B6966A7271DULL,
		0x122FE7540FA8839BULL,
		0x3A37EFF3E366D320ULL,
		0x9E22131B69195287ULL,
		0xD44A669B4B3CCD0DULL,
		0x1D577F1A463B57C4ULL,
		0xD80C76AB04D51E4EULL,
		0x38BC76F467B8F8C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01436D2CD4E4E3AULL,
		0x245FCEA81F510737ULL,
		0x746FDFE7C6CDA640ULL,
		0x3C442636D232A50EULL,
		0xA894CD3696799A1BULL,
		0x3AAEFE348C76AF89ULL,
		0xB018ED5609AA3C9CULL,
		0x7178EDE8CF71F189ULL
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
		0x56B4104030C1B273ULL,
		0x358A9AC61933CE65ULL,
		0xF58C2E7F65DCF90AULL,
		0x106554CF8A07EBBFULL,
		0xE1DD5EFD33A12C76ULL,
		0x10A8D13504100ACFULL,
		0xC847212892B25F82ULL,
		0x3F6F03E0D9364A01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD682080618364E6ULL,
		0x6B15358C32679CCAULL,
		0xEB185CFECBB9F214ULL,
		0x20CAA99F140FD77FULL,
		0xC3BABDFA674258ECULL,
		0x2151A26A0820159FULL,
		0x908E42512564BF04ULL,
		0x7EDE07C1B26C9403ULL
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
		0xFDF3538E5856EC67ULL,
		0xB178A9CB75D6C55AULL,
		0xC5BB6DF9B60AAC5CULL,
		0x9414787D13953DE1ULL,
		0xC54888C4A7291071ULL,
		0x7009CEB284FC6C11ULL,
		0x508E9E3FE34282C6ULL,
		0x0904A2C95FC9914DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE6A71CB0ADD8CEULL,
		0x62F15396EBAD8AB5ULL,
		0x8B76DBF36C1558B9ULL,
		0x2828F0FA272A7BC3ULL,
		0x8A9111894E5220E3ULL,
		0xE0139D6509F8D823ULL,
		0xA11D3C7FC685058CULL,
		0x12094592BF93229AULL
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
		0xFB6E255E277BE070ULL,
		0xC252880196E87741ULL,
		0x7AD9DB652E9A495FULL,
		0x08883D3AAE305AB7ULL,
		0xFAB2BC2A8C116FA7ULL,
		0xB7ADC73C6C373623ULL,
		0xEA1946C2A0099277ULL,
		0x1381BEE51E782F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6DC4ABC4EF7C0E0ULL,
		0x84A510032DD0EE83ULL,
		0xF5B3B6CA5D3492BFULL,
		0x11107A755C60B56EULL,
		0xF56578551822DF4EULL,
		0x6F5B8E78D86E6C47ULL,
		0xD4328D85401324EFULL,
		0x27037DCA3CF05F17ULL
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
		0xCDA0978A54DC26A2ULL,
		0xC94203F2ACE4A433ULL,
		0x97C23D66384DE5FFULL,
		0x4DDA9DBBB17298B6ULL,
		0x1EEE663C28CD6FF9ULL,
		0x1AB168B4B8B48EB3ULL,
		0x342C374BF39B17ABULL,
		0x2B3FCDDE483F4C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B412F14A9B84D44ULL,
		0x928407E559C94867ULL,
		0x2F847ACC709BCBFFULL,
		0x9BB53B7762E5316DULL,
		0x3DDCCC78519ADFF2ULL,
		0x3562D16971691D66ULL,
		0x68586E97E7362F56ULL,
		0x567F9BBC907E9816ULL
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
		0xAE7B55E2569B27ACULL,
		0x6741C5AFBF3BF81DULL,
		0xB9A05060636EC6B9ULL,
		0x4E0D7AAD19A485A0ULL,
		0xE5F1D2700C93E2B6ULL,
		0xB6F2E527DCDEC766ULL,
		0x5E53A3AB083C2376ULL,
		0x28BAAC7CB380C286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CF6ABC4AD364F58ULL,
		0xCE838B5F7E77F03BULL,
		0x7340A0C0C6DD8D72ULL,
		0x9C1AF55A33490B41ULL,
		0xCBE3A4E01927C56CULL,
		0x6DE5CA4FB9BD8ECDULL,
		0xBCA74756107846EDULL,
		0x517558F96701850CULL
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
		0x6E1F6EF4113A4946ULL,
		0x0A435ACCAF6DD678ULL,
		0xE3F7E45DCC6979A7ULL,
		0x8306BFA8488090E9ULL,
		0xF67021359F8FBB42ULL,
		0x6D98D73915532852ULL,
		0x84BD9EA54B8AA6FCULL,
		0x1CBB6C132F114937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC3EDDE82274928CULL,
		0x1486B5995EDBACF0ULL,
		0xC7EFC8BB98D2F34EULL,
		0x060D7F50910121D3ULL,
		0xECE0426B3F1F7685ULL,
		0xDB31AE722AA650A5ULL,
		0x097B3D4A97154DF8ULL,
		0x3976D8265E22926FULL
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
		0x192D211A9E70F878ULL,
		0xF50C17C98D3EB0DAULL,
		0xBB011D37ABDBBE93ULL,
		0xB96AD9136C59D1CBULL,
		0x226110BE7BDFE4C2ULL,
		0xAA48C09B09FF03CFULL,
		0x6DD526F5E6FE4266ULL,
		0x1D5A4F065AE0BAD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x325A42353CE1F0F0ULL,
		0xEA182F931A7D61B4ULL,
		0x76023A6F57B77D27ULL,
		0x72D5B226D8B3A397ULL,
		0x44C2217CF7BFC985ULL,
		0x5491813613FE079EULL,
		0xDBAA4DEBCDFC84CDULL,
		0x3AB49E0CB5C175A0ULL
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
		0xC82364F926CF5272ULL,
		0x5A2839708E0F3A25ULL,
		0xE5AD98E481EC4EC6ULL,
		0xBFAAACC323DF32C6ULL,
		0xD69484245581FB89ULL,
		0x01F2DE6989306087ULL,
		0x7DC18E6E9A6C0125ULL,
		0x2E71C282112F566AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9046C9F24D9EA4E4ULL,
		0xB45072E11C1E744BULL,
		0xCB5B31C903D89D8CULL,
		0x7F55598647BE658DULL,
		0xAD290848AB03F713ULL,
		0x03E5BCD31260C10FULL,
		0xFB831CDD34D8024AULL,
		0x5CE38504225EACD4ULL
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
		0x03D19835FA6B34ABULL,
		0x2B6E4B16BFCDFB0FULL,
		0x6C8B0DD3F99FC6EBULL,
		0x47F4C3D2C11E6BA6ULL,
		0x0CF7FD23FC716FD4ULL,
		0xD1A0655C00FE27A4ULL,
		0x1694A282DC1E47C5ULL,
		0x3E25A100EFCE5DDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A3306BF4D66956ULL,
		0x56DC962D7F9BF61EULL,
		0xD9161BA7F33F8DD6ULL,
		0x8FE987A5823CD74CULL,
		0x19EFFA47F8E2DFA8ULL,
		0xA340CAB801FC4F48ULL,
		0x2D294505B83C8F8BULL,
		0x7C4B4201DF9CBBB6ULL
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
		0x07AB94DA42344005ULL,
		0x0B445E4D8959CD47ULL,
		0x536D36BF5E06407CULL,
		0x0F0B200DDB1C66FEULL,
		0x93E138AC40566698ULL,
		0xAE2FDC25D22AFC81ULL,
		0xA362DFA46C4E9ECAULL,
		0x159E95B03FD6897DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5729B48468800AULL,
		0x1688BC9B12B39A8EULL,
		0xA6DA6D7EBC0C80F8ULL,
		0x1E16401BB638CDFCULL,
		0x27C2715880ACCD30ULL,
		0x5C5FB84BA455F903ULL,
		0x46C5BF48D89D3D95ULL,
		0x2B3D2B607FAD12FBULL
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
		0x8E668F723D0A995DULL,
		0xF3849094BBE733C1ULL,
		0x3DFDB4E20F78332CULL,
		0x206EC5B40EBA3B8AULL,
		0x2F3908F00A07323FULL,
		0xAC305D092E683FD8ULL,
		0x1E95047A6B14A9CAULL,
		0x15F7847FF3F19BB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CCD1EE47A1532BAULL,
		0xE709212977CE6783ULL,
		0x7BFB69C41EF06659ULL,
		0x40DD8B681D747714ULL,
		0x5E7211E0140E647EULL,
		0x5860BA125CD07FB0ULL,
		0x3D2A08F4D6295395ULL,
		0x2BEF08FFE7E3376CULL
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
		0x1EB9A8B981AB390EULL,
		0x2F6F52F5024CBF5CULL,
		0xE3A209F3BBA79493ULL,
		0x612F8A4329970307ULL,
		0x6A3A481E41B0C262ULL,
		0xFA0F75BA3C1DE044ULL,
		0x0B4DFE936033E150ULL,
		0x0BD7153ADF5CBEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D7351730356721CULL,
		0x5EDEA5EA04997EB8ULL,
		0xC74413E7774F2926ULL,
		0xC25F1486532E060FULL,
		0xD474903C836184C4ULL,
		0xF41EEB74783BC088ULL,
		0x169BFD26C067C2A1ULL,
		0x17AE2A75BEB97D64ULL
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
		0x7C52C1926FEE39C3ULL,
		0x5A49E2FA604786ABULL,
		0xAE11BEC603699E87ULL,
		0xB5E6745D3C823593ULL,
		0xB759A99C0CF35145ULL,
		0x25F6F7D4BA21E0DFULL,
		0x9C613B194CA4B15BULL,
		0x370DF4118A941385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A58324DFDC7386ULL,
		0xB493C5F4C08F0D56ULL,
		0x5C237D8C06D33D0EULL,
		0x6BCCE8BA79046B27ULL,
		0x6EB3533819E6A28BULL,
		0x4BEDEFA97443C1BFULL,
		0x38C27632994962B6ULL,
		0x6E1BE8231528270BULL
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
		0x61204D64806866BEULL,
		0x9A57C634D67D083EULL,
		0x56ED5EA0209450B0ULL,
		0x85126E30614E55EDULL,
		0x25B01DE863F7722CULL,
		0xD79B0CCD06685AA7ULL,
		0x9E1D55B7C3E3FAADULL,
		0x0E55014DCCA04A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2409AC900D0CD7CULL,
		0x34AF8C69ACFA107CULL,
		0xADDABD404128A161ULL,
		0x0A24DC60C29CABDAULL,
		0x4B603BD0C7EEE459ULL,
		0xAF36199A0CD0B54EULL,
		0x3C3AAB6F87C7F55BULL,
		0x1CAA029B994094A5ULL
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
		0x2E078012E9A6B582ULL,
		0x7FE9674F07F9EB98ULL,
		0xFD6B04ACFDE1B121ULL,
		0x468226660A268BB0ULL,
		0x6F6CBA178AEFBFD2ULL,
		0xBF9A63F2D4EFED10ULL,
		0x77668E0FB5A8B4B1ULL,
		0x27BFB609641E74AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C0F0025D34D6B04ULL,
		0xFFD2CE9E0FF3D730ULL,
		0xFAD60959FBC36242ULL,
		0x8D044CCC144D1761ULL,
		0xDED9742F15DF7FA4ULL,
		0x7F34C7E5A9DFDA20ULL,
		0xEECD1C1F6B516963ULL,
		0x4F7F6C12C83CE954ULL
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
		0xA6853CD89D279143ULL,
		0x20D0ECBD08E089F5ULL,
		0xBE3EED8DB9784A8FULL,
		0x1111DAB808FB1632ULL,
		0x155910159C388D59ULL,
		0x262B07CBC3261F03ULL,
		0x3D63013CD0C1CB78ULL,
		0x37F34C51F1EAA71DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D0A79B13A4F2286ULL,
		0x41A1D97A11C113EBULL,
		0x7C7DDB1B72F0951EULL,
		0x2223B57011F62C65ULL,
		0x2AB2202B38711AB2ULL,
		0x4C560F97864C3E06ULL,
		0x7AC60279A18396F0ULL,
		0x6FE698A3E3D54E3AULL
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
		0x0AA75988946F6387ULL,
		0xDD96C0068F777236ULL,
		0x2085DD7A51378968ULL,
		0xE17B7A4D6CB8209BULL,
		0x4537665E1A322255ULL,
		0x98B9C2230B63BC0BULL,
		0xA36E38FF5C082095ULL,
		0x1AAB6AC0696A68B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x154EB31128DEC70EULL,
		0xBB2D800D1EEEE46CULL,
		0x410BBAF4A26F12D1ULL,
		0xC2F6F49AD9704136ULL,
		0x8A6ECCBC346444ABULL,
		0x3173844616C77816ULL,
		0x46DC71FEB810412BULL,
		0x3556D580D2D4D171ULL
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
		0x1308507A5E03CD4BULL,
		0xDFA16B594884F150ULL,
		0x721725BBD0855A10ULL,
		0xA8688AE36D22C203ULL,
		0x34E864549F0D2CB4ULL,
		0xB6B7E4213DA0077AULL,
		0x852026552715FECDULL,
		0x0566784BFBAACD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2610A0F4BC079A96ULL,
		0xBF42D6B29109E2A0ULL,
		0xE42E4B77A10AB421ULL,
		0x50D115C6DA458406ULL,
		0x69D0C8A93E1A5969ULL,
		0x6D6FC8427B400EF4ULL,
		0x0A404CAA4E2BFD9BULL,
		0x0ACCF097F7559AB1ULL
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
		0x573FD849D881F22FULL,
		0xE79815FC23CACCD5ULL,
		0xD6738944CCEA2131ULL,
		0x96C91786929B746FULL,
		0xD8F3016586EA8C35ULL,
		0x982F1FE93014718CULL,
		0xB4D48D516D53299FULL,
		0x1937DCB4C8B6D932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7FB093B103E45EULL,
		0xCF302BF8479599AAULL,
		0xACE7128999D44263ULL,
		0x2D922F0D2536E8DFULL,
		0xB1E602CB0DD5186BULL,
		0x305E3FD26028E319ULL,
		0x69A91AA2DAA6533FULL,
		0x326FB969916DB265ULL
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
		0x980FB3DC019FB213ULL,
		0x13822CE899972F0EULL,
		0x3062768ED37B0057ULL,
		0x0BE1F30C918C496FULL,
		0xD395D939D25AAE49ULL,
		0x57FA7C5B5D44C153ULL,
		0xD681548F810220A9ULL,
		0x1D3AEC234A4FB714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x301F67B8033F6426ULL,
		0x270459D1332E5E1DULL,
		0x60C4ED1DA6F600AEULL,
		0x17C3E619231892DEULL,
		0xA72BB273A4B55C92ULL,
		0xAFF4F8B6BA8982A7ULL,
		0xAD02A91F02044152ULL,
		0x3A75D846949F6E29ULL
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
		0x84B72DD39317F57EULL,
		0x38F83CD6D8A66452ULL,
		0x9D3B177D46AABC3DULL,
		0xD03E20B36EE8AEB2ULL,
		0x111D35BF45159297ULL,
		0x773B747BA6F5EAB8ULL,
		0x34B9A935FB35C7C7ULL,
		0x170155B0322731EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x096E5BA7262FEAFCULL,
		0x71F079ADB14CC8A5ULL,
		0x3A762EFA8D55787AULL,
		0xA07C4166DDD15D65ULL,
		0x223A6B7E8A2B252FULL,
		0xEE76E8F74DEBD570ULL,
		0x6973526BF66B8F8EULL,
		0x2E02AB60644E63DAULL
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
		0x13F7B7CB361A9746ULL,
		0x5AA09A37B5CB60BBULL,
		0x55B2D2CFB01EF639ULL,
		0xA6CE786B985724D3ULL,
		0xE45E2A5EFED6D560ULL,
		0xB65C47B78E8BBCE0ULL,
		0xDFBDC11348D996E9ULL,
		0x280CC5BD9B3503B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27EF6F966C352E8CULL,
		0xB541346F6B96C176ULL,
		0xAB65A59F603DEC72ULL,
		0x4D9CF0D730AE49A6ULL,
		0xC8BC54BDFDADAAC1ULL,
		0x6CB88F6F1D1779C1ULL,
		0xBF7B822691B32DD3ULL,
		0x50198B7B366A0767ULL
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
		0xEC13DF0CD8F93CE3ULL,
		0x507C603113BD21EBULL,
		0xE8AE290BC5D4764FULL,
		0x186FC3FAC259480DULL,
		0xB19FFBC791FF1767ULL,
		0x6C890D38DA42D836ULL,
		0x7F1780C9E82EE75CULL,
		0x19DC7D4A7271BB88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD827BE19B1F279C6ULL,
		0xA0F8C062277A43D7ULL,
		0xD15C52178BA8EC9EULL,
		0x30DF87F584B2901BULL,
		0x633FF78F23FE2ECEULL,
		0xD9121A71B485B06DULL,
		0xFE2F0193D05DCEB8ULL,
		0x33B8FA94E4E37710ULL
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
		0x54744814B1DD3088ULL,
		0x947A70E1F870985FULL,
		0x85D5A4C0B96207F6ULL,
		0x85ED1E56E60E9DB0ULL,
		0x16ABFDA173BF40DCULL,
		0x8D622C17DBED73A8ULL,
		0x4F584CCFED9F51D5ULL,
		0x3F66C61E60EC0D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8E8902963BA6110ULL,
		0x28F4E1C3F0E130BEULL,
		0x0BAB498172C40FEDULL,
		0x0BDA3CADCC1D3B61ULL,
		0x2D57FB42E77E81B9ULL,
		0x1AC4582FB7DAE750ULL,
		0x9EB0999FDB3EA3ABULL,
		0x7ECD8C3CC1D81AD2ULL
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
		0x39C31CA8E59D154BULL,
		0x4FCB01C0377DEF8FULL,
		0xF7559154CFDA4C5BULL,
		0x2654CD4A47ADCDADULL,
		0x9B6A7A2CC3AA0DCBULL,
		0x0DE561324D9190A6ULL,
		0x560D59FAB9BFE208ULL,
		0x06B63694AD4BD6A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73863951CB3A2A96ULL,
		0x9F9603806EFBDF1EULL,
		0xEEAB22A99FB498B6ULL,
		0x4CA99A948F5B9B5BULL,
		0x36D4F45987541B96ULL,
		0x1BCAC2649B23214DULL,
		0xAC1AB3F5737FC410ULL,
		0x0D6C6D295A97AD4CULL
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
		0x9DCBD043771FBAF2ULL,
		0xA63E5D6CEBFF85CCULL,
		0x15742CEF25A3F805ULL,
		0xEB3BB954655E3BE4ULL,
		0xC59B8E5EE3707CD0ULL,
		0xB3C9184F5ABD4E4BULL,
		0x09454E6670C7D59CULL,
		0x068E5A9AE5D250CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B97A086EE3F75E4ULL,
		0x4C7CBAD9D7FF0B99ULL,
		0x2AE859DE4B47F00BULL,
		0xD67772A8CABC77C8ULL,
		0x8B371CBDC6E0F9A1ULL,
		0x6792309EB57A9C97ULL,
		0x128A9CCCE18FAB39ULL,
		0x0D1CB535CBA4A19AULL
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
		0x94C5F4DBA1F86BA9ULL,
		0x54FBBAB56B2B3DF2ULL,
		0x46680DDBD64984D5ULL,
		0x2A82D727007EC044ULL,
		0x8F91428454638CB0ULL,
		0x2878F64B37F6DBEDULL,
		0x61604671B0A4E255ULL,
		0x0731C140B8232D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x298BE9B743F0D752ULL,
		0xA9F7756AD6567BE5ULL,
		0x8CD01BB7AC9309AAULL,
		0x5505AE4E00FD8088ULL,
		0x1F228508A8C71960ULL,
		0x50F1EC966FEDB7DBULL,
		0xC2C08CE36149C4AAULL,
		0x0E63828170465AC0ULL
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
		0x3D4B2B64CA24BE6BULL,
		0x1340429A36A14489ULL,
		0x5C5AE8693A8153B5ULL,
		0x9CAC47E8EE489176ULL,
		0x6448DF8FED21100BULL,
		0x37E26CE50F60BFE6ULL,
		0x33582B7BF4ED4431ULL,
		0x042ED6EED293A5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9656C994497CD6ULL,
		0x268085346D428912ULL,
		0xB8B5D0D27502A76AULL,
		0x39588FD1DC9122ECULL,
		0xC891BF1FDA422017ULL,
		0x6FC4D9CA1EC17FCCULL,
		0x66B056F7E9DA8862ULL,
		0x085DADDDA5274B7EULL
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
		0xC2C518BA93158299ULL,
		0xA545AF292566ADD0ULL,
		0x0142372CCF053F63ULL,
		0xA5D5AC3015979D6FULL,
		0x4F3579E8C6FE50F6ULL,
		0x0795F15852C4CD55ULL,
		0x7544B59459504C26ULL,
		0x34E7C02C19B13100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858A3175262B0532ULL,
		0x4A8B5E524ACD5BA1ULL,
		0x02846E599E0A7EC7ULL,
		0x4BAB58602B2F3ADEULL,
		0x9E6AF3D18DFCA1EDULL,
		0x0F2BE2B0A5899AAAULL,
		0xEA896B28B2A0984CULL,
		0x69CF805833626200ULL
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
		0x6A811A9FB9B108EFULL,
		0xD3E94B956B062F89ULL,
		0x6F6997F82D5EDC5FULL,
		0x899D2C091727A1C0ULL,
		0xE9736E35924524BFULL,
		0xB7BCEAD23BA1DB98ULL,
		0x6CE54848728DB096ULL,
		0x1BC864BAFDDD35E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD502353F736211DEULL,
		0xA7D2972AD60C5F12ULL,
		0xDED32FF05ABDB8BFULL,
		0x133A58122E4F4380ULL,
		0xD2E6DC6B248A497FULL,
		0x6F79D5A47743B731ULL,
		0xD9CA9090E51B612DULL,
		0x3790C975FBBA6BD0ULL
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
		0xC2C1C67B167A32CDULL,
		0xB5A74D9A7B19E952ULL,
		0x1244205AB1EF926CULL,
		0x1099D552775474F8ULL,
		0x8AE7B23A8602DEB4ULL,
		0xEF755FA31B5BB49EULL,
		0xFEEDBA9417710018ULL,
		0x0899461203DD4E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85838CF62CF4659AULL,
		0x6B4E9B34F633D2A5ULL,
		0x248840B563DF24D9ULL,
		0x2133AAA4EEA8E9F0ULL,
		0x15CF64750C05BD68ULL,
		0xDEEABF4636B7693DULL,
		0xFDDB75282EE20031ULL,
		0x11328C2407BA9CD3ULL
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
		0x3ED435A316641978ULL,
		0xB99DABFB7A4A3EA2ULL,
		0x3B3D23ECA1D6C08EULL,
		0x4BA169403E9F1CBCULL,
		0x1770934815B66E13ULL,
		0x4707E34138F5964CULL,
		0xED7F87480B7D27A6ULL,
		0x27E7C2D5CFAE050CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DA86B462CC832F0ULL,
		0x733B57F6F4947D44ULL,
		0x767A47D943AD811DULL,
		0x9742D2807D3E3978ULL,
		0x2EE126902B6CDC26ULL,
		0x8E0FC68271EB2C98ULL,
		0xDAFF0E9016FA4F4CULL,
		0x4FCF85AB9F5C0A19ULL
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
		0xBD6A23AC1835CA53ULL,
		0x3F6DA62C2F7D29A8ULL,
		0xA3FBD41B0A17F920ULL,
		0x998D233976431ECAULL,
		0x3DE1EDD966A7CBF3ULL,
		0x8222057087FA7E78ULL,
		0x7C59FE20B22DABBEULL,
		0x1AE4DD1A3836A3C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD44758306B94A6ULL,
		0x7EDB4C585EFA5351ULL,
		0x47F7A836142FF240ULL,
		0x331A4672EC863D95ULL,
		0x7BC3DBB2CD4F97E7ULL,
		0x04440AE10FF4FCF0ULL,
		0xF8B3FC41645B577DULL,
		0x35C9BA34706D478CULL
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
		0x31EAF8AD244FF521ULL,
		0x4D68CB6C07AA2544ULL,
		0x578BA1E02B586B63ULL,
		0x452ADAE6B51F0C43ULL,
		0xD9F8BE76EDFCB60AULL,
		0x0253F9B5A6B35081ULL,
		0x3A7512E8C213405BULL,
		0x3E62CC5C9C5C17A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63D5F15A489FEA42ULL,
		0x9AD196D80F544A88ULL,
		0xAF1743C056B0D6C6ULL,
		0x8A55B5CD6A3E1886ULL,
		0xB3F17CEDDBF96C14ULL,
		0x04A7F36B4D66A103ULL,
		0x74EA25D1842680B6ULL,
		0x7CC598B938B82F42ULL
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
		0x244DE164AB178B89ULL,
		0x60D6D17AE85CBD8DULL,
		0x2A1D88FB24028BD7ULL,
		0x1662C60CEDB66B24ULL,
		0x0A32EFAA6BFFF7F6ULL,
		0xFA57CF1F58E58721ULL,
		0xC25ACBB4BDB7E2D4ULL,
		0x0D0C747EE157F1CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x489BC2C9562F1712ULL,
		0xC1ADA2F5D0B97B1AULL,
		0x543B11F6480517AEULL,
		0x2CC58C19DB6CD648ULL,
		0x1465DF54D7FFEFECULL,
		0xF4AF9E3EB1CB0E42ULL,
		0x84B597697B6FC5A9ULL,
		0x1A18E8FDC2AFE39BULL
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
		0x791B87893FCBF9BFULL,
		0x4B55E2150A9F9027ULL,
		0x037EB0D013A6C700ULL,
		0x36F7948F2946BCC6ULL,
		0xCDF6C1F029B19119ULL,
		0x27B320E45EBD6479ULL,
		0x9AB5969E58FE0ED0ULL,
		0x12C98B59D7E371D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2370F127F97F37EULL,
		0x96ABC42A153F204EULL,
		0x06FD61A0274D8E00ULL,
		0x6DEF291E528D798CULL,
		0x9BED83E053632232ULL,
		0x4F6641C8BD7AC8F3ULL,
		0x356B2D3CB1FC1DA0ULL,
		0x259316B3AFC6E3A7ULL
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
		0x4316F6B5AF16C5DCULL,
		0x663386C4F4B5E1D7ULL,
		0xF40C295C8251CB6DULL,
		0xC67EF433C3578CB0ULL,
		0x487B799F9F31F7E3ULL,
		0x1D5A799EC913F315ULL,
		0xF75F980A7263156DULL,
		0x1892E3F34212773AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862DED6B5E2D8BB8ULL,
		0xCC670D89E96BC3AEULL,
		0xE81852B904A396DAULL,
		0x8CFDE86786AF1961ULL,
		0x90F6F33F3E63EFC7ULL,
		0x3AB4F33D9227E62AULL,
		0xEEBF3014E4C62ADAULL,
		0x3125C7E68424EE75ULL
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
		0x81D3B83049A90865ULL,
		0xC74C2D0DADFAB937ULL,
		0x6E3C90FB11A7D0C3ULL,
		0xC99323D27A3EF451ULL,
		0xDF938BB99629FCE8ULL,
		0x0988C3777C98F307ULL,
		0xA657AB1AFFD6E31EULL,
		0x201CFE3D049C6867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A77060935210CAULL,
		0x8E985A1B5BF5726FULL,
		0xDC7921F6234FA187ULL,
		0x932647A4F47DE8A2ULL,
		0xBF2717732C53F9D1ULL,
		0x131186EEF931E60FULL,
		0x4CAF5635FFADC63CULL,
		0x4039FC7A0938D0CFULL
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
		0x1393B8874787208DULL,
		0xE1B03DFC50599727ULL,
		0xF25CBFAED42D8AECULL,
		0xC206504DD8363AB6ULL,
		0xFF60503B965F35DBULL,
		0xC0012B15D1ABA81BULL,
		0x83359B1A49D3939FULL,
		0x230CB570E17B276BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2727710E8F0E411AULL,
		0xC3607BF8A0B32E4EULL,
		0xE4B97F5DA85B15D9ULL,
		0x840CA09BB06C756DULL,
		0xFEC0A0772CBE6BB7ULL,
		0x8002562BA3575037ULL,
		0x066B363493A7273FULL,
		0x46196AE1C2F64ED7ULL
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
		0x37703C7CC77E2610ULL,
		0xC3DCDABC0C13287BULL,
		0xE59CFA020508BAFDULL,
		0x9D91B68F7769F4D2ULL,
		0xA5AB8BB5BBFA9489ULL,
		0xEC6DDE496E9D423BULL,
		0x1B2AA441172C5F2FULL,
		0x2786A3E4E1F1F87FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE078F98EFC4C20ULL,
		0x87B9B578182650F6ULL,
		0xCB39F4040A1175FBULL,
		0x3B236D1EEED3E9A5ULL,
		0x4B57176B77F52913ULL,
		0xD8DBBC92DD3A8477ULL,
		0x365548822E58BE5FULL,
		0x4F0D47C9C3E3F0FEULL
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
		0x2045F1369CC534B6ULL,
		0xBDBF8C9E9C179922ULL,
		0xB67D026CCB789DF6ULL,
		0x872495DA5F701FA2ULL,
		0x635BB79A7104EC02ULL,
		0xF825FF2AA815E793ULL,
		0x65C8D4B418E6F21EULL,
		0x28516B8CBC919AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408BE26D398A696CULL,
		0x7B7F193D382F3244ULL,
		0x6CFA04D996F13BEDULL,
		0x0E492BB4BEE03F45ULL,
		0xC6B76F34E209D805ULL,
		0xF04BFE55502BCF26ULL,
		0xCB91A96831CDE43DULL,
		0x50A2D719792335C0ULL
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
		0x94BCC6B3F87C2CB4ULL,
		0x96D5946BB0697721ULL,
		0x2062C02D82EC67EDULL,
		0x41643694039DC868ULL,
		0xCD0793FB0F454924ULL,
		0x7C12D43D79B24B4DULL,
		0xA7D471C87AC0A246ULL,
		0x22CE7481CE4603C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29798D67F0F85968ULL,
		0x2DAB28D760D2EE43ULL,
		0x40C5805B05D8CFDBULL,
		0x82C86D28073B90D0ULL,
		0x9A0F27F61E8A9248ULL,
		0xF825A87AF364969BULL,
		0x4FA8E390F581448CULL,
		0x459CE9039C8C078DULL
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
		0x75838B7E7D478744ULL,
		0xC4AFCEC89CEA08FEULL,
		0x3C0FC97FF24CE81AULL,
		0x2D03C5874D23C316ULL,
		0x6D0723CD0F5390E2ULL,
		0x1DA882C50C04E001ULL,
		0x1CD7A59AAFB699A1ULL,
		0x0FF7730037AE97FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB0716FCFA8F0E88ULL,
		0x895F9D9139D411FCULL,
		0x781F92FFE499D035ULL,
		0x5A078B0E9A47862CULL,
		0xDA0E479A1EA721C4ULL,
		0x3B51058A1809C002ULL,
		0x39AF4B355F6D3342ULL,
		0x1FEEE6006F5D2FF8ULL
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
		0xACF8A37B66E61342ULL,
		0x46F4408F90CF16D1ULL,
		0x1BDC221B52DCFEC5ULL,
		0x3F4C99DB77234AF9ULL,
		0xFEECD7DAB1A214CCULL,
		0x4ED0AA2F80324EEFULL,
		0x0F856D6B9DAF84DDULL,
		0x2D854C9F60EC36ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F146F6CDCC2684ULL,
		0x8DE8811F219E2DA3ULL,
		0x37B84436A5B9FD8AULL,
		0x7E9933B6EE4695F2ULL,
		0xFDD9AFB563442998ULL,
		0x9DA1545F00649DDFULL,
		0x1F0ADAD73B5F09BAULL,
		0x5B0A993EC1D86D56ULL
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
		0x9039988050B1546DULL,
		0xA271B7D1E29708A9ULL,
		0x4251B624D92FD399ULL,
		0x963D88C15D9E4060ULL,
		0xC03E8E212956288AULL,
		0xAC228BB33E328D17ULL,
		0x80A72FD831E323BEULL,
		0x17F574625444BAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20733100A162A8DAULL,
		0x44E36FA3C52E1153ULL,
		0x84A36C49B25FA733ULL,
		0x2C7B1182BB3C80C0ULL,
		0x807D1C4252AC5115ULL,
		0x584517667C651A2FULL,
		0x014E5FB063C6477DULL,
		0x2FEAE8C4A88975A9ULL
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
		0x76C75FA5ADF09CF2ULL,
		0x1D38E8DD439935F3ULL,
		0xD471E5021539FB63ULL,
		0xAA09C76AC088BE5AULL,
		0xD9DCC9B43B46A661ULL,
		0x117F068D6E30E029ULL,
		0x03AFD6AE713FA152ULL,
		0x1928307C0FEB111BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED8EBF4B5BE139E4ULL,
		0x3A71D1BA87326BE6ULL,
		0xA8E3CA042A73F6C6ULL,
		0x54138ED581117CB5ULL,
		0xB3B99368768D4CC3ULL,
		0x22FE0D1ADC61C053ULL,
		0x075FAD5CE27F42A4ULL,
		0x325060F81FD62236ULL
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
		0x3E5ADC22C3D23BDBULL,
		0x43F4E6BD80FD67F3ULL,
		0x9C9B614075F5808CULL,
		0x1C52C6CCFB9F6B8DULL,
		0x3BAB3C1573B9F88BULL,
		0xC1E49C7CA24CB2CAULL,
		0xE27233034CF3A9DBULL,
		0x09867CA8349A732AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CB5B84587A477B6ULL,
		0x87E9CD7B01FACFE6ULL,
		0x3936C280EBEB0118ULL,
		0x38A58D99F73ED71BULL,
		0x7756782AE773F116ULL,
		0x83C938F944996594ULL,
		0xC4E4660699E753B7ULL,
		0x130CF9506934E655ULL
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
		0xFBD54440B6B310BAULL,
		0x110B25363E0AC5E2ULL,
		0x330888951B0B652DULL,
		0x0A48FB436EFB835FULL,
		0x631BBB86980F688EULL,
		0xF8846EFCDFE799CFULL,
		0xE35BAFA6835C47C5ULL,
		0x27EFA28FCC244B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7AA88816D662174ULL,
		0x22164A6C7C158BC5ULL,
		0x6611112A3616CA5AULL,
		0x1491F686DDF706BEULL,
		0xC637770D301ED11CULL,
		0xF108DDF9BFCF339EULL,
		0xC6B75F4D06B88F8BULL,
		0x4FDF451F984896E7ULL
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
		0xCB4144E7D90CACAEULL,
		0xAEA9FC589399F5F3ULL,
		0xAF417D5FE26D8D97ULL,
		0x2007659990B22D44ULL,
		0xD641211CBEE236EEULL,
		0xCBCB1C1E9523A1C2ULL,
		0x879ED3BB82A93E7BULL,
		0x2696142AC6286166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x968289CFB219595CULL,
		0x5D53F8B12733EBE7ULL,
		0x5E82FABFC4DB1B2FULL,
		0x400ECB3321645A89ULL,
		0xAC8242397DC46DDCULL,
		0x9796383D2A474385ULL,
		0x0F3DA77705527CF7ULL,
		0x4D2C28558C50C2CDULL
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
		0x0B2209CC42A3A53FULL,
		0xFC0BEDB68DC494FEULL,
		0x7CDE4DECC8E23379ULL,
		0x32C7AFCEEEB1E47BULL,
		0xD0AD5D5437AF71FBULL,
		0x88D5544EC0796627ULL,
		0xACB20E96F8D91894ULL,
		0x334DCAD6604BE657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1644139885474A7EULL,
		0xF817DB6D1B8929FCULL,
		0xF9BC9BD991C466F3ULL,
		0x658F5F9DDD63C8F6ULL,
		0xA15ABAA86F5EE3F6ULL,
		0x11AAA89D80F2CC4FULL,
		0x59641D2DF1B23129ULL,
		0x669B95ACC097CCAFULL
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
		0x338646ED3C960D5DULL,
		0x0FB4F900BB42F469ULL,
		0xB02BF988E58C7617ULL,
		0x35F08E02D20C62CFULL,
		0x2F3330C8792AD214ULL,
		0x2508A58A8CFF2F4FULL,
		0x201121EE49EF97DAULL,
		0x3963FE30EFE327AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670C8DDA792C1ABAULL,
		0x1F69F2017685E8D2ULL,
		0x6057F311CB18EC2EULL,
		0x6BE11C05A418C59FULL,
		0x5E666190F255A428ULL,
		0x4A114B1519FE5E9EULL,
		0x402243DC93DF2FB4ULL,
		0x72C7FC61DFC64F5CULL
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
		0x8B7073F6E422075FULL,
		0x28B53F05B6C08D93ULL,
		0xD2C26229FCBB3D4BULL,
		0xDC5276C2F92C4707ULL,
		0xF84106259067A881ULL,
		0xF517A99EC2FA561CULL,
		0xD0D28885B82EE95FULL,
		0x3BF2FB52136366E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E0E7EDC8440EBEULL,
		0x516A7E0B6D811B27ULL,
		0xA584C453F9767A96ULL,
		0xB8A4ED85F2588E0FULL,
		0xF0820C4B20CF5103ULL,
		0xEA2F533D85F4AC39ULL,
		0xA1A5110B705DD2BFULL,
		0x77E5F6A426C6CDD1ULL
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
		0x4188AFB2E7DED8EEULL,
		0x696DD774285FFFA6ULL,
		0x2D861646633CB0A8ULL,
		0xF3602217E039926DULL,
		0x019299480C227E3AULL,
		0x829E35C88711B55DULL,
		0x7F3236C9297AD0A5ULL,
		0x2F155920A6E16F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83115F65CFBDB1DCULL,
		0xD2DBAEE850BFFF4CULL,
		0x5B0C2C8CC6796150ULL,
		0xE6C0442FC07324DAULL,
		0x032532901844FC75ULL,
		0x053C6B910E236ABAULL,
		0xFE646D9252F5A14BULL,
		0x5E2AB2414DC2DF38ULL
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
		0xE3F4CB7B1C6FE88CULL,
		0x992717A3EAF17D69ULL,
		0x28BE098C92AD2039ULL,
		0x415AC8546CF34E5DULL,
		0x6063E08CB43BCF8DULL,
		0x65FF6E6C29546DFDULL,
		0x0FBEF0AC37CD9347ULL,
		0x04D5E16D5CC4C96EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7E996F638DFD118ULL,
		0x324E2F47D5E2FAD3ULL,
		0x517C1319255A4073ULL,
		0x82B590A8D9E69CBAULL,
		0xC0C7C11968779F1AULL,
		0xCBFEDCD852A8DBFAULL,
		0x1F7DE1586F9B268EULL,
		0x09ABC2DAB98992DCULL
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
		0x4D82C7C5DCE3B606ULL,
		0xEED2DB52E9FD3526ULL,
		0xF77CDDB728A2928EULL,
		0x4013DFC7BF385E41ULL,
		0xCF195CDD0089D5B0ULL,
		0xFB5E61305BAB1599ULL,
		0x118428CDE26909E4ULL,
		0x209D14BDAE71B1ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B058F8BB9C76C0CULL,
		0xDDA5B6A5D3FA6A4CULL,
		0xEEF9BB6E5145251DULL,
		0x8027BF8F7E70BC83ULL,
		0x9E32B9BA0113AB60ULL,
		0xF6BCC260B7562B33ULL,
		0x2308519BC4D213C9ULL,
		0x413A297B5CE363D8ULL
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
		0x7D458FE954191D10ULL,
		0x3454B86C44F14166ULL,
		0x8185FE8986058939ULL,
		0x5C59566C62A42CBEULL,
		0xC7E232DEC1AAF25FULL,
		0x5F240337EC8E1BE1ULL,
		0xDFE76329B5A65988ULL,
		0x28612F1E09CBACD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA8B1FD2A8323A20ULL,
		0x68A970D889E282CCULL,
		0x030BFD130C0B1272ULL,
		0xB8B2ACD8C548597DULL,
		0x8FC465BD8355E4BEULL,
		0xBE48066FD91C37C3ULL,
		0xBFCEC6536B4CB310ULL,
		0x50C25E3C139759ADULL
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
		0x61BFF08915E38E50ULL,
		0xC90B310F5D4890CAULL,
		0x549126851DD0953CULL,
		0xD39D18152D086DD4ULL,
		0xEE223E16C2209BC3ULL,
		0x62E9300893D36FF5ULL,
		0xE38A1BF2F61DB68CULL,
		0x0A022BB03ADB9C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC37FE1122BC71CA0ULL,
		0x9216621EBA912194ULL,
		0xA9224D0A3BA12A79ULL,
		0xA73A302A5A10DBA8ULL,
		0xDC447C2D84413787ULL,
		0xC5D2601127A6DFEBULL,
		0xC71437E5EC3B6D18ULL,
		0x1404576075B73869ULL
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
		0x26A2D86C1183218CULL,
		0xD54B166CBEC02B83ULL,
		0x9032AECAF9C88912ULL,
		0x7F6AE2AFAB023AA1ULL,
		0x3A84F25D0231CB8CULL,
		0xFE7C5BD7C1A94213ULL,
		0x9F86594D8D385754ULL,
		0x3731542FF6C39D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D45B0D823064318ULL,
		0xAA962CD97D805706ULL,
		0x20655D95F3911225ULL,
		0xFED5C55F56047543ULL,
		0x7509E4BA04639718ULL,
		0xFCF8B7AF83528426ULL,
		0x3F0CB29B1A70AEA9ULL,
		0x6E62A85FED873A23ULL
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
		0x83F5F218BD4FDEF6ULL,
		0x4E331C8049C9CCC7ULL,
		0x6FDD89346B786BD2ULL,
		0x3ECDB2CE918C3ED4ULL,
		0x0EDBEA798894077BULL,
		0xF67707760473D1C0ULL,
		0xCE4BF7432AA0B898ULL,
		0x06AD235D39D83557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EBE4317A9FBDECULL,
		0x9C6639009393998FULL,
		0xDFBB1268D6F0D7A4ULL,
		0x7D9B659D23187DA8ULL,
		0x1DB7D4F311280EF6ULL,
		0xECEE0EEC08E7A380ULL,
		0x9C97EE8655417131ULL,
		0x0D5A46BA73B06AAFULL
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
		0x1C4C68625F0BA3CCULL,
		0x0DF572B10491E62FULL,
		0xB352C60C4A113100ULL,
		0xF270A2915B0D0B47ULL,
		0xB2D3220E125CE53CULL,
		0x0739C03280BCE114ULL,
		0xAD3FC211B46BF15DULL,
		0x0DEA3365160DF770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3898D0C4BE174798ULL,
		0x1BEAE5620923CC5EULL,
		0x66A58C1894226200ULL,
		0xE4E14522B61A168FULL,
		0x65A6441C24B9CA79ULL,
		0x0E7380650179C229ULL,
		0x5A7F842368D7E2BAULL,
		0x1BD466CA2C1BEEE1ULL
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
		0x2BB4EEA80F2694DEULL,
		0x74B5A3D421284655ULL,
		0x8527D666365BF533ULL,
		0xD801CBDB2E3FA123ULL,
		0xAFA734EB122C3B09ULL,
		0xE007DE828B66DE11ULL,
		0x0F9356822AE72B71ULL,
		0x2A2A003887432EA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5769DD501E4D29BCULL,
		0xE96B47A842508CAAULL,
		0x0A4FACCC6CB7EA66ULL,
		0xB00397B65C7F4247ULL,
		0x5F4E69D624587613ULL,
		0xC00FBD0516CDBC23ULL,
		0x1F26AD0455CE56E3ULL,
		0x545400710E865D52ULL
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
		0x964D881D89CBDBE9ULL,
		0x8E9AA4E4BEE93240ULL,
		0x815052B928023125ULL,
		0x13E76FD39E3B6903ULL,
		0xE68E2AD8F2D0EE7AULL,
		0x12F7515BFF48498EULL,
		0xA265C56C81A4D8E6ULL,
		0x24B774065E63ACFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C9B103B1397B7D2ULL,
		0x1D3549C97DD26481ULL,
		0x02A0A5725004624BULL,
		0x27CEDFA73C76D207ULL,
		0xCD1C55B1E5A1DCF4ULL,
		0x25EEA2B7FE90931DULL,
		0x44CB8AD90349B1CCULL,
		0x496EE80CBCC759FDULL
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
		0x6064038294F429C0ULL,
		0x51D92685D2E93B1EULL,
		0xD1F54EF85239386AULL,
		0x4F74240829DBFE1BULL,
		0xD008EB03B8F6A477ULL,
		0x06C3813F20F2C68AULL,
		0xE08637CB69749054ULL,
		0x00FED51C1CCBFFD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C8070529E85380ULL,
		0xA3B24D0BA5D2763CULL,
		0xA3EA9DF0A47270D4ULL,
		0x9EE8481053B7FC37ULL,
		0xA011D60771ED48EEULL,
		0x0D87027E41E58D15ULL,
		0xC10C6F96D2E920A8ULL,
		0x01FDAA383997FFA3ULL
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
		0xE635590052CB5B82ULL,
		0x5FFDD4FE53E63216ULL,
		0xC8F6AF583882D324ULL,
		0x06AD763ACBE342AAULL,
		0x4AB6A952D613A1EDULL,
		0xB7938E07347D2F85ULL,
		0x9DC427FBE4ADCA28ULL,
		0x049F126BA42DDD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6AB200A596B704ULL,
		0xBFFBA9FCA7CC642DULL,
		0x91ED5EB07105A648ULL,
		0x0D5AEC7597C68555ULL,
		0x956D52A5AC2743DAULL,
		0x6F271C0E68FA5F0AULL,
		0x3B884FF7C95B9451ULL,
		0x093E24D7485BBA97ULL
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
		0x17DD9DA28EFB91DCULL,
		0xA5797F991DD83DD3ULL,
		0xB8963C4CEFDDDCEBULL,
		0xEBB283D7F56AB7B3ULL,
		0xF579FE6040DF8360ULL,
		0x32D26D7C1FAEC6C2ULL,
		0x42A86446D14151C6ULL,
		0x07FC48CFA93709F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FBB3B451DF723B8ULL,
		0x4AF2FF323BB07BA6ULL,
		0x712C7899DFBBB9D7ULL,
		0xD76507AFEAD56F67ULL,
		0xEAF3FCC081BF06C1ULL,
		0x65A4DAF83F5D8D85ULL,
		0x8550C88DA282A38CULL,
		0x0FF8919F526E13EEULL
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
		0x35FACEB45633AC13ULL,
		0xFF7FA8EBA1307EE9ULL,
		0x3A13FA4A0BC9B8F1ULL,
		0xCC8F40DBA4B8E64CULL,
		0xDDF4F470271AB7EFULL,
		0x2B95290A75D6C280ULL,
		0x316BB34CF66CD7B3ULL,
		0x30DBA25F2AE83339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF59D68AC675826ULL,
		0xFEFF51D74260FDD2ULL,
		0x7427F494179371E3ULL,
		0x991E81B74971CC98ULL,
		0xBBE9E8E04E356FDFULL,
		0x572A5214EBAD8501ULL,
		0x62D76699ECD9AF66ULL,
		0x61B744BE55D06672ULL
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
		0xFB39902EAA25DCEAULL,
		0x0B99283555A4253CULL,
		0xA4F765B731D56493ULL,
		0x70FE51392443E49EULL,
		0x79E6E785F0209268ULL,
		0x1B0687F647145AC4ULL,
		0x713BF1D34F880511ULL,
		0x39B54958D3EB1E56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF673205D544BB9D4ULL,
		0x1732506AAB484A79ULL,
		0x49EECB6E63AAC926ULL,
		0xE1FCA2724887C93DULL,
		0xF3CDCF0BE04124D0ULL,
		0x360D0FEC8E28B588ULL,
		0xE277E3A69F100A22ULL,
		0x736A92B1A7D63CACULL
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
		0x424DD1FA3D9547ECULL,
		0x69975B238C4462F3ULL,
		0xD9476848EE475BE0ULL,
		0x935A60A0B6F4AFB5ULL,
		0x830DB519512F8BBAULL,
		0xD3CDE7C94C8D3E3FULL,
		0x4085B53FDACA8B04ULL,
		0x2DDD483A0BB5FAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849BA3F47B2A8FD8ULL,
		0xD32EB6471888C5E6ULL,
		0xB28ED091DC8EB7C0ULL,
		0x26B4C1416DE95F6BULL,
		0x061B6A32A25F1775ULL,
		0xA79BCF92991A7C7FULL,
		0x810B6A7FB5951609ULL,
		0x5BBA9074176BF5A8ULL
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
		0xCBCFA608813CAB9AULL,
		0x546B6AE926779BC2ULL,
		0xD0491C466B5C00E3ULL,
		0xC956F62D19C8AD6AULL,
		0xDCDCF000CA4D408FULL,
		0xF7F01334137F108BULL,
		0xA02AABF6966F9F78ULL,
		0x16E2123D913322F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979F4C1102795734ULL,
		0xA8D6D5D24CEF3785ULL,
		0xA092388CD6B801C6ULL,
		0x92ADEC5A33915AD5ULL,
		0xB9B9E001949A811FULL,
		0xEFE0266826FE2117ULL,
		0x405557ED2CDF3EF1ULL,
		0x2DC4247B226645E7ULL
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
		0xC36FE12899233408ULL,
		0x68863DB55D5BC986ULL,
		0xAEC7F3748A9865F2ULL,
		0x442C5E60C02D30C8ULL,
		0x843E09753DA9CC4AULL,
		0x262B385D51292FC6ULL,
		0x869856E24CE5BB48ULL,
		0x3DAF97DF832A885CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86DFC25132466810ULL,
		0xD10C7B6ABAB7930DULL,
		0x5D8FE6E91530CBE4ULL,
		0x8858BCC1805A6191ULL,
		0x087C12EA7B539894ULL,
		0x4C5670BAA2525F8DULL,
		0x0D30ADC499CB7690ULL,
		0x7B5F2FBF065510B9ULL
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
		0xD0FD53CAD8C27A6BULL,
		0x94DEC6A277C0FB6DULL,
		0xDA4C890F547303ABULL,
		0x984B092C40F1C6A5ULL,
		0xD1D377D3DB346B26ULL,
		0xB18269D7010920B9ULL,
		0xE3ED7149F8FD1523ULL,
		0x17F9EE85091765A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1FAA795B184F4D6ULL,
		0x29BD8D44EF81F6DBULL,
		0xB499121EA8E60757ULL,
		0x3096125881E38D4BULL,
		0xA3A6EFA7B668D64DULL,
		0x6304D3AE02124173ULL,
		0xC7DAE293F1FA2A47ULL,
		0x2FF3DD0A122ECB4DULL
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
		0x7A3820F78C5FEEB5ULL,
		0x428C549455F93887ULL,
		0x40B2147B64CC2FC5ULL,
		0xD26F7E5671C9E961ULL,
		0x278B82896E4DBD0CULL,
		0x0285B03271585A96ULL,
		0x16E7A4AC144291BEULL,
		0x25FA68DE3DD908F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF47041EF18BFDD6AULL,
		0x8518A928ABF2710EULL,
		0x816428F6C9985F8AULL,
		0xA4DEFCACE393D2C2ULL,
		0x4F170512DC9B7A19ULL,
		0x050B6064E2B0B52CULL,
		0x2DCF49582885237CULL,
		0x4BF4D1BC7BB211E0ULL
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
		0x56785BA1EF31FF82ULL,
		0x684943643B0E08D4ULL,
		0x78CF110464D01150ULL,
		0x992EB9F40C2D00D1ULL,
		0x7E5ED0F6150BD385ULL,
		0x686092E9ACD9D7D2ULL,
		0x8720C4CF33618324ULL,
		0x27E0851D51EB38D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF0B743DE63FF04ULL,
		0xD09286C8761C11A8ULL,
		0xF19E2208C9A022A0ULL,
		0x325D73E8185A01A2ULL,
		0xFCBDA1EC2A17A70BULL,
		0xD0C125D359B3AFA4ULL,
		0x0E41899E66C30648ULL,
		0x4FC10A3AA3D671A3ULL
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
		0xADA23704A09DF044ULL,
		0x53C7F454FDAB749FULL,
		0x165D2FB10767B296ULL,
		0x2AD36ABDF4414816ULL,
		0xFDC47B30332F0C49ULL,
		0xD38EAA9DF5933B2CULL,
		0xF90EAAFDB80C15A8ULL,
		0x3B8BCB6AACA1CCA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B446E09413BE088ULL,
		0xA78FE8A9FB56E93FULL,
		0x2CBA5F620ECF652CULL,
		0x55A6D57BE882902CULL,
		0xFB88F660665E1892ULL,
		0xA71D553BEB267659ULL,
		0xF21D55FB70182B51ULL,
		0x771796D55943994FULL
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
		0xB84DE0E953EEB5CBULL,
		0x2C6DA5B88502295DULL,
		0x06D9C46BF2F2A13EULL,
		0xCDB47B32192838AAULL,
		0xDC9B84A843DA4A96ULL,
		0x75B8375B1DC5FB67ULL,
		0x67576FC893161A57ULL,
		0x29B096CDF86FAECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x709BC1D2A7DD6B96ULL,
		0x58DB4B710A0452BBULL,
		0x0DB388D7E5E5427CULL,
		0x9B68F66432507154ULL,
		0xB937095087B4952DULL,
		0xEB706EB63B8BF6CFULL,
		0xCEAEDF91262C34AEULL,
		0x53612D9BF0DF5D9EULL
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
		0x3657D011BFAC15B5ULL,
		0x3CFD5F188B8C42C7ULL,
		0x316623981C814008ULL,
		0xC8641DA2D924BADDULL,
		0xFA89318E5ADF91DAULL,
		0x664612E5F77F8CD8ULL,
		0x4D3BEE04033B4152ULL,
		0x1948D340E2A8262AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CAFA0237F582B6AULL,
		0x79FABE311718858EULL,
		0x62CC473039028010ULL,
		0x90C83B45B24975BAULL,
		0xF512631CB5BF23B5ULL,
		0xCC8C25CBEEFF19B1ULL,
		0x9A77DC08067682A4ULL,
		0x3291A681C5504C54ULL
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
		0x9526E74BFD270F9EULL,
		0x667002FDC0932A2FULL,
		0x6A3155C7C3C2E698ULL,
		0x1CC04AACBD722DBDULL,
		0xCEB59990BA8BBF49ULL,
		0x1EC7FB4E0502E616ULL,
		0xAA3955D1BD75E592ULL,
		0x3A8D9C4C20E7898BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A4DCE97FA4E1F3CULL,
		0xCCE005FB8126545FULL,
		0xD462AB8F8785CD30ULL,
		0x398095597AE45B7AULL,
		0x9D6B332175177E92ULL,
		0x3D8FF69C0A05CC2DULL,
		0x5472ABA37AEBCB24ULL,
		0x751B389841CF1317ULL
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
		0x06DB548D28BDE334ULL,
		0xF001204A7F80F8EFULL,
		0x948CDC18692F571AULL,
		0x51B3850704C8161CULL,
		0xEA88B888C434C359ULL,
		0xE7A5E0FCC7BAAEB5ULL,
		0x4BC807FB85F4C7E0ULL,
		0x055B1E4D3253C5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DB6A91A517BC668ULL,
		0xE0024094FF01F1DEULL,
		0x2919B830D25EAE35ULL,
		0xA3670A0E09902C39ULL,
		0xD5117111886986B2ULL,
		0xCF4BC1F98F755D6BULL,
		0x97900FF70BE98FC1ULL,
		0x0AB63C9A64A78BA0ULL
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
		0x82F33C836A446ACBULL,
		0x8EA7549D4A67CF04ULL,
		0xCC56BD3422AD5D45ULL,
		0xD94864FCD2F9F24CULL,
		0xA1036B67BF86F927ULL,
		0x4162977DC26FFAC0ULL,
		0x2F360A25A324BA72ULL,
		0x21B7565A0AE7E732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05E67906D488D596ULL,
		0x1D4EA93A94CF9E09ULL,
		0x98AD7A68455ABA8BULL,
		0xB290C9F9A5F3E499ULL,
		0x4206D6CF7F0DF24FULL,
		0x82C52EFB84DFF581ULL,
		0x5E6C144B464974E4ULL,
		0x436EACB415CFCE64ULL
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
		0x6FCFCE9A407624EBULL,
		0x0FA5A5E2B6A284D3ULL,
		0xD6C77AAB08AA0AD9ULL,
		0xDABC11040B063E75ULL,
		0x92F5689439157C2DULL,
		0xA680C45A3D6221B8ULL,
		0xE31899982AC40B96ULL,
		0x0CA94C975EC83AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF9F9D3480EC49D6ULL,
		0x1F4B4BC56D4509A6ULL,
		0xAD8EF556115415B2ULL,
		0xB5782208160C7CEBULL,
		0x25EAD128722AF85BULL,
		0x4D0188B47AC44371ULL,
		0xC63133305588172DULL,
		0x1952992EBD90754BULL
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
		0xE80D179469A764F8ULL,
		0xBC917A25E8592EDCULL,
		0xEDA63BF2543027FFULL,
		0x2E48DB4E9595D8D9ULL,
		0xD28D4EB4A03F4D11ULL,
		0xB08034F2FA517A4EULL,
		0xB1EA4A90D39C190CULL,
		0x26C0C30C9F824EF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD01A2F28D34EC9F0ULL,
		0x7922F44BD0B25DB9ULL,
		0xDB4C77E4A8604FFFULL,
		0x5C91B69D2B2BB1B3ULL,
		0xA51A9D69407E9A22ULL,
		0x610069E5F4A2F49DULL,
		0x63D49521A7383219ULL,
		0x4D8186193F049DE7ULL
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
		0xC4BAA8298E170097ULL,
		0xEE3CCC4B5CCF799EULL,
		0xF3208085C6F70EEAULL,
		0xA19C19444C5A71BAULL,
		0x8DC690F9F077DF42ULL,
		0xC055E7C2ECC77450ULL,
		0xD5AD70BC79308648ULL,
		0x3917E7474DE1A930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897550531C2E012EULL,
		0xDC799896B99EF33DULL,
		0xE641010B8DEE1DD5ULL,
		0x4338328898B4E375ULL,
		0x1B8D21F3E0EFBE85ULL,
		0x80ABCF85D98EE8A1ULL,
		0xAB5AE178F2610C91ULL,
		0x722FCE8E9BC35261ULL
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
		0xC42A68C2335D09E2ULL,
		0x2A24E8E5CDCC8F16ULL,
		0x15F585B30610BE09ULL,
		0x6E3634EBA57AC8E0ULL,
		0xA0BC79CF918A950FULL,
		0x45D00A7A0278DCEBULL,
		0x15A0F73D967C756DULL,
		0x16283A78D3CCE9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8854D18466BA13C4ULL,
		0x5449D1CB9B991E2DULL,
		0x2BEB0B660C217C12ULL,
		0xDC6C69D74AF591C0ULL,
		0x4178F39F23152A1EULL,
		0x8BA014F404F1B9D7ULL,
		0x2B41EE7B2CF8EADAULL,
		0x2C5074F1A799D38EULL
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
		0x2EF99407B06D5020ULL,
		0x2AEF4BDB4E14263DULL,
		0x3CC24EEAAE5B053DULL,
		0x26419F227A6C6B61ULL,
		0xCCF07672FFA464F2ULL,
		0x3E3CFF85CFF1200AULL,
		0x5B002BEE4254361EULL,
		0x1C512399C5A4DE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DF3280F60DAA040ULL,
		0x55DE97B69C284C7AULL,
		0x79849DD55CB60A7AULL,
		0x4C833E44F4D8D6C2ULL,
		0x99E0ECE5FF48C9E4ULL,
		0x7C79FF0B9FE24015ULL,
		0xB60057DC84A86C3CULL,
		0x38A247338B49BC82ULL
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
		0xB064A60C80F92639ULL,
		0x8C75B910EBE3BE69ULL,
		0x633D7027C12F6F78ULL,
		0xBBD99550E5D05415ULL,
		0xE06D0F5942F08001ULL,
		0x0814E42059008C97ULL,
		0xF2C35832733A5042ULL,
		0x25562DD57553F586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C94C1901F24C72ULL,
		0x18EB7221D7C77CD3ULL,
		0xC67AE04F825EDEF1ULL,
		0x77B32AA1CBA0A82AULL,
		0xC0DA1EB285E10003ULL,
		0x1029C840B201192FULL,
		0xE586B064E674A084ULL,
		0x4AAC5BAAEAA7EB0DULL
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
		0x3740B8D508454F79ULL,
		0x58A3493283B23368ULL,
		0xD2EEEB77ACACAFE1ULL,
		0x37AE2526F3296C11ULL,
		0x41464967C88AB2CAULL,
		0x49F770511039ECC8ULL,
		0x0911AFCBB455E671ULL,
		0x3712EB7FD025E541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E8171AA108A9EF2ULL,
		0xB1469265076466D0ULL,
		0xA5DDD6EF59595FC2ULL,
		0x6F5C4A4DE652D823ULL,
		0x828C92CF91156594ULL,
		0x93EEE0A22073D990ULL,
		0x12235F9768ABCCE2ULL,
		0x6E25D6FFA04BCA82ULL
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
		0x85F18E83713A0D41ULL,
		0x03452CA8F9E17541ULL,
		0x43F1C2DB7D16F3D8ULL,
		0x51FB6F55DE734642ULL,
		0x7F31C68D6FE2956FULL,
		0xC766455E2D59A9C7ULL,
		0x230201D00DC08EE0ULL,
		0x0E9EC00797618F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE31D06E2741A82ULL,
		0x068A5951F3C2EA83ULL,
		0x87E385B6FA2DE7B0ULL,
		0xA3F6DEABBCE68C84ULL,
		0xFE638D1ADFC52ADEULL,
		0x8ECC8ABC5AB3538EULL,
		0x460403A01B811DC1ULL,
		0x1D3D800F2EC31E80ULL
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
		0x909D500F68C569EDULL,
		0xD715A3691E0D7625ULL,
		0xE1EFFA73D7E4565BULL,
		0xA5D9C312286A3873ULL,
		0x159F47EDBE4CAEF3ULL,
		0x93C26A13B51A3670ULL,
		0x6339DAB92CB62342ULL,
		0x2864233157E79D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213AA01ED18AD3DAULL,
		0xAE2B46D23C1AEC4BULL,
		0xC3DFF4E7AFC8ACB7ULL,
		0x4BB3862450D470E7ULL,
		0x2B3E8FDB7C995DE7ULL,
		0x2784D4276A346CE0ULL,
		0xC673B572596C4685ULL,
		0x50C84662AFCF3AB0ULL
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
		0x7E9D3766E7833C95ULL,
		0x8B07F3116E301CBEULL,
		0xA59A4E19E2411E8EULL,
		0xC924C08AC1F332A0ULL,
		0xBC1096B899C02AD2ULL,
		0xF3CEDD424F92DC46ULL,
		0x12DCE38A4DA10BF2ULL,
		0x11744CB6E93B4C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD3A6ECDCF06792AULL,
		0x160FE622DC60397CULL,
		0x4B349C33C4823D1DULL,
		0x9249811583E66541ULL,
		0x78212D71338055A5ULL,
		0xE79DBA849F25B88DULL,
		0x25B9C7149B4217E5ULL,
		0x22E8996DD2769870ULL
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
		0xF358CD1E11908336ULL,
		0x09E297D55E9CD45CULL,
		0x7A9B44A4B41DAF8BULL,
		0x0674E05325F7902CULL,
		0xC1DD26DB73E33AF2ULL,
		0xA53FF1FB08FA4BE1ULL,
		0xD9491CFEDCFBD467ULL,
		0x2C3D51D20B9E540AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B19A3C2321066CULL,
		0x13C52FAABD39A8B9ULL,
		0xF5368949683B5F16ULL,
		0x0CE9C0A64BEF2058ULL,
		0x83BA4DB6E7C675E4ULL,
		0x4A7FE3F611F497C3ULL,
		0xB29239FDB9F7A8CFULL,
		0x587AA3A4173CA815ULL
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
		0x63B87EBF13444CC7ULL,
		0x317C51B3DD71B180ULL,
		0xF3899E0693641C9EULL,
		0x36F0ECD132BC42A5ULL,
		0x40E70909379926BEULL,
		0x1F29A08B3A879D90ULL,
		0xBEB8A0A9E952C271ULL,
		0x398DB9E30629CF20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC770FD7E2688998EULL,
		0x62F8A367BAE36300ULL,
		0xE7133C0D26C8393CULL,
		0x6DE1D9A26578854BULL,
		0x81CE12126F324D7CULL,
		0x3E534116750F3B20ULL,
		0x7D714153D2A584E2ULL,
		0x731B73C60C539E41ULL
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
		0xB7C3CF937DEB4BCDULL,
		0x595092BC417C01FEULL,
		0x4AE61847B0C31E58ULL,
		0xAA7FC09E07DA031BULL,
		0x1644DCB30E712A78ULL,
		0x0C5F80FEC0BA077BULL,
		0xA844CA113C8AF8CAULL,
		0x1CC712140BF83BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F879F26FBD6979AULL,
		0xB2A1257882F803FDULL,
		0x95CC308F61863CB0ULL,
		0x54FF813C0FB40636ULL,
		0x2C89B9661CE254F1ULL,
		0x18BF01FD81740EF6ULL,
		0x508994227915F194ULL,
		0x398E242817F077C1ULL
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
		0x0389EA45417B1D14ULL,
		0xCCF130E613904DB5ULL,
		0x109E0B4A234C5DFDULL,
		0xF26898F52FF8104BULL,
		0x3C73923A5F7795FFULL,
		0x9EE0C66D807BADF9ULL,
		0x5FF552006DAB8465ULL,
		0x108BF69933713309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0713D48A82F63A28ULL,
		0x99E261CC27209B6AULL,
		0x213C16944698BBFBULL,
		0xE4D131EA5FF02096ULL,
		0x78E72474BEEF2BFFULL,
		0x3DC18CDB00F75BF2ULL,
		0xBFEAA400DB5708CBULL,
		0x2117ED3266E26612ULL
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
		0x7D90DC4A896E40A1ULL,
		0x05FC505A237539F2ULL,
		0x844FF16F2EDE63A3ULL,
		0x543D46FCF8E9FA59ULL,
		0xB6903920CD0DAF14ULL,
		0xC3FB52E0DDE866E2ULL,
		0xF174C385C104433EULL,
		0x0FC6168867BAF560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB21B89512DC8142ULL,
		0x0BF8A0B446EA73E4ULL,
		0x089FE2DE5DBCC746ULL,
		0xA87A8DF9F1D3F4B3ULL,
		0x6D2072419A1B5E28ULL,
		0x87F6A5C1BBD0CDC5ULL,
		0xE2E9870B8208867DULL,
		0x1F8C2D10CF75EAC1ULL
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
		0xCF7B772D9BAE63E9ULL,
		0xB7BBAB23DABB2EA6ULL,
		0xAAC9D4FA25CDF390ULL,
		0xDCD79CD5437E6CAAULL,
		0x8AB52AB9C601AC41ULL,
		0xBB5C69F961382A24ULL,
		0xC9B05DAD60D2FC4BULL,
		0x0BF3EAE3642E4F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF6EE5B375CC7D2ULL,
		0x6F775647B5765D4DULL,
		0x5593A9F44B9BE721ULL,
		0xB9AF39AA86FCD955ULL,
		0x156A55738C035883ULL,
		0x76B8D3F2C2705449ULL,
		0x9360BB5AC1A5F897ULL,
		0x17E7D5C6C85C9EA9ULL
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
		0x10324AD3C5FE9A66ULL,
		0x6548B62D2A8005FFULL,
		0xB8B9830192DA6C21ULL,
		0x03951AD7D18C695EULL,
		0x9AA6548C0D5B0D1DULL,
		0x680B5C18E10164F3ULL,
		0xB5728BFCD087D221ULL,
		0x1E37EE23FC965F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206495A78BFD34CCULL,
		0xCA916C5A55000BFEULL,
		0x7173060325B4D842ULL,
		0x072A35AFA318D2BDULL,
		0x354CA9181AB61A3AULL,
		0xD016B831C202C9E7ULL,
		0x6AE517F9A10FA442ULL,
		0x3C6FDC47F92CBEB5ULL
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
		0x42DD842692EAADC6ULL,
		0x430EC30F0BA8AFB7ULL,
		0x2E4252CC91E80951ULL,
		0x4CA5DC6D8EA91775ULL,
		0x6A3DAB048BB0E15CULL,
		0x48429DF0A98FF268ULL,
		0xC906E36DA6DC6E01ULL,
		0x03774DD75793DC2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85BB084D25D55B8CULL,
		0x861D861E17515F6EULL,
		0x5C84A59923D012A2ULL,
		0x994BB8DB1D522EEAULL,
		0xD47B56091761C2B8ULL,
		0x90853BE1531FE4D0ULL,
		0x920DC6DB4DB8DC02ULL,
		0x06EE9BAEAF27B859ULL
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
		0xE63706A3F7DCEAD9ULL,
		0x525FC463E1ADD46EULL,
		0x682AFA602AC899E3ULL,
		0x885C4B933E21385FULL,
		0x61D0B0E0CD7CD7A2ULL,
		0x60D016371C981421ULL,
		0x5698A6C98DD6455AULL,
		0x180C394072BF28C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6E0D47EFB9D5B2ULL,
		0xA4BF88C7C35BA8DDULL,
		0xD055F4C0559133C6ULL,
		0x10B897267C4270BEULL,
		0xC3A161C19AF9AF45ULL,
		0xC1A02C6E39302842ULL,
		0xAD314D931BAC8AB4ULL,
		0x30187280E57E5182ULL
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
		0x841B882209B7A1F2ULL,
		0x635F3B5B819F7BB7ULL,
		0x325E67C401DC1E47ULL,
		0xCEC681DE99E90778ULL,
		0x2975BE2840350671ULL,
		0x2BB990F969D7E964ULL,
		0xD3524BBA7D925C40ULL,
		0x2AF2E75FF272528EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08371044136F43E4ULL,
		0xC6BE76B7033EF76FULL,
		0x64BCCF8803B83C8EULL,
		0x9D8D03BD33D20EF0ULL,
		0x52EB7C50806A0CE3ULL,
		0x577321F2D3AFD2C8ULL,
		0xA6A49774FB24B880ULL,
		0x55E5CEBFE4E4A51DULL
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
		0x7188F67F88A7D080ULL,
		0xC8FB8A44C293B4D3ULL,
		0x4936FD9F73A5EEF2ULL,
		0x99C8DDF96A6A3AE4ULL,
		0xDB87FD179968E3DEULL,
		0xBD414F5C0A7DD9D3ULL,
		0x1591C3173A5EA492ULL,
		0x129B987CF5168F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE311ECFF114FA100ULL,
		0x91F71489852769A6ULL,
		0x926DFB3EE74BDDE5ULL,
		0x3391BBF2D4D475C8ULL,
		0xB70FFA2F32D1C7BDULL,
		0x7A829EB814FBB3A7ULL,
		0x2B23862E74BD4925ULL,
		0x253730F9EA2D1E08ULL
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
		0x19B8F01213F3CB7DULL,
		0x08A067F575EE94B6ULL,
		0x4ED02BC2AAFF703FULL,
		0x5B37A2B72164D935ULL,
		0xD855BCACE2F54AAEULL,
		0x5AFC30E62169A002ULL,
		0xB38B0A40DA1C447CULL,
		0x13A56142EA8E687BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3371E02427E796FAULL,
		0x1140CFEAEBDD296CULL,
		0x9DA0578555FEE07EULL,
		0xB66F456E42C9B26AULL,
		0xB0AB7959C5EA955CULL,
		0xB5F861CC42D34005ULL,
		0x67161481B43888F8ULL,
		0x274AC285D51CD0F7ULL
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
		0xE1B9A96D365E4D8AULL,
		0xD0EAE894AC64756AULL,
		0x894190806654D1BFULL,
		0x127D3298AB1D2788ULL,
		0x574BB8293CC1C2F8ULL,
		0x215B393BD9EEC8D1ULL,
		0x28ADF5AC1E263A76ULL,
		0x39937E99C3DEF5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC37352DA6CBC9B14ULL,
		0xA1D5D12958C8EAD5ULL,
		0x12832100CCA9A37FULL,
		0x24FA6531563A4F11ULL,
		0xAE977052798385F0ULL,
		0x42B67277B3DD91A2ULL,
		0x515BEB583C4C74ECULL,
		0x7326FD3387BDEBA6ULL
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
		0xC26267C7581A6577ULL,
		0xF2EEC30569463F31ULL,
		0xB18252B21CCACD48ULL,
		0xFE673EBAE36D1683ULL,
		0xD7B982FF8999906FULL,
		0x6C695BB0A02D53F9ULL,
		0x8CBC06ADF68AA4DBULL,
		0x38A8CD32226176B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C4CF8EB034CAEEULL,
		0xE5DD860AD28C7E63ULL,
		0x6304A56439959A91ULL,
		0xFCCE7D75C6DA2D07ULL,
		0xAF7305FF133320DFULL,
		0xD8D2B761405AA7F3ULL,
		0x19780D5BED1549B6ULL,
		0x71519A6444C2ED71ULL
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
		0x28FC685BB99AE578ULL,
		0x70D4F8A0B18B6026ULL,
		0xACA3B5E7DD1422B0ULL,
		0xAB8F140416CDA043ULL,
		0xA41F6DCB5DCD3427ULL,
		0x6526E8082ABDAB85ULL,
		0x5E0A76499D3FE7DCULL,
		0x3D6CA49C50309B50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51F8D0B77335CAF0ULL,
		0xE1A9F1416316C04CULL,
		0x59476BCFBA284560ULL,
		0x571E28082D9B4087ULL,
		0x483EDB96BB9A684FULL,
		0xCA4DD010557B570BULL,
		0xBC14EC933A7FCFB8ULL,
		0x7AD94938A06136A0ULL
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
		0x5B3F6230387435D4ULL,
		0x35456DCF047839BAULL,
		0xC8C05E9483EF5804ULL,
		0x0A5B4D850D004E19ULL,
		0xB6C05100395AAC74ULL,
		0x8195762955533C0EULL,
		0xC291FF94A7B5AAD6ULL,
		0x14EDFE9C901596D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67EC46070E86BA8ULL,
		0x6A8ADB9E08F07374ULL,
		0x9180BD2907DEB008ULL,
		0x14B69B0A1A009C33ULL,
		0x6D80A20072B558E8ULL,
		0x032AEC52AAA6781DULL,
		0x8523FF294F6B55ADULL,
		0x29DBFD39202B2DADULL
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
		0x53712255923644FAULL,
		0x0DFD0F72C80BB8E1ULL,
		0x150156EF4ACDA35CULL,
		0xF16E944A87F4C216ULL,
		0xD05A733BBB05F088ULL,
		0x71D9222BF8962C36ULL,
		0xDB63689238D1B1D1ULL,
		0x367B6C37F31A2405ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E244AB246C89F4ULL,
		0x1BFA1EE5901771C2ULL,
		0x2A02ADDE959B46B8ULL,
		0xE2DD28950FE9842CULL,
		0xA0B4E677760BE111ULL,
		0xE3B24457F12C586DULL,
		0xB6C6D12471A363A2ULL,
		0x6CF6D86FE634480BULL
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
		0x72BA7DC1614A60A6ULL,
		0x37DC8CC57A0EBB36ULL,
		0x2255D589D03B80ACULL,
		0x89CA31AD351EE46FULL,
		0xDA2E2BF991D3403DULL,
		0xA5524D64C16DE460ULL,
		0x5A8F4B18325406BCULL,
		0x0AE954018FDAFCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE574FB82C294C14CULL,
		0x6FB9198AF41D766CULL,
		0x44ABAB13A0770158ULL,
		0x1394635A6A3DC8DEULL,
		0xB45C57F323A6807BULL,
		0x4AA49AC982DBC8C1ULL,
		0xB51E963064A80D79ULL,
		0x15D2A8031FB5F960ULL
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
		0xF8BFFD1548415419ULL,
		0xE8C758D119EC2FAFULL,
		0x53B7344EC4BB732AULL,
		0xFB7A3F8DD77CCF8FULL,
		0x104C8A13894CFC74ULL,
		0xC4F868D895608486ULL,
		0x0094DF226787E4D2ULL,
		0x11C57EE679707689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17FFA2A9082A832ULL,
		0xD18EB1A233D85F5FULL,
		0xA76E689D8976E655ULL,
		0xF6F47F1BAEF99F1EULL,
		0x209914271299F8E9ULL,
		0x89F0D1B12AC1090CULL,
		0x0129BE44CF0FC9A5ULL,
		0x238AFDCCF2E0ED12ULL
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
		0xEC06D9AE17889B4AULL,
		0x66F72A154A79E4F8ULL,
		0xA1CDA0DA4683A871ULL,
		0x0F2950B92CE7D281ULL,
		0x93D1A447958706DDULL,
		0x0ADAA24639276882ULL,
		0xBD7A6CFF79E07CCEULL,
		0x3F3A873885B7436BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80DB35C2F113694ULL,
		0xCDEE542A94F3C9F1ULL,
		0x439B41B48D0750E2ULL,
		0x1E52A17259CFA503ULL,
		0x27A3488F2B0E0DBAULL,
		0x15B5448C724ED105ULL,
		0x7AF4D9FEF3C0F99CULL,
		0x7E750E710B6E86D7ULL
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
		0x3E4CFA8B68644E2BULL,
		0xD7B5CD26A6A26814ULL,
		0x61732D466C94BA7DULL,
		0x28ADE1C093AA518AULL,
		0x8664F01918369678ULL,
		0xC82AECCFBFA15AC1ULL,
		0xC67A861CA7A946DFULL,
		0x163D6AC92073C1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C99F516D0C89C56ULL,
		0xAF6B9A4D4D44D028ULL,
		0xC2E65A8CD92974FBULL,
		0x515BC3812754A314ULL,
		0x0CC9E032306D2CF0ULL,
		0x9055D99F7F42B583ULL,
		0x8CF50C394F528DBFULL,
		0x2C7AD59240E78361ULL
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
		0x744CB7D0CC70B6C0ULL,
		0xE1F997F934437139ULL,
		0xD920055C16C67382ULL,
		0xD0141AE8B5824A8AULL,
		0x2C252CB6157DE176ULL,
		0x4048B07590A337E5ULL,
		0x911A1E0E9EFB23FFULL,
		0x120D6987FF61A6F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8996FA198E16D80ULL,
		0xC3F32FF26886E272ULL,
		0xB2400AB82D8CE705ULL,
		0xA02835D16B049515ULL,
		0x584A596C2AFBC2EDULL,
		0x809160EB21466FCAULL,
		0x22343C1D3DF647FEULL,
		0x241AD30FFEC34DE1ULL
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
		0xB556171F9AEA2800ULL,
		0x5EBFDDB3D4AEF039ULL,
		0x6158D477961825BAULL,
		0xA89C43D5119003C6ULL,
		0x85D9049A41383A9DULL,
		0xC64CBAD9F5620CE4ULL,
		0x388783B320B666B3ULL,
		0x21FCA4C8697BBD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAC2E3F35D45000ULL,
		0xBD7FBB67A95DE073ULL,
		0xC2B1A8EF2C304B74ULL,
		0x513887AA2320078CULL,
		0x0BB209348270753BULL,
		0x8C9975B3EAC419C9ULL,
		0x710F0766416CCD67ULL,
		0x43F94990D2F77ABEULL
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
		0xDD4A2ECF325D7D87ULL,
		0xFCF534C568DDCB60ULL,
		0x6F716E46937E1168ULL,
		0xB12447F17BB6AD25ULL,
		0xEEA8898CC1B4495EULL,
		0xD9C6A05154712085ULL,
		0x16DE44A17FB0190FULL,
		0x2557ABE825A9E564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA945D9E64BAFB0EULL,
		0xF9EA698AD1BB96C1ULL,
		0xDEE2DC8D26FC22D1ULL,
		0x62488FE2F76D5A4AULL,
		0xDD511319836892BDULL,
		0xB38D40A2A8E2410BULL,
		0x2DBC8942FF60321FULL,
		0x4AAF57D04B53CAC8ULL
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
		0xB66C62C7EAAD4B71ULL,
		0xEC9B328771B77472ULL,
		0x593DB548756695A3ULL,
		0x1DDAC05D716EB5CEULL,
		0x6CF7C0C8A035AAD1ULL,
		0x4C15ED486C0BD8D3ULL,
		0x39D72853A4A97C92ULL,
		0x3614107D3489756CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD8C58FD55A96E2ULL,
		0xD936650EE36EE8E5ULL,
		0xB27B6A90EACD2B47ULL,
		0x3BB580BAE2DD6B9CULL,
		0xD9EF8191406B55A2ULL,
		0x982BDA90D817B1A6ULL,
		0x73AE50A74952F924ULL,
		0x6C2820FA6912EAD8ULL
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
		0xADC9A02186A6BD51ULL,
		0xEAA31EBDD759C76CULL,
		0x0B6BE85D25A9B8B6ULL,
		0xFB21DEBEC5F40FBDULL,
		0xE72A51E5690039E9ULL,
		0xB8524C809493C9E4ULL,
		0x4507965974ADECFEULL,
		0x3D58B08237F59180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9340430D4D7AA2ULL,
		0xD5463D7BAEB38ED9ULL,
		0x16D7D0BA4B53716DULL,
		0xF643BD7D8BE81F7AULL,
		0xCE54A3CAD20073D3ULL,
		0x70A49901292793C9ULL,
		0x8A0F2CB2E95BD9FDULL,
		0x7AB161046FEB2300ULL
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
		0x0815FD186CE05C1BULL,
		0x2090EE443A20389FULL,
		0xC2EAA2B0ACE36D5EULL,
		0x44D1492B16324FA5ULL,
		0x1B612DBCA72C6345ULL,
		0xBB2817A54EC9C60AULL,
		0x2C4959E1F4105A90ULL,
		0x1DC7AC1D4F209FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x102BFA30D9C0B836ULL,
		0x4121DC887440713EULL,
		0x85D5456159C6DABCULL,
		0x89A292562C649F4BULL,
		0x36C25B794E58C68AULL,
		0x76502F4A9D938C14ULL,
		0x5892B3C3E820B521ULL,
		0x3B8F583A9E413FE6ULL
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
		0xBFE82DD08A0C1B59ULL,
		0x1003A599AE90A3BFULL,
		0xE6FC8B81B54A6A50ULL,
		0xEFED9DABCD58A9D4ULL,
		0x6A460FA445AE262CULL,
		0x6FE90AB4BD92A78DULL,
		0x10B7CA7DC745EC04ULL,
		0x2F58D3F1DB4BA447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD05BA1141836B2ULL,
		0x20074B335D21477FULL,
		0xCDF917036A94D4A0ULL,
		0xDFDB3B579AB153A9ULL,
		0xD48C1F488B5C4C59ULL,
		0xDFD215697B254F1AULL,
		0x216F94FB8E8BD808ULL,
		0x5EB1A7E3B697488EULL
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
		0x72CDC91D25855A75ULL,
		0xFC32F22CDA6DCC63ULL,
		0x86B3B211E2FAE0C3ULL,
		0x338996BD8F19C784ULL,
		0x808B8176707C9FCAULL,
		0xDE13514D3D8F1B56ULL,
		0x2981CC0637ABE49BULL,
		0x1FBC7E35CFF89E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE59B923A4B0AB4EAULL,
		0xF865E459B4DB98C6ULL,
		0x0D676423C5F5C187ULL,
		0x67132D7B1E338F09ULL,
		0x011702ECE0F93F94ULL,
		0xBC26A29A7B1E36ADULL,
		0x5303980C6F57C937ULL,
		0x3F78FC6B9FF13D30ULL
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
		0x2B97ADC48345D3EEULL,
		0x1D50F16D408799B2ULL,
		0x1B4C0D2DD782A212ULL,
		0xCF75EA16607B2395ULL,
		0xEE948CC53C2738B0ULL,
		0x5B69DDAB7D555A3BULL,
		0x7DFF9027E6214017ULL,
		0x1851FD4A0EF8F788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x572F5B89068BA7DCULL,
		0x3AA1E2DA810F3364ULL,
		0x36981A5BAF054424ULL,
		0x9EEBD42CC0F6472AULL,
		0xDD29198A784E7161ULL,
		0xB6D3BB56FAAAB477ULL,
		0xFBFF204FCC42802EULL,
		0x30A3FA941DF1EF10ULL
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
		0x294102667467D46BULL,
		0xAA4A4F5C4168E14EULL,
		0xE9C6234CB7461FD5ULL,
		0xE6077F6105D45016ULL,
		0xE1B84D686608D2E6ULL,
		0x1D3E427AF450ADECULL,
		0xC891707EDD477B89ULL,
		0x04079BBA69E68D5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528204CCE8CFA8D6ULL,
		0x54949EB882D1C29CULL,
		0xD38C46996E8C3FABULL,
		0xCC0EFEC20BA8A02DULL,
		0xC3709AD0CC11A5CDULL,
		0x3A7C84F5E8A15BD9ULL,
		0x9122E0FDBA8EF712ULL,
		0x080F3774D3CD1AB9ULL
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
		0x44CEB7E6DCC54438ULL,
		0x8C7964C8B5657457ULL,
		0x018ABD8189112C4DULL,
		0x8EE51374B2D5089FULL,
		0x9368C74BCA26D651ULL,
		0xD0FFC83D2E227335ULL,
		0xB1BF3570998DCC3AULL,
		0x273BF0B28D85B594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899D6FCDB98A8870ULL,
		0x18F2C9916ACAE8AEULL,
		0x03157B031222589BULL,
		0x1DCA26E965AA113EULL,
		0x26D18E97944DACA3ULL,
		0xA1FF907A5C44E66BULL,
		0x637E6AE1331B9875ULL,
		0x4E77E1651B0B6B29ULL
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
		0x45987C1B94302453ULL,
		0x0FD58E336C8629FBULL,
		0x709428AE3E1C3D5AULL,
		0x5158A2ED0388F978ULL,
		0xE5F0451F9656808FULL,
		0x5F16DD1B2BD147A0ULL,
		0x58B1946834261A2AULL,
		0x02182E2F0AE2543BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B30F837286048A6ULL,
		0x1FAB1C66D90C53F6ULL,
		0xE128515C7C387AB4ULL,
		0xA2B145DA0711F2F0ULL,
		0xCBE08A3F2CAD011EULL,
		0xBE2DBA3657A28F41ULL,
		0xB16328D0684C3454ULL,
		0x04305C5E15C4A876ULL
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
		0x9ED1ECF473EE4060ULL,
		0xCC4F322EC165F7FFULL,
		0x072BB1D14D8BA5A0ULL,
		0xCC1FC39B3383D891ULL,
		0x6162359B147B2BD9ULL,
		0x465AF4E6CC4718E7ULL,
		0x5E509B82A88528CCULL,
		0x1BF176E11B8A37C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA3D9E8E7DC80C0ULL,
		0x989E645D82CBEFFFULL,
		0x0E5763A29B174B41ULL,
		0x983F87366707B122ULL,
		0xC2C46B3628F657B3ULL,
		0x8CB5E9CD988E31CEULL,
		0xBCA13705510A5198ULL,
		0x37E2EDC237146F80ULL
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
		0xC85D4350CDE0C5DAULL,
		0x383D9964D7742F09ULL,
		0xCDD7E9708EF05AD0ULL,
		0xF47E0C105F9D8E36ULL,
		0x98FADEBC1E9A2CD4ULL,
		0x27009EF3891146B4ULL,
		0xE8515A9D27ED4ABAULL,
		0x032664A96C715911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90BA86A19BC18BB4ULL,
		0x707B32C9AEE85E13ULL,
		0x9BAFD2E11DE0B5A0ULL,
		0xE8FC1820BF3B1C6DULL,
		0x31F5BD783D3459A9ULL,
		0x4E013DE712228D69ULL,
		0xD0A2B53A4FDA9574ULL,
		0x064CC952D8E2B223ULL
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
	return 0;
}