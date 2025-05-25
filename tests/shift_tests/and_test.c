#include "../tests.h"

int32_t curve25519_key_and_test(void) {
	printf("Key AND Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x4410940B1AC203C6ULL,
		0xF0119214B3F9E017ULL,
		0x138876B7A928A186ULL,
		0x5D08DC20D248DD50ULL,
		0x6C6207367185F75FULL,
		0x875994B3E5618C14ULL,
		0xF0615AC429283E6CULL,
		0x8449A9388D1A1B97ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x682D0DC1E32D591FULL,
		0x49267C269780824DULL,
		0x98588D5C76FBE128ULL,
		0xF396EAF36EF24F38ULL,
		0xBD348F213461A8A0ULL,
		0x78D9C7A9CAFD3DF4ULL,
		0x41A9709E155F307EULL,
		0x93142543C04E2284ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x4000040102000106ULL,
		0x4000100493808005ULL,
		0x100804142028A100ULL,
		0x5100C82042404D10ULL,
		0x2C2007203001A000ULL,
		0x005984A1C0610C14ULL,
		0x402150840108306CULL,
		0x80002100800A0284ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88A74D9C61DA4ECAULL,
		0xD52064EBA0F693DDULL,
		0x4056E08F240E5E8AULL,
		0x54780695FC34DB75ULL,
		0x90DDA740DF1BA779ULL,
		0x005155A6EFFF9E46ULL,
		0xE96DFB9AA41ADC4BULL,
		0xC5E54A95EEC0E510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C19695FB2DE957ULL,
		0xAEA78BFBA355590CULL,
		0xD6361129181E9BAAULL,
		0xAB42FC4D2C5909A4ULL,
		0x56664B7265915987ULL,
		0x59239D9059E4C2CBULL,
		0x51F1D386F1E1498BULL,
		0xEA9C8D92FA079211ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8881049461084842ULL,
		0x842000EBA054110CULL,
		0x40160009000E1A8AULL,
		0x004004052C100924ULL,
		0x1044034045110101ULL,
		0x0001158049E48242ULL,
		0x4161D382A000480BULL,
		0xC0840890EA008010ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x910C8958B3C19DCBULL,
		0x5E2B0FC84ED79CCCULL,
		0x3D2CB46EEBE98C59ULL,
		0x5A3DD5CA3098274FULL,
		0x43704B42F340F570ULL,
		0x97FEF43DE632D681ULL,
		0x6C701F92E9EFB147ULL,
		0xAD4238A74A0A724BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A6ECAB474DC37BULL,
		0x7FD9E2DA10CE05A2ULL,
		0x27D2D6506F50C9B8ULL,
		0x4637A9C1B4CFA764ULL,
		0xFD340BF902807361ULL,
		0xA7F7EC3E579021F5ULL,
		0x06DF395F09BBC90FULL,
		0xCD57B1C0DC247ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110488080341814BULL,
		0x5E0902C800C60480ULL,
		0x250094406B408818ULL,
		0x423581C030882744ULL,
		0x41300B4002007160ULL,
		0x87F6E43C46100081ULL,
		0x0450191209AB8107ULL,
		0x8D4230804800724BULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6044C1B75F1EE9BULL,
		0x1FED951236005EDBULL,
		0x4A97E02986980412ULL,
		0x22BC972DCD546B2EULL,
		0xCD4C85E02151D1A6ULL,
		0xC82560A2DDC3C983ULL,
		0x4560C494F15F542CULL,
		0x7E0DFD22D0CCDEE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A416554AAFE95CULL,
		0xD3EE3343F5CEEE18ULL,
		0x4D332EC2E85EF77EULL,
		0x2321423DE8653265ULL,
		0x24E2D7831C7F8233ULL,
		0xB4B33BC20A87E736ULL,
		0xC327F4F476C6AF29ULL,
		0xF526AFE597DF092FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2004041140A1E818ULL,
		0x13EC110234004E18ULL,
		0x4813200080180412ULL,
		0x2220022DC8442224ULL,
		0x0440858000518022ULL,
		0x802120820883C102ULL,
		0x4120C49470460428ULL,
		0x7404AD2090CC0822ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90B9208D5F262FB9ULL,
		0xEB0F654655F735FAULL,
		0xA2CC78605FAD0FF0ULL,
		0xBA09F688D9B47F8AULL,
		0x884232D1830C123FULL,
		0x32B2717DEBD6E39DULL,
		0xFBFBDA60243D2620ULL,
		0x0B7FA3ACFBE6492DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E120D80320BF10BULL,
		0x8936567F96A291B8ULL,
		0x9580FF26434009AFULL,
		0x133B60F5BC8A6667ULL,
		0xFBB9403854340E3DULL,
		0xB2AF850E0CCB5288ULL,
		0x8E1A7D8141F4360EULL,
		0xFDB17FC356A57025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1010008012022109ULL,
		0x8906444614A211B8ULL,
		0x80807820430009A0ULL,
		0x1209608098806602ULL,
		0x880000100004023DULL,
		0x32A2010C08C24288ULL,
		0x8A1A580000342600ULL,
		0x0931238052A44025ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB2BC14EE51D6979ULL,
		0xBB5F11F143D745DDULL,
		0xE006FDEC928342B1ULL,
		0x5A1DC03D41B486C4ULL,
		0x68A4BD8B34F73C92ULL,
		0x40FD3B59EFB5E8A7ULL,
		0xE89AB0D8CDBAB428ULL,
		0x68ED1E81F562DE27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5BC802169831CABULL,
		0xCF47E5F4706D9C3DULL,
		0x7CD93FCE5DF39746ULL,
		0xA88738ABA7FD61BDULL,
		0xD5B9CCC57C95BDF1ULL,
		0x0BDB748F021D2898ULL,
		0x3AFA51DD4E3A33CEULL,
		0x5353FFF379B5505AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8128800061010829ULL,
		0x8B4701F04045041DULL,
		0x60003DCC10830200ULL,
		0x0805002901B40084ULL,
		0x40A08C8134953C90ULL,
		0x00D9300902152880ULL,
		0x289A10D84C3A3008ULL,
		0x40411E8171205002ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF776942CA0548D90ULL,
		0x5B122D6C749021AEULL,
		0x94D67C667863D9EEULL,
		0x028F185FDAFFA2D4ULL,
		0x4548636C7BF7FE56ULL,
		0x8C041B179EDAAA9DULL,
		0x5A30E08E077C5F59ULL,
		0x73092BA950A3F2F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF10F64F727EFE652ULL,
		0x956FFD71B3F647A4ULL,
		0x9258AE02C18D59D3ULL,
		0xA2ECC39508004ED3ULL,
		0xA027513813E5F4E9ULL,
		0xDF548EF2F41B8BEEULL,
		0xB9128BBE2EE53755ULL,
		0xFECBF4D8B747C650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF106042420448410ULL,
		0x11022D60309001A4ULL,
		0x90502C02400159C2ULL,
		0x028C0015080002D0ULL,
		0x0000412813E5F440ULL,
		0x8C040A12941A8A8CULL,
		0x1810808E06641751ULL,
		0x720920881003C250ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A069B58E223C4AAULL,
		0xD4A9E805C963408FULL,
		0xAFF7553F7464A122ULL,
		0x67D03B76F9912CD2ULL,
		0x7C913C37D421973BULL,
		0xCA19E1C686AA957CULL,
		0x3A1B40E84C5FD7A6ULL,
		0x2ADF8F3B7A9C7C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B737D025070794BULL,
		0x4762428031C6633AULL,
		0xA2A3B1A8FCBAAA9BULL,
		0x55653145079E7EC2ULL,
		0x866827AECEB51207ULL,
		0xC64D3C8F4299F89EULL,
		0x737C2EE4C70F8D34ULL,
		0x232D3D7F08175D23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A0219004020400AULL,
		0x442040000142400AULL,
		0xA2A311287420A002ULL,
		0x4540314401902CC2ULL,
		0x04002426C4211203ULL,
		0xC20920860288901CULL,
		0x321800E0440F8524ULL,
		0x220D0D3B08145C00ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4601D1B8146DD20ULL,
		0xC8428A33FA08822DULL,
		0x3387A31825AD0964ULL,
		0x696F518713456EB7ULL,
		0xD8266AA2EFB53FE1ULL,
		0x98E3DE2A1CDDCD9CULL,
		0xBC8F93344C88F4C1ULL,
		0x46CCCD0CA0BDE024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91BC07D9C914AABBULL,
		0x327A86A39D470AACULL,
		0xAA65FEFF31DA5918ULL,
		0x86213D09E73A92C4ULL,
		0x142E1F3160AC7C69ULL,
		0x495252E0444B434EULL,
		0x881CD11E17D35FD0ULL,
		0xB2FC50EE50F35123ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8020051981048820ULL,
		0x004282239800022CULL,
		0x2205A21821880900ULL,
		0x0021110103000284ULL,
		0x10260A2060A43C61ULL,
		0x084252200449410CULL,
		0x880C9114048054C0ULL,
		0x02CC400C00B14020ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10D46748FF083C33ULL,
		0x44A72B2DF445854BULL,
		0x0198125655847C9DULL,
		0x374FB0439EE3086DULL,
		0x58C60BDA40756AABULL,
		0x12177694F2D9323CULL,
		0xF98E290C7E94B904ULL,
		0x015E431339F3B3BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C8A1DC004BC7038ULL,
		0x959DD36BA820F651ULL,
		0xCFE029FA09477977ULL,
		0xF6D49B371A809880ULL,
		0x490418D592D7E397ULL,
		0xA58E6B5212DE127FULL,
		0xED83D2D52ED59172ULL,
		0x8E82370599E47DFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080054004083030ULL,
		0x04850329A0008441ULL,
		0x0180005201047815ULL,
		0x364490031A800800ULL,
		0x480408D000556283ULL,
		0x0006621012D8123CULL,
		0xE98200042E949100ULL,
		0x0002030119E031BCULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF03788246B52805EULL,
		0xDCDEB7CF3ECB8B5FULL,
		0x2B9DFABAC6D4F9E9ULL,
		0xA8E09F255B5B699CULL,
		0xE3C781152032ECB1ULL,
		0x4EA60CA65D4AFFD2ULL,
		0x1B27F75A5EFBDC1DULL,
		0x3C5656E446A8FED5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AE6204A0C397124ULL,
		0xD2DA0A72E626E6DCULL,
		0xD08AE5BD174E45D1ULL,
		0x180BCF033E8A8DE8ULL,
		0x06361426A19067B0ULL,
		0xC1F6D0AEDB04181DULL,
		0x06CF2BC7AAC04DE1ULL,
		0x7D8930BE060C8C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1026000008100004ULL,
		0xD0DA02422602825CULL,
		0x0088E0B8064441C1ULL,
		0x08008F011A0A0988ULL,
		0x02060004201064B0ULL,
		0x40A600A659001810ULL,
		0x020723420AC04C01ULL,
		0x3C0010A406088C95ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA92A89C9C85D3BBDULL,
		0xEFB050370D123D60ULL,
		0xEDA3F19739BDF93EULL,
		0x4C3CBC965D789E45ULL,
		0xDAD775891287DDEDULL,
		0x872992A33DC7E26BULL,
		0xE1D6BC9F19811683ULL,
		0x3B874163EA2F2DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57B98D56E792E91DULL,
		0x3BEFD1C858D31BD5ULL,
		0x4DF1183A20EF37D0ULL,
		0x60E8D6D61DCC831BULL,
		0x1C564ABC891170AEULL,
		0x42F8640A66184978ULL,
		0x10436B0E3C1E1AB2ULL,
		0x45DE8C762739AEE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01288940C010291DULL,
		0x2BA0500008121940ULL,
		0x4DA1101220AD3110ULL,
		0x402894961D488201ULL,
		0x18564088000150ACULL,
		0x0228000224004068ULL,
		0x0042280E18001282ULL,
		0x0186006222292CE0ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF2956970985FE0CULL,
		0xB807F35FE25AE943ULL,
		0xFFE43988F706C551ULL,
		0x7A8CDFE6E13337C3ULL,
		0x86793D881709FC41ULL,
		0x256149FB5D56F0D8ULL,
		0xFC5FB0C069B9F67AULL,
		0x225949220FCABCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4006F267665CA7D2ULL,
		0x83152C6DB0E784B6ULL,
		0xD7296D0EA75AD8EAULL,
		0x7A7EBB6101E48B11ULL,
		0x24E241439A9714FEULL,
		0xB1D70343A13C475BULL,
		0xCC26E7A898FFB385ULL,
		0x446A1BBFC5634CB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400052070004A600ULL,
		0x8005204DA0428002ULL,
		0xD7202908A702C040ULL,
		0x7A0C9B6001200301ULL,
		0x0460010012011440ULL,
		0x2141014301144058ULL,
		0xCC06A08008B9B200ULL,
		0x0048092205420CA2ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD3BE677A9F85052ULL,
		0x6967CFC70C0BCE29ULL,
		0x05C2528D485F317FULL,
		0xF86258CDEEE4FBA3ULL,
		0x4274A8C1283838ADULL,
		0x0C0F6E70EDFF2F32ULL,
		0x45E09879F2364AA3ULL,
		0x100E515DB5E5475FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B2F58C95B0F5AAULL,
		0x3A10CE204F0B095BULL,
		0x528CF5C338225AD7ULL,
		0xCF8F63D52C2D2787ULL,
		0xBFE502FC3B7BFC2DULL,
		0x33D406CF5C7F3E8EULL,
		0x98733EAA33ED18FCULL,
		0xFF2FC71B2B297992ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8132E40481B05002ULL,
		0x2800CE000C0B0809ULL,
		0x0080508108021057ULL,
		0xC80240C52C242383ULL,
		0x026400C02838382DULL,
		0x000406404C7F2E02ULL,
		0x00601828322408A0ULL,
		0x100E411921214112ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A770B728FE17B23ULL,
		0x554F83F167DBC3D4ULL,
		0xBC2C63B30753A2E0ULL,
		0x4C8D9AE1B4A28DF0ULL,
		0xD5DEB48546D80608ULL,
		0x01368090FF93E62CULL,
		0x8F72F140DE58B9C6ULL,
		0xAE0A50A52AEFC7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345CE7F7FC3875DBULL,
		0xE696DBADEE004945ULL,
		0x51B6CBA38BB36055ULL,
		0x99F141E66E3806A5ULL,
		0x20307098FA850330ULL,
		0xD3E560C3ED4EC146ULL,
		0x65E757BC035A9EEAULL,
		0xA6BC5DD188F9E894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x205403728C207103ULL,
		0x440683A166004144ULL,
		0x102443A303132040ULL,
		0x088100E0242004A0ULL,
		0x0010308042800200ULL,
		0x01240080ED02C004ULL,
		0x05625100025898C2ULL,
		0xA608508108E9C090ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x639B805E71F91F08ULL,
		0x9518CE10BC3EEC7FULL,
		0x0C924A9FDF21FC89ULL,
		0x73F85AC2017BA430ULL,
		0x3A75E2A1F91DFBE2ULL,
		0xDD1D51D7FFCE45A0ULL,
		0x45B62ACA49A2191AULL,
		0x68BC0B29EBC4E842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA42AADE4FA247C8ULL,
		0x2C04E6EFFE23F00CULL,
		0x3AFC214A3CC6B795ULL,
		0x7EED8E41E72B761BULL,
		0xB7DF7E1AD99413E6ULL,
		0xA688FF220785AB15ULL,
		0xD4EBF0173E1777A0ULL,
		0x6086745BB95B4A98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4202805E41A00708ULL,
		0x0400C600BC22E00CULL,
		0x0890000A1C00B481ULL,
		0x72E80A40012B2410ULL,
		0x32556200D91413E2ULL,
		0x8408510207840100ULL,
		0x44A2200208021100ULL,
		0x60840009A9404800ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22942E0A72E9DCECULL,
		0xFF85B673BAEA1AC1ULL,
		0x21E9527CC195132AULL,
		0x6332DA234F6D701DULL,
		0x4CD054D37BDEF65CULL,
		0xFD4B896AB2FA4379ULL,
		0xB996C9506C78DF11ULL,
		0x256FB6E933385272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF697F0253B0C718ULL,
		0x4D9C8A795710CE9EULL,
		0x9F1AC92E513E2521ULL,
		0x01AF099BC14D6860ULL,
		0x29B9C8AEC8F1F4D4ULL,
		0x3B9D563A656721DFULL,
		0x1B87B53B8C968968ULL,
		0xC60E53411E0C995BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22002E0252A0C408ULL,
		0x4D84827112000A80ULL,
		0x0108402C41140120ULL,
		0x01220803414D6000ULL,
		0x0890408248D0F454ULL,
		0x3909002A20620159ULL,
		0x198681100C108900ULL,
		0x040E124112081052ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD65BB6222140C5CULL,
		0x0A0EE6086AEDC4E1ULL,
		0x972DB41545EB0D23ULL,
		0xD42D015D820EF44AULL,
		0x6F27A19AE4002486ULL,
		0xBC0E8AEA1613F5B4ULL,
		0x12E45885923DB6BBULL,
		0xC03922841C137CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEE89170D642E0FULL,
		0xDF83FEE9053CE7F8ULL,
		0xCE3A4FB67388A77FULL,
		0x126BFA7E1C3126DDULL,
		0x25CA7174B4C09FCDULL,
		0xA243AD179A7F9395ULL,
		0x7DB6653C7530C5D7ULL,
		0x1783EE0815696F90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD64890200040C0CULL,
		0x0A02E608002CC4E0ULL,
		0x8628041441880523ULL,
		0x1029005C00002448ULL,
		0x25022110A4000484ULL,
		0xA002880212139194ULL,
		0x10A4400410308493ULL,
		0x0001220014016C90ULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42B1C66FD3627150ULL,
		0xEDB57C21B0FF6074ULL,
		0x0B797D7053C92F32ULL,
		0xCD25F33B9BB8B54DULL,
		0xEEA715238C905910ULL,
		0x6D22784ADD7B204FULL,
		0x61C0AA91440C89DCULL,
		0xBF5B2C9D39EF874AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA41E0C284497442ULL,
		0x37EAA8AB7FA3200FULL,
		0x5AF57E728A3A483CULL,
		0x5F7458618DA4E184ULL,
		0xF8FAECF5DEC02F9CULL,
		0x949C149DC01A1E5CULL,
		0xA40103F134049EDFULL,
		0x8CC04CBA0DC291C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4201C04280407040ULL,
		0x25A0282130A32004ULL,
		0x0A717C7002080830ULL,
		0x4D24502189A0A104ULL,
		0xE8A204218C800910ULL,
		0x04001008C01A004CULL,
		0x20000291040488DCULL,
		0x8C400C9809C28142ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80366BC44B3FC515ULL,
		0x1C443FD8B74DB24EULL,
		0x205F89CF503BBF82ULL,
		0xF76B69426CB59E7DULL,
		0x96037DDA5C492B5AULL,
		0x6ED83B9BAED318BCULL,
		0xFB2539271AA02E14ULL,
		0xE2825EC61461A7DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2443EC05B978B7ULL,
		0x8CD3A9976FE85C0FULL,
		0x941E5CA0A1501311ULL,
		0x9C70BB762A7CEE4FULL,
		0xBEEAFA3D75DB4225ULL,
		0x804A01DA8FEB25F6ULL,
		0xCE8081D54FFFDDEAULL,
		0x36D388ADA399CB45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002443C401394015ULL,
		0x0C4029902748100EULL,
		0x001E088000101300ULL,
		0x9460294228348E4DULL,
		0x9602781854490200ULL,
		0x0048019A8EC300B4ULL,
		0xCA0001050AA00C00ULL,
		0x2282088400018340ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71AA7B12FED7C538ULL,
		0x33D5785BF732399EULL,
		0x29D3CC1DB775FDC1ULL,
		0xFF73A2684551AA41ULL,
		0x0E5FE1A1DD712D97ULL,
		0x5807D6767251D34EULL,
		0x74A2D0A71A1AE6E9ULL,
		0x137674ADCE6BEAE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF93B57B5793B336ULL,
		0xA70792835AE623F6ULL,
		0xA52D5DEE0F5D867AULL,
		0x826AB1DA8FDB7F1EULL,
		0x0BC965ABE19F657CULL,
		0x264825CE3DCB991DULL,
		0xC4828AA84ED45B59ULL,
		0x52E95B3A1E921C21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3182311256938130ULL,
		0x2305100352222196ULL,
		0x21014C0C07558440ULL,
		0x8262A04805512A00ULL,
		0x0A4961A1C1112514ULL,
		0x000004463041910CULL,
		0x448280A00A104249ULL,
		0x126050280E020821ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x742857B7C48D25CEULL,
		0x8EF2A9B8EB90069DULL,
		0x738B6B19A44AD6E6ULL,
		0x3FE3147DABE4071CULL,
		0x0B1CE4C60AED79B6ULL,
		0x72CB387CDE820F8EULL,
		0x580E3D8340620E97ULL,
		0x78C4243C27D26ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AADA1166A82FA71ULL,
		0x7913524972422E5FULL,
		0x92563BA480F9FE0CULL,
		0xBF8EB4C30E3EA42CULL,
		0x2182038DBAF66C75ULL,
		0xFDDD8A78AFC6540AULL,
		0x8BF3F8CD13715F8FULL,
		0xB6FC72D75536C005ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0028011640802040ULL,
		0x081200086200061DULL,
		0x12022B008048D604ULL,
		0x3F8214410A24040CULL,
		0x010000840AE46834ULL,
		0x70C908788E82040AULL,
		0x0802388100600E87ULL,
		0x30C4201405124000ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FAD7C80A9FE215BULL,
		0xF5F79B74376BCE32ULL,
		0x0431E7DEFF6E74F8ULL,
		0x3C59ADF7CB3FC1F6ULL,
		0x9C38686193A28F40ULL,
		0x0062584D234C2987ULL,
		0x7FB237D68037BD0CULL,
		0x7994606D02AC7778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF717675286479932ULL,
		0x484CECA017DD108CULL,
		0x29580066CB17A384ULL,
		0xE9B7C7F90900C0EFULL,
		0xDE149BED6B89B7C7ULL,
		0x9C6A5F2D5E8F27CCULL,
		0x3FFDC423AE6E6390ULL,
		0x01080D1554963AB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9705640080460112ULL,
		0x4044882017490000ULL,
		0x00100046CB062080ULL,
		0x281185F10900C0E6ULL,
		0x9C10086103808740ULL,
		0x0062580D020C2184ULL,
		0x3FB0040280262100ULL,
		0x0100000500843230ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69546FEE17210E92ULL,
		0x95F32E97EFC53857ULL,
		0x57D7B8B0FEF6E655ULL,
		0xC1944DF519BDE28EULL,
		0x25FBDDB3614621CAULL,
		0x0C2996ED1A0DA3D2ULL,
		0xC234286FC3796D2EULL,
		0xFFFA2E8029D60952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEBD31D965AA74CEULL,
		0xBF3054F58ECCA7CAULL,
		0x6B2E69EBDFE48AC1ULL,
		0xBA12EEDD3A75AE4FULL,
		0xDD1C5BC0EF0C1842ULL,
		0xF7B4055207DFB7E6ULL,
		0x29397C220D89166DULL,
		0xC796F06509DEF6D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x281421C805200482ULL,
		0x953004958EC42042ULL,
		0x430628A0DEE48241ULL,
		0x80104CD51835A20EULL,
		0x0518598061040042ULL,
		0x04200440020DA3C2ULL,
		0x003028220109042CULL,
		0xC792200009D60052ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9F9F6AE4D9279F5ULL,
		0x877C8130D941620BULL,
		0x4B23997092410941ULL,
		0xF760B55062C8B7ADULL,
		0x35871DF5299E1152ULL,
		0x51A62616CF664F54ULL,
		0x2BFFFC4079E9AAEAULL,
		0x74E62A9245A71D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23F7449A216F19ECULL,
		0x203E6758E755FD4CULL,
		0xF5EE98D855749407ULL,
		0xFF858022485EC98AULL,
		0x9593BD90FBA7ACC9ULL,
		0x78FCBEE1C2560242ULL,
		0x812B993F4B58122FULL,
		0x5C195C3810412F4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01F1448A010219E4ULL,
		0x003C0110C1416008ULL,
		0x4122985010400001ULL,
		0xF700800040488188ULL,
		0x15831D9029860040ULL,
		0x50A42600C2460240ULL,
		0x012B98004948022AULL,
		0x5400081000010D02ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42A166B8369CA798ULL,
		0xD2E068E4758134DAULL,
		0x2953F2BE7BE16447ULL,
		0x44011BE391991FA6ULL,
		0x97E10794F16822A8ULL,
		0xAD0D51570D44445FULL,
		0xB5E6B0B3E6879513ULL,
		0xC7B06FF851FF3E67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDD580817AFDA4E6ULL,
		0x00B5CB06AA605C07ULL,
		0x8824EF1BB67B7AECULL,
		0x578E528DAB1A3EE9ULL,
		0x8CA41AD84B9B9BFFULL,
		0xB782EE462FAE8895ULL,
		0x1550392B8F9A8AACULL,
		0x9E610BD274D71AB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40810080329CA480ULL,
		0x00A0480420001402ULL,
		0x0800E21A32616044ULL,
		0x4400128181181EA0ULL,
		0x84A00290410802A8ULL,
		0xA50040460D040015ULL,
		0x1540302386828000ULL,
		0x86200BD050D71A23ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D28255CDC299CA1ULL,
		0x01DF0F7541859B7EULL,
		0x82A458D4369AF36CULL,
		0x2A6A885724410DCEULL,
		0xBBBF9D82CACA63B2ULL,
		0x349F43501E25B30BULL,
		0x8DEAA5F245C9B21CULL,
		0x0CD4085179478349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAB2ED8C96A23EEAULL,
		0x1A6AD8D7BABDCF9EULL,
		0x3BC2389735AA16A7ULL,
		0x3DA31CBD734BA7B0ULL,
		0xC16B6E287A954702ULL,
		0xBEFF4BBD014C2599ULL,
		0xBCD815A501A3BE11ULL,
		0xFA1F66B0F3BCBEE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8820250C94201CA0ULL,
		0x004A085500858B1EULL,
		0x02801894348A1224ULL,
		0x2822081520410580ULL,
		0x812B0C004A804302ULL,
		0x349F431000042109ULL,
		0x8CC805A00181B210ULL,
		0x0814001071048241ULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x242778860541AC03ULL,
		0x340FF01482610D64ULL,
		0x8E7E711FBDCE11C2ULL,
		0xD4C8C832B9F51894ULL,
		0x04B4976D467D0CA5ULL,
		0x14AE09126D52456EULL,
		0x7C1EE387EFB5EC06ULL,
		0x8280177E4E33F168ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7BB6E499ECAD8FCULL,
		0x7D8BCD3E543AC4E6ULL,
		0x151F9CBBE941FE3AULL,
		0xBC8E29881088BAC7ULL,
		0xD4E78444725B9BEFULL,
		0x23837ECA43ED7932ULL,
		0x7EF74D179B79BA4CULL,
		0xB509145194716ADFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0423680004408800ULL,
		0x340BC01400200464ULL,
		0x041E101BA9401002ULL,
		0x9488080010801884ULL,
		0x04A48444425908A5ULL,
		0x0082080241404122ULL,
		0x7C1641078B31A804ULL,
		0x8000145004316048ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF196EC5EC9BE20F5ULL,
		0xCD2681DA63F4EA6AULL,
		0x4878EE2B12FC68F8ULL,
		0x0744DC842057D958ULL,
		0x3CC34BB202CDA39CULL,
		0x8497FE3A0BE71426ULL,
		0x1136FB2C8FA10D6CULL,
		0x81C26347D72CCE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C9EB8C4B0614B66ULL,
		0xE56F9074EE8B48E4ULL,
		0x1A94F6C00E65A53CULL,
		0xC03BABAE36BD2E23ULL,
		0xCBB7E7C2D3D77DF1ULL,
		0xDAB42F75519EC746ULL,
		0x6E321FDE0D03AF93ULL,
		0x50FDC76E6C7C0BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4096A84480200064ULL,
		0xC526805062804860ULL,
		0x0810E60002642038ULL,
		0x0000888420150800ULL,
		0x0883438202C52190ULL,
		0x80942E3001860406ULL,
		0x00321B0C0D010D00ULL,
		0x00C04346442C0A20ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9900A964DA4CCB53ULL,
		0x8186DF56A40B8C6CULL,
		0x819E71D66B1F4C2DULL,
		0xEF620EA383CDF53BULL,
		0x0EE8CBE7B68CEB3BULL,
		0xCA8345AB478D6B13ULL,
		0x2742B18E79F13DC0ULL,
		0x09DB27FB178A5EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEDF421BB5862246ULL,
		0xAE1AE20B9D67252DULL,
		0x9EA2DDF64A6B502AULL,
		0x5693FBFB6501D83DULL,
		0x06B0420A06BF7B24ULL,
		0x71261C7DE93FA99CULL,
		0x8FBC19FFFA5B2EF7ULL,
		0xB322D55638FF06B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8800000090040242ULL,
		0x8002C2028403042CULL,
		0x808251D64A0B4028ULL,
		0x46020AA30101D039ULL,
		0x06A04202068C6B20ULL,
		0x40020429410D2910ULL,
		0x0700118E78512CC0ULL,
		0x01020552108A06A0ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F2222B249F50351ULL,
		0xE1C1C6E2D749C3AEULL,
		0xBF687DD966CC4107ULL,
		0xC519BA446A5495BEULL,
		0xE308FE4DE424D659ULL,
		0x12227AFB882CEE7BULL,
		0x42B3633AF01360F3ULL,
		0x7CB27BC006DA76BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C43D76C6C6912F9ULL,
		0x34CF3A3690C3812AULL,
		0x6A996BDB6E242C09ULL,
		0x9383F1379EB79A51ULL,
		0x0F6811051C474DE6ULL,
		0xBFAC9CDBE4218DECULL,
		0x65838D41E72F2FB9ULL,
		0x35DC6C440A95FD5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C02022048610251ULL,
		0x20C102229041812AULL,
		0x2A0869D966040001ULL,
		0x8101B0040A149010ULL,
		0x0308100504044440ULL,
		0x122018DB80208C68ULL,
		0x40830100E00320B1ULL,
		0x349068400290741BULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A15389192FBB28EULL,
		0x3E07A225C010A794ULL,
		0xB118F760424A0461ULL,
		0x253E602211942FB5ULL,
		0xE236572476B2F880ULL,
		0xC63C6D200A319D5EULL,
		0xCF142056D779D745ULL,
		0x2C0878E4BD6CE6ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3480E9BDCFF9D5E6ULL,
		0x166A4C652B8D532EULL,
		0x9DB0F0BB4111635BULL,
		0x0D35EB5FDCC69CCDULL,
		0x64F3256E219D264FULL,
		0x6CDBAF5545D2D36FULL,
		0xC89AFE50037B0A01ULL,
		0x16DABE645BFD7BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000289182F99086ULL,
		0x1602002500000304ULL,
		0x9110F02040000041ULL,
		0x0534600210840C85ULL,
		0x6032052420902000ULL,
		0x44182D000010914EULL,
		0xC810205003790201ULL,
		0x04083864196C62A9ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05F1FFA1B2D9FD70ULL,
		0x3213466C0EA9E6C0ULL,
		0x4A51269A2016E377ULL,
		0xC8E13023C9024163ULL,
		0x03879CE24D7B2600ULL,
		0x9DCB9FDDA025F8F1ULL,
		0x21815D50F06A7C66ULL,
		0x386896BECA9B44A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2318AC8B1848C84DULL,
		0x50C5B29503C6D1AAULL,
		0xE5F9FE255A1E0084ULL,
		0xB80768E214A63D61ULL,
		0x0574AE14F831BA30ULL,
		0x6E59A018634F95C4ULL,
		0xBB07112C65F9D106ULL,
		0xF59C18874158ACDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0110AC811048C840ULL,
		0x100102040280C080ULL,
		0x4051260000160004ULL,
		0x8801202200020161ULL,
		0x01048C0048312200ULL,
		0x0C498018200590C0ULL,
		0x2101110060685006ULL,
		0x3008108640180480ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB6B75198FACFE6DULL,
		0x0DC597757FF7AFACULL,
		0x0CA83F7311562AF3ULL,
		0xC564FF63F7C59768ULL,
		0xE2D0ECE29BDA7C00ULL,
		0x0665FB5AA6C6A2E1ULL,
		0xFCA566074AEED544ULL,
		0x9E473C520D8E857CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49506ADDEAA7B85FULL,
		0x9339765F61A3F0DDULL,
		0x89EF726F0382D19CULL,
		0xF7BB407C42767AB1ULL,
		0x62083F04BAF124A2ULL,
		0x089708AA23B54E16ULL,
		0xB381AFAE535F06EBULL,
		0x4C17481F163135DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x094060198AA4B84DULL,
		0x0101165561A3A08CULL,
		0x08A8326301020090ULL,
		0xC520406042441220ULL,
		0x62002C009AD02400ULL,
		0x0005080A22840200ULL,
		0xB0812606424E0440ULL,
		0x0C0708120400055CULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86858B8D0C6BA1B0ULL,
		0x052C010491EC0D48ULL,
		0x932F6F62E3375725ULL,
		0x063530FDC39B1ABCULL,
		0x3B6AB53013414F1AULL,
		0x177F5AFB05F98FAAULL,
		0x83FB6658EAFC1ADDULL,
		0xD79BEB7FD7A51E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF98F4BA1D4D1B8FULL,
		0x487878B083ECE247ULL,
		0x3BF1C1EA8F9BC515ULL,
		0xF4D652CD39FD2774ULL,
		0xD3365688C51A53A4ULL,
		0x01D30B7DA5BB6DC4ULL,
		0x1BC4DFE870482C35ULL,
		0x6C30A58EF69C028EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x868080880C490180ULL,
		0x0028000081EC0040ULL,
		0x1321416283134505ULL,
		0x041410CD01990234ULL,
		0x1322140001004300ULL,
		0x01530A7905B90D80ULL,
		0x03C0464860480815ULL,
		0x4410A10ED684020EULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AE3EBB94D3D1E42ULL,
		0x61D9AAF7C4400774ULL,
		0x4348C4A44AC78830ULL,
		0xC3560E935E04116FULL,
		0x778A24D553B1CD26ULL,
		0xC545072CEA9779F9ULL,
		0xC0ABA512B71FE293ULL,
		0x443F1F691F9D270CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F85CAF39E15C273ULL,
		0xCE6561C9485EF169ULL,
		0xBA549DB0D931312CULL,
		0x2E50D1A45B27C751ULL,
		0x1C3B42A1FC1A6019ULL,
		0xA68A236159AD8F9EULL,
		0x8C25F276D4462BADULL,
		0xF04151701E427858ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A81CAB10C150242ULL,
		0x404120C140400160ULL,
		0x024084A048010020ULL,
		0x025000805A040141ULL,
		0x140A008150104000ULL,
		0x8400032048850998ULL,
		0x8021A01294062281ULL,
		0x400111601E002008ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x451DEDC762A28296ULL,
		0xD01288F32BC305E7ULL,
		0x3A74FE63560FD5D3ULL,
		0xD067B9873FE70836ULL,
		0x411AAD0461D54DEDULL,
		0xF5749FA3430449DDULL,
		0x579514798D609321ULL,
		0x36D7382554FBB69DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D82AB8AC98C64E0ULL,
		0x73727CDE820C778BULL,
		0x14F07D6C258318EAULL,
		0x0F102E37C34976F4ULL,
		0x30B43948E9CF29C4ULL,
		0x4A84AC307C1CFBECULL,
		0x49D850F88CDD438FULL,
		0x8AAE71E1BEDD530FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0500A98240800080ULL,
		0x501208D202000583ULL,
		0x10707C60040310C2ULL,
		0x0000280703410034ULL,
		0x0010290061C509C4ULL,
		0x40048C20400449CCULL,
		0x419010788C400301ULL,
		0x0286302114D9120DULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x753C6B5BD54FBE7CULL,
		0xB0A1F0C3A8495748ULL,
		0xAF7519095E3EC5A0ULL,
		0x013EC98C05E0ECD1ULL,
		0x2114C822E4565695ULL,
		0x24755B890E66DED1ULL,
		0x6E6587450D5DCCB0ULL,
		0x6C0A05313B61FD5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFF81F5B6DB3935BULL,
		0x1A2037C272798AD4ULL,
		0x2F57AFDE1D0BC420ULL,
		0x49E4C0AA0F29C876ULL,
		0xC6966391C038F6B6ULL,
		0x1B91C0F55DCAB3A4ULL,
		0xF4FFF44A811FA6E1ULL,
		0xB58010F39BD164A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25380B5B45039258ULL,
		0x102030C220490240ULL,
		0x2F5509081C0AC420ULL,
		0x0124C0880520C850ULL,
		0x00144000C0105694ULL,
		0x001140810C429280ULL,
		0x64658440011D84A0ULL,
		0x240000311B416401ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE38D30A9DDD4AFFULL,
		0x9C00A8E9DA9D717CULL,
		0x48D3FD92721C9334ULL,
		0x3D211EAD5E0525B2ULL,
		0x8FC0DEC4EE2A4C40ULL,
		0x6E7A1794AD9BE31FULL,
		0x348302225F872439ULL,
		0xE6B59112C2A9EE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CD420B9C229476ULL,
		0x9D7F758165086680ULL,
		0xF2FBF3DBCC3B637FULL,
		0xBB37D3F6BA73E92FULL,
		0x0AB8A59F70F0A60FULL,
		0x70F20B4A2348D996ULL,
		0x4BB231161987150DULL,
		0x9D0E10794B438C00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0408420A9C000076ULL,
		0x9C00208140086000ULL,
		0x40D3F19240180334ULL,
		0x392112A41A012122ULL,
		0x0A80848460200400ULL,
		0x607203002108C116ULL,
		0x0082000219870409ULL,
		0x8404101042018C00ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CABDDDD081642C8ULL,
		0xEFFD53929379529DULL,
		0x4E93B0A6DB9A6861ULL,
		0xCBA2D7BAA441354DULL,
		0x27E92D969F6AED9EULL,
		0xD0BC16726B7C7820ULL,
		0x19B96F879C6D0A2BULL,
		0x1092B85E75160326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC66E5E6EC8213EULL,
		0xF958C84EBDEB2409ULL,
		0x26C6B5697851612DULL,
		0x7ACC9515F274ECAAULL,
		0xA95F543BD3BCDA66ULL,
		0xDA4A2E10337E428EULL,
		0xD243FC326161455FULL,
		0x627BE246DAE17C47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28824C5C08000008ULL,
		0xE958400291690009ULL,
		0x0682B02058106021ULL,
		0x4A809510A0402408ULL,
		0x214904129328C806ULL,
		0xD0080610237C4000ULL,
		0x10016C020061000BULL,
		0x0012A04650000006ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EF2C0528A9E008CULL,
		0xD294B7FC7E6A6212ULL,
		0x582FE567A2CCC062ULL,
		0x525FF07CCAC76B5CULL,
		0x76D145DA6C48E0A7ULL,
		0x1D049588064FCC87ULL,
		0xA4BB3BB53A0BE710ULL,
		0x32815869E6ACD1E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E58ABF5FA199AFFULL,
		0xB39A79A3089D5DE6ULL,
		0xD672929B9569BAEEULL,
		0xD168ECA92F6B95C9ULL,
		0x1B63AC2A2DD6DD68ULL,
		0x58231291CD27ED3CULL,
		0x6F12E851B0BD7E69ULL,
		0x608A6E365179F7DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E5080508A18008CULL,
		0x929031A008084002ULL,
		0x5022800380488062ULL,
		0x5048E0280A430148ULL,
		0x1241040A2C40C020ULL,
		0x180010800407CC04ULL,
		0x2412281130096600ULL,
		0x208048204028D1C0ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x126EE92488DA3DE6ULL,
		0xCD697269E415E559ULL,
		0x6F3329EE87AF3D56ULL,
		0xE2E44635C2DEE021ULL,
		0x6386518607D2C3A2ULL,
		0x092045A240A29A1FULL,
		0x51DAA006C7A29E13ULL,
		0xCE885F5223132054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1909E1637679E0AULL,
		0xBCA7ABEDB1D001A9ULL,
		0x20408A39915BE9AAULL,
		0xB8D0F513A8C35CE7ULL,
		0xA3C9911A0DA69208ULL,
		0xA3BBE4CC03F7A326ULL,
		0x83990B655ABEB93EULL,
		0x3BA9EA5C1C9CE663ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000880400421C02ULL,
		0x8C212269A0100109ULL,
		0x20000828810B2902ULL,
		0xA0C0441180C24021ULL,
		0x2380110205828200ULL,
		0x0120448000A28206ULL,
		0x0198000442A29812ULL,
		0x0A884A5000102040ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8126E91D5A27B252ULL,
		0xB9994EC2D040F90BULL,
		0x43994E158949E24BULL,
		0xD23811DDFD8D1628ULL,
		0x090D7013D5FF7A74ULL,
		0xFDDB37307E3BE55AULL,
		0xFA620E0CEFE44769ULL,
		0xAC56E025EC967E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0ECB7BF4EA0B56ULL,
		0x26732DD7E024EB5AULL,
		0x81982928FA429129ULL,
		0x407C4F7246811938ULL,
		0xCD8291598FAFBEA1ULL,
		0x5A1F4E29120D4D80ULL,
		0x3E9FFE01E153490AULL,
		0x4F3052A2DA25BC3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0106C91950220252ULL,
		0x20110CC2C000E90AULL,
		0x0198080088408009ULL,
		0x4038015044811028ULL,
		0x0900101185AF3A20ULL,
		0x581B062012094500ULL,
		0x3A020E00E1404108ULL,
		0x0C104020C8043C30ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x031801726DA38FE5ULL,
		0x3676853F11D738C9ULL,
		0xB5A5C6974B1A9FD6ULL,
		0xDEA9A67A6C2026DAULL,
		0xA3BCD068A0163A31ULL,
		0xB8D745A30E4D4ADBULL,
		0xDC6A3D5446970ED1ULL,
		0x9E80739849A8651DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11F0109636DCD2FULL,
		0xE78AADC98FB78A83ULL,
		0xF5808D6E7C851617ULL,
		0x15DB74263647DC9EULL,
		0xFF4146F0A1112817ULL,
		0x1F27EA36DF89EBA7ULL,
		0x2997A07883093671ULL,
		0x0718712CA288106FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0118010061218D25ULL,
		0x2602850901970881ULL,
		0xB580840648001616ULL,
		0x148924222400049AULL,
		0xA3004060A0102811ULL,
		0x180740220E094A83ULL,
		0x0802205002010651ULL,
		0x060071080088000DULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25FC4682E8773229ULL,
		0x7B06548A6A7E0BBEULL,
		0xFFF16A28DC948E69ULL,
		0x22451BAE47B6976EULL,
		0x1FB933A5BA2BED24ULL,
		0xF0499AE7B9158269ULL,
		0x30001065043E6092ULL,
		0x5D64A06106B16E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DDF14AD1729261EULL,
		0x0E3C3B27CD6D1646ULL,
		0x4F87684B95040058ULL,
		0x5256314799D55FC7ULL,
		0x974D5921CD39CA3AULL,
		0x6FA527883BEAB16AULL,
		0xE8B30FF64920AB50ULL,
		0x91C89EF157C92CA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25DC048000212208ULL,
		0x0A041002486C0206ULL,
		0x4F81680894040048ULL,
		0x0244110601941746ULL,
		0x170911218829C820ULL,
		0x6001028039008068ULL,
		0x2000006400202010ULL,
		0x1140806106812C20ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA90B83D1B90041CFULL,
		0x94A36AD086B0916AULL,
		0x725EADD2B2C33774ULL,
		0x336F23A48B16D71BULL,
		0xA33F06C3C6384BD9ULL,
		0x759ABBC07ABED250ULL,
		0x760137BA29A801E8ULL,
		0xF7464655310086EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x011C7EAB765A141FULL,
		0x07A5FD7294984A98ULL,
		0x3C5DC73A139046E2ULL,
		0x7351F16CF954E9E4ULL,
		0x14A6ED12F70A8718ULL,
		0x59EAF1373BB7692DULL,
		0x6A4541590FDDC782ULL,
		0xC38BABE68C9368E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010802813000000FULL,
		0x04A1685084900008ULL,
		0x305C851212800660ULL,
		0x334121248914C100ULL,
		0x00260402C6080318ULL,
		0x518AB1003AB64000ULL,
		0x6201011809880180ULL,
		0xC3020244000000E0ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13AED3AAEDCEE850ULL,
		0x90FFED1D6207A494ULL,
		0xDD36C43F6593FD60ULL,
		0x383C60D28D8197A7ULL,
		0x469F6F9F27F81945ULL,
		0x9D0D0E7BA192AAFEULL,
		0x50C3364832EB315FULL,
		0x93247ED93974ADDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E8E2B77655B89B8ULL,
		0x388927B6B07A0B2FULL,
		0xDFA66AE7295163BBULL,
		0x6E29A6AE7E0ED71BULL,
		0x820BD328EFBCDC17ULL,
		0xCC3E6EB3370DAC39ULL,
		0x687149769BD206D8ULL,
		0x0AF7719D90E8879EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028E0322654A8810ULL,
		0x1089251420020004ULL,
		0xDD26402721116120ULL,
		0x282820820C009703ULL,
		0x020B430827B81805ULL,
		0x8C0C0E332100A838ULL,
		0x4041004012C20058ULL,
		0x022470991060859AULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5E3A63AE0FAC1C6ULL,
		0xCFD93E21470B1734ULL,
		0x9FB2C91F6DE27D68ULL,
		0x24555E38DC3BBFC2ULL,
		0x180BBB4B40E946A8ULL,
		0xD83DF23A9E4670EFULL,
		0xB50517745D4ACEE9ULL,
		0x36BF1CB92CDE61B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x709C5DAFF00BBF0DULL,
		0x8BB3543FC9D63B35ULL,
		0x3217CAA2A9DC0807ULL,
		0xEC7E1CFCA280B346ULL,
		0x98E2F3CDDCFB12F8ULL,
		0xB33D4C9062C44A0DULL,
		0x7B7531D66752B4D6ULL,
		0x774F74E3780F56C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2080042AE00A8104ULL,
		0x8B91142141021334ULL,
		0x1212C80229C00800ULL,
		0x24541C388000B342ULL,
		0x1802B34940E902A8ULL,
		0x903D40100244400DULL,
		0x31051154454284C0ULL,
		0x360F14A1280E4081ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92ED2F1803002B2DULL,
		0xFE762F1691513A5EULL,
		0x3BE5F72AB49A54A2ULL,
		0x4ADFEB885EEEF358ULL,
		0xE3263CC6809E441BULL,
		0xEC0AEEB436880BC2ULL,
		0xB9AD952E9E5B7858ULL,
		0x20117C560E72D99EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4FF9698C0E65F92ULL,
		0x7697C8CA74AC6380ULL,
		0x8836953410E3D2D2ULL,
		0x308653D87CCAFD8BULL,
		0x0F2BF465D58C336DULL,
		0xDC635AA7DCC6E21AULL,
		0xF5F9C2C6248FF964ULL,
		0xE2A6F96BB268E677ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90ED061800000B00ULL,
		0x7616080210002200ULL,
		0x0824952010825082ULL,
		0x008643885CCAF108ULL,
		0x03223444808C0009ULL,
		0xCC024AA414800202ULL,
		0xB1A98006040B7840ULL,
		0x200078420260C016ULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB13D8478F1C2176CULL,
		0x69B633EE74A80953ULL,
		0xE57ABCF2A4175DB7ULL,
		0x3973A68984378346ULL,
		0x36DEB9D5DC3FF4E6ULL,
		0xF642C2EBAF2E0382ULL,
		0x61A7673A3A4AB083ULL,
		0xC580592F088D132AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF890484536377B24ULL,
		0x2934E832FF67FA69ULL,
		0x5CEB3E75D0FAF547ULL,
		0x84F97866DD024343ULL,
		0x263EAE66334D671AULL,
		0x86C6DA099AAB7A3EULL,
		0xB8E83CFDFAA19593ULL,
		0xBE0D82EC1D7881CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB010004030021324ULL,
		0x2934202274200841ULL,
		0x446A3C7080125507ULL,
		0x0071200084020342ULL,
		0x261EA844100D6402ULL,
		0x8642C2098A2A0202ULL,
		0x20A024383A009083ULL,
		0x8400002C0808010AULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x173FCC3EE39CE136ULL,
		0x9B161CC1E8C6819DULL,
		0x69138506F9C62F72ULL,
		0x5DC622DA536A2353ULL,
		0xB4BE26C643EB32E2ULL,
		0x1E45821C2C538F5CULL,
		0xAC48E0256B5AD548ULL,
		0x21D10551CD750492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632B953C49F05D71ULL,
		0x703B0A0AFB10D52EULL,
		0xB543E5D6E47FF50BULL,
		0x3C6D3DBBC496E8F8ULL,
		0x0E0169E691BE3EBCULL,
		0xAD660BCE4F219046ULL,
		0xC1EF200C6DA72F40ULL,
		0x135E302115D57DB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x032B843C41904130ULL,
		0x10120800E800810CULL,
		0x21038506E0462502ULL,
		0x1C44209A40022050ULL,
		0x040020C601AA32A0ULL,
		0x0C44020C0C018044ULL,
		0x8048200469020540ULL,
		0x0150000105550490ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60EA08183CC2D223ULL,
		0xCF2532FBF6D23461ULL,
		0x9F15CB530371710AULL,
		0xFBCFCDE2D97559D6ULL,
		0xE2B3FBE2D84EE96EULL,
		0x77794EDF06D8F078ULL,
		0x3EF054121A949C1CULL,
		0x611BE0B86265424CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7095D9D226EFFFF0ULL,
		0x0943DDF44ACF38FFULL,
		0xABB38BE97D295A5EULL,
		0xFAEB01C57D108221ULL,
		0x7D5C67D088BEB744ULL,
		0x440E00001670F5D9ULL,
		0x4276158E3591970EULL,
		0xF7FC03414A159EFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6080081024C2D220ULL,
		0x090110F042C23061ULL,
		0x8B118B410121500AULL,
		0xFACB01C059100000ULL,
		0x601063C0880EA144ULL,
		0x440800000650F058ULL,
		0x027014021090940CULL,
		0x611800004205024CULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ECE3A8C8491A2D1ULL,
		0xAF40BAD7F2BB7C7FULL,
		0xF5F654D67293225AULL,
		0xCFF6E7278358D49FULL,
		0x34D18EE87B415D38ULL,
		0xFEFABDD5968763D0ULL,
		0xD610A77F35803093ULL,
		0x8A35264C40F30923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F4761165246C38AULL,
		0x4A95F0B61C1262CBULL,
		0x6474A7AF855675D5ULL,
		0x3D0D88F7A469BE1CULL,
		0xD499F33F3FDF6D38ULL,
		0x16375421E6313995ULL,
		0x071AD5806130C029ULL,
		0x1DC4EAB63C2B3566ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E46200400008280ULL,
		0x0A00B0961012604BULL,
		0x6474048600122050ULL,
		0x0D0480278048941CULL,
		0x149182283B414D38ULL,
		0x1632140186012190ULL,
		0x0610850021000001ULL,
		0x0804220400230122ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B42754714D762F9ULL,
		0x57B2F37108233404ULL,
		0x8CA7A32AEA5B9594ULL,
		0x2AAC6E2004C4125AULL,
		0xD4273E73A8DC7E4FULL,
		0x204D49FFD70B0AD1ULL,
		0xD401CEBB763EF390ULL,
		0xB906EA71F447286DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF14B32C4A63502AAULL,
		0xB76272C2E57487E3ULL,
		0x6FEE682EFC3C2706ULL,
		0x660470429C9FCA0BULL,
		0x8F7ACC655A5EBBA5ULL,
		0xF11D0647070D5A75ULL,
		0x60AC4D92931F5DBEULL,
		0x60D4563E9BF24505ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41423044041502A8ULL,
		0x1722724000200400ULL,
		0x0CA6202AE8180504ULL,
		0x220460000484020AULL,
		0x84220C61085C3A05ULL,
		0x200D004707090A51ULL,
		0x40004C92121E5190ULL,
		0x2004423090420005ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x871BCE3C7F15A348ULL,
		0x25E31F394C37A9B3ULL,
		0xDE3810741F642A90ULL,
		0x7118A6EE3A839DC2ULL,
		0x3199DB36DD3F0C97ULL,
		0xE29C5FE62AB96D0EULL,
		0xCE1A132C0A58625AULL,
		0x58C7284C7177A7A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA46094E36F41706CULL,
		0xD7EA7BF5F0CC216CULL,
		0x8632C77267D2FA8EULL,
		0x2E4EB586BCDB5746ULL,
		0x2D5E641FA0059F7DULL,
		0x055C4372D8C1B7ADULL,
		0xFD6AE553D91B652FULL,
		0x778AEAD2A3760378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x840084206F012048ULL,
		0x05E21B3140042120ULL,
		0x8630007007402A80ULL,
		0x2008A48638831542ULL,
		0x2118401680050C15ULL,
		0x001C43620881250CULL,
		0xCC0A01000818600AULL,
		0x5082284021760328ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x804291A49E5E77DCULL,
		0x8590D13927FE08AEULL,
		0x62D15F3BB6F616CCULL,
		0x7C582CDD2E687A09ULL,
		0x30A8AC3AD40127C4ULL,
		0x9795B6CEFCEF06ECULL,
		0x319C90AAE1CE7C4AULL,
		0xD372FEC4333037CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DBC9B6172160CDULL,
		0xF65DA6142140EAF0ULL,
		0xBD29568FDB80D0B8ULL,
		0xD02D2C2D07ECA292ULL,
		0x92C87ACC77C671A0ULL,
		0xC40053728E61109EULL,
		0xA4E4B04AAC4BEC3AULL,
		0x8531FA8A6ABC89D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x804281A4160060CCULL,
		0x84108010214008A0ULL,
		0x2001560B92801088ULL,
		0x50082C0D06682200ULL,
		0x1088280854002180ULL,
		0x840012428C61008CULL,
		0x2084900AA04A6C0AULL,
		0x8130FA80223001C8ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x837E81B6CE7F719BULL,
		0xEA6C2C8B2D502F5EULL,
		0x6BC27153FE53BF8BULL,
		0x4F8A7602E5C78F82ULL,
		0x7A69D66422A63BBEULL,
		0xC0756FA8FEA0193CULL,
		0x57F17AA0855B95F3ULL,
		0xDF81F0EFCFCDB5ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFFD59B442C5052ULL,
		0x7556FE62EF157076ULL,
		0x038DFBC7EE17E18EULL,
		0x20E44BC939E60D6EULL,
		0x758B57C5699FBF92ULL,
		0x0DB8D69407E6D4EBULL,
		0x03D5312B268C806DULL,
		0x898F6083B515F524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x827E8192442C5012ULL,
		0x60442C022D102056ULL,
		0x03807143EE13A18AULL,
		0x0080420021C60D02ULL,
		0x7009564420863B92ULL,
		0x0030468006A01028ULL,
		0x03D1302004088061ULL,
		0x898160838505B524ULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7BBB993DBA2E274ULL,
		0x11E9649A1055E15FULL,
		0xCD5D0025DC640C2DULL,
		0xA049A304582784EDULL,
		0xF95A6E34DDCD8C2BULL,
		0x2C2A1688BCBD0885ULL,
		0x6FB60BCF1EF140E6ULL,
		0x6401D51307740B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C47E3F35C578B60ULL,
		0xBC27BE542B4CCD0BULL,
		0xE5D9B20C0216C669ULL,
		0xCC15613D9682E216ULL,
		0x48F5139C5D9CEC7BULL,
		0x745E3F619D9A1343ULL,
		0x97B094BA8F1D5BE9ULL,
		0x005330027DE43338ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8403A19358028260ULL,
		0x102124100044C10BULL,
		0xC559000400040429ULL,
		0x8001210410028004ULL,
		0x485002145D8C8C2BULL,
		0x240A16009C980001ULL,
		0x07B0008A0E1140E0ULL,
		0x0001100205640310ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC233072857822D62ULL,
		0x3CC493134704B9D8ULL,
		0xA5A05AED8AA37931ULL,
		0xDEE8E2FC2D50983BULL,
		0x5A7F95FF0AE204BFULL,
		0xF80C31C887EC5198ULL,
		0x5070CBF34C01687AULL,
		0x162EAE1455321150ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B91DBD0C6709489ULL,
		0xF04E3192ED799B9FULL,
		0xBE6F6BF07F344B3BULL,
		0xB92F1F7DDE6ECE16ULL,
		0xE0445C82D3D9CB8CULL,
		0x3C8E40D0EC3FF557ULL,
		0x2421CEBCEB2D7BB1ULL,
		0xB0515F71F43EBBF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0211030046000400ULL,
		0x3044111245009998ULL,
		0xA4204AE00A204931ULL,
		0x9828027C0C408812ULL,
		0x4044148202C0008CULL,
		0x380C00C0842C5110ULL,
		0x0020CAB048016830ULL,
		0x10000E1054321150ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A1A5223BF3E731ULL,
		0xEC28BE6AFEFBAB45ULL,
		0x88EC273116AC9FB1ULL,
		0xAAC8B60148E27A25ULL,
		0xE8FE085762CAD72FULL,
		0xD22D6D6959BE3B3DULL,
		0xA388D62CF4A5A76DULL,
		0x8280F1CF67D687BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79FB8CEC84A8A1A6ULL,
		0xD73682FEB3D4C891ULL,
		0xC4C2A14901E1C609ULL,
		0x0E6D678149F5CF92ULL,
		0xC3F10470134F0FD6ULL,
		0x4B14E0436D87C5F1ULL,
		0xBC829ED515204EDCULL,
		0xA19FCB370447EA99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11A1842000A0A120ULL,
		0xC420826AB2D08801ULL,
		0x80C0210100A08601ULL,
		0x0A48260148E04A00ULL,
		0xC0F00050024A0706ULL,
		0x4204604149860131ULL,
		0xA08096041420064CULL,
		0x8080C10704468299ULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EC01B350C4EBDA4ULL,
		0x81EB3025C21F53EBULL,
		0x32F704311C8A52F6ULL,
		0x7C15FE4962508EB0ULL,
		0xFCF0FE2D3A5FB224ULL,
		0x69D3F6AF5519F7C1ULL,
		0x81B78EBE4B33253CULL,
		0xE7727962CA954D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E52262A6E1E91CULL,
		0x4ED26EC4B9F62614ULL,
		0x53D6E780CE12AC83ULL,
		0xCFBF8A04A3ACBCFEULL,
		0xF939BBB9E4E6179FULL,
		0x33D67FB3776BFA25ULL,
		0x4932F9B24DAC6FA1ULL,
		0x5BF727E491771425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C002200440A904ULL,
		0x00C2200480160200ULL,
		0x12D604000C020082ULL,
		0x4C158A0022008CB0ULL,
		0xF830BA2920461204ULL,
		0x21D276A35509F201ULL,
		0x013288B249202520ULL,
		0x4372216080150401ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE135181A7A000E80ULL,
		0x73A0EED21D896F42ULL,
		0x363CCCD3C00BB6ACULL,
		0x0E98CB56227FCFC4ULL,
		0xE32BFBCCD3596291ULL,
		0xB679D0874BA09398ULL,
		0x93C662F335A8DA72ULL,
		0xB18F8A028F924E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AE6C9B0AA9C6E3ULL,
		0x2EC9A44232BD7EC9ULL,
		0xED50C26E764DC698ULL,
		0x9078D568603DE520ULL,
		0x0441B10A91A86FBCULL,
		0x3546752C4F68386CULL,
		0x1D5FE1C19CDA7534ULL,
		0xCE78B788F7C1564DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0124081A0A000680ULL,
		0x2280A44210896E40ULL,
		0x2410C04240098688ULL,
		0x0018C140203DC500ULL,
		0x0001B10891086290ULL,
		0x344050044B201008ULL,
		0x114660C114885030ULL,
		0x8008820087804605ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5497F6A0FD6BAD0FULL,
		0x0BF94929B56B788FULL,
		0x968884BF945A14CCULL,
		0xA654598830327FEEULL,
		0xD124819B373BE254ULL,
		0x3BE2245AD6B483B1ULL,
		0x3F652B5D7EB9FBA4ULL,
		0x049E8E188F5CC9CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AF35FADF8B21A72ULL,
		0x2995B8A134047E81ULL,
		0xE226B040694E7F2CULL,
		0xCC0ED141DD8AC540ULL,
		0xABD87D3B5E33C683ULL,
		0x80954B87083E1F2BULL,
		0x6467B92DA63E6356ULL,
		0x20F858EC9C54637BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x009356A0F8220802ULL,
		0x0991082134007881ULL,
		0x82008000004A140CULL,
		0x8404510010024540ULL,
		0x8100011B1633C200ULL,
		0x0080000200340321ULL,
		0x2465290D26386304ULL,
		0x009808088C54414BULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x341BC60FC337B3D0ULL,
		0xAEE575EF8F934FBEULL,
		0x9492886936DFF559ULL,
		0x1A18E739BC8A00D3ULL,
		0x57287C5BF978A16DULL,
		0x7746A95FDB512D42ULL,
		0x4550EFAF211530F5ULL,
		0xA1EF15C4BE0EA58AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D62C5D67E300A6EULL,
		0x73D28542BBC0FC1AULL,
		0x59061E737D223B86ULL,
		0xA854AD00522113E0ULL,
		0x94D02C7CF796B96DULL,
		0x433DC0B4A05A7095ULL,
		0x21DC1A04649064F1ULL,
		0xA3B2908163B10FC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0402C40642300240ULL,
		0x22C005428B804C1AULL,
		0x1002086134023100ULL,
		0x0810A500100000C0ULL,
		0x14002C58F110A16DULL,
		0x4304801480502000ULL,
		0x01500A04201020F1ULL,
		0xA1A2108022000582ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBBE15402A5B1F6CULL,
		0x85AB567311AB72DEULL,
		0x984EC6498D927E4CULL,
		0xB5586291DB3E3046ULL,
		0x50DB6853680A7EC0ULL,
		0x2BEC7C6697890884ULL,
		0x201FE78402686BDCULL,
		0x9095C031298C4A60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E28C5F7C6A4A78ULL,
		0x541AA0D802F61752ULL,
		0xF09D21D940D9F936ULL,
		0x7245D29628D0A45FULL,
		0x5A9D7FE70552C961ULL,
		0x7A3A80D39496D887ULL,
		0xE9C6978A412C5D3EULL,
		0xD692090E4BC1B90DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8A20440284A0A68ULL,
		0x040A005000A21252ULL,
		0x900C004900907804ULL,
		0x3040429008102046ULL,
		0x5099684300024840ULL,
		0x2A28004294800884ULL,
		0x200687800028491CULL,
		0x9090000009800800ULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C7706FD0158325ULL,
		0x4A130A85F04023C2ULL,
		0x36255741A3A10753ULL,
		0xA3F81A8AC3FDE348ULL,
		0x6BBC9F29361526DDULL,
		0xC621E8F551B4C3CDULL,
		0xEC0E9F822EE08075ULL,
		0xDD064D6A82F576BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C8EE4751A9817E0ULL,
		0x68084C15BAA32926ULL,
		0xB9F0451EB2F6D8B0ULL,
		0x133381EE13F8FE18ULL,
		0xE7EC70F2FE291DB4ULL,
		0xED0703892238346DULL,
		0x19DCF86CA33E1429ULL,
		0xD259841B1B9DB555ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0886606510100320ULL,
		0x48000805B0002102ULL,
		0x30204500A2A00010ULL,
		0x0330008A03F8E208ULL,
		0x63AC102036010494ULL,
		0xC40100810030004DULL,
		0x080C980022200021ULL,
		0xD000040A02953415ULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD697CC8A5C4C2084ULL,
		0xDD2833B0112286E7ULL,
		0xC472E5ABB33E36CBULL,
		0xFDE17FD78E88E419ULL,
		0x5BAF07C25CBE5639ULL,
		0x4A35114F2D78D433ULL,
		0xF9DB2BF64F0105D4ULL,
		0xCAC97D4304597C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA431DCF0CC935ACBULL,
		0x425A725B08030044ULL,
		0xC75A20D449633E3AULL,
		0xB7F96446A5155CA0ULL,
		0x96945B3CA87D1482ULL,
		0xCD3418558FC95DFBULL,
		0x5BDD086E1364800FULL,
		0xF043028AB786126CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8411CC804C000080ULL,
		0x4008321000020044ULL,
		0xC45220800122360AULL,
		0xB5E1644684004400ULL,
		0x12840300083C1400ULL,
		0x483410450D485433ULL,
		0x59D9086603000004ULL,
		0xC04100020400102CULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C2698211C732364ULL,
		0xB13B4A8824BA45D7ULL,
		0xEA046D9EDAB539B2ULL,
		0x940693B62CAB850DULL,
		0x011F923D7A8CF4DCULL,
		0xB01C86B5CB51833EULL,
		0xE7F44F9B428FF3BEULL,
		0xC20F9E8C38E21A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5477E57E2CA368EAULL,
		0x910FB925243E947DULL,
		0xF9C689E0CC41A022ULL,
		0x10C0A42938C53757ULL,
		0xB0E0A31DD80B33F9ULL,
		0x2DBF2EE7E3E85303ULL,
		0x37A8879445D43860ULL,
		0x12250756F78AE00DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x142680200C232060ULL,
		0x910B0800243A0455ULL,
		0xE8040980C8012022ULL,
		0x1000802028810505ULL,
		0x0000821D580830D8ULL,
		0x201C06A5C3400302ULL,
		0x27A0079040843020ULL,
		0x0205060430820009ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ACCF417B0138AA0ULL,
		0x6FB1D819A2CA5F95ULL,
		0x06EFC1CE7505DF83ULL,
		0xE88CBE0ABAC27A7FULL,
		0x6CF4DE335A7865D5ULL,
		0x6A685077DC5604FAULL,
		0x4A8FEFE59F46A242ULL,
		0x33CE8B6514753D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC645BF77012FBF92ULL,
		0xADD1ACADC32917E3ULL,
		0x0EC94578D28A7384ULL,
		0xB4C24F8F71FF72A5ULL,
		0x3430D4479B484810ULL,
		0xADACCEBCB3200B8AULL,
		0xD1A12253445C6A64ULL,
		0x0B79E3C8C7CD4C69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8244B41700038A80ULL,
		0x2D91880982081781ULL,
		0x06C9414850005380ULL,
		0xA0800E0A30C27225ULL,
		0x2430D4031A484010ULL,
		0x282840349000008AULL,
		0x4081224104442240ULL,
		0x0348834004450C28ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DF6EA180F80334FULL,
		0x3EBA8107B41030A4ULL,
		0x3FB595B0F2A6EF02ULL,
		0x7ACECACD279BBA9DULL,
		0x7EC0E7187517B7ECULL,
		0xA6157F426026AC81ULL,
		0xE2931CF9FBA646D1ULL,
		0x5FFE1E14C597B4B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C3B008DA0F36149ULL,
		0x378141FF79015834ULL,
		0x4E86EEECEF072CB8ULL,
		0xEFA01ED2910111D8ULL,
		0x289CFF68BF442FE5ULL,
		0xA5CE2F7ADDBA83E3ULL,
		0xF27A3ED4E004B2DEULL,
		0x1C52DE4259F94747ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C32000800802149ULL,
		0x3680010730001024ULL,
		0x0E8484A0E2062C00ULL,
		0x6A800AC001011098ULL,
		0x2880E708350427E4ULL,
		0xA4042F4240228081ULL,
		0xE2121CD0E00402D0ULL,
		0x1C521E0041910400ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x039E49FC6E2D00C4ULL,
		0x31BF6C789C6CFDCBULL,
		0x3AD88E0B85E6FAFAULL,
		0x5A712292BBE3C1FEULL,
		0x50D44ECA3E56DB22ULL,
		0x79ACE645F9D11F09ULL,
		0x4380A6546A0AC6E8ULL,
		0xA005CFB13B149DB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EC0C0135D723C7FULL,
		0x4FE5CB702339F968ULL,
		0x6E003E6F0CAF366EULL,
		0x463DF2F621910C1AULL,
		0x2004060E95A69D7CULL,
		0xD34D240E33E8422FULL,
		0xCD57D3FC05549903ULL,
		0xB3079AF173770D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028040104C200044ULL,
		0x01A548700028F948ULL,
		0x2A000E0B04A6326AULL,
		0x423122922181001AULL,
		0x0004060A14069920ULL,
		0x510C240431C00209ULL,
		0x4100825400008000ULL,
		0xA0058AB133140D10ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x955DB65E30CBA17AULL,
		0x24DAFB46A80FC1F5ULL,
		0x461850C0A8496136ULL,
		0x1DA2BD7C369E4D88ULL,
		0xD6277A623E9BD27FULL,
		0x803744338818D0C9ULL,
		0x417232CE82343AA1ULL,
		0xFC25C8F527F298F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6DE33021A598B5ULL,
		0x57D4E268F544F006ULL,
		0x467A4C1569EBD008ULL,
		0xC2590062EF2DD0F8ULL,
		0x4488F57841E0B968ULL,
		0x166B5ADF54C0A2C2ULL,
		0x3EA7CE0DAAD9164BULL,
		0xC8EB7002620814FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x144DA21020818030ULL,
		0x04D0E240A004C004ULL,
		0x4618400028494000ULL,
		0x00000060260C4088ULL,
		0x4400706000809068ULL,
		0x00234013000080C0ULL,
		0x0022020C82101201ULL,
		0xC8214000220010F7ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA039E0D44D03C951ULL,
		0xC5168C25D62309A2ULL,
		0x288A4ABA1B34D643ULL,
		0x94287F5FDD1754D7ULL,
		0x896E80E973DA543BULL,
		0xDFA649C3B6DD0B5CULL,
		0xB3B5AA3274C8E357ULL,
		0xD4227C23F898C078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D6DDF5D0DC504B2ULL,
		0xD45FB350FD423375ULL,
		0xC49147DF51B2DEB2ULL,
		0xD013237C332E6859ULL,
		0xD7AB3445C4BA5638ULL,
		0xD8D146C5BB3C721BULL,
		0x5C0129141D252A14ULL,
		0x9A77E628E0386EDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0029C0540D010010ULL,
		0xC4168000D4020120ULL,
		0x0080429A1130D602ULL,
		0x9000235C11064051ULL,
		0x812A0041409A5438ULL,
		0xD88040C1B21C0218ULL,
		0x1001281014002214ULL,
		0x90226420E0184058ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8EF221F1E198E1FULL,
		0x67480201693EC1CFULL,
		0x1C41EF60E8427ADCULL,
		0x24F70920B0C799A3ULL,
		0xE9693DBA3919E1ECULL,
		0x20BF89C573F2141AULL,
		0xEBAA5D72CFCD4446ULL,
		0x1517191E0182D12EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x399583815C9889DBULL,
		0x08A4D86B82A8D43BULL,
		0x7DAA8C1F06CE4E7BULL,
		0x904AE19C20C41FA8ULL,
		0x66FE62C365A2B7C2ULL,
		0xBA7011674B28CDDBULL,
		0x2B72016616FE96BAULL,
		0xA67CA0DE8C577F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x188502011C18881BULL,
		0x000000010028C00BULL,
		0x1C008C0000424A58ULL,
		0x0042010020C419A0ULL,
		0x606820822100A1C0ULL,
		0x203001454320041AULL,
		0x2B22016206CC0402ULL,
		0x0414001E0002512AULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E289221EBAB264EULL,
		0xB4F1F13023EAE5EEULL,
		0xFB41D211206D2C85ULL,
		0xE892B3850234C948ULL,
		0x5D59C9B6DB390675ULL,
		0x1716EB0753A9AA0FULL,
		0x7049F16A05970B12ULL,
		0x0168FBA2776580F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5681750BCD4070ECULL,
		0xBFD1F887AB751CF5ULL,
		0x33E938C82AF9CD93ULL,
		0x86EFDFA274D41C3FULL,
		0x645DE95AE9BED9F6ULL,
		0xEA60313F01EDD47EULL,
		0x2BA4E85A0BB207A6ULL,
		0x4CD23CAA42B8542AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06001001C900204CULL,
		0xB4D1F000236004E4ULL,
		0x3341100020690C81ULL,
		0x8082938000140808ULL,
		0x4459C912C9380074ULL,
		0x0200210701A9800EULL,
		0x2000E04A01920302ULL,
		0x004038A242200022ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD2AABF5957F19A1ULL,
		0xCEEFF233CD41BD8EULL,
		0x15045B92DFFCDDB0ULL,
		0x76F7085E7B7B8DF1ULL,
		0x7D2446CC87D4D33FULL,
		0xD77A3848DED09E24ULL,
		0x7EE2CD65BA6F0EA5ULL,
		0xC57FC18787BBF760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2502F6BD3F88DA50ULL,
		0xEDF3616AAF63760FULL,
		0x089137FDC856C1E2ULL,
		0x909BCA0294233D68ULL,
		0x2E0D865AD7257FB5ULL,
		0xADF343E5A6C7A994ULL,
		0xB63C092BB9DF1592ULL,
		0xE4D1C3E2CD9A81BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2502A2B515081800ULL,
		0xCCE360228D41340EULL,
		0x00001390C854C1A0ULL,
		0x1093080210230D60ULL,
		0x2C04064887045335ULL,
		0x8572004086C08804ULL,
		0x36200921B84F0480ULL,
		0xC451C182859A8120ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEAE6A61266DAB32ULL,
		0x6B69E7B01C3FFA42ULL,
		0x9B365F26BC9CAB99ULL,
		0x75EC416A17E4D6A8ULL,
		0x3F0347FBBA1CCD00ULL,
		0x1D02988E2BC91DB8ULL,
		0x668E795B5F570212ULL,
		0x6D6DF964D1E52E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9352D66D0BF1DFDFULL,
		0x34C614DE472A9051ULL,
		0xF6145ECAC5462AA2ULL,
		0xB2CFB266D6C2F9A4ULL,
		0xCDB028E80664192CULL,
		0x61F73A2D8847696AULL,
		0xD32B94611A87F37FULL,
		0xAE0F876F04A8C5EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8202426102618B12ULL,
		0x20400490042A9040ULL,
		0x92145E0284042A80ULL,
		0x30CC006216C0D0A0ULL,
		0x0D0000E802040900ULL,
		0x0102180C08410928ULL,
		0x420A10411A070212ULL,
		0x2C0D816400A00482ULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30534AC16B99C05DULL,
		0x9B38B2BE946394E9ULL,
		0x4D7F129D0B1CD2E1ULL,
		0xAE801DE445A9D461ULL,
		0x81282957C715ACA1ULL,
		0xDC1C836E8D0CCEBFULL,
		0xE9AEE83F7F69480EULL,
		0x1E39E7259FDF971BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A8D7D3E4BFA800ULL,
		0xC60226666E0DBAA2ULL,
		0x8CE8E2EBD62996ABULL,
		0x1D0710C7727F2A7CULL,
		0xE1273CC680084914ULL,
		0x3B6F82BA3FCE6EE6ULL,
		0x9EFC6E64346F3523ULL,
		0xD859998ADF02E25BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100042C160998000ULL,
		0x82002226040190A0ULL,
		0x0C680289020892A1ULL,
		0x0C0010C440290060ULL,
		0x8120284680000800ULL,
		0x180C822A0D0C4EA6ULL,
		0x88AC682434690002ULL,
		0x181981009F02821BULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9542AB8AAA26F9BULL,
		0x7EA37052ED8ACBD2ULL,
		0x7EA3C9D842A21954ULL,
		0xA1D3C06D1580220BULL,
		0xE3A85EA017D9A770ULL,
		0xF1511DB0D3842085ULL,
		0x69CAB6061EA513D1ULL,
		0x6F56A45F7C16BBC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD4990A0ACAE085ULL,
		0x170209D82611E4C8ULL,
		0x6125111954CC7654ULL,
		0x2819E2FA43FEA5FBULL,
		0x59A36A3B5A1A9F70ULL,
		0x4F06B3BA052DE5CEULL,
		0x7CC8F667D5079FFCULL,
		0xC50BB9B0D4DDAE4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x295408080A826081ULL,
		0x160200502400C0C0ULL,
		0x6021011840801054ULL,
		0x2011C0680180200BULL,
		0x41A04A2012188770ULL,
		0x410011B001042084ULL,
		0x68C8B606140513D0ULL,
		0x4502A0105414AA48ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0644B397C08E1C4EULL,
		0x85DF241EF6139DACULL,
		0x8B82A9FD59E4AADFULL,
		0x5E97F6A034EBD39EULL,
		0xAB52820E8643DA4EULL,
		0x9A6D2E9C4074C7C2ULL,
		0xF3E35A9EE1A29F60ULL,
		0xBE2083767ED5C437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D0E0DAB18635C8CULL,
		0x13BA898ECF02C704ULL,
		0xE2D4A3CB6F3AA7C7ULL,
		0x805338531A6C217AULL,
		0x97F3B1EDDCC54502ULL,
		0xAD007EE7B22CD95EULL,
		0x3E1595227F210887ULL,
		0x5C5CF3187E8D628DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0404018300021C0CULL,
		0x019A000EC6028504ULL,
		0x8280A1C94920A2C7ULL,
		0x001330001068011AULL,
		0x8352800C84414002ULL,
		0x88002E840024C142ULL,
		0x3201100261200800ULL,
		0x1C0083107E854005ULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDC6889CA93A385EULL,
		0x5EEBB0605A80B4ADULL,
		0x014261D356A90574ULL,
		0xAA5D81C18DC269DFULL,
		0x0630CF685E9860EDULL,
		0x9AADC7E4245AB461ULL,
		0x53524D47AD3724D2ULL,
		0x34C5728471D06152ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCB9325E6FA2E84ULL,
		0x53D3B597B3BB4528ULL,
		0x3B736D205ABEAEE5ULL,
		0xE32BEDE1C4E6B303ULL,
		0xAD38206FFAC60DC7ULL,
		0xCC42B2365BC79CFAULL,
		0x15806D11105A89A2ULL,
		0xF61DA9AF599817A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CC28004A03A2804ULL,
		0x52C3B00012800428ULL,
		0x0142610052A80464ULL,
		0xA20981C184C22103ULL,
		0x043000685A8000C5ULL,
		0x8800822400429460ULL,
		0x11004D0100120082ULL,
		0x3405208451900100ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC658CD0A69031B82ULL,
		0xCF7877766C99ECD6ULL,
		0x6C9F616416FEA409ULL,
		0x81DE5482E62715F7ULL,
		0xB46849CD5A92F3A1ULL,
		0xEB13F6B74B294F5CULL,
		0x54765366CA3B3AA5ULL,
		0x6197EE781AD07AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DFAACB7339B511CULL,
		0x649136F539EB05A9ULL,
		0xE91398548A6FA2B7ULL,
		0xD9AA620AA4F6E300ULL,
		0xD3AB6BEE54B0DA3EULL,
		0xCD9A227A2A731C1DULL,
		0x4B74B6D6F2D67FBAULL,
		0xF4263FEC4BD0330CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44588C0221031100ULL,
		0x4410367428890480ULL,
		0x68130044026EA001ULL,
		0x818A4002A4260100ULL,
		0x902849CC5090D220ULL,
		0xC91222320A210C1CULL,
		0x40741246C2123AA0ULL,
		0x60062E680AD03204ULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x890DEA4E75C4E043ULL,
		0x031D7346319E1ED2ULL,
		0x7D7CE0102F240E1BULL,
		0xBD9399257F18BFEFULL,
		0x277008280346F1EDULL,
		0x23EA1E551CDFCF85ULL,
		0x64345E63AC2D7ADDULL,
		0x87D6704CDD622627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8339B6692457388ULL,
		0x09B3C7601A5A4CE5ULL,
		0x381FCD21CFF0EBE7ULL,
		0xFF0B3A258FA244E1ULL,
		0x666B3CF834AC9D33ULL,
		0xDD99CD42E1E1AD9BULL,
		0xBE7ACAFF9AFBC8DAULL,
		0x00289CD710EBBFBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88018A4610446000ULL,
		0x01114340101A0CC0ULL,
		0x381CC0000F200A03ULL,
		0xBD0318250F0004E1ULL,
		0x2660082800049121ULL,
		0x01880C4000C18D81ULL,
		0x24304A63882948D8ULL,
		0x0000104410622624ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D3AE0622D4C7D30ULL,
		0x379259E3C4783FDAULL,
		0x5A2F3072BC74B307ULL,
		0xA95019E7487EC9BFULL,
		0xD233CB5CE95C1718ULL,
		0x53F4499976814005ULL,
		0x01D7202176B1606EULL,
		0xA78ECA598860D8A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB0A732F9425CEAFULL,
		0x873D4F31AAA3C212ULL,
		0xF815BC9AA5166A18ULL,
		0x0934CE1615196A8AULL,
		0x82D2F6DAA76518ADULL,
		0x60036496C79B4474ULL,
		0x315692A64DFA6AB2ULL,
		0xB4F57F9B7280C9FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x090A602204044C20ULL,
		0x0710492180200212ULL,
		0x58053012A4142200ULL,
		0x091008060018488AULL,
		0x8212C258A1441008ULL,
		0x4000409046814004ULL,
		0x0156002044B06022ULL,
		0xA4844A190000C8A0ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3AD775537ABCFB2ULL,
		0x24C7670A8D40759AULL,
		0xA8E62174356AB8F0ULL,
		0xB2856094DCEEB0C1ULL,
		0x2720DA922CBC3B04ULL,
		0x9D8CE1FD9D226B62ULL,
		0x88EB4778940D2623ULL,
		0xBE43EBD46BAF9857ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB41633C993079D53ULL,
		0x7796829E78A252C3ULL,
		0xC039E07D03987EBBULL,
		0xD0BA83EA796CD8CEULL,
		0x0132E036FCF018C7ULL,
		0xFB73436C44389776ULL,
		0x873B3E92CCA865A5ULL,
		0x156A6441CC2EAABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9004334113038D12ULL,
		0x2486020A08005082ULL,
		0x80202074010838B0ULL,
		0x90800080586C90C0ULL,
		0x0120C0122CB01804ULL,
		0x9900416C04200362ULL,
		0x802B061084082421ULL,
		0x14426040482E8817ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D35E1D8A4D39F8DULL,
		0xBD78312B4487653FULL,
		0x4DAA7260C2F65961ULL,
		0x76F388DFD1DAD19DULL,
		0xED61CFCB10C043CDULL,
		0x10BD815A44EA5547ULL,
		0xD98942169ABFCE61ULL,
		0xA171B7662FE32653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6346F48ABF6A16F9ULL,
		0x6949212E20215C36ULL,
		0x4209D2D325AF2946ULL,
		0x4B4614BD001470C3ULL,
		0xC5F647C6D0FD08F2ULL,
		0xBD9F289B4EECDF6FULL,
		0x11D0E7E505FE97ECULL,
		0x2F2A990955544E96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0104E088A4421689ULL,
		0x2948212A00014436ULL,
		0x4008524000A60940ULL,
		0x4242009D00105081ULL,
		0xC56047C210C000C0ULL,
		0x109D001A44E85547ULL,
		0x1180420400BE8660ULL,
		0x2120910005400612ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC553C4CF3428732ULL,
		0xF3F59E218D005EDDULL,
		0xC5A872F0ABBE05A1ULL,
		0x42FD3617929A3C5AULL,
		0x8592B5CD77617880ULL,
		0x40AC9C1EA99C4FA7ULL,
		0xDE8B6BB2C19213B2ULL,
		0x4480ED5D502D7288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA903DD2AC5AE0AULL,
		0xD66E8D40DECBCCE6ULL,
		0x58AC0C3C12D6895BULL,
		0x4513E5B28674FA66ULL,
		0xDE94B0312EBF456CULL,
		0xFBB80D5AC20B511CULL,
		0xB085E315DFC7541AULL,
		0x370F0EA487FC829FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC01004C22408602ULL,
		0xD2648C008C004CC4ULL,
		0x40A8003002960101ULL,
		0x4011241282103842ULL,
		0x8490B00126214000ULL,
		0x40A80C1A80084104ULL,
		0x90816310C1821012ULL,
		0x04000C04002C0288ULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAEB94E495CE7F25ULL,
		0x47E953BA04AFA75EULL,
		0xB2A94B94723669A1ULL,
		0x0140CEB34DB7C0FBULL,
		0x4A0831919096BE3DULL,
		0x7CF2CCF478AD92F0ULL,
		0x8BD37DFDE91C7955ULL,
		0xD53015C8EDD20E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A742DE809351B8CULL,
		0x6FA7087B6F08D8CDULL,
		0x0BBC85C720196D6BULL,
		0x96CAD49D5D320932ULL,
		0x74BB0A6A93EFB149ULL,
		0xAC3ECB39CA2CDB96ULL,
		0xB174C347461360CFULL,
		0x9DD4F424B0788B73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A6004E001041B04ULL,
		0x47A1003A0408804CULL,
		0x02A8018420106921ULL,
		0x0040C4914D320032ULL,
		0x400800009086B009ULL,
		0x2C32C830482C9290ULL,
		0x8150414540106045ULL,
		0x95101400A0500A10ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB8315BF06664252ULL,
		0x749776F4F566EB94ULL,
		0xFB1F9F939A5C49EEULL,
		0xF2AF4FB53673A0E2ULL,
		0xDBF759A208ED641DULL,
		0xE26549ACF6556E4BULL,
		0xE93E68DDE1732E1FULL,
		0x949A3C9A3845A220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5EA27AAE92C77C2ULL,
		0x2A10766B50D77875ULL,
		0xB14D57B47F1F5060ULL,
		0x91F9AC0FAB94A7C2ULL,
		0x74E27808B4EE0E36ULL,
		0x8C62095F45D9FFB5ULL,
		0xF735BCE61BE02BDBULL,
		0x71BF53D38B8F6FCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE18205AA00244242ULL,
		0x2010766050466814ULL,
		0xB10D17901A1C4060ULL,
		0x90A90C052210A0C2ULL,
		0x50E2580000EC0414ULL,
		0x8060090C44516E01ULL,
		0xE13428C401602A1BULL,
		0x109A109208052200ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F4D84115414A146ULL,
		0x1244DB1639A98F40ULL,
		0x3ABD379FD9EDF190ULL,
		0xDF1CEA465D893AFEULL,
		0x8C44D83EE7CC1892ULL,
		0x529C607DBDE4BA7CULL,
		0x112F0825BB1AEBDEULL,
		0xF660902904342E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C590AF1035032EULL,
		0x2264728138531F2FULL,
		0x2A58F6E608C53B0CULL,
		0x399964AF01558B97ULL,
		0x46579B628F02D059ULL,
		0x65C42A95A2318DB5ULL,
		0x6DC96F2267219FB9ULL,
		0xB50F6B3F9E009735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2745800110140106ULL,
		0x0244520038010F00ULL,
		0x2A18368608C53100ULL,
		0x1918600601010A96ULL,
		0x0444982287001010ULL,
		0x40842015A0208834ULL,
		0x0109082023008B98ULL,
		0xB400002904000601ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1A9CBF67C48DF62ULL,
		0x301D44CFB0C05CE9ULL,
		0xD9F5A706CD539B4FULL,
		0xBE18CAD6583F1ABDULL,
		0xCCB5DAA74B7E12E1ULL,
		0x73916800704C67C7ULL,
		0xAC8B9F45D497E7A8ULL,
		0x5876ED7B81D3AA08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEA04D6B7B499742ULL,
		0x65121E708BC0713BULL,
		0x9FB213C8B65F0559ULL,
		0xAE5A072E7ED4FC08ULL,
		0x9444227AC263987BULL,
		0x59E3F65391FA57BAULL,
		0xA39A75316897F982ULL,
		0x7FA24E03C68B1E83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0A0496278489742ULL,
		0x2010044080C05029ULL,
		0x99B0030084530149ULL,
		0xAE18020658141808ULL,
		0x8404022242621061ULL,
		0x5181600010484782ULL,
		0xA08A15014097E180ULL,
		0x58224C0380830A00ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCD2244C91086864ULL,
		0x88A019C999959F04ULL,
		0x00B0CFBF446A3CA1ULL,
		0x6EB4BE8F45DEDA36ULL,
		0x54DAB5B55FD67A15ULL,
		0xF9F78D686AAC5D35ULL,
		0x62316FD861659798ULL,
		0x632AD2A2C4F28FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76EBDCDAD0B18183ULL,
		0x26432C8C06F51600ULL,
		0x03524C3FDB68F913ULL,
		0xE0C6734AA685AEB0ULL,
		0xDCF5AF540F5AAE7CULL,
		0x3F28BB0AD82C6313ULL,
		0xD49C0CB9C6A5077CULL,
		0xD9B5668A23A8390FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54C2044890000000ULL,
		0x0000088800951600ULL,
		0x00104C3F40683801ULL,
		0x6084320A04848A30ULL,
		0x54D0A5140F522A14ULL,
		0x39208908482C4111ULL,
		0x40100C9840250718ULL,
		0x4120428200A00907ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF83544FA3FED020ULL,
		0xC2C5D6E7E0BCABD7ULL,
		0x6E63AC06EC097E2AULL,
		0x587609CAFAF5F774ULL,
		0x0663FF1997968DF8ULL,
		0x7945BA42B638C99CULL,
		0x444D9F4F34F9B6EEULL,
		0x9F2A9AC13684B087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFF60F9698E00417ULL,
		0x96E20DFD7DBBD97DULL,
		0x119EEE1068581E75ULL,
		0x95699A2269A7845BULL,
		0x4C818B5CDE850E00ULL,
		0xF0B923301D566C05ULL,
		0x71D4E986E310CCFAULL,
		0x8D2A32AEBEC292A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F82040680E00000ULL,
		0x82C004E560B88955ULL,
		0x0002AC0068081E20ULL,
		0x1060080268A58450ULL,
		0x04018B1896840C00ULL,
		0x7001220014104804ULL,
		0x40448906201084EAULL,
		0x8D2A128036809081ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E1C224C770141A3ULL,
		0xF11805098F9D19CCULL,
		0xC7D9D6AE30A2E6C2ULL,
		0xC7B561760811A39FULL,
		0xC020233C134827F6ULL,
		0xC9A77FF379AB7BFFULL,
		0xD0EB03640A4A2A2FULL,
		0xE3F4BC79133F6953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C6F4E122AD756B0ULL,
		0x36861ED55CCB0449ULL,
		0x495509EAB41BFFD1ULL,
		0xE62E20F8EF3A5ACCULL,
		0xC234F80D17951DCBULL,
		0x20A3FE10CA5A8181ULL,
		0xC8D3D5BF408E3D0BULL,
		0x4C423C253195EB64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0C0200220140A0ULL,
		0x300004010C890048ULL,
		0x415100AA3002E6C0ULL,
		0xC62420700810028CULL,
		0xC020200C130005C2ULL,
		0x00A37E10480A0181ULL,
		0xC0C30124000A280BULL,
		0x40403C2111156940ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74D1F80950B5638CULL,
		0x619BC8E6468385BEULL,
		0xF0120F3D45CCE8FDULL,
		0xEE757B3D71A7502CULL,
		0x08681ACE40AEBE73ULL,
		0x7887D61C53139634ULL,
		0x214F5283D2866A2BULL,
		0x98CB13964EF36772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBA0C28468B0134ULL,
		0x9F3FAFA0C0C79071ULL,
		0xA14C4B0B7617DC10ULL,
		0xB5B301E403A31402ULL,
		0x23DBF3092D823483ULL,
		0xAE82F6C4261F4EAAULL,
		0x32AFFA3828C0B413ULL,
		0x870C83985C0D3B59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7090080840810104ULL,
		0x011B88A040838030ULL,
		0xA0000B094404C810ULL,
		0xA431012401A31000ULL,
		0x0048120800823403ULL,
		0x2882D60402130620ULL,
		0x200F520000802003ULL,
		0x800803904C012350ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA366ACBBFF53710ULL,
		0xEB078878AEF25066ULL,
		0x8C62B4AC1AEFE748ULL,
		0x524E169D1FF64777ULL,
		0xB6A969862B88EC53ULL,
		0x72A9BE3E3EE8CCA8ULL,
		0x43140E37A347A995ULL,
		0xC0DA2A28FFD55362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F913292A1EDD39ULL,
		0x1FA0F0F7835C9F5EULL,
		0xB6095C2A2714A269ULL,
		0x09487DF6687FB9F1ULL,
		0x79A79D22BA0ADDB8ULL,
		0x0E332EEB61A3AE7EULL,
		0x1CCB8C47BB9692E0ULL,
		0x85ED5F4030B1FAB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC23002092A141510ULL,
		0x0B00807082501046ULL,
		0x840014280204A248ULL,
		0x0048149408760171ULL,
		0x30A109022A08CC10ULL,
		0x02212E2A20A08C28ULL,
		0x00000C07A3068080ULL,
		0x80C80A0030915220ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99DE6F531F97269BULL,
		0xD851D36E463F0B04ULL,
		0x517FF67F9E912D48ULL,
		0x9CF8E1CF01A405C4ULL,
		0x4AFB3316EB5E6F25ULL,
		0x70DD6770C2FCBD5FULL,
		0xCB2720E5BC110CBEULL,
		0xB01FDDCB10009FACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12167AF0692C7546ULL,
		0x02CA6602B3D0D77DULL,
		0x537852E9FE82529FULL,
		0x7DF364BAB3255CF3ULL,
		0x60DC980B8ED3BE0AULL,
		0x0E9B2ED52F38D63AULL,
		0x2B474E9E6D3DED92ULL,
		0x8910D02BE780F291ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10166A5009042402ULL,
		0x0040420202100304ULL,
		0x517852699E800008ULL,
		0x1CF0608A012404C0ULL,
		0x40D810028A522E00ULL,
		0x009926500238941AULL,
		0x0B0700842C110C92ULL,
		0x8010D00B00009280ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAA9E38601AEBCAEULL,
		0x41FBBC971060E55EULL,
		0xF0801A01515E0A2AULL,
		0xCE973FFC73F86B3CULL,
		0xAE5572ED3D8F1D9FULL,
		0xC8CFA211C18AFE0BULL,
		0xBE197A5F7EB5860AULL,
		0x8B956B788D3D302CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x850D2A2E449F6B3FULL,
		0xA2A7D8C7C3C900E9ULL,
		0x9CC7CAC61B4D8328ULL,
		0xF7EAE5F741C21241ULL,
		0x9A17D60AB93639CCULL,
		0x873D1F1034C3C87AULL,
		0x85F7E496770E5192ULL,
		0xA31F97BB3F0D05E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80092206008E282EULL,
		0x00A3988700400048ULL,
		0x90800A00114C0228ULL,
		0xC68225F441C00200ULL,
		0x8A1552083906198CULL,
		0x800D02100082C80AULL,
		0x8411601676040002ULL,
		0x831503380D0D0024ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F277A0704A2DD09ULL,
		0x1E2703DC083284A2ULL,
		0x7B5C697D78D108ADULL,
		0xD6B0216C1EABF535ULL,
		0x4C512B5779A75B13ULL,
		0xD64D5524F7542143ULL,
		0x83230362310E7863ULL,
		0xC0B1909B40AC5BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB45B4BC9C0E5CAA7ULL,
		0x0E8F1496595D26CBULL,
		0x719C18C1D595D4CBULL,
		0x9611B76B0A3E6318ULL,
		0x04756D6AAAB2D3E3ULL,
		0x522BAAA4453C2ABEULL,
		0xEB9337F45D4AF0C1ULL,
		0x65A472BFB467F226ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94034A0100A0C801ULL,
		0x0E07009408100482ULL,
		0x711C084150910089ULL,
		0x961021680A2A6110ULL,
		0x0451294228A25303ULL,
		0x5209002445142002ULL,
		0x83030360110A7041ULL,
		0x40A0109B00245206ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC3F80C10634DE2EULL,
		0x1CD981AD835DBBC9ULL,
		0x7635108CD58646F1ULL,
		0x892FF2BA23A08614ULL,
		0x40FEF65CF126659FULL,
		0xF9C8B9416E8F6767ULL,
		0xCCBAF562B7B5C2B6ULL,
		0xE6E88F62590AE196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8623231CB2DBA21ULL,
		0x525E5E1E558B0F04ULL,
		0x69A1F0ECF938BB6DULL,
		0x8CC3B97FB7AB8584ULL,
		0x30E26438D98D8266ULL,
		0x81660EBE10C9EF64ULL,
		0x08E51E7A54DEE542ULL,
		0xDB3E50A590ECC9BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA822000102249A20ULL,
		0x1058000C01090B00ULL,
		0x6021108CD1000261ULL,
		0x8803B03A23A08404ULL,
		0x00E26418D1040006ULL,
		0x8140080000896764ULL,
		0x08A014621494C002ULL,
		0xC22800201008C196ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40FC684D86D1F8C5ULL,
		0xE523FCC7923B9D1BULL,
		0x879D8318B608C4B7ULL,
		0x449B6ABE8DF24D2FULL,
		0xCE9FA2B0F05FB69FULL,
		0x066DDC2C2DEA87BBULL,
		0xD180F4DDDBE62DB5ULL,
		0x3CA402BCF081B3AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FE830D7D3578D8CULL,
		0x8E7542C3D168BA8AULL,
		0x908869AF8EE2FB50ULL,
		0x5F6C03875D43F657ULL,
		0x2DC1A139BD8BC63FULL,
		0x7252A86F4A49D118ULL,
		0xCC28BE1DA0C3FF4DULL,
		0xF5A5C23C325AF1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00E8204582518884ULL,
		0x842140C39028980AULL,
		0x808801088600C010ULL,
		0x440802860D424407ULL,
		0x0C81A030B00B861FULL,
		0x0240882C08488118ULL,
		0xC000B41D80C22D05ULL,
		0x34A4023C3000B1A8ULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x808E160B6131212AULL,
		0x7FB4741373B32538ULL,
		0xEBC033F98EFC138AULL,
		0x6275175357D6F745ULL,
		0x5CA1052412CB0C40ULL,
		0xD904D85EAF3526E3ULL,
		0x93C7CAFD31A26679ULL,
		0x42127C17193DD640ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43996032B2E2B32EULL,
		0xD4FA86887475D139ULL,
		0xCCE43E64DAF8FF56ULL,
		0x679E38A57DD9A930ULL,
		0x259D001DDAC92810ULL,
		0x2A6E3D5A5D30EC1AULL,
		0x377B3F8C6B989B2EULL,
		0x01E67196614274E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008800022020212AULL,
		0x54B0040070310138ULL,
		0xC8C032608AF81302ULL,
		0x6214100155D0A100ULL,
		0x0481000412C90800ULL,
		0x0804185A0D302402ULL,
		0x13430A8C21800228ULL,
		0x0002701601005440ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE479D9F4A15E56F1ULL,
		0xE6FCBCD672641D44ULL,
		0xEE3CC6D8B3C8D8A7ULL,
		0x4695BC5AAC6B4290ULL,
		0x39D90984B508A58EULL,
		0x234E00501D2E241EULL,
		0xA1D1826C49345C91ULL,
		0x76A19F1D9225087AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C4584AD78303868ULL,
		0xE542A4637745D945ULL,
		0xAB7E45CF7842B2FBULL,
		0x9E763E1FDFFB40B1ULL,
		0x489B83133A96F4E5ULL,
		0xE63004D78CA12B3EULL,
		0x850A1341905EF73FULL,
		0x5FCF37A5CDAFD618ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x244180A420101060ULL,
		0xE440A44272441944ULL,
		0xAA3C44C8304090A3ULL,
		0x06143C1A8C6B4090ULL,
		0x089901003000A484ULL,
		0x220000500C20201EULL,
		0x8100024000145411ULL,
		0x5681170580250018ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D26350C596A3DD0ULL,
		0x890E829A011CF483ULL,
		0x2E98D7CB3399814DULL,
		0x40B10A3343A5A77EULL,
		0x36120329A3706D02ULL,
		0x439FDDBA611E457DULL,
		0x86C0927D1C967534ULL,
		0xFE70E90ABFC6D465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC0B3397E0B14B8ULL,
		0x18495B4A5125AB11ULL,
		0xB77BE92AC161EF82ULL,
		0x5C1B9FA58F8FCE09ULL,
		0x51F99F98F99C457DULL,
		0xE5DD6D59C9EFDA3BULL,
		0x72EDF858B8E6996DULL,
		0x1C60498CE39433FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D003108580A1490ULL,
		0x0808020A0104A001ULL,
		0x2618C10A01018100ULL,
		0x40110A2103858608ULL,
		0x10100308A1104500ULL,
		0x419D4D18410E4039ULL,
		0x02C0905818861124ULL,
		0x1C604908A3841065ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FBC2B62AAFF5096ULL,
		0xD26D82305D2DD659ULL,
		0xC75C63D23C4ED38FULL,
		0x34DD893E63A04BAAULL,
		0xDAC81E4C65E553E5ULL,
		0x1EA23FD3B61F264FULL,
		0xD702DA737DD049EBULL,
		0xDDC7AC832FBECF80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73ABB006739EBD34ULL,
		0x2CD4E58A32A1A206ULL,
		0x2463C67F5C086C6AULL,
		0xD08F1A2F21264A56ULL,
		0xA83A374188B4E41AULL,
		0x77A2CF8E6E16A93BULL,
		0xC9D0292BE2CE6F06ULL,
		0xADFEC63625EBB4B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23A82002229E1014ULL,
		0x0044800010218200ULL,
		0x044042521C08400AULL,
		0x108D082E21204A02ULL,
		0x8808164000A44000ULL,
		0x16A20F822616200BULL,
		0xC100082360C04902ULL,
		0x8DC6840225AA8480ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7848B3AA8D257106ULL,
		0xA47B992063B4672FULL,
		0x71CE467798907BCBULL,
		0x158C9CDC9F9AECCCULL,
		0x5B45626DFDC4AA0FULL,
		0x8203FF3A8C551C62ULL,
		0xE78C5854C43AE98CULL,
		0x97EAA1E2DD100E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD084D10A2C800C2FULL,
		0x48667BE9FB567A0CULL,
		0x8CA722CB097CF484ULL,
		0x73AECEA027C1A591ULL,
		0x0747F7EF62DD5E05ULL,
		0x061149E9B478D4ABULL,
		0xE25AB0E6463102BAULL,
		0xBAF3C2FB624CE5C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5000910A0C000006ULL,
		0x006219206314620CULL,
		0x0086024308107080ULL,
		0x118C8C800780A480ULL,
		0x0345626D60C40A05ULL,
		0x0201492884501422ULL,
		0xE208104444300088ULL,
		0x92E280E240000442ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38BD79BAD1AABEC1ULL,
		0xDE1B021B0955212EULL,
		0x3F31A5EF123E838AULL,
		0xF2B42DD5060A95ABULL,
		0x51D79A8F54FDEBBDULL,
		0x52A2710276596CF4ULL,
		0x22C6A88C9614BC35ULL,
		0xF785EA11B109864BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267FC57843201E2BULL,
		0x8AA7D9D5F593EFD5ULL,
		0xE80A79664E6BF5ACULL,
		0x8A4A3BF489A41751ULL,
		0xEC2C94815A6E5C1FULL,
		0xD85FE71B4D3290E7ULL,
		0xAC3F57A0691E68CAULL,
		0x90F9DDA28D50E9B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x203D413841201E01ULL,
		0x8A03001101112104ULL,
		0x28002166022A8188ULL,
		0x820029D400001501ULL,
		0x40049081506C481DULL,
		0x50026102441000E4ULL,
		0x2006008000142800ULL,
		0x9081C80081008008ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E96232F4757B225ULL,
		0x1D43C09E2786578BULL,
		0xCCF24D5F61026BA6ULL,
		0x1E2348E445A7C5B1ULL,
		0x91CB5BEF55416D0DULL,
		0x1A0191244971145FULL,
		0x40EFB60C7953BC4EULL,
		0x5ABAA98E61A3D837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3C0A6E869E0375ULL,
		0x43E837165AC62FC5ULL,
		0xFEBE3A40E7C28377ULL,
		0x795AA9640DFF9E2EULL,
		0x1E0C3AEB642343A3ULL,
		0x97E27744055BC0D0ULL,
		0x70CAF0A920257AC0ULL,
		0x8DF847CE0CA8D60FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A14022E06160225ULL,
		0x0140001602860781ULL,
		0xCCB2084061020326ULL,
		0x1802086405A78420ULL,
		0x10081AEB44014101ULL,
		0x1200110401510050ULL,
		0x40CAB00820013840ULL,
		0x08B8018E00A0D007ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AAB4DB583FC41C9ULL,
		0x84DA230A9E492A39ULL,
		0x800A36852E53D98FULL,
		0xEA1A7A7596E96375ULL,
		0xE6603C8907B2A334ULL,
		0xDAFE9555CF00CDA4ULL,
		0x1B78C5243FDC60E7ULL,
		0x224FDD2A0274245CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2481513A36AC898FULL,
		0x9CD3D6DEF9637CC8ULL,
		0x628E274948566710ULL,
		0x5C06B61961F95001ULL,
		0x101A99829D32EB0FULL,
		0x72F82490F623C76EULL,
		0x671194505A565511ULL,
		0x3E4DB0433858234FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0081413002AC0189ULL,
		0x84D2020A98412808ULL,
		0x000A260108524100ULL,
		0x4802321100E94001ULL,
		0x000018800532A304ULL,
		0x52F80410C600C524ULL,
		0x031084001A544001ULL,
		0x224D90020050204CULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEB7BB41D1F69D00ULL,
		0xE0BC621E9DC26F93ULL,
		0xE00359F5F46BBFC8ULL,
		0xD9DDFFAE069DF4A3ULL,
		0x2ED809A901D02598ULL,
		0x743BBFF3D546F85CULL,
		0x0C23754777BE617CULL,
		0x87B3C641E75C8F6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EEDCEDE7020916ULL,
		0x3EF80C5E658D0FB2ULL,
		0x49A47C247AC32571ULL,
		0x75AF6956CE7A8805ULL,
		0xAB65C035A066D34CULL,
		0x124C16D5990869FBULL,
		0xD0EFE41322B8AF21ULL,
		0xF6739B35EAF823D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A69841C1020900ULL,
		0x20B8001E05800F92ULL,
		0x4000582470432540ULL,
		0x518D690606188001ULL,
		0x2A40002100400108ULL,
		0x100816D191006858ULL,
		0x0023640322B82120ULL,
		0x86338201E2580342ULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89A06B77382215AAULL,
		0x7F2944EE8DCB4DBEULL,
		0xFCFC222C6E7626CAULL,
		0x516A5540EE0A744EULL,
		0x7FF9E08BDEE290A0ULL,
		0xBCEAD2F7E3A8FA20ULL,
		0xAFC1891AF2BF9C60ULL,
		0xFBDEB63C51BEA907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97367AA9A9BA1956ULL,
		0x76D84C9175955B0AULL,
		0x67FF660ED059421FULL,
		0xA6B76DCE44735655ULL,
		0xA02356E4ED417A6CULL,
		0x2524E5F3195D323EULL,
		0xA95C8DB2D0FC5173ULL,
		0xADF70F3E766DE1C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81206A2128221102ULL,
		0x760844800581490AULL,
		0x64FC220C4050020AULL,
		0x0022454044025444ULL,
		0x20214080CC401020ULL,
		0x2420C0F301083220ULL,
		0xA9408912D0BC1060ULL,
		0xA9D6063C502CA100ULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC5427DA9FB7AEF7ULL,
		0xFD5972DBCA5B7EC5ULL,
		0xD7C48662F4EF2303ULL,
		0x2DA63CE9F15F06C8ULL,
		0xF9AA03A44A836198ULL,
		0xD392F05285C61A51ULL,
		0x91E26E024BF9434FULL,
		0xFFF000CCFF09B60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD631382173A126AULL,
		0xB08A6765C14F9843ULL,
		0xF6C927B82D4719F2ULL,
		0x98742C3BAC009F94ULL,
		0x62462C07F8C00E57ULL,
		0x0F41B9467359C413ULL,
		0x67A8690ED733FAADULL,
		0x31E7631B90CDC810ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC40038217320262ULL,
		0xB0086241C04B1841ULL,
		0xD6C0062024470102ULL,
		0x08242C29A0000680ULL,
		0x6002000448800010ULL,
		0x0300B04201400011ULL,
		0x01A068024331420DULL,
		0x31E0000890098000ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF14D931180F31396ULL,
		0x615170EACD8B2E00ULL,
		0xEF1652D76668FCD9ULL,
		0xB56F716D5AE1253AULL,
		0x37A7A76B673E47BCULL,
		0x5739F72FF508BBBBULL,
		0x9015F4F36A649D55ULL,
		0xA2F866CD44B06A2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158489A2DAEA1528ULL,
		0xF613777E0B35EBB2ULL,
		0x801AF0D26CC38CFEULL,
		0x82465B91EBC8FF8FULL,
		0xB7A176034AB257D4ULL,
		0xE95765F9349B1D20ULL,
		0x90400E6B2660E4C0ULL,
		0xAF4E62EEB2F20793ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1104810080E21100ULL,
		0x6011706A09012A00ULL,
		0x801250D264408CD8ULL,
		0x804651014AC0250AULL,
		0x37A1260342324794ULL,
		0x4111652934081920ULL,
		0x9000046322608440ULL,
		0xA24862CC00B00201ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5F52550F0E57E8DULL,
		0xC172465C4E35AB70ULL,
		0x0018537CBF789854ULL,
		0xA628FE5185D26490ULL,
		0xDDD29F16DE29D9E9ULL,
		0xE7A74CB6B951C830ULL,
		0x6D242CA2B6F9C508ULL,
		0x177E6FFF778BD7DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7A5506F75832283ULL,
		0x6212DE69B95FE4AEULL,
		0x51CB51A14B757EAFULL,
		0x910554126ABD6983ULL,
		0x46260C809D968822ULL,
		0xB0CF6972E7A6E9D1ULL,
		0x3DAA07269CB2C487ULL,
		0x623112837E8B3D7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95A5004070812281ULL,
		0x401246480815A020ULL,
		0x000851200B701804ULL,
		0x8000541000906080ULL,
		0x44020C009C008820ULL,
		0xA0874832A100C810ULL,
		0x2D20042294B0C400ULL,
		0x02300283768B1558ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8604FE04B38CBDE6ULL,
		0xDFC93188129500CEULL,
		0x4530289AE0BBB041ULL,
		0xB8B6CFB31B287740ULL,
		0x98B6ED6A69C0C42CULL,
		0x62CCC276CE4E9E04ULL,
		0x18AE57CC034080C4ULL,
		0x6F822CCC276C2EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A362538DB86FB3ULL,
		0x46AA4A0871B57651ULL,
		0x45DD28C60A98049DULL,
		0xB812EB9B0291F286ULL,
		0x0C686E0B34F3A3C5ULL,
		0x32B612EDA684BF90ULL,
		0xE0CE4A3E65F817EFULL,
		0xEB709B03A5487361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000620081882DA2ULL,
		0x4688000810950040ULL,
		0x4510288200980001ULL,
		0xB812CB9302007200ULL,
		0x08206C0A20C08004ULL,
		0x2284026486049E00ULL,
		0x008E420C014000C4ULL,
		0x6B00080025482241ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x640CD3A28FCCDE0AULL,
		0xEF6D663B85D28EC2ULL,
		0xCEAF967714185B84ULL,
		0x4EAAF4AC45CA90D5ULL,
		0x6ADD82F3EEB64906ULL,
		0x54CAC8A8CAD89D36ULL,
		0xE0C3CC51692572EBULL,
		0xD4DA9719EBD1DF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A165E883304A2A9ULL,
		0x67D721A75184BAACULL,
		0xCF903AE23F117B87ULL,
		0xC4151279F22C6710ULL,
		0x960A86446E43DCAEULL,
		0x40D1F4633AB4B69FULL,
		0x4A30CCBCB50030D2ULL,
		0x51C30132F4E959BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004528003048208ULL,
		0x6745202301808A80ULL,
		0xCE80126214105B84ULL,
		0x4400102840080010ULL,
		0x020882406E024806ULL,
		0x40C0C0200A909416ULL,
		0x4000CC10210030C2ULL,
		0x50C20110E0C1598AULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBAA2637389581CBULL,
		0xD670C7BEE58C99EBULL,
		0x1A0CFAFD214E8E64ULL,
		0x2F4AFF16133947D5ULL,
		0xF80ED8FDBCD7D697ULL,
		0x7553D696394E2DF3ULL,
		0x5FA8C31F73BA8D16ULL,
		0x1D7DE1A75F452092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1827EB779D31AE4ULL,
		0xE8A5EDC8A3C40168ULL,
		0x6C1946B66D2120C7ULL,
		0x86267B7FD62D8407ULL,
		0xF21DD868F590A395ULL,
		0x51E0BF777CB77EC8ULL,
		0x0E516815DF5D2397ULL,
		0x21F6C3B78A260408ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1822637389100C0ULL,
		0xC020C588A1840168ULL,
		0x080842B421000044ULL,
		0x06027B1612290405ULL,
		0xF00CD868B4908295ULL,
		0x5140961638062CC0ULL,
		0x0E00401553180116ULL,
		0x0174C1A70A040000ULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5040B1B57F7A3300ULL,
		0xA557798377D15AEAULL,
		0x3DB64CF9731CFEE3ULL,
		0x414D66847EE0DC93ULL,
		0x630C30633B2EEA5FULL,
		0x39EBBB0A7B04003DULL,
		0xB87D4006FD45AF58ULL,
		0xE144DECE365DA7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CE11DCE8BB15F61ULL,
		0xEE6952E701CFEA9BULL,
		0xB11D96A794F0290DULL,
		0xD05EBC23BD2F9145ULL,
		0x4139A985AC1A2D5FULL,
		0xAE5658B96C7B37AFULL,
		0xD0205C9724D55BC5ULL,
		0x935E4C1DDD39066FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504011840B301300ULL,
		0xA441508301C14A8AULL,
		0x311404A110102801ULL,
		0x404C24003C209001ULL,
		0x41082001280A285FULL,
		0x284218086800002DULL,
		0x9020400624450B40ULL,
		0x81444C0C1419062DULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0FE75229813F207ULL,
		0xA5A3EC6C75BA0ABEULL,
		0x66B920F62F7CED8AULL,
		0x5755068AAB10B7FEULL,
		0x1978A8302B2EE7EAULL,
		0xA665B8E1B4CF196DULL,
		0x828D4C95957A0F51ULL,
		0xD2269760032F8416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC032B73C26E314ULL,
		0x6AC285958A470F65ULL,
		0x0C88D14C8263E282ULL,
		0x3D3344843D81B01FULL,
		0xDFE40C0FD35E652CULL,
		0xD47C861552E431C6ULL,
		0x03C60397DFAA715AULL,
		0x2BFF396B3F29DA30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0C030221802E204ULL,
		0x2082840400020A24ULL,
		0x048800440260E082ULL,
		0x151104802900B01EULL,
		0x19600800030E6528ULL,
		0x8464800110C41144ULL,
		0x02840095952A0150ULL,
		0x0226116003298010ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F54AE0C5D94969CULL,
		0xE688F5104F7259BAULL,
		0xE82A3F960C967825ULL,
		0xB908E50A835461C5ULL,
		0xF3FAAF577AF543AFULL,
		0x0CF4183473374E48ULL,
		0x7DEA5B081318C5ECULL,
		0x78BDDC52EE7EF2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48B525EFB435DD42ULL,
		0xBAC914FA75B0F018ULL,
		0xB49D12F8440F517FULL,
		0x2DE1ACBB3AF89D88ULL,
		0xF6BFAEF2BA37865BULL,
		0xD8CA2FEC7527C552ULL,
		0x3880B8615A742068ULL,
		0xC4EAA1C73FBDC680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0814240C14149400ULL,
		0xA288141045305018ULL,
		0xA008129004065025ULL,
		0x2900A40A02500180ULL,
		0xF2BAAE523A35020BULL,
		0x08C0082471274440ULL,
		0x3880180012100068ULL,
		0x40A880422E3CC280ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADC7A67FCB30BB28ULL,
		0x5189D7EB74BE6474ULL,
		0x087D2BA16115A2A7ULL,
		0xD51A03228A569EF2ULL,
		0x17BEC14EF8555D42ULL,
		0x61ED60E6E2527CBBULL,
		0x72043CF39EB9AC87ULL,
		0xDDBDCFA3A952D5E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE51D2A23EB2C05ULL,
		0x2BE8004309C3202FULL,
		0x8B30B56DACC0FF3BULL,
		0xB7792C1C04CCE4F0ULL,
		0x20FB614CB892E3F1ULL,
		0x1AC1B8BFA6E80B26ULL,
		0xC1C6FCC74276FB92ULL,
		0x1E8B1B0BA4AF8BAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9C5042A03202800ULL,
		0x0188004300822024ULL,
		0x083021212000A223ULL,
		0x95180000004484F0ULL,
		0x00BA414CB8104140ULL,
		0x00C120A6A2400822ULL,
		0x40043CC30230A882ULL,
		0x1C890B03A00281A0ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x468ADC6EA4D4795AULL,
		0xD86D6EA364912770ULL,
		0x82873B2021FE715DULL,
		0x7032E6FBCFCE75A8ULL,
		0x7E50937C8227142BULL,
		0x1D833C91B6B652DAULL,
		0xE351AF5B6B588971ULL,
		0x33934F6AAC5945ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEE4945E3BD297E6ULL,
		0x5671162B20CC05EBULL,
		0x67F572CD39DA5966ULL,
		0x8E0750DC2A300F58ULL,
		0x97046640F745FB19ULL,
		0x1F46BB46AB57EBCBULL,
		0x056FC89A02A6BCB4ULL,
		0x1BE1025B59EBC420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4680944E20D01142ULL,
		0x5061062320800560ULL,
		0x0285320021DA5144ULL,
		0x000240D80A000508ULL,
		0x1600024082051009ULL,
		0x1D023800A21642CAULL,
		0x0141881A02008830ULL,
		0x1381024A08494420ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DEF9E02696417C3ULL,
		0xF5278E0550B042E3ULL,
		0xCBE657289D259E60ULL,
		0xE57EDFB43C33EBE4ULL,
		0x3E4ADAF774C8C87DULL,
		0xFEBEB9D91DEC8A10ULL,
		0x6574EDED5A1F624BULL,
		0x15F5CDD354779865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14C17E6512C3D6B3ULL,
		0xE415CC3144D9F735ULL,
		0xCD13038207712AA7ULL,
		0xD5CC165F83D0B069ULL,
		0x4DEAFFB57CADCD72ULL,
		0x07130EFB9C7D978DULL,
		0x234F7D624CFC6D16ULL,
		0x52541553AFAC8177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C11E0000401683ULL,
		0xE4058C0140904221ULL,
		0xC902030005210A20ULL,
		0xC54C16140010A060ULL,
		0x0C4ADAB57488C870ULL,
		0x061208D91C6C8200ULL,
		0x21446D60481C6002ULL,
		0x1054055304248065ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7CA0B9631E8A22EULL,
		0x5AFCD775F7F1D212ULL,
		0x43893E1F9A9AE901ULL,
		0xDC411D63D328DF30ULL,
		0xF5749A66653C8C0BULL,
		0xEF9E19A6A562AB42ULL,
		0x1515B2206EBFC2A9ULL,
		0xD7D8E413D2DB2877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A79363525FD164ULL,
		0x4EEC892C809CC003ULL,
		0x28445AA9D32D7E5EULL,
		0x366B631224F33C99ULL,
		0xB69069CCB9958F63ULL,
		0x649A7C118BA158E3ULL,
		0x8D16CC1ECEDD3908ULL,
		0x935634BC2F42C4EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0082030210488024ULL,
		0x4AEC81248090C002ULL,
		0x00001A0992086800ULL,
		0x1441010200201C10ULL,
		0xB410084421148C03ULL,
		0x649A180081200842ULL,
		0x051480004E9D0008ULL,
		0x9350241002420067ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4925CA1F631F9C30ULL,
		0x9DFBBB5D6ECBAAE7ULL,
		0x8B10B45C170DEB5CULL,
		0xDCB44E9BBC043C98ULL,
		0x69A178D5C1780CADULL,
		0xC16B671DA2652EFDULL,
		0xF2B45979012485CFULL,
		0x9F01FA67B2294A57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EDEC2090D8A5BAULL,
		0x551DCAB45003F249ULL,
		0xC46723AD44953FD1ULL,
		0x6EE8D5FDAF7F96F4ULL,
		0x77C594CD02922D1AULL,
		0x0FC549693799068FULL,
		0x552BB5B9598AD2B2ULL,
		0xA95BCFA88A90C2CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0125C80000188430ULL,
		0x15198A144003A241ULL,
		0x8000200C04052B50ULL,
		0x4CA04499AC041490ULL,
		0x618110C500100C08ULL,
		0x014141092201068DULL,
		0x5020113901008082ULL,
		0x8901CA2082004245ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4B1E368BC9588A6ULL,
		0xB46E43FCBD54DA2EULL,
		0x8BFF0E16D3C258D5ULL,
		0x0D7E6AD37E0B562AULL,
		0x483BBEAED1782ED0ULL,
		0x6A7B33A40A5E8CBEULL,
		0xA7D7370373FBEAA8ULL,
		0xD7FA872D046082CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33D96556F1E6AEC5ULL,
		0xEC172093C28E4CC4ULL,
		0xB065B6F05D22EB5EULL,
		0xCAC8FA20BD9CE4FEULL,
		0x1A6A8C9D9722D912ULL,
		0x2E427AB3051DC593ULL,
		0x005AD02D16324324ULL,
		0x1FCF8BBB7E2DEE30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00916140B0848884ULL,
		0xA406009080044804ULL,
		0x8065061051024854ULL,
		0x08486A003C08442AULL,
		0x082A8C8C91200810ULL,
		0x2A4232A0001C8492ULL,
		0x0052100112324220ULL,
		0x17CA832904208200ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8374103F4822EEDDULL,
		0x8EC3899B67845F82ULL,
		0xE5AC259107C0D49BULL,
		0x0D95A96E58668F98ULL,
		0x16054D84216E3A82ULL,
		0x46C374A44F09A445ULL,
		0x150BDEF8D489C455ULL,
		0x1127689B04185688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEF81C1655536DE3ULL,
		0x1AC263C5CFDD63EDULL,
		0xA170CE0D9199C11CULL,
		0x543F095471D40DC2ULL,
		0xCA18027102CFC5E2ULL,
		0xE7ED91E96A67CAC1ULL,
		0xE084E09C09356FCBULL,
		0xB258EAC3A4AAF22DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8270101640026CC1ULL,
		0x0AC2018147844380ULL,
		0xA12004010180C018ULL,
		0x0415094450440D80ULL,
		0x02000000004E0082ULL,
		0x46C110A04A018041ULL,
		0x0000C09800014441ULL,
		0x1000688304085208ULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE059B0C3F8B6805CULL,
		0x331AD9A1442FEB00ULL,
		0xB6603B62EE79EDA7ULL,
		0x2961C066EF5F3A0EULL,
		0xFA3A03AA9AEE9CF8ULL,
		0xEE77F1EE4D46216BULL,
		0x6CB08998330DBAEFULL,
		0x4A8531DABD354988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2140125E99ED25AULL,
		0x712EF57936C22C2BULL,
		0x27514C652F092292ULL,
		0x461A75A810113204ULL,
		0x0CE85582CA14C3ECULL,
		0xCB6A8C87BAD60602ULL,
		0x586DE3EE9203508FULL,
		0xD809961F01E5CDA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0100001E8968058ULL,
		0x310AD12104022800ULL,
		0x264008602E092082ULL,
		0x0000402000113204ULL,
		0x082801828A0480E8ULL,
		0xCA62808608460002ULL,
		0x482081881201108FULL,
		0x4801101A01254980ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ABA25673D47BE23ULL,
		0x6F7E1072A52AB596ULL,
		0x60B56ACFC0379AB4ULL,
		0x768532621CC24B04ULL,
		0x351C8FEF7F112B87ULL,
		0x5EAD63CB1705EAA1ULL,
		0xA01BE0D4FECF1091ULL,
		0x888B4D329E2C62DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39425C5A1B996C1FULL,
		0xC9335EB753C35626ULL,
		0xDABB80F49A586CCBULL,
		0x5A032A660781B2FBULL,
		0x5FA7C0B261CC578CULL,
		0xB8F30734E3978786ULL,
		0xEA6378D1BC4B333DULL,
		0x5F4D536C73061AC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0802044219012C03ULL,
		0x4932103201021406ULL,
		0x40B100C480100880ULL,
		0x5201226204800200ULL,
		0x150480A261000384ULL,
		0x18A1030003058280ULL,
		0xA00360D0BC4B1011ULL,
		0x08094120120402C0ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0097170A055EE9FULL,
		0x77AFDDD1E8AD4778ULL,
		0x1D43489278368512ULL,
		0x532E7041A9E2DB23ULL,
		0x2816503873C0601EULL,
		0xDEDDF0FF4F8638E0ULL,
		0xD692EC7B2A12EABCULL,
		0xF3FC2D62B090A40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA6D0FED7EB8005ULL,
		0xEBB056CDA3E5D18CULL,
		0x1D77B7B86276DCC8ULL,
		0x6933F3F293E36088ULL,
		0xC3DB24C7AD5F4C22ULL,
		0xD33327323B220242ULL,
		0x6D9F78089D52226EULL,
		0xB1A507DC353656D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3000507080418005ULL,
		0x63A054C1A0A54108ULL,
		0x1D43009060368400ULL,
		0x4122704081E24000ULL,
		0x0012000021404002ULL,
		0xD21120320B020040ULL,
		0x449268080812222CULL,
		0xB1A4054030100407ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71B8F94CEED8EDFCULL,
		0x90CC11234B715249ULL,
		0xB840121A4483C8FCULL,
		0xF3B0CB9C28F0844EULL,
		0x4D965AEB933B8C45ULL,
		0xD5C416DA4795614BULL,
		0x26A594133A447651ULL,
		0xFC15B347ECB5BB8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4AF6A4AA05C82D5ULL,
		0x3DAE4984DF4F01B0ULL,
		0xB7D4555E7896452FULL,
		0xC9F08D7599181258ULL,
		0x9A9A4693E06207C7ULL,
		0x96CAB565E5F0CD66ULL,
		0x4A3FDC6032B77178ULL,
		0x496EAF7F246C3FB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A86848A05880D4ULL,
		0x108C01004B410000ULL,
		0xB040101A4082402CULL,
		0xC1B0891408100048ULL,
		0x0892428380220445ULL,
		0x94C0144045904142ULL,
		0x0225940032047050ULL,
		0x4804A34724243B84ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD74B2AE5E05B71A0ULL,
		0x4ECBC39DB0D0683EULL,
		0xDA492DC4A60B7C51ULL,
		0xFB3CF1A3038A9052ULL,
		0xD8B3D897B3CE85A0ULL,
		0x114BA75128D45E01ULL,
		0x98FE2BC3E6C38F36ULL,
		0xECA54FFABF4297A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B964CB3878ECEBULL,
		0xC58CB28E8959B367ULL,
		0xD3032BC8D2277492ULL,
		0xABCC17FE8F755FB5ULL,
		0x0EF7E1AAC366D7ACULL,
		0xDBB929B6C16C172CULL,
		0x6ECB4D1B4A159B0BULL,
		0x580BA79BAB60AEF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050920C1205860A0ULL,
		0x4488828C80502026ULL,
		0xD20129C082037410ULL,
		0xAB0C11A203001010ULL,
		0x08B3C082834685A0ULL,
		0x1109211000441600ULL,
		0x08CA090342018B02ULL,
		0x4801079AAB4086A0ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA65478F793C3D54ULL,
		0x612505AD9ABC5AACULL,
		0x6795F36034A6574EULL,
		0x0B0F105ADFD72492ULL,
		0x208FC808C6C23D25ULL,
		0xE076003F76E967A9ULL,
		0x536B33EDAAD27AA0ULL,
		0x9EAC5DA724CCBC9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AE2B51D94A943C3ULL,
		0xC30A993B034C5C49ULL,
		0x3ACE29264E810F3DULL,
		0x23543B32D45711AEULL,
		0x599AE2844966C401ULL,
		0x6D86EB293741DF64ULL,
		0x687E1797DC98FE14ULL,
		0xE3866C312D6F4768ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A60050D10280140ULL,
		0x41000129020C5808ULL,
		0x228421200480070CULL,
		0x03041012D4570082ULL,
		0x008AC00040420401ULL,
		0x6006002936414720ULL,
		0x406A138588907A00ULL,
		0x82844C21244C0408ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB91C26C03C76D92CULL,
		0x6DCE4D1F6157EE2BULL,
		0x6CC3ADC529FA19FCULL,
		0xE9F0C974699AE9EDULL,
		0x3D01F2DD252D7B75ULL,
		0xC0EF3BF73E727777ULL,
		0x1B2EC0EABCC4A75BULL,
		0x52E919463380CD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9507570A8D22D2ULL,
		0x29FD8F3FDB1810E0ULL,
		0x91BEF9794D1F5184ULL,
		0xED4EA40792C381C3ULL,
		0x7A341C31D1C0C642ULL,
		0xEFDD6EE539426E29ULL,
		0xBC4E7982E9BE7BABULL,
		0xFD41B4B1FDA5C5EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB914064008040000ULL,
		0x29CC0D1F41100020ULL,
		0x0082A941091A1184ULL,
		0xE9408004008281C1ULL,
		0x3800101101004240ULL,
		0xC0CD2AE538426621ULL,
		0x180E4082A884230BULL,
		0x504110003180C521ULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBF088ACC2137AC4ULL,
		0x003144E9B6EFAEBFULL,
		0x991F2DDDEA9162E9ULL,
		0xF08E212688CED05BULL,
		0x05BEB2A7A3C5B98AULL,
		0x2934B306442F115CULL,
		0xA03BCEA4C2D415D7ULL,
		0x45FD85EF46150B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC94A2F2A03B02E3ULL,
		0x22F0EF40BD860FA3ULL,
		0xCA79CF5F2F4148D7ULL,
		0x54AA0DEF2C82D011ULL,
		0xE0F0ECB50E149B16ULL,
		0xF4E45081A4269223ULL,
		0xD0DC66F67C298BC2ULL,
		0x723CF2FDFCFEF9B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA89080A0801302C0ULL,
		0x00304440B4860EA3ULL,
		0x88190D5D2A0140C1ULL,
		0x508A01260882D011ULL,
		0x00B0A0A502049902ULL,
		0x2024100004261000ULL,
		0x801846A4400001C2ULL,
		0x403C80ED44140990ULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86BB7F1B42E5FA0AULL,
		0xCA18DC5CFB2C167FULL,
		0x85D501EDF6AE8A28ULL,
		0x6C74CAF2A979ED4DULL,
		0x7161D5BC27FE8E37ULL,
		0xD4E76B331480ED08ULL,
		0x4DD69B5CFDAD0B92ULL,
		0xDDD6A620F613468CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4865F2445263C164ULL,
		0x9CCB2310D15CFF9FULL,
		0x158C57B15BA4F215ULL,
		0xC66E3ADE8E1F041EULL,
		0xB296E66EDAEE1B57ULL,
		0x9B12888E23F77433ULL,
		0xBB657ADBFC669F78ULL,
		0x82169AE22041EE64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002172004261C000ULL,
		0x88080010D10C161FULL,
		0x058401A152A48200ULL,
		0x44640AD28819040CULL,
		0x3000C42C02EE0A17ULL,
		0x9002080200806400ULL,
		0x09441A58FC240B10ULL,
		0x8016822020014604ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DC275FD985750F7ULL,
		0xD631FA488207D78EULL,
		0x05351091272B8660ULL,
		0x276714B7BE53FF55ULL,
		0xB00034E9A0148C70ULL,
		0xBBF91D797D329AC8ULL,
		0xD7350DCC920C8B3EULL,
		0xABC73C6FC9733538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B28FC16E2C0C8FULL,
		0xB35CE13ABCBAA358ULL,
		0x3FFDFFDFBD476085ULL,
		0x8CF3656A22F41F7EULL,
		0x71566A5BF0CBB087ULL,
		0x81CDAF42BFFD95B0ULL,
		0xBB6AFBCDA87C782BULL,
		0x8C260CFC075BB1EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808205C108040087ULL,
		0x9210E00880028308ULL,
		0x0535109125030000ULL,
		0x0463042222501F54ULL,
		0x30002049A0008000ULL,
		0x81C90D403D309080ULL,
		0x932009CC800C082AULL,
		0x88060C6C01533128ULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AC455169B92F970ULL,
		0xCF211A931A013182ULL,
		0x629A53FD7B241E9BULL,
		0xE58D029AAA4C5699ULL,
		0x51630032520971E4ULL,
		0xDE750A6EB6957F0AULL,
		0xFD8E6A54116EA913ULL,
		0xDA3A51C67116EE42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x524B3E936E5FC3E3ULL,
		0x76CFF11B5E75385DULL,
		0x563EF4B8AB6A6C5EULL,
		0xD1AB71B06E51A114ULL,
		0xEB2D5433AB0B1CDEULL,
		0x0A9BDCF7DA71C860ULL,
		0xF8EA1D0EFB143022ULL,
		0xF303125B8D59BA35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x524014120A12C160ULL,
		0x460110131A013000ULL,
		0x421A50B82B200C1AULL,
		0xC18900902A400010ULL,
		0x41210032020910C4ULL,
		0x0A11086692114800ULL,
		0xF88A080411042002ULL,
		0xD20210420110AA00ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF6F37C73E21450DULL,
		0x18017F72B3236277ULL,
		0xC86FD46E4E7E7C1FULL,
		0x49CFE6D4B8F02BF7ULL,
		0x9AADD964695BB432ULL,
		0xE4284A4853F517DDULL,
		0xA4933E24980645C0ULL,
		0xB40D8739EB016509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5320900DFC5A3046ULL,
		0x3E3645B1DCAF0921ULL,
		0x917804AE7A86C983ULL,
		0xCF0B99D019A56569ULL,
		0x7157C83F77E1D62DULL,
		0x3F9AC08620338D8CULL,
		0x5AEC0066844928F5ULL,
		0x3CF19A1C875537BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x532010053C000004ULL,
		0x1800453090230021ULL,
		0x8068042E4A064803ULL,
		0x490B80D018A02161ULL,
		0x1005C82461419420ULL,
		0x240840000031058CULL,
		0x00800024800000C0ULL,
		0x3401821883012508ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A106C5F0376685CULL,
		0x45AE8F4E916D18E6ULL,
		0x4D32BE1D69DB6C06ULL,
		0xBF6A94566D0250CCULL,
		0x74A2C6824CE0901AULL,
		0xD64AEA74B30A927DULL,
		0x5454F27144686F18ULL,
		0xF05951F07111A411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED5DC697F46B9D2AULL,
		0xB079AF069578FED6ULL,
		0xE803D420DB3C8D7CULL,
		0xD5EEED8D2F0EA008ULL,
		0xE6B716C1B48160A5ULL,
		0xE208430E889DA8CEULL,
		0x987FC631A1DCD02CULL,
		0x74178EC1C65B0CB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4810441700620808ULL,
		0x00288F06916818C6ULL,
		0x4802940049180C04ULL,
		0x956A84042D020008ULL,
		0x64A2068004800000ULL,
		0xC20842048008804CULL,
		0x1054C23100484008ULL,
		0x701100C040110410ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E5BF74A48770FF5ULL,
		0xAD7EB7AB345C50DBULL,
		0x6AF61BABC8843936ULL,
		0x20B3FD4D980A800FULL,
		0x77DBDA33DF686916ULL,
		0x136AB7EA807CF899ULL,
		0xF7AD940033BA6FE1ULL,
		0x22EF9126E79F6176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA58B02612E8D57DULL,
		0xB4A8794A91667CB0ULL,
		0x743B2CC570E33CC3ULL,
		0x2F632E83ECA40B9BULL,
		0xBF57C8DD1A1B70ADULL,
		0x38B22944EAB6B108ULL,
		0xB110F7A0164A5860ULL,
		0x81B969A3A9626A44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A58B00200600575ULL,
		0xA428310A10445090ULL,
		0x6032088140803802ULL,
		0x20232C018800000BULL,
		0x3753C8111A086004ULL,
		0x102221408034B008ULL,
		0xB1009400120A4860ULL,
		0x00A90122A1026044ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE6A62BBC6EAB851ULL,
		0x42FDE03E48838093ULL,
		0xA7550872641456CDULL,
		0xCD3BB86749284F08ULL,
		0xC107B26F37A567F3ULL,
		0xEF21D1FDB7E26B76ULL,
		0x19B12EDFF993390CULL,
		0xAF8FB9859C33C19FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213428FF65ED9864ULL,
		0xC79BAFDF1DC71B47ULL,
		0x5E88285D844C1B25ULL,
		0x384C5673FA006780ULL,
		0x6599296BBFF5C1CEULL,
		0x992DE0F720184E78ULL,
		0xB7B30C7A0D468180ULL,
		0x77A840E3D3C241D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x202020BB44E89840ULL,
		0x4299A01E08830003ULL,
		0x0600085004041205ULL,
		0x0808106348004700ULL,
		0x4101206B37A541C2ULL,
		0x8921C0F520004A70ULL,
		0x11B10C5A09020100ULL,
		0x2788008190024196ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50F2017785246E2BULL,
		0x0B94D4623B035728ULL,
		0x4556A1A64C5C3108ULL,
		0x6C4BA4B4E6685A9FULL,
		0xA81311DE35F34A43ULL,
		0x301D49D20F223878ULL,
		0x5E418FF623EDE2CEULL,
		0xB4765BCED0B41B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8537017BB9B8A275ULL,
		0x846A0FBC0EE08288ULL,
		0x5A8ED4164119AF6CULL,
		0x0413FE5A59226EDAULL,
		0xB5D59A289742485FULL,
		0xE7DD6C510CAEFC47ULL,
		0xC730D32267BAA49EULL,
		0x9002EF11307846AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0032017381202221ULL,
		0x000004200A000208ULL,
		0x4006800640182108ULL,
		0x0403A41040204A9AULL,
		0xA011100815424843ULL,
		0x201D48500C223840ULL,
		0x4600832223A8A08EULL,
		0x90024B0010300204ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF93EA12955DED850ULL,
		0x0B69017BA727DB25ULL,
		0x8648D046CBCC6022ULL,
		0x96803B09A939A787ULL,
		0x25C1447405652AB1ULL,
		0xC01D1CED55708220ULL,
		0xB0E376AA85653ADDULL,
		0xB84E5E15AACA2941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CABB9A4D14F20B0ULL,
		0x5262245A48573713ULL,
		0xD694F45F3CB10E44ULL,
		0x18954B483369906CULL,
		0x12505C2CC6107DBAULL,
		0x3F9F755844878D14ULL,
		0x67D4059415B6E1C0ULL,
		0x030173329589D809ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x482AA120514E0010ULL,
		0x0260005A00071301ULL,
		0x8600D04608800000ULL,
		0x10800B0821298004ULL,
		0x00404424040028B0ULL,
		0x001D144844008000ULL,
		0x20C00480052420C0ULL,
		0x0000521080880801ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x846D870E49F04106ULL,
		0xADE75E97F469749FULL,
		0x48DB46287F42F82DULL,
		0x46926AA98DA18999ULL,
		0x1D92869A2857C8D0ULL,
		0xCCD7D5728FDE4C0BULL,
		0x9A62E90AA932F29FULL,
		0xB66C13D27D15ADC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9D0C60E41EFBD6EULL,
		0xB6A23FC754F65CC6ULL,
		0x05D2E260921E80B2ULL,
		0xB93A9144B1444076ULL,
		0x005B008B2FB91489ULL,
		0x2A94075B9A58BB51ULL,
		0xF61DF6120CAE0A61ULL,
		0xC17A5AE7993560FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8040860E41E00106ULL,
		0xA4A21E8754605486ULL,
		0x00D2422012028020ULL,
		0x0012000081000010ULL,
		0x0012008A28110080ULL,
		0x089405528A580801ULL,
		0x9200E00208220201ULL,
		0x806812C2191520C8ULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEDDB127A6B30301ULL,
		0x37D8E9B1F5FFFBAFULL,
		0x326CB6E1EA5FE7BFULL,
		0x8521042512B4E85FULL,
		0x4DEC1493E83E6DF0ULL,
		0x5F7D67A63226A87FULL,
		0xC0BF87121B6CBDC9ULL,
		0x8717FC67706DB97DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39149F3420513FE5ULL,
		0xD6D2289113018666ULL,
		0x5616270FB888981AULL,
		0x560A1AC53186B398ULL,
		0xC668C8998E71862EULL,
		0x175F9E307C6897CBULL,
		0xFDC925FCDB1C63F0ULL,
		0xB517953971EF51F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3814912420110301ULL,
		0x16D0289111018226ULL,
		0x12042601A808801AULL,
		0x040000051084A018ULL,
		0x4468009188300420ULL,
		0x175D06203020804BULL,
		0xC08905101B0C21C0ULL,
		0x85179421706D1170ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x987049B7273DB78FULL,
		0xF8CEF88F5115CE9FULL,
		0xB47D81F088841F92ULL,
		0x8118C0DE24672DD1ULL,
		0xEE12596D7C53B7FEULL,
		0x60114C6550FA7F3BULL,
		0x90BC96D3796871A7ULL,
		0x3E8D12D9434B995EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAEC572BED7F0D11ULL,
		0xC67356F069A2B1B4ULL,
		0x34E4D754BD11E579ULL,
		0x3C2E0C1060BE73A8ULL,
		0x29F6616244027DFBULL,
		0x632E875814ACD16DULL,
		0xD3361C06B86DB064ULL,
		0x8ABC83AA998965DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88604123253D0501ULL,
		0xC042508041008094ULL,
		0x3464815088000510ULL,
		0x0008001020262180ULL,
		0x28124160440235FAULL,
		0x6000044010A85129ULL,
		0x9034140238683024ULL,
		0x0A8C02880109015AULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4841AE7AFED27A03ULL,
		0x406A181348E16CACULL,
		0xF65CFB5BE750EAD9ULL,
		0xA339F66493AA8389ULL,
		0x498EADF5B9A62823ULL,
		0x373F1D8DA92E600DULL,
		0x855FBEF5D067812FULL,
		0x64622B670CCC9004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9D38180550EB1BULL,
		0x11EAD9E8B0F3F937ULL,
		0x1A90755731FDC677ULL,
		0xF3A463BA0117464DULL,
		0x6B8350AB8432ACDAULL,
		0x9DBE8E55172D82A0ULL,
		0x9CB4DA2062942F44ULL,
		0x2727284EFFF63E54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4801281804506A03ULL,
		0x006A180000E16824ULL,
		0x121071532150C251ULL,
		0xA320622001020209ULL,
		0x498200A180222802ULL,
		0x153E0C05012C0000ULL,
		0x84149A2040040104ULL,
		0x242228460CC41004ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A66D26E90F60315ULL,
		0x395E429B5B4120E9ULL,
		0x58A0EC9F54D387B8ULL,
		0x2B853F167A0749F3ULL,
		0x9811DC37CAFD593CULL,
		0x45CC09F769C845DFULL,
		0xF56E8DDCBDB63C27ULL,
		0x79F9DAD3A865BAFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2B3A70647C1EDCULL,
		0x3801A750C6A44F52ULL,
		0xACD23B6FECE819A0ULL,
		0xD750DD5CDE7B6E2BULL,
		0xB5590196590C29E2ULL,
		0xF740AFFFC3850E6CULL,
		0x7E2235235890CA4FULL,
		0xFDE9EFDD3C615163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A22126000740214ULL,
		0x3800021042000040ULL,
		0x0880280F44C001A0ULL,
		0x03001D145A034823ULL,
		0x90110016480C0920ULL,
		0x454009F74180044CULL,
		0x7422050018900807ULL,
		0x79E9CAD128611062ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E802635F20747FCULL,
		0xBFBA37E65D7A5407ULL,
		0x00F132A5E5573865ULL,
		0xBD7EC3BA53C25B28ULL,
		0x6B0B5F02B02F3AA0ULL,
		0xF401E16B44B08FBCULL,
		0xF45F4FEA548233C4ULL,
		0xA76E6D026A77529BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19AE5941DEED95CCULL,
		0xB37E392AB98BD370ULL,
		0xC7FEEB76435D2E64ULL,
		0xA8D194D2CB8E3BFDULL,
		0x88161E0959AE9199ULL,
		0xA2D59C13BE0E5C81ULL,
		0xD77BF7ABD5D92076ULL,
		0x8B592F0EEF226D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18800001D20505CCULL,
		0xB33A3122190A5000ULL,
		0x00F0222441552864ULL,
		0xA850809243821B28ULL,
		0x08021E00102E1080ULL,
		0xA001800304000C80ULL,
		0xD45B47AA54802044ULL,
		0x83482D026A224082ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC0FDA431BE531E7ULL,
		0x24D07C5F462CE02DULL,
		0xA4EEC4587FAEB418ULL,
		0x1F1A1F382B3CE3E3ULL,
		0xA8220C05EF170202ULL,
		0xC216258EEDBFAD24ULL,
		0xB7B87D4CF7925B1EULL,
		0x7830199A5E092CFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC96DC66410066981ULL,
		0x68BEF0E518CAB7E3ULL,
		0xA391BCF35EC06515ULL,
		0xEF37CF852C58D02BULL,
		0xDA8958470C8CEC0DULL,
		0xBBA09815AEC0D79CULL,
		0x88C1FFBE0F0FF5CCULL,
		0x6100459EC8B1E63AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC80DC24010042181ULL,
		0x209070450008A021ULL,
		0xA08084505E802410ULL,
		0x0F120F002818C023ULL,
		0x880008050C040000ULL,
		0x82000004AC808504ULL,
		0x80807D0C0702510CULL,
		0x6000019A4801243AULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA51170F70D39E4BDULL,
		0xC8B830D0D9CE5D37ULL,
		0xF6C9D203F1F980A6ULL,
		0x3B5CE7D0BF8DF082ULL,
		0x9A4AE218C045B0C4ULL,
		0x7C0E7881FFDF4A1FULL,
		0x37D1FD5507D8F655ULL,
		0x4367680E1B5E7C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2801A64DE90704D8ULL,
		0x077FB839BACDE708ULL,
		0x86CC983B089ED716ULL,
		0xB6D08A8BE181A703ULL,
		0xBFE90F5D7BEAE072ULL,
		0x40DAF71215CBAEE9ULL,
		0x18A05D301733FB0AULL,
		0x83C2828E824EC422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2001204509010498ULL,
		0x0038301098CC4500ULL,
		0x86C8900300988006ULL,
		0x32508280A181A002ULL,
		0x9A4802184040A040ULL,
		0x400A700015CB0A09ULL,
		0x10805D100710F200ULL,
		0x0342000E024E4400ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x716A856F6D720712ULL,
		0xEB4B4E3868E6AD75ULL,
		0x2DAF866F70880171ULL,
		0x78CF697EBD8C5E5EULL,
		0x5F113F6CA2F6057FULL,
		0x0B9BA849215A451FULL,
		0xDCC0CC56E4F68D58ULL,
		0x46FBEDF4598DAD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38AC98BBB4CD4AC4ULL,
		0x90547AA585FE1BA2ULL,
		0x8A1C992473679EDBULL,
		0x324B0E357785EC09ULL,
		0x7A4585DDDA166AC8ULL,
		0xCF71CADBA359063EULL,
		0x8FFC9F07E0C85F28ULL,
		0xE3D914F06A83AFF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3028802B24400200ULL,
		0x80404A2000E60920ULL,
		0x080C802470000051ULL,
		0x304B083435844C08ULL,
		0x5A01054C82160048ULL,
		0x0B1188492158041EULL,
		0x8CC08C06E0C00D08ULL,
		0x42D904F04881AD30ULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9422721233DA53A8ULL,
		0xCA423D71A45ED682ULL,
		0xA8805E83DCCFA6DAULL,
		0x108F994034CED125ULL,
		0xBD4A07E627CD5C0BULL,
		0xD9B21A2D2F3DD017ULL,
		0xE4238E4F191E9EEFULL,
		0xFF64304D75BBD4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150AD90547F73960ULL,
		0x863C8AA734ACAB63ULL,
		0x55EA0ADB77959938ULL,
		0x12877AE11EA70F07ULL,
		0xB5EB265F383428CDULL,
		0xECB7C8AE4BCE3D8DULL,
		0x73B960E2CEBC562CULL,
		0x0644C691C6CC4068ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1402500003D21120ULL,
		0x82000821240C8202ULL,
		0x00800A8354858018ULL,
		0x1087184014860105ULL,
		0xB54A064620040809ULL,
		0xC8B2082C0B0C1005ULL,
		0x60210042081C162CULL,
		0x0644000144884028ULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC2D8D1BC5A4DDC0ULL,
		0x8933A7B86AC1B54BULL,
		0xE906450D1C6715D3ULL,
		0x8E8B6D6F8D0BE320ULL,
		0x92C4438EAFAB526BULL,
		0xE035116A9AF27783ULL,
		0x819929E5C24F636CULL,
		0x694356FFA6C88700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F65B1B4392AE6BBULL,
		0x83C7D1BF052870D8ULL,
		0x0023524A674B8E61ULL,
		0xC892CBC8611E21ABULL,
		0xAFF2C4A963B423A5ULL,
		0x6AC0115A9A05D657ULL,
		0xA82985AC6045EB47ULL,
		0x3028AC158AE0B668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C2581100120C480ULL,
		0x810381B800003048ULL,
		0x0002400804430441ULL,
		0x88824948010A2120ULL,
		0x82C0408823A00221ULL,
		0x6000114A9A005603ULL,
		0x800901A440456344ULL,
		0x2000041582C08600ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16C5C4B53EA337CBULL,
		0x83B69DF2C3154E9AULL,
		0xA4E2C88DE5532503ULL,
		0xA68001935E6DFAFCULL,
		0x82882D7EF6AE67F0ULL,
		0x63761B2E5871B107ULL,
		0x8342440E3C6C8AE0ULL,
		0xE475A9A684345D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D18C4AB9AA16960ULL,
		0x833B8858FFEA6DB5ULL,
		0x3D8A5CF05A1B12DBULL,
		0x0748997B12797AF9ULL,
		0xEEE49487526FC5BDULL,
		0x5192E4121C52E2D6ULL,
		0xA32219BE14D995B6ULL,
		0xCE87A548A2561475ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0400C4A11AA12140ULL,
		0x83328850C3004C90ULL,
		0x2482488040130003ULL,
		0x0600011312697AF8ULL,
		0x82800406522E45B0ULL,
		0x411200021850A006ULL,
		0x8302000E144880A0ULL,
		0xC405A10080141470ULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5744C558F3C032ADULL,
		0xAC9C57F91954E944ULL,
		0x9DFFEA4E30D108F8ULL,
		0x5EBDDD85CD81488AULL,
		0xE7D84F804C14CE52ULL,
		0xDB9BD11EF131AE38ULL,
		0xE02EA7CE10534E9FULL,
		0x7CC4331FFC227C90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3F904854D3DA93ULL,
		0x283BBCD066A8BD1EULL,
		0xA1FFEBE8542D1B4CULL,
		0x9E00F2004E091282ULL,
		0xD0BD9DA648108F71ULL,
		0x62B399FAE18544BEULL,
		0x63FBE676FD83917EULL,
		0x6E41FFAA3858D914ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0504804850C01281ULL,
		0x281814D00000A904ULL,
		0x81FFEA4810010848ULL,
		0x1E00D0004C010082ULL,
		0xC0980D8048108E50ULL,
		0x4293911AE1010438ULL,
		0x602AA6461003001EULL,
		0x6C40330A38005810ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ABD62481B53A4A8ULL,
		0x18F933629323220DULL,
		0x4489C88DE26219CAULL,
		0x21A63D949B765092ULL,
		0x2E9CF5BCD656538AULL,
		0xF661CFA5C5F9F2E8ULL,
		0x6EFEECCC544DBACDULL,
		0x172612789FEE7434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F06AD21988D7CEULL,
		0x370CE2CAF9F10C9AULL,
		0x1345326C2EFF31FAULL,
		0xBBCE9264291FC657ULL,
		0x083DC5EBF503D239ULL,
		0xA53FA7C1A973B735ULL,
		0x0FE5D538EE489EF7ULL,
		0x48A4B78E1457BF3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18B0624019008488ULL,
		0x1008224291210008ULL,
		0x0001000C226211CAULL,
		0x2186100409164012ULL,
		0x081CC5A8D4025208ULL,
		0xA42187818171B220ULL,
		0x0EE4C40844489AC5ULL,
		0x0024120814463434ULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51BB8AB47D5891FAULL,
		0xC182F4821113A4CDULL,
		0xA80CB0C7AB915F2FULL,
		0xF51631371844002FULL,
		0x659BB18E780DD64EULL,
		0x6F02462663BC1B11ULL,
		0x242CCE1487862E0CULL,
		0x5AD1D51728C13A6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACFEF666038144BULL,
		0x67E15510E7032745ULL,
		0xACEFA6462D2685ECULL,
		0xA61920EF4ACE42DAULL,
		0x1E541F205C57ABC8ULL,
		0xD48CF42A18A9622FULL,
		0xE87478EC0865DD45ULL,
		0x4D3DE4D8B30AD1DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108B8A246018104AULL,
		0x4180540001032445ULL,
		0xA80CA0462900052CULL,
		0xA41020270844000AULL,
		0x0410110058058248ULL,
		0x4400442200A80201ULL,
		0x2024480400040C04ULL,
		0x4811C41020001048ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06673DA560931895ULL,
		0x4235C893544DE7A8ULL,
		0xB6344AADA04E9B7FULL,
		0xF16413C167E4E9A1ULL,
		0x5A576FD5C7E8A701ULL,
		0x0BE9B29C21E023F3ULL,
		0x7CBC8571E1403C26ULL,
		0x53E88322B496EA21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41700F2C9FDDD3EULL,
		0x36D00A08664C43EAULL,
		0xFCD5A2E7048D07F1ULL,
		0x3A6747B40A320B85ULL,
		0x5D677E3B31FFD037ULL,
		0xC29DE9E4FDCDFD05ULL,
		0x68BF49864E46D1A1ULL,
		0x6F7A90AE39897EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040700A040911814ULL,
		0x02100800444C43A8ULL,
		0xB41402A5000C0371ULL,
		0x3064038002200981ULL,
		0x58476E1101E88001ULL,
		0x0289A08421C02101ULL,
		0x68BC010040401020ULL,
		0x4368802230806A21ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB8ABF862D5901BFULL,
		0x74D81B9C279D17D1ULL,
		0x77EF03FE5FD788CAULL,
		0xB09DFB526E2FF207ULL,
		0x0D8906AFE1042A2FULL,
		0x6B91C82C2B5EDC00ULL,
		0xC68E1A3C4CC92F74ULL,
		0x16A98137CDCA3FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83362C858203045EULL,
		0x9CDF584EB9950CB8ULL,
		0x53F519DDD356E4C8ULL,
		0x098EE27A041307F8ULL,
		0x10BF0E467780CAD6ULL,
		0x2B7DF7AB3838A814ULL,
		0x0F0BDB355EC25145ULL,
		0x0837C2C134912E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83022C840001001EULL,
		0x14D8180C21950490ULL,
		0x53E501DC535680C8ULL,
		0x008CE25204030200ULL,
		0x0089060661000A06ULL,
		0x2B11C02828188800ULL,
		0x060A1A344CC00144ULL,
		0x0021800104802E14ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AE0E4F8C0C8A5AEULL,
		0x1BCDFAC1E5371D11ULL,
		0x1E4C11A1CD991200ULL,
		0xB1643003DF0F8607ULL,
		0xC65ACF4BE84C2950ULL,
		0x9C1BDEE63E875A7BULL,
		0x2555FE30CD777460ULL,
		0xC018C981EFEB5C59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97EB5FBCD230476AULL,
		0xC351ECEAAFD80DDAULL,
		0x181D2757349536B8ULL,
		0x9C7F7EF3E0A6AA7DULL,
		0x5D395F7AA0DC9318ULL,
		0xC2FA06E5FDA1312EULL,
		0x15459A73DDB10D8AULL,
		0xB8E7BFA29B98D7ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12E044B8C000052AULL,
		0x0341E8C0A5100D10ULL,
		0x180C010104911200ULL,
		0x90643003C0068205ULL,
		0x44184F4AA04C0110ULL,
		0x801A06E43C81102AULL,
		0x05459A30CD310400ULL,
		0x800089808B885448ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x832B6DCBE3770AE0ULL,
		0x0ADA788941715BD9ULL,
		0x22626E0EFC17921BULL,
		0xD6095ED28FD7E18CULL,
		0x51160ADDCA3D7DD4ULL,
		0x9E4AAA382607E2E1ULL,
		0x53739ADF58CE8651ULL,
		0x0CF75CDC98D1240FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9B15324AFA98C4EULL,
		0x9AE48110FF7EB3BDULL,
		0xEBEB2B581839D409ULL,
		0xC50C0DA326C6737AULL,
		0xB97393CC0E79B78EULL,
		0x4871FAB1B6341BD1ULL,
		0xDD4C5AE19DECD4C5ULL,
		0xC901E538FAFB2202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81214100A3210840ULL,
		0x0AC0000041701399ULL,
		0x22622A0818119009ULL,
		0xC4080C8206C66108ULL,
		0x111202CC0A393584ULL,
		0x0840AA30260402C1ULL,
		0x51401AC118CC8441ULL,
		0x0801441898D12002ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x852B1BE0DFACF25AULL,
		0xC298E64FA54E975BULL,
		0x7B20C74B6EDD020AULL,
		0x7919E45C9BDD85DFULL,
		0x2D7D93EFFC66273DULL,
		0x88568454321AA37AULL,
		0x4D9F076676B788E2ULL,
		0xA160C2A782E0D770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x312DAA51BB254746ULL,
		0xE4700D4CDEDED8EEULL,
		0x8FE99B3F1018EDC7ULL,
		0xA30803EEB5F1C764ULL,
		0xC0DEAE80687C31BEULL,
		0x6BC82A6739821903ULL,
		0xBF897E32D0DD4BBEULL,
		0xDB5CFE4A96085EF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01290A409B244242ULL,
		0xC010044C844E904AULL,
		0x0B20830B00180002ULL,
		0x2108004C91D18544ULL,
		0x005C82806864213CULL,
		0x0840004430020102ULL,
		0x0D890622509508A2ULL,
		0x8140C20282005670ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABDD85C83EF842C2ULL,
		0xE77E31B0425E1113ULL,
		0x7F55D38A8876A739ULL,
		0x1AEDD19A9611DA94ULL,
		0x7B1177A8FF9EB60FULL,
		0xC554D6268D936DE6ULL,
		0x0C576F9BCF1AB81EULL,
		0x6320FE494862D939ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC95AB828D11EA36ULL,
		0xCF1D44FFCAAB66F8ULL,
		0xB0ED542475A81879ULL,
		0xB61561FFAC12FAB2ULL,
		0xDB46407399836B29ULL,
		0x42DBE6C6507C2CF4ULL,
		0x5EB3D4BF3E40ABE3ULL,
		0xE6DB8E2242761842ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA89581800C104202ULL,
		0xC71C00B0420A0010ULL,
		0x3045500000200039ULL,
		0x1205419A8410DA90ULL,
		0x5B00402099822209ULL,
		0x4050C60600102CE4ULL,
		0x0C13449B0E00A802ULL,
		0x62008E0040621800ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF119BBF5C6C406C1ULL,
		0xA838F3BEACC13C0CULL,
		0xC4C1474C9EDF55E1ULL,
		0x84FDEAAD815492D4ULL,
		0x6B7E4CC9D8CD65FFULL,
		0x5E514DCB14729D5DULL,
		0x68F9FF44259BD800ULL,
		0x6AA50F2D8CB16ABDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D05FAF7D2668C93ULL,
		0x208B8337B43BA0F3ULL,
		0xF180808105BA270CULL,
		0x2B42BDC990F6E9D0ULL,
		0xF7AFEC099856825CULL,
		0x16DCD3D4F4867371ULL,
		0x61000CCA3C80A6A2ULL,
		0x548C95915C13D179ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4101BAF5C2440481ULL,
		0x20088336A4012000ULL,
		0xC0800000049A0500ULL,
		0x0040A889805480D0ULL,
		0x632E4C099844005CULL,
		0x165041C014021151ULL,
		0x60000C4024808000ULL,
		0x408405010C114039ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF14CE1A3F0262830ULL,
		0xEA3CF260F302F4A8ULL,
		0xB4767EEC2BA9B7E9ULL,
		0x7C2E539346697980ULL,
		0x70CB97C9339FEEC1ULL,
		0x3C36BE40CCA2C2F0ULL,
		0xF09F0F3998B98E82ULL,
		0x1043BA34DB19622BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775E95D0CCF66FD6ULL,
		0x9D7CC0D85FD87123ULL,
		0x71FEB83E61307BDDULL,
		0x109E1150610ED82AULL,
		0xFEE9D75962CDBF2AULL,
		0x5CBE89352838DB82ULL,
		0x0AD6E498C3852B9BULL,
		0x72124F1AE379C562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x714C8180C0262810ULL,
		0x883CC04053007020ULL,
		0x3076382C212033C9ULL,
		0x100E111040085800ULL,
		0x70C99749228DAE00ULL,
		0x1C3688000820C280ULL,
		0x0096041880810A82ULL,
		0x10020A10C3194022ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4618EB4A6D1484D3ULL,
		0x729DF34AEED66FC5ULL,
		0x338EB1D110BEE072ULL,
		0xA61985D271444192ULL,
		0xF356BB655EE49C59ULL,
		0xA5667887AF3B31EFULL,
		0xC89A792C7CF00537ULL,
		0x80A592B2C5E332B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7E952D6EF792D0ULL,
		0xAFF3E7642F324D7EULL,
		0x7F4ACA36DEAE9E31ULL,
		0x4C5236083E70B7DEULL,
		0x46C471DB4093CCDDULL,
		0xC39BBEF511C41C63ULL,
		0x9FDD8415DD56B1F6ULL,
		0x790BDEDFB80FED28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x021881086C1480D0ULL,
		0x2291E3402E124D44ULL,
		0x330A801010AE8030ULL,
		0x0410040030400192ULL,
		0x4244314140808C59ULL,
		0x8102388501001063ULL,
		0x889800045C500136ULL,
		0x0001929280032020ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE2AEE4EB0E85E30ULL,
		0xBBC88EA38D86B64CULL,
		0x3FBDCA29D55DFBFAULL,
		0xA1A28BD756F86881ULL,
		0x9B71DC573D456A4AULL,
		0x586653AFDBBD4A62ULL,
		0x106617771936304CULL,
		0x07F3863F8A29EFB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D2387B5038B6E1ULL,
		0xAF8041D761D038BEULL,
		0xC600910920283A09ULL,
		0x7A62A6900D7DB053ULL,
		0x13E8FDE63DA72990ULL,
		0xE6BB7DBA3E15809CULL,
		0x4849B9D78D3C1A0CULL,
		0xE1B2EE71F76EE8E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2802284A10281620ULL,
		0xAB8000830180300CULL,
		0x0600800900083A08ULL,
		0x2022829004782001ULL,
		0x1360DC463D052800ULL,
		0x402251AA1A150000ULL,
		0x004011570934100CULL,
		0x01B286318228E8A0ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x463C8FC5D4DF1849ULL,
		0x8ABF830B726A0FF2ULL,
		0x3BE6D13AF54E1D56ULL,
		0x158B424CA57E60DAULL,
		0xE908813A1375A804ULL,
		0xAE467B034A3A8A0DULL,
		0x0E4FD254F006FEE3ULL,
		0x17EE9EDF4D47B95EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A19CCA77D51E0BEULL,
		0x5C2F6CDFFFDF2263ULL,
		0x294C6EEE65B3AB1CULL,
		0x63CED29E0D969533ULL,
		0xA2767CFACCFCC592ULL,
		0x4ECB7D16FC48BCFEULL,
		0x83A90243DA585E9EULL,
		0xB94D8B2DB88B758DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02188C8554510008ULL,
		0x082F000B724A0262ULL,
		0x2944402A65020914ULL,
		0x018A420C05160012ULL,
		0xA000003A00748000ULL,
		0x0E4279024808880CULL,
		0x02090240D0005E82ULL,
		0x114C8A0D0803310CULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE8DEEFEF19F860AULL,
		0x126224723A9C9C3AULL,
		0xE9D251EBAA012AA8ULL,
		0xAB77D83E27BB3523ULL,
		0x0086D41F6DC8B98AULL,
		0x599701CFF3C480D5ULL,
		0x063741FAE5C9FBCCULL,
		0x927F1EE9D4B9C800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC9CA04D86F600ECULL,
		0xFF50697EA4DE2A7EULL,
		0xFB324665355710D7ULL,
		0x01A0E9CA2D22FF12ULL,
		0x7CB637C15504EF41ULL,
		0xAB5FE72E4870BF38ULL,
		0x21DF32B1F9B98580ULL,
		0x476F2017DE8CAE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8CA04C80960008ULL,
		0x12402072209C083AULL,
		0xE912406120010080ULL,
		0x0120C80A25223502ULL,
		0x008614014500A900ULL,
		0x0917010E40408010ULL,
		0x001700B0E1898180ULL,
		0x026F0001D4888800ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C38CC68AFBA9D58ULL,
		0xF58CA38EC0AF888CULL,
		0xDBE4800CBF36697FULL,
		0x939E2BCE45632768ULL,
		0x743A73139657A510ULL,
		0xF7CC7AF86CA623D3ULL,
		0xA9B7CFBEF9C0EBD9ULL,
		0x23609CA7ABC75474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702F08C5BFC2B7EDULL,
		0x1E03B49BC565552DULL,
		0x92FFF07AB676FBF1ULL,
		0x3ABEB89457FBA820ULL,
		0x68AA4831415FD41CULL,
		0x7E4131AB958C60C7ULL,
		0xA1034C4E105D5686ULL,
		0xADCCB472E5542180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70280840AF829548ULL,
		0x1400A08AC025000CULL,
		0x92E48008B6366971ULL,
		0x129E288445632020ULL,
		0x602A401100578410ULL,
		0x764030A8048420C3ULL,
		0xA1034C0E10404280ULL,
		0x21409422A1440000ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x032600382B6E73C9ULL,
		0x500037B8C2485117ULL,
		0x8D9C61E6B4CA6AD9ULL,
		0xAC5F46278B6BA6B0ULL,
		0x6E5DD32BC2C0DA6AULL,
		0xBF62DE5036B98E36ULL,
		0xC19F268E9709C4E1ULL,
		0x16A1AEE1B4F6E0E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60096B1957349FBAULL,
		0xAC16D6F2E42E733FULL,
		0x68A3FC5E953DFE68ULL,
		0x6A78EA00463E2CEBULL,
		0x68664E181E0D5771ULL,
		0x4743D1CD460180F9ULL,
		0x995A0DE7DDD899BEULL,
		0xD4D40DB931C66D91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000001803241388ULL,
		0x000016B0C0085117ULL,
		0x0880604694086A48ULL,
		0x28584200022A24A0ULL,
		0x6844420802005260ULL,
		0x0742D04006018030ULL,
		0x811A0486950880A0ULL,
		0x14800CA130C66081ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x846DA442F66E76F2ULL,
		0x15E1C66F40275866ULL,
		0x6BA27F57BC1BB566ULL,
		0x181C4D2D8F72915AULL,
		0x54413735618F7209ULL,
		0x3BB19ECBA1ADDDF2ULL,
		0xE32F70772F9BEA52ULL,
		0x8FEE200AA0B36FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE3FEC5F09ADEE7DULL,
		0x4835F70312D0D023ULL,
		0xC1A5AE0D4ED1205CULL,
		0xA5C063282A158E6DULL,
		0x8BB2A7DAD0D9CE28ULL,
		0x0188868D86DFD9B3ULL,
		0x8E9D5CBB33D0F55FULL,
		0xA6198F8DBEEC1E36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x842DA442002C6670ULL,
		0x0021C60300005022ULL,
		0x41A02E050C112044ULL,
		0x000041280A108048ULL,
		0x0000271040894208ULL,
		0x01808689808DD9B2ULL,
		0x820D50332390E052ULL,
		0x86080008A0A00E20ULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x311E78FB94C8FA20ULL,
		0x00EACDFC2F9F2417ULL,
		0xA9E21BFE98D16559ULL,
		0x38F1728C325FE68CULL,
		0x839C6586FD4755C0ULL,
		0x312CFEC9839C248FULL,
		0xA6574DDCDE110E67ULL,
		0x6273A6668A98D3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x312E856F5C5E28D6ULL,
		0x7F16F80AEC89B2F6ULL,
		0x5EF00B342B0559E0ULL,
		0xBE3F9FF835E5F938ULL,
		0xE934354282318686ULL,
		0x4A7E0512AA9287C8ULL,
		0x05911A8D548872A7ULL,
		0xBC2C7E4C49728D9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x310E006B14482800ULL,
		0x0002C8082C892016ULL,
		0x08E00B3408014140ULL,
		0x383112883045E008ULL,
		0x8114250280010480ULL,
		0x002C040082900488ULL,
		0x0411088C54000227ULL,
		0x202026440810819AULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E3BC84239D54E68ULL,
		0x6AE70A94E1490904ULL,
		0xFD66F9CEEC9C76E3ULL,
		0xA50C93B47E6EFBDEULL,
		0x28197558F5A0E2B1ULL,
		0x37398095DF96F1E1ULL,
		0xB0BBA39A6825A5B9ULL,
		0x4456C033A3A5BE6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96322E37534BBAF1ULL,
		0x016111D112D28898ULL,
		0x237AED61BE1C4259ULL,
		0x3A4D27FBAB3B7825ULL,
		0xFFC858C4CB2E61B0ULL,
		0xA57CAA230EB4E110ULL,
		0x593F09D321E33A8FULL,
		0x148E927387927A67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0632080211410A60ULL,
		0x0061009000400800ULL,
		0x2162E940AC1C4241ULL,
		0x200C03B02A2A7804ULL,
		0x28085040C12060B0ULL,
		0x253880010E94E100ULL,
		0x103B019220212089ULL,
		0x0406803383803A63ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4B04601D5B8E3A1ULL,
		0xB092B7B99CEDCA80ULL,
		0xB366FF319D89C86AULL,
		0xBE713C6319287867ULL,
		0x2A543DF6D22DAA85ULL,
		0x5DC4BC6ECA3FE08AULL,
		0x0CF965F5FEE88ECFULL,
		0x9695FE306A8D61E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C773F3082605AECULL,
		0x803B4E849608A441ULL,
		0xF4A52A5A1099B259ULL,
		0x005DA4A8BA5112FEULL,
		0x9F2F35D621643729ULL,
		0x7D1A9ECD53DB0AC5ULL,
		0xB1D102F674ED4E25ULL,
		0xCB028E57B2FC0583ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04300600802042A0ULL,
		0x8012068094088000ULL,
		0xB0242A1010898048ULL,
		0x0051242018001066ULL,
		0x0A0435D600242201ULL,
		0x5D009C4C421B0080ULL,
		0x00D100F474E80E05ULL,
		0x82008E10228C0181ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x000AFB5E8C380A70ULL,
		0xC8ECF17DDDE985C0ULL,
		0x843A84D29795A3EFULL,
		0xE026B3DD41426B31ULL,
		0xF52F623B3E5A2BB2ULL,
		0xEED5B2BF6A3B0EAAULL,
		0x9AC2BA89A6FBD3E9ULL,
		0x61E161D9028C0C1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01B02D463034B797ULL,
		0xB046E76502E9B574ULL,
		0x0626D9160089EF2AULL,
		0x967AED7A338295BAULL,
		0x9C1E7A6B196D9286ULL,
		0xD7F344035BC2A821ULL,
		0x09440398E45AC2FCULL,
		0xC6BEBD23CAF8831FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000294600300210ULL,
		0x8044E16500E98540ULL,
		0x042280120081A32AULL,
		0x8022A15801020130ULL,
		0x940E622B18480282ULL,
		0xC6D100034A020820ULL,
		0x08400288A45AC2E8ULL,
		0x40A021010288001AULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0431C3799C27BC65ULL,
		0xD13D19A2D42A4FFBULL,
		0xEF4093036B6FA70AULL,
		0x549A98BA4E9A71BFULL,
		0xA9A15A5392E99355ULL,
		0xBB5214FF7167C6FDULL,
		0xB14BFAEEE7ABBF86ULL,
		0x1D2D5EFABA0FD783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67224799F1034A8DULL,
		0x67DB5414AD9A83DFULL,
		0x8C34FE1C542D7A55ULL,
		0x26515D0C33181958ULL,
		0x6F61F30399461E34ULL,
		0xD32D3A7293BC862EULL,
		0x3E7668BB670CC63EULL,
		0x281E0A3F7CA10EFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0420431990030805ULL,
		0x41191000840A03DBULL,
		0x8C009200402D2200ULL,
		0x0410180802181118ULL,
		0x2921520390401214ULL,
		0x930010721124862CULL,
		0x304268AA67088606ULL,
		0x080C0A3A38010683ULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1EBF49AF4E59C0CULL,
		0x0ECB18005799E439ULL,
		0xE3CB3DB32B8D6532ULL,
		0xA58790AE14273E2EULL,
		0xC46F9C8305F5AFCDULL,
		0x1EC0553B317BFD0FULL,
		0x274D324FB8BA0706ULL,
		0x8D875F76B371C4ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DE8BD7414F30A67ULL,
		0xB1BFD10EADB5ABF1ULL,
		0x78B2C1DEB5FA256EULL,
		0x29FEC1EF73E2A2BCULL,
		0xF2DBAA30114E3183ULL,
		0x2D2AD41B6E2FE738ULL,
		0x1A806D470C59D251ULL,
		0x71B3C0029D122057ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81E8B41014E10804ULL,
		0x008B10000591A031ULL,
		0x6082019221882522ULL,
		0x218680AE1022222CULL,
		0xC04B880001442181ULL,
		0x0C00541B202BE508ULL,
		0x0200204708180200ULL,
		0x0183400291100044ULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF21CA06EBDCD22BULL,
		0x5F6011FF05AA2F53ULL,
		0x610C3B1BDB957D2CULL,
		0x35A6B112771D5FD5ULL,
		0x5A02F38BEE6FE350ULL,
		0xECCCBA2AA99DC2F7ULL,
		0xD7E91DFB248C0FF4ULL,
		0x68E2D4428DB4B765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A5C483B6F8D96BULL,
		0xCB2817EF8A7ED3F7ULL,
		0x7259B4AA2EC206B0ULL,
		0x43A75A608DC9DCD1ULL,
		0x23258705F017C84FULL,
		0x56EF217B484FDCBBULL,
		0xB74DFB8FFC3138C8ULL,
		0xC43E5D9E32406235ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1021C002A2D8D02BULL,
		0x4B2011EF002A0353ULL,
		0x6008300A0A800420ULL,
		0x01A6100005095CD1ULL,
		0x02008301E007C040ULL,
		0x44CC202A080DC0B3ULL,
		0x9749198B240008C0ULL,
		0x4022540200002225ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9ECC7500BBD391ULL,
		0x8D32F19941C655E5ULL,
		0x526167421C1CB713ULL,
		0xCD5B91258FE1EE81ULL,
		0xFB5B9727EEFE766AULL,
		0x46E4DFDBCA5061C9ULL,
		0x732020A53D5CCD27ULL,
		0x753F90F23704A607ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B13031E5440B799ULL,
		0x3325754E114E7F3FULL,
		0xE7C66D593EFA9051ULL,
		0x375D8D9B1B9BD5C8ULL,
		0xEECBB70A27CD3E37ULL,
		0xCB291138AF5760BEULL,
		0xF7A63D58ABE0177FULL,
		0x01D2086A70B7FC10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A12001400009391ULL,
		0x0120710801465525ULL,
		0x424065401C189011ULL,
		0x055981010B81C480ULL,
		0xEA4B970226CC3622ULL,
		0x422011188A506088ULL,
		0x7320200029400527ULL,
		0x011200623004A400ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA2FEBFDFFC415F5ULL,
		0x1F375A5A25C996E8ULL,
		0xE1D0248759362DD0ULL,
		0x4B135441DE5B01CBULL,
		0xE171D23732DEA5A1ULL,
		0x471BDA401B274128ULL,
		0x58CBA6214646E1DFULL,
		0x60E78911EC8D01C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECA0F2AE68DC2056ULL,
		0x01026FFD6A0AB890ULL,
		0x598BD693F26FCE68ULL,
		0xD4AC5DE79D0C1A0EULL,
		0x80A1583DCB4DE27DULL,
		0x241334516FDE51FFULL,
		0x78C4F768260011BFULL,
		0xAB9D385E2193E3A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA820E2AC68C40054ULL,
		0x01024A5820089080ULL,
		0x4180048350260C40ULL,
		0x400054419C08000AULL,
		0x80215035024CA021ULL,
		0x041310400B064128ULL,
		0x58C0A6200600019FULL,
		0x2085081020810184ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7C4A0D78DCDEB62ULL,
		0x4431362A082D4E3AULL,
		0xCC2B2FBDA24F9A9CULL,
		0x819592FD738A0EA0ULL,
		0xD3A6ECFC53C68582ULL,
		0x077160563B27D575ULL,
		0x317D9F276123268AULL,
		0x0F83C92B6575D34CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC1B318258FF1FE2ULL,
		0xCB659676C66E02B0ULL,
		0x5AA9F9A8562D2B00ULL,
		0x16CC8F38AE65C6C3ULL,
		0xBD7A94F501A12FE4ULL,
		0x7A771001C79B9A20ULL,
		0x6AD7DC1FBA707E0FULL,
		0xF58C030D4492E3AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA400208208CD0B62ULL,
		0x40211622002C0230ULL,
		0x482929A8020D0A00ULL,
		0x0084823822000680ULL,
		0x912284F401800580ULL,
		0x0271000003039020ULL,
		0x20559C072020260AULL,
		0x058001094410C30CULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D7D94CAB8DACB27ULL,
		0xEC27A177D4987E2DULL,
		0x53B276446DA4ACB3ULL,
		0xE3D6681B342FA1B9ULL,
		0x6E1664513471BB11ULL,
		0x710E569EFF68867FULL,
		0x84EF24B0520D1BF3ULL,
		0x080A6AA4B32D1B0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D7E3831540A0622ULL,
		0x4211D2FC54F36C45ULL,
		0xF3D40572DE5269C9ULL,
		0x90C613DF7CE9804EULL,
		0x58962656CEDB10EBULL,
		0x315929B84F8296A2ULL,
		0x8433AA1CB5810B78ULL,
		0xD68392CFEF0774B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D7C1000100A0222ULL,
		0x4001807454906C05ULL,
		0x539004404C002881ULL,
		0x80C6001B34298008ULL,
		0x4816245004511001ULL,
		0x310800984F008622ULL,
		0x8423201010010B70ULL,
		0x00020284A3051001ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94FDDA69C781A972ULL,
		0x9E3AB753B74C0195ULL,
		0x67CA5CB5136455D5ULL,
		0x33F4D3483D201D69ULL,
		0x94D0A14C45C0FC9BULL,
		0xF1FBBFD01094DA48ULL,
		0x3854DF86F0CEB384ULL,
		0x27BB7C9778D79D8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A34995CB7C23D2ULL,
		0x8DADEBE79FFFD6B0ULL,
		0x06F019883832F0ACULL,
		0xD01BA3CB186A49B4ULL,
		0x0E5ACFAD1A974289ULL,
		0x4D09D671E464912EULL,
		0x35091CB57DE32BACULL,
		0x5C85FE6906A7D902ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A14801C3002152ULL,
		0x8C28A343974C0090ULL,
		0x06C0188010205084ULL,
		0x1010834818200920ULL,
		0x0450810C00804089ULL,
		0x4109965000049008ULL,
		0x30001C8470C22384ULL,
		0x04817C0100879902ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DE7FDCD6DB5CCC1ULL,
		0xEE41EF2DA766CEABULL,
		0x05297DA88AAC9C2BULL,
		0x8C700E0855C6ACF1ULL,
		0x5BA5F14109E5EB89ULL,
		0x35E6A7BD32A12BA3ULL,
		0x4657A653CBA5C527ULL,
		0xFE673CFA7CB3D4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5193607404267EAULL,
		0x369E90DBAB4D2D3BULL,
		0x2B6DF466D65668CBULL,
		0x8A0DC22ADD0BDC40ULL,
		0x27E512EDA085D80BULL,
		0xC7FBFCA247A08717ULL,
		0x1BA9FE35DAD3107EULL,
		0x7A06A77935340F91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75013405400044C0ULL,
		0x26008009A3440C2BULL,
		0x012974208204080BULL,
		0x8800020855028C40ULL,
		0x03A510410085C809ULL,
		0x05E2A4A002A00303ULL,
		0x0201A611CA810026ULL,
		0x7A06247834300481ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4F0E0BF997EB988ULL,
		0xFD55E7C40E53C8FFULL,
		0xCDF051E4BA0DD8BFULL,
		0x4BDD7E4B3C538BF4ULL,
		0x6BB150773AA1D00CULL,
		0x7D9B5975959D7AD5ULL,
		0xBFED9B77B0B46057ULL,
		0xCB37D8D691DC4060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955947C132E2EA12ULL,
		0xCD4D2990E53A935CULL,
		0xB3DA5B885AAD902BULL,
		0x9E24FCC4A63410B7ULL,
		0x97BBB002A5BB7CD7ULL,
		0x0D8B1921DA71334EULL,
		0x81B29190A94020E2ULL,
		0x41645F2A43416278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x945040811062A800ULL,
		0xCD4521800412805CULL,
		0x81D051801A0D902BULL,
		0x0A047C40241000B4ULL,
		0x03B1100220A15004ULL,
		0x0D8B192190113244ULL,
		0x81A09110A0002042ULL,
		0x4124580201404060ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43D05EB4B4F5D386ULL,
		0xE26807AD8AB956E4ULL,
		0x05CE09283096A2F3ULL,
		0x126B3BB2AEA1A579ULL,
		0xF3DD524271AA563EULL,
		0xC83A13BAAE932EDDULL,
		0x6F8DBAE8387C234CULL,
		0xA4F420721D075224ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2E0DF0A3C39E71ULL,
		0x757E8E94736EFDFDULL,
		0x754A03BCF83A14F5ULL,
		0x304651D2C839A19EULL,
		0x91D36E920DF38321ULL,
		0x6A91A1D8759291E1ULL,
		0x6E987143AEAACB78ULL,
		0x9B9D495C32752BFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03000CB0A0C19200ULL,
		0x60680684022854E4ULL,
		0x054A0128301200F1ULL,
		0x104211928821A118ULL,
		0x91D1420201A20220ULL,
		0x48100198249200C1ULL,
		0x6E88304028280348ULL,
		0x8094005010050224ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD770EB620C151DADULL,
		0x0BB1EDD00962C2ACULL,
		0xAAE7EB885E233CA9ULL,
		0x9BCEBA315DE4C3D1ULL,
		0x0D6E0DF0BD2A204AULL,
		0x91E0B96A8B422F4EULL,
		0x9B0E507C79856D1EULL,
		0x39321A74974FB423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7CE5F1A4D37E1F9ULL,
		0xFED48DC06A26A354ULL,
		0x93E3DC85E6BE8026ULL,
		0x879FBE68BBFE75BAULL,
		0x3CCD656CCF3D94A1ULL,
		0x2AE416C836085352ULL,
		0x856E090DE0E8089DULL,
		0x52EF686CB9E39396ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87404B020C1501A9ULL,
		0x0A908DC008228204ULL,
		0x82E3C88046220020ULL,
		0x838EBA2019E44190ULL,
		0x0C4C05608D280000ULL,
		0x00E0104802000342ULL,
		0x810E000C6080081CULL,
		0x1022086491439002ULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D64B97E70EAE456ULL,
		0x4B03E1D9C1552139ULL,
		0x4B48304E38706267ULL,
		0x2868105C6FA3209FULL,
		0x6C9116F4E5CB08B3ULL,
		0x9D4912562FA403CDULL,
		0x8B992D0C3D25AEF6ULL,
		0x90BCB97FC47FB973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE57EF394F5189E0DULL,
		0x3C17DC48D4D17C80ULL,
		0x44C4604BF873B7EBULL,
		0x621032446738D2B5ULL,
		0x4FC8DE55FC33C240ULL,
		0x32CED4E24F6ADA14ULL,
		0x88C337F4CA7D2F1DULL,
		0xCBB1DE78F4B2444FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8564B11470088404ULL,
		0x0803C048C0512000ULL,
		0x4040204A38702263ULL,
		0x2000104467200095ULL,
		0x4C801654E4030000ULL,
		0x104810420F200204ULL,
		0x8881250408252E14ULL,
		0x80B09878C4320043ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99A2AE9070AEB42FULL,
		0x15CF471D69EE4C11ULL,
		0x632D2DE6A304913FULL,
		0x03E365C78313182EULL,
		0xE1570A7C4EBCA983ULL,
		0x91FCEA333A3730F7ULL,
		0x05E5A1F6A346E482ULL,
		0x296C7D22694DAA07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A786A298D83F85ULL,
		0xCD088E1EE7A9F9D9ULL,
		0x36397B0BD880084EULL,
		0xD7E3FF013EA8374AULL,
		0x6836F5FC6D6A3ECAULL,
		0x87A04FADB0F70317ULL,
		0x50E957DF66F9BAF9ULL,
		0x96647B7A9E3BA784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10A2868010883405ULL,
		0x0508061C61A84811ULL,
		0x222929028000000EULL,
		0x03E365010200100AULL,
		0x6016007C4C282882ULL,
		0x81A04A2130370017ULL,
		0x00E101D62240A080ULL,
		0x006479220809A204ULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3510BF6375E49E6DULL,
		0x7B7C021E9CC8762FULL,
		0x4C4FADAE30591DFBULL,
		0x6F910B58B443E002ULL,
		0x4F83607410794B19ULL,
		0x13A95B2C97F83F05ULL,
		0xBFDFB96A73DBC116ULL,
		0x1CE40033AE3D402EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030F1E8F865E46E8ULL,
		0xE44428658B26D3FBULL,
		0x529F9D2B7B873183ULL,
		0x67B09FB00A667249ULL,
		0xA2A0D98AF6C19DD6ULL,
		0x59481AED3725AE9EULL,
		0xAA0B953EFC627A7DULL,
		0xDBD524E3DFC57A33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01001E0304440668ULL,
		0x604400048800522BULL,
		0x400F8D2A30011183ULL,
		0x67900B1000426000ULL,
		0x0280400010410910ULL,
		0x11081A2C17202E04ULL,
		0xAA0B912A70424014ULL,
		0x18C400238E054022ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65057B28BC98A539ULL,
		0xAFE51DA144EE4B74ULL,
		0x52EBDCF5EB89DB2DULL,
		0x2CB74D22B6B7C83CULL,
		0x9E12630624157AFCULL,
		0xEC57E6F095FD52DCULL,
		0xFB69951E1D6BCF35ULL,
		0x26BFD568970DA98BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9CA160728EA7FEBULL,
		0xA32B87C6BB46EF98ULL,
		0x01130328CB1140C6ULL,
		0x724BF0C44B5FC8BAULL,
		0xD0C5C507AD3C5A4BULL,
		0x8470C04E65447570ULL,
		0xB1D09627F04EA563ULL,
		0x905E4D7D8E8BD84AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4100120028882529ULL,
		0xA321058000464B10ULL,
		0x00030020CB014004ULL,
		0x200340000217C838ULL,
		0x9000410624145A48ULL,
		0x8450C04005445050ULL,
		0xB1409406104A8521ULL,
		0x001E45688609880AULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA679DAFDD021744ULL,
		0x8363AB96215C9388ULL,
		0xD78934E963253E47ULL,
		0xF6751824D920DE6BULL,
		0xF52E63549C3123D3ULL,
		0x7ED4B393F0D4CF46ULL,
		0x5EEF562AEFC47197ULL,
		0x6A53D3A0245BC32FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADA2571D347B2574ULL,
		0x6A87ABE92EDD40FAULL,
		0x9DACCE1BC2A0E1FDULL,
		0x32F464D8B513A275ULL,
		0xD84E6D2B6B1E52DFULL,
		0x6FB7FD8CA9C64351ULL,
		0x226C33C17C792028ULL,
		0xA38808C8F4C6D328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA822150D14020544ULL,
		0x0203AB80205C0088ULL,
		0x9588040942202045ULL,
		0x3274000091008261ULL,
		0xD00E6100081002D3ULL,
		0x6E94B180A0C44340ULL,
		0x026C12006C402000ULL,
		0x220000802442C328ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18833B9E44D23C9CULL,
		0x0A94BF71DC6365A6ULL,
		0x90D4E1CA972F81DDULL,
		0x935A0A344A44E112ULL,
		0xA5E6DBB66AE0B9B1ULL,
		0xDD292CEC4067E6C6ULL,
		0x3437B03C6CF59F46ULL,
		0x1BF15108E9D9046AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA827C57165D6EEA8ULL,
		0xA9AAFE2672ADC823ULL,
		0x65F9EE0EAE1D1548ULL,
		0xEED80A83BFBCBD52ULL,
		0x8210AE1F513069D3ULL,
		0x42B2B50B1B4CBE16ULL,
		0xCA10876BBA40129AULL,
		0xAC8DEBCBBB53E86BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0803011044D22C88ULL,
		0x0880BE2050214022ULL,
		0x00D0E00A860D0148ULL,
		0x82580A000A04A112ULL,
		0x80008A1640202991ULL,
		0x402024080044A606ULL,
		0x0010802828401202ULL,
		0x08814108A951006AULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC331078D83AF2A11ULL,
		0xBBBB03F09562DD26ULL,
		0x04084743BCE1D3B6ULL,
		0xF89F56BEBB45CB3BULL,
		0x5F48B5EA99729E6AULL,
		0x9F9611A316839967ULL,
		0xAD337F4C666375BBULL,
		0x2741E6D95339071EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0EF4816532B9F92ULL,
		0x429521944CAAE278ULL,
		0x519A3D02EED1BFFAULL,
		0x1B8D7131B058AE89ULL,
		0x8862FA4F2F7DD553ULL,
		0xE5308380059F1AEDULL,
		0xDEFFB63A1D85DA2BULL,
		0xC5A43883672EF12AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80210004032B0A10ULL,
		0x029101900422C020ULL,
		0x00080502ACC193B2ULL,
		0x188D5030B0408A09ULL,
		0x0840B04A09709442ULL,
		0x8510018004831865ULL,
		0x8C3336080401502BULL,
		0x050020814328010AULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DC611F8956B8650ULL,
		0x740387A1667B5DF3ULL,
		0x0EE5DFB1F1371AACULL,
		0xC0545609272272EAULL,
		0x83CC50AC44439173ULL,
		0xDFBBD6134AFB388EULL,
		0x1A47CB6CFE84B79CULL,
		0xE002D840ED856923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD543494DEB333C15ULL,
		0x2629206977969A4AULL,
		0x14878C9015988F04ULL,
		0xE8D9E4BFA6CDD930ULL,
		0xB59FF707F5C70D9FULL,
		0x824707EBD9FCFC23ULL,
		0xD048941582E82B43ULL,
		0x3145BBF5E2F1D53CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1542014881230410ULL,
		0x2401002166121842ULL,
		0x04858C9011100A04ULL,
		0xC050440926005020ULL,
		0x818C500444430113ULL,
		0x8203060348F83802ULL,
		0x1040800482802300ULL,
		0x20009840E0814120ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC266C4AF26DC071BULL,
		0x9570BA3EBB29C966ULL,
		0x7988F20E6F9E99D7ULL,
		0x01A349AD53CBD8D0ULL,
		0x1DCD7EB986C3F430ULL,
		0x2AB25777C7CC0A99ULL,
		0xB80ACD536F2286BBULL,
		0x2409788B077FC38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D4140EF00D9FB5ULL,
		0x53B73BBFF5687E33ULL,
		0x81611438D9DA579DULL,
		0xA8F33A43569FF095ULL,
		0x84B99526C30721C1ULL,
		0x6722B585F5640B6CULL,
		0x6079CF2CEE38F9F8ULL,
		0xA8C1AF5319ACF3E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0044040E200C0711ULL,
		0x11303A3EB1284822ULL,
		0x01001008499A1195ULL,
		0x00A30801528BD090ULL,
		0x0489142082032000ULL,
		0x22221505C5440A08ULL,
		0x2008CD006E2080B8ULL,
		0x20012803012CC385ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA46399158A762DFFULL,
		0xFA97BDB9F811E617ULL,
		0xB692329B6287B9FFULL,
		0x5F4A68D7259AC126ULL,
		0xF515D78731FB5800ULL,
		0xBA3CF8EB46AA1AFEULL,
		0x4532B9B79B2FEC25ULL,
		0xADA562AE09147F7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA67E7962FB99FE55ULL,
		0xF839799CE5051498ULL,
		0x65F44DC613855F01ULL,
		0x116AD79DBD615CD1ULL,
		0x16A6A53178E150B8ULL,
		0xB9EA98B721E2AAE8ULL,
		0xF7D7D4A6A8D1BA1FULL,
		0x8B94DDE361CF6F71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA46219008A102C55ULL,
		0xF8113998E0010410ULL,
		0x2490008202851901ULL,
		0x114A409525004000ULL,
		0x1404850130E15000ULL,
		0xB82898A300A20AE8ULL,
		0x451290A68801A805ULL,
		0x898440A201046F71ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46DDA9881E86A581ULL,
		0x5A7BDA01A8C796BCULL,
		0xBD50C20A460EAAF4ULL,
		0x85722A3631134A51ULL,
		0x3D8DF0EFFE624131ULL,
		0x9CAB73788270CCF3ULL,
		0x57EE5C4AB51E42A2ULL,
		0x78E37248386134BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x444BDA9058E0F615ULL,
		0xEDC913A968B3BAC1ULL,
		0x2A0F847F459EFC7FULL,
		0x84D9209E137A462BULL,
		0x437A965D1F388C1AULL,
		0x0639D8FB1F4B9435ULL,
		0x4A955AE76D4ECD13ULL,
		0x29F91743F3F78378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x444988801880A401ULL,
		0x4849120128839280ULL,
		0x2800800A440EA874ULL,
		0x8450201611124201ULL,
		0x0108904D1E200010ULL,
		0x0429507802408431ULL,
		0x42845842250E4002ULL,
		0x28E1124030610038ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5BFA631DB3AA7B9ULL,
		0xACBC1D1C1928476AULL,
		0x9B601D105D24A62BULL,
		0xD5F2F9107C7B903FULL,
		0x1FDEE7E8DCE50927ULL,
		0x26A252749F023A49ULL,
		0x2AB5F1C99B5974D1ULL,
		0x8C257D6D2CFAA697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E76BFA0B40DD1A9ULL,
		0xDFD8925BBFA0D89EULL,
		0x5665F0BA122C6A47ULL,
		0x2728C9944FBF00A5ULL,
		0x5730614D15E9F4B6ULL,
		0x705BE8E0F6B2D18AULL,
		0xB77C15052ED7AC44ULL,
		0xA492E62B55F3A6C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2436A620900881A9ULL,
		0x8C9810181920400AULL,
		0x1260101010242203ULL,
		0x0520C9104C3B0025ULL,
		0x1710614814E10026ULL,
		0x2002406096021008ULL,
		0x223411010A512440ULL,
		0x8400642904F2A680ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC92F89DBF1770244ULL,
		0xD6AE28F3F121B3B5ULL,
		0xB3FE11A7FEDAFE30ULL,
		0xE4C85CF3E7E1814AULL,
		0x3E39D9094D834FD5ULL,
		0x3FB78D3B20CCCD3BULL,
		0x4FE3954F00352767ULL,
		0xD0AAA5501CC3998AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BC9AAB6D9B6844FULL,
		0xEC08341817A0880FULL,
		0x47A0DCC1E14A81F8ULL,
		0xB80A24B44BE3EEB1ULL,
		0x41A0020BDC8D8919ULL,
		0x325BDEE85000F570ULL,
		0xD54799951C15C96BULL,
		0xFB90D340B73EA884ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49098892D1360044ULL,
		0xC408201011208005ULL,
		0x03A01081E04A8030ULL,
		0xA00804B043E18000ULL,
		0x002000094C810911ULL,
		0x32138C280000C530ULL,
		0x4543910500150163ULL,
		0xD080814014028880ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6BC8E45CDAE2AC6ULL,
		0x0F4443E7FDE9F14CULL,
		0xE12E62186B884FEBULL,
		0x80022A483797657EULL,
		0x6B535B5DB47F7E4BULL,
		0xEEA17A5E788401BFULL,
		0xFB1ADB84FCE356D5ULL,
		0x52A26E435C8CF29BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B374458361F0244ULL,
		0x6F3A6AB2A42AC3F5ULL,
		0x4C6B18916C01B330ULL,
		0xABD854FEEF9F1B21ULL,
		0xE0E7AF34063E6201ULL,
		0x96EAF5C79022B6BDULL,
		0xD7AE10C8126ACB81ULL,
		0x9100B89AECDE9C28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42340440040E0244ULL,
		0x0F0042A2A428C144ULL,
		0x402A001068000320ULL,
		0x8000004827970120ULL,
		0x60430B14043E6201ULL,
		0x86A07046100000BDULL,
		0xD30A108010624281ULL,
		0x100028024C8C9008ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1146F9056B8BCD50ULL,
		0x4C527F393998FAB0ULL,
		0x6528CF9D0A4F4919ULL,
		0x23CFCAFC9C91DFF2ULL,
		0xEC0B52011BE52B41ULL,
		0xD187230EB989A309ULL,
		0xFF783A1D9CE403A7ULL,
		0x4C1273F0699C84A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60604DF9364E6A45ULL,
		0x7A0FA495349AB048ULL,
		0xD7894654C86F1D65ULL,
		0xC122941F8DCC280AULL,
		0xF7AC9B1E3D5C0D93ULL,
		0x6B67202CB5F55BA3ULL,
		0xFBCCACFB66763ABDULL,
		0xD74757EEDA81026FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00404901220A4840ULL,
		0x480224113098B000ULL,
		0x45084614084F0901ULL,
		0x0102801C8C800802ULL,
		0xE408120019440901ULL,
		0x4107200CB1810301ULL,
		0xFB482819046402A5ULL,
		0x440253E048800024ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09EF669C8683C190ULL,
		0x374F542FB0985EC4ULL,
		0xBD6853E8D211C1A8ULL,
		0x7444343704FC04FBULL,
		0x4719717646D4624DULL,
		0x788F64C92FD41920ULL,
		0x3BD20442FF249338ULL,
		0x8766EB358F550FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BAF3ACBDF7C08D4ULL,
		0xA949F6A43EA34C76ULL,
		0x8B868801E02AA380ULL,
		0x57B129B66E806778ULL,
		0x9C08E43C382474F4ULL,
		0xFE0371AE4C0CB257ULL,
		0x553952B480433E7BULL,
		0xF9F5BB7627C15CCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09AF228886000090ULL,
		0x2149542430804C44ULL,
		0x89000000C0008180ULL,
		0x5400203604800478ULL,
		0x0408603400046044ULL,
		0x780360880C041000ULL,
		0x1110000080001238ULL,
		0x8164AB3407410CC0ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x603A167431E72EABULL,
		0x8C82576D60BE5BBBULL,
		0xD7F18DA728C24823ULL,
		0x2EBD5A64778166E8ULL,
		0x9D07B9BED567E2ECULL,
		0x9962D1C35400D9ABULL,
		0x7892F4574001C624ULL,
		0x7D57CF90F0A1CAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4802968C18A5FCULL,
		0x7EAA290783198109ULL,
		0xF1B4EBC49FA26259ULL,
		0x8BD6BF47F867379CULL,
		0x17C1B5202CCD2B4CULL,
		0x0772A0A881F4A13AULL,
		0x2449BC4985417A8EULL,
		0x6A60D166879F46E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40080214000024A8ULL,
		0x0C82010500180109ULL,
		0xD1B0898408824001ULL,
		0x0A941A4470012688ULL,
		0x1501B1200445224CULL,
		0x016280800000812AULL,
		0x2000B44100014204ULL,
		0x6840C100808142A0ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6023EBCADF99BF77ULL,
		0x9E57B3BCE5505BF3ULL,
		0xAA04135880722B55ULL,
		0x756F40B02E4ADBEBULL,
		0x3257BCE933838701ULL,
		0x152B87734A65A412ULL,
		0x7AF06387B056232EULL,
		0x74328174AAC0F0D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C658B183B1C7056ULL,
		0x9274A65B0E17C8E7ULL,
		0xDE7A911265E5375FULL,
		0xDE433FEB5A76E9D2ULL,
		0x57307C8CC9D60693ULL,
		0x09C73E8520EEA100ULL,
		0x12DE91EB6053FB9BULL,
		0x4CB8CB2753876DBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60218B081B183056ULL,
		0x9254A218041048E3ULL,
		0x8A00111000602355ULL,
		0x544300A00A42C9C2ULL,
		0x12103C8801820601ULL,
		0x010306010064A000ULL,
		0x12D001832052230AULL,
		0x4430812402806092ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D267496A4D41A2AULL,
		0xCF5E7E540511D015ULL,
		0xB5BF14CEEB76463DULL,
		0x44605514CE6D7B89ULL,
		0x2DAE160132FD7ECDULL,
		0x71E3B3C63802979BULL,
		0x0FA70099D33E2DABULL,
		0x4861E74BBA855B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30C6FCE269DD7685ULL,
		0xF08E3D59CF5D0264ULL,
		0x4552A4761EA13F4DULL,
		0x95A4D96CE47A371BULL,
		0xD27691D15138FEF8ULL,
		0x21F1E8869EBEEDF8ULL,
		0xD4896DFC5242568EULL,
		0xBD5E89B56B46E83BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1006748220D41200ULL,
		0xC00E3C5005110004ULL,
		0x051204460A20060DULL,
		0x04205104C4683309ULL,
		0x0026100110387EC8ULL,
		0x21E1A08618028598ULL,
		0x048100985202048AULL,
		0x084081012A044829ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FF864A588BCEC88ULL,
		0x413DE79B88CD8946ULL,
		0xFACA38E4FCEE909CULL,
		0x392545F81E3D4199ULL,
		0xB7C38E2AD2405C6EULL,
		0x0D099B2D553397BCULL,
		0x2279BFA82C41DC3CULL,
		0x7AF35CE0043F2872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EFF95FA23B53FC0ULL,
		0xBF5742437210C57BULL,
		0x87AE4C77535894DCULL,
		0xCD90972725771AE4ULL,
		0xE0AD1C398ED61C74ULL,
		0x3A5A2DB330300871ULL,
		0x2F9C37A17C16F213ULL,
		0xBB76149F6ABC0730ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EF804A000B42C80ULL,
		0x0115420300008142ULL,
		0x828A08645048909CULL,
		0x0900052004350080ULL,
		0xA0810C2882401C64ULL,
		0x0808092110300030ULL,
		0x221837A02C00D010ULL,
		0x3A721480003C0030ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92EEBD633822D769ULL,
		0x9C50A78225A5A962ULL,
		0x7013CB4F1C15019BULL,
		0x1DB5288BAB7E4F89ULL,
		0x507EBCAA739969A6ULL,
		0x4BAC7AB72D548C3CULL,
		0xF717662A85839B0BULL,
		0x3088E584007692A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83C354B6F5586EBULL,
		0x50C23A8CAA033D95ULL,
		0xB551635E2A2F7A81ULL,
		0xBAE307D70306AEE2ULL,
		0x8BDD54C5A45093CBULL,
		0x67E4FDD7EC1D3329ULL,
		0xC93EB89994CBB6F1ULL,
		0x3F6880D862588F17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902C354328008669ULL,
		0x1040228020012900ULL,
		0x3011434E08050081ULL,
		0x18A1008303060E80ULL,
		0x005C148020100182ULL,
		0x43A478972C140028ULL,
		0xC116200884839201ULL,
		0x3008808000508201ULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7F99371209A5109ULL,
		0xFD173B092B3C48F2ULL,
		0xF5FEEDD9826367CEULL,
		0x504E29513F3D9ADEULL,
		0xFB20190B8B3A0AE8ULL,
		0x5EE89A61B114E828ULL,
		0xB57460B386D9654EULL,
		0xEFACCEB682CF006DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F5F330D71E959EULL,
		0x7BDC7DDE7D8661B5ULL,
		0x49450D368BC8A50DULL,
		0x1D873B15A465E318ULL,
		0x4A560851A67253A9ULL,
		0x01AC4116659D6353ULL,
		0xB44E73141059B9A4ULL,
		0x079C6CB86BC2B649ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80F19330001A1108ULL,
		0x79143908290440B0ULL,
		0x41440D108240250CULL,
		0x1006291124258218ULL,
		0x4A000801823202A8ULL,
		0x00A8000021146000ULL,
		0xB444601000592104ULL,
		0x078C4CB002C20049ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0EE28ED4957CB32ULL,
		0xA31DD28FE0FFDAF3ULL,
		0xE407478BD73BF4EFULL,
		0x018FE9B5CFB23C3EULL,
		0xC68C4545504058B3ULL,
		0xD26C1C915E873518ULL,
		0xC6C3204D6E83C9CEULL,
		0x211FC479BAB70D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A76E305E1CF6EF8ULL,
		0x89E1BC547A078E08ULL,
		0x8E64D6CF12A63C27ULL,
		0x941C5B31D54CBE2BULL,
		0x659143E4FAF843D6ULL,
		0x84E5537A9D09ACAAULL,
		0xB23F8EB63838BC9BULL,
		0x181DA38D1B186202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0066200541474A30ULL,
		0x8101900460078A00ULL,
		0x8404468B12223427ULL,
		0x000C4931C5003C2AULL,
		0x4480414450404092ULL,
		0x806410101C012408ULL,
		0x820300042800888AULL,
		0x001D80091A100000ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16CA406A2B496052ULL,
		0xCE37A8DE3854C8D1ULL,
		0x34254FA20B3AD402ULL,
		0xC7450A40B458BAF0ULL,
		0x75BEAD7EAE79F397ULL,
		0x15EEC276B06E8CB0ULL,
		0x71C7552E6E0E39DCULL,
		0x6609DEA43497968BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B48EC6560D3B315ULL,
		0x9B64C7ADC00D74E1ULL,
		0xF4EBC024EC433B18ULL,
		0xCED7E1ABD72B08B2ULL,
		0xA369242618E4DB5FULL,
		0x517408912EDFC996ULL,
		0xAFE0B6AAB795ACF4ULL,
		0x0FBED48497EC2D15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0248406020412010ULL,
		0x8A24808C000440C1ULL,
		0x3421402008021000ULL,
		0xC6450000940808B0ULL,
		0x212824260860D317ULL,
		0x11640010204E8890ULL,
		0x21C0142A260428D4ULL,
		0x0608D48414840401ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x016D66F4A5179F64ULL,
		0x387B4E2C79835D3AULL,
		0x9E67EEE6A65C27A4ULL,
		0x1EF4F9B13FB143FEULL,
		0xD43399E527BD51AAULL,
		0x74F844C42F834832ULL,
		0xC53F01C1D02FCD5AULL,
		0x461AB520CDAFA9C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93147A78C84EBC77ULL,
		0x3966A743816797CBULL,
		0x6AF23D96E2C542C6ULL,
		0xEDA5248BA4BC5151ULL,
		0x1007C0A860C70353ULL,
		0x63D8D2ED03ACECC3ULL,
		0x4A0521B4679DC27FULL,
		0x1CB21F44BE12C58AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0104627080069C64ULL,
		0x386206000103150AULL,
		0x0A622C86A2440284ULL,
		0x0CA4208124B04150ULL,
		0x100380A020850102ULL,
		0x60D840C403804802ULL,
		0x40050180400DC05AULL,
		0x041215008C028182ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD04E52458DE4C8D0ULL,
		0x9C264FF885D4825AULL,
		0x4AC287FFB1790D70ULL,
		0x1506D7E7C42F0952ULL,
		0xC3C035C05866B97CULL,
		0x319F60905BF049E3ULL,
		0x8EE981F7F9E72024ULL,
		0x891782DCD53297CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CB3985F6B80077ULL,
		0x937142A0C7ECC2EEULL,
		0xE4B782EB1655336FULL,
		0x49FF7B01BBE84AC5ULL,
		0x4E6717760B4D3FA4ULL,
		0x175CA4F9D9A6C0CFULL,
		0xB789CF14967F2AD3ULL,
		0xA9EE2C80E4EC9B4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x904A100584A00050ULL,
		0x902042A085C4824AULL,
		0x408282EB10510160ULL,
		0x0106530180280840ULL,
		0x4240154008443924ULL,
		0x111C209059A040C3ULL,
		0x8689811490672000ULL,
		0x89060080C420934CULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFBE7E03A0077C395ULL,
		0xD822FE41CD9FB414ULL,
		0xAF33117F9C29D0AAULL,
		0x80CC949B9100C9B4ULL,
		0xA90881110D838994ULL,
		0xD96735CB99A601BEULL,
		0x9CA91CA385AAD67BULL,
		0x27839A8010A9E030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A83BCAB90AD4D50ULL,
		0x0C86BF3C2BE758FCULL,
		0xE2CC41143ABF7AEEULL,
		0xEB81421B2BF7842CULL,
		0x1F848D40800D4070ULL,
		0xF0AB6AB545D01889ULL,
		0x19AABBB69411BAA8ULL,
		0x96235FB29AE365BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A83A02A00254110ULL,
		0x0802BE0009871014ULL,
		0xA2000114182950AAULL,
		0x8080001B01008024ULL,
		0x0900810000010010ULL,
		0xD023208101800088ULL,
		0x18A818A284009228ULL,
		0x06031A8010A16030ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23BE1F6773256E88ULL,
		0x851370DDA7970ADFULL,
		0x110C898092BCE0A6ULL,
		0x220FAFEA7C26709BULL,
		0x4ABF07D70AF9F58CULL,
		0xDCCB1BCE16CD3021ULL,
		0x9BB1E20CE223E1FEULL,
		0xED497A263E17D50BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E7CCEBC2346F1ECULL,
		0x1F3ED7E9C752CF43ULL,
		0x421CE9034A5CABACULL,
		0xDFC6CD3B833F2E98ULL,
		0x93A2CFFE70424B36ULL,
		0x783F96A9B9DBA87DULL,
		0x1C892F6DDDEB91E9ULL,
		0xE90FC09218D01A9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023C0E2423046088ULL,
		0x051250C987120A43ULL,
		0x000C8900021CA0A4ULL,
		0x02068D2A00262098ULL,
		0x02A207D600404104ULL,
		0x580B128810C92021ULL,
		0x1881220CC02381E8ULL,
		0xE90940021810100AULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35ECC30E9E1D0A65ULL,
		0x4310F4974EE28ADAULL,
		0xBB87D2C5DDD6DE83ULL,
		0xC060BFCEB6BB9C1DULL,
		0x1A92A5EF3E8A0500ULL,
		0xE2536C09676C43FFULL,
		0x6B1C10A495F770EEULL,
		0x39281583B4F81A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA1D3FFB8F49A95ULL,
		0x44B0345A344A7CC1ULL,
		0x0A6EDD26F9638F0AULL,
		0xA077CD148365C87BULL,
		0xD4287AE83385D667ULL,
		0x222EAE49DFA879ACULL,
		0x2496D4C402968795ULL,
		0xEFC96AD945927073ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25A0C30E98140A05ULL,
		0x40103412044208C0ULL,
		0x0A06D004D9428E02ULL,
		0x80608D0482218819ULL,
		0x100020E832800400ULL,
		0x22022C09472841ACULL,
		0x2014108400960084ULL,
		0x2908008104901010ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14F9BE6285539F24ULL,
		0xECB737BA65736603ULL,
		0x3FE8C1FBBAF7DDBFULL,
		0xC4FEA2176DEE0C59ULL,
		0x15DF7FED0F57DC5AULL,
		0x5550B92222647E20ULL,
		0xF92F32BA611E3981ULL,
		0x6E6890E4934AE792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655FE579464524FAULL,
		0x26377F7D58FD398EULL,
		0x0E9CC02D66A1DF1FULL,
		0xB52522D37192DF7DULL,
		0xAC883AE4BDA144F8ULL,
		0xFA5BF805C495F1BAULL,
		0xB69DC7543CD83D2EULL,
		0x9F69CC19B902F63BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0459A46004410420ULL,
		0x2437373840712002ULL,
		0x0E88C02922A1DD1FULL,
		0x8424221361820C59ULL,
		0x04883AE40D014458ULL,
		0x5050B80000047020ULL,
		0xB00D021020183900ULL,
		0x0E6880009102E612ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38C8A3C0DD4FC562ULL,
		0x8AA7AFEC2E972E82ULL,
		0x51CB3BC55C5AA8B0ULL,
		0x39B9E848A96B59DDULL,
		0xEBABE87629CFDE10ULL,
		0x6BF16C9CFD769536ULL,
		0xA71617EC3631DC75ULL,
		0x55F9D7138F9AD27CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x081BF138566813A3ULL,
		0x6F21B0D847943453ULL,
		0x3515333E1A55508FULL,
		0x9B7EBC587B26808BULL,
		0xD49F939277E1B529ULL,
		0x150950E7352187B8ULL,
		0x5428C9BF7C9F6220ULL,
		0x62D94F72B1EA53CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0808A10054480122ULL,
		0x0A21A0C806942402ULL,
		0x1101330418500080ULL,
		0x1938A84829220089ULL,
		0xC08B801221C19400ULL,
		0x0101408435208530ULL,
		0x040001AC34114020ULL,
		0x40D94712818A524CULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E412145A666C395ULL,
		0x6B22AA8F77C40445ULL,
		0x729486DA413FECB1ULL,
		0x59A991BF329A393BULL,
		0xA584CFA9FFC7CC8EULL,
		0x6BCD1847B2141572ULL,
		0x6EEFECB7F66C6CD6ULL,
		0x4B9585B1925A7B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37AFD8B05B369F8BULL,
		0x41EA9F5D7C543456ULL,
		0xC35EA2D579650A48ULL,
		0xB92C226F07AD1F18ULL,
		0xAC75A4AEB1B7E1C4ULL,
		0xC29DE0F0D3340A8DULL,
		0xF58CE7DF89ACFD10ULL,
		0xC6AEBBA2A261F6BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3601000002268381ULL,
		0x41228A0D74440444ULL,
		0x421482D041250800ULL,
		0x1928002F02881918ULL,
		0xA40484A8B187C084ULL,
		0x428D004092140000ULL,
		0x648CE497802C6C10ULL,
		0x428481A08240722AULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB01E0C735D573A0BULL,
		0xE90430F474679335ULL,
		0xDC188F0485BC49EDULL,
		0xA8CE0DC9D3DC74DDULL,
		0xD81322E5DCDD46C0ULL,
		0xF380B87B3F49FC82ULL,
		0x5408AD31976F12C0ULL,
		0x520C9A01E35C4BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B962367578492FULL,
		0x08E3A06C317F5414ULL,
		0x6D468D8058921BFAULL,
		0xD9682943A5658F48ULL,
		0xF2D532C51E398985ULL,
		0x078FD122E8555B59ULL,
		0xE37305EFC51A1788ULL,
		0x8D0D2E67C46060CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA01800325550080BULL,
		0x0800206430671014ULL,
		0x4C008D00009009E8ULL,
		0x8848094181440448ULL,
		0xD01122C51C190080ULL,
		0x0380902228415800ULL,
		0x40000521850A1280ULL,
		0x000C0A01C04040C2ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AB90D2F93A76815ULL,
		0xC5CEFFAA2FE668BCULL,
		0x973ED6167F30040AULL,
		0x8B48507C85D4D638ULL,
		0xCB9C9B092DF19B09ULL,
		0x1ECF5B430214E153ULL,
		0x533C0557D598312DULL,
		0xAA3C8F8E49B16B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B7539530BD1C0CULL,
		0x1CF77E4A71B64512ULL,
		0xA4E0B2D64242DC30ULL,
		0xE0EC63EF9F805B3AULL,
		0x9B4116742B0BA724ULL,
		0x840276BC950C7A86ULL,
		0x17CB86E7F4CF30FAULL,
		0xBAD3F7732C98858AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B1010510A50804ULL,
		0x04C67E0A21A64010ULL,
		0x8420921642000400ULL,
		0x8048406C85805238ULL,
		0x8B00120029018300ULL,
		0x0402520000046002ULL,
		0x13080447D4883028ULL,
		0xAA10870208900102ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8D2A74F2F3511E8ULL,
		0xA4D5914B9F5C502FULL,
		0x20F087B3DA80203AULL,
		0x032BF4A19DE0C443ULL,
		0x32B9EDD3F9DFFD8EULL,
		0xBCD554DE91130317ULL,
		0xA8E4940C1DE68E4CULL,
		0xB9D60B1B7FADAFC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEA4399FF0208612ULL,
		0xF37F7674F5DE78B4ULL,
		0xEA15B7F07739077DULL,
		0x9F1ADB01DB57BBE0ULL,
		0x676FDEEF1523B5DDULL,
		0xE141F007646B6625ULL,
		0x623E051FF52B2BCEULL,
		0x759811F91E90063DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD880210F20200000ULL,
		0xA0551040955C5024ULL,
		0x201087B052000038ULL,
		0x030AD00199408040ULL,
		0x2229CCC31103B58CULL,
		0xA041500600030205ULL,
		0x2024040C15220A4CULL,
		0x319001191E800608ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56FB0832E9435346ULL,
		0x1AD206135E7BEBFDULL,
		0x798C8D6D62BDBBAAULL,
		0xB86C329AD6118E33ULL,
		0x7190A87D06FED184ULL,
		0xD8E65E271725F1C1ULL,
		0x2D0E63B025F5A002ULL,
		0x0AF0F2C66ED9ED6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9DB1CEAB50EE43ULL,
		0x6A59ABF71277C17BULL,
		0x4B074BDFEEB8EE1DULL,
		0x9EDAE537FB9EE3B4ULL,
		0xD1A0671625BDD124ULL,
		0x43BC287B6B8D15AEULL,
		0xD46B71593987087AULL,
		0x655934D2FD8BB5CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56990002A9404242ULL,
		0x0A5002131273C179ULL,
		0x4904094D62B8AA08ULL,
		0x98482012D2108230ULL,
		0x5180201404BCD104ULL,
		0x40A4082303051180ULL,
		0x040A611021850002ULL,
		0x005030C26C89A54AULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3757EDE54D2C4061ULL,
		0x6E36CB65CB3D71F2ULL,
		0x7DEBA5A7C833AAC4ULL,
		0x3EC4514CB515D6C2ULL,
		0xD06D125AF4141F6CULL,
		0x4B07C068CD7D7884ULL,
		0x9A33A3B5B487F9D6ULL,
		0x654B2DD5E6B858EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85040FDB95617581ULL,
		0x407985D8B1FB4554ULL,
		0x027C7B527FE47E32ULL,
		0xBA7DA0D123728819ULL,
		0xA477E4C83B85DD1CULL,
		0x6AC3CF348693162BULL,
		0x5C87A20F0521979AULL,
		0x91F7F824347B4CF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05040DC105204001ULL,
		0x4030814081394150ULL,
		0x0068210248202A00ULL,
		0x3A44004021108000ULL,
		0x8065004830041D0CULL,
		0x4A03C02084111000ULL,
		0x1803A20504019192ULL,
		0x01432804243848E8ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E6CAF98D7973756ULL,
		0xF5FE51DDDF02ACE0ULL,
		0xDAD8C8BF1C6CD8AFULL,
		0xB940B20547C7F100ULL,
		0xB875B08E31D6922BULL,
		0x9EA89687417A804BULL,
		0xA1734A5A26F611C6ULL,
		0x980E8BB519873C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FA9ABD1C170725AULL,
		0x49EEC77BC4AC9547ULL,
		0xA0F4AD0256F1E75BULL,
		0x7CE839D0B69F70F8ULL,
		0x2D7E4859F29781A2ULL,
		0x4A623AB2F1C7C9E0ULL,
		0xBCDCAA4ABEC854BFULL,
		0x24802B97D55DEE9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E28AB90C1103252ULL,
		0x41EE4159C4008440ULL,
		0x80D088021460C00BULL,
		0x3840300006877000ULL,
		0x2874000830968022ULL,
		0x0A20128241428040ULL,
		0xA0500A4A26C01086ULL,
		0x00000B9511052C01ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5BF4F8827086C97ULL,
		0x028ABAD5B05227EDULL,
		0x28FDE080DE97DE28ULL,
		0xA6EC8D9E7FD3F0F1ULL,
		0xE12A5D3CD59179F4ULL,
		0xAFAC29521C1D4C2FULL,
		0xD37F4CDD05A77E4EULL,
		0x0CFEE9A834B26469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E9405ABE3C259D8ULL,
		0xC98AA537F691F153ULL,
		0xA617A44DEC982D9FULL,
		0xFEB5F70A87D99200ULL,
		0x4B3F240DBF6B18B5ULL,
		0x7C31A57A75D3E4A7ULL,
		0xF6B4EA13FFB3F30DULL,
		0x8AF8DA5A8EEE928BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8494058823004890ULL,
		0x008AA015B0102141ULL,
		0x2015A000CC900C08ULL,
		0xA6A4850A07D19000ULL,
		0x412A040C950118B4ULL,
		0x2C20215214114427ULL,
		0xD234481105A3720CULL,
		0x08F8C80804A20009ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FA129B8CCD7C0A2ULL,
		0x590CAED11D7D8B54ULL,
		0x7EEF8142DE6E4421ULL,
		0x24752E3FB1239155ULL,
		0x3C4EA50E610A36C9ULL,
		0xE2B6AF18497A4D76ULL,
		0x43EF7DEDB101E24BULL,
		0x32D42F5EB8F9A704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47614771CC76668BULL,
		0xD3981311DE71DCD5ULL,
		0xBF82C5C955C71345ULL,
		0x1146E32F70425037ULL,
		0x0DFF9E9A4BF6DD36ULL,
		0xDC0A5CFC1336EFB3ULL,
		0xEAF33FAE9E320882ULL,
		0x45D7B4A4F280F132ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47210130CC564082ULL,
		0x510802111C718854ULL,
		0x3E82814054460001ULL,
		0x0044222F30021015ULL,
		0x0C4E840A41021400ULL,
		0xC0020C1801324D32ULL,
		0x42E33DAC90000002ULL,
		0x00D42404B080A100ULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F636989246C648AULL,
		0x9A60D2E19744C7E2ULL,
		0xA49735B190439C14ULL,
		0xE95F693E94FBD3D9ULL,
		0x8C068C926513884DULL,
		0x31C3D06D8C5CFF67ULL,
		0xADAF1474F3DCE5F2ULL,
		0xF3167DD976114675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4BD9D478483EE3FULL,
		0xE5CE0A321C36312AULL,
		0xF38B1E1CDD81080BULL,
		0x708B185800123752ULL,
		0x27BCFB0AAD10F38BULL,
		0x77432E4AA3D6610CULL,
		0x109EFE0D4407AB9BULL,
		0x616BA4B6FB66B3C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042109010400640AULL,
		0x8040022014040122ULL,
		0xA083141090010800ULL,
		0x600B081800121350ULL,
		0x0404880225108009ULL,
		0x3143004880546104ULL,
		0x008E14044004A192ULL,
		0x6102249072000240ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92F4A07BB19827B5ULL,
		0x7B03CF932B358ADEULL,
		0x37D36A057EB4ADECULL,
		0xB8A1FDA1D606DB8CULL,
		0xC9AEB40375F77BD9ULL,
		0xE6329D65436F6C07ULL,
		0x287C775012C23E47ULL,
		0xAB39E3C10E543B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5B6713B56EA685ULL,
		0x518AF3E1C3FD2DFCULL,
		0x69F12CD6A74DB820ULL,
		0xC86B06389377EF1DULL,
		0xACB03B05B0AD77E4ULL,
		0xBB9B6EC46D66F31BULL,
		0x17B8A345553CD28CULL,
		0x6FA373A0D8AEC0AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10502013B1082685ULL,
		0x5102C381033508DCULL,
		0x21D128042604A820ULL,
		0x882104209206CB0CULL,
		0x88A0300130A573C0ULL,
		0xA2120C4441666003ULL,
		0x0038234010001204ULL,
		0x2B21638008040000ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x351BC4DB95892E3EULL,
		0x3FE35B292143C2D9ULL,
		0x4FF3F6230E23E466ULL,
		0x39DBCBC7B214CBF0ULL,
		0xE08F3E6048660C57ULL,
		0xC4E7BD08FD5EAA37ULL,
		0x66173BA6D8A4AA25ULL,
		0x55ECFC0DD42F3A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FFAAF44DFCF09ECULL,
		0x59DB5DCE451D5854ULL,
		0x2202FF1503FF0F43ULL,
		0xC731FD72E5DD519EULL,
		0x91F674F204F3F123ULL,
		0x68F833D3368CCDE4ULL,
		0x0415AA1F381B595EULL,
		0x48C37CB280C1B2B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x251A84409589082CULL,
		0x19C3590801014050ULL,
		0x0202F60102230442ULL,
		0x0111C942A0144190ULL,
		0x8086346000620003ULL,
		0x40E03100340C8824ULL,
		0x04152A0618000804ULL,
		0x40C07C0080013211ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA72EF8D0E903D7CULL,
		0x141A0361B749F8A5ULL,
		0xFAB16A64A3D573CAULL,
		0xA83285F77337F5E3ULL,
		0xE3D20A2318F7D2D7ULL,
		0xF6756E75A7D29D26ULL,
		0x3167AF3CBAF312D4ULL,
		0x5523E7A64CAF07BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21AD9C067C63F5FFULL,
		0x6E8EB5EA41355D1AULL,
		0x03E21E12994744FDULL,
		0x3031F0A5C438DACEULL,
		0xE4C8B9D7C07850AEULL,
		0xE534625842F01BC6ULL,
		0xB3DFFF2E6086B97AULL,
		0xBDA5E789AB8051FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20208C040C00357CULL,
		0x040A016001015800ULL,
		0x02A00A00814540C8ULL,
		0x203080A54030D0C2ULL,
		0xE0C0080300705086ULL,
		0xE434625002D01906ULL,
		0x3147AF2C20821050ULL,
		0x1521E780088001BEULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x591CE8E82CAD4952ULL,
		0x5E2D408A72A2D0FCULL,
		0xA69446730A4A3CCDULL,
		0xD4C53FB43F5E9404ULL,
		0xA1B463C1D043200DULL,
		0xE5162ED7B2552444ULL,
		0x7C172EDE4CFDAC3FULL,
		0x5F1E3228E6EC49EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5142B36B216BD61ULL,
		0xDA1278DCEC346BCAULL,
		0x212D044B51399712ULL,
		0x36E604E5FC337F96ULL,
		0xC1BFF2360F8F1D0DULL,
		0xE964E87918475E09ULL,
		0x4396B4F57933BD2CULL,
		0x4D25F7A19465D93FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0114282020040940ULL,
		0x5A004088602040C8ULL,
		0x2004044300081400ULL,
		0x14C404A43C121404ULL,
		0x81B462000003000DULL,
		0xE104285110450400ULL,
		0x401624D44831AC2CULL,
		0x4D0432208464492BULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD86F067B7640F7FULL,
		0x2E56C93D12BA5D6EULL,
		0x62EB0C9C8137F2C9ULL,
		0xD5F1EAC305A25220ULL,
		0x605E7088FFB89BAFULL,
		0xA125B27F2BB46296ULL,
		0xF916199602347C49ULL,
		0xF114C2A60F20CB85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC31E33B2745E9AB4ULL,
		0xF94119E1FC4581E2ULL,
		0x9B1EE1CA68747CC3ULL,
		0xF7CED33007F4E4FCULL,
		0x78E7EBE4D3ED985AULL,
		0x3D8DF28D71F23192ULL,
		0xE4FB3660C7DE0FF8ULL,
		0x80AB24B647583A10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC106302234440A34ULL,
		0x2840092110000162ULL,
		0x020A0088003470C1ULL,
		0xD5C0C20005A04020ULL,
		0x60466080D3A8980AULL,
		0x2105B20D21B02092ULL,
		0xE012100002140C48ULL,
		0x800000A607000A00ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x189C3F555A92ED96ULL,
		0xFE97931B410C93E9ULL,
		0xC2006FA340BC5F6CULL,
		0x33BB26E4502DD96DULL,
		0x3FECEB5819B800CEULL,
		0x5B199E9BDBDDBF5AULL,
		0xE48AA6C8860CA070ULL,
		0xA104BA630DE6F018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FE75D85C17C49EULL,
		0x2D97C9FE95E1EA1FULL,
		0x8E849BA14B32870DULL,
		0x865845F2DCB86E64ULL,
		0x1450B77A76592103ULL,
		0x7B87B55843038989ULL,
		0x8BF60544B4B8BFF2ULL,
		0xDAA1DD31FA2C7D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x009C35505812C496ULL,
		0x2C97811A01008209ULL,
		0x82000BA14030070CULL,
		0x021804E050284864ULL,
		0x1440A35810180002ULL,
		0x5B01941843018908ULL,
		0x808204408408A070ULL,
		0x8000982108247000ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCFE84265130C246ULL,
		0x06A3892D9DB9E32CULL,
		0x9A047659026E7708ULL,
		0xF62C32D558DE7AE2ULL,
		0x9BE633DBA82ED3DDULL,
		0xBDBDBCA6C1938EDEULL,
		0xFAD1115804110B70ULL,
		0xCCA0045C3D45EF2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8244E043E1A0D4ULL,
		0x24381A237E65CD25ULL,
		0x3BA7ACD74F5A91E5ULL,
		0x933E3675503EC06CULL,
		0x31BF1F2B21ADDEB9ULL,
		0x2888E9ADAA88549FULL,
		0x16D23F189E60E88CULL,
		0xD06DFCD5AD62902FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C82042041208044ULL,
		0x042008211C21C124ULL,
		0x1A042451024A1100ULL,
		0x922C3255501E4060ULL,
		0x11A6130B202CD299ULL,
		0x2888A8A48080049EULL,
		0x12D0111804000800ULL,
		0xC02004542D40802DULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9201E33382925EBULL,
		0xC75A6365277EFA08ULL,
		0x4A5A9B1DA65C8FCFULL,
		0x613D66CD43905373ULL,
		0x9C162AE2B0A514A9ULL,
		0xD1185D7AC4F9541FULL,
		0xE5FCC5A10DE866EBULL,
		0x07C5F83E76967919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B53F0F902FD1EAULL,
		0x3D7AE8C8F51AA28BULL,
		0x3855854EBF1ACD8AULL,
		0x93351B397BC22DAEULL,
		0x66E6302C026F7AB5ULL,
		0x4944FDB4B3A45370ULL,
		0xB0E42092741E425FULL,
		0x064E2425B2C874AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20201E03102901EAULL,
		0x055A6040251AA208ULL,
		0x0850810CA6188D8AULL,
		0x0135020943800122ULL,
		0x04062020002510A1ULL,
		0x41005D3080A05010ULL,
		0xA0E400800408424BULL,
		0x0644202432807009ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AFE2BA6AEE47A85ULL,
		0x228CED64418B2A1BULL,
		0x14B91F222E821631ULL,
		0x7BDD28D1920F931FULL,
		0x5603177A1F514E21ULL,
		0xB799FBED6EBDECDEULL,
		0x3F39CA5383081A71ULL,
		0x3FA746BD7C013610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5622348067B2C4FFULL,
		0xA4A6F42C7C044195ULL,
		0x93CE40AAA8F0549DULL,
		0x5CF0CA71197EB774ULL,
		0xB20BFCD76ECDF521ULL,
		0xB0FF689C4C4EA9D4ULL,
		0xE01231474BEF7520ULL,
		0x00337808CB2DC350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1222208026A04085ULL,
		0x2084E42440000011ULL,
		0x1088002228801411ULL,
		0x58D00851100E9314ULL,
		0x120314520E414421ULL,
		0xB099688C4C0CA8D4ULL,
		0x2010004303081020ULL,
		0x0023400848010210ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0E100AD39ED117EULL,
		0xF9717A406EE231FBULL,
		0xBEAF703473AE7A07ULL,
		0x1F239CDFD9667CBDULL,
		0x74B10D7A0B7B880CULL,
		0x9E732C3584876D48ULL,
		0x42D8D67F72469815ULL,
		0x647351727F3896C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE59AFFE9601B17ULL,
		0xDD3B1E5618D44871ULL,
		0x63D50A2C1790E176ULL,
		0x4049F6C13A5F3674ULL,
		0x51C26BC26BB7922AULL,
		0xD34F0D8542E2404BULL,
		0x7F6A763E4591FE4EULL,
		0x1F6166E929DBCFC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0E100AD29601116ULL,
		0xD9311A4008C00071ULL,
		0x2285002413806006ULL,
		0x000194C118463434ULL,
		0x508009420B338008ULL,
		0x92430C0500824048ULL,
		0x4248563E40009804ULL,
		0x04614060291886C0ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B67CDEFEC7BA3E3ULL,
		0xC10BDC73923C1775ULL,
		0xD78DBF4797C44796ULL,
		0xCF9C7665F82FB351ULL,
		0xAA596B2C50E0F0F7ULL,
		0x29F30D1C10790639ULL,
		0x6616F7C75A7D1D6DULL,
		0xD591494BC1FB42A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F74AD9B679D2506ULL,
		0xBAA2AB8D012CF8F7ULL,
		0xFB1593DE78ED9580ULL,
		0x34BDBE01EC811A05ULL,
		0xBF3C17B411849A51ULL,
		0xFAECDF18586A59CBULL,
		0x06E00972A2CD9A33ULL,
		0x8F8B96FAD638806FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B648D8B64192102ULL,
		0x80028801002C1075ULL,
		0xD305934610C40580ULL,
		0x049C3601E8011201ULL,
		0xAA18032410809051ULL,
		0x28E00D1810680009ULL,
		0x06000142024D1821ULL,
		0x8581004AC0380028ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF879A6BBD43FE05ULL,
		0x21DA59BFA166DDD2ULL,
		0x9F3C8947183E4B68ULL,
		0x885117554A6B6EB7ULL,
		0x6F067C66038F8FFDULL,
		0xF05B6FF9DFA61076ULL,
		0x35E8396814A64AA6ULL,
		0x4248F728793F9EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95AA6F917F738E7ULL,
		0x74BDE6EFCA65BF56ULL,
		0xDC868334AE15055CULL,
		0xA4B1BA88E38C0F85ULL,
		0x9B2413EACB8BD898ULL,
		0x8CE668349E908E56ULL,
		0xE365D44819D24A2CULL,
		0x26474206BD3C3528ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB902826915433805ULL,
		0x209840AF80649D52ULL,
		0x9C04810408140148ULL,
		0x8011120042080E85ULL,
		0x0B041062038B8898ULL,
		0x804268309E800056ULL,
		0x2160104810824A24ULL,
		0x02404200393C1420ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x444C6BAAF506A143ULL,
		0x52A674825688050CULL,
		0x0AAA8BED1828DE46ULL,
		0x64EAF90A8E59028BULL,
		0x8C0F458E8399CE97ULL,
		0x4C75C3196888A3BFULL,
		0x9D8AC09984BC6146ULL,
		0xD58510C0BDA31A16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x326CB8067717B652ULL,
		0xDABC1FB024015A9DULL,
		0xB275FEA7B7C57FD1ULL,
		0x37DEF0C3457DC478ULL,
		0x4C7278765A6AF62DULL,
		0xF28AFCA4AD48AA03ULL,
		0x0932BE9DA08A3D5FULL,
		0x7A51008C2F323E0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004C28027506A042ULL,
		0x52A414800400000CULL,
		0x02208AA510005E40ULL,
		0x24CAF00204590008ULL,
		0x0C0240060208C605ULL,
		0x4000C0002808A203ULL,
		0x0902809980882146ULL,
		0x500100802D221A02ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45A4F50CDA7CCEF4ULL,
		0x015D828DF6EC7BB7ULL,
		0x7A32A45D55C31993ULL,
		0x5072BE85B26A1EF5ULL,
		0x3CBB64ED3499262DULL,
		0xBC9DA9FAF37C3723ULL,
		0x39F7F44B1C4778FBULL,
		0x5F67ECA669815F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F0DE8070F881681ULL,
		0xE319ED61B9BFC5C1ULL,
		0x90BDB3C1F0257BCEULL,
		0x08C1C4DEBC243224ULL,
		0x459C3F0034C4040AULL,
		0x78BFB4CBB09A0F13ULL,
		0xCEE882EB1B59E862ULL,
		0xE3024516541B477DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4504E0040A080680ULL,
		0x01198001B0AC4181ULL,
		0x1030A04150011982ULL,
		0x00408484B0201224ULL,
		0x0498240034800408ULL,
		0x389DA0CAB0180703ULL,
		0x08E0804B18416862ULL,
		0x430244064001476DULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B9806E2CBB3265DULL,
		0x6B21173053797CE0ULL,
		0xA45FC0A9C7EB39C7ULL,
		0xA9E850C76430FFF6ULL,
		0x9D459220DDDFCAC3ULL,
		0x10254E0D5ADC517FULL,
		0x90295976F8EBA13CULL,
		0x592612CD36184631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B9A5BCD4974C7D2ULL,
		0x2EA4022C82C95C40ULL,
		0xBB5CD8505ECFF83FULL,
		0x7D9F0116F927EBE1ULL,
		0x6002DA73C77319E7ULL,
		0xD7F9B86BF226E269ULL,
		0x72E0038174D44F35ULL,
		0xDD05017C0997A34AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B9802C049300650ULL,
		0x2A20022002495C40ULL,
		0xA05CC00046CB3807ULL,
		0x298800066020EBE0ULL,
		0x00009220C55308C3ULL,
		0x1021080952044069ULL,
		0x1020010070C00134ULL,
		0x5904004C00100200ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E7A4B169182520ULL,
		0xDBF1D2AC4E238D5DULL,
		0x222CB6996EF35A03ULL,
		0x5D55BE7AA0D91B56ULL,
		0xEEA75632FC1596A3ULL,
		0x7B027D957C3DA2EBULL,
		0x48613C1AD4A9A4C7ULL,
		0xF92F89614C5BCA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B5DBE4DD7F8A03ULL,
		0xE71C3347E32DBA07ULL,
		0xF0E45BDC8DF38879ULL,
		0x6DF43F731FA674CFULL,
		0x6B76C6BC4BBABD3EULL,
		0x98FF2D19C6020852ULL,
		0xF699C63A50F4A1A2ULL,
		0x5199867742276F71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A580A049180000ULL,
		0xC310120442218805ULL,
		0x202412980CF30801ULL,
		0x4D543E7200801046ULL,
		0x6A26463048109422ULL,
		0x18022D1144000042ULL,
		0x4001041A50A0A082ULL,
		0x5109806140034A30ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED5281F90BB8FB70ULL,
		0xBC5305EBFBE3B935ULL,
		0x0E6AF2B680E637F3ULL,
		0x6416C0AA46757E74ULL,
		0x668E38867556F780ULL,
		0x828323FD20D08FB6ULL,
		0xADB52EAB10E22B90ULL,
		0x2F581DF154560227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFBFE359586BA329ULL,
		0x952F64CBA0C900A7ULL,
		0xF00131CF24CC51AAULL,
		0xFA765847177C5795ULL,
		0xBFD42FCBA1955587ULL,
		0xD5AF6BFFC5B3DAA3ULL,
		0x69300F5D74AFDE18ULL,
		0xE57F7BA8C9E77BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD1281590828A320ULL,
		0x940304CBA0C10025ULL,
		0x0000308600C411A2ULL,
		0x6016400206745614ULL,
		0x2684288221145580ULL,
		0x808323FD00908AA2ULL,
		0x29300E0910A20A10ULL,
		0x255819A040460224ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6153F31938697779ULL,
		0x0B1B9D272F868173ULL,
		0xB58DBAE2F5F640AFULL,
		0xBBA0AEF80695D54EULL,
		0x371028B7DD7DC353ULL,
		0x1A34C93B887C726FULL,
		0x903DE7F9CDD9A1DAULL,
		0xFF545D65C513A61FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A868F03E5FBDB4ULL,
		0x344664ADE7413D36ULL,
		0xB1026F32FD85521BULL,
		0xA81D6370ED4FB02EULL,
		0xAEAE6D1A421A189AULL,
		0xD9666FAC766BA82EULL,
		0x3270CB50F614F6F5ULL,
		0x7513E08FBF715203ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000601038493530ULL,
		0x0002042527000132ULL,
		0xB1002A22F584400BULL,
		0xA80022700405900EULL,
		0x2600281240180012ULL,
		0x182449280068202EULL,
		0x1030C350C410A0D0ULL,
		0x7510400585110203ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7BDCCA3CEF74D2AULL,
		0xB8BAA4285422EE2BULL,
		0xE0131715FAE4D667ULL,
		0x801F5A457313B67BULL,
		0x0898837D334835E8ULL,
		0xDACA3AE280BB5D10ULL,
		0x85A004BE5224606EULL,
		0xFAA603AE0FAB03E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF9E3CA8F4043E3ULL,
		0x0075E0050854A3D3ULL,
		0xEC5E81227BA63D0CULL,
		0xC1BB633AEE921190ULL,
		0x29944F3B5EDC65E2ULL,
		0x28D938C7C668BC39ULL,
		0xB439A00D2224C7E5ULL,
		0xED7CF54807F82F7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3B9C0828E404122ULL,
		0x0030A0000000A203ULL,
		0xE01201007AA41404ULL,
		0x801B420062121010ULL,
		0x08900339124825E0ULL,
		0x08C838C280281C10ULL,
		0x8420000C02244064ULL,
		0xE824010807A80364ULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC461CCE5D91B12E3ULL,
		0x3F9C7490E1301A3BULL,
		0xF244621454E31637ULL,
		0x7E6C6F39612FE6DDULL,
		0xE20461205E6DFEEEULL,
		0x7C4C08AF72BF01D2ULL,
		0x1C52498DA125EE18ULL,
		0x5F89D3EB00C4E20AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95DA218859A98272ULL,
		0x75E20AC66A7F761EULL,
		0x16A9007167A69785ULL,
		0x1297CCD7A1F4A8E6ULL,
		0xC9F2B97CDE0ABE8CULL,
		0xD0ECD437934F93D3ULL,
		0x1ECE6EE9C790C0A0ULL,
		0x6975EA06D17D711EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8440008059090262ULL,
		0x358000806030121AULL,
		0x1200001044A21605ULL,
		0x12044C112124A0C4ULL,
		0xC00021205E08BE8CULL,
		0x504C0027120F01D2ULL,
		0x1C4248898100C000ULL,
		0x4901C2020044600AULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84012FCF231E3D74ULL,
		0x9A099F99384C230AULL,
		0x394208F5FC2468B9ULL,
		0x1E792213C537F44FULL,
		0x402B46C493E56B35ULL,
		0xB557357F196F0453ULL,
		0xD2BB44522A2F3ADDULL,
		0x40136A096541EEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B28A67F972B0ADULL,
		0xD5CF7F2E62BD88B1ULL,
		0xEF070BDCC5BEB0CDULL,
		0x0FD55A9537F7A38BULL,
		0x47B4CB3951B5E52BULL,
		0xA12ABB3EC093C9DBULL,
		0x40D42540C3D0720BULL,
		0x91F6A54FF436BED2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80000A4721123024ULL,
		0x90091F08200C0000ULL,
		0x290208D4C4242089ULL,
		0x0E5102110537A00BULL,
		0x4020420011A56121ULL,
		0xA102313E00030053ULL,
		0x4090044002003209ULL,
		0x001220096400AEC0ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06D3938656C9DA3EULL,
		0x57643EFFC7DE50B4ULL,
		0x74ADD921E204260FULL,
		0x8877F7EFC8F6F41AULL,
		0x9E8845F204CA1442ULL,
		0xFA463C8979BF2964ULL,
		0x666A43984EBEE29AULL,
		0xAF9D9F8D97312D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D9ECBA63BC635BULL,
		0x814EE0CA2565E267ULL,
		0xBA3E3A23577D27D9ULL,
		0x4A7C2FE6F4ECEACAULL,
		0x2A12B1C5F0C71354ULL,
		0x4E80BDAFFA85F124ULL,
		0x47D4401F4F087943ULL,
		0x5936A8FE063699A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D180824288421AULL,
		0x014420CA05444024ULL,
		0x302C182142042609ULL,
		0x087427E6C0E4E00AULL,
		0x0A0001C000C21040ULL,
		0x4A003C8978852124ULL,
		0x464040184E086002ULL,
		0x0914888C06300900ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x134A7696D6980CA0ULL,
		0x3B12A9F42DF05A25ULL,
		0x0B3D99FA757B5BEAULL,
		0x10E359DFF56CFA56ULL,
		0x39EF642626D63BDCULL,
		0x94357D8F9BC0C715ULL,
		0xEB3D2A6D334B09ACULL,
		0x2664D0412FDAB4D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4224A45912BA996ULL,
		0x301A4EFC59AEBFC8ULL,
		0x9644BE747990A5C6ULL,
		0x7447195A49559CD7ULL,
		0xCCAAD024471D3AF4ULL,
		0x95EE152B901CBA09ULL,
		0x8CF7E38EA5913928ULL,
		0x4AF9439AC39970F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1002420490080880ULL,
		0x301208F409A01A00ULL,
		0x02049870711001C2ULL,
		0x1043195A41449856ULL,
		0x08AA402406143AD4ULL,
		0x9424150B90008201ULL,
		0x8835220C21010928ULL,
		0x02604000039830D3ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB44688A57D006D8ULL,
		0x8E094EB21C997352ULL,
		0xFC81E969C151D9B0ULL,
		0xDCDA960B58AF6D7AULL,
		0xCFC8F4174886E328ULL,
		0xEB6F59BEAF0B4634ULL,
		0x629168B5CCE94417ULL,
		0x04291671D8862A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34A946F8368F2A66ULL,
		0xE5E691416AFB45CDULL,
		0x59884753529492C9ULL,
		0xA3B7C75D8980C1FFULL,
		0x93E07E4FD9D10A34ULL,
		0x62A46A299214578DULL,
		0xDA008829F4BB7A39ULL,
		0xD1DF291C93E0C894ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3000408816800240ULL,
		0x8400000008994140ULL,
		0x5880414140109080ULL,
		0x809286090880417AULL,
		0x83C0740748800220ULL,
		0x6224482882004604ULL,
		0x42000821C4A94011ULL,
		0x0009001090800800ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x718B96061DB5BBCFULL,
		0x1E3E78038F6C6BFDULL,
		0x45548907A4E215FAULL,
		0x940286C2E62EC1CBULL,
		0x26006755C7F4DC9BULL,
		0x59DE09F5822D27ECULL,
		0x363CECD5BDAAD836ULL,
		0x21F97E82714BA1E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F52609346AA472CULL,
		0xA04BCD509DC0BE1FULL,
		0x4DB37DF0F6E23BB3ULL,
		0x9BFEB59C99C60F01ULL,
		0xE1AA3E814933FEE6ULL,
		0xBE583BB3C9AE8A72ULL,
		0x95309108E239494AULL,
		0x78CB784F8C843B45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2102000204A0030CULL,
		0x000A48008D402A1DULL,
		0x45100900A4E211B2ULL,
		0x9002848080060101ULL,
		0x200026014130DC82ULL,
		0x185809B1802C0260ULL,
		0x14308000A0284802ULL,
		0x20C9780200002141ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x207D3EFA7246D88EULL,
		0x51EE704CE5042107ULL,
		0xFCBB6D61D04A5817ULL,
		0x0AE7716D85105539ULL,
		0x3C28195181C59A9EULL,
		0x489E823A7ACD2824ULL,
		0x7533F5FD1B500D5AULL,
		0xADC43413A3134051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B07D46E9D6B3D40ULL,
		0x8F14E9B696E308F4ULL,
		0xF08CBECF84403501ULL,
		0x0D7E29D168BB7D50ULL,
		0xD085EDC8EAFA17D3ULL,
		0x6B4C25F5E36DF22BULL,
		0xE6688C4E48586CF7ULL,
		0xE06AF32968846E6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0005146A10421800ULL,
		0x0104600484000004ULL,
		0xF0882C4180401001ULL,
		0x0866214100105510ULL,
		0x1000094080C01292ULL,
		0x480C0030624D2020ULL,
		0x6420844C08500C52ULL,
		0xA040300120004040ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AC7F06CCFD2E917ULL,
		0xEC4A726EE2EE4333ULL,
		0x6858BFD9555F3435ULL,
		0x75EE14D49868ADF9ULL,
		0xA864C6D1C31AB6E1ULL,
		0xF662F667857961FBULL,
		0xED66D316DB418E6EULL,
		0x7284C20931AE1B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E310CD57109A16FULL,
		0xA43C2F7296471148ULL,
		0x29C202FA963D2574ULL,
		0x61C62A5DCD16BB3AULL,
		0x2B8850A95CDE9896ULL,
		0xDE551D5A7E9B7B03ULL,
		0x1E367A9A56D40013ULL,
		0xE81F69F3A45D643CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A0100444100A107ULL,
		0xA408226282460100ULL,
		0x284002D8141D2434ULL,
		0x61C600548800A938ULL,
		0x28004081401A9080ULL,
		0xD640144204196103ULL,
		0x0C26521252400002ULL,
		0x60044001200C0038ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9ECA4D5EA737DDEULL,
		0xAB227F5D8B0DC4D3ULL,
		0x4AF7A6C259C27C9BULL,
		0x76C0FE9761A44388ULL,
		0x0F446816A09E7F08ULL,
		0x28E3EB114CC0180FULL,
		0xB893F02BDB336E97ULL,
		0xE5DFB9F6998D4112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51267889CC5F048ULL,
		0xE1022970F60464AFULL,
		0xAFB0D075DD7ACE1AULL,
		0xB32954D28DF72EFAULL,
		0xCF1ACF0127655170ULL,
		0x37C03866BBEE6917ULL,
		0x2B0AF6FCF93D4315ULL,
		0x41EF58CDFEF1882BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8100248088417048ULL,
		0xA102295082044483ULL,
		0x0AB0804059424C1AULL,
		0x3200549201A40288ULL,
		0x0F00480020045100ULL,
		0x20C0280008C00807ULL,
		0x2802F028D9314215ULL,
		0x41CF18C498810002ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E1BAA1346457460ULL,
		0x9B83DE7C350E83B3ULL,
		0x31915D728BB0B6B2ULL,
		0x37B315E2A9A0CBE1ULL,
		0xEA12B000499ADE4FULL,
		0x6B5E3DC37B6FB4F1ULL,
		0xB27DA799075317E5ULL,
		0x98C4EC8F1F536D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B05FAE59B3DE5C7ULL,
		0xA0558C9E2EA7CD84ULL,
		0xA9E2087D47E6F273ULL,
		0xA1893EC42F286318ULL,
		0xAD2562CC48239B0FULL,
		0xC8757E3A67EFE916ULL,
		0xD9EC28B2EAF12790ULL,
		0x8AE1295E726A0F22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A01AA0102056440ULL,
		0x80018C1C24068180ULL,
		0x2180087003A0B232ULL,
		0x218114C029204300ULL,
		0xA800200048029A0FULL,
		0x48543C02636FA010ULL,
		0x906C209002510780ULL,
		0x88C0280E12420D02ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x024FAE9A91D07154ULL,
		0x2D83B1E661B2A31AULL,
		0x323DD96754132F25ULL,
		0x66F45FE335FD98AFULL,
		0x747E3BE2E6AD248EULL,
		0x44F349098B8BB62EULL,
		0xC267AB2A0D66F1BFULL,
		0x49F1C63C778999B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x282705180671B925ULL,
		0x9D80A24F594F15D3ULL,
		0xB2C8C275AFFFB8E0ULL,
		0xBA2623C58E2BF678ULL,
		0x9130021D30045BB9ULL,
		0x7AC219B3A4A1239AULL,
		0xE20C2A6691CC7595ULL,
		0x3EE24C8DE36D9F5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0007041800503104ULL,
		0x0D80A04641020112ULL,
		0x3208C06504132820ULL,
		0x222403C104299028ULL,
		0x1030020020040088ULL,
		0x40C209018081220AULL,
		0xC2042A2201447195ULL,
		0x08E0440C63099918ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A0813CD3D2E815BULL,
		0x48E8880B8B868D5EULL,
		0x7A57467AE9B8CE78ULL,
		0xF52A42FF3A3EF3A8ULL,
		0x4D2C1BB26641EF24ULL,
		0xD0F83C77A66B65FFULL,
		0xB61742C3FE5519DCULL,
		0xBEE5C57E430EED2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0872F1303D151058ULL,
		0x8653592217EBBF6CULL,
		0xBFD232982425359FULL,
		0xC82BE32057DE572FULL,
		0x98B693BD05FA2A5CULL,
		0xCCE6BC375AFCDC71ULL,
		0xB60287BEADCFBA04ULL,
		0x468E8CB978C473ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080011003D040058ULL,
		0x0040080203828D4CULL,
		0x3A52021820200418ULL,
		0xC02A4220121E5328ULL,
		0x082413B004402A04ULL,
		0xC0E03C3702684471ULL,
		0xB6020282AC451804ULL,
		0x0684843840046128ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B996DAD8666D2A7ULL,
		0xA30EC204CF83A36BULL,
		0x5DEB1D6F68E23A5FULL,
		0x2D460B6706E00BAFULL,
		0x5830C635DF01088AULL,
		0xC18BEF28096D3016ULL,
		0x56E8262E49A48EB4ULL,
		0x7F547341B80AD18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3E975D54924C20FULL,
		0x6C1AE5EFA8F5915DULL,
		0xE7F9555FC5FC6F5BULL,
		0xE408F471A2156496ULL,
		0xA91ACFF18505FDDBULL,
		0xADF20AEBC46A9E32ULL,
		0x34BA72088CBB0AF8ULL,
		0x9DEA13FC2BB2C459ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x538965850024C207ULL,
		0x200AC00488818149ULL,
		0x45E9154F40E02A5BULL,
		0x2400006102000086ULL,
		0x0810C6318501088AULL,
		0x81820A2800681012ULL,
		0x14A8220808A00AB0ULL,
		0x1D4013402802C009ULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB1FB06B89C1024ULL,
		0x5223A4CE38C21902ULL,
		0xE0DBA32305AC075AULL,
		0xD93DF29826BE5E02ULL,
		0xAB806A757C58206CULL,
		0x828238F8A55B3B01ULL,
		0x5BB56B5993A0ADD2ULL,
		0x4B9B88D461B8037FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0EBA7E0FA57481FULL,
		0xB868AAB1A53EC3C0ULL,
		0x180F0BB80D0F6D8DULL,
		0xF456DC412DA39017ULL,
		0xC4ADFBE2F7B48F69ULL,
		0x6BAC25BA4B35EE6DULL,
		0x187BDAE0C28119D2ULL,
		0xDF5BEE0F1D876D71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20A1A300B8140004ULL,
		0x1020A08020020100ULL,
		0x000B0320050C0508ULL,
		0xD014D00024A21002ULL,
		0x80806A6074100068ULL,
		0x028020B801112A01ULL,
		0x18314A40828009D2ULL,
		0x4B1B880401800171ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1990EE780A78EAE1ULL,
		0x9EB10F6C37B765CDULL,
		0xD9EF2A25E25FB574ULL,
		0xC0F4AC4BB363BF53ULL,
		0x142727794AC5998DULL,
		0xEF2EB2FF1D2AE297ULL,
		0xCC2733183924CE69ULL,
		0x283C34A9A204A815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x164DAB1EEEABC2E7ULL,
		0x7EF4DE877F2A3B9EULL,
		0xDB8C988E894E751CULL,
		0xBEC269D868FF2C5CULL,
		0x9A58FD0D905C8A65ULL,
		0xD14835F0075042B3ULL,
		0xF87FE7E8E91456F9ULL,
		0xFAA0D54099E8FABEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000AA180A28C2E1ULL,
		0x1EB00E043722218CULL,
		0xD98C0804804E3514ULL,
		0x80C0284820632C50ULL,
		0x1000250900448805ULL,
		0xC10830F005004293ULL,
		0xC827230829044669ULL,
		0x282014008000A814ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AC80829A939010CULL,
		0x040005CD35F1CE43ULL,
		0x2D89BAEFD38C1587ULL,
		0xD8323173D97BD0B3ULL,
		0xD03D389E18853AEEULL,
		0x637BB3B8F8335EA1ULL,
		0x9C6D403ABEB5F2FFULL,
		0x7663D6B9B2E3AE86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x198C6E71DBD7EFB7ULL,
		0xE0DED7187084AFC1ULL,
		0x2EF7466A60FDC033ULL,
		0x5D2B535D8E445ABFULL,
		0x81FA8A0BCD8AEFBFULL,
		0xF638F491C2B2D917ULL,
		0xFF38DD35766876DCULL,
		0x642DEFFF25BFAFECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0888082189110104ULL,
		0x0000050830808E41ULL,
		0x2C81026A408C0003ULL,
		0x58221151884050B3ULL,
		0x8038080A08802AAEULL,
		0x6238B090C0325801ULL,
		0x9C284030362072DCULL,
		0x6421C6B920A3AE84ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FE98942F6D5B866ULL,
		0x8398249CA05345E2ULL,
		0xC30CCE207BCF289DULL,
		0x1BFBB1484BA72CBBULL,
		0xBB5FA7373217DEAAULL,
		0xF73A3BA14B07C6DCULL,
		0xB9DA47A0FF592D9CULL,
		0x6CC8144CBF3130D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1BC11D38C57FC05ULL,
		0xF1BE8402C60A7383ULL,
		0x7AA7373019161ABEULL,
		0x6FD29854491A4693ULL,
		0x9B186D55C9ABBCF4ULL,
		0xD4771687F5CA0A73ULL,
		0x849743983C1960A9ULL,
		0xFE3094F94D807D94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61A801428455B804ULL,
		0x8198040080024182ULL,
		0x420406201906089CULL,
		0x0BD2904049020493ULL,
		0x9B18251500039CA0ULL,
		0xD432128141020250ULL,
		0x809243803C192088ULL,
		0x6C0014480D003090ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB21B87AC1693E01ULL,
		0x9080590CD949283DULL,
		0x58C341AAB8B3824BULL,
		0xE0B3C47C865C9CFCULL,
		0xCD60D7E687052CFFULL,
		0xD18171558E84EFB5ULL,
		0x94CF40515E658AE5ULL,
		0x8C87C0FF9326150EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329CE9342CF2C120ULL,
		0xF6FB1A27096194E1ULL,
		0x125DF5A287E9A56BULL,
		0x37EFB0AB467CD0B8ULL,
		0x39963AE677834817ULL,
		0xD5F18292577312CBULL,
		0x154365C6CCF45C5EULL,
		0x911B847198443C4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2200A83000600000ULL,
		0x9080180409410021ULL,
		0x104141A280A1804BULL,
		0x20A38028065C90B8ULL,
		0x090012E607010817ULL,
		0xD181001006000281ULL,
		0x144340404C640844ULL,
		0x800380719004140AULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AB40AD9080C64CBULL,
		0x0C2DB26FE7F9F65CULL,
		0x3C01CD08EA5556E3ULL,
		0xF2AD1CFAA6A96AE0ULL,
		0x2D964198EEBC4C58ULL,
		0x1FEA1DBFA32626C6ULL,
		0x49ACB521ED15215AULL,
		0xC1D1ACB672346FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F5DD8513F8C81EULL,
		0xEDBFB0D45FCC6CFEULL,
		0x0832B54C53E5141DULL,
		0x85C74DFAEC193B58ULL,
		0x55CB71FC2875F655ULL,
		0xAD9923F77CC8DC30ULL,
		0xDAE07DF1168C0211ULL,
		0x622B9524DF66C794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50B408810008400AULL,
		0x0C2DB04447C8645CULL,
		0x0800850842451401ULL,
		0x80850CFAA4092A40ULL,
		0x0582419828344450ULL,
		0x0D8801B720000400ULL,
		0x48A0352104040010ULL,
		0x4001842452244780ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9BF7AD16EC91216ULL,
		0x4814A989B21F90D8ULL,
		0x8BD27F2C8F9EFDBFULL,
		0x44813D2DF946283CULL,
		0x049E0521737461E7ULL,
		0x8FB7F758C79961A1ULL,
		0x01FB25B2A15E5E2FULL,
		0xBD8828AD09C54AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6502BAF42C7809BULL,
		0x568C25A250DD38D8ULL,
		0x12AD65005CF07011ULL,
		0x72721E0B884CCC2BULL,
		0xB6DD925A8856FF6DULL,
		0xB024F2B2BA138529ULL,
		0xCC6CC1EEB585EBDAULL,
		0x634BFF086B892C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90102A8142C10012ULL,
		0x40042180101D10D8ULL,
		0x028065000C907011ULL,
		0x40001C0988440828ULL,
		0x049C000000546165ULL,
		0x8024F21082110121ULL,
		0x006801A2A1044A0AULL,
		0x2108280809810838ULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC43749B8B1A26CB1ULL,
		0x7A7BABE200EE52E2ULL,
		0x90E3A2CE498930A5ULL,
		0x72D5CACAF909A3F4ULL,
		0x2C2E126F318892F7ULL,
		0x69A10CB0C1ED50E3ULL,
		0x26E5C90EC53911F6ULL,
		0x3FC3D0D3B25CF822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A17B211FF41018AULL,
		0x9DF6C366ACE10947ULL,
		0xF655751B847C619EULL,
		0x07416CB1A2EAAADEULL,
		0x0D03CC724B6450CCULL,
		0x256636763B3F6B0EULL,
		0x83914B9C92C2BE4EULL,
		0xF3BE4EA55526B65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00170010B1000080ULL,
		0x1872836200E00042ULL,
		0x9041200A00082084ULL,
		0x02414880A008A2D4ULL,
		0x0C020062010010C4ULL,
		0x21200430012D4002ULL,
		0x0281490C80001046ULL,
		0x338240811004B002ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AB4AD327FC56683ULL,
		0x67E80C9D42AC8C55ULL,
		0x38A3ACB35819961DULL,
		0x3DF42BBD3141D020ULL,
		0x4F6AF427B23268B8ULL,
		0xCCC751FBF8CCB6FFULL,
		0x59FCE78D0758445CULL,
		0x5ED4841AA8AE7A4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE223F87D273D190EULL,
		0x0CDAD4BC7DC57DC4ULL,
		0x98B848A9BE6B6392ULL,
		0x0938D6F001035703ULL,
		0xC26F28F400DC8B72ULL,
		0xB03142ED6BFA8CD3ULL,
		0x5CFBF11FA8BFDC35ULL,
		0xB4E5115F84E6E22EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2220A83027050002ULL,
		0x04C8049C40840C44ULL,
		0x18A008A118090210ULL,
		0x093002B001015000ULL,
		0x426A202400100830ULL,
		0x800140E968C884D3ULL,
		0x58F8E10D00184414ULL,
		0x14C4001A80A6620EULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66257D523A0FDD5BULL,
		0x61517EDC900C7EAEULL,
		0x080C23CDBBF9C27AULL,
		0xE7EB2325EAB789D5ULL,
		0xFABDAB895F328BA1ULL,
		0x4AACCE2D77096C7AULL,
		0xBEDA2BCE4BBF4E0BULL,
		0x062D5493EFB91658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8917FC97EBC6A0BBULL,
		0x77CF4AEB8746F568ULL,
		0x6813AB223C2DC7C3ULL,
		0x2306F1B911541C49ULL,
		0x0B2A871F89103AB4ULL,
		0x557DC3F4515BDC80ULL,
		0x507B1E3E998BF98FULL,
		0x8262F830A29B2C1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00057C122A06801BULL,
		0x61414AC880047428ULL,
		0x080023003829C242ULL,
		0x2302212100140841ULL,
		0x0A28830909100AA0ULL,
		0x402CC22451094C00ULL,
		0x105A0A0E098B480BULL,
		0x02205010A2990418ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B357D1623AAA4F7ULL,
		0xF7478D530D533D14ULL,
		0xFA3C61F14CC0953AULL,
		0xB217E3B2A5639FC7ULL,
		0xB8558B899AA8E84EULL,
		0xAFD660FC3C1761D2ULL,
		0x0458840A926F94ABULL,
		0x1B2F815E0EC83106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1689075EE3C45B4ULL,
		0xA563AEF3EA451A3EULL,
		0x58D39DDDEE431801ULL,
		0x396ADF2CA06EADA8ULL,
		0x3D7890F05BCDD091ULL,
		0x80D67C7DFBE475ABULL,
		0x6F94EF9D88C320A2ULL,
		0x54F7B830C5A030C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01201014222804B4ULL,
		0xA5438C5308411814ULL,
		0x581001D14C401000ULL,
		0x3002C320A0628D80ULL,
		0x385080801A88C000ULL,
		0x80D6607C38046182ULL,
		0x04108408804300A2ULL,
		0x1027801004803006ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FA4732DF7A58E3DULL,
		0x220A5CEF116DF732ULL,
		0x32DC26D7097E117CULL,
		0x0751239369DDFC83ULL,
		0x354EC9BC024C7792ULL,
		0xF30A22FEA056184CULL,
		0x0547A27346F5775EULL,
		0x8CE548943C236901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0C328641B366AD4ULL,
		0x87E6104DEA338794ULL,
		0x90530BC40C58BE2CULL,
		0x4268BB38B6BDFE1EULL,
		0x54ACFB3638FD0869ULL,
		0x9AEB5DE3C16D3703ULL,
		0x0650941BD6FC2511ULL,
		0x15DFB59ED428049AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4080202413240A14ULL,
		0x0202104D00218710ULL,
		0x105002C40858102CULL,
		0x02402310209DFC02ULL,
		0x140CC934004C0000ULL,
		0x920A00E280441000ULL,
		0x0440801346F42510ULL,
		0x04C5009414200000ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD048CE7719BEF7D3ULL,
		0xE2AD7DA65D51C00BULL,
		0x1F9480FFF6C2B38AULL,
		0x840E93A07A2A9E9FULL,
		0x0DC83874553CCCF2ULL,
		0x45167A193F980CE5ULL,
		0x93F8EA8A65271896ULL,
		0xD6D36864E402AD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7462A6D7E424C938ULL,
		0x0EC10D5B26EB8AA3ULL,
		0xF4DE940D0DFEA669ULL,
		0x9244E0C25D69500BULL,
		0xA48562BD23E5551DULL,
		0xFF31728A19A2D2E4ULL,
		0x1869A15B1C5B4EC9ULL,
		0x8AFFAC8047394E6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504086570024C110ULL,
		0x02810D0204418003ULL,
		0x1494800D04C2A208ULL,
		0x800480805828100BULL,
		0x0480203401244410ULL,
		0x45107208198000E4ULL,
		0x1068A00A04030880ULL,
		0x82D3280044000C2AULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA49C1ECC5FB2AC32ULL,
		0xBCFD08D3FDCFEB24ULL,
		0x35975F05C37FD15EULL,
		0x74E779DEBBC774F3ULL,
		0xE8612044741D2122ULL,
		0x80627A12CB6448C7ULL,
		0x9F04A82AD1BF1F83ULL,
		0xDF6D3412E2FB301BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB87FEA4E707FC23ULL,
		0x2337859FE53A473FULL,
		0x35A33CB61FA2D7BDULL,
		0xC71BE9714D906E72ULL,
		0xE45EAB742902F8C6ULL,
		0x153EFCA1F59407CDULL,
		0x8508C5E67F123087ULL,
		0xA33A59A3CC64AAF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0841E844702AC22ULL,
		0x20350093E50A4324ULL,
		0x35831C040322D11CULL,
		0x4403695009806472ULL,
		0xE040204420002002ULL,
		0x00227800C10400C5ULL,
		0x8500802251121083ULL,
		0x83281002C0602012ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A997B594F6A18C3ULL,
		0x20D0D450C1D73C98ULL,
		0x2B9221C2AEB3A295ULL,
		0x43643D8EA8865A02ULL,
		0x8EF505191D659C4AULL,
		0xBB9BD320589C44FFULL,
		0xC81649815FF255D3ULL,
		0xA24F2E43CA9425CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE61804C9D7495CULL,
		0x415203BB0AE7B210ULL,
		0x0A9E80210991590FULL,
		0xDC65E08688FFDE77ULL,
		0x8A421DE2C5841DCCULL,
		0x3E3BD576FC98CA93ULL,
		0x7A6A61EAC7A1301DULL,
		0x768C10A12A9E20C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A80180049420840ULL,
		0x0050001000C73010ULL,
		0x0A92000008910005ULL,
		0x4064208688865A02ULL,
		0x8A40050005041C48ULL,
		0x3A1BD12058984093ULL,
		0x4802418047A01011ULL,
		0x220C00010A9420C0ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1E82B33942E815CULL,
		0x34CB59E261B32EBEULL,
		0xE4B462D06FED50A1ULL,
		0xDA9112AB1AF57E9FULL,
		0x141F8381E0622069ULL,
		0x876D5A8BCA616913ULL,
		0x9566E6D7F8877F0AULL,
		0xABD9548D44402F48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B7013115E9A04BULL,
		0xEB80758EDB9A7C07ULL,
		0x040553304ABE3F51ULL,
		0x8E0421DD2B578591ULL,
		0x615E92813C2205CDULL,
		0xD5E11965FB8D699EULL,
		0xD90AF4CFA932B620ULL,
		0x13195358D38BC795ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A0013114288048ULL,
		0x2080518241922C06ULL,
		0x040442104AAC1001ULL,
		0x8A0000890A550491ULL,
		0x001E828120220049ULL,
		0x85611801CA016912ULL,
		0x9102E4C7A8023600ULL,
		0x0319500840000700ULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F8BC3EAFFDDF98DULL,
		0x253CCBD292101F2EULL,
		0x46F64BF92A4D5E0AULL,
		0xBE1B66419973374EULL,
		0xF14EBB5444320009ULL,
		0xDE496C697F0D5F86ULL,
		0x2F801F841F698DD8ULL,
		0x19D0ED49DE38C232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4210E8409ED801C3ULL,
		0x4C553C0F4F3FBA14ULL,
		0x32A466F8409E8948ULL,
		0xED6014423077B8E3ULL,
		0xF3970AD66A1670D4ULL,
		0xDE626F9BF86F9370ULL,
		0x23FB16854CDF17FBULL,
		0x50B51BDC4522E88AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4200C0409ED80181ULL,
		0x0414080202101A04ULL,
		0x02A442F8000C0808ULL,
		0xAC00044010733042ULL,
		0xF1060A5440120000ULL,
		0xDE406C09780D1300ULL,
		0x238016840C4905D8ULL,
		0x109009484420C002ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2984EF1B66FEF057ULL,
		0x82A820F8514C32E5ULL,
		0x58156B75C5023838ULL,
		0x4C7107837D402D3DULL,
		0xA24537D7CE2F9ED4ULL,
		0x292795DE7BAEB29DULL,
		0x587F3F82D6728032ULL,
		0x32C92AC3542212DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8853DFF6969A0C94ULL,
		0x809D219794FA16BAULL,
		0x8DB9149201B00DF4ULL,
		0x436EE510C8D6124DULL,
		0x4447DE99DFF47161ULL,
		0x74FF7839F19B0C3DULL,
		0xC7668976E83F96CBULL,
		0xF75ED58BCFFF8B14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0800CF12069A0014ULL,
		0x80882090104812A0ULL,
		0x0811001001000830ULL,
		0x406005004840000DULL,
		0x00451691CE241040ULL,
		0x20271018718A001DULL,
		0x40660902C0328002ULL,
		0x3248008344220210ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB1D02EBBC8B3E85ULL,
		0xBDC8276D32AEE534ULL,
		0x262EEF8E4CCE2C41ULL,
		0xF64973A0B1EFD803ULL,
		0xA1774F07BD84EE80ULL,
		0x6D56D92F90C10070ULL,
		0xAB037937183F4F36ULL,
		0x51A493DCCD3CF237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2AAD86DCC95975ULL,
		0x7D965A8FE526E30EULL,
		0x408B58B8553E7C18ULL,
		0xFB0D99957E1FF6E1ULL,
		0x6212635355F8ABBBULL,
		0xBFB7A7DCE0C0F9FEULL,
		0x0F6DEE4E55E587AEULL,
		0x691F734A85F19C26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080800829C891805ULL,
		0x3D80020D2026E104ULL,
		0x000A4888440E2C00ULL,
		0xF2091180300FD001ULL,
		0x201243031580AA80ULL,
		0x2D16810C80C00070ULL,
		0x0B01680610250726ULL,
		0x4104134885309026ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB070983CA570A4CDULL,
		0x3D53D8FA9FD72561ULL,
		0x5A154313BA866AD4ULL,
		0x750659B66BC74585ULL,
		0x60BD87AEE1CC8072ULL,
		0x229E307102853240ULL,
		0x9549990252D18CE8ULL,
		0xF1330252C31A6059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30300A6737FFD437ULL,
		0xDB793CFE39239A3BULL,
		0x5305F54ECD27F505ULL,
		0x8394C6CE2F02F280ULL,
		0x5119EFFCA32BA4FAULL,
		0x70C49C8165141073ULL,
		0x4E60AEDC63788098ULL,
		0xFB98ECFC618D41F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3030082425708405ULL,
		0x195118FA19030021ULL,
		0x5205410288066004ULL,
		0x010440862B024080ULL,
		0x401987ACA1088072ULL,
		0x2084100100041040ULL,
		0x0440880042508088ULL,
		0xF110005041084051ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4E2D756BC5DE672ULL,
		0xDADE0B8EAD1C3AA4ULL,
		0x81E1445065E231C7ULL,
		0x59235AC21BFCD1F0ULL,
		0x965FA9C5A64C5B9EULL,
		0x4E8432F4632F17C4ULL,
		0xA5A63736C2042C6BULL,
		0x2873BD46D559D7F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2576B5B36C0777ULL,
		0x3EE2546B4507B6E8ULL,
		0x21DC2A4A4CB748C7ULL,
		0x4BEF4A305922C8A1ULL,
		0xA298721EBA3C9269ULL,
		0x26A8933CECB43F49ULL,
		0x4D1C99ECBF4ECCB1ULL,
		0xB8EC8C9E1F5BC8EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04205614B04C0672ULL,
		0x1AC2000A050432A0ULL,
		0x01C0004044A200C7ULL,
		0x49234A001920C0A0ULL,
		0x82182004A20C1208ULL,
		0x0680123460241740ULL,
		0x0504112482040C21ULL,
		0x28608C061559C0E0ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB37CB21A412D22E9ULL,
		0xE70468BF82ABA893ULL,
		0xA6788682B66C2E12ULL,
		0x74FBDFBE0EB631B4ULL,
		0x8167080994E82711ULL,
		0x20C8887F0BB847E8ULL,
		0xB7F4F50E8A15B51AULL,
		0xD6B367EB64C9E900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x710187746B1C68CEULL,
		0x851813DDBD663AAFULL,
		0x495C9D81412BAA71ULL,
		0xA82F2B8E3E09B75BULL,
		0xFB5F7B890C31D6CBULL,
		0x183745C01C3B5CA2ULL,
		0x8E9BCFC56D74FFFFULL,
		0xC4B08CF8DC3FB56EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31008210410C20C8ULL,
		0x8500009D80222883ULL,
		0x0058848000282A10ULL,
		0x202B0B8E0E003110ULL,
		0x8147080904200601ULL,
		0x00000040083844A0ULL,
		0x8690C5040814B51AULL,
		0xC4B004E84409A100ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9953F88B946DBFABULL,
		0x656350095197D279ULL,
		0x0FC24035886CC279ULL,
		0x3D28EA77340C0B51ULL,
		0xADEDBE0D0969E494ULL,
		0xF80D4251D1EA113AULL,
		0xC77EB9D5A8D7C10EULL,
		0x123606C60AE96AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B1926AC638E3E31ULL,
		0x8458D3D9A5514992ULL,
		0x8418350731FC959BULL,
		0x3DCB37128EA8DA9FULL,
		0xA0E6BD7A8BAF1963ULL,
		0x60515E3D42D7FD57ULL,
		0x010ABDF5B2CB3246ULL,
		0xCFAF040F99CA5050ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19112088000C3E21ULL,
		0x0440500901114010ULL,
		0x04000005006C8019ULL,
		0x3D08221204080A11ULL,
		0xA0E4BC0809290000ULL,
		0x6001421140C21112ULL,
		0x010AB9D5A0C30006ULL,
		0x0226040608C84050ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C993058DAE38FEBULL,
		0x12270507687528F5ULL,
		0x38200A88C7E1E835ULL,
		0x9A4790C77445F65CULL,
		0xDF065D131093EA20ULL,
		0xCCDA096D7EDCA33DULL,
		0x1CE24D07FFB804F7ULL,
		0x5D14FBE3846E521AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5650839630D320C0ULL,
		0x457AD8D897146C27ULL,
		0xC5FC6B981B9D316EULL,
		0x1CC48008932534B2ULL,
		0x1F9D055A0D5136DAULL,
		0xBA03D76F4F322645ULL,
		0x061DE5CF66B710E6ULL,
		0x181162C640731939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5410001010C300C0ULL,
		0x0022000000142825ULL,
		0x00200A8803812024ULL,
		0x1844800010053410ULL,
		0x1F04051200112200ULL,
		0x8802016D4E102205ULL,
		0x0400450766B000E6ULL,
		0x181062C200621018ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C09F49557E13D8AULL,
		0xDF91CD4D38FB030AULL,
		0x531B3B23098F72C3ULL,
		0xD43ECB4C2BF18006ULL,
		0x2024DC2F5F36703CULL,
		0xF4800A4743D0A61CULL,
		0x904D64C1F209B60FULL,
		0xEECB583195C89277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA80377CB45B5FE83ULL,
		0x63E79A70D3F6933EULL,
		0x78F6DC9C836B3C3CULL,
		0x979B4E45C2484003ULL,
		0xDC9E31982C5AD19DULL,
		0x2C21E55B6F970705ULL,
		0x0B1FB70786F1ED11ULL,
		0x4256376865DA57D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2801748145A13C82ULL,
		0x4381884010F2030AULL,
		0x50121800010B3000ULL,
		0x941A4A4402400002ULL,
		0x000410080C12501CULL,
		0x2400004343900604ULL,
		0x000D24018201A401ULL,
		0x4242102005C81250ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x338D3D870A8DB719ULL,
		0x9A488E4788D0963CULL,
		0xC9EF4E4BD9A411E5ULL,
		0x9FC6F6A7A2D9962CULL,
		0x576415E9932A5108ULL,
		0x3F2174390F3418BEULL,
		0x3DDB62509E9AC051ULL,
		0xF0F74D9F2C98660BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C41E664433C924ULL,
		0xBE27EFABCEB588DEULL,
		0x0514E9744BFA33D7ULL,
		0x47D20ABE53C5E65DULL,
		0xFB059B0D850D6A5AULL,
		0xFB547265BF4B6F9EULL,
		0x439790068156B864ULL,
		0xDEF1B0B79A12FC92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13841C0600018100ULL,
		0x9A008E038890801CULL,
		0x0104484049A011C5ULL,
		0x07C202A602C1860CULL,
		0x5304110981084008ULL,
		0x3B0070210F00089EULL,
		0x0193000080128040ULL,
		0xD0F1009708106402ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8F408D00111C20CULL,
		0xA401FE4735D68971ULL,
		0x50C76DB951565860ULL,
		0xD513438D7C101968ULL,
		0x72DA0A1DA670FABCULL,
		0x3F5A584A50DDE614ULL,
		0xD2AA6CCF290924B0ULL,
		0xC5BC9D1FA6FF9604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA74E91294372C8DFULL,
		0x855A783D433C7C26ULL,
		0x34F83A16F09CC4B7ULL,
		0x78734713287ED6C0ULL,
		0x53D079F8D10E5537ULL,
		0x601CFD22D0E7B837ULL,
		0x17B8BE8BADA1E800ULL,
		0x0C9610CE7450CFBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA04400000110C00CULL,
		0x8400780501140820ULL,
		0x10C0281050144020ULL,
		0x5013430128101040ULL,
		0x52D0081880005034ULL,
		0x2018580250C5A014ULL,
		0x12A82C8B29012000ULL,
		0x0494100E24508604ULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6A8CCC30FFC45F1ULL,
		0x13C438DDFB87BA36ULL,
		0x9A57BA0D703CB2EFULL,
		0x475D3D2240E336B8ULL,
		0xE1D30DDB4809087AULL,
		0xDF6DE0604CD4FCA1ULL,
		0x9CD6C9389D1E97E0ULL,
		0x1BB8FA3D67831110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D508A0D0AB10AFCULL,
		0x248B130AE1DEFC5EULL,
		0xD6996037DAB882DFULL,
		0x013B74BEA52850F9ULL,
		0x10C07AF68B6BFB10ULL,
		0x8EF8DD1DBD64F677ULL,
		0xA7721C8AFB2A600BULL,
		0x75F0663E971C6A0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x640088010AB000F0ULL,
		0x00801008E186B816ULL,
		0x92112005503882CFULL,
		0x01193422002010B8ULL,
		0x00C008D208090810ULL,
		0x8E68C0000C44F421ULL,
		0x84520808990A0000ULL,
		0x11B0623C07000000ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0213A6EAB0985BB7ULL,
		0x9882B2868F418A30ULL,
		0x4275968C0ACC7FBCULL,
		0xF2A6DE8B184AC5FAULL,
		0x2CFA5B71A60BE620ULL,
		0x9E43DA365146ACA8ULL,
		0x6E265AC4E7BACAEEULL,
		0x4301CFFA6AF91D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556B1437869A5FF8ULL,
		0x177475DF7F33DECFULL,
		0xAA99BAEC3DE12062ULL,
		0x6609D4CF7C0AB536ULL,
		0x523EADC3D363381DULL,
		0x23454A6409324C0AULL,
		0xD49895D18521AF63ULL,
		0x077DB8D86D3DB60EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0003042280985BB0ULL,
		0x100030860F018A00ULL,
		0x0211928C08C02020ULL,
		0x6200D48B180A8532ULL,
		0x003A094182032000ULL,
		0x02414A2401020C08ULL,
		0x440010C085208A62ULL,
		0x030188D868391400ULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF79F0CD3C6DE063DULL,
		0xC5717F88A75CAEC6ULL,
		0x8C32EC1E81B36FA0ULL,
		0x93D2F4EEBDC993D6ULL,
		0xFFF93D0E36DA59D9ULL,
		0x51A091593B59DD37ULL,
		0xA9C474A5545A0D70ULL,
		0xB5B5B5185721F887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BC2E1B33F0DB1ADULL,
		0x2E11BB9A624DE219ULL,
		0xC4B25A2C25C78E6DULL,
		0xF1ABFBFCEDBC43FBULL,
		0xE8C3B4E7B22F8F44ULL,
		0x25AB33B3F53595A0ULL,
		0x0D86DAD92D784CDAULL,
		0xDC933A0D184BC6B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13820093060C002DULL,
		0x04113B88224CA200ULL,
		0x8432480C01830E20ULL,
		0x9182F0ECAD8803D2ULL,
		0xE8C13406320A0940ULL,
		0x01A0111131119520ULL,
		0x0984508104580C50ULL,
		0x949130081001C081ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C162DF9755A007FULL,
		0x3DF1B6EE044968AAULL,
		0xE519D0FE9A7A9C54ULL,
		0x19E0F14DD8F8D7C2ULL,
		0xA3E1B29CBE58D808ULL,
		0xD6067E4CD5B6BD1FULL,
		0x55EA15EEFAF83250ULL,
		0x0BE04042A18D70B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF8C94B6F135499ULL,
		0x87B46C48E90F10DAULL,
		0xB0FFABA79B34BDFFULL,
		0x37BB61A7168B6CC7ULL,
		0x579A29F1FD1DCB5EULL,
		0xC3CC7B85DB5966B8ULL,
		0xF2344F091C4149F5ULL,
		0xF0A2272F074204A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C10094965120019ULL,
		0x05B024480009008AULL,
		0xA01980A69A309C54ULL,
		0x11A06105108844C2ULL,
		0x03802090BC18C808ULL,
		0xC2047A04D1102418ULL,
		0x5020050818400050ULL,
		0x00A00002010000A1ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x675B5F36F7FB429CULL,
		0xEDA30107F0572D0DULL,
		0xC2B99802E909E774ULL,
		0xF2230FCAED6829EBULL,
		0x0DD48B6A246A74B1ULL,
		0x72395AA84552F3B2ULL,
		0xED6F24327AD214DCULL,
		0x6CCC512986700386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x960D0CE981D5F19CULL,
		0xAA328EFFD70340CCULL,
		0x90C133F0C1A56AAFULL,
		0xB67DC5AEFA20ED90ULL,
		0xC54BF5CBC351AE76ULL,
		0x642C16AF7818C042ULL,
		0xA4F586495A556A10ULL,
		0x155848EA0471E0EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06090C2081D1409CULL,
		0xA8220007D003000CULL,
		0x80811000C1016224ULL,
		0xB221058AE8202980ULL,
		0x0540814A00402430ULL,
		0x602812A84010C002ULL,
		0xA46504005A500010ULL,
		0x0448402804700086ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x471BFAA453E5AD1EULL,
		0x4F0064384F5CAB9FULL,
		0x4A68717AF20415F8ULL,
		0x8AE2078FD80EC83FULL,
		0xD71615507C82A3DEULL,
		0xE1F8BC93E392CBD8ULL,
		0x4F82CF43ED609888ULL,
		0x4594DEFDD33E70A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9285A299FD086CULL,
		0xE08385C1CEB8A8FAULL,
		0x958C3391149F9E80ULL,
		0x7BE78882ED3A8596ULL,
		0x7F28D5E9E9234A57ULL,
		0x9C6180F7C1390681ULL,
		0x0F9DCEB9315A63E6ULL,
		0xA382FFE9C0557848ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x451280A011E5080CULL,
		0x400004004E18A89AULL,
		0x0008311010041480ULL,
		0x0AE20082C80A8016ULL,
		0x5700154068020256ULL,
		0x80608093C1100280ULL,
		0x0F80CE0121400080ULL,
		0x0180DEE9C0147008ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF909E72C5D6A9392ULL,
		0x28F24057DF13F7AFULL,
		0xD4D61F733947049AULL,
		0xF581FCDFB8C4CDA4ULL,
		0x1BE035C0F910363DULL,
		0x7823AA49B8475DAFULL,
		0x9FA4C0FDC2C0A800ULL,
		0xC4B5AB5A67D9DAD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBF33E2A3064ED2ULL,
		0x709D6CF898E7FD7BULL,
		0x3420A479A7D31854ULL,
		0x74C799A1E820D541ULL,
		0xF48B29D8B8B3A356ULL,
		0x3D3E66EC4475C771ULL,
		0x276A23E85D702692ULL,
		0x9E5FE462B88F7C6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4909232001020292ULL,
		0x209040509803F52BULL,
		0x1400047121430010ULL,
		0x74819881A800C500ULL,
		0x108021C0B8102214ULL,
		0x3822224800454521ULL,
		0x072000E840402000ULL,
		0x8415A04220895844ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC33CE73A36F93F0CULL,
		0x737E8FA4FF49A947ULL,
		0xFE425563CEA1734BULL,
		0xB74A496DF73C7AA5ULL,
		0x16BA14B468B8C58FULL,
		0x53F4D33F10CEF9BAULL,
		0x27CF3F9D79784849ULL,
		0xEC6B391F7CF65BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD395D1ED532A2A5ULL,
		0xD019CD7B5B797465ULL,
		0x60FE68874EAA2704ULL,
		0xCF8062A07E0D6325ULL,
		0x7662892EF1D05E6FULL,
		0xBB77EA0BA49BB47EULL,
		0x4F4AC1D06AB2642DULL,
		0x0FE2E3E165C5B166ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8138451A14302204ULL,
		0x50188D205B492045ULL,
		0x604240034EA02300ULL,
		0x87004020760C6225ULL,
		0x162200246090440FULL,
		0x1374C20B008AB03AULL,
		0x074A019068304009ULL,
		0x0C62210164C41146ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DFCA4CE2239381FULL,
		0xA238346000F4D001ULL,
		0xE64106D2A982DC1FULL,
		0xB3E9909ED585B5E9ULL,
		0x2316C89AC0921397ULL,
		0xC0A67DF438D68A10ULL,
		0x36F1E47707E631B0ULL,
		0x68B7C3D98A3DC42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B83544B7BCE64F3ULL,
		0x7F1F1ADCD5828E54ULL,
		0x39D1D637BC83126FULL,
		0xC3FEA36E1D1D572FULL,
		0xA61AC79925C7BB78ULL,
		0x4FB5DAA9F55B0126ULL,
		0x75B491BC8DF78903ULL,
		0x5C50B745791D9165ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0980044A22082013ULL,
		0x2218104000808000ULL,
		0x20410612A882100FULL,
		0x83E8800E15051529ULL,
		0x2212C09800821310ULL,
		0x40A458A030520000ULL,
		0x34B0803405E60100ULL,
		0x48108341081D8025ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85FBD95BB69BC033ULL,
		0xC96230A59E114D8EULL,
		0x39BA6E8078CB2E6EULL,
		0xE23E762B098F1FBAULL,
		0x4A93D53C80BA8DACULL,
		0xDE0CD08A05BE08FDULL,
		0xBA02F100884D4657ULL,
		0xA830EBD77B4B9512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30FADFAA497A62B7ULL,
		0x0F9D307C7CA593F5ULL,
		0x89F4F8817F41CF62ULL,
		0x632F3CB8F3D3D62CULL,
		0x2C1BED602FD3BED7ULL,
		0xF4CFADABAB68B20EULL,
		0xA1C8D7B6ED53640DULL,
		0xF76CF70F6AD38F15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00FAD90A001A4033ULL,
		0x090030241C010184ULL,
		0x09B0688078410E62ULL,
		0x622E342801831628ULL,
		0x0813C52000928C84ULL,
		0xD40C808A0128000CULL,
		0xA000D10088414405ULL,
		0xA020E3076A438510ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E87A7C086FAAB3EULL,
		0xC3BC4F0A557E21E7ULL,
		0x0E31B34191602D13ULL,
		0x27A5B56D5209527CULL,
		0x9976BE054C27A83CULL,
		0x1CD417C932D9DDC9ULL,
		0xB58361A70D99CC95ULL,
		0x925CE96A6C1631E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF9287767BF85435ULL,
		0x39B202087FCCA9CFULL,
		0x0FDB1A1A1CD972C8ULL,
		0xEEEE9839FFCED9CFULL,
		0x747C23133807BBFDULL,
		0x428C2C66777BD963ULL,
		0xC3F35C2EACEEE317ULL,
		0xCBF12FB3DA137368ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E82874002F80034ULL,
		0x01B00208554C21C7ULL,
		0x0E11120010402000ULL,
		0x26A490295208504CULL,
		0x107422010807A83CULL,
		0x008404403259D941ULL,
		0x818340260C88C015ULL,
		0x8250292248123160ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F3242566AB21F6EULL,
		0xE9A304615A1682BEULL,
		0xC13C592DC3F0F6D1ULL,
		0x82FEB3AB7148A016ULL,
		0x20410BC6ECD82EF8ULL,
		0x394A7A1BA94EF149ULL,
		0xF7C4553AF6750608ULL,
		0xCB6C3A3B79358DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2685D993E0BCC8ULL,
		0x3F84143B83ACE8A6ULL,
		0x887FA5A9E0FD0B57ULL,
		0x53E6E7365D448C99ULL,
		0x2E4A59BAAE0A668BULL,
		0xB21E6B0B35CDCCA9ULL,
		0x9E68D45118C90883ULL,
		0xC2B705856AED5AD9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E22005002A01C48ULL,
		0x29800421020480A6ULL,
		0x803C0129C0F00251ULL,
		0x02E6A32251408010ULL,
		0x20400982AC082688ULL,
		0x300A6A0B214CC009ULL,
		0x9640541010410000ULL,
		0xC224000168250889ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE883F8628D2A6282ULL,
		0xADC760B0A9EEEAD7ULL,
		0xD1F875DF02C85AD7ULL,
		0x9EA81182AA3DD3EBULL,
		0xF45C5F790AA2F015ULL,
		0x545DF44AB794648AULL,
		0x7133263B47053EF6ULL,
		0xA1FAC3150F40EAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAD02AE29D009D54ULL,
		0xA3EB1F762BF262F1ULL,
		0x232799DAACEDF6A0ULL,
		0x4FB0900DCCF00818ULL,
		0xFF7E67400645C5CAULL,
		0x955363BEC12F1693ULL,
		0x77DCF3EBA42CD9C7ULL,
		0xBF48E9FD4723EC43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE88028628D000000ULL,
		0xA1C3003029E262D1ULL,
		0x012011DA00C85280ULL,
		0x0EA0100088300008ULL,
		0xF45C47400200C000ULL,
		0x1451600A81040482ULL,
		0x7110222B040418C6ULL,
		0xA148C1150700E800ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD856E5DC3FBDDA06ULL,
		0x92DB750B85058F61ULL,
		0x4187727737FAE8CEULL,
		0xF60A50BA14F7F3F3ULL,
		0x819FD8C041BC3B75ULL,
		0x3DD8FB77F5829414ULL,
		0x2BD226DDD6BB9E4AULL,
		0x03B9FCC657CB2CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x243222734A11ABB2ULL,
		0xA08FDAFD8962CD10ULL,
		0x2DBF3828E2A40AAAULL,
		0xFCFF274A9C689685ULL,
		0x5FAD9BA1E61D10DEULL,
		0x09F40108FB9ACB10ULL,
		0xC0F2C7807127780AULL,
		0x4A69EF5972313885ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001220500A118A02ULL,
		0x808B500981008D00ULL,
		0x0187302022A0088AULL,
		0xF40A000A14609281ULL,
		0x018D9880401C1054ULL,
		0x09D00100F1828010ULL,
		0x00D206805023180AULL,
		0x0229EC4052012880ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09C92744065A7E77ULL,
		0x9E9AE4C983B7FE95ULL,
		0x8CD4A8C5355A3D81ULL,
		0xA2E8D37A50C046C9ULL,
		0xDB8AB55E51A75CFCULL,
		0xC542B420D3E0A0E1ULL,
		0x49FEC3CF841DFEECULL,
		0xCDC7517740B3FC04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8280825DB7B9E12FULL,
		0x6AEB30AB8BCB2556ULL,
		0xCC33461EB8F6F986ULL,
		0x1957F01C4B3F2125ULL,
		0x9EEFCCF4F5FA0FB4ULL,
		0xF6C213BF9B470871ULL,
		0xDA32F26C4237C0BEULL,
		0x3016802400232072ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080024406186027ULL,
		0x0A8A208983832414ULL,
		0x8C10000430523980ULL,
		0x0040D01840000001ULL,
		0x9A8A845451A20CB4ULL,
		0xC442102093400061ULL,
		0x4832C24C0015C0ACULL,
		0x0006002400232000ULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7040035C3866A56ULL,
		0x2E4BDBB866084475ULL,
		0x7E87DE47757F45E7ULL,
		0x95EF2EC06F5F8309ULL,
		0xFCB3E49C89CA2751ULL,
		0x6EDF5F3744C12600ULL,
		0x807442E020CB0E3FULL,
		0xA1F665146E5F61F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE3768593FF02808ULL,
		0x6625DE2F6BCAF708ULL,
		0xF414D79EE934BFEFULL,
		0xD7EE2BFF9D4639A8ULL,
		0xD5BECE8B14BCDC85ULL,
		0xF005F7C48DD24C41ULL,
		0x1EE46209123B3707ULL,
		0xAABEFEE22B7C9C48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA604001103802800ULL,
		0x2601DA2862084400ULL,
		0x7404D606613405E7ULL,
		0x95EE2AC00D460108ULL,
		0xD4B2C48800880401ULL,
		0x6005570404C00400ULL,
		0x00644200000B0607ULL,
		0xA0B664002A5C0040ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98FDF56CF26B2E83ULL,
		0x837D16CEB7B15DB7ULL,
		0xA348236C7D7ED3C9ULL,
		0x551ADE5D333421ECULL,
		0x95BE62322459E5E6ULL,
		0xDA336F6BE5730786ULL,
		0xEC830A291FAD2257ULL,
		0x32FBE043ACFB9B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B1747697C69F33ULL,
		0x788A2BD2F17DDDD9ULL,
		0x1B9CA68FD24BFCFDULL,
		0xB566925375686120ULL,
		0x932BAD66CC978A4AULL,
		0xFE4B9BFE87A9B2A3ULL,
		0x99B5847B7D596DD9ULL,
		0xA8C2FB1E47C5A521ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90B1746492420E03ULL,
		0x000802C2B1315D91ULL,
		0x0308220C504AD0C9ULL,
		0x1502925131202120ULL,
		0x912A202204118042ULL,
		0xDA030B6A85210282ULL,
		0x888100291D092051ULL,
		0x20C2E00204C18101ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x587F55D625A4DDC1ULL,
		0x3223E4B27888C0BBULL,
		0x14F9D8C76FF31FC4ULL,
		0x5397702B1B1C517AULL,
		0xBD78DFD0B69B93F4ULL,
		0x9D447372A6D356D9ULL,
		0x2E480173D3F6D30CULL,
		0xCA149E62E3CDB3F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DC1B6DE8B4CAFA6ULL,
		0x9184C925DA7FBA48ULL,
		0xDE61AF2087FB2F74ULL,
		0x4F3BF918253BED48ULL,
		0x120A93C70FFAC343ULL,
		0x559F8EA0ECDFAC44ULL,
		0x59348D26874AE0CDULL,
		0xE0DAC147C71FDD53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x484114D601048D80ULL,
		0x1000C02058088008ULL,
		0x1461880007F30F44ULL,
		0x4313700801184148ULL,
		0x100893C0069A8340ULL,
		0x15040220A4D30440ULL,
		0x080001228342C00CULL,
		0xC0108042C30D9150ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F3FE35AE07E4446ULL,
		0x36DF70A1C312C51AULL,
		0x6BF55E90759E1CA5ULL,
		0xF4783AFFF4805E0CULL,
		0x5FE3CFD3F2302341ULL,
		0x805A80C911ED487EULL,
		0x8F2F45131E4ADCF5ULL,
		0xEFCDF142634ACFDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CE81691F90083F4ULL,
		0xC5537777199241AEULL,
		0xB2A5FED267709601ULL,
		0xED6AFCEB52BDA451ULL,
		0x3A424489C8656373ULL,
		0x69F8FC8E7FEEA2FAULL,
		0x8F74711AD89C717DULL,
		0xC405A638E879E2E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C280210E0000044ULL,
		0x045370210112410AULL,
		0x22A55E9065101401ULL,
		0xE46838EB50800400ULL,
		0x1A424481C0202341ULL,
		0x0058808811EC007AULL,
		0x8F24411218085075ULL,
		0xC405A0006048C2C2ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0DE8728728E5ADCULL,
		0xFF6A265AD04F8007ULL,
		0x620EA380F3607847ULL,
		0x59DA21A909A251A7ULL,
		0x53AD2A08500B2225ULL,
		0x274A42DB6910E2F7ULL,
		0xD8BC3E14DCB371B0ULL,
		0x3835D6F4AAFE9AD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2946349ACBD8DF3CULL,
		0x350CD827711BE03BULL,
		0x033BDB8388FA096DULL,
		0x7E708672066ABD2CULL,
		0x6A0AE62504B89663ULL,
		0x17039008EAC5CB04ULL,
		0xAB50B4748629FA1AULL,
		0xD4E580942546F05BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2046040842885A1CULL,
		0x35080002500B8003ULL,
		0x020A838080600845ULL,
		0x5850002000221124ULL,
		0x4208220000080221ULL,
		0x070200086800C204ULL,
		0x8810341484217010ULL,
		0x1025809420469053ULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x336CBB043840DCE0ULL,
		0xA84A4CCAD518A334ULL,
		0x44781A6ED5260808ULL,
		0xF01290182C750991ULL,
		0xAB3EF916A41B90BAULL,
		0x0B0CC3B0AA243020ULL,
		0xD126CAD95C7C75DAULL,
		0x64CBCD5E6072813CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEE53D86D32FDD2ULL,
		0x58AB251225BE43DDULL,
		0x38C7F88D1234C8BAULL,
		0x506BA948822CABC4ULL,
		0x3345FD7232032620ULL,
		0xED782B877082464FULL,
		0x259B02EF2EA8034FULL,
		0xDA2AAD2FE0954D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x016C13002800DCC0ULL,
		0x080A040205180314ULL,
		0x0040180C10240808ULL,
		0x5002800800240980ULL,
		0x2304F91220030020ULL,
		0x0908038020000000ULL,
		0x010202C90C28014AULL,
		0x400A8D0E60100104ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7D740F497D62BBFULL,
		0xA2E48455741C0D0CULL,
		0x4882410B91EDD9E8ULL,
		0x5140B3A513B55064ULL,
		0x331DBDD4BEFF7CA0ULL,
		0x9545821118E884A9ULL,
		0x07443328678BD7E5ULL,
		0x4F8AB74C4418FC7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2229C36ADFBC33C5ULL,
		0x1BCB1CD50ACF2796ULL,
		0x60AB3D954DF047C1ULL,
		0xE852FE589869B5CFULL,
		0x521C43943DFBC714ULL,
		0x841C067E2B240711ULL,
		0x44B4B8EA6CBD3F43ULL,
		0x644DDADE6627C6FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0201406097942385ULL,
		0x02C00455000C0504ULL,
		0x4082010101E041C0ULL,
		0x4040B20010211044ULL,
		0x121C01943CFB4400ULL,
		0x8404021008200401ULL,
		0x0404302864891741ULL,
		0x4408924C4400C47CULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52D03C427333DB4DULL,
		0xD95F3F276E734A32ULL,
		0x9AF962038250A9A9ULL,
		0x9AA9FE354CC49019ULL,
		0x38518EB5C1212305ULL,
		0xA95F6DB6AB037D1EULL,
		0x62A3124019FEDD13ULL,
		0x966B900A220CA2D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC25CC3BDC86DF1ULL,
		0xC888AD7A6CCF3B5AULL,
		0xB4B3CD28A2B5F7A5ULL,
		0x0D5598B840F0C140ULL,
		0x85ECB272F8C70098ULL,
		0x5B2425DDEFC1841BULL,
		0x133BF291FBF6E053ULL,
		0x5B3DF7A86091DE3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C01C4231004941ULL,
		0xC8082D226C430A12ULL,
		0x90B140008210A1A1ULL,
		0x0801983040C08000ULL,
		0x00408230C0010000ULL,
		0x09042594AB01041AULL,
		0x0223120019F6C013ULL,
		0x1229900820008214ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78C2CCE28312F407ULL,
		0xE700FF89B1C042E6ULL,
		0x4D77AEF4A41E5D98ULL,
		0x274BCE410A2AB2FFULL,
		0xEB56730AC35A00A3ULL,
		0x71424E925AABA58AULL,
		0x1F4E47F5391AC490ULL,
		0xC782F36DC1B105C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECB8ED64786BB98ULL,
		0x28A2C6B804F94934ULL,
		0x7D7A2E89A9FE9773ULL,
		0xFA8C80D9675BE507ULL,
		0x410824CB349E19C9ULL,
		0xAB748E865C230291ULL,
		0xA5427ADD2091A335ULL,
		0xBF3438BFCD73B6BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18C28CC20302B000ULL,
		0x2000C68800C04024ULL,
		0x4D722E80A01E1510ULL,
		0x22088041020AA007ULL,
		0x4100200A001A0081ULL,
		0x21400E8258230080ULL,
		0x054242D520108010ULL,
		0x8700302DC1310488ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13D54BA3CD668833ULL,
		0xCB1D7A8C83B84A70ULL,
		0xB0A4DF3CFA2F86A2ULL,
		0xF59E0BC719A4E342ULL,
		0xC0B4CCFB995FC8EBULL,
		0x418A113255B21F70ULL,
		0xD4AFC63FDB2D4CFFULL,
		0x9A4744531B50CC60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5141D37FC2A04231ULL,
		0x1358E15F7027225BULL,
		0xD1581FD69CDDCB69ULL,
		0x6B6D77AEAC20B917ULL,
		0xAF47FB496E479623ULL,
		0x5B56F380CC5157BDULL,
		0x2616504C0A86263CULL,
		0xAD7D8CC0D453AD1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11414323C0200031ULL,
		0x0318600C00200250ULL,
		0x90001F14980D8220ULL,
		0x610C03860820A102ULL,
		0x8004C84908478023ULL,
		0x4102110044101730ULL,
		0x0406400C0A04043CULL,
		0x8845044010508C00ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75F33C0B9FBB012FULL,
		0x266D24981B86AC69ULL,
		0xA319B67472121AA1ULL,
		0xE25D71D3D5D8BF9DULL,
		0x817DC9D4850B28FEULL,
		0x2FAC9AB7279E5178ULL,
		0x445719371FCDB9BEULL,
		0x3B6FA7D898A4587BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDB4E1DDB34F2A75ULL,
		0x2C4123018BE120F5ULL,
		0x4472B71576481C9AULL,
		0x57EEA25A5ECEFC8FULL,
		0x347B69BFFECE6D1DULL,
		0x948CC158295CF2CFULL,
		0xAC6A1F4ACAA54E3AULL,
		0xAC44AECBC1DD267CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65B02009930B0025ULL,
		0x244120000B802061ULL,
		0x0010B61472001880ULL,
		0x424C205254C8BC8DULL,
		0x00794994840A281CULL,
		0x048C8010211C5048ULL,
		0x044219020A85083AULL,
		0x2844A6C880840078ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EF86662F302FF01ULL,
		0x0DDFB5D83E36351BULL,
		0x5475A6EDCFF0A01BULL,
		0x794015BB869DDE6FULL,
		0xD93E42FFBB28F67DULL,
		0xDDCA683251208ACFULL,
		0x9341914C5BDE318DULL,
		0x4FBBE0AB696738A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC0805B54372B8CULL,
		0x66F04CC77D7EF2DBULL,
		0x36D58AFD07911696ULL,
		0xE12BE1C08BCB1D40ULL,
		0x77979FD76BA28DA8ULL,
		0x3E4996142AC2803FULL,
		0x77DD07B291B38F35ULL,
		0xD538FD6A33A73963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CC0004250022B00ULL,
		0x04D004C03C36301BULL,
		0x145582ED07900012ULL,
		0x6100018082891C40ULL,
		0x511602D72B208428ULL,
		0x1C4800100000800FULL,
		0x1341010011920105ULL,
		0x4538E02A21273823ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D199A98E7D00A7CULL,
		0xBA731AF248C62662ULL,
		0x607D19BE9BB7856EULL,
		0xE28A102E359A131EULL,
		0xAE0166E93D9463CEULL,
		0xA0677BECF66C466CULL,
		0xFC2E012076F472ACULL,
		0x9344DA1C435985E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CA22E5FC24B04D3ULL,
		0x14817008AFACC870ULL,
		0xE1FB47C14D849CE3ULL,
		0x8A99B388D27CC095ULL,
		0x4DFEF3620D3E7555ULL,
		0x67601B1C211013F1ULL,
		0x860375F6DC6F629DULL,
		0x5BD52310F7A4BCCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C000A18C2400050ULL,
		0x1001100008840060ULL,
		0x6079018009848462ULL,
		0x8288100810180014ULL,
		0x0C0062600D146144ULL,
		0x20601B0C20000260ULL,
		0x840201205464628CULL,
		0x13440210430084C8ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B6CA62925A2B374ULL,
		0x2F44EAFCBBE68658ULL,
		0x2482A91F6ECA631BULL,
		0x59B612BA5E0863AFULL,
		0x7C96C9944360113CULL,
		0xA9E3B1D8F436FA13ULL,
		0x7E93C76F695E2C25ULL,
		0xEBCE9237ED59F87EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DDD86C1B08D1EC1ULL,
		0x0EC35FFDD8095BDBULL,
		0xCB39180E858A363CULL,
		0x76777F616A7F0EEAULL,
		0x6E48E80E5CF96004ULL,
		0x805B9E1703EB023BULL,
		0xC78C5C92AC9F73F4ULL,
		0x6527C858BF583C82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x094C860120801240ULL,
		0x0E404AFC98000258ULL,
		0x0000080E048A2218ULL,
		0x503612204A0802AAULL,
		0x6C00C80440600004ULL,
		0x8043901000220213ULL,
		0x46804402281E2024ULL,
		0x61068010AD583802ULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x476A3DC16A44BF9CULL,
		0xDEDF34EF9DE739B9ULL,
		0xFF8B7A6937BAA02FULL,
		0x2941313C918356A0ULL,
		0xA8F805351C05A90FULL,
		0x2199158E225A3C45ULL,
		0x847D2118A32173C2ULL,
		0xE38E53867479DFDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040F9D0B5D52F9CCULL,
		0x73BDFF40EF193DADULL,
		0x703177D3F8D380E1ULL,
		0xAE1144564141704AULL,
		0x70F1583F25A6B141ULL,
		0xAFCA7B2B89028CD3ULL,
		0xF5BF5A7CE849CBF1ULL,
		0x5C78FC15ED1D33EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040A1D014840B98CULL,
		0x529D34408D0139A9ULL,
		0x7001724130928021ULL,
		0x2801001401015000ULL,
		0x20F000350404A101ULL,
		0x2188110A00020C41ULL,
		0x843D0018A00143C0ULL,
		0x40085004641913CCULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DCD5A3CB924A2DFULL,
		0xBC1B3CBA76F036A0ULL,
		0x7A05DB406F0BE9AFULL,
		0xF0173A2DBBAFD9E3ULL,
		0x9895AC072A4AA93DULL,
		0x909E79446CB906D6ULL,
		0xE694843AA3DE3688ULL,
		0x4E2C7E75507E6CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D1A2044C391B65ULL,
		0xA557C97AF9C943BBULL,
		0x2D760C7574980D3AULL,
		0xB6E3EBD364EF0C68ULL,
		0x9402F0DC8327E575ULL,
		0x678BD586E7A18DF6ULL,
		0xE73648EDEB902AC8ULL,
		0xBE47C498B86F6379ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10C1020408200245ULL,
		0xA413083A70C002A0ULL,
		0x280408406408092AULL,
		0xB0032A0120AF0860ULL,
		0x9000A0040202A135ULL,
		0x008A510464A104D6ULL,
		0xE6140028A3902288ULL,
		0x0E044410106E6071ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD38EE46429F50ED8ULL,
		0x718FB3F45D88797DULL,
		0x3C978D16B03FCD02ULL,
		0x5FA8E907AEA09E8DULL,
		0x7B066F875E8610E9ULL,
		0x521D712330A7AD06ULL,
		0x570B7226804F20A9ULL,
		0xC88FCDBACC59E0D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B26852B7C161DB0ULL,
		0x7658AE34701E8B65ULL,
		0xE99D74CEB31A5630ULL,
		0x12199CC6570CE35EULL,
		0xC8A9FD42D1B8E210ULL,
		0xA19A5F8FE566D1C2ULL,
		0x2CCB432BD4094561ULL,
		0x73BEB53155DE281EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1306842028140C90ULL,
		0x7008A23450080965ULL,
		0x28950406B01A4400ULL,
		0x120888060600820CULL,
		0x48006D0250800000ULL,
		0x0018510320268102ULL,
		0x040B422280090021ULL,
		0x408E853044582012ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3BE74EB7DAC8C40ULL,
		0x7A9B926A91397917ULL,
		0xC0F5CE27FF0B67B5ULL,
		0x3F5CDF1FFBBD0A5CULL,
		0x5F6CEF154B59A5EBULL,
		0xAD8BBEF1F714EF74ULL,
		0x504227C337A4966CULL,
		0x6E031779F161E7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE934FAF2873EED3ULL,
		0xF899D3513920979CULL,
		0x175BCD3C92A24A93ULL,
		0x814FA51F574D9217ULL,
		0xFB3F0900F0F9BAEDULL,
		0x6008E65EC522DCA9ULL,
		0x7C7F3F8A05978ED9ULL,
		0x7E55275471F5DB5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA29244AB28208C40ULL,
		0x7899924011201114ULL,
		0x0051CC2492024291ULL,
		0x014C851F530D0214ULL,
		0x5B2C09004059A0E9ULL,
		0x2008A650C500CC20ULL,
		0x5042278205848648ULL,
		0x6E0107507161C353ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1DE19D89EA47B86ULL,
		0xF39713AC04519D68ULL,
		0x21D0FAA48361782EULL,
		0x1DE0747391A0F6F4ULL,
		0x610A35B8CE568389ULL,
		0x6CE49426C4A74638ULL,
		0xDBBFCF6502C262DEULL,
		0xAB416A1AC9A4C308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x099D06E81377BB13ULL,
		0xB6E8CBD947882F99ULL,
		0xB0B521DC3D2348D2ULL,
		0x936247E97C1192D6ULL,
		0xF7076C3F561A6B59ULL,
		0x3869FB2605B11317ULL,
		0xAAB68B7FA2E4AE53ULL,
		0x3BE286C8AFE4D7B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x019C00C812243B02ULL,
		0xB280038804000D08ULL,
		0x2090208401214802ULL,
		0x11604461100092D4ULL,
		0x6102243846120309ULL,
		0x2860902604A10210ULL,
		0x8AB68B6502C02252ULL,
		0x2B40020889A4C300ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16FBDAE623905E9FULL,
		0x73E8DD26434CBCF6ULL,
		0xA13E282033DC6320ULL,
		0x20B2824AF470C216ULL,
		0x48146664767E4D10ULL,
		0xB5FC50447BAFD5E9ULL,
		0x33B1FBA6F30FFE93ULL,
		0x6F578116BAD61310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BD2BA29B937135ULL,
		0xD7CD54A7790ED552ULL,
		0xE94BF56F72B779E0ULL,
		0x3DB1EABFFD988353ULL,
		0xF087CAFA7C2CE16CULL,
		0xCECAE7EE6E5608FBULL,
		0x94EC9A3D236611B3ULL,
		0x27AA3296A286A1D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02B90AA203905015ULL,
		0x53C85426410C9452ULL,
		0xA10A202032946120ULL,
		0x20B0820AF4108212ULL,
		0x40044260742C4100ULL,
		0x84C840446A0600E9ULL,
		0x10A09A2423061093ULL,
		0x27020016A2860110ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE106D934C2A44DFULL,
		0x1CF74239751977B9ULL,
		0xBAE3952594AF311DULL,
		0x07DE7D0B1038EB21ULL,
		0x4BF9E9402CDEAFFAULL,
		0x37DDD597333869F2ULL,
		0x98527AC80AC08AD9ULL,
		0x47F78AC31A8A132DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995ABCDA1D8142C2ULL,
		0xE46A9D7AF5642AD5ULL,
		0xEB8129E9A0911884ULL,
		0xFE3F37E0D4A8682AULL,
		0xA6AF437AC7F4989AULL,
		0x578D484E0C024186ULL,
		0x65891EFA0D06DD50ULL,
		0x1F39E7B58FB976D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88102C920C0040C2ULL,
		0x0462003875002291ULL,
		0xAA81012180811004ULL,
		0x061E350010286820ULL,
		0x02A9414004D4889AULL,
		0x178D400600004182ULL,
		0x00001AC808008850ULL,
		0x073182810A881201ULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CAF9D3CB480F4FCULL,
		0x351DA0F497414770ULL,
		0x630D24BECA84568EULL,
		0x740A15B4BB8E32BEULL,
		0xC1F82E130685E9FCULL,
		0x0547C291BD5A0A45ULL,
		0x04ACDB906B47E151ULL,
		0x8B64EECEEA96D313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74BC61A8EC651FF3ULL,
		0x45B0A4A11CFE418EULL,
		0x06A2615DB265022DULL,
		0xDEE7978CA0009D01ULL,
		0x883451A8F3CC0EEBULL,
		0x4756530C61FB757DULL,
		0xF109E2DDEEFF628CULL,
		0xA9473501E21CF2A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74AC0128A40014F0ULL,
		0x0510A0A014404100ULL,
		0x0200201C8204020CULL,
		0x54021584A0001000ULL,
		0x80300000028408E8ULL,
		0x05464200215A0045ULL,
		0x0008C2906A476000ULL,
		0x89442400E214D200ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCEDE83AFC06E345ULL,
		0xC6BCCFB59E1E3E67ULL,
		0xBE94F73A2E747BC7ULL,
		0x41F45A475E41C4C7ULL,
		0xB43C6D7EE5261323ULL,
		0xCC0295E058845963ULL,
		0x03B1CE5E997D9908ULL,
		0x6EF8DAE4BFC2A722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEAD8961A09662B0ULL,
		0x7799B0A53B949810ULL,
		0x3C900A7B6F22068EULL,
		0x0D3C98BC89D44CA3ULL,
		0x908D637BF8F22888ULL,
		0x9D7623DB099454E8ULL,
		0x4D2A589BEDAEBC92ULL,
		0xEC0718F7867B04E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CAD8820A0066200ULL,
		0x469880A51A141800ULL,
		0x3C90023A2E200286ULL,
		0x0134180408404483ULL,
		0x900C617AE0220000ULL,
		0x8C0201C008845060ULL,
		0x0120481A892C9800ULL,
		0x6C0018E486420422ULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67D9D2B8DEBDD9D3ULL,
		0xF04A2A199A2E4653ULL,
		0x9A14782CAA2FFAB8ULL,
		0x06CAC5C38F397688ULL,
		0xD77A6B72DDA7615FULL,
		0xCA9C42C2FD588EC3ULL,
		0xDC846730995ABAFAULL,
		0x195ACD5A28BC1D1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC144E9D6EE04B163ULL,
		0x6844EA622C174D15ULL,
		0x5F3EF88A46D3AF17ULL,
		0xAB5137B807CF2937ULL,
		0xD24D67DE6CBE077EULL,
		0x82D3A5CD9DA92FA7ULL,
		0x5C2E6AEDA3A1CF5DULL,
		0x7930BD030809509EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4140C090CE049143ULL,
		0x60402A0008064411ULL,
		0x1A1478080203AA10ULL,
		0x0240058007092000ULL,
		0xD24863524CA6015EULL,
		0x829000C09D080E83ULL,
		0x5C04622081008A58ULL,
		0x19108D020808101EULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDF4C16A3F8A485EULL,
		0x32902BAF56098FEEULL,
		0x254CF2980A80C642ULL,
		0x6EF9AC66936F4829ULL,
		0x4B5D46B704BC5DEFULL,
		0xEB4B042771DAA313ULL,
		0x0A45EC25F1417687ULL,
		0x7580D39D116FD717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x178989D0552EFDFEULL,
		0x607A92312B8A0177ULL,
		0xAF2B1258B3A90159ULL,
		0xB838F1EBF4A8561AULL,
		0x29EA5DE32850FF52ULL,
		0xF7614E60C1327C30ULL,
		0x44B1F85DDB225A4FULL,
		0x025C0CAD234BD0F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15808140150A485EULL,
		0x2010022102080166ULL,
		0x2508121802800040ULL,
		0x2838A06290284008ULL,
		0x094844A300105D42ULL,
		0xE341042041122010ULL,
		0x0001E805D1005207ULL,
		0x0000008D014BD011ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1C4F68E31EFD136ULL,
		0x43D90702FF8CD2BEULL,
		0x2A3CA2942738EE3FULL,
		0xC1D2D5D2EC449E71ULL,
		0xB12AEA217FB58865ULL,
		0x3EBE77C89AE79CD7ULL,
		0xF7724D543BFA33C9ULL,
		0x90EB51F108E55CFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D6D0FB693DC05BDULL,
		0xE5D73CB2C3BFCA1AULL,
		0x0C62976722839833ULL,
		0x8099ABF340DA2DA6ULL,
		0x8ABE3FBDF8D85AC7ULL,
		0x3234B491D2770145ULL,
		0x6F54F6DAC816B38EULL,
		0xCD72BF23F8EA6598ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0144068611CC0134ULL,
		0x41D10402C38CC21AULL,
		0x0820820422008833ULL,
		0x809081D240400C20ULL,
		0x802A2A2178900845ULL,
		0x3234348092670045ULL,
		0x6750445008123388ULL,
		0x8062112108E04498ULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD312335A56A0298AULL,
		0xA8C28E1C5F43EE7AULL,
		0x1FE2E23EDD4B3715ULL,
		0xA1D3BB1634EF6A88ULL,
		0x9AD4AB5305E39B17ULL,
		0x0429DAB33E3F3F5CULL,
		0x7213457C209AAC2DULL,
		0x6E0E7A5387543901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380EF2F1E53932B6ULL,
		0x501BBF40F9767C26ULL,
		0xD7DB223A436B59C0ULL,
		0x07A1490A26595404ULL,
		0x3B63B9CB0DF4D119ULL,
		0x1B68CC0BAE31E0A6ULL,
		0xC5E0B7759B6C6D74ULL,
		0x9165C9FB2B6B604EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1002325044202082ULL,
		0x00028E0059426C22ULL,
		0x17C2223A414B1100ULL,
		0x0181090224494000ULL,
		0x1A40A94305E09111ULL,
		0x0028C8032E312004ULL,
		0x4000057400082C24ULL,
		0x0004485303402000ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x047120110AE60FCFULL,
		0xD4DD182F575FE04EULL,
		0x00CB8A3AC8F89D2BULL,
		0xE566BA7BB356FD67ULL,
		0x079A69FC8C2DB152ULL,
		0xBA7119CF074921A4ULL,
		0x944CA723AF1ECBDFULL,
		0xC199C2AE95B5A137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE792EBE978FF1F0AULL,
		0xC5734B7197C838E1ULL,
		0xCE53942B926B2882ULL,
		0x15A110B2F98CE843ULL,
		0x935DE84765DD7B51ULL,
		0x96B6DC211C7E1691ULL,
		0xEA7C5E82D646A39AULL,
		0x6B7BADB3F1D501DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0410200108E60F0AULL,
		0xC451082117482040ULL,
		0x0043802A80680802ULL,
		0x05201032B104E843ULL,
		0x03186844040D3150ULL,
		0x9230180104480080ULL,
		0x804C06028606839AULL,
		0x411980A291950116ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB9FC35DDB4FBCF9ULL,
		0x5DDCD12D48EEB008ULL,
		0x377285549A603CEDULL,
		0xB0ADAEBAB7AA16ADULL,
		0xA033FADDDEA911D3ULL,
		0x7DF346E973CC72A8ULL,
		0x4FFC79151A77A53FULL,
		0xBC16D1B03191989DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE325C1B0E7111154ULL,
		0xDEC8E70C71A0449AULL,
		0x10D38D996B54AFD1ULL,
		0x9FD20657DA586542ULL,
		0x76C97DF426B722B3ULL,
		0x78DA497D56A6E134ULL,
		0xC7C3C1E099DEE958ULL,
		0x4693759B5F95D4DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC305C110C3011050ULL,
		0x5CC8C10C40A00008ULL,
		0x105285100A402CC1ULL,
		0x9080061292080400ULL,
		0x200178D406A10093ULL,
		0x78D2406952846020ULL,
		0x47C041001856A118ULL,
		0x041251901191909DULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x605E8CD4BEC87B7AULL,
		0xF317032E2564F1C4ULL,
		0xB7EC8D9D71EC67F3ULL,
		0x471E1E8DAB92CA4DULL,
		0x59C6AA7BF9B32ABFULL,
		0xBEC012D44BFA5F2EULL,
		0x1EC8717C761AF41AULL,
		0x04083D750C66E6BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF93D672099D21AEULL,
		0x2199BDE8B903CC12ULL,
		0x1932CD0CAE7F6A8CULL,
		0x5B10E25C6CA443C8ULL,
		0xA77BBBCE0774B087ULL,
		0xD8B81BB574C79B6CULL,
		0x6B0FB2AE6464D2D0ULL,
		0xF5F0105600A465A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x201284500888212AULL,
		0x211101282100C000ULL,
		0x11208D0C206C6280ULL,
		0x4310020C28804248ULL,
		0x0142AA4A01302087ULL,
		0x9880129440C21B2CULL,
		0x0A08302C6400D010ULL,
		0x04001054002464A7ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x929AA19C79FE14F6ULL,
		0xEC0640B01FAE411CULL,
		0x1EFE5FF95C58AF1CULL,
		0x47A1C10CCAA2E27AULL,
		0x7A06C6C222063971ULL,
		0x0A143B73247756D8ULL,
		0x0DE619292D548E98ULL,
		0xCC439E1C72E25AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF58142C6EDD0C48ULL,
		0x5F2258506FEBD728ULL,
		0x4A5BDB628C625F67ULL,
		0xA48F23523E8EA2E5ULL,
		0x828B93ACC09A1C72ULL,
		0x0D028565E82E58C7ULL,
		0x6DE6BE4976F8F13DULL,
		0x6D87B69DAF38F31CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8218000C68DC0440ULL,
		0x4C0240100FAA4108ULL,
		0x0A5A5B600C400F04ULL,
		0x048101000A82A260ULL,
		0x0202828000021870ULL,
		0x08000161202650C0ULL,
		0x0DE6180924508018ULL,
		0x4C03961C22205210ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32AA9CBDCA23A772ULL,
		0x560E85062104FD73ULL,
		0x448DAD5F2421B1F2ULL,
		0x91F9FB3CA6CF82FDULL,
		0x02C528C41F6B3188ULL,
		0xEAD3C798AA11E556ULL,
		0x686E8A72923F19C4ULL,
		0x29913977EA73BC32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64D0E491590B90D0ULL,
		0x253570F987EFB9F8ULL,
		0x8356ED35FC00AEEBULL,
		0x9C8EE14C8B849D88ULL,
		0xFFE934F18221C7EEULL,
		0x87B3522B6929E45CULL,
		0x55EBFE5958277645ULL,
		0x2E97CD4229D017EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2080849148038050ULL,
		0x040400000104B970ULL,
		0x0004AD152400A0E2ULL,
		0x9088E10C82848088ULL,
		0x02C120C002210188ULL,
		0x829342082801E454ULL,
		0x406A8A5010271044ULL,
		0x2891094228501422ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98C9CB1C2B378AC7ULL,
		0xE377C2D1B504D3EFULL,
		0x24554B842DC63791ULL,
		0x7B7BC6A261F48E9EULL,
		0xF57C0DEC446EEC4EULL,
		0xE46B65D1BA53FB50ULL,
		0xF8D27942ECFE4AEFULL,
		0x9B1B96B60CE26DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B9C14335B900295ULL,
		0xBE0B3ADCED685747ULL,
		0x892D1EA1A84E8E68ULL,
		0x690AF32312E916D6ULL,
		0xC834299235BDFE08ULL,
		0x672CAFCA8B65D995ULL,
		0x7F7C56DA45BA2590ULL,
		0x7DB7EA5E7BDF16C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x188800100B100285ULL,
		0xA20302D0A5005347ULL,
		0x00050A8028460600ULL,
		0x690AC22200E00696ULL,
		0xC0340980042CEC08ULL,
		0x642825C08A41D910ULL,
		0x7850504244BA0080ULL,
		0x1913821608C20480ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E4F4FD4A17ABB43ULL,
		0xBFA04DE57A0FD8D3ULL,
		0x33E1422861BCBA91ULL,
		0xE0FC1A2C035C2885ULL,
		0x812D039113CBFDFAULL,
		0x23C5FF7E06D3B8DFULL,
		0xE5018070CB14F5DBULL,
		0xED81ACAD3D818D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x398A7C9F73E7A285ULL,
		0xB3F9F4EF837A41EBULL,
		0xC9802C32E43B27F9ULL,
		0xFE9D7573F4B852DEULL,
		0x4F0795B3C3628518ULL,
		0x10A1EE00AD579543ULL,
		0x8A45385AEE042D51ULL,
		0x11DCC9DD9A2CA0A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080A4C942162A201ULL,
		0xB3A044E5020A40C3ULL,
		0x0180002060382291ULL,
		0xE09C102000180084ULL,
		0x0105019103428518ULL,
		0x0081EE0004539043ULL,
		0x80010050CA042551ULL,
		0x0180888D18008008ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF202FE03CDA9276ULL,
		0xF308FB9EC4E2648DULL,
		0x863CB5D260810C4BULL,
		0xED1E150FA4B3C75DULL,
		0x168652D3FCFB37F7ULL,
		0x74CEFA1213A86EADULL,
		0x24B5858EBE16459FULL,
		0xE1DBBBA500B0F773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0CAE0E680EB716DULL,
		0x26441D9B50BED770ULL,
		0x32A7AA3EF3805C4DULL,
		0xD018F540FFF0CEC5ULL,
		0x73E638253AECB1DCULL,
		0x937AA14E67245A62ULL,
		0xDD7DF6EEA3C72A27ULL,
		0xFC0815FC12C7B642ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800020E000CA1064ULL,
		0x2200199A40A24400ULL,
		0x0224A01260800C49ULL,
		0xC0181500A4B0C645ULL,
		0x1286100138E831D4ULL,
		0x104AA00203204A20ULL,
		0x0435848EA2060007ULL,
		0xE00811A40080B642ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0BCC4D88A75C65ULL,
		0x22068FA577397374ULL,
		0x45454D0B55337A2BULL,
		0x05E94198894D3FFCULL,
		0x091FE68F2A6148B7ULL,
		0xEA681DF5204CA0F9ULL,
		0x432980A0EE3099CDULL,
		0xB333D135B1E53561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x031286F2A3E22B91ULL,
		0x3F3863D1C2898955ULL,
		0x7056A27CC205F168ULL,
		0xA89FCC878D9840A7ULL,
		0x12653B539A81C62EULL,
		0xE46CBED8E16A1762ULL,
		0xCC835F5F87725E21ULL,
		0xB678EEABC9940BEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0102844080A20801ULL,
		0x2200038142090154ULL,
		0x4044000840017028ULL,
		0x00894080890800A4ULL,
		0x000522030A014026ULL,
		0xE0681CD020480060ULL,
		0x4001000086301801ULL,
		0xB230C02181840161ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C72D3154B170EEDULL,
		0x62AA4C99D7EF6095ULL,
		0x80F7A6AE2B3DE451ULL,
		0x004D0D248DAE15E9ULL,
		0x42FF809B9515EFDEULL,
		0x7B685FB1346361E6ULL,
		0xA818D46B71B2F563ULL,
		0xD423288832C810B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF401F7691394C1ULL,
		0xABDF98C523D6C3E4ULL,
		0x99B152A7069707BEULL,
		0x32E6FB74E637D467ULL,
		0xD43208F5D95865B8ULL,
		0xD43A5D9F7B196457ULL,
		0x3E2524D195292F3AULL,
		0x5B1BEBE1CD88518CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08700115491304C1ULL,
		0x228A088103C64084ULL,
		0x80B102A602150410ULL,
		0x0044092484261461ULL,
		0x4032009191106598ULL,
		0x50285D9130016046ULL,
		0x2800044111202522ULL,
		0x5003288000881088ULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE12B642E3919E9A7ULL,
		0xAC613A4CBADB88E7ULL,
		0x9B11D2D17B62925EULL,
		0x12F7BE57EC9F0679ULL,
		0x3536266617809781ULL,
		0xD152AF7ADF055842ULL,
		0xC16310C7B303B4C0ULL,
		0xF34DBEC9F31C8911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EED9E8DCD77AD53ULL,
		0x8A9571E8101A4EEEULL,
		0x18A953FFEFBC597DULL,
		0xC97BC6667A9A087BULL,
		0x9BC681360828A183ULL,
		0xBCBDFE855F1DEAB0ULL,
		0x0743B6A582960FEEULL,
		0xA20FBF2EC5CA27B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2029040C0911A903ULL,
		0x88013048101A08E6ULL,
		0x180152D16B20105CULL,
		0x00738646689A0079ULL,
		0x1106002600008181ULL,
		0x9010AE005F054800ULL,
		0x01431085820204C0ULL,
		0xA20DBE08C1080110ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCAAC8057B493865ULL,
		0x49C1958E729BFAABULL,
		0xE0527F4F284195F6ULL,
		0xF74C7ACF373BC093ULL,
		0x55D4DE8F2F7CB795ULL,
		0x00494DB55A6FAB0EULL,
		0x3AD0AE40DAD5EFE0ULL,
		0x6224E776A68C9C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED7117E98DAD08AEULL,
		0xF492D99D29602CA5ULL,
		0x17ADA2EDC201219BULL,
		0xED515671C010C04AULL,
		0x3A36C1ACCCC329E9ULL,
		0xE61A2BC8D5A97411ULL,
		0x18E9AFBED549957CULL,
		0xB952B1B0BED281D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC20000109090824ULL,
		0x4080918C200028A1ULL,
		0x0000224D00010192ULL,
		0xE54052410010C002ULL,
		0x1014C08C0C402181ULL,
		0x0008098050292000ULL,
		0x18C0AE00D0418560ULL,
		0x2000A130A6808092ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F93428BEB3F920ULL,
		0x987AB0BBDEF3C1B8ULL,
		0x82FFAD4BF0548EACULL,
		0x05BB7B7D5BFB4ADBULL,
		0x108117BD5CCABA0EULL,
		0x2C17A265E93C4854ULL,
		0xC2AEDD93C3691E6AULL,
		0x6456166FADA6E255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A8E01C90E9D4E1AULL,
		0xD00AA7E88E6EA520ULL,
		0x9D17550FAA6AB0C0ULL,
		0x8637139952D4D7DCULL,
		0xB46840E82E09727EULL,
		0x50784E44BCD63264ULL,
		0xF3C98CB9A625FC31ULL,
		0x17852E07B7381BD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008800080E914800ULL,
		0x900AA0A88E628120ULL,
		0x8017050BA0408080ULL,
		0x0433131952D042D8ULL,
		0x100000A80C08320EULL,
		0x00100244A8140044ULL,
		0xC2888C9182211C20ULL,
		0x04040607A5200250ULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27546B2489DDD27DULL,
		0x139DF2E3A5BD4325ULL,
		0x1BD67B6CA6087948ULL,
		0x8EA2796C0964DDA3ULL,
		0xFF23C210DA970C14ULL,
		0x45EEA33B929E346BULL,
		0x4ED5B8C8FC4A2E4DULL,
		0x7953C0A405A2EF53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE809216A643491BFULL,
		0x367B7D7CF7D6E568ULL,
		0xD1226E13C91BE3C5ULL,
		0xB456F28C9E0BD648ULL,
		0xD6C12C0909F8FF13ULL,
		0x72DCE1FE41B6CB59ULL,
		0x74D3BA79B2981E00ULL,
		0x5A46AAB429E376D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200021200014903DULL,
		0x12197060A5944120ULL,
		0x11026A0080086140ULL,
		0x8402700C0800D400ULL,
		0xD601000008900C10ULL,
		0x40CCA13A00960049ULL,
		0x44D1B848B0080E00ULL,
		0x584280A401A26652ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3978722C42FFE0BEULL,
		0x1740F783000DC60FULL,
		0x84459B2D28CC2321ULL,
		0x39F4D25345CE2B75ULL,
		0x4113FD3D6F1FFF08ULL,
		0x11D519AC6A96D488ULL,
		0xF2CC1B25D2C25C04ULL,
		0xA431E97D1CE33BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75059EEEDC76E337ULL,
		0xE91A92F5276C24CCULL,
		0x13F35BC830406402ULL,
		0xB84E964247E02C6FULL,
		0xD577660CCD225CEEULL,
		0xFABAFEEB5E1668FAULL,
		0xCD84D56A7778F2DBULL,
		0x4FACE47EB7ED490FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3100122C4076E036ULL,
		0x01009281000C040CULL,
		0x00411B0820402000ULL,
		0x3844924245C02865ULL,
		0x4113640C4D025C08ULL,
		0x109018A84A164088ULL,
		0xC084112052405000ULL,
		0x0420E07C14E10901ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD008D0CBE2ECCDA6ULL,
		0x6E6AEFBCE0B6B4B2ULL,
		0xDB238FD0F6814C89ULL,
		0xEFFF72C2E6497AC6ULL,
		0xCFB60444B11F87B1ULL,
		0x2232551FCEAB508BULL,
		0xEE6389857CA35F01ULL,
		0xACCEB60553090A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C9D88F1AB622E0ULL,
		0x5D8605989ECEF18FULL,
		0x3D444D85B1B55806ULL,
		0x7F0B78B0B6F11FDBULL,
		0xA7AE82E9B7D74083ULL,
		0xEE28691B20473A8AULL,
		0xEEB7A604D7BCD324ULL,
		0x2E2209848E7A80DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4008D08B02A400A0ULL,
		0x4C0205988086B082ULL,
		0x19000D80B0814800ULL,
		0x6F0B7080A6411AC2ULL,
		0x87A60040B1170081ULL,
		0x2220411B0003108AULL,
		0xEE23800454A05300ULL,
		0x2C0200040208009BULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC0BAD845A7A57E2ULL,
		0xA1BCE3D6C13EB783ULL,
		0xE8241F4C554EC3B8ULL,
		0x13FCD0098B01A145ULL,
		0xA7CE5F1E85D87F03ULL,
		0x28D87E37F8988DEDULL,
		0x09DD378E8E0BF4D5ULL,
		0xF34D4E4B581EA242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD703628601A69E9ULL,
		0xD88C371E5AA4AD25ULL,
		0x02189427D908242DULL,
		0x8CEB3B41FFBF2231ULL,
		0x97F63BAC0D9810D4ULL,
		0x3E87ECE442EC654CULL,
		0xA5883E1CB3881E08ULL,
		0x0FB6A5CE5C7AD0F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C002400401A41E0ULL,
		0x808C23164024A501ULL,
		0x0000140451080028ULL,
		0x00E810018B012001ULL,
		0x87C61B0C05981000ULL,
		0x28806C244088054CULL,
		0x0188360C82081400ULL,
		0x0304044A581A8040ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x977DD2F2C818068EULL,
		0xE134D0FC854A65EBULL,
		0x41061AC1C948967FULL,
		0xF3A44E0565F1EBD3ULL,
		0xEA0EE9AA02C74E61ULL,
		0xCD7D43F4D66B5AACULL,
		0x37D573EE6648BA41ULL,
		0xBCC0FD9F8332B17FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79FDA847ECD66115ULL,
		0xF8F78F8B7A9C6A47ULL,
		0x6B8F8FF2B28DC958ULL,
		0x58E90A2550BD5C31ULL,
		0xA60AFBE8A743F2B9ULL,
		0xD295313E04E7F0F2ULL,
		0xBFDB99AAFBD78176ULL,
		0x83AF9ACC7BA7F02FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x117D8042C8100004ULL,
		0xE034808800086043ULL,
		0x41060AC080088058ULL,
		0x50A00A0540B14811ULL,
		0xA20AE9A802434221ULL,
		0xC0150134046350A0ULL,
		0x37D111AA62408040ULL,
		0x8080988C0322B02FULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A15053648DE3A74ULL,
		0x7EC4F58F839AB121ULL,
		0x83D76979556E998BULL,
		0x788E7AB40A15C098ULL,
		0xFAB41D1CFD54E74EULL,
		0xFFBF83A059EEDD20ULL,
		0x2B67275435820494ULL,
		0x02581A1B0098E337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B70E6F4DA33257EULL,
		0xB9D9B450577B647EULL,
		0xF27C303292490B44ULL,
		0x22943800A60C8942ULL,
		0x8CE35FDF0E0B4EBEULL,
		0x2DE9B62F75C40481ULL,
		0x24ABA472299115B9ULL,
		0xDDEB6EA84E269066ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A10043448122074ULL,
		0x38C0B400031A2020ULL,
		0x8254203010480900ULL,
		0x2084380002048000ULL,
		0x88A01D1C0C00460EULL,
		0x2DA9822051C40400ULL,
		0x2023245021800490ULL,
		0x00480A0800008026ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AA5A1320428EA77ULL,
		0xFBD808770C23CD86ULL,
		0x4426F80DA7ADCF5BULL,
		0x8100378210C00E64ULL,
		0x400E347A23BA3A53ULL,
		0x640FD828D5113E7FULL,
		0xDFB900F62340790BULL,
		0xBED55A3E6478FB66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860A837B398F129DULL,
		0xE941906EF33EE139ULL,
		0xE001BAE2D849E07CULL,
		0x1CD7B54AEFC67443ULL,
		0xFDA2A4F33C9B98A8ULL,
		0x613A15BEAB53F7A9ULL,
		0x7860D5E413F5F15EULL,
		0xE9C702138B2364BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0200813200080215ULL,
		0xE94000660022C100ULL,
		0x4000B8008009C058ULL,
		0x0000350200C00440ULL,
		0x40022472209A1800ULL,
		0x600A102881113629ULL,
		0x582000E40340710AULL,
		0xA8C5021200206026ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3515845BED361609ULL,
		0x5466671F87204B31ULL,
		0x4E4B1AC8D3271D6EULL,
		0xA72814DA5AA6CB89ULL,
		0x63A2AE55B8E144A0ULL,
		0x234459A52A7A4D9CULL,
		0x4316D61C0618EB10ULL,
		0xC40FEDC947EA014CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE29BC68BD49C53BULL,
		0x8C8C4EA2215E7443ULL,
		0x49D0A68A49BDB80AULL,
		0x1FC4AC473F29BA20ULL,
		0x583431634DA7B41AULL,
		0x6F135FF8FB1808D5ULL,
		0x867A2C96DECAF6B7ULL,
		0x5E2695671CDF5D2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34018448AD000409ULL,
		0x0404460201004001ULL,
		0x484002884125180AULL,
		0x070004421A208A00ULL,
		0x4020204108A10400ULL,
		0x230059A02A180894ULL,
		0x021204140608E210ULL,
		0x4406854104CA010CULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E557BC6F26F1B2AULL,
		0x32EB3270246FF0E1ULL,
		0x57048F27539AE502ULL,
		0x6AC736E588D65D3EULL,
		0x66005C8803EFCE2DULL,
		0x3C8C30F22C598C5DULL,
		0xB5604EE990D1E00CULL,
		0x948657F1D1C6633EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD346715675B4B513ULL,
		0x6735456A92CFF6BEULL,
		0x7D3D4A4C81053F14ULL,
		0x1075F2A6DFC01D2FULL,
		0x252CB37D24FA088FULL,
		0x5EA069C01225FB6AULL,
		0xE7EC5DD74B7A4B68ULL,
		0x419E3EC6F9E9DDC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5244714670241102ULL,
		0x22210060004FF0A0ULL,
		0x55040A0401002500ULL,
		0x004532A488C01D2EULL,
		0x2400100800EA080DULL,
		0x1C8020C000018848ULL,
		0xA5604CC100504008ULL,
		0x008616C0D1C04104ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39908F39F38241A0ULL,
		0xD417045198AEBFB0ULL,
		0x604975F4DBB432CDULL,
		0xFBC096BDB071533FULL,
		0x4297A59F24ADA872ULL,
		0xFA3FA0DD8152EE2DULL,
		0x1C0FE22C7B82C43FULL,
		0xC7F674D0E2883B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532B342C04C2BD30ULL,
		0x68F862F6CEEC0A5CULL,
		0x4DCC4CEFC565C4C7ULL,
		0x299DCFBDC8C824F0ULL,
		0x1A71CA595AA5089CULL,
		0x33E3A76148761414ULL,
		0x2239CC583DD3BD5EULL,
		0xF628D83730A2C93FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1100042800820120ULL,
		0x4010005088AC0A10ULL,
		0x404844E4C12400C5ULL,
		0x298086BD80400030ULL,
		0x0211801900A50810ULL,
		0x3223A04100520404ULL,
		0x0009C0083982841EULL,
		0xC620501020800924ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEDE935241F233E1ULL,
		0x64138ECEE3157905ULL,
		0x460D4425A836F838ULL,
		0x0E13030C7D6D6D9AULL,
		0x072057624088AD60ULL,
		0xA5FE018B6D5B70BBULL,
		0x6442F2325206A9BDULL,
		0xAE519FF7EB84E51EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3E8BEA628E28743ULL,
		0x205C99050DC338EAULL,
		0xBE20102370861722ULL,
		0xFAE676367D0AA15EULL,
		0x85F9AFC9A9F2C2EEULL,
		0xE155C58291318BA1ULL,
		0x700483217D717179ULL,
		0x75461D3BFC84F464ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2C8920200E20341ULL,
		0x2010880401013800ULL,
		0x0600002120061020ULL,
		0x0A0202047D08211AULL,
		0x0520074000808060ULL,
		0xA1540182011100A1ULL,
		0x6000822050002139ULL,
		0x24401D33E884E404ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5E0D316AEF30B50ULL,
		0x8B58066BF70B4A3BULL,
		0xE5B25A2196C31924ULL,
		0x3E210196C90D554CULL,
		0xF48DE04E72372601ULL,
		0x7A45F16712849E6EULL,
		0x1C63D628978EBED2ULL,
		0x373B6E9895E7AF61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0F3F35817CAC4FEULL,
		0x0018A91F46C03F19ULL,
		0x39B1FC74C674F7E4ULL,
		0xCC82087809FD42F7ULL,
		0x3715DE39A2CA7C73ULL,
		0x66988E273626AF33ULL,
		0x62A62E65C8214B10ULL,
		0x22945417DFBCF64CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90E0D31006C20050ULL,
		0x0018000B46000A19ULL,
		0x21B0582086401124ULL,
		0x0C000010090D4044ULL,
		0x3405C00822022401ULL,
		0x6200802712048E22ULL,
		0x0022062080000A10ULL,
		0x2210441095A4A640ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB8B162335B75A12ULL,
		0x4A05543FB36749D1ULL,
		0x6B78CE664DF1963AULL,
		0x464EC879BBE3C836ULL,
		0x2C9C659CEC35EFC7ULL,
		0xB0EB0697F8BFF4B1ULL,
		0x4C41A4D95D96A45FULL,
		0x568A30984417EE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0232C31D4144A22ULL,
		0x862F8BCFBE1EF005ULL,
		0x869B50AFB7319FC5ULL,
		0xF71EAE95D4F39AD3ULL,
		0x2F08DA3F3809328BULL,
		0x99F44D4E37B85205ULL,
		0x6E20CF642BD233C2ULL,
		0x07CDDC1020282FF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE003042114144A02ULL,
		0x0205000FB2064001ULL,
		0x0218402605319600ULL,
		0x460E881190E38812ULL,
		0x2C08401C28012283ULL,
		0x90E0040630B85001ULL,
		0x4C00844009922042ULL,
		0x0688101000002E58ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE116E67079DB9710ULL,
		0x5545B9DEFDAE7BB8ULL,
		0xD559B02059B46B16ULL,
		0x208CC4738CB185C7ULL,
		0xDE84E77EEA490C2FULL,
		0xF31BE45A29FD35E0ULL,
		0x67E8AC598A469B4DULL,
		0x448F7E58233C12F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2352238B211FC4ULL,
		0x3E0074C27A6C5DBEULL,
		0xB4C93BBCB5BE25B1ULL,
		0x289E486D22D370E7ULL,
		0xF1517705109EF1FCULL,
		0xC2D143FE4F10BA6BULL,
		0x20F90E65872DA188ULL,
		0x3D4D279B438C5D73ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0002422009011700ULL,
		0x140030C2782C59B8ULL,
		0x9449302011B42110ULL,
		0x208C4061009100C7ULL,
		0xD00067040008002CULL,
		0xC211405A09103060ULL,
		0x20E80C4182048108ULL,
		0x040D2618030C1070ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x250E8E12CE88A734ULL,
		0xDFC723A3523AF320ULL,
		0x17F47BD833835375ULL,
		0x86BDFB32C61B72A3ULL,
		0x8B4C96E6710D3277ULL,
		0x26FFD7CC0A09195AULL,
		0xDA426162C097FF49ULL,
		0x6F478A28CB3F4B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x721897EDB2E5B76EULL,
		0x201B2C1CB2ADFAF3ULL,
		0x429BABA511D52D3AULL,
		0x1FC42543D218C1F6ULL,
		0x90CA2864B1408F83ULL,
		0x4018035C9BA1E729ULL,
		0x96E4DB26B6C0DA6BULL,
		0xF0AB84DB2A8B396BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200886008280A724ULL,
		0x000320001228F220ULL,
		0x02902B8011810130ULL,
		0x06842102C21840A2ULL,
		0x8048006431000203ULL,
		0x0018034C0A010108ULL,
		0x924041228080DA49ULL,
		0x600380080A0B0940ULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB24B22FA83166356ULL,
		0x3D7D905A9DFDB65EULL,
		0x0493997E8D53FD3AULL,
		0xED0CCE29D1B304BFULL,
		0x86ED052C87D3813EULL,
		0x32E1A0D00D26E975ULL,
		0xB7E0D7F4D086FAD6ULL,
		0xCE4FA4F64195236EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A777BAC70F937CBULL,
		0xED6D41EA8F8082A0ULL,
		0x737720586E6E4CDCULL,
		0x364E2602EFD35941ULL,
		0xAF895F8B717C5D07ULL,
		0x64C80DC4C0819EEEULL,
		0xA18C2C0C670BE582ULL,
		0x10E74EC4030B906AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x224322A800102342ULL,
		0x2D6D004A8D808200ULL,
		0x001300580C424C18ULL,
		0x240C0600C1930001ULL,
		0x8689050801500106ULL,
		0x20C000C000008864ULL,
		0xA18004044002E082ULL,
		0x004704C40101006AULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x303B3B31ADD4007CULL,
		0x8C8A2CE6B70A03B3ULL,
		0x0C7F14F1B6300674ULL,
		0x0C71574B416ADEE1ULL,
		0xBC5C3C758269DA89ULL,
		0x9FA8CAC2E2FC75B3ULL,
		0xDC6824DD401CB1D8ULL,
		0x871E50A8A8592317ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B51FE3A4D9E9433ULL,
		0x86372F07D35C7919ULL,
		0xE5FB1EFF3C1125E1ULL,
		0xF80A6FA5DEC67FC5ULL,
		0x35AF39E1FC851DE8ULL,
		0xBA1929FA31DFCDBAULL,
		0x7C32E3278BB2AEEFULL,
		0xC88B4E8F60BEA372ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20113A300D940030ULL,
		0x84022C0693080111ULL,
		0x047B14F134100460ULL,
		0x0800470140425EC1ULL,
		0x340C386180011888ULL,
		0x9A0808C220DC45B2ULL,
		0x5C2020050010A0C8ULL,
		0x800A408820182312ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB40DF5603EBD992BULL,
		0x05DFE26A77F4F5EFULL,
		0xC1F56F93FCB76462ULL,
		0x9322E779B78D997CULL,
		0xE68CC819D4B0B7E0ULL,
		0xE411E323CC9266B0ULL,
		0x0306504C323CFCDFULL,
		0x1B50F03AC6709BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F7C50D7CFCE04AULL,
		0xAB0EC482E7E433E5ULL,
		0x2AF1A2C8A805FF30ULL,
		0x725A59304578338BULL,
		0x3EBA2A381313F75BULL,
		0x1620A1B9CBB99572ULL,
		0x6B52A2A3DC8CD4EEULL,
		0x7313630A898F28C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3405C5003CBC800AULL,
		0x010EC00267E431E5ULL,
		0x00F12280A8056420ULL,
		0x1202413005081108ULL,
		0x268808181010B740ULL,
		0x0400A121C8900430ULL,
		0x03020000100CD4CEULL,
		0x1310600A800008C2ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x178615D34F9B17DCULL,
		0x90303DE4069B7FD0ULL,
		0x447A0F40555F793AULL,
		0x7804BBB92C6C253DULL,
		0x660277BB4E0B7F1FULL,
		0x7B6D2889C0E52680ULL,
		0x1A06D2FDED7586BBULL,
		0x75C1994E31E00035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB8A7FD13D04E6FULL,
		0xDF7B76870718F5CBULL,
		0xD2294838418CB9B4ULL,
		0x56BEC848D90B0692ULL,
		0x99B8AE62C4DC0FA1ULL,
		0x32D7366586BC430EULL,
		0xEBD56498576B29F3ULL,
		0xD6CF727C6975D6E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028005D10390064CULL,
		0x90303484061875C0ULL,
		0x40280800410C3930ULL,
		0x5004880808080410ULL,
		0x0000262244080F01ULL,
		0x3245200180A40200ULL,
		0x0A044098456100B3ULL,
		0x54C1104C21600021ULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4D0724369217DB1ULL,
		0x7A64104B0BD6BA7BULL,
		0x742D61F767D89892ULL,
		0x7AD25A0CC093EA90ULL,
		0x2781408F3CBD44A7ULL,
		0x23BC8FB0602CF84CULL,
		0x2C66DF08C008B65CULL,
		0xEB9FA411CD52F58AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB04B172704853AAULL,
		0xB4EF9FB0867DFEA7ULL,
		0xFB7D2769107E6AAAULL,
		0x3A43F8C80ADDB491ULL,
		0xBF926C245984ED84ULL,
		0x7DF95E98FAD6318EULL,
		0x69871E57C3CA9CB8ULL,
		0x0D9E528840447D13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0003042600051A0ULL,
		0x306410000254BA23ULL,
		0x702D216100580882ULL,
		0x3A4258080091A090ULL,
		0x2780400418844484ULL,
		0x21B80E906004300CULL,
		0x28061E00C0089418ULL,
		0x099E000040407502ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE5C7D6ACEB9E7BFULL,
		0xBD860E064A184F94ULL,
		0x69FC03805141D388ULL,
		0xC1FC9FBB3EF888BDULL,
		0x644A4A2A181F43EDULL,
		0x17E3D6DFC65F266AULL,
		0x9B795ADD515C666EULL,
		0xE2915938781C6480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x310BF473FA02A99AULL,
		0xA70944C78B4B0040ULL,
		0x40404FB6D72EB57EULL,
		0xC0E8DB4327891537ULL,
		0x403B260BE4E6A54BULL,
		0x5ECF2E7B8D5ABBB0ULL,
		0x4FC3245B214A3548ULL,
		0x53712343727A66E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00087462CA00A19AULL,
		0xA50004060A080000ULL,
		0x4040038051009108ULL,
		0xC0E89B0326880035ULL,
		0x400A020A00060149ULL,
		0x16C3065B845A2220ULL,
		0x0B41005901482448ULL,
		0x4211010070186480ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16F2EE2EEC3AB542ULL,
		0x99FE82606C91BE3CULL,
		0x9CAD9B8E4F687611ULL,
		0xBEF12E7AAFC98281ULL,
		0x9EDF26ED94CB86FFULL,
		0x5F0DFA7C9FD67943ULL,
		0x82DAB4148B711065ULL,
		0x1FC4D753AE3CCB76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD634DAC075562883ULL,
		0x8A3ABCC4EC140C26ULL,
		0x170BF279C9B0F4C2ULL,
		0x3B8D8FD70AFC3A32ULL,
		0x7752E43DD9E8DEEDULL,
		0xE20EC64D55B4889FULL,
		0x3C3A74A17A4EEE8BULL,
		0x019D0193E69029E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1630CA0064122002ULL,
		0x883A80406C100C24ULL,
		0x1409920849207400ULL,
		0x3A810E520AC80200ULL,
		0x1652242D90C886EDULL,
		0x420CC24C15940803ULL,
		0x001A34000A400001ULL,
		0x01840113A6100964ULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFCEB76D0F30E144ULL,
		0xF113286B44C4BCFCULL,
		0x96D4146777CC07F1ULL,
		0xF66F08CEF4244D35ULL,
		0xF3E344EF873179DEULL,
		0xAA5DE9F81C24DF6BULL,
		0xFCAAF5F4FAA349E2ULL,
		0xE8B15C2CA0798470ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x650CCDE7443E05C0ULL,
		0xFA19B38F47107A74ULL,
		0xFE091E4085E3E6E2ULL,
		0x9F12B7B03DDE223DULL,
		0xA6DF42278CB6E8D7ULL,
		0xF60337FAAA2A1B5BULL,
		0x93A0340DF5D45AE9ULL,
		0x70FF81488742A86AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x450C856504300140ULL,
		0xF011200B44003874ULL,
		0x9600144005C006E0ULL,
		0x9602008034040035ULL,
		0xA2C34027843068D6ULL,
		0xA20121F808201B4BULL,
		0x90A03404F08048E0ULL,
		0x60B1000880408060ULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x514AB83C8C3B74DBULL,
		0xF096F2926423EB62ULL,
		0xF72AE8D427377CE2ULL,
		0x3E17946DE8BE505FULL,
		0x2FFE77366185E1AEULL,
		0xF64A333D580417FDULL,
		0x74084A7DC7D574A8ULL,
		0x43BF5E3DA91C69F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03DFF2A379FF9F6EULL,
		0x700BE0000105DC7FULL,
		0x866249889B60E776ULL,
		0x1D4B6B96455BCAE3ULL,
		0xDA2C84E458CBE52EULL,
		0xD17AC6F73E5B3BEDULL,
		0x4682D474D99C4C69ULL,
		0x794BB7418FBF914DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x014AB020083B144AULL,
		0x7002E0000001C862ULL,
		0x8622488003206462ULL,
		0x1C030004401A4043ULL,
		0x0A2C04244081E12EULL,
		0xD04A0235180013EDULL,
		0x44004074C1944428ULL,
		0x410B1601891C0145ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE04754752277F6E3ULL,
		0x41A728D09B2DEF3DULL,
		0x346291CC98E185DAULL,
		0x792B05B8856BBCC1ULL,
		0xFDB9F69D8D000D1BULL,
		0x07991C2BC80C37BFULL,
		0xB582BE171053EEC9ULL,
		0x7E161E7D6F353539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B74BD9CB360A14CULL,
		0xA04A7046294D8422ULL,
		0x0E5C188C7D20D737ULL,
		0x695E52E25ABCCF65ULL,
		0x3AF6E84CAA87DF4DULL,
		0x7465977C4C7EB95EULL,
		0x0946654C06AAF3BAULL,
		0x71F6DF805327BCFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x204414142260A040ULL,
		0x00022040090D8420ULL,
		0x0440108C18208512ULL,
		0x690A00A000288C41ULL,
		0x38B0E00C88000D09ULL,
		0x04011428480C311EULL,
		0x010224040002E288ULL,
		0x70161E0043253438ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9AFD57B94D3179ULL,
		0x1D5F344FF89C857AULL,
		0x829D1EF1AB9B35C2ULL,
		0x9A5A742CDC533FEEULL,
		0xC227BB1ED3F88D13ULL,
		0x987B4564A358F3CDULL,
		0x5D3F19C1EA6E0345ULL,
		0x594EA34B14E13E4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF732F746C71878B7ULL,
		0xF5957DEFBA9A64D1ULL,
		0x947FC138EE877E39ULL,
		0x89F49FB49F14C8B4ULL,
		0xD3DDED7A0E2D840CULL,
		0x9E9FA0556ECE9B48ULL,
		0x4923C89C996071D8ULL,
		0x965BAA40ED5A2ECAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9412F54681083031ULL,
		0x1515344FB8980450ULL,
		0x801D0030AA833400ULL,
		0x885014249C1008A4ULL,
		0xC205A91A02288400ULL,
		0x981B004422489348ULL,
		0x4923088088600140ULL,
		0x104AA24004402E4AULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3825D1CEFB542D84ULL,
		0xB0EB6C3D3A0891D2ULL,
		0x324C2A0D301F7BC8ULL,
		0x76D3E3DE22F2E291ULL,
		0x41028C4304ADA193ULL,
		0xB688017231F1323CULL,
		0xC7EF9A0E59219290ULL,
		0xA88F3E96C395330BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF46B07B12F148B92ULL,
		0x19A7418B74E26E04ULL,
		0xE50315A1E0EF67A5ULL,
		0xACBF019F36EA30F0ULL,
		0x43A7108791296BE2ULL,
		0x53C7BFDFFA636833ULL,
		0x1DD62D95108530CDULL,
		0x23DBBC81563C8A8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302101802B140980ULL,
		0x10A3400930000000ULL,
		0x20000001200F6380ULL,
		0x2493019E22E22090ULL,
		0x4102000300292182ULL,
		0x1280015230612030ULL,
		0x05C6080410011080ULL,
		0x208B3C8042140208ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A747095725C7C99ULL,
		0x6A5422F61F75F5FBULL,
		0xDC431D3EEDE91278ULL,
		0xA8F197D464A4D55CULL,
		0xF3B7516E63AF4B23ULL,
		0x91D3605CE7E83920ULL,
		0x0FEEBD8B91FD31C3ULL,
		0x3D5877BE18B678B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x257A26ED0C822883ULL,
		0xCBD17155C1812B50ULL,
		0x1A7DAE0146DA9D74ULL,
		0x30898B3580E5CE16ULL,
		0xCAD59D0506583CB4ULL,
		0x932583EE961F501FULL,
		0x4F78D15F9C28B9DEULL,
		0x2460A8F46BB7FB04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0070208500002881ULL,
		0x4A50205401012150ULL,
		0x18410C0044C81070ULL,
		0x2081831400A4C414ULL,
		0xC295110402080820ULL,
		0x9101004C86081000ULL,
		0x0F68910B902831C2ULL,
		0x244020B408B67804ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFB49DD0A906ABA0ULL,
		0xC4AF458D1A0F43C6ULL,
		0x411EB5F063B3EC76ULL,
		0x012EFC51B10FAA88ULL,
		0x781EC50CBCC31647ULL,
		0xBA06195E7F24EC72ULL,
		0x1C6FC5F29FA7C8ECULL,
		0xBFBDA6BFDDFF1099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF3A06738FB857EBULL,
		0x5F8C282554420818ULL,
		0xE3F90DC56DECEE0CULL,
		0x054DB65819762838ULL,
		0xF86488A19CA4468FULL,
		0x926961EB32E3836CULL,
		0xE81612FD7F23A83FULL,
		0x678DB7FBA37C9DC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF300450890003A0ULL,
		0x448C000510020000ULL,
		0x411805C061A0EC04ULL,
		0x010CB45011062808ULL,
		0x780480009C800607ULL,
		0x9200014A32208060ULL,
		0x080600F01F23882CULL,
		0x278DA6BB817C1081ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE78D6C917BC919E7ULL,
		0x55CF68B4DB5CEE0EULL,
		0xACD8BD1A3090133DULL,
		0x98819E78F30E6BC8ULL,
		0xC08F635B06F7C74DULL,
		0xBAA772678510859DULL,
		0x48071861D42D4FBEULL,
		0x0F60F5553E54F364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC64498562CD35F91ULL,
		0xFD1FBA9B1FFF0FD3ULL,
		0xD20123595FFCD541ULL,
		0xFA5A2264163FFD8BULL,
		0x7BC0DF0C066EF6C5ULL,
		0x748D100E31CD6034ULL,
		0xCE28E52D3B045840ULL,
		0x27CC815BB553C5DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC604081028C11981ULL,
		0x550F28901B5C0E02ULL,
		0x8000211810901101ULL,
		0x98000260120E6988ULL,
		0x408043080666C645ULL,
		0x3085100601000014ULL,
		0x4800002110044800ULL,
		0x074081513450C144ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97CA804C09EE93F9ULL,
		0x14AA37BEAD226F7FULL,
		0x2E9E768A8CA70D1BULL,
		0x1697F50A581EFD37ULL,
		0x28BA3BA1F2912321ULL,
		0xEEA1897C3AEA3E79ULL,
		0x9E6532874941BC40ULL,
		0x1715E9EEE8B6F97EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x732DB8C76A832B68ULL,
		0x81BECF7D77A9996FULL,
		0xE15DE367FA10597FULL,
		0x3DC8729A13CBAF36ULL,
		0xEDC5692AC70FCE25ULL,
		0x33B2DE282EB93858ULL,
		0xE306CDB6CC3EF0B1ULL,
		0xCF5FBD167A3A080CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1308804408820368ULL,
		0x00AA073C2520096FULL,
		0x201C62028800091BULL,
		0x1480700A100AAD36ULL,
		0x28802920C2010221ULL,
		0x22A088282AA83858ULL,
		0x820400864800B000ULL,
		0x0715A9066832080CULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2F5950B3EDDA598ULL,
		0x0D69A25815719C83ULL,
		0x89FB6BCCA1ABB902ULL,
		0xABAB66613DF7AB21ULL,
		0x7C332A03BF7AF2BDULL,
		0x6B91197A7E6F0FE9ULL,
		0x068A2C0F24CC3FEFULL,
		0x0ED2EA5F10B51B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6089111B6172DA42ULL,
		0x536EDF2565EE4315ULL,
		0x217D44C95BCCE3EEULL,
		0x3BE5C92A463088E4ULL,
		0x672400CC6DF3EEB3ULL,
		0x6AA0FA597D80CBC3ULL,
		0x9F9A07C84541A94CULL,
		0x50EBB079F4E4E941ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6081110B20508000ULL,
		0x0168820005600001ULL,
		0x017940C80188A102ULL,
		0x2BA1402004308820ULL,
		0x642000002D72E2B1ULL,
		0x6A8018587C000BC1ULL,
		0x068A04080440294CULL,
		0x00C2A05910A40901ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACEA8C4CC054241DULL,
		0xD37207FB0EDDD121ULL,
		0x742E28611CC0D0CCULL,
		0x952A7123493C3C7EULL,
		0x176AAF5CFC0434E9ULL,
		0x39DEE6814071CEB6ULL,
		0x4520856AC6A13C00ULL,
		0xAB608E35A1C7FD3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C2152BFF1B7312ULL,
		0x1C8C0C2F7AA77C36ULL,
		0x6F829A22196486A1ULL,
		0xE8193CC9C77AD635ULL,
		0xE0850D5FB368B552ULL,
		0x14067E2176F6693AULL,
		0x3B07AEE170F602E8ULL,
		0xCC646E568B166E4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20C20408C0102010ULL,
		0x1000042B0A855020ULL,
		0x6402082018408080ULL,
		0x8008300141381434ULL,
		0x00000D5CB0003440ULL,
		0x1006660140704832ULL,
		0x0100846040A00000ULL,
		0x88600E1481066C0AULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF56D601509C27831ULL,
		0xBC740DA3C09E0799ULL,
		0x9438E7FE63306DCCULL,
		0x1E845E433E747E3FULL,
		0xC5A6131ADB7D14E0ULL,
		0x72DC99A74E7CD199ULL,
		0x3419718ECC2218E6ULL,
		0x12A73AF3518B499FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79D6D285064348C4ULL,
		0xADFD94EBE4376658ULL,
		0x1DF969D9CD0DCAF3ULL,
		0x68F10AF1E3714279ULL,
		0x8DD0E7D2799045DFULL,
		0xF046184689B90E6EULL,
		0x0C997CC19062730FULL,
		0x25B8A5A9F07FD6C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7144400500424800ULL,
		0xAC7404A3C0160618ULL,
		0x143861D8410048C0ULL,
		0x08800A4122704239ULL,
		0x85800312591004C0ULL,
		0x7044180608380008ULL,
		0x0419708080221006ULL,
		0x00A020A1500B4084ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x555E75788CA034BDULL,
		0x71724C7C3E122D7EULL,
		0x4245C40F92C3CFF9ULL,
		0x2D9AF204ACC22E8AULL,
		0xC1644C8C0DE13AFDULL,
		0xF30C956FE3B9D82BULL,
		0xC305F9BF65920E68ULL,
		0xF78A4D57C29F61FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6570C715CA4913D6ULL,
		0xC6D8ECA2E94A3931ULL,
		0x39B499F411422607ULL,
		0x04EB6D1D4B2F735FULL,
		0x21564B2D2AF9E0E2ULL,
		0x185394C47BDB57D5ULL,
		0x26125010DB1EE571ULL,
		0x037B56B08BB33739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4550451088001094ULL,
		0x40504C2028022930ULL,
		0x0004800410420601ULL,
		0x048A60040802220AULL,
		0x0144480C08E120E0ULL,
		0x1000944463995001ULL,
		0x0200501041120460ULL,
		0x030A441082932138ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC5FD25E71C70A28ULL,
		0xB3F8F77C4EE8034EULL,
		0x0FCC2FE588AC0F14ULL,
		0x8986771EF72618E7ULL,
		0x851C416BBF45DD5BULL,
		0xE06B3A043B37C52CULL,
		0x97A6E34FDA1E0332ULL,
		0x4AC85D3AABCAA513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E41CE75330F533ULL,
		0x209E15DE024BFF20ULL,
		0x66296F1F07F4CE37ULL,
		0x5D29EEBD55F9B553ULL,
		0x8B1B6B257808AF41ULL,
		0x08EF66B2C8346EDBULL,
		0xEF42858DC0A60BFBULL,
		0xF0499D4FD9B8E721ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4044104651000020ULL,
		0x2098155C02480300ULL,
		0x06082F0500A40E14ULL,
		0x0900661C55201043ULL,
		0x8118412138008D41ULL,
		0x006B220008344408ULL,
		0x8702810DC0060332ULL,
		0x40481D0A8988A501ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F2614FF0EFFE0B0ULL,
		0x48754C73F16C3586ULL,
		0x38A8EFC9014F53E8ULL,
		0x1EFA99830F3B1F1AULL,
		0x2BEF391F5060EDB8ULL,
		0x86D481846A887C44ULL,
		0xD6F0B98BA27C2D32ULL,
		0xE0FD7D81EAC60420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD8AE8E486BCC8BULL,
		0x294B829025226B0BULL,
		0x9A7CF13C254AA3ABULL,
		0x162A621BD01A9C42ULL,
		0x2E446916F39CEA2AULL,
		0x8C4CB8655939CE6FULL,
		0xC1971193FCFAD7C4ULL,
		0x9BCAA7C0E86475C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B00048E086BC080ULL,
		0x0841001021202102ULL,
		0x1828E108014A03A8ULL,
		0x162A0003001A1C02ULL,
		0x2A4429165000E828ULL,
		0x8444800448084C44ULL,
		0xC0901183A0780500ULL,
		0x80C82580E8440400ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1AEDCEE51CAC7E4ULL,
		0x145FC704A0E1E7F0ULL,
		0xF52CA81FD79D5963ULL,
		0x68FB88035D6E6E9CULL,
		0x7E409727B3A1F3C7ULL,
		0x7AC62192AB247177ULL,
		0x54187D9C347B8823ULL,
		0xE9481ADFF5C341C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B3A48DD66A241DULL,
		0x3F38643927379112ULL,
		0x39DC9461CFDF8D54ULL,
		0x6F351A71FF373B4AULL,
		0x0F02FA510A9AC24BULL,
		0x2F718600EDA51C61ULL,
		0xD0CDE5EAFE731AF9ULL,
		0x13A8E6D9A6A8E1B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A2848C504A0404ULL,
		0x1418440020218110ULL,
		0x310C8001C79D0940ULL,
		0x683108015D262A08ULL,
		0x0E0092010280C243ULL,
		0x2A400000A9241061ULL,
		0x5008658834730821ULL,
		0x010802D9A4804180ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E089F0F38B1087BULL,
		0x50C36A7D89667874ULL,
		0x15DFE589868F1ECCULL,
		0x73256223F6727EE4ULL,
		0xF799A0AAB993F799ULL,
		0xF4C2834E08E13292ULL,
		0xA14526343A4D78A3ULL,
		0xB560F438849005D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2012BF9E0532A9D3ULL,
		0xD4203BED87012E8BULL,
		0x06289BBE1FB08DABULL,
		0x62B82877BBA3EB4AULL,
		0x5BD81B3448F683DCULL,
		0x0492A2443CD92BC3ULL,
		0x80ECA27730B35B61ULL,
		0x31DC2AFE47B003E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00009F0E00300853ULL,
		0x50002A6D81002800ULL,
		0x0408818806800C88ULL,
		0x62202023B2226A40ULL,
		0x5398002008928398ULL,
		0x0482824408C12282ULL,
		0x8044223430015821ULL,
		0x31402038049001C4ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2EC435F28C9F44CULL,
		0x52DC3AA538CBA6BDULL,
		0x2E45DEDD4FBC808BULL,
		0x2A8E2CA4B178251CULL,
		0x3B1E9EE2F9D88FB5ULL,
		0x0F0B4E8F17B788F7ULL,
		0xC8099AA9A2640D84ULL,
		0x094614F815E89CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D02694BF9319050ULL,
		0x28B7D1156CED03ECULL,
		0x53A35536BE537370ULL,
		0x871CAE03A4F6D19AULL,
		0x726FF88706A430BEULL,
		0xD3C2B8244709975EULL,
		0x781C834A5EEC694DULL,
		0xAC133ADCB4FC5698ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000414B28019040ULL,
		0x0094100528C902ACULL,
		0x020154140E100000ULL,
		0x020C2C00A0700118ULL,
		0x320E9882008000B4ULL,
		0x0302080407018056ULL,
		0x4808820802640904ULL,
		0x080210D814E81498ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864FD8D5BE2C5FF3ULL,
		0xB5D01A2F60E392B5ULL,
		0xF2E245651EB9C9FAULL,
		0x4FA5345000B1FE27ULL,
		0xC99DE37F822B8D71ULL,
		0xF1164477AECE4BFCULL,
		0x8D1835F4F1381861ULL,
		0x8E0B8B034C9E9D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E7E948FA398606ULL,
		0xE810C43CC2AD793EULL,
		0xBA3A0CEB971CEB6CULL,
		0x1A76AAC29AF4684AULL,
		0x44EABC0DD4C55AF2ULL,
		0x099B198816BF7B34ULL,
		0x1CB347100A6DA4ECULL,
		0x4B342AB12AE46E3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8047C840BA280602ULL,
		0xA010002C40A11034ULL,
		0xB22204611618C968ULL,
		0x0A24204000B06802ULL,
		0x4088A00D80010870ULL,
		0x01120000068E4B34ULL,
		0x0C10051000280060ULL,
		0x0A000A0108840C31ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1B278AFD6A84CABULL,
		0x15A68D6252D8329DULL,
		0x364F326FB307FBF3ULL,
		0x676883184B91CF5EULL,
		0x3C4638D2097EF275ULL,
		0xC0E5A0F9595EA1D2ULL,
		0xE47634F14F15CE4EULL,
		0x519D8766B260AD87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5FE67806C37B7BCULL,
		0x25E525BCB4452B3AULL,
		0x094D342ECB6E80FBULL,
		0x391351D38E721162ULL,
		0xE3D0F898771DC6DCULL,
		0xE47038657DA4EB39ULL,
		0x3B84887517C41666ULL,
		0x25E8C16BB4130CD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1B26080442004A8ULL,
		0x05A4052010402218ULL,
		0x004D302E830680F3ULL,
		0x210001100A100142ULL,
		0x20403890011CC254ULL,
		0xC06020615904A110ULL,
		0x2004007107040646ULL,
		0x01888162B0000C84ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05154D48ED02F4CFULL,
		0x04FA902A5C45E7BBULL,
		0x63CD4E22BBBCFA8EULL,
		0x27393D8C32D4820DULL,
		0xD09F5DA1DE921F33ULL,
		0xBF828BA400D619BEULL,
		0xA2D71E4094E55427ULL,
		0x76B6D6B29A7442B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C236D5C6BE893EBULL,
		0xC2F5D75C4CCBE368ULL,
		0x5A151546498431F0ULL,
		0x6AFAAD1A0207A88CULL,
		0x3F51074EA46471A8ULL,
		0xB1E74AD426E7FED9ULL,
		0x0101C40772CDD666ULL,
		0x09E59D63A5DEDE17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04014D48690090CBULL,
		0x00F090084C41E328ULL,
		0x4205040209843080ULL,
		0x22382D080204800CULL,
		0x1011050084001120ULL,
		0xB1820A8400C61898ULL,
		0x0001040010C55426ULL,
		0x00A4942280544211ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30DAEBAF9387A3DFULL,
		0x3006E6592B29805FULL,
		0xA25E81D0C38137DEULL,
		0xB800147C2FE407BCULL,
		0x81C29A59E9586E0BULL,
		0x1B6216B657482FB2ULL,
		0xC810707ADCBCC668ULL,
		0xB0B0CB3EFD18FA77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891785AF20482B17ULL,
		0x62436F70E51F39ACULL,
		0x4551F91AA2E10AE3ULL,
		0xA59CA073E82843B1ULL,
		0x78B60CFE7561A78BULL,
		0xED220DAB175A68A8ULL,
		0xFE944DFEE0EFBB8EULL,
		0xF8CA204B756C2F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001281AF00002317ULL,
		0x200266502109000CULL,
		0x00508110828102C2ULL,
		0xA0000070282003B0ULL,
		0x008208586140260BULL,
		0x092204A2174828A0ULL,
		0xC810407AC0AC8208ULL,
		0xB080000A75082A10ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD86B57F12B1D02D1ULL,
		0xB735A7A4C0788806ULL,
		0x60F5CB909F497353ULL,
		0x1CC83D09324FE79AULL,
		0x177CCC31835C0FF2ULL,
		0xEE4099B77665A69FULL,
		0x4E48B1F7D06EEA62ULL,
		0xDF9F75CF803FF6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB25EF1C3FB091CULL,
		0x5AB314F0A7F401B5ULL,
		0x3F77FAB67D25F40AULL,
		0x80289B1F67F177D6ULL,
		0xF26AE419549FDA73ULL,
		0x66CD65783E4B365AULL,
		0xD493D315B26E73CDULL,
		0x62F96523C7ED77E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x082256F103190010ULL,
		0x123104A080700004ULL,
		0x2075CA901D017002ULL,
		0x0008190922416792ULL,
		0x1268C411001C0A72ULL,
		0x664001303641261AULL,
		0x44009115906E6240ULL,
		0x42996503802D76C2ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2422D9E1EB96AEF9ULL,
		0x53C10122939D9358ULL,
		0xB6CA7C679DD6642BULL,
		0x76D0A0D8B33B5C27ULL,
		0x354EC7DF092A4F32ULL,
		0x030B92FF39211A92ULL,
		0xD9F16918DA8F7385ULL,
		0xFEF334646CA7C275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C25E91869937F6BULL,
		0xFDC47DC9ABDC7254ULL,
		0xE24CBEC7B149AD07ULL,
		0xFD6D9C096BB3F3BCULL,
		0x745957946153ECA1ULL,
		0x05EDB3BF28C21881ULL,
		0x99FD2FB49EA0A2D0ULL,
		0xD2DBC35981780424ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0420C90069922E69ULL,
		0x51C00100839C1250ULL,
		0xA2483C4791402403ULL,
		0x7440800823335024ULL,
		0x3448479401024C20ULL,
		0x010992BF28001880ULL,
		0x99F129109A802280ULL,
		0xD2D3004000200024ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8C399ED74330AD5ULL,
		0x11C6E509E87012ADULL,
		0x977CC3750D582FCBULL,
		0xA30A7472DE35A0C7ULL,
		0xA72E5655C1577CAEULL,
		0x1F3CC033F88E8433ULL,
		0x5CDBB56D49D07A68ULL,
		0x6B8CDB300E13A932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BC96747DBC4989ULL,
		0xB087563C56A1F2B9ULL,
		0x0298430B3DE8F9E6ULL,
		0x19B35625624AB017ULL,
		0x1E76CBD77C157D93ULL,
		0x6A6FCC5236F2FD25ULL,
		0xF87356C5E53E9E6BULL,
		0x5DD8E1D821DB559FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA880906474300881ULL,
		0x10864408402012A9ULL,
		0x021843010D4829C2ULL,
		0x010254204200A007ULL,
		0x0626425540157C82ULL,
		0x0A2CC01230828421ULL,
		0x5853144541101A68ULL,
		0x4988C11000130112ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49A57D1F4147D605ULL,
		0xEC0CE8D3815C0D56ULL,
		0xD16DB54878B1C3ECULL,
		0x66D781F0377E4986ULL,
		0x5F85E26F4109070EULL,
		0xD728E25B17D94D55ULL,
		0xF985F69AC6AE54FAULL,
		0x1A3B3A11043F50CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC087B8DC2660BE3DULL,
		0xF8B38D20D92AD851ULL,
		0xC0EAAA0A57A5C183ULL,
		0x0035FA9449E64385ULL,
		0x0B3A792437D722D5ULL,
		0xA3BDD1EE3798EF96ULL,
		0x99B1B2846CD29A7EULL,
		0x2B2F62B704FC5F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4085381C00409605ULL,
		0xE800880081080850ULL,
		0xC068A00850A1C180ULL,
		0x0015809001664184ULL,
		0x0B00602401010204ULL,
		0x8328C04A17984D14ULL,
		0x9981B2804482107AULL,
		0x0A2B2211043C5000ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x364F2791AD1EEDACULL,
		0x813B5E349489733DULL,
		0x7267C189991A9CD8ULL,
		0xA8A37100EB700992ULL,
		0xC7E08BE1846169B8ULL,
		0x442A671B0058442CULL,
		0x8C5B5F56D9FB29C1ULL,
		0xC6EC0AFA409286A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D0E907AEECD06EULL,
		0xD061F3658B815EC2ULL,
		0x879DB9C07A24DF29ULL,
		0x1199693E971C1467ULL,
		0x1FF6732F9196E7A4ULL,
		0x6FA3A5A06FA3DB98ULL,
		0x30989A4EF3CEB4E6ULL,
		0x6B8B7F2E82468EA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00402101AC0CC02CULL,
		0x8021522480815200ULL,
		0x0205818018009C08ULL,
		0x0081610083100002ULL,
		0x07E00321800061A0ULL,
		0x4422250000004008ULL,
		0x00181A46D1CA20C0ULL,
		0x42880A2A000286A1ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E6FB75D7CE59C8EULL,
		0x94B9A67E196DACEDULL,
		0x3176D4BC153196EDULL,
		0x60E9373D0EBE750BULL,
		0x92E6F8AB272042E7ULL,
		0xC020339F3C64D48DULL,
		0x86ADCCA575D21661ULL,
		0x75CA442DD3E929A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B7871386EF2811ULL,
		0x9BEAE13B9CC1052CULL,
		0x20ED14B024E730BBULL,
		0x39703606016F162DULL,
		0xE5054CA477A1472CULL,
		0x5FE29C41B728A34DULL,
		0x17CF32B37EB10D70ULL,
		0xCAA3C5D0A10F903BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6627871104E50800ULL,
		0x90A8A03A1841042CULL,
		0x206414B0042110A9ULL,
		0x20603604002E1409ULL,
		0x800448A027204224ULL,
		0x402010013420800DULL,
		0x068D00A174900460ULL,
		0x4082440081090023ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C0B3760F6B62AECULL,
		0x8BF3CAFF8B5B5B8CULL,
		0x3BC8F5CC64425F11ULL,
		0xC2C5B1FC265F7072ULL,
		0xB65A10E1DCF80394ULL,
		0x1715888E91C79326ULL,
		0x0432C5E4793B7655ULL,
		0x203ED0D6F247FBDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE74BE7ABA20684ULL,
		0xDF3D847E76F3BFE6ULL,
		0xD7DE277B849B9BDCULL,
		0xE821DB6B4BF316D0ULL,
		0x3044345A2E06CDC1ULL,
		0x653A8DF31DB6BF7FULL,
		0x859853DBB9CFB67FULL,
		0x693C283C9C913DF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C030360A2A20284ULL,
		0x8B31807E02531B84ULL,
		0x13C8254804021B10ULL,
		0xC001916802531050ULL,
		0x304010400C000180ULL,
		0x0510888211869326ULL,
		0x041041C0390B3655ULL,
		0x203C0014900139D2ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C400564ACCEB1B4ULL,
		0xACD63CED902DF744ULL,
		0xF5DD4492622D2FE2ULL,
		0xE0F612D22B0CE2CAULL,
		0x8CD7AAAD7174A232ULL,
		0x7DDBE95DE98C6C60ULL,
		0x38BC165CD170E425ULL,
		0x98DB2702D0C574F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD01C2E18544F6C04ULL,
		0xB69602B90AFF30C4ULL,
		0x497C014F32651AF1ULL,
		0x381D98B0B539E82FULL,
		0x6D1C67F1418E4482ULL,
		0x45F530FD70973B82ULL,
		0x0040A3BD50928E36ULL,
		0x8444ED2D0EEBE10EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00000400044E2004ULL,
		0xA49600A9002D3044ULL,
		0x415C000222250AE0ULL,
		0x201410902108E00AULL,
		0x0C1422A141040002ULL,
		0x45D1205D60842800ULL,
		0x0000021C50108424ULL,
		0x8040250000C16006ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3043FE860B9CB6FBULL,
		0xEF38D3AE312BE018ULL,
		0xFB6F771891AC11AAULL,
		0xDAE78C6A3CAC885EULL,
		0x2926946AE4CDAFD9ULL,
		0xBDFE782D3EDE1202ULL,
		0x87C6C7E527651B45ULL,
		0xA77BB4D1F0ED2428ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E8279EACE1C93C4ULL,
		0x2213170B68BC2D28ULL,
		0x098E0A91B2A24E88ULL,
		0xC6A20C225EE40170ULL,
		0xB16B70C0FFDC4113ULL,
		0x71B984EC0BB0727FULL,
		0x562F21CDA277FC5BULL,
		0x3616795737EFE1DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000278820A1C92C0ULL,
		0x2210130A20282008ULL,
		0x090E021090A00088ULL,
		0xC2A20C221CA40050ULL,
		0x21221040E4CC0111ULL,
		0x31B8002C0A901202ULL,
		0x060601C522651841ULL,
		0x2612305130ED2008ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FECED6B030F8639ULL,
		0x7EBB98AF10AD9C47ULL,
		0x80FBBC9DBF4C229DULL,
		0xE971A2955400B817ULL,
		0xAF74FFDE83DD8D8EULL,
		0x2DAB09DA48F46966ULL,
		0x55674EE43C8643C5ULL,
		0x7BAD387DE03C6D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE797D9C3ABDB523ULL,
		0xEAE03CF329323EC6ULL,
		0x6534900158DB65E2ULL,
		0xD43B1E10EF27B0ACULL,
		0x55875CC672157402ULL,
		0xA955024519266BD6ULL,
		0x97A6DCD5BC148F39ULL,
		0x488CA1EC991FC594ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E686D08020D8421ULL,
		0x6AA018A300201C46ULL,
		0x0030900118482080ULL,
		0xC03102104400B004ULL,
		0x05045CC602150402ULL,
		0x2901004008246946ULL,
		0x15264CC43C040301ULL,
		0x488C206C801C4510ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9AE0EF3FA76DC69ULL,
		0x5B3BF471DD83EA44ULL,
		0xB3F1017EE57B59A4ULL,
		0x6DF22692D92DAF01ULL,
		0xD1C66930D3C51D17ULL,
		0x77D4DBABE26A5DB7ULL,
		0x6EAD8CA2A923960CULL,
		0xE2D1E28927D3B99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F7E7F61390A465DULL,
		0x4961DEA20C12E793ULL,
		0xCC7086105F2E8CBDULL,
		0x924F293CBC221E32ULL,
		0x807019195A75B5BBULL,
		0x677561679B5A8D89ULL,
		0xCBF7CF3DB9BFCA1FULL,
		0x241FA5724E647815ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x292E0E6138024449ULL,
		0x4921D4200C02E200ULL,
		0x80700010452A08A4ULL,
		0x0042201098200E00ULL,
		0x8040091052451513ULL,
		0x67544123824A0D81ULL,
		0x4AA58C20A923820CULL,
		0x2011A00006403811ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x028818BD44A37346ULL,
		0x2D390F89B851C19DULL,
		0x234CA79ACB6EA6D3ULL,
		0x3FF94848F4673711ULL,
		0xC70D1966E48FCD4BULL,
		0x10C425F808FB3E5BULL,
		0x2B7282C85E6912A4ULL,
		0x706593E1CD33E0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9103E36BA00D0258ULL,
		0xE020F389EF85B617ULL,
		0xD7ABF2A278DCCF35ULL,
		0xD581355931347C27ULL,
		0x9CAEC93171DB64A3ULL,
		0x9E167A9B8BC733F1ULL,
		0xD666EEE15F6EDD9BULL,
		0xC46D520669B86B79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000002900010240ULL,
		0x20200389A8018015ULL,
		0x0308A282484C8611ULL,
		0x1581004830243401ULL,
		0x840C0920608B4403ULL,
		0x1004209808C33251ULL,
		0x026282C05E681080ULL,
		0x4065120049306031ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA80443E6F5AD782ULL,
		0xA8CEE0B80A6B46FEULL,
		0xC85408C8EE9E6139ULL,
		0xA4EEC0BC7318E81EULL,
		0x7500AFB4C1BA0D45ULL,
		0x350CDBD8DEA00894ULL,
		0x09AF5FDB3D4FEB73ULL,
		0x2BFA0DA001BEDAA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1046FB55A765BD8ULL,
		0x23029628FE01A316ULL,
		0xC28D7F9CF30C9DD7ULL,
		0xCD5C8C82BE2A0C15ULL,
		0x77924BCD5A8A43B2ULL,
		0x9E21D292465E8BD5ULL,
		0xD2370893836F45F3ULL,
		0x4BF29C6A1AF0494AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC00044344A525380ULL,
		0x200280280A010216ULL,
		0xC0040888E20C0111ULL,
		0x844C808032080814ULL,
		0x75000B84408A0100ULL,
		0x1400D29046000894ULL,
		0x00270893014F4173ULL,
		0x0BF20C2000B04808ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95C491EF2F16EE95ULL,
		0x5F93D73408DF483DULL,
		0xA521D391C2824C49ULL,
		0xA896151276CBCD26ULL,
		0xF8859440EB402C2FULL,
		0xD150EB0CC5F5D697ULL,
		0xE97A38C91ABF523DULL,
		0xD5A93ED33A320B57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE00529A5A275CFULL,
		0xCB36F8D6704B9FE4ULL,
		0x9AC12C1F47CD8012ULL,
		0x4852CC19E3C50CB5ULL,
		0x06F3B545BEAE77C8ULL,
		0x80AB843B00A7A3F5ULL,
		0x35554E76846A726AULL,
		0x5B060A0B16B0A5A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05C0012925026485ULL,
		0x4B12D014004B0824ULL,
		0x8001001142800000ULL,
		0x0812041062C10C24ULL,
		0x00819440AA002408ULL,
		0x8000800800A58295ULL,
		0x21500840002A5228ULL,
		0x51000A0312300101ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF743D06316D29D0DULL,
		0xEA65D4FDA690D0ACULL,
		0x95ABA93DB0ECBF1CULL,
		0x1149F6C20EA6185DULL,
		0xC9D2800E4DD4C9B8ULL,
		0x6C3BAACE4417325AULL,
		0x0D1C5CC1EC1F37F0ULL,
		0x8563139E118A3404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC66BA4DBE6E36339ULL,
		0x1CB06E89E9FB28C3ULL,
		0x29016C1A97905114ULL,
		0x945EEE175297DC33ULL,
		0xE393AAC129DDAD7CULL,
		0xEAA1198701134115ULL,
		0x57692EDDEBC54F9BULL,
		0x98B2BB79FB61C905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC643804306C20109ULL,
		0x08204489A0900080ULL,
		0x0101281890801114ULL,
		0x1048E60202861811ULL,
		0xC192800009D48938ULL,
		0x6821088600130010ULL,
		0x05080CC1E8050790ULL,
		0x8022131811000004ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6F256A3DE0B81EAULL,
		0xF389CAC59D369FA4ULL,
		0x3B8397210CE0F188ULL,
		0x413C8D8C12ADDA29ULL,
		0x74A2A95A34726698ULL,
		0xA143690806061D71ULL,
		0xDADB5F103813AFC1ULL,
		0xEC6F0DBBECD445C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x801FFC1220124333ULL,
		0xA6E0AE9808C7F053ULL,
		0xF686D563C74C2237ULL,
		0xFBEE03AF7DE5DF6AULL,
		0x8B4A35FC1F74A3A3ULL,
		0x748E8D59DE60EFC2ULL,
		0x1B8FF1929D04894BULL,
		0x0379285C93A1BD23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8012540200020122ULL,
		0xA2808A8008069000ULL,
		0x3282952104402000ULL,
		0x412C018C10A5DA28ULL,
		0x0002215814702280ULL,
		0x2002090806000D40ULL,
		0x1A8B511018008941ULL,
		0x0069081880800502ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C11FBE7406D68ECULL,
		0xF74C01F526BFDB28ULL,
		0x85A883BD6CF71896ULL,
		0x615CF238DAE0071FULL,
		0x6E3ED85CA7EE5B4AULL,
		0x119647E7D34F586DULL,
		0x84EF49A3B4B85433ULL,
		0xAAD03A90B5A1FBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94084BC1CADB8AE3ULL,
		0xD0C228A5B4846F72ULL,
		0x6ABCAC787A7E7B2AULL,
		0x2C0BDD0AAE918547ULL,
		0x9496618BA6683EBEULL,
		0xC85A21DDBF59FCA8ULL,
		0x776B550A3290EFBCULL,
		0x6C1EB46A1A345214ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84004BC1404908E0ULL,
		0xD04000A524844B20ULL,
		0x00A8803868761802ULL,
		0x2008D0088A800507ULL,
		0x04164008A6681A0AULL,
		0x001201C593495828ULL,
		0x046B410230904430ULL,
		0x2810300010205204ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x156D4D5DD3332E06ULL,
		0x7AF678105A552278ULL,
		0x5D47EE8AF915BCA3ULL,
		0x6D93F2D35CDACACBULL,
		0x36C3FAD233BF8D12ULL,
		0x47D5A15122DE49A5ULL,
		0xB448799EE186D623ULL,
		0x81E66F73DA9165FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15B965D47D240F06ULL,
		0xC563FE7E689618DBULL,
		0xAEF9713CFF333113ULL,
		0x11175BF15EBD51F4ULL,
		0x1BA37BD7CADC52F8ULL,
		0x42C59BD1C92F7CC6ULL,
		0xA2E66DB96821707EULL,
		0x83EA310BEBC14205ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1529455451200E06ULL,
		0x4062781048140058ULL,
		0x0C416008F9113003ULL,
		0x011352D15C9840C0ULL,
		0x12837AD2029C0010ULL,
		0x42C58151000E4884ULL,
		0xA040699860005022ULL,
		0x81E22103CA814001ULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x556A4732A4E6A39AULL,
		0x1F45303788E2F0B4ULL,
		0x74E107F7D6E2FC86ULL,
		0x8F6A97CA76DD2BA2ULL,
		0xF83342FD440DCBCEULL,
		0x81F6243F432C3822ULL,
		0x8733EB50217B2651ULL,
		0x774796F0E1589292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7737DB71F41457D4ULL,
		0x6080FC64054F3ACEULL,
		0xDAFB59638C401411ULL,
		0x0775CFB180B03EDAULL,
		0x8D9A563CF16F5B0EULL,
		0x5473B1E3BF6EEB1CULL,
		0xB9F0E4ED21FBDADBULL,
		0xF55387D63C32651BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55224330A4040390ULL,
		0x0000302400423084ULL,
		0x50E1016384401400ULL,
		0x0760878000902A82ULL,
		0x8812423C400D4B0EULL,
		0x00722023032C2800ULL,
		0x8130E040217B0251ULL,
		0x754386D020100012ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3DFD9555EAAB2EEULL,
		0xED7652E405ECA196ULL,
		0xAC96CA155853892DULL,
		0xD560A66FA4B03764ULL,
		0x5A62897F29E32D0CULL,
		0x6CD77FCDC29FDA91ULL,
		0x1BE9E52E60997276ULL,
		0xD6118566EF600B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BAC9C206EF57B71ULL,
		0xFF7D0DD3BB5AD4FCULL,
		0x321BD09DBBF804D5ULL,
		0xF42637868FAF5997ULL,
		0xFB7B81420AE785B8ULL,
		0xC18CE346A405EE07ULL,
		0x775B8CB700873E7AULL,
		0x7FF74BEDA57E7551ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x438C98004EA03260ULL,
		0xED7400C001488094ULL,
		0x2012C01518500005ULL,
		0xD420260684A01104ULL,
		0x5A62814208E30508ULL,
		0x408463448005CA01ULL,
		0x1349842600813272ULL,
		0x56110164A5600150ULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98006DD2207CFE26ULL,
		0x65E67948AD2E31F3ULL,
		0x357DF8C02E973D4EULL,
		0xAAE531B3B4B8D534ULL,
		0xF7C3D4C98DC6B529ULL,
		0x9CA84BFECE82A232ULL,
		0xA607492770F7BC4DULL,
		0x2FD110681A132252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB1B02872F36E1FULL,
		0x7B03E301D035C1DDULL,
		0x6A66395B52A7AA1BULL,
		0xC7510FC0407DDDB2ULL,
		0xD8B669CD6D7280FCULL,
		0xA2309BFC76FDF2A5ULL,
		0xF1D4F34E4310528FULL,
		0xB7FD78816FFB9B4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8800200020706E06ULL,
		0x61026100802401D1ULL,
		0x206438400287280AULL,
		0x824101800038D530ULL,
		0xD08240C90D428028ULL,
		0x80200BFC4680A220ULL,
		0xA00441064010100DULL,
		0x27D110000A130242ULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x952CA1D769698831ULL,
		0xB24B01C175C80CE4ULL,
		0x5E609B71A5DF47A7ULL,
		0xA84F8B471F20B9CCULL,
		0x62F4D3180272DC43ULL,
		0x6BA8DE9BD2A62E5BULL,
		0x6978E2F5EE4E5DCCULL,
		0xEFA2E8B3C810F4BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x689C3259C66737F8ULL,
		0xE860739793A3EFDBULL,
		0xEC81B2B8D595FBF1ULL,
		0xAEC5E5FCC89359D9ULL,
		0x5AE9526D15713949ULL,
		0xC322A6CD8B522263ULL,
		0x9FCD9E79180A71CAULL,
		0x64EDABEB723B0B88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000C205140610030ULL,
		0xA040018111800CC0ULL,
		0x4C009230859543A1ULL,
		0xA8458144080019C8ULL,
		0x42E0520800701841ULL,
		0x4320868982022243ULL,
		0x09488271080A51C8ULL,
		0x64A0A8A340100088ULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x548AA07E8CC162FAULL,
		0x9BF2CEDADD763246ULL,
		0x2798E40DD6872628ULL,
		0x4710A2F6DE4F8C99ULL,
		0xAEDF5C70FD4AD036ULL,
		0xEB444BC7120CB72DULL,
		0x2859E052DA2522D7ULL,
		0x6D9299C2D0E627B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F7F74330C95AE6ULL,
		0xF340E9070FFAFDFFULL,
		0xDFF4D3F399DD5E2BULL,
		0xCAC1FBF2B5A78262ULL,
		0xE773555EC99294A8ULL,
		0x37303A13F6662F45ULL,
		0x0B49D62300413ACAULL,
		0x98A24FF99DEBF9C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0082A04200C142E2ULL,
		0x9340C8020D723046ULL,
		0x0790C00190850628ULL,
		0x4200A2F294078000ULL,
		0xA6535450C9029020ULL,
		0x23000A0312042705ULL,
		0x0849C002000122C2ULL,
		0x088209C090E22186ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7DAE3F098DCDD31ULL,
		0x73C796B35081A424ULL,
		0x7CE998433DCA9689ULL,
		0x8996FE5E04D71156ULL,
		0x13185859A2D7CF17ULL,
		0x96F092618CA05587ULL,
		0x6AEDAD8B0161E4B6ULL,
		0xAEE729112D0934B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x563F98CEC10ACD5BULL,
		0x9C89E7B8040C67D3ULL,
		0x4CE2CC050985C62AULL,
		0xD1FB08D2CE961FEDULL,
		0x937671EA2BED1029ULL,
		0x6E72CEA7EA052688ULL,
		0x4D918A18D729DF44ULL,
		0x13F1CF4EE1A99308ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x061A80C08008CD11ULL,
		0x108186B000002400ULL,
		0x4CE0880109808608ULL,
		0x8192085204961144ULL,
		0x1310504822C50001ULL,
		0x0670822188000480ULL,
		0x488188080121C404ULL,
		0x02E1090021091000ULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB831194DC2F2BD7CULL,
		0xB7B6EABE6D032AD3ULL,
		0x1074956950D0B9E1ULL,
		0x584EA5557CB34E64ULL,
		0x33B72D28C350C7E6ULL,
		0x64782CE02277FB47ULL,
		0x7B1A054FA5A78D3FULL,
		0xC02E871BEF2E9DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E756747F3379EAULL,
		0x43BC8130E796E347ULL,
		0x9AFFE35AD59821ECULL,
		0x9AE0643030DBE01AULL,
		0x0E1F985F637428D6ULL,
		0x793DCB83876A3A65ULL,
		0x245A683E19111935ULL,
		0xB0337F66EC703C5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA021104442323968ULL,
		0x03B4803065022243ULL,
		0x10748148509021E0ULL,
		0x1840241030934000ULL,
		0x02170808435000C6ULL,
		0x6038088002623A45ULL,
		0x201A000E01010935ULL,
		0x80220702EC201C40ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x843318BE8E629447ULL,
		0xA2F88B15CA18C59EULL,
		0xEB07ABBF8076FCF0ULL,
		0xE2196DDA53B32BA7ULL,
		0x009DA5F8235AF1ABULL,
		0x9CF794D780159D89ULL,
		0x689227B8B8C34C28ULL,
		0x4B2F926D531BB738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x862B636383F668D0ULL,
		0xC6B5583CC5C3BBD9ULL,
		0xA0DBF61942A4E60AULL,
		0x6D441E8579D34BD6ULL,
		0x3DA6BFF44A9ECB48ULL,
		0x1134F3D5658D616AULL,
		0x502BB7A33E94F5C2ULL,
		0x883E2AD5716D15C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8423002282620040ULL,
		0x82B00814C0008198ULL,
		0xA003A2190024E400ULL,
		0x60000C8051930B86ULL,
		0x0084A5F0021AC108ULL,
		0x103490D500050108ULL,
		0x400227A038804400ULL,
		0x082E024551091500ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE38517DD7D454EBULL,
		0x883966B763C937E8ULL,
		0xCD0BCDF06C89DAC6ULL,
		0xD6E0D9A1519920E7ULL,
		0xDC12A48C59790EC2ULL,
		0x24A7E35B7670C9B5ULL,
		0x15A057B5919B8F9FULL,
		0x763D3B5CA382BCA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE18045E0FF5B1771ULL,
		0x836476A8ECC6F43FULL,
		0x31FEA211B7794AA7ULL,
		0x6CA682BC8CE51D82ULL,
		0x94BE81DB6971B3C2ULL,
		0x2D7BD823C12BE910ULL,
		0x510E42A6EB73B5B9ULL,
		0xBAF01CE501FBCB88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0004160D7501461ULL,
		0x802066A060C03428ULL,
		0x010A801024094A86ULL,
		0x44A080A000810082ULL,
		0x94128088497102C2ULL,
		0x2423C0034020C910ULL,
		0x110042A481138599ULL,
		0x3230184401828888ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4DDD4C49C029EAEULL,
		0x9BD996B2F5ACEEBCULL,
		0xB10D7942712DCF58ULL,
		0x45E815A16CADBD81ULL,
		0x731A3ECF0F9CE5A3ULL,
		0xDAFE3C27E127D383ULL,
		0x177A4816A67D0D79ULL,
		0xFF14C0BB9BBD2125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9E7394FE6EB85D7ULL,
		0xCB0D0AC037E8AF1FULL,
		0x1FC11993C8F455D8ULL,
		0xAA9967E116BE31C7ULL,
		0x3FBD81D83A074A92ULL,
		0x3EF538530CED974FULL,
		0xA642BB0A2A77F63EULL,
		0x59F1E19F3BE1C786ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0C5104484028486ULL,
		0x8B09028035A8AE1CULL,
		0x1101190240244558ULL,
		0x008805A104AC3181ULL,
		0x331800C80A044082ULL,
		0x1AF4380300259303ULL,
		0x0642080222750438ULL,
		0x5910C09B1BA10104ULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C6B0CA45ED02063ULL,
		0x6AA8B1D12A804490ULL,
		0xAA05F57A4B15AEA0ULL,
		0xF28D81486FE848ECULL,
		0x968CA72EEAA4E9C4ULL,
		0x4888151E85C96CE7ULL,
		0x45EBF5980C22430EULL,
		0x8B826E0B4FD80C27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F2FABDAA175C2FULL,
		0x228259E6C8D097E6ULL,
		0xD2DCCCCF6F23F527ULL,
		0x1DD2B655D6DAA01DULL,
		0x3738FA17BC53EC4DULL,
		0x85910203D43B8352ULL,
		0xCC115CB803E5A4B0ULL,
		0x7847D51FD91EC3C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x806208A40A100023ULL,
		0x228011C008800480ULL,
		0x8204C44A4B01A420ULL,
		0x1080804046C8000CULL,
		0x1608A206A800E844ULL,
		0x0080000284090042ULL,
		0x4401549800200000ULL,
		0x0802440B49180000ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7C5C97BFE36FACFULL,
		0xD201B9A048CD9306ULL,
		0x0456B8FC31A479DAULL,
		0x1D69741923BFE58FULL,
		0x83BC3DA3953FF0FEULL,
		0x2B65B8A349B43157ULL,
		0xFB572852E424AA19ULL,
		0x729344803B4377E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5034C14DEAD3EEAULL,
		0x9190FE4DCFD24DCDULL,
		0xF4998A4B22EAF6CCULL,
		0x6CDB5B50DFD5501CULL,
		0xE91BCE9B270A6665ULL,
		0xA03F94A8C5C95BD6ULL,
		0x3076FF360A8A10ADULL,
		0x080B3917BEE80D72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85014810DE243ACAULL,
		0x9000B80048C00104ULL,
		0x0410884820A070C8ULL,
		0x0C4950100395400CULL,
		0x81180C83050A6064ULL,
		0x202590A041801156ULL,
		0x3056281200000009ULL,
		0x000300003A400560ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5537BC7A621BD3A8ULL,
		0xE53B073A9EC341D5ULL,
		0xE15CDC4E445C15DEULL,
		0x9506F1E01F034295ULL,
		0x431AF5837D5530A7ULL,
		0xE9B433F7DFDDAE58ULL,
		0x6C2EEC2B3AFE0989ULL,
		0x30E1406146484D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893BAA3F6DF68582ULL,
		0xCA8A50F6A21AB98DULL,
		0xEFBDD83BCE3C4C63ULL,
		0x69723C2375101385ULL,
		0xE7EF678889D0B512ULL,
		0x0D0B03C6432EB98AULL,
		0xE74191E611601065ULL,
		0x82796BFD45C1AAFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0133A83A60128180ULL,
		0xC00A003282020185ULL,
		0xE11CD80A441C0442ULL,
		0x0102302015000285ULL,
		0x430A658009503002ULL,
		0x090003C6430CA808ULL,
		0x6400802210600001ULL,
		0x0061406144400834ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E340B948C67E479ULL,
		0x217B78D6FC640462ULL,
		0x21C119566C5C9FF2ULL,
		0x7F8A1B1D66F5A7FBULL,
		0xB04F6092FD4208E0ULL,
		0xA655AB879C0D2A03ULL,
		0x16797E4677320DB5ULL,
		0x9FB5F091AE43CAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x181DCE770E3500CBULL,
		0x8F934D0D079BD373ULL,
		0x6381596703EA7619ULL,
		0x9B9F44382B10AE18ULL,
		0x0F13683F88F556EBULL,
		0xCAF42DEF463A3C8BULL,
		0x35F9BF2B2E6E529BULL,
		0xE23EA555AB927C4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08140A140C250049ULL,
		0x0113480404000062ULL,
		0x2181194600481610ULL,
		0x1B8A00182210A618ULL,
		0x00036012884000E0ULL,
		0x8254298704082803ULL,
		0x14793E0226220091ULL,
		0x8234A011AA024800ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x062FED062AFF396DULL,
		0xDEC995E77D203B56ULL,
		0x6CE0B82F163AF663ULL,
		0x1BAFB48EA6598097ULL,
		0x2C7669F7FBD97995ULL,
		0x30E2DA989475CE4CULL,
		0xCE9D01199EDECCAEULL,
		0x1CF4438D444E157BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A633526E2559DAULL,
		0x9C929C7490F5A5BAULL,
		0x282B4DE92A327400ULL,
		0x06F634E8382915C0ULL,
		0xE969E48DDEAB04F5ULL,
		0x3EBA8DC1E9D2040CULL,
		0x83700EF8F3615D87ULL,
		0x57211D75F759D69BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042621022A251948ULL,
		0x9C80946410202112ULL,
		0x2820082902327400ULL,
		0x02A6348820090080ULL,
		0x28606085DA890095ULL,
		0x30A288808050040CULL,
		0x8210001892404C86ULL,
		0x142001054448141BULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279DBC06EECFA772ULL,
		0xE5A51D8EBE436687ULL,
		0x7FB56E9CE53BCF2AULL,
		0x2914DF50D42CEABDULL,
		0xDDC07256F769D01DULL,
		0x494FAA3E6496D63DULL,
		0xCA864287E1F862A7ULL,
		0x987CCDFAD6DEE120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06F419E97D7CD31ULL,
		0x54541DE1C13CF8AEULL,
		0x1522BABC62A296C3ULL,
		0x4A8009FF91CCAF4AULL,
		0x32A4033438643083ULL,
		0x7F0EF8AF54B4F111ULL,
		0x8F27FB20B65BC721ULL,
		0x8BB00089293B71D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200D000686C78530ULL,
		0x44041D8080006086ULL,
		0x15202A9C60228602ULL,
		0x08000950900CAA08ULL,
		0x1080021430601001ULL,
		0x490EA82E4494D011ULL,
		0x8A064200A0584221ULL,
		0x88300088001A6100ULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA3CA82E8E83CFA5ULL,
		0x2B796041E10CA2C1ULL,
		0x5E2005947709439CULL,
		0xDFBB57B873448915ULL,
		0x6C3FBC04FEEA5FA0ULL,
		0xA4B9F816A57E009AULL,
		0xD715A5E89B6A2DD9ULL,
		0x0AD8E5643F103EB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA33A83B5A5BD658ULL,
		0xBE97C690A62ED16FULL,
		0x3AF4639971334693ULL,
		0x55F1F312A94ED938ULL,
		0xCB0B34D2637C4005ULL,
		0x528FD112EB33566EULL,
		0x28F0BCF355A49344ULL,
		0x0BB1B61403728462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA30A82A0A03C600ULL,
		0x2A114000A00C8041ULL,
		0x1A20019071014290ULL,
		0x55B1531021448910ULL,
		0x480B340062684000ULL,
		0x0089D012A132000AULL,
		0x0010A4E011200140ULL,
		0x0A90A40403100422ULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00E5FDBF30E255E8ULL,
		0x524753B4C63E18B5ULL,
		0x57169F3CB7E246A7ULL,
		0x2E552D0665D0F9A5ULL,
		0x88AE099062FE501AULL,
		0xD3DB6557042EE85DULL,
		0x8CC427C8D478E522ULL,
		0xF86BDFA738D16880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D56D007F026F913ULL,
		0xC41B5BF02A6751E1ULL,
		0x375E2C5F27638BB2ULL,
		0xDBF738436DD8D38EULL,
		0x5A0DCDBECC17FE54ULL,
		0x58088C950A6E27B2ULL,
		0xC4BA7DD1167EB743ULL,
		0x0BA09A823E67F8A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0044D00730225100ULL,
		0x400353B0022610A1ULL,
		0x17160C1C276202A2ULL,
		0x0A55280265D0D184ULL,
		0x080C099040165010ULL,
		0x50080415002E2010ULL,
		0x848025C01478A502ULL,
		0x08209A8238416880ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x268F3C84BBF8B3AAULL,
		0x462B7E1BD589F566ULL,
		0xF250A75961D6AE54ULL,
		0x2A06E8E9D5B45349ULL,
		0xEFF1B7EA366B6AEDULL,
		0x774BFDEF2E33F4A3ULL,
		0x00920D125F384FA3ULL,
		0xD74F1B26BCD9B3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68DF357973B2AFE8ULL,
		0x83E10403ABCE9D88ULL,
		0x19204BCF2A7EC3E6ULL,
		0xC5B052A43411BB7FULL,
		0x51F9C2D7F19FFD72ULL,
		0xBDACF2244228A1BEULL,
		0x6F537856E21EC71CULL,
		0x40DEEE96811EFBE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x208F340033B0A3A8ULL,
		0x0221040381889500ULL,
		0x1000034920568244ULL,
		0x000040A014101349ULL,
		0x41F182C2300B6860ULL,
		0x3508F0240220A0A2ULL,
		0x0012081242184700ULL,
		0x404E0A068018B3A0ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC9D04C8B51986BULL,
		0xF9F2B2B48941B756ULL,
		0x5346301069B6EBD2ULL,
		0x27730CF20F1FFF69ULL,
		0x06B037B6924213D6ULL,
		0x66854BA14A465B80ULL,
		0xBD0217D5496640D5ULL,
		0xEE4F71343E7A87F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15B0118D779C0EBAULL,
		0xE6788E7EDA3A98A4ULL,
		0x02692FDB39281A9CULL,
		0x9BBE706CE904D354ULL,
		0x7F3BC8722A8D9E06ULL,
		0xFD21CBA0CEDED220ULL,
		0x0E0E1BE962F98683ULL,
		0xD7C3D5ACBE8D57BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0480100C0310082AULL,
		0xE070823488009004ULL,
		0x0240201029200A90ULL,
		0x033200600904D340ULL,
		0x0630003202001206ULL,
		0x64014BA04A465200ULL,
		0x0C0213C140600081ULL,
		0xC64351243E0807B4ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC9783262C0AB91ULL,
		0x7457A1B5E20010C1ULL,
		0xA34B215237FEFF48ULL,
		0xB5666F56A9FAA4C0ULL,
		0xD80C2EAF10D87B3DULL,
		0x05B903856AE104B1ULL,
		0xD9DB2BBDFFA11261ULL,
		0x3EC61C6AE9B190F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD62B48C5B5CB1FB2ULL,
		0xEA3D4F5C10B8ABCEULL,
		0x615600ADF7E2C910ULL,
		0x19096B5213564E67ULL,
		0x6A37938323735F68ULL,
		0x1730057BBD50C3F7ULL,
		0x78FB02EC72EAF3ABULL,
		0x493DCA298F3B0924ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4409480020C00B90ULL,
		0x60150114000000C0ULL,
		0x2142000037E2C900ULL,
		0x11006B5201520440ULL,
		0x4804028300505B28ULL,
		0x05300101284000B1ULL,
		0x58DB02AC72A01221ULL,
		0x0804082889310024ULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8C50D0E926FC76BULL,
		0x15CEDE3D7F16CF50ULL,
		0x51FF451689CC0433ULL,
		0xE6F169910BAE7170ULL,
		0xC52A3A48815DECC7ULL,
		0xBE4CC31D72DF7B49ULL,
		0x4311D412296BD840ULL,
		0x42CCACF63412A0E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76F14EFADF348ABULL,
		0xA98EEB85A38B700AULL,
		0x2E4027D30AD26E89ULL,
		0x8EEAD7533AA278FDULL,
		0xD12BD68081F32A0AULL,
		0xCDEB1954098D345CULL,
		0x4CB95FF4CB14A088ULL,
		0x6C7F1E98F3FA8316ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8045040E8063402BULL,
		0x018ECA0523024000ULL,
		0x0040051208C00401ULL,
		0x86E041110AA27070ULL,
		0xC12A120081512802ULL,
		0x8C480114008D3048ULL,
		0x4011541009008000ULL,
		0x404C0C9030128004ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84D091D8402E5384ULL,
		0x5942794873A56FBDULL,
		0xEB6EDC5A775EC957ULL,
		0xC88734DC1B0AB82FULL,
		0xC2245C323F4C2952ULL,
		0xB13605269E20F725ULL,
		0xD1F6163FBAD3B586ULL,
		0x8E3488A140738A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A47BB4D6E92D985ULL,
		0x6B01A4258A18FE43ULL,
		0xBF186C6C955506E4ULL,
		0x7B4CEB178B417AC7ULL,
		0xA2619258124B97F4ULL,
		0x4B862A94DFE7A797ULL,
		0xCB6E4D711C4A7C1AULL,
		0x4AF84379CBA41DA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0040914840025184ULL,
		0x4900200002006E01ULL,
		0xAB084C4815540044ULL,
		0x480420140B003807ULL,
		0x8220101012480150ULL,
		0x010600049E20A705ULL,
		0xC166043118423402ULL,
		0x0A30002140200801ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x150CF784C6B935B1ULL,
		0xE24616DE4BFB559CULL,
		0x5B65B1ACCA6208F5ULL,
		0xDE3107D14FA77A59ULL,
		0x0C9F4E3111BE7491ULL,
		0x69D8E4C10604DEDCULL,
		0xB8AACDEC701CD200ULL,
		0xE46AE27CD5D30924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27775EE25EFD883CULL,
		0x03B809A4CCD2A975ULL,
		0xB4EB48DB373A6005ULL,
		0xEE254FE43373F0F0ULL,
		0x248E1F56E2F56AF3ULL,
		0xC62BF6FFB39162C8ULL,
		0x5B3EE7235C1CF535ULL,
		0x13ED1CBC8C005B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0504568046B90030ULL,
		0x0200008448D20114ULL,
		0x1061008802220005ULL,
		0xCE2107C003237050ULL,
		0x048E0E1000B46091ULL,
		0x4008E4C1020042C8ULL,
		0x182AC520501CD000ULL,
		0x0068003C84000920ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77BA13599774202DULL,
		0xBB1BDE3834D353AEULL,
		0xF517A33A5DF94C36ULL,
		0xF82DE27BDA5DC593ULL,
		0xD656E92A07DAC887ULL,
		0x983F120E80A84896ULL,
		0x20CBF6732F890328ULL,
		0x7465F12682A3C4E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EB0981A5CDA774CULL,
		0x4205C5A6996A1246ULL,
		0xF5DCD6FE5C165FABULL,
		0x8DC83A49D33E1CE4ULL,
		0x62F9E2D14232CFC2ULL,
		0xDBEE305DCF15E69CULL,
		0x9752170EA8C8B3DEULL,
		0x085DAA0709CB31B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16B010181450200CULL,
		0x0201C42010421206ULL,
		0xF514823A5C104C22ULL,
		0x88082249D21C0480ULL,
		0x4250E0000212C882ULL,
		0x982E100C80004094ULL,
		0x0042160228880308ULL,
		0x0045A006008300A0ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47D234E9411FEA58ULL,
		0x99CDBC8BFE3FB661ULL,
		0xC9D7211C5CC6F581ULL,
		0x00C1DAB15AF21B32ULL,
		0xA3A4E0899826FA9FULL,
		0x17B4B65DBED3CB81ULL,
		0xC11297139989EE83ULL,
		0x6D4CA097716AA077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32B44C28040D329CULL,
		0x7CDDAF99CDEFDFAEULL,
		0x2A0F455C6157F7E8ULL,
		0x9B3D0DE664B0E0BDULL,
		0x51EE2F6DB55AA173ULL,
		0x60A11E9692F1200BULL,
		0x45D806CEE24176F4ULL,
		0xC35E75DFB21FEE40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02900428000D2218ULL,
		0x18CDAC89CC2F9620ULL,
		0x0807011C4046F580ULL,
		0x000108A040B00030ULL,
		0x01A420099002A013ULL,
		0x00A0161492D10001ULL,
		0x4110060280016680ULL,
		0x414C2097300AA040ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF21FA2F46D9BD6C2ULL,
		0xCE7A76AD5B45F55FULL,
		0x599F7C77E2B09D29ULL,
		0xC65CF8ED21AA85E6ULL,
		0xE84D86A26FDF86DAULL,
		0x31DCC8C9CD7B78DFULL,
		0xFAA8F0D107929A23ULL,
		0x910DADA9C74492E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6442AEF744EDD9F7ULL,
		0xEE3C5FE4ACECADC0ULL,
		0x553154038ED6A26BULL,
		0x32BDCCCE28694254ULL,
		0x961D73543662A5F6ULL,
		0x03E7F4193515FAB3ULL,
		0xEA11A225F3CD9081ULL,
		0x1A1640A7B7F8E58CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6002A2F44489D0C2ULL,
		0xCE3856A40844A540ULL,
		0x5111540382908029ULL,
		0x021CC8CC20280044ULL,
		0x800D0200264284D2ULL,
		0x01C4C00905117893ULL,
		0xEA00A00103809001ULL,
		0x100400A187408084ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EE6A2B040ABB174ULL,
		0x4AC2D200A438EC93ULL,
		0xEA09D09204D071AAULL,
		0x43F502342DC8C038ULL,
		0x863E3375A11D7CC9ULL,
		0x1BF93D06EB67B253ULL,
		0x89BE09620999835EULL,
		0x04898CED98501412ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4135093F126D572ULL,
		0x91195A3DB9E693BEULL,
		0xA4541CF5B96880CCULL,
		0xA7FEA11031FCFEA9ULL,
		0x694612B74258F4E3ULL,
		0x63A713A8253B58AEULL,
		0x6731AF4BA9D29F54ULL,
		0x84A453AB394A894CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0402009040229170ULL,
		0x00005200A0208092ULL,
		0xA000109000400088ULL,
		0x03F4001021C8C028ULL,
		0x00061235001874C1ULL,
		0x03A1110021231002ULL,
		0x0130094209908354ULL,
		0x048000A918400000ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18AB0AC7A7196BD4ULL,
		0xAAD706B94383DFFEULL,
		0xB2026F8835D160FCULL,
		0xADB4692BA9852DECULL,
		0x6B52042B72AAF7F0ULL,
		0x71C8BB5999E1E2ABULL,
		0xF77A1712621C21B7ULL,
		0x1FB9E0A37620DC6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA591B8AE69297EA5ULL,
		0x1C9E3CF0E19E9849ULL,
		0xF31A4AB2907E1EA2ULL,
		0xDE253996F8813C22ULL,
		0xABFBD9CEA2C2E0FEULL,
		0x17B4A4681CB407C1ULL,
		0x80B4303EDAAB57CDULL,
		0x504DB461BB89F3BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0081088621096A84ULL,
		0x089604B041829848ULL,
		0xB2024A80105000A0ULL,
		0x8C242902A8812C20ULL,
		0x2B52000A2282E0F0ULL,
		0x1180A04818A00281ULL,
		0x8030101242080185ULL,
		0x1009A0213200D02AULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16982735D11869CEULL,
		0xEDFAC70AC1A3892EULL,
		0xBE725EFC68F5C869ULL,
		0x030687C1F74D85A8ULL,
		0xBECE932D32C700EBULL,
		0xB2A5FCB9378CE969ULL,
		0xAFA7427BD4D93440ULL,
		0x8F492382D7016AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEB25BE6C3A33DBCULL,
		0xCF23169B5D1E9516ULL,
		0x212E6DCCCE84EC09ULL,
		0x66B9FFA09F92CA7DULL,
		0xBC9A94BBE65F3A3BULL,
		0x048BB3C7780DA559ULL,
		0x9725EE0FD0544424ULL,
		0x7F3622593A2ADD03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16900324C100298CULL,
		0xCD22060A41028106ULL,
		0x20224CCC4884C809ULL,
		0x0200878097008028ULL,
		0xBC8A90292247002BULL,
		0x0081B081300CA149ULL,
		0x8725420BD0500400ULL,
		0x0F00220012004803ULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49981B471590DCA7ULL,
		0x4D6C2CBAA56001BCULL,
		0x7DC98F4CF95CACACULL,
		0x3FEFA07A50170A9AULL,
		0xA21F8F1963E59020ULL,
		0x047C938584372C6AULL,
		0x8352C48A46B88666ULL,
		0xF6F7C19B340857B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42888128BA9DC4EDULL,
		0xED5BD2CC54DF9588ULL,
		0x9720C470C0D663BEULL,
		0x1C39CC5D2D44CB7AULL,
		0x7FEDBECAE6A9D6A4ULL,
		0xB5CB72B4D7645140ULL,
		0x3B214575A45360ABULL,
		0xDD50218694669237ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408801001090C4A5ULL,
		0x4D48008804400188ULL,
		0x15008440C05420ACULL,
		0x1C29805800040A1AULL,
		0x220D8E0862A19020ULL,
		0x0448128484240040ULL,
		0x0300440004100022ULL,
		0xD450018214001232ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FF899C0372A198CULL,
		0xC3FE57B40B0F5FD0ULL,
		0x9396448290505D1CULL,
		0xD918C6543B3892CAULL,
		0x9B059CDE060F70D2ULL,
		0x79D12A8B8C66FDB3ULL,
		0x1CE44EE1268DC449ULL,
		0x14E074ACF7A5F122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF435DE266AF5EB1ULL,
		0x0A43A58739E8B536ULL,
		0x12F932012632E076ULL,
		0x3855788B491EA570ULL,
		0xDF9B9ADA586F2B39ULL,
		0x921760998A645BEFULL,
		0x7F4AED182F5EC228ULL,
		0x55FCDE2CB70F6C40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F4019C0262A1880ULL,
		0x0242058409081510ULL,
		0x1290000000104014ULL,
		0x1810400009188040ULL,
		0x9B0198DA000F2010ULL,
		0x10112089886459A3ULL,
		0x1C404C00260CC008ULL,
		0x14E0542CB7056000ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7A1FF275C79DDBCULL,
		0xC5228DA1BD85A35BULL,
		0xE70A7245AF965F5BULL,
		0x9AD8037C38A9BA2DULL,
		0x1DD72E1BCC7966C7ULL,
		0x8783DA28AA628412ULL,
		0x88FFAF04CD6B22A1ULL,
		0x4A95B4BD0155BBDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869129BD888B7C70ULL,
		0x81B59D89A0510B94ULL,
		0x6CFE394968824EFFULL,
		0x354295351CFDA82EULL,
		0x322BE6D26492F0FBULL,
		0x3BC863E2A1EC1392ULL,
		0x13F3699A566B3229ULL,
		0xCC1AAD41D14E8453ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8681292508095C30ULL,
		0x81208D81A0010310ULL,
		0x640A304128824E5BULL,
		0x1040013418A9A82CULL,
		0x10032612441060C3ULL,
		0x03804220A0600012ULL,
		0x00F32900446B2221ULL,
		0x4810A40101448051ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3347221CA9771094ULL,
		0x44012A5CBCBA105BULL,
		0x674F487AE3AE479BULL,
		0xB3AF06850348E14EULL,
		0x292CF00580777679ULL,
		0x5C72E6B1DB60A48BULL,
		0xA3C5B5EC648449FAULL,
		0x75196BE8BB15D016ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB691991E0CB3EF18ULL,
		0xEC61D362EE545615ULL,
		0xBA6DC9E9AC47A8BDULL,
		0x9B727C73DECD66E3ULL,
		0xBAE23257D5E27DC2ULL,
		0xEA3C56647A449DA0ULL,
		0xF12D04C057B122A9ULL,
		0xE10CD491DCB1CD94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3201001C08330010ULL,
		0x44010240AC101011ULL,
		0x224D4868A0060099ULL,
		0x9322040102486042ULL,
		0x2820300580627440ULL,
		0x483046205A408480ULL,
		0xA10504C0448000A8ULL,
		0x610840809811C014ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE054A42D36097F97ULL,
		0x1F19B8DE0B66981AULL,
		0x845619ED660357B8ULL,
		0x32C745097824B153ULL,
		0x4BA7DA9FC5EA21C1ULL,
		0xBFE8BE1B2BC6B586ULL,
		0x487FCB3A188D0ACBULL,
		0xB67C7287DAD95119ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A21008CA97083E1ULL,
		0x15020E4961321E30ULL,
		0xB3BF937392524CB2ULL,
		0x718715D40E29A772ULL,
		0x8A9E26B4567A9E24ULL,
		0x6C9AC67F2A75B24DULL,
		0xA316C3E791DC1D02ULL,
		0xCC2596029B820113ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000000C20000381ULL,
		0x1500084801221810ULL,
		0x80161161020244B0ULL,
		0x308705000820A152ULL,
		0x0A860294446A0000ULL,
		0x2C88861B2A44B004ULL,
		0x0016C322108C0802ULL,
		0x842412029A800111ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB5114B3E3B571E8ULL,
		0x5CB22ACBD826A8B8ULL,
		0x86CC1238A5A5077EULL,
		0x5A02958CE3C86C91ULL,
		0x9BEA5E69A2E8FC75ULL,
		0xB2503F55E2825050ULL,
		0xE39B247A9BCC1971ULL,
		0x3CF6E14FC8966835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FCB89CBAF19429ULL,
		0x766D16921672525EULL,
		0x732D87078B84BF25ULL,
		0x1C48DC6BE796A799ULL,
		0x8C9D648755620520ULL,
		0x623260CAB94D84D0ULL,
		0xA1786C8B3AD7C99AULL,
		0x6C47AB916294BE49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42501090A2B11028ULL,
		0x5420028210220018ULL,
		0x020C020081840724ULL,
		0x18009408E3802491ULL,
		0x8888440100600420ULL,
		0x22102040A0000050ULL,
		0xA118240A1AC40910ULL,
		0x2C46A10140942801ULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E1583AFAB68FC52ULL,
		0x5BE92694F7A10440ULL,
		0x37E4B5CAE5F9647FULL,
		0x38B211DC7EECDC31ULL,
		0x493634E71B73F0B4ULL,
		0xE4BB8A6BCDD51AEDULL,
		0x37E886AF136027A8ULL,
		0x8F91AF335AFEF59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2547DB166F013858ULL,
		0x8002B872C1EBFAF8ULL,
		0xC37D03EF7628F5B5ULL,
		0x6B48E86829FA6DEDULL,
		0x17E51C026008F1D1ULL,
		0xB7C19E0BC773E20BULL,
		0x78483B12CC4343F8ULL,
		0xDAB36090FDBCE55DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x240583062B003850ULL,
		0x00002010C1A10040ULL,
		0x036401CA64286435ULL,
		0x2800004828E84C21ULL,
		0x012414020000F090ULL,
		0xA4818A0BC5510209ULL,
		0x30480202004003A8ULL,
		0x8A91201058BCE518ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4487331446E5201FULL,
		0xE35EEDE85AD4A3DAULL,
		0x7715B814788F67C6ULL,
		0xA1F9286D9FFF6788ULL,
		0xA9B84E2565E8099AULL,
		0xEE4FDF243A333CCFULL,
		0x4F267D79B0226560ULL,
		0xA063A47A77510EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F5998F415BD212ULL,
		0xD7CEACE9C6C3EB57ULL,
		0x2514B3E811A38944ULL,
		0xBD2EB2BBEEE0BB16ULL,
		0x46B647D173BF3EDCULL,
		0xD736CFB5E8312C01ULL,
		0x7384427724F4365EULL,
		0x37235CF59CCBF2CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0085110440410012ULL,
		0xC34EACE842C0A352ULL,
		0x2514B00010830144ULL,
		0xA12820298EE02300ULL,
		0x00B0460161A80898ULL,
		0xC606CF2428312C01ULL,
		0x4304407120202440ULL,
		0x2023047014410282ULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x357D9D0CFC85B2BBULL,
		0xB324F53A635355F2ULL,
		0x28EC659C08840E55ULL,
		0x67AD30603A91FD42ULL,
		0x7601941ED2ED6281ULL,
		0x22499787BEADC0DEULL,
		0x2A2BD171904C4F4DULL,
		0x6962072D47245226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BFB9C7F84F7D0DAULL,
		0x3CA97D2FDA14E43CULL,
		0x71AC70F0DDD78E2EULL,
		0xE34D4E4390AC9D62ULL,
		0xF02C1EBD1CE52E0BULL,
		0x6E7D2EFB9C0FF89DULL,
		0x7334CC07262268F7ULL,
		0x8012405C31C3E4FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31799C0C8485909AULL,
		0x3020752A42104430ULL,
		0x20AC609008840E04ULL,
		0x630D004010809D42ULL,
		0x7000141C10E52201ULL,
		0x224906839C0DC09CULL,
		0x2220C00100004845ULL,
		0x0002000C01004026ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA86FE144A9B2CA96ULL,
		0xA40F090304D0E997ULL,
		0x372090384B18EEA0ULL,
		0x6DD1ACD80D059429ULL,
		0x188C5266478D09F3ULL,
		0x97A54727DFD70502ULL,
		0xAE2B1C4EAB85C273ULL,
		0x00332027D148FFFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB547B2B96E1CB275ULL,
		0xF03EC38F86BBA4AFULL,
		0xC8E4AE2F0A113B14ULL,
		0x7633C35FDBC78BD2ULL,
		0x8508F45E93C323D0ULL,
		0x9DFFCD6D6EF61A6DULL,
		0xCF6AF9FE322C38F6ULL,
		0x883EACDCF2D8D9C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA047A00028108214ULL,
		0xA00E01030490A087ULL,
		0x002080280A102A00ULL,
		0x6411805809058000ULL,
		0x00085046038101D0ULL,
		0x95A545254ED60000ULL,
		0x8E2A184E22040072ULL,
		0x00322004D048D9C0ULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x680085F00C25A108ULL,
		0x0306787CDE7047F2ULL,
		0x5B68F53F36C5C649ULL,
		0x80BA99840B041E5CULL,
		0xC6B2AEA10D2002AFULL,
		0xEE3BAB6BAC520CE1ULL,
		0x8C0F1CA5A030BDE2ULL,
		0x5E37CAAE1808D755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0103939943FA71BCULL,
		0x61C2222D12054E08ULL,
		0x817F30D230EE6875ULL,
		0xC278A433DA185FAAULL,
		0x914FBB7C81A55753ULL,
		0xFC344F73E188E043ULL,
		0xE950629CABB034A1ULL,
		0x892A246DE5F6EFBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000819000202108ULL,
		0x0102202C12004600ULL,
		0x0168301230C44041ULL,
		0x803880000A001E08ULL,
		0x8002AA2001200203ULL,
		0xEC300B63A0000041ULL,
		0x88000084A03034A0ULL,
		0x0822002C0000C715ULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7DE5F3B578827BAULL,
		0xC1788C5C269D294FULL,
		0xFC257EE918B969BEULL,
		0x3B3DD84C356B053FULL,
		0x8A20EE4495940931ULL,
		0x14C6B8A548F9C711ULL,
		0x0E3E4E45A19572FEULL,
		0x5A6B7A7590A9A381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9216AF808B069A92ULL,
		0x4757F228B44B0186ULL,
		0x84ABB429CA99B2EBULL,
		0x3C43A17FE9ECAF4CULL,
		0x4020D5E6654C491BULL,
		0x78FD149CCACE5773ULL,
		0x20258C5DCD3AE3B5ULL,
		0x0AAAA7C6FA3C2A09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82160F0003000292ULL,
		0x4150800824090106ULL,
		0x84213429089920AAULL,
		0x3801804C2168050CULL,
		0x0020C44405040911ULL,
		0x10C4108448C84711ULL,
		0x00240C45811062B4ULL,
		0x0A2A224490282201ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD02A6D8BD35B8C8ULL,
		0x7AA45F7DD23982FEULL,
		0x265ECBA4AB2298B3ULL,
		0xACF64050D01D0202ULL,
		0xAE4D7B0EAE79203CULL,
		0x405FB95CB95E8C21ULL,
		0x1CC5FD2CFF20C547ULL,
		0xC7527CD011CABBD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB245AA128447E2EULL,
		0xF5CC76D9E299257AULL,
		0x5907995B8A732045ULL,
		0x3921433AA6FF5A91ULL,
		0x19BB82FC3B22A346ULL,
		0x3B07587A31F3A59EULL,
		0xC22A10214C9681AFULL,
		0x75EB55547FF45388ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA900028028043808ULL,
		0x70845659C219007AULL,
		0x000689008A220001ULL,
		0x28204010801D0200ULL,
		0x0809020C2A202004ULL,
		0x0007185831528400ULL,
		0x000010204C008107ULL,
		0x4542545011C01388ULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61D816B3D00EB689ULL,
		0xA8904FC0794E2FBFULL,
		0xE6ABF714FA479942ULL,
		0x244D39FC426D76CAULL,
		0x0FA0BB3D52A94FAAULL,
		0x6A019171DB9562A6ULL,
		0x979F18AA7CB7ED38ULL,
		0x71E641F10B89D90DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAEE871AE5456DD6ULL,
		0x69EFC447E946A630ULL,
		0x7B6BB993943305B4ULL,
		0xA4F40CB39EB598AEULL,
		0xE389462FFB896E4DULL,
		0xE9B6675BD450A8A7ULL,
		0x569A2451BCB52CFFULL,
		0x9F6DAEC77A03A3EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60C80612C0042480ULL,
		0x2880444069462630ULL,
		0x622BB11090030100ULL,
		0x244408B00225108AULL,
		0x0380022D52894E08ULL,
		0x68000151D01020A6ULL,
		0x169A00003CB52C38ULL,
		0x116400C10A01810DULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD01B2473884F3548ULL,
		0x6F0D27B2F0473C37ULL,
		0x3E91861E417B07EFULL,
		0x99FAB4F56B737AF7ULL,
		0x7EC61463BE959BCAULL,
		0x6500E91FC9FF18BFULL,
		0x20A92601A3ED615DULL,
		0x8B42B377B647192EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF195927417521CAAULL,
		0xF2B4A3B11F04AF96ULL,
		0x71D6749C54865F67ULL,
		0x997FE0B884BC5535ULL,
		0xBD2470BD106B17CEULL,
		0xC8F63977F77F40BEULL,
		0xF0A888387A55BBCBULL,
		0x9C9FC44BFF1C3C14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD011007000421408ULL,
		0x620423B010042C16ULL,
		0x3090041C40020767ULL,
		0x997AA0B000305035ULL,
		0x3C041021100113CAULL,
		0x40002917C17F00BEULL,
		0x20A8000022452149ULL,
		0x88028043B6041804ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AA33C7E2BEF756FULL,
		0x35B93A6A831C802DULL,
		0x86828147F3128BF1ULL,
		0x790DA82C53A030CFULL,
		0x0D13AA703AD43919ULL,
		0x68D6F23DBC1F7D1AULL,
		0x687B05C8F1D9D234ULL,
		0x070AE54E1FE12F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12CFD71BDFD21FF6ULL,
		0x0DA6E10CE89B690AULL,
		0x7C5AEA69313DFA8FULL,
		0x2714C201F0F17604ULL,
		0x41AB4CA389849CE2ULL,
		0x5A78F6C6A9EE1334ULL,
		0x8290C3E0D31E4D8CULL,
		0x65C878221FA18EF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0283141A0BC21566ULL,
		0x05A0200880180008ULL,
		0x0402804131108A81ULL,
		0x2104800050A03004ULL,
		0x0103082008841800ULL,
		0x4850F204A80E1110ULL,
		0x001001C0D1184004ULL,
		0x050860021FA10E20ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x136E66A01F430060ULL,
		0x440CC49659DBA992ULL,
		0x9EBF7AABC521FE39ULL,
		0x82CA91639AEE0B82ULL,
		0xCA5DF6CD73523E8DULL,
		0x6805C8A8BDA25AB4ULL,
		0x4B5D58994219559AULL,
		0xEE3556300D7E4A00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA649C5B37BE013F8ULL,
		0xB519997B35DE6104ULL,
		0xFE258FADE7EA8253ULL,
		0xE0615F06E17B8BB3ULL,
		0x153989E12D9077C6ULL,
		0xB423A6B4656EF33DULL,
		0x4600DD9AAE448A4BULL,
		0xB35900F65F67BFA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x024844A01B400060ULL,
		0x0408801211DA2100ULL,
		0x9E250AA9C5208211ULL,
		0x80401102806A0B82ULL,
		0x001980C121103684ULL,
		0x200180A025225234ULL,
		0x420058980200000AULL,
		0xA21100300D660A00ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CE0F96F0E03E5E6ULL,
		0xE7593C5554FC1811ULL,
		0x15C339F5DB1ACBC6ULL,
		0x95CCA1F1D9321346ULL,
		0x49AE0B4FDFAF3CB4ULL,
		0xDFFEF1C19DF36B36ULL,
		0xFF85CB526B6B5F54ULL,
		0x63E8289D19965A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A99B7BA6665C40ULL,
		0x5FAF752456DF5F92ULL,
		0x36E685B62D9AF93BULL,
		0xC7D2A1DEAA41206EULL,
		0xF6237744BA312CBEULL,
		0xE232CA6703ECAF03ULL,
		0xCE472688D2D65AB5ULL,
		0xDE55826FFE561844ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44A0996B06024440ULL,
		0x4709340454DC1810ULL,
		0x14C201B4091AC902ULL,
		0x85C0A1D088000046ULL,
		0x402203449A212CB4ULL,
		0xC232C04101E02B02ULL,
		0xCE05020042425A14ULL,
		0x4240000D18161800ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DD8A8213E5F3A73ULL,
		0x161027C24F158880ULL,
		0x1A9DA7CEEEC67347ULL,
		0x85233B7F69350480ULL,
		0x1B97E2BF3BF32FCDULL,
		0xB29F1CC94DE6D478ULL,
		0x919C9EAD71B12920ULL,
		0x6D330F13D51B9122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D04C48099167E06ULL,
		0x8CD6B205AD21249DULL,
		0xA00C312313283A36ULL,
		0x4C3401EDA774C9A0ULL,
		0x46F503066A8C2126ULL,
		0x4BFA4AC4B02D6E6CULL,
		0x90088A8B79150BE2ULL,
		0x39FBD8665DC25CB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D00800018163A02ULL,
		0x041022000D010080ULL,
		0x000C210202003206ULL,
		0x0420016D21340080ULL,
		0x029502062A802104ULL,
		0x029A08C000244468ULL,
		0x90088A8971110920ULL,
		0x2933080255021022ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7989D41CAAC945AULL,
		0xBF75BF8C75788B12ULL,
		0xC9F963CB1264FA02ULL,
		0x3CBC5582D28187F3ULL,
		0x71E27619B80321F4ULL,
		0x8D573CAFF83A9551ULL,
		0xC1D3BB868D9CE799ULL,
		0x602D0BEC4373C25DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD649255D1B818BULL,
		0xE231CC4703C60A45ULL,
		0xA1EA6A60EE325F32ULL,
		0x7087CED400B1DC06ULL,
		0x0E3F8FD2CA4ADE8EULL,
		0x9FF964DD3D432FEFULL,
		0x2AD9A20CA1701E28ULL,
		0x783DBC69088FA30BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x229009014808800AULL,
		0xA2318C0401400A00ULL,
		0x81E8624002205A02ULL,
		0x3084448000818402ULL,
		0x0022061088020084ULL,
		0x8D51248D38020541ULL,
		0x00D1A20481100608ULL,
		0x602D086800038209ULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9C16ED3E8A1E78FULL,
		0xB80A10C401170D6FULL,
		0x6D8462587DDBD826ULL,
		0xCDFFF7E29BE2D275ULL,
		0x8D74A64926617BFEULL,
		0x3477BF0239DC35B2ULL,
		0x93D8B7EB8890A726ULL,
		0x2FE3E24EC8D5862DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C02F9640047FD3ULL,
		0xC37F18DCB6D9335BULL,
		0x8B6E24F1CE735287ULL,
		0x1A2F3F925F1FB572ULL,
		0x33D3216B3B9E5161ULL,
		0xC58DFFB961E66F01ULL,
		0x5C4FA94C6C42E078ULL,
		0x3F36EB121BEB0606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8C02E9240006783ULL,
		0x800A10C40011014BULL,
		0x090420504C535006ULL,
		0x082F37821B029070ULL,
		0x0150204922005160ULL,
		0x0405BF0021C42500ULL,
		0x1048A1480800A020ULL,
		0x2F22E20208C10604ULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96DC947CFCE5B557ULL,
		0xBB9031C2A4B91679ULL,
		0xC3AAD3DEAA9D7904ULL,
		0x578ED4432F42A96EULL,
		0x0C160215856CE636ULL,
		0x12E589E9C264051CULL,
		0xF580F7A110AB461DULL,
		0x260458BF990F123CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3741FB631B501A8ULL,
		0xB4EBF6D203CE0229ULL,
		0xF1B6BAB09B7C3984ULL,
		0x33116D67D8A8CB53ULL,
		0xE3C8EE6408F6A7E3ULL,
		0x61A50AC9B834650EULL,
		0x22581D7A34322DECULL,
		0xDB51FD6AE398E4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9254143430A50100ULL,
		0xB08030C200880229ULL,
		0xC1A292908A1C3904ULL,
		0x1300444308008942ULL,
		0x000002040064A622ULL,
		0x00A508C98024050CULL,
		0x200015201022040CULL,
		0x0200582A81080020ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8304D2D231F61823ULL,
		0x965B65ADAC566F8BULL,
		0xCFC3F59BF18ED347ULL,
		0x591B5515C834A532ULL,
		0x247C688C35B699EFULL,
		0x419A2D9A0DF7C79AULL,
		0xF78FE2B727394FC9ULL,
		0x22C06BD68320B623ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE02B7228707385ECULL,
		0xE004A6F23F9AF68DULL,
		0x943A63ECAD47CD24ULL,
		0x060890392F2DB050ULL,
		0x0535369C47205D59ULL,
		0xB3B2AEC28E2B0C91ULL,
		0x0AAD05045FE935B4ULL,
		0xF2676B81D10A9384ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000520030720020ULL,
		0x800024A02C126689ULL,
		0x84026188A106C104ULL,
		0x000810110824A010ULL,
		0x0434208C05201949ULL,
		0x01922C820C230490ULL,
		0x028D000407290580ULL,
		0x22406B8081009200ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA3E30177C1BDFD6ULL,
		0x6BF9B598538E9D0EULL,
		0x27369FC8D7B32DE7ULL,
		0xC5A1238DD94EC751ULL,
		0x52F8145FCF2D7978ULL,
		0x000C1DF10C394923ULL,
		0x9DF483FD513E99D9ULL,
		0xF98F327C9CC5B771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x420F047DAC512346ULL,
		0x22E07BED35002E38ULL,
		0x503DAE1899433F44ULL,
		0xBA6444E46343B178ULL,
		0x3CF04BE3BD9EB3B1ULL,
		0xF8ECFCEDAF028927ULL,
		0x0FE4C6C1E932E678ULL,
		0x12FBBCFA8C0BC332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x420E00152C110346ULL,
		0x22E0318811000C08ULL,
		0x00348E0891032D44ULL,
		0x8020008441428150ULL,
		0x10F000438D0C3130ULL,
		0x000C1CE10C000923ULL,
		0x0DE482C141328058ULL,
		0x108B30788C018330ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE27B8EDCC7116FDCULL,
		0xC8F1E9C91D424EB4ULL,
		0xFE6B09816AA84A33ULL,
		0x28660B0D11A21D38ULL,
		0xF68925896FCFD4F6ULL,
		0xDDC9889ED927A827ULL,
		0x24DE0A44DC40C66CULL,
		0x2AB28AE0EF039AF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D94ED59E7E9B6F3ULL,
		0xFAE3F9AA42C5B2ACULL,
		0x697B428AE4381353ULL,
		0x1F205B7BD7075788ULL,
		0xDAA6342F24E5B9BFULL,
		0x6532B1768A4D3E50ULL,
		0x09A651D0D559D4D4ULL,
		0x86A197A2BCBFB67DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80108C58C70126D0ULL,
		0xC8E1E988004002A4ULL,
		0x686B008060280213ULL,
		0x08200B0911021508ULL,
		0xD280240924C590B6ULL,
		0x4500801688052800ULL,
		0x00860040D440C444ULL,
		0x02A082A0AC039270ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F8F6F5305D4BFF4ULL,
		0x85862B67E8E6BF4EULL,
		0x89E63E4B995515E4ULL,
		0xE16CB1D88A85C452ULL,
		0x7BD1D5B8036CBF2BULL,
		0x4079BB78D976D480ULL,
		0x502A6C34E9813C59ULL,
		0x710D624B4F24DBE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F1440CDD639C4EULL,
		0xF47F7ED5A9196AE7ULL,
		0x60171695561F6FD6ULL,
		0x25BE01EEEB31D804ULL,
		0x5437D0F560F0EF80ULL,
		0x6DAFB81FA047475AULL,
		0x70FB468B9EA9D0B2ULL,
		0x4F3626EF2DEA55A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4281440005409C44ULL,
		0x84062A45A8002A46ULL,
		0x00061601101505C4ULL,
		0x212C01C88A01C000ULL,
		0x5011D0B00060AF00ULL,
		0x4029B81880464400ULL,
		0x502A440088811010ULL,
		0x4104224B0D2051A2ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10625F52894A5438ULL,
		0xEBDFC5D90C8350C8ULL,
		0xA3E61CF5C1B5841BULL,
		0xFDA934915395D169ULL,
		0xF77AE7EF2D6D8AD3ULL,
		0x4F829C603E870578ULL,
		0x280D158C4D51FEFCULL,
		0x879F144AB79B9402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE68C66C509AF6C7ULL,
		0xFD789968316F18E3ULL,
		0xC7F4A6B23658CCAEULL,
		0x92F67073E29968A4ULL,
		0xA5EF89F99CE1B28EULL,
		0x925E6176A2E2D09FULL,
		0xC03515C8A10ABF47ULL,
		0x75FB0E61D422A89AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10604640000A5400ULL,
		0xE9588148000310C0ULL,
		0x83E404B00010840AULL,
		0x90A0301142914020ULL,
		0xA56A81E90C618282ULL,
		0x0202006022820018ULL,
		0x000515880100BE44ULL,
		0x059B044094028002ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB63D7814FE6AF330ULL,
		0xBC4CA86B203CA264ULL,
		0x753E79B29CDFF2CBULL,
		0xB14783919E032BBEULL,
		0x56749E1F54425A17ULL,
		0x7ADEDEE90F4D733BULL,
		0x8E348FB674D192EBULL,
		0x4584362E26F4AB35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EAF7CA0D2125B70ULL,
		0xB2DE8D1666B0156AULL,
		0x3547468694C54A84ULL,
		0x59CE05BCB15C0518ULL,
		0xB66605D6863186E9ULL,
		0xD2E70B1002A34632ULL,
		0x2C05044EF48774CAULL,
		0xA17FA74DF03C5466ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x962D7800D2025330ULL,
		0xB04C880220300060ULL,
		0x3506408294C54280ULL,
		0x1146019090000118ULL,
		0x1664041604000201ULL,
		0x52C60A0002014232ULL,
		0x0C040406748110CAULL,
		0x0104260C20340024ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0F549DDFFA59DFFULL,
		0x996FD11103F4A929ULL,
		0xCDD520C6DDEB6175ULL,
		0xDCA9BC909512A52AULL,
		0x82820851DA563C33ULL,
		0xDD2768122D26DC12ULL,
		0xC656F19745539DE8ULL,
		0x7B21C54B81708920ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03578E336C78256ULL,
		0x39DDB148FB83FFDEULL,
		0xA96CBB35F3FA256DULL,
		0x842B6310AB1243FAULL,
		0x8A318E071E6E4F6DULL,
		0x977A50C982351480ULL,
		0x60CB7F263AF3E781ULL,
		0xB56225C150F36B00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x803548C136858056ULL,
		0x194D91000380A908ULL,
		0x89442004D1EA2165ULL,
		0x842920108112012AULL,
		0x820008011A460C21ULL,
		0x9522400000241400ULL,
		0x4042710600538580ULL,
		0x3120054100700900ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCE284F7AFF65CACULL,
		0x8DC0CFE68BC4F68FULL,
		0x83D80770F319855EULL,
		0xB078DDE39E0B4959ULL,
		0x94FBC6E9BE72C679ULL,
		0x162A633FDF1A851CULL,
		0x2839341AC67A3C1FULL,
		0xD28C56ADA7DC92EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13DE66E27891F288ULL,
		0x2C88DE67566392A9ULL,
		0x11A023440319B71FULL,
		0x15B6BA2B5E83BD06ULL,
		0x633E38A795D04D50ULL,
		0x94FE8F90EF947B6CULL,
		0x86DDC68EF9C1FFF2ULL,
		0xA25BBFB02C430F6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10C204E228905088ULL,
		0x0C80CE6602409289ULL,
		0x018003400319851EULL,
		0x103098231E030900ULL,
		0x003A00A194504450ULL,
		0x142A0310CF10010CULL,
		0x0019040AC0403C12ULL,
		0x820816A02440026BULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7ADEE60F3A8A6E9ULL,
		0x182230362C8EA11CULL,
		0xF8061F3350BF42F8ULL,
		0x293DE559335335EDULL,
		0xFEA88AF826F5ECA6ULL,
		0x50E660EC6DE62C23ULL,
		0x2542181D82E5E975ULL,
		0xBDFEAFC57AD7FCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE524D434572F6264ULL,
		0x4923C9D20451538AULL,
		0x8CB1686FEDAA222DULL,
		0x2F11C4B37A26865DULL,
		0x205E22E89926CB38ULL,
		0x12B5E4BFE60FBD7DULL,
		0x12162D77940537BBULL,
		0xAC4F9FCEC1225D29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE524C42053282260ULL,
		0x0822001204000108ULL,
		0x8800082340AA0228ULL,
		0x2911C4113202044DULL,
		0x200802E80024C820ULL,
		0x10A460AC64062C21ULL,
		0x0002081580052131ULL,
		0xAC4E8FC440025C09ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA106AE72E254D96FULL,
		0x17FB7FC93F52CE67ULL,
		0x5CC1798F3E49C6D8ULL,
		0xAA819754BAB4CEE6ULL,
		0xC3656B694FADEBCEULL,
		0xC08E8B9B507A989BULL,
		0x8BDF4213E9B6F56CULL,
		0xB5D3568AFD358B17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC233568640C9318DULL,
		0x4F1B2C7B8252207BULL,
		0xDD45FA47895FA5B2ULL,
		0xECE9297F358453CCULL,
		0x62D2E30F92FF042CULL,
		0xEFB922A6766A3005ULL,
		0xEC6230CEE774365CULL,
		0xCB3EC4922300C778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800206024040110DULL,
		0x071B2C4902520063ULL,
		0x5C41780708498490ULL,
		0xA8810154308442C4ULL,
		0x4240630902AD000CULL,
		0xC0880282506A1001ULL,
		0x88420002E134344CULL,
		0x8112448221008310ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73CC7E4F44246084ULL,
		0xF1D6C29137B223FAULL,
		0xEFDF9BDEFE7D156BULL,
		0xB8172AF3DEDF12C1ULL,
		0xCB31AD076B78356CULL,
		0x496011247E13319AULL,
		0x941C09E9472CC212ULL,
		0xA9C998C73E5F0966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x153AAC962BE564E5ULL,
		0xFD1BC630F9F3DECFULL,
		0x8D2BE483236B92B5ULL,
		0x70CE5EABDEA7209DULL,
		0x6724B4A9885FB0E4ULL,
		0xF991C0DB572751B9ULL,
		0x714F12663A6B2484ULL,
		0x01ED89A998691EE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11082C0600246084ULL,
		0xF112C21031B202CAULL,
		0x8D0B808222691021ULL,
		0x30060AA3DE870081ULL,
		0x4320A40108583064ULL,
		0x4900000056031198ULL,
		0x100C006002280000ULL,
		0x01C9888118490862ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF64C238EB0676E4ULL,
		0xE0782761FE76E8A1ULL,
		0x6DABF7C39A67DE37ULL,
		0xBB003B2195D4A91CULL,
		0x9EFBE02BA8866542ULL,
		0xB2DC8D1FC53A8CE7ULL,
		0x6335B5E22CD2943EULL,
		0x33A21E2D751B1348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26EEEC85B202533CULL,
		0xEA14CAB5F407AAD4ULL,
		0x0B1E8EAA317E55F4ULL,
		0x17F4F27BCADA084CULL,
		0xFE431FBB68FE2950ULL,
		0x07E38C548B84EE89ULL,
		0x09BBB89F79E1012FULL,
		0x106CC221CDA9A2D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2664C000A2025224ULL,
		0xE0100221F406A880ULL,
		0x090A868210665434ULL,
		0x1300322180D0080CULL,
		0x9E43002B28862140ULL,
		0x02C08C1481008C81ULL,
		0x0131B08228C0002EULL,
		0x1020022145090240ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9DFCA0E76C9CB3FULL,
		0x726D31DB1719C91EULL,
		0xBC36BBEB5D646EF6ULL,
		0xFE5F1681D7BD9D6DULL,
		0xBDA130EF458B2765ULL,
		0x219A150728F6F0D8ULL,
		0xC9A717A8E044ED1AULL,
		0xA51EA91B402878E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB50C597107CBD8ULL,
		0x3FB983893751F019ULL,
		0x7BA6FCB54B270071ULL,
		0x2596140636B69BB2ULL,
		0x0749719AA0F62F39ULL,
		0x39AF4EAFA41F4ECCULL,
		0x31FA3FC1973B22A3ULL,
		0x82A47DC32074B1BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x499508087001CB18ULL,
		0x322901891711C018ULL,
		0x3826B8A149240070ULL,
		0x2416140016B49920ULL,
		0x0501308A00822721ULL,
		0x218A0407201640C8ULL,
		0x01A2178080002002ULL,
		0x80042903002030A2ULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3E0B40713E28A63ULL,
		0xDCAC8B140A9A108FULL,
		0x7B921E2C6F3D7950ULL,
		0xFDF4E3BAE2E6DB11ULL,
		0x0AA13AE81B257E17ULL,
		0xC61B77458E3E1950ULL,
		0x85C856E1F3F334AFULL,
		0xEA4E59F73540E3EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF491E7E3CD25FEB6ULL,
		0xAD793F413A32FA85ULL,
		0xB7FD4354416E627EULL,
		0xDDC70B8EE4A35FF6ULL,
		0xEAF9C9277EA9AD20ULL,
		0xCE779CE5F4399E00ULL,
		0x57D2A5DFE4CC211FULL,
		0x7601B23DF3C86732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF080A40301208A22ULL,
		0x8C280B000A121085ULL,
		0x33900204412C6050ULL,
		0xDDC4038AE0A25B10ULL,
		0x0AA108201A212C00ULL,
		0xC613144584381800ULL,
		0x05C004C1E0C0200FULL,
		0x6200103531406322ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2458C1D845A4D1BULL,
		0xB2894E671C442D9FULL,
		0x666F981ACAD14869ULL,
		0x6CB3B465283AC5DEULL,
		0xEC4F397B639025BCULL,
		0x4B0CDF4BDAF66F9EULL,
		0x250672A51F1253D7ULL,
		0xD38AD3D05684ED04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCE9DB3173B1B75AULL,
		0x523113E93DD77A33ULL,
		0x573AC0FA969CD8B0ULL,
		0xC51976F0E1368FC9ULL,
		0x5CA00B2BE96B8DADULL,
		0x978C8E80C6233518ULL,
		0x3EDC584817A8D31BULL,
		0xA4D95351F75BB68AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB04188110010051AULL,
		0x120102611C442813ULL,
		0x462A801A82904820ULL,
		0x44113460203285C8ULL,
		0x4C00092B610005ACULL,
		0x030C8E00C2222518ULL,
		0x2404500017005313ULL,
		0x808853505600A400ULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D38522A8AA2E790ULL,
		0x4C5710314B7D255EULL,
		0x8B4EE55A93BA43EBULL,
		0xC9E3E936D4B496CFULL,
		0xAF24EC454BB4A7B9ULL,
		0xC704E3DA19F488DEULL,
		0x4FF6B646691F41D9ULL,
		0xFE7B15A05D98C5CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x376E5351A846DC7EULL,
		0x0634BA90B6BFADB6ULL,
		0xD1772DACB2C5BC71ULL,
		0x88C7C7AE0C657858ULL,
		0x3D7594491386A90FULL,
		0xC6FF1768B49F63E7ULL,
		0x482B5DC679CA5968ULL,
		0x06440FCA57669F6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x352852008802C410ULL,
		0x04141010023D2516ULL,
		0x8146250892800061ULL,
		0x88C3C12604241048ULL,
		0x2D2484410384A109ULL,
		0xC6040348109400C6ULL,
		0x48221446690A4148ULL,
		0x064005805500854CULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x560A7F003419CE1DULL,
		0x7BF7DD79A71F4CCBULL,
		0x68C596FC29951D8FULL,
		0x89BB62EF9246BA9FULL,
		0x81748DAC47482FB9ULL,
		0x024E3BA58BAABF83ULL,
		0x3DE603D4EBF4E300ULL,
		0xDBECB6C2255888ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603F233A025233E3ULL,
		0x10A55E1B335D8B41ULL,
		0xB1F154B3A8657CC0ULL,
		0x6CE166276CE9D5D8ULL,
		0x6D6E6599DCA92205ULL,
		0x24E3A31D7F2B2BBBULL,
		0xBFDC3E21117A93D5ULL,
		0x5078C1B924C6C04AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400A230000100201ULL,
		0x10A55C19231D0841ULL,
		0x20C114B028051C80ULL,
		0x08A1622700409098ULL,
		0x0164058844082201ULL,
		0x004223050B2A2B83ULL,
		0x3DC4020001708300ULL,
		0x506880802440800AULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58C3249B06A54DB7ULL,
		0x844F9A08B97E32A7ULL,
		0x19071B8B58728464ULL,
		0xD7EF6C01C2083A5CULL,
		0x370C6063E1776B1AULL,
		0x935AD81753ABD94DULL,
		0xD2F48237EA9C88F8ULL,
		0xA8B88BADB41FE6C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE781244DCA1B69B0ULL,
		0x832B2C37603F8459ULL,
		0x55045BBD18FEFF3BULL,
		0xCA95DD30F1EEF74AULL,
		0x2262530E06231482ULL,
		0x287F9AED7600A3D7ULL,
		0x55F65A4819F587D3ULL,
		0xBC0F4674ED3889E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40812409020149B0ULL,
		0x800B0800203E0001ULL,
		0x11041B8918728420ULL,
		0xC2854C00C0083248ULL,
		0x2200400200230002ULL,
		0x005A980552008145ULL,
		0x50F40200089480D0ULL,
		0xA8080224A41880C0ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D26BD86AD564433ULL,
		0xA3FBB096841FC95DULL,
		0x0A7C09B9D48C161EULL,
		0xA74B9F3FC2F9D70DULL,
		0x792420D51EAD380DULL,
		0x3A1D64501488C32EULL,
		0x077A01099DB4DF5EULL,
		0x89CB61CFAB92ECE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4010F461328C7CE0ULL,
		0x44348FA075BE9CF0ULL,
		0x2A73E196F986E7C5ULL,
		0x1FE944A71AC42B18ULL,
		0xFA5E8AA6AA99E243ULL,
		0x8CF149C160A87D04ULL,
		0xFD49818C370E8D81ULL,
		0xA78F345F62B4F01EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000B40020044420ULL,
		0x00308080041E8850ULL,
		0x0A700190D0840604ULL,
		0x0749042702C00308ULL,
		0x780400840A892001ULL,
		0x0811404000884104ULL,
		0x0548010815048D00ULL,
		0x818B204F2290E002ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84BA857829CC08BEULL,
		0xBABE56064E049506ULL,
		0xCF63FDFC3B81A4B7ULL,
		0xFBC26030C195E534ULL,
		0xFBE5D33A1F97DDC8ULL,
		0x77BDD6D161224547ULL,
		0x3EDE5FB843BC7C9EULL,
		0xDEED2856C6E271CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84E64E1EEFDE96B6ULL,
		0x4BEC2EB9A9F726FCULL,
		0x8BA92C31E5B4FDACULL,
		0xBCBB821E516F981CULL,
		0x110BBCA7AE736880ULL,
		0xDBB46663B5EC53E6ULL,
		0xBCC71B4FB8AE3180ULL,
		0xBE034D5CB409D0BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84A2041829CC00B6ULL,
		0x0AAC060008040404ULL,
		0x8B212C302180A4A4ULL,
		0xB882001041058014ULL,
		0x110190220E134880ULL,
		0x53B4464121204146ULL,
		0x3CC61B0800AC3080ULL,
		0x9E0108548400508CULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0953BF872AAA41CDULL,
		0xC0EC70DAD277EF07ULL,
		0x58D548580F8245A7ULL,
		0xB504B89F2EE4B39BULL,
		0x492502ACC824FD69ULL,
		0xDD071A7167C48DA1ULL,
		0xAAF5E748FF9ECDB0ULL,
		0xFBED3789A523554EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9321A1A5697F85ULL,
		0xA42E48316ED1F6E3ULL,
		0x45F2083D1A2C6347ULL,
		0x1A110871138880CFULL,
		0x32B4E625EC3698DFULL,
		0xE2E9A97B25BF47E9ULL,
		0x5FECB99C29138B9DULL,
		0xEDAAB3EF376F016CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0913218120284185ULL,
		0x802C40104251E603ULL,
		0x40D008180A004107ULL,
		0x100008110280808BULL,
		0x00240224C8249849ULL,
		0xC0010871258405A1ULL,
		0x0AE4A10829128990ULL,
		0xE9A833892523014CULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x884C346FD0BFE6B2ULL,
		0xFD749ADA477CF288ULL,
		0xFDE87C6910245C4EULL,
		0x0AC103861423BAFAULL,
		0xE972BD3F99FD4518ULL,
		0x7A2195838980D9C2ULL,
		0x424FB5A83516F4F8ULL,
		0xD6131FD2D3DA345CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D1957583A446B9DULL,
		0xC5D1B6CE4CED44B3ULL,
		0x6217E02258005DC6ULL,
		0x3947A0CD8B10B562ULL,
		0xFED18BCEEE244A68ULL,
		0xDAE971BA777929D7ULL,
		0x9D4EBFDAF11B5D3CULL,
		0xA8F98E420B74F898ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8808144810046290ULL,
		0xC55092CA446C4080ULL,
		0x6000602010005C46ULL,
		0x084100840000B062ULL,
		0xE850890E88244008ULL,
		0x5A211182010009C2ULL,
		0x004EB58831125438ULL,
		0x80110E4203503018ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x880C5D115BB6FC45ULL,
		0x3CA9EA7CC1C33857ULL,
		0xCAE95116E8BD2B68ULL,
		0x0E999D60FA26CA7DULL,
		0x99F01B3FC97B005DULL,
		0x1F5822C3890374DAULL,
		0x53DAD7354D43B140ULL,
		0xA5F72DE3CF3C3A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x941EC8D4A0971FC6ULL,
		0x715FEAE942ECEB4FULL,
		0xB6A1420821535447ULL,
		0x69FA7C0F50C8AB2EULL,
		0xC8DCF81184AC8C7CULL,
		0x58CDC1C81D906EC8ULL,
		0x7AE9E8A4F7284208ULL,
		0x689CCD36DDFC7BE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800C481000961C44ULL,
		0x3009EA6840C02847ULL,
		0x82A1400020110040ULL,
		0x08981C0050008A2CULL,
		0x88D018118028005CULL,
		0x184800C0090064C8ULL,
		0x52C8C02445000000ULL,
		0x20940D22CD3C3A41ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47DA3352B37FE74BULL,
		0x499058178293FF9AULL,
		0xE9104B6574B7D4E7ULL,
		0x26E0088C051D138AULL,
		0x1D388B6CD0CDF34BULL,
		0x73209D2FDCC9FB09ULL,
		0x7D664C15A8B627C6ULL,
		0x161E2A86CC155A22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342688499F055649ULL,
		0x65E5EDB5C5F00752ULL,
		0x0009D11B95D2D00EULL,
		0xDCC3C12DEA886CE4ULL,
		0xD293BE23717DF081ULL,
		0xBE947117BAB27473ULL,
		0xD37DA55CF2945929ULL,
		0xF9A7C0D219857FD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0402004093054649ULL,
		0x4180481580900712ULL,
		0x000041011492D006ULL,
		0x04C0000C00080080ULL,
		0x10108A20504DF001ULL,
		0x3200110798807001ULL,
		0x51640414A0940100ULL,
		0x1006008208055A02ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CCD7014A4A53D84ULL,
		0x442AA4C1CA366CF8ULL,
		0x5862A261C148389EULL,
		0x7057293693DD840BULL,
		0xA40DA3478420CC03ULL,
		0xABDC863BD9EFC078ULL,
		0x0C64E4F7263FA78DULL,
		0xFBF4173EDE7A2710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5738F66AB9E7260ULL,
		0x38F1C2F4B22547FFULL,
		0x9166E6D95FAB2579ULL,
		0x2D8B616C018D7E37ULL,
		0x6468525F60FBA6CAULL,
		0x520493A481986F15ULL,
		0xAD62E44B68063B4AULL,
		0x515BDF02947302C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24410004A0843000ULL,
		0x002080C0822444F8ULL,
		0x1062A24141082018ULL,
		0x20032124018D0403ULL,
		0x2408024700208402ULL,
		0x0204822081884010ULL,
		0x0C60E44320062308ULL,
		0x5150170294720200ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431B95882B6388A8ULL,
		0xDB0BA33E3277A833ULL,
		0x917D7C2B297A54BAULL,
		0xCF3A6F481D62125EULL,
		0xBEDB9A817A0BE50AULL,
		0x31831ABA279A689FULL,
		0x799CD41F4675D966ULL,
		0xA90B06FA1A44EF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E02F1CAC20E12FULL,
		0x99B0DCE81F1B3A17ULL,
		0x70D6C41DFF09CBF7ULL,
		0xE8C11A0E183E31FFULL,
		0xCE2CD406C00B0679ULL,
		0xF638CB7C08BC9A1FULL,
		0xD037589D2612087DULL,
		0x06A61FD8ECA4299CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4200050828208028ULL,
		0x9900802812132813ULL,
		0x10544409290840B2ULL,
		0xC8000A081822105EULL,
		0x8E089000400B0408ULL,
		0x30000A380098081FULL,
		0x5014501D06100864ULL,
		0x000206D80804290CULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA807F0C163826A7ULL,
		0x37DF47337C81658AULL,
		0x5DCD3DA290FA4416ULL,
		0x54C673D4697FC77BULL,
		0xF009875C6CA6D6C1ULL,
		0x14DE938D9EBA2625ULL,
		0xA7C486609982E860ULL,
		0xB1C30FE9EBA2F1DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EACF7B00645431ULL,
		0x6C4C0E9E7DD5861AULL,
		0x989B5C436B7B07BAULL,
		0x491EFB34185ACAA3ULL,
		0xD7A1010B4F9E6C5EULL,
		0x6AE41F25BD1BBC6CULL,
		0xD925505AB487DA87ULL,
		0x8EE5E344ECA35B21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2804F0800200421ULL,
		0x244C06127C81040AULL,
		0x18891C02007A0412ULL,
		0x40067314085AC223ULL,
		0xD00101084C864440ULL,
		0x00C413059C1A2424ULL,
		0x810400409082C800ULL,
		0x80C10340E8A25100ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F8449873CA52F1DULL,
		0x182AC2C12EF1A7CBULL,
		0x66E53EF06E8AFCE7ULL,
		0x8E7958CB964BBE19ULL,
		0x991EBE6129CA5C2BULL,
		0x808C6F02B2B0E5E5ULL,
		0xEC3010A364679620ULL,
		0x07389E58045C7B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8932AFDBD7B49AEULL,
		0x02CBE8C6383111E1ULL,
		0xF379F41C8E5C59CBULL,
		0x6732EA4D72501AECULL,
		0xAB20348118CA115AULL,
		0x6ED8F8CB1940F2C6ULL,
		0xE0FB4AC55B84858FULL,
		0x2C7D78D13AC2F3ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288008853C21090CULL,
		0x000AC0C0283101C1ULL,
		0x626134100E0858C3ULL,
		0x0630484912401A08ULL,
		0x8900340108CA100AULL,
		0x008868021000E0C4ULL,
		0xE030008140048400ULL,
		0x043818500040732CULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA422A9701851A38DULL,
		0xCFB99C106DF51AB5ULL,
		0xA6F0B381F35EFFCAULL,
		0x2C1159BB179B3A1AULL,
		0xC36EA59FAA286126ULL,
		0x7B1C0D34DCEFC284ULL,
		0xDE9B82F49487CA3BULL,
		0xB478D8DE14149469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0630F876EDA724C2ULL,
		0x8F12F2EDEABE556BULL,
		0x7F48DDF6AF06E140ULL,
		0x61FD86EB678E3DA3ULL,
		0x20AED88F0F1CEFF1ULL,
		0xAE555DB4A096B765ULL,
		0xC98FC8C72A9F37AFULL,
		0xC085590D0C70512AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0420A87008012080ULL,
		0x8F10900068B41021ULL,
		0x26409180A306E140ULL,
		0x201100AB078A3802ULL,
		0x002E808F0A086120ULL,
		0x2A140D3480868204ULL,
		0xC88B80C40087022BULL,
		0x8000580C04101028ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F232973658F326FULL,
		0x0807A7524D4CB0F8ULL,
		0x24ADF253C4D9ED2FULL,
		0x52B1442B96C47885ULL,
		0xE9FC9D84815672E4ULL,
		0x9AE3533B2BD89DDDULL,
		0xBC8572673EA997CBULL,
		0x8568FACCD2F58A8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B5D7313411D299ULL,
		0x63095212F308AB67ULL,
		0xE4D9D8B0FF492A55ULL,
		0xC506C3424E368F81ULL,
		0xDB99CE3C17EC2037ULL,
		0x492682B20AD0ED32ULL,
		0x37842E3CD7A9D03BULL,
		0x6DCDD6BF3EB3D904ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6521013124011209ULL,
		0x000102124108A060ULL,
		0x2489D010C4492805ULL,
		0x4000400206040881ULL,
		0xC9988C0401442024ULL,
		0x082202320AD08D10ULL,
		0x3484222416A9900BULL,
		0x0548D28C12B18804ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34E5599C0EAE6C8ULL,
		0xC2AEDA81D971953FULL,
		0x8A453B356ADF8BB7ULL,
		0x43CBD9C8A55B6669ULL,
		0xB31A80330637AB55ULL,
		0x513F43B8EAE01C5AULL,
		0xD0DB78310997F154ULL,
		0x8BB62054E517DD82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0C903376CE684FULL,
		0xF5624C4EE0EAB00DULL,
		0xEAB7A7BEB4F68320ULL,
		0xBB5B84DD4445B76DULL,
		0x48088799C1769287ULL,
		0x11FEE7A429B5C4A4ULL,
		0xFC6B360B087A37CEULL,
		0xC53A061C79EC58EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030C101140CA6048ULL,
		0xC0224800C060900DULL,
		0x8A05233420D68320ULL,
		0x034B80C804412669ULL,
		0x0008801100368205ULL,
		0x113E43A028A00400ULL,
		0xD04B300108123144ULL,
		0x8132001461045882ULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE0BD09B10607FCDULL,
		0x4FE0634013918E47ULL,
		0x5532BF8D70F90C6FULL,
		0x83EE4840B49982AEULL,
		0x33B2076D789B128AULL,
		0x3F10CDEDEBA27554ULL,
		0x8E7751838BC9BCC7ULL,
		0x72DD8DFA9B0930DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DF0E59EDFBAC735ULL,
		0x7C5F3287B4C0C253ULL,
		0x03A19F5FDC263789ULL,
		0x4F284ED3BB193305ULL,
		0x416D0A3D4242C95AULL,
		0xF6B1891D56DC0949ULL,
		0xA5A66A6E751B94A3ULL,
		0x301182C3482EC000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C00C09A10204705ULL,
		0x4C40220010808243ULL,
		0x01209F0D50200409ULL,
		0x03284840B0190204ULL,
		0x0120022D4002000AULL,
		0x3610890D42800140ULL,
		0x8426400201099483ULL,
		0x301180C208080000ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79C896081328DC0AULL,
		0xE2DBCAD3C3F4045AULL,
		0xD3462BF9EC75DA7DULL,
		0x7617D4AAA11ACBCBULL,
		0x6D95ED46AD560E4CULL,
		0xE290EC9366DB011BULL,
		0x6164993A755C2936ULL,
		0x8D42A826B3149963ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA20635420C2B90CDULL,
		0xD3C34A588A227DEFULL,
		0x14E8213FAC0EFC8AULL,
		0xF3F44127FD19BA61ULL,
		0x3651E782081B8347ULL,
		0x5CB344F7013C93D0ULL,
		0x34CD1B978C2B6EC7ULL,
		0x93404B5F98116D0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000140000289008ULL,
		0xC2C34A508220044AULL,
		0x10402139AC04D808ULL,
		0x72144022A1188A41ULL,
		0x2411E50208120244ULL,
		0x4090449300180110ULL,
		0x2044191204082806ULL,
		0x8140080690100901ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x908AB99ADFBB7294ULL,
		0x39063D3A0747B06FULL,
		0x77A234E4AC04D138ULL,
		0xCC697FBE9ED3EECFULL,
		0xFC02722369325858ULL,
		0xC9C3FA8E8653CCCDULL,
		0xE4E3B01AC618FA0DULL,
		0xAFB327E36D46C23CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6641F25B6FF7368ULL,
		0x7533E14AEABEB914ULL,
		0x404E9A9419CAB13AULL,
		0xC42AB38B3EA7BDC0ULL,
		0xEF746670C8A30430ULL,
		0x6A4CBEAA4B92FD53ULL,
		0x60DD2B46E1894873ULL,
		0xF00073FDB9D514F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9000190096BB7200ULL,
		0x3102210A0206B004ULL,
		0x4002108408009138ULL,
		0xC428338A1E83ACC0ULL,
		0xEC00622048220010ULL,
		0x4840BA8A0212CC41ULL,
		0x60C12002C0084801ULL,
		0xA00023E129440030ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF0665A20E39BF58ULL,
		0xC98C091CB373C39AULL,
		0x1B64452574A468D5ULL,
		0x046DB52CE254E74CULL,
		0x9D71CFD6CBE73B71ULL,
		0x6A023BE161C54E55ULL,
		0x71BA4589C4920A74ULL,
		0xD4829485AB3C3454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB25558363328859EULL,
		0x74B0FC57EC0DB94EULL,
		0xDBA4D53CB53BDF5AULL,
		0x0AAB775C4CC94761ULL,
		0xF8E877D3BA7D31D2ULL,
		0x0FA2DCCF2E4B6097ULL,
		0xCE1B530D9A88F3BFULL,
		0x8F46F2488B22592AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA204402202288518ULL,
		0x40800814A001810AULL,
		0x1B24452434204850ULL,
		0x0029350C40404740ULL,
		0x986047D28A653150ULL,
		0x0A0218C120414015ULL,
		0x401A410980800234ULL,
		0x840290008B201000ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFBEFBF690318C7BULL,
		0xCA236F7142505B94ULL,
		0xF75A24B7623F484FULL,
		0xC94EDE39CF90FE5CULL,
		0x4776B9410C6511AEULL,
		0x098EFB8BB41C2C5AULL,
		0x8D5C6BFB49D051D6ULL,
		0x4570AE4299F7D32AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790A7CA8FE749F0EULL,
		0xBB8A177538027B02ULL,
		0xF07E1D5C3F59210AULL,
		0x646F2126497F6376ULL,
		0xC8E1208CDBFCFE63ULL,
		0x45F1CCF49C15E98AULL,
		0xA7A07E5FF9FEE1CDULL,
		0x99637F2B15971F18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x590A78A090308C0AULL,
		0x8A02077100005B00ULL,
		0xF05A04142219000AULL,
		0x404E002049106254ULL,
		0x4060200008641022ULL,
		0x0180C8809414280AULL,
		0x85006A5B49D041C4ULL,
		0x01602E0211971308ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF48BC95FD1073E3FULL,
		0x531655AC601605F9ULL,
		0x58EDBF28F1A8A776ULL,
		0x7743F7D7A8AF817EULL,
		0xD35A1AD3BC670EC9ULL,
		0x52B49850A5E450E5ULL,
		0x2ACA50AD9D67FDC9ULL,
		0x5433FBAB3A198D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6B465DA793307EULL,
		0x791B41AEC62E8619ULL,
		0x8A7B85D416CC358AULL,
		0xA433E4E88F876C05ULL,
		0xB8AFC87DD77D8A89ULL,
		0x9E48BBF859398A6DULL,
		0x8193AE8CBCB3AC33ULL,
		0xB9E4FEFA27328936ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x740B405D8103303EULL,
		0x511241AC40060419ULL,
		0x0869850010882502ULL,
		0x2403E4C088870004ULL,
		0x900A085194650A89ULL,
		0x1200985001200065ULL,
		0x0082008C9C23AC01ULL,
		0x1020FAAA22108916ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ED4D7FF4AF823BCULL,
		0xA026C3798C68A0A1ULL,
		0xFDBF409DE0E3470CULL,
		0x8A0E7986F36CB132ULL,
		0x5B2C331FD00CB0A5ULL,
		0xE89439AA9A201B4BULL,
		0x4375662987F91298ULL,
		0xBDEFB27939F790F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC79E23DDD1CE8AEULL,
		0x080ADE6980E1F6B5ULL,
		0x4555F3325E79C17DULL,
		0x41D3483A1BD1609DULL,
		0x1938C2348F1A849BULL,
		0x95CAD7711CB5D8C4ULL,
		0x920A7DC139CF5B0AULL,
		0x7EE3F7C0D831EC00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C50C23D481820ACULL,
		0x0002C2698060A0A1ULL,
		0x451540104061410CULL,
		0x0002480213402010ULL,
		0x1928021480088081ULL,
		0x8080112018201840ULL,
		0x0200640101C91208ULL,
		0x3CE3B24018318000ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33F64F6230D59B1FULL,
		0x08207C0F48BCB622ULL,
		0x75D1C943A7C07BECULL,
		0xD2390CA42911AE12ULL,
		0xBD9CFBF8B1A9F0F3ULL,
		0x68FC463215A1C5EDULL,
		0xEC39D962B5D61952ULL,
		0xAB9971BC5D6836ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69424ECB4CC72684ULL,
		0x810530719EAF57BBULL,
		0x97B1812EFDF2138CULL,
		0x0246C4476083FF99ULL,
		0x794B4CD60E093A14ULL,
		0x719ACFD4B91E0E08ULL,
		0xFD603E5D9ACB3513ULL,
		0x0AD178F872EC7EBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21424E4200C50204ULL,
		0x0000300108AC1622ULL,
		0x15918102A5C0138CULL,
		0x020004042001AE10ULL,
		0x390848D000093010ULL,
		0x6098461011000408ULL,
		0xEC20184090C21112ULL,
		0x0A9170B8506836ACULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C775316B381E4FDULL,
		0xECEA91DA01A5800FULL,
		0xCF2725C4DAEDF825ULL,
		0xA64EF93469B7A7D9ULL,
		0xA0D3F1B736D702E6ULL,
		0x3874B958A3333D6DULL,
		0x14988ED41FA4A33CULL,
		0x9DCA4F6080ABA53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5176FDFF44031A4AULL,
		0xA9B47E004A9B74A9ULL,
		0x45321ABA39F05080ULL,
		0x8CB11E5C0B8B966CULL,
		0x69481414E9538F63ULL,
		0x5EA60F4A0B6670D2ULL,
		0x76E1E4ED9F3C7663ULL,
		0x7B7D38F4DF03BC22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1076511600010048ULL,
		0xA8A0100000810009ULL,
		0x4522008018E05000ULL,
		0x8400181409838648ULL,
		0x2040101420530262ULL,
		0x1824094803223040ULL,
		0x148084C41F242220ULL,
		0x194808608003A422ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6892089C50A50CDULL,
		0x8A1BF1533F8B1C70ULL,
		0x752512E8B37E18CEULL,
		0x97542FCC13B678E5ULL,
		0x0EEF4C03A7F255B4ULL,
		0x8237F635AF822AADULL,
		0x9F0B4100F918C8DFULL,
		0xA8DA0DB312025C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F95D6E342575AC0ULL,
		0x64AE5A1F06D7CBF0ULL,
		0xD771151E88D44DC0ULL,
		0xF4754226BE89CBF6ULL,
		0x1325A3F10E0FB275ULL,
		0x0728D3055D403094ULL,
		0x6387DF8374A7FED9ULL,
		0xEA25EC573C1DFEDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26810081400250C0ULL,
		0x000A501306830870ULL,
		0x55211008805408C0ULL,
		0x94540204128048E4ULL,
		0x0225000106021034ULL,
		0x0220D2050D002084ULL,
		0x030341007000C8D9ULL,
		0xA8000C1310005C14ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}