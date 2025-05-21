#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x074829B1E16A583EULL,
		0x5B7A3C29B3E4F518ULL,
		0xC5B83FB425C58D5DULL,
		0x0BE6D5D7284F8914ULL,
		0x441E8BB8AE6D2A77ULL,
		0xB61370CF4C75CD80ULL,
		0x0A06A008D72570A8ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3A414D8F0B52C1F0ULL,
		0xDBD1E14D9F27A8C0ULL,
		0x2DC1FDA12E2C6AEAULL,
		0x5F36AEB9427C48A6ULL,
		0x20F45DC5736953B8ULL,
		0xB09B867A63AE6C02ULL,
		0x50350046B92B8545ULL,
		0x0000000000000000ULL
	}};
	int shift = 3;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x142DEB6B84E3D0D0ULL,
		0xE03D969144DDD777ULL,
		0x3E32CBF96EBB5528ULL,
		0x015A1D30AD028AABULL,
		0x56D0118B3FA5B6A4ULL,
		0xB95A5EE054B8DBFEULL,
		0xF98134FB83BA332FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6D709C7A1A00000ULL,
		0x2D2289BBAEEE285BULL,
		0x97F2DD76AA51C07BULL,
		0x3A615A0515567C65ULL,
		0x23167F4B6D4802B4ULL,
		0xBDC0A971B7FCADA0ULL,
		0x69F70774665F72B4ULL,
		0x000000000001F302ULL
	}};
	shift = 17;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC7E0F680EACD9620ULL,
		0xCBF3B968ADC469A4ULL,
		0xFBB90D0D5AC12CBCULL,
		0x3E857EC1381893FFULL,
		0x60C34A973EA59C44ULL,
		0xD59E72972FC40BD0ULL,
		0xE19FD328B0892228ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9620000000000000ULL,
		0x69A4C7E0F680EACDULL,
		0x2CBCCBF3B968ADC4ULL,
		0x93FFFBB90D0D5AC1ULL,
		0x9C443E857EC13818ULL,
		0x0BD060C34A973EA5ULL,
		0x2228D59E72972FC4ULL,
		0x0000E19FD328B089ULL
	}};
	shift = 48;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x65A7F70F5EAC582DULL,
		0x92C1E43F73BF99EAULL,
		0xA75233EBD687BD9DULL,
		0x6400522DA345AB38ULL,
		0x81365B7424DA036EULL,
		0x3075E15F6E6157E1ULL,
		0x41288F5183583AFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD58B05A00000000ULL,
		0xE77F33D4CB4FEE1EULL,
		0xAD0F7B3B2583C87EULL,
		0x468B56714EA467D7ULL,
		0x49B406DCC800A45BULL,
		0xDCC2AFC3026CB6E8ULL,
		0x06B075F860EBC2BEULL,
		0x0000000082511EA3ULL
	}};
	shift = 33;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x39E3F58D0027637DULL,
		0x1D7D49B6FF106518ULL,
		0x5FFD76DD2383C8A6ULL,
		0x2CDF97BD20D4009AULL,
		0x710E99A605A09372ULL,
		0x42959991571AF0A1ULL,
		0xF8E993ED7E644234ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EC6FA0000000000ULL,
		0x20CA3073C7EB1A00ULL,
		0x07914C3AFA936DFEULL,
		0xA80134BFFAEDBA47ULL,
		0x4126E459BF2F7A41ULL,
		0x35E142E21D334C0BULL,
		0xC88468852B3322AEULL,
		0x000001F1D327DAFCULL
	}};
	shift = 41;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB9CEAE4837C0258ULL,
		0xB34DFCF29723C277ULL,
		0xFD0C4DAD685808E3ULL,
		0xBA14B418F0AD1954ULL,
		0x0F9E702F358B7338ULL,
		0xD027D795EC03734DULL,
		0x5421C1DDDE352AEDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0960000000000000ULL,
		0x09DEAE73AB920DF0ULL,
		0x238ECD37F3CA5C8FULL,
		0x6553F43136B5A160ULL,
		0xCCE2E852D063C2B4ULL,
		0xCD343E79C0BCD62DULL,
		0xABB7409F5E57B00DULL,
		0x00015087077778D4ULL
	}};
	shift = 50;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD2024E7491C51212ULL,
		0xBE9754FECB8762E4ULL,
		0x4FF10CA52C9AFEF8ULL,
		0xFB67472B06FD23CAULL,
		0x8DDB61A902496196ULL,
		0x3D212FCD85012B64ULL,
		0x245A5CD32DB94F10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2120000000000000ULL,
		0x2E4D2024E7491C51ULL,
		0xEF8BE9754FECB876ULL,
		0x3CA4FF10CA52C9AFULL,
		0x196FB67472B06FD2ULL,
		0xB648DDB61A902496ULL,
		0xF103D212FCD85012ULL,
		0x000245A5CD32DB94ULL
	}};
	shift = 52;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9E0794828F2AA1F1ULL,
		0x021440A995B0964CULL,
		0xB70AD5221C9A59BBULL,
		0xA6B451A6411EF65BULL,
		0x00B9B3D09DA481A7ULL,
		0xDE3BF4FC5E149170ULL,
		0xAE5EFE9AC5B729DBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA87C400000000000ULL,
		0x25932781E520A3CAULL,
		0x966EC085102A656CULL,
		0xBD96EDC2B5488726ULL,
		0x2069E9AD14699047ULL,
		0x245C002E6CF42769ULL,
		0xCA76F78EFD3F1785ULL,
		0x00002B97BFA6B16DULL
	}};
	shift = 46;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x13C967C3D0AC3822ULL,
		0xC1A655645EA44A2BULL,
		0x281D9F950E7BEFDCULL,
		0xECD680996F161A98ULL,
		0xF4DEF7D07FE35F80ULL,
		0x7762B4B9674DAC4BULL,
		0xEACB2EEE92357211ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42B0E0880000000ULL,
		0x17A9128AC4F259F0ULL,
		0x439EFBF730699559ULL,
		0x5BC586A60A0767E5ULL,
		0x1FF8D7E03B35A026ULL,
		0x59D36B12FD37BDF4ULL,
		0xA48D5C845DD8AD2EULL,
		0x000000003AB2CBBBULL
	}};
	shift = 30;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x652E164DB75B8F87ULL,
		0xA22D295D2DE29601ULL,
		0x508EB2B6F7A36558ULL,
		0x3BDE2CCF8B035C26ULL,
		0x08D6603E6572B007ULL,
		0xA2CC88D89D775DF4ULL,
		0x7160BB1188CB5ECFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2970B26DBADC7C38ULL,
		0x11694AE96F14B00BULL,
		0x847595B7BD1B2AC5ULL,
		0xDEF1667C581AE132ULL,
		0x46B301F32B958039ULL,
		0x166446C4EBBAEFA0ULL,
		0x8B05D88C465AF67DULL,
		0x0000000000000003ULL
	}};
	shift = 3;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x59D3FEA4D0E02244ULL,
		0xFC54BABBC7304675ULL,
		0x7B63C0943BC22F32ULL,
		0xDAF0F321252DD743ULL,
		0x5A7E6577CA13392CULL,
		0xE84BF537BFD1F7E4ULL,
		0x069F805B3F8FC321ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A7FD49A1C04488ULL,
		0xF8A975778E608CEAULL,
		0xF6C7812877845E65ULL,
		0xB5E1E6424A5BAE86ULL,
		0xB4FCCAEF94267259ULL,
		0xD097EA6F7FA3EFC8ULL,
		0x0D3F00B67F1F8643ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2C30933E1D199ACDULL,
		0x5ECA03AED6E3002CULL,
		0x68F560D854BFBA2AULL,
		0x942D8D88ACB88FA0ULL,
		0x8BE1D112983FB8A4ULL,
		0x296E8C219D0637BEULL,
		0xEDC489E312EBD3E4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8CCD66800000000ULL,
		0xB7180161618499F0ULL,
		0xA5FDD152F6501D76ULL,
		0x65C47D0347AB06C2ULL,
		0xC1FDC524A16C6C45ULL,
		0xE831BDF45F0E8894ULL,
		0x975E9F214B74610CULL,
		0x000000076E244F18ULL
	}};
	shift = 35;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC496F0D1DEE85466ULL,
		0x1ED8BA0BFCAD0E74ULL,
		0x37C05E859AED6F0FULL,
		0x12ED43A9F91990A0ULL,
		0x328EC885BA425901ULL,
		0x8060B0B75FCC150AULL,
		0x613CAA035DAE5DFFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77BA151980000000ULL,
		0xFF2B439D3125BC34ULL,
		0x66BB5BC3C7B62E82ULL,
		0x7E4664280DF017A1ULL,
		0x6E90964044BB50EAULL,
		0xD7F305428CA3B221ULL,
		0xD76B977FE0182C2DULL,
		0x00000000184F2A80ULL
	}};
	shift = 30;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE3FAF968B5DD6DEAULL,
		0xE3451A378AA09340ULL,
		0xD144CDDBB69E3CBBULL,
		0xFF646121937EE0B7ULL,
		0xDA0B465B88E4B105ULL,
		0x79BFE601C7425B2DULL,
		0xFCE51878BEA006CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F50000000000000ULL,
		0x9A071FD7CB45AEEBULL,
		0xE5DF1A28D1BC5504ULL,
		0x05BE8A266EDDB4F1ULL,
		0x882FFB23090C9BF7ULL,
		0xD96ED05A32DC4725ULL,
		0x366BCDFF300E3A12ULL,
		0x0007E728C3C5F500ULL
	}};
	shift = 51;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0836A667EB05A58CULL,
		0x6600C7A23DB9394CULL,
		0x095F5FF8971F6F9AULL,
		0x62B47FAF0D04C5E2ULL,
		0xE1809C42DB435221ULL,
		0xF337263E5229DC92ULL,
		0xB4FD9194E150B098ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB05A58C000000000ULL,
		0xDB9394C0836A667EULL,
		0x71F6F9A6600C7A23ULL,
		0xD04C5E2095F5FF89ULL,
		0xB43522162B47FAF0ULL,
		0x229DC92E1809C42DULL,
		0x150B098F337263E5ULL,
		0x0000000B4FD9194EULL
	}};
	shift = 36;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x472910332499AF35ULL,
		0x19A85389C3DE2DBEULL,
		0xCBF37DC606F731C3ULL,
		0x91F7D23FE08A31EEULL,
		0x92A71FC05D20E804ULL,
		0x6788699CCBB0CF4CULL,
		0x1B5D8DBEDFB4DF76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32499AF350000000ULL,
		0x9C3DE2DBE4729103ULL,
		0x606F731C319A8538ULL,
		0xFE08A31EECBF37DCULL,
		0x05D20E80491F7D23ULL,
		0xCCBB0CF4C92A71FCULL,
		0xEDFB4DF766788699ULL,
		0x0000000001B5D8DBULL
	}};
	shift = 28;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6E6D8D9801E461B2ULL,
		0x5364FC07A472C904ULL,
		0x9F79626741B5C209ULL,
		0x367D633103482829ULL,
		0xBF178F56043C9579ULL,
		0xD27945FD770708C4ULL,
		0xBD86BF1186066345ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x8DCDB1B3003C8C36ULL,
		0x2A6C9F80F48E5920ULL,
		0x33EF2C4CE836B841ULL,
		0x26CFAC6620690505ULL,
		0x97E2F1EAC08792AFULL,
		0xBA4F28BFAEE0E118ULL,
		0x17B0D7E230C0CC68ULL
	}};
	shift = 61;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0828CAA4649C98A4ULL,
		0xECAA8D66A9640D5DULL,
		0xFBC78E5D6A4AEBC3ULL,
		0x7966C3A792F1EEE5ULL,
		0xCFFA40F42B6E9739ULL,
		0x650C8EF7EA129728ULL,
		0xC7CDC5A220487815ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324E4C5200000000ULL,
		0x54B206AE84146552ULL,
		0xB52575E1F65546B3ULL,
		0xC978F772FDE3C72EULL,
		0x15B74B9CBCB361D3ULL,
		0xF5094B9467FD207AULL,
		0x10243C0AB286477BULL,
		0x0000000063E6E2D1ULL
	}};
	shift = 31;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x29BAE5EBD1DC2E7EULL,
		0xA0AA39B43C0F0270ULL,
		0x8D10FF49D6FE4694ULL,
		0x2A44A2211F130534ULL,
		0x24942998A443AA58ULL,
		0x2E6C415484F14C95ULL,
		0x9D159BE40830C57FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD7A3B85CFC0000ULL,
		0x7368781E04E05375ULL,
		0xFE93ADFC8D294154ULL,
		0x44423E260A691A21ULL,
		0x5331488754B05489ULL,
		0x82A909E2992A4928ULL,
		0x37C810618AFE5CD8ULL,
		0x0000000000013A2BULL
	}};
	shift = 17;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5F6D11A96EBEDD1AULL,
		0x93B93E5615EF9603ULL,
		0x68B2B4516ACD3B66ULL,
		0xDEBE999B4B4B58B3ULL,
		0xC0DDE45F0BED0DDAULL,
		0x1789E40C2F038D0AULL,
		0x0FDC556B204C485AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB746800000000000ULL,
		0xE580D7DB446A5BAFULL,
		0x4ED9A4EE4F95857BULL,
		0xD62CDA2CAD145AB3ULL,
		0x4376B7AFA666D2D2ULL,
		0xE342B0377917C2FBULL,
		0x121685E279030BC0ULL,
		0x000003F7155AC813ULL
	}};
	shift = 46;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x89EBA1E08E91A732ULL,
		0x31B8D119B3F4FAD5ULL,
		0xF479CFE8667B288AULL,
		0xF341866EEFA0B951ULL,
		0xD2030DD177B3146EULL,
		0x5CCB39DB3059EC45ULL,
		0x976302B9C157C563ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA732000000000000ULL,
		0xFAD589EBA1E08E91ULL,
		0x288A31B8D119B3F4ULL,
		0xB951F479CFE8667BULL,
		0x146EF341866EEFA0ULL,
		0xEC45D2030DD177B3ULL,
		0xC5635CCB39DB3059ULL,
		0x0000976302B9C157ULL
	}};
	shift = 48;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDE18B415481F77BEULL,
		0xABB81A2796538AF8ULL,
		0x36A780589FB147E8ULL,
		0xB126C2E2B78228C5ULL,
		0x4CD00DCB1123B452ULL,
		0x65AAFABF14ABD8F4ULL,
		0xC5BA836105E59F73ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055207DDEF800000ULL,
		0x89E594E2BE37862DULL,
		0x1627EC51FA2AEE06ULL,
		0xB8ADE08A314DA9E0ULL,
		0x72C448ED14AC49B0ULL,
		0xAFC52AF63D133403ULL,
		0xD8417967DCD96ABEULL,
		0x0000000000316EA0ULL
	}};
	shift = 22;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x04B5C72F318C241FULL,
		0x9EF2732DB86BE7CBULL,
		0xB02CF2B0E0D41730ULL,
		0x69B5B2E84A8EE82FULL,
		0x9497E842000C7DF1ULL,
		0x4B6575B509CD0236ULL,
		0x2082B28786B07FA9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF318C241F0000000ULL,
		0xDB86BE7CB04B5C72ULL,
		0x0E0D417309EF2732ULL,
		0x84A8EE82FB02CF2BULL,
		0x2000C7DF169B5B2EULL,
		0x509CD02369497E84ULL,
		0x786B07FA94B6575BULL,
		0x0000000002082B28ULL
	}};
	shift = 28;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD62243E8090EDD98ULL,
		0x28B67C85C9D36692ULL,
		0x8EF3BC0C03B3F9ECULL,
		0x91CA23CC01C83B96ULL,
		0x462486D3C722C9A7ULL,
		0xE4774E50EA9B1632ULL,
		0xCCCC34BE6E9082A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DBB300000000000ULL,
		0xA6CD25AC4487D012ULL,
		0x67F3D8516CF90B93ULL,
		0x90772D1DE7781807ULL,
		0x45934F2394479803ULL,
		0x362C648C490DA78EULL,
		0x210547C8EE9CA1D5ULL,
		0x0000019998697CDDULL
	}};
	shift = 41;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF545D3FDA67127D9ULL,
		0xB42181A48E677E64ULL,
		0xF03734C53E85377DULL,
		0x6A86EACA79005C46ULL,
		0x7C7DD8170F505A43ULL,
		0x8E46325E8CA6D2FDULL,
		0xCC65E1B2751145DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74FF699C49F64000ULL,
		0x60692399DF993D51ULL,
		0xCD314FA14DDF6D08ULL,
		0xBAB29E401711BC0DULL,
		0x7605C3D41690DAA1ULL,
		0x8C97A329B4BF5F1FULL,
		0x786C9D4451776391ULL,
		0x0000000000003319ULL
	}};
	shift = 14;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x444D6EE9A63D3BABULL,
		0x73E7EE9592558509ULL,
		0xA69D858539B032A2ULL,
		0x3F2E8CF60C21B697ULL,
		0xE8CE2BF40D4D0F32ULL,
		0xA17683518959C14FULL,
		0x02009584D3A2B198ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E9DD5800000000ULL,
		0x92AC284A226B774DULL,
		0xCD8195139F3F74ACULL,
		0x610DB4BD34EC2C29ULL,
		0x6A687991F97467B0ULL,
		0x4ACE0A7F46715FA0ULL,
		0x9D158CC50BB41A8CULL,
		0x000000001004AC26ULL
	}};
	shift = 35;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9F25873A89C4FAD5ULL,
		0x0B4D4E3A18AF7013ULL,
		0x7D27158463559CD7ULL,
		0x9B688F19F1686F4FULL,
		0xB2481FA85C3BCC11ULL,
		0xAF9CCBC27043D792ULL,
		0x768FC4039E60BF5DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A8000000000000ULL,
		0x809CF92C39D44E27ULL,
		0xE6B85A6A71D0C57BULL,
		0x7A7BE938AC231AACULL,
		0x608CDB4478CF8B43ULL,
		0xBC959240FD42E1DEULL,
		0xFAED7CE65E13821EULL,
		0x0003B47E201CF305ULL
	}};
	shift = 51;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2A8BC48B2F2A0A7BULL,
		0x786D27721E65CC1AULL,
		0xB97571134FBE2003ULL,
		0xC0EDBEB7813D77CBULL,
		0x056C34E268638BCDULL,
		0x8641EB4691F4F47EULL,
		0x8E029449BC1BD856ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC48B2F2A0A7B0000ULL,
		0x27721E65CC1A2A8BULL,
		0x71134FBE2003786DULL,
		0xBEB7813D77CBB975ULL,
		0x34E268638BCDC0EDULL,
		0xEB4691F4F47E056CULL,
		0x9449BC1BD8568641ULL,
		0x0000000000008E02ULL
	}};
	shift = 16;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC3A8554EBA1CC80ULL,
		0x2B23F0E504D5F4E9ULL,
		0xD1F86BA23B6D5DBFULL,
		0xEB9336ABEC1BEF23ULL,
		0x9951C24B6C93867EULL,
		0x3BDB1E04654B81E2ULL,
		0xDE23186E87DC3CA5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E64000000000000ULL,
		0xAFA74DE1D42AA75DULL,
		0x6AEDF9591F872826ULL,
		0xDF791E8FC35D11DBULL,
		0x9C33F75C99B55F60ULL,
		0x5C0F14CA8E125B64ULL,
		0xE1E529DED8F0232AULL,
		0x000006F118C3743EULL
	}};
	shift = 43;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9966AA959A28E32DULL,
		0xA68445E96E8DDBBEULL,
		0xC84490587EE61CB7ULL,
		0x2A46A415A1BA9A63ULL,
		0xD61FCC36DC6E7568ULL,
		0x5F92B59FB9898998ULL,
		0xA154FF366742A787ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD552B3451C65A0ULL,
		0xD088BD2DD1BB77D3ULL,
		0x08920B0FDCC396F4ULL,
		0x48D482B437534C79ULL,
		0xC3F986DB8DCEAD05ULL,
		0xF256B3F73131331AULL,
		0x2A9FE6CCE854F0EBULL,
		0x0000000000000014ULL
	}};
	shift = 5;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA3DF7E1CD49B12E5ULL,
		0x64D5965D5288B3AFULL,
		0x364FC94B952478A8ULL,
		0x9EAD92E00D81B98BULL,
		0x7428B1939BABFEE5ULL,
		0x74A700956A92E568ULL,
		0x68F54470734A3AFEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC39A93625CA00000ULL,
		0xCBAA511675F47BEFULL,
		0x2972A48F150C9AB2ULL,
		0x5C01B0373166C9F9ULL,
		0x3273757FDCB3D5B2ULL,
		0x12AD525CAD0E8516ULL,
		0x8E0E69475FCE94E0ULL,
		0x00000000000D1EA8ULL
	}};
	shift = 21;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8087756813FE7C7EULL,
		0x6720B67E13D305A0ULL,
		0x8146661059E1E874ULL,
		0x04551063B28A6218ULL,
		0x582CBED8634A052BULL,
		0x3127A7EBA5EA0A11ULL,
		0x648A7BF784717470ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F00000000000000ULL,
		0xD04043BAB409FF3EULL,
		0x3A33905B3F09E982ULL,
		0x0C40A333082CF0F4ULL,
		0x95822A8831D94531ULL,
		0x08AC165F6C31A502ULL,
		0x381893D3F5D2F505ULL,
		0x0032453DFBC238BAULL
	}};
	shift = 55;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75070E947EAF503EULL,
		0xD6F383FD2D4862B1ULL,
		0xD1F0206298803581ULL,
		0xBDB3CDC9F98264E1ULL,
		0x657FCA368A5584FCULL,
		0x273DD7A9AFADCC31ULL,
		0x765CE7D97158E917ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A3F57A81F00000ULL,
		0x1FE96A43158BA838ULL,
		0x0314C401AC0EB79CULL,
		0x6E4FCC13270E8F81ULL,
		0x51B452AC27E5ED9EULL,
		0xBD4D7D6E618B2BFEULL,
		0x3ECB8AC748B939EEULL,
		0x000000000003B2E7ULL
	}};
	shift = 19;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6B70819235610945ULL,
		0xE33319806DC419B1ULL,
		0xEA80EB5AFE457269ULL,
		0xEE8F12A50EE07164ULL,
		0xE17167DD807DC2F4ULL,
		0xC1952785E8BCD4BBULL,
		0xC97CCB35A5EADFDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1400000000000000ULL,
		0xC5ADC20648D58425ULL,
		0xA78CCC6601B71066ULL,
		0x93AA03AD6BF915C9ULL,
		0xD3BA3C4A943B81C5ULL,
		0xEF85C59F7601F70BULL,
		0x6B06549E17A2F352ULL,
		0x0325F32CD697AB7FULL
	}};
	shift = 58;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x28618B6F24567777ULL,
		0x950117DCD196D94CULL,
		0xD52A5EB24C889BCCULL,
		0xEFABCEA4AA31EBC0ULL,
		0xF34CDAEC05D4F6B9ULL,
		0x289945023C384559ULL,
		0xFB0E75E608F0F6E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F2456777700000ULL,
		0x7DCD196D94C28618ULL,
		0xEB24C889BCC95011ULL,
		0xEA4AA31EBC0D52A5ULL,
		0xAEC05D4F6B9EFABCULL,
		0x5023C384559F34CDULL,
		0x5E608F0F6E528994ULL,
		0x00000000000FB0E7ULL
	}};
	shift = 20;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x135D07A63D11C273ULL,
		0xC7C13DD09A82440BULL,
		0xB06D1E9757EFA8C2ULL,
		0xA5D6F69FDD53DDC9ULL,
		0x0DE907D3342E04B1ULL,
		0x89BF9737BF94E80CULL,
		0xF85D16695A03A16AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x89AE83D31E88E139ULL,
		0x63E09EE84D412205ULL,
		0xD8368F4BABF7D461ULL,
		0xD2EB7B4FEEA9EEE4ULL,
		0x06F483E99A170258ULL,
		0x44DFCB9BDFCA7406ULL,
		0x7C2E8B34AD01D0B5ULL
	}};
	shift = 63;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x36CA6B3DB0677AF2ULL,
		0x361A270F8969841DULL,
		0x0656719BA97E92FEULL,
		0xD3F13B8DB85697FCULL,
		0x7A9A468A51CA7932ULL,
		0xF52E0880B35C0028ULL,
		0x5A6558C729B1290EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ACF6C19DEBC8000ULL,
		0x89C3E25A61074DB2ULL,
		0x9C66EA5FA4BF8D86ULL,
		0x4EE36E15A5FF0195ULL,
		0x91A294729E4CB4FCULL,
		0x82202CD7000A1EA6ULL,
		0x5631CA6C4A43BD4BULL,
		0x0000000000001699ULL
	}};
	shift = 14;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3886FB189EAFAD5DULL,
		0x3275F41433995476ULL,
		0xC9287A1406F87534ULL,
		0xDA7FB4EFDD94E01AULL,
		0xC2E9AF9E26ACDE2EULL,
		0xB2D56506E0CF0AEEULL,
		0x20E988758496E57FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x8E21BEC627ABEB57ULL,
		0x0C9D7D050CE6551DULL,
		0xB24A1E8501BE1D4DULL,
		0xB69FED3BF7653806ULL,
		0xB0BA6BE789AB378BULL,
		0xECB55941B833C2BBULL,
		0x083A621D6125B95FULL
	}};
	shift = 62;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDC67BB1A2A923EF8ULL,
		0x6D656BE87D997F79ULL,
		0x2249AC138AE16916ULL,
		0x390E812CCE57214EULL,
		0xEFA9B17DC559E44CULL,
		0xF2CE07C0375D95A7ULL,
		0x6FAE3E94E0C7305DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF000000000000000ULL,
		0xF3B8CF763455247DULL,
		0x2CDACAD7D0FB32FEULL,
		0x9C4493582715C2D2ULL,
		0x98721D02599CAE42ULL,
		0x4FDF5362FB8AB3C8ULL,
		0xBBE59C0F806EBB2BULL,
		0x00DF5C7D29C18E60ULL
	}};
	shift = 57;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3E2EEBD44030A3B8ULL,
		0x3B4288DC79A8FB10ULL,
		0x44CA09501B0A3288ULL,
		0x4C98B0BD987BC4B5ULL,
		0x01EF99C755A2F1F3ULL,
		0x5F3786FE5B54BB84ULL,
		0xB6BFA0CAEDEAE21AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x81F1775EA201851DULL,
		0x41DA1446E3CD47D8ULL,
		0xAA26504A80D85194ULL,
		0x9A64C585ECC3DE25ULL,
		0x200F7CCE3AAD178FULL,
		0xD2F9BC37F2DAA5DCULL,
		0x05B5FD06576F5710ULL
	}};
	shift = 59;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE2C7229C4D902CE3ULL,
		0xA3CC25E676AA923DULL,
		0xE8172584E6926043ULL,
		0x445A427B271D981EULL,
		0x41781EBE61591F87ULL,
		0xCF60D26BE2133FE0ULL,
		0x98D4277384180071ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1C8A713640B38CULL,
		0x8F309799DAAA48F7ULL,
		0xA05C96139A49810EULL,
		0x116909EC9C76607BULL,
		0x05E07AF985647E1DULL,
		0x3D8349AF884CFF81ULL,
		0x63509DCE106001C7ULL,
		0x0000000000000002ULL
	}};
	shift = 2;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x71B7DA29E803F972ULL,
		0x3D365478C4D91FAFULL,
		0xCB44296DA662652BULL,
		0xA1A42D210681D45FULL,
		0x265B5F42C7C13B1BULL,
		0x1CC191705E0EDA27ULL,
		0x5CEA96E198F6D711ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A7A00FE5C800000ULL,
		0x1E313647EBDC6DF6ULL,
		0x5B6998994ACF4D95ULL,
		0x4841A07517F2D10AULL,
		0xD0B1F04EC6E8690BULL,
		0x5C1783B689C996D7ULL,
		0xB8663DB5C4473064ULL,
		0x0000000000173AA5ULL
	}};
	shift = 22;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB8F35535DCF9BC1FULL,
		0x6FA2A1566422DD0DULL,
		0xBBC08AF036D1B6C2ULL,
		0x832DD58EAA8A9FBAULL,
		0x2AF1F5D406165BCCULL,
		0x191D77A7F9C11DC3ULL,
		0x16EC8565F6377928ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E6AA6BB9F3783E0ULL,
		0xF4542ACC845BA1B7ULL,
		0x78115E06DA36D84DULL,
		0x65BAB1D55153F757ULL,
		0x5E3EBA80C2CB7990ULL,
		0x23AEF4FF3823B865ULL,
		0xDD90ACBEC6EF2503ULL,
		0x0000000000000002ULL
	}};
	shift = 5;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0D7C305CE2123A3AULL,
		0x999CAE4DBAF2CAA7ULL,
		0xCF7E2DF818689164ULL,
		0xF0EF58A3597626C6ULL,
		0x63A0B786D57F143DULL,
		0xA457FEEE9A0E4DCDULL,
		0x63077F6BB0536BBAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8E800000000000ULL,
		0xB2A9C35F0C173884ULL,
		0x245926672B936EBCULL,
		0x89B1B3DF8B7E061AULL,
		0xC50F7C3BD628D65DULL,
		0x937358E82DE1B55FULL,
		0xDAEEA915FFBBA683ULL,
		0x000018C1DFDAEC14ULL
	}};
	shift = 46;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x05C0EC25213A63A7ULL,
		0xF9C245C41AFD6D8BULL,
		0x8955E1D80963B936ULL,
		0x9D52ABC5EA89DC28ULL,
		0x3B5C94F5F7219F03ULL,
		0x3003B931D03B2D14ULL,
		0x5EA5725D9776A1D9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC25213A63A70000ULL,
		0x45C41AFD6D8B05C0ULL,
		0xE1D80963B936F9C2ULL,
		0xABC5EA89DC288955ULL,
		0x94F5F7219F039D52ULL,
		0xB931D03B2D143B5CULL,
		0x725D9776A1D93003ULL,
		0x0000000000005EA5ULL
	}};
	shift = 16;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6729939CD1D6076CULL,
		0xBF6CFFD599376D30ULL,
		0xBF9B23F4B27135FBULL,
		0x6EA90BA3956AB50CULL,
		0x108D07BA49E2429FULL,
		0x8337A460668F0CCBULL,
		0x80AF461B7A420E6DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6076C0000000000ULL,
		0x376D306729939CD1ULL,
		0x7135FBBF6CFFD599ULL,
		0x6AB50CBF9B23F4B2ULL,
		0xE2429F6EA90BA395ULL,
		0x8F0CCB108D07BA49ULL,
		0x420E6D8337A46066ULL,
		0x00000080AF461B7AULL
	}};
	shift = 40;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1E1D3EE3CFD120C2ULL,
		0x397DEAB1467262D9ULL,
		0x29085DE74CC2A3E2ULL,
		0x5AEBBC3ED1722BB1ULL,
		0xDE6E52B33C94AB2AULL,
		0xEC5A648A0F85075AULL,
		0x12F1DC13FA71392EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7E8906100000000ULL,
		0xA339316C8F0E9F71ULL,
		0xA66151F11CBEF558ULL,
		0x68B915D894842EF3ULL,
		0x9E4A55952D75DE1FULL,
		0x07C283AD6F372959ULL,
		0xFD389C97762D3245ULL,
		0x000000000978EE09ULL
	}};
	shift = 31;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x292F0945ACFEA5A3ULL,
		0x046CD1CFC77BD592ULL,
		0xE38ACAD9940EC081ULL,
		0xBA89B1220F707DAFULL,
		0xDD28BDB70CD9B777ULL,
		0x62C17E379E971F1EULL,
		0xA91D510F6ECEE397ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4600000000000000ULL,
		0x24525E128B59FD4BULL,
		0x0208D9A39F8EF7ABULL,
		0x5FC71595B3281D81ULL,
		0xEF751362441EE0FBULL,
		0x3DBA517B6E19B36EULL,
		0x2EC582FC6F3D2E3EULL,
		0x01523AA21EDD9DC7ULL
	}};
	shift = 57;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4DE7A67C5B80CFA8ULL,
		0x2C030C8491940C0DULL,
		0xAFD9EC4E286A2F66ULL,
		0x0223DE64C02BA921ULL,
		0x7B7948AE6F2FB272ULL,
		0xE590F4EE8C5CF73FULL,
		0x6969405FF1D2B554ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E033EA000000000ULL,
		0x46503035379E99F1ULL,
		0xA1A8BD98B00C3212ULL,
		0x00AEA486BF67B138ULL,
		0xBCBEC9C8088F7993ULL,
		0x3173DCFDEDE522B9ULL,
		0xC74AD5539643D3BAULL,
		0x00000001A5A5017FULL
	}};
	shift = 34;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x156E17D8A77D49ADULL,
		0x6E6E22A74E1B2097ULL,
		0x947AC4EABE70BFF0ULL,
		0x6ABBC02A4C78EFD3ULL,
		0x30D3053FB2429D96ULL,
		0x66D322DD77637CD5ULL,
		0x6656391DBFCDB356ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE17D8A77D49AD000ULL,
		0xE22A74E1B2097156ULL,
		0xAC4EABE70BFF06E6ULL,
		0xBC02A4C78EFD3947ULL,
		0x3053FB2429D966ABULL,
		0x322DD77637CD530DULL,
		0x6391DBFCDB35666DULL,
		0x0000000000000665ULL
	}};
	shift = 12;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x474B24EA3A2AFCB3ULL,
		0xC84F36C105BEC5F9ULL,
		0x938050B31EAC5088ULL,
		0x267C36A979D13946ULL,
		0xDE492CFA59B22439ULL,
		0x1CC83F6983E0E4D8ULL,
		0x24C315F21636C7AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9649D47455F966ULL,
		0x909E6D820B7D8BF2ULL,
		0x2700A1663D58A111ULL,
		0x4CF86D52F3A2728DULL,
		0xBC9259F4B3644872ULL,
		0x39907ED307C1C9B1ULL,
		0x49862BE42C6D8F5CULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCAD2024897B22801ULL,
		0x92A73D529FA37525ULL,
		0x4C12ABB234DAB268ULL,
		0x7B272DCA67844619ULL,
		0x7D1EFF136D202BB4ULL,
		0x692B8513E75871C2ULL,
		0x8C3A9220FC395BBEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0080000000000000ULL,
		0x92E56901244BD914ULL,
		0x3449539EA94FD1BAULL,
		0x0CA60955D91A6D59ULL,
		0xDA3D9396E533C223ULL,
		0xE13E8F7F89B69015ULL,
		0xDF3495C289F3AC38ULL,
		0x00461D49107E1CADULL
	}};
	shift = 55;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9031D302090D1F45ULL,
		0x6820395FA4BE5116ULL,
		0x8BB5C1F6FE3A0AFBULL,
		0x375DC6E43EABB4C4ULL,
		0x25ADC8E61C499BBDULL,
		0x12F5DB71D4EE9C28ULL,
		0x2E897EF414E288A3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC74C0824347D1400ULL,
		0x80E57E92F9445A40ULL,
		0xD707DBF8E82BEDA0ULL,
		0x771B90FAAED3122EULL,
		0xB7239871266EF4DDULL,
		0xD76DC753BA70A096ULL,
		0x25FBD0538A228C4BULL,
		0x00000000000000BAULL
	}};
	shift = 10;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC3F449FD7E2D29DULL,
		0xE432B49C476EB495ULL,
		0x9DB03DFBF11FA7DEULL,
		0xD8D53759E2AD67CEULL,
		0x8AF420D0A82E5E3AULL,
		0x1700428BBA90C339ULL,
		0x26D3B18E074862C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1694E8000000000ULL,
		0xB75A4AFE1FA24FEBULL,
		0x8FD3EF72195A4E23ULL,
		0x56B3E74ED81EFDF8ULL,
		0x172F1D6C6A9BACF1ULL,
		0x48619CC57A106854ULL,
		0xA431608B802145DDULL,
		0x0000001369D8C703ULL
	}};
	shift = 39;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07C338638C488379ULL,
		0xE047F3CDCA68495EULL,
		0x6A0F4B5AC94DC9B3ULL,
		0x941A44F0D801EA12ULL,
		0x63E8E9CA26B166DDULL,
		0x5658266B3C5CF566ULL,
		0xC0D6CA4044AEB323ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C62441BC800000ULL,
		0xE6E53424AF03E19CULL,
		0xAD64A6E4D9F023F9ULL,
		0x786C00F5093507A5ULL,
		0xE51358B36ECA0D22ULL,
		0x359E2E7AB331F474ULL,
		0x2022575991AB2C13ULL,
		0x0000000000606B65ULL
	}};
	shift = 23;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B4AACC762C36E62ULL,
		0x1CE7272C4B7B7483ULL,
		0xA656E32305755582ULL,
		0x62F3615CFFC69FF2ULL,
		0x6A14E222F8078B95ULL,
		0xBC1B4A01B67DE366ULL,
		0xA62DB1B1724D101DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9880000000000000ULL,
		0x20CED2AB31D8B0DBULL,
		0x608739C9CB12DEDDULL,
		0xFCA995B8C8C15D55ULL,
		0xE558BCD8573FF1A7ULL,
		0xD99A853888BE01E2ULL,
		0x076F06D2806D9F78ULL,
		0x00298B6C6C5C9344ULL
	}};
	shift = 54;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD591F507C9F527F3ULL,
		0xEB492CDA52AE4A78ULL,
		0x989EFDB05F00DA65ULL,
		0xEB16F1380FD27513ULL,
		0x6D8361173F2D8024ULL,
		0x59C11443C53A4E62ULL,
		0xC66326A26E584210ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23EA0F93EA4FE600ULL,
		0x9259B4A55C94F1ABULL,
		0x3DFB60BE01B4CBD6ULL,
		0x2DE2701FA4EA2731ULL,
		0x06C22E7E5B0049D6ULL,
		0x8228878A749CC4DBULL,
		0xC64D44DCB08420B3ULL,
		0x000000000000018CULL
	}};
	shift = 9;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x26DC9D965B40FA56ULL,
		0x120C8857D8A3DD3FULL,
		0xF3EE9B95DA7EBF72ULL,
		0x35601A98663D6328ULL,
		0xB6B960564F53AE70ULL,
		0xDD597E5CE4DE6205ULL,
		0x9207AEE18C8AEFE5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB000000000000000ULL,
		0xF936E4ECB2DA07D2ULL,
		0x90906442BEC51EE9ULL,
		0x479F74DCAED3F5FBULL,
		0x81AB00D4C331EB19ULL,
		0x2DB5CB02B27A9D73ULL,
		0x2EEACBF2E726F310ULL,
		0x04903D770C64577FULL
	}};
	shift = 59;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB20C822B55331170ULL,
		0x85C68C36B9680C61ULL,
		0x0658EBA994945ADFULL,
		0x57C51C41B12406FFULL,
		0x6DF6306193610D20ULL,
		0xB02157DFD82A7A03ULL,
		0xDBDBC5A14D2C0281ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x988B800000000000ULL,
		0x40630D9064115AA9ULL,
		0xA2D6FC2E3461B5CBULL,
		0x2037F832C75D4CA4ULL,
		0x086902BE28E20D89ULL,
		0x53D01B6FB1830C9BULL,
		0x60140D810ABEFEC1ULL,
		0x000006DEDE2D0A69ULL
	}};
	shift = 43;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC993998861F2C46FULL,
		0xAF4EEDCFC7E7B59EULL,
		0xA1C0930F8E152AFBULL,
		0x4307BD08D98F8752ULL,
		0x74F78B694A0F05EBULL,
		0xF8846627C4740D16ULL,
		0x1808DB9E8C43FBDDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3998861F2C46F000ULL,
		0xEEDCFC7E7B59EC99ULL,
		0x0930F8E152AFBAF4ULL,
		0x7BD08D98F8752A1CULL,
		0x78B694A0F05EB430ULL,
		0x46627C4740D1674FULL,
		0x8DB9E8C43FBDDF88ULL,
		0x0000000000000180ULL
	}};
	shift = 12;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6482ED685C02A2C0ULL,
		0x08CDC543417DA850ULL,
		0xF2F6DA424C40894CULL,
		0x3936FCE0C76BCAD7ULL,
		0x509902191BF99C9AULL,
		0x868E5AC26797AE37ULL,
		0x5580EA436EBC4E43ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C02A2C00000000ULL,
		0x3417DA8506482ED6ULL,
		0x24C40894C08CDC54ULL,
		0x0C76BCAD7F2F6DA4ULL,
		0x91BF99C9A3936FCEULL,
		0x26797AE375099021ULL,
		0x36EBC4E43868E5ACULL,
		0x0000000005580EA4ULL
	}};
	shift = 28;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5093A2949F9E51EEULL,
		0x59C536603AF4F0FAULL,
		0x6FC2B1CC39C29E69ULL,
		0xE538B81A4279F8FBULL,
		0x059ACA7EE92F1E1EULL,
		0x89AC57B6DECF3314ULL,
		0xE0A46AB1DBC19675ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12745293F3CA3DCULL,
		0xB38A6CC075E9E1F4ULL,
		0xDF85639873853CD2ULL,
		0xCA71703484F3F1F6ULL,
		0x0B3594FDD25E3C3DULL,
		0x1358AF6DBD9E6628ULL,
		0xC148D563B7832CEBULL,
		0x0000000000000001ULL
	}};
	shift = 1;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x617636BFFBD8DFF6ULL,
		0x497B96E175ED96C5ULL,
		0x4D3FE1992D8AB203ULL,
		0xBB80A692F85B7D10ULL,
		0x14D7A2AF3663E800ULL,
		0xF9EC212ECB32B02AULL,
		0xCBE46C00CD1BEF8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF600000000000000ULL,
		0xC5617636BFFBD8DFULL,
		0x03497B96E175ED96ULL,
		0x104D3FE1992D8AB2ULL,
		0x00BB80A692F85B7DULL,
		0x2A14D7A2AF3663E8ULL,
		0x8AF9EC212ECB32B0ULL,
		0x00CBE46C00CD1BEFULL
	}};
	shift = 56;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5CAB9565C77A7AFDULL,
		0x2AD96710CF55B5D3ULL,
		0x2F4270E3BB954DBAULL,
		0x84CCF718368C4E44ULL,
		0xF65F6C8D8166CA52ULL,
		0xE77EA6FB78D86ECDULL,
		0xABBAAD9B1F1BBC2BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9565C77A7AFD0000ULL,
		0x6710CF55B5D35CABULL,
		0x70E3BB954DBA2AD9ULL,
		0xF718368C4E442F42ULL,
		0x6C8D8166CA5284CCULL,
		0xA6FB78D86ECDF65FULL,
		0xAD9B1F1BBC2BE77EULL,
		0x000000000000ABBAULL
	}};
	shift = 16;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6EE191B8E6ADB154ULL,
		0xA117152DB7FA2FD9ULL,
		0xFF9E6A36F0F24872ULL,
		0x4CB77DCFC8B5A861ULL,
		0x301052103249AC08ULL,
		0x049601625D1550B2ULL,
		0x69FC15754F15F8B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB154000000000000ULL,
		0x2FD96EE191B8E6ADULL,
		0x4872A117152DB7FAULL,
		0xA861FF9E6A36F0F2ULL,
		0xAC084CB77DCFC8B5ULL,
		0x50B2301052103249ULL,
		0xF8B4049601625D15ULL,
		0x000069FC15754F15ULL
	}};
	shift = 48;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5DF25B77D435B8C9ULL,
		0x703ABB97C1658305ULL,
		0x4695CB3DF351333AULL,
		0x4869B2AAFFE90C23ULL,
		0x2C737F4B038C112DULL,
		0xDA19B1660D6CC20FULL,
		0x0CFA0D0D833FCC36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBBEA1ADC6480000ULL,
		0xDCBE0B2C182AEF92ULL,
		0x59EF9A8999D381D5ULL,
		0x9557FF48611A34AEULL,
		0xFA581C60896A434DULL,
		0x8B306B661079639BULL,
		0x686C19FE61B6D0CDULL,
		0x00000000000067D0ULL
	}};
	shift = 19;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4E62A3C437DFBD5FULL,
		0x2910C83F5328D0C5ULL,
		0x0AA2D72EA1FCC81FULL,
		0xCCE2E16A4E747C70ULL,
		0x150D4CC72B5958D9ULL,
		0x8DDBE82443D9861EULL,
		0xE751B1B5549DE9B7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A8F10DF7EF57C0ULL,
		0x44320FD4CA343153ULL,
		0xA8B5CBA87F3207CAULL,
		0x38B85A939D1F1C02ULL,
		0x435331CAD6563673ULL,
		0x76FA0910F6618785ULL,
		0xD46C6D55277A6DE3ULL,
		0x0000000000000039ULL
	}};
	shift = 6;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x721EB0366A3F93C3ULL,
		0xA463AF277E446FF5ULL,
		0x2B3F23FEC0255364ULL,
		0x30020AD041094F6FULL,
		0xCA50C6EAB38E5F62ULL,
		0x2C0AA3698A5C538FULL,
		0x838B2C6E1D53136AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A8FE4F0C0000000ULL,
		0xDF911BFD5C87AC0DULL,
		0xB00954D92918EBC9ULL,
		0x104253DBCACFC8FFULL,
		0xACE397D88C0082B4ULL,
		0x629714E3F29431BAULL,
		0x8754C4DA8B02A8DAULL,
		0x0000000020E2CB1BULL
	}};
	shift = 30;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x875816AAEFEB9804ULL,
		0x6AA007CAAB897386ULL,
		0x594DC16A5BAA9B8AULL,
		0x61059339D19288B1ULL,
		0x539C7F247C7484A1ULL,
		0xF86850B418803E91ULL,
		0x3BFA7FE31A1D363AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577F5CC020000000ULL,
		0x555C4B9C343AC0B5ULL,
		0x52DD54DC5355003EULL,
		0xCE8C94458ACA6E0BULL,
		0x23E3A4250B082C99ULL,
		0xA0C401F48A9CE3F9ULL,
		0x18D0E9B1D7C34285ULL,
		0x0000000001DFD3FFULL
	}};
	shift = 27;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9AEEB25AC7424358ULL,
		0x86F2AAF56D5B9B13ULL,
		0x7914F741DC6F2AB1ULL,
		0x2273FDAF38184EF6ULL,
		0x7EFB1F1F63EF79CFULL,
		0xC83DF9642405CE9BULL,
		0x3C657976FE6156D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96B1D090D6000000ULL,
		0xBD5B56E6C4E6BBACULL,
		0xD0771BCAAC61BCAAULL,
		0x6BCE0613BD9E453DULL,
		0xC7D8FBDE73C89CFFULL,
		0x59090173A6DFBEC7ULL,
		0x5DBF9855B5F20F7EULL,
		0x00000000000F195EULL
	}};
	shift = 22;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAEF86202B32A19AAULL,
		0xFFA9D0BAAFD14015ULL,
		0xE8275411389E5942ULL,
		0xC4D4CD567590B681ULL,
		0xA2BA3E45D2F265C2ULL,
		0xBA5D0B06D5C7C28FULL,
		0x70BDDC0F06F1643BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x5AEF86202B32A19AULL,
		0x2FFA9D0BAAFD1401ULL,
		0x1E8275411389E594ULL,
		0x2C4D4CD567590B68ULL,
		0xFA2BA3E45D2F265CULL,
		0xBBA5D0B06D5C7C28ULL,
		0x070BDDC0F06F1643ULL
	}};
	shift = 60;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07F5EB31F08014EBULL,
		0x8811C6D3FEEC54FDULL,
		0xC6A28E5453D52530ULL,
		0xBE3FF4CA27AC80D5ULL,
		0xBB7DA9F961F250F7ULL,
		0xE21EF0FAAFC54C45ULL,
		0x63D19A1A30CC719BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53AC000000000000ULL,
		0x53F41FD7ACC7C200ULL,
		0x94C220471B4FFBB1ULL,
		0x03571A8A39514F54ULL,
		0x43DEF8FFD3289EB2ULL,
		0x3116EDF6A7E587C9ULL,
		0xC66F887BC3EABF15ULL,
		0x00018F466868C331ULL
	}};
	shift = 50;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2EAED7A7184950C2ULL,
		0xEE2351786DD31262ULL,
		0xEC5ADDD11006C226ULL,
		0xE009D26015F34506ULL,
		0x6DD6BDB70C6F665CULL,
		0xDB4F550EC86B3813ULL,
		0x653CF25F7D82C43FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C24A86100000000ULL,
		0x36E9893117576BD3ULL,
		0x880361137711A8BCULL,
		0x0AF9A283762D6EE8ULL,
		0x8637B32E7004E930ULL,
		0x64359C09B6EB5EDBULL,
		0xBEC1621FEDA7AA87ULL,
		0x00000000329E792FULL
	}};
	shift = 31;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1ED8409DFB31728FULL,
		0xE38299FDCAAECCE1ULL,
		0x6D8F942031576632ULL,
		0x20A136E8CA57BD4CULL,
		0x6650AD91B9BFCFC2ULL,
		0xB4A5F51FB2A98901ULL,
		0x823C7E1BB910FE7AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10277ECC5CA3C000ULL,
		0xA67F72ABB33847B6ULL,
		0xE5080C55D98CB8E0ULL,
		0x4DBA3295EF531B63ULL,
		0x2B646E6FF3F08828ULL,
		0x7D47ECAA62405994ULL,
		0x1F86EE443F9EAD29ULL,
		0x000000000000208FULL
	}};
	shift = 14;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x886770F9C258A7BAULL,
		0x9F53EAA37F8099F2ULL,
		0x73F9125B82875A74ULL,
		0xC0AE09D5E98E82F9ULL,
		0xFAFA591A232244E3ULL,
		0xF38949FFB04FF379ULL,
		0x8FFE01DD51E88142ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3E709629EE80000ULL,
		0xAA8DFE0267CA219DULL,
		0x496E0A1D69D27D4FULL,
		0x2757A63A0BE5CFE4ULL,
		0x64688C89138F02B8ULL,
		0x27FEC13FCDE7EBE9ULL,
		0x077547A2050BCE25ULL,
		0x0000000000023FF8ULL
	}};
	shift = 18;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2F6718E5B6295864ULL,
		0x6052DC8317F70F4CULL,
		0x1AEAC5B7C8B455BFULL,
		0x9307FA4534FFF289ULL,
		0x8E9D12D115A6627CULL,
		0x95C168828396D600ULL,
		0x5E00569954B41FABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x617B38C72DB14AC3ULL,
		0xFB0296E418BFB87AULL,
		0x48D7562DBE45A2ADULL,
		0xE4983FD229A7FF94ULL,
		0x0474E89688AD3313ULL,
		0x5CAE0B44141CB6B0ULL,
		0x02F002B4CAA5A0FDULL
	}};
	shift = 59;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x676E19C836F72A6BULL,
		0xD0BEF20A23D55399ULL,
		0x36618AB5B5ED8FBCULL,
		0x317A752D8C378CE1ULL,
		0x4DC2AE1B5DBD44C0ULL,
		0xD8FB4A7ADD5A5D7EULL,
		0xD3DD4E69B1F25688ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7B953580000000ULL,
		0x11EAA9CCB3B70CE4ULL,
		0xDAF6C7DE685F7905ULL,
		0xC61BC6709B30C55AULL,
		0xAEDEA26018BD3A96ULL,
		0x6EAD2EBF26E1570DULL,
		0xD8F92B446C7DA53DULL,
		0x0000000069EEA734ULL
	}};
	shift = 31;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x703F1D71E59CABD0ULL,
		0x473E9B58BEE74B15ULL,
		0x1B4C5C8D4BAB273DULL,
		0xD857683343B11772ULL,
		0x97AE5643DFC50A7FULL,
		0xF097186464E4AAD8ULL,
		0x897C67ABADEFBE76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE3CB3957A00000ULL,
		0x36B17DCE962AE07EULL,
		0xB91A97564E7A8E7DULL,
		0xD06687622EE43698ULL,
		0xAC87BF8A14FFB0AEULL,
		0x30C8C9C955B12F5CULL,
		0xCF575BDF7CEDE12EULL,
		0x00000000000112F8ULL
	}};
	shift = 17;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD8709C910092E587ULL,
		0xF55C54B2254E3918ULL,
		0xCA4BC19B46CD89DEULL,
		0xB9F84C851ACEBFB1ULL,
		0x652D418CF9482E40ULL,
		0x9C12B81599C71841ULL,
		0x211C09D14A8295FEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8709C910092E5870ULL,
		0x55C54B2254E3918DULL,
		0xA4BC19B46CD89DEFULL,
		0x9F84C851ACEBFB1CULL,
		0x52D418CF9482E40BULL,
		0xC12B81599C718416ULL,
		0x11C09D14A8295FE9ULL,
		0x0000000000000002ULL
	}};
	shift = 4;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBDDAD332A82751D6ULL,
		0x868FE8F8BDE9A1DDULL,
		0xBD393BB8D1587904ULL,
		0x72F406BA246FCEB6ULL,
		0x4FC2EAA304F4BF9CULL,
		0x379DCFABB8F99594ULL,
		0xC0B58031A97DB976ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA09D47580000000ULL,
		0x2F7A68776F76B4CCULL,
		0x34561E4121A3FA3EULL,
		0x891BF3ADAF4E4EEEULL,
		0xC13D2FE71CBD01AEULL,
		0xEE3E656513F0BAA8ULL,
		0x6A5F6E5D8DE773EAULL,
		0x00000000302D600CULL
	}};
	shift = 30;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x59EB76ABEB5D112DULL,
		0x120A735598768508ULL,
		0x7F09E9F2FA341917ULL,
		0xA0D186F3E570ABC3ULL,
		0xDE6B867AF4B4CBB0ULL,
		0x16AC5C537C5D7EE9ULL,
		0x1894464014A40D47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D6BA225A000000ULL,
		0xAB30ED0A10B3D6EDULL,
		0xE5F468322E2414E6ULL,
		0xE7CAE15786FE13D3ULL,
		0xF5E969976141A30DULL,
		0xA6F8BAFDD3BCD70CULL,
		0x8029481A8E2D58B8ULL,
		0x000000000031288CULL
	}};
	shift = 25;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC257582AD2639FABULL,
		0x66A058F6AB16B70AULL,
		0x93CA47EF474D0306ULL,
		0x61CE641EBFDB0C89ULL,
		0x0AD31760EC4F9527ULL,
		0x07C01158D8FE2B85ULL,
		0xA843627E40E8971FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931CFD5800000000ULL,
		0x58B5B85612BAC156ULL,
		0x3A6818333502C7B5ULL,
		0xFED8644C9E523F7AULL,
		0x627CA93B0E7320F5ULL,
		0xC7F15C285698BB07ULL,
		0x0744B8F83E008AC6ULL,
		0x00000005421B13F2ULL
	}};
	shift = 35;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x61F40389ABDB59C3ULL,
		0x1D2ECE6D67533868ULL,
		0xDB81C55A990C504CULL,
		0x34B562B975076E76ULL,
		0x05DA082C2222FE48ULL,
		0x35A4EDBBF2C9978AULL,
		0x93412C3CA9D471C4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5EDACE180000000ULL,
		0xB3A99C3430FA01C4ULL,
		0x4C8628260E976736ULL,
		0xBA83B73B6DC0E2ADULL,
		0x11117F241A5AB15CULL,
		0xF964CBC502ED0416ULL,
		0x54EA38E21AD276DDULL,
		0x0000000049A0961EULL
	}};
	shift = 31;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x66ABB7D201C17486ULL,
		0x963E372B4707FBD9ULL,
		0x986FBE42B3B27426ULL,
		0x9CBBDFCC0648F0E7ULL,
		0x56DEBFD47FF53238ULL,
		0x552A05B633767F4EULL,
		0x08AF8C72712E42FDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA43000000000000ULL,
		0xFDECB355DBE900E0ULL,
		0x3A134B1F1B95A383ULL,
		0x7873CC37DF2159D9ULL,
		0x991C4E5DEFE60324ULL,
		0x3FA72B6F5FEA3FFAULL,
		0x217EAA9502DB19BBULL,
		0x00000457C6393897ULL
	}};
	shift = 47;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x53B5F1EE9FAA574AULL,
		0xE49EF83134D7785BULL,
		0x50B1BCC68512A827ULL,
		0xFAA24AF0B7A91E14ULL,
		0x57A7B6C2E194914CULL,
		0xB7FC79229A10758BULL,
		0xBCFA7DB96FDE896BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F74FD52BA50000ULL,
		0x7C189A6BBC2DA9DAULL,
		0xDE6342895413F24FULL,
		0x25785BD48F0A2858ULL,
		0xDB6170CA48A67D51ULL,
		0x3C914D083AC5ABD3ULL,
		0x3EDCB7EF44B5DBFEULL,
		0x0000000000005E7DULL
	}};
	shift = 15;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4C7D8D16B6662B27ULL,
		0x3CCACE59D91CBCB4ULL,
		0xAD7A39CA3A9BAEADULL,
		0xF89BD69A2BCF4E78ULL,
		0xC1E55543583E43DBULL,
		0x804F012D2323FD4DULL,
		0x2F5B491F431AE7D8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62B2700000000000ULL,
		0xCBCB44C7D8D16B66ULL,
		0xBAEAD3CCACE59D91ULL,
		0xF4E78AD7A39CA3A9ULL,
		0xE43DBF89BD69A2BCULL,
		0x3FD4DC1E55543583ULL,
		0xAE7D8804F012D232ULL,
		0x000002F5B491F431ULL
	}};
	shift = 44;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7F67CE4913472EC8ULL,
		0x0EB26D5FF3B47A52ULL,
		0x3077006E09FCD00AULL,
		0x450DA8CA1F3D779AULL,
		0xCD8D5B6B378D3478ULL,
		0x5BEF1599E369A6BBULL,
		0x7C8CE85E2D999666ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5D900000000000ULL,
		0x68F4A4FECF9C9226ULL,
		0xF9A0141D64DABFE7ULL,
		0x7AEF3460EE00DC13ULL,
		0x1A68F08A1B51943EULL,
		0xD34D779B1AB6D66FULL,
		0x332CCCB7DE2B33C6ULL,
		0x000000F919D0BC5BULL
	}};
	shift = 41;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x83E32D1709F1E135ULL,
		0x390AE2270D624788ULL,
		0x959947C0F9F65BC6ULL,
		0xE30C0AFAACBF00A6ULL,
		0x896F7BB851ADD2CCULL,
		0x481025C4C02830B8ULL,
		0xB9E3AB7AE3325EF8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F1E135000000000ULL,
		0xD62478883E32D170ULL,
		0x9F65BC6390AE2270ULL,
		0xCBF00A6959947C0FULL,
		0x1ADD2CCE30C0AFAAULL,
		0x02830B8896F7BB85ULL,
		0x3325EF8481025C4CULL,
		0x0000000B9E3AB7AEULL
	}};
	shift = 36;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEF8604BD7E779C13ULL,
		0x7BFF6A94D44D62F9ULL,
		0xAE5041B38BA6AA0BULL,
		0xB6EEC8060D67F604ULL,
		0x1410C4E3A902AA17ULL,
		0xE8E2047FCDAF10B5ULL,
		0xF56ED86DC7F3F096ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F9DE704C000000ULL,
		0x5351358BE7BE1812ULL,
		0xCE2E9AA82DEFFDAAULL,
		0x18359FD812B94106ULL,
		0x8EA40AA85EDBBB20ULL,
		0xFF36BC42D4504313ULL,
		0xB71FCFC25BA38811ULL,
		0x0000000003D5BB61ULL
	}};
	shift = 26;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCB314A2B4CC14825ULL,
		0x3F28E1AA27CFF3EDULL,
		0xE40D7DE17DF83505ULL,
		0xAA9B10AAFD5FFDADULL,
		0xF72F6A1DFDBF3CEAULL,
		0x8ED95C15929F4BBAULL,
		0x282BFF9DB7B1F0BDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC528AD33052094ULL,
		0xFCA386A89F3FCFB7ULL,
		0x9035F785F7E0D414ULL,
		0xAA6C42ABF57FF6B7ULL,
		0xDCBDA877F6FCF3AAULL,
		0x3B6570564A7D2EEBULL,
		0xA0AFFE76DEC7C2F6ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6E8F1B7536D29BE6ULL,
		0xA5C1A016B5793E5CULL,
		0xDA3189C6E3D9CA94ULL,
		0x32D25609C1789696ULL,
		0xE75A5DDD12E9CDD5ULL,
		0x97A679E447DA34E5ULL,
		0xC1E88865DDD5DCFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4DB4A6F98000000ULL,
		0x5AD5E4F971BA3C6DULL,
		0x1B8F672A52970680ULL,
		0x2705E25A5B68C627ULL,
		0x744BA73754CB4958ULL,
		0x911F68D3979D6977ULL,
		0x97775773F25E99E7ULL,
		0x000000000307A221ULL
	}};
	shift = 26;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAD16024DA52524D6ULL,
		0x614957677B014856ULL,
		0x028420D5CEA6C434ULL,
		0x4999D3E0A4CCF673ULL,
		0x1DFBB1DA66573D55ULL,
		0xEF3EDFEEDDEB2AAEULL,
		0xFF74FD57501439D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D292926B000000ULL,
		0xB3BD80A42B568B01ULL,
		0x6AE753621A30A4ABULL,
		0xF052667B39814210ULL,
		0xED332B9EAAA4CCE9ULL,
		0xF76EF595570EFDD8ULL,
		0xABA80A1CEBF79F6FULL,
		0x00000000007FBA7EULL
	}};
	shift = 23;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF0667394F45D7932ULL,
		0x9DEB4C922DA8708EULL,
		0x7EF3AE0EE7DC4EB1ULL,
		0x05006849E16D73F8ULL,
		0xF594BC6AF01826E6ULL,
		0xD9958BBC7206F4DFULL,
		0x043CDD5B7B14C55EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3339CA7A2EBC9900ULL,
		0xF5A64916D4384778ULL,
		0x79D70773EE2758CEULL,
		0x803424F0B6B9FC3FULL,
		0xCA5E35780C137302ULL,
		0xCAC5DE39037A6FFAULL,
		0x1E6EADBD8A62AF6CULL,
		0x0000000000000002ULL
	}};
	shift = 7;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B470D4DA28A9E73ULL,
		0x16D1440B1D0FCC3DULL,
		0x73A42D4869E80D4AULL,
		0x65CD382913A0D2BCULL,
		0xC2AEB7401271269DULL,
		0x9F066B71414ED3C3ULL,
		0xEB28C902DD67F157ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1454F3980000000ULL,
		0x8E87E61EC5A386A6ULL,
		0x34F406A50B68A205ULL,
		0x89D0695E39D216A4ULL,
		0x0938934EB2E69C14ULL,
		0xA0A769E1E1575BA0ULL,
		0x6EB3F8ABCF8335B8ULL,
		0x0000000075946481ULL
	}};
	shift = 31;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA694CF853CE1381CULL,
		0xA75A4AD552CB622CULL,
		0x4554307B00273152ULL,
		0xBE53181A35A48FBEULL,
		0xF2F40FA369B3CED8ULL,
		0x3A873E0529D79F89ULL,
		0xE96AFBEACDF492D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA694CF853CE1381CULL,
		0xA75A4AD552CB622CULL,
		0x4554307B00273152ULL,
		0xBE53181A35A48FBEULL,
		0xF2F40FA369B3CED8ULL,
		0x3A873E0529D79F89ULL,
		0xE96AFBEACDF492D5ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x38FB496AAF3E4D3CULL,
		0xBB2D5802438F70B8ULL,
		0x634D8FF9F16EE07FULL,
		0x13EDFFCF6278BB12ULL,
		0x71C4F60242CD5344ULL,
		0x45C4AEE590E75E5EULL,
		0xF39104AF25E1558FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3ED25AABCF934F0ULL,
		0xECB560090E3DC2E0ULL,
		0x8D363FE7C5BB81FEULL,
		0x4FB7FF3D89E2EC49ULL,
		0xC713D8090B354D10ULL,
		0x1712BB96439D7979ULL,
		0xCE4412BC9785563DULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x259A6D9945C29313ULL,
		0xB5EBCC9421D4E670ULL,
		0xBB8A62F3BA6AB08FULL,
		0x01846B6B2C567F5FULL,
		0xE4B5AA95A17F132CULL,
		0x20C8DFA069685C5DULL,
		0x35625CF6438133A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C00000000000000ULL,
		0xC09669B665170A4CULL,
		0x3ED7AF3250875399ULL,
		0x7EEE298BCEE9AAC2ULL,
		0xB00611ADACB159FDULL,
		0x7792D6AA5685FC4CULL,
		0xA483237E81A5A171ULL,
		0x00D58973D90E04CEULL
	}};
	shift = 58;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4BF91CE3F41AF267ULL,
		0x4E8C4310A53F9901ULL,
		0xAD5C553C2AA1EE68ULL,
		0x78150E1D98A7A19FULL,
		0x9E52177A5E594FDFULL,
		0xF5C35B1DA6FEB4D5ULL,
		0x8779E6A639ECBDB3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF26700000000000ULL,
		0xF99014BF91CE3F41ULL,
		0x1EE684E8C4310A53ULL,
		0x7A19FAD5C553C2AAULL,
		0x94FDF78150E1D98AULL,
		0xEB4D59E52177A5E5ULL,
		0xCBDB3F5C35B1DA6FULL,
		0x000008779E6A639EULL
	}};
	shift = 44;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD8BD5F477BD3C378ULL,
		0x2B165453152963CBULL,
		0x28BB5937D7401045ULL,
		0x2E7873B01E2C8732ULL,
		0x684BD8A8FD94637AULL,
		0x3C7B8877B0862CC3ULL,
		0xFF0586CA369F9458ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DEF4F0DE0000000ULL,
		0x4C54A58F2F62F57DULL,
		0xDF5D004114AC5951ULL,
		0xC078B21CC8A2ED64ULL,
		0xA3F6518DE8B9E1CEULL,
		0xDEC218B30DA12F62ULL,
		0x28DA7E5160F1EE21ULL,
		0x0000000003FC161BULL
	}};
	shift = 26;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAA7B4B3E608B2AD2ULL,
		0x7B98F703B8E5CEEEULL,
		0x137D4E656B56D02FULL,
		0xCD129277F8FEC142ULL,
		0x933A95C6483C37CDULL,
		0xF8C7652FB4A5AB3AULL,
		0x08B3C65A72DFAE59ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E608B2AD2000000ULL,
		0x03B8E5CEEEAA7B4BULL,
		0x656B56D02F7B98F7ULL,
		0x77F8FEC142137D4EULL,
		0xC6483C37CDCD1292ULL,
		0x2FB4A5AB3A933A95ULL,
		0x5A72DFAE59F8C765ULL,
		0x000000000008B3C6ULL
	}};
	shift = 24;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x82F86C5C9A64AE2BULL,
		0x4789A9D92C7242C3ULL,
		0xEE43DA0792683883ULL,
		0x533C696DAD0D0AE3ULL,
		0x5703E267A8F4C67FULL,
		0x5E6F8F48FD80FCBAULL,
		0x1C1D8C2A4D213D66ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D3257158000000ULL,
		0xC96392161C17C362ULL,
		0x3C9341C41A3C4D4EULL,
		0x6D6868571F721ED0ULL,
		0x3D47A633FA99E34BULL,
		0x47EC07E5D2B81F13ULL,
		0x526909EB32F37C7AULL,
		0x0000000000E0EC61ULL
	}};
	shift = 27;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA273563DFD900588ULL,
		0xC1BC8E07EAA0D28EULL,
		0xE419466B5E3486FEULL,
		0x33723EF724E64F6FULL,
		0x7B9455B2036707AAULL,
		0xA4979EDA69D2D55BULL,
		0x5F4CDE444DCF8909ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x200B100000000000ULL,
		0x41A51D44E6AC7BFBULL,
		0x690DFD83791C0FD5ULL,
		0xCC9EDFC8328CD6BCULL,
		0xCE0F5466E47DEE49ULL,
		0xA5AAB6F728AB6406ULL,
		0x9F1213492F3DB4D3ULL,
		0x000000BE99BC889BULL
	}};
	shift = 41;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD92B431B322C0767ULL,
		0x4F7E619B5366B39DULL,
		0xD93EB4B777AB7E4BULL,
		0x8B9F53AA3B4875D3ULL,
		0x2D04C8C3C4D1ACBAULL,
		0x6ECB012863DE599CULL,
		0xC6E7F6417B6DD168ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01D9C0000000000ULL,
		0x9ACE7764AD0C6CC8ULL,
		0xADF92D3DF9866D4DULL,
		0x21D74F64FAD2DDDEULL,
		0x46B2EA2E7D4EA8EDULL,
		0x796670B413230F13ULL,
		0xB745A1BB2C04A18FULL,
		0x0000031B9FD905EDULL
	}};
	shift = 42;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF15B11AB7A6D3CF7ULL,
		0x85951E7B19B7727CULL,
		0xB266151FB40CEBB0ULL,
		0x2924B61BA5329340ULL,
		0x9906AA35FF7D0CBCULL,
		0x211F98196757BACEULL,
		0x42BC2954CD26B2D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CF7000000000000ULL,
		0x727CF15B11AB7A6DULL,
		0xEBB085951E7B19B7ULL,
		0x9340B266151FB40CULL,
		0x0CBC2924B61BA532ULL,
		0xBACE9906AA35FF7DULL,
		0xB2D1211F98196757ULL,
		0x000042BC2954CD26ULL
	}};
	shift = 48;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x24DB2886F7D4B01EULL,
		0x9F796D3BFA2BEDD0ULL,
		0xCE9DEAFBE058A6FCULL,
		0xE33786E07C75691BULL,
		0x91C141315CF2B1D9ULL,
		0x52C6D14135A6E689ULL,
		0xA14BFCAE3C253DBDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437BEA580F000000ULL,
		0x9DFD15F6E8126D94ULL,
		0x7DF02C537E4FBCB6ULL,
		0x703E3AB48DE74EF5ULL,
		0x98AE7958ECF19BC3ULL,
		0xA09AD37344C8E0A0ULL,
		0x571E129EDEA96368ULL,
		0x000000000050A5FEULL
	}};
	shift = 23;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF9CDD4D211DB6260ULL,
		0x19C4DC41331D5C63ULL,
		0xC2A55F533036B36CULL,
		0x53B7431946E6A743ULL,
		0xBF50D51EA2C8544DULL,
		0x89F197488DFAFB6CULL,
		0xBCB9C73EFFDB5310ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A423B6C4C000000ULL,
		0x882663AB8C7F39BAULL,
		0xEA6606D66D83389BULL,
		0x6328DCD4E87854ABULL,
		0xA3D4590A89AA76E8ULL,
		0xE911BF5F6D97EA1AULL,
		0xE7DFFB6A62113E32ULL,
		0x0000000000179738ULL
	}};
	shift = 21;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF8CBD37815FEBB72ULL,
		0x934BFCB1690C364FULL,
		0xE970FA80947621D7ULL,
		0x1A2F83BCA904A5DEULL,
		0x01FA49148B58482FULL,
		0xF922B560F3E2B18DULL,
		0xA95619ACC0675379ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC0AFF5DB900000ULL,
		0xE58B4861B27FC65EULL,
		0xD404A3B10EBC9A5FULL,
		0x1DE548252EF74B87ULL,
		0x48A45AC24178D17CULL,
		0xAB079F158C680FD2ULL,
		0xCD66033A9BCFC915ULL,
		0x0000000000054AB0ULL
	}};
	shift = 19;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x18E78F740B6AD3F6ULL,
		0xC5CDBDEB53426FC2ULL,
		0xDEF6A4975FB3C7C8ULL,
		0x1F0708A6EABC1F89ULL,
		0x6831904AFB8A76E4ULL,
		0x707DB3DDA562B9B4ULL,
		0x467FC552B49BB787ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB0000000000000ULL,
		0x7E10C73C7BA05B56ULL,
		0x3E462E6DEF5A9A13ULL,
		0xFC4EF7B524BAFD9EULL,
		0xB720F838453755E0ULL,
		0xCDA3418C8257DC53ULL,
		0xBC3B83ED9EED2B15ULL,
		0x000233FE2A95A4DDULL
	}};
	shift = 51;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9B8E2EED2F57496FULL,
		0x6F1F80078A2DFB25ULL,
		0xF10AC504F8AF31DDULL,
		0x50FDD27942DC16CEULL,
		0xA5996CE467C01F7DULL,
		0xEC98C34C9974A595ULL,
		0x1559AF52BA8199D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5EAE92DE0000000ULL,
		0xF145BF64B371C5DDULL,
		0x9F15E63BADE3F000ULL,
		0x285B82D9DE2158A0ULL,
		0x8CF803EFAA1FBA4FULL,
		0x932E94B2B4B32D9CULL,
		0x5750333AFD931869ULL,
		0x0000000002AB35EAULL
	}};
	shift = 29;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAF80858B67629F68ULL,
		0x20FCBA6CC83BB7DCULL,
		0x3A3786610318D0E0ULL,
		0x34FAF75AFE84B574ULL,
		0xF3F22A46D8299CEEULL,
		0x247CB37EE27CC9EDULL,
		0x7AEF2E8F14114BD5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16CEC53ED000000ULL,
		0x4D990776FB95F010ULL,
		0xCC20631A1C041F97ULL,
		0xEB5FD096AE8746F0ULL,
		0x48DB05339DC69F5EULL,
		0x6FDC4F993DBE7E45ULL,
		0xD1E282297AA48F96ULL,
		0x00000000000F5DE5ULL
	}};
	shift = 21;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9E256748C70735EULL,
		0x405289CA1A727F3AULL,
		0xEEF8817B4C87A7C6ULL,
		0xADACB827924F6E70ULL,
		0x2781004E3CBF0FF3ULL,
		0xEBAC860041BFED6AULL,
		0xCFE2DB5071AC8C2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3839AF0000000000ULL,
		0x393F9D74F12B3A46ULL,
		0x43D3E3202944E50DULL,
		0x27B738777C40BDA6ULL,
		0x5F87F9D6D65C13C9ULL,
		0xDFF6B513C080271EULL,
		0xD6461675D6430020ULL,
		0x00000067F16DA838ULL
	}};
	shift = 39;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3D1B5B4987C03E89ULL,
		0xA4BC7BE83D38D4F0ULL,
		0x8CC837775D619DF1ULL,
		0x39468934B1342227ULL,
		0x50E7F360C0421FC4ULL,
		0x76B55B3E171388F0ULL,
		0x0F2670303D594B83ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36B6930F807D1200ULL,
		0x78F7D07A71A9E07AULL,
		0x906EEEBAC33BE349ULL,
		0x8D12696268444F19ULL,
		0xCFE6C180843F8872ULL,
		0x6AB67C2E2711E0A1ULL,
		0x4CE0607AB29706EDULL,
		0x000000000000001EULL
	}};
	shift = 9;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA0D8AD33BDDF2E7EULL,
		0x39DA9FFC01F482D1ULL,
		0x20B632CD969072F3ULL,
		0x32A5C2F4BC018002ULL,
		0xF85EB7F871E97B1AULL,
		0x332BE53DB1D6134EULL,
		0xEBD1C68D19EDB042ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC0000000000000ULL,
		0x5A341B15A677BBE5ULL,
		0x5E673B53FF803E90ULL,
		0x004416C659B2D20EULL,
		0x634654B85E978030ULL,
		0x69DF0BD6FF0E3D2FULL,
		0x0846657CA7B63AC2ULL,
		0x001D7A38D1A33DB6ULL
	}};
	shift = 53;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDD80F16AC76932B6ULL,
		0x7B7B7BA35EF1E1D4ULL,
		0x5900E0C6FF42B2F3ULL,
		0x102EDB5793974A31ULL,
		0xACF2B299F1DE91F3ULL,
		0x12ACEB191FE0486BULL,
		0x2E30831613F49CE7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E2D58ED2656C00ULL,
		0xF6F746BDE3C3A9BBULL,
		0x01C18DFE8565E6F6ULL,
		0x5DB6AF272E9462B2ULL,
		0xE56533E3BD23E620ULL,
		0x59D6323FC090D759ULL,
		0x61062C27E939CE25ULL,
		0x000000000000005CULL
	}};
	shift = 9;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF14C97E78F2B6B82ULL,
		0x339271342F73FDCBULL,
		0xBA2D63AB03C18CF2ULL,
		0x03E64D972D7EA866ULL,
		0xB87E3F19D74B27EDULL,
		0xC64BFE329A461456ULL,
		0x63BBD2B2C9F8B0DEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E78F2B6B820000ULL,
		0x71342F73FDCBF14CULL,
		0x63AB03C18CF23392ULL,
		0x4D972D7EA866BA2DULL,
		0x3F19D74B27ED03E6ULL,
		0xFE329A461456B87EULL,
		0xD2B2C9F8B0DEC64BULL,
		0x00000000000063BBULL
	}};
	shift = 16;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA752C773D63A4BA5ULL,
		0x31AFE04C532C11A8ULL,
		0x6B8D0B2FFB6B0EB3ULL,
		0x229664C0DFE3D0EBULL,
		0x3F3D91080E48B2A7ULL,
		0x4C10871E9BEE154CULL,
		0x220F00B2A59FC2F6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF58E92E9400000ULL,
		0x1314CB046A29D4B1ULL,
		0xCBFEDAC3ACCC6BF8ULL,
		0x3037F8F43ADAE342ULL,
		0x4203922CA9C8A599ULL,
		0xC7A6FB85530FCF64ULL,
		0x2CA967F0BD930421ULL,
		0x00000000000883C0ULL
	}};
	shift = 22;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x09FFD230FC039367ULL,
		0xFF644074D12FA72EULL,
		0x981729C9A7B4B19FULL,
		0xA14504F83B001CD0ULL,
		0x087404A100000FB8ULL,
		0x5A1E2E6D511C768CULL,
		0x2D60861235DBDEB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9187E01C9B38000ULL,
		0x203A6897D39704FFULL,
		0x94E4D3DA58CFFFB2ULL,
		0x827C1D800E684C0BULL,
		0x0250800007DC50A2ULL,
		0x1736A88E3B46043AULL,
		0x43091AEDEF5A2D0FULL,
		0x00000000000016B0ULL
	}};
	shift = 15;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF00412B69D0EF784ULL,
		0x079DF8748BCF8959ULL,
		0xA8BC185087ED3496ULL,
		0x002DE7CCF1F09E7DULL,
		0x645E8A0FFE721291ULL,
		0x6524ED74CF7AE946ULL,
		0x97F889F819CD1A88ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00412B69D0EF784ULL,
		0x079DF8748BCF8959ULL,
		0xA8BC185087ED3496ULL,
		0x002DE7CCF1F09E7DULL,
		0x645E8A0FFE721291ULL,
		0x6524ED74CF7AE946ULL,
		0x97F889F819CD1A88ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4258F3C034060304ULL,
		0x1BBE06DC38E863B2ULL,
		0xFEC264F908D4F184ULL,
		0xB5441441E7B63A5DULL,
		0x984BDA827DACC590ULL,
		0x9A8E9C607292AFE2ULL,
		0x22E20CEA82D61F8BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0400000000000000ULL,
		0xB24258F3C0340603ULL,
		0x841BBE06DC38E863ULL,
		0x5DFEC264F908D4F1ULL,
		0x90B5441441E7B63AULL,
		0xE2984BDA827DACC5ULL,
		0x8B9A8E9C607292AFULL,
		0x0022E20CEA82D61FULL
	}};
	shift = 56;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4628CEA0971731E5ULL,
		0x81DCB0C77D36B496ULL,
		0x27B6D6A4C6FB125AULL,
		0xCF82A74F40F8B08BULL,
		0x958F322C3AB0FEF8ULL,
		0xBD2B884E9646CA0CULL,
		0x7EC0E1456B3A600FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5CC794000000000ULL,
		0x4DAD25918A33A825ULL,
		0xBEC496A0772C31DFULL,
		0x3E2C22C9EDB5A931ULL,
		0xAC3FBE33E0A9D3D0ULL,
		0x91B2832563CC8B0EULL,
		0xCE9803EF4AE213A5ULL,
		0x0000001FB038515AULL
	}};
	shift = 38;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5D250535438453B4ULL,
		0x2DC72EF485FCE164ULL,
		0x7DB0C2ED18D9BAE8ULL,
		0xBD764B4A67137B80ULL,
		0xDA1AAD9ED51727E5ULL,
		0xC43B1F161193FC53ULL,
		0x4E8A51F4B382518BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8708A768000000ULL,
		0xE90BF9C2C8BA4A0AULL,
		0xDA31B375D05B8E5DULL,
		0x94CE26F700FB6185ULL,
		0x3DAA2E4FCB7AEC96ULL,
		0x2C2327F8A7B4355BULL,
		0xE96704A31788763EULL,
		0x00000000009D14A3ULL
	}};
	shift = 25;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFC7C1C6B5772517AULL,
		0x17DE96A61687374AULL,
		0xA2CCF1D3226C479EULL,
		0x62C405899000C68EULL,
		0x23FAF3EB3D6FBEE7ULL,
		0x2931018CC6E6645FULL,
		0x3AB403107EABEDC8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72517A0000000000ULL,
		0x87374AFC7C1C6B57ULL,
		0x6C479E17DE96A616ULL,
		0x00C68EA2CCF1D322ULL,
		0x6FBEE762C4058990ULL,
		0xE6645F23FAF3EB3DULL,
		0xABEDC82931018CC6ULL,
		0x0000003AB403107EULL
	}};
	shift = 40;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x485E55570E44BCDDULL,
		0x15FC1B731219C879ULL,
		0x2277AF2BEA1519FDULL,
		0xBAA42A0B78BD075EULL,
		0xBFEF45501914336FULL,
		0x0035D5D69B07C428ULL,
		0x416362365342280FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87225E6E80000000ULL,
		0x890CE43CA42F2AABULL,
		0xF50A8CFE8AFE0DB9ULL,
		0xBC5E83AF113BD795ULL,
		0x0C8A19B7DD521505ULL,
		0x4D83E2145FF7A2A8ULL,
		0x29A11407801AEAEBULL,
		0x0000000020B1B11BULL
	}};
	shift = 31;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x42FB82A424D8AA8DULL,
		0xF0C2BF55F63954A9ULL,
		0x25C7BD49EBDDC4FDULL,
		0xF02C5B614538F787ULL,
		0x02807A54E775795EULL,
		0x00AF8DF012670821ULL,
		0x6FDD71AFAB25074DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909362AA34000000ULL,
		0x57D8E552A50BEE0AULL,
		0x27AF7713F7C30AFDULL,
		0x8514E3DE1C971EF5ULL,
		0x539DD5E57BC0B16DULL,
		0xC0499C20840A01E9ULL,
		0xBEAC941D3402BE37ULL,
		0x0000000001BF75C6ULL
	}};
	shift = 26;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x21B5E89185EB4B35ULL,
		0xAC78974CE9F75BAEULL,
		0x9778E8D75C878F8CULL,
		0xD4812CCFA485BA9CULL,
		0x1881B40C0A8E292BULL,
		0xF1DCBE93C1C2C523ULL,
		0xA4A5261EC326C4E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D7A24617AD2CD40ULL,
		0x1E25D33A7DD6EB88ULL,
		0xDE3A35D721E3E32BULL,
		0x204B33E9216EA725ULL,
		0x206D0302A38A4AF5ULL,
		0x772FA4F070B148C6ULL,
		0x294987B0C9B138FCULL,
		0x0000000000000029ULL
	}};
	shift = 6;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB7DD4E0AF900D6A1ULL,
		0xB0C82C47FBF0DF75ULL,
		0x02B00A48C34A84DCULL,
		0x92F73DBCBC72EC78ULL,
		0xED5F9E0B367762BAULL,
		0x599EAAF76EE23814ULL,
		0x539A2B4EE3EF6678ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD4E0AF900D6A10ULL,
		0x0C82C47FBF0DF75BULL,
		0x2B00A48C34A84DCBULL,
		0x2F73DBCBC72EC780ULL,
		0xD5F9E0B367762BA9ULL,
		0x99EAAF76EE23814EULL,
		0x39A2B4EE3EF66785ULL,
		0x0000000000000005ULL
	}};
	shift = 4;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x885E8C9392C117D4ULL,
		0x8FCA79C0980FA6EEULL,
		0xB4FCF3C759E982BEULL,
		0x5884615B2800F603ULL,
		0x75A03320EB6B9515ULL,
		0x021B7D5858669BEAULL,
		0x1B8C51BD7D29D9E1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0xBA217A324E4B045FULL,
		0xFA3F29E702603E9BULL,
		0x0ED3F3CF1D67A60AULL,
		0x556211856CA003D8ULL,
		0xA9D680CC83ADAE54ULL,
		0x84086DF561619A6FULL,
		0x006E3146F5F4A767ULL
	}};
	shift = 58;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB3BFE8E13D5FA466ULL,
		0x315355B91883A50BULL,
		0xC04CD79BCAB717B0ULL,
		0xFFF400E1A443D8C2ULL,
		0xCF5B065D3181ED5AULL,
		0x0CA3A3BE5535186BULL,
		0x4B9106FCF3554260ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF57E919800000000ULL,
		0x620E942ECEFFA384ULL,
		0x2ADC5EC0C54D56E4ULL,
		0x910F630B01335E6FULL,
		0xC607B56BFFD00386ULL,
		0x54D461AF3D6C1974ULL,
		0xCD550980328E8EF9ULL,
		0x000000012E441BF3ULL
	}};
	shift = 34;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAFDFF94BF4E83689ULL,
		0x2B30D182B2D3797FULL,
		0x83A3E741F3633240ULL,
		0xBBDC2C6FD5F445CBULL,
		0x60B71C0CC91D4C83ULL,
		0x169B1F82DE3DE532ULL,
		0xFE5D0726EE8EDBAAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA741B44800000000ULL,
		0x969BCBFD7EFFCA5FULL,
		0x9B19920159868C15ULL,
		0xAFA22E5C1D1F3A0FULL,
		0x48EA641DDEE1637EULL,
		0xF1EF299305B8E066ULL,
		0x7476DD50B4D8FC16ULL,
		0x00000007F2E83937ULL
	}};
	shift = 35;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x16E8A8E0E1CCC81CULL,
		0x6A0EA7FC628E3D97ULL,
		0xC196A14EC1323F4DULL,
		0x27832892E0B5EED4ULL,
		0xBDCFCBA49329C699ULL,
		0x6D24FA9B75FFA0CAULL,
		0x969DE3AE28AEB78FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74547070E6640E00ULL,
		0x0753FE31471ECB8BULL,
		0xCB50A760991FA6B5ULL,
		0xC19449705AF76A60ULL,
		0xE7E5D24994E34C93ULL,
		0x927D4DBAFFD0655EULL,
		0x4EF1D714575BC7B6ULL,
		0x000000000000004BULL
	}};
	shift = 7;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B4711FB97D914B4ULL,
		0x3C1254B65F1904CFULL,
		0x9570B5C5BEEF8B67ULL,
		0x217B548521CB1E3BULL,
		0x3F64B8C5F31CD3E4ULL,
		0x69BB3994DAE88082ULL,
		0x08A2D96D05898F5CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCED1C47EE5F6452DULL,
		0xCF04952D97C64133ULL,
		0xE55C2D716FBBE2D9ULL,
		0x085ED5214872C78EULL,
		0x8FD92E317CC734F9ULL,
		0x1A6ECE6536BA2020ULL,
		0x0228B65B416263D7ULL
	}};
	shift = 62;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1D4B71DF4A656172ULL,
		0x280552ACB53897F2ULL,
		0x209A762FAFD7B2A1ULL,
		0x0612C0C9F1F8B222ULL,
		0x879B390679E9F68FULL,
		0xDA81E54DFCE88DA4ULL,
		0x15C26EDB5CE0B355ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94CAC2E40000000ULL,
		0x96A712FE43A96E3BULL,
		0xF5FAF6542500AA55ULL,
		0x3E3F164444134EC5ULL,
		0xCF3D3ED1E0C25819ULL,
		0xBF9D11B490F36720ULL,
		0x6B9C166ABB503CA9ULL,
		0x0000000002B84DDBULL
	}};
	shift = 29;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x35B664ED99D1B715ULL,
		0x607EF5EBAC498FC3ULL,
		0x0311A132A3B22AEAULL,
		0xE9C7347B53F52E0BULL,
		0xDCEE498FE42075A7ULL,
		0x2B691E7AC8C45861ULL,
		0x354CDD98DECEEF42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD99D1B7150000000ULL,
		0xBAC498FC335B664EULL,
		0x2A3B22AEA607EF5EULL,
		0xB53F52E0B0311A13ULL,
		0xFE42075A7E9C7347ULL,
		0xAC8C45861DCEE498ULL,
		0x8DECEEF422B691E7ULL,
		0x000000000354CDD9ULL
	}};
	shift = 28;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A1DD283228C2448ULL,
		0xDD4C320F0E60098BULL,
		0x035D102D6DEE7DA0ULL,
		0x322ACAAB515F0A8DULL,
		0xDE6BA9BDCAA12E9FULL,
		0x8F83C018894E1F96ULL,
		0x017F17A5A6535DB5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA50EE94191461224ULL,
		0x6EA61907873004C5ULL,
		0x81AE8816B6F73ED0ULL,
		0x99156555A8AF8546ULL,
		0x6F35D4DEE550974FULL,
		0xC7C1E00C44A70FCBULL,
		0x00BF8BD2D329AEDAULL
	}};
	shift = 63;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x721C632597804167ULL,
		0x430DE12E07E89312ULL,
		0x61172E0158DDEB3FULL,
		0xE629631A67F7D4B8ULL,
		0xD3409ED3F124FBE4ULL,
		0x9F95B6FCA29AA54EULL,
		0x21CB715E880892EBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0082CE000000000ULL,
		0xFD12624E438C64B2ULL,
		0x1BBD67E861BC25C0ULL,
		0xFEFA970C22E5C02BULL,
		0x249F7C9CC52C634CULL,
		0x5354A9DA6813DA7EULL,
		0x01125D73F2B6DF94ULL,
		0x00000004396E2BD1ULL
	}};
	shift = 37;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB8A94F61C1DAC42AULL,
		0xAFACD66046615B0FULL,
		0xA9A1BB01F4943254ULL,
		0x80DC862AFDABC3EAULL,
		0xA1838005B776C16CULL,
		0x5508A2AF672D8C37ULL,
		0xB3AC46BE29F2987CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED6215000000000ULL,
		0x330AD87DC54A7B0EULL,
		0xA4A192A57D66B302ULL,
		0xED5E1F554D0DD80FULL,
		0xBBB60B6406E43157ULL,
		0x396C61BD0C1C002DULL,
		0x4F94C3E2A845157BULL,
		0x000000059D6235F1ULL
	}};
	shift = 35;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2DF00B2225FA15B0ULL,
		0xCFBE2205554E5916ULL,
		0xB49605C4DC268952ULL,
		0xFB90D14D58A7C2D8ULL,
		0x39E91EA375BCB41FULL,
		0x2DD8C40FAF775A7FULL,
		0x4A4AAD65F6B2F631ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42B6000000000000ULL,
		0xCB22C5BE016444BFULL,
		0xD12A59F7C440AAA9ULL,
		0xF85B1692C0B89B84ULL,
		0x9683FF721A29AB14ULL,
		0xEB4FE73D23D46EB7ULL,
		0x5EC625BB1881F5EEULL,
		0x0000094955ACBED6ULL
	}};
	shift = 45;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEFF1CD78869F915AULL,
		0x9519E1153D2CA3C0ULL,
		0xAC7E99802A760F31ULL,
		0x4BBF8BC7500DC41DULL,
		0x3CC8CB0B7E8A2F44ULL,
		0xD46F4FB6B43737B3ULL,
		0x2EB338A0F9789099ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x77F8E6BC434FC8ADULL,
		0xCA8CF08A9E9651E0ULL,
		0xD63F4CC0153B0798ULL,
		0x25DFC5E3A806E20EULL,
		0x9E646585BF4517A2ULL,
		0xEA37A7DB5A1B9BD9ULL,
		0x17599C507CBC484CULL
	}};
	shift = 63;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4A62708BDC762A41ULL,
		0xF4387F071F820C71ULL,
		0x97422138E2B44E6DULL,
		0x59793C6FC426EF64ULL,
		0x2CF04FEFD80E4759ULL,
		0xCB1191E2E30DCD22ULL,
		0x7183251603D6346DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC762A410000000ULL,
		0x71F820C714A62708ULL,
		0x8E2B44E6DF4387F0ULL,
		0xFC426EF649742213ULL,
		0xFD80E475959793C6ULL,
		0x2E30DCD222CF04FEULL,
		0x603D6346DCB1191EULL,
		0x0000000007183251ULL
	}};
	shift = 28;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF28D401769BA8BD1ULL,
		0xC5D64503C216B6AFULL,
		0x49134099E79D6539ULL,
		0x548C22DE66A5935BULL,
		0x048207995B76E435ULL,
		0x6C0721F48E0D1C4BULL,
		0xAF0AB5D83BBD9A77ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517A200000000000ULL,
		0xD6D5FE51A802ED37ULL,
		0xACA738BAC8A07842ULL,
		0xB26B692268133CF3ULL,
		0xDC86AA91845BCCD4ULL,
		0xA389609040F32B6EULL,
		0xB34EED80E43E91C1ULL,
		0x000015E156BB0777ULL
	}};
	shift = 45;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9DA767FD2A8EAC63ULL,
		0x6B18B3EEA485AFC2ULL,
		0x979A9D1E58BE092CULL,
		0xD7DEBBF1B80D9689ULL,
		0x97213BD09206FCF7ULL,
		0xB5CD9AE6E8DF63D0ULL,
		0x31F743F83E58F203ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA767FD2A8EAC6300ULL,
		0x18B3EEA485AFC29DULL,
		0x9A9D1E58BE092C6BULL,
		0xDEBBF1B80D968997ULL,
		0x213BD09206FCF7D7ULL,
		0xCD9AE6E8DF63D097ULL,
		0xF743F83E58F203B5ULL,
		0x0000000000000031ULL
	}};
	shift = 8;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4071AF1D7C591D27ULL,
		0x668564043A95643FULL,
		0x3C7F80DC142C783DULL,
		0xC0F0A0732CD19541ULL,
		0x5AF9BE8E26710842ULL,
		0x1D798C899CA3FF94ULL,
		0xEC59DE46E376D9F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E93800000000000ULL,
		0xB21FA038D78EBE2CULL,
		0x3C1EB342B2021D4AULL,
		0xCAA09E3FC06E0A16ULL,
		0x8421607850399668ULL,
		0xFFCA2D7CDF471338ULL,
		0x6CFC8EBCC644CE51ULL,
		0x0000762CEF2371BBULL
	}};
	shift = 47;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x90C5ED05B4E4109FULL,
		0xB373DE7CC5A9BC56ULL,
		0x84A4EC094FCEF978ULL,
		0x01E0D89426999139ULL,
		0x12090B64B74B618FULL,
		0xA1FAFACBC46878C9ULL,
		0x93F92AAEF91AC711ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4109F000000000ULL,
		0x5A9BC5690C5ED05BULL,
		0xFCEF978B373DE7CCULL,
		0x699913984A4EC094ULL,
		0x74B618F01E0D8942ULL,
		0x46878C912090B64BULL,
		0x91AC711A1FAFACBCULL,
		0x000000093F92AAEFULL
	}};
	shift = 36;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x47CEED58DBDA1A74ULL,
		0xF8DF54FCC277B559ULL,
		0x1201DAE650A00234ULL,
		0x30814A93B2691783ULL,
		0x3221AC99F6C27887ULL,
		0xDAE04E6FD7EDCFC4ULL,
		0xFD01474DE3F82844ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1A740000000000ULL,
		0x77B55947CEED58DBULL,
		0xA00234F8DF54FCC2ULL,
		0x6917831201DAE650ULL,
		0xC2788730814A93B2ULL,
		0xEDCFC43221AC99F6ULL,
		0xF82844DAE04E6FD7ULL,
		0x000000FD01474DE3ULL
	}};
	shift = 40;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB1E22A19E1816CFAULL,
		0x5842113A0EE1C9DAULL,
		0x046889EF1CECD5FEULL,
		0x8DB03A665F1E3FDCULL,
		0x7E715FB8317CE32BULL,
		0x801181CFE1D01EF1ULL,
		0xFB974F742545C9FFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0B67D000000000ULL,
		0x770E4ED58F1150CFULL,
		0xE766AFF2C21089D0ULL,
		0xF8F1FEE023444F78ULL,
		0x8BE7195C6D81D332ULL,
		0x0E80F78BF38AFDC1ULL,
		0x2A2E4FFC008C0E7FULL,
		0x00000007DCBA7BA1ULL
	}};
	shift = 35;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x955C73D6DA4BA628ULL,
		0x3579755E3F2EF27FULL,
		0xE07B7E5FF1B2C081ULL,
		0x1C9FDA4311D6B737ULL,
		0x5D08DE8C48A54E87ULL,
		0x273E707C6C3393A5ULL,
		0x97B24BE1AA65F35EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB692E98A00000000ULL,
		0x8FCBBC9FE5571CF5ULL,
		0xFC6CB0204D5E5D57ULL,
		0xC475ADCDF81EDF97ULL,
		0x122953A1C727F690ULL,
		0x1B0CE4E9574237A3ULL,
		0x6A997CD789CF9C1FULL,
		0x0000000025EC92F8ULL
	}};
	shift = 30;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x11451FF9C2F9D0A9ULL,
		0xE14FFBC89F11934CULL,
		0x04562D3ECDAB4018ULL,
		0x8F9AA8BB2366E2E1ULL,
		0x1A46825EEF35CA82ULL,
		0x101B2FDA7B258CF3ULL,
		0x391A09C20356FFCEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA152000000000000ULL,
		0x2698228A3FF385F3ULL,
		0x8031C29FF7913E23ULL,
		0xC5C208AC5A7D9B56ULL,
		0x95051F35517646CDULL,
		0x19E6348D04BDDE6BULL,
		0xFF9C20365FB4F64BULL,
		0x00007234138406ADULL
	}};
	shift = 49;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAC0454F09B9A32E0ULL,
		0x3C54063B6E61719CULL,
		0x125D77A4E1034B9AULL,
		0x0C21E24961DFBFC5ULL,
		0xD4886CD545B90A2AULL,
		0x185E55EB3284032BULL,
		0x792714E36FA2FD62ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7000000000000000ULL,
		0xCE56022A784DCD19ULL,
		0xCD1E2A031DB730B8ULL,
		0xE2892EBBD27081A5ULL,
		0x150610F124B0EFDFULL,
		0x95EA44366AA2DC85ULL,
		0xB10C2F2AF5994201ULL,
		0x003C938A71B7D17EULL
	}};
	shift = 55;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF18142AE3C59F0AEULL,
		0x2EAABA80B48F1F7DULL,
		0xD900E3A370CA97C7ULL,
		0xD4971FDF5A5C2C20ULL,
		0x7E9101B04F3C260EULL,
		0x4BEC2B0FD0A5099AULL,
		0xB57EB4FC4864587BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A1571E2CF857000ULL,
		0x55D405A478FBEF8CULL,
		0x071D1B8654BE3975ULL,
		0xB8FEFAD2E16106C8ULL,
		0x880D8279E13076A4ULL,
		0x61587E85284CD3F4ULL,
		0xF5A7E24322C3DA5FULL,
		0x00000000000005ABULL
	}};
	shift = 11;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB40987D0C8FB27F4ULL,
		0x9D4E5567067A608AULL,
		0xAEE91FA9871E1158ULL,
		0x1AB1C0DEC4E66AACULL,
		0xF9A15535FDD52ECBULL,
		0x1F0335B57532EBFAULL,
		0x48DDE58BE90EEFCDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0261F4323EC9FD0ULL,
		0x7539559C19E9822AULL,
		0xBBA47EA61C784562ULL,
		0x6AC7037B1399AAB2ULL,
		0xE68554D7F754BB2CULL,
		0x7C0CD6D5D4CBAFEBULL,
		0x2377962FA43BBF34ULL,
		0x0000000000000001ULL
	}};
	shift = 2;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC52FD7C9B275001BULL,
		0x64629264DCCF03B8ULL,
		0xC24B633095A74C5CULL,
		0xD6ED23A35E537BA1ULL,
		0x663A5033094BCB94ULL,
		0xED2BDCCF7561C85AULL,
		0x1EAD68CC62267E1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA00360000000000ULL,
		0x9E07718A5FAF9364ULL,
		0x4E98B8C8C524C9B9ULL,
		0xA6F7438496C6612BULL,
		0x979729ADDA4746BCULL,
		0xC390B4CC74A06612ULL,
		0x4CFC3DDA57B99EEAULL,
		0x0000003D5AD198C4ULL
	}};
	shift = 41;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x360610E8B5FAF10CULL,
		0xF23C3CE0973060E0ULL,
		0x89F310EBC2C181B8ULL,
		0x15C74B71A6CE30D0ULL,
		0x52F8721BA2EBE97BULL,
		0x8891BAB78F6E8A1DULL,
		0xC4721F648AF9DB5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E2180000000000ULL,
		0x60C1C06C0C21D16BULL,
		0x830371E47879C12EULL,
		0x9C61A113E621D785ULL,
		0xD7D2F62B8E96E34DULL,
		0xDD143AA5F0E43745ULL,
		0xF3B6B71123756F1EULL,
		0x00000188E43EC915ULL
	}};
	shift = 41;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA2245885BC41B82EULL,
		0x2FB24DC1D2DC4D53ULL,
		0xE66966554BE5347CULL,
		0x4E40F54671A268CEULL,
		0xA317F1C735D5E7FFULL,
		0x7D9D5C06EC16BFF1ULL,
		0xBD34C0578FF377C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83705C0000000000ULL,
		0xB89AA74448B10B78ULL,
		0xCA68F85F649B83A5ULL,
		0x44D19DCCD2CCAA97ULL,
		0xABCFFE9C81EA8CE3ULL,
		0x2D7FE3462FE38E6BULL,
		0xE6EF82FB3AB80DD8ULL,
		0x0000017A6980AF1FULL
	}};
	shift = 41;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB987B5C18763FC6DULL,
		0x53727755F1B7DAC8ULL,
		0x7790F619DED28AA4ULL,
		0xFAC77F1D81DEA92FULL,
		0x1396D76A9ADF7183ULL,
		0x5442462C85C1E50FULL,
		0xD79A95BC48EF488BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6800000000000000ULL,
		0x45CC3DAE0C3B1FE3ULL,
		0x229B93BAAF8DBED6ULL,
		0x7BBC87B0CEF69455ULL,
		0x1FD63BF8EC0EF549ULL,
		0x789CB6BB54D6FB8CULL,
		0x5AA21231642E0F28ULL,
		0x06BCD4ADE2477A44ULL
	}};
	shift = 59;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x820CD1A02019EB14ULL,
		0xAEE47F782D83E3ECULL,
		0xF3029708AA5301EAULL,
		0x50B3F9134627CF09ULL,
		0x724822342F1F8CB1ULL,
		0x1E282661A967B654ULL,
		0xD8D1816E7D048762ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x668D0100CF58A000ULL,
		0x23FBC16C1F1F6410ULL,
		0x14B84552980F5577ULL,
		0x9FC89A313E784F98ULL,
		0x4111A178FC658A85ULL,
		0x41330D4B3DB2A392ULL,
		0x8C0B73E8243B10F1ULL,
		0x00000000000006C6ULL
	}};
	shift = 11;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x19DACECF20B1C66DULL,
		0x2E38AE7DDFB0E8C6ULL,
		0xFEF923DCF7D32E32ULL,
		0xB2EE7AE6017002AEULL,
		0x8860A530C7C613BCULL,
		0xC625F723D799BAB6ULL,
		0x1B40AB7C72C1DFA2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED67679058E3368ULL,
		0x71C573EEFD874630ULL,
		0xF7C91EE7BE997191ULL,
		0x9773D7300B801577ULL,
		0x430529863E309DE5ULL,
		0x312FB91EBCCDD5B4ULL,
		0xDA055BE3960EFD16ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x512C3DAE4078D428ULL,
		0x0F8349D16EDD1E26ULL,
		0x49B37BB86D62A95BULL,
		0xDA40E65F8BADB575ULL,
		0x68A547D01451D1A1ULL,
		0x6119DA4AB542A763ULL,
		0x493A107F7850120FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB901E350A0000000ULL,
		0x45BB74789944B0F6ULL,
		0xE1B58AA56C3E0D27ULL,
		0x7E2EB6D5D526CDEEULL,
		0x4051474687690399ULL,
		0x2AD50A9D8DA2951FULL,
		0xFDE140483D846769ULL,
		0x000000000124E841ULL
	}};
	shift = 26;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8385C17D740C35CCULL,
		0xB8D927CE3B138CFDULL,
		0xC461499602E7568CULL,
		0xAE4B418B39EC25E2ULL,
		0x23D16049029D9238ULL,
		0x0F8F7163145885A8ULL,
		0x6DC2A6A3402479B3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA061AE600000000ULL,
		0x1D89C67EC1C2E0BEULL,
		0x0173AB465C6C93E7ULL,
		0x9CF612F16230A4CBULL,
		0x814EC91C5725A0C5ULL,
		0x8A2C42D411E8B024ULL,
		0xA0123CD987C7B8B1ULL,
		0x0000000036E15351ULL
	}};
	shift = 31;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD516AA7BBFFC5D18ULL,
		0x3C8CCAEC5ABA4AACULL,
		0xEA753CFC2252363BULL,
		0x7F818A8048D372C4ULL,
		0xCC7FA0E254C4F160ULL,
		0xC611A720459E835CULL,
		0x088A6665E8046753ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F77FF8BA3000000ULL,
		0x5D8B5749559AA2D5ULL,
		0x9F844A46C7679199ULL,
		0x50091A6E589D4EA7ULL,
		0x1C4A989E2C0FF031ULL,
		0xE408B3D06B998FF4ULL,
		0xCCBD008CEA78C234ULL,
		0x000000000001114CULL
	}};
	shift = 21;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9D1EFBE81E9E17FULL,
		0x2341503AAA8AAD50ULL,
		0x2F2277D80AC91C80ULL,
		0x3DA425A928F64F17ULL,
		0xBE1FA03B87CF0DD4ULL,
		0xDAEF40E92B4EF6F1ULL,
		0x58AEF9FEAAE9B511ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA07A785FC0000000ULL,
		0xAAA2AB543A747BEFULL,
		0x02B2472008D0540EULL,
		0x4A3D93C5CBC89DF6ULL,
		0xE1F3C3750F69096AULL,
		0x4AD3BDBC6F87E80EULL,
		0xAABA6D4476BBD03AULL,
		0x00000000162BBE7FULL
	}};
	shift = 30;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1AAAC264F57EB79DULL,
		0x7E33237F906FA140ULL,
		0x2F65691B22A8323EULL,
		0xE39495EBA4AEFD6FULL,
		0xB674DDDE3B17B4D4ULL,
		0xCE016FBE337AF1B2ULL,
		0x4D1B30C6B8D10413ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAAC264F57EB79D0ULL,
		0xE33237F906FA1401ULL,
		0xF65691B22A8323E7ULL,
		0x39495EBA4AEFD6F2ULL,
		0x674DDDE3B17B4D4EULL,
		0xE016FBE337AF1B2BULL,
		0xD1B30C6B8D10413CULL,
		0x0000000000000004ULL
	}};
	shift = 4;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF05A2DFCEDD69925ULL,
		0x50855FE0E754975CULL,
		0xBAF1CCA81D4B5F65ULL,
		0x58C624F3A035506DULL,
		0x5A3945082AD170F6ULL,
		0xFE2172465DB08EF3ULL,
		0x0BC6B75F4C42B6ABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE76EB4C928000000ULL,
		0x073AA4BAE782D16FULL,
		0x40EA5AFB2A842AFFULL,
		0x9D01AA836DD78E65ULL,
		0x41568B87B2C63127ULL,
		0x32ED84779AD1CA28ULL,
		0xFA6215B55FF10B92ULL,
		0x00000000005E35BAULL
	}};
	shift = 27;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x41C1DEA841AA5BDCULL,
		0x71D83E7770DB2851ULL,
		0x948D2A48BDAB4DCDULL,
		0x20A94759F5BCE8F2ULL,
		0x0F31386411F6FE91ULL,
		0x69C655578F6645BFULL,
		0x3384B3C679E1CDD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA106A96F70000000ULL,
		0xDDC36CA14507077AULL,
		0x22F6AD3735C760F9ULL,
		0x67D6F3A3CA5234A9ULL,
		0x9047DBFA4482A51DULL,
		0x5E3D9916FC3CC4E1ULL,
		0x19E787375DA71955ULL,
		0x0000000000CE12CFULL
	}};
	shift = 26;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF684CDA681B60A06ULL,
		0xC0A1DFF232789B36ULL,
		0x4901CF2483256E8FULL,
		0x0B89526D2F9F067DULL,
		0x251D602F262C9D1EULL,
		0x903F7D388BF833EBULL,
		0xB06A8190C87477BCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD828180000000000ULL,
		0xE26CDBDA13369A06ULL,
		0x95BA3F02877FC8C9ULL,
		0x7C19F524073C920CULL,
		0xB274782E2549B4BEULL,
		0xE0CFAC947580BC98ULL,
		0xD1DEF240FDF4E22FULL,
		0x000002C1AA064321ULL
	}};
	shift = 42;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA5C23490B046210EULL,
		0xEB08EF7FE1288AF4ULL,
		0xD13DE1CA0BB10CE4ULL,
		0xD21038A51A1EB8DFULL,
		0xDDFE95572AA90803ULL,
		0x3CBAD13382F28B91ULL,
		0x518B988238A8042CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11A485823108700ULL,
		0x8477BFF094457A52ULL,
		0x9EF0E505D8867275ULL,
		0x081C528D0F5C6FE8ULL,
		0xFF4AAB95548401E9ULL,
		0x5D6899C17945C8EEULL,
		0xC5CC411C5402161EULL,
		0x0000000000000028ULL
	}};
	shift = 7;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x87571E3B95E80CBEULL,
		0x14D989300D1E55AFULL,
		0xEC4FB599003CEB89ULL,
		0xA3817CBA961C33A8ULL,
		0xF56DE9E440F0F17FULL,
		0xC04A5EFBAFAA0C20ULL,
		0x9D68403BFE2F470AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xF87571E3B95E80CBULL,
		0x914D989300D1E55AULL,
		0x8EC4FB599003CEB8ULL,
		0xFA3817CBA961C33AULL,
		0x0F56DE9E440F0F17ULL,
		0xAC04A5EFBAFAA0C2ULL,
		0x09D68403BFE2F470ULL
	}};
	shift = 60;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2D3D751F4BA94655ULL,
		0x749DCF57E7B43FE4ULL,
		0x963F2646DA25657FULL,
		0xBCF62482C2CCE11EULL,
		0x078CBA32254B0B9AULL,
		0x1F161329706F4014ULL,
		0x01879B37B903A44CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0x2169EBA8FA5D4A32ULL,
		0xFBA4EE7ABF3DA1FFULL,
		0xF4B1F93236D12B2BULL,
		0xD5E7B12416166708ULL,
		0xA03C65D1912A585CULL,
		0x60F8B0994B837A00ULL,
		0x000C3CD9BDC81D22ULL
	}};
	shift = 59;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFA3F478F6C06C557ULL,
		0x2C606ABC4330B79EULL,
		0x6768D158C018D28CULL,
		0x846395A880D5CEADULL,
		0x249B16902491A92CULL,
		0x61E779A7E6A6ED76ULL,
		0x38DB7F4CDA97FF8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AAE000000000000ULL,
		0x6F3DF47E8F1ED80DULL,
		0xA51858C0D5788661ULL,
		0x9D5ACED1A2B18031ULL,
		0x525908C72B5101ABULL,
		0xDAEC49362D204923ULL,
		0xFF1EC3CEF34FCD4DULL,
		0x000071B6FE99B52FULL
	}};
	shift = 49;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD7A47A9803C206E2ULL,
		0x5F6B7B07EF600DCEULL,
		0xAD5487337224FE84ULL,
		0x8763863B70F57C25ULL,
		0x506B8F5CE0121F6DULL,
		0xC1D94CEB38E0894AULL,
		0xD65FAFA51CFA4196ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF081B88000000000ULL,
		0xD80373B5E91EA600ULL,
		0x893FA117DADEC1FBULL,
		0x3D5F096B5521CCDCULL,
		0x0487DB61D8E18EDCULL,
		0x382252941AE3D738ULL,
		0x3E9065B076533ACEULL,
		0x0000003597EBE947ULL
	}};
	shift = 38;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA48848DDDB501871ULL,
		0xC3B60F843582902EULL,
		0xE23A86913B469219ULL,
		0x34F44BBD367CB579ULL,
		0xD708742A62F7A20AULL,
		0xEE93D06CBAC6F67CULL,
		0x76E7433BAA99C88BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBB6A030E2000000ULL,
		0x086B05205D491091ULL,
		0x22768D2433876C1FULL,
		0x7A6CF96AF3C4750DULL,
		0x54C5EF441469E897ULL,
		0xD9758DECF9AE10E8ULL,
		0x7755339117DD27A0ULL,
		0x0000000000EDCE86ULL
	}};
	shift = 25;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x29F3C1A3F9550960ULL,
		0x6244F7345E325771ULL,
		0x58B047F2B3ED0EF4ULL,
		0x9B1BC0057B53E415ULL,
		0xF38A75CF610C62F6ULL,
		0xDF139B434F50C398ULL,
		0xD46B38ACBDBF0724ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FE5542580000000ULL,
		0xD178C95DC4A7CF06ULL,
		0xCACFB43BD18913DCULL,
		0x15ED4F905562C11FULL,
		0x3D84318BDA6C6F00ULL,
		0x0D3D430E63CE29D7ULL,
		0xB2F6FC1C937C4E6DULL,
		0x000000000351ACE2ULL
	}};
	shift = 26;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD5D2012D6F4638C8ULL,
		0x8C65A63A07D2AF12ULL,
		0x8F6D91F09DE72953ULL,
		0xF85CB3DE648F5AADULL,
		0x5715CADCB25EB51BULL,
		0x9A0146FB067FE961ULL,
		0x8996CC7FAA03F6C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB574804B5BD18E32ULL,
		0xE319698E81F4ABC4ULL,
		0x63DB647C2779CA54ULL,
		0xFE172CF79923D6ABULL,
		0x55C572B72C97AD46ULL,
		0x268051BEC19FFA58ULL,
		0x2265B31FEA80FDB0ULL
	}};
	shift = 62;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAB93A4ADA62BE3EBULL,
		0x7BC9561014E026B4ULL,
		0x960626382F9E991DULL,
		0xB3CA95507C1C6F24ULL,
		0x26A6DD7FC098C479ULL,
		0xA5E32454432794B3ULL,
		0x803F318BBD117E74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x698AF8FAC0000000ULL,
		0x053809AD2AE4E92BULL,
		0x0BE7A6475EF25584ULL,
		0x1F071BC92581898EULL,
		0xF026311E6CF2A554ULL,
		0x10C9E52CC9A9B75FULL,
		0xEF445F9D2978C915ULL,
		0x00000000200FCC62ULL
	}};
	shift = 30;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7F7D0600D1906EB1ULL,
		0x322B1366A459F986ULL,
		0x42CFD47CB28F5B67ULL,
		0x94889DA2C305F780ULL,
		0x90FC565BBADDBB49ULL,
		0x916310B530FB120BULL,
		0x7531E201158D8845ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A320DD620000000ULL,
		0xD48B3F30CFEFA0C0ULL,
		0x9651EB6CE645626CULL,
		0x5860BEF00859FA8FULL,
		0x775BB769329113B4ULL,
		0xA61F6241721F8ACBULL,
		0x22B1B108B22C6216ULL,
		0x000000000EA63C40ULL
	}};
	shift = 29;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5990058BBD12A89EULL,
		0x44F588A699BE6784ULL,
		0x2AD09A124BFEC768ULL,
		0x4727D7B1846AC96FULL,
		0x33E23061A8A1333AULL,
		0xF6EDDC92A1DC34CAULL,
		0xC70D7663B1C85F15ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x640162EF44AA2780ULL,
		0x3D6229A66F99E116ULL,
		0xB4268492FFB1DA11ULL,
		0xC9F5EC611AB25BCAULL,
		0xF88C186A284CCE91ULL,
		0xBB7724A8770D328CULL,
		0xC35D98EC7217C57DULL,
		0x0000000000000031ULL
	}};
	shift = 6;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x94C27D60ECCF095BULL,
		0x8EAFD0F5A1EC1FA8ULL,
		0xE1765E2C2EDCDE0FULL,
		0x1D155FCA4FB16C4DULL,
		0x16D880C28D075D99ULL,
		0xBE13CFAB7A12B374ULL,
		0x61185B6DAE5E837DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D99E12B6000000ULL,
		0xEB43D83F512984FAULL,
		0x585DB9BC1F1D5FA1ULL,
		0x949F62D89BC2ECBCULL,
		0x851A0EBB323A2ABFULL,
		0x56F42566E82DB101ULL,
		0xDB5CBD06FB7C279FULL,
		0x0000000000C230B6ULL
	}};
	shift = 25;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCE7A6F3FEF8CD7A4ULL,
		0x77093BB517D8927AULL,
		0xCB50F99767B9AFE0ULL,
		0xBBD988CFD4ADB2C1ULL,
		0x63F8D823F923A14DULL,
		0xF44FFF6BE898567BULL,
		0x8E43B0AEA101933DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x59CF4DE7FDF19AF4ULL,
		0x0EE12776A2FB124FULL,
		0x396A1F32ECF735FCULL,
		0xB77B3119FA95B658ULL,
		0x6C7F1B047F247429ULL,
		0xBE89FFED7D130ACFULL,
		0x11C87615D4203267ULL
	}};
	shift = 61;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE8ABC1AF7FB983F8ULL,
		0xD1B3D89AB23A20B4ULL,
		0xE2C00B6642E055CFULL,
		0xBE89D2C0AA106E79ULL,
		0x3E918DEB64057576ULL,
		0xD7DD82A477D40F57ULL,
		0xA21776EC48C32455ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xD3A2AF06BDFEE60FULL,
		0x3F46CF626AC8E882ULL,
		0xE78B002D990B8157ULL,
		0xDAFA274B02A841B9ULL,
		0x5CFA4637AD9015D5ULL,
		0x575F760A91DF503DULL,
		0x02885DDBB1230C91ULL
	}};
	shift = 58;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8D7D6F344A35EB80ULL,
		0x931C799DF62F2F77ULL,
		0xBAEC1BB6313B8C80ULL,
		0xD95D0CD7BAC965F3ULL,
		0x16E9B13AF5F86EDAULL,
		0x0FF073606A17E8AEULL,
		0x702D794C1B8B1122ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46BD700000000000ULL,
		0xC5E5EEF1AFADE689ULL,
		0x27719012638F33BEULL,
		0x592CBE775D8376C6ULL,
		0xBF0DDB5B2BA19AF7ULL,
		0x42FD15C2DD36275EULL,
		0x71622441FE0E6C0DULL,
		0x0000000E05AF2983ULL
	}};
	shift = 37;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA8EC457C0EE25503ULL,
		0xFC1737A8AE34B091ULL,
		0x8B4882975E456EA4ULL,
		0x3E54FF38087CB71FULL,
		0xB4F37D876DCE6A3EULL,
		0x8A3F6FCCD95D4FB0ULL,
		0xDFC16DAA166EFABFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE255030000000000ULL,
		0x34B091A8EC457C0EULL,
		0x456EA4FC1737A8AEULL,
		0x7CB71F8B4882975EULL,
		0xCE6A3E3E54FF3808ULL,
		0x5D4FB0B4F37D876DULL,
		0x6EFABF8A3F6FCCD9ULL,
		0x000000DFC16DAA16ULL
	}};
	shift = 40;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC615C944D0B1430ULL,
		0x9FF9D498D23C3338ULL,
		0xD6FBA71682C72AD9ULL,
		0xA25915E071C48F93ULL,
		0xB8E7331694715D42ULL,
		0xB8F1D029A7CF689FULL,
		0x476FC500F74B80A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D0B143000000000ULL,
		0xD23C3338BC615C94ULL,
		0x82C72AD99FF9D498ULL,
		0x71C48F93D6FBA716ULL,
		0x94715D42A25915E0ULL,
		0xA7CF689FB8E73316ULL,
		0xF74B80A4B8F1D029ULL,
		0x00000000476FC500ULL
	}};
	shift = 32;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7D95DF0BC6D96D8AULL,
		0x985BDF299792E774ULL,
		0x9817B9D2EA8DDBD6ULL,
		0xDD974EB49B5AB475ULL,
		0xD49912BECBBFD51CULL,
		0x3C1BF338D6A33BECULL,
		0x294DD86F1E93A5EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F1B65B628000000ULL,
		0xA65E4B9DD1F6577CULL,
		0x4BAA376F5A616F7CULL,
		0xD26D6AD1D6605EE7ULL,
		0xFB2EFF5473765D3AULL,
		0xE35A8CEFB352644AULL,
		0xBC7A4E97B8F06FCCULL,
		0x0000000000A53761ULL
	}};
	shift = 26;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB7DFE9E4118E7B17ULL,
		0xFBCF1454DE55EE0FULL,
		0xBA1F40F7186E4F52ULL,
		0x276C4CAD376E3E5BULL,
		0x49DF2357C6ACF77BULL,
		0x20E857D1A92D9D22ULL,
		0x1202A4B6EB294627ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7904639EC5C0000ULL,
		0x51537957B83EDF7FULL,
		0x03DC61B93D4BEF3CULL,
		0x32B4DDB8F96EE87DULL,
		0x8D5F1AB3DDEC9DB1ULL,
		0x5F46A4B67489277CULL,
		0x92DBACA5189C83A1ULL,
		0x000000000000480AULL
	}};
	shift = 18;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5F64D4D1750AF681ULL,
		0x015DB7BE2EFEEA92ULL,
		0xF634DC989E016CC5ULL,
		0x4A060E6C05E0F95AULL,
		0x26034DEE22D17F7CULL,
		0x4A064CEB352C413BULL,
		0xC9DEF960F2018321ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD935345D42BDA040ULL,
		0x576DEF8BBFBAA497ULL,
		0x8D372627805B3140ULL,
		0x81839B01783E56BDULL,
		0x80D37B88B45FDF12ULL,
		0x81933ACD4B104EC9ULL,
		0x77BE583C8060C852ULL,
		0x0000000000000032ULL
	}};
	shift = 6;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA4B3AFF1CDA5D89FULL,
		0x7D923D36170739A9ULL,
		0x9FC4C25C37FFDF7DULL,
		0xE0BF0C66092D50CDULL,
		0x52423B9A835F5D33ULL,
		0x8B0B777A481CC459ULL,
		0xDD5902238D6E1A32ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x692CEBFC73697627ULL,
		0x5F648F4D85C1CE6AULL,
		0x67F130970DFFF7DFULL,
		0xF82FC319824B5433ULL,
		0x54908EE6A0D7D74CULL,
		0xA2C2DDDE92073116ULL,
		0x37564088E35B868CULL
	}};
	shift = 62;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3B11339CE1B2693BULL,
		0xCF6A7E3C108960DEULL,
		0xE968EEED90B8C2AAULL,
		0x98C61499550875A0ULL,
		0x856017DA05182B5EULL,
		0xDCEA14163A0B77CDULL,
		0x19BE6F87FB5AACD9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x8EC44CE7386C9A4EULL,
		0xB3DA9F8F04225837ULL,
		0x3A5A3BBB642E30AAULL,
		0xA631852655421D68ULL,
		0x615805F681460AD7ULL,
		0x773A85058E82DDF3ULL,
		0x066F9BE1FED6AB36ULL
	}};
	shift = 62;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC5F9F51A736831B6ULL,
		0x239E5B2729FC313CULL,
		0xDAD3B1162A8C956BULL,
		0x57F13A5B6D449CAFULL,
		0x9688A0975F14D1C1ULL,
		0x6AB33672D375E92BULL,
		0x5E249D5B53601F0FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA34E6D0636C00000ULL,
		0x64E53F862798BF3EULL,
		0x22C55192AD6473CBULL,
		0x4B6DA89395FB5A76ULL,
		0x12EBE29A382AFE27ULL,
		0xCE5A6EBD2572D114ULL,
		0xAB6A6C03E1ED5666ULL,
		0x00000000000BC493ULL
	}};
	shift = 21;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE5AC2ECE1E35B668ULL,
		0x249CB15EFE9CA0C4ULL,
		0x289F0B42A92D608BULL,
		0x136A0BAD6081FA81ULL,
		0x50719A734D3ACD77ULL,
		0xF82B81DA83DDB8F5ULL,
		0xBE9460704583302DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x4E5AC2ECE1E35B66ULL,
		0xB249CB15EFE9CA0CULL,
		0x1289F0B42A92D608ULL,
		0x7136A0BAD6081FA8ULL,
		0x550719A734D3ACD7ULL,
		0xDF82B81DA83DDB8FULL,
		0x0BE9460704583302ULL
	}};
	shift = 60;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7E6B013E18007143ULL,
		0x0A256F76BD10B06BULL,
		0xF03A051DE76640A6ULL,
		0xC8928C764B5469B0ULL,
		0x812935339C6A5BDEULL,
		0xB7E9B4BC241B1A32ULL,
		0xF4CAB2FE69FE0209ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5809F0C0038A1800ULL,
		0x2B7BB5E885835BF3ULL,
		0xD028EF3B32053051ULL,
		0x9463B25AA34D8781ULL,
		0x49A99CE352DEF644ULL,
		0x4DA5E120D8D19409ULL,
		0x5597F34FF0104DBFULL,
		0x00000000000007A6ULL
	}};
	shift = 11;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDD33B4EF471EEA31ULL,
		0x1F150FA966006C6FULL,
		0xDA93DD1642A372E1ULL,
		0x39D577B5870FB8C2ULL,
		0xEB25AF5B494ABB49ULL,
		0x69E61A908A4BF834ULL,
		0xB3E164ABC119DA4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99DA77A38F751880ULL,
		0x8A87D4B3003637EEULL,
		0x49EE8B2151B9708FULL,
		0xEABBDAC387DC616DULL,
		0x92D7ADA4A55DA49CULL,
		0xF30D484525FC1A75ULL,
		0xF0B255E08CED25B4ULL,
		0x0000000000000059ULL
	}};
	shift = 7;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x58CFC82DE918A8D0ULL,
		0xBC816CEE9D910FD9ULL,
		0x7CF90A5DCB53935EULL,
		0x3D788E29C4FA078AULL,
		0xC48A153AF6C3EE57ULL,
		0x1040BFE98F565415ULL,
		0x154FCEB28F4C1964ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE918A8D000000000ULL,
		0x9D910FD958CFC82DULL,
		0xCB53935EBC816CEEULL,
		0xC4FA078A7CF90A5DULL,
		0xF6C3EE573D788E29ULL,
		0x8F565415C48A153AULL,
		0x8F4C19641040BFE9ULL,
		0x00000000154FCEB2ULL
	}};
	shift = 32;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x85488B6A36D3E59FULL,
		0x392797A53DAB0824ULL,
		0x2FD4867D8EC904FFULL,
		0x1B074788E199251BULL,
		0x6D847887465E7015ULL,
		0x82E0B0172B0FDCEDULL,
		0xA949C02CE8D746EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800000000000000ULL,
		0x242A445B51B69F2CULL,
		0xF9C93CBD29ED5841ULL,
		0xD97EA433EC764827ULL,
		0xA8D83A3C470CC928ULL,
		0x6B6C23C43A32F380ULL,
		0x74170580B9587EE7ULL,
		0x054A4E016746BA37ULL
	}};
	shift = 59;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x195AB8B94A9184A2ULL,
		0xB6CA5B4D54174CAAULL,
		0x8E9D21A9DBD9494EULL,
		0xDAA6331F58176880ULL,
		0x3B3564B74D05652FULL,
		0xC33B28B4BD1E679DULL,
		0xAE03B2079C0E7152ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2E52A461288000ULL,
		0x96D35505D32A8656ULL,
		0x486A76F65253ADB2ULL,
		0x8CC7D605DA2023A7ULL,
		0x592DD341594BF6A9ULL,
		0xCA2D2F4799E74ECDULL,
		0xEC81E7039C54B0CEULL,
		0x0000000000002B80ULL
	}};
	shift = 14;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA08BB625FE1DCF92ULL,
		0x541E8E9C2F80DE09ULL,
		0x8F8E1E885BFA879AULL,
		0x23E181039B46CD12ULL,
		0x774FCB407CED99E6ULL,
		0x96142E13F09622ABULL,
		0x791CE9D4CDA7F211ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F2400000000000ULL,
		0x1BC1341176C4BFC3ULL,
		0x50F34A83D1D385F0ULL,
		0xD9A251F1C3D10B7FULL,
		0xB33CC47C30207368ULL,
		0xC4556EE9F9680F9DULL,
		0xFE4232C285C27E12ULL,
		0x00000F239D3A99B4ULL
	}};
	shift = 45;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9B41D4B8826F6831ULL,
		0x4DC67649C60B5631ULL,
		0x074D9BF017F11151ULL,
		0x3EF4A7BB8C15B43DULL,
		0x9C13D81534E6C233ULL,
		0xDEF00DF2DC5FD22AULL,
		0x35B527638C0BCE0AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209BDA0C40000000ULL,
		0x7182D58C66D0752EULL,
		0x05FC445453719D92ULL,
		0xE3056D0F41D366FCULL,
		0x4D39B08CCFBD29EEULL,
		0xB717F48AA704F605ULL,
		0xE302F382B7BC037CULL,
		0x000000000D6D49D8ULL
	}};
	shift = 30;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE5CBCEC2F5FA3560ULL,
		0x202F4CCC767EF381ULL,
		0xEBBAFDF4D16911D7ULL,
		0x6E983E5B56F1D6E2ULL,
		0x9A8E9F357EEB1E3EULL,
		0x4827C12F14B550FCULL,
		0xAE920597B9EC9659ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFD1AB000000000ULL,
		0x3B3F79C0F2E5E761ULL,
		0x68B488EB9017A666ULL,
		0xAB78EB7175DD7EFAULL,
		0xBF758F1F374C1F2DULL,
		0x8A5AA87E4D474F9AULL,
		0xDCF64B2CA413E097ULL,
		0x00000000574902CBULL
	}};
	shift = 31;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8C0FFC8A9B5636A2ULL,
		0xAAC50C60073864CEULL,
		0xF81DACBC4D6161FCULL,
		0x9D43759193A87070ULL,
		0xDC91A630F1297E03ULL,
		0xB95223188A1F59ACULL,
		0x3AB98430ED1C99B8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1536AC6D44000000ULL,
		0xC00E70C99D181FF9ULL,
		0x789AC2C3F9558A18ULL,
		0x232750E0E1F03B59ULL,
		0x61E252FC073A86EBULL,
		0x31143EB359B9234CULL,
		0x61DA39337172A446ULL,
		0x0000000000757308ULL
	}};
	shift = 25;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBE0292C044A37855ULL,
		0xEAEE2EF415C1650CULL,
		0x7CC9AE93607AC5B4ULL,
		0xC7122FFD4169C163ULL,
		0x2CE611DC28971E7BULL,
		0xC3C36D22754A999CULL,
		0xB12D5811DC1E6D62ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x292C044A37855000ULL,
		0xE2EF415C1650CBE0ULL,
		0x9AE93607AC5B4EAEULL,
		0x22FFD4169C1637CCULL,
		0x611DC28971E7BC71ULL,
		0x36D22754A999C2CEULL,
		0xD5811DC1E6D62C3CULL,
		0x0000000000000B12ULL
	}};
	shift = 12;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x962620108B9F1347ULL,
		0x078068912D80F784ULL,
		0xE5CD24CE84CA31F3ULL,
		0x0A99D33653CB72A0ULL,
		0xD8A337EEC7FA6679ULL,
		0x4725AE38D3EEF39AULL,
		0xFFCB522C0D0ACE51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D1C00000000000ULL,
		0x3DE12589880422E7ULL,
		0x8C7CC1E01A244B60ULL,
		0xDCA839734933A132ULL,
		0x999E42A674CD94F2ULL,
		0xBCE6B628CDFBB1FEULL,
		0xB39451C96B8E34FBULL,
		0x00003FF2D48B0342ULL
	}};
	shift = 46;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F225E83427E4575ULL,
		0x21C8A71CB9548C0EULL,
		0x7687FA1220237697ULL,
		0x4FDA98C319B1D195ULL,
		0xC50144EC42E123B4ULL,
		0x228EA736526A73FFULL,
		0x89FBE99E733EBE63ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD400000000000000ULL,
		0x38FC897A0D09F915ULL,
		0x5C87229C72E55230ULL,
		0x55DA1FE848808DDAULL,
		0xD13F6A630C66C746ULL,
		0xFF140513B10B848EULL,
		0x8C8A3A9CD949A9CFULL,
		0x0227EFA679CCFAF9ULL
	}};
	shift = 58;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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