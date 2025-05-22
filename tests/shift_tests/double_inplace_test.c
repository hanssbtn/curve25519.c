#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x74A1CCFF256B240EULL,
		0xB966CE0D18739AD9ULL,
		0x834EAE049085AFD3ULL,
		0xC1D3F71F6584FDF7ULL,
		0x1CC19BCD1A1C8FF1ULL,
		0x73D2D3ED6C46A04AULL,
		0x1B82C6531BB7FDB5ULL,
		0x1EA7795C9ACBE64FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE94399FE4AD6481CULL,
		0x72CD9C1A30E735B2ULL,
		0x069D5C09210B5FA7ULL,
		0x83A7EE3ECB09FBEFULL,
		0x3983379A34391FE3ULL,
		0xE7A5A7DAD88D4094ULL,
		0x37058CA6376FFB6AULL,
		0x3D4EF2B93597CC9EULL
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
		0x8104FC5907FF06D6ULL,
		0xD2D436F731760655ULL,
		0x2477E0B2440E92D7ULL,
		0x6DC276692DC375E5ULL,
		0x9FD2CEF66FC4164EULL,
		0xBE89A02B6EB55532ULL,
		0xA83431EF2E547714ULL,
		0x28EB7BD4406036F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0209F8B20FFE0DACULL,
		0xA5A86DEE62EC0CABULL,
		0x48EFC164881D25AFULL,
		0xDB84ECD25B86EBCAULL,
		0x3FA59DECDF882C9CULL,
		0x7D134056DD6AAA65ULL,
		0x506863DE5CA8EE29ULL,
		0x51D6F7A880C06DE3ULL
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
		0x6205620D90F0C565ULL,
		0x433937C236EC845FULL,
		0x826C73B416C25F27ULL,
		0x4A86A6B9544A38B3ULL,
		0xE435F343EBB66DB1ULL,
		0xEAA7BF0DF4B5F264ULL,
		0x8C645062EF5AF2ABULL,
		0x34BF49C93AF1DE7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC40AC41B21E18ACAULL,
		0x86726F846DD908BEULL,
		0x04D8E7682D84BE4EULL,
		0x950D4D72A8947167ULL,
		0xC86BE687D76CDB62ULL,
		0xD54F7E1BE96BE4C9ULL,
		0x18C8A0C5DEB5E557ULL,
		0x697E939275E3BCF5ULL
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
		0xDDAB565C0FCB52A6ULL,
		0x1204E2D93A642E64ULL,
		0xAB2A583D430A1B95ULL,
		0x8761E39112D6A2CBULL,
		0xD302B30FD551A2E1ULL,
		0x43F127B1C81A3805ULL,
		0x58F564783EAD06B9ULL,
		0x1C20029D07A658DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB56ACB81F96A54CULL,
		0x2409C5B274C85CC9ULL,
		0x5654B07A8614372AULL,
		0x0EC3C72225AD4597ULL,
		0xA605661FAAA345C3ULL,
		0x87E24F639034700BULL,
		0xB1EAC8F07D5A0D72ULL,
		0x3840053A0F4CB1BCULL
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
		0x1AA753668ADE00F8ULL,
		0xBDBC0C83D363B21DULL,
		0xD46B165E654E666DULL,
		0x4D7F347C9A4D9C47ULL,
		0x1AED703D689D2179ULL,
		0x404083B78400F920ULL,
		0xAF106FF267D9F83FULL,
		0x1305A6B0918C5C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x354EA6CD15BC01F0ULL,
		0x7B781907A6C7643AULL,
		0xA8D62CBCCA9CCCDBULL,
		0x9AFE68F9349B388FULL,
		0x35DAE07AD13A42F2ULL,
		0x8081076F0801F240ULL,
		0x5E20DFE4CFB3F07EULL,
		0x260B4D612318B85FULL
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
		0x62107A0D1B535F2CULL,
		0xA4496DB4E4EA3965ULL,
		0x338CDA42518FFC19ULL,
		0x5C004D799030F3DDULL,
		0x40BFBDA044BFABECULL,
		0x9CC8B376545BDE40ULL,
		0xFC126C613290C686ULL,
		0x00823AA2158D3610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC420F41A36A6BE58ULL,
		0x4892DB69C9D472CAULL,
		0x6719B484A31FF833ULL,
		0xB8009AF32061E7BAULL,
		0x817F7B40897F57D8ULL,
		0x399166ECA8B7BC80ULL,
		0xF824D8C265218D0DULL,
		0x010475442B1A6C21ULL
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
		0x86F697DC7E08B900ULL,
		0xF7F3C5671912D886ULL,
		0x321924BC80B63C72ULL,
		0x7C304FB0615D7087ULL,
		0x954B99F9E45D6E24ULL,
		0x34FCC4C688E53887ULL,
		0x0107E2EC39F8A74DULL,
		0x1EBA924039DF8896ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DED2FB8FC117200ULL,
		0xEFE78ACE3225B10DULL,
		0x64324979016C78E5ULL,
		0xF8609F60C2BAE10EULL,
		0x2A9733F3C8BADC48ULL,
		0x69F9898D11CA710FULL,
		0x020FC5D873F14E9AULL,
		0x3D75248073BF112CULL
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
		0xFC5302A31C40470FULL,
		0x210CFE0547595496ULL,
		0x121EA099C2BB9A69ULL,
		0x034B8866931CC361ULL,
		0x6DF3BD70B77C7FCDULL,
		0xF1F83ED011E590FBULL,
		0x75723F10D8C74129ULL,
		0x26A2B338431D0486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A6054638808E1EULL,
		0x4219FC0A8EB2A92DULL,
		0x243D4133857734D2ULL,
		0x069710CD263986C2ULL,
		0xDBE77AE16EF8FF9AULL,
		0xE3F07DA023CB21F6ULL,
		0xEAE47E21B18E8253ULL,
		0x4D456670863A090CULL
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
		0x1693083612A6ACE6ULL,
		0x139481F950858766ULL,
		0x2051ECB2EEF4688CULL,
		0xE623C00CDEC3E133ULL,
		0xD85BE6602A6C1F1EULL,
		0x7D11FC56174736B1ULL,
		0xCDEFB3E8EB424B5EULL,
		0x37830466CE17BA1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D26106C254D59CCULL,
		0x272903F2A10B0ECCULL,
		0x40A3D965DDE8D118ULL,
		0xCC478019BD87C266ULL,
		0xB0B7CCC054D83E3DULL,
		0xFA23F8AC2E8E6D63ULL,
		0x9BDF67D1D68496BCULL,
		0x6F0608CD9C2F743DULL
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
		0x94F3E04B530C3606ULL,
		0x559A4893D3629773ULL,
		0xCB8DB9B5D7E6E51AULL,
		0x3D31B6AD732A743BULL,
		0x142386CDDBF66D33ULL,
		0xB7EC354E22E6638AULL,
		0xEC39534088946E4CULL,
		0x255E2B1EB5BBC05DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E7C096A6186C0CULL,
		0xAB349127A6C52EE7ULL,
		0x971B736BAFCDCA34ULL,
		0x7A636D5AE654E877ULL,
		0x28470D9BB7ECDA66ULL,
		0x6FD86A9C45CCC714ULL,
		0xD872A6811128DC99ULL,
		0x4ABC563D6B7780BBULL
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
		0x779C4ABA34612BEEULL,
		0x7FBA995DF4BB01A7ULL,
		0xC9BBD4F9E210979FULL,
		0x6960C821FFE7C4B0ULL,
		0x71CED72AA52616C3ULL,
		0x514373258ABE5755ULL,
		0xA5DB26B58484AA4EULL,
		0x02770963F844B274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF38957468C257DCULL,
		0xFF7532BBE976034EULL,
		0x9377A9F3C4212F3EULL,
		0xD2C19043FFCF8961ULL,
		0xE39DAE554A4C2D86ULL,
		0xA286E64B157CAEAAULL,
		0x4BB64D6B0909549CULL,
		0x04EE12C7F08964E9ULL
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
		0x91CE39022032508EULL,
		0x54C5A090C647C1E7ULL,
		0xB63876E2E4099F16ULL,
		0xCF73ECC51F8AF8B7ULL,
		0xD854084247C62FB2ULL,
		0xA0D030F412497B63ULL,
		0xDC862C026DC2BEB9ULL,
		0x17C3B383C40936EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x239C72044064A11CULL,
		0xA98B41218C8F83CFULL,
		0x6C70EDC5C8133E2CULL,
		0x9EE7D98A3F15F16FULL,
		0xB0A810848F8C5F65ULL,
		0x41A061E82492F6C7ULL,
		0xB90C5804DB857D73ULL,
		0x2F87670788126DD5ULL
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
		0x31745F17BCE32E59ULL,
		0x507EFCE22E81CE2CULL,
		0xAE8E887224ACA471ULL,
		0x64044A213AFB5382ULL,
		0x9E5062851761199EULL,
		0xAAFEB0DE335AF09AULL,
		0xCF7E591FCBF75113ULL,
		0x22B23ECA75EF2187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E8BE2F79C65CB2ULL,
		0xA0FDF9C45D039C58ULL,
		0x5D1D10E4495948E2ULL,
		0xC808944275F6A705ULL,
		0x3CA0C50A2EC2333CULL,
		0x55FD61BC66B5E135ULL,
		0x9EFCB23F97EEA227ULL,
		0x45647D94EBDE430FULL
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
		0xE5C3CFD5AE4AF124ULL,
		0x42EDE1B60D51E0F8ULL,
		0xC8CEA0F0C018B118ULL,
		0x904A7C6D4C366F7EULL,
		0xE3CE58934B261BF8ULL,
		0xDAD5A53BEE28AA3AULL,
		0x39D1E16F00592B32ULL,
		0x22C173996E4DB02EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB879FAB5C95E248ULL,
		0x85DBC36C1AA3C1F1ULL,
		0x919D41E180316230ULL,
		0x2094F8DA986CDEFDULL,
		0xC79CB126964C37F1ULL,
		0xB5AB4A77DC515475ULL,
		0x73A3C2DE00B25665ULL,
		0x4582E732DC9B605CULL
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
		0xF8360AD5E9326295ULL,
		0x31002729D9987DD6ULL,
		0xF0A46B173877DE58ULL,
		0x7367F087D5127788ULL,
		0x368CC2800E6FD300ULL,
		0xCCA3F5451CE944A6ULL,
		0x479B91D41FAFF7A5ULL,
		0x0D15819F01B6E7E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06C15ABD264C52AULL,
		0x62004E53B330FBADULL,
		0xE148D62E70EFBCB0ULL,
		0xE6CFE10FAA24EF11ULL,
		0x6D1985001CDFA600ULL,
		0x9947EA8A39D2894CULL,
		0x8F3723A83F5FEF4BULL,
		0x1A2B033E036DCFD0ULL
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
		0x0DF35A5BD34BF879ULL,
		0x31EB822C594C1395ULL,
		0xCC722B19B969B2B0ULL,
		0xB33165E834C42C2FULL,
		0x2094955E1FBCB0AFULL,
		0x52D6C7FAC2CC5D76ULL,
		0x04092D7DB11A4D8EULL,
		0x2AAD40C71B234505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE6B4B7A697F0F2ULL,
		0x63D70458B298272AULL,
		0x98E4563372D36560ULL,
		0x6662CBD06988585FULL,
		0x41292ABC3F79615FULL,
		0xA5AD8FF58598BAECULL,
		0x08125AFB62349B1CULL,
		0x555A818E36468A0AULL
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
		0x0FD4B37A5870DBB6ULL,
		0x0EFB04B01FA3E15DULL,
		0x0D8F4F4A3C4D663EULL,
		0xD9B105C7366D380CULL,
		0x040F4D1C29EB705CULL,
		0xF8C0BEFE2F8FE47DULL,
		0x9E82BC82DDF15BA5ULL,
		0x054E4AF990C34BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA966F4B0E1B76CULL,
		0x1DF609603F47C2BAULL,
		0x1B1E9E94789ACC7CULL,
		0xB3620B8E6CDA7018ULL,
		0x081E9A3853D6E0B9ULL,
		0xF1817DFC5F1FC8FAULL,
		0x3D057905BBE2B74BULL,
		0x0A9C95F321869793ULL
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
		0xDD33ED4EF6F4B3A2ULL,
		0xE1C6841B018A2C5EULL,
		0x231A52004EE237E1ULL,
		0x270BE1ADE73EBD4DULL,
		0xBAF857C8B5171B82ULL,
		0x091ACD6FAE8C5699ULL,
		0x02506B8C36D7C029ULL,
		0x0951FE7E5639E005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA67DA9DEDE96744ULL,
		0xC38D0836031458BDULL,
		0x4634A4009DC46FC3ULL,
		0x4E17C35BCE7D7A9AULL,
		0x75F0AF916A2E3704ULL,
		0x12359ADF5D18AD33ULL,
		0x04A0D7186DAF8052ULL,
		0x12A3FCFCAC73C00AULL
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
		0x940726F54BA9ADB7ULL,
		0xE32CA46ED98BBA3EULL,
		0x6C454B96C2F08D2DULL,
		0xCE954AF63BD441B9ULL,
		0x3215D849BF129116ULL,
		0xE14648B435FF9245ULL,
		0x4B28085CEF0416DCULL,
		0x342088965ED02DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x280E4DEA97535B6EULL,
		0xC65948DDB317747DULL,
		0xD88A972D85E11A5BULL,
		0x9D2A95EC77A88372ULL,
		0x642BB0937E25222DULL,
		0xC28C91686BFF248AULL,
		0x965010B9DE082DB9ULL,
		0x6841112CBDA05BB4ULL
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
		0xBC16EE09A029B3DFULL,
		0x8377FB14328E2529ULL,
		0x5C2E1549817550ADULL,
		0xCC3E5348DD9E641AULL,
		0xBBC85876FF63A2E2ULL,
		0x1EB395E3388C3633ULL,
		0x081CC40DEAE2D8C3ULL,
		0x3DC934C9007395D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x782DDC13405367BEULL,
		0x06EFF628651C4A53ULL,
		0xB85C2A9302EAA15BULL,
		0x987CA691BB3CC834ULL,
		0x7790B0EDFEC745C5ULL,
		0x3D672BC671186C67ULL,
		0x1039881BD5C5B186ULL,
		0x7B92699200E72BA6ULL
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
		0xC263F9D21F4D93DEULL,
		0xC665A0A673918B48ULL,
		0xE27BBABFFEA6DC9FULL,
		0x19542E29CC56B1A7ULL,
		0xA965A65D068317B2ULL,
		0xCD81402225D9FA4DULL,
		0x195A9391BB9464F7ULL,
		0x177A5D19CBB830F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C7F3A43E9B27BCULL,
		0x8CCB414CE7231691ULL,
		0xC4F7757FFD4DB93FULL,
		0x32A85C5398AD634FULL,
		0x52CB4CBA0D062F64ULL,
		0x9B0280444BB3F49BULL,
		0x32B527237728C9EFULL,
		0x2EF4BA33977061E8ULL
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
		0x98DAAEF4DD504883ULL,
		0x3E87B07EC743DC9AULL,
		0xFAE10ACF904C431BULL,
		0x0D8CC379C380F1A5ULL,
		0x2DA23587C7A14410ULL,
		0x09740C958436B186ULL,
		0xE6FE1DCECB7A4527ULL,
		0x3966C6DF64057CC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B55DE9BAA09106ULL,
		0x7D0F60FD8E87B935ULL,
		0xF5C2159F20988636ULL,
		0x1B1986F38701E34BULL,
		0x5B446B0F8F428820ULL,
		0x12E8192B086D630CULL,
		0xCDFC3B9D96F48A4EULL,
		0x72CD8DBEC80AF983ULL
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
		0xAA954E0706A6038AULL,
		0xFE5A3200803B2BCEULL,
		0xAA4589E36D29A1F2ULL,
		0x0A2999AC8CA0FD70ULL,
		0x61DD50B2B278DA4DULL,
		0x73496218BD768E12ULL,
		0x6EE5C2D6EA142A66ULL,
		0x181AFE67A25AD852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x552A9C0E0D4C0714ULL,
		0xFCB464010076579DULL,
		0x548B13C6DA5343E5ULL,
		0x145333591941FAE1ULL,
		0xC3BAA16564F1B49AULL,
		0xE692C4317AED1C24ULL,
		0xDDCB85ADD42854CCULL,
		0x3035FCCF44B5B0A4ULL
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
		0xEB22B3A3CEF0D89CULL,
		0x0E3EA8D5BA6A73DEULL,
		0xC6AACAB7693F02E9ULL,
		0x751C3CFC1992DC00ULL,
		0x3AD4B294677D5584ULL,
		0xD39D34729AC39049ULL,
		0x70D895DC6A7E6B94ULL,
		0x39D18BE6E7FA0BD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD64567479DE1B138ULL,
		0x1C7D51AB74D4E7BDULL,
		0x8D55956ED27E05D2ULL,
		0xEA3879F83325B801ULL,
		0x75A96528CEFAAB08ULL,
		0xA73A68E535872092ULL,
		0xE1B12BB8D4FCD729ULL,
		0x73A317CDCFF417B0ULL
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
		0x88D2CBE439AB9EBBULL,
		0x4388F4CD592300F2ULL,
		0xDD0F87EA605ED42AULL,
		0x0B248344A14FC25EULL,
		0xBFF59873755A9E5AULL,
		0x20E35C3DDF5580CBULL,
		0x8F20286AA17B23B8ULL,
		0x2514572FA913BB41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A597C873573D76ULL,
		0x8711E99AB24601E5ULL,
		0xBA1F0FD4C0BDA854ULL,
		0x16490689429F84BDULL,
		0x7FEB30E6EAB53CB4ULL,
		0x41C6B87BBEAB0197ULL,
		0x1E4050D542F64770ULL,
		0x4A28AE5F52277683ULL
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
		0x0E30F4F261C58DAAULL,
		0x83A0DD92CB8A79FAULL,
		0x0DE438FCE049F459ULL,
		0x45A73AC1C8B04C18ULL,
		0x693003ED36DF7461ULL,
		0xFEF47AF6E3971CF3ULL,
		0xAAA7A5C96A3DD930ULL,
		0x0C9CA9C19FEAA8C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C61E9E4C38B1B54ULL,
		0x0741BB259714F3F4ULL,
		0x1BC871F9C093E8B3ULL,
		0x8B4E758391609830ULL,
		0xD26007DA6DBEE8C2ULL,
		0xFDE8F5EDC72E39E6ULL,
		0x554F4B92D47BB261ULL,
		0x193953833FD55181ULL
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
		0xCA80FE3C4DCBF604ULL,
		0x845B579EED556099ULL,
		0xA0BF013B8DAD4667ULL,
		0x5B41518A1B064F2BULL,
		0xBFDD753EA38653C0ULL,
		0x8685589633760138ULL,
		0x65C4B29D7DB0E3F1ULL,
		0x3DF7C5E76C9A1B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9501FC789B97EC08ULL,
		0x08B6AF3DDAAAC133ULL,
		0x417E02771B5A8CCFULL,
		0xB682A314360C9E57ULL,
		0x7FBAEA7D470CA780ULL,
		0x0D0AB12C66EC0271ULL,
		0xCB89653AFB61C7E3ULL,
		0x7BEF8BCED9343606ULL
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
		0xE0AEA265F92BFA50ULL,
		0x001C95EFBB44ABBBULL,
		0xF591B41EDB60211FULL,
		0x7CCB2AAD865E5CE8ULL,
		0xD9D92F8CC75DB210ULL,
		0x16759CF2B467F4DFULL,
		0xD49B84B04684FD4FULL,
		0x160F5357894BF987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15D44CBF257F4A0ULL,
		0x00392BDF76895777ULL,
		0xEB23683DB6C0423EULL,
		0xF996555B0CBCB9D1ULL,
		0xB3B25F198EBB6420ULL,
		0x2CEB39E568CFE9BFULL,
		0xA93709608D09FA9EULL,
		0x2C1EA6AF1297F30FULL
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
		0x90ADCF3706139F73ULL,
		0x8902CF175D741416ULL,
		0x4D5022F47E440F5FULL,
		0xC2EC0AE82031A32AULL,
		0xC7D74AA475171DCDULL,
		0xE9A0AC5D0C383526ULL,
		0x1A6A97D986D31CE9ULL,
		0x0822C6D2B9C7E149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x215B9E6E0C273EE6ULL,
		0x12059E2EBAE8282DULL,
		0x9AA045E8FC881EBFULL,
		0x85D815D040634654ULL,
		0x8FAE9548EA2E3B9BULL,
		0xD34158BA18706A4DULL,
		0x34D52FB30DA639D3ULL,
		0x10458DA5738FC292ULL
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
		0xB43A4DBC1F986AF7ULL,
		0x73F5E486D883D1A5ULL,
		0x331921AA23E25567ULL,
		0xA8C85E207644EEECULL,
		0x8653B59A52AC54CAULL,
		0xBACEF9A35E7FE6D8ULL,
		0x97C904387EB1EF32ULL,
		0x20AEA4C3E6F4D59BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68749B783F30D5EEULL,
		0xE7EBC90DB107A34BULL,
		0x6632435447C4AACEULL,
		0x5190BC40EC89DDD8ULL,
		0x0CA76B34A558A995ULL,
		0x759DF346BCFFCDB1ULL,
		0x2F920870FD63DE65ULL,
		0x415D4987CDE9AB37ULL
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
		0x35811032B3FA0B11ULL,
		0x484EFCBC5A706FE9ULL,
		0xB71EEEB9CBABF2F7ULL,
		0x41666B800E84EC84ULL,
		0x09DDEC3A01992A6DULL,
		0x619303C68653CC9BULL,
		0x244CBDB75155DE87ULL,
		0x276EDC76B3F21D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B02206567F41622ULL,
		0x909DF978B4E0DFD2ULL,
		0x6E3DDD739757E5EEULL,
		0x82CCD7001D09D909ULL,
		0x13BBD874033254DAULL,
		0xC326078D0CA79936ULL,
		0x48997B6EA2ABBD0EULL,
		0x4EDDB8ED67E43A26ULL
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
		0x7BE6AA79B5C47F99ULL,
		0xCDA6DFA14DA61946ULL,
		0xDBD53A30BAD3F35BULL,
		0x549D518F8F8BCE69ULL,
		0x5FB644AE3A69E965ULL,
		0x64E16C247517B5A2ULL,
		0x80C04D25D89536A8ULL,
		0x355ABF923349A4D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7CD54F36B88FF32ULL,
		0x9B4DBF429B4C328CULL,
		0xB7AA746175A7E6B7ULL,
		0xA93AA31F1F179CD3ULL,
		0xBF6C895C74D3D2CAULL,
		0xC9C2D848EA2F6B44ULL,
		0x01809A4BB12A6D50ULL,
		0x6AB57F24669349AFULL
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
		0x2B7585112A1ED31DULL,
		0xFD0EF19FD2E57ED9ULL,
		0x5D548D75C5E158D2ULL,
		0xB6EC254CF6B56EEAULL,
		0x6224E0FF75F9E7B6ULL,
		0x55B59481BA1A4DBBULL,
		0x4CF7B6CEC8809C83ULL,
		0x0CBF96468256BADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56EB0A22543DA63AULL,
		0xFA1DE33FA5CAFDB2ULL,
		0xBAA91AEB8BC2B1A5ULL,
		0x6DD84A99ED6ADDD4ULL,
		0xC449C1FEEBF3CF6DULL,
		0xAB6B290374349B76ULL,
		0x99EF6D9D91013906ULL,
		0x197F2C8D04AD75B6ULL
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
		0xD419674720D27EDFULL,
		0x4E7D1A57AA645721ULL,
		0x5EABC932B2B13980ULL,
		0x27C192A1FC72AC85ULL,
		0x9B955FB78485BD11ULL,
		0x1DD43599CFD6BEFBULL,
		0xA4339C7F11901E9EULL,
		0x314F09EE2AEDC708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA832CE8E41A4FDBEULL,
		0x9CFA34AF54C8AE43ULL,
		0xBD57926565627300ULL,
		0x4F832543F8E5590AULL,
		0x372ABF6F090B7A22ULL,
		0x3BA86B339FAD7DF7ULL,
		0x486738FE23203D3CULL,
		0x629E13DC55DB8E11ULL
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
		0xB466776142BA4A32ULL,
		0x2149F986E6603F9FULL,
		0xEF1C2DB6380FD856ULL,
		0x93A3F39E65E81BDBULL,
		0xFA7166E51D43AE11ULL,
		0xF8D2276F895999BBULL,
		0x294B3F8FB42A9885ULL,
		0x014352D8C8C813F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CCEEC285749464ULL,
		0x4293F30DCCC07F3FULL,
		0xDE385B6C701FB0ACULL,
		0x2747E73CCBD037B7ULL,
		0xF4E2CDCA3A875C23ULL,
		0xF1A44EDF12B33377ULL,
		0x52967F1F6855310BULL,
		0x0286A5B1919027E2ULL
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
		0x5E81E60361AC978AULL,
		0xE3502D6F4A3934AEULL,
		0x61C1EB58738D6EEAULL,
		0x8EC99D045A99C33CULL,
		0x4FF807614E383595ULL,
		0x4B931347DB440A97ULL,
		0x080611BAF1A3DD87ULL,
		0x1E864C844BE58C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD03CC06C3592F14ULL,
		0xC6A05ADE9472695CULL,
		0xC383D6B0E71ADDD5ULL,
		0x1D933A08B5338678ULL,
		0x9FF00EC29C706B2BULL,
		0x9726268FB688152EULL,
		0x100C2375E347BB0EULL,
		0x3D0C990897CB185EULL
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
		0xAE43B9BD9E5D3D5BULL,
		0xC4FB6FEC70F72636ULL,
		0xAF4A967B5755ED46ULL,
		0xD573531A10D77C41ULL,
		0x8154054575A155BDULL,
		0x9454CB1A07ADEAD1ULL,
		0x33C2DCDD6B934150ULL,
		0x27B009030E95CAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C87737B3CBA7AB6ULL,
		0x89F6DFD8E1EE4C6DULL,
		0x5E952CF6AEABDA8DULL,
		0xAAE6A63421AEF883ULL,
		0x02A80A8AEB42AB7BULL,
		0x28A996340F5BD5A3ULL,
		0x6785B9BAD72682A1ULL,
		0x4F6012061D2B95C4ULL
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
		0x85FBCD824F3E0D94ULL,
		0x61792929A4D35C92ULL,
		0x5C7CB705E4B782B5ULL,
		0xCD48C8E46D6C7EEEULL,
		0x319848DA6C4ECA22ULL,
		0x0896190619D61F29ULL,
		0xB25E5DA4ACF539F3ULL,
		0x08271AD354AB8E1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF79B049E7C1B28ULL,
		0xC2F2525349A6B925ULL,
		0xB8F96E0BC96F056AULL,
		0x9A9191C8DAD8FDDCULL,
		0x633091B4D89D9445ULL,
		0x112C320C33AC3E52ULL,
		0x64BCBB4959EA73E6ULL,
		0x104E35A6A9571C39ULL
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
		0xB5EA8D231EBA86E8ULL,
		0x4BDA3CAA56FB4A3FULL,
		0x9935AB011BD19ADCULL,
		0x0314B0F512E8BDEAULL,
		0xF16925B5AE59447CULL,
		0x86BBB11E019C9B04ULL,
		0xA279AA56C4500B1EULL,
		0x0192727723D3DA0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BD51A463D750DD0ULL,
		0x97B47954ADF6947FULL,
		0x326B560237A335B8ULL,
		0x062961EA25D17BD5ULL,
		0xE2D24B6B5CB288F8ULL,
		0x0D77623C03393609ULL,
		0x44F354AD88A0163DULL,
		0x0324E4EE47A7B41BULL
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
		0x6AA1548F5D25A1C0ULL,
		0x11D928D431C0C5BBULL,
		0x489ADBBC4750B401ULL,
		0x7DB71F54C8A15427ULL,
		0xB1FAAE6E098BEAD9ULL,
		0xF025393A2477F430ULL,
		0xCFF03F9D60256D31ULL,
		0x3656878F5B7A2EF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD542A91EBA4B4380ULL,
		0x23B251A863818B76ULL,
		0x9135B7788EA16802ULL,
		0xFB6E3EA99142A84EULL,
		0x63F55CDC1317D5B2ULL,
		0xE04A727448EFE861ULL,
		0x9FE07F3AC04ADA63ULL,
		0x6CAD0F1EB6F45DEFULL
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
		0x12DB8E88C5840144ULL,
		0xACC62FE438C76141ULL,
		0x620BF944E7604853ULL,
		0x1F2829D922ABF9A7ULL,
		0x51BC2A4382A43DBCULL,
		0xEA9E7F86889037B3ULL,
		0x6EF1C82497B50A55ULL,
		0x14BB3B32B50FFB69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B71D118B080288ULL,
		0x598C5FC8718EC282ULL,
		0xC417F289CEC090A7ULL,
		0x3E5053B24557F34EULL,
		0xA378548705487B78ULL,
		0xD53CFF0D11206F66ULL,
		0xDDE390492F6A14ABULL,
		0x297676656A1FF6D2ULL
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
		0xE568D1C45FED2051ULL,
		0x67B5F57C7942E6BDULL,
		0xFCCBE4C887D9FBEFULL,
		0x962E4CE2EDF3F098ULL,
		0x412EFAD0A467818DULL,
		0xA0C0674084966A21ULL,
		0xF35E3CF2F9A762EEULL,
		0x045AF015D93742EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAD1A388BFDA40A2ULL,
		0xCF6BEAF8F285CD7BULL,
		0xF997C9910FB3F7DEULL,
		0x2C5C99C5DBE7E131ULL,
		0x825DF5A148CF031BULL,
		0x4180CE81092CD442ULL,
		0xE6BC79E5F34EC5DDULL,
		0x08B5E02BB26E85DDULL
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
		0x2EC30812809B6CABULL,
		0xCA49DC0E03033CBCULL,
		0xFE65A72405CDCED4ULL,
		0xC8767100079A3DD5ULL,
		0xC7EEBF1C1D1024C3ULL,
		0x709809EE5405C5B4ULL,
		0xF92C493868A4E91AULL,
		0x04594678632A655DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D8610250136D956ULL,
		0x9493B81C06067978ULL,
		0xFCCB4E480B9B9DA9ULL,
		0x90ECE2000F347BABULL,
		0x8FDD7E383A204987ULL,
		0xE13013DCA80B8B69ULL,
		0xF2589270D149D234ULL,
		0x08B28CF0C654CABBULL
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
		0x6268D0C979C07414ULL,
		0x80E03F3674FBB3E9ULL,
		0x2D25D1EF161970DFULL,
		0x0E7C43662892090EULL,
		0xDFE175DCA7069E6EULL,
		0x6CCF2EBF963684C5ULL,
		0x793517650186BBF4ULL,
		0x3DC872381E9910DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D1A192F380E828ULL,
		0x01C07E6CE9F767D2ULL,
		0x5A4BA3DE2C32E1BFULL,
		0x1CF886CC5124121CULL,
		0xBFC2EBB94E0D3CDCULL,
		0xD99E5D7F2C6D098BULL,
		0xF26A2ECA030D77E8ULL,
		0x7B90E4703D3221B8ULL
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
		0x8D54FA9C6FF90B30ULL,
		0xF254268E84FF194DULL,
		0xFA7C78426F5F6595ULL,
		0x87A9F91F7C40E0C3ULL,
		0x09565D5BD21DB5B7ULL,
		0x753C8F9CA9B4DFDFULL,
		0x1356D9EAB1CA4784ULL,
		0x32A797BF447AAA70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA9F538DFF21660ULL,
		0xE4A84D1D09FE329BULL,
		0xF4F8F084DEBECB2BULL,
		0x0F53F23EF881C187ULL,
		0x12ACBAB7A43B6B6FULL,
		0xEA791F395369BFBEULL,
		0x26ADB3D563948F08ULL,
		0x654F2F7E88F554E0ULL
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
		0xF4B95320F28FEB77ULL,
		0x38406717BA94809DULL,
		0x97B97AE01233FDD8ULL,
		0x2DB911D88E041F5EULL,
		0xB219B49BDBB2ECBCULL,
		0xE374323271F56069ULL,
		0x9EE7812751ACBF3EULL,
		0x147E044FEC70095DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE972A641E51FD6EEULL,
		0x7080CE2F7529013BULL,
		0x2F72F5C02467FBB0ULL,
		0x5B7223B11C083EBDULL,
		0x64336937B765D978ULL,
		0xC6E86464E3EAC0D3ULL,
		0x3DCF024EA3597E7DULL,
		0x28FC089FD8E012BBULL
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
		0x8462AEF4150EBB4DULL,
		0x661FD1F7D09D9597ULL,
		0x88B5A7576E9FC3E4ULL,
		0xA794B88FC5ABC3A5ULL,
		0x791FA7C10C939E4BULL,
		0xCF91E3E90B6122F8ULL,
		0x2C130710B78300F9ULL,
		0x010832934F52D758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C55DE82A1D769AULL,
		0xCC3FA3EFA13B2B2FULL,
		0x116B4EAEDD3F87C8ULL,
		0x4F29711F8B57874BULL,
		0xF23F4F8219273C97ULL,
		0x9F23C7D216C245F0ULL,
		0x58260E216F0601F3ULL,
		0x021065269EA5AEB0ULL
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
		0xBBFAD99AB4486AA8ULL,
		0xB0AC1F18DD19656CULL,
		0xA94269209A78AF0CULL,
		0xFC39B4E996E7B1B3ULL,
		0x7CCE985384ECDF51ULL,
		0x4EC5D6C6673D3797ULL,
		0x6184C02B8231481EULL,
		0x0BCDC4458051F0FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F5B3356890D550ULL,
		0x61583E31BA32CAD9ULL,
		0x5284D24134F15E19ULL,
		0xF87369D32DCF6367ULL,
		0xF99D30A709D9BEA3ULL,
		0x9D8BAD8CCE7A6F2EULL,
		0xC30980570462903CULL,
		0x179B888B00A3E1FAULL
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
		0xD203356F06A72BA1ULL,
		0xCA0ECDE7B8D99E30ULL,
		0x62D4E3C347500ECEULL,
		0x54884A59B44C8D3EULL,
		0xA6C2A701D984B0B2ULL,
		0xC60B86B7887AF472ULL,
		0xA8620BACA0A100BFULL,
		0x2A99CC7B43050489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4066ADE0D4E5742ULL,
		0x941D9BCF71B33C61ULL,
		0xC5A9C7868EA01D9DULL,
		0xA91094B368991A7CULL,
		0x4D854E03B3096164ULL,
		0x8C170D6F10F5E8E5ULL,
		0x50C417594142017FULL,
		0x553398F6860A0913ULL
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
		0x14A86FA41617BBFFULL,
		0x3ED2B318EC143EBEULL,
		0xECFF45B2B2812B88ULL,
		0x5AE41BF59CCC67F4ULL,
		0x41B556C30A1F350AULL,
		0xA30932AE46ED61F7ULL,
		0x43CA868F76F7DE03ULL,
		0x19943D2EE901549EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2950DF482C2F77FEULL,
		0x7DA56631D8287D7CULL,
		0xD9FE8B6565025710ULL,
		0xB5C837EB3998CFE9ULL,
		0x836AAD86143E6A14ULL,
		0x4612655C8DDAC3EEULL,
		0x87950D1EEDEFBC07ULL,
		0x33287A5DD202A93CULL
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
		0x15A4AB4D82E094B2ULL,
		0xA07CE4D947EC7AB6ULL,
		0x089532C471D32FA6ULL,
		0x58FB1405F97B3E09ULL,
		0x28C591FD2DA84961ULL,
		0xD857A92D34B68242ULL,
		0x660EDC040FCD43B2ULL,
		0x32DCA4665250E77DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B49569B05C12964ULL,
		0x40F9C9B28FD8F56CULL,
		0x112A6588E3A65F4DULL,
		0xB1F6280BF2F67C12ULL,
		0x518B23FA5B5092C2ULL,
		0xB0AF525A696D0484ULL,
		0xCC1DB8081F9A8765ULL,
		0x65B948CCA4A1CEFAULL
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
		0x06439E58BBB752ACULL,
		0x0291C99BA16042DBULL,
		0x9D39B176A738C09AULL,
		0x7444392A266B597DULL,
		0x347A078D3150EA86ULL,
		0xFB5427937812458BULL,
		0x18096969FA1AAA13ULL,
		0x2522289FBBAC1DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C873CB1776EA558ULL,
		0x0523933742C085B6ULL,
		0x3A7362ED4E718134ULL,
		0xE88872544CD6B2FBULL,
		0x68F40F1A62A1D50CULL,
		0xF6A84F26F0248B16ULL,
		0x3012D2D3F4355427ULL,
		0x4A44513F77583B8AULL
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
		0xAD0A28A2A2B17EC4ULL,
		0x9FD3A3BD69C3E0DCULL,
		0x262E54F3E2D21405ULL,
		0x5EDCE347F1AFD681ULL,
		0x2F7F431E57D565C0ULL,
		0x5776A6A508271A7EULL,
		0x19B50590B97871B5ULL,
		0x20B83DF5F7BD8704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A1451454562FD88ULL,
		0x3FA7477AD387C1B9ULL,
		0x4C5CA9E7C5A4280BULL,
		0xBDB9C68FE35FAD02ULL,
		0x5EFE863CAFAACB80ULL,
		0xAEED4D4A104E34FCULL,
		0x336A0B2172F0E36AULL,
		0x41707BEBEF7B0E08ULL
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
		0x2C31902D344174FDULL,
		0x0EB76C467CDBBA8EULL,
		0xAC7F27FB24A62111ULL,
		0xEC24A7182F9DC4EAULL,
		0x77F0BF3D63B6DE26ULL,
		0x92AD25B73AD001B2ULL,
		0xC93DFDE0D0DB7ABFULL,
		0x2754AF3EAB0B874CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5863205A6882E9FAULL,
		0x1D6ED88CF9B7751CULL,
		0x58FE4FF6494C4222ULL,
		0xD8494E305F3B89D5ULL,
		0xEFE17E7AC76DBC4DULL,
		0x255A4B6E75A00364ULL,
		0x927BFBC1A1B6F57FULL,
		0x4EA95E7D56170E99ULL
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
		0x5CAD5C61525D08ECULL,
		0xA9F539E41C40FDD0ULL,
		0x267FE6A999E6544CULL,
		0xC996484E78D2223AULL,
		0xB1F6BAD2DD37E4F6ULL,
		0x8716A97D98AA105EULL,
		0x68B8FF1F51EF81A8ULL,
		0x3CD6321CB935663CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95AB8C2A4BA11D8ULL,
		0x53EA73C83881FBA0ULL,
		0x4CFFCD5333CCA899ULL,
		0x932C909CF1A44474ULL,
		0x63ED75A5BA6FC9EDULL,
		0x0E2D52FB315420BDULL,
		0xD171FE3EA3DF0351ULL,
		0x79AC6439726ACC78ULL
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
		0xF24B14A29DC57827ULL,
		0x52572BA09CCFC80CULL,
		0x3386FE4EB2254A43ULL,
		0xD8FF58B536053005ULL,
		0xD3FB6D556F0B43F7ULL,
		0x5CA91D926717014BULL,
		0xBC418FA8D51A0F85ULL,
		0x3BCF74338CA92686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49629453B8AF04EULL,
		0xA4AE5741399F9019ULL,
		0x670DFC9D644A9486ULL,
		0xB1FEB16A6C0A600AULL,
		0xA7F6DAAADE1687EFULL,
		0xB9523B24CE2E0297ULL,
		0x78831F51AA341F0AULL,
		0x779EE86719524D0DULL
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
		0xE9EA808EB0A214C5ULL,
		0x747677FC74629FA0ULL,
		0x59D39D80F2A523E8ULL,
		0xCCAF762F492F3120ULL,
		0xD71DAEA0C646C817ULL,
		0xCB6B47DAB85962DFULL,
		0x56417F202CD8F45DULL,
		0x3AD1D8C300743009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D5011D6144298AULL,
		0xE8ECEFF8E8C53F41ULL,
		0xB3A73B01E54A47D0ULL,
		0x995EEC5E925E6240ULL,
		0xAE3B5D418C8D902FULL,
		0x96D68FB570B2C5BFULL,
		0xAC82FE4059B1E8BBULL,
		0x75A3B18600E86012ULL
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
		0x39DF7587740543C1ULL,
		0x31B67C8108678DF8ULL,
		0xC40AE9733DA4BBF0ULL,
		0x984E38A313ECD39CULL,
		0x478B91D500B9D4A7ULL,
		0x3F93CB85D5F181FEULL,
		0xE91D9FB8A90240AFULL,
		0x1402B89DB185FBD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73BEEB0EE80A8782ULL,
		0x636CF90210CF1BF0ULL,
		0x8815D2E67B4977E0ULL,
		0x309C714627D9A739ULL,
		0x8F1723AA0173A94FULL,
		0x7F27970BABE303FCULL,
		0xD23B3F715204815EULL,
		0x2805713B630BF7B1ULL
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
		0x7C247C3653873C4FULL,
		0x786F8AADCD087BCDULL,
		0x6C2AA2CF6C8BD34AULL,
		0xE200C4DF7915D0F4ULL,
		0x949F17B57FB14373ULL,
		0xE688F56FBD96DA3EULL,
		0xFCDB84EADF280B41ULL,
		0x1A956689736A35F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF848F86CA70E789EULL,
		0xF0DF155B9A10F79AULL,
		0xD855459ED917A694ULL,
		0xC40189BEF22BA1E8ULL,
		0x293E2F6AFF6286E7ULL,
		0xCD11EADF7B2DB47DULL,
		0xF9B709D5BE501683ULL,
		0x352ACD12E6D46BEFULL
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
		0x323CC07E1A956FBFULL,
		0x3429E6C59BD1EFF1ULL,
		0x1D63C4B99134A313ULL,
		0xD5BE43B2E5ED5942ULL,
		0xF58C94E19720BDC4ULL,
		0xAEB1053C3D29FCDDULL,
		0x956D5CC2A8E27C4FULL,
		0x139EF4B860C5C691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x647980FC352ADF7EULL,
		0x6853CD8B37A3DFE2ULL,
		0x3AC7897322694626ULL,
		0xAB7C8765CBDAB284ULL,
		0xEB1929C32E417B89ULL,
		0x5D620A787A53F9BBULL,
		0x2ADAB98551C4F89FULL,
		0x273DE970C18B8D23ULL
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
		0x2F2B9FAEE7CF3EC5ULL,
		0x49A70AAAC1E36A5CULL,
		0x77EB78E16B4732C6ULL,
		0x94F4EECB30ADA0D6ULL,
		0x5570AF16B0107A80ULL,
		0x6205371BD48B4665ULL,
		0x22D43F3CDDFCA081ULL,
		0x0267F4F98A57929DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E573F5DCF9E7D8AULL,
		0x934E155583C6D4B8ULL,
		0xEFD6F1C2D68E658CULL,
		0x29E9DD96615B41ACULL,
		0xAAE15E2D6020F501ULL,
		0xC40A6E37A9168CCAULL,
		0x45A87E79BBF94102ULL,
		0x04CFE9F314AF253AULL
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
		0xB4FD1C5388A661A5ULL,
		0x9EC29156E065455FULL,
		0xF9E0C237E523965CULL,
		0x2B87399328446878ULL,
		0xFCAD8A464797E7B7ULL,
		0x6C86F5FA6F68CA91ULL,
		0xE2915F9E9C40E04EULL,
		0x139ED1A74439453AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69FA38A7114CC34AULL,
		0x3D8522ADC0CA8ABFULL,
		0xF3C1846FCA472CB9ULL,
		0x570E73265088D0F1ULL,
		0xF95B148C8F2FCF6EULL,
		0xD90DEBF4DED19523ULL,
		0xC522BF3D3881C09CULL,
		0x273DA34E88728A75ULL
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
		0xF4F792767EEFFB84ULL,
		0x64CB96E9B359E26AULL,
		0x573404B04BF90BDFULL,
		0x87377973CAE491C0ULL,
		0x803692559D137F2BULL,
		0xC07BEE882C63D169ULL,
		0xDFD1244208636595ULL,
		0x18BE3B00D5F74CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9EF24ECFDDFF708ULL,
		0xC9972DD366B3C4D5ULL,
		0xAE68096097F217BEULL,
		0x0E6EF2E795C92380ULL,
		0x006D24AB3A26FE57ULL,
		0x80F7DD1058C7A2D3ULL,
		0xBFA2488410C6CB2BULL,
		0x317C7601ABEE9949ULL
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
		0xC6F75761A51ADD53ULL,
		0x5F0837AFE85DAFFDULL,
		0x498F16D7E4A783B3ULL,
		0x451AC3A10B41BFFAULL,
		0xF59C36E61D54C39FULL,
		0xCDCE2DC4C814B40BULL,
		0x8E422F57F55F16A8ULL,
		0x1431A73A6F940014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DEEAEC34A35BAA6ULL,
		0xBE106F5FD0BB5FFBULL,
		0x931E2DAFC94F0766ULL,
		0x8A35874216837FF4ULL,
		0xEB386DCC3AA9873EULL,
		0x9B9C5B8990296817ULL,
		0x1C845EAFEABE2D51ULL,
		0x28634E74DF280029ULL
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
		0x02C5DAAAF3AF8CA9ULL,
		0x8631962AAF693180ULL,
		0xC23CBC91BD75DDFBULL,
		0x62CC3743391D3F55ULL,
		0xC37DA703B7B88CD6ULL,
		0x3EE3E1AC0FC153AEULL,
		0x8DA5A71B69ABCB5FULL,
		0x0C508D9815677EE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058BB555E75F1952ULL,
		0x0C632C555ED26300ULL,
		0x847979237AEBBBF7ULL,
		0xC5986E86723A7EABULL,
		0x86FB4E076F7119ACULL,
		0x7DC7C3581F82A75DULL,
		0x1B4B4E36D35796BEULL,
		0x18A11B302ACEFDC9ULL
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
		0x6546E317C149B69BULL,
		0xC778BE19D4FF0D3FULL,
		0x830116368004BB0AULL,
		0xCE798F1ABEFAC4E5ULL,
		0x157B0A0B5BE53DE5ULL,
		0xBD0867D74949E732ULL,
		0xF0519B805B1CE5EBULL,
		0x34DCD1B16FFE7A05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA8DC62F82936D36ULL,
		0x8EF17C33A9FE1A7EULL,
		0x06022C6D00097615ULL,
		0x9CF31E357DF589CBULL,
		0x2AF61416B7CA7BCBULL,
		0x7A10CFAE9293CE64ULL,
		0xE0A33700B639CBD7ULL,
		0x69B9A362DFFCF40BULL
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
		0x66F9E5ECDF2AD14FULL,
		0xDBF7EFFFD40155E1ULL,
		0xF1B450F7013B4EDAULL,
		0x14AA6CF1F4CCB33CULL,
		0x2BC0A830D8234E44ULL,
		0xF7D40237D602A14EULL,
		0x7715BD18C570119FULL,
		0x06C857B4FFE9A063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF3CBD9BE55A29EULL,
		0xB7EFDFFFA802ABC2ULL,
		0xE368A1EE02769DB5ULL,
		0x2954D9E3E9996679ULL,
		0x57815061B0469C88ULL,
		0xEFA8046FAC05429CULL,
		0xEE2B7A318AE0233FULL,
		0x0D90AF69FFD340C6ULL
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
		0xE157F3DB164B63A8ULL,
		0x051A414C358ED967ULL,
		0x3D3FE3AD66A1F259ULL,
		0x340250350700928BULL,
		0xE689E5BB518D0426ULL,
		0xEED7C3D9645E3615ULL,
		0x0385A47B463D8B2FULL,
		0x29864D712D68DBF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2AFE7B62C96C750ULL,
		0x0A3482986B1DB2CFULL,
		0x7A7FC75ACD43E4B2ULL,
		0x6804A06A0E012516ULL,
		0xCD13CB76A31A084CULL,
		0xDDAF87B2C8BC6C2BULL,
		0x070B48F68C7B165FULL,
		0x530C9AE25AD1B7E4ULL
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
		0x6BDB05FAE7533FEBULL,
		0x77536AA0D959B84FULL,
		0x4547EF6F1FBD565AULL,
		0x972F9AC7CD52CB0DULL,
		0xB20C99EE8820D3F0ULL,
		0x11BDDF52C9D2B29EULL,
		0x61A3518F5D626192ULL,
		0x34DB0F9DBCCBB61AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B60BF5CEA67FD6ULL,
		0xEEA6D541B2B3709EULL,
		0x8A8FDEDE3F7AACB4ULL,
		0x2E5F358F9AA5961AULL,
		0x641933DD1041A7E1ULL,
		0x237BBEA593A5653DULL,
		0xC346A31EBAC4C324ULL,
		0x69B61F3B79976C34ULL
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
		0x499DCEA521A1E239ULL,
		0xD7227A990AA4889AULL,
		0x61AEE986173111C3ULL,
		0xB8B3FD23C752674DULL,
		0xA350575ECEDCD237ULL,
		0xE778654B1DC48CAAULL,
		0x619894968EC40948ULL,
		0x35F4079096C18912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933B9D4A4343C472ULL,
		0xAE44F53215491134ULL,
		0xC35DD30C2E622387ULL,
		0x7167FA478EA4CE9AULL,
		0x46A0AEBD9DB9A46FULL,
		0xCEF0CA963B891955ULL,
		0xC331292D1D881291ULL,
		0x6BE80F212D831224ULL
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
		0xADA902114E22C970ULL,
		0x9510AA9ECC6C9E7EULL,
		0x67EAF80E0C232EDEULL,
		0xA65B4DA160872DDDULL,
		0x9FF01C6DF35F3B0BULL,
		0x3E25770969557596ULL,
		0x00596CD446ED0C5FULL,
		0x07867C28FAA79FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B5204229C4592E0ULL,
		0x2A21553D98D93CFDULL,
		0xCFD5F01C18465DBDULL,
		0x4CB69B42C10E5BBAULL,
		0x3FE038DBE6BE7617ULL,
		0x7C4AEE12D2AAEB2DULL,
		0x00B2D9A88DDA18BEULL,
		0x0F0CF851F54F3F52ULL
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
		0xE31CB5E310770D02ULL,
		0x9608725E1C470CA2ULL,
		0xB6EBAF71475F2F37ULL,
		0xADCD87C724A7607EULL,
		0x0BF35C0C5DF07BFFULL,
		0x012C5E1AB61A5F89ULL,
		0x4F39FBEBFAABE5EDULL,
		0x14812224114D83E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6396BC620EE1A04ULL,
		0x2C10E4BC388E1945ULL,
		0x6DD75EE28EBE5E6FULL,
		0x5B9B0F8E494EC0FDULL,
		0x17E6B818BBE0F7FFULL,
		0x0258BC356C34BF12ULL,
		0x9E73F7D7F557CBDAULL,
		0x29024448229B07C0ULL
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
		0x250E596F618EF1B5ULL,
		0xEFDED0CF2291DF7FULL,
		0xEC22AB42D1F79C0EULL,
		0x1270DBA52C2EF31CULL,
		0x2B15C3736B219E6DULL,
		0x2D0766236CDBC71FULL,
		0x9EB678EF1AE5471BULL,
		0x1E368ABC9D3BFDB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1CB2DEC31DE36AULL,
		0xDFBDA19E4523BEFEULL,
		0xD8455685A3EF381DULL,
		0x24E1B74A585DE639ULL,
		0x562B86E6D6433CDAULL,
		0x5A0ECC46D9B78E3EULL,
		0x3D6CF1DE35CA8E36ULL,
		0x3C6D15793A77FB73ULL
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
		0x900B2FEC297E80BFULL,
		0x67A87BD3C8FC3F65ULL,
		0x179A10BAF239124EULL,
		0x94B0D3DB430D4D37ULL,
		0x0342E45F54C293E4ULL,
		0x30F48F36EB9EE11EULL,
		0xC1BA5691B81B9D63ULL,
		0x27AA6EC946F247F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20165FD852FD017EULL,
		0xCF50F7A791F87ECBULL,
		0x2F342175E472249CULL,
		0x2961A7B6861A9A6EULL,
		0x0685C8BEA98527C9ULL,
		0x61E91E6DD73DC23CULL,
		0x8374AD2370373AC6ULL,
		0x4F54DD928DE48FE9ULL
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
		0x4DD956C6527DDD17ULL,
		0xFC9E741CA6207BA2ULL,
		0x317C0D7FCC64C3A0ULL,
		0xBF98E57539033111ULL,
		0x8B4C818D69EDA5A6ULL,
		0xAF18D47587DD2210ULL,
		0xC7B96D0BA39FD7B0ULL,
		0x195DB9E38636BD5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB2AD8CA4FBBA2EULL,
		0xF93CE8394C40F744ULL,
		0x62F81AFF98C98741ULL,
		0x7F31CAEA72066222ULL,
		0x1699031AD3DB4B4DULL,
		0x5E31A8EB0FBA4421ULL,
		0x8F72DA17473FAF61ULL,
		0x32BB73C70C6D7ABBULL
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
		0xD761ED5CE44CEECCULL,
		0x7B52A5D1CA9BAD87ULL,
		0xEE91E7D809DA258EULL,
		0xEE5BF0E1CE3DF283ULL,
		0x2E7305A1F8D941B8ULL,
		0xD5F903F696519568ULL,
		0x5449513A20EDFC00ULL,
		0x1C02782CBC5C581BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC3DAB9C899DD98ULL,
		0xF6A54BA395375B0FULL,
		0xDD23CFB013B44B1CULL,
		0xDCB7E1C39C7BE507ULL,
		0x5CE60B43F1B28371ULL,
		0xABF207ED2CA32AD0ULL,
		0xA892A27441DBF801ULL,
		0x3804F05978B8B036ULL
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
		0xEEB1BCCB88745B10ULL,
		0xF12261BB8E9293DDULL,
		0x4445757E3C322183ULL,
		0xDC722AE501B74AA4ULL,
		0xFB80C437F242F7FAULL,
		0x4118F0CE63A62506ULL,
		0x9D46A872B4D5CB34ULL,
		0x3A75D336E0658FBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD63799710E8B620ULL,
		0xE244C3771D2527BBULL,
		0x888AEAFC78644307ULL,
		0xB8E455CA036E9548ULL,
		0xF701886FE485EFF5ULL,
		0x8231E19CC74C4A0DULL,
		0x3A8D50E569AB9668ULL,
		0x74EBA66DC0CB1F75ULL
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
		0x4F388597509063FEULL,
		0xFCD00D351392F275ULL,
		0x520789C35DD93345ULL,
		0x3976AEFBD5A6411CULL,
		0x25FD8124DB50E757ULL,
		0x613EC100E84CD9E5ULL,
		0x3CF6A9462BB8F00BULL,
		0x01737C6284D9CAA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E710B2EA120C7FCULL,
		0xF9A01A6A2725E4EAULL,
		0xA40F1386BBB2668BULL,
		0x72ED5DF7AB4C8238ULL,
		0x4BFB0249B6A1CEAEULL,
		0xC27D8201D099B3CAULL,
		0x79ED528C5771E016ULL,
		0x02E6F8C509B3954EULL
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
		0x0F262C1D2C518900ULL,
		0x8C9D41862FCFE8B1ULL,
		0x68EF47EF8246FAC7ULL,
		0xC9F9ED0C86E1EF0BULL,
		0x3C127C89F0FA2061ULL,
		0x7DBE48CB051515A5ULL,
		0xC27181DF41086CA7ULL,
		0x1E39CAC57C0B08AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4C583A58A31200ULL,
		0x193A830C5F9FD162ULL,
		0xD1DE8FDF048DF58FULL,
		0x93F3DA190DC3DE16ULL,
		0x7824F913E1F440C3ULL,
		0xFB7C91960A2A2B4AULL,
		0x84E303BE8210D94EULL,
		0x3C73958AF8161155ULL
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
		0x69928A6116274964ULL,
		0xF31E17421213FCD4ULL,
		0x8294542A4C15BD69ULL,
		0x2141F89185BA9D60ULL,
		0xCEDF97E75E4BE23BULL,
		0x2D01DB80B0210F15ULL,
		0x013616B8D307B658ULL,
		0x07A681F7AACFF717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32514C22C4E92C8ULL,
		0xE63C2E842427F9A8ULL,
		0x0528A854982B7AD3ULL,
		0x4283F1230B753AC1ULL,
		0x9DBF2FCEBC97C476ULL,
		0x5A03B70160421E2BULL,
		0x026C2D71A60F6CB0ULL,
		0x0F4D03EF559FEE2EULL
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
		0x07C4053DE43D1A1DULL,
		0xE077C29D10285153ULL,
		0x63EC31A15ACDAED5ULL,
		0xA7004357E56AACACULL,
		0x7C8B20E6A262E0C6ULL,
		0xDC9C35A1A9DC3814ULL,
		0xB7610B87C3F6BB6FULL,
		0x3E465B323CC0F3B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F880A7BC87A343AULL,
		0xC0EF853A2050A2A6ULL,
		0xC7D86342B59B5DABULL,
		0x4E0086AFCAD55958ULL,
		0xF91641CD44C5C18DULL,
		0xB9386B4353B87028ULL,
		0x6EC2170F87ED76DFULL,
		0x7C8CB6647981E769ULL
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
		0x0278C970028C492FULL,
		0x60FED016189D5939ULL,
		0xFF95D9389D6A2DCAULL,
		0xD4488EE003A4042DULL,
		0xAE1F5DD6520BA6D3ULL,
		0xA02CF85E4BE9E062ULL,
		0xC0A3B168D1C47A58ULL,
		0x3E73A238BB8CE19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F192E00518925EULL,
		0xC1FDA02C313AB272ULL,
		0xFF2BB2713AD45B94ULL,
		0xA8911DC00748085BULL,
		0x5C3EBBACA4174DA7ULL,
		0x4059F0BC97D3C0C5ULL,
		0x814762D1A388F4B1ULL,
		0x7CE744717719C337ULL
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
		0xD6DA27B501482168ULL,
		0x21C415EB9022764EULL,
		0x6AD0DDB8FD02E49FULL,
		0x34FF4E9D10CE9A32ULL,
		0xA2E9D0479231A7E9ULL,
		0x0AF33E874DF957B4ULL,
		0xABDA7D211703A970ULL,
		0x18FBF5F5ADDAB757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB44F6A029042D0ULL,
		0x43882BD72044EC9DULL,
		0xD5A1BB71FA05C93EULL,
		0x69FE9D3A219D3464ULL,
		0x45D3A08F24634FD2ULL,
		0x15E67D0E9BF2AF69ULL,
		0x57B4FA422E0752E0ULL,
		0x31F7EBEB5BB56EAFULL
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
		0x6E72020D18137347ULL,
		0xD6D47045C18FC64AULL,
		0xC5DA906C16093A27ULL,
		0xD91BAED1237E63FDULL,
		0x8253B51DC6D6AE5FULL,
		0x1B497A609969A8FCULL,
		0x49129DA8338BA57EULL,
		0x09A65A3FE976912CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCE4041A3026E68EULL,
		0xADA8E08B831F8C94ULL,
		0x8BB520D82C12744FULL,
		0xB2375DA246FCC7FBULL,
		0x04A76A3B8DAD5CBFULL,
		0x3692F4C132D351F9ULL,
		0x92253B5067174AFCULL,
		0x134CB47FD2ED2258ULL
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
		0x78323CFBBB00C1FEULL,
		0x0813A41F98248DB4ULL,
		0xE09E4BA4E8B12819ULL,
		0xC6DBB00156BB3AAFULL,
		0x50629AEE38D9068CULL,
		0x7FBE38D9DC8A4FA2ULL,
		0x097D44FC9A5EEBC9ULL,
		0x1FC7A27B5606EA69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06479F7760183FCULL,
		0x1027483F30491B68ULL,
		0xC13C9749D1625032ULL,
		0x8DB76002AD76755FULL,
		0xA0C535DC71B20D19ULL,
		0xFF7C71B3B9149F44ULL,
		0x12FA89F934BDD792ULL,
		0x3F8F44F6AC0DD4D2ULL
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
		0x5362DC49526C93E6ULL,
		0x7FDACA088D37F91AULL,
		0x7F4BFCC60B2211D1ULL,
		0xA9EDA3EC29A24D81ULL,
		0x0188246CB6B71225ULL,
		0xACAFB56427B3B957ULL,
		0xC032014524E2018BULL,
		0x15FAE0780090BF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6C5B892A4D927CCULL,
		0xFFB594111A6FF234ULL,
		0xFE97F98C164423A2ULL,
		0x53DB47D853449B02ULL,
		0x031048D96D6E244BULL,
		0x595F6AC84F6772AEULL,
		0x8064028A49C40317ULL,
		0x2BF5C0F001217F3DULL
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
		0x2C992D008EE23C66ULL,
		0x377B110899991A65ULL,
		0x019DC87027A4F134ULL,
		0x54FBDAF8961E87C5ULL,
		0xA421877A11725AEFULL,
		0xA1573C399C7F675DULL,
		0x8B7CDB8BFA3A5ED4ULL,
		0x2AA8CAD1632ACCC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59325A011DC478CCULL,
		0x6EF62211333234CAULL,
		0x033B90E04F49E268ULL,
		0xA9F7B5F12C3D0F8AULL,
		0x48430EF422E4B5DEULL,
		0x42AE787338FECEBBULL,
		0x16F9B717F474BDA9ULL,
		0x555195A2C6559989ULL
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
		0xA3A1FED50C5E8562ULL,
		0x3A90CF49D1F9F340ULL,
		0x4EE367B4871E0A12ULL,
		0x05BF7806F5A20C2CULL,
		0x721EE60CC17D6E1BULL,
		0x216ACA4C21979D01ULL,
		0xC41470D87BCE87A6ULL,
		0x329A65C2DF486463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4743FDAA18BD0AC4ULL,
		0x75219E93A3F3E681ULL,
		0x9DC6CF690E3C1424ULL,
		0x0B7EF00DEB441858ULL,
		0xE43DCC1982FADC36ULL,
		0x42D59498432F3A02ULL,
		0x8828E1B0F79D0F4CULL,
		0x6534CB85BE90C8C7ULL
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
		0xC0942870058D735BULL,
		0x2835081137C43360ULL,
		0x89A894AAE21DC331ULL,
		0xF5CA174D6CE707A4ULL,
		0xA4FB6A00A95074EAULL,
		0xE25B0B141A808D4CULL,
		0xF53ABC46B71CF8E7ULL,
		0x01C41C57724BDC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812850E00B1AE6B6ULL,
		0x506A10226F8866C1ULL,
		0x13512955C43B8662ULL,
		0xEB942E9AD9CE0F49ULL,
		0x49F6D40152A0E9D5ULL,
		0xC4B6162835011A99ULL,
		0xEA75788D6E39F1CFULL,
		0x038838AEE497B86DULL
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
		0x385C03687DD7C8CBULL,
		0x3C5935A0D594491EULL,
		0xEEF31176820B7836ULL,
		0xB6D1DEC0C0FB26E6ULL,
		0x3B95F19EEB7F8F0CULL,
		0x343FE2E1F1DE749CULL,
		0xF0FE783E3EA52297ULL,
		0x2AED142DFE7EDCFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B806D0FBAF9196ULL,
		0x78B26B41AB28923CULL,
		0xDDE622ED0416F06CULL,
		0x6DA3BD8181F64DCDULL,
		0x772BE33DD6FF1E19ULL,
		0x687FC5C3E3BCE938ULL,
		0xE1FCF07C7D4A452EULL,
		0x55DA285BFCFDB9F9ULL
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
		0xF5967FE847653F5CULL,
		0x504899FC412E65A7ULL,
		0xB9C9FAF16101583BULL,
		0xB6D644D3135467FBULL,
		0xE5D2CAF3DF9E5201ULL,
		0x9DCAA3129B9B663CULL,
		0x503979F647C62453ULL,
		0x2E275EC46671EFBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB2CFFD08ECA7EB8ULL,
		0xA09133F8825CCB4FULL,
		0x7393F5E2C202B076ULL,
		0x6DAC89A626A8CFF7ULL,
		0xCBA595E7BF3CA403ULL,
		0x3B9546253736CC79ULL,
		0xA072F3EC8F8C48A7ULL,
		0x5C4EBD88CCE3DF74ULL
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
		0x7290AA188DEC00E1ULL,
		0xEC5756D77B869A2BULL,
		0xAE8F10C71B263765ULL,
		0x3D36BE2482BA54D7ULL,
		0xDF62F2565F0A3EA0ULL,
		0x399EA8D19AF656EEULL,
		0xFA4FCD99910A70A7ULL,
		0x206ACFCEC927F971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE52154311BD801C2ULL,
		0xD8AEADAEF70D3456ULL,
		0x5D1E218E364C6ECBULL,
		0x7A6D7C490574A9AFULL,
		0xBEC5E4ACBE147D40ULL,
		0x733D51A335ECADDDULL,
		0xF49F9B332214E14EULL,
		0x40D59F9D924FF2E3ULL
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
		0xD52860074FDC105CULL,
		0x0D1B4C071FF3CD7BULL,
		0xCB22574C6F355E22ULL,
		0x7B4DB7203EB10745ULL,
		0x2ACA82026980D3DDULL,
		0xCE2D88D0A4A233D4ULL,
		0x2A4BA93587402903ULL,
		0x22F9CE6A179456D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA50C00E9FB820B8ULL,
		0x1A36980E3FE79AF7ULL,
		0x9644AE98DE6ABC44ULL,
		0xF69B6E407D620E8BULL,
		0x55950404D301A7BAULL,
		0x9C5B11A1494467A8ULL,
		0x5497526B0E805207ULL,
		0x45F39CD42F28ADAEULL
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
		0x9BBEA96E2DEA9A55ULL,
		0x11515CE3B6A60042ULL,
		0xB4B1CAFB505A3E08ULL,
		0x80522B654A1F2CD7ULL,
		0x496AA86EA039CB5FULL,
		0xA3EF963233549448ULL,
		0xF4B58648FE30504DULL,
		0x3D6C9177CAA4B13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x377D52DC5BD534AAULL,
		0x22A2B9C76D4C0085ULL,
		0x696395F6A0B47C10ULL,
		0x00A456CA943E59AFULL,
		0x92D550DD407396BFULL,
		0x47DF2C6466A92890ULL,
		0xE96B0C91FC60A09BULL,
		0x7AD922EF95496277ULL
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
		0xF5D0AFC6279D870AULL,
		0x47D86448F3B11B06ULL,
		0xF11196DFD6D641EEULL,
		0xB8CF170F6975A251ULL,
		0x051239753CE3C277ULL,
		0xE7922952DF62F413ULL,
		0x202624F52FB7C875ULL,
		0x0D64D5A25520820EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA15F8C4F3B0E14ULL,
		0x8FB0C891E762360DULL,
		0xE2232DBFADAC83DCULL,
		0x719E2E1ED2EB44A3ULL,
		0x0A2472EA79C784EFULL,
		0xCF2452A5BEC5E826ULL,
		0x404C49EA5F6F90EBULL,
		0x1AC9AB44AA41041CULL
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
		0xC76DA003389C9D4BULL,
		0x55C4A31D55986ADAULL,
		0x624D7BB1FD919B39ULL,
		0xFE1DFD1DB53806E5ULL,
		0x81B2928CFA686C34ULL,
		0x18926649E7F2ADC7ULL,
		0x284130CBE28E02E3ULL,
		0x197B320C2C3822F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDB400671393A96ULL,
		0xAB89463AAB30D5B5ULL,
		0xC49AF763FB233672ULL,
		0xFC3BFA3B6A700DCAULL,
		0x03652519F4D0D869ULL,
		0x3124CC93CFE55B8FULL,
		0x50826197C51C05C6ULL,
		0x32F66418587045EAULL
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
		0xD5356585D675A06CULL,
		0xC7964ED35B2B7467ULL,
		0x32BD4C9A2D714927ULL,
		0x7C4E2EC897C2CE7BULL,
		0xF46659D9357FF2C1ULL,
		0x3EDC752C4B015E5BULL,
		0xB32FCF9DA4225ECAULL,
		0x294CCE0AB2037600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA6ACB0BACEB40D8ULL,
		0x8F2C9DA6B656E8CFULL,
		0x657A99345AE2924FULL,
		0xF89C5D912F859CF6ULL,
		0xE8CCB3B26AFFE582ULL,
		0x7DB8EA589602BCB7ULL,
		0x665F9F3B4844BD94ULL,
		0x52999C156406EC01ULL
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
		0xF3B25003D712EB05ULL,
		0x487B4E20DA0D1E75ULL,
		0xC38CF89B977BE4A4ULL,
		0x133945AD33B302F3ULL,
		0xF7C68DF7AEF6E227ULL,
		0x0FBF57C9DAD30C4CULL,
		0xA2D00E8D243EE121ULL,
		0x1EC22486AB77BA37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE764A007AE25D60AULL,
		0x90F69C41B41A3CEBULL,
		0x8719F1372EF7C948ULL,
		0x26728B5A676605E7ULL,
		0xEF8D1BEF5DEDC44EULL,
		0x1F7EAF93B5A61899ULL,
		0x45A01D1A487DC242ULL,
		0x3D84490D56EF746FULL
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
		0x7B2AE530E48519BCULL,
		0xDDF7CE6C24491926ULL,
		0xE0D60FD4768453AFULL,
		0x5F959D9FE071B029ULL,
		0xA272BB96A40A6EC0ULL,
		0xE66527D88EB51152ULL,
		0x82754A0425E27F02ULL,
		0x1938F3CD4DE95C3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF655CA61C90A3378ULL,
		0xBBEF9CD84892324CULL,
		0xC1AC1FA8ED08A75FULL,
		0xBF2B3B3FC0E36053ULL,
		0x44E5772D4814DD80ULL,
		0xCCCA4FB11D6A22A5ULL,
		0x04EA94084BC4FE05ULL,
		0x3271E79A9BD2B875ULL
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
		0x3364572350498183ULL,
		0x078FE21C7BB0C12EULL,
		0x78F1DA1C85533F88ULL,
		0xAF9CE7F533781412ULL,
		0x89B178AF0391AE55ULL,
		0xB41C24F0A799533CULL,
		0xC6A78C5FC0559AD6ULL,
		0x2EA3ECE709F034B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C8AE46A0930306ULL,
		0x0F1FC438F761825CULL,
		0xF1E3B4390AA67F10ULL,
		0x5F39CFEA66F02824ULL,
		0x1362F15E07235CABULL,
		0x683849E14F32A679ULL,
		0x8D4F18BF80AB35ADULL,
		0x5D47D9CE13E06967ULL
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
		0x12F95427D6DA1000ULL,
		0xA94B724F185BF0FFULL,
		0xCBB3079BE89D86AFULL,
		0xD5932210017CD9B0ULL,
		0x48CAA815A36D9673ULL,
		0xCEB88E7BDBF94FDCULL,
		0xAE7ECCC7A8357B62ULL,
		0x23EA271B982D0D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F2A84FADB42000ULL,
		0x5296E49E30B7E1FEULL,
		0x97660F37D13B0D5FULL,
		0xAB26442002F9B361ULL,
		0x9195502B46DB2CE7ULL,
		0x9D711CF7B7F29FB8ULL,
		0x5CFD998F506AF6C5ULL,
		0x47D44E37305A1A5FULL
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
		0x561EDE9E7A6295E0ULL,
		0x642FAEE7B000BEC2ULL,
		0x40B7FAEF58B960A4ULL,
		0x95549B77FAE47E8BULL,
		0x92A211DD8E541AB5ULL,
		0x866A581148D274DFULL,
		0xBEDA527E3F8B1132ULL,
		0x125C404277D47D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3DBD3CF4C52BC0ULL,
		0xC85F5DCF60017D84ULL,
		0x816FF5DEB172C148ULL,
		0x2AA936EFF5C8FD16ULL,
		0x254423BB1CA8356BULL,
		0x0CD4B02291A4E9BFULL,
		0x7DB4A4FC7F162265ULL,
		0x24B88084EFA8FA6BULL
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
		0x413EF18BB1CAEBC1ULL,
		0xEE00B0751E635E36ULL,
		0x4E0EBB07CD71511AULL,
		0x70FFB56C046973B5ULL,
		0x088C5C393FD329FDULL,
		0xB018BA8717CA2D56ULL,
		0x29F30561AE317F11ULL,
		0x22CACFD2BB71B8FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x827DE3176395D782ULL,
		0xDC0160EA3CC6BC6CULL,
		0x9C1D760F9AE2A235ULL,
		0xE1FF6AD808D2E76AULL,
		0x1118B8727FA653FAULL,
		0x6031750E2F945AACULL,
		0x53E60AC35C62FE23ULL,
		0x45959FA576E371F4ULL
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
		0xBFB976E7CBA9AF66ULL,
		0xBA2C29E606C61630ULL,
		0xA25688E722BA9317ULL,
		0x72F35894D19EB060ULL,
		0x30D9720821509C70ULL,
		0x5598F026A61728FBULL,
		0xC4D28941F42B1CC8ULL,
		0x1BE78C2D0DD7080BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F72EDCF97535ECCULL,
		0x745853CC0D8C2C61ULL,
		0x44AD11CE4575262FULL,
		0xE5E6B129A33D60C1ULL,
		0x61B2E41042A138E0ULL,
		0xAB31E04D4C2E51F6ULL,
		0x89A51283E8563990ULL,
		0x37CF185A1BAE1017ULL
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
		0x08837D43C0A6188BULL,
		0x64151AC5674375A8ULL,
		0xC02A91C2D8F40702ULL,
		0x73F48C0800F8A7DBULL,
		0x6B570E02B07CDF3FULL,
		0x8C29767AD3FAA9DBULL,
		0x9A882A05F3EF79B6ULL,
		0x08B293C40770EDF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1106FA87814C3116ULL,
		0xC82A358ACE86EB50ULL,
		0x80552385B1E80E04ULL,
		0xE7E9181001F14FB7ULL,
		0xD6AE1C0560F9BE7EULL,
		0x1852ECF5A7F553B6ULL,
		0x3510540BE7DEF36DULL,
		0x116527880EE1DBF3ULL
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
		0x4E414D86603B9F5FULL,
		0x48DEB3E7F794C4D1ULL,
		0xA80C1D47852C853AULL,
		0xDF337E0FF86BE6BCULL,
		0x48F5C8EA3B7754D9ULL,
		0xC745CD5B9A312DCDULL,
		0x830CDB1CB2ED2C1BULL,
		0x2BDB057AE40817F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C829B0CC0773EBEULL,
		0x91BD67CFEF2989A2ULL,
		0x50183A8F0A590A74ULL,
		0xBE66FC1FF0D7CD79ULL,
		0x91EB91D476EEA9B3ULL,
		0x8E8B9AB734625B9AULL,
		0x0619B63965DA5837ULL,
		0x57B60AF5C8102FF1ULL
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
		0x4659B1AC01B8A26AULL,
		0x6705669B54FE2AE9ULL,
		0x0D9C25CC8B75B961ULL,
		0x747D34DBA09D24BCULL,
		0x3654527DEE48945AULL,
		0x9C8C0BCE899D6EA2ULL,
		0xA11E72EF8FC388C4ULL,
		0x384F2790D03B3135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB36358037144D4ULL,
		0xCE0ACD36A9FC55D2ULL,
		0x1B384B9916EB72C2ULL,
		0xE8FA69B7413A4978ULL,
		0x6CA8A4FBDC9128B4ULL,
		0x3918179D133ADD44ULL,
		0x423CE5DF1F871189ULL,
		0x709E4F21A076626BULL
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
		0x519171536B2D77EAULL,
		0x070175752C4C23B1ULL,
		0xAE369B4336E270A6ULL,
		0x89D9D9DDC9F22104ULL,
		0xE52E7FEEB1113D2CULL,
		0x9968CEEE39A385C7ULL,
		0xDF9B2BEFACD7B97BULL,
		0x2E71A036CB728003ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA322E2A6D65AEFD4ULL,
		0x0E02EAEA58984762ULL,
		0x5C6D36866DC4E14CULL,
		0x13B3B3BB93E44209ULL,
		0xCA5CFFDD62227A59ULL,
		0x32D19DDC73470B8FULL,
		0xBF3657DF59AF72F7ULL,
		0x5CE3406D96E50007ULL
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
		0x4F88F9A95C317288ULL,
		0x15CBF51121AD2331ULL,
		0xFB33E363A39E9BE3ULL,
		0x0AB06637D2FF1C0FULL,
		0x08D9AB1764443986ULL,
		0xFAA7FADA1C4C1525ULL,
		0x21C7E022AEC069F9ULL,
		0x018824DBE11570E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F11F352B862E510ULL,
		0x2B97EA22435A4662ULL,
		0xF667C6C7473D37C6ULL,
		0x1560CC6FA5FE381FULL,
		0x11B3562EC888730CULL,
		0xF54FF5B438982A4AULL,
		0x438FC0455D80D3F3ULL,
		0x031049B7C22AE1D0ULL
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
		0xFDB2529154A4D1A8ULL,
		0x8D72535B814548D1ULL,
		0x2DF1467702159CA7ULL,
		0xAC8B79914C2C3ABCULL,
		0x31E8C0F0C0930A8EULL,
		0x8DB253796B254413ULL,
		0xF3093879A86BCB52ULL,
		0x09FD41EEA9E7F807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB64A522A949A350ULL,
		0x1AE4A6B7028A91A3ULL,
		0x5BE28CEE042B394FULL,
		0x5916F32298587578ULL,
		0x63D181E18126151DULL,
		0x1B64A6F2D64A8826ULL,
		0xE61270F350D796A5ULL,
		0x13FA83DD53CFF00FULL
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
		0x86FDC15D037BE0DEULL,
		0x89FFC5B77B5A4438ULL,
		0x3FBFAC297B174AE1ULL,
		0x9EFB534425F05859ULL,
		0xEB911CE1527D129BULL,
		0xF5C15E8DE6DE1304ULL,
		0x1A741056CED18A26ULL,
		0x2C0896A853A004BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFB82BA06F7C1BCULL,
		0x13FF8B6EF6B48871ULL,
		0x7F7F5852F62E95C3ULL,
		0x3DF6A6884BE0B0B2ULL,
		0xD72239C2A4FA2537ULL,
		0xEB82BD1BCDBC2609ULL,
		0x34E820AD9DA3144DULL,
		0x58112D50A7400974ULL
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
		0x8E17C628F739FF8EULL,
		0xD580D611BD6207A3ULL,
		0xD6F544804E4327DAULL,
		0x34EA07529DFAADD5ULL,
		0xF9E3237AF2417DB3ULL,
		0x14E404F289FF5864ULL,
		0x230617CBFCD82558ULL,
		0x11A3146D4DEC9936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2F8C51EE73FF1CULL,
		0xAB01AC237AC40F47ULL,
		0xADEA89009C864FB5ULL,
		0x69D40EA53BF55BABULL,
		0xF3C646F5E482FB66ULL,
		0x29C809E513FEB0C9ULL,
		0x460C2F97F9B04AB0ULL,
		0x234628DA9BD9326CULL
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
		0x764FDF549626FFC7ULL,
		0x8AABA5576D4F5F9EULL,
		0xA9E8E9B41B62A28CULL,
		0x96701DF891F2BBD6ULL,
		0x42B77C6D463980A1ULL,
		0x60292A737397B7DAULL,
		0x9CC3FBA24552ACE1ULL,
		0x10524DE93D6AFEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC9FBEA92C4DFF8EULL,
		0x15574AAEDA9EBF3CULL,
		0x53D1D36836C54519ULL,
		0x2CE03BF123E577ADULL,
		0x856EF8DA8C730143ULL,
		0xC05254E6E72F6FB4ULL,
		0x3987F7448AA559C2ULL,
		0x20A49BD27AD5FDB9ULL
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
		0xCBA95C3F16B5A1ECULL,
		0xD6F00178E962A509ULL,
		0x42A72483A04DEE30ULL,
		0x96A2B1DA638A4FDDULL,
		0xA7683C6CB3AD39ADULL,
		0x24B92DF42BD920B4ULL,
		0x3C140FB79BC91E4AULL,
		0x1DAC570292314653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9752B87E2D6B43D8ULL,
		0xADE002F1D2C54A13ULL,
		0x854E4907409BDC61ULL,
		0x2D4563B4C7149FBAULL,
		0x4ED078D9675A735BULL,
		0x49725BE857B24169ULL,
		0x78281F6F37923C94ULL,
		0x3B58AE0524628CA6ULL
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
		0xCB0FA3DC048BA4DFULL,
		0xF183762AC20A4435ULL,
		0x0D745432451167AAULL,
		0x1605B207CF1626EAULL,
		0x49412EC1768A57C2ULL,
		0x7B7F76AA725FB0A7ULL,
		0x5359C23B1969C320ULL,
		0x2F66FDA18575BB58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x961F47B8091749BEULL,
		0xE306EC558414886BULL,
		0x1AE8A8648A22CF55ULL,
		0x2C0B640F9E2C4DD4ULL,
		0x92825D82ED14AF84ULL,
		0xF6FEED54E4BF614EULL,
		0xA6B3847632D38640ULL,
		0x5ECDFB430AEB76B0ULL
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
		0x664F838289C0AA12ULL,
		0x4207583762500061ULL,
		0x87FED350767D5D71ULL,
		0x4B62596764B0FC7CULL,
		0x0443D35CC6B7668DULL,
		0x1D16ED2500473B3EULL,
		0x6F373B7E106CCB76ULL,
		0x130C25FE2A60E1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC9F070513815424ULL,
		0x840EB06EC4A000C2ULL,
		0x0FFDA6A0ECFABAE2ULL,
		0x96C4B2CEC961F8F9ULL,
		0x0887A6B98D6ECD1AULL,
		0x3A2DDA4A008E767CULL,
		0xDE6E76FC20D996ECULL,
		0x26184BFC54C1C388ULL
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
		0xF289236A28EDDDD6ULL,
		0x417A693429092054ULL,
		0x5DAA9CF77C48B5BEULL,
		0xE816A50BF96ACC7CULL,
		0x830A5E16FB11B3E4ULL,
		0x9383B3923983BA54ULL,
		0x68B0830046032067ULL,
		0x2428D87D5C3DB07AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51246D451DBBBACULL,
		0x82F4D268521240A9ULL,
		0xBB5539EEF8916B7CULL,
		0xD02D4A17F2D598F8ULL,
		0x0614BC2DF62367C9ULL,
		0x27076724730774A9ULL,
		0xD16106008C0640CFULL,
		0x4851B0FAB87B60F4ULL
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
		0x31F9EE3058D77BC2ULL,
		0x0675E4BAC4559584ULL,
		0x10E0F8208BF67557ULL,
		0x7A8F6BBC37AEB9BFULL,
		0xB4BBCE10D7E6ED0DULL,
		0xF8785841151AD6F5ULL,
		0x153D32ACE399EEB9ULL,
		0x0387120E2BB5E9F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F3DC60B1AEF784ULL,
		0x0CEBC97588AB2B08ULL,
		0x21C1F04117ECEAAEULL,
		0xF51ED7786F5D737EULL,
		0x69779C21AFCDDA1AULL,
		0xF0F0B0822A35ADEBULL,
		0x2A7A6559C733DD73ULL,
		0x070E241C576BD3E6ULL
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
		0xEFFF0DE04C3D1771ULL,
		0x1F1034191625AF11ULL,
		0x13E2E24EC7B8750AULL,
		0xF6DE6B55D83A08A7ULL,
		0x496A9438CC7681B4ULL,
		0xCF7305F0D1E3A9A4ULL,
		0x4E89DC1CB0612EF5ULL,
		0x3A2F6A9A766FA1DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFFE1BC0987A2EE2ULL,
		0x3E2068322C4B5E23ULL,
		0x27C5C49D8F70EA14ULL,
		0xEDBCD6ABB074114EULL,
		0x92D5287198ED0369ULL,
		0x9EE60BE1A3C75348ULL,
		0x9D13B83960C25DEBULL,
		0x745ED534ECDF43BCULL
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
		0x4AF7753D55532A95ULL,
		0x1B36442F36EC4212ULL,
		0x2DFCC530CAF12C87ULL,
		0x1AE2D366AEB66FBFULL,
		0xF7DDD4A023FAD158ULL,
		0x82C58EB5DC9B8B6FULL,
		0x21CD893984105D3CULL,
		0x34221C51847F809AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EEEA7AAAA6552AULL,
		0x366C885E6DD88424ULL,
		0x5BF98A6195E2590EULL,
		0x35C5A6CD5D6CDF7EULL,
		0xEFBBA94047F5A2B0ULL,
		0x058B1D6BB93716DFULL,
		0x439B12730820BA79ULL,
		0x684438A308FF0134ULL
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
		0x258618DD00E433D8ULL,
		0x34245B0CA4268E25ULL,
		0x7682C45DBF8669F5ULL,
		0x1A53A50996E8AED0ULL,
		0x5A6DC74C7380606AULL,
		0xBB375B1845D1B093ULL,
		0x15FAA74EBEA5E0E1ULL,
		0x12AD0C33EFBF68CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0C31BA01C867B0ULL,
		0x6848B619484D1C4AULL,
		0xED0588BB7F0CD3EAULL,
		0x34A74A132DD15DA0ULL,
		0xB4DB8E98E700C0D4ULL,
		0x766EB6308BA36126ULL,
		0x2BF54E9D7D4BC1C3ULL,
		0x255A1867DF7ED196ULL
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
		0x86F31C24DAA345C1ULL,
		0xC3ECB0BCAA373385ULL,
		0xCA0EA0287F578D2DULL,
		0xEB542A70EC9686C1ULL,
		0x70669D84EF556A25ULL,
		0x6306F3F1ACE9B705ULL,
		0x866B192C74A1F0EFULL,
		0x1A2265D173ABAFC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE63849B5468B82ULL,
		0x87D96179546E670BULL,
		0x941D4050FEAF1A5BULL,
		0xD6A854E1D92D0D83ULL,
		0xE0CD3B09DEAAD44BULL,
		0xC60DE7E359D36E0AULL,
		0x0CD63258E943E1DEULL,
		0x3444CBA2E7575F83ULL
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
		0x0B8AB620CD0C67C2ULL,
		0x168963FDEF88CBB3ULL,
		0x5CC841796A1E3188ULL,
		0x93B075D4D416D9A4ULL,
		0x258F1A49A70DABA1ULL,
		0x851EB01EE0E51B32ULL,
		0x62DEF63092C3B367ULL,
		0x2D68201D1CBF2771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17156C419A18CF84ULL,
		0x2D12C7FBDF119766ULL,
		0xB99082F2D43C6310ULL,
		0x2760EBA9A82DB348ULL,
		0x4B1E34934E1B5743ULL,
		0x0A3D603DC1CA3664ULL,
		0xC5BDEC61258766CFULL,
		0x5AD0403A397E4EE2ULL
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
		0xEE9FBEDD0D3BE7A6ULL,
		0x1C76B28FF7428DB0ULL,
		0x01829F20600D0CFFULL,
		0xA290C912F24514C4ULL,
		0xAFCB1E053680EF19ULL,
		0xE0433195BC99238EULL,
		0xA1A471475EB1A5FEULL,
		0x1ED8305B30D53FB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3F7DBA1A77CF4CULL,
		0x38ED651FEE851B61ULL,
		0x03053E40C01A19FEULL,
		0x45219225E48A2988ULL,
		0x5F963C0A6D01DE33ULL,
		0xC086632B7932471DULL,
		0x4348E28EBD634BFDULL,
		0x3DB060B661AA7F6BULL
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
		0xF79B3773C92E56F8ULL,
		0x99E97EFF21D5114CULL,
		0x003B2154EF72BAFDULL,
		0x9BF68D1D39466892ULL,
		0x6DED9EC33432BD4DULL,
		0x85EA2FE7015F8A4AULL,
		0x5CC00EDED28FAF0BULL,
		0x16F20011B34754E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF366EE7925CADF0ULL,
		0x33D2FDFE43AA2299ULL,
		0x007642A9DEE575FBULL,
		0x37ED1A3A728CD124ULL,
		0xDBDB3D8668657A9BULL,
		0x0BD45FCE02BF1494ULL,
		0xB9801DBDA51F5E17ULL,
		0x2DE40023668EA9D0ULL
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
		0xD6369B1E44799D46ULL,
		0x1B6378FF5AF70EB6ULL,
		0xF585543B5AB632CBULL,
		0x55040292BEA18FF3ULL,
		0xE682D6E3BF1C400AULL,
		0x9A88432C46575D82ULL,
		0xE99B2BFADA6A0232ULL,
		0x18529F11BA5CF66BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC6D363C88F33A8CULL,
		0x36C6F1FEB5EE1D6DULL,
		0xEB0AA876B56C6596ULL,
		0xAA0805257D431FE7ULL,
		0xCD05ADC77E388014ULL,
		0x351086588CAEBB05ULL,
		0xD33657F5B4D40465ULL,
		0x30A53E2374B9ECD7ULL
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
		0xBCF2DE275B641AC4ULL,
		0x9B91694934D57494ULL,
		0x311F0128A4308584ULL,
		0x33CF16857BF65DF4ULL,
		0x6C98173E23A263EAULL,
		0x3BF6737178A7978FULL,
		0x12981F488E803ACEULL,
		0x07E003D2978E545BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79E5BC4EB6C83588ULL,
		0x3722D29269AAE929ULL,
		0x623E025148610B09ULL,
		0x679E2D0AF7ECBBE8ULL,
		0xD9302E7C4744C7D4ULL,
		0x77ECE6E2F14F2F1EULL,
		0x25303E911D00759CULL,
		0x0FC007A52F1CA8B6ULL
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
		0x2EA6E1277096F9DDULL,
		0x0FFC37E5935E872EULL,
		0x5EB603F2A5FAF982ULL,
		0x181D17B24C5DCA45ULL,
		0x14D16EFDCD903E18ULL,
		0x9F131012CF775EEEULL,
		0x867DC28F3A5D1BA5ULL,
		0x04F9EE87EE4D23C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4DC24EE12DF3BAULL,
		0x1FF86FCB26BD0E5CULL,
		0xBD6C07E54BF5F304ULL,
		0x303A2F6498BB948AULL,
		0x29A2DDFB9B207C30ULL,
		0x3E2620259EEEBDDCULL,
		0x0CFB851E74BA374BULL,
		0x09F3DD0FDC9A4789ULL
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
		0x6BBD7ACDA1FA86FAULL,
		0x842105AF5F7D33E8ULL,
		0xA9C3E1AB421BF135ULL,
		0x6DF536F372412729ULL,
		0x2A0B231863D8CCE4ULL,
		0x7A005AB6ADD91287ULL,
		0x6C80BE6172BE227EULL,
		0x2DBE1FB1BFEB4E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD77AF59B43F50DF4ULL,
		0x08420B5EBEFA67D0ULL,
		0x5387C3568437E26BULL,
		0xDBEA6DE6E4824E53ULL,
		0x54164630C7B199C8ULL,
		0xF400B56D5BB2250EULL,
		0xD9017CC2E57C44FCULL,
		0x5B7C3F637FD69CC4ULL
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
		0xBDDC23CD6D2BEDA1ULL,
		0x5E9BD670077B3200ULL,
		0xFB348B665064B1C0ULL,
		0xC6C4EF65BFB70A68ULL,
		0x9A068275755102B1ULL,
		0x0CA42658A3B8EC28ULL,
		0x41910C91CE792B2EULL,
		0x1FB9A966CACACA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BB8479ADA57DB42ULL,
		0xBD37ACE00EF66401ULL,
		0xF66916CCA0C96380ULL,
		0x8D89DECB7F6E14D1ULL,
		0x340D04EAEAA20563ULL,
		0x19484CB14771D851ULL,
		0x832219239CF2565CULL,
		0x3F7352CD95959482ULL
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
		0x71E4508973FD9F5BULL,
		0x27507AA6F06EABC7ULL,
		0x0747F8F2BDD22147ULL,
		0x889011F005CE8DA4ULL,
		0xF5DDC3B843DA982CULL,
		0x7D25A15B959311F8ULL,
		0x1239CC6F28421888ULL,
		0x1FC4AC9FB880423BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C8A112E7FB3EB6ULL,
		0x4EA0F54DE0DD578EULL,
		0x0E8FF1E57BA4428EULL,
		0x112023E00B9D1B48ULL,
		0xEBBB877087B53059ULL,
		0xFA4B42B72B2623F1ULL,
		0x247398DE50843110ULL,
		0x3F89593F71008476ULL
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
		0xC217737381BA37EDULL,
		0x8534B78DA9A4B857ULL,
		0xFFB0D200865E4552ULL,
		0xE5B6921099954B7BULL,
		0x7F409BFAF88C7F2AULL,
		0x1B28CE97BAEFF2C9ULL,
		0xA9849CCBB3C08294ULL,
		0x20A775EB7F82551EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842EE6E703746FDAULL,
		0x0A696F1B534970AFULL,
		0xFF61A4010CBC8AA5ULL,
		0xCB6D2421332A96F7ULL,
		0xFE8137F5F118FE55ULL,
		0x36519D2F75DFE592ULL,
		0x5309399767810528ULL,
		0x414EEBD6FF04AA3DULL
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
		0x799B660410FFE115ULL,
		0x3CDF1BC6D5CBDF54ULL,
		0x0B3BF637D3F2A4C8ULL,
		0x191F12021C389862ULL,
		0xC09747826EF0AD10ULL,
		0x68CB1A7222AB916CULL,
		0xB9724380970B0752ULL,
		0x310CCE277E4C3966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF336CC0821FFC22AULL,
		0x79BE378DAB97BEA8ULL,
		0x1677EC6FA7E54990ULL,
		0x323E2404387130C4ULL,
		0x812E8F04DDE15A20ULL,
		0xD19634E4455722D9ULL,
		0x72E487012E160EA4ULL,
		0x62199C4EFC9872CDULL
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
		0x8250A2ED763DB7E8ULL,
		0xFEF40E91763CDA94ULL,
		0xDD75A5F2D6A656EDULL,
		0xC6FC6DAA3ED69CC9ULL,
		0x4640B1EEE4E3C72FULL,
		0xA832A32F4149351EULL,
		0xD86290727271DEB5ULL,
		0x1C9DDC044A289D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04A145DAEC7B6FD0ULL,
		0xFDE81D22EC79B529ULL,
		0xBAEB4BE5AD4CADDBULL,
		0x8DF8DB547DAD3993ULL,
		0x8C8163DDC9C78E5FULL,
		0x5065465E82926A3CULL,
		0xB0C520E4E4E3BD6BULL,
		0x393BB80894513AE3ULL
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
		0xC29CC3FCEC6706BFULL,
		0xC78E302550D4C62CULL,
		0x784F3163076F3C3FULL,
		0xD5D373B775F95BFFULL,
		0x36EDE00C585C7BD3ULL,
		0xB8D28AD7BB0C5161ULL,
		0x9B341A5E4A2B4AF0ULL,
		0x1001272EA5E9444BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x853987F9D8CE0D7EULL,
		0x8F1C604AA1A98C59ULL,
		0xF09E62C60EDE787FULL,
		0xABA6E76EEBF2B7FEULL,
		0x6DDBC018B0B8F7A7ULL,
		0x71A515AF7618A2C2ULL,
		0x366834BC945695E1ULL,
		0x20024E5D4BD28897ULL
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
		0x4F93F8D68FDFCCEAULL,
		0xC15FDEC3E937BF7FULL,
		0x990C0A4E72377906ULL,
		0x20B0D5D2A5B8304DULL,
		0x75F7D75DA59DB9ACULL,
		0x613BD7966B4C33FBULL,
		0xF64A2CEDDC0412B7ULL,
		0x1B895709E7D1F6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F27F1AD1FBF99D4ULL,
		0x82BFBD87D26F7EFEULL,
		0x3218149CE46EF20DULL,
		0x4161ABA54B70609BULL,
		0xEBEFAEBB4B3B7358ULL,
		0xC277AF2CD69867F6ULL,
		0xEC9459DBB808256EULL,
		0x3712AE13CFA3EDFDULL
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
		0x0CDA19E647DED3BFULL,
		0x13DA3903C8631CE1ULL,
		0xB08E7EBD4BED0B4CULL,
		0xB034D20659CA7D15ULL,
		0x415688C10255DA14ULL,
		0x567E3F23C3BEC244ULL,
		0xB98EFD9D29FB2608ULL,
		0x0EAB031CA484CA14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19B433CC8FBDA77EULL,
		0x27B4720790C639C2ULL,
		0x611CFD7A97DA1698ULL,
		0x6069A40CB394FA2BULL,
		0x82AD118204ABB429ULL,
		0xACFC7E47877D8488ULL,
		0x731DFB3A53F64C10ULL,
		0x1D56063949099429ULL
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
		0x6001680D3B85E11BULL,
		0x59BD01498D62C3C6ULL,
		0xACDAA74501C313F3ULL,
		0xE67FAB4B404DA975ULL,
		0xE77A95349DCC647FULL,
		0x9D3A3703312F87D4ULL,
		0x317FF75735CF8988ULL,
		0x1B83BC84AB1C1C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC002D01A770BC236ULL,
		0xB37A02931AC5878CULL,
		0x59B54E8A038627E6ULL,
		0xCCFF5696809B52EBULL,
		0xCEF52A693B98C8FFULL,
		0x3A746E06625F0FA9ULL,
		0x62FFEEAE6B9F1311ULL,
		0x370779095638381AULL
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
		0x264F2572BDEFF261ULL,
		0xB9AF25FF9A725515ULL,
		0x8AC5D3A7F74C081FULL,
		0x492B9D3A60C6F774ULL,
		0xE8E4D517F50E74F1ULL,
		0x505A61F6C10817D0ULL,
		0xFC516AE77C6939D9ULL,
		0x34C5F40D479549AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C9E4AE57BDFE4C2ULL,
		0x735E4BFF34E4AA2AULL,
		0x158BA74FEE98103FULL,
		0x92573A74C18DEEE9ULL,
		0xD1C9AA2FEA1CE9E2ULL,
		0xA0B4C3ED82102FA1ULL,
		0xF8A2D5CEF8D273B2ULL,
		0x698BE81A8F2A935FULL
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
		0x56655BDD381F6EACULL,
		0xED254955B37D666CULL,
		0xA11205786FAD874AULL,
		0xFA8D38D8DF2F9F56ULL,
		0x3C075B4B3484C5E1ULL,
		0xADD840857BC8D7C2ULL,
		0x1CD542F9EF962643ULL,
		0x36FF46FADAC098F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCAB7BA703EDD58ULL,
		0xDA4A92AB66FACCD8ULL,
		0x42240AF0DF5B0E95ULL,
		0xF51A71B1BE5F3EADULL,
		0x780EB69669098BC3ULL,
		0x5BB0810AF791AF84ULL,
		0x39AA85F3DF2C4C87ULL,
		0x6DFE8DF5B58131EAULL
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
		0x469B65F2F3322C9CULL,
		0x40C752A05B53057FULL,
		0x32648CE8586B22E0ULL,
		0x5F10EFDC4D510B68ULL,
		0xF2F8814BA04497CDULL,
		0xE7D1E99E08006473ULL,
		0xD66DBC5D3DC898C7ULL,
		0x1789BD2D5D94638BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D36CBE5E6645938ULL,
		0x818EA540B6A60AFEULL,
		0x64C919D0B0D645C0ULL,
		0xBE21DFB89AA216D0ULL,
		0xE5F1029740892F9AULL,
		0xCFA3D33C1000C8E7ULL,
		0xACDB78BA7B91318FULL,
		0x2F137A5ABB28C717ULL
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
		0xD2CB5514EB11F581ULL,
		0x28E09A2AAB10EF9EULL,
		0xB48CEB04D732AA00ULL,
		0x638B7B5A7DE25E42ULL,
		0x74942C6C3339E655ULL,
		0x1FB5A59FD4196FB3ULL,
		0xB83954E74C284F44ULL,
		0x3BE6A044D1BB1871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA596AA29D623EB02ULL,
		0x51C134555621DF3DULL,
		0x6919D609AE655400ULL,
		0xC716F6B4FBC4BC85ULL,
		0xE92858D86673CCAAULL,
		0x3F6B4B3FA832DF66ULL,
		0x7072A9CE98509E88ULL,
		0x77CD4089A37630E3ULL
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
		0xF411BB9A6DAB34BEULL,
		0x3EBE75FE587F0747ULL,
		0x0AD4900891EDDDA9ULL,
		0xB80559E9845F7AEDULL,
		0xC987D4E7F9F8473AULL,
		0x15A2E452F109336CULL,
		0x96F5C473A14AB5FBULL,
		0x2207C8012D112E1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8237734DB56697CULL,
		0x7D7CEBFCB0FE0E8FULL,
		0x15A9201123DBBB52ULL,
		0x700AB3D308BEF5DAULL,
		0x930FA9CFF3F08E75ULL,
		0x2B45C8A5E21266D9ULL,
		0x2DEB88E742956BF6ULL,
		0x440F90025A225C37ULL
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
		0x08D4C99119036470ULL,
		0xFF0CBC77475D6606ULL,
		0xDD99DB43D0C6CD26ULL,
		0x99F5677D96F36419ULL,
		0x5F6EC0C579EDE132ULL,
		0x222FC4883CC4275DULL,
		0xD1BC7AB2B8BE5001ULL,
		0x1B13D840A96144F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A993223206C8E0ULL,
		0xFE1978EE8EBACC0CULL,
		0xBB33B687A18D9A4DULL,
		0x33EACEFB2DE6C833ULL,
		0xBEDD818AF3DBC265ULL,
		0x445F891079884EBAULL,
		0xA378F565717CA002ULL,
		0x3627B08152C289F3ULL
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
		0x71A8004AE7E68F87ULL,
		0x4CC82BA7BB15B00DULL,
		0x21078F0740E3166AULL,
		0x66F2BB8D9FAC75F1ULL,
		0xA1C45146BB6A2F52ULL,
		0xDB94166F4EEF2BE3ULL,
		0x31E9131B299309CDULL,
		0x38ADDE8D8C127B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3500095CFCD1F0EULL,
		0x9990574F762B601AULL,
		0x420F1E0E81C62CD4ULL,
		0xCDE5771B3F58EBE2ULL,
		0x4388A28D76D45EA4ULL,
		0xB7282CDE9DDE57C7ULL,
		0x63D226365326139BULL,
		0x715BBD1B1824F60EULL
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
		0x8E97F09C50EED50EULL,
		0x5D8075748359B309ULL,
		0x961BE07C1CB95F4DULL,
		0x6DF78D15A3A68E82ULL,
		0x6DF7140823276798ULL,
		0x02C2D923004C7111ULL,
		0x0FB9E488E86DBB65ULL,
		0x3E9713886597833EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2FE138A1DDAA1CULL,
		0xBB00EAE906B36613ULL,
		0x2C37C0F83972BE9AULL,
		0xDBEF1A2B474D1D05ULL,
		0xDBEE2810464ECF30ULL,
		0x0585B2460098E222ULL,
		0x1F73C911D0DB76CAULL,
		0x7D2E2710CB2F067CULL
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
		0xDF4194B6079EBD5FULL,
		0x675987F34B2852D8ULL,
		0xF42957D906C6C57DULL,
		0xA272681C4669B07EULL,
		0xC8BDF41DFC1DE1ECULL,
		0x9CED9C793433955AULL,
		0x7C401F306BC0C313ULL,
		0x0BEB4BFC3FAA50BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE83296C0F3D7ABEULL,
		0xCEB30FE69650A5B1ULL,
		0xE852AFB20D8D8AFAULL,
		0x44E4D0388CD360FDULL,
		0x917BE83BF83BC3D9ULL,
		0x39DB38F268672AB5ULL,
		0xF8803E60D7818627ULL,
		0x17D697F87F54A17CULL
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
		0xF54B0FC30CDC2B0EULL,
		0x8E5B9173483EDB6CULL,
		0xAF6A81D0658DE944ULL,
		0x957686DBB4D82A97ULL,
		0x1F2A45641AB4FD9BULL,
		0x3E8BE0D1DCD46090ULL,
		0x0C6F5E086ED2AE6AULL,
		0x364CE59949A43E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA961F8619B8561CULL,
		0x1CB722E6907DB6D9ULL,
		0x5ED503A0CB1BD289ULL,
		0x2AED0DB769B0552FULL,
		0x3E548AC83569FB37ULL,
		0x7D17C1A3B9A8C120ULL,
		0x18DEBC10DDA55CD4ULL,
		0x6C99CB3293487CE2ULL
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
		0xE83FF4FDBC9337B9ULL,
		0x53903A9A3A0F7BCEULL,
		0x323252C78EB9C3F9ULL,
		0xFBDCB6C65137B012ULL,
		0x490DCF2F0866BEE5ULL,
		0x554E0D7A71189286ULL,
		0x5B9548B1180D6529ULL,
		0x3EEC50F7736B2E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD07FE9FB79266F72ULL,
		0xA7207534741EF79DULL,
		0x6464A58F1D7387F2ULL,
		0xF7B96D8CA26F6024ULL,
		0x921B9E5E10CD7DCBULL,
		0xAA9C1AF4E231250CULL,
		0xB72A9162301ACA52ULL,
		0x7DD8A1EEE6D65D34ULL
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
		0xF8309283090AF620ULL,
		0xA3CD64FC327B03C3ULL,
		0x1BC6C211590A885AULL,
		0x369F3F671FC66F98ULL,
		0xD83936B4DA4A7D94ULL,
		0xD134C98651FAF077ULL,
		0x8AD81737883226C0ULL,
		0x1E6832BF3492F1E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06125061215EC40ULL,
		0x479AC9F864F60787ULL,
		0x378D8422B21510B5ULL,
		0x6D3E7ECE3F8CDF30ULL,
		0xB0726D69B494FB28ULL,
		0xA269930CA3F5E0EFULL,
		0x15B02E6F10644D81ULL,
		0x3CD0657E6925E3D1ULL
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
		0x7986D9D69FD88D1FULL,
		0x09A89FCECE5EAC88ULL,
		0x065462F94DA5DC67ULL,
		0x948DF4C5952D058AULL,
		0x6C643CFAFFBDA370ULL,
		0xA672E7AA28B97149ULL,
		0xC0EC63BF4D8011B8ULL,
		0x00E1215EDAEACC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30DB3AD3FB11A3EULL,
		0x13513F9D9CBD5910ULL,
		0x0CA8C5F29B4BB8CEULL,
		0x291BE98B2A5A0B14ULL,
		0xD8C879F5FF7B46E1ULL,
		0x4CE5CF545172E292ULL,
		0x81D8C77E9B002371ULL,
		0x01C242BDB5D59909ULL
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
		0xB605A8DBA7EFDFEFULL,
		0x9A0E5B1A44748D7AULL,
		0x5FDE05758BBC4285ULL,
		0xBB394953478E03F7ULL,
		0x907125254D2B1959ULL,
		0x14E255AE29E8E89BULL,
		0x57538708064AB2F8ULL,
		0x214CA4A7616C1364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C0B51B74FDFBFDEULL,
		0x341CB63488E91AF5ULL,
		0xBFBC0AEB1778850BULL,
		0x767292A68F1C07EEULL,
		0x20E24A4A9A5632B3ULL,
		0x29C4AB5C53D1D137ULL,
		0xAEA70E100C9565F0ULL,
		0x4299494EC2D826C8ULL
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
		0x1C84DF4A6B0396ABULL,
		0x6CA10DE3C74FF322ULL,
		0x60E5F8A68FDC9D83ULL,
		0x07DBEF193C1A522BULL,
		0xE660537C390C980EULL,
		0x8A430E37349CF1F3ULL,
		0x8B6DA1E6590500FFULL,
		0x236A62850D339F3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3909BE94D6072D56ULL,
		0xD9421BC78E9FE644ULL,
		0xC1CBF14D1FB93B06ULL,
		0x0FB7DE327834A456ULL,
		0xCCC0A6F87219301CULL,
		0x14861C6E6939E3E7ULL,
		0x16DB43CCB20A01FFULL,
		0x46D4C50A1A673E7DULL
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
		0x2A6D654A85B40C98ULL,
		0xE5610E4D8D93A77BULL,
		0x0AB8FE0378960216ULL,
		0xF3E54821E7E124EEULL,
		0x38AE7CAE4C9CA413ULL,
		0x29D3A9C0FF2A6582ULL,
		0x51DEE44C342D7E3EULL,
		0x3D051F04189FF924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54DACA950B681930ULL,
		0xCAC21C9B1B274EF6ULL,
		0x1571FC06F12C042DULL,
		0xE7CA9043CFC249DCULL,
		0x715CF95C99394827ULL,
		0x53A75381FE54CB04ULL,
		0xA3BDC898685AFC7CULL,
		0x7A0A3E08313FF248ULL
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
		0xA4CF964C87DB583BULL,
		0xD065BDBE7E19BB49ULL,
		0x9F3F12CC2122D9C2ULL,
		0x8EA0F4C2D1811EEEULL,
		0xCE3E0AAD85638C46ULL,
		0x3FCE7B903DBE4F0EULL,
		0x7B07581C9C87064DULL,
		0x3A4E328127437389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499F2C990FB6B076ULL,
		0xA0CB7B7CFC337693ULL,
		0x3E7E25984245B385ULL,
		0x1D41E985A3023DDDULL,
		0x9C7C155B0AC7188DULL,
		0x7F9CF7207B7C9E1DULL,
		0xF60EB039390E0C9AULL,
		0x749C65024E86E712ULL
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
		0x3AC03F9CD71B43E4ULL,
		0xA7B94FB4D841B11BULL,
		0x63C37870320EB8E2ULL,
		0x7707D9D405974A39ULL,
		0xEB86ACC1F6A6F1E4ULL,
		0xA4D1029C80A6D4A8ULL,
		0x23AD29ED5A78F708ULL,
		0x242D24D6469EB1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75807F39AE3687C8ULL,
		0x4F729F69B0836236ULL,
		0xC786F0E0641D71C5ULL,
		0xEE0FB3A80B2E9472ULL,
		0xD70D5983ED4DE3C8ULL,
		0x49A20539014DA951ULL,
		0x475A53DAB4F1EE11ULL,
		0x485A49AC8D3D63E6ULL
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
		0xC60A1EDCD923794FULL,
		0xDCB05BAD03C92155ULL,
		0x440D4F71745FE185ULL,
		0x9E065A60C7A341BFULL,
		0x6A0664626B7C347DULL,
		0xADC65993C574405AULL,
		0xDAA68D88747138ABULL,
		0x32444C14CB0C6E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C143DB9B246F29EULL,
		0xB960B75A079242ABULL,
		0x881A9EE2E8BFC30BULL,
		0x3C0CB4C18F46837EULL,
		0xD40CC8C4D6F868FBULL,
		0x5B8CB3278AE880B4ULL,
		0xB54D1B10E8E27157ULL,
		0x648898299618DC5DULL
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
		0xFD1DEB54FBD761F4ULL,
		0x0869AE11B2B26202ULL,
		0x8F75965159E08307ULL,
		0xC4E24C721B8396A5ULL,
		0xE80215025B5B740BULL,
		0x506BA62C595A1009ULL,
		0xE9DF28309A657BD8ULL,
		0x2D6D67389F5032F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA3BD6A9F7AEC3E8ULL,
		0x10D35C236564C405ULL,
		0x1EEB2CA2B3C1060EULL,
		0x89C498E437072D4BULL,
		0xD0042A04B6B6E817ULL,
		0xA0D74C58B2B42013ULL,
		0xD3BE506134CAF7B0ULL,
		0x5ADACE713EA065EBULL
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
		0xC72530FC09679F44ULL,
		0x2A5FCA7DD0A38281ULL,
		0x7B92A6A5D2A2AB26ULL,
		0x1C42D158787C39E5ULL,
		0xF553812AC019E362ULL,
		0xDDE3D1A5FBB34ADFULL,
		0xD9CE4AE071DD202CULL,
		0x3D95AAB1CF816859ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E4A61F812CF3E88ULL,
		0x54BF94FBA1470503ULL,
		0xF7254D4BA545564CULL,
		0x3885A2B0F0F873CAULL,
		0xEAA702558033C6C4ULL,
		0xBBC7A34BF76695BFULL,
		0xB39C95C0E3BA4059ULL,
		0x7B2B55639F02D0B3ULL
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
		0x74A05FBDAB088534ULL,
		0x58B0F113153398DDULL,
		0x344F83F9A1DE1FB9ULL,
		0x2B1B4C6045B332BFULL,
		0x9D98DD777AE7B321ULL,
		0xFBD0334851D16DB6ULL,
		0x840AB092473196E8ULL,
		0x028AE5D2A498F985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE940BF7B56110A68ULL,
		0xB161E2262A6731BAULL,
		0x689F07F343BC3F72ULL,
		0x563698C08B66657EULL,
		0x3B31BAEEF5CF6642ULL,
		0xF7A06690A3A2DB6DULL,
		0x081561248E632DD1ULL,
		0x0515CBA54931F30BULL
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
		0xAD99A8F01EE1CF5BULL,
		0x32A9456E80DB2161ULL,
		0x89F8459EE88ED8D0ULL,
		0x8E4833A6E945702FULL,
		0xFEF5A8CF5400AF14ULL,
		0x1D89ABE311D8A827ULL,
		0x9C89DB68F8E09C98ULL,
		0x331DB03F3B5DFFEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B3351E03DC39EB6ULL,
		0x65528ADD01B642C3ULL,
		0x13F08B3DD11DB1A0ULL,
		0x1C90674DD28AE05FULL,
		0xFDEB519EA8015E29ULL,
		0x3B1357C623B1504FULL,
		0x3913B6D1F1C13930ULL,
		0x663B607E76BBFFDFULL
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
		0x64D5DF4017CABA7AULL,
		0xD20868FC0F3B7473ULL,
		0xD63057B6126F2DEFULL,
		0xBB6B074C3097DA5CULL,
		0xF8FAC8DA5B6D7DC4ULL,
		0xC587813583DA6AD5ULL,
		0xD246E69B749E290AULL,
		0x24D4238D4E24CFB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9ABBE802F9574F4ULL,
		0xA410D1F81E76E8E6ULL,
		0xAC60AF6C24DE5BDFULL,
		0x76D60E98612FB4B9ULL,
		0xF1F591B4B6DAFB89ULL,
		0x8B0F026B07B4D5ABULL,
		0xA48DCD36E93C5215ULL,
		0x49A8471A9C499F6BULL
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
		0xD83A8F6F95C4E65FULL,
		0x6A3F6025BED4B1D5ULL,
		0xEFA53A8739C30A6BULL,
		0x1CED9A70D40AD36EULL,
		0xDF413DDBFFAD73D2ULL,
		0xE7524881AA5E6724ULL,
		0x46426690161368B6ULL,
		0x1CD9905A2526C672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0751EDF2B89CCBEULL,
		0xD47EC04B7DA963ABULL,
		0xDF4A750E738614D6ULL,
		0x39DB34E1A815A6DDULL,
		0xBE827BB7FF5AE7A4ULL,
		0xCEA4910354BCCE49ULL,
		0x8C84CD202C26D16DULL,
		0x39B320B44A4D8CE4ULL
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
		0xEA003D550B6009CFULL,
		0x0C0BDFB02676D9ACULL,
		0xC5BFC8DA5DE97FD8ULL,
		0x3B342DFC3233B83AULL,
		0xB441707E8F2C49F7ULL,
		0xC097DEF7F4CD0DFDULL,
		0xBD488E4EA0B588A9ULL,
		0x0C8A369A7CEDC4AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4007AAA16C0139EULL,
		0x1817BF604CEDB359ULL,
		0x8B7F91B4BBD2FFB0ULL,
		0x76685BF864677075ULL,
		0x6882E0FD1E5893EEULL,
		0x812FBDEFE99A1BFBULL,
		0x7A911C9D416B1153ULL,
		0x19146D34F9DB8955ULL
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
		0xF0A4B969859A9227ULL,
		0xF1429D0AC345A7DDULL,
		0xA8ED8480CA85C072ULL,
		0x0F877F009A4EE41EULL,
		0x4A5664D680F74430ULL,
		0x5D30B987883F75E7ULL,
		0x920FDBD3D1832B04ULL,
		0x126EB9ACE4D51540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE14972D30B35244EULL,
		0xE2853A15868B4FBBULL,
		0x51DB0901950B80E5ULL,
		0x1F0EFE01349DC83DULL,
		0x94ACC9AD01EE8860ULL,
		0xBA61730F107EEBCEULL,
		0x241FB7A7A3065608ULL,
		0x24DD7359C9AA2A81ULL
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
		0xB8B2208277795217ULL,
		0x6DED9B2B56E8ABFDULL,
		0x5D07CAE207517BF9ULL,
		0x1D20C76A1F2EEAE9ULL,
		0x0906BD06530BD105ULL,
		0xDCB7BD4023FEE5EDULL,
		0xF41C5E73A74E5C9DULL,
		0x290690763397852EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71644104EEF2A42EULL,
		0xDBDB3656ADD157FBULL,
		0xBA0F95C40EA2F7F2ULL,
		0x3A418ED43E5DD5D2ULL,
		0x120D7A0CA617A20AULL,
		0xB96F7A8047FDCBDAULL,
		0xE838BCE74E9CB93BULL,
		0x520D20EC672F0A5DULL
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
		0xF4D0EEFE89CBE469ULL,
		0x2073D109621F6091ULL,
		0x8F1F591FC59D03AAULL,
		0x7F8C2F60D182E731ULL,
		0x09F850435EBF1294ULL,
		0xABF9AFE38638F443ULL,
		0xE77AA9A8B2F52698ULL,
		0x1F3D2AA2877BCBCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A1DDFD1397C8D2ULL,
		0x40E7A212C43EC123ULL,
		0x1E3EB23F8B3A0754ULL,
		0xFF185EC1A305CE63ULL,
		0x13F0A086BD7E2528ULL,
		0x57F35FC70C71E886ULL,
		0xCEF5535165EA4D31ULL,
		0x3E7A55450EF79795ULL
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
		0xF9D81DDF27E33254ULL,
		0x8E6DB27791D0169AULL,
		0x1E955226C052EEE8ULL,
		0xF5999A95407F0504ULL,
		0x902BF9A4234B0432ULL,
		0x5DF27E291AB05DEFULL,
		0x9973A8D85041913CULL,
		0x11582076612C1B0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B03BBE4FC664A8ULL,
		0x1CDB64EF23A02D35ULL,
		0x3D2AA44D80A5DDD1ULL,
		0xEB33352A80FE0A08ULL,
		0x2057F34846960865ULL,
		0xBBE4FC523560BBDFULL,
		0x32E751B0A0832278ULL,
		0x22B040ECC2583615ULL
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
		0xFCD72C5936D1021BULL,
		0xB77A87F68D0B2277ULL,
		0x1C637055A51D842DULL,
		0x32A10B90D59733E1ULL,
		0xF48B91067D3E907FULL,
		0x99FEFE7097714907ULL,
		0x490D329B4B4E6D82ULL,
		0x301A2E691C172676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9AE58B26DA20436ULL,
		0x6EF50FED1A1644EFULL,
		0x38C6E0AB4A3B085BULL,
		0x65421721AB2E67C2ULL,
		0xE917220CFA7D20FEULL,
		0x33FDFCE12EE2920FULL,
		0x921A6536969CDB05ULL,
		0x60345CD2382E4CECULL
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
		0xF1E978CD254C80BFULL,
		0x22B3801EA25B68ACULL,
		0x1261D038AF165BF1ULL,
		0xA1AA39AFAD5BF4AFULL,
		0x68743B460C7E8D38ULL,
		0x273BE8CF3F6CC50EULL,
		0x46A8F7E6D5178A1CULL,
		0x1A916C019D09C3BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3D2F19A4A99017EULL,
		0x4567003D44B6D159ULL,
		0x24C3A0715E2CB7E2ULL,
		0x4354735F5AB7E95EULL,
		0xD0E8768C18FD1A71ULL,
		0x4E77D19E7ED98A1CULL,
		0x8D51EFCDAA2F1438ULL,
		0x3522D8033A13877CULL
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
		0x9021C0C315DC2D43ULL,
		0x7722A4A4F3A125B4ULL,
		0xCEC334511FD9275EULL,
		0xC48E583CCFDC7788ULL,
		0x56229766D25AF538ULL,
		0xE5B759FDCFBD1F60ULL,
		0x325A656E1803DE7FULL,
		0x2A9A581CD0B8FD48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204381862BB85A86ULL,
		0xEE454949E7424B69ULL,
		0x9D8668A23FB24EBCULL,
		0x891CB0799FB8EF11ULL,
		0xAC452ECDA4B5EA71ULL,
		0xCB6EB3FB9F7A3EC0ULL,
		0x64B4CADC3007BCFFULL,
		0x5534B039A171FA90ULL
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
		0xE81A9A78CB2EF812ULL,
		0xBA1CE1D5644D5874ULL,
		0x2812875539143C6AULL,
		0xE381DFC933E0CED8ULL,
		0xB30501E746CF562CULL,
		0xF2FD3E6390981C05ULL,
		0x1FC6DADDFC8B8687ULL,
		0x2940263C858C731CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD03534F1965DF024ULL,
		0x7439C3AAC89AB0E9ULL,
		0x50250EAA722878D5ULL,
		0xC703BF9267C19DB0ULL,
		0x660A03CE8D9EAC59ULL,
		0xE5FA7CC72130380BULL,
		0x3F8DB5BBF9170D0FULL,
		0x52804C790B18E638ULL
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
		0x6EB5DC8831CB6349ULL,
		0x93ADD9540C593647ULL,
		0xCFFA44A0D741213BULL,
		0xD3A3A4E431B91287ULL,
		0x95461444F3481C65ULL,
		0x3E0115B0EBA1C0F1ULL,
		0x5E76ADDA34152F87ULL,
		0x0462868803A4A4BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD6BB9106396C692ULL,
		0x275BB2A818B26C8EULL,
		0x9FF48941AE824277ULL,
		0xA74749C86372250FULL,
		0x2A8C2889E69038CBULL,
		0x7C022B61D74381E3ULL,
		0xBCED5BB4682A5F0EULL,
		0x08C50D1007494974ULL
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
		0xE3C72E04B47B89A9ULL,
		0x30939169D4FF0645ULL,
		0x4368FB023A0187ADULL,
		0x014CA536943EA4D8ULL,
		0x72576817956E10AAULL,
		0xFDB3F7008B25FB97ULL,
		0x56B463FE76FB286FULL,
		0x35F9BD56F44BAFFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC78E5C0968F71352ULL,
		0x612722D3A9FE0C8BULL,
		0x86D1F60474030F5AULL,
		0x02994A6D287D49B0ULL,
		0xE4AED02F2ADC2154ULL,
		0xFB67EE01164BF72EULL,
		0xAD68C7FCEDF650DFULL,
		0x6BF37AADE8975FF6ULL
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
		0xF5E763C320AAF5EAULL,
		0xCF0209260C9C91E7ULL,
		0xF15D5951AE0C9F53ULL,
		0xE20002D608BE5894ULL,
		0x65E10F9231B9869EULL,
		0xB9E83E7C925BA74EULL,
		0x064A0AC67C0DFD0EULL,
		0x1BCA07413665BE06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBCEC7864155EBD4ULL,
		0x9E04124C193923CFULL,
		0xE2BAB2A35C193EA7ULL,
		0xC40005AC117CB129ULL,
		0xCBC21F2463730D3DULL,
		0x73D07CF924B74E9CULL,
		0x0C94158CF81BFA1DULL,
		0x37940E826CCB7C0CULL
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
		0x5BC26CF4ABCD3A98ULL,
		0x165B7B05E43C8956ULL,
		0xF882D0A7C4E82EC9ULL,
		0xC157F421517817E5ULL,
		0x5B98B10A0C93DD1DULL,
		0xDC57D7B1E574FDDCULL,
		0x9222A73832673B4BULL,
		0x1304AB1500F5A545ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB784D9E9579A7530ULL,
		0x2CB6F60BC87912ACULL,
		0xF105A14F89D05D92ULL,
		0x82AFE842A2F02FCBULL,
		0xB73162141927BA3BULL,
		0xB8AFAF63CAE9FBB8ULL,
		0x24454E7064CE7697ULL,
		0x2609562A01EB4A8BULL
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
		0x53589D2583D0BEF1ULL,
		0x8952FD32D8CF5EC3ULL,
		0x689901752F361D1CULL,
		0x2FABBA3E969DA367ULL,
		0x03CDB3D9A25D9245ULL,
		0x51115389A17E593BULL,
		0x5537A6526A4CAD1CULL,
		0x0BC6B33E461C8592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6B13A4B07A17DE2ULL,
		0x12A5FA65B19EBD86ULL,
		0xD13202EA5E6C3A39ULL,
		0x5F57747D2D3B46CEULL,
		0x079B67B344BB248AULL,
		0xA222A71342FCB276ULL,
		0xAA6F4CA4D4995A38ULL,
		0x178D667C8C390B24ULL
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
		0xE93859B891CFDD43ULL,
		0x94F745CC5B0EABBAULL,
		0x08290190388861B5ULL,
		0xC580119BFDA7AD2AULL,
		0x145C13A19EB6E00FULL,
		0xC9EF0EAF65B178ADULL,
		0xF2C265928A8A5CBCULL,
		0x1C1081002CC00B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD270B371239FBA86ULL,
		0x29EE8B98B61D5775ULL,
		0x105203207110C36BULL,
		0x8B002337FB4F5A54ULL,
		0x28B827433D6DC01FULL,
		0x93DE1D5ECB62F15AULL,
		0xE584CB251514B979ULL,
		0x38210200598016B7ULL
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
		0xF72D4FC35A6101A6ULL,
		0x5ED1B7ACD8AF5CC5ULL,
		0xCFC2A0BBB235271AULL,
		0x9CCD81803CC7C4DFULL,
		0x0494EB30EC3E2F11ULL,
		0xC7C732AF6E150E5DULL,
		0xCEFBD77D3C1DAAA2ULL,
		0x39258E9ACCC94E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5A9F86B4C2034CULL,
		0xBDA36F59B15EB98BULL,
		0x9F854177646A4E34ULL,
		0x399B0300798F89BFULL,
		0x0929D661D87C5E23ULL,
		0x8F8E655EDC2A1CBAULL,
		0x9DF7AEFA783B5545ULL,
		0x724B1D3599929CE7ULL
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
		0x16033DA9A3DF788DULL,
		0x5AB8FF9A40F294A2ULL,
		0xA24F17CA3CB47DFBULL,
		0x88FBA7B464CC3426ULL,
		0x75FD2AED857CFF46ULL,
		0xD77D23CB5D2FF295ULL,
		0xB3C2175CF6F4E2D0ULL,
		0x0AF97A554B51A4A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C067B5347BEF11AULL,
		0xB571FF3481E52944ULL,
		0x449E2F947968FBF6ULL,
		0x11F74F68C998684DULL,
		0xEBFA55DB0AF9FE8DULL,
		0xAEFA4796BA5FE52AULL,
		0x67842EB9EDE9C5A1ULL,
		0x15F2F4AA96A3494DULL
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
		0x1D6BB8BC6598A341ULL,
		0x9CC9DFCF5E99E6B9ULL,
		0x43A5D1AB45605D08ULL,
		0xEEC02DB9808DF1A3ULL,
		0xC02E96092DD2CC01ULL,
		0xDE6FD84EB132D176ULL,
		0x263A6F8CED491912ULL,
		0x0D67F96A49ABF70DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD77178CB314682ULL,
		0x3993BF9EBD33CD72ULL,
		0x874BA3568AC0BA11ULL,
		0xDD805B73011BE346ULL,
		0x805D2C125BA59803ULL,
		0xBCDFB09D6265A2EDULL,
		0x4C74DF19DA923225ULL,
		0x1ACFF2D49357EE1AULL
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
		0xAF57C82434B8AEDEULL,
		0xA7C44F7D7125A094ULL,
		0x908E12F94028A2F4ULL,
		0x1DB5B4338CD8A467ULL,
		0xE62737CC49004049ULL,
		0x11640E2D06BC9A41ULL,
		0xD1F25D19AB18760FULL,
		0x20170608DE75DFC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAF904869715DBCULL,
		0x4F889EFAE24B4129ULL,
		0x211C25F2805145E9ULL,
		0x3B6B686719B148CFULL,
		0xCC4E6F9892008092ULL,
		0x22C81C5A0D793483ULL,
		0xA3E4BA335630EC1EULL,
		0x402E0C11BCEBBF91ULL
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
		0xCB210B68D58D627CULL,
		0xCCC2F09DF76C54C8ULL,
		0x8E541E7BCB38FEF0ULL,
		0xC656C652200F97E2ULL,
		0x58F61D8FABBEA6E4ULL,
		0x002D6CE5B55CECAEULL,
		0x5CFBC4F52BF541BEULL,
		0x3431F6259FC8B3FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x964216D1AB1AC4F8ULL,
		0x9985E13BEED8A991ULL,
		0x1CA83CF79671FDE1ULL,
		0x8CAD8CA4401F2FC5ULL,
		0xB1EC3B1F577D4DC9ULL,
		0x005AD9CB6AB9D95CULL,
		0xB9F789EA57EA837CULL,
		0x6863EC4B3F9167F8ULL
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
		0x1E87D9B6484CE192ULL,
		0xE16EF357692B8AFEULL,
		0x7FD97241488BC4B6ULL,
		0x951B35B6497EE7B5ULL,
		0x9DAA70BF125B5424ULL,
		0xEF177C76EA8FCEEAULL,
		0xEEAFFDBF750D1EA1ULL,
		0x36B1610CAA139B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0FB36C9099C324ULL,
		0xC2DDE6AED25715FCULL,
		0xFFB2E4829117896DULL,
		0x2A366B6C92FDCF6AULL,
		0x3B54E17E24B6A849ULL,
		0xDE2EF8EDD51F9DD5ULL,
		0xDD5FFB7EEA1A3D43ULL,
		0x6D62C21954273603ULL
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
		0x0D7FAEC5C9D084ADULL,
		0x04C2BDF59E98B93BULL,
		0xDE159065CA7F9D60ULL,
		0xFCC4DC71E3EE87EAULL,
		0x5C3DFE38FE3017DEULL,
		0xA69EA07FF0317D1AULL,
		0x3480D842E18F10BEULL,
		0x2194A2EDC5B444A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFF5D8B93A1095AULL,
		0x09857BEB3D317276ULL,
		0xBC2B20CB94FF3AC0ULL,
		0xF989B8E3C7DD0FD5ULL,
		0xB87BFC71FC602FBDULL,
		0x4D3D40FFE062FA34ULL,
		0x6901B085C31E217DULL,
		0x432945DB8B68894EULL
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
		0x2578E4B1910C10C1ULL,
		0xD0CCAD8CF46944EAULL,
		0x6768F14F69EFCEE5ULL,
		0x32D71C66BB85E1F3ULL,
		0xDE89F9609B384406ULL,
		0x8E7D5031DD9D5D6FULL,
		0x4A4D855321BAF811ULL,
		0x06DB149A53E075A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF1C96322182182ULL,
		0xA1995B19E8D289D4ULL,
		0xCED1E29ED3DF9DCBULL,
		0x65AE38CD770BC3E6ULL,
		0xBD13F2C13670880CULL,
		0x1CFAA063BB3ABADFULL,
		0x949B0AA64375F023ULL,
		0x0DB62934A7C0EB40ULL
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
		0x5D71595215509039ULL,
		0x62F3731DDA339245ULL,
		0x4C82B8A827E29B58ULL,
		0x5EFBE607B4C7E0CDULL,
		0xD07D9D2DBB198406ULL,
		0xA1F427A57B0805B7ULL,
		0xBEE212E40F202DDDULL,
		0x211B17F767BF2EC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAE2B2A42AA12072ULL,
		0xC5E6E63BB467248AULL,
		0x990571504FC536B0ULL,
		0xBDF7CC0F698FC19AULL,
		0xA0FB3A5B7633080CULL,
		0x43E84F4AF6100B6FULL,
		0x7DC425C81E405BBBULL,
		0x42362FEECF7E5D85ULL
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
		0x94B59FD124AF6895ULL,
		0x5DDDA362029AC111ULL,
		0xC00E31DF24140015ULL,
		0x473A2ED465DC392BULL,
		0x73A8EA5DE242B1B7ULL,
		0xE530F5A842EE44C3ULL,
		0x1C8F8214791D05A6ULL,
		0x082397D0BB2D34FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x296B3FA2495ED12AULL,
		0xBBBB46C405358223ULL,
		0x801C63BE4828002AULL,
		0x8E745DA8CBB87257ULL,
		0xE751D4BBC485636EULL,
		0xCA61EB5085DC8986ULL,
		0x391F0428F23A0B4DULL,
		0x10472FA1765A69FCULL
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
		0x6B76AF938C70D781ULL,
		0xF4165E80FBD4ACD8ULL,
		0xFA627565238C0C29ULL,
		0x64F2C9EF7F6A5915ULL,
		0x2BEB020574A201BAULL,
		0x568E797C9757E4EFULL,
		0x4E91DF1AF632A4AFULL,
		0x3CF8E4F07BEA947EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6ED5F2718E1AF02ULL,
		0xE82CBD01F7A959B0ULL,
		0xF4C4EACA47181853ULL,
		0xC9E593DEFED4B22BULL,
		0x57D6040AE9440374ULL,
		0xAD1CF2F92EAFC9DEULL,
		0x9D23BE35EC65495EULL,
		0x79F1C9E0F7D528FCULL
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
		0xDC2A7B93DB54139AULL,
		0x02FB639B5CEF3624ULL,
		0xB98A1E1B8066E7E2ULL,
		0x92EE258E4DCB29DBULL,
		0xF26FFB539347542EULL,
		0xCFF00DE093918A0BULL,
		0x00F6B423CEC7DC9FULL,
		0x342C8A2F151E1666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB854F727B6A82734ULL,
		0x05F6C736B9DE6C49ULL,
		0x73143C3700CDCFC4ULL,
		0x25DC4B1C9B9653B7ULL,
		0xE4DFF6A7268EA85DULL,
		0x9FE01BC127231417ULL,
		0x01ED68479D8FB93FULL,
		0x6859145E2A3C2CCCULL
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
		0xC42336CAE3442D4CULL,
		0x1256B22550340498ULL,
		0x3C856BDB794FBE61ULL,
		0x8C7D940779FB3796ULL,
		0x68E6208015B5F2E2ULL,
		0x680774AF353FB150ULL,
		0x9808EA70E5F9763AULL,
		0x254DDB0D59CBA99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88466D95C6885A98ULL,
		0x24AD644AA0680931ULL,
		0x790AD7B6F29F7CC2ULL,
		0x18FB280EF3F66F2CULL,
		0xD1CC41002B6BE5C5ULL,
		0xD00EE95E6A7F62A0ULL,
		0x3011D4E1CBF2EC74ULL,
		0x4A9BB61AB397533FULL
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
		0xC0B08C48021FE76DULL,
		0x020EBB8986227D12ULL,
		0xF380C64FFD807C50ULL,
		0x92A8E412C7C9BFB4ULL,
		0xA5E6F05092A5FE08ULL,
		0x1AD6B281CB428DB8ULL,
		0x925942A763D7A29DULL,
		0x11B83C556D0C8E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81611890043FCEDAULL,
		0x041D77130C44FA25ULL,
		0xE7018C9FFB00F8A0ULL,
		0x2551C8258F937F69ULL,
		0x4BCDE0A1254BFC11ULL,
		0x35AD650396851B71ULL,
		0x24B2854EC7AF453AULL,
		0x237078AADA191CD3ULL
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
		0x13633635D3C28E7AULL,
		0x20FC3DD87AEFF860ULL,
		0x5E10B661C2FDE0E8ULL,
		0xFD5E225A330722B5ULL,
		0xA15F0BD4DE249CC0ULL,
		0xB5B238E1E0B12245ULL,
		0x1EB88D37E49F87EFULL,
		0x32D0DEB4F417AE59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C66C6BA7851CF4ULL,
		0x41F87BB0F5DFF0C0ULL,
		0xBC216CC385FBC1D0ULL,
		0xFABC44B4660E456AULL,
		0x42BE17A9BC493981ULL,
		0x6B6471C3C162448BULL,
		0x3D711A6FC93F0FDFULL,
		0x65A1BD69E82F5CB2ULL
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
		0x6484A7C797F4B608ULL,
		0xAA11A7F22EEF85E4ULL,
		0xB4411D490ED31495ULL,
		0xC0E2D1E12490D325ULL,
		0x1904E66D1105BA40ULL,
		0xEDB62CC210D4834EULL,
		0xB49F94DC06C3800CULL,
		0x01EA5B45F2994217ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9094F8F2FE96C10ULL,
		0x54234FE45DDF0BC8ULL,
		0x68823A921DA6292BULL,
		0x81C5A3C24921A64BULL,
		0x3209CCDA220B7481ULL,
		0xDB6C598421A9069CULL,
		0x693F29B80D870019ULL,
		0x03D4B68BE532842FULL
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
		0xD60120B72D3CB43CULL,
		0x01B80D702D6D4F5AULL,
		0x9952F2AC342222AEULL,
		0x639803D04E70F962ULL,
		0x8B468951B7CEAFA1ULL,
		0x78A3CC16680D2497ULL,
		0x57D8ADE6FAB149ADULL,
		0x1D04FE410B971E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC02416E5A796878ULL,
		0x03701AE05ADA9EB5ULL,
		0x32A5E5586844455CULL,
		0xC73007A09CE1F2C5ULL,
		0x168D12A36F9D5F42ULL,
		0xF147982CD01A492FULL,
		0xAFB15BCDF562935AULL,
		0x3A09FC82172E3D06ULL
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
		0xDEB9DE93DB67C7BDULL,
		0xEEC697C12C6A009CULL,
		0x78A6FA56AF90AEE5ULL,
		0x877B79B8B6E2F8CDULL,
		0x0123DE5ADFE0F3DAULL,
		0xE1C2602BDAB68402ULL,
		0x129E7D36E3C60364ULL,
		0x32B99D3EB7A9A315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD73BD27B6CF8F7AULL,
		0xDD8D2F8258D40139ULL,
		0xF14DF4AD5F215DCBULL,
		0x0EF6F3716DC5F19AULL,
		0x0247BCB5BFC1E7B5ULL,
		0xC384C057B56D0804ULL,
		0x253CFA6DC78C06C9ULL,
		0x65733A7D6F53462AULL
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
		0x85C7C7F3828F5246ULL,
		0x820040E0A48D329BULL,
		0xCE8B769A26828BC6ULL,
		0xCDB78E34CC699E92ULL,
		0xD17F9D512D08B4E4ULL,
		0x32198B244C19E513ULL,
		0x8EE4809035C8BE23ULL,
		0x08198F771E39076EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8F8FE7051EA48CULL,
		0x040081C1491A6537ULL,
		0x9D16ED344D05178DULL,
		0x9B6F1C6998D33D25ULL,
		0xA2FF3AA25A1169C9ULL,
		0x643316489833CA27ULL,
		0x1DC901206B917C46ULL,
		0x10331EEE3C720EDDULL
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
		0xEA117D9EE4EBD262ULL,
		0x53CEC93599281218ULL,
		0xF761C21120F4BA4AULL,
		0x96B6438B5E6072F9ULL,
		0x10F4B24797978BEDULL,
		0x077C2EC996E0062FULL,
		0x91E6E4E5AFBB46B2ULL,
		0x24F7835B9707A893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD422FB3DC9D7A4C4ULL,
		0xA79D926B32502431ULL,
		0xEEC3842241E97494ULL,
		0x2D6C8716BCC0E5F3ULL,
		0x21E9648F2F2F17DBULL,
		0x0EF85D932DC00C5EULL,
		0x23CDC9CB5F768D64ULL,
		0x49EF06B72E0F5127ULL
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
		0x2B93E4A056CAF7ACULL,
		0x7DCEC3CD716F65CEULL,
		0x0AA5591DE41DBE21ULL,
		0xA60DE1F9AF31C893ULL,
		0x02F3A685CFFFCD57ULL,
		0x7F81BD209F847A36ULL,
		0xE025198E123B1438ULL,
		0x0D6976411F431429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5727C940AD95EF58ULL,
		0xFB9D879AE2DECB9CULL,
		0x154AB23BC83B7C42ULL,
		0x4C1BC3F35E639126ULL,
		0x05E74D0B9FFF9AAFULL,
		0xFF037A413F08F46CULL,
		0xC04A331C24762870ULL,
		0x1AD2EC823E862853ULL
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
		0xF904BEE06C8EBF43ULL,
		0x269F509CF42542C8ULL,
		0x4D9CD228D5AC9374ULL,
		0x345754C8797257B0ULL,
		0x9CC05F03DDE99D9FULL,
		0xA95031CC5D8604FBULL,
		0xD2983F7BFE20CAA6ULL,
		0x0F148579E701BE16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2097DC0D91D7E86ULL,
		0x4D3EA139E84A8591ULL,
		0x9B39A451AB5926E8ULL,
		0x68AEA990F2E4AF60ULL,
		0x3980BE07BBD33B3EULL,
		0x52A06398BB0C09F7ULL,
		0xA5307EF7FC41954DULL,
		0x1E290AF3CE037C2DULL
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