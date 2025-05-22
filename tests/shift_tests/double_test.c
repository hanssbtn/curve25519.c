#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5AA01E644E66C0A9ULL,
		0x8B8D0911E907A2C3ULL,
		0x5FCC9D317911B23FULL,
		0x3814A8D893236970ULL,
		0x9B083E098674B900ULL,
		0x3C294D92FD3A232EULL,
		0x53C1EDC5F3747A6DULL,
		0x0802A9A0076A8B5BULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB5403CC89CCD8152ULL,
		0x171A1223D20F4586ULL,
		0xBF993A62F223647FULL,
		0x702951B12646D2E0ULL,
		0x36107C130CE97200ULL,
		0x78529B25FA74465DULL,
		0xA783DB8BE6E8F4DAULL,
		0x100553400ED516B6ULL
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
		0xAC8789C187616EFDULL,
		0x828D7F3B24DA6930ULL,
		0x4E2645C06E735650ULL,
		0xB88E211BD8063786ULL,
		0xF65E33000B22F1D2ULL,
		0xB2C0F8038BBB56D1ULL,
		0x6ED1C429B8830547ULL,
		0x265C8EA6DD62C870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x590F13830EC2DDFAULL,
		0x051AFE7649B4D261ULL,
		0x9C4C8B80DCE6ACA1ULL,
		0x711C4237B00C6F0CULL,
		0xECBC66001645E3A5ULL,
		0x6581F0071776ADA3ULL,
		0xDDA3885371060A8FULL,
		0x4CB91D4DBAC590E0ULL
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
		0x66BF1727F86E6F93ULL,
		0xFE1B410C7FA42912ULL,
		0x39DB71E6245B747EULL,
		0xBF8691FD871D1AF2ULL,
		0xD601786DD4B7B184ULL,
		0x39E90EC57537CA50ULL,
		0x962FA99BE7D2D5F8ULL,
		0x1B83ACF15E74D778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD7E2E4FF0DCDF26ULL,
		0xFC368218FF485224ULL,
		0x73B6E3CC48B6E8FDULL,
		0x7F0D23FB0E3A35E4ULL,
		0xAC02F0DBA96F6309ULL,
		0x73D21D8AEA6F94A1ULL,
		0x2C5F5337CFA5ABF0ULL,
		0x370759E2BCE9AEF1ULL
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
		0x517390F981AC04F6ULL,
		0x119882C2A971200EULL,
		0x82E3EA891398E943ULL,
		0x90C68F556229ABD5ULL,
		0x39FCD301BEED00C5ULL,
		0x4566D03A37F7EA01ULL,
		0x2AEB932275778DC2ULL,
		0x20CD1C6CC56C1BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2E721F3035809ECULL,
		0x2331058552E2401CULL,
		0x05C7D5122731D286ULL,
		0x218D1EAAC45357ABULL,
		0x73F9A6037DDA018BULL,
		0x8ACDA0746FEFD402ULL,
		0x55D72644EAEF1B84ULL,
		0x419A38D98AD837E2ULL
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
		0x4513E1B819D5E471ULL,
		0xDFE334A26108245FULL,
		0xA0E4E1224AB914CAULL,
		0xF8F1CC563AB28C05ULL,
		0x7718F7E4613B5B20ULL,
		0x5FD79115809ACF06ULL,
		0xE1B2DB064C805852ULL,
		0x2E320AD0B6DCF6AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A27C37033ABC8E2ULL,
		0xBFC66944C21048BEULL,
		0x41C9C24495722995ULL,
		0xF1E398AC7565180BULL,
		0xEE31EFC8C276B641ULL,
		0xBFAF222B01359E0CULL,
		0xC365B60C9900B0A4ULL,
		0x5C6415A16DB9ED5FULL
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
		0xF60D5FABF5E97BA5ULL,
		0x9D17A5856C7AED75ULL,
		0x2A26A2F3F7F1E04FULL,
		0x9FDC1E03C0DE9FFCULL,
		0xD3F6DF034748828BULL,
		0xCDBF459E0FC10706ULL,
		0x1B4CCE1AEEB0DEFCULL,
		0x1727298B76961081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC1ABF57EBD2F74AULL,
		0x3A2F4B0AD8F5DAEBULL,
		0x544D45E7EFE3C09FULL,
		0x3FB83C0781BD3FF8ULL,
		0xA7EDBE068E910517ULL,
		0x9B7E8B3C1F820E0DULL,
		0x36999C35DD61BDF9ULL,
		0x2E4E5316ED2C2102ULL
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
		0xB7CF20B4E06DDA95ULL,
		0x622A9B7196EFB228ULL,
		0x2E4B37413189E3E5ULL,
		0xF8CA87812CBF05CFULL,
		0x33D75640231AEED1ULL,
		0x87F75020E0187B87ULL,
		0x1F68E62B951874FFULL,
		0x2F8586CAB69A3D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9E4169C0DBB52AULL,
		0xC45536E32DDF6451ULL,
		0x5C966E826313C7CAULL,
		0xF1950F02597E0B9EULL,
		0x67AEAC804635DDA3ULL,
		0x0FEEA041C030F70EULL,
		0x3ED1CC572A30E9FFULL,
		0x5F0B0D956D347A5CULL
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
		0x0BA73BF0338917D3ULL,
		0x2487994AD62595ACULL,
		0x95C699622039A8B4ULL,
		0x818A918E72C0DB94ULL,
		0xE82637B61924B4BCULL,
		0x8F7A4805BBA41B18ULL,
		0xDF480689AB489872ULL,
		0x29FCB74EC6520951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174E77E067122FA6ULL,
		0x490F3295AC4B2B58ULL,
		0x2B8D32C440735168ULL,
		0x0315231CE581B729ULL,
		0xD04C6F6C32496979ULL,
		0x1EF4900B77483631ULL,
		0xBE900D13569130E5ULL,
		0x53F96E9D8CA412A3ULL
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
		0xE47467E205A86269ULL,
		0x21C569923354548AULL,
		0xACC600BA479F8536ULL,
		0xF1869AFA67C3FD8CULL,
		0x8A04E35D1A1185A1ULL,
		0x0271906FEC3F748BULL,
		0x25110C156FC09E12ULL,
		0x0FECCACCE4C0444BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E8CFC40B50C4D2ULL,
		0x438AD32466A8A915ULL,
		0x598C01748F3F0A6CULL,
		0xE30D35F4CF87FB19ULL,
		0x1409C6BA34230B43ULL,
		0x04E320DFD87EE917ULL,
		0x4A22182ADF813C24ULL,
		0x1FD99599C9808896ULL
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
		0x62C63DEB86366C09ULL,
		0x89028299A9D00171ULL,
		0x566666E6D71A95C3ULL,
		0x08A1AC22CAF251E5ULL,
		0x98BE0FD4AB274B5BULL,
		0xA7FB7C2E2593DECBULL,
		0x5B301D67F9D67E2FULL,
		0x1483F51893E5642AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58C7BD70C6CD812ULL,
		0x1205053353A002E2ULL,
		0xACCCCDCDAE352B87ULL,
		0x1143584595E4A3CAULL,
		0x317C1FA9564E96B6ULL,
		0x4FF6F85C4B27BD97ULL,
		0xB6603ACFF3ACFC5FULL,
		0x2907EA3127CAC854ULL
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
		0x84FECD1C6059E519ULL,
		0x241FD667A4FE38BBULL,
		0xFFFF51BE0B632BBCULL,
		0x52FB61CC7C1A2681ULL,
		0xFB92D590AEA2465AULL,
		0x368469A4AB11C730ULL,
		0xC8656386D7B8D71CULL,
		0x063211EB3EB2546AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FD9A38C0B3CA32ULL,
		0x483FACCF49FC7177ULL,
		0xFFFEA37C16C65778ULL,
		0xA5F6C398F8344D03ULL,
		0xF725AB215D448CB4ULL,
		0x6D08D34956238E61ULL,
		0x90CAC70DAF71AE38ULL,
		0x0C6423D67D64A8D5ULL
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
		0x88A437D8D3B328DBULL,
		0xCB7F9940B0872F1EULL,
		0x47E0398BE216B96CULL,
		0x1D0CCC9B8A65AFFEULL,
		0x8A2BE4C65B1BA96DULL,
		0x8A3847338CE3560FULL,
		0xC0D34369639F4DDDULL,
		0x38E07A71B51DABCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11486FB1A76651B6ULL,
		0x96FF3281610E5E3DULL,
		0x8FC07317C42D72D9ULL,
		0x3A19993714CB5FFCULL,
		0x1457C98CB63752DAULL,
		0x14708E6719C6AC1FULL,
		0x81A686D2C73E9BBBULL,
		0x71C0F4E36A3B579BULL
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
		0xE88F510C24FF0EA9ULL,
		0x5190535A84688411ULL,
		0xD3F3DEF1FBD51244ULL,
		0xE845B1F1C98E0DD1ULL,
		0x238F455AD9DC9C8CULL,
		0x7F454B5EA68AEA95ULL,
		0xCEEFD54F25F37109ULL,
		0x00007D2A411244A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11EA21849FE1D52ULL,
		0xA320A6B508D10823ULL,
		0xA7E7BDE3F7AA2488ULL,
		0xD08B63E3931C1BA3ULL,
		0x471E8AB5B3B93919ULL,
		0xFE8A96BD4D15D52AULL,
		0x9DDFAA9E4BE6E212ULL,
		0x0000FA548224894FULL
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
		0xE19C8D81620408B8ULL,
		0x05F27E308F0A07B7ULL,
		0x8275D2450067658CULL,
		0x376D500EA5C3C260ULL,
		0x23E7AFE590D621D4ULL,
		0xEC1A7CFF38A09868ULL,
		0x919662A3C5CD0B08ULL,
		0x091CBC1F90BF52B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3391B02C4081170ULL,
		0x0BE4FC611E140F6FULL,
		0x04EBA48A00CECB18ULL,
		0x6EDAA01D4B8784C1ULL,
		0x47CF5FCB21AC43A8ULL,
		0xD834F9FE714130D0ULL,
		0x232CC5478B9A1611ULL,
		0x1239783F217EA56FULL
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
		0xAE47B3CF5524F71EULL,
		0xC2D479C0598F2791ULL,
		0xA1D4C35A301BD875ULL,
		0x89FF350C90E48997ULL,
		0xC0BC06E5F33BDC27ULL,
		0xF7E5E8044E360881ULL,
		0x27BFF05334B39A2BULL,
		0x3E8CF01F3C4E1E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C8F679EAA49EE3CULL,
		0x85A8F380B31E4F23ULL,
		0x43A986B46037B0EBULL,
		0x13FE6A1921C9132FULL,
		0x81780DCBE677B84FULL,
		0xEFCBD0089C6C1103ULL,
		0x4F7FE0A669673457ULL,
		0x7D19E03E789C3D26ULL
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
		0xC3C2210F778B9C8FULL,
		0x31F6DC6F42C8407FULL,
		0x37ABE31933F0A61EULL,
		0xE05ACCEFC676F007ULL,
		0xF689011F49C176B1ULL,
		0x6D860B4965480E63ULL,
		0x01633EFF1C07C016ULL,
		0x0DA7F9E933801DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8784421EEF17391EULL,
		0x63EDB8DE859080FFULL,
		0x6F57C63267E14C3CULL,
		0xC0B599DF8CEDE00EULL,
		0xED12023E9382ED63ULL,
		0xDB0C1692CA901CC7ULL,
		0x02C67DFE380F802CULL,
		0x1B4FF3D267003B56ULL
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
		0x5DEBB6ADB99DA175ULL,
		0x9A6F4DF38C97BDE4ULL,
		0x91F6B04944316528ULL,
		0x70E3B86DCA44CDA8ULL,
		0xD8DDB42FA2266BFEULL,
		0x29848060D8FD9947ULL,
		0x63988EDDF50503A4ULL,
		0x3DD36F51062593B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD76D5B733B42EAULL,
		0x34DE9BE7192F7BC8ULL,
		0x23ED60928862CA51ULL,
		0xE1C770DB94899B51ULL,
		0xB1BB685F444CD7FCULL,
		0x530900C1B1FB328FULL,
		0xC7311DBBEA0A0748ULL,
		0x7BA6DEA20C4B2770ULL
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
		0xD14871BFA9219216ULL,
		0xDAFBCC5E34FB0FCAULL,
		0xA00C5CC82C36154CULL,
		0xA5650A90B10F7B33ULL,
		0xF8FAD55DC9CEDAF8ULL,
		0x8601A744AF0C981FULL,
		0x2734CF6ADF1B3DD4ULL,
		0x193CF60890ACBF22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA290E37F5243242CULL,
		0xB5F798BC69F61F95ULL,
		0x4018B990586C2A99ULL,
		0x4ACA1521621EF667ULL,
		0xF1F5AABB939DB5F1ULL,
		0x0C034E895E19303FULL,
		0x4E699ED5BE367BA9ULL,
		0x3279EC1121597E44ULL
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
		0x729C3FC086E88A58ULL,
		0x65E3F01521340C95ULL,
		0x866685DD6976F5ADULL,
		0x60FDC441DE9CDA6BULL,
		0x77B29CF7B8A897BEULL,
		0xF67E982729BCAEABULL,
		0x7B0AB17379334D26ULL,
		0x122F2675695313C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5387F810DD114B0ULL,
		0xCBC7E02A4268192AULL,
		0x0CCD0BBAD2EDEB5AULL,
		0xC1FB8883BD39B4D7ULL,
		0xEF6539EF71512F7CULL,
		0xECFD304E53795D56ULL,
		0xF61562E6F2669A4DULL,
		0x245E4CEAD2A62792ULL
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
		0x100CA42A79DD0FB6ULL,
		0xD4D10CDD60B93D7FULL,
		0x90675E3A51863C03ULL,
		0x56062EB7BA55A09BULL,
		0xBF5EC95E99B5AD5DULL,
		0x430238C943D95209ULL,
		0xD6B41F73A6DF23DEULL,
		0x3873EDD3150BF90EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20194854F3BA1F6CULL,
		0xA9A219BAC1727AFEULL,
		0x20CEBC74A30C7807ULL,
		0xAC0C5D6F74AB4137ULL,
		0x7EBD92BD336B5ABAULL,
		0x8604719287B2A413ULL,
		0xAD683EE74DBE47BCULL,
		0x70E7DBA62A17F21DULL
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
		0xC350EA808E89A5EBULL,
		0x68150E9445E39B05ULL,
		0x966CF57B07CBDA83ULL,
		0xD543F466A063BF74ULL,
		0x5276AD8B524CBE36ULL,
		0x01E0B43E469EE457ULL,
		0x2274986DF32DE31AULL,
		0x14975B9CFA7CCF07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A1D5011D134BD6ULL,
		0xD02A1D288BC7360BULL,
		0x2CD9EAF60F97B506ULL,
		0xAA87E8CD40C77EE9ULL,
		0xA4ED5B16A4997C6DULL,
		0x03C1687C8D3DC8AEULL,
		0x44E930DBE65BC634ULL,
		0x292EB739F4F99E0EULL
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
		0x8EF066FF8278C1FAULL,
		0xC9B222F9AC229E45ULL,
		0x61476EEB0327287DULL,
		0x7E073F2284A691D3ULL,
		0x4B7D0234E221FA2FULL,
		0x2AE2A8705CDFF4D3ULL,
		0xC915906CF375282BULL,
		0x1439D1B46C3212ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DE0CDFF04F183F4ULL,
		0x936445F358453C8BULL,
		0xC28EDDD6064E50FBULL,
		0xFC0E7E45094D23A6ULL,
		0x96FA0469C443F45EULL,
		0x55C550E0B9BFE9A6ULL,
		0x922B20D9E6EA5056ULL,
		0x2873A368D864255BULL
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
		0x060C3F35D9AC365FULL,
		0x7B6177811474195AULL,
		0xDAB6E4CEEA022673ULL,
		0x1206859EBC2487A3ULL,
		0x27049F2A6D4F9280ULL,
		0x3D76B61E33D01639ULL,
		0xE71BC70CCD96664FULL,
		0x346B1B2A31090533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C187E6BB3586CBEULL,
		0xF6C2EF0228E832B4ULL,
		0xB56DC99DD4044CE6ULL,
		0x240D0B3D78490F47ULL,
		0x4E093E54DA9F2500ULL,
		0x7AED6C3C67A02C72ULL,
		0xCE378E199B2CCC9EULL,
		0x68D6365462120A67ULL
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
		0x522591CF87583B48ULL,
		0xBE615CABEA850C9EULL,
		0x7159D78A8BE52C1BULL,
		0x4AEC54E31198D182ULL,
		0x9FC214AC56D51ABDULL,
		0xAEAB8D34528E3924ULL,
		0xE3E4973D8270A370ULL,
		0x2BF2242D04918BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA44B239F0EB07690ULL,
		0x7CC2B957D50A193CULL,
		0xE2B3AF1517CA5837ULL,
		0x95D8A9C62331A304ULL,
		0x3F842958ADAA357AULL,
		0x5D571A68A51C7249ULL,
		0xC7C92E7B04E146E1ULL,
		0x57E4485A0923177BULL
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
		0x70DBC1070013E59AULL,
		0xB9CF4EFD60338A31ULL,
		0x72A270759134C62DULL,
		0x590E2C38C79FACFCULL,
		0xB2F49EDB845C88E5ULL,
		0xA6258B456E76CE95ULL,
		0xD43BEA89A713D029ULL,
		0x16CAA428C1C71AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1B7820E0027CB34ULL,
		0x739E9DFAC0671462ULL,
		0xE544E0EB22698C5BULL,
		0xB21C58718F3F59F8ULL,
		0x65E93DB708B911CAULL,
		0x4C4B168ADCED9D2BULL,
		0xA877D5134E27A053ULL,
		0x2D954851838E35F9ULL
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
		0x6E9EE3335AD57181ULL,
		0xAD2558663E3E341BULL,
		0x27E40C2995191A57ULL,
		0xEC64119137AE74ABULL,
		0x3EF8B4D346E90D0BULL,
		0x9FB7CBE8AD165464ULL,
		0x890DEBA30A17855DULL,
		0x036A4ABD306A376DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3DC666B5AAE302ULL,
		0x5A4AB0CC7C7C6836ULL,
		0x4FC818532A3234AFULL,
		0xD8C823226F5CE956ULL,
		0x7DF169A68DD21A17ULL,
		0x3F6F97D15A2CA8C8ULL,
		0x121BD746142F0ABBULL,
		0x06D4957A60D46EDBULL
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
		0x8E27907C133A2AA3ULL,
		0x40C147B4C9A36DF0ULL,
		0x52AB7E108581A6C8ULL,
		0xBA7A540DEB3E0291ULL,
		0xDABC79FB74A0AF44ULL,
		0x5F5C1B5C3D59ECAFULL,
		0xCEAD6961DB12315CULL,
		0x2CB6A7E11A9F9BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4F20F826745546ULL,
		0x81828F699346DBE1ULL,
		0xA556FC210B034D90ULL,
		0x74F4A81BD67C0522ULL,
		0xB578F3F6E9415E89ULL,
		0xBEB836B87AB3D95FULL,
		0x9D5AD2C3B62462B8ULL,
		0x596D4FC2353F3799ULL
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
		0x339A35230A16F8FDULL,
		0x54F0EB79318C67BEULL,
		0xE986F7E52A364849ULL,
		0x318AAF0E3785BF61ULL,
		0x58B79ACB6C016162ULL,
		0x61858FA16E0C9977ULL,
		0xEA663AA89D56DA08ULL,
		0x2B666AB3B62E3C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67346A46142DF1FAULL,
		0xA9E1D6F26318CF7CULL,
		0xD30DEFCA546C9092ULL,
		0x63155E1C6F0B7EC3ULL,
		0xB16F3596D802C2C4ULL,
		0xC30B1F42DC1932EEULL,
		0xD4CC75513AADB410ULL,
		0x56CCD5676C5C790DULL
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
		0x822A81649DFBBE90ULL,
		0x0B4516F91EA61B5CULL,
		0xF9C4276733151977ULL,
		0x168C818132746F83ULL,
		0x0B128869E834E285ULL,
		0xC7C9DB7C3EE253F8ULL,
		0xB511CDD74C15C8AAULL,
		0x25405A7D40E48E8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x045502C93BF77D20ULL,
		0x168A2DF23D4C36B9ULL,
		0xF3884ECE662A32EEULL,
		0x2D19030264E8DF07ULL,
		0x162510D3D069C50AULL,
		0x8F93B6F87DC4A7F0ULL,
		0x6A239BAE982B9155ULL,
		0x4A80B4FA81C91D19ULL
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
		0x8C127975F6DACFB0ULL,
		0x2A82A29918EDAF72ULL,
		0xCB36D7C933EC938CULL,
		0xF6901794AC6B15C6ULL,
		0xF8B6096B3473AFBDULL,
		0x9DA4732A86556EE5ULL,
		0x0F52433EEB01FC0FULL,
		0x3D12FEB75DB88EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1824F2EBEDB59F60ULL,
		0x5505453231DB5EE5ULL,
		0x966DAF9267D92718ULL,
		0xED202F2958D62B8DULL,
		0xF16C12D668E75F7BULL,
		0x3B48E6550CAADDCBULL,
		0x1EA4867DD603F81FULL,
		0x7A25FD6EBB711DF8ULL
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
		0xA12711A3B48EB371ULL,
		0x53E47098A39F36B5ULL,
		0x0C8AD5E5C109BDE7ULL,
		0xF3C14D0D57FA52C5ULL,
		0xB281987C16E481F9ULL,
		0x8BF3FBF91E15F627ULL,
		0x4674C92960E7B4E7ULL,
		0x0A3DD34FBAC601BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x424E2347691D66E2ULL,
		0xA7C8E131473E6D6BULL,
		0x1915ABCB82137BCEULL,
		0xE7829A1AAFF4A58AULL,
		0x650330F82DC903F3ULL,
		0x17E7F7F23C2BEC4FULL,
		0x8CE99252C1CF69CFULL,
		0x147BA69F758C037AULL
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
		0xA26EDADD2D21A021ULL,
		0xFD1833C76E7FB826ULL,
		0x165E2AFCBA459D40ULL,
		0x6AC11B3E9D7EC40EULL,
		0xCDDED91DB0E29007ULL,
		0x096E5166F9CADFB4ULL,
		0x3527F4EDAB551AA6ULL,
		0x016E9C120E3E34CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DDB5BA5A434042ULL,
		0xFA30678EDCFF704DULL,
		0x2CBC55F9748B3A81ULL,
		0xD582367D3AFD881CULL,
		0x9BBDB23B61C5200EULL,
		0x12DCA2CDF395BF69ULL,
		0x6A4FE9DB56AA354CULL,
		0x02DD38241C7C6996ULL
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
		0xE08B2E87FBF2EB1BULL,
		0x45AD84F04645A8C1ULL,
		0x26C50AAFB7AB40DDULL,
		0xDD880690127E283BULL,
		0xE63C30F7C70B2B99ULL,
		0x04CB20E09A22224BULL,
		0x26C5B4A99602578AULL,
		0x01F76E7036EDB8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1165D0FF7E5D636ULL,
		0x8B5B09E08C8B5183ULL,
		0x4D8A155F6F5681BAULL,
		0xBB100D2024FC5076ULL,
		0xCC7861EF8E165733ULL,
		0x099641C134444497ULL,
		0x4D8B69532C04AF14ULL,
		0x03EEDCE06DDB714AULL
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
		0xCB0C664A1BD18888ULL,
		0x766A13D9F55436DCULL,
		0xFEE23EC41CF71407ULL,
		0x54811CDDD25B9312ULL,
		0xCBC2E0A2AD05EA8CULL,
		0xA465F16308E9DBB4ULL,
		0x236D5CE3C2723497ULL,
		0x3E17ADD6A0379038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9618CC9437A31110ULL,
		0xECD427B3EAA86DB9ULL,
		0xFDC47D8839EE280EULL,
		0xA90239BBA4B72625ULL,
		0x9785C1455A0BD518ULL,
		0x48CBE2C611D3B769ULL,
		0x46DAB9C784E4692FULL,
		0x7C2F5BAD406F2070ULL
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
		0x9EC220E311F66799ULL,
		0x962450A7C341EF6BULL,
		0xF0F6548257763B9EULL,
		0xEBDD98179A9B257DULL,
		0xC022E4A29B2690ACULL,
		0x88A2DEE109998B27ULL,
		0xFD9997591AD1DFCBULL,
		0x3750D9E5C17C6A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D8441C623ECCF32ULL,
		0x2C48A14F8683DED7ULL,
		0xE1ECA904AEEC773DULL,
		0xD7BB302F35364AFBULL,
		0x8045C945364D2159ULL,
		0x1145BDC21333164FULL,
		0xFB332EB235A3BF97ULL,
		0x6EA1B3CB82F8D505ULL
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
		0xA3281ACEC7B0AF51ULL,
		0x51B621656F17036AULL,
		0x5E393DC2FDAA8A82ULL,
		0xD5ECD6D6A8DEA65FULL,
		0x10B1DF16E149813CULL,
		0x1EB86D9F49DC0863ULL,
		0xA5A33CF9E8DF47C3ULL,
		0x27EDD3DC982A441EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4650359D8F615EA2ULL,
		0xA36C42CADE2E06D5ULL,
		0xBC727B85FB551504ULL,
		0xABD9ADAD51BD4CBEULL,
		0x2163BE2DC2930279ULL,
		0x3D70DB3E93B810C6ULL,
		0x4B4679F3D1BE8F86ULL,
		0x4FDBA7B93054883DULL
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
		0xF899FD2F9194DBECULL,
		0xC57E6EBC5E4D656EULL,
		0xB38386289B6F946CULL,
		0x4264828EF18FFED4ULL,
		0xA1AABE22CDBACC77ULL,
		0x08ABD803924F70ABULL,
		0x7169F1192D4B9E5CULL,
		0x2E80017C0B228602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF133FA5F2329B7D8ULL,
		0x8AFCDD78BC9ACADDULL,
		0x67070C5136DF28D9ULL,
		0x84C9051DE31FFDA9ULL,
		0x43557C459B7598EEULL,
		0x1157B007249EE157ULL,
		0xE2D3E2325A973CB8ULL,
		0x5D0002F816450C04ULL
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
		0xF1FAFA8C86F63B73ULL,
		0xD6C9A21015A74DC6ULL,
		0xF5D2216626483C7DULL,
		0x0B97371A5549C22BULL,
		0xF71680910D580457ULL,
		0xE7B6C3431BA16759ULL,
		0xDB7F9CC042B2E48DULL,
		0x31B28B3510FC680DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3F5F5190DEC76E6ULL,
		0xAD9344202B4E9B8DULL,
		0xEBA442CC4C9078FBULL,
		0x172E6E34AA938457ULL,
		0xEE2D01221AB008AEULL,
		0xCF6D86863742CEB3ULL,
		0xB6FF39808565C91BULL,
		0x6365166A21F8D01BULL
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
		0x1F4D1E3BDFB39D38ULL,
		0xE63B3C9277E4DBECULL,
		0xEAFE5019B95F166BULL,
		0x56AF73F3DEA0E431ULL,
		0xCBAD1FE754B0372CULL,
		0xA700EEB6B513F524ULL,
		0x279D44A52982F26FULL,
		0x0742C39F1DEBB858ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E9A3C77BF673A70ULL,
		0xCC767924EFC9B7D8ULL,
		0xD5FCA03372BE2CD7ULL,
		0xAD5EE7E7BD41C863ULL,
		0x975A3FCEA9606E58ULL,
		0x4E01DD6D6A27EA49ULL,
		0x4F3A894A5305E4DFULL,
		0x0E85873E3BD770B0ULL
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
		0x639EDEABE550D3B5ULL,
		0xA223A541A8924536ULL,
		0xD309C58A35BD5553ULL,
		0x972453D6A3221DC9ULL,
		0xFC2E85324C95DF19ULL,
		0x6E7F087609CB78FFULL,
		0xED210169C6A0CE56ULL,
		0x050EE653D020AF4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73DBD57CAA1A76AULL,
		0x44474A8351248A6CULL,
		0xA6138B146B7AAAA7ULL,
		0x2E48A7AD46443B93ULL,
		0xF85D0A64992BBE33ULL,
		0xDCFE10EC1396F1FFULL,
		0xDA4202D38D419CACULL,
		0x0A1DCCA7A0415E9BULL
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
		0xD649EA2FF249C94BULL,
		0xE237144F6BC1F8A3ULL,
		0xD0492A89892B5F92ULL,
		0xF9EC84DEC597F834ULL,
		0x49B168A42D6B636BULL,
		0x4F3A4DD10BD9CBB5ULL,
		0x7B5ACABB5DC3F2AAULL,
		0x15E156AFD84625B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC93D45FE4939296ULL,
		0xC46E289ED783F147ULL,
		0xA09255131256BF25ULL,
		0xF3D909BD8B2FF069ULL,
		0x9362D1485AD6C6D7ULL,
		0x9E749BA217B3976AULL,
		0xF6B59576BB87E554ULL,
		0x2BC2AD5FB08C4B70ULL
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
		0x7729871C2A48F71CULL,
		0x7EA10364453D3DBBULL,
		0x5A158D82AA4E1DD7ULL,
		0x16ED8D6BFC0B4E00ULL,
		0x432CF9CC9222C3F3ULL,
		0x135B09B2548CEE99ULL,
		0xE0B016A3699981C1ULL,
		0x2069728E6EB61C06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE530E385491EE38ULL,
		0xFD4206C88A7A7B76ULL,
		0xB42B1B05549C3BAEULL,
		0x2DDB1AD7F8169C00ULL,
		0x8659F399244587E6ULL,
		0x26B61364A919DD32ULL,
		0xC1602D46D3330382ULL,
		0x40D2E51CDD6C380DULL
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
		0xF9D0BED0BEC131DAULL,
		0x83B353D94BDB2C46ULL,
		0xB6504847386AB3E5ULL,
		0xDB2CE946718504FBULL,
		0x590AFBA2C84D183AULL,
		0x6CDDDB79DFD7ABA6ULL,
		0xEBB18E308266D7B1ULL,
		0x0CD67C8C46C17B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A17DA17D8263B4ULL,
		0x0766A7B297B6588DULL,
		0x6CA0908E70D567CBULL,
		0xB659D28CE30A09F7ULL,
		0xB215F745909A3075ULL,
		0xD9BBB6F3BFAF574CULL,
		0xD7631C6104CDAF62ULL,
		0x19ACF9188D82F713ULL
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
		0x7A7FBB642E82FB04ULL,
		0x5F877FD53BAB4238ULL,
		0x563CF5D201918F11ULL,
		0x3EA068E8A91DB682ULL,
		0x6B03CEC5D75F780BULL,
		0xD5FA3BAF52E3C5F8ULL,
		0x3E0D697F3B9F1094ULL,
		0x0D85EA2BC51BEE75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4FF76C85D05F608ULL,
		0xBF0EFFAA77568470ULL,
		0xAC79EBA403231E22ULL,
		0x7D40D1D1523B6D04ULL,
		0xD6079D8BAEBEF016ULL,
		0xABF4775EA5C78BF0ULL,
		0x7C1AD2FE773E2129ULL,
		0x1B0BD4578A37DCEAULL
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
		0x2865D07EA84CD3EDULL,
		0xB8201243D9CFD597ULL,
		0xE03A21790F4DA7CDULL,
		0x1D91B72DC6A2E17AULL,
		0xDC6FCFDB6A211179ULL,
		0x5380B608D0A2E2EDULL,
		0xB94245296435D9F5ULL,
		0x22A617AF8DD5E275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50CBA0FD5099A7DAULL,
		0x70402487B39FAB2EULL,
		0xC07442F21E9B4F9BULL,
		0x3B236E5B8D45C2F5ULL,
		0xB8DF9FB6D44222F2ULL,
		0xA7016C11A145C5DBULL,
		0x72848A52C86BB3EAULL,
		0x454C2F5F1BABC4EBULL
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
		0xE8EA4F76DDDFCDE9ULL,
		0xA029E029262653B6ULL,
		0x209A14EF76A56546ULL,
		0x4DB2233F28BB16B6ULL,
		0xCB4AB003DD0AB833ULL,
		0xDB52EE77631821AFULL,
		0x49A80EA18EE93021ULL,
		0x05E1F5120EC4439AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D49EEDBBBF9BD2ULL,
		0x4053C0524C4CA76DULL,
		0x413429DEED4ACA8DULL,
		0x9B64467E51762D6CULL,
		0x96956007BA157066ULL,
		0xB6A5DCEEC630435FULL,
		0x93501D431DD26043ULL,
		0x0BC3EA241D888734ULL
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
		0xD4822E7F196A0732ULL,
		0x4E2DEFF861964CFFULL,
		0x638B5E694C01AA25ULL,
		0x283C23028C66423DULL,
		0x7C88753E19A69B21ULL,
		0x58BF7D24EACB6A6DULL,
		0x3EA8064B3ECC6AA6ULL,
		0x14027880BF74B0E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9045CFE32D40E64ULL,
		0x9C5BDFF0C32C99FFULL,
		0xC716BCD29803544AULL,
		0x5078460518CC847AULL,
		0xF910EA7C334D3642ULL,
		0xB17EFA49D596D4DAULL,
		0x7D500C967D98D54CULL,
		0x2804F1017EE961CAULL
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
		0x9C9F5E9F0F808C47ULL,
		0xE79269B09ED0A2F9ULL,
		0x39973F9B34850CADULL,
		0x8D514DF554654CD7ULL,
		0x02EF61FD6B7ADB05ULL,
		0xF4B5C691256A0157ULL,
		0x6658572C89C1D383ULL,
		0x39709EAE529EBEFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x393EBD3E1F01188EULL,
		0xCF24D3613DA145F3ULL,
		0x732E7F36690A195BULL,
		0x1AA29BEAA8CA99AEULL,
		0x05DEC3FAD6F5B60BULL,
		0xE96B8D224AD402AEULL,
		0xCCB0AE591383A707ULL,
		0x72E13D5CA53D7DF4ULL
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
		0xB75B34681E55C0C9ULL,
		0x0A5DC5786B5BD7B6ULL,
		0x85B4BB3A173446E1ULL,
		0xD79E1AA4E0814FC2ULL,
		0x698BBBAEB5D0D8BFULL,
		0xD7866260468C6DABULL,
		0x2180E0C1E14774A7ULL,
		0x2F006F1C56BAE45EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EB668D03CAB8192ULL,
		0x14BB8AF0D6B7AF6DULL,
		0x0B6976742E688DC2ULL,
		0xAF3C3549C1029F85ULL,
		0xD317775D6BA1B17FULL,
		0xAF0CC4C08D18DB56ULL,
		0x4301C183C28EE94FULL,
		0x5E00DE38AD75C8BCULL
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
		0xF6BA0EB10D9B20C1ULL,
		0x71824F6F0F6931E4ULL,
		0xD26EA47EA4C2491DULL,
		0x4F15EC5462801ED8ULL,
		0x1C5100862CD0DC8BULL,
		0xF24E1D4DAD380EE8ULL,
		0xBD66692E7A61FDE4ULL,
		0x31B47BE61D7EDDA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED741D621B364182ULL,
		0xE3049EDE1ED263C9ULL,
		0xA4DD48FD4984923AULL,
		0x9E2BD8A8C5003DB1ULL,
		0x38A2010C59A1B916ULL,
		0xE49C3A9B5A701DD0ULL,
		0x7ACCD25CF4C3FBC9ULL,
		0x6368F7CC3AFDBB53ULL
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
		0x5A2B4D885ED5549CULL,
		0x9E1FC0BA17CFFD62ULL,
		0x1B9B1E21B4A81393ULL,
		0xB6BFDD44A6F667B2ULL,
		0x5D3B02A2E92F62A5ULL,
		0x0CA91A2EE845D798ULL,
		0xE00E5AB7A04E72B5ULL,
		0x37B0513DB39DA2D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4569B10BDAAA938ULL,
		0x3C3F81742F9FFAC4ULL,
		0x37363C4369502727ULL,
		0x6D7FBA894DECCF64ULL,
		0xBA760545D25EC54BULL,
		0x1952345DD08BAF30ULL,
		0xC01CB56F409CE56AULL,
		0x6F60A27B673B45A9ULL
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
		0xF26E8A143CED3E2FULL,
		0xB732AD1AE79D7C89ULL,
		0x0D9E3891AA37ED70ULL,
		0x4DE86F287666E282ULL,
		0x4A761CF6BD340C8AULL,
		0xE2B16B9E1CDB4C07ULL,
		0x73D04FF483E453D7ULL,
		0x13CEC5BED061C92AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4DD142879DA7C5EULL,
		0x6E655A35CF3AF913ULL,
		0x1B3C7123546FDAE1ULL,
		0x9BD0DE50ECCDC504ULL,
		0x94EC39ED7A681914ULL,
		0xC562D73C39B6980EULL,
		0xE7A09FE907C8A7AFULL,
		0x279D8B7DA0C39254ULL
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
		0xAB7BBCDF267755B8ULL,
		0xDEA2BFBF66A86A68ULL,
		0xCEBB44338E7BF71AULL,
		0x240BBEC747BAEF58ULL,
		0x08D08A8D7B3F37AEULL,
		0x999770D10F161A21ULL,
		0x4D7F813AB018C6A0ULL,
		0x0BBA9885EA0C2C4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F779BE4CEEAB70ULL,
		0xBD457F7ECD50D4D1ULL,
		0x9D7688671CF7EE35ULL,
		0x48177D8E8F75DEB1ULL,
		0x11A1151AF67E6F5CULL,
		0x332EE1A21E2C3442ULL,
		0x9AFF027560318D41ULL,
		0x1775310BD4185898ULL
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
		0x3E4F8181AD51BFB9ULL,
		0x5F2EFE9AAAF9AF31ULL,
		0x712C9947228807F0ULL,
		0x0DB0B364DF004D70ULL,
		0xDD259B879DB8288AULL,
		0x4AAAA19CE85C2EFFULL,
		0xB2543ED8027E2B78ULL,
		0x3B90EA342E272E90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C9F03035AA37F72ULL,
		0xBE5DFD3555F35E62ULL,
		0xE259328E45100FE0ULL,
		0x1B6166C9BE009AE0ULL,
		0xBA4B370F3B705114ULL,
		0x95554339D0B85DFFULL,
		0x64A87DB004FC56F0ULL,
		0x7721D4685C4E5D21ULL
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
		0x12EA73909DB29D3BULL,
		0x927C69FE37AB2869ULL,
		0x7A3EF891F4D5DC78ULL,
		0x83642A68391191F3ULL,
		0x072FAF42CDBD6BA3ULL,
		0x2E1A30B54BAFA85AULL,
		0x07DE659880E3CC63ULL,
		0x06FD2D594EDF98E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D4E7213B653A76ULL,
		0x24F8D3FC6F5650D2ULL,
		0xF47DF123E9ABB8F1ULL,
		0x06C854D0722323E6ULL,
		0x0E5F5E859B7AD747ULL,
		0x5C34616A975F50B4ULL,
		0x0FBCCB3101C798C6ULL,
		0x0DFA5AB29DBF31D0ULL
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
		0x7A180746CBF5B6F2ULL,
		0x54495B8E3F28AD22ULL,
		0xB1A6C60816E00D3DULL,
		0xBC0791779065DFBFULL,
		0x675BE368DCC0BC72ULL,
		0x0614B5854615FC15ULL,
		0x6E3DD024CD0B68D1ULL,
		0x10FC65EF972F386DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4300E8D97EB6DE4ULL,
		0xA892B71C7E515A44ULL,
		0x634D8C102DC01A7AULL,
		0x780F22EF20CBBF7FULL,
		0xCEB7C6D1B98178E5ULL,
		0x0C296B0A8C2BF82AULL,
		0xDC7BA0499A16D1A2ULL,
		0x21F8CBDF2E5E70DAULL
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
		0x7E76A44C0FBA839EULL,
		0xA248099805C5FB1BULL,
		0x6EC8D2BA6DA6B168ULL,
		0x835FE9AD4BB67535ULL,
		0xEE81DA9D915099BFULL,
		0x5C9969CFFEAAC70CULL,
		0xB2BB9D398DC1A403ULL,
		0x27B5CA29C78E816AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCED48981F75073CULL,
		0x449013300B8BF636ULL,
		0xDD91A574DB4D62D1ULL,
		0x06BFD35A976CEA6AULL,
		0xDD03B53B22A1337FULL,
		0xB932D39FFD558E19ULL,
		0x65773A731B834806ULL,
		0x4F6B94538F1D02D5ULL
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
		0x36F084A009310BAAULL,
		0xD4281B1FDD9C913CULL,
		0xF3E677CDD672060CULL,
		0xA6DA9F09228E9328ULL,
		0x504D3EFDB0863D78ULL,
		0x1616B96CAB03735CULL,
		0x40E500F713971E31ULL,
		0x353389AA347DCFBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DE1094012621754ULL,
		0xA850363FBB392278ULL,
		0xE7CCEF9BACE40C19ULL,
		0x4DB53E12451D2651ULL,
		0xA09A7DFB610C7AF1ULL,
		0x2C2D72D95606E6B8ULL,
		0x81CA01EE272E3C62ULL,
		0x6A67135468FB9F74ULL
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
		0xEFC4D763C4A4FAC8ULL,
		0xF8D21E323C5D6E8AULL,
		0x15862002120B9E7DULL,
		0xDD2ECF84C77388C5ULL,
		0x46ACA88F9B9A99DCULL,
		0xDA4B555E348A892FULL,
		0xB003C0AAE042E03FULL,
		0x34B7B4986A07C77FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF89AEC78949F590ULL,
		0xF1A43C6478BADD15ULL,
		0x2B0C400424173CFBULL,
		0xBA5D9F098EE7118AULL,
		0x8D59511F373533B9ULL,
		0xB496AABC6915125EULL,
		0x60078155C085C07FULL,
		0x696F6930D40F8EFFULL
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
		0x090CEE74D5D52626ULL,
		0x0903BC6F2FB6F9FCULL,
		0x7521008878D43B09ULL,
		0x1780211D50EAA44BULL,
		0x54E7DA10B14E2991ULL,
		0x701DFD97E5B497D4ULL,
		0xE0221DAD5564E3F0ULL,
		0x045CFACF1A808FB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1219DCE9ABAA4C4CULL,
		0x120778DE5F6DF3F8ULL,
		0xEA420110F1A87612ULL,
		0x2F00423AA1D54896ULL,
		0xA9CFB421629C5322ULL,
		0xE03BFB2FCB692FA8ULL,
		0xC0443B5AAAC9C7E0ULL,
		0x08B9F59E35011F73ULL
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
		0x05FBBFFA6298560CULL,
		0xC446892367F3C55DULL,
		0x0B8EE7CDBACDA231ULL,
		0x3B405F662EC66F53ULL,
		0xD780DC3676C21EC7ULL,
		0xEF6911693CD5475CULL,
		0x91EFED7DE8AD7C2AULL,
		0x3547D752EC6CC164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF77FF4C530AC18ULL,
		0x888D1246CFE78ABAULL,
		0x171DCF9B759B4463ULL,
		0x7680BECC5D8CDEA6ULL,
		0xAF01B86CED843D8EULL,
		0xDED222D279AA8EB9ULL,
		0x23DFDAFBD15AF855ULL,
		0x6A8FAEA5D8D982C9ULL
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
		0x558260F2E5D9024CULL,
		0x5BF05EAB3528EEEDULL,
		0xDF98CE7E56BBE8AEULL,
		0xEEECAA1EF6FB9DECULL,
		0x43A65501725D7EDCULL,
		0x7D69BC949B8FB16AULL,
		0x16F0F549B1A882C9ULL,
		0x1DA344752AC61864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB04C1E5CBB20498ULL,
		0xB7E0BD566A51DDDAULL,
		0xBF319CFCAD77D15CULL,
		0xDDD9543DEDF73BD9ULL,
		0x874CAA02E4BAFDB9ULL,
		0xFAD37929371F62D4ULL,
		0x2DE1EA9363510592ULL,
		0x3B4688EA558C30C8ULL
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
		0x5716DC0EA62BF413ULL,
		0xEF4A963610B692BDULL,
		0xB301271B89677E40ULL,
		0x095486FDDDA012E2ULL,
		0x49B2E7C4C14733E1ULL,
		0xDBF9FBC363891427ULL,
		0xE855525842FD42D8ULL,
		0x3C070CBD0F8EAD48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2DB81D4C57E826ULL,
		0xDE952C6C216D257AULL,
		0x66024E3712CEFC81ULL,
		0x12A90DFBBB4025C5ULL,
		0x9365CF89828E67C2ULL,
		0xB7F3F786C712284EULL,
		0xD0AAA4B085FA85B1ULL,
		0x780E197A1F1D5A91ULL
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
		0xDF81F707C6D48E85ULL,
		0x52395E19FE073D37ULL,
		0xCF50ABA777CBD88AULL,
		0x3E259294DCD345C6ULL,
		0x499CEBD260EA1D25ULL,
		0x215DAF17B681E71EULL,
		0x807891BE6908669AULL,
		0x01207263A8B4A54FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF03EE0F8DA91D0AULL,
		0xA472BC33FC0E7A6FULL,
		0x9EA1574EEF97B114ULL,
		0x7C4B2529B9A68B8DULL,
		0x9339D7A4C1D43A4AULL,
		0x42BB5E2F6D03CE3CULL,
		0x00F1237CD210CD34ULL,
		0x0240E4C751694A9FULL
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
		0xBCD68D0944AE0E16ULL,
		0xFB4F8632929DFF96ULL,
		0x861D60FF66E53453ULL,
		0xD6F2891D5F8010D0ULL,
		0x8CF73AE28843CB68ULL,
		0xA8271042E5C71ED8ULL,
		0x7B38467575BF9473ULL,
		0x3A5013A04C850E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79AD1A12895C1C2CULL,
		0xF69F0C65253BFF2DULL,
		0x0C3AC1FECDCA68A7ULL,
		0xADE5123ABF0021A1ULL,
		0x19EE75C5108796D1ULL,
		0x504E2085CB8E3DB1ULL,
		0xF6708CEAEB7F28E7ULL,
		0x74A02740990A1CC6ULL
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
		0xB7EA68051498E328ULL,
		0x73A25361CC808AA7ULL,
		0xEB52A35C91DD0B25ULL,
		0x5146939AB5F99421ULL,
		0xA141AFBE62488487ULL,
		0x9996B7272124729EULL,
		0xBA6ED3DFA04ABB9CULL,
		0x0AF3B36AC3685630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FD4D00A2931C650ULL,
		0xE744A6C39901154FULL,
		0xD6A546B923BA164AULL,
		0xA28D27356BF32843ULL,
		0x42835F7CC491090EULL,
		0x332D6E4E4248E53DULL,
		0x74DDA7BF40957739ULL,
		0x15E766D586D0AC61ULL
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
		0xD70F7D162129C3A1ULL,
		0x4052891ADCF7A922ULL,
		0x5CED48F07B338F0FULL,
		0x13B6A091A7C6A950ULL,
		0xD53662C8383B8660ULL,
		0x6EA4EC6F1546DC3DULL,
		0x4E0FB6E82877AEFCULL,
		0x1BA8644CBA1BF027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE1EFA2C42538742ULL,
		0x80A51235B9EF5245ULL,
		0xB9DA91E0F6671E1EULL,
		0x276D41234F8D52A0ULL,
		0xAA6CC59070770CC0ULL,
		0xDD49D8DE2A8DB87BULL,
		0x9C1F6DD050EF5DF8ULL,
		0x3750C8997437E04EULL
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
		0x4167C0E547247F92ULL,
		0x3D38A8B381DF1E87ULL,
		0x23012C09B6E2EAA1ULL,
		0x119847705108B782ULL,
		0x4FEB576A58B90A7DULL,
		0xE07646A7CA888324ULL,
		0x8A21747ACDF16B3BULL,
		0x13DF657C054D39BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82CF81CA8E48FF24ULL,
		0x7A71516703BE3D0EULL,
		0x460258136DC5D542ULL,
		0x23308EE0A2116F04ULL,
		0x9FD6AED4B17214FAULL,
		0xC0EC8D4F95110648ULL,
		0x1442E8F59BE2D677ULL,
		0x27BECAF80A9A737DULL
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
		0xEFFC6F4B2FD308C1ULL,
		0x86A47CCCB7BCC6F2ULL,
		0x19BE5CCB4AC05618ULL,
		0xDAFBDBAA9EA5A699ULL,
		0x52257086A1A48454ULL,
		0x3564A732AC69EE03ULL,
		0x522D86735B6EA0A7ULL,
		0x0BB55A4351394892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF8DE965FA61182ULL,
		0x0D48F9996F798DE5ULL,
		0x337CB9969580AC31ULL,
		0xB5F7B7553D4B4D32ULL,
		0xA44AE10D434908A9ULL,
		0x6AC94E6558D3DC06ULL,
		0xA45B0CE6B6DD414EULL,
		0x176AB486A2729124ULL
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
		0x6F49DE6DA6BFA9B5ULL,
		0x24EDD7EF750EA4A9ULL,
		0xF311D171F0845F42ULL,
		0xFA25B165A00B5669ULL,
		0xCCB08D928364F09FULL,
		0x91FB999AE4CADFCFULL,
		0x26F5B2ABECF15591ULL,
		0x3F6872438920A000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE93BCDB4D7F536AULL,
		0x49DBAFDEEA1D4952ULL,
		0xE623A2E3E108BE84ULL,
		0xF44B62CB4016ACD3ULL,
		0x99611B2506C9E13FULL,
		0x23F73335C995BF9FULL,
		0x4DEB6557D9E2AB23ULL,
		0x7ED0E48712414000ULL
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
		0x34035873446C675AULL,
		0x090BDAD354C04138ULL,
		0xAAD6D5377A1C1F6AULL,
		0x11B708FAF659FDDBULL,
		0x459A77DD89D586C8ULL,
		0x57AE0CF9A36DA57FULL,
		0xDC348509DC9143CBULL,
		0x0D9D9B25209D07DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6806B0E688D8CEB4ULL,
		0x1217B5A6A9808270ULL,
		0x55ADAA6EF4383ED4ULL,
		0x236E11F5ECB3FBB7ULL,
		0x8B34EFBB13AB0D90ULL,
		0xAF5C19F346DB4AFEULL,
		0xB8690A13B9228796ULL,
		0x1B3B364A413A0FBBULL
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
		0x54822D0150572790ULL,
		0x6923C8F50A4D838EULL,
		0x628754E1E940A20AULL,
		0xBB29A4B730079324ULL,
		0xF377B5F7D169F29BULL,
		0xA45701C9444343C6ULL,
		0xF0872FFB7A01AEE2ULL,
		0x2194385FB358B42CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9045A02A0AE4F20ULL,
		0xD24791EA149B071CULL,
		0xC50EA9C3D2814414ULL,
		0x7653496E600F2648ULL,
		0xE6EF6BEFA2D3E537ULL,
		0x48AE03928886878DULL,
		0xE10E5FF6F4035DC5ULL,
		0x432870BF66B16859ULL
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
		0x2BFD8DDE6553239EULL,
		0xC684EA14CEB6C29FULL,
		0x3FE9DCA5D3A7508CULL,
		0xEC98107F942A09FBULL,
		0xCDD3D263C604BC02ULL,
		0x2B739723806A2868ULL,
		0x6A2E6FDCED99F117ULL,
		0x26C62D86D9CF4019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FB1BBCCAA6473CULL,
		0x8D09D4299D6D853EULL,
		0x7FD3B94BA74EA119ULL,
		0xD93020FF285413F6ULL,
		0x9BA7A4C78C097805ULL,
		0x56E72E4700D450D1ULL,
		0xD45CDFB9DB33E22EULL,
		0x4D8C5B0DB39E8032ULL
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
		0x79F9609D01BE9BACULL,
		0x942BC4F165958CA7ULL,
		0x1F1720F96C88CE8AULL,
		0x8A61B09FF9F56922ULL,
		0x3F140B54EA6FB0C7ULL,
		0x2CD64AC1EFDCA467ULL,
		0x5E3D8118A4541FE3ULL,
		0x16891DDDFED2B2CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F2C13A037D3758ULL,
		0x285789E2CB2B194EULL,
		0x3E2E41F2D9119D15ULL,
		0x14C3613FF3EAD244ULL,
		0x7E2816A9D4DF618FULL,
		0x59AC9583DFB948CEULL,
		0xBC7B023148A83FC6ULL,
		0x2D123BBBFDA5659CULL
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
		0x067FD858F9BF03C8ULL,
		0x914A9D451320B12CULL,
		0x2A368818D67BDA75ULL,
		0x7C0216B5AC3E7EE2ULL,
		0x9C274BE18B37B3B7ULL,
		0x0C9D16E3EB12722AULL,
		0x285D7674B5F50A23ULL,
		0x3D7AA46D2F55B0A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CFFB0B1F37E0790ULL,
		0x22953A8A26416258ULL,
		0x546D1031ACF7B4EBULL,
		0xF8042D6B587CFDC4ULL,
		0x384E97C3166F676EULL,
		0x193A2DC7D624E455ULL,
		0x50BAECE96BEA1446ULL,
		0x7AF548DA5EAB6152ULL
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
		0x29E081706014858EULL,
		0xDB340C258D5A3C68ULL,
		0x0E320CB018D196C2ULL,
		0x4AC8F47E6BB73E71ULL,
		0xC1D7E372C6ED9307ULL,
		0x2F8637E47C1B4BF7ULL,
		0xF9590E7366EF0F7BULL,
		0x31EDDDB8C577FB6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C102E0C0290B1CULL,
		0xB668184B1AB478D0ULL,
		0x1C64196031A32D85ULL,
		0x9591E8FCD76E7CE2ULL,
		0x83AFC6E58DDB260EULL,
		0x5F0C6FC8F83697EFULL,
		0xF2B21CE6CDDE1EF6ULL,
		0x63DBBB718AEFF6D7ULL
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
		0x99714C5730C9A33EULL,
		0xACF160DB3FB1A0C8ULL,
		0x973624A13C39CC4CULL,
		0x3DDB30AFD8645CC2ULL,
		0x3C4CD60156B2C094ULL,
		0xC221B421B34CFCACULL,
		0xE5A90F36076DD1F5ULL,
		0x3EACE328C317AA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E298AE6193467CULL,
		0x59E2C1B67F634191ULL,
		0x2E6C494278739899ULL,
		0x7BB6615FB0C8B985ULL,
		0x7899AC02AD658128ULL,
		0x844368436699F958ULL,
		0xCB521E6C0EDBA3EBULL,
		0x7D59C651862F5495ULL
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
		0xB351C435F6567465ULL,
		0x83FC0ED1E68CF0DDULL,
		0x7043332ACC8A3A5FULL,
		0x159BD11EADFAC6C5ULL,
		0xE57F6AD4BB12B478ULL,
		0x6AC8426A91D08752ULL,
		0xC79E6C489A9FFC7AULL,
		0x122C80F1B7C89665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A3886BECACE8CAULL,
		0x07F81DA3CD19E1BBULL,
		0xE0866655991474BFULL,
		0x2B37A23D5BF58D8AULL,
		0xCAFED5A9762568F0ULL,
		0xD59084D523A10EA5ULL,
		0x8F3CD891353FF8F4ULL,
		0x245901E36F912CCBULL
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
		0x7DBC364DEF0EF845ULL,
		0x35F0661653859FA3ULL,
		0x97035178246A0382ULL,
		0xEB0F297ED20F47E4ULL,
		0x43DEABC131BC3C4BULL,
		0x4D5CF85031FAB422ULL,
		0x62EC03F0B3758052ULL,
		0x304430AFAFC0EF5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB786C9BDE1DF08AULL,
		0x6BE0CC2CA70B3F46ULL,
		0x2E06A2F048D40704ULL,
		0xD61E52FDA41E8FC9ULL,
		0x87BD578263787897ULL,
		0x9AB9F0A063F56844ULL,
		0xC5D807E166EB00A4ULL,
		0x6088615F5F81DEB4ULL
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
		0xBF01F76BA40BD327ULL,
		0x36AB214848A1C019ULL,
		0x50E53D5659A0D81AULL,
		0xB2794EDDC15F2BCCULL,
		0xE1E8C00DCDA02784ULL,
		0x3B6D14A3641C9403ULL,
		0x1730EBC6D34DE04BULL,
		0x3DEE991BF3DC8A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E03EED74817A64EULL,
		0x6D56429091438033ULL,
		0xA1CA7AACB341B034ULL,
		0x64F29DBB82BE5798ULL,
		0xC3D1801B9B404F09ULL,
		0x76DA2946C8392807ULL,
		0x2E61D78DA69BC096ULL,
		0x7BDD3237E7B914A4ULL
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
		0xB3C1E1609EA52206ULL,
		0xFB106AC48AA55A94ULL,
		0x5A2A70949C7EC389ULL,
		0x795955A13DA5B346ULL,
		0xA4C6B8CD03184A4EULL,
		0x0523D87C2390732AULL,
		0xD0F5A644079A95ADULL,
		0x1BD74A203C183929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6783C2C13D4A440CULL,
		0xF620D589154AB529ULL,
		0xB454E12938FD8713ULL,
		0xF2B2AB427B4B668CULL,
		0x498D719A0630949CULL,
		0x0A47B0F84720E655ULL,
		0xA1EB4C880F352B5AULL,
		0x37AE944078307253ULL
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
		0xE8D78285B4F6E104ULL,
		0xFFDE52936F6290D3ULL,
		0xAC63BD2592AC4777ULL,
		0x3541A2544F2A4FF8ULL,
		0x58829A406E0631B8ULL,
		0x0FADF9651310633CULL,
		0xDB71CB4F11B17ADBULL,
		0x2A2BBD9DD0465990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1AF050B69EDC208ULL,
		0xFFBCA526DEC521A7ULL,
		0x58C77A4B25588EEFULL,
		0x6A8344A89E549FF1ULL,
		0xB1053480DC0C6370ULL,
		0x1F5BF2CA2620C678ULL,
		0xB6E3969E2362F5B6ULL,
		0x54577B3BA08CB321ULL
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
		0xD5769F59AF452657ULL,
		0x422CA94406BEEBD1ULL,
		0x41AEF11D2E50CF07ULL,
		0xA65F6B98ADE415BCULL,
		0x23F3E425C40175AFULL,
		0x70BD03EBF9A0C054ULL,
		0xBB0268807191235CULL,
		0x012418DB7A48DB64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAED3EB35E8A4CAEULL,
		0x845952880D7DD7A3ULL,
		0x835DE23A5CA19E0EULL,
		0x4CBED7315BC82B78ULL,
		0x47E7C84B8802EB5FULL,
		0xE17A07D7F34180A8ULL,
		0x7604D100E32246B8ULL,
		0x024831B6F491B6C9ULL
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
		0x4C5FC73970E38F7AULL,
		0xC7E3B324B497617BULL,
		0xE404094B3283B864ULL,
		0xC6255E1B978AC61BULL,
		0x46C315F9F733C950ULL,
		0x07E5D88ABA6A1D4BULL,
		0x798F8D57CE00118BULL,
		0x08D39AFECEB99406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98BF8E72E1C71EF4ULL,
		0x8FC76649692EC2F6ULL,
		0xC8081296650770C9ULL,
		0x8C4ABC372F158C37ULL,
		0x8D862BF3EE6792A1ULL,
		0x0FCBB11574D43A96ULL,
		0xF31F1AAF9C002316ULL,
		0x11A735FD9D73280CULL
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
		0x4DF491EA49861798ULL,
		0xC4D2378BFCDF0581ULL,
		0x5623EBCCC673AF82ULL,
		0x7B2F24DE51993557ULL,
		0x65C7BDC8796061BBULL,
		0xD352882D69CC7275ULL,
		0x66479CE047BBBCB9ULL,
		0x35CEF3373CB5B62AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE923D4930C2F30ULL,
		0x89A46F17F9BE0B02ULL,
		0xAC47D7998CE75F05ULL,
		0xF65E49BCA3326AAEULL,
		0xCB8F7B90F2C0C376ULL,
		0xA6A5105AD398E4EAULL,
		0xCC8F39C08F777973ULL,
		0x6B9DE66E796B6C54ULL
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
		0xEE25EFF7DEA2FDC3ULL,
		0xDF64B18E4106B3B1ULL,
		0xD9781B98A6B7B209ULL,
		0x74AE4E9C962682F2ULL,
		0x2000FFC33A4BA795ULL,
		0x270298CB68B44515ULL,
		0x68D74B7FEB9E3A34ULL,
		0x0C0759CF1023D755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC4BDFEFBD45FB86ULL,
		0xBEC9631C820D6763ULL,
		0xB2F037314D6F6413ULL,
		0xE95C9D392C4D05E5ULL,
		0x4001FF8674974F2AULL,
		0x4E053196D1688A2AULL,
		0xD1AE96FFD73C7468ULL,
		0x180EB39E2047AEAAULL
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
		0x4109BB5E5366D7DFULL,
		0x71B712282D0CF683ULL,
		0xE170C140BF5C98C0ULL,
		0x21598D571F166360ULL,
		0x2A9BD65827D8EEC3ULL,
		0x4E27EF7A7DC5A4F6ULL,
		0x689A723A560E2A00ULL,
		0x3C8665441ABD3FBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x821376BCA6CDAFBEULL,
		0xE36E24505A19ED06ULL,
		0xC2E182817EB93180ULL,
		0x42B31AAE3E2CC6C1ULL,
		0x5537ACB04FB1DD86ULL,
		0x9C4FDEF4FB8B49ECULL,
		0xD134E474AC1C5400ULL,
		0x790CCA88357A7F7AULL
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
		0x41D0D8AE2BE34BB9ULL,
		0x7C35EC58DCF0C89FULL,
		0x4B229132B75C2BDFULL,
		0x3BAF242F593690D7ULL,
		0x3D3EB35DA6DC7A24ULL,
		0xFCB4FBC30212F903ULL,
		0x5E9A59879E598A5EULL,
		0x279C325EE27519D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A1B15C57C69772ULL,
		0xF86BD8B1B9E1913EULL,
		0x964522656EB857BEULL,
		0x775E485EB26D21AEULL,
		0x7A7D66BB4DB8F448ULL,
		0xF969F7860425F206ULL,
		0xBD34B30F3CB314BDULL,
		0x4F3864BDC4EA33B0ULL
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
		0x5ABCDA0374222299ULL,
		0xE05F1CE6AFB3D71CULL,
		0x6F64B1011E5E5A2BULL,
		0x4DD90FCB6049CFC4ULL,
		0x7C44E4E6C66A5446ULL,
		0x6DADF3E6A5D845ACULL,
		0x43F5DDA14F5161C7ULL,
		0x1F27FC6B1501031AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB579B406E8444532ULL,
		0xC0BE39CD5F67AE38ULL,
		0xDEC962023CBCB457ULL,
		0x9BB21F96C0939F88ULL,
		0xF889C9CD8CD4A88CULL,
		0xDB5BE7CD4BB08B58ULL,
		0x87EBBB429EA2C38EULL,
		0x3E4FF8D62A020634ULL
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
		0x3E2C4CFF8E0567AAULL,
		0x5CF14CE23ADFE9ECULL,
		0x6175D4ED0359C334ULL,
		0x23A50DE882BBFAF3ULL,
		0xA68FBBBB658130E3ULL,
		0x3EBE7C895308EAC5ULL,
		0x23A3B7C000EA1A2EULL,
		0x1F40C05062EFEC5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5899FF1C0ACF54ULL,
		0xB9E299C475BFD3D8ULL,
		0xC2EBA9DA06B38668ULL,
		0x474A1BD10577F5E6ULL,
		0x4D1F7776CB0261C6ULL,
		0x7D7CF912A611D58BULL,
		0x47476F8001D4345CULL,
		0x3E8180A0C5DFD8B8ULL
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
		0x0AE833BB3630B267ULL,
		0x4D4F02E1B86CC9B4ULL,
		0x53FB75DEEF4931A2ULL,
		0xD7C2B6910D53621AULL,
		0xCB10448ED348DF02ULL,
		0xC1864007BAD7F475ULL,
		0x74027F6659237393ULL,
		0x2A92AA2983396BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15D067766C6164CEULL,
		0x9A9E05C370D99368ULL,
		0xA7F6EBBDDE926344ULL,
		0xAF856D221AA6C434ULL,
		0x9620891DA691BE05ULL,
		0x830C800F75AFE8EBULL,
		0xE804FECCB246E727ULL,
		0x552554530672D7FAULL
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
		0xEEBC3D0860A4C535ULL,
		0xE5E2BBCA1615D643ULL,
		0x8C96B880FBB92881ULL,
		0x9187C1EC6170BCD0ULL,
		0x12CA9CFB34256A2FULL,
		0x2A5DCCF8646A9E71ULL,
		0x7CB7A6ACDC7194E5ULL,
		0x0FE874D2850E040DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD787A10C1498A6AULL,
		0xCBC577942C2BAC87ULL,
		0x192D7101F7725103ULL,
		0x230F83D8C2E179A1ULL,
		0x259539F6684AD45FULL,
		0x54BB99F0C8D53CE2ULL,
		0xF96F4D59B8E329CAULL,
		0x1FD0E9A50A1C081AULL
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
		0xFF62D2010C579D33ULL,
		0x2D934E82138315E0ULL,
		0xF723A7D223032264ULL,
		0x538D608978002D6EULL,
		0x6C195A15E8CAA96DULL,
		0xD468490D22B70F0BULL,
		0x76EA866300E58369ULL,
		0x2E16FA9C00CD52D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC5A40218AF3A66ULL,
		0x5B269D0427062BC1ULL,
		0xEE474FA4460644C8ULL,
		0xA71AC112F0005ADDULL,
		0xD832B42BD19552DAULL,
		0xA8D0921A456E1E16ULL,
		0xEDD50CC601CB06D3ULL,
		0x5C2DF538019AA5A8ULL
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
		0x4AF504167EDEA2A0ULL,
		0x3E4874515ABB6FEEULL,
		0x99F1A31FDAE3989CULL,
		0xF2556F81B7370837ULL,
		0x46910E6E766F36B9ULL,
		0x75A01E2088AA3130ULL,
		0x001BE824A6CEDA33ULL,
		0x09B18FBB9ECB0087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EA082CFDBD4540ULL,
		0x7C90E8A2B576DFDCULL,
		0x33E3463FB5C73138ULL,
		0xE4AADF036E6E106FULL,
		0x8D221CDCECDE6D73ULL,
		0xEB403C4111546260ULL,
		0x0037D0494D9DB466ULL,
		0x13631F773D96010EULL
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
		0x87C72B69930EB629ULL,
		0xD4F635907726134EULL,
		0x804B193579B09E8CULL,
		0xCF74C26AD96375AAULL,
		0x34A123CF4FD7707DULL,
		0x3CF479F535731CABULL,
		0x5AFC8A22CC15DAA5ULL,
		0x12BAF6B21CEB6DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F8E56D3261D6C52ULL,
		0xA9EC6B20EE4C269DULL,
		0x0096326AF3613D19ULL,
		0x9EE984D5B2C6EB55ULL,
		0x6942479E9FAEE0FBULL,
		0x79E8F3EA6AE63956ULL,
		0xB5F91445982BB54AULL,
		0x2575ED6439D6DBDCULL
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
		0x7F88CC78CF40A801ULL,
		0x4A9FABDE7BA6A8F1ULL,
		0x128A1D0C39899256ULL,
		0x3E4E6A7AD58FE03AULL,
		0xBFB4260C1C91D98EULL,
		0x9492B06467A8C493ULL,
		0x2C5734E9BB123FAFULL,
		0x3B94AE14B6481494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF1198F19E815002ULL,
		0x953F57BCF74D51E2ULL,
		0x25143A18731324ACULL,
		0x7C9CD4F5AB1FC074ULL,
		0x7F684C183923B31CULL,
		0x292560C8CF518927ULL,
		0x58AE69D376247F5FULL,
		0x77295C296C902928ULL
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
		0xC063EF3DB22ED096ULL,
		0xECC04B7ECBA5DCFFULL,
		0x9CA4151B0812C09AULL,
		0x60107532A21B129FULL,
		0x18C2F13B566C8D53ULL,
		0x557DE99A8649F0E0ULL,
		0xCC10F0638DF87640ULL,
		0x31D3B984B82E5C82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80C7DE7B645DA12CULL,
		0xD98096FD974BB9FFULL,
		0x39482A3610258135ULL,
		0xC020EA654436253FULL,
		0x3185E276ACD91AA6ULL,
		0xAAFBD3350C93E1C0ULL,
		0x9821E0C71BF0EC80ULL,
		0x63A77309705CB905ULL
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
		0x62CCFD826839DBCEULL,
		0x1FBE915BDAAF902BULL,
		0x1107259A9FD34CE2ULL,
		0x6D3769DD16383FBCULL,
		0xB4E178CE13E6F468ULL,
		0x7D667B5B1CA1A85CULL,
		0xA0AE88855008CE9EULL,
		0x276FBE0385884B72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC599FB04D073B79CULL,
		0x3F7D22B7B55F2056ULL,
		0x220E4B353FA699C4ULL,
		0xDA6ED3BA2C707F78ULL,
		0x69C2F19C27CDE8D0ULL,
		0xFACCF6B6394350B9ULL,
		0x415D110AA0119D3CULL,
		0x4EDF7C070B1096E5ULL
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
		0x3A51213D6366D036ULL,
		0xF776B2F3AB34BF31ULL,
		0x441E4FC9C85E4E60ULL,
		0xF12CD0341E370E0CULL,
		0x40DABF52A5658D80ULL,
		0x7555C4EB94BA5EBAULL,
		0x82B26866EF77C4F6ULL,
		0x1DA76FC9BC513C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A2427AC6CDA06CULL,
		0xEEED65E756697E62ULL,
		0x883C9F9390BC9CC1ULL,
		0xE259A0683C6E1C18ULL,
		0x81B57EA54ACB1B01ULL,
		0xEAAB89D72974BD74ULL,
		0x0564D0CDDEEF89ECULL,
		0x3B4EDF9378A278BBULL
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
		0x9ADE79A013B6AA97ULL,
		0x7F01E6232FFEA274ULL,
		0x818D8962D313DBADULL,
		0x250BEE9DB0A9EF26ULL,
		0x79D9F03091F708D0ULL,
		0x2782F6EEC87CF831ULL,
		0x657AD3D00A045041ULL,
		0x384D3A601646015DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35BCF340276D552EULL,
		0xFE03CC465FFD44E9ULL,
		0x031B12C5A627B75AULL,
		0x4A17DD3B6153DE4DULL,
		0xF3B3E06123EE11A0ULL,
		0x4F05EDDD90F9F062ULL,
		0xCAF5A7A01408A082ULL,
		0x709A74C02C8C02BAULL
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
		0xA2E6C3F7946DFF51ULL,
		0x7F16B70AAC3D8495ULL,
		0xBC02C320C4CB82E2ULL,
		0x443A27FCDB5FEC49ULL,
		0xE659D6B790945284ULL,
		0x58D97BDBB8BC0B49ULL,
		0x5F94650189694ED7ULL,
		0x174495C0FF7E7856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45CD87EF28DBFEA2ULL,
		0xFE2D6E15587B092BULL,
		0x78058641899705C4ULL,
		0x88744FF9B6BFD893ULL,
		0xCCB3AD6F2128A508ULL,
		0xB1B2F7B771781693ULL,
		0xBF28CA0312D29DAEULL,
		0x2E892B81FEFCF0ACULL
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
		0xFDE5BC6AD05CBD67ULL,
		0x90413A541EB05481ULL,
		0xB5CF75DC5CA1DB96ULL,
		0x324BE742FA87A7A0ULL,
		0x494ED6A2F8EC7A5CULL,
		0xCCEBF05A4AEB66E9ULL,
		0x26887AF97688F19FULL,
		0x20C767A51E84F837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBCB78D5A0B97ACEULL,
		0x208274A83D60A903ULL,
		0x6B9EEBB8B943B72DULL,
		0x6497CE85F50F4F41ULL,
		0x929DAD45F1D8F4B8ULL,
		0x99D7E0B495D6CDD2ULL,
		0x4D10F5F2ED11E33FULL,
		0x418ECF4A3D09F06EULL
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
		0xF21C64503F0BB850ULL,
		0x1EE453DD488C8904ULL,
		0x57366CC458FD7F23ULL,
		0x9FFE1D0C1E7A88A1ULL,
		0x3F4E10DA19224843ULL,
		0x30C0638054C05F64ULL,
		0xA57F8FFD1260CFBFULL,
		0x332648FA5729C599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE438C8A07E1770A0ULL,
		0x3DC8A7BA91191209ULL,
		0xAE6CD988B1FAFE46ULL,
		0x3FFC3A183CF51142ULL,
		0x7E9C21B432449087ULL,
		0x6180C700A980BEC8ULL,
		0x4AFF1FFA24C19F7EULL,
		0x664C91F4AE538B33ULL
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
		0xEC61BC9AFBAC7AE0ULL,
		0x2092773343BA3A54ULL,
		0x311BA485873E9E07ULL,
		0xE7CE52ADFA02334EULL,
		0x246FDD9B4AE10727ULL,
		0xC06E4D5FB06484FDULL,
		0x219FFD08E5FA5EB2ULL,
		0x0477DB39DE3A4AC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C37935F758F5C0ULL,
		0x4124EE66877474A9ULL,
		0x6237490B0E7D3C0EULL,
		0xCF9CA55BF404669CULL,
		0x48DFBB3695C20E4FULL,
		0x80DC9ABF60C909FAULL,
		0x433FFA11CBF4BD65ULL,
		0x08EFB673BC749580ULL
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
		0x01733CF1F9342B13ULL,
		0x8A985E641EFFAB71ULL,
		0xEA70A115E74CF15FULL,
		0xF3CD8880B7B3FA32ULL,
		0x232994666C0AC055ULL,
		0xA6B4EA3A30E9977AULL,
		0xCE0BE2B7F294654DULL,
		0x26DC8ADE3C85682AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E679E3F2685626ULL,
		0x1530BCC83DFF56E2ULL,
		0xD4E1422BCE99E2BFULL,
		0xE79B11016F67F465ULL,
		0x465328CCD81580ABULL,
		0x4D69D47461D32EF4ULL,
		0x9C17C56FE528CA9BULL,
		0x4DB915BC790AD055ULL
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
		0xC222443D29A50C6CULL,
		0x23F54DC0FC88B010ULL,
		0xF8E970A57DB0E6EEULL,
		0x15D01BE5A894E7A9ULL,
		0x066090A245BCE048ULL,
		0x99015E1FBF031567ULL,
		0x4062A52A2FA2EC9DULL,
		0x3B2B66CFCF1B14E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8444887A534A18D8ULL,
		0x47EA9B81F9116021ULL,
		0xF1D2E14AFB61CDDCULL,
		0x2BA037CB5129CF53ULL,
		0x0CC121448B79C090ULL,
		0x3202BC3F7E062ACEULL,
		0x80C54A545F45D93BULL,
		0x7656CD9F9E3629CAULL
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
		0x3BC05D8F0A817E7FULL,
		0xF482A4CA5630C790ULL,
		0xF788D84BFBC2510DULL,
		0x8409B14F910205ADULL,
		0xDF82E88440720C4EULL,
		0xBFEEF40E86C7934FULL,
		0xA73AAB5EDDF234DFULL,
		0x39E4559B63EF8EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7780BB1E1502FCFEULL,
		0xE9054994AC618F20ULL,
		0xEF11B097F784A21BULL,
		0x0813629F22040B5BULL,
		0xBF05D10880E4189DULL,
		0x7FDDE81D0D8F269FULL,
		0x4E7556BDBBE469BFULL,
		0x73C8AB36C7DF1D75ULL
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
		0x66345BA49431B98FULL,
		0x4C9EA464070A9254ULL,
		0xB0CDD9EB408902DBULL,
		0xC306E5BB7A8AD6EBULL,
		0x4027B33FD235F760ULL,
		0xB1E2942D010AEBEAULL,
		0xEE19B3F24D042CBEULL,
		0x3C5F42D404296A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC68B7492863731EULL,
		0x993D48C80E1524A8ULL,
		0x619BB3D6811205B6ULL,
		0x860DCB76F515ADD7ULL,
		0x804F667FA46BEEC1ULL,
		0x63C5285A0215D7D4ULL,
		0xDC3367E49A08597DULL,
		0x78BE85A80852D52DULL
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
		0x579E16A77E7D8DEBULL,
		0x269B077494281D76ULL,
		0x31E98508ADC74F3AULL,
		0x89EC0E7116F7BBE6ULL,
		0xC604C904F84C75EBULL,
		0x639CC579DA8DB5AFULL,
		0x78C35EE35BBCA003ULL,
		0x0BCAFA42E8DA5B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3C2D4EFCFB1BD6ULL,
		0x4D360EE928503AECULL,
		0x63D30A115B8E9E74ULL,
		0x13D81CE22DEF77CCULL,
		0x8C099209F098EBD7ULL,
		0xC7398AF3B51B6B5FULL,
		0xF186BDC6B7794006ULL,
		0x1795F485D1B4B688ULL
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
		0x4B0C875A84A6BE84ULL,
		0x8E6FE1FC7767E8EBULL,
		0x4BAB75946EBE023DULL,
		0x8FF9B59D2A3CE534ULL,
		0x9AB5896F3BB328DFULL,
		0x73A861F7C9C8CADBULL,
		0xCC9815225A874742ULL,
		0x1083C308A329ED4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96190EB5094D7D08ULL,
		0x1CDFC3F8EECFD1D6ULL,
		0x9756EB28DD7C047BULL,
		0x1FF36B3A5479CA68ULL,
		0x356B12DE776651BFULL,
		0xE750C3EF939195B7ULL,
		0x99302A44B50E8E84ULL,
		0x210786114653DA9DULL
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
		0x8753BD1C8F84284DULL,
		0xDAE09208995E418DULL,
		0x37154501D7258985ULL,
		0x4029F4FDBB6BA6EAULL,
		0xD8DF90C5D2FD8A98ULL,
		0xAB0C72BACF132AD5ULL,
		0xED244F8F62EAC795ULL,
		0x31CD0717CD1D9777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EA77A391F08509AULL,
		0xB5C1241132BC831BULL,
		0x6E2A8A03AE4B130BULL,
		0x8053E9FB76D74DD4ULL,
		0xB1BF218BA5FB1530ULL,
		0x5618E5759E2655ABULL,
		0xDA489F1EC5D58F2BULL,
		0x639A0E2F9A3B2EEFULL
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
		0xE4817FB0A8D64282ULL,
		0xA8F4B5C638842C33ULL,
		0x3983779152556DCBULL,
		0x760CA5DD09ECF523ULL,
		0xCDC311FB1D03B3D0ULL,
		0x7A0C376A1649E43DULL,
		0x8C01FA884CACDCFFULL,
		0x15A081D52BEF33D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC902FF6151AC8504ULL,
		0x51E96B8C71085867ULL,
		0x7306EF22A4AADB97ULL,
		0xEC194BBA13D9EA46ULL,
		0x9B8623F63A0767A0ULL,
		0xF4186ED42C93C87BULL,
		0x1803F5109959B9FEULL,
		0x2B4103AA57DE67AFULL
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
		0xF68D389B0B2805D5ULL,
		0x48BD0D5D747F6E40ULL,
		0xBF8B64715D5FE660ULL,
		0x20C6A468E43F5EE2ULL,
		0xB558DA5608B05AEAULL,
		0xB43AAF2C9EEA963FULL,
		0x533D7566FC815ECFULL,
		0x24F5366186B56025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED1A713616500BAAULL,
		0x917A1ABAE8FEDC81ULL,
		0x7F16C8E2BABFCCC0ULL,
		0x418D48D1C87EBDC5ULL,
		0x6AB1B4AC1160B5D4ULL,
		0x68755E593DD52C7FULL,
		0xA67AEACDF902BD9FULL,
		0x49EA6CC30D6AC04AULL
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
		0xBB47CB23395EFBBEULL,
		0xCC51325BBB506054ULL,
		0xD750EFE918481D0FULL,
		0xB86C554FCE3856BEULL,
		0x4FCBCD09CC3C147AULL,
		0x03DF3F3CA4E3E04CULL,
		0xECF171AC152AB8B4ULL,
		0x1DF6E51E617B557FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768F964672BDF77CULL,
		0x98A264B776A0C0A9ULL,
		0xAEA1DFD230903A1FULL,
		0x70D8AA9F9C70AD7DULL,
		0x9F979A13987828F5ULL,
		0x07BE7E7949C7C098ULL,
		0xD9E2E3582A557168ULL,
		0x3BEDCA3CC2F6AAFFULL
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
		0xA0246EDA41A8DF60ULL,
		0x12582B271994F2DFULL,
		0x79C4D3EC7BE76A60ULL,
		0xA9A065E6C97BD8F7ULL,
		0xA9E646DFFF085BA1ULL,
		0x2A53C7555D6A1EEAULL,
		0xDEF0FA4140E44E4AULL,
		0x3BCBB070F5144727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4048DDB48351BEC0ULL,
		0x24B0564E3329E5BFULL,
		0xF389A7D8F7CED4C0ULL,
		0x5340CBCD92F7B1EEULL,
		0x53CC8DBFFE10B743ULL,
		0x54A78EAABAD43DD5ULL,
		0xBDE1F48281C89C94ULL,
		0x779760E1EA288E4FULL
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
		0xF11A3014A1F91A16ULL,
		0xB430155DB4199173ULL,
		0x21FC7AFF58FFCC9AULL,
		0xC444DB33EC02EEE8ULL,
		0xEB4CF62DCD9743C3ULL,
		0x47B46154005321D0ULL,
		0x023C6D12789754FAULL,
		0x32E694DAC094DE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE234602943F2342CULL,
		0x68602ABB683322E7ULL,
		0x43F8F5FEB1FF9935ULL,
		0x8889B667D805DDD0ULL,
		0xD699EC5B9B2E8787ULL,
		0x8F68C2A800A643A1ULL,
		0x0478DA24F12EA9F4ULL,
		0x65CD29B58129BC94ULL
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
		0xA82A39EAEC32A467ULL,
		0x33D1C2981FA8A72DULL,
		0x20AFA911F6F3BE76ULL,
		0x93E32DBA099DA03FULL,
		0x126446FC2BEE4FBEULL,
		0x25656A35CE2BC45CULL,
		0x646B4B4581ED8D2CULL,
		0x0E2C440053B6DEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505473D5D86548CEULL,
		0x67A385303F514E5BULL,
		0x415F5223EDE77CECULL,
		0x27C65B74133B407EULL,
		0x24C88DF857DC9F7DULL,
		0x4ACAD46B9C5788B8ULL,
		0xC8D6968B03DB1A58ULL,
		0x1C588800A76DBDC0ULL
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
		0x281E9A3C097C2DA5ULL,
		0x97B895E0B43350F4ULL,
		0x67EB267AD6DBF121ULL,
		0x10E9AAE0A5B892E7ULL,
		0xF45879F6AC1B93DEULL,
		0xDE18F59ED59C9F33ULL,
		0xF4CCDF0256D46919ULL,
		0x3A152262E3F22084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x503D347812F85B4AULL,
		0x2F712BC16866A1E8ULL,
		0xCFD64CF5ADB7E243ULL,
		0x21D355C14B7125CEULL,
		0xE8B0F3ED583727BCULL,
		0xBC31EB3DAB393E67ULL,
		0xE999BE04ADA8D233ULL,
		0x742A44C5C7E44109ULL
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
		0x16D168EB44DAD585ULL,
		0xB605962FDF70F1BEULL,
		0xD9BE53AC20CD0CA0ULL,
		0x623A363D11ECF958ULL,
		0x19090357E17C3764ULL,
		0x57A800F1737D3990ULL,
		0x7899023D8A541CF5ULL,
		0x12E9E005B8C3A167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DA2D1D689B5AB0AULL,
		0x6C0B2C5FBEE1E37CULL,
		0xB37CA758419A1941ULL,
		0xC4746C7A23D9F2B1ULL,
		0x321206AFC2F86EC8ULL,
		0xAF5001E2E6FA7320ULL,
		0xF132047B14A839EAULL,
		0x25D3C00B718742CEULL
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
		0x26D8FFE31A7A802AULL,
		0xBA5F7F59F0E21B9FULL,
		0xEF21432DB6EA6F80ULL,
		0xFE1EC341A426940FULL,
		0xDB37B726C0174B64ULL,
		0x311652CEDA695CD8ULL,
		0x14C9D80B7426794FULL,
		0x33BA12F623356971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB1FFC634F50054ULL,
		0x74BEFEB3E1C4373EULL,
		0xDE42865B6DD4DF01ULL,
		0xFC3D8683484D281FULL,
		0xB66F6E4D802E96C9ULL,
		0x622CA59DB4D2B9B1ULL,
		0x2993B016E84CF29EULL,
		0x677425EC466AD2E2ULL
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
		0x76CFCA9C40088021ULL,
		0xD965DB21B3D1E352ULL,
		0x5EEC3277BA449BB0ULL,
		0xC15F66F697092AAAULL,
		0x0739BA962EF4656DULL,
		0xF94245D0CA947E2FULL,
		0xD256F0EB8F6C46B6ULL,
		0x242F0561CA914736ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED9F953880110042ULL,
		0xB2CBB64367A3C6A4ULL,
		0xBDD864EF74893761ULL,
		0x82BECDED2E125554ULL,
		0x0E73752C5DE8CADBULL,
		0xF2848BA19528FC5EULL,
		0xA4ADE1D71ED88D6DULL,
		0x485E0AC395228E6DULL
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
		0x49D839C19122F2DAULL,
		0x2BD225B7495BA5B2ULL,
		0x57DB884275167257ULL,
		0x65F8A010997811DAULL,
		0xE2FA57A033AA1B1EULL,
		0xBA64EBA187630A40ULL,
		0x8663D54B813EB059ULL,
		0x0C409FF5E2F2A14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B073832245E5B4ULL,
		0x57A44B6E92B74B64ULL,
		0xAFB71084EA2CE4AEULL,
		0xCBF1402132F023B4ULL,
		0xC5F4AF406754363CULL,
		0x74C9D7430EC61481ULL,
		0x0CC7AA97027D60B3ULL,
		0x18813FEBC5E54299ULL
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
		0x7F2A12B0B05092BEULL,
		0xCF3A9F911919C525ULL,
		0xFC792ADE27D40210ULL,
		0x6144761D6BEFC760ULL,
		0xD3F112468F1018D2ULL,
		0xA8838554DEE75E83ULL,
		0x3E5EE2069B6E5AC4ULL,
		0x01F4FA691EF38377ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE54256160A1257CULL,
		0x9E753F2232338A4AULL,
		0xF8F255BC4FA80421ULL,
		0xC288EC3AD7DF8EC1ULL,
		0xA7E2248D1E2031A4ULL,
		0x51070AA9BDCEBD07ULL,
		0x7CBDC40D36DCB589ULL,
		0x03E9F4D23DE706EEULL
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
		0x24DD0DD727E3D8E9ULL,
		0xF37069FE32383598ULL,
		0xCF20EF6B89398CBCULL,
		0xA37C567C7D6F6576ULL,
		0xD089EE1ACF5B5FFDULL,
		0x3D998A3E24D6DD6AULL,
		0x3DE94A9054220432ULL,
		0x1BCF05F6DD5C270AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BA1BAE4FC7B1D2ULL,
		0xE6E0D3FC64706B30ULL,
		0x9E41DED712731979ULL,
		0x46F8ACF8FADECAEDULL,
		0xA113DC359EB6BFFBULL,
		0x7B33147C49ADBAD5ULL,
		0x7BD29520A8440864ULL,
		0x379E0BEDBAB84E14ULL
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
		0x88A11F1D65FFC8C4ULL,
		0x6C44B46FB2C046FBULL,
		0x8826BFE736032362ULL,
		0x8F6CFF9D8542E1FBULL,
		0x86B01F49C54D52B6ULL,
		0xFADE9439CAC72B4AULL,
		0x403040BABCFBA4A0ULL,
		0x050FCBDA328B780EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11423E3ACBFF9188ULL,
		0xD88968DF65808DF7ULL,
		0x104D7FCE6C0646C4ULL,
		0x1ED9FF3B0A85C3F7ULL,
		0x0D603E938A9AA56DULL,
		0xF5BD2873958E5695ULL,
		0x8060817579F74941ULL,
		0x0A1F97B46516F01CULL
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
		0x7F99B536DB1807C7ULL,
		0x480D44FF777C862FULL,
		0x78B6072D780E611DULL,
		0xEB9C5D630E603EA3ULL,
		0x994D4D082009A20CULL,
		0x707922C6695695FBULL,
		0x0BC6EE1E1F86C12DULL,
		0x1C7740D07A5F8635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF336A6DB6300F8EULL,
		0x901A89FEEEF90C5EULL,
		0xF16C0E5AF01CC23AULL,
		0xD738BAC61CC07D46ULL,
		0x329A9A1040134419ULL,
		0xE0F2458CD2AD2BF7ULL,
		0x178DDC3C3F0D825AULL,
		0x38EE81A0F4BF0C6AULL
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
		0xFCC5310C08385E22ULL,
		0xBC11FE56632A539DULL,
		0xF4A7FCF2505FF91BULL,
		0x47DA5881C7D18AE4ULL,
		0xB07AA3B9556DD108ULL,
		0x9B110DAFEE4A1975ULL,
		0xDAC166D70F97FBB5ULL,
		0x11687F916C19F716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF98A62181070BC44ULL,
		0x7823FCACC654A73BULL,
		0xE94FF9E4A0BFF237ULL,
		0x8FB4B1038FA315C9ULL,
		0x60F54772AADBA210ULL,
		0x36221B5FDC9432EBULL,
		0xB582CDAE1F2FF76BULL,
		0x22D0FF22D833EE2DULL
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
		0x12EA874AFF681125ULL,
		0xB9494D2C1EC8A1B2ULL,
		0xF539EDA5F17C6D88ULL,
		0x4AD04E47EE9AB9F7ULL,
		0xB22D9E1F1B25FCCFULL,
		0x63D8A24ABF3E74D4ULL,
		0x25275790C5065C14ULL,
		0x3FBDF777365AE598ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D50E95FED0224AULL,
		0x72929A583D914364ULL,
		0xEA73DB4BE2F8DB11ULL,
		0x95A09C8FDD3573EFULL,
		0x645B3C3E364BF99EULL,
		0xC7B144957E7CE9A9ULL,
		0x4A4EAF218A0CB828ULL,
		0x7F7BEEEE6CB5CB30ULL
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
		0x98F0EC70CCF20516ULL,
		0xFC44696A1F53837EULL,
		0xC6661D4DFE076643ULL,
		0xCEDA4667D8052E39ULL,
		0x7D9CAB0D28270A98ULL,
		0xACFA475749262DD4ULL,
		0xC15B0F1CEE0215FBULL,
		0x254A6A51130866C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E1D8E199E40A2CULL,
		0xF888D2D43EA706FDULL,
		0x8CCC3A9BFC0ECC87ULL,
		0x9DB48CCFB00A5C73ULL,
		0xFB39561A504E1531ULL,
		0x59F48EAE924C5BA8ULL,
		0x82B61E39DC042BF7ULL,
		0x4A94D4A22610CD85ULL
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
		0x2FE49EC52794BCD8ULL,
		0x0D53A8046C7D054DULL,
		0x69F692664EE03233ULL,
		0x3ACA00B6A16129F9ULL,
		0x1174D99C572C4CEEULL,
		0x86F2B737F15EF7C6ULL,
		0xB281C43D8794C5A8ULL,
		0x20DB6530C4242DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC93D8A4F2979B0ULL,
		0x1AA75008D8FA0A9AULL,
		0xD3ED24CC9DC06466ULL,
		0x7594016D42C253F2ULL,
		0x22E9B338AE5899DCULL,
		0x0DE56E6FE2BDEF8CULL,
		0x6503887B0F298B51ULL,
		0x41B6CA6188485BD5ULL
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
		0x1E48A4D7E0035F0EULL,
		0xE420C1DD39B70238ULL,
		0x2609DA03207DCA24ULL,
		0xD3B84D37D783480AULL,
		0x425089B98FEF2BECULL,
		0xDE4D2A234EA4C01CULL,
		0x6E65AF686C2A10A6ULL,
		0x14C95FC37FF7BA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C9149AFC006BE1CULL,
		0xC84183BA736E0470ULL,
		0x4C13B40640FB9449ULL,
		0xA7709A6FAF069014ULL,
		0x84A113731FDE57D9ULL,
		0xBC9A54469D498038ULL,
		0xDCCB5ED0D854214DULL,
		0x2992BF86FFEF7480ULL
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
		0x78F71CB0ED4C4BA0ULL,
		0xC34EA37B7A060E96ULL,
		0x69722793EDFEB780ULL,
		0xD94BCEAAE82628B2ULL,
		0x798D9AF0DB3C184FULL,
		0x29DAF24FCF055399ULL,
		0xF014F3ABE5AB6426ULL,
		0x2B74EE76B41BC165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1EE3961DA989740ULL,
		0x869D46F6F40C1D2CULL,
		0xD2E44F27DBFD6F01ULL,
		0xB2979D55D04C5164ULL,
		0xF31B35E1B678309FULL,
		0x53B5E49F9E0AA732ULL,
		0xE029E757CB56C84CULL,
		0x56E9DCED683782CBULL
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
		0x41A231F96B41AE3DULL,
		0x760007214202CE3FULL,
		0x8A88DFF4A459FE38ULL,
		0x6338C14C10AD8646ULL,
		0xB2759CB3C48CAB85ULL,
		0xCF9B251D35E2726FULL,
		0x068DDA367E613355ULL,
		0x09E724CE34167671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834463F2D6835C7AULL,
		0xEC000E4284059C7EULL,
		0x1511BFE948B3FC70ULL,
		0xC6718298215B0C8DULL,
		0x64EB39678919570AULL,
		0x9F364A3A6BC4E4DFULL,
		0x0D1BB46CFCC266ABULL,
		0x13CE499C682CECE2ULL
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
		0x292C56D6C253588AULL,
		0x86250A049DE269D8ULL,
		0x24BFF3F1E3B9EEA1ULL,
		0xADA1B8961C2FB697ULL,
		0x6AE5A7CD5885353EULL,
		0xCC1FD4B67644EA33ULL,
		0x3F2C30AA7146D6B4ULL,
		0x3FA21093A5127A7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5258ADAD84A6B114ULL,
		0x0C4A14093BC4D3B0ULL,
		0x497FE7E3C773DD43ULL,
		0x5B43712C385F6D2EULL,
		0xD5CB4F9AB10A6A7DULL,
		0x983FA96CEC89D466ULL,
		0x7E586154E28DAD69ULL,
		0x7F4421274A24F4FEULL
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
		0x92421A2032D60988ULL,
		0xE374BEADCA11EA18ULL,
		0x1D25834A8D719124ULL,
		0x34467FE58865709CULL,
		0x9CF33AA80183AC55ULL,
		0xE432F2E0A5BE656EULL,
		0xE8FB2BB74C329FE3ULL,
		0x2277071566FA52DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2484344065AC1310ULL,
		0xC6E97D5B9423D431ULL,
		0x3A4B06951AE32249ULL,
		0x688CFFCB10CAE138ULL,
		0x39E67550030758AAULL,
		0xC865E5C14B7CCADDULL,
		0xD1F6576E98653FC7ULL,
		0x44EE0E2ACDF4A5B9ULL
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
		0x8BAB70BAA953BDB1ULL,
		0x6C715C089F1AEA81ULL,
		0x12C80A1A0CCE3D1DULL,
		0x6DADDD54DC1AB617ULL,
		0x88BF74DB70529AE5ULL,
		0xAE948E071B555099ULL,
		0x53CC066FC4049325ULL,
		0x096F77349ACC0D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1756E17552A77B62ULL,
		0xD8E2B8113E35D503ULL,
		0x25901434199C7A3AULL,
		0xDB5BBAA9B8356C2EULL,
		0x117EE9B6E0A535CAULL,
		0x5D291C0E36AAA133ULL,
		0xA7980CDF8809264BULL,
		0x12DEEE6935981AC4ULL
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
		0xEAAA8553DC21DD03ULL,
		0x54665BB8D5DFF5F3ULL,
		0x21DC0FC4814DE904ULL,
		0xC92C90EF8A92C6FAULL,
		0xBE07ADE99C64E5A2ULL,
		0x25137A1CECB0B2A8ULL,
		0x7BAA939125E0835CULL,
		0x0C41837A22314580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5550AA7B843BA06ULL,
		0xA8CCB771ABBFEBE7ULL,
		0x43B81F89029BD208ULL,
		0x925921DF15258DF4ULL,
		0x7C0F5BD338C9CB45ULL,
		0x4A26F439D9616551ULL,
		0xF75527224BC106B8ULL,
		0x188306F444628B00ULL
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
		0x4FE3758409543050ULL,
		0x399409C64B8BF4A5ULL,
		0xF71E1518CF3129CBULL,
		0xE7108453D88128FDULL,
		0x189524C21AE6D4A8ULL,
		0xAB9D04D0940E0FB6ULL,
		0x45E63CC29D3AE993ULL,
		0x08A221DB6710B814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FC6EB0812A860A0ULL,
		0x7328138C9717E94AULL,
		0xEE3C2A319E625396ULL,
		0xCE2108A7B10251FBULL,
		0x312A498435CDA951ULL,
		0x573A09A1281C1F6CULL,
		0x8BCC79853A75D327ULL,
		0x114443B6CE217028ULL
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
		0xE1693C02A8DEF0DFULL,
		0xBED471FA4B716FB2ULL,
		0x1DADCDA6A25DA162ULL,
		0xB1539DA09B142F94ULL,
		0x2007A43DB3B957A3ULL,
		0xB1F083B01CC9303AULL,
		0xC95518C81C51A87FULL,
		0x2FEFD6759A9A4006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D2780551BDE1BEULL,
		0x7DA8E3F496E2DF65ULL,
		0x3B5B9B4D44BB42C5ULL,
		0x62A73B4136285F28ULL,
		0x400F487B6772AF47ULL,
		0x63E1076039926074ULL,
		0x92AA319038A350FFULL,
		0x5FDFACEB3534800DULL
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
		0xD9C3F191B4B059BDULL,
		0x5FE98B1304E8BBB1ULL,
		0x77839B9680B521A4ULL,
		0xFD7C7351807B8452ULL,
		0x737F6AD7DC2F6492ULL,
		0x7E8602A9B3CBA4C0ULL,
		0x5EC62ED24931AC2CULL,
		0x1263B30542291FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB387E3236960B37AULL,
		0xBFD3162609D17763ULL,
		0xEF07372D016A4348ULL,
		0xFAF8E6A300F708A4ULL,
		0xE6FED5AFB85EC925ULL,
		0xFD0C055367974980ULL,
		0xBD8C5DA492635858ULL,
		0x24C7660A84523FE2ULL
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
		0xBE91229902484934ULL,
		0x622F8F7822FE89A9ULL,
		0x7CDBF8A1B5D986DCULL,
		0x2560FFA76A2D9F78ULL,
		0x20683DE3310366EAULL,
		0xF40EA20E7388396CULL,
		0x0D4F3BFFAEE53C3AULL,
		0x051665D126263C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D22453204909268ULL,
		0xC45F1EF045FD1353ULL,
		0xF9B7F1436BB30DB8ULL,
		0x4AC1FF4ED45B3EF0ULL,
		0x40D07BC66206CDD4ULL,
		0xE81D441CE71072D8ULL,
		0x1A9E77FF5DCA7875ULL,
		0x0A2CCBA24C4C7906ULL
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
		0xEE2CF3C8172FB94EULL,
		0x7E01C0F13D5D0602ULL,
		0xDD9D6E7102FBDF8AULL,
		0xE9276C5BF6505F53ULL,
		0x0BE5B082E59B5300ULL,
		0x8FE900E61501D722ULL,
		0xF4516FAFE9427315ULL,
		0x1403EBB698BD05B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC59E7902E5F729CULL,
		0xFC0381E27ABA0C05ULL,
		0xBB3ADCE205F7BF14ULL,
		0xD24ED8B7ECA0BEA7ULL,
		0x17CB6105CB36A601ULL,
		0x1FD201CC2A03AE44ULL,
		0xE8A2DF5FD284E62BULL,
		0x2807D76D317A0B6BULL
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
		0x4979C38DF74FC04BULL,
		0x3AFF17711771BDF5ULL,
		0x5AA1E565A928F1EEULL,
		0x808D63A72E7C3DCBULL,
		0xB8BB8E2D85D1C7E0ULL,
		0xE973782B4A7E08ECULL,
		0xAC7FAEEC2125EA1DULL,
		0x2EB757F83CEBD3DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F3871BEE9F8096ULL,
		0x75FE2EE22EE37BEAULL,
		0xB543CACB5251E3DCULL,
		0x011AC74E5CF87B96ULL,
		0x71771C5B0BA38FC1ULL,
		0xD2E6F05694FC11D9ULL,
		0x58FF5DD8424BD43BULL,
		0x5D6EAFF079D7A7B5ULL
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
		0xA53379E24941BA0CULL,
		0xB9A60B5BD10FB6ADULL,
		0xE0F66D49FCD6A78DULL,
		0x0302392065C154D9ULL,
		0x843FBD0EEE7154D1ULL,
		0x83442D000ECD29BCULL,
		0xE9C3F7ED784B9340ULL,
		0x0B30261DACA8F2B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A66F3C492837418ULL,
		0x734C16B7A21F6D5BULL,
		0xC1ECDA93F9AD4F1BULL,
		0x06047240CB82A9B3ULL,
		0x087F7A1DDCE2A9A2ULL,
		0x06885A001D9A5379ULL,
		0xD387EFDAF0972681ULL,
		0x16604C3B5951E565ULL
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
		0xE799FB559925F9CEULL,
		0xB591562B729A6760ULL,
		0x0CFE08AC36430C5AULL,
		0x435D16F66FEEE826ULL,
		0xEB7E06EF6CCA19E7ULL,
		0x5204C7250F77F3EBULL,
		0x3B66F374A61273F9ULL,
		0x04E29C6A6136D0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF33F6AB324BF39CULL,
		0x6B22AC56E534CEC1ULL,
		0x19FC11586C8618B5ULL,
		0x86BA2DECDFDDD04CULL,
		0xD6FC0DDED99433CEULL,
		0xA4098E4A1EEFE7D7ULL,
		0x76CDE6E94C24E7F2ULL,
		0x09C538D4C26DA1EEULL
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
		0x01D2C9C758C8F6BCULL,
		0xE01A224BD5B66ADCULL,
		0x452E48EA2A233291ULL,
		0x9401B356F2E4833EULL,
		0x6D98ED22C597EF51ULL,
		0xE9BA88B63A2BC6C8ULL,
		0x274292E884131596ULL,
		0x30999D87727833E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A5938EB191ED78ULL,
		0xC0344497AB6CD5B8ULL,
		0x8A5C91D454466523ULL,
		0x280366ADE5C9067CULL,
		0xDB31DA458B2FDEA3ULL,
		0xD375116C74578D90ULL,
		0x4E8525D108262B2DULL,
		0x61333B0EE4F067C4ULL
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
		0xBFD43A94AF913857ULL,
		0x1621245954F379BAULL,
		0x61ED92A0ABC8858FULL,
		0xA75A464EA97706C1ULL,
		0xB8AAB193C7765090ULL,
		0x2FFE062FD0E9519BULL,
		0x9FD9882F74C9A16FULL,
		0x28BB4141CF3CDFF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA875295F2270AEULL,
		0x2C4248B2A9E6F375ULL,
		0xC3DB254157910B1EULL,
		0x4EB48C9D52EE0D82ULL,
		0x715563278EECA121ULL,
		0x5FFC0C5FA1D2A337ULL,
		0x3FB3105EE99342DEULL,
		0x517682839E79BFE5ULL
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
		0x0092AF2746C29B85ULL,
		0xD070DEE7E92F137EULL,
		0xBDF85F7A4EBED70BULL,
		0x1E2E5D715D912A6CULL,
		0x534825C8F3316E59ULL,
		0x19DD92573F28977BULL,
		0x1A62484A36EFD12FULL,
		0x0E0045CE6795EA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01255E4E8D85370AULL,
		0xA0E1BDCFD25E26FCULL,
		0x7BF0BEF49D7DAE17ULL,
		0x3C5CBAE2BB2254D9ULL,
		0xA6904B91E662DCB2ULL,
		0x33BB24AE7E512EF6ULL,
		0x34C490946DDFA25EULL,
		0x1C008B9CCF2BD4FAULL
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
		0xCFCA03992CA63AC4ULL,
		0x777F70AB745EB80AULL,
		0x4EC62579804AF09DULL,
		0xA2E3F050FEF04A3DULL,
		0xF6931B35642D3A69ULL,
		0x41304C48B79D04DDULL,
		0xECB421A7B4BE22B9ULL,
		0x1F30FFC21387695DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F940732594C7588ULL,
		0xEEFEE156E8BD7015ULL,
		0x9D8C4AF30095E13AULL,
		0x45C7E0A1FDE0947AULL,
		0xED26366AC85A74D3ULL,
		0x826098916F3A09BBULL,
		0xD968434F697C4572ULL,
		0x3E61FF84270ED2BBULL
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
		0x5AB91AA1DF570D71ULL,
		0xFB75B357ACB86B55ULL,
		0x9101211FDC0AF030ULL,
		0x055C1CE30A38AA21ULL,
		0x9A054F58797BFF0FULL,
		0x9D5B72B9E52DEF08ULL,
		0xB2F7A4E903D388AAULL,
		0x32262A66F378EB35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5723543BEAE1AE2ULL,
		0xF6EB66AF5970D6AAULL,
		0x2202423FB815E061ULL,
		0x0AB839C614715443ULL,
		0x340A9EB0F2F7FE1EULL,
		0x3AB6E573CA5BDE11ULL,
		0x65EF49D207A71155ULL,
		0x644C54CDE6F1D66BULL
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
		0xCDC20D281D3F47D2ULL,
		0x94542631DA89F020ULL,
		0xC98A0803EB4AB0DAULL,
		0x69C7F8279690F7E3ULL,
		0x4670999C70425F6FULL,
		0x9235F4DCBF9714BCULL,
		0x06CC5DA1DA05382DULL,
		0x0FED8DB36A7888F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B841A503A7E8FA4ULL,
		0x28A84C63B513E041ULL,
		0x93141007D69561B5ULL,
		0xD38FF04F2D21EFC7ULL,
		0x8CE13338E084BEDEULL,
		0x246BE9B97F2E2978ULL,
		0x0D98BB43B40A705BULL,
		0x1FDB1B66D4F111EAULL
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
		0x7AC39FD362E05B5FULL,
		0x4A16B5DB0789063AULL,
		0xDD2D3BBACB4F60EFULL,
		0x000A07E684DE91B1ULL,
		0xC1EAE26CFB1DF8D1ULL,
		0x83DF1BD139EDFA7DULL,
		0x89E31D40993BFC3DULL,
		0x12668AD17ACEE735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5873FA6C5C0B6BEULL,
		0x942D6BB60F120C74ULL,
		0xBA5A7775969EC1DEULL,
		0x00140FCD09BD2363ULL,
		0x83D5C4D9F63BF1A2ULL,
		0x07BE37A273DBF4FBULL,
		0x13C63A813277F87BULL,
		0x24CD15A2F59DCE6BULL
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
		0x91055798AD8988A0ULL,
		0xAC724C73BDF151D5ULL,
		0x5679166832719DD3ULL,
		0x1DC9353440FD26DAULL,
		0xE4D289DFA29611D5ULL,
		0x09FB5A4C51566A84ULL,
		0xF7611149FBCEC6CEULL,
		0x1C18104FD211EBC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x220AAF315B131140ULL,
		0x58E498E77BE2A3ABULL,
		0xACF22CD064E33BA7ULL,
		0x3B926A6881FA4DB4ULL,
		0xC9A513BF452C23AAULL,
		0x13F6B498A2ACD509ULL,
		0xEEC22293F79D8D9CULL,
		0x3830209FA423D78FULL
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
		0xE283DD94523309B8ULL,
		0xEF68240ED9BD1BCCULL,
		0xF8C779AE923EC0E0ULL,
		0x55EECB4A2F52D17AULL,
		0xF7EF2426030C4C2FULL,
		0x8884B70811C7FEDFULL,
		0x6784612BA41864B0ULL,
		0x3C14B58214F345F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC507BB28A4661370ULL,
		0xDED0481DB37A3799ULL,
		0xF18EF35D247D81C1ULL,
		0xABDD96945EA5A2F5ULL,
		0xEFDE484C0618985EULL,
		0x11096E10238FFDBFULL,
		0xCF08C2574830C961ULL,
		0x78296B0429E68BE2ULL
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
		0x5D1AFB479512DBC7ULL,
		0x3CACA29F1288F2BEULL,
		0xC7E87751B74739ACULL,
		0x2464E6294E77F9FFULL,
		0x4ABD76BE68AD730AULL,
		0xFC203044C886F0C2ULL,
		0x04A96A5372D68F8BULL,
		0x2C01833DC0F52BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA35F68F2A25B78EULL,
		0x7959453E2511E57CULL,
		0x8FD0EEA36E8E7358ULL,
		0x48C9CC529CEFF3FFULL,
		0x957AED7CD15AE614ULL,
		0xF8406089910DE184ULL,
		0x0952D4A6E5AD1F17ULL,
		0x5803067B81EA577EULL
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
		0x7FB36B45197D9A4AULL,
		0x45861C81C3825C86ULL,
		0x7DB7D3141097507BULL,
		0x388582F74A3A19DEULL,
		0x49172BA09FA6668DULL,
		0x6B8506A5A7134229ULL,
		0xAD79BD7A72153211ULL,
		0x3C0772DDD3AAB1A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF66D68A32FB3494ULL,
		0x8B0C39038704B90CULL,
		0xFB6FA628212EA0F6ULL,
		0x710B05EE947433BCULL,
		0x922E57413F4CCD1AULL,
		0xD70A0D4B4E268452ULL,
		0x5AF37AF4E42A6422ULL,
		0x780EE5BBA7556341ULL
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
		0xA40AC8649E35C4A2ULL,
		0x3668C2C012BAE7F0ULL,
		0xC738412A6DA1E032ULL,
		0x69B329A4484A3D78ULL,
		0x3E02ACB7BCADC696ULL,
		0xC90F16C83EB52925ULL,
		0x6109120DC9F9CF25ULL,
		0x2AC2DCD135047379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x481590C93C6B8944ULL,
		0x6CD185802575CFE1ULL,
		0x8E708254DB43C064ULL,
		0xD366534890947AF1ULL,
		0x7C05596F795B8D2CULL,
		0x921E2D907D6A524AULL,
		0xC212241B93F39E4BULL,
		0x5585B9A26A08E6F2ULL
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
		0xE7BC4BF7FFC7AC24ULL,
		0x62DCE32B988CE320ULL,
		0xC90473B7EA14080AULL,
		0x81A106C4ADCAC090ULL,
		0xEE26954732F06B4BULL,
		0xBB5946ABB515AFA1ULL,
		0x57CC58DE7E2D2947ULL,
		0x0CF8FBFC3852D77AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF7897EFFF8F5848ULL,
		0xC5B9C6573119C641ULL,
		0x9208E76FD4281014ULL,
		0x03420D895B958121ULL,
		0xDC4D2A8E65E0D697ULL,
		0x76B28D576A2B5F43ULL,
		0xAF98B1BCFC5A528FULL,
		0x19F1F7F870A5AEF4ULL
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
		0xC4A767EB3C8A8CD5ULL,
		0x7F1B3895C90E7862ULL,
		0x30FDBDB32FADB923ULL,
		0xA6CAED88CA550639ULL,
		0x8588771E5FA5844FULL,
		0x830801B4E6B3C541ULL,
		0xCC57CBB4FFA3544DULL,
		0x0EBE7856B26ADB0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x894ECFD6791519AAULL,
		0xFE36712B921CF0C5ULL,
		0x61FB7B665F5B7246ULL,
		0x4D95DB1194AA0C72ULL,
		0x0B10EE3CBF4B089FULL,
		0x06100369CD678A83ULL,
		0x98AF9769FF46A89BULL,
		0x1D7CF0AD64D5B61DULL
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
		0x75028EE066E06642ULL,
		0x38D2DC6A9A06F977ULL,
		0x08AF5767CC9D9972ULL,
		0x91E0CA406D9A7772ULL,
		0x96CC9CF11A0B03C6ULL,
		0x62208D4AA99534BAULL,
		0xCD90F026F6D16106ULL,
		0x0DB668E9DBC4D4BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA051DC0CDC0CC84ULL,
		0x71A5B8D5340DF2EEULL,
		0x115EAECF993B32E4ULL,
		0x23C19480DB34EEE4ULL,
		0x2D9939E23416078DULL,
		0xC4411A95532A6975ULL,
		0x9B21E04DEDA2C20CULL,
		0x1B6CD1D3B789A97BULL
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
		0xF04CB19DA8C9E911ULL,
		0x1153B1A7D8C2C29CULL,
		0x70760A594B31713EULL,
		0x703F10C192B6004BULL,
		0x3AE706A0784FE6C7ULL,
		0x80040CC720CB9C7FULL,
		0x74999D3691D8802FULL,
		0x078B06521F82763BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE099633B5193D222ULL,
		0x22A7634FB1858539ULL,
		0xE0EC14B29662E27CULL,
		0xE07E2183256C0096ULL,
		0x75CE0D40F09FCD8EULL,
		0x0008198E419738FEULL,
		0xE9333A6D23B1005FULL,
		0x0F160CA43F04EC76ULL
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
		0x454FB156F01D1CAAULL,
		0x7F03C947C1877E30ULL,
		0x2B0689F992967146ULL,
		0xDAE67F5FA1C9E4AFULL,
		0x1B34C3D8D97CF986ULL,
		0x4FD68FE65157115CULL,
		0x430E8F9EF0F13FAEULL,
		0x016E944C5D826368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A9F62ADE03A3954ULL,
		0xFE07928F830EFC60ULL,
		0x560D13F3252CE28CULL,
		0xB5CCFEBF4393C95EULL,
		0x366987B1B2F9F30DULL,
		0x9FAD1FCCA2AE22B8ULL,
		0x861D1F3DE1E27F5CULL,
		0x02DD2898BB04C6D0ULL
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
		0xEB51450E853CD5EDULL,
		0xFF64E5CD9F7689BFULL,
		0xFFFDDBFD139F8754ULL,
		0xD1B2AF7F38BB54CBULL,
		0x20762273C82B3097ULL,
		0xEDF05C03550B5B06ULL,
		0x072E159F510FE8A7ULL,
		0x220297304C7699DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A28A1D0A79ABDAULL,
		0xFEC9CB9B3EED137FULL,
		0xFFFBB7FA273F0EA9ULL,
		0xA3655EFE7176A997ULL,
		0x40EC44E79056612FULL,
		0xDBE0B806AA16B60CULL,
		0x0E5C2B3EA21FD14FULL,
		0x44052E6098ED33B6ULL
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
		0x3032B11CC7FBD8AEULL,
		0x17A490BC7F8EF5E5ULL,
		0x875EDC70A37913A6ULL,
		0xB502D78934B0FF05ULL,
		0x00BD78BDB9E5F85DULL,
		0xFD4EAB040977BE67ULL,
		0x0D56930982EF99F0ULL,
		0x1E340EF897D7DC68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606562398FF7B15CULL,
		0x2F492178FF1DEBCAULL,
		0x0EBDB8E146F2274CULL,
		0x6A05AF126961FE0BULL,
		0x017AF17B73CBF0BBULL,
		0xFA9D560812EF7CCEULL,
		0x1AAD261305DF33E1ULL,
		0x3C681DF12FAFB8D0ULL
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
		0xDE4F04C9582D7F37ULL,
		0x2470E6C75A24CE01ULL,
		0x597877C8ED8C9CF2ULL,
		0xCBBAB928F424B9A6ULL,
		0xFB7F17861EFD29FAULL,
		0x8997E6356D528727ULL,
		0x7EF5157C5040F3A7ULL,
		0x0CA57C15DEDC257CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC9E0992B05AFE6EULL,
		0x48E1CD8EB4499C03ULL,
		0xB2F0EF91DB1939E4ULL,
		0x97757251E849734CULL,
		0xF6FE2F0C3DFA53F5ULL,
		0x132FCC6ADAA50E4FULL,
		0xFDEA2AF8A081E74FULL,
		0x194AF82BBDB84AF8ULL
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
		0xE22AFA8AD72616CCULL,
		0xA57CDD3E59CA9379ULL,
		0x9947B801EA440FDFULL,
		0x6C959FF03CA32444ULL,
		0xC9855F1D60D31AD6ULL,
		0x56F7EECAEBD8D067ULL,
		0x6848C955E0CB7BD7ULL,
		0x0838363D65EB4902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC455F515AE4C2D98ULL,
		0x4AF9BA7CB39526F3ULL,
		0x328F7003D4881FBFULL,
		0xD92B3FE079464889ULL,
		0x930ABE3AC1A635ACULL,
		0xADEFDD95D7B1A0CFULL,
		0xD09192ABC196F7AEULL,
		0x10706C7ACBD69204ULL
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
		0x951D5A88AE022940ULL,
		0x90D52F950CF4036BULL,
		0x3C9FD1AFA4C9AA5EULL,
		0x9B0F9E46D264614FULL,
		0x6CA46481EAE5104CULL,
		0x7692673EDAA5A1F8ULL,
		0xC0803B764160CED6ULL,
		0x0EB80C168FEF4731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A3AB5115C045280ULL,
		0x21AA5F2A19E806D7ULL,
		0x793FA35F499354BDULL,
		0x361F3C8DA4C8C29EULL,
		0xD948C903D5CA2099ULL,
		0xED24CE7DB54B43F0ULL,
		0x810076EC82C19DACULL,
		0x1D70182D1FDE8E63ULL
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
		0x5A68230C332A547DULL,
		0x03DAC1A3840E6BD9ULL,
		0x08267AFF7D980C71ULL,
		0x55897505842E853EULL,
		0x08F1575544691430ULL,
		0xB4DB4A27B98E2B6FULL,
		0xC653FA3AE788EF1AULL,
		0x39DE25BFC06342F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4D046186654A8FAULL,
		0x07B58347081CD7B2ULL,
		0x104CF5FEFB3018E2ULL,
		0xAB12EA0B085D0A7CULL,
		0x11E2AEAA88D22860ULL,
		0x69B6944F731C56DEULL,
		0x8CA7F475CF11DE35ULL,
		0x73BC4B7F80C685EDULL
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
		0xF88BE54638C4A42CULL,
		0xE59D42A805556AE0ULL,
		0x9E87CC64048058A5ULL,
		0xEEDA6A19724AB724ULL,
		0x8246EB7B71486459ULL,
		0x45D9EE785E42666CULL,
		0xC8613303A775698BULL,
		0x3EC397FE192D0242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF117CA8C71894858ULL,
		0xCB3A85500AAAD5C1ULL,
		0x3D0F98C80900B14BULL,
		0xDDB4D432E4956E49ULL,
		0x048DD6F6E290C8B3ULL,
		0x8BB3DCF0BC84CCD9ULL,
		0x90C266074EEAD316ULL,
		0x7D872FFC325A0485ULL
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
		0x16B9AD467DBC54F4ULL,
		0x4F274201FD9EA3F2ULL,
		0x0CA9A9398CA7FE00ULL,
		0x3D282F9630F3BC39ULL,
		0x0E752C57D63B0968ULL,
		0x99080BF08D029807ULL,
		0x4EFA328487BE0B7BULL,
		0x2BD63D2C223CD029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D735A8CFB78A9E8ULL,
		0x9E4E8403FB3D47E4ULL,
		0x19535273194FFC00ULL,
		0x7A505F2C61E77872ULL,
		0x1CEA58AFAC7612D0ULL,
		0x321017E11A05300EULL,
		0x9DF465090F7C16F7ULL,
		0x57AC7A584479A052ULL
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
		0x91EB59B22F34C8A6ULL,
		0x270DB153F72AEB6FULL,
		0xF04DDAD03650A3D5ULL,
		0x5E0DDB9974DCC758ULL,
		0xB9DCA5316EB2ADC1ULL,
		0x8C74E04F4B6FA406ULL,
		0x3152E42D614BB532ULL,
		0x30F3F6F5DE3FF3D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D6B3645E69914CULL,
		0x4E1B62A7EE55D6DFULL,
		0xE09BB5A06CA147AAULL,
		0xBC1BB732E9B98EB1ULL,
		0x73B94A62DD655B82ULL,
		0x18E9C09E96DF480DULL,
		0x62A5C85AC2976A65ULL,
		0x61E7EDEBBC7FE7A6ULL
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
		0xE84DF3FDBF7C7118ULL,
		0x3005E88ABBBEA732ULL,
		0xA674C1A1AF10A7BEULL,
		0x1E0151DCB202DB5DULL,
		0xA46B4DFA32C04998ULL,
		0x89E3C2A97F80AEF1ULL,
		0x27163ED275E8CE77ULL,
		0x3474ECCDF3802CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD09BE7FB7EF8E230ULL,
		0x600BD115777D4E65ULL,
		0x4CE983435E214F7CULL,
		0x3C02A3B96405B6BBULL,
		0x48D69BF465809330ULL,
		0x13C78552FF015DE3ULL,
		0x4E2C7DA4EBD19CEFULL,
		0x68E9D99BE70059E6ULL
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
		0xDF963492BEFA9CD4ULL,
		0x2EA887F3B74DCF14ULL,
		0x471B3360D13FAA62ULL,
		0x5725860728094C67ULL,
		0xC83715F0B7A81FDCULL,
		0x7995F1F1AB515176ULL,
		0xBD6943A3BC041E8DULL,
		0x34974C3B1A276088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF2C69257DF539A8ULL,
		0x5D510FE76E9B9E29ULL,
		0x8E3666C1A27F54C4ULL,
		0xAE4B0C0E501298CEULL,
		0x906E2BE16F503FB8ULL,
		0xF32BE3E356A2A2EDULL,
		0x7AD2874778083D1AULL,
		0x692E9876344EC111ULL
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
		0x97651B03B05732A5ULL,
		0x8DEB4CF5A8F04FA8ULL,
		0xB3928E594477B535ULL,
		0x45EB40753154DA71ULL,
		0x69CF702719F66DB2ULL,
		0x5C4698ABC972C092ULL,
		0xF3325F22B98E8AECULL,
		0x2D198D94020B77D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ECA360760AE654AULL,
		0x1BD699EB51E09F51ULL,
		0x67251CB288EF6A6BULL,
		0x8BD680EA62A9B4E3ULL,
		0xD39EE04E33ECDB64ULL,
		0xB88D315792E58124ULL,
		0xE664BE45731D15D8ULL,
		0x5A331B280416EFB1ULL
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
		0xABA2DFC796D95BDCULL,
		0x7165C9ED986BBBCBULL,
		0xECE43E14438D6770ULL,
		0x810BC9C18F778DB8ULL,
		0xEF92706D431345B3ULL,
		0x9564859FA2B2CB7AULL,
		0xC98BE7875134301AULL,
		0x29E8961DF287B778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5745BF8F2DB2B7B8ULL,
		0xE2CB93DB30D77797ULL,
		0xD9C87C28871ACEE0ULL,
		0x021793831EEF1B71ULL,
		0xDF24E0DA86268B67ULL,
		0x2AC90B3F456596F5ULL,
		0x9317CF0EA2686035ULL,
		0x53D12C3BE50F6EF1ULL
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
		0x26ECB9224BD54410ULL,
		0xE64B5D1D66A52878ULL,
		0xD33B1D300C523941ULL,
		0x7667F0AE7C136498ULL,
		0x2682E0BF7AA544A5ULL,
		0x58A795E239F3AA36ULL,
		0x4ECB2474CC1FCC6FULL,
		0x1AD288401F722652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD9724497AA8820ULL,
		0xCC96BA3ACD4A50F0ULL,
		0xA6763A6018A47283ULL,
		0xECCFE15CF826C931ULL,
		0x4D05C17EF54A894AULL,
		0xB14F2BC473E7546CULL,
		0x9D9648E9983F98DEULL,
		0x35A510803EE44CA4ULL
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
		0x943946AC9FF5C3D7ULL,
		0xE5FF611EEA1821CBULL,
		0x1586E464FBAE95D7ULL,
		0x5B40D82B8F3C3799ULL,
		0x968CB21520D66484ULL,
		0xF0B699D70E2B2242ULL,
		0x2E00B4656B636AABULL,
		0x081F5D3102EF51A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28728D593FEB87AEULL,
		0xCBFEC23DD4304397ULL,
		0x2B0DC8C9F75D2BAFULL,
		0xB681B0571E786F32ULL,
		0x2D19642A41ACC908ULL,
		0xE16D33AE1C564485ULL,
		0x5C0168CAD6C6D557ULL,
		0x103EBA6205DEA346ULL
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
		0xCD955E9450094333ULL,
		0xF8D24EDEA2B49DC1ULL,
		0xD812ACEA4F688FA5ULL,
		0x8AAED5356D982BC9ULL,
		0x7943E2B4E465CAE9ULL,
		0xBF2083D0737615BBULL,
		0x36057FA2EB30D250ULL,
		0x1422E4D880CAF6F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B2ABD28A0128666ULL,
		0xF1A49DBD45693B83ULL,
		0xB02559D49ED11F4BULL,
		0x155DAA6ADB305793ULL,
		0xF287C569C8CB95D3ULL,
		0x7E4107A0E6EC2B76ULL,
		0x6C0AFF45D661A4A1ULL,
		0x2845C9B10195EDE2ULL
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
		0xDDE99362E1B0C6C9ULL,
		0x2857A3AD5D2EE4A8ULL,
		0x332FC22CAD63C6B9ULL,
		0x652753541D95CF39ULL,
		0xBA2762BF56C81A69ULL,
		0x41D82C4AADE43B72ULL,
		0x66187E885E518FF5ULL,
		0x27A61602CF7050FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBD326C5C3618D92ULL,
		0x50AF475ABA5DC951ULL,
		0x665F84595AC78D72ULL,
		0xCA4EA6A83B2B9E72ULL,
		0x744EC57EAD9034D2ULL,
		0x83B058955BC876E5ULL,
		0xCC30FD10BCA31FEAULL,
		0x4F4C2C059EE0A1FEULL
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
		0xC4D9F3BFC5AAD075ULL,
		0x1B0F4DDAFA4E5559ULL,
		0x17901ED6DA0D97C1ULL,
		0x7827B6921E064016ULL,
		0x40899D40D2C83917ULL,
		0xEE5E273DF72197DBULL,
		0x560BA5163A0603E2ULL,
		0x135016BFBC60DC0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B3E77F8B55A0EAULL,
		0x361E9BB5F49CAAB3ULL,
		0x2F203DADB41B2F82ULL,
		0xF04F6D243C0C802CULL,
		0x81133A81A590722EULL,
		0xDCBC4E7BEE432FB6ULL,
		0xAC174A2C740C07C5ULL,
		0x26A02D7F78C1B81CULL
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
		0x3DC57BAAC134B7EBULL,
		0xCAC892E824CE4A07ULL,
		0xDD3AC2F2B7136E49ULL,
		0x7940E4C6B592894DULL,
		0xC4949542EB1901B3ULL,
		0x4D58B9085B61AF9AULL,
		0x1010B351FB6731A5ULL,
		0x0EF5A7FF338C6A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B8AF75582696FD6ULL,
		0x959125D0499C940EULL,
		0xBA7585E56E26DC93ULL,
		0xF281C98D6B25129BULL,
		0x89292A85D6320366ULL,
		0x9AB17210B6C35F35ULL,
		0x202166A3F6CE634AULL,
		0x1DEB4FFE6718D438ULL
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
		0xA6FA6C6960FF7A09ULL,
		0xC4B56D4834F31BF3ULL,
		0xBAA2BF111029993AULL,
		0x2175CD001E2AD354ULL,
		0x075841536014457BULL,
		0x87C6C0F12DF5F7E1ULL,
		0x42E6168C8B953CFCULL,
		0x1441C0E5303753FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF4D8D2C1FEF412ULL,
		0x896ADA9069E637E7ULL,
		0x75457E2220533275ULL,
		0x42EB9A003C55A6A9ULL,
		0x0EB082A6C0288AF6ULL,
		0x0F8D81E25BEBEFC2ULL,
		0x85CC2D19172A79F9ULL,
		0x288381CA606EA7FEULL
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
		0x0EAA5CFA2FBC94DFULL,
		0x3BA611E1D26FC5A3ULL,
		0x858FA4429DFA5EE9ULL,
		0x2D244163D1A62B56ULL,
		0x90E0EE00D822338DULL,
		0x348BE70081562352ULL,
		0x2A1073B44038786AULL,
		0x0CCACDF5534726B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D54B9F45F7929BEULL,
		0x774C23C3A4DF8B46ULL,
		0x0B1F48853BF4BDD2ULL,
		0x5A4882C7A34C56ADULL,
		0x21C1DC01B044671AULL,
		0x6917CE0102AC46A5ULL,
		0x5420E7688070F0D4ULL,
		0x19959BEAA68E4D6AULL
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
		0x8583690A79F1F2FEULL,
		0x4B65A927538DB9BDULL,
		0x866344EAB020C5E9ULL,
		0x0CF01F763F91F57CULL,
		0x422A805DE598816DULL,
		0x5BB53A75CFBCC6A8ULL,
		0x7C57EC8F2A5512C9ULL,
		0x0D26DD9D21154FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B06D214F3E3E5FCULL,
		0x96CB524EA71B737BULL,
		0x0CC689D560418BD2ULL,
		0x19E03EEC7F23EAF9ULL,
		0x845500BBCB3102DAULL,
		0xB76A74EB9F798D50ULL,
		0xF8AFD91E54AA2592ULL,
		0x1A4DBB3A422A9FA4ULL
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
		0xD0C65A46BFCD26D0ULL,
		0x72BB678997C6C6F3ULL,
		0x601BD0A0EB59F6C7ULL,
		0x3CBB963C21606E63ULL,
		0x88A4D9AED2B0B84DULL,
		0xCED8EE5B07DB75C9ULL,
		0x8054DC76DCDBBDECULL,
		0x2039D210BCE6EE29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18CB48D7F9A4DA0ULL,
		0xE576CF132F8D8DE7ULL,
		0xC037A141D6B3ED8EULL,
		0x79772C7842C0DCC6ULL,
		0x1149B35DA561709AULL,
		0x9DB1DCB60FB6EB93ULL,
		0x00A9B8EDB9B77BD9ULL,
		0x4073A42179CDDC53ULL
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
		0xD732B31A13A89E63ULL,
		0xA63888FE7AF33130ULL,
		0xDA2DD95195F53D3EULL,
		0x2C22C69421996A68ULL,
		0xDCD1EF30743823E7ULL,
		0xA40C520C5FDFE60AULL,
		0xC339DA81CB89D5AEULL,
		0x1F6A5C5DC97DFC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE65663427513CC6ULL,
		0x4C7111FCF5E66261ULL,
		0xB45BB2A32BEA7A7DULL,
		0x58458D284332D4D1ULL,
		0xB9A3DE60E87047CEULL,
		0x4818A418BFBFCC15ULL,
		0x8673B5039713AB5DULL,
		0x3ED4B8BB92FBF931ULL
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
		0xAD80C2A94AAD12FDULL,
		0x62B335DDA9BDC491ULL,
		0xC910DB4EB3ECC3C7ULL,
		0xAC9A19012C5996B2ULL,
		0x1C0CD4376B64B13BULL,
		0x04C72D043674890AULL,
		0x8A0811A5E47FD842ULL,
		0x36BD91A1BD44D591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B018552955A25FAULL,
		0xC5666BBB537B8923ULL,
		0x9221B69D67D9878EULL,
		0x5934320258B32D65ULL,
		0x3819A86ED6C96277ULL,
		0x098E5A086CE91214ULL,
		0x1410234BC8FFB084ULL,
		0x6D7B23437A89AB23ULL
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
		0xDCBD66E0895C6E5BULL,
		0x5B3CB4B18F7DCC1EULL,
		0x572FDF9676B60813ULL,
		0x572178D17E8F7111ULL,
		0x3F4BD4A252772128ULL,
		0xB35E2553CCFF987BULL,
		0xAD1E02574CE754A8ULL,
		0x29027B25AF8B7804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97ACDC112B8DCB6ULL,
		0xB67969631EFB983DULL,
		0xAE5FBF2CED6C1026ULL,
		0xAE42F1A2FD1EE222ULL,
		0x7E97A944A4EE4250ULL,
		0x66BC4AA799FF30F6ULL,
		0x5A3C04AE99CEA951ULL,
		0x5204F64B5F16F009ULL
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
		0xF18C828D1C3DC326ULL,
		0xCE2862F956197DC3ULL,
		0x7BA30BE772E8CBB3ULL,
		0x9B94D59EED63587FULL,
		0x9A168648B8471ED9ULL,
		0xDC15B3DD8AC8ED4FULL,
		0x5EC1121A2C4E91B0ULL,
		0x16C5A5E7BBF85B6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE319051A387B864CULL,
		0x9C50C5F2AC32FB87ULL,
		0xF74617CEE5D19767ULL,
		0x3729AB3DDAC6B0FEULL,
		0x342D0C91708E3DB3ULL,
		0xB82B67BB1591DA9FULL,
		0xBD822434589D2361ULL,
		0x2D8B4BCF77F0B6DCULL
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
		0x671C8496FFE4E130ULL,
		0x28DA19D7A41EC540ULL,
		0x8D139F3F85B3B485ULL,
		0x59B670472FC25E9DULL,
		0x064E93E3252964B4ULL,
		0x8094D47F1CC6E327ULL,
		0x97B7F05227B2CA7AULL,
		0x0F62575CD12936D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE39092DFFC9C260ULL,
		0x51B433AF483D8A80ULL,
		0x1A273E7F0B67690AULL,
		0xB36CE08E5F84BD3BULL,
		0x0C9D27C64A52C968ULL,
		0x0129A8FE398DC64EULL,
		0x2F6FE0A44F6594F5ULL,
		0x1EC4AEB9A2526DB3ULL
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
		0x9F1D24EC0D5A8CE1ULL,
		0xC458A46B2CAC36D4ULL,
		0xA1AE4AE59E160B56ULL,
		0x57555862E7DCCE2DULL,
		0x6424239589117A83ULL,
		0xF5A58021E06C22F3ULL,
		0x3118E584ACF36F16ULL,
		0x3C5A0E008566057AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E3A49D81AB519C2ULL,
		0x88B148D659586DA9ULL,
		0x435C95CB3C2C16ADULL,
		0xAEAAB0C5CFB99C5BULL,
		0xC848472B1222F506ULL,
		0xEB4B0043C0D845E6ULL,
		0x6231CB0959E6DE2DULL,
		0x78B41C010ACC0AF4ULL
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
		0xC02DD60746BE43E6ULL,
		0x3240E2C6918D12CDULL,
		0x7B74FCCA8CD4B2BFULL,
		0x863A28009CE00A38ULL,
		0x51850FE691242B5BULL,
		0xEEB24C4B0B8555E6ULL,
		0x611C8E400DD56D99ULL,
		0x06CE7E201CC43933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805BAC0E8D7C87CCULL,
		0x6481C58D231A259BULL,
		0xF6E9F99519A9657EULL,
		0x0C74500139C01470ULL,
		0xA30A1FCD224856B7ULL,
		0xDD649896170AABCCULL,
		0xC2391C801BAADB33ULL,
		0x0D9CFC4039887266ULL
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
		0xAAE1F7233FF1C245ULL,
		0x06D961AD76973545ULL,
		0x64DB7B4BADE8BC24ULL,
		0x65CEEBE4FC99008FULL,
		0xF62AF448E7772E94ULL,
		0x27AB4D6A7BC2A370ULL,
		0x40BB644A0E874372ULL,
		0x286546B3C9C18B4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C3EE467FE3848AULL,
		0x0DB2C35AED2E6A8BULL,
		0xC9B6F6975BD17848ULL,
		0xCB9DD7C9F932011EULL,
		0xEC55E891CEEE5D28ULL,
		0x4F569AD4F78546E1ULL,
		0x8176C8941D0E86E4ULL,
		0x50CA8D6793831696ULL
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
		0x5D090A6F533F2581ULL,
		0xC09C6646BAD96AC1ULL,
		0xDB8FB0984CCA2F67ULL,
		0xD2514906E50349C1ULL,
		0xF5950343D5556D66ULL,
		0xE3D1E407D0A31F5CULL,
		0x4FB681F670DB58A8ULL,
		0x368601795D37F355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1214DEA67E4B02ULL,
		0x8138CC8D75B2D582ULL,
		0xB71F613099945ECFULL,
		0xA4A2920DCA069383ULL,
		0xEB2A0687AAAADACDULL,
		0xC7A3C80FA1463EB9ULL,
		0x9F6D03ECE1B6B151ULL,
		0x6D0C02F2BA6FE6AAULL
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
		0x30E505D5E46A3B9AULL,
		0x15A23D6151312312ULL,
		0x92CAE3671EB8A909ULL,
		0x07513BEB8CDD7086ULL,
		0xBE37B25B738DF9A4ULL,
		0x482C9B347C1EAFFAULL,
		0x99548D323A9EBD9BULL,
		0x0C22D3903EEDF754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61CA0BABC8D47734ULL,
		0x2B447AC2A2624624ULL,
		0x2595C6CE3D715212ULL,
		0x0EA277D719BAE10DULL,
		0x7C6F64B6E71BF348ULL,
		0x90593668F83D5FF5ULL,
		0x32A91A64753D7B36ULL,
		0x1845A7207DDBEEA9ULL
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
		0xCB2C701B32E492DFULL,
		0x98C638634894B003ULL,
		0x601441FF3DD89E9AULL,
		0x1BFFF718FD435F98ULL,
		0xE3D78A26B7C95559ULL,
		0x5C19155C5F1A401EULL,
		0x56FE0F76B987DA03ULL,
		0x39DB1B8877E83138ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9658E03665C925BEULL,
		0x318C70C691296007ULL,
		0xC02883FE7BB13D35ULL,
		0x37FFEE31FA86BF30ULL,
		0xC7AF144D6F92AAB2ULL,
		0xB8322AB8BE34803DULL,
		0xADFC1EED730FB406ULL,
		0x73B63710EFD06270ULL
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
		0x3186849BEF2C00F2ULL,
		0x04D78682E1F9E22FULL,
		0xCBDF1BF739DAD914ULL,
		0x8A60E07D9ED057A3ULL,
		0xEEA209ACA347CB17ULL,
		0xCD9249CECC18251BULL,
		0xB18C1A53A49A7981ULL,
		0x192C1B5CBA55A07AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x630D0937DE5801E4ULL,
		0x09AF0D05C3F3C45EULL,
		0x97BE37EE73B5B228ULL,
		0x14C1C0FB3DA0AF47ULL,
		0xDD441359468F962FULL,
		0x9B24939D98304A37ULL,
		0x631834A74934F303ULL,
		0x325836B974AB40F5ULL
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
		0xE34207E4F93C09D7ULL,
		0x44A0C18712ED0D87ULL,
		0xBE9631AD31ECFDD7ULL,
		0x143499F6656B1970ULL,
		0xB6C4E55699B27520ULL,
		0x8F6DB20B2F315ABDULL,
		0xA80CC18EBC934BE3ULL,
		0x24772A87B7DAAFDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6840FC9F27813AEULL,
		0x8941830E25DA1B0FULL,
		0x7D2C635A63D9FBAEULL,
		0x286933ECCAD632E1ULL,
		0x6D89CAAD3364EA40ULL,
		0x1EDB64165E62B57BULL,
		0x5019831D792697C7ULL,
		0x48EE550F6FB55FB9ULL
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
		0x46D9445A4CD11437ULL,
		0x1DB4EE24DB98E453ULL,
		0x860324C128089FD3ULL,
		0xCCDD2C84B6752DA6ULL,
		0xD25A1D4B9B17E242ULL,
		0x4029CB7B8D645563ULL,
		0x909FE5779214EE23ULL,
		0x2A35CA6F8CDA2D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DB288B499A2286EULL,
		0x3B69DC49B731C8A6ULL,
		0x0C06498250113FA6ULL,
		0x99BA59096CEA5B4DULL,
		0xA4B43A97362FC485ULL,
		0x805396F71AC8AAC7ULL,
		0x213FCAEF2429DC46ULL,
		0x546B94DF19B45AA5ULL
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
		0x0906900721BE0602ULL,
		0x6CCB998B50152F0CULL,
		0xDAC6E787CA1F7B3AULL,
		0x45CA151205D417E2ULL,
		0xEC45A2792E57914AULL,
		0xEDE863FF7853F46BULL,
		0x35EA90AAA2B134A0ULL,
		0x1BEB996C49A7A30FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120D200E437C0C04ULL,
		0xD9973316A02A5E18ULL,
		0xB58DCF0F943EF674ULL,
		0x8B942A240BA82FC5ULL,
		0xD88B44F25CAF2294ULL,
		0xDBD0C7FEF0A7E8D7ULL,
		0x6BD5215545626941ULL,
		0x37D732D8934F461EULL
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