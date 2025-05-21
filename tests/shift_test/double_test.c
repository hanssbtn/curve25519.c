#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6C7641E3FD31718EULL,
		0xF775396AB3D6A0A8ULL,
		0x24EC2758866D9547ULL,
		0x04B4F2BD0ED85053ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xD8EC83C7FA62E31CULL,
		0xEEEA72D567AD4150ULL,
		0x49D84EB10CDB2A8FULL,
		0x0969E57A1DB0A0A6ULL
	}};
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE81EB73313B75E59ULL,
		0x1C6C6E5CA3EA9DAFULL,
		0xCDD3AD73ED63B6F4ULL,
		0x65E96AA7463B0988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD03D6E66276EBCC5ULL,
		0x38D8DCB947D53B5FULL,
		0x9BA75AE7DAC76DE8ULL,
		0x4BD2D54E8C761311ULL
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
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9622BBC75642D8EULL,
		0x12282B97797DAB85ULL,
		0xD6B4DC76D038FF61ULL,
		0x727BCA6C09C2D4A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92C45778EAC85B2FULL,
		0x2450572EF2FB570BULL,
		0xAD69B8EDA071FEC2ULL,
		0x64F794D81385A951ULL
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
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEC6EDFEFAA90E90ULL,
		0x767F6489FE8E8873ULL,
		0x340133E68E3CB802ULL,
		0x23D5B92134157E62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD8DDBFDF5521D20ULL,
		0xECFEC913FD1D10E7ULL,
		0x680267CD1C797004ULL,
		0x47AB7242682AFCC4ULL
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
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F65626650803E41ULL,
		0xDCEDA697175908E2ULL,
		0x39E8F283C97D42E7ULL,
		0x58A65C0F193A7A20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ECAC4CCA1007C95ULL,
		0xB9DB4D2E2EB211C5ULL,
		0x73D1E50792FA85CFULL,
		0x314CB81E3274F440ULL
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
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F07B4811F008FF8ULL,
		0xDD2FA893B550E228ULL,
		0x2C0500E0F92CF160ULL,
		0x75720C6C2690DF0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0F69023E012003ULL,
		0xBA5F51276AA1C450ULL,
		0x580A01C1F259E2C1ULL,
		0x6AE418D84D21BE16ULL
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
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C83D3C12256C3A5ULL,
		0xE8078F48587B9EDBULL,
		0xD95FA9544AE1E6BAULL,
		0x22D93E8C4CA03A66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5907A78244AD874AULL,
		0xD00F1E90B0F73DB6ULL,
		0xB2BF52A895C3CD75ULL,
		0x45B27D18994074CDULL
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
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DF5475B720BE687ULL,
		0x0AA1E233F5516BE6ULL,
		0x5E317ED9B2E3D897ULL,
		0x12874D3CBA36757FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BEA8EB6E417CD0EULL,
		0x1543C467EAA2D7CCULL,
		0xBC62FDB365C7B12EULL,
		0x250E9A79746CEAFEULL
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
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF90CC53C009D785CULL,
		0x5F0604ED0376B5B2ULL,
		0x9B2B5BD2A995B127ULL,
		0x0BBFCEA51F280839ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2198A78013AF0B8ULL,
		0xBE0C09DA06ED6B65ULL,
		0x3656B7A5532B624EULL,
		0x177F9D4A3E501073ULL
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
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7388F4D57ABFDABULL,
		0xA6592649EFF01582ULL,
		0x39D17FFFE58FD5CEULL,
		0x3EB23442F310132CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE711E9AAF57FB56ULL,
		0x4CB24C93DFE02B05ULL,
		0x73A2FFFFCB1FAB9DULL,
		0x7D646885E6202658ULL
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
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ED4C9564437FD7BULL,
		0x8D55F6C6CD0926E8ULL,
		0x5ECF67F8D28B278AULL,
		0x47901E5EC8CF4786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA992AC886FFB09ULL,
		0x1AABED8D9A124DD0ULL,
		0xBD9ECFF1A5164F15ULL,
		0x0F203CBD919E8F0CULL
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
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85C6EF76EBB5CC2DULL,
		0x3955C1D73C3EC701ULL,
		0x204C9D30DCFB6AF7ULL,
		0x521C4B1A10BB2735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B8DDEEDD76B986DULL,
		0x72AB83AE787D8E03ULL,
		0x40993A61B9F6D5EEULL,
		0x2438963421764E6AULL
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
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x098AFA93BBD37132ULL,
		0x363A26D547D0749DULL,
		0x536B9C4C868AC51BULL,
		0x16A5613BEF3DE3EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1315F52777A6E264ULL,
		0x6C744DAA8FA0E93AULL,
		0xA6D738990D158A36ULL,
		0x2D4AC277DE7BC7D4ULL
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
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x480573470D3F9145ULL,
		0xDB31921988855B9CULL,
		0xF442DDD9F9D3378AULL,
		0x5FA10927F392D26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x900AE68E1A7F229DULL,
		0xB6632433110AB738ULL,
		0xE885BBB3F3A66F15ULL,
		0x3F42124FE725A4D5ULL
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
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E3802DAA9F2ED2BULL,
		0xC29FD508FCCAEA06ULL,
		0x75F93D35A6E11E54ULL,
		0x68CE34DCF38556BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C7005B553E5DA69ULL,
		0x853FAA11F995D40CULL,
		0xEBF27A6B4DC23CA9ULL,
		0x519C69B9E70AAD74ULL
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
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECD0F9C999BECD3BULL,
		0x1B64C11C6528FACAULL,
		0xA2B109364296F7D6ULL,
		0x0007BAF0848A7502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A1F393337D9A76ULL,
		0x36C98238CA51F595ULL,
		0x4562126C852DEFACULL,
		0x000F75E10914EA05ULL
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
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01E61542C088BCBAULL,
		0x391C9994F6D7DED7ULL,
		0x4EF62231F0D3F092ULL,
		0x63870618262BAF3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03CC2A8581117987ULL,
		0x72393329EDAFBDAEULL,
		0x9DEC4463E1A7E124ULL,
		0x470E0C304C575E74ULL
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
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x097497E359C55913ULL,
		0x018974FEA62411C0ULL,
		0x6E20BF2AA0D03CE3ULL,
		0x17C1412B7CFC0EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E92FC6B38AB226ULL,
		0x0312E9FD4C482380ULL,
		0xDC417E5541A079C6ULL,
		0x2F828256F9F81DBCULL
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
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x129E9F275B5074FCULL,
		0xB52A43980EB4EB88ULL,
		0xE0A57B5CD7412FECULL,
		0x1366593BF26E67D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x253D3E4EB6A0E9F8ULL,
		0x6A5487301D69D710ULL,
		0xC14AF6B9AE825FD9ULL,
		0x26CCB277E4DCCFABULL
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
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4BC960AD246CF38ULL,
		0xBAF56A91EE6589BEULL,
		0x4F6A02B6FA7823AFULL,
		0x529697DCEBE7C792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49792C15A48D9E83ULL,
		0x75EAD523DCCB137DULL,
		0x9ED4056DF4F0475FULL,
		0x252D2FB9D7CF8F24ULL
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
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x013C835560C3F198ULL,
		0x13A0DFEE444A2A42ULL,
		0x86D1B8BF2C1A7CCCULL,
		0x0644ACE8559BE5DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027906AAC187E330ULL,
		0x2741BFDC88945484ULL,
		0x0DA3717E5834F998ULL,
		0x0C8959D0AB37CBBDULL
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
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB73AC901CF122B58ULL,
		0xC390E45DD36F4DBDULL,
		0x2AD890165B2A5A38ULL,
		0x01AC6307DCF7F35DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7592039E2456B0ULL,
		0x8721C8BBA6DE9B7BULL,
		0x55B1202CB654B471ULL,
		0x0358C60FB9EFE6BAULL
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
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C2147569D621E77ULL,
		0xD738F48327C642EFULL,
		0x820EAB98CF0EB882ULL,
		0x729DD87E976DD1D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8428EAD3AC43D01ULL,
		0xAE71E9064F8C85DEULL,
		0x041D57319E1D7105ULL,
		0x653BB0FD2EDBA3ABULL
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
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54F795DCA2148624ULL,
		0xD4B728D77D22EBA2ULL,
		0x435BEC17B6324C72ULL,
		0x4EC403245DE83D04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EF2BB944290C5BULL,
		0xA96E51AEFA45D744ULL,
		0x86B7D82F6C6498E5ULL,
		0x1D880648BBD07A08ULL
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
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD79B0B3FD6DC4FDULL,
		0xAD05128AD904CE18ULL,
		0x32E43A903D655FFDULL,
		0x160C4E1F07CCF894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF36167FADB89FAULL,
		0x5A0A2515B2099C31ULL,
		0x65C875207ACABFFBULL,
		0x2C189C3E0F99F128ULL
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
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11B31BD819F21B23ULL,
		0xF896C72F98C1A600ULL,
		0x0FB51F55A807B34AULL,
		0x13DDFBE4C87D1162ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x236637B033E43646ULL,
		0xF12D8E5F31834C00ULL,
		0x1F6A3EAB500F6695ULL,
		0x27BBF7C990FA22C4ULL
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
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD29222577BD17BB6ULL,
		0x69F001260FF1C0A2ULL,
		0xF66EBA428C190E7EULL,
		0x47326B5F1A0E9E43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA52444AEF7A2F77FULL,
		0xD3E0024C1FE38145ULL,
		0xECDD748518321CFCULL,
		0x0E64D6BE341D3C87ULL
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
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DAD8837B81F3E10ULL,
		0x32381125AD494BD8ULL,
		0xDCEAA3E17A9C4892ULL,
		0x53D3125B3E2D0C38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B5B106F703E7C33ULL,
		0x6470224B5A9297B0ULL,
		0xB9D547C2F5389124ULL,
		0x27A624B67C5A1871ULL
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
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24B88FB6FC23A89BULL,
		0xF90DE7927042B148ULL,
		0xE8F74B478AB6F320ULL,
		0x76D538B32A48AC61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49711F6DF8475149ULL,
		0xF21BCF24E0856290ULL,
		0xD1EE968F156DE641ULL,
		0x6DAA7166549158C3ULL
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
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E8EABA680FA153EULL,
		0x69B6721098124810ULL,
		0x727BE4E7484DEF20ULL,
		0x796B685E722A36E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D1D574D01F42A8FULL,
		0xD36CE42130249020ULL,
		0xE4F7C9CE909BDE40ULL,
		0x72D6D0BCE4546DC6ULL
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
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ACE9B878C415AE7ULL,
		0x63F70D3ADEEA8EB2ULL,
		0x42E2EE24C9D5643CULL,
		0x272EFFBCCA329322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x759D370F1882B5CEULL,
		0xC7EE1A75BDD51D64ULL,
		0x85C5DC4993AAC878ULL,
		0x4E5DFF7994652644ULL
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
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x943D9CF54BB7C55DULL,
		0xA2D6922A1B0A52B3ULL,
		0x5A076ED78965C385ULL,
		0x729558CC6A5F1A59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x287B39EA976F8ACDULL,
		0x45AD24543614A567ULL,
		0xB40EDDAF12CB870BULL,
		0x652AB198D4BE34B2ULL
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
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3D3EC012812E7F3ULL,
		0xBFD56F931E844487ULL,
		0x73909821D4262625ULL,
		0x3B6BB443C9F01F3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A7D8025025CFE6ULL,
		0x7FAADF263D08890FULL,
		0xE7213043A84C4C4BULL,
		0x76D7688793E03E7AULL
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
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4EA06F41F5A75C0ULL,
		0x27A80A655EEC0279ULL,
		0x9BBA4713E5AC14DBULL,
		0x6DE085A27BABB198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D40DE83EB4EB93ULL,
		0x4F5014CABDD804F3ULL,
		0x37748E27CB5829B6ULL,
		0x5BC10B44F7576331ULL
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
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64E55F1492EAF87CULL,
		0xAA71651880E5C494ULL,
		0x7AF6F8BD83FE263BULL,
		0x7D65C922A457DD9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9CABE2925D5F10BULL,
		0x54E2CA3101CB8928ULL,
		0xF5EDF17B07FC4C77ULL,
		0x7ACB924548AFBB3AULL
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
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CA41045332C9708ULL,
		0x312AAD8808EB861CULL,
		0xF8C5C515403A33B9ULL,
		0x0362FC2ED84BAC8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1948208A66592E10ULL,
		0x62555B1011D70C39ULL,
		0xF18B8A2A80746772ULL,
		0x06C5F85DB0975919ULL
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
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7AE70EF3CEADC6ULL,
		0xA7F48EB2C7B6D395ULL,
		0xAEC747C1A9D9EF06ULL,
		0x6C0DB2857321F445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF5CE1DE79D5B9FULL,
		0x4FE91D658F6DA72BULL,
		0x5D8E8F8353B3DE0DULL,
		0x581B650AE643E88BULL
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
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21B8B40EB3423664ULL,
		0x4977CDC2F82B6698ULL,
		0xC8420C8567A2A18CULL,
		0x02B04614108C9164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4371681D66846CC8ULL,
		0x92EF9B85F056CD30ULL,
		0x9084190ACF454318ULL,
		0x05608C28211922C9ULL
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
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x620FC0BBA25D0241ULL,
		0xB47208493D3F90DFULL,
		0x15538D0C86654EFAULL,
		0x2153B01BE770CD7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41F817744BA0482ULL,
		0x68E410927A7F21BEULL,
		0x2AA71A190CCA9DF5ULL,
		0x42A76037CEE19AFCULL
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
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADB201B3342169E4ULL,
		0xB4131E8B75E580ECULL,
		0x926B44145D65862BULL,
		0x4B95FD1292E01C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B6403666842D3DBULL,
		0x68263D16EBCB01D9ULL,
		0x24D68828BACB0C57ULL,
		0x172BFA2525C03823ULL
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
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D6978CB8D501DD3ULL,
		0xC653C2D72E9B97D6ULL,
		0x46C8F0D4F9BA8671ULL,
		0x5C09038831ED4694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD2F1971AA03BB9ULL,
		0x8CA785AE5D372FACULL,
		0x8D91E1A9F3750CE3ULL,
		0x3812071063DA8D28ULL
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
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x801457D2E56D9718ULL,
		0x38EB193F63E83B77ULL,
		0x63DD1FB87900201AULL,
		0x5552F09CEFE60D50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0028AFA5CADB2E43ULL,
		0x71D6327EC7D076EFULL,
		0xC7BA3F70F2004034ULL,
		0x2AA5E139DFCC1AA0ULL
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
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC455C90597BD120ULL,
		0x39EF169B7839C087ULL,
		0x0DB504636FAC5AEBULL,
		0x732840D84923C9BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x988AB920B2F7A253ULL,
		0x73DE2D36F073810FULL,
		0x1B6A08C6DF58B5D6ULL,
		0x665081B09247937AULL
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
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FC48A71DEEF5110ULL,
		0xF7EB51335B79D113ULL,
		0x493F633CF84F9121ULL,
		0x6C3E93587D7235FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F8914E3BDDEA233ULL,
		0xEFD6A266B6F3A226ULL,
		0x927EC679F09F2243ULL,
		0x587D26B0FAE46BFCULL
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
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4F6AD2ADE0EE402ULL,
		0xF52AD96B5CC73625ULL,
		0xE19D14EDAF781D0EULL,
		0x00F6178B10E05038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9ED5A55BC1DC804ULL,
		0xEA55B2D6B98E6C4BULL,
		0xC33A29DB5EF03A1DULL,
		0x01EC2F1621C0A071ULL
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
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1E477D8EFF0BF5ULL,
		0xE7D2605186402EE0ULL,
		0x74C4BBF8011CFD7FULL,
		0x559B0595EB9DCAFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3C8EFB1DFE17FDULL,
		0xCFA4C0A30C805DC1ULL,
		0xE98977F00239FAFFULL,
		0x2B360B2BD73B95FEULL
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
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C40972507D8AE41ULL,
		0xE4A30CB79DBB3706ULL,
		0xAE1FD9F5AF0D1633ULL,
		0x26CA5DEB579155E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8812E4A0FB15C82ULL,
		0xC946196F3B766E0CULL,
		0x5C3FB3EB5E1A2C67ULL,
		0x4D94BBD6AF22ABC1ULL
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
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x308BE6091A271FCDULL,
		0x3B283AA3803930EDULL,
		0xDFBC55BB59E569E2ULL,
		0x299063EF36EC1A6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6117CC12344E3F9AULL,
		0x76507547007261DAULL,
		0xBF78AB76B3CAD3C4ULL,
		0x5320C7DE6DD834DDULL
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
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB34AB6788E39BEULL,
		0xA4A5B0D8EE20B2A8ULL,
		0x7A6BC8DF6367AAEEULL,
		0x4F3CCA85EB0409FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF66956CF11C738FULL,
		0x494B61B1DC416551ULL,
		0xF4D791BEC6CF55DDULL,
		0x1E79950BD60813FCULL
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
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB2D5B903A066239ULL,
		0x1FE601D449BC9762ULL,
		0x2F76397481A77BD8ULL,
		0x40FA8582F1BCC17AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x765AB720740CC485ULL,
		0x3FCC03A893792EC5ULL,
		0x5EEC72E9034EF7B0ULL,
		0x01F50B05E37982F4ULL
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
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}